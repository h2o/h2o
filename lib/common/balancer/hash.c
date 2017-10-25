/*
 * Copyright (c) 2017 Justin Zhu
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */
#include "h2o/balancer.h"
#include "siphash.h"
#include "h2o.h"

struct hash_bucket_t {
    uint64_t hash;
    size_t *request_count;
};

typedef H2O_VECTOR(struct hash_bucket_t) hash_bucket_vector_t;

struct bounded_hash_t {
    hash_bucket_vector_t buckets;
    h2o_balancer_hash_key_type type;
    double c;
    pthread_mutex_t mutex;
};

/* though endians would cause difference, we could accept */
#define BYTE_TO_QWORD(x) (*(uint64_t *)x)

struct bounded_hash_conf_t {
    h2o_balancer_hash_key_type type;
    double c;
};

/* we don't really need a key */
static uint8_t hash_key[16];

static size_t range_bsearch(const void *key, const void *base, size_t num, size_t size,
                            int (*cmp)(const void *, const void *), int ring)
{
    size_t start = 0;
    size_t end = num;
    size_t mid;
    int result;
    
    while (start < end) {
        mid = start + (end - start) / 2;
        result = cmp(key, base + size * mid);
        if (result < 0)
            end = mid;
        else if (result > 0)
            start = mid + 1;
        else
            return mid;
    }
    
    if (ring && end == num)
        end = 0;
    return end;
}

static uint64_t compute_hash(const void *key, size_t key_len)
{
    uint8_t hashtag_array[8];
    siphash(key, key_len, hash_key, hashtag_array, 8);
    return BYTE_TO_QWORD(hashtag_array);
}

static int hash_cmp(const void *_key, const void *_elt)
{
    const uint64_t *key = _key;
    const uint64_t *elt = _elt;
    
    if (*key > *elt) return 1;
    else if (*key < *elt) return -1;
    else return 0;
}

static size_t find_bucket_for_item(hash_bucket_vector_t *ring, void *key, size_t key_size)
{
    uint64_t hash = compute_hash(key, key_size);
    size_t index = range_bsearch(&hash, ring->entries, ring->size, sizeof(struct hash_bucket_t),
                                 hash_cmp, 1);
    return index;
}

static void insert_new_bucket(hash_bucket_vector_t *ring, struct hash_bucket_t *bucket)
{
    size_t index = range_bsearch(bucket, ring->entries, ring->size, sizeof(struct hash_bucket_t),
                                 hash_cmp, 0);
    size_t i;

    if (index != ring->size)
        for (i = ring->size; i > index; i--)
            ring->entries[i] = ring->entries[i - 1];
    ring->entries[index] = *bucket;
    ring->size++;
}

static void add_bucket(hash_bucket_vector_t *ring, size_t *request_count, const void *key, size_t key_len)
{
    struct hash_bucket_t bucket = {compute_hash(key, key_len), request_count};
    if (ring->capacity == ring->size) {
        h2o_vector_reserve(NULL, ring, 2 * ring->capacity);
    }
    insert_new_bucket(ring, &bucket);
}

static void init(h2o_socketpool_target_vector_t *targets, void *_conf, void **data)
{
    struct bounded_hash_conf_t *conf = _conf;
    size_t i;
    struct bounded_hash_t *self = h2o_mem_alloc(sizeof(*self));
    char tag_buf[NI_MAXHOST + sizeof(":65535")];
    size_t tag_buf_len;

    if (conf == NULL) {
        self->c = 1.2;
        self->type = H2O_BALANCER_HASH_KEY_TYPE_IP_PORT;
    } else {
        self->c = conf->c;
        self->type = conf->type;
    }
    pthread_mutex_init(&self->mutex, NULL);
    memset(&self->buckets, 0, sizeof(self->buckets));
    
    h2o_vector_reserve(NULL, &self->buckets, targets->size);
    for (i = 0; i < targets->size; i++) {
        tag_buf_len = sprintf(tag_buf, "%s:%zu", targets->entries[i]->url.host.base, i);
        add_bucket(&self->buckets, &targets->entries[i]->_shared.request_count, tag_buf, tag_buf_len);
    }
    *data = self;
}

static size_t bounded_find_bucket(hash_bucket_vector_t buckets, size_t startat, double c)
{
    size_t index = startat;
    size_t i;
    size_t total = 0;
    double lower_total_bound = (1.0 / (c - 1)) * buckets.size;
    for (i = 0; i < buckets.size; i++) {
        total += *buckets.entries[i].request_count;
    }
    
    double bound_total = c * (total + 1);
    
    if (total > lower_total_bound) {
        for (i = 0; i < buckets.size; i++) {
            if (bound_total >= buckets.size * (*buckets.entries[i].request_count + 1)) {
                break;
            }
            if (++index == buckets.size) {
                index = 0;
            }
        }
    }
    
    assert(bound_total <= lower_total_bound || i != buckets.size);
    
    return index;
}

static size_t selector(h2o_socketpool_target_vector_t *targets, void *_data, int *tried, void *_req)
{
    h2o_req_t *req = _req;
    struct bounded_hash_t *self = _data;
    h2o_iovec_t hash_key;
    
    size_t index;
    size_t i;
    hash_bucket_vector_t buckets = self->buckets;
    
    size_t remote_addr_len = SIZE_MAX;
    char remote_addr[NI_MAXHOST + sizeof(":65535")];
    struct sockaddr_storage ss;
    socklen_t sslen;
    int32_t port;
    
    if ((sslen = req->conn->callbacks->get_peername(req->conn, (void *)&ss)) != 0) {
        remote_addr_len = h2o_socket_getnumerichost((void *)&ss, sslen, remote_addr);
        port = h2o_socket_getport((void *)&ss);
    }
    
    /* if remote addr cannot be fetched, use a default one */
    if (remote_addr_len == SIZE_MAX) {
        strcpy(remote_addr, "169.254.0.1");
        remote_addr_len = strlen(remote_addr);
    }
    
    switch (self->type) {
        case H2O_BALANCER_HASH_KEY_TYPE_IP:
            hash_key.base = remote_addr;
            hash_key.len = remote_addr_len;
            break;
        case H2O_BALANCER_HASH_KEY_TYPE_IP_PORT:
            hash_key.base = remote_addr;
            hash_key.len = sprintf(remote_addr + remote_addr_len, ":%d", port);
            break;
        case H2O_BALANCER_HASH_KEY_TYPE_PATH:
            hash_key = req->path;
            break;
    }
    index = find_bucket_for_item(&self->buckets, hash_key.base, hash_key.len);
    
    pthread_mutex_lock(&self->mutex);
    
    index = bounded_find_bucket(buckets, index, self->c);
    
    /* If the chosen bucket was used (i.e. failed to connect), fall back to find next available bucket */
    if (tried[index]) {
        for (i = 1; i < buckets.size; i++) {
            index++;
            if (index == buckets.size)
                index = 0;
            if (!tried[index])
                break;
        }
    }
    pthread_mutex_unlock(&self->mutex);
    return index;
}

static int overall_parser(yoml_t *node, void **data, yoml_t **errnode, char **errstr)
{
    struct bounded_hash_conf_t *result;
    if (node != NULL && node->type == YOML_TYPE_MAPPING) {
        result = h2o_mem_alloc(sizeof(*result));
        result->type = H2O_BALANCER_HASH_KEY_TYPE_IP;
        result->c = 1.2;
        size_t i;
        int scanf_ret;
        for (i = 0; i < node->data.mapping.size; i++) {
            yoml_t *key = node->data.mapping.elements[i].key;
            yoml_t *value = node->data.mapping.elements[i].value;
            if (key->type != YOML_TYPE_SCALAR) {
                *errnode = key;
                *errstr = "key must be a scalar";
                free(result);
                return -1;
            }
            if (strcasecmp(key->data.scalar, "source") == 0) {
                if (value->type != YOML_TYPE_SCALAR) {
                    *errnode = value;
                    *errstr = "value must be a scalar";
                    free(result);
                    return -1;
                }
                if (strcasecmp(value->data.scalar, "ip") == 0) {
                    result->type = H2O_BALANCER_HASH_KEY_TYPE_IP;
                } else if (strcasecmp(value->data.scalar, "ip-port") == 0) {
                    result->type = H2O_BALANCER_HASH_KEY_TYPE_IP_PORT;
                } else if (strcasecmp(value->data.scalar, "path") == 0) {
                    result->type = H2O_BALANCER_HASH_KEY_TYPE_PATH;
                } else {
                    *errnode = value;
                    *errstr = "value should be one of the following: ip, ip-port, path";
                }
            }
            if (strcasecmp(key->data.scalar, "c") == 0) {
                if (value->type != YOML_TYPE_SCALAR) {
                    *errnode = value;
                    *errstr = "value must be a scalar";
                    free(result);
                    return -1;
                }
                scanf_ret = sscanf(value->data.scalar, "%lf", &result->c);
                if (scanf_ret != 1 || result->c <= 1.0) {
                    *errnode = value;
                    *errstr = "value must be a real number over 1.0";
                    free(result);
                    return -1;
                }
            }
        }
        *data = (void *)result;
        return 0;
    }
    return -1;
}

static void dispose(void *data)
{
    struct bounded_hash_t *self = data;

    pthread_mutex_destroy(&self->mutex);
    
    free(self->buckets.entries);
}

const h2o_balancer_callbacks_t *h2o_balancer_hash_get_callbacks() {
    static const h2o_balancer_callbacks_t hash_callbacks = {
        NULL,
        overall_parser,
        init,
        selector,
        dispose
    };
    return &hash_callbacks;
}
