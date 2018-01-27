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

#include <math.h>

struct hash_bucket_t {
    /* hash should be first so that pointer to bucket is also pointer to hash */
    uint64_t hash;
    size_t target;
    size_t weight;
    size_t *request_count;
};

typedef H2O_VECTOR(struct hash_bucket_t) hash_bucket_vector_t;

struct bounded_hash_t {
    h2o_balancer_t super;
    hash_bucket_vector_t buckets;
    h2o_balancer_hash_key_type_t type;
    float c;
    size_t *total_leased;
    size_t total_weight;
    pthread_mutex_t mutex;
    h2o_balancer_hash_get_key_cb get_key_cb;
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

union un_hash_result {
    uint8_t octets[8];
    uint32_t dword[2];
};

static uint64_t compute_hash(const void *key, size_t key_len)
{
    union un_hash_result hash_result = {};
    siphash(key, key_len, hash_key, hash_result.octets, 8);
    /**
     * Hash result should be treated as the same uint64 no matter which endianness
     * is chosen. Or else locality of backends could not be optimal when served
     * with clustered servers working with different endianness.
     *
     * Actually little endian would be preferred since it is mostly chosen nowadays
     * but is there any portable ways to do such endianness independence without
     * much performance overhead?
     *
     * Or... do we really need to care about that?
     */
    uint64_t hash = ntohl(hash_result.dword[0]);
    hash = (hash << 32) | ntohl(hash_result.dword[1]);
    return hash;
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
    size_t index = range_bsearch(&hash, ring->entries, ring->size, sizeof(struct hash_bucket_t), hash_cmp, 1);
    return index;
}

static void add_bucket(hash_bucket_vector_t *ring, struct hash_bucket_t *bucket)
{
    size_t index = range_bsearch(bucket, ring->entries, ring->size, sizeof(struct hash_bucket_t), hash_cmp, 0);
    size_t i;

    if (index != ring->size)
        for (i = ring->size; i > index; i--)
            ring->entries[i] = ring->entries[i - 1];
    ring->entries[index] = *bucket;
    ring->size++;
}

static size_t bounded_find_target(struct bounded_hash_t *self, size_t startat)
{
    size_t index = startat;
    size_t i;
    size_t total = 0;
    if (self->total_leased == NULL) {
        for (i = 0; i < self->buckets.size; i++)
            total += *self->buckets.entries[i].request_count;
    } else {
        total = *self->total_leased;
    }

    float bound_per_weight = ((total + 1) * self->c) / self->total_weight;
    for (i = 0; i < self->buckets.size; i++) {
        size_t bound_this_bucket = ceil(bound_per_weight * self->buckets.entries[index].weight);
        if (*self->buckets.entries[index].request_count + 1 <= bound_this_bucket) {
            return self->buckets.entries[index].target;
        }
        index++;
        if (index == self->buckets.size)
            index = 0;
    }
    assert(!"all buckets over bound. should not happen");
}

static size_t selector(h2o_balancer_t *_self, h2o_socketpool_target_vector_t *targets, char *tried, void *socketpool_req_data)
{
    struct bounded_hash_t *self = (void *)_self;
    h2o_iovec_t hash_key = self->get_key_cb(socketpool_req_data, self->type);

    size_t index;
    size_t result;
    size_t i;
    hash_bucket_vector_t buckets = self->buckets;

    index = find_bucket_for_item(&self->buckets, hash_key.base, hash_key.len);

    pthread_mutex_lock(&self->mutex);

    result = bounded_find_target(self, index);

    /* If the chosen bucket was used (i.e. failed to connect), fall back to find next available bucket */
    if (tried[result]) {
        for (i = 1; i < buckets.size; i++) {
            result++;
            if (result == buckets.size)
                result = 0;
            if (!tried[result])
                break;
        }
    }
    pthread_mutex_unlock(&self->mutex);
    return result;
}

static void destroy(h2o_balancer_t *_self)
{
    struct bounded_hash_t *self = (void *)_self;

    pthread_mutex_destroy(&self->mutex);

    free(self->buckets.entries);
}

h2o_balancer_t *h2o_balancer_create_hash(float c, h2o_balancer_hash_key_type_t type) {
    static const h2o_balancer_callbacks_t hash_callbacks = {
        selector,
        destroy
    };

    struct bounded_hash_t *self = h2o_mem_alloc(sizeof(*self));
    self->super.callbacks = &hash_callbacks;
    self->super.type = H2O_BALANCER_TYPE_HASH;

    self->c = c;
    self->type = type;
    self->buckets.capacity = 0;
    self->buckets.size = 0;
    self->buckets.entries = NULL;
    self->total_leased = NULL;
    self->total_weight = 0;
    self->get_key_cb = NULL;
    pthread_mutex_init(&self->mutex, NULL);
    memset(&self->buckets, 0, sizeof(self->buckets));

    return &self->super;
}

void h2o_balancer_hash_set_get_key_cb(h2o_balancer_t *_self, h2o_balancer_hash_get_key_cb cb)
{
    struct bounded_hash_t *self = (void *)_self;
    self->get_key_cb = cb;
}

void h2o_balancer_hash_set_total_leased_count(h2o_balancer_t *_self, size_t *total_leased_count)
{
    struct bounded_hash_t *self = (void *)_self;
    self->total_leased = total_leased_count;
}

void h2o_balancer_hash_set_targets(h2o_balancer_t *_self, h2o_socketpool_target_t **targets, size_t num_targets)
{
    struct bounded_hash_t *self = (void *)_self;
    char tag_buf[NI_MAXHOST + sizeof(":65535")];
    size_t tag_buf_len;
    size_t i;

    h2o_vector_reserve(NULL, &self->buckets, num_targets);
    for (i = 0; i < num_targets; i++) {
        tag_buf_len = sprintf(tag_buf, "%s:%zu", targets[i]->url.host.base, i);
        struct hash_bucket_t bucket = {
            compute_hash(tag_buf, tag_buf_len),
            i,
            targets[i]->conf.weight_m1 + 1,
            &targets[i]->_shared.leased_count
        };
        if (self->buckets.capacity == self->buckets.size) {
            h2o_vector_reserve(NULL, &self->buckets, 2 * self->buckets.capacity);
        }
        add_bucket(&self->buckets, &bucket);
        self->total_weight += targets[i]->conf.weight_m1 + 1;
    }
}
