/*
 * Copyright (c) 2015 DeNA Co., Ltd., Kazuho Oku
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
#include <openssl/sha.h>
#include "golombset.h"
#include "h2o/string_.h"
#include "h2o/http2_casper.h"

#define COOKIE_NAME "h2o_casper"
#define COOKIE_ATTRIBUTES "; Path=/; Expires=Tue, 01 Jan 2030 00:00:00 GMT; Secure"

struct st_h2o_http2_casper_t {
    H2O_VECTOR(uint64_t) keys;
    unsigned capacity_bits;
    unsigned remainder_bits;
    h2o_iovec_t cookie_cache;
};

static unsigned calc_key(h2o_http2_casper_t *casper, const char *path, size_t path_len)
{
    SHA_CTX ctx;
    SHA1_Init(&ctx);
    SHA1_Update(&ctx, path, path_len);

    union {
        unsigned key;
        unsigned char bytes[SHA_DIGEST_LENGTH];
    } md;
    SHA1_Final(md.bytes, &ctx);

    return md.key & ((1 << casper->capacity_bits) - 1);
}

h2o_http2_casper_t *h2o_http2_casper_create(unsigned capacity_bits, unsigned remainder_bits)
{
    h2o_http2_casper_t *casper = h2o_mem_alloc(sizeof(*casper));

    memset(&casper->keys, 0, sizeof(casper->keys));
    casper->capacity_bits = capacity_bits;
    casper->remainder_bits = remainder_bits;
    casper->cookie_cache = (h2o_iovec_t){NULL};

    return casper;
}

void h2o_http2_casper_destroy(h2o_http2_casper_t *casper)
{
    free(casper->keys.entries);
    free(casper->cookie_cache.base);
    free(casper);
}

size_t h2o_http2_casper_num_entries(h2o_http2_casper_t *casper)
{
    return casper->keys.size;
}

int h2o_http2_casper_lookup(h2o_http2_casper_t *casper, const char *path, size_t path_len, int set)
{
    unsigned key = calc_key(casper, path, path_len);
    size_t i;

    /* FIXME use binary search */
    for (i = 0; i != casper->keys.size; ++i)
        if (key <= casper->keys.entries[i])
            break;
    if (i != casper->keys.size && key == casper->keys.entries[i])
        return 1;
    if (!set)
        return 0;

    /* we need to set a new value */
    free(casper->cookie_cache.base);
    casper->cookie_cache = (h2o_iovec_t){NULL};
    h2o_vector_reserve(NULL, &casper->keys, casper->keys.size + 1);
    memmove(casper->keys.entries + i + 1, casper->keys.entries + i, (casper->keys.size - i) * sizeof(casper->keys.entries[0]));
    ++casper->keys.size;
    casper->keys.entries[i] = key;
    return 0;
}

void h2o_http2_casper_consume_cookie(h2o_http2_casper_t *casper, const char *cookie, size_t cookie_len)
{
    h2o_iovec_t binary = {NULL};
    uint64_t tiny_keys_buf[128], *keys = tiny_keys_buf;

    /* check the name of the cookie */
    if (!(cookie_len > sizeof(COOKIE_NAME "=") - 1 && memcmp(cookie, H2O_STRLIT(COOKIE_NAME "=")) == 0))
        goto Exit;

    /* base64 decode */
    if ((binary = h2o_decode_base64url(NULL, cookie + sizeof(COOKIE_NAME "=") - 1, cookie_len - (sizeof(COOKIE_NAME "=") - 1)))
            .base == NULL)
        goto Exit;

    /* decode GCS, either using tiny_keys_buf or using heap */
    size_t capacity = sizeof(tiny_keys_buf) / sizeof(tiny_keys_buf[0]), num_keys;
    while (num_keys = capacity, golombset_decode(casper->remainder_bits, binary.base, binary.len, keys, &num_keys) != 0) {
        if (keys != tiny_keys_buf) {
            free(keys);
            keys = tiny_keys_buf; /* reset to something that would not trigger call to free(3) */
        }
        if (capacity >= (size_t)1 << casper->capacity_bits)
            goto Exit;
        capacity *= 2;
        keys = h2o_mem_alloc(capacity * sizeof(*keys));
    }

    /* copy or merge the entries */
    if (num_keys == 0) {
        /* nothing to do */
    } else if (casper->keys.size == 0) {
        h2o_vector_reserve(NULL, &casper->keys, num_keys);
        memcpy(casper->keys.entries, keys, num_keys * sizeof(*keys));
        casper->keys.size = num_keys;
    } else {
        uint64_t *orig_keys = casper->keys.entries;
        size_t num_orig_keys = casper->keys.size, orig_index = 0, new_index = 0;
        memset(&casper->keys, 0, sizeof(casper->keys));
        h2o_vector_reserve(NULL, &casper->keys, num_keys + num_orig_keys);
        do {
            if (orig_keys[orig_index] < keys[new_index]) {
                casper->keys.entries[casper->keys.size++] = orig_keys[orig_index++];
            } else if (orig_keys[orig_index] > keys[new_index]) {
                casper->keys.entries[casper->keys.size++] = keys[new_index++];
            } else {
                casper->keys.entries[casper->keys.size++] = orig_keys[orig_index];
                ++orig_index;
                ++new_index;
            }
        } while (orig_index != num_orig_keys && new_index != num_keys);
        if (orig_index != num_orig_keys) {
            do {
                casper->keys.entries[casper->keys.size++] = orig_keys[orig_index++];
            } while (orig_index != num_orig_keys);
        } else if (new_index != num_keys) {
            do {
                casper->keys.entries[casper->keys.size++] = keys[new_index++];
            } while (new_index != num_keys);
        }
        free(orig_keys);
    }

Exit:
    if (keys != tiny_keys_buf)
        free(keys);
    free(binary.base);
}

static size_t append_str(char *dst, const char *s, size_t l)
{
    memcpy(dst, s, l);
    return l;
}

h2o_iovec_t h2o_http2_casper_get_cookie(h2o_http2_casper_t *casper)
{
    if (casper->cookie_cache.base != NULL)
        return casper->cookie_cache;

    if (casper->keys.size == 0)
        return (h2o_iovec_t){NULL};

    /* encode as binary */
    char tiny_bin_buf[128], *bin_buf = tiny_bin_buf;
    size_t bin_capacity = sizeof(tiny_bin_buf), bin_size;
    while (bin_size = bin_capacity,
           golombset_encode(casper->remainder_bits, casper->keys.entries, casper->keys.size, bin_buf, &bin_size) != 0) {
        if (bin_buf != tiny_bin_buf)
            free(bin_buf);
        bin_capacity *= 2;
        bin_buf = h2o_mem_alloc(bin_capacity);
    }

    char *header_bytes = h2o_mem_alloc(sizeof(COOKIE_NAME "=" COOKIE_ATTRIBUTES) - 1 + (bin_size + 3) * 4 / 3);
    size_t header_len = 0;

    header_len += append_str(header_bytes + header_len, H2O_STRLIT(COOKIE_NAME "="));
    header_len += h2o_base64_encode(header_bytes + header_len, bin_buf, bin_size, 1);
    header_len += append_str(header_bytes + header_len, H2O_STRLIT(COOKIE_ATTRIBUTES));

    if (bin_buf != tiny_bin_buf)
        free(bin_buf);

    casper->cookie_cache = h2o_iovec_init(header_bytes, header_len);
    return casper->cookie_cache;
}
