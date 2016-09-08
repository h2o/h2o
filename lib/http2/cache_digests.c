/*
 * Copyright (c) 2016 DeNA Co., Ltd., Kazuho Oku
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
#include <limits.h>
#include <openssl/sha.h>
#include <stdlib.h>
#include "golombset.h"
#include "h2o/string_.h"
#include "h2o/cache_digests.h"

struct st_h2o_cache_digests_frame_t {
    H2O_VECTOR(uint64_t) keys;
    unsigned capacity_bits;
};

static void dispose_frame_vector(h2o_cache_digests_frame_vector_t *v)
{
    size_t i;
    for (i = 0; i != v->size; ++i)
        free(v->entries[i].keys.entries);
    free(v->entries);
}

static void dispose_digests(h2o_cache_digests_t *digests)
{
    dispose_frame_vector(&digests->fresh.url_only);
    dispose_frame_vector(&digests->fresh.url_and_etag);
}

void h2o_cache_digests_destroy(h2o_cache_digests_t *digests)
{
    dispose_digests(digests);
    free(digests);
}

static void load_digest(h2o_cache_digests_t **digests, const char *gcs_base64, size_t gcs_base64_len, int with_validators,
                        int complete)
{
    h2o_cache_digests_frame_t frame = {{NULL}};
    h2o_iovec_t gcs_bin;
    struct st_golombset_decode_t ctx = {NULL};
    uint64_t nbits, pbits;

    /* decode base64 */
    if ((gcs_bin = h2o_decode_base64url(NULL, gcs_base64, gcs_base64_len)).base == NULL)
        goto Exit;

    /* prepare GCS context */
    ctx.src = (void *)(gcs_bin.base - 1);
    ctx.src_max = (void *)(gcs_bin.base + gcs_bin.len);
    ctx.src_shift = 0;

    /* decode nbits and pbits */
    if (golombset_decode_bits(&ctx, 5, &nbits) != 0 || golombset_decode_bits(&ctx, 5, &pbits) != 0)
        goto Exit;
    frame.capacity_bits = (unsigned)(nbits + pbits);

    /* decode the values */
    uint64_t value = UINT64_MAX, decoded;
    while (golombset_decode_value(&ctx, (unsigned)pbits, &decoded) == 0) {
        value += decoded + 1;
        if (value >= (uint64_t)1 << frame.capacity_bits)
            goto Exit;
        h2o_vector_reserve(NULL, &frame.keys, frame.keys.size + 1);
        frame.keys.entries[frame.keys.size++] = value;
    }

    /* store the result */
    if (*digests == NULL) {
        *digests = h2o_mem_alloc(sizeof(**digests));
        **digests = (h2o_cache_digests_t){{{NULL}}};
    }
    h2o_cache_digests_frame_vector_t *target = with_validators ? &(*digests)->fresh.url_and_etag : &(*digests)->fresh.url_only;
    h2o_vector_reserve(NULL, target, target->size + 1);
    target->entries[target->size++] = frame;
    frame = (h2o_cache_digests_frame_t){{NULL}};
    (*digests)->fresh.complete = complete;

Exit:
    free(frame.keys.entries);
    free(gcs_bin.base);
}

void h2o_cache_digests_load_header(h2o_cache_digests_t **digests, const char *value, size_t len)
{
    h2o_iovec_t iter = h2o_iovec_init(value, len);
    const char *token;
    size_t token_len;

    do {
        const char *gcs_base64;
        size_t gcs_base64_len;
        int reset = 0, validators = 0, complete = 0, skip = 0;
        h2o_iovec_t token_value;

        if ((gcs_base64 = h2o_next_token(&iter, ';', &gcs_base64_len, NULL)) == NULL)
            return;
        while ((token = h2o_next_token(&iter, ';', &token_len, &token_value)) != NULL &&
               !h2o_memis(token, token_len, H2O_STRLIT(","))) {
            if (h2o_lcstris(token, token_len, H2O_STRLIT("reset"))) {
                reset = 1;
            } else if (h2o_lcstris(token, token_len, H2O_STRLIT("validators"))) {
                validators = 1;
            } else if (h2o_lcstris(token, token_len, H2O_STRLIT("complete"))) {
                complete = 1;
            } else {
                skip = 1;
            }
        }

        if (reset && *digests != NULL) {
            h2o_cache_digests_destroy(*digests);
            *digests = NULL;
        }

        if (skip) {
            /* not supported for the time being */
        } else {
            load_digest(digests, gcs_base64, gcs_base64_len, validators, complete);
        }
    } while (token != NULL);
}

static uint64_t calc_hash(const char *url, size_t url_len, const char *etag, size_t etag_len)
{
    SHA256_CTX ctx;
    union {
        unsigned char bytes[SHA256_DIGEST_LENGTH];
        uint64_t u64;
    } md;

    SHA256_Init(&ctx);
    SHA256_Update(&ctx, url, url_len);
    SHA256_Update(&ctx, etag, etag_len);
    SHA256_Final(md.bytes, &ctx);

    if (*(uint16_t *)"\xde\xad" == 0xdead)
        return md.u64;
    else
        return __builtin_bswap64(md.u64);
}

static int cmp_key(const void *_x, const void *_y)
{
    uint64_t x = *(uint64_t *)_x, y = *(uint64_t *)_y;

    if (x < y) {
        return -1;
    } else if (x > y) {
        return 1;
    } else {
        return 0;
    }
}

static int lookup(h2o_cache_digests_frame_vector_t *vector, const char *url, size_t url_len, const char *etag, size_t etag_len,
                  int is_fresh, int is_complete)
{
    if (vector->size != 0) {
        uint64_t hash = calc_hash(url, url_len, etag, etag_len);
        size_t i = 0;
        do {
            h2o_cache_digests_frame_t *frame = vector->entries + i;
            uint64_t key = hash >> (64 - frame->capacity_bits);
            if (bsearch(&key, frame->keys.entries, frame->keys.size, sizeof(frame->keys.entries[0]), cmp_key) != NULL)
                return is_fresh ? H2O_CACHE_DIGESTS_STATE_FRESH : H2O_CACHE_DIGESTS_STATE_STALE;
        } while (++i != vector->size);
    }

    return is_complete ? H2O_CACHE_DIGESTS_STATE_NOT_CACHED : H2O_CACHE_DIGESTS_STATE_UNKNOWN;
}

h2o_cache_digests_state_t h2o_cache_digests_lookup_by_url(h2o_cache_digests_t *digests, const char *url, size_t url_len)
{
    return lookup(&digests->fresh.url_only, url, url_len, "", 0, 1, digests->fresh.complete);
}

h2o_cache_digests_state_t h2o_cache_digests_lookup_by_url_and_etag(h2o_cache_digests_t *digests, const char *url, size_t url_len,
                                                                   const char *etag, size_t etag_len)
{
    return lookup(&digests->fresh.url_and_etag, url, url_len, etag, etag_len, 1, digests->fresh.complete);
}
