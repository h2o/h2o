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
#ifndef h2o__cache_digests_h
#define h2o__cache_digests_h

#include <stddef.h>
#include <stdlib.h>
#include "h2o/memory.h"

typedef enum en_h2o_cache_digests_state_t {
    H2O_CACHE_DIGESTS_STATE_UNKNOWN,
    H2O_CACHE_DIGESTS_STATE_NOT_CACHED,
    H2O_CACHE_DIGESTS_STATE_FRESH,
    H2O_CACHE_DIGESTS_STATE_STALE
} h2o_cache_digests_state_t;

typedef struct st_h2o_cache_digests_frame_t h2o_cache_digests_frame_t;

typedef H2O_VECTOR(h2o_cache_digests_frame_t) h2o_cache_digests_frame_vector_t;

typedef struct st_h2o_cache_digests_t {
    struct {
        h2o_cache_digests_frame_vector_t url_only;
        h2o_cache_digests_frame_vector_t url_and_etag;
        int complete;
    } fresh;
} h2o_cache_digests_t;

/**
 * destroys the object
 */
void h2o_cache_digests_destroy(h2o_cache_digests_t *digests);
/**
 * loads a header (*digests may be NULL)
 */
void h2o_cache_digests_load_header(h2o_cache_digests_t **digests, const char *value, size_t len);
/**
 * lookup for a match with URL only
 */
h2o_cache_digests_state_t h2o_cache_digests_lookup_by_url(h2o_cache_digests_t *digests, const char *url, size_t url_len);
/**
 * lookup for a match with URL and etag
 */
h2o_cache_digests_state_t h2o_cache_digests_lookup_by_url_and_etag(h2o_cache_digests_t *digests, const char *url, size_t url_len,
                                                                   const char *etag, size_t etag_len);

#endif
