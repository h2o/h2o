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
#ifndef h2o__http2__casper_h
#define h2o__http2__casper_h

#include <stddef.h>
#include <stdlib.h>
#include "h2o/memory.h"

typedef struct st_h2o_http2_casper_t {
    H2O_VECTOR(unsigned) keys;
    unsigned capacity_bits;
    unsigned remainder_bits;
} h2o_http2_casper_t;

/**
 * initializes the structure with provided parameters
 */
static void h2o_http2_casper_init(h2o_http2_casper_t *casper, unsigned capacity_bits, unsigned remainder_bits);
/**
 * disposes of the structure and resources associated to it
 */
static void h2o_http2_casper_dispose(h2o_http2_casper_t *casper);
/**
 * checks if a key is (was) marked as cached at the moment the fuction is invoked
 */
int h2o_http2_casper_lookup(h2o_http2_casper_t *casper, const char *path, size_t path_len, const char *etag, size_t etag_len, int set);
/**
 * consumes the `Cookie` headers in requests and updates the structure
 */
void h2o_http2_casper_consume_cookie(h2o_http2_casper_t *casper, const char *cookie, size_t cookie_len);
/**
 * emits a `Set-Cookie` header that should be sent to the client
 */
h2o_iovec_t h2o_http2_casper_build_cookie(h2o_http2_casper_t *casper, h2o_mem_pool_t *pool);

/* inline definitions */

inline void h2o_http2_casper_init(h2o_http2_casper_t *casper, unsigned capacity_bits, unsigned remainder_bits)
{
    memset(&casper->keys, 0, sizeof(casper->keys));
    casper->capacity_bits = capacity_bits;
    casper->remainder_bits = remainder_bits;
}

inline void h2o_http2_casper_dispose(h2o_http2_casper_t *casper)
{
    free(casper->keys.entries);
}

#endif
