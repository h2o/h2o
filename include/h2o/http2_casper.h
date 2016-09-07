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

typedef struct st_h2o_http2_casper_t h2o_http2_casper_t;

/**
 * creates an object with provided parameters
 */
h2o_http2_casper_t *h2o_http2_casper_create(unsigned capacity_bits, unsigned remainder_bits);
/**
 * destroys the object and resources associated to it
 */
void h2o_http2_casper_destroy(h2o_http2_casper_t *casper);
/**
 * returns the number of keys stored
 */
size_t h2o_http2_casper_num_entries(h2o_http2_casper_t *casper);
/**
 * checks if a key is (was) marked as cached at the moment the fuction is invoked
 */
int h2o_http2_casper_lookup(h2o_http2_casper_t *casper, const char *path, size_t path_len, int set);
/**
 * consumes the `Cookie` headers in requests and updates the structure
 */
void h2o_http2_casper_consume_cookie(h2o_http2_casper_t *casper, const char *cookie, size_t cookie_len);
/**
 * returns the value of the `Set-Cookie` header that should be sent to the client
 */
h2o_iovec_t h2o_http2_casper_get_cookie(h2o_http2_casper_t *casper);

#endif
