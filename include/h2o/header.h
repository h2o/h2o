/*
 * Copyright (c) 2018 Fastly, Ichito Nagata
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
#ifndef h2o__header_h
#define h2o__header_h

#include "h2o/memory.h"
#include "h2o/token.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_h2o_header_flags_t {
    unsigned char dont_compress : 1;
} h2o_header_flags_t;

/**
 * represents a HTTP header
 */
typedef struct st_h2o_header_t {
    /**
     * name of the header (may point to h2o_token_t which is an optimized subclass of h2o_iovec_t)
     */
    h2o_iovec_t *name;
    /**
     * The name of the header as originally received from the client, same length as `name`
     */
    const char *orig_name;
    /**
     * value of the header
     */
    h2o_iovec_t value;
    /**
     * flags of the header
     */
    h2o_header_flags_t flags;
} h2o_header_t;

/**
 * list of headers
 */
typedef H2O_VECTOR(h2o_header_t) h2o_headers_t;

static int h2o_header_name_is_equal(const h2o_header_t *x, const h2o_header_t *y);
/**
 * searches for a header of given name (fast, by comparing tokens)
 * @param headers header list
 * @param token name of the header to search for
 * @param cursor index of the last match (or set -1 to start a new search)
 * @return index of the found header (or -1 if not found)
 */
ssize_t h2o_find_header(const h2o_headers_t *headers, const h2o_token_t *token, ssize_t cursor);
/**
 * searches for a header of given name (slow, by comparing strings)
 * @param headers header list
 * @param name name of the header to search for
 * @param name_len length of the name
 * @param cursor index of the last match (or set -1 to start a new search)
 * @return index of the found header (or -1 if not found)
 */
ssize_t h2o_find_header_by_str(const h2o_headers_t *headers, const char *name, size_t name_len, ssize_t cursor);
/**
 * adds a header to list
 */
ssize_t h2o_add_header(h2o_mem_pool_t *pool, h2o_headers_t *headers, const h2o_token_t *token, const char *orig_name,
                       const char *value, size_t value_len);
/**
 * adds a header to list
 */
ssize_t h2o_add_header_by_str(h2o_mem_pool_t *pool, h2o_headers_t *headers, const char *lowercase_name, size_t lowercase_name_len,
                              int maybe_token, const char *orig_name, const char *value, size_t value_len);
/**
 * adds or replaces a header into the list
 */
ssize_t h2o_set_header(h2o_mem_pool_t *pool, h2o_headers_t *headers, const h2o_token_t *token, const char *value, size_t value_len,
                       int overwrite_if_exists);
/**
 * adds or replaces a header into the list
 */
ssize_t h2o_set_header_by_str(h2o_mem_pool_t *pool, h2o_headers_t *headers, const char *lowercase_name, size_t lowercase_name_len,
                              int maybe_token, const char *value, size_t value_len, int overwrite_if_exists);
/**
 * sets a header token
 */
ssize_t h2o_set_header_token(h2o_mem_pool_t *pool, h2o_headers_t *headers, const h2o_token_t *token, const char *value,
                             size_t value_len);
/**
 * deletes a header from list
 */
ssize_t h2o_delete_header(h2o_headers_t *headers, ssize_t cursor);

/* inline definitions */

inline int h2o_header_name_is_equal(const h2o_header_t *x, const h2o_header_t *y)
{
    if (x->name == y->name) {
        return 1;
    } else {
        return h2o_memis(x->name->base, x->name->len, y->name->base, y->name->len);
    }
}

#ifdef __cplusplus
}
#endif

#endif
