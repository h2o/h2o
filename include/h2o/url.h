/*
 * Copyright (c) 2014,2015 DeNA Co., Ltd.
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
#ifndef h2o__url_h
#define h2o__url_h

#include "h2o/memory.h"

typedef struct st_h2o_parse_url_t {
    h2o_iovec_t scheme;
    h2o_iovec_t authority; /* i.e. host:port */
    h2o_iovec_t host;
    h2o_iovec_t path;
    uint16_t port;
} h2o_parse_url_t;

/**
 * removes "..", ".", decodes %xx from a path representation
 * @param pool memory pool to be used in case the path contained references to directories
 * @param path source path
 * @param len source length
 * @return buffer pointing to source, or buffer pointing to an allocated chunk with normalized representation of the given path
 */
h2o_iovec_t h2o_normalize_path(h2o_mem_pool_t *pool, const char *path, size_t len);
/**
 * parses absolute URL (either http or https)
 */
int h2o_parse_url(const char *url, size_t url_len, h2o_parse_url_t *result);

#endif
