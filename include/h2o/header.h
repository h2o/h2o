/*
 * Copyright (c) 2018 Fastly Inc, Ichito Nagata
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
} h2o_header_t;

/**
 * list of headers
 */
typedef H2O_VECTOR(h2o_header_t) h2o_headers_t;

#endif
