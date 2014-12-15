/*
 * Copyright (c) 2014 DeNA Co., Ltd.
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
#ifndef h2o__regexp_h
#define h2o__regexp_h

#include "h2o/memory.h"

enum {
    H2O_REGEXP_FLAG_CASELESS = 0x1,
    H2O_REGEXP_FLAG_MULTILINE = 0x2,
    H2O_REGEXP_FLAG_DOTALL = 0x4
};

typedef struct st_h2o_regexp_t h2o_regexp_t;

typedef struct st_h2o_regexp_match_t {
    size_t first;
    size_t last;
} h2o_regexp_match_t;

h2o_regexp_t *h2o_regexp_compile(h2o_iovec_t pattern, int flags, const char **err, size_t *err_offset);
void h2o_regexp_destroy(h2o_regexp_t *re);
ssize_t h2o_regexp_exec(h2o_regexp_t *re, h2o_iovec_t str, h2o_regexp_match_t *matches, size_t match_size);

#endif
