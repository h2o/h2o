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
#include "../test.h"
#include "../../../lib/regexp.c"

void test_lib__regexp_c()
{
    h2o_regexp_t *re;
    const char *errstr;
    size_t erroffset;
    h2o_iovec_t matches[2];
    ssize_t nmatches;

    re = h2o_regexp_compile(h2o_iovec_init(H2O_STRLIT("bcd")), 0, &errstr, &erroffset);
    ok(re != NULL);

    nmatches = h2o_regexp_exec(re, h2o_iovec_init(H2O_STRLIT("abcde")), matches, sizeof(matches) / sizeof(matches[0]));
    ok(nmatches == 1);
    ok(h2o_memis(matches[0].base, matches[0].len, H2O_STRLIT("bcd")));

    nmatches = h2o_regexp_exec(re, h2o_iovec_init(H2O_STRLIT("bce")), matches, sizeof(matches) / sizeof(matches[0]));
    ok(nmatches == -1);

    h2o_regexp_destroy(re);
}
