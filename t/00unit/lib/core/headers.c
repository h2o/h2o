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
#include "../../test.h"
#include "../../../../lib/core/headers.c"

static void test_set_header_token(void)
{
    h2o_mem_pool_t pool;
    h2o_headers_t headers = {NULL};

    h2o_mem_init_pool(&pool);

    h2o_set_header_token(&pool, &headers, H2O_TOKEN_VARY, H2O_STRLIT("cookie"));
    ok(headers.size == 1);
    ok(headers.entries[0].name == &H2O_TOKEN_VARY->buf);
    ok(h2o_memis(headers.entries[0].value.base, headers.entries[0].value.len, H2O_STRLIT("cookie")));
    h2o_set_header_token(&pool, &headers, H2O_TOKEN_VARY, H2O_STRLIT("accept-encoding"));
    ok(headers.size == 1);
    ok(headers.entries[0].name == &H2O_TOKEN_VARY->buf);
    ok(h2o_memis(headers.entries[0].value.base, headers.entries[0].value.len, H2O_STRLIT("cookie, accept-encoding")));

    headers.entries[0].value.base[0] = 'C';
    h2o_set_header_token(&pool, &headers, H2O_TOKEN_VARY, H2O_STRLIT("cookie"));
    ok(headers.size == 1);
    ok(headers.entries[0].name == &H2O_TOKEN_VARY->buf);
    ok(h2o_memis(headers.entries[0].value.base, headers.entries[0].value.len, H2O_STRLIT("Cookie, accept-encoding")));

    h2o_mem_clear_pool(&pool);
}

void test_lib__core__headers_c(void)
{
    subtest("set_header_token", test_set_header_token);
}
