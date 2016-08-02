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
#include "../../test.h"
#include "../../../../lib/handler/headers.c"

static int headers_are(h2o_mem_pool_t *pool, h2o_headers_t *headers, const char *s, size_t len)
{
    size_t i;
    h2o_iovec_t flattened = {NULL};

    for (i = 0; i != headers->size; ++i) {
        flattened = h2o_concat(pool, flattened, *headers->entries[i].name, h2o_iovec_init(H2O_STRLIT(": ")),
                               headers->entries[i].value, h2o_iovec_init(H2O_STRLIT("\n")));
    }

    return h2o_memis(flattened.base, flattened.len, s, len);
}

static void setup_headers(h2o_mem_pool_t *pool, h2o_headers_t *headers)
{
    *headers = (h2o_headers_t){NULL};
    h2o_add_header(pool, headers, H2O_TOKEN_CONTENT_TYPE, H2O_STRLIT("text/plain"));
    h2o_add_header(pool, headers, H2O_TOKEN_CACHE_CONTROL, H2O_STRLIT("public, max-age=86400"));
    h2o_add_header(pool, headers, H2O_TOKEN_SET_COOKIE, H2O_STRLIT("a=b"));
    h2o_add_header_by_str(pool, headers, H2O_STRLIT("x-foo"), 0, H2O_STRLIT("bar"));
}

void test_lib__handler__headers_c(void)
{
    h2o_mem_pool_t pool;
    h2o_headers_t headers;
    h2o_headers_command_t cmd;
    h2o_iovec_t header_str;

    h2o_mem_init_pool(&pool);

    /* tests using token headers */
    setup_headers(&pool, &headers);
    ok(headers_are(&pool, &headers,
                   H2O_STRLIT("content-type: text/plain\ncache-control: public, max-age=86400\nset-cookie: a=b\nx-foo: bar\n")));
    cmd = (h2o_headers_command_t){H2O_HEADERS_CMD_ADD, &H2O_TOKEN_SET_COOKIE->buf, {H2O_STRLIT("c=d")}};
    rewrite_headers(&pool, &headers, &cmd);
    ok(headers_are(
        &pool, &headers,
        H2O_STRLIT(
            "content-type: text/plain\ncache-control: public, max-age=86400\nset-cookie: a=b\nx-foo: bar\nset-cookie: c=d\n")));

    setup_headers(&pool, &headers);
    cmd = (h2o_headers_command_t){H2O_HEADERS_CMD_APPEND, &H2O_TOKEN_CACHE_CONTROL->buf, {H2O_STRLIT("public")}};
    rewrite_headers(&pool, &headers, &cmd);
    ok(headers_are(
        &pool, &headers,
        H2O_STRLIT("content-type: text/plain\ncache-control: public, max-age=86400, public\nset-cookie: a=b\nx-foo: bar\n")));

    setup_headers(&pool, &headers);
    cmd = (h2o_headers_command_t){H2O_HEADERS_CMD_MERGE, &H2O_TOKEN_CACHE_CONTROL->buf, {H2O_STRLIT("public")}};
    rewrite_headers(&pool, &headers, &cmd);
    ok(headers_are(&pool, &headers,
                   H2O_STRLIT("content-type: text/plain\ncache-control: public, max-age=86400\nset-cookie: a=b\nx-foo: bar\n")));

    setup_headers(&pool, &headers);
    cmd = (h2o_headers_command_t){H2O_HEADERS_CMD_SET, &H2O_TOKEN_CACHE_CONTROL->buf, {H2O_STRLIT("no-cache")}};
    rewrite_headers(&pool, &headers, &cmd);
    ok(headers_are(&pool, &headers,
                   H2O_STRLIT("content-type: text/plain\nset-cookie: a=b\nx-foo: bar\ncache-control: no-cache\n")));

    setup_headers(&pool, &headers);
    cmd = (h2o_headers_command_t){H2O_HEADERS_CMD_SETIFEMPTY, &H2O_TOKEN_CACHE_CONTROL->buf, {H2O_STRLIT("no-cache")}};
    rewrite_headers(&pool, &headers, &cmd);
    ok(headers_are(&pool, &headers,
                   H2O_STRLIT("content-type: text/plain\ncache-control: public, max-age=86400\nset-cookie: a=b\nx-foo: bar\n")));

    /* tests using non-token headers */
    header_str = h2o_iovec_init(H2O_STRLIT("x-foo"));
    setup_headers(&pool, &headers);
    cmd = (h2o_headers_command_t){H2O_HEADERS_CMD_ADD, &header_str, {H2O_STRLIT("baz")}};
    rewrite_headers(&pool, &headers, &cmd);
    ok(headers_are(
        &pool, &headers,
        H2O_STRLIT("content-type: text/plain\ncache-control: public, max-age=86400\nset-cookie: a=b\nx-foo: bar\nx-foo: baz\n")));

    setup_headers(&pool, &headers);
    cmd = (h2o_headers_command_t){H2O_HEADERS_CMD_APPEND, &header_str, {H2O_STRLIT("bar")}};
    rewrite_headers(&pool, &headers, &cmd);
    ok(headers_are(
        &pool, &headers,
        H2O_STRLIT("content-type: text/plain\ncache-control: public, max-age=86400\nset-cookie: a=b\nx-foo: bar, bar\n")));

    setup_headers(&pool, &headers);
    cmd = (h2o_headers_command_t){H2O_HEADERS_CMD_MERGE, &header_str, {H2O_STRLIT("bar")}};
    rewrite_headers(&pool, &headers, &cmd);
    ok(headers_are(&pool, &headers,
                   H2O_STRLIT("content-type: text/plain\ncache-control: public, max-age=86400\nset-cookie: a=b\nx-foo: bar\n")));

    setup_headers(&pool, &headers);
    cmd = (h2o_headers_command_t){H2O_HEADERS_CMD_SET, &header_str, {H2O_STRLIT("baz")}};
    rewrite_headers(&pool, &headers, &cmd);
    ok(headers_are(&pool, &headers,
                   H2O_STRLIT("content-type: text/plain\ncache-control: public, max-age=86400\nset-cookie: a=b\nx-foo: baz\n")));

    setup_headers(&pool, &headers);
    cmd = (h2o_headers_command_t){H2O_HEADERS_CMD_SETIFEMPTY, &header_str, {H2O_STRLIT("baz")}};
    rewrite_headers(&pool, &headers, &cmd);
    ok(headers_are(&pool, &headers,
                   H2O_STRLIT("content-type: text/plain\ncache-control: public, max-age=86400\nset-cookie: a=b\nx-foo: bar\n")));

    h2o_mem_clear_pool(&pool);
}
