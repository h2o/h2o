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
#include "../../../lib/string.c"

static void test_decode_base64(void)
{
    h2o_mem_pool_t pool;
        char buf[256];

    h2o_mem_init_pool(&pool);

    h2o_iovec_t src = { H2O_STRLIT("The quick brown fox jumps over the lazy dog.") }, decoded;
    h2o_base64_encode(buf, (const uint8_t*)src.base, src.len, 1);
    ok(strcmp(buf, "VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZy4") == 0);
    decoded = h2o_decode_base64url(&pool, buf, strlen(buf));
    ok(src.len == decoded.len);
    ok(strcmp(decoded.base, src.base) == 0);

    h2o_mem_clear_pool(&pool);
}

static void test_normalize_path(void)
{
    h2o_mem_pool_t pool;

    h2o_mem_init_pool(&pool);

    h2o_iovec_t b = h2o_normalize_path(&pool, H2O_STRLIT("/"));
    ok(b.len == 1);
    ok(memcmp(b.base, H2O_STRLIT("/")) == 0);

    b = h2o_normalize_path(&pool, H2O_STRLIT("/abc"));
    ok(b.len == 4);
    ok(memcmp(b.base, H2O_STRLIT("/abc")) == 0);

    b = h2o_normalize_path(&pool, H2O_STRLIT("/abc"));
    ok(b.len == 4);
    ok(memcmp(b.base, H2O_STRLIT("/abc")) == 0);

    b = h2o_normalize_path(&pool, H2O_STRLIT("/abc/../def"));
    ok(b.len == 4);
    ok(memcmp(b.base, H2O_STRLIT("/def")) == 0);

    b = h2o_normalize_path(&pool, H2O_STRLIT("/abc/../../def"));
    ok(b.len == 4);
    ok(memcmp(b.base, H2O_STRLIT("/def")) == 0);

    b = h2o_normalize_path(&pool, H2O_STRLIT("/abc/./def"));
    ok(b.len == 8);
    ok(memcmp(b.base, H2O_STRLIT("/abc/def")) == 0);

    b = h2o_normalize_path(&pool, H2O_STRLIT("/abc/def/.."));
    ok(b.len == 5);
    ok(memcmp(b.base, H2O_STRLIT("/abc/")) == 0);

    b = h2o_normalize_path(&pool, H2O_STRLIT("/abc/def/."));
    ok(b.len == 9);
    ok(memcmp(b.base, H2O_STRLIT("/abc/def/")) == 0);

    b = h2o_normalize_path(&pool, H2O_STRLIT("/abc?xx"));
    ok(b.len == 4);
    ok(memcmp(b.base, H2O_STRLIT("/abc")) == 0);

    b = h2o_normalize_path(&pool, H2O_STRLIT("/abc/../def?xx"));
    ok(b.len == 4);
    ok(memcmp(b.base, H2O_STRLIT("/def")) == 0);

    b = h2o_normalize_path(&pool, H2O_STRLIT("/a%62c"));
    ok(b.len == 4);
    ok(memcmp(b.base, H2O_STRLIT("/abc")) == 0);

    b = h2o_normalize_path(&pool, H2O_STRLIT("/a%6"));
    ok(b.len == 4);
    ok(memcmp(b.base, H2O_STRLIT("/a%6")) == 0);

    b = h2o_normalize_path(&pool, H2O_STRLIT("/a%6?"));
    ok(b.len == 4);
    ok(memcmp(b.base, H2O_STRLIT("/a%6")) == 0);

    h2o_mem_clear_pool(&pool);
}

static void test_parse_url(void)
{
    h2o_iovec_t scheme, host, path;
    uint16_t port;
    int ret;

    ret = h2o_parse_url("http://example.com/abc", SIZE_MAX, &scheme, &host, &port, &path);
    ok(ret == 0);
    ok(h2o_memis(scheme.base, scheme.len, H2O_STRLIT("http")));
    ok(h2o_memis(host.base, host.len, H2O_STRLIT("example.com")));
    ok(port == 80);
    ok(h2o_memis(path.base, path.len, H2O_STRLIT("/abc")));

    ret = h2o_parse_url("http://example.com", SIZE_MAX, &scheme, &host, &port, &path);
    ok(ret == 0);
    ok(h2o_memis(scheme.base, scheme.len, H2O_STRLIT("http")));
    ok(h2o_memis(host.base, host.len, H2O_STRLIT("example.com")));
    ok(port == 80);
    ok(h2o_memis(path.base, path.len, H2O_STRLIT("/")));

    ret = h2o_parse_url("http://example.com:81/abc", SIZE_MAX, &scheme, &host, &port, &path);
    ok(ret == 0);
    ok(h2o_memis(scheme.base, scheme.len, H2O_STRLIT("http")));
    ok(h2o_memis(host.base, host.len, H2O_STRLIT("example.com")));
    ok(port == 81);
    ok(h2o_memis(path.base, path.len, H2O_STRLIT("/abc")));

    ret = h2o_parse_url("http://example.com:81", SIZE_MAX, &scheme, &host, &port, &path);
    ok(ret == 0);
    ok(h2o_memis(scheme.base, scheme.len, H2O_STRLIT("http")));
    ok(h2o_memis(host.base, host.len, H2O_STRLIT("example.com")));
    ok(port == 81);
    ok(h2o_memis(path.base, path.len, H2O_STRLIT("/")));

    ret = h2o_parse_url("https://example.com/abc", SIZE_MAX, &scheme, &host, &port, &path);
    ok(ret == 0);
    ok(h2o_memis(scheme.base, scheme.len, H2O_STRLIT("https")));
    ok(h2o_memis(host.base, host.len, H2O_STRLIT("example.com")));
    ok(port == 443);
    ok(h2o_memis(path.base, path.len, H2O_STRLIT("/abc")));

    ret = h2o_parse_url("http:/abc", SIZE_MAX, &scheme, &host, &port, &path);
    ok(ret != 0);

    ret = h2o_parse_url("ftp://example.com/abc", SIZE_MAX, &scheme, &host, &port, &path);
    ok(ret != 0);

    ret = h2o_parse_url("http://abc:111111/def", SIZE_MAX, &scheme, &host, &port, &path);
    ok(ret != 0);

    ret = h2o_parse_url("http://[::ffff:192.0.2.128]", SIZE_MAX, &scheme, &host, &port, &path);
    ok(ret == 0);
    ok(h2o_memis(scheme.base, scheme.len, H2O_STRLIT("http")));
    ok(h2o_memis(host.base, host.len, H2O_STRLIT("::ffff:192.0.2.128")));
    ok(port == 80);
    ok(h2o_memis(path.base, path.len, H2O_STRLIT("/")));

    ret = h2o_parse_url("https://[::ffff:192.0.2.128]/abc", SIZE_MAX, &scheme, &host, &port, &path);
    ok(ret == 0);
    ok(h2o_memis(scheme.base, scheme.len, H2O_STRLIT("https")));
    ok(h2o_memis(host.base, host.len, H2O_STRLIT("::ffff:192.0.2.128")));
    ok(port == 443);
    ok(h2o_memis(path.base, path.len, H2O_STRLIT("/abc")));

    ret = h2o_parse_url("https://[::ffff:192.0.2.128]:111/abc", SIZE_MAX, &scheme, &host, &port, &path);
    ok(ret == 0);
    ok(h2o_memis(scheme.base, scheme.len, H2O_STRLIT("https")));
    ok(h2o_memis(host.base, host.len, H2O_STRLIT("::ffff:192.0.2.128")));
    ok(port == 111);
    ok(h2o_memis(path.base, path.len, H2O_STRLIT("/abc")));
}

static void test_htmlescape(void)
{
    h2o_mem_pool_t pool;
    h2o_mem_init_pool(&pool);

#define TEST(src, expected) \
    do { \
        h2o_iovec_t escaped = h2o_htmlescape(&pool, H2O_STRLIT(src)); \
        ok(h2o_memis(escaped.base, escaped.len, H2O_STRLIT(expected))); \
    } while (0)

    TEST("hello world", "hello world");
    TEST("x < y", "x &lt; y");
    TEST("\0\"&'<>", "\0&quot;&amp;&#39;&lt;&gt;");

#undef TEST

    h2o_mem_clear_pool(&pool);
}

void test_lib__string_c(void)
{
    subtest("decode_base64", test_decode_base64);
    subtest("normalize_path", test_normalize_path);
    subtest("parse_url", test_parse_url);
    subtest("htmlescape", test_htmlescape);
}
