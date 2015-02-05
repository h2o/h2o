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
#include "../../../../lib/common/string.c"

static void test_next_token(void)
{
    h2o_iovec_t iter;
    const char *token;
    size_t token_len;

#define NEXT() \
    if ((token = h2o_next_token(&iter, ',', &token_len, NULL)) == NULL) { \
        ok(0); \
        return; \
    }

    iter = h2o_iovec_init(H2O_STRLIT("public, max-age=86400, must-revalidate"));
    NEXT();
    ok(h2o_memis(token, token_len, H2O_STRLIT("public")));
    NEXT();
    ok(h2o_memis(token, token_len, H2O_STRLIT("max-age=86400")));
    NEXT();
    ok(h2o_memis(token, token_len, H2O_STRLIT("must-revalidate")));
    token = h2o_next_token(&iter, ',', &token_len, NULL);
    ok(token == NULL);

    iter = h2o_iovec_init(H2O_STRLIT("  public  ,max-age=86400  ,"));
    NEXT();
    ok(h2o_memis(token, token_len, H2O_STRLIT("public")));
    NEXT();
    ok(h2o_memis(token, token_len, H2O_STRLIT("max-age=86400")));
    token = h2o_next_token(&iter, ',', &token_len, NULL);
    ok(token == NULL);

    iter = h2o_iovec_init(H2O_STRLIT(""));
    token = h2o_next_token(&iter, ',', &token_len, NULL);
    ok(token == NULL);

    iter = h2o_iovec_init(H2O_STRLIT(", ,a, "));
    NEXT();
    ok(token_len == 0);
    NEXT();
    ok(token_len == 0);
    NEXT();
    ok(h2o_memis(token, token_len, H2O_STRLIT("a")));
    token = h2o_next_token(&iter, ',', &token_len, NULL);
    ok(token == NULL);

#undef NEXT
}

static void test_next_token2(void)
{
    h2o_iovec_t iter, value;
    const char *name;
    size_t name_len;

#define NEXT() \
    if ((name = h2o_next_token(&iter, ',', &name_len, &value)) == NULL) { \
        ok(0); \
        return; \
    }

    iter = h2o_iovec_init(H2O_STRLIT("public, max-age=86400, must-revalidate"));
    NEXT();
    ok(h2o_memis(name, name_len, H2O_STRLIT("public")));
    ok(value.base == NULL);
    ok(value.len == 0);
    NEXT();
    ok(h2o_memis(name, name_len, H2O_STRLIT("max-age")));
    ok(h2o_memis(value.base, value.len, H2O_STRLIT("86400")));
    NEXT();
    ok(h2o_memis(name, name_len, H2O_STRLIT("must-revalidate")));
    ok(value.base == NULL);
    ok(value.len == 0);
    name = h2o_next_token(&iter, ',', &name_len, &value);
    ok(name == NULL);

    iter = h2o_iovec_init(H2O_STRLIT("public, max-age = 86400 = c , must-revalidate="));
    NEXT();
    ok(h2o_memis(name, name_len, H2O_STRLIT("public")));
    ok(value.base == NULL);
    ok(value.len == 0);
    NEXT();
    ok(h2o_memis(name, name_len, H2O_STRLIT("max-age")));
    ok(h2o_memis(value.base, value.len, H2O_STRLIT("86400 = c")));
    NEXT();
    ok(h2o_memis(name, name_len, H2O_STRLIT("must-revalidate")));
    name = h2o_next_token(&iter, ',', &name_len, &value);
    ok(h2o_memis(value.base, value.len, H2O_STRLIT("")));

#undef NEXT
}

static void test_decode_base64(void)
{
    h2o_mem_pool_t pool;
    char buf[256];

    h2o_mem_init_pool(&pool);

    h2o_iovec_t src = {H2O_STRLIT("The quick brown fox jumps over the lazy dog.")}, decoded;
    h2o_base64_encode(buf, (const uint8_t *)src.base, src.len, 1);
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
    h2o_parse_url_t parsed;
    int ret;

    ret = h2o_parse_url("http://example.com/abc", SIZE_MAX, &parsed);
    ok(ret == 0);
    ok(h2o_memis(parsed.scheme.base, parsed.scheme.len, H2O_STRLIT("http")));
    ok(h2o_memis(parsed.authority.base, parsed.authority.len, H2O_STRLIT("example.com")));
    ok(h2o_memis(parsed.host.base, parsed.host.len, H2O_STRLIT("example.com")));
    ok(parsed.port == 80);
    ok(h2o_memis(parsed.path.base, parsed.path.len, H2O_STRLIT("/abc")));

    ret = h2o_parse_url("http://example.com", SIZE_MAX, &parsed);
    ok(ret == 0);
    ok(h2o_memis(parsed.scheme.base, parsed.scheme.len, H2O_STRLIT("http")));
    ok(h2o_memis(parsed.authority.base, parsed.authority.len, H2O_STRLIT("example.com")));
    ok(h2o_memis(parsed.host.base, parsed.host.len, H2O_STRLIT("example.com")));
    ok(parsed.port == 80);
    ok(h2o_memis(parsed.path.base, parsed.path.len, H2O_STRLIT("/")));

    ret = h2o_parse_url("http://example.com:81/abc", SIZE_MAX, &parsed);
    ok(ret == 0);
    ok(h2o_memis(parsed.scheme.base, parsed.scheme.len, H2O_STRLIT("http")));
    ok(h2o_memis(parsed.authority.base, parsed.authority.len, H2O_STRLIT("example.com:81")));
    ok(h2o_memis(parsed.host.base, parsed.host.len, H2O_STRLIT("example.com")));
    ok(parsed.port == 81);
    ok(h2o_memis(parsed.path.base, parsed.path.len, H2O_STRLIT("/abc")));

    ret = h2o_parse_url("http://example.com:81", SIZE_MAX, &parsed);
    ok(ret == 0);
    ok(h2o_memis(parsed.scheme.base, parsed.scheme.len, H2O_STRLIT("http")));
    ok(h2o_memis(parsed.authority.base, parsed.authority.len, H2O_STRLIT("example.com:81")));
    ok(h2o_memis(parsed.host.base, parsed.host.len, H2O_STRLIT("example.com")));
    ok(parsed.port == 81);
    ok(h2o_memis(parsed.path.base, parsed.path.len, H2O_STRLIT("/")));

    ret = h2o_parse_url("https://example.com/abc", SIZE_MAX, &parsed);
    ok(ret == 0);
    ok(h2o_memis(parsed.scheme.base, parsed.scheme.len, H2O_STRLIT("https")));
    ok(h2o_memis(parsed.authority.base, parsed.authority.len, H2O_STRLIT("example.com")));
    ok(h2o_memis(parsed.host.base, parsed.host.len, H2O_STRLIT("example.com")));
    ok(parsed.port == 443);
    ok(h2o_memis(parsed.path.base, parsed.path.len, H2O_STRLIT("/abc")));

    ret = h2o_parse_url("http:/abc", SIZE_MAX, &parsed);
    ok(ret != 0);

    ret = h2o_parse_url("ftp://example.com/abc", SIZE_MAX, &parsed);
    ok(ret != 0);

    ret = h2o_parse_url("http://abc:111111/def", SIZE_MAX, &parsed);
    ok(ret != 0);

    ret = h2o_parse_url("http://[::ffff:192.0.2.128]", SIZE_MAX, &parsed);
    ok(ret == 0);
    ok(h2o_memis(parsed.scheme.base, parsed.scheme.len, H2O_STRLIT("http")));
    ok(h2o_memis(parsed.authority.base, parsed.authority.len, H2O_STRLIT("[::ffff:192.0.2.128]")));
    ok(h2o_memis(parsed.host.base, parsed.host.len, H2O_STRLIT("::ffff:192.0.2.128")));
    ok(parsed.port == 80);
    ok(h2o_memis(parsed.path.base, parsed.path.len, H2O_STRLIT("/")));

    ret = h2o_parse_url("https://[::ffff:192.0.2.128]/abc", SIZE_MAX, &parsed);
    ok(ret == 0);
    ok(h2o_memis(parsed.scheme.base, parsed.scheme.len, H2O_STRLIT("https")));
    ok(h2o_memis(parsed.authority.base, parsed.authority.len, H2O_STRLIT("[::ffff:192.0.2.128]")));
    ok(h2o_memis(parsed.host.base, parsed.host.len, H2O_STRLIT("::ffff:192.0.2.128")));
    ok(parsed.port == 443);
    ok(h2o_memis(parsed.path.base, parsed.path.len, H2O_STRLIT("/abc")));

    ret = h2o_parse_url("https://[::ffff:192.0.2.128]:111/abc", SIZE_MAX, &parsed);
    ok(ret == 0);
    ok(h2o_memis(parsed.scheme.base, parsed.scheme.len, H2O_STRLIT("https")));
    ok(h2o_memis(parsed.authority.base, parsed.authority.len, H2O_STRLIT("[::ffff:192.0.2.128]:111")));
    ok(h2o_memis(parsed.host.base, parsed.host.len, H2O_STRLIT("::ffff:192.0.2.128")));
    ok(parsed.port == 111);
    ok(h2o_memis(parsed.path.base, parsed.path.len, H2O_STRLIT("/abc")));
}

static void test_htmlescape(void)
{
    h2o_mem_pool_t pool;
    h2o_mem_init_pool(&pool);

#define TEST(src, expected)                                                                                                        \
    do {                                                                                                                           \
        h2o_iovec_t escaped = h2o_htmlescape(&pool, H2O_STRLIT(src));                                                              \
        ok(h2o_memis(escaped.base, escaped.len, H2O_STRLIT(expected)));                                                            \
    } while (0)

    TEST("hello world", "hello world");
    TEST("x < y", "x &lt; y");
    TEST("\0\"&'<>", "\0&quot;&amp;&#39;&lt;&gt;");

#undef TEST

    h2o_mem_clear_pool(&pool);
}

void test_lib__string_c(void)
{
    subtest("next_token", test_next_token);
    subtest("next_token2", test_next_token2);
    subtest("decode_base64", test_decode_base64);
    subtest("normalize_path", test_normalize_path);
    subtest("parse_url", test_parse_url);
    subtest("htmlescape", test_htmlescape);
}
