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

static void test_strstr(void)
{
    ok(h2o_strstr("abcd", 4, "bc", 2) == 1);
    ok(h2o_strstr("abcd", 3, "bc", 2) == 1);
    ok(h2o_strstr("abcd", 2, "bc", 2) == -1);
}

static void test_stripws(void)
{
    h2o_iovec_t t;

    t = h2o_str_stripws(H2O_STRLIT(""));
    ok(h2o_memis(t.base, t.len, H2O_STRLIT("")));
    t = h2o_str_stripws(H2O_STRLIT("hello world"));
    ok(h2o_memis(t.base, t.len, H2O_STRLIT("hello world")));
    t = h2o_str_stripws(H2O_STRLIT("   hello world"));
    ok(h2o_memis(t.base, t.len, H2O_STRLIT("hello world")));
    t = h2o_str_stripws(H2O_STRLIT("hello world   "));
    ok(h2o_memis(t.base, t.len, H2O_STRLIT("hello world")));
    t = h2o_str_stripws(H2O_STRLIT("   hello world   "));
    ok(h2o_memis(t.base, t.len, H2O_STRLIT("hello world")));
    t = h2o_str_stripws(H2O_STRLIT("     "));
    ok(h2o_memis(t.base, t.len, H2O_STRLIT("")));
}

static void test_get_filext(void)
{
    h2o_iovec_t ext;

    ext = h2o_get_filext(H2O_STRLIT("/abc.txt"));
    ok(h2o_memis(ext.base, ext.len, H2O_STRLIT("txt")));
    ext = h2o_get_filext(H2O_STRLIT("/abc.txt.gz"));
    ok(h2o_memis(ext.base, ext.len, H2O_STRLIT("gz")));
    ext = h2o_get_filext(H2O_STRLIT("/abc."));
    ok(h2o_memis(ext.base, ext.len, H2O_STRLIT("")));
    ext = h2o_get_filext(H2O_STRLIT("/abc"));
    ok(ext.base == NULL);
    ext = h2o_get_filext(H2O_STRLIT("/abc.def/abc"));
    ok(ext.base == NULL);
    ext = h2o_get_filext(H2O_STRLIT("/abc.def/"));
    ok(ext.base == NULL);
}

static void test_next_token(void)
{
    h2o_iovec_t iter;
    const char *token;
    size_t token_len;

#define NEXT()                                                                                                                     \
    if ((token = h2o_next_token(&iter, ',', &token_len, NULL)) == NULL) {                                                          \
        ok(0);                                                                                                                     \
        return;                                                                                                                    \
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

#define NEXT()                                                                                                                     \
    if ((name = h2o_next_token(&iter, ',', &name_len, &value)) == NULL) {                                                          \
        ok(0);                                                                                                                     \
        return;                                                                                                                    \
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

static void test_next_token3(void)
{
    h2o_iovec_t iter, value;
    const char *name;
    size_t name_len;

#define NEXT()                                                                                                                     \
    if ((name = h2o_next_token(&iter, ';', &name_len, &value)) == NULL) {                                                          \
        ok(0);                                                                                                                     \
        return;                                                                                                                    \
    }

    iter = h2o_iovec_init(H2O_STRLIT("</foo.css>; rel=preload; xxx=,</bar.js>, </zzz.js>"));
    NEXT();
    ok(h2o_memis(name, name_len, H2O_STRLIT("</foo.css>")));
    ok(value.base == NULL);
    ok(value.len == 0);
    NEXT();
    ok(h2o_memis(name, name_len, H2O_STRLIT("rel")));
    ok(h2o_memis(value.base, value.len, H2O_STRLIT("preload")));
    NEXT();
    ok(h2o_memis(name, name_len, H2O_STRLIT("xxx")));
    ok(value.base != NULL); /* xxx _has_ a value! */
    ok(value.len == 0);
    NEXT();
    ok(h2o_memis(name, name_len, H2O_STRLIT(",")));
    ok(value.base == NULL);
    ok(value.len == 0);
    NEXT();
    ok(h2o_memis(name, name_len, H2O_STRLIT("</bar.js>")));
    ok(value.base == NULL);
    ok(value.len == 0);
    NEXT();
    ok(h2o_memis(name, name_len, H2O_STRLIT(",")));
    ok(value.base == NULL);
    ok(value.len == 0);
    NEXT();
    ok(h2o_memis(name, name_len, H2O_STRLIT("</zzz.js>")));
    ok(value.base == NULL);
    ok(value.len == 0);
    name = h2o_next_token(&iter, ',', &name_len, &value);
    ok(name == NULL);

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

static void test_uri_escape(void)
{
    h2o_mem_pool_t pool;
    h2o_mem_init_pool(&pool);

#define TEST(src, preserve, expected)                                                                                              \
    do {                                                                                                                           \
        h2o_iovec_t escaped = h2o_uri_escape(&pool, H2O_STRLIT(src), preserve);                                                    \
        ok(h2o_memis(escaped.base, escaped.len, H2O_STRLIT(expected)));                                                            \
    } while (0)

    TEST("abc", NULL, "abc");
    TEST("a/c", NULL, "a%2Fc");
    TEST("a/c", "/", "a/c");
    TEST("\xe3\x81\x82", NULL, "%E3%81%82");
    TEST("a\0!", NULL, "a%00!");
    TEST("a/\0!", "/", "a/%00!");

#undef TEST

    h2o_mem_clear_pool(&pool);
}

static void test_at_position(void)
{
    char buf[160];
    int ret;

    /* normal cases */
    ret = h2o_str_at_position(buf, H2O_STRLIT("hello\nworld\n"), 1, 1);
    ok(ret == 0);
    ok(strcmp(buf, "hello\n^\n") == 0);

    ret = h2o_str_at_position(buf, H2O_STRLIT("hello\nworld\n"), 1, 5);
    ok(ret == 0);
    ok(strcmp(buf, "hello\n    ^\n") == 0);

    ret = h2o_str_at_position(buf, H2O_STRLIT("hello\nworld\n"), 1, 6);
    ok(ret == 0);
    ok(strcmp(buf, "hello\n     ^\n") == 0);

    ret = h2o_str_at_position(buf, H2O_STRLIT("hello\nworld\n"), 1, 7);
    ok(ret == 0);
    ok(strcmp(buf, "hello\n     ^\n") == 0);

    ret = h2o_str_at_position(buf, H2O_STRLIT("hello\nworld\n"), 2, 1);
    ok(ret == 0);
    ok(strcmp(buf, "world\n^\n") == 0);

    ret = h2o_str_at_position(buf, H2O_STRLIT("hello\nworld\n"), 2, 5);
    ok(ret == 0);
    ok(strcmp(buf, "world\n    ^\n") == 0);

    ret = h2o_str_at_position(buf, H2O_STRLIT("hello\nworld\n"), 1, 7);
    ok(ret == 0);
    ok(strcmp(buf, "hello\n     ^\n") == 0);

    ret = h2o_str_at_position(
        buf, H2O_STRLIT("_________1_________2_________3_________4_________5_________6_________7_________\nworld\n"), 1, 5);
    ok(ret == 0);
    ok(strcmp(buf, "_________1_________2_________3_________4_________5_________6_________7______\n    ^\n") == 0);

    ret = h2o_str_at_position(
        buf, H2O_STRLIT("_________1_________2_________3_________4_________5_________6_________7_________\nworld\n"), 1, 60);
    ok(ret == 0);
    ok(strcmp(buf, "_________3_________4_________5_________6_________7_________\n                                       ^\n") == 0);

    ret = h2o_str_at_position(buf, H2O_STRLIT("hello"), 1, 20);
    ok(ret == 0);
    ok(strcmp(buf, "hello\n     ^\n") == 0);

    /* error cases */
    ret = h2o_str_at_position(buf, H2O_STRLIT("hello\nworld\n"), 0, 1);
    ok(ret != 0);

    ret = h2o_str_at_position(buf, H2O_STRLIT("hello\nworld\n"), 1, 0);
    ok(ret != 0);

    ret = h2o_str_at_position(buf, H2O_STRLIT("hello\nworld\n"), 4, 1);
    ok(ret != 0);
}

void test_lib__common__string_c(void)
{
    subtest("strstr", test_strstr);
    subtest("stripws", test_stripws);
    subtest("get_filext", test_get_filext);
    subtest("next_token", test_next_token);
    subtest("next_token2", test_next_token2);
    subtest("next_token3", test_next_token3);
    subtest("decode_base64", test_decode_base64);
    subtest("htmlescape", test_htmlescape);
    subtest("uri_escape", test_uri_escape);
    subtest("at_position", test_at_position);
}
