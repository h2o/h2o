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
#include "../../test.h"
#include "../../../../lib/common/url.c"

static void test_normalize_path(void)
{
    h2o_mem_pool_t pool;

    h2o_mem_init_pool(&pool);

    size_t q;
    h2o_iovec_t b = h2o_url_normalize_path(&pool, H2O_STRLIT("/"), &q);
    ok(b.len == 1);
    ok(memcmp(b.base, H2O_STRLIT("/")) == 0);
    ok(q == SIZE_MAX);

    b = h2o_url_normalize_path(&pool, H2O_STRLIT("/abc"), &q);
    ok(b.len == 4);
    ok(memcmp(b.base, H2O_STRLIT("/abc")) == 0);
    ok(q == SIZE_MAX);

    b = h2o_url_normalize_path(&pool, H2O_STRLIT("/abc"), &q);
    ok(b.len == 4);
    ok(memcmp(b.base, H2O_STRLIT("/abc")) == 0);
    ok(q == SIZE_MAX);

    b = h2o_url_normalize_path(&pool, H2O_STRLIT("/abc/../def"), &q);
    ok(b.len == 4);
    ok(memcmp(b.base, H2O_STRLIT("/def")) == 0);
    ok(q == SIZE_MAX);

    b = h2o_url_normalize_path(&pool, H2O_STRLIT("/abc/../../def"), &q);
    ok(b.len == 4);
    ok(memcmp(b.base, H2O_STRLIT("/def")) == 0);
    ok(q == SIZE_MAX);

    b = h2o_url_normalize_path(&pool, H2O_STRLIT("/abc/./def"), &q);
    ok(b.len == 8);
    ok(memcmp(b.base, H2O_STRLIT("/abc/def")) == 0);
    ok(q == SIZE_MAX);

    b = h2o_url_normalize_path(&pool, H2O_STRLIT("/abc/def/.."), &q);
    ok(b.len == 5);
    ok(memcmp(b.base, H2O_STRLIT("/abc/")) == 0);
    ok(q == SIZE_MAX);

    b = h2o_url_normalize_path(&pool, H2O_STRLIT("/abc/def/."), &q);
    ok(b.len == 9);
    ok(memcmp(b.base, H2O_STRLIT("/abc/def/")) == 0);
    ok(q == SIZE_MAX);

    b = h2o_url_normalize_path(&pool, H2O_STRLIT("/abc?xx"), &q);
    ok(b.len == 4);
    ok(memcmp(b.base, H2O_STRLIT("/abc")) == 0);
    ok(q == 4);

    b = h2o_url_normalize_path(&pool, H2O_STRLIT("/abc/../def?xx"), &q);
    ok(b.len == 4);
    ok(memcmp(b.base, H2O_STRLIT("/def")) == 0);
    ok(q == 11);

    b = h2o_url_normalize_path(&pool, H2O_STRLIT("/a%62c"), &q);
    ok(b.len == 4);
    ok(memcmp(b.base, H2O_STRLIT("/abc")) == 0);
    ok(q == SIZE_MAX);

    b = h2o_url_normalize_path(&pool, H2O_STRLIT("/a%6"), &q);
    ok(b.len == 4);
    ok(memcmp(b.base, H2O_STRLIT("/a%6")) == 0);
    ok(q == SIZE_MAX);

    b = h2o_url_normalize_path(&pool, H2O_STRLIT("/a%6?"), &q);
    ok(b.len == 4);
    ok(memcmp(b.base, H2O_STRLIT("/a%6")) == 0);
    ok(q == 4);

    h2o_mem_clear_pool(&pool);
}

static void test_parse(void)
{
    h2o_url_t parsed;
    int ret;

    ret = h2o_url_parse("http://example.com/abc", SIZE_MAX, &parsed);
    ok(ret == 0);
    ok(parsed.scheme == &H2O_URL_SCHEME_HTTP);
    ok(h2o_memis(parsed.authority.base, parsed.authority.len, H2O_STRLIT("example.com")));
    ok(h2o_memis(parsed.host.base, parsed.host.len, H2O_STRLIT("example.com")));
    ok(parsed._port == 65535);
    ok(h2o_url_get_port(&parsed) == 80);
    ok(h2o_memis(parsed.path.base, parsed.path.len, H2O_STRLIT("/abc")));

    ret = h2o_url_parse("http://example.com", SIZE_MAX, &parsed);
    ok(ret == 0);
    ok(parsed.scheme == &H2O_URL_SCHEME_HTTP);
    ok(h2o_memis(parsed.authority.base, parsed.authority.len, H2O_STRLIT("example.com")));
    ok(h2o_memis(parsed.host.base, parsed.host.len, H2O_STRLIT("example.com")));
    ok(parsed._port == 65535);
    ok(h2o_url_get_port(&parsed) == 80);
    ok(h2o_memis(parsed.path.base, parsed.path.len, H2O_STRLIT("/")));

    ret = h2o_url_parse("http://example.com:81/abc", SIZE_MAX, &parsed);
    ok(ret == 0);
    ok(parsed.scheme == &H2O_URL_SCHEME_HTTP);
    ok(h2o_memis(parsed.authority.base, parsed.authority.len, H2O_STRLIT("example.com:81")));
    ok(h2o_memis(parsed.host.base, parsed.host.len, H2O_STRLIT("example.com")));
    ok(parsed._port == 81);
    ok(h2o_url_get_port(&parsed) == 81);
    ok(h2o_memis(parsed.path.base, parsed.path.len, H2O_STRLIT("/abc")));

    ret = h2o_url_parse("http://example.com:81", SIZE_MAX, &parsed);
    ok(ret == 0);
    ok(parsed.scheme == &H2O_URL_SCHEME_HTTP);
    ok(h2o_memis(parsed.authority.base, parsed.authority.len, H2O_STRLIT("example.com:81")));
    ok(h2o_memis(parsed.host.base, parsed.host.len, H2O_STRLIT("example.com")));
    ok(parsed._port == 81);
    ok(h2o_url_get_port(&parsed) == 81);
    ok(h2o_memis(parsed.path.base, parsed.path.len, H2O_STRLIT("/")));

    ret = h2o_url_parse("https://example.com/abc", SIZE_MAX, &parsed);
    ok(ret == 0);
    ok(parsed.scheme == &H2O_URL_SCHEME_HTTPS);
    ok(h2o_memis(parsed.authority.base, parsed.authority.len, H2O_STRLIT("example.com")));
    ok(h2o_memis(parsed.host.base, parsed.host.len, H2O_STRLIT("example.com")));
    ok(parsed._port == 65535);
    ok(h2o_url_get_port(&parsed) == 443);
    ok(h2o_memis(parsed.path.base, parsed.path.len, H2O_STRLIT("/abc")));

    ret = h2o_url_parse("http:/abc", SIZE_MAX, &parsed);
    ok(ret != 0);

    ret = h2o_url_parse("ftp://example.com/abc", SIZE_MAX, &parsed);
    ok(ret != 0);

    ret = h2o_url_parse("http://abc:111111/def", SIZE_MAX, &parsed);
    ok(ret != 0);

    ret = h2o_url_parse("http://[::ffff:192.0.2.128]", SIZE_MAX, &parsed);
    ok(ret == 0);
    ok(parsed.scheme == &H2O_URL_SCHEME_HTTP);
    ok(h2o_memis(parsed.authority.base, parsed.authority.len, H2O_STRLIT("[::ffff:192.0.2.128]")));
    ok(h2o_memis(parsed.host.base, parsed.host.len, H2O_STRLIT("::ffff:192.0.2.128")));
    ok(parsed._port == 65535);
    ok(h2o_url_get_port(&parsed) == 80);
    ok(h2o_memis(parsed.path.base, parsed.path.len, H2O_STRLIT("/")));

    ret = h2o_url_parse("https://[::ffff:192.0.2.128]/abc", SIZE_MAX, &parsed);
    ok(ret == 0);
    ok(parsed.scheme == &H2O_URL_SCHEME_HTTPS);
    ok(h2o_memis(parsed.authority.base, parsed.authority.len, H2O_STRLIT("[::ffff:192.0.2.128]")));
    ok(h2o_memis(parsed.host.base, parsed.host.len, H2O_STRLIT("::ffff:192.0.2.128")));
    ok(parsed._port == 65535);
    ok(h2o_url_get_port(&parsed) == 443);
    ok(h2o_memis(parsed.path.base, parsed.path.len, H2O_STRLIT("/abc")));

    ret = h2o_url_parse("https://[::ffff:192.0.2.128]:111/abc", SIZE_MAX, &parsed);
    ok(ret == 0);
    ok(parsed.scheme == &H2O_URL_SCHEME_HTTPS);
    ok(h2o_memis(parsed.authority.base, parsed.authority.len, H2O_STRLIT("[::ffff:192.0.2.128]:111")));
    ok(h2o_memis(parsed.host.base, parsed.host.len, H2O_STRLIT("::ffff:192.0.2.128")));
    ok(parsed._port == 111);
    ok(h2o_url_get_port(&parsed) == 111);
    ok(h2o_memis(parsed.path.base, parsed.path.len, H2O_STRLIT("/abc")));
}

static void test_parse_relative(void)
{
    h2o_url_t parsed;
    int ret;

    memset(&parsed, 0x55, sizeof(parsed));
    ret = h2o_url_parse_relative("abc", SIZE_MAX, &parsed);
    ok(ret == 0);
    ok(parsed.scheme == NULL);
    ok(parsed.authority.base == NULL);
    ok(parsed.host.base == NULL);
    ok(parsed._port == 65535);
    ok(h2o_memis(parsed.path.base, parsed.path.len, H2O_STRLIT("abc")));

    memset(&parsed, 0x55, sizeof(parsed));
    ret = h2o_url_parse_relative("/abc", SIZE_MAX, &parsed);
    ok(ret == 0);
    ok(parsed.scheme == NULL);
    ok(parsed.authority.base == NULL);
    ok(parsed.host.base == NULL);
    ok(parsed._port == 65535);
    ok(h2o_memis(parsed.path.base, parsed.path.len, H2O_STRLIT("/abc")));

    memset(&parsed, 0x55, sizeof(parsed));
    ret = h2o_url_parse_relative("http:abc", SIZE_MAX, &parsed);
    ok(ret == 0);
    ok(parsed.scheme == &H2O_URL_SCHEME_HTTP);
    ok(parsed.authority.base == NULL);
    ok(parsed.host.base == NULL);
    ok(parsed._port == 65535);
    ok(h2o_memis(parsed.path.base, parsed.path.len, H2O_STRLIT("abc")));

    memset(&parsed, 0x55, sizeof(parsed));
    ret = h2o_url_parse_relative("//host", SIZE_MAX, &parsed);
    ok(ret == 0);
    ok(parsed.scheme == NULL);
    ok(h2o_memis(parsed.authority.base, parsed.authority.len, H2O_STRLIT("host")));
    ok(h2o_memis(parsed.host.base, parsed.host.len, H2O_STRLIT("host")));
    ok(parsed._port == 65535);
    ok(h2o_memis(parsed.path.base, parsed.path.len, H2O_STRLIT("/")));

    memset(&parsed, 0x55, sizeof(parsed));
    ret = h2o_url_parse_relative("//host:12345/path", SIZE_MAX, &parsed);
    ok(ret == 0);
    ok(parsed.scheme == NULL);
    ok(h2o_memis(parsed.authority.base, parsed.authority.len, H2O_STRLIT("host:12345")));
    ok(h2o_memis(parsed.host.base, parsed.host.len, H2O_STRLIT("host")));
    ok(parsed._port == 12345);
    ok(h2o_memis(parsed.path.base, parsed.path.len, H2O_STRLIT("/path")));

    memset(&parsed, 0x55, sizeof(parsed));
    ret = h2o_url_parse_relative("https://host:12345/path", SIZE_MAX, &parsed);
    ok(ret == 0);
    ok(parsed.scheme == &H2O_URL_SCHEME_HTTPS);
    ok(h2o_memis(parsed.authority.base, parsed.authority.len, H2O_STRLIT("host:12345")));
    ok(h2o_memis(parsed.host.base, parsed.host.len, H2O_STRLIT("host")));
    ok(parsed._port == 12345);
    ok(h2o_memis(parsed.path.base, parsed.path.len, H2O_STRLIT("/path")));
}

static void test_resolve(void)
{
    h2o_mem_pool_t pool;
    h2o_url_t base, relative, resolved;
    h2o_iovec_t final;
    int ret;

    h2o_mem_init_pool(&pool);

    ret = h2o_url_parse("http://example.com/dir/index.html", SIZE_MAX, &base);
    ok(ret == 0);

    ret = h2o_url_parse_relative("../assets/jquery.js", SIZE_MAX, &relative);
    ok(ret == 0);
    final = h2o_url_resolve(&pool, &base, &relative, &resolved);
    ok(h2o_memis(final.base, final.len, H2O_STRLIT("http://example.com/assets/jquery.js")));
    ok(resolved.scheme == &H2O_URL_SCHEME_HTTP);
    ok(h2o_memis(resolved.authority.base, resolved.authority.len, H2O_STRLIT("example.com")));
    ok(h2o_memis(resolved.host.base, resolved.host.len, H2O_STRLIT("example.com")));
    ok(resolved._port == 65535);
    ok(h2o_url_get_port(&resolved) == 80);
    ok(h2o_memis(resolved.path.base, resolved.path.len, H2O_STRLIT("/assets/jquery.js")));

    ret = h2o_url_parse_relative("foo.html", SIZE_MAX, &relative);
    ok(ret == 0);
    final = h2o_url_resolve(&pool, &base, &relative, &resolved);
    ok(h2o_memis(final.base, final.len, H2O_STRLIT("http://example.com/dir/foo.html")));
    ok(resolved.scheme == &H2O_URL_SCHEME_HTTP);
    ok(h2o_memis(resolved.authority.base, resolved.authority.len, H2O_STRLIT("example.com")));
    ok(h2o_memis(resolved.host.base, resolved.host.len, H2O_STRLIT("example.com")));
    ok(resolved._port == 65535);
    ok(h2o_url_get_port(&resolved) == 80);
    ok(h2o_memis(resolved.path.base, resolved.path.len, H2O_STRLIT("/dir/foo.html")));

    ret = h2o_url_parse_relative("./bar.txt", SIZE_MAX, &relative);
    ok(ret == 0);
    final = h2o_url_resolve(&pool, &base, &relative, &resolved);
    ok(h2o_memis(final.base, final.len, H2O_STRLIT("http://example.com/dir/bar.txt")));
    ok(resolved.scheme == &H2O_URL_SCHEME_HTTP);
    ok(h2o_memis(resolved.authority.base, resolved.authority.len, H2O_STRLIT("example.com")));
    ok(h2o_memis(resolved.host.base, resolved.host.len, H2O_STRLIT("example.com")));
    ok(resolved._port == 65535);
    ok(h2o_url_get_port(&resolved) == 80);
    ok(h2o_memis(resolved.path.base, resolved.path.len, H2O_STRLIT("/dir/bar.txt")));

    ret = h2o_url_parse_relative("../../../traverse", SIZE_MAX, &relative);
    ok(ret == 0);
    final = h2o_url_resolve(&pool, &base, &relative, &resolved);
    ok(h2o_memis(final.base, final.len, H2O_STRLIT("http://example.com/traverse")));
    ok(resolved.scheme == &H2O_URL_SCHEME_HTTP);
    ok(h2o_memis(resolved.authority.base, resolved.authority.len, H2O_STRLIT("example.com")));
    ok(h2o_memis(resolved.host.base, resolved.host.len, H2O_STRLIT("example.com")));
    ok(resolved._port == 65535);
    ok(h2o_url_get_port(&resolved) == 80);
    ok(h2o_memis(resolved.path.base, resolved.path.len, H2O_STRLIT("/traverse")));

    ret = h2o_url_parse_relative("http:foo.html", SIZE_MAX, &relative);
    ok(ret == 0);
    final = h2o_url_resolve(&pool, &base, &relative, &resolved);
    ok(h2o_memis(final.base, final.len, H2O_STRLIT("http://example.com/dir/foo.html")));
    ok(resolved.scheme == &H2O_URL_SCHEME_HTTP);
    ok(h2o_memis(resolved.authority.base, resolved.authority.len, H2O_STRLIT("example.com")));
    ok(h2o_memis(resolved.host.base, resolved.host.len, H2O_STRLIT("example.com")));
    ok(resolved._port == 65535);
    ok(h2o_url_get_port(&resolved) == 80);
    ok(h2o_memis(resolved.path.base, resolved.path.len, H2O_STRLIT("/dir/foo.html")));

    ret = h2o_url_parse_relative("http:/icon.ico", SIZE_MAX, &relative);
    ok(ret == 0);
    final = h2o_url_resolve(&pool, &base, &relative, &resolved);
    ok(h2o_memis(final.base, final.len, H2O_STRLIT("http://example.com/icon.ico")));
    ok(resolved.scheme == &H2O_URL_SCHEME_HTTP);
    ok(h2o_memis(resolved.authority.base, resolved.authority.len, H2O_STRLIT("example.com")));
    ok(h2o_memis(resolved.host.base, resolved.host.len, H2O_STRLIT("example.com")));
    ok(resolved._port == 65535);
    ok(h2o_url_get_port(&resolved) == 80);
    ok(h2o_memis(resolved.path.base, resolved.path.len, H2O_STRLIT("/icon.ico")));

    ret = h2o_url_parse_relative("https:/icon.ico", SIZE_MAX, &relative);
    ok(ret == 0);
    final = h2o_url_resolve(&pool, &base, &relative, &resolved);
    ok(h2o_memis(final.base, final.len, H2O_STRLIT("https://example.com/icon.ico")));
    ok(resolved.scheme == &H2O_URL_SCHEME_HTTPS);
    ok(h2o_memis(resolved.authority.base, resolved.authority.len, H2O_STRLIT("example.com")));
    ok(h2o_memis(resolved.host.base, resolved.host.len, H2O_STRLIT("example.com")));
    ok(resolved._port == 65535);
    ok(h2o_url_get_port(&resolved) == 443);
    ok(h2o_memis(resolved.path.base, resolved.path.len, H2O_STRLIT("/icon.ico")));

    ret = h2o_url_parse_relative("//example.jp:81/icon.ico", SIZE_MAX, &relative);
    ok(ret == 0);
    final = h2o_url_resolve(&pool, &base, &relative, &resolved);
    ok(h2o_memis(final.base, final.len, H2O_STRLIT("http://example.jp:81/icon.ico")));
    ok(resolved.scheme == &H2O_URL_SCHEME_HTTP);
    ok(h2o_memis(resolved.authority.base, resolved.authority.len, H2O_STRLIT("example.jp:81")));
    ok(h2o_memis(resolved.host.base, resolved.host.len, H2O_STRLIT("example.jp")));
    ok(resolved._port == 81);
    ok(h2o_url_get_port(&resolved) == 81);
    ok(h2o_memis(resolved.path.base, resolved.path.len, H2O_STRLIT("/icon.ico")));

    h2o_mem_clear_pool(&pool);
}

void test_lib__url_c(void)
{
    subtest("normalize_path", test_normalize_path);
    subtest("parse", test_parse);
    subtest("parse_relative", test_parse_relative);
    subtest("resolve", test_resolve);
}
