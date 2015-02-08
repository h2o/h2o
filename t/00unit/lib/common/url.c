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

void test_lib__url_c(void)
{
    subtest("normalize_path", test_normalize_path);
    subtest("parse_url", test_parse_url);
}
