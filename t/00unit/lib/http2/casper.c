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
#include <string.h>
#include "../../test.h"
#include "../../../../lib/http2/casper.c"

static size_t get_end_of_cookie_value(char *cookie, size_t cookie_len)
{
    size_t i;
    for (i = 0; i != cookie_len; ++i)
        if (cookie[i] == ';')
            break;
    return i;
}

static void test_calc_key(void)
{
    h2o_http2_casper_t *casper = h2o_http2_casper_create(13, 6);

    unsigned key = calc_key(casper, H2O_STRLIT("/index.html")), expected;
    memcpy(&expected, "\x14\xfe\x45\x59", 4);
    expected &= (1 << 13) - 1;
    ok(key == expected);

    h2o_http2_casper_destroy(casper);
}

static void test_lookup(void)
{
    h2o_http2_casper_t *casper;
    casper = h2o_http2_casper_create(13, 6);

    ok(h2o_http2_casper_lookup(casper, H2O_STRLIT("/index.html"), 0) == 0);
    ok(h2o_http2_casper_lookup(casper, H2O_STRLIT("/index.html"), 1) == 0);
    ok(casper->keys.size == 1);
    ok(h2o_http2_casper_lookup(casper, H2O_STRLIT("/index.html"), 0) == 1);
    ok(h2o_http2_casper_lookup(casper, H2O_STRLIT("/index.html"), 1) == 1);
    ok(casper->keys.size == 1);

    h2o_http2_casper_destroy(casper);
}

static void test_cookie(void)
{
    h2o_http2_casper_t *casper;

    casper = h2o_http2_casper_create(13, 6);

    h2o_iovec_t cookie = h2o_http2_casper_get_cookie(casper);
    ok(cookie.base == NULL);
    ok(cookie.len == 0);

    h2o_http2_casper_lookup(casper, H2O_STRLIT("/index.html"), 1);
    cookie = h2o_http2_casper_get_cookie(casper);
    ok(cookie.len != 0);
    cookie = h2o_strdup(NULL, cookie.base, cookie.len);
    h2o_http2_casper_destroy(casper);
    casper = h2o_http2_casper_create(13, 6);

    h2o_http2_casper_consume_cookie(casper, cookie.base, get_end_of_cookie_value(cookie.base, cookie.len));
    ok(h2o_http2_casper_lookup(casper, H2O_STRLIT("/index.html"), 0) == 1);
    ok(h2o_http2_casper_lookup(casper, H2O_STRLIT("/index.php"), 0) == 0);
    h2o_http2_casper_lookup(casper, H2O_STRLIT("/index.php"), 1);

    h2o_http2_casper_lookup(casper, H2O_STRLIT("/index.html"), 1);
    cookie = h2o_http2_casper_get_cookie(casper);
    ok(cookie.len != 0);
    cookie = h2o_strdup(NULL, cookie.base, cookie.len);

    h2o_http2_casper_destroy(casper);
    casper = h2o_http2_casper_create(13, 6);

    h2o_http2_casper_consume_cookie(casper, cookie.base, get_end_of_cookie_value(cookie.base, cookie.len));
    ok(h2o_http2_casper_lookup(casper, H2O_STRLIT("/index.html"), 0) == 1);
    ok(h2o_http2_casper_lookup(casper, H2O_STRLIT("/index.php"), 0) == 1);

    h2o_http2_casper_destroy(casper);
}

static void test_cookie_merge(void)
{
    h2o_http2_casper_t *casper;

    casper = h2o_http2_casper_create(13, 6);
    h2o_http2_casper_lookup(casper, H2O_STRLIT("/index.html"), 1);
    h2o_iovec_t cookie1 = h2o_http2_casper_get_cookie(casper);
    cookie1 = h2o_strdup(NULL, cookie1.base, cookie1.len);
    h2o_http2_casper_destroy(casper);

    casper = h2o_http2_casper_create(13, 6);
    h2o_http2_casper_lookup(casper, H2O_STRLIT("/index.php"), 1);
    h2o_iovec_t cookie2 = h2o_http2_casper_get_cookie(casper);
    cookie2 = h2o_strdup(NULL, cookie2.base, cookie2.len);
    h2o_http2_casper_destroy(casper);

    casper = h2o_http2_casper_create(13, 6);
    h2o_http2_casper_consume_cookie(casper, cookie1.base, get_end_of_cookie_value(cookie1.base, cookie1.len));
    h2o_http2_casper_consume_cookie(casper, cookie1.base, get_end_of_cookie_value(cookie1.base, cookie1.len));
    ok(casper->keys.size == 1);
    ok(h2o_http2_casper_lookup(casper, H2O_STRLIT("/index.html"), 0) == 1);
    h2o_http2_casper_consume_cookie(casper, cookie2.base, get_end_of_cookie_value(cookie2.base, cookie2.len));
    ok(casper->keys.size == 2);
    ok(h2o_http2_casper_lookup(casper, H2O_STRLIT("/index.html"), 0) == 1);
    ok(h2o_http2_casper_lookup(casper, H2O_STRLIT("/index.php"), 0) == 1);
    h2o_http2_casper_destroy(casper);
}

static void test_cookie_merge_updates_cookie(void)
{
    h2o_http2_casper_t *casper;

    casper = h2o_http2_casper_create(13, 6);
    h2o_http2_casper_lookup(casper, H2O_STRLIT("/index.php"), 1);
    h2o_iovec_t cookie = h2o_http2_casper_get_cookie(casper);
    cookie = h2o_strdup(NULL, cookie.base, cookie.len);
    h2o_http2_casper_destroy(casper);

    /* merge a cookie after the cookie of the casper has been built */
    casper = h2o_http2_casper_create(13, 6);
    h2o_http2_casper_lookup(casper, H2O_STRLIT("/index.html"), 1);
    h2o_http2_casper_get_cookie(casper);
    h2o_http2_casper_consume_cookie(casper, cookie.base, get_end_of_cookie_value(cookie.base, cookie.len));
    free(cookie.base);
    cookie = h2o_http2_casper_get_cookie(casper);
    cookie = h2o_strdup(NULL, cookie.base, cookie.len);
    h2o_http2_casper_destroy(casper);

    /* the rebuilt cookie should contain both keys */
    casper = h2o_http2_casper_create(13, 6);
    h2o_http2_casper_consume_cookie(casper, cookie.base, get_end_of_cookie_value(cookie.base, cookie.len));
    ok(casper->keys.size == 2);
    ok(h2o_http2_casper_lookup(casper, H2O_STRLIT("/index.html"), 0) == 1);
    ok(h2o_http2_casper_lookup(casper, H2O_STRLIT("/index.php"), 0) == 1);
    h2o_http2_casper_destroy(casper);
    free(cookie.base);
}

static void test_cookie_out_of_range_keys(void)
{
    uint64_t keys[] = {1, 2, 1 << 13, (1 << 13) + 1};
    char bin[64], cookie[128];
    size_t bin_len = sizeof(bin), cookie_len;

    ok(golombset_encode(6, keys, sizeof(keys) / sizeof(keys[0]), bin, &bin_len) == 0);
    cookie_len = sprintf(cookie, COOKIE_NAME "=");
    cookie_len += h2o_base64_encode(cookie + cookie_len, bin, bin_len, 1);

    h2o_http2_casper_t *casper = h2o_http2_casper_create(13, 6);
    h2o_http2_casper_consume_cookie(casper, cookie, cookie_len);
    ok(casper->keys.size == 2);
    ok(casper->keys.entries[0] == 1);
    ok(casper->keys.entries[1] == 2);
    h2o_http2_casper_destroy(casper);
}

void test_lib__http2__casper(void)
{
    subtest("calc_key", test_calc_key);
    subtest("test_lookup", test_lookup);
    subtest("cookie", test_cookie);
    subtest("cookie-merge", test_cookie_merge);
    subtest("cookie-merge-updates-cookie", test_cookie_merge_updates_cookie);
    subtest("cookie-out-of-range-keys", test_cookie_out_of_range_keys);
}
