/*
 * Copyright (c) 2016 DeNA Co., Ltd., Kazuho Oku
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
#include "../../../../lib/http2/cache_digests.c"

static void test_calc_hash(void)
{
    ok(calc_hash(H2O_STRLIT("https://example.com/style.css"), H2O_STRLIT("")) == 0xbaf9e86f03330860);
    ok(calc_hash(H2O_STRLIT("https://example.com/style.css"), H2O_STRLIT("\"deadbeef\"")) == 0xa53eb398509042d7);
}

static void test_decode(void)
{
    h2o_cache_digests_t *digests = NULL;

    h2o_cache_digests_load_header(&digests, H2O_STRLIT("AeLA"));
    ok(digests != NULL);
    if (digests == NULL)
        return;
    ok(digests->fresh.url_only.size == 1);
    ok(digests->fresh.url_and_etag.size == 0);
    ok(digests->fresh.url_only.entries[0].capacity_bits == 7);
    ok(digests->fresh.url_only.entries[0].keys.size == 1);
    ok(digests->fresh.url_only.entries[0].keys.entries[0] == 0x0b);
    ok(!digests->fresh.complete);

    ok(h2o_cache_digests_lookup_by_url(digests, H2O_STRLIT("https://127.0.0.1.xip.io:8081/cache-digests.cgi/hello.js")) ==
       H2O_CACHE_DIGESTS_STATE_FRESH);
    ok(h2o_cache_digests_lookup_by_url(digests, H2O_STRLIT("https://127.0.0.1.xip.io:8081/notfound.js")) ==
       H2O_CACHE_DIGESTS_STATE_UNKNOWN);

    h2o_cache_digests_load_header(&digests, H2O_STRLIT("FOO; stale, AcA; validators; complete"));
    ok(digests->fresh.url_only.size == 1);
    ok(digests->fresh.url_and_etag.size == 1);
    ok(digests->fresh.url_and_etag.entries[0].capacity_bits == 7);
    ok(digests->fresh.url_and_etag.entries[0].keys.size == 0);
    ok(digests->fresh.complete);

    ok(h2o_cache_digests_lookup_by_url(digests, H2O_STRLIT("https://127.0.0.1.xip.io:8081/notfound.js")) ==
       H2O_CACHE_DIGESTS_STATE_NOT_CACHED);
    ok(h2o_cache_digests_lookup_by_url(digests, H2O_STRLIT("https://127.0.0.1.xip.io:8081/cache-digests.cgi/hello.js")) ==
       H2O_CACHE_DIGESTS_STATE_FRESH);

    h2o_cache_digests_load_header(&digests, H2O_STRLIT("AcA; reset"));
    ok(digests->fresh.url_only.size == 1);
    ok(digests->fresh.url_and_etag.size == 0);
    ok(digests->fresh.url_only.entries[0].capacity_bits == 7);
    ok(digests->fresh.url_only.entries[0].keys.size == 0);
    ok(!digests->fresh.complete);

    h2o_cache_digests_destroy(digests);
}

void test_lib__http2__cache_digests(void)
{
    subtest("calc_hash", test_calc_hash);
    subtest("test_decode", test_decode);
}
