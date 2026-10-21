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

static void test_decode_limit(void)
{
    h2o_cache_digests_t *digests = NULL;

    /* a digest that carries exactly the maximum number of keys is accepted */
    h2o_cache_digests_load_header(&digests, H2O_STRLIT("QD__________wA"));
    ok(digests != NULL);
    if (digests == NULL)
        return;
    ok(digests->fresh.url_only.size == 1);
    ok(digests->fresh.url_only.entries[0].keys.size == H2O_CACHE_DIGESTS_MAX_KEYS);
    h2o_cache_digests_destroy(digests);
    digests = NULL;

    /* a digest that carries one key too many is discarded as a whole */
    h2o_cache_digests_load_header(&digests, H2O_STRLIT("QD__________4A"));
    ok(digests == NULL);

    /* so is a digest that carries many keys */
    h2o_cache_digests_load_header(&digests, H2O_STRLIT("QD_________________________________A"));
    ok(digests == NULL);

    /* the number of digests that a request may carry is bounded as well */
    for (size_t i = 0; i < H2O_CACHE_DIGESTS_MAX_FRAMES; ++i)
        h2o_cache_digests_load_header(&digests, H2O_STRLIT("AeLA"));
    ok(digests != NULL);
    if (digests == NULL)
        return;
    ok(digests->fresh.url_only.size == H2O_CACHE_DIGESTS_MAX_FRAMES);
    h2o_cache_digests_load_header(&digests, H2O_STRLIT("AeLA"));
    ok(digests->fresh.url_only.size == H2O_CACHE_DIGESTS_MAX_FRAMES);
    h2o_cache_digests_destroy(digests);
}

static void test_lookup_zero_capacity(void)
{
    /* A frame that carries no capacity holds the key zero. Looking a URL up in such a frame used to
     * shift the hash by the width of the type, which is undefined behaviour. */
    h2o_cache_digests_frame_t frame = {0};
    h2o_cache_digests_frame_vector_t vector = {NULL};
    h2o_cache_digests_t digests = {0};
    uint64_t keys[1] = {0};

    frame.capacity_bits = 0;
    frame.keys.entries = keys;
    frame.keys.size = 1;

    h2o_vector_reserve(NULL, &vector, 1);
    vector.entries[vector.size++] = frame;
    digests.fresh.url_only = vector;

    ok(h2o_cache_digests_lookup_by_url(&digests, H2O_STRLIT("https://example.com/style.css")) == H2O_CACHE_DIGESTS_STATE_FRESH);
    ok(h2o_cache_digests_lookup_by_url(&digests, H2O_STRLIT("https://example.com/other.css")) == H2O_CACHE_DIGESTS_STATE_FRESH);
}

void test_lib__http2__cache_digests(void)
{
    subtest("calc_hash", test_calc_hash);
    subtest("test_decode", test_decode);
    subtest("test_decode_limit", test_decode_limit);
    subtest("test_lookup_zero_capacity", test_lookup_zero_capacity);
}
