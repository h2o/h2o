/*
 * Copyright (c) 2014-2016 DeNA Co., Ltd., Kazuho Oku
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
#include "../../../../lib/common/cache.c"

static size_t bytes_destroyed;

static void on_destroy(h2o_iovec_t vec)
{
    bytes_destroyed += vec.len;
}

void test_lib__common__cache_c(void)
{
    h2o_cache_t *cache = h2o_cache_create(H2O_CACHE_FLAG_EARLY_UPDATE, 1024, 1000, on_destroy);
    uint64_t now = 0;
    h2o_iovec_t key = {H2O_STRLIT("key")};
    h2o_cache_ref_t *ref;

    /* fetch "key" */
    ref = h2o_cache_fetch(cache, now, key, 0);
    ok(ref == NULL);

    /* set "key" => "value" */
    h2o_cache_set(cache, now, key, 0, h2o_iovec_init(H2O_STRLIT("value")));

    /* delete "key" */
    h2o_cache_delete(cache, now, key, 0);
    ref = h2o_cache_fetch(cache, now, key, 0);
    ok(ref == NULL);

    /* set "key" => "value" */
    h2o_cache_set(cache, now, key, 0, h2o_iovec_init(H2O_STRLIT("value")));

    /* fetch "key" */
    ref = h2o_cache_fetch(cache, now, key, 0);
    ok(h2o_memis(ref->value.base, ref->value.len, H2O_STRLIT("value")));
    h2o_cache_release(cache, ref);

    /* proceed 999ms */
    now += 999;

    /* should fail to fetch "key" */
    ref = h2o_cache_fetch(cache, now, key, 0);
    ok(ref == NULL);

    /* refetch should succeed */
    ref = h2o_cache_fetch(cache, now, key, 0);
    ok(h2o_memis(ref->value.base, ref->value.len, H2O_STRLIT("value")));
    h2o_cache_release(cache, ref);

    /* set "key" to "value2" */
    h2o_cache_set(cache, now, key, 0, h2o_iovec_init(H2O_STRLIT("value2")));

    /* fetch */
    ref = h2o_cache_fetch(cache, now, key, 0);
    ok(h2o_memis(ref->value.base, ref->value.len, H2O_STRLIT("value2")));
    h2o_cache_release(cache, ref);

    ok(bytes_destroyed == 10);

    h2o_cache_destroy(cache);

    ok(bytes_destroyed == 16);
}
