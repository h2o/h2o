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
#include <assert.h>
#include <pthread.h>
#include "khash.h"
#include "h2o/cache.h"
#include "h2o/linklist.h"
#include "h2o/memory.h"

static h2o_cache_hashcode_t get_keyhash(h2o_cache_ref_t *ref);
static int is_equal(h2o_cache_ref_t *x, h2o_cache_ref_t *y);

KHASH_INIT(cache, h2o_cache_ref_t *, char, 0, get_keyhash, is_equal)

struct st_h2o_cache_t {
    pthread_mutex_t lock;
    khash_t(cache) *table;
    size_t size;
    size_t capacity;
    h2o_linklist_t lru;
    h2o_linklist_t age;
    uint64_t duration;
    void (*destroy_cb)(h2o_iovec_t value);
};

static h2o_cache_hashcode_t calchash(const char *s, size_t l)
{
    h2o_cache_hashcode_t h = 0;
    for (; l != 0; --l)
        h = (h << 5) - h + *(unsigned char*)s;
    return h;
}

static h2o_cache_hashcode_t get_keyhash(h2o_cache_ref_t *ref)
{
    return ref->key.hash;
}

static int is_equal(h2o_cache_ref_t *x, h2o_cache_ref_t *y)
{
    return x->key.vec.len == y->key.vec.len && memcmp(x->key.vec.base, y->key.vec.base, x->key.vec.len) == 0;
}

static void erase_ref(h2o_cache_t *cache, khiter_t iter, h2o_cache_ref_t *new_ref)
{
    h2o_cache_ref_t *ref = kh_key(cache->table, iter);

    if (new_ref != NULL) {
        kh_key(cache->table, iter) = new_ref;
    } else {
        kh_del(cache, cache->table, iter);
    }
    h2o_linklist_unlink(&ref->_lru_link);
    h2o_linklist_unlink(&ref->_age_link);
    cache->size -= ref->data.len;

    h2o_cache_release(cache, ref);
}

static int64_t get_timeleft(h2o_cache_t *cache, h2o_cache_ref_t *ref, uint64_t now)
{
    return (int64_t)(ref->at + cache->duration) - now;
}

h2o_cache_t *h2o_cache_create(size_t capacity, uint64_t duration, void (*destroy_cb)(h2o_iovec_t value))
{
    h2o_cache_t *cache = h2o_mem_alloc(sizeof(*cache));

    pthread_mutex_init(&cache->lock, NULL);
    cache->table = kh_init(cache);
    cache->size = 0;
    cache->capacity = capacity;
    h2o_linklist_init_anchor(&cache->lru);
    h2o_linklist_init_anchor(&cache->age);
    cache->duration = duration;
    cache->destroy_cb = destroy_cb;

    return cache;
}

void h2o_cache_destroy(h2o_cache_t *cache)
{
    h2o_cache_clear(cache, 0);

    assert(kh_size(cache->table) == 0);

    kh_destroy(cache, cache->table);
    pthread_mutex_destroy(&cache->lock);
    free(cache);
}

void h2o_cache_clear(h2o_cache_t *cache, uint64_t now)
{
    pthread_mutex_lock(&cache->lock);

    while (! h2o_linklist_is_empty(&cache->age)) {
        h2o_cache_ref_t *ref = H2O_STRUCT_FROM_MEMBER(h2o_cache_ref_t, _age_link, cache->age.next);
        if (! (now == 0 || get_timeleft(cache, ref, now) < 0))
            break;
        erase_ref(cache, kh_get(cache, cache->table, ref), NULL);
    }

    pthread_mutex_unlock(&cache->lock);
}

h2o_cache_ref_t *h2o_cache_fetch(h2o_cache_t *cache, h2o_iovec_t key, uint64_t now)
{
    h2o_cache_key_t search_key = { key, calchash(key.base, key.len) };
    khiter_t iter;
    h2o_cache_ref_t *ref;
    int64_t timeleft;

    pthread_mutex_lock(&cache->lock);

    if ((iter = kh_get(cache, cache->table, (void*)&search_key)) == kh_end(cache->table))
        goto NotFound;

    /* found */
    ref = kh_key(cache->table, iter);
    timeleft = get_timeleft(cache, ref, now);
    if (timeleft < 0)
        goto NotFound;
    if (timeleft < 10 && ! ref->_requested_early_update) {
        ref->_requested_early_update = 1;
        goto NotFound;
    }
    /* move the entry to the top of LRU, and return */
    h2o_linklist_unlink(&ref->_lru_link);
    h2o_linklist_insert(&cache->lru, &ref->_lru_link);
    __sync_fetch_and_add(&ref->_refcnt, 1);

    /* unlock and return the found entry */
    pthread_mutex_unlock(&cache->lock);
    return ref;

NotFound:
    pthread_mutex_unlock(&cache->lock);

    /* prepare new ref and return */
    ref = h2o_mem_alloc(sizeof(*ref) + key.len);
    ref->key.vec.base = (void*)(ref + 1);
    ref->key.vec.len = key.len;
    ref->key.hash = search_key.hash;
    ref->data = (h2o_iovec_t){};
    ref->at = 0;
    ref->_requested_early_update = 0;
    ref->_lru_link = (h2o_linklist_t){};
    ref->_age_link = (h2o_linklist_t){};
    ref->_refcnt = 1;
    memcpy(ref->key.vec.base, key.base, key.len);

    return ref;
}

void h2o_cache_release(h2o_cache_t *cache, h2o_cache_ref_t *ref)
{
    if (__sync_fetch_and_sub(&ref->_refcnt, 1) == 1) {
        cache->destroy_cb(ref->data);
        free(ref);
    }
}

void h2o_cache_update(h2o_cache_t *cache, h2o_cache_ref_t *ref, uint64_t now)
{
    khiter_t iter;

    assert(ref->_refcnt == 1);
    assert(! h2o_linklist_is_linked(&ref->_lru_link));

    pthread_mutex_lock(&cache->lock);

    /* look for existing entry */
    iter = kh_get(cache, cache->table, ref);

    /* if delete is requested, doit, and return */
    if (ref->data.base == NULL) {
        if (iter != kh_end(cache->table)) {
            erase_ref(cache, iter, NULL);
        }
        pthread_mutex_unlock(&cache->lock);
        h2o_cache_release(cache, ref);
        return;
    }

    /* update */
    if (iter == kh_end(cache->table)) {
        /* attach the entry to cache */
        int unused;
        kh_put(cache, cache->table, ref, &unused);
    } else {
        /* swap with the existing entry */
        erase_ref(cache, iter, ref);
    }
    ref->at = now;
    h2o_linklist_insert(&cache->lru, &ref->_lru_link);
    h2o_linklist_insert(&cache->age, &ref->_age_link);
    cache->size += ref->data.len;

    /* purge if the cache has become too large */
    while (cache->capacity < cache->size) {
        h2o_cache_ref_t *oldest;
        assert(! h2o_linklist_is_empty(&cache->age));
        oldest = H2O_STRUCT_FROM_MEMBER(h2o_cache_ref_t, _age_link, cache->age.next);
        if (get_timeleft(cache, oldest, now) >= 0)
            break;
        erase_ref(cache, kh_get(cache, cache->table, oldest), NULL);
    }
    while (cache->capacity < cache->size) {
        h2o_cache_ref_t *last;
        assert(! h2o_linklist_is_empty(&cache->lru));
        last = H2O_STRUCT_FROM_MEMBER(h2o_cache_ref_t, _lru_link, cache->lru.next);
        erase_ref(cache, kh_get(cache, cache->table, last), NULL);
    }

    pthread_mutex_unlock(&cache->lock);
}
