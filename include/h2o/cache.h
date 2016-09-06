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
#ifndef h2o__cache_h
#define h2o__cache_h

#include <stdint.h>
#include "h2o/linklist.h"
#include "h2o/memory.h"

typedef struct st_h2o_cache_t h2o_cache_t;

typedef uint32_t /* eq. khint_t */ h2o_cache_hashcode_t;

typedef struct st_h2o_cache_key_t {
    h2o_iovec_t vec;
    h2o_cache_hashcode_t hash;
} h2o_cache_key_t;

typedef struct st_h2o_cache_ref_t {
    h2o_iovec_t key;
    h2o_cache_hashcode_t keyhash;
    uint64_t at;
    h2o_iovec_t value;
    int _requested_early_update;
    h2o_linklist_t _lru_link;
    h2o_linklist_t _age_link;
    size_t _refcnt;
} h2o_cache_ref_t;

/**
 * calculates the hash code of a key
 */
h2o_cache_hashcode_t h2o_cache_calchash(const char *s, size_t len);

enum {
    /**
     * if set, the internals of the cache is protected by a mutex so that it can be accessed concurrently
     */
    H2O_CACHE_FLAG_MULTITHREADED = 0x1,
    /**
     * if set, the cache triggers an early update
     */
    H2O_CACHE_FLAG_EARLY_UPDATE = 0x2
};

/**
 * creates a new cache
 */
h2o_cache_t *h2o_cache_create(int flags, size_t capacity, uint64_t duration, void (*destroy_cb)(h2o_iovec_t value));
/**
 * destroys a cache
 */
void h2o_cache_destroy(h2o_cache_t *cache);
/**
 * clears a cache
 */
void h2o_cache_clear(h2o_cache_t *cache);
/**
 * returns a value named by key from the cache if found, or else returns NULL
 * @param cache
 * @param now
 * @param key
 * @param keyhash callers may optionally pass in the precalculated hash value (or should be set to 0)
 */
h2o_cache_ref_t *h2o_cache_fetch(h2o_cache_t *cache, uint64_t now, h2o_iovec_t key, h2o_cache_hashcode_t keyhash);
/**
 * releases the reference returned by h2o_cache_fetch
 */
void h2o_cache_release(h2o_cache_t *cache, h2o_cache_ref_t *ref);
/**
 * sets the value of the cache
 * @param cache
 * @param now
 * @param key
 * @param keyhash callers may optionally pass in the precalculated hash value (or should be set to 0)
 * @param value (when no longer needed, destroy_cb will be called)
 * @return if the specified value already existed
 */
int h2o_cache_set(h2o_cache_t *cache, uint64_t now, h2o_iovec_t key, h2o_cache_hashcode_t keyhash, h2o_iovec_t value);
/**
 * deletes a named value from the cache
 * @param cache
 * @param now
 * @param key
 * @param keyhash callers may optionally pass in the precalculated hash value (or should be set to 0)
 */
void h2o_cache_delete(h2o_cache_t *cache, uint64_t now, h2o_iovec_t key, h2o_cache_hashcode_t keyhash);

/**
 * getter functions
 */
size_t h2o_cache_get_capacity(h2o_cache_t *cache);
uint64_t h2o_cache_get_duration(h2o_cache_t *cache);

#endif
