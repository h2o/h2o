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
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <unistd.h>
#include "khash.h"
#include "h2o/memory.h"
#include "h2o/filecache.h"

KHASH_SET_INIT_STR(opencache_set)

struct st_h2o_filecache_t {
    khash_t(opencache_set) * hash;
    h2o_linklist_t lru;
    size_t capacity;
};

static inline void release_from_cache(h2o_filecache_t *cache, khiter_t iter)
{
    const char *path = kh_key(cache->hash, iter);
    h2o_filecache_ref_t *ref = H2O_STRUCT_FROM_MEMBER(h2o_filecache_ref_t, _path, path);

    /* detach from list */
    kh_del(opencache_set, cache->hash, iter);
    h2o_linklist_unlink(&ref->_lru);

    /* and close */
    h2o_filecache_close_file(ref);
}

h2o_filecache_t *h2o_filecache_create(size_t capacity)
{
    h2o_filecache_t *cache = h2o_mem_alloc(sizeof(*cache));

    cache->hash = kh_init(opencache_set);
    h2o_linklist_init_anchor(&cache->lru);
    cache->capacity = capacity;

    return cache;
}

void h2o_filecache_destroy(h2o_filecache_t *cache)
{
    h2o_filecache_clear(cache);
    assert(kh_size(cache->hash) == 0);
    assert(h2o_linklist_is_empty(&cache->lru));
    kh_destroy(opencache_set, cache->hash);
    free(cache);
}

void h2o_filecache_clear(h2o_filecache_t *cache)
{
    khiter_t iter;
    for (iter = kh_begin(cache->hash); iter != kh_end(cache->hash); ++iter) {
        if (!kh_exist(cache->hash, iter))
            continue;
        release_from_cache(cache, iter);
    }
    assert(kh_size(cache->hash) == 0);
}

h2o_filecache_ref_t *h2o_filecache_open_file(h2o_filecache_t *cache, const char *path, int oflag)
{
    khiter_t iter = kh_get(opencache_set, cache->hash, path);
    h2o_filecache_ref_t *ref;
    int dummy;

    /* lookup cache, and return the one if found */
    if (iter != kh_end(cache->hash)) {
        ref = H2O_STRUCT_FROM_MEMBER(h2o_filecache_ref_t, _path, kh_key(cache->hash, iter));
        ++ref->_refcnt;
        goto Exit;
    }

    /* create a new cache entry */
    ref = h2o_mem_alloc(offsetof(h2o_filecache_ref_t, _path) + strlen(path) + 1);
    ref->_refcnt = 1;
    ref->_lru = (h2o_linklist_t){NULL};
    strcpy(ref->_path, path);

    /* if cache is used, then... */
    if (cache->capacity != 0) {
        /* purge one entry from LRU if cache is full */
        if (kh_size(cache->hash) == cache->capacity) {
            h2o_filecache_ref_t *purge_ref = H2O_STRUCT_FROM_MEMBER(h2o_filecache_ref_t, _lru, cache->lru.prev);
            khiter_t purge_iter = kh_get(opencache_set, cache->hash, purge_ref->_path);
            assert(purge_iter != kh_end(cache->hash));
            release_from_cache(cache, purge_iter);
        }
        /* assign the new entry */
        ++ref->_refcnt;
        kh_put(opencache_set, cache->hash, ref->_path, &dummy);
        h2o_linklist_insert(cache->lru.next, &ref->_lru);
    }

    /* open the file, or memoize the error */
    if ((ref->fd = open(path, oflag)) != -1 && fstat(ref->fd, &ref->st) == 0) {
        ref->_last_modified.str[0] = '\0';
        ref->_etag.len = 0;
    } else {
        ref->open_err = errno;
        if (ref->fd != -1) {
            close(ref->fd);
            ref->fd = -1;
        }
    }

Exit:
    /* if the cache entry retains an error, return it instead of the reference */
    if (ref->fd == -1) {
        errno = ref->open_err;
        h2o_filecache_close_file(ref);
        ref = NULL;
    }
    return ref;
}

void h2o_filecache_close_file(h2o_filecache_ref_t *ref)
{
    if (--ref->_refcnt != 0)
        return;
    assert(!h2o_linklist_is_linked(&ref->_lru));
    if (ref->fd != -1) {
        close(ref->fd);
        ref->fd = -1;
    }
    free(ref);
}

struct tm *h2o_filecache_get_last_modified(h2o_filecache_ref_t *ref, char *outbuf)
{
    assert(ref->fd != -1);
    if (ref->_last_modified.str[0] == '\0') {
        gmtime_r(&ref->st.st_mtime, &ref->_last_modified.gm);
        h2o_time2str_rfc1123(ref->_last_modified.str, &ref->_last_modified.gm);
    }
    if (outbuf != NULL)
        memcpy(outbuf, ref->_last_modified.str, H2O_TIMESTR_RFC1123_LEN + 1);
    return &ref->_last_modified.gm;
}

size_t h2o_filecache_get_etag(h2o_filecache_ref_t *ref, char *outbuf)
{
    assert(ref->fd != -1);
    if (ref->_etag.len == 0)
        ref->_etag.len = sprintf(ref->_etag.buf, "\"%08x-%zx\"", (unsigned)ref->st.st_mtime, (size_t)ref->st.st_size);
    memcpy(outbuf, ref->_etag.buf, ref->_etag.len + 1);
    return ref->_etag.len;
}
