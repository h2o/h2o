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
    h2o_cache_key_t key;
    h2o_iovec_t data;
    uint64_t at;
    h2o_linklist_t _link;
    size_t _refcnt;
} h2o_cache_ref_t;

h2o_cache_t *h2o_cache_create(size_t capacity, uint64_t duration, void (*destroy_cb)(h2o_iovec_t value));
void h2o_cache_destroy(h2o_cache_t *cache);

void h2o_cache_clear(h2o_cache_t *cache, uint64_t now);

h2o_cache_ref_t *h2o_cache_fetch(h2o_cache_t *cache, h2o_iovec_t key, uint64_t now);
void h2o_cache_release(h2o_cache_t *cache, h2o_cache_ref_t *ref);
void h2o_cache_update(h2o_cache_t *cache, h2o_cache_ref_t *ref, uint64_t now);

#endif
