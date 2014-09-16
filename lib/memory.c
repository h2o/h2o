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
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include "h2o.h"

struct st_h2o_mempool_direct_t {
    struct st_h2o_mempool_direct_t *next;
    size_t _dummy; /* align to 2*sizeof(void*) */
    char bytes[1];
};

struct st_h2o_mempool_shared_ref_t {
    struct st_h2o_mempool_shared_ref_t *next;
    struct st_h2o_mempool_shared_entry_t *entry;
};

void h2o_mempool_init(h2o_mempool_t *pool)
{
    pool->chunks = &pool->_first_chunk;
    pool->directs = NULL;
    pool->shared_refs = NULL;
    pool->_first_chunk.next = NULL;
    pool->_first_chunk.offset = 0;
}

void h2o_mempool_clear(h2o_mempool_t *pool)
{
    /* release the refcounted chunks */
    if (pool->shared_refs != NULL) {
        struct st_h2o_mempool_shared_ref_t *ref = pool->shared_refs;
        do {
            h2o_mempool_release_shared(ref->entry->bytes);
        } while ((ref = ref->next) != NULL);
        pool->shared_refs = NULL;
    }
    /* release the direct chunks */
    if (pool->directs != NULL) {
        struct st_h2o_mempool_direct_t *direct = pool->directs, *next;
        do {
            next = direct->next;
            free(direct);
        } while ((direct = next) != NULL);
        pool->directs = NULL;
    }
    /* free chunks, and reset the first chunk */
    while (pool->chunks != &pool->_first_chunk) {
        h2o_mempool_chunk_t *next = pool->chunks->next;
        free(pool->chunks);
        pool->chunks = next;
    }
    pool->_first_chunk.next = NULL;
    pool->_first_chunk.offset = 0;
}

void *h2o_mempool_alloc(h2o_mempool_t *pool, size_t sz)
{
    void *ret;

    if (sz >= sizeof(pool->chunks->bytes) / 4) {
        /* allocate large requests directly */
        struct st_h2o_mempool_direct_t *newp = h2o_malloc(offsetof(struct st_h2o_mempool_direct_t, bytes) + sz);
        newp->next = pool->directs;
        pool->directs = newp;
        return newp->bytes;
    }

    /* 16-bytes rounding */
    sz = (sz + 15) & ~15;
    if (sizeof(pool->chunks->bytes) < pool->chunks->offset + sz) {
        /* allocate new chunk */
        h2o_mempool_chunk_t *newp = h2o_malloc(sizeof(*newp));
        newp->next = pool->chunks;
        newp->offset = 0;
        pool->chunks = newp;
    }

    ret = pool->chunks->bytes + pool->chunks->offset;
    pool->chunks->offset += sz;
    return ret;
}

static void link_shared(h2o_mempool_t *pool, struct st_h2o_mempool_shared_entry_t *entry)
{
    struct st_h2o_mempool_shared_ref_t *ref = h2o_mempool_alloc(pool, sizeof(struct st_h2o_mempool_shared_ref_t));
    ref->entry = entry;
    ref->next = pool->shared_refs;
    pool->shared_refs = ref;
}

void *h2o_mempool_alloc_shared(h2o_mempool_t *pool, size_t sz)
{
    struct st_h2o_mempool_shared_entry_t *entry = h2o_malloc(offsetof(struct st_h2o_mempool_shared_entry_t, bytes) + sz);
    entry->refcnt = 1;
    if (pool != NULL)
        link_shared(pool, entry);
    return entry->bytes;
}

void h2o_mempool_link_shared(h2o_mempool_t *pool, void *p)
{
    h2o_mempool_addref_shared(p);
    link_shared(pool, H2O_STRUCT_FROM_MEMBER(h2o_mempool_shared_entry_t, bytes, p));
}

h2o_buf_t h2o_allocate_input_buffer(h2o_input_buffer_t **_inbuf, size_t initial_size)
{
    h2o_input_buffer_t *inbuf = *_inbuf;
    h2o_buf_t ret;

    if (inbuf == NULL) {
        inbuf = h2o_malloc(offsetof(h2o_input_buffer_t, bytes) + initial_size);
        *_inbuf = inbuf;
        inbuf->size = 0;
        inbuf->bytes = inbuf->_buf;
        inbuf->_capacity = initial_size;
    } else {
        if (inbuf->bytes != inbuf->_buf) {
            assert(inbuf->size != 0);
            memmove(inbuf->_buf, inbuf->bytes, inbuf->size);
            inbuf->bytes = inbuf->_buf;
        }
        if (inbuf->size == inbuf->_capacity) {
            inbuf->_capacity *= 2;
            inbuf = h2o_realloc(inbuf, offsetof(h2o_input_buffer_t, bytes) + inbuf->_capacity);
            inbuf->bytes = inbuf->_buf;
            *_inbuf = inbuf;
        }
        /* TODO shrink the size if possible */
    }

    ret.base = inbuf->bytes + inbuf->size;
    ret.len = inbuf->_capacity - inbuf->size;

    return ret;
}

void h2o_consume_input_buffer(h2o_input_buffer_t **_inbuf, size_t delta)
{
    h2o_input_buffer_t *inbuf = *_inbuf;

    if (delta != 0) {
        assert(inbuf != NULL);
        if (inbuf->size == delta) {
            inbuf->size = 0;
            inbuf->bytes = inbuf->_buf;
        } else {
            inbuf->size -= delta;
            inbuf->bytes += delta;
        }
    }
}

void h2o_vector__expand(h2o_mempool_t *pool, h2o_vector_t *vector, size_t element_size, size_t new_capacity)
{
    void *new_entries;
    assert(vector->capacity < new_capacity);
    if (vector->capacity == 0)
        vector->capacity = 4;
    while (vector->capacity < new_capacity)
        vector->capacity *= 2;
    new_entries = h2o_mempool_alloc(pool, element_size * vector->capacity);
    memcpy(new_entries, vector->entries, element_size * vector->size);
    vector->entries = new_entries;
}
