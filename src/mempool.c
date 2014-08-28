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
        struct st_h2o_mempool_shared_ref_t **ref = &pool->shared_refs;
        do {
            h2o_mempool_release_shared((*ref)->entry->bytes);
        } while ((*ref = (*ref)->next) != NULL);
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
        struct st_h2o_mempool_direct_t *newp = malloc(offsetof(struct st_h2o_mempool_direct_t, bytes) + sz);
        if (newp == NULL) {
            h2o_fatal("");
            return NULL;
        }
        newp->next = pool->directs;
        pool->directs = newp;
        return newp->bytes;
    }

    /* 16-bytes rounding */
    sz = (sz + 15) & ~15;
    if (sizeof(pool->chunks->bytes) < pool->chunks->offset + sz) {
        /* allocate new chunk */
        h2o_mempool_chunk_t *newp = malloc(sizeof(h2o_mempool_chunk_t));
        if (newp == NULL) {
            h2o_fatal("");
            return NULL;
        }
        newp->next = pool->chunks;
        newp->offset = 0;
        pool->chunks = newp;
    }

    ret = pool->chunks->bytes + pool->chunks->offset;
    pool->chunks->offset += sz;
    return ret;
}

static void link(h2o_mempool_t *pool, struct st_h2o_mempool_shared_entry_t *entry)
{
    struct st_h2o_mempool_shared_ref_t *ref = h2o_mempool_alloc(pool, sizeof(struct st_h2o_mempool_shared_ref_t));
    ref->entry = entry;
    ref->next = pool->shared_refs;
    pool->shared_refs = ref;
}

void *h2o_mempool_alloc_shared(h2o_mempool_t *pool, size_t sz)
{
    struct st_h2o_mempool_shared_entry_t *entry = malloc(offsetof(struct st_h2o_mempool_shared_entry_t, bytes) + sz);
    if (entry == NULL) {
        h2o_fatal("");
        return NULL;
    }
    entry->refcnt = 1;
    link(pool, entry);
    return entry->bytes;
}

void h2o_mempool_link_shared(h2o_mempool_t *pool, void *p)
{
    h2o_mempool_addref_shared(p);
    link(pool, H2O_STRUCT_FROM_MEMBER(h2o_mempool_shared_entry_t, bytes, p));
}
