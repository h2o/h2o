#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include "h2o.h"

struct st_h2o_mempool_direct_t {
    struct st_h2o_mempool_direct_t *next;
    size_t refcnt;
    char bytes[1];
};

static struct st_h2o_mempool_direct_t direct_is_orphan;

void h2o_mempool_init(h2o_mempool_t *pool)
{
    pool->chunks = &pool->_first_chunk;
    pool->directs = NULL;
    pool->_first_chunk.next = NULL;
    pool->_first_chunk.offset = 0;
}

void h2o_mempool_clear(h2o_mempool_t *pool)
{
    /* free chunks, and reset the first chunk */
    while (pool->chunks != &pool->_first_chunk) {
        h2o_mempool_chunk_t *next = pool->chunks->next;
        free(pool->chunks);
        pool->chunks = next;
    }
    pool->_first_chunk.next = NULL;
    pool->_first_chunk.offset = 0;

    /* free directs */
    while (pool->directs != NULL) {
        struct st_h2o_mempool_direct_t *next = pool->directs->next;
        if (pool->directs->refcnt == 0) {
            free(pool->directs);
        } else {
            pool->directs->next = &direct_is_orphan;
        }
        pool->directs = next;
    }
}

void *h2o_mempool_alloc(h2o_mempool_t *pool, size_t sz)
{
    void *ret;

    if (sz >= sizeof(pool->chunks->bytes) / 4) {
        /* allocate large requests directly */
        return h2o_mempool_alloc_refcnt(pool, sz);
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

void *h2o_mempool_alloc_refcnt(h2o_mempool_t *pool, size_t sz)
{
    struct st_h2o_mempool_direct_t *newp = malloc(offsetof(struct st_h2o_mempool_direct_t, bytes) + sz);
    if (newp == NULL) {
        h2o_fatal("");
        return NULL;
    }
    newp->next = pool->directs;
    pool->directs = newp;
    newp->refcnt = 0;
    return newp->bytes;
}

void h2o_mempool_addref(void *p)
{
    struct st_h2o_mempool_direct_t *direct = H2O_STRUCT_FROM_MEMBER(struct st_h2o_mempool_direct_t, bytes, p);
    ++direct->refcnt;
}

void h2o_mempool_release(h2o_mempool_t *pool, void *p)
{
    struct st_h2o_mempool_direct_t *direct = H2O_STRUCT_FROM_MEMBER(struct st_h2o_mempool_direct_t, bytes, p);
    if (--direct->refcnt == 0) {
        if (direct->next == &direct_is_orphan) {
            if (pool != NULL) {
                direct->next = pool->directs;
                pool->directs = direct;
            } else {
                free(direct);
            }
        }
    }
}
