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
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include "h2o/memory.h"

#if defined(__linux__)
#define USE_POSIX_FALLOCATE 1
#elif __FreeBSD__ >= 9
#define USE_POSIX_FALLOCATE 1
#elif __NetBSD__ >= 7
#define USE_POSIX_FALLOCATE 1
#else
#define USE_POSIX_FALLOCATE 0
#endif

struct st_h2o_mem_recycle_chunk_t {
    struct st_h2o_mem_recycle_chunk_t *next;
};

struct st_h2o_mem_pool_chunk_t {
    struct st_h2o_mem_pool_chunk_t *next;
    size_t _dummy; /* align to 2*sizeof(void*) */
    char bytes[4096 - sizeof(void *) * 2];
};

struct st_h2o_mem_pool_direct_t {
    struct st_h2o_mem_pool_direct_t *next;
    size_t _dummy; /* align to 2*sizeof(void*) */
    char bytes[1];
};

struct st_h2o_mem_pool_shared_ref_t {
    struct st_h2o_mem_pool_shared_ref_t *next;
    struct st_h2o_mem_pool_shared_entry_t *entry;
};

void *(*h2o_mem__set_secure)(void *, int, size_t) = memset;

static __thread h2o_mem_recycle_t mempool_allocator = {16};

void h2o__fatal(const char *msg)
{
    fprintf(stderr, "fatal:%s\n", msg);
    abort();
}

void *h2o_mem_alloc_recycle(h2o_mem_recycle_t *allocator, size_t sz)
{
    struct st_h2o_mem_recycle_chunk_t *chunk;
    if (allocator->cnt == 0)
        return h2o_mem_alloc(sz);
    /* detach and return the pooled pointer */
    chunk = allocator->_link;
    assert(chunk != NULL);
    allocator->_link = chunk->next;
    --allocator->cnt;
    return chunk;
}

void h2o_mem_free_recycle(h2o_mem_recycle_t *allocator, void *p)
{
    struct st_h2o_mem_recycle_chunk_t *chunk;
    if (allocator->cnt == allocator->max) {
        free(p);
        return;
    }
    /* register the pointer to the pool */
    chunk = p;
    chunk->next = allocator->_link;
    allocator->_link = chunk;
    ++allocator->cnt;
}

void h2o_mem_init_pool(h2o_mem_pool_t *pool)
{
    pool->chunks = NULL;
    pool->chunk_offset = sizeof(pool->chunks->bytes);
    pool->directs = NULL;
    pool->shared_refs = NULL;
}

void h2o_mem_clear_pool(h2o_mem_pool_t *pool)
{
    /* release the refcounted chunks */
    if (pool->shared_refs != NULL) {
        struct st_h2o_mem_pool_shared_ref_t *ref = pool->shared_refs;
        do {
            h2o_mem_release_shared(ref->entry->bytes);
        } while ((ref = ref->next) != NULL);
        pool->shared_refs = NULL;
    }
    /* release the direct chunks */
    if (pool->directs != NULL) {
        struct st_h2o_mem_pool_direct_t *direct = pool->directs, *next;
        do {
            next = direct->next;
            free(direct);
        } while ((direct = next) != NULL);
        pool->directs = NULL;
    }
    /* free chunks, and reset the first chunk */
    while (pool->chunks != NULL) {
        struct st_h2o_mem_pool_chunk_t *next = pool->chunks->next;
        h2o_mem_free_recycle(&mempool_allocator, pool->chunks);
        pool->chunks = next;
    }
    pool->chunk_offset = sizeof(pool->chunks->bytes);
}

void *h2o_mem_alloc_pool(h2o_mem_pool_t *pool, size_t sz)
{
    void *ret;

    if (sz >= sizeof(pool->chunks->bytes) / 4) {
        /* allocate large requests directly */
        struct st_h2o_mem_pool_direct_t *newp = h2o_mem_alloc(offsetof(struct st_h2o_mem_pool_direct_t, bytes) + sz);
        newp->next = pool->directs;
        pool->directs = newp;
        return newp->bytes;
    }

    /* return a valid pointer even for 0 sized allocs */
    if (sz == 0)
        sz = 1;

    /* 16-bytes rounding */
    sz = (sz + 15) & ~15;
    if (sizeof(pool->chunks->bytes) - pool->chunk_offset < sz) {
        /* allocate new chunk */
        struct st_h2o_mem_pool_chunk_t *newp = h2o_mem_alloc_recycle(&mempool_allocator, sizeof(*newp));
        newp->next = pool->chunks;
        pool->chunks = newp;
        pool->chunk_offset = 0;
    }

    ret = pool->chunks->bytes + pool->chunk_offset;
    pool->chunk_offset += sz;
    return ret;
}

static void link_shared(h2o_mem_pool_t *pool, struct st_h2o_mem_pool_shared_entry_t *entry)
{
    struct st_h2o_mem_pool_shared_ref_t *ref = h2o_mem_alloc_pool(pool, sizeof(struct st_h2o_mem_pool_shared_ref_t));
    ref->entry = entry;
    ref->next = pool->shared_refs;
    pool->shared_refs = ref;
}

void *h2o_mem_alloc_shared(h2o_mem_pool_t *pool, size_t sz, void (*dispose)(void *))
{
    struct st_h2o_mem_pool_shared_entry_t *entry = h2o_mem_alloc(offsetof(struct st_h2o_mem_pool_shared_entry_t, bytes) + sz);
    entry->refcnt = 1;
    entry->dispose = dispose;
    if (pool != NULL)
        link_shared(pool, entry);
    return entry->bytes;
}

void h2o_mem_link_shared(h2o_mem_pool_t *pool, void *p)
{
    h2o_mem_addref_shared(p);
    link_shared(pool, H2O_STRUCT_FROM_MEMBER(struct st_h2o_mem_pool_shared_entry_t, bytes, p));
}

static size_t topagesize(size_t capacity)
{
    size_t pagesize = getpagesize();
    return (offsetof(h2o_buffer_t, _buf) + capacity + pagesize - 1) / pagesize * pagesize;
}

void h2o_buffer__do_free(h2o_buffer_t *buffer)
{
    /* caller should assert that the buffer is not part of the prototype */
    if (buffer->capacity == buffer->_prototype->_initial_buf.capacity) {
        h2o_mem_free_recycle(&buffer->_prototype->allocator, buffer);
    } else if (buffer->_fd != -1) {
        close(buffer->_fd);
        munmap((void *)buffer, topagesize(buffer->capacity));
    } else {
        free(buffer);
    }
}

h2o_iovec_t h2o_buffer_reserve(h2o_buffer_t **_inbuf, size_t min_guarantee)
{
    h2o_buffer_t *inbuf = *_inbuf;
    h2o_iovec_t ret;

    if (inbuf->bytes == NULL) {
        h2o_buffer_prototype_t *prototype = H2O_STRUCT_FROM_MEMBER(h2o_buffer_prototype_t, _initial_buf, inbuf);
        if (min_guarantee <= prototype->_initial_buf.capacity) {
            min_guarantee = prototype->_initial_buf.capacity;
            inbuf = h2o_mem_alloc_recycle(&prototype->allocator, offsetof(h2o_buffer_t, _buf) + min_guarantee);
        } else {
            inbuf = h2o_mem_alloc(offsetof(h2o_buffer_t, _buf) + min_guarantee);
        }
        *_inbuf = inbuf;
        inbuf->size = 0;
        inbuf->bytes = inbuf->_buf;
        inbuf->capacity = min_guarantee;
        inbuf->_prototype = prototype;
        inbuf->_fd = -1;
    } else {
        if (min_guarantee <= inbuf->capacity - inbuf->size - (inbuf->bytes - inbuf->_buf)) {
            /* ok */
        } else if ((inbuf->size + min_guarantee) * 2 <= inbuf->capacity) {
            /* the capacity should be less than or equal to 2 times of: size + guarantee */
            memmove(inbuf->_buf, inbuf->bytes, inbuf->size);
            inbuf->bytes = inbuf->_buf;
        } else {
            size_t new_capacity = inbuf->capacity;
            do {
                new_capacity *= 2;
            } while (new_capacity - inbuf->size < min_guarantee);
            if (inbuf->_prototype->mmap_settings != NULL && inbuf->_prototype->mmap_settings->threshold <= new_capacity) {
                size_t new_allocsize = topagesize(new_capacity);
                int fd;
                h2o_buffer_t *newp;
                if (inbuf->_fd == -1) {
                    char *tmpfn = alloca(strlen(inbuf->_prototype->mmap_settings->fn_template) + 1);
                    strcpy(tmpfn, inbuf->_prototype->mmap_settings->fn_template);
                    if ((fd = mkstemp(tmpfn)) == -1) {
                        fprintf(stderr, "failed to create temporary file:%s:%s\n", tmpfn, strerror(errno));
                        goto MapError;
                    }
                    unlink(tmpfn);
                } else {
                    fd = inbuf->_fd;
                }
                int fallocate_ret;
#if USE_POSIX_FALLOCATE
                fallocate_ret = posix_fallocate(fd, 0, new_allocsize);
#else
                fallocate_ret = ftruncate(fd, new_allocsize);
#endif
                if (fallocate_ret != 0) {
                    perror("failed to resize temporary file");
                    goto MapError;
                }
                if ((newp = (void *)mmap(NULL, new_allocsize, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0)) == MAP_FAILED) {
                    perror("mmap failed");
                    goto MapError;
                }
                if (inbuf->_fd == -1) {
                    /* copy data (moving from malloc to mmap) */
                    newp->size = inbuf->size;
                    newp->bytes = newp->_buf;
                    newp->capacity = new_capacity;
                    newp->_prototype = inbuf->_prototype;
                    newp->_fd = fd;
                    memcpy(newp->_buf, inbuf->bytes, inbuf->size);
                    h2o_buffer__do_free(inbuf);
                    *_inbuf = inbuf = newp;
                } else {
                    /* munmap */
                    size_t offset = inbuf->bytes - inbuf->_buf;
                    munmap((void *)inbuf, topagesize(inbuf->capacity));
                    *_inbuf = inbuf = newp;
                    inbuf->capacity = new_capacity;
                    inbuf->bytes = newp->_buf + offset;
                }
            } else {
                h2o_buffer_t *newp = h2o_mem_alloc(offsetof(h2o_buffer_t, _buf) + new_capacity);
                newp->size = inbuf->size;
                newp->bytes = newp->_buf;
                newp->capacity = new_capacity;
                newp->_prototype = inbuf->_prototype;
                newp->_fd = -1;
                memcpy(newp->_buf, inbuf->bytes, inbuf->size);
                h2o_buffer__do_free(inbuf);
                *_inbuf = inbuf = newp;
            }
        }
    }

    ret.base = inbuf->bytes + inbuf->size;
    ret.len = inbuf->_buf + inbuf->capacity - ret.base;

    return ret;

MapError:
    ret.base = NULL;
    ret.len = 0;
    return ret;
}

void h2o_buffer_consume(h2o_buffer_t **_inbuf, size_t delta)
{
    h2o_buffer_t *inbuf = *_inbuf;

    if (delta != 0) {
        assert(inbuf->bytes != NULL);
        if (inbuf->size == delta) {
            *_inbuf = &inbuf->_prototype->_initial_buf;
            h2o_buffer__do_free(inbuf);
        } else {
            inbuf->size -= delta;
            inbuf->bytes += delta;
        }
    }
}

void h2o_buffer__dispose_linked(void *p)
{
    h2o_buffer_t **buf = p;
    h2o_buffer_dispose(buf);
}

void h2o_vector__expand(h2o_mem_pool_t *pool, h2o_vector_t *vector, size_t element_size, size_t new_capacity)
{
    void *new_entries;
    assert(vector->capacity < new_capacity);
    if (vector->capacity == 0)
        vector->capacity = 4;
    while (vector->capacity < new_capacity)
        vector->capacity *= 2;
    if (pool != NULL) {
        new_entries = h2o_mem_alloc_pool(pool, element_size * vector->capacity);
        h2o_memcpy(new_entries, vector->entries, element_size * vector->size);
    } else {
        new_entries = h2o_mem_realloc(vector->entries, element_size * vector->capacity);
    }
    vector->entries = new_entries;
}

void h2o_mem_swap(void *_x, void *_y, size_t len)
{
    char *x = _x, *y = _y;
    char buf[256];

    while (len != 0) {
        size_t blocksz = len < sizeof(buf) ? len : sizeof(buf);
        memcpy(buf, x, blocksz);
        memcpy(x, y, blocksz);
        memcpy(y, buf, blocksz);
        len -= blocksz;
        x += blocksz;
        y += blocksz;
    }
}

void h2o_dump_memory(FILE *fp, const char *buf, size_t len)
{
    size_t i, j;

    for (i = 0; i < len; i += 16) {
        fprintf(fp, "%08zx", i);
        for (j = 0; j != 16; ++j) {
            if (i + j < len)
                fprintf(fp, " %02x", (int)(unsigned char)buf[i + j]);
            else
                fprintf(fp, "   ");
        }
        fprintf(fp, " ");
        for (j = 0; j != 16 && i + j < len; ++j) {
            int ch = buf[i + j];
            fputc(' ' <= ch && ch < 0x7f ? ch : '.', fp);
        }
        fprintf(fp, "\n");
    }
}

void h2o_append_to_null_terminated_list(void ***list, void *element)
{
    size_t cnt;

    for (cnt = 0; (*list)[cnt] != NULL; ++cnt)
        ;
    *list = h2o_mem_realloc(*list, (cnt + 2) * sizeof(void *));
    (*list)[cnt++] = element;
    (*list)[cnt] = NULL;
}
