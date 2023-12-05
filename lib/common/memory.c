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
#include <stdarg.h>
#include <sys/mman.h>
#include <unistd.h>
#include "h2o/memory.h"
#include "h2o/file.h"

#if defined(__linux__)
#if defined(__ANDROID__) && (__ANDROID_API__ < 21)
#define USE_POSIX_FALLOCATE 0
#else
#define USE_POSIX_FALLOCATE 1
#endif
#elif __FreeBSD__ >= 9
#define USE_POSIX_FALLOCATE 1
#elif __NetBSD__ >= 7
#define USE_POSIX_FALLOCATE 1
#else
#define USE_POSIX_FALLOCATE 0
#endif

#if defined(__clang__)
#if __has_feature(address_sanitizer)
#define ASAN_IN_USE 1
#endif
#elif __SANITIZE_ADDRESS__ /* gcc */
#define ASAN_IN_USE 1
#else
#define ASAN_IN_USE 0
#endif

struct st_h2o_mem_recycle_chunk_t {
    struct st_h2o_mem_recycle_chunk_t *next;
};

union un_h2o_mem_pool_chunk_t {
    union un_h2o_mem_pool_chunk_t *next;
    char bytes[4096];
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

void *(*volatile h2o_mem__set_secure)(void *, int, size_t) = memset;

static const h2o_mem_recycle_conf_t mem_pool_allocator_conf = {.memsize = sizeof(union un_h2o_mem_pool_chunk_t)};
__thread h2o_mem_recycle_t h2o_mem_pool_allocator = {&mem_pool_allocator_conf};
size_t h2o_mmap_errors = 0;

void h2o__fatal(const char *file, int line, const char *msg, ...)
{
    char buf[1024];
    va_list args;

    va_start(args, msg);
    vsnprintf(buf, sizeof(buf), msg, args);
    va_end(args);

    h2o_error_printf("fatal:%s:%d:%s\n", file, line, buf);

    abort();
}

void *h2o_mem_alloc_recycle(h2o_mem_recycle_t *allocator)
{
    if (allocator->chunks.size == 0)
        return h2o_mem_aligned_alloc(1 << allocator->conf->align_bits, allocator->conf->memsize);

    /* detach and return the pooled pointer */
    void *p = allocator->chunks.entries[--allocator->chunks.size];

    /* adjust low watermark */
    if (allocator->low_watermark > allocator->chunks.size)
        allocator->low_watermark = allocator->chunks.size;

    return p;
}

void h2o_mem_free_recycle(h2o_mem_recycle_t *allocator, void *p)
{
#if !ASAN_IN_USE
    /* register the pointer to the pool and return unless the pool is full */
    h2o_vector_reserve(NULL, &allocator->chunks, allocator->chunks.size + 1);
    allocator->chunks.entries[allocator->chunks.size++] = p;
#else
    free(p);
#endif
}

void h2o_mem_clear_recycle(h2o_mem_recycle_t *allocator, int full)
{
    /* Bail out if the allocator is in the initial (cleared) state. */
    if (allocator->chunks.capacity == 0)
        return;

    if (full) {
        allocator->low_watermark = 0;
    } else {
        /* Since the last invocation of `h2o_mem_clear_recycle`, at any given point, there was at least `low_watermark` buffers
         * being cached for reuse. Release half of them. Division by 2 is rounded up so that `low_watermark` eventually reaches zero
         * (instead of one) when there is no traffic. */
        size_t delta = (allocator->low_watermark + 1) / 2;
        assert(allocator->chunks.size >= delta);
        allocator->low_watermark = allocator->chunks.size - delta;
    }

    while (allocator->chunks.size > allocator->low_watermark)
        free(allocator->chunks.entries[--allocator->chunks.size]);

    if (allocator->chunks.size == 0) {
        free(allocator->chunks.entries);
        memset(&allocator->chunks, 0, sizeof(allocator->chunks));
    }
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
        union un_h2o_mem_pool_chunk_t *next = pool->chunks->next;
        h2o_mem_free_recycle(&h2o_mem_pool_allocator, pool->chunks);
        pool->chunks = next;
    }
    pool->chunk_offset = sizeof(pool->chunks->bytes);
}

void *h2o_mem__do_alloc_pool_aligned(h2o_mem_pool_t *pool, size_t alignment, size_t sz)
{
#define ALIGN_TO(x, a) (((x) + (a)-1) & ~((a)-1))
    void *ret;

    if (sz >= (sizeof(pool->chunks->bytes) - sizeof(pool->chunks->next)) / 4) {
        /* allocate large requests directly */
        struct st_h2o_mem_pool_direct_t *newp = h2o_mem_alloc(offsetof(struct st_h2o_mem_pool_direct_t, bytes) + sz);
        newp->next = pool->directs;
        pool->directs = newp;
        return newp->bytes;
    }

    /* return a valid pointer even for 0 sized allocs */
    if (H2O_UNLIKELY(sz == 0))
        sz = 1;

    pool->chunk_offset = ALIGN_TO(pool->chunk_offset, alignment);
    if (sizeof(pool->chunks->bytes) - pool->chunk_offset < sz) {
        /* allocate new chunk */
        union un_h2o_mem_pool_chunk_t *newp = h2o_mem_alloc_recycle(&h2o_mem_pool_allocator);
        newp->next = pool->chunks;
        pool->chunks = newp;
        pool->chunk_offset = ALIGN_TO(sizeof(newp->next), alignment);
    }

    ret = pool->chunks->bytes + pool->chunk_offset;
    pool->chunk_offset += sz;
    return ret;
#undef ALIGN_TO
}

static void link_shared(h2o_mem_pool_t *pool, struct st_h2o_mem_pool_shared_entry_t *entry)
{
    struct st_h2o_mem_pool_shared_ref_t *ref = h2o_mem_alloc_pool(pool, *ref, 1);
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

/**
 * size of the smallest bin is 4096 bytes (1<<12)
 */
#define H2O_BUFFER_MIN_ALLOC_POWER 12

static const h2o_mem_recycle_conf_t buffer_recycle_bins_zero_sized_conf = {.memsize = sizeof(h2o_buffer_t)};
/**
 * Retains recycle bins for `h2o_buffer_t`.
 */
static __thread struct {
    /**
     * Holds recycle bins for `h2o_buffer_t`. Bin for capacity 2^x is located at x - H2O_BUFFER_MIN_ALLOC_POWER.
     */
    struct buffer_recycle_bin_t {
        h2o_mem_recycle_conf_t conf;
        h2o_mem_recycle_t recycle;
    } *bins;
    /**
     * Bins for capacicties no greater than this value exist.
     */
    size_t largest_power;
    /**
     * Bin containing chunks of sizeof(h2o_buffer_t). This is used by empties buffers to retain the previous capacity.
     */
    h2o_mem_recycle_t zero_sized;
} buffer_recycle_bins = {NULL, H2O_BUFFER_MIN_ALLOC_POWER - 1, {&buffer_recycle_bins_zero_sized_conf}};

static unsigned buffer_size_to_power(size_t sz)
{
    assert(sz != 0);

    unsigned power = sizeof(unsigned long long) * 8 - __builtin_clzll(sz) - 1;
    if (power < H2O_BUFFER_MIN_ALLOC_POWER) {
        power = H2O_BUFFER_MIN_ALLOC_POWER;
    } else if (sz != (1 << power)) {
        ++power;
    }
    return power;
}

void h2o_buffer_clear_recycle(int full)
{
    for (unsigned i = H2O_BUFFER_MIN_ALLOC_POWER; i <= buffer_recycle_bins.largest_power; ++i)
        h2o_mem_clear_recycle(&buffer_recycle_bins.bins[i - H2O_BUFFER_MIN_ALLOC_POWER].recycle, full);

    if (full) {
        free(buffer_recycle_bins.bins);
        buffer_recycle_bins.bins = NULL;
        buffer_recycle_bins.largest_power = H2O_BUFFER_MIN_ALLOC_POWER - 1;
    }

    h2o_mem_clear_recycle(&buffer_recycle_bins.zero_sized, full);
}

int h2o_buffer_recycle_is_empty(void)
{
    for (unsigned i = H2O_BUFFER_MIN_ALLOC_POWER; i <= buffer_recycle_bins.largest_power; ++i) {
        if (!h2o_mem_recycle_is_empty(&buffer_recycle_bins.bins[i - H2O_BUFFER_MIN_ALLOC_POWER].recycle))
            return 0;
    }
    if (!h2o_mem_recycle_is_empty(&buffer_recycle_bins.zero_sized))
        return 0;
    return 1;
}

static h2o_mem_recycle_t *buffer_get_recycle(unsigned power, int only_if_exists)
{
    if (power > buffer_recycle_bins.largest_power) {
        if (only_if_exists)
            return NULL;
        buffer_recycle_bins.bins =
            h2o_mem_realloc(buffer_recycle_bins.bins, sizeof(*buffer_recycle_bins.bins) * (power - H2O_BUFFER_MIN_ALLOC_POWER + 1));
        for (size_t p = H2O_BUFFER_MIN_ALLOC_POWER; p <= buffer_recycle_bins.largest_power; ++p) {
            struct buffer_recycle_bin_t *bin = buffer_recycle_bins.bins + p - H2O_BUFFER_MIN_ALLOC_POWER;
            bin->recycle.conf = &bin->conf;
        }
        do {
            ++buffer_recycle_bins.largest_power;
            struct buffer_recycle_bin_t *newbin =
                buffer_recycle_bins.bins + buffer_recycle_bins.largest_power - H2O_BUFFER_MIN_ALLOC_POWER;
            newbin->conf = (h2o_mem_recycle_conf_t){.memsize = (size_t)1 << buffer_recycle_bins.largest_power};
            newbin->recycle = (h2o_mem_recycle_t){&newbin->conf};
        } while (buffer_recycle_bins.largest_power < power);
    }

    return &buffer_recycle_bins.bins[power - H2O_BUFFER_MIN_ALLOC_POWER].recycle;
}

static void buffer_init(h2o_buffer_t *buf, size_t size, char *bytes, size_t capacity, h2o_buffer_prototype_t *prototype, int fd)
{
    buf->size = size;
    buf->bytes = bytes;
    buf->capacity = capacity;
    buf->_prototype = prototype;
    buf->_fd = fd;
}

void h2o_buffer__do_free(h2o_buffer_t *buffer)
{
    assert(buffer->_prototype != NULL);

    if (buffer->_fd != -1) {
        close(buffer->_fd);
        munmap((void *)buffer, topagesize(buffer->capacity));
    } else {
        h2o_mem_recycle_t *allocator;
        if (buffer->bytes == NULL) {
            allocator = &buffer_recycle_bins.zero_sized;
        } else {
            unsigned power = buffer_size_to_power(offsetof(h2o_buffer_t, _buf) + buffer->capacity);
            assert(((size_t)1 << power) == offsetof(h2o_buffer_t, _buf) + buffer->capacity);
            allocator = buffer_get_recycle(power, 0);
            assert(allocator != NULL);
        }
        h2o_mem_free_recycle(allocator, buffer);
    }
}

h2o_iovec_t h2o_buffer_reserve(h2o_buffer_t **_inbuf, size_t min_guarantee)
{
    h2o_iovec_t reserved = h2o_buffer_try_reserve(_inbuf, min_guarantee);
    if (reserved.base == NULL) {
        h2o_fatal("failed to reserve buffer; capacity: %zu, min_guarantee: %zu", (*_inbuf)->capacity, min_guarantee);
    }
    return reserved;
}

static h2o_buffer_t *buffer_allocate(h2o_buffer_prototype_t *prototype, size_t min_capacity, size_t desired_capacity)
{
    h2o_buffer_t *newp;
    unsigned alloc_power;

    /* normalize */
    if (min_capacity < prototype->_initial_buf.capacity)
        min_capacity = prototype->_initial_buf.capacity;

    /* try to allocate at first using `desired_capacity`, otherwise bail out to AllocNormal */
    if (desired_capacity <= min_capacity)
        goto AllocNormal;
    alloc_power = buffer_size_to_power(offsetof(h2o_buffer_t, _buf) + desired_capacity);
    h2o_mem_recycle_t *allocator = buffer_get_recycle(alloc_power, 1);
    if (allocator == NULL || allocator->chunks.size == 0)
        goto AllocNormal;
    assert(allocator->conf->memsize == (size_t)1 << alloc_power);
    newp = h2o_mem_alloc_recycle(allocator);
    goto AllocDone;

AllocNormal:
    /* allocate using `min_capacity` */
    alloc_power = buffer_size_to_power(offsetof(h2o_buffer_t, _buf) + min_capacity);
    newp = h2o_mem_alloc_recycle(buffer_get_recycle(alloc_power, 0));

AllocDone:
    buffer_init(newp, 0, newp->_buf, ((size_t)1 << alloc_power) - offsetof(h2o_buffer_t, _buf), prototype, -1);
    return newp;
}

h2o_iovec_t h2o_buffer_try_reserve(h2o_buffer_t **_inbuf, size_t min_guarantee)
{
    h2o_buffer_t *inbuf = *_inbuf;
    h2o_iovec_t ret;

    if (inbuf->bytes == NULL) {
        h2o_buffer_prototype_t *prototype;
        size_t desired_capacity;
        if (inbuf->_prototype == NULL) {
            prototype = H2O_STRUCT_FROM_MEMBER(h2o_buffer_prototype_t, _initial_buf, inbuf);
            desired_capacity = 0;
        } else {
            prototype = inbuf->_prototype;
            desired_capacity = inbuf->capacity;
            h2o_mem_free_recycle(&buffer_recycle_bins.zero_sized, inbuf);
        }
        inbuf = buffer_allocate(prototype, min_guarantee, desired_capacity);
        *_inbuf = inbuf;
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
                    if ((fd = h2o_file_mktemp(inbuf->_prototype->mmap_settings->fn_template)) == -1) {
                        h2o_perror("failed to create temporary file");
                        goto MapError;
                    }
                } else {
                    fd = inbuf->_fd;
                }
                int fallocate_ret;
#if USE_POSIX_FALLOCATE
                fallocate_ret = posix_fallocate(fd, 0, new_allocsize);
                if (fallocate_ret != EINVAL) {
                    errno = fallocate_ret;
                } else
#endif
                    fallocate_ret = ftruncate(fd, new_allocsize);
                if (fallocate_ret != 0) {
                    h2o_perror("failed to resize temporary file");
                    goto MapError;
                }
                if ((newp = (void *)mmap(NULL, new_allocsize, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0)) == MAP_FAILED) {
                    h2o_perror("mmap failed");
                    goto MapError;
                }
                if (inbuf->_fd == -1) {
                    /* copy data (moving from malloc to mmap) */
                    buffer_init(newp, inbuf->size, newp->_buf, new_capacity, inbuf->_prototype, fd);
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
                unsigned alloc_power = buffer_size_to_power(offsetof(h2o_buffer_t, _buf) + new_capacity);
                new_capacity = ((size_t)1 << alloc_power) - offsetof(h2o_buffer_t, _buf);
                h2o_buffer_t *newp = h2o_mem_alloc_recycle(buffer_get_recycle(alloc_power, 0));
                buffer_init(newp, inbuf->size, newp->_buf, new_capacity, inbuf->_prototype, -1);
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
    __sync_add_and_fetch(&h2o_mmap_errors, 1);
    ret.base = NULL;
    ret.len = 0;
    return ret;
}

void h2o_buffer_consume(h2o_buffer_t **inbuf, size_t delta)
{
    if (delta != 0) {
        if ((*inbuf)->size == delta) {
            h2o_buffer_consume_all(inbuf, 0);
        } else {
            assert((*inbuf)->bytes != NULL);
            (*inbuf)->size -= delta;
            (*inbuf)->bytes += delta;
        }
    }
}

void h2o_buffer_consume_all(h2o_buffer_t **inbuf, int record_capacity)
{
    if ((*inbuf)->size != 0) {
        if (record_capacity) {
            h2o_buffer_t *newp = h2o_mem_alloc_recycle(&buffer_recycle_bins.zero_sized);
            buffer_init(newp, 0, NULL, (*inbuf)->capacity, (*inbuf)->_prototype, -1);
            h2o_buffer__do_free(*inbuf);
            *inbuf = newp;
        } else {
            h2o_buffer_t *prototype_buf = &(*inbuf)->_prototype->_initial_buf;
            h2o_buffer__do_free(*inbuf);
            *inbuf = prototype_buf;
        }
    }
}

void h2o_buffer__dispose_linked(void *p)
{
    h2o_buffer_t **buf = p;
    h2o_buffer_dispose(buf);
}

void h2o_vector__expand(h2o_mem_pool_t *pool, h2o_vector_t *vector, size_t alignment, size_t element_size, size_t new_capacity)
{
    void *new_entries;
    assert(vector->capacity < new_capacity);
    if (vector->capacity == 0)
        vector->capacity = 4;
    while (vector->capacity < new_capacity)
        vector->capacity *= 2;
    if (pool != NULL) {
        new_entries = h2o_mem_alloc_pool_aligned(pool, alignment, element_size * vector->capacity);
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

char *h2o_strerror_r(int err, char *buf, size_t len)
{
#if !(defined(_GNU_SOURCE) && defined(__gnu_linux__))
    strerror_r(err, buf, len);
    return buf;
#else
    /**
     * The GNU-specific strerror_r() returns a pointer to a string containing the error message.
     * This may be either a pointer to a string that the function stores in  buf,
     * or a pointer to some (immutable) static string (in which case buf is unused)
     */
    return strerror_r(err, buf, len);
#endif
}

void h2o_perror(const char *msg)
{
    char buf[128];

    h2o_error_printf("%s: %s\n", msg, h2o_strerror_r(errno, buf, sizeof(buf)));
}
