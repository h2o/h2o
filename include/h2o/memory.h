/*
 * Copyright (c) 2014,2015 DeNA Co., Ltd., Kazuho Oku, Justin Zhu
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
#ifndef h2o__memory_h
#define h2o__memory_h

#ifdef __sun__
#include <alloca.h>
#endif
#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#define H2O_STRUCT_FROM_MEMBER(s, m, p) ((s *)((char *)(p)-offsetof(s, m)))

#if __GNUC__ >= 3
#define H2O_LIKELY(x) __builtin_expect(!!(x), 1)
#define H2O_UNLIKELY(x) __builtin_expect(!!(x), 0)
#else
#define H2O_LIKELY(x) (x)
#define H2O_UNLIKELY(x) (x)
#endif

#ifdef __GNUC__
#define H2O_GNUC_VERSION ((__GNUC__ << 16) | (__GNUC_MINOR__ << 8) | __GNUC_PATCHLEVEL__)
#else
#define H2O_GNUC_VERSION 0
#endif

#if __STDC_VERSION__ >= 201112L
#define H2O_NORETURN _Noreturn
#elif defined(__clang__) || defined(__GNUC__) && H2O_GNUC_VERSION >= 0x20500
// noreturn was not defined before gcc 2.5
#define H2O_NORETURN __attribute__((noreturn))
#else
#define H2O_NORETURN
#endif

#if !defined(__clang__) && defined(__GNUC__) && H2O_GNUC_VERSION >= 0x40900
// returns_nonnull was seemingly not defined before gcc 4.9 (exists in 4.9.1 but not in 4.8.2)
#define H2O_RETURNS_NONNULL __attribute__((returns_nonnull))
#else
#define H2O_RETURNS_NONNULL
#endif

#define H2O_TO__STR(n) #n
#define H2O_TO_STR(n) H2O_TO__STR(n)

#define H2O_BUILD_ASSERT(condition) ((void)sizeof(char[2 * !!(!__builtin_constant_p(condition) || (condition)) - 1]))

typedef struct st_h2o_buffer_prototype_t h2o_buffer_prototype_t;

/**
 * buffer structure compatible with iovec
 */
typedef struct st_h2o_iovec_t {
    char *base;
    size_t len;
} h2o_iovec_t;

typedef struct st_h2o_mem_recycle_t {
    size_t max;
    size_t cnt;
    struct st_h2o_mem_recycle_chunk_t *_link;
} h2o_mem_recycle_t;

struct st_h2o_mem_pool_shared_entry_t {
    size_t refcnt;
    void (*dispose)(void *);
    char bytes[1];
};

/**
 * the memory pool
 */
typedef struct st_h2o_mem_pool_t {
    struct st_h2o_mem_pool_chunk_t *chunks;
    size_t chunk_offset;
    struct st_h2o_mem_pool_shared_ref_t *shared_refs;
    struct st_h2o_mem_pool_direct_t *directs;
} h2o_mem_pool_t;

/**
 * buffer used to store incoming / outgoing octets
 */
typedef struct st_h2o_buffer_t {
    /**
     * capacity of the buffer (or minimum initial capacity in case of a prototype (i.e. bytes == NULL))
     */
    size_t capacity;
    /**
     * amount of the data available
     */
    size_t size;
    /**
     * pointer to the start of the data (or NULL if is pointing to a prototype)
     */
    char *bytes;
    /**
     * prototype (or NULL if the instance is part of the prototype (i.e. bytes == NULL))
     */
    h2o_buffer_prototype_t *_prototype;
    /**
     * file descriptor (if not -1, used to store the buffer)
     */
    int _fd;
    char _buf[1];
} h2o_buffer_t;

typedef struct st_h2o_buffer_mmap_settings_t {
    size_t threshold;
    char fn_template[FILENAME_MAX];
} h2o_buffer_mmap_settings_t;

struct st_h2o_buffer_prototype_t {
    h2o_mem_recycle_t allocator;
    h2o_buffer_t _initial_buf;
    h2o_buffer_mmap_settings_t *mmap_settings;
};

#define H2O_VECTOR(type)                                                                                                           \
    struct {                                                                                                                       \
        type *entries;                                                                                                             \
        size_t size;                                                                                                               \
        size_t capacity;                                                                                                           \
    }

typedef H2O_VECTOR(void) h2o_vector_t;
typedef H2O_VECTOR(h2o_iovec_t) h2o_iovec_vector_t;

extern void *(*h2o_mem__set_secure)(void *, int, size_t);

/**
 * prints an error message and aborts
 */
#define h2o_fatal(msg) h2o__fatal(__FILE__ ":" H2O_TO_STR(__LINE__) ":" msg)
H2O_NORETURN void h2o__fatal(const char *msg);

/**
 * A version of memcpy that can take a NULL @src to avoid UB
 */
static void *h2o_memcpy(void *dst, const void *src, size_t n);
/**
 * constructor for h2o_iovec_t
 */
static h2o_iovec_t h2o_iovec_init(const void *base, size_t len);
/**
 * wrapper of malloc; allocates given size of memory or dies if impossible
 */
H2O_RETURNS_NONNULL static void *h2o_mem_alloc(size_t sz);
/**
 * warpper of realloc; reallocs the given chunk or dies if impossible
 */
static void *h2o_mem_realloc(void *oldp, size_t sz);

/**
 * allocates memory using the reusing allocator
 */
void *h2o_mem_alloc_recycle(h2o_mem_recycle_t *allocator, size_t sz);
/**
 * returns the memory to the reusing allocator
 */
void h2o_mem_free_recycle(h2o_mem_recycle_t *allocator, void *p);

/**
 * initializes the memory pool.
 */
void h2o_mem_init_pool(h2o_mem_pool_t *pool);
/**
 * clears the memory pool.
 * Applications may dispose the pool after calling the function or reuse it without calling h2o_mem_init_pool.
 */
void h2o_mem_clear_pool(h2o_mem_pool_t *pool);
/**
 * allocates given size of memory from the memory pool, or dies if impossible
 */
void *h2o_mem_alloc_pool(h2o_mem_pool_t *pool, size_t sz);
/**
 * allocates a ref-counted chunk of given size from the memory pool, or dies if impossible.
 * The ref-count of the returned chunk is 1 regardless of whether or not the chunk is linked to a pool.
 * @param pool pool to which the allocated chunk should be linked (or NULL to allocate an orphan chunk)
 */
void *h2o_mem_alloc_shared(h2o_mem_pool_t *pool, size_t sz, void (*dispose)(void *));
/**
 * links a ref-counted chunk to a memory pool.
 * The ref-count of the chunk will be decremented when the pool is cleared.
 * It is permitted to link a chunk more than once to a single pool.
 */
void h2o_mem_link_shared(h2o_mem_pool_t *pool, void *p);
/**
 * increments the reference count of a ref-counted chunk.
 */
static void h2o_mem_addref_shared(void *p);
/**
 * decrements the reference count of a ref-counted chunk.
 * The chunk gets freed when the ref-count reaches zero.
 */
static int h2o_mem_release_shared(void *p);
/**
 * initialize the buffer using given prototype.
 */
static void h2o_buffer_init(h2o_buffer_t **buffer, h2o_buffer_prototype_t *prototype);
/**
 *
 */
void h2o_buffer__do_free(h2o_buffer_t *buffer);
/**
 * disposes of the buffer
 */
static void h2o_buffer_dispose(h2o_buffer_t **buffer);
/**
 * allocates a buffer.
 * @param inbuf - pointer to a pointer pointing to the structure (set *inbuf to NULL to allocate a new buffer)
 * @param min_guarantee minimum number of bytes to reserve
 * @return buffer to which the next data should be stored
 * @note When called against a new buffer, the function returns a buffer twice the size of requested guarantee.  The function uses
 * exponential backoff for already-allocated buffers.
 */
h2o_iovec_t h2o_buffer_reserve(h2o_buffer_t **inbuf, size_t min_guarantee);
/**
 * throws away given size of the data from the buffer.
 * @param delta number of octets to be drained from the buffer
 */
void h2o_buffer_consume(h2o_buffer_t **inbuf, size_t delta);
/**
 * resets the buffer prototype
 */
static void h2o_buffer_set_prototype(h2o_buffer_t **buffer, h2o_buffer_prototype_t *prototype);
/**
 * registers a buffer to memory pool, so that it would be freed when the pool is flushed.  Note that the buffer cannot be resized
 * after it is linked.
 */
static void h2o_buffer_link_to_pool(h2o_buffer_t *buffer, h2o_mem_pool_t *pool);
void h2o_buffer__dispose_linked(void *p);
/**
 * grows the vector so that it could store at least new_capacity elements of given size (or dies if impossible).
 * @param pool memory pool that the vector is using
 * @param vector the vector
 * @param element_size size of the elements stored in the vector
 * @param new_capacity the capacity of the buffer after the function returns
 */
#define h2o_vector_reserve(pool, vector, new_capacity)                                                                             \
    h2o_vector__reserve((pool), (h2o_vector_t *)(void *)(vector), sizeof((vector)->entries[0]), (new_capacity))
static void h2o_vector__reserve(h2o_mem_pool_t *pool, h2o_vector_t *vector, size_t element_size, size_t new_capacity);
void h2o_vector__expand(h2o_mem_pool_t *pool, h2o_vector_t *vector, size_t element_size, size_t new_capacity);
/**
 * erase the entry at given index from the vector
 */
#define h2o_vector_erase(vector, index) h2o_vector__erase((h2o_vector_t *)(void *)(vector), sizeof((vector)->entries[0]), (index))
static void h2o_vector__erase(h2o_vector_t *vector, size_t element_size, size_t index);

/**
 * tests if target chunk (target_len bytes long) is equal to test chunk (test_len bytes long)
 */
static int h2o_memis(const void *target, size_t target_len, const void *test, size_t test_len);

/**
 * variant of memchr that searches the string from tail
 */
static void *h2o_memrchr(const void *s, int c, size_t n);

/**
 * secure memset
 */
static void *h2o_mem_set_secure(void *b, int c, size_t len);

/**
 * swaps contents of memory
 */
void h2o_mem_swap(void *x, void *y, size_t len);

/**
 * emits hexdump of given buffer to fp
 */
void h2o_dump_memory(FILE *fp, const char *buf, size_t len);

/**
 * appends an element to a NULL-terminated list allocated using malloc
 */
void h2o_append_to_null_terminated_list(void ***list, void *element);

/* inline defs */

inline void *h2o_memcpy(void *dst, const void *src, size_t n)
{
    if (src != NULL)
        return memcpy(dst, src, n);
    else if (n != 0)
        h2o_fatal("null pointer passed to memcpy");
    return dst;
}

inline h2o_iovec_t h2o_iovec_init(const void *base, size_t len)
{
    /* intentionally declared to take a "const void*" since it may contain any type of data and since _some_ buffers are constant */
    h2o_iovec_t buf;
    buf.base = (char *)base;
    buf.len = len;
    return buf;
}

inline void *h2o_mem_alloc(size_t sz)
{
    void *p = malloc(sz);
    if (p == NULL)
        h2o_fatal("no memory");
    return p;
}

inline void *h2o_mem_realloc(void *oldp, size_t sz)
{
    void *newp = realloc(oldp, sz);
    if (newp == NULL) {
        h2o_fatal("no memory");
        return oldp;
    }
    return newp;
}

inline void h2o_mem_addref_shared(void *p)
{
    struct st_h2o_mem_pool_shared_entry_t *entry = H2O_STRUCT_FROM_MEMBER(struct st_h2o_mem_pool_shared_entry_t, bytes, p);
    assert(entry->refcnt != 0);
    ++entry->refcnt;
}

inline int h2o_mem_release_shared(void *p)
{
    struct st_h2o_mem_pool_shared_entry_t *entry = H2O_STRUCT_FROM_MEMBER(struct st_h2o_mem_pool_shared_entry_t, bytes, p);
    if (--entry->refcnt == 0) {
        if (entry->dispose != NULL)
            entry->dispose(entry->bytes);
        free(entry);
        return 1;
    }
    return 0;
}

inline void h2o_buffer_init(h2o_buffer_t **buffer, h2o_buffer_prototype_t *prototype)
{
    *buffer = &prototype->_initial_buf;
}

inline void h2o_buffer_dispose(h2o_buffer_t **_buffer)
{
    h2o_buffer_t *buffer = *_buffer;
    *_buffer = NULL;
    if (buffer->bytes != NULL)
        h2o_buffer__do_free(buffer);
}

inline void h2o_buffer_set_prototype(h2o_buffer_t **buffer, h2o_buffer_prototype_t *prototype)
{
    if ((*buffer)->_prototype != NULL)
        (*buffer)->_prototype = prototype;
    else
        *buffer = &prototype->_initial_buf;
}

inline void h2o_buffer_link_to_pool(h2o_buffer_t *buffer, h2o_mem_pool_t *pool)
{
    h2o_buffer_t **slot = (h2o_buffer_t **)h2o_mem_alloc_shared(pool, sizeof(*slot), h2o_buffer__dispose_linked);
    *slot = buffer;
}

inline void h2o_vector__reserve(h2o_mem_pool_t *pool, h2o_vector_t *vector, size_t element_size, size_t new_capacity)
{
    if (vector->capacity < new_capacity) {
        h2o_vector__expand(pool, vector, element_size, new_capacity);
    }
}

inline void h2o_vector__erase(h2o_vector_t *vector, size_t element_size, size_t index)
{
    char *entries = (char *)vector->entries;
    memmove(entries + element_size * index, entries + element_size * (index + 1), vector->size - index - 1);
    --vector->size;
}

inline int h2o_memis(const void *_target, size_t target_len, const void *_test, size_t test_len)
{
    const char *target = (const char *)_target, *test = (const char *)_test;
    if (target_len != test_len)
        return 0;
    if (target_len == 0)
        return 1;
    if (target[0] != test[0])
        return 0;
    return memcmp(target + 1, test + 1, test_len - 1) == 0;
}

inline void *h2o_memrchr(const void *s, int c, size_t n)
{
    if (n != 0) {
        const char *p = (const char *)s + n;
        do {
            if (*--p == c)
                return (void *)p;
        } while (p != s);
    }
    return NULL;
}

inline void *h2o_mem_set_secure(void *b, int c, size_t len)
{
    return h2o_mem__set_secure(b, c, len);
}

#ifdef __cplusplus
}
#endif

#endif
