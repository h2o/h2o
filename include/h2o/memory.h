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
#ifndef h2o__memory_h
#define h2o__memory_h

#include <assert.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#define H2O_TO__STR(n) #n
#define H2O_TO_STR(n) H2O_TO__STR(n)

#define H2O_STRLIT(s) (s), sizeof(s) - 1
#define H2O_STRUCT_FROM_MEMBER(s, m, p) ((s*)((char*)(p) - offsetof(s, m)))

/**
 * buffer structure compatible with iovec
 */
typedef struct st_h2o_buf_t {
    char *base;
    size_t len;
} h2o_buf_t;

typedef struct st_h2o_mempool_chunk_t {
    struct st_h2o_mempool_chunk_t *next;
    size_t offset;
    char bytes[4096 - sizeof(void*) * 2];
} h2o_mempool_chunk_t;

typedef struct st_h2o_mempool_shared_entry_t {
    size_t refcnt;
    size_t _dummy; /* align to 2*sizeof(void*) */
    char bytes[1];
} h2o_mempool_shared_entry_t;

/**
 * the memory pool
 */
typedef struct st_h2o_mempool_t {
    h2o_mempool_chunk_t *chunks;
    struct st_h2o_mempool_shared_ref_t *shared_refs;
    struct st_h2o_mempool_direct_t *directs;
    h2o_mempool_chunk_t _first_chunk;
} h2o_mempool_t;

/**
 * buffer used to store incoming octets
 */
typedef struct st_h2o_input_buffer_t {
    /**
     * amount of the data available
     */
    size_t size;
    /**
     * pointer to the start of the data
     */
    char *bytes;
    size_t _capacity;
    char _buf[1];
} h2o_input_buffer_t;

#define H2O_VECTOR(type) \
    struct { \
        type *entries; \
        size_t size; \
        size_t capacity; \
    }

typedef H2O_VECTOR(void) h2o_vector_t;

/* memory */

/**
 * prints an error message and aborts
 */
void h2o_fatal(const char *msg);

/**
 * constructor for h2o_buf_t
 */
static h2o_buf_t h2o_buf_init(const void *base, size_t len);
/**
 * wrapper of malloc; allocates given size of memory or dies if impossible
 */
static void *h2o_malloc(size_t sz);
/**
 * warpper of realloc; reallocs the given chunk or dies if impossible
 */
static void *h2o_realloc(void *oldp, size_t sz);
/**
 * initializes the memory pool.
 */
void h2o_mempool_init(h2o_mempool_t *pool);
/**
 * clears the memory pool.
 * Applications may dispose the pool after calling the function or reuse it without calling h2o_mempool_init.
 */
void h2o_mempool_clear(h2o_mempool_t *pool);
/**
 * allocates given size of memory from the memory pool, or dies if impossible
 */
void *h2o_mempool_alloc(h2o_mempool_t *pool, size_t sz);
/**
 * allocates a ref-counted chunk of given size from the memory pool, or dies if impossible.
 * The ref-count of the returned chunk is 1 regardless of whether or not the chunk is linked to a pool.
 * @param pool pool to which the allocated chunk should be linked (or NULL to allocate an orphan chunk)
 */
void *h2o_mempool_alloc_shared(h2o_mempool_t *pool, size_t sz);
/**
 * links a ref-counted chunk to a memory pool.
 * The ref-count of the chunk will be decremented when the pool is cleared.
 * It is permitted to link a chunk more than once to a single pool.
 */
void h2o_mempool_link_shared(h2o_mempool_t *pool, void *p);
/**
 * increments the reference count of a ref-counted chunk.
 */
static void h2o_mempool_addref_shared(void *p);
/**
 * decrements the reference count of a ref-counted chunk.
 * The chunk gets freed when the ref-count reaches zero.
 */
static int h2o_mempool_release_shared(void *p);
/**
 * allocates a input buffer.
 * @param inbuf - pointer to a pointer pointing to the structure (set *inbuf to NULL to allocate a new buffer)
 * @param initial_size an advisory value for the initial size of the input buffer
 * @return buffer to which the next data should be stored
 */
h2o_buf_t h2o_allocate_input_buffer(h2o_input_buffer_t **inbuf, size_t initial_size);
/**
 * throws away given size of the data from the buffer.
 * @param delta number of octets to be drained from the buffer
 */
void h2o_consume_input_buffer(h2o_input_buffer_t **inbuf, size_t delta);
/**
 * grows the vector so that it could store at least new_capacity elements of given size (or dies if impossible).
 * @param pool memory pool that the vector is using
 * @param vector the vector
 * @param element_size size of the elements stored in the vector
 * @param new_capacity the capacity of the buffer after the function returns
 */
static void h2o_vector_reserve(h2o_mempool_t *pool, h2o_vector_t *vector, size_t element_size, size_t new_capacity);
void h2o_vector__expand(h2o_mempool_t *pool, h2o_vector_t *vector, size_t element_size, size_t new_capacity);

/**
 * tests if target chunk (target_len bytes long) is equal to test chunk (test_len bytes long)
 */
static int h2o_memis(const void *target, size_t target_len, const void *test, size_t test_len);
/**
 * duplicates given string
 * @param pool memory pool (or NULL to use malloc)
 * @param s source string
 * @param len length of the source string (the result of strlen(s) used in case len is SIZE_MAX)
 * @return buffer pointing to the duplicated string (buf is NUL-terminated but the length does not include the NUL char)
 */
h2o_buf_t h2o_strdup(h2o_mempool_t *pool, const char *s, size_t len);

/* inline defs */

inline h2o_buf_t h2o_buf_init(const void *base, size_t len)
{
    /* intentionally declared to take a "const void*" since it may contain any type of data and since _some_ buffers are constant */
    h2o_buf_t buf;
    buf.base = (char*)base;
    buf.len = len;
    return buf;
}

inline void *h2o_malloc(size_t sz)
{
    void *p = malloc(sz);
    if (p == NULL)
        h2o_fatal("no memory");
    return p;
}

inline void *h2o_realloc(void *oldp, size_t sz)
{
    void *newp = realloc(oldp, sz);
    if (newp == NULL) {
        h2o_fatal("no memory");
        return oldp;
    }
    return newp;
}

inline void h2o_mempool_addref_shared(void *p)
{
    struct st_h2o_mempool_shared_entry_t *entry = H2O_STRUCT_FROM_MEMBER(struct st_h2o_mempool_shared_entry_t, bytes, p);
    assert(entry->refcnt != 0);
    ++entry->refcnt;
}

inline int h2o_mempool_release_shared(void *p)
{
    struct st_h2o_mempool_shared_entry_t *entry = H2O_STRUCT_FROM_MEMBER(struct st_h2o_mempool_shared_entry_t, bytes, p);
    if (--entry->refcnt == 0) {
        free(entry);
        return 1;
    }
    return 0;
}

inline void h2o_vector_reserve(h2o_mempool_t *pool, h2o_vector_t *vector, size_t element_size, size_t new_capacity)
{
    if (vector->capacity < new_capacity) {
        h2o_vector__expand(pool, vector, element_size, new_capacity);
    }
}

inline int h2o_memis(const void *_target, size_t target_len, const void *_test, size_t test_len)
{
    const char *target = _target, *test = _test;
    if (target_len != test_len)
        return 0;
    if (target_len == 0)
        return 1;
    if (target[0] != test[0])
        return 0;
    return memcmp(target + 1, test + 1, test_len - 1) == 0;
}

#endif
