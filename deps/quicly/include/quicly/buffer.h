/*
 * Copyright (c) 2017 Fastly, Kazuho Oku
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
#ifndef quicly_buffer_h
#define quicly_buffer_h

#include <stddef.h>

typedef struct st_quicly_buffer_t quicly_buffer_t;
typedef struct st_quicly_buffer_vec_t quicly_buffer_vec_t;

typedef void (*quicly_buffer_free_cb)(quicly_buffer_t *buf, quicly_buffer_vec_t *vec);

struct st_quicly_buffer_vec_t {
    /**
     * pointer to next
     */
    quicly_buffer_vec_t *next;
    /**
     * pointer to data (points to _buf if the vector is internal)
     */
    uint8_t *p;
    /**
     * offset to where the data is stored
     */
    size_t len;
    /**
     * callback that destroys the vec
     */
    quicly_buffer_free_cb free_cb;
    /**
     * buffer used for internal vector
     */
    uint8_t _buf[1];
};

struct st_quicly_buffer_t {
    /**
     * references to the linked list of vec
     */
    quicly_buffer_vec_t *first, **tail_ref;
    /**
     * amount of data available
     */
    size_t len;
    /**
     * offset within the `first` where the data starts from
     */
    size_t skip;
    /**
     * capacity of the last vec
     */
    size_t capacity;
};

typedef struct st_quicly_buffer_iter_t {
    quicly_buffer_vec_t *vec;
    size_t vec_off;
} quicly_buffer_iter_t;

static void quicly_buffer_init(quicly_buffer_t *buf);
void quicly_buffer_dispose(quicly_buffer_t *buf);
void quicly_buffer_set_fast_external(quicly_buffer_t *buf, quicly_buffer_vec_t *vec, const void *p, size_t len);
int quicly_buffer_push(quicly_buffer_t *buf, const void *p, size_t len, quicly_buffer_free_cb free_cb);
int quicly_buffer_write(quicly_buffer_t *buf, size_t pos, const void *p, size_t len);
size_t quicly_buffer_shift(quicly_buffer_t *buf, size_t delta);
void quicly_buffer_emit(quicly_buffer_iter_t *iter, size_t nbytes, void *_dst);
static void quicly_buffer_init_iter(quicly_buffer_t *buf, quicly_buffer_iter_t *iter);
static void quicly_buffer_advance_iter(quicly_buffer_iter_t *iter, size_t nbytes);

/* inline definitions */

inline void quicly_buffer_init(quicly_buffer_t *buf)
{
    buf->first = NULL;
    buf->tail_ref = &buf->first;
    buf->len = 0;
    buf->skip = 0;
    buf->capacity = 0;
}

inline void quicly_buffer_init_iter(quicly_buffer_t *buf, quicly_buffer_iter_t *iter)
{
    iter->vec = buf->first;
    iter->vec_off = buf->skip;
}

inline void quicly_buffer_advance_iter(quicly_buffer_iter_t *iter, size_t nbytes)
{
    while (nbytes >= iter->vec->len - iter->vec_off) {
        nbytes -= iter->vec->len - iter->vec_off;
        iter->vec = iter->vec->next;
        iter->vec_off = 0;
    }
    iter->vec_off += nbytes;
}

#endif
