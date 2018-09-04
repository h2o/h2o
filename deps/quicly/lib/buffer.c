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
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "picotls.h"
#include "quicly/buffer.h"

#define INTERNAL_MIN_CAPACITY (2048 - offsetof(struct st_quicly_buffer_vec_t, _buf))
#define INTERNAL_EXACT_CAPACITY_THRESHOLD (1024 * 1024)

static struct st_quicly_buffer_vec_t *get_tail(quicly_buffer_t *buf)
{
    return (void *)((char *)buf->tail_ref - offsetof(struct st_quicly_buffer_vec_t, next));
}

static size_t alloc_size(quicly_buffer_t *buf, size_t sz)
{
    size_t optimal = buf->len;
    if (optimal < INTERNAL_MIN_CAPACITY) {
        optimal = INTERNAL_MIN_CAPACITY;
    } else if (optimal > INTERNAL_EXACT_CAPACITY_THRESHOLD) {
        optimal = INTERNAL_EXACT_CAPACITY_THRESHOLD;
    }

    return sz < optimal ? optimal : sz;
}

static struct st_quicly_buffer_vec_t *new_vec(quicly_buffer_t *buf, size_t internal_capacity)
{
    struct st_quicly_buffer_vec_t *vec;

    if ((vec = malloc(offsetof(struct st_quicly_buffer_vec_t, _buf) + internal_capacity)) == NULL)
        return NULL;

    vec->next = NULL;
    *buf->tail_ref = vec;
    buf->tail_ref = &vec->next;
    buf->capacity = internal_capacity;
    return vec;
}

static void free_noop(struct st_quicly_buffer_vec_t *vec)
{
}

static void free_internal(struct st_quicly_buffer_vec_t *vec)
{
    free(vec);
}

void quicly_buffer_dispose(quicly_buffer_t *buf)
{
    struct st_quicly_buffer_vec_t *vec;

    while ((vec = buf->first) != NULL) {
        buf->first = vec->next;
        vec->len = 0; /* fast path of apply_stream_frame relies on the field reset on disposal */
        vec->free_cb(vec);
    }
}

void quicly_buffer_set_fast_external(quicly_buffer_t *buf, struct st_quicly_buffer_vec_t *vec, const void *p, size_t len)
{
    assert(buf->first == NULL);

    vec->p = (void *)p;
    vec->len = len;
    vec->next = NULL;
    vec->free_cb = free_noop;
    buf->first = vec;
    buf->tail_ref = &vec->next;
    buf->len = len;
    buf->skip = 0;
}

static int push_external(quicly_buffer_t *buf, const void *p, size_t len, quicly_buffer_free_cb free_cb)
{
    struct st_quicly_buffer_vec_t *vec;

    assert(len != 0);

    if ((vec = new_vec(buf, 0)) == NULL)
        return PTLS_ERROR_NO_MEMORY;

    vec->p = (void *)p;
    vec->len = len;
    vec->free_cb = free_cb;
    buf->len += len;

    return 0;
}

static int push_internal(quicly_buffer_t *buf, const void *p, size_t len)
{
    struct st_quicly_buffer_vec_t *vec;

    if (len == 0)
        return 0;

    /* push to current tail, if possible */
    if (buf->first != NULL) {
        vec = get_tail(buf);
        if (vec->len < buf->capacity) {
            size_t copysize = len;
            if (copysize > buf->capacity - vec->len)
                copysize = buf->capacity - vec->len;
            memcpy(vec->_buf + vec->len, p, copysize);
            vec->len += copysize;
            buf->len += copysize;
            p = (char *)p + copysize;
            if ((len -= copysize) == 0)
                return 0;
        }
    }

    /* allocate new vec and save */
    if ((vec = new_vec(buf, alloc_size(buf, len))) == NULL)
        return PTLS_ERROR_NO_MEMORY;
    vec->p = vec->_buf;
    memcpy(vec->_buf, p, len);
    vec->len = len;
    vec->free_cb = free_internal;
    buf->len += len;

    return 0;
}

int quicly_buffer_push(quicly_buffer_t *buf, const void *p, size_t len, quicly_buffer_free_cb free_cb)
{

    return free_cb != NULL ? push_external(buf, p, len, free_cb) : push_internal(buf, p, len);
}

int quicly_buffer_write(quicly_buffer_t *buf, size_t pos, const void *p, size_t len)
{
    quicly_buffer_iter_t iter;

    if (len == 0)
        return 0;

    /* fast path */
    if (buf->len == pos)
        return quicly_buffer_push(buf, p, len, NULL);

    if (buf->len < pos + len) {
        size_t newlen = pos + len;
        /* adjust the size of the current tail */
        if (buf->capacity != 0) {
            struct st_quicly_buffer_vec_t *tail = get_tail(buf);
            size_t space_avail = buf->capacity - tail->len;
            if (newlen <= buf->len + space_avail) {
                tail->len += pos + len - buf->len;
                buf->len = newlen;
            } else {
                buf->len += buf->capacity - tail->len;
                tail->len = buf->capacity;
            }
        }
        /* expand the buffer if necessary */
        if (buf->len < newlen) {
            struct st_quicly_buffer_vec_t *vec;
            size_t veclen = newlen - buf->len;
            if ((vec = new_vec(buf, alloc_size(buf, veclen))) == NULL)
                return PTLS_ERROR_NO_MEMORY;
            vec->p = vec->_buf;
            vec->len = veclen;
            vec->free_cb = free_internal;
            buf->len = newlen;
        }
    }

    quicly_buffer_init_iter(buf, &iter);
    quicly_buffer_advance_iter(&iter, pos);
    for (; len != 0; iter.vec = iter.vec->next, iter.vec_off = 0) {
        size_t copysize = iter.vec->len - iter.vec_off;
        if (len < copysize)
            copysize = len;
        memcpy(iter.vec->p + iter.vec_off, p, copysize);
        p = p + copysize;
        len -= copysize;
    }

    return 0;
}

size_t quicly_buffer_shift(quicly_buffer_t *buf, size_t delta)
{
    struct st_quicly_buffer_vec_t *vec;
    size_t avail_in_vec;

    while ((vec = buf->first) != NULL) {
        if ((avail_in_vec = vec->len - buf->skip) > delta) {
            buf->skip += delta;
            buf->len -= delta;
            return 0;
        }
        buf->len -= avail_in_vec;
        delta -= avail_in_vec;
        buf->first = vec->next;
        buf->skip = 0;
        vec->free_cb(vec);
    }
    assert(buf->len == 0);
    buf->tail_ref = &buf->first;
    buf->capacity = 0;

    return delta;
}

void quicly_buffer_emit(quicly_buffer_iter_t *iter, size_t nbytes, void *_dst)
{
    uint8_t *dst = _dst;

    while (nbytes != 0) {
        size_t l = iter->vec->len - iter->vec_off;
        if (nbytes < l)
            l = nbytes;
        memcpy(dst, iter->vec->p + iter->vec_off, l);
        dst += l;
        if ((iter->vec_off += l) == iter->vec->len) {
            iter->vec = iter->vec->next;
            iter->vec_off = 0;
        }
        nbytes -= l;
    }
}
