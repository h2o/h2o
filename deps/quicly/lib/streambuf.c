/*
 * Copyright (c) 2018 Fastly, Kazuho Oku
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
#include "quicly/streambuf.h"

void quicly_sendbuf_dispose(quicly_sendbuf_t *sb)
{
    size_t i;

    for (i = 0; i != sb->vecs.size; ++i) {
        quicly_sendbuf_vec_t *vec = sb->vecs.entries + i;
        if (vec->cb->discard_vec != NULL)
            vec->cb->discard_vec(vec);
    }
    free(sb->vecs.entries);
}

void quicly_sendbuf_shift(quicly_stream_t *stream, quicly_sendbuf_t *sb, size_t delta)
{
    size_t i;

    for (i = 0; delta != 0; ++i) {
        assert(i < sb->vecs.size);
        quicly_sendbuf_vec_t *first_vec = sb->vecs.entries + i;
        size_t bytes_in_first_vec = first_vec->len - sb->off_in_first_vec;
        if (delta < bytes_in_first_vec) {
            sb->off_in_first_vec += delta;
            break;
        }
        delta -= bytes_in_first_vec;
        if (first_vec->cb->discard_vec != NULL)
            first_vec->cb->discard_vec(first_vec);
        sb->off_in_first_vec = 0;
    }
    if (i != 0) {
        if (sb->vecs.size != i) {
            memmove(sb->vecs.entries, sb->vecs.entries + i, (sb->vecs.size - i) * sizeof(*sb->vecs.entries));
            sb->vecs.size -= i;
        } else {
            free(sb->vecs.entries);
            sb->vecs.entries = NULL;
            sb->vecs.size = 0;
            sb->vecs.capacity = 0;
        }
    }
    quicly_stream_sync_sendbuf(stream, 0);
}

int quicly_sendbuf_emit(quicly_stream_t *stream, quicly_sendbuf_t *sb, size_t off, void *dst, size_t *len, int *wrote_all)
{
    size_t vec_index, capacity = *len;
    int ret;

    off += sb->off_in_first_vec;
    for (vec_index = 0; capacity != 0 && vec_index < sb->vecs.size; ++vec_index) {
        quicly_sendbuf_vec_t *vec = sb->vecs.entries + vec_index;
        if (off < vec->len) {
            size_t bytes_flatten = vec->len - off;
            int partial = 0;
            if (capacity < bytes_flatten) {
                bytes_flatten = capacity;
                partial = 1;
            }
            if ((ret = vec->cb->flatten_vec(vec, dst, off, bytes_flatten)) != 0)
                return ret;
            dst = (uint8_t *)dst + bytes_flatten;
            capacity -= bytes_flatten;
            off = 0;
            if (partial)
                break;
        } else {
            off -= vec->len;
        }
    }

    if (capacity == 0 && vec_index < sb->vecs.size) {
        *wrote_all = 0;
    } else {
        *len = *len - capacity;
        *wrote_all = 1;
    }

    return 0;
}

static int flatten_raw(quicly_sendbuf_vec_t *vec, void *dst, size_t off, size_t len)
{
    memcpy(dst, (uint8_t *)vec->cbdata + off, len);
    return 0;
}

static void discard_raw(quicly_sendbuf_vec_t *vec)
{
    free(vec->cbdata);
}

int quicly_sendbuf_write(quicly_stream_t *stream, quicly_sendbuf_t *sb, const void *src, size_t len)
{
    static const quicly_streambuf_sendvec_callbacks_t raw_callbacks = {flatten_raw, discard_raw};
    quicly_sendbuf_vec_t vec = {&raw_callbacks, len, NULL};
    int ret;

    assert(quicly_sendstate_is_open(&stream->sendstate));

    if ((vec.cbdata = malloc(len)) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Error;
    }
    memcpy(vec.cbdata, src, len);
    if ((ret = quicly_sendbuf_write_vec(stream, sb, &vec)) != 0)
        goto Error;
    return 0;

Error:
    free(vec.cbdata);
    return ret;
}

int quicly_sendbuf_write_vec(quicly_stream_t *stream, quicly_sendbuf_t *sb, quicly_sendbuf_vec_t *vec)
{
    assert(sb->vecs.size <= sb->vecs.capacity);

    if (sb->vecs.size == sb->vecs.capacity) {
        quicly_sendbuf_vec_t *new_entries;
        size_t new_capacity = sb->vecs.capacity == 0 ? 4 : sb->vecs.capacity * 2;
        if ((new_entries = realloc(sb->vecs.entries, new_capacity * sizeof(*sb->vecs.entries))) == NULL)
            return PTLS_ERROR_NO_MEMORY;
        sb->vecs.entries = new_entries;
        sb->vecs.capacity = new_capacity;
    }
    sb->vecs.entries[sb->vecs.size++] = *vec;
    sb->bytes_written += vec->len;

    return quicly_stream_sync_sendbuf(stream, 1);
}

void quicly_recvbuf_shift(quicly_stream_t *stream, ptls_buffer_t *rb, size_t delta)
{
    assert(delta <= rb->off);
    rb->off -= delta;
    memmove(rb->base, rb->base + delta, rb->off);

    quicly_stream_sync_recvbuf(stream, delta);
}

ptls_iovec_t quicly_recvbuf_get(quicly_stream_t *stream, ptls_buffer_t *rb)
{
    size_t avail;

    if (quicly_recvstate_transfer_complete(&stream->recvstate)) {
        avail = rb->off;
    } else if (stream->recvstate.data_off < stream->recvstate.received.ranges[0].end) {
        avail = stream->recvstate.received.ranges[0].end - stream->recvstate.data_off;
    } else {
        avail = 0;
    }

    return ptls_iovec_init(rb->base, avail);
}

int quicly_recvbuf_receive(quicly_stream_t *stream, ptls_buffer_t *rb, size_t off, const void *src, size_t len)
{
    if (len != 0) {
        int ret;
        if ((ret = ptls_buffer_reserve(rb, off + len - rb->off)) != 0)
            return ret;
        memcpy(rb->base + off, src, len);
        if (rb->off < off + len)
            rb->off = off + len;
    }
    return 0;
}

int quicly_streambuf_create(quicly_stream_t *stream, size_t sz)
{
    quicly_streambuf_t *sbuf;

    assert(sz >= sizeof(*sbuf));
    assert(stream->data == NULL);

    if ((sbuf = malloc(sz)) == NULL)
        return PTLS_ERROR_NO_MEMORY;
    quicly_sendbuf_init(&sbuf->egress);
    ptls_buffer_init(&sbuf->ingress, "", 0);
    if (sz != sizeof(*sbuf))
        memset((char *)sbuf + sizeof(*sbuf), 0, sz - sizeof(*sbuf));

    stream->data = sbuf;
    return 0;
}

void quicly_streambuf_destroy(quicly_stream_t *stream, int err)
{
    quicly_streambuf_t *sbuf = stream->data;

    quicly_sendbuf_dispose(&sbuf->egress);
    ptls_buffer_dispose(&sbuf->ingress);
    free(sbuf);
    stream->data = NULL;
}

int quicly_streambuf_egress_emit(quicly_stream_t *stream, size_t off, void *dst, size_t *len, int *wrote_all)
{
    quicly_streambuf_t *sbuf = stream->data;
    return quicly_sendbuf_emit(stream, &sbuf->egress, off, dst, len, wrote_all);
}

int quicly_streambuf_egress_shutdown(quicly_stream_t *stream)
{
    quicly_streambuf_t *sbuf = stream->data;
    quicly_sendstate_shutdown(&stream->sendstate, sbuf->egress.bytes_written);
    return quicly_stream_sync_sendbuf(stream, 1);
}

int quicly_streambuf_ingress_receive(quicly_stream_t *stream, size_t off, const void *src, size_t len)
{
    quicly_streambuf_t *sbuf = stream->data;
    return quicly_recvbuf_receive(stream, &sbuf->ingress, off, src, len);
}
