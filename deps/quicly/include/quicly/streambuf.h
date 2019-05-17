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
#ifndef quicly_streambuf_h
#define quicly_streambuf_h

#ifdef __cplusplus
extern "C" {
#endif

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "picotls.h"
#include "quicly.h"

typedef struct st_quicly_sendbuf_vec_t quicly_sendbuf_vec_t;

/**
 * Callback that flattens the contents of an iovec.
 * @param dst the destination
 * @param off offset within the iovec from where serialization should happen
 * @param len number of bytes to serialize
 * @return 0 if successful, otherwise an error code
 */
typedef int (*quicly_sendbuf_flatten_vec_cb)(quicly_sendbuf_vec_t *vec, void *dst, size_t off, size_t len);
/**
 * An optional callback that is called when an iovec is discarded.
 */
typedef void (*quicly_sendbuf_discard_vec_cb)(quicly_sendbuf_vec_t *vec);

typedef struct st_quicly_streambuf_sendvec_callbacks_t {
    quicly_sendbuf_flatten_vec_cb flatten_vec;
    quicly_sendbuf_discard_vec_cb discard_vec;
} quicly_streambuf_sendvec_callbacks_t;

struct st_quicly_sendbuf_vec_t {
    const quicly_streambuf_sendvec_callbacks_t *cb;
    size_t len;
    void *cbdata;
};

/**
 * A simple stream-level send buffer that can be used to store data to be sent.
 */
typedef struct st_quicly_sendbuf_t {
    struct {
        quicly_sendbuf_vec_t *entries;
        size_t size, capacity;
    } vecs;
    size_t off_in_first_vec;
    uint64_t bytes_written;
} quicly_sendbuf_t;

/**
 * Inilializes the send buffer.
 */
static void quicly_sendbuf_init(quicly_sendbuf_t *sb);
/**
 * Disposes of the send buffer.
 */
void quicly_sendbuf_dispose(quicly_sendbuf_t *sb);
/**
 * The concrete function to be used when `quicly_stream_callbacks_t::on_send_shift` is being invoked (i.e., applications using
 * `quicly_sendbuf_t` as the stream-level send buffer should call this function from it's `on_send_shift` callback).
 */
void quicly_sendbuf_shift(quicly_stream_t *stream, quicly_sendbuf_t *sb, size_t delta);
/**
 * The concrete function for `quicly_stream_callbacks_t::on_send_emit`.
 */
int quicly_sendbuf_emit(quicly_stream_t *stream, quicly_sendbuf_t *sb, size_t off, void *dst, size_t *len, int *wrote_all);
/**
 * Appends some bytes to the send buffer.  The data being appended is copied.
 */
int quicly_sendbuf_write(quicly_stream_t *stream, quicly_sendbuf_t *sb, const void *src, size_t len);
/**
 * Appends a vector to the send buffer.  Members of the `quicly_sendbuf_vec_t` are copied.
 */
int quicly_sendbuf_write_vec(quicly_stream_t *stream, quicly_sendbuf_t *sb, quicly_sendbuf_vec_t *vec);

/**
 * Pops the specified amount of bytes at the beginning of the simple stream-level receive buffer (which in fact is `ptls_buffer_t`).
 */
void quicly_recvbuf_shift(quicly_stream_t *stream, ptls_buffer_t *rb, size_t delta);
/**
 * Returns an iovec that refers to the data available in the receive buffer.  Applications are expected to call `quicly_recvbuf_get`
 * to first peek at the received data, process the bytes they can, then call `quicly_recvbuf_shift` to pop the bytes that have been
 * processed.
 */
ptls_iovec_t quicly_recvbuf_get(quicly_stream_t *stream, ptls_buffer_t *rb);
/**
 * The concrete function for `quicly_stream_callbacks_t::on_receive`.
 */
int quicly_recvbuf_receive(quicly_stream_t *stream, ptls_buffer_t *rb, size_t off, const void *src, size_t len);

/**
 * The simple stream buffer.  The API assumes that stream->data points to quicly_streambuf_t.  Applications can extend the structure
 * by passing arbitrary size to `quicly_streambuf_create`.
 */
typedef struct st_quicly_streambuf_t {
    quicly_sendbuf_t egress;
    ptls_buffer_t ingress;
} quicly_streambuf_t;

int quicly_streambuf_create(quicly_stream_t *stream, size_t sz);
void quicly_streambuf_destroy(quicly_stream_t *stream, int err);
static void quicly_streambuf_egress_shift(quicly_stream_t *stream, size_t delta);
int quicly_streambuf_egress_emit(quicly_stream_t *stream, size_t off, void *dst, size_t *len, int *wrote_all);
static int quicly_streambuf_egress_write(quicly_stream_t *stream, const void *src, size_t len);
static int quicly_streambuf_egress_write_vec(quicly_stream_t *stream, quicly_sendbuf_vec_t *vec);
int quicly_streambuf_egress_shutdown(quicly_stream_t *stream);
static void quicly_streambuf_ingress_shift(quicly_stream_t *stream, size_t delta);
static ptls_iovec_t quicly_streambuf_ingress_get(quicly_stream_t *stream);
int quicly_streambuf_ingress_receive(quicly_stream_t *stream, size_t off, const void *src, size_t len);

/* inline definitions */

inline void quicly_sendbuf_init(quicly_sendbuf_t *sb)
{
    memset(sb, 0, sizeof(*sb));
}

inline void quicly_streambuf_egress_shift(quicly_stream_t *stream, size_t delta)
{
    quicly_streambuf_t *sbuf = stream->data;
    quicly_sendbuf_shift(stream, &sbuf->egress, delta);
}

inline int quicly_streambuf_egress_write(quicly_stream_t *stream, const void *src, size_t len)
{
    quicly_streambuf_t *sbuf = stream->data;
    return quicly_sendbuf_write(stream, &sbuf->egress, src, len);
}

inline int quicly_streambuf_egress_write_vec(quicly_stream_t *stream, quicly_sendbuf_vec_t *vec)
{
    quicly_streambuf_t *sbuf = stream->data;
    return quicly_sendbuf_write_vec(stream, &sbuf->egress, vec);
}

inline void quicly_streambuf_ingress_shift(quicly_stream_t *stream, size_t delta)
{
    quicly_streambuf_t *sbuf = stream->data;
    quicly_recvbuf_shift(stream, &sbuf->ingress, delta);
}

inline ptls_iovec_t quicly_streambuf_ingress_get(quicly_stream_t *stream)
{
    quicly_streambuf_t *sbuf = (quicly_streambuf_t *)stream->data;
    return quicly_recvbuf_get(stream, &sbuf->ingress);
}

#ifdef __cplusplus
}
#endif

#endif
