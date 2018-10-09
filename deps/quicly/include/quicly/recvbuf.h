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
#ifndef quicly_recvbuf_h
#define quicly_recvbuf_h

#include <assert.h>
#include <stddef.h>
#include "picotls.h"
#include "quicly/buffer.h"
#include "quicly/ranges.h"

typedef struct st_quicly_recvbuf_t quicly_recvbuf_t;
typedef void (*quicly_recvbuf_change_cb)(quicly_recvbuf_t *buf, size_t shift_amount);

struct st_quicly_recvbuf_t {
    /**
     * ranges that have been received (guaranteed to be non-empty; first element always start from zero)
     */
    quicly_ranges_t received;
    /**
     * buffered data
     */
    quicly_buffer_t data;
    /**
     * starting offset of data
     */
    uint64_t data_off;
    /**
     * end_of_stream offset (or UINT64_MAX)
     */
    uint64_t eos;
    /**
     * error code of RST_STREAM frame that closed the stream (or IS_OPEN, FIN_CLOSED, STOPPED)
     */
    quicly_stream_error_t _error_code;
    /**
     * callback
     */
    quicly_recvbuf_change_cb on_change;
};

void quicly_recvbuf_init(quicly_recvbuf_t *buf, quicly_recvbuf_change_cb on_change);
void quicly_recvbuf_init_closed(quicly_recvbuf_t *buf);
void quicly_recvbuf_dispose(quicly_recvbuf_t *buf);
static quicly_stream_error_t quicly_recvbuf_get_error(quicly_recvbuf_t *buf);
static int quicly_recvbuf_transfer_complete(quicly_recvbuf_t *buf);
static size_t quicly_recvbuf_available(quicly_recvbuf_t *buf);
static ptls_iovec_t quicly_recvbuf_get(quicly_recvbuf_t *buf);
static void quicly_recvbuf_shift(quicly_recvbuf_t *buf, size_t delta);
int quicly_recvbuf_mark_eos(quicly_recvbuf_t *buf, uint64_t eos_at);
int quicly_recvbuf_reset(quicly_recvbuf_t *buf, uint16_t error_code, uint64_t eos_at, uint64_t *bytes_missing);
int quicly_recvbuf_write(quicly_recvbuf_t *buf, uint64_t offset, const void *p, size_t len);

/* inline definitions */

inline quicly_stream_error_t quicly_recvbuf_get_error(quicly_recvbuf_t *buf)
{
    if (buf->data_off != buf->eos)
        return QUICLY_STREAM_ERROR_IS_OPEN;
    return buf->_error_code;
}

inline int quicly_recvbuf_transfer_complete(quicly_recvbuf_t *buf)
{
    return buf->received.ranges[0].end == buf->eos;
}

inline size_t quicly_recvbuf_available(quicly_recvbuf_t *buf)
{
    return buf->received.ranges[0].end - buf->data_off;
}

inline ptls_iovec_t quicly_recvbuf_get(quicly_recvbuf_t *buf)
{
    size_t avail = quicly_recvbuf_available(buf);
    if (avail == 0)
        return ptls_iovec_init(NULL, 0);
    ptls_iovec_t ret = ptls_iovec_init(buf->data.first->p + buf->data.skip, buf->data.first->len - buf->data.skip);
    if (ret.len > avail)
        ret.len = avail;
    return ret;
}

inline void quicly_recvbuf_shift(quicly_recvbuf_t *buf, size_t delta)
{
    if (delta == 0)
        return;

    buf->data_off += delta;
    quicly_buffer_shift(&buf->data, delta);
    (*buf->on_change)(buf, delta);
}

#endif
