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
#ifndef quicly_sendbuf_h
#define quicly_sendbuf_h

#include "quicly/buffer.h"
#include "quicly/ranges.h"

typedef struct st_quicly_sendbuf_t quicly_sendbuf_t;
typedef void (*quicly_sendbuf_change_cb)(quicly_sendbuf_t *buf);

struct st_quicly_sendbuf_t {
    /**
     * ranges that have been acked (guaranteed to be non-empty; i.e., acked.ranges[0].end == contiguous_acked_offset)
     */
    quicly_ranges_t acked;
    /**
     * ranges that needs to be sent
     */
    quicly_ranges_t pending;
    /**
     * buffered data (starting from acked.ranges[0].end)
     */
    quicly_buffer_t data;
    /**
     * end_of_stream offset (or UINT64_MAX)
     */
    uint64_t eos;
    /**
     * the reason peer requested stop (or ERROR_FIN_CLOSED)
     */
    uint16_t stop_reason;
    /**
     * callback
     */
    quicly_sendbuf_change_cb on_change;
};

typedef struct st_quicly_sendbuf_ackargs_t {
    uint64_t start;
    uint64_t end;
} quicly_sendbuf_ackargs_t;

typedef struct st_quicly_sendbuf_dataiter_t {
    quicly_buffer_iter_t d;
    uint64_t stream_off;
} quicly_sendbuf_dataiter_t;

void quicly_sendbuf_init(quicly_sendbuf_t *buf, quicly_sendbuf_change_cb on_change);
void quicly_sendbuf_dispose(quicly_sendbuf_t *buf);
static int quicly_sendbuf_transfer_complete(quicly_sendbuf_t *buf);
int quicly_sendbuf_write(quicly_sendbuf_t *buf, const void *p, size_t len, quicly_buffer_free_cb free_cb);
int quicly_sendbuf_shutdown(quicly_sendbuf_t *buf);
void quicly_sendbuf_emit(quicly_sendbuf_t *buf, quicly_sendbuf_dataiter_t *iter, size_t nbytes, void *dst,
                         quicly_sendbuf_ackargs_t *ackargs);
int quicly_sendbuf_acked(quicly_sendbuf_t *buf, quicly_sendbuf_ackargs_t *args, int is_active);
int quicly_sendbuf_lost(quicly_sendbuf_t *buf, quicly_sendbuf_ackargs_t *args);
static void quicly_sendbuf_init_dataiter(quicly_sendbuf_t *buf, quicly_sendbuf_dataiter_t *iter);
static void quicly_sendbuf_advance_dataiter(quicly_sendbuf_dataiter_t *iter, size_t nbytes);

/* inline definitions */

inline int quicly_sendbuf_transfer_complete(quicly_sendbuf_t *buf)
{
    /* end of the range is non-inclusive, hence one after the eos */
    return buf->acked.ranges[0].end > buf->eos;
}

inline void quicly_sendbuf_init_dataiter(quicly_sendbuf_t *buf, quicly_sendbuf_dataiter_t *iter)
{
    iter->stream_off = buf->acked.ranges[0].end;
    quicly_buffer_init_iter(&buf->data, &iter->d);
}

inline void quicly_sendbuf_advance_dataiter(quicly_sendbuf_dataiter_t *iter, size_t nbytes)
{
    iter->stream_off += nbytes;
    quicly_buffer_advance_iter(&iter->d, nbytes);
}

#endif
