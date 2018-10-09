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
#include "quicly/constants.h"
#include "quicly/sendbuf.h"

void quicly_sendbuf_init(quicly_sendbuf_t *buf, quicly_sendbuf_change_cb on_change)
{
    quicly_ranges_init_with_empty_range(&buf->acked);
    quicly_ranges_init(&buf->pending);
    quicly_buffer_init(&buf->data);
    buf->eos = UINT64_MAX;
    buf->error_code = QUICLY_STREAM_ERROR_IS_OPEN;
    buf->on_change = on_change;
}

void quicly_sendbuf_init_closed(quicly_sendbuf_t *buf)
{
    quicly_sendbuf_init(buf, NULL);
    buf->eos = 1;
    assert(buf->acked.num_ranges == 1);
    buf->acked.ranges[0].end = 1;
    buf->error_code = QUICLY_STREAM_ERROR_NOT_IN_USE;
}

void quicly_sendbuf_dispose(quicly_sendbuf_t *buf)
{
    quicly_buffer_dispose(&buf->data);
    quicly_ranges_dispose(&buf->acked);
    quicly_ranges_dispose(&buf->pending);
}

int quicly_sendbuf_write(quicly_sendbuf_t *buf, const void *p, size_t len, quicly_buffer_free_cb free_cb)
{
    uint64_t end_off;
    int ret;

    assert(buf->eos == UINT64_MAX);

    if ((ret = quicly_buffer_push(&buf->data, p, len, free_cb)) != 0)
        goto Exit;
    end_off = buf->acked.ranges[0].end + buf->data.len;
    if ((ret = quicly_ranges_add(&buf->pending, end_off - len, end_off)) != 0)
        goto Exit;

    buf->on_change(buf);
Exit:
    return ret;
}

int quicly_sendbuf_shutdown(quicly_sendbuf_t *buf)
{
    int ret;

    assert(buf->eos == UINT64_MAX);

    buf->eos = buf->acked.ranges[0].end + buf->data.len;
    if ((ret = quicly_ranges_add(&buf->pending, buf->eos, buf->eos + 1)) != 0)
        goto Exit;
    buf->error_code = QUICLY_STREAM_ERROR_FIN_CLOSED;

    buf->on_change(buf);
Exit:
    return ret;
}

void quicly_sendbuf_emit(quicly_sendbuf_t *buf, quicly_sendbuf_dataiter_t *iter, size_t nbytes, void *dst,
                         quicly_sendbuf_ackargs_t *ackargs)
{
    ackargs->start = iter->stream_off;

    /* emit data */
    if (nbytes != 0) {
        iter->stream_off += nbytes;
        quicly_buffer_emit(&iter->d, nbytes, dst);
    }

    /* adjust iter->stream_off to off-by-one indicating that FIN has been sent */
    if (buf->eos == iter->stream_off) {
        assert(iter->d.vec == NULL);
        ++iter->stream_off;
    }

    ackargs->end = iter->stream_off;
}

int quicly_sendbuf_acked(quicly_sendbuf_t *buf, quicly_sendbuf_ackargs_t *args, int is_active)
{
    uint64_t prev_base_off = buf->acked.ranges[0].end;
    int ret;

    if ((ret = quicly_ranges_add(&buf->acked, args->start, args->end)) != 0)
        return ret;
    if (!is_active) {
        if ((ret = quicly_ranges_subtract(&buf->pending, args->start, args->end)) != 0)
            return ret;
    }
    assert(buf->pending.num_ranges == 0 || buf->acked.ranges[0].end <= buf->pending.ranges[0].start);

    size_t delta = buf->acked.ranges[0].end - prev_base_off;
    if (delta != 0)
        quicly_buffer_shift(&buf->data, delta);

    return 0;
}

int quicly_sendbuf_lost(quicly_sendbuf_t *buf, quicly_sendbuf_ackargs_t *args)
{
    uint64_t start = args->start, end = args->end;
    size_t acked_slot = 0;
    int ret;

    while (start < end) {
        if (start < buf->acked.ranges[acked_slot].end)
            start = buf->acked.ranges[acked_slot].end;
        ++acked_slot;
        if (acked_slot == buf->acked.num_ranges || end <= buf->acked.ranges[acked_slot].start) {
            if (!(start < end))
                return 0;
            return quicly_ranges_add(&buf->pending, start, end);
        }
        if (start < buf->acked.ranges[acked_slot].start) {
            if ((ret = quicly_ranges_add(&buf->pending, start, buf->acked.ranges[acked_slot].start)) != 0)
                return ret;
        }
    }

    assert(buf->acked.ranges[0].end <= buf->pending.ranges[0].start);
    return 0;
}
