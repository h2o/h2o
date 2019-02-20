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

static void shift_bytes(ptls_buffer_t *buf, size_t delta)
{
    assert(delta <= buf->off);
    buf->off -= delta;
    memmove(buf->base, buf->base + delta, buf->off);
}

int quicly_streambuf_create(quicly_stream_t *stream, size_t sz)
{
    quicly_streambuf_t *sbuf;

    assert(sz >= sizeof(*sbuf));
    assert(stream->data == NULL);

    if ((sbuf = malloc(sz)) == NULL)
        return PTLS_ERROR_NO_MEMORY;
    ptls_buffer_init(&sbuf->egress.buf, "", 0);
    sbuf->egress.max_stream_data = 0;
    ptls_buffer_init(&sbuf->ingress, "", 0);
    if (sz != sizeof(*sbuf))
        memset((char *)sbuf + sizeof(*sbuf), 0, sz - sizeof(*sbuf));

    stream->data = sbuf;
    return 0;
}

void quicly_streambuf_destroy(quicly_stream_t *stream, int err)
{
    quicly_streambuf_t *sbuf = stream->data;

    ptls_buffer_dispose(&sbuf->egress.buf);
    ptls_buffer_dispose(&sbuf->ingress);
    free(sbuf);
    stream->data = NULL;
}

void quicly_streambuf_egress_shift(quicly_stream_t *stream, size_t delta)
{
    quicly_streambuf_t *sbuf = stream->data;
    shift_bytes(&sbuf->egress.buf, delta);
    quicly_stream_sync_sendbuf(stream, 0);
}

int quicly_streambuf_egress_emit(quicly_stream_t *stream, size_t off, void *dst, size_t *len, int *wrote_all)
{
    quicly_streambuf_t *sbuf = stream->data;

    assert(off < sbuf->egress.buf.off);

    if (off + *len < sbuf->egress.buf.off) {
        *wrote_all = 0;
    } else {
        *len = sbuf->egress.buf.off - off;
        *wrote_all = 1;
    }
    memcpy(dst, sbuf->egress.buf.base + off, *len);

    return 0;
}

int quicly_streambuf_egress_write(quicly_stream_t *stream, const void *src, size_t len)
{
    quicly_streambuf_t *sbuf = stream->data;
    int ret;

    assert(stream->sendstate.is_open);

    ptls_buffer_pushv(&sbuf->egress.buf, src, len);
    sbuf->egress.max_stream_data += len;
    if ((ret = quicly_stream_sync_sendbuf(stream, 1)) != 0)
        goto Exit;
    ret = 0;

Exit:
    return ret;
}

int quicly_streambuf_egress_shutdown(quicly_stream_t *stream)
{
    quicly_streambuf_t *sbuf = stream->data;
    quicly_sendstate_shutdown(&stream->sendstate, sbuf->egress.max_stream_data);
    return quicly_stream_sync_sendbuf(stream, 1);
}

void quicly_streambuf_ingress_shift(quicly_stream_t *stream, size_t delta)
{
    quicly_streambuf_t *sbuf = stream->data;

    shift_bytes(&sbuf->ingress, delta);
    quicly_stream_sync_recvbuf(stream, delta);
}

ptls_iovec_t quicly_streambuf_ingress_get(quicly_stream_t *stream)
{
    quicly_streambuf_t *sbuf = (quicly_streambuf_t *)stream->data;
    size_t avail;

    if (quicly_recvstate_transfer_complete(&stream->recvstate)) {
        avail = sbuf->ingress.off;
    } else if (stream->recvstate.data_off < stream->recvstate.received.ranges[0].end) {
        avail = stream->recvstate.received.ranges[0].end - stream->recvstate.data_off;
    } else {
        avail = 0;
    }

    return ptls_iovec_init(sbuf->ingress.base, avail);
}

int quicly_streambuf_ingress_receive(quicly_stream_t *stream, size_t off, const void *src, size_t len)
{
    quicly_streambuf_t *sbuf = stream->data;

    if (len != 0) {
        int ret;
        if ((ret = ptls_buffer_reserve(&sbuf->ingress, off + len - sbuf->ingress.off)) != 0)
            return ret;
        memcpy(sbuf->ingress.base + off, src, len);
        if (sbuf->ingress.off < off + len)
            sbuf->ingress.off = off + len;
    }
    return 0;
}
