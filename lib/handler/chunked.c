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
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include "h2o.h"

typedef struct st_chunked_encoder_t {
    h2o_ostream_t super;
    char buf[64];
} chunked_encoder_t;

static void send_chunk(h2o_ostream_t *_self, h2o_req_t *req, h2o_iovec_t *inbufs, size_t inbufcnt, h2o_send_state_t state)
{
    chunked_encoder_t *self = (void *)_self;
    h2o_iovec_t *outbufs = alloca(sizeof(h2o_iovec_t) * (inbufcnt + 2));
    size_t chunk_size, outbufcnt = 0, i;

    /* calc chunk size */
    chunk_size = 0;
    for (i = 0; i != inbufcnt; ++i)
        chunk_size += inbufs[i].len;

    /* create chunk header and output data */
    if (chunk_size != 0) {
        outbufs[outbufcnt].base = self->buf;
        outbufs[outbufcnt].len = sprintf(self->buf, "%zx\r\n", chunk_size);
        assert(outbufs[outbufcnt].len < sizeof(self->buf));
        outbufcnt++;
        memcpy(outbufs + outbufcnt, inbufs, sizeof(h2o_iovec_t) * inbufcnt);
        outbufcnt += inbufcnt;
        if (state != H2O_SEND_STATE_ERROR) {
            outbufs[outbufcnt].base = "\r\n0\r\n\r\n";
            outbufs[outbufcnt].len = state == H2O_SEND_STATE_FINAL ? 7 : 2;
            outbufcnt++;
        }
    } else if (state == H2O_SEND_STATE_FINAL) {
        outbufs[outbufcnt].base = "0\r\n\r\n";
        outbufs[outbufcnt].len = 5;
        outbufcnt++;
    }

    /* if state is error, send a broken chunk to pass the error down to the browser */
    if (state == H2O_SEND_STATE_ERROR) {
        outbufs[outbufcnt].base = "\r\n1\r\n";
        outbufs[outbufcnt].len = 5;
        outbufcnt++;
    }

    h2o_ostream_send_next(&self->super, req, outbufs, outbufcnt, state);
}

static void on_setup_ostream(h2o_filter_t *self, h2o_req_t *req, h2o_ostream_t **slot)
{
    chunked_encoder_t *encoder;

    /* do nothing if not HTTP/1.1 or content-length is known */
    if (req->res.content_length != SIZE_MAX || req->version != 0x101)
        goto Next;
    /* RFC 2616 4.4 states that the following status codes (and response to a HEAD method) should not include message body */
    if ((100 <= req->res.status && req->res.status <= 199) || req->res.status == 204 || req->res.status == 304)
        goto Next;
    else if (h2o_memis(req->input.method.base, req->input.method.len, H2O_STRLIT("HEAD")))
        goto Next;
    /* we cannot handle certain responses (like 101 switching protocols) */
    if (req->res.status != 200) {
        req->http1_is_persistent = 0;
        goto Next;
    }
    /* skip if content-encoding header is being set */
    if (h2o_find_header(&req->res.headers, H2O_TOKEN_TRANSFER_ENCODING, -1) != -1)
        goto Next;

    /* set content-encoding header */
    h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_TRANSFER_ENCODING, H2O_STRLIT("chunked"));

    /* setup filter */
    encoder = (void *)h2o_add_ostream(req, sizeof(chunked_encoder_t), slot);
    encoder->super.do_send = send_chunk;
    slot = &encoder->super.next;

Next:
    h2o_setup_next_ostream(req, slot);
}

void h2o_chunked_register(h2o_pathconf_t *pathconf)
{
    h2o_filter_t *self = h2o_create_filter(pathconf, sizeof(*self));
    self->on_setup_ostream = on_setup_ostream;
}
