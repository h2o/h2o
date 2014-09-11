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
#include <alloca.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include "h2o.h"

typedef struct st_chunked_encoder_t {
    h2o_ostream_t super;
    char buf[64];
} chunked_encoder_t;

static void send_chunk(h2o_ostream_t *_self, h2o_req_t *req, h2o_buf_t *inbufs, size_t inbufcnt, int is_final)
{
    chunked_encoder_t *self = (void*)_self;
    h2o_buf_t *outbufs = alloca(sizeof(h2o_buf_t) * (inbufcnt + 2));
    size_t chunk_size, outbufcnt = 0, i;

    /* calc chunk size */
    chunk_size = 0;
    for (i = 0; i != inbufcnt; ++i)
        chunk_size += inbufs[i].len;

    /* create chunk header */
    if (chunk_size != 0) {
        outbufs[outbufcnt].base = self->buf;
        outbufs[outbufcnt].len = h2o_snprintf(self->buf, sizeof(self->buf), "%zx\r\n", chunk_size);
        outbufcnt++;
    }
    /* set output data */
    memcpy(outbufs + outbufcnt, inbufs, sizeof(h2o_buf_t) * inbufcnt);
    outbufcnt += inbufcnt;
    /* set EOF chunk header if is_final */
    if (is_final) {
        outbufs[outbufcnt].base = "\r\n0\r\n\r\n";
        outbufs[outbufcnt].len = 7;
        outbufcnt++;
    } else {
        outbufs[outbufcnt].base = "\r\n";
        outbufs[outbufcnt].len = 2;
    }

    h2o_ostream_send_next(&self->super, req, outbufs, outbufcnt, is_final);
}

static void on_start_response(h2o_filter_t *self, h2o_req_t *req)
{
    chunked_encoder_t *encoder;

    /* do nothing if content-length is known */
    if (req->res.content_length != SIZE_MAX)
        goto Next;
    /* we cannot handle certain responses (like 101 switching protocols) */
    if (req->res.status != 200)
        goto Next;
    /* skip if content-encoding header is being set */
    if (h2o_find_header(&req->res.headers, H2O_TOKEN_TRANSFER_ENCODING, -1) != -1)
        goto Next;

    /* set content-encoding header */
    h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_TRANSFER_ENCODING, H2O_STRLIT("chunked"));

    /* setup filter */
    encoder = (void*)h2o_prepend_output_filter(req, sizeof(chunked_encoder_t));
    encoder->super.do_send = send_chunk;

Next:
    if (self->next != NULL)
        self->next->on_start_response(self->next, req);
}

void h2o_prepend_chunked_encoder(h2o_context_t *context)
{
    h2o_prepend_filter(context, sizeof(h2o_filter_t), on_start_response);
}
