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

static void on_setup_ostream(h2o_filter_t *self, h2o_req_t *req, h2o_ostream_t **slot)
{
    chunked_encoder_t *encoder;

    /* do nothing if content-length is known */
    if (req->res.content_length != SIZE_MAX)
        goto Next;
    /* RFC 2616 4.4 states that the following status codes (and response to a HEAD method) should not include message body */
    if ((100 <= req->res.status && req->res.status <= 199) || req->res.status == 204 || req->res.status == 304)
        goto Next;
    else if (h2o_memis(req->method.base, req->method.len, H2O_STRLIT("HEAD")))
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
    encoder = (void*)h2o_add_ostream(req, sizeof(chunked_encoder_t), slot);
    encoder->super.do_send = send_chunk;
    slot = &encoder->super.next;

Next:
    h2o_setup_next_ostream(self, req, slot);
}

void h2o_register_chunked_filter(h2o_host_configuration_t *host_config)
{
    h2o_filter_t *self = h2o_malloc(sizeof(*self));

    memset(self, 0, sizeof(*self));
    self->destroy = (void*)free;
    self->on_setup_ostream = on_setup_ostream;

    h2o_linklist_insert(&host_config->filters, &self->_link);
}
