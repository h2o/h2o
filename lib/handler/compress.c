/*
 * Copyright (c) 2015,2016 Justin Zhu, DeNA Co., Ltd., Kazuho Oku
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
#include "h2o.h"

#ifndef BUF_SIZE
#define BUF_SIZE 8192
#endif

typedef struct st_compress_encoder_t {
    h2o_ostream_t super;
    h2o_compress_context_t *compressor;
} compress_encoder_t;

static void do_send(h2o_ostream_t *_self, h2o_req_t *req, h2o_iovec_t *inbufs, size_t inbufcnt, int is_final)
{
    compress_encoder_t *self = (void *)_self;
    h2o_iovec_t *outbufs;
    size_t outbufcnt;

    /* initialize compressor */
    if (self->compressor == NULL)
        self->compressor = h2o_compress_gzip_open(&req->pool);

    /* compress */
    self->compressor->compress(self->compressor, inbufs, inbufcnt, is_final, &outbufs, &outbufcnt);

    /* send next */
    h2o_ostream_send_next(&self->super, req, outbufs, outbufcnt, is_final);
}

static void on_setup_ostream(h2o_filter_t *self, h2o_req_t *req, h2o_ostream_t **slot)
{
    compress_encoder_t *encoder;
    ssize_t i;

    if (req->version < 0x101)
        goto Next;
    if (req->res.status != 200)
        goto Next;
    if (h2o_memis(req->input.method.base, req->input.method.len, H2O_STRLIT("HEAD")))
        goto Next;
    if (req->res.mime_attr == NULL)
        h2o_req_fill_mime_attributes(req);
    if (!req->res.mime_attr->is_compressible)
        goto Next;
    /* 100 is a rough estimate */
    if (req->res.content_length <= 100)
        goto Next;
    /* skip if no accept-encoding is set */
    if ((i = h2o_find_header(&req->headers, H2O_TOKEN_ACCEPT_ENCODING, -1)) == -1)
        goto Next;
    if (!h2o_contains_token(req->headers.entries[i].value.base, req->headers.entries[i].value.len, H2O_STRLIT("gzip"), ','))
        goto Next;

    /* skip if content-encoding header is being set (as well as obtain the location of accept-ranges */
    size_t content_encoding_header_index = -1, accept_ranges_header_index = -1;
    for (i = 0; i != req->res.headers.size; ++i) {
        if (req->res.headers.entries[i].name == &H2O_TOKEN_CONTENT_ENCODING->buf)
            content_encoding_header_index = i;
        else if (req->res.headers.entries[i].name == &H2O_TOKEN_ACCEPT_RANGES->buf)
            accept_ranges_header_index = i;
        else
            continue;
    }
    if (content_encoding_header_index != -1)
        goto Next;

    /* adjust the response headers */
    req->res.content_length = SIZE_MAX;
    h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_CONTENT_ENCODING, H2O_STRLIT("gzip"));
    h2o_add_header_token(&req->pool, &req->res.headers, H2O_TOKEN_VARY, H2O_STRLIT("accept-encoding"));
    if (accept_ranges_header_index != -1) {
        req->res.headers.entries[accept_ranges_header_index].value = h2o_iovec_init(H2O_STRLIT("none"));
    } else {
        h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_ACCEPT_RANGES, H2O_STRLIT("none"));
    }

    /* setup filter */
    encoder = (void *)h2o_add_ostream(req, sizeof(*encoder), slot);
    encoder->super.do_send = do_send;
    slot = &encoder->super.next;

    encoder->compressor = NULL;

    /* adjust preferred chunk size (compress by 8192 bytes) */
    if (req->preferred_chunk_size > BUF_SIZE)
        req->preferred_chunk_size = BUF_SIZE;

Next:
    h2o_setup_next_ostream(req, slot);
}

void h2o_compress_register(h2o_pathconf_t *pathconf)
{
    h2o_filter_t *self = h2o_create_filter(pathconf, sizeof(*self));
    self->on_setup_ostream = on_setup_ostream;
}
