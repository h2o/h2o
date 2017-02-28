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

struct st_compress_filter_t {
    h2o_filter_t super;
    h2o_compress_args_t args;
};

struct st_compress_encoder_t {
    h2o_ostream_t super;
    h2o_compress_context_t *compressor;
};

static void do_send(h2o_ostream_t *_self, h2o_req_t *req, h2o_iovec_t *inbufs, size_t inbufcnt, h2o_send_state_t state)
{
    struct st_compress_encoder_t *self = (void *)_self;
    h2o_iovec_t *outbufs;
    size_t outbufcnt;

    self->compressor->transform(self->compressor, inbufs, inbufcnt, state, &outbufs, &outbufcnt);
    h2o_ostream_send_next(&self->super, req, outbufs, outbufcnt, state);
}

static void on_setup_ostream(h2o_filter_t *_self, h2o_req_t *req, h2o_ostream_t **slot)
{
    struct st_compress_filter_t *self = (void *)_self;
    struct st_compress_encoder_t *encoder;
    int compressible_types;
    h2o_compress_context_t *compressor;
    ssize_t i;

    if (req->version < 0x101)
        goto Next;
    if (req->res.status != 200)
        goto Next;
    if (h2o_memis(req->input.method.base, req->input.method.len, H2O_STRLIT("HEAD")))
        goto Next;

    switch (req->compress_hint) {
    case H2O_COMPRESS_HINT_DISABLE:
        /* compression was explicitely disabled, skip */
        goto Next;
    case H2O_COMPRESS_HINT_ENABLE:
        /* compression was explicitely enabled */
        break;
    case H2O_COMPRESS_HINT_AUTO:
    default:
        /* no hint from the producer, decide whether to compress based
           on the configuration */
        if (req->res.mime_attr == NULL)
            h2o_req_fill_mime_attributes(req);
        if (!req->res.mime_attr->is_compressible)
            goto Next;
        if (req->res.content_length < self->args.min_size)
            goto Next;
    }

    /* skip if failed to gather the list of compressible types */
    if ((compressible_types = h2o_get_compressible_types(&req->headers)) == 0)
        goto Next;

    /* skip if content-encoding header is being set (as well as obtain the location of accept-ranges) */
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

/* open the compressor */
#if H2O_USE_BROTLI
    if (self->args.brotli.quality != -1 && (compressible_types & H2O_COMPRESSIBLE_BROTLI) != 0) {
        compressor = h2o_compress_brotli_open(&req->pool, self->args.brotli.quality, req->res.content_length);
    } else
#endif
        if (self->args.gzip.quality != -1 && (compressible_types & H2O_COMPRESSIBLE_GZIP) != 0) {
        compressor = h2o_compress_gzip_open(&req->pool, self->args.gzip.quality);
    } else {
        /* let proxies know that we looked at accept-encoding when deciding not to compress */
        h2o_set_header_token(&req->pool, &req->res.headers, H2O_TOKEN_VARY, H2O_STRLIT("accept-encoding"));
        goto Next;
    }

    /* adjust the response headers */
    req->res.content_length = SIZE_MAX;
    h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_CONTENT_ENCODING, NULL, compressor->name.base, compressor->name.len);
    h2o_set_header_token(&req->pool, &req->res.headers, H2O_TOKEN_VARY, H2O_STRLIT("accept-encoding"));
    if (accept_ranges_header_index != -1) {
        req->res.headers.entries[accept_ranges_header_index].value = h2o_iovec_init(H2O_STRLIT("none"));
    } else {
        h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_ACCEPT_RANGES, NULL, H2O_STRLIT("none"));
    }

    /* setup filter */
    encoder = (void *)h2o_add_ostream(req, sizeof(*encoder), slot);
    encoder->super.do_send = do_send;
    slot = &encoder->super.next;
    encoder->compressor = compressor;

    /* adjust preferred chunk size (compress by 8192 bytes) */
    if (req->preferred_chunk_size > BUF_SIZE)
        req->preferred_chunk_size = BUF_SIZE;

Next:
    h2o_setup_next_ostream(req, slot);
}

void h2o_compress_register(h2o_pathconf_t *pathconf, h2o_compress_args_t *args)
{
    struct st_compress_filter_t *self = (void *)h2o_create_filter(pathconf, sizeof(*self));
    self->super.on_setup_ostream = on_setup_ostream;
    self->args = *args;
}
