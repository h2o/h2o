/*
 * Copyright (c) 2015 Justin Zhu, DeNA Co., Ltd., Kazuho Oku
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
#include <zlib.h>
#include "h2o.h"

#ifndef BUF_SIZE
#define BUF_SIZE 8192
#endif
#define WINDOW_BITS 31

typedef H2O_VECTOR(h2o_iovec_t) iovec_vector_t;

typedef struct st_gzip_encoder_t {
    h2o_ostream_t super;
    z_stream zstream;
    iovec_vector_t bufs;
} gzip_encoder_t;

static void *gzip_encoder_alloc(void *opaque, unsigned int items, unsigned int size)
{
    return h2o_mem_alloc(items * size);
}

static void gzip_encoder_free(void *opaque, void *address)
{
    free(address);
}

static void expand_buf(h2o_mem_pool_t *pool, iovec_vector_t *bufs)
{
    h2o_vector_reserve(pool, (void *)bufs, sizeof(bufs->entries[0]), bufs->size + 1);
    bufs->entries[bufs->size++] = h2o_iovec_init(h2o_mem_alloc_pool(pool, BUF_SIZE), 0);
}

static size_t compress_chunk(h2o_mem_pool_t *pool, z_stream *zs, const void *src, size_t len, int flush, iovec_vector_t *bufs,
                             size_t bufindex)
{
    int ret;

    zs->next_in = (void *)src;
    zs->avail_in = (unsigned)len;

    /* man says: If deflate returns with avail_out == 0, this function must be called again with the same value of the flush
     * parameter and more output space (updated avail_out), until the flush is complete (deflate returns with non-zero avail_out).
     */
    do {
        /* expand buffer (note: in case of Z_SYNC_FLUSH we need to supply at least 6 bytes of output buffer) */
        if (bufs->entries[bufindex].len + 32 > BUF_SIZE) {
            ++bufindex;
            if (bufindex == bufs->size)
                expand_buf(pool, bufs);
            bufs->entries[bufindex].len = 0;
        }
        zs->next_out = (void *)bufs->entries[bufindex].base + bufs->entries[bufindex].len;
        zs->avail_out = (unsigned)(BUF_SIZE - bufs->entries[bufindex].len);
        ret = deflate(zs, flush);
        assert(ret == Z_OK || ret == Z_STREAM_END);
        bufs->entries[bufindex].len = BUF_SIZE - zs->avail_out;
    } while (zs->avail_out == 0 && ret != Z_STREAM_END);

    return bufindex;
}

static void send_gzip(h2o_ostream_t *_self, h2o_req_t *req, h2o_iovec_t *inbufs, size_t inbufcnt, int is_final)
{
    gzip_encoder_t *self = (void *)_self;
    size_t outbufindex;

    /* initialize deflate (Z_BEST_SPEED for on-the-fly compression, memlevel set to 8 as suggested by the manual) */
    if (self->bufs.size == 0) {
        deflateInit2(&self->zstream, Z_BEST_SPEED, Z_DEFLATED, WINDOW_BITS, 8, Z_DEFAULT_STRATEGY);
        expand_buf(&req->pool, &self->bufs);
    }

    /* compress */
    outbufindex = 0;
    self->bufs.entries[0].len = 0;
    if (inbufcnt != 0) {
        size_t i;
        for (i = 0; i != inbufcnt - 1; ++i)
            if (inbufs[i].len != 0)
                outbufindex =
                    compress_chunk(&req->pool, &self->zstream, inbufs[i].base, inbufs[i].len, Z_NO_FLUSH, &self->bufs, outbufindex);
        outbufindex = compress_chunk(&req->pool, &self->zstream, inbufs[i].base, inbufs[i].len, is_final ? Z_FINISH : Z_SYNC_FLUSH,
                                     &self->bufs, outbufindex);
    } else {
        outbufindex = compress_chunk(&req->pool, &self->zstream, "", 0, Z_FINISH, &self->bufs, outbufindex);
    }

    /* destroy deflate */
    if (is_final)
        deflateEnd(&self->zstream);

    h2o_ostream_send_next(&self->super, req, self->bufs.entries, outbufindex + 1, is_final);
}

static void stop_gzip(h2o_ostream_t *_self, h2o_req_t *req)
{
    gzip_encoder_t *self = (void *)_self;

    if (self->bufs.size != 0)
        deflateEnd(&self->zstream);
}

static void on_setup_ostream(h2o_filter_t *self, h2o_req_t *req, h2o_ostream_t **slot)
{
    gzip_encoder_t *encoder;
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
    encoder = (void *)h2o_add_ostream(req, sizeof(gzip_encoder_t), slot);
    encoder->super.do_send = send_gzip;
    encoder->super.stop = stop_gzip;
    slot = &encoder->super.next;

    encoder->bufs.capacity = 0;
    encoder->bufs.size = 0;
    encoder->zstream.zalloc = gzip_encoder_alloc;
    encoder->zstream.zfree = gzip_encoder_free;
    encoder->zstream.opaque = encoder;

    /* adjust preferred chunk size (compress by 8192 bytes) */
    if (req->preferred_chunk_size > BUF_SIZE)
        req->preferred_chunk_size = BUF_SIZE;

Next:
    h2o_setup_next_ostream(self, req, slot);
}

void h2o_gzip_register(h2o_pathconf_t *pathconf)
{
    h2o_filter_t *self = h2o_create_filter(pathconf, sizeof(*self));
    self->on_setup_ostream = on_setup_ostream;
}
