/*
 * Copyright (c) 2016 DeNA Co., Ltd., Kazuho Oku
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

#define WINDOW_BITS 31
#ifndef BUF_SIZE /* is altered by unit test */
#define BUF_SIZE 8192
#endif

typedef H2O_VECTOR(h2o_iovec_t) iovec_vector_t;

struct st_gzip_context_t {
    h2o_compress_context_t super;
    z_stream zs;
    int zs_is_open;
    iovec_vector_t bufs;
};

static void *alloc_cb(void *_unused, unsigned int cnt, unsigned int sz)
{
    return h2o_mem_alloc(cnt * (size_t)sz);
}

static void free_cb(void *_unused, void *p)
{
    free(p);
}

static void expand_buf(iovec_vector_t *bufs)
{
    h2o_vector_reserve(NULL, bufs, bufs->size + 1);
    bufs->entries[bufs->size++] = h2o_iovec_init(h2o_mem_alloc(BUF_SIZE), 0);
}

static size_t compress_chunk(struct st_gzip_context_t *self, const void *src, size_t len, int flush, size_t bufindex)
{
    int ret;

    self->zs.next_in = (void *)src;
    self->zs.avail_in = (unsigned)len;

    /* man says: If deflate returns with avail_out == 0, this function must be called again with the same value of the flush
     * parameter and more output space (updated avail_out), until the flush is complete (deflate returns with non-zero avail_out).
     */
    do {
        /* expand buffer (note: in case of Z_SYNC_FLUSH we need to supply at least 6 bytes of output buffer) */
        if (self->bufs.entries[bufindex].len + 32 > BUF_SIZE) {
            ++bufindex;
            if (bufindex == self->bufs.size)
                expand_buf(&self->bufs);
            self->bufs.entries[bufindex].len = 0;
        }
        self->zs.next_out = (void *)(self->bufs.entries[bufindex].base + self->bufs.entries[bufindex].len);
        self->zs.avail_out = (unsigned)(BUF_SIZE - self->bufs.entries[bufindex].len);
        ret = deflate(&self->zs, flush);
        assert(ret == Z_OK || ret == Z_STREAM_END);
        self->bufs.entries[bufindex].len = BUF_SIZE - self->zs.avail_out;
    } while (self->zs.avail_out == 0 && ret != Z_STREAM_END);

    return bufindex;
}

static void do_compress(h2o_compress_context_t *_self, h2o_iovec_t *inbufs, size_t inbufcnt, h2o_send_state_t state,
                        h2o_iovec_t **outbufs, size_t *outbufcnt)
{
    struct st_gzip_context_t *self = (void *)_self;
    size_t outbufindex;
    h2o_iovec_t last_buf;

    outbufindex = 0;
    self->bufs.entries[0].len = 0;

    if (inbufcnt != 0) {
        size_t i;
        for (i = 0; i != inbufcnt - 1; ++i)
            outbufindex = compress_chunk(self, inbufs[i].base, inbufs[i].len, Z_NO_FLUSH, outbufindex);
        last_buf = inbufs[i];
    } else {
        last_buf = h2o_iovec_init(NULL, 0);
    }
    outbufindex = compress_chunk(self, last_buf.base, last_buf.len, h2o_send_state_is_in_progress(state) ? Z_SYNC_FLUSH : Z_FINISH,
                                 outbufindex);

    *outbufs = self->bufs.entries;
    *outbufcnt = outbufindex + 1;

    if (!h2o_send_state_is_in_progress(state)) {
        deflateEnd(&self->zs);
        self->zs_is_open = 0;
    }
}

static void do_free(void *_self)
{
    struct st_gzip_context_t *self = _self;
    size_t i;

    if (self->zs_is_open)
        deflateEnd(&self->zs);

    for (i = 0; i != self->bufs.size; ++i)
        free(self->bufs.entries[i].base);
    free(self->bufs.entries);
}

h2o_compress_context_t *h2o_compress_gzip_open(h2o_mem_pool_t *pool, int quality)
{
    struct st_gzip_context_t *self = h2o_mem_alloc_shared(pool, sizeof(*self), do_free);

    self->super.name = h2o_iovec_init(H2O_STRLIT("gzip"));
    self->super.compress = do_compress;
    self->zs.zalloc = alloc_cb;
    self->zs.zfree = free_cb;
    self->zs.opaque = NULL;
    /* Z_BEST_SPEED for on-the-fly compression, memlevel set to 8 as suggested by the manual */
    deflateInit2(&self->zs, quality, Z_DEFLATED, WINDOW_BITS, 8, Z_DEFAULT_STRATEGY);
    self->zs_is_open = 1;
    self->bufs = (iovec_vector_t){NULL};
    expand_buf(&self->bufs);

    return &self->super;
}
