/*
 * Copyright (c) 2025 Casey Link, Outskirts Labs e.U.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to do so, subject to the
 * following conditions:
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
#include <stdint.h>
#include <stdbool.h>
#include <zstd.h>
#include "h2o.h"

#ifndef BUF_SIZE /* allows unit tests to override */
#define BUF_SIZE 8192
#endif

struct st_zstd_context_t {
    h2o_compress_context_t super;
    ZSTD_CStream *cstream;
    H2O_VECTOR(h2o_sendvec_t) bufs;
    size_t buf_capacity;
};

static void expand_buf(struct st_zstd_context_t *self)
{
    h2o_vector_reserve(NULL, &self->bufs, self->bufs.size + 1);
    h2o_sendvec_init_raw(self->bufs.entries + self->bufs.size++, h2o_mem_alloc(self->buf_capacity), 0);
}

static void shrink_buf(struct st_zstd_context_t *self, size_t new_size)
{
    while (self->bufs.size > new_size)
        free(self->bufs.entries[--self->bufs.size].raw);
}

static void ensure_space(struct st_zstd_context_t *self)
{
    if (self->bufs.size == 0)
        expand_buf(self);
    size_t active = self->bufs.size - 1;
    if (self->bufs.entries[active].len == self->buf_capacity) {
        expand_buf(self);
        self->bufs.entries[self->bufs.size - 1].len = 0;
    }
}

static int compress_chunk(struct st_zstd_context_t *self, const void *src, size_t len, ZSTD_EndDirective directive)
{
    static const uint8_t dummy = 0;
    ZSTD_inBuffer input = {.src = src != NULL ? src : &dummy, .size = len, .pos = 0};
    size_t remaining = 0;

    bool need_more_output;
    do {
        ensure_space(self);
        size_t active = self->bufs.size - 1;
        ZSTD_outBuffer output = {
            .dst = self->bufs.entries[active].raw + self->bufs.entries[active].len,
            .size = self->buf_capacity - self->bufs.entries[active].len,
            .pos = 0,
        };

        remaining = ZSTD_compressStream2(self->cstream, &output, &input, directive);
        if (ZSTD_isError(remaining)) {
            h2o_error_printf("zstd: compressStream2 failed: %s\n", ZSTD_getErrorName(remaining));
            return -1;
        }

        self->bufs.entries[active].len += output.pos;

        if (output.pos == output.size && self->bufs.entries[active].len == self->buf_capacity) {
            expand_buf(self);
            self->bufs.entries[self->bufs.size - 1].len = 0;
        }
        need_more_output = output.pos == output.size;
    } while (input.pos < input.size || (directive != ZSTD_e_continue && remaining != 0) || need_more_output);

    return 0;
}

static h2o_send_state_t do_compress(h2o_compress_context_t *_self, h2o_sendvec_t *inbufs, size_t inbufcnt, h2o_send_state_t state,
                                    h2o_sendvec_t **outbufs, size_t *outbufcnt)
{
    struct st_zstd_context_t *self = (void *)_self;
    ZSTD_EndDirective final_directive = h2o_send_state_is_in_progress(state) ? ZSTD_e_flush : ZSTD_e_end;

    shrink_buf(self, 1);
    self->bufs.entries[0].len = 0;

    if (inbufcnt != 0) {
        for (size_t i = 0; i < inbufcnt; ++i) {
            assert(inbufs[i].callbacks->read_ == h2o_sendvec_read_raw);
            ZSTD_EndDirective directive = (i + 1 == inbufcnt) ? final_directive : ZSTD_e_continue;
            if (compress_chunk(self, inbufs[i].raw, inbufs[i].len, directive) != 0) {
                *outbufs = NULL;
                *outbufcnt = 0;
                return H2O_SEND_STATE_ERROR;
            }
        }
    } else {
        if (compress_chunk(self, NULL, 0, final_directive) != 0) {
            *outbufs = NULL;
            *outbufcnt = 0;
            return H2O_SEND_STATE_ERROR;
        }
    }

    *outbufs = self->bufs.entries;
    size_t outcnt = self->bufs.size;
    if (outcnt != 0 && self->bufs.entries[outcnt - 1].len == 0)
        --outcnt;
    *outbufcnt = outcnt;

    return state;
}

static void on_dispose(void *_self)
{
    struct st_zstd_context_t *self = _self;

    if (self->cstream != NULL)
        ZSTD_freeCStream(self->cstream);
    shrink_buf(self, 0);
    free(self->bufs.entries);
    free(self->super.push_buf);
}

h2o_compress_context_t *h2o_compress_zstd_open(h2o_mem_pool_t *pool, int quality, size_t estimated_content_length,
                                               size_t preferred_chunk_size)
{
    struct st_zstd_context_t *self = h2o_mem_alloc_shared(pool, sizeof(*self), on_dispose);

    self->super.name = h2o_iovec_init(H2O_STRLIT("zstd"));
    self->super.do_transform = do_compress;
    self->super.push_buf = NULL;
    self->cstream = ZSTD_createCStream();
    if (self->cstream == NULL)
        h2o_fatal("ZSTD_createCStream failed");

    if (estimated_content_length != SIZE_MAX) {
        size_t set_ret = ZSTD_CCtx_setPledgedSrcSize(self->cstream, estimated_content_length);
        if (ZSTD_isError(set_ret))
            h2o_error_printf("zstd: failed to set pledged size: %s\n", ZSTD_getErrorName(set_ret));
    }

    size_t ret = ZSTD_initCStream(self->cstream, quality);
    if (ZSTD_isError(ret))
        h2o_fatal("ZSTD_initCStream: %s", ZSTD_getErrorName(ret));

    self->buf_capacity = preferred_chunk_size;
    if (estimated_content_length != SIZE_MAX && self->buf_capacity > estimated_content_length)
        self->buf_capacity = estimated_content_length;
    if (self->buf_capacity > 65536)
        self->buf_capacity = 65536;
    if (self->buf_capacity < 1024)
        self->buf_capacity = 1024;

    memset(&self->bufs, 0, sizeof(self->bufs));
    expand_buf(self);

    return &self->super;
}
