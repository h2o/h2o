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
#include <cassert>
#include <cstdlib>
#include <vector>
#include <zlib.h>
#include "h2o.h"
#include "encode.h"

namespace {
    class brotli_context : public h2o_compress_context_t {
    protected:
        brotli::BrotliCompressor *brotli_;
        brotli::BrotliParams params_;
        std::vector<h2o_iovec_t> bufs_; // all bufs_[nnn].base must be free(3)ed
    public:
        brotli_context() : brotli_(NULL) {
            name = h2o_iovec_init(H2O_STRLIT("br"));
            compress = _compress;
        }
        ~brotli_context() {
            _clear_bufs();
            delete brotli_;
        }
        static void dispose(void *_self) {
            brotli_context *self = static_cast<brotli_context *>(_self);
            self->~brotli_context();
        }
    private:
        void _clear_bufs();
        void _duplicate_last_buf();
        void _compress_block(const void *src, size_t len, bool is_last, bool force_flush);
        void _compress(h2o_iovec_t *inbufs, size_t inbufcnt, int is_final, h2o_iovec_t **outbufs, size_t *outbufcnt);
        static void _compress(h2o_compress_context_t *self, h2o_iovec_t *inbufs, size_t inbufcnt, int is_final,
                              h2o_iovec_t **outbufs, size_t *outbufcnt) {
            static_cast<brotli_context*>(self)->_compress(inbufs, inbufcnt, is_final, outbufs, outbufcnt);
        }
    };
}

void brotli_context::_clear_bufs()
{
    for (std::vector<h2o_iovec_t>::iterator i = bufs_.begin(); i != bufs_.end(); ++i)
        free(i->base);
    bufs_.clear();
}

void brotli_context::_compress_block(const void *src, size_t len, bool is_last, bool force_flush)
{
    uint8_t *output;
    size_t out_size;

    brotli_->CopyInputToRingBuffer(len, static_cast<const uint8_t *>(src));
    bool ret = brotli_->WriteBrotliData(is_last, force_flush, &out_size, &output);
    assert(ret);

    if (out_size != 0)
        bufs_.push_back(h2o_strdup(NULL, reinterpret_cast<const char *>(output), out_size));
}

void brotli_context::_compress(h2o_iovec_t *inbufs, size_t inbufcnt, int is_final, h2o_iovec_t **outbufs, size_t *outbufcnt)
{
    if (brotli_ == NULL)
        brotli_ = new brotli::BrotliCompressor(params_);

    _clear_bufs();

    if (inbufcnt != 0) {
        size_t max_block_size = brotli_->input_block_size();
        for (size_t inbufindex = 0; inbufindex != inbufcnt; ++inbufindex) {
            for (size_t offset = 0; offset != inbufs[inbufindex].len;) {
                size_t block_size = std::min(inbufs[inbufindex].len - offset, max_block_size);
                bool is_last = inbufindex == inbufcnt - 1 && offset + block_size == inbufs[inbufindex].len;
                _compress_block(inbufs[inbufindex].base + offset, block_size, is_last && is_final, is_last && !is_final);
                offset += block_size;
            }
        }
    } else {
        if (is_final)
            _compress_block("", 0, true, false);
    }

    if (is_final) {
        delete brotli_;
        brotli_ = NULL;
    }

    *outbufs = &bufs_.front();
    *outbufcnt = bufs_.size();
}

h2o_compress_context_t *h2o_compress_brotli_open(h2o_mem_pool_t *pool)
{
    brotli_context *ctx = static_cast<brotli_context *>(h2o_mem_alloc_shared(pool, sizeof(*ctx), brotli_context::dispose));
    return new (ctx) brotli_context();
}
