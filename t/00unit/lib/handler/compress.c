/*
 * Copyright (c) 2015 DeNA Co., Ltd., Kazuho Oku
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
#include <stdlib.h>
#include <zlib.h>
#include "../../test.h"
#define BUF_SIZE 256
#include "../../../../lib/handler/compress/gzip.c"
#include "../../../../lib/handler/compress.c"

static void check_result(h2o_iovec_t *vecs, size_t num_vecs, const char *expected, size_t expectedlen)
{
    z_stream zs;
    char decbuf[expectedlen + 1];

    memset(&zs, 0, sizeof(zs));
    zs.zalloc = alloc_cb;
    zs.zfree = free_cb;
    zs.next_out = (void *)decbuf;
    zs.avail_out = (unsigned)sizeof(decbuf);

    inflateInit2(&zs, WINDOW_BITS);

    int inflate_ret = -1;
    size_t i;
    for (i = 0; i != num_vecs; ++i) {
        zs.next_in = (void *)vecs[i].base;
        zs.avail_in = (unsigned)vecs[i].len;
        inflate_ret = inflate(&zs, Z_NO_FLUSH);
        if (zs.avail_out == 0) {
            ok(0);
            return;
        }
        if (zs.avail_in != 0) {
            ok(0);
            return;
        }
    }

    ok(inflate_ret == Z_STREAM_END);
    inflateEnd(&zs);

    ok(zs.avail_out == sizeof(decbuf) - expectedlen);
    ok(memcmp(decbuf, expected, expectedlen) == 0);
}

void test_gzip_simple(void)
{
    h2o_mem_pool_t pool;
    h2o_iovec_t inbuf, *outbufs;
    size_t outbufcnt;

    h2o_mem_init_pool(&pool);

    h2o_compress_context_t *compressor = h2o_compress_gzip_open(&pool, Z_BEST_SPEED);
    inbuf = h2o_iovec_init(H2O_STRLIT("hello world"));
    compressor->compress(compressor, &inbuf, 1, 1, &outbufs, &outbufcnt);

    check_result(outbufs, outbufcnt, H2O_STRLIT("hello world"));

    h2o_mem_clear_pool(&pool);
}

void test_gzip_multi(void)
{
#define P1                                                                                                                         \
    "Alice was beginning to get very tired of sitting by her sister on the bank, and of having nothing to do: once or twice she "  \
    "had peeped into the book her sister was reading, but it had no pictures or conversations in it, `and what is the use of a "   \
    "book,' thought Alice `without pictures or conversation?'\n\n"
#define P2                                                                                                                         \
    "So she was considering in her own mind (as well as she could, for the hot day made her feel very sleepy and stupid), "        \
    "whether the pleasure of making a daisy-chain would be worth the trouble of getting up and picking the daisies, when "         \
    "suddenly a White Rabbit with pink eyes ran close by her.\n\n"
#define P3                                                                                                                         \
    "There was nothing so very remarkable in that; nor did Alice think it so very much out of the way to hear the Rabbit say to "  \
    "itself, `Oh dear! Oh dear! I shall be late!' (when she thought it over afterwards, it occurred to her that she ought to "     \
    "have wondered at this, but at the time it all seemed quite natural); but when the Rabbit actually took a watch out of its "   \
    "waistcoat-pocket, and looked at it, and then hurried on, Alice started to her feet, for it flashed across her mind that she " \
    "had never before seen a rabbit with either a waistcoat-pocket, or a watch to take out of it, and burning with curiosity, "    \
    "she ran across the field after it, and fortunately was just in time to see it pop down a large rabbit-hole under the "        \
    "hedge.\n\n"

    h2o_mem_pool_t pool;
    h2o_iovec_t inbufs[] = {{H2O_STRLIT(P1)}, {H2O_STRLIT(P2)}, {H2O_STRLIT(P3)}}, *outbufs;
    size_t outbufcnt;

    h2o_mem_init_pool(&pool);

    h2o_compress_context_t *compressor = h2o_compress_gzip_open(&pool, Z_BEST_SPEED);
    compressor->compress(compressor, inbufs, sizeof(inbufs) / sizeof(inbufs[0]), 1, &outbufs, &outbufcnt);

    assert(outbufcnt > 1); /* we want to test multi-vec output */

    check_result(outbufs, outbufcnt, H2O_STRLIT(P1 P2 P3));

    h2o_mem_clear_pool(&pool);

#undef P1
#undef P2
#undef P3
}

void test_lib__handler__gzip_c()
{
    subtest("gzip_simple", test_gzip_simple);
    subtest("gzip_multi", test_gzip_multi);
}
