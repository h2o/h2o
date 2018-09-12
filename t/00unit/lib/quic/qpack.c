/*
 * Copyright (c) 2018 Fastly, Kazuho Oku
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
#include "quicly/recvbuf.h"
#include "../../test.h"
#include "../../../../lib/quic/qpack.c"

static void buffer_transmit(quicly_recvbuf_t *recvbuf, quicly_sendbuf_t *sendbuf)
{
    quicly_sendbuf_dataiter_t iter;
    uint8_t *buf;
    uint64_t off;
    size_t len;
    quicly_sendbuf_ackargs_t ackargs;

    assert(sendbuf->pending.num_ranges == 1);

    off = sendbuf->pending.ranges[0].start;
    len = sendbuf->pending.ranges[0].end - off;
    buf = h2o_mem_alloc(len);

    /* extract data from sendbuf */
    quicly_sendbuf_init_dataiter(sendbuf, &iter);
    quicly_sendbuf_emit(sendbuf, &iter, len, buf, &ackargs);
    quicly_sendbuf_acked(sendbuf, &ackargs, 0);

    /* write */
    quicly_recvbuf_write(recvbuf, off, buf, len);

    free(buf);
}

static void dummy_recvbuf_on_change(quicly_recvbuf_t *buf, size_t shift_amount)
{
}

static quicly_recvbuf_t enc_recvbuf;

static void on_enc_send(quicly_sendbuf_t *sendbuf)
{
    buffer_transmit(&enc_recvbuf, sendbuf);
}

static void on_dec_send(quicly_sendbuf_t *sendbuf)
{
    assert(!"FIXME");
}

void test_lib__quic_qpack(void)
{
    h2o_qpack_context_t ctx = {4096};
    h2o_qpack_decoder_t *dec = h2o_qpack_create_decoder(&ctx);
    h2o_qpack_encoder_t *enc = NULL;
    quicly_sendbuf_t enc_sendbuf, dec_sendbuf;
    int ret;

    quicly_recvbuf_init(&enc_recvbuf, dummy_recvbuf_on_change);
    quicly_sendbuf_init(&enc_sendbuf, on_enc_send);
    quicly_sendbuf_init(&dec_sendbuf, on_dec_send);

    {
        h2o_mem_pool_t pool;
        h2o_headers_t headers = {NULL};
        h2o_mem_init_pool(&pool);
        h2o_add_header(&pool, &headers, H2O_TOKEN_METHOD, NULL, H2O_STRLIT("GET"));
        h2o_add_header(&pool, &headers, H2O_TOKEN_SCHEME, NULL, H2O_STRLIT("https"));
        h2o_add_header(&pool, &headers, H2O_TOKEN_AUTHORITY, NULL, H2O_STRLIT("example.com"));
        h2o_add_header(&pool, &headers, H2O_TOKEN_PATH, NULL, H2O_STRLIT("/foobar"));
        h2o_add_header_by_str(&pool, &headers, H2O_STRLIT("x-hoge"), 0, NULL, H2O_STRLIT("\x01\x02\x03")); /* literal, non-huff */
        ret = h2o_qpack_flatten_headers(enc, &enc_sendbuf, headers.entries, headers.size);
        ok(ret == 0);
        h2o_mem_clear_pool(&pool);
    }

    {
        h2o_mem_pool_t pool;
        ptls_iovec_t input = quicly_recvbuf_get(&enc_recvbuf);
        h2o_iovec_t method = {NULL}, authority = {NULL}, path = {NULL};
        const h2o_url_scheme_t *scheme = NULL;
        int pseudo_header_exists_map = 0;
        h2o_headers_t headers = {NULL};
        size_t content_length = SIZE_MAX;
        const char *err_desc = NULL;
        h2o_mem_init_pool(&pool);
        ret = h2o_qpack_parse_request(&pool, dec, 0, &method, &scheme, &authority, &path, &headers, &pseudo_header_exists_map,
                                      &content_length, NULL, &dec_sendbuf, input.base, input.len, &err_desc);
        ok(ret == 0);
        ok(h2o_memis(method.base, method.len, H2O_STRLIT("GET")));
        ok(scheme == &H2O_URL_SCHEME_HTTPS);
        ok(h2o_memis(authority.base, authority.len, H2O_STRLIT("example.com")));
        ok(h2o_memis(path.base, path.len, H2O_STRLIT("/foobar")));
        ok(headers.size == 1);
        ok(h2o_memis(headers.entries[0].name->base, headers.entries[0].name->len, H2O_STRLIT("x-hoge")));
        ok(h2o_memis(headers.entries[0].value.base, headers.entries[0].value.len, H2O_STRLIT("\x01\x02\x03")));
        h2o_mem_clear_pool(&pool);
    }

    ok(dec_sendbuf.pending.num_ranges == 0);
}
