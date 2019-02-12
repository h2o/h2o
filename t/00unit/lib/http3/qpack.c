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
#include <stdlib.h>
#include "../../test.h"
#include "../../../../lib/http3/qpack.c"

static void doit(int use_enc_stream)
{
    h2o_qpack_decoder_t *dec = h2o_qpack_create_decoder(4096, 10);
    h2o_qpack_encoder_t *enc = h2o_qpack_create_encoder(4096, 10);
    h2o_mem_pool_t pool;
    h2o_byte_vector_t *enc_stream = NULL, flattened = {NULL};
    uint8_t header_ack[H2O_HPACK_ENCODE_INT_MAX_LENGTH];
    size_t header_ack_len;
    const char *err_desc = NULL;
    int ret;

    h2o_mem_init_pool(&pool);

    if (use_enc_stream) {
        enc_stream = alloca(sizeof(*enc_stream));
        memset(enc_stream, 0, sizeof(*enc_stream));
    }

    {
        h2o_headers_t headers = {NULL};
        h2o_add_header_by_str(&pool, &headers, H2O_STRLIT("x-hoge"), 0, NULL, H2O_STRLIT("\x01\x02\x03")); /* literal, non-huff */
        h2o_qpack_flatten_request(enc, &pool, 123, enc_stream, &flattened, h2o_iovec_init(H2O_STRLIT("GET")), &H2O_URL_SCHEME_HTTPS,
                                  h2o_iovec_init(H2O_STRLIT("example.com")), h2o_iovec_init(H2O_STRLIT("/foobar")), headers.entries,
                                  headers.size);
    }

    if (enc_stream != NULL) {
        int64_t *unblocked_stream_ids;
        size_t num_unblocked;
        assert(enc_stream->size != 0);
        const uint8_t *p = enc_stream->entries;
        ret = h2o_qpack_decoder_handle_input(dec, &unblocked_stream_ids, &num_unblocked, &p, p + enc_stream->size, &err_desc);
        assert(ret == 0);
        assert(p == enc_stream->entries + enc_stream->size);
    }

    {
        h2o_iovec_t method = {NULL}, authority = {NULL}, path = {NULL};
        const h2o_url_scheme_t *scheme = NULL;
        int pseudo_header_exists_map = 0;
        h2o_headers_t headers = {NULL};
        size_t content_length = SIZE_MAX;
        ret = h2o_qpack_parse_request(&pool, dec, 0, &method, &scheme, &authority, &path, &headers, &pseudo_header_exists_map,
                                      &content_length, NULL, header_ack, &header_ack_len, flattened.entries, flattened.size,
                                      &err_desc);
        ok(ret == 0);
        ok(h2o_memis(method.base, method.len, H2O_STRLIT("GET")));
        ok(scheme == &H2O_URL_SCHEME_HTTPS);
        ok(h2o_memis(authority.base, authority.len, H2O_STRLIT("example.com")));
        ok(h2o_memis(path.base, path.len, H2O_STRLIT("/foobar")));
        ok(headers.size == 1);
        ok(h2o_memis(headers.entries[0].name->base, headers.entries[0].name->len, H2O_STRLIT("x-hoge")));
        ok(h2o_memis(headers.entries[0].value.base, headers.entries[0].value.len, H2O_STRLIT("\x01\x02\x03")));
    }

    if (enc_stream != NULL) {
        ok(header_ack_len != 0);
    } else {
        ok(header_ack_len == 0);
    }

    h2o_mem_clear_pool(&pool);
    h2o_qpack_destroy_decoder(dec);
    h2o_qpack_destroy_encoder(enc);
}

void test_lib__quic_qpack(void)
{
    doit(0);
    doit(1);
}
