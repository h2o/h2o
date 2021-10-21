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

static h2o_iovec_t get_payload(const char *_src, size_t len)
{
    const uint8_t *src = (const uint8_t *)_src, *end = src + len;
    uint64_t v;

    /* decode frame type and payload length */
    v = ptls_decode_quicint(&src, end);
    assert(v == H2O_HTTP3_FRAME_TYPE_HEADERS);
    v = ptls_decode_quicint(&src, end);
    assert(end - src == v);

    return h2o_iovec_init(src, end - src);
}

static void do_test_simple(int use_enc_stream)
{
    h2o_qpack_decoder_t *dec = h2o_qpack_create_decoder(4096, 10);
    h2o_qpack_encoder_t *enc = h2o_qpack_create_encoder(4096, 10);
    h2o_mem_pool_t pool;
    h2o_byte_vector_t *enc_stream = NULL;
    h2o_iovec_t flattened;
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
        h2o_add_header_by_str(&pool, &headers, H2O_STRLIT("dnt"), 0, NULL, H2O_STRLIT("1"));
        h2o_add_header_by_str(&pool, &headers, H2O_STRLIT("x-hoge"), 0, NULL, H2O_STRLIT("A")); /* literal, non-huff */
        h2o_iovec_t headers_frame = h2o_qpack_flatten_request(enc, &pool, 123, enc_stream, h2o_iovec_init(H2O_STRLIT("GET")),
                                                              &H2O_URL_SCHEME_HTTPS, h2o_iovec_init(H2O_STRLIT("example.com")),
                                                              h2o_iovec_init(H2O_STRLIT("/foobar")), headers.entries, headers.size);
        flattened = get_payload(headers_frame.base, headers_frame.len);
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
                                      &content_length, NULL, header_ack, &header_ack_len, (const uint8_t *)flattened.base,
                                      flattened.len, &err_desc);
        ok(ret == 0);
        ok(h2o_memis(method.base, method.len, H2O_STRLIT("GET")));
        ok(scheme == &H2O_URL_SCHEME_HTTPS);
        ok(h2o_memis(authority.base, authority.len, H2O_STRLIT("example.com")));
        ok(h2o_memis(path.base, path.len, H2O_STRLIT("/foobar")));
        ok(headers.size == 2);
        ok(h2o_memis(headers.entries[0].name->base, headers.entries[0].name->len, H2O_STRLIT("dnt")));
        ok(h2o_memis(headers.entries[0].value.base, headers.entries[0].value.len, H2O_STRLIT("1")));
        ok(h2o_memis(headers.entries[1].name->base, headers.entries[1].name->len, H2O_STRLIT("x-hoge")));
        ok(h2o_memis(headers.entries[1].value.base, headers.entries[1].value.len, H2O_STRLIT("A")));
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

static void test_simple(void)
{
    do_test_simple(0);
    do_test_simple(1);
}

static void do_test_decode_request(h2o_qpack_decoder_t *dec, int64_t stream_id, h2o_iovec_t input, int expected_ret,
                                   const char *expected_err_desc, h2o_iovec_t expected_method,
                                   const h2o_url_scheme_t *expected_scheme, h2o_iovec_t expected_authority,
                                   h2o_iovec_t expected_path, size_t expected_content_length, const h2o_header_t *expected_headers,
                                   size_t expected_num_headers, h2o_iovec_t expected_header_ack)
{
    h2o_mem_pool_t pool;
    h2o_iovec_t method = {}, authority = {}, path = {};
    const h2o_url_scheme_t *scheme = NULL;
    h2o_headers_t headers = {};
    int pseudo_header_exists_map = 0;
    size_t content_length = SIZE_MAX;
    const char *err_desc = NULL;
    uint8_t header_ack[H2O_HPACK_ENCODE_INT_MAX_LENGTH];
    size_t header_ack_len;

    h2o_mem_init_pool(&pool);

    int ret = h2o_qpack_parse_request(&pool, dec, stream_id, &method, &scheme, &authority, &path, &headers,
                                      &pseudo_header_exists_map, &content_length, NULL, header_ack, &header_ack_len,
                                      (const uint8_t *)input.base, input.len, &err_desc);

    ok(ret == expected_ret);
    ok(err_desc == expected_err_desc);
    if (ret != 0 && ret != H2O_HTTP2_ERROR_INVALID_HEADER_CHAR)
        return;

    ok(pseudo_header_exists_map == (H2O_HPACK_PARSE_HEADERS_METHOD_EXISTS | H2O_HPACK_PARSE_HEADERS_SCHEME_EXISTS |
                                    H2O_HPACK_PARSE_HEADERS_AUTHORITY_EXISTS | H2O_HPACK_PARSE_HEADERS_PATH_EXISTS));
    ok(h2o_memis(method.base, method.len, expected_method.base, expected_method.len));
    ok(scheme == expected_scheme);
    ok(h2o_memis(authority.base, authority.len, expected_authority.base, expected_authority.len));
    ok(h2o_memis(path.base, path.len, expected_path.base, expected_path.len));
    ok(content_length == expected_content_length);
    ok(headers.size == expected_num_headers);
    for (size_t i = 0; i < expected_num_headers; ++i) {
        if (i < headers.size) {
            ok(h2o_iovec_is_token(headers.entries[i].name) == h2o_iovec_is_token(expected_headers[i].name));
            ok(h2o_memis(headers.entries[i].name->base, headers.entries[i].name->len, expected_headers[i].name->base,
                         expected_headers[i].name->len));
            ok(h2o_memis(headers.entries[i].value.base, headers.entries[i].value.len, expected_headers[i].value.base,
                         expected_headers[i].value.len));
        }
    }

    ok(h2o_memis(header_ack, header_ack_len, expected_header_ack.base, expected_header_ack.len));

    h2o_mem_clear_pool(&pool);
}

static void test_decode_literal_invalid_name(void)
{
    h2o_qpack_decoder_t *dec = h2o_qpack_create_decoder(4096, 10);

    static const uint8_t input[] = {
        0,    0,                        /* required_inesrt_count=0, base=0 */
        0xd1,                           /* :method: GET */
        0xd7,                           /* :scheme: https */
        0x50, 1,   'a',                 /* :authority: a */
        0xc1,                           /* :path: / */
        0x23, 'a', '\n', 'b', 0x1, '0', /* a\nb: 0 */
    };
    static h2o_iovec_t invalid_header_name = {H2O_STRLIT("a\nb")};
    static const h2o_header_t expected_header = {.name = &invalid_header_name, .orig_name = "a\nb", .value = {H2O_STRLIT("0")}};

    do_test_decode_request(dec, 0, h2o_iovec_init(input, sizeof(input)), H2O_HTTP2_ERROR_INVALID_HEADER_CHAR,
                           h2o_hpack_soft_err_found_invalid_char_in_header_name, h2o_iovec_init(H2O_STRLIT("GET")),
                           &H2O_URL_SCHEME_HTTPS, h2o_iovec_init(H2O_STRLIT("a")), h2o_iovec_init(H2O_STRLIT("/")), SIZE_MAX,
                           &expected_header, 1, h2o_iovec_init(NULL, 0));

    h2o_qpack_destroy_decoder(dec);
}

static void test_decode_literal_invalid_value(void)
{
    h2o_qpack_decoder_t *dec = h2o_qpack_create_decoder(4096, 10);

    static const uint8_t input[] = {
        0,    0,                 /* required_inesrt_count=0, base=0 */
        0xd1,                    /* :method: GET */
        0xd7,                    /* :scheme: https */
        0x50, 3, 'a', '\n', 'b', /* :authority: a\nb */
        0xc1,                    /* :path: / */
    };
    do_test_decode_request(dec, 0, h2o_iovec_init(input, sizeof(input)), H2O_HTTP2_ERROR_INVALID_HEADER_CHAR,
                           h2o_hpack_soft_err_found_invalid_char_in_header_value, h2o_iovec_init(H2O_STRLIT("GET")),
                           &H2O_URL_SCHEME_HTTPS, h2o_iovec_init(H2O_STRLIT("a\nb")), h2o_iovec_init(H2O_STRLIT("/")), SIZE_MAX,
                           NULL, 0, h2o_iovec_init(NULL, 0));

    h2o_qpack_destroy_decoder(dec);
}

static void test_decode_referred(void)
{
    h2o_qpack_decoder_t *dec = h2o_qpack_create_decoder(4096, 10);

    static const uint8_t instructions[] = {
        0xc8, 3,   'a',  '\n', 'b',                 /* if-modified-since: a\nb (insert-with-static-nameref) */
        0x43, 'c', '\n', 'd',  3,   'e', '\n', 'f', /* c\nd: e\nf              (insert-with-literal-name) */
        0x81, 1,   '0',                             /* if-modified-since: 0    (insert-with-dynamic-nameref) */
        0x81, 1,   '1',                             /* c\nd: 1                 (insert-with-dynamic-nameref) */
    };

    { /* feed the instructions */
        int64_t *unblocked_stream_ids;
        size_t num_unblocked;
        const uint8_t *p = instructions;
        const char *err_desc;
        int ret =
            h2o_qpack_decoder_handle_input(dec, &unblocked_stream_ids, &num_unblocked, &p, p + sizeof(instructions), &err_desc);
        ok(ret == 0);
        ok(p == instructions + sizeof(instructions));
        ok(num_unblocked == 0);
    }

    note("use indexed(0)");
    {
        static const uint8_t input[] = {
            2,    0,      /* required_insert_count=1, base=1 */
            0xd1,         /* :method: GET */
            0xd7,         /* :scheme: https */
            0x50, 1, 'a', /* :authority: a */
            0xc1,         /* :path: / */
            0x80          /* dynamic entry = 0 */
        };
        static const h2o_header_t invalid_header = {.name = &H2O_TOKEN_IF_MODIFIED_SINCE->buf, .value = {H2O_STRLIT("a\nb")}};
        static const uint8_t expected_ack[] = {0x80};
        do_test_decode_request(dec, 0, h2o_iovec_init(input, sizeof(input)), H2O_HTTP2_ERROR_INVALID_HEADER_CHAR,
                               h2o_hpack_soft_err_found_invalid_char_in_header_value, h2o_iovec_init(H2O_STRLIT("GET")),
                               &H2O_URL_SCHEME_HTTPS, h2o_iovec_init(H2O_STRLIT("a")), h2o_iovec_init(H2O_STRLIT("/")), SIZE_MAX,
                               &invalid_header, 1, h2o_iovec_init(expected_ack, sizeof(expected_ack)));
    }

    note("use indexed(1)");
    {
        static const uint8_t input[] = {
            3,    0,      /* required_insert_count=2, base=2 */
            0xd1,         /* :method: GET */
            0xd7,         /* :scheme: https */
            0x50, 1, 'a', /* :authority: a */
            0xc1,         /* :path: / */
            0x80          /* dynamic entry = 1 */
        };
        static h2o_iovec_t invalid_name = {H2O_STRLIT("c\nd")};
        static const h2o_header_t invalid_header = {.name = &invalid_name, .value = {H2O_STRLIT("e\nf")}};
        static const uint8_t expected_ack[] = {0x84};
        do_test_decode_request(dec, 4, h2o_iovec_init(input, sizeof(input)), H2O_HTTP2_ERROR_INVALID_HEADER_CHAR,
                               h2o_hpack_soft_err_found_invalid_char_in_header_name, h2o_iovec_init(H2O_STRLIT("GET")),
                               &H2O_URL_SCHEME_HTTPS, h2o_iovec_init(H2O_STRLIT("a")), h2o_iovec_init(H2O_STRLIT("/")), SIZE_MAX,
                               &invalid_header, 1, h2o_iovec_init(expected_ack, sizeof(expected_ack)));
    }

    note("use indexed(2)");
    {
        static const uint8_t input[] = {
            4,    0,      /* required_insert_count=3, base=3 */
            0xd1,         /* :method: GET */
            0xd7,         /* :scheme: https */
            0x50, 1, 'a', /* :authority: a */
            0xc1,         /* :path: / */
            0x80          /* dynamic entry = 2 */
        };
        static const h2o_header_t header = {.name = &H2O_TOKEN_IF_MODIFIED_SINCE->buf, .value = {H2O_STRLIT("0")}};
        static const uint8_t expected_ack[] = {0x88};
        do_test_decode_request(dec, 8, h2o_iovec_init(input, sizeof(input)), 0, NULL, h2o_iovec_init(H2O_STRLIT("GET")),
                               &H2O_URL_SCHEME_HTTPS, h2o_iovec_init(H2O_STRLIT("a")), h2o_iovec_init(H2O_STRLIT("/")), SIZE_MAX,
                               &header, 1, h2o_iovec_init(expected_ack, sizeof(expected_ack)));
    }

    note("use indexed(3)");
    {
        static const uint8_t input[] = {
            5,    0,      /* required_insert_count=4, base=4 */
            0xd1,         /* :method: GET */
            0xd7,         /* :scheme: https */
            0x50, 1, 'a', /* :authority: a */
            0xc1,         /* :path: / */
            0x80          /* dynamic entry = 3 */
        };
        static h2o_iovec_t invalid_name = {H2O_STRLIT("c\nd")};
        static const h2o_header_t invalid_header = {.name = &invalid_name, .value = {H2O_STRLIT("1")}};
        static const uint8_t expected_ack[] = {0x8c};
        do_test_decode_request(dec, 12, h2o_iovec_init(input, sizeof(input)), H2O_HTTP2_ERROR_INVALID_HEADER_CHAR,
                               h2o_hpack_soft_err_found_invalid_char_in_header_name, h2o_iovec_init(H2O_STRLIT("GET")),
                               &H2O_URL_SCHEME_HTTPS, h2o_iovec_init(H2O_STRLIT("a")), h2o_iovec_init(H2O_STRLIT("/")), SIZE_MAX,
                               &invalid_header, 1, h2o_iovec_init(expected_ack, sizeof(expected_ack)));
    }

    note("use name-ref(0)");
    {
        static const uint8_t input[] = {
            2,    0,      /* required_insert_count=1, base=1 */
            0xd1,         /* :method: GET */
            0xd7,         /* :scheme: https */
            0x50, 1, 'a', /* :authority: a */
            0xc1,         /* :path: / */
            0x40, 1, '1', /* if-modified-since: 1 (dynamic entry = 0) */
        };
        static const h2o_header_t header = {.name = &H2O_TOKEN_IF_MODIFIED_SINCE->buf, .value = {H2O_STRLIT("1")}};
        static const uint8_t expected_ack[] = {0x90};
        do_test_decode_request(dec, 16, h2o_iovec_init(input, sizeof(input)), 0, NULL, h2o_iovec_init(H2O_STRLIT("GET")),
                               &H2O_URL_SCHEME_HTTPS, h2o_iovec_init(H2O_STRLIT("a")), h2o_iovec_init(H2O_STRLIT("/")), SIZE_MAX,
                               &header, 1, h2o_iovec_init(expected_ack, sizeof(expected_ack)));
    }

    note("use name-ref(1)");
    {
        static const uint8_t input[] = {
            3,    0,      /* required_insert_count=2, base=2 */
            0xd1,         /* :method: GET */
            0xd7,         /* :scheme: https */
            0x50, 1, 'a', /* :authority: a */
            0xc1,         /* :path: / */
            0x40, 1, '1', /* c\nd: 1 (dynamic entry = 1) */
        };
        static h2o_iovec_t invalid_name = {H2O_STRLIT("c\nd")};
        static const h2o_header_t header = {.name = &invalid_name, .value = {H2O_STRLIT("1")}};
        static const uint8_t expected_ack[] = {0x94};
        do_test_decode_request(dec, 20, h2o_iovec_init(input, sizeof(input)), H2O_HTTP2_ERROR_INVALID_HEADER_CHAR,
                               h2o_hpack_soft_err_found_invalid_char_in_header_name, h2o_iovec_init(H2O_STRLIT("GET")),
                               &H2O_URL_SCHEME_HTTPS, h2o_iovec_init(H2O_STRLIT("a")), h2o_iovec_init(H2O_STRLIT("/")), SIZE_MAX,
                               &header, 1, h2o_iovec_init(expected_ack, sizeof(expected_ack)));
    }

    note("use post-base indexed(0)");
    {
        static const uint8_t input[] = {
            2,    0x80,      /* required_insert_count=1, base=0 */
            0xd1,            /* :method: GET */
            0xd7,            /* :scheme: https */
            0x50, 1,    'a', /* :authority: a */
            0xc1,            /* :path: / */
            0x10             /* dynamic entry = 0 */
        };
        static const h2o_header_t invalid_header = {.name = &H2O_TOKEN_IF_MODIFIED_SINCE->buf, .value = {H2O_STRLIT("a\nb")}};
        static const uint8_t expected_ack[] = {0x98};
        do_test_decode_request(dec, 24, h2o_iovec_init(input, sizeof(input)), H2O_HTTP2_ERROR_INVALID_HEADER_CHAR,
                               h2o_hpack_soft_err_found_invalid_char_in_header_value, h2o_iovec_init(H2O_STRLIT("GET")),
                               &H2O_URL_SCHEME_HTTPS, h2o_iovec_init(H2O_STRLIT("a")), h2o_iovec_init(H2O_STRLIT("/")), SIZE_MAX,
                               &invalid_header, 1, h2o_iovec_init(expected_ack, sizeof(expected_ack)));
    }

    note("use post-base name-ref(1)");
    {
        static const uint8_t input[] = {
            3,    0x80,      /* required_insert_count=2, base=1 */
            0xd1,            /* :method: GET */
            0xd7,            /* :scheme: https */
            0x50, 1,    'a', /* :authority: a */
            0xc1,            /* :path: / */
            0,    1,    '1', /* c\nd: 1 (dynamic entry = 1) */
        };
        static h2o_iovec_t invalid_name = {H2O_STRLIT("c\nd")};
        static const h2o_header_t header = {.name = &invalid_name, .value = {H2O_STRLIT("1")}};
        static const uint8_t expected_ack[] = {0x9c};
        do_test_decode_request(dec, 28, h2o_iovec_init(input, sizeof(input)), H2O_HTTP2_ERROR_INVALID_HEADER_CHAR,
                               h2o_hpack_soft_err_found_invalid_char_in_header_name, h2o_iovec_init(H2O_STRLIT("GET")),
                               &H2O_URL_SCHEME_HTTPS, h2o_iovec_init(H2O_STRLIT("a")), h2o_iovec_init(H2O_STRLIT("/")), SIZE_MAX,
                               &header, 1, h2o_iovec_init(expected_ack, sizeof(expected_ack)));
    }

    h2o_qpack_destroy_decoder(dec);
}

void test_lib__http3_qpack(void)
{
    subtest("simple", test_simple);
    subtest("decode-literal-invalid-name", test_decode_literal_invalid_name);
    subtest("decode-literal-invalid-value", test_decode_literal_invalid_value);
    subtest("decode-referred", test_decode_referred);
}
