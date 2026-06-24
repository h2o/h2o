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
        h2o_qpack_section_stats_t unused = {1, 2};
        h2o_iovec_t headers_frame =
            h2o_qpack_flatten_request(enc, &pool, 123, enc_stream, h2o_iovec_init(H2O_STRLIT("GET")), &H2O_URL_SCHEME_HTTPS,
                                      h2o_iovec_init(H2O_STRLIT("example.com")), h2o_iovec_init(H2O_STRLIT("/foobar")),
                                      h2o_iovec_init(NULL, 0), headers.entries, headers.size, h2o_iovec_init(NULL, 0), &unused);
        ok(unused.count == 7);
        ok(unused.text_bytes == 68);
        flattened = get_payload(headers_frame.base, headers_frame.len);
    }

    if (enc_stream != NULL) {
        uint64_t insert_count;
        assert(enc_stream->size != 0);
        const uint8_t *p = enc_stream->entries;
        ret = h2o_qpack_decoder_handle_input(dec, &insert_count, &p, p + enc_stream->size, &err_desc);
        assert(ret == 0);
        assert(p == enc_stream->entries + enc_stream->size);
    }

    {
        h2o_iovec_t method = {NULL}, authority = {NULL}, path = {NULL}, protocol = {NULL};
        const h2o_url_scheme_t *scheme = NULL;
        int pseudo_header_exists_map = 0;
        h2o_headers_t headers = {NULL};
        size_t content_length = SIZE_MAX;
        h2o_iovec_t expect = {NULL};
        uint64_t blocked_ref;
        h2o_qpack_section_stats_t recv_stats = {3, 4};
        ret = h2o_qpack_parse_request(&pool, dec, 0, &method, &scheme, &authority, &path, &protocol, &headers,
                                      &pseudo_header_exists_map, &content_length, &expect, NULL, NULL, 0, &blocked_ref, &recv_stats,
                                      header_ack, &header_ack_len, (const uint8_t *)flattened.base, flattened.len, &err_desc);
        ok(ret == 0);
        ok(recv_stats.count == 9);
        ok(recv_stats.text_bytes == 70);
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
    h2o_iovec_t method = {}, authority = {}, path = {}, protocol = {};
    const h2o_url_scheme_t *scheme = NULL;
    h2o_headers_t headers = {};
    int pseudo_header_exists_map = 0;
    size_t content_length = SIZE_MAX;
    h2o_iovec_t expect = {};
    const char *err_desc = NULL;
    uint8_t header_ack[H2O_HPACK_ENCODE_INT_MAX_LENGTH];
    size_t header_ack_len;

    h2o_mem_init_pool(&pool);

    uint64_t blocked_ref;
    h2o_qpack_section_stats_t recv_stats = {0};
    int ret = h2o_qpack_parse_request(&pool, dec, stream_id, &method, &scheme, &authority, &path, &protocol, &headers,
                                      &pseudo_header_exists_map, &content_length, &expect, NULL, NULL, 0, &blocked_ref, &recv_stats,
                                      header_ack, &header_ack_len, (const uint8_t *)input.base, input.len, &err_desc);

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

    {
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
    }
    {
        static const uint8_t input[] = {
            0,    0,                /* required_inesrt_count=0, base=0 */
            0xd1,                   /* :method: GET */
            0xd7,                   /* :scheme: https */
            0x50, 3, ' ', 'a', 'b', /* :authority: SP ab */
            0xc1,                   /* :path: / */
        };
        do_test_decode_request(dec, 0, h2o_iovec_init(input, sizeof(input)), H2O_HTTP2_ERROR_INVALID_HEADER_CHAR,
                               h2o_hpack_soft_err_found_invalid_char_in_header_value, h2o_iovec_init(H2O_STRLIT("GET")),
                               &H2O_URL_SCHEME_HTTPS, h2o_iovec_init(H2O_STRLIT(" ab")), h2o_iovec_init(H2O_STRLIT("/")), SIZE_MAX,
                               NULL, 0, h2o_iovec_init(NULL, 0));
    }
    {
        static const uint8_t input[] = {
            0,    0,                      /* required_inesrt_count=0, base=0 */
            0xd1,                         /* :method: GET */
            0xd7,                         /* :scheme: https */
            0x50, 0x83, 0x50, 0x71, 0xff, /* :authority: SP ab (in huffman)*/
            0xc1,                         /* :path: / */
        };
        do_test_decode_request(dec, 0, h2o_iovec_init(input, sizeof(input)), H2O_HTTP2_ERROR_INVALID_HEADER_CHAR,
                               h2o_hpack_soft_err_found_invalid_char_in_header_value, h2o_iovec_init(H2O_STRLIT("GET")),
                               &H2O_URL_SCHEME_HTTPS, h2o_iovec_init(H2O_STRLIT(" ab")), h2o_iovec_init(H2O_STRLIT("/")), SIZE_MAX,
                               NULL, 0, h2o_iovec_init(NULL, 0));
    }

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
        uint64_t insert_count;
        const uint8_t *p = instructions;
        const char *err_desc;
        int ret = h2o_qpack_decoder_handle_input(dec, &insert_count, &p, p + sizeof(instructions), &err_desc);
        ok(ret == 0);
        ok(p == instructions + sizeof(instructions));
        ok(insert_count == 4);
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

    note("dynamic reference beyond required insert count");
    {
        static const uint8_t input[] = {
            2,    1,      /* required_insert_count=1, base=2 */
            0xd1,         /* :method: GET */
            0xd7,         /* :scheme: https */
            0x50, 1, 'a', /* :authority: a */
            0xc1,         /* :path: / */
            0x80          /* dynamic entry = 1 */
        };
        static const uint8_t expected_ack[] = {};
        do_test_decode_request(dec, 16, h2o_iovec_init(input, sizeof(input)), H2O_HTTP3_ERROR_QPACK_DECOMPRESSION_FAILED,
                               h2o_qpack_err_invalid_dynamic_reference, h2o_iovec_init(NULL, 0), NULL, h2o_iovec_init(NULL, 0),
                               h2o_iovec_init(NULL, 0), SIZE_MAX, NULL, 0, h2o_iovec_init(expected_ack, sizeof(expected_ack)));
    }

    note("post-base dynamic reference beyond required insert count");
    {
        static const uint8_t input[] = {
            2,    0x80,      /* required_insert_count=1, base=0 */
            0xd1,            /* :method: GET */
            0xd7,            /* :scheme: https */
            0x50, 1,    'a', /* :authority: a */
            0xc1,            /* :path: / */
            0x11             /* dynamic entry = 1 */
        };
        static const uint8_t expected_ack[] = {};
        do_test_decode_request(dec, 16, h2o_iovec_init(input, sizeof(input)), H2O_HTTP3_ERROR_QPACK_DECOMPRESSION_FAILED,
                               h2o_qpack_err_invalid_dynamic_reference, h2o_iovec_init(NULL, 0), NULL, h2o_iovec_init(NULL, 0),
                               h2o_iovec_init(NULL, 0), SIZE_MAX, NULL, 0, h2o_iovec_init(expected_ack, sizeof(expected_ack)));
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

static void feed_encoder_stream(h2o_qpack_decoder_t *dec, const uint8_t *input, size_t len)
{
    uint64_t insert_count;
    const uint8_t *p = input;
    const char *err_desc = NULL;
    int ret = h2o_qpack_decoder_handle_input(dec, &insert_count, &p, p + len, &err_desc);

    ok(ret == 0);
    ok(err_desc == NULL);
    ok(p == input + len);
}

static void do_test_decode_field_section(h2o_qpack_decoder_t *dec, int64_t stream_id, h2o_iovec_t input,
                                         const h2o_header_t *expected_headers, size_t expected_num_headers,
                                         h2o_iovec_t expected_header_ack)
{
    h2o_mem_pool_t pool;
    struct st_h2o_qpack_decode_header_ctx_t ctx;
    const uint8_t *src = (const uint8_t *)input.base, *src_end = src + input.len;
    h2o_qpack_section_stats_t stats = {0};
    const char *err_desc = NULL;
    uint8_t header_ack[H2O_HPACK_ENCODE_INT_MAX_LENGTH];

    h2o_mem_init_pool(&pool);

    ok(parse_decode_context(dec, &ctx, &src, src_end) == 0);
    ctx.stats = &stats;
    for (size_t i = 0; i < expected_num_headers; ++i) {
        h2o_iovec_t *name = NULL, value = {};
        ok(decode_header(&pool, &ctx, &name, &value, &src, src_end, &err_desc) == 0);
        ok(err_desc == NULL);
        ok(h2o_iovec_is_token(name) == h2o_iovec_is_token(expected_headers[i].name));
        ok(h2o_memis(name->base, name->len, expected_headers[i].name->base, expected_headers[i].name->len));
        ok(h2o_memis(value.base, value.len, expected_headers[i].value.base, expected_headers[i].value.len));
    }
    ok(src == src_end);

    size_t header_ack_len = send_header_ack(dec, &ctx, header_ack, stream_id);
    ok(h2o_memis(header_ack, header_ack_len, expected_header_ack.base, expected_header_ack.len));

    h2o_mem_clear_pool(&pool);
}

static void test_rfc9204_appendix_b(void)
{
    h2o_qpack_decoder_t *dec = h2o_qpack_create_decoder(220, 10);

    note("B.1. Literal Field Line with Name Reference");
    {
        static const uint8_t input[] = {
            0x00, 0x00,                                                       /* Required Insert Count = 0, Base = 0 */
            0x51, 0x0b, '/', 'i', 'n', 'd', 'e', 'x', '.', 'h', 't', 'm', 'l' /* :path=/index.html */
        };
        static const h2o_header_t expected[] = {
            {.name = &H2O_TOKEN_PATH->buf, .value = {H2O_STRLIT("/index.html")}},
        };
        do_test_decode_field_section(dec, 0, h2o_iovec_init(input, sizeof(input)), expected, PTLS_ELEMENTSOF(expected),
                                     h2o_iovec_init(NULL, 0));
    }

    note("B.2. Dynamic Table");
    {
        static const uint8_t encoder[] = {
            0x3f, 0xbd, 0x01, /* Set Dynamic Table Capacity=220 */
            0xc0, 0x0f, 'w',  'w', 'w', '.', 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm', /* :authority=www.example.com */
            0xc1, 0x0c, '/',  's', 'a', 'm', 'p', 'l', 'e', '/', 'p', 'a', 't', 'h'                 /* :path=/sample/path */
        };
        static const uint8_t input[] = {
            0x03,
            0x81, /* Required Insert Count = 2, Base = 0 */
            0x10, /* :authority=www.example.com */
            0x11, /* :path=/sample/path */
        };
        static const h2o_header_t expected[] = {
            {.name = &H2O_TOKEN_AUTHORITY->buf, .value = {H2O_STRLIT("www.example.com")}},
            {.name = &H2O_TOKEN_PATH->buf, .value = {H2O_STRLIT("/sample/path")}},
        };
        static const uint8_t expected_ack[] = {0x84};
        feed_encoder_stream(dec, encoder, sizeof(encoder));
        do_test_decode_field_section(dec, 4, h2o_iovec_init(input, sizeof(input)), expected, PTLS_ELEMENTSOF(expected),
                                     h2o_iovec_init(expected_ack, sizeof(expected_ack)));
        dec->insert_count = 0; /* The Section Acknowledgment above implies receipt of the referenced inserts. */
    }

    note("B.3. Speculative Insert");
    {
        static const uint8_t encoder[] = {
            0x4a, 'c', 'u', 's', 't', 'o', 'm', '-', 'k', 'e', 'y', 0x0c,
            'c',  'u', 's', 't', 'o', 'm', '-', 'v', 'a', 'l', 'u', 'e',
        };
        static const uint8_t expected_state_sync[] = {0x01};
        uint8_t state_sync[H2O_HPACK_ENCODE_INT_MAX_LENGTH];
        feed_encoder_stream(dec, encoder, sizeof(encoder));
        size_t state_sync_len = h2o_qpack_decoder_send_state_sync(dec, state_sync);
        ok(h2o_memis(state_sync, state_sync_len, expected_state_sync, sizeof(expected_state_sync)));
    }

    note("B.4. Duplicate Instruction, Stream Cancellation");
    {
        static const uint8_t encoder[] = {0x02}; /* Duplicate (Relative Index = 2) */
        static const uint8_t expected_cancel[] = {0x48};
        uint8_t cancel[H2O_HPACK_ENCODE_INT_MAX_LENGTH];
        feed_encoder_stream(dec, encoder, sizeof(encoder));
        ok(dec->table.last - dec->table.first == 4);
        ok(h2o_memis(dec->table.first[3]->name->base, dec->table.first[3]->name->len, H2O_STRLIT(":authority")));
        ok(h2o_memis(dec->table.first[3]->value, dec->table.first[3]->value_len, H2O_STRLIT("www.example.com")));
        size_t cancel_len = h2o_qpack_decoder_send_stream_cancel(dec, cancel, 8);
        ok(h2o_memis(cancel, cancel_len, expected_cancel, sizeof(expected_cancel)));
    }

    note("B.5. Dynamic Table Insert, Eviction");
    {
        static const uint8_t encoder[] = {
            0x81, 0x0d, 'c', 'u', 's', 't', 'o', 'm', '-', 'v', 'a', 'l', 'u', 'e', '2',
        };
        feed_encoder_stream(dec, encoder, sizeof(encoder));
        ok(dec->table.num_bytes == 215);
        ok(dec->table.last - dec->table.first == 4);
        ok(h2o_memis(dec->table.first[0]->name->base, dec->table.first[0]->name->len, H2O_STRLIT(":path")));
        ok(h2o_memis(dec->table.first[0]->value, dec->table.first[0]->value_len, H2O_STRLIT("/sample/path")));
        ok(h2o_memis(dec->table.first[3]->name->base, dec->table.first[3]->name->len, H2O_STRLIT("custom-key")));
        ok(h2o_memis(dec->table.first[3]->value, dec->table.first[3]->value_len, H2O_STRLIT("custom-value2")));
    }

    h2o_qpack_destroy_decoder(dec);
}

static void do_test_decoder_stream_error(h2o_qpack_decoder_t *dec, h2o_iovec_t input, const char *expected_err_desc)
{
    uint64_t insert_count;
    const uint8_t *src = (const uint8_t *)input.base, *src_end = src + input.len;
    const char *err_desc = NULL;
    int ret = h2o_qpack_decoder_handle_input(dec, &insert_count, &src, src_end, &err_desc);

    ok(ret == H2O_HTTP3_ERROR_QPACK_DECOMPRESSION_FAILED);
    ok(err_desc == expected_err_desc);
}

static void do_test_decode_context_error(h2o_qpack_decoder_t *dec, h2o_iovec_t input)
{
    struct st_h2o_qpack_decode_header_ctx_t ctx;
    const uint8_t *src = (const uint8_t *)input.base, *src_end = src + input.len;

    ok(parse_decode_context(dec, &ctx, &src, src_end) == H2O_HTTP3_ERROR_QPACK_DECOMPRESSION_FAILED);
}

static void do_test_decode_header_error(h2o_qpack_decoder_t *dec, h2o_iovec_t input, const char *expected_err_desc)
{
    h2o_mem_pool_t pool;
    struct st_h2o_qpack_decode_header_ctx_t ctx;
    h2o_iovec_t *name = NULL, value = {};
    const uint8_t *src = (const uint8_t *)input.base, *src_end = src + input.len;
    const char *err_desc = NULL;

    h2o_mem_init_pool(&pool);

    ok(parse_decode_context(dec, &ctx, &src, src_end) == 0);
    ok(decode_header(&pool, &ctx, &name, &value, &src, src_end, &err_desc) == H2O_HTTP3_ERROR_QPACK_DECOMPRESSION_FAILED);
    ok(err_desc == expected_err_desc);

    h2o_mem_clear_pool(&pool);
}

static void test_decode_errors(void)
{
    note("encoder stream errors");
    {
        h2o_qpack_decoder_t *dec = h2o_qpack_create_decoder(31, 10);
        /* RFC 9204 Section 4.3.1: capacity greater than the decoder's maximum dynamic table capacity is invalid. */
        static const uint8_t input[] = {0x3f, 0x01}; /* Set Dynamic Table Capacity=32 */
        do_test_decoder_stream_error(dec, h2o_iovec_init(input, sizeof(input)), h2o_qpack_err_invalid_max_size);
        h2o_qpack_destroy_decoder(dec);
    }

    {
        h2o_qpack_decoder_t *dec = h2o_qpack_create_decoder(4096, 10);
        /* RFC 9204 Appendix A defines static table indices 0..98; Section 3.1 forbids invalid static indices. */
        static const uint8_t input[] = {0xff, 0x24, 0}; /* Insert With Name Reference, Static Table, Index=99 */
        do_test_decoder_stream_error(dec, h2o_iovec_init(input, sizeof(input)), h2o_qpack_err_invalid_static_reference);
        h2o_qpack_destroy_decoder(dec);
    }

    {
        h2o_qpack_decoder_t *dec = h2o_qpack_create_decoder(4096, 10);
        /* RFC 9204 Section 2.2.3: an encoder-stream reference to an evicted dynamic entry is invalid. */
        static const uint8_t input[] = {0x80, 0}; /* Insert With Name Reference, Dynamic Table, Index=0 */
        do_test_decoder_stream_error(dec, h2o_iovec_init(input, sizeof(input)), h2o_qpack_err_invalid_dynamic_reference);
        h2o_qpack_destroy_decoder(dec);
    }

    {
        h2o_qpack_decoder_t *dec = h2o_qpack_create_decoder(4096, 10);
        /* RFC 9204 Section 4.3.4 duplicates an existing entry; index 0 is invalid when the table is empty. */
        static const uint8_t input[] = {0}; /* Duplicate, Relative Index=0 */
        do_test_decoder_stream_error(dec, h2o_iovec_init(input, sizeof(input)), h2o_qpack_err_invalid_duplicate);
        h2o_qpack_destroy_decoder(dec);
    }

    {
        h2o_qpack_decoder_t *dec = h2o_qpack_create_decoder(40, 10);
        /*
         * RFC 9204 Section 3.2.1: entry size is name length + value length + 32.
         * Section 3.2.2: adding an entry larger than the dynamic table capacity is invalid.
         */
        static const uint8_t input[] = {
            0x3f, 0x09,                                              /* Set Dynamic Table Capacity=40 */
            0xc0, 9,    't', 'o', 'o', '-', 'l', 'a', 'r', 'g', 'e', /* :authority value; 10 + 9 + 32 > 40 */
        };
        do_test_decoder_stream_error(dec, h2o_iovec_init(input, sizeof(input)), h2o_qpack_err_header_exceeds_table_size);
        h2o_qpack_destroy_decoder(dec);
    }

    note("field section prefix errors");
    {
        h2o_qpack_decoder_t *dec = h2o_qpack_create_decoder(32, 10);
        /* RFC 9204 Section 4.5.1.1: EncodedInsertCount greater than FullRange=2*MaxEntries is invalid. */
        static const uint8_t input[] = {3, 0}; /* MaxEntries=1, FullRange=2, EncodedInsertCount=3 */
        do_test_decode_context_error(dec, h2o_iovec_init(input, sizeof(input)));
        h2o_qpack_destroy_decoder(dec);
    }

    {
        h2o_qpack_decoder_t *dec = h2o_qpack_create_decoder(4096, 10);
        /* RFC 9204 Section 4.5.1.2: Base MUST NOT be negative; RIC <= DeltaBase with Sign=1 is invalid. */
        static const uint8_t input[] = {0, 0x80}; /* negative Base */
        do_test_decode_context_error(dec, h2o_iovec_init(input, sizeof(input)));
        h2o_qpack_destroy_decoder(dec);
    }

    note("field line reference errors");
    {
        h2o_qpack_decoder_t *dec = h2o_qpack_create_decoder(4096, 10);
        /* RFC 9204 Appendix A defines static table indices 0..98; Section 3.1 forbids invalid static indices. */
        static const uint8_t input[] = {
            0,
            0, /* Required Insert Count=0, Base=0 */
            0xff,
            0x24, /* Indexed Field Line, Static Table, Index=99 */
        };
        do_test_decode_header_error(dec, h2o_iovec_init(input, sizeof(input)), h2o_qpack_err_invalid_static_reference);
        h2o_qpack_destroy_decoder(dec);
    }

    {
        h2o_qpack_decoder_t *dec = h2o_qpack_create_decoder(4096, 10);
        /* RFC 9204 Section 2.2.3 forbids dynamic references with absolute index >= Required Insert Count. */
        static const uint8_t input[] = {
            0,
            1,    /* Required Insert Count=0, Base=1 */
            0x80, /* Indexed Field Line, Dynamic Table, Relative Index=0 */
        };
        do_test_decode_header_error(dec, h2o_iovec_init(input, sizeof(input)), h2o_qpack_err_invalid_dynamic_reference);
        h2o_qpack_destroy_decoder(dec);
    }
}

static void test_decode_edge_cases(void)
{
    note("partial encoder stream instruction");
    {
        h2o_qpack_decoder_t *dec = h2o_qpack_create_decoder(4096, 10);
        uint64_t insert_count;
        static const uint8_t input[] = {
            0xc0,
            5,
            'a', /* Insert With Name Reference, Static Table, Index=0, partial value */
        };
        const uint8_t *src = input;
        const char *err_desc = NULL;
        int ret = h2o_qpack_decoder_handle_input(dec, &insert_count, &src, input + sizeof(input), &err_desc);
        ok(ret == 0);
        ok(err_desc == NULL);
        ok(src == input);
        ok(insert_count == 0);
        h2o_qpack_destroy_decoder(dec);
    }

    note("dynamic table exact-capacity insertion and eviction");
    {
        h2o_qpack_decoder_t *dec = h2o_qpack_create_decoder(42, 10);
        static const uint8_t input[] = {
            0x3f, 0x0b, /* Set Dynamic Table Capacity=42 */
            0xc0, 0,    /* Insert :authority with empty value; size = 10 + 0 + 32 */
            0xc0, 0,    /* Insert another exact-size entry, evicting the first */
        };
        feed_encoder_stream(dec, input, sizeof(input));
        ok(dec->table.num_bytes == 42);
        ok(dec->table.last - dec->table.first == 1);
        ok(dec->table.base_offset == 2);
        h2o_qpack_destroy_decoder(dec);
    }

    note("required insert count reconstruction across full range");
    {
        h2o_qpack_decoder_t *dec = h2o_qpack_create_decoder(32, 10);
        struct st_h2o_qpack_decode_header_ctx_t ctx;
        static const uint8_t input[] = {1, 0}; /* MaxEntries=1, FullRange=2, reconstructed RIC=2 */
        const uint8_t *src = input;

        dec->total_inserts = 2;
        dec->table.base_offset = 3;

        ok(parse_decode_context(dec, &ctx, &src, input + sizeof(input)) == 0);
        ok(ctx.req_insert_count == 2);
        ok(ctx.base_index == 2);
        ok(src == input + sizeof(input));
        h2o_qpack_destroy_decoder(dec);
    }

    note("blocked stream limit boundary");
    {
        h2o_qpack_decoder_t *dec = h2o_qpack_create_decoder(4096, 1);
        struct st_h2o_qpack_decode_header_ctx_t ctx;
        static const uint8_t input[] = {2, 0}; /* RIC=1, Base=1, blocked until first insert arrives */
        const uint8_t *src = input;
        uint64_t blocked_ref;

        ok(parse_decode_context(dec, &ctx, &src, input + sizeof(input)) == 0);
        ok(check_decode_context_blocked(dec, &ctx, 0, &blocked_ref) == 0);
        ok(blocked_ref == 1);
        h2o_qpack_destroy_decoder(dec);
    }

    note("released blocked stream frees blocked stream budget");
    {
        h2o_qpack_decoder_t *dec = h2o_qpack_create_decoder(4096, 1);
        struct st_h2o_qpack_decode_header_ctx_t ctx;
        static const uint8_t input[] = {2, 0}; /* RIC=1, Base=1 */
        const uint8_t *src = input;
        uint64_t blocked_ref;

        ok(parse_decode_context(dec, &ctx, &src, input + sizeof(input)) == 0);
        ok(check_decode_context_blocked(dec, &ctx, 0, &blocked_ref) == 0);
        /* caller-tracked counter goes 0 -> 1 -> 0; next blocked section is admissible again */
        src = input;
        ok(parse_decode_context(dec, &ctx, &src, input + sizeof(input)) == 0);
        ok(check_decode_context_blocked(dec, &ctx, 0, &blocked_ref) == 0);
        ok(blocked_ref == 1);
        h2o_qpack_destroy_decoder(dec);
    }

    note("blocked stream budget is enforced from caller-supplied num_blocked");
    {
        h2o_qpack_decoder_t *dec = h2o_qpack_create_decoder(4096, 1);
        struct st_h2o_qpack_decode_header_ctx_t ctx;
        static const uint8_t input1[] = {2, 0}; /* RIC=1, Base=1 */
        const uint8_t *src = input1;
        uint64_t blocked_ref;

        ok(parse_decode_context(dec, &ctx, &src, input1 + sizeof(input1)) == 0);
        ok(check_decode_context_blocked(dec, &ctx, 0, &blocked_ref) == 0);

        src = input1;
        ok(parse_decode_context(dec, &ctx, &src, input1 + sizeof(input1)) == 0);
        ok(check_decode_context_blocked(dec, &ctx, 1, &blocked_ref) == H2O_HTTP3_ERROR_QPACK_DECOMPRESSION_FAILED);
        h2o_qpack_destroy_decoder(dec);
    }

    note("encoder stream input reports insert count for H3-side unblocking");
    {
        h2o_qpack_decoder_t *dec = h2o_qpack_create_decoder(4096, 2);
        struct st_h2o_qpack_decode_header_ctx_t ctx;
        static const uint8_t input1[] = {2, 0}; /* RIC=1, Base=1 */
        static const uint8_t input2[] = {3, 0}; /* RIC=2, Base=2 */
        static const uint8_t inserts[] = {
            0xc0,
            0, /* Insert With Name Reference, Static Table, Index=0, empty value */
            0xc0,
            0, /* Insert With Name Reference, Static Table, Index=0, empty value */
        };
        const uint8_t *src = input1;
        uint64_t blocked_ref;

        ok(parse_decode_context(dec, &ctx, &src, input1 + sizeof(input1)) == 0);
        ok(check_decode_context_blocked(dec, &ctx, 0, &blocked_ref) == 0);
        src = input2;
        ok(parse_decode_context(dec, &ctx, &src, input2 + sizeof(input2)) == 0);
        ok(check_decode_context_blocked(dec, &ctx, 1, &blocked_ref) == 0);

        uint64_t insert_count;
        const char *err_desc = NULL;
        src = inserts;
        ok(h2o_qpack_decoder_handle_input(dec, &insert_count, &src, inserts + sizeof(inserts), &err_desc) == 0);
        ok(err_desc == NULL);
        ok(src == inserts + sizeof(inserts));
        ok(insert_count == 2);
        h2o_qpack_destroy_decoder(dec);
    }
}

void test_lib__http3_qpack(void)
{
    subtest("simple", test_simple);
    subtest("decode-literal-invalid-name", test_decode_literal_invalid_name);
    subtest("decode-literal-invalid-value", test_decode_literal_invalid_value);
    subtest("decode-referred", test_decode_referred);
    subtest("rfc9204-appendix-b", test_rfc9204_appendix_b);
    subtest("decode-errors", test_decode_errors);
    subtest("decode-edge-cases", test_decode_edge_cases);
}
