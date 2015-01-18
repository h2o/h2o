/*
 * Copyright (c) 2014 DeNA Co., Ltd.
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
#include "../../test.h"
#include "../../../../lib/http2/hpack.c"

static void test_request(h2o_iovec_t first_req, h2o_iovec_t second_req, h2o_iovec_t third_req)
{
    h2o_hpack_header_table_t header_table;
    h2o_req_t req;
    h2o_iovec_t in;
    int r, allow_psuedo;

    memset(&header_table, 0, sizeof(header_table));
    header_table.hpack_capacity = 4096;

    memset(&req, 0, sizeof(req));
    h2o_mem_init_pool(&req.pool);
    allow_psuedo = 1;
    in = first_req;
    r = h2o_hpack_parse_headers(&req, &header_table, &allow_psuedo, (const uint8_t *)in.base, in.len);
    ok(r == 0);
    ok(allow_psuedo == 1);
    ok(req.authority.len == 15);
    ok(memcmp(req.authority.base, H2O_STRLIT("www.example.com")) == 0);
    ok(req.method.len == 3);
    ok(memcmp(req.method.base, H2O_STRLIT("GET")) == 0);
    ok(req.path.len == 1);
    ok(memcmp(req.path.base, H2O_STRLIT("/")) == 0);
    ok(req.scheme.len == 4);
    ok(memcmp(req.scheme.base, H2O_STRLIT("http")) == 0);
    ok(req.headers.size == 0);

    h2o_mem_clear_pool(&req.pool);

    memset(&req, 0, sizeof(req));
    h2o_mem_init_pool(&req.pool);
    allow_psuedo = 1;
    in = second_req;
    r = h2o_hpack_parse_headers(&req, &header_table, &allow_psuedo, (const uint8_t *)in.base, in.len);
    ok(r == 0);
    ok(allow_psuedo == 0);
    ok(req.authority.len == 15);
    ok(memcmp(req.authority.base, H2O_STRLIT("www.example.com")) == 0);
    ok(req.method.len == 3);
    ok(memcmp(req.method.base, H2O_STRLIT("GET")) == 0);
    ok(req.path.len == 1);
    ok(memcmp(req.path.base, H2O_STRLIT("/")) == 0);
    ok(req.scheme.len == 4);
    ok(memcmp(req.scheme.base, H2O_STRLIT("http")) == 0);
    ok(req.headers.size == 1);
    ok(h2o_lcstris(req.headers.entries[0].name->base, req.headers.entries[0].name->len, H2O_STRLIT("cache-control")));
    ok(h2o_lcstris(req.headers.entries[0].value.base, req.headers.entries[0].value.len, H2O_STRLIT("no-cache")));

    h2o_mem_clear_pool(&req.pool);

    memset(&req, 0, sizeof(req));
    h2o_mem_init_pool(&req.pool);
    allow_psuedo = 1;
    in = third_req;
    r = h2o_hpack_parse_headers(&req, &header_table, &allow_psuedo, (const uint8_t *)in.base, in.len);
    ok(r == 0);
    ok(allow_psuedo == 0);
    ok(req.authority.len == 15);
    ok(memcmp(req.authority.base, H2O_STRLIT("www.example.com")) == 0);
    ok(req.method.len == 3);
    ok(memcmp(req.method.base, H2O_STRLIT("GET")) == 0);
    ok(req.path.len == 11);
    ok(memcmp(req.path.base, H2O_STRLIT("/index.html")) == 0);
    ok(req.scheme.len == 5);
    ok(memcmp(req.scheme.base, H2O_STRLIT("https")) == 0);
    ok(req.headers.size == 1);
    ok(h2o_lcstris(req.headers.entries[0].name->base, req.headers.entries[0].name->len, H2O_STRLIT("custom-key")));
    ok(h2o_lcstris(req.headers.entries[0].value.base, req.headers.entries[0].value.len, H2O_STRLIT("custom-value")));

    h2o_hpack_dispose_header_table(&header_table);
    h2o_mem_clear_pool(&req.pool);
}

static void check_flatten(h2o_hpack_header_table_t *header_table, h2o_res_t *res, const char *expected, size_t expected_len)
{
    h2o_buffer_t *buf;
    h2o_http2_frame_t frame;
    const char *err_desc;

    h2o_buffer_init(&buf, &h2o_socket_buffer_prototype);
    h2o_hpack_flatten_headers(&buf, header_table, 1, H2O_HTTP2_SETTINGS_DEFAULT.max_frame_size, res, NULL, NULL);

    ok(h2o_http2_decode_frame(&frame, (uint8_t *)buf->bytes, buf->size, &H2O_HTTP2_SETTINGS_DEFAULT, &err_desc) > 0);
    ok(h2o_memis(frame.payload, frame.length, expected, expected_len));

    h2o_buffer_dispose(&buf);
}

void test_lib__http2__hpack(void)
{
    h2o_mem_pool_t pool;
    h2o_mem_init_pool(&pool);

    note("decode_int");
    {
        h2o_iovec_t in;
        const uint8_t *p;
        int32_t out;
#define TEST(input, output)                                                                                                        \
    in = h2o_iovec_init(H2O_STRLIT(input));                                                                                        \
    p = (const uint8_t *)in.base;                                                                                                  \
    out = decode_int(&p, p + in.len, 7);                                                                                           \
    ok(out == output);                                                                                                             \
    ok(p == (const uint8_t *)in.base + in.len);
        TEST("\x00", 0);
        TEST("\x03", 3);
        TEST("\x81", 1);
        TEST("\x7f\x00", 127);
        TEST("\x7f\x01", 128);
        TEST("\x7f\x7f", 254);
        TEST("\x7f\x81\x00", 128);
        TEST("\x7f\x80\x01", 255);
        TEST("\x7f\xff\xff\xff\x7f", 0xfffffff + 127);
        /* failures */
        TEST("", -1);
        TEST("\x7f", -1);
        TEST("\x7f\xff", -1);
        TEST("\x7f\xff\xff\xff\xff", -1);
#undef TEST
    }

    note("decode_huffman");
    {
        h2o_iovec_t huffcode = {H2O_STRLIT("\xf1\xe3\xc2\xe5\xf2\x3a\x6b\xa0\xab\x90\xf4\xff")};
        h2o_iovec_t *decoded = decode_huffman(&pool, (const uint8_t *)huffcode.base, huffcode.len);
        ok(decoded->len == sizeof("www.example.com") - 1);
        ok(strcmp(decoded->base, "www.example.com") == 0);
    }
    h2o_mem_clear_pool(&pool);

    note("decode_header (literal header field with indexing)");
    {
        struct st_h2o_decode_header_result_t result;
        h2o_hpack_header_table_t header_table;
        h2o_iovec_t in;
        int r;

        memset(&header_table, 0, sizeof(header_table));
        header_table.hpack_capacity = 4096;
        in = h2o_iovec_init(
            H2O_STRLIT("\x40\x0a\x63\x75\x73\x74\x6f\x6d\x2d\x6b\x65\x79\x0d\x63\x75\x73\x74\x6f\x6d\x2d\x68\x65\x61\x64\x65\x72"));
        const uint8_t *p = (const uint8_t *)in.base;
        r = decode_header(&pool, &result, &header_table, &p, p + in.len);
        ok(r == 0);
        ok(result.name->len == 10);
        ok(strcmp(result.name->base, "custom-key") == 0);
        ok(result.value->len == 13);
        ok(strcmp(result.value->base, "custom-header") == 0);
        ok(header_table.hpack_size == 55);
    }
    h2o_mem_clear_pool(&pool);

    note("decode_header (literal header field without indexing)");
    {
        struct st_h2o_decode_header_result_t result;
        h2o_hpack_header_table_t header_table;
        h2o_iovec_t in;
        int r;

        memset(&header_table, 0, sizeof(header_table));
        header_table.hpack_capacity = 4096;
        in = h2o_iovec_init(H2O_STRLIT("\x04\x0c\x2f\x73\x61\x6d\x70\x6c\x65\x2f\x70\x61\x74\x68"));
        const uint8_t *p = (const uint8_t *)in.base;
        r = decode_header(&pool, &result, &header_table, &p, p + in.len);
        ok(r == 0);
        ok(result.name == &H2O_TOKEN_PATH->buf);
        ok(result.value->len == 12);
        ok(strcmp(result.value->base, "/sample/path") == 0);
        ok(header_table.hpack_size == 0);
    }
    h2o_mem_clear_pool(&pool);

    note("decode_header (literal header field never indexed)");
    {
        struct st_h2o_decode_header_result_t result;
        h2o_hpack_header_table_t header_table;
        h2o_iovec_t in;
        int r;

        memset(&header_table, 0, sizeof(header_table));
        header_table.hpack_capacity = 4096;
        in = h2o_iovec_init(H2O_STRLIT("\x10\x08\x70\x61\x73\x73\x77\x6f\x72\x64\x06\x73\x65\x63\x72\x65\x74"));
        const uint8_t *p = (const uint8_t *)in.base;
        r = decode_header(&pool, &result, &header_table, &p, p + in.len);
        ok(r == 0);
        ok(result.name->len == 8);
        ok(strcmp(result.name->base, "password") == 0);
        ok(result.value->len == 6);
        ok(strcmp(result.value->base, "secret") == 0);
        ok(header_table.hpack_size == 0);
    }
    h2o_mem_clear_pool(&pool);

    note("decode_header (indexed header field)");
    {
        struct st_h2o_decode_header_result_t result;
        h2o_hpack_header_table_t header_table;
        h2o_iovec_t in;
        int r;

        memset(&header_table, 0, sizeof(header_table));
        header_table.hpack_capacity = 4096;
        in = h2o_iovec_init(H2O_STRLIT("\x82"));
        const uint8_t *p = (const uint8_t *)in.base;
        r = decode_header(&pool, &result, &header_table, &p, p + in.len);
        ok(r == 0);
        ok(result.name == &H2O_TOKEN_METHOD->buf);
        ok(result.value->len == 3);
        ok(strcmp(result.value->base, "GET") == 0);
        ok(header_table.hpack_size == 0);
    }
    h2o_mem_clear_pool(&pool);

    note("request examples without huffman coding");
    test_request(h2o_iovec_init(H2O_STRLIT("\x82\x86\x84\x41\x0f\x77\x77\x77\x2e\x65\x78\x61\x6d\x70\x6c\x65\x2e\x63\x6f\x6d")),
                 h2o_iovec_init(H2O_STRLIT("\x82\x86\x84\xbe\x58\x08\x6e\x6f\x2d\x63\x61\x63\x68\x65")),
                 h2o_iovec_init(H2O_STRLIT("\x82\x87\x85\xbf\x40\x0a\x63\x75\x73\x74\x6f\x6d\x2d\x6b\x65\x79\x0c\x63\x75\x73\x74"
                                           "\x6f\x6d\x2d\x76\x61\x6c\x75\x65")));

    note("request examples with huffman coding");
    test_request(h2o_iovec_init(H2O_STRLIT("\x82\x86\x84\x41\x8c\xf1\xe3\xc2\xe5\xf2\x3a\x6b\xa0\xab\x90\xf4\xff")),
                 h2o_iovec_init(H2O_STRLIT("\x82\x86\x84\xbe\x58\x86\xa8\xeb\x10\x64\x9c\xbf")),
                 h2o_iovec_init(H2O_STRLIT(
                     "\x82\x87\x85\xbf\x40\x88\x25\xa8\x49\xe9\x5b\xa9\x7d\x7f\x89\x25\xa8\x49\xe9\x5b\xb8\xe8\xb4\xbf")));

    note("encode_huffman");
    {
        h2o_iovec_t huffcode = {H2O_STRLIT("\xf1\xe3\xc2\xe5\xf2\x3a\x6b\xa0\xab\x90\xf4\xff")};
        char buf[sizeof("www.example.com")];
        size_t l = encode_huffman((uint8_t *)buf, (uint8_t *)H2O_STRLIT("www.example.com"));
        ok(l == huffcode.len);
        ok(memcmp(buf, huffcode.base, huffcode.len) == 0);
    }

    note("response examples with huffmann coding");
    {
        h2o_hpack_header_table_t header_table;
        h2o_res_t res;

        memset(&header_table, 0, sizeof(header_table));
        header_table.hpack_capacity = 256;

        memset(&res, 0, sizeof(res));
        res.status = 302;
        res.reason = "Found";
        h2o_add_header(&pool, &res.headers, H2O_TOKEN_CACHE_CONTROL, H2O_STRLIT("private"));
        h2o_add_header(&pool, &res.headers, H2O_TOKEN_DATE, H2O_STRLIT("Mon, 21 Oct 2013 20:13:21 GMT"));
        h2o_add_header(&pool, &res.headers, H2O_TOKEN_LOCATION, H2O_STRLIT("https://www.example.com"));
        check_flatten(&header_table, &res, H2O_STRLIT("\x08\x03\x33\x30\x32\x58\x85\xae\xc3\x77\x1a\x4b\x61\x96\xd0\x7a\xbe\x94\x10"
                                                      "\x54\xd4\x44\xa8\x20\x05\x95\x04\x0b\x81\x66\xe0\x82\xa6\x2d\x1b\xff\x6e\x91"
                                                      "\x9d\x29\xad\x17\x18\x63\xc7\x8f\x0b\x97\xc8\xe9\xae\x82\xae\x43\xd3"));

        memset(&res, 0, sizeof(res));
        res.status = 307;
        res.reason = "Temporary Redirect";
        h2o_add_header(&pool, &res.headers, H2O_TOKEN_CACHE_CONTROL, H2O_STRLIT("private"));
        h2o_add_header(&pool, &res.headers, H2O_TOKEN_DATE, H2O_STRLIT("Mon, 21 Oct 2013 20:13:21 GMT"));
        h2o_add_header(&pool, &res.headers, H2O_TOKEN_LOCATION, H2O_STRLIT("https://www.example.com"));
        check_flatten(&header_table, &res, H2O_STRLIT("\x08\x03\x33\x30\x37\xc0\xbf\xbe"));
#if 0
        h2o_iovec_init(H2O_STRLIT("\x48\x03\x33\x30\x37\xc1\xc0\xbf")),
        h2o_iovec_init(H2O_STRLIT("\x88\xc1\x61\x1d\x4d\x6f\x6e\x2c\x20\x32\x31\x20\x4f\x63\x74\x20\x32\x30\x31\x33\x20\x32\x30\x3a\x31\x33\x3a\x32\x32\x20\x47\x4d\x54\xc0\x5a\x04\x67\x7a\x69\x70\x77\x38\x66\x6f\x6f\x3d\x41\x53\x44\x4a\x4b\x48\x51\x4b\x42\x5a\x58\x4f\x51\x57\x45\x4f\x50\x49\x55\x41\x58\x51\x57\x45\x4f\x49\x55\x3b\x20\x6d\x61\x78\x2d\x61\x67\x65\x3d\x33\x36\x30\x30\x3b\x20\x76\x65\x72\x73\x69\x6f\x6e\x3d\x31")));
#endif
    }

    h2o_mem_clear_pool(&pool);
}
