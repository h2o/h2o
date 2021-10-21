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
#include <stdarg.h>
#include "../../test.h"
#include "../../../../lib/http2/hpack.c"

static void test_request(h2o_iovec_t first_req, h2o_iovec_t second_req, h2o_iovec_t third_req)
{
    h2o_hpack_header_table_t header_table;
    h2o_req_t req;
    h2o_iovec_t in;
    int r, pseudo_headers_map;
    size_t content_length;
    const char *err_desc = NULL;

    memset(&header_table, 0, sizeof(header_table));
    header_table.hpack_capacity = 4096;

    memset(&req, 0, sizeof(req));
    h2o_mem_init_pool(&req.pool);
    in = first_req;
    r = h2o_hpack_parse_request(&req.pool, h2o_hpack_decode_header, &header_table, &req.input.method, &req.input.scheme,
                                &req.input.authority, &req.input.path, &req.headers, &pseudo_headers_map, &content_length, NULL,
                                (const uint8_t *)in.base, in.len, &err_desc);
    ok(r == 0);
    ok(req.input.authority.len == 15);
    ok(memcmp(req.input.authority.base, H2O_STRLIT("www.example.com")) == 0);
    ok(req.input.method.len == 3);
    ok(memcmp(req.input.method.base, H2O_STRLIT("GET")) == 0);
    ok(req.input.path.len == 1);
    ok(memcmp(req.input.path.base, H2O_STRLIT("/")) == 0);
    ok(req.input.scheme == &H2O_URL_SCHEME_HTTP);
    ok(req.headers.size == 0);

    h2o_mem_clear_pool(&req.pool);

    memset(&req, 0, sizeof(req));
    h2o_mem_init_pool(&req.pool);
    in = second_req;
    r = h2o_hpack_parse_request(&req.pool, h2o_hpack_decode_header, &header_table, &req.input.method, &req.input.scheme,
                                &req.input.authority, &req.input.path, &req.headers, &pseudo_headers_map, &content_length, NULL,
                                (const uint8_t *)in.base, in.len, &err_desc);
    ok(r == 0);
    ok(req.input.authority.len == 15);
    ok(memcmp(req.input.authority.base, H2O_STRLIT("www.example.com")) == 0);
    ok(req.input.method.len == 3);
    ok(memcmp(req.input.method.base, H2O_STRLIT("GET")) == 0);
    ok(req.input.path.len == 1);
    ok(memcmp(req.input.path.base, H2O_STRLIT("/")) == 0);
    ok(req.input.scheme == &H2O_URL_SCHEME_HTTP);
    ok(req.headers.size == 1);
    ok(h2o_memis(req.headers.entries[0].name->base, req.headers.entries[0].name->len, H2O_STRLIT("cache-control")));
    ok(h2o_lcstris(req.headers.entries[0].value.base, req.headers.entries[0].value.len, H2O_STRLIT("no-cache")));

    h2o_mem_clear_pool(&req.pool);

    memset(&req, 0, sizeof(req));
    h2o_mem_init_pool(&req.pool);
    in = third_req;
    r = h2o_hpack_parse_request(&req.pool, h2o_hpack_decode_header, &header_table, &req.input.method, &req.input.scheme,
                                &req.input.authority, &req.input.path, &req.headers, &pseudo_headers_map, &content_length, NULL,
                                (const uint8_t *)in.base, in.len, &err_desc);
    ok(r == 0);
    ok(req.input.authority.len == 15);
    ok(memcmp(req.input.authority.base, H2O_STRLIT("www.example.com")) == 0);
    ok(req.input.method.len == 3);
    ok(memcmp(req.input.method.base, H2O_STRLIT("GET")) == 0);
    ok(req.input.path.len == 11);
    ok(memcmp(req.input.path.base, H2O_STRLIT("/index.html")) == 0);
    ok(req.input.scheme == &H2O_URL_SCHEME_HTTPS);
    ok(req.headers.size == 1);
    ok(h2o_memis(req.headers.entries[0].name->base, req.headers.entries[0].name->len, H2O_STRLIT("custom-key")));
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
    h2o_hpack_flatten_response(&buf, header_table, 1, H2O_HTTP2_SETTINGS_DEFAULT.max_frame_size, res->status, res->headers.entries,
                               res->headers.size, NULL, SIZE_MAX);

    ok(h2o_http2_decode_frame(&frame, (uint8_t *)buf->bytes, buf->size, H2O_HTTP2_SETTINGS_DEFAULT.max_frame_size, &err_desc) > 0);
    ok(h2o_memis(frame.payload, frame.length, expected, expected_len));

    h2o_buffer_dispose(&buf);
}

static void test_hpack(void)
{
    h2o_mem_pool_t pool;
    const char *err_desc;

    h2o_mem_init_pool(&pool);

    note("decode_int");
    {
        h2o_iovec_t in;
        const uint8_t *p;
        int64_t out;
#define TEST(input, output)                                                                                                        \
    in = h2o_iovec_init(H2O_STRLIT(input));                                                                                        \
    p = (const uint8_t *)in.base;                                                                                                  \
    out = h2o_hpack_decode_int(&p, p + in.len, 7);                                                                                 \
    ok(out == output);                                                                                                             \
    ok(output == H2O_HTTP2_ERROR_COMPRESSION || p == (const uint8_t *)in.base + in.len);
        TEST("\x00", 0);
        TEST("\x03", 3);
        TEST("\x81", 1);
        TEST("\x7f\x00", 127);
        TEST("\x7f\x01", 128);
        TEST("\x7f\x7f", 254);
        TEST("\x7f\x81\x00", 128);
        TEST("\x7f\x80\x01", 255);
        TEST("\x7f\xff\xff\xff\x7f", 0xfffffff + 127);
        TEST("\x7f\x80\xff\xff\xff\xff\xff\xff\xff\x7f", INT64_MAX);
        /* failures */
        TEST("", H2O_HTTP2_ERROR_INCOMPLETE);
        TEST("\x7f", H2O_HTTP2_ERROR_INCOMPLETE);
        TEST("\x7f\xff", H2O_HTTP2_ERROR_INCOMPLETE);
        TEST("\x7f\xff\xff\xff\xff", H2O_HTTP2_ERROR_INCOMPLETE);
        TEST("\x7f\x81\xff\xff\xff\xff\xff\xff\xff\x7f", H2O_HTTP2_ERROR_COMPRESSION);
        TEST("\x7f\x80\xff\xff\xff\xff\xff\xff\xff\xff", H2O_HTTP2_ERROR_COMPRESSION);
#undef TEST
    }

    note("encode_int");
    {
        uint8_t buf[16];
        size_t len;
#define TEST(encoded, value)                                                                                                       \
    memset(buf, 0, sizeof(buf));                                                                                                   \
    len = h2o_hpack_encode_int(buf, value, 7) - buf;                                                                               \
    ok(len == sizeof(encoded) - 1);                                                                                                \
    ok(memcmp(buf, encoded, sizeof(encoded) - 1) == 0);
        TEST("\x00", 0);
        TEST("\x03", 3);
        TEST("\x7e", 126);
        TEST("\x7f\x00", 127);
        TEST("\x7f\x01", 128);
        TEST("\x7f\x7f", 254);
        TEST("\x7f\x80\x01", 255);
        TEST("\x7f\xff\xff\xff\x7f", 0xfffffff + 127);
        TEST("\x7f\x80\xff\xff\xff\xff\xff\xff\xff\x7f", INT64_MAX);
#undef TEST
    }

    note("decode_huffman");
    {
        h2o_iovec_t huffcode = {H2O_STRLIT("\xf1\xe3\xc2\xe5\xf2\x3a\x6b\xa0\xab\x90\xf4\xff")};
        char buf[32];
        unsigned soft_errors = 0;
        const char *err_desc = NULL;
        size_t len = h2o_hpack_decode_huffman(buf, &soft_errors, (const uint8_t *)huffcode.base, huffcode.len, 0, &err_desc);
        ok(len == sizeof("www.example.com") - 1);
        ok(memcmp(buf, "www.example.com", len) == 0);
        ok(soft_errors == 0);
        ok(err_desc == NULL);
    }
    h2o_mem_clear_pool(&pool);

    note("decode_string_bogus");
    {
        char *str = "\x8c\xf1\xe3\xc2\xe5\xf2\x3a\x6b\xa0\xab\x90\xf4\xff";
        const uint8_t *buf;
        unsigned soft_errors = 0;
        const char *errstr = NULL;
        size_t len;
        len = strlen(str);
        buf = (const uint8_t *)str;
        /* since we're only passing one byte, decode_string should fail */
        h2o_iovec_t *decoded = decode_string(&pool, &soft_errors, &buf, &buf[1], 0, &errstr);
        ok(decoded == NULL);
    }
    h2o_mem_clear_pool(&pool);

    note("decode_header (literal header field with indexing)");
    {
        h2o_hpack_header_table_t header_table;
        h2o_iovec_t in, *name, value;
        int r;

        memset(&header_table, 0, sizeof(header_table));
        header_table.hpack_capacity = 4096;
        in = h2o_iovec_init(
            H2O_STRLIT("\x40\x0a\x63\x75\x73\x74\x6f\x6d\x2d\x6b\x65\x79\x0d\x63\x75\x73\x74\x6f\x6d\x2d\x68\x65\x61\x64\x65\x72"));
        const uint8_t *p = (const uint8_t *)in.base;
        err_desc = NULL;
        r = h2o_hpack_decode_header(&pool, &header_table, &name, &value, &p, p + in.len, &err_desc);
        ok(r == 0);
        ok(name->len == 10);
        ok(strcmp(name->base, "custom-key") == 0);
        ok(value.len == 13);
        ok(strcmp(value.base, "custom-header") == 0);
        ok(header_table.hpack_size == 55);
    }
    h2o_mem_clear_pool(&pool);

    note("decode_header (literal header field without indexing)");
    {
        h2o_hpack_header_table_t header_table;
        h2o_iovec_t in, *name, value;
        int r;

        memset(&header_table, 0, sizeof(header_table));
        header_table.hpack_capacity = 4096;
        in = h2o_iovec_init(H2O_STRLIT("\x04\x0c\x2f\x73\x61\x6d\x70\x6c\x65\x2f\x70\x61\x74\x68"));
        const uint8_t *p = (const uint8_t *)in.base;
        err_desc = NULL;
        r = h2o_hpack_decode_header(&pool, &header_table, &name, &value, &p, p + in.len, &err_desc);
        ok(r == 0);
        ok(name == &H2O_TOKEN_PATH->buf);
        ok(value.len == 12);
        ok(strcmp(value.base, "/sample/path") == 0);
        ok(header_table.hpack_size == 0);
    }
    h2o_mem_clear_pool(&pool);

    note("decode_header (literal header field never indexed)");
    {
        h2o_hpack_header_table_t header_table;
        h2o_iovec_t in, *name, value;
        int r;

        memset(&header_table, 0, sizeof(header_table));
        header_table.hpack_capacity = 4096;
        in = h2o_iovec_init(H2O_STRLIT("\x10\x08\x70\x61\x73\x73\x77\x6f\x72\x64\x06\x73\x65\x63\x72\x65\x74"));
        const uint8_t *p = (const uint8_t *)in.base;
        err_desc = NULL;
        r = h2o_hpack_decode_header(&pool, &header_table, &name, &value, &p, p + in.len, &err_desc);
        ok(r == 0);
        ok(name->len == 8);
        ok(strcmp(name->base, "password") == 0);
        ok(value.len == 6);
        ok(strcmp(value.base, "secret") == 0);
        ok(header_table.hpack_size == 0);
    }
    h2o_mem_clear_pool(&pool);

    note("decode_header (indexed header field)");
    {
        h2o_hpack_header_table_t header_table;
        h2o_iovec_t in, *name, value;
        int r;

        memset(&header_table, 0, sizeof(header_table));
        header_table.hpack_capacity = 4096;
        in = h2o_iovec_init(H2O_STRLIT("\x82"));
        const uint8_t *p = (const uint8_t *)in.base;
        err_desc = NULL;
        r = h2o_hpack_decode_header(&pool, &header_table, &name, &value, &p, p + in.len, &err_desc);
        ok(r == 0);
        ok(name == &H2O_TOKEN_METHOD->buf);
        ok(value.len == 3);
        ok(strcmp(value.base, "GET") == 0);
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
        size_t l = h2o_hpack_encode_huffman((uint8_t *)buf, (uint8_t *)H2O_STRLIT("www.example.com"));
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
        h2o_add_header(&pool, &res.headers, H2O_TOKEN_CACHE_CONTROL, NULL, H2O_STRLIT("private"));
        h2o_add_header(&pool, &res.headers, H2O_TOKEN_DATE, NULL, H2O_STRLIT("Mon, 21 Oct 2013 20:13:21 GMT"));
        h2o_add_header(&pool, &res.headers, H2O_TOKEN_LOCATION, NULL, H2O_STRLIT("https://www.example.com"));
        check_flatten(&header_table, &res,
                      H2O_STRLIT("\x08\x03\x33\x30\x32\x58\x85\xae\xc3\x77\x1a\x4b\x61\x96\xd0\x7a\xbe\x94\x10"
                                 "\x54\xd4\x44\xa8\x20\x05\x95\x04\x0b\x81\x66\xe0\x82\xa6\x2d\x1b\xff\x6e\x91"
                                 "\x9d\x29\xad\x17\x18\x63\xc7\x8f\x0b\x97\xc8\xe9\xae\x82\xae\x43\xd3"));

        memset(&res, 0, sizeof(res));
        res.status = 307;
        res.reason = "Temporary Redirect";
        h2o_add_header(&pool, &res.headers, H2O_TOKEN_CACHE_CONTROL, NULL, H2O_STRLIT("private"));
        h2o_add_header(&pool, &res.headers, H2O_TOKEN_DATE, NULL, H2O_STRLIT("Mon, 21 Oct 2013 20:13:21 GMT"));
        h2o_add_header(&pool, &res.headers, H2O_TOKEN_LOCATION, NULL, H2O_STRLIT("https://www.example.com"));
        check_flatten(&header_table, &res, H2O_STRLIT("\x08\x03\x33\x30\x37\xc0\xbf\xbe"));
#if 0
        h2o_iovec_init(H2O_STRLIT("\x48\x03\x33\x30\x37\xc1\xc0\xbf")),
        h2o_iovec_init(H2O_STRLIT("\x88\xc1\x61\x1d\x4d\x6f\x6e\x2c\x20\x32\x31\x20\x4f\x63\x74\x20\x32\x30\x31\x33\x20\x32\x30\x3a\x31\x33\x3a\x32\x32\x20\x47\x4d\x54\xc0\x5a\x04\x67\x7a\x69\x70\x77\x38\x66\x6f\x6f\x3d\x41\x53\x44\x4a\x4b\x48\x51\x4b\x42\x5a\x58\x4f\x51\x57\x45\x4f\x50\x49\x55\x41\x58\x51\x57\x45\x4f\x49\x55\x3b\x20\x6d\x61\x78\x2d\x61\x67\x65\x3d\x33\x36\x30\x30\x3b\x20\x76\x65\x72\x73\x69\x6f\x6e\x3d\x31")));
#endif
    }

    h2o_mem_clear_pool(&pool);
}

static void parse_and_compare_request(h2o_hpack_header_table_t *ht, const char *promise_base, size_t promise_len,
                                      h2o_iovec_t expected_method, const h2o_url_scheme_t *expected_scheme,
                                      h2o_iovec_t expected_authority, h2o_iovec_t expected_path, ...)
{
    h2o_req_t req = {NULL};
    h2o_mem_init_pool(&req.pool);

    int pseudo_header_exists_map = 0;
    size_t content_length = SIZE_MAX;
    const char *err_desc = NULL;
    int r = h2o_hpack_parse_request(&req.pool, h2o_hpack_decode_header, ht, &req.input.method, &req.input.scheme,
                                    &req.input.authority, &req.input.path, &req.headers, &pseudo_header_exists_map, &content_length,
                                    NULL, (void *)(promise_base + 13), promise_len - 13, &err_desc);
    ok(r == 0);
    ok(h2o_memis(req.input.method.base, req.input.method.len, expected_method.base, expected_method.len));
    ok(req.input.scheme == expected_scheme);
    ok(h2o_memis(req.input.authority.base, req.input.authority.len, expected_authority.base, expected_authority.len));
    ok(h2o_memis(req.input.path.base, req.input.path.len, expected_path.base, expected_path.len));

    va_list args;
    va_start(args, expected_path);
    size_t i;
    for (i = 0; i != req.headers.size; ++i) {
        h2o_iovec_t expected_name = va_arg(args, h2o_iovec_t);
        if (expected_name.base == NULL)
            break;
        h2o_iovec_t expected_value = va_arg(args, h2o_iovec_t);
        ok(h2o_memis(req.headers.entries[i].name->base, req.headers.entries[i].name->len, expected_name.base, expected_name.len));
        ok(h2o_memis(req.headers.entries[i].value.base, req.headers.entries[i].value.len, expected_value.base, expected_value.len));
    }
    ok(i == req.headers.size);
    va_end(args);

    h2o_mem_clear_pool(&req.pool);
}

static void test_hpack_push(void)
{
    const static h2o_iovec_t method = {H2O_STRLIT("GET")}, authority = {H2O_STRLIT("example.com")},
                             user_agent = {H2O_STRLIT(
                                 "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.9; rv:40.0) Gecko/20100101 Firefox/40.0")},
                             accept_root = {H2O_STRLIT("text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")},
                             accept_images = {H2O_STRLIT("image/png,image/*;q=0.8,*/*;q=0.5")},
                             accept_language = {H2O_STRLIT("ja,en-US;q=0.7,en;q=0.3")},
                             accept_encoding = {H2O_STRLIT("gzip, deflate")}, referer = {H2O_STRLIT("https://example.com/")};

    h2o_hpack_header_table_t encode_table = {NULL}, decode_table = {NULL};
    encode_table.hpack_capacity = decode_table.hpack_capacity = 4096;
    h2o_req_t req = {NULL};
    h2o_mem_init_pool(&req.pool);
    h2o_buffer_t *buf;
    h2o_buffer_init(&buf, &h2o_socket_buffer_prototype);

    /* setup first request */
    req.input.method = method;
    req.input.scheme = &H2O_URL_SCHEME_HTTPS;
    req.input.authority = authority;
    req.input.path = h2o_iovec_init(H2O_STRLIT("/"));
    h2o_add_header(&req.pool, &req.headers, H2O_TOKEN_USER_AGENT, NULL, user_agent.base, user_agent.len);
    h2o_add_header(&req.pool, &req.headers, H2O_TOKEN_ACCEPT, NULL, accept_root.base, accept_root.len);
    h2o_add_header(&req.pool, &req.headers, H2O_TOKEN_ACCEPT_LANGUAGE, NULL, accept_language.base, accept_language.len);
    h2o_add_header(&req.pool, &req.headers, H2O_TOKEN_ACCEPT_ENCODING, NULL, accept_encoding.base, accept_encoding.len);

    /* serialize, deserialize, and compare */
    h2o_hpack_flatten_push_promise(&buf, &encode_table, 0, 16384, req.input.scheme, req.input.authority, req.input.method,
                                   req.input.path, req.headers.entries, req.headers.size, 0);
    parse_and_compare_request(&decode_table, buf->bytes, buf->size, method, &H2O_URL_SCHEME_HTTPS, authority,
                              h2o_iovec_init(H2O_STRLIT("/")), H2O_TOKEN_USER_AGENT->buf, user_agent, H2O_TOKEN_ACCEPT->buf,
                              accept_root, H2O_TOKEN_ACCEPT_LANGUAGE->buf, accept_language, H2O_TOKEN_ACCEPT_ENCODING->buf,
                              accept_encoding, (h2o_iovec_t){NULL});
    h2o_buffer_consume(&buf, buf->size);

    /* setup second request */
    req.input.path = h2o_iovec_init(H2O_STRLIT("/banner.jpg"));
    req.headers = (h2o_headers_t){NULL};
    h2o_add_header(&req.pool, &req.headers, H2O_TOKEN_USER_AGENT, NULL, user_agent.base, user_agent.len);
    h2o_add_header(&req.pool, &req.headers, H2O_TOKEN_ACCEPT, NULL, accept_images.base, accept_images.len);
    h2o_add_header(&req.pool, &req.headers, H2O_TOKEN_ACCEPT_LANGUAGE, NULL, accept_language.base, accept_language.len);
    h2o_add_header(&req.pool, &req.headers, H2O_TOKEN_ACCEPT_ENCODING, NULL, accept_encoding.base, accept_encoding.len);
    h2o_add_header(&req.pool, &req.headers, H2O_TOKEN_REFERER, NULL, referer.base, referer.len);

    /* serialize, deserialize, and compare */
    h2o_hpack_flatten_push_promise(&buf, &encode_table, 0, 16384, req.input.scheme, req.input.authority, req.input.method,
                                   req.input.path, req.headers.entries, req.headers.size, 0);
    parse_and_compare_request(
        &decode_table, buf->bytes, buf->size, method, &H2O_URL_SCHEME_HTTPS, authority, h2o_iovec_init(H2O_STRLIT("/banner.jpg")),
        H2O_TOKEN_USER_AGENT->buf, user_agent, H2O_TOKEN_ACCEPT->buf, accept_images, H2O_TOKEN_ACCEPT_LANGUAGE->buf,
        accept_language, H2O_TOKEN_ACCEPT_ENCODING->buf, accept_encoding, H2O_TOKEN_REFERER->buf, referer, (h2o_iovec_t){NULL});
    h2o_buffer_consume(&buf, buf->size);

    /* setup third request (headers are the same) */
    req.input.path = h2o_iovec_init(H2O_STRLIT("/icon.png"));

    /* serialize, deserialize, and compare */
    h2o_hpack_flatten_push_promise(&buf, &encode_table, 0, 16384, req.input.scheme, req.input.authority, req.input.method,
                                   req.input.path, req.headers.entries, req.headers.size, 0);
    parse_and_compare_request(&decode_table, buf->bytes, buf->size, method, &H2O_URL_SCHEME_HTTPS, authority,
                              h2o_iovec_init(H2O_STRLIT("/icon.png")), H2O_TOKEN_USER_AGENT->buf, user_agent, H2O_TOKEN_ACCEPT->buf,
                              accept_images, H2O_TOKEN_ACCEPT_LANGUAGE->buf, accept_language, H2O_TOKEN_ACCEPT_ENCODING->buf,
                              accept_encoding, H2O_TOKEN_REFERER->buf, referer, (h2o_iovec_t){NULL});
    h2o_buffer_consume(&buf, buf->size);

    h2o_buffer_dispose(&buf);
    h2o_mem_clear_pool(&req.pool);
}

static void test_hpack_dynamic_table(void)
{
    h2o_hpack_header_table_t header_table;
    uint8_t encoded[256], *p;
    h2o_iovec_t n, v;

    memset(&header_table, 0, sizeof(header_table));
    header_table.hpack_capacity = 4096;

    p = encoded;
    /* expected: literal header with incremental indexing (name not indexed) */
    n = h2o_iovec_init(H2O_STRLIT("x-name"));
    v = h2o_iovec_init(H2O_STRLIT("v1"));
    p = do_encode_header(&header_table, p, &n, &v, 0);
    /* expected: literal header with incremental indexing (name indexed) */
    v = h2o_iovec_init(H2O_STRLIT("v2"));
    p = do_encode_header(&header_table, p, &n, &v, 0);
    /* expected: literal header with incremental indexing (name indexed, referring to the name associated with v2) */
    v = h2o_iovec_init(H2O_STRLIT("v3"));
    p = do_encode_header(&header_table, p, &n, &v, 0);
    /* expected: indexed header field */
    v = h2o_iovec_init(H2O_STRLIT("v1"));
    p = do_encode_header(&header_table, p, &n, &v, 0);

    const h2o_iovec_t expected = h2o_iovec_init(
        H2O_STRLIT("\x40\x85"             /* literal header with incremental indexing (name not indexed, 5 bytes, huffman coded) */
                   "\xf2\xb5\x43\xa4\xbf" /* "x-name" */
                   "\x02"                 /* value not compressed, 2 bytes */
                   "v1"                   /* "v1" */
                   "\x7e"                 /* literal header with incremental indexing (name indexed) */
                   "\x02"                 /* value not compressed, 2 bytes */
                   "v2"                   /* "v2" */
                   "\x7e"                 /* literal header with incremental indexing (name indexed, referring to the last entry) */
                   "\x02"                 /* value not compressed, 2 bytes */
                   "v3"                   /* "v3" */
                   "\xc0"                 /* indexed header field */
                   ));
    ok(p - encoded == expected.len);
    ok(memcmp(encoded, expected.base, expected.len) == 0);
}

static void test_token_wo_hpack_id(void)
{
    h2o_mem_pool_t pool;
    h2o_mem_init_pool(&pool);
    h2o_hpack_header_table_t table = {NULL};
    table.hpack_capacity = 4096;
    h2o_res_t res = {0};
    h2o_buffer_t *buf;
    h2o_buffer_init(&buf, &h2o_socket_buffer_prototype);

    res.status = 200;
    res.reason = "OK";
    h2o_add_header(&pool, &res.headers, H2O_TOKEN_TE, NULL, H2O_STRLIT("test"));

    h2o_hpack_flatten_response(&buf, &table, 1, H2O_HTTP2_SETTINGS_DEFAULT.max_frame_size, res.status, res.headers.entries,
                               res.headers.size, NULL, SIZE_MAX);
    ok(h2o_memis(buf->bytes + 9, buf->size - 9,
                 H2O_STRLIT("\x88"     /* :status:200 */
                            "\x40\x02" /* literal header w. incremental indexing, raw, TE */
                            "te"
                            "\x83" /* header value, huffman */
                            "IP\x9f" /* test */)));
    h2o_buffer_consume(&buf, buf->size);
    h2o_hpack_flatten_response(&buf, &table, 1, H2O_HTTP2_SETTINGS_DEFAULT.max_frame_size, res.status, res.headers.entries,
                               res.headers.size, NULL, SIZE_MAX);
    ok(h2o_memis(buf->bytes + 9, buf->size - 9,
                 H2O_STRLIT("\x88" /* :status:200 */
                            "\xbe" /* te: test, indexed */)));

    h2o_buffer_dispose(&buf);
    h2o_hpack_dispose_header_table(&table);
    h2o_mem_clear_pool(&pool);
}

static void do_test_inherit_invalid(h2o_iovec_t first_input, h2o_iovec_t second_input, h2o_iovec_t expected_name,
                                    h2o_iovec_t expected_first_value, const char *expected_first_err_desc,
                                    h2o_iovec_t expected_second_value, const char *expected_second_err_desc)
{
    h2o_mem_pool_t pool;
    h2o_hpack_header_table_t table = {.hpack_capacity = 4096};

    h2o_mem_init_pool(&pool);

    { /* add header with invalid name, valid value */
        int status;
        h2o_headers_t headers = {};
        const char *err_desc = NULL;
        int ret = h2o_hpack_parse_response(&pool, h2o_hpack_decode_header, &table, &status, &headers,
                                           (const uint8_t *)first_input.base, first_input.len, &err_desc);
        ok(ret == H2O_HTTP2_ERROR_INVALID_HEADER_CHAR);
        ok(err_desc == expected_first_err_desc);
        ok(status == 200);
        ok(headers.size == 1);
        ok(h2o_memis(headers.entries[0].name->base, headers.entries[0].name->len, expected_name.base, expected_name.len));
        ok(h2o_memis(headers.entries[0].value.base, headers.entries[0].value.len, expected_first_value.base,
                     expected_first_value.len));
    }

    { /* check that the invalid_name is inherited */
        int status;
        h2o_headers_t headers = {};
        const char *err_desc = NULL;
        int ret = h2o_hpack_parse_response(&pool, h2o_hpack_decode_header, &table, &status, &headers,
                                           (const uint8_t *)second_input.base, second_input.len, &err_desc);
        if (expected_second_err_desc == NULL) {
            ok(ret == 0);
        } else {
            ok(ret == H2O_HTTP2_ERROR_INVALID_HEADER_CHAR);
            ok(err_desc == expected_second_err_desc);
        }
        ok(status == 200);
        ok(headers.size == 1);
        ok(h2o_memis(headers.entries[0].name->base, headers.entries[0].name->len, expected_name.base, expected_name.len));
        ok(h2o_memis(headers.entries[0].value.base, headers.entries[0].value.len, expected_second_value.base,
                     expected_second_value.len));
    }

    h2o_mem_clear_pool(&pool);
}

static void test_inherit_invalid(void)
{
    { /* inherit invalid name */
        static const uint8_t first_input[] = {
            0x88,                           /* :status: 200 */
            0x40, 3, 'a', '\n', 'b', 1, '0' /* a\nb: 0 */
        };
        static const uint8_t second_input[] = {
            0x88,        /* :status: 200 */
            0x7e, 1, '1' /* a\nb: 1 */
        };
        do_test_inherit_invalid(h2o_iovec_init(first_input, sizeof(first_input)),
                                h2o_iovec_init(second_input, sizeof(second_input)), h2o_iovec_init(H2O_STRLIT("a\nb")),
                                h2o_iovec_init(H2O_STRLIT("0")), h2o_hpack_soft_err_found_invalid_char_in_header_name,
                                h2o_iovec_init(H2O_STRLIT("1")), h2o_hpack_soft_err_found_invalid_char_in_header_name);
    }

    { /* inherit invalid name & value */
        static const uint8_t first_input[] = {
            0x88,                                      /* :status: 200 */
            0x40, 3, 'a', '\n', 'b', 3, '0', '\n', '1' /* a\nb: 0\n1 */
        };
        static const uint8_t second_input[] = {
            0x88,        /* :status: 200 */
            0x7e, 1, '1' /* a\nb: 1 */
        };
        do_test_inherit_invalid(h2o_iovec_init(first_input, sizeof(first_input)),
                                h2o_iovec_init(second_input, sizeof(second_input)), h2o_iovec_init(H2O_STRLIT("a\nb")),
                                h2o_iovec_init(H2O_STRLIT("0\n1")), h2o_hpack_soft_err_found_invalid_char_in_header_name,
                                h2o_iovec_init(H2O_STRLIT("1")), h2o_hpack_soft_err_found_invalid_char_in_header_name);
    }

    { /* do not inherit invalid value */
        static const uint8_t first_input[] = {
            0x88,                           /* :status: 200 */
            0x40, 1, 'a', 3, '0', '\n', '1' /* a: 0\n1 */
        };
        static const uint8_t second_input[] = {
            0x88,        /* :status: 200 */
            0x7e, 1, '1' /* a: 1 */
        };
        do_test_inherit_invalid(h2o_iovec_init(first_input, sizeof(first_input)),
                                h2o_iovec_init(second_input, sizeof(second_input)), h2o_iovec_init(H2O_STRLIT("a")),
                                h2o_iovec_init(H2O_STRLIT("0\n1")), h2o_hpack_soft_err_found_invalid_char_in_header_value,
                                h2o_iovec_init(H2O_STRLIT("1")), NULL);
    }
}

void test_lib__http2__hpack(void)
{
    subtest("hpack", test_hpack);
    subtest("hpack-push", test_hpack_push);
    subtest("hpack-dynamic-table", test_hpack_dynamic_table);
    subtest("token-wo-hpack-id", test_token_wo_hpack_id);
    subtest("inherit-invalid", test_inherit_invalid);
}
