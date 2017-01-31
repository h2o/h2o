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
#include <string.h>
#include "../../test.h"
#include "../../../../lib/core/util.c"

static void test_parse_proxy_line(void)
{
    char in[256];
    struct sockaddr_storage sa;
    socklen_t salen;
    ssize_t ret;

    strcpy(in, "");
    ret = parse_proxy_line(in, strlen(in), (void *)&sa, &salen);
    ok(ret == -2);

    strcpy(in, "PROXY TCP4 192.168.0.1 192.168.0.11 56324 443\r\nabc");
    ret = parse_proxy_line(in, strlen(in), (void *)&sa, &salen);
    ok(ret == strlen(in) - 3);
    ok(salen == sizeof(struct sockaddr_in));
    ok(sa.ss_family == AF_INET);
    ok(((struct sockaddr_in *)&sa)->sin_addr.s_addr == htonl(0xc0a80001));
    ok(((struct sockaddr_in *)&sa)->sin_port == htons(56324));

    strcpy(in, "PROXY TCP4 192.168.0.1 192.168.0.11 56324 443\r");
    ret = parse_proxy_line(in, strlen(in), (void *)&sa, &salen);
    ok(ret == -2);

    strcpy(in, "PROXY TCP5");
    ret = parse_proxy_line(in, strlen(in), (void *)&sa, &salen);
    ok(ret == -1);

    strcpy(in, "PROXY UNKNOWN");
    ret = parse_proxy_line(in, strlen(in), (void *)&sa, &salen);
    ok(ret == -2);

    strcpy(in, "PROXY UNKNOWN\r\nabc");
    ret = parse_proxy_line(in, strlen(in), (void *)&sa, &salen);
    ok(ret == strlen(in) - 3);
    ok(salen == 0);

    strcpy(in, "PROXY TCP6 ::1 ::1 56324 443\r\n");
    ret = parse_proxy_line(in, strlen(in), (void *)&sa, &salen);
    ok(ret == strlen(in));
    ok(salen == sizeof(struct sockaddr_in6));
    ok(sa.ss_family == AF_INET6);
    ok(memcmp(&((struct sockaddr_in6 *)&sa)->sin6_addr, H2O_STRLIT("\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\1")) == 0);
    ok(((struct sockaddr_in6 *)&sa)->sin6_port == htons(56324));
}

static void test_extract_push_path_from_link_header(void)
{
    h2o_mem_pool_t pool;
    h2o_iovec_vector_t paths;
    h2o_iovec_t path;
    h2o_iovec_t filtered_value;
    h2o_iovec_t base_path = {H2O_STRLIT("/basepath/")}, input_authority = {H2O_STRLIT("basehost")},
                other_authority = {H2O_STRLIT("otherhost")};
#define INPUT base_path, &H2O_URL_SCHEME_HTTP, input_authority
    h2o_mem_init_pool(&pool);
    h2o_iovec_t value;

    value = h2o_iovec_init(H2O_STRLIT("<http://basehost/otherpath>; rel=preload"));
    paths = h2o_extract_push_path_from_link_header(&pool, value.base, value.len, INPUT, NULL, NULL, &filtered_value);
    ok(paths.size == 1);
    path = paths.entries[0];
    ok(h2o_memis(path.base, path.len, H2O_STRLIT("/otherpath")));
    ok(h2o_memis(value.base, value.len, filtered_value.base, filtered_value.len));

    value = h2o_iovec_init(H2O_STRLIT("</otherpath>; rel=preload"));
    paths = h2o_extract_push_path_from_link_header(&pool, value.base, value.len, INPUT, NULL, NULL, &filtered_value);
    ok(paths.size == 1);
    path = paths.entries[0];
    ok(h2o_memis(path.base, path.len, H2O_STRLIT("/otherpath")));
    ok(h2o_memis(value.base, value.len, filtered_value.base, filtered_value.len));

    value = h2o_iovec_init(H2O_STRLIT("<otherpath>; rel=preload"));
    paths = h2o_extract_push_path_from_link_header(&pool, value.base, value.len, INPUT, NULL, NULL, &filtered_value);
    ok(paths.size == 1);
    path = paths.entries[0];
    ok(h2o_memis(path.base, path.len, H2O_STRLIT("/basepath/otherpath")));
    ok(h2o_memis(value.base, value.len, filtered_value.base, filtered_value.len));

    value = h2o_iovec_init(H2O_STRLIT("<../otherpath>; rel=preload"));
    paths = h2o_extract_push_path_from_link_header(&pool, value.base, value.len, INPUT, NULL, NULL, &filtered_value);
    ok(paths.size == 1);
    path = paths.entries[0];
    ok(h2o_memis(path.base, path.len, H2O_STRLIT("/otherpath")));
    ok(h2o_memis(value.base, value.len, filtered_value.base, filtered_value.len));

    value = h2o_iovec_init(H2O_STRLIT("<http:otherpath>; rel=preload"));
    paths = h2o_extract_push_path_from_link_header(&pool, value.base, value.len, INPUT, NULL, NULL, &filtered_value);
    ok(paths.size == 1);
    path = paths.entries[0];
    ok(h2o_memis(path.base, path.len, H2O_STRLIT("/basepath/otherpath")));
    ok(h2o_memis(value.base, value.len, filtered_value.base, filtered_value.len));

    value = h2o_iovec_init(H2O_STRLIT("<../otherpath>; rel=author"));
    paths = h2o_extract_push_path_from_link_header(&pool, value.base, value.len, INPUT, NULL, NULL, &filtered_value);
    ok(paths.size == 0);
    ok(h2o_memis(value.base, value.len, filtered_value.base, filtered_value.len));

    value = h2o_iovec_init(H2O_STRLIT("<http://basehost:81/otherpath>; rel=preload"));
    paths = h2o_extract_push_path_from_link_header(&pool, value.base, value.len, INPUT, NULL, NULL, &filtered_value);
    ok(paths.size == 0);
    ok(h2o_memis(value.base, value.len, filtered_value.base, filtered_value.len));

    value = h2o_iovec_init(H2O_STRLIT("<https://basehost/otherpath>; rel=preload"));
    paths = h2o_extract_push_path_from_link_header(&pool, value.base, value.len, INPUT, NULL, NULL, &filtered_value);
    ok(paths.size == 0);
    ok(h2o_memis(value.base, value.len, filtered_value.base, filtered_value.len));

    value = h2o_iovec_init(H2O_STRLIT("<https:otherpath>; rel=preload"));
    paths = h2o_extract_push_path_from_link_header(&pool, value.base, value.len, INPUT, NULL, NULL, &filtered_value);
    ok(paths.size == 0);
    ok(h2o_memis(value.base, value.len, filtered_value.base, filtered_value.len));

    value = h2o_iovec_init(H2O_STRLIT("</otherpath>; rel=preload"));
    paths = h2o_extract_push_path_from_link_header(&pool, value.base, value.len, INPUT, &H2O_URL_SCHEME_HTTPS, &input_authority,
                                                   &filtered_value);
    ok(paths.size == 0);
    ok(h2o_memis(value.base, value.len, filtered_value.base, filtered_value.len));

    value = h2o_iovec_init(H2O_STRLIT("</otherpath>; rel=preload"));
    paths = h2o_extract_push_path_from_link_header(&pool, value.base, value.len, INPUT, &H2O_URL_SCHEME_HTTP, &input_authority,
                                                   &filtered_value);
    ok(paths.size == 1);
    path = paths.entries[0];
    ok(h2o_memis(path.base, path.len, H2O_STRLIT("/otherpath")));
    ok(h2o_memis(value.base, value.len, filtered_value.base, filtered_value.len));

    value = h2o_iovec_init(H2O_STRLIT("</otherpath>; rel=preload"));
    paths = h2o_extract_push_path_from_link_header(&pool, value.base, value.len, INPUT, &H2O_URL_SCHEME_HTTP, &other_authority,
                                                   &filtered_value);
    ok(paths.entries == 0);
    ok(h2o_memis(value.base, value.len, filtered_value.base, filtered_value.len));

    value = h2o_iovec_init(H2O_STRLIT("<http://basehost/otherpath>; rel=preload"));
    paths = h2o_extract_push_path_from_link_header(&pool, value.base, value.len, INPUT, &H2O_URL_SCHEME_HTTP, &other_authority,
                                                   &filtered_value);
    ok(paths.size == 1);
    path = paths.entries[0];
    ok(h2o_memis(path.base, path.len, H2O_STRLIT("/otherpath")));
    ok(h2o_memis(value.base, value.len, filtered_value.base, filtered_value.len));

    value = h2o_iovec_init(H2O_STRLIT("<http:otherpath>; rel=preload; nopush"));
    paths = h2o_extract_push_path_from_link_header(&pool, value.base, value.len, INPUT, NULL, NULL, &filtered_value);
    ok(paths.entries == 0);
    ok(h2o_memis(value.base, value.len, filtered_value.base, filtered_value.len));

    value = h2o_iovec_init(H2O_STRLIT("</firstpath>; rel=preload, </secondpath>; rel=preload"));
    paths = h2o_extract_push_path_from_link_header(&pool, value.base, value.len, INPUT, &H2O_URL_SCHEME_HTTP, &input_authority,
                                                   &filtered_value);
    ok(paths.size == 2);
    path = paths.entries[0];
    ok(h2o_memis(path.base, path.len, H2O_STRLIT("/firstpath")));
    path = paths.entries[1];
    ok(h2o_memis(path.base, path.len, H2O_STRLIT("/secondpath")));
    ok(h2o_memis(value.base, value.len, filtered_value.base, filtered_value.len));

    value = h2o_iovec_init(H2O_STRLIT("</firstpath>; rel=preload; nopush, </secondpath>; rel=preload"));
    paths = h2o_extract_push_path_from_link_header(&pool, value.base, value.len, INPUT, &H2O_URL_SCHEME_HTTP, &input_authority,
                                                   &filtered_value);
    ok(paths.size == 1);
    path = paths.entries[0];
    ok(h2o_memis(path.base, path.len, H2O_STRLIT("/secondpath")));
    ok(h2o_memis(value.base, value.len, filtered_value.base, filtered_value.len));

    value = h2o_iovec_init(H2O_STRLIT("</firstpath>; rel=preload; nopush, </secondpath>; nopush; rel=preload; </thirdpath>"));
    paths = h2o_extract_push_path_from_link_header(&pool, value.base, value.len, INPUT, &H2O_URL_SCHEME_HTTP, &input_authority,
                                                   &filtered_value);
    ok(paths.size == 0);
    ok(h2o_memis(value.base, value.len, filtered_value.base, filtered_value.len));

    value = h2o_iovec_init(H2O_STRLIT("</firstpath>; rel=preload; nopush, <secondpath>; rel=notpreload"));
    paths = h2o_extract_push_path_from_link_header(&pool, value.base, value.len, INPUT, &H2O_URL_SCHEME_HTTP, &input_authority,
                                                   &filtered_value);
    ok(paths.size == 0);
    ok(h2o_memis(value.base, value.len, filtered_value.base, filtered_value.len));

    value = h2o_iovec_init(H2O_STRLIT("</firstpath>; rel=preload, </secondpath>; rel=preload; nopush, </thirdpath>; rel=preload"));
    paths = h2o_extract_push_path_from_link_header(&pool, value.base, value.len, INPUT, &H2O_URL_SCHEME_HTTP, &input_authority,
                                                   &filtered_value);
    ok(paths.size == 2);
    path = paths.entries[0];
    ok(h2o_memis(path.base, path.len, H2O_STRLIT("/firstpath")));
    path = paths.entries[1];
    ok(h2o_memis(path.base, path.len, H2O_STRLIT("/thirdpath")));
    ok(h2o_memis(value.base, value.len, filtered_value.base, filtered_value.len));

    value = h2o_iovec_init(H2O_STRLIT("hogefoo"));
    paths = h2o_extract_push_path_from_link_header(&pool, value.base, value.len, INPUT, &H2O_URL_SCHEME_HTTP, &input_authority,
                                                   &filtered_value);
    ok(paths.size == 0);
    ok(h2o_memis(value.base, value.len, filtered_value.base, filtered_value.len));

    h2o_mem_clear_pool(&pool);
#undef INPUT
}

static void test_extract_push_path_from_link_header_push_only(void)
{
    h2o_mem_pool_t pool;
    h2o_iovec_vector_t paths;
    h2o_iovec_t path;
    h2o_iovec_t filtered_value;
    h2o_iovec_t base_path = {H2O_STRLIT("/basepath/")}, input_authority = {H2O_STRLIT("basehost")};
#define INPUT base_path, &H2O_URL_SCHEME_HTTP, input_authority
    h2o_mem_init_pool(&pool);
    h2o_iovec_t value;

    value = h2o_iovec_init(H2O_STRLIT("</firstpath>; rel=preload, </secondpath>; rel=preload; nopush, </thirdpath>; rel=preload, "
                                      "</fourthpath>; rel=preload; x-http2-push-only"));
    paths = h2o_extract_push_path_from_link_header(&pool, value.base, value.len, INPUT, &H2O_URL_SCHEME_HTTP, &input_authority,
                                                   &filtered_value);
    ok(paths.size == 3);
    path = paths.entries[0];
    ok(h2o_memis(path.base, path.len, H2O_STRLIT("/firstpath")));
    path = paths.entries[1];
    ok(h2o_memis(path.base, path.len, H2O_STRLIT("/thirdpath")));
    path = paths.entries[2];
    ok(h2o_memis(path.base, path.len, H2O_STRLIT("/fourthpath")));
    value = h2o_iovec_init(H2O_STRLIT("</firstpath>; rel=preload, </secondpath>; rel=preload; nopush, </thirdpath>; rel=preload"));
    ok(h2o_memis(value.base, value.len, filtered_value.base, filtered_value.len));

    value = h2o_iovec_init(H2O_STRLIT("</firstpath>; rel=preload; x-http2-push-only, </secondpath>; rel=preload; nopush, "
                                      "</thirdpath>; rel=preload, </fourthpath>; rel=preload; x-http2-push-only"));
    paths = h2o_extract_push_path_from_link_header(&pool, value.base, value.len, INPUT, &H2O_URL_SCHEME_HTTP, &input_authority,
                                                   &filtered_value);
    ok(paths.size == 3);
    path = paths.entries[0];
    ok(h2o_memis(path.base, path.len, H2O_STRLIT("/firstpath")));
    path = paths.entries[1];
    ok(h2o_memis(path.base, path.len, H2O_STRLIT("/thirdpath")));
    path = paths.entries[2];
    ok(h2o_memis(path.base, path.len, H2O_STRLIT("/fourthpath")));
    value = h2o_iovec_init(H2O_STRLIT("</secondpath>; rel=preload; nopush, </thirdpath>; rel=preload"));
    ok(h2o_memis(value.base, value.len, filtered_value.base, filtered_value.len));

    value = h2o_iovec_init(H2O_STRLIT("</firstpath>; rel=preload, </secondpath>; rel=preload; x-http2-push-only, </thirdpath>; "
                                      "rel=preload; nopush, </fourthpath>; rel=preload; x-http2-push-only"));
    paths = h2o_extract_push_path_from_link_header(&pool, value.base, value.len, INPUT, &H2O_URL_SCHEME_HTTP, &input_authority,
                                                   &filtered_value);
    ok(paths.size == 3);
    path = paths.entries[0];
    ok(h2o_memis(path.base, path.len, H2O_STRLIT("/firstpath")));
    path = paths.entries[1];
    ok(h2o_memis(path.base, path.len, H2O_STRLIT("/secondpath")));
    path = paths.entries[2];
    ok(h2o_memis(path.base, path.len, H2O_STRLIT("/fourthpath")));
    value = h2o_iovec_init(H2O_STRLIT("</firstpath>; rel=preload, </thirdpath>; rel=preload; nopush"));
    ok(h2o_memis(value.base, value.len, filtered_value.base, filtered_value.len));

    value = h2o_iovec_init(H2O_STRLIT("</firstpath>; rel=preload; x-http2-push-only, </secondpath>; rel=preload, </thirdpath>; "
                                      "rel=preload; x-http2-push-only, </fourthpath>; rel=preload; nopush"));
    paths = h2o_extract_push_path_from_link_header(&pool, value.base, value.len, INPUT, &H2O_URL_SCHEME_HTTP, &input_authority,
                                                   &filtered_value);
    ok(paths.size == 3);
    path = paths.entries[0];
    ok(h2o_memis(path.base, path.len, H2O_STRLIT("/firstpath")));
    path = paths.entries[1];
    ok(h2o_memis(path.base, path.len, H2O_STRLIT("/secondpath")));
    path = paths.entries[2];
    ok(h2o_memis(path.base, path.len, H2O_STRLIT("/thirdpath")));
    value = h2o_iovec_init(H2O_STRLIT("</secondpath>; rel=preload, </fourthpath>; rel=preload; nopush"));
    ok(h2o_memis(value.base, value.len, filtered_value.base, filtered_value.len));

    value = h2o_iovec_init(
        H2O_STRLIT("</firstpath>; rel=preload; x-http2-push-only, </secondpath>; rel=preload; x-http2-push-only, </thirdpath>; "
                   "rel=preload, </fourthpath>; rel=preload; nopush"));
    paths = h2o_extract_push_path_from_link_header(&pool, value.base, value.len, INPUT, &H2O_URL_SCHEME_HTTP, &input_authority,
                                                   &filtered_value);
    ok(paths.size == 3);
    path = paths.entries[0];
    ok(h2o_memis(path.base, path.len, H2O_STRLIT("/firstpath")));
    path = paths.entries[1];
    ok(h2o_memis(path.base, path.len, H2O_STRLIT("/secondpath")));
    path = paths.entries[2];
    ok(h2o_memis(path.base, path.len, H2O_STRLIT("/thirdpath")));
    value = h2o_iovec_init(H2O_STRLIT("</thirdpath>; rel=preload, </fourthpath>; rel=preload; nopush"));
    ok(h2o_memis(value.base, value.len, filtered_value.base, filtered_value.len));

    value = h2o_iovec_init(H2O_STRLIT("firstpath; rel=preload, </secondpath>; rel=preload; x-http2-push-only, </thirdpath>; "
                                      "rel=preload; nopush, </fourthpath>; rel=preload; x-http2-push-only"));
    paths = h2o_extract_push_path_from_link_header(&pool, value.base, value.len, INPUT, &H2O_URL_SCHEME_HTTP, &input_authority,
                                                   &filtered_value);
    ok(paths.size == 0);
    ok(h2o_memis(value.base, value.len, filtered_value.base, filtered_value.len));

    value = h2o_iovec_init(H2O_STRLIT("</firstpath>; rel=preload; x-http2-push-only, bar"));
    paths = h2o_extract_push_path_from_link_header(&pool, value.base, value.len, INPUT, &H2O_URL_SCHEME_HTTP, &input_authority,
                                                   &filtered_value);
    ok(paths.size == 1);
    path = paths.entries[0];
    ok(h2o_memis(path.base, path.len, H2O_STRLIT("/firstpath")));
    ok(h2o_memis(H2O_STRLIT("bar"), filtered_value.base, filtered_value.len));

    h2o_mem_clear_pool(&pool);
}
void test_build_destination(void)
{
    h2o_pathconf_t conf_not_slashed = {NULL, {H2O_STRLIT("/abc")}}, conf_slashed = {NULL, {H2O_STRLIT("/abc/")}};
    h2o_req_t req;
    h2o_iovec_t dest;
    int escape;

    for (escape = 0; escape <= 1; escape++) {
        h2o_init_request(&req, NULL, NULL);

        note("escaping: %s", escape ? "on" : "off");
        req.path_normalized = h2o_iovec_init(H2O_STRLIT("/abc/xyz"));
        req.query_at = req.path_normalized.len;
        req.input.path = req.path = h2o_concat(&req.pool, req.path_normalized, h2o_iovec_init(H2O_STRLIT("?q")));

        /* basic pattern */
        req.pathconf = &conf_not_slashed;
        dest = h2o_build_destination(&req, H2O_STRLIT("/def"), escape);
        ok(h2o_memis(dest.base, dest.len, H2O_STRLIT("/def/xyz?q")));
        dest = h2o_build_destination(&req, H2O_STRLIT("/def/"), escape);
        ok(h2o_memis(dest.base, dest.len, H2O_STRLIT("/def/xyz?q")));
        req.pathconf = &conf_slashed;
        dest = h2o_build_destination(&req, H2O_STRLIT("/def"), escape);
        ok(h2o_memis(dest.base, dest.len, H2O_STRLIT("/def/xyz?q")));
        dest = h2o_build_destination(&req, H2O_STRLIT("/def/"), escape);
        ok(h2o_memis(dest.base, dest.len, H2O_STRLIT("/def/xyz?q")));

        /* test wo. query */
        if (escape) {
            req.pathconf = &conf_not_slashed;
            req.query_at = SIZE_MAX;
            dest = h2o_build_destination(&req, H2O_STRLIT("/def"), escape);
            ok(h2o_memis(dest.base, dest.len, H2O_STRLIT("/def/xyz")));
        }

        /* no trailing */
        req.path_normalized = h2o_iovec_init(H2O_STRLIT("/abc"));
        req.query_at = req.path_normalized.len;
        req.input.path = req.path = h2o_concat(&req.pool, req.path_normalized, h2o_iovec_init(H2O_STRLIT("?q")));

        req.pathconf = &conf_not_slashed;
        dest = h2o_build_destination(&req, H2O_STRLIT("/def"), escape);
        ok(h2o_memis(dest.base, dest.len, H2O_STRLIT("/def?q")));
        dest = h2o_build_destination(&req, H2O_STRLIT("/def/"), escape);
        ok(h2o_memis(dest.base, dest.len, H2O_STRLIT("/def/?q")));
    }

    h2o_mem_clear_pool(&req.pool);
}

void test_build_destination_escaping(void)
{
    h2o_req_t req;
    h2o_iovec_t dest;
    int escape = 0;
    int i, j;
    struct {
        char *pathconf;
        char *dest;
        char *input;
        char *output;
    } tests[] = {
        {"/abc", "/def", "/abc/xyz?query&m=n/o", "/def/xyz?query&m=n/o"},
        {"/abc", "/def", "/%61bc/xyz?query&m=n/o", "/def/xyz?query&m=n/o"},
        {"/abc", "/def", "/%61%62c/xyz?query&m=n/o", "/def/xyz?query&m=n/o"},
        {"/abc", "/def", "/%61%62%63/xyz?query&m=n/o", "/def/xyz?query&m=n/o"},
        {"/abc", "/def", "/./%61%62%63/xyz?query&m=n/o", "/def/xyz?query&m=n/o"},
        {"/abc", "/def", "/../%61%62%63/xyz?query&m=n/o", "/def/xyz?query&m=n/o"},
        {"/abc", "/def", "/././%61%62%63/xyz?query&m=n/o", "/def/xyz?query&m=n/o"},
        {"/abc", "/def", "/./.././%61%62%63/xyz?query&m=n/o", "/def/xyz?query&m=n/o"},
        {"/abc", "/def", "/./../blah/../%61%62%63/xyz?query&m=n/o", "/def/xyz?query&m=n/o"},
        {"/abc", "/def", "/./../blah/.././%61%62c/xyz?query&m=n/o", "/def/xyz?query&m=n/o"},
        {"/abc", "/def", "/./../blah/.././../../%61b%63/xyz?query&m=n/o", "/def/xyz?query&m=n/o"},
        {"/abc", "/def", "/abc/xyz/?query&m=n/o", "/def/xyz/?query&m=n/o"},
        {"/abc", "/def", "/abc/xyz/.?query&m=n/o", "/def/xyz/.?query&m=n/o"},
        {"/abc", "/def", "/abc/xyz/./?query&m=n/o", "/def/xyz/./?query&m=n/o"},
        {"/abc", "/def", "/abc/xyz/..?query&m=n/o", "/def/xyz/..?query&m=n/o"},
        {"/abc", "/def", "/abc/xyz/../?query&m=n/o", "/def/xyz/../?query&m=n/o"},
        {"/abc", "/def", "/abc/xyz/../a?query&m=n/o", "/def/xyz/../a?query&m=n/o"},
        {"/abc", "/def", "/abc/%yz/?query&m=n/o", "/def/%yz/?query&m=n/o"},
        {"/abc", "/def", "/abc/%78yz/?query&m=n/o", "/def/%78yz/?query&m=n/o"},
        {"/", "/", "/xyz/../mno", "/xyz/../mno"},
        {"/", "/", "/xyz/../mno/..", "/xyz/../mno/.."},
        {"/", "/def", "/xyz/../mno", "/def/xyz/../mno"},
        {"/", "/def/", "/xyz/../mno", "/def/xyz/../mno"},
        {"/", "/def", "/xyz/../", "/def/xyz/../"},
        {"/", "/def/", "/xyz/..", "/def/xyz/.."},
    };
    h2o_init_request(&req, NULL, NULL);

    /* 'j' runs the test with a missing leading '/' in the input path */
    for (j = 0; j <= 1; j++) {
        for (i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
            h2o_pathconf_t conf = {NULL, {tests[i].pathconf, strlen(tests[i].pathconf)}};
            req.pathconf = &conf;
            req.path = req.input.path = h2o_iovec_init(tests[i].input + j, strlen(tests[i].input) - j);
            req.norm_indexes = NULL;
            req.path_normalized = h2o_url_normalize_path(&req.pool, req.path.base, req.path.len, &req.query_at, &req.norm_indexes);
            dest = h2o_build_destination(&req, tests[i].dest, strlen(tests[i].dest), escape);
            note("%s: %d, %sskipping the leading '/'", tests[i].input, i, !j ? "not " : "");
            ok(dest.len == strlen(tests[i].output));
            ok(h2o_memis(dest.base, dest.len, tests[i].output, strlen(tests[i].output)));
        }
    }

    h2o_mem_clear_pool(&req.pool);
}

void test_lib__core__util_c()
{
    subtest("parse_proxy_line", test_parse_proxy_line);
    subtest("extract_push_path_from_link_header", test_extract_push_path_from_link_header);
    subtest("extract_push_path_from_link_header_push_only", test_extract_push_path_from_link_header_push_only);
    subtest("test_build_destination", test_build_destination);
    subtest("test_build_destination_escaping", test_build_destination_escaping);
}
