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
    h2o_iovec_t path;
    h2o_iovec_t base_path = {H2O_STRLIT("/basepath/")}, input_authority = {H2O_STRLIT("basehost")},
                other_authority = {H2O_STRLIT("otherhost")};
#define INPUT base_path, &H2O_URL_SCHEME_HTTP, input_authority
    h2o_mem_init_pool(&pool);

    path = h2o_extract_push_path_from_link_header(&pool, H2O_STRLIT("<http://basehost/otherpath>; rel=preload"), INPUT, NULL, NULL);
    ok(h2o_memis(path.base, path.len, H2O_STRLIT("/otherpath")));
    path = h2o_extract_push_path_from_link_header(&pool, H2O_STRLIT("</otherpath>; rel=preload"), INPUT, NULL, NULL);
    ok(h2o_memis(path.base, path.len, H2O_STRLIT("/otherpath")));
    path = h2o_extract_push_path_from_link_header(&pool, H2O_STRLIT("<otherpath>; rel=preload"), INPUT, NULL, NULL);
    ok(h2o_memis(path.base, path.len, H2O_STRLIT("/basepath/otherpath")));
    path = h2o_extract_push_path_from_link_header(&pool, H2O_STRLIT("<../otherpath>; rel=preload"), INPUT, NULL, NULL);
    ok(h2o_memis(path.base, path.len, H2O_STRLIT("/otherpath")));
    path = h2o_extract_push_path_from_link_header(&pool, H2O_STRLIT("<http:otherpath>; rel=preload"), INPUT, NULL, NULL);
    ok(h2o_memis(path.base, path.len, H2O_STRLIT("/basepath/otherpath")));

    path = h2o_extract_push_path_from_link_header(&pool, H2O_STRLIT("<../otherpath>; rel=author"), INPUT, NULL, NULL);
    ok(path.base == NULL);
    ok(path.len == 0);
    path =
        h2o_extract_push_path_from_link_header(&pool, H2O_STRLIT("<http://basehost:81/otherpath>; rel=preload"), INPUT, NULL, NULL);
    ok(path.base == NULL);
    ok(path.len == 0);
    path =
        h2o_extract_push_path_from_link_header(&pool, H2O_STRLIT("<https://basehost/otherpath>; rel=preload"), INPUT, NULL, NULL);
    ok(path.base == NULL);
    ok(path.len == 0);
    path = h2o_extract_push_path_from_link_header(&pool, H2O_STRLIT("<https:otherpath>; rel=preload"), INPUT, NULL, NULL);
    ok(path.base == NULL);
    ok(path.len == 0);

    path = h2o_extract_push_path_from_link_header(&pool, H2O_STRLIT("</otherpath>; rel=preload"), INPUT, &H2O_URL_SCHEME_HTTPS,
                                                  &input_authority);
    ok(path.base == NULL);
    ok(path.len == 0);
    path = h2o_extract_push_path_from_link_header(&pool, H2O_STRLIT("</otherpath>; rel=preload"), INPUT, &H2O_URL_SCHEME_HTTP,
                                                  &input_authority);
    ok(h2o_memis(path.base, path.len, H2O_STRLIT("/otherpath")));
    path = h2o_extract_push_path_from_link_header(&pool, H2O_STRLIT("</otherpath>; rel=preload"), INPUT, &H2O_URL_SCHEME_HTTP,
                                                  &other_authority);
    ok(path.base == NULL);
    ok(path.len == 0);
    path = h2o_extract_push_path_from_link_header(&pool, H2O_STRLIT("<http://basehost/otherpath>; rel=preload"), INPUT,
                                                  &H2O_URL_SCHEME_HTTP, &other_authority);
    ok(h2o_memis(path.base, path.len, H2O_STRLIT("/otherpath")));

    path = h2o_extract_push_path_from_link_header(&pool, H2O_STRLIT("<http:otherpath>; rel=preload; nopush"), INPUT, NULL, NULL);
    ok(path.base == NULL);
    ok(path.len == 0);

    h2o_mem_clear_pool(&pool);
#undef INPUT
}

void test_build_destination(void)
{
    h2o_pathconf_t conf_not_slashed = {NULL, {H2O_STRLIT("/abc")}}, conf_slashed = {NULL, {H2O_STRLIT("/abc")}};
    h2o_req_t req;
    h2o_iovec_t dest;

    h2o_init_request(&req, NULL, NULL);

    /* basic pattern */
    req.path_normalized = h2o_iovec_init(H2O_STRLIT("/abc/xyz"));
    req.query_at = req.path_normalized.len;
    req.path = h2o_concat(&req.pool, req.path_normalized, h2o_iovec_init(H2O_STRLIT("?q")));
    req.pathconf = &conf_not_slashed;
    dest = h2o_build_destination(&req, H2O_STRLIT("/def"));
    ok(h2o_memis(dest.base, dest.len, H2O_STRLIT("/def/xyz?q")));
    dest = h2o_build_destination(&req, H2O_STRLIT("/def/"));
    ok(h2o_memis(dest.base, dest.len, H2O_STRLIT("/def/xyz?q")));
    req.pathconf = &conf_slashed;
    dest = h2o_build_destination(&req, H2O_STRLIT("/def"));
    ok(h2o_memis(dest.base, dest.len, H2O_STRLIT("/def/xyz?q")));
    dest = h2o_build_destination(&req, H2O_STRLIT("/def/"));
    ok(h2o_memis(dest.base, dest.len, H2O_STRLIT("/def/xyz?q")));

    /* test wo. query */
    req.pathconf = &conf_not_slashed;
    req.query_at = SIZE_MAX;
    dest = h2o_build_destination(&req, H2O_STRLIT("/def"));
    ok(h2o_memis(dest.base, dest.len, H2O_STRLIT("/def/xyz")));

    /* no trailing */
    req.path_normalized = h2o_iovec_init(H2O_STRLIT("/abc"));
    req.query_at = req.path_normalized.len;
    req.path = h2o_concat(&req.pool, req.path_normalized, h2o_iovec_init(H2O_STRLIT("?q")));
    req.pathconf = &conf_not_slashed;
    dest = h2o_build_destination(&req, H2O_STRLIT("/def"));
    ok(h2o_memis(dest.base, dest.len, H2O_STRLIT("/def?q")));
    dest = h2o_build_destination(&req, H2O_STRLIT("/def/"));
    ok(h2o_memis(dest.base, dest.len, H2O_STRLIT("/def/?q")));

    h2o_mem_clear_pool(&req.pool);
}

void test_lib__core__util_c()
{
    subtest("parse_proxy_line", test_parse_proxy_line);
    subtest("extract_push_path_from_link_header", test_extract_push_path_from_link_header);
    subtest("test_build_destination", test_build_destination);
}
