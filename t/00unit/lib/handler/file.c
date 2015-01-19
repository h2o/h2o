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
#include "../../../../lib/handler/file.c"

static int check_header(h2o_res_t *res, const h2o_token_t *header_name, const char *expected)
{
    size_t index = h2o_find_header(&res->headers, header_name, SIZE_MAX);
    if (index == SIZE_MAX)
        return 0;
    return h2o_lcstris(res->headers.entries[index].value.base, res->headers.entries[index].value.len, expected, strlen(expected));
}

void test_lib__file_c()
{
    h2o_globalconf_t globalconf;
    h2o_hostconf_t *hostconf;
    h2o_pathconf_t *pathconf;
    h2o_context_t ctx;

    h2o_config_init(&globalconf);
    hostconf = h2o_config_register_host(&globalconf, "default");
    pathconf = h2o_config_register_path(hostconf, "/");
    h2o_file_register(pathconf, "t/00unit/assets", NULL, NULL, 0);

    h2o_context_init(&ctx, test_loop, &globalconf);

    {
        h2o_loopback_conn_t *conn = h2o_loopback_create(&ctx);
        conn->req.method = h2o_iovec_init(H2O_STRLIT("HEAD"));
        conn->req.path = h2o_iovec_init(H2O_STRLIT("/"));
        h2o_loopback_run_loop(conn);
        ok(conn->req.res.status == 200);
        ok(check_header(&conn->req.res, H2O_TOKEN_CONTENT_TYPE, "text/html"));
        ok(conn->body->size == 0);
        h2o_loopback_destroy(conn);
    }
    {
        h2o_loopback_conn_t *conn = h2o_loopback_create(&ctx);
        conn->req.method = h2o_iovec_init(H2O_STRLIT("GET"));
        conn->req.path = h2o_iovec_init(H2O_STRLIT("/"));
        h2o_loopback_run_loop(conn);
        ok(conn->req.res.status == 200);
        ok(check_header(&conn->req.res, H2O_TOKEN_CONTENT_TYPE, "text/html"));
        ok(h2o_memis(conn->body->bytes, conn->body->size, H2O_STRLIT("hello html\n")));
        h2o_loopback_destroy(conn);
    }
    {
        h2o_loopback_conn_t *conn = h2o_loopback_create(&ctx);
        conn->req.method = h2o_iovec_init(H2O_STRLIT("HEAD"));
        conn->req.path = h2o_iovec_init(H2O_STRLIT("/index.html"));
        h2o_loopback_run_loop(conn);
        ok(conn->req.res.status == 200);
        ok(check_header(&conn->req.res, H2O_TOKEN_CONTENT_TYPE, "text/html"));
        ok(conn->body->size == 0);
        h2o_loopback_destroy(conn);
    }
    {
        h2o_loopback_conn_t *conn = h2o_loopback_create(&ctx);
        conn->req.method = h2o_iovec_init(H2O_STRLIT("GET"));
        conn->req.path = h2o_iovec_init(H2O_STRLIT("/index.html"));
        h2o_loopback_run_loop(conn);
        ok(conn->req.res.status == 200);
        ok(check_header(&conn->req.res, H2O_TOKEN_CONTENT_TYPE, "text/html"));
        ok(h2o_memis(conn->body->bytes, conn->body->size, H2O_STRLIT("hello html\n")));
        h2o_loopback_destroy(conn);
    }
    {
        h2o_loopback_conn_t *conn = h2o_loopback_create(&ctx);
        conn->req.method = h2o_iovec_init(H2O_STRLIT("GET"));
        conn->req.path = h2o_iovec_init(H2O_STRLIT("/1000.txt"));
        h2o_loopback_run_loop(conn);
        ok(conn->req.res.status == 200);
        ok(check_header(&conn->req.res, H2O_TOKEN_CONTENT_TYPE, "text/plain"));
        ok(conn->body->size == 1000);
        ok(strcmp(sha1sum(conn->body->bytes, conn->body->size), "dfd3ae1f5c475555fad62efe42e07309fa45f2ed") == 0);
        h2o_loopback_destroy(conn);
    }
    {
        h2o_loopback_conn_t *conn = h2o_loopback_create(&ctx);
        conn->req.method = h2o_iovec_init(H2O_STRLIT("GET"));
        conn->req.path = h2o_iovec_init(H2O_STRLIT("/1000000.txt"));
        h2o_loopback_run_loop(conn);
        ok(conn->req.res.status == 200);
        ok(check_header(&conn->req.res, H2O_TOKEN_CONTENT_TYPE, "text/plain"));
        ok(conn->body->size == 1000000);
        ok(strcmp(sha1sum(conn->body->bytes, conn->body->size), "00c8ab71d0914dce6a1ec2eaa0fda0df7044b2a2") == 0);
        h2o_loopback_destroy(conn);
    }
    {
        h2o_loopback_conn_t *conn = h2o_loopback_create(&ctx);
        conn->req.method = h2o_iovec_init(H2O_STRLIT("HEAD"));
        conn->req.path = h2o_iovec_init(H2O_STRLIT("/index_txt/"));
        h2o_loopback_run_loop(conn);
        ok(conn->req.res.status == 200);
        ok(check_header(&conn->req.res, H2O_TOKEN_CONTENT_TYPE, "text/plain"));
        ok(conn->body->size == 0);
        h2o_loopback_destroy(conn);
    }
    {
        h2o_loopback_conn_t *conn = h2o_loopback_create(&ctx);
        conn->req.method = h2o_iovec_init(H2O_STRLIT("GET"));
        conn->req.path = h2o_iovec_init(H2O_STRLIT("/index_txt/"));
        h2o_loopback_run_loop(conn);
        ok(conn->req.res.status == 200);
        ok(check_header(&conn->req.res, H2O_TOKEN_CONTENT_TYPE, "text/plain"));
        ok(h2o_memis(conn->body->bytes, conn->body->size, H2O_STRLIT("hello text\n")));
        h2o_loopback_destroy(conn);
    }
    {
        h2o_loopback_conn_t *conn = h2o_loopback_create(&ctx);
        conn->req.method = h2o_iovec_init(H2O_STRLIT("HEAD"));
        conn->req.path = h2o_iovec_init(H2O_STRLIT("/index_txt"));
        h2o_loopback_run_loop(conn);
        ok(conn->req.res.status == 301);
        ok(check_header(&conn->req.res, H2O_TOKEN_LOCATION, "http://default/index_txt/"));
        ok(conn->body->size == 0);
        h2o_loopback_destroy(conn);
    }
    {
        h2o_loopback_conn_t *conn = h2o_loopback_create(&ctx);
        conn->req.method = h2o_iovec_init(H2O_STRLIT("GET"));
        conn->req.path = h2o_iovec_init(H2O_STRLIT("/index_txt"));
        h2o_loopback_run_loop(conn);
        ok(conn->req.res.status == 301);
        ok(check_header(&conn->req.res, H2O_TOKEN_LOCATION, "http://default/index_txt/"));
        h2o_loopback_destroy(conn);
    }
    {
        h2o_loopback_conn_t *conn = h2o_loopback_create(&ctx);
        conn->req.method = h2o_iovec_init(H2O_STRLIT("HEAD"));
        conn->req.path = h2o_iovec_init(H2O_STRLIT("/index_txt_as_dir/"));
        h2o_loopback_run_loop(conn);
        ok(conn->req.res.status == 301);
        ok(check_header(&conn->req.res, H2O_TOKEN_LOCATION, "http://default/index_txt_as_dir/index.txt/"));
        ok(conn->body->size == 0);
        h2o_loopback_destroy(conn);
    }
    {
        h2o_loopback_conn_t *conn = h2o_loopback_create(&ctx);
        conn->req.method = h2o_iovec_init(H2O_STRLIT("GET"));
        conn->req.path = h2o_iovec_init(H2O_STRLIT("/index_txt_as_dir/"));
        h2o_loopback_run_loop(conn);
        ok(conn->req.res.status == 301);
        ok(check_header(&conn->req.res, H2O_TOKEN_LOCATION, "http://default/index_txt_as_dir/index.txt/"));
        h2o_loopback_destroy(conn);
    }

    h2o_context_dispose(&ctx);
    h2o_config_dispose(&globalconf);
}
