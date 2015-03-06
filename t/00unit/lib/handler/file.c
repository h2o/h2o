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
#include <stdlib.h>
#include "../../test.h"
#include "../../../../lib/handler/file.c"

static h2o_context_t ctx;

static int check_header(h2o_res_t *res, const h2o_token_t *header_name, const char *expected)
{
    size_t index = h2o_find_header(&res->headers, header_name, SIZE_MAX);
    if (index == SIZE_MAX)
        return 0;
    return h2o_lcstris(res->headers.entries[index].value.base, res->headers.entries[index].value.len, expected, strlen(expected));
}

static void test_if_modified_since(void)
{
    char lm_date[H2O_TIMESTR_RFC1123_LEN + 1];

    { /* obtain last-modified */
        h2o_loopback_conn_t *conn = h2o_loopback_create(&ctx, ctx.globalconf->hosts);
        ssize_t lm_index;
        conn->req.input.method = h2o_iovec_init(H2O_STRLIT("GET"));
        conn->req.input.path = h2o_iovec_init(H2O_STRLIT("/"));
        h2o_loopback_run_loop(conn);
        ok(conn->req.res.status == 200);
        if ((lm_index = h2o_find_header(&conn->req.res.headers, H2O_TOKEN_LAST_MODIFIED, -1)) == -1) {
            ok(0);
            return;
        }
        ok(conn->req.res.headers.entries[lm_index].value.len == H2O_TIMESTR_RFC1123_LEN);
        memcpy(lm_date, conn->req.res.headers.entries[lm_index].value.base, H2O_TIMESTR_RFC1123_LEN);
        lm_date[H2O_TIMESTR_RFC1123_LEN] = '\0';
        h2o_loopback_destroy(conn);
    }

    { /* send if-modified-since using the obtained last-modified */
        h2o_loopback_conn_t *conn = h2o_loopback_create(&ctx, ctx.globalconf->hosts);
        conn->req.input.method = h2o_iovec_init(H2O_STRLIT("GET"));
        conn->req.input.path = h2o_iovec_init(H2O_STRLIT("/"));
        h2o_add_header(&conn->req.pool, &conn->req.headers, H2O_TOKEN_IF_MODIFIED_SINCE, lm_date, H2O_TIMESTR_RFC1123_LEN);
        h2o_loopback_run_loop(conn);
        ok(conn->req.res.status == 304);
        ok(conn->body->size == 0);
        h2o_loopback_destroy(conn);
    }

    { /* send if-modified-since using an old date */
        h2o_loopback_conn_t *conn = h2o_loopback_create(&ctx, ctx.globalconf->hosts);
        conn->req.input.method = h2o_iovec_init(H2O_STRLIT("GET"));
        conn->req.input.path = h2o_iovec_init(H2O_STRLIT("/"));
        h2o_add_header(&conn->req.pool, &conn->req.headers, H2O_TOKEN_IF_MODIFIED_SINCE,
                       H2O_STRLIT("Sun, 06 Nov 1994 08:49:37 GMT"));
        h2o_loopback_run_loop(conn);
        ok(conn->req.res.status == 200);
        h2o_loopback_destroy(conn);
    }

    { /* send if-modified-since using a date in the future */
        h2o_loopback_conn_t *conn = h2o_loopback_create(&ctx, ctx.globalconf->hosts);
        conn->req.input.method = h2o_iovec_init(H2O_STRLIT("GET"));
        conn->req.input.path = h2o_iovec_init(H2O_STRLIT("/"));
        h2o_add_header(&conn->req.pool, &conn->req.headers, H2O_TOKEN_IF_MODIFIED_SINCE,
                       H2O_STRLIT("Wed, 18 May 2033 12:33:20 GMT"));
        h2o_loopback_run_loop(conn);
        ok(conn->req.res.status == 304);
        ok(conn->body->size == 0);
        h2o_loopback_destroy(conn);
    }
}

static void test_if_match(void)
{
    h2o_iovec_t etag = {};

    { /* obtain etag */
        h2o_loopback_conn_t *conn = h2o_loopback_create(&ctx, ctx.globalconf->hosts);
        ssize_t etag_index;
        conn->req.input.method = h2o_iovec_init(H2O_STRLIT("GET"));
        conn->req.input.path = h2o_iovec_init(H2O_STRLIT("/"));
        h2o_loopback_run_loop(conn);
        ok(conn->req.res.status == 200);
        if ((etag_index = h2o_find_header(&conn->req.res.headers, H2O_TOKEN_ETAG, -1)) == -1) {
            ok(0);
            return;
        }
        etag = h2o_strdup(NULL, conn->req.res.headers.entries[etag_index].value.base,
                          conn->req.res.headers.entries[etag_index].value.len);
        h2o_loopback_destroy(conn);
    }

    { /* send if-non-match using the obtained etag */
        h2o_loopback_conn_t *conn = h2o_loopback_create(&ctx, ctx.globalconf->hosts);
        conn->req.input.method = h2o_iovec_init(H2O_STRLIT("GET"));
        conn->req.input.path = h2o_iovec_init(H2O_STRLIT("/"));
        h2o_add_header(&conn->req.pool, &conn->req.headers, H2O_TOKEN_IF_NONE_MATCH, etag.base, etag.len);
        h2o_loopback_run_loop(conn);
        ok(conn->req.res.status == 304);
        ok(conn->body->size == 0);
        h2o_loopback_destroy(conn);
    }

    free(etag.base);
}

void test_lib__handler__file_c()
{
    h2o_globalconf_t globalconf;
    h2o_hostconf_t *hostconf;
    h2o_pathconf_t *pathconf;

    h2o_config_init(&globalconf);
    hostconf = h2o_config_register_host(&globalconf, "default");
    pathconf = h2o_config_register_path(hostconf, "/");
    h2o_file_register(pathconf, "t/00unit/assets", NULL, NULL, 0);

    h2o_context_init(&ctx, test_loop, &globalconf);

    {
        h2o_loopback_conn_t *conn = h2o_loopback_create(&ctx, ctx.globalconf->hosts);
        conn->req.input.method = h2o_iovec_init(H2O_STRLIT("HEAD"));
        conn->req.input.path = h2o_iovec_init(H2O_STRLIT("/"));
        h2o_loopback_run_loop(conn);
        ok(conn->req.res.status == 200);
        ok(check_header(&conn->req.res, H2O_TOKEN_CONTENT_TYPE, "text/html"));
        ok(conn->body->size == 0);
        h2o_loopback_destroy(conn);
    }
    {
        h2o_loopback_conn_t *conn = h2o_loopback_create(&ctx, ctx.globalconf->hosts);
        conn->req.input.method = h2o_iovec_init(H2O_STRLIT("GET"));
        conn->req.input.path = h2o_iovec_init(H2O_STRLIT("/"));
        h2o_loopback_run_loop(conn);
        ok(conn->req.res.status == 200);
        ok(check_header(&conn->req.res, H2O_TOKEN_CONTENT_TYPE, "text/html"));
        ok(h2o_memis(conn->body->bytes, conn->body->size, H2O_STRLIT("hello html\n")));
        h2o_loopback_destroy(conn);
    }
    {
        h2o_loopback_conn_t *conn = h2o_loopback_create(&ctx, ctx.globalconf->hosts);
        conn->req.input.method = h2o_iovec_init(H2O_STRLIT("HEAD"));
        conn->req.input.path = h2o_iovec_init(H2O_STRLIT("/index.html"));
        h2o_loopback_run_loop(conn);
        ok(conn->req.res.status == 200);
        ok(check_header(&conn->req.res, H2O_TOKEN_CONTENT_TYPE, "text/html"));
        ok(conn->body->size == 0);
        h2o_loopback_destroy(conn);
    }
    {
        h2o_loopback_conn_t *conn = h2o_loopback_create(&ctx, ctx.globalconf->hosts);
        conn->req.input.method = h2o_iovec_init(H2O_STRLIT("GET"));
        conn->req.input.path = h2o_iovec_init(H2O_STRLIT("/index.html"));
        h2o_loopback_run_loop(conn);
        ok(conn->req.res.status == 200);
        ok(check_header(&conn->req.res, H2O_TOKEN_CONTENT_TYPE, "text/html"));
        ok(h2o_memis(conn->body->bytes, conn->body->size, H2O_STRLIT("hello html\n")));
        h2o_loopback_destroy(conn);
    }
    {
        h2o_loopback_conn_t *conn = h2o_loopback_create(&ctx, ctx.globalconf->hosts);
        conn->req.input.method = h2o_iovec_init(H2O_STRLIT("HEAD"));
        conn->req.input.path = h2o_iovec_init(H2O_STRLIT("/1000.txt"));
        h2o_loopback_run_loop(conn);
        ok(conn->req.res.status == 200);
        ok(check_header(&conn->req.res, H2O_TOKEN_CONTENT_TYPE, "text/plain"));
        ok(conn->body->size == 0);
        h2o_loopback_destroy(conn);
    }
    {
        h2o_loopback_conn_t *conn = h2o_loopback_create(&ctx, ctx.globalconf->hosts);
        conn->req.input.method = h2o_iovec_init(H2O_STRLIT("GET"));
        conn->req.input.path = h2o_iovec_init(H2O_STRLIT("/1000.txt"));
        h2o_loopback_run_loop(conn);
        ok(conn->req.res.status == 200);
        ok(check_header(&conn->req.res, H2O_TOKEN_CONTENT_TYPE, "text/plain"));
        ok(conn->body->size == 1000);
        ok(strcmp(sha1sum(conn->body->bytes, conn->body->size), "dfd3ae1f5c475555fad62efe42e07309fa45f2ed") == 0);
        h2o_loopback_destroy(conn);
    }
    {
        h2o_loopback_conn_t *conn = h2o_loopback_create(&ctx, ctx.globalconf->hosts);
        conn->req.input.method = h2o_iovec_init(H2O_STRLIT("HEAD"));
        conn->req.input.path = h2o_iovec_init(H2O_STRLIT("/1000000.txt"));
        h2o_loopback_run_loop(conn);
        ok(conn->req.res.status == 200);
        ok(check_header(&conn->req.res, H2O_TOKEN_CONTENT_TYPE, "text/plain"));
        ok(conn->body->size == 0);
        h2o_loopback_destroy(conn);
    }
    {
        h2o_loopback_conn_t *conn = h2o_loopback_create(&ctx, ctx.globalconf->hosts);
        conn->req.input.method = h2o_iovec_init(H2O_STRLIT("GET"));
        conn->req.input.path = h2o_iovec_init(H2O_STRLIT("/1000000.txt"));
        h2o_loopback_run_loop(conn);
        ok(conn->req.res.status == 200);
        ok(check_header(&conn->req.res, H2O_TOKEN_CONTENT_TYPE, "text/plain"));
        ok(conn->body->size == 1000000);
        ok(strcmp(sha1sum(conn->body->bytes, conn->body->size), "00c8ab71d0914dce6a1ec2eaa0fda0df7044b2a2") == 0);
        h2o_loopback_destroy(conn);
    }
    {
        h2o_loopback_conn_t *conn = h2o_loopback_create(&ctx, ctx.globalconf->hosts);
        conn->req.input.method = h2o_iovec_init(H2O_STRLIT("HEAD"));
        conn->req.input.path = h2o_iovec_init(H2O_STRLIT("/index_txt/"));
        h2o_loopback_run_loop(conn);
        ok(conn->req.res.status == 200);
        ok(check_header(&conn->req.res, H2O_TOKEN_CONTENT_TYPE, "text/plain"));
        ok(conn->body->size == 0);
        h2o_loopback_destroy(conn);
    }
    {
        h2o_loopback_conn_t *conn = h2o_loopback_create(&ctx, ctx.globalconf->hosts);
        conn->req.input.method = h2o_iovec_init(H2O_STRLIT("GET"));
        conn->req.input.path = h2o_iovec_init(H2O_STRLIT("/index_txt/"));
        h2o_loopback_run_loop(conn);
        ok(conn->req.res.status == 200);
        ok(check_header(&conn->req.res, H2O_TOKEN_CONTENT_TYPE, "text/plain"));
        ok(h2o_memis(conn->body->bytes, conn->body->size, H2O_STRLIT("hello text\n")));
        h2o_loopback_destroy(conn);
    }
    {
        h2o_loopback_conn_t *conn = h2o_loopback_create(&ctx, ctx.globalconf->hosts);
        conn->req.input.method = h2o_iovec_init(H2O_STRLIT("HEAD"));
        conn->req.input.path = h2o_iovec_init(H2O_STRLIT("/index_txt"));
        h2o_loopback_run_loop(conn);
        ok(conn->req.res.status == 301);
        ok(check_header(&conn->req.res, H2O_TOKEN_LOCATION, "/index_txt/"));
        h2o_loopback_destroy(conn);
    }
    {
        h2o_loopback_conn_t *conn = h2o_loopback_create(&ctx, ctx.globalconf->hosts);
        conn->req.input.method = h2o_iovec_init(H2O_STRLIT("GET"));
        conn->req.input.path = h2o_iovec_init(H2O_STRLIT("/index_txt"));
        h2o_loopback_run_loop(conn);
        ok(conn->req.res.status == 301);
        ok(check_header(&conn->req.res, H2O_TOKEN_LOCATION, "/index_txt/"));
        h2o_loopback_destroy(conn);
    }
    {
        h2o_loopback_conn_t *conn = h2o_loopback_create(&ctx, ctx.globalconf->hosts);
        conn->req.input.method = h2o_iovec_init(H2O_STRLIT("HEAD"));
        conn->req.input.path = h2o_iovec_init(H2O_STRLIT("/index_txt_as_dir/"));
        h2o_loopback_run_loop(conn);
        ok(conn->req.res.status == 301);
        ok(check_header(&conn->req.res, H2O_TOKEN_LOCATION, "/index_txt_as_dir/index.txt/"));
        h2o_loopback_destroy(conn);
    }
    {
        h2o_loopback_conn_t *conn = h2o_loopback_create(&ctx, ctx.globalconf->hosts);
        conn->req.input.method = h2o_iovec_init(H2O_STRLIT("GET"));
        conn->req.input.path = h2o_iovec_init(H2O_STRLIT("/index_txt_as_dir/"));
        h2o_loopback_run_loop(conn);
        ok(conn->req.res.status == 301);
        ok(check_header(&conn->req.res, H2O_TOKEN_LOCATION, "/index_txt_as_dir/index.txt/"));
        h2o_loopback_destroy(conn);
    }

    subtest("if-modified-since", test_if_modified_since);
    subtest("if-match", test_if_match);

    h2o_context_dispose(&ctx);
    h2o_config_dispose(&globalconf);
}
