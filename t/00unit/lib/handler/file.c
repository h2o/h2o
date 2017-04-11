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

static int check_multirange_body(char *resbody, const char *boundary, const h2o_iovec_t *expected, size_t partlen)
{
    char *bptr = resbody;
    const h2o_iovec_t *eptr = expected;
    int not_first_line = 0;
    while (partlen--) {
        if (not_first_line) {
            if (!h2o_memis(bptr, 2, H2O_STRLIT("\r\n")))
                return 0;
            bptr += 2;
        } else
            not_first_line = 1;
        if (!h2o_memis(bptr, 2, H2O_STRLIT("--")))
            return 0;
        bptr += 2;
        if (!h2o_memis(bptr, BOUNDARY_SIZE, boundary, BOUNDARY_SIZE))
            return 0;
        bptr += 20;
        if (!h2o_memis(bptr, 2, H2O_STRLIT("\r\n")))
            return 0;
        bptr += 2;
        if (!h2o_memis(bptr, eptr->len, eptr->base, eptr->len))
            return 0;
        bptr += eptr->len;
        eptr++;
    }
    if (!h2o_memis(bptr, 4, H2O_STRLIT("\r\n--")))
        return 0;
    bptr += 4;
    if (!h2o_memis(bptr, BOUNDARY_SIZE, boundary, BOUNDARY_SIZE))
        return 0;
    bptr += 20;
    if (!h2o_memis(bptr, 4, H2O_STRLIT("--\r\n")))
        return 0;
    return 1;
}

static void test_process_range(void)
{
    h2o_mem_pool_t testpool;
    size_t ret, *ranges;
    h2o_iovec_t testrange;
    h2o_mem_init_pool(&testpool);

    { /* check single range within filesize */
        testrange = h2o_iovec_init(H2O_STRLIT("bytes=, 0-10"));
        ranges = process_range(&testpool, &testrange, 100, &ret);
        ok(ret == 1);
        ok(*ranges++ == 0);
        ok(*ranges == 11);
    }

    { /* check single range with only start */
        testrange = h2o_iovec_init(H2O_STRLIT("bytes=60-"));
        ranges = process_range(&testpool, &testrange, 100, &ret);
        ok(ret == 1);
        ok(*ranges++ == 60);
        ok(*ranges == 40);
    }

    { /* check single suffix range */
        testrange = h2o_iovec_init(H2O_STRLIT("bytes=-10"));
        ranges = process_range(&testpool, &testrange, 100, &ret);
        ok(ret == 1);
        ok(*ranges++ == 90);
        ok(*ranges == 10);
    }

    { /* this and next two check multiple ranges within filesize */
        testrange = h2o_iovec_init(H2O_STRLIT("bytes=0-10, -10"));
        ranges = process_range(&testpool, &testrange, 100, &ret);
        ok(ret == 2);
        ok(*ranges++ == 0);
        ok(*ranges++ == 11);
        ok(*ranges++ == 90);
        ok(*ranges == 10);
    }

    {
        testrange = h2o_iovec_init(H2O_STRLIT("bytes=0-0, 20-89"));
        ranges = process_range(&testpool, &testrange, 100, &ret);
        ok(ret == 2);
        ok(*ranges++ == 0);
        ok(*ranges++ == 1);
        ok(*ranges++ == 20);
        ok(*ranges == 70);
    }

    {
        testrange = h2o_iovec_init(H2O_STRLIT("bytes=-10,-20"));
        ranges = process_range(&testpool, &testrange, 100, &ret);
        ok(ret == 2);
        ok(*ranges++ == 90);
        ok(*ranges++ == 10);
        ok(*ranges++ == 80);
        ok(*ranges++ == 20);
    }

    { /* check ranges entirely out of filesize */
        testrange = h2o_iovec_init(H2O_STRLIT("bytes=100-102"));
        ranges = process_range(&testpool, &testrange, 100, &ret);
        ok(ranges == NULL);
    }

    { /* check ranges with "negative" length */
        testrange = h2o_iovec_init(H2O_STRLIT("bytes=70-21"));
        ranges = process_range(&testpool, &testrange, 100, &ret);
        ok(ranges == NULL);
    }

    { /* check ranges with one side inside filesize */
        testrange = h2o_iovec_init(H2O_STRLIT("bytes=90-102"));
        ranges = process_range(&testpool, &testrange, 100, &ret);
        ok(ret == 1);
        ok(*ranges++ == 90);
        ok(*ranges == 10);
    }

    { /* check suffix range larger than filesize */
        testrange = h2o_iovec_init(H2O_STRLIT("bytes=-200"));
        ranges = process_range(&testpool, &testrange, 100, &ret);
        ok(ret == 1);
        ok(*ranges++ == 0);
        ok(*ranges == 100);
    }

    { /* check multiple ranges with unsatisfiable ranges, but also contain satisfiable ranges */
        testrange = h2o_iovec_init(H2O_STRLIT("bytes=100-102,  90-102, 72-30,-22, 95-"));
        ranges = process_range(&testpool, &testrange, 100, &ret);
        ok(ret == 3);
        ok(*ranges++ == 90);
        ok(*ranges++ == 10);
        ok(*ranges++ == 78);
        ok(*ranges++ == 22);
        ok(*ranges++ == 95);
        ok(*ranges++ == 5);
    }

    { /* this and next 6 check malformed ranges */
        testrange = h2o_iovec_init(H2O_STRLIT("bytes 20-1002"));
        ranges = process_range(&testpool, &testrange, 100, &ret);
        ok(ranges == NULL);
    }

    {
        testrange = h2o_iovec_init(H2O_STRLIT("bytes="));
        ranges = process_range(&testpool, &testrange, 100, &ret);
        ok(ranges == NULL);
    }

    {
        testrange = h2o_iovec_init(H2O_STRLIT("bsdfeadsfjwleakjf"));
        ranges = process_range(&testpool, &testrange, 100, &ret);
        ok(ranges == NULL);
    }

    {
        testrange = h2o_iovec_init(H2O_STRLIT("bytes=100-102, 90-102, -72-30,-22,95-"));
        ranges = process_range(&testpool, &testrange, 100, &ret);
        ok(ranges == NULL);
    }

    {
        testrange = h2o_iovec_init(H2O_STRLIT("bytes=10-12-13, 90-102, -72, -22, 95-"));
        ranges = process_range(&testpool, &testrange, 100, &ret);
        ok(ranges == NULL);
    }

    {
        testrange = h2o_iovec_init(H2O_STRLIT("bytes=100-102, 90-102, 70-39, -22$"));
        ranges = process_range(&testpool, &testrange, 100, &ret);
        ok(ranges == NULL);
    }

    {
        testrange = h2o_iovec_init(H2O_STRLIT("bytes=-0"));
        ranges = process_range(&testpool, &testrange, 100, &ret);
        ok(ranges == NULL);
    }

    { /* check same ranges with different filesize */
        testrange = h2o_iovec_init(H2O_STRLIT("bytes=20-200"));
        ranges = process_range(&testpool, &testrange, 100, &ret);
        ok(ret == 1);
        ok(*ranges++ == 20);
        ok(*ranges == 80);
    }

    {
        ranges = process_range(&testpool, &testrange, 1000, &ret);
        ok(ret == 1);
        ok(*ranges++ == 20);
        ok(*ranges == 181);
    }

    { /* check a range with plenty of WS and COMMA */
        testrange = h2o_iovec_init(H2O_STRLIT("bytes=,\t,1-3 ,, ,5-9,"));
        ranges = process_range(&testpool, &testrange, 100, &ret);
        ok(ret == 2);
        ok(*ranges++ == 1);
        ok(*ranges++ == 3);
        ok(*ranges++ == 5);
        ok(*ranges == 5);
    }

    {
        testrange = h2o_iovec_init(H2O_STRLIT("bytes= 1-3"));
        ranges = process_range(&testpool, &testrange, 100, &ret);
        ok(ranges == NULL);
    }

    {
        testrange = h2o_iovec_init(H2O_STRLIT("bytes=1-3 5-10"));
        ranges = process_range(&testpool, &testrange, 100, &ret);
        ok(ranges == NULL);
    }

    {
        testrange = h2o_iovec_init(H2O_STRLIT("bytes=1-\t,5-10"));
        ranges = process_range(&testpool, &testrange, 100, &ret);
        ok(ret == 2);
        ok(*ranges++ == 1);
        ok(*ranges++ == 99);
        ok(*ranges++ == 5);
        ok(*ranges == 6);
    }

    h2o_mem_clear_pool(&testpool);
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
        h2o_add_header(&conn->req.pool, &conn->req.headers, H2O_TOKEN_IF_MODIFIED_SINCE, NULL, lm_date, H2O_TIMESTR_RFC1123_LEN);
        h2o_loopback_run_loop(conn);
        ok(conn->req.res.status == 304);
        ok(conn->body->size == 0);
        ok(h2o_find_header(&conn->req.res.headers, H2O_TOKEN_ETAG, -1) != -1);
        h2o_loopback_destroy(conn);
    }

    { /* send if-modified-since using an old date */
        h2o_loopback_conn_t *conn = h2o_loopback_create(&ctx, ctx.globalconf->hosts);
        conn->req.input.method = h2o_iovec_init(H2O_STRLIT("GET"));
        conn->req.input.path = h2o_iovec_init(H2O_STRLIT("/"));
        h2o_add_header(&conn->req.pool, &conn->req.headers, H2O_TOKEN_IF_MODIFIED_SINCE, NULL,
                       H2O_STRLIT("Sun, 06 Nov 1994 08:49:37 GMT"));
        h2o_loopback_run_loop(conn);
        ok(conn->req.res.status == 200);
        h2o_loopback_destroy(conn);
    }

    { /* send if-modified-since using a date in the future */
        h2o_loopback_conn_t *conn = h2o_loopback_create(&ctx, ctx.globalconf->hosts);
        conn->req.input.method = h2o_iovec_init(H2O_STRLIT("GET"));
        conn->req.input.path = h2o_iovec_init(H2O_STRLIT("/"));
        h2o_add_header(&conn->req.pool, &conn->req.headers, H2O_TOKEN_IF_MODIFIED_SINCE, NULL,
                       H2O_STRLIT("Wed, 18 May 2033 12:33:20 GMT"));
        h2o_loopback_run_loop(conn);
        ok(conn->req.res.status == 304);
        ok(conn->body->size == 0);
        ok(h2o_find_header(&conn->req.res.headers, H2O_TOKEN_ETAG, -1) != -1);
        h2o_loopback_destroy(conn);
    }
}

static void test_if_match(void)
{
    h2o_iovec_t etag = {NULL};

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
        h2o_add_header(&conn->req.pool, &conn->req.headers, H2O_TOKEN_IF_NONE_MATCH, NULL, etag.base, etag.len);
        h2o_loopback_run_loop(conn);
        ok(conn->req.res.status == 304);
        ok(conn->body->size == 0);
        h2o_loopback_destroy(conn);
    }

    free(etag.base);
}

static void test_range_req(void)
{
    { /* check if accept-ranges is "bytes" */
        h2o_loopback_conn_t *conn = h2o_loopback_create(&ctx, ctx.globalconf->hosts);
        conn->req.input.method = h2o_iovec_init(H2O_STRLIT("GET"));
        conn->req.input.path = h2o_iovec_init(H2O_STRLIT("/1000.txt"));
        h2o_loopback_run_loop(conn);
        ok(conn->req.res.status == 200);
        ok(check_header(&conn->req.res, H2O_TOKEN_CONTENT_TYPE, "text/plain"));
        if (check_header(&conn->req.res, H2O_TOKEN_ACCEPT_RANGES, "none")) {
            ok(1);
            return;
        }
        ok(check_header(&conn->req.res, H2O_TOKEN_ACCEPT_RANGES, "bytes"));
        ok(conn->body->size == 1000);
        ok(strcmp(sha1sum(conn->body->bytes, conn->body->size), "dfd3ae1f5c475555fad62efe42e07309fa45f2ed") == 0);
        h2o_loopback_destroy(conn);
    }
    { /* check a normal single range */
        h2o_loopback_conn_t *conn = h2o_loopback_create(&ctx, ctx.globalconf->hosts);
        conn->req.input.method = h2o_iovec_init(H2O_STRLIT("GET"));
        conn->req.input.path = h2o_iovec_init(H2O_STRLIT("/1000.txt"));
        h2o_add_header(&conn->req.pool, &conn->req.headers, H2O_TOKEN_RANGE, NULL, H2O_STRLIT("bytes=0-10"));
        h2o_loopback_run_loop(conn);
        ok(conn->req.res.status == 206);
        ok(check_header(&conn->req.res, H2O_TOKEN_CONTENT_TYPE, "text/plain"));
        ok(check_header(&conn->req.res, H2O_TOKEN_CONTENT_RANGE, "bytes 0-10/1000"));
        ok(conn->body->size == 11);
        ok(memcmp(conn->body->bytes, "123456789\n1", 11) == 0);
        h2o_loopback_destroy(conn);
    }
    { /* check an over range single range */
        h2o_loopback_conn_t *conn = h2o_loopback_create(&ctx, ctx.globalconf->hosts);
        conn->req.input.method = h2o_iovec_init(H2O_STRLIT("GET"));
        conn->req.input.path = h2o_iovec_init(H2O_STRLIT("/1000.txt"));
        h2o_add_header(&conn->req.pool, &conn->req.headers, H2O_TOKEN_RANGE, NULL, H2O_STRLIT("bytes=990-1100"));
        h2o_loopback_run_loop(conn);
        ok(conn->req.res.status == 206);
        ok(check_header(&conn->req.res, H2O_TOKEN_CONTENT_TYPE, "text/plain"));
        ok(check_header(&conn->req.res, H2O_TOKEN_CONTENT_RANGE, "bytes 990-999/1000"));
        ok(conn->body->size == 10);
        ok(memcmp(conn->body->bytes, "123456789\n", 10) == 0);
        h2o_loopback_destroy(conn);
    }
    { /* check a single range without end */
        h2o_loopback_conn_t *conn = h2o_loopback_create(&ctx, ctx.globalconf->hosts);
        conn->req.input.method = h2o_iovec_init(H2O_STRLIT("GET"));
        conn->req.input.path = h2o_iovec_init(H2O_STRLIT("/1000.txt"));
        h2o_add_header(&conn->req.pool, &conn->req.headers, H2O_TOKEN_RANGE, NULL, H2O_STRLIT("bytes=989-"));
        h2o_loopback_run_loop(conn);
        ok(conn->req.res.status == 206);
        ok(check_header(&conn->req.res, H2O_TOKEN_CONTENT_TYPE, "text/plain"));
        ok(check_header(&conn->req.res, H2O_TOKEN_CONTENT_RANGE, "bytes 989-999/1000"));
        ok(conn->body->size == 11);
        ok(memcmp(conn->body->bytes, "\n123456789\n", 11) == 0);
        h2o_loopback_destroy(conn);
    }
    { /* check a single suffix range */
        h2o_loopback_conn_t *conn = h2o_loopback_create(&ctx, ctx.globalconf->hosts);
        conn->req.input.method = h2o_iovec_init(H2O_STRLIT("GET"));
        conn->req.input.path = h2o_iovec_init(H2O_STRLIT("/1000.txt"));
        h2o_add_header(&conn->req.pool, &conn->req.headers, H2O_TOKEN_RANGE, NULL, H2O_STRLIT("bytes=-21"));
        h2o_loopback_run_loop(conn);
        ok(conn->req.res.status == 206);
        ok(check_header(&conn->req.res, H2O_TOKEN_CONTENT_TYPE, "text/plain"));
        ok(check_header(&conn->req.res, H2O_TOKEN_CONTENT_RANGE, "bytes 979-999/1000"));
        ok(conn->body->size == 21);
        ok(memcmp(conn->body->bytes, "\n123456789\n123456789\n", 21) == 0);
        h2o_loopback_destroy(conn);
    }
    { /* check a single suffix range over filesize */
        h2o_loopback_conn_t *conn = h2o_loopback_create(&ctx, ctx.globalconf->hosts);
        conn->req.input.method = h2o_iovec_init(H2O_STRLIT("GET"));
        conn->req.input.path = h2o_iovec_init(H2O_STRLIT("/1000.txt"));
        h2o_add_header(&conn->req.pool, &conn->req.headers, H2O_TOKEN_RANGE, NULL, H2O_STRLIT("bytes=-2100"));
        h2o_loopback_run_loop(conn);
        ok(conn->req.res.status == 206);
        ok(check_header(&conn->req.res, H2O_TOKEN_CONTENT_TYPE, "text/plain"));
        ok(check_header(&conn->req.res, H2O_TOKEN_CONTENT_RANGE, "bytes 0-999/1000"));
        ok(conn->body->size == 1000);
        ok(strcmp(sha1sum(conn->body->bytes, conn->body->size), "dfd3ae1f5c475555fad62efe42e07309fa45f2ed") == 0);
        h2o_loopback_destroy(conn);
    }
    { /* malformed range */
        h2o_loopback_conn_t *conn = h2o_loopback_create(&ctx, ctx.globalconf->hosts);
        conn->req.input.method = h2o_iovec_init(H2O_STRLIT("GET"));
        conn->req.input.path = h2o_iovec_init(H2O_STRLIT("/1000.txt"));
        h2o_add_header(&conn->req.pool, &conn->req.headers, H2O_TOKEN_RANGE, NULL, H2O_STRLIT("bytes=-0-10, 9-, -10"));
        h2o_loopback_run_loop(conn);
        ok(conn->req.res.status == 416);
        ok(check_header(&conn->req.res, H2O_TOKEN_CONTENT_TYPE, "text/plain; charset=utf-8"));
        ok(check_header(&conn->req.res, H2O_TOKEN_CONTENT_RANGE, "bytes */1000"));
        ok(conn->body->size == strlen("requested range not satisfiable"));
        ok(h2o_memis(conn->body->bytes, conn->body->size, H2O_STRLIT("requested range not satisfiable")));
        h2o_loopback_destroy(conn);
    }
    { /* malformed range */
        h2o_loopback_conn_t *conn = h2o_loopback_create(&ctx, ctx.globalconf->hosts);
        conn->req.input.method = h2o_iovec_init(H2O_STRLIT("GET"));
        conn->req.input.path = h2o_iovec_init(H2O_STRLIT("/1000.txt"));
        h2o_add_header(&conn->req.pool, &conn->req.headers, H2O_TOKEN_RANGE, NULL, H2O_STRLIT("bytes=0-10-12, 9-, -10"));
        h2o_loopback_run_loop(conn);
        ok(conn->req.res.status == 416);
        ok(check_header(&conn->req.res, H2O_TOKEN_CONTENT_TYPE, "text/plain; charset=utf-8"));
        ok(check_header(&conn->req.res, H2O_TOKEN_CONTENT_RANGE, "bytes */1000"));
        ok(conn->body->size == strlen("requested range not satisfiable"));
        ok(h2o_memis(conn->body->bytes, conn->body->size, H2O_STRLIT("requested range not satisfiable")));
        h2o_loopback_destroy(conn);
    }
    { /* malformed range */
        h2o_loopback_conn_t *conn = h2o_loopback_create(&ctx, ctx.globalconf->hosts);
        conn->req.input.method = h2o_iovec_init(H2O_STRLIT("GET"));
        conn->req.input.path = h2o_iovec_init(H2O_STRLIT("/1000.txt"));
        h2o_add_header(&conn->req.pool, &conn->req.headers, H2O_TOKEN_RANGE, NULL, H2O_STRLIT("bytfasdf"));
        h2o_loopback_run_loop(conn);
        ok(conn->req.res.status == 416);
        ok(check_header(&conn->req.res, H2O_TOKEN_CONTENT_TYPE, "text/plain; charset=utf-8"));
        ok(check_header(&conn->req.res, H2O_TOKEN_CONTENT_RANGE, "bytes */1000"));
        ok(conn->body->size == strlen("requested range not satisfiable"));
        ok(h2o_memis(conn->body->bytes, conn->body->size, H2O_STRLIT("requested range not satisfiable")));
        h2o_loopback_destroy(conn);
    }
    { /* half-malformed range */
        h2o_loopback_conn_t *conn = h2o_loopback_create(&ctx, ctx.globalconf->hosts);
        conn->req.input.method = h2o_iovec_init(H2O_STRLIT("GET"));
        conn->req.input.path = h2o_iovec_init(H2O_STRLIT("/1000.txt"));
        h2o_add_header(&conn->req.pool, &conn->req.headers, H2O_TOKEN_RANGE, NULL, H2O_STRLIT("bytes=-0"));
        h2o_loopback_run_loop(conn);
        ok(conn->req.res.status == 416);
        ok(check_header(&conn->req.res, H2O_TOKEN_CONTENT_TYPE, "text/plain; charset=utf-8"));
        ok(check_header(&conn->req.res, H2O_TOKEN_CONTENT_RANGE, "bytes */1000"));
        ok(conn->body->size == strlen("requested range not satisfiable"));
        ok(h2o_memis(conn->body->bytes, conn->body->size, H2O_STRLIT("requested range not satisfiable")));
        h2o_loopback_destroy(conn);
    }
    { /* single range over filesize */
        h2o_loopback_conn_t *conn = h2o_loopback_create(&ctx, ctx.globalconf->hosts);
        conn->req.input.method = h2o_iovec_init(H2O_STRLIT("GET"));
        conn->req.input.path = h2o_iovec_init(H2O_STRLIT("/1000.txt"));
        h2o_add_header(&conn->req.pool, &conn->req.headers, H2O_TOKEN_RANGE, NULL, H2O_STRLIT("bytes=1000-1001"));
        h2o_loopback_run_loop(conn);
        ok(conn->req.res.status == 416);
        ok(check_header(&conn->req.res, H2O_TOKEN_CONTENT_TYPE, "text/plain; charset=utf-8"));
        ok(check_header(&conn->req.res, H2O_TOKEN_CONTENT_RANGE, "bytes */1000"));
        ok(conn->body->size == strlen("requested range not satisfiable"));
        ok(h2o_memis(conn->body->bytes, conn->body->size, H2O_STRLIT("requested range not satisfiable")));
        h2o_loopback_destroy(conn);
    }
    { /* single range with "negative" length */
        h2o_loopback_conn_t *conn = h2o_loopback_create(&ctx, ctx.globalconf->hosts);
        conn->req.input.method = h2o_iovec_init(H2O_STRLIT("GET"));
        conn->req.input.path = h2o_iovec_init(H2O_STRLIT("/1000.txt"));
        h2o_add_header(&conn->req.pool, &conn->req.headers, H2O_TOKEN_RANGE, NULL, H2O_STRLIT("bytes=900-100"));
        h2o_loopback_run_loop(conn);
        ok(conn->req.res.status == 416);
        ok(check_header(&conn->req.res, H2O_TOKEN_CONTENT_TYPE, "text/plain; charset=utf-8"));
        ok(check_header(&conn->req.res, H2O_TOKEN_CONTENT_RANGE, "bytes */1000"));
        ok(conn->body->size == strlen("requested range not satisfiable"));
        ok(h2o_memis(conn->body->bytes, conn->body->size, H2O_STRLIT("requested range not satisfiable")));
        h2o_loopback_destroy(conn);
    }
    { /* check a half-malformed range with a normal range */
        h2o_loopback_conn_t *conn = h2o_loopback_create(&ctx, ctx.globalconf->hosts);
        conn->req.input.method = h2o_iovec_init(H2O_STRLIT("GET"));
        conn->req.input.path = h2o_iovec_init(H2O_STRLIT("/1000.txt"));
        h2o_add_header(&conn->req.pool, &conn->req.headers, H2O_TOKEN_RANGE, NULL, H2O_STRLIT("bytes=-0, 0-0"));
        h2o_loopback_run_loop(conn);
        ok(conn->req.res.status == 206);
        ok(check_header(&conn->req.res, H2O_TOKEN_CONTENT_TYPE, "text/plain"));
        ok(check_header(&conn->req.res, H2O_TOKEN_CONTENT_RANGE, "bytes 0-0/1000"));
        ok(conn->body->size == 1);
        ok(memcmp(conn->body->bytes, "1", 1) == 0);
        h2o_loopback_destroy(conn);
    }
    { /* multiple ranges */
        h2o_loopback_conn_t *conn = h2o_loopback_create(&ctx, ctx.globalconf->hosts);
        ssize_t content_type_index;
        h2o_iovec_t content_type, expected[2] = {{NULL}};
        char boundary[BOUNDARY_SIZE + 1];
        size_t mimebaselen = strlen("multipart/byteranges; boundary=");
        conn->req.input.method = h2o_iovec_init(H2O_STRLIT("GET"));
        conn->req.input.path = h2o_iovec_init(H2O_STRLIT("/1000.txt"));
        h2o_add_header(&conn->req.pool, &conn->req.headers, H2O_TOKEN_RANGE, NULL, H2O_STRLIT("bytes=-0, 0-9,-11"));
        h2o_loopback_run_loop(conn);
        ok(conn->req.res.status == 206);
        if ((content_type_index = h2o_find_header(&conn->req.res.headers, H2O_TOKEN_CONTENT_TYPE, -1)) == -1) {
            ok(0);
            return;
        }
        content_type = conn->req.res.headers.entries[content_type_index].value;
        ok(h2o_memis(content_type.base, mimebaselen, "multipart/byteranges; boundary=", mimebaselen));
        memcpy(boundary, content_type.base + mimebaselen, BOUNDARY_SIZE);
        boundary[BOUNDARY_SIZE] = 0;
        expected[0].base = h2o_mem_alloc_pool(&conn->req.pool, 256);
        expected[0].len =
            sprintf(expected[0].base, "Content-Type: %s\r\nContent-Range: bytes 0-9/1000\r\n\r\n%s", "text/plain", "123456789\n");
        expected[1].base = h2o_mem_alloc_pool(&conn->req.pool, 256);
        expected[1].len = sprintf(expected[1].base, "Content-Type: %s\r\nContent-Range: bytes 989-999/1000\r\n\r\n%s", "text/plain",
                                  "\n123456789\n");
        ok(h2o_find_header(&conn->req.res.headers, H2O_TOKEN_CONTENT_RANGE, -1) == -1);
        ok(conn->body->size == conn->req.res.content_length);
        ok(check_multirange_body(conn->body->bytes, boundary, expected, 2));
        h2o_loopback_destroy(conn);
    }
    { /* multiple ranges with plenty of WS and COMMA */
        h2o_loopback_conn_t *conn = h2o_loopback_create(&ctx, ctx.globalconf->hosts);
        ssize_t content_type_index;
        h2o_iovec_t content_type, expected[2] = {{NULL}};
        char boundary[BOUNDARY_SIZE + 1];
        size_t mimebaselen = strlen("multipart/byteranges; boundary=");
        conn->req.input.method = h2o_iovec_init(H2O_STRLIT("GET"));
        conn->req.input.path = h2o_iovec_init(H2O_STRLIT("/1000.txt"));
        h2o_add_header(&conn->req.pool, &conn->req.headers, H2O_TOKEN_RANGE, NULL, H2O_STRLIT("bytes=,\t,1-3 ,, ,5-9,"));
        h2o_loopback_run_loop(conn);
        ok(conn->req.res.status == 206);
        if ((content_type_index = h2o_find_header(&conn->req.res.headers, H2O_TOKEN_CONTENT_TYPE, -1)) == -1) {
            ok(0);
            return;
        }
        content_type = conn->req.res.headers.entries[content_type_index].value;
        ok(h2o_memis(content_type.base, mimebaselen, "multipart/byteranges; boundary=", mimebaselen));
        memcpy(boundary, content_type.base + mimebaselen, BOUNDARY_SIZE);
        boundary[BOUNDARY_SIZE] = 0;
        expected[0].base = h2o_mem_alloc_pool(&conn->req.pool, 256);
        expected[0].len =
            sprintf(expected[0].base, "Content-Type: %s\r\nContent-Range: bytes 1-3/1000\r\n\r\n%s", "text/plain", "234");
        expected[1].base = h2o_mem_alloc_pool(&conn->req.pool, 256);
        expected[1].len =
            sprintf(expected[1].base, "Content-Type: %s\r\nContent-Range: bytes 5-9/1000\r\n\r\n%s", "text/plain", "6789\n");
        ok(h2o_find_header(&conn->req.res.headers, H2O_TOKEN_CONTENT_RANGE, -1) == -1);
        ok(conn->body->size == conn->req.res.content_length);
        ok(check_multirange_body(conn->body->bytes, boundary, expected, 2));
        h2o_loopback_destroy(conn);
    }
}

void test_lib__handler__file_c()
{
    h2o_globalconf_t globalconf;
    h2o_hostconf_t *hostconf;
    h2o_pathconf_t *pathconf;

    h2o_config_init(&globalconf);
    hostconf = h2o_config_register_host(&globalconf, h2o_iovec_init(H2O_STRLIT("default")), 65535);
    pathconf = h2o_config_register_path(hostconf, "/", 0);
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
    subtest("process_range()", test_process_range);
    subtest("range request", test_range_req);

    h2o_context_dispose(&ctx);
    h2o_config_dispose(&globalconf);
}
