/*
 * Copyright (c) 2026 Alejandro Pacheco
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
#include <fcntl.h>
#include <sys/socket.h>
#include "../../test.h"
#include "../../../../lib/common/http2client.c"

#if !H2O_USE_LIBUV

static h2o_mem_pool_t test_pool;
static size_t test_on_head_calls;
static const char *test_on_head_errstr;
static int test_on_head_conn_pooled;

static h2o_httpclient_body_cb test_on_head(h2o_httpclient_t *client, const char *errstr, h2o_httpclient_on_head_t *args)
{
    ++test_on_head_calls;
    test_on_head_errstr = errstr;
    test_on_head_conn_pooled = !h2o_linklist_is_empty(&client->connpool->http2.conns);
    return NULL;
}

static h2o_httpclient_head_cb test_on_connect(h2o_httpclient_t *client, const char *errstr, h2o_iovec_t *method, h2o_url_t *url,
                                              const h2o_header_t **headers, size_t *num_headers, h2o_iovec_t *body,
                                              h2o_httpclient_proceed_req_cb *proceed_req_cb, h2o_httpclient_properties_t *props,
                                              h2o_url_t *origin)
{
    *method = h2o_iovec_init(H2O_STRLIT("GET"));
    *url = *origin;
    *headers = NULL;
    *num_headers = 0;
    *body = h2o_iovec_init(NULL, 0);
    *proceed_req_cb = NULL;
    return test_on_head;
}

static void test_error_closes_streams(void)
{
    h2o_httpclient_ctx_t ctx = {
        .loop = test_loop,
        .io_timeout = 100,
        .connect_timeout = 5000,
        .first_byte_timeout = 5000,
        .keepalive_timeout = 5000,
        .max_buffer_size = 65536,
        .http2.max_concurrent_streams = 100,
    };
    h2o_httpclient_connection_pool_t connpool = {};
    h2o_url_t origin;
    int fds[2];
    char junk[4096] = {0};

    h2o_linklist_init_anchor(&connpool.http2.conns);
    h2o_mem_init_pool(&test_pool);
    test_on_head_calls = 0;
    test_on_head_errstr = NULL;
    test_on_head_conn_pooled = 1;

    ok(h2o_url_parse(&test_pool, H2O_STRLIT("http://example.com/"), &origin) == 0);
    ok(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);

    /* the server does not read, so that writes by the client stay in flight */
    fcntl(fds[0], F_SETFL, O_NONBLOCK);
    while (write(fds[0], junk, sizeof(junk)) > 0)
        ;
    /* a frame other than SETTINGS at the beginning of the connection is a protocol error */
    static const uint8_t ping[] = {0, 0, 8, H2O_HTTP2_FRAME_TYPE_PING, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    ok(write(fds[1], ping, sizeof(ping)) == sizeof(ping));

    h2o_socket_t *sock = h2o_evloop_socket_create(test_loop, fds[0], 0);
    struct st_h2o_http2client_stream_t *stream = h2o_mem_alloc(h2o_httpclient__h2_size);
    memset(stream, 0, h2o_httpclient__h2_size);
    stream->super.pool = &test_pool;
    stream->super.ctx = &ctx;
    stream->super.connpool = &connpool;
    stream->super._cb.on_connect = test_on_connect;
    h2o_httpclient__h2_on_connect(&stream->super, sock, &origin);

    struct st_h2o_http2client_conn_t *conn = sock->data;
    ok(conn->super.num_streams == 1);
    ok(connpool.http2.conns.next == &conn->super.link);

    while (test_on_head_calls == 0)
        h2o_evloop_run(test_loop, 10);
    ok(test_on_head_calls == 1);
    ok(test_on_head_errstr == h2o_httpclient_error_protocol_violation);
    ok(conn->state == H2O_HTTP2CLIENT_CONN_STATE_IS_CLOSING);
    ok(conn->super.num_streams == 0);
    ok(!test_on_head_conn_pooled);

    /* the connection is closed by the I/O timeout */
    uint64_t deadline = h2o_now(test_loop) + ctx.io_timeout * 10;
    while (h2o_now(test_loop) < deadline)
        h2o_evloop_run(test_loop, 10);
    ok(test_on_head_calls == 1);

    close(fds[1]);
    h2o_mem_clear_pool(&test_pool);
}

#endif

void test_lib__common__http2client_c(void)
{
#if !H2O_USE_LIBUV
    subtest("error-closes-streams", test_error_closes_streams);
#endif
}
