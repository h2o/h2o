/*
 * Copyright (c) 2026 Fastly, Inc.
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
/*
 * This file implements a test harness for using h2o's client-side HTTP/2
 * response parser (lib/common/http2client.c) with LibFuzzer.
 * See http://llvm.org/docs/LibFuzzer.html for more info.
 */
#define H2O_USE_EPOLL 1

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "h2o.h"
#include "h2o/httpclient.h"
#include "h2o/url.h"

#ifdef __cplusplus
extern "C" {
#endif

static h2o_loop_t *loop;
static h2o_httpclient_ctx_t client_ctx;
static h2o_httpclient_connection_pool_t connpool;
static h2o_socketpool_t sockpool;
static h2o_url_t origin_url;
static h2o_mem_pool_t origin_pool;
static int init_done;

/* Response body callback: consume bytes, keep going until EOS/error */
static int on_body(h2o_httpclient_t *client, const char *errstr, h2o_header_t *trailers, size_t num_trailers)
{
    (void)client;
    (void)trailers;
    (void)num_trailers;
    /* Returning non-zero would ask the stack to abort; we just keep consuming */
    return errstr != NULL ? -1 : 0;
}

/* Response head callback: returns the on_body callback (or NULL to cancel) */
static h2o_httpclient_body_cb on_head(h2o_httpclient_t *client, const char *errstr, h2o_httpclient_on_head_t *args)
{
    (void)client;
    (void)errstr;
    (void)args;
    return on_body;
}

/* Invoked by http2client once the (already-established) connection is ready to
 * issue a request; we hand it a trivial GET so a stream gets registered */
static h2o_httpclient_head_cb on_connect(h2o_httpclient_t *client, const char *errstr, h2o_iovec_t *method, h2o_url_t *url,
                                         const h2o_header_t **headers, size_t *num_headers, h2o_iovec_t *body,
                                         h2o_httpclient_proceed_req_cb *proceed_req_cb, h2o_httpclient_properties_t *props,
                                         h2o_url_t *origin)
{
    (void)client;
    (void)props;
    if (errstr != NULL)
        return NULL;
    *method = h2o_iovec_init(H2O_STRLIT("GET"));
    *url = *origin;
    *headers = NULL;
    *num_headers = 0;
    *body = h2o_iovec_init(NULL, 0);
    *proceed_req_cb = NULL;
    return on_head;
}

static void do_init(void)
{
    loop = h2o_evloop_create();

    memset(&client_ctx, 0, sizeof(client_ctx));
    client_ctx.loop = loop;
    client_ctx.getaddr_receiver = NULL;
    client_ctx.io_timeout = 10;
    client_ctx.connect_timeout = 10;
    client_ctx.first_byte_timeout = 10;
    client_ctx.keepalive_timeout = 10;
    client_ctx.max_buffer_size = 1024 * 1024;
    client_ctx.protocol_selector.ratio.http2 = 100;

    /* A socketpool/connpool is required by the client struct even though we
     * call __h2_on_connect directly (close paths inspect connpool). */
    h2o_socketpool_init_global(&sockpool, 10);
    h2o_httpclient_connection_pool_init(&connpool, &sockpool);

    h2o_mem_init_pool(&origin_pool);
    h2o_url_parse(&origin_pool, H2O_STRLIT("http://127.0.0.1:80/"), &origin_url);

    init_done = 1;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (!init_done)
        do_init();

    int sp[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) != 0)
        return 0;

    /* sp[0]: the side h2o's client reads/writes (the "connection" to upstream)
     * sp[1]: the side we use to play the upstream server, feeding response bytes */
    h2o_socket_t *sock = h2o_evloop_socket_create(loop, sp[0], H2O_SOCKET_FLAG_IS_ACCEPTED_CONNECTION);
    if (sock == NULL) {
        close(sp[0]);
        close(sp[1]);
        return 0;
    }

    /* Allocate a client large enough for the h2 stream struct */
    size_t client_sz = h2o_httpclient__h2_size;
    if (h2o_httpclient__h1_size > client_sz)
        client_sz = h2o_httpclient__h1_size;
    h2o_httpclient_t *client = h2o_mem_alloc(client_sz);
    memset(client, 0, client_sz);

    h2o_mem_pool_t pool;
    h2o_mem_init_pool(&pool);

    client->pool = &pool;
    client->ctx = &client_ctx;
    client->connpool = &connpool;
    client->_cb.on_connect = on_connect;

    /* Establish the client connection on the socket: this sends the client
     * preface (into sp[0], drained below), registers a stream, and starts
     * reading via on_read() */
    h2o_httpclient__h2_on_connect(client, sock, &origin_url);

    /* Drain whatever the client wrote (preface/SETTINGS/HEADERS) on the peer
     * end so the socket buffer does not fill up */
    {
        char drainbuf[65536];
        int fl = fcntl(sp[1], F_GETFL, 0);
        fcntl(sp[1], F_SETFL, fl | O_NONBLOCK);
        while (read(sp[1], drainbuf, sizeof(drainbuf)) > 0)
            ;
    }

    /* Feed the fuzz input as the upstream server's response byte stream */
    {
        size_t off = 0;
        while (off < size) {
            ssize_t n = write(sp[1], data + off, size - off);
            if (n <= 0) {
                if (n < 0 && errno == EINTR)
                    continue;
                break;
            }
            off += (size_t)n;
        }
    }
    /* Signal EOF so the client tears down the connection and frees the stream
     * (touching `client` after this would be a use-after-free) */
    shutdown(sp[1], SHUT_WR);

    /* Pump the loop: on_read() runs the http2client parser, then EOF triggers
     * teardown; bounded so a stuck connection cannot hang the fuzzer */
    for (int i = 0; i < 64; ++i) {
        /* Non-zero timeout so the io/keepalive teardown timers can fire */
        h2o_evloop_run(loop, 1);
        char drainbuf[4096];
        while (read(sp[1], drainbuf, sizeof(drainbuf)) > 0)
            ;
    }

    close(sp[1]);

    h2o_mem_clear_pool(&pool);
    return 0;
}

#ifdef __cplusplus
}
#endif
