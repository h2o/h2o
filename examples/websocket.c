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
#include <alloca.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <uv.h>
#include "h2o.h"
#include "h2o/http1.h"
#include "h2o/websocket.h"

static void on_ws_message(h2o_websocket_conn_t *conn, const struct wslay_event_on_msg_recv_arg *arg)
{
    if (arg == NULL) {
        h2o_websocket_close(conn);
        return;
    }

    if (! wslay_is_ctrl_frame(arg->opcode)) {
        struct wslay_event_msg msgarg = {
            arg->opcode,
            arg->msg,
            arg->msg_length
        };
        wslay_event_queue_msg(conn->ws_ctx, &msgarg);
    }
}

static int on_req(h2o_handler_t *self, h2o_req_t *req)
{
    const char *client_key;

    if (h2o_is_websocket_handshake(req, &client_key) != 0 || client_key == NULL) {
        return -1;
    }
    h2o_upgrade_to_websocket((h2o_http1_conn_t*)req->conn, client_key, NULL, on_ws_message);
    return 0;
}

static h2o_context_t ctx;
static h2o_ssl_context_t *ssl_ctx;

static void on_connect(uv_stream_t *server, int status)
{
    uv_tcp_t *conn;
    h2o_socket_t *sock;

    if (status != 0)
        return;

    conn = h2o_malloc(sizeof(*conn));
    uv_tcp_init(server->loop, conn);
    if (uv_accept(server, (uv_stream_t*)conn) != 0) {
        uv_close((uv_handle_t*)conn, (uv_close_cb)free);
        return;
    }

    sock = h2o_uv_socket_create((uv_stream_t*)conn, (uv_close_cb)free);
    if (ssl_ctx != NULL)
        h2o_accept_ssl(&ctx, sock, ssl_ctx);
    else
        h2o_http1_accept(&ctx, sock);
}

int main(int argc, char **argv)
{
    uv_loop_t *loop = uv_default_loop();
    uv_tcp_t listener;
    struct sockaddr_in sockaddr;
    h2o_handler_t ws_handler;
    int r;

    if ((r = uv_tcp_init(loop, &listener)) != 0) {
        fprintf(stderr, "uv_tcp_init:%s\n", uv_strerror(r));
        goto Error;
    }
    uv_ip4_addr("127.0.0.1", 7890, &sockaddr);
    if ((r = uv_tcp_bind(&listener, (struct sockaddr*)&sockaddr, sizeof(sockaddr))) != 0) {
        fprintf(stderr, "uv_tcp_bind:%s\n", uv_strerror(r));
        goto Error;
    }
    if ((r = uv_listen((uv_stream_t*)&listener, 128, on_connect)) != 0) {
        fprintf(stderr, "uv_listen:%s\n", uv_strerror(r));
        goto Error;
    }

    h2o_context_init(&ctx, loop);
    memset(&ws_handler, 0, sizeof(ws_handler));
    ws_handler.on_req = on_req;
    h2o_linklist_insert(&ctx.handlers, &ws_handler._link);
    //ssl_ctx = h2o_ssl_new_server_context("server.crt", "server.key", NULL);

    return uv_run(loop, UV_RUN_DEFAULT);

Error:
    return 1;
}
