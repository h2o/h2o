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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <uv.h>
#include "h2o.h"
#include "h2o/websocket.h"

static void on_ws_message(h2o_websocket_conn_t *conn, const struct wslay_event_on_msg_recv_arg *arg)
{
    if (arg == NULL) {
        h2o_websocket_close(conn);
        return;
    }

    if (!wslay_is_ctrl_frame(arg->opcode)) {
        struct wslay_event_msg msgarg = {arg->opcode, arg->msg, arg->msg_length};
        wslay_event_queue_msg(conn->ws_ctx, &msgarg);
    }
}

static int on_req(h2o_handler_t *self, h2o_req_t *req)
{
    const char *client_key;

    if (h2o_is_websocket_handshake(req, &client_key) != 0 || client_key == NULL) {
        return -1;
    }
    h2o_upgrade_to_websocket(req, client_key, NULL, on_ws_message);
    return 0;
}

static h2o_globalconf_t config;
static h2o_context_t ctx;
static h2o_accept_ctx_t accept_ctx;

static void on_connect(uv_stream_t *server, int status)
{
    uv_tcp_t *conn;
    h2o_socket_t *sock;

    if (status != 0)
        return;

    conn = h2o_mem_alloc(sizeof(*conn));
    uv_tcp_init(server->loop, conn);
    if (uv_accept(server, (uv_stream_t *)conn) != 0) {
        uv_close((uv_handle_t *)conn, (uv_close_cb)free);
        return;
    }

    sock = h2o_uv_socket_create((uv_stream_t *)conn, (uv_close_cb)free);
    h2o_accept(&accept_ctx, sock);
}

static int setup_ssl(const char *cert_file, const char *key_file)
{
    SSL_load_error_strings();
    SSL_library_init();
    OpenSSL_add_all_algorithms();

    accept_ctx.ssl_ctx = SSL_CTX_new(SSLv23_server_method());
    SSL_CTX_set_options(accept_ctx.ssl_ctx, SSL_OP_NO_SSLv2);

    /* load certificate and private key */
    if (SSL_CTX_use_certificate_file(accept_ctx.ssl_ctx, cert_file, SSL_FILETYPE_PEM) != 1) {
        fprintf(stderr, "an error occurred while trying to load server certificate file:%s\n", cert_file);
        return -1;
    }
    if (SSL_CTX_use_PrivateKey_file(accept_ctx.ssl_ctx, key_file, SSL_FILETYPE_PEM) != 1) {
        fprintf(stderr, "an error occurred while trying to load private key file:%s\n", key_file);
        return -1;
    }

    return 0;
}

int main(int argc, char **argv)
{
    uv_loop_t *loop = uv_default_loop();
    uv_tcp_t listener;
    struct sockaddr_in sockaddr;
    h2o_hostconf_t *hostconf;
    h2o_pathconf_t *pathconf;
    int r;

    if ((r = uv_tcp_init(loop, &listener)) != 0) {
        fprintf(stderr, "uv_tcp_init:%s\n", uv_strerror(r));
        goto Error;
    }
    uv_ip4_addr("127.0.0.1", 7890, &sockaddr);
    if ((r = uv_tcp_bind(&listener, (struct sockaddr *)&sockaddr, sizeof(sockaddr))) != 0) {
        fprintf(stderr, "uv_tcp_bind:%s\n", uv_strerror(r));
        goto Error;
    }
    if ((r = uv_listen((uv_stream_t *)&listener, 128, on_connect)) != 0) {
        fprintf(stderr, "uv_listen:%s\n", uv_strerror(r));
        goto Error;
    }

    h2o_config_init(&config);
    hostconf = h2o_config_register_host(&config, h2o_iovec_init(H2O_STRLIT("default")), 65535);
    pathconf = h2o_config_register_path(hostconf, "/", 0);
    h2o_create_handler(pathconf, sizeof(h2o_handler_t))->on_req = on_req;

    h2o_context_init(&ctx, loop, &config);

    /* disabled by default: uncomment the block below to use HTTPS instead of HTTP */
    /*
    if (setup_ssl("server.crt", "server.key") != 0)
        goto Error;
    */

    accept_ctx.ctx = &ctx;
    accept_ctx.hosts = config.hosts;

    return uv_run(loop, UV_RUN_DEFAULT);

Error:
    return 1;
}
