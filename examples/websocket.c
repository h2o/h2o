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

static void on_req(h2o_req_t *req)
{
    const char *client_key;

    if (h2o_is_websocket_handshake(req, &client_key) != 0) {
        /* error, response is sent by  */
        h2o_send_error(req, 400, "Invalid Request", "broken websocket handshake");
        return;
    }
    if (client_key != NULL) {
        h2o_upgrade_to_websocket((h2o_http1_conn_t*)req->conn, client_key, NULL, on_ws_message);
    } else {
        h2o_send_error(req, 404, "File Not Found", "not found");
    }
}

static h2o_loop_context_t loop_ctx;

static void on_connect(uv_stream_t *server, int status)
{
    h2o_socket_t *sock;

    if (status == -1)
        return;

    if ((sock = h2o_socket_accept(server)) == NULL)
        return;

    h2o_accept(&loop_ctx, sock);
}

int main(int argc, char **argv)
{
    uv_loop_t *loop = uv_default_loop();
    uv_tcp_t listener;

    if (uv_tcp_init(loop, &listener) != 0) {
        fprintf(stderr, "uv_tcp_init:%s\n", uv_strerror(uv_last_error(loop)));
        goto Error;
    }
    if (uv_tcp_bind(&listener, uv_ip4_addr("127.0.0.1", 7890)) != 0) {
        fprintf(stderr, "uv_tcp_bind:%s\n", uv_strerror(uv_last_error(loop)));
        goto Error;
    }
    if (uv_listen((uv_stream_t*)&listener, 128, (uv_connection_cb)on_connect) != 0) {
        fprintf(stderr, "uv_listen:%s\n", uv_strerror(uv_last_error(loop)));
        goto Error;
    }

    //h2o_loop_context_init(&loop_ctx, loop, on_req);
    loop_ctx.ssl_ctx = h2o_ssl_new_server_context("server.crt", "server.key", NULL);

    return uv_run(loop, UV_RUN_DEFAULT);

Error:
    return 1;
}
