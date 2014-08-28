#include <alloca.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <uv.h>
#include "h2o.h"
#include "h2o/http1.h"
#include "h2o/http2.h"

static void on_req(h2o_req_t *req)
{
    if (req->upgrade.base != NULL && h2o_lcstris(req->upgrade.base, req->upgrade.len, H2O_STRLIT("h2c-14"))) {
        h2o_http2_conn_t *conn = malloc(sizeof(*conn));
        if (h2o_http2_handle_upgrade(conn, req, on_req, h2o_http2_close_and_free) == 0) {
            return;
        }
        free(conn);
    }

    if (h2o_memis(req->method, req->method_len, H2O_STRLIT("GET"))
        && req->path_len <= PATH_MAX) {

        /* normalize path */
        uv_buf_t path_normalized = h2o_normalize_path(&req->pool, req->path, req->path_len);
        /* send file (FIXME handle directory traversal) */
        char *dir_path = alloca(path_normalized.len + sizeof(".index.html"));
        size_t dir_path_len;
        uv_buf_t mime_type;
        dir_path[0] = '.';
        memcpy(dir_path + 1, path_normalized.base, path_normalized.len);
        dir_path_len = path_normalized.len + 1;
        if (dir_path[dir_path_len - 1] == '/') {
            strcpy(dir_path + dir_path_len, "index.html");
            dir_path_len += sizeof("index.html") - 1;
        } else {
            dir_path[dir_path_len] = '\0';
        }
        mime_type = h2o_get_mimetype(&req->conn->ctx->mimemap, h2o_get_filext(dir_path, dir_path_len));
        if (h2o_send_file(req, 200, "OK", dir_path, &mime_type) != 0) {
            h2o_send_error(req, 404, "File Not Found", "not found");
        }

    } else if (h2o_memis(req->method, req->method_len, H2O_STRLIT("POST"))
        && h2o_memis(req->path, req->path_len, H2O_STRLIT("/post-test"))) {

        /* post-test */
        req->res.status = 200;
        req->res.reason = "OK";
        h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_CONTENT_TYPE, H2O_STRLIT("text/plain; charset=utf-8"));
        h2o_send_inline(req, req->entity.base, req->entity.len);

    } else {
        h2o_send_error(req, 403, "Request Forbidden", "only GET is allowed");
    }
}

static h2o_loop_context_t loop_ctx;

static void on_connect(uv_stream_t *server, int status)
{
    uv_tcp_t *tcp;
    h2o_http1_conn_t *conn;

    if (status == -1) {
        return;
    }

    tcp = malloc(sizeof(*tcp));
    uv_tcp_init(server->loop, tcp);
    if (uv_accept(server, (uv_stream_t*)tcp) != 0) {
        uv_close((uv_handle_t*)tcp, (uv_close_cb)free);
        return;
    }

    conn = malloc(sizeof(*conn));
    h2o_http1_init(conn, (uv_stream_t*)tcp, &loop_ctx, on_req, h2o_http1_close_and_free);
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

    h2o_loop_context_init(&loop_ctx, loop);
    h2o_define_mimetype(&loop_ctx.mimemap, "html", "text/html");
    h2o_add_reproxy_url(&loop_ctx);

    return uv_run(loop, UV_RUN_DEFAULT);

Error:
    return 1;
}
