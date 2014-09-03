#include <alloca.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <uv.h>
#include "h2o.h"
#include "h2o/http2.h"

static void on_req(h2o_req_t *req)
{
    if (h2o_memis(req->method, req->method_len, H2O_STRLIT("GET"))
        && req->path_len <= PATH_MAX) {

        if (h2o_memis(req->path, req->path_len, H2O_STRLIT("/chunked-test"))) {

            /* chunked test */
            uv_buf_t body = h2o_strdup(&req->pool, "hello world\n", SIZE_MAX);
            req->res.status = 200;
            req->res.reason = "OK";
            h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_CONTENT_TYPE, H2O_STRLIT("text/plain"));
            h2o_start_response(req, sizeof(h2o_generator_t));
            h2o_send(req, &body, 1, 1);

        } else if (h2o_memis(req->path, req->path_len, H2O_STRLIT("/reproxy-test"))) {

            /* reproxy-test */
            req->res.status = 200;
            req->res.reason = "OK";
            h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_X_REPROXY_URL, H2O_STRLIT("http://example.com:81/bar"));
            h2o_send_inline(req, H2O_STRLIT("you should never see this!\n"));

        } else {

            /* normalize path */
            uv_buf_t path_normalized = h2o_normalize_path(&req->pool, req->path, req->path_len);
            /* send file (FIXME handle directory traversal) */
            char *dir_path = alloca(path_normalized.len + sizeof("htdocsindex.html"));
            size_t dir_path_len;
            uv_buf_t mime_type;
            strcpy(dir_path, "htdocs");
            memcpy(dir_path + 6, path_normalized.base, path_normalized.len);
            dir_path_len = path_normalized.len + 6;
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

        }

    } else if (h2o_memis(req->method, req->method_len, H2O_STRLIT("POST"))
        && h2o_memis(req->path, req->path_len, H2O_STRLIT("/post-test"))) {

        /* post-test */
        req->res.status = 200;
        req->res.reason = "OK";
        h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_CONTENT_TYPE, H2O_STRLIT("text/plain; charset=utf-8"));
        h2o_start_response(req, sizeof(h2o_generator_t));
        h2o_send(req, req->entity.entries, req->entity.size, 1);

    } else {
        h2o_send_error(req, 403, "Request Forbidden", "only GET is allowed");
    }
}

static h2o_loop_context_t loop_ctx;

static void on_connect(uv_stream_t *server, int status)
{
    h2o_socket_t *sock;

    if (status == -1) {
        return;
    }

    if ((sock = h2o_socket_accept(server)) == NULL) {
        return;
    }
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

    h2o_loop_context_init(&loop_ctx, loop, on_req);
    h2o_define_mimetype(&loop_ctx.mimemap, "html", "text/html");
    h2o_add_reproxy_url(&loop_ctx);
    //loop_ctx.ssl_ctx = h2o_ssl_new_server_context("server.crt", "server.key", h2o_http2_tls_identifiers);
    //loop_ctx.access_log = h2o_open_access_log(loop, "/dev/stdout");

    return uv_run(loop, UV_RUN_DEFAULT);

Error:
    return 1;
}
