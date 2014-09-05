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
#ifdef _WIN32
# include <ws2tcpip.h>
# include <malloc.h>
# include <stdio.h>
#else
# include <alloca.h>
# include <errno.h>
# include <limits.h>
# include <netinet/in.h>
# include <stdio.h>
# include <stdlib.h>
# include <sys/socket.h>
# include <sys/stat.h>
#endif
#include "h2o.h"
#include "h2o/http2.h"

static void on_req(h2o_req_t *req)
{
    if (h2o_memis(req->method, req->method_len, H2O_STRLIT("GET"))
        && req->path_len <= PATH_MAX) {

        if (h2o_memis(req->path, req->path_len, H2O_STRLIT("/chunked-test"))) {

            /* chunked test */
            h2o_buf_t body = h2o_strdup(&req->pool, "hello world\n", SIZE_MAX);
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
            h2o_buf_t path_normalized = h2o_normalize_path(&req->pool, req->path, req->path_len);
            /* send file (FIXME handle directory traversal) */
            char *dir_path = alloca(path_normalized.len + sizeof("htdocsindex.html"));
            size_t dir_path_len;
            h2o_buf_t mime_type;
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

static void on_accept(h2o_socket_t *listener, int status)
{
    h2o_socket_t *sock;

    if (status == -1) {
        return;
    }

    if ((sock = h2o_socket_accept(listener)) == NULL) {
        return;
    }
    h2o_accept(&loop_ctx, sock);
}

static int create_listener(void)
{
    struct sockaddr_in addr;
    int fd;
#ifdef _WIN32
    char reuseaddr_flag = 1;
#else
    int reuseaddr_flag = 1;
#endif
    h2o_socket_t *sock;

    h2o_loop_context_init(&loop_ctx, on_req);

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(0x7f000001);
    addr.sin_port = htons(7890);

    if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1
        || setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr_flag, sizeof(reuseaddr_flag)) != 0
        || bind(fd, (struct sockaddr*)&addr, sizeof(addr)) != 0
        || listen(fd, SOMAXCONN) != 0) {
        return -1;
    }

    sock = h2o_socket_create(loop_ctx.socket_loop, fd);
    sock->_flags |= H2O_SOCKET_FLAG_IS_ACCEPT;
    h2o_socket_read_start(sock, on_accept);

    return 0;
}

int main(int argc, char **argv)
{
#ifdef _WIN32
	WSADATA wsaData;
	WSAStartup(MAKEWORD(2, 0), &wsaData);
#endif
    h2o_loop_context_init(&loop_ctx, on_req);
    h2o_define_mimetype(&loop_ctx.mimemap, "html", "text/html");
    h2o_add_reproxy_url(&loop_ctx);
    //loop_ctx.ssl_ctx = h2o_ssl_new_server_context("server.crt", "server.key", h2o_http2_tls_identifiers);
    //loop_ctx.access_log = h2o_open_access_log(loop, "/dev/stdout");

    if (create_listener() != 0) {
        fprintf(stderr, "failed to listen to 127.0.0.1:7890:%s\n", strerror(errno));
        goto Error;
    }

    while (h2o_loop_context_run(&loop_ctx) == 0)
        ;

Error:
    return 1;
}
