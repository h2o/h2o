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
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include "h2o/socket.h"

static h2o_loop_t *loop;
static int exit_loop;

static void on_read(h2o_socket_t *sock, int status)
{
    if (status != 0) {
        /* read failed */
        fprintf(stderr, "read failed\n");
        h2o_socket_close(sock);
        exit_loop = 1;
        return;
    }

    fwrite(sock->input->bytes, 1, sock->input->size, stdout);
}

static void on_write(h2o_socket_t *sock, int status)
{
    if (status != 0) {
        /* write failed */
        fprintf(stderr, "write failed\n");
        h2o_socket_close(sock);
        exit_loop = 1;
        return;
    }

    h2o_socket_read_start(sock, on_read);
}

static void on_connect(h2o_socket_t *sock, int status)
{
    h2o_buf_t *send_data = sock->data;

    if (status != 0) {
        /* connection failed */
        fprintf(stderr, "failed to connect to host:%s\n", strerror(status));
        h2o_socket_close(sock);
        exit_loop = 1;
        return;
    }

    h2o_socket_write(sock, send_data, 1, on_write);
}

int main(int argc, char **argv)
{
    struct addrinfo hints, *res = NULL;
    int err, ret = 1;
    h2o_socket_t *sock;
    h2o_buf_t send_data = { H2O_STRLIT("GET / HTTP/1.0\r\n\r\n") };

    if (argc != 3) {
        fprintf(stderr, "Usage: %s <host> <port>\n", argv[0]);
        goto Exit;
    }

#if H2O_USE_LIBUV
    loop = uv_loop_new();
#else
    loop = h2o_evloop_create();
#endif

    /* resolve destination (FIXME use the function supplied by the loop) */
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_ADDRCONFIG;
    if ((err = getaddrinfo(argv[1], argv[2], &hints, &res)) != 0) {
        fprintf(stderr, "failed to resolve %s:%s:%s\n", argv[1], argv[2], gai_strerror(err));
        goto Exit;
    }

    if ((sock = h2o_socket_connect(loop, res->ai_addr, res->ai_addrlen, on_connect)) == NULL) {
        fprintf(stderr, "failed to create socket:%s\n", strerror(errno));
        goto Exit;
    }
    sock->data = &send_data;

    while (! exit_loop) {
#if H2O_USE_LIBUV
        uv_run(loop, UV_RUN_DEFAULT);
#else
        h2o_evloop_run(loop);
#endif
    }

    ret = 0;

Exit:
    if (loop != NULL) {
#if H2O_USE_LIBUV
        uv_loop_delete(loop);
#else
        // FIXME
        //h2o_evloop_destroy(loop);
#endif
    }
    return ret;
}
