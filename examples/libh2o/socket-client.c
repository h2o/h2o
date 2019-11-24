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
#include "h2o/string_.h"
#include "h2o/hostinfo.h"

static h2o_loop_t *loop;
const char *host;
static SSL_CTX *ssl_ctx;
static int exit_loop;

static void on_read(h2o_socket_t *sock, const char *err)
{
    if (err != NULL) {
        /* read failed */
        fprintf(stderr, "read failed:%s\n", err);
        h2o_socket_close(sock);
        exit_loop = 1;
        return;
    }

    fwrite(sock->input->bytes, 1, sock->input->size, stdout);
}

static void on_write(h2o_socket_t *sock, const char *err)
{
    if (err != NULL) {
        /* write failed */
        fprintf(stderr, "write failed:%s\n", err);
        h2o_socket_close(sock);
        exit_loop = 1;
        return;
    }

    h2o_socket_read_start(sock, on_read);
}

static void on_handshake_complete(h2o_socket_t *sock, const char *err)
{
    if (err != NULL) {
        /* TLS handshake failed */
        fprintf(stderr, "TLS handshake failure:%s\n", err);
        h2o_socket_close(sock);
        exit_loop = 1;
        return;
    }

    h2o_socket_write(sock, sock->data, 1, on_write);
}

static void on_connect(h2o_socket_t *sock, const char *err)
{
    if (err != NULL) {
        /* connection failed */
        fprintf(stderr, "failed to connect to host:%s\n", err);
        h2o_socket_close(sock);
        exit_loop = 1;
        return;
    }

    if (ssl_ctx != NULL) {
        h2o_socket_ssl_handshake(sock, ssl_ctx, host, h2o_iovec_init(NULL, 0), on_handshake_complete);
    } else {
        h2o_socket_write(sock, sock->data, 1, on_write);
    }
}

static void on_getaddr(h2o_hostinfo_getaddr_req_t *getaddr_req, const char *errstr, struct addrinfo *res, void *cbdata)
{
    static h2o_iovec_t send_data = {H2O_STRLIT("GET / HTTP/1.0\r\n\r\n")};
    if (errstr != NULL) {
        /* connection failed */
        fprintf(stderr, "failed to resolve address:%s\n", errstr);
        exit_loop = 1;
        return;
    }

    struct addrinfo *selected = h2o_hostinfo_select_one(res);

    h2o_socket_t *sock;
    if ((sock = h2o_socket_connect(loop, selected->ai_addr, selected->ai_addrlen, on_connect)) == NULL) {
        fprintf(stderr, "failed to create socket:%s\n", strerror(errno));
        exit_loop = 1;
        return;
    }
    sock->data = &send_data;
}

static void usage(const char *cmd)
{
    fprintf(stderr, "Usage: %s [--tls] <host> <port>\n", cmd);
    exit(1);
}

int main(int argc, char **argv)
{
    h2o_multithread_receiver_t getaddr_receiver;
    h2o_multithread_queue_t *queue;
    int ret = 1;

    const char *cmd = (--argc, *argv++);
    if (argc < 2)
        usage(cmd);
    if (strcmp(*argv, "-t") == 0 || strcmp(*argv, "--tls") == 0) {
        --argc, ++argv;
        SSL_load_error_strings();
        SSL_library_init();
        OpenSSL_add_all_algorithms();
        ssl_ctx = SSL_CTX_new(TLSv1_client_method());

        /* obtain root */
        char *root;
        if ((root = getenv("H2O_ROOT")) == NULL)
            root = H2O_TO_STR(H2O_ROOT);
#define CA_PATH "/share/h2o/ca-bundle.crt"
        static char crt_fullpath[256];
        snprintf(crt_fullpath, sizeof(crt_fullpath), "%s%s", root, CA_PATH);
#undef CA_PATH
        SSL_CTX_load_verify_locations(ssl_ctx, crt_fullpath, NULL);
        SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    }
    if (argc != 2)
        usage(cmd);
    host = (--argc, *argv++);
    const char *port = (--argc, *argv++);

#if H2O_USE_LIBUV
    loop = uv_loop_new();
#else
    loop = h2o_evloop_create();
#endif

    queue = h2o_multithread_create_queue(loop);
    h2o_multithread_register_receiver(queue, &getaddr_receiver, h2o_hostinfo_getaddr_receiver);

    /* resolve the name, and connect */
    h2o_hostinfo_getaddr(&getaddr_receiver, h2o_iovec_init(host, strlen(host)), h2o_iovec_init(port, strlen(port)), AF_UNSPEC,
                         SOCK_STREAM, IPPROTO_TCP, AI_ADDRCONFIG, on_getaddr, NULL);

    while (!exit_loop) {
#if H2O_USE_LIBUV
        uv_run(loop, UV_RUN_DEFAULT);
#else
        h2o_evloop_run(loop, INT32_MAX);
#endif
    }

    ret = 0;

    h2o_multithread_unregister_receiver(queue, &getaddr_receiver);
    h2o_multithread_destroy_queue(queue);

#if H2O_USE_LIBUV
    uv_loop_delete(loop);
#else
    h2o_evloop_destroy(loop);
#endif
    extern void h2o_cleanup_thread(void);
    h2o_cleanup_thread();
    return ret;
}
