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
#include <getopt.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include "h2o/socket.h"
#include "h2o/string_.h"

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
    h2o_buffer_consume(&sock->input, sock->input->size);
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

int main(int argc, char **argv)
{
    struct addrinfo hints, *res = NULL;
    int optch, err, skip_verify = 0;
    h2o_socket_t *sock;
    h2o_iovec_t send_data = {H2O_STRLIT("GET / HTTP/1.0\r\n\r\n")};

    static struct option longopts[] = {{"tls", no_argument, NULL, 't'},
                                       {"insecure", no_argument, NULL, 'k'},
                                       {"stdin", no_argument, NULL, 's'},
                                       {"help", no_argument, NULL, 'h'},
                                       {}};
    while ((optch = getopt_long(argc, argv, "tksh", longopts, NULL)) != -1) {
        switch (optch) {
        case 't':
            SSL_load_error_strings();
            SSL_library_init();
            OpenSSL_add_all_algorithms();
            ssl_ctx = SSL_CTX_new(SSLv23_client_method());
            SSL_CTX_load_verify_locations(ssl_ctx, H2O_TO_STR(H2O_ROOT) "/share/h2o/ca-bundle.crt", NULL);
            break;
        case 'k':
            skip_verify = 1;
            break;
        case 's': {
            send_data = h2o_iovec_init(NULL, 0);
            while (1) {
                size_t new_capacity = send_data.len == 0 ? 1024 : send_data.len * 2;
                send_data.base = h2o_mem_realloc(send_data.base, new_capacity);
                size_t nread = fread(send_data.base + send_data.len, 1, new_capacity - send_data.len, stdin);
                if (nread == 0)
                    break;
                send_data.len += nread;
            }
        } break;
        case 'h':
            printf("Usage: %s [options] host port\n"
                   "Options:\n"
                   "  -t, --tls       use TLS\n"
                   "  -k, --insecure  ignore TLS certificate errors\n"
                   "  -s, --stdin     read data to be sent from STDIN\n"
                   "  -h, --help      print this help\n"
                   "\n",
                   argv[0]);
            exit(0);
        default:
            exit(1);
        }
    }
    argc -= optind;
    argv += optind;

    if (argc < 2) {
        fprintf(stderr, "host port not provided\n");
        exit(1);
    }
    host = argv[0];

    if (ssl_ctx != NULL && !skip_verify)
        SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

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
    if ((err = getaddrinfo(host, argv[1], &hints, &res)) != 0) {
        fprintf(stderr, "failed to resolve %s:%s:%s\n", host, argv[1], gai_strerror(err));
        exit(1);
    }

    if ((sock = h2o_socket_connect(loop, res->ai_addr, res->ai_addrlen, on_connect, NULL)) == NULL) {
        fprintf(stderr, "failed to create socket:%s\n", strerror(errno));
        exit(1);
    }
    sock->data = &send_data;

    while (!exit_loop) {
#if H2O_USE_LIBUV
        uv_run(loop, UV_RUN_DEFAULT);
#else
        h2o_evloop_run(loop, INT32_MAX);
#endif
    }

    return 0;
}
