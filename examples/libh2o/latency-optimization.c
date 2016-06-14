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
#include <inttypes.h>
#include <netdb.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <openssl/ssl.h>
#include "h2o/socket.h"
#include "h2o/string_.h"

static h2o_loop_t *loop;
static char *host, *port;
static SSL_CTX *ssl_ctx;
static int mode_server, server_flag_received;
static h2o_socket_t *sock;
static struct {
    uint64_t ms;
    uint64_t octets;
} delay;

static void server_write(h2o_socket_t *sock);

static void server_on_read(h2o_socket_t *sock, const char *err)
{
    if (err != NULL) {
        fprintf(stderr, "connection closed unexpectedly:%s\n", err);
        exit(1);
        return;
    }

    server_flag_received = 1;
}

static void server_on_write_ready(h2o_socket_t *sock, const char *err)
{
    if (err != NULL) {
        fprintf(stderr, "socket unexpected closed by peer:%s\n", err);
        exit(1);
        return;
    }
    server_write(sock);
}

static void server_on_write_complete(h2o_socket_t *sock, const char *err)
{
    if (err != NULL) {
        fprintf(stderr, "write failed:%s\n", err);
        exit(1);
        return;
    }
    h2o_socket_notify_write(sock, server_on_write_ready);
}

void server_write(h2o_socket_t *sock)
{
#define BUF_SIZE 65536

    static h2o_socket_latency_optimization_conditions_t cond = {
        .min_rtt              = 50,
        .max_additional_delay = 10,
        .max_cwnd             = 65535,
    };
    static char *buf;

    if (buf == NULL) {
        buf = h2o_mem_alloc(BUF_SIZE);
        memset(buf, '0', BUF_SIZE);
    }
    if (server_flag_received)
        buf[1] = '1';

    size_t sz = h2o_socket_prepare_for_latency_optimized_write(sock, &cond);
    h2o_iovec_t warg = h2o_iovec_init(buf, sz < BUF_SIZE ? sz : BUF_SIZE);
    fprintf(stderr, "writing %zu bytes\n", warg.len);
    h2o_socket_write(sock, &warg, 1, server_on_write_complete);
}

static void client_on_write_complete(h2o_socket_t *sock, const char *err)
{
    if (err == NULL)
        return;
    /* handle error */
    fprintf(stderr, "write failed:%s\n", err);
    h2o_socket_close(sock);
    exit(1);
}

static void client_on_read_second(h2o_socket_t *sock, const char *err)
{
    size_t i;

    if (err != NULL) {
        fprintf(stderr, "connection closed unexpectedly:%s\n", err);
        exit(1);
        return;
    }

    for (i = 0; i != sock->input->size; ++i) {
        if (sock->input->bytes[i] != '0')
            goto FoundSig;
        ++delay.octets;
    }
    return;

FoundSig:
    delay.ms = h2o_now(h2o_socket_get_loop(sock)) - delay.ms;
    printf("Delay: %" PRIu64 " ms, %" PRIu64 " octets\n", delay.ms, delay.octets);
    exit(0);
}

static void client_on_read_first(h2o_socket_t *sock, const char *err)
{
    if (err != NULL) {
        fprintf(stderr, "connection closed unexpectedly:%s\n", err);
        exit(1);
        return;
    }

    h2o_buffer_consume(&sock->input, sock->input->size);
    delay.ms = h2o_now(h2o_socket_get_loop(sock));
    h2o_iovec_t data = {H2O_STRLIT("!")};
    h2o_socket_write(sock, &data, 1, client_on_write_complete);
    h2o_socket_read_start(sock, client_on_read_second);
}

static void on_handshake_complete(h2o_socket_t *sock, const char *err)
{
    if (err != NULL && err != h2o_socket_error_ssl_cert_name_mismatch) {
        /* TLS handshake failed */
        fprintf(stderr, "TLS handshake failure:%s\n", err);
        h2o_socket_close(sock);
        exit(1);
        return;
    }

    if (mode_server) {
        h2o_socket_read_start(sock, server_on_read);
        server_write(sock);
    } else {
        h2o_socket_read_start(sock, client_on_read_first);
    }
}

static void on_connect(h2o_socket_t *sock, const char *err)
{
    if (err != NULL) {
        /* connection failed */
        fprintf(stderr, "failed to connect to host:%s\n", err);
        h2o_socket_close(sock);
        exit(1);
        return;
    }

    if (ssl_ctx != NULL) {
        h2o_socket_ssl_handshake(sock, ssl_ctx, mode_server ? NULL : "blahblah", on_handshake_complete);
    } else {
        on_handshake_complete(sock, NULL);
    }
}

static void on_accept(h2o_socket_t *listener, const char *err)
{
    if (err != NULL)
        return;

    if ((sock = h2o_evloop_socket_accept(listener)) != NULL) {
        h2o_socket_close(listener);
        if (ssl_ctx != NULL) {
            h2o_socket_ssl_handshake(sock, ssl_ctx, NULL, on_handshake_complete);
        } else {
            on_handshake_complete(sock, NULL);
        }
    }
}

static void usage(const char *cmd)
{
    fprintf(stderr, "Usage: %s [--listen] [--reverse-role] [--tls] [<host>:]<port>\n", cmd);
    exit(1);
}

int main(int argc, char **argv)
{
    static const struct option longopts[] = {
        {"listen", no_argument, NULL, 'l'},
        {"reverse-role", no_argument, NULL, 'r'},
        {"tls", no_argument, NULL, 't'},
        {}
    };
    int opt_ch, mode_listen = 0, mode_reverse_role = 0, mode_tls = 0;
    struct addrinfo hints, *res = NULL;
    int err;

    while ((opt_ch = getopt_long(argc, argv, "lrt", longopts, NULL)) != -1) {
        switch (opt_ch) {
        case 'l':
            mode_listen = 1;
            break;
        case 'r':
            mode_reverse_role = 1;
            break;
        case 't':
            mode_tls = 1;
            break;
        default:
            usage(argv[0]);
            break;
        }
    }
    mode_server = mode_listen;
    if (mode_reverse_role)
        mode_server = !mode_server;

    if (argc == optind) {
        usage(argv[0]);
    } else {
        char *hostport = argv[optind], *colon;
        if ((colon = strchr(hostport, ':')) != NULL) {
            hostport = argv[optind];
            host = strdup(hostport);
            host[colon - hostport] = '\0';
            port = colon + 1;
        } else {
            host = "0.0.0.0";
            port = argv[optind];
            hostport = malloc(strlen(host) + strlen(port) + 2);
            sprintf(hostport, "%s:%s", host, port);
        }
    }

    if (mode_tls) {
        SSL_load_error_strings();
        SSL_library_init();
        OpenSSL_add_all_algorithms();
        if (mode_server) {
            ssl_ctx = SSL_CTX_new(TLSv1_server_method());
            SSL_CTX_use_certificate_file(ssl_ctx, H2O_TO_STR(H2O_ROOT) "/examples/h2o/server.crt", SSL_FILETYPE_PEM);
            SSL_CTX_use_PrivateKey_file(ssl_ctx, H2O_TO_STR(H2O_ROOT) "/examples/h2o/server.key", SSL_FILETYPE_PEM);
        } else {
            ssl_ctx = SSL_CTX_new(TLSv1_client_method());
        }
    }

#if H2O_USE_LIBUV
    loop = uv_loop_new();
#else
    loop = h2o_evloop_create();
#endif

    /* resolve host:port (FIXME use the function supplied by the loop) */
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_ADDRCONFIG;
    if ((err = getaddrinfo(host, port, &hints, &res)) != 0) {
        fprintf(stderr, "failed to resolve %s:%s:%s\n", host, port, gai_strerror(err));
        exit(1);
    }

    if (mode_listen) {
        int fd, reuseaddr_flag = 1;
        if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1 ||
            setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr_flag, sizeof(reuseaddr_flag)) != 0 ||
            bind(fd, res->ai_addr, res->ai_addrlen) != 0 || listen(fd, SOMAXCONN) != 0) {
            fprintf(stderr, "failed to listen to %s:%s:%s\n", host, port, strerror(errno));
            exit(1);
        }
        h2o_socket_t *listen_sock = h2o_evloop_socket_create(loop, fd, H2O_SOCKET_FLAG_DONT_READ);
        h2o_socket_read_start(listen_sock, on_accept);
    } else {
        if ((sock = h2o_socket_connect(loop, res->ai_addr, res->ai_addrlen, on_connect)) == NULL) {
            fprintf(stderr, "failed to create socket:%s\n", strerror(errno));
            exit(1);
        }
    }

    while (1) {
#if H2O_USE_LIBUV
        uv_run(loop, UV_RUN_DEFAULT);
#else
        h2o_evloop_run(loop);
#endif
    }

    return 0;
}
