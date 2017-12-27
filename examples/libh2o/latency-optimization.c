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
#include <netinet/in.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include "h2o/socket.h"
#include "h2o/string_.h"

/* configuration */
static char *host, *port;
static SSL_CTX *ssl_ctx;
static int mode_server, server_flag_received;
static h2o_socket_latency_optimization_conditions_t latopt_cond = {.min_rtt = 50, .max_additional_delay = 10, .max_cwnd = 65535};
size_t write_block_size = 65536;

/* globals */
static h2o_loop_t *loop;
static h2o_socket_t *sock;
static struct {
    uint64_t resp_start_at;
    uint64_t sig_received_at;
    uint64_t bytes_received;
    uint64_t bytes_before_sig;
} client_stats;

static void server_write(h2o_socket_t *sock);

static h2o_iovec_t prepare_write_buf(void)
{
    static h2o_iovec_t buf;
    if (buf.base == NULL) {
        buf.base = h2o_mem_alloc(write_block_size);
        buf.len = write_block_size;
        memset(buf.base, '0', buf.len);
    }
    return buf;
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
    size_t sz = h2o_socket_prepare_for_latency_optimized_write(sock, &latopt_cond);
    h2o_iovec_t buf = prepare_write_buf();

    if (server_flag_received)
        buf.base[0] = '1';
    if (sz < buf.len)
        buf.len = sz;

    fprintf(stderr, "writing %zu bytes\n", buf.len);
    h2o_socket_write(sock, &buf, 1, server_on_write_complete);
}

static void server_on_read_second(h2o_socket_t *sock, const char *err)
{
    if (err != NULL) {
        fprintf(stderr, "connection closed unexpectedly:%s\n", err);
        exit(1);
        return;
    }

    fprintf(stderr, "received the flag\n");
    server_flag_received = 1;
}

static void server_on_read_first(h2o_socket_t *sock, const char *err)
{
    if (err != NULL) {
        fprintf(stderr, "connection closed unexpectedly:%s\n", err);
        exit(1);
        return;
    }

    server_write(sock);
    h2o_socket_read_start(sock, server_on_read_second);
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

    if (client_stats.sig_received_at == 0) {
        for (i = 0; i != sock->input->size; ++i) {
            if (sock->input->bytes[i] != '0') {
                client_stats.sig_received_at = h2o_now(h2o_socket_get_loop(sock));
                break;
            }
            ++client_stats.bytes_before_sig;
        }
    }
    client_stats.bytes_received += sock->input->size;
    h2o_buffer_consume(&sock->input, sock->input->size);

    if (client_stats.bytes_received >= 1024 * 1024) {
        uint64_t now = h2o_now(h2o_socket_get_loop(sock));
        printf("Delay: %" PRIu64 " octets, %" PRIu64 " ms\n", client_stats.bytes_before_sig,
               client_stats.sig_received_at - client_stats.resp_start_at);
        printf("Total: %" PRIu64 " octets, %" PRIu64 " ms\n", client_stats.bytes_received, now - client_stats.resp_start_at);
        exit(0);
    }
}

static void client_on_read_first(h2o_socket_t *sock, const char *err)
{
    if (err != NULL) {
        fprintf(stderr, "connection closed unexpectedly:%s\n", err);
        exit(1);
        return;
    }

    client_stats.resp_start_at = h2o_now(h2o_socket_get_loop(sock));
    client_stats.bytes_before_sig = sock->input->size;
    client_stats.bytes_received = sock->input->size;
    h2o_buffer_consume(&sock->input, sock->input->size);

    h2o_iovec_t data = {H2O_STRLIT("!")};
    h2o_socket_write(sock, &data, 1, client_on_write_complete);
    h2o_socket_read_start(sock, client_on_read_second);
}

static void on_handshake_complete(h2o_socket_t *sock, const char *err)
{
    if (err != NULL && err != h2o_socket_error_ssl_cert_name_mismatch) {
        /* TLS handshake failed */
        fprintf(stderr, "TLS handshake failure:%s\n", err);
        ERR_print_errors_fp(stderr);
        h2o_socket_close(sock);
        exit(1);
        return;
    }

    if (mode_server) {
        h2o_socket_read_start(sock, server_on_read_first);
    } else {
        h2o_iovec_t buf = {H2O_STRLIT("0")};
        h2o_socket_write(sock, &buf, 1, client_on_write_complete);
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
            h2o_socket_ssl_handshake(sock, ssl_ctx, mode_server ? NULL : "blahblah", on_handshake_complete);
        } else {
            on_handshake_complete(sock, NULL);
        }
    }
}

static void usage(const char *cmd)
{
    fprintf(stderr, "Usage: %s [opts] [<host>:]<port>\n"
                    "Options: --listen             if set, waits for incoming connection. Otherwise,\n"
                    "                              connects to the server running at given address\n"
                    "         --reverse-role       if set, reverses the role bet. server and the\n"
                    "                              client once the connection is established\n"
                    "         --tls                use TLS\n"
                    "         --block-size=octets  default write block size\n"
                    "         --min-rtt=ms         minimum RTT to enable latency optimization\n"
                    "         --max-cwnd=octets    maximum size of CWND to enable latency\n"
                    "                              optimization\n",
            cmd);
    exit(1);
}

int main(int argc, char **argv)
{
    static const struct option longopts[] = {{"listen", no_argument, NULL, 'l'},
                                             {"reverse-role", no_argument, NULL, 'r'},
                                             {"tls", no_argument, NULL, 't'},
                                             {"block-size", no_argument, NULL, 'b'},
                                             {"min-rtt", required_argument, NULL, 'R'},
                                             {"max-cwnd", required_argument, NULL, 'c'},
                                             {}};
    int opt_ch, mode_listen = 0, mode_reverse_role = 0, mode_tls = 0;
    struct addrinfo hints, *res = NULL;
    int err;

    while ((opt_ch = getopt_long(argc, argv, "lrtb:R:c:", longopts, NULL)) != -1) {
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
        case 'b':
            if (sscanf(optarg, "%zu", &write_block_size) != 1) {
                fprintf(stderr, "write block size (-b) must be a non-negative number of octets\n");
                exit(1);
            }
            break;
        case 'R':
            if (sscanf(optarg, "%u", &latopt_cond.min_rtt) != 1) {
                fprintf(stderr, "min RTT (-m) must be a non-negative number in milliseconds\n");
                exit(1);
            }
            break;
        case 'c':
            if (sscanf(optarg, "%u", &latopt_cond.max_cwnd) != 1) {
                fprintf(stderr, "max CWND size must be a non-negative number of octets\n");
                exit(1);
            }
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
        }
    }

    if (mode_tls) {
        SSL_load_error_strings();
        SSL_library_init();
        OpenSSL_add_all_algorithms();
        if (mode_server) {
            ssl_ctx = SSL_CTX_new(SSLv23_server_method());
            SSL_CTX_use_certificate_file(ssl_ctx, "examples/h2o/server.crt", SSL_FILETYPE_PEM);
            SSL_CTX_use_PrivateKey_file(ssl_ctx, "examples/h2o/server.key", SSL_FILETYPE_PEM);
        } else {
            ssl_ctx = SSL_CTX_new(SSLv23_client_method());
        }
        int nid = NID_X9_62_prime256v1;
        EC_KEY *key = EC_KEY_new_by_curve_name(nid);
        if (key == NULL) {
            fprintf(stderr, "Failed to create curve \"%s\"\n", OBJ_nid2sn(nid));
            exit(1);
        }
        SSL_CTX_set_tmp_ecdh(ssl_ctx, key);
        EC_KEY_free(key);
        SSL_CTX_set_options(ssl_ctx, SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
        SSL_CTX_set_cipher_list(ssl_ctx, "ECDHE-RSA-AES128-GCM-SHA256");
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
        h2o_evloop_run(loop, INT32_MAX);
#endif
    }

    return 0;
}
