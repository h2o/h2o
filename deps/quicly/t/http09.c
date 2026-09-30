/*
 * Copyright (c) 2026 Kazuho Oku
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
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <time.h>
#include <unistd.h>
#include <openssl/pem.h>
#include "picotls.h"
#include "picotls/openssl.h"

struct statistics {
    uint64_t next_at, bytes;
};

static void fail(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fputc('\n', stderr);
    exit(EXIT_FAILURE);
}

static uint64_t get_now(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        fail("clock_gettime: %s", strerror(errno));
    return (uint64_t)ts.tv_sec * 1000000 + ts.tv_nsec / 1000;
}

static void advance_statistics(struct statistics *s, uint64_t now)
{
    if (now < s->next_at)
        return;
    while (now >= s->next_at) {
        printf("%" PRIu64 "\n", s->bytes);
        s->bytes = 0;
        s->next_at += 1000;
    }
    if (fflush(stdout) != 0 || ferror(stdout))
        fail("writing statistics: %s", strerror(errno));
}

static void configure_socket(int fd, const char *cc, unsigned long pacing)
{
    int on = 1;
    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on)) != 0)
        fail("TCP_NODELAY: %s", strerror(errno));
    if (cc != NULL && setsockopt(fd, IPPROTO_TCP, TCP_CONGESTION, cc, strlen(cc)) != 0)
        fail("TCP_CONGESTION %s: %s", cc, strerror(errno));
    if (pacing != 0 && setsockopt(fd, SOL_SOCKET, SO_MAX_PACING_RATE, &pacing, sizeof(pacing)) != 0)
        fail("SO_MAX_PACING_RATE: %s", strerror(errno));
}

static void send_plaintext(ptls_t *tls, ptls_buffer_t *out, const void *bytes, size_t len)
{
    int ret = ptls_send(tls, out, bytes, len);
    if (ret != 0)
        fail("ptls_send: %d", ret);
}

static void run_connection(int fd, ptls_context_t *ctx, int is_server, struct statistics *stats)
{
    ptls_t *tls = ptls_new(ctx, is_server);
    ptls_buffer_t out, plain;
    size_t written = 0;
    int requested = 0;
    if (tls == NULL)
        fail("allocating TLS connection");
    ptls_buffer_init(&out, "", 0);
    ptls_buffer_init(&plain, "", 0);
    if (fd >= FD_SETSIZE || fcntl(fd, F_SETFL, O_NONBLOCK) != 0)
        fail("setting up socket for select");
    if (!is_server) {
        int ret = ptls_handshake(tls, &out, NULL, NULL, NULL);
        if (ret != PTLS_ERROR_IN_PROGRESS)
            fail("ptls_handshake: %d", ret);
    }

    while (1) {
        if (is_server && requested && out.off == 0) {
            static const char body[16384] = {0};
            send_plaintext(tls, &out, body, sizeof(body));
        }
        fd_set reads, writes;
        FD_ZERO(&reads);
        FD_ZERO(&writes);
        FD_SET(fd, &reads);
        if (out.off != 0)
            FD_SET(fd, &writes);
        struct timeval timeout, *timeoutp = NULL;
        if (!is_server) {
            uint64_t now = get_now();
            advance_statistics(stats, now);
            uint64_t wait = stats->next_at + 999000 - now;
            timeout = (struct timeval){.tv_sec = wait / 1000000, .tv_usec = wait % 1000000};
            timeoutp = &timeout;
        }
        int ret = select(fd + 1, &reads, &writes, NULL, timeoutp);
        if (ret < 0) {
            if (errno == EINTR)
                continue;
            fail("select: %s", strerror(errno));
        }
        if (FD_ISSET(fd, &reads)) {
            uint8_t input[65536];
            ssize_t len = read(fd, input, sizeof(input));
            if (len == 0 || (len < 0 && errno == ECONNRESET))
                break;
            if (len < 0 && errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK)
                fail("read: %s", strerror(errno));
            for (size_t off = 0; len > 0 && off < (size_t)len;) {
                size_t consumed = len - off;
                if (!ptls_handshake_is_complete(tls)) {
                    ret = ptls_handshake(tls, &out, input + off, &consumed, NULL);
                    if (ret == 0 && !is_server) {
                        static const char request[] = "GET /\r\n";
                        send_plaintext(tls, &out, request, sizeof(request) - 1);
                    }
                } else {
                    ret = ptls_receive(tls, &plain, input + off, &consumed);
                    if (!is_server) {
                        advance_statistics(stats, get_now());
                        stats->bytes += plain.off;
                        plain.off = 0;
                    } else if (!requested) {
                        if (memchr(plain.base, '\n', plain.off) != NULL) {
                            if (!((plain.off == 7 && memcmp(plain.base, "GET /\r\n", 7) == 0) ||
                                  (plain.off == 6 && memcmp(plain.base, "GET /\n", 6) == 0)))
                                fail("expected GET /");
                            requested = 1;
                        } else if (plain.off > 7) {
                            fail("expected GET /");
                        }
                    }
                    if (is_server && requested)
                        plain.off = 0;
                }
                if (ret == PTLS_ALERT_TO_PEER_ERROR(PTLS_ALERT_CLOSE_NOTIFY))
                    goto Exit;
                if (ret != 0 && ret != PTLS_ERROR_IN_PROGRESS)
                    fail("TLS receive: %d", ret);
                off += consumed;
            }
        }
        if (FD_ISSET(fd, &writes) && out.off != 0) {
            ssize_t len = write(fd, out.base + written, out.off - written);
            if (len < 0) {
                if (errno == EPIPE || errno == ECONNRESET)
                    break;
                if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK)
                    fail("write: %s", strerror(errno));
            } else if ((written += len) == out.off) {
                out.off = written = 0;
            }
        }
    }
Exit:
    if (!is_server)
        advance_statistics(stats, get_now());
    ptls_buffer_dispose(&plain);
    ptls_buffer_dispose(&out);
    ptls_free(tls);
    close(fd);
}

static void usage(const char *cmd)
{
    printf("Usage: %s [options] server-ip port\n"
           "       %s -c certificate -k key [options] bind-ip port\n"
           "\n"
           "HTTP/0.9 over TLS_AES_128_GCM_SHA256 for TCP congestion-control experiments.\n"
           "The client requests /; the server streams indefinitely, with a child process per client.\n"
           "\n"
           "  -c <file>         server certificate chain (PEM; selects server mode)\n"
           "  -k <file>         server private key (PEM; selects server mode)\n"
           "  -C <algorithm>    TCP congestion control (default: system setting)\n"
           "  -p                enable TCP pacing with a 1 Gbit/s ceiling (default: disabled)\n"
           "  -h                print this help\n"
           "\n"
           "Client stdout: one integer per millisecond, followed by a newline, counting delivered\n"
           "plaintext bytes. Time starts before connect; empty milliseconds emit 0.\n"
           "Output advances on I/O and at least once per second while idle.\n"
           "IPv4 only. The client does not verify certificates.\n",
           cmd, cmd);
}

int main(int argc, char **argv)
{
    ptls_cipher_suite_t *cipher_suites[] = {&ptls_openssl_aes128gcmsha256, NULL};
    ptls_context_t ctx = {.random_bytes = ptls_openssl_random_bytes,
                          .get_time = &ptls_get_time,
                          .key_exchanges = ptls_openssl_key_exchanges,
                          .cipher_suites = cipher_suites};
    const char *cert = NULL, *key = NULL, *cc = NULL;
    unsigned long pacing = 0;
    int ch;
    while ((ch = getopt(argc, argv, "c:k:C:ph")) != -1) {
        switch (ch) {
        case 'c':
            cert = optarg;
            break;
        case 'k':
            key = optarg;
            break;
        case 'C':
            cc = optarg;
            break;
        case 'p':
            pacing = 1000000000 / 8;
            break;
        case 'h':
            usage(argv[0]);
            return 0;
        default:
            return 1;
        }
    }
    unsigned port;
    struct sockaddr_in addr = {.sin_family = AF_INET};
    if (argc - optind != 2)
        fail("expected IPv4 address and port; use -h for help");
    if (inet_pton(AF_INET, argv[optind], &addr.sin_addr) != 1 || sscanf(argv[optind + 1], "%u", &port) != 1 || port == 0 ||
        port > 65535)
        fail("invalid IPv4 address or port");
    addr.sin_port = htons(port);
    int is_server = cert != NULL || key != NULL;
    if (is_server) {
        if (cert == NULL || key == NULL)
            fail("server requires -c certificate and -k key");
        if (ptls_load_certificates(&ctx, cert) != 0)
            fail("loading certificate: %s", cert);
        FILE *fp = fopen(key, "r");
        if (fp == NULL)
            fail("opening private key: %s", strerror(errno));
        EVP_PKEY *pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
        fclose(fp);
        static ptls_openssl_sign_certificate_t signer;
        if (pkey == NULL || ptls_openssl_init_sign_certificate(&signer, pkey) != 0)
            fail("loading private key: %s", key);
        EVP_PKEY_free(pkey);
        ctx.sign_certificate = &signer.super;
    }
    signal(SIGPIPE, SIG_IGN);
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        fail("socket: %s", strerror(errno));
    if (!is_server) {
        configure_socket(fd, cc, pacing);
        struct statistics stats = {.next_at = get_now() + 1000};
        if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0)
            fail("connect: %s", strerror(errno));
        run_connection(fd, &ctx, 0, &stats);
    } else {
        int on = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) != 0 ||
            bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0 || listen(fd, SOMAXCONN) != 0)
            fail("listen: %s", strerror(errno));
        signal(SIGCHLD, SIG_IGN);
        while (1) {
            int conn = accept(fd, NULL, NULL);
            if (conn < 0) {
                if (errno == EINTR)
                    continue;
                fail("accept: %s", strerror(errno));
            }
            pid_t pid = fork();
            if (pid < 0)
                fail("fork: %s", strerror(errno));
            if (pid == 0) {
                close(fd);
                configure_socket(conn, cc, pacing);
                run_connection(conn, &ctx, 1, NULL);
                return 0;
            }
            close(conn);
        }
    }
    return 0;
}
