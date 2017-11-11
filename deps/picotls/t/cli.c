/*
 * Copyright (c) 2016 DeNA Co., Ltd., Kazuho Oku
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
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700 /* required for glibc to use getaddrinfo, etc. */
#endif

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/engine.h>
#include <openssl/pem.h>
#include "picotls.h"
#include "picotls/openssl.h"
#include "util.h"

static int write_all(int fd, const uint8_t *data, size_t len)
{
    ssize_t wret;

    while (len != 0) {
        while ((wret = write(fd, data, len)) == -1 && errno == EINTR)
            ;
        if (wret <= 0)
            return -1;
        data += wret;
        len -= wret;
    }

    return 0;
}

static int run_handshake(int fd, ptls_t *tls, ptls_buffer_t *wbuf, uint8_t *pending_input, size_t *pending_input_len,
                         ptls_handshake_properties_t *hsprop, ptls_iovec_t early_data)
{
    size_t pending_input_bufsz = *pending_input_len;
    int ret;
    ssize_t rret = 0;

    *pending_input_len = 0;

    while ((ret = ptls_handshake(tls, wbuf, pending_input, pending_input_len, hsprop)) == PTLS_ERROR_IN_PROGRESS) {
        /* send early-data if possible */
        if (early_data.len != 0) {
            if (hsprop->client.max_early_data_size != NULL && early_data.len <= *hsprop->client.max_early_data_size) {
                if ((ret = ptls_send(tls, wbuf, early_data.base, early_data.len)) != 0) {
                    fprintf(stderr, "ptls_send(early_data): %d\n", ret);
                    return ret;
                }
            }
            early_data.len = 0; /* do not send twice! */
        }
        /* write to socket */
        if (write_all(fd, wbuf->base, wbuf->off) != 0)
            return -1;
        wbuf->off = 0;
        /* read from socket */
        while ((rret = read(fd, pending_input, pending_input_bufsz)) == -1 && errno == EINTR)
            ;
        if (rret <= 0)
            return -1;
        *pending_input_len = rret;
    }

    if (write_all(fd, wbuf->base, wbuf->off) != 0)
        return -1;

    if (ret != 0) {
        fprintf(stderr, "ptls_handshake:%d\n", ret);
        return -1;
    }

    if (rret != *pending_input_len)
        memmove(pending_input, pending_input + *pending_input_len, rret - *pending_input_len);
    *pending_input_len = rret - *pending_input_len;
    return 0;
}

static int decrypt_and_print(ptls_t *tls, const uint8_t *input, size_t inlen)
{
    ptls_buffer_t decryptbuf;
    uint8_t decryptbuf_small[1024];
    int ret;

    ptls_buffer_init(&decryptbuf, decryptbuf_small, sizeof(decryptbuf_small));

    while (inlen != 0) {
        size_t consumed = inlen;
        if ((ret = ptls_receive(tls, &decryptbuf, input, &consumed)) != 0) {
            fprintf(stderr, "ptls_receive:%d\n", ret);
            ret = -1;
            goto Exit;
        }
        input += consumed;
        inlen -= consumed;
        if (decryptbuf.off != 0) {
            if (write_all(1, decryptbuf.base, decryptbuf.off) != 0) {
                ret = -1;
                goto Exit;
            }
            decryptbuf.off = 0;
        }
    }

    ret = 0;

Exit:
    ptls_buffer_dispose(&decryptbuf);
    return ret;
}

static int handle_connection(int fd, ptls_context_t *ctx, const char *server_name, ptls_handshake_properties_t *hsprop)
{
    ptls_t *tls = ptls_new(ctx, server_name == NULL);
    uint8_t rbuf[1024], wbuf_small[1024], early_data[1024];
    ptls_buffer_t wbuf;
    int stdin_closed = 0, ret;
    size_t early_data_size = 0, roff;
    ssize_t rret;

    if (server_name != NULL)
        ptls_set_server_name(tls, server_name, 0);

    if (server_name != NULL && hsprop->client.max_early_data_size != NULL) {
        /* using early data */
        if ((rret = read(0, early_data, sizeof(early_data))) > 0)
            early_data_size = rret;
    }

    ptls_buffer_init(&wbuf, wbuf_small, sizeof(wbuf_small));

    roff = sizeof(rbuf);
    if (run_handshake(fd, tls, &wbuf, rbuf, &roff, hsprop, ptls_iovec_init(early_data, early_data_size)) != 0)
        goto Exit;
    wbuf.off = 0;

    /* re-send early data if necessary */
    if (early_data_size != 0 && !hsprop->client.early_data_accepted_by_peer) {
        if ((ret = ptls_send(tls, &wbuf, early_data, early_data_size)) != 0) {
            fprintf(stderr, "ptls_send:%d\n", ret);
            goto Exit;
        }
        if (write_all(fd, wbuf.base, wbuf.off) != 0)
            goto Exit;
        wbuf.off = 0;
    }

    /* process pending post-handshake data (if any) */
    if (decrypt_and_print(tls, rbuf, roff) != 0)
        goto Exit;
    roff = 0;

    /* do the communication */
    while (1) {

        /* wait for either of STDIN or read-side of the socket to become available */
        fd_set readfds;
        FD_ZERO(&readfds);
        if (!stdin_closed)
            FD_SET(0, &readfds);
        FD_SET(fd, &readfds);
        if (select(fd + 1, &readfds, NULL, NULL, NULL) <= 0)
            continue;

        if (FD_ISSET(0, &readfds)) {
            /* read from stdin, encrypt and send */
            while ((rret = read(0, rbuf, sizeof(rbuf))) == -1 && errno == EINTR)
                ;
            if (rret == 0)
                stdin_closed = 1;
            if ((ret = ptls_send(tls, &wbuf, rbuf, rret)) != 0) {
                fprintf(stderr, "ptls_send:%d\n", ret);
                goto Exit;
            }
            if (write_all(fd, wbuf.base, wbuf.off) != 0)
                goto Exit;
            wbuf.off = 0;
        }

        if (FD_ISSET(fd, &readfds)) {
            /* read from socket, decrypt and print */
            while ((rret = read(fd, rbuf, sizeof(rbuf))) == -1 && errno == EINTR)
                ;
            if (rret <= 0)
                goto Exit;
            if (decrypt_and_print(tls, rbuf, rret) != 0)
                goto Exit;
        }
    }

Exit:
    ptls_buffer_dispose(&wbuf);
    ptls_free(tls);
    return 0;
}

static int run_server(struct sockaddr *sa, socklen_t salen, ptls_context_t *ctx, ptls_handshake_properties_t *hsprop)
{
    int listen_fd, conn_fd, on = 1;

    if ((listen_fd = socket(sa->sa_family, SOCK_STREAM, 0)) == -1) {
        perror("socket(2) failed");
        return 1;
    }
    if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) != 0) {
        perror("setsockopt(SO_REUSEADDR) failed");
        return 1;
    }
    if (bind(listen_fd, sa, salen) != 0) {
        perror("bind(2) failed");
        return 1;
    }
    if (listen(listen_fd, SOMAXCONN) != 0) {
        perror("listen(2) failed");
        return 1;
    }

    while (1) {
        if ((conn_fd = accept(listen_fd, NULL, 0)) != -1) {
            handle_connection(conn_fd, ctx, NULL, hsprop);
            close(conn_fd);
        }
    }

    return 0;
}

static int run_client(struct sockaddr *sa, socklen_t salen, ptls_context_t *ctx, const char *server_name,
                      ptls_handshake_properties_t *hsprop)
{
    int fd;

    if ((fd = socket(sa->sa_family, SOCK_STREAM, 0)) == 1) {
        perror("socket(2) failed");
        return 1;
    }
    if (connect(fd, sa, salen) != 0) {
        perror("connect(2) failed");
        return 1;
    }

    return handle_connection(fd, ctx, server_name, hsprop);
}

static void usage(const char *cmd)
{
    printf("Usage: %s [options] host port\n"
           "\n"
           "Options:\n"
           "  -4                   force IPv4\n"
           "  -6                   force IPv6\n"
           "  -c certificate-file\n"
           "  -k key-file          specifies the credentials to be used for running the\n"
           "                       server. If omitted, the command runs as a client.\n"
           "  -l log-file          file to log traffic secrets\n"
           "  -s session-file      file to read/write the session ticket\n"
           "  -e                   when resuming a session, send first 8,192 bytes of input\n"
           "                       as early data\n"
           "  -v                   verify peer using the default certificates\n"
           "  -h                   print this help\n"
           "\n",
           cmd);
}

int main(int argc, char **argv)
{
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
#if !defined(OPENSSL_NO_ENGINE)
    /* Load all compiled-in ENGINEs */
    ENGINE_load_builtin_engines();
    ENGINE_register_all_ciphers();
    ENGINE_register_all_digests();
#endif

    ptls_context_t ctx = {ptls_openssl_random_bytes, ptls_openssl_key_exchanges, ptls_openssl_cipher_suites};
    ptls_handshake_properties_t hsprop = {{{{NULL}}}};
    const char *host, *port;
    int use_early_data = 0, ch;
    struct sockaddr_storage sa;
    socklen_t salen;
    int family = 0;

    while ((ch = getopt(argc, argv, "46c:k:es:l:vh")) != -1) {
        switch (ch) {
        case '4':
            family = AF_INET;
            break;
        case '6':
            family = AF_INET6;
            break;
        case 'c':
            load_certificate_chain(&ctx, optarg);
            break;
        case 'k':
            load_private_key(&ctx, optarg);
            break;
        case 'e':
            use_early_data = 1;
            break;
        case 's':
            setup_session_file(&ctx, &hsprop, optarg);
            break;
        case 'l':
            setup_log_secret(&ctx, optarg);
            break;
        case 'v':
            setup_verify_certificate(&ctx);
            break;
        default:
            usage(argv[0]);
            exit(1);
        }
    }
    argc -= optind;
    argv += optind;
    if (ctx.certificates.count != 0 || ctx.sign_certificate != NULL) {
        /* server */
        if (ctx.certificates.count == 0 || ctx.sign_certificate == NULL) {
            fprintf(stderr, "-c and -k options must be used together\n");
            return 1;
        }
        setup_session_cache(&ctx);
    } else {
        /* client */
        if (use_early_data) {
            static size_t max_early_data_size;
            hsprop.client.max_early_data_size = &max_early_data_size;
        }
    }
    if (argc != 2) {
        fprintf(stderr, "missing host and port\n");
        return 1;
    }
    host = (--argc, *argv++);
    port = (--argc, *argv++);

    if (resolve_address((struct sockaddr *)&sa, &salen, host, port, family, SOCK_STREAM, IPPROTO_TCP) != 0)
        exit(1);

    if (ctx.certificates.count != 0) {
        return run_server((struct sockaddr *)&sa, salen, &ctx, &hsprop);
    } else {
        return run_client((struct sockaddr *)&sa, salen, &ctx, host, &hsprop);
    }
}
