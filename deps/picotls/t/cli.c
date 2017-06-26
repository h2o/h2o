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
#include <netdb.h>
#include <netinet/in.h>
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

/* single-entry session cache */
static struct {
    uint8_t id[32];
    ptls_iovec_t data;
} session_cache = {{0}};

static int encrypt_ticket_cb(ptls_encrypt_ticket_t *self, ptls_t *tls, ptls_buffer_t *dst, ptls_iovec_t src)
{
    int ret;

    free(session_cache.data.base);
    if ((session_cache.data.base = malloc(src.len)) == NULL)
        return PTLS_ERROR_NO_MEMORY;

    ptls_get_context(tls)->random_bytes(session_cache.id, sizeof(session_cache.id));
    memcpy(session_cache.data.base, src.base, src.len);
    session_cache.data.len = src.len;

    if ((ret = ptls_buffer_reserve(dst, sizeof(session_cache.id))) != 0)
        return ret;
    memcpy(dst->base + dst->off, session_cache.id, sizeof(session_cache.id));
    dst->off += sizeof(session_cache.id);

    return 0;
}

static int decrypt_ticket_cb(ptls_encrypt_ticket_t *self, ptls_t *tls, ptls_buffer_t *dst, ptls_iovec_t src)
{
    int ret;

    if (src.len != sizeof(session_cache.id))
        return PTLS_ERROR_SESSION_NOT_FOUND;
    if (memcmp(session_cache.id, src.base, sizeof(session_cache.id)) != 0)
        return PTLS_ERROR_SESSION_NOT_FOUND;

    if ((ret = ptls_buffer_reserve(dst, session_cache.data.len)) != 0)
        return ret;
    memcpy(dst->base + dst->off, session_cache.data.base, session_cache.data.len);
    dst->off += session_cache.data.len;
    return 0;
}

static int run_server(struct sockaddr *sa, socklen_t salen, ptls_context_t *ctx, ptls_handshake_properties_t *hsprop)
{
    int listen_fd, conn_fd, on = 1;

    if ((listen_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
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

static char *session_file = NULL;

static int load_ticket(ptls_buffer_t *dst)
{
    FILE *fp;

    if ((fp = fopen(session_file, "rb")) == NULL)
        return PTLS_ERROR_LIBRARY;
    while (1) {
        size_t n;
        int ret;
        if ((ret = ptls_buffer_reserve(dst, 256)) != 0)
            return ret;
        if ((n = fread(dst->base + dst->off, 1, 256, fp)) == 0)
            break;
        dst->off += n;
    }
    fclose(fp);

    return 0;
}

static int save_ticket_cb(ptls_save_ticket_t *self, ptls_t *tls, ptls_iovec_t src)
{
    FILE *fp;

    if (session_file == NULL)
        return 0;

    if ((fp = fopen(session_file, "wb")) == NULL) {
        fprintf(stderr, "failed to open file:%s:%s\n", session_file, strerror(errno));
        return PTLS_ERROR_LIBRARY;
    }
    fwrite(src.base, 1, src.len, fp);
    fclose(fp);

    return 0;
}

static FILE *secret_fp = NULL;

static void fprinthex(FILE *fp, ptls_iovec_t vec)
{
    size_t i;
    for (i = 0; i != vec.len; ++i)
        fprintf(fp, "%02x", vec.base[i]);
}

static void log_secret_cb(ptls_log_secret_t *self, ptls_t *tls, const char *label, ptls_iovec_t secret)
{
    fprintf(secret_fp, "%s ", label);
    fprinthex(secret_fp, ptls_get_client_random(tls));
    fprintf(secret_fp, " ");
    fprinthex(secret_fp, secret);
    fprintf(secret_fp, "\n");
    fflush(secret_fp);
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

static int resolve_address(struct sockaddr *sa, socklen_t *salen, const char *host, const char *port)
{
    struct addrinfo hints, *res;
    int err;

    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_ADDRCONFIG | AI_NUMERICSERV | AI_PASSIVE;
    if ((err = getaddrinfo(host, port, &hints, &res)) != 0 || res == NULL) {
        fprintf(stderr, "failed to resolve address:%s:%s:%s\n", host, port,
                err != 0 ? gai_strerror(err) : "getaddrinfo returned NULL");
        return -1;
    }

    memcpy(sa, res->ai_addr, res->ai_addrlen);
    *salen = res->ai_addrlen;

    freeaddrinfo(res);
    return 0;
}

static void usage(const char *cmd)
{
    printf("Usage: %s [options] host port\n"
           "\n"
           "Options:\n"
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

    ptls_iovec_t _certs[16] = {{NULL}};
    ptls_openssl_sign_certificate_t sign_certificate = {{NULL}};
    ptls_encrypt_ticket_t encrypt_ticket = {encrypt_ticket_cb}, decrypt_ticket = {decrypt_ticket_cb};
    ptls_save_ticket_t save_ticket = {save_ticket_cb};
    ptls_log_secret_t log_secret = {log_secret_cb};
    ptls_context_t ctx = {ptls_openssl_random_bytes,
                          ptls_openssl_key_exchanges,
                          ptls_openssl_cipher_suites,
                          {_certs, 0},
                          NULL,
                          NULL,
                          &sign_certificate.super,
                          NULL,
                          86400,
                          8192,
                          0,
                          0,
                          &encrypt_ticket,
                          &decrypt_ticket,
                          &save_ticket};
    ptls_openssl_verify_certificate_t verify_certificate = {{NULL}};
    ptls_handshake_properties_t hsprop = {{{{NULL}}}};
    const char *host, *port;
    int use_early_data = 0, ch;
    struct sockaddr_storage sa;
    socklen_t salen;

    while ((ch = getopt(argc, argv, "c:k:es:l:vh")) != -1) {
        switch (ch) {
        case 'c': {
            FILE *fp;
            X509 *cert;
            if ((fp = fopen(optarg, "rb")) == NULL) {
                fprintf(stderr, "failed to open file:%s:%s\n", optarg, strerror(errno));
                return 1;
            }
            while ((cert = PEM_read_X509(fp, NULL, NULL, NULL)) != NULL) {
                ptls_iovec_t *dst = ctx.certificates.list + ctx.certificates.count++;
                dst->len = i2d_X509(cert, &dst->base);
            }
            fclose(fp);
            if (ctx.certificates.count == 0) {
                fprintf(stderr, "failed to load certificate chain from file:%s\n", optarg);
                return 1;
            }
        } break;
        case 'k': {
            FILE *fp;
            if ((fp = fopen(optarg, "rb")) == NULL) {
                fprintf(stderr, "failed to open file:%s:%s\n", optarg, strerror(errno));
                return 1;
            }
            EVP_PKEY *pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
            fclose(fp);
            if (pkey == NULL) {
                fprintf(stderr, "failed to load private key from file:%s\n", optarg);
                return 1;
            }
            ptls_openssl_init_sign_certificate(&sign_certificate, pkey);
            EVP_PKEY_free(pkey);
        } break;
        case 'e':
            use_early_data = 1;
            break;
        case 's':
            session_file = optarg;
            break;
        case 'l':
            if ((secret_fp = fopen(optarg, "at")) == NULL) {
                fprintf(stderr, "failed to open file:%s:%s\n", optarg, strerror(errno));
                return 1;
            }
            ctx.log_secret = &log_secret;
            break;
        case 'v':
            ptls_openssl_init_verify_certificate(&verify_certificate, NULL);
            break;
        default:
            usage(argv[0]);
            exit(1);
        }
    }
    argc -= optind;
    argv += optind;
    if (ctx.certificates.count != 0 || sign_certificate.key != NULL) {
        /* server */
        if (ctx.certificates.count == 0 || sign_certificate.key == NULL) {
            fprintf(stderr, "-c and -k options must be used together\n");
            return 1;
        }
        if (session_file != NULL) {
            fprintf(stderr, "-s option cannot be used for server\n");
            return 1;
        }
        if (use_early_data) {
            fprintf(stderr, "-e option cannot be used for server\n");
            return 1;
        }
    } else {
        /* client */
        if (session_file != NULL) {
            ptls_buffer_t sessdata;
            ptls_buffer_init(&sessdata, "", 0);
            if (load_ticket(&sessdata) == 0)
                hsprop.client.session_ticket = ptls_iovec_init(sessdata.base, sessdata.off);
        }
        if (use_early_data) {
            static size_t max_early_data_size;
            hsprop.client.max_early_data_size = &max_early_data_size;
        }
    }
    if (verify_certificate.super.cb == NULL)
        ptls_openssl_init_verify_certificate(&verify_certificate, NULL);
    ctx.verify_certificate = &verify_certificate.super;
    if (argc != 2) {
        fprintf(stderr, "missing host and port\n");
        return 1;
    }
    host = (--argc, *argv++);
    port = (--argc, *argv++);

    if (resolve_address((struct sockaddr *)&sa, &salen, host, port) != 0)
        exit(1);

    if (ctx.certificates.count != 0) {
        return run_server((struct sockaddr *)&sa, salen, &ctx, &hsprop);
    } else {
        return run_client((struct sockaddr *)&sa, salen, &ctx, host, &hsprop);
    }
}
