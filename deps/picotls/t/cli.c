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
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/engine.h>
#include <openssl/pem.h>
#if PICOTLS_USE_BROTLI
#include "brotli/decode.h"
#endif
#include "picotls.h"
#include "picotls/openssl.h"
#if PICOTLS_USE_BROTLI
#include "picotls/certificate_compression.h"
#endif
#include "util.h"

static void shift_buffer(ptls_buffer_t *buf, size_t delta)
{
    if (delta != 0) {
        assert(delta <= buf->off);
        if (delta != buf->off)
            memmove(buf->base, buf->base + delta, buf->off - delta);
        buf->off -= delta;
    }
}

static int handle_connection(int sockfd, ptls_context_t *ctx, const char *server_name, const char *input_file,
                             ptls_handshake_properties_t *hsprop, int request_key_update)
{
    ptls_t *tls = ptls_new(ctx, server_name == NULL);
    ptls_buffer_t rbuf, encbuf, ptbuf;
    char bytebuf[16384];
    enum { IN_HANDSHAKE, IN_1RTT, IN_SHUTDOWN } state = IN_HANDSHAKE;
    int inputfd = 0, ret = 0;
    size_t early_bytes_sent = 0;
    ssize_t ioret;

    ptls_buffer_init(&rbuf, "", 0);
    ptls_buffer_init(&encbuf, "", 0);
    ptls_buffer_init(&ptbuf, "", 0);

    fcntl(sockfd, F_SETFL, O_NONBLOCK);

    if (input_file != NULL) {
        if ((inputfd = open(input_file, O_RDONLY)) == -1) {
            fprintf(stderr, "failed to open file:%s:%s\n", input_file, strerror(errno));
            ret = 1;
            goto Exit;
        }
    }
    if (server_name != NULL) {
        ptls_set_server_name(tls, server_name, 0);
        if ((ret = ptls_handshake(tls, &encbuf, NULL, NULL, hsprop)) != PTLS_ERROR_IN_PROGRESS) {
            fprintf(stderr, "ptls_handshake:%d\n", ret);
            ret = 1;
            goto Exit;
        }
    }

    while (1) {
        /* check if data is available */
        fd_set readfds, writefds, exceptfds;
        int maxfd = 0;
        struct timeval timeout;
        do {
            FD_ZERO(&readfds);
            FD_ZERO(&writefds);
            FD_ZERO(&exceptfds);
            FD_SET(sockfd, &readfds);
            if (encbuf.off != 0)
                FD_SET(sockfd, &writefds);
            FD_SET(sockfd, &exceptfds);
            maxfd = sockfd + 1;
            if (inputfd != -1) {
                FD_SET(inputfd, &readfds);
                FD_SET(inputfd, &exceptfds);
                if (maxfd <= inputfd)
                    maxfd = inputfd + 1;
            }
            timeout.tv_sec = encbuf.off != 0 ? 0 : 3600;
            timeout.tv_usec = 0;
        } while (select(maxfd, &readfds, &writefds, &exceptfds, &timeout) == -1);

        /* consume incoming messages */
        if (FD_ISSET(sockfd, &readfds) || FD_ISSET(sockfd, &exceptfds)) {
            size_t off = 0, leftlen;
            while ((ioret = read(sockfd, bytebuf, sizeof(bytebuf))) == -1 && errno == EINTR)
                ;
            if (ioret == -1 && (errno == EWOULDBLOCK || errno == EAGAIN)) {
                /* no data */
                ioret = 0;
            } else if (ioret <= 0) {
                goto Exit;
            }
            while ((leftlen = ioret - off) != 0) {
                if (state == IN_HANDSHAKE) {
                    if ((ret = ptls_handshake(tls, &encbuf, bytebuf + off, &leftlen, hsprop)) == 0) {
                        state = IN_1RTT;
                        assert(ptls_is_server(tls) || hsprop->client.early_data_acceptance != PTLS_EARLY_DATA_ACCEPTANCE_UNKNOWN);
                        /* release data sent as early-data, if server accepted it */
                        if (hsprop->client.early_data_acceptance == PTLS_EARLY_DATA_ACCEPTED)
                            shift_buffer(&ptbuf, early_bytes_sent);
                        if (request_key_update)
                            ptls_update_key(tls, 1);
                        if (ptbuf.off != 0) {
                            if ((ret = ptls_send(tls, &encbuf, ptbuf.base, ptbuf.off)) != 0) {
                                fprintf(stderr, "ptls_send(1rtt):%d\n", ret);
                                goto Exit;
                            }
                            ptbuf.off = 0;
                        }
                    } else if (ret == PTLS_ERROR_IN_PROGRESS) {
                        /* ok */
                    } else {
                        if (encbuf.off != 0)
                            (void)write(sockfd, encbuf.base, encbuf.off);
                        fprintf(stderr, "ptls_handshake:%d\n", ret);
                        goto Exit;
                    }
                } else {
                    if ((ret = ptls_receive(tls, &rbuf, bytebuf + off, &leftlen)) == 0) {
                        if (rbuf.off != 0) {
                            write(1, rbuf.base, rbuf.off);
                            rbuf.off = 0;
                        }
                    } else if (ret == PTLS_ERROR_IN_PROGRESS) {
                        /* ok */
                    } else {
                        fprintf(stderr, "ptls_receive:%d\n", ret);
                        goto Exit;
                    }
                }
                off += leftlen;
            }
        }

        /* read input (and send if possible) */
        if (inputfd != -1 && (FD_ISSET(inputfd, &readfds) || FD_ISSET(inputfd, &exceptfds))) {
            while ((ioret = read(inputfd, bytebuf, sizeof(bytebuf))) == -1 && errno == EINTR)
                ;
            if (ioret > 0) {
                ptls_buffer_pushv(&ptbuf, bytebuf, ioret);
                if (state == IN_HANDSHAKE) {
                    size_t send_amount = 0;
                    if (server_name != NULL && hsprop->client.max_early_data_size != NULL) {
                        size_t max_can_be_sent = *hsprop->client.max_early_data_size;
                        if (max_can_be_sent > ptbuf.off)
                            max_can_be_sent = ptbuf.off;
                        send_amount = max_can_be_sent - early_bytes_sent;
                    }
                    if (send_amount != 0) {
                        if ((ret = ptls_send(tls, &encbuf, ptbuf.base, send_amount)) != 0) {
                            fprintf(stderr, "ptls_send(early_data):%d\n", ret);
                            goto Exit;
                        }
                        early_bytes_sent += send_amount;
                    }
                } else {
                    if ((ret = ptls_send(tls, &encbuf, bytebuf, ioret)) != 0) {
                        fprintf(stderr, "ptls_send(1rtt):%d\n", ret);
                        goto Exit;
                    }
                    ptbuf.off = 0;
                }
            } else {
                /* closed */
                if (input_file != NULL)
                    close(inputfd);
                inputfd = -1;
            }
        }

        /* send any data */
        if (encbuf.off != 0) {
            while ((ioret = write(sockfd, encbuf.base, encbuf.off)) == -1 && errno == EINTR)
                ;
            if (ioret == -1 && (errno == EWOULDBLOCK || errno == EAGAIN)) {
                /* no data */
            } else if (ioret <= 0) {
                goto Exit;
            } else {
                shift_buffer(&encbuf, ioret);
            }
        }

        /* close the sender side when necessary */
        if (state == IN_1RTT && inputfd == -1) {
            /* FIXME send close_alert */
            shutdown(sockfd, SHUT_WR);
            state = IN_SHUTDOWN;
        }
    }

Exit:
    if (sockfd != -1)
        close(sockfd);
    if (input_file != NULL && inputfd != -1)
        close(inputfd);
    ptls_buffer_dispose(&rbuf);
    ptls_buffer_dispose(&encbuf);
    ptls_buffer_dispose(&ptbuf);
    ptls_free(tls);
    return ret != 0;
}

static int run_server(struct sockaddr *sa, socklen_t salen, ptls_context_t *ctx, const char *input_file,
                      ptls_handshake_properties_t *hsprop, int request_key_update)
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
        if ((conn_fd = accept(listen_fd, NULL, 0)) != -1)
            handle_connection(conn_fd, ctx, NULL, input_file, hsprop, request_key_update);
    }

    return 0;
}

static int run_client(struct sockaddr *sa, socklen_t salen, ptls_context_t *ctx, const char *server_name, const char *input_file,
                      ptls_handshake_properties_t *hsprop, int request_key_update)
{
    int fd;

    hsprop->client.esni_keys = resolve_esni_keys(server_name);

    if ((fd = socket(sa->sa_family, SOCK_STREAM, 0)) == 1) {
        perror("socket(2) failed");
        return 1;
    }
    if (connect(fd, sa, salen) != 0) {
        perror("connect(2) failed");
        return 1;
    }

    int ret = handle_connection(fd, ctx, server_name, input_file, hsprop, request_key_update);
    free(hsprop->client.esni_keys.base);
    return ret;
}

static void usage(const char *cmd)
{
    printf("Usage: %s [options] host port\n"
           "\n"
           "Options:\n"
           "  -4                   force IPv4\n"
           "  -6                   force IPv6\n"
           "  -a                   require client authentication\n"
           "  -b                   enable brotli compression\n"
           "  -C certificate-file  certificate chain used for client authentication\n"
           "  -c certificate-file  certificate chain used for server authentication\n"
           "  -i file              a file to read from and send to the peer (default: stdin)\n"
           "  -k key-file          specifies the credentials for signing the certificate\n"
           "  -l log-file          file to log events (incl. traffic secrets)\n"
           "  -n                   negotiates the key exchange method (i.e. wait for HRR)\n"
           "  -N named-group       named group to be used (default: secp256r1)\n"
           "  -s session-file      file to read/write the session ticket\n"
           "  -S                   require public key exchange when resuming a session\n"
           "  -E esni-file         file that stores ESNI data generated by picotls-esni\n"
           "  -e                   when resuming a session, send first 8,192 bytes of input\n"
           "                       as early data\n"
           "  -u                   update the traffic key when handshake is complete\n"
           "  -v                   verify peer using the default certificates\n"
           "  -h                   print this help\n"
           "\n"
           "Supported named groups: secp256r1"
#if PTLS_OPENSSL_HAVE_SECP384R1
           ", secp384r1"
#endif
#if PTLS_OPENSSL_HAVE_SECP521R1
           ", secp521r1"
#endif
#if PTLS_OPENSSL_HAVE_X25519
           ", X25519"
#endif
           "\n\n",
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

    res_init();

    ptls_key_exchange_algorithm_t *key_exchanges[128] = {NULL};
    ptls_context_t ctx = {ptls_openssl_random_bytes, &ptls_get_time, key_exchanges, ptls_openssl_cipher_suites};
    ptls_handshake_properties_t hsprop = {{{{NULL}}}};
    const char *host, *port, *file = NULL, *esni_file = NULL;
    struct {
        ptls_key_exchange_context_t *elements[16];
        size_t count;
    } esni_key_exchanges;
    int is_server = 0, use_early_data = 0, request_key_update = 0, ch;
    struct sockaddr_storage sa;
    socklen_t salen;
    int family = 0;

    while ((ch = getopt(argc, argv, "46abC:c:i:k:nN:es:SE:K:l:vh")) != -1) {
        switch (ch) {
        case '4':
            family = AF_INET;
            break;
        case '6':
            family = AF_INET6;
            break;
        case 'a':
            ctx.require_client_authentication = 1;
            break;
        case 'b':
#if PICOTLS_USE_BROTLI
            ctx.decompress_certificate = &ptls_decompress_certificate;
#else
            fprintf(stderr, "support for `-b` option was turned off during configuration\n");
            exit(1);
#endif
            break;
        case 'C':
        case 'c':
            if (ctx.certificates.count != 0) {
                fprintf(stderr, "-C/-c can only be specified once\n");
                return 1;
            }
            load_certificate_chain(&ctx, optarg);
            is_server = ch == 'c';
            break;
        case 'i':
            file = optarg;
            break;
        case 'k':
            load_private_key(&ctx, optarg);
            break;
        case 'n':
            hsprop.client.negotiate_before_key_exchange = 1;
            break;
        case 'e':
            use_early_data = 1;
            break;
        case 's':
            setup_session_file(&ctx, &hsprop, optarg);
            break;
        case 'S':
            ctx.require_dhe_on_psk = 1;
            break;
        case 'E':
            esni_file = optarg;
            break;
        case 'K': {
            FILE *fp;
            EVP_PKEY *pkey;
            int ret;
            if ((fp = fopen(optarg, "rt")) == NULL) {
                fprintf(stderr, "failed to open ESNI private key file:%s:%s\n", optarg, strerror(errno));
                return 1;
            }
            if ((pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL)) == NULL) {
                fprintf(stderr, "failed to load private key from file:%s\n", optarg);
                return 1;
            }
            if ((ret = ptls_openssl_create_key_exchange(esni_key_exchanges.elements + esni_key_exchanges.count++, pkey)) != 0) {
                fprintf(stderr, "failed to load private key from file:%s:picotls-error:%d", optarg, ret);
                return 1;
            }
            EVP_PKEY_free(pkey);
            fclose(fp);
        } break;
        case 'l':
            setup_log_event(&ctx, optarg);
            break;
        case 'v':
            setup_verify_certificate(&ctx);
            break;
        case 'N': {
            ptls_key_exchange_algorithm_t *algo = NULL;
#define MATCH(name)                                                                                                                \
    if (algo == NULL && strcasecmp(optarg, #name) == 0)                                                                            \
    algo = (&ptls_openssl_##name)
            MATCH(secp256r1);
#if PTLS_OPENSSL_HAVE_SECP384R1
            MATCH(secp384r1);
#endif
#if PTLS_OPENSSL_HAVE_SECP521R1
            MATCH(secp521r1);
#endif
#if PTLS_OPENSSL_HAVE_X25519
            MATCH(x25519);
#endif
#undef MATCH
            if (algo == NULL) {
                fprintf(stderr, "could not find key exchange: %s\n", optarg);
                return 1;
            }
            size_t i;
            for (i = 0; key_exchanges[i] != NULL; ++i)
                ;
            key_exchanges[i++] = algo;
        } break;
        case 'u':
            request_key_update = 1;
            break;
        case 'h':
            usage(argv[0]);
            exit(0);
        default:
            exit(1);
        }
    }
    argc -= optind;
    argv += optind;
    if ((ctx.certificates.count == 0) != (ctx.sign_certificate == NULL)) {
        fprintf(stderr, "-C/-c and -k options must be used together\n");
        return 1;
    }
    if (is_server) {
        if (ctx.certificates.count == 0) {
            fprintf(stderr, "-c and -k options must be set\n");
            return 1;
        }
#if PICOTLS_USE_BROTLI
        if (ctx.decompress_certificate != NULL) {
            static ptls_emit_compressed_certificate_t ecc;
            if (ptls_init_compressed_certificate(&ecc, ctx.certificates.list, ctx.certificates.count, ptls_iovec_init(NULL, 0)) !=
                0) {
                fprintf(stderr, "failed to create a brotli-compressed version of the certificate chain.\n");
                exit(1);
            }
            ctx.emit_certificate = &ecc.super;
        }
#endif
        setup_session_cache(&ctx);
    } else {
        /* client */
        if (use_early_data) {
            static size_t max_early_data_size;
            hsprop.client.max_early_data_size = &max_early_data_size;
        }
    }
    if (key_exchanges[0] == NULL)
        key_exchanges[0] = &ptls_openssl_secp256r1;
    if (esni_file != NULL) {
        if (esni_key_exchanges.count == 0) {
            fprintf(stderr, "-E must be used together with -K\n");
            return 1;
        }
        setup_esni(&ctx, esni_file, esni_key_exchanges.elements);
    }
    if (argc != 2) {
        fprintf(stderr, "missing host and port\n");
        return 1;
    }
    host = (--argc, *argv++);
    port = (--argc, *argv++);

    if (resolve_address((struct sockaddr *)&sa, &salen, host, port, family, SOCK_STREAM, IPPROTO_TCP) != 0)
        exit(1);

    if (is_server) {
        return run_server((struct sockaddr *)&sa, salen, &ctx, file, &hsprop, request_key_update);
    } else {
        return run_client((struct sockaddr *)&sa, salen, &ctx, host, file, &hsprop, request_key_update);
    }
}
