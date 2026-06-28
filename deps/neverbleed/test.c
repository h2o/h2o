/*
 * Copyright (c) 2015 Kazuho Oku, DeNA Co., Ltd.
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
#include <assert.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define OPENSSL_SUPPRESS_DEPRECATED
#include <openssl/opensslconf.h>
#include <openssl/opensslv.h>

#if OPENSSL_VERSION_NUMBER >= 0x1010000fL && !defined(OPENSSL_NO_EC) &&                                                            \
    (!defined(LIBRESSL_VERSION_NUMBER) || LIBRESSL_VERSION_NUMBER >= 0x2090100fL)
#define NEVERBLEED_TEST_ECDSA
#endif

#ifdef NEVERBLEED_TEST_ECDSA
#include <openssl/ec.h>
#endif
#include <openssl/evp.h>
#include <openssl/ssl.h>

#include "neverbleed.h"

static neverbleed_t nb;

#ifdef OPENSSL_IS_BORINGSSL
static void setup_boringssl_key_method(SSL_CTX *ctx);
static int boringssl_get_pkey_index(void);
static void boringssl_free_pkey_callback(void *parent, void *ptr, CRYPTO_EX_DATA *ad, int idx, long argl, void *argp);
#endif

#ifdef NEVERBLEED_TEST_ECDSA
static void setup_ecc_key(SSL_CTX *ssl_ctx)
{
    int nid = NID_X9_62_prime256v1;
    EC_KEY *key = EC_KEY_new_by_curve_name(nid);
    if (key == NULL) {
        fprintf(stderr, "Failed to create curve \"%s\"\n", OBJ_nid2sn(nid));
        return;
    }
    SSL_CTX_set_tmp_ecdh(ssl_ctx, key);
    EC_KEY_free(key);
}
#endif

#ifdef OPENSSL_IS_BORINGSSL
static void boringssl_free_pkey_callback(void *parent, void *ptr, CRYPTO_EX_DATA *ad, int idx, long argl, void *argp)
{
    if (ptr != NULL)
        EVP_PKEY_free(ptr);
}

static int boringssl_get_pkey_index(void)
{
    static volatile int index;
    static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
    pthread_mutex_lock(&mutex);
    if (!index) {
        index = SSL_CTX_get_ex_new_index(0, NULL, NULL, NULL, boringssl_free_pkey_callback);
    }
    pthread_mutex_unlock(&mutex);
    return index;
}

static enum ssl_private_key_result_t boringssl_sign(SSL *ssl, uint8_t *out, size_t *outlen, size_t max_out,
                                                    uint16_t signature_algorithm, const uint8_t *in, size_t len)
{
    neverbleed_iobuf_t buf = {NULL};
    void *digest = NULL;
    size_t digestlen = 0;
    SSL_CTX *ctx = SSL_get_SSL_CTX(ssl);
    EVP_PKEY *pkey = SSL_CTX_get_ex_data(ctx, boringssl_get_pkey_index());
    const EVP_MD *md = SSL_get_signature_algorithm_digest(signature_algorithm);
    int rsa_pss = SSL_is_signature_algorithm_rsa_pss(signature_algorithm);

    neverbleed_start_digestsign(&buf, pkey, md, in, len, rsa_pss);
    neverbleed_transaction_write(&nb, &buf);
    neverbleed_transaction_read(&nb, &buf);
    neverbleed_finish_digestsign(&buf, &digest, &digestlen);

    assert(digestlen <= max_out);
    memcpy(out, digest, digestlen);
    *outlen = digestlen;

    free(digest);
    return ssl_private_key_success;
}

static enum ssl_private_key_result_t boringssl_decrypt(SSL *ssl, uint8_t *out, size_t *outlen, size_t max_out, const uint8_t *in,
                                                       size_t len)
{
    neverbleed_iobuf_t buf = {NULL};
    void *digest = NULL;
    size_t digestlen = 0;
    SSL_CTX *ctx = SSL_get_SSL_CTX(ssl);
    EVP_PKEY *pkey = SSL_CTX_get_ex_data(ctx, boringssl_get_pkey_index());

    neverbleed_start_decrypt(&buf, pkey, in, len);
    neverbleed_transaction_write(&nb, &buf);
    neverbleed_transaction_read(&nb, &buf);
    neverbleed_finish_decrypt(&buf, &digest, &digestlen);

    assert(digestlen <= max_out);
    memcpy(out, digest, digestlen);
    *outlen = digestlen;

    free(digest);
    return ssl_private_key_success;
}

static void setup_boringssl_key_method(SSL_CTX *ctx)
{
    EVP_PKEY *pkey = SSL_CTX_get0_privatekey(ctx);
    EVP_PKEY_up_ref(pkey);
    SSL_CTX_set_ex_data(ctx, boringssl_get_pkey_index(), pkey);
    static const SSL_PRIVATE_KEY_METHOD meth = {
        .sign = boringssl_sign,
        .decrypt = boringssl_decrypt,
    };
    SSL_CTX_set_private_key_method(ctx, &meth);
}
#endif

int dumb_https_server(unsigned short port, SSL_CTX *ctx)
{
    int listen_fd, reuse_flag;
    struct sockaddr_in sin = {};

    if ((listen_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        fprintf(stderr, "failed to create socket:%s\n", strerror(errno));
        return 111;
    }
    reuse_flag = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &reuse_flag, sizeof(reuse_flag));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(0x7f000001);
    sin.sin_port = htons(port);
    if (bind(listen_fd, (void *)&sin, sizeof(sin)) != 0) {
        fprintf(stderr, "bind failed:%s\n", strerror(errno));
        return 111;
    }
    if (listen(listen_fd, SOMAXCONN) != 0) {
        fprintf(stderr, "listen failed:%s\n", strerror(errno));
        return 111;
    }

    while (1) {
        int conn_fd;
        SSL *ssl;
        char buf[4096];
        /* accept connection */
        while ((conn_fd = accept(listen_fd, NULL, NULL)) == -1 && errno == EINTR)
            ;
        if (conn_fd == -1) {
            fprintf(stderr, "accept(2) failed:%s\n", strerror(errno));
            return 111;
        }
        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, conn_fd);
        if (SSL_accept(ssl) == 1) {
            SSL_read(ssl, buf, sizeof(buf));
            const char *resp =
                "HTTP/1.0 200 OK\r\nContent-Length: 6\r\nConnection: close\r\nContent-Type: text/plain\r\n\r\nhello\n";
            SSL_write(ssl, resp, strlen(resp));
            SSL_shutdown(ssl);
        } else {
            fprintf(stderr, "SSL_accept failed\n");
        }
        SSL_free(ssl);
        close(conn_fd);
    }
}

int main(int argc, char **argv)
{
    unsigned short port;
    SSL_CTX *ctx;
    char errbuf[NEVERBLEED_ERRBUF_SIZE];
    int use_privsep;

    /* initialization */
    /* FIXME: These APIs are deprecated in favor of OPENSSL_init_crypto in 1.1.0. */
    SSL_load_error_strings();
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    if (neverbleed_init(&nb, errbuf) != 0) {
        fprintf(stderr, "openssl_privsep_init: %s\n", errbuf);
        return 111;
    }
    ctx = SSL_CTX_new(SSLv23_server_method());
    SSL_CTX_set_options(ctx, SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION);
#ifdef NEVERBLEED_TEST_ECDSA
    setup_ecc_key(ctx);
#endif

    /* parse args */
    if (argc != 5) {
        fprintf(stderr, "Usage: %s <internal|privsep> <port> <certificate-chain-file> <private-key-file>\n", argv[0]);
        return 111;
    }
    if (strcmp(argv[1], "internal") == 0) {
        use_privsep = 0;
    } else if (strcmp(argv[1], "privsep") == 0) {
        use_privsep = 1;
    } else {
        fprintf(stderr, "unknown mode:%s\n", argv[1]);
        return 111;
    }
    if (sscanf(argv[2], "%hu", &port) != 1) {
        fprintf(stderr, "failed to parse port:%s\n", argv[2]);
        return 111;
    }
    if (SSL_CTX_use_certificate_chain_file(ctx, argv[3]) != 1) {
        fprintf(stderr, "failed to load certificate chain file:%s\n", argv[3]);
        return 111;
    }
    if (use_privsep) {
        if (neverbleed_load_private_key_file(&nb, ctx, argv[4], errbuf) != 1) {
            fprintf(stderr, "failed to load private key from file:%s:%s\n", argv[4], errbuf);
            return 111;
        }
#ifdef OPENSSL_IS_BORINGSSL
        setup_boringssl_key_method(ctx);
#endif
    } else {
        if (SSL_CTX_use_PrivateKey_file(ctx, argv[4], SSL_FILETYPE_PEM) != 1) {
            fprintf(stderr, "failed to load private key from file:%s\n", argv[4]);
            return 111;
        }
    }

    /* start the httpd */
    return dumb_https_server(port, ctx);
}
