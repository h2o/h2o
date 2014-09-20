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
#include <fcntl.h>
#include <limits.h>
#include <string.h>
#include <openssl/ssl.h>
#include "h2o.h"

#if defined(__APPLE__) && defined(__clang__)
# pragma clang diagnostic ignored "-Wdeprecated-declarations"
#endif

#ifndef IOV_MAX
# define IOV_MAX UIO_MAXIOV
#endif

struct st_h2o_socket_ssl_t {
    SSL *ssl;
    struct {
        h2o_socket_cb cb;
    } handshake;
    struct {
        h2o_input_buffer_t *encrypted;
    } input;
    struct {
        H2O_VECTOR(h2o_buf_t) bufs;
        h2o_mempool_t pool; /* placed at the last */
    } output;
};

struct st_h2o_ssl_context_t {
    SSL_CTX *ctx;
    const h2o_buf_t *protocols;
    h2o_buf_t _npn_list_of_protocols;
};

/* backend functions */
static void do_dispose_socket(h2o_socket_t *sock);
static void do_write(h2o_socket_t *sock, h2o_buf_t *bufs, size_t bufcnt, h2o_socket_cb cb);
static void do_read_start(h2o_socket_t *sock);
static void do_read_stop(h2o_socket_t *sock);

/* internal functions called from the backend */
static int decode_ssl_input(h2o_socket_t *sock);
static void on_write_complete(h2o_socket_t *sock, int status);

#if H2O_USE_LIBUV
# include "socket/uv-binding.c.h"
#else
# include "socket/evloop.c.h"
#endif

static int read_bio(BIO *b, char *out, int len)
{
    h2o_socket_t *sock = b->ptr;

    if (len == 0)
        return 0;

    if (sock->ssl->input.encrypted == NULL || sock->ssl->input.encrypted->size == 0) {
        BIO_set_retry_read(b);
        return -1;
    }

    if (sock->ssl->input.encrypted->size < len) {
        len = (int)sock->ssl->input.encrypted->size;
    }
    memcpy(out, sock->ssl->input.encrypted->bytes, len);
    h2o_consume_input_buffer(&sock->ssl->input.encrypted, len);

    return len;
}

static int write_bio(BIO *b, const char *in, int len)
{
    h2o_socket_t *sock = b->ptr;
    void *bytes_alloced;

    if (len == 0)
        return 0;

    bytes_alloced = h2o_mempool_alloc(&sock->ssl->output.pool, len);
    memcpy(bytes_alloced, in, len);

    h2o_vector_reserve(&sock->ssl->output.pool, (h2o_vector_t*)&sock->ssl->output.bufs, sizeof(h2o_buf_t), sock->ssl->output.bufs.size + 1);
    sock->ssl->output.bufs.entries[sock->ssl->output.bufs.size++] = h2o_buf_init(bytes_alloced, len);

    return len;
}

static int puts_bio(BIO *b, const char *str)
{
    return write_bio(b, str, (int)strlen(str));
}

static long ctrl_bio(BIO *b, int cmd, long num, void *ptr)
{
    switch (cmd) {
    case BIO_CTRL_GET_CLOSE:
        return b->shutdown;
    case BIO_CTRL_SET_CLOSE:
        b->shutdown = (int)num;
        return 1;
    case BIO_CTRL_FLUSH:
        return 1;
    default:
        return 0;
    }
}

static int new_bio(BIO *b)
{
    b->init = 0;
    b->num = 0;
    b->ptr = NULL;
    b->flags = 0;
    return 1;
}

static int free_bio(BIO *b)
{
    return b != NULL;
}

int decode_ssl_input(h2o_socket_t *sock)
{
    assert(sock->ssl != NULL);
    assert(sock->ssl->handshake.cb == NULL);

    while (1) {
        h2o_buf_t buf = h2o_allocate_input_buffer(&sock->input, 8192);
        int rlen = SSL_read(sock->ssl->ssl, buf.base, (int)buf.len);
        if (rlen == -1) {
            if (SSL_get_error(sock->ssl->ssl, rlen) != SSL_ERROR_WANT_READ) {
                return -1;
            }
            break;
        } else if (rlen == 0) {
            break;
        } else {
            sock->input->size += rlen;
        }
    }

    return 0;
}

static void flush_pending_ssl(h2o_socket_t *sock, h2o_socket_cb cb)
{
    do_write(sock, sock->ssl->output.bufs.entries, (int)sock->ssl->output.bufs.size, cb);
}

static void dispose_socket(h2o_socket_t *sock, int status)
{
    if (sock->ssl != NULL) {
        SSL_free(sock->ssl->ssl);
        free(sock->ssl->input.encrypted);
        h2o_mempool_clear(&sock->ssl->output.pool);
        free(sock->ssl);
    }
    free(sock->input);

    do_dispose_socket(sock);
}

static void shutdown_ssl(h2o_socket_t *sock, int status)
{
    int ret;

    if (status != 0)
        goto Close;

    if ((ret = SSL_shutdown(sock->ssl->ssl)) == -1) {
        goto Close;
    }

    if (sock->ssl->output.bufs.size != 0) {
        h2o_socket_read_stop(sock);
        flush_pending_ssl(sock, ret == 1 ? dispose_socket : shutdown_ssl);
    } else if (ret == 2 && SSL_get_error(sock->ssl->ssl, ret) == SSL_ERROR_WANT_READ) {
        h2o_socket_read_start(sock, shutdown_ssl);
    } else {
        status = ret == 1;
        goto Close;
    }

    return;
Close:
    dispose_socket(sock, status);
}

void h2o_socket_close(h2o_socket_t *sock)
{
    if (sock->ssl == NULL) {
        dispose_socket(sock, 0);
    } else {
        shutdown_ssl(sock, 0);
    }
}

void h2o_socket_write(h2o_socket_t *sock, h2o_buf_t *bufs, size_t bufcnt, h2o_socket_cb cb)
{
    if (sock->ssl == NULL) {
        do_write(sock, bufs, bufcnt, cb);
    } else {
        size_t i;
        assert(sock->ssl->output.bufs.size == 0);
        /* fill in the data */
        for (i = 0; i != bufcnt; ++i) {
            int ret = SSL_write(sock->ssl->ssl, bufs[i].base, (int)bufs[i].len);
            /* FIXME handle error (by deferred-calling cb(sock, -1)) */
            assert(ret == bufs[i].len);
        }
        flush_pending_ssl(sock, cb);
    }
}

void on_write_complete(h2o_socket_t *sock, int status)
{
    h2o_socket_cb cb;

    if (sock->ssl != NULL) {
        memset(&sock->ssl->output.bufs, 0, sizeof(sock->ssl->output.bufs));
        h2o_mempool_clear(&sock->ssl->output.pool);
    }

    cb = sock->_cb.write;
    sock->_cb.write = NULL;
    cb(sock, status);
}

void h2o_socket_read_start(h2o_socket_t *sock, h2o_socket_cb cb)
{
    sock->_cb.read = cb;
    do_read_start(sock);
}

void h2o_socket_read_stop(h2o_socket_t *sock)
{
    sock->_cb.read = NULL;
    do_read_stop(sock);
}

static void on_handshake_complete(h2o_socket_t *sock, int status)
{
    h2o_socket_cb handshake_cb = sock->ssl->handshake.cb;
    sock->_cb.write = NULL;
    sock->ssl->handshake.cb = NULL;
    handshake_cb(sock, status);
}

static void proceed_handshake(h2o_socket_t *sock, int status)
{
    int ret;

    sock->_cb.write = NULL;

    if (status != 0) {
        goto Complete;
    }

    ret = SSL_accept(sock->ssl->ssl);

    if (ret == 2 || (ret < 0 && SSL_get_error(sock->ssl->ssl, ret) != SSL_ERROR_WANT_READ)) {
        /* failed */
        status = -1;
        goto Complete;
    }

    if (sock->ssl->output.bufs.size != 0) {
        h2o_socket_read_stop(sock);
        flush_pending_ssl(sock, ret == 1 ? on_handshake_complete : proceed_handshake);
    } else {
        h2o_socket_read_start(sock, proceed_handshake);
    }
    return;

Complete:
    h2o_socket_read_stop(sock);
    on_handshake_complete(sock, status);
}

void h2o_socket_ssl_server_handshake(h2o_socket_t *sock, h2o_ssl_context_t *ssl_ctx, h2o_socket_cb handshake_cb)
{
    static BIO_METHOD bio_methods = {
        BIO_TYPE_FD,
        "h2o_socket",
        write_bio,
        read_bio,
        puts_bio,
        NULL,
        ctrl_bio,
        new_bio,
        free_bio,
        NULL
    };

    BIO *bio;

    sock->ssl = h2o_malloc(sizeof(*sock->ssl));
    memset(sock->ssl, 0, offsetof(struct st_h2o_socket_ssl_t, output.pool));
    h2o_mempool_init(&sock->ssl->output.pool);
    bio = BIO_new(&bio_methods);
    bio->ptr = sock;
    bio->init = 1;
    sock->ssl->ssl = SSL_new(ssl_ctx->ctx);
    SSL_set_bio(sock->ssl->ssl, bio, bio);

    sock->ssl->handshake.cb = handshake_cb;
    proceed_handshake(sock, 0);
}

#if OPENSSL_VERSION_NUMBER >= 0x10002000L
# define USE_ALPN 1
# define USE_NPN 1
#elif OPENSSL_VERSION_NUMBER >= 0x10001000L
# define USE_ALPN 0
# define USE_NPN 1
#else
# define USE_ALPN 0
# define USE_NPN 0
#endif

h2o_buf_t h2o_socket_ssl_get_selected_protocol(h2o_socket_t *sock)
{
    const unsigned char *data = NULL;
    unsigned len = 0;

    assert(sock->ssl != NULL);

#if USE_ALPN
    if (len == 0)
        SSL_get0_alpn_selected(sock->ssl->ssl, &data, &len);
#endif
#if USE_NPN
    if (len == 0)
        SSL_get0_next_proto_negotiated(sock->ssl->ssl, &data, &len);
#endif

    return h2o_buf_init(data, len);
}

#if USE_ALPN
static int on_alpn_select(SSL *ssl, const unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int inlen, void *_ctx)
{
    h2o_ssl_context_t *ctx = _ctx;
    const unsigned char *in_end = in + inlen;
    size_t i;

    while (in != in_end) {
        size_t cand_len = *in++;
        if (in_end - in < cand_len) {
            /* broken request */
            break;
        }
        for (i = 0; ctx->protocols[i].len != 0; ++i) {
            if (cand_len == ctx->protocols[i].len && memcmp(in, ctx->protocols[i].base, cand_len) == 0) {
                goto Found;
            }
        }
        in += cand_len;
    }
    /* not found */
    return SSL_TLSEXT_ERR_NOACK;

Found:
    *out = (const unsigned char*)ctx->protocols[i].base;
    *outlen = (unsigned char)ctx->protocols[i].len;
    return SSL_TLSEXT_ERR_OK;
}
#endif

#if USE_NPN
static int on_npn_advertise(SSL *ssl, const unsigned char **out, unsigned *outlen, void *_ctx)
{
    h2o_ssl_context_t *ctx = _ctx;

    *out = (const unsigned char*)ctx->_npn_list_of_protocols.base;
    *outlen = (unsigned)ctx->_npn_list_of_protocols.len;

    return SSL_TLSEXT_ERR_OK;
}
#endif

h2o_ssl_context_t *h2o_ssl_new_server_context(const char *cert_file, const char *key_file, const h2o_buf_t *protocols)
{
    h2o_ssl_context_t *ctx = h2o_malloc(sizeof(*ctx));

    memset(ctx, 0, sizeof(*ctx));

    SSL_load_error_strings();
    SSL_library_init();
    OpenSSL_add_all_algorithms();

    ctx->ctx = SSL_CTX_new(SSLv23_server_method());
    SSL_CTX_set_options(ctx->ctx, SSL_OP_NO_SSLv2);

    /* load certificate and private key */
    if (SSL_CTX_use_certificate_file(ctx->ctx, cert_file, SSL_FILETYPE_PEM) != 1) {
        fprintf(stderr, "an error occured while trying to load server certificate file:%s\n", cert_file);
        goto Error;
    }
    if (SSL_CTX_use_PrivateKey_file(ctx->ctx, key_file, SSL_FILETYPE_PEM) != 1) {
        fprintf(stderr, "an error occured while trying to load private key file:%s\n", key_file);
        goto Error;
    }

    /* copy list of protocols, init npm */
    ctx->protocols = protocols;
    if (protocols != NULL) {
        size_t i, off;
#if USE_ALPN
        SSL_CTX_set_alpn_select_cb(ctx->ctx, on_alpn_select, ctx);
#endif
#if USE_NPN
        SSL_CTX_set_next_protos_advertised_cb(ctx->ctx, on_npn_advertise, ctx);
#endif
        for (i = 0; protocols[i].len != 0; ++i) {
            assert(protocols[i].len <= 255);
            ctx->_npn_list_of_protocols.len += 1 + protocols[i].len;
        }
        ctx->_npn_list_of_protocols.base = h2o_malloc(ctx->_npn_list_of_protocols.len);
        for (i = 0, off = 0; protocols[i].len != 0; ++i) {
            ((unsigned char*)ctx->_npn_list_of_protocols.base)[off++] = protocols[i].len;
            memcpy(ctx->_npn_list_of_protocols.base + off, protocols[i].base, protocols[i].len);
            off += protocols[i].len;
        }
        assert(off == ctx->_npn_list_of_protocols.len);
    }

    return ctx;
Error:
    SSL_CTX_free(ctx->ctx);
    free(ctx);
    return NULL;
}
