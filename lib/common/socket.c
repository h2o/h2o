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
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <sys/un.h>
#include <unistd.h>
#include <openssl/err.h>
#include "h2o/socket.h"
#include "h2o/timeout.h"

#if defined(__APPLE__) && defined(__clang__)
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#endif

#ifndef IOV_MAX
#define IOV_MAX UIO_MAXIOV
#endif

struct st_h2o_socket_ssl_t {
    SSL *ssl;
    int *did_write_in_read; /* used for detecting and closing the connection upon renegotiation (FIXME implement renegotiation) */
    struct {
        h2o_socket_cb cb;
    } handshake;
    struct {
        h2o_buffer_t *encrypted;
    } input;
    struct {
        H2O_VECTOR(h2o_iovec_t) bufs;
        h2o_mem_pool_t pool; /* placed at the last */
    } output;
};

struct st_h2o_ssl_context_t {
    SSL_CTX *ctx;
    const h2o_iovec_t *protocols;
    h2o_iovec_t _npn_list_of_protocols;
};

/* backend functions */
static void do_dispose_socket(h2o_socket_t *sock);
static void do_write(h2o_socket_t *sock, const h2o_iovec_t *bufs, size_t bufcnt, h2o_socket_cb cb);
static void do_read_start(h2o_socket_t *sock);
static void do_read_stop(h2o_socket_t *sock);
static int do_export(h2o_socket_t *_sock, h2o_socket_export_t *info);
static h2o_socket_t *do_import(h2o_loop_t *loop, h2o_socket_export_t *info);

/* internal functions called from the backend */
static int decode_ssl_input(h2o_socket_t *sock);
static void on_write_complete(h2o_socket_t *sock, int status);

#if H2O_USE_LIBUV
#include "socket/uv-binding.c.h"
#else
#include "socket/evloop.c.h"
#endif

h2o_buffer_mmap_settings_t h2o_socket_buffer_mmap_settings = {
    32 * 1024 * 1024, /* 32MB, should better be greater than max frame size of HTTP2 for performance reasons */
    "/tmp/h2o.b.XXXXXX"};

__thread h2o_buffer_prototype_t h2o_socket_buffer_prototype = {
    {16},                                       /* keep 16 recently used chunks */
    {H2O_SOCKET_INITIAL_INPUT_BUFFER_SIZE * 2}, /* minimum initial capacity */
    &h2o_socket_buffer_mmap_settings};

static int read_bio(BIO *b, char *out, int len)
{
    h2o_socket_t *sock = b->ptr;

    if (len == 0)
        return 0;

    if (sock->ssl->input.encrypted->size == 0) {
        BIO_set_retry_read(b);
        return -1;
    }

    if (sock->ssl->input.encrypted->size < len) {
        len = (int)sock->ssl->input.encrypted->size;
    }
    memcpy(out, sock->ssl->input.encrypted->bytes, len);
    h2o_buffer_consume(&sock->ssl->input.encrypted, len);

    return len;
}

static int write_bio(BIO *b, const char *in, int len)
{
    h2o_socket_t *sock = b->ptr;
    void *bytes_alloced;

    /* FIXME no support for SSL renegotiation (yet) */
    if (sock->ssl->did_write_in_read != NULL) {
        *sock->ssl->did_write_in_read = 1;
        return -1;
    }

    if (len == 0)
        return 0;

    bytes_alloced = h2o_mem_alloc_pool(&sock->ssl->output.pool, len);
    memcpy(bytes_alloced, in, len);

    h2o_vector_reserve(&sock->ssl->output.pool, (h2o_vector_t *)&sock->ssl->output.bufs, sizeof(h2o_iovec_t),
                       sock->ssl->output.bufs.size + 1);
    sock->ssl->output.bufs.entries[sock->ssl->output.bufs.size++] = h2o_iovec_init(bytes_alloced, len);

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

    while (sock->ssl->input.encrypted->size != 0 || SSL_pending(sock->ssl->ssl)) {
        int rlen;
        h2o_iovec_t buf = h2o_buffer_reserve(&sock->input, 4096);
        if (buf.base == NULL)
            return errno;
        { /* call SSL_read (while detecting SSL renegotiation and reporting it as error) */
            int did_write_in_read = 0;
            sock->ssl->did_write_in_read = &did_write_in_read;
            rlen = SSL_read(sock->ssl->ssl, buf.base, (int)buf.len);
            sock->ssl->did_write_in_read = NULL;
            if (did_write_in_read)
                return EIO;
        }
        if (rlen == -1) {
            if (SSL_get_error(sock->ssl->ssl, rlen) != SSL_ERROR_WANT_READ) {
                return EIO;
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
    do_write(sock, sock->ssl->output.bufs.entries, sock->ssl->output.bufs.size, cb);
}

static void destroy_ssl(struct st_h2o_socket_ssl_t *ssl)
{
    SSL_free(ssl->ssl);
    ssl->ssl = NULL;
    h2o_buffer_dispose(&ssl->input.encrypted);
    h2o_mem_clear_pool(&ssl->output.pool);
    free(ssl);
}

static void dispose_socket(h2o_socket_t *sock, int status)
{
    void (*close_cb)(void *data);
    void *close_cb_data;

    if (sock->ssl != NULL) {
        destroy_ssl(sock->ssl);
        sock->ssl = NULL;
    }
    h2o_buffer_dispose(&sock->input);

    close_cb = sock->on_close.cb;
    close_cb_data = sock->on_close.data;

    do_dispose_socket(sock);

    if (close_cb != NULL)
        close_cb(close_cb_data);
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

void h2o_socket_dispose_export(h2o_socket_export_t *info)
{
    assert(info->fd != -1);
    if (info->ssl != NULL) {
        destroy_ssl(info->ssl);
        info->ssl = NULL;
    }
    h2o_buffer_dispose(&info->input);
    close(info->fd);
    info->fd = -1;
}

int h2o_socket_export(h2o_socket_t *sock, h2o_socket_export_t *info)
{
    static h2o_buffer_prototype_t nonpooling_prototype = {};

    assert(!h2o_socket_is_writing(sock));

    if (do_export(sock, info) == -1)
        return -1;

    if ((info->ssl = sock->ssl) != NULL) {
        sock->ssl = NULL;
        h2o_buffer_set_prototype(&info->ssl->input.encrypted, &nonpooling_prototype);
    }
    info->input = sock->input;
    h2o_buffer_set_prototype(&info->input, &nonpooling_prototype);
    h2o_buffer_init(&sock->input, &h2o_socket_buffer_prototype);

    h2o_socket_close(sock);

    return 0;
}

h2o_socket_t *h2o_socket_import(h2o_loop_t *loop, h2o_socket_export_t *info)
{
    h2o_socket_t *sock;

    assert(info->fd != -1);

    sock = do_import(loop, info);
    info->fd = -1; /* just in case */
    if ((sock->ssl = info->ssl) != NULL)
        h2o_buffer_set_prototype(&sock->ssl->input.encrypted, &h2o_socket_buffer_prototype);
    sock->input = info->input;
    h2o_buffer_set_prototype(&sock->input, &h2o_socket_buffer_prototype);
    return sock;
}

void h2o_socket_close(h2o_socket_t *sock)
{
    if (sock->ssl == NULL) {
        dispose_socket(sock, 0);
    } else {
        shutdown_ssl(sock, 0);
    }
}

static int encrypt_ssl(h2o_socket_t *sock, const h2o_iovec_t *bufs, size_t bufcnt)
{
    char *smallbuf = NULL;
    size_t smallbufsz = 0;
    h2o_iovec_t pending = {};
    int wret;

#define COPY_PENDING()                                                                                                             \
    if (pending.len != 0) {                                                                                                        \
        if (smallbuf == NULL)                                                                                                      \
            smallbuf = alloca(H2O_SSL_MAX_PAYLOAD_SIZE);                                                                           \
        memcpy(smallbuf + smallbufsz - pending.len, pending.base, pending.len);                                                    \
        pending.len = 0;                                                                                                           \
    }
#define WRITE_SSL(p, s)                                                                                                            \
    do {                                                                                                                           \
        if ((wret = SSL_write(sock->ssl->ssl, (p), (s))) != (s))                                                                   \
            goto Error;                                                                                                            \
    } while (0)
#define WRITE_SMALL()                                                                                                              \
    do {                                                                                                                           \
        if (smallbufsz == pending.len) {                                                                                           \
            WRITE_SSL(pending.base, (int)pending.len);                                                                             \
        } else {                                                                                                                   \
            COPY_PENDING();                                                                                                        \
            WRITE_SSL(smallbuf, (int)smallbufsz);                                                                                  \
        }                                                                                                                          \
    } while (0)

    for (; bufcnt != 0; ++bufs, --bufcnt) {
        if (smallbufsz + bufs->len < H2O_SSL_MAX_PAYLOAD_SIZE) {
            COPY_PENDING();
            smallbufsz += bufs->len;
            pending = *bufs;
        } else {
            if (smallbufsz != 0) {
                WRITE_SMALL();
                smallbufsz = 0;
            }
            size_t off = 0;
            while (bufs->len - off >= H2O_SSL_MAX_PAYLOAD_SIZE) {
                WRITE_SSL(bufs->base + off, H2O_SSL_MAX_PAYLOAD_SIZE);
                off += H2O_SSL_MAX_PAYLOAD_SIZE;
            }
            if (bufs->len != off) {
                pending = (h2o_iovec_t){bufs->base + off, bufs->len - off};
                smallbufsz = pending.len;
            }
        }
    }
    if (smallbufsz != 0)
        WRITE_SMALL();

    return 0;

Error:
    /* The error happens if SSL_write is called after SSL_read returns a fatal error (e.g. due to corrupt TCP packet being
     * received). We need to take care of this since some protocol implementations send data after the read-side of the connection
     * gets closed (note that protocol implementations are (yet) incapable of distinguishing a normal shutdown and close due to an
     * error using the `status` value of the read callback).
     */
    assert(wret <= 0);
    return -1;

#undef COPY_PENDING
#undef WRITE_SSL
#undef WRITE_SMALL
}

void h2o_socket_write(h2o_socket_t *sock, const h2o_iovec_t *bufs, size_t bufcnt, h2o_socket_cb cb)
{
#if H2O_SOCKET_DUMP_WRITE
    {
        size_t i;
        for (i = 0; i != bufcnt; ++i) {
            fprintf(stderr, "writing %zu bytes to fd:%d\n", bufs[i].len,
#if H2O_USE_LIBUV
                    ((struct st_h2o_uv_socket_t *)sock)->uv.stream->io_watcher.fd
#else
                    ((struct st_h2o_evloop_socket_t *)sock)->fd
#endif
                    );
            h2o_dump_memory(stderr, bufs[i].base, bufs[i].len);
        }
    }
#endif
    if (sock->ssl == NULL) {
        do_write(sock, bufs, bufcnt, cb);
    } else {
        assert(sock->ssl->output.bufs.size == 0);
        /* fill in the data */
        if (encrypt_ssl(sock, bufs, bufcnt) != 0) {
            memset(&sock->ssl->output.bufs, 0, sizeof(sock->ssl->output.bufs));
            h2o_mem_clear_pool(&sock->ssl->output.pool);
            flush_pending_ssl(sock, cb);
#ifndef H2O_USE_LIBUV
            ((struct st_h2o_evloop_socket_t *)sock)->_flags |= H2O_SOCKET_FLAG_IS_WRITE_ERROR;
#endif
            return;
        }
        flush_pending_ssl(sock, cb);
    }
}

void on_write_complete(h2o_socket_t *sock, int status)
{
    h2o_socket_cb cb;

    if (sock->ssl != NULL) {
        memset(&sock->ssl->output.bufs, 0, sizeof(sock->ssl->output.bufs));
        h2o_mem_clear_pool(&sock->ssl->output.pool);
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

int h2o_socket_compare_address(struct sockaddr *x, struct sockaddr *y)
{
#define CMP(a, b)                                                                                                                  \
    if (a != b)                                                                                                                    \
    return a < b ? -1 : 1

    CMP(x->sa_family, y->sa_family);

    if (x->sa_family == AF_UNIX) {
        struct sockaddr_un *xun = (void *)x, *yun = (void *)y;
        int r = strcmp(xun->sun_path, yun->sun_path);
        if (r != 0)
            return r;
    } else if (x->sa_family == AF_INET) {
        struct sockaddr_in *xin = (void *)x, *yin = (void *)y;
        CMP(ntohl(xin->sin_addr.s_addr), ntohl(yin->sin_addr.s_addr));
        CMP(ntohs(xin->sin_port), ntohs(yin->sin_port));
    } else if (x->sa_family == AF_INET6) {
        struct sockaddr_in6 *xin6 = (void *)x, *yin6 = (void *)y;
        int r = memcmp(xin6->sin6_addr.s6_addr, yin6->sin6_addr.s6_addr, sizeof(xin6->sin6_addr.s6_addr));
        if (r != 0)
            return r;
        CMP(ntohs(xin6->sin6_port), ntohs(yin6->sin6_port));
        CMP(xin6->sin6_flowinfo, yin6->sin6_flowinfo);
        CMP(xin6->sin6_scope_id, yin6->sin6_scope_id);
    } else {
        assert(!"unknown sa_family");
    }

#undef CMP
    return 0;
}

size_t h2o_socket_getnumerichost(struct sockaddr *sa, socklen_t salen, char *buf)
{
    if (sa->sa_family == AF_INET) {
        /* fast path for IPv4 addresses */
        struct sockaddr_in *sin = (void *)sa;
        uint32_t addr;
        addr = htonl(sin->sin_addr.s_addr);
        return sprintf(buf, "%d.%d.%d.%d", addr >> 24, (addr >> 16) & 255, (addr >> 8) & 255, addr & 255);
    }

    if (getnameinfo(sa, salen, buf, NI_MAXHOST, NULL, 0, NI_NUMERICHOST) != 0)
        return SIZE_MAX;
    return strlen(buf);
}

static void on_handshake_complete(h2o_socket_t *sock, int status)
{
    h2o_socket_cb handshake_cb = sock->ssl->handshake.cb;
    sock->_cb.write = NULL;
    sock->ssl->handshake.cb = NULL;
    decode_ssl_input(sock);
    handshake_cb(sock, status);
}

static void proceed_handshake(h2o_socket_t *sock, int status)
{
    int ret;

    sock->_cb.write = NULL;

    if (status != 0) {
        goto Complete;
    }

Redo:
    ret = SSL_accept(sock->ssl->ssl);

    if (ret == 0 || (ret < 0 && SSL_get_error(sock->ssl->ssl, ret) != SSL_ERROR_WANT_READ)) {
        /* failed */
        status = -1;
        goto Complete;
    }

    if (sock->ssl->output.bufs.size != 0) {
        h2o_socket_read_stop(sock);
        flush_pending_ssl(sock, ret == 1 ? on_handshake_complete : proceed_handshake);
    } else {
        if (ret == 1) {
            goto Complete;
        }
        if (sock->ssl->input.encrypted->size != 0)
            goto Redo;
        h2o_socket_read_start(sock, proceed_handshake);
    }
    return;

Complete:
    h2o_socket_read_stop(sock);
    on_handshake_complete(sock, status);
}

void h2o_socket_ssl_server_handshake(h2o_socket_t *sock, SSL_CTX *ssl_ctx, h2o_socket_cb handshake_cb)
{
    static BIO_METHOD bio_methods = {BIO_TYPE_FD, "h2o_socket", write_bio, read_bio, puts_bio,
                                     NULL,        ctrl_bio,     new_bio,   free_bio, NULL};

    BIO *bio;

    sock->ssl = h2o_mem_alloc(sizeof(*sock->ssl));
    memset(sock->ssl, 0, offsetof(struct st_h2o_socket_ssl_t, output.pool));
    h2o_buffer_init(&sock->ssl->input.encrypted, &h2o_socket_buffer_prototype);
    h2o_mem_init_pool(&sock->ssl->output.pool);
    bio = BIO_new(&bio_methods);
    bio->ptr = sock;
    bio->init = 1;
    sock->ssl->ssl = SSL_new(ssl_ctx);
    SSL_set_bio(sock->ssl->ssl, bio, bio);

    sock->ssl->handshake.cb = handshake_cb;
    proceed_handshake(sock, 0);
}

h2o_iovec_t h2o_socket_ssl_get_selected_protocol(h2o_socket_t *sock)
{
    const unsigned char *data = NULL;
    unsigned len = 0;

    assert(sock->ssl != NULL);

#if H2O_USE_ALPN
    if (len == 0)
        SSL_get0_alpn_selected(sock->ssl->ssl, &data, &len);
#endif
#if H2O_USE_NPN
    if (len == 0)
        SSL_get0_next_proto_negotiated(sock->ssl->ssl, &data, &len);
#endif

    return h2o_iovec_init(data, len);
}

#if H2O_USE_ALPN

static int on_alpn_select(SSL *ssl, const unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int inlen,
                          void *_protocols)
{
    const h2o_iovec_t *protocols = _protocols;
    const unsigned char *in_end = in + inlen;
    size_t i;

    while (in != in_end) {
        size_t cand_len = *in++;
        if (in_end - in < cand_len) {
            /* broken request */
            break;
        }
        for (i = 0; protocols[i].len != 0; ++i) {
            if (cand_len == protocols[i].len && memcmp(in, protocols[i].base, cand_len) == 0) {
                goto Found;
            }
        }
        in += cand_len;
    }
    /* not found */
    return SSL_TLSEXT_ERR_NOACK;

Found:
    *out = (const unsigned char *)protocols[i].base;
    *outlen = (unsigned char)protocols[i].len;
    return SSL_TLSEXT_ERR_OK;
}

void h2o_ssl_register_alpn_protocols(SSL_CTX *ctx, const h2o_iovec_t *protocols)
{
    SSL_CTX_set_alpn_select_cb(ctx, on_alpn_select, (void *)protocols);
}

#endif

#if H2O_USE_NPN

static int on_npn_advertise(SSL *ssl, const unsigned char **out, unsigned *outlen, void *protocols)
{
    *out = protocols;
    *outlen = (unsigned)strlen(protocols);
    return SSL_TLSEXT_ERR_OK;
}

void h2o_ssl_register_npn_protocols(SSL_CTX *ctx, const char *protocols)
{
    SSL_CTX_set_next_protos_advertised_cb(ctx, on_npn_advertise, (void *)protocols);
}

#endif
