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
#ifndef h2o__socket_h
#define h2o__socket_h

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include "h2o/memory.h"

#ifndef H2O_USE_LIBUV
#if H2O_USE_SELECT || H2O_USE_EPOLL || H2O_USE_KQUEUE
#define H2O_USE_LIBUV 0
#else
#define H2O_USE_LIBUV 1
#endif
#endif

#if OPENSSL_VERSION_NUMBER >= 0x10002000L
#define H2O_USE_ALPN 1
#define H2O_USE_NPN 1
#elif OPENSSL_VERSION_NUMBER >= 0x10001000L
#define H2O_USE_ALPN 0
#define H2O_USE_NPN 1
#else
#define H2O_USE_ALPN 0
#define H2O_USE_NPN 0
#endif

#define H2O_SOCKET_INITIAL_INPUT_BUFFER_SIZE 4096

typedef struct st_h2o_socket_t h2o_socket_t;

typedef void (*h2o_socket_cb)(h2o_socket_t *sock, int err);

#if H2O_USE_LIBUV
#include "socket/uv-binding.h"
#else
#include "socket/evloop.h"
#endif

typedef struct st_h2o_socket_peername_t {
    struct sockaddr_storage addr;
    socklen_t len;
} h2o_socket_peername_t;

/**
 * abstraction layer for sockets (SSL vs. TCP)
 */
struct st_h2o_socket_t {
    void *data;
    void *data2;
    struct st_h2o_socket_ssl_t *ssl;
    h2o_buffer_t *input;
    size_t bytes_read;
    struct {
        void (*cb)(void *data);
        void *data;
    } on_close;
    struct {
        h2o_socket_cb read;
        h2o_socket_cb write;
    } _cb;
    /* zero-filled in case of invalid address */
    h2o_socket_peername_t peername;
};

typedef struct st_h2o_socket_export_t {
    int fd;
    h2o_socket_peername_t peername;
    struct st_h2o_socket_ssl_t *ssl;
    h2o_buffer_t *input;
} h2o_socket_export_t;

extern h2o_buffer_mmap_settings_t h2o_socket_buffer_mmap_settings;
extern __thread h2o_buffer_prototype_t h2o_socket_buffer_prototype;

/**
 * returns the loop
 */
h2o_loop_t *h2o_socket_get_loop(h2o_socket_t *sock);
/**
 * detaches a socket from loop.
 */
int h2o_socket_export(h2o_socket_t *sock, h2o_socket_export_t *info);
/**
 * attaches a socket onto a loop.
 */
h2o_socket_t *h2o_socket_import(h2o_loop_t *loop, h2o_socket_export_t *info);
/**
 * destroys an exported socket info.
 */
void h2o_socket_dispose_export(h2o_socket_export_t *info);
/**
 * closes the socket
 */
void h2o_socket_close(h2o_socket_t *sock);
/**
 * connects to peer
 */
h2o_socket_t *h2o_socket_connect(h2o_loop_t *loop, struct sockaddr *addr, socklen_t addrlen, h2o_socket_cb cb);
/**
 * writes given data to socket
 * @param sock the socket
 * @param bufs an array of buffers
 * @param bufcnt length of the buffer array
 * @param cb callback to be called when write is complete
 */
void h2o_socket_write(h2o_socket_t *sock, const h2o_iovec_t *bufs, size_t bufcnt, h2o_socket_cb cb);
/**
 * starts polling on the socket (for read) and calls given callback when data arrives
 * @param sock the socket
 * @param cb callback to be called when data arrives
 * @note callback is called when any data arrives at the TCP level so that the
 * applications can update their timeout counters.  In other words, there is no
 * guarantee that _new_ data is available when the callback gets called (e.g.
 * in cases like receiving a partial SSL record or a corrupt TCP packet).
 */
void h2o_socket_read_start(h2o_socket_t *sock, h2o_socket_cb cb);
/**
 * stops polling on the socket (for read)
 * @param sock the socket
 */
void h2o_socket_read_stop(h2o_socket_t *sock);
/**
 * returns a boolean value indicating whether if there is a write is under operation
 */
static int h2o_socket_is_writing(h2o_socket_t *sock);
/**
 * returns a boolean value indicating whether if the socket is being polled for read
 */
static int h2o_socket_is_reading(h2o_socket_t *sock);
/**
 * compares socket addresses
 */
int h2o_socket_compare_address(struct sockaddr *x, struct sockaddr *y);
/**
 * getnameinfo (buf should be NI_MAXHOST in length), returns SIZE_MAX if failed
 */
size_t h2o_socket_getnumerichost(struct sockaddr *sa, socklen_t salen, char *buf);
/**
 * performs SSL handshake on a socket
 * @param sock the socket
 * @param ssl_ctx SSL context
 * @param handshake_cb callback to be called when handshake is complete
 */
void h2o_socket_ssl_server_handshake(h2o_socket_t *sock, SSL_CTX *ssl_ctx, h2o_socket_cb handshake_cb);
/**
 * returns the name of the protocol selected using either NPN or ALPN (ALPN has the precedence).
 * @param sock the socket
 */
h2o_iovec_t h2o_socket_ssl_get_selected_protocol(h2o_socket_t *sock);
/**
 * registers the protocol list to be used for ALPN
 */
void h2o_ssl_register_alpn_protocols(SSL_CTX *ctx, const h2o_iovec_t *protocols);
/**
 * registers the protocol list to be used for NPN
 */
void h2o_ssl_register_npn_protocols(SSL_CTX *ctx, const char *protocols);

void h2o_socket__write_pending(h2o_socket_t *sock);
void h2o_socket__write_on_complete(h2o_socket_t *sock, int status);

/* inline defs */

inline int h2o_socket_is_writing(h2o_socket_t *sock)
{
    return sock->_cb.write != NULL;
}

inline int h2o_socket_is_reading(h2o_socket_t *sock)
{
    return sock->_cb.read != NULL;
}

#ifdef __cplusplus
}
#endif

#endif
