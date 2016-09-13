/*
 * Copyright (c) 2014-2016 DeNA Co., Ltd., Kazuho Oku, Fastly, Inc.
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
#include "h2o/cache.h"
#include "h2o/memory.h"
#include "h2o/openssl_backport.h"
#include "h2o/string_.h"

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

typedef struct st_h2o_sliding_counter_t {
    uint64_t average;
    struct {
        uint64_t sum;
        uint64_t slots[8];
        size_t index;
    } prev;
    struct {
        uint64_t start_at;
    } cur;
} h2o_sliding_counter_t;

static int h2o_sliding_counter_is_running(h2o_sliding_counter_t *counter);
static void h2o_sliding_counter_start(h2o_sliding_counter_t *counter, uint64_t now);
void h2o_sliding_counter_stop(h2o_sliding_counter_t *counter, uint64_t now);

#define H2O_SOCKET_INITIAL_INPUT_BUFFER_SIZE 4096

typedef struct st_h2o_socket_t h2o_socket_t;

typedef void (*h2o_socket_cb)(h2o_socket_t *sock, const char *err);

#if H2O_USE_LIBUV
#include "socket/uv-binding.h"
#else
#include "socket/evloop.h"
#endif

struct st_h2o_socket_peername_t {
    socklen_t len;
    struct sockaddr addr;
};

enum {
    H2O_SOCKET_LATENCY_OPTIMIZATION_STATE_TBD = 0,
    H2O_SOCKET_LATENCY_OPTIMIZATION_STATE_NEEDS_UPDATE,
    H2O_SOCKET_LATENCY_OPTIMIZATION_STATE_DISABLED,
    H2O_SOCKET_LATENCY_OPTIMIZATION_STATE_DETERMINED
};

/**
 * abstraction layer for sockets (SSL vs. TCP)
 */
struct st_h2o_socket_t {
    void *data;
    struct st_h2o_socket_ssl_t *ssl;
    h2o_buffer_t *input;
    /**
     * total bytes read (above the TLS layer)
     */
    size_t bytes_read;
    /**
     * total bytes written (above the TLS layer)
     */
    size_t bytes_written;
    struct {
        void (*cb)(void *data);
        void *data;
    } on_close;
    struct {
        h2o_socket_cb read;
        h2o_socket_cb write;
    } _cb;
    struct st_h2o_socket_peername_t *_peername;
    struct {
        uint8_t state; /* one of H2O_SOCKET_LATENCY_STATE_* */
        uint8_t notsent_is_minimized : 1;
        uint16_t suggested_tls_payload_size;
        size_t suggested_write_size; /* SIZE_MAX if no need to optimize for latency */
    } _latency_optimization;
};

typedef struct st_h2o_socket_export_t {
    int fd;
    struct st_h2o_socket_ssl_t *ssl;
    h2o_buffer_t *input;
} h2o_socket_export_t;

/**
 * sets the conditions to enable the optimization
 */
typedef struct st_h2o_socket_latency_optimization_conditions_t {
    /**
     * in milliseconds
     */
    unsigned min_rtt;
    /**
     * percent ratio
     */
    unsigned max_additional_delay;
    /**
     * in number of octets
     */
    unsigned max_cwnd;
} h2o_socket_latency_optimization_conditions_t;

typedef void (*h2o_socket_ssl_resumption_get_async_cb)(h2o_socket_t *sock, h2o_iovec_t session_id);
typedef void (*h2o_socket_ssl_resumption_new_cb)(h2o_iovec_t session_id, h2o_iovec_t session_data);
typedef void (*h2o_socket_ssl_resumption_remove_cb)(h2o_iovec_t session_id);

extern h2o_buffer_mmap_settings_t h2o_socket_buffer_mmap_settings;
extern __thread h2o_buffer_prototype_t h2o_socket_buffer_prototype;

extern const char *h2o_socket_error_out_of_memory;
extern const char *h2o_socket_error_io;
extern const char *h2o_socket_error_closed;
extern const char *h2o_socket_error_conn_fail;
extern const char *h2o_socket_error_ssl_no_cert;
extern const char *h2o_socket_error_ssl_cert_invalid;
extern const char *h2o_socket_error_ssl_cert_name_mismatch;
extern const char *h2o_socket_error_ssl_decode;

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
 * Schedules a callback to be notify we the socket can be written to
 */
void h2o_socket_notify_write(h2o_socket_t *sock, h2o_socket_cb cb);
/**
 * Obtain the underlying fd of a sock struct
 */
int h2o_socket_get_fd(h2o_socket_t *sock);
/**
 * Set/Unset the H2O_SOCKET_FLAG_DONT_READ flag.
 * Setting it allows to be simply notified rather than having the data
 * automatically be read.
 */
void h2o_socket_dont_read(h2o_socket_t *sock, int dont_read);
/**
 * connects to peer
 */
h2o_socket_t *h2o_socket_connect(h2o_loop_t *loop, struct sockaddr *addr, socklen_t addrlen, h2o_socket_cb cb);
/**
 * prepares for latency-optimized write and returns the number of octets that should be written, or SIZE_MAX if failed to prepare
 */
static size_t h2o_socket_prepare_for_latency_optimized_write(h2o_socket_t *sock,
                                                             const h2o_socket_latency_optimization_conditions_t *conditions);
size_t h2o_socket_do_prepare_for_latency_optimized_write(h2o_socket_t *sock,
                                                         const h2o_socket_latency_optimization_conditions_t *conditions);
/**
 * writes given data to socket
 * @param sock the socket
 * @param bufs an array of buffers
 * @param bufcnt length of the buffer array
 * @param cb callback to be called when write is complete
 */
void h2o_socket_write(h2o_socket_t *sock, h2o_iovec_t *bufs, size_t bufcnt, h2o_socket_cb cb);
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
 * returns the length of the local address obtained (or 0 if failed)
 */
socklen_t h2o_socket_getsockname(h2o_socket_t *sock, struct sockaddr *sa);
/**
 * returns the length of the remote address obtained (or 0 if failed)
 */
socklen_t h2o_socket_getpeername(h2o_socket_t *sock, struct sockaddr *sa);
/**
 * sets the remote address (used for overriding the value)
 */
void h2o_socket_setpeername(h2o_socket_t *sock, struct sockaddr *sa, socklen_t len);
/**
 *
 */
const char *h2o_socket_get_ssl_protocol_version(h2o_socket_t *sock);
int h2o_socket_get_ssl_session_reused(h2o_socket_t *sock);
const char *h2o_socket_get_ssl_cipher(h2o_socket_t *sock);
int h2o_socket_get_ssl_cipher_bits(h2o_socket_t *sock);
static h2o_iovec_t h2o_socket_log_ssl_protocol_version(h2o_socket_t *sock, h2o_mem_pool_t *pool);
static h2o_iovec_t h2o_socket_log_ssl_session_reused(h2o_socket_t *sock, h2o_mem_pool_t *pool);
static h2o_iovec_t h2o_socket_log_ssl_cipher(h2o_socket_t *sock, h2o_mem_pool_t *pool);
h2o_iovec_t h2o_socket_log_ssl_cipher_bits(h2o_socket_t *sock, h2o_mem_pool_t *pool);
/**
 * compares socket addresses
 */
int h2o_socket_compare_address(struct sockaddr *x, struct sockaddr *y);
/**
 * getnameinfo (buf should be NI_MAXHOST in length), returns SIZE_MAX if failed
 */
size_t h2o_socket_getnumerichost(struct sockaddr *sa, socklen_t salen, char *buf);
/**
 * returns the port number, or -1 if failed
 */
int32_t h2o_socket_getport(struct sockaddr *sa);
/**
 * performs SSL handshake on a socket
 * @param sock the socket
 * @param ssl_ctx SSL context
 * @param handshake_cb callback to be called when handshake is complete
 */
void h2o_socket_ssl_handshake(h2o_socket_t *sock, SSL_CTX *ssl_ctx, const char *server_name, h2o_socket_cb handshake_cb);
/**
 * resumes SSL handshake with given session data
 * @param sock the socket
 * @param session_data session data (or {NULL,0} if not available)
 */
void h2o_socket_ssl_resume_server_handshake(h2o_socket_t *sock, h2o_iovec_t session_data);
/**
 * registers callbacks to be called for handling session data
 */
void h2o_socket_ssl_async_resumption_init(h2o_socket_ssl_resumption_get_async_cb get_cb, h2o_socket_ssl_resumption_new_cb new_cb,
                                          h2o_socket_ssl_resumption_remove_cb remove_cb);
/**
 * setups the SSL context to use the async resumption
 */
void h2o_socket_ssl_async_resumption_setup_ctx(SSL_CTX *ctx);
/**
 * returns the name of the protocol selected using either NPN or ALPN (ALPN has the precedence).
 * @param sock the socket
 */
h2o_iovec_t h2o_socket_ssl_get_selected_protocol(h2o_socket_t *sock);
/**
 *
 */
h2o_cache_t *h2o_socket_ssl_get_session_cache(SSL_CTX *ctx);
/**
 *
 */
void h2o_socket_ssl_set_session_cache(SSL_CTX *ctx, h2o_cache_t *cache);
/**
 *
 */
void h2o_socket_ssl_destroy_session_cache_entry(h2o_iovec_t value);
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

inline size_t h2o_socket_prepare_for_latency_optimized_write(h2o_socket_t *sock,
                                                             const h2o_socket_latency_optimization_conditions_t *conditions)
{
    switch (sock->_latency_optimization.state) {
    case H2O_SOCKET_LATENCY_OPTIMIZATION_STATE_TBD:
    case H2O_SOCKET_LATENCY_OPTIMIZATION_STATE_NEEDS_UPDATE:
        return h2o_socket_do_prepare_for_latency_optimized_write(sock, conditions);
    default:
        return sock->_latency_optimization.suggested_write_size;
    }
}

inline h2o_iovec_t h2o_socket_log_ssl_protocol_version(h2o_socket_t *sock, h2o_mem_pool_t *pool)
{
    const char *s = h2o_socket_get_ssl_protocol_version(sock);
    return s != NULL ? h2o_iovec_init(s, strlen(s)) : h2o_iovec_init(H2O_STRLIT("-"));
}

inline h2o_iovec_t h2o_socket_log_ssl_session_reused(h2o_socket_t *sock, h2o_mem_pool_t *pool)
{
    switch (h2o_socket_get_ssl_session_reused(sock)) {
    case 0:
        return h2o_iovec_init(H2O_STRLIT("0"));
    case 1:
        return h2o_iovec_init(H2O_STRLIT("1"));
    default:
        return h2o_iovec_init(H2O_STRLIT("-"));
    }
}

inline h2o_iovec_t h2o_socket_log_ssl_cipher(h2o_socket_t *sock, h2o_mem_pool_t *pool)
{
    const char *s = h2o_socket_get_ssl_cipher(sock);
    return s != NULL ? h2o_iovec_init(s, strlen(s)) : h2o_iovec_init(H2O_STRLIT("-"));
}

inline int h2o_sliding_counter_is_running(h2o_sliding_counter_t *counter)
{
    return counter->cur.start_at != 0;
}

inline void h2o_sliding_counter_start(h2o_sliding_counter_t *counter, uint64_t now)
{
    counter->cur.start_at = now;
}

#ifdef __cplusplus
}
#endif

#endif
