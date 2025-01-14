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
#include <time.h>
#ifdef __linux__
#include <linux/errqueue.h>
#endif
#include <openssl/ssl.h>
#include <openssl/opensslconf.h>
#include "picotls.h"
#include "picotls/openssl.h" /* for H2O_CAN_OSSL_ASYNC */
#include "h2o/cache.h"
#include "h2o/memory.h"
#include "h2o/openssl_backport.h"
#include "h2o/string_.h"

#ifndef H2O_USE_LIBUV
#if H2O_USE_POLL || H2O_USE_EPOLL || H2O_USE_KQUEUE
#define H2O_USE_LIBUV 0
#else
#define H2O_USE_LIBUV 1
#endif
#endif

#if defined(SO_ZEROCOPY) && defined(SO_EE_ORIGIN_ZEROCOPY) && defined(MSG_ZEROCOPY)
#define H2O_USE_MSG_ZEROCOPY 1
#endif

#if OPENSSL_VERSION_NUMBER >= 0x10002000L
#define H2O_USE_ALPN 1
#ifndef OPENSSL_NO_NEXTPROTONEG
#define H2O_USE_NPN 1
#else
#define H2O_USE_NPN 0
#endif
#elif OPENSSL_VERSION_NUMBER >= 0x10001000L
#define H2O_USE_ALPN 0
#define H2O_USE_NPN 1
#else
#define H2O_USE_ALPN 0
#define H2O_USE_NPN 0
#endif

#if !defined(LIBRESSL_VERSION_NUMBER) && !defined(OPENSSL_IS_BORINGSSL) && OPENSSL_VERSION_NUMBER >= 0x1010100fL
#define H2O_USE_OPENSSL_CLIENT_HELLO_CB 1
#endif
#if PTLS_OPENSSL_HAVE_ASYNC && H2O_USE_OPENSSL_CLIENT_HELLO_CB
#define H2O_CAN_OSSL_ASYNC 1
#endif

/**
 * Maximum size of sendvec when a pull (i.e. non-raw) vector is used. Note also that bufcnt must be set to one when a pull mode
 * vector is used.
 */
#define H2O_PULL_SENDVEC_MAX_SIZE 65536
/**
 * Maximum amount of TLS records to generate at once. Default is 4 full-sized TLS records using 32-byte tag. This value is defined
 * to be slightly greater than H2O_PULL_SENDVEC_MAX_SIZE, so that the two buffers can recycle the same memory buffers.
 */
#define H2O_SOCKET_DEFAULT_SSL_BUFFER_SIZE ((5 + 16384 + 32) * 4)

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

#define H2O_SESSID_CTX ((const uint8_t *)"h2o")
#define H2O_SESSID_CTX_LEN (sizeof("h2o") - 1)

typedef struct st_h2o_socket_t h2o_socket_t;

typedef void (*h2o_socket_cb)(h2o_socket_t *sock, const char *err);

#if H2O_USE_LIBUV
#include "socket/uv-binding.h"
#else
#include "socket/evloop.h"
#endif

struct st_h2o_socket_addr_t {
    socklen_t len;
    struct sockaddr addr;
};

enum {
    H2O_SOCKET_LATENCY_OPTIMIZATION_STATE_TBD = 0,
    H2O_SOCKET_LATENCY_OPTIMIZATION_STATE_NEEDS_UPDATE,
    H2O_SOCKET_LATENCY_OPTIMIZATION_STATE_DISABLED,
    H2O_SOCKET_LATENCY_OPTIMIZATION_STATE_DETERMINED
};

typedef struct st_h2o_sendvec_t h2o_sendvec_t;

/**
 * Callbacks of `h2o_sendvec_t`. Random access capability has been removed. `read_` and `send_` only provide one-pass sequential
 * access. Properties of `h2o_sendvec_t` (e.g., `len`, `raw`) are adjusted as bytes are read / sent from the vector.
 */
typedef struct st_h2o_sendvec_callbacks_t {
    /**
     * Mandatory callback used to load the bytes held by the vector. Returns if the operation succeeded. When false is returned, the
     * generator is considered as been error-closed by itself.  If the callback is `h2o_sendvec_read_raw`, the data is available as
     * raw bytes in `h2o_sendvec_t::raw`.
     */
    int (*read_)(h2o_sendvec_t *vec, void *dst, size_t len);
    /**
     * Optional callback for sending contents of a vector directly to a socket. Returns number of bytes being sent (could be zero),
     * or, upon error, SIZE_MAX.
     */
    size_t (*send_)(h2o_sendvec_t *vec, int sockfd, size_t len);
} h2o_sendvec_callbacks_t;

/**
 * send vector. Unlike an ordinary `h2o_iovec_t`, the vector has a callback that allows the sender to delay the flattening of data
 * until it becomes necessary.
 */
struct st_h2o_sendvec_t {
    /**
     *
     */
    const h2o_sendvec_callbacks_t *callbacks;
    /**
     * size of the vector
     */
    size_t len;
    /**
     *
     */
    union {
        char *raw;
        uint64_t cb_arg[2];
    };
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
    uint64_t bytes_read;
    /**
     * total bytes written (above the TLS layer)
     */
    uint64_t bytes_written;
    /**
     * trace state; when picotls is used as the TLS stack, this state is duplicated to that of picotls to achieve consistent
     * behavior across layers
     */
    ptls_log_conn_state_t _log_state;
    struct {
        void (*cb)(void *data);
        void *data;
    } on_close;
    struct {
        h2o_socket_cb read;
        h2o_socket_cb write;
    } _cb;
    struct st_h2o_socket_addr_t *_peername;
    struct st_h2o_socket_addr_t *_sockname;
    struct {
        size_t cnt;
        h2o_iovec_t *bufs;
        union {
            h2o_iovec_t *alloced_ptr;
            h2o_iovec_t smallbufs[4];
        };
        char *flattened;
    } _write_buf;
    struct {
        uint8_t state; /* one of H2O_SOCKET_LATENCY_STATE_* */
        uint8_t notsent_is_minimized : 1;
        size_t suggested_tls_payload_size; /* suggested TLS record payload size, or SIZE_MAX when no need to restrict */
        size_t suggested_write_size;       /* SIZE_MAX if no need to optimize for latency */
    } _latency_optimization;
    struct st_h2o_socket_zerocopy_buffers_t *_zerocopy;
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
typedef void (*h2o_socket_ssl_resumption_new_cb)(h2o_socket_t *sock, h2o_iovec_t session_id, h2o_iovec_t session_data);
typedef void (*h2o_socket_ssl_resumption_remove_cb)(h2o_iovec_t session_id);

extern h2o_buffer_mmap_settings_t h2o_socket_buffer_mmap_settings;
extern h2o_buffer_prototype_t h2o_socket_buffer_prototype;

/**
 * see H2O_SOCKET_DEFAULT_SSL_BUFFER_SIZE
 */
extern h2o_mem_recycle_conf_t h2o_socket_ssl_buffer_conf;
extern __thread h2o_mem_recycle_t h2o_socket_ssl_buffer_allocator;
extern __thread h2o_mem_recycle_t h2o_socket_zerocopy_buffer_allocator;
extern __thread size_t h2o_socket_num_zerocopy_buffers_inflight;

/**
 * boolean flag indicating if kTLS should be used (when preferable)
 */
extern int h2o_socket_use_ktls;

extern const char h2o_socket_error_out_of_memory[];
extern const char h2o_socket_error_io[];
extern const char h2o_socket_error_closed[];
extern const char h2o_socket_error_conn_fail[];
extern const char h2o_socket_error_conn_refused[];
extern const char h2o_socket_error_conn_timed_out[];
extern const char h2o_socket_error_network_unreachable[];
extern const char h2o_socket_error_host_unreachable[];
extern const char h2o_socket_error_socket_fail[];
extern const char h2o_socket_error_ssl_no_cert[];
extern const char h2o_socket_error_ssl_cert_invalid[];
extern const char h2o_socket_error_ssl_cert_name_mismatch[];
extern const char h2o_socket_error_ssl_decode[];
extern const char h2o_socket_error_ssl_handshake[];

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
 * Schedules a callback that would be invoked when the socket becomes immediately writable
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
h2o_socket_t *h2o_socket_connect(h2o_loop_t *loop, struct sockaddr *addr, socklen_t addrlen, h2o_socket_cb cb, const char **err);
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
 *
 */
void h2o_socket_sendvec(h2o_socket_t *sock, h2o_sendvec_t *bufs, size_t bufcnt, h2o_socket_cb cb);
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
ptls_t *h2o_socket_get_ptls(h2o_socket_t *sock);
/**
 *
 */
int h2o_socket_can_tls_offload(h2o_socket_t *sock);
/**
 *
 */
h2o_iovec_t h2o_socket_log_tcp_congestion_controller(h2o_socket_t *sock, h2o_mem_pool_t *pool);
h2o_iovec_t h2o_socket_log_tcp_delivery_rate(h2o_socket_t *sock, h2o_mem_pool_t *pool);
const char *h2o_socket_get_ssl_protocol_version(h2o_socket_t *sock);
int h2o_socket_get_ssl_session_reused(h2o_socket_t *sock);
const char *h2o_socket_get_ssl_cipher(h2o_socket_t *sock);
int h2o_socket_get_ssl_cipher_bits(h2o_socket_t *sock);
h2o_iovec_t h2o_socket_get_ssl_session_id(h2o_socket_t *sock);
const char *h2o_socket_get_ssl_server_name(const h2o_socket_t *sock);
static h2o_iovec_t h2o_socket_log_ssl_protocol_version(h2o_socket_t *sock, h2o_mem_pool_t *pool);
static h2o_iovec_t h2o_socket_log_ssl_session_reused(h2o_socket_t *sock, h2o_mem_pool_t *pool);
static h2o_iovec_t h2o_socket_log_ssl_cipher(h2o_socket_t *sock, h2o_mem_pool_t *pool);
h2o_iovec_t h2o_socket_log_ssl_cipher_bits(h2o_socket_t *sock, h2o_mem_pool_t *pool);
h2o_iovec_t h2o_socket_log_ssl_session_id(h2o_socket_t *sock, h2o_mem_pool_t *pool);
static h2o_iovec_t h2o_socket_log_ssl_server_name(h2o_socket_t *sock, h2o_mem_pool_t *pool);
static h2o_iovec_t h2o_socket_log_ssl_negotiated_protocol(h2o_socket_t *sock, h2o_mem_pool_t *pool);
h2o_iovec_t h2o_socket_log_ssl_ech_config_id(h2o_socket_t *sock, h2o_mem_pool_t *pool);
h2o_iovec_t h2o_socket_log_ssl_ech_kem(h2o_socket_t *sock, h2o_mem_pool_t *pool);
h2o_iovec_t h2o_socket_log_ssl_ech_cipher(h2o_socket_t *sock, h2o_mem_pool_t *pool);
h2o_iovec_t h2o_socket_log_ssl_ech_cipher_bits(h2o_socket_t *sock, h2o_mem_pool_t *pool);
h2o_iovec_t h2o_socket_log_ssl_backend(h2o_socket_t *sock, h2o_mem_pool_t *pool);
int h2o_socket_ssl_new_session_cb(SSL *s, SSL_SESSION *sess);

/**
 * compares socket addresses
 */
int h2o_socket_compare_address(struct sockaddr *x, struct sockaddr *y, int check_port);
/**
 * getnameinfo (buf should be NI_MAXHOST in length), returns SIZE_MAX if failed
 */
size_t h2o_socket_getnumerichost(const struct sockaddr *sa, socklen_t salen, char *buf);
/**
 * returns the port number, or -1 if failed
 */
int32_t h2o_socket_getport(const struct sockaddr *sa);
/**
 * converts given error number to string representation if known, otherwise returns `default_err`
 */
const char *h2o_socket_get_error_string(int errnum, const char *default_err);
/**
 * performs SSL handshake on a socket
 * @param sock the socket
 * @param ssl_ctx SSL context
 * @param handshake_cb callback to be called when handshake is complete
 */
void h2o_socket_ssl_handshake(h2o_socket_t *sock, SSL_CTX *ssl_ctx, const char *server_name, h2o_iovec_t alpn_protos,
                              h2o_socket_cb handshake_cb);
/**
 * resumes SSL handshake with given session data
 * @param sock the socket
 * @param session_data session data (or {NULL,0} if not available)
 */
void h2o_socket_ssl_resume_server_handshake(h2o_socket_t *sock, h2o_iovec_t session_data);
/**
 * registers callbacks to be called for handling session data
 */
void h2o_socket_ssl_async_resumption_init(h2o_socket_ssl_resumption_get_async_cb get_cb, h2o_socket_ssl_resumption_new_cb new_cb);
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
 * returns if the socket is in early-data state (i.e. have not yet seen ClientFinished)
 */
int h2o_socket_ssl_is_early_data(h2o_socket_t *sock);
/**
 *
 */
struct st_ptls_context_t *h2o_socket_ssl_get_picotls_context(SSL_CTX *ossl);
/**
 * associates a picotls context to SSL_CTX
 */
void h2o_socket_ssl_set_picotls_context(SSL_CTX *ossl, struct st_ptls_context_t *ptls);
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
/**
 * Sets the DF bit if possible. Returns true when the operation was succcessful, or when the operating system does not provide the
 * necessary features. In either case, operation can continue with or without the DF bit being set.
 */
int h2o_socket_set_df_bit(int fd, int domain);
/**
 * returns trace state
 */
static ptls_log_conn_state_t *h2o_socket_log_state(h2o_socket_t *sock);

#if H2O_CAN_OSSL_ASYNC
/**
 * When generating a TLS handshake signature asynchronously, it is necessary to wait for a notification on a file descriptor at
 * which point the TLS handshake machinery is to be resumed. This function sets up a callback that would be called when that
 * notification is received. The callback must invoke `h2o_socket_async_handshake_on_notify` to do the necessary clean up, as well
 * as obtain the `data` pointer it has supplied.
 */
void h2o_socket_start_async_handshake(h2o_loop_t *loop, int async_fd, void *data, h2o_socket_cb cb);
/**
 * The function to be called by the callback supplied to `h2o_socket_start_async_handshake`. It returns the `data` pointer supplied
 * to `h2o_socket_start_async_handshake`.
 */
void *h2o_socket_async_handshake_on_notify(h2o_socket_t *async_sock, const char *err);
#endif

/**
 * Initializes a send vector that refers to mutable memory region. When the `proceed` callback is invoked, it is possible for the
 * generator to reuse (or release) that memory region.
 */
void h2o_sendvec_init_raw(h2o_sendvec_t *vec, const void *base, size_t len);
/**
 *
 */
int h2o_sendvec_read_raw(h2o_sendvec_t *vec, void *dst, size_t len);

/**
 * GC resources
 */
void h2o_socket_clear_recycle(int full);
/**
 *
 */
int h2o_socket_recycle_is_empty(void);

/**
 * This is a thin wrapper around sendfile (2) that hides the differences between various OS implementations.
 * @return number of bytes written (zero is a valid value indicating that the send buffer is full), or SIZE_MAX on error
 */
size_t h2o_sendfile(int sockfd, int filefd, off_t off, size_t len);

#ifdef OPENSSL_IS_BORINGSSL
/**
 * returns SSL_[gs]et_ext_data slot used to store `ptls_async_job_t` for handling async TLS handshake signature generation
 */
int h2o_socket_boringssl_get_async_job_index(void);
/**
 * If async resumption is in flight. When true is returned the TLS handshake is going to be discarded, and therefore the async
 * signature calculation callback should return failure rather than starting the calculation.
 */
int h2o_socket_boringssl_async_resumption_in_flight(SSL *ssl);
#endif

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
    (void)pool;
    const char *s = h2o_socket_get_ssl_protocol_version(sock);
    return s != NULL ? h2o_iovec_init(s, strlen(s)) : h2o_iovec_init(NULL, 0);
}

inline h2o_iovec_t h2o_socket_log_ssl_session_reused(h2o_socket_t *sock, h2o_mem_pool_t *pool)
{
    (void)pool;
    switch (h2o_socket_get_ssl_session_reused(sock)) {
    case 0:
        return h2o_iovec_init(H2O_STRLIT("0"));
    case 1:
        return h2o_iovec_init(H2O_STRLIT("1"));
    default:
        return h2o_iovec_init(NULL, 0);
    }
}

inline h2o_iovec_t h2o_socket_log_ssl_cipher(h2o_socket_t *sock, h2o_mem_pool_t *pool)
{
    (void)pool;
    const char *s = h2o_socket_get_ssl_cipher(sock);
    return s != NULL ? h2o_iovec_init(s, strlen(s)) : h2o_iovec_init(NULL, 0);
}

inline h2o_iovec_t h2o_socket_log_ssl_server_name(h2o_socket_t *sock, h2o_mem_pool_t *pool)
{
    (void)pool;
    const char *s = h2o_socket_get_ssl_server_name(sock);
    return s != NULL ? h2o_iovec_init(s, strlen(s)) : h2o_iovec_init(NULL, 0);
}

inline h2o_iovec_t h2o_socket_log_ssl_negotiated_protocol(h2o_socket_t *sock, h2o_mem_pool_t *pool)
{
    (void)pool;
    return h2o_socket_ssl_get_selected_protocol(sock);
}

inline int h2o_sliding_counter_is_running(h2o_sliding_counter_t *counter)
{
    return counter->cur.start_at != 0;
}

inline void h2o_sliding_counter_start(h2o_sliding_counter_t *counter, uint64_t now)
{
    counter->cur.start_at = now;
}

inline ptls_log_conn_state_t *h2o_socket_log_state(h2o_socket_t *sock)
{
    return &sock->_log_state;
}

#ifdef __cplusplus
}
#endif

#endif
