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
#include <openssl/opensslconf.h>
#include "picotls.h"
#include "h2o/cache.h"
#include "h2o/ebpf.h"
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

/**
 * Maximum amount of TLS records to generate at once. Default is 4 full-sized TLS records using 32-byte tag.
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

typedef struct st_h2o_socket_read_file_cmd_t h2o_socket_read_file_cmd_t;
typedef void (*h2o_socket_read_file_cb)(h2o_socket_read_file_cmd_t *);
struct st_h2o_socket_read_file_cmd_t {
    struct {
        h2o_socket_read_file_cb func;
        void *data;
    } cb;
    /**
     * result
     */
    const char *err;
};

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
     * boolean flag to indicate if sock is NOT being traced
     */
    unsigned _skip_tracing : 1;
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
    } _write_buf;
    struct {
        h2o_iovec_t *bufs;
        size_t bufcnt;
        h2o_socket_read_file_cmd_t *cmd;
    } _flatten;
    struct {
        uint8_t state; /* one of H2O_SOCKET_LATENCY_STATE_* */
        uint8_t notsent_is_minimized : 1;
        size_t suggested_tls_payload_size; /* suggested TLS record payload size, or SIZE_MAX when no need to restrict */
        size_t suggested_write_size;       /* SIZE_MAX if no need to optimize for latency */
    } _latency_optimization;
};

/**
 * Maximum size of sendvec when a pull (i.e. non-raw) vector is used. Note also that bufcnt must be set to one when a pull mode
 * vector is used. TODO lift the size and usage restrictions.
 */
#define H2O_PULL_SENDVEC_MAX_SIZE 65536

typedef struct st_h2o_sendvec_t h2o_sendvec_t;

typedef struct st_h2o_sendvec_callbacks_t {
    /**
     * Reads the content of send vector into the specified memory buffer, either synchronously or asynchronously. The interface is
     * designed to look like a wrapper of `h2o_socket_read_file`, allowing the provider to do additional mangling if necessary.
     */
    void (*flatten)(h2o_sendvec_t *vec, h2o_loop_t *loop, h2o_socket_read_file_cmd_t **cmd, h2o_iovec_t dst, size_t off,
                    h2o_socket_read_file_cb cb, void *data);
    /**
     * Optional callback that returns file reference of the vector.
     */
    int (*get_fileref)(h2o_sendvec_t *vec, h2o_loop_t *loop, off_t *off);
    /**
     * optional callback that can be used to retain the buffer after flattening all data. This allows H3 to re-flatten data upon
     * retransmission. Increments the reference counter if `is_incr` is set to true, otherwise the counter is decremented.
     */
    void (*update_refcnt)(h2o_sendvec_t *vec, int is_incr);
} h2o_sendvec_callbacks_t;

/**
 * Send vector. Unlike an ordinary `h2o_iovec_t`, the vector has a callback that allows the sender to delay the flattening of data
 * until it becomes necessary.
 */
struct st_h2o_sendvec_t {
    /**
     * callbacks
     */
    const h2o_sendvec_callbacks_t *callbacks;
    /**
     * size of the vector
     */
    size_t len;
    /**
     * If `callback->read_` is `h2o_sendvec_flatten_raw`, payload is stored in the buffer pointed to by `raw`. Otherwise, the
     * payload cannot be accessed directly and callbacks have to be used. For convenience of output filters, the
     * `h2o_sendvec_flattener_t` and associated functions can be used for normalizing all the sendvecs to the raw form before being
     * supplied.
     */
    union {
        char *raw;
        uint64_t cb_arg[2];
    };
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

extern size_t h2o_socket_ssl_buffer_size;
extern __thread h2o_mem_recycle_t h2o_socket_ssl_buffer_allocator;

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
void h2o_socket_sendvec(h2o_socket_t *sock, h2o_sendvec_t *vecs, size_t cnt, h2o_socket_cb cb);
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
 * Initializes a send vector that refers to mutable memory region. When the `proceed` callback is invoked, it is possible for the
 * generator to reuse (or release) that memory region.
 */
void h2o_sendvec_init_raw(h2o_sendvec_t *vec, const void *base, size_t len);
/**
 * Initializes a send vector that refers to immutable memory region. It is the responsible of the generator to preserve the contents
 * of the specified memory region until the user of the send vector finishes using the send vector.
 */
void h2o_sendvec_init_immutable(h2o_sendvec_t *vec, const void *base, size_t len);
/**
 * The flatten callback to be used when the data is stored in `h2o_sendvec_t::raw`. Applications can use access the raw buffer
 * directly, if the flatten callback of a sendvec points to this function.
 */
void h2o_sendvec_flatten_raw(h2o_sendvec_t *vec, h2o_loop_t *loop, h2o_socket_read_file_cmd_t **cmd, h2o_iovec_t dst, size_t off,
                             h2o_socket_read_file_cb cb, void *data);
/**
 * Reads file without blocking. Read can complete either synchronously or asynchronously.
 * @param cmd  Upon return, `*cmd` points to an object that file read inflight. If the read completed synchronously, `*cmd` is set
 *             to NULL when the callback is called as well as when this function returns.
 * @param cb   Callback function to be invoked when read is complete. This callback can get called synchronously.
 */
void h2o_socket_read_file(h2o_socket_read_file_cmd_t **cmd, h2o_loop_t *loop, int fd, uint64_t offset, h2o_iovec_t dst,
                          h2o_socket_read_file_cb cb, void *data);
/**
 *
 */
ptls_t *h2o_socket_get_ptls(h2o_socket_t *sock);
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
 * helper to check if socket the socket is target of tracing
 */
static int h2o_socket_skip_tracing(h2o_socket_t *sock);
/**
 *
 */
void h2o_socket_set_skip_tracing(h2o_socket_t *sock, int skip_tracing);

/**
 * Prepares eBPF maps. Requires root privileges and thus should be called before dropping the privileges. Returns a boolean
 * indicating if operation succeeded.
 */
int h2o_socket_ebpf_setup(void);
/**
 * Function to lookup if the connection is tagged for special treatment. The result is a union of `H2O_EBPF_FLAGS_*`.
 */
uint64_t h2o_socket_ebpf_lookup_flags(h2o_loop_t *loop, int (*init_key)(h2o_ebpf_map_key_t *key, void *cbdata), void *cbdata);
/**
 *
 */
uint64_t h2o_socket_ebpf_lookup_flags_sni(h2o_loop_t *loop, uint64_t flags, const char *server_name, size_t server_name_len);
/**
 * function for initializing the ebpf lookup key from raw information
 */
int h2o_socket_ebpf_init_key_raw(h2o_ebpf_map_key_t *key, int sock_type, struct sockaddr *local, struct sockaddr *remote);
/**
 * callback for initializing the ebpf lookup key from `h2o_socket_t`
 */
int h2o_socket_ebpf_init_key(h2o_ebpf_map_key_t *key, void *sock);

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

inline int h2o_socket_skip_tracing(h2o_socket_t *sock)
{
    return sock->_skip_tracing;
}

#ifdef __cplusplus
}
#endif

#endif
