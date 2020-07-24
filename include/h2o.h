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
#ifndef h2o_h
#define h2o_h

#ifdef __cplusplus
extern "C" {
#endif

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include "h2o/filecache.h"
#include "h2o/header.h"
#include "h2o/hostinfo.h"
#include "h2o/memcached.h"
#include "h2o/redis.h"
#include "h2o/linklist.h"
#include "h2o/httpclient.h"
#include "h2o/memory.h"
#include "h2o/multithread.h"
#include "h2o/rand.h"
#include "h2o/socket.h"
#include "h2o/string_.h"
#include "h2o/time_.h"
#include "h2o/token.h"
#include "h2o/url.h"
#include "h2o/version.h"
#include "h2o/balancer.h"
#include "h2o/http2_common.h"
#include "h2o/send_state.h"

#ifndef H2O_USE_BROTLI
/* disabled for all but the standalone server, since the encoder is written in C++ */
#define H2O_USE_BROTLI 0
#endif

#ifndef H2O_MAX_HEADERS
#define H2O_MAX_HEADERS 100
#endif
#ifndef H2O_MAX_REQLEN
#define H2O_MAX_REQLEN (8192 + 4096 * (H2O_MAX_HEADERS))
#endif

#ifndef H2O_SOMAXCONN
/* simply use a large value, and let the kernel clip it to the internal max */
#define H2O_SOMAXCONN 65535
#endif

#define H2O_HTTP2_MIN_STREAM_WINDOW_SIZE 65535
#define H2O_HTTP2_MAX_STREAM_WINDOW_SIZE 16777216

#define H2O_DEFAULT_MAX_REQUEST_ENTITY_SIZE (1024 * 1024 * 1024)
#define H2O_DEFAULT_MAX_DELEGATIONS 5
#define H2O_DEFAULT_HANDSHAKE_TIMEOUT_IN_SECS 10
#define H2O_DEFAULT_HANDSHAKE_TIMEOUT (H2O_DEFAULT_HANDSHAKE_TIMEOUT_IN_SECS * 1000)
#define H2O_DEFAULT_HTTP1_REQ_TIMEOUT_IN_SECS 10
#define H2O_DEFAULT_HTTP1_REQ_TIMEOUT (H2O_DEFAULT_HTTP1_REQ_TIMEOUT_IN_SECS * 1000)
#define H2O_DEFAULT_HTTP1_REQ_IO_TIMEOUT_IN_SECS 5
#define H2O_DEFAULT_HTTP1_REQ_IO_TIMEOUT (H2O_DEFAULT_HTTP1_REQ_IO_TIMEOUT_IN_SECS * 1000)
#define H2O_DEFAULT_HTTP1_UPGRADE_TO_HTTP2 1
#define H2O_DEFAULT_HTTP2_IDLE_TIMEOUT_IN_SECS 10
#define H2O_DEFAULT_HTTP2_IDLE_TIMEOUT (H2O_DEFAULT_HTTP2_IDLE_TIMEOUT_IN_SECS * 1000)
#define H2O_DEFAULT_HTTP2_GRACEFUL_SHUTDOWN_TIMEOUT_IN_SECS 0 /* no timeout */
#define H2O_DEFAULT_HTTP2_GRACEFUL_SHUTDOWN_TIMEOUT (H2O_DEFAULT_HTTP2_GRACEFUL_SHUTDOWN_TIMEOUT_IN_SECS * 1000)
#define H2O_DEFAULT_HTTP2_ACTIVE_STREAM_WINDOW_SIZE H2O_HTTP2_MAX_STREAM_WINDOW_SIZE
#define H2O_DEFAULT_PROXY_IO_TIMEOUT_IN_SECS 30
#define H2O_DEFAULT_PROXY_IO_TIMEOUT (H2O_DEFAULT_PROXY_IO_TIMEOUT_IN_SECS * 1000)
#define H2O_DEFAULT_PROXY_WEBSOCKET_TIMEOUT_IN_SECS 300
#define H2O_DEFAULT_PROXY_WEBSOCKET_TIMEOUT (H2O_DEFAULT_PROXY_WEBSOCKET_TIMEOUT_IN_SECS * 1000)
#define H2O_DEFAULT_PROXY_SSL_SESSION_CACHE_CAPACITY 4096
#define H2O_DEFAULT_PROXY_SSL_SESSION_CACHE_DURATION 86400000 /* 24 hours */
#define H2O_DEFAULT_PROXY_HTTP2_MAX_CONCURRENT_STREAMS 100

typedef struct st_h2o_conn_t h2o_conn_t;
typedef struct st_h2o_context_t h2o_context_t;
typedef struct st_h2o_req_t h2o_req_t;
typedef struct st_h2o_ostream_t h2o_ostream_t;
typedef struct st_h2o_configurator_command_t h2o_configurator_command_t;
typedef struct st_h2o_configurator_t h2o_configurator_t;
typedef struct st_h2o_pathconf_t h2o_pathconf_t;
typedef struct st_h2o_hostconf_t h2o_hostconf_t;
typedef struct st_h2o_globalconf_t h2o_globalconf_t;
typedef struct st_h2o_mimemap_t h2o_mimemap_t;
typedef struct st_h2o_logconf_t h2o_logconf_t;
typedef struct st_h2o_headers_command_t h2o_headers_command_t;

/**
 * basic structure of a handler (an object that MAY generate a response)
 * The handlers should register themselves to h2o_context_t::handlers.
 */
typedef struct st_h2o_handler_t {
    size_t _config_slot;
    void (*on_context_init)(struct st_h2o_handler_t *self, h2o_context_t *ctx);
    void (*on_context_dispose)(struct st_h2o_handler_t *self, h2o_context_t *ctx);
    void (*dispose)(struct st_h2o_handler_t *self);
    int (*on_req)(struct st_h2o_handler_t *self, h2o_req_t *req);
    /**
     * If the flag is set, protocol handler may invoke the request handler before receiving the end of the request body. The request
     * handler can determine if the protocol handler has actually done so by checking if `req->proceed_req` is set to non-NULL.
     * In such case, the handler should replace `req->write_req.cb` (and ctx) with its own callback to receive the request body
     * bypassing the buffer of the protocol handler. Parts of the request body being received before the handler replacing the
     * callback is accessible via `req->entity`.
     * The request handler can delay replacing the callback to a later moment. In such case, the handler can determine if
     * `req->entity` already contains a complete request body by checking if `req->proceed_req` is NULL.
     */
    unsigned supports_request_streaming : 1;
} h2o_handler_t;

/**
 * basic structure of a filter (an object that MAY modify a response)
 * The filters should register themselves to h2o_context_t::filters.
 */
typedef struct st_h2o_filter_t {
    size_t _config_slot;
    void (*on_context_init)(struct st_h2o_filter_t *self, h2o_context_t *ctx);
    void (*on_context_dispose)(struct st_h2o_filter_t *self, h2o_context_t *ctx);
    void (*dispose)(struct st_h2o_filter_t *self);
    void (*on_setup_ostream)(struct st_h2o_filter_t *self, h2o_req_t *req, h2o_ostream_t **slot);
    void (*on_informational)(struct st_h2o_filter_t *self, h2o_req_t *req);
} h2o_filter_t;

/**
 * basic structure of a logger (an object that MAY log a request)
 * The loggers should register themselves to h2o_context_t::loggers.
 */
typedef struct st_h2o_logger_t {
    size_t _config_slot;
    void (*on_context_init)(struct st_h2o_logger_t *self, h2o_context_t *ctx);
    void (*on_context_dispose)(struct st_h2o_logger_t *self, h2o_context_t *ctx);
    void (*dispose)(struct st_h2o_logger_t *self);
    void (*log_access)(struct st_h2o_logger_t *self, h2o_req_t *req);
} h2o_logger_t;

/**
 * contains stringified representations of a timestamp
 */
typedef struct st_h2o_timestamp_string_t {
    char rfc1123[H2O_TIMESTR_RFC1123_LEN + 1];
    char log[H2O_TIMESTR_LOG_LEN + 1];
} h2o_timestamp_string_t;

/**
 * a timestamp.
 * Applications should call h2o_get_timestamp to obtain a timestamp.
 */
typedef struct st_h2o_timestamp_t {
    struct timeval at;
    h2o_timestamp_string_t *str;
} h2o_timestamp_t;

typedef struct st_h2o_casper_conf_t {
    /**
     * capacity bits (0 to disable casper)
     */
    unsigned capacity_bits;
    /**
     * whether if all type of files should be tracked (or only the blocking assets)
     */
    int track_all_types;
} h2o_casper_conf_t;

typedef struct st_h2o_envconf_t {
    /**
     * parent
     */
    struct st_h2o_envconf_t *parent;
    /**
     * list of names to be unset
     */
    h2o_iovec_vector_t unsets;
    /**
     * list of name-value pairs to be set
     */
    h2o_iovec_vector_t sets;
} h2o_envconf_t;

struct st_h2o_pathconf_t {
    /**
     * globalconf to which the pathconf belongs
     */
    h2o_globalconf_t *global;
    /**
     * pathname in lower case, may or may not have "/" at last, NULL terminated, or is {NULL,0} if is fallback or extension-level
     */
    h2o_iovec_t path;
    /**
     * list of handlers
     */
    H2O_VECTOR(h2o_handler_t *) handlers;
    /**
     * list of filters to be applied unless when processing a subrequest.
     * The address of the list is set in `req->filters` and used when processing a request.
     */
    H2O_VECTOR(h2o_filter_t *) _filters;
    /**
     * list of loggers to be applied unless when processing a subrequest.
     * The address of the list is set in `req->loggers` and used when processing a request.
     */
    H2O_VECTOR(h2o_logger_t *) _loggers;
    /**
     * mimemap
     */
    h2o_mimemap_t *mimemap;
    /**
     * env
     */
    h2o_envconf_t *env;
    /**
     * error-log
     */
    struct {
        /**
         * if request-level errors should be emitted to stderr
         */
        unsigned emit_request_errors : 1;
    } error_log;
};

struct st_h2o_hostconf_t {
    /**
     * reverse reference to the global configuration
     */
    h2o_globalconf_t *global;
    /**
     * host and port
     */
    struct {
        /**
         * host and port (in lower-case; base is NULL-terminated)
         */
        h2o_iovec_t hostport;
        /**
         *  in lower-case; base is NULL-terminated
         */
        h2o_iovec_t host;
        /**
         * port number (or 65535 if default)
         */
        uint16_t port;
    } authority;
    /**
     * list of path configurations
     */
    H2O_VECTOR(h2o_pathconf_t *) paths;
    /**
     * catch-all path configuration
     */
    h2o_pathconf_t fallback_path;
    /**
     * mimemap
     */
    h2o_mimemap_t *mimemap;
    /**
     * http2
     */
    struct {
        /**
         * whether if blocking assets being pulled should be given highest priority in case of clients that do not implement
         * dependency-based prioritization
         */
        unsigned reprioritize_blocking_assets : 1;
        /**
         * if server push should be used
         */
        unsigned push_preload : 1;
        /**
         * if cross origin pushes should be authorized
         */
        unsigned allow_cross_origin_push : 1;
        /**
         * casper settings
         */
        h2o_casper_conf_t casper;
    } http2;
};

typedef struct st_h2o_protocol_callbacks_t {
    void (*request_shutdown)(h2o_context_t *ctx);
    int (*foreach_request)(h2o_context_t *ctx, int (*cb)(h2o_req_t *req, void *cbdata), void *cbdata);
} h2o_protocol_callbacks_t;

typedef h2o_iovec_t (*final_status_handler_cb)(void *ctx, h2o_globalconf_t *gconf, h2o_req_t *req);
typedef const struct st_h2o_status_handler_t {
    h2o_iovec_t name;
    h2o_iovec_t (*final)(void *ctx, h2o_globalconf_t *gconf, h2o_req_t *req); /* mandatory, will be passed the optional context */
    void *(*init)(void); /* optional callback, allocates a context that will be passed to per_thread() */
    void (*per_thread)(void *priv, h2o_context_t *ctx); /* optional callback, will be called for each thread */
} h2o_status_handler_t;

typedef H2O_VECTOR(h2o_status_handler_t *) h2o_status_callbacks_t;

typedef enum h2o_send_informational_mode {
    H2O_SEND_INFORMATIONAL_MODE_EXCEPT_H1,
    H2O_SEND_INFORMATIONAL_MODE_NONE,
    H2O_SEND_INFORMATIONAL_MODE_ALL
} h2o_send_informational_mode_t;

struct st_h2o_globalconf_t {
    /**
     * a NULL-terminated list of host contexts (h2o_hostconf_t)
     */
    h2o_hostconf_t **hosts;
    /**
     * list of configurators
     */
    h2o_linklist_t configurators;
    /**
     * name of the server (not the hostname)
     */
    h2o_iovec_t server_name;
    /**
     * maximum size of the accepted request entity (e.g. POST data)
     */
    size_t max_request_entity_size;
    /**
     * maximum count for delegations
     */
    unsigned max_delegations;
    /**
     * setuid user (or NULL)
     */
    char *user;

    /**
     * SSL handshake timeout
     */
    uint64_t handshake_timeout;

    struct {
        /**
         * request timeout (in milliseconds)
         */
        uint64_t req_timeout;
        /**
         * request io timeout (in milliseconds)
         */
        uint64_t req_io_timeout;
        /**
         * a boolean value indicating whether or not to upgrade to HTTP/2
         */
        int upgrade_to_http2;
        /**
         * list of callbacks
         */
        h2o_protocol_callbacks_t callbacks;
    } http1;

    struct {
        /**
         * idle timeout (in milliseconds)
         */
        uint64_t idle_timeout;
        /**
         * graceful shutdown timeout (in milliseconds)
         */
        uint64_t graceful_shutdown_timeout;
        /**
         * maximum number of HTTP2 requests (per connection) to be handled simultaneously internally.
         * H2O accepts at most 256 requests over HTTP/2, but internally limits the number of in-flight requests to the value
         * specified by this property in order to limit the resources allocated to a single connection.
         */
        size_t max_concurrent_requests_per_connection;
        /**
         * maximum nuber of streams (per connection) to be allowed in IDLE / CLOSED state (used for tracking dependencies).
         */
        size_t max_streams_for_priority;
        /**
         * size of the stream-level flow control window (once it becomes active)
         */
        uint32_t active_stream_window_size;
        /**
         * conditions for latency optimization
         */
        h2o_socket_latency_optimization_conditions_t latency_optimization;
        /**
         * list of callbacks
         */
        h2o_protocol_callbacks_t callbacks;
        /* */
        h2o_iovec_t origin_frame;
    } http2;

    struct {
        /**
         * graceful shutdown timeout (in milliseconds)
         */
        uint64_t graceful_shutdown_timeout;
        h2o_protocol_callbacks_t callbacks;
    } http3;

    struct {
        /**
         * io timeout (in milliseconds)
         */
        uint64_t io_timeout;
        /**
         * io timeout (in milliseconds)
         */
        uint64_t connect_timeout;
        /**
         * io timeout (in milliseconds)
         */
        uint64_t first_byte_timeout;
        /**
         * keepalive timeout (in milliseconds)
         */
        uint64_t keepalive_timeout;
        /**
         * a boolean flag if set to true, instructs the proxy to close the frontend h1 connection on behalf of the upstream
         */
        unsigned forward_close_connection : 1;
        /**
         * a boolean flag if set to true, instructs the proxy to preserve the x-forwarded-proto header passed by the client
         */
        unsigned preserve_x_forwarded_proto : 1;
        /**
         * a boolean flag if set to true, instructs the proxy to preserve the server header passed by the origin
         */
        unsigned preserve_server_header : 1;
        /**
         * a boolean flag if set to true, instructs the proxy to emit x-forwarded-proto and x-forwarded-for headers
         */
        unsigned emit_x_forwarded_headers : 1;
        /**
         * a boolean flag if set to true, instructs the proxy to emit a via header
         */
        unsigned emit_via_header : 1;
        /**
         * a boolean flag if set to true, instructs the proxy to emit a date header, if it's missing from the upstream response
         */
        unsigned emit_missing_date_header : 1;
        /**
         * maximum size to buffer for the response
         */
        size_t max_buffer_size;

        struct {
            uint32_t max_concurrent_streams;
            /**
             * ratio in percentage (0 ~ 100) at which each request will be sent via http2. negative value means that fixed ratio
             * mode is disabled
             */
            int8_t ratio;
        } http2;
        /**
         * global socketpool
         */
        h2o_socketpool_t global_socketpool;
    } proxy;

    /**
     * enum indicating to what clients h2o sends 1xx response
     */
    h2o_send_informational_mode_t send_informational_mode;

    /**
     * mimemap
     */
    h2o_mimemap_t *mimemap;

    /**
     * filecache
     */
    struct {
        /* capacity of the filecache */
        size_t capacity;
    } filecache;

    /* status */
    h2o_status_callbacks_t statuses;

    size_t _num_config_slots;
};

enum {
    H2O_COMPRESS_HINT_AUTO = 0,    /* default: let h2o negociate compression based on the configuration */
    H2O_COMPRESS_HINT_DISABLE,     /* compression was explicitely disabled for this request */
    H2O_COMPRESS_HINT_ENABLE,      /* compression was explicitely enabled for this request */
    H2O_COMPRESS_HINT_ENABLE_GZIP, /* compression was explicitely enabled for this request, asking for gzip */
    H2O_COMPRESS_HINT_ENABLE_BR,   /* compression was explicitely enabled for this request, asking for br */
};

/**
 * holds various attributes related to the mime-type
 */
typedef struct st_h2o_mime_attributes_t {
    /**
     * whether if the content can be compressed by using gzip
     */
    char is_compressible;
    /**
     * how the resource should be prioritized
     */
    enum { H2O_MIME_ATTRIBUTE_PRIORITY_NORMAL = 0, H2O_MIME_ATTRIBUTE_PRIORITY_HIGHEST } priority;
} h2o_mime_attributes_t;

extern h2o_mime_attributes_t h2o_mime_attributes_as_is;

/**
 * represents either a mime-type (and associated info), or contains pathinfo in case of a dynamic type (e.g. .php files)
 */
typedef struct st_h2o_mimemap_type_t {
    enum { H2O_MIMEMAP_TYPE_MIMETYPE = 0, H2O_MIMEMAP_TYPE_DYNAMIC = 1 } type;
    union {
        struct {
            h2o_iovec_t mimetype;
            h2o_mime_attributes_t attr;
        };
        struct {
            h2o_pathconf_t pathconf;
        } dynamic;
    } data;
} h2o_mimemap_type_t;

enum {
    /* http1 protocol errors */
    H2O_STATUS_ERROR_400 = 0,
    H2O_STATUS_ERROR_403,
    H2O_STATUS_ERROR_404,
    H2O_STATUS_ERROR_405,
    H2O_STATUS_ERROR_413,
    H2O_STATUS_ERROR_416,
    H2O_STATUS_ERROR_417,
    H2O_STATUS_ERROR_500,
    H2O_STATUS_ERROR_502,
    H2O_STATUS_ERROR_503,
    H2O_STATUS_ERROR_MAX,
};

/**
 * holds various data related to the context
 */
typedef struct st_h2o_context_storage_item_t {
    void (*dispose)(void *data);
    void *data;
} h2o_context_storage_item_t;

typedef H2O_VECTOR(h2o_context_storage_item_t) h2o_context_storage_t;

/**
 * context of the http server.
 */
struct st_h2o_context_t {
    /**
     * points to the loop (either uv_loop_t or h2o_evloop_t, depending on the value of H2O_USE_LIBUV)
     */
    h2o_loop_t *loop;
    /**
     * pointer to the global configuration
     */
    h2o_globalconf_t *globalconf;
    /**
     * queue for receiving messages from other contexts
     */
    h2o_multithread_queue_t *queue;
    /**
     * receivers
     */
    struct {
        h2o_multithread_receiver_t hostinfo_getaddr;
    } receivers;
    /**
     * open file cache
     */
    h2o_filecache_t *filecache;
    /**
     * context scope storage for general use
     */
    h2o_context_storage_t storage;
    /**
     * flag indicating if shutdown has been requested
     */
    int shutdown_requested;

    struct {
        /**
         * link-list of h2o_http1_conn_t
         */
        h2o_linklist_t _conns;
        struct {
            uint64_t request_timeouts;
            uint64_t request_io_timeouts;
        } events;
    } http1;

    struct {
        /**
         * link-list of h2o_http2_conn_t
         */
        h2o_linklist_t _conns;
        /**
         * timeout entry used for graceful shutdown
         */
        h2o_timer_t _graceful_shutdown_timeout;
        struct {
            /**
             * counter for http2 errors internally emitted by h2o
             */
            uint64_t protocol_level_errors[H2O_HTTP2_ERROR_MAX];
            /**
             * premature close on read
             */
            uint64_t read_closed;
            /**
             * premature close on write
             */
            uint64_t write_closed;
        } events;
    } http2;

    struct {
        /**
         * the default client context for proxy
         */
        h2o_httpclient_ctx_t client_ctx;
        /**
         * the default connection pool for proxy
         */
        h2o_httpclient_connection_pool_t connpool;
    } proxy;

    struct {
        /**
         * counter for SSL errors
         */
        uint64_t errors;
        /**
         * counter for selected ALPN protocols
         */
        uint64_t alpn_h1;
        uint64_t alpn_h2;
        /**
         * counter for handshakes
         */
        uint64_t handshake_full;
        uint64_t handshake_resume;
        /**
         * summations of handshake latency in microsecond
         */
        uint64_t handshake_accum_time_full;
        uint64_t handshake_accum_time_resume;
    } ssl;

    /**
     * pointer to per-module configs
     */
    void **_module_configs;

    struct {
        struct timeval tv_at;
        h2o_timestamp_string_t *value;
    } _timestamp_cache;

    /**
     * counter for http1 error status internally emitted by h2o
     */
    uint64_t emitted_error_status[H2O_STATUS_ERROR_MAX];

    H2O_VECTOR(h2o_pathconf_t *) _pathconfs_inited;
};

/**
 * an object that generates a response.
 * The object is typically constructed by handlers calling the h2o_start_response function.
 */
typedef struct st_h2o_generator_t {
    /**
     * called by the core to request new data to be pushed via the h2o_send function.
     */
    void (*proceed)(struct st_h2o_generator_t *self, h2o_req_t *req);
    /**
     * called by the core when there is a need to terminate the response abruptly
     */
    void (*stop)(struct st_h2o_generator_t *self, h2o_req_t *req);
} h2o_generator_t;

/**
 * the maximum size of sendvec when a pull (i.e. non-raw) vector is used. Note also that bufcnt must be set to one when a pull mode
 * vector is used.
 */
#define H2O_PULL_SENDVEC_MAX_SIZE 65536

typedef struct st_h2o_sendvec_t h2o_sendvec_t;

typedef struct st_h2o_sendvec_callbacks_t {
    /**
     * optional callback used to serialize the bytes held by the vector. Returns if the operation succeeded. When false is returned,
     * the generator is considered as been error-closed by itself.  If the callback is NULL, the data is pre-flattened and available
     * in `h2o_sendvec_t::raw`.
     */
    int (*flatten)(h2o_sendvec_t *vec, h2o_req_t *req, h2o_iovec_t dst, size_t off);
    /**
     * optional callback that can be used to retain the buffer after flattening all data. This allows H3 to re-flatten data upon
     * retransmission. Increments the reference counter if `is_incr` is set to true, otherwise the counter is decremented.
     */
    void (*update_refcnt)(h2o_sendvec_t *vec, h2o_req_t *req, int is_incr);
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
 * an output stream that may alter the output.
 * The object is typically constructed by filters calling the h2o_prepend_ostream function.
 */
struct st_h2o_ostream_t {
    /**
     * points to the next output stream
     */
    struct st_h2o_ostream_t *next;
    /**
     * called by the core to send output.
     * Intermediary output streams should process the given output and call the h2o_ostream_send_next function if any data can be
     * sent.
     */
    void (*do_send)(struct st_h2o_ostream_t *self, h2o_req_t *req, h2o_sendvec_t *bufs, size_t bufcnt, h2o_send_state_t state);
    /**
     * called by the core when there is a need to terminate the response abruptly
     */
    void (*stop)(struct st_h2o_ostream_t *self, h2o_req_t *req);
    /**
     * called by the core via h2o_send_informational
     */
    void (*send_informational)(struct st_h2o_ostream_t *self, h2o_req_t *req);
};

/**
 * a HTTP response
 */
typedef struct st_h2o_res_t {
    /**
     * status code
     */
    int status;
    /**
     * reason phrase
     */
    const char *reason;
    /**
     * length of the content (that is sent as the Content-Length header).
     * The default value is SIZE_MAX, which means that the length is indeterminate.
     * Generators should set this value whenever possible.
     */
    size_t content_length;
    /**
     * list of response headers
     */
    h2o_headers_t headers;
    /**
     * mime-related attributes (may be NULL)
     */
    h2o_mime_attributes_t *mime_attr;
    /**
     * retains the original response header before rewritten by ostream filters
     */
    struct {
        int status;
        h2o_headers_t headers;
    } original;
} h2o_res_t;

/**
 * debug state (currently only for HTTP/2)
 */
typedef struct st_h2o_http2_debug_state_t {
    h2o_iovec_vector_t json;
    ssize_t conn_flow_in;
    ssize_t conn_flow_out;
} h2o_http2_debug_state_t;

typedef struct st_h2o_conn_callbacks_t {
    /**
     * getsockname (return size of the obtained address, or 0 if failed)
     */
    socklen_t (*get_sockname)(h2o_conn_t *conn, struct sockaddr *sa);
    /**
     * getpeername (return size of the obtained address, or 0 if failed)
     */
    socklen_t (*get_peername)(h2o_conn_t *conn, struct sockaddr *sa);
    /**
     * returns picotls connection object used by the connection (or NULL if TLS is not used)
     */
    ptls_t *(*get_ptls)(h2o_conn_t *conn);
    /**
     * returns if the connection is target of tracing
     */
    int (*skip_tracing)(h2o_conn_t *conn);
    /**
     * optional (i.e. may be NULL) callback for server push
     */
    void (*push_path)(h2o_req_t *req, const char *abspath, size_t abspath_len, int is_critical);
    /**
     * debug state callback (optional)
     */
    h2o_http2_debug_state_t *(*get_debug_state)(h2o_req_t *req, int hpack_enabled);
    /**
     * logging callbacks (all of them are optional)
     */
    union {
        struct {
            struct {
                h2o_iovec_t (*protocol_version)(h2o_req_t *req);
                h2o_iovec_t (*session_reused)(h2o_req_t *req);
                h2o_iovec_t (*cipher)(h2o_req_t *req);
                h2o_iovec_t (*cipher_bits)(h2o_req_t *req);
                h2o_iovec_t (*session_id)(h2o_req_t *req);
                h2o_iovec_t (*server_name)(h2o_req_t *req);
                h2o_iovec_t (*negotiated_protocol)(h2o_req_t *req);
            } ssl;
            struct {
                h2o_iovec_t (*request_index)(h2o_req_t *req);
            } http1;
            struct {
                h2o_iovec_t (*stream_id)(h2o_req_t *req);
                h2o_iovec_t (*priority_received)(h2o_req_t *req);
                h2o_iovec_t (*priority_received_exclusive)(h2o_req_t *req);
                h2o_iovec_t (*priority_received_parent)(h2o_req_t *req);
                h2o_iovec_t (*priority_received_weight)(h2o_req_t *req);
                h2o_iovec_t (*priority_actual)(h2o_req_t *req);
                h2o_iovec_t (*priority_actual_parent)(h2o_req_t *req);
                h2o_iovec_t (*priority_actual_weight)(h2o_req_t *req);
            } http2;
            struct {
                h2o_iovec_t (*stream_id)(h2o_req_t *req);
                h2o_iovec_t (*quic_stats)(h2o_req_t *req);
            } http3;
        };
        h2o_iovec_t (*callbacks[1])(h2o_req_t *req);
    } log_;
} h2o_conn_callbacks_t;

/**
 * basic structure of an HTTP connection (HTTP/1, HTTP/2, etc.)
 */
struct st_h2o_conn_t {
    /**
     * the context of the server
     */
    h2o_context_t *ctx;
    /**
     * NULL-terminated list of hostconfs bound to the connection
     */
    h2o_hostconf_t **hosts;
    /**
     * time when the connection was established
     */
    struct timeval connected_at;
    /**
     * connection id
     */
    uint64_t id;
    /**
     * callbacks
     */
    const h2o_conn_callbacks_t *callbacks;
};

/**
 * filter used for capturing a response (can be used to implement subreq)
 */
typedef struct st_h2o_req_prefilter_t {
    struct st_h2o_req_prefilter_t *next;
    void (*on_setup_ostream)(struct st_h2o_req_prefilter_t *self, h2o_req_t *req, h2o_ostream_t **slot);
} h2o_req_prefilter_t;

typedef struct st_h2o_req_overrides_t {
    /**
     * specific client context (or NULL)
     */
    h2o_httpclient_ctx_t *client_ctx;
    /**
     * connpool to be used when connecting to upstream (or NULL)
     */
    h2o_httpclient_connection_pool_t *connpool;
    /**
     * upstream to connect to (or NULL)
     */
    h2o_url_t *upstream;
    /**
     * parameters for rewriting the `Location` header (only used if match.len != 0)
     */
    struct {
        /**
         * if the prefix of the location header matches the url, then the header will be rewritten
         */
        h2o_url_t *match;
        /**
         * path prefix to be inserted upon rewrite
         */
        h2o_iovec_t path_prefix;
    } location_rewrite;
    /**
     * whether if the PROXY header should be sent
     */
    unsigned use_proxy_protocol : 1;
    /**
     * whether the proxied request should preserve host
     */
    unsigned proxy_preserve_host : 1;
    /**
     * headers rewrite commands to be used when sending requests to upstream (or NULL)
     */
    h2o_headers_command_t *headers_cmds;
} h2o_req_overrides_t;

/**
 * additional information for extension-based dynamic content
 */
typedef struct st_h2o_filereq_t {
    h2o_iovec_t script_name;
    h2o_iovec_t path_info;
    h2o_iovec_t local_path;
} h2o_filereq_t;

typedef void (*h2o_proceed_req_cb)(h2o_req_t *req, size_t written, h2o_send_state_t send_state);
typedef int (*h2o_write_req_cb)(void *ctx, h2o_iovec_t chunk, int is_end_stream);

#define H2O_SEND_SERVER_TIMING_BASIC 1
#define H2O_SEND_SERVER_TIMING_PROXY 2

/**
 * a HTTP request
 */
struct st_h2o_req_t {
    /**
     * the underlying connection
     */
    h2o_conn_t *conn;
    /**
     * the request sent by the client (as is)
     */
    struct {
        /**
         * scheme (http, https, etc.)
         */
        const h2o_url_scheme_t *scheme;
        /**
         * authority (a.k.a. the Host header; the value is supplemented if missing before the handlers are being called)
         */
        h2o_iovec_t authority;
        /**
         * method
         */
        h2o_iovec_t method;
        /**
         * abs-path of the request (unmodified)
         */
        h2o_iovec_t path;
        /**
         * offset of '?' within path, or SIZE_MAX if not found
         */
        size_t query_at;
    } input;
    /**
     * the host context
     */
    h2o_hostconf_t *hostconf;
    /**
     * the path context
     */
    h2o_pathconf_t *pathconf;
    /**
     * filters and the size of it
     */
    h2o_filter_t **filters;
    size_t num_filters;
    /**
     * loggers and the size of it
     */
    h2o_logger_t **loggers;
    size_t num_loggers;
    /**
     * the handler that has been executed
     */
    h2o_handler_t *handler;
    /**
     * scheme (http, https, etc.)
     */
    const h2o_url_scheme_t *scheme;
    /**
     * authority (of the processing request)
     */
    h2o_iovec_t authority;
    /**
     * method (of the processing request)
     */
    h2o_iovec_t method;
    /**
     * abs-path of the processing request
     */
    h2o_iovec_t path;
    /**
     * offset of '?' within path, or SIZE_MAX if not found
     */
    size_t query_at;
    /**
     * normalized path of the processing request (i.e. no "." or "..", no query)
     */
    h2o_iovec_t path_normalized;
    /**
     * Map of indexes of `path_normalized` into the next character in `path`; built only if `path` required normalization
     */
    size_t *norm_indexes;
    /**
     * authority's prefix matched with `*` against defined hosts
     */
    h2o_iovec_t authority_wildcard_match;
    /**
     * filters assigned per request
     */
    h2o_req_prefilter_t *prefilters;
    /**
     * additional information (becomes available for extension-based dynamic content)
     */
    h2o_filereq_t *filereq;
    /**
     * overrides (maybe NULL)
     */
    h2o_req_overrides_t *overrides;
    /**
     * the HTTP version (represented as 0xMMmm (M=major, m=minor))
     */
    int version;
    /**
     * list of request headers
     */
    h2o_headers_t headers;
    /**
     * the request entity (base == NULL if none), can't be used if the handler is streaming the body
     */
    h2o_iovec_t entity;
    /**
     * amount of request body being received
     */
    size_t req_body_bytes_received;
    /**
     * If different of SIZE_MAX, the numeric value of the received content-length: header
     */
    size_t content_length;
    /**
     * timestamp when the request was processed
     */
    h2o_timestamp_t processed_at;
    /**
     * additional timestamps
     */
    struct {
        struct timeval request_begin_at;
        struct timeval request_body_begin_at;
        struct timeval response_start_at;
        struct timeval response_end_at;
    } timestamps;
    /**
     * proxy stats
     */
    struct {
        struct {
            uint64_t total;
            uint64_t header;
            uint64_t body;
        } bytes_written;
        struct {
            uint64_t total;
            uint64_t header;
            uint64_t body;
        } bytes_read;
        h2o_httpclient_timings_t timestamps;
    } proxy_stats;
    /**
     * the response
     */
    h2o_res_t res;
    /**
     * number of bytes sent by the generator (excluding headers)
     */
    uint64_t bytes_sent;
    /**
     * the number of times the request can be reprocessed (excluding delegation)
     */
    unsigned remaining_reprocesses;
    /**
     * the number of times the request can be delegated
     */
    unsigned remaining_delegations;

    /**
     * environment variables
     */
    h2o_iovec_vector_t env;

    /**
     * error log for the request (`h2o_req_log_error` must be used for error logging)
     */
    h2o_buffer_t *error_logs;

    /**
     * error log redirection called by `h2o_req_log_error`. By default, the error is appended to `error_logs`. The callback is
     * replaced by mruby middleware to send the error log to the rack handler.
     */
    struct {
        void (*cb)(void *data, h2o_iovec_t prefix, h2o_iovec_t msg);
        void *data;
    } error_log_delegate;

    /* flags */

    /**
     * whether or not the connection is persistent.
     * Applications should set this flag to zero in case the connection cannot be kept keep-alive (due to an error etc.)
     */
    unsigned char http1_is_persistent : 1;
    /**
     * whether if the response has been delegated (i.e. reproxied).
     * For delegated responses, redirect responses would be handled internally.
     */
    unsigned char res_is_delegated : 1;
    /**
     * set by the generator if the protocol handler should replay the request upon seeing 425
     */
    unsigned char reprocess_if_too_early : 1;
    /**
     * set by the prxy handler if the http2 upstream refused the stream so the client can retry the request
     */
    unsigned char upstream_refused : 1;
    /**
     * if h2o_process_request has been called
     */
    unsigned char process_called : 1;

    /**
     * whether if the response should include server-timing header. Logical OR of H2O_SEND_SERVER_TIMING_*
     */
    unsigned send_server_timing;

    /**
     * Whether the producer of the response has explicitely disabled or
     * enabled compression. One of H2O_COMPRESS_HINT_*
     */
    char compress_hint;

    /**
     * the Upgrade request header (or { NULL, 0 } if not available)
     */
    h2o_iovec_t upgrade;

    /**
     * preferred chunk size by the ostream
     */
    size_t preferred_chunk_size;

    /**
     * callback and context for receiving request body (see h2o_handler_t::supports_request_streaming for details)
     */
    struct {
        h2o_write_req_cb cb;
        void *ctx;
    } write_req;

    /**
     * callback and context for receiving more request body (see h2o_handler_t::supports_request_streaming for details)
     */
    h2o_proceed_req_cb proceed_req;

    /* internal structure */
    h2o_generator_t *_generator;
    h2o_ostream_t *_ostr_top;
    size_t _next_filter_index;
    h2o_timer_t _timeout_entry;

    /* per-request memory pool (placed at the last since the structure is large) */
    h2o_mem_pool_t pool;
};

typedef struct st_h2o_accept_ctx_t {
    h2o_context_t *ctx;
    h2o_hostconf_t **hosts;
    SSL_CTX *ssl_ctx;
    h2o_iovec_t *http2_origin_frame;
    int expect_proxy_line;
    h2o_multithread_receiver_t *libmemcached_receiver;
} h2o_accept_ctx_t;

typedef struct st_h2o_doublebuffer_t {
    h2o_buffer_t *buf;
    unsigned char inflight : 1;
    size_t _bytes_inflight;
} h2o_doublebuffer_t;

static void h2o_doublebuffer_init(h2o_doublebuffer_t *db, h2o_buffer_prototype_t *prototype);
static void h2o_doublebuffer_dispose(h2o_doublebuffer_t *db);
static h2o_iovec_t h2o_doublebuffer_prepare(h2o_doublebuffer_t *db, h2o_buffer_t **receiving, size_t max_bytes);
static void h2o_doublebuffer_prepare_empty(h2o_doublebuffer_t *db);
static void h2o_doublebuffer_consume(h2o_doublebuffer_t *db);

/* util */

extern const char h2o_http2_npn_protocols[];
extern const char h2o_npn_protocols[];
extern const h2o_iovec_t h2o_http2_alpn_protocols[];
extern const h2o_iovec_t h2o_alpn_protocols[];

/**
 * accepts a connection
 */
void h2o_accept(h2o_accept_ctx_t *ctx, h2o_socket_t *sock);
/**
 * creates a new connection
 */
static h2o_conn_t *h2o_create_connection(size_t sz, h2o_context_t *ctx, h2o_hostconf_t **hosts, struct timeval connected_at,
                                         const h2o_conn_callbacks_t *callbacks);
/**
 * returns if the connection is still in early-data state (i.e., if there is a risk of received requests being a replay)
 */
static int h2o_conn_is_early_data(h2o_conn_t *conn);
/**
 * setups accept context for memcached SSL resumption
 */
void h2o_accept_setup_memcached_ssl_resumption(h2o_memcached_context_t *ctx, unsigned expiration);
/**
 * setups accept context for redis SSL resumption
 */
void h2o_accept_setup_redis_ssl_resumption(const char *host, uint16_t port, unsigned expiration, const char *prefix);
/**
 * returns the protocol version (e.g. "HTTP/1.1", "HTTP/2")
 */
size_t h2o_stringify_protocol_version(char *dst, int version);
/**
 * builds the proxy header defined by the PROXY PROTOCOL
 */
size_t h2o_stringify_proxy_header(h2o_conn_t *conn, char *buf);
#define H2O_PROXY_HEADER_MAX_LENGTH                                                                                                \
    (sizeof("PROXY TCP6 ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n") - 1)
/**
 * extracts path to be pushed from `Link: rel=preload` header.
 */
void h2o_extract_push_path_from_link_header(h2o_mem_pool_t *pool, const char *value, size_t value_len, h2o_iovec_t base_path,
                                            const h2o_url_scheme_t *input_scheme, h2o_iovec_t input_authority,
                                            const h2o_url_scheme_t *base_scheme, h2o_iovec_t *base_authority,
                                            void (*cb)(void *ctx, const char *path, size_t path_len, int is_critical), void *cb_ctx,
                                            h2o_iovec_t *filtered_value, int allow_cross_origin_push);
/**
 * return a bitmap of compressible types, by parsing the `accept-encoding` header
 */
int h2o_get_compressible_types(const h2o_headers_t *headers);
#define H2O_COMPRESSIBLE_GZIP 1
#define H2O_COMPRESSIBLE_BROTLI 2
/**
 * builds destination URL or path, by contatenating the prefix and path_info of the request
 */
h2o_iovec_t h2o_build_destination(h2o_req_t *req, const char *prefix, size_t prefix_len, int use_path_normalized);
/**
 * encodes the duration value of the `server-timing` header
 */
void h2o_add_server_timing_header(h2o_req_t *req, int uses_trailer);
/**
 * encodes the duration value of the `server-timing` trailer
 */
h2o_iovec_t h2o_build_server_timing_trailer(h2o_req_t *req, const char *prefix, size_t prefix_len, const char *suffix,
                                            size_t suffix_len);
/**
 * release all thread-local resources used by h2o
 */
void h2o_cleanup_thread(void);

extern uint64_t h2o_connection_id;

/* request */

/**
 * initializes the request structure
 * @param req the request structure
 * @param conn the underlying connection
 * @param src if not NULL, the request structure would be a shallow copy of src
 */
void h2o_init_request(h2o_req_t *req, h2o_conn_t *conn, h2o_req_t *src);
/**
 * releases resources allocated for handling a request
 */
void h2o_dispose_request(h2o_req_t *req);
/**
 * called by the connection layer to start processing a request that is ready
 */
void h2o_process_request(h2o_req_t *req);
/**
 * returns the first handler that will be used for the request
 */
h2o_handler_t *h2o_get_first_handler(h2o_req_t *req);
/**
 * delegates the request to the next handler
 */
void h2o_delegate_request(h2o_req_t *req);
/**
 * calls h2o_delegate_request using zero_timeout callback
 */
void h2o_delegate_request_deferred(h2o_req_t *req);
/**
 * reprocesses a request once more (used for internal redirection)
 */
void h2o_reprocess_request(h2o_req_t *req, h2o_iovec_t method, const h2o_url_scheme_t *scheme, h2o_iovec_t authority,
                           h2o_iovec_t path, h2o_req_overrides_t *overrides, int is_delegated);
/**
 * calls h2o_reprocess_request using zero_timeout callback
 */
void h2o_reprocess_request_deferred(h2o_req_t *req, h2o_iovec_t method, const h2o_url_scheme_t *scheme, h2o_iovec_t authority,
                                    h2o_iovec_t path, h2o_req_overrides_t *overrides, int is_delegated);
/**
 *
 */
void h2o_replay_request(h2o_req_t *req);
/**
 *
 */
void h2o_replay_request_deferred(h2o_req_t *req);
/**
 * called by handlers to set the generator
 * @param req the request
 * @param generator the generator
 */
void h2o_start_response(h2o_req_t *req, h2o_generator_t *generator);
/**
 * called by filters to insert output-stream filters for modifying the response
 * @param req the request
 * @param alignment of the memory to be allocated for the ostream filter
 * @param size of the memory to be allocated for the ostream filter
 * @param slot where the stream should be inserted
 * @return pointer to the ostream filter
 */
h2o_ostream_t *h2o_add_ostream(h2o_req_t *req, size_t alignment, size_t sz, h2o_ostream_t **slot);
/**
 * prepares the request for processing by looking at the method, URI, headers
 */
h2o_hostconf_t *h2o_req_setup(h2o_req_t *req);
/**
 * binds configurations to the request
 */
void h2o_req_bind_conf(h2o_req_t *req, h2o_hostconf_t *hostconf, h2o_pathconf_t *pathconf);
/**
 *
 */
static int h2o_send_state_is_in_progress(h2o_send_state_t s);
/**
 *
 */
void h2o_sendvec_init_raw(h2o_sendvec_t *vec, const void *base, size_t len);
/**
 *
 */
int h2o_sendvec_flatten_raw(h2o_sendvec_t *vec, h2o_req_t *req, h2o_iovec_t dst, size_t off);
/**
 * called by the generators to send output
 * note: generators should free itself after sending the final chunk (i.e. calling the function with is_final set to true)
 * @param req the request
 * @param bufs an array of buffers
 * @param bufcnt length of the buffers array
 * @param state describes if the output is final, has an error, or is in progress
 */
void h2o_send(h2o_req_t *req, h2o_iovec_t *bufs, size_t bufcnt, h2o_send_state_t state);
void h2o_sendvec(h2o_req_t *req, h2o_sendvec_t *vecs, size_t veccnt, h2o_send_state_t state);
/**
 * creates an uninitialized prefilter and returns pointer to it
 */
h2o_req_prefilter_t *h2o_add_prefilter(h2o_req_t *req, size_t alignment, size_t sz);
/**
 * requests the next prefilter or filter (if any) to setup the ostream if necessary
 */
static void h2o_setup_next_prefilter(h2o_req_prefilter_t *self, h2o_req_t *req, h2o_ostream_t **slot);
/**
 * requests the next filter (if any) to setup the ostream if necessary
 */
static void h2o_setup_next_ostream(h2o_req_t *req, h2o_ostream_t **slot);
/**
 * called by the ostream filters to send output to the next ostream filter
 * note: ostream filters should free itself after sending the final chunk (i.e. calling the function with is_final set to true)
 * note: ostream filters must not set is_final flag to TRUE unless is_final flag of the do_send callback was set as such
 * @param ostr current ostream filter
 * @param req the request
 * @param bufs an array of buffers
 * @param bufcnt length of the buffers array
 * @param state whether the output is in progress, final, or in error
 */
void h2o_ostream_send_next(h2o_ostream_t *ostream, h2o_req_t *req, h2o_sendvec_t *bufs, size_t bufcnt, h2o_send_state_t state);
/**
 * called by the connection layer to request additional data to the generator
 */
static void h2o_proceed_response(h2o_req_t *req);
void h2o_proceed_response_deferred(h2o_req_t *req);
/**
 * if NULL, supplements h2o_req_t::mime_attr
 */
void h2o_req_fill_mime_attributes(h2o_req_t *req);
/**
 * returns an environment variable
 */
static h2o_iovec_t *h2o_req_getenv(h2o_req_t *req, const char *name, size_t name_len, int allocate_if_not_found);
/**
 * unsets an environment variable
 */
static void h2o_req_unsetenv(h2o_req_t *req, const char *name, size_t name_len);

/* config */

h2o_envconf_t *h2o_config_create_envconf(h2o_envconf_t *src);
void h2o_config_setenv(h2o_envconf_t *envconf, const char *name, const char *value);
void h2o_config_unsetenv(h2o_envconf_t *envconf, const char *name);

/**
 * initializes pathconf
 * @param path path to serve, or NULL if fallback or extension-level
 * @param mimemap mimemap to use, or NULL if fallback or extension-level
 */
void h2o_config_init_pathconf(h2o_pathconf_t *pathconf, h2o_globalconf_t *globalconf, const char *path, h2o_mimemap_t *mimemap);
/**
 *
 */
void h2o_config_dispose_pathconf(h2o_pathconf_t *pathconf);
/**
 * initializes the global configuration
 */
void h2o_config_init(h2o_globalconf_t *config);
/**
 * registers a host context
 */
h2o_hostconf_t *h2o_config_register_host(h2o_globalconf_t *config, h2o_iovec_t host, uint16_t port);
/**
 * registers a path context
 * @param hostconf host-level configuration that the path-level configuration belongs to
 * @param path path
 * @param flags unused and must be set to zero
 *
 * Handling of the path argument has changed in version 2.0 (of the standard server).
 *
 * Before 2.0, the function implicitely added a trailing `/` to the supplied path (if it did not end with a `/`), and when receiving
 * a HTTP request for a matching path without the trailing `/`, libh2o sent a 301 response redirecting the client to a URI with a
 * trailing `/`.
 *
 * Since 2.0, the function retains the exact path given as the argument, and the handlers of the pathconf is invoked if one of the
 * following conditions are met:
 *
 * * request path is an exact match to the configuration path
 * * configuration path does not end with a `/`, and the request path begins with the configuration path followed by a `/`
 */
h2o_pathconf_t *h2o_config_register_path(h2o_hostconf_t *hostconf, const char *path, int flags);
/**
 * registers an extra status handler
 */
void h2o_config_register_status_handler(h2o_globalconf_t *config, h2o_status_handler_t *status_handler);
/**
 * disposes of the resources allocated for the global configuration
 */
void h2o_config_dispose(h2o_globalconf_t *config);
/**
 * creates a handler associated to a given pathconf
 */
h2o_handler_t *h2o_create_handler(h2o_pathconf_t *conf, size_t sz);
/**
 * creates a filter associated to a given pathconf
 */
h2o_filter_t *h2o_create_filter(h2o_pathconf_t *conf, size_t sz);
/**
 * creates a logger associated to a given pathconf
 */
h2o_logger_t *h2o_create_logger(h2o_pathconf_t *conf, size_t sz);

/* context */

/**
 * initializes the context
 */
void h2o_context_init(h2o_context_t *context, h2o_loop_t *loop, h2o_globalconf_t *config);
/**
 * disposes of the resources allocated for the context
 */
void h2o_context_dispose(h2o_context_t *context);
/**
 * requests shutdown to the connections governed by the context
 */
void h2o_context_request_shutdown(h2o_context_t *context);
/**
 *
 */
void h2o_context_init_pathconf_context(h2o_context_t *ctx, h2o_pathconf_t *pathconf);
/**
 *
 */
void h2o_context_dispose_pathconf_context(h2o_context_t *ctx, h2o_pathconf_t *pathconf);

/**
 * returns current timestamp
 * @param ctx the context
 * @param pool memory pool (used when ts != NULL)
 * @param ts buffer to store the timestamp (optional)
 * @return current time in UTC
 */
static h2o_timestamp_t h2o_get_timestamp(h2o_context_t *ctx, h2o_mem_pool_t *pool);
void h2o_context_update_timestamp_string_cache(h2o_context_t *ctx);
/**
 * returns per-module context set
 */
static void *h2o_context_get_handler_context(h2o_context_t *ctx, h2o_handler_t *handler);
/**
 * sets per-module context
 */
static void h2o_context_set_handler_context(h2o_context_t *ctx, h2o_handler_t *handler, void *handler_ctx);
/**
 * returns per-module context set by the on_context_init callback
 */
static void *h2o_context_get_filter_context(h2o_context_t *ctx, h2o_filter_t *filter);
/**
 * sets per-module filter context
 */
static void h2o_context_set_filter_context(h2o_context_t *ctx, h2o_filter_t *filter, void *filter_ctx);
/**
 * returns per-module context set by the on_context_init callback
 */
static void *h2o_context_get_logger_context(h2o_context_t *ctx, h2o_logger_t *logger);
/*
 * return the address associated with the key in the context storage
 */
static void **h2o_context_get_storage(h2o_context_t *ctx, size_t *key, void (*dispose_cb)(void *));

/* built-in generators */

enum {
    /**
     * enforces the http1 protocol handler to close the connection after sending the response
     */
    H2O_SEND_ERROR_HTTP1_CLOSE_CONNECTION = 0x1,
    /**
     * if set, does not flush the registered response headers
     */
    H2O_SEND_ERROR_KEEP_HEADERS = 0x2
};

/**
 * Add a `date:` header to the response
 */
void h2o_resp_add_date_header(h2o_req_t *req);
/**
 * Sends the given string as the response. The function copies the string so that the caller can discard it immediately.
 *
 * Be careful of calling the function asynchronously, because there is a chance of the request object getting destroyed before the
 * function is being invoked.  This could happpen for example when the client abruptly closing the connection. There are two ways to
 * detect the destruction:
 *
 * * allocate a memory chunk using the request's memory pool with a destructor that you define; i.e. call `h2o_mem_alloc_shared(
 *   &req->pool, obj_size, my_destructor)`. When the request object is destroyed, `my_destructor` will be invoked as part of the
 *   memory reclamation process.
 * * register the `stop` callback of the generator that is bound to the request. The downside of the approach is that a generator
 *   is not associated to a request until all the response headers become ready to be sent, i.e., when `h2o_start_response` is
 *   called.
 */
void h2o_send_inline(h2o_req_t *req, const char *body, size_t len);
/**
 * sends the given information as an error response to the client. Uses h2o_send_inline internally, so the same restrictions apply.
 */
void h2o_send_error_generic(h2o_req_t *req, int status, const char *reason, const char *body, int flags);
#define H2O_SEND_ERROR_XXX(status)                                                                                                 \
    static inline void h2o_send_error_##status(h2o_req_t *req, const char *reason, const char *body, int flags)                    \
    {                                                                                                                              \
        req->conn->ctx->emitted_error_status[H2O_STATUS_ERROR_##status]++;                                                         \
        h2o_send_error_generic(req, status, reason, body, flags);                                                                  \
    }

H2O_SEND_ERROR_XXX(400)
H2O_SEND_ERROR_XXX(403)
H2O_SEND_ERROR_XXX(404)
H2O_SEND_ERROR_XXX(405)
H2O_SEND_ERROR_XXX(413)
H2O_SEND_ERROR_XXX(416)
H2O_SEND_ERROR_XXX(417)
H2O_SEND_ERROR_XXX(500)
H2O_SEND_ERROR_XXX(502)
H2O_SEND_ERROR_XXX(503)

/**
 * sends error response using zero timeout; can be called by output filters while processing the headers.  Uses h2o_send_inline
 * internally, so the same restrictions apply.
 */
void h2o_send_error_deferred(h2o_req_t *req, int status, const char *reason, const char *body, int flags);
/**
 * sends a redirect response.  Uses (the equivalent of) h2o_send_inline internally, so the same restrictions apply.
 */
void h2o_send_redirect(h2o_req_t *req, int status, const char *reason, const char *url, size_t url_len);
/**
 * handles redirect internally.
 */
void h2o_send_redirect_internal(h2o_req_t *req, h2o_iovec_t method, const char *url_str, size_t url_len, int preserve_overrides);
/**
 * returns method to be used after redirection
 */
h2o_iovec_t h2o_get_redirect_method(h2o_iovec_t method, int status);
/**
 * registers push path (if necessary) by parsing a Link header
 * this returns a version of `value` that removes the links that had the `x-http2-push-only` attribute
 */
h2o_iovec_t h2o_push_path_in_link_header(h2o_req_t *req, const char *value, size_t value_len);
/**
 * sends 1xx response
 */
void h2o_send_informational(h2o_req_t *req);
/**
 *
 */
static int h2o_req_can_stream_request(h2o_req_t *req);
/**
 * resolves internal redirect url for dest regarding req's hostconf
 */
int h2o_req_resolve_internal_redirect_url(h2o_req_t *req, h2o_iovec_t dest, h2o_url_t *resolved);
/**
 * logs an error
 */
void h2o_req_log_error(h2o_req_t *req, const char *module, const char *fmt, ...) __attribute__((format(printf, 3, 4)));
void h2o_write_error_log(h2o_iovec_t prefix, h2o_iovec_t msg);

/* log */

enum { H2O_LOGCONF_ESCAPE_APACHE, H2O_LOGCONF_ESCAPE_JSON };

/**
 * compiles a log configuration
 */
h2o_logconf_t *h2o_logconf_compile(const char *fmt, int escape, char *errbuf);
/**
 * disposes of a log configuration
 */
void h2o_logconf_dispose(h2o_logconf_t *logconf);
/**
 * logs a request
 */
char *h2o_log_request(h2o_logconf_t *logconf, h2o_req_t *req, size_t *len, char *buf);

/* proxy */

/**
 * processes a request (by sending the request upstream)
 */
void h2o__proxy_process_request(h2o_req_t *req);

/* mime mapper */

/**
 * initializes the mimemap (the returned chunk is refcounted)
 */
h2o_mimemap_t *h2o_mimemap_create(void);
/**
 * clones a mimemap
 */
h2o_mimemap_t *h2o_mimemap_clone(h2o_mimemap_t *src);
/**
 *
 */
void h2o_mimemap_on_context_init(h2o_mimemap_t *mimemap, h2o_context_t *ctx);
/**
 *
 */
void h2o_mimemap_on_context_dispose(h2o_mimemap_t *mimemap, h2o_context_t *ctx);
/**
 * returns if the map contains a dynamic type
 */
int h2o_mimemap_has_dynamic_type(h2o_mimemap_t *mimemap);
/**
 * sets the default mime-type
 */
void h2o_mimemap_set_default_type(h2o_mimemap_t *mimemap, const char *mime, h2o_mime_attributes_t *attr);
/**
 * adds a mime-type mapping
 */
void h2o_mimemap_define_mimetype(h2o_mimemap_t *mimemap, const char *ext, const char *mime, h2o_mime_attributes_t *attr);
/**
 * adds a mime-type mapping
 */
h2o_mimemap_type_t *h2o_mimemap_define_dynamic(h2o_mimemap_t *mimemap, const char **exts, h2o_globalconf_t *globalconf);
/**
 * removes a mime-type mapping
 */
void h2o_mimemap_remove_type(h2o_mimemap_t *mimemap, const char *ext);
/**
 * clears all mime-type mapping
 */
void h2o_mimemap_clear_types(h2o_mimemap_t *mimemap);
/**
 * sets the default mime-type
 */
h2o_mimemap_type_t *h2o_mimemap_get_default_type(h2o_mimemap_t *mimemap);
/**
 * returns the mime-type corresponding to given extension
 */
h2o_mimemap_type_t *h2o_mimemap_get_type_by_extension(h2o_mimemap_t *mimemap, h2o_iovec_t ext);
/**
 * returns the mime-type corresponding to given mimetype
 */
h2o_mimemap_type_t *h2o_mimemap_get_type_by_mimetype(h2o_mimemap_t *mimemap, h2o_iovec_t mime, int exact_match_only);
/**
 * returns the default mime attributes given a mime type
 */
void h2o_mimemap_get_default_attributes(const char *mime, h2o_mime_attributes_t *attr);

/* various handlers */

/* lib/access_log.c */

typedef struct st_h2o_access_log_filehandle_t h2o_access_log_filehandle_t;

int h2o_access_log_open_log(const char *path);
h2o_access_log_filehandle_t *h2o_access_log_open_handle(const char *path, const char *fmt, int escape);
h2o_logger_t *h2o_access_log_register(h2o_pathconf_t *pathconf, h2o_access_log_filehandle_t *handle);
void h2o_access_log_register_configurator(h2o_globalconf_t *conf);

/* lib/handler/server_timing.c */
void h2o_server_timing_register(h2o_pathconf_t *pathconf, int enforce);
void h2o_server_timing_register_configurator(h2o_globalconf_t *conf);

/* lib/compress.c */

enum { H2O_COMPRESS_FLAG_PARTIAL, H2O_COMPRESS_FLAG_FLUSH, H2O_COMPRESS_FLAG_EOS };

/**
 * compressor context
 */
typedef struct st_h2o_compress_context_t {
    /**
     * name used in content-encoding header
     */
    h2o_iovec_t name;
    /**
     * compress or decompress callback (inbufs are raw buffers)
     */
    h2o_send_state_t (*do_transform)(struct st_h2o_compress_context_t *self, h2o_sendvec_t *inbufs, size_t inbufcnt,
                                     h2o_send_state_t state, h2o_sendvec_t **outbufs, size_t *outbufcnt);
    /**
     * push buffer
     */
    char *push_buf;
} h2o_compress_context_t;

typedef struct st_h2o_compress_args_t {
    size_t min_size;
    struct {
        int quality; /* -1 if disabled */
    } gzip;
    struct {
        int quality; /* -1 if disabled */
    } brotli;
} h2o_compress_args_t;

/**
 * registers the gzip/brotli encoding output filter (added by default, for now)
 */
void h2o_compress_register(h2o_pathconf_t *pathconf, h2o_compress_args_t *args);
/**
 * compresses given chunk
 */
h2o_send_state_t h2o_compress_transform(h2o_compress_context_t *self, h2o_req_t *req, h2o_sendvec_t *inbufs, size_t inbufcnt,
                                        h2o_send_state_t state, h2o_sendvec_t **outbufs, size_t *outbufcnt);
/**
 * instantiates the gzip compressor
 */
h2o_compress_context_t *h2o_compress_gzip_open(h2o_mem_pool_t *pool, int quality);
/**
 * instantiates the gzip decompressor
 */
h2o_compress_context_t *h2o_compress_gunzip_open(h2o_mem_pool_t *pool);
/**
 * instantiates the brotli compressor (only available if H2O_USE_BROTLI is set)
 */
h2o_compress_context_t *h2o_compress_brotli_open(h2o_mem_pool_t *pool, int quality, size_t estimated_cotent_length,
                                                 size_t preferred_chunk_size);
/**
 * registers the configurator for the gzip/brotli output filter
 */
void h2o_compress_register_configurator(h2o_globalconf_t *conf);

/* lib/handler/throttle_resp.c */
/**
 * registers the throttle response filter
 */
void h2o_throttle_resp_register(h2o_pathconf_t *pathconf);
/**
 * configurator
 */
void h2o_throttle_resp_register_configurator(h2o_globalconf_t *conf);

/* lib/errordoc.c */

typedef struct st_h2o_errordoc_t {
    int status;
    h2o_iovec_t url; /* can be relative */
} h2o_errordoc_t;

/**
 * registers the errordocument output filter
 */
void h2o_errordoc_register(h2o_pathconf_t *pathconf, h2o_errordoc_t *errdocs, size_t cnt);
/**
 *
 */
void h2o_errordoc_register_configurator(h2o_globalconf_t *conf);

/* lib/expires.c */

enum { H2O_EXPIRES_MODE_ABSOLUTE, H2O_EXPIRES_MODE_MAX_AGE };

typedef struct st_h2o_expires_args_t {
    int mode;
    union {
        const char *absolute;
        uint64_t max_age;
    } data;
} h2o_expires_args_t;

/**
 * registers a filter that adds an Expires (or Cache-Control) header
 */
void h2o_expires_register(h2o_pathconf_t *pathconf, h2o_expires_args_t *args);
/**
 *
 */
void h2o_expires_register_configurator(h2o_globalconf_t *conf);

/* lib/fastcgi.c */

typedef struct st_h2o_fastcgi_handler_t h2o_fastcgi_handler_t;

#define H2O_DEFAULT_FASTCGI_IO_TIMEOUT 30000

typedef struct st_h2o_fastcgi_config_vars_t {
    uint64_t io_timeout;
    uint64_t keepalive_timeout; /* 0 to disable */
    h2o_iovec_t document_root;  /* .base=NULL if not set */
    int send_delegated_uri;     /* whether to send the rewritten HTTP_HOST & REQUEST_URI by delegation, or the original */
    struct {
        void (*dispose)(h2o_fastcgi_handler_t *handler, void *data);
        void *data;
    } callbacks;
} h2o_fastcgi_config_vars_t;

/**
 * registers the fastcgi handler to the context
 */
h2o_fastcgi_handler_t *h2o_fastcgi_register(h2o_pathconf_t *pathconf, h2o_url_t *upstream, h2o_fastcgi_config_vars_t *vars);
/**
 * registers the fastcgi handler to the context
 */
h2o_fastcgi_handler_t *h2o_fastcgi_register_by_spawnproc(h2o_pathconf_t *pathconf, char **argv, h2o_fastcgi_config_vars_t *vars);
/**
 * registers the configurator
 */
void h2o_fastcgi_register_configurator(h2o_globalconf_t *conf);

/* lib/file.c */

enum {
    H2O_FILE_FLAG_NO_ETAG = 0x1,
    H2O_FILE_FLAG_DIR_LISTING = 0x2,
    H2O_FILE_FLAG_SEND_COMPRESSED = 0x4,
    H2O_FILE_FLAG_GUNZIP = 0x8
};

typedef struct st_h2o_file_handler_t h2o_file_handler_t;

extern const char **h2o_file_default_index_files;

/**
 * sends given file as the response to the client
 */
int h2o_file_send(h2o_req_t *req, int status, const char *reason, const char *path, h2o_iovec_t mime_type, int flags);
/**
 * registers a handler that serves a directory of statically-served files
 * @param pathconf
 * @param virtual_path
 * @param real_path
 * @param index_files optional NULL-terminated list of of filenames to be considered as the "directory-index"
 * @param mimemap the mimemap (h2o_mimemap_create is called internally if the argument is NULL)
 */
h2o_file_handler_t *h2o_file_register(h2o_pathconf_t *pathconf, const char *real_path, const char **index_files,
                                      h2o_mimemap_t *mimemap, int flags);
/**
 * registers a handler that serves a specific file
 * @param pathconf
 * @param virtual_path
 * @param real_path
 * @param index_files optional NULL-terminated list of of filenames to be considered as the "directory-index"
 * @param mimemap the mimemap (h2o_mimemap_create is called internally if the argument is NULL)
 */
h2o_handler_t *h2o_file_register_file(h2o_pathconf_t *pathconf, const char *real_path, h2o_mimemap_type_t *mime_type, int flags);
/**
 * returns the associated mimemap
 */
h2o_mimemap_t *h2o_file_get_mimemap(h2o_file_handler_t *handler);
/**
 * registers the configurator
 */
void h2o_file_register_configurator(h2o_globalconf_t *conf);

/* lib/headers.c */

enum {
    H2O_HEADERS_CMD_NULL,
    H2O_HEADERS_CMD_ADD,        /* adds a new header line */
    H2O_HEADERS_CMD_APPEND,     /* adds a new header line or contenates to the existing header */
    H2O_HEADERS_CMD_MERGE,      /* merges the value into a comma-listed values of the named header */
    H2O_HEADERS_CMD_SET,        /* sets a header line, overwriting the existing one (if any) */
    H2O_HEADERS_CMD_SETIFEMPTY, /* sets a header line if empty */
    H2O_HEADERS_CMD_UNSET,       /* removes the named header(s) */
    H2O_HEADERS_CMD_UNSETUNLESS,       /* only keeps the named header(s) */
    H2O_HEADERS_CMD_COOKIE_UNSET,       /* removes the named cookie(s) */
    H2O_HEADERS_CMD_COOKIE_UNSETUNLESS,       /* only keeps the named cookie(s) */
};

typedef enum h2o_headers_command_when {
    H2O_HEADERS_CMD_WHEN_FINAL,
    H2O_HEADERS_CMD_WHEN_EARLY,
    H2O_HEADERS_CMD_WHEN_ALL,
} h2o_headers_command_when_t;

typedef struct st_h2o_headers_command_arg_t {
    h2o_iovec_t *name; /* maybe a token */
    h2o_iovec_t value;
} h2o_headers_command_arg_t;

struct st_h2o_headers_command_t {
    int cmd;
    h2o_headers_command_arg_t *args;
    size_t num_args;
    h2o_headers_command_when_t when;
};

/**
 * registers a list of commands terminated by cmd==H2O_HEADERS_CMD_NULL
 */
void h2o_headers_register(h2o_pathconf_t *pathconf, h2o_headers_command_t *cmds);
/**
 * returns whether if the given name can be registered to the filter
 */
int h2o_headers_is_prohibited_name(const h2o_token_t *token);
/**
 * registers the configurator
 */
void h2o_headers_register_configurator(h2o_globalconf_t *conf);

/* lib/proxy.c */

typedef struct st_h2o_proxy_config_vars_t {
    uint64_t io_timeout;
    uint64_t connect_timeout;
    uint64_t first_byte_timeout;
    uint64_t keepalive_timeout;
    unsigned preserve_host : 1;
    unsigned use_proxy_protocol : 1;
    struct {
        int enabled;
        uint64_t timeout;
    } websocket;
    h2o_headers_command_t *headers_cmds;
    size_t max_buffer_size;
    struct {
        uint32_t max_concurrent_strams;
        int ratio;
    } http2;
} h2o_proxy_config_vars_t;

/**
 * registers the reverse proxy handler to the context
 */
void h2o_proxy_register_reverse_proxy(h2o_pathconf_t *pathconf, h2o_proxy_config_vars_t *config, h2o_socketpool_t *sockpool);
/**
 * registers the configurator
 */
void h2o_proxy_register_configurator(h2o_globalconf_t *conf);

/* lib/redirect.c */

typedef struct st_h2o_redirect_handler_t h2o_redirect_handler_t;

/**
 * registers the redirect handler to the context
 * @param pathconf
 * @param internal whether if the redirect is internal or external
 * @param status status code to be sent (e.g. 301, 303, 308, ...)
 * @param prefix prefix of the destitation URL
 */
h2o_redirect_handler_t *h2o_redirect_register(h2o_pathconf_t *pathconf, int internal, int status, const char *prefix);
/**
 * registers the configurator
 */
void h2o_redirect_register_configurator(h2o_globalconf_t *conf);

/* lib/handler/reproxy.c */

typedef struct st_h2o_reproxy_handler_t h2o_reproxy_handler_t;

/**
 * registers the reproxy filter
 */
void h2o_reproxy_register(h2o_pathconf_t *pathconf);
/**
 * registers the configurator
 */
void h2o_reproxy_register_configurator(h2o_globalconf_t *conf);

/* lib/handler/status.c */

/**
 * registers the status handler
 */
void h2o_status_register(h2o_pathconf_t *pathconf);
/**
 * registers the duration handler
 */
void h2o_duration_stats_register(h2o_globalconf_t *conf);
/**
 * registers the configurator
 */
void h2o_status_register_configurator(h2o_globalconf_t *conf);

/* lib/handler/headers_util.c */

struct headers_util_add_arg_t;

/**
 * appends a headers command to the list
 */
void h2o_headers_append_command(h2o_headers_command_t **cmds, int cmd, h2o_headers_command_arg_t *args, size_t num_args,
                                h2o_headers_command_when_t when);
/**
 * rewrite headers by the command provided
 */
void h2o_rewrite_headers(h2o_mem_pool_t *pool, h2o_headers_t *headers, h2o_headers_command_t *cmd);

/* lib/handler/http2_debug_state.c */

/**
 * registers the http2 debug state handler
 */
void h2o_http2_debug_state_register(h2o_hostconf_t *hostconf, int hpack_enabled);
/**
 * registers the configurator
 */
void h2o_http2_debug_state_register_configurator(h2o_globalconf_t *conf);

/* inline defs */

#ifdef H2O_NO_64BIT_ATOMICS
extern pthread_mutex_t h2o_conn_id_mutex;
#endif

inline h2o_conn_t *h2o_create_connection(size_t sz, h2o_context_t *ctx, h2o_hostconf_t **hosts, struct timeval connected_at,
                                         const h2o_conn_callbacks_t *callbacks)
{
    h2o_conn_t *conn = (h2o_conn_t *)h2o_mem_alloc(sz);

    conn->ctx = ctx;
    conn->hosts = hosts;
    conn->connected_at = connected_at;
#ifdef H2O_NO_64BIT_ATOMICS
    pthread_mutex_lock(&h2o_conn_id_mutex);
    conn->id = ++h2o_connection_id;
    pthread_mutex_unlock(&h2o_conn_id_mutex);
#else
    conn->id = __sync_add_and_fetch(&h2o_connection_id, 1);
#endif
    conn->callbacks = callbacks;

    return conn;
}

inline int h2o_conn_is_early_data(h2o_conn_t *conn)
{
    ptls_t *tls;
    if (conn->callbacks->get_ptls == NULL)
        return 0;
    if ((tls = conn->callbacks->get_ptls(conn)) == NULL)
        return 0;
    if (ptls_handshake_is_complete(tls))
        return 0;
    return 1;
}

inline void h2o_proceed_response(h2o_req_t *req)
{
    if (req->_generator != NULL) {
        req->_generator->proceed(req->_generator, req);
    } else {
        req->_ostr_top->do_send(req->_ostr_top, req, NULL, 0, H2O_SEND_STATE_FINAL);
    }
}

inline h2o_iovec_t *h2o_req_getenv(h2o_req_t *req, const char *name, size_t name_len, int allocate_if_not_found)
{
    size_t i;
    for (i = 0; i != req->env.size; i += 2)
        if (h2o_memis(req->env.entries[i].base, req->env.entries[i].len, name, name_len))
            return req->env.entries + i + 1;
    if (!allocate_if_not_found)
        return NULL;
    h2o_vector_reserve(&req->pool, &req->env, req->env.size + 2);
    req->env.entries[req->env.size++] = h2o_iovec_init(name, name_len);
    req->env.entries[req->env.size++] = h2o_iovec_init(NULL, 0);
    return req->env.entries + req->env.size - 1;
}

inline void h2o_req_unsetenv(h2o_req_t *req, const char *name, size_t name_len)
{
    size_t i;
    for (i = 0; i != req->env.size; i += 2)
        if (h2o_memis(req->env.entries[i].base, req->env.entries[i].len, name, name_len))
            goto Found;
    /* not found */
    return;
Found:
    memmove(req->env.entries + i, req->env.entries + i + 2, req->env.size - i - 2);
    req->env.size -= 2;
}

inline int h2o_send_state_is_in_progress(h2o_send_state_t s)
{
    return s == H2O_SEND_STATE_IN_PROGRESS;
}

inline void h2o_setup_next_ostream(h2o_req_t *req, h2o_ostream_t **slot)
{
    h2o_filter_t *next;

    if (req->_next_filter_index < req->num_filters) {
        next = req->filters[req->_next_filter_index++];
        next->on_setup_ostream(next, req, slot);
    }
}

inline void h2o_setup_next_prefilter(h2o_req_prefilter_t *self, h2o_req_t *req, h2o_ostream_t **slot)
{
    h2o_req_prefilter_t *next = self->next;

    if (next != NULL)
        next->on_setup_ostream(next, req, slot);
    else
        h2o_setup_next_ostream(req, slot);
}

inline h2o_timestamp_t h2o_get_timestamp(h2o_context_t *ctx, h2o_mem_pool_t *pool)
{
    time_t prev_sec = ctx->_timestamp_cache.tv_at.tv_sec;
    ctx->_timestamp_cache.tv_at = h2o_gettimeofday(ctx->loop);
    if (ctx->_timestamp_cache.tv_at.tv_sec != prev_sec)
        h2o_context_update_timestamp_string_cache(ctx);

    h2o_timestamp_t ts;
    ts.at = ctx->_timestamp_cache.tv_at;
    h2o_mem_link_shared(pool, ctx->_timestamp_cache.value);
    ts.str = ctx->_timestamp_cache.value;

    return ts;
}

inline void *h2o_context_get_handler_context(h2o_context_t *ctx, h2o_handler_t *handler)
{
    return ctx->_module_configs[handler->_config_slot];
}

inline void h2o_context_set_handler_context(h2o_context_t *ctx, h2o_handler_t *handler, void *handler_ctx)
{
    ctx->_module_configs[handler->_config_slot] = handler_ctx;
}

inline void *h2o_context_get_filter_context(h2o_context_t *ctx, h2o_filter_t *filter)
{
    return ctx->_module_configs[filter->_config_slot];
}

inline void h2o_context_set_filter_context(h2o_context_t *ctx, h2o_filter_t *filter, void *filter_ctx)
{
    ctx->_module_configs[filter->_config_slot] = filter_ctx;
}

inline void *h2o_context_get_logger_context(h2o_context_t *ctx, h2o_logger_t *logger)
{
    return ctx->_module_configs[logger->_config_slot];
}

inline void **h2o_context_get_storage(h2o_context_t *ctx, size_t *key, void (*dispose_cb)(void *))
{
    /* SIZE_MAX might not be available in case the file is included from a C++ source file */
    size_t size_max = (size_t)-1;
    if (*key == size_max)
        *key = ctx->storage.size;
    if (ctx->storage.size <= *key) {
        h2o_vector_reserve(NULL, &ctx->storage, *key + 1);
        memset(ctx->storage.entries + ctx->storage.size, 0, (*key + 1 - ctx->storage.size) * sizeof(ctx->storage.entries[0]));
        ctx->storage.size = *key + 1;
    }

    ctx->storage.entries[*key].dispose = dispose_cb;
    return &ctx->storage.entries[*key].data;
}

static inline void h2o_context_set_logger_context(h2o_context_t *ctx, h2o_logger_t *logger, void *logger_ctx)
{
    ctx->_module_configs[logger->_config_slot] = logger_ctx;
}

static inline void h2o_doublebuffer_init(h2o_doublebuffer_t *db, h2o_buffer_prototype_t *prototype)
{
    h2o_buffer_init(&db->buf, prototype);
    db->inflight = 0;
    db->_bytes_inflight = 0;
}

static inline void h2o_doublebuffer_dispose(h2o_doublebuffer_t *db)
{
    h2o_buffer_dispose(&db->buf);
}

static inline h2o_iovec_t h2o_doublebuffer_prepare(h2o_doublebuffer_t *db, h2o_buffer_t **receiving, size_t max_bytes)
{
    assert(!db->inflight);
    assert(max_bytes != 0);

    if (db->buf->size == 0) {
        if ((*receiving)->size == 0)
            return h2o_iovec_init(NULL, 0);
        /* swap buffers */
        h2o_buffer_t *t = db->buf;
        db->buf = *receiving;
        *receiving = t;
    }
    if ((db->_bytes_inflight = db->buf->size) > max_bytes)
        db->_bytes_inflight = max_bytes;
    db->inflight = 1;
    return h2o_iovec_init(db->buf->bytes, db->_bytes_inflight);
}

static inline void h2o_doublebuffer_prepare_empty(h2o_doublebuffer_t *db)
{
    assert(!db->inflight);
    db->inflight = 1;
}

static inline void h2o_doublebuffer_consume(h2o_doublebuffer_t *db)
{
    assert(db->inflight);
    db->inflight = 0;

    h2o_buffer_consume(&db->buf, db->_bytes_inflight);
    db->_bytes_inflight = 0;
}

inline int h2o_req_can_stream_request(h2o_req_t *req)
{
    h2o_handler_t *first_handler = h2o_get_first_handler(req);
    return first_handler != NULL && first_handler->supports_request_streaming;
}

#define COMPUTE_DURATION(name, from, until)                                                                                        \
    static inline int h2o_time_compute_##name(struct st_h2o_req_t *req, int64_t *delta_usec)                                       \
    {                                                                                                                              \
        if (h2o_timeval_is_null((from)) || h2o_timeval_is_null((until))) {                                                         \
            return 0;                                                                                                              \
        }                                                                                                                          \
        *delta_usec = h2o_timeval_subtract((from), (until));                                                                       \
        return 1;                                                                                                                  \
    }

COMPUTE_DURATION(connect_time, &req->conn->connected_at, &req->timestamps.request_begin_at)
COMPUTE_DURATION(header_time, &req->timestamps.request_begin_at,
                 h2o_timeval_is_null(&req->timestamps.request_body_begin_at) ? &req->processed_at.at
                                                                             : &req->timestamps.request_body_begin_at)
COMPUTE_DURATION(body_time,
                 h2o_timeval_is_null(&req->timestamps.request_body_begin_at) ? &req->processed_at.at
                                                                             : &req->timestamps.request_body_begin_at,
                 &req->processed_at.at)
COMPUTE_DURATION(request_total_time, &req->timestamps.request_begin_at, &req->processed_at.at)
COMPUTE_DURATION(process_time, &req->processed_at.at, &req->timestamps.response_start_at)
COMPUTE_DURATION(response_time, &req->timestamps.response_start_at, &req->timestamps.response_end_at)
COMPUTE_DURATION(total_time, &req->timestamps.request_begin_at, &req->timestamps.response_end_at)

COMPUTE_DURATION(proxy_idle_time, &req->timestamps.request_begin_at, &req->proxy_stats.timestamps.start_at)
COMPUTE_DURATION(proxy_connect_time, &req->proxy_stats.timestamps.start_at, &req->proxy_stats.timestamps.request_begin_at)
COMPUTE_DURATION(proxy_request_time, &req->proxy_stats.timestamps.request_begin_at, &req->proxy_stats.timestamps.request_end_at)
COMPUTE_DURATION(proxy_process_time, &req->proxy_stats.timestamps.request_end_at, &req->proxy_stats.timestamps.response_start_at)
COMPUTE_DURATION(proxy_response_time, &req->proxy_stats.timestamps.response_start_at, &req->proxy_stats.timestamps.response_end_at)
COMPUTE_DURATION(proxy_total_time, &req->proxy_stats.timestamps.request_begin_at, &req->proxy_stats.timestamps.response_end_at)

#undef COMPUTE_DURATION

#ifdef __cplusplus
}
#endif

#endif
