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
#include "h2o/hostinfo.h"
#include "h2o/memcached.h"
#include "h2o/linklist.h"
#include "h2o/http1client.h"
#include "h2o/memory.h"
#include "h2o/multithread.h"
#include "h2o/rand.h"
#include "h2o/socket.h"
#include "h2o/string_.h"
#include "h2o/time_.h"
#include "h2o/timeout.h"
#include "h2o/url.h"
#include "h2o/version.h"

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

#ifndef H2O_MAX_TOKENS
#define H2O_MAX_TOKENS 100
#endif

#ifndef H2O_SOMAXCONN
/* simply use a large value, and let the kernel clip it to the internal max */
#define H2O_SOMAXCONN 65535
#endif

#define H2O_DEFAULT_MAX_REQUEST_ENTITY_SIZE (1024 * 1024 * 1024)
#define H2O_DEFAULT_MAX_DELEGATIONS 5
#define H2O_DEFAULT_HANDSHAKE_TIMEOUT_IN_SECS 10
#define H2O_DEFAULT_HANDSHAKE_TIMEOUT (H2O_DEFAULT_HANDSHAKE_TIMEOUT_IN_SECS * 1000)
#define H2O_DEFAULT_HTTP1_REQ_TIMEOUT_IN_SECS 10
#define H2O_DEFAULT_HTTP1_REQ_TIMEOUT (H2O_DEFAULT_HTTP1_REQ_TIMEOUT_IN_SECS * 1000)
#define H2O_DEFAULT_HTTP1_UPGRADE_TO_HTTP2 1
#define H2O_DEFAULT_HTTP2_IDLE_TIMEOUT_IN_SECS 10
#define H2O_DEFAULT_HTTP2_IDLE_TIMEOUT (H2O_DEFAULT_HTTP2_IDLE_TIMEOUT_IN_SECS * 1000)
#define H2O_DEFAULT_PROXY_IO_TIMEOUT_IN_SECS 30
#define H2O_DEFAULT_PROXY_IO_TIMEOUT (H2O_DEFAULT_PROXY_IO_TIMEOUT_IN_SECS * 1000)
#define H2O_DEFAULT_PROXY_WEBSOCKET_TIMEOUT_IN_SECS 300
#define H2O_DEFAULT_PROXY_WEBSOCKET_TIMEOUT (H2O_DEFAULT_PROXY_WEBSOCKET_TIMEOUT_IN_SECS * 1000)
#define H2O_DEFAULT_PROXY_SSL_SESSION_CACHE_CAPACITY 4096
#define H2O_DEFAULT_PROXY_SSL_SESSION_CACHE_DURATION 86400000 /* 24 hours */

typedef struct st_h2o_conn_t h2o_conn_t;
typedef struct st_h2o_context_t h2o_context_t;
typedef struct st_h2o_req_t h2o_req_t;
typedef struct st_h2o_ostream_t h2o_ostream_t;
typedef struct st_h2o_configurator_command_t h2o_configurator_command_t;
typedef struct st_h2o_configurator_t h2o_configurator_t;
typedef struct st_h2o_hostconf_t h2o_hostconf_t;
typedef struct st_h2o_globalconf_t h2o_globalconf_t;
typedef struct st_h2o_mimemap_t h2o_mimemap_t;
typedef struct st_h2o_logconf_t h2o_logconf_t;

/**
 * a predefined, read-only, fast variant of h2o_iovec_t, defined in h2o/token.h
 */
typedef struct st_h2o_token_t {
    h2o_iovec_t buf;
    char http2_static_table_name_index; /* non-zero if any */
    unsigned char proxy_should_drop : 1;
    unsigned char is_init_header_special : 1;
    unsigned char http2_should_reject : 1;
    unsigned char copy_for_push_request : 1;
} h2o_token_t;

#include "h2o/token.h"

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

typedef struct st_h2o_pathconf_t {
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
     * list of filters
     */
    H2O_VECTOR(h2o_filter_t *) filters;
    /**
     * list of loggers (h2o_logger_t)
     */
    H2O_VECTOR(h2o_logger_t *) loggers;
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
} h2o_pathconf_t;

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
    H2O_VECTOR(h2o_pathconf_t) paths;
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
typedef struct st_h2o_status_handler_t {
    h2o_iovec_t name;
    void *(*init)(void); /* optional callback, allocates a context that will be passed to per_thread() */
    void (*per_thread)(void *priv, h2o_context_t *ctx); /* optional callback, will be called for each thread */
    h2o_iovec_t (* final)(void *ctx, h2o_globalconf_t *gconf, h2o_req_t *req); /* mandatory, will be passed the optional context */
} h2o_status_handler_t;

typedef H2O_VECTOR(h2o_status_handler_t) h2o_status_callbacks_t;
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
         * conditions for latency optimization
         */
        h2o_socket_latency_optimization_conditions_t latency_optimization;
        /**
         * list of callbacks
         */
        h2o_protocol_callbacks_t callbacks;
    } http2;

    struct {
        /**
         * io timeout (in milliseconds)
         */
        uint64_t io_timeout;
        /**
         * SSL context for connections initiated by the proxy (optional, governed by the application)
         */
        SSL_CTX *ssl_ctx;
        /**
         * a boolean flag if set to true, instructs the proxy to preserve the x-forwarded-proto header passed by the client
         */
        int preserve_x_forwarded_proto;
        /**
         * a boolean flag if set to true, instructs the proxy to emit x-forwarded-proto and x-forwarded-for headers
         */
        int emit_x_forwarded_headers;
    } proxy;

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
    H2O_COMPRESS_HINT_AUTO = 0, /* default: let h2o negociate compression based on the configuration */
    H2O_COMPRESS_HINT_DISABLE,  /* compression was explicitely disabled for this request */
    H2O_COMPRESS_HINT_ENABLE,   /* compression was explicitely enabled for this request */
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

/* defined as negated form of the error codes defined in HTTP2-spec section 7 */
#define H2O_HTTP2_ERROR_NONE 0
#define H2O_HTTP2_ERROR_PROTOCOL -1
#define H2O_HTTP2_ERROR_INTERNAL -2
#define H2O_HTTP2_ERROR_FLOW_CONTROL -3
#define H2O_HTTP2_ERROR_SETTINGS_TIMEOUT -4
#define H2O_HTTP2_ERROR_STREAM_CLOSED -5
#define H2O_HTTP2_ERROR_FRAME_SIZE -6
#define H2O_HTTP2_ERROR_REFUSED_STREAM -7
#define H2O_HTTP2_ERROR_CANCEL -8
#define H2O_HTTP2_ERROR_COMPRESSION -9
#define H2O_HTTP2_ERROR_CONNECT -10
#define H2O_HTTP2_ERROR_ENHANCE_YOUR_CALM -11
#define H2O_HTTP2_ERROR_INADEQUATE_SECURITY -12
#define H2O_HTTP2_ERROR_MAX 13
/* end of the HTT2-spec defined errors */
#define H2O_HTTP2_ERROR_INVALID_HEADER_CHAR                                                                                        \
    -254 /* an internal value indicating that invalid characters were found in the header name or value */
#define H2O_HTTP2_ERROR_INCOMPLETE -255 /* an internal value indicating that all data is not ready */
#define H2O_HTTP2_ERROR_PROTOCOL_CLOSE_IMMEDIATELY -256

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
     * timeout structure to be used for registering deferred callbacks
     */
    h2o_timeout_t zero_timeout;
    /**
     * timeout structure to be used for registering 1-second timeout callbacks
     */
    h2o_timeout_t one_sec_timeout;
    /**
     * timeout structrue to be used for registering 100-milisecond timeout callbacks
     */
    h2o_timeout_t hundred_ms_timeout;
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

    /**
     * SSL handshake timeout
     */
    h2o_timeout_t handshake_timeout;

    struct {
        /**
         * request timeout
         */
        h2o_timeout_t req_timeout;
        /**
         * link-list of h2o_http1_conn_t
         */
        h2o_linklist_t _conns;
    } http1;

    struct {
        /**
         * idle timeout
         */
        h2o_timeout_t idle_timeout;
        /**
         * link-list of h2o_http2_conn_t
         */
        h2o_linklist_t _conns;
        /**
         * timeout entry used for graceful shutdown
         */
        h2o_timeout_entry_t _graceful_shutdown_timeout;
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
        h2o_http1client_ctx_t client_ctx;
        /**
         * timeout handler used by the default client context
         */
        h2o_timeout_t io_timeout;
    } proxy;

    /**
     * pointer to per-module configs
     */
    void **_module_configs;

    struct {
        uint64_t uv_now_at;
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
 * represents a HTTP header
 */
typedef struct st_h2o_header_t {
    /**
     * name of the header (may point to h2o_token_t which is an optimized subclass of h2o_iovec_t)
     */
    h2o_iovec_t *name;
    /**
     * value of the header
     */
    h2o_iovec_t value;
} h2o_header_t;

/**
 * list of headers
 */
typedef H2O_VECTOR(h2o_header_t) h2o_headers_t;

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

typedef enum h2o_send_state {
    H2O_SEND_STATE_IN_PROGRESS,
    H2O_SEND_STATE_FINAL,
    H2O_SEND_STATE_ERROR,
} h2o_send_state_t;

typedef h2o_send_state_t (*h2o_ostream_pull_cb)(h2o_generator_t *generator, h2o_req_t *req, h2o_iovec_t *buf);

static inline int h2o_send_state_is_in_progress(h2o_send_state_t s)
{
    return s == H2O_SEND_STATE_IN_PROGRESS;
}
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
    void (*do_send)(struct st_h2o_ostream_t *self, h2o_req_t *req, h2o_iovec_t *bufs, size_t bufcnt, h2o_send_state_t state);
    /**
     * called by the core when there is a need to terminate the response abruptly
     */
    void (*stop)(struct st_h2o_ostream_t *self, h2o_req_t *req);
    /**
     * whether if the ostream supports "pull" interface
     */
    void (*start_pull)(struct st_h2o_ostream_t *self, h2o_ostream_pull_cb cb);
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
     * callback for server push (may be NULL)
     */
    void (*push_path)(h2o_req_t *req, const char *abspath, size_t abspath_len);
    /**
     * Return the underlying socket struct
     */
    h2o_socket_t *(*get_socket)(h2o_conn_t *_conn);
    /**
     * debug state callback (may be NULL)
     */
    h2o_http2_debug_state_t *(*get_debug_state)(h2o_req_t *req, int hpack_enabled);
    /**
     * logging callbacks (may be NULL)
     */
    union {
        struct {
            struct {
                h2o_iovec_t (*protocol_version)(h2o_req_t *req);
                h2o_iovec_t (*session_reused)(h2o_req_t *req);
                h2o_iovec_t (*cipher)(h2o_req_t *req);
                h2o_iovec_t (*cipher_bits)(h2o_req_t *req);
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
    h2o_http1client_ctx_t *client_ctx;
    /**
     * socketpool to be used when connecting to upstream (or NULL)
     */
    h2o_socketpool_t *socketpool;
    /**
     * upstream host:port to connect to (or host.base == NULL)
     */
    struct {
        h2o_iovec_t host;
        uint16_t port;
    } hostport;
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
} h2o_req_overrides_t;

/**
 * additional information for extension-based dynamic content
 */
typedef struct st_h2o_filereq_t {
    size_t url_path_len;
    h2o_iovec_t local_path;
} h2o_filereq_t;

/**
 * error message associated to a request
 */
typedef struct st_h2o_req_error_log_t {
    const char *module;
    h2o_iovec_t msg;
} h2o_req_error_log_t;

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
     * the request entity (base == NULL if none)
     */
    h2o_iovec_t entity;
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
     * the response
     */
    h2o_res_t res;
    /**
     * number of bytes sent by the generator (excluding headers)
     */
    size_t bytes_sent;
    /**
     * counts the number of times the request has been reprocessed (excluding delegation)
     */
    unsigned num_reprocessed;
    /**
     * counts the number of times the request has been delegated
     */
    unsigned num_delegated;

    /**
     * environment variables
     */
    h2o_iovec_vector_t env;

    /**
     * error logs
     */
    H2O_VECTOR(h2o_req_error_log_t) error_logs;

    /* flags */

    /**
     * whether or not the connection is persistent.
     * Applications should set this flag to zero in case the connection cannot be kept keep-alive (due to an error etc.)
     */
    char http1_is_persistent;
    /**
     * whether if the response has been delegated (i.e. reproxied).
     * For delegated responses, redirect responses would be handled internally.
     */
    char res_is_delegated;
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

    /* internal structure */
    h2o_generator_t *_generator;
    h2o_ostream_t *_ostr_top;
    size_t _next_filter_index;
    h2o_timeout_entry_t _timeout_entry;
    /* per-request memory pool (placed at the last since the structure is large) */
    h2o_mem_pool_t pool;
};

typedef struct st_h2o_accept_ctx_t {
    h2o_context_t *ctx;
    h2o_hostconf_t **hosts;
    SSL_CTX *ssl_ctx;
    int expect_proxy_line;
    h2o_multithread_receiver_t *libmemcached_receiver;
} h2o_accept_ctx_t;

typedef struct st_h2o_doublebuffer_t {
    h2o_buffer_t *buf;
    size_t bytes_inflight;
} h2o_doublebuffer_t;

static void h2o_doublebuffer_init(h2o_doublebuffer_t *db, h2o_buffer_prototype_t *prototype);
static void h2o_doublebuffer_dispose(h2o_doublebuffer_t *db);
static h2o_iovec_t h2o_doublebuffer_prepare(h2o_doublebuffer_t *db, h2o_buffer_t **receiving, size_t max_bytes);
static void h2o_doublebuffer_consume(h2o_doublebuffer_t *db);

/* token */

extern h2o_token_t h2o__tokens[H2O_MAX_TOKENS];
extern size_t h2o__num_tokens;

/**
 * returns a token (an optimized subclass of h2o_iovec_t) containing given string, or NULL if no such thing is available
 */
const h2o_token_t *h2o_lookup_token(const char *name, size_t len);
/**
 * returns an boolean value if given buffer is a h2o_token_t.
 */
int h2o_iovec_is_token(const h2o_iovec_t *buf);

/* headers */

/**
 * searches for a header of given name (fast, by comparing tokens)
 * @param headers header list
 * @param token name of the header to search for
 * @param cursor index of the last match (or set SIZE_MAX to start a new search)
 * @return index of the found header (or SIZE_MAX if not found)
 */
ssize_t h2o_find_header(const h2o_headers_t *headers, const h2o_token_t *token, ssize_t cursor);
/**
 * searches for a header of given name (slow, by comparing strings)
 * @param headers header list
 * @param name name of the header to search for
 * @param name_len length of the name
 * @param cursor index of the last match (or set SIZE_MAX to start a new search)
 * @return index of the found header (or SIZE_MAX if not found)
 */
ssize_t h2o_find_header_by_str(const h2o_headers_t *headers, const char *name, size_t name_len, ssize_t cursor);
/**
 * adds a header to list
 */
void h2o_add_header(h2o_mem_pool_t *pool, h2o_headers_t *headers, const h2o_token_t *token, const char *value, size_t value_len);
/**
 * adds a header to list
 */
void h2o_add_header_by_str(h2o_mem_pool_t *pool, h2o_headers_t *headers, const char *name, size_t name_len, int maybe_token,
                           const char *value, size_t value_len);
/**
 * adds or replaces a header into the list
 */
void h2o_set_header(h2o_mem_pool_t *pool, h2o_headers_t *headers, const h2o_token_t *token, const char *value, size_t value_len,
                    int overwrite_if_exists);
/**
 * adds or replaces a header into the list
 */
void h2o_set_header_by_str(h2o_mem_pool_t *pool, h2o_headers_t *headers, const char *name, size_t name_len, int maybe_token,
                           const char *value, size_t value_len, int overwrite_if_exists);
/**
 * sets a header token
 */
void h2o_set_header_token(h2o_mem_pool_t *pool, h2o_headers_t *headers, const h2o_token_t *token, const char *value,
                          size_t value_len);
/**
 * deletes a header from list
 */
ssize_t h2o_delete_header(h2o_headers_t *headers, ssize_t cursor);

/* util */

extern const char *h2o_http2_npn_protocols;
extern const char *h2o_npn_protocols;
extern const h2o_iovec_t *h2o_http2_alpn_protocols;
extern const h2o_iovec_t *h2o_alpn_protocols;

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
 * setups accept context for async SSL resumption
 */
void h2o_accept_setup_async_ssl_resumption(h2o_memcached_context_t *ctx, unsigned expiration);
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
 * extracts path to be pushed from `Link: rel=prelead` header, duplicating the chunk (or returns {NULL,0} if none)
 */
h2o_iovec_vector_t h2o_extract_push_path_from_link_header(h2o_mem_pool_t *pool, const char *value, size_t value_len,
                                                          h2o_iovec_t base_path, const h2o_url_scheme_t *input_scheme,
                                                          h2o_iovec_t input_authority, const h2o_url_scheme_t *base_scheme,
                                                          h2o_iovec_t *base_authority);
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
 * delegates the request to the next handler; called asynchronously by handlers that returned zero from `on_req`
 */
void h2o_delegate_request(h2o_req_t *req, h2o_handler_t *current_handler);
/**
 * calls h2o_delegate_request using zero_timeout callback
 */
void h2o_delegate_request_deferred(h2o_req_t *req, h2o_handler_t *current_handler);
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
 * called by handlers to set the generator
 * @param req the request
 * @param generator the generator
 */
void h2o_start_response(h2o_req_t *req, h2o_generator_t *generator);
/**
 * called by filters to insert output-stream filters for modifying the response
 * @param req the request
 * @param size of the memory to be allocated for the ostream filter
 * @param slot where the stream should be inserted
 * @return pointer to the ostream filter
 */
h2o_ostream_t *h2o_add_ostream(h2o_req_t *req, size_t sz, h2o_ostream_t **slot);
/**
 * binds configurations to the request
 */
void h2o_req_bind_conf(h2o_req_t *req, h2o_hostconf_t *hostconf, h2o_pathconf_t *pathconf);

/**
 * called by the generators to send output
 * note: generators should free itself after sending the final chunk (i.e. calling the function with is_final set to true)
 * @param req the request
 * @param bufs an array of buffers
 * @param bufcnt length of the buffers array
 * @param state describes if the output is final, has an error, or is in progress
 */
void h2o_send(h2o_req_t *req, h2o_iovec_t *bufs, size_t bufcnt, h2o_send_state_t state);
/**
 * called by the connection layer to pull the content from generator (if pull mode is being used)
 */
static h2o_send_state_t h2o_pull(h2o_req_t *req, h2o_ostream_pull_cb cb, h2o_iovec_t *buf);
/**
 * creates an uninitialized prefilter and returns pointer to it
 */
h2o_req_prefilter_t *h2o_add_prefilter(h2o_req_t *req, size_t sz);
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
void h2o_ostream_send_next(h2o_ostream_t *ostream, h2o_req_t *req, h2o_iovec_t *bufs, size_t bufcnt, h2o_send_state_t state);
/**
 * called by the connection layer to request additional data to the generator
 */
static void h2o_proceed_response(h2o_req_t *req);
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
void h2o_config_register_status_handler(h2o_globalconf_t *config, h2o_status_handler_t);
void h2o_config_register_simple_status_handler(h2o_globalconf_t *config, h2o_iovec_t name, final_status_handler_cb status_handler);
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
static struct timeval *h2o_get_timestamp(h2o_context_t *ctx, h2o_mem_pool_t *pool, h2o_timestamp_t *ts);
void h2o_context_update_timestamp_cache(h2o_context_t *ctx);
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
 * sends the given string as the response
 */
void h2o_send_inline(h2o_req_t *req, const char *body, size_t len);
/**
 * sends the given information as an error response to the client
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
H2O_SEND_ERROR_XXX(416)
H2O_SEND_ERROR_XXX(417)
H2O_SEND_ERROR_XXX(500)
H2O_SEND_ERROR_XXX(502)
H2O_SEND_ERROR_XXX(503)

/**
 * sends error response using zero timeout; can be called by output filters while processing the headers
 */
void h2o_send_error_deferred(h2o_req_t *req, int status, const char *reason, const char *body, int flags);
/**
 * sends a redirect response
 */
void h2o_send_redirect(h2o_req_t *req, int status, const char *reason, const char *url, size_t url_len);
/**
 * handles redirect internally
 */
void h2o_send_redirect_internal(h2o_req_t *req, h2o_iovec_t method, const char *url_str, size_t url_len, int preserve_overrides);
/**
 * returns method to be used after redirection
 */
h2o_iovec_t h2o_get_redirect_method(h2o_iovec_t method, int status);
/**
 * registers push path (if necessary) by parsing a Link header
 */
int h2o_push_path_in_link_header(h2o_req_t *req, const char *value, size_t value_len);
/**
 * logs an error
 */
void h2o_req_log_error(h2o_req_t *req, const char *module, const char *fmt, ...) __attribute__((format(printf, 3, 4)));

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
h2o_access_log_filehandle_t *h2o_access_log_open_handle(const char *path, const char *fmt);
h2o_logger_t *h2o_access_log_register(h2o_pathconf_t *pathconf, h2o_access_log_filehandle_t *handle);
void h2o_access_log_register_configurator(h2o_globalconf_t *conf);

/* lib/chunked.c */

/**
 * registers the chunked encoding output filter (added by default)
 */
void h2o_chunked_register(h2o_pathconf_t *pathconf);

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
     * compress
     */
    void (*compress)(struct st_h2o_compress_context_t *self, h2o_iovec_t *inbufs, size_t inbufcnt, h2o_send_state_t state,
                     h2o_iovec_t **outbufs, size_t *outbufcnt);
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
 * instantiates the gzip compressor
 */
h2o_compress_context_t *h2o_compress_gzip_open(h2o_mem_pool_t *pool, int quality);
/**
 * instantiates the brotli compressor (only available if H2O_USE_BROTLI is set)
 */
h2o_compress_context_t *h2o_compress_brotli_open(h2o_mem_pool_t *pool, int quality, size_t estimated_cotent_length);
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
h2o_fastcgi_handler_t *h2o_fastcgi_register_by_hostport(h2o_pathconf_t *pathconf, const char *host, uint16_t port,
                                                        h2o_fastcgi_config_vars_t *vars);
/**
 * registers the fastcgi handler to the context
 */
h2o_fastcgi_handler_t *h2o_fastcgi_register_by_address(h2o_pathconf_t *pathconf, struct sockaddr *sa, socklen_t salen,
                                                       h2o_fastcgi_config_vars_t *vars);
/**
 * registers the fastcgi handler to the context
 */
h2o_fastcgi_handler_t *h2o_fastcgi_register_by_spawnproc(h2o_pathconf_t *pathconf, char **argv, h2o_fastcgi_config_vars_t *vars);
/**
 * registers the configurator
 */
void h2o_fastcgi_register_configurator(h2o_globalconf_t *conf);

/* lib/file.c */

enum { H2O_FILE_FLAG_NO_ETAG = 0x1, H2O_FILE_FLAG_DIR_LISTING = 0x2, H2O_FILE_FLAG_SEND_COMPRESSED = 0x4 };

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
    H2O_HEADERS_CMD_UNSET       /* removes the named header(s) */
};

typedef struct st_h2o_headers_command_t {
    int cmd;
    h2o_iovec_t *name; /* maybe a token */
    h2o_iovec_t value;
} h2o_headers_command_t;

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
    unsigned preserve_host : 1;
    unsigned use_proxy_protocol : 1;
    uint64_t keepalive_timeout; /* in milliseconds; set to zero to disable keepalive */
    struct {
        int enabled;
        uint64_t timeout;
    } websocket;
    SSL_CTX *ssl_ctx; /* optional */
} h2o_proxy_config_vars_t;

/**
 * registers the reverse proxy handler to the context
 */
void h2o_proxy_register_reverse_proxy(h2o_pathconf_t *pathconf, h2o_url_t *upstream, h2o_proxy_config_vars_t *config);
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

inline h2o_conn_t *h2o_create_connection(size_t sz, h2o_context_t *ctx, h2o_hostconf_t **hosts, struct timeval connected_at,
                                         const h2o_conn_callbacks_t *callbacks)
{
    h2o_conn_t *conn = (h2o_conn_t *)h2o_mem_alloc(sz);

    conn->ctx = ctx;
    conn->hosts = hosts;
    conn->connected_at = connected_at;
    conn->id = __sync_add_and_fetch(&h2o_connection_id, 1);
    conn->callbacks = callbacks;

    return conn;
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

inline h2o_send_state_t h2o_pull(h2o_req_t *req, h2o_ostream_pull_cb cb, h2o_iovec_t *buf)
{
    h2o_send_state_t send_state;
    assert(req->_generator != NULL);
    send_state = cb(req->_generator, req, buf);
    req->bytes_sent += buf->len;
    if (!h2o_send_state_is_in_progress(send_state))
        req->_generator = NULL;
    return send_state;
}

inline void h2o_setup_next_ostream(h2o_req_t *req, h2o_ostream_t **slot)
{
    h2o_filter_t *next;

    if (req->_next_filter_index < req->pathconf->filters.size) {
        next = req->pathconf->filters.entries[req->_next_filter_index++];
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

inline struct timeval *h2o_get_timestamp(h2o_context_t *ctx, h2o_mem_pool_t *pool, h2o_timestamp_t *ts)
{
    uint64_t now = h2o_now(ctx->loop);

    if (ctx->_timestamp_cache.uv_now_at != now) {
        h2o_context_update_timestamp_cache(ctx);
    }

    if (ts != NULL) {
        ts->at = ctx->_timestamp_cache.tv_at;
        h2o_mem_link_shared(pool, ctx->_timestamp_cache.value);
        ts->str = ctx->_timestamp_cache.value;
    }

    return &ctx->_timestamp_cache.tv_at;
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
    db->bytes_inflight = 0;
}

static inline void h2o_doublebuffer_dispose(h2o_doublebuffer_t *db)
{
    h2o_buffer_dispose(&db->buf);
}

static inline h2o_iovec_t h2o_doublebuffer_prepare(h2o_doublebuffer_t *db, h2o_buffer_t **receiving, size_t max_bytes)
{
    assert(db->bytes_inflight == 0);

    if (db->buf->size == 0) {
        if ((*receiving)->size == 0)
            return h2o_iovec_init(NULL, 0);
        /* swap buffers */
        h2o_buffer_t *t = db->buf;
        db->buf = *receiving;
        *receiving = t;
    }
    if ((db->bytes_inflight = db->buf->size) > max_bytes)
        db->bytes_inflight = max_bytes;
    return h2o_iovec_init(db->buf->bytes, db->bytes_inflight);
}

static inline void h2o_doublebuffer_consume(h2o_doublebuffer_t *db)
{
    assert(db->bytes_inflight != 0);
    h2o_buffer_consume(&db->buf, db->bytes_inflight);
    db->bytes_inflight = 0;
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

COMPUTE_DURATION(connect_time, &req->conn->connected_at, &req->timestamps.request_begin_at);
COMPUTE_DURATION(header_time, &req->timestamps.request_begin_at, h2o_timeval_is_null(&req->timestamps.request_body_begin_at)
                                                                     ? &req->processed_at.at
                                                                     : &req->timestamps.request_body_begin_at);
COMPUTE_DURATION(body_time, h2o_timeval_is_null(&req->timestamps.request_body_begin_at) ? &req->processed_at.at
                                                                                        : &req->timestamps.request_body_begin_at,
                 &req->processed_at.at);
COMPUTE_DURATION(request_total_time, &req->timestamps.request_begin_at, &req->processed_at.at);
COMPUTE_DURATION(process_time, &req->processed_at.at, &req->timestamps.response_start_at);
COMPUTE_DURATION(response_time, &req->timestamps.response_start_at, &req->timestamps.response_end_at);
COMPUTE_DURATION(duration, &req->timestamps.request_begin_at, &req->timestamps.response_end_at);

#undef COMPUTE_DURATION

#ifdef __cplusplus
}
#endif

#endif
