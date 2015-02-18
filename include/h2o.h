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
#include "h2o/linklist.h"
#include "h2o/http1client.h"
#include "h2o/memory.h"
#include "h2o/multithread.h"
#include "h2o/socket.h"
#include "h2o/string_.h"
#include "h2o/time_.h"
#include "h2o/timeout.h"
#include "h2o/url.h"
#include "h2o/version.h"

#ifndef H2O_MAX_HEADERS
#define H2O_MAX_HEADERS 100
#endif
#ifndef H2O_MAX_REQLEN
#define H2O_MAX_REQLEN (8192 + 4096 * (H2O_MAX_HEADERS))
#endif

#ifndef H2O_MAX_TOKENS
#define H2O_MAX_TOKENS 10240
#endif

#define H2O_DEFAULT_MAX_REQUEST_ENTITY_SIZE (1024 * 1024 * 1024)
#define H2O_DEFAULT_HTTP1_REQ_TIMEOUT_IN_SECS 10
#define H2O_DEFAULT_HTTP1_REQ_TIMEOUT (H2O_DEFAULT_HTTP1_REQ_TIMEOUT_IN_SECS * 1000)
#define H2O_DEFAULT_HTTP1_UPGRADE_TO_HTTP2 1
#define H2O_DEFAULT_HTTP2_IDLE_TIMEOUT_IN_SECS 10
#define H2O_DEFAULT_HTTP2_IDLE_TIMEOUT (H2O_DEFAULT_HTTP2_IDLE_TIMEOUT_IN_SECS * 1000)

typedef struct st_h2o_conn_t h2o_conn_t;
typedef struct st_h2o_context_t h2o_context_t;
typedef struct st_h2o_req_t h2o_req_t;
typedef struct st_h2o_ostream_t h2o_ostream_t;
typedef struct st_h2o_configurator_command_t h2o_configurator_command_t;
typedef struct st_h2o_configurator_t h2o_configurator_t;
typedef struct st_h2o_hostconf_t h2o_hostconf_t;
typedef struct st_h2o_globalconf_t h2o_globalconf_t;
typedef struct st_h2o_mimemap_t h2o_mimemap_t;

/**
 * a predefined, read-only, fast variant of h2o_iovec_t, defined in h2o/token.h
 */
typedef struct st_h2o_token_t {
    h2o_iovec_t buf;
    char http2_static_table_name_index; /* non-zero if any */
    char proxy_should_drop : 1;
    char is_init_header_special : 1;
    char http2_should_reject : 1;
    char copy_for_push_request : 1;
} h2o_token_t;

#include "h2o/token.h"

/**
 * basic structure of a handler (an object that MAY generate a response)
 * The handlers should register themselves to h2o_context_t::handlers.
 */
typedef struct st_h2o_handler_t {
    size_t _config_slot;
    void *(*on_context_init)(struct st_h2o_handler_t *self, h2o_context_t *ctx);
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
    void *(*on_context_init)(struct st_h2o_filter_t *self, h2o_context_t *ctx);
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
    void *(*on_context_init)(struct st_h2o_logger_t *self, h2o_context_t *ctx);
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

typedef struct st_h2o_pathconf_t {
    /**
     * reverse reference to the host configuration
     */
    h2o_hostconf_t *host;
    /**
     * pathname in lower case (has "/" appended at last (unless it is the fallback path), base is NUL terminated)
     */
    h2o_iovec_t path;
    /**
     * list of handlers
     */
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
} h2o_pathconf_t;

struct st_h2o_hostconf_t {
    /**
     * reverse reference to the global configuration
     */
    h2o_globalconf_t *global;
    /**
     * hostname in lower-case (base is NUL terminated)
     */
    h2o_iovec_t hostname;
    /**
     * list of path configurations
     */
    H2O_VECTOR(h2o_pathconf_t) paths;
    /**
     * catch-all path configuration
     */
    h2o_pathconf_t fallback_path;
};

typedef struct st_h2o_protocol_callbacks_t {
    void (*request_shutdown)(h2o_context_t *ctx);
} h2o_protocol_callbacks_t;

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
         * list of callbacks
         */
        h2o_protocol_callbacks_t callbacks;
    } http2;

    size_t _num_config_slots;
};

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
     * pointer to the global configuration
     */
    h2o_globalconf_t *globalconf;
    /**
     * queue for receiving messages from other contexts
     */
    h2o_multithread_queue_t *queue;
    /**
     * flag indicating if shutdown has been requested
     */
    int shutdown_requested;

    struct {
        /**
         * request timeout
         */
        h2o_timeout_t req_timeout;
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
    } http2;

    /**
     * pointer to per-module configs
     */
    void **_module_configs;

    struct {
        uint64_t uv_now_at;
        struct timeval tv_at;
        h2o_timestamp_string_t *value;
    } _timestamp_cache;
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

typedef int (*h2o_ostream_pull_cb)(h2o_generator_t *generator, h2o_req_t *req, h2o_iovec_t *buf);

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
    void (*do_send)(struct st_h2o_ostream_t *self, h2o_req_t *req, h2o_iovec_t *bufs, size_t bufcnt, int is_final);
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
} h2o_res_t;

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
     * peername (peername.addr == NULL if not available)
     */
    struct {
        struct sockaddr *addr;
        socklen_t len;
    } peername;
};

/**
 * a HTTP request
 */
struct st_h2o_req_t {
    /**
     * the underlying connection
     */
    h2o_conn_t *conn;
    /**
     * the path context
     */
    h2o_pathconf_t *pathconf;
    /**
     * authority (a.k.a. the Host header; the value is supplemented if missing before the handlers are being called)
     */
    h2o_iovec_t authority;
    /**
     * HTTP method
     * This is a non-terminated string of method_len bytes long.
     */
    h2o_iovec_t method;
    /**
     * abs-path of the request (unmodified)
     */
    h2o_iovec_t path;
    /**
     * abs-path of the request (normalized, only guaranteed to be non-NULL for non-fallback handler)
     */
    h2o_iovec_t path_normalized;
    /**
     * offset of '?' within path, or SIZE_MAX if not found
     */
    size_t query_at;
    /**
     * scheme (http, https, etc.)
     */
    const h2o_url_scheme_t *scheme;
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
     * the response
     */
    h2o_res_t res;
    /**
     * number of bytes sent by the generator (excluding headers)
     */
    size_t bytes_sent;
    /**
     * whether or not the connection is persistent.
     * Applications should set this flag to zero in case the connection cannot be kept keep-alive (due to an error etc.)
     */
    int http1_is_persistent;
    /**
     * absolute paths to be pushed (using HTTP/2 server push)
     */
    H2O_VECTOR(h2o_iovec_t) http2_push_paths;
    /**
     * the Upgrade request header (or { NULL, 0 } if not available)
     */
    h2o_iovec_t upgrade;

    /* internal structure */
    h2o_generator_t *_generator;
    h2o_ostream_t *_ostr_top;
    size_t _ostr_init_index;
    h2o_timeout_entry_t _timeout_entry;
    /* per-request memory pool (placed at the last since the structure is large) */
    h2o_mem_pool_t pool;
};

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
 * adds a header token
 */
void h2o_add_header_token(h2o_mem_pool_t *pool, h2o_headers_t *headers, const h2o_token_t *token, const char *value,
                          size_t value_len);
/**
 * deletes a header from list
 */
ssize_t h2o_delete_header(h2o_headers_t *headers, ssize_t cursor);

/* util */

/**
 * accepts a SSL connection
 */
void h2o_accept_ssl(h2o_context_t *ctx, h2o_hostconf_t **hosts, h2o_socket_t *sock, SSL_CTX *ssl_ctx);

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
 * called by the generators to send output
 * note: generators should free itself after sending the final chunk (i.e. calling the function with is_final set to true)
 * @param req the request
 * @param bufs an array of buffers
 * @param bufcnt length of the buffers array
 * @param is_final if the output is final
 */
void h2o_send(h2o_req_t *req, h2o_iovec_t *bufs, size_t bufcnt, int is_final);
/**
 * called by the connection layer to pull the content from generator (if pull mode is being used)
 */
static int h2o_pull(h2o_req_t *req, h2o_ostream_pull_cb cb, h2o_iovec_t *buf);
/**
 * requests the next filter (if any) to setup the ostream if necessary
 */
static void h2o_setup_next_ostream(h2o_filter_t *self, h2o_req_t *req, h2o_ostream_t **slot);
/**
 * called by the ostream filters to send output to the next ostream filter
 * note: ostream filters should free itself after sending the final chunk (i.e. calling the function with is_final set to true)
 * note: ostream filters must not set is_final flag to TRUE unless is_final flag of the do_send callback was set as such
 * @param ostr current ostream filter
 * @param req the request
 * @param bufs an array of buffers
 * @param bufcnt length of the buffers array
 * @param is_final if the output is final
 */
void h2o_ostream_send_next(h2o_ostream_t *ostr, h2o_req_t *req, h2o_iovec_t *bufs, size_t bufcnt, int is_final);
/**
 * called by the connection layer to request additional data to the generator
 */
static void h2o_proceed_response(h2o_req_t *req);

/* config */

/**
 * initializes the global configuration
 */
void h2o_config_init(h2o_globalconf_t *config);
/**
 * registers a host context
 */
h2o_hostconf_t *h2o_config_register_host(h2o_globalconf_t *config, const char *hostname);
/**
 * registers a path context
 */
h2o_pathconf_t *h2o_config_register_path(h2o_hostconf_t *hostconf, const char *pathname);
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
 * returns current timestamp
 * @param ctx the context
 * @param pool memory pool
 * @param ts buffer to store the timestamp
 */
void h2o_get_timestamp(h2o_context_t *ctx, h2o_mem_pool_t *pool, h2o_timestamp_t *ts);
/**
 * returns per-module context set by the on_context_init callback
 */
static void *h2o_context_get_handler_context(h2o_context_t *ctx, h2o_handler_t *handler);
/**
 * returns per-module context set by the on_context_init callback
 */
static void *h2o_context_get_filter_context(h2o_context_t *ctx, h2o_filter_t *filter);
/**
 * returns per-module context set by the on_context_init callback
 */
static void *h2o_context_get_logger_context(h2o_context_t *ctx, h2o_logger_t *logger);

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
void h2o_send_error(h2o_req_t *req, int status, const char *reason, const char *body, int flags);
/**
 * sends a redirect response
 */
void h2o_send_redirect(h2o_req_t *req, int status, const char *reason, const char *url, size_t url_len);

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
 * sets the default mime-type
 */
void h2o_mimemap_set_default_type(h2o_mimemap_t *mimemap, const char *type);
/**
 * adds a mime-type mapping
 */
void h2o_mimemap_set_type(h2o_mimemap_t *mimemap, const char *ext, const char *type);
/**
 * removes a mime-type mapping
 */
void h2o_mimemap_remove_type(h2o_mimemap_t *mimemap, const char *ext);
/**
 * sets the default mime-type
 */
h2o_iovec_t h2o_mimemap_get_default_type(h2o_mimemap_t *mimemap);
/**
 * returns the mime-type corresponding to given extension
 */
h2o_iovec_t h2o_mimemap_get_type(h2o_mimemap_t *mimemap, const char *ext);

/* various handlers */

/* lib/access_log.c */

typedef struct st_h2o_access_log_filehandle_t h2o_access_log_filehandle_t;

h2o_access_log_filehandle_t *h2o_access_log_open_handle(const char *path, const char *fmt);
h2o_logger_t *h2o_access_log_register(h2o_pathconf_t *pathconf, h2o_access_log_filehandle_t *handle);
void h2o_access_log_register_configurator(h2o_globalconf_t *conf);

/* lib/chunked.c */

/**
 * registers the chunked encoding output filter (added by default)
 */
void h2o_chunked_register(h2o_pathconf_t *pathconf);

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

/* lib/file.c */

enum { H2O_FILE_FLAG_NO_ETAG = 0x1, H2O_FILE_FLAG_DIR_LISTING = 0x2, H2O_FILE_FLAG_SEND_GZIP = 0x4 };

typedef struct st_h2o_file_handler_t h2o_file_handler_t;

extern const char **h2o_file_default_index_files;

/**
 * sends given file as the response to the client
 */
int h2o_file_send(h2o_req_t *req, int status, const char *reason, const char *path, h2o_iovec_t mime_type, int flags);
/**
 * registers the file handler to the context
 * @param pathconf
 * @param virtual_path
 * @param real_path
 * @param index_files optional NULL-terminated list of of filenames to be considered as the "directory-index"
 * @param mimemap the mimemap (h2o_mimemap_create is called internally if the argument is NULL)
 */
h2o_file_handler_t *h2o_file_register(h2o_pathconf_t *pathconf, const char *real_path, const char **index_files,
                                      h2o_mimemap_t *mimemap, int flags);
/**
 * returns the associated mimemap
 */
h2o_mimemap_t *h2o_file_get_mimemap(h2o_file_handler_t *handler);
/**
 * registers the configurator
 */
void h2o_file_register_configurator(h2o_globalconf_t *conf);

/* lib/proxy.c */

typedef struct st_h2o_proxy_config_vars_t {
    uint64_t io_timeout;
    int use_keepalive;
    int preserve_host;
    uint64_t keepalive_timeout;
} h2o_proxy_config_vars_t;

typedef struct st_h2o_proxy_location_t {
    h2o_iovec_t host;
    uint16_t port;
    h2o_iovec_t path;
} h2o_proxy_location_t;

/**
 * delegates the request to given server, rewriting the path as specified
 */
int h2o_proxy_send(h2o_req_t *req, h2o_http1client_ctx_t *client_ctx, h2o_proxy_location_t *upstream, int preserve_host);
/**
 * delegates the request to given server, rewriting the path as specified
 */
int h2o_proxy_send_with_pool(h2o_req_t *req, h2o_http1client_ctx_t *client_ctx, h2o_proxy_location_t *upstream,
                             h2o_socketpool_t *sockpool, int preserve_host);
/**
 * registers the reverse proxy handler to the context
 */
void h2o_proxy_register_reverse_proxy(h2o_pathconf_t *pathconf, const char *host, uint16_t port, const char *real_path,
                                      h2o_proxy_config_vars_t *config);
/**
 * registers the configurator
 */
void h2o_proxy_register_configurator(h2o_globalconf_t *conf);

/* lib/redirect.c */

typedef struct st_h2o_redirect_handler_t h2o_redirect_handler_t;

/**
 * registers the redirect handler to the context
 * @param pathconf
 * @param status status code to be sent (e.g. 301, 303, 308, ...)
 * @param prefix prefix of the destitation URL
 */
h2o_redirect_handler_t *h2o_redirect_register(h2o_pathconf_t *pathconf, int status, const char *prefix);
/**
 * registers the configurator
 */
void h2o_redirect_register_configurator(h2o_globalconf_t *conf);

/* inline defs */

inline void h2o_proceed_response(h2o_req_t *req)
{
    if (req->_generator != NULL) {
        req->_generator->proceed(req->_generator, req);
    } else {
        req->_ostr_top->do_send(req->_ostr_top, req, NULL, 0, 1);
    }
}

inline int h2o_pull(h2o_req_t *req, h2o_ostream_pull_cb cb, h2o_iovec_t *buf)
{
    int is_final;
    assert(req->_generator != NULL);
    is_final = cb(req->_generator, req, buf);
    req->bytes_sent += buf->len;
    if (is_final)
        req->_generator = NULL;
    return is_final;
}

inline void h2o_setup_next_ostream(h2o_filter_t *self, h2o_req_t *req, h2o_ostream_t **slot)
{
    h2o_filter_t *next;

    assert(self == req->pathconf->filters.entries[req->_ostr_init_index]);
    if (req->_ostr_init_index + 1 < req->pathconf->filters.size) {
        next = req->pathconf->filters.entries[++req->_ostr_init_index];
        next->on_setup_ostream(next, req, slot);
    }
}

inline void *h2o_context_get_handler_context(h2o_context_t *ctx, h2o_handler_t *handler)
{
    return ctx->_module_configs[handler->_config_slot];
}

inline void *h2o_context_get_filter_context(h2o_context_t *ctx, h2o_filter_t *filter)
{
    return ctx->_module_configs[filter->_config_slot];
}

inline void *h2o_context_get_logger_context(h2o_context_t *ctx, h2o_logger_t *logger)
{
    return ctx->_module_configs[logger->_config_slot];
}

#ifdef __cplusplus
}
#endif

#endif
