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
#include "picohttpparser.h"
#include "yoml.h"
#include "h2o/linklist.h"
#include "h2o/http1client.h"
#include "h2o/memory.h"
#include "h2o/socket.h"
#include "h2o/string_.h"
#include "h2o/timeout.h"

#ifndef H2O_MAX_HEADERS
# define H2O_MAX_HEADERS 100
#endif
#ifndef H2O_MAX_REQLEN
# define H2O_MAX_REQLEN (8192+4096*(H2O_MAX_HEADERS))
#endif

#ifndef H2O_MAX_TOKENS
# define H2O_MAX_TOKENS 10240
#endif

#define H2O_DEFAULT_REQ_TIMEOUT (10 * 1000)
#define H2O_DEFAULT_MAX_REQUEST_ENTITY_SIZE (1024 * 1024 * 1024)
#define H2O_DEFAULT_HTTP1_UPGRADE_TO_HTTP2 1
#define H2O_DEFAULT_HTTP2_MAX_CONCURRENT_REQUESTS_PER_CONNECTION 16
#define H2O_DEFAULT_MIMETYPE "application/octet-stream"

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
 * a predefined, read-only, fast variant of h2o_buf_t, defined in h2o/token.h
 */
typedef struct st_h2o_token_t {
    h2o_buf_t buf;
    int http2_static_table_name_index; /* non-zero if any */
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

enum {
    H2O_CONFIGURATOR_FLAG_GLOBAL = 0x1,
    H2O_CONFIGURATOR_FLAG_HOST = 0x2,
    H2O_CONFIGURATOR_FLAG_PATH = 0x4,
    H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR = 0x100,
    H2O_CONFIGURATOR_FLAG_EXPECT_SEQUENCE = 0x200,
    H2O_CONFIGURATOR_FLAG_EXPECT_MAPPING = 0x400,
    H2O_CONFIGURATOR_FLAG_DEFERRED = 0x1000
};

#define H2O_CONFIGURATOR_NUM_LEVELS 3

typedef struct h2o_configurator_context_t {
    h2o_globalconf_t *globalconf;
    h2o_hostconf_t *hostconf;
    h2o_buf_t *path;
} h2o_configurator_context_t;

typedef int (*h2o_configurator_dispose_cb)(h2o_configurator_t *configurator);
typedef int (*h2o_configurator_enter_cb)(h2o_configurator_t *configurator, h2o_configurator_context_t *ctx);
typedef int (*h2o_configurator_exit_cb)(h2o_configurator_t *configurator, h2o_configurator_context_t *ctx);
typedef int (*h2o_configurator_command_cb)(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, const char *file, yoml_t *node);

struct st_h2o_configurator_command_t {
    /**
     * configurator to which the command belongs
     */
    h2o_configurator_t *configurator;
    /**
     * name of the command handled by the configurator
     */
    const char *name;
    /**
     * flags
     */
    int flags;
    /**
     * mandatory callcack called to handle the command
     */
    h2o_configurator_command_cb cb;
    /**
     * lines of strings (NULL-terminated) describing of the command (printed by h2o --help)
     */
    const char **description;
};

/**
 * basic structure of a configurator (handles a configuration command)
 */
struct st_h2o_configurator_t {
    h2o_linklist_t _link;
    /**
     * optional callback called when the global config is being disposed
     */
    h2o_configurator_dispose_cb dispose;
    /**
     * optional callback called before the configuration commands are handled
     */
    h2o_configurator_enter_cb enter;
    /**
     * optional callback called after all the configuration commands are handled
     */
    h2o_configurator_exit_cb exit;
    /**
     * list of commands
     */
    H2O_VECTOR(h2o_configurator_command_t) commands;
};

struct st_h2o_hostconf_t {
    /**
     * reverse reference to the global configuration
     */
    h2o_globalconf_t *global;
    /**
     * hostname in lower-case (base is NUL terminated)
     */
    h2o_buf_t hostname;
    /**
     * list of handlers
     */
    H2O_VECTOR(h2o_handler_t*) handlers;
    /**
     * list of filters
     */
    H2O_VECTOR(h2o_filter_t*) filters;
    /**
     * list of loggers (h2o_logger_t)
     */
    H2O_VECTOR(h2o_logger_t*) loggers;
};

struct st_h2o_globalconf_t {
    /**
     * list of host contexts (h2o_hostconf_t)
     */
    H2O_VECTOR(h2o_hostconf_t) hosts;
    /**
     * list of configurators
     */
    h2o_linklist_t configurators;
    /**
     * name of the server (not the hostname)
     */
    h2o_buf_t server_name;
    /**
     * request timeout (in milliseconds)
     */
    uint64_t req_timeout;
    /**
     * maximum size of the accepted request entity (e.g. POST data)
     */
    size_t max_request_entity_size;
    /**
     * a boolean value indicating whether or not to upgrade to HTTP/2
     */
    int http1_upgrade_to_http2;
    /**
     * maximum number of HTTP2 requests (per connection) to be handled simultaneously internally.
     * H2O accepts at most 256 requests over HTTP/2, but internally limits the number of in-flight requests to the value specified by this property in order to limit the resources allocated to a single connection.
     */
    size_t http2_max_concurrent_requests_per_connection;
    /**
     * an optional callback called when a connection is being closed
     */
    void (*close_cb)(h2o_context_t *ctx);

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
     * request timeout
     */
    h2o_timeout_t req_timeout;
    /**
     * pointer to the global configuration
     */
    h2o_globalconf_t *global_config;
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
     * name of the header (may point to h2o_token_t which is an optimized subclass of h2o_buf_t)
     */
    h2o_buf_t *name;
    /**
     * value of the header
     */
    h2o_buf_t value;
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
     * Intermediary output streams should process the given output and call the h2o_ostream_send_next function if any data can be sent.
     */
    void (*do_send)(struct st_h2o_ostream_t *self, h2o_req_t *req, h2o_buf_t *bufs, size_t bufcnt, int is_final);
    /**
     * called by the core when there is a need to terminate the response abruptly
     */
    void (*stop)(struct st_h2o_ostream_t *self, h2o_req_t *req);
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
     * the host context
     */
    h2o_hostconf_t *host_config;
    /**
     * authority (a.k.a. the Host header; the value is supplemented if missing before the handlers are being called)
     */
    h2o_buf_t authority;
    /**
     * HTTP method
     * This is a non-terminated string of method_len bytes long.
     */
    h2o_buf_t method;
    /**
     * abs-path of the request
     */
    h2o_buf_t path;
    /**
     * scheme (http, https, etc.)
     */
    h2o_buf_t scheme;
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
    h2o_buf_t entity;
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
     * the Upgrade request header (or { NULL, 0 } if not available)
     */
    h2o_buf_t upgrade;

    /* internal structure */
    h2o_generator_t *_generator;
    h2o_ostream_t *_ostr_top;
    size_t _ostr_init_index;
    h2o_timeout_entry_t _timeout_entry;
    /* per-request memory pool (placed at the last since the structure is large) */
    h2o_mempool_t pool;
};

/* token */

extern h2o_token_t h2o__tokens[H2O_MAX_TOKENS];
extern size_t h2o__num_tokens;

/**
 * returns a token (an optimized subclass of h2o_buf_t) containing given string, or NULL if no such thing is available
 */
const h2o_token_t *h2o_lookup_token(const char *name, size_t len);
/**
 * returns an boolean value if given buffer is a h2o_token_t.
 */
int h2o_buf_is_token(const h2o_buf_t *buf);

/* headers */

/**
 * fills in the headers list while returning references to special headers
 * @return index of content-length or content-encoding header within src (or -1 if not found)
 */
ssize_t h2o_init_headers(h2o_mempool_t *pool, h2o_headers_t *headers, const struct phr_header *src, size_t len, h2o_buf_t *connection, h2o_buf_t *host, h2o_buf_t *upgrade);
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
void h2o_add_header(h2o_mempool_t *pool, h2o_headers_t *headers, const h2o_token_t *token, const char *value, size_t value_len);
/**
 * adds a header to list
 */
void h2o_add_header_by_str(h2o_mempool_t *pool, h2o_headers_t *headers, const char *name, size_t name_len, int maybe_token, const char *value, size_t value_len);
/**
 * adds or replaces a header into the list
 */
void h2o_set_header(h2o_mempool_t *pool, h2o_headers_t *headers, const h2o_token_t *token, const char *value, size_t value_len, int overwrite_if_exists);
/**
 * adds or replaces a header into the list
 */
void h2o_set_header_by_str(h2o_mempool_t *pool, h2o_headers_t *headers, const char *name, size_t name_len, int maybe_token, const char *value, size_t value_len, int overwrite_if_exists);
/**
 * deletes a header from list
 */
ssize_t h2o_delete_header(h2o_headers_t *headers, ssize_t cursor);

/* util */

/**
 * accepts a SSL connection
 */
void h2o_accept_ssl(h2o_context_t *ctx, h2o_socket_t *sock, SSL_CTX *ssl_ctx);

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
void h2o_send(h2o_req_t *req, h2o_buf_t *bufs, size_t bufcnt, int is_final);
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
void h2o_ostream_send_next(h2o_ostream_t *ostr, h2o_req_t *req, h2o_buf_t *bufs, size_t bufcnt, int is_final);
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
 * disposes of the resources allocated for the global configuration
 */
void h2o_config_dispose(h2o_globalconf_t *config);
/**
 * registers a configurator
 */
h2o_configurator_t *h2o_config_create_configurator(h2o_globalconf_t *conf, size_t sz);
/**
 *
 */
#define h2o_config_define_command(configurator, name, flags, cb, ...) \
    do { \
        static const char *desc[] = { __VA_ARGS__, NULL }; \
        h2o_config__define_command(configurator, name, flags, cb, desc); \
    } while (0)
void h2o_config__define_command(h2o_configurator_t *configurator, const char *name, int flags, h2o_configurator_command_cb cb, const char **desc);
/**
 * returns a configurator of given command name
 * @return configurator for given name or NULL if not found
 */
h2o_configurator_command_t *h2o_config_get_configurator(h2o_globalconf_t *conf, const char *name);
/**
 * applies the configuration to the context
 * @return 0 if successful, -1 if not
 */
int h2o_config_configure(h2o_globalconf_t *config, const char *file, yoml_t *node);
/**
 * emits configuration error
 */
void h2o_config_print_error(h2o_configurator_command_t *cmd, const char *file, yoml_t *node, const char *reason, ...) __attribute__((format (printf, 4, 5)));
/**
 * interprets the configuration value using sscanf, or prints an error upon failure
 * @param configurator configurator
 * @param config_file name of the configuration file
 * @param config_node configuration value
 * @param fmt scanf-style format string
 * @return 0 if successful, -1 if not
 */
int h2o_config_scanf(h2o_configurator_command_t *cmd, const char *config_file, yoml_t *config_node, const char *fmt, ...) __attribute__((format (scanf, 4, 5)));
/**
 * interprets the configuration value and returns the index of the matched string within the candidate strings, or prints an error upon failure
 * @param configurator configurator
 * @param config_file name of the configuration file
 * @param config_node configuration value
 * @param candidates a comma-separated list of strings (should not contain whitespaces)
 * @return index of the matched string within the given list, or -1 if none of them matched
 */
ssize_t h2o_config_get_one_of(h2o_configurator_command_t *cmd, const char *config_file, yoml_t *config_node, const char *candidates);

h2o_handler_t *h2o_create_handler(h2o_hostconf_t *conf, size_t sz);
h2o_filter_t *h2o_create_filter(h2o_hostconf_t *conf, size_t sz);
h2o_logger_t *h2o_create_logger(h2o_hostconf_t *conf, size_t sz);

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
 * returns current timestamp
 * @param ctx the context
 * @param pool memory pool
 * @param ts buffer to store the timestamp
 */
void h2o_get_timestamp(h2o_context_t *ctx, h2o_mempool_t *pool, h2o_timestamp_t *ts);
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

/**
 * sends the given string as the response
 */
void h2o_send_inline(h2o_req_t *req, const char *body, size_t len);
/**
 * sends the given information as an error response to the client
 */
void h2o_send_error(h2o_req_t *req, int status, const char *reason, const char *body);

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
h2o_buf_t h2o_mimemap_get_default_type(h2o_mimemap_t *mimemap);
/**
 * returns the mime-type corresponding to given extension
 */
h2o_buf_t h2o_mimemap_get_type(h2o_mimemap_t *mimemap, const char *ext);

/* various handlers */

/* lib/access_log.c */

h2o_logger_t *h2o_access_log_register(h2o_hostconf_t *host_config, const char *path, const char *fmt);
void h2o_access_log_register_configurator(h2o_globalconf_t *conf);

/* lib/chunked.c */

/**
 * registers the chunked encoding output filter (added by default)
 */
void h2o_chunked_register(h2o_hostconf_t *host_config);

/* lib/file.c */

/**
 * sends given file as the response to the client
 */
int h2o_file_send(h2o_req_t *req, int status, const char *reason, const char *path, h2o_buf_t mime_type);
/**
 * registers the file handler to the context
 */
void h2o_file_register(h2o_hostconf_t *host_config, const char *virtual_path, const char *real_path, const char **index_files, h2o_mimemap_t *mimemap);
/**
 * registers the configurator
 */
void h2o_file_register_configurator(h2o_globalconf_t *conf);

/* lib/proxy.c */

/**
 * delegates the request to given server, rewriting the path as specified
 */
int h2o_proxy_send(h2o_req_t *req, h2o_http1client_ctx_t *client_ctx, h2o_buf_t host, uint16_t port, size_t path_replace_length, h2o_buf_t path_prefix);
/**
 * registers the reverse proxy handler to the context
 */
void h2o_proxy_register_reverse_proxy(h2o_hostconf_t *host_config, const char *virtual_path, const char *host, uint16_t port, const char *real_path, uint64_t io_timeout);
/**
 * registers the configurator
 */
void h2o_proxy_register_configurator(h2o_globalconf_t *conf);

/* lib/rproxy.c */

/**
 * registers the reproxy filter
 */
void h2o_reproxy_register(h2o_hostconf_t *host_config);

/* inline defs */

inline void h2o_proceed_response(h2o_req_t *req)
{
    if (req->_generator != NULL) {
        req->_generator->proceed(req->_generator, req);
    } else {
        req->_ostr_top->do_send(req->_ostr_top, req, NULL, 0, 1);
    }
}

inline void h2o_setup_next_ostream(h2o_filter_t *self, h2o_req_t *req, h2o_ostream_t **slot)
{
    h2o_filter_t *next;

    assert(self == req->host_config->filters.entries[req->_ostr_init_index]);
    if (req->_ostr_init_index + 1 < req->host_config->filters.size) {
        next = req->host_config->filters.entries[++req->_ostr_init_index];
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
