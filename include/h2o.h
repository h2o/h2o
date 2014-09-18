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

#ifndef H2O_USE_LIBUV
# if H2O_USE_SELECT || H2O_USE_EPOLL || H2O_USE_KQUEUE
#  define H2O_USE_LIBUV 0
# else
#  define H2O_USE_LIBUV 1
# endif
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
#include "picohttpparser.h"
#include "yoml.h"

#ifndef H2O_MAX_HEADERS
# define H2O_MAX_HEADERS 100
#endif
#ifndef H2O_MAX_REQLEN
# define H2O_MAX_REQLEN (8192+4096*(H2O_MAX_HEADERS))
#endif

#ifndef H2O_MAX_TOKENS
# define H2O_MAX_TOKENS 10240
#endif

#define H2O_STRLIT(s) (s), sizeof(s) - 1
#define H2O_STRUCT_FROM_MEMBER(s, m, p) ((s*)((char*)(p) - offsetof(s, m)))
#define H2O_TIMESTR_RFC1123_LEN (sizeof("Sun, 06 Nov 1994 08:49:37 GMT") - 1)
#define H2O_TIMESTR_LOG_LEN (sizeof("29/Aug/2014:15:34:38 +0900") - 1)

#define H2O_DEFAULT_REQ_TIMEOUT (10 * 1000)
#define H2O_DEFAULT_MAX_REQUEST_ENTITY_SIZE (1024 * 1024 * 1024)
#define H2O_DEFAULT_HTTP1_UPGRADE_TO_HTTP2 1
#define H2O_DEFAULT_HTTP2_MAX_CONCURRENT_REQUESTS_PER_CONNECTION 16
#define H2O_DEFAULT_MIMETYPE "application/octet-stream"

typedef struct st_h2o_conn_t h2o_conn_t;
typedef struct st_h2o_context_t h2o_context_t;
typedef struct st_h2o_req_t h2o_req_t;
typedef struct st_h2o_socket_t h2o_socket_t;
typedef struct st_h2o_ssl_context_t h2o_ssl_context_t;
typedef struct st_h2o_timeout_entry_t h2o_timeout_entry_t;
typedef struct st_h2o_ostream_t h2o_ostream_t;

typedef void (*h2o_socket_cb)(h2o_socket_t *sock, int err);

#if H2O_USE_LIBUV
# include "h2o/uv-binding.h"
#else
# include "h2o/evloop.h"
#endif

/**
 * buffer structure compatible with iovec
 */
typedef struct st_h2o_buf_t {
    char *base;
    size_t len;
} h2o_buf_t;

/**
 * a predefined, read-only, fast variant of h2o_buf_t, defined in h2o/token.h
 */
typedef struct st_h2o_token_t {
    h2o_buf_t buf;
    int http2_static_table_name_index; /* non-zero if any */
} h2o_token_t;

#include "h2o/token.h"

typedef struct st_h2o_mempool_chunk_t {
    struct st_h2o_mempool_chunk_t *next;
    size_t offset;
    char bytes[4096 - sizeof(void*) * 2];
} h2o_mempool_chunk_t;

typedef struct st_h2o_mempool_shared_entry_t {
    size_t refcnt;
    size_t _dummy; /* align to 2*sizeof(void*) */
    char bytes[1];
} h2o_mempool_shared_entry_t;

/**
 * the memory pool
 */
typedef struct st_h2o_mempool_t {
    h2o_mempool_chunk_t *chunks;
    struct st_h2o_mempool_shared_ref_t *shared_refs;
    struct st_h2o_mempool_direct_t *directs;
    h2o_mempool_chunk_t _first_chunk;
} h2o_mempool_t;

/**
 * buffer used to store incoming octets
 */
typedef struct st_h2o_input_buffer_t {
    /**
     * amount of the data available
     */
    size_t size;
    /**
     * pointer to the start of the data
     */
    char *bytes;
    size_t _capacity;
    char _buf[1];
} h2o_input_buffer_t;

#define H2O_VECTOR(type) \
    struct { \
        type *entries; \
        size_t size; \
        size_t capacity; \
    }

typedef H2O_VECTOR(void) h2o_vector_t;

typedef void (*h2o_timeout_cb)(h2o_timeout_entry_t *entry);

/**
 * linklist
 * The structure is used to represent both nodes and the head of the list.
 * Nodes should be zero-filled upon initialization.
 * Heads should be initialized by calling h2o_linklist_init_anchor.
 */
typedef struct st_h2o_linklist_t {
    struct st_h2o_linklist_t *next;
    struct st_h2o_linklist_t *prev;
} h2o_linklist_t;

/**
 * an entry linked to h2o_timeout_t.
 * Modules willing to use timeouts should embed this object as part of itself, and link it to a specific timeout by calling h2o_timeout_link.
 */
struct st_h2o_timeout_entry_t {
    uint64_t registered_at;
    h2o_timeout_cb cb;
    h2o_linklist_t _link;
};

/**
 * represents a collection of h2o_timeout_entry_t linked to a single timeout value
 */
typedef struct st_h2o_timeout_t {
    uint64_t timeout;
    h2o_linklist_t _link;
    h2o_linklist_t _entries; /* link list of h2o_timeout_entry_t */
    struct st_h2o_timeout_backend_properties_t _backend;
} h2o_timeout_t;

/**
 * abstraction layer for sockets (SSL vs. TCP)
 */
struct st_h2o_socket_t {
    void *data;
    struct st_h2o_socket_ssl_t *ssl;
    h2o_input_buffer_t *input;
    struct {
        h2o_socket_cb read;
        h2o_socket_cb write;
    } _cb;
};

/**
 * basic structure of a handler (an object that MAY generate a response)
 * The handlers should register themselves to h2o_context_t::handlers.
 */
typedef struct st_h2o_handler_t {
    h2o_linklist_t _link;
    void (*destroy)(struct st_h2o_handler_t *self);
    int (*on_req)(struct st_h2o_handler_t *self, h2o_req_t *req);
} h2o_handler_t;
 
/**
 * basic structure of a filter (an object that MAY modify a response)
 * The filters should register themselves to h2o_context_t::filters.
 */
typedef struct st_h2o_filter_t {
    h2o_linklist_t _link;
    void (*destroy)(struct st_h2o_filter_t *self);
    void (*on_setup_ostream)(struct st_h2o_filter_t *self, h2o_req_t *req, h2o_ostream_t **slot);
} h2o_filter_t;

/**
 * basic structure of a logger (an object that MAY log a request)
 * The loggers should register themselves to h2o_context_t::loggers.
 */
typedef struct st_h2o_logger_t {
    h2o_linklist_t _link;
    void (*destroy)(struct st_h2o_logger_t *self);
    void (*log)(struct st_h2o_logger_t *self, h2o_req_t *req);
} h2o_logger_t;

/**
 * basic structure of a configurator (handles a configuration command)
 */
typedef struct st_h2o_configurator_t {
    h2o_linklist_t _link;
    /**
     * name of the command handled by the configurator
     */
    const char *cmd;
    /**
     * optional callback called when the context is being disposed
     */
    void (*destroy)(struct st_h2o_configurator_t *self);
    /**
     * mandatory callcack called to handle the command
     */
    int (*on_cmd)(struct st_h2o_configurator_t* self, h2o_context_t *ctx, const char *config_file, yoml_t *config_node);
    /**
     * optional callback called just before the server starts, after all the configuration commands are handled
     */
    int (*on_complete)(struct st_h2o_configurator_t *self, h2o_context_t *ctx);
} h2o_configurator_t;

/**
 * mime-map
 */
typedef struct st_h2o_mimemap_t {
    struct st_h2o_mimemap_entry_t *top;
    h2o_buf_t default_type;
} h2o_mimemap_t;

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
     * list of handlers (h2o_handler_t)
     */
    h2o_linklist_t handlers;
    /**
     * list of filters (h2o_filter_t)
     */
    h2o_linklist_t filters;
    /**
     * list of loggers (h2o_logger_t)
     */
    h2o_linklist_t loggers;
    /**
     * list of configurators (h2o_configurator_t)
     */
    h2o_linklist_t configurators;
    /**
     * mime-map
     */
    h2o_mimemap_t mimemap;
    /**
     * name of the server (not the hostname)
     */
    h2o_buf_t server_name;
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
     * The default value is SIZE_MAX, which means that the length is undeterminate.
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
     * a callback to obtain the address of the peer
     */
    int (*getpeername)(h2o_conn_t *conn, struct sockaddr *name, socklen_t *namelen);
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
     * authority (a.k.a. the Host header; the value is { NULL, 0 } in case the header is unavailable)
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
     * the request entity
     */
    H2O_VECTOR(h2o_buf_t) entity;
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

/* memory */

/**
 * constructor for h2o_buf_t
 */
static h2o_buf_t h2o_buf_init(const void *base, size_t len);
/**
 * wrapper of malloc; allocates given size of memory or dies if impossible
 */
static void *h2o_malloc(size_t sz);
/**
 * warpper of realloc; reallocs the given chunk or dies if impossible
 */
static void *h2o_realloc(void *oldp, size_t sz);
/**
 * initializes the memory pool.
 */
void h2o_mempool_init(h2o_mempool_t *pool);
/**
 * clears the memory pool.
 * Applications may dispose the pool after calling the function or reuse it without calling h2o_mempool_init.
 */
void h2o_mempool_clear(h2o_mempool_t *pool);
/**
 * allocates given size of memory from the memory pool, or dies if impossible
 */
void *h2o_mempool_alloc(h2o_mempool_t *pool, size_t sz);
/**
 * allocates a ref-counted chunk of given size from the memory pool, or dies if impossible.
 * The ref-count of the returned chunk is 1 regardless of whether or not the chunk is linked to a pool.
 * @param pool pool to which the allocated chunk should be linked (or NULL to allocate an orphan chunk)
 */
void *h2o_mempool_alloc_shared(h2o_mempool_t *pool, size_t sz);
/**
 * links a ref-counted chunk to a memory pool.
 * The ref-count of the chunk will be decremented when the pool is cleared.
 * It is permitted to link a chunk more than once to a single pool.
 */
void h2o_mempool_link_shared(h2o_mempool_t *pool, void *p);
/**
 * increments the reference count of a ref-counted chunk.
 */
static void h2o_mempool_addref_shared(void *p);
/**
 * decrements the reference count of a ref-counted chunk.
 * The chunk gets freed when the ref-count reaches zero.
 */
static int h2o_mempool_release_shared(void *p);
/**
 * allocates a input buffer.
 * @param inbuf - pointer to a pointer pointing to the structure (set *inbuf to NULL to allocate a new buffer)
 * @param initial_size an advisory value for the initial size of the input buffer
 * @return buffer to which the next data should be stored
 */
h2o_buf_t h2o_allocate_input_buffer(h2o_input_buffer_t **inbuf, size_t initial_size);
/**
 * throws away given size of the data from the buffer.
 * @param delta number of octets to be drained from the buffer
 */
void h2o_consume_input_buffer(h2o_input_buffer_t **inbuf, size_t delta);
/**
 * grows the vector so that it could store at least new_capacity elements of given size (or dies if impossible).
 * @param pool memory pool that the vector is using
 * @param vector the vector
 * @param element_size size of the elements stored in the vector
 * @param new_capacity the capacity of the buffer after the function returns
 */
static void h2o_vector_reserve(h2o_mempool_t *pool, h2o_vector_t *vector, size_t element_size, size_t new_capacity);
void h2o_vector__expand(h2o_mempool_t *pool, h2o_vector_t *vector, size_t element_size, size_t new_capacity);

/* link list */

/**
 * initializes the anchor (i.e. head) of a linked list
 */
static void h2o_linklist_init_anchor(h2o_linklist_t *anchor);
/**
 * tests if the list is empty
 */
static int h2o_linklist_is_empty(h2o_linklist_t *anchor);
/**
 * tests if the node is linked to a list
 */
static int h2o_linklist_is_linked(h2o_linklist_t *node);
/**
 * inserts a node to the linked list
 * @param pos insert position; the node will be inserted before pos (or NULL in case *head is NULL)
 * @param node the node to be inserted
 */
static void h2o_linklist_insert(h2o_linklist_t *pos, h2o_linklist_t *node);
/**
 * unlinks a node from the linked list
 */
static void h2o_linklist_unlink(h2o_linklist_t *node);

/* socket */

/**
 * closes the socket
 */
void h2o_socket_close(h2o_socket_t *sock);
/**
 * writes given data to socket
 * @param sock the socket
 * @param bufs an array of buffers
 * @param bufcnt length of the buffer array
 * @param cb callback to be called when write is complete
 */
void h2o_socket_write(h2o_socket_t *sock, h2o_buf_t *bufs, size_t bufcnt, h2o_socket_cb cb);
/**
 * starts polling on the socket (for read) and calls given callback when data arrives
 * @param sock the socket
 * @param cb callback to be called when data arrives
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
 * getpeername(2) equivalent
 */
int h2o_socket_getpeername(h2o_socket_t *sock, struct sockaddr *name, socklen_t *namelen);
/**
 * performs SSL handshake on a socket
 * @param sock the socket
 * @param ssl_ctx SSL context
 * @param handshake_cb callback to be called when handshake is complete
 */
void h2o_socket_ssl_server_handshake(h2o_socket_t *sock, h2o_ssl_context_t *ssl_ctx, h2o_socket_cb handshake_cb);
/**
 * returns the name of the protocol selected using either NPN or ALPN (ALPN has the precedence).
 * @param sock the socket
 */
h2o_buf_t h2o_socket_ssl_get_selected_protocol(h2o_socket_t *sock);
/**
 * construct an SSL context
 * @param cert_file the certificate file (in PEM format)
 * @param key_file the private key file (in PEM format)
 * @param protocols a NULL-terminated list of protocols used for negotiation using ALPN/NPN
 */
h2o_ssl_context_t *h2o_ssl_new_server_context(const char *cert_file, const char *key_file, const h2o_buf_t *protocols);

void h2o_socket__write_pending(h2o_socket_t *sock);
void h2o_socket__write_on_complete(h2o_socket_t *sock, int status);

/* timeout */

/**
 * initializes and registers a timeout
 * @param loop loop to which the timeout should be registered
 * @param timeout the timeout structure to be initialized
 * @param millis timeout in milliseconds
 */
void h2o_timeout_init(h2o_loop_t *loop, h2o_timeout_t *timeout, uint64_t millis);
/**
 * activates a timeout entry, by linking it to a timeout
 */
void h2o_timeout_link(h2o_loop_t *loop, h2o_timeout_t *timeout, h2o_timeout_entry_t *entry);
/**
 * disactivates a timeout entry, by unlinking it from a timeout
 */
void h2o_timeout_unlink(h2o_timeout_t *timeout, h2o_timeout_entry_t *entry);
/**
 * returns a boolean value indicating if the timeout is linked (i.e. active) or not
 */
static int h2o_timeout_is_linked(h2o_timeout_entry_t *entry);

size_t h2o_timeout_run(h2o_timeout_t *timeout, uint64_t now);
size_t h2o_timeout_run_all(h2o_linklist_t *timeouts, uint64_t now);
uint64_t h2o_timeout_get_wake_at(h2o_linklist_t *timeouts);
void h2o_timeout__do_init(h2o_loop_t *loop, h2o_timeout_t *timeout);
void h2o_timeout__do_link(h2o_loop_t *loop, h2o_timeout_t *timeout, h2o_timeout_entry_t *entry);

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
/**
 * serializes the header list into a string
 */
h2o_buf_t h2o_flatten_headers(h2o_mempool_t *pool, const h2o_headers_t *headers);

/* util */

/**
 * prints an error message and aborts
 */
void h2o_fatal(const char *msg);
/**
 * tr/A-Z/a-z/
 */
static int h2o_tolower(int ch);
/**
 * tests if target chunk (target_len bytes long) is equal to test chunk (test_len bytes long)
 */
static int h2o_memis(const void *target, size_t target_len, const void *test, size_t test_len);
/**
 * tests if target string (target_len bytes long) is equal to test string (test_len bytes long) after being converted to lower-case
 */
static int h2o_lcstris(const char *target, size_t target_len, const char *test, size_t test_len);
/**
 * duplicates given string
 * @param pool memory pool (or NULL to use malloc)
 * @param s source string
 * @param len length of the source string (the result of strlen(s) used in case len is SIZE_MAX)
 * @return buffer pointing to the duplicated string (buf is NUL-terminated but the length does not include the NUL char)
 */
h2o_buf_t h2o_strdup(h2o_mempool_t *pool, const char *s, size_t len);
/**
 * printf's the string to an allocated buffer
 * @param pool memory pool (or NULL to use malloc)
 * @param fmt printf-style format
 * @return buffer pointing to the formatted string (buf is NUL-terminated but the length does not include the NUL char)
 */
h2o_buf_t h2o_sprintf(h2o_mempool_t *pool, const char *fmt, ...) __attribute__((format (printf, 2, 3)));
/**
 * calls sprintf (aborts if the given buffer is too small)
 */
size_t h2o_snprintf(char *buf, size_t bufsz, const char *fmt, ...) __attribute__((format (printf, 3, 4)));
/**
 * base64 url decoder
 */
h2o_buf_t h2o_decode_base64url(h2o_mempool_t *pool, const char *src, size_t len);
/**
 * base64 encoder
 */
void h2o_base64_encode(char *dst, const uint8_t *src, size_t len, int url_encoded);
/**
 * builds a RFC-1123 style date string
 */
void h2o_time2str_rfc1123(char *buf, time_t time);
/**
 * builds an Apache log-style date string
 */
void h2o_time2str_log(char *buf, time_t time);
/**
 * returns the extension portion of path
 */
const char *h2o_get_filext(const char *path, size_t len);
/**
 * 
 */
const char *h2o_next_token(const char* elements, size_t elements_len, size_t *element_len, const char *cur);
/**
 * tests if string needle exists within a comma-separated string (for handling "#rule" of RFC 2616)
 */
int h2o_contains_token(const char *haysack, size_t haysack_len, const char *needle, size_t needle_len);
/**
 * removes ".." and "." from a path representation
 * @param pool memory pool to be used in case the path contained references to directories
 * @param path source path
 * @param len source length
 * @return buffer pointing to source, or buffer pointing to an allocated chunk with normalized representation of the given path
 */
h2o_buf_t h2o_normalize_path(h2o_mempool_t *pool, const char *path, size_t len);
/**
 * accepts a SSL connection
 */
void h2o_accept_ssl(h2o_context_t *ctx, h2o_socket_t *sock, h2o_ssl_context_t *ssl_ctx);
/**
 * interprets the configuration value using sscanf, or prints an error upon failure
 * @param configurator configurator
 * @param config_file name of the configuration file
 * @param config_node configuration value
 * @param fmt scanf-style format string
 * @return 0 if successful, -1 if not
 */
int h2o_config_scanf(h2o_configurator_t *configurator, const char *config_file, yoml_t *config_node, const char *fmt, ...) __attribute__((format (scanf, 4, 5)));
/**
 * interprets the configuration value and returns the index of the matched string within the candidate strings, or prints an error upon failure
 * @param configurator configurator
 * @param config_file name of the configuration file
 * @param config_node configuration value
 * @param candidates a comma-separated list of strings (should not contain whitespaces)
 * @return index of the matched string within the given list, or -1 if none of them matched
 */
ssize_t h2o_config_get_one_of(h2o_configurator_t *configurator, const char *config_file, yoml_t *config_node, const char *candidates);

int h2o__lcstris_core(const char *target, const char *test, size_t test_len);

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
 * called by handlers to open a generator
 * note: Handlers should call the function _after_ setting the response information (i.e. response headers, etc.) since this function initializes the filters.
 * @param req the request
 * @param size of the memory needed to be allocated for the generator
 * @return pointer to the generator
 */
h2o_generator_t *h2o_start_response(h2o_req_t *req, size_t sz);
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

/* context */

/**
 * initializes the context
 */
void h2o_context_init(h2o_context_t *context, h2o_loop_t *loop);
/**
 * disposes of the resources allocated for the context
 */
void h2o_context_dispose(h2o_context_t *context);
/**
 * returns a configurator of given command name
 * @return configurator for given name or NULL if not found
 */
h2o_configurator_t *h2o_context_get_configurator(h2o_context_t *context, const char *cmd);
/**
 * applies the configuration to the context
 * @return 0 if successful, -1 if not
 */
int h2o_context_configure(h2o_context_t *context, const char *config_file, yoml_t *config_node);
/**
 * emits configuration error
 */
void h2o_context_print_config_error(h2o_configurator_t *configurator, const char *config_file, yoml_t *config_node, const char *reason, ...) __attribute__((format (printf, 4, 5)));

/**
 * returns current timestamp
 * @param ctx the context
 * @param pool memory pool
 * @param ts buffer to store the timestamp
 */
void h2o_get_timestamp(h2o_context_t *ctx, h2o_mempool_t *pool, h2o_timestamp_t *ts);

void h2o_context__init_global_configurators(h2o_context_t *context);

/* built-in generators */

/**
 * sends the given string as the response
 */
void h2o_send_inline(h2o_req_t *req, const char *body, size_t len);
/**
 * sends the given information as an error response to the client
 */
void h2o_send_error(h2o_req_t *req, int status, const char *reason, const char *body);
/**
 * sends given file as the response to the client
 */
int h2o_send_file(h2o_req_t *req, int status, const char *reason, const char *path, h2o_buf_t mime_type);

/* handlers */

/**
 * registers the file handler to the context
 */
void h2o_register_file_handler(h2o_context_t *context, const char *virtual_path, const char *real_path, const char *index_file);

/* output filters */

/**
 * requests the next filter (if any) to setup the ostream if necessary
 */
static void h2o_setup_next_ostream(h2o_filter_t *self, h2o_req_t *req, h2o_ostream_t **slot);
/**
 * registers the chunked encoding output filter (added by default)
 */
void h2o_register_chunked_filter(h2o_context_t *context);
/**
 * registers the reproxy filter
 */
void h2o_register_reproxy_filter(h2o_context_t *context);

/* mime mapper */

/**
 * initializes the mimemap
 */
void h2o_init_mimemap(h2o_mimemap_t *mimemap, const char *default_type);
/**
 * releases the resource allocated for the mimemap
 */
void h2o_dispose_mimemap(h2o_mimemap_t *mimemap);
/**
 * adds a mime-type mapping
 */
void h2o_define_mimetype(h2o_mimemap_t *mimemap, const char *ext, const char *type);
/**
 * returns the mime-type corresponding to given extension
 */
h2o_buf_t h2o_get_mimetype(h2o_mimemap_t *mimemap, const char *ext);

/* access log */

h2o_logger_t *h2o_register_access_logger(h2o_context_t *context, const char *path);

/* inline defs */

inline h2o_buf_t h2o_buf_init(const void *base, size_t len)
{
    /* intentionally declared to take a "const void*" since it may contain any type of data and since _some_ buffers are constant */
    h2o_buf_t buf;
    buf.base = (char*)base;
    buf.len = len;
    return buf;
}

inline void *h2o_malloc(size_t sz)
{
    void *p = malloc(sz);
    if (p == NULL)
        h2o_fatal("no memory");
    return p;
}

inline void *h2o_realloc(void *oldp, size_t sz)
{
    void *newp = realloc(oldp, sz);
    if (newp == NULL) {
        h2o_fatal("no memory");
        return oldp;
    }
    return newp;
}

inline void h2o_mempool_addref_shared(void *p)
{
    struct st_h2o_mempool_shared_entry_t *entry = H2O_STRUCT_FROM_MEMBER(struct st_h2o_mempool_shared_entry_t, bytes, p);
    assert(entry->refcnt != 0);
    ++entry->refcnt;
}

inline int h2o_mempool_release_shared(void *p)
{
    struct st_h2o_mempool_shared_entry_t *entry = H2O_STRUCT_FROM_MEMBER(struct st_h2o_mempool_shared_entry_t, bytes, p);
    if (--entry->refcnt == 0) {
        free(entry);
        return 1;
    }
    return 0;
}

inline int h2o_socket_is_writing(h2o_socket_t *sock)
{
    return sock->_cb.write != NULL;
}

inline int h2o_socket_is_reading(h2o_socket_t *sock)
{
    return sock->_cb.read != NULL;
}

inline int h2o_timeout_is_linked(h2o_timeout_entry_t *entry)
{
    return h2o_linklist_is_linked(&entry->_link);
}

inline int h2o_tolower(int ch)
{
    return 'A' <= ch && ch <= 'Z' ? ch + 0x20 : ch;
}

inline int h2o_memis(const void *_target, size_t target_len, const void *_test, size_t test_len)
{
    const char *target = _target, *test = _test;
    if (target_len != test_len)
        return 0;
    if (target_len == 0)
        return 1;
    if (target[0] != test[0])
        return 0;
    return memcmp(target + 1, test + 1, test_len - 1) == 0;
}

inline int h2o_lcstris(const char *target, size_t target_len, const char *test, size_t test_len)
{
    if (target_len != test_len)
        return 0;
    return h2o__lcstris_core(target, test, test_len);
}

inline void h2o_vector_reserve(h2o_mempool_t *pool, h2o_vector_t *vector, size_t element_size, size_t new_capacity)
{
    if (vector->capacity < new_capacity) {
        h2o_vector__expand(pool, vector, element_size, new_capacity);
    }
}

inline void h2o_linklist_init_anchor(h2o_linklist_t *anchor)
{
    anchor->next = anchor->prev = anchor;
}

inline int h2o_linklist_is_linked(h2o_linklist_t *node)
{
    return node->next != NULL;
}

inline int h2o_linklist_is_empty(h2o_linklist_t *anchor)
{
    return anchor->next == anchor;
}

inline void h2o_linklist_insert(h2o_linklist_t *pos, h2o_linklist_t *node)
{
    assert(! h2o_linklist_is_linked(node));

    node->prev = pos->prev;
    node->next = pos;
    node->prev->next = node;
    node->next->prev = node;
}

inline void h2o_linklist_unlink(h2o_linklist_t *node)
{
    node->next->prev = node->prev;
    node->prev->next = node->next;
    node->next = node->prev = NULL;
}

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
    if (self->_link.next != &req->conn->ctx->filters) {
        h2o_filter_t *next_filter = H2O_STRUCT_FROM_MEMBER(h2o_filter_t, _link, self->_link.next);
        next_filter->on_setup_ostream(next_filter, req, slot);
    }
}

#ifdef __cplusplus
}
#endif

#endif
