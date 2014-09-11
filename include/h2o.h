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
typedef struct st_h2o_req_t h2o_req_t;
typedef struct st_h2o_timeout_entry_t h2o_timeout_entry_t;
typedef struct st_h2o_socket_t h2o_socket_t;
typedef struct st_h2o_ssl_context_t h2o_ssl_context_t;

typedef void (*h2o_req_cb)(h2o_req_t *req);
typedef void (*h2o_socket_cb)(h2o_socket_t *sock, int err);

#if H2O_USE_LIBUV
# include "h2o/uv-binding.h"
#else
# include "h2o/evloop.h"
#endif

typedef struct st_h2o_buf_t {
    char *base;
    size_t len;
} h2o_buf_t;

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

typedef struct st_h2o_mempool_t {
    h2o_mempool_chunk_t *chunks;
    struct st_h2o_mempool_shared_ref_t *shared_refs;
    struct st_h2o_mempool_direct_t *directs;
    h2o_mempool_chunk_t _first_chunk;
} h2o_mempool_t;

typedef struct st_h2o_input_buffer_t {
    size_t size;
    size_t capacity;
    char *bytes;
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

typedef struct h2o_linklist_t {
    struct h2o_linklist_t *next;
    struct h2o_linklist_t *prev;
} h2o_linklist_t;

struct st_h2o_timeout_entry_t {
    uint64_t wake_at;
    h2o_timeout_cb cb;
    h2o_linklist_t _link;
};

typedef struct st_h2o_timeout_t {
    uint64_t timeout;
    h2o_linklist_t _link;
    h2o_linklist_t *_entries; /* link list of h2o_timeout_entry_t */
    struct st_h2o_timeout_backend_properties_t _backend;
} h2o_timeout_t;

struct st_h2o_timeout_manager_t {
    h2o_loop_t *loop;
    h2o_timeout_t zero_timeout; /* for deferred tasks (0 second timeout is handled separately, since all of them togeter with pending cbs should be invoked before poll) */
};

struct st_h2o_socket_t {
    void *data;
    struct st_h2o_socket_ssl_t *ssl;
    h2o_input_buffer_t *input;
    struct {
        h2o_socket_cb read;
        h2o_socket_cb write;
    } _cb;
};

typedef struct st_h2o_filter_t {
    struct st_h2o_filter_t *next;
    void (*dispose)(struct st_h2o_filter_t *self);
    void (*on_start_response)(struct st_h2o_filter_t *self, h2o_req_t *req);
} h2o_filter_t;

typedef struct st_h2o_mimemap_t {
    struct st_h2o_mimemap_entry_t *top;
    h2o_buf_t default_type;
} h2o_mimemap_t;

typedef struct st_h2o_logger_t {
    struct st_h2o_logger_t *next;
    void (*log)(struct st_h2o_logger_t *self, h2o_req_t *req);
} h2o_logger_t;

typedef struct st_h2o_timestamp_string_t {
    char rfc1123[H2O_TIMESTR_RFC1123_LEN + 1];
    char log[H2O_TIMESTR_LOG_LEN + 1];
} h2o_timestamp_string_t;

typedef struct st_h2o_timestamp_t {
    struct timeval at;
    h2o_timestamp_string_t *str;
} h2o_timestamp_t;

typedef struct h2o_context_t {
    h2o_loop_t *loop;
    h2o_req_cb req_cb;
    h2o_timeout_t zero_timeout;
    h2o_timeout_t req_timeout; /* for request timeout */
    h2o_filter_t *filters;
    h2o_mimemap_t mimemap;
    h2o_buf_t server_name;
    size_t max_request_entity_size;
    int http1_upgrade_to_http2;
    size_t http2_max_concurrent_requests_per_connection;
    h2o_logger_t *loggers;
    h2o_ssl_context_t *ssl_ctx;
    struct {
        uint64_t uv_now_at;
        struct timeval tv_at;
        h2o_timestamp_string_t *value;
    } _timestamp_cache;
} h2o_context_t;

typedef struct st_h2o_header_t {
    union {
        h2o_token_t *token;
        h2o_buf_t *str;
    } name;
    h2o_buf_t value;
} h2o_header_t;

typedef H2O_VECTOR(h2o_header_t) h2o_headers_t;

typedef struct st_h2o_generator_t {
    void (*proceed)(struct st_h2o_generator_t *self, h2o_req_t *req);
    void (*stop)(struct st_h2o_generator_t *self, h2o_req_t *req);
} h2o_generator_t;

typedef struct st_h2o_ostream_t {
    struct st_h2o_ostream_t *next;
    void (*do_send)(struct st_h2o_ostream_t *self, h2o_req_t *req, h2o_buf_t *bufs, size_t bufcnt, int is_final);
    void (*stop)(struct st_h2o_ostream_t *self, h2o_req_t *req);
} h2o_ostream_t;

typedef struct st_h2o_res_t {
    int status;
    const char *reason;
    size_t content_length; /* SIZE_MAX if unavailable */
    h2o_headers_t headers;
} h2o_res_t;

struct st_h2o_conn_t {
    h2o_context_t *ctx;
    /* callbacks */
    int (*getpeername)(h2o_conn_t *conn, struct sockaddr *name, socklen_t *namelen);
};

struct st_h2o_req_t {
    /* connection */
    h2o_conn_t *conn;
    /* the request */
    const char *authority;
    size_t authority_len;
    const char *method;
    size_t method_len;
    const char *path;
    size_t path_len;
    const char *scheme;
    size_t scheme_len;
    int version;
    h2o_headers_t headers;
    H2O_VECTOR(h2o_buf_t) entity;
    h2o_timestamp_t processed_at;
    /* the response */
    h2o_res_t res;
    size_t bytes_sent;
    /* flags */
    int http1_is_persistent;
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
const h2o_token_t *h2o_lookup_token(const char *name, size_t len);
int h2o_buf_is_token(const h2o_buf_t *buf);

/* memory */

static h2o_buf_t h2o_buf_init(const void *base, size_t len);
static void *h2o_malloc(size_t sz);
static void *h2o_realloc(void *oldp, size_t sz);
void h2o_mempool_init(h2o_mempool_t *pool);
void h2o_mempool_clear(h2o_mempool_t *pool);
void *h2o_mempool_alloc(h2o_mempool_t *pool, size_t sz);
void *h2o_mempool_alloc_shared(h2o_mempool_t *pool, size_t sz);
void h2o_mempool_link_shared(h2o_mempool_t *pool, void *p);
static void h2o_mempool_addref_shared(void *p);
static int h2o_mempool_release_shared(void *p);
h2o_buf_t h2o_allocate_input_buffer(h2o_input_buffer_t **inbuf, size_t initial_size);
void h2o_consume_input_buffer(h2o_input_buffer_t **inbuf, size_t delta);
static void h2o_vector_reserve(h2o_mempool_t *pool, h2o_vector_t *vector, size_t element_size, size_t new_capacity);
void h2o_vector__expand(h2o_mempool_t *pool, h2o_vector_t *vector, size_t element_size, size_t new_capacity);

/* link list */

static void h2o_linklist_init(h2o_linklist_t *link);
static int h2o_linklist_is_linked(h2o_linklist_t *link);
static void h2o_linklist_insert(h2o_linklist_t **head, h2o_linklist_t *pos, h2o_linklist_t *link);
static void h2o_linklist_unlink(h2o_linklist_t **head, h2o_linklist_t *link);
#define h2o_linklist_get_first(type, member, head) ((type*)((char*)head - offsetof(type, member)))
#define h2o_linklist_get_next(type, member, p) ((type*)((char*)(p)->member.next - offsetof(type, member)))
#define h2o_linklist_get_prev(type, member, p) ((type*)((char*)(p)->member.prev - offsetof(type, member)))
void h2o_linklist_merge(h2o_linklist_t *head, h2o_linklist_t **added);

/* socket */

void h2o_socket_close(h2o_socket_t *sock);
void h2o_socket_write(h2o_socket_t *sock, h2o_buf_t *bufs, size_t bufcnt, h2o_socket_cb cb);
void h2o_socket__write_pending(h2o_socket_t *sock);
void h2o_socket__write_on_complete(h2o_socket_t *sock, int status);
void h2o_socket_read_start(h2o_socket_t *sock, h2o_socket_cb cb);
void h2o_socket_read_stop(h2o_socket_t *sock);
static int h2o_socket_is_writing(h2o_socket_t *sock);
static int h2o_socket_is_reading(h2o_socket_t *sock);
int h2o_socket_getpeername(h2o_socket_t *sock, struct sockaddr *name, socklen_t *namelen);
void h2o_socket_ssl_server_handshake(h2o_socket_t *sock, h2o_ssl_context_t *ssl_ctx, h2o_socket_cb handshake_cb);
h2o_buf_t h2o_socket_ssl_get_selected_protocol(h2o_socket_t *sock);
h2o_ssl_context_t *h2o_ssl_new_server_context(const char *cert_file, const char *key_file, const h2o_buf_t *protocols);

/* timeout */

size_t h2o_timeout_run(h2o_timeout_t *timeout, uint64_t now);
size_t h2o_timeout_run_all(h2o_linklist_t *timeouts, uint64_t now);
uint64_t h2o_timeout_get_wake_at(h2o_linklist_t *timeouts);
void h2o_timeout_init(h2o_loop_t *loop, h2o_timeout_t *timeout, uint64_t millis);
void h2o_timeout_link(h2o_loop_t *loop, h2o_timeout_t *timeout, h2o_timeout_entry_t *entry);
void h2o_timeout_unlink(h2o_timeout_t *timeout, h2o_timeout_entry_t *entry);
static int h2o_timeout_is_linked(h2o_timeout_entry_t *entry);
void h2o_timeout__do_init(h2o_loop_t *loop, h2o_timeout_t *timeout);
void h2o_timeout__do_link(h2o_loop_t *loop, h2o_timeout_t *timeout, h2o_timeout_entry_t *entry);

/* headers */

ssize_t h2o_init_headers(h2o_mempool_t *pool, h2o_headers_t *headers, const struct phr_header *src, size_t len, h2o_buf_t *connection, h2o_buf_t *host, h2o_buf_t *upgrade);
ssize_t h2o_find_header(const h2o_headers_t *headers, const h2o_token_t *token, ssize_t cursor);
ssize_t h2o_find_header_by_str(const h2o_headers_t *headers, const char *name, size_t name_len, ssize_t cursor);
void h2o_add_header(h2o_mempool_t *pool, h2o_headers_t *headers, const h2o_token_t *token, const char *value, size_t value_len);
void h2o_add_header_by_str(h2o_mempool_t *pool, h2o_headers_t *headers, const char *name, size_t name_len, int maybe_token, const char *value, size_t value_len);
void h2o_set_header(h2o_mempool_t *pool, h2o_headers_t *headers, const h2o_token_t *token, const char *value, size_t value_len, int overwrite_if_exists);
void h2o_set_header_by_str(h2o_mempool_t *pool, h2o_headers_t *headers, const char *name, size_t name_len, int maybe_token, const char *value, size_t value_len, int overwrite_if_exists);
ssize_t h2o_delete_header(h2o_headers_t *headers, ssize_t cursor);
h2o_buf_t h2o_flatten_headers(h2o_mempool_t *pool, const h2o_headers_t *headers);

/* util */

void h2o_fatal(const char *msg);
static int h2o_tolower(int ch);
static int h2o_memis(const void *target, size_t target_len, const void *test, size_t test_len);
static int h2o_lcstris(const char *target, size_t target_len, const char *test, size_t test_len);
int h2o_lcstris_core(const char *target, const char *test, size_t test_len);
h2o_buf_t h2o_strdup(h2o_mempool_t *pool, const char *s, size_t len);
h2o_buf_t h2o_sprintf(h2o_mempool_t *pool, const char *fmt, ...) __attribute__((format (printf, 2, 3)));
size_t h2o_snprintf(char *buf, size_t bufsz, const char *fmt, ...) __attribute__((format (printf, 3, 4)));
h2o_buf_t h2o_decode_base64url(h2o_mempool_t *pool, const char *src, size_t len);
void h2o_base64_encode(char *dst, const uint8_t *src, size_t len, int url_encoded);
void h2o_time2str_rfc1123(char *buf, time_t time);
void h2o_time2str_log(char *buf, time_t time);
const char *h2o_get_filext(const char *path, size_t len);
const char *h2o_next_token(const char* elements, size_t elements_len, size_t *element_len, const char *cur);
int h2o_contains_token(const char *haysack, size_t haysack_len, const char *needle, size_t needle_len);
h2o_buf_t h2o_normalize_path(h2o_mempool_t *pool, const char *path, size_t len);

/* request */

void h2o_init_request(h2o_req_t *req, h2o_conn_t *conn, h2o_req_t *src);
void h2o_dispose_request(h2o_req_t *req);
void h2o_process_request(h2o_req_t *req);
h2o_generator_t *h2o_start_response(h2o_req_t *req, size_t sz);
h2o_ostream_t *h2o_prepend_output_filter(h2o_req_t *req, size_t sz);

void h2o_send(h2o_req_t *req, h2o_buf_t *bufs, size_t bufcnt, int is_final);
static void h2o_ostream_send_next(h2o_ostream_t *ostr, h2o_req_t *req, h2o_buf_t *bufs, size_t bufcnt, int is_final);
void h2o_schedule_proceed_response(h2o_req_t *req); /* called by buffering output filters to request next content */
static void h2o_proceed_response(h2o_req_t *req);

/* context */

void h2o_context_init(h2o_context_t *context, h2o_loop_t *loop, h2o_req_cb req_cb);
void h2o_context_dispose(h2o_context_t *context);
int h2o_context_run(h2o_context_t *context);

h2o_filter_t *h2o_add_filter(h2o_context_t *context, size_t sz);
h2o_logger_t *h2o_add_logger(h2o_context_t *context, size_t sz);

void h2o_get_timestamp(h2o_context_t *ctx, h2o_mempool_t *pool, h2o_timestamp_t *ts);

void h2o_accept(h2o_context_t *ctx, h2o_socket_t *sock);

/* built-in generators */

void h2o_send_inline(h2o_req_t *req, const char *body, size_t len);
void h2o_send_error(h2o_req_t *req, int status, const char *reason, const char *body);
int h2o_send_file(h2o_req_t *req, int status, const char *reason, const char *path, h2o_buf_t *mime_type);

/* output filters */

void h2o_add_chunked_encoder(h2o_context_t *context); /* added by default */
void h2o_add_reproxy_url(h2o_context_t *context);

/* mime mapper */

void h2o_init_mimemap(h2o_mimemap_t *mimemap, const char *default_type);
void h2o_dispose_mimemap(h2o_mimemap_t *mimemap);
void h2o_define_mimetype(h2o_mimemap_t *mimemap, const char *ext, const char *type);
h2o_buf_t h2o_get_mimetype(h2o_mimemap_t *mimemap, const char *ext);

/* access log */
h2o_logger_t *h2o_add_access_logger(h2o_context_t *context, const char *path);

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
    return h2o_lcstris_core(target, test, test_len);
}

inline void h2o_vector_reserve(h2o_mempool_t *pool, h2o_vector_t *vector, size_t element_size, size_t new_capacity)
{
    if (vector->capacity < new_capacity) {
        h2o_vector__expand(pool, vector, element_size, new_capacity);
    }
}

inline void h2o_linklist_init(h2o_linklist_t *link)
{
    link->next = link->prev = NULL;
}

inline int h2o_linklist_is_linked(h2o_linklist_t *link)
{
    return link->next != NULL;
}

inline void h2o_linklist_insert(h2o_linklist_t **head, h2o_linklist_t *pos, h2o_linklist_t *link)
{
    assert(! h2o_linklist_is_linked(link));

    if (*head == NULL) {
        assert(pos == NULL);
        *head = link;
        link->next = link->prev = link;
    } else {
        assert(pos != NULL);
        link->prev = pos->prev;
        link->next = pos;
        link->prev->next = link;
        link->next->prev = link;
    }
}

inline void h2o_linklist_unlink(h2o_linklist_t **head, h2o_linklist_t *link)
{
    assert(h2o_linklist_is_linked(link));

    if (link->next == link) {
        assert(*head == link);
        *head = NULL;
    } else {
        assert(*head != NULL);
        link->next->prev = link->prev;
        link->prev->next = link->next;
        if (link == *head)
            *head = link->next;
    }
    link->next = link->prev = NULL;
}

inline void h2o_ostream_send_next(h2o_ostream_t *ostr, h2o_req_t *req, h2o_buf_t *bufs, size_t bufcnt, int is_final)
{
    if (is_final) {
        assert(req->_ostr_top == ostr);
        req->_ostr_top = ostr->next;
    }
    ostr->next->do_send(ostr->next, req, bufs, bufcnt, is_final);
}

inline void h2o_proceed_response(h2o_req_t *req)
{
    if (req->_generator != NULL) {
        req->_generator->proceed(req->_generator, req);
    } else {
        req->_ostr_top->do_send(req->_ostr_top, req, NULL, 0, 1);
    }
}

#ifdef __cplusplus
}
#endif

#endif
