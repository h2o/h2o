/*
 * Copyright (c) 2017 Ichito Nagata, Fastly, Inc.
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
#ifndef h2o__httpclient_h
#define h2o__httpclient_h

#ifdef __cplusplus
extern "C" {
#endif

#include "quicly.h"
#include "h2o/header.h"
#include "h2o/send_state.h"
#include "h2o/socket.h"
#include "h2o/socketpool.h"

typedef struct st_h2o_httpclient_t h2o_httpclient_t;

/**
 * Additional properties related to the HTTP request being issued.
 * When the connect callback is being called, the properties of the objects are set to their initial values. Applications MAY alter
 * the properties to achieve desirable behavior. The reason we require the protocol stacks to initialize the values to their default
 * values instead of requiring applications to set all the values correctly is to avoid requiring applications making changes
 * every time a new field is added to the object.
 */
typedef struct st_h2o_httpclient_properties_t {
    /**
     * When the value is a non-NULL pointer (at the moment, only happens with the HTTP/1 client), the application MAY set it to an
     * iovec pointing to the payload of the PROXY protocol (i.e., the first line).
     */
    h2o_iovec_t *proxy_protocol;
    /**
     * When the value is a non-NULL pointer (at the moment, only happens with the HTTP/1 client), the application MAY set it to 1 to
     * indicate that the request body should be encoded using the chunked transfer-encoding.
     */
    int *chunked;
    /**
     * When the value is a non-NULL pointer (at the moment, only happens with the HTTP/1 client), the application MAY set it to the
     * value of the connection header field to be sent to the server. This can be used for upgrading an HTTP/1.1 connection.
     */
    h2o_iovec_t *connection_header;
} h2o_httpclient_properties_t;

typedef void (*h2o_httpclient_proceed_req_cb)(h2o_httpclient_t *client, size_t written, h2o_send_state_t send_state);
typedef int (*h2o_httpclient_body_cb)(h2o_httpclient_t *client, const char *errstr);
typedef h2o_httpclient_body_cb (*h2o_httpclient_head_cb)(h2o_httpclient_t *client, const char *errstr, int version, int status,
                                                         h2o_iovec_t msg, h2o_header_t *headers, size_t num_headers,
                                                         int header_requires_dup);
/**
 * Called when the protocol stack is ready to issue a request. Application must set all the output parameters (i.e. all except
 * `client`, `errstr`, `origin`) and return a callback that will be called when the protocol stack receives the response headers
 * from the server.
 */
typedef h2o_httpclient_head_cb (*h2o_httpclient_connect_cb)(h2o_httpclient_t *client, const char *errstr, h2o_iovec_t *method,
                                                            h2o_url_t *url, const h2o_header_t **headers, size_t *num_headers,
                                                            h2o_iovec_t *body, h2o_httpclient_proceed_req_cb *proceed_req_cb,
                                                            h2o_httpclient_properties_t *props, h2o_url_t *origin);
typedef int (*h2o_httpclient_informational_cb)(h2o_httpclient_t *client, int version, int status, h2o_iovec_t msg,
                                               h2o_header_t *headers, size_t num_headers);

typedef void (*h2o_httpclient_finish_cb)(h2o_httpclient_t *client);

typedef struct st_h2o_httpclient_connection_pool_t {
    /**
     * used to establish connections and pool those when h1 is used.
     * socketpool is shared among multiple threads while connection pool is dedicated to each thread
     */
    h2o_socketpool_t *socketpool;

    struct {
        h2o_linklist_t conns;
    } http2;

    /**
     * static connection pools have zero refcnt.
     * dynamic allocated connection pools have nonzero refcnt.
     */
    int refcnt;
} h2o_httpclient_connection_pool_t;

typedef struct st_h2o_httpclient_ctx_t {
    h2o_loop_t *loop;
    h2o_multithread_receiver_t *getaddr_receiver;
    uint64_t io_timeout;
    uint64_t connect_timeout;
    uint64_t first_byte_timeout;
    uint64_t *websocket_timeout; /* NULL if upgrade to websocket is not allowed */
    uint64_t keepalive_timeout;  /* only used for http2 for now */
    size_t max_buffer_size;

    struct {
        h2o_socket_latency_optimization_conditions_t latency_optimization;
        uint32_t max_concurrent_streams;
        /**
         * ratio of requests to use HTTP/2; between 0 to 100
         */
        int8_t ratio;
        int8_t counter; /* default is -1. then it'll be initialized by 50 / ratio */
    } http2;

    struct {
        /**
         * 1-to-(0|1) relationship; NULL when h3 is not used
         */
        struct st_h2o_quic_ctx_t *ctx;
        /**
         * Optional callback invoked by the HTTP/3 client implementation to obtain information used for resuming a connection. When
         * the connection is to be resumed, the callback should set `*address_token` and `*session_ticket` to a vector that can be
         * freed by calling free (3), as well as writing the resumed transport parameters to `*resumed_tp`. Otherwise,
         * `*address_token`, `*session_ticket`, `*resumed_tp` can be left untouched, and a full handshake will be exercised. The
         * function returns if the operation was successful. When false is returned, the connection attempt is aborted.
         */
        int (*load_session)(struct st_h2o_httpclient_ctx_t *ctx, struct sockaddr *server_addr, const char *server_name,
                            ptls_iovec_t *address_token, ptls_iovec_t *session_ticket, quicly_transport_parameters_t *resumed_tp);
    } http3;

} h2o_httpclient_ctx_t;

typedef struct st_h2o_httpclient_timings_t {
    struct timeval start_at;
    struct timeval request_begin_at;
    struct timeval request_end_at;
    struct timeval response_start_at;
    struct timeval response_end_at;
} h2o_httpclient_timings_t;

struct st_h2o_httpclient_t {
    /**
     * memory pool
     */
    h2o_mem_pool_t *pool;
    /**
     * context
     */
    h2o_httpclient_ctx_t *ctx;
    /**
     * connection pool
     */
    h2o_httpclient_connection_pool_t *connpool;
    /**
     * buffer in which response data is stored (see update_window)
     */
    h2o_buffer_t **buf;
    /**
     * application data pointer
     */
    void *data;
    /**
     * optional callback to receive informational response(s)
     */
    h2o_httpclient_informational_cb informational_cb;
    /**
     * server-timing data
     */
    h2o_httpclient_timings_t timings;

    /**
     * bytes written (above the TLS layer)
     */
    struct {
        uint64_t header;
        uint64_t body;
        uint64_t total;
    } bytes_written;

    /**
     * bytes read (above the TLS layer)
     */
    struct {
        uint64_t header;
        uint64_t body;
        uint64_t total;
    } bytes_read;

    /**
     * cancels a in-flight request
     */
    void (*cancel)(h2o_httpclient_t *client);
    /**
     * optional function that lets the application steal the socket (for HTTP/1.1.-style upgrade)
     */
    h2o_socket_t *(*steal_socket)(h2o_httpclient_t *client);
    /**
     * returns a pointer to the underlying h2o_socket_t
     */
    h2o_socket_t *(*get_socket)(h2o_httpclient_t *client);
    /**
     * callback that should be called when some data is fetched out from `buf`.
     */
    void (*update_window)(h2o_httpclient_t *client);
    /**
     * function for writing request body. `proceed_req_cb` supplied through the `on_connect` callback will be called when the
     * given data is sent to the server.
     */
    int (*write_req)(h2o_httpclient_t *client, h2o_iovec_t chunk, int is_end_stream);

    h2o_timer_t _timeout;
    h2o_socketpool_connect_request_t *_connect_req;
    union {
        h2o_httpclient_connect_cb on_connect;
        h2o_httpclient_head_cb on_head;
        h2o_httpclient_body_cb on_body;
    } _cb;
};

/**
 * public members of h2 client connection
 */
typedef struct st_h2o_httpclient__h2_conn_t {
    /**
     * context
     */
    h2o_httpclient_ctx_t *ctx;
    /**
     * origin server (path is ignored)
     */
    h2o_url_t origin_url;
    /**
     * underlying socket
     */
    h2o_socket_t *sock;
    /**
     * number of open streams (FIXME can't we refer to khash?)
     */
    size_t num_streams;
    /**
     * linklist of connections anchored to h2o_httpclient_connection_pool_t::http2.conns. The link is in the ascending order of
     * `num_streams`.
     */
    h2o_linklist_t link;
} h2o_httpclient__h2_conn_t;

extern const char h2o_httpclient_error_is_eos[];
extern const char h2o_httpclient_error_refused_stream[];
extern const char h2o_httpclient_error_unknown_alpn_protocol[];
extern const char h2o_httpclient_error_io[];
extern const char h2o_httpclient_error_connect_timeout[];
extern const char h2o_httpclient_error_first_byte_timeout[];
extern const char h2o_httpclient_error_io_timeout[];
extern const char h2o_httpclient_error_invalid_content_length[];
extern const char h2o_httpclient_error_flow_control[];
extern const char h2o_httpclient_error_http1_line_folding[];
extern const char h2o_httpclient_error_http1_unexpected_transfer_encoding[];
extern const char h2o_httpclient_error_http1_parse_failed[];
extern const char h2o_httpclient_error_http2_protocol_violation[];
extern const char h2o_httpclient_error_internal[];

void h2o_httpclient_connection_pool_init(h2o_httpclient_connection_pool_t *connpool, h2o_socketpool_t *sockpool);
h2o_httpclient_connection_pool_t *h2o_httpclient_connection_pool_create(h2o_socketpool_t *sockpool);
void h2o_httpclient_connection_pool_dispose(h2o_httpclient_connection_pool_t *connpool);

/**
 * issues a HTTP request using the connection pool. Either H1 or H2 may be used, depending on the given context.
 * TODO: create H1- or H2-specific connect function that works without the connection pool?
 */
void h2o_httpclient_connect(h2o_httpclient_t **client, h2o_mem_pool_t *pool, void *data, h2o_httpclient_ctx_t *ctx,
                            h2o_httpclient_connection_pool_t *connpool, h2o_url_t *target, h2o_httpclient_connect_cb on_connect);

void h2o_httpclient__h1_on_connect(h2o_httpclient_t *client, h2o_socket_t *sock, h2o_url_t *origin);
extern const size_t h2o_httpclient__h1_size;

void h2o_httpclient__h2_on_connect(h2o_httpclient_t *client, h2o_socket_t *sock, h2o_url_t *origin);
uint32_t h2o_httpclient__h2_get_max_concurrent_streams(h2o_httpclient__h2_conn_t *conn);
void h2o_httpclient__trigger_keepalive_timeout(h2o_httpclient__h2_conn_t *conn);
extern const size_t h2o_httpclient__h2_size;

h2o_httpclient_connection_pool_t *h2o_httpclient_connpool_create(void);
void h2o_httpclient_connpool_dispose(h2o_httpclient_connection_pool_t *);
    
#ifdef quicly_h /* create http3client.h? */

#include "h2o/http3_common.h"

void h2o_httpclient_connect_h3(h2o_httpclient_t **_client, h2o_mem_pool_t *pool, void *data, h2o_httpclient_ctx_t *ctx,
                               h2o_url_t *target, h2o_httpclient_connect_cb cb);
void h2o_httpclient_http3_notify_connection_update(h2o_quic_ctx_t *ctx, h2o_quic_conn_t *conn);
extern quicly_stream_open_t h2o_httpclient_http3_on_stream_open;

#endif

#ifdef __cplusplus
}
#endif

#endif
