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

#include "h2o/header.h"
#include "h2o/socket.h"
#include "h2o/socketpool.h"

typedef struct st_h2o_httpclient_t h2o_httpclient_t;

typedef struct st_h2o_httpclient_properties_t {
    h2o_iovec_t *proxy_protocol;
    int *chunked;
    h2o_iovec_t *connection_header;
} h2o_httpclient_properties_t;

typedef void (*h2o_httpclient_proceed_req_cb)(h2o_httpclient_t *client, size_t written, int is_end_stream);
typedef int (*h2o_httpclient_body_cb)(h2o_httpclient_t *client, const char *errstr);
typedef h2o_httpclient_body_cb (*h2o_httpclient_head_cb)(h2o_httpclient_t *client, const char *errstr, int version, int status,
                                                         h2o_iovec_t msg, h2o_header_t *headers, size_t num_headers,
                                                         int header_requires_dup);
typedef h2o_httpclient_head_cb (*h2o_httpclient_connect_cb)(h2o_httpclient_t *client, const char *errstr, h2o_iovec_t *method,
                                                            h2o_url_t *url, const h2o_header_t **headers, size_t *num_headers,
                                                            h2o_iovec_t *body, h2o_httpclient_proceed_req_cb *proceed_req_cb,
                                                            h2o_httpclient_properties_t *props, h2o_url_t *origin);
typedef int (*h2o_httpclient_informational_cb)(h2o_httpclient_t *client, int version, int status, h2o_iovec_t msg,
                                               h2o_header_t *headers, size_t num_headers);

typedef struct st_h2o_httpclient_connection_pool_t {
    /**
     * used to establish connections and pool those when h1 is used.
     * socketpool is shared among multiple threads while connection pool is dedicated to each thread
     */
    h2o_socketpool_t *socketpool;

    struct {
        h2o_linklist_t conns;
    } http2;

} h2o_httpclient_connection_pool_t;

typedef struct st_h2o_httpclient_ctx_t {
    h2o_loop_t *loop;
    h2o_multithread_receiver_t *getaddr_receiver;
    uint64_t io_timeout;
    uint64_t connect_timeout;
    uint64_t first_byte_timeout;
    uint64_t *websocket_timeout; /* NULL if upgrade to websocket is not allowed */
    uint64_t keepalive_timeout;
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

    /**
     * 1-to-(0|1) relationship; NULL when h3 is not used
     */
    struct st_h2o_http3_ctx_t *http3;

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

void h2o_httpclient_connection_pool_init(h2o_httpclient_connection_pool_t *connpool, h2o_socketpool_t *sockpool);

/**
 * issues a HTTP request using the connection pool. Either H1 or H2 may be used, depending on the given context.
 * TODO: create H1- or H2-specific connect function that works without the connection pool?
 */
void h2o_httpclient_connect(h2o_httpclient_t **client, h2o_mem_pool_t *pool, void *data, h2o_httpclient_ctx_t *ctx,
                            h2o_httpclient_connection_pool_t *connpool, h2o_url_t *target, h2o_httpclient_connect_cb cb);

void h2o_httpclient__h1_on_connect(h2o_httpclient_t *client, h2o_socket_t *sock, h2o_url_t *origin);
extern const size_t h2o_httpclient__h1_size;

void h2o_httpclient__h2_on_connect(h2o_httpclient_t *client, h2o_socket_t *sock, h2o_url_t *origin);
uint32_t h2o_httpclient__h2_get_max_concurrent_streams(h2o_httpclient__h2_conn_t *conn);
extern const size_t h2o_httpclient__h2_size;

#ifdef quicly_h /* create http3client.h? */

#include "h2o/http3_common.h"

void h2o_httpclient_connect_h3(h2o_httpclient_t **_client, h2o_mem_pool_t *pool, void *data, h2o_httpclient_ctx_t *ctx,
                               h2o_url_t *target, h2o_httpclient_connect_cb cb);
void h2o_httpclient_http3_notify_connection_update(h2o_http3_ctx_t *ctx, h2o_http3_conn_t *conn);
extern quicly_stream_open_t h2o_httpclient_http3_on_stream_open;

#endif

#ifdef __cplusplus
}
#endif

#endif
