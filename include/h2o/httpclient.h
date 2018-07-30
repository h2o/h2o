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
#include "h2o/timeout.h"

typedef struct st_h2o_httpclient_t h2o_httpclient_t;

typedef struct st_h2o_httpclient_properties_t {
    h2o_iovec_t *proxy_protocol;
    int *chunked;
    h2o_iovec_t *connection_header;
} h2o_httpclient_properties_t;

typedef void (*h2o_httpclient_proceed_req_cb)(h2o_httpclient_t *client, size_t written, int is_end_stream);
typedef int (*h2o_httpclient_body_cb)(h2o_httpclient_t *client, const char *errstr);
typedef h2o_httpclient_body_cb (*h2o_httpclient_head_cb)(h2o_httpclient_t *client, const char *errstr, int minor_version,
                                                           int status, h2o_iovec_t msg, h2o_header_t *headers,
                                                           size_t num_headers, int rlen, int header_requires_dup);
typedef h2o_httpclient_head_cb (*h2o_httpclient_connect_cb)(h2o_httpclient_t *client, const char *errstr, h2o_iovec_t *method, h2o_url_t *url,
                                                              const h2o_header_t **headers, size_t *num_headers, h2o_iovec_t *body,
                                                              h2o_httpclient_proceed_req_cb *proceed_req_cb, h2o_httpclient_properties_t *props, h2o_url_t *origin);
typedef int (*h2o_httpclient_informational_cb)(h2o_httpclient_t *client, int minor_version, int status, h2o_iovec_t msg,
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
    h2o_timeout_t *io_timeout;
    h2o_timeout_t *connect_timeout;
    h2o_timeout_t *first_byte_timeout;
    h2o_timeout_t *websocket_timeout; /* NULL if upgrade to websocket is not allowed */
    h2o_timeout_t *keepalive_timeout;
    h2o_timeout_t *zero_timeout;
    size_t max_buffer_size;

    struct {
        h2o_socket_latency_optimization_conditions_t latency_optimization;
        uint32_t max_concurrent_streams;

        /* for weighted fair queueing */
        int8_t ratio;
        int8_t counter; /* default is -1. then it'll be initialized by 50 / ratio */
    } http2;

} h2o_httpclient_ctx_t;

struct st_h2o_httpclient_t {
    h2o_mem_pool_t *pool;
    h2o_httpclient_ctx_t *ctx;
    h2o_httpclient_connection_pool_t *connpool;
    h2o_buffer_t **buf;
    void *data;
    h2o_httpclient_informational_cb informational_cb;

    void (*cancel)(h2o_httpclient_t *client);
    h2o_socket_t *(*steal_socket)(h2o_httpclient_t *client);
    void (*update_window)(h2o_httpclient_t *client);
    int (*write_req)(h2o_httpclient_t *client, h2o_iovec_t chunk, int is_end_stream);
};

extern const char *const h2o_httpclient_error_is_eos;
extern const char *const h2o_httpclient_error_refused_stream;


void h2o_httpclient_connection_pool_init(h2o_httpclient_connection_pool_t *connpool, h2o_socketpool_t *sockpool);

void h2o_httpclient_connect(h2o_httpclient_t **_client, h2o_mem_pool_t *pool, void *data, h2o_httpclient_ctx_t *ctx, h2o_httpclient_connection_pool_t *connpool,
                            h2o_url_t *target, h2o_httpclient_connect_cb cb);

#ifdef __cplusplus
}
#endif

#endif
