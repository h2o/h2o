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
#ifndef h2o__http1client_h
#define h2o__http1client_h

#ifdef __cplusplus
extern "C" {
#endif

#include "h2o/memory.h"
#include "h2o/socket.h"
#include "h2o/socketpool.h"
#include "h2o/timeout.h"

typedef struct st_h2o_httpclient_t h2o_httpclient_t;

typedef struct st_h2o_httpclient_features_t {
    h2o_iovec_t *proxy_protocol;
    int *chunked;
    int connection_header;
} h2o_httpclient_features_t;

struct st_h2o_header_t;

typedef void (*h2o_httpclient_proceed_req_cb)(h2o_httpclient_t *client, size_t written, int is_end_stream);
typedef int (*h2o_httpclient_body_cb)(h2o_httpclient_t *client, const char *errstr);
typedef h2o_httpclient_body_cb (*h2o_httpclient_head_cb)(h2o_httpclient_t *client, const char *errstr, int minor_version,
                                                           int status, h2o_iovec_t msg, struct st_h2o_header_t *headers,
                                                           size_t num_headers, int rlen);
typedef h2o_httpclient_head_cb (*h2o_httpclient_connect_cb)(h2o_httpclient_t *client, const char *errstr, h2o_iovec_t *method, h2o_url_t *url,
                                                              h2o_headers_t *headers, h2o_iovec_t *body,
                                                              h2o_httpclient_proceed_req_cb *proceed_req_cb, h2o_httpclient_features_t features, h2o_url_t *origin);
typedef int (*h2o_http1client_informational_cb)(h2o_httpclient_t *client, int minor_version, int status, h2o_iovec_t msg,
                                                struct st_h2o_header_t *headers, size_t num_headers);

typedef struct st_h2o_httpclient_ctx_t {
    h2o_loop_t *loop;
    h2o_multithread_receiver_t *getaddr_receiver;
    h2o_timeout_t *io_timeout;
    h2o_timeout_t *connect_timeout;
    h2o_timeout_t *first_byte_timeout;
    h2o_timeout_t *websocket_timeout; /* NULL if upgrade to websocket is not allowed */
    h2o_timeout_t *zero_timeout;

    struct {
        h2o_socket_latency_optimization_conditions_t latency_optimization;
        h2o_linklist_t conns;
        h2o_timeout_t *keepalive_timeout;
    } http2;

} h2o_httpclient_ctx_t;

struct st_h2o_httpclient_t {
    h2o_httpclient_ctx_t *ctx;
    struct {
        h2o_socketpool_t *pool;
        h2o_socketpool_connect_request_t *connect_req;
    } sockpool;
    h2o_buffer_t **buf;
    void *data;
    h2o_http1client_informational_cb informational_cb;

    void (*cancel)(h2o_httpclient_t *client);
    h2o_socket_t *(*steal_socket)(h2o_httpclient_t *client);
    void (*stop_read)(h2o_httpclient_t *client);
    void (*resume_read)(h2o_httpclient_t *client);
    int (*write_req)(h2o_httpclient_t *client, h2o_iovec_t chunk, int is_end_stream);
};

extern const char *const h2o_httpclient_error_is_eos;

/**
 * connects to a HTTP/1.1 server
 * @param client
 * @param data
 * @param ctx
 * @param socketpool
 * @param target URL of the target to connect to (or NULL if relying on a non-global socket pool to connect and supply SNI value)
 * @param is_chunked
 * @param cb
 */
void h2o_http1client_connect(h2o_httpclient_t **client, void *data, h2o_httpclient_ctx_t *ctx, h2o_socketpool_t *socketpool,
                             h2o_url_t *target, h2o_httpclient_connect_cb cb);

#ifdef __cplusplus
}
#endif

#endif
