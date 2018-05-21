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
#ifndef h2o__http2client_h
#define h2o__http2client_h

#ifdef __cplusplus
extern "C" {
#endif

#include "khash.h"
#include "h2o/http2_common.h"

enum enum_h2o_http2client_stream_state {
    H2O_HTTP2CLIENT_STREAM_STATE_SEND_HEADERS,
    H2O_HTTP2CLIENT_STREAM_STATE_SEND_BODY,
    H2O_HTTP2CLIENT_STREAM_STATE_RECV_HEADERS,
    H2O_HTTP2CLIENT_STREAM_STATE_RECV_BODY,
};

enum enum_h2o_http2client_conn_state {
    H2O_HTTP2CLIENT_CONN_STATE_OPEN,
    H2O_HTTP2CLIENT_CONN_STATE_HALF_CLOSED,
    H2O_HTTP2CLIENT_CONN_STATE_IS_CLOSING,
};

struct st_h2o_http2client_stream_t;
KHASH_MAP_INIT_INT64(stream, struct st_h2o_http2client_stream_t *)

struct st_h2o_http2client_conn_t {
    h2o_httpclient_ctx_t *ctx;
    h2o_url_t origin_url;
    h2o_socket_t *sock;
    enum enum_h2o_http2client_conn_state state;
    khash_t(stream) * streams;
    h2o_linklist_t link;
    h2o_http2_settings_t peer_settings;
    uint32_t max_open_stream_id;
    size_t num_streams;
    h2o_timeout_entry_t io_timeout_entry;
    h2o_timeout_entry_t keepalive_timeout_entry;

    struct {
        h2o_hpack_header_table_t header_table;
        h2o_http2_window_t window;
        h2o_buffer_t *buf;
        h2o_buffer_t *buf_in_flight;
        h2o_timeout_entry_t defer_timeout_entry;
        h2o_linklist_t sending_streams;
        h2o_linklist_t sent_streams;
    } output;

    struct {
        h2o_hpack_header_table_t header_table;
        h2o_http2_window_t window;
        ssize_t (*read_frame)(struct st_h2o_http2client_conn_t *conn, const uint8_t *src, size_t len, const char **err_desc);
        h2o_buffer_t *headers_unparsed;
    } input;
};

struct st_h2o_http2client_stream_t {
    struct st_h2o_httpclient_private_t super;
    struct st_h2o_http2client_conn_t *conn;
    uint32_t stream_id;
    enum enum_h2o_http2client_stream_state state;
    h2o_timeout_entry_t timeout_entry;

    struct {
        h2o_http2_window_t window;
        H2O_VECTOR(h2o_iovec_t) data;
        h2o_linklist_t sending_link;
    } output;

    struct {
        h2o_http2_window_t window;
        int status;
        h2o_headers_t headers;
        h2o_buffer_t *body;
    } input;

    struct {
        h2o_httpclient_proceed_req_cb proceed_req;
        size_t bytes_in_flight;
        unsigned char done : 1;
    } streaming;

    h2o_mem_pool_t pool;
};

void h2o_http2client_on_connect(struct st_h2o_httpclient_private_t *client, h2o_socket_t *sock, h2o_url_t *origin);

uint32_t h2o_http2client_get_max_concurrent_streams(struct st_h2o_http2client_conn_t *conn);

#ifdef __cplusplus
}
#endif

#endif
