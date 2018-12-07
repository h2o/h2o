/*
 * Copyright (c) 2014,2015 DeNA Co., Ltd.
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
#ifndef h2o__http2__internal_h
#define h2o__http2__internal_h

#include <assert.h>
#include <stdint.h>
#include "khash.h"
#include "h2o/cache.h"
#include "h2o/http2_casper.h"
#include "h2o/http2_scheduler.h"

typedef struct st_h2o_http2_conn_t h2o_http2_conn_t;
typedef struct st_h2o_http2_stream_t h2o_http2_stream_t;

typedef enum enum_h2o_http2_stream_state_t {
    /**
     * stream in idle state (but registered; i.e. priority stream)
     */
    H2O_HTTP2_STREAM_STATE_IDLE,
    /**
     * receiving headers
     */
    H2O_HTTP2_STREAM_STATE_RECV_HEADERS,
    /**
     * receiving body (or trailers), waiting for the arrival of END_STREAM
     */
    H2O_HTTP2_STREAM_STATE_RECV_BODY,
    /**
     * received request but haven't been assigned a handler
     */
    H2O_HTTP2_STREAM_STATE_REQ_PENDING,
    /**
     * waiting for receiving response headers from the handler
     */
    H2O_HTTP2_STREAM_STATE_SEND_HEADERS,
    /**
     * sending body
     */
    H2O_HTTP2_STREAM_STATE_SEND_BODY,
    /**
     * received EOS from handler but still is sending body to client
     */
    H2O_HTTP2_STREAM_STATE_SEND_BODY_IS_FINAL,
    /**
     * closed
     */
    H2O_HTTP2_STREAM_STATE_END_STREAM
} h2o_http2_stream_state_t;

typedef struct st_h2o_http2_conn_num_streams_t {
    uint32_t open;
    uint32_t half_closed;
    uint32_t send_body;
} h2o_http2_conn_num_streams_t;

struct st_h2o_http2_stream_t {
    uint32_t stream_id;
    h2o_ostream_t _ostr_final;
    h2o_http2_stream_state_t state;
    h2o_http2_window_t output_window;
    struct {
        h2o_http2_window_t window;
        size_t bytes_unnotified;
    } input_window;
    h2o_http2_priority_t received_priority;
    H2O_VECTOR(h2o_iovec_t) _data;
    h2o_ostream_pull_cb _pull_cb;
    h2o_http2_conn_num_streams_t *_num_streams_slot; /* points http2_conn_t::num_streams::* in which the stream is counted */
    h2o_cache_digests_t *cache_digests;
    union {
        struct {
            uint32_t parent_stream_id;
            unsigned promise_sent : 1;
        } push;
        struct {
            unsigned casper_is_ready : 1;
        } pull;
    };

    unsigned blocked_by_server : 1;
    unsigned _conn_stream_in_progress : 1; /* true if the body is streaming */

    /* references governed by connection.c for handling various things */
    struct {
        h2o_linklist_t link;
        h2o_http2_scheduler_openref_t scheduler;
    } _refs;
    h2o_send_state_t send_state; /* steate of the ostream, only used in push mode */

    struct {
        h2o_buffer_t *body; /* NULL unless request body IS expected */
        size_t bytes_received;
    } _req_body;

    /* placed at last since it is large and has it's own ctor */
    h2o_req_t req;
};

KHASH_MAP_INIT_INT64(h2o_http2_stream_t, h2o_http2_stream_t *)

typedef enum enum_h2o_http2_conn_state_t {
    H2O_HTTP2_CONN_STATE_OPEN,        /* accepting new connections */
    H2O_HTTP2_CONN_STATE_HALF_CLOSED, /* no more accepting new streams */
    H2O_HTTP2_CONN_STATE_IS_CLOSING   /* nothing should be sent */
} h2o_http2_conn_state_t;

struct st_h2o_http2_conn_t {
    h2o_conn_t super;
    h2o_socket_t *sock;
    /* settings */
    h2o_http2_settings_t peer_settings;
    /* streams */
    khash_t(h2o_http2_stream_t) * streams;
    struct {
        uint32_t max_open;
        uint32_t max_processed;
    } pull_stream_ids;
    struct {
        uint32_t max_open;
    } push_stream_ids;
    struct {
        h2o_http2_conn_num_streams_t priority;
        h2o_http2_conn_num_streams_t pull;
        h2o_http2_conn_num_streams_t push;
        uint32_t blocked_by_server;
        uint32_t _request_body_in_progress;
    } num_streams;
    /* internal */
    h2o_http2_scheduler_node_t scheduler;
    h2o_http2_conn_state_t state;
    h2o_linklist_t _conns; /* linklist to h2o_context_t::http2._conns */
    ssize_t (*_read_expect)(h2o_http2_conn_t *conn, const uint8_t *src, size_t len, const char **err_desc);
    h2o_buffer_t *_http1_req_input; /* contains data referred to by original request via HTTP/1.1 */
    h2o_hpack_header_table_t _input_header_table;
    h2o_http2_window_t _input_window;
    h2o_hpack_header_table_t _output_header_table;
    h2o_linklist_t _pending_reqs; /* list of h2o_http2_stream_t that contain pending requests */
    h2o_timer_t _timeout_entry;
    h2o_buffer_t *_headers_unparsed; /* for temporary storing HEADERS|CONTINUATION frames without END_HEADERS flag set */
    struct {
        h2o_buffer_t *buf;
        h2o_buffer_t *buf_in_flight;
        h2o_linklist_t streams_to_proceed;
        h2o_timer_t timeout_entry;
        h2o_http2_window_t window;
    } _write;
    h2o_cache_t *push_memo;
    h2o_http2_casper_t *casper;
    struct {
        h2o_linklist_t blocked_streams;
    } early_data;
    h2o_iovec_t *http2_origin_frame;
#define HTTP2_CLOSED_STREAM_PRIORITIES 10
    struct {
        struct {
            h2o_http2_scheduler_openref_t sched_node;
            uint32_t stream_id;
        } streams[HTTP2_CLOSED_STREAM_PRIORITIES]; /* a ring buffer, next_slot points to the next entry */
        size_t next_slot;
    } recently_closed_streams;
};

/* connection */
void h2o_http2_conn_register_stream(h2o_http2_conn_t *conn, h2o_http2_stream_t *stream);
void h2o_http2_conn_unregister_stream(h2o_http2_conn_t *conn, h2o_http2_stream_t *stream);
static h2o_http2_stream_t *h2o_http2_conn_get_stream(h2o_http2_conn_t *conn, uint32_t stream_id);
void h2o_http2_conn_push_path(h2o_http2_conn_t *conn, h2o_iovec_t path, h2o_http2_stream_t *src_stream);
void h2o_http2_conn_request_write(h2o_http2_conn_t *conn);
void h2o_http2_conn_register_for_proceed_callback(h2o_http2_conn_t *conn, h2o_http2_stream_t *stream);
static ssize_t h2o_http2_conn_get_buffer_window(h2o_http2_conn_t *conn);
static void h2o_http2_conn_init_casper(h2o_http2_conn_t *conn, unsigned capacity_bits);
void h2o_http2_conn_register_for_replay(h2o_http2_conn_t *conn, h2o_http2_stream_t *stream);

/* stream */
static int h2o_http2_stream_is_push(uint32_t stream_id);
h2o_http2_stream_t *h2o_http2_stream_open(h2o_http2_conn_t *conn, uint32_t stream_id, h2o_req_t *src_req,
                                          const h2o_http2_priority_t *received_priority);
static void h2o_http2_stream_update_open_slot(h2o_http2_stream_t *stream, h2o_http2_conn_num_streams_t *slot);
static void h2o_http2_stream_set_blocked_by_server(h2o_http2_conn_t *conn, h2o_http2_stream_t *stream, unsigned on);
static void h2o_http2_stream_set_state(h2o_http2_conn_t *conn, h2o_http2_stream_t *stream, h2o_http2_stream_state_t new_state);
static void h2o_http2_stream_prepare_for_request(h2o_http2_conn_t *conn, h2o_http2_stream_t *stream);
void h2o_http2_stream_close(h2o_http2_conn_t *conn, h2o_http2_stream_t *stream);
void h2o_http2_stream_reset(h2o_http2_conn_t *conn, h2o_http2_stream_t *stream);
void h2o_http2_stream_send_pending_data(h2o_http2_conn_t *conn, h2o_http2_stream_t *stream);
static int h2o_http2_stream_has_pending_data(h2o_http2_stream_t *stream);
void h2o_http2_stream_proceed(h2o_http2_conn_t *conn, h2o_http2_stream_t *stream);
static void h2o_http2_stream_send_push_promise(h2o_http2_conn_t *conn, h2o_http2_stream_t *stream);
h2o_http2_debug_state_t *h2o_http2_get_debug_state(h2o_req_t *req, int hpack_enabled);

/* inline definitions */

inline h2o_http2_stream_t *h2o_http2_conn_get_stream(h2o_http2_conn_t *conn, uint32_t stream_id)
{
    khiter_t iter = kh_get(h2o_http2_stream_t, conn->streams, stream_id);
    if (iter != kh_end(conn->streams))
        return kh_val(conn->streams, iter);
    return NULL;
}

inline int h2o_http2_stream_is_push(uint32_t stream_id)
{
    return stream_id % 2 == 0;
}

inline ssize_t h2o_http2_conn_get_buffer_window(h2o_http2_conn_t *conn)
{
    ssize_t ret, winsz;
    size_t capacity, cwnd_left;

    capacity = conn->_write.buf->capacity;
    if ((cwnd_left = h2o_socket_prepare_for_latency_optimized_write(
             conn->sock, &conn->super.ctx->globalconf->http2.latency_optimization)) < capacity) {
        capacity = cwnd_left;
        if (capacity < conn->_write.buf->size)
            return 0;
    }

    ret = capacity - conn->_write.buf->size;
    if (ret < H2O_HTTP2_FRAME_HEADER_SIZE)
        return 0;
    ret -= H2O_HTTP2_FRAME_HEADER_SIZE;
    winsz = h2o_http2_window_get_avail(&conn->_write.window);
    if (winsz < ret)
        ret = winsz;
    return ret;
}

inline void h2o_http2_conn_init_casper(h2o_http2_conn_t *conn, unsigned capacity_bits)
{
    assert(conn->casper == NULL);
    conn->casper = h2o_http2_casper_create(capacity_bits, 6);
}

inline void h2o_http2_stream_update_open_slot(h2o_http2_stream_t *stream, h2o_http2_conn_num_streams_t *slot)
{
    --stream->_num_streams_slot->open;
    ++slot->open;
    stream->_num_streams_slot = slot;
}

inline void h2o_http2_stream_set_blocked_by_server(h2o_http2_conn_t *conn, h2o_http2_stream_t *stream, unsigned on)
{
    if (on) {
        assert(!stream->blocked_by_server);
        stream->blocked_by_server = 1;
        ++conn->num_streams.blocked_by_server;
    } else {
        assert(stream->blocked_by_server);
        stream->blocked_by_server = 0;
        --conn->num_streams.blocked_by_server;
    }
}

inline void h2o_http2_stream_set_state(h2o_http2_conn_t *conn, h2o_http2_stream_t *stream, h2o_http2_stream_state_t new_state)
{
    switch (new_state) {
    case H2O_HTTP2_STREAM_STATE_IDLE:
        assert(!"FIXME");
        break;
    case H2O_HTTP2_STREAM_STATE_RECV_HEADERS:
        assert(stream->state == H2O_HTTP2_STREAM_STATE_IDLE);
        if (h2o_http2_stream_is_push(stream->stream_id))
            h2o_http2_stream_update_open_slot(stream, &conn->num_streams.push);
        else
            h2o_http2_stream_update_open_slot(stream, &conn->num_streams.pull);
        stream->state = new_state;
        stream->req.timestamps.request_begin_at = h2o_gettimeofday(conn->super.ctx->loop);
        break;
    case H2O_HTTP2_STREAM_STATE_RECV_BODY:
        stream->state = new_state;
        stream->req.timestamps.request_body_begin_at = h2o_gettimeofday(conn->super.ctx->loop);
        break;
    case H2O_HTTP2_STREAM_STATE_REQ_PENDING:
        stream->state = new_state;
        break;
    case H2O_HTTP2_STREAM_STATE_SEND_HEADERS:
        assert(stream->state == H2O_HTTP2_STREAM_STATE_REQ_PENDING);
        ++stream->_num_streams_slot->half_closed;
        stream->state = new_state;
        break;
    case H2O_HTTP2_STREAM_STATE_SEND_BODY:
        assert(stream->state == H2O_HTTP2_STREAM_STATE_SEND_HEADERS);
        stream->state = new_state;
        ++stream->_num_streams_slot->send_body;
        break;
    case H2O_HTTP2_STREAM_STATE_SEND_BODY_IS_FINAL:
        assert(stream->state == H2O_HTTP2_STREAM_STATE_SEND_BODY);
        stream->state = new_state;
        break;
    case H2O_HTTP2_STREAM_STATE_END_STREAM:
        switch (stream->state) {
        case H2O_HTTP2_STREAM_STATE_IDLE:
        case H2O_HTTP2_STREAM_STATE_RECV_BODY:
        case H2O_HTTP2_STREAM_STATE_RECV_HEADERS:
            break;
        case H2O_HTTP2_STREAM_STATE_REQ_PENDING:
            break;
        case H2O_HTTP2_STREAM_STATE_SEND_HEADERS:
            --stream->_num_streams_slot->half_closed;
            break;
        case H2O_HTTP2_STREAM_STATE_SEND_BODY:
        case H2O_HTTP2_STREAM_STATE_SEND_BODY_IS_FINAL:
            --stream->_num_streams_slot->half_closed;
            --stream->_num_streams_slot->send_body;
            break;
        case H2O_HTTP2_STREAM_STATE_END_STREAM:
            assert(!"FIXME");
            break;
        }
        stream->state = new_state;
        stream->req.timestamps.response_end_at = h2o_gettimeofday(conn->super.ctx->loop);
        --stream->_num_streams_slot->open;
        stream->_num_streams_slot = NULL;
        if (stream->blocked_by_server)
            h2o_http2_stream_set_blocked_by_server(conn, stream, 0);
        break;
    }
}

inline void h2o_http2_stream_prepare_for_request(h2o_http2_conn_t *conn, h2o_http2_stream_t *stream)
{
    assert(conn->state != H2O_HTTP2_CONN_STATE_IS_CLOSING);
    assert(h2o_http2_scheduler_is_open(&stream->_refs.scheduler));

    /* adjust max-open */
    uint32_t *max_open = NULL;
    if (h2o_http2_stream_is_push(stream->stream_id)) {
        max_open = &conn->push_stream_ids.max_open;
    } else if (conn->state == H2O_HTTP2_CONN_STATE_OPEN) {
        max_open = &conn->pull_stream_ids.max_open;
    }
    if (max_open != NULL && *max_open < stream->stream_id)
        *max_open = stream->stream_id;

    h2o_http2_stream_set_state(conn, stream, H2O_HTTP2_STREAM_STATE_RECV_HEADERS);
    h2o_http2_window_init(&stream->output_window, conn->peer_settings.initial_window_size);
}

inline int h2o_http2_stream_has_pending_data(h2o_http2_stream_t *stream)
{
    return stream->_data.size != 0;
}

inline void h2o_http2_stream_send_push_promise(h2o_http2_conn_t *conn, h2o_http2_stream_t *stream)
{
    assert(!stream->push.promise_sent);
    h2o_hpack_flatten_push_promise(&conn->_write.buf, &conn->_output_header_table, stream->stream_id,
                                   conn->peer_settings.max_frame_size, stream->req.input.scheme, stream->req.input.authority,
                                   stream->req.input.method, stream->req.input.path, stream->req.headers.entries,
                                   stream->req.headers.size, stream->push.parent_stream_id);
    stream->push.promise_sent = 1;
}

#endif
