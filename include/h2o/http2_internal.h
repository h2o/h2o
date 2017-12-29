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
#include "h2o/cache_digests.h"
#include "h2o/http2_scheduler.h"

typedef struct st_h2o_http2_conn_t h2o_http2_conn_t;
typedef struct st_h2o_http2_stream_t h2o_http2_stream_t;

/* connection flow control window + alpha */
#define H2O_HTTP2_DEFAULT_OUTBUF_SIZE 81920

/* hpack */

#define H2O_HTTP2_ENCODE_INT_MAX_LENGTH 5

typedef struct st_h2o_hpack_header_table_t {
    /* ring buffer */
    struct st_h2o_hpack_header_table_entry_t *entries;
    size_t num_entries, entry_capacity, entry_start_index;
    /* size and capacities are 32+name_len+value_len (as defined by hpack spec.) */
    size_t hpack_size;
    size_t hpack_capacity;     /* the value set by SETTINGS_HEADER_TABLE_SIZE _and_ dynamic table size update */
    size_t hpack_max_capacity; /* the value set by SETTINGS_HEADER_TABLE_SIZE */
} h2o_hpack_header_table_t;

typedef struct st_h2o_hpack_header_table_entry_t {
    h2o_iovec_t *name;
    h2o_iovec_t *value;
    const char *err_desc; /* the recorded soft error description */
} h2o_hpack_header_table_entry_t;

#define H2O_HPACK_PARSE_HEADERS_METHOD_EXISTS 1
#define H2O_HPACK_PARSE_HEADERS_SCHEME_EXISTS 2
#define H2O_HPACK_PARSE_HEADERS_PATH_EXISTS 4
#define H2O_HPACK_PARSE_HEADERS_AUTHORITY_EXISTS 8

void h2o_hpack_dispose_header_table(h2o_hpack_header_table_t *header_table);
int h2o_hpack_parse_headers(h2o_req_t *req, h2o_hpack_header_table_t *header_table, const uint8_t *src, size_t len,
                            int *pseudo_header_exists_map, size_t *content_length, h2o_cache_digests_t **digests,
                            const char **err_desc);
size_t h2o_hpack_encode_string(uint8_t *dst, const char *s, size_t len);
void h2o_hpack_flatten_request(h2o_buffer_t **buf, h2o_hpack_header_table_t *header_table, uint32_t stream_id,
                               size_t max_frame_size, h2o_req_t *req, uint32_t parent_stream_id);
void h2o_hpack_flatten_response(h2o_buffer_t **buf, h2o_hpack_header_table_t *header_table, uint32_t stream_id,
                                size_t max_frame_size, h2o_res_t *res, h2o_timestamp_t *ts, const h2o_iovec_t *server_name,
                                size_t content_length);
static h2o_hpack_header_table_entry_t *h2o_hpack_header_table_get(h2o_hpack_header_table_t *table, size_t index);

/* frames */

#define H2O_HTTP2_FRAME_HEADER_SIZE 9

#define H2O_HTTP2_FRAME_TYPE_DATA 0
#define H2O_HTTP2_FRAME_TYPE_HEADERS 1
#define H2O_HTTP2_FRAME_TYPE_PRIORITY 2
#define H2O_HTTP2_FRAME_TYPE_RST_STREAM 3
#define H2O_HTTP2_FRAME_TYPE_SETTINGS 4
#define H2O_HTTP2_FRAME_TYPE_PUSH_PROMISE 5
#define H2O_HTTP2_FRAME_TYPE_PING 6
#define H2O_HTTP2_FRAME_TYPE_GOAWAY 7
#define H2O_HTTP2_FRAME_TYPE_WINDOW_UPDATE 8
#define H2O_HTTP2_FRAME_TYPE_CONTINUATION 9

#define H2O_HTTP2_FRAME_FLAG_END_STREAM 0x1
#define H2O_HTTP2_FRAME_FLAG_ACK 0x1
#define H2O_HTTP2_FRAME_FLAG_END_HEADERS 0x4
#define H2O_HTTP2_FRAME_FLAG_PADDED 0x8
#define H2O_HTTP2_FRAME_FLAG_PRIORITY 0x20

typedef struct st_h2o_http2_frame_t {
    uint32_t length;
    uint8_t type;
    uint8_t flags;
    uint32_t stream_id;
    const uint8_t *payload;
} h2o_http2_frame_t;

typedef struct st_h2o_http2_data_payload_t {
    const uint8_t *data;
    size_t length;
} h2o_http2_data_payload_t;

typedef struct st_h2o_http2_headers_payload_t {
    h2o_http2_priority_t priority;
    const uint8_t *headers;
    size_t headers_len;
} h2o_http2_headers_payload_t;

typedef struct st_h2o_http2_rst_stream_payload_t {
    uint32_t error_code;
} h2o_http2_rst_stream_payload_t;

typedef struct st_h2o_http2_ping_payload_t {
    uint8_t data[8];
} h2o_http2_ping_payload_t;

typedef struct st_h2o_http2_goaway_payload_t {
    uint32_t last_stream_id;
    uint32_t error_code;
    h2o_iovec_t debug_data;
} h2o_http2_goaway_payload_t;

typedef struct st_h2o_http2_window_update_payload_t {
    uint32_t window_size_increment;
} h2o_http2_window_update_payload_t;

typedef struct st_h2o_http2_window_t {
    ssize_t _avail;
} h2o_http2_window_t;

typedef enum enum_h2o_http2_stream_state_t {
    H2O_HTTP2_STREAM_STATE_IDLE,
    H2O_HTTP2_STREAM_STATE_RECV_HEADERS,
    H2O_HTTP2_STREAM_STATE_RECV_BODY,
    H2O_HTTP2_STREAM_STATE_REQ_PENDING,
    H2O_HTTP2_STREAM_STATE_SEND_HEADERS,
    H2O_HTTP2_STREAM_STATE_SEND_BODY,
    H2O_HTTP2_STREAM_STATE_SEND_BODY_IS_FINAL,
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
    h2o_http2_window_t input_window;
    h2o_http2_priority_t received_priority;
    h2o_buffer_t *_req_body;         /* NULL unless request body IS expected */
    size_t _expected_content_length; /* SIZE_MAX if unknown */
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
    /* references governed by connection.c for handling various things */
    struct {
        h2o_linklist_t link;
        h2o_http2_scheduler_openref_t scheduler;
    } _refs;
    h2o_send_state_t send_state; /* state of the ostream, only used in push mode */
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
    h2o_timeout_entry_t _timeout_entry;
    h2o_buffer_t *_headers_unparsed; /* for temporary storing HEADERS|CONTINUATION frames without END_HEADERS flag set */
    struct {
        h2o_buffer_t *buf;
        h2o_buffer_t *buf_in_flight;
        h2o_linklist_t streams_to_proceed;
        h2o_timeout_entry_t timeout_entry;
        h2o_http2_window_t window;
    } _write;
    h2o_cache_t *push_memo;
    h2o_http2_casper_t *casper;
};

int h2o_http2_update_peer_settings(h2o_http2_settings_t *settings, const uint8_t *src, size_t len, const char **err_desc);

/* frames */
uint8_t *h2o_http2_encode_frame_header(uint8_t *dst, size_t length, uint8_t type, uint8_t flags, int32_t stream_id);

#define h2o_http2_encode_rst_stream_frame(buf, stream_id, errnum)                                                                  \
    h2o_http2__encode_rst_stream_frame(buf, stream_id, (H2O_BUILD_ASSERT((errnum) > 0), errnum))

void h2o_http2__encode_rst_stream_frame(h2o_buffer_t **buf, uint32_t stream_id, int errnum);
void h2o_http2_encode_ping_frame(h2o_buffer_t **buf, int is_ack, const uint8_t *data);
void h2o_http2_encode_goaway_frame(h2o_buffer_t **buf, uint32_t last_stream_id, int errnum, h2o_iovec_t additional_data);
void h2o_http2_encode_window_update_frame(h2o_buffer_t **buf, uint32_t stream_id, int32_t window_size_increment);
ssize_t h2o_http2_decode_frame(h2o_http2_frame_t *frame, const uint8_t *src, size_t len, const h2o_http2_settings_t *host_settings,
                               const char **err_desc);
int h2o_http2_decode_data_payload(h2o_http2_data_payload_t *payload, const h2o_http2_frame_t *frame, const char **err_desc);
int h2o_http2_decode_headers_payload(h2o_http2_headers_payload_t *payload, const h2o_http2_frame_t *frame, const char **err_desc);
int h2o_http2_decode_priority_payload(h2o_http2_priority_t *payload, const h2o_http2_frame_t *frame, const char **err_desc);
int h2o_http2_decode_rst_stream_payload(h2o_http2_rst_stream_payload_t *payload, const h2o_http2_frame_t *frame,
                                        const char **err_desc);
int h2o_http2_decode_ping_payload(h2o_http2_ping_payload_t *payload, const h2o_http2_frame_t *frame, const char **err_desc);
int h2o_http2_decode_goaway_payload(h2o_http2_goaway_payload_t *payload, const h2o_http2_frame_t *frame, const char **err_desc);
int h2o_http2_decode_window_update_payload(h2o_http2_window_update_payload_t *paylaod, const h2o_http2_frame_t *frame,
                                           const char **err_desc, int *err_is_stream_level);

/* connection */
void h2o_http2_conn_register_stream(h2o_http2_conn_t *conn, h2o_http2_stream_t *stream);
void h2o_http2_conn_unregister_stream(h2o_http2_conn_t *conn, h2o_http2_stream_t *stream);
static h2o_http2_stream_t *h2o_http2_conn_get_stream(h2o_http2_conn_t *conn, uint32_t stream_id);
void h2o_http2_conn_push_path(h2o_http2_conn_t *conn, h2o_iovec_t path, h2o_http2_stream_t *src_stream);
void h2o_http2_conn_request_write(h2o_http2_conn_t *conn);
void h2o_http2_conn_register_for_proceed_callback(h2o_http2_conn_t *conn, h2o_http2_stream_t *stream);
static ssize_t h2o_http2_conn_get_buffer_window(h2o_http2_conn_t *conn);
static void h2o_http2_conn_init_casper(h2o_http2_conn_t *conn, unsigned capacity_bits);

/* stream */
static int h2o_http2_stream_is_push(uint32_t stream_id);
h2o_http2_stream_t *h2o_http2_stream_open(h2o_http2_conn_t *conn, uint32_t stream_id, h2o_req_t *src_req,
                                          const h2o_http2_priority_t *received_priority);
static void h2o_http2_stream_update_open_slot(h2o_http2_stream_t *stream, h2o_http2_conn_num_streams_t *slot);
static void h2o_http2_stream_set_state(h2o_http2_conn_t *conn, h2o_http2_stream_t *stream, h2o_http2_stream_state_t new_state);
static void h2o_http2_stream_prepare_for_request(h2o_http2_conn_t *conn, h2o_http2_stream_t *stream);
void h2o_http2_stream_close(h2o_http2_conn_t *conn, h2o_http2_stream_t *stream);
void h2o_http2_stream_reset(h2o_http2_conn_t *conn, h2o_http2_stream_t *stream);
void h2o_http2_stream_send_pending_data(h2o_http2_conn_t *conn, h2o_http2_stream_t *stream);
static int h2o_http2_stream_has_pending_data(h2o_http2_stream_t *stream);
void h2o_http2_stream_proceed(h2o_http2_conn_t *conn, h2o_http2_stream_t *stream);
static void h2o_http2_stream_send_push_promise(h2o_http2_conn_t *conn, h2o_http2_stream_t *stream);

/* misc */
static void h2o_http2_window_init(h2o_http2_window_t *window, const h2o_http2_settings_t *peer_settings);
static int h2o_http2_window_update(h2o_http2_window_t *window, ssize_t delta);
static ssize_t h2o_http2_window_get_window(h2o_http2_window_t *window);
static void h2o_http2_window_consume_window(h2o_http2_window_t *window, size_t bytes);

static uint16_t h2o_http2_decode16u(const uint8_t *src);
static uint32_t h2o_http2_decode24u(const uint8_t *src);
static uint32_t h2o_http2_decode32u(const uint8_t *src);
static uint8_t *h2o_http2_encode24u(uint8_t *dst, uint32_t value);
static uint8_t *h2o_http2_encode32u(uint8_t *dst, uint32_t value);

h2o_http2_debug_state_t *h2o_http2_get_debug_state(h2o_req_t *req, int hpack_enabled);

/* inline definitions */

inline void h2o_http2_window_init(h2o_http2_window_t *window, const h2o_http2_settings_t *peer_settings)
{
    window->_avail = peer_settings->initial_window_size;
}

inline int h2o_http2_window_update(h2o_http2_window_t *window, ssize_t delta)
{
    ssize_t v = window->_avail + delta;
    if (v > INT32_MAX)
        return -1;
    window->_avail = v;
    return 0;
}

inline ssize_t h2o_http2_window_get_window(h2o_http2_window_t *window)
{
    return window->_avail;
}

inline void h2o_http2_window_consume_window(h2o_http2_window_t *window, size_t bytes)
{
    window->_avail -= bytes;
}

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
    winsz = h2o_http2_window_get_window(&conn->_write.window);
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
        stream->req.timestamps.request_begin_at = *h2o_get_timestamp(conn->super.ctx, NULL, NULL);
        break;
    case H2O_HTTP2_STREAM_STATE_RECV_BODY:
        stream->state = new_state;
        stream->req.timestamps.request_body_begin_at = *h2o_get_timestamp(conn->super.ctx, NULL, NULL);
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
        stream->state = new_state;
        ++stream->_num_streams_slot->send_body;
        stream->req.timestamps.response_start_at = *h2o_get_timestamp(conn->super.ctx, NULL, NULL);
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
        stream->req.timestamps.response_end_at = *h2o_get_timestamp(conn->super.ctx, NULL, NULL);
        --stream->_num_streams_slot->open;
        stream->_num_streams_slot = NULL;
        break;
    }
}

inline void h2o_http2_stream_prepare_for_request(h2o_http2_conn_t *conn, h2o_http2_stream_t *stream)
{
    assert(h2o_http2_scheduler_is_open(&stream->_refs.scheduler));

    /* adjust max-open */
    uint32_t *max_open =
        h2o_http2_stream_is_push(stream->stream_id) ? &conn->push_stream_ids.max_open : &conn->pull_stream_ids.max_open;
    if (*max_open < stream->stream_id)
        *max_open = stream->stream_id;
    h2o_http2_stream_set_state(conn, stream, H2O_HTTP2_STREAM_STATE_RECV_HEADERS);
    h2o_http2_window_init(&stream->output_window, &conn->peer_settings);
}

inline int h2o_http2_stream_has_pending_data(h2o_http2_stream_t *stream)
{
    return stream->_data.size != 0;
}

inline void h2o_http2_stream_send_push_promise(h2o_http2_conn_t *conn, h2o_http2_stream_t *stream)
{
    assert(!stream->push.promise_sent);
    h2o_hpack_flatten_request(&conn->_write.buf, &conn->_output_header_table, stream->stream_id, conn->peer_settings.max_frame_size,
                              &stream->req, stream->push.parent_stream_id);
    stream->push.promise_sent = 1;
}

inline uint16_t h2o_http2_decode16u(const uint8_t *src)
{
    return (uint16_t)src[0] << 8 | src[1];
}

inline uint32_t h2o_http2_decode24u(const uint8_t *src)
{
    return (uint32_t)src[0] << 16 | (uint32_t)src[1] << 8 | src[2];
}

inline uint32_t h2o_http2_decode32u(const uint8_t *src)
{
    return (uint32_t)src[0] << 24 | (uint32_t)src[1] << 16 | (uint32_t)src[2] << 8 | src[3];
}

inline uint8_t *h2o_http2_encode24u(uint8_t *dst, uint32_t value)
{
    *dst++ = value >> 16;
    *dst++ = value >> 8;
    *dst++ = value;
    return dst;
}

inline uint8_t *h2o_http2_encode32u(uint8_t *dst, uint32_t value)
{
    *dst++ = value >> 24;
    *dst++ = value >> 16;
    *dst++ = value >> 8;
    *dst++ = value;
    return dst;
}

inline h2o_hpack_header_table_entry_t *h2o_hpack_header_table_get(h2o_hpack_header_table_t *table, size_t index)
{
    size_t entry_index = (index + table->entry_start_index) % table->entry_capacity;
    struct st_h2o_hpack_header_table_entry_t *entry = table->entries + entry_index;
    assert(entry->name != NULL);
    return entry;
}

#endif
