/*
 * Copyright (c) 2016 Ichito Nagata, Fastly, Inc.
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
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include "khash.h"
#include "picohttpparser.h"
#include "h2o.h"
#include "h2o/http2.h"
#include "h2o/http2_internal.h"

enum enum_stream_state_t {
    STREAM_STATE_SEND_HEADERS,
    STREAM_STATE_SEND_BODY,
    STREAM_STATE_RECV_HEADERS,
    STREAM_STATE_RECV_BODY,
};

enum enum_conn_state_t {
    CONN_STATE_OPEN,
    CONN_STATE_HALF_CLOSED,
    CONN_STATE_IS_CLOSING,
};

#define H2O_HTTP2_SETTINGS_CLIENT_CONNECTION_WINDOW_SIZE 16777216
#define H2O_HTTP2_SETTINGS_CLIENT_HEADER_TABLE_SIZE 4096

#define H2O_HTTP2_DEFAULT_OUTBUF_SIZE 81920
static __thread h2o_buffer_prototype_t wbuf_buffer_prototype = {{16}, {H2O_HTTP2_DEFAULT_OUTBUF_SIZE}};

struct st_h2o_http2client_stream_t;
KHASH_MAP_INIT_INT64(stream, struct st_h2o_http2client_stream_t *)

#define UNUSED_FUNCTION(name)                                                                                                      \
    __attribute__((unused)) static void unused_function_##name(void)                                                               \
    {                                                                                                                              \
        (void)name;                                                                                                                \
    }
UNUSED_FUNCTION(kh_clear_stream)
UNUSED_FUNCTION(kh_destroy_stream)
#undef UNUSED_FUNCTION

struct st_h2o_http2client_conn_t {
    h2o_httpclient_ctx_t *ctx;
    h2o_url_t origin_url;
    h2o_socket_t *sock;
    enum enum_conn_state_t state;
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
    h2o_httpclient_t client;
    struct st_h2o_http2client_conn_t *conn;
    uint32_t stream_id;
    enum enum_stream_state_t state;
    h2o_timeout_entry_t timeout_entry;

    union {
        h2o_httpclient_connect_cb on_connect;
        h2o_httpclient_head_cb on_head;
        h2o_httpclient_body_cb on_body;
    } cb;

    struct {
        h2o_http2_window_t window;
        H2O_VECTOR(h2o_iovec_t) data;
        h2o_linklist_t sending_link;
    } output;

    struct {
        h2o_http2_window_t window;
        h2o_res_t res;
        h2o_buffer_t *body;
    } input;

    struct {
        h2o_httpclient_proceed_req_cb proceed_req;
        size_t bytes_in_flight;
        unsigned char done : 1;
    } streaming;

    h2o_mem_pool_t pool;
};

static void do_emit_writereq(struct st_h2o_http2client_conn_t *conn);

/////////////////////////////////////////////////////////////////////////////////////

static void request_write(struct st_h2o_http2client_conn_t *conn)
{
    if (conn->state == CONN_STATE_IS_CLOSING)
        return;
    if (conn->sock->_cb.write == NULL && !h2o_timeout_is_linked(&conn->output.defer_timeout_entry))
        h2o_timeout_link(conn->ctx->loop, conn->ctx->zero_timeout, &conn->output.defer_timeout_entry);
}

static void enqueue_window_update(struct st_h2o_http2client_conn_t *conn, uint32_t stream_id, h2o_http2_window_t *window,
                                  size_t desired)
{
    assert(desired <= INT32_MAX);
    if (h2o_http2_window_get_avail(window) * 2 < desired) {
        int32_t delta = (int32_t)(desired - h2o_http2_window_get_avail(window));
        h2o_http2_encode_window_update_frame(&conn->output.buf, stream_id, delta);
        request_write(conn);
        h2o_http2_window_update(window, delta);
    }
}

static void stream_send_error(struct st_h2o_http2client_conn_t *conn, uint32_t stream_id, int errnum)
{
    assert(stream_id != 0);
    assert(conn->state != CONN_STATE_IS_CLOSING);

    h2o_http2_encode_rst_stream_frame(&conn->output.buf, stream_id, -errnum);
    request_write(conn);
}

static void transition_state(struct st_h2o_http2client_stream_t *stream, enum enum_stream_state_t new_state)
{
    switch (new_state) {
    case STREAM_STATE_SEND_HEADERS:
        assert(!"FIXME");
        break;
    case STREAM_STATE_SEND_BODY:
        assert(stream->state == STREAM_STATE_SEND_HEADERS);
        break;
    case STREAM_STATE_RECV_HEADERS:
        assert(stream->state == STREAM_STATE_SEND_BODY);
        break;
    case STREAM_STATE_RECV_BODY:
        assert(stream->state == STREAM_STATE_RECV_HEADERS);
        break;
    }
    stream->state = new_state;
}

static struct st_h2o_http2client_stream_t *get_stream(struct st_h2o_http2client_conn_t *conn, uint32_t stream_id)
{
    khiter_t iter = kh_get(stream, conn->streams, stream_id);
    if (iter != kh_end(conn->streams))
        return (struct st_h2o_http2client_stream_t *)kh_val(conn->streams, iter);
    return NULL;
}

static void register_stream(struct st_h2o_http2client_stream_t *stream, struct st_h2o_http2client_conn_t *conn)
{
    assert(stream->stream_id == 0);

    stream->conn = conn;

    stream->stream_id = conn->max_open_stream_id == 0 ? 1 : conn->max_open_stream_id + 2;
    conn->max_open_stream_id = stream->stream_id;

    int r;
    khiter_t iter = kh_put(stream, conn->streams, stream->stream_id, &r);
    assert(iter != kh_end(conn->streams));
    kh_val(conn->streams, iter) = stream;

    ++conn->num_streams;

    if (h2o_timeout_is_linked(&conn->keepalive_timeout_entry))
        h2o_timeout_unlink(&conn->keepalive_timeout_entry);
}

static void unregister_stream(struct st_h2o_http2client_stream_t *stream)
{
    khiter_t iter = kh_get(stream, stream->conn->streams, stream->stream_id);
    assert(iter != kh_end(stream->conn->streams));
    kh_del(stream, stream->conn->streams, iter);

    --stream->conn->num_streams;

    if (stream->conn->num_streams == 0)
        h2o_timeout_link(stream->conn->ctx->loop, stream->conn->ctx->keepalive_timeout, &stream->conn->keepalive_timeout_entry);
}

static void close_stream(struct st_h2o_http2client_stream_t *stream)
{
    if (stream->conn != NULL) {
        unregister_stream(stream);
    }

    if (stream->client.sockpool.connect_req != NULL) {
        h2o_socketpool_cancel_connect(stream->client.sockpool.connect_req);
        stream->client.sockpool.connect_req = NULL;
    }

    if (h2o_timeout_is_linked(&stream->timeout_entry))
        h2o_timeout_unlink(&stream->timeout_entry);
    if (h2o_linklist_is_linked(&stream->output.sending_link))
        h2o_linklist_unlink(&stream->output.sending_link);

    if (stream->input.body != NULL)
        h2o_buffer_dispose(&stream->input.body);

    h2o_mem_clear_pool(&stream->pool);

    free(stream);
}

static int on_head(struct st_h2o_http2client_conn_t *conn, struct st_h2o_http2client_stream_t *stream, const uint8_t *src,
                   size_t len, const char **err_desc)
{
    int ret;

    assert(stream->state == STREAM_STATE_RECV_HEADERS);

    if ((ret = h2o_hpack_parse_response_headers(&stream->pool, &stream->input.res, &conn->input.header_table, src, len,
                                                err_desc)) != 0) {
        if (ret == H2O_HTTP2_ERROR_INVALID_HEADER_CHAR) {
            ret = H2O_HTTP2_ERROR_PROTOCOL;
            goto SendRSTStream;
        }
        return ret;
    }
    if (stream->input.res.status == 0) {
        /* couldn't find :status pseudo header */
        ret = H2O_HTTP2_ERROR_PROTOCOL;
        goto SendRSTStream;
    }

    stream->cb.on_body = stream->cb.on_head(&stream->client, NULL, 0, stream->input.res.status, h2o_iovec_init(NULL, 0),
                                            stream->input.res.headers.entries, stream->input.res.headers.size, (int)len);
    if (stream->cb.on_body == NULL) {
        ret = H2O_HTTP2_ERROR_PROTOCOL; // TODO: what error is suitable for this case?
        goto SendRSTStream;
    }

    transition_state(stream, STREAM_STATE_RECV_BODY);
    if (stream->input.body == NULL) {
        close_stream(stream);
    }

    return 0;

SendRSTStream:
    stream_send_error(conn, stream->stream_id, ret);
    close_stream(stream);
    return 0;
}

ssize_t expect_default(struct st_h2o_http2client_conn_t *conn, const uint8_t *src, size_t len, const char **err_desc);
static ssize_t expect_continuation_of_headers(struct st_h2o_http2client_conn_t *conn, const uint8_t *src, size_t len,
                                              const char **err_desc)
{
    h2o_http2_frame_t frame;
    ssize_t ret;
    struct st_h2o_http2client_stream_t *stream;
    int hret;

    if ((ret = h2o_http2_decode_frame(&frame, src, len, err_desc)) < 0)
        return ret;
    if (frame.type != H2O_HTTP2_FRAME_TYPE_CONTINUATION) {
        *err_desc = "expected CONTINUATION frame";
        return H2O_HTTP2_ERROR_PROTOCOL;
    }

    if ((stream = get_stream(conn, frame.stream_id)) == NULL ||
        !(stream->state == STREAM_STATE_RECV_HEADERS || stream->state == STREAM_STATE_RECV_BODY)) {
        *err_desc = "unexpected stream id in CONTINUATION frame";
        return H2O_HTTP2_ERROR_PROTOCOL;
    }

    if (stream->state == STREAM_STATE_RECV_BODY) {
        /* is a trailer, do nothing */
        return ret;
    }

    h2o_buffer_reserve(&conn->input.headers_unparsed, frame.length);
    memcpy(conn->input.headers_unparsed->bytes + conn->input.headers_unparsed->size, frame.payload, frame.length);
    conn->input.headers_unparsed->size += frame.length;

    if ((frame.flags & H2O_HTTP2_FRAME_FLAG_END_HEADERS) != 0) {
        conn->input.read_frame = expect_default;
        hret = on_head(conn, stream, (const uint8_t *)conn->input.headers_unparsed->bytes, conn->input.headers_unparsed->size,
                       err_desc);
        if (hret != 0)
            ret = hret;
        h2o_buffer_dispose(&conn->input.headers_unparsed);
        conn->input.headers_unparsed = NULL;
    }

    return ret;
}

static void do_update_window(h2o_httpclient_t *client);
static int handle_data_frame(struct st_h2o_http2client_conn_t *conn, h2o_http2_frame_t *frame, const char **err_desc)
{
    h2o_http2_data_payload_t payload;
    struct st_h2o_http2client_stream_t *stream;
    int ret;

    if ((ret = h2o_http2_decode_data_payload(&payload, frame, err_desc)) != 0)
        return ret;

    /* save the input in the request body buffer, or send error (and close the stream) */
    if ((stream = get_stream(conn, frame->stream_id)) == NULL) {
        if (frame->stream_id <= conn->max_open_stream_id) {
            stream_send_error(conn, frame->stream_id, H2O_HTTP2_ERROR_STREAM_CLOSED);
            return 0;
        } else {
            *err_desc = "invalid DATA frame";
            return H2O_HTTP2_ERROR_PROTOCOL;
        }
    }
    if (stream->state != STREAM_STATE_RECV_BODY) {
        stream_send_error(conn, frame->stream_id, H2O_HTTP2_ERROR_STREAM_CLOSED);
        close_stream(stream);
        return 0;
    }
    assert(stream->input.body != NULL);

    h2o_buffer_append(&stream->input.body, (void *)payload.data, payload.length);

    h2o_http2_window_consume_window(&conn->input.window, payload.length);
    h2o_http2_window_consume_window(&stream->input.window, payload.length);

    int is_final = (frame->flags & H2O_HTTP2_FRAME_FLAG_END_STREAM) != 0;
    if (stream->cb.on_body(&stream->client, is_final ? h2o_httpclient_error_is_eos : NULL) != 0) {
        stream_send_error(conn, frame->stream_id, H2O_HTTP2_ERROR_PROTOCOL); // TODO which error code is it suit for this case?
        close_stream(stream);
        return 0;
    }

    if (is_final) {
        close_stream(stream);
    } else {
        /* update connection-level window */
        enqueue_window_update(stream->conn, 0, &stream->conn->input.window, H2O_HTTP2_SETTINGS_CLIENT_CONNECTION_WINDOW_SIZE);
        /* update stream-level window */
        do_update_window(&stream->client);
    }

    return 0;
}

static int handle_headers_frame(struct st_h2o_http2client_conn_t *conn, h2o_http2_frame_t *frame, const char **err_desc)
{
    h2o_http2_headers_payload_t payload;
    struct st_h2o_http2client_stream_t *stream;
    int ret;

    /* decode */
    if ((ret = h2o_http2_decode_headers_payload(&payload, frame, err_desc)) != 0)
        return ret;
    if ((frame->stream_id & 1) == 0) {
        *err_desc = "invalid stream id in HEADERS frame";
        return H2O_HTTP2_ERROR_PROTOCOL;
    }

    if (frame->stream_id == payload.priority.dependency) {
        *err_desc = "stream cannot depend on itself";
        return H2O_HTTP2_ERROR_PROTOCOL;
    }

    if ((stream = get_stream(conn, frame->stream_id)) == NULL) {
        *err_desc = "invalid stream id in HEADERS frame";
        return H2O_HTTP2_ERROR_STREAM_CLOSED;
    }

    h2o_timeout_unlink(&stream->timeout_entry);

    switch (stream->state) {
    case STREAM_STATE_RECV_HEADERS:
        break;
    case STREAM_STATE_RECV_BODY:
        /* is a trailer (ignore after only validate it) */
        if ((frame->flags & H2O_HTTP2_FRAME_FLAG_END_STREAM) == 0) {
            *err_desc = "trailing HEADERS frame MUST have END_STREAM flag set";
            return H2O_HTTP2_ERROR_PROTOCOL;
        }
        if ((frame->flags & H2O_HTTP2_FRAME_FLAG_END_HEADERS) == 0)
            /* read following continuation frames without initializing `headers_unparsed` */
            conn->input.read_frame = expect_continuation_of_headers;
        return 0;
    default:
        stream_send_error(conn, frame->stream_id, H2O_HTTP2_ERROR_STREAM_CLOSED);
        close_stream(stream);
        return 0;
    }

    if ((frame->flags & H2O_HTTP2_FRAME_FLAG_END_HEADERS) == 0) {
        /* request is not complete, store in buffer */
        conn->input.read_frame = expect_continuation_of_headers;
        h2o_buffer_init(&conn->input.headers_unparsed, &h2o_socket_buffer_prototype);
        h2o_buffer_reserve(&conn->input.headers_unparsed, payload.headers_len);
        memcpy(conn->input.headers_unparsed->bytes, payload.headers, payload.headers_len);
        conn->input.headers_unparsed->size = payload.headers_len;
        return 0;
    }

    if ((frame->flags & H2O_HTTP2_FRAME_FLAG_END_STREAM) == 0) {
        h2o_buffer_init(&stream->input.body, &h2o_socket_buffer_prototype);
    }

    /* request is complete, handle it */
    return on_head(conn, stream, payload.headers, payload.headers_len, err_desc);
}

static int handle_priority_frame(struct st_h2o_http2client_conn_t *conn, h2o_http2_frame_t *frame, const char **err_desc)
{
    h2o_http2_priority_t payload;
    int ret;

    if ((ret = h2o_http2_decode_priority_payload(&payload, frame, err_desc)) != 0)
        return ret;
    if (frame->stream_id == payload.dependency) {
        *err_desc = "stream cannot depend on itself";
        return H2O_HTTP2_ERROR_PROTOCOL;
    }

    /* Ignore PRIORITY frames */
    return 0;
}

static int handle_rst_stream_frame(struct st_h2o_http2client_conn_t *conn, h2o_http2_frame_t *frame, const char **err_desc)
{
    h2o_http2_rst_stream_payload_t payload;
    struct st_h2o_http2client_stream_t *stream;
    int ret;

    if ((ret = h2o_http2_decode_rst_stream_payload(&payload, frame, err_desc)) != 0)
        return ret;
    if (frame->stream_id > conn->max_open_stream_id) {
        *err_desc = "unexpected stream id in RST_STREAM frame";
        return H2O_HTTP2_ERROR_PROTOCOL;
    }

    stream = get_stream(conn, frame->stream_id);
    if (stream != NULL) {
        /* reset the stream */
        // TODO: retry if REFUSED_STREAM flags is set
        close_stream(stream);
    }

    return 0;
}

static int update_stream_output_window(struct st_h2o_http2client_stream_t *stream, ssize_t delta)
{
    ssize_t before = h2o_http2_window_get_avail(&stream->output.window);
    if (h2o_http2_window_update(&stream->output.window, delta) != 0)
        return -1;
    ssize_t after = h2o_http2_window_get_avail(&stream->output.window);
    if (before <= 0 && 0 < after && stream->output.data.size != 0) {
        assert(!h2o_linklist_is_linked(&stream->output.sending_link));
        h2o_linklist_insert(&stream->conn->output.sending_streams, &stream->output.sending_link);
    }
    return 0;
}

static ssize_t conn_get_buffer_window(struct st_h2o_http2client_conn_t *conn)
{
    ssize_t ret, winsz;
    size_t capacity, cwnd_left;

    capacity = conn->output.buf->capacity;
    if ((cwnd_left = h2o_socket_prepare_for_latency_optimized_write(conn->sock, &conn->ctx->http2.latency_optimization)) <
        capacity) {
        capacity = cwnd_left;
        if (capacity < conn->output.buf->size)
            return 0;
    }

    ret = capacity - conn->output.buf->size;
    if (ret < H2O_HTTP2_FRAME_HEADER_SIZE)
        return 0;
    ret -= H2O_HTTP2_FRAME_HEADER_SIZE;
    winsz = h2o_http2_window_get_avail(&conn->output.window);
    if (winsz < ret)
        ret = winsz;
    return ret;
}

static int handle_settings_frame(struct st_h2o_http2client_conn_t *conn, h2o_http2_frame_t *frame, const char **err_desc)
{
    if (frame->stream_id != 0) {
        *err_desc = "invalid stream id in SETTINGS frame";
        return H2O_HTTP2_ERROR_PROTOCOL;
    }

    if ((frame->flags & H2O_HTTP2_FRAME_FLAG_ACK) != 0) {
        if (frame->length != 0) {
            *err_desc = "invalid SETTINGS frame (+ACK)";
            return H2O_HTTP2_ERROR_FRAME_SIZE;
        }
    } else {
        uint32_t prev_initial_window_size = conn->peer_settings.initial_window_size;
        /* FIXME handle SETTINGS_HEADER_TABLE_SIZE */
        int ret = h2o_http2_update_peer_settings(&conn->peer_settings, frame->payload, frame->length, err_desc);
        if (ret != 0)
            return ret;
        { /* schedule ack */
            h2o_iovec_t header_buf = h2o_buffer_reserve(&conn->output.buf, H2O_HTTP2_FRAME_HEADER_SIZE);
            h2o_http2_encode_frame_header((void *)header_buf.base, 0, H2O_HTTP2_FRAME_TYPE_SETTINGS, H2O_HTTP2_FRAME_FLAG_ACK, 0);
            conn->output.buf->size += H2O_HTTP2_FRAME_HEADER_SIZE;
            request_write(conn);
        }
        /* apply the change to window size (to all the streams but not the connection, see 6.9.2 of draft-15) */
        if (prev_initial_window_size != conn->peer_settings.initial_window_size) {
            ssize_t delta = conn->peer_settings.initial_window_size - prev_initial_window_size;
            struct st_h2o_http2client_stream_t *stream;
            kh_foreach_value(conn->streams, stream, { update_stream_output_window((void *)stream, delta); });

            if (conn_get_buffer_window(conn) > 0)
                request_write(conn);
        }
    }

    return 0;
}

static int handle_push_promise_frame(struct st_h2o_http2client_conn_t *conn, h2o_http2_frame_t *frame, const char **err_desc)
{
    *err_desc = "received PUSH_PROMISE frame";
    return H2O_HTTP2_ERROR_PROTOCOL;
}

static int handle_ping_frame(struct st_h2o_http2client_conn_t *conn, h2o_http2_frame_t *frame, const char **err_desc)
{
    h2o_http2_ping_payload_t payload;
    int ret;

    if ((ret = h2o_http2_decode_ping_payload(&payload, frame, err_desc)) != 0)
        return ret;

    if ((frame->flags & H2O_HTTP2_FRAME_FLAG_ACK) == 0) {
        h2o_http2_encode_ping_frame(&conn->output.buf, 1, payload.data);
        request_write(conn);
    }

    return 0;
}

static int handle_goaway_frame(struct st_h2o_http2client_conn_t *conn, h2o_http2_frame_t *frame, const char **err_desc)
{
    h2o_http2_goaway_payload_t payload;
    int ret;

    if ((ret = h2o_http2_decode_goaway_payload(&payload, frame, err_desc)) != 0)
        return ret;

    // TODO: retry streams which can be retried

    /* stop opening new streams */
    h2o_linklist_unlink(&conn->link);

    return 0;
}

static int handle_window_update_frame(struct st_h2o_http2client_conn_t *conn, h2o_http2_frame_t *frame, const char **err_desc)
{
    h2o_http2_window_update_payload_t payload;
    int ret, err_is_stream_level;

    if ((ret = h2o_http2_decode_window_update_payload(&payload, frame, err_desc, &err_is_stream_level)) != 0) {
        if (err_is_stream_level) {
            stream_send_error(conn, frame->stream_id, ret);
            struct st_h2o_http2client_stream_t *stream = get_stream(conn, frame->stream_id);
            if (stream != NULL)
                close_stream(stream);
            return 0;
        } else {
            return ret;
        }
    }

    if (frame->stream_id == 0) {
        if (h2o_http2_window_update(&conn->output.window, payload.window_size_increment) != 0) {
            *err_desc = "flow control window overflow";
            return H2O_HTTP2_ERROR_FLOW_CONTROL;
        }
    } else if (frame->stream_id <= conn->max_open_stream_id) {
        struct st_h2o_http2client_stream_t *stream = get_stream(conn, frame->stream_id);
        if (stream != NULL) {
            if (update_stream_output_window(stream, payload.window_size_increment) != 0) {
                stream_send_error(conn, frame->stream_id, H2O_HTTP2_ERROR_FLOW_CONTROL);
                close_stream(stream);
                return 0;
            }
        }
    } else {
        *err_desc = "invalid stream id in WINDOW_UPDATE frame";
        return H2O_HTTP2_ERROR_PROTOCOL;
    }

    if (conn_get_buffer_window(conn) > 0)
        request_write(conn);

    return 0;
}

static int handle_invalid_continuation_frame(struct st_h2o_http2client_conn_t *conn, h2o_http2_frame_t *frame,
                                             const char **err_desc)
{
    *err_desc = "received invalid CONTINUATION frame";
    return H2O_HTTP2_ERROR_PROTOCOL;
}

ssize_t expect_default(struct st_h2o_http2client_conn_t *conn, const uint8_t *src, size_t len, const char **err_desc)
{
    assert(conn->state != CONN_STATE_IS_CLOSING);

    h2o_http2_frame_t frame;
    ssize_t ret;
    static int (*FRAME_HANDLERS[])(struct st_h2o_http2client_conn_t * conn, h2o_http2_frame_t * frame, const char **err_desc) = {
        handle_data_frame,                /* DATA */
        handle_headers_frame,             /* HEADERS */
        handle_priority_frame,            /* PRIORITY */
        handle_rst_stream_frame,          /* RST_STREAM */
        handle_settings_frame,            /* SETTINGS */
        handle_push_promise_frame,        /* PUSH_PROMISE */
        handle_ping_frame,                /* PING */
        handle_goaway_frame,              /* GOAWAY */
        handle_window_update_frame,       /* WINDOW_UPDATE */
        handle_invalid_continuation_frame /* CONTINUATION */
    };

    if ((ret = h2o_http2_decode_frame(&frame, src, len, err_desc)) < 0)
        return ret;

    if (frame.type < sizeof(FRAME_HANDLERS) / sizeof(FRAME_HANDLERS[0])) {
        int hret = FRAME_HANDLERS[frame.type](conn, &frame, err_desc);
        if (hret != 0)
            ret = hret;
    } else {
        fprintf(stderr, "skipping frame (type:%d)\n", frame.type);
    }

    return ret;
}

static ssize_t expect_settings(struct st_h2o_http2client_conn_t *conn, const uint8_t *src, size_t len, const char **err_desc)
{
    assert(conn->state != CONN_STATE_IS_CLOSING);

    h2o_http2_frame_t frame;
    ssize_t ret;

    if ((ret = h2o_http2_decode_frame(&frame, src, len, err_desc)) < 0)
        return ret;

    if (frame.type != H2O_HTTP2_FRAME_TYPE_SETTINGS)
        return H2O_HTTP2_ERROR_PROTOCOL_CLOSE_IMMEDIATELY;

    int hret = handle_settings_frame(conn, &frame, err_desc);
    if (hret != 0)
        return hret;

    conn->input.read_frame = expect_default;
    return ret;
}

static void close_connection_now(struct st_h2o_http2client_conn_t *conn)
{
    assert(!h2o_timeout_is_linked(&conn->output.defer_timeout_entry));

    free(conn->origin_url.authority.base);
    free(conn->origin_url.host.base);
    free(conn->origin_url.path.base);

    h2o_socket_close(conn->sock);

    struct st_h2o_http2client_stream_t *stream;
    kh_foreach_value(conn->streams, stream, { close_stream(stream); });
    kh_destroy(stream, conn->streams);

    if (h2o_linklist_is_linked(&conn->link))
        h2o_linklist_unlink(&conn->link);

    if (h2o_timeout_is_linked(&conn->io_timeout_entry))
        h2o_timeout_unlink(&conn->io_timeout_entry);
    if (h2o_timeout_is_linked(&conn->keepalive_timeout_entry))
        h2o_timeout_unlink(&conn->keepalive_timeout_entry);

    /* output */
    h2o_hpack_dispose_header_table(&conn->output.header_table);
    h2o_buffer_dispose(&conn->output.buf);
    if (conn->output.buf_in_flight != NULL)
        h2o_buffer_dispose(&conn->output.buf_in_flight);
    if (h2o_timeout_is_linked(&conn->output.defer_timeout_entry))
        h2o_timeout_unlink(&conn->output.defer_timeout_entry);
    assert(h2o_linklist_is_empty(&conn->output.sending_streams));
    assert(h2o_linklist_is_empty(&conn->output.sent_streams));

    /* input */
    h2o_hpack_dispose_header_table(&conn->input.header_table);
    if (conn->input.headers_unparsed != NULL)
        h2o_buffer_dispose(&conn->input.headers_unparsed);

    free(conn);
}

static int close_connection_if_necessary(struct st_h2o_http2client_conn_t *conn)
{
    if (conn->state == CONN_STATE_HALF_CLOSED && conn->num_streams == 0)
        conn->state = CONN_STATE_IS_CLOSING;
    if (conn->state == CONN_STATE_IS_CLOSING) {
        close_connection_now(conn);
        return 1;
    }
    return 0;
}

static int close_connection(struct st_h2o_http2client_conn_t *conn)
{
    conn->state = CONN_STATE_IS_CLOSING;
    h2o_socket_read_stop(conn->sock);

    if (conn->output.buf_in_flight != NULL || h2o_timeout_is_linked(&conn->output.defer_timeout_entry)) {
        /* there is a pending write, let close_connection_if_necessary actually close the connection */
    } else {
        close_connection_now(conn);
        return -1;
    }
    return 0;
}

static void enqueue_goaway(struct st_h2o_http2client_conn_t *conn, int errnum, h2o_iovec_t additional_data)
{
    if (conn->state == CONN_STATE_IS_CLOSING)
        return;

    h2o_http2_encode_goaway_frame(&conn->output.buf, 0, errnum, additional_data);
    request_write(conn);
    conn->state = CONN_STATE_HALF_CLOSED;

    /* stop opening new streams */
    h2o_linklist_unlink(&conn->link);
}

static void on_connect_error(struct st_h2o_http2client_stream_t *stream, const char *errstr)
{
    assert(errstr != NULL);
    stream->cb.on_connect(&stream->client, errstr, NULL, NULL, NULL, NULL, NULL, (h2o_httpclient_features_t){NULL}, NULL);
    close_stream(stream);
}

static void do_stream_timeout(struct st_h2o_http2client_stream_t *stream)
{
    if (stream->conn == NULL) {
        on_connect_error(stream, "connection timeout");
        return;
    }
    switch (stream->state) {
    case STREAM_STATE_SEND_HEADERS:
    case STREAM_STATE_SEND_BODY:
        stream->cb.on_head(&stream->client, "I/O timeout", 0, 0, h2o_iovec_init(NULL, 0), NULL, 0, 0);
        break;
    case STREAM_STATE_RECV_HEADERS:
        stream->cb.on_head(&stream->client, "first byte timeout", 0, 0, h2o_iovec_init(NULL, 0), NULL, 0, 0);
        break;
    case STREAM_STATE_RECV_BODY:
        stream->cb.on_body(&stream->client, "I/O timeout");
        break;
    }
    close_stream(stream);
}

static void on_stream_timeout(h2o_timeout_entry_t *entry)
{
    struct st_h2o_http2client_stream_t *stream = H2O_STRUCT_FROM_MEMBER(struct st_h2o_http2client_stream_t, timeout_entry, entry);
    do_stream_timeout(stream);
}

static void on_io_timeout(h2o_timeout_entry_t *entry)
{
    struct st_h2o_http2client_conn_t *conn = H2O_STRUCT_FROM_MEMBER(struct st_h2o_http2client_conn_t, io_timeout_entry, entry);
    struct st_h2o_http2client_stream_t *stream;
    kh_foreach_value(conn->streams, stream, { do_stream_timeout(stream); });
    close_connection_now(conn);
}

static void on_keepalive_timeout(h2o_timeout_entry_t *entry)
{
    struct st_h2o_http2client_conn_t *conn =
        H2O_STRUCT_FROM_MEMBER(struct st_h2o_http2client_conn_t, keepalive_timeout_entry, entry);
    enqueue_goaway(conn, H2O_HTTP2_ERROR_NONE, h2o_iovec_init(NULL, 0));
    request_write(conn);
    close_connection(conn);
}

static int parse_input(struct st_h2o_http2client_conn_t *conn)
{
    /* handle the input */
    while (conn->state != CONN_STATE_IS_CLOSING && conn->sock->input->size != 0) {
        /* process a frame */
        const char *err_desc = NULL;
        ssize_t ret = conn->input.read_frame(conn, (uint8_t *)conn->sock->input->bytes, conn->sock->input->size, &err_desc);
        if (ret == H2O_HTTP2_ERROR_INCOMPLETE) {
            break;
        } else if (ret < 0) {
            if (ret != H2O_HTTP2_ERROR_PROTOCOL_CLOSE_IMMEDIATELY) {
                enqueue_goaway(conn, (int)ret,
                               err_desc != NULL ? (h2o_iovec_t){(char *)err_desc, strlen(err_desc)} : (h2o_iovec_t){NULL});
            }
            return close_connection(conn);
        }
        /* advance to the next frame */
        h2o_buffer_consume(&conn->sock->input, ret);
    }
    return 0;
}

static void on_read(h2o_socket_t *sock, const char *err)
{
    struct st_h2o_http2client_conn_t *conn = sock->data;

    h2o_timeout_unlink(&conn->io_timeout_entry);

    if (err != NULL) {
        close_connection(conn);
        return;
    }

    if (parse_input(conn) != 0)
        return;

    /* write immediately, if pending write exists */
    if (h2o_timeout_is_linked(&conn->output.defer_timeout_entry)) {
        h2o_timeout_unlink(&conn->output.defer_timeout_entry);
        do_emit_writereq(conn);
    }

    if (!h2o_timeout_is_linked(&conn->io_timeout_entry))
        h2o_timeout_link(conn->ctx->loop, conn->ctx->io_timeout, &conn->io_timeout_entry);
}

static void on_connection_ready(struct st_h2o_http2client_stream_t *stream, struct st_h2o_http2client_conn_t *conn)
{
    h2o_iovec_t method;
    h2o_url_t url;
    h2o_headers_t headers = (h2o_headers_t){NULL};
    h2o_iovec_t body = h2o_iovec_init(NULL, 0);
    stream->cb.on_head =
        stream->cb.on_connect(&stream->client, NULL, &method, &url, &headers, &body, &stream->streaming.proceed_req,
                              (h2o_httpclient_features_t){NULL, NULL, 0}, &conn->origin_url);
    if (stream->cb.on_head == NULL) {
        close_stream(stream);
        return;
    }

    register_stream(stream, conn);

    h2o_http2_window_init(&stream->output.window, conn->peer_settings.initial_window_size);

    /* send headers */
    h2o_hpack_flatten_request(&conn->output.buf, &conn->output.header_table, stream->stream_id, conn->peer_settings.max_frame_size,
                              method, &url, &headers, body.base == NULL);
    transition_state(stream, STREAM_STATE_SEND_BODY);

    if (body.base != NULL) {
        /* send body */
        h2o_vector_reserve(&stream->pool, &stream->output.data, stream->output.data.size + 1);
        stream->output.data.entries[stream->output.data.size++] = body;
    }
    h2o_linklist_insert(&conn->output.sending_streams, &stream->output.sending_link);
    request_write(conn);
}

static void on_notify_write(h2o_socket_t *sock, const char *err)
{
    struct st_h2o_http2client_conn_t *conn = sock->data;

    if (err != NULL) {
        close_connection_now(conn);
        return;
    }
    do_emit_writereq(conn);
    close_connection_if_necessary(conn);
}

static void on_write_complete(h2o_socket_t *sock, const char *err)
{
    struct st_h2o_http2client_conn_t *conn = sock->data;

    assert(conn->output.buf_in_flight != NULL);

    h2o_timeout_unlink(&conn->io_timeout_entry);

    /* close by error if necessary */
    if (err != NULL) {
        close_connection_now(conn);
        return;
    }

    if (close_connection_if_necessary(conn))
        return;

    /* unlink timeouts of streams that has finished sending requests */
    while (!h2o_linklist_is_empty(&conn->output.sent_streams)) {
        h2o_linklist_t *link = conn->output.sent_streams.next;
        struct st_h2o_http2client_stream_t *stream =
            H2O_STRUCT_FROM_MEMBER(struct st_h2o_http2client_stream_t, output.sending_link, link);
        h2o_linklist_unlink(link);

        if (stream->streaming.proceed_req != NULL) {
            size_t bytes_written = stream->streaming.bytes_in_flight;
            stream->streaming.bytes_in_flight = 0;
            stream->streaming.proceed_req(&stream->client, bytes_written, stream->streaming.done);
        }

        if (stream->streaming.proceed_req == NULL || stream->streaming.done) {
            transition_state(stream, STREAM_STATE_RECV_HEADERS);
            h2o_timeout_link(stream->client.ctx->loop, stream->client.ctx->first_byte_timeout, &stream->timeout_entry);
        }
    }

    /* reset the other buffer */
    h2o_buffer_dispose(&conn->output.buf_in_flight);

#if !H2O_USE_LIBUV
    if (conn->state == CONN_STATE_OPEN) {
        if (conn->output.buf->size != 0 || !h2o_linklist_is_empty(&conn->output.sending_streams))
            h2o_socket_notify_write(sock, on_notify_write);
        return;
    }
#endif

    /* write more, if possible */
    do_emit_writereq(conn);
    close_connection_if_necessary(conn);
}

static size_t sz_min(size_t x, size_t y)
{
    return x < y ? x : y;
}

static size_t calc_max_payload_size(struct st_h2o_http2client_stream_t *stream)
{
    ssize_t conn_max, stream_max;

    if ((conn_max = conn_get_buffer_window(stream->conn)) <= 0)
        return 0;
    if ((stream_max = h2o_http2_window_get_avail(&stream->output.window)) <= 0)
        return 0;
    return sz_min(sz_min(conn_max, stream_max), stream->conn->peer_settings.max_frame_size);
}

static size_t stream_emit_pending_data(struct st_h2o_http2client_stream_t *stream)
{
    size_t max_payload_size = calc_max_payload_size(stream);
    if (max_payload_size == 0)
        return 0;

    /* reserve buffer and point dst to the payload */
    h2o_iovec_t dst;
    dst.base = h2o_buffer_reserve(&stream->conn->output.buf, H2O_HTTP2_FRAME_HEADER_SIZE + max_payload_size).base +
               H2O_HTTP2_FRAME_HEADER_SIZE;
    dst.len = max_payload_size;

    h2o_iovec_t *buf = stream->output.data.entries;
    h2o_iovec_t *end = buf + stream->output.data.size;

    while (buf != end && dst.len != 0) {
        if (buf->len == 0) {
            ++buf;
            continue;
        }
        size_t fill_size = sz_min(dst.len, buf->len);
        memcpy(dst.base, buf->base, fill_size);
        dst.base += fill_size;
        dst.len -= fill_size;
        buf->base += fill_size;
        buf->len -= fill_size;
        if (buf->len == 0)
            ++buf;
    }

    if (dst.len == max_payload_size)
        return 0; /* nothing is emitted at all */

    /* emit data frame */
    size_t length = max_payload_size - dst.len;
    int end_stream = (stream->streaming.proceed_req == NULL || stream->streaming.done) && (buf == end);
    h2o_http2_encode_frame_header((void *)(stream->conn->output.buf->bytes + stream->conn->output.buf->size), length,
                                  H2O_HTTP2_FRAME_TYPE_DATA, end_stream ? H2O_HTTP2_FRAME_FLAG_END_STREAM : 0, stream->stream_id);
    stream->conn->output.buf->size += length + H2O_HTTP2_FRAME_HEADER_SIZE;

    h2o_http2_window_consume_window(&stream->conn->output.window, length);
    h2o_http2_window_consume_window(&stream->output.window, length);

    /* adjust data vector and state */
    if (buf == end) {
        stream->output.data.size = 0;
    } else if (buf != stream->output.data.entries) {
        size_t new_size = stream->output.data.entries + stream->output.data.size - buf;
        memcpy(stream->output.data.entries, buf, sizeof(*buf) * new_size);
        stream->output.data.size = new_size;
    }

    return length;
}

static void do_emit_writereq(struct st_h2o_http2client_conn_t *conn)
{
    assert(conn->output.buf_in_flight == NULL);

    /* emit DATA frames */
    h2o_linklist_t *node = conn->output.sending_streams.next;
    h2o_linklist_t *first = node;
    while (node != &conn->output.sending_streams) {
        h2o_linklist_t *next = node->next;
        struct st_h2o_http2client_stream_t *stream =
            H2O_STRUCT_FROM_MEMBER(struct st_h2o_http2client_stream_t, output.sending_link, node);
        h2o_linklist_unlink(node);

        size_t bytes_emitted = 0;
        if (stream->output.data.size != 0)
            bytes_emitted = stream_emit_pending_data(stream);

        if (stream->output.data.size == 0) {
            h2o_linklist_insert(&conn->output.sent_streams, node);
        } else if (h2o_http2_window_get_avail(&stream->output.window) > 0) {
            h2o_linklist_insert(&conn->output.sending_streams, node); /* move to the tail to rotate buffers */
        }

        if (stream->streaming.proceed_req != NULL)
            stream->streaming.bytes_in_flight += bytes_emitted;

        if (next == first)
            break;
        node = next;
    }

    if (conn->output.buf->size != 0) {
        /* write and wait for completion */
        h2o_iovec_t buf = {conn->output.buf->bytes, conn->output.buf->size};
        h2o_socket_write(conn->sock, &buf, 1, on_write_complete);
        conn->output.buf_in_flight = conn->output.buf;
        h2o_buffer_init(&conn->output.buf, &wbuf_buffer_prototype);
        if (!h2o_timeout_is_linked(&conn->io_timeout_entry))
            h2o_timeout_link(conn->ctx->loop, conn->ctx->io_timeout, &conn->io_timeout_entry);
    }
}

static void emit_writereq(h2o_timeout_entry_t *entry)
{
    struct st_h2o_http2client_conn_t *conn =
        H2O_STRUCT_FROM_MEMBER(struct st_h2o_http2client_conn_t, output.defer_timeout_entry, entry);
    do_emit_writereq(conn);
}

static struct st_h2o_http2client_conn_t *create_connection(h2o_httpclient_ctx_t *ctx, h2o_socket_t *sock, h2o_url_t *origin_url,
                                                           h2o_socketpool_t *socketpool)
{
    struct st_h2o_http2client_conn_t *conn = h2o_mem_alloc(sizeof(*conn));
    memset(conn, 0, sizeof(*conn));
    conn->ctx = ctx;
    conn->sock = sock;
    conn->state = CONN_STATE_OPEN;
    conn->peer_settings = H2O_HTTP2_SETTINGS_DEFAULT;
    conn->streams = kh_init(stream);
    h2o_url_copy(NULL, &conn->origin_url, origin_url);
    h2o_linklist_insert(&ctx->http2.conns, &conn->link);
    conn->io_timeout_entry.cb = on_io_timeout;
    conn->keepalive_timeout_entry.cb = on_keepalive_timeout;

    /* output */
    conn->output.header_table.hpack_capacity = H2O_HTTP2_SETTINGS_CLIENT_HEADER_TABLE_SIZE;
    h2o_http2_window_init(&conn->output.window, conn->peer_settings.initial_window_size);
    h2o_buffer_init(&conn->output.buf, &wbuf_buffer_prototype);
    conn->output.defer_timeout_entry.cb = emit_writereq;
    h2o_linklist_init_anchor(&conn->output.sending_streams);
    h2o_linklist_init_anchor(&conn->output.sent_streams);

    /* input */
    conn->input.header_table.hpack_capacity = conn->input.header_table.hpack_max_capacity =
        H2O_HTTP2_SETTINGS_DEFAULT.header_table_size;
    h2o_http2_window_init(&conn->input.window, H2O_HTTP2_SETTINGS_DEFAULT.initial_window_size);
    conn->input.read_frame = expect_settings;

    return conn;
}

static uint32_t get_max_buffer_size(h2o_httpclient_ctx_t *ctx)
{
    size_t sz = ctx->max_buffer_size;
    if (sz > INT32_MAX)
        sz = INT32_MAX;
    return (uint32_t)sz;
}

static void send_client_preface(struct st_h2o_http2client_conn_t *conn, h2o_httpclient_ctx_t *ctx)
{
#define PREFIX                                                                                                                     \
    "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"                                                                                             \
    "\x00\x00\x12"     /* frame size */                                                                                            \
    "\x04"             /* settings frame */                                                                                        \
    "\x00"             /* no flags */                                                                                              \
    "\x00\x00\x00\x00" /* stream id */                                                                                             \
    "\x00\x02"         /* enable_push */                                                                                           \
    "\x00\x00\x00\x00" /* 0 */                                                                                                     \
    "\x00\x03"         /* max_concurrent_streams */                                                                                \
    "\x00\x00\x00\x64" /* 100 */                                                                                                   \
    "\x00\x04"         /* initial_window_size */
    static const size_t len = sizeof(PREFIX) - 1 + 4;

    uint32_t initial_window_size = get_max_buffer_size(ctx);

    h2o_iovec_t vec = h2o_buffer_reserve(&conn->output.buf, len);
    memcpy(vec.base, PREFIX, sizeof(PREFIX) - 1);

    /* encode max_buffer_size */
    vec.base[len - 4] = (char)((initial_window_size >> 24) & 0xff);
    vec.base[len - 3] = (char)((initial_window_size >> 16) & 0xff);
    vec.base[len - 2] = (char)((initial_window_size >> 8) & 0xff);
    vec.base[len - 1] = (char)(initial_window_size & 0xff);

    conn->output.buf->size += len;
    request_write(conn);
#undef PREFIX
}

static void on_pool_connect(h2o_socket_t *sock, const char *errstr, void *data, h2o_url_t *origin_url)
{
    struct st_h2o_http2client_stream_t *stream = data;

    h2o_timeout_unlink(&stream->timeout_entry);
    stream->client.sockpool.connect_req = NULL;

    if (sock == NULL) {
        assert(errstr != NULL);
        on_connect_error(stream, errstr);
        return;
    }

    struct st_h2o_http2client_conn_t *conn = create_connection(stream->client.ctx, sock, origin_url, stream->client.sockpool.pool);
    sock->data = conn;

    /* send preface, settings, and connection-level window update */
    send_client_preface(conn, stream->client.ctx);

    h2o_socket_read_start(conn->sock, on_read);

    h2o_timeout_link(conn->ctx->loop, conn->ctx->io_timeout, &conn->io_timeout_entry);

    on_connection_ready(stream, conn);
}

static void do_cancel(h2o_httpclient_t *client)
{
    struct st_h2o_http2client_stream_t *stream = H2O_STRUCT_FROM_MEMBER(struct st_h2o_http2client_stream_t, client, client);
    stream_send_error(stream->conn, stream->stream_id, H2O_HTTP2_ERROR_CANCEL);
    close_stream(stream);
}

static void do_update_window(h2o_httpclient_t *client)
{
    struct st_h2o_http2client_stream_t *stream = H2O_STRUCT_FROM_MEMBER(struct st_h2o_http2client_stream_t, client, client);
    size_t max = get_max_buffer_size(client->ctx);
    size_t bufsize = (*client->buf)->size;
    if (bufsize > max) {
        stream->cb.on_body(client, "buffered data size exceeds input window");
        stream_send_error(stream->conn, stream->stream_id, H2O_HTTP2_ERROR_FLOW_CONTROL);
        close_stream(stream);
        return;
    }
    enqueue_window_update(stream->conn, stream->stream_id, &stream->input.window, max - bufsize);
}

static int do_write_req(h2o_httpclient_t *client, h2o_iovec_t chunk, int is_end_stream)
{
    struct st_h2o_http2client_stream_t *stream = H2O_STRUCT_FROM_MEMBER(struct st_h2o_http2client_stream_t, client, client);
    assert(stream->streaming.proceed_req != NULL);

    if (is_end_stream)
        stream->streaming.done = 1;

    if (chunk.len != 0) {
        h2o_vector_reserve(&stream->pool, &stream->output.data, stream->output.data.size + 1);
        stream->output.data.entries[stream->output.data.size++] = chunk;
    }

    if (!h2o_linklist_is_linked(&stream->output.sending_link)) {
        h2o_linklist_insert(&stream->conn->output.sending_streams, &stream->output.sending_link);
        request_write(stream->conn);
    }

    return 0;
}

static struct st_h2o_http2client_stream_t *create_stream(h2o_httpclient_t **client, void *data, h2o_httpclient_ctx_t *ctx,
                                                         h2o_httpclient_connect_cb cb)
{
    struct st_h2o_http2client_stream_t *stream = h2o_mem_alloc(sizeof(*stream));
    memset(stream, 0, offsetof(struct st_h2o_http2client_stream_t, pool));
    h2o_mem_init_pool(&stream->pool);

    stream->client.ctx = ctx;
    stream->client.data = data;
    stream->client.buf = &stream->input.body;
    stream->client.cancel = do_cancel;
    stream->client.steal_socket = NULL;
    stream->client.write_req = do_write_req;
    stream->client.update_window = do_update_window;
    stream->cb.on_connect = cb;
    stream->input.res.content_length = SIZE_MAX;
    stream->state = STREAM_STATE_SEND_HEADERS;
    stream->timeout_entry.cb = on_stream_timeout;
    h2o_http2_window_init(&stream->input.window, get_max_buffer_size(ctx));

    /* caller needs to setup _cb, timeout.cb, sock, and sock->data */

    if (client != NULL)
        *client = &stream->client;

    return stream;
}

static struct st_h2o_http2client_conn_t *select_connection(h2o_httpclient_ctx_t *ctx)
{
    if (h2o_linklist_is_empty(&ctx->http2.conns))
        return NULL;

    /* select the connection and modify the list */
    // TODO: temporary do the simple round-robin rotation, but should somehow consider least-streams algorithm
    struct st_h2o_http2client_conn_t *conn;
    h2o_linklist_t *node = ctx->http2.conns.next;
    h2o_linklist_t *first = node;
    while (node != &ctx->http2.conns) {
        h2o_linklist_t *next = node->next;
        conn = H2O_STRUCT_FROM_MEMBER(struct st_h2o_http2client_conn_t, link, node);
        h2o_linklist_unlink(ctx->http2.conns.next);
        h2o_linklist_insert(&ctx->http2.conns, &conn->link);
        if (conn->num_streams < conn->peer_settings.max_concurrent_streams)
            return conn;
        if (next == first)
            break;
        node = next;
    }

    return NULL;
}

void h2o_http2client_connect(h2o_httpclient_t **_client, void *data, h2o_httpclient_ctx_t *ctx, h2o_socketpool_t *socketpool,
                             h2o_url_t *origin_url, h2o_httpclient_connect_cb cb)
{
    assert(socketpool != NULL);
    struct st_h2o_http2client_stream_t *stream;

    stream = create_stream(_client, data, ctx, cb);
    stream->client.sockpool.pool = socketpool; // TODO is this needed?

    struct st_h2o_http2client_conn_t *conn = select_connection(ctx);
    if (conn == NULL) {
        h2o_timeout_link(ctx->loop, ctx->connect_timeout, &stream->timeout_entry);
        h2o_socketpool_connect(&stream->client.sockpool.connect_req, socketpool, origin_url, ctx->loop, ctx->getaddr_receiver,
                               on_pool_connect, stream);
    } else {
        on_connection_ready(stream, conn);
    }
}
