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
#include <stdio.h>
#include <stdlib.h>
#include "h2o.h"
#include "h2o/http1.h"
#include "h2o/http2.h"
#include "internal.h"

static const h2o_buf_t CONNECTION_PREFACE = { H2O_STRLIT("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n") };

#define H2_PROTOCOL_IDENTIFIER "h2-14"
const char *h2o_http2_npn_protocols = "\x05" H2_PROTOCOL_IDENTIFIER;
static const h2o_buf_t alpn_protocols[] = {
    { H2O_STRLIT(H2_PROTOCOL_IDENTIFIER) },
    { NULL, 0 }
};
const h2o_buf_t *h2o_http2_alpn_protocols = alpn_protocols;

const h2o_http2_settings_t H2O_HTTP2_SETTINGS_HOST = {
    /* header_table_size = */ 4096,
    /* enable_push = */ 0,
    /* max_concurrent_streams = */ 100,
    /* initial_window_size = */ 262144,
    /* max_frame_size = */ 16384
};

static const h2o_buf_t SETTINGS_HOST_BIN = {
    H2O_STRLIT(
        "\x00\x00\x12" /* frame size */
        "\x04" /* settings frame */
        "\x00" /* no flags */
        "\x00\x00\x00\x00" /* stream id */
        "\x00\x02" "\x00\x00\x00\x00" /* enable_push = 0 */
        "\x00\x03" "\x00\x00\x00\x64" /* max_concurrent_streams = 100 */
        "\x00\x04" "\x00\x04\x00\x00" /* initial_window_size = 262144 */
    )
};

static ssize_t expect_default(h2o_http2_conn_t *conn, const uint8_t *src, size_t len);
static void emit_writereq(h2o_timeout_entry_t *entry);
static void on_read(h2o_socket_t *sock, int status);

static void link_stream(h2o_http2_stream_t **slot, h2o_http2_stream_t *stream)
{
    assert(! h2o_http2_conn_stream_is_linked(stream));

    if (*slot == NULL) {
        *slot = stream->_link.prev = stream->_link.next = stream;
    } else {
        stream->_link.prev = (*slot)->_link.prev;
        stream->_link.next = *slot;
        (*slot)->_link.prev->_link.next = stream;
        (*slot)->_link.prev = stream;
    }
}

static h2o_http2_stream_t *unlink_stream(h2o_http2_stream_t **slot, h2o_http2_stream_t *stream)
{
    h2o_http2_stream_t *next;

    assert(h2o_http2_conn_stream_is_linked(stream));

    if (stream->_link.prev == stream) {
        /* is the only entry */
        assert(*slot == stream);
        *slot = NULL;
        next = NULL;
    } else {
        if (*slot == stream)
            *slot = stream->_link.next;
        stream->_link.prev->_link.next = stream->_link.next;
        stream->_link.next->_link.prev = stream->_link.prev;
        next = stream->_link.next;
    }
    stream->_link.prev = stream->_link.next = NULL;
    return next;
}

static void run_pending_requests(h2o_http2_conn_t *conn)
{
    while (conn->num_responding_streams < conn->super.ctx->global_config->http2_max_concurrent_requests_per_connection) {
        h2o_http2_stream_t *stream;
        if (conn->_pending_reqs == NULL)
            break;
        /* fetch and detach a pending stream */
        stream = conn->_pending_reqs;
        unlink_stream(&conn->_pending_reqs, stream);
        /* handle it */
        assert(stream->state == H2O_HTTP2_STREAM_STATE_REQ_PENDING);
        ++conn->num_responding_streams;
        stream->state = H2O_HTTP2_STREAM_STATE_SEND_HEADERS;
        if (conn->max_processed_stream_id < stream->stream_id)
            conn->max_processed_stream_id = stream->stream_id;
        h2o_process_request(&stream->req);
    }
}

static void execute_or_enqueue_request(h2o_http2_conn_t *conn, h2o_http2_stream_t *stream)
{
    assert(stream->state < H2O_HTTP2_STREAM_STATE_REQ_PENDING);
    stream->state = H2O_HTTP2_STREAM_STATE_REQ_PENDING;
    link_stream(&conn->_pending_reqs, stream);
    run_pending_requests(conn);
}

void h2o_http2_conn_register_stream(h2o_http2_conn_t *conn, h2o_http2_stream_t *stream)
{
    khiter_t iter;
    int r;

    assert(conn->max_open_stream_id < stream->stream_id);
    conn->max_open_stream_id = stream->stream_id;

    iter = kh_put(h2o_http2_stream_t, conn->open_streams, stream->stream_id, &r);
    assert(iter != kh_end(conn->open_streams));
    kh_val(conn->open_streams, iter) = stream;
}

void h2o_http2_conn_unregister_stream(h2o_http2_conn_t *conn, h2o_http2_stream_t *stream)
{
    khiter_t iter = kh_get(h2o_http2_stream_t, conn->open_streams, stream->stream_id);
    assert(iter != kh_end(conn->open_streams));
    kh_del(h2o_http2_stream_t, conn->open_streams, iter);

    switch (stream->state) {
    case H2O_HTTP2_STREAM_STATE_RECV_PSUEDO_HEADERS:
    case H2O_HTTP2_STREAM_STATE_RECV_HEADERS:
    case H2O_HTTP2_STREAM_STATE_RECV_BODY:
        assert(! h2o_http2_conn_stream_is_linked(stream));
        break;
    case H2O_HTTP2_STREAM_STATE_REQ_PENDING:
        if (h2o_http2_conn_stream_is_linked(stream)) {
            unlink_stream(&conn->_pending_reqs, stream);
        }
        break;
    case H2O_HTTP2_STREAM_STATE_SEND_HEADERS:
    case H2O_HTTP2_STREAM_STATE_SEND_BODY:
    case H2O_HTTP2_STREAM_STATE_END_STREAM:
        --conn->num_responding_streams;
        if (h2o_http2_conn_stream_is_linked(stream)) {
            unlink_stream(
                h2o_http2_stream_has_pending_data(stream) ? &conn->_write.streams_with_pending_data : &conn->_write.streams_without_pending_data,
                stream);
        }
        break;
    }

    if (conn->state != H2O_HTTP2_CONN_STATE_IS_CLOSING)
        run_pending_requests(conn);
}

static void close_connection_now(h2o_http2_conn_t *conn)
{
    h2o_http2_stream_t *stream;

    assert(! h2o_timeout_is_linked(&conn->_write.timeout_entry));

    kh_foreach_value(conn->open_streams, stream, {
        h2o_http2_stream_close(conn, stream);
    });
    kh_destroy(h2o_http2_stream_t, conn->open_streams);
    assert(conn->_http1_req_input == NULL);
    h2o_hpack_dispose_header_table(&conn->_input_header_table);
    h2o_hpack_dispose_header_table(&conn->_output_header_table);
    assert(conn->_pending_reqs == NULL);
    h2o_mempool_clear(&conn->_write._pools[0]);
    h2o_mempool_clear(&conn->_write._pools[1]);
    assert(conn->_write.streams_with_pending_data == NULL);
    assert(conn->_write.streams_without_pending_data == NULL);
    assert(! h2o_timeout_is_linked(&conn->_write.timeout_entry));

    h2o_socket_close(conn->sock);
    if (conn->super.ctx->global_config->close_cb != NULL)
        conn->super.ctx->global_config->close_cb(conn->super.ctx);
    free(conn);
}

static void close_connection(h2o_http2_conn_t *conn)
{
    conn->state = H2O_HTTP2_CONN_STATE_IS_CLOSING;

    if (conn->_write.wreq_in_flight) {
        /* there is a pending write, let on_write_complete actually close the connection */
    } else {
        if (h2o_timeout_is_linked(&conn->_write.timeout_entry))
            h2o_timeout_unlink(&conn->_write.timeout_entry);
        close_connection_now(conn);
    }
}

static void enqueue_goaway_and_initiate_close(h2o_http2_conn_t *conn, int errnum)
{
    h2o_buf_t goaway = h2o_http2_encode_goaway_frame(conn->_write.pool, conn->max_processed_stream_id, -errnum);
    h2o_http2_conn_enqueue_write(conn, goaway);
    conn->state = H2O_HTTP2_CONN_STATE_IS_CLOSING;
}

static void send_error(h2o_http2_conn_t *conn, uint32_t stream_id, int errnum)
{
    assert(conn->state != H2O_HTTP2_CONN_STATE_IS_CLOSING);

    if (stream_id != 0) {
        h2o_buf_t rst_frame = h2o_http2_encode_rst_stream_frame(conn->_write.pool, stream_id, -errnum);
        h2o_http2_conn_enqueue_write(conn, rst_frame);
    } else {
        enqueue_goaway_and_initiate_close(conn, errnum);
    }
}

static void request_gathered_write(h2o_http2_conn_t *conn)
{
    assert(conn->state != H2O_HTTP2_CONN_STATE_IS_CLOSING);
    if (conn->_write.wreq_in_flight) {
        conn->_write.write_once_more = 1;
    } else {
        if (! h2o_timeout_is_linked(&conn->_write.timeout_entry))
            h2o_timeout_link(conn->super.ctx->loop, &conn->super.ctx->zero_timeout, &conn->_write.timeout_entry);
    }
}

/* handles HEADERS frame or succeeding CONTINUATION frames */
static void handle_incoming_request(h2o_http2_conn_t *conn, h2o_http2_stream_t *stream, const uint8_t *src, size_t len, int is_end_of_headers)
{
    int allow_psuedo = stream->state == H2O_HTTP2_STREAM_STATE_RECV_PSUEDO_HEADERS;
    if (h2o_hpack_parse_headers(&stream->req, &conn->_input_header_table, &allow_psuedo, src, len) != 0) {
        send_error(conn, stream->stream_id, H2O_HTTP2_ERROR_COMPRESSION);
        return;
    }
    if (! allow_psuedo)
        stream->state = H2O_HTTP2_STREAM_STATE_RECV_HEADERS;

    if (! is_end_of_headers) {
        /* FIXME request timeout? */
        return;
    }

    /* handle the request */
    conn->_read_expect = expect_default;
    if (kh_size(conn->open_streams) <= H2O_HTTP2_SETTINGS_HOST.max_concurrent_streams) {
        if (stream->is_half_closed) {
            execute_or_enqueue_request(conn, stream);
        } else {
            stream->state = H2O_HTTP2_STREAM_STATE_RECV_BODY;
        }
    } else {
        send_error(conn, stream->stream_id, H2O_HTTP2_ERROR_ENHANCE_YOUR_CALM);
        h2o_http2_stream_close(conn, stream);
    }
}

static ssize_t expect_continuation_of_headers(h2o_http2_conn_t *conn, const uint8_t *src, size_t len)
{
    h2o_http2_frame_t frame;
    ssize_t ret;
    h2o_http2_stream_t *stream;

    if ((ret = h2o_http2_decode_frame(&frame, src, len, &H2O_HTTP2_SETTINGS_HOST)) < 0)
        return ret;

    if (! (frame.type == H2O_HTTP2_FRAME_TYPE_CONTINUATION && frame.stream_id == conn->max_open_stream_id))
        return H2O_HTTP2_ERROR_PROTOCOL;

    stream = h2o_http2_conn_get_stream(conn, conn->max_open_stream_id);
    handle_incoming_request(
        conn,
        stream,
        frame.payload,
        frame.length,
        (frame.flags & H2O_HTTP2_FRAME_FLAG_END_HEADERS) != 0);

    return ret;
}

static void update_input_window(h2o_http2_conn_t *conn, uint32_t stream_id, h2o_http2_window_t *window, size_t consumed)
{
    h2o_http2_window_consume_window(window, consumed);
    if (h2o_http2_window_get_window(window) * 2 < H2O_HTTP2_SETTINGS_HOST.initial_window_size) {
        h2o_http2_conn_enqueue_write(conn, h2o_http2_encode_window_update_frame(conn->_write.pool, stream_id, H2O_HTTP2_SETTINGS_HOST.initial_window_size));
        h2o_http2_window_update(window, H2O_HTTP2_SETTINGS_HOST.initial_window_size);
    }
}

static void handle_data_frame(h2o_http2_conn_t *conn, h2o_http2_frame_t *frame)
{
    h2o_http2_data_payload_t payload;
    h2o_http2_stream_t *stream;

    if (frame->stream_id == 0 || h2o_http2_decode_data_payload(&payload, frame) != 0) {
        send_error(conn, 0, H2O_HTTP2_ERROR_PROTOCOL);
        return;
    }

    stream = h2o_http2_conn_get_stream(conn, frame->stream_id);

    /* save the input in the request body buffer, or send error (and close the stream) */
    if (stream == NULL) {
        send_error(conn, frame->stream_id, H2O_HTTP2_ERROR_STREAM_CLOSED);
        stream = NULL;
    } else if (stream->state != H2O_HTTP2_STREAM_STATE_RECV_BODY) {
        send_error(conn, frame->stream_id, H2O_HTTP2_ERROR_STREAM_CLOSED);
        h2o_http2_stream_reset(conn, stream, H2O_HTTP2_ERROR_NONE);
        stream = NULL;
    } else {
        h2o_buf_t buf = h2o_reserve_input_buffer(&stream->_req_body, payload.length);
        memcpy(buf.base, payload.data, payload.length);
        stream->_req_body->size += payload.length;
        /* handle request if request body is complete */
        if ((frame->flags & H2O_HTTP2_FRAME_FLAG_END_STREAM) != 0) {
            stream->is_half_closed = 1;
            execute_or_enqueue_request(conn, stream);
            stream = NULL; /* no need to send window update for this stream */
        }
    }

    /* consume input buffer (and set window_update) */
    update_input_window(conn, 0, &conn->_input_window, frame->length);
    if (stream != NULL)
        update_input_window(conn, stream->stream_id, &stream->input_window, frame->length);
}

static void handle_headers_frame(h2o_http2_conn_t *conn, h2o_http2_frame_t *frame)
{
    h2o_http2_headers_payload_t payload;
    h2o_http2_stream_t *stream;

    if (frame->stream_id == 0
        || ! (conn->max_open_stream_id < frame->stream_id)
        || h2o_http2_decode_headers_payload(&payload, frame) != 0) {
        send_error(conn, 0, H2O_HTTP2_ERROR_PROTOCOL);
        return;
    }

    conn->_read_expect = expect_continuation_of_headers;

    stream = h2o_http2_stream_open(conn, frame->stream_id, NULL);
    stream->is_half_closed = (frame->flags & H2O_HTTP2_FRAME_FLAG_END_STREAM) != 0;
    handle_incoming_request(
        conn,
        stream,
        payload.headers,
        payload.headers_len,
        (frame->flags & H2O_HTTP2_FRAME_FLAG_END_HEADERS) != 0);
}

static void resume_send(h2o_http2_conn_t *conn)
{
    if (h2o_http2_window_get_window(&conn->_write.window) <= 0)
        return;
    if (conn->_write.streams_with_pending_data == NULL)
        return;
    request_gathered_write(conn);
}

static void handle_settings_frame(h2o_http2_conn_t *conn, h2o_http2_frame_t *frame)
{
    if (frame->stream_id != 0) {
        send_error(conn, 0, H2O_HTTP2_ERROR_PROTOCOL);
        return;
    }

    if ((frame->flags & H2O_HTTP2_FRAME_FLAG_ACK) != 0) {
        if (frame->length != 0) {
            send_error(conn, 0, H2O_HTTP2_ERROR_FRAME_SIZE);
            return;
        }
    } else {
        uint32_t prev_initial_window_size = conn->peer_settings.initial_window_size;
        /* FIXME handle SETTINGS_HEADER_TABLE_SIZE */
        if (h2o_http2_update_peer_settings(&conn->peer_settings, frame->payload, frame->length) != 0) {
            send_error(conn, 0, H2O_HTTP2_ERROR_PROTOCOL);
            return;
        }
        { /* schedule ack */
            uint8_t *header_buf = h2o_mempool_alloc(conn->_write.pool, H2O_HTTP2_FRAME_HEADER_SIZE);
            h2o_http2_encode_frame_header(header_buf, 0, H2O_HTTP2_FRAME_TYPE_SETTINGS, H2O_HTTP2_FRAME_FLAG_ACK, 0);
            h2o_http2_conn_enqueue_write(conn, h2o_buf_init(header_buf, H2O_HTTP2_FRAME_HEADER_SIZE));
        }
        /* apply the change to window size */
        if (prev_initial_window_size != conn->peer_settings.initial_window_size) {
            ssize_t delta = conn->peer_settings.initial_window_size - prev_initial_window_size;
            h2o_http2_stream_t *stream;
            kh_foreach_value(conn->open_streams, stream, {
                h2o_http2_window_update(&stream->output_window, delta);
            });
            h2o_http2_window_update(&conn->_write.window, delta);
            resume_send(conn);
        }
    }
}

static void handle_window_update_frame(h2o_http2_conn_t *conn, h2o_http2_frame_t *frame)
{
    h2o_http2_window_update_payload_t payload;

    if (h2o_http2_decode_window_update_payload(&payload, frame) != 0) {
        send_error(conn, frame->stream_id, H2O_HTTP2_ERROR_PROTOCOL);
        return;
    }

    if (frame->stream_id == 0) {
        h2o_http2_window_update(&conn->_write.window, payload.window_size_increment);
    } else if (frame->stream_id <= conn->max_open_stream_id) {
        h2o_http2_stream_t *stream = h2o_http2_conn_get_stream(conn, frame->stream_id);
        if (stream != NULL) {
            h2o_http2_window_update(&stream->output_window, payload.window_size_increment);
        }
    } else {
        send_error(conn, 0, H2O_HTTP2_ERROR_FLOW_CONTROL);
        return;
    }

    resume_send(conn);
}

static void handle_goaway_frame(h2o_http2_conn_t *conn, h2o_http2_frame_t *frame)
{
    h2o_http2_goaway_payload_t payload;

    assert(conn->state == H2O_HTTP2_CONN_STATE_OPEN);

    if (frame->stream_id != 0 || h2o_http2_decode_goaway_payload(&payload, frame) != 0) {
        send_error(conn, 0, H2O_HTTP2_ERROR_PROTOCOL);
        return;
    }

    /* nothing to do, since we do not open new streams by ourselves */
}

static void handle_ping_frame(h2o_http2_conn_t *conn, h2o_http2_frame_t *frame)
{
    h2o_http2_ping_payload_t payload;
    h2o_buf_t pong;

    if (frame->stream_id != 0 || h2o_http2_decode_ping_payload(&payload, frame) != 0) {
        send_error(conn, 0, H2O_HTTP2_ERROR_PROTOCOL);
        return;
    }

    pong = h2o_http2_encode_ping_frame(conn->_write.pool, 1, payload.data);
    h2o_http2_conn_enqueue_write(conn, pong);
}

static void handle_rst_stream_frame(h2o_http2_conn_t *conn, h2o_http2_frame_t *frame)
{
    h2o_http2_rst_stream_payload_t payload;
    h2o_http2_stream_t *stream;

    if (frame->stream_id == 0
        || conn->max_open_stream_id < frame->stream_id
        || h2o_http2_decode_rst_stream_payload(&payload, frame) != 0) {
        send_error(conn, 0, H2O_HTTP2_ERROR_PROTOCOL);
        return;
    }

    stream = h2o_http2_conn_get_stream(conn, frame->stream_id);
    if (stream != NULL) {
        /* reset the stream */
        h2o_http2_stream_reset(conn, stream, -payload.error_code);
    }
    /* TODO log */
}

static void handle_frame_as_protocol_error(h2o_http2_conn_t *conn, h2o_http2_frame_t *frame)
{
    fprintf(stderr, "received an unexpected frame (type:%d)\n", frame->type);
    send_error(conn, 0, H2O_HTTP2_ERROR_PROTOCOL);
}

static void handle_frame_skip(h2o_http2_conn_t *conn, h2o_http2_frame_t *frame)
{
    fprintf(stderr, "skipping frame (type:%d)\n", frame->type);
}

ssize_t expect_default(h2o_http2_conn_t *conn, const uint8_t *src, size_t len)
{
    h2o_http2_frame_t frame;
    ssize_t ret;
    static void (*FRAME_HANDLERS[])(h2o_http2_conn_t *conn, h2o_http2_frame_t *frame) = {
        handle_data_frame,              /* DATA */
        handle_headers_frame,
        handle_frame_skip,              /* PRIORITY */
        handle_rst_stream_frame,
        handle_settings_frame,
        handle_frame_as_protocol_error, /* PUSH_PROMISE */
        handle_ping_frame,
        handle_goaway_frame,
        handle_window_update_frame,
        handle_frame_as_protocol_error  /* CONTINUATION */
    };

    if ((ret = h2o_http2_decode_frame(&frame, src, len, &H2O_HTTP2_SETTINGS_HOST)) < 0)
        return ret;

    if (frame.type < sizeof(FRAME_HANDLERS) / sizeof(FRAME_HANDLERS[0])) {
        FRAME_HANDLERS[frame.type](conn, &frame);
    } else {
        fprintf(stderr, "skipping frame (type:%d)\n", frame.type);
    }

    return ret;
}

static ssize_t expect_preface(h2o_http2_conn_t *conn, const uint8_t *src, size_t len)
{
    if (len < CONNECTION_PREFACE.len) {
        return H2O_HTTP2_ERROR_INCOMPLETE;
    }
    if (memcmp(src, CONNECTION_PREFACE.base, CONNECTION_PREFACE.len) != 0) {
        return H2O_HTTP2_ERROR_PROTOCOL_CLOSE_IMMEDIATELY;
    }

    conn->_read_expect = expect_default;
    return CONNECTION_PREFACE.len;
}

static void parse_input(h2o_http2_conn_t *conn)
{
    size_t http2_max_concurrent_requests_per_connection = conn->super.ctx->global_config->http2_max_concurrent_requests_per_connection;
    int perform_early_exit = 0;

    if (conn->num_responding_streams != http2_max_concurrent_requests_per_connection)
        perform_early_exit = 1;

    /* handle the input */
    while (conn->state != H2O_HTTP2_CONN_STATE_IS_CLOSING && conn->sock->input->size != 0) {
        if (perform_early_exit == 1 && conn->num_responding_streams == http2_max_concurrent_requests_per_connection)
            goto EarlyExit;
        /* process a frame */
        ssize_t ret = conn->_read_expect(conn, (uint8_t*)conn->sock->input->bytes, conn->sock->input->size);
        if (ret == H2O_HTTP2_ERROR_INCOMPLETE) {
            break;
        } else if (ret < 0) {
            switch (ret) {
            default:
                /* send error */
                send_error(conn, 0, (int)-ret);
                /* fallthru */
            case H2O_HTTP2_ERROR_PROTOCOL_CLOSE_IMMEDIATELY:
                close_connection(conn);
                break;
            }
            break;
        }
        /* advance to the next frame */
        h2o_consume_input_buffer(&conn->sock->input, ret);
    }

    if (! h2o_socket_is_reading(conn->sock))
        h2o_socket_read_start(conn->sock, on_read);
    return;

EarlyExit:
    if (h2o_socket_is_reading(conn->sock))
        h2o_socket_read_stop(conn->sock);
}

static void on_read(h2o_socket_t *sock, int status)
{
    h2o_http2_conn_t *conn = sock->data;

    if (status != 0) {
        h2o_socket_read_stop(conn->sock);
        close_connection(conn);
        return;
    }

    parse_input(conn);
}

static void on_upgrade_complete(void *_conn, h2o_socket_t *sock, size_t reqsize)
{
    h2o_http2_conn_t *conn = _conn;

    if (sock == NULL) {
        close_connection(conn);
        return;
    }

    conn->sock = sock;
    sock->data = conn;
    conn->_http1_req_input = sock->input;
    h2o_init_input_buffer(&sock->input);

    /* setup inbound */
    h2o_socket_read_start(conn->sock, on_read);

    /* handle the request */
    execute_or_enqueue_request(conn, h2o_http2_conn_get_stream(conn, 1));

    if (conn->_http1_req_input->size != reqsize) {
        /* FIXME copy the remaining data to conn->_input and call handle_input */
        assert(0);
    }
}

void h2o_http2_conn_enqueue_write(h2o_http2_conn_t *conn, h2o_buf_t buf)
{
    if (conn->state == H2O_HTTP2_CONN_STATE_IS_CLOSING)
        return;
    request_gathered_write(conn);
    h2o_vector_reserve(conn->_write.pool, (h2o_vector_t*)&conn->_write.bufs, sizeof(h2o_buf_t), conn->_write.bufs.size + 1);
    conn->_write.bufs.entries[conn->_write.bufs.size++] = buf;
}

void h2o_http2_conn_register_for_proceed_callback(h2o_http2_conn_t *conn, h2o_http2_stream_t *stream)
{
    request_gathered_write(conn);
    link_stream(
        h2o_http2_stream_has_pending_data(stream) ? &conn->_write.streams_with_pending_data : &conn->_write.streams_without_pending_data,
        stream);
}

static void on_write_complete(h2o_socket_t *sock, int status)
{
    h2o_http2_conn_t *conn = sock->data;

    assert(conn->_write.wreq_in_flight);

    /* close by error if necessary */
    if (status != 0) {
        close_connection_now(conn);
        return;
    }

    /* reset the other memory pool */
    h2o_mempool_clear(conn->_write._pools + (conn->_write.pool == conn->_write._pools));

    /* call the proceed callback of the streams that have been flushed (while unlinking them from the list) */
    if (status == 0 && conn->state == H2O_HTTP2_CONN_STATE_OPEN && conn->_write.streams_without_pending_data != NULL) {
        h2o_http2_stream_t *streams_to_proceed = conn->_write.streams_without_pending_data;
        conn->_write.streams_without_pending_data = NULL;
        while (streams_to_proceed != NULL) {
            h2o_http2_stream_t *stream = streams_to_proceed;
            assert(! h2o_http2_stream_has_pending_data(stream));
            unlink_stream(&streams_to_proceed, stream);
            h2o_http2_stream_proceed(conn, stream);
        }
    }

    /* trigger write once more immediately (if necesssary) */
    conn->_write.wreq_in_flight = 0;
    if (conn->_write.write_once_more) {
        conn->_write.write_once_more = 0;
        emit_writereq(&conn->_write.timeout_entry);
        return;
    }

    assert(conn->_write.bufs.size == 0);

    /* close the connection if necessary */
    if (conn->state == H2O_HTTP2_CONN_STATE_IS_CLOSING) {
        close_connection_now(conn);
        return;
    }

    /* start receiving input if necessary, as well as parse the pending input */
    if (conn->sock->input->size != 0)
        parse_input(conn);
}

void emit_writereq(h2o_timeout_entry_t *entry)
{
    h2o_http2_conn_t *conn = H2O_STRUCT_FROM_MEMBER(h2o_http2_conn_t, _write.timeout_entry, entry);

    assert(! conn->_write.wreq_in_flight);
    assert(! conn->_write.write_once_more);
    conn->_write.wreq_in_flight = 1;

    /* push DATA frames */
    if (conn->state == H2O_HTTP2_CONN_STATE_OPEN && conn->_write.streams_with_pending_data != NULL) {
        h2o_http2_stream_t *stream = conn->_write.streams_with_pending_data, * next;
        do {
            if (h2o_http2_window_get_window(&conn->_write.window) <= 0)
                break;
            assert(h2o_http2_stream_has_pending_data(stream));
            h2o_http2_stream_send_pending_data(conn, stream);
            if ((next = stream->_link.next) == conn->_write.streams_with_pending_data)
                next = NULL;
            if (! h2o_http2_stream_has_pending_data(stream)) {
                unlink_stream(&conn->_write.streams_with_pending_data, stream);
                link_stream(&conn->_write.streams_without_pending_data, stream);
            }
        } while ((stream = next) != NULL);
    }

    if (conn->_write.bufs.size != 0) {
        h2o_socket_write(conn->sock, conn->_write.bufs.entries, (int)conn->_write.bufs.size, on_write_complete);
        conn->_write.pool = conn->_write._pools + (conn->_write.pool == conn->_write._pools); /* flip the memory pool */
        memset(&conn->_write.bufs, 0, sizeof(conn->_write.bufs));
        conn->_write.write_once_more = 0;
    } else {
        conn->_write.wreq_in_flight = 0;
        /* assert that memory pool is empty */
    }
}

static h2o_http2_conn_t *create_conn(h2o_context_t *ctx, h2o_socket_t *sock, struct sockaddr *addr, socklen_t addrlen)
{
    h2o_http2_conn_t *conn = h2o_malloc(sizeof(*conn));

    /* init the connection */
    memset(conn, 0, offsetof(h2o_http2_conn_t, _write._pools[0]));
    conn->super.ctx = ctx;
    conn->super.peername.addr = addr;
    conn->super.peername.len = addrlen;
    conn->sock = sock;
    conn->peer_settings = H2O_HTTP2_SETTINGS_DEFAULT;
    conn->open_streams = kh_init(h2o_http2_stream_t);
    conn->state = H2O_HTTP2_CONN_STATE_OPEN;
    conn->_read_expect = expect_preface;
    conn->_input_header_table.hpack_capacity = H2O_HTTP2_SETTINGS_DEFAULT.header_table_size;
    h2o_http2_window_init(&conn->_input_window, &H2O_HTTP2_SETTINGS_HOST);
    conn->_write.pool = conn->_write._pools;
    conn->_output_header_table.hpack_capacity = H2O_HTTP2_SETTINGS_HOST.header_table_size;
    conn->_write.timeout_entry.cb = emit_writereq;
    h2o_http2_window_init(&conn->_write.window, &conn->peer_settings);
    h2o_mempool_init(conn->_write._pools);
    h2o_mempool_init(conn->_write._pools + 1);

    return conn;
}

void h2o_http2_accept(h2o_context_t *ctx, h2o_socket_t *sock)
{
    h2o_http2_conn_t *conn = create_conn(ctx, sock, (void*)&sock->peername.addr, sock->peername.len);
    sock->data = conn;
    h2o_socket_read_start(conn->sock, on_read);
    if (sock->input->size != 0)
        on_read(sock, 0);
}

int h2o_http2_handle_upgrade(h2o_req_t *req)
{
    h2o_http2_conn_t *http2conn = create_conn(req->conn->ctx, NULL, req->conn->peername.addr, req->conn->peername.len);
    h2o_http1_conn_t *req_conn = (h2o_http1_conn_t*)req->conn;
    ssize_t connection_index, settings_index;
    h2o_buf_t settings_decoded;

    assert(req->version < 0x200); /* from HTTP/1.x */

    /* check that "HTTP2-Settings" is declared in the connection header */
    connection_index = h2o_find_header(&req->headers, H2O_TOKEN_CONNECTION, -1);
    assert(connection_index != -1);
    if (! h2o_contains_token(req->headers.entries[connection_index].value.base, req->headers.entries[connection_index].value.len, H2O_STRLIT("http2-settings"))) {
        goto Error;
    }

    /* decode the settings */
    if ((settings_index = h2o_find_header(&req->headers, H2O_TOKEN_HTTP2_SETTINGS, -1)) == -1) {
        goto Error;
    }
    if ((settings_decoded = h2o_decode_base64url(&req->pool, req->headers.entries[settings_index].value.base, req->headers.entries[settings_index].value.len)).base == NULL) {
        goto Error;
    }
    if (h2o_http2_update_peer_settings(&http2conn->peer_settings, (uint8_t*)settings_decoded.base, settings_decoded.len) != 0) {
        goto Error;
    }

    /* open the stream, now that the function is guaranteed to succeed */
    h2o_http2_stream_open(http2conn, 1, req);

    /* send response */
    req->res.status = 101;
    req->res.reason = "Switching Protocols";
    h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_UPGRADE, H2O_STRLIT("h2c"));
    h2o_http1_upgrade(req_conn, (h2o_buf_t*)&SETTINGS_HOST_BIN, 1, on_upgrade_complete, http2conn);

    return 0;
Error:
    free(http2conn);
    return -1;
}
