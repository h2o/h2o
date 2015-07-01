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
#include "h2o/http2_internal.h"

static const h2o_iovec_t CONNECTION_PREFACE = {H2O_STRLIT("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")};

/* h2-14 and h2-16 are kept for backwards compatibility, as they are often used */
static const h2o_iovec_t alpn_protocols[] = {{H2O_STRLIT("h2")}, {H2O_STRLIT("h2-16")}, {H2O_STRLIT("h2-14")}, {NULL, 0}};
const h2o_iovec_t *h2o_http2_alpn_protocols = alpn_protocols;
/* npn defs should match the definition of alpn_protocols */
const char *h2o_http2_npn_protocols = "\x02"
                                      "h2"
                                      "\x05"
                                      "h2-16"
                                      "\x05"
                                      "h2-14";

const h2o_http2_priority_t h2o_http2_default_priority = {
    0, /* exclusive */
    0, /* dependency */
    16 /* weight */
};

const h2o_http2_settings_t H2O_HTTP2_SETTINGS_HOST = {
    4096,   /* header_table_size */
    0,      /* enable_push */
    100,    /* max_concurrent_streams */
    262144, /* initial_window_size */
    16384   /* max_frame_size */
};

static const h2o_iovec_t SETTINGS_HOST_BIN = {H2O_STRLIT("\x00\x00\x12"     /* frame size */
                                                         "\x04"             /* settings frame */
                                                         "\x00"             /* no flags */
                                                         "\x00\x00\x00\x00" /* stream id */
                                                         "\x00\x02"
                                                         "\x00\x00\x00\x00" /* enable_push = 0 */
                                                         "\x00\x03"
                                                         "\x00\x00\x00\x64" /* max_concurrent_streams = 100 */
                                                         "\x00\x04"
                                                         "\x00\x04\x00\x00" /* initial_window_size = 262144 */
                                                         )};

static __thread h2o_buffer_prototype_t wbuf_buffer_prototype = {{16}, {H2O_HTTP2_DEFAULT_OUTBUF_SIZE}};

static void initiate_graceful_shutdown(h2o_context_t *ctx);
static void close_connection(h2o_http2_conn_t *conn);
static void send_stream_error(h2o_http2_conn_t *conn, uint32_t stream_id, int errnum);
static ssize_t expect_default(h2o_http2_conn_t *conn, const uint8_t *src, size_t len, const char **err_desc);
static int do_emit_writereq(h2o_http2_conn_t *conn);
static void on_read(h2o_socket_t *sock, int status);

const h2o_protocol_callbacks_t H2O_HTTP2_CALLBACKS = {initiate_graceful_shutdown};

static int is_idle_stream_id(h2o_http2_conn_t *conn, uint32_t stream_id)
{
    return (h2o_http2_stream_is_push(stream_id) ? conn->push_stream_ids.max_open : conn->pull_stream_ids.max_open) < stream_id;
}

static void enqueue_goaway(h2o_http2_conn_t *conn, int errnum, h2o_iovec_t additional_data)
{
    if (conn->state < H2O_HTTP2_CONN_STATE_IS_CLOSING) {
        /* http2 spec allows sending GOAWAY more than once (for one reason since errors may arise after sending the first one) */
        h2o_http2_encode_goaway_frame(&conn->_write.buf, conn->pull_stream_ids.max_open, errnum, additional_data);
        h2o_http2_conn_request_write(conn);
        conn->state = H2O_HTTP2_CONN_STATE_HALF_CLOSED;
    }
}

static void graceful_shutdown_resend_goaway(h2o_timeout_entry_t *entry)
{
    h2o_context_t *ctx = H2O_STRUCT_FROM_MEMBER(h2o_context_t, http2._graceful_shutdown_timeout, entry);
    h2o_linklist_t *node;

    for (node = ctx->http2._conns.next; node != &ctx->http2._conns; node = node->next) {
        h2o_http2_conn_t *conn = H2O_STRUCT_FROM_MEMBER(h2o_http2_conn_t, _conns, node);
        if (conn->state < H2O_HTTP2_CONN_STATE_HALF_CLOSED)
            enqueue_goaway(conn, H2O_HTTP2_ERROR_NONE, (h2o_iovec_t){});
    }
}

static void initiate_graceful_shutdown(h2o_context_t *ctx)
{
    /* draft-16 6.8
     * A server that is attempting to gracefully shut down a connection SHOULD send an initial GOAWAY frame with the last stream
     * identifier set to 231-1 and a NO_ERROR code. This signals to the client that a shutdown is imminent and that no further
     * requests can be initiated. After waiting at least one round trip time, the server can send another GOAWAY frame with an
     * updated last stream identifier. This ensures that a connection can be cleanly shut down without losing requests.
     */
    h2o_linklist_t *node;

    /* only doit once */
    if (ctx->http2._graceful_shutdown_timeout.cb != NULL)
        return;
    ctx->http2._graceful_shutdown_timeout.cb = graceful_shutdown_resend_goaway;

    for (node = ctx->http2._conns.next; node != &ctx->http2._conns; node = node->next) {
        h2o_http2_conn_t *conn = H2O_STRUCT_FROM_MEMBER(h2o_http2_conn_t, _conns, node);
        if (conn->state < H2O_HTTP2_CONN_STATE_HALF_CLOSED) {
            h2o_http2_encode_goaway_frame(&conn->_write.buf, INT32_MAX, H2O_HTTP2_ERROR_NONE,
                                          (h2o_iovec_t){H2O_STRLIT("graceful shutdown")});
            h2o_http2_conn_request_write(conn);
        }
    }
    h2o_timeout_link(ctx->loop, &ctx->one_sec_timeout, &ctx->http2._graceful_shutdown_timeout);
}

static void on_idle_timeout(h2o_timeout_entry_t *entry)
{
    h2o_http2_conn_t *conn = H2O_STRUCT_FROM_MEMBER(h2o_http2_conn_t, _timeout_entry, entry);

    enqueue_goaway(conn, H2O_HTTP2_ERROR_NONE, h2o_iovec_init(H2O_STRLIT("idle timeout")));
    close_connection(conn);
}

static void update_idle_timeout(h2o_http2_conn_t *conn)
{
    h2o_timeout_unlink(&conn->_timeout_entry);

    if (conn->num_streams.responding == 0) {
        assert(h2o_linklist_is_empty(&conn->_pending_reqs));
        conn->_timeout_entry.cb = on_idle_timeout;
        h2o_timeout_link(conn->super.ctx->loop, &conn->super.ctx->http2.idle_timeout, &conn->_timeout_entry);
    }
}

static void run_pending_requests(h2o_http2_conn_t *conn)
{
    conn->_is_dispatching_pending_reqs = 1;

    while (!h2o_linklist_is_empty(&conn->_pending_reqs) &&
           conn->num_streams.responding < conn->super.ctx->globalconf->http2.max_concurrent_requests_per_connection) {
        /* fetch and detach a pending stream */
        h2o_http2_stream_t *stream = H2O_STRUCT_FROM_MEMBER(h2o_http2_stream_t, _refs.link, conn->_pending_reqs.next);
        h2o_linklist_unlink(&stream->_refs.link);
        /* handle it */
        h2o_http2_stream_set_state(conn, stream, H2O_HTTP2_STREAM_STATE_SEND_HEADERS);
        if (!h2o_http2_stream_is_push(stream->stream_id) && conn->pull_stream_ids.max_processed < stream->stream_id)
            conn->pull_stream_ids.max_processed = stream->stream_id;
        h2o_process_request(&stream->req);
    }

    conn->_is_dispatching_pending_reqs = 0;
}

static void execute_or_enqueue_request(h2o_http2_conn_t *conn, h2o_http2_stream_t *stream)
{
    assert(stream->state < H2O_HTTP2_STREAM_STATE_REQ_PENDING);

    if (stream->_req_body != NULL && stream->_expected_content_length != SIZE_MAX &&
        stream->_req_body->size != stream->_expected_content_length) {
        send_stream_error(conn, stream->stream_id, H2O_HTTP2_ERROR_PROTOCOL);
        h2o_http2_stream_reset(conn, stream);
        return;
    }

    h2o_http2_stream_set_state(conn, stream, H2O_HTTP2_STREAM_STATE_REQ_PENDING);

    /* TODO schedule the pending reqs using the scheduler */
    h2o_linklist_insert(&conn->_pending_reqs, &stream->_refs.link);

    if (conn->_is_dispatching_pending_reqs)
        return;

    run_pending_requests(conn);
    update_idle_timeout(conn);
}

void h2o_http2_conn_register_stream(h2o_http2_conn_t *conn, h2o_http2_stream_t *stream)
{
    khiter_t iter;
    int r;

    if (!h2o_http2_stream_is_push(stream->stream_id) && conn->pull_stream_ids.max_open < stream->stream_id)
        conn->pull_stream_ids.max_open = stream->stream_id;

    iter = kh_put(h2o_http2_stream_t, conn->streams, stream->stream_id, &r);
    assert(iter != kh_end(conn->streams));
    kh_val(conn->streams, iter) = stream;
}

void h2o_http2_conn_unregister_stream(h2o_http2_conn_t *conn, h2o_http2_stream_t *stream)
{
    khiter_t iter = kh_get(h2o_http2_stream_t, conn->streams, stream->stream_id);
    assert(iter != kh_end(conn->streams));
    kh_del(h2o_http2_stream_t, conn->streams, iter);

    assert(h2o_http2_scheduler_is_open(&stream->_refs.scheduler));
    h2o_http2_scheduler_close(&stream->_refs.scheduler);

    switch (stream->state) {
    case H2O_HTTP2_STREAM_STATE_IDLE:
    case H2O_HTTP2_STREAM_STATE_RECV_HEADERS:
    case H2O_HTTP2_STREAM_STATE_RECV_BODY:
        assert(!h2o_linklist_is_linked(&stream->_refs.link));
        break;
    case H2O_HTTP2_STREAM_STATE_REQ_PENDING:
        assert(h2o_linklist_is_linked(&stream->_refs.link));
        h2o_linklist_unlink(&stream->_refs.link);
        break;
    case H2O_HTTP2_STREAM_STATE_SEND_HEADERS:
    case H2O_HTTP2_STREAM_STATE_SEND_BODY:
    case H2O_HTTP2_STREAM_STATE_END_STREAM:
        if (h2o_linklist_is_linked(&stream->_refs.link))
            h2o_linklist_unlink(&stream->_refs.link);
        break;
    }
    if (stream->state != H2O_HTTP2_STREAM_STATE_END_STREAM)
        h2o_http2_stream_set_state(conn, stream, H2O_HTTP2_STREAM_STATE_END_STREAM);

    if (conn->state < H2O_HTTP2_CONN_STATE_IS_CLOSING) {
        run_pending_requests(conn);
        update_idle_timeout(conn);
    }
}

static void close_connection_now(h2o_http2_conn_t *conn)
{
    h2o_http2_stream_t *stream;

    assert(!h2o_timeout_is_linked(&conn->_write.timeout_entry));

    kh_foreach_value(conn->streams, stream, { h2o_http2_stream_close(conn, stream); });
    assert(conn->num_streams.open_pull == 0);
    assert(conn->num_streams.responding == 0);
    assert(conn->num_streams.open_priority == 0);
    kh_destroy(h2o_http2_stream_t, conn->streams);
    assert(conn->_http1_req_input == NULL);
    h2o_hpack_dispose_header_table(&conn->_input_header_table);
    h2o_hpack_dispose_header_table(&conn->_output_header_table);
    assert(h2o_linklist_is_empty(&conn->_pending_reqs));
    h2o_timeout_unlink(&conn->_timeout_entry);
    h2o_buffer_dispose(&conn->_write.buf);
    if (conn->_write.buf_in_flight != NULL)
        h2o_buffer_dispose(&conn->_write.buf_in_flight);
    h2o_http2_scheduler_dispose(&conn->scheduler);
    assert(h2o_linklist_is_empty(&conn->_write.streams_to_proceed));
    assert(!h2o_timeout_is_linked(&conn->_write.timeout_entry));
    h2o_linklist_unlink(&conn->_conns);

    h2o_socket_close(conn->sock);
    free(conn);
}

void close_connection(h2o_http2_conn_t *conn)
{
    conn->state = H2O_HTTP2_CONN_STATE_IS_CLOSING;

    if (conn->_write.buf_in_flight != NULL || h2o_timeout_is_linked(&conn->_write.timeout_entry)) {
        /* there is a pending write, let on_write_complete actually close the connection */
    } else {
        close_connection_now(conn);
    }
}

void send_stream_error(h2o_http2_conn_t *conn, uint32_t stream_id, int errnum)
{
    assert(stream_id != 0);
    assert(conn->state < H2O_HTTP2_CONN_STATE_IS_CLOSING);

    h2o_http2_encode_rst_stream_frame(&conn->_write.buf, stream_id, -errnum);
    h2o_http2_conn_request_write(conn);
}

static void request_gathered_write(h2o_http2_conn_t *conn)
{
    assert(conn->state < H2O_HTTP2_CONN_STATE_IS_CLOSING);
    if (conn->_write.buf_in_flight == NULL) {
        if (!h2o_timeout_is_linked(&conn->_write.timeout_entry))
            h2o_timeout_link(conn->super.ctx->loop, &conn->super.ctx->zero_timeout, &conn->_write.timeout_entry);
    }
}

static int update_stream_output_window(h2o_http2_stream_t *stream, ssize_t delta)
{
    ssize_t cur = h2o_http2_window_get_window(&stream->output_window);
    if (h2o_http2_window_update(&stream->output_window, delta) != 0)
        return -1;
    if (cur <= 0 && h2o_http2_window_get_window(&stream->output_window) > 0 && h2o_http2_stream_has_pending_data(stream)) {
        assert(!h2o_linklist_is_linked(&stream->_refs.link));
        h2o_http2_scheduler_activate(&stream->_refs.scheduler);
    }
    return 0;
}

static int is_blocking_asset(const char *path, size_t pathlen)
{
    size_t i;

    /* move pathlen to '?' */
    for (i = 0; i != pathlen; ++i) {
        if (path[i] == '?') {
            pathlen = i;
            break;
        }
    }

    /* check if end of path is either ".js" or ".css" */
    if (pathlen < 3)
        return 0;
    if (memcmp(path + pathlen - 3, ".js", 3) == 0)
        return 1;
    if (pathlen < 4)
        return 0;
    if (memcmp(path + pathlen - 4, ".css", 4) == 0)
        return 1;
    return 0;
}

static int handle_incoming_request(h2o_http2_conn_t *conn, h2o_http2_stream_t *stream, const uint8_t *src, size_t len,
                                   const char **err_desc)
{
    int ret, header_exists_map;

    assert(stream->state == H2O_HTTP2_STREAM_STATE_RECV_HEADERS);

    if ((ret = h2o_hpack_parse_headers(&stream->req, &conn->_input_header_table, src, len, &header_exists_map,
                                       &stream->_expected_content_length, err_desc)) != 0)
        return ret;

    /* raise the priority of asset files that block rendering to highest if the user-agent is not using sophisticated prioritization
     * logic (e.g. that of Firefox)
     */
    if (conn->num_streams.open_priority == 0 && conn->super.ctx->globalconf->http2.reprioritize_blocking_assets &&
        h2o_http2_scheduler_get_parent(&stream->_refs.scheduler) == &conn->scheduler &&
        h2o_memis(stream->req.input.method.base, stream->req.input.method.len, H2O_STRLIT("GET")) &&
        is_blocking_asset(stream->req.input.path.base, stream->req.input.path.len)) {
        h2o_http2_scheduler_rebind(&stream->_refs.scheduler, &conn->scheduler, 257, 0);
    }

    conn->_read_expect = expect_default;

#define EXPECTED_MAP                                                                                                               \
    (H2O_HPACK_PARSE_HEADERS_METHOD_EXISTS | H2O_HPACK_PARSE_HEADERS_PATH_EXISTS | H2O_HPACK_PARSE_HEADERS_SCHEME_EXISTS)
    if ((header_exists_map & EXPECTED_MAP) != EXPECTED_MAP) {
        ret = H2O_HTTP2_ERROR_PROTOCOL;
        goto SendRSTStream;
    }
#undef EXPECTED_MAP

    /* handle the request */
    if (conn->num_streams.open_pull > H2O_HTTP2_SETTINGS_HOST.max_concurrent_streams) {
        ret = H2O_HTTP2_ERROR_REFUSED_STREAM;
        goto SendRSTStream;
    }

    if (stream->_req_body == NULL) {
        execute_or_enqueue_request(conn, stream);
    } else {
        h2o_http2_stream_set_state(conn, stream, H2O_HTTP2_STREAM_STATE_RECV_BODY);
    }
    return 0;

SendRSTStream:
    send_stream_error(conn, stream->stream_id, ret);
    h2o_http2_stream_reset(conn, stream);
    return 0;
}

static ssize_t expect_continuation_of_headers(h2o_http2_conn_t *conn, const uint8_t *src, size_t len, const char **err_desc)
{
    h2o_http2_frame_t frame;
    ssize_t ret;
    h2o_http2_stream_t *stream;
    int hret;

    if ((ret = h2o_http2_decode_frame(&frame, src, len, &H2O_HTTP2_SETTINGS_HOST, err_desc)) < 0)
        return ret;
    if (frame.type != H2O_HTTP2_FRAME_TYPE_CONTINUATION) {
        *err_desc = "expected CONTINUATION frame";
        return H2O_HTTP2_ERROR_PROTOCOL;
    }

    if (conn->state >= H2O_HTTP2_CONN_STATE_HALF_CLOSED)
        return 0;

    if (frame.stream_id != conn->pull_stream_ids.max_open ||
        (stream = h2o_http2_conn_get_stream(conn, conn->pull_stream_ids.max_open)) == NULL ||
        stream->state != H2O_HTTP2_STREAM_STATE_RECV_HEADERS) {
        *err_desc = "unexpected stream id in CONTINUATION frame";
        return H2O_HTTP2_ERROR_PROTOCOL;
    }

    h2o_buffer_reserve(&stream->_req_headers, frame.length);
    memcpy(stream->_req_headers->bytes + stream->_req_headers->size, frame.payload, frame.length);
    stream->_req_headers->size += frame.length;

    if (stream->_req_headers->size <= H2O_MAX_REQLEN) {
        if ((frame.flags & H2O_HTTP2_FRAME_FLAG_END_HEADERS) != 0) {
            if ((hret = handle_incoming_request(conn, stream, (const uint8_t *)stream->_req_headers->bytes,
                                                stream->_req_headers->size, err_desc)) != 0)
                ret = hret;
            h2o_buffer_dispose(&stream->_req_headers);
            stream->_req_headers = NULL;
        }
    } else {
        /* request is too large (TODO log) */
        send_stream_error(conn, stream->stream_id, H2O_HTTP2_ERROR_REFUSED_STREAM);
        h2o_http2_stream_reset(conn, stream);
    }

    return ret;
}

static void update_input_window(h2o_http2_conn_t *conn, uint32_t stream_id, h2o_http2_window_t *window, size_t consumed)
{
    h2o_http2_window_consume_window(window, consumed);
    if (h2o_http2_window_get_window(window) * 2 < H2O_HTTP2_SETTINGS_HOST.initial_window_size) {
        int32_t delta = (int32_t)(H2O_HTTP2_SETTINGS_HOST.initial_window_size - h2o_http2_window_get_window(window));
        h2o_http2_encode_window_update_frame(&conn->_write.buf, stream_id, delta);
        h2o_http2_conn_request_write(conn);
        h2o_http2_window_update(window, delta);
    }
}

static int open_stream(h2o_http2_conn_t *conn, uint32_t stream_id, h2o_http2_stream_t **stream, const char **err_desc)
{
    if (conn->num_streams.open_priority >= conn->super.ctx->globalconf->http2.max_streams_for_priority) {
        *err_desc = "too many streams in idle/closed state";
        return H2O_HTTP2_ERROR_INTERNAL; /* FIXME? */
    }
    *stream = h2o_http2_stream_open(conn, stream_id, NULL, 0);
    return 0;
}

static int set_priority(h2o_http2_conn_t *conn, h2o_http2_stream_t *stream, const h2o_http2_priority_t *priority,
                        int scheduler_is_open, const char **err_desc)
{
    h2o_http2_scheduler_node_t *parent_sched;

    /* cannot depend on itself */
    if (stream->stream_id == priority->dependency)
        return H2O_HTTP2_ERROR_PROTOCOL;

    /* determine the parent */
    if (priority->dependency != 0) {
        h2o_http2_stream_t *parent_stream = h2o_http2_conn_get_stream(conn, priority->dependency);
        if (parent_stream == NULL) {
            int ret = open_stream(conn, priority->dependency, &parent_stream, err_desc);
            if (ret != 0)
                return ret;
            set_priority(conn, parent_stream, &h2o_http2_default_priority, 0, err_desc); /* guaranteed to succeed */
        }
        parent_sched = &parent_stream->_refs.scheduler.node;
    } else {
        parent_sched = &conn->scheduler;
    }

    /* setup the scheduler */
    if (!scheduler_is_open) {
        h2o_http2_scheduler_open(&stream->_refs.scheduler, parent_sched, priority->weight, priority->exclusive);
    } else {
        h2o_http2_scheduler_rebind(&stream->_refs.scheduler, parent_sched, priority->weight, priority->exclusive);
    }

    return 0;
}

static int handle_data_frame(h2o_http2_conn_t *conn, h2o_http2_frame_t *frame, const char **err_desc)
{
    h2o_http2_data_payload_t payload;
    h2o_http2_stream_t *stream;
    int ret;

    if ((ret = h2o_http2_decode_data_payload(&payload, frame, err_desc)) != 0)
        return ret;

    if (conn->state >= H2O_HTTP2_CONN_STATE_HALF_CLOSED)
        return 0;

    stream = h2o_http2_conn_get_stream(conn, frame->stream_id);

    /* save the input in the request body buffer, or send error (and close the stream) */
    if (stream == NULL) {
        *err_desc = "invalid DATA frame";
        return H2O_HTTP2_ERROR_PROTOCOL;
    } else if (stream->state != H2O_HTTP2_STREAM_STATE_RECV_BODY) {
        send_stream_error(conn, frame->stream_id, H2O_HTTP2_ERROR_STREAM_CLOSED);
        h2o_http2_stream_reset(conn, stream);
        stream = NULL;
    } else if (stream->_req_body->size + payload.length > conn->super.ctx->globalconf->max_request_entity_size) {
        send_stream_error(conn, frame->stream_id, H2O_HTTP2_ERROR_REFUSED_STREAM);
        h2o_http2_stream_reset(conn, stream);
        stream = NULL;
    } else {
        h2o_iovec_t buf = h2o_buffer_reserve(&stream->_req_body, payload.length);
        if (buf.base != NULL) {
            memcpy(buf.base, payload.data, payload.length);
            stream->_req_body->size += payload.length;
            /* handle request if request body is complete */
            if ((frame->flags & H2O_HTTP2_FRAME_FLAG_END_STREAM) != 0) {
                stream->req.entity = h2o_iovec_init(stream->_req_body->bytes, stream->_req_body->size);
                execute_or_enqueue_request(conn, stream);
                stream = NULL; /* no need to send window update for this stream */
            }
        } else {
            /* memory allocation failed */
            send_stream_error(conn, frame->stream_id, H2O_HTTP2_ERROR_STREAM_CLOSED);
            h2o_http2_stream_reset(conn, stream);
            stream = NULL;
        }
    }

    /* consume buffer (and set window_update) */
    update_input_window(conn, 0, &conn->_input_window, frame->length);
    if (stream != NULL)
        update_input_window(conn, stream->stream_id, &stream->input_window, frame->length);

    return 0;
}

static int handle_headers_frame(h2o_http2_conn_t *conn, h2o_http2_frame_t *frame, const char **err_desc)
{
    h2o_http2_headers_payload_t payload;
    h2o_http2_stream_t *stream;
    int ret;

    /* decode */
    if ((ret = h2o_http2_decode_headers_payload(&payload, frame, err_desc)) != 0)
        return ret;
    if ((frame->stream_id & 1) == 0 || !(conn->pull_stream_ids.max_open < frame->stream_id)) {
        *err_desc = "invalid stream id in HEADERS frame";
        return H2O_HTTP2_ERROR_PROTOCOL;
    }

    if (conn->state >= H2O_HTTP2_CONN_STATE_HALF_CLOSED)
        return 0;

    /* adjust state */
    conn->_read_expect = expect_continuation_of_headers;

    /* open or determine the stream and prepare */
    if ((stream = h2o_http2_conn_get_stream(conn, frame->stream_id)) != NULL) {
        if ((frame->flags & H2O_HTTP2_FRAME_FLAG_PRIORITY) != 0)
            if ((ret = set_priority(conn, stream, &payload.priority, 1, err_desc)) != 0)
                return ret;
    } else {
        if ((ret = open_stream(conn, frame->stream_id, &stream, err_desc)) != 0)
            return ret;
        if ((ret = set_priority(conn, stream, &payload.priority, 0, err_desc)) != 0)
            return ret;
    }
    h2o_http2_stream_prepare_for_request(conn, stream);

    /* setup container for request body if it is expected to arrive */
    if ((frame->flags & H2O_HTTP2_FRAME_FLAG_END_STREAM) == 0)
        h2o_buffer_init(&stream->_req_body, &h2o_socket_buffer_prototype);

    if ((frame->flags & H2O_HTTP2_FRAME_FLAG_END_HEADERS) == 0) {
        /* request is not complete, store in buffer */
        h2o_buffer_init(&stream->_req_headers, &h2o_socket_buffer_prototype);
        h2o_buffer_reserve(&stream->_req_headers, payload.headers_len);
        memcpy(stream->_req_headers->bytes, payload.headers, payload.headers_len);
        stream->_req_headers->size = payload.headers_len;
    } else {
        /* request is complete, handle it */
        ret = handle_incoming_request(conn, stream, payload.headers, payload.headers_len, err_desc);
    }

    return ret;
}

static int handle_priority_frame(h2o_http2_conn_t *conn, h2o_http2_frame_t *frame, const char **err_desc)
{
    h2o_http2_priority_t payload;
    h2o_http2_stream_t *stream;
    int ret;

    if ((ret = h2o_http2_decode_priority_payload(&payload, frame, err_desc)) != 0)
        return ret;
    if (frame->stream_id == payload.dependency) {
        *err_desc = "stream cannot depend on itself";
        return H2O_HTTP2_ERROR_PROTOCOL;
    }

    if ((stream = h2o_http2_conn_get_stream(conn, frame->stream_id)) != NULL) {
        if ((ret = set_priority(conn, stream, &payload, 1, err_desc)) != 0)
            return ret;
    } else {
        if ((ret = open_stream(conn, frame->stream_id, &stream, err_desc)) != 0)
            return ret;
        if ((ret = set_priority(conn, stream, &payload, 0, err_desc)) != 0)
            return ret;
    }

    return 0;
}

static void resume_send(h2o_http2_conn_t *conn)
{
    if (h2o_http2_conn_get_buffer_window(conn) <= 0)
        return;
#if 0 /* TODO reenable this check for performance? */
    if (conn->scheduler.list.size == 0)
        return;
#endif
    request_gathered_write(conn);
}

static int handle_settings_frame(h2o_http2_conn_t *conn, h2o_http2_frame_t *frame, const char **err_desc)
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
            h2o_iovec_t header_buf = h2o_buffer_reserve(&conn->_write.buf, H2O_HTTP2_FRAME_HEADER_SIZE);
            h2o_http2_encode_frame_header((void *)header_buf.base, 0, H2O_HTTP2_FRAME_TYPE_SETTINGS, H2O_HTTP2_FRAME_FLAG_ACK, 0);
            conn->_write.buf->size += H2O_HTTP2_FRAME_HEADER_SIZE;
            h2o_http2_conn_request_write(conn);
        }
        /* apply the change to window size (to all the streams but not the connection, see 6.9.2 of draft-15) */
        if (prev_initial_window_size != conn->peer_settings.initial_window_size) {
            ssize_t delta = conn->peer_settings.initial_window_size - prev_initial_window_size;
            h2o_http2_stream_t *stream;
            kh_foreach_value(conn->streams, stream, { update_stream_output_window(stream, delta); });
            resume_send(conn);
        }
    }

    return 0;
}

static int handle_window_update_frame(h2o_http2_conn_t *conn, h2o_http2_frame_t *frame, const char **err_desc)
{
    h2o_http2_window_update_payload_t payload;
    int ret, err_is_stream_level;

    if ((ret = h2o_http2_decode_window_update_payload(&payload, frame, err_desc, &err_is_stream_level)) != 0) {
        if (err_is_stream_level) {
            h2o_http2_stream_t *stream = h2o_http2_conn_get_stream(conn, frame->stream_id);
            if (stream != NULL)
                h2o_http2_stream_reset(conn, stream);
            send_stream_error(conn, frame->stream_id, ret);
            return 0;
        } else {
            return ret;
        }
    }

    if (frame->stream_id == 0) {
        if (h2o_http2_window_update(&conn->_write.window, payload.window_size_increment) != 0) {
            *err_desc = "flow control window overflow";
            return H2O_HTTP2_ERROR_FLOW_CONTROL;
        }
    } else if (!is_idle_stream_id(conn, frame->stream_id)) {
        h2o_http2_stream_t *stream = h2o_http2_conn_get_stream(conn, frame->stream_id);
        if (stream != NULL) {
            if (update_stream_output_window(stream, payload.window_size_increment) != 0) {
                h2o_http2_stream_reset(conn, stream);
                send_stream_error(conn, frame->stream_id, H2O_HTTP2_ERROR_FLOW_CONTROL);
                return 0;
            }
        }
    } else {
        *err_desc = "invalid stream id in WINDOW_UPDATE frame";
        return H2O_HTTP2_ERROR_FLOW_CONTROL;
    }

    resume_send(conn);

    return 0;
}

static int handle_goaway_frame(h2o_http2_conn_t *conn, h2o_http2_frame_t *frame, const char **err_desc)
{
    h2o_http2_goaway_payload_t payload;
    int ret;

    if ((ret = h2o_http2_decode_goaway_payload(&payload, frame, err_desc)) != 0)
        return ret;

    /* nothing to do, since we do not open new streams by ourselves */
    return 0;
}

static int handle_ping_frame(h2o_http2_conn_t *conn, h2o_http2_frame_t *frame, const char **err_desc)
{
    h2o_http2_ping_payload_t payload;
    int ret;

    if ((ret = h2o_http2_decode_ping_payload(&payload, frame, err_desc)) != 0)
        return ret;

    h2o_http2_encode_ping_frame(&conn->_write.buf, 1, payload.data);
    h2o_http2_conn_request_write(conn);

    return 0;
}

static int handle_rst_stream_frame(h2o_http2_conn_t *conn, h2o_http2_frame_t *frame, const char **err_desc)
{
    h2o_http2_rst_stream_payload_t payload;
    h2o_http2_stream_t *stream;
    int ret;

    if ((ret = h2o_http2_decode_rst_stream_payload(&payload, frame, err_desc)) != 0)
        return ret;
    if (is_idle_stream_id(conn, frame->stream_id)) {
        *err_desc = "unexpected stream id in RST_STREAM frame";
        return H2O_HTTP2_ERROR_PROTOCOL;
    }

    stream = h2o_http2_conn_get_stream(conn, frame->stream_id);
    if (stream != NULL) {
        /* reset the stream */
        h2o_http2_stream_reset(conn, stream);
    }
    /* TODO log */

    return 0;
}

static int handle_push_promise_frame(h2o_http2_conn_t *conn, h2o_http2_frame_t *frame, const char **err_desc)
{
    *err_desc = "received PUSH_PROMISE frame";
    return H2O_HTTP2_ERROR_PROTOCOL;
}

static int handle_invalid_continuation_frame(h2o_http2_conn_t *conn, h2o_http2_frame_t *frame, const char **err_desc)
{
    *err_desc = "received invalid CONTINUATION frame";
    return H2O_HTTP2_ERROR_PROTOCOL;
}

ssize_t expect_default(h2o_http2_conn_t *conn, const uint8_t *src, size_t len, const char **err_desc)
{
    h2o_http2_frame_t frame;
    ssize_t ret;
    static int (*FRAME_HANDLERS[])(h2o_http2_conn_t *conn, h2o_http2_frame_t *frame, const char **err_desc) = {
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

    if ((ret = h2o_http2_decode_frame(&frame, src, len, &H2O_HTTP2_SETTINGS_HOST, err_desc)) < 0)
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

static ssize_t expect_preface(h2o_http2_conn_t *conn, const uint8_t *src, size_t len, const char **err_desc)
{
    if (len < CONNECTION_PREFACE.len) {
        return H2O_HTTP2_ERROR_INCOMPLETE;
    }
    if (memcmp(src, CONNECTION_PREFACE.base, CONNECTION_PREFACE.len) != 0) {
        return H2O_HTTP2_ERROR_PROTOCOL_CLOSE_IMMEDIATELY;
    }

    { /* send SETTINGS */
        h2o_iovec_t vec = h2o_buffer_reserve(&conn->_write.buf, SETTINGS_HOST_BIN.len);
        memcpy(vec.base, SETTINGS_HOST_BIN.base, SETTINGS_HOST_BIN.len);
        conn->_write.buf->size += SETTINGS_HOST_BIN.len;
        h2o_http2_conn_request_write(conn);
    }

    conn->_read_expect = expect_default;
    return CONNECTION_PREFACE.len;
}

static void parse_input(h2o_http2_conn_t *conn)
{
    size_t http2_max_concurrent_requests_per_connection = conn->super.ctx->globalconf->http2.max_concurrent_requests_per_connection;
    int perform_early_exit = 0;

    if (conn->num_streams.responding != http2_max_concurrent_requests_per_connection)
        perform_early_exit = 1;

    /* handle the input */
    while (conn->state < H2O_HTTP2_CONN_STATE_IS_CLOSING && conn->sock->input->size != 0) {
        if (perform_early_exit == 1 && conn->num_streams.responding == http2_max_concurrent_requests_per_connection)
            goto EarlyExit;
        /* process a frame */
        const char *err_desc = NULL;
        ssize_t ret = conn->_read_expect(conn, (uint8_t *)conn->sock->input->bytes, conn->sock->input->size, &err_desc);
        if (ret == H2O_HTTP2_ERROR_INCOMPLETE) {
            break;
        } else if (ret < 0) {
            if (ret != H2O_HTTP2_ERROR_PROTOCOL_CLOSE_IMMEDIATELY) {
                enqueue_goaway(conn, (int)ret,
                               err_desc != NULL ? (h2o_iovec_t){(char *)err_desc, strlen(err_desc)} : (h2o_iovec_t){});
            }
            close_connection(conn);
            return;
        }
        /* advance to the next frame */
        h2o_buffer_consume(&conn->sock->input, ret);
    }

    if (!h2o_socket_is_reading(conn->sock))
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

    update_idle_timeout(conn);
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
    h2o_buffer_init(&sock->input, &h2o_socket_buffer_prototype);

    /* setup inbound */
    h2o_socket_read_start(conn->sock, on_read);

    /* handle the request */
    execute_or_enqueue_request(conn, h2o_http2_conn_get_stream(conn, 1));

    if (conn->_http1_req_input->size != reqsize) {
        /* FIXME copy the remaining data to conn->_input and call handle_input */
        assert(0);
    }
}

void h2o_http2_conn_request_write(h2o_http2_conn_t *conn)
{
    if (conn->state == H2O_HTTP2_CONN_STATE_IS_CLOSING)
        return;
    request_gathered_write(conn);
}

void h2o_http2_conn_register_for_proceed_callback(h2o_http2_conn_t *conn, h2o_http2_stream_t *stream)
{
    h2o_http2_conn_request_write(conn);

    if (h2o_http2_stream_has_pending_data(stream) || stream->state == H2O_HTTP2_STREAM_STATE_END_STREAM) {
        if (h2o_http2_window_get_window(&stream->output_window) > 0) {
            assert(!h2o_linklist_is_linked(&stream->_refs.link));
            h2o_http2_scheduler_activate(&stream->_refs.scheduler);
        }
    } else {
        h2o_linklist_insert(&conn->_write.streams_to_proceed, &stream->_refs.link);
    }
}

static void on_write_complete(h2o_socket_t *sock, int status)
{
    h2o_http2_conn_t *conn = sock->data;

    assert(conn->_write.buf_in_flight != NULL);

    /* close by error if necessary */
    if (status != 0) {
        close_connection_now(conn);
        return;
    }

    /* reset the other memory pool */
    h2o_buffer_dispose(&conn->_write.buf_in_flight);
    assert(conn->_write.buf_in_flight == NULL);

    /* call the proceed callback of the streams that have been flushed (while unlinking them from the list) */
    if (status == 0 && conn->state < H2O_HTTP2_CONN_STATE_IS_CLOSING) {
        while (!h2o_linklist_is_empty(&conn->_write.streams_to_proceed)) {
            h2o_http2_stream_t *stream =
                H2O_STRUCT_FROM_MEMBER(h2o_http2_stream_t, _refs.link, conn->_write.streams_to_proceed.next);
            assert(!h2o_http2_stream_has_pending_data(stream));
            h2o_linklist_unlink(&stream->_refs.link);
            h2o_http2_stream_proceed(conn, stream);
        }
    }

    /* cancel the write callback if scheduled (as the generator may have scheduled a write just before this function gets called) */
    if (h2o_timeout_is_linked(&conn->_write.timeout_entry))
        h2o_timeout_unlink(&conn->_write.timeout_entry);

    /* write more, if possible */
    if (do_emit_writereq(conn))
        return;

    /* close the connection if necessary */
    switch (conn->state) {
    case H2O_HTTP2_CONN_STATE_OPEN:
        break;
    case H2O_HTTP2_CONN_STATE_HALF_CLOSED:
        if (conn->num_streams.responding != 0)
            break;
        conn->state = H2O_HTTP2_CONN_STATE_IS_CLOSING;
    /* fall-thru */
    case H2O_HTTP2_CONN_STATE_IS_CLOSING:
        close_connection_now(conn);
        return;
    }

    /* start receiving input if necessary, as well as parse the pending input */
    if (conn->sock->input->size != 0)
        parse_input(conn);
}

static int emit_writereq_of_openref(h2o_http2_scheduler_openref_t *ref, int *still_is_active, void *cb_arg)
{
    h2o_http2_conn_t *conn = cb_arg;
    h2o_http2_stream_t *stream = H2O_STRUCT_FROM_MEMBER(h2o_http2_stream_t, _refs.scheduler, ref);

    assert(h2o_http2_stream_has_pending_data(stream) || stream->state == H2O_HTTP2_STREAM_STATE_END_STREAM);

    *still_is_active = 0;

    h2o_http2_stream_send_pending_data(conn, stream);
    if (h2o_http2_stream_has_pending_data(stream)) {
        if (h2o_http2_window_get_window(&stream->output_window) <= 0) {
            /* is blocked */
        } else {
            *still_is_active = 1;
        }
    } else {
        h2o_linklist_insert(&conn->_write.streams_to_proceed, &stream->_refs.link);
    }

    return h2o_http2_conn_get_buffer_window(conn) > 0 ? 0 : -1;
}

int do_emit_writereq(h2o_http2_conn_t *conn)
{
    assert(conn->_write.buf_in_flight == NULL);

    /* push DATA frames */
    if (conn->state < H2O_HTTP2_CONN_STATE_IS_CLOSING && h2o_http2_conn_get_buffer_window(conn) > 0)
        h2o_http2_scheduler_run(&conn->scheduler, emit_writereq_of_openref, conn);

    if (conn->_write.buf->size == 0)
        return 0;

    { /* write */
        h2o_iovec_t buf = {conn->_write.buf->bytes, conn->_write.buf->size};
        h2o_socket_write(conn->sock, &buf, 1, on_write_complete);
        conn->_write.buf_in_flight = conn->_write.buf;
        h2o_buffer_init(&conn->_write.buf, &wbuf_buffer_prototype);
    }
    return 1;
}

static void emit_writereq(h2o_timeout_entry_t *entry)
{
    h2o_http2_conn_t *conn = H2O_STRUCT_FROM_MEMBER(h2o_http2_conn_t, _write.timeout_entry, entry);

    do_emit_writereq(conn);
}

static socklen_t get_sockname(h2o_conn_t *_conn, struct sockaddr *sa)
{
    h2o_http2_conn_t *conn = (void *)_conn;
    return h2o_socket_getsockname(conn->sock, sa);
}

static socklen_t get_peername(h2o_conn_t *_conn, struct sockaddr *sa)
{
    h2o_http2_conn_t *conn = (void *)_conn;
    return h2o_socket_getpeername(conn->sock, sa);
}

static h2o_http2_conn_t *create_conn(h2o_context_t *ctx, h2o_hostconf_t **hosts, h2o_socket_t *sock)
{
    h2o_http2_conn_t *conn = h2o_mem_alloc(sizeof(*conn));

    /* init the connection */
    memset(conn, 0, sizeof(*conn));
    conn->super.ctx = ctx;
    conn->super.hosts = hosts;
    conn->super.get_sockname = get_sockname;
    conn->super.get_peername = get_peername;
    conn->sock = sock;
    conn->peer_settings = H2O_HTTP2_SETTINGS_DEFAULT;
    conn->streams = kh_init(h2o_http2_stream_t);
    h2o_http2_scheduler_init(&conn->scheduler);
    conn->state = H2O_HTTP2_CONN_STATE_OPEN;
    h2o_linklist_insert(&ctx->http2._conns, &conn->_conns);
    conn->_read_expect = expect_preface;
    conn->_input_header_table.hpack_capacity = conn->_input_header_table.hpack_max_capacity =
        H2O_HTTP2_SETTINGS_DEFAULT.header_table_size;
    h2o_http2_window_init(&conn->_input_window, &H2O_HTTP2_SETTINGS_DEFAULT);
    conn->_output_header_table.hpack_capacity = H2O_HTTP2_SETTINGS_HOST.header_table_size;
    h2o_linklist_init_anchor(&conn->_pending_reqs);
    h2o_buffer_init(&conn->_write.buf, &wbuf_buffer_prototype);
    h2o_linklist_init_anchor(&conn->_write.streams_to_proceed);
    conn->_write.timeout_entry.cb = emit_writereq;
    h2o_http2_window_init(&conn->_write.window, &conn->peer_settings);

    return conn;
}

void h2o_http2_conn_push_path(h2o_http2_conn_t *conn, h2o_iovec_t path, h2o_http2_stream_t *src_stream)
{
    h2o_http2_stream_t *stream;

    if (!conn->peer_settings.enable_push || conn->num_streams.open_push >= conn->peer_settings.max_concurrent_streams)
        return;
    if (conn->push_stream_ids.max_open >= 0x7ffffff0)
        return;

    /* open the stream with heighest weight (TODO find a better way to determine the weight) */
    conn->push_stream_ids.max_open += 2;
    stream = h2o_http2_stream_open(conn, conn->push_stream_ids.max_open, NULL, src_stream->stream_id);
    h2o_http2_scheduler_open(&stream->_refs.scheduler, &conn->scheduler, 257, 0);
    h2o_http2_stream_prepare_for_request(conn, stream);

    /* setup request */
    stream->req.input.method = (h2o_iovec_t){H2O_STRLIT("GET")};
    stream->req.input.scheme = src_stream->req.input.scheme;
    stream->req.input.authority =
        h2o_strdup(&stream->req.pool, src_stream->req.input.authority.base, src_stream->req.input.authority.len);
    stream->req.input.path = h2o_strdup(&stream->req.pool, path.base, path.len);
    stream->req.version = 0x200;

    { /* copy headers that may affect the response (of a cacheable response) */
        size_t i;
        for (i = 0; i != src_stream->req.headers.size; ++i) {
            h2o_header_t *src_header = src_stream->req.headers.entries + i;
            if (h2o_iovec_is_token(src_header->name)) {
                h2o_token_t *token = H2O_STRUCT_FROM_MEMBER(h2o_token_t, buf, src_header->name);
                if (token->copy_for_push_request) {
                    h2o_add_header(&stream->req.pool, &stream->req.headers, token,
                                   h2o_strdup(&stream->req.pool, src_header->value.base, src_header->value.len).base,
                                   src_header->value.len);
                }
            }
        }
    }

    /* send the push_promise frame */
    h2o_hpack_flatten_request(&conn->_write.buf, &conn->_output_header_table, stream->stream_id, conn->peer_settings.max_frame_size,
                              &stream->req, stream->push.parent_stream_id);

    execute_or_enqueue_request(conn, stream);
}

void h2o_http2_accept(h2o_context_t *ctx, h2o_hostconf_t **hosts, h2o_socket_t *sock)
{
    h2o_http2_conn_t *conn = create_conn(ctx, hosts, sock);
    sock->data = conn;
    h2o_socket_read_start(conn->sock, on_read);
    update_idle_timeout(conn);
    if (sock->input->size != 0)
        on_read(sock, 0);
}

int h2o_http2_handle_upgrade(h2o_req_t *req)
{
    h2o_http2_conn_t *http2conn = create_conn(req->conn->ctx, req->conn->hosts, NULL);
    h2o_http2_stream_t *stream;
    ssize_t connection_index, settings_index;
    h2o_iovec_t settings_decoded;
    const char *err_desc;

    assert(req->version < 0x200); /* from HTTP/1.x */

    /* check that "HTTP2-Settings" is declared in the connection header */
    connection_index = h2o_find_header(&req->headers, H2O_TOKEN_CONNECTION, -1);
    assert(connection_index != -1);
    if (!h2o_contains_token(req->headers.entries[connection_index].value.base, req->headers.entries[connection_index].value.len,
                            H2O_STRLIT("http2-settings"), ',')) {
        goto Error;
    }

    /* decode the settings */
    if ((settings_index = h2o_find_header(&req->headers, H2O_TOKEN_HTTP2_SETTINGS, -1)) == -1) {
        goto Error;
    }
    if ((settings_decoded = h2o_decode_base64url(&req->pool, req->headers.entries[settings_index].value.base,
                                                 req->headers.entries[settings_index].value.len)).base == NULL) {
        goto Error;
    }
    if (h2o_http2_update_peer_settings(&http2conn->peer_settings, (uint8_t *)settings_decoded.base, settings_decoded.len,
                                       &err_desc) != 0) {
        goto Error;
    }

    /* open the stream, now that the function is guaranteed to succeed */
    stream = h2o_http2_stream_open(http2conn, 1, req, 0);
    h2o_http2_scheduler_open(&stream->_refs.scheduler, &http2conn->scheduler, h2o_http2_default_priority.weight, 0);
    h2o_http2_stream_prepare_for_request(http2conn, stream);

    /* send response */
    req->res.status = 101;
    req->res.reason = "Switching Protocols";
    h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_UPGRADE, H2O_STRLIT("h2c"));
    h2o_http1_upgrade(req, (h2o_iovec_t *)&SETTINGS_HOST_BIN, 1, on_upgrade_complete, http2conn);

    return 0;
Error:
    free(http2conn);
    return -1;
}
