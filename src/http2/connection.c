#include <stdio.h>
#include <stdlib.h>
#include "h2o.h"
#include "h2o/http1.h"
#include "h2o/http2.h"
#include "internal.h"

static const uv_buf_t CONNECTION_PREFACE = { H2O_STRLIT("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n") };

static const h2o_http2_settings_t HOST_SETTINGS = {
    /* header_table_size = */ 4096,
    /* enable_push = */ 0,
    /* max_concurrent_streams = */ 100,
    /* initial_window_size = */ 0x7fffffff,
    /* max_frame_size = */ 16384
};

static const uv_buf_t HOST_SETTINGS_BIN = {
    H2O_STRLIT(
        "\x00\x00\x0c" /* frame size */
        "\x04" /* settings frame */
        "\x00" /* no flags */
        "\x00\x00\x00\x00" /* stream id */
        "\x00\x02" "\x00\x00\x00\x00" /* enable_push = 0 */
        "\x00\x03" "\x00\x00\x00\x64" /* max_concurrent_streams = 100 */

        "\x00\x00\x00" /* frame size */
        "\x04" /* settings frame */
        "\x01" /* ack flag */
        "\x00\x00\x00\x00" /* stream id */
    )
};

static ssize_t expect_default(h2o_http2_conn_t *conn, const uint8_t *src, size_t len);

static inline void unregister_stream(h2o_http2_conn_t *conn, uint32_t stream_id)
{
    khiter_t iter = kh_get(h2o_http2_stream_t, conn->active_streams, stream_id);
    assert(iter != kh_end(conn->active_streams));
    kh_del(h2o_http2_stream_t, conn->active_streams, iter);
}

static inline h2o_http2_stream_t *get_stream(h2o_http2_conn_t *conn, uint32_t stream_id)
{
    khiter_t iter = kh_get(h2o_http2_stream_t, conn->active_streams, stream_id);
    if (iter != kh_end(conn->active_streams))
        return kh_val(conn->active_streams, iter);
    return NULL;
}

static void close_connection(h2o_http2_conn_t *conn)
{
    h2o_http2_stream_t *stream;

    kh_foreach_value(conn->active_streams, stream, {
        h2o_http2_stream_close(stream, &conn->_http1_req_input);
    });
    kh_destroy(h2o_http2_stream_t, conn->active_streams);
    free(conn->_input);
    free(conn->_http1_req_input);
    h2o_mempool_clear(&conn->_write.pool);
    conn->close_cb(conn);
}

static uv_buf_t alloc_inbuf(uv_handle_t *handle, size_t suggested_size)
{
    h2o_http2_conn_t *conn = handle->data;
    return h2o_allocate_input_buffer(&conn->_input, suggested_size);
}

/* handles HEADERS frame or succeeding CONTINUATION frames */
static int handle_incoming_request(h2o_http2_conn_t *conn, h2o_http2_stream_t *stream, const uint8_t *src, size_t len, int is_final)
{
    int allow_psuedo = stream->state == H2O_HTTP2_STREAM_STATE_RECV_PSUEDO_HEADERS;

    if (h2o_hpack_parse_headers(&stream->req, &conn->_input_header_table, &allow_psuedo, src, len) != 0) {
        return -1;
    }
    if (! allow_psuedo)
        stream->state = H2O_HTTP2_STREAM_STATE_RECV_HEADERS;

    if (! is_final) {
        /* FIXME request timeout? */
        return 0;
    }

    /* handle the request */
    stream->state = H2O_HTTP2_STREAM_STATE_SEND_HEADERS;
    conn->req_cb(&stream->req);
    conn->_read_expect = expect_default;

    return 0;
}

static ssize_t expect_continuation_of_headers(h2o_http2_conn_t *conn, const uint8_t *src, size_t len)
{
    h2o_http2_frame_t frame;
    ssize_t ret;

    if ((ret = h2o_http2_decode_frame(&frame, src, len, &HOST_SETTINGS)) < 0)
        return ret;

    if (! (frame.type == H2O_HTTP2_FRAME_TYPE_CONTINUATION && frame.stream_id == conn->max_stream_id))
        return H2O_HTTP2_DECODE_ERROR;

    if (handle_incoming_request(
        conn,
        get_stream(conn, conn->max_stream_id),
        frame.payload,
        frame.length,
        (frame.flags & H2O_HTTP2_FRAME_FLAG_END_HEADERS) != 0)
        != 0) {
        return H2O_HTTP2_DECODE_ERROR;
    }

    return ret;
}

static int handle_headers_frame(h2o_http2_conn_t *conn, h2o_http2_frame_t *frame)
{
    h2o_http2_headers_payload_t payload;
    h2o_http2_stream_t *stream;

    if (h2o_http2_decode_headers_payload(&payload, frame) != 0)
        return -1;

    /* open new stream */
    if (! (conn->max_stream_id < frame->stream_id)) {
        return -1;
    }
    stream = h2o_http2_stream_open(conn, frame->stream_id, NULL);

    /* should only handle CONTINUATION frames until hitting END_HEADERS flag */
    conn->_read_expect = expect_continuation_of_headers;

    return handle_incoming_request(
        conn,
        stream,
        payload.headers,
        payload.headers_len,
        (frame->flags & H2O_HTTP2_FRAME_FLAG_END_HEADERS) != 0);
}

static inline int handle_settings_frame(h2o_http2_conn_t *conn, h2o_http2_frame_t *frame)
{
    if ((frame->flags & H2O_HTTP2_FRAME_FLAG_ACK) != 0) {
        if (frame->length != 0)
            return -1;
        /* FIXME do we need to do something? */
        return 0;
    } else {
        return h2o_http2_update_peer_settings(&conn->peer_settings, frame->payload, frame->length);
    }
}

static void resume_send(h2o_http2_conn_t *conn, h2o_http2_stream_t *stream)
{
    if (h2o_http2_window_get_window(&conn->_write.window) <= 0)
        return;

    if (stream != NULL) {
        h2o_http2_stream_send_pending(conn, stream);
    } else {
        /* FIXME priority! */
        h2o_http2_stream_t *stream;
        kh_foreach_value(conn->active_streams, stream, {
            h2o_http2_stream_send_pending(conn, stream);
            if (h2o_http2_window_get_window(&conn->_write.window) <= 0) {
                break;
            }
        });
    }
}

static int handle_window_update_frame(h2o_http2_conn_t *conn, h2o_http2_frame_t *frame)
{
    h2o_http2_window_update_payload_t payload;

    if (h2o_http2_decode_window_update_payload(&payload, frame) != 0)
        return -1;

    if (frame->stream_id == 0) {
        h2o_http2_window_update(&conn->_write.window, payload.window_size_increment);
        resume_send(conn, NULL);
    } else if (frame->stream_id <= conn->max_stream_id) {
        h2o_http2_stream_t *stream = get_stream(conn, frame->stream_id);
        if (stream != NULL) {
            h2o_http2_window_update(&stream->window, payload.window_size_increment);
            resume_send(conn, stream);
        }
    } else {
        return -1;
    }

    return 0;
}

ssize_t expect_default(h2o_http2_conn_t *conn, const uint8_t *src, size_t len)
{
    h2o_http2_frame_t frame;
    ssize_t ret;

    if ((ret = h2o_http2_decode_frame(&frame, src, len, &HOST_SETTINGS)) < 0)
        return ret;

    switch (frame.type) {
    case H2O_HTTP2_FRAME_TYPE_HEADERS:
        if (handle_headers_frame(conn, &frame) != 0)
            return H2O_HTTP2_DECODE_ERROR;
        break;
    case H2O_HTTP2_FRAME_TYPE_SETTINGS:
        if (handle_settings_frame(conn, &frame) != 0)
            return H2O_HTTP2_DECODE_ERROR;
        break;
    case H2O_HTTP2_FRAME_TYPE_WINDOW_UPDATE:
        if (handle_window_update_frame(conn, &frame) != 0)
            return H2O_HTTP2_DECODE_ERROR;
        break;
    case H2O_HTTP2_FRAME_TYPE_CONTINUATION:
        return H2O_HTTP2_DECODE_ERROR;
    default:
        fprintf(stderr, "skipping frame (type:%d)\n", frame.type);
        break;
    }

    return ret;
}

static ssize_t expect_preface(h2o_http2_conn_t *conn, const uint8_t *src, size_t len)
{
    if (len < CONNECTION_PREFACE.len) {
        return H2O_HTTP2_DECODE_INCOMPLETE;
    }
    if (memcmp(src, CONNECTION_PREFACE.base, CONNECTION_PREFACE.len) != 0) {
        return H2O_HTTP2_DECODE_ERROR;
    }

    conn->_read_expect = expect_default;
    return CONNECTION_PREFACE.len;
}

static void handle_input(h2o_http2_conn_t *conn)
{
    const uint8_t *src = (uint8_t*)conn->_input->bytes, *src_end = src + conn->_input->size;
    ssize_t ret = 0;

    while (src != src_end) {
        if ((ret = conn->_read_expect(conn, src, src_end - src)) < 0)
            break;
        src += ret;
    }
    h2o_consume_input_buffer(&conn->_input, (char*)src - conn->_input->bytes);

    if (ret == H2O_HTTP2_DECODE_ERROR) {
        fprintf(stderr, "protocol error\n");
        close_connection(conn);
    }
}

static void on_read(uv_stream_t *stream, ssize_t nread, uv_buf_t _buf)
{
    h2o_http2_conn_t *conn = stream->data;

    if (nread == -1) {
        close_connection(conn);
    } else {
        conn->_input->size += nread;
        handle_input(conn);
    }
}

static void on_upgrade_complete(void *_conn, uv_stream_t *stream, h2o_input_buffer_t *buffered_input, size_t reqsize)
{
    h2o_http2_conn_t *conn = _conn;

    if (stream == NULL) {
        close_connection(conn);
        return;
    }

    conn->stream = stream;
    stream->data = conn;
    conn->_http1_req_input = buffered_input;

    /* setup inbound */
    uv_read_start(conn->stream, alloc_inbuf, on_read);

    /* handle the request */
    conn->req_cb(&get_stream(conn, 1)->req);

    if (conn->_http1_req_input->size != reqsize) {
        /* FIXME copy the remaining data to conn->_input and call handle_input */
        assert(0);
    }
}

void h2o_http2_conn_enqueue_write(h2o_http2_conn_t *conn, uv_buf_t buf)
{
    /* activate the timeout if not yet being done */
    if (conn->_write.bufs.size == 0) {
        h2o_timeout_link_entry(&conn->ctx->zero_timeout, &conn->_write.timeout_entry);
    }
    /* push the buf */
    h2o_vector_reserve(&conn->_write.pool, (h2o_vector_t*)&conn->_write.bufs, sizeof(uv_buf_t), conn->_write.bufs.size + 1);
    conn->_write.bufs.entries[conn->_write.bufs.size++] = buf;
}

void h2o_http2_conn_register_flushed_stream(h2o_http2_conn_t *conn, h2o_http2_stream_t *stream, int is_becoming_inactive)
{
    assert(conn->_write.bufs.size != 0);
    h2o_vector_reserve(&conn->_write.pool, (h2o_vector_t*)&conn->_write.flushed_streams, sizeof(h2o_http2_stream_t*), conn->_write.flushed_streams.size + 1);
    conn->_write.flushed_streams.entries[conn->_write.flushed_streams.size++] = stream;

    if (is_becoming_inactive) {
        unregister_stream(conn, stream->stream_id);
    }
}

static void on_write_complete(uv_write_t *wreq, int status)
{
    h2o_http2_conn_t *conn = H2O_STRUCT_FROM_MEMBER(h2o_http2_conn_t, _write.wreq, wreq);
    size_t i;

    /* free the streams */
    for (i = 0; i != conn->_write.flushed_streams.size; ++i) {
        h2o_http2_stream_t *stream = conn->_write.flushed_streams.entries[i];
        h2o_http2_stream_proceed(conn, stream, status);
    }

    /* reinit */
    h2o_mempool_clear(&conn->_write.pool);
    memset(&conn->_write.bufs, 0, sizeof(conn->_write.bufs));
    memset(&conn->_write.flushed_streams, 0, sizeof(conn->_write.flushed_streams));

    if (status != 0) {
        close_connection(conn);
    }
}

static void emit_writereq(h2o_timeout_entry_t *entry)
{
    h2o_http2_conn_t *conn = H2O_STRUCT_FROM_MEMBER(h2o_http2_conn_t, _write.timeout_entry, entry);

    assert(conn->_write.bufs.size != 0);
    uv_write(&conn->_write.wreq, conn->stream, conn->_write.bufs.entries, (int)conn->_write.bufs.size, on_write_complete);
}

void h2o_http2_close_and_free(h2o_http2_conn_t *conn)
{
    if (conn->stream != NULL)
        uv_close((uv_handle_t*)conn->stream, (uv_close_cb)free);
    free(conn);
}

int h2o_http2_handle_upgrade(h2o_req_t *req, h2o_http2_conn_t *http2conn)
{
    ssize_t connection_index, settings_index;
    uv_buf_t settings_decoded;

    assert(req->version < 0x200); /* from HTTP/1.x */

    /* init the connection */
    http2conn->stream = NULL; /* not set until upgrade is complete */
    http2conn->ctx = req->ctx;
    http2conn->peer_settings = H2O_HTTP2_SETTINGS_DEFAULT;
    http2conn->active_streams = kh_init(h2o_http2_stream_t);
    http2conn->max_stream_id = 0;
    http2conn->_read_expect = expect_preface;
    http2conn->_input = NULL;
    http2conn->_http1_req_input = NULL;
    memset(&http2conn->_input_header_table, 0, sizeof(http2conn->_input_header_table));
    http2conn->_input_header_table.hpack_capacity = H2O_HTTP2_SETTINGS_DEFAULT.header_table_size;
    h2o_mempool_init(&http2conn->_write.pool);
    memset(&http2conn->_write.wreq, 0, sizeof(http2conn->_write.wreq));
    memset(&http2conn->_write.bufs, 0, sizeof(http2conn->_write.bufs));
    memset(&http2conn->_write.flushed_streams, 0, sizeof(http2conn->_write.flushed_streams));
    memset(&http2conn->_write.timeout_entry, 0, sizeof(http2conn->_write.timeout_entry));
    http2conn->_write.timeout_entry.cb = emit_writereq;
    h2o_http2_window_init(&http2conn->_write.window, &http2conn->peer_settings);

    /* check that "HTTP2-Settings" is declared in the connection header */
    connection_index = h2o_find_header(&req->headers, H2O_TOKEN_CONNECTION, -1);
    assert(connection_index != -1);
    if (! h2o_contains_token(req->headers.entries[connection_index].value.base, req->headers.entries[connection_index].value.len, H2O_STRLIT("http2-settings"))) {
        return -1;
    }

    /* decode the settings */
    if ((settings_index = h2o_find_header(&req->headers, H2O_TOKEN_HTTP2_SETTINGS, -1)) == -1) {
        return -1;
    }
    if ((settings_decoded = h2o_decode_base64url(&req->pool, req->headers.entries[settings_index].value.base, req->headers.entries[settings_index].value.len)).base == NULL) {
        return -1;
    }
    if (h2o_http2_update_peer_settings(&http2conn->peer_settings, (uint8_t*)settings_decoded.base, settings_decoded.len) != 0) {
        return -1;
    }

    /* open the stream, now that the function is guaranteed to succeed */
    h2o_http2_stream_open(http2conn, 1, req);

    /* send response */
    req->res.status = 101;
    req->res.reason = "Switching Protocols";
    h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_UPGRADE, H2O_STRLIT("h2c"));
    h2o_http1_upgrade(req->conn, (uv_buf_t*)&HOST_SETTINGS_BIN, 1, on_upgrade_complete, http2conn);

    return 0;
}
