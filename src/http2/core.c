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
static void finalostream_send(h2o_ostream_t *self, h2o_req_t *req, uv_buf_t *inbufs, size_t incnt, int is_final);

static void free_stream(h2o_http2_stream_t *stream, h2o_input_buffer_t **http1_req_input)
{
    h2o_dispose_request(&stream->req);
    if (stream->stream_id == 1) {
        free(*http1_req_input);
        *http1_req_input = NULL;
    }
    free(stream);
}

static h2o_http2_stream_t *open_stream(h2o_http2_conn_t *conn, uint32_t stream_id, h2o_req_t *src_req)
{
    h2o_http2_stream_t *stream = malloc(sizeof(*stream));
    if (stream == NULL)
        h2o_fatal("no memory");

    stream->stream_id = stream_id;
    h2o_init_request(&stream->req, conn, conn->ctx, src_req);
    stream->req.version = 0x200;
    stream->req.upgrade = uv_buf_init(NULL, 0);
    stream->req._ostr_top = &stream->_ostr_final;
    stream->_ostr_final.do_send = finalostream_send;
    stream->_state = src_req != NULL ? H2O_HTTP2_STREAM_STATE_SEND_HEADERS : H2O_HTTP2_STREAM_STATE_RECV_PSUEDO_HEADERS;
    stream->_wreq.data = conn;

    { /* register the stream */
        int r;
        khiter_t iter = kh_put(h2o_http2_stream_t, conn->active_streams, stream->stream_id, &r);
        assert(iter != kh_end(conn->active_streams));
        kh_val(conn->active_streams, iter) = stream;
    }

    assert(conn->max_stream_id < stream_id);
    conn->max_stream_id = stream_id;

    return stream;
}

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
        free_stream(stream, &conn->_http1_req_input);
    });
    kh_destroy(h2o_http2_stream_t, conn->active_streams);
    free(conn->_input);
    free(conn->_http1_req_input);
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
    int allow_psuedo = stream->_state == H2O_HTTP2_STREAM_STATE_RECV_PSUEDO_HEADERS;

    if (h2o_hpack_parse_headers(&stream->req, &conn->_input_header_table, &allow_psuedo, src, len) != 0) {
        return -1;
    }
    if (! allow_psuedo)
        stream->_state = H2O_HTTP2_STREAM_STATE_RECV_HEADERS;

    if (! is_final) {
        /* FIXME request timeout? */
        return 0;
    }

    /* handle the request */
    stream->_state = H2O_HTTP2_STREAM_STATE_SEND_HEADERS;
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
    stream = open_stream(conn, frame->stream_id, NULL);

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

static void proceed(h2o_http2_conn_t *conn)
{
    if (kh_size(conn->active_streams) != 0) {
        /* FIXME implement priority and window handling */
        khint_t iter;
        h2o_http2_stream_t *stream;

        for (iter = kh_begin(conn->active_streams); ! kh_exist(conn->active_streams, iter); ++iter)
            assert(iter != kh_end(conn->active_streams));
        stream = kh_val(conn->active_streams, iter);
        h2o_proceed_response(&stream->req, 0);
    }
}

static void on_stream_send_complete(uv_write_t *wreq, int status)
{
    h2o_http2_stream_t *stream = H2O_STRUCT_FROM_MEMBER(h2o_http2_stream_t, _wreq, wreq);
    h2o_http2_conn_t *conn = wreq->data;

    free_stream(stream, &conn->_http1_req_input);

    if (status != 0) {
        close_connection(conn);
        return;
    }
    proceed(conn);
}

static void on_stream_send_next(uv_write_t *wreq, int status)
{
    /* h2o_http2_stream_t *stream = H2O_STRUCT_FROM_MEMBER(h2o_http2_stream_t, _wreq, wreq); */
    h2o_http2_conn_t *conn = wreq->data;

    if (status != 0) {
        close_connection(conn);
        return;
    }
    proceed(conn);
}

static uv_buf_t build_frame_header(h2o_http2_stream_t *stream, size_t length, int is_final)
{
    static char buf[9];
    uv_buf_t out = uv_buf_init(buf, H2O_HTTP2_FRAME_HEADER_SIZE);
    h2o_http2_encode_frame_header(
        (uint8_t*)out.base,
        length,
        H2O_HTTP2_FRAME_TYPE_DATA,
        is_final ? H2O_HTTP2_FRAME_FLAG_END_STREAM : 0,
        stream->stream_id);
    return out;
}

void finalostream_send(h2o_ostream_t *self, h2o_req_t *req, uv_buf_t *inbufs, size_t incnt, int is_final)
{
    h2o_http2_stream_t *stream = H2O_STRUCT_FROM_MEMBER(h2o_http2_stream_t, _ostr_final, self);
    h2o_http2_conn_t *conn = req->conn;
    uv_buf_t *outbufs;
    int alloc_cnt = 0, outcnt, i;
    size_t total_data_size = 0;

    /* calculate the number of buffers we need (in the worst case) */
    if (stream->_state == H2O_HTTP2_STREAM_STATE_SEND_HEADERS)
        ++alloc_cnt;
    if (incnt != 0) {
        for (i = 0; i != incnt; ++i) {
            if (inbufs[i].len != 0) {
                alloc_cnt += (inbufs[i].len / conn->peer_settings.max_frame_size) * 2 + 3;
                total_data_size += inbufs[i].len;
            }
        }
    } else if (is_final) {
        ++alloc_cnt;
    }

    /* allocate */
    outbufs = alloca(sizeof(uv_buf_t) * alloc_cnt);
    outcnt = 0;

    /* emit the headers if necessary */
    if (stream->_state == H2O_HTTP2_STREAM_STATE_SEND_HEADERS) {
        stream->_state = H2O_HTTP2_STREAM_STATE_SEND_BODY;
        outbufs[outcnt++] = h2o_hpack_flatten_headers(&req->pool, stream->stream_id, conn->peer_settings.max_frame_size, &req->res);
    }
    /* emit the data */
    if (total_data_size != 0) {
        size_t cur_frame_size = 0;
        for (i = 0; i != incnt; ++i) {
            if (inbufs[i].len != 0) {
                size_t off = 0;
                do {
                    size_t emit_size = sz_min(inbufs[i].len - off, conn->peer_settings.max_frame_size - cur_frame_size);
                    if (cur_frame_size == 0) {
                        outbufs[outcnt++] = build_frame_header(
                            stream,
                            sz_min(total_data_size, conn->peer_settings.max_frame_size),
                            is_final && total_data_size <= conn->peer_settings.max_frame_size);
                    }
                    outbufs[outcnt++] = uv_buf_init(inbufs[i].base + off, (unsigned)emit_size);
                    cur_frame_size += emit_size;
                    if (cur_frame_size == conn->peer_settings.max_frame_size)
                        cur_frame_size = 0;
                    total_data_size -= emit_size;
                    off += emit_size;
                } while (off != inbufs[i].len);
            }
        }
        assert(total_data_size == 0);
    } else if (is_final) {
        outbufs[outcnt++] = build_frame_header(stream, 0, 1);
    }

    assert(outcnt != 0);
    assert(outcnt <= alloc_cnt);

    uv_write(&stream->_wreq, conn->stream, outbufs, outcnt, is_final ? on_stream_send_complete : on_stream_send_next);

    if (is_final)
        unregister_stream(conn, stream->stream_id);
}

void h2o_http2_close_and_free(h2o_http2_conn_t *conn)
{
    if (conn->stream != NULL)
        uv_close((uv_handle_t*)conn->stream, (uv_close_cb)free);
    free(conn);
}

int h2o_http2_handle_upgrade(h2o_req_t *req, h2o_http2_conn_t *http2conn)
{
    uv_buf_t *connection, *settings_encoded, settings_decoded;

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
    http2conn->_conn_wreq.data = http2conn;

    /* check that "HTTP2-Settings" is declared in the connection header */
    connection = h2o_find_header(&req->headers, H2O_TOKEN_CONNECTION).value;
    assert(connection != NULL);
    if (! h2o_contains_token(connection->base, connection->len, H2O_STRLIT("http2-settings"))) {
        return -1;
    }

    /* decode the settings */
    if ((settings_encoded = h2o_find_header(&req->headers, H2O_TOKEN_HTTP2_SETTINGS).value) == NULL) {
        return -1;
    }
    if ((settings_decoded = h2o_decode_base64url(&req->pool, settings_encoded->base, settings_encoded->len)).base == NULL) {
        return -1;
    }
    if (h2o_http2_update_peer_settings(&http2conn->peer_settings, (uint8_t*)settings_decoded.base, settings_decoded.len) != 0) {
        return -1;
    }

    /* open the stream, now that the function is guaranteed to succeed */
    open_stream(http2conn, 1, req);

    /* send response */
    req->res.status = 101;
    req->res.reason = "Switching Protocols";
    h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_UPGRADE, H2O_STRLIT("h2c"));
    h2o_http1_upgrade(req->conn, (uv_buf_t*)&HOST_SETTINGS_BIN, 1, on_upgrade_complete, http2conn);

    return 0;
}
