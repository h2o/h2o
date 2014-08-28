#include "h2o.h"
#include "h2o/http2.h"
#include "internal.h"

static void finalostream_send(h2o_ostream_t *self, h2o_req_t *req, uv_buf_t *bufs, size_t bufcnt, int is_final);

h2o_http2_stream_t *h2o_http2_stream_open(h2o_http2_conn_t *conn, uint32_t stream_id, h2o_req_t *src_req)
{
    h2o_http2_stream_t *stream = malloc(sizeof(*stream));
    if (stream == NULL)
        h2o_fatal("no memory");

    stream->stream_id = stream_id;
    h2o_init_request(&stream->req, conn, conn->super.ctx, src_req);
    stream->req.version = 0x200;
    stream->req.upgrade = uv_buf_init(NULL, 0);
    stream->req._ostr_top = &stream->_ostr_final;
    stream->is_half_closed = src_req != NULL;
    stream->_ostr_final.do_send = finalostream_send;
    stream->state = H2O_HTTP2_STREAM_STATE_RECV_PSUEDO_HEADERS;
    h2o_http2_window_init(&stream->output_window, &conn->peer_settings);
    h2o_http2_window_init(&stream->input_window, &H2O_HTTP2_SETTINGS_HOST);
    stream->_req_body = NULL;
    memset(&stream->_data, 0, sizeof(stream->_data));
    memset(&stream->_link, 0, sizeof(stream->_link));

    h2o_http2_conn_register_stream(conn, stream);

    return stream;
}

void h2o_http2_stream_close(h2o_http2_conn_t *conn, h2o_http2_stream_t *stream)
{
    h2o_http2_conn_unregister_stream(conn, stream);
    free(stream->_req_body);
    h2o_dispose_request(&stream->req);
    if (stream->stream_id == 1) {
        free(conn->_http1_req_input);
        conn->_http1_req_input = NULL;
    }
    free(stream);
}

void h2o_http2_stream_reset(h2o_http2_conn_t *conn, h2o_http2_stream_t *stream, int errnum)
{
    switch (stream->state) {
    case H2O_HTTP2_STREAM_STATE_RECV_PSUEDO_HEADERS:
    case H2O_HTTP2_STREAM_STATE_RECV_HEADERS:
    case H2O_HTTP2_STREAM_STATE_RECV_BODY:
    case H2O_HTTP2_STREAM_STATE_REQ_PENDING:
        h2o_http2_stream_close(conn, stream);
        break;
    case H2O_HTTP2_STREAM_STATE_SEND_HEADERS:
    case H2O_HTTP2_STREAM_STATE_SEND_BODY:
    case H2O_HTTP2_STREAM_STATE_END_STREAM:
        /* change the state to EOS, clear all the queued bufs, and close the connection in the callback */
        stream->state = H2O_HTTP2_STREAM_STATE_END_STREAM;
        stream->_data.size = 0;
        if (h2o_http2_conn_stream_is_linked(stream)) {
            /* will be closed in the callaback */
        } else {
            h2o_http2_stream_close(conn, stream);
        }
        break;
    }
}

static size_t calc_max_payload_size(h2o_http2_conn_t *conn, h2o_http2_stream_t *stream)
{
    ssize_t conn_max, stream_max;

    if ((conn_max = h2o_http2_window_get_window(&conn->_write.window)) <= 0)
        return 0;
    if ((stream_max = h2o_http2_window_get_window(&stream->output_window)) <= 0)
        return 0;
    return sz_min(sz_min(conn_max, stream_max), conn->peer_settings.max_frame_size);
}

static void encode_data_header_and_consume_window(h2o_http2_conn_t *conn, h2o_http2_stream_t *stream, uint8_t *header, size_t length, int eos)
{
    assert(header != NULL);
    h2o_http2_encode_frame_header(header, length, H2O_HTTP2_FRAME_TYPE_DATA, eos ? H2O_HTTP2_FRAME_FLAG_END_STREAM : 0, stream->stream_id);
    h2o_http2_window_consume_window(&conn->_write.window, length);
    h2o_http2_window_consume_window(&stream->output_window, length);
}

static uv_buf_t *send_data(h2o_http2_conn_t *conn, h2o_http2_stream_t *stream, uv_buf_t *bufs, size_t bufcnt, int is_final)
{
    ssize_t max_payload_size = 0, payload_size = 0;
    uint8_t *data_header_slot = NULL;

    for (; bufcnt != 0; ++bufs, --bufcnt) {
        while (bufs->len != 0) {
            size_t fill_size;
            /* encode the header, and allocate space for the next header */
            if (payload_size == max_payload_size) {
                if (payload_size != 0)
                    encode_data_header_and_consume_window(conn, stream, data_header_slot, payload_size, 0);
                if ((max_payload_size = calc_max_payload_size(conn, stream)) == 0)
                    goto Exit;
                data_header_slot = h2o_mempool_alloc(conn->_write.pool, H2O_HTTP2_FRAME_HEADER_SIZE);
                h2o_http2_conn_enqueue_write(conn, uv_buf_init((char*)data_header_slot, H2O_HTTP2_FRAME_HEADER_SIZE));
                payload_size = 0;
            }
            /* emit payload */
            fill_size = sz_min(max_payload_size, bufs->len);
            h2o_http2_conn_enqueue_write(conn, uv_buf_init(bufs->base, (unsigned)fill_size));
            bufs->base += fill_size;
            bufs->len -= fill_size;
            payload_size += fill_size;
        }
    }
    /* all data have been emitted */
    if (payload_size != 0) {
        encode_data_header_and_consume_window(conn, stream, data_header_slot, payload_size, is_final);
    } else if (is_final) {
        data_header_slot = h2o_mempool_alloc(conn->_write.pool, H2O_HTTP2_FRAME_HEADER_SIZE);
        h2o_http2_conn_enqueue_write(conn, uv_buf_init((char*)data_header_slot, H2O_HTTP2_FRAME_HEADER_SIZE));
        encode_data_header_and_consume_window(conn, stream, data_header_slot, 0, 1);
    }

Exit:
    return bufs;
}

void finalostream_send(h2o_ostream_t *self, h2o_req_t *req, uv_buf_t *bufs, size_t bufcnt, int is_final)
{
    h2o_http2_stream_t *stream = H2O_STRUCT_FROM_MEMBER(h2o_http2_stream_t, _ostr_final, self);
    h2o_http2_conn_t *conn = (h2o_http2_conn_t*)req->conn;

    assert(stream->_data.size == 0);

    /* send headers */
    switch (stream->state) {
    case H2O_HTTP2_STREAM_STATE_SEND_HEADERS:
        h2o_http2_conn_enqueue_write(conn, h2o_hpack_flatten_headers(&req->pool, stream->stream_id, conn->peer_settings.max_frame_size, &req->res));
        stream->state = H2O_HTTP2_STREAM_STATE_SEND_BODY;
        /* fallthru */
    case H2O_HTTP2_STREAM_STATE_SEND_BODY:
        if (is_final)
            stream->state = H2O_HTTP2_STREAM_STATE_END_STREAM;
        break;
    case H2O_HTTP2_STREAM_STATE_END_STREAM:
        /* might get set by h2o_http2_stream_reset */
        return;
    default:
        assert(!"cannot be in a receiving state");
    }

    /* save the contents in queue */
    if (bufcnt != 0) {
        h2o_vector_reserve(&req->pool, (h2o_vector_t*)&stream->_data, sizeof(uv_buf_t), bufcnt);
        memcpy(stream->_data.entries, bufs, sizeof(uv_buf_t) * bufcnt);
        stream->_data.size = bufcnt;
    }

    h2o_http2_conn_register_for_proceed_callback(conn, stream);
}

void h2o_http2_stream_send_pending_data(h2o_http2_conn_t *conn, h2o_http2_stream_t *stream)
{
    uv_buf_t *nextbuf;

    if (stream->_data.size == 0 || h2o_http2_window_get_window(&stream->output_window) <= 0)
        return;

    nextbuf = send_data(conn, stream, stream->_data.entries, stream->_data.size, stream->state == H2O_HTTP2_STREAM_STATE_END_STREAM);
    if (nextbuf == stream->_data.entries + stream->_data.size) {
        /* sent all data */
        stream->_data.size = 0;
    } else if (nextbuf != stream->_data.entries) {
        /* adjust the buffer */
        size_t newsize = stream->_data.size - (nextbuf - stream->_data.entries);
        memmove(stream->_data.entries, nextbuf, sizeof(uv_buf_t) * newsize);
        stream->_data.size = newsize;
    }
}

void h2o_http2_stream_proceed(h2o_http2_conn_t *conn, h2o_http2_stream_t *stream)
{
    if (stream->state == H2O_HTTP2_STREAM_STATE_END_STREAM) {
        h2o_http2_stream_close(conn, stream);
    } else {
        h2o_proceed_response(&stream->req);
    }
}
