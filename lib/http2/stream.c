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
#include "h2o.h"
#include "h2o/http2.h"
#include "internal.h"

static void finalostream_start_pull(h2o_ostream_t *self, h2o_ostream_pull_cb cb);
static void finalostream_send(h2o_ostream_t *self, h2o_req_t *req, h2o_iovec_t *bufs, size_t bufcnt, int is_final);

h2o_http2_stream_t *h2o_http2_stream_open(h2o_http2_conn_t *conn, uint32_t stream_id, h2o_req_t *src_req, uint32_t push_parent_stream_id)
{
    h2o_http2_stream_t *stream = h2o_mem_alloc(sizeof(*stream));

    /* init properties (other than req) */
    memset(stream, 0, offsetof(h2o_http2_stream_t, req));
    stream->stream_id = stream_id;
    stream->_ostr_final.do_send = finalostream_send;
    stream->_ostr_final.start_pull = finalostream_start_pull;
    stream->state = H2O_HTTP2_STREAM_STATE_IDLE;
    h2o_http2_window_init(&stream->output_window, &conn->peer_settings);
    h2o_http2_window_init(&stream->input_window, &H2O_HTTP2_SETTINGS_HOST);
    stream->_expected_content_length = SIZE_MAX;
    stream->push.parent_stream_id = push_parent_stream_id;

    /* init request */
    h2o_init_request(&stream->req, &conn->super, src_req);
    stream->req.version = 0x200;
    if (src_req != NULL)
        memset(&stream->req.upgrade, 0, sizeof(stream->req.upgrade));
    stream->req._ostr_top = &stream->_ostr_final;

    h2o_http2_conn_register_stream(conn, stream);
    ++conn->num_streams.priority;

    return stream;
}

void h2o_http2_stream_close(h2o_http2_conn_t *conn, h2o_http2_stream_t *stream)
{
    h2o_http2_conn_unregister_stream(conn, stream);
    if (stream->_req_headers != NULL)
        h2o_buffer_dispose(&stream->_req_headers);
    if (stream->_req_body != NULL)
        h2o_buffer_dispose(&stream->_req_body);
    h2o_dispose_request(&stream->req);
    if (stream->stream_id == 1 && conn->_http1_req_input != NULL)
        h2o_buffer_dispose(&conn->_http1_req_input);
    free(stream);
}

void h2o_http2_stream_reset(h2o_http2_conn_t *conn, h2o_http2_stream_t *stream)
{
    switch (stream->state) {
    case H2O_HTTP2_STREAM_STATE_IDLE:
    case H2O_HTTP2_STREAM_STATE_RECV_HEADERS:
    case H2O_HTTP2_STREAM_STATE_RECV_BODY:
    case H2O_HTTP2_STREAM_STATE_REQ_PENDING:
        h2o_http2_stream_close(conn, stream);
        break;
    case H2O_HTTP2_STREAM_STATE_SEND_HEADERS:
    case H2O_HTTP2_STREAM_STATE_SEND_BODY:
        h2o_http2_stream_set_state(conn, stream, H2O_HTTP2_STREAM_STATE_END_STREAM);
    /* continues */
    case H2O_HTTP2_STREAM_STATE_END_STREAM:
        /* clear all the queued bufs, and close the connection in the callback */
        stream->_data.size = 0;
        if (h2o_linklist_is_linked(&stream->_refs.link)) {
            /* will be closed in the callback */
        } else {
            h2o_http2_stream_close(conn, stream);
        }
        break;
    }
}

static size_t calc_max_payload_size(h2o_http2_conn_t *conn, h2o_http2_stream_t *stream)
{
    ssize_t conn_max, stream_max;

    if ((conn_max = h2o_http2_conn_get_buffer_window(conn)) <= 0)
        return 0;
    if ((stream_max = h2o_http2_window_get_window(&stream->output_window)) <= 0)
        return 0;
    return sz_min(sz_min(conn_max, stream_max), conn->peer_settings.max_frame_size);
}

static void encode_data_header_and_consume_window(h2o_http2_conn_t *conn, h2o_http2_stream_t *stream, uint8_t *header,
                                                  size_t length, int eos)
{
    assert(header != NULL);
    h2o_http2_encode_frame_header(header, length, H2O_HTTP2_FRAME_TYPE_DATA, eos ? H2O_HTTP2_FRAME_FLAG_END_STREAM : 0,
                                  stream->stream_id);
    h2o_http2_window_consume_window(&conn->_write.window, length);
    h2o_http2_window_consume_window(&stream->output_window, length);
}

static int send_data_pull(h2o_http2_conn_t *conn, h2o_http2_stream_t *stream)
{
    size_t max_payload_size;
    h2o_iovec_t cbuf;
    int is_final = 0;

    do {
        if ((max_payload_size = calc_max_payload_size(conn, stream)) == 0)
            break;
        /* reserve buffer */
        h2o_buffer_reserve(&conn->_write.buf, H2O_HTTP2_FRAME_HEADER_SIZE + max_payload_size);
        /* obtain content */
        cbuf.base = conn->_write.buf->bytes + conn->_write.buf->size + H2O_HTTP2_FRAME_HEADER_SIZE;
        cbuf.len = max_payload_size;
        is_final = h2o_pull(&stream->req, stream->_pull_cb, &cbuf);
        /* write the header */
        encode_data_header_and_consume_window(conn, stream, (void *)(conn->_write.buf->bytes + conn->_write.buf->size), cbuf.len,
                                              is_final);
        /* adjust the write buf size */
        conn->_write.buf->size += H2O_HTTP2_FRAME_HEADER_SIZE + cbuf.len;
    } while (!is_final);

    return is_final;
}

static h2o_iovec_t *send_data_push(h2o_http2_conn_t *conn, h2o_http2_stream_t *stream, h2o_iovec_t *bufs, size_t bufcnt,
                                   int is_final)
{
    ssize_t max_payload_size = 0, payload_size = 0;
    size_t data_header_offset = 0;

    for (; bufcnt != 0; ++bufs, --bufcnt) {
        while (bufs->len != 0) {
            size_t fill_size;
            /* encode the header, and allocate space for the next header */
            if (payload_size == max_payload_size) {
                if (payload_size != 0)
                    encode_data_header_and_consume_window(conn, stream, (uint8_t *)conn->_write.buf->bytes + data_header_offset,
                                                          payload_size, 0);
                if ((max_payload_size = calc_max_payload_size(conn, stream)) == 0)
                    goto Exit;
                h2o_buffer_reserve(&conn->_write.buf, H2O_HTTP2_FRAME_HEADER_SIZE);
                data_header_offset = conn->_write.buf->size;
                conn->_write.buf->size += H2O_HTTP2_FRAME_HEADER_SIZE;
                payload_size = 0;
            }
            /* emit payload */
            fill_size = sz_min(max_payload_size, bufs->len);
            memcpy(h2o_buffer_reserve(&conn->_write.buf, fill_size).base, bufs->base, fill_size);
            conn->_write.buf->size += fill_size;
            bufs->base += fill_size;
            bufs->len -= fill_size;
            payload_size += fill_size;
        }
    }
    /* all data have been emitted */
    if (payload_size != 0) {
        encode_data_header_and_consume_window(conn, stream, (uint8_t *)conn->_write.buf->bytes + data_header_offset, payload_size,
                                              is_final);
    } else if (is_final) {
        encode_data_header_and_consume_window(
            conn, stream, (void *)h2o_buffer_reserve(&conn->_write.buf, H2O_HTTP2_FRAME_HEADER_SIZE).base, 0, 1);
        conn->_write.buf->size += H2O_HTTP2_FRAME_HEADER_SIZE;
    }

Exit:
    return bufs;
}

static int send_headers(h2o_http2_conn_t *conn, h2o_http2_stream_t *stream)
{
    h2o_timestamp_t ts;
    size_t i;

    h2o_get_timestamp(conn->super.ctx, &stream->req.pool, &ts);

    /* send PUSH_PROMISE frame if is push */
    if (h2o_http2_stream_is_push(stream->stream_id)) {
        /* cancel the PUSH unless it is 200 OK */
        if (stream->req.res.status != 200) {
            h2o_http2_stream_set_state(conn, stream, H2O_HTTP2_STREAM_STATE_END_STREAM);
            h2o_http2_conn_register_for_proceed_callback(conn, stream);
            return -1;
        }
        h2o_hpack_flatten_request(&conn->_write.buf, &conn->_output_header_table, stream->stream_id,
                                  conn->peer_settings.max_frame_size, &stream->req, stream->push.parent_stream_id);
    }

    /* FIXME the function may return error, check it! */
    h2o_hpack_flatten_response(&conn->_write.buf, &conn->_output_header_table, stream->stream_id,
                               conn->peer_settings.max_frame_size, &stream->req.res, &ts,
                               &conn->super.ctx->globalconf->server_name);
    h2o_http2_conn_request_write(conn);
    h2o_http2_stream_set_state(conn, stream, H2O_HTTP2_STREAM_STATE_SEND_BODY);

    /* push URLs */
    for (i = 0; i != stream->req.http2_push_urls.size; ++i)
        h2o_http2_conn_push_url(conn, stream->req.http2_push_urls.entries[i], stream);

    return 0;
}

void finalostream_start_pull(h2o_ostream_t *self, h2o_ostream_pull_cb cb)
{
    h2o_http2_stream_t *stream = H2O_STRUCT_FROM_MEMBER(h2o_http2_stream_t, _ostr_final, self);
    h2o_http2_conn_t *conn = (void *)stream->req.conn;

    assert(stream->req._ostr_top == &stream->_ostr_final);
    assert(stream->state == H2O_HTTP2_STREAM_STATE_SEND_HEADERS);

    /* register the pull callback */
    stream->_pull_cb = cb;

    /* send headers */
    if (send_headers(conn, stream) != 0)
        return;

    /* set dummy data in the send buffer */
    h2o_vector_reserve(&stream->req.pool, (h2o_vector_t *)&stream->_data, sizeof(h2o_iovec_t), 1);
    stream->_data.entries[0].base = "<pull interface>";
    stream->_data.entries[0].len = 1;
    stream->_data.size = 1;

    h2o_http2_conn_register_for_proceed_callback(conn, stream);
}

void finalostream_send(h2o_ostream_t *self, h2o_req_t *req, h2o_iovec_t *bufs, size_t bufcnt, int is_final)
{
    h2o_http2_stream_t *stream = H2O_STRUCT_FROM_MEMBER(h2o_http2_stream_t, _ostr_final, self);
    h2o_http2_conn_t *conn = (h2o_http2_conn_t *)req->conn;

    assert(stream->_data.size == 0);

    /* send headers */
    switch (stream->state) {
    case H2O_HTTP2_STREAM_STATE_SEND_HEADERS:
        if (send_headers(conn, stream) != 0)
            return;
    /* fallthru */
    case H2O_HTTP2_STREAM_STATE_SEND_BODY:
        if (is_final)
            h2o_http2_stream_set_state(conn, stream, H2O_HTTP2_STREAM_STATE_END_STREAM);
        break;
    case H2O_HTTP2_STREAM_STATE_END_STREAM:
        /* might get set by h2o_http2_stream_reset */
        return;
    default:
        assert(!"cannot be in a receiving state");
    }

    /* save the contents in queue */
    if (bufcnt != 0) {
        h2o_vector_reserve(&req->pool, (h2o_vector_t *)&stream->_data, sizeof(h2o_iovec_t), bufcnt);
        memcpy(stream->_data.entries, bufs, sizeof(h2o_iovec_t) * bufcnt);
        stream->_data.size = bufcnt;
    }

    h2o_http2_conn_register_for_proceed_callback(conn, stream);
}

void h2o_http2_stream_send_pending_data(h2o_http2_conn_t *conn, h2o_http2_stream_t *stream)
{
    if (h2o_http2_window_get_window(&stream->output_window) <= 0)
        return;

    if (stream->_pull_cb != NULL) {
        /* pull mode */
        assert(stream->state != H2O_HTTP2_STREAM_STATE_END_STREAM);
        if (send_data_pull(conn, stream)) {
            /* sent all data */
            stream->_data.size = 0;
            h2o_http2_stream_set_state(conn, stream, H2O_HTTP2_STREAM_STATE_END_STREAM);
        }
    } else {
        /* push mode */
        h2o_iovec_t *nextbuf = send_data_push(conn, stream, stream->_data.entries, stream->_data.size,
                                              stream->state == H2O_HTTP2_STREAM_STATE_END_STREAM);
        if (nextbuf == stream->_data.entries + stream->_data.size) {
            /* sent all data */
            stream->_data.size = 0;
        } else if (nextbuf != stream->_data.entries) {
            /* adjust the buffer */
            size_t newsize = stream->_data.size - (nextbuf - stream->_data.entries);
            memmove(stream->_data.entries, nextbuf, sizeof(h2o_iovec_t) * newsize);
            stream->_data.size = newsize;
        }
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
