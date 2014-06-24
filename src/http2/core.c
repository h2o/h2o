#include <stdio.h>
#include <stdlib.h>
#include "h2o.h"
#include "h2o/http1.h"
#include "h2o/http2.h"
#include "internal.h"

#define INCOMPLETE -2
#define PROTOCOL_ERROR -1

static const uv_buf_t CONNECTION_PREFACE = { H2O_STRLIT("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n") };

static const h2o_http2_settings_t HOST_SETTINGS = {
    /* header_table_size = */ 4096,
    /* enable_push = */ 0,
    /* max_concurrent_streams = */ 1,
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
        "\x00\x03" "\x00\x00\x00\x01" /* max_concurrent_streams = 1*/

        "\x00\x00\x00" /* frame size */
        "\x04" /* settings frame */
        "\x01" /* ack flag */
        "\x00\x00\x00\x00" /* stream id */
    )
};

static void close_connection(h2o_http2_conn_t *conn)
{
    h2o_dispose_request(&conn->req);
    free(conn->_input);
    conn->close_cb(conn);
}

static uv_buf_t alloc_inbuf(uv_handle_t *handle, size_t suggested_size)
{
    h2o_http2_conn_t *conn = handle->data;
    return h2o_allocate_input_buffer(&conn->_input, suggested_size);
}

static int decode_stream_header(h2o_http2_conn_t *conn, h2o_http2_frame_header_t *header)
{
    const uint8_t *src = (const uint8_t*)conn->_input->bytes;

    if (conn->_input->size < H2O_HTTP2_FRAME_HEADER_SIZE)
        return INCOMPLETE;

    header->length = decode24u(src);
    header->type = src[3];
    header->flags = src[4];
    header->stream_id = decode32u(src + 5);

    if (header->length > HOST_SETTINGS.max_frame_size)
        return PROTOCOL_ERROR;

    if (conn->_input->size < H2O_HTTP2_FRAME_HEADER_SIZE + header->length)
        return INCOMPLETE;

    return 0;
}

static int expect_anyframe(h2o_http2_conn_t *conn)
{
    h2o_http2_frame_header_t header;
    int status;

    if ((status = decode_stream_header(conn, &header)) != 0)
        return status;

    fprintf(stderr, "got frame of type:%d\n", header.type);
    h2o_consume_input_buffer(&conn->_input, H2O_HTTP2_FRAME_HEADER_SIZE + header.length);
    return 0;
}

static int expect_preface(h2o_http2_conn_t *conn)
{
    if (conn->_input->size < CONNECTION_PREFACE.len) {
        return INCOMPLETE;
    }
    if (memcmp(conn->_input->bytes, CONNECTION_PREFACE.base, CONNECTION_PREFACE.len) != 0) {
        return PROTOCOL_ERROR;
    }

    h2o_consume_input_buffer(&conn->_input, CONNECTION_PREFACE.len);
    conn->_read_expect = expect_anyframe;
    return 0;
}

static void on_read(uv_stream_t *stream, ssize_t nread, uv_buf_t _buf)
{
    h2o_http2_conn_t *conn = stream->data;

    if (nread == -1) {
        close_connection(conn);
        return;
    }

    conn->_input->size += nread;

    while (conn->_input->size != 0) {
        switch (conn->_read_expect(conn)) {
        case PROTOCOL_ERROR: /* error */
            fprintf(stderr, "protocol error\n");
            close_connection(conn);
            return;
        case INCOMPLETE: /* incomplete */
            return;
        default:
            break;
        }
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
    if (conn->_input != NULL && conn->_input->size != 0)
        conn->_read_expect(conn);

    /* handle the request */
    conn->req_cb(&conn->req);
}

static void on_send_complete(uv_write_t *wreq, int status)
{
    h2o_http2_conn_t *conn = wreq->data;

    /* FIXME */
}

static void on_send_next(uv_write_t *wreq, int status)
{
    h2o_http2_conn_t *conn = wreq->data;

    if (status != 0)
        close_connection(conn);
    else
        conn->req._generator->proceed(conn->req._generator, &conn->req, status);
}

static uv_buf_t finalostream_build_frame_header(h2o_mempool_t *pool, h2o_http2_finalostream_t *self, size_t length, int is_final, uint32_t stream_id)
{
    static char buf[9];
    uv_buf_t out = uv_buf_init(buf, H2O_HTTP2_FRAME_HEADER_SIZE);
    h2o_http2_encode_frame_header(
        (uint8_t*)out.base,
        length,
        H2O_HTTP2_DATA_FRAME_TYPE,
        is_final ? H2O_HTTP2_END_STREAM_FRAME_FLAG : 0,
        stream_id);
    return out;
}

static void finalostream_send(h2o_ostream_t *_self, h2o_req_t *req, uv_buf_t *inbufs, size_t incnt, int *is_final)
{
    h2o_http2_finalostream_t *self = (void*)_self;
    h2o_http2_conn_t *conn = req->conn;
    uv_buf_t *outbufs;
    int alloc_cnt = 0, outcnt, i;
    size_t total_data_size = 0;

    assert(self == &conn->_ostr_final);

    /* calculate the number of buffers we need (in the worst case) */
    if (! self->sent_headers) {
        ++alloc_cnt;
    }
    if (incnt != 0) {
        for (i = 0; i != incnt; ++i) {
            if (inbufs[i].len != 0) {
                alloc_cnt += (inbufs[i].len / conn->peer_settings.max_frame_size) * 2 + 3;
                total_data_size += inbufs[i].len;
            }
        }
    } else if (*is_final) {
        ++alloc_cnt;
    }

    /* allocate */
    outbufs = alloca(sizeof(uv_buf_t) * alloc_cnt);
    outcnt = 0;

    /* emit the headers if necessary */
    if (! self->sent_headers) {
        self->sent_headers = 1;
        outbufs[outcnt++] = h2o_http2_flatten_headers(&req->pool, conn->peer_settings.max_frame_size, &req->res);
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
                        outbufs[outcnt++] = finalostream_build_frame_header(
                            &req->pool, self,
                            sz_min(total_data_size, conn->peer_settings.max_frame_size),
                            *is_final && total_data_size <= conn->peer_settings.max_frame_size,
                            1);
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
    } else if (*is_final) {
        outbufs[outcnt++] = finalostream_build_frame_header(&req->pool, self, 0, 1, 1);
    }

    assert(outcnt != 0);
    assert(outcnt <= alloc_cnt);

    uv_write(&conn->_wreq, conn->stream, outbufs, outcnt, *is_final ? on_send_complete : on_send_next);
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
    h2o_http2_settings_init(&http2conn->peer_settings);
    h2o_init_request(&http2conn->req, http2conn, req->ctx, req);
    http2conn->req.version = 0x200;
    http2conn->req.upgrade = uv_buf_init(NULL, 0);
    http2conn->_read_expect = expect_preface;
    http2conn->_input = NULL;
    http2conn->_wreq.data = http2conn;
    http2conn->req._ostr_top = &http2conn->_ostr_final.super;
    http2conn->_ostr_final.super.do_send = finalostream_send;
    http2conn->_ostr_final.sent_headers = 0;


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
    if (h2o_http2_settings_decode_payload(&http2conn->peer_settings, (uint8_t*)settings_decoded.base, settings_decoded.len) != 0) {
        return -1;
    }

    /* send response */
    req->res.status = 101;
    req->res.reason = "Switching Protocols";
    h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_UPGRADE, H2O_STRLIT("h2c"));
    h2o_http1_upgrade(req->conn, (uv_buf_t*)&HOST_SETTINGS_BIN, 1, on_upgrade_complete, http2conn);

    return 0;
}
