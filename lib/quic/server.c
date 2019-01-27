/*
 * Copyright (c) 2018 Fastly, Kazuho Oku
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
#include <sys/socket.h>
#include "h2o/hq_common.h"
#include "h2o/hq_server.h"

enum h2o_hq_server_stream_state {
    /**
     * receiving headers
     */
    H2O_HQ_SERVER_STREAM_STATE_RECV_HEADERS,
    /**
     * received request but haven't been assigned a handler
     */
    H2O_HQ_SERVER_STREAM_STATE_REQ_PENDING,
    /**
     * waiting for receiving response headers from the handler
     */
    H2O_HQ_SERVER_STREAM_STATE_SEND_HEADERS,
    /**
     * sending body
     */
    H2O_HQ_SERVER_STREAM_STATE_SEND_BODY,
    /**
     * sent fin, waiting for the transport stream to close (`req` is disposed when entering this state)
     */
    H2O_HQ_SERVER_STREAM_STATE_CLOSE_WAIT
};

struct st_h2o_hq_server_conn_t {
    h2o_conn_t super;
    h2o_hq_conn_t hq;
    ptls_handshake_properties_t handshake_properties;
    /**
     * link-list of pending requests using st_h2o_hq_server_stream_t::link
     */
    h2o_linklist_t pending_reqs;
    /**
     * next application-level timeout
     */
    h2o_timer_t timeout;
    /**
     * counter (the order MUST match that of h2o_hq_server_stream; it is accessed by index via the use of counters[])
     */
    union {
        struct {
            uint32_t recv_headers;
            uint32_t req_pending;
            uint32_t send_headers;
            uint32_t send_body;
            uint32_t close_wait;
        };
        uint32_t counters[1];
    } num_streams;
};

struct st_h2o_hq_server_stream_t {
    quicly_stream_t *quic;
    struct {
        h2o_buffer_t *buf;
        int (*handle_input)(struct st_h2o_hq_server_stream_t *stream, const uint8_t **src, const uint8_t *src_end);
    } recvbuf;
    struct {
        H2O_VECTOR(h2o_iovec_t) vecs;
        uint8_t data_frame_header_buf[9];
        uint64_t final_size;
    } sendbuf;
    enum h2o_hq_server_stream_state state;
    h2o_linklist_t link;
    h2o_ostream_t ostr_final;
    h2o_send_state_t send_state;
    h2o_req_t req;
};

static struct st_h2o_hq_server_conn_t *get_conn(struct st_h2o_hq_server_stream_t *stream)
{
    return (void *)stream->req.conn;
}

static uint32_t *get_state_counter(struct st_h2o_hq_server_conn_t *conn, enum h2o_hq_server_stream_state state)
{
    return conn->num_streams.counters + (size_t)state;
}

static void set_state(struct st_h2o_hq_server_stream_t *stream, enum h2o_hq_server_stream_state state)
{
    struct st_h2o_hq_server_conn_t *conn = get_conn(stream);

    --*get_state_counter(conn, stream->state);
    stream->state = state;
    ++*get_state_counter(conn, stream->state);

    if (state == H2O_HQ_SERVER_STREAM_STATE_CLOSE_WAIT)
        h2o_dispose_request(&stream->req);
}

static socklen_t get_sockname(h2o_conn_t *_conn, struct sockaddr *sa)
{
    struct st_h2o_hq_server_conn_t *conn = (void *)_conn;
    return h2o_socket_getsockname(conn->hq.ctx->sock, sa);
}

static socklen_t get_peername(h2o_conn_t *_conn, struct sockaddr *_sa)
{
    struct st_h2o_hq_server_conn_t *conn = (void *)_conn;
    struct sockaddr *sa;
    socklen_t salen;
    quicly_get_peername(conn->hq.quic, &sa, &salen);
    memcpy(_sa, sa, salen);
    return salen;
}

static h2o_iovec_t log_tls_protocol_version(h2o_req_t *_req)
{
    return h2o_iovec_init(H2O_STRLIT("TLSv1.3"));
}

static h2o_iovec_t log_session_reused(h2o_req_t *_req)
{
    /* FIXME */
    return h2o_iovec_init(NULL, 0);
}

static h2o_iovec_t log_cipher(h2o_req_t *_req)
{
    /* FIXME */
    return h2o_iovec_init(NULL, 0);
}

static h2o_iovec_t log_cipher_bits(h2o_req_t *_req)
{
    /* FIXME */
    return h2o_iovec_init(NULL, 0);
}

static h2o_iovec_t log_session_id(h2o_req_t *_req)
{
    /* FIXME */
    return h2o_iovec_init(NULL, 0);
}

static void on_stream_destroy(quicly_stream_t *qs)
{
    struct st_h2o_hq_server_stream_t *stream = qs->data;

    --*get_state_counter(get_conn(stream), stream->state);
    if (h2o_linklist_is_linked(&stream->link))
        h2o_linklist_unlink(&stream->link);
    if (stream->state != H2O_HQ_SERVER_STREAM_STATE_CLOSE_WAIT)
        h2o_dispose_request(&stream->req);
    free(stream);
}

static void on_send_shift(quicly_stream_t *qs, size_t delta)
{
    struct st_h2o_hq_server_stream_t *stream = qs->data;
    size_t i = 0;

    while (delta != 0) {
        assert(i < stream->sendbuf.vecs.size);
        if (delta < stream->sendbuf.vecs.entries[i].len) {
            stream->sendbuf.vecs.entries[i].base += delta;
            stream->sendbuf.vecs.entries[i].len -= delta;
            break;
        }
        delta -= stream->sendbuf.vecs.entries[i].len;
        ++i;
    }
    if (i != 0) {
        memmove(stream->sendbuf.vecs.entries, stream->sendbuf.vecs.entries + i, stream->sendbuf.vecs.size - i);
        stream->sendbuf.vecs.size -= i;
    }

    if (stream->sendbuf.vecs.size == 0) {
        switch (stream->send_state) {
        case H2O_SEND_STATE_IN_PROGRESS:
            h2o_proceed_response(&stream->req);
            break;
        case H2O_SEND_STATE_FINAL:
            assert(quicly_sendstate_transfer_complete(&stream->quic->sendstate));
            break;
        default:
            assert(!"unexpected state");
            break;
        }
    }
}

static int on_send_emit(quicly_stream_t *qs, size_t off, void *_dst, size_t *len, int *wrote_all)
{
    struct st_h2o_hq_server_stream_t *stream = qs->data;
    uint8_t *dst = _dst, *dst_end = dst + *len;
    size_t i = 0;

    /* find the start position */
    while (off != 0) {
        assert(i < stream->sendbuf.vecs.size);
        if (off < stream->sendbuf.vecs.entries[i].len)
            break;
        off -= stream->sendbuf.vecs.entries[i].len;
        ++i;
    }

    /* write */
    *wrote_all = 0;
    while (dst != dst_end) {
        if (i == stream->sendbuf.vecs.size) {
            *wrote_all = 1;
            break;
        }
        size_t sz = stream->sendbuf.vecs.entries[i].len - off;
        if (dst_end - dst < sz)
            sz = dst_end - dst;
        memcpy(dst, stream->sendbuf.vecs.entries[i].base + off, sz);
        dst += sz;
    }

    *len = dst - (uint8_t *)_dst;
    return 0;
}

static int on_send_stop(quicly_stream_t *qs, uint16_t error_code)
{
    struct st_h2o_hq_server_stream_t *stream = qs->data;

    if (!quicly_recvstate_transfer_complete(&stream->quic->recvstate))
        quicly_request_stop(stream->quic, H2O_HQ_ERROR_REQUEST_CANCELLED);

    set_state(stream, H2O_HQ_SERVER_STREAM_STATE_CLOSE_WAIT);

    return 0;
}

static void handle_pending_reqs(h2o_timer_t *timer)
{
    struct st_h2o_hq_server_conn_t *conn = H2O_STRUCT_FROM_MEMBER(struct st_h2o_hq_server_conn_t, timeout, timer);

    /* TODO cap the maximum */
    while (!h2o_linklist_is_empty(&conn->pending_reqs)) {
        struct st_h2o_hq_server_stream_t *stream =
            H2O_STRUCT_FROM_MEMBER(struct st_h2o_hq_server_stream_t, link, conn->pending_reqs.next);
        h2o_linklist_unlink(&stream->link);
        set_state(stream, H2O_HQ_SERVER_STREAM_STATE_SEND_HEADERS);
        h2o_process_request(&stream->req);
    }
}

static void register_pending_req(struct st_h2o_hq_server_stream_t *stream)
{
    struct st_h2o_hq_server_conn_t *conn = get_conn(stream);

    h2o_linklist_insert(&conn->pending_reqs, &stream->link);
    set_state(stream, H2O_HQ_SERVER_STREAM_STATE_REQ_PENDING);
    h2o_timer_link(conn->super.ctx->loop, 0, &conn->timeout);
}

static int on_receive(quicly_stream_t *qs, size_t off, const void *input, size_t len)
{
    struct st_h2o_hq_server_stream_t *stream = qs->data;
    const uint8_t *src, *src_end;
    int ret;

    /* save received data (FIXME avoid copying if possible; see hqclient.c) */
    if ((ret = h2o_hq_update_recvbuf(&stream->recvbuf.buf, off, input, len)) != 0)
        return ret;

    /* consume contiguous bytes */
    src = (const uint8_t *)stream->recvbuf.buf->bytes;
    src_end = src + quicly_recvstate_bytes_available(&stream->quic->recvstate);
    while (src != src_end) {
        if ((ret = stream->recvbuf.handle_input(stream, &src, src_end)) != 0)
            break;
    }
    h2o_buffer_consume(&stream->recvbuf.buf, src - (const uint8_t *)stream->recvbuf.buf->bytes);

    if (quicly_recvstate_transfer_complete(&stream->quic->recvstate)) {
        if (ret != 0) {
            quicly_reset_stream(stream->quic, ret == H2O_HQ_ERROR_INCOMPLETE ? H2O_HQ_ERROR_GENERAL_PROTOCOL : ret);
            set_state(stream, H2O_HQ_SERVER_STREAM_STATE_CLOSE_WAIT);
        } else if (stream->state == H2O_HQ_SERVER_STREAM_STATE_RECV_HEADERS) {
            quicly_reset_stream(stream->quic, H2O_HQ_ERROR_INCOMPLETE_REQUEST);
            set_state(stream, H2O_HQ_SERVER_STREAM_STATE_CLOSE_WAIT);
        } else {
            /* we are processing the request */
        }
    } else {
        switch (ret) {
        case 0:
        case H2O_HQ_ERROR_INCOMPLETE:
            /* ok */
            break;
        default:
            quicly_request_stop(stream->quic, ret);
            quicly_reset_stream(stream->quic, ret);
            break;
        }
    }

    return 0;
}

static int on_receive_reset(quicly_stream_t *qs, uint16_t error_code)
{
    struct st_h2o_hq_server_stream_t *stream = qs->data;

    if (!quicly_sendstate_transfer_complete(&stream->quic->sendstate))
        quicly_reset_stream(stream->quic, H2O_HQ_ERROR_STOPPING);

    assert(stream->state != H2O_HQ_SERVER_STREAM_STATE_CLOSE_WAIT);
    if (h2o_linklist_is_linked(&stream->link))
        h2o_linklist_unlink(&stream->link);
    set_state(stream, H2O_HQ_SERVER_STREAM_STATE_CLOSE_WAIT);

    return 0;
}

static int handle_input_expect_headers(struct st_h2o_hq_server_stream_t *stream, const uint8_t **src, const uint8_t *src_end)
{
    struct st_h2o_hq_server_conn_t *conn = get_conn(stream);
    h2o_hq_read_frame_t frame;
    int header_exists_map, ret;
    const char *err_desc;
    uint8_t header_ack[H2O_HPACK_ENCODE_INT_MAX_LENGTH];
    size_t header_ack_len;

    /* read haeders frame */
    if ((ret = h2o_hq_read_frame(&frame, src, src_end, &err_desc)) != 0)
        return ret;
    if (frame.type != H2O_HQ_FRAME_TYPE_HEADERS)
        return H2O_HQ_ERROR_GENERAL_PROTOCOL;

    if ((ret = h2o_qpack_parse_request(&stream->req.pool, get_conn(stream)->hq.qpack.dec, stream->quic->stream_id,
                                       &stream->req.input.method, &stream->req.input.scheme, &stream->req.input.authority,
                                       &stream->req.input.path, &stream->req.headers, &header_exists_map,
                                       &stream->req.content_length, NULL /* TODO cache-digests */, header_ack, &header_ack_len,
                                       frame.payload, frame.length, &err_desc)) != 0) {
        if (ret != H2O_HTTP2_ERROR_INVALID_HEADER_CHAR)
            return ret;
        if (!quicly_recvstate_transfer_complete(&stream->quic->recvstate))
            quicly_request_stop(stream->quic, H2O_HQ_ERROR_EARLY_RESPONSE);
        h2o_send_error_400(&stream->req, "Invalid Request", err_desc, 0);
        return 0;
    }
    if (header_ack_len != 0)
        h2o_hq_send_qpack_header_ack(&conn->hq, header_ack, header_ack_len);

    register_pending_req(stream);
    return 0;
}

static void write_response(struct st_h2o_hq_server_stream_t *stream)
{
    h2o_byte_vector_t buf = {NULL};

    h2o_hq_encode_frame(&stream->req.pool, &buf, H2O_HQ_FRAME_TYPE_HEADERS, {
        h2o_qpack_flatten_response(get_conn(stream)->hq.qpack.enc, &stream->req.pool, stream->quic->stream_id, NULL, &buf,
                                   stream->req.res.status, stream->req.res.headers.entries, stream->req.res.headers.size,
                                   &get_conn(stream)->super.ctx->globalconf->server_name, stream->req.res.content_length);
    });

    h2o_vector_reserve(&stream->req.pool, &stream->sendbuf.vecs, stream->sendbuf.vecs.size + 1);
    stream->sendbuf.vecs.entries[stream->sendbuf.vecs.size++] = h2o_iovec_init(buf.entries, buf.size);
    stream->sendbuf.final_size += buf.size;
}

static void do_send(h2o_ostream_t *_ostr, h2o_req_t *_req, h2o_iovec_t *bufs, size_t bufcnt, h2o_send_state_t _state)
{
    struct st_h2o_hq_server_stream_t *stream = H2O_STRUCT_FROM_MEMBER(struct st_h2o_hq_server_stream_t, ostr_final, _ostr);
    assert(&stream->req == _req);

    stream->send_state = _state;

    if (stream->state == H2O_HQ_SERVER_STREAM_STATE_SEND_HEADERS) {
        write_response(stream);
        set_state(stream, H2O_HQ_SERVER_STREAM_STATE_SEND_BODY);
    } else {
        assert(stream->state == H2O_HQ_SERVER_STREAM_STATE_SEND_BODY);
    }

    if (bufcnt != 0) {
        size_t i;
        /* build DATA frame header */
        uint64_t size_total = 0;
        for (i = 0; i != bufcnt; ++i)
            size_total += bufs[i].len;
        size_t header_size =
            quicly_encodev(stream->sendbuf.data_frame_header_buf, size_total) - stream->sendbuf.data_frame_header_buf;
        stream->sendbuf.data_frame_header_buf[header_size++] = H2O_HQ_FRAME_TYPE_DATA;
        /* write */
        h2o_vector_reserve(&stream->req.pool, &stream->sendbuf.vecs, stream->sendbuf.vecs.size + 1 + bufcnt);
        stream->sendbuf.vecs.entries[stream->sendbuf.vecs.size++] =
            h2o_iovec_init(stream->sendbuf.data_frame_header_buf, header_size);
        stream->sendbuf.final_size += header_size;
        memcpy(stream->sendbuf.vecs.entries + stream->sendbuf.vecs.size, bufs, bufcnt * sizeof(h2o_iovec_t));
        stream->sendbuf.vecs.size += bufcnt;
        stream->sendbuf.final_size += size_total;
    }

    switch (stream->send_state) {
    case H2O_SEND_STATE_IN_PROGRESS:
        break;
    case H2O_SEND_STATE_FINAL:
        quicly_sendstate_shutdown(&stream->quic->sendstate, stream->sendbuf.final_size);
        break;
    case H2O_SEND_STATE_ERROR:
        quicly_reset_stream(stream->quic, H2O_HQ_ERROR_INTERNAL);
        break;
    }
}

static void do_send_informational(h2o_ostream_t *_ostr, h2o_req_t *_req)
{
    struct st_h2o_hq_server_stream_t *stream = H2O_STRUCT_FROM_MEMBER(struct st_h2o_hq_server_stream_t, ostr_final, _ostr);
    assert(&stream->req == _req);

    write_response(stream);
}

static int handle_control_stream_frame(h2o_hq_conn_t *_conn, uint8_t type, const uint8_t *payload, size_t len,
                                       const char **err_desc)
{
    struct st_h2o_hq_server_conn_t *conn = H2O_STRUCT_FROM_MEMBER(struct st_h2o_hq_server_conn_t, hq, _conn);
    int ret;

    switch (type) {
    case H2O_HQ_FRAME_TYPE_SETTINGS:
        if ((ret = h2o_hq_handle_settings_frame(&conn->hq, payload, len, err_desc)) != 0)
            return ret;
        break;
    default:
        break;
    }

    return 0;
}

int h2o_hq_server_on_stream_open(quicly_stream_t *qs)
{
    static const quicly_stream_callbacks_t callbacks = {on_stream_destroy, on_send_shift, on_send_emit,
                                                        on_send_stop,      on_receive,    on_receive_reset};

    /* handling of unidirectional streams is not server-specific */
    if (quicly_stream_is_unidirectional(qs->stream_id)) {
        h2o_hq_on_create_unidirectional_stream(qs);
        return 0;
    }

    assert(quicly_stream_is_client_initiated(qs->stream_id));

    /* create new stream and start handling the request */
    struct st_h2o_hq_server_stream_t *stream = h2o_mem_alloc(sizeof(*stream));
    stream->quic = qs;
    h2o_buffer_init(&stream->recvbuf.buf, &h2o_socket_buffer_prototype);
    stream->recvbuf.handle_input = handle_input_expect_headers;
    memset(&stream->sendbuf.vecs, 0, sizeof(stream->sendbuf.vecs));
    stream->sendbuf.final_size = 0;
    stream->state = H2O_HQ_SERVER_STREAM_STATE_RECV_HEADERS;
    stream->link = (h2o_linklist_t){NULL};
    stream->ostr_final = (h2o_ostream_t){NULL, do_send, NULL, NULL, do_send_informational};
    stream->send_state = H2O_SEND_STATE_IN_PROGRESS;
    h2o_init_request(&stream->req,
                     &H2O_STRUCT_FROM_MEMBER(struct st_h2o_hq_server_conn_t, hq, *quicly_get_data(stream->quic->conn))->super,
                     NULL);
    stream->req.version = 0x0300;
    stream->req._ostr_top = &stream->ostr_final;

    stream->quic->data = stream;
    stream->quic->callbacks = &callbacks;

    ++*get_state_counter(get_conn(stream), stream->state);
    return 0;
}

h2o_hq_conn_t *h2o_hq_server_accept(h2o_hq_ctx_t *_ctx, struct sockaddr *sa, socklen_t salen, quicly_decoded_packet_t *packets,
                                    size_t num_packets)
{
    h2o_hq_server_ctx_t *ctx = (void *)_ctx;
    size_t i, syn_index = SIZE_MAX;

    /* find the Initial packet */
    for (i = 0; i != num_packets; ++i) {
        if (packets[i].octets.base[0] == 0xff) {
            syn_index = i;
            goto SynFound;
        }
    }
    return NULL;

SynFound : {
    static const h2o_conn_callbacks_t conn_callbacks = {
        get_sockname,
        get_peername,
        NULL, /* push */
        NULL, /* should expose is_early_data instead of get_socket, because QUIC shares single socket */
        NULL, /* get debug state */
        {{
            {log_tls_protocol_version, log_session_reused, log_cipher, log_cipher_bits, log_session_id}, /* ssl */
            {NULL},                                                                                      /* http1 */
            {NULL}                                                                                       /* http2 */
        }}                                                                                               /* loggers */
    };
    struct st_h2o_hq_server_conn_t *conn = (void *)h2o_create_connection(
        sizeof(*conn), ctx->accept_ctx->ctx, ctx->accept_ctx->hosts, h2o_gettimeofday(ctx->accept_ctx->ctx->loop), &conn_callbacks);
    h2o_hq_init_conn(&conn->hq, &ctx->super, handle_control_stream_frame);
    conn->handshake_properties = (ptls_handshake_properties_t){{{{NULL}}}};
    h2o_linklist_init_anchor(&conn->pending_reqs);
    h2o_timer_init(&conn->timeout, handle_pending_reqs);
    quicly_conn_t *qconn;

    /* accept connection */
    if (quicly_accept(&qconn, ctx->super.quic, sa, salen, &conn->handshake_properties, packets + syn_index) != 0) {
        h2o_hq_dispose_conn(&conn->hq);
        free(conn);
        return NULL;
    }
    h2o_hq_setup(&conn->hq, qconn);
    /* handle the other packet */
    for (i = 0; i != num_packets; ++i) {
        if (i == syn_index)
            continue;
        quicly_receive(conn->hq.quic, packets + i);
    }
    h2o_hq_send(&conn->hq);
    return &conn->hq;
}
}

static void initiate_graceful_shutdown(h2o_context_t *ctx)
{
}

static int foreach_request(h2o_context_t *ctx, int (*cb)(h2o_req_t *req, void *cbdata), void *cbdata)
{
    return 0;
}

const h2o_protocol_callbacks_t H2O_HQ_SERVER_CALLBACKS = {initiate_graceful_shutdown, foreach_request};
