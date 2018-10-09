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
    H2O_HQ_SERVER_STREAM_STATE_SEND_BODY
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
        };
        uint32_t counters[1];
    } num_streams;
};

struct st_h2o_hq_server_stream_t {
    quicly_stream_t *quic;
    enum h2o_hq_server_stream_state state;
    h2o_linklist_t link;
    h2o_timer_t timer;
    h2o_ostream_t ostr_final;
    h2o_send_state_t send_state;
    uint8_t data_frame_header_buf[8 + 1];
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

static int on_stream_wait_close(quicly_stream_t *stream)
{
    assert(stream->data == NULL);
    if (quicly_stream_is_closable(stream))
        quicly_close_stream(stream);
    return 0;
}

static int destroy_stream(struct st_h2o_hq_server_stream_t *stream, quicly_stream_error_t stream_error)
{
    int ret;

    assert(stream_error != QUICLY_STREAM_ERROR_IS_OPEN);

    stream->quic->data = NULL;
    if (quicly_stream_is_closable(stream->quic)) {
        quicly_close_stream(stream->quic);
    } else {
        if (stream_error == QUICLY_STREAM_ERROR_FIN_CLOSED) {
            quicly_sendbuf_shutdown(&stream->quic->sendbuf);
            quicly_request_stop(stream->quic, H2O_HQ_ERROR_EARLY_RESPONSE);
        } else {
            if ((ret = h2o_hq_send_qpack_stream_cancel(&get_conn(stream)->hq, stream->quic->stream_id)) != 0)
                return ret;
            quicly_reset_stream(stream->quic, stream_error);
            quicly_request_stop(stream->quic, stream_error);
        }
        stream->quic->on_update = on_stream_wait_close;
    }
    stream->quic = NULL;

    --*get_state_counter(get_conn(stream), stream->state);
    if (h2o_linklist_is_linked(&stream->link))
        h2o_linklist_unlink(&stream->link);
    h2o_dispose_request(&stream->req);
    free(stream);

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

static int on_update_req_pending(quicly_stream_t *_stream)
{
    struct st_h2o_hq_server_stream_t *stream = _stream->data;
    quicly_stream_error_t stream_error;

    if ((stream_error = quicly_sendbuf_get_error(&stream->quic->sendbuf)) != QUICLY_STREAM_ERROR_IS_OPEN) {
        assert(stream_error != QUICLY_STREAM_ERROR_FIN_CLOSED);
        return destroy_stream(stream, QUICLY_STREAM_ERROR_STOPPED);
    }

    return 0;
}

static void register_pending_req(struct st_h2o_hq_server_stream_t *stream)
{
    h2o_linklist_insert(&get_conn(stream)->pending_reqs, &stream->link);
    set_state(stream, H2O_HQ_SERVER_STREAM_STATE_REQ_PENDING);
    stream->quic->on_update = on_update_req_pending;

    struct st_h2o_hq_server_conn_t *conn = get_conn(stream);
    h2o_timer_link(conn->super.ctx->loop, 0, &conn->timeout);
}

static int on_update_expect_headers(quicly_stream_t *_stream)
{
    struct st_h2o_hq_server_stream_t *stream = _stream->data;
    quicly_stream_error_t stream_error;
    h2o_hq_peek_frame_t frame;
    int header_exists_map, ret;
    uint8_t header_ack[H2O_HPACK_ENCODE_INT_MAX_LENGTH];
    size_t header_ack_len;
    const char *err_desc = NULL;

    /* error handling */
    if ((stream_error = quicly_recvbuf_get_error(&stream->quic->recvbuf)) != QUICLY_STREAM_ERROR_IS_OPEN)
        return destroy_stream(stream, H2O_HQ_ERROR_INCOMPLETE_REQUEST);

    /* read HEADERS frame */
    if ((ret = h2o_hq_peek_frame(&stream->quic->recvbuf, &frame)) != 0) {
        if (ret == H2O_HQ_ERROR_INCOMPLETE)
            return 0;
        return destroy_stream(stream, ret);
    }
    if (frame.type != H2O_HQ_FRAME_TYPE_HEADERS)
        return destroy_stream(stream, H2O_HQ_ERROR_GENERAL_PROTOCOL);
    if ((ret = h2o_qpack_parse_request(&stream->req.pool, get_conn(stream)->hq.qpack.dec, stream->quic->stream_id,
                                       &stream->req.input.method, &stream->req.input.scheme, &stream->req.input.authority,
                                       &stream->req.input.path, &stream->req.headers, &header_exists_map,
                                       &stream->req.content_length, NULL /* TODO cache-digests */, header_ack, &header_ack_len,
                                       frame.payload, frame.length, &err_desc)) != 0) {
        if (ret != H2O_HTTP2_ERROR_INVALID_HEADER_CHAR)
            return ret;
        h2o_send_error_400(&stream->req, "Invalid Request", err_desc, 0);
        return 0;
    }
    h2o_hq_shift_frame(&stream->quic->recvbuf, &frame);
    if (header_ack_len != 0 && get_conn(stream)->hq._control_streams.egress.qpack_decoder != NULL)
        h2o_hq_call_and_assert(quicly_sendbuf_write(&get_conn(stream)->hq._control_streams.egress.qpack_decoder->sendbuf,
                                                    header_ack, header_ack_len, NULL));

    if (quicly_recvbuf_get_error(&stream->quic->recvbuf) != QUICLY_STREAM_ERROR_FIN_CLOSED) {
        h2o_send_error_400(&stream->req, "FIXME", "handle request body", 0);
        return 0;
    }

    register_pending_req(stream);
    return 0;
}

static void proceed_response(h2o_timer_t *timer)
{
    struct st_h2o_hq_server_stream_t *stream = H2O_STRUCT_FROM_MEMBER(struct st_h2o_hq_server_stream_t, timer, timer);

    if (stream->send_state == H2O_SEND_STATE_IN_PROGRESS) {
        h2o_proceed_response(&stream->req);
    } else {
        destroy_stream(stream, stream->send_state == H2O_SEND_STATE_FINAL ? QUICLY_ERROR_FIN_CLOSED : H2O_HQ_ERROR_INTERNAL);
    }
}

static void on_write_complete(struct st_h2o_hq_server_stream_t *stream)
{
    if (stream->state == H2O_HQ_SERVER_STREAM_STATE_SEND_HEADERS)
        return;

    /* schedule next if no more data is in-flight (FIXME find a better way) */
    if (stream->quic->sendbuf.data.len != 0)
        return;

    assert(!h2o_timer_is_linked(&stream->timer));
    stream->timer.cb = proceed_response;
    h2o_timer_link(get_conn(stream)->super.ctx->loop, 0, &stream->timer);
}

static void write_stream_free_cb(quicly_buffer_t *_buf, quicly_buffer_vec_t *vec)
{
    quicly_stream_t *qs;

    free(vec);

    if ((qs = H2O_STRUCT_FROM_MEMBER(quicly_stream_t, sendbuf, _buf))->data != NULL)
        on_write_complete(qs->data);
}

#define write_stream(s, p, l) h2o_hq_call_and_assert(quicly_sendbuf_write(&(s)->quic->sendbuf, (p), (l), write_stream_free_cb))

static void write_response(struct st_h2o_hq_server_stream_t *stream)
{
    h2o_byte_vector_t buf = {NULL};
    h2o_hq_encode_frame(&stream->req.pool, &buf, H2O_HQ_FRAME_TYPE_HEADERS, {
        h2o_qpack_flatten_response(get_conn(stream)->hq.qpack.enc, &stream->req.pool, &buf, stream->req.res.status,
                                   stream->req.res.headers.entries, stream->req.res.headers.size,
                                   &get_conn(stream)->super.ctx->globalconf->server_name, stream->req.res.content_length);
    });
    write_stream(stream, buf.entries, buf.size);
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
        /* write DATA frame header */
        uint64_t size_total = 0;
        for (i = 0; i != bufcnt; ++i)
            size_total += bufs[i].len;
        uint8_t *end = quicly_encodev(stream->data_frame_header_buf, size_total);
        *end++ = H2O_HQ_FRAME_TYPE_DATA;
        write_stream(stream, stream->data_frame_header_buf, end - stream->data_frame_header_buf);
        /* write body */
        for (i = 0; i != bufcnt; ++i)
            write_stream(stream, bufs[i].base, bufs[i].len);
    }

    if (stream->send_state == H2O_SEND_STATE_FINAL)
        h2o_hq_call_and_assert(quicly_sendbuf_shutdown(&stream->quic->sendbuf));
}

static void do_send_informational(h2o_ostream_t *_ostr, h2o_req_t *_req)
{
    struct st_h2o_hq_server_stream_t *stream = H2O_STRUCT_FROM_MEMBER(struct st_h2o_hq_server_stream_t, ostr_final, _ostr);
    assert(&stream->req == _req);

    write_response(stream);
}

int h2o_hq_server_on_stream_open(quicly_stream_t *quic)
{
    /* handling of unidirectional streams is not server-specific */
    if (quicly_stream_is_unidirectional(quic->stream_id))
        return h2o_hq_on_stream_open(quic);

    /* create new stream and start handling the request */
    struct st_h2o_hq_server_stream_t *stream = h2o_mem_alloc(sizeof(*stream));
    h2o_init_request(&stream->req, &H2O_STRUCT_FROM_MEMBER(struct st_h2o_hq_server_conn_t, hq, *quicly_get_data(quic->conn))->super,
                     NULL);
    stream->req.version = 0x0300;
    stream->quic = quic;
    stream->link = (h2o_linklist_t){NULL};
    stream->state = H2O_HQ_SERVER_STREAM_STATE_RECV_HEADERS;
    ++*get_state_counter(get_conn(stream), stream->state);
    stream->ostr_final = (h2o_ostream_t){NULL, do_send, NULL, NULL, do_send_informational};
    stream->req._ostr_top = &stream->ostr_final;
    quic->data = stream;

    stream->quic->on_update = on_update_expect_headers;
    return stream->quic->on_update(stream->quic);
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
    h2o_hq_init_conn(&conn->hq, &ctx->super, h2o_hq_handle_control_stream_frame);
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
