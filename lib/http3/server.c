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
#include "h2o/http3_common.h"
#include "h2o/http3_server.h"

enum h2o_http3_server_stream_state {
    /**
     * receiving headers
     */
    H2O_HTTP3_SERVER_STREAM_STATE_RECV_HEADERS,
    /**
     * received request but haven't been assigned a handler
     */
    H2O_HTTP3_SERVER_STREAM_STATE_REQ_PENDING,
    /**
     * waiting for receiving response headers from the handler
     */
    H2O_HTTP3_SERVER_STREAM_STATE_SEND_HEADERS,
    /**
     * sending body
     */
    H2O_HTTP3_SERVER_STREAM_STATE_SEND_BODY,
    /**
     * sent fin, waiting for the transport stream to close (`req` is disposed when entering this state)
     */
    H2O_HTTP3_SERVER_STREAM_STATE_CLOSE_WAIT
};

struct st_h2o_http3_server_conn_t {
    h2o_conn_t super;
    h2o_http3_conn_t h3;
    ptls_handshake_properties_t handshake_properties;
    /**
     * link-list of pending requests using st_h2o_http3_server_stream_t::link
     */
    h2o_linklist_t pending_reqs;
    /**
     * next application-level timeout
     */
    h2o_timer_t timeout;
    /**
     * counter (the order MUST match that of h2o_http3_server_stream_state; it is accessed by index via the use of counters[])
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

struct st_h2o_http3_server_stream_t {
    quicly_stream_t *quic;
    struct {
        h2o_buffer_t *buf;
        int (*handle_input)(struct st_h2o_http3_server_stream_t *stream, const uint8_t **src, const uint8_t *src_end);
    } recvbuf;
    struct {
        H2O_VECTOR(h2o_sendvec_t) vecs;
        size_t off_within_first_vec;
        size_t min_index_to_addref;
        uint64_t final_size;
        uint8_t data_frame_header_buf[9];
        uint8_t proceed_called : 1;
    } sendbuf;
    enum h2o_http3_server_stream_state state;
    h2o_linklist_t link;
    h2o_ostream_t ostr_final;
    h2o_send_state_t send_state;
    h2o_req_t req;
};

static struct st_h2o_http3_server_conn_t *get_conn(struct st_h2o_http3_server_stream_t *stream)
{
    return (void *)stream->req.conn;
}

static uint32_t *get_state_counter(struct st_h2o_http3_server_conn_t *conn, enum h2o_http3_server_stream_state state)
{
    return conn->num_streams.counters + (size_t)state;
}

static void dispose_request(struct st_h2o_http3_server_stream_t *stream)
{
    size_t i;

    /* release vectors */
    for (i = 0; i != stream->sendbuf.vecs.size; ++i) {
        h2o_sendvec_t *vec = stream->sendbuf.vecs.entries + i;
        if (vec->callbacks->update_refcnt != NULL)
            vec->callbacks->update_refcnt(vec, &stream->req, 0);
    }

    /* dispose the request */
    h2o_dispose_request(&stream->req);
}

static void set_state(struct st_h2o_http3_server_stream_t *stream, enum h2o_http3_server_stream_state state)
{
    struct st_h2o_http3_server_conn_t *conn = get_conn(stream);

    --*get_state_counter(conn, stream->state);
    stream->state = state;
    ++*get_state_counter(conn, stream->state);

    if (state == H2O_HTTP3_SERVER_STREAM_STATE_CLOSE_WAIT)
        dispose_request(stream);
}

static socklen_t get_sockname(h2o_conn_t *_conn, struct sockaddr *sa)
{
    struct st_h2o_http3_server_conn_t *conn = (void *)_conn;
    return h2o_socket_getsockname(conn->h3.ctx->sock, sa);
}

static socklen_t get_peername(h2o_conn_t *_conn, struct sockaddr *_sa)
{
    struct st_h2o_http3_server_conn_t *conn = (void *)_conn;
    struct sockaddr *sa;
    socklen_t salen;
    quicly_get_peername(conn->h3.quic, &sa, &salen);
    memcpy(_sa, sa, salen);
    return salen;
}

static ptls_t *get_ptls(h2o_conn_t *_conn)
{
    struct st_h2o_http3_server_conn_t *conn = (void *)_conn;
    return quicly_get_tls(conn->h3.quic);
}

static h2o_iovec_t log_tls_protocol_version(h2o_req_t *_req)
{
    return h2o_iovec_init(H2O_STRLIT("TLSv1.3"));
}

static h2o_iovec_t log_session_reused(h2o_req_t *req)
{
    struct st_h2o_http3_server_conn_t *conn = (struct st_h2o_http3_server_conn_t *)req->conn;
    ptls_t *tls = quicly_get_tls(conn->h3.quic);
    return ptls_is_psk_handshake(tls) ? h2o_iovec_init(H2O_STRLIT("1")) : h2o_iovec_init(H2O_STRLIT("0"));
}

static h2o_iovec_t log_cipher(h2o_req_t *req)
{
    struct st_h2o_http3_server_conn_t *conn = (struct st_h2o_http3_server_conn_t *)req->conn;
    ptls_t *tls = quicly_get_tls(conn->h3.quic);
    ptls_cipher_suite_t *cipher = ptls_get_cipher(tls);
    return cipher != NULL ? h2o_iovec_init(cipher->aead->name, strlen(cipher->aead->name)) : h2o_iovec_init(NULL, 0);
}

static h2o_iovec_t log_cipher_bits(h2o_req_t *req)
{
    struct st_h2o_http3_server_conn_t *conn = (struct st_h2o_http3_server_conn_t *)req->conn;
    ptls_t *tls = quicly_get_tls(conn->h3.quic);
    ptls_cipher_suite_t *cipher = ptls_get_cipher(tls);
    if (cipher == NULL)
        return h2o_iovec_init(NULL, 0);

    char *buf = h2o_mem_alloc_pool(&req->pool, char, sizeof(H2O_UINT16_LONGEST_STR));
    return h2o_iovec_init(buf, sprintf(buf, "%" PRIu16, (uint16_t)(cipher->aead->key_size * 8)));
}

static h2o_iovec_t log_session_id(h2o_req_t *_req)
{
    /* FIXME */
    return h2o_iovec_init(NULL, 0);
}

static void on_stream_destroy(quicly_stream_t *qs, int err)
{
    struct st_h2o_http3_server_stream_t *stream = qs->data;

    --*get_state_counter(get_conn(stream), stream->state);
    if (h2o_linklist_is_linked(&stream->link))
        h2o_linklist_unlink(&stream->link);
    if (stream->state != H2O_HTTP3_SERVER_STREAM_STATE_CLOSE_WAIT)
        dispose_request(stream);
    free(stream);
}

static void allocated_vec_update_refcnt(h2o_sendvec_t *vec, h2o_req_t *req, int is_incr)
{
    assert(!is_incr);
    free(vec->raw);
}

static int retain_sendvecs(struct st_h2o_http3_server_stream_t *stream)
{
    for (; stream->sendbuf.min_index_to_addref != stream->sendbuf.vecs.size; ++stream->sendbuf.min_index_to_addref) {
        h2o_sendvec_t *vec = stream->sendbuf.vecs.entries + stream->sendbuf.min_index_to_addref;
        /* create a copy if it does not provide update_refcnt (update_refcnt is already called in do_send, if available) */
        if (vec->callbacks->update_refcnt == NULL) {
            static const h2o_sendvec_callbacks_t vec_callbacks = {h2o_sendvec_flatten_raw, allocated_vec_update_refcnt};
            size_t off_within_vec = stream->sendbuf.min_index_to_addref == 0 ? stream->sendbuf.off_within_first_vec : 0;
            h2o_iovec_t copy = h2o_iovec_init(h2o_mem_alloc(vec->len - off_within_vec), vec->len - off_within_vec);
            if (!(*vec->callbacks->flatten)(vec, &stream->req, copy, off_within_vec)) {
                free(copy.base);
                return 0;
            }
            *vec = (h2o_sendvec_t){&vec_callbacks, copy.len, {copy.base}};
            if (stream->sendbuf.min_index_to_addref == 0)
                stream->sendbuf.off_within_first_vec = 0;
        }
    }

    return 1;
}

static void on_send_shift(quicly_stream_t *qs, size_t delta)
{
    struct st_h2o_http3_server_stream_t *stream = qs->data;
    size_t i;

    assert(delta != 0);
    assert(stream->sendbuf.vecs.size != 0);

    size_t bytes_avail_in_first_vec = stream->sendbuf.vecs.entries[0].len - stream->sendbuf.off_within_first_vec;
    if (delta < bytes_avail_in_first_vec) {
        stream->sendbuf.off_within_first_vec += delta;
        return;
    }
    delta -= bytes_avail_in_first_vec;
    stream->sendbuf.off_within_first_vec = 0;
    if (stream->sendbuf.min_index_to_addref != 0)
        stream->sendbuf.vecs.entries[0].callbacks->update_refcnt(stream->sendbuf.vecs.entries, &stream->req, 0);

    for (i = 1; delta != 0; ++i) {
        assert(i < stream->sendbuf.vecs.size);
        if (delta < stream->sendbuf.vecs.entries[i].len) {
            stream->sendbuf.off_within_first_vec = delta;
            break;
        }
        delta -= stream->sendbuf.vecs.entries[i].len;
        if (i < stream->sendbuf.min_index_to_addref)
            stream->sendbuf.vecs.entries[i].callbacks->update_refcnt(stream->sendbuf.vecs.entries + i, &stream->req, 0);
    }
    memmove(stream->sendbuf.vecs.entries, stream->sendbuf.vecs.entries + i,
            (stream->sendbuf.vecs.size - i) * sizeof(stream->sendbuf.vecs.entries[0]));
    stream->sendbuf.vecs.size -= i;
    if (stream->sendbuf.min_index_to_addref <= i) {
        stream->sendbuf.min_index_to_addref = 0;
    } else {
        stream->sendbuf.min_index_to_addref -= i;
    }

    if (stream->sendbuf.vecs.size == 0) {
        switch (stream->send_state) {
        case H2O_SEND_STATE_IN_PROGRESS:
            assert(stream->sendbuf.proceed_called);
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
    struct st_h2o_http3_server_stream_t *stream = qs->data;
    uint8_t *dst = _dst, *dst_end = dst + *len;
    size_t vec_index = 0, off_within_vec = stream->sendbuf.off_within_first_vec;

    /* find the start position */
    while (off != 0) {
        assert(vec_index < stream->sendbuf.vecs.size);
        if (off < stream->sendbuf.vecs.entries[vec_index].len - off_within_vec)
            break;
        off -= stream->sendbuf.vecs.entries[vec_index].len - off_within_vec;
        off_within_vec = 0;
        ++vec_index;
    }

    /* write */
    *wrote_all = 0;
    while (dst != dst_end) {
        if (vec_index == stream->sendbuf.vecs.size) {
            *wrote_all = 1;
            break;
        }
        size_t sz = stream->sendbuf.vecs.entries[vec_index].len - (off + off_within_vec);
        if (dst_end - dst < sz)
            sz = dst_end - dst;
        if (!(stream->sendbuf.vecs.entries[vec_index].callbacks->flatten)(stream->sendbuf.vecs.entries + vec_index, &stream->req,
                                                                          h2o_iovec_init(dst, sz), off + off_within_vec))
            goto Error;
        dst += sz;
        /* prepare to write next */
        off = 0;
        off_within_vec = 0;
        ++vec_index;
    }

    *len = dst - (uint8_t *)_dst;

    if (*wrote_all && stream->send_state == H2O_SEND_STATE_IN_PROGRESS && !stream->sendbuf.proceed_called) {
        if (!retain_sendvecs(stream))
            goto Error;
        stream->sendbuf.proceed_called = 1;
        h2o_proceed_response_deferred(&stream->req);
    }

    return 0;

Error:
    *len = 0;
    *wrote_all = 1;
    quicly_reset_stream(stream->quic, H2O_HTTP3_ERROR_INTERNAL);
    set_state(stream, H2O_HTTP3_SERVER_STREAM_STATE_CLOSE_WAIT);
    return 0;
}

static int on_send_stop(quicly_stream_t *qs, int err)
{
    struct st_h2o_http3_server_stream_t *stream = qs->data;

    set_state(stream, H2O_HTTP3_SERVER_STREAM_STATE_CLOSE_WAIT);

    return 0;
}

static void handle_pending_reqs(h2o_timer_t *timer)
{
    struct st_h2o_http3_server_conn_t *conn = H2O_STRUCT_FROM_MEMBER(struct st_h2o_http3_server_conn_t, timeout, timer);

    /* TODO cap the maximum */
    while (!h2o_linklist_is_empty(&conn->pending_reqs)) {
        struct st_h2o_http3_server_stream_t *stream =
            H2O_STRUCT_FROM_MEMBER(struct st_h2o_http3_server_stream_t, link, conn->pending_reqs.next);
        h2o_linklist_unlink(&stream->link);
        set_state(stream, H2O_HTTP3_SERVER_STREAM_STATE_SEND_HEADERS);
        h2o_process_request(&stream->req);
    }
}

static void register_pending_req(struct st_h2o_http3_server_stream_t *stream)
{
    struct st_h2o_http3_server_conn_t *conn = get_conn(stream);

    h2o_linklist_insert(&conn->pending_reqs, &stream->link);
    set_state(stream, H2O_HTTP3_SERVER_STREAM_STATE_REQ_PENDING);
    if (!h2o_timer_is_linked(&conn->timeout))
        h2o_timer_link(conn->super.ctx->loop, 0, &conn->timeout);
}

static int on_receive(quicly_stream_t *qs, size_t off, const void *input, size_t len)
{
    struct st_h2o_http3_server_stream_t *stream = qs->data;
    const uint8_t *src, *src_end;
    int ret;

    /* save received data (FIXME avoid copying if possible; see hqclient.c) */
    if ((ret = h2o_http3_update_recvbuf(&stream->recvbuf.buf, off, input, len)) != 0)
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
            /* fixme send MALFORMED_FRAME(last_frame); we might need to observe the value of handle_input */
            quicly_reset_stream(stream->quic, ret == H2O_HTTP3_ERROR_INCOMPLETE ? H2O_HTTP3_ERROR_GENERAL : ret);
            set_state(stream, H2O_HTTP3_SERVER_STREAM_STATE_CLOSE_WAIT);
        } else if (stream->state == H2O_HTTP3_SERVER_STREAM_STATE_RECV_HEADERS) {
            quicly_reset_stream(stream->quic, H2O_HTTP3_ERROR_INCOMPLETE_REQUEST);
            set_state(stream, H2O_HTTP3_SERVER_STREAM_STATE_CLOSE_WAIT);
        } else {
            /* we are processing the request */
        }
    } else {
        switch (ret) {
        case 0:
        case H2O_HTTP3_ERROR_INCOMPLETE:
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

static int on_receive_reset(quicly_stream_t *qs, int err)
{
    struct st_h2o_http3_server_stream_t *stream = qs->data;

    /* if we were still receiving the request, discard! */
    if (stream->state == H2O_HTTP3_SERVER_STREAM_STATE_RECV_HEADERS) {
        assert(!quicly_sendstate_transfer_complete(&stream->quic->sendstate));
        quicly_reset_stream(stream->quic, H2O_HTTP3_ERROR_REQUEST_REJECTED);
        if (h2o_linklist_is_linked(&stream->link))
            h2o_linklist_unlink(&stream->link);
        set_state(stream, H2O_HTTP3_SERVER_STREAM_STATE_CLOSE_WAIT);
    }

    return 0;
}

static int handle_input_expect_headers(struct st_h2o_http3_server_stream_t *stream, const uint8_t **src, const uint8_t *src_end)
{
    struct st_h2o_http3_server_conn_t *conn = get_conn(stream);
    h2o_http3_read_frame_t frame;
    int header_exists_map, ret;
    const char *err_desc = NULL;
    uint8_t header_ack[H2O_HPACK_ENCODE_INT_MAX_LENGTH];
    size_t header_ack_len;

    /* read haeders frame */
    if ((ret = h2o_http3_read_frame(&frame, src, src_end, &err_desc)) != 0)
        return ret;
    if (frame.type != H2O_HTTP3_FRAME_TYPE_HEADERS)
        return H2O_HTTP3_ERROR_UNEXPECTED_FRAME;

    if ((ret = h2o_qpack_parse_request(&stream->req.pool, get_conn(stream)->h3.qpack.dec, stream->quic->stream_id,
                                       &stream->req.input.method, &stream->req.input.scheme, &stream->req.input.authority,
                                       &stream->req.input.path, &stream->req.headers, &header_exists_map,
                                       &stream->req.content_length, NULL /* TODO cache-digests */, header_ack, &header_ack_len,
                                       frame.payload, frame.length, &err_desc)) != 0) {
        if (ret != H2O_HTTP2_ERROR_INVALID_HEADER_CHAR)
            return ret;
        if (!quicly_recvstate_transfer_complete(&stream->quic->recvstate))
            quicly_request_stop(stream->quic, H2O_HTTP3_ERROR_EARLY_RESPONSE);
        h2o_send_error_400(&stream->req, "Invalid Request", err_desc, 0);
        return 0;
    }
    if (header_ack_len != 0)
        h2o_http3_send_qpack_header_ack(&conn->h3, header_ack, header_ack_len);

    register_pending_req(stream);
    return 0;
}

static void write_response(struct st_h2o_http3_server_stream_t *stream)
{
    h2o_byte_vector_t buf = {NULL};

    h2o_http3_encode_frame(&stream->req.pool, &buf, H2O_HTTP3_FRAME_TYPE_HEADERS, {
        h2o_qpack_flatten_response(get_conn(stream)->h3.qpack.enc, &stream->req.pool, stream->quic->stream_id, NULL, &buf,
                                   stream->req.res.status, stream->req.res.headers.entries, stream->req.res.headers.size,
                                   &get_conn(stream)->super.ctx->globalconf->server_name, stream->req.res.content_length);
    });

    h2o_vector_reserve(&stream->req.pool, &stream->sendbuf.vecs, stream->sendbuf.vecs.size + 1);
    h2o_sendvec_init_raw(stream->sendbuf.vecs.entries + stream->sendbuf.vecs.size++, buf.entries, buf.size);
    stream->sendbuf.final_size += buf.size;
}

static void do_send(h2o_ostream_t *_ostr, h2o_req_t *_req, h2o_sendvec_t *bufs, size_t bufcnt, h2o_send_state_t _state)
{
    struct st_h2o_http3_server_stream_t *stream = H2O_STRUCT_FROM_MEMBER(struct st_h2o_http3_server_stream_t, ostr_final, _ostr);
    uint64_t size_total = 0;

    assert(&stream->req == _req);

    stream->send_state = _state;
    stream->sendbuf.proceed_called = 0;

    if (stream->state == H2O_HTTP3_SERVER_STREAM_STATE_SEND_HEADERS) {
        write_response(stream);
        set_state(stream, H2O_HTTP3_SERVER_STREAM_STATE_SEND_BODY);
    } else {
        assert(stream->state == H2O_HTTP3_SERVER_STREAM_STATE_SEND_BODY);
    }

    { /* calculate number of bytes received, as well as retaining reference to the vectors (for future retransmission) */
        size_t i;
        for (i = 0; i != bufcnt; ++i) {
            size_total += bufs[i].len;
            if (bufs[i].callbacks->update_refcnt != NULL)
                bufs[i].callbacks->update_refcnt(bufs + i, &stream->req, 1);
        }
    }

    if (bufcnt != 0) {
        /* build DATA frame header */
        size_t header_size =
            quicly_encodev(stream->sendbuf.data_frame_header_buf, size_total) - stream->sendbuf.data_frame_header_buf;
        stream->sendbuf.data_frame_header_buf[header_size++] = H2O_HTTP3_FRAME_TYPE_DATA;
        /* write */
        h2o_vector_reserve(&stream->req.pool, &stream->sendbuf.vecs, stream->sendbuf.vecs.size + 1 + bufcnt);
        h2o_sendvec_init_raw(stream->sendbuf.vecs.entries + stream->sendbuf.vecs.size++, stream->sendbuf.data_frame_header_buf,
                             header_size);
        stream->sendbuf.final_size += header_size;
        memcpy(stream->sendbuf.vecs.entries + stream->sendbuf.vecs.size, bufs, sizeof(*bufs) * bufcnt);
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
        quicly_reset_stream(stream->quic, H2O_HTTP3_ERROR_INTERNAL);
        break;
    }

    quicly_stream_sync_sendbuf(stream->quic, 1);
    h2o_http3_schedule_timer(&get_conn(stream)->h3);
}

static void do_send_informational(h2o_ostream_t *_ostr, h2o_req_t *_req)
{
    struct st_h2o_http3_server_stream_t *stream = H2O_STRUCT_FROM_MEMBER(struct st_h2o_http3_server_stream_t, ostr_final, _ostr);
    assert(&stream->req == _req);

    write_response(stream);
}

static int handle_control_stream_frame(h2o_http3_conn_t *_conn, uint8_t type, const uint8_t *payload, size_t len,
                                       const char **err_desc)
{
    struct st_h2o_http3_server_conn_t *conn = H2O_STRUCT_FROM_MEMBER(struct st_h2o_http3_server_conn_t, h3, _conn);
    int ret;

    switch (type) {
    case H2O_HTTP3_FRAME_TYPE_SETTINGS:
        if ((ret = h2o_http3_handle_settings_frame(&conn->h3, payload, len, err_desc)) != 0)
            return ret;
        break;
    default:
        break;
    }

    return 0;
}

static int stream_open_cb(quicly_stream_open_t *self, quicly_stream_t *qs)
{
    static const quicly_stream_callbacks_t callbacks = {on_stream_destroy, on_send_shift, on_send_emit,
                                                        on_send_stop,      on_receive,    on_receive_reset};

    /* handling of unidirectional streams is not server-specific */
    if (quicly_stream_is_unidirectional(qs->stream_id)) {
        h2o_http3_on_create_unidirectional_stream(qs);
        return 0;
    }

    assert(quicly_stream_is_client_initiated(qs->stream_id));

    /* create new stream and start handling the request */
    struct st_h2o_http3_server_stream_t *stream = h2o_mem_alloc(sizeof(*stream));
    stream->quic = qs;
    h2o_buffer_init(&stream->recvbuf.buf, &h2o_socket_buffer_prototype);
    stream->recvbuf.handle_input = handle_input_expect_headers;
    memset(&stream->sendbuf, 0, sizeof(stream->sendbuf));
    stream->state = H2O_HTTP3_SERVER_STREAM_STATE_RECV_HEADERS;
    stream->link = (h2o_linklist_t){NULL};
    stream->ostr_final = (h2o_ostream_t){NULL, do_send, NULL, do_send_informational};
    stream->send_state = H2O_SEND_STATE_IN_PROGRESS;
    h2o_init_request(&stream->req,
                     &H2O_STRUCT_FROM_MEMBER(struct st_h2o_http3_server_conn_t, h3, *quicly_get_data(stream->quic->conn))->super,
                     NULL);
    stream->req.version = 0x0300;
    stream->req._ostr_top = &stream->ostr_final;

    stream->quic->data = stream;
    stream->quic->callbacks = &callbacks;

    ++*get_state_counter(get_conn(stream), stream->state);
    return 0;
}

quicly_stream_open_t h2o_http3_server_on_stream_open = {stream_open_cb};

static void on_h3_destroy(h2o_http3_conn_t *h3)
{
    struct st_h2o_http3_server_conn_t *conn = H2O_STRUCT_FROM_MEMBER(struct st_h2o_http3_server_conn_t, h3, h3);

    assert(quicly_num_streams(conn->h3.quic) == 0);
    assert(conn->num_streams.recv_headers == 0);
    assert(conn->num_streams.req_pending == 0);
    assert(conn->num_streams.send_headers == 0);
    assert(conn->num_streams.send_body == 0);
    assert(conn->num_streams.close_wait == 0);
    assert(h2o_linklist_is_empty(&conn->pending_reqs));

    if (h2o_timer_is_linked(&conn->timeout))
        h2o_timer_unlink(&conn->timeout);
    h2o_http3_dispose_conn(&conn->h3);
    free(conn);
}

h2o_http3_conn_t *h2o_http3_server_accept(h2o_http3_ctx_t *_ctx, struct sockaddr *sa, socklen_t salen,
                                          quicly_decoded_packet_t *packets, size_t num_packets,
                                          const h2o_http3_conn_callbacks_t *h3_callbacks)
{
    h2o_http3_server_ctx_t *ctx = (void *)_ctx;
    size_t i, syn_index = SIZE_MAX;

    /* find the Initial packet */
    for (i = 0; i != num_packets; ++i) {
        if ((packets[i].octets.base[0] & 0xf0) == 0xc0) {
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
        get_ptls,
        NULL, /* get debug state */
        {{
            {log_tls_protocol_version, log_session_reused, log_cipher, log_cipher_bits, log_session_id}, /* ssl */
            {NULL},                                                                                      /* http1 */
            {NULL}                                                                                       /* http2 */
        }}                                                                                               /* loggers */
    };
    struct st_h2o_http3_server_conn_t *conn = (void *)h2o_create_connection(
        sizeof(*conn), ctx->accept_ctx->ctx, ctx->accept_ctx->hosts, h2o_gettimeofday(ctx->accept_ctx->ctx->loop), &conn_callbacks);
    h2o_http3_init_conn(&conn->h3, &ctx->super, h3_callbacks);
    conn->handshake_properties = (ptls_handshake_properties_t){{{{NULL}}}};
    h2o_linklist_init_anchor(&conn->pending_reqs);
    h2o_timer_init(&conn->timeout, handle_pending_reqs);
    memset(&conn->num_streams, 0, sizeof(conn->num_streams));
    quicly_conn_t *qconn;

    /* accept connection */
    if (quicly_accept(&qconn, ctx->super.quic, sa, salen, packets + syn_index, ptls_iovec_init(NULL, 0), &ctx->super.next_cid,
                      &conn->handshake_properties) != 0) {
        h2o_http3_dispose_conn(&conn->h3);
        free(conn);
        return NULL;
    }
    ++ctx->super.next_cid.master_id; /* FIXME check overlap */
    h2o_http3_setup(&conn->h3, qconn);
    /* handle the other packet */
    for (i = 0; i != num_packets; ++i) {
        if (i == syn_index)
            continue;
        quicly_receive(conn->h3.quic, packets + i);
    }
    h2o_http3_send(&conn->h3);
    return &conn->h3;
}
}

static void initiate_graceful_shutdown(h2o_context_t *ctx)
{
}

static int foreach_request(h2o_context_t *ctx, int (*cb)(h2o_req_t *req, void *cbdata), void *cbdata)
{
    return 0;
}

const h2o_protocol_callbacks_t H2O_HTTP3_SERVER_CALLBACKS = {initiate_graceful_shutdown, foreach_request};
const h2o_http3_conn_callbacks_t H2O_HTTP3_CONN_CALLBACKS = {on_h3_destroy, handle_control_stream_frame};
