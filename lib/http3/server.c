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
#include "khash.h"
#include "h2o/http2_scheduler.h"
#include "h2o/http3_common.h"
#include "h2o/http3_server.h"
#include "h2o/http3_internal.h"

#define H2O_HTTP3_MAX_PLACEHOLDERS 10
#define H2O_HTTP3_NUM_RETAINED_PRIORITIES 10

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

KHASH_MAP_INIT_INT64(h2o_http3_freestanding_priority, h2o_http2_scheduler_openref_t *);

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
    /**
     * scheduler
     */
    struct {
        struct {
            /**
             * the root node
             */
            h2o_http2_scheduler_node_t root;
            /**
             * list of openrefs for placeholders
             */
            h2o_http2_scheduler_openref_t placeholders[H2O_HTTP3_MAX_PLACEHOLDERS];
            /**
             *
             */
            kh_h2o_http3_freestanding_priority_t *freestanding;
            /**
             * list of streams that have gone into freestanding after being closed.
             */
            struct st_h2o_http3_closed_priorities_t {
                struct {
                    quicly_stream_id_t id;
                    h2o_http2_scheduler_openref_t ref;
                } entries[H2O_HTTP3_NUM_RETAINED_PRIORITIES];
                size_t oldest_index;
            } closed_streams;
        } reqs;
        /**
         * States for unidirectional streams. Each element is a bit vector where slot for each stream is defined as: 1 << stream_id.
         */
        uint16_t uni;
        struct {
            h2o_linklist_t reqs;
            uint16_t uni;
        } conn_blocked;
    } scheduler;
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
    struct {
        h2o_http2_scheduler_openref_t ref;
        h2o_linklist_t conn_blocked;
    } scheduler;
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
    struct st_h2o_http3_server_conn_t *conn = get_conn(stream);

    --*get_state_counter(conn, stream->state);
    if (h2o_http2_scheduler_is_open(&stream->scheduler.ref)) {
        if (h2o_linklist_is_linked(&stream->scheduler.conn_blocked))
            h2o_linklist_unlink(&stream->scheduler.conn_blocked);
        /* transplant the scheduler node to the freestanding list */
        struct st_h2o_http3_closed_priorities_t *closed = &conn->scheduler.reqs.closed_streams;
        khiter_t iter;
        int r;
        /* ... by destructing the entry at oldest_index */
        if (closed->entries[closed->oldest_index].id != -1) {
            iter = kh_get(h2o_http3_freestanding_priority, conn->scheduler.reqs.freestanding, stream->quic->stream_id);
            assert(iter != kh_end(conn->scheduler.reqs.freestanding));
            kh_del(h2o_http3_freestanding_priority, conn->scheduler.reqs.freestanding, iter);
            h2o_http2_scheduler_close(&closed->entries[closed->oldest_index].ref);
        }
        /* ... then instantiate the new entry at the same location */
        closed->entries[closed->oldest_index].id = stream->quic->stream_id;
        h2o_http2_scheduler_relocate(&closed->entries[closed->oldest_index].ref, &stream->scheduler.ref);
        iter = kh_put(h2o_http3_freestanding_priority, conn->scheduler.reqs.freestanding, stream->quic->stream_id, &r);
        assert(r != 0 && "new entry");
        kh_val(conn->scheduler.reqs.freestanding, iter) = &closed->entries[closed->oldest_index].ref;
        /* ... then increment oldest_index */
        closed->oldest_index = (closed->oldest_index + 1) % (sizeof(closed->entries) / sizeof(closed->entries[0]));
    }
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

static int get_scheduler_node(struct st_h2o_http3_server_conn_t *conn, h2o_http2_scheduler_node_t **node,
                              h2o_http3_priority_element_type_t type, int64_t id, h2o_http2_scheduler_node_t *self,
                              const char **err_desc)
{
    switch (type) {
    case H2O_HTTP3_PRIORITY_ELEMENT_TYPE_REQUEST_STREAM: {

        /* Return the scheduler node of an existing request stream, or create a queued entry and returns that */
        quicly_stream_t *qs;
        if (!(quicly_stream_is_client_initiated(id) && !quicly_stream_is_unidirectional(id) &&
              id / 4 < quicly_get_ingress_max_streams(conn->h3.quic, 0))) {
            *err_desc = "invalid request stream id in PRIORITY frame";
            return H2O_HTTP3_ERROR_MALFORMED_FRAME(H2O_HTTP3_FRAME_TYPE_PRIORITY);
        }
        if ((qs = quicly_get_stream(conn->h3.quic, id)) != NULL) {
            struct st_h2o_http3_server_stream_t *stream = qs->data;
            assert(stream != NULL);
            if (!h2o_http2_scheduler_is_open(&stream->scheduler.ref))
                h2o_http2_scheduler_open(&stream->scheduler.ref, &conn->scheduler.reqs.root, H2O_HTTP3_IMPLICIT_WEIGHT, 0, 1);
            *node = &stream->scheduler.ref.node;
        } else {
            int r;
            khiter_t iter = kh_put(h2o_http3_freestanding_priority, conn->scheduler.reqs.freestanding, id, &r);
            assert(iter != kh_end(conn->scheduler.reqs.freestanding));
            if (r == 0) {
                /* the entry exists */
                *node = &kh_val(conn->scheduler.reqs.freestanding, iter)->node;
            } else if (id >= quicly_get_peer_next_stream_id(conn->h3.quic, 0)) {
                /* create new entry */
                h2o_http2_scheduler_openref_t *queued_ref = h2o_mem_alloc(sizeof(*queued_ref));
                h2o_http2_scheduler_open(queued_ref, &conn->scheduler.reqs.root, H2O_HTTP3_IMPLICIT_WEIGHT, 0, 1);
                kh_val(conn->scheduler.reqs.freestanding, iter) = queued_ref;
                *node = &queued_ref->node;
            } else {
                /* the stream has been closed and the PRIORITY information is no longer available (TODO consider returning orphan
                 * placeholder) */
                *node = self;
            }
        }

    } break;

    case H2O_HTTP3_PRIORITY_ELEMENT_TYPE_PUSH_STREAM:
        *err_desc = "unexpectedly found a push stream id in PRIORITY frame";
        return H2O_HTTP3_ERROR_GENERAL;

    case H2O_HTTP3_PRIORITY_ELEMENT_TYPE_PLACEHOLDER: {

        /* return a placeholder, initializing it to the default values if it is not open yet */
        h2o_http2_scheduler_openref_t *ref;
        if (id >= H2O_HTTP3_SETTINGS_NUM_PLACEHOLDERS) {
            *err_desc = "invalid placeholder id found in PRIORITY frame";
            return H2O_HTTP3_ERROR_MALFORMED_FRAME(H2O_HTTP3_FRAME_TYPE_PRIORITY);
        }
        ref = conn->scheduler.reqs.placeholders + id;
        if (!h2o_http2_scheduler_is_open(ref))
            h2o_http2_scheduler_open(ref, &conn->scheduler.reqs.root, H2O_HTTP3_IMPLICIT_WEIGHT, 0, 1);
        *node = &ref->node;

    } break;

    case H2O_HTTP3_PRIORITY_ELEMENT_TYPE_ABSENT:
        if (self == NULL) {
            *err_desc = "invalid depedency type in PRIORITY frame";
            return H2O_HTTP3_ERROR_MALFORMED_FRAME(H2O_HTTP3_FRAME_TYPE_PRIORITY);
        }
        *node = self;
        break;
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

    /* read the HEADERS frame (or a frame that precedes that) */
    if ((ret = h2o_http3_read_frame(&frame, 0, H2O_HTTP3_STREAM_TYPE_REQUEST, src, src_end, &err_desc)) != 0)
        return ret;
    if (frame.type != H2O_HTTP3_FRAME_TYPE_HEADERS) {
        switch (frame.type) {
        case H2O_HTTP3_FRAME_TYPE_PRIORITY: {
            h2o_http3_priority_frame_t priority_frame;
            h2o_http2_scheduler_node_t *parent;
            if ((ret = h2o_http3_decode_priority_frame(&priority_frame, frame.payload, frame.length, &err_desc)) != 0)
                return ret;
            if ((ret = get_scheduler_node(conn, &parent, priority_frame.dependency.type, priority_frame.dependency.id_,
                                          &conn->scheduler.reqs.root, &err_desc)) != 0)
                return ret;
            if (!h2o_http2_scheduler_is_open(&stream->scheduler.ref)) {
                h2o_http2_scheduler_open(&stream->scheduler.ref, parent, priority_frame.weight_m1 + 1, 0, 0);
            } else if (stream->scheduler.ref.initialized_implicitly) {
                h2o_http2_scheduler_rebind(&stream->scheduler.ref, parent, priority_frame.weight_m1 + 1, 0);
            }
        } break;
        case H2O_HTTP3_FRAME_TYPE_DATA:
            return H2O_HTTP3_ERROR_UNEXPECTED_FRAME;
        default:
            break;
        }
        return 0;
    }

    if (!h2o_http2_scheduler_is_open(&stream->scheduler.ref)) {
        h2o_http2_scheduler_open(&stream->scheduler.ref, &conn->scheduler.reqs.root, H2O_HTTP3_DEFAULT_WEIGHT, 0, 0);
    } else if (stream->scheduler.ref.initialized_implicitly) {
        assert(h2o_http2_scheduler_get_parent(&stream->scheduler.ref) == &conn->scheduler.reqs.root);
        assert(h2o_http2_scheduler_get_weight(&stream->scheduler.ref) == H2O_HTTP3_DEFAULT_WEIGHT);
        stream->scheduler.ref.initialized_implicitly = 0;
    }
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
        size_t header_size = 0;
        stream->sendbuf.data_frame_header_buf[header_size++] = H2O_HTTP3_FRAME_TYPE_DATA;
        header_size =
            quicly_encodev(stream->sendbuf.data_frame_header_buf + header_size, size_total) - stream->sendbuf.data_frame_header_buf;
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
    case H2O_HTTP3_FRAME_TYPE_PRIORITY: {
        h2o_http3_priority_frame_t frame;
        h2o_http2_scheduler_node_t *dependency, *prioritized;
        if ((ret = h2o_http3_decode_priority_frame(&frame, payload, len, err_desc)) != 0)
            return ret;
        if ((ret = get_scheduler_node(conn, &dependency, frame.dependency.type, frame.dependency.id_, &conn->scheduler.reqs.root,
                                      err_desc)) != 0)
            return ret;
        if ((ret = get_scheduler_node(conn, &prioritized, frame.prioritized.type, frame.prioritized.id_, NULL, err_desc)) != 0)
            return ret;
        if (prioritized != NULL)
            h2o_http2_scheduler_rebind(H2O_STRUCT_FROM_MEMBER(h2o_http2_scheduler_openref_t, node, prioritized), dependency,
                                       frame.weight_m1 + 1, 0);
    } break;
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

    struct st_h2o_http3_server_conn_t *conn =
        H2O_STRUCT_FROM_MEMBER(struct st_h2o_http3_server_conn_t, h3, *quicly_get_data(qs->conn));

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

    /* transplant the priority in the queue, or lazy-initialize the scheduler until the receipt of HEADERS frame (at the maximum) */
    khiter_t iter = kh_get(h2o_http3_freestanding_priority, conn->scheduler.reqs.freestanding, stream->quic->stream_id);
    if (iter != kh_end(conn->scheduler.reqs.freestanding)) {
        h2o_http2_scheduler_openref_t *v = kh_val(conn->scheduler.reqs.freestanding, iter);
        h2o_http2_scheduler_relocate(&stream->scheduler.ref, v);
        kh_del(h2o_http3_freestanding_priority, conn->scheduler.reqs.freestanding, iter);
        free(v);
    } else {
        memset(&stream->scheduler, 0, sizeof(stream->scheduler));
    }

    h2o_init_request(&stream->req, &conn->super, NULL);
    stream->req.version = 0x0300;
    stream->req._ostr_top = &stream->ostr_final;

    stream->quic->data = stream;
    stream->quic->callbacks = &callbacks;

    ++*get_state_counter(get_conn(stream), stream->state);
    return 0;
}

quicly_stream_open_t h2o_http3_server_on_stream_open = {stream_open_cb};

static int scheduler_can_send(quicly_stream_scheduler_t *sched, quicly_conn_t *qc, int conn_is_saturated)
{
    struct st_h2o_http3_server_conn_t *conn = H2O_STRUCT_FROM_MEMBER(struct st_h2o_http3_server_conn_t, h3, *quicly_get_data(qc));

    if (!conn_is_saturated) {
        /* not saturated, activate streams marked as being conn-blocked */
        if (conn->scheduler.conn_blocked.uni != 0) {
            conn->scheduler.uni |= conn->scheduler.conn_blocked.uni;
            conn->scheduler.conn_blocked.uni = 0;
        }
        while (!h2o_linklist_is_empty(&conn->scheduler.conn_blocked.reqs)) {
            struct st_h2o_http3_server_stream_t *stream = H2O_STRUCT_FROM_MEMBER(
                struct st_h2o_http3_server_stream_t, scheduler.conn_blocked, conn->scheduler.conn_blocked.reqs.next);
            h2o_linklist_unlink(&stream->scheduler.conn_blocked);
            h2o_http2_scheduler_activate(&stream->scheduler.ref);
        }
    } else {
        /* TODO lazily move the active request and unidirectional streams to conn_blocked.  Not doing so results in at most one
         * spurious call to quicly_send. */
    }

    return conn->scheduler.uni != 0 || h2o_http2_scheduler_is_active(&conn->scheduler.reqs.root);
}

static int scheduler_do_send_stream(h2o_http2_scheduler_openref_t *ref, int *still_is_active, void *cb_arg)
{
    struct st_h2o_http3_server_stream_t *stream = H2O_STRUCT_FROM_MEMBER(struct st_h2o_http3_server_stream_t, scheduler, ref);
    quicly_send_context_t *s = cb_arg;
    int ret = 0;

    /* 2. link to the conn_blocked list if necessary */
    if (quicly_is_flow_capped(stream->quic->conn) && !quicly_sendstate_can_send(&stream->quic->sendstate, NULL))
        goto ActiveBlocked;
    /* 3. send */
    if ((ret = quicly_send_stream(stream->quic, s)) != 0 && ret != QUICLY_ERROR_SENDBUF_FULL)
        goto Exit;
    /* 4. enqueue to conn_blocked list, or set *still_is_active */
    if (quicly_sendstate_can_send(&stream->quic->sendstate, &stream->quic->_send_aux.max_stream_data)) {
        if (quicly_is_flow_capped(stream->quic->conn) && !quicly_sendstate_can_send(&stream->quic->sendstate, NULL))
            goto ActiveBlocked;
        *still_is_active = 1;
    } else {
        *still_is_active = 0;
    }

Exit:
    return ret;
ActiveBlocked : {
    struct st_h2o_http3_server_conn_t *conn = (struct st_h2o_http3_server_conn_t *)(stream->req.conn);
    h2o_linklist_insert(&conn->scheduler.conn_blocked.reqs, &stream->scheduler.conn_blocked);
    *still_is_active = 0;
    goto Exit;
}
}

static int scheduler_do_send(quicly_stream_scheduler_t *sched, quicly_conn_t *qc, quicly_send_context_t *s)
{
    struct st_h2o_http3_server_conn_t *conn = H2O_STRUCT_FROM_MEMBER(struct st_h2o_http3_server_conn_t, h3, *quicly_get_data(qc));
    int ret = 0;

    while (quicly_can_send_stream_data(conn->h3.quic, s)) {
        /* The strategy is:
         *
         * 1. dequeue the first active stream
         * 2. link the stream to the conn_blocked list, if nothing can be sent for the stream due to the connection being capped
         * 3. otherwise, send
         * 4. enqueue to the appropriate place
         */
        if (conn->scheduler.uni != 0) {
            static const ptrdiff_t stream_offsets[] = {
                offsetof(struct st_h2o_http3_server_conn_t, h3._control_streams.egress.control),
                offsetof(struct st_h2o_http3_server_conn_t, h3._control_streams.egress.qpack_encoder),
                offsetof(struct st_h2o_http3_server_conn_t, h3._control_streams.egress.qpack_decoder)};
            struct st_h2o_http3_egress_unistream_t *stream = NULL;
            size_t i;
            for (i = 0; i != sizeof(stream_offsets) / sizeof(stream_offsets[0]); ++i) {
                stream = *(void **)((char *)conn + stream_offsets[i]);
                if ((conn->scheduler.uni & (1 << stream->quic->stream_id)) != 0)
                    break;
            }
            assert(i != sizeof(stream_offsets) / sizeof(stream_offsets[0]) && "we should have found one stream");
            /* 1. dequeue */
            conn->scheduler.uni &= ~(1 << stream->quic->stream_id);
            /* 2. link to the conn_blocked list if necessary */
            if (quicly_is_flow_capped(conn->h3.quic) && !quicly_sendstate_can_send(&stream->quic->sendstate, NULL)) {
                conn->scheduler.conn_blocked.uni += 1 << stream->quic->stream_id;
                continue;
            }
            /* 3. send */
            if ((ret = quicly_send_stream(stream->quic, s)) != 0 && ret != QUICLY_ERROR_SENDBUF_FULL)
                goto Exit;
            /* 4. enqueue */
            if (quicly_sendstate_can_send(&stream->quic->sendstate, &stream->quic->_send_aux.max_stream_data)) {
                uint16_t *slot = &conn->scheduler.uni;
                if (quicly_is_flow_capped(conn->h3.quic) && !quicly_sendstate_can_send(&stream->quic->sendstate, NULL))
                    slot = &conn->scheduler.conn_blocked.uni;
                *slot |= 1 << stream->quic->stream_id;
            }
        } else if (h2o_http2_scheduler_is_active(&conn->scheduler.reqs.root)) {
            /* 1 and part of 4 is done by h2o_http2_scheduler_run, the rest is done by shceduler_do_send_stream */
            if ((ret = h2o_http2_scheduler_run(&conn->scheduler.reqs.root, scheduler_do_send_stream, s)) != 0 &&
                ret != QUICLY_ERROR_SENDBUF_FULL)
                goto Exit;
        } else {
            break;
        }
        /* TODO Remove below (and the code above that deals with SENDBUF_FULL) once quicly_send_stream stops returning that */
        if (ret == QUICLY_ERROR_SENDBUF_FULL) {
            ret = 0;
            goto Exit;
        }
    }

Exit:
    return ret;
}

static int scheduler_update_state(struct st_quicly_stream_scheduler_t *sched, quicly_stream_t *qs)
{
    enum { DEACTIVATE, ACTIVATE, CONN_BLOCKED } new_state;

    if (quicly_sendstate_can_send(&qs->sendstate, &qs->_send_aux.max_stream_data)) {
        if (quicly_is_flow_capped(qs->conn) && !quicly_sendstate_can_send(&qs->sendstate, NULL)) {
            new_state = CONN_BLOCKED;
        } else {
            new_state = ACTIVATE;
        }
    } else {
        new_state = DEACTIVATE;
    }

    if (quicly_stream_is_unidirectional(qs->stream_id)) {
        struct st_h2o_http3_server_conn_t *conn =
            H2O_STRUCT_FROM_MEMBER(struct st_h2o_http3_server_conn_t, h3, *quicly_get_data(qs->conn));
        assert(qs->stream_id < sizeof(uint16_t) * 8);
        uint16_t mask = (uint16_t)1 << qs->stream_id;
        switch (new_state) {
        case DEACTIVATE:
            conn->scheduler.uni &= ~mask;
            conn->scheduler.conn_blocked.uni &= ~mask;
            break;
        case ACTIVATE:
            conn->scheduler.uni |= mask;
            conn->scheduler.conn_blocked.uni &= ~mask;
            break;
        case CONN_BLOCKED:
            conn->scheduler.uni &= ~mask;
            conn->scheduler.conn_blocked.uni |= mask;
            break;
        }
    } else {
        struct st_h2o_http3_server_stream_t *stream = qs->data;
        switch (new_state) {
        case DEACTIVATE:
            h2o_http2_scheduler_deactivate(&stream->scheduler.ref);
            if (h2o_linklist_is_linked(&stream->scheduler.conn_blocked))
                h2o_linklist_unlink(&stream->scheduler.conn_blocked);
            break;
        case ACTIVATE:
            h2o_http2_scheduler_activate(&stream->scheduler.ref);
            if (h2o_linklist_is_linked(&stream->scheduler.conn_blocked))
                h2o_linklist_unlink(&stream->scheduler.conn_blocked);
            break;
        case CONN_BLOCKED:
            if (!h2o_linklist_is_linked(&stream->scheduler.conn_blocked)) {
                struct st_h2o_http3_server_conn_t *conn = (void *)stream->req.conn;
                h2o_http2_scheduler_deactivate(&stream->scheduler.ref);
                h2o_linklist_insert(&conn->scheduler.conn_blocked.reqs, &stream->scheduler.conn_blocked);
            }
            break;
        }
    }

    return 0;
}

quicly_stream_scheduler_t h2o_http3_server_stream_scheduler = {scheduler_can_send, scheduler_do_send, scheduler_update_state};

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

    /* destroy the scheduler */

    { /* ... by first releasing entries in closed_streams */
        struct st_h2o_http3_closed_priorities_t *closed = &conn->scheduler.reqs.closed_streams;
        while (1) {
            if (closed->oldest_index == 0)
                closed->oldest_index = sizeof(closed->entries) / sizeof(closed->entries[0]);
            closed->oldest_index -= 1;
            if (closed->entries[closed->oldest_index].id == -1)
                break;
            khiter_t iter = kh_get(h2o_http3_freestanding_priority, conn->scheduler.reqs.freestanding,
                                   closed->entries[closed->oldest_index].id);
            assert(iter != kh_end(conn->scheduler.reqs.freestanding));
            kh_del(h2o_http3_freestanding_priority, conn->scheduler.reqs.freestanding, iter);
            h2o_http2_scheduler_close(&closed->entries[closed->oldest_index].ref);
        }
    }
    { /* ... then releasing the entries that were never associated to a stream */
        h2o_http2_scheduler_openref_t *ref;
        kh_foreach_value(conn->scheduler.reqs.freestanding, ref, {
            h2o_http2_scheduler_close(ref);
            free(ref);
        });
        kh_destroy(h2o_http3_freestanding_priority, conn->scheduler.reqs.freestanding);
    }
    { /* ... then closing the placeholders */
        size_t i;
        for (i = 0; i != sizeof(conn->scheduler.reqs.placeholders) / sizeof(conn->scheduler.reqs.placeholders[0]); ++i)
            if (h2o_http2_scheduler_is_open(conn->scheduler.reqs.placeholders + i))
                h2o_http2_scheduler_close(conn->scheduler.reqs.placeholders + i);
    }
    h2o_http2_scheduler_dispose(&conn->scheduler.reqs.root);
    assert(h2o_linklist_is_empty(&conn->scheduler.conn_blocked.reqs));

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
    h2o_http2_scheduler_init(&conn->scheduler.reqs.root);
    memset(&conn->scheduler.reqs.placeholders, 0, sizeof(conn->scheduler.reqs.placeholders));
    conn->scheduler.reqs.freestanding = kh_init(h2o_http3_freestanding_priority);
    assert(conn->scheduler.reqs.freestanding != NULL);
    {
        struct st_h2o_http3_closed_priorities_t *closed = &conn->scheduler.reqs.closed_streams;
        for (i = 0; i != sizeof(closed->entries) / sizeof(closed->entries[0]); ++i) {
            closed->entries[i].id = -1;
            memset(&closed->entries[i].ref, 0, sizeof(closed->entries[i].ref));
        }
        closed->oldest_index = 0;
    }
    conn->scheduler.uni = 0;
    h2o_linklist_init_anchor(&conn->scheduler.conn_blocked.reqs);
    conn->scheduler.conn_blocked.uni = 0;

    /* accept connection */
    quicly_conn_t *qconn;
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
