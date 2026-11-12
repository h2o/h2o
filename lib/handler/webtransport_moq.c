/*
 * Copyright (c) 2026 Fastly, Kazuho Oku
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

/**
 * The `webtransport.moq` handler: accepts MoQ sessions over WebTransport (draft-ietf-webtrans-http3-02, as Chrome implements it),
 * and forwards each one to a MoQ relay over native QUIC, splicing the streams and the datagrams 1:1. It implements no MoQ; the MoQ
 * draft is selected as the WebTransport subprotocol, and used as the ALPN of the backend connection.
 */
#include <stdio.h>
#include "picotls/openssl.h"
#include "h2o.h"
#include "h2o/http3_common.h"
#include "h2o/http3_server.h"

#define WT_STREAM_TYPE_UNI 0x54
#define WT_SIGNAL_BIDI 0x41
#define WT_ERROR_BUFFERED_STREAM_REJECTED QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0x3994bd84)
#define WT_CAPSULE_CLOSE_SESSION 0x2843
#define WT_MAX_CLOSE_MESSAGE 1024
#define WT_MAPPED_ERROR_CODE_FIRST UINT64_C(0x52e4a40fa8db)
#define WT_MAPPED_ERROR_CODE_LAST UINT64_C(0x52e5ac983162)

#define MAX_STREAMS 100
#define STREAM_WINDOW (1024 * 1024)
#define CONNECT_TIMEOUT 10000 /* in milliseconds */
#define MAX_CAPSULE_SIZE 16384
#define MAX_DATAGRAM_FRAME_SIZE 1500 /* advertised to the relay; same as what h2o advertises to the client */

/**
 * the MoQ drafts being supported, used as the WebTransport subprotocol and the ALPN
 */
static const char *supported_protocols[] = {"moqt-20", "moqt-21", "moqt-22", NULL};

/**
 * the relay to which the sessions are forwarded
 */
struct st_wtmoq_relay_t {
    char *host; /* NUL-terminated */
    h2o_iovec_t port;
    /**
     * for testing; connects to the relay using QMux over cleartext TCP, instead of QUIC
     */
    unsigned qmux_cleartext : 1;
};

struct st_wtmoq_handler_t {
    h2o_handler_t super;
    struct st_wtmoq_relay_t relay;
};

/**
 * per-thread state; holds the QUIC client context used for the backend connections
 */
struct st_wtmoq_thread_ctx_t {
    h2o_context_t *ctx;
    ptls_context_t tls;
    quicly_context_t quic;
    quicly_stream_open_t stream_open;
    quicly_receive_datagram_frame_t receive_datagram_frame;
    h2o_quic_ctx_t quic_ctx;
};

struct st_wtmoq_session_t;

struct st_wtmoq_backend_t {
    h2o_quic_conn_t super;
    /**
     * the session, or NULL once the session has ended
     */
    struct st_wtmoq_session_t *session;
    ptls_iovec_t alpn;
    ptls_handshake_properties_t handshake_properties;
};

struct st_wtmoq_pair_t;

/**
 * One of the two streams of a pair. Bytes received on a half are kept in its `recvbuf` until the peer half has sent them and they
 * have been acknowledged; only then are they consumed, returning the credit. Buffering is therefore bounded by the receive window.
 */
struct st_wtmoq_half_t {
    struct st_wtmoq_pair_t *pair;
    /**
     * the QUIC stream; NULL once the stream has been destroyed, or detached from
     */
    quicly_stream_t *quic;
    /**
     * received bytes (after the WebTransport header, if any), starting at `quic->recvstate.data_off`; retained after the stream is
     * destroyed, until the peer has sent them
     */
    h2o_buffer_t *recvbuf;
    /**
     * number of contiguous bytes in `recvbuf` ready to be sent by the peer
     */
    size_t bytes_ready;
    /**
     * if the receive side has ended with a FIN
     */
    unsigned recv_fin : 1;
    /**
     * The WebTransport header to be sent before the bytes of the peer, on a stream that we opened toward the client. Emitted from
     * here; `header_len` is 0 for the other streams.
     */
    uint8_t header[16];
    uint8_t header_len;
    /**
     * number of bytes of the send side that have been acknowledged (i.e., shifted)
     */
    uint64_t bytes_shifted;
    /**
     * number of bytes of the send side that have been made available to quicly; activating the send side without new bytes is not
     * allowed (`quicly_send_stream` asserts that `on_send_emit` provides some)
     */
    uint64_t bytes_available;
    /**
     * if this is the frontend half (i.e., on the WebTransport side)
     */
    unsigned is_frontend : 1;
    /**
     * set for a stream that the client opened, until the session ID that follows the stream type (or signal value) has been read
     */
    unsigned header_pending : 1;
};

struct st_wtmoq_pair_t {
    /**
     * the session, or NULL once the session has ended
     */
    struct st_wtmoq_session_t *session;
    /**
     * that of the session, retained for mapping the error codes after the session has ended
     */
    const struct st_wtmoq_frontend_t *frontend_cb;
    h2o_linklist_t link;
    struct st_wtmoq_half_t frontend, backend;
    /**
     * set for a stream that a native client opened before the relay connection was established, until the backend stream is opened
     */
    unsigned backend_pending : 1;
};

/**
 * What depends on how the client reaches us. The splicing of the streams and datagrams does not; the frontend wraps it in
 * WebTransport (see `wt_frontend`).
 */
struct st_wtmoq_frontend_t {
    /**
     * writes the header to be sent before the bytes of the relay, on a stream opened toward the client; returns its length
     */
    size_t (*encode_stream_header)(struct st_wtmoq_session_t *session, uint8_t *dst, int unidirectional);
    /**
     * map the application error codes received from the client to those sent to the relay, and vice versa
     */
    uint64_t (*error_from_client)(uint64_t code);
    uint64_t (*error_to_client)(uint64_t code);
    /**
     * called once the connection to the relay has been established
     */
    void (*on_established)(struct st_wtmoq_session_t *session);
    /**
     * called when the connection to the relay could not be established
     */
    void (*on_connect_failed)(struct st_wtmoq_session_t *session, const char *errstr);
    /**
     * ends the session, as the relay has closed the connection with `code` and `reason`
     */
    void (*close)(struct st_wtmoq_session_t *session, uint64_t code, const char *reason);
    /**
     * sends a datagram received from the relay to the client
     */
    void (*send_datagram)(struct st_wtmoq_session_t *session, ptls_iovec_t payload);
};

struct st_wtmoq_session_t {
    h2o_generator_t super;
    const struct st_wtmoq_frontend_t *frontend_cb;
    /**
     * the extended CONNECT request (only for WebTransport)
     */
    h2o_req_t *req;
    const struct st_wtmoq_relay_t *relay;
    struct st_wtmoq_thread_ctx_t *tctx;
    /**
     * the stream ID of the extended CONNECT request
     */
    uint64_t session_id;
    /**
     * the QUIC connection with the client (for WebTransport, as returned by `h2o_req_t::open_extended_http3`)
     */
    quicly_conn_t *frontend;
    /**
     * the backend connection, or NULL if not open
     */
    struct st_wtmoq_backend_t *backend;
    const char *protocol;
    h2o_hostinfo_getaddr_req_t *getaddr_req;
    /**
     * the TCP connection to the relay being established, when QMux is used
     */
    h2o_socket_t *connect_sock;
    h2o_timer_t connect_timeout;
    /**
     * list of pairs
     */
    h2o_linklist_t pairs;
    /**
     * capsules received on the request stream, being parsed
     */
    h2o_buffer_t *capsules;
    /**
     * Bytes to be sent on the response. `pending` is appended to, while `inflight` holds the bytes passed to `h2o_send` until the
     * generator is called to proceed.
     */
    struct {
        h2o_buffer_t *pending;
        h2o_buffer_t *inflight;
        unsigned is_inflight : 1;
        unsigned is_final : 1;
        unsigned final_sent : 1;
    } resp;
    unsigned established : 1;
    /**
     * set once CLOSE_WEBTRANSPORT_SESSION has been received; nothing but the end of the request stream may follow
     */
    unsigned close_received : 1;
    /**
     * set once the session has terminated (draft-ietf-webtrans-http3-02 section 5); the streams have been aborted and detached from
     */
    unsigned terminated : 1;
    unsigned disposed : 1;
};

static void close_backend(struct st_wtmoq_session_t *session, uint64_t code, const char *reason);
static void send_session_close(struct st_wtmoq_session_t *session, uint32_t code, const char *reason, size_t reason_len);

/* error codes */

static uint64_t error_to_http3(uint32_t code)
{
    return WT_MAPPED_ERROR_CODE_FIRST + code + code / 0x1e;
}

static uint32_t error_from_http3(uint64_t h3code)
{
    if (!(WT_MAPPED_ERROR_CODE_FIRST <= h3code && h3code <= WT_MAPPED_ERROR_CODE_LAST) || (h3code - 0x21) % 0x1f == 0)
        return 0;
    uint64_t shifted = h3code - WT_MAPPED_ERROR_CODE_FIRST;
    return (uint32_t)(shifted - shifted / 0x1f);
}

/**
 * converts the error received on `from` to the one to be sent on its peer
 */
static quicly_error_t convert_error(struct st_wtmoq_half_t *from, quicly_error_t err)
{
    const struct st_wtmoq_frontend_t *frontend_cb = from->pair->frontend_cb;
    uint64_t code = QUICLY_ERROR_IS_QUIC_APPLICATION(err) ? QUICLY_ERROR_GET_ERROR_CODE(err) : 0;

    return QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(from->is_frontend ? frontend_cb->error_from_client(code)
                                                                      : frontend_cb->error_to_client(code));
}

/* pairs */

static struct st_wtmoq_half_t *get_peer(struct st_wtmoq_half_t *half)
{
    return half->is_frontend ? &half->pair->backend : &half->pair->frontend;
}

static int has_send_side(quicly_stream_t *qs)
{
    return quicly_stream_has_send_side(quicly_is_client(qs->conn), qs->stream_id);
}

static int has_receive_side(quicly_stream_t *qs)
{
    return quicly_stream_has_receive_side(quicly_is_client(qs->conn), qs->stream_id);
}

static struct st_wtmoq_pair_t *create_pair(struct st_wtmoq_session_t *session)
{
    struct st_wtmoq_pair_t *pair = h2o_mem_alloc(sizeof(*pair));

    *pair = (struct st_wtmoq_pair_t){.session = session, .frontend_cb = session->frontend_cb};
    pair->frontend = (struct st_wtmoq_half_t){.pair = pair, .is_frontend = 1};
    pair->backend = (struct st_wtmoq_half_t){.pair = pair};
    h2o_buffer_init(&pair->frontend.recvbuf, &h2o_socket_buffer_prototype);
    h2o_buffer_init(&pair->backend.recvbuf, &h2o_socket_buffer_prototype);
    h2o_linklist_insert(&session->pairs, &pair->link);

    return pair;
}

static void free_pair_if_done(struct st_wtmoq_pair_t *pair)
{
    if (pair->frontend.quic != NULL || pair->backend.quic != NULL)
        return;
    if (h2o_linklist_is_linked(&pair->link))
        h2o_linklist_unlink(&pair->link);
    if (pair->frontend.recvbuf != NULL)
        h2o_buffer_dispose(&pair->frontend.recvbuf);
    if (pair->backend.recvbuf != NULL)
        h2o_buffer_dispose(&pair->backend.recvbuf);
    free(pair);
}

/**
 * Schedules the connection of the stream to send what has been made available. h2o sends on a QUIC connection when its timer
 * fires, and the timer is otherwise updated only when the connection itself receives packets.
 */
static void schedule_send(quicly_stream_t *qs)
{
    h2o_quic_schedule_timer(*quicly_get_data(qs->conn));
}

/**
 * discards the bytes received on the half that are no longer going to be sent, returning the credit
 */
static void discard_input(struct st_wtmoq_half_t *half)
{
    if (half->bytes_ready == 0)
        return;
    h2o_buffer_consume(&half->recvbuf, half->bytes_ready);
    if (half->quic != NULL)
        quicly_stream_sync_recvbuf(half->quic, half->bytes_ready);
    half->bytes_ready = 0;
}

/**
 * Resets the send side of the stream, unless it has been closed already, then discards the bytes of the peer, which are no longer
 * going to be sent. On a stream we opened toward the client, until the WebTransport header has been acknowledged, the reset is a
 * RESET_STREAM_AT with the header as the reliable size, so that the client can associate the stream with the session. A client
 * that does not support RESET_STREAM_AT gets a RESET_STREAM.
 */
static void reset_half(struct st_wtmoq_half_t *half, quicly_error_t err)
{
    quicly_stream_t *qs = half->quic;

    if (qs != NULL) {
        if (!has_send_side(qs) || !quicly_sendstate_is_open(&qs->sendstate))
            return;
        if (half->bytes_shifted < half->header_len && quicly_set_reset_stream_at(qs, err, half->header_len) == 0) {
            quicly_stream_sync_sendbuf(qs, 1);
        } else {
            quicly_reset_stream(qs, err);
        }
        schedule_send(qs);
    }
    discard_input(get_peer(half));
}

/**
 * resets the send side and stops the receive side of the stream, unless they have been closed already
 */
static void abort_half(struct st_wtmoq_half_t *half, quicly_error_t err)
{
    quicly_stream_t *qs = half->quic;

    if (qs == NULL)
        return;
    reset_half(half, err);
    if (has_receive_side(qs)) {
        quicly_request_stop(qs, err);
        discard_input(half);
        schedule_send(qs);
    }
}

/**
 * Called when the peer of `half` has new bytes to be sent or has ended. Updates the send side of `half` accordingly.
 */
static void sync_send(struct st_wtmoq_half_t *half)
{
    struct st_wtmoq_half_t *src = get_peer(half);
    quicly_stream_t *qs = half->quic;

    if (qs == NULL || !quicly_sendstate_is_open(&qs->sendstate))
        return;

    /* the header, then the bytes received by the peer */
    uint64_t payload_shifted = half->bytes_shifted > half->header_len ? half->bytes_shifted - half->header_len : 0,
             total = half->header_len + payload_shifted + src->bytes_ready;
    if (src->recv_fin) {
        quicly_sendstate_shutdown(&qs->sendstate, total);
    } else if (total <= half->bytes_available) {
        return;
    }
    half->bytes_available = total;
    quicly_stream_sync_sendbuf(qs, 1);
    schedule_send(qs);
}

static void on_send_shift(quicly_stream_t *qs, size_t delta)
{
    struct st_wtmoq_half_t *half = qs->data, *src = get_peer(half);

    /* bytes of the header are emitted from `header`, the rest from the receive buffer of the peer, consumed here */
    uint64_t header_left = half->bytes_shifted < half->header_len ? half->header_len - half->bytes_shifted : 0;
    size_t payload = delta > header_left ? delta - header_left : 0;
    half->bytes_shifted += delta;

    /* Once the send side has been reset, the bytes of the peer have been discarded. Bytes are still shifted after a RESET_STREAM_AT
     * (acknowledging the header retires the payload bytes in flight beyond it), and after a reset in response to STOP_SENDING that
     * follows a FIN (quicly retires the bytes up to the FIN). */
    if (qs->sendstate.app_error_code != UINT64_MAX) {
        discard_input(src);
        return;
    }

    if (payload != 0) {
        assert(payload <= src->bytes_ready);
        h2o_buffer_consume(&src->recvbuf, payload);
        src->bytes_ready -= payload;
        if (src->quic != NULL) {
            quicly_stream_sync_recvbuf(src->quic, payload);
            schedule_send(src->quic);
        }
    }
}

static void on_send_emit(quicly_stream_t *qs, size_t off, void *_dst, size_t *len, int *wrote_all)
{
    struct st_wtmoq_half_t *half = qs->data, *src = get_peer(half);
    uint8_t *dst = _dst, *dst_end = dst + *len;
    uint64_t pos = half->bytes_shifted + off; /* the offset within the stream */

    /* the header */
    if (pos < half->header_len) {
        size_t n = half->header_len - pos;
        if (n > dst_end - dst)
            n = dst_end - dst;
        memcpy(dst, half->header + pos, n);
        dst += n;
        pos += n;
        if (pos < half->header_len) {
            *len = dst - (uint8_t *)_dst;
            *wrote_all = 0;
            return;
        }
    }

    /* the bytes of the peer; the receive buffer starts at the first byte not yet shifted */
    uint64_t payload_shifted = half->bytes_shifted > half->header_len ? half->bytes_shifted - half->header_len : 0;
    size_t src_off = pos - half->header_len - payload_shifted;
    assert(src_off <= src->bytes_ready);
    size_t n = src->bytes_ready - src_off;
    if (n > dst_end - dst)
        n = dst_end - dst;
    memcpy(dst, src->recvbuf->bytes + src_off, n);
    dst += n;

    *len = dst - (uint8_t *)_dst;
    *wrote_all = src_off + n == src->bytes_ready;
}

static void on_send_stop(quicly_stream_t *qs, quicly_error_t err)
{
    struct st_wtmoq_half_t *half = qs->data, *src = get_peer(half);

    /* the send side has been reset by quicly; stop the peer from sending what would be forwarded */
    if (src->quic != NULL && has_receive_side(src->quic) && !quicly_recvstate_transfer_complete(&src->quic->recvstate)) {
        quicly_request_stop(src->quic, convert_error(half, err));
        schedule_send(src->quic);
    }
    discard_input(src);
}

static int open_backend_stream(struct st_wtmoq_pair_t *pair, int unidirectional);

/**
 * processes the bytes received on `half`, making them available to the peer, and the end of the stream
 */
static void process_input(struct st_wtmoq_half_t *half)
{
    quicly_stream_t *qs = half->quic;
    struct st_wtmoq_half_t *peer = get_peer(half);

    /* read the session ID that follows the stream type or signal value of a stream the client opened */
    if (half->header_pending) {
        const uint8_t *src = (const uint8_t *)half->recvbuf->bytes,
                      *src_end = src + quicly_recvstate_bytes_available(&qs->recvstate);
        uint64_t session_id;
        if ((session_id = quicly_decodev(&src, src_end)) == UINT64_MAX) {
            if (quicly_recvstate_transfer_complete(&qs->recvstate))
                abort_half(half, WT_ERROR_BUFFERED_STREAM_REJECTED);
            return;
        }
        size_t header_len = src - (const uint8_t *)half->recvbuf->bytes;
        h2o_buffer_consume(&half->recvbuf, header_len);
        quicly_stream_sync_recvbuf(qs, header_len);
        half->header_pending = 0;
        /* draft-ietf-webtrans-http3-02 section 4: an ID that cannot be that of a client-initiated bidirectional stream is a
         * connection error */
        if ((session_id & 3) != 0) {
            h2o_quic_close_connection(*quicly_get_data(qs->conn), H2O_HTTP3_ERROR_ID, "invalid WebTransport session ID");
            return;
        }
        if (half->pair->session == NULL || session_id != half->pair->session->session_id ||
            open_backend_stream(half->pair, quicly_stream_is_unidirectional(qs->stream_id)) != 0) {
            abort_half(half, WT_ERROR_BUFFERED_STREAM_REJECTED);
            return;
        }
    }

    /* make the bytes available to the peer; they are consumed as the peer's sends are acknowledged */
    half->bytes_ready = quicly_recvstate_bytes_available(&qs->recvstate);
    if (quicly_recvstate_transfer_complete(&qs->recvstate)) {
        if (qs->recvstate.app_error_code == UINT64_MAX) {
            half->recv_fin = 1;
        } else {
            reset_half(peer, convert_error(half, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(qs->recvstate.app_error_code)));
            return;
        }
    }
    sync_send(peer);
}

static void on_receive(quicly_stream_t *qs, size_t off, const void *src, size_t len)
{
    struct st_wtmoq_half_t *half = qs->data;

    h2o_http3_update_recvbuf(&half->recvbuf, off, src, len);
    process_input(half);
}

static void on_stream_destroy(quicly_stream_t *qs, quicly_error_t err)
{
    struct st_wtmoq_half_t *half = qs->data, *peer = get_peer(half);
    quicly_error_t abort_err = convert_error(half, err != 0 ? err : QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0));

    half->quic = NULL;

    /* If the stream was destroyed before its sides were closed (e.g., the connection was closed), abort the peer. The bytes
     * received with a FIN remain in `recvbuf`, to be sent by the peer. */
    if (peer->quic != NULL) {
        if (has_send_side(qs) && !quicly_sendstate_transfer_complete(&qs->sendstate)) {
            abort_half(peer, abort_err);
        } else if (has_receive_side(qs) && !quicly_recvstate_transfer_complete(&qs->recvstate)) {
            reset_half(peer, abort_err);
        }
    }

    free_pair_if_done(half->pair);
}

static const quicly_stream_callbacks_t half_callbacks = {on_stream_destroy, on_send_shift, on_send_emit,
                                                         on_send_stop,      on_receive,    NULL};

static void bind_half(struct st_wtmoq_half_t *half, quicly_stream_t *qs)
{
    half->quic = qs;
    qs->data = half;
    qs->callbacks = &half_callbacks;
    if (has_receive_side(qs))
        quicly_stream_set_receive_window(qs, STREAM_WINDOW);
}

static int open_backend_stream(struct st_wtmoq_pair_t *pair, int unidirectional)
{
    quicly_stream_t *qs;

    if (pair->session->backend == NULL || quicly_open_stream(pair->session->backend->super.quic, &qs, unidirectional) != 0)
        return -1;
    bind_half(&pair->backend, qs);
    return 0;
}

static int open_frontend_stream(struct st_wtmoq_pair_t *pair, int unidirectional)
{
    quicly_stream_t *qs;

    if (quicly_open_stream(pair->session->frontend, &qs, unidirectional) != 0)
        return -1;
    bind_half(&pair->frontend, qs);

    /* the header, sent before the bytes of the peer */
    pair->frontend.header_len =
        (uint8_t)pair->session->frontend_cb->encode_stream_header(pair->session, pair->frontend.header, unidirectional);
    sync_send(&pair->frontend);

    return 0;
}

/**
 * called by the HTTP/3 layer for the streams the client opens and HTTP/3 does not recognize (see `h2o_req_t::open_extended_http3`)
 */
static quicly_error_t on_frontend_stream_open(h2o_req_t *req, quicly_stream_t *qs, h2o_buffer_t **recvbuf)
{
    struct st_wtmoq_session_t *session = req->write_req.ctx;
    int unidirectional = quicly_stream_is_unidirectional(qs->stream_id);

    /* decode the stream type or signal value, which the HTTP/3 layer guarantees to have been received */
    const uint8_t *src = (const uint8_t *)(*recvbuf)->bytes, *src_end = src + quicly_recvstate_bytes_available(&qs->recvstate);
    uint64_t type = quicly_decodev(&src, src_end);
    assert(type != UINT64_MAX);
    if (type != (unidirectional ? WT_STREAM_TYPE_UNI : WT_SIGNAL_BIDI))
        return H2O_HTTP3_ERROR_DECLINED;
    if (!session->established || session->terminated)
        return WT_ERROR_BUFFERED_STREAM_REJECTED;

    /* take the stream, consuming the type */
    struct st_wtmoq_pair_t *pair = create_pair(session);
    h2o_buffer_dispose(&pair->frontend.recvbuf);
    pair->frontend.recvbuf = *recvbuf;
    *recvbuf = NULL;
    pair->frontend.header_pending = 1;
    bind_half(&pair->frontend, qs);
    size_t type_len = src - (const uint8_t *)pair->frontend.recvbuf->bytes;
    h2o_buffer_consume(&pair->frontend.recvbuf, type_len);
    quicly_stream_sync_recvbuf(qs, type_len);

    process_input(&pair->frontend);
    return 0;
}

/**
 * quicly's stream_open callback of the backend connections
 */
static quicly_error_t on_backend_stream_open(quicly_stream_open_t *self, quicly_stream_t *qs)
{
    /* streams we open are set up by the caller of `quicly_open_stream` */
    if (quicly_stream_is_self_initiated(qs)) {
        qs->callbacks = &quicly_stream_noop_callbacks;
        qs->data = NULL;
        return 0;
    }

    struct st_wtmoq_backend_t *backend = *quicly_get_data(qs->conn);
    struct st_wtmoq_session_t *session = backend->session;
    int unidirectional = quicly_stream_is_unidirectional(qs->stream_id);

    if (session == NULL || !session->established || session->terminated) {
        qs->callbacks = &quicly_stream_noop_callbacks;
        qs->data = NULL;
        quicly_request_stop(qs, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0));
        if (!unidirectional)
            quicly_reset_stream(qs, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0));
        return 0;
    }

    struct st_wtmoq_pair_t *pair = create_pair(session);
    bind_half(&pair->backend, qs);
    if (open_frontend_stream(pair, unidirectional) != 0)
        abort_half(&pair->backend, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0));
    return 0;
}

/**
 * Terminates the session's streams on the client connection: resets their send sides, stops their receive sides, and detaches from
 * them, as draft-ietf-webtrans-http3-02 section 5 requires once the session has terminated. Nothing is forwarded to the client
 * thereafter; in particular, how the relay ends its streams in response to the session ending is not relayed.
 *
 * A send side that has not been acknowledged in full is reset by RESET_STREAM even if it has been ended with a FIN or a
 * RESET_STREAM_AT, as nothing is left to emit its bytes once detached.
 */
static void terminate_session_streams(struct st_wtmoq_session_t *session)
{
    quicly_error_t err = QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(session->frontend_cb->error_to_client(0));

    session->terminated = 1;
    for (h2o_linklist_t *l = session->pairs.next; l != &session->pairs;) {
        struct st_wtmoq_pair_t *pair = H2O_STRUCT_FROM_MEMBER(struct st_wtmoq_pair_t, link, l);
        l = l->next;
        quicly_stream_t *qs;
        if ((qs = pair->frontend.quic) != NULL) {
            if (has_send_side(qs) && !quicly_sendstate_transfer_complete(&qs->sendstate) &&
                quicly_sendstate_eos_type(&qs->sendstate) != QUICLY_SENDSTATE_EOS_TYPE_RESET)
                quicly_reset_stream(qs, err);
            if (has_receive_side(qs) && !quicly_recvstate_transfer_complete(&qs->recvstate))
                quicly_request_stop(qs, err);
            schedule_send(qs);
            discard_input(&pair->frontend);
            qs->callbacks = &quicly_stream_noop_callbacks;
            qs->data = NULL;
            pair->frontend.quic = NULL;
            discard_input(&pair->backend);
        }
        free_pair_if_done(pair);
    }
}

/* the response (capsules sent to the client) */

static void flush_response(struct st_wtmoq_session_t *session)
{
    if (!session->established || session->resp.is_inflight || session->resp.final_sent)
        return;
    if (session->resp.pending->size == 0 && !session->resp.is_final)
        return;

    /* swap the buffers, then send */
    h2o_buffer_t *t = session->resp.inflight;
    session->resp.inflight = session->resp.pending;
    session->resp.pending = t;
    h2o_iovec_t vec = h2o_iovec_init(session->resp.inflight->bytes, session->resp.inflight->size);
    session->resp.is_inflight = 1;
    if (session->resp.is_final)
        session->resp.final_sent = 1;
    h2o_send(session->req, &vec, vec.len != 0 ? 1 : 0, session->resp.is_final ? H2O_SEND_STATE_FINAL : H2O_SEND_STATE_IN_PROGRESS);
}

static void on_generator_proceed(h2o_generator_t *_self, h2o_req_t *req)
{
    struct st_wtmoq_session_t *session = H2O_STRUCT_FROM_MEMBER(struct st_wtmoq_session_t, super, _self);

    session->resp.is_inflight = 0;
    h2o_buffer_consume_all(&session->resp.inflight, 0);
    flush_response(session);
}

/**
 * sends CLOSE_WEBTRANSPORT_SESSION, followed by the end of the response
 */
/**
 * Returns the length of the error message of CLOSE_WEBTRANSPORT_SESSION, which must not exceed 1024 bytes
 * (draft-ietf-webtrans-http3-02 section 5); a longer message is cut at the last UTF-8 character boundary within the limit.
 */
static size_t limit_close_message(const char *msg, size_t len)
{
    if (len <= WT_MAX_CLOSE_MESSAGE)
        return len;
    len = WT_MAX_CLOSE_MESSAGE;
    while (len != 0 && ((uint8_t)msg[len] & 0xc0) == 0x80)
        --len;
    return len;
}

static void send_session_close(struct st_wtmoq_session_t *session, uint32_t code, const char *reason, size_t reason_len)
{
    if (session->resp.is_final)
        return;

    reason_len = limit_close_message(reason, reason_len);
    uint8_t header[24], *p = header;
    p = quicly_encodev(p, WT_CAPSULE_CLOSE_SESSION);
    p = quicly_encodev(p, 4 + reason_len);
    *p++ = code >> 24;
    *p++ = code >> 16;
    *p++ = code >> 8;
    *p++ = code;
    h2o_buffer_append(&session->resp.pending, header, p - header);
    h2o_buffer_append(&session->resp.pending, reason, reason_len);
    session->resp.is_final = 1;
    flush_response(session);
}

/* the request (capsules received from the client) */

static int on_write_req(void *_session, int is_end_stream)
{
    struct st_wtmoq_session_t *session = _session;
    h2o_req_t *req = session->req;

    h2o_buffer_append(&session->capsules, req->entity.base, req->entity.len);

    /* handle the capsules */
    while (session->capsules->size != 0) {
        /* Data following CLOSE_WEBTRANSPORT_SESSION is an error of the request stream. Draft-ietf-webtrans-http3-02 section 5
         * requires the stream to be reset with H3_MESSAGE_ERROR, but it is reset with H3_INTERNAL_ERROR: `write_req.cb` can only
         * report failure, which the HTTP/3 layer cannot tell apart from the destination of the request body being gone. Doing it
         * right requires the callback to distinguish a malformed request body from such failures. */
        if (session->close_received)
            return 1;
        const uint8_t *src = (const uint8_t *)session->capsules->bytes, *src_end = src + session->capsules->size;
        uint64_t type, length;
        if ((type = quicly_decodev(&src, src_end)) == UINT64_MAX || (length = quicly_decodev(&src, src_end)) == UINT64_MAX) {
            if (session->capsules->size >= 16)
                goto Malformed;
            break;
        }
        if (length > MAX_CAPSULE_SIZE)
            goto Malformed;
        if (src_end - src < length)
            break;
        if (type == WT_CAPSULE_CLOSE_SESSION) {
            if (length < 4)
                goto Malformed;
            uint32_t code = (uint32_t)src[0] << 24 | (uint32_t)src[1] << 16 | (uint32_t)src[2] << 8 | src[3];
            size_t reason_len = limit_close_message((const char *)src + 4, length - 4);
            char *reason = h2o_mem_alloc_pool(&req->pool, char, reason_len + 1);
            memcpy(reason, src + 4, reason_len);
            reason[reason_len] = '\0';
            /* the client has terminated the session */
            session->close_received = 1;
            terminate_session_streams(session);
            close_backend(session, code, reason);
        }
        /* other capsules (e.g., DRAIN_WEBTRANSPORT_SESSION, unknown types) are ignored */
        h2o_buffer_consume(&session->capsules, src + length - (const uint8_t *)session->capsules->bytes);
    }

    if (!(session->close_received || is_end_stream)) {
        req->proceed_req(req, NULL);
        return 0;
    }

    /* The session has terminated, by CLOSE_WEBTRANSPORT_SESSION or by the client ending the request stream; end the response.
     * Ending the response might end the request stream as well (the HTTP/3 layer stops the receive side and releases the request
     * body when the response has been sent in full), so the request body is not proceeded, and nothing follows; in particular, data
     * that arrives after CLOSE_WEBTRANSPORT_SESSION is detected as above only when delivered together with the capsule. */
    if (!session->close_received) {
        terminate_session_streams(session);
        close_backend(session, 0, "");
    }
    session->resp.is_final = 1;
    flush_response(session);
    return 0;

Malformed:
    /* the request stream is reset with H3_INTERNAL_ERROR, for the reason stated above */
    terminate_session_streams(session);
    close_backend(session, 0, "");
    return 1;
}

/* the backend connection */

static void close_backend(struct st_wtmoq_session_t *session, uint64_t code, const char *reason)
{
    struct st_wtmoq_backend_t *backend;

    if ((backend = session->backend) == NULL)
        return;
    session->backend = NULL;
    backend->session = NULL;
    h2o_quic_close_connection(&backend->super, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(code), reason);
}

static void establish_session(struct st_wtmoq_session_t *session)
{
    h2o_timer_unlink(&session->connect_timeout);
    session->established = 1;
    session->frontend_cb->on_established(session);
}

static void wt_on_established(struct st_wtmoq_session_t *session)
{
    h2o_req_t *req = session->req;

    /* send the 2xx */
    req->res.status = 200;
    h2o_add_header_by_str(&req->pool, &req->res.headers, H2O_STRLIT("sec-webtransport-http3-draft"), 0, NULL,
                          H2O_STRLIT("draft02"));
    char *protocol = h2o_mem_alloc_pool(&req->pool, char, strlen(session->protocol) + 3);
    size_t protocol_len = sprintf(protocol, "\"%s\"", session->protocol);
    h2o_add_header_by_str(&req->pool, &req->res.headers, H2O_STRLIT("wt-protocol"), 0, NULL, protocol, protocol_len);
    h2o_start_response(req, &session->super);
    session->resp.is_inflight = 1;
    h2o_send(req, NULL, 0, H2O_SEND_STATE_IN_PROGRESS);

    /* start reading the capsules */
    on_write_req(session, 0);
}

static void fail_session(struct st_wtmoq_session_t *session, const char *errstr)
{
    h2o_timer_unlink(&session->connect_timeout);
    close_backend(session, 0, "");
    session->frontend_cb->on_connect_failed(session, errstr);
}

static void wt_on_connect_failed(struct st_wtmoq_session_t *session, const char *errstr)
{
    h2o_send_error_502(session->req, "Bad Gateway", errstr, 0);
}

static void wt_close(struct st_wtmoq_session_t *session, uint64_t code, const char *reason)
{
    send_session_close(session, code <= UINT32_MAX ? (uint32_t)code : 0, reason, strlen(reason));
}

static void on_backend_destroy(h2o_quic_conn_t *_backend)
{
    struct st_wtmoq_backend_t *backend = (void *)_backend;
    struct st_wtmoq_session_t *session = backend->session;

    if (session != NULL) {
        session->backend = NULL;
        backend->session = NULL;
        if (!session->established) {
            fail_session(session, "backend connection failed");
        } else {
            /* the relay has closed the connection; close the session with the application error code */
            uint64_t code = 0;
            const char *reason = "";
            if (quicly_get_state(backend->super.quic) >= QUICLY_STATE_CLOSING) {
                quicly_error_t err = quicly_get_close_reason(backend->super.quic, NULL, &reason, NULL);
                if (QUICLY_ERROR_IS_QUIC_APPLICATION(err))
                    code = QUICLY_ERROR_GET_ERROR_CODE(err);
                if (reason == NULL)
                    reason = "";
            }
            terminate_session_streams(session);
            session->frontend_cb->close(session, code, reason);
        }
    }

    /* destroys the streams, which in turn abort their peers */
    h2o_quic_dispose_conn(&backend->super);
    free(backend);
}

static void on_backend_update(h2o_quic_ctx_t *ctx, h2o_quic_conn_t *_backend)
{
    struct st_wtmoq_backend_t *backend = (void *)_backend;
    struct st_wtmoq_session_t *session = backend->session;

    if (session != NULL && !session->established && quicly_connection_is_ready(backend->super.quic))
        establish_session(session);
}

static struct st_wtmoq_backend_t *create_backend(struct st_wtmoq_session_t *session)
{
    static const h2o_quic_conn_callbacks_t callbacks = {on_backend_destroy};
    struct st_wtmoq_backend_t *backend = h2o_mem_alloc(sizeof(*backend));

    *backend = (struct st_wtmoq_backend_t){.session = session};
    h2o_quic_init_conn(&backend->super, &session->tctx->quic_ctx, &callbacks);
    backend->alpn = ptls_iovec_init(session->protocol, strlen(session->protocol));
    backend->handshake_properties.client.negotiated_protocols.list = &backend->alpn;
    backend->handshake_properties.client.negotiated_protocols.count = 1;

    return backend;
}

/**
 * Called when the TCP connection to the relay has been established, when QMux is used. QMux has no handshake; the session is
 * established at once, and streams opened before the transport parameters of the relay arrive wait for its stream limits.
 */
static void on_qmux_connect(h2o_socket_t *sock, const char *err)
{
    struct st_wtmoq_session_t *session = sock->data;
    quicly_conn_t *qc;

    session->connect_sock = NULL;
    if (err != NULL) {
        h2o_socket_close(sock);
        fail_session(session, err);
        return;
    }

    struct st_wtmoq_backend_t *backend = create_backend(session);
    if ((qc = quicly_qmux_new(&session->tctx->quic, 1, NULL)) == NULL)
        h2o_fatal("no memory");
    h2o_quic_setup(&backend->super, qc, sock);
    session->backend = backend;
    establish_session(session);
    h2o_quic_send(&backend->super);
}

static void on_getaddr(h2o_hostinfo_getaddr_req_t *getaddr_req, const char *errstr, struct addrinfo *res, void *_session)
{
    struct st_wtmoq_session_t *session = _session;
    h2o_context_t *ctx = session->tctx->ctx;
    quicly_conn_t *qc;

    session->getaddr_req = NULL;
    if (errstr != NULL) {
        fail_session(session, errstr);
        return;
    }
    struct addrinfo *selected = h2o_hostinfo_select_one(res);

    if (session->relay->qmux_cleartext) {
        if ((session->connect_sock =
                 h2o_socket_connect(ctx->loop, selected->ai_addr, selected->ai_addrlen, on_qmux_connect, &errstr)) == NULL) {
            fail_session(session, errstr);
            return;
        }
        session->connect_sock->data = session;
        return;
    }

    struct st_wtmoq_backend_t *backend = create_backend(session);
    if (quicly_connect(&qc, &session->tctx->quic, session->relay->host, selected->ai_addr, NULL, &ctx->http3.next_cid,
                       ptls_iovec_init(NULL, 0), &backend->handshake_properties, NULL, NULL) != 0) {
        free(backend);
        fail_session(session, "failed to connect to backend");
        return;
    }
    ++ctx->http3.next_cid.master_id;
    h2o_quic_setup(&backend->super, qc, NULL);
    session->backend = backend;
    h2o_quic_send(&backend->super);
}

static void cancel_connect(struct st_wtmoq_session_t *session)
{
    if (session->getaddr_req != NULL) {
        h2o_hostinfo_getaddr_cancel(session->getaddr_req);
        session->getaddr_req = NULL;
    }
    if (session->connect_sock != NULL) {
        h2o_socket_close(session->connect_sock);
        session->connect_sock = NULL;
    }
}

static void on_connect_timeout(h2o_timer_t *timer)
{
    struct st_wtmoq_session_t *session = H2O_STRUCT_FROM_MEMBER(struct st_wtmoq_session_t, connect_timeout, timer);

    cancel_connect(session);
    fail_session(session, "backend connection timeout");
}

/* datagrams */

/**
 * returns if a DATAGRAM frame carrying `payload_len` bytes is acceptable to the peer of `conn`, i.e., does not exceed its
 * max_datagram_frame_size; a peer that has not advertised the transport parameter accepts none
 */
static int datagram_is_acceptable(quicly_conn_t *conn, size_t payload_len)
{
    return quicly_datagram_frame_capacity(ptls_iovec_init(NULL, payload_len)) <=
           quicly_get_remote_transport_parameters(conn)->max_datagram_frame_size;
}

/**
 * called by the HTTP/3 layer for the datagrams of the session sent by the client, without the Quarter Stream ID
 */
static void forward_datagrams_to_backend(struct st_wtmoq_session_t *session, h2o_iovec_t *datagrams, size_t num_datagrams)
{
    struct st_wtmoq_backend_t *backend = session->backend;

    if (!session->established || session->terminated || backend == NULL)
        return;

    for (size_t i = 0; i != num_datagrams; ++i) {
        if (!datagram_is_acceptable(backend->super.quic, datagrams[i].len))
            continue;
        ptls_iovec_t payload = ptls_iovec_init(datagrams[i].base, datagrams[i].len);
        quicly_send_datagram_frames(backend->super.quic, &payload, 1);
    }
    h2o_quic_schedule_timer(&backend->super);
}

static void on_frontend_datagram(h2o_req_t *req, h2o_iovec_t *datagrams, size_t num_datagrams)
{
    forward_datagrams_to_backend(req->write_req.ctx, datagrams, num_datagrams);
}

/**
 * quicly's receive_datagram_frame callback of the backend connections
 */
static void on_backend_datagram(quicly_receive_datagram_frame_t *self, quicly_conn_t *quic, ptls_iovec_t payload)
{
    struct st_wtmoq_backend_t *backend = *quicly_get_data(quic);
    struct st_wtmoq_session_t *session = backend->session;

    if (session == NULL || !session->established || session->terminated)
        return;
    session->frontend_cb->send_datagram(session, payload);
}

static void wt_send_datagram(struct st_wtmoq_session_t *session, ptls_iovec_t payload)
{
    /* `forward_datagram.read_` is set by the HTTP/3 layer once the 2xx has been sent, if the client accepts HTTP datagrams */
    if (session->req->forward_datagram.read_ == NULL)
        return;
    /* the HTTP/3 layer prepends the Quarter Stream ID (RFC 9297) */
    if (!datagram_is_acceptable(session->frontend, quicly_encodev_capacity(session->session_id / 4) + payload.len))
        return;

    h2o_iovec_t vec = h2o_iovec_init(payload.base, payload.len);
    session->req->forward_datagram.read_(session->req, &vec, 1);
}

/* the session */

static void dispose_session(struct st_wtmoq_session_t *session)
{
    if (session->disposed)
        return;
    session->disposed = 1;

    cancel_connect(session);
    h2o_timer_unlink(&session->connect_timeout);

    /* terminate the streams on the client connection; the backend ones are destroyed with the connection */
    terminate_session_streams(session);
    while (!h2o_linklist_is_empty(&session->pairs)) {
        struct st_wtmoq_pair_t *pair = H2O_STRUCT_FROM_MEMBER(struct st_wtmoq_pair_t, link, session->pairs.next);
        h2o_linklist_unlink(&pair->link);
        pair->session = NULL;
    }

    close_backend(session, 0, "");

    h2o_buffer_dispose(&session->capsules);
    h2o_buffer_dispose(&session->resp.pending);
    h2o_buffer_dispose(&session->resp.inflight);
}

static void on_generator_stop(h2o_generator_t *_self, h2o_req_t *req)
{
    struct st_wtmoq_session_t *session = H2O_STRUCT_FROM_MEMBER(struct st_wtmoq_session_t, super, _self);
    dispose_session(session);
}

static void on_session_dispose(void *_session)
{
    dispose_session(_session);
}

/**
 * selects the first of the subprotocols offered in WT-Available-Protocols (a Structured Fields List of Strings) that is supported
 */
static const char *select_protocol(h2o_req_t *req)
{
    ssize_t index;
    if ((index = h2o_find_header_by_str(&req->headers, H2O_STRLIT("wt-available-protocols"), -1)) == -1)
        return NULL;
    h2o_iovec_t value = req->headers.entries[index].value;
    const char *p = value.base, *end = p + value.len;

    while (p < end) {
        /* skip OWS and commas, then read a string, ignoring parameters */
        while (p < end && (*p == ' ' || *p == '\t' || *p == ','))
            ++p;
        if (p == end || *p != '"')
            return NULL;
        const char *start = ++p;
        while (p < end && *p != '"') {
            if (*p == '\\')
                return NULL; /* escapes are never used by the supported protocols */
            ++p;
        }
        if (p == end)
            return NULL;
        size_t len = p++ - start;
        for (const char **s = supported_protocols; *s != NULL; ++s)
            if (h2o_memis(start, len, *s, strlen(*s)))
                return *s;
        while (p < end && *p != ',')
            ++p;
    }
    return NULL;
}

static size_t wt_encode_stream_header(struct st_wtmoq_session_t *session, uint8_t *dst, int unidirectional)
{
    uint8_t *p = dst;
    p = quicly_encodev(p, unidirectional ? WT_STREAM_TYPE_UNI : WT_SIGNAL_BIDI);
    p = quicly_encodev(p, session->session_id);
    return p - dst;
}

static uint64_t wt_error_from_client(uint64_t code)
{
    return error_from_http3(code);
}

static uint64_t wt_error_to_client(uint64_t code)
{
    return error_to_http3(code <= UINT32_MAX ? (uint32_t)code : 0);
}

static const struct st_wtmoq_frontend_t wt_frontend = {
    wt_encode_stream_header, wt_error_from_client, wt_error_to_client, wt_on_established, wt_on_connect_failed, wt_close,
    wt_send_datagram};

/**
 * initializes the fields of the session that do not depend on the frontend
 */
static void init_session(struct st_wtmoq_session_t *session)
{
    h2o_linklist_init_anchor(&session->pairs);
    h2o_buffer_init(&session->capsules, &h2o_socket_buffer_prototype);
    h2o_buffer_init(&session->resp.pending, &h2o_socket_buffer_prototype);
    h2o_buffer_init(&session->resp.inflight, &h2o_socket_buffer_prototype);
    h2o_timer_init(&session->connect_timeout, on_connect_timeout);
}

/**
 * starts connecting to the relay
 */
static void connect_backend(struct st_wtmoq_session_t *session, h2o_context_t *ctx)
{
    const struct st_wtmoq_relay_t *relay = session->relay;

    h2o_timer_link(ctx->loop, CONNECT_TIMEOUT, &session->connect_timeout);
    session->getaddr_req = h2o_hostinfo_getaddr(
        &ctx->receivers.hostinfo_getaddr, h2o_iovec_init(relay->host, strlen(relay->host)), relay->port, AF_UNSPEC,
        relay->qmux_cleartext ? SOCK_STREAM : SOCK_DGRAM, relay->qmux_cleartext ? IPPROTO_TCP : IPPROTO_UDP,
        AI_ADDRCONFIG | AI_NUMERICSERV, on_getaddr, session);
}

static int on_req(h2o_handler_t *_handler, h2o_req_t *req)
{
    struct st_wtmoq_handler_t *handler = (void *)_handler;

    /* only WebTransport sessions are handled */
    if (!(h2o_memis(req->method.base, req->method.len, H2O_STRLIT("CONNECT")) && req->upgrade.base != NULL &&
          h2o_lcstris(req->upgrade.base, req->upgrade.len, H2O_STRLIT("webtransport"))))
        return -1;
    if (req->open_extended_http3 == NULL) {
        h2o_send_error_generic(req, 501, "Not Implemented", "WebTransport is supported only over HTTP/3", 0);
        return 0;
    }

    const char *protocol;
    if ((protocol = select_protocol(req)) == NULL) {
        h2o_send_error_400(req, "Bad Request", "no supported subprotocol", 0);
        return 0;
    }

    struct st_wtmoq_session_t *session = h2o_mem_alloc_shared(&req->pool, sizeof(*session), on_session_dispose);
    *session = (struct st_wtmoq_session_t){
        .super = {.proceed = on_generator_proceed, .stop = on_generator_stop},
        .frontend_cb = &wt_frontend,
        .req = req,
        .relay = &handler->relay,
        .tctx = h2o_context_get_handler_context(req->conn->ctx, &handler->super),
        .session_id = req->conn->callbacks->get_req_id(req),
        .protocol = protocol,
    };
    init_session(session);

    /* capsules are not read until the session is established; datagrams are not received until the 2xx is sent */
    req->write_req.cb = on_write_req;
    req->write_req.ctx = session;
    req->forward_datagram.write_ = on_frontend_datagram;

    /* extend the connection; there can be one session per connection */
    h2o_quic_conn_t *frontend;
    if ((frontend = req->open_extended_http3(req, on_frontend_stream_open)) == NULL) {
        h2o_send_error_generic(req, 409, "Conflict", "WebTransport session already exists on the connection", 0);
        return 0;
    }
    session->frontend = frontend->quic;

    connect_backend(session, req->conn->ctx);
    return 0;
}

/* per-thread context */

static struct st_wtmoq_thread_ctx_t *create_thread_ctx(h2o_context_t *ctx)
{
#if H2O_USE_LIBUV
    h2o_fatal("webtransport.moq: no support for libuv");
#else
    struct st_wtmoq_thread_ctx_t *tctx = h2o_mem_alloc(sizeof(*tctx));

    tctx->ctx = ctx;

    /* TLS; the certificate of the relay is not verified in the MVP */
    tctx->tls = (ptls_context_t){
        .random_bytes = ptls_openssl_random_bytes,
        .get_time = &ptls_get_time,
        .key_exchanges = ptls_openssl_key_exchanges,
        .cipher_suites = ptls_openssl_cipher_suites,
    };
    quicly_amend_ptls_context(&tctx->tls);

    /* QUIC */
    tctx->quic = quicly_spec_context;
    tctx->quic.tls = &tctx->tls;
    tctx->quic.transport_params.max_streams_uni = MAX_STREAMS;
    tctx->quic.transport_params.max_streams_bidi = MAX_STREAMS;
    tctx->quic.transport_params.max_stream_data.uni = STREAM_WINDOW;
    tctx->quic.transport_params.max_stream_data.bidi_local = STREAM_WINDOW;
    tctx->quic.transport_params.max_stream_data.bidi_remote = STREAM_WINDOW;
    tctx->quic.transport_params.max_data = MAX_STREAMS * STREAM_WINDOW;
    uint8_t cid_key[PTLS_SHA256_DIGEST_SIZE];
    ptls_openssl_random_bytes(cid_key, sizeof(cid_key));
    tctx->quic.cid_encryptor = quicly_new_default_cid_encryptor(&ptls_openssl_quiclb, &ptls_openssl_aes128ecb, &ptls_openssl_sha256,
                                                                ptls_iovec_init(cid_key, sizeof(cid_key)));
    ptls_clear_memory(cid_key, sizeof(cid_key));
    tctx->quic.transport_params.max_datagram_frame_size = MAX_DATAGRAM_FRAME_SIZE;
    tctx->stream_open = (quicly_stream_open_t){on_backend_stream_open};
    tctx->quic.stream_open = &tctx->stream_open;
    tctx->receive_datagram_frame = (quicly_receive_datagram_frame_t){on_backend_datagram};
    tctx->quic.receive_datagram_frame = &tctx->receive_datagram_frame;
    tctx->quic.qmux_writable = &h2o_quic_qmux_writable;
    tctx->quic.qmux_log_state = &h2o_quic_qmux_log_state;

    /* sockets */
    h2o_socket_t *socks[2] = {NULL, NULL}, **sp = socks;
    if ((*sp = h2o_quic_create_client_socket(ctx->loop, AF_INET, ctx->globalconf->http3.client_socket.sndbuf,
                                             ctx->globalconf->http3.client_socket.rcvbuf)) != NULL)
        ++sp;
    if ((*sp = h2o_quic_create_client_socket(ctx->loop, AF_INET6, ctx->globalconf->http3.client_socket.sndbuf,
                                             ctx->globalconf->http3.client_socket.rcvbuf)) != NULL)
        ++sp;
    if (sp == socks)
        h2o_fatal("webtransport.moq: failed to create a UDP socket");
    h2o_quic_init_context(&tctx->quic_ctx, ctx->loop, socks[0], socks[1], &tctx->quic, &ctx->http3.next_cid, NULL,
                          on_backend_update, 0, NULL);

    return tctx;
#endif
}

static void destroy_thread_ctx(struct st_wtmoq_thread_ctx_t *tctx)
{
    h2o_quic_dispose_context(&tctx->quic_ctx);
    quicly_free_default_cid_encryptor(tctx->quic.cid_encryptor);
    free(tctx);
}

static void on_context_init(h2o_handler_t *_handler, h2o_context_t *ctx)
{
    h2o_context_set_handler_context(ctx, _handler, create_thread_ctx(ctx));
}

static void on_context_dispose(h2o_handler_t *_handler, h2o_context_t *ctx)
{
    destroy_thread_ctx(h2o_context_get_handler_context(ctx, _handler));
}

static void init_relay(struct st_wtmoq_relay_t *relay, h2o_iovec_t host, uint16_t port, int qmux_cleartext)
{
    relay->host = h2o_strdup(NULL, host.base, host.len).base;
    relay->port.base = h2o_mem_alloc(sizeof(H2O_UINT16_LONGEST_STR));
    relay->port.len = sprintf(relay->port.base, "%" PRIu16, port);
    relay->qmux_cleartext = qmux_cleartext;
}

static void on_handler_dispose(h2o_handler_t *_handler)
{
    struct st_wtmoq_handler_t *handler = (void *)_handler;
    free(handler->relay.host);
    free(handler->relay.port.base);
}

void h2o_webtransport_moq_register(h2o_pathconf_t *pathconf, h2o_iovec_t host, uint16_t port, int qmux_cleartext)
{
    struct st_wtmoq_handler_t *handler = (void *)h2o_create_handler(pathconf, sizeof(*handler));

    handler->super.on_context_init = on_context_init;
    handler->super.on_context_dispose = on_context_dispose;
    handler->super.dispose = on_handler_dispose;
    handler->super.on_req = on_req;
    handler->super.supports_request_streaming = 1;
    init_relay(&handler->relay, host, port, qmux_cleartext);
}

/* native MoQ: the client speaks MoQ directly over QUIC, on a listener of its own */

struct st_h2o_webtransport_moq_native_t {
    struct st_wtmoq_relay_t relay;
};

/**
 * a QUIC connection accepted from a native client; carries one session
 */
struct st_wtmoq_native_conn_t {
    h2o_quic_conn_t super;
    /**
     * the session, or NULL if none has been set up
     */
    struct st_wtmoq_session_t *session;
    h2o_webtransport_moq_native_t *native;
    h2o_context_t *ctx;
    ptls_handshake_properties_t handshake_properties;
    /**
     * link in `native_conns`
     */
    h2o_linklist_t link;
};

/**
 * the native connections of the thread, closed when the server shuts down (see `h2o_webtransport_moq_native_request_shutdown`)
 */
static __thread h2o_linklist_t native_conns;
static __thread h2o_timer_t native_shutdown_timer;

/**
 * The per-thread QUIC client context used for connecting to the relays on behalf of the native clients. Created when the first
 * native client is accepted by the thread, and retained as long as the thread runs.
 */
static __thread struct st_wtmoq_thread_ctx_t *native_tctx;

static h2o_quic_conn_t *native_get_conn(struct st_wtmoq_session_t *session)
{
    return *quicly_get_data(session->frontend);
}

static size_t native_encode_stream_header(struct st_wtmoq_session_t *session, uint8_t *dst, int unidirectional)
{
    return 0;
}

static uint64_t native_map_error(uint64_t code)
{
    return code;
}

/**
 * opens the backend streams of the streams that the client has opened while the relay connection was being established
 */
static void native_on_established(struct st_wtmoq_session_t *session)
{
    for (h2o_linklist_t *l = session->pairs.next; l != &session->pairs;) {
        struct st_wtmoq_pair_t *pair = H2O_STRUCT_FROM_MEMBER(struct st_wtmoq_pair_t, link, l);
        l = l->next;
        if (!pair->backend_pending)
            continue;
        pair->backend_pending = 0;
        if (pair->frontend.quic == NULL)
            continue;
        if (open_backend_stream(pair, quicly_stream_is_unidirectional(pair->frontend.quic->stream_id)) != 0) {
            abort_half(&pair->frontend, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0));
            continue;
        }
        process_input(&pair->frontend);
    }
}

static void native_on_connect_failed(struct st_wtmoq_session_t *session, const char *errstr)
{
    /* MoQT's INTERNAL_ERROR */
    h2o_quic_close_connection(native_get_conn(session), QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0x1), errstr);
}

static void native_close(struct st_wtmoq_session_t *session, uint64_t code, const char *reason)
{
    h2o_quic_close_connection(native_get_conn(session), QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(code), reason);
}

static void native_send_datagram(struct st_wtmoq_session_t *session, ptls_iovec_t payload)
{
    if (!datagram_is_acceptable(session->frontend, payload.len))
        return;
    quicly_send_datagram_frames(session->frontend, &payload, 1);
    h2o_quic_schedule_timer(native_get_conn(session));
}

static const struct st_wtmoq_frontend_t native_frontend = {
    native_encode_stream_header, native_map_error,     native_map_error,    native_on_established,
    native_on_connect_failed,    native_close,         native_send_datagram};

/**
 * Sets up the session of a native connection and starts connecting to the relay, once the ALPN has been selected. It might not have
 * been when the connection is accepted, as the ClientHello can span more than one Initial packet (e.g., with a post-quantum key
 * share). Returns the session, or NULL if it cannot be set up yet.
 */
static struct st_wtmoq_session_t *native_start_session(struct st_wtmoq_native_conn_t *conn)
{
    quicly_conn_t *qc = conn->super.quic;

    if (conn->session != NULL)
        return conn->session;
    if (quicly_get_state(qc) >= QUICLY_STATE_CLOSING)
        return NULL;

    /* the ALPN is selected while handling the ClientHello (see `h2o_webtransport_moq_native_select_alpn`) */
    const char *alpn = ptls_get_negotiated_protocol(quicly_get_tls(qc)), *protocol = NULL;
    if (alpn != NULL)
        for (const char **s = supported_protocols; *s != NULL; ++s)
            if (strcmp(alpn, *s) == 0)
                protocol = *s;
    if (protocol == NULL) {
        /* the handshake has completed without the client offering an ALPN; MoQT's PROTOCOL_VIOLATION */
        if (quicly_connection_is_ready(qc))
            h2o_quic_close_connection(&conn->super, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0x3), "no MoQ ALPN");
        return NULL;
    }

    if (native_tctx == NULL)
        native_tctx = create_thread_ctx(conn->ctx);
    struct st_wtmoq_session_t *session = h2o_mem_alloc(sizeof(*session));
    *session = (struct st_wtmoq_session_t){
        .frontend_cb = &native_frontend,
        .relay = &conn->native->relay,
        .tctx = native_tctx,
        .frontend = qc,
        .protocol = protocol,
    };
    init_session(session);
    conn->session = session;
    connect_backend(session, conn->ctx);
    return session;
}

void h2o_webtransport_moq_native_on_conn_update(h2o_quic_ctx_t *qctx, h2o_quic_conn_t *conn)
{
    native_start_session((void *)conn);
}

/**
 * quicly's stream_open callback of the native connections; every stream the client opens is spliced to one opened toward the relay
 */
static quicly_error_t on_native_stream_open(quicly_stream_open_t *self, quicly_stream_t *qs)
{
    /* streams we open are set up by the caller of `quicly_open_stream` */
    if (quicly_stream_is_self_initiated(qs)) {
        qs->callbacks = &quicly_stream_noop_callbacks;
        qs->data = NULL;
        return 0;
    }

    struct st_wtmoq_native_conn_t *conn = *quicly_get_data(qs->conn);
    struct st_wtmoq_session_t *session = native_start_session(conn);

    if (session == NULL || session->terminated) {
        qs->callbacks = &quicly_stream_noop_callbacks;
        qs->data = NULL;
        quicly_request_stop(qs, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0));
        if (!quicly_stream_is_unidirectional(qs->stream_id))
            quicly_reset_stream(qs, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0));
        return 0;
    }

    /* The client opens its streams (e.g., the control stream) as soon as the handshake completes, possibly before the relay
     * connection is established. They are held until then; flow control bounds what is buffered. */
    struct st_wtmoq_pair_t *pair = create_pair(session);
    bind_half(&pair->frontend, qs);
    if (session->established) {
        if (open_backend_stream(pair, quicly_stream_is_unidirectional(qs->stream_id)) != 0)
            abort_half(&pair->frontend, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0));
    } else {
        pair->backend_pending = 1;
    }
    return 0;
}

static quicly_stream_open_t native_stream_open = {on_native_stream_open};

static void on_native_datagram(quicly_receive_datagram_frame_t *self, quicly_conn_t *quic, ptls_iovec_t payload)
{
    struct st_wtmoq_native_conn_t *conn = *quicly_get_data(quic);

    if (conn->session == NULL)
        return;
    h2o_iovec_t vec = h2o_iovec_init(payload.base, payload.len);
    forward_datagrams_to_backend(conn->session, &vec, 1);
}

static quicly_receive_datagram_frame_t native_receive_datagram_frame = {on_native_datagram};

/**
 * Called by quicly when the native connection enters the closing or draining state. Unless the session has already terminated
 * (i.e., we are closing the connection because the relay did), the client has ended it; the relay connection is closed with the
 * same application error code, as CLOSE_WEBTRANSPORT_SESSION is passed on.
 */
static void on_native_closed(quicly_closed_t *self, quicly_conn_t *quic)
{
    struct st_wtmoq_native_conn_t *conn = *quicly_get_data(quic);
    struct st_wtmoq_session_t *session;

    if (conn == NULL || (session = conn->session) == NULL || session->terminated)
        return;

    uint64_t code = 0;
    const char *reason = NULL;
    quicly_error_t err = quicly_get_close_reason(quic, NULL, &reason, NULL);
    if (QUICLY_ERROR_IS_QUIC_APPLICATION(err))
        code = QUICLY_ERROR_GET_ERROR_CODE(err);
    terminate_session_streams(session);
    close_backend(session, code, reason != NULL ? reason : "");
}

static quicly_closed_t native_closed = {on_native_closed};

static void on_native_destroy(h2o_quic_conn_t *_conn)
{
    struct st_wtmoq_native_conn_t *conn = (void *)_conn;

    if (conn->session != NULL) {
        dispose_session(conn->session);
        free(conn->session);
        conn->session = NULL;
    }
    if (h2o_linklist_is_linked(&conn->link))
        h2o_linklist_unlink(&conn->link);
    h2o_quic_dispose_conn(&conn->super);
    free(conn);
}

const h2o_quic_conn_callbacks_t H2O_WEBTRANSPORT_MOQ_NATIVE_CONN_CALLBACKS = {on_native_destroy};

h2o_webtransport_moq_native_t *h2o_webtransport_moq_native_create(h2o_iovec_t host, uint16_t port)
{
    h2o_webtransport_moq_native_t *native = h2o_mem_alloc(sizeof(*native));
    init_relay(&native->relay, host, port, 0);
    return native;
}

void h2o_webtransport_moq_native_amend_quicly_context(h2o_globalconf_t *conf, quicly_context_t *quic)
{
    /* as HTTP/3 does; in particular, a client might send ACK_FREQUENCY frames, which are a protocol violation unless negotiated */
    quic->transport_params.max_idle_timeout = conf->http3.idle_timeout;
    quic->transport_params.min_ack_delay_usec = conf->http3.allow_delayed_ack ? 0 : UINT64_MAX;
    quic->ack_frequency = conf->http3.ack_frequency;
    /* the stream limits and windows are those of the relay connections */
    quic->transport_params.max_streams_uni = MAX_STREAMS;
    quic->transport_params.max_streams_bidi = MAX_STREAMS;
    quic->transport_params.max_stream_data.uni = STREAM_WINDOW;
    quic->transport_params.max_stream_data.bidi_local = STREAM_WINDOW;
    quic->transport_params.max_stream_data.bidi_remote = STREAM_WINDOW;
    quic->transport_params.max_data = MAX_STREAMS * STREAM_WINDOW;
    quic->transport_params.max_datagram_frame_size = MAX_DATAGRAM_FRAME_SIZE;
    quic->stream_open = &native_stream_open;
    quic->receive_datagram_frame = &native_receive_datagram_frame;
    quic->closed = &native_closed;
}

int h2o_webtransport_moq_native_select_alpn(ptls_t *tls, const ptls_iovec_t *protocols, size_t num_protocols)
{
    /* the first of those offered by the client that is supported, as WT-Available-Protocols is handled */
    for (size_t i = 0; i != num_protocols; ++i)
        for (const char **s = supported_protocols; *s != NULL; ++s)
            if (h2o_memis(protocols[i].base, protocols[i].len, *s, strlen(*s)))
                return ptls_set_negotiated_protocol(tls, *s, strlen(*s));
    return PTLS_ALERT_NO_APPLICATION_PROTOCOL;
}

h2o_quic_conn_t *h2o_webtransport_moq_native_accept(h2o_webtransport_moq_native_t *native, h2o_context_t *ctx, h2o_quic_ctx_t *qctx,
                                                    quicly_address_t *destaddr, quicly_address_t *srcaddr,
                                                    quicly_decoded_packet_t *packet,
                                                    quicly_address_token_plaintext_t *address_token,
                                                    const h2o_quic_conn_callbacks_t *callbacks)
{
    struct st_wtmoq_native_conn_t *conn = h2o_mem_alloc(sizeof(*conn));
    quicly_conn_t *qc;

    *conn = (struct st_wtmoq_native_conn_t){.native = native, .ctx = ctx};
    h2o_quic_init_conn(&conn->super, qctx, callbacks);
    quicly_error_t ret = quicly_accept(&qc, qctx->quic, &destaddr->sa, &srcaddr->sa, packet, address_token, qctx->next_cid,
                                       &conn->handshake_properties, &conn->super);
    if (ret != 0) {
        free(conn);
        return ret == QUICLY_ERROR_DECRYPTION_FAILED ? &h2o_quic_accept_conn_decryption_failed : NULL;
    }
    ++qctx->next_cid->master_id;
    h2o_quic_setup(&conn->super, qc, NULL);
    if (native_conns.next == NULL)
        h2o_linklist_init_anchor(&native_conns);
    h2o_linklist_insert(&native_conns, &conn->link);

    native_start_session(conn);

    if (!h2o_quic_send(&conn->super))
        return &h2o_http3_accept_conn_closed.super;
    return &conn->super;
}

static void on_native_shutdown_timeout(h2o_timer_t *timer)
{
    for (h2o_linklist_t *l = native_conns.next; l != &native_conns;) {
        struct st_wtmoq_native_conn_t *conn = H2O_STRUCT_FROM_MEMBER(struct st_wtmoq_native_conn_t, link, l);
        l = l->next; /* closing might destroy the connection */
        h2o_quic_close_connection(&conn->super, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0), "shutting down");
    }
}

void h2o_webtransport_moq_native_request_shutdown(h2o_context_t *ctx)
{
    /* As HTTP/3 connections carrying WebTransport sessions are, native connections are closed once
     * `http3-graceful-shutdown-timeout` has passed, if it is set; there is no draining yet. */
    if (native_conns.next == NULL || h2o_linklist_is_empty(&native_conns) || ctx->globalconf->http3.graceful_shutdown_timeout == 0)
        return;
    h2o_timer_init(&native_shutdown_timer, on_native_shutdown_timeout);
    h2o_timer_link(ctx->loop, ctx->globalconf->http3.graceful_shutdown_timeout, &native_shutdown_timer);
}
