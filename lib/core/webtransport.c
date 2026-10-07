/*
 * Copyright (c) 2026 Fastly, Inc.
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
/*
 * This file implements the session / stream API of WebTransport on top of `h2o_req_t`, using the capsule protocol defined in
 * draft-ietf-webtrans-http2 (the "capsule backend"). The state machines mirror those of quicly; `quicly_sendstate_t` and
 * `quicly_recvstate_t` are used as-is, and the capsules being exchanged are the counterparts of the QUIC frames. Because the
 * capsules are delivered reliably and in order, data is never retransmitted, and a batch of capsules is considered acknowledged
 * once it is handed to the protocol layer (i.e., when the `proceed` callback of the generator is invoked).
 */
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "khash.h"
#include "h2o.h"
#include "h2o/webtransport.h"

/**
 * maximum size of the payload of control capsules being buffered (stream ID + error code + reliable size, each being a varint)
 */
#define MAX_CONTROL_CAPSULE_PAYLOAD 24
/**
 * maximum size of the datagrams being received or sent
 */
#define MAX_DATAGRAM_SIZE 65535
/**
 * maximum amount of datagrams queued while a batch is inflight; excess datagrams are dropped
 */
#define MAX_PENDING_DATAGRAM_BYTES 65536
/**
 * maximum amount of stream data being emitted at once for each stream
 */
#define MAX_STREAM_CHUNK_SIZE 16384
/**
 * a batch is closed when it becomes larger than this
 */
#define MAX_BATCH_SIZE 65536
/**
 * maximum number of streams (RFC 9000 section 4.6)
 */
#define MAX_STREAMS_LIMIT ((uint64_t)1 << 60)
/**
 * space being reserved in front of the stream data being emitted, for writing the WT_STREAM capsule header later
 */
#define STREAM_CAPSULE_HEADER_RESERVE (H2O_WEBTRANSPORT_MAX_CAPSULE_HEADER_SIZE + 8)
/**
 * internal error indicating that the application closed the session from within a callback
 */
#define ERROR_CLOSED_BY_APP ((quicly_error_t)0x2e7ff)

enum en_sender_state_t {
    SENDER_STATE_NONE,
    SENDER_STATE_SEND,
    SENDER_STATE_SENT,
};

struct st_capsule_stream_t {
    h2o_webtransport_stream_t super;
    struct {
        /**
         * limit set by the peer
         */
        uint64_t max_stream_data;
        /**
         * value of `max_stream_data` when WT_STREAM_DATA_BLOCKED was sent last, or UINT64_MAX
         */
        uint64_t blocked_sent_at;
        struct {
            enum en_sender_state_t state;
            uint64_t error_code;
        } reset;
        /**
         * if WT_STOP_SENDING has been received
         */
        unsigned stop_received : 1;
        /**
         * if the stream is locally initiated and its index is beyond the limit set by the peer
         */
        unsigned is_blocked : 1;
        /**
         * if WT_STREAM_DATA_BLOCKED is to be sent
         */
        unsigned send_blocked : 1;
        /**
         * linked to `egress.data_streams` when the stream has data to be sent
         */
        h2o_linklist_t data_link;
    } send_aux;
    struct {
        /**
         * number of bytes being received
         */
        uint64_t bytes_received;
        /**
         * limit being advertised to the peer
         */
        uint64_t max_stream_data;
        uint64_t window;
        struct {
            enum en_sender_state_t state;
            uint64_t error_code;
        } stop_sending;
        /**
         * set once the bytes that the application has not consumed are returned to the session-level credit (i.e., the stream has
         * been reset or destroyed)
         */
        unsigned credit_released : 1;
    } recv_aux;
    /**
     * linked to `egress.control_streams` when the stream has control capsules to be sent
     */
    h2o_linklist_t control_link;
};

KHASH_MAP_INIT_INT64(h2o_webtransport_capsule_stream, struct st_capsule_stream_t *)

struct st_capsule_inflight_t {
    quicly_stream_id_t stream_id;
    quicly_sendstate_sent_t args;
};

enum en_ingress_state_t {
    INGRESS_STATE_HEADER,
    INGRESS_STATE_STREAM_DATA,
    INGRESS_STATE_PAYLOAD,
    INGRESS_STATE_SKIP,
    /**
     * the session has ended; input is discarded
     */
    INGRESS_STATE_DISCARD,
};

struct st_capsule_session_t {
    h2o_webtransport_session_t super;
    h2o_generator_t generator;
    khash_t(h2o_webtransport_capsule_stream) * streams;
    /**
     * operations provided by the protocol layer, if the streams are carried natively; when set, `streams` is not used, and the
     * capsules other than those relating to the session (DATAGRAM, WT_CLOSE_SESSION, WT_DRAIN_SESSION) are ignored
     */
    const h2o_webtransport_native_t *native;
    /**
     * if the session has ended; once set, the application callbacks are not invoked other than `on_destroy` of the streams being
     * destroyed
     */
    unsigned closing : 1;
    /**
     * if `native->start` is yet to be called
     */
    unsigned native_start_pending : 1;
    struct {
        enum en_ingress_state_t state;
        /**
         * partial capsule header (type, length, and the stream ID of WT_STREAM)
         */
        uint8_t hdr[H2O_WEBTRANSPORT_MAX_CAPSULE_HEADER_SIZE + 8];
        size_t hdr_len;
        uint64_t type;
        uint64_t bytes_left;
        /**
         * the stream to which the payload of the WT_STREAM capsule being received is delivered (or NULL if destroyed)
         */
        struct st_capsule_stream_t *stream;
        unsigned is_fin : 1;
        /**
         * if the request body that was received before the session was accepted is yet to be processed
         */
        unsigned initial_pending : 1;
        h2o_buffer_t *payload;
        struct {
            uint64_t advertised;
            /**
             * bytes received
             */
            uint64_t consumed;
            /**
             * bytes consumed by the application (or discarded)
             */
            uint64_t shifted;
            uint64_t window;
        } max_data;
        /**
         * streams initiated by the peer; indexed by `is_unidirectional`
         */
        struct {
            uint64_t next_index;
            uint64_t max;
            uint64_t num_closed;
            uint64_t window;
        } streams[2];
        /**
         * initial receive windows
         */
        struct {
            uint64_t bidi_local;
            uint64_t bidi_remote;
            uint64_t uni;
        } max_stream_data;
    } ingress;
    struct {
        /**
         * the batch being built or inflight
         */
        h2o_buffer_t *buf;
        /**
         * capsules (datagrams, WT_CLOSE_SESSION, WT_DRAIN_SESSION) to be appended to the next batch
         */
        h2o_buffer_t *pending;
        size_t pending_datagram_bytes;
        H2O_VECTOR(struct st_capsule_inflight_t) inflight;
        struct {
            uint64_t permitted;
            uint64_t sent;
            uint64_t blocked_sent_at;
            unsigned is_blocked : 1;
        } max_data;
        /**
         * streams initiated locally; indexed by `is_unidirectional`
         */
        struct {
            uint64_t next_index;
            uint64_t max;
            uint64_t blocked_sent_at;
        } streams[2];
        /**
         * initial send windows
         */
        struct {
            uint64_t bidi_local;
            uint64_t bidi_remote;
            uint64_t uni;
        } max_stream_data;
        h2o_linklist_t control_streams;
        h2o_linklist_t data_streams;
        h2o_timer_t timer;
        unsigned send_inflight : 1;
        /**
         * if the HTTP stream is to be reset
         */
        unsigned send_error : 1;
        /**
         * if the final (or error) response has been sent
         */
        unsigned final_sent : 1;
        /**
         * if the generator has been stopped
         */
        unsigned done : 1;
        unsigned drain_queued : 1;
        /**
         * if `on_drain` is to be invoked due to the server shutting down
         */
        unsigned shutdown_pending : 1;
        unsigned shutdown_notified : 1;
    } egress;
};

static const h2o_webtransport_backend_t capsule_backend, native_backend;

static void noop_on_destroy(h2o_webtransport_stream_t *stream, quicly_error_t err)
{
}

static void noop_on_send_shift(h2o_webtransport_stream_t *stream, size_t delta)
{
}

static void noop_on_send_emit(h2o_webtransport_stream_t *stream, size_t off, void *dst, size_t *len, int *wrote_all)
{
    assert(!"unexpected");
}

static void noop_on_send_stop(h2o_webtransport_stream_t *stream, quicly_error_t err)
{
}

static void noop_on_receive(h2o_webtransport_stream_t *stream, size_t off, const void *src, size_t len)
{
}

static void noop_on_receive_reset(h2o_webtransport_stream_t *stream, quicly_error_t err)
{
}

static const h2o_webtransport_stream_callbacks_t noop_stream_callbacks = {
    noop_on_destroy, noop_on_send_shift, noop_on_send_emit, noop_on_send_stop, noop_on_receive, noop_on_receive_reset};

static struct st_capsule_session_t *get_session(h2o_webtransport_stream_t *stream)
{
    return (struct st_capsule_session_t *)stream->session;
}

static uint64_t max_u64(uint64_t x, uint64_t y)
{
    return x > y ? x : y;
}

/**
 * Determines the credit to be advertised. A new value is sent when at least half of the window has been consumed.
 */
static int should_update_credit(uint64_t advertised, uint64_t consumed, uint64_t window, uint64_t *new_value)
{
    uint64_t v = consumed + window;
    if (v <= advertised || v - advertised < (window + 1) / 2)
        return 0;
    *new_value = v;
    return 1;
}

static void schedule_send(struct st_capsule_session_t *sess)
{
    if (sess->egress.done || sess->egress.final_sent || h2o_timer_is_linked(&sess->egress.timer))
        return;
    h2o_timer_link(sess->super.req->conn->ctx->loop, 0, &sess->egress.timer);
}

static void schedule_control(struct st_capsule_stream_t *stream)
{
    struct st_capsule_session_t *sess = get_session(&stream->super);
    if (!h2o_linklist_is_linked(&stream->control_link))
        h2o_linklist_insert(&sess->egress.control_streams, &stream->control_link);
    schedule_send(sess);
}

static void schedule_data(struct st_capsule_stream_t *stream)
{
    struct st_capsule_session_t *sess = get_session(&stream->super);
    quicly_sendstate_t *ss = &stream->super.sendstate;
    int has_data =
        ss->pending.num_ranges != 0 || (!quicly_sendstate_is_open(ss) && ss->eos_state == QUICLY_SENDSTATE_EOS_STATE_UNSENT);
    if (!has_data || stream->send_aux.reset.state != SENDER_STATE_NONE || stream->send_aux.is_blocked ||
        h2o_linklist_is_linked(&stream->send_aux.data_link))
        return;
    h2o_linklist_insert(&sess->egress.data_streams, &stream->send_aux.data_link);
    schedule_send(sess);
}

static int should_send_max_stream_data(struct st_capsule_stream_t *stream, uint64_t *new_value)
{
    if (!h2o_webtransport_stream_has_receive_side(&stream->super) || stream->super.recvstate.eos != UINT64_MAX ||
        quicly_recvstate_transfer_complete(&stream->super.recvstate) || stream->recv_aux.stop_sending.state != SENDER_STATE_NONE)
        return 0;
    return should_update_credit(stream->recv_aux.max_stream_data, stream->super.recvstate.data_off, stream->recv_aux.window,
                                new_value);
}

static int should_send_max_data(struct st_capsule_session_t *sess, uint64_t *new_value)
{
    return should_update_credit(sess->ingress.max_data.advertised, sess->ingress.max_data.shifted, sess->ingress.max_data.window,
                                new_value);
}

static int should_send_max_streams(struct st_capsule_session_t *sess, int uni, uint64_t *new_value)
{
    return should_update_credit(sess->ingress.streams[uni].max, sess->ingress.streams[uni].num_closed,
                                sess->ingress.streams[uni].window, new_value);
}

static struct st_capsule_stream_t *find_stream(struct st_capsule_session_t *sess, quicly_stream_id_t stream_id)
{
    khiter_t iter = kh_get(h2o_webtransport_capsule_stream, sess->streams, stream_id);
    return iter != kh_end(sess->streams) ? kh_val(sess->streams, iter) : NULL;
}

static struct st_capsule_stream_t *create_stream(struct st_capsule_session_t *sess, quicly_stream_id_t stream_id)
{
    struct st_capsule_stream_t *stream = h2o_mem_alloc(sizeof(*stream));
    int is_local = h2o_webtransport_stream_is_server_initiated(stream_id),
        uni = h2o_webtransport_stream_is_unidirectional(stream_id);

    *stream = (struct st_capsule_stream_t){{&sess->super, stream_id, &noop_stream_callbacks}};
    stream->send_aux.blocked_sent_at = UINT64_MAX;

    /* setup send side; the limits are those advertised by the peer (i.e., `bidi_local` applies to the streams opened by the peer)
     */
    if (h2o_webtransport_stream_has_send_side(&stream->super)) {
        quicly_sendstate_init(&stream->super.sendstate);
        stream->send_aux.max_stream_data = uni        ? sess->egress.max_stream_data.uni
                                           : is_local ? sess->egress.max_stream_data.bidi_remote
                                                      : sess->egress.max_stream_data.bidi_local;
    } else {
        quicly_sendstate_init_closed(&stream->super.sendstate);
    }

    /* setup receive side; the limits are those that we advertised */
    if (h2o_webtransport_stream_has_receive_side(&stream->super)) {
        quicly_recvstate_init(&stream->super.recvstate);
        stream->recv_aux.window = uni        ? sess->ingress.max_stream_data.uni
                                  : is_local ? sess->ingress.max_stream_data.bidi_local
                                             : sess->ingress.max_stream_data.bidi_remote;
        stream->recv_aux.max_stream_data = stream->recv_aux.window;
    } else {
        quicly_recvstate_init_closed(&stream->super.recvstate);
        stream->recv_aux.credit_released = 1;
    }

    int r;
    khiter_t iter = kh_put(h2o_webtransport_capsule_stream, sess->streams, stream_id, &r);
    assert(r > 0);
    kh_val(sess->streams, iter) = stream;

    return stream;
}

static void release_recv_credit(struct st_capsule_session_t *sess, struct st_capsule_stream_t *stream)
{
    if (stream->recv_aux.credit_released)
        return;
    stream->recv_aux.credit_released = 1;
    sess->ingress.max_data.shifted += stream->recv_aux.bytes_received - stream->super.recvstate.data_off;
}

static void destroy_stream(struct st_capsule_stream_t *stream, quicly_error_t err)
{
    struct st_capsule_session_t *sess = get_session(&stream->super);
    khiter_t iter = kh_get(h2o_webtransport_capsule_stream, sess->streams, stream->super.stream_id);
    uint64_t unused;

    assert(iter != kh_end(sess->streams));
    kh_del(h2o_webtransport_capsule_stream, sess->streams, iter);
    if (sess->ingress.stream == stream)
        sess->ingress.stream = NULL;
    if (h2o_linklist_is_linked(&stream->send_aux.data_link))
        h2o_linklist_unlink(&stream->send_aux.data_link);
    if (h2o_linklist_is_linked(&stream->control_link))
        h2o_linklist_unlink(&stream->control_link);

    /* return credit */
    release_recv_credit(sess, stream);
    if (!h2o_webtransport_stream_is_server_initiated(stream->super.stream_id)) {
        int uni = h2o_webtransport_stream_is_unidirectional(stream->super.stream_id);
        ++sess->ingress.streams[uni].num_closed;
        if (should_send_max_streams(sess, uni, &unused))
            schedule_send(sess);
    }
    if (should_send_max_data(sess, &unused))
        schedule_send(sess);

    stream->super.callbacks->on_destroy(&stream->super, err);

    quicly_sendstate_dispose(&stream->super.sendstate);
    quicly_recvstate_dispose(&stream->super.recvstate);
    free(stream);
}

static int stream_is_destroyable(struct st_capsule_stream_t *stream)
{
    return quicly_recvstate_transfer_complete(&stream->super.recvstate) &&
           quicly_sendstate_transfer_complete(&stream->super.sendstate) && stream->send_aux.reset.state != SENDER_STATE_SEND;
}

static void destroy_stream_if_possible(struct st_capsule_stream_t *stream)
{
    if (stream_is_destroyable(stream))
        destroy_stream(stream, 0);
}

static void destroy_all_streams(struct st_capsule_session_t *sess, quicly_error_t err)
{
    /* the streams are destroyed one by one, as `on_destroy` might destroy other streams (e.g., by closing the session) */
    while (kh_size(sess->streams) != 0) {
        struct st_capsule_stream_t *stream;
        kh_foreach_value(sess->streams, stream, {
            destroy_stream(stream, err);
            break;
        });
    }
}

/**
 * Ends the session. When `notify` is set, `on_close` is invoked.
 */
static void terminate(struct st_capsule_session_t *sess, quicly_error_t err, h2o_iovec_t reason, int notify)
{
    if (sess->closing)
        return;
    sess->closing = 1;

    /* discard what is no longer needed, then destroy the streams */
    sess->ingress.state = INGRESS_STATE_DISCARD;
    sess->ingress.stream = NULL;
    if (sess->native != NULL)
        sess->native->detach(&sess->super);
    destroy_all_streams(sess, H2O_WEBTRANSPORT_ERROR_SESSION_GONE);
    schedule_send(sess);

    if (notify)
        sess->super.callbacks->on_close(&sess->super, err, reason);
}

static void session_error(struct st_capsule_session_t *sess, quicly_error_t err)
{
    if (sess->closing)
        return;
    sess->egress.send_error = 1;
    terminate(sess, err, h2o_iovec_init(NULL, 0), 1);
}

static void reset_stream_core(struct st_capsule_stream_t *stream, uint64_t error_code)
{
    /* once FIN has been sent, WT_RESET_STREAM cannot be sent, as capsules are delivered in order */
    if (stream->send_aux.reset.state != SENDER_STATE_NONE || stream->super.sendstate.eos_state != QUICLY_SENDSTATE_EOS_STATE_UNSENT)
        return;

    /* the bytes that have been sent are delivered, as the capsules are; the Reliable Size of WT_RESET_STREAM is therefore
     * `size_inflight`, but the sendstate is reset with zero, as there is nothing left to retransmit */
    if (quicly_sendstate_reset(&stream->super.sendstate, error_code, 0) != 0)
        h2o_fatal("no memory");
    stream->send_aux.reset.state = SENDER_STATE_SEND;
    stream->send_aux.reset.error_code = error_code;
    if (h2o_linklist_is_linked(&stream->send_aux.data_link))
        h2o_linklist_unlink(&stream->send_aux.data_link);
    schedule_control(stream);
}

static void request_stop_core(struct st_capsule_stream_t *stream, uint64_t error_code)
{
    if (stream->recv_aux.stop_sending.state != SENDER_STATE_NONE || stream->super.recvstate.eos != UINT64_MAX ||
        quicly_recvstate_transfer_complete(&stream->super.recvstate))
        return;

    stream->recv_aux.stop_sending.state = SENDER_STATE_SEND;
    stream->recv_aux.stop_sending.error_code = error_code;
    schedule_control(stream);
}

/**
 * Invokes `on_stream_open`. Returns zero if successful, ERROR_CLOSED_BY_APP if the application closed the session, or an error
 * that closes the session.
 */
static quicly_error_t open_peer_stream(struct st_capsule_session_t *sess, quicly_stream_id_t stream_id)
{
    struct st_capsule_stream_t *stream = create_stream(sess, stream_id);
    quicly_error_t ret;

    if ((ret = sess->super.callbacks->on_stream_open(&stream->super)) != 0) {
        if (sess->closing)
            return ERROR_CLOSED_BY_APP;
        if (!QUICLY_ERROR_IS_QUIC_APPLICATION(ret))
            return ret;
        if (h2o_webtransport_stream_has_send_side(&stream->super))
            reset_stream_core(stream, QUICLY_ERROR_GET_ERROR_CODE(ret));
        if (h2o_webtransport_stream_has_receive_side(&stream->super))
            request_stop_core(stream, QUICLY_ERROR_GET_ERROR_CODE(ret));
    } else if (sess->closing) {
        return ERROR_CLOSED_BY_APP;
    }

    return 0;
}

/**
 * Looks up the stream identified by a capsule being received, opening the peer-initiated streams up to that ID if necessary.
 * `*stream` is set to NULL if the stream has already been destroyed.
 */
static quicly_error_t get_or_open_stream(struct st_capsule_session_t *sess, uint64_t stream_id, struct st_capsule_stream_t **stream)
{
    uint64_t index = stream_id >> 2;
    int uni = h2o_webtransport_stream_is_unidirectional(stream_id);
    quicly_error_t ret;

    if ((*stream = find_stream(sess, stream_id)) != NULL)
        return 0;

    /* locally-initiated stream; it is an error to refer to a stream that has not been opened */
    if (h2o_webtransport_stream_is_server_initiated(stream_id))
        return index < sess->egress.streams[uni].next_index ? 0 : H2O_WEBTRANSPORT_ERROR_STREAM_STATE;

    /* peer-initiated stream; open the stream as well as the ones with smaller IDs */
    if (index < sess->ingress.streams[uni].next_index)
        return 0;
    if (index >= sess->ingress.streams[uni].max)
        return H2O_WEBTRANSPORT_ERROR_FLOW_CONTROL;
    do {
        uint64_t next_id = sess->ingress.streams[uni].next_index++ << 2 | (uint64_t)uni << 1;
        if ((ret = open_peer_stream(sess, (quicly_stream_id_t)next_id)) != 0)
            return ret;
    } while (sess->ingress.streams[uni].next_index <= index);

    *stream = find_stream(sess, stream_id);
    return 0;
}

static quicly_error_t deliver_stream_data(struct st_capsule_session_t *sess, const uint8_t *src, size_t len, int is_fin)
{
    struct st_capsule_stream_t *stream = sess->ingress.stream;
    quicly_error_t ret;

    if (stream == NULL)
        return 0;

    uint64_t off = stream->recv_aux.bytes_received, apply_off = off;
    size_t apply_len = len;
    if ((ret = quicly_recvstate_update(&stream->super.recvstate, &apply_off, &apply_len, is_fin, 1)) != 0)
        return H2O_WEBTRANSPORT_ERROR_PROTOCOL;
    stream->recv_aux.bytes_received += len;

    if (apply_len != 0 || quicly_recvstate_transfer_complete(&stream->super.recvstate)) {
        uint64_t buf_offset = apply_off - stream->super.recvstate.data_off;
        stream->super.callbacks->on_receive(&stream->super, (size_t)buf_offset, src + (apply_off - off), apply_len);
        if (sess->closing)
            return ERROR_CLOSED_BY_APP;
        if ((stream = sess->ingress.stream) == NULL)
            return 0;
    }

    destroy_stream_if_possible(stream);
    return 0;
}

static quicly_error_t begin_stream_capsule(struct st_capsule_session_t *sess, uint64_t stream_id, uint64_t length, int is_fin)
{
    struct st_capsule_stream_t *stream;
    quicly_error_t ret;

    if ((ret = get_or_open_stream(sess, stream_id, &stream)) != 0)
        return ret;
    if (stream == NULL || !h2o_webtransport_stream_has_receive_side(&stream->super) || stream->super.recvstate.eos != UINT64_MAX ||
        quicly_recvstate_transfer_complete(&stream->super.recvstate))
        return H2O_WEBTRANSPORT_ERROR_STREAM_STATE;

    /* check flow control, and account the entire payload */
    if (stream->recv_aux.bytes_received + length > stream->recv_aux.max_stream_data)
        return H2O_WEBTRANSPORT_ERROR_FLOW_CONTROL;
    if (sess->ingress.max_data.consumed + length > sess->ingress.max_data.advertised)
        return H2O_WEBTRANSPORT_ERROR_FLOW_CONTROL;
    sess->ingress.max_data.consumed += length;

    sess->ingress.stream = stream;
    sess->ingress.is_fin = is_fin;
    sess->ingress.bytes_left = length;

    if (length != 0) {
        sess->ingress.state = INGRESS_STATE_STREAM_DATA;
        return 0;
    }
    return is_fin ? deliver_stream_data(sess, (const uint8_t *)"", 0, 1) : 0;
}

static int is_valid_error_code(uint64_t code)
{
    return code <= UINT32_MAX;
}

static quicly_error_t handle_reset_stream(struct st_capsule_session_t *sess, h2o_iovec_t payload)
{
    uint64_t fields[3];
    struct st_capsule_stream_t *stream;
    quicly_error_t ret;

    if (h2o_webtransport_decode_varint_capsule(payload, fields, 3) != 0 || !is_valid_error_code(fields[1]))
        return H2O_WEBTRANSPORT_ERROR_PROTOCOL;
    if ((ret = get_or_open_stream(sess, fields[0], &stream)) != 0)
        return ret;
    if (stream == NULL || !h2o_webtransport_stream_has_receive_side(&stream->super) ||
        quicly_recvstate_transfer_complete(&stream->super.recvstate))
        return H2O_WEBTRANSPORT_ERROR_STREAM_STATE;
    /* as capsules are delivered in order, reliable size must be equal to the amount of data being received */
    if (fields[2] != stream->recv_aux.bytes_received)
        return H2O_WEBTRANSPORT_ERROR_STREAM_STATE;

    uint64_t bytes_missing;
    if (quicly_recvstate_reset(&stream->super.recvstate, stream->recv_aux.bytes_received, stream->recv_aux.bytes_received,
                               fields[1], &bytes_missing) != 0)
        return H2O_WEBTRANSPORT_ERROR_STREAM_STATE;
    assert(bytes_missing == 0);
    release_recv_credit(sess, stream);
    stream->super.callbacks->on_receive_reset(&stream->super, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(fields[1]));
    if (sess->closing)
        return ERROR_CLOSED_BY_APP;

    if ((stream = find_stream(sess, (quicly_stream_id_t)fields[0])) != NULL)
        destroy_stream_if_possible(stream);
    return 0;
}

static quicly_error_t handle_stop_sending(struct st_capsule_session_t *sess, h2o_iovec_t payload)
{
    uint64_t fields[2];
    struct st_capsule_stream_t *stream;
    quicly_error_t ret;

    if (h2o_webtransport_decode_varint_capsule(payload, fields, 2) != 0 || !is_valid_error_code(fields[1]))
        return H2O_WEBTRANSPORT_ERROR_PROTOCOL;
    if (h2o_webtransport_stream_is_unidirectional(fields[0]) && !h2o_webtransport_stream_is_server_initiated(fields[0]))
        return H2O_WEBTRANSPORT_ERROR_STREAM_STATE;
    if ((ret = get_or_open_stream(sess, fields[0], &stream)) != 0)
        return ret;
    /* the stream might have been closed while the capsule was inflight */
    if (stream == NULL)
        return 0;
    if (stream->send_aux.stop_received)
        return H2O_WEBTRANSPORT_ERROR_STREAM_STATE;
    stream->send_aux.stop_received = 1;

    /* like quicly, reset the stream and then notify the application */
    if (quicly_sendstate_is_open(&stream->super.sendstate)) {
        quicly_error_t err = QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(fields[1]);
        reset_stream_core(stream, fields[1]);
        stream->super.callbacks->on_send_stop(&stream->super, err);
        if (sess->closing)
            return ERROR_CLOSED_BY_APP;
        if ((stream = find_stream(sess, (quicly_stream_id_t)fields[0])) == NULL)
            return 0;
    }

    destroy_stream_if_possible(stream);
    return 0;
}

static quicly_error_t handle_max_stream_data(struct st_capsule_session_t *sess, h2o_iovec_t payload)
{
    uint64_t fields[2];
    struct st_capsule_stream_t *stream;
    quicly_error_t ret;

    if (h2o_webtransport_decode_varint_capsule(payload, fields, 2) != 0)
        return H2O_WEBTRANSPORT_ERROR_PROTOCOL;
    if (h2o_webtransport_stream_is_unidirectional(fields[0]) && !h2o_webtransport_stream_is_server_initiated(fields[0]))
        return H2O_WEBTRANSPORT_ERROR_STREAM_STATE;
    if ((ret = get_or_open_stream(sess, fields[0], &stream)) != 0)
        return ret;
    if (stream == NULL)
        return 0;
    if (stream->send_aux.stop_received)
        return H2O_WEBTRANSPORT_ERROR_STREAM_STATE;
    if (fields[1] < stream->send_aux.max_stream_data)
        return H2O_WEBTRANSPORT_ERROR_FLOW_CONTROL;

    if (fields[1] > stream->send_aux.max_stream_data) {
        stream->send_aux.max_stream_data = fields[1];
        schedule_data(stream);
    }
    return 0;
}

static quicly_error_t handle_stream_data_blocked(struct st_capsule_session_t *sess, h2o_iovec_t payload)
{
    uint64_t fields[2];
    struct st_capsule_stream_t *stream;
    quicly_error_t ret;

    if (h2o_webtransport_decode_varint_capsule(payload, fields, 2) != 0)
        return H2O_WEBTRANSPORT_ERROR_PROTOCOL;
    if (h2o_webtransport_stream_is_unidirectional(fields[0]) && h2o_webtransport_stream_is_server_initiated(fields[0]))
        return H2O_WEBTRANSPORT_ERROR_STREAM_STATE;
    if ((ret = get_or_open_stream(sess, fields[0], &stream)) != 0)
        return ret;
    if (stream == NULL || stream->super.recvstate.eos != UINT64_MAX || quicly_recvstate_transfer_complete(&stream->super.recvstate))
        return H2O_WEBTRANSPORT_ERROR_STREAM_STATE;
    /* the credit is replenished as the application consumes data */
    return 0;
}

static void unblock_local_streams(struct st_capsule_session_t *sess, int uni)
{
    struct st_capsule_stream_t *stream;
    kh_foreach_value(sess->streams, stream, {
        if (stream->send_aux.is_blocked && h2o_webtransport_stream_is_unidirectional(stream->super.stream_id) == uni &&
            (uint64_t)stream->super.stream_id >> 2 < sess->egress.streams[uni].max) {
            stream->send_aux.is_blocked = 0;
            schedule_data(stream);
            if (h2o_linklist_is_linked(&stream->control_link))
                schedule_send(sess);
        }
    });
}

static quicly_error_t handle_max_streams(struct st_capsule_session_t *sess, int uni, h2o_iovec_t payload)
{
    uint64_t max;

    if (h2o_webtransport_decode_varint_capsule(payload, &max, 1) != 0)
        return H2O_WEBTRANSPORT_ERROR_PROTOCOL;
    if (max > MAX_STREAMS_LIMIT || max < sess->egress.streams[uni].max)
        return H2O_WEBTRANSPORT_ERROR_FLOW_CONTROL;

    if (max > sess->egress.streams[uni].max) {
        sess->egress.streams[uni].max = max;
        unblock_local_streams(sess, uni);
    }
    return 0;
}

static quicly_error_t handle_max_data(struct st_capsule_session_t *sess, h2o_iovec_t payload)
{
    uint64_t max;

    if (h2o_webtransport_decode_varint_capsule(payload, &max, 1) != 0)
        return H2O_WEBTRANSPORT_ERROR_PROTOCOL;
    if (max < sess->egress.max_data.permitted)
        return H2O_WEBTRANSPORT_ERROR_FLOW_CONTROL;

    if (max > sess->egress.max_data.permitted) {
        sess->egress.max_data.permitted = max;
        sess->egress.max_data.is_blocked = 0;
        if (!h2o_linklist_is_empty(&sess->egress.data_streams))
            schedule_send(sess);
    }
    return 0;
}

static quicly_error_t handle_blocked(struct st_capsule_session_t *sess, int is_streams, h2o_iovec_t payload)
{
    uint64_t limit;

    if (h2o_webtransport_decode_varint_capsule(payload, &limit, 1) != 0)
        return H2O_WEBTRANSPORT_ERROR_PROTOCOL;
    if (is_streams && limit > MAX_STREAMS_LIMIT)
        return H2O_WEBTRANSPORT_ERROR_FLOW_CONTROL;
    /* the credit is replenished as the application consumes data, or as streams are closed */
    return 0;
}

static quicly_error_t handle_close_session(struct st_capsule_session_t *sess, h2o_iovec_t payload)
{
    uint32_t app_error;
    h2o_iovec_t reason;

    if (h2o_webtransport_decode_close_session(payload, &app_error, &reason) != 0)
        return H2O_WEBTRANSPORT_ERROR_PROTOCOL;

    terminate(sess, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(app_error), reason, 1);
    return ERROR_CLOSED_BY_APP;
}

static quicly_error_t handle_capsule_payload(struct st_capsule_session_t *sess, h2o_iovec_t payload)
{
    switch (sess->ingress.type) {
    case H2O_WEBTRANSPORT_CAPSULE_DATAGRAM:
        if (sess->super.callbacks->on_receive_datagram != NULL) {
            sess->super.callbacks->on_receive_datagram(&sess->super, payload);
            if (sess->closing)
                return ERROR_CLOSED_BY_APP;
        }
        return 0;
    case H2O_WEBTRANSPORT_CAPSULE_CLOSE_SESSION:
        return handle_close_session(sess, payload);
    case H2O_WEBTRANSPORT_CAPSULE_DRAIN_SESSION:
        if (payload.len != 0)
            return H2O_WEBTRANSPORT_ERROR_PROTOCOL;
        if (sess->super.callbacks->on_drain != NULL) {
            sess->super.callbacks->on_drain(&sess->super);
            if (sess->closing)
                return ERROR_CLOSED_BY_APP;
        }
        return 0;
    case H2O_WEBTRANSPORT_CAPSULE_RESET_STREAM:
        return handle_reset_stream(sess, payload);
    case H2O_WEBTRANSPORT_CAPSULE_STOP_SENDING:
        return handle_stop_sending(sess, payload);
    case H2O_WEBTRANSPORT_CAPSULE_MAX_DATA:
        return handle_max_data(sess, payload);
    case H2O_WEBTRANSPORT_CAPSULE_MAX_STREAM_DATA:
        return handle_max_stream_data(sess, payload);
    case H2O_WEBTRANSPORT_CAPSULE_MAX_STREAMS_BIDI:
        return handle_max_streams(sess, 0, payload);
    case H2O_WEBTRANSPORT_CAPSULE_MAX_STREAMS_UNI:
        return handle_max_streams(sess, 1, payload);
    case H2O_WEBTRANSPORT_CAPSULE_DATA_BLOCKED:
        return handle_blocked(sess, 0, payload);
    case H2O_WEBTRANSPORT_CAPSULE_STREAM_DATA_BLOCKED:
        return handle_stream_data_blocked(sess, payload);
    case H2O_WEBTRANSPORT_CAPSULE_STREAMS_BLOCKED_BIDI:
    case H2O_WEBTRANSPORT_CAPSULE_STREAMS_BLOCKED_UNI:
        return handle_blocked(sess, 1, payload);
    default:
        assert(!"unexpected capsule type");
        return H2O_WEBTRANSPORT_ERROR_PROTOCOL;
    }
}

static quicly_error_t begin_capsule(struct st_capsule_session_t *sess, uint64_t type, uint64_t length, uint64_t stream_id)
{
    sess->ingress.type = type;
    sess->ingress.bytes_left = length;

    /* When the streams are carried natively, the capsules relating to the streams and the flow control are ignored. For the flow
     * control capsules, this is required when flow control is disabled (draft-ietf-webtrans-http3-16 section 5.1); the others are
     * not defined for HTTP/3. */
    if (sess->native != NULL && !(type == H2O_WEBTRANSPORT_CAPSULE_DATAGRAM || type == H2O_WEBTRANSPORT_CAPSULE_CLOSE_SESSION ||
                                  type == H2O_WEBTRANSPORT_CAPSULE_DRAIN_SESSION))
        type = UINT64_MAX; /* skip */

    switch (type) {
    case H2O_WEBTRANSPORT_CAPSULE_STREAM:
    case H2O_WEBTRANSPORT_CAPSULE_STREAM_FIN:
        return begin_stream_capsule(sess, stream_id, length, type == H2O_WEBTRANSPORT_CAPSULE_STREAM_FIN);
    case H2O_WEBTRANSPORT_CAPSULE_DATAGRAM:
        sess->ingress.state = length <= MAX_DATAGRAM_SIZE ? INGRESS_STATE_PAYLOAD : INGRESS_STATE_SKIP;
        break;
    case H2O_WEBTRANSPORT_CAPSULE_CLOSE_SESSION:
        if (length > 4 + H2O_WEBTRANSPORT_MAX_CLOSE_REASON_SIZE)
            return H2O_WEBTRANSPORT_ERROR_PROTOCOL;
        sess->ingress.state = INGRESS_STATE_PAYLOAD;
        break;
    case H2O_WEBTRANSPORT_CAPSULE_DRAIN_SESSION:
    case H2O_WEBTRANSPORT_CAPSULE_RESET_STREAM:
    case H2O_WEBTRANSPORT_CAPSULE_STOP_SENDING:
    case H2O_WEBTRANSPORT_CAPSULE_MAX_DATA:
    case H2O_WEBTRANSPORT_CAPSULE_MAX_STREAM_DATA:
    case H2O_WEBTRANSPORT_CAPSULE_MAX_STREAMS_BIDI:
    case H2O_WEBTRANSPORT_CAPSULE_MAX_STREAMS_UNI:
    case H2O_WEBTRANSPORT_CAPSULE_DATA_BLOCKED:
    case H2O_WEBTRANSPORT_CAPSULE_STREAM_DATA_BLOCKED:
    case H2O_WEBTRANSPORT_CAPSULE_STREAMS_BLOCKED_BIDI:
    case H2O_WEBTRANSPORT_CAPSULE_STREAMS_BLOCKED_UNI:
        if (length > MAX_CONTROL_CAPSULE_PAYLOAD)
            return H2O_WEBTRANSPORT_ERROR_PROTOCOL;
        sess->ingress.state = INGRESS_STATE_PAYLOAD;
        break;
    default:
        /* PADDING and unknown capsules are ignored (RFC 9297 section 3.2) */
        sess->ingress.state = INGRESS_STATE_SKIP;
        break;
    }

    if (length == 0) {
        int is_payload = sess->ingress.state == INGRESS_STATE_PAYLOAD;
        sess->ingress.state = INGRESS_STATE_HEADER;
        if (is_payload)
            return handle_capsule_payload(sess, h2o_iovec_init("", 0));
    }
    return 0;
}

static quicly_error_t handle_capsule_header(struct st_capsule_session_t *sess, const uint8_t **src, const uint8_t *end)
{
    size_t copy = sizeof(sess->ingress.hdr) - sess->ingress.hdr_len;
    if (copy > (size_t)(end - *src))
        copy = end - *src;
    memcpy(sess->ingress.hdr + sess->ingress.hdr_len, *src, copy);

    const uint8_t *p = sess->ingress.hdr, *hdr_end = sess->ingress.hdr + sess->ingress.hdr_len + copy;
    uint64_t type, length, stream_id = 0;

    if (h2o_webtransport_decode_capsule_header(&p, hdr_end, &type, &length) != 0)
        goto NeedMore;
    if (sess->native == NULL && (type == H2O_WEBTRANSPORT_CAPSULE_STREAM || type == H2O_WEBTRANSPORT_CAPSULE_STREAM_FIN)) {
        /* decode the stream ID as well, which must fit within the capsule */
        const uint8_t *id_end = (uint64_t)(hdr_end - p) > length ? p + length : hdr_end, *q = p;
        if ((stream_id = ptls_decode_quicint(&q, id_end)) == UINT64_MAX) {
            if ((uint64_t)(id_end - p) == length)
                return H2O_WEBTRANSPORT_ERROR_PROTOCOL;
            goto NeedMore;
        }
        length -= q - p;
        p = q;
    }

    /* consume the bytes that constitute the header, and handle the capsule */
    assert((size_t)(p - sess->ingress.hdr) > sess->ingress.hdr_len);
    *src += (p - sess->ingress.hdr) - sess->ingress.hdr_len;
    sess->ingress.hdr_len = 0;
    return begin_capsule(sess, type, length, stream_id);

NeedMore:
    /* the buffer is large enough to hold any header */
    assert(sess->ingress.hdr_len + copy < sizeof(sess->ingress.hdr));
    sess->ingress.hdr_len += copy;
    *src += copy;
    return 0;
}

static quicly_error_t handle_input_step(struct st_capsule_session_t *sess, const uint8_t **src, const uint8_t *end)
{
    size_t avail = end - *src;

    switch (sess->ingress.state) {
    case INGRESS_STATE_HEADER:
        return handle_capsule_header(sess, src, end);
    case INGRESS_STATE_STREAM_DATA: {
        size_t len = sess->ingress.bytes_left < avail ? (size_t)sess->ingress.bytes_left : avail;
        const uint8_t *data = *src;
        *src += len;
        sess->ingress.bytes_left -= len;
        if (sess->ingress.bytes_left == 0)
            sess->ingress.state = INGRESS_STATE_HEADER;
        return deliver_stream_data(sess, data, len, sess->ingress.is_fin && sess->ingress.bytes_left == 0);
    }
    case INGRESS_STATE_PAYLOAD: {
        h2o_iovec_t payload;
        quicly_error_t ret;
        if (sess->ingress.payload->size == 0 && sess->ingress.bytes_left <= avail) {
            /* process in place */
            payload = h2o_iovec_init(*src, sess->ingress.bytes_left);
            *src += sess->ingress.bytes_left;
            sess->ingress.state = INGRESS_STATE_HEADER;
            return handle_capsule_payload(sess, payload);
        }
        size_t len = sess->ingress.bytes_left < avail ? (size_t)sess->ingress.bytes_left : avail;
        h2o_buffer_append(&sess->ingress.payload, *src, len);
        *src += len;
        if ((sess->ingress.bytes_left -= len) != 0)
            return 0;
        sess->ingress.state = INGRESS_STATE_HEADER;
        payload = h2o_iovec_init(sess->ingress.payload->bytes, sess->ingress.payload->size);
        ret = handle_capsule_payload(sess, payload);
        h2o_buffer_consume(&sess->ingress.payload, sess->ingress.payload->size);
        return ret;
    }
    case INGRESS_STATE_SKIP: {
        size_t len = sess->ingress.bytes_left < avail ? (size_t)sess->ingress.bytes_left : avail;
        *src += len;
        if ((sess->ingress.bytes_left -= len) == 0)
            sess->ingress.state = INGRESS_STATE_HEADER;
        return 0;
    }
    case INGRESS_STATE_DISCARD:
        *src = end;
        return 0;
    }

    assert(!"unexpected state");
    return H2O_WEBTRANSPORT_ERROR_PROTOCOL;
}

static void handle_input(struct st_capsule_session_t *sess, h2o_iovec_t input, int is_eos)
{
    const uint8_t *src = (const uint8_t *)input.base, *end = src + input.len;

    while (src != end && sess->ingress.state != INGRESS_STATE_DISCARD) {
        quicly_error_t ret;
        if ((ret = handle_input_step(sess, &src, end)) != 0) {
            if (ret != ERROR_CLOSED_BY_APP)
                session_error(sess, ret);
            sess->ingress.state = INGRESS_STATE_DISCARD;
        }
    }

    if (is_eos && sess->ingress.state != INGRESS_STATE_DISCARD) {
        if (sess->ingress.state != INGRESS_STATE_HEADER || sess->ingress.hdr_len != 0) {
            /* the stream ended in the middle of a capsule */
            session_error(sess, H2O_WEBTRANSPORT_ERROR_PROTOCOL);
        } else {
            /* the peer closed the session without WT_CLOSE_SESSION */
            terminate(sess, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0), h2o_iovec_init(NULL, 0), 1);
        }
        sess->ingress.state = INGRESS_STATE_DISCARD;
    }
}

static int on_write_req(void *ctx, int is_end_stream)
{
    struct st_capsule_session_t *sess = ctx;
    h2o_req_t *req = sess->super.req;

    if (sess->egress.done)
        return 0;

    sess->ingress.initial_pending = 0;
    handle_input(sess, req->entity, is_end_stream);

    /* this has to be the last action, as the request (and therefore the session) might be disposed */
    if (req->proceed_req != NULL)
        req->proceed_req(req, NULL);
    return 0;
}

static void on_forward_datagram(h2o_req_t *req, h2o_iovec_t *datagrams, size_t num_datagrams)
{
    struct st_capsule_session_t *sess = req->write_req.ctx;

    for (size_t i = 0; i != num_datagrams && !sess->closing; ++i)
        if (sess->super.callbacks->on_receive_datagram != NULL)
            sess->super.callbacks->on_receive_datagram(&sess->super, datagrams[i]);
}

static void encode_varint_capsule(struct st_capsule_session_t *sess, uint64_t type, const uint64_t *fields, size_t num_fields)
{
    h2o_webtransport_encode_varint_capsule(&sess->egress.buf, type, fields, num_fields);
}

static void push_inflight(struct st_capsule_session_t *sess, quicly_stream_id_t stream_id, uint64_t start, uint64_t end,
                          uint8_t eos_type)
{
    h2o_vector_reserve(NULL, &sess->egress.inflight, sess->egress.inflight.size + 1);
    sess->egress.inflight.entries[sess->egress.inflight.size++] =
        (struct st_capsule_inflight_t){stream_id, {.start = start, .end = end, .eos_type = eos_type}};
}

static void emit_stream_control(struct st_capsule_session_t *sess)
{
    h2o_linklist_t *link = sess->egress.control_streams.next;

    while (link != &sess->egress.control_streams) {
        struct st_capsule_stream_t *stream = H2O_STRUCT_FROM_MEMBER(struct st_capsule_stream_t, control_link, link);
        link = link->next;
        /* capsules cannot be sent for streams that the peer does not allow us to open yet */
        if (stream->send_aux.is_blocked)
            continue;
        h2o_linklist_unlink(&stream->control_link);
        uint64_t id = (uint64_t)stream->super.stream_id, new_value;
        if (stream->send_aux.reset.state == SENDER_STATE_SEND) {
            uint64_t fields[] = {id, stream->send_aux.reset.error_code, stream->super.sendstate.size_inflight};
            encode_varint_capsule(sess, H2O_WEBTRANSPORT_CAPSULE_RESET_STREAM, fields, PTLS_ELEMENTSOF(fields));
            stream->send_aux.reset.state = SENDER_STATE_SENT;
            stream->super.sendstate.eos_state = QUICLY_SENDSTATE_EOS_STATE_INFLIGHT;
            push_inflight(sess, stream->super.stream_id, stream->super.sendstate.final_size, stream->super.sendstate.final_size,
                          QUICLY_SENDSTATE_EOS_TYPE_RESET);
        }
        if (stream->recv_aux.stop_sending.state == SENDER_STATE_SEND) {
            uint64_t fields[] = {id, stream->recv_aux.stop_sending.error_code};
            encode_varint_capsule(sess, H2O_WEBTRANSPORT_CAPSULE_STOP_SENDING, fields, PTLS_ELEMENTSOF(fields));
            stream->recv_aux.stop_sending.state = SENDER_STATE_SENT;
        }
        if (should_send_max_stream_data(stream, &new_value)) {
            uint64_t fields[] = {id, new_value};
            encode_varint_capsule(sess, H2O_WEBTRANSPORT_CAPSULE_MAX_STREAM_DATA, fields, PTLS_ELEMENTSOF(fields));
            stream->recv_aux.max_stream_data = new_value;
        }
        if (stream->send_aux.send_blocked) {
            stream->send_aux.send_blocked = 0;
            if (stream->send_aux.reset.state == SENDER_STATE_NONE &&
                stream->send_aux.blocked_sent_at != stream->send_aux.max_stream_data) {
                uint64_t fields[] = {id, stream->send_aux.max_stream_data};
                encode_varint_capsule(sess, H2O_WEBTRANSPORT_CAPSULE_STREAM_DATA_BLOCKED, fields, PTLS_ELEMENTSOF(fields));
                stream->send_aux.blocked_sent_at = stream->send_aux.max_stream_data;
            }
        }
    }
}

static void emit_session_control(struct st_capsule_session_t *sess)
{
    uint64_t new_value;

    if (should_send_max_data(sess, &new_value)) {
        encode_varint_capsule(sess, H2O_WEBTRANSPORT_CAPSULE_MAX_DATA, &new_value, 1);
        sess->ingress.max_data.advertised = new_value;
    }
    for (int uni = 0; uni < 2; ++uni) {
        if (should_send_max_streams(sess, uni, &new_value)) {
            encode_varint_capsule(sess, uni ? H2O_WEBTRANSPORT_CAPSULE_MAX_STREAMS_UNI : H2O_WEBTRANSPORT_CAPSULE_MAX_STREAMS_BIDI,
                                  &new_value, 1);
            sess->ingress.streams[uni].max = new_value;
        }
        if (sess->egress.streams[uni].next_index > sess->egress.streams[uni].max &&
            sess->egress.streams[uni].blocked_sent_at != sess->egress.streams[uni].max) {
            encode_varint_capsule(
                sess, uni ? H2O_WEBTRANSPORT_CAPSULE_STREAMS_BLOCKED_UNI : H2O_WEBTRANSPORT_CAPSULE_STREAMS_BLOCKED_BIDI,
                &sess->egress.streams[uni].max, 1);
            sess->egress.streams[uni].blocked_sent_at = sess->egress.streams[uni].max;
        }
    }
}

/**
 * Emits WT_DATA_BLOCKED; this is done after emitting stream data, as that is when the session-level credit is found exhausted.
 */
static void emit_data_blocked(struct st_capsule_session_t *sess)
{
    if (sess->egress.max_data.is_blocked && sess->egress.max_data.blocked_sent_at != sess->egress.max_data.permitted) {
        encode_varint_capsule(sess, H2O_WEBTRANSPORT_CAPSULE_DATA_BLOCKED, &sess->egress.max_data.permitted, 1);
        sess->egress.max_data.blocked_sent_at = sess->egress.max_data.permitted;
    }
}

/**
 * Emits one WT_STREAM capsule, mirroring `quicly_send_stream`. Returns if the caller should stop emitting stream data.
 */
static int emit_stream_data_one(struct st_capsule_session_t *sess, struct st_capsule_stream_t *stream)
{
    quicly_sendstate_t *ss = &stream->super.sendstate;
    /* when nothing but FIN remains to be sent, the stream ends where the capsule goes */
    uint64_t off = ss->pending.num_ranges != 0 ? ss->pending.ranges[0].start : ss->final_size,
             id = (uint64_t)stream->super.stream_id;
    size_t len;
    int wrote_all, is_fin;

    assert(stream->send_aux.reset.state == SENDER_STATE_NONE && !stream->send_aux.is_blocked);

    if (off == ss->final_size) {
        /* special case for emitting FIN only */
        uint8_t *dst = (uint8_t *)h2o_buffer_reserve(&sess->egress.buf, STREAM_CAPSULE_HEADER_RESERVE).base, *p = dst;
        p = h2o_webtransport_encode_capsule_header(p, H2O_WEBTRANSPORT_CAPSULE_STREAM_FIN, quicly_encodev_capacity(id));
        p = ptls_encode_quicint(p, id);
        sess->egress.buf->size += p - dst;
        len = 0;
        wrote_all = 1;
        is_fin = 1;
        goto UpdateState;
    }

    /* determine the amount to emit */
    if (off >= stream->send_aux.max_stream_data) {
        stream->send_aux.send_blocked = 1;
        schedule_control(stream);
        return 0; /* the stream is scheduled again upon receiving WT_MAX_STREAM_DATA */
    }
    if (sess->egress.max_data.sent >= sess->egress.max_data.permitted) {
        sess->egress.max_data.is_blocked = 1;
        h2o_linklist_insert(sess->egress.data_streams.next, &stream->send_aux.data_link);
        return 1;
    }
    len = MAX_STREAM_CHUNK_SIZE;
    if (sess->egress.buf->size + len > MAX_BATCH_SIZE)
        len = sess->egress.buf->size < MAX_BATCH_SIZE ? MAX_BATCH_SIZE - sess->egress.buf->size : 1;
    if (off + len > stream->send_aux.max_stream_data)
        len = stream->send_aux.max_stream_data - off;
    if (off + len > ss->size_inflight) {
        uint64_t new_bytes = off + len - ss->size_inflight;
        if (new_bytes > sess->egress.max_data.permitted - sess->egress.max_data.sent)
            len = ss->size_inflight + sess->egress.max_data.permitted - sess->egress.max_data.sent - off;
    }
    { /* cap len to the current range */
        uint64_t range_capacity = ss->pending.ranges[0].end - off;
        if (len > range_capacity)
            len = range_capacity;
    }
    assert(len != 0);

    /* emit the payload, leaving room for the capsule header */
    uint8_t *dst = (uint8_t *)h2o_buffer_reserve(&sess->egress.buf, STREAM_CAPSULE_HEADER_RESERVE + len).base;
    size_t emit_off = (size_t)(off - ss->acked.ranges[0].end);
    wrote_all = 0;
    stream->super.callbacks->on_send_emit(&stream->super, emit_off, dst + STREAM_CAPSULE_HEADER_RESERVE, &len, &wrote_all);
    if (sess->closing)
        return 1;
    if (stream->send_aux.reset.state != SENDER_STATE_NONE)
        return 0;
    assert(len != 0);
    is_fin = off + len == ss->final_size;

    { /* write the capsule header, then move the payload next to it */
        uint8_t hdr[STREAM_CAPSULE_HEADER_RESERVE], *p = hdr;
        p = h2o_webtransport_encode_capsule_header(
            p, is_fin ? H2O_WEBTRANSPORT_CAPSULE_STREAM_FIN : H2O_WEBTRANSPORT_CAPSULE_STREAM, quicly_encodev_capacity(id) + len);
        p = ptls_encode_quicint(p, id);
        memmove(dst + (p - hdr), dst + STREAM_CAPSULE_HEADER_RESERVE, len);
        memcpy(dst, hdr, p - hdr);
        sess->egress.buf->size += (p - hdr) + len;
    }

UpdateState:
    if (ss->size_inflight < off + len) {
        sess->egress.max_data.sent += off + len - ss->size_inflight;
        ss->size_inflight = off + len;
    }
    if ((len != 0 && quicly_ranges_subtract(&ss->pending, off, off + len) != 0) ||
        (wrote_all && quicly_ranges_subtract(&ss->pending, ss->size_inflight, UINT64_MAX) != 0))
        h2o_fatal("no memory");
    if (is_fin)
        ss->eos_state = QUICLY_SENDSTATE_EOS_STATE_INFLIGHT;
    push_inflight(sess, stream->super.stream_id, off, off + len,
                  is_fin ? QUICLY_SENDSTATE_EOS_TYPE_FIN : QUICLY_SENDSTATE_EOS_TYPE_NONE);

    /* reschedule, being put at the tail for round-robin */
    schedule_data(stream);
    return 0;
}

static void emit_stream_data(struct st_capsule_session_t *sess)
{
    while (!h2o_linklist_is_empty(&sess->egress.data_streams) && sess->egress.buf->size < MAX_BATCH_SIZE) {
        struct st_capsule_stream_t *stream =
            H2O_STRUCT_FROM_MEMBER(struct st_capsule_stream_t, send_aux.data_link, sess->egress.data_streams.next);
        h2o_linklist_unlink(&stream->send_aux.data_link);
        if (emit_stream_data_one(sess, stream))
            break;
    }
}

static void do_send(struct st_capsule_session_t *sess)
{
    /* keep the timer if it is to run the deferred actions (see `on_timer`); it would call this function again */
    if (!(sess->native_start_pending || sess->ingress.initial_pending || sess->egress.shutdown_pending))
        h2o_timer_unlink(&sess->egress.timer);

    if (sess->egress.done || sess->egress.send_inflight || sess->egress.final_sent)
        return;

    if (sess->egress.send_error) {
        sess->egress.final_sent = 1;
        h2o_send(sess->super.req, NULL, 0, H2O_SEND_STATE_ERROR);
        return;
    }

    assert(sess->egress.buf->size == 0 && sess->egress.inflight.size == 0);

    if (!sess->closing) {
        emit_stream_control(sess);
        emit_session_control(sess);
        emit_stream_data(sess); /* this might close the session, as the application is called */
        if (!sess->closing)
            emit_data_blocked(sess);
    }
    if (sess->egress.pending->size != 0) {
        h2o_buffer_append(&sess->egress.buf, sess->egress.pending->bytes, sess->egress.pending->size);
        h2o_buffer_consume(&sess->egress.pending, sess->egress.pending->size);
        sess->egress.pending_datagram_bytes = 0;
    }

    if (sess->egress.buf->size == 0 && !sess->closing)
        return;

    h2o_send_state_t send_state = H2O_SEND_STATE_IN_PROGRESS;
    if (sess->closing) {
        sess->egress.final_sent = 1;
        send_state = H2O_SEND_STATE_FINAL;
    }
    sess->egress.send_inflight = 1;
    h2o_iovec_t vec = h2o_iovec_init(sess->egress.buf->bytes, sess->egress.buf->size);
    h2o_send(sess->super.req, &vec, vec.len != 0, send_state);
}

static void on_timer(h2o_timer_t *timer)
{
    struct st_capsule_session_t *sess = H2O_STRUCT_FROM_MEMBER(struct st_capsule_session_t, egress.timer, timer);

    if (sess->native_start_pending) {
        sess->native_start_pending = 0;
        if (!sess->closing)
            sess->native->start(&sess->super);
    }

    if (sess->ingress.initial_pending) {
        /* Process the request body that was received before the session was accepted. As doing so might dispose the request, send
         * is scheduled beforehand for the output that the application might have generated after accepting the session. */
        h2o_req_t *req = sess->super.req;
        schedule_send(sess);
        on_write_req(sess, req->proceed_req == NULL);
        return;
    }

    if (sess->egress.shutdown_pending) {
        sess->egress.shutdown_pending = 0;
        if (!sess->closing && sess->super.callbacks->on_drain != NULL)
            sess->super.callbacks->on_drain(&sess->super);
    }

    do_send(sess);
}

static void on_generator_proceed(h2o_generator_t *generator, h2o_req_t *req)
{
    struct st_capsule_session_t *sess = H2O_STRUCT_FROM_MEMBER(struct st_capsule_session_t, generator, generator);

    assert(sess->egress.send_inflight);
    sess->egress.send_inflight = 0;
    h2o_buffer_consume(&sess->egress.buf, sess->egress.buf->size);

    /* the capsules have been handed to the protocol layer, which delivers them reliably; treat them as acknowledged */
    for (size_t i = 0; i != sess->egress.inflight.size && !sess->closing; ++i) {
        struct st_capsule_inflight_t *inflight = sess->egress.inflight.entries + i;
        struct st_capsule_stream_t *stream;
        if ((stream = find_stream(sess, inflight->stream_id)) == NULL)
            continue;
        { /* the bytes retired by a reset are not shifted, as `quicly_sendstate_reset` accounts them as acked */
            size_t bytes_to_shift;
            if (quicly_sendstate_acked(&stream->super.sendstate, &inflight->args, &bytes_to_shift) != 0)
                h2o_fatal("no memory");
            if (bytes_to_shift != 0) {
                stream->super.callbacks->on_send_shift(&stream->super, bytes_to_shift);
                if (sess->closing)
                    break;
                if ((stream = find_stream(sess, inflight->stream_id)) == NULL)
                    continue;
            }
        }
        destroy_stream_if_possible(stream);
    }
    sess->egress.inflight.size = 0;

    do_send(sess);
}

static void on_generator_stop(h2o_generator_t *generator, h2o_req_t *req)
{
    struct st_capsule_session_t *sess = H2O_STRUCT_FROM_MEMBER(struct st_capsule_session_t, generator, generator);

    sess->egress.done = 1;
    h2o_timer_unlink(&sess->egress.timer);
    terminate(sess, H2O_WEBTRANSPORT_ERROR_TRANSPORT, h2o_iovec_init(NULL, 0), 1);
}

static void on_session_dispose(void *_sess)
{
    struct st_capsule_session_t *sess = _sess;

    sess->egress.done = 1;
    h2o_timer_unlink(&sess->egress.timer);
    terminate(sess, H2O_WEBTRANSPORT_ERROR_TRANSPORT, h2o_iovec_init(NULL, 0), 1);

    kh_destroy(h2o_webtransport_capsule_stream, sess->streams);
    h2o_buffer_dispose(&sess->ingress.payload);
    h2o_buffer_dispose(&sess->egress.buf);
    h2o_buffer_dispose(&sess->egress.pending);
    free(sess->egress.inflight.entries);
}

static quicly_error_t capsule_open_stream(h2o_webtransport_session_t *_sess, h2o_webtransport_stream_t **_stream, int uni)
{
    struct st_capsule_session_t *sess = (struct st_capsule_session_t *)_sess;
    quicly_error_t ret;

    if (sess->closing)
        return H2O_WEBTRANSPORT_ERROR_SESSION_GONE;

    uint64_t index = sess->egress.streams[uni].next_index;
    if (index >= MAX_STREAMS_LIMIT)
        return QUICLY_ERROR_STATE_EXHAUSTION;
    ++sess->egress.streams[uni].next_index;

    struct st_capsule_stream_t *stream = create_stream(sess, (quicly_stream_id_t)(index << 2 | (uint64_t)uni << 1 | 1));
    if (index >= sess->egress.streams[uni].max) {
        stream->send_aux.is_blocked = 1;
        schedule_send(sess); /* send WT_STREAMS_BLOCKED */
    }

    if ((ret = sess->super.callbacks->on_stream_open(&stream->super)) != 0) {
        if (sess->closing)
            return ret; /* the stream has been destroyed along with the session */
        destroy_stream(stream, ret);
        /* give the stream ID back unless another stream has been opened, as the peer would otherwise see a stream that never
         * closes */
        if (sess->egress.streams[uni].next_index == index + 1)
            sess->egress.streams[uni].next_index = index;
        return ret;
    }
    if (sess->closing)
        return H2O_WEBTRANSPORT_ERROR_SESSION_GONE;

    *_stream = &stream->super;
    return 0;
}

static quicly_error_t capsule_stream_sync_sendbuf(h2o_webtransport_stream_t *_stream, int activate)
{
    struct st_capsule_stream_t *stream = (struct st_capsule_stream_t *)_stream;
    int ret;

    if (stream->send_aux.reset.state != SENDER_STATE_NONE)
        return 0;
    if (activate && (ret = quicly_sendstate_activate(&stream->super.sendstate)) != 0)
        return ret;
    if (!get_session(_stream)->closing)
        schedule_data(stream);
    return 0;
}

static void capsule_stream_sync_recvbuf(h2o_webtransport_stream_t *_stream, size_t shift_amount)
{
    struct st_capsule_stream_t *stream = (struct st_capsule_stream_t *)_stream;
    struct st_capsule_session_t *sess = get_session(_stream);
    uint64_t unused;

    stream->super.recvstate.data_off += shift_amount;
    if (sess->closing)
        return;
    if (!stream->recv_aux.credit_released)
        sess->ingress.max_data.shifted += shift_amount;

    if (should_send_max_stream_data(stream, &unused))
        schedule_control(stream);
    if (should_send_max_data(sess, &unused))
        schedule_send(sess);
}

static void capsule_reset_stream(h2o_webtransport_stream_t *_stream, quicly_error_t err)
{
    struct st_capsule_stream_t *stream = (struct st_capsule_stream_t *)_stream;

    assert(QUICLY_ERROR_IS_QUIC_APPLICATION(err));
    assert(h2o_webtransport_stream_has_send_side(_stream));

    if (get_session(_stream)->closing)
        return;
    reset_stream_core(stream, QUICLY_ERROR_GET_ERROR_CODE(err));
}

static void capsule_request_stop(h2o_webtransport_stream_t *_stream, quicly_error_t err)
{
    struct st_capsule_stream_t *stream = (struct st_capsule_stream_t *)_stream;

    assert(QUICLY_ERROR_IS_QUIC_APPLICATION(err));
    assert(h2o_webtransport_stream_has_receive_side(_stream));

    if (get_session(_stream)->closing)
        return;
    request_stop_core(stream, QUICLY_ERROR_GET_ERROR_CODE(err));
}

static void capsule_send_datagrams(h2o_webtransport_session_t *_sess, h2o_iovec_t *datagrams, size_t num_datagrams)
{
    struct st_capsule_session_t *sess = (struct st_capsule_session_t *)_sess;

    if (sess->closing)
        return;

    for (size_t i = 0; i != num_datagrams; ++i) {
        if (datagrams[i].len > MAX_DATAGRAM_SIZE ||
            sess->egress.pending_datagram_bytes + datagrams[i].len > MAX_PENDING_DATAGRAM_BYTES)
            continue; /* drop */
        uint8_t *dst = (uint8_t *)h2o_buffer_reserve(&sess->egress.pending,
                                                     H2O_WEBTRANSPORT_MAX_CAPSULE_HEADER_SIZE + datagrams[i].len)
                           .base,
                *p = dst;
        p = h2o_webtransport_encode_capsule_header(p, H2O_WEBTRANSPORT_CAPSULE_DATAGRAM, datagrams[i].len);
        memcpy(p, datagrams[i].base, datagrams[i].len);
        p += datagrams[i].len;
        sess->egress.pending->size += p - dst;
        sess->egress.pending_datagram_bytes += datagrams[i].len;
    }
    schedule_send(sess);
}

static void capsule_drain(h2o_webtransport_session_t *_sess)
{
    struct st_capsule_session_t *sess = (struct st_capsule_session_t *)_sess;

    if (sess->closing || sess->egress.drain_queued)
        return;
    sess->egress.drain_queued = 1;
    h2o_webtransport_encode_drain_session(&sess->egress.pending);
    schedule_send(sess);
}

void h2o_webtransport_notify_shutdown(h2o_req_t *req)
{
    if (req->write_req.cb != on_write_req)
        return;

    struct st_capsule_session_t *sess = req->write_req.ctx;
    if (sess->closing || sess->egress.shutdown_notified)
        return;
    sess->egress.shutdown_notified = 1;
    sess->egress.shutdown_pending = 1;
    capsule_drain(&sess->super);
}

static void capsule_close(h2o_webtransport_session_t *_sess, uint32_t app_error, h2o_iovec_t reason)
{
    struct st_capsule_session_t *sess = (struct st_capsule_session_t *)_sess;

    if (sess->closing)
        return;
    if (h2o_webtransport_encode_close_session(&sess->egress.pending, app_error, reason) != 0)
        h2o_webtransport_encode_close_session(&sess->egress.pending, app_error, h2o_iovec_init(NULL, 0));
    terminate(sess, 0, h2o_iovec_init(NULL, 0), 0);
}

static quicly_error_t native_open_stream(h2o_webtransport_session_t *_sess, h2o_webtransport_stream_t **stream, int uni)
{
    struct st_capsule_session_t *sess = (struct st_capsule_session_t *)_sess;

    if (sess->closing)
        return H2O_WEBTRANSPORT_ERROR_SESSION_GONE;
    return sess->native->open_stream(_sess, stream, uni);
}

static quicly_error_t native_stream_sync_sendbuf(h2o_webtransport_stream_t *stream, int activate)
{
    return get_session(stream)->native->stream_sync_sendbuf(stream, activate);
}

static void native_stream_sync_recvbuf(h2o_webtransport_stream_t *stream, size_t shift_amount)
{
    get_session(stream)->native->stream_sync_recvbuf(stream, shift_amount);
}

static void native_reset_stream(h2o_webtransport_stream_t *stream, quicly_error_t err)
{
    assert(QUICLY_ERROR_IS_QUIC_APPLICATION(err));
    assert(h2o_webtransport_stream_has_send_side(stream));
    get_session(stream)->native->reset_stream(stream, err);
}

static void native_request_stop(h2o_webtransport_stream_t *stream, quicly_error_t err)
{
    assert(QUICLY_ERROR_IS_QUIC_APPLICATION(err));
    assert(h2o_webtransport_stream_has_receive_side(stream));
    get_session(stream)->native->request_stop(stream, err);
}

void h2o_webtransport_native_error(h2o_webtransport_session_t *_sess, quicly_error_t err)
{
    session_error((struct st_capsule_session_t *)_sess, err);
}

static void native_send_datagrams(h2o_webtransport_session_t *_sess, h2o_iovec_t *datagrams, size_t num_datagrams)
{
    struct st_capsule_session_t *sess = (struct st_capsule_session_t *)_sess;
    h2o_req_t *req = sess->super.req;

    if (sess->closing)
        return;

    /* use the datagram flow of the protocol layer once it has been set up, or fall back to DATAGRAM capsules */
    if (req->forward_datagram.read_ != NULL) {
        req->forward_datagram.read_(req, datagrams, num_datagrams);
    } else {
        capsule_send_datagrams(_sess, datagrams, num_datagrams);
    }
}

static const h2o_webtransport_backend_t native_backend = {native_open_stream,
                                                          native_stream_sync_sendbuf,
                                                          native_stream_sync_recvbuf,
                                                          native_reset_stream,
                                                          native_request_stop,
                                                          native_send_datagrams,
                                                          capsule_drain,
                                                          capsule_close};

static const h2o_webtransport_backend_t capsule_backend = {capsule_open_stream,
                                                           capsule_stream_sync_sendbuf,
                                                           capsule_stream_sync_recvbuf,
                                                           capsule_reset_stream,
                                                           capsule_request_stop,
                                                           capsule_send_datagrams,
                                                           capsule_drain,
                                                           capsule_close};

int h2o_webtransport_is_request(h2o_req_t *req)
{
    return h2o_memis(req->method.base, req->method.len, H2O_STRLIT("CONNECT")) &&
           (h2o_lcstris(req->upgrade.base, req->upgrade.len, H2O_STRLIT("webtransport")) ||
            h2o_lcstris(req->upgrade.base, req->upgrade.len, H2O_STRLIT("webtransport-h3")));
}

static int parse_init_header(h2o_req_t *req, h2o_webtransport_init_params_t *params)
{
    H2O_VECTOR(h2o_iovec_t) lines = {NULL};
    ssize_t cursor = -1;

    while ((cursor = h2o_find_header_by_str(&req->headers, H2O_STRLIT("webtransport-init"), cursor)) != -1) {
        h2o_vector_reserve(&req->pool, &lines, lines.size + 1);
        lines.entries[lines.size++] = req->headers.entries[cursor].value;
    }
    return h2o_webtransport_parse_init_header(lines.entries, lines.size, params);
}

h2o_webtransport_session_t *h2o_webtransport_accept(h2o_req_t *req, const h2o_webtransport_session_callbacks_t *callbacks,
                                                    void *data, h2o_iovec_t protocol)
{
    h2o_webtransport_settings_t local = {0}, remote = {0};
    h2o_webtransport_init_params_t init = {0};
    int is_native;

    assert(callbacks->on_stream_open != NULL && callbacks->on_close != NULL);

    /* validate */
    if (!h2o_webtransport_is_request(req)) {
        h2o_send_error_400(req, "Bad Request", "not a WebTransport request", 0);
        return NULL;
    }
    if ((is_native = h2o_lcstris(req->upgrade.base, req->upgrade.len, H2O_STRLIT("webtransport-h3")))) {
        /* the streams are carried natively; flow control is provided by the protocol layer */
        if (req->conn->callbacks->webtransport_attach == NULL) {
            h2o_send_error_400(req, "Bad Request", "WebTransport is not available", 0);
            return NULL;
        }
    } else {
        if (req->conn->callbacks->get_webtransport_settings == NULL ||
            req->conn->callbacks->get_webtransport_settings(req->conn, &local, &remote) != 0) {
            h2o_send_error_400(req, "Bad Request", "WebTransport is not available", 0);
            return NULL;
        }
        if (parse_init_header(req, &init) != 0) {
            h2o_send_error_400(req, "Bad Request", "invalid webtransport-init", 0);
            return NULL;
        }
        /* the limits of the peer are either those carried by SETTINGS or by WebTransport-Init, whichever larger */
        remote.max_stream_data_uni = max_u64(remote.max_stream_data_uni, init.max_stream_data_uni);
        remote.max_stream_data_bidi_local = max_u64(remote.max_stream_data_bidi_local, init.max_stream_data_bidi_local);
        remote.max_stream_data_bidi_remote = max_u64(remote.max_stream_data_bidi_remote, init.max_stream_data_bidi_remote);
    }

    /* instantiate the session */
    struct st_capsule_session_t *sess = h2o_mem_alloc_shared(&req->pool, sizeof(*sess), on_session_dispose);
    *sess = (struct st_capsule_session_t){{req, callbacks, data, is_native ? &native_backend : &capsule_backend},
                                          {on_generator_proceed, on_generator_stop}};
    sess->streams = kh_init(h2o_webtransport_capsule_stream);
    sess->ingress.initial_pending = 1;
    h2o_buffer_init(&sess->ingress.payload, &h2o_socket_buffer_prototype);
    sess->ingress.max_data.advertised = local.max_data;
    sess->ingress.max_data.window = local.max_data;
    sess->ingress.streams[0].max = sess->ingress.streams[0].window = local.max_streams_bidi;
    sess->ingress.streams[1].max = sess->ingress.streams[1].window = local.max_streams_uni;
    sess->ingress.max_stream_data.bidi_local = local.max_stream_data_bidi_local;
    sess->ingress.max_stream_data.bidi_remote = local.max_stream_data_bidi_remote;
    sess->ingress.max_stream_data.uni = local.max_stream_data_uni;
    h2o_buffer_init(&sess->egress.buf, &h2o_socket_buffer_prototype);
    h2o_buffer_init(&sess->egress.pending, &h2o_socket_buffer_prototype);
    sess->egress.max_data.permitted = remote.max_data;
    sess->egress.max_data.blocked_sent_at = UINT64_MAX;
    sess->egress.streams[0].max = remote.max_streams_bidi;
    sess->egress.streams[1].max = remote.max_streams_uni;
    sess->egress.streams[0].blocked_sent_at = sess->egress.streams[1].blocked_sent_at = UINT64_MAX;
    sess->egress.max_stream_data.bidi_local = remote.max_stream_data_bidi_local;
    sess->egress.max_stream_data.bidi_remote = remote.max_stream_data_bidi_remote;
    sess->egress.max_stream_data.uni = remote.max_stream_data_uni;
    h2o_linklist_init_anchor(&sess->egress.control_streams);
    h2o_linklist_init_anchor(&sess->egress.data_streams);
    h2o_timer_init(&sess->egress.timer, on_timer);

    /* attach to the protocol layer that carries the streams */
    if (is_native) {
        if ((sess->native = req->conn->callbacks->webtransport_attach(req, &sess->super)) == NULL) {
            sess->closing = 1; /* the session has never been visible to the application */
            h2o_send_error_400(req, "Bad Request", "WebTransport is not available", 0);
            return NULL;
        }
        sess->native_start_pending = 1;
    }

    /* send the response headers */
    req->res.status = 200;
    req->res.reason = "OK";
    if (protocol.len != 0) {
        h2o_iovec_t value = h2o_encode_sf_string(&req->pool, protocol.base, protocol.len);
        h2o_add_header_by_str(&req->pool, &req->res.headers, H2O_STRLIT("wt-protocol"), 0, NULL, value.base, value.len);
    }
    req->write_req.cb = on_write_req;
    req->write_req.ctx = sess;
    req->forward_datagram.write_ = on_forward_datagram;
    h2o_start_response(req, &sess->generator);
    sess->egress.send_inflight = 1;
    h2o_send(req, NULL, 0, H2O_SEND_STATE_IN_PROGRESS);

    /* the request body received so far is processed asynchronously, so that the callbacks are invoked after this function returns
     */
    h2o_timer_link(req->conn->ctx->loop, 0, &sess->egress.timer);

    return &sess->super;
}

static void convert_error(h2o_webtransport_stream_t *stream, quicly_error_t err)
{
    assert(err != 0);
    if (!QUICLY_ERROR_IS_QUIC_APPLICATION(err))
        err = QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0);
    if (h2o_webtransport_stream_has_send_side(stream) && quicly_sendstate_is_open(&stream->sendstate))
        h2o_webtransport_reset_stream(stream, err);
    if (h2o_webtransport_stream_has_receive_side(stream))
        h2o_webtransport_request_stop(stream, err);
}

int h2o_webtransport_streambuf_create(h2o_webtransport_stream_t *stream, size_t sz)
{
    h2o_webtransport_streambuf_t *sbuf;

    assert(sz >= sizeof(*sbuf));
    assert(stream->data == NULL);

    if ((sbuf = malloc(sz)) == NULL)
        return PTLS_ERROR_NO_MEMORY;
    quicly_sendbuf_init(&sbuf->egress);
    ptls_buffer_init(&sbuf->ingress, "", 0);
    if (sz != sizeof(*sbuf))
        memset((char *)sbuf + sizeof(*sbuf), 0, sz - sizeof(*sbuf));

    stream->data = sbuf;
    return 0;
}

void h2o_webtransport_streambuf_destroy(h2o_webtransport_stream_t *stream, quicly_error_t err)
{
    h2o_webtransport_streambuf_t *sbuf = stream->data;

    quicly_sendbuf_dispose(&sbuf->egress);
    ptls_buffer_dispose(&sbuf->ingress);
    free(sbuf);
    stream->data = NULL;
}

void h2o_webtransport_streambuf_egress_shift(h2o_webtransport_stream_t *stream, size_t delta)
{
    quicly_sendbuf_t *sb = &((h2o_webtransport_streambuf_t *)stream->data)->egress;
    size_t i;

    for (i = 0; delta != 0; ++i) {
        assert(i < sb->vecs.size);
        quicly_sendbuf_vec_t *first_vec = sb->vecs.entries + i;
        size_t bytes_in_first_vec = first_vec->len - sb->off_in_first_vec;
        if (delta < bytes_in_first_vec) {
            sb->off_in_first_vec += delta;
            break;
        }
        delta -= bytes_in_first_vec;
        if (first_vec->cb->discard_vec != NULL)
            first_vec->cb->discard_vec(first_vec);
        sb->off_in_first_vec = 0;
    }
    if (i != 0) {
        if (sb->vecs.size != i) {
            memmove(sb->vecs.entries, sb->vecs.entries + i, (sb->vecs.size - i) * sizeof(*sb->vecs.entries));
            sb->vecs.size -= i;
        } else {
            free(sb->vecs.entries);
            sb->vecs.entries = NULL;
            sb->vecs.size = 0;
            sb->vecs.capacity = 0;
        }
    }
    h2o_webtransport_stream_sync_sendbuf(stream, 0);
}

void h2o_webtransport_streambuf_egress_emit(h2o_webtransport_stream_t *stream, size_t off, void *dst, size_t *len, int *wrote_all)
{
    quicly_sendbuf_t *sb = &((h2o_webtransport_streambuf_t *)stream->data)->egress;
    size_t vec_index, capacity = *len;
    quicly_error_t ret;

    off += sb->off_in_first_vec;
    for (vec_index = 0; capacity != 0 && vec_index < sb->vecs.size; ++vec_index) {
        quicly_sendbuf_vec_t *vec = sb->vecs.entries + vec_index;
        if (off < vec->len) {
            size_t bytes_flatten = vec->len - off;
            int partial = 0;
            if (capacity < bytes_flatten) {
                bytes_flatten = capacity;
                partial = 1;
            }
            if ((ret = vec->cb->flatten_vec(vec, dst, off, bytes_flatten)) != 0) {
                convert_error(stream, ret);
                return;
            }
            dst = (uint8_t *)dst + bytes_flatten;
            capacity -= bytes_flatten;
            off = 0;
            if (partial)
                break;
        } else {
            off -= vec->len;
        }
    }

    if (capacity == 0 && vec_index < sb->vecs.size) {
        *wrote_all = 0;
    } else {
        *len = *len - capacity;
        *wrote_all = 1;
    }
}

static quicly_error_t flatten_raw(quicly_sendbuf_vec_t *vec, void *dst, size_t off, size_t len)
{
    memcpy(dst, (uint8_t *)vec->cbdata + off, len);
    return 0;
}

static void discard_raw(quicly_sendbuf_vec_t *vec)
{
    free(vec->cbdata);
}

int h2o_webtransport_streambuf_egress_write(h2o_webtransport_stream_t *stream, const void *src, size_t len)
{
    static const quicly_streambuf_sendvec_callbacks_t raw_callbacks = {flatten_raw, discard_raw};
    quicly_sendbuf_vec_t vec = {&raw_callbacks, len, NULL};
    int ret;

    assert(quicly_sendstate_is_open(&stream->sendstate));

    if ((vec.cbdata = malloc(len)) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Error;
    }
    memcpy(vec.cbdata, src, len);
    if ((ret = h2o_webtransport_streambuf_egress_write_vec(stream, &vec)) != 0)
        goto Error;
    return 0;

Error:
    free(vec.cbdata);
    return ret;
}

int h2o_webtransport_streambuf_egress_write_vec(h2o_webtransport_stream_t *stream, quicly_sendbuf_vec_t *vec)
{
    quicly_sendbuf_t *sb = &((h2o_webtransport_streambuf_t *)stream->data)->egress;

    assert(sb->vecs.size <= sb->vecs.capacity);

    if (sb->vecs.size == sb->vecs.capacity) {
        quicly_sendbuf_vec_t *new_entries;
        size_t new_capacity = sb->vecs.capacity == 0 ? 4 : sb->vecs.capacity * 2;
        if ((new_entries = realloc(sb->vecs.entries, new_capacity * sizeof(*sb->vecs.entries))) == NULL)
            return PTLS_ERROR_NO_MEMORY;
        sb->vecs.entries = new_entries;
        sb->vecs.capacity = new_capacity;
    }
    sb->vecs.entries[sb->vecs.size++] = *vec;
    sb->bytes_written += vec->len;

    return (int)h2o_webtransport_stream_sync_sendbuf(stream, 1);
}

int h2o_webtransport_streambuf_egress_shutdown(h2o_webtransport_stream_t *stream)
{
    h2o_webtransport_streambuf_t *sbuf = stream->data;
    int ret;

    if ((ret = quicly_sendstate_shutdown(&stream->sendstate, sbuf->egress.bytes_written)) != 0)
        return ret;
    return (int)h2o_webtransport_stream_sync_sendbuf(stream, 1);
}

void h2o_webtransport_streambuf_ingress_shift(h2o_webtransport_stream_t *stream, size_t delta)
{
    ptls_buffer_t *rb = &((h2o_webtransport_streambuf_t *)stream->data)->ingress;

    assert(delta <= rb->off);
    rb->off -= delta;
    memmove(rb->base, rb->base + delta, rb->off);

    h2o_webtransport_stream_sync_recvbuf(stream, delta);
}

ptls_iovec_t h2o_webtransport_streambuf_ingress_get(h2o_webtransport_stream_t *stream)
{
    ptls_buffer_t *rb = &((h2o_webtransport_streambuf_t *)stream->data)->ingress;
    size_t avail;

    if (quicly_recvstate_transfer_complete(&stream->recvstate)) {
        avail = rb->off;
    } else if (stream->recvstate.data_off < stream->recvstate.received.ranges[0].end) {
        avail = stream->recvstate.received.ranges[0].end - stream->recvstate.data_off;
    } else {
        avail = 0;
    }

    return ptls_iovec_init(rb->base, avail);
}

int h2o_webtransport_streambuf_ingress_receive(h2o_webtransport_stream_t *stream, size_t off, const void *src, size_t len)
{
    ptls_buffer_t *rb = &((h2o_webtransport_streambuf_t *)stream->data)->ingress;

    if (len != 0) {
        int ret;
        if ((ret = ptls_buffer_reserve(rb, off + len - rb->off)) != 0) {
            convert_error(stream, ret);
            return -1;
        }
        memcpy(rb->base + off, src, len);
        if (rb->off < off + len)
            rb->off = off + len;
    }
    return 0;
}
