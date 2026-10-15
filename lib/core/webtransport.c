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
 * This file implements the session / stream API of WebTransport on top of `h2o_req_t`. The streams are carried natively by the
 * protocol layer (i.e., HTTP/3; see `h2o_conn_callbacks_t::webtransport_attach`), while this file handles the extended CONNECT
 * stream: the capsules being exchanged on it (DATAGRAM, WT_CLOSE_SESSION, WT_DRAIN_SESSION), and the lifetime of the session.
 * Capsules are written with `h2o_send`, a batch being considered delivered once the `proceed` callback of the generator is invoked.
 */
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "h2o.h"
#include "h2o/webtransport.h"

/**
 * maximum size of the datagrams being received or sent
 */
#define MAX_DATAGRAM_SIZE 65535
/**
 * maximum amount of datagrams queued while a batch is inflight; excess datagrams are dropped
 */
#define MAX_PENDING_DATAGRAM_BYTES 65536
/**
 * internal error indicating that the application closed the session from within a callback
 */
#define ERROR_CLOSED_BY_APP ((quicly_error_t)0x2e7ff)

enum en_ingress_state_t {
    INGRESS_STATE_HEADER,
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
    /**
     * operations provided by the protocol layer that carries the streams
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
         * partial capsule header (type and length)
         */
        uint8_t hdr[H2O_WEBTRANSPORT_MAX_CAPSULE_HEADER_SIZE];
        size_t hdr_len;
        uint64_t type;
        uint64_t bytes_left;
        /**
         * if the request body that was received before the session was accepted is yet to be processed
         */
        unsigned initial_pending : 1;
        h2o_buffer_t *payload;
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

static const h2o_webtransport_backend_t native_backend;

static struct st_capsule_session_t *get_session(h2o_webtransport_stream_t *stream)
{
    return (struct st_capsule_session_t *)stream->session;
}

static void schedule_send(struct st_capsule_session_t *sess)
{
    if (sess->egress.done || sess->egress.final_sent || h2o_timer_is_linked(&sess->egress.timer))
        return;
    h2o_timer_link(sess->super.req->conn->ctx->loop, 0, &sess->egress.timer);
}

/**
 * Ends the session. When `notify` is set, `on_close` is invoked.
 */
static void terminate(struct st_capsule_session_t *sess, quicly_error_t err, h2o_iovec_t reason, int notify)
{
    if (sess->closing)
        return;
    sess->closing = 1;

    /* discard what is no longer needed; the protocol layer destroys the streams */
    sess->ingress.state = INGRESS_STATE_DISCARD;
    if (sess->native != NULL)
        sess->native->detach(&sess->super);
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
            sess->super.callbacks->on_drain(&sess->super, 1);
            if (sess->closing)
                return ERROR_CLOSED_BY_APP;
        }
        return 0;
    default:
        assert(!"unexpected capsule type");
        return H2O_WEBTRANSPORT_ERROR_PROTOCOL;
    }
}

static quicly_error_t begin_capsule(struct st_capsule_session_t *sess, uint64_t type, uint64_t length)
{
    sess->ingress.type = type;
    sess->ingress.bytes_left = length;

    switch (type) {
    case H2O_WEBTRANSPORT_CAPSULE_DATAGRAM:
        sess->ingress.state = length <= MAX_DATAGRAM_SIZE ? INGRESS_STATE_PAYLOAD : INGRESS_STATE_SKIP;
        break;
    case H2O_WEBTRANSPORT_CAPSULE_CLOSE_SESSION:
        if (length > 4 + H2O_WEBTRANSPORT_MAX_CLOSE_REASON_SIZE)
            return H2O_WEBTRANSPORT_ERROR_PROTOCOL;
        sess->ingress.state = INGRESS_STATE_PAYLOAD;
        break;
    case H2O_WEBTRANSPORT_CAPSULE_DRAIN_SESSION:
        if (length != 0)
            return H2O_WEBTRANSPORT_ERROR_PROTOCOL;
        sess->ingress.state = INGRESS_STATE_PAYLOAD;
        break;
    default:
        /* PADDING and unknown capsules are ignored (RFC 9297 section 3.2), as are those of flow control, which is required when
         * flow control is disabled (draft-ietf-webtrans-http3-16 section 5.1) */
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
    uint64_t type, length;

    if (h2o_webtransport_decode_capsule_header(&p, hdr_end, &type, &length) != 0) {
        /* the buffer is large enough to hold any header */
        assert(sess->ingress.hdr_len + copy < sizeof(sess->ingress.hdr));
        sess->ingress.hdr_len += copy;
        *src += copy;
        return 0;
    }

    /* consume the bytes that constitute the header, and handle the capsule */
    assert((size_t)(p - sess->ingress.hdr) > sess->ingress.hdr_len);
    *src += (p - sess->ingress.hdr) - sess->ingress.hdr_len;
    sess->ingress.hdr_len = 0;
    return begin_capsule(sess, type, length);
}

static quicly_error_t handle_input_step(struct st_capsule_session_t *sess, const uint8_t **src, const uint8_t *end)
{
    size_t avail = end - *src;

    switch (sess->ingress.state) {
    case INGRESS_STATE_HEADER:
        return handle_capsule_header(sess, src, end);
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

    assert(sess->egress.buf->size == 0);

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
            sess->super.callbacks->on_drain(&sess->super, 0);
    }

    do_send(sess);
}

static void on_generator_proceed(h2o_generator_t *generator, h2o_req_t *req)
{
    struct st_capsule_session_t *sess = H2O_STRUCT_FROM_MEMBER(struct st_capsule_session_t, generator, generator);

    assert(sess->egress.send_inflight);
    sess->egress.send_inflight = 0;
    h2o_buffer_consume(&sess->egress.buf, sess->egress.buf->size);

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

    h2o_buffer_dispose(&sess->ingress.payload);
    h2o_buffer_dispose(&sess->egress.buf);
    h2o_buffer_dispose(&sess->egress.pending);
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

static void native_stream_update_send_order(h2o_webtransport_stream_t *stream)
{
    get_session(stream)->native->stream_update_send_order(stream);
}

static size_t native_get_max_datagram_payload(h2o_webtransport_session_t *_sess)
{
    /* conservative while the datagrams are sent as capsules, before the datagram flow is set up */
    return ((struct st_capsule_session_t *)_sess)->native->get_max_datagram_payload(_sess);
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

static const h2o_webtransport_backend_t native_backend = {
    native_open_stream,
    native_stream_sync_sendbuf,
    native_stream_sync_recvbuf,
    native_reset_stream,
    native_request_stop,
    native_stream_update_send_order,
    native_get_max_datagram_payload,
    native_send_datagrams,
    capsule_drain,
    capsule_close,
};

int h2o_webtransport_is_request(h2o_req_t *req)
{
    return h2o_memis(req->method.base, req->method.len, H2O_STRLIT("CONNECT")) &&
           h2o_lcstris(req->upgrade.base, req->upgrade.len, H2O_STRLIT("webtransport-h3"));
}

h2o_webtransport_session_t *h2o_webtransport_accept(h2o_req_t *req, const h2o_webtransport_session_callbacks_t *callbacks,
                                                    void *data, h2o_iovec_t protocol)
{
    assert(callbacks->on_stream_open != NULL && callbacks->on_close != NULL);

    /* validate */
    if (!h2o_webtransport_is_request(req)) {
        h2o_send_error_400(req, "Bad Request", "not a WebTransport request", 0);
        return NULL;
    }
    /* the streams are carried natively by the protocol layer, which provides flow control as well */
    if (req->conn->callbacks->webtransport_attach == NULL) {
        h2o_send_error_400(req, "Bad Request", "WebTransport is not available", 0);
        return NULL;
    }

    /* instantiate the session */
    struct st_capsule_session_t *sess = h2o_mem_alloc_shared(&req->pool, sizeof(*sess), on_session_dispose);
    *sess = (struct st_capsule_session_t){{req, callbacks, data, &native_backend}, {on_generator_proceed, on_generator_stop}};
    sess->ingress.initial_pending = 1;
    h2o_buffer_init(&sess->ingress.payload, &h2o_socket_buffer_prototype);
    h2o_buffer_init(&sess->egress.buf, &h2o_socket_buffer_prototype);
    h2o_buffer_init(&sess->egress.pending, &h2o_socket_buffer_prototype);
    h2o_timer_init(&sess->egress.timer, on_timer);

    /* attach to the protocol layer that carries the streams */
    if ((sess->native = req->conn->callbacks->webtransport_attach(req, &sess->super)) == NULL) {
        sess->closing = 1; /* the session has never been visible to the application */
        h2o_send_error_400(req, "Bad Request", "WebTransport is not available", 0);
        return NULL;
    }
    sess->native_start_pending = 1;

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
    if (h2o_webtransport_stream_has_send_side(stream) && !quicly_sendstate_transfer_complete(&stream->sendstate))
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
                /* nothing is to be sent; the stream is being reset */
                *len = 0;
                *wrote_all = 1;
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

    int ret;
    if ((ret = (int)h2o_webtransport_stream_sync_sendbuf(stream, 1)) != 0) {
        /* revert, so that the vector is not retained when returning an error */
        --sb->vecs.size;
        sb->bytes_written -= vec->len;
    }
    return ret;
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
        /* once reset, the buffer might extend over ranges received out of order beyond the bytes that are to be delivered */
        avail = rb->off;
        if (stream->recvstate.eos - stream->recvstate.data_off < avail)
            avail = stream->recvstate.eos - stream->recvstate.data_off;
    } else if (stream->recvstate.data_off < stream->recvstate.received.first.ranges[0].end) {
        avail = stream->recvstate.received.first.ranges[0].end - stream->recvstate.data_off;
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
        if (rb->off < off + len && (ret = ptls_buffer_reserve(rb, off + len - rb->off)) != 0) {
            convert_error(stream, ret);
            return -1;
        }
        memcpy(rb->base + off, src, len);
        if (rb->off < off + len)
            rb->off = off + len;
    }
    return 0;
}
