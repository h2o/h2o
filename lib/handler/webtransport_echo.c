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

/**
 * A WebTransport echo server, written only against the `h2o_webtransport_*` API:
 *
 * - data received on a bidirectional stream opened by the client is echoed back on the same stream
 * - data received on a unidirectional stream opened by the client is echoed back on a unidirectional stream opened by the server
 * - datagrams are echoed back
 * - resets and STOP_SENDING are mirrored, using the same error code
 * - when the session is drained, it is closed with error code 0
 *
 * The query string of the CONNECT request can be used to exercise other paths:
 *
 * - `open-bidi=N` / `open-uni=N`: the server opens N streams, each sending "stream <id>\n" then FIN
 * - `drain`: the server sends WT_DRAIN_SESSION immediately
 * - `close=<code>`: the server closes the session with the given error code, once the first bidirectional stream opened by the
 *   client is fully echoed
 *
 * Received data is retained until it is acknowledged on the sending side, so the memory used by each stream is bounded by the
 * receive window.
 */
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include "h2o.h"

#define MAX_STREAMS_OPENED_BY_QUERY 100

struct st_echo_session_t {
    h2o_webtransport_session_t *wt;
    /**
     * set while opening a stream to echo the data received on a client-initiated unidirectional stream
     */
    h2o_webtransport_stream_t *opening_sink_for;
    uint32_t close_code;
    unsigned close_requested : 1;
};

struct st_echo_stream_t {
    h2o_webtransport_streambuf_t super;
    /**
     * The stream at the other end of the echo; for bidirectional streams it is the stream itself. For unidirectional streams, the
     * one opened by the client (source) and the one opened by the server (sink) point to each other. NULL once the other end is
     * destroyed, or if the stream is a greeting stream opened due to `open-bidi` / `open-uni`.
     */
    h2o_webtransport_stream_t *peer;
    /**
     * number of bytes at the head of the ingress buffer that have been written to the sink (used by the source)
     */
    size_t bytes_forwarded;
};

static void forward_input(h2o_webtransport_stream_t *source)
{
    struct st_echo_stream_t *self = source->data;
    h2o_webtransport_stream_t *sink = self->peer;
    ptls_iovec_t input = h2o_webtransport_streambuf_ingress_get(source);

    /* discard input if the data cannot be echoed back; the bytes already forwarded will not be acknowledged either, as the sink has
     * been destroyed or reset */
    if (sink == NULL || !quicly_sendstate_is_open(&sink->sendstate)) {
        h2o_webtransport_streambuf_ingress_shift(source, input.len);
        self->bytes_forwarded = 0;
        return;
    }

    /* write the data being received to the sink, retaining it in the ingress buffer until it is acknowledged */
    if (self->bytes_forwarded < input.len) {
        if (h2o_webtransport_streambuf_egress_write(sink, input.base + self->bytes_forwarded, input.len - self->bytes_forwarded) !=
            0) {
            h2o_webtransport_reset_stream(sink, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0));
            h2o_webtransport_request_stop(source, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0));
            return;
        }
        self->bytes_forwarded = input.len;
    }
    if (quicly_recvstate_transfer_complete(&source->recvstate))
        h2o_webtransport_streambuf_egress_shutdown(sink);
}

static void on_echo_receive(h2o_webtransport_stream_t *stream, size_t off, const void *src, size_t len)
{
    if (h2o_webtransport_streambuf_ingress_receive(stream, off, src, len) != 0)
        return;
    forward_input(stream);
}

static void on_echo_send_shift(h2o_webtransport_stream_t *stream, size_t delta)
{
    struct st_echo_stream_t *self = stream->data;

    h2o_webtransport_streambuf_egress_shift(stream, delta);

    /* release the acknowledged bytes retained by the source, returning flow control credit to the client */
    if (self->peer != NULL) {
        struct st_echo_stream_t *source = self->peer->data;
        assert(delta <= source->bytes_forwarded);
        source->bytes_forwarded -= delta;
        h2o_webtransport_streambuf_ingress_shift(self->peer, delta);
    }
}

static void on_echo_send_stop(h2o_webtransport_stream_t *stream, quicly_error_t err)
{
    struct st_echo_stream_t *self = stream->data;
    h2o_webtransport_stream_t *source = self->peer;

    if (source != NULL && QUICLY_ERROR_IS_QUIC_APPLICATION(err) && !quicly_recvstate_transfer_complete(&source->recvstate))
        h2o_webtransport_request_stop(source, err);
}

static void on_echo_receive_reset(h2o_webtransport_stream_t *stream, quicly_error_t err)
{
    struct st_echo_stream_t *self = stream->data;
    h2o_webtransport_stream_t *sink = self->peer;

    if (sink != NULL && QUICLY_ERROR_IS_QUIC_APPLICATION(err) && quicly_sendstate_is_open(&sink->sendstate))
        h2o_webtransport_reset_stream(sink, err);
}

static void on_echo_destroy(h2o_webtransport_stream_t *stream, quicly_error_t err)
{
    struct st_echo_stream_t *self = stream->data;
    struct st_echo_session_t *sess = stream->session->data;

    if (self->peer != NULL && self->peer != stream)
        ((struct st_echo_stream_t *)self->peer->data)->peer = NULL;
    h2o_webtransport_streambuf_destroy(stream, err);

    /* close the session if asked to, once the first bidirectional stream opened by the client is echoed */
    if (sess->close_requested && err == 0 && !h2o_webtransport_stream_is_server_initiated(stream->stream_id) &&
        !h2o_webtransport_stream_is_unidirectional(stream->stream_id)) {
        sess->close_requested = 0;
        h2o_webtransport_close(stream->session, sess->close_code, h2o_iovec_init(H2O_STRLIT("bye")));
    }
}

static const h2o_webtransport_stream_callbacks_t echo_callbacks = {
    on_echo_destroy,   on_echo_send_shift, h2o_webtransport_streambuf_egress_emit,
    on_echo_send_stop, on_echo_receive,    on_echo_receive_reset};

static void on_greeting_receive(h2o_webtransport_stream_t *stream, size_t off, const void *src, size_t len)
{
    /* data sent by the client on the greeting streams is discarded */
    if (h2o_webtransport_streambuf_ingress_receive(stream, off, src, len) != 0)
        return;
    h2o_webtransport_streambuf_ingress_shift(stream, h2o_webtransport_streambuf_ingress_get(stream).len);
}

static void on_greeting_send_stop(h2o_webtransport_stream_t *stream, quicly_error_t err)
{
}

static void on_greeting_receive_reset(h2o_webtransport_stream_t *stream, quicly_error_t err)
{
}

static const h2o_webtransport_stream_callbacks_t greeting_callbacks = {h2o_webtransport_streambuf_destroy,
                                                                       h2o_webtransport_streambuf_egress_shift,
                                                                       h2o_webtransport_streambuf_egress_emit,
                                                                       on_greeting_send_stop,
                                                                       on_greeting_receive,
                                                                       on_greeting_receive_reset};

static quicly_error_t on_stream_open(h2o_webtransport_stream_t *stream)
{
    struct st_echo_session_t *sess = stream->session->data;
    int ret;

    if ((ret = h2o_webtransport_streambuf_create(stream, sizeof(struct st_echo_stream_t))) != 0)
        return ret;
    struct st_echo_stream_t *self = stream->data;

    if (h2o_webtransport_stream_is_server_initiated(stream->stream_id)) {
        if (sess->opening_sink_for != NULL) {
            /* sink of a unidirectional echo */
            stream->callbacks = &echo_callbacks;
            self->peer = sess->opening_sink_for;
            ((struct st_echo_stream_t *)self->peer->data)->peer = stream;
        } else {
            stream->callbacks = &greeting_callbacks;
        }
    } else if (h2o_webtransport_stream_is_unidirectional(stream->stream_id)) {
        /* source of a unidirectional echo; open the sink */
        h2o_webtransport_stream_t *sink;
        quicly_error_t open_ret;
        stream->callbacks = &echo_callbacks;
        sess->opening_sink_for = stream;
        open_ret = h2o_webtransport_open_stream(stream->session, &sink, 1);
        sess->opening_sink_for = NULL;
        if (open_ret != 0)
            return QUICLY_ERROR_IS_QUIC_APPLICATION(open_ret) ? open_ret : QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0);
    } else {
        /* bidirectional echo */
        stream->callbacks = &echo_callbacks;
        self->peer = stream;
    }

    return 0;
}

static void on_receive_datagram(h2o_webtransport_session_t *session, h2o_iovec_t payload)
{
    h2o_webtransport_send_datagrams(session, &payload, 1);
}

static void on_drain(h2o_webtransport_session_t *session)
{
    h2o_webtransport_close(session, 0, h2o_iovec_init(NULL, 0));
}

static void on_close(h2o_webtransport_session_t *session, quicly_error_t err, h2o_iovec_t reason)
{
    /* nothing to do; the session object is allocated from the memory pool of the request */
}

static const h2o_webtransport_session_callbacks_t session_callbacks = {on_stream_open, on_receive_datagram, on_drain, on_close};

static void open_greeting_streams(h2o_webtransport_session_t *session, int uni, size_t count)
{
    for (size_t i = 0; i != count; ++i) {
        h2o_webtransport_stream_t *stream;
        char buf[sizeof("stream 18446744073709551615\n")];
        if (h2o_webtransport_open_stream(session, &stream, uni) != 0)
            return;
        int len = sprintf(buf, "stream %" PRId64 "\n", stream->stream_id);
        if (h2o_webtransport_streambuf_egress_write(stream, buf, len) != 0 ||
            h2o_webtransport_streambuf_egress_shutdown(stream) != 0) {
            h2o_webtransport_reset_stream(stream, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0));
            if (h2o_webtransport_stream_has_receive_side(stream))
                h2o_webtransport_request_stop(stream, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0));
        }
    }
}

/**
 * Parses the query parameter `name`. Returns if the parameter exists; `value` is set to the value, or to an empty string if the
 * parameter has no value.
 */
static int get_query_param(h2o_req_t *req, const char *name, h2o_iovec_t *value)
{
    if (req->query_at == SIZE_MAX)
        return 0;

    size_t name_len = strlen(name);
    const char *p = req->path.base + req->query_at + 1, *end = req->path.base + req->path.len;
    while (p < end) {
        const char *param_end = memchr(p, '&', end - p);
        if (param_end == NULL)
            param_end = end;
        if ((size_t)(param_end - p) >= name_len && memcmp(p, name, name_len) == 0) {
            if (p + name_len == param_end) {
                *value = h2o_iovec_init("", 0);
                return 1;
            } else if (p[name_len] == '=') {
                *value = h2o_iovec_init(p + name_len + 1, param_end - (p + name_len + 1));
                return 1;
            }
        }
        p = param_end + 1;
    }
    return 0;
}

static int get_query_number(h2o_req_t *req, const char *name, uint64_t max_value, uint64_t *value)
{
    h2o_iovec_t str;
    if (!get_query_param(req, name, &str))
        return 0;
    size_t v = h2o_strtosize(str.base, str.len);
    if (v == SIZE_MAX || v > max_value)
        return -1;
    *value = v;
    return 1;
}

static int on_req(h2o_handler_t *self, h2o_req_t *req)
{
    uint64_t num_bidi = 0, num_uni = 0, close_code = 0;
    int close_requested;
    h2o_iovec_t unused;

    if (!h2o_webtransport_is_request(req))
        return -1;

    if (get_query_number(req, "open-bidi", MAX_STREAMS_OPENED_BY_QUERY, &num_bidi) < 0 ||
        get_query_number(req, "open-uni", MAX_STREAMS_OPENED_BY_QUERY, &num_uni) < 0 ||
        (close_requested = get_query_number(req, "close", UINT32_MAX, &close_code)) < 0) {
        h2o_send_error_400(req, "Bad Request", "invalid query", 0);
        return 0;
    }

    struct st_echo_session_t *sess = h2o_mem_alloc_pool(&req->pool, *sess, 1);
    *sess = (struct st_echo_session_t){.close_code = (uint32_t)close_code, .close_requested = close_requested};
    if ((sess->wt = h2o_webtransport_accept(req, &session_callbacks, sess, h2o_iovec_init(NULL, 0))) == NULL)
        return 0;

    open_greeting_streams(sess->wt, 0, num_bidi);
    open_greeting_streams(sess->wt, 1, num_uni);
    if (get_query_param(req, "drain", &unused))
        h2o_webtransport_drain(sess->wt);

    return 0;
}

void h2o_webtransport_echo_register(h2o_pathconf_t *pathconf)
{
    h2o_handler_t *self = h2o_create_handler(pathconf, sizeof(*self));
    self->on_req = on_req;
}
