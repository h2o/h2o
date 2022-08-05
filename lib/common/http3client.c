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
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/types.h>
#include "quicly.h"
#include "h2o/hostinfo.h"
#include "h2o/httpclient.h"
#include "h2o/http2_common.h"
#include "h2o/http3_common.h"
#include "h2o/http3_internal.h"
#include "../probes_.h"

/**
 * internal error code used for signalling EOS
 */
#define ERROR_EOS H2O_HTTP3_ERROR_USER1
/**
 * Maxmium amount of unsent bytes to be buffered when acting as a tunnel.
 */
#define TUNNEL_MAX_UNSENT 16384

struct st_h2o_http3client_req_t {
    /**
     * superclass
     */
    h2o_httpclient_t super;
    /**
     * pointer to the connection
     */
    struct st_h2o_httpclient__h3_conn_t *conn;
    /**
     * is NULL until connection is established
     */
    quicly_stream_t *quic;
    /**
     * currently only used for pending_requests
     */
    h2o_linklist_t link;
    /**
     *
     */
    uint64_t bytes_left_in_data_frame;
    /**
     *
     */
    h2o_buffer_t *sendbuf;
    /**
     *
     */
    struct {
        /**
         * HTTP-level buffer that contains (part of) response body received. Is the variable registered as `h2o_httpclient::buf`.
         */
        h2o_buffer_t *body;
        /**
         * QUIC stream-level buffer that contains bytes that have not yet been processed at the HTTP/3 framing decoding level. This
         * buffer may have gaps. The beginning offset of `partial_frame` is equal to `recvstate.data_off`.
         */
        h2o_buffer_t *stream;
        /**
         * Retains the amount of stream-level data that was available in the previous call. This value is used to see if processing
         * of new stream data is necessary.
         */
        size_t prev_bytes_available;
    } recvbuf;
    /**
     * called when new contigious data becomes available
     */
    int (*handle_input)(struct st_h2o_http3client_req_t *req, const uint8_t **src, const uint8_t *src_end, int err,
                        const char **err_desc);
    /**
     * `proceed_req` callback. The callback is invoked when all bytes in the send buffer is emitted for the first time.
     * `bytes_inflight` contains the number of bytes being transmitted, or SIZE_MAX if nothing is inflight.
     */
    struct {
        h2o_httpclient_proceed_req_cb cb;
        size_t bytes_inflight;
    } proceed_req;
    /**
     *
     */
    enum {
        H2O_HTTP3CLIENT_RESPONSE_STATE_HEAD,
        H2O_HTTP3CLIENT_RESPONSE_STATE_BODY,
        H2O_HTTP3CLIENT_RESPONSE_STATE_CLOSED
    } response_state;
    /**
     * callback used for forwarding CONNECT-UDP using H3_DATAGRAMS
     */
    h2o_httpclient_forward_datagram_cb on_read_datagrams;
    /**
     * flags
     */
    unsigned offered_datagram_flow_id : 1;
};

static int handle_input_expect_data_frame(struct st_h2o_http3client_req_t *req, const uint8_t **src, const uint8_t *src_end,
                                          int err, const char **err_desc);
static void start_request(struct st_h2o_http3client_req_t *req);
static int do_write_req(h2o_httpclient_t *_client, h2o_iovec_t chunk, int is_end_stream);

static size_t emit_data(struct st_h2o_http3client_req_t *req, h2o_iovec_t payload)
{
    size_t nbytes;

    { /* emit header */
        uint8_t buf[9], *p = buf;
        *p++ = H2O_HTTP3_FRAME_TYPE_DATA;
        p = quicly_encodev(p, payload.len);
        nbytes = p - buf;
        h2o_buffer_append(&req->sendbuf, buf, nbytes);
    }

    /* emit payload */
    h2o_buffer_append(&req->sendbuf, payload.base, payload.len);
    nbytes += payload.len;

    return nbytes;
}

static void destroy_request(struct st_h2o_http3client_req_t *req)
{
    assert(req->quic == NULL);

    h2o_buffer_dispose(&req->sendbuf);
    h2o_buffer_dispose(&req->recvbuf.body);
    h2o_buffer_dispose(&req->recvbuf.stream);
    if (h2o_timer_is_linked(&req->super._timeout))
        h2o_timer_unlink(&req->super._timeout);
    if (h2o_linklist_is_linked(&req->link))
        h2o_linklist_unlink(&req->link);
    free(req);
}

static void detach_stream(struct st_h2o_http3client_req_t *req)
{
    req->quic->callbacks = &quicly_stream_noop_callbacks;
    req->quic->data = NULL;
    req->quic = NULL;
}

static void close_stream(struct st_h2o_http3client_req_t *req, int err)
{
    /* TODO are we expected to send two error codes? */
    if (!quicly_sendstate_transfer_complete(&req->quic->sendstate))
        quicly_reset_stream(req->quic, err);
    if (!quicly_recvstate_transfer_complete(&req->quic->recvstate))
        quicly_request_stop(req->quic, err);
    detach_stream(req);
}

static void write_datagrams(h2o_httpclient_t *_client, h2o_iovec_t *datagrams, size_t num_datagrams)
{
    struct st_h2o_http3client_req_t *req = H2O_STRUCT_FROM_MEMBER(struct st_h2o_http3client_req_t, super, _client);
    h2o_http3_send_h3_datagrams(&req->conn->super, req->quic->stream_id, datagrams, num_datagrams);
}

static struct st_h2o_httpclient__h3_conn_t *find_connection(h2o_httpclient_connection_pool_t *pool, h2o_url_t *origin)
{
    int should_check_target = h2o_socketpool_is_global(pool->socketpool);

    /* FIXME:
     * - check connection state(e.g., max_concurrent_streams, if received GOAWAY)
     * - use hashmap
     */
    for (h2o_linklist_t *l = pool->http3.conns.next; l != &pool->http3.conns; l = l->next) {
        struct st_h2o_httpclient__h3_conn_t *conn = H2O_STRUCT_FROM_MEMBER(struct st_h2o_httpclient__h3_conn_t, link, l);
        if (should_check_target && !(conn->server.origin_url.scheme == origin->scheme &&
                                     h2o_memis(conn->server.origin_url.authority.base, conn->server.origin_url.authority.len,
                                               origin->authority.base, origin->authority.len)))
            continue;
        return conn;
    }

    return NULL;
}

static void start_pending_requests(struct st_h2o_httpclient__h3_conn_t *conn)
{
    while (!h2o_linklist_is_empty(&conn->pending_requests)) {
        struct st_h2o_http3client_req_t *req =
            H2O_STRUCT_FROM_MEMBER(struct st_h2o_http3client_req_t, link, conn->pending_requests.next);
        h2o_linklist_unlink(&req->link);
        start_request(req);
    }
}

static void call_proceed_req(struct st_h2o_http3client_req_t *req, const char *errstr)
{
    req->proceed_req.bytes_inflight = SIZE_MAX;
    req->proceed_req.cb(&req->super, errstr);
}

static void destroy_connection(struct st_h2o_httpclient__h3_conn_t *conn, const char *errstr)
{
    assert(errstr != NULL);
    if (h2o_linklist_is_linked(&conn->link))
        h2o_linklist_unlink(&conn->link);
    while (!h2o_linklist_is_empty(&conn->pending_requests)) {
        struct st_h2o_http3client_req_t *req =
            H2O_STRUCT_FROM_MEMBER(struct st_h2o_http3client_req_t, link, conn->pending_requests.next);
        h2o_linklist_unlink(&req->link);
        req->super._cb.on_connect(&req->super, errstr, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
        destroy_request(req);
    }
    assert(h2o_linklist_is_empty(&conn->pending_requests));
    if (conn->getaddr_req != NULL)
        h2o_hostinfo_getaddr_cancel(conn->getaddr_req);
    h2o_timer_unlink(&conn->timeout);
    free(conn->server.origin_url.authority.base);
    free(conn->server.origin_url.host.base);
    free(conn->handshake_properties.client.session_ticket.base);
    h2o_http3_dispose_conn(&conn->super);
    free(conn);
}

static void destroy_connection_on_transport_close(h2o_quic_conn_t *_conn)
{
    struct st_h2o_httpclient__h3_conn_t *conn = (void *)_conn;

    /* When a connection gets closed while request is inflight, the most probable cause is some error in the transport (or at the
     * application protocol layer). But as we do not know the exact cause, we use a generic error here. */
    destroy_connection(conn, h2o_httpclient_error_io);
}

static void on_connect_timeout(h2o_timer_t *timeout)
{
    struct st_h2o_httpclient__h3_conn_t *conn = H2O_STRUCT_FROM_MEMBER(struct st_h2o_httpclient__h3_conn_t, timeout, timeout);
    destroy_connection(conn, h2o_httpclient_error_connect_timeout);
}

static void start_connect(struct st_h2o_httpclient__h3_conn_t *conn, struct sockaddr *sa)
{
    quicly_conn_t *qconn;
    ptls_iovec_t address_token = ptls_iovec_init(NULL, 0);
    quicly_transport_parameters_t resumed_tp;
    int ret;

    assert(conn->super.super.quic == NULL);
    assert(conn->getaddr_req == NULL);
    assert(h2o_timer_is_linked(&conn->timeout));
    assert(conn->timeout.cb == on_connect_timeout);

    /* create QUIC connection context and attach */
    if (conn->ctx->http3->load_session != NULL) {
        if (!conn->ctx->http3->load_session(conn->ctx, sa, conn->server.origin_url.host.base, &address_token,
                                            &conn->handshake_properties.client.session_ticket, &resumed_tp))
            goto Fail;
    }
    if ((ret = quicly_connect(&qconn, &conn->ctx->http3->quic, conn->server.origin_url.host.base, sa, NULL,
                              &conn->ctx->http3->h3.next_cid, address_token, &conn->handshake_properties,
                              conn->handshake_properties.client.session_ticket.base != NULL ? &resumed_tp : NULL)) != 0) {
        conn->super.super.quic = NULL; /* just in case */
        goto Fail;
    }
    ++conn->ctx->http3->h3.next_cid.master_id; /* FIXME check overlap */
    if ((ret = h2o_http3_setup(&conn->super, qconn)) != 0)
        goto Fail;

    if (quicly_connection_is_ready(conn->super.super.quic))
        start_pending_requests(conn);

    h2o_quic_send(&conn->super.super);

    free(address_token.base);
    return;
Fail:
    free(address_token.base);
    destroy_connection(conn, h2o_httpclient_error_internal);
}

static void on_getaddr(h2o_hostinfo_getaddr_req_t *getaddr_req, const char *errstr, struct addrinfo *res, void *_conn)
{
    struct st_h2o_httpclient__h3_conn_t *conn = _conn;

    assert(getaddr_req == conn->getaddr_req);
    conn->getaddr_req = NULL;

    if (errstr != NULL) {
        destroy_connection(conn, errstr);
        return;
    }

    struct addrinfo *selected = h2o_hostinfo_select_one(res);
    start_connect(conn, selected->ai_addr);
}

static void handle_control_stream_frame(h2o_http3_conn_t *_conn, uint8_t type, const uint8_t *payload, size_t len)
{
    struct st_h2o_httpclient__h3_conn_t *conn = (void *)_conn;
    int err;
    const char *err_desc = NULL;

    if (!h2o_http3_has_received_settings(&conn->super)) {
        if (type != H2O_HTTP3_FRAME_TYPE_SETTINGS) {
            err = H2O_HTTP3_ERROR_MISSING_SETTINGS;
            goto Fail;
        }
        if ((err = h2o_http3_handle_settings_frame(&conn->super, payload, len, &err_desc)) != 0)
            goto Fail;
        assert(h2o_http3_has_received_settings(&conn->super));
        /* issue requests (unless it has been done already due to 0-RTT key being available) */
        start_pending_requests(conn);
    } else {
        switch (type) {
        case H2O_HTTP3_FRAME_TYPE_SETTINGS:
            err = H2O_HTTP3_ERROR_FRAME_UNEXPECTED;
            err_desc = "unexpected SETTINGS frame";
            goto Fail;
        case H2O_HTTP3_FRAME_TYPE_GOAWAY: {
            h2o_http3_goaway_frame_t frame;
            if ((err = h2o_http3_decode_goaway_frame(&frame, payload, len, &err_desc)) != 0)
                goto Fail;
            /* FIXME: stop issuing new requests */
            break;
        }
        default:
            break;
        }
    }

    return;
Fail:
    h2o_quic_close_connection(&conn->super.super, err, err_desc);
}

struct st_h2o_httpclient__h3_conn_t *create_connection(h2o_httpclient_ctx_t *ctx, h2o_httpclient_connection_pool_t *pool,
                                                       h2o_url_t *origin)
{
    /* FIXME When using a non-global socket pool, let the socket pool load balance H3 connections among the list of targets being
     * available. But until then, we use the first entry. */
    if (!h2o_socketpool_is_global(pool->socketpool))
        origin = &pool->socketpool->targets.entries[0]->url;

    static const h2o_http3_conn_callbacks_t callbacks = {{destroy_connection_on_transport_close}, handle_control_stream_frame};
    static const h2o_http3_qpack_context_t qpack_ctx = {0 /* TODO */};

    struct st_h2o_httpclient__h3_conn_t *conn = h2o_mem_alloc(sizeof(*conn));

    h2o_http3_init_conn(&conn->super, &ctx->http3->h3, &callbacks, &qpack_ctx);
    memset((char *)conn + sizeof(conn->super), 0, sizeof(*conn) - sizeof(conn->super));
    conn->ctx = ctx;
    h2o_url_copy(NULL, &conn->server.origin_url, origin);
    sprintf(conn->server.named_serv, "%" PRIu16, h2o_url_get_port(origin));
    conn->handshake_properties.client.negotiated_protocols.list = h2o_http3_alpn;
    conn->handshake_properties.client.negotiated_protocols.count = sizeof(h2o_http3_alpn) / sizeof(h2o_http3_alpn[0]);
    h2o_linklist_insert(&pool->http3.conns, &conn->link);
    h2o_linklist_init_anchor(&conn->pending_requests);

    conn->getaddr_req = h2o_hostinfo_getaddr(conn->ctx->getaddr_receiver, conn->server.origin_url.host,
                                             h2o_iovec_init(conn->server.named_serv, strlen(conn->server.named_serv)), AF_UNSPEC,
                                             SOCK_DGRAM, IPPROTO_UDP, AI_ADDRCONFIG | AI_NUMERICSERV, on_getaddr, conn);
    h2o_timer_link(conn->ctx->loop, conn->ctx->connect_timeout, &conn->timeout);
    conn->timeout.cb = on_connect_timeout;

    return conn;
}

static void notify_response_error(struct st_h2o_http3client_req_t *req, const char *errstr)
{
    assert(errstr != NULL);

    switch (req->response_state) {
    case H2O_HTTP3CLIENT_RESPONSE_STATE_HEAD:
        req->super._cb.on_head(&req->super, errstr, NULL);
        break;
    case H2O_HTTP3CLIENT_RESPONSE_STATE_BODY:
        req->super._cb.on_body(&req->super, errstr);
        break;
    default:
        break;
    }
    req->response_state = H2O_HTTP3CLIENT_RESPONSE_STATE_CLOSED;
}

static int call_on_body(struct st_h2o_http3client_req_t *req, const char *errstr)
{
    assert(req->response_state == H2O_HTTP3CLIENT_RESPONSE_STATE_BODY);

    int ret = req->super._cb.on_body(&req->super, errstr);
    if (errstr != NULL)
        req->response_state = H2O_HTTP3CLIENT_RESPONSE_STATE_CLOSED;

    return ret;
}

static int handle_input_data_payload(struct st_h2o_http3client_req_t *req, const uint8_t **src, const uint8_t *src_end, int err,
                                     const char **err_desc)
{
    /* save data, update states */
    if (req->bytes_left_in_data_frame != 0) {
        size_t payload_bytes = req->bytes_left_in_data_frame;
        if (src_end - *src < payload_bytes)
            payload_bytes = src_end - *src;
        h2o_buffer_append(&req->recvbuf.body, *src, payload_bytes);
        *src += payload_bytes;
        req->bytes_left_in_data_frame -= payload_bytes;
    }
    if (req->bytes_left_in_data_frame == 0)
        req->handle_input = handle_input_expect_data_frame;

    /* call the handler */
    const char *errstr = NULL;
    if (*src == src_end && err != 0) {
        /* FIXME also check content-length? see what other protocol handlers do */
        errstr = err == ERROR_EOS && req->bytes_left_in_data_frame == 0 ? h2o_httpclient_error_is_eos : h2o_httpclient_error_io;
    }
    if (call_on_body(req, errstr) != 0)
        return H2O_HTTP3_ERROR_INTERNAL;

    return 0;
}

int handle_input_expect_data_frame(struct st_h2o_http3client_req_t *req, const uint8_t **src, const uint8_t *src_end, int err,
                                   const char **err_desc)
{
    assert(req->bytes_left_in_data_frame == 0);
    if (*src == src_end) {
        /* return early if no input, no state change */
        if (err == 0)
            return 0;
        /* either EOS or an unexpected close; delegate the task to the payload processing function */
    } else {
        /* otherwise, read the frame */
        h2o_http3_read_frame_t frame;
        int ret;
        if ((ret = h2o_http3_read_frame(&frame, 1, H2O_HTTP3_STREAM_TYPE_REQUEST, src, src_end, err_desc)) != 0) {
            /* incomplete */
            if (ret == H2O_HTTP3_ERROR_INCOMPLETE && err == 0)
                return ret;
            call_on_body(req, h2o_httpclient_error_malformed_frame);
            return ret;
        }
        switch (frame.type) {
        case H2O_HTTP3_FRAME_TYPE_DATA:
            break;
        case H2O_HTTP3_FRAME_TYPE_HEADERS:
            if (req->super.upgrade_to == h2o_httpclient_upgrade_to_connect)
                return H2O_HTTP3_ERROR_FRAME_UNEXPECTED;
            /* flow continues */
        default:
            /* FIXME handle push_promise, trailers */
            return 0;
        }
        req->bytes_left_in_data_frame = frame.length;
    }

    /* unexpected close of DATA frame is handled by handle_input_data_payload. We rely on the function to detect if the DATA frame
     * is closed right after the frame header */
    req->handle_input = handle_input_data_payload;
    return handle_input_data_payload(req, src, src_end, err, err_desc);
}

static int handle_input_expect_headers(struct st_h2o_http3client_req_t *req, const uint8_t **src, const uint8_t *src_end, int err,
                                       const char **err_desc)
{
    h2o_http3_read_frame_t frame;
    int status;
    h2o_headers_t headers = {NULL};
    h2o_iovec_t datagram_flow_id = {};
    uint8_t header_ack[H2O_HPACK_ENCODE_INT_MAX_LENGTH];
    size_t header_ack_len;
    int ret, frame_is_eos;

    /* read HEADERS frame */
    if ((ret = h2o_http3_read_frame(&frame, 1, H2O_HTTP3_STREAM_TYPE_REQUEST, src, src_end, err_desc)) != 0) {
        if (ret == H2O_HTTP3_ERROR_INCOMPLETE) {
            if (err != 0) {
                notify_response_error(req, h2o_httpclient_error_io);
                return 0;
            }
            return ret;
        }
        notify_response_error(req, "response header too large");
        return H2O_HTTP3_ERROR_EXCESSIVE_LOAD; /* FIXME correct code? */
    }
    frame_is_eos = *src == src_end && err != 0;
    if (frame.type != H2O_HTTP3_FRAME_TYPE_HEADERS) {
        switch (frame.type) {
        case H2O_HTTP3_FRAME_TYPE_DATA:
            *err_desc = "received DATA frame before HEADERS";
            return H2O_HTTP3_ERROR_FRAME_UNEXPECTED;
        default:
            return 0;
        }
    }
    if ((ret = h2o_qpack_parse_response(req->super.pool, req->conn->super.qpack.dec, req->quic->stream_id, &status, &headers,
                                        &datagram_flow_id, header_ack, &header_ack_len, frame.payload, frame.length, err_desc)) !=
        0) {
        if (ret == H2O_HTTP2_ERROR_INCOMPLETE) {
            /* the request is blocked by the QPACK stream */
            req->handle_input = NULL; /* FIXME */
            return 0;
        }
        if (*err_desc == NULL)
            *err_desc = "qpack error";
        notify_response_error(req, *err_desc);
        return H2O_HTTP3_ERROR_GENERAL_PROTOCOL; /* FIXME */
    }
    if (header_ack_len != 0)
        h2o_http3_send_qpack_header_ack(&req->conn->super, header_ack, header_ack_len);

    if (datagram_flow_id.base != NULL) {
        if (!req->offered_datagram_flow_id) {
            *err_desc = "no offered datagram-flow-id";
            return H2O_HTTP3_ERROR_GENERAL_PROTOCOL;
        }
        /* TODO validate the returned value */
    }

    /* handle 1xx */
    if (100 <= status && status <= 199) {
        if (status == 101) {
            *err_desc = "unexpected 101";
            notify_response_error(req, *err_desc);
            return H2O_HTTP3_ERROR_GENERAL_PROTOCOL;
        }
        if (frame_is_eos) {
            notify_response_error(req, h2o_httpclient_error_io);
            return 0;
        }
        if (req->super.informational_cb != NULL &&
            req->super.informational_cb(&req->super, 0x300, status, h2o_iovec_init(NULL, 0), headers.entries, headers.size) != 0) {
            return H2O_HTTP3_ERROR_INTERNAL;
        }
        return 0;
    }

    /* handle final response, creating tunnel object if necessary */
    h2o_httpclient_on_head_t on_head = {.version = 0x300,
                                        .msg = h2o_iovec_init(NULL, 0),
                                        .status = status,
                                        .headers = headers.entries,
                                        .num_headers = headers.size};
    if (h2o_httpclient__tunnel_is_ready(&req->super, status) && datagram_flow_id.base != NULL) {
        on_head.forward_datagram.write_ = write_datagrams;
        on_head.forward_datagram.read_ = &req->on_read_datagrams;
    }
    req->super._cb.on_body = req->super._cb.on_head(&req->super, frame_is_eos ? h2o_httpclient_error_is_eos : NULL, &on_head);
    req->response_state = H2O_HTTP3CLIENT_RESPONSE_STATE_BODY;
    if (req->super._cb.on_body == NULL)
        return frame_is_eos ? 0 : H2O_HTTP3_ERROR_INTERNAL;

    /* handle body */
    req->handle_input = handle_input_expect_data_frame;
    return 0;
}

static void on_stream_destroy(quicly_stream_t *qs, int err)
{
    struct st_h2o_http3client_req_t *req;

    if ((req = qs->data) == NULL)
        return;
    notify_response_error(req, h2o_httpclient_error_io);
    detach_stream(req);
    destroy_request(req);
}

static void on_send_shift(quicly_stream_t *qs, size_t delta)
{
    struct st_h2o_http3client_req_t *req = qs->data;

    assert(req != NULL);
    h2o_buffer_consume(&req->sendbuf, delta);
}

static void on_send_emit(quicly_stream_t *qs, size_t off, void *dst, size_t *len, int *wrote_all)
{
    struct st_h2o_http3client_req_t *req = qs->data;

    if (*len >= req->sendbuf->size - off) {
        *len = req->sendbuf->size - off;
        *wrote_all = 1;
    } else {
        *wrote_all = 0;
    }
    memcpy(dst, req->sendbuf->bytes + off, *len);

    if (*wrote_all && req->proceed_req.bytes_inflight != SIZE_MAX)
        call_proceed_req(req, NULL);
}

static void on_send_stop(quicly_stream_t *qs, int err)
{
    struct st_h2o_http3client_req_t *req;

    if ((req = qs->data) == NULL)
        return;

    if (!quicly_sendstate_transfer_complete(&req->quic->sendstate))
        quicly_reset_stream(req->quic, err);

    if (req->proceed_req.bytes_inflight != SIZE_MAX)
        call_proceed_req(req, h2o_httpclient_error_io /* TODO better error code? */);

    if (!quicly_recvstate_transfer_complete(&req->quic->recvstate)) {
        quicly_request_stop(req->quic, H2O_HTTP3_ERROR_REQUEST_CANCELLED);
        notify_response_error(req, h2o_httpclient_error_io);
    }
    detach_stream(req);
    destroy_request(req);
}

static int on_receive_process_bytes(struct st_h2o_http3client_req_t *req, const uint8_t **src, const uint8_t *src_end,
                                    const char **err_desc)
{
    int ret, is_eos = quicly_recvstate_transfer_complete(&req->quic->recvstate);
    assert(is_eos || *src != src_end);

    do {
        if ((ret = req->handle_input(req, src, src_end, is_eos ? ERROR_EOS : 0, err_desc)) != 0) {
            if (ret == H2O_HTTP3_ERROR_INCOMPLETE)
                ret = is_eos ? H2O_HTTP3_ERROR_FRAME : 0;
            break;
        }
    } while (*src != src_end);

    return ret;
}

static void on_receive(quicly_stream_t *qs, size_t off, const void *input, size_t len)
{
    struct st_h2o_http3client_req_t *req = qs->data;
    size_t bytes_consumed;
    int err = 0;
    const char *err_desc = NULL;

    /* process the input, update stream-level receive buffer */
    if (req->recvbuf.stream->size == 0 && off == 0) {

        /* fast path; process the input directly, save the remaining bytes */
        const uint8_t *src = input;
        err = on_receive_process_bytes(req, &src, src + len, &err_desc);
        bytes_consumed = src - (const uint8_t *)input;
        if (bytes_consumed != len)
            h2o_buffer_append(&req->recvbuf.stream, src, len - bytes_consumed);
    } else {
        /* slow path; copy data to partial_frame */
        size_t size_required = off + len;
        if (req->recvbuf.stream->size < size_required) {
            h2o_buffer_reserve(&req->recvbuf.stream, size_required - req->recvbuf.stream->size);
            req->recvbuf.stream->size = size_required;
        }
        memcpy(req->recvbuf.stream->bytes + off, input, len);

        /* just return if no new data is available */
        size_t bytes_available = quicly_recvstate_bytes_available(&req->quic->recvstate);
        if (req->recvbuf.prev_bytes_available == bytes_available)
            return;

        /* process the bytes that have not been processed, update stream-level buffer */
        const uint8_t *src = (const uint8_t *)req->recvbuf.stream->bytes;
        err = on_receive_process_bytes(req, &src, (const uint8_t *)req->recvbuf.stream->bytes + bytes_available, &err_desc);
        bytes_consumed = src - (const uint8_t *)req->recvbuf.stream->bytes;
        h2o_buffer_consume(&req->recvbuf.stream, bytes_consumed);
    }

    /* update QUIC stream-level state */
    if (bytes_consumed != 0)
        quicly_stream_sync_recvbuf(req->quic, bytes_consumed);
    req->recvbuf.prev_bytes_available = quicly_recvstate_bytes_available(&req->quic->recvstate);

    /* cleanup */
    if (quicly_recvstate_transfer_complete(&req->quic->recvstate)) {
        /* destroy the request if send-side is already closed, otherwise wait until the send-side gets closed */
        if (quicly_sendstate_transfer_complete(&req->quic->sendstate)) {
            detach_stream(req);
            destroy_request(req);
        }
    } else if (err != 0) {
        notify_response_error(req, h2o_httpclient_error_io);
        int send_is_open = quicly_sendstate_is_open(&req->quic->sendstate);
        close_stream(req, err);
        /* immediately dispose of the request if possible, or wait for the send-side to close */
        if (!send_is_open) {
            destroy_request(req);
        } else if (req->proceed_req.bytes_inflight != SIZE_MAX) {
            call_proceed_req(req, h2o_httpclient_error_io);
            destroy_request(req);
        } else {
            /* wait for write_req to be called */
        }
    }
}

static void on_receive_reset(quicly_stream_t *qs, int err)
{
    struct st_h2o_http3client_req_t *req = qs->data;

    notify_response_error(req, h2o_httpclient_error_io);
    close_stream(req, H2O_HTTP3_ERROR_REQUEST_CANCELLED);
    destroy_request(req);
}

void start_request(struct st_h2o_http3client_req_t *req)
{
    h2o_iovec_t method;
    h2o_url_t url;
    const h2o_header_t *headers;
    size_t num_headers;
    h2o_iovec_t body;
    h2o_httpclient_properties_t props = {NULL};
    char datagram_flow_id_buf[sizeof(H2O_UINT64_LONGEST_STR)];
    int ret;

    assert(req->quic == NULL);
    assert(!h2o_linklist_is_linked(&req->link));

    if ((req->super._cb.on_head = req->super._cb.on_connect(&req->super, NULL, &method, &url, &headers, &num_headers, &body,
                                                            &req->proceed_req.cb, &props, &req->conn->server.origin_url)) == NULL) {
        destroy_request(req);
        return;
    }

    if ((ret = quicly_open_stream(req->conn->super.super.quic, &req->quic, 0)) != 0) {
        notify_response_error(req, "failed to open stream");
        destroy_request(req);
        return;
    }
    req->quic->data = req;

    /* send request (TODO optimize) */
    h2o_iovec_t datagram_flow_id = {};
    if (req->super.upgrade_to == h2o_httpclient_upgrade_to_connect &&
        h2o_memis(method.base, method.len, H2O_STRLIT("CONNECT-UDP")) && req->conn->super.peer_settings.h3_datagram) {
        datagram_flow_id.len = sprintf(datagram_flow_id_buf, "%" PRIu64, req->quic->stream_id);
        datagram_flow_id.base = datagram_flow_id_buf;
        req->offered_datagram_flow_id = 1;
    }
    h2o_iovec_t headers_frame =
        h2o_qpack_flatten_request(req->conn->super.qpack.enc, req->super.pool, req->quic->stream_id, NULL, method, url.scheme,
                                  url.authority, url.path, headers, num_headers, datagram_flow_id);
    h2o_buffer_append(&req->sendbuf, headers_frame.base, headers_frame.len);
    if (body.len != 0)
        emit_data(req, body);
    if (req->proceed_req.cb != NULL) {
        req->super.write_req = do_write_req;
        if (body.len != 0)
            req->proceed_req.bytes_inflight = body.len;
    }
    if (req->proceed_req.cb == NULL && req->super.upgrade_to == NULL)
        quicly_sendstate_shutdown(&req->quic->sendstate, req->sendbuf->size);
    quicly_stream_sync_sendbuf(req->quic, 1);

    req->handle_input = handle_input_expect_headers;
}

static void cancel_request(h2o_httpclient_t *_client)
{
    struct st_h2o_http3client_req_t *req = (void *)_client;
    if (req->quic != NULL)
        close_stream(req, H2O_HTTP3_ERROR_REQUEST_CANCELLED);
    destroy_request(req);
}

static void do_get_conn_properties(h2o_httpclient_t *_client, h2o_httpclient_conn_properties_t *properties)
{
    struct st_h2o_http3client_req_t *req = (void *)_client;
    ptls_t *tls;
    ptls_cipher_suite_t *cipher;

    if (req->quic != NULL && (tls = quicly_get_tls(req->quic->conn), (cipher = ptls_get_cipher(tls)) != NULL)) {
        properties->ssl.protocol_version = "TLSv1.3";
        properties->ssl.session_reused = ptls_is_psk_handshake(tls);
        properties->ssl.cipher = cipher->aead->name;
        properties->ssl.cipher_bits = (int)cipher->aead->key_size;
    } else {
        properties->ssl.protocol_version = NULL;
        properties->ssl.session_reused = -1;
        properties->ssl.cipher = NULL;
        properties->ssl.cipher_bits = 0;
    }
    properties->sock = NULL;
}

static void do_update_window(h2o_httpclient_t *_client)
{
    /* TODO Stop receiving data for the stream when `buf` grows to certain extent. Then, resume when this function is being called.
     */
}

int do_write_req(h2o_httpclient_t *_client, h2o_iovec_t chunk, int is_end_stream)
{
    struct st_h2o_http3client_req_t *req = (void *)_client;

    assert(req->proceed_req.bytes_inflight == SIZE_MAX);

    /* Notify error to the application, if the stream has already been closed (due to e.g., a stream error) or if the send-side has
     * been closed (due to STOP_SENDING). Also, destroy the request if the receive side has already been closed. */
    if (req->quic == NULL || !quicly_sendstate_is_open(&req->quic->sendstate)) {
        if (req->quic != NULL && quicly_recvstate_transfer_complete(&req->quic->recvstate))
            close_stream(req, H2O_HTTP3_ERROR_REQUEST_CANCELLED);
        if (req->quic == NULL)
            destroy_request(req);
        return 1;
    }

    emit_data(req, chunk);

    /* shutdown if we've written all request body */
    if (is_end_stream) {
        assert(quicly_sendstate_is_open(&req->quic->sendstate));
        quicly_sendstate_shutdown(&req->quic->sendstate, req->quic->sendstate.acked.ranges[0].end + req->sendbuf->size);
    } else {
        assert(chunk.len != 0);
    }

    req->proceed_req.bytes_inflight = chunk.len;
    quicly_stream_sync_sendbuf(req->quic, 1);
    h2o_quic_schedule_timer(&req->conn->super.super);
    return 0;
}

void h2o_httpclient__connect_h3(h2o_httpclient_t **_client, h2o_mem_pool_t *pool, void *data, h2o_httpclient_ctx_t *ctx,
                                h2o_httpclient_connection_pool_t *connpool, h2o_url_t *target, const char *upgrade_to,
                                h2o_httpclient_connect_cb cb)
{
    struct st_h2o_httpclient__h3_conn_t *conn;
    struct st_h2o_http3client_req_t *req;

    assert(upgrade_to == NULL || upgrade_to == h2o_httpclient_upgrade_to_connect);

    if ((conn = find_connection(connpool, target)) == NULL)
        conn = create_connection(ctx, connpool, target);

    req = h2o_mem_alloc(sizeof(*req));
    *req = (struct st_h2o_http3client_req_t){
        .super = {pool,
                  ctx,
                  connpool,
                  &req->recvbuf.body,
                  data,
                  NULL,
                  {h2o_gettimeofday(ctx->loop)},
                  upgrade_to,
                  {0},
                  {0},
                  cancel_request,
                  do_get_conn_properties,
                  do_update_window},
        .conn = conn,
        .proceed_req = {.cb = NULL, .bytes_inflight = SIZE_MAX},
    };
    req->super._cb.on_connect = cb;
    h2o_buffer_init(&req->sendbuf, &h2o_socket_buffer_prototype);
    h2o_buffer_init(&req->recvbuf.body, &h2o_socket_buffer_prototype);
    h2o_buffer_init(&req->recvbuf.stream, &h2o_socket_buffer_prototype);

    if (_client != NULL)
        *_client = &req->super;

    if (h2o_http3_has_received_settings(&conn->super)) {
        start_request(req);
        h2o_quic_schedule_timer(&conn->super.super);
    } else {
        h2o_linklist_insert(&conn->pending_requests, &req->link);
    }
}

void h2o_httpclient_http3_notify_connection_update(h2o_quic_ctx_t *ctx, h2o_quic_conn_t *_conn)
{
    struct st_h2o_httpclient__h3_conn_t *conn = (void *)_conn;

    if (h2o_timer_is_linked(&conn->timeout) && conn->timeout.cb == on_connect_timeout) {
        /* TODO check connection state? */
        h2o_timer_unlink(&conn->timeout);
    }
}

static int stream_open_cb(quicly_stream_open_t *self, quicly_stream_t *qs)
{
    if (quicly_stream_is_unidirectional(qs->stream_id)) {
        h2o_http3_on_create_unidirectional_stream(qs);
    } else {
        static const quicly_stream_callbacks_t callbacks = {on_stream_destroy, on_send_shift, on_send_emit,
                                                            on_send_stop,      on_receive,    on_receive_reset};
        assert(quicly_stream_is_client_initiated(qs->stream_id));
        qs->callbacks = &callbacks;
    }
    return 0;
}

quicly_stream_open_t h2o_httpclient_http3_on_stream_open = {stream_open_cb};

static void on_receive_datagram_frame(quicly_receive_datagram_frame_t *self, quicly_conn_t *qc, ptls_iovec_t datagram)
{
    struct st_h2o_httpclient__h3_conn_t *conn =
        H2O_STRUCT_FROM_MEMBER(struct st_h2o_httpclient__h3_conn_t, super, *quicly_get_data(qc));
    uint64_t flow_id;
    h2o_iovec_t payload;
    quicly_stream_t *qs;

    /* decode, validate, get stream */
    if ((flow_id = h2o_http3_decode_h3_datagram(&payload, datagram.base, datagram.len)) == UINT64_MAX ||
        !(quicly_stream_is_client_initiated(flow_id) && !quicly_stream_is_unidirectional(flow_id))) {
        h2o_quic_close_connection(&conn->super.super, H2O_HTTP3_ERROR_GENERAL_PROTOCOL, "invalid DATAGRAM frame");
        return;
    }
    if ((qs = quicly_get_stream(conn->super.super.quic, flow_id)) == NULL)
        return;

    struct st_h2o_http3client_req_t *req = qs->data;
    if (req->on_read_datagrams != NULL)
        req->on_read_datagrams(&req->super, &payload, 1);
}

quicly_receive_datagram_frame_t h2o_httpclient_http3_on_receive_datagram_frame = {on_receive_datagram_frame};
