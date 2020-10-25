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

#define H2O_HTTP3_ERROR_EOS H2O_HTTP3_ERROR_USER1 /* the client uses USER1 for signaling eos */

struct st_h2o_http3client_conn_t {
    h2o_http3_conn_t super;
    h2o_httpclient_ctx_t *ctx;
    struct {
        h2o_url_t origin_url;
        char named_serv[sizeof(H2O_UINT16_LONGEST_STR)];
    } server;
    ptls_handshake_properties_t handshake_properties;
    h2o_timer_t timeout;
    h2o_hostinfo_getaddr_req_t *getaddr_req;
    /**
     * see h2o_http3_ctx_t::clients
     */
    h2o_linklist_t clients_link;
    /**
     * linklist used to queue pending requests
     */
    h2o_linklist_t pending_requests;
};

struct st_h2o_http3client_req_t {
    /**
     * superclass
     */
    h2o_httpclient_t super;
    /**
     * pointer to the connection
     */
    struct st_h2o_http3client_conn_t *conn;
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
     * proceed_req callback.  The callback is invoked when all bytes in the send buffer is emitted for the first time (at this point
     * bytes_written is changed to zero, so that the proceed_req function is called once per every block being supplied from the
     * application).
     */
    struct {
        h2o_httpclient_proceed_req_cb cb;
        size_t bytes_written;
    } proceed_req;
};

static int handle_input_expect_data_frame(struct st_h2o_http3client_req_t *req, const uint8_t **src, const uint8_t *src_end,
                                          int err, const char **err_desc);
static void start_request(struct st_h2o_http3client_req_t *req);
static void destroy_request(struct st_h2o_http3client_req_t *req);

static struct st_h2o_http3client_conn_t *find_connection_for_origin(h2o_httpclient_ctx_t *ctx, const h2o_url_scheme_t *scheme,
                                                                    h2o_iovec_t authority)
{
    h2o_linklist_t *l;

    /* FIXME:
     * - check connection state(e.g., max_concurrent_streams, if received GOAWAY)
     * - use hashmap
     */
    for (l = ctx->http3.ctx->clients.next; l != &ctx->http3.ctx->clients; l = l->next) {
        struct st_h2o_http3client_conn_t *conn = H2O_STRUCT_FROM_MEMBER(struct st_h2o_http3client_conn_t, clients_link, l);
        if (conn->server.origin_url.scheme == scheme &&
            h2o_memis(conn->server.origin_url.authority.base, conn->server.origin_url.authority.len, authority.base, authority.len))
            return conn;
    }

    return NULL;
}

static void start_pending_requests(struct st_h2o_http3client_conn_t *conn)
{
    while (!h2o_linklist_is_empty(&conn->pending_requests)) {
        struct st_h2o_http3client_req_t *req =
            H2O_STRUCT_FROM_MEMBER(struct st_h2o_http3client_req_t, link, conn->pending_requests.next);
        h2o_linklist_unlink(&req->link);
        start_request(req);
    }
}

static void destroy_connection(struct st_h2o_http3client_conn_t *conn)
{
    if (h2o_linklist_is_linked(&conn->clients_link))
        h2o_linklist_unlink(&conn->clients_link);
    while (!h2o_linklist_is_empty(&conn->pending_requests)) {
        struct st_h2o_http3client_req_t *req =
            H2O_STRUCT_FROM_MEMBER(struct st_h2o_http3client_req_t, link, conn->pending_requests.next);
        h2o_linklist_unlink(&req->link);
        req->super._cb.on_connect(&req->super, h2o_socket_error_conn_fail, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
        destroy_request(req);
    }
    assert(h2o_linklist_is_empty(&conn->pending_requests));
    if (conn->getaddr_req != NULL)
        h2o_hostinfo_getaddr_cancel(conn->getaddr_req);
    h2o_timer_unlink(&conn->timeout);
    free(conn->server.origin_url.host.base);
    free(conn->server.origin_url.authority.base);
    free(conn->handshake_properties.client.session_ticket.base);
    h2o_http3_dispose_conn(&conn->super);
    free(conn);
}

static void on_connect_timeout(h2o_timer_t *timeout)
{
    struct st_h2o_http3client_conn_t *conn = H2O_STRUCT_FROM_MEMBER(struct st_h2o_http3client_conn_t, timeout, timeout);
    destroy_connection(conn);
}

static void start_connect(struct st_h2o_http3client_conn_t *conn, struct sockaddr *sa)
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
    if (conn->ctx->http3.load_session != NULL) {
        if (!conn->ctx->http3.load_session(conn->ctx, sa, conn->server.origin_url.host.base, &address_token,
                                           &conn->handshake_properties.client.session_ticket, &resumed_tp))
            goto Fail;
    }
    if ((ret = quicly_connect(&qconn, conn->ctx->http3.ctx->quic, conn->server.origin_url.host.base, sa, NULL,
                              &conn->ctx->http3.ctx->next_cid, address_token, &conn->handshake_properties,
                              conn->handshake_properties.client.session_ticket.base != NULL ? &resumed_tp : NULL)) != 0) {
        conn->super.super.quic = NULL; /* just in case */
        goto Fail;
    }
    ++conn->ctx->http3.ctx->next_cid.master_id; /* FIXME check overlap */
    if ((ret = h2o_http3_setup(&conn->super, qconn)) != 0)
        goto Fail;

    if (quicly_connection_is_ready(conn->super.super.quic))
        start_pending_requests(conn);

    h2o_quic_send(&conn->super.super);

    free(address_token.base);
    return;
Fail:
    free(address_token.base);
    destroy_connection(conn);
}

static void on_getaddr(h2o_hostinfo_getaddr_req_t *getaddr_req, const char *errstr, struct addrinfo *res, void *_conn)
{
    struct st_h2o_http3client_conn_t *conn = _conn;

    assert(getaddr_req == conn->getaddr_req);
    conn->getaddr_req = NULL;

    if (errstr != NULL) {
        /* TODO reconnect */
        abort();
    }

    struct addrinfo *selected = h2o_hostinfo_select_one(res);
    start_connect(conn, selected->ai_addr);
}

static void handle_control_stream_frame(h2o_http3_conn_t *_conn, uint8_t type, const uint8_t *payload, size_t len)
{
    struct st_h2o_http3client_conn_t *conn = (void *)_conn;
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

struct st_h2o_http3client_conn_t *create_connection(h2o_httpclient_ctx_t *ctx, h2o_url_t *origin)
{
    static const h2o_http3_conn_callbacks_t callbacks = {{(void *)destroy_connection}, handle_control_stream_frame};
    static const h2o_http3_qpack_context_t qpack_ctx = {0 /* TODO */};
    struct st_h2o_http3client_conn_t *conn = h2o_mem_alloc(sizeof(*conn));

    h2o_http3_init_conn(&conn->super, ctx->http3.ctx, &callbacks, &qpack_ctx);
    memset((char *)conn + sizeof(conn->super), 0, sizeof(*conn) - sizeof(conn->super));
    conn->ctx = ctx;
    conn->server.origin_url = (h2o_url_t){origin->scheme, h2o_strdup(NULL, origin->authority.base, origin->authority.len),
                                          h2o_strdup(NULL, origin->host.base, origin->host.len)};
    sprintf(conn->server.named_serv, "%" PRIu16, h2o_url_get_port(origin));
    conn->handshake_properties.client.negotiated_protocols.list = h2o_http3_alpn;
    conn->handshake_properties.client.negotiated_protocols.count = sizeof(h2o_http3_alpn) / sizeof(h2o_http3_alpn[0]);
    h2o_linklist_insert(&ctx->http3.ctx->clients, &conn->clients_link);
    h2o_linklist_init_anchor(&conn->pending_requests);

    conn->getaddr_req = h2o_hostinfo_getaddr(conn->ctx->getaddr_receiver, conn->server.origin_url.host,
                                             h2o_iovec_init(conn->server.named_serv, strlen(conn->server.named_serv)), AF_UNSPEC,
                                             SOCK_DGRAM, IPPROTO_UDP, AI_ADDRCONFIG | AI_NUMERICSERV, on_getaddr, conn);
    h2o_timer_link(conn->ctx->loop, conn->ctx->connect_timeout, &conn->timeout);
    conn->timeout.cb = on_connect_timeout;

    return conn;
}

void destroy_request(struct st_h2o_http3client_req_t *req)
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

static void on_error_before_head(struct st_h2o_http3client_req_t *req, const char *errstr)
{
    req->super._cb.on_head(&req->super, errstr, 0, 0, h2o_iovec_init(NULL, 0), NULL, 0, 0);
}

static int handle_input_data_payload(struct st_h2o_http3client_req_t *req, const uint8_t **src, const uint8_t *src_end, int err,
                                     const char **err_desc)
{
    const char *errstr;

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
    errstr = NULL;
    if (*src == src_end && err != 0) {
        /* FIXME also check content-length? see what other protocol handlers do */
        errstr = err == H2O_HTTP3_ERROR_EOS && req->bytes_left_in_data_frame == 0 ? h2o_httpclient_error_is_eos : "reset by peer";
    } else {
        errstr = NULL;
    }
    if (req->super._cb.on_body(&req->super, errstr) != 0)
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
            req->super._cb.on_body(&req->super, "malformed frame");
            return ret;
        }
        switch (frame.type) {
        case H2O_HTTP3_FRAME_TYPE_DATA:
            break;
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
    uint8_t header_ack[H2O_HPACK_ENCODE_INT_MAX_LENGTH];
    size_t header_ack_len;
    int ret, frame_is_eos;

    /* read HEADERS frame */
    if ((ret = h2o_http3_read_frame(&frame, 1, H2O_HTTP3_STREAM_TYPE_REQUEST, src, src_end, err_desc)) != 0) {
        if (ret == H2O_HTTP3_ERROR_INCOMPLETE) {
            if (err != 0) {
                on_error_before_head(req, err == H2O_HTTP3_ERROR_NONE ? "unexpected close" : "reset by peer");
                return 0;
            }
            return ret;
        }
        on_error_before_head(req, "response header too large");
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
                                        header_ack, &header_ack_len, frame.payload, frame.length, err_desc)) != 0) {
        if (ret == H2O_HTTP2_ERROR_INCOMPLETE) {
            /* the request is blocked by the QPACK stream */
            req->handle_input = NULL; /* FIXME */
            return 0;
        }
        on_error_before_head(req, *err_desc != NULL ? *err_desc : "qpack error");
        return H2O_HTTP3_ERROR_GENERAL_PROTOCOL; /* FIXME */
    }
    if (header_ack_len != 0)
        h2o_http3_send_qpack_header_ack(&req->conn->super, header_ack, header_ack_len);

    /* handle 1xx */
    if (100 <= status && status <= 199) {
        if (status == 101) {
            on_error_before_head(req, "unexpected 101");
            return H2O_HTTP3_ERROR_GENERAL_PROTOCOL;
        }
        if (frame_is_eos) {
            on_error_before_head(req, err == H2O_HTTP3_ERROR_EOS ? "unexpected close" : "reset by peer");
            return 0;
        }
        if (req->super.informational_cb != NULL &&
            req->super.informational_cb(&req->super, 0, status, h2o_iovec_init(NULL, 0), headers.entries, headers.size) != 0) {
            return H2O_HTTP3_ERROR_INTERNAL;
        }
        return 0;
    }

    /* handle final response */
    if ((req->super._cb.on_body = req->super._cb.on_head(&req->super, frame_is_eos ? h2o_httpclient_error_is_eos : NULL, 0x300,
                                                         status, h2o_iovec_init(NULL, 0), headers.entries, headers.size, 0)) ==
        NULL)
        return frame_is_eos ? 0 : H2O_HTTP3_ERROR_INTERNAL;

    /* handle body */
    req->handle_input = handle_input_expect_data_frame;
    return 0;
}

static void handle_input_error(struct st_h2o_http3client_req_t *req, int err)
{
    const uint8_t *src = NULL, *src_end = NULL;
    const char *err_desc = NULL;
    req->handle_input(req, &src, src_end, err, &err_desc);
}

static void on_stream_destroy(quicly_stream_t *qs, int err)
{
    struct st_h2o_http3client_req_t *req;

    if ((req = qs->data) == NULL)
        return;
    handle_input_error(req, H2O_HTTP3_ERROR_TRANSPORT);
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

    if (*wrote_all && req->proceed_req.bytes_written != 0) {
        size_t bytes_written = req->proceed_req.bytes_written;
        req->proceed_req.bytes_written = 0;
        req->proceed_req.cb(&req->super, bytes_written,
                            quicly_sendstate_is_open(&req->quic->sendstate) ? H2O_SEND_STATE_IN_PROGRESS : H2O_SEND_STATE_FINAL);
    }
}

static void on_send_stop(quicly_stream_t *qs, int err)
{
    struct st_h2o_http3client_req_t *req;

    if ((req = qs->data) != NULL) {
        handle_input_error(req, err);
        close_stream(req, H2O_HTTP3_ERROR_REQUEST_CANCELLED);
        destroy_request(req);
    }
}

static int on_receive_process_bytes(struct st_h2o_http3client_req_t *req, const uint8_t **src, const uint8_t *src_end,
                                    const char **err_desc)
{
    int ret, is_eos = quicly_recvstate_transfer_complete(&req->quic->recvstate);
    assert(is_eos || *src != src_end);

    do {
        if ((ret = req->handle_input(req, src, src_end, is_eos ? H2O_HTTP3_ERROR_EOS : 0, err_desc)) != 0) {
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
            H2O_HTTP3_CHECK_SUCCESS(h2o_buffer_reserve(&req->recvbuf.stream, size_required).base != NULL);
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
        if (!quicly_sendstate_transfer_complete(&req->quic->sendstate))
            quicly_reset_stream(req->quic, H2O_HTTP3_ERROR_NONE);
        detach_stream(req);
        destroy_request(req);
    } else if (err != 0) {
        /* FIXME all the errors are reported at stream-level. Is that correct? */
        close_stream(req, err);
        destroy_request(req);
    }
}

static void on_receive_reset(quicly_stream_t *qs, int err)
{
    struct st_h2o_http3client_req_t *req = qs->data;

    handle_input_error(req, err);
    close_stream(req, H2O_HTTP3_ERROR_REQUEST_CANCELLED);
    destroy_request(req);
}

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

void start_request(struct st_h2o_http3client_req_t *req)
{
    h2o_iovec_t method;
    h2o_url_t url;
    const h2o_header_t *headers;
    size_t num_headers;
    h2o_iovec_t body;
    h2o_httpclient_properties_t props = {NULL};
    int ret;

    assert(req->quic == NULL);
    assert(!h2o_linklist_is_linked(&req->link));

    if ((req->super._cb.on_head = req->super._cb.on_connect(&req->super, NULL, &method, &url, &headers, &num_headers, &body,
                                                            &req->proceed_req.cb, &props, &req->conn->server.origin_url)) == NULL) {
        destroy_request(req);
        return;
    }

    if ((ret = quicly_open_stream(req->conn->super.super.quic, &req->quic, 0)) != 0) {
        on_error_before_head(req, "failed to open stream");
        destroy_request(req);
        return;
    }
    req->quic->data = req;

    /* send request (TODO optimize) */
    h2o_byte_vector_t buf = {NULL};
    h2o_http3_encode_frame(req->super.pool, &buf, H2O_HTTP3_FRAME_TYPE_HEADERS, {
        h2o_qpack_flatten_request(req->conn->super.qpack.enc, req->super.pool, req->quic->stream_id, NULL, &buf, method, url.scheme,
                                  url.authority, url.path, headers, num_headers);
    });
    h2o_buffer_append(&req->sendbuf, buf.entries, buf.size);
    if (body.len != 0) {
        emit_data(req, body);
        if (req->proceed_req.cb != NULL)
            req->proceed_req.bytes_written = body.len;
    }
    if (req->proceed_req.cb == NULL)
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

static void do_update_window(h2o_httpclient_t *_client)
{
    /* TODO Stop receiving data for the stream when `buf` grows to certain extent. Then, resume when this function is being called.
     */
}

static int do_write_req(h2o_httpclient_t *_client, h2o_iovec_t chunk, int is_end_stream)
{
    struct st_h2o_http3client_req_t *req = (void *)_client;

    assert(req->quic != NULL && quicly_sendstate_is_open(&req->quic->sendstate));
    assert(req->proceed_req.bytes_written == 0);

    emit_data(req, chunk);

    /* shutdown if we've written all request body */
    if (is_end_stream) {
        assert(quicly_sendstate_is_open(&req->quic->sendstate));
        quicly_sendstate_shutdown(&req->quic->sendstate, req->quic->sendstate.acked.ranges[0].end + req->sendbuf->size);
    }

    req->proceed_req.bytes_written = chunk.len;
    quicly_stream_sync_sendbuf(req->quic, 1);
    h2o_quic_schedule_timer(&req->conn->super.super);
    return 0;
}

void h2o_httpclient_connect_h3(h2o_httpclient_t **_client, h2o_mem_pool_t *pool, void *data, h2o_httpclient_ctx_t *ctx,
                               h2o_url_t *target, h2o_httpclient_connect_cb cb)
{
    struct st_h2o_http3client_conn_t *conn;
    struct st_h2o_http3client_req_t *req;

    if ((conn = find_connection_for_origin(ctx, target->scheme, target->authority)) == NULL)
        conn = create_connection(ctx, target);

    req = h2o_mem_alloc(sizeof(*req));
    *req = (struct st_h2o_http3client_req_t){{pool,
                                              ctx,
                                              NULL,
                                              &req->recvbuf.body,
                                              data,
                                              NULL,
                                              {h2o_gettimeofday(ctx->loop)},
                                              {0},
                                              {0},
                                              cancel_request,
                                              NULL /* steal_socket */,
                                              NULL /* get_socket */,
                                              do_update_window,
                                              do_write_req},
                                             conn};
    req->super._cb.on_connect = cb;
    h2o_buffer_init(&req->sendbuf, &h2o_socket_buffer_prototype);
    h2o_buffer_init(&req->recvbuf.body, &h2o_socket_buffer_prototype);
    h2o_buffer_init(&req->recvbuf.stream, &h2o_socket_buffer_prototype);

    if (h2o_http3_has_received_settings(&conn->super)) {
        start_request(req);
        h2o_quic_schedule_timer(&conn->super.super);
    } else {
        h2o_linklist_insert(&conn->pending_requests, &req->link);
    }
}

void h2o_httpclient_http3_notify_connection_update(h2o_quic_ctx_t *ctx, h2o_quic_conn_t *_conn)
{
    struct st_h2o_http3client_conn_t *conn = (void *)_conn;

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
