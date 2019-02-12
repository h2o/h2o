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
#include "khash.h"
#include "quicly.h"
#include "h2o/hostinfo.h"
#include "h2o/httpclient.h"
#include "h2o/http3_common.h"
#include "h2o/http2_common.h"

#define H2O_HTTP3_ERROR_EOS H2O_HTTP3_ERROR_USER1 /* the client uses USER1 for signaling eos */

struct st_h2o_hqclient_conn_t {
    h2o_http3_conn_t super;
    h2o_httpclient_ctx_t *ctx;
    struct {
        h2o_url_t origin_url;
        char named_serv[sizeof(H2O_UINT16_LONGEST_STR)];
    } server;
    ptls_handshake_properties_t handshake_properties;
    h2o_timer_t timeout;
    h2o_hostinfo_getaddr_req_t *getaddr_req;
    h2o_linklist_t pending_requests; /* linklist used to queue pending requests */
};

struct st_h2o_hqclient_req_t {
    /**
     * superclass
     */
    h2o_httpclient_t super;
    /**
     * pointer to the connection
     */
    struct st_h2o_hqclient_conn_t *conn;
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
        h2o_buffer_t *body, *partial_frame, *noncontiguous;
        size_t bytes_contiguous;
    } recvbuf;
    /**
     * called when new contigious data becomes available
     */
    int (*handle_input)(struct st_h2o_hqclient_req_t *req, const uint8_t **src, const uint8_t *src_end, int err,
                        const char **err_desc);
};

static int handle_input_expect_data_frame(struct st_h2o_hqclient_req_t *req, const uint8_t **src, const uint8_t *src_end, int err,
                                          const char **err_desc);
static void start_request(struct st_h2o_hqclient_req_t *req);

static struct st_h2o_hqclient_conn_t *find_connection(h2o_httpclient_ctx_t *ctx, h2o_url_t *origin)
{
    h2o_linklist_t *link;

    for (link = ctx->quic->conns.next; link != &ctx->quic->conns; link = link->next) {
        struct st_h2o_hqclient_conn_t *conn = H2O_STRUCT_FROM_MEMBER(struct st_h2o_hqclient_conn_t, super.conns_link, link);
        /* FIXME check max_concurrent_streams, etc. */
        if (conn->server.origin_url.scheme == origin->scheme &&
            h2o_memis(conn->server.origin_url.authority.base, conn->server.origin_url.authority.len, origin->authority.base,
                      origin->authority.len))
            return conn;
    }

    return NULL;
}

static void destroy_connection(struct st_h2o_hqclient_conn_t *conn)
{
    /* FIXME pending_requests */
    if (conn->getaddr_req != NULL)
        h2o_hostinfo_getaddr_cancel(conn->getaddr_req);
    h2o_timer_unlink(&conn->timeout);
    free(conn->server.origin_url.host.base);
    free(conn->server.origin_url.authority.base);
    h2o_http3_dispose_conn(&conn->super);
    free(conn);
}

static void on_connect_timeout(h2o_timer_t *timeout)
{
    struct st_h2o_hqclient_conn_t *conn = H2O_STRUCT_FROM_MEMBER(struct st_h2o_hqclient_conn_t, timeout, timeout);
    destroy_connection(conn);
}

static void start_connect(struct st_h2o_hqclient_conn_t *conn, struct sockaddr *sa, socklen_t salen)
{
    quicly_conn_t *qconn;
    int ret;

    assert(conn->super.quic == NULL);
    assert(conn->getaddr_req == NULL);
    assert(h2o_timer_is_linked(&conn->timeout));
    assert(conn->timeout.cb == on_connect_timeout);

    /* create QUIC connection context and attach */
    if ((ret = quicly_connect(&qconn, conn->ctx->quic->quic, conn->server.origin_url.host.base, sa, salen,
                              &conn->handshake_properties, NULL /* TODO pass transport params */)) != 0) {
        conn->super.quic = NULL; /* just in case */
        goto Fail;
    }
    if ((ret = h2o_http3_setup(&conn->super, qconn)) != 0)
        goto Fail;

    h2o_http3_send(&conn->super);

    return;
Fail:
    destroy_connection(conn);
}

static void on_getaddr(h2o_hostinfo_getaddr_req_t *getaddr_req, const char *errstr, struct addrinfo *res, void *_conn)
{
    struct st_h2o_hqclient_conn_t *conn = _conn;

    assert(getaddr_req == conn->getaddr_req);
    conn->getaddr_req = NULL;

    if (errstr != NULL) {
        /* TODO reconnect */
        abort();
    }

    struct addrinfo *selected = h2o_hostinfo_select_one(res);
    start_connect(conn, selected->ai_addr, selected->ai_addrlen);
}

static int handle_control_stream_frame(h2o_http3_conn_t *_conn, uint8_t type, const uint8_t *payload, size_t len,
                                       const char **err_desc)
{
    struct st_h2o_hqclient_conn_t *conn = (void *)_conn;
    int ret;

    switch (type) {
    case H2O_HTTP3_FRAME_TYPE_SETTINGS:
        if ((ret = h2o_http3_handle_settings_frame(&conn->super, payload, len, err_desc)) != 0)
            return ret;
        while (!h2o_linklist_is_empty(&conn->pending_requests)) {
            struct st_h2o_hqclient_req_t *req =
                H2O_STRUCT_FROM_MEMBER(struct st_h2o_hqclient_req_t, link, conn->pending_requests.next);
            h2o_linklist_unlink(&req->link);
            start_request(req);
        }
        break;
    default:
        break;
    }

    return 0;
}

struct st_h2o_hqclient_conn_t *create_connection(h2o_httpclient_ctx_t *ctx, h2o_url_t *origin)
{
    struct st_h2o_hqclient_conn_t *conn = h2o_mem_alloc(sizeof(*conn));

    memset(conn, 0, sizeof(*conn));
    h2o_http3_init_conn(&conn->super, ctx->quic, handle_control_stream_frame);
    conn->ctx = ctx;
    conn->server.origin_url = (h2o_url_t){origin->scheme, h2o_strdup(NULL, origin->authority.base, origin->authority.len),
                                          h2o_strdup(NULL, origin->host.base, origin->host.len)};
    sprintf(conn->server.named_serv, "%" PRIu16, h2o_url_get_port(origin));
    conn->handshake_properties.client.negotiated_protocols.list = h2o_http3_alpn;
    conn->handshake_properties.client.negotiated_protocols.count = sizeof(h2o_http3_alpn) / sizeof(h2o_http3_alpn);
    h2o_linklist_init_anchor(&conn->pending_requests);

    conn->getaddr_req = h2o_hostinfo_getaddr(conn->ctx->getaddr_receiver, conn->server.origin_url.host,
                                             h2o_iovec_init(conn->server.named_serv, strlen(conn->server.named_serv)), AF_UNSPEC,
                                             SOCK_DGRAM, IPPROTO_UDP, AI_ADDRCONFIG | AI_NUMERICSERV, on_getaddr, conn);
    h2o_timer_link(conn->ctx->loop, conn->ctx->connect_timeout, &conn->timeout);
    conn->timeout.cb = on_connect_timeout;

    return conn;
}

static void destroy_request(struct st_h2o_hqclient_req_t *req)
{
    assert(req->quic == NULL);
    h2o_buffer_dispose(&req->sendbuf);
    h2o_buffer_dispose(&req->recvbuf.body);
    h2o_buffer_dispose(&req->recvbuf.partial_frame);
    h2o_buffer_dispose(&req->recvbuf.noncontiguous);
    if (h2o_timer_is_linked(&req->super._timeout))
        h2o_timer_unlink(&req->super._timeout);
    if (h2o_linklist_is_linked(&req->link))
        h2o_linklist_unlink(&req->link);
    free(req);
}

static void close_stream(struct st_h2o_hqclient_req_t *req, int err)
{
    /* TODO are we expected to send two error codes? */
    if (quicly_sendstate_transfer_complete(&req->quic->sendstate))
        quicly_reset_stream(req->quic, err);
    if (quicly_recvstate_transfer_complete(&req->quic->recvstate))
        quicly_request_stop(req->quic, err);
    req->quic->data = NULL;
    req->quic = NULL;
}

static void on_error_before_head(struct st_h2o_hqclient_req_t *req, const char *errstr)
{
    req->super._cb.on_head(&req->super, errstr, 0, 0, h2o_iovec_init(NULL, 0), NULL, 0, 0);
}

static int handle_input_data_payload(struct st_h2o_hqclient_req_t *req, const uint8_t **src, const uint8_t *src_end, int err,
                                     const char **err_desc)
{
    size_t payload_bytes = req->bytes_left_in_data_frame;
    const char *errstr;

    /* save data, update states */
    if (src_end - *src < payload_bytes)
        payload_bytes = src_end - *src;
    H2O_HTTP3_CHECK_SUCCESS(h2o_buffer_append(&req->recvbuf.body, *src, payload_bytes));
    *src += payload_bytes;
    req->bytes_left_in_data_frame -= payload_bytes;
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

int handle_input_expect_data_frame(struct st_h2o_hqclient_req_t *req, const uint8_t **src, const uint8_t *src_end, int err,
                                   const char **err_desc)
{
    h2o_http3_read_frame_t frame;
    int ret;

    if ((ret = h2o_http3_read_frame(&frame, src, src_end, err_desc)) != 0) {
        if (ret != H2O_HTTP3_ERROR_INCOMPLETE)
            return 0;
        req->super._cb.on_body(&req->super, "malformed frame");
        return ret;
    }

    switch (frame.type) {
    case H2O_HTTP3_FRAME_TYPE_DATA:
        break;
    default:
        /* FIXME handle push_promise, trailers */
        req->super._cb.on_body(&req->super, "unexpected frame");
        return H2O_HTTP3_ERROR_UNEXPECTED_FRAME;
    }

    req->handle_input = handle_input_data_payload;
    req->bytes_left_in_data_frame = frame.length;

    /* unexpected close of DATA frame is handled by handle_input_data_payload. We rely on the function to detect if the DATA frame
     * is closed right after the frame header */
    return handle_input_data_payload(req, src, src_end, err, err_desc);
}

static int handle_input_expect_headers(struct st_h2o_hqclient_req_t *req, const uint8_t **src, const uint8_t *src_end, int err,
                                       const char **err_desc)
{
    h2o_http3_read_frame_t frame;
    int status;
    h2o_headers_t headers = {NULL};
    uint8_t header_ack[H2O_HPACK_ENCODE_INT_MAX_LENGTH];
    size_t header_ack_len;
    int ret, frame_is_eos;

    /* read HEADERS frame */
    if ((ret = h2o_http3_read_frame(&frame, src, src_end, err_desc)) != 0) {
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
        on_error_before_head(req, "unexpected frame");
        return H2O_HTTP3_ERROR_UNEXPECTED_FRAME;
    }
    if ((ret = h2o_qpack_parse_response(req->super.pool, req->conn->super.qpack.dec, req->quic->stream_id, &status, &headers,
                                        header_ack, &header_ack_len, frame.payload, frame.length, err_desc)) != 0) {
        if (ret == H2O_HTTP2_ERROR_INCOMPLETE) {
            /* the request is blocked by the QPACK stream */
            req->handle_input = NULL; /* FIXME */
            return 0;
        }
        on_error_before_head(req, *err_desc != NULL ? *err_desc : "qpack error");
        return H2O_HTTP3_ERROR_GENERAL; /* FIXME */
    }
    if (header_ack_len != 0)
        h2o_http3_send_qpack_header_ack(&req->conn->super, header_ack, header_ack_len);

    /* handle 1xx */
    if (100 <= status && status <= 199) {
        if (status == 101) {
            on_error_before_head(req, "unexpected 101");
            return H2O_HTTP3_ERROR_GENERAL;
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
    if ((req->super._cb.on_body = req->super._cb.on_head(&req->super, frame_is_eos ? h2o_httpclient_error_is_eos : NULL, 0, status,
                                                         h2o_iovec_init(NULL, 0), headers.entries, headers.size, 0)) == NULL)
        return frame_is_eos ? 0 : H2O_HTTP3_ERROR_INTERNAL;

    /* handle body */
    req->handle_input = handle_input_expect_data_frame;
    return 0;
}

static void handle_input_error(struct st_h2o_hqclient_req_t *req, int err)
{
    const uint8_t *src = NULL, *src_end = NULL;
    const char *err_desc = NULL;
    req->handle_input(req, &src, src_end, err, &err_desc);
}

static void on_stream_destroy(quicly_stream_t *qs)
{
    struct st_h2o_hqclient_req_t *req;

    if ((req = qs->data) == NULL)
        return;
    handle_input_error(req, H2O_HTTP3_ERROR_TRANSPORT);
    req->quic->data = NULL;
    req->quic = NULL;
    destroy_request(req);
}

static void on_send_shift(quicly_stream_t *qs, size_t delta)
{
    struct st_h2o_hqclient_req_t *req = qs->data;

    assert(req != NULL);
    h2o_buffer_consume(&req->sendbuf, delta);
}

static int on_send_emit(quicly_stream_t *qs, size_t off, void *dst, size_t *len, int *wrote_all)
{
    struct st_h2o_hqclient_req_t *stream = qs->data;

    if (*len >= stream->sendbuf->size - off) {
        *len = stream->sendbuf->size - off;
        *wrote_all = 1;
    } else {
        *wrote_all = 0;
    }
    memcpy(dst, stream->sendbuf->bytes, *len);
    return 0;
}

static int on_send_stop(quicly_stream_t *qs, int err)
{
    struct st_h2o_hqclient_req_t *req;

    if ((req = qs->data) == NULL)
        return 0;
    handle_input_error(req, err);
    close_stream(req, H2O_HTTP3_ERROR_REQUEST_CANCELLED);
    destroy_request(req);

    return 0;
}

static int on_receive(quicly_stream_t *qs, size_t off, const void *input, size_t len)
{
    struct st_h2o_hqclient_req_t *req = qs->data;
    const uint8_t *src, *src_end;
    size_t bytes_available = quicly_recvstate_bytes_available(&req->quic->recvstate), bytes_from_noncontiguous;
    int is_eos, ret;
    const char *err_desc = NULL;

    assert(req->recvbuf.body->size + req->recvbuf.partial_frame->size == req->recvbuf.bytes_contiguous);

    if (req->recvbuf.noncontiguous->size == 0 && bytes_available == off + len) {
        /* fast path; there was no hole */
        src = input;
        src_end = src + len;
        bytes_from_noncontiguous = 0;
    } else {
        /* slow path; copy data to noncontiguous buffer */
        size_t size_required = off + len - req->recvbuf.bytes_contiguous;
        if (req->recvbuf.noncontiguous->size < size_required) {
            H2O_HTTP3_CHECK_SUCCESS(h2o_buffer_reserve(&req->recvbuf.noncontiguous, size_required).base != NULL);
            req->recvbuf.noncontiguous->size = size_required;
        }
        memcpy(req->recvbuf.noncontiguous->bytes + off - req->recvbuf.bytes_contiguous, input, len);
        /* just return if no new data is available */
        if (bytes_available == req->recvbuf.bytes_contiguous)
            return 0;
        /* update input, len, as well as record the number of bytes to retire from noncontiguous buffer */
        assert(bytes_available > req->recvbuf.bytes_contiguous);
        bytes_from_noncontiguous = bytes_available - req->recvbuf.bytes_contiguous;
        src = (const uint8_t *)req->recvbuf.noncontiguous->bytes;
        src_end = src + bytes_from_noncontiguous;
    }

    /* append data to partial buffer (if it's non-empty) */
    if (req->recvbuf.partial_frame->size != 0) {
        H2O_HTTP3_CHECK_SUCCESS(h2o_buffer_append(&req->recvbuf.partial_frame, src, src_end - src));
        src = (const uint8_t *)req->recvbuf.partial_frame->bytes;
        src_end = src + req->recvbuf.partial_frame->size;
    }

    /* process the contiguous input */
    is_eos = quicly_recvstate_transfer_complete(&req->quic->recvstate);
    assert(is_eos || src != src_end);
    do {
        ret = req->handle_input(req, &src, src_end, is_eos ? H2O_HTTP3_ERROR_EOS : 0, &err_desc);
    } while (ret == 0 && src != src_end);

    /* save data to partial buffer (if necessary) */
    if (ret == H2O_HTTP3_ERROR_INCOMPLETE) {
        if (is_eos)
            return H2O_HTTP3_ERROR_MALFORMED_FRAME(src == src_end ? H2O_HTTP3_FRAME_TYPE_DATA : *src);
        assert(src < src_end);
        if (req->recvbuf.partial_frame->size != 0) {
            assert(src_end == (const uint8_t *)req->recvbuf.partial_frame->bytes + req->recvbuf.partial_frame->size);
            h2o_buffer_consume(&req->recvbuf.partial_frame, src - (const uint8_t *)req->recvbuf.partial_frame->bytes);
        } else {
            H2O_HTTP3_CHECK_SUCCESS(h2o_buffer_append(&req->recvbuf.partial_frame, src, src_end - src));
        }
    }

    /* cleanup */
    if (is_eos) {
        if (!quicly_sendstate_transfer_complete(&req->quic->sendstate))
            quicly_reset_stream(req->quic, H2O_HTTP3_ERROR_NONE);
        req->quic->data = NULL;
        req->quic = NULL;
        destroy_request(req);
    } else if (ret != 0) {
        /* FIXME consider how to send err_desc */
        close_stream(req, ret);
        destroy_request(req);
    } else {
        if (bytes_from_noncontiguous != 0)
            h2o_buffer_consume(&req->recvbuf.noncontiguous, bytes_from_noncontiguous);
        size_t contiguous_bytes_in_buffer = req->recvbuf.body->size + req->recvbuf.partial_frame->size;
        if (bytes_available != contiguous_bytes_in_buffer) {
            assert(contiguous_bytes_in_buffer < bytes_available);
            quicly_stream_sync_recvbuf(req->quic, bytes_available - contiguous_bytes_in_buffer);
            req->recvbuf.bytes_contiguous = contiguous_bytes_in_buffer;
        }
    }

    return 0;
}

static int on_receive_reset(quicly_stream_t *qs, int err)
{
    struct st_h2o_hqclient_req_t *req = qs->data;

    assert(req->recvbuf.body->size + req->recvbuf.partial_frame->size == req->recvbuf.bytes_contiguous);

    handle_input_error(req, err);
    close_stream(req, H2O_HTTP3_ERROR_REQUEST_CANCELLED);
    destroy_request(req);

    return 0;
}

void start_request(struct st_h2o_hqclient_req_t *req)
{
    h2o_iovec_t method;
    h2o_url_t url;
    const h2o_header_t *headers;
    size_t num_headers;
    h2o_iovec_t body;
    h2o_httpclient_proceed_req_cb proceed_req;
    h2o_httpclient_properties_t props = {NULL};
    int ret;

    assert(req->quic == NULL);
    assert(!h2o_linklist_is_linked(&req->link));

    if ((req->super._cb.on_head = req->super._cb.on_connect(&req->super, NULL, &method, &url, &headers, &num_headers, &body,
                                                            &proceed_req, &props, &req->conn->server.origin_url)) == NULL) {
        destroy_request(req);
        return;
    }
    assert(body.base == NULL && proceed_req == NULL); /* FIXME add request entity support */

    if ((ret = quicly_open_stream(req->conn->super.quic, &req->quic, 0)) != 0) {
        on_error_before_head(req, "failed to open stream");
        destroy_request(req);
        return;
    }
    req->quic->data = req;

    /* TODO optimize */
    h2o_byte_vector_t buf = {NULL};
    h2o_http3_encode_frame(req->super.pool, &buf, H2O_HTTP3_FRAME_TYPE_HEADERS, {
        h2o_qpack_flatten_request(req->conn->super.qpack.enc, req->super.pool, req->quic->stream_id, NULL, &buf, method, url.scheme,
                                  url.authority, url.path, headers, num_headers);
    });
    H2O_HTTP3_CHECK_SUCCESS(h2o_buffer_append(&req->sendbuf, buf.entries, buf.size));

    quicly_sendstate_shutdown(&req->quic->sendstate, req->sendbuf->size);
    quicly_stream_sync_sendbuf(req->quic, 1);

    req->handle_input = handle_input_expect_headers;
}

static void cancel_request(h2o_httpclient_t *_client)
{
    struct st_h2o_hqclient_req_t *req = (void *)_client;
    if (req->quic != NULL)
        close_stream(req, H2O_HTTP3_ERROR_REQUEST_CANCELLED);
    destroy_request(req);
}

void h2o_httpclient_connect_hq(h2o_httpclient_t **_client, h2o_mem_pool_t *pool, void *data, h2o_httpclient_ctx_t *ctx,
                               h2o_url_t *target, h2o_httpclient_connect_cb cb)
{
    struct st_h2o_hqclient_conn_t *conn;
    struct st_h2o_hqclient_req_t *req;

    if ((conn = find_connection(ctx, target)) == NULL)
        conn = create_connection(ctx, target);

    req = h2o_mem_alloc(sizeof(*req));
    *req = (struct st_h2o_hqclient_req_t){
        {pool, ctx, NULL, &req->recvbuf.body, data, NULL, {h2o_gettimeofday(ctx->loop)}, cancel_request}, conn};
    req->super._cb.on_connect = cb;
    h2o_buffer_init(&req->sendbuf, &h2o_socket_buffer_prototype);
    h2o_buffer_init(&req->recvbuf.body, &h2o_socket_buffer_prototype);
    h2o_buffer_init(&req->recvbuf.partial_frame, &h2o_socket_buffer_prototype);
    h2o_buffer_init(&req->recvbuf.noncontiguous, &h2o_socket_buffer_prototype);

    if (h2o_http3_has_received_settings(&conn->super)) {
        start_request(req);
    } else {
        h2o_linklist_insert(&conn->pending_requests, &req->link);
    }
}

int h2o_httpclient_http3_on_stream_open(quicly_stream_t *qs)
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
