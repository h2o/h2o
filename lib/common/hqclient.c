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
#include "h2o/hq_common.h"
#include "h2o/http2_common.h"

struct st_h2o_hqclient_conn_t {
    h2o_hq_conn_t super;
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
    quicly_stream_t *stream;
    /**
     * currently only used for pending_requests
     */
    h2o_linklist_t link;
    /**
     *
     */
    uint64_t bytes_left;
    /**
     *
     */
    h2o_buffer_t *respbuf;
};

static int on_update_expect_data_frame(quicly_stream_t *_stream);
static void handle_input(h2o_hq_conn_t *conn, quicly_decoded_packet_t *packets, size_t num_packets);

static const h2o_hq_conn_callbacks_t callbacks = {handle_input};

static struct st_h2o_hqclient_conn_t *find_connection(h2o_httpclient_ctx_t *ctx, h2o_url_t *origin)
{
    h2o_linklist_t *link;

    for (link = ctx->quic->conns.next; link != &ctx->quic->conns; link = link->next) {
        struct st_h2o_hqclient_conn_t *conn = H2O_STRUCT_FROM_MEMBER(struct st_h2o_hqclient_conn_t, super.conns_link, link);
        if (!(conn->super.callbacks == &callbacks && conn->ctx == ctx))
            continue;
        /* FIXME check max_concurrent_streams, etc. */
        if (conn->server.origin_url.scheme == origin->scheme &&
            h2o_memis(conn->server.origin_url.authority.base, conn->server.origin_url.authority.len, origin->authority.base,
                      origin->authority.len))
            return conn;
    }

    return NULL;
}

static void handle_input(h2o_hq_conn_t *_conn, quicly_decoded_packet_t *packets, size_t num_packets)
{
    struct st_h2o_hqclient_conn_t *conn = (void *)_conn;
    size_t i;

    for (i = 0; i != num_packets; ++i) {
        /* FIXME process closure and errors */
        quicly_receive(conn->super.quic, packets + i);
    }

    /* for locality, emit packets belonging to the same connection NOW! */
    h2o_hq_send(&conn->super);
}

static void destroy_connection(struct st_h2o_hqclient_conn_t *conn)
{
    /* FIXME pending_requests */
    if (conn->getaddr_req != NULL)
        h2o_hostinfo_getaddr_cancel(conn->getaddr_req);
    h2o_timer_unlink(&conn->timeout);
    free(conn->server.origin_url.host.base);
    free(conn->server.origin_url.authority.base);
    h2o_hq_dispose_conn(&conn->super);
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

    if ((ret = quicly_connect(&qconn, conn->ctx->quic->quic, conn->server.origin_url.host.base, sa, salen,
                              &conn->handshake_properties)) != 0) {
        conn->super.quic = NULL; /* just in case */
        goto Fail;
    }
    if ((ret = h2o_hq_setup(&conn->super, qconn)) != 0)
        goto Fail;

    h2o_hq_send(&conn->super);

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

struct st_h2o_hqclient_conn_t *create_connection(h2o_httpclient_ctx_t *ctx, h2o_url_t *origin)
{
    static const ptls_iovec_t alpn[] = {{(void *)"hq", 2}};

    struct st_h2o_hqclient_conn_t *conn = h2o_mem_alloc(sizeof(*conn));

    memset(conn, 0, sizeof(*conn));
    h2o_hq_init_conn(&conn->super, ctx->quic, &callbacks);
    conn->ctx = ctx;
    conn->server.origin_url = (h2o_url_t){origin->scheme, h2o_strdup(NULL, origin->authority.base, origin->authority.len),
                                          h2o_strdup(NULL, origin->host.base, origin->host.len)};
    sprintf(conn->server.named_serv, "%" PRIu16, h2o_url_get_port(origin));
    conn->handshake_properties.client.negotiated_protocols.list = alpn;
    conn->handshake_properties.client.negotiated_protocols.count = sizeof(alpn) / sizeof(alpn[0]);
    h2o_linklist_init_anchor(&conn->pending_requests);

    conn->getaddr_req = h2o_hostinfo_getaddr(conn->ctx->getaddr_receiver, conn->server.origin_url.host,
                                             h2o_iovec_init(conn->server.named_serv, strlen(conn->server.named_serv)), AF_UNSPEC,
                                             SOCK_DGRAM, IPPROTO_UDP, AI_ADDRCONFIG | AI_NUMERICSERV, on_getaddr, conn);
    h2o_timer_link(conn->ctx->loop, conn->ctx->connect_timeout, &conn->timeout);
    conn->timeout.cb = on_connect_timeout;

    return conn;
}

static int on_stream_wait_close(quicly_stream_t *stream)
{
    assert(stream->data == NULL);
    if (quicly_stream_is_closable(stream))
        quicly_close_stream(stream);
    return 0;
}

static void close_request(struct st_h2o_hqclient_req_t *req, uint32_t reason)
{
    h2o_buffer_dispose(&req->respbuf);

    if (req->stream != NULL) {
        if (quicly_stream_is_closable(req->stream)) {
            quicly_close_stream(req->stream);
        } else {
            quicly_reset_stream(req->stream, QUICLY_RESET_STREAM_BOTH_DIRECTIONS, reason);
            req->stream->on_update = on_stream_wait_close;
            req->stream->data = NULL;
        }
        req->stream = NULL;
    }

    if (h2o_timer_is_linked(&req->super._timeout))
        h2o_timer_unlink(&req->super._timeout);
    if (h2o_linklist_is_linked(&req->link))
        h2o_linklist_unlink(&req->link);
}

static int on_error_before_head(struct st_h2o_hqclient_req_t *req, const char *errstr, int32_t hq_reason)
{
    req->super._cb.on_head(&req->super, errstr, 0, 0, h2o_iovec_init(NULL, 0), NULL, 0, 0, 0);
    close_request(req, hq_reason);
    return 0;
}

static int on_error_in_body(struct st_h2o_hqclient_req_t *req, const char *errstr, int32_t hq_reason)
{
    req->super._cb.on_body(&req->super, errstr);
    close_request(req, hq_reason);
    return 0;
}

static int on_update_expect_data_payload(quicly_stream_t *_stream)
{
    struct st_h2o_hqclient_req_t *req = _stream->data;
    ptls_iovec_t input;

    assert(req->bytes_left != 0);

    if (quicly_recvbuf_is_shutdown(&req->stream->recvbuf))
        return on_error_in_body(req, "unexpected EOS", H2O_HQ_ERROR_MALFORMED_FRAME(H2O_HQ_FRAME_TYPE_DATA));

    while ((input = quicly_recvbuf_get(&req->stream->recvbuf)).len != 0) {
        if (input.len > req->bytes_left) {
            input.len = req->bytes_left;
            req->bytes_left = 0;
        } else {
            req->bytes_left -= input.len;
        }
        h2o_buffer_append(&req->respbuf, input.base, input.len);
        quicly_recvbuf_shift(&req->stream->recvbuf, input.len);
        if (req->bytes_left == 0) {
            req->stream->on_update = on_update_expect_data_frame;
            return req->stream->on_update(req->stream);
        }
    }

    return 0;
}

int on_update_expect_data_frame(quicly_stream_t *_stream)
{
    struct st_h2o_hqclient_req_t *req = _stream->data;
    h2o_hq_peek_frame_t frame;
    int ret;

    /* handle close */
    if (quicly_recvbuf_is_shutdown(&req->stream->recvbuf))
        return on_error_in_body(req, h2o_httpclient_error_is_eos, H2O_HQ_ERROR_NO_ERROR);

    /* read frame header */
    if ((ret = h2o_hq_peek_frame(&req->stream->recvbuf, &frame)) != 0) {
        assert(ret == H2O_HQ_ERROR_INCOMPLETE);
        return 0;
    }
    switch (frame.type) {
    case H2O_HQ_FRAME_TYPE_DATA:
        break;
    default:
        /* FIXME handle push_promise, trailers */
        return on_error_in_body(req, "unexpected frame", H2O_HQ_ERROR_GENERAL_PROTOCOL); /* FIXME error code */
    }
    if (frame.length == 0)
        return on_error_in_body(req, "malformed frame", H2O_HQ_ERROR_MALFORMED_FRAME(H2O_HQ_FRAME_TYPE_DATA));
    h2o_hq_shift_frame(&req->stream->recvbuf, &frame);

    req->bytes_left = frame.length;
    req->stream->on_update = on_update_expect_data_payload;
    return req->stream->on_update(req->stream);
}

static int on_update_expect_header(quicly_stream_t *_stream)
{
    struct st_h2o_hqclient_req_t *req = _stream->data;
    h2o_hq_peek_frame_t frame;
    int status;
    h2o_headers_t headers = {NULL};
    size_t content_length;
    uint8_t header_ack[H2O_HPACK_ENCODE_INT_MAX_LENGTH];
    size_t header_ack_len;
    const char *err_desc = NULL;
    int ret;

    /* error handling */
    if (quicly_recvbuf_is_shutdown(&req->stream->recvbuf))
        return on_error_before_head(req, "unexpected shutdown", H2O_HQ_ERROR_GENERAL_PROTOCOL);

    /* read HEADERS frame */
    if ((ret = h2o_hq_peek_frame(&req->stream->recvbuf, &frame)) != 0) {
        if (ret == H2O_HQ_ERROR_INCOMPLETE)
            return 0;
        return on_error_before_head(req, "response header too large", H2O_HQ_ERROR_GENERAL_PROTOCOL); /* FIXME correct code? */
    }
    if (frame.type != H2O_HQ_FRAME_TYPE_HEADERS)
        return on_error_before_head(req, "unexpected frame", H2O_HQ_ERROR_GENERAL_PROTOCOL);
    if ((ret = h2o_qpack_parse_response(req->super.pool, req->conn->super.qpack.dec, req->stream->stream_id, &status, &headers,
                                        &content_length, header_ack, &header_ack_len, frame.payload, frame.length, &err_desc)) !=
        0) {
        if (ret == H2O_HTTP2_ERROR_INCOMPLETE)
            return 0;
        return on_error_before_head(req, err_desc != NULL ? err_desc : "qpack error", H2O_HQ_ERROR_GENERAL_PROTOCOL /* FIXME */);
    }
    h2o_hq_shift_frame(&req->stream->recvbuf, &frame);
    if ((ret = quicly_sendbuf_write(&req->stream->sendbuf, header_ack, header_ack_len, NULL)) != 0)
        h2o_fatal("no memory");

    /* handle 1xx */
    if (100 <= status && status <= 199) {
        if (quicly_recvbuf_is_shutdown(&req->stream->recvbuf))
            return on_error_before_head(req, "unexpected shutdown", H2O_HQ_ERROR_GENERAL_PROTOCOL);
        if (status == 101)
            return on_error_before_head(req, "unexpected 101", H2O_HQ_ERROR_GENERAL_PROTOCOL);
        if (req->super.informational_cb != NULL &&
            req->super.informational_cb(&req->super, 0, status, h2o_iovec_init(NULL, 0), headers.entries, headers.size) != 0) {
            close_request(req, H2O_HQ_ERROR_INTERNAL);
            return 0;
        }
        return 0;
    }

    /* handle final response */
    if ((req->super._cb.on_body = req->super._cb.on_head(
             &req->super, quicly_recvbuf_is_shutdown(&req->stream->recvbuf) ? h2o_httpclient_error_is_eos : NULL, 0, status,
             h2o_iovec_init(NULL, 0), headers.entries, headers.size, 0, 0)) == NULL) {
        close_request(req, H2O_HQ_ERROR_INTERNAL);
        return 0;
    }
    if (quicly_recvbuf_is_shutdown(&req->stream->recvbuf)) {
        close_request(req, H2O_HQ_ERROR_NO_ERROR);
        return 0;
    }

    /* handle body (or prepare to handle body) */
    req->stream->on_update = on_update_expect_data_frame;
    if (quicly_recvbuf_available(&req->stream->recvbuf) != 0)
        return req->stream->on_update(req->stream);
    return 0;
}

static void start_request(struct st_h2o_hqclient_req_t *req)
{
    h2o_iovec_t method;
    h2o_url_t url;
    const h2o_header_t *headers;
    size_t num_headers;
    h2o_iovec_t body;
    h2o_httpclient_proceed_req_cb proceed_req;
    h2o_httpclient_properties_t props = {NULL};
    int ret;

    assert(!h2o_linklist_is_linked(&req->link));

    if ((req->super._cb.on_head = req->super._cb.on_connect(&req->super, NULL, &method, &url, &headers, &num_headers, &body,
                                                            &proceed_req, &props, &req->conn->server.origin_url)) == NULL) {
        close_request(req, H2O_HQ_ERROR_NO_ERROR /* ignored */);
        return;
    }
    assert(body.base == NULL && proceed_req == NULL); /* FIXME add request entity support */

    if ((ret = quicly_open_stream(req->conn->super.quic, &req->stream, 0)) != 0) {
        on_error_before_head(req, "failed to open stream", H2O_HQ_ERROR_NO_ERROR /* ignored */);
        return;
    }
    req->stream->data = req;

    h2o_byte_vector_t buf = {NULL};
    h2o_hq_encode_frame(req->super.pool, &buf, H2O_HQ_FRAME_TYPE_HEADERS, {
        h2o_qpack_flatten_request(req->conn->super.qpack.enc, req->super.pool, &buf, method, url.scheme, url.authority, url.path,
                                  headers, num_headers);
    });
    if (quicly_sendbuf_write(&req->stream->sendbuf, buf.entries, buf.size, NULL) != 0)
        h2o_fatal("no memory");

    quicly_sendbuf_shutdown(&req->stream->sendbuf);

    req->stream->on_update = on_update_expect_header;
}

static void cancel_request(h2o_httpclient_t *_client)
{
    struct st_h2o_hqclient_req_t *req = (void *)_client;
    close_request(req, H2O_HQ_ERROR_REQUEST_CANCELLED);
}

void h2o_httpclient_connect_hq(h2o_httpclient_t **_client, h2o_mem_pool_t *pool, void *data, h2o_httpclient_ctx_t *ctx,
                               h2o_url_t *target, h2o_httpclient_connect_cb cb)
{
    struct st_h2o_hqclient_conn_t *conn;
    struct st_h2o_hqclient_req_t *req;

    if ((conn = find_connection(ctx, target)) == NULL)
        conn = create_connection(ctx, target);

    req = h2o_mem_alloc(sizeof(*req));
    *req = (struct st_h2o_hqclient_req_t){{pool, ctx, NULL, NULL, data, NULL, {h2o_gettimeofday(ctx->loop)}, cancel_request}, conn};
    req->super._cb.on_connect = cb;

    if (conn->super.quic != NULL && quicly_connection_is_ready(conn->super.quic)) {
        start_request(req);
    } else {
        h2o_linklist_insert(&conn->pending_requests, &req->link);
    }
}
