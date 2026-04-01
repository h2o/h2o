/*
 * Copyright (c) 2018 Ichito Nagata, Fastly, Inc.
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

#include "h2o/httpclient.h"

const char h2o_httpclient_error_is_eos[] = "end of stream";
const char h2o_httpclient_error_refused_stream[] = "refused stream";
const char h2o_httpclient_error_unknown_alpn_protocol[] = "unknown alpn protocol";
const char h2o_httpclient_error_io[] = "I/O error";
const char h2o_httpclient_error_connect_timeout[] = "connection timeout";
const char h2o_httpclient_error_first_byte_timeout[] = "first byte timeout";
const char h2o_httpclient_error_io_timeout[] = "I/O timeout";
const char h2o_httpclient_error_invalid_content_length[] = "invalid content-length";
const char h2o_httpclient_error_flow_control[] = "flow control error";
const char h2o_httpclient_error_http1_line_folding[] = "line folding of header fields is not supported";
const char h2o_httpclient_error_http1_unexpected_transfer_encoding[] = "unexpected type of transfer-encoding";
const char h2o_httpclient_error_http1_parse_failed[] = "failed to parse the response";
const char h2o_httpclient_error_protocol_violation[] = "protocol violation";
const char h2o_httpclient_error_internal[] = "internal error";
const char h2o_httpclient_error_malformed_frame[] = "malformed HTTP frame";
const char h2o_httpclient_error_unexpected_101[] = "received unexpected 101 response";

/**
 * Used to indicate that the HTTP request is to be "upgraded" into a CONNECT tunnel.
 */
const char h2o_httpclient_upgrade_to_connect[] = "\nCONNECT / CONNECT-UDP method";

void h2o_httpclient_connection_pool_init(h2o_httpclient_connection_pool_t *connpool, h2o_socketpool_t *sockpool)
{
    connpool->socketpool = sockpool;
    h2o_linklist_init_anchor(&connpool->http2.conns);
    h2o_linklist_init_anchor(&connpool->http3.conns);
}

static void close_client(h2o_httpclient_t *client)
{
    if (client->_connect_req != NULL) {
        h2o_socketpool_cancel_connect(client->_connect_req);
        client->_connect_req = NULL;
    }

    if (h2o_timer_is_linked(&client->_timeout))
        h2o_timer_unlink(&client->_timeout);

    free(client);
}

static void on_connect_error(h2o_httpclient_t *client, const char *errstr)
{
    assert(errstr != NULL);
    client->_cb.on_connect(client, errstr, NULL, NULL, NULL, 0, NULL, NULL, NULL, NULL);
    close_client(client);
}

static void on_connect_timeout(h2o_timer_t *entry)
{
    h2o_httpclient_t *client = H2O_STRUCT_FROM_MEMBER(h2o_httpclient_t, _timeout, entry);
    on_connect_error(client, h2o_httpclient_error_connect_timeout);
}

static void do_cancel(h2o_httpclient_t *_client)
{
    h2o_httpclient_t *client = (void *)_client;
    close_client(client);
}

static h2o_httpclient_t *create_client(h2o_httpclient_t **_client, h2o_mem_pool_t *pool, void *data, h2o_httpclient_ctx_t *ctx,
                                       h2o_httpclient_connection_pool_t *connpool, const char *upgrade_to,
                                       h2o_httpclient_connect_cb on_connect)
{
#define SZ_MAX(x, y) ((x) > (y) ? (x) : (y))
    size_t sz = SZ_MAX(h2o_httpclient__h1_size, h2o_httpclient__h2_size);
#undef SZ_MAX
    h2o_httpclient_t *client = h2o_mem_alloc(sz);
    memset(client, 0, sz);
    client->pool = pool;
    client->ctx = ctx;
    client->data = data;
    client->upgrade_to = upgrade_to;
    client->connpool = connpool;
    client->cancel = do_cancel;
    client->_cb.on_connect = on_connect;
    client->_timeout.cb = on_connect_timeout;
    client->timings.start_at = h2o_gettimeofday(ctx->loop);

    if (_client != NULL)
        *_client = client;

    return client;
}

static void on_pool_connect(h2o_socket_t *sock, const char *errstr, void *data, h2o_url_t *origin)
{
    h2o_httpclient_t *client = data;

    h2o_timer_unlink(&client->_timeout);

    client->_connect_req = NULL;

    if (sock == NULL) {
        assert(errstr != NULL);
        on_connect_error(client, errstr);
        return;
    }

    h2o_iovec_t alpn_proto;
    if (client->ctx->force_cleartext_http2 && sock->ssl == NULL && client->ctx->protocol_selector.ratio.http2 == 100) {
        /* The client has prior knowledge and wants to use http2 without
         * discovery or upgrade. Make sure that we're using a 100%
         * H2 context, to avoid having this connection reused for H1
         * accidentaly */
        goto ForceH2;
    } else if (sock->ssl == NULL || (alpn_proto = h2o_socket_ssl_get_selected_protocol(sock)).len == 0) {
        h2o_httpclient__h1_on_connect(client, sock, origin);
    } else {
        if (h2o_memis(alpn_proto.base, alpn_proto.len, H2O_STRLIT("h2"))) {
        ForceH2:
            /* detach this socket from the socketpool to count the number of h1 connections correctly */
            h2o_socketpool_detach(client->connpool->socketpool, sock);
            h2o_httpclient__h2_on_connect(client, sock, origin);
        } else if (memcmp(alpn_proto.base, "http/1.1", alpn_proto.len) == 0) {
            h2o_httpclient__h1_on_connect(client, sock, origin);
        } else {
            on_connect_error(client, h2o_httpclient_error_unknown_alpn_protocol);
        }
    }
}

enum {
    /**
     * indicates that H1 should be chosen
     */
    PROTOCOL_SELECTOR_H1,
    /**
     * indicates that H2 should be chosen (though the server might fallback to H1)
     */
    PROTOCOL_SELECTOR_H2,
    /**
     * indicates that H3 should be chosen
     */
    PROTOCOL_SELECTOR_H3,
    /**
     * used when ratio.http2 < 0; see h2o_httpclient_ctx_t::protocol_selector.ratio.http2
     */
    PROTOCOL_SELECTOR_SERVER_DRIVEN,
    /**
     * total number
     */
    PROTOCOL_SELECTOR_COUNT
};

static size_t select_protocol(struct st_h2o_httpclient_protocol_selector_t *selector)
{
    H2O_BUILD_ASSERT(PTLS_ELEMENTSOF(selector->_deficits) == PROTOCOL_SELECTOR_COUNT);

    /* update the deficits */
    if (selector->ratio.http2 < 0) {
        selector->_deficits[PROTOCOL_SELECTOR_SERVER_DRIVEN] += 100 - selector->ratio.http3;
    } else {
        selector->_deficits[PROTOCOL_SELECTOR_H1] += 100 - selector->ratio.http2 - selector->ratio.http3;
        selector->_deficits[PROTOCOL_SELECTOR_H2] += selector->ratio.http2;
    }
    selector->_deficits[PROTOCOL_SELECTOR_H3] += selector->ratio.http3;

    /* select one with the highest value */
    size_t result = 0;
    for (size_t i = 1; i < PROTOCOL_SELECTOR_COUNT; ++i) {
        if (selector->_deficits[result] < selector->_deficits[i])
            result = i;
    }

    /* decrement the one being selected */
    selector->_deficits[result] -= 100;

    return result;
}

static struct st_h2o_httpclient__h2_conn_t *find_h2conn(h2o_httpclient_connection_pool_t *pool, h2o_url_t *target)
{
    int should_check_target = h2o_socketpool_is_global(pool->socketpool);

    for (h2o_linklist_t *l = pool->http2.conns.next; l != &pool->http2.conns; l = l->next) {
        struct st_h2o_httpclient__h2_conn_t *conn = H2O_STRUCT_FROM_MEMBER(struct st_h2o_httpclient__h2_conn_t, link, l);
        if (should_check_target && !(conn->origin_url.scheme == target->scheme &&
                                     h2o_memis(conn->origin_url.authority.base, conn->origin_url.authority.len,
                                               target->authority.base, target->authority.len)))
            continue;
        if (conn->num_streams >= h2o_httpclient__h2_get_max_concurrent_streams(conn))
            continue;
        return conn;
    }

    return NULL;
}

static void connect_using_socket_pool(h2o_httpclient_t **_client, h2o_mem_pool_t *pool, void *data, h2o_httpclient_ctx_t *ctx,
                                      h2o_httpclient_connection_pool_t *connpool, h2o_url_t *origin, const char *upgrade_to,
                                      h2o_httpclient_connect_cb on_connect, h2o_iovec_t alpn_protos)
{
    h2o_httpclient_t *client = create_client(_client, pool, data, ctx, connpool, upgrade_to, on_connect);
    h2o_timer_link(client->ctx->loop, client->ctx->connect_timeout, &client->_timeout);
    h2o_socketpool_connect(&client->_connect_req, connpool->socketpool, origin, ctx->loop, ctx->getaddr_receiver, alpn_protos,
                           on_pool_connect, client);
}

static void connect_using_h2conn(h2o_httpclient_t **_client, h2o_mem_pool_t *pool, void *data,
                                 struct st_h2o_httpclient__h2_conn_t *conn, h2o_httpclient_connection_pool_t *connpool,
                                 const char *upgrade_to, h2o_httpclient_connect_cb on_connect)
{
    h2o_httpclient_t *client = create_client(_client, pool, data, conn->ctx, connpool, upgrade_to, on_connect);
    h2o_httpclient__h2_on_connect(client, conn->sock, &conn->origin_url);
}

void h2o_httpclient_connect(h2o_httpclient_t **_client, h2o_mem_pool_t *pool, void *data, h2o_httpclient_ctx_t *ctx,
                            h2o_httpclient_connection_pool_t *connpool, h2o_url_t *origin, const char *upgrade_to,
                            h2o_httpclient_connect_cb on_connect)
{
    static const h2o_iovec_t no_protos = {}, both_protos = {H2O_STRLIT("\x02"
                                                                       "h2"
                                                                       "\x08"
                                                                       "http/1.1")};
    assert(connpool != NULL);

    size_t selected_protocol = select_protocol(&ctx->protocol_selector);

    /* adjust selected protocol if the attempt is to create a tunnel */
    if (upgrade_to != NULL) {
        /* TODO provide a knob to map each upgrade token to some, all, or no HTTP version. Until that is done, upgrade other than to
         * a CONNECT and CONNECT-UDP tunnel is directed to H1. */
        if (upgrade_to != h2o_httpclient_upgrade_to_connect && strcmp(upgrade_to, "connect-udp") != 0)
            selected_protocol = PROTOCOL_SELECTOR_H1;
    }

    switch (selected_protocol) {
    case PROTOCOL_SELECTOR_H1:
        /* H1: use the socket pool to obtain a connection, without any ALPN */
        connect_using_socket_pool(_client, pool, data, ctx, connpool, origin, upgrade_to, on_connect, no_protos);
        break;
    case PROTOCOL_SELECTOR_H2: {
        /* H2: use existing H2 connection (if any) or create a new connection offering both H1 and H2 */
        struct st_h2o_httpclient__h2_conn_t *h2conn = find_h2conn(connpool, origin);
        if (h2conn != NULL) {
            connect_using_h2conn(_client, pool, data, h2conn, connpool, upgrade_to, on_connect);
        } else {
            connect_using_socket_pool(_client, pool, data, ctx, connpool, origin, upgrade_to, on_connect, both_protos);
        }
    } break;
    case PROTOCOL_SELECTOR_H3:
        h2o_httpclient__connect_h3(_client, pool, data, ctx, connpool, origin, upgrade_to, on_connect);
        break;
    case PROTOCOL_SELECTOR_SERVER_DRIVEN: {
        /* offer H2 the server, but evenly distribute the load among existing H1 and H2 connections */
        struct st_h2o_httpclient__h2_conn_t *h2conn = find_h2conn(connpool, origin);
        if (h2conn != NULL && connpool->socketpool->_shared.pooled_count != 0) {
            /* both of h1 and h2 connections exist, compare in-use ratio */
            double http1_ratio = (double)(connpool->socketpool->_shared.count - connpool->socketpool->_shared.pooled_count) /
                                 connpool->socketpool->_shared.count;
            double http2_ratio = (double)h2conn->num_streams / h2o_httpclient__h2_get_max_concurrent_streams(h2conn);
            if (http2_ratio <= http1_ratio) {
                connect_using_h2conn(_client, pool, data, h2conn, connpool, upgrade_to, on_connect);
            } else {
                connect_using_socket_pool(_client, pool, data, ctx, connpool, origin, upgrade_to, on_connect, no_protos);
            }
        } else if (h2conn != NULL) {
            /* h2 connection exists */
            connect_using_h2conn(_client, pool, data, h2conn, connpool, upgrade_to, on_connect);
        } else if (connpool->socketpool->_shared.pooled_count != 0) {
            /* h1 connection exists */
            connect_using_socket_pool(_client, pool, data, ctx, connpool, origin, upgrade_to, on_connect, no_protos);
        } else {
            /* no connections, connect using ALPN */
            connect_using_socket_pool(_client, pool, data, ctx, connpool, origin, upgrade_to, on_connect, both_protos);
        }
    } break;
    }
}

void h2o_httpclient_set_conn_properties_of_socket(h2o_socket_t *sock, h2o_httpclient_conn_properties_t *properties)
{
    properties->ssl.protocol_version = h2o_socket_get_ssl_protocol_version(sock);
    properties->ssl.session_reused = h2o_socket_get_ssl_session_reused(sock);
    properties->ssl.cipher = h2o_socket_get_ssl_cipher(sock);
    properties->ssl.cipher_bits = h2o_socket_get_ssl_cipher_bits(sock);
    properties->sock = sock;
}
