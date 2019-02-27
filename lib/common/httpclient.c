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

void h2o_httpclient_connection_pool_init(h2o_httpclient_connection_pool_t *connpool, h2o_socketpool_t *sockpool)
{
    connpool->socketpool = sockpool;
    h2o_linklist_init_anchor(&connpool->http2.conns);
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
    on_connect_error(client, "connection timeout");
}

static void do_cancel(h2o_httpclient_t *_client)
{
    h2o_httpclient_t *client = (void *)_client;
    close_client(client);
}

static h2o_httpclient_t *create_client(h2o_mem_pool_t *pool, void *data, h2o_httpclient_ctx_t *ctx, h2o_httpclient_connect_cb cb)
{
#define SZ_MAX(x, y) ((x) > (y) ? (x) : (y))
    size_t sz = SZ_MAX(h2o_httpclient__h1_size, h2o_httpclient__h2_size);
#undef SZ_MAX
    h2o_httpclient_t *client = h2o_mem_alloc(sz);
    memset(client, 0, sz);
    client->pool = pool;
    client->ctx = ctx;
    client->data = data;
    client->cancel = do_cancel;
    client->steal_socket = NULL;
    client->get_socket = NULL;
    client->update_window = NULL;
    client->write_req = NULL;
    client->_cb.on_connect = cb;
    client->_timeout.cb = on_connect_timeout;

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
    if (sock->ssl == NULL || (alpn_proto = h2o_socket_ssl_get_selected_protocol(sock)).len == 0) {
        h2o_httpclient__h1_on_connect(client, sock, origin);
    } else {
        if (h2o_memis(alpn_proto.base, alpn_proto.len, H2O_STRLIT("h2"))) {
            /* detach this socket from the socketpool to count the number of h1 connections correctly */
            h2o_socketpool_detach(client->connpool->socketpool, sock);
            h2o_httpclient__h2_on_connect(client, sock, origin);
        } else if (memcmp(alpn_proto.base, "http/1.1", alpn_proto.len) == 0) {
            h2o_httpclient__h1_on_connect(client, sock, origin);
        } else {
            on_connect_error(client, "unknown alpn protocol");
        }
    }
}

static int should_use_h2(int8_t ratio, int8_t *counter)
{
    /* weighted fair queueing */
    if (*counter < 0)
        *counter = ratio == 0 ? 0 : 50 / ratio; /* set initial counter value */
    int use_h2 = (((int)ratio * *counter) % 100) + ratio >= 100;
    if (++*counter == 100)
        *counter = 0;
    return use_h2;
}

void h2o_httpclient_connect(h2o_httpclient_t **_client, h2o_mem_pool_t *pool, void *data, h2o_httpclient_ctx_t *ctx,
                            h2o_httpclient_connection_pool_t *connpool, h2o_url_t *origin, h2o_httpclient_connect_cb cb)
{
    static const h2o_iovec_t both_protos = {H2O_STRLIT("\x02"
                                                       "h2"
                                                       "\x08"
                                                       "http/1.1")};
    assert(connpool != NULL);
    h2o_iovec_t alpn_protos = h2o_iovec_init(NULL, 0);

    h2o_httpclient_t *client = create_client(pool, data, ctx, cb);
    client->connpool = connpool;
    if (_client != NULL)
        *_client = client;

    client->timings.start_at = h2o_gettimeofday(ctx->loop);

    h2o_httpclient__h2_conn_t *http2_conn = NULL;
    if (!h2o_linklist_is_empty(&connpool->http2.conns)) {
        http2_conn = H2O_STRUCT_FROM_MEMBER(h2o_httpclient__h2_conn_t, link, connpool->http2.conns.next);
        if (http2_conn->num_streams >= h2o_httpclient__h2_get_max_concurrent_streams(http2_conn))
            http2_conn = NULL;
    }

    if (ctx->http2.ratio < 0) {
        /* mix mode */

        if (http2_conn != NULL && connpool->socketpool->_shared.pooled_count != 0) {
            /* both of h1 and h2 connections exist, compare in-use ratio */
            double http1_ratio = (double)(connpool->socketpool->_shared.count - connpool->socketpool->_shared.pooled_count) /
                                 connpool->socketpool->_shared.count;
            double http2_ratio = http2_conn->num_streams / h2o_httpclient__h2_get_max_concurrent_streams(http2_conn);
            if (http2_ratio <= http1_ratio) {
                h2o_httpclient__h2_on_connect(client, http2_conn->sock, &http2_conn->origin_url);
            } else {
                goto UseSocketPool;
            }
        } else if (http2_conn != NULL) {
            /* h2 connection exists */
            h2o_httpclient__h2_on_connect(client, http2_conn->sock, &http2_conn->origin_url);
        } else if (connpool->socketpool->_shared.pooled_count != 0) {
            /* h1 connection exists */
            goto UseSocketPool;
        } else {
            /* no connections, connect using ALPN */
            alpn_protos = both_protos;
            goto UseSocketPool;
        }
    } else {
        /* fixed ratio mode */

        if (should_use_h2(ctx->http2.ratio, &ctx->http2.counter)) {
            if (http2_conn != NULL) {
                h2o_httpclient__h2_on_connect(client, http2_conn->sock, &http2_conn->origin_url);
            } else {
                alpn_protos = both_protos;
                goto UseSocketPool;
            }
        } else {
            goto UseSocketPool;
        }
    }

    return;

UseSocketPool:
    h2o_timer_link(client->ctx->loop, client->ctx->connect_timeout, &client->_timeout);
    h2o_socketpool_connect(&client->_connect_req, connpool->socketpool, origin, ctx->loop, ctx->getaddr_receiver, alpn_protos,
                           on_pool_connect, client);
}

void h2o_httpclient_connect_with_socket(h2o_httpclient_t **_client, h2o_mem_pool_t *pool, void *data, h2o_httpclient_ctx_t *ctx, h2o_socket_t *sock, h2o_httpclient_connect_cb cb)
{
    h2o_httpclient_t *client = create_client(pool, data, ctx, cb);
	client->disable_socket_close = 1;
    if (_client != NULL)
        *_client = client;

    client->timings.start_at = h2o_gettimeofday(ctx->loop);
    /* currently only support h1 */
    h2o_httpclient__h1_on_connect(client, sock, NULL);
}
