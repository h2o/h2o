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
#include "h2o/http1client.h"
#include "h2o/http2client.h"
#include "h2o/httpclient_internal.h"

void h2o_httpclient_connection_pool_init(h2o_httpclient_connection_pool_t *connpool, h2o_socketpool_t *sockpool)
{
    connpool->socketpool = sockpool;
    h2o_linklist_init_anchor(&connpool->http2.conns);
}

static struct st_h2o_httpclient_private_t *create_client(void *data, h2o_httpclient_ctx_t *ctx, h2o_httpclient_connect_cb cb)
{
    struct st_h2o_httpclient_private_t *client = h2o_mem_alloc(sizeof(*client));
    memset(client, 0, sizeof(*client));
    client->super.ctx = ctx;
    client->super.data = data;
    client->super.cancel = NULL;
    client->super.steal_socket = NULL;
    client->super.update_window = NULL;
    client->super.write_req = NULL;
    client->cb.on_connect = cb;

    return client;
}

static void close_client(struct st_h2o_httpclient_private_t *client)
{
    if (client->super.conn.req != NULL) {
        h2o_socketpool_cancel_connect(client->super.conn.req);
        client->super.conn.req = NULL;
    }

    // FIXME
//    if (h2o_timeout_is_linked(&client->_timeout))
//        h2o_timeout_unlink(&client->_timeout);
//    if (client->_body_buf != NULL)
//        h2o_buffer_dispose(&client->_body_buf);
//    if (client->_body_buf_in_flight != NULL)
//        h2o_buffer_dispose(&client->_body_buf_in_flight);
//    h2o_mem_clear_pool(&client->pool);
//    --client->super->ctx->http1.num_inflight_connections;
    free(client);
}

static void on_connect_error(struct st_h2o_httpclient_private_t *client, const char *errstr)
{
    assert(errstr != NULL);
    client->cb.on_connect(&client->super, errstr, NULL, NULL, NULL, NULL, NULL, (h2o_httpclient_features_t){NULL}, NULL);
    close_client(client);
}

static void on_pool_connect(h2o_socket_t *sock, const char *errstr, void *data, h2o_url_t *origin, h2o_iovec_t alpn_proto, int pooled)
{
    struct st_h2o_httpclient_private_t *client = data;


    client->super.conn.req = NULL;

    if (sock == NULL) {
        assert(errstr != NULL);
//        h2o_timeout_unlink(&client->_timeout); // FIXME
        on_connect_error(client, errstr);
        return;
    }

    if (alpn_proto.base == NULL) {
        h2o_http1client_on_connect(&client->http1, sock, origin, pooled);
    } else {
        if (memcmp(alpn_proto.base, "h2", alpn_proto.len) == 0) {
            h2o_http2client_on_connect(&client->http2, sock, origin, 0);
        } else if (memcmp(alpn_proto.base, "http/1.1", alpn_proto.len) == 0) {
            h2o_http1client_on_connect(&client->http1, sock, origin, pooled);
        } else {
            on_connect_error(client, "unknown alpn protocol");
        }
    }
}

void h2o_httpclient_connect(h2o_httpclient_t **_client, void *data, h2o_httpclient_ctx_t *ctx, h2o_httpclient_connection_pool_t *connpool,
                            h2o_url_t *origin, h2o_httpclient_connect_cb cb)
{
    static const h2o_iovec_t both_protos = {H2O_STRLIT(
                                                       "\x02"
                                                       "h2"
                                                       "\x08"
                                                       "http/1.1"
                                                       )};
    assert(connpool != NULL);
    h2o_iovec_t alpn_protos = h2o_iovec_init(NULL, 0);

    struct st_h2o_httpclient_private_t *client = create_client(data, ctx, cb);
    client->super.conn.pool = connpool;
    if (_client != NULL)
        *_client = &client->super;

    struct st_h2o_http2client_conn_t *http2_conn = NULL;
    if (!h2o_linklist_is_empty(&connpool->http2.conns)) {
        http2_conn = H2O_STRUCT_FROM_MEMBER(struct st_h2o_http2client_conn_t, link, connpool->http2.conns.next);
        if (http2_conn->num_streams >= h2o_http2client_get_max_concurrent_streams(http2_conn))
            http2_conn = NULL;
    }

    /* compare in-use ratio */
    if (http2_conn != NULL && connpool->http1.num_pooled_connections != 0) {
        double http1_ratio = (double)connpool->http1.num_inflight_connections / connpool->http1.num_pooled_connections;
        double http2_ratio = http2_conn->num_streams / h2o_http2client_get_max_concurrent_streams(http2_conn);
        if (http2_ratio <= http1_ratio) {
            fprintf(stderr, "##### both h1 and h2 has pooled connections, but h2 selected\n");
            h2o_http2client_on_connect(&client->http2, http2_conn->sock, &http2_conn->origin_url, 1);
            return;
        } else {
            fprintf(stderr, "##### both h1 and h2 has pooled connections, but h1 selected (if ssl is used)\n");
            alpn_protos = both_protos;
            goto UseSocketPool;
        }
    }

    /* reuse idle h2 connection */
    if (http2_conn != NULL) {
        fprintf(stderr, "##### h2 has pooled connections\n");
        h2o_http2client_on_connect(&client->http2, http2_conn->sock, &http2_conn->origin_url, 1);
        return;
    }

    /* reuse pooled h1 connection via socketpool */
    if (connpool->http1.num_pooled_connections != 0) {
        fprintf(stderr, "##### h1 has pooled connections\n");
        goto UseSocketPool;
    }

    /* connect using ALPN */
    alpn_protos = both_protos;
    fprintf(stderr, "##### no pooled connections, use ALPN\n");

UseSocketPool:
    h2o_socketpool_connect(&client->super.conn.req, connpool->socketpool, origin, ctx->loop, ctx->getaddr_receiver, alpn_protos, on_pool_connect, client);

}
