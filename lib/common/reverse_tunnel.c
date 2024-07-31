/*
 * Copyright (c) 2024 Ichito Nagata, Fastly, Inc.
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

#include "h2o/reverse_tunnel.h"
#include "h2o.h"

static inline void schedule_reconnect(h2o_reverse_ctx_t *reverse)
{
    h2o_timer_link(reverse->accept_ctx->ctx->loop, reverse->config.reconnect_interval, &reverse->reconnect_timer);
}

struct on_reverse_close_data_t {
    void (*orig_cb)(void *data);
    void *orig_data;
    h2o_reverse_ctx_t *reverse;
};

void on_reverse_close(void *_data) {
    struct on_reverse_close_data_t *data = (void *)_data;
    data->orig_cb(data->orig_data);

    h2o_reverse_ctx_t *reverse = data->reverse;
    reverse->httpclient.client = NULL;
    h2o_mem_clear_pool(&reverse->pool);

    schedule_reconnect(reverse);
}

static void on_reverse_reconnect_timeout(h2o_timer_t *timer)
{
    h2o_reverse_ctx_t *reverse = H2O_STRUCT_FROM_MEMBER(h2o_reverse_ctx_t, reconnect_timer, timer);
    h2o_reverse_start_listening(reverse);
}

static void on_reverse_read(h2o_socket_t *sock, const char *err)
{
    h2o_reverse_ctx_t *reverse = (void *)sock->data;

    h2o_socket_read_stop(sock);
    if (err != NULL) {
        h2o_error_printf("unexpected read error in on_reverse_rea: %s\n", err);
        return;
    }

    h2o_accept(reverse->accept_ctx, sock);
}

static h2o_httpclient_body_cb on_reverse_head(h2o_httpclient_t *client, const char *errstr, h2o_httpclient_on_head_t *args)
{
    h2o_reverse_ctx_t *reverse = (void *)client->data;

    if (errstr != NULL) {
        h2o_error_printf("received error in on_reverse_head: %s\n", errstr);
        schedule_reconnect(reverse);
        return NULL;
    }

    if (args->status != 101) {
        h2o_error_printf("received unexpected status in on_reverse_head: %u\n", args->status);
        schedule_reconnect(reverse);
        return NULL;
    }


    // replace sock's on_close data with our own to retry on close
    h2o_httpclient_conn_properties_t conn_props;
    client->get_conn_properties(client, &conn_props);

    struct on_reverse_close_data_t *data = h2o_mem_alloc_pool(&reverse->pool, *data, sizeof(*data));
    data->reverse = reverse;
    data->orig_cb = conn_props.sock->on_close.cb;
    data->orig_data = conn_props.sock->on_close.data;
    conn_props.sock->on_close.cb = on_reverse_close;
    conn_props.sock->on_close.data = data;

    conn_props.sock->data = reverse;

    if (reverse->config.setup_socket != NULL)
        reverse->config.setup_socket(conn_props.sock, reverse->data);

    h2o_socket_read_stop(conn_props.sock);
    h2o_socket_read_start(conn_props.sock, on_reverse_read);

    return h2o_httpclient_socket_stealed;
}

// this callback is actually never called, but needed just to signal that streaming mode is enabled
static void reverse_proceed_request(h2o_httpclient_t *client, const char *errstr)
{
    if (errstr != NULL)
        h2o_error_printf("reverse_proceed_request failed: %s\n", errstr);
}


static h2o_httpclient_head_cb on_reverse_connect(h2o_httpclient_t *client, const char *errstr, h2o_iovec_t *method, h2o_url_t *url,
                                         const h2o_header_t **headers, size_t *num_headers, h2o_iovec_t *body,
                                         h2o_httpclient_proceed_req_cb *proceed_req_cb, h2o_httpclient_properties_t *props,
                                         h2o_url_t *origin)
{
    h2o_reverse_ctx_t *reverse = (void *)client->data;

    if (errstr != NULL) {
        h2o_error_printf("error in on_reverse_connect: %s\n", errstr);
        schedule_reconnect(reverse);
        return NULL;
    }

    // setup request
    *method = h2o_iovec_init(H2O_STRLIT("GET"));
    *url = *reverse->client;

    h2o_headers_t headers_vec = (h2o_headers_t){};
    h2o_add_header_by_str(&reverse->pool, &headers_vec, H2O_STRLIT("ALPN"), 0, NULL, H2O_STRLIT("http%2F1.1"));
    *headers = headers_vec.entries;
    *num_headers = headers_vec.size;
    *body = h2o_iovec_init(NULL, 0);
    *proceed_req_cb = reverse_proceed_request;

    return on_reverse_head;
}

void h2o_reverse_init(h2o_reverse_ctx_t *reverse, h2o_url_t *client, h2o_accept_ctx_t *accept_ctx, h2o_reverse_config_t config, void *data)
{
    reverse->client = client;
    reverse->config = config;
    reverse->accept_ctx = accept_ctx;
    h2o_timer_init(&reverse->reconnect_timer, on_reverse_reconnect_timeout);
    reverse->data = data;

    reverse->httpclient.ctx = (h2o_httpclient_ctx_t){
        .loop = accept_ctx->ctx->loop,
        .getaddr_receiver = &accept_ctx->ctx->receivers.hostinfo_getaddr,
        // TODO: make these parameters configurable
        .io_timeout = 10000,
        .connect_timeout = 10000,
        .first_byte_timeout = 10000,
        .keepalive_timeout = 10000,
        .max_buffer_size = SIZE_MAX,
        .protocol_selector = {.ratio = { .http2 = 0, .http3 = 0}}, // now only supports h1
    };
    reverse->httpclient.connpool = (h2o_httpclient_connection_pool_t){
        .socketpool = &reverse->httpclient.sockpool,
    };

    h2o_socketpool_target_t *target = h2o_socketpool_create_target(client, NULL);
    h2o_socketpool_init_specific(&reverse->httpclient.sockpool, SIZE_MAX, &target, 1, NULL);
    h2o_socketpool_set_timeout(&reverse->httpclient.sockpool, UINT64_MAX);
    h2o_socketpool_register_loop(&reverse->httpclient.sockpool, accept_ctx->ctx->loop);

    SSL_CTX *ssl_ctx = config.ssl_ctx;
    if (config.ssl_ctx == NULL) {
        ssl_ctx = SSL_CTX_new(SSLv23_client_method());
        SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    } else {
        SSL_CTX_up_ref(ssl_ctx);
    }
    h2o_socketpool_set_ssl_ctx(&reverse->httpclient.sockpool, ssl_ctx);
    SSL_CTX_free(ssl_ctx);

    h2o_httpclient_connection_pool_init(&reverse->httpclient.connpool, &reverse->httpclient.sockpool);
}

void h2o_reverse_start_listening(h2o_reverse_ctx_t *reverse)
{
    h2o_mem_init_pool(&reverse->pool);
    h2o_httpclient_connect(&reverse->httpclient.client, &reverse->pool,
        reverse, &reverse->httpclient.ctx, &reverse->httpclient.connpool,
        reverse->client, "reverse", on_reverse_connect);
}

