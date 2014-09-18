/*
 * Copyright (c) 2014 DeNA Co., Ltd.
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
#include <stddef.h>
#include <stdlib.h>
#include <sys/time.h>
#include "h2o.h"
#include "h2o/http1.h"
#include "h2o/http2.h"

#define DESTROY_LIST(type, anchor) do { \
    while (! h2o_linklist_is_empty(&anchor)) { \
        type *e = H2O_STRUCT_FROM_MEMBER(type, _link, anchor.next); \
        h2o_linklist_unlink(&e->_link); \
        if (e->destroy != NULL) \
            e->destroy(e); \
    } \
} while (0)

static void init_host_context(h2o_host_context_t *host_ctx)
{
    h2o_linklist_init_anchor(&host_ctx->handlers);
    h2o_linklist_init_anchor(&host_ctx->filters);
    h2o_linklist_init_anchor(&host_ctx->loggers);
    h2o_register_chunked_filter(host_ctx);
    h2o_init_mimemap(&host_ctx->mimemap, H2O_DEFAULT_MIMETYPE);
}

static void dispose_host_context(h2o_host_context_t *host_ctx)
{
    free(host_ctx->hostname.base);
    DESTROY_LIST(h2o_handler_t, host_ctx->handlers);
    DESTROY_LIST(h2o_filter_t, host_ctx->filters);
    DESTROY_LIST(h2o_logger_t, host_ctx->loggers);
    h2o_dispose_mimemap(&host_ctx->mimemap);
}

static void destroy_host_context(h2o_host_context_t *host_ctx)
{
    dispose_host_context(host_ctx);
    free(host_ctx);
}

void h2o_context_init(h2o_context_t *ctx, h2o_loop_t *loop)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->loop = loop;
    h2o_timeout_init(ctx->loop, &ctx->zero_timeout, 0);
    h2o_timeout_init(ctx->loop, &ctx->req_timeout, H2O_DEFAULT_REQ_TIMEOUT);
    h2o_linklist_init_anchor(&ctx->virtual_host_contexts);
    init_host_context(&ctx->default_host_context);
    h2o_linklist_init_anchor(&ctx->global_configurators);
    h2o_linklist_init_anchor(&ctx->host_configurators);
    ctx->server_name = h2o_buf_init(H2O_STRLIT("h2o/0.1"));
    ctx->max_request_entity_size = H2O_DEFAULT_MAX_REQUEST_ENTITY_SIZE;
    ctx->http1_upgrade_to_http2 = H2O_DEFAULT_HTTP1_UPGRADE_TO_HTTP2;
    ctx->http2_max_concurrent_requests_per_connection = H2O_DEFAULT_HTTP2_MAX_CONCURRENT_REQUESTS_PER_CONNECTION;
}

h2o_host_context_t *h2o_context_register_virtual_host(h2o_context_t *ctx, const char *hostname)
{
    h2o_host_context_t *host_ctx = h2o_malloc(sizeof(*host_ctx));
    size_t i;

    memset(host_ctx, 0, sizeof(*host_ctx));
    init_host_context(host_ctx);
    host_ctx->hostname = h2o_strdup(NULL, hostname, SIZE_MAX);
    for (i = 0; i != host_ctx->hostname.len; ++i)
        host_ctx->hostname.base[i] = h2o_tolower(host_ctx->hostname.base[i]);

    h2o_linklist_insert(&ctx->virtual_host_contexts, &host_ctx->_link);

    return host_ctx;
}

void h2o_context_dispose(h2o_context_t *ctx)
{
    while (! h2o_linklist_is_empty(&ctx->virtual_host_contexts)) {
        h2o_host_context_t *host_ctx = H2O_STRUCT_FROM_MEMBER(h2o_host_context_t, _link, ctx->virtual_host_contexts.next);
        h2o_linklist_unlink(&host_ctx->_link);
        destroy_host_context(host_ctx);
    }
    dispose_host_context(&ctx->default_host_context);
    DESTROY_LIST(h2o_configurator_t, ctx->global_configurators);
    DESTROY_LIST(h2o_configurator_t, ctx->host_configurators);
}

void h2o_get_timestamp(h2o_context_t *ctx, h2o_mempool_t *pool, h2o_timestamp_t *ts)
{
    uint64_t now = h2o_now(ctx->loop);

    if (ctx->_timestamp_cache.uv_now_at != now) {
        time_t prev_sec = ctx->_timestamp_cache.tv_at.tv_sec;
        ctx->_timestamp_cache.uv_now_at = now;
        gettimeofday(&ctx->_timestamp_cache.tv_at, NULL);
        if (ctx->_timestamp_cache.tv_at.tv_sec != prev_sec) {
            /* update the string cache */
            if (ctx->_timestamp_cache.value != NULL)
                h2o_mempool_release_shared(ctx->_timestamp_cache.value);
            ctx->_timestamp_cache.value = h2o_mempool_alloc_shared(NULL, sizeof(h2o_timestamp_string_t));
            h2o_time2str_rfc1123(ctx->_timestamp_cache.value->rfc1123, ctx->_timestamp_cache.tv_at.tv_sec);
            h2o_time2str_log(ctx->_timestamp_cache.value->log, ctx->_timestamp_cache.tv_at.tv_sec);
        }
    }

    ts->at = ctx->_timestamp_cache.tv_at;
    h2o_mempool_link_shared(pool, ctx->_timestamp_cache.value);
    ts->str = ctx->_timestamp_cache.value;
}

static void on_ssl_handshake_complete(h2o_socket_t *sock, int status)
{
    const h2o_buf_t *ident;
    h2o_context_t *ctx = sock->data;
    sock->data = NULL;

    h2o_buf_t proto;
    if (status != 0) {
        h2o_socket_close(sock);
        return;
    }

    proto = h2o_socket_ssl_get_selected_protocol(sock);
    for (ident = h2o_http2_tls_identifiers; ident->len != 0; ++ident) {
        if (proto.len == ident->len && memcmp(proto.base, ident->base, proto.len) == 0) {
            goto Is_Http2;
        }
    }
    /* connect as http1 */
    h2o_http1_accept(ctx, sock);
    return;

Is_Http2:
    /* connect as http2 */
    h2o_http2_accept(ctx, sock);
}

void h2o_accept_ssl(h2o_context_t *ctx, h2o_socket_t *sock, h2o_ssl_context_t* ssl_ctx)
{
    sock->data = ctx;
    h2o_socket_ssl_server_handshake(sock, ssl_ctx, on_ssl_handshake_complete);
}
