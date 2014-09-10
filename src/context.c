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

static void default_dispose_filter(h2o_filter_t *filter)
{
    if (filter->next != NULL)
        filter->next->dispose(filter->next);
}

void h2o_context_init(h2o_context_t *ctx, h2o_loop_t *loop, h2o_req_cb req_cb)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->loop = loop;
    ctx->req_cb = req_cb;
    h2o_timeout_init(ctx->loop, &ctx->zero_timeout, 0);
    h2o_timeout_init(ctx->loop, &ctx->req_timeout, 10000);
    h2o_add_chunked_encoder(ctx);
    h2o_init_mimemap(&ctx->mimemap, "application/octet-stream");
    ctx->server_name = h2o_buf_init(H2O_STRLIT("h2o/0.1"));
    ctx->max_request_entity_size = 1024 * 1024 * 1024;
    ctx->http1_upgrade_to_http2 = 1;
    ctx->http2_max_concurrent_requests_per_connection = 16;
}

void h2o_context_dispose(h2o_context_t *ctx)
{
    if (ctx->filters != NULL) {
        ctx->filters->dispose(ctx->filters);
    }
    h2o_dispose_mimemap(&ctx->mimemap);
}

h2o_filter_t *h2o_define_filter(h2o_context_t *context, size_t sz)
{
    h2o_filter_t *filter = h2o_malloc(sz);

    memset(filter, 0, sz);
    filter->next = context->filters;
    filter->dispose = default_dispose_filter;
    filter->on_start_response = NULL; /* filters should always set this */

    context->filters = filter;

    return filter;
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

void h2o_accept(h2o_context_t *ctx, h2o_socket_t *sock)
{
    if (ctx->ssl_ctx != NULL) {
        sock->data = ctx;
        h2o_socket_ssl_server_handshake(sock, ctx->ssl_ctx, on_ssl_handshake_complete);
    } else {
        h2o_http1_accept(ctx, sock);
    }
}
