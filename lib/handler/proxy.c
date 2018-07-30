/*
 * Copyright (c) 2014,2015 DeNA Co., Ltd., Masahiro Nagano
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
#include <sys/un.h>
#include "h2o.h"
#include "h2o/socketpool.h"
#include "h2o/balancer.h"

struct rp_handler_t {
    h2o_handler_t super;
    h2o_socketpool_t *sockpool;
    h2o_proxy_config_vars_t config;
};

struct rp_handler_context_t {
    h2o_httpclient_connection_pool_t connpool;
    h2o_httpclient_ctx_t *client_ctx;
};

static int on_req(h2o_handler_t *_self, h2o_req_t *req)
{
    struct rp_handler_t *self = (void *)_self;
    h2o_req_overrides_t *overrides = h2o_mem_alloc_pool(&req->pool, *overrides, 1);
    struct rp_handler_context_t *handler_ctx = h2o_context_get_handler_context(req->conn->ctx, &self->super);

    /* setup overrides */
    *overrides = (h2o_req_overrides_t){NULL};
    overrides->connpool = &handler_ctx->connpool;
    overrides->location_rewrite.path_prefix = req->pathconf->path;
    overrides->use_proxy_protocol = self->config.use_proxy_protocol;
    overrides->client_ctx = handler_ctx->client_ctx;
    overrides->headers_cmds = self->config.headers_cmds;
    overrides->proxy_preserve_host = self->config.preserve_host;

    /* request reprocess (note: path may become an empty string, to which one of the target URL within the socketpool will be
     * right-padded when lib/core/proxy connects to upstream; see #1563) */
    h2o_iovec_t path = h2o_build_destination(req, NULL, 0, 0);
    h2o_reprocess_request(req, req->method, req->scheme, req->authority, path, overrides, 0);

    return 0;
}

static void on_context_init(h2o_handler_t *_self, h2o_context_t *ctx)
{
    struct rp_handler_t *self = (void *)_self;

    /* use the loop of first context for handling socketpool timeouts */
    h2o_socketpool_register_loop(self->sockpool, ctx->loop);

    struct rp_handler_context_t *handler_ctx = h2o_mem_alloc(sizeof(*handler_ctx));
    memset(handler_ctx, 0, sizeof(*handler_ctx));
    h2o_httpclient_connection_pool_init(&handler_ctx->connpool, self->sockpool);
    h2o_context_set_handler_context(ctx, &self->super, handler_ctx);

    /* setup a specific client context only if we need to */
    if (ctx->globalconf->proxy.io_timeout == self->config.io_timeout &&
        ctx->globalconf->proxy.connect_timeout == self->config.connect_timeout &&
        ctx->globalconf->proxy.first_byte_timeout == self->config.first_byte_timeout &&
        ctx->globalconf->proxy.keepalive_timeout == self->config.keepalive_timeout &&
        ctx->globalconf->proxy.max_buffer_size == self->config.max_buffer_size && ctx->globalconf->proxy.http2.ratio == self->config.http2.ratio && !self->config.websocket.enabled)
        return;

    h2o_httpclient_ctx_t *client_ctx = h2o_mem_alloc(sizeof(*ctx));
    client_ctx->loop = ctx->loop;
    client_ctx->getaddr_receiver = &ctx->receivers.hostinfo_getaddr;
#define ALLOC_TIMEOUT(to_)                                                                                                         \
    if (ctx->globalconf->proxy.to_ == self->config.to_) {                                                                          \
        client_ctx->to_ = &ctx->proxy.to_;                                                                                         \
    } else {                                                                                                                       \
        client_ctx->to_ = h2o_mem_alloc(sizeof(*client_ctx->to_));                                                                 \
        h2o_timeout_init(client_ctx->loop, client_ctx->to_, self->config.to_);                                                     \
    }
    ALLOC_TIMEOUT(io_timeout);
    ALLOC_TIMEOUT(connect_timeout);
    ALLOC_TIMEOUT(first_byte_timeout);
    ALLOC_TIMEOUT(keepalive_timeout);
#undef ALLOC_TIMEOUT
    client_ctx->zero_timeout = &ctx->zero_timeout;

    if (self->config.websocket.enabled) {
        /* FIXME avoid creating h2o_timeout_t for every path-level context in case the timeout values are the same */
        client_ctx->websocket_timeout = h2o_mem_alloc(sizeof(*client_ctx->websocket_timeout));
        h2o_timeout_init(client_ctx->loop, client_ctx->websocket_timeout, self->config.websocket.timeout);
    } else {
        client_ctx->websocket_timeout = NULL;
    }

    client_ctx->max_buffer_size = self->config.max_buffer_size;
    client_ctx->http2.ratio = self->config.http2.ratio;
    client_ctx->http2.counter = 0;

    handler_ctx->client_ctx = client_ctx;
}

static void on_context_dispose(h2o_handler_t *_self, h2o_context_t *ctx)
{
    struct rp_handler_t *self = (void *)_self;
    struct rp_handler_context_t *handler_ctx = h2o_context_get_handler_context(ctx, &self->super);

    if (handler_ctx->client_ctx != NULL) {
#define FREE_TIMEOUT(to_)                                                                                                          \
        if (handler_ctx->client_ctx->to_ != &ctx->proxy.to_) {                                                                                      \
            h2o_timeout_dispose(handler_ctx->client_ctx->loop, handler_ctx->client_ctx->to_);                                                                    \
            free(handler_ctx->client_ctx->to_);                                                                                                     \
        }
        FREE_TIMEOUT(io_timeout);
        FREE_TIMEOUT(connect_timeout);
        FREE_TIMEOUT(first_byte_timeout);
#undef FREE_TIMEOUT

        if (handler_ctx->client_ctx->websocket_timeout != NULL) {
            h2o_timeout_dispose(handler_ctx->client_ctx->loop, handler_ctx->client_ctx->websocket_timeout);
            free(handler_ctx->client_ctx->websocket_timeout);
        }
        h2o_socketpool_unregister_loop(self->sockpool, ctx->loop);
        free(handler_ctx->client_ctx);
    }

    free(handler_ctx);
}

static void on_handler_dispose(h2o_handler_t *_self)
{
    struct rp_handler_t *self = (void *)_self;

    h2o_socketpool_dispose(self->sockpool);
    free(self->sockpool);
}

void h2o_proxy_register_reverse_proxy(h2o_pathconf_t *pathconf, h2o_proxy_config_vars_t *config, h2o_socketpool_t *sockpool)
{
    struct rp_handler_t *self = (void *)h2o_create_handler(pathconf, sizeof(*self));

    self->super.on_context_init = on_context_init;
    self->super.on_context_dispose = on_context_dispose;
    self->super.dispose = on_handler_dispose;
    self->super.on_req = on_req;
    self->super.supports_request_streaming = 1;
    self->config = *config;
    self->sockpool = sockpool;
}
