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

static int on_req(h2o_handler_t *_self, h2o_req_t *req)
{
    struct rp_handler_t *self = (void *)_self;
    h2o_req_overrides_t *overrides = h2o_mem_alloc_pool(&req->pool, *overrides, 1);

    /* setup overrides */
    *overrides = (h2o_req_overrides_t){NULL};
    overrides->socketpool = self->sockpool;
    overrides->location_rewrite.path_prefix = req->pathconf->path;
    overrides->use_proxy_protocol = self->config.use_proxy_protocol;
    overrides->max_buffer_size = self->config.max_buffer_size;
    overrides->client_ctx = h2o_context_get_handler_context(req->conn->ctx, &self->super);
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

    /* setup a specific client context only if we need to */
    if (ctx->globalconf->proxy.io_timeout == self->config.io_timeout &&
        ctx->globalconf->proxy.connect_timeout == self->config.connect_timeout &&
        ctx->globalconf->proxy.first_byte_timeout == self->config.first_byte_timeout && !self->config.websocket.enabled)
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
#undef ALLOC_TIMEOUT
    if (self->config.websocket.enabled) {
        /* FIXME avoid creating h2o_timeout_t for every path-level context in case the timeout values are the same */
        client_ctx->websocket_timeout = h2o_mem_alloc(sizeof(*client_ctx->websocket_timeout));
        h2o_timeout_init(client_ctx->loop, client_ctx->websocket_timeout, self->config.websocket.timeout);
    } else {
        client_ctx->websocket_timeout = NULL;
    }

    h2o_context_set_handler_context(ctx, &self->super, client_ctx);
}

static void on_context_dispose(h2o_handler_t *_self, h2o_context_t *ctx)
{
    struct rp_handler_t *self = (void *)_self;
    h2o_httpclient_ctx_t *client_ctx = h2o_context_get_handler_context(ctx, &self->super);

    if (client_ctx == NULL)
        return;

#define FREE_TIMEOUT(to_)                                                                                                          \
    if (client_ctx->to_ != &ctx->proxy.to_) {                                                                                      \
        h2o_timeout_dispose(client_ctx->loop, client_ctx->to_);                                                                    \
        free(client_ctx->to_);                                                                                                     \
    }
    FREE_TIMEOUT(io_timeout);
    FREE_TIMEOUT(connect_timeout);
    FREE_TIMEOUT(first_byte_timeout);
#undef FREE_TIMEOUT

    if (client_ctx->websocket_timeout != NULL) {
        h2o_timeout_dispose(client_ctx->loop, client_ctx->websocket_timeout);
        free(client_ctx->websocket_timeout);
    }
    h2o_socketpool_unregister_loop(self->sockpool, ctx->loop);
    free(client_ctx);
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
