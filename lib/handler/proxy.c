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

struct rp_handler_t {
    h2o_handler_t super;
    h2o_socketpool_t sockpool;
    h2o_proxy_config_vars_t config;
};

static int on_req(h2o_handler_t *_self, h2o_req_t *req)
{
    struct rp_handler_t *self = (void *)_self;
    h2o_req_overrides_t *overrides = h2o_mem_alloc_pool(&req->pool, sizeof(*overrides));
    h2o_url_t *upstream_url = &self->sockpool.targets.entries[0]->url;
    const h2o_url_scheme_t *scheme;
    h2o_iovec_t *authority;

    /* setup overrides */
    *overrides = (h2o_req_overrides_t){NULL};
    overrides->socketpool = &self->sockpool;
    overrides->location_rewrite.match = upstream_url;
    overrides->location_rewrite.path_prefix = req->pathconf->path;
    overrides->use_proxy_protocol = self->config.use_proxy_protocol;
    overrides->max_buffer_size = self->config.max_buffer_size;
    overrides->client_ctx = h2o_context_get_handler_context(req->conn->ctx, &self->super);
    overrides->headers_cmds = self->config.headers_cmds;

    /* determine the scheme and authority */
    if (self->config.preserve_host) {
        scheme = req->scheme;
        authority = &req->authority;
        overrides->proxy_preserve_host = 1;
    } else {
        scheme = upstream_url->scheme;
        authority = &upstream_url->authority;
        overrides->proxy_preserve_host = 0;
    }

    /* request reprocess */
    h2o_reprocess_request(req, req->method, scheme, *authority,
                          h2o_build_destination(req, upstream_url->path.base, upstream_url->path.len, 0), overrides, 0);

    return 0;
}

static void on_context_init(h2o_handler_t *_self, h2o_context_t *ctx)
{
    struct rp_handler_t *self = (void *)_self;

    /* use the loop of first context for handling socketpool timeouts */
    h2o_socketpool_register_loop(&self->sockpool, ctx->loop);

    /* setup a specific client context only if we need to */
    if (ctx->globalconf->proxy.io_timeout == self->config.io_timeout &&
        ctx->globalconf->proxy.connect_timeout == self->config.connect_timeout &&
        ctx->globalconf->proxy.first_byte_timeout == self->config.first_byte_timeout && !self->config.websocket.enabled &&
        self->config.ssl_ctx == ctx->globalconf->proxy.ssl_ctx)
        return;

    h2o_http1client_ctx_t *client_ctx = h2o_mem_alloc(sizeof(*ctx));
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
    client_ctx->ssl_ctx = self->config.ssl_ctx;

    h2o_context_set_handler_context(ctx, &self->super, client_ctx);
}

static void on_context_dispose(h2o_handler_t *_self, h2o_context_t *ctx)
{
    struct rp_handler_t *self = (void *)_self;
    h2o_http1client_ctx_t *client_ctx = h2o_context_get_handler_context(ctx, &self->super);

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
    h2o_socketpool_unregister_loop(&self->sockpool, ctx->loop);
    free(client_ctx);
}

static void on_handler_dispose(h2o_handler_t *_self)
{
    struct rp_handler_t *self = (void *)_self;

    if (self->config.ssl_ctx != NULL)
        SSL_CTX_free(self->config.ssl_ctx);
    h2o_socketpool_dispose(&self->sockpool);
}

void h2o_proxy_register_reverse_proxy(h2o_pathconf_t *pathconf, h2o_url_t *upstreams, size_t num_upstreams,
                                      h2o_proxy_config_vars_t *config)
{
    assert(num_upstreams != 0);

    struct rp_handler_t *self = (void *)h2o_create_handler(pathconf, sizeof(*self));

    self->super.on_context_init = on_context_init;
    self->super.on_context_dispose = on_context_dispose;
    self->super.dispose = on_handler_dispose;
    self->super.on_req = on_req;
    self->super.supports_request_streaming = 1;
    self->config = *config;

    /* init socket pool */
    if (config->registered_as_backends && config->reverse_path.base != NULL) {
        /* create shallow copy of upstreams so that we can modify them */
        h2o_url_t *p = alloca(sizeof(*upstreams) * num_upstreams);
        memcpy(p, upstreams, sizeof(*upstreams) * num_upstreams);
        upstreams = p;
        size_t i;
        for (i = 0; i != num_upstreams; ++i)
            upstreams[i].path = config->reverse_path;
    }
    h2o_socketpool_init_specific(&self->sockpool, SIZE_MAX /* FIXME */, upstreams, num_upstreams);
    h2o_socketpool_set_timeout(&self->sockpool, config->keepalive_timeout);

    if (self->config.ssl_ctx != NULL)
        SSL_CTX_up_ref(self->config.ssl_ctx);
}
