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
    h2o_url_t upstream;         /* host should be NULL-terminated */
    h2o_socketpool_t *sockpool; /* non-NULL if config.use_keepalive == 1 */
    h2o_proxy_config_vars_t config;
};

static int on_req(h2o_handler_t *_self, h2o_req_t *req)
{
    struct rp_handler_t *self = (void *)_self;
    h2o_req_overrides_t *overrides = h2o_mem_alloc_pool(&req->pool, sizeof(*overrides));
    const h2o_url_scheme_t *scheme;
    h2o_iovec_t *authority;

    /* setup overrides */
    *overrides = (h2o_req_overrides_t){NULL};
    if (self->sockpool != NULL) {
        overrides->socketpool = self->sockpool;
    } else if (self->config.preserve_host) {
        overrides->hostport.host = self->upstream.host;
        overrides->hostport.port = h2o_url_get_port(&self->upstream);
    }
    overrides->location_rewrite.match = &self->upstream;
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
        scheme = self->upstream.scheme;
        authority = &self->upstream.authority;
        overrides->proxy_preserve_host = 0;
    }

    /* request reprocess */
    h2o_reprocess_request(req, req->method, scheme, *authority,
                          h2o_build_destination(req, self->upstream.path.base, self->upstream.path.len, 0), overrides, 0);

    return 0;
}

static void on_context_init(h2o_handler_t *_self, h2o_context_t *ctx)
{
    struct rp_handler_t *self = (void *)_self;

    /* use the loop of first context for handling socketpool timeouts */
    if (self->sockpool != NULL && self->sockpool->timeout == UINT64_MAX)
        h2o_socketpool_set_timeout(self->sockpool, ctx->loop, self->config.keepalive_timeout);

    /* setup a specific client context only if we need to */
    if (ctx->globalconf->proxy.io_timeout == self->config.io_timeout &&
        ctx->globalconf->proxy.connect_timeout == self->config.connect_timeout &&
        ctx->globalconf->proxy.first_byte_timeout == self->config.first_byte_timeout && !self->config.websocket.enabled &&
        self->config.ssl_ctx == ctx->globalconf->proxy.ssl_ctx)
        return;

    h2o_http1client_ctx_t *client_ctx = h2o_mem_alloc(sizeof(*ctx));

    client_ctx->io_timeout = self->config.io_timeout;
    client_ctx->connect_timeout = self->config.connect_timeout;
    client_ctx->first_byte_timeout = self->config.first_byte_timeout;
    client_ctx->loop = ctx->loop;
    client_ctx->getaddr_receiver = &ctx->receivers.hostinfo_getaddr;
    if (self->config.websocket.enabled) {
        client_ctx->websocket_timeout = self->config.websocket.timeout;
    } else {
        client_ctx->websocket_timeout = 0;
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
    free(client_ctx);
}

static void on_handler_dispose(h2o_handler_t *_self)
{
    struct rp_handler_t *self = (void *)_self;

    if (self->config.ssl_ctx != NULL)
        SSL_CTX_free(self->config.ssl_ctx);
    free(self->upstream.host.base);
    free(self->upstream.path.base);
    if (self->sockpool != NULL) {
        h2o_socketpool_dispose(self->sockpool);
        free(self->sockpool);
    }
}

void h2o_proxy_register_reverse_proxy(h2o_pathconf_t *pathconf, h2o_url_t *upstreams, size_t count, h2o_proxy_config_vars_t *config)
{
    struct sockaddr_un sa;
    const char *to_sa_err;
    struct rp_handler_t *self = (void *)h2o_create_handler(pathconf, sizeof(*self));
    self->super.on_context_init = on_context_init;
    self->super.on_context_dispose = on_context_dispose;
    self->super.dispose = on_handler_dispose;
    self->super.on_req = on_req;
    self->super.has_body_stream = 1;
    if (config->keepalive_timeout != 0) {
        size_t i;
        int is_ssl;
        h2o_socketpool_target_vector_t targets = {};
        h2o_vector_reserve(NULL, &targets, count);
        self->sockpool = h2o_mem_alloc(sizeof(*self->sockpool));
        for (i = 0; i != count; ++i) {
            if (config->registered_as_backends && config->reverse_path.base != NULL) {
                upstreams[i].path = config->reverse_path;
            }
            to_sa_err = h2o_url_host_to_sun(upstreams[i].host, &sa);
            is_ssl = upstreams[i].scheme == &H2O_URL_SCHEME_HTTPS;
            if (to_sa_err == h2o_url_host_to_sun_err_is_not_unix_socket) {
                h2o_socketpool_init_target_by_hostport(&targets.entries[i], upstreams[i].host, h2o_url_get_port(&upstreams[i]),
                                                       is_ssl, &upstreams[i]);
            } else {
                assert(to_sa_err == NULL);
                h2o_socketpool_init_target_by_address(&targets.entries[i], (void *)&sa, sizeof(sa), is_ssl, &upstreams[i]);
            }
            targets.size++;
        }
        h2o_socketpool_init_by_targets(self->sockpool, targets, SIZE_MAX /* FIXME */);
    }
    to_sa_err = h2o_url_host_to_sun(upstreams[0].host, &sa);
    h2o_url_copy(NULL, &self->upstream, &upstreams[0]);
    if (to_sa_err) {
        h2o_strtolower(self->upstream.host.base, self->upstream.host.len);
    }
    self->config = *config;
    if (self->config.ssl_ctx != NULL)
        SSL_CTX_up_ref(self->config.ssl_ctx);
}
