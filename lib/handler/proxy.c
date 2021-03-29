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
#include "picotls.h"
#include "picotls/openssl.h"
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

static h2o_http3client_ctx_t *create_http3_context(h2o_loop_t *loop)
{
#if H2O_USE_LIBUV
    fprintf(stderr, "no HTTP/3 support for libuv\n");
    abort();
#else

    h2o_http3client_ctx_t *h3ctx = h2o_mem_alloc(sizeof(*h3ctx));

    /* tls (FIXME provide knobs to configure, incl. certificate validation) */
    h3ctx->tls = (ptls_context_t){
        .random_bytes = ptls_openssl_random_bytes,
        .get_time = &ptls_get_time,
        .key_exchanges = ptls_openssl_key_exchanges,
        .cipher_suites = ptls_openssl_cipher_suites,
    };
    quicly_amend_ptls_context(&h3ctx->tls);

    /* quic */
    h3ctx->quic = quicly_spec_context;
    h3ctx->quic.tls = &h3ctx->tls;
    h3ctx->quic.transport_params.max_streams_uni = 10;
    uint8_t cid_key[PTLS_SHA256_DIGEST_SIZE];
    ptls_openssl_random_bytes(cid_key, sizeof(cid_key));
    h3ctx->quic.cid_encryptor = quicly_new_default_cid_encryptor(&ptls_openssl_bfecb, &ptls_openssl_aes128ecb, &ptls_openssl_sha256,
                                                                 ptls_iovec_init(cid_key, sizeof(cid_key)));
    ptls_clear_memory(cid_key, sizeof(cid_key));
    h3ctx->quic.stream_open = &h2o_httpclient_http3_on_stream_open;

    /* http3 */
    int sockfd;
    if ((sockfd = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("failed to open UDP socket");
        abort();
    }
    struct sockaddr_in sin = {};
    if (bind(sockfd, (struct sockaddr *)&sin, sizeof(sin)) != 0) {
        perror("failed to bind default address to UDP socket");
        abort();
    }
    h2o_socket_t *sock = h2o_evloop_socket_create(loop, sockfd, H2O_SOCKET_FLAG_DONT_READ);
    h2o_quic_init_context(&h3ctx->h3, loop, sock, &h3ctx->quic, NULL, h2o_httpclient_http3_notify_connection_update);

    h3ctx->load_session = NULL; /* TODO reuse session? */

    return h3ctx;
#endif
}

static void destroy_http3_context(h2o_http3client_ctx_t *h3ctx)
{
    h2o_quic_dispose_context(&h3ctx->h3);
    quicly_free_default_cid_encryptor(h3ctx->quic.cid_encryptor);
    free(h3ctx);
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
        ctx->globalconf->proxy.max_buffer_size == self->config.max_buffer_size &&
        ctx->globalconf->proxy.protocol_ratio.http2 == self->config.protocol_ratio.http2 &&
        ctx->globalconf->proxy.protocol_ratio.http3 == self->config.protocol_ratio.http3 && !self->config.tunnel_enabled)
        return;

    h2o_httpclient_ctx_t *client_ctx = h2o_mem_alloc(sizeof(*ctx));
    client_ctx->loop = ctx->loop;
    client_ctx->getaddr_receiver = &ctx->receivers.hostinfo_getaddr;
    client_ctx->io_timeout = self->config.io_timeout;
    client_ctx->connect_timeout = self->config.connect_timeout;
    client_ctx->first_byte_timeout = self->config.first_byte_timeout;
    client_ctx->keepalive_timeout = self->config.keepalive_timeout;
    client_ctx->tunnel_enabled = self->config.tunnel_enabled;

    client_ctx->max_buffer_size = self->config.max_buffer_size;
    client_ctx->protocol_selector = (struct st_h2o_httpclient_protocol_selector_t){.ratio = self->config.protocol_ratio};

    client_ctx->http2.latency_optimization =
        ctx->globalconf->http2.latency_optimization; /* TODO provide config knob, or disable? */
    client_ctx->http2.max_concurrent_streams = self->config.http2.max_concurrent_streams;

    client_ctx->http3 = client_ctx->protocol_selector.ratio.http3 != 0 ? create_http3_context(ctx->loop) : NULL;

    handler_ctx->client_ctx = client_ctx;
}

static void on_context_dispose(h2o_handler_t *_self, h2o_context_t *ctx)
{
    struct rp_handler_t *self = (void *)_self;
    struct rp_handler_context_t *handler_ctx = h2o_context_get_handler_context(ctx, &self->super);

    if (handler_ctx->client_ctx != NULL) {
        if (handler_ctx->client_ctx->http3 != NULL)
            destroy_http3_context(handler_ctx->client_ctx->http3);
        free(handler_ctx->client_ctx);
    }

    h2o_socketpool_unregister_loop(self->sockpool, ctx->loop);
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
