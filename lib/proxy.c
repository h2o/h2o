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
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include "h2o.h"
#include "h2o/http1client.h"
#include "h2o/socketpool.h"

struct rp_generator_t {
    h2o_generator_t super;
    h2o_req_t *src_req;
    h2o_http1client_t *client;
    struct {
        h2o_buf_t bufs[2]; /* first buf is the request line and headers, the second is the POST content */
        int is_head;
    } up_req;
    h2o_input_buffer_t *buf_before_send;
    h2o_input_buffer_t *buf_sending;
};

struct rp_handler_t {
    h2o_handler_t super;
    h2o_buf_t virtual_path;
    struct {
        h2o_buf_t host;
        uint16_t port;
        h2o_socketpool_t *sockpool; /* non-NULL if config.use_keepalive == 1 */
        h2o_buf_t path;
        h2o_proxy_config_vars_t config;
    } upstream;
};

struct proxy_configurator_t {
    h2o_configurator_t super;
    h2o_proxy_config_vars_t *vars;
    h2o_proxy_config_vars_t _vars_stack[H2O_CONFIGURATOR_NUM_LEVELS + 1];
};

static h2o_buf_t build_request(h2o_req_t *req, h2o_buf_t host, uint16_t port, size_t path_replace_length, h2o_buf_t path_prefix, int keepalive)
{
    h2o_buf_t buf;
    size_t bufsz;
    const h2o_header_t *h, * h_end;
    char *p;

    /* calc buffer length */
    bufsz = sizeof("  HTTP/1.1\r\nhost: :65535\r\nconnection: keep-alive\r\ncontent-length: 18446744073709551615\r\n\r\n")
        + req->method.len
        + req->path.len - path_replace_length + path_prefix.len
        + host.len;
    for (h = req->headers.entries, h_end = h + req->headers.size; h != h_end; ++h)
        bufsz += h->name->len + h->value.len + 4;

    /* allocate */
    buf.base = h2o_mempool_alloc(&req->pool, bufsz);

    /* build response */
    p = buf.base;
    p += sprintf(p, "%.*s %.*s%.*s HTTP/1.1\r\nconnection: %s\r\n",
        (int)req->method.len, req->method.base,
        (int)path_prefix.len, path_prefix.base,
        (int)(req->path.len - path_replace_length), req->path.base + path_replace_length,
        keepalive ? "keep-alive" : "close");
    if (port == 80)
        p += sprintf(p, "host: %.*s\r\n", (int)host.len, host.base);
    else
        p += sprintf(p, "host: %.*s:%u\r\n", (int)host.len, host.base, (unsigned)port);
    if (req->entity.base != NULL) {
        p += sprintf(p, "content-length: %zu\r\n", req->entity.len);
    }
    for (h = req->headers.entries, h_end = h + req->headers.size; h != h_end; ++h) {
        p += sprintf(p, "%.*s: %.*s\r\n",
            (int)h->name->len, h->name->base,
            (int)h->value.len, h->value.base);
    }
    *p++ = '\r';
    *p++ = '\n';

    /* set the length */
    buf.len = p - buf.base;
    assert(buf.len < bufsz);

    return buf;
}

static void close_generator(struct rp_generator_t *self, int cancel_client)
{
    if (cancel_client && self->client != NULL)
        h2o_http1client_cancel(self->client);
    h2o_dispose_input_buffer(&self->buf_before_send);
    h2o_dispose_input_buffer(&self->buf_sending);
}

static void close_and_send_error(struct rp_generator_t *self, int cancel_client, const char *errstr)
{
    close_generator(self, cancel_client);
    h2o_send_error(self->src_req, 502, "Gateway Error", errstr);
}

static void do_close(h2o_generator_t *generator, h2o_req_t *req)
{
    struct rp_generator_t *self = (void*)generator;
    close_generator(self, 0);
}

static void do_send(struct rp_generator_t *self)
{
    assert(self->buf_sending->size == 0);

    if (self->buf_before_send->size != 0) {
        h2o_buf_t buf;
        /* swap buf_before_send and buf_sending */
        h2o_input_buffer_t *tmp = self->buf_before_send;
        self->buf_before_send = self->buf_sending;
        self->buf_sending = tmp;
        /* call h2o_send */
        buf = h2o_buf_init(self->buf_sending->bytes, self->buf_sending->size);
        h2o_send(self->src_req, &buf, 1, self->client == NULL);
    } else if (self->client == NULL) {
        close_generator(self, 0);
        h2o_send(self->src_req, NULL, 0, 1);
    }
}

static void do_proceed(h2o_generator_t *generator, h2o_req_t *req)
{
    struct rp_generator_t *self = (void*)generator;

    h2o_consume_input_buffer(&self->buf_sending, self->buf_sending->size);

    do_send(self);
}

static int on_body(h2o_http1client_t *client, const char *errstr, h2o_buf_t *bufs, size_t bufcnt)
{
    struct rp_generator_t *self = client->data;

    /* FIXME should there be a way to notify error downstream? */

    { /* copy data into content_buf (FIXME optimize, this could be a zero-copy, direct access to sock->input) */
        h2o_buf_t content_buf;
        size_t i, len = 0;
        for (i = 0; i != bufcnt; ++i)
            len += bufs[i].len;
        content_buf = h2o_reserve_input_buffer(&self->buf_before_send, len);
        self->buf_before_send->size += len;
        for (i = 0; i != bufcnt; ++i) {
            memcpy(content_buf.base, bufs[i].base, bufs[i].len);
            content_buf.base += bufs[i].len;
        }
    }

    if (errstr != NULL)
        self->client = NULL;
    if (self->buf_sending->size == 0)
        do_send(self);

    return 0;
}

static h2o_http1client_body_cb on_head(h2o_http1client_t *client, const char *errstr, int minor_version, int status, h2o_buf_t msg, struct phr_header *headers, size_t num_headers)
{
    struct rp_generator_t *self = client->data;
    size_t i;

    if (errstr != NULL && errstr != h2o_http1client_error_is_eos) {
        close_and_send_error(self, 0, errstr);
        return NULL;
    }

    /* copy the response */
    self->src_req->res.status = status;
    self->src_req->res.reason = h2o_strdup(&self->src_req->pool, msg.base, msg.len).base;
    for (i = 0; i != num_headers; ++i) {
        const h2o_token_t *token = h2o_lookup_token(headers[i].name, headers[i].name_len);
        if (token == H2O_TOKEN_CONNECTION
            || token == H2O_TOKEN_SERVER
            || token == H2O_TOKEN_DATE) {
            /* skip */
        } else if (token == H2O_TOKEN_CONTENT_LENGTH) {
            if (self->src_req->res.content_length != SIZE_MAX
                || (self->src_req->res.content_length = h2o_strtosize(headers[i].value, headers[i].value_len)) == SIZE_MAX) {
                close_and_send_error(self, 0, "invalid response from upstream");
                return NULL;
            }
        } else {
            h2o_buf_t value = h2o_strdup(&self->src_req->pool, headers[i].value, headers[i].value_len);
            if (token != NULL) {
                h2o_add_header(&self->src_req->pool, &self->src_req->res.headers, token, value.base, value.len);
            } else {
                h2o_buf_t name = h2o_strdup(&self->src_req->pool, headers[i].name, headers[i].name_len);
                h2o_add_header_by_str(&self->src_req->pool, &self->src_req->res.headers, name.base, name.len, 0, value.base, value.len);
            }
        }
    }

    /* declare the start of the response */
    h2o_start_response(self->src_req, &self->super);

    if (errstr == h2o_http1client_error_is_eos) {
        close_generator(self, 0);
        h2o_send(self->src_req, NULL, 0, 1);
        return NULL;
    }

    return on_body;
}

static h2o_http1client_head_cb on_connect(h2o_http1client_t *client, const char *errstr, h2o_buf_t **reqbufs, size_t *reqbufcnt, int *method_is_head)
{
    struct rp_generator_t *self = client->data;

    if (errstr != NULL) {
        close_generator(self, 0);
        h2o_send_error(self->src_req, 502, "Gateway Error", errstr);
        return NULL;
    }

    *reqbufs = self->up_req.bufs;
    *reqbufcnt = self->up_req.bufs[1].base != NULL ? 2 : 1;
    *method_is_head = self->up_req.is_head;
    return on_head;
}

static struct rp_generator_t *proxy_send_prepare(h2o_req_t *req, h2o_buf_t host, uint16_t port, size_t path_replace_length, h2o_buf_t path_prefix, int keepalive)
{
    struct rp_generator_t *self = h2o_mempool_alloc(&req->pool, sizeof(*self));

    self->super.proceed = do_proceed;
    self->super.stop = do_close;
    self->src_req = req;
    self->up_req.bufs[0] = build_request(req, host, port, path_replace_length, path_prefix, keepalive);
    self->up_req.bufs[1] = req->entity;
    self->up_req.is_head = h2o_memis(req->method.base, req->method.len, H2O_STRLIT("HEAD"));
    h2o_init_input_buffer(&self->buf_before_send);
    h2o_init_input_buffer(&self->buf_sending);

    return self;
}

int h2o_proxy_send(h2o_req_t *req, h2o_http1client_ctx_t *client_ctx, h2o_buf_t host, uint16_t port, size_t path_replace_length, h2o_buf_t path_prefix)
{
    struct rp_generator_t *self = proxy_send_prepare(req, host, port, path_replace_length, path_prefix, 0);

    self->client = h2o_http1client_connect(client_ctx, &req->pool, host.base, port, on_connect);
    self->client->data = self;

    return 0;
}

int h2o_proxy_send_with_pool(h2o_req_t *req, h2o_http1client_ctx_t *client_ctx, h2o_socketpool_t *sockpool, size_t path_replace_length, h2o_buf_t path_prefix)
{
    struct rp_generator_t *self = proxy_send_prepare(req, sockpool->host, sockpool->port.n, path_replace_length, path_prefix, 1);

    self->client = h2o_http1client_connect_with_pool(client_ctx, &req->pool, sockpool, on_connect);
    self->client->data = self;

    return 0;
}

static int on_req(h2o_handler_t *_self, h2o_req_t *req)
{
    struct rp_handler_t *self = (void*)_self;
    h2o_http1client_ctx_t *client_ctx;

    /* prefix match */
    if (! (self->virtual_path.len <= req->path.len && memcmp(self->virtual_path.base, req->path.base, self->virtual_path.len) == 0)) {
        return -1;
    }

    client_ctx = h2o_context_get_handler_context(req->conn->ctx, &self->super);
    if (self->upstream.sockpool != NULL)
        return h2o_proxy_send_with_pool(req, client_ctx, self->upstream.sockpool, self->virtual_path.len, self->upstream.path);
    else
        return h2o_proxy_send(req, client_ctx, self->upstream.host, self->upstream.port, self->virtual_path.len, self->upstream.path);
}

static void *on_context_init(h2o_handler_t *_self, h2o_context_t *ctx)
{
    struct rp_handler_t *self = (void*)_self;
    h2o_http1client_ctx_t *client_ctx = h2o_malloc(sizeof(*ctx) + sizeof(*client_ctx->io_timeout));

    /* use the loop of first context for handling socketpool timeouts */
    if (self->upstream.sockpool != NULL && self->upstream.sockpool->timeout == UINT64_MAX)
        h2o_socketpool_set_timeout(self->upstream.sockpool, ctx->loop, self->upstream.config.keepalive_timeout);

    client_ctx->loop = ctx->loop;
    client_ctx->zero_timeout = &ctx->zero_timeout;
    client_ctx->io_timeout = (void*)(client_ctx + 1);
    h2o_timeout_init(client_ctx->loop, client_ctx->io_timeout, self->upstream.config.io_timeout); /* TODO add a way to configure the variable */

    return client_ctx;
}

static void on_context_dispose(h2o_handler_t *_self, h2o_context_t *ctx)
{
    struct rp_handler_t *self = (void*)_self;
    h2o_http1client_ctx_t *client_ctx = h2o_context_get_handler_context(ctx, &self->super);

    free(client_ctx);
}

static void on_dispose(h2o_handler_t *_self)
{
    struct rp_handler_t *self = (void*)_self;

    free(self->virtual_path.base);
    free(self->upstream.host.base);
    h2o_socketpool_dispose(self->upstream.sockpool);
    free(self->upstream.sockpool);

    free(self);
}

void h2o_proxy_register_reverse_proxy(h2o_hostconf_t *host_config, const char *virtual_path, const char *host, uint16_t port, const char *real_path, h2o_proxy_config_vars_t *config)
{
    struct rp_handler_t *self = (void*)h2o_create_handler(host_config, sizeof(*self));
    self->super.on_context_init = on_context_init;
    self->super.on_context_dispose = on_context_dispose;
    self->super.dispose = on_dispose;
    self->super.on_req = on_req;
    self->virtual_path = h2o_strdup(NULL, virtual_path, SIZE_MAX);
    self->upstream.host = h2o_strdup(NULL, host, SIZE_MAX);
    self->upstream.port = port;
    if (config->use_keepalive) {
        self->upstream.sockpool = h2o_malloc(sizeof(*self->upstream.sockpool));
        h2o_socketpool_init(self->upstream.sockpool, host, port, SIZE_MAX /* FIXME */);
    }
    self->upstream.path = h2o_strdup(NULL, real_path, SIZE_MAX);
    self->upstream.config = *config;
}

static int on_config_timeout_io(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, const char *file, yoml_t *node)
{
    struct proxy_configurator_t *self = (void*)cmd->configurator;
    return h2o_config_scanf(cmd, file, node, "%" PRIu64, &self->vars->io_timeout);
}

static int on_config_timeout_keepalive(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, const char *file, yoml_t *node)
{
    struct proxy_configurator_t *self = (void*)cmd->configurator;
    return h2o_config_scanf(cmd, file, node, "%" PRIu64, &self->vars->keepalive_timeout);
}

static int on_config_keepalive(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, const char *file, yoml_t *node)
{
    struct proxy_configurator_t *self = (void*)cmd->configurator;
    ssize_t ret = h2o_config_get_one_of(cmd, file, node, "OFF,ON");
    if (ret == -1)
        return -1;
    self->vars->use_keepalive = (int)ret;
    return 0;
}

static int on_config_reverse_url(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, const char *file, yoml_t *node)
{
    struct proxy_configurator_t *self = (void*)cmd->configurator;
    h2o_mempool_t pool;
    char *scheme, *host, *path;
    uint16_t port;

    h2o_mempool_init(&pool);

    if (h2o_parse_url(&pool, node->data.scalar, &scheme, &host, &port, &path) != 0) {
        h2o_config_print_error(cmd, file, node, "failed to parse URL: %s\n", node->data.scalar);
        goto ErrExit;
    }
    if (strcmp(scheme, "http") != 0) {
        h2o_config_print_error(cmd, file, node, "only HTTP URLs are supported");
        goto ErrExit;
    }
    /* register */
    h2o_proxy_register_reverse_proxy(ctx->hostconf, ctx->path != NULL ? ctx->path->base : "", host, port, path, self->vars);

    h2o_mempool_clear(&pool);
    return 0;

ErrExit:
    h2o_mempool_clear(&pool);
    return -1;
}

static int on_config_enter(h2o_configurator_t *_self, h2o_configurator_context_t *ctx)
{
    struct proxy_configurator_t *self = (void*)_self;

    memcpy(self->vars + 1, self->vars, sizeof(*self->vars));
    ++self->vars;
    return 0;
}

static int on_config_exit(h2o_configurator_t *_self, h2o_configurator_context_t *ctx)
{
    struct proxy_configurator_t *self = (void*)_self;

    --self->vars;
    return 0;
}

void h2o_proxy_register_configurator(h2o_globalconf_t *conf)
{
    struct proxy_configurator_t *c = (void*)h2o_config_create_configurator(conf, sizeof(*c));

    /* set default vars */
    c->vars = c->_vars_stack;
    c->vars->io_timeout = 5000;

    /* setup handlers */
    c->super.enter = on_config_enter;
    c->super.exit = on_config_exit;
    h2o_config_define_command(&c->super, "proxy.reverse.url",
        H2O_CONFIGURATOR_FLAG_PATH | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR | H2O_CONFIGURATOR_FLAG_DEFERRED,
        on_config_reverse_url,
        "upstream URL (only HTTP is suppported)");
    h2o_config_define_command(&c->super, "proxy.keepalive",
        H2O_CONFIGURATOR_FLAG_GLOBAL | H2O_CONFIGURATOR_FLAG_HOST | H2O_CONFIGURATOR_FLAG_PATH | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR,
        on_config_keepalive,
        "boolean flag (ON/OFF) indicating whether or not to use persistent connections",
        "to upstream (default: OFF)");
    h2o_config_define_command(&c->super, "proxy.timeout.io",
        H2O_CONFIGURATOR_FLAG_GLOBAL | H2O_CONFIGURATOR_FLAG_HOST | H2O_CONFIGURATOR_FLAG_PATH | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR,
        on_config_timeout_io,
        "sets upstream I/O timeout (in milliseconds, default: 5000)");
    h2o_config_define_command(&c->super, "proxy.timeout.keepalive",
        H2O_CONFIGURATOR_FLAG_GLOBAL | H2O_CONFIGURATOR_FLAG_HOST | H2O_CONFIGURATOR_FLAG_PATH | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR,
        on_config_timeout_keepalive,
        "timeout for idle conncections (default: 2)");
}
