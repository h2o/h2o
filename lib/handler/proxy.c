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
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include "h2o.h"
#include "h2o/http1client.h"
#include "h2o/socketpool.h"

struct rp_generator_t {
    h2o_generator_t super;
    h2o_proxy_location_t *upstream;
    h2o_req_t *src_req;
    h2o_http1client_t *client;
    struct {
        h2o_iovec_t bufs[2]; /* first buf is the request line and headers, the second is the POST content */
        int is_head;
    } up_req;
    h2o_buffer_t *last_content_before_send;
    h2o_buffer_t *buf_sending;
};

struct rp_handler_t {
    h2o_handler_t super;
    h2o_proxy_location_t upstream;
    h2o_socketpool_t *sockpool; /* non-NULL if config.use_keepalive == 1 */
    h2o_proxy_config_vars_t config;
};

static int test_location_match(h2o_proxy_location_t *location, const h2o_url_scheme_t *scheme, h2o_iovec_t host, uint16_t port,
                               h2o_iovec_t path)
{
    if (scheme != &H2O_URL_SCHEME_HTTP)
        return 0;
    if (!h2o_lcstris(host.base, host.len, location->host.base, location->host.len))
        return 0;
    if (port != location->port)
        return 0;
    if (path.len < location->path.len)
        return 0;
    if (memcmp(path.base, location->path.base, location->path.len) != 0)
        return 0;
    return 1;
}

static h2o_iovec_t rewrite_location(h2o_mem_pool_t *pool, const char *location, size_t location_len, h2o_proxy_location_t *upstream,
                                    h2o_iovec_t req_scheme, h2o_iovec_t req_authority, h2o_iovec_t req_basepath)
{
    h2o_url_t loc_parsed;

    if (h2o_url_parse(location, location_len, &loc_parsed) != 0 ||
        !test_location_match(upstream, loc_parsed.scheme, loc_parsed.host, h2o_url_get_port(&loc_parsed), loc_parsed.path))
        return h2o_iovec_init(location, location_len);

    return h2o_concat(pool, req_scheme, h2o_iovec_init(H2O_STRLIT("://")), req_authority, req_basepath,
                      h2o_iovec_init(loc_parsed.path.base + upstream->path.len, loc_parsed.path.len - upstream->path.len));
}

static h2o_iovec_t build_request(h2o_req_t *req, h2o_proxy_location_t *upstream, int keepalive, int preserve_host)
{
    h2o_iovec_t buf;
    size_t bufsz, remote_addr_len = SIZE_MAX;
    const h2o_header_t *h, *h_end;
    char *p;
    int xff = 0;
    char remote_addr[NI_MAXHOST];

    /* for x-f-f */
    if (req->conn->peername.addr != NULL)
        remote_addr_len = h2o_socket_getnumerichost(req->conn->peername.addr, req->conn->peername.len, remote_addr);

    /* calc buffer length (TODO switch to a safer way of building request as the current approach is potentially vulnerable to
     * buffer overrun) */
    bufsz = sizeof("  HTTP/1.1\r\nhost: :65535\r\nconnection: keep-alive\r\ncontent-length: 18446744073709551615\r\n") +
            sizeof("x-forwarded-proto: https\r\nx-forwarded-for: \r\n\r\n") + req->method.len + req->path.len -
            req->pathconf->path.len + upstream->path.len + upstream->host.len + (remote_addr_len + 1);
    for (h = req->headers.entries, h_end = h + req->headers.size; h != h_end; ++h)
        bufsz += h->name->len + h->value.len + 4;
    /* allocate */
    buf.base = h2o_mem_alloc_pool(&req->pool, bufsz);

    /* build response */
    p = buf.base;
    p += sprintf(p, "%.*s %.*s%.*s HTTP/1.1\r\nconnection: %s\r\n", (int)req->method.len, req->method.base, (int)upstream->path.len,
                 upstream->path.base, (int)(req->path.len - req->pathconf->path.len), req->path.base + req->pathconf->path.len,
                 keepalive ? "keep-alive" : "close");
    if (preserve_host) {
        p += sprintf(p, "host: %.*s\r\n", (int)req->authority.len, req->authority.base);
    } else {
        if (upstream->port == 80)
            p += sprintf(p, "host: %.*s\r\n", (int)upstream->host.len, upstream->host.base);
        else
            p += sprintf(p, "host: %.*s:%u\r\n", (int)upstream->host.len, upstream->host.base, (unsigned)upstream->port);
    }
    if (req->entity.base != NULL) {
        p += sprintf(p, "content-length: %zu\r\n", req->entity.len);
    }
    for (h = req->headers.entries, h_end = h + req->headers.size; h != h_end; ++h) {
        if (h2o_iovec_is_token(h->name) && ((h2o_token_t *)h->name)->proxy_should_drop)
            continue;
        if (h2o_lcstris(h->name->base, h->name->len, H2O_STRLIT("x-forwarded-proto")))
            continue;
        if (h2o_lcstris(h->name->base, h->name->len, H2O_STRLIT("x-forwarded-for"))) {
            xff++;
            if (remote_addr_len != SIZE_MAX) {
                p += sprintf(p, "x-forwarded-for: %.*s, %.*s\r\n", (int)h->value.len, h->value.base, (int)remote_addr_len,
                             remote_addr);
                continue;
            }
        }
        p += sprintf(p, "%.*s: %.*s\r\n", (int)h->name->len, h->name->base, (int)h->value.len, h->value.base);
    }
    p += sprintf(p, "x-forwarded-proto: %.*s\r\n", (int)req->scheme.len, req->scheme.base);
    if (xff == 0 && remote_addr_len != SIZE_MAX) {
        p += sprintf(p, "x-forwarded-for: %.*s\r\n", (int)remote_addr_len, remote_addr);
    }
    *p++ = '\r';
    *p++ = '\n';

    /* set the length */
    buf.len = p - buf.base;
    assert(buf.len < bufsz);

    return buf;
}

static void do_close(h2o_generator_t *generator, h2o_req_t *req)
{
    struct rp_generator_t *self = (void *)generator;

    if (self->client != NULL) {
        h2o_http1client_cancel(self->client);
        self->client = NULL;
    }
}

static void swap_buffer(h2o_buffer_t **x, h2o_buffer_t **y)
{
    h2o_buffer_t *t = *x;
    *x = *y;
    *y = t;
}

static void do_send(struct rp_generator_t *self)
{
    assert(self->buf_sending->size == 0);

    swap_buffer(&self->buf_sending, self->client != NULL ? &self->client->sock->input : &self->last_content_before_send);

    if (self->buf_sending->size != 0) {
        h2o_iovec_t buf = h2o_iovec_init(self->buf_sending->bytes, self->buf_sending->size);
        h2o_send(self->src_req, &buf, 1, self->client == NULL);
    } else if (self->client == NULL) {
        h2o_send(self->src_req, NULL, 0, 1);
    }
}

static void do_proceed(h2o_generator_t *generator, h2o_req_t *req)
{
    struct rp_generator_t *self = (void *)generator;

    h2o_buffer_consume(&self->buf_sending, self->buf_sending->size);

    do_send(self);
}

static int on_body(h2o_http1client_t *client, const char *errstr)
{
    struct rp_generator_t *self = client->data;

    /* FIXME should there be a way to notify error downstream? */

    if (errstr != NULL) {
        /* detach the content */
        self->last_content_before_send = self->client->sock->input;
        h2o_buffer_init(&self->client->sock->input, &h2o_socket_buffer_prototype);
        self->client = NULL;
    }
    if (self->buf_sending->size == 0)
        do_send(self);

    return 0;
}

static void on_server_push_header(h2o_req_t *req, const char *value, size_t value_len)
{
    h2o_iovec_t url, iter = h2o_iovec_init(value, value_len);

    if (req->version < 0x200)
        return;

    /* extract URL value from: X-Server-Push: http://server/pushed.css; attr1=foo; attr2=bar */
    /* TODO log malformed headers */
    if ((url.base = (char *)h2o_next_token(&iter, ';', &url.len, NULL)) == NULL)
        return;
    if (!(url.len >= sizeof("http://") - 1 && memcmp(url.base, H2O_STRLIT("http")) == 0))
        return;

    h2o_vector_reserve(&req->pool, (h2o_vector_t *)&req->http2_push_urls, sizeof(req->http2_push_urls.entries[0]),
                       req->http2_push_urls.size + 1);
    req->http2_push_urls.entries[req->http2_push_urls.size++] = h2o_strdup(&req->pool, url.base, url.len);
}

static h2o_http1client_body_cb on_head(h2o_http1client_t *client, const char *errstr, int minor_version, int status,
                                       h2o_iovec_t msg, struct phr_header *headers, size_t num_headers)
{
    struct rp_generator_t *self = client->data;
    size_t i;

    if (errstr != NULL && errstr != h2o_http1client_error_is_eos) {
        self->client = NULL;
        h2o_send_error(self->src_req, 502, "Gateway Error", errstr, 0);
        return NULL;
    }

    /* copy the response */
    self->src_req->res.status = status;
    self->src_req->res.reason = h2o_strdup(&self->src_req->pool, msg.base, msg.len).base;
    for (i = 0; i != num_headers; ++i) {
        const h2o_token_t *token = h2o_lookup_token(headers[i].name, headers[i].name_len);
        h2o_iovec_t value;
        if (token != NULL) {
            if (token->proxy_should_drop) {
                goto Skip;
            }
            if (token == H2O_TOKEN_CONTENT_LENGTH) {
                if (self->src_req->res.content_length != SIZE_MAX ||
                    (self->src_req->res.content_length = h2o_strtosize(headers[i].value, headers[i].value_len)) == SIZE_MAX) {
                    self->client = NULL;
                    h2o_send_error(self->src_req, 502, "Gateway Error", "invalid response from upstream", 0);
                    return NULL;
                }
                goto Skip;
            } else if (token == H2O_TOKEN_LOCATION) {
                value = rewrite_location(&self->src_req->pool, headers[i].value, headers[i].value_len, self->upstream,
                                         self->src_req->scheme, self->src_req->authority, self->src_req->pathconf->path);
                goto AddHeader;
            } else if (token == H2O_TOKEN_X_SERVER_PUSH) {
                on_server_push_header(self->src_req, headers[i].value, headers[i].value_len);
                goto Skip;
            }
            /* default behaviour, transfer the header downstream */
            value = h2o_strdup(&self->src_req->pool, headers[i].value, headers[i].value_len);
        AddHeader:
            h2o_add_header(&self->src_req->pool, &self->src_req->res.headers, token, value.base, value.len);
        Skip:
            ;
        } else {
            h2o_iovec_t name = h2o_strdup(&self->src_req->pool, headers[i].name, headers[i].name_len);
            h2o_iovec_t value = h2o_strdup(&self->src_req->pool, headers[i].value, headers[i].value_len);
            h2o_add_header_by_str(&self->src_req->pool, &self->src_req->res.headers, name.base, name.len, 0, value.base, value.len);
        }
    }

    /* declare the start of the response */
    h2o_start_response(self->src_req, &self->super);

    if (errstr == h2o_http1client_error_is_eos) {
        self->client = NULL;
        h2o_send(self->src_req, NULL, 0, 1);
        return NULL;
    }

    return on_body;
}

static h2o_http1client_head_cb on_connect(h2o_http1client_t *client, const char *errstr, h2o_iovec_t **reqbufs, size_t *reqbufcnt,
                                          int *method_is_head)
{
    struct rp_generator_t *self = client->data;

    if (errstr != NULL) {
        self->client = NULL;
        h2o_send_error(self->src_req, 502, "Gateway Error", errstr, 0);
        return NULL;
    }

    *reqbufs = self->up_req.bufs;
    *reqbufcnt = self->up_req.bufs[1].base != NULL ? 2 : 1;
    *method_is_head = self->up_req.is_head;
    return on_head;
}

static void on_generator_dispose(void *_self)
{
    struct rp_generator_t *self = _self;

    if (self->client != NULL) {
        h2o_http1client_cancel(self->client);
        self->client = NULL;
    }
    h2o_buffer_dispose(&self->last_content_before_send);
    h2o_buffer_dispose(&self->buf_sending);
}

static struct rp_generator_t *proxy_send_prepare(h2o_req_t *req, h2o_proxy_location_t *upstream, int keepalive, int preserve_host)
{
    struct rp_generator_t *self = h2o_mem_alloc_shared(&req->pool, sizeof(*self), on_generator_dispose);

    self->super.proceed = do_proceed;
    self->super.stop = do_close;
    self->upstream = upstream;
    self->src_req = req;
    self->up_req.bufs[0] = build_request(req, upstream, keepalive, preserve_host);
    self->up_req.bufs[1] = req->entity;
    self->up_req.is_head = h2o_memis(req->method.base, req->method.len, H2O_STRLIT("HEAD"));
    h2o_buffer_init(&self->last_content_before_send, &h2o_socket_buffer_prototype);
    h2o_buffer_init(&self->buf_sending, &h2o_socket_buffer_prototype);

    return self;
}

int h2o_proxy_send(h2o_req_t *req, h2o_http1client_ctx_t *client_ctx, h2o_proxy_location_t *upstream, int preserve_host)
{
    struct rp_generator_t *self = proxy_send_prepare(req, upstream, 0, preserve_host);

    self->client = h2o_http1client_connect(
        client_ctx, &req->pool, h2o_strdup(&req->pool, upstream->host.base, upstream->host.len).base, upstream->port, on_connect);
    self->client->data = self;

    return 0;
}

int h2o_proxy_send_with_pool(h2o_req_t *req, h2o_http1client_ctx_t *client_ctx, h2o_proxy_location_t *upstream,
                             h2o_socketpool_t *sockpool, int preserve_host)
{
    struct rp_generator_t *self = proxy_send_prepare(req, upstream, 1, preserve_host);

    self->client = h2o_http1client_connect_with_pool(client_ctx, &req->pool, sockpool, on_connect);
    self->client->data = self;

    return 0;
}

static int on_req(h2o_handler_t *_self, h2o_req_t *req)
{
    struct rp_handler_t *self = (void *)_self;
    h2o_http1client_ctx_t *client_ctx = h2o_context_get_handler_context(req->conn->ctx, &self->super);

    if (self->sockpool != NULL)
        return h2o_proxy_send_with_pool(req, client_ctx, &self->upstream, self->sockpool, self->config.preserve_host);
    else
        return h2o_proxy_send(req, client_ctx, &self->upstream, self->config.preserve_host);
}

static void *on_context_init(h2o_handler_t *_self, h2o_context_t *ctx)
{
    struct rp_handler_t *self = (void *)_self;
    h2o_http1client_ctx_t *client_ctx = h2o_mem_alloc(sizeof(*ctx) + sizeof(*client_ctx->io_timeout));

    /* use the loop of first context for handling socketpool timeouts */
    if (self->sockpool != NULL && self->sockpool->timeout == UINT64_MAX)
        h2o_socketpool_set_timeout(self->sockpool, ctx->loop, self->config.keepalive_timeout);

    client_ctx->loop = ctx->loop;
    client_ctx->zero_timeout = &ctx->zero_timeout;
    client_ctx->io_timeout = (void *)(client_ctx + 1);
    h2o_timeout_init(client_ctx->loop, client_ctx->io_timeout,
                     self->config.io_timeout); /* TODO add a way to configure the variable */

    return client_ctx;
}

static void on_context_dispose(h2o_handler_t *_self, h2o_context_t *ctx)
{
    struct rp_handler_t *self = (void *)_self;
    h2o_http1client_ctx_t *client_ctx = h2o_context_get_handler_context(ctx, &self->super);

    free(client_ctx);
}

static void on_handler_dispose(h2o_handler_t *_self)
{
    struct rp_handler_t *self = (void *)_self;

    free(self->upstream.host.base);
    free(self->upstream.path.base);
    if (self->sockpool != NULL) {
        h2o_socketpool_dispose(self->sockpool);
        free(self->sockpool);
    }

    free(self);
}

void h2o_proxy_register_reverse_proxy(h2o_pathconf_t *pathconf, const char *host, uint16_t port, const char *real_path,
                                      h2o_proxy_config_vars_t *config)
{
    struct rp_handler_t *self = (void *)h2o_create_handler(pathconf, sizeof(*self));
    self->super.on_context_init = on_context_init;
    self->super.on_context_dispose = on_context_dispose;
    self->super.dispose = on_handler_dispose;
    self->super.on_req = on_req;
    self->upstream.host = h2o_strdup(NULL, host, SIZE_MAX);
    self->upstream.port = port;
    self->upstream.path = h2o_strdup(NULL, real_path, SIZE_MAX);
    if (config->use_keepalive) {
        self->sockpool = h2o_mem_alloc(sizeof(*self->sockpool));
        h2o_socketpool_init(self->sockpool, host, port, SIZE_MAX /* FIXME */);
    }
    self->config = *config;
}
