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

struct rp_generator_t {
    h2o_generator_t super;
    h2o_req_t *src_req;
    h2o_http1client_t *client;
    h2o_buf_t sent_req;
    h2o_input_buffer_t *content_buf;
    size_t bytes_sending;
};

struct rp_handler_t {
    h2o_handler_t super;
    h2o_buf_t virtual_path;
    struct {
        h2o_buf_t host;
        uint16_t port;
        h2o_buf_t path;
        uint64_t io_timeout;
    } upstream;
};

static h2o_buf_t build_request(h2o_req_t *req, h2o_buf_t host, uint16_t port, size_t path_replace_length, h2o_buf_t path_prefix)
{
    h2o_buf_t buf;
    size_t bufsz;
    const h2o_header_t *h, * h_end;
    char *p;

    /* calc buffer length */
    bufsz = sizeof("  HTTP/1.1\r\nhost: :65535\r\nconnection: close\r\ncontent-length: 18446744073709551615\r\n\r\n")
        + req->method.len
        + req->path.len - path_replace_length + path_prefix.len
        + host.len;
    for (h = req->headers.entries, h_end = h + req->headers.size; h != h_end; ++h)
        bufsz += h->name->len + h->value.len + 4;

    /* allocate */
    buf.base = h2o_mempool_alloc(&req->pool, bufsz);

    /* build response */
    p = buf.base;
    p += sprintf(p, "%.*s %.*s%.*s HTTP/1.1\r\nconnection: close\r\n",
        (int)req->method.len, req->method.base,
        (int)path_prefix.len, path_prefix.base,
        (int)(req->path.len - path_replace_length), req->path.base + path_replace_length);
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
    h2o_dispose_input_buffer(&self->content_buf);
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
    assert(self->bytes_sending == 0);

    if (self->content_buf->size != 0) {
        h2o_buf_t buf = h2o_buf_init(self->content_buf->bytes, self->content_buf->size);
        self->bytes_sending = self->content_buf->size;
        h2o_send(self->src_req, &buf, 1, 0);
    } else if (self->client == NULL) {
        close_generator(self, 0);
        h2o_send(self->src_req, NULL, 0, 1);
    }
}

static void do_proceed(h2o_generator_t *generator, h2o_req_t *req)
{
    struct rp_generator_t *self = (void*)generator;

    h2o_consume_input_buffer(&self->content_buf, self->bytes_sending);
    self->bytes_sending = 0;

    do_send(self);
}

static int on_body(h2o_http1client_t *client, const char *errstr, h2o_buf_t *bufs, size_t bufcnt)
{
    struct rp_generator_t *self = client->data;

    /* FIXME should there be a way to notify error downstream? */

    { /* copy data into content_buf */
        h2o_buf_t content_buf;
        size_t i, len = 0;
        for (i = 0; i != bufcnt; ++i)
            len += bufs[i].len;
        content_buf = h2o_reserve_input_buffer(&self->content_buf, len);
        self->content_buf->size += len;
        for (i = 0; i != bufcnt; ++i) {
            memcpy(content_buf.base, bufs[i].base, bufs[i].len);
            content_buf.base += bufs[i].len;
        }
    }

    if (self->bytes_sending == 0)
        do_send(self);

    if (errstr != NULL)
        self->client = NULL;
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

    *reqbufs = &self->sent_req;
    *reqbufcnt = 1;
    *method_is_head = self->sent_req.len >= 5 && memcmp(self->sent_req.base, "HEAD ", 5) == 0;
    return on_head;
}

int h2o_proxy_send(h2o_req_t *req, h2o_http1client_ctx_t *client_ctx, h2o_buf_t host, uint16_t port, size_t path_replace_length, h2o_buf_t path_prefix)
{
    struct rp_generator_t *self;

    self = h2o_mempool_alloc(&req->pool, sizeof(*self));
    self->super.proceed = do_proceed;
    self->super.stop = do_close;
    self->src_req = req;
    self->client = h2o_http1client_connect(client_ctx, &req->pool, host.base, port, on_connect);
    self->client->data = self;
    self->sent_req = build_request(req, host, port, path_replace_length, path_prefix);
    h2o_init_input_buffer(&self->content_buf);
    self->bytes_sending = 0;

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
    return h2o_proxy_send(req, client_ctx, self->upstream.host, self->upstream.port, self->virtual_path.len, self->upstream.path);
}

static void *on_context_init(h2o_handler_t *_self, h2o_context_t *ctx)
{
    struct rp_handler_t *self = (void*)_self;
    h2o_http1client_ctx_t *client_ctx = h2o_malloc(sizeof(*ctx) + sizeof(*client_ctx->io_timeout));

    client_ctx->loop = ctx->loop;
    client_ctx->zero_timeout = &ctx->zero_timeout;
    client_ctx->io_timeout = (void*)(client_ctx + 1);
    h2o_timeout_init(client_ctx->loop, client_ctx->io_timeout, self->upstream.io_timeout); /* TODO add a way to configure the variable */

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
    free(self->upstream.path.base);

    free(self);
}

void h2o_proxy_register_reverse_proxy(h2o_hostconf_t *host_config, const char *virtual_path, const char *host, uint16_t port, const char *real_path, uint64_t io_timeout)
{
    struct rp_handler_t *self = (void*)h2o_create_handler(host_config, sizeof(*self));
    self->super.on_context_init = on_context_init;
    self->super.on_context_dispose = on_context_dispose;
    self->super.dispose = on_dispose;
    self->super.on_req = on_req;
    self->virtual_path = h2o_strdup(NULL, virtual_path, SIZE_MAX);
    self->upstream.host = h2o_strdup(NULL, host, SIZE_MAX);
    self->upstream.port = port;
    self->upstream.path = h2o_strdup(NULL, real_path, SIZE_MAX);
    self->upstream.io_timeout = io_timeout;
}

static int on_config(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, const char *file, yoml_t *node)
{
    h2o_mempool_t pool;
    size_t i;

    h2o_mempool_init(&pool);

    if (node->type != YOML_TYPE_MAPPING) {
        h2o_config_print_error(cmd, file, node, "argument is not a mapping");
        goto ErrExit;
    }
    for (i = 0; i != node->data.mapping.size; ++i) {
        yoml_t *key = node->data.mapping.elements[i].key,
            *value = node->data.mapping.elements[i].value,
            *upstream_url;
        char *scheme, *host, *path;
        uint16_t port;
        uint64_t io_timeout = 5000; /* default: 5 seconds */
        if (key->type != YOML_TYPE_SCALAR) {
            h2o_config_print_error(cmd, file, key, "key (virtual path) is not a scalar");
            goto ErrExit;
        }
        if (key->data.scalar[0] != '/') {
            h2o_config_print_error(cmd, file, key, "key (virtual path) should start with a '/'");
            goto ErrExit;
        }
        switch (value->type) {
        case YOML_TYPE_SCALAR:
            upstream_url = value;
            break;
        case YOML_TYPE_MAPPING:
            {
                yoml_t *t;
                if ((t = yoml_get(value, "url")) == NULL) {
                    h2o_config_print_error(cmd, file, value, "mandatory key `url` is missing");
                    goto ErrExit;
                } else if (t->type != YOML_TYPE_SCALAR) {
                    h2o_config_print_error(cmd, file, t, "value is not a scalar");
                    goto ErrExit;
                }
                upstream_url = t;
                if ((t = yoml_get(value, "io-timeout")) != NULL) {
                    if (t->type != YOML_TYPE_SCALAR
                        || sscanf(t->data.scalar, "%" PRIu64, &io_timeout) != 1) {
                        h2o_config_print_error(cmd, file, t, "value is not a number");
                        goto ErrExit;
                    }
                    io_timeout *= 1000; /* convert to milliseconds */
                }
            }
            break;
        default:
            h2o_config_print_error(cmd, file, value, "value should either be a scalar (upstream URL) or a mapping (url and io-timeout)");
            goto ErrExit;
        }
        if (h2o_parse_url(&pool, upstream_url->data.scalar, &scheme, &host, &port, &path) != 0) {
            h2o_config_print_error(cmd, file, upstream_url, "failed to parse URL: %s\n", value->data.scalar);
            goto ErrExit;
        }
        if (strcmp(scheme, "http") != 0) {
            h2o_config_print_error(cmd, file, upstream_url, "only HTTP URLs are supported");
            goto ErrExit;
        }
        /* register */
        h2o_proxy_register_reverse_proxy(ctx->hostconf, key->data.scalar, host, port, path, io_timeout);
    }

    h2o_mempool_clear(&pool);
    return 0;

ErrExit:
    h2o_mempool_clear(&pool);
    return -1;
}

void h2o_proxy_register_reverse_proxy_configurator(h2o_globalconf_t *conf)
{
    h2o_configurator_t *c = h2o_config_create_configurator(conf, sizeof(*c));
    h2o_config_define_command(c, "reverse-proxy", H2O_CONFIGURATOR_FLAG_HOST,
        on_config,
        "map of virtual-path -> http://upstream_host:port/path");
}
