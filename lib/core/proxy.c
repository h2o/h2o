/*
 * Copyright (c) 2014,2015 DeNA Co., Ltd., Kazuho Oku, Masahiro Nagano
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
#include "picohttpparser.h"
#include "h2o.h"
#include "h2o/http1client.h"

struct rp_generator_t {
    h2o_generator_t super;
    h2o_req_t *src_req;
    h2o_http1client_t *client;
    struct {
        h2o_iovec_t bufs[2]; /* first buf is the request line and headers, the second is the POST content */
        int is_head;
    } up_req;
    h2o_buffer_t *last_content_before_send;
    h2o_buffer_t *buf_sending;
};

static void send_error(h2o_req_t *req, const char *internal_reason)
{
    fprintf(stderr, "[proxy] an error ocurred while handling internal redirect to %s://%.*s%.*s; %s\n", req->scheme->name.base,
            (int)req->authority.len, req->authority.base, (int)req->path.len, req->path.base, internal_reason);
    h2o_send_error(req, 502, "Gateway Error", "internal error", 0);
}

static h2o_iovec_t rewrite_location(h2o_mem_pool_t *pool, const char *location, size_t location_len, h2o_url_t *match,
                                    const h2o_url_scheme_t *req_scheme, h2o_iovec_t req_authority, h2o_iovec_t req_basepath)
{
    h2o_url_t loc_parsed;

    if (h2o_url_parse(location, location_len, &loc_parsed) != 0)
        goto NoRewrite;
    if (loc_parsed.scheme != &H2O_URL_SCHEME_HTTP)
        goto NoRewrite;
    if (!h2o_lcstris(loc_parsed.host.base, loc_parsed.host.len, match->host.base, match->host.len))
        goto NoRewrite;
    if (h2o_url_get_port(&loc_parsed) != h2o_url_get_port(match))
        goto NoRewrite;
    if (loc_parsed.path.len < match->path.len)
        goto NoRewrite;
    if (memcmp(loc_parsed.path.base, match->path.base, match->path.len) != 0)
        goto NoRewrite;

    return h2o_concat(pool, req_scheme->name, h2o_iovec_init(H2O_STRLIT("://")), req_authority, req_basepath,
                      h2o_iovec_init(loc_parsed.path.base + match->path.len, loc_parsed.path.len - match->path.len));

NoRewrite:
    return (h2o_iovec_t){};
}

static h2o_iovec_t build_request_merge_headers(h2o_mem_pool_t *pool, h2o_iovec_t merged, h2o_iovec_t added, int seperator)
{
    if (added.len == 0)
        return merged;
    if (merged.len == 0)
        return added;

    size_t newlen = merged.len + 2 + added.len;
    char *buf = h2o_mem_alloc_pool(pool, newlen);
    memcpy(buf, merged.base, merged.len);
    buf[merged.len] = seperator;
    buf[merged.len + 1] = ' ';
    memcpy(buf + merged.len + 2, added.base, added.len);
    merged.base = buf;
    merged.len = newlen;
    return merged;
}

static h2o_iovec_t build_request(h2o_req_t *req, int keepalive)
{
    h2o_iovec_t buf;
    size_t offset = 0, remote_addr_len = SIZE_MAX;
    char remote_addr[NI_MAXHOST];
    h2o_iovec_t cookie_buf = {}, xff_buf = {}, via_buf = {};

    /* for x-f-f */
    if (req->conn->peername.addr != NULL)
        remote_addr_len = h2o_socket_getnumerichost(req->conn->peername.addr, req->conn->peername.len, remote_addr);

    /* build response */
    buf.len = req->method.len + req->path.len + req->authority.len + 512;
    buf.base = h2o_mem_alloc_pool(&req->pool, buf.len);

#define RESERVE(sz)                                                                                                                \
    do {                                                                                                                           \
        if (offset + sz + 4 /* for "\r\n\r\n" */ > buf.len) {                                                                      \
            buf.len *= 2;                                                                                                          \
            char *newp = h2o_mem_alloc_pool(&req->pool, buf.len);                                                                  \
            memcpy(newp, buf.base, offset);                                                                                        \
            buf.base = newp;                                                                                                       \
        }                                                                                                                          \
    } while (0)
#define APPEND(s, l)                                                                                                               \
    do {                                                                                                                           \
        memcpy(buf.base + offset, (s), (l));                                                                                       \
        offset += (l);                                                                                                             \
    } while (0)
#define APPEND_STRLIT(lit) APPEND((lit), sizeof(lit) - 1)
#define FLATTEN_PREFIXED_VALUE(prefix, value, add_size)                                                                            \
    do {                                                                                                                           \
        RESERVE(sizeof(prefix) - 1 + value.len + 2 + add_size);                                                                    \
        APPEND_STRLIT(prefix);                                                                                                     \
        if (value.len != 0) {                                                                                                      \
            APPEND(value.base, value.len);                                                                                         \
            if (add_size != 0) {                                                                                                   \
                buf.base[offset++] = ',';                                                                                          \
                buf.base[offset++] = ' ';                                                                                          \
            }                                                                                                                      \
        }                                                                                                                          \
    } while (0)

    APPEND(req->method.base, req->method.len);
    buf.base[offset++] = ' ';
    APPEND(req->path.base, req->path.len);
    APPEND_STRLIT(" HTTP/1.1\r\nconnection: ");
    if (keepalive) {
        APPEND_STRLIT("keep-alive\r\nhost: ");
    } else {
        APPEND_STRLIT("close\r\nhost: ");
    }
    APPEND(req->authority.base, req->authority.len);
    buf.base[offset++] = '\r';
    buf.base[offset++] = '\n';
    assert(offset <= buf.len);
    if (req->entity.base != NULL) {
        RESERVE(sizeof("content-length: 18446744073709551615") - 1);
        offset += sprintf(buf.base + offset, "content-length: %zu\r\n", req->entity.len);
    }
    {
        const h2o_header_t *h, *h_end;
        for (h = req->headers.entries, h_end = h + req->headers.size; h != h_end; ++h) {
            if (h2o_iovec_is_token(h->name)) {
                const h2o_token_t *token = (void *)h->name;
                if (token->proxy_should_drop) {
                    continue;
                } else if (token == H2O_TOKEN_COOKIE) {
                    /* merge the cookie headers; see HTTP/2 8.1.2.5 and HTTP/1 (RFC6265 5.4) */
                    /* FIXME current algorithm is O(n^2) against the number of cookie headers */
                    cookie_buf = build_request_merge_headers(&req->pool, cookie_buf, h->value, ';');
                    continue;
                } else if (token == H2O_TOKEN_VIA) {
                    via_buf = build_request_merge_headers(&req->pool, via_buf, h->value, ',');
                    continue;
                }
            }
            if (h2o_lcstris(h->name->base, h->name->len, H2O_STRLIT("x-forwarded-proto")))
                continue;
            if (h2o_lcstris(h->name->base, h->name->len, H2O_STRLIT("x-forwarded-for"))) {
                xff_buf = build_request_merge_headers(&req->pool, xff_buf, h->value, ',');
                continue;
            }
            RESERVE(h->name->len + h->value.len + 2);
            APPEND(h->name->base, h->name->len);
            buf.base[offset++] = ':';
            buf.base[offset++] = ' ';
            APPEND(h->value.base, h->value.len);
            buf.base[offset++] = '\r';
            buf.base[offset++] = '\n';
        }
    }
    if (cookie_buf.len != 0) {
        FLATTEN_PREFIXED_VALUE("cookie: ", cookie_buf, 0);
        buf.base[offset++] = '\r';
        buf.base[offset++] = '\n';
    }
    FLATTEN_PREFIXED_VALUE("x-forwarded-proto: ", req->input.scheme->name, 0);
    buf.base[offset++] = '\r';
    buf.base[offset++] = '\n';
    if (remote_addr_len != SIZE_MAX) {
        FLATTEN_PREFIXED_VALUE("x-forwarded-for: ", xff_buf, remote_addr_len);
        APPEND(remote_addr, remote_addr_len);
    } else {
        FLATTEN_PREFIXED_VALUE("x-forwarded-for: ", xff_buf, 0);
    }
    buf.base[offset++] = '\r';
    buf.base[offset++] = '\n';
    FLATTEN_PREFIXED_VALUE("via: ", via_buf, sizeof("1.1 ") - 1 + req->input.authority.len);
    if (req->version < 0x200) {
        buf.base[offset++] = '1';
        buf.base[offset++] = '.';
        buf.base[offset++] = '0' + (0x100 <= req->version && req->version <= 0x109 ? req->version - 0x100 : 0);
    } else {
        buf.base[offset++] = '2';
    }
    buf.base[offset++] = ' ';
    APPEND(req->input.authority.base, req->input.authority.len);
    APPEND_STRLIT("\r\n\r\n");

#undef RESERVE
#undef APPEND
#undef APPEND_STRLIT
#undef FLATTEN_PREFIXED_VALUE

    /* set the length */
    assert(offset <= buf.len);
    buf.len = offset;

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

/**
 * extracts path to be pushed from link header (or returns {NULL,0} if none)
 */
static h2o_iovec_t extract_pushpath_from_link_header(h2o_mem_pool_t *pool, const char *value, size_t value_len, h2o_url_t *base)
{
    h2o_iovec_t url;
    h2o_url_t parsed, resolved;

    { /* extract URL value from: Link: </pushed.css>; rel=preload */
        h2o_iovec_t iter = h2o_iovec_init(value, value_len), token_value;
        const char *token;
        size_t token_len;
        /* first element should be <URL> */
        if ((token = h2o_next_token(&iter, ';', &token_len, NULL)) == NULL)
            goto None;
        if (!(token_len >= 2 && token[0] == '<' && token[token_len - 1] == '>'))
            goto None;
        url = h2o_iovec_init(token + 1, token_len - 2);
        /* find rel=preload */
        while ((token = h2o_next_token(&iter, ';', &token_len, &token_value)) != NULL) {
            if (h2o_lcstris(token, token_len, H2O_STRLIT("rel")) &&
                h2o_lcstris(token_value.base, token_value.len, H2O_STRLIT("preload")))
                break;
        }
        if (token == NULL)
            goto None;
    }

    /* check the authority, and extract absolute path */
    if (h2o_url_parse_relative(url.base, url.len, &parsed) != 0)
        goto None;
    h2o_url_resolve(pool, base, &parsed, &resolved);
    if (!(base->scheme == resolved.scheme &&
          (parsed.authority.base == NULL ||
           h2o_lcstris(base->authority.base, base->authority.len, resolved.authority.base, resolved.authority.len))))
        goto None;

    return resolved.path;
None:
    return (h2o_iovec_t){};
}

static h2o_http1client_body_cb on_head(h2o_http1client_t *client, const char *errstr, int minor_version, int status,
                                       h2o_iovec_t msg, struct phr_header *headers, size_t num_headers)
{
    struct rp_generator_t *self = client->data;
    h2o_req_t *req = self->src_req;
    size_t i;
    h2o_url_t url_parsed = {};

    if (errstr != NULL && errstr != h2o_http1client_error_is_eos) {
        self->client = NULL;
        h2o_send_error(req, 502, "Gateway Error", errstr, 0);
        return NULL;
    }

    /* copy the response (note: all the headers must be copied; http1client discards the input once we return from this callback) */
    req->res.status = status;
    req->res.reason = h2o_strdup(&req->pool, msg.base, msg.len).base;
    for (i = 0; i != num_headers; ++i) {
        const h2o_token_t *token = h2o_lookup_token(headers[i].name, headers[i].name_len);
        h2o_iovec_t value;
        if (token != NULL) {
            if (token->proxy_should_drop) {
                goto Skip;
            }
            if (token == H2O_TOKEN_CONTENT_LENGTH) {
                if (req->res.content_length != SIZE_MAX ||
                    (req->res.content_length = h2o_strtosize(headers[i].value, headers[i].value_len)) == SIZE_MAX) {
                    self->client = NULL;
                    h2o_send_error(req, 502, "Gateway Error", "invalid response from upstream", 0);
                    return NULL;
                }
                goto Skip;
            } else if (token == H2O_TOKEN_LOCATION) {
                if (req->res_is_delegated && (300 <= status && status <= 399) && status != 304) {
                    self->client = NULL;
                    h2o_send_redirect_internal(req, status, headers[i].value, headers[i].value_len);
                    return NULL;
                }
                if (req->overrides != NULL && req->overrides->location_rewrite.match != NULL) {
                    value =
                        rewrite_location(&req->pool, headers[i].value, headers[i].value_len, req->overrides->location_rewrite.match,
                                         req->input.scheme, req->input.authority, req->overrides->location_rewrite.path_prefix);
                    if (value.base != NULL)
                        goto AddHeader;
                }
                goto AddHeaderDuped;
            } else if (token == H2O_TOKEN_LINK && req->version >= 0x200 && !req->res_is_delegated) {
                if (url_parsed.scheme == NULL) {
                    if (h2o_url_parse_hostport(req->input.authority.base, req->input.authority.len, &url_parsed.host,
                                               &url_parsed._port) != NULL) {
                        url_parsed = (h2o_url_t){
                            req->input.scheme,    /* scheme */
                            req->input.authority, /* authority */
                            {},                   /* host */
                            req->path_normalized, /* path */
                            65535                 /* port */
                        };
                    }
                }
                if (url_parsed.scheme != NULL) {
                    h2o_iovec_t path =
                        extract_pushpath_from_link_header(&req->pool, headers[i].value, headers[i].value_len, &url_parsed);
                    if (path.base != NULL) {
                        h2o_vector_reserve(&req->pool, (h2o_vector_t *)&req->http2_push_paths,
                                           sizeof(req->http2_push_paths.entries[0]), req->http2_push_paths.size + 1);
                        req->http2_push_paths.entries[req->http2_push_paths.size++] = path;
                    }
                }
            }
        /* default behaviour, transfer the header downstream */
        AddHeaderDuped:
            value = h2o_strdup(&req->pool, headers[i].value, headers[i].value_len);
        AddHeader:
            h2o_add_header(&req->pool, &req->res.headers, token, value.base, value.len);
        Skip:
            ;
        } else {
            h2o_iovec_t name = h2o_strdup(&req->pool, headers[i].name, headers[i].name_len);
            h2o_iovec_t value = h2o_strdup(&req->pool, headers[i].value, headers[i].value_len);
            h2o_add_header_by_str(&req->pool, &req->res.headers, name.base, name.len, 0, value.base, value.len);
        }
    }

    /* declare the start of the response */
    h2o_start_response(req, &self->super);

    if (errstr == h2o_http1client_error_is_eos) {
        self->client = NULL;
        h2o_send(req, NULL, 0, 1);
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

static struct rp_generator_t *proxy_send_prepare(h2o_req_t *req, int keepalive)
{
    struct rp_generator_t *self = h2o_mem_alloc_shared(&req->pool, sizeof(*self), on_generator_dispose);

    self->super.proceed = do_proceed;
    self->super.stop = do_close;
    self->src_req = req;
    self->up_req.bufs[0] = build_request(req, keepalive);
    self->up_req.bufs[1] = req->entity;
    self->up_req.is_head = h2o_memis(req->method.base, req->method.len, H2O_STRLIT("HEAD"));
    h2o_buffer_init(&self->last_content_before_send, &h2o_socket_buffer_prototype);
    h2o_buffer_init(&self->buf_sending, &h2o_socket_buffer_prototype);

    return self;
}

void h2o__proxy_process_request(h2o_req_t *req)
{
    h2o_context_t *ctx = req->conn->ctx;
    h2o_req_overrides_t *overrides = req->overrides;
    h2o_http1client_ctx_t *client_ctx =
        overrides != NULL && overrides->client_ctx != NULL ? overrides->client_ctx : &ctx->proxy.client_ctx;
    struct rp_generator_t *self;

    if (overrides != NULL) {
        if (overrides->socketpool != NULL) {
            self = proxy_send_prepare(req, 1);
            self->client = h2o_http1client_connect_with_pool(client_ctx, &req->pool, overrides->socketpool, on_connect);
            goto Connecting;
        } else if (overrides->hostport.host != NULL) {
            self = proxy_send_prepare(req, 0);
            self->client = h2o_http1client_connect(client_ctx, &req->pool, req->overrides->hostport.host,
                                                   req->overrides->hostport.port, on_connect);
            goto Connecting;
        }
    }
    { /* default logic */
        h2o_iovec_t host;
        uint16_t port;
        if (req->scheme != &H2O_URL_SCHEME_HTTP) {
            send_error(req, "only HTTP (not HTTPS) URLs are supported");
            return;
        }
        if (h2o_url_parse_hostport(req->authority.base, req->authority.len, &host, &port) == NULL) {
            send_error(req, "could not parse host and port of URL");
            return;
        }
        if (port == 65535)
            port = 80;
        self = proxy_send_prepare(req, 0);
        self->client =
            h2o_http1client_connect(client_ctx, &req->pool, h2o_strdup(&req->pool, host.base, host.len).base, port, on_connect);
    }

Connecting:
    self->client->data = self;
}
