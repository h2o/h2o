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
#include "h2o/http1.h"
#include "h2o/http1client.h"
#include "h2o/tunnel.h"

struct rp_generator_t {
    h2o_generator_t super;
    h2o_req_t *src_req;
    h2o_http1client_t *client;
    struct {
        h2o_iovec_t bufs[2]; /* first buf is the request line and headers, the second is the POST content */
        int is_head;
    } up_req;
    h2o_buffer_t *last_content_before_send;
    h2o_doublebuffer_t sending;
    int is_websocket_handshake;
    int had_body_error; /* set if an error happened while fetching the body so that we can propagate the error */
};

struct rp_ws_upgrade_info_t {
    h2o_context_t *ctx;
    h2o_timeout_t *timeout;
    h2o_socket_t *upstream_sock;
};

static h2o_http1client_ctx_t *get_client_ctx(h2o_req_t *req)
{
    h2o_req_overrides_t *overrides = req->overrides;
    if (overrides != NULL && overrides->client_ctx != NULL)
        return overrides->client_ctx;
    return &req->conn->ctx->proxy.client_ctx;
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
    return (h2o_iovec_t){NULL};
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

/*
 * A request without neither Content-Length or Transfer-Encoding header implies a zero-length request body (see 6th rule of RFC 7230
 * 3.3.3).
 * OTOH, section 3.3.3 states:
 *
 *   A user agent SHOULD send a Content-Length in a request message when
 *   no Transfer-Encoding is sent and the request method defines a meaning
 *   for an enclosed payload body.  For example, a Content-Length header
 *   field is normally sent in a POST request even when the value is 0
 *   (indicating an empty payload body).  A user agent SHOULD NOT send a
 *   Content-Length header field when the request message does not contain
 *   a payload body and the method semantics do not anticipate such a
 *   body.
 *
 * PUT and POST define a meaning for the payload body, let's emit a
 * Content-Length header if it doesn't exist already, since the server
 * might send a '411 Length Required' response.
 *
 * see also: ML thread starting at https://lists.w3.org/Archives/Public/ietf-http-wg/2016JulSep/0580.html
 */
static int req_requires_content_length(h2o_req_t *req)
{
    int is_put_or_post =
        (req->method.len >= 1 && req->method.base[0] == 'P' && (h2o_memis(req->method.base, req->method.len, H2O_STRLIT("POST")) ||
                                                                h2o_memis(req->method.base, req->method.len, H2O_STRLIT("PUT"))));

    return is_put_or_post && h2o_find_header(&req->res.headers, H2O_TOKEN_TRANSFER_ENCODING, -1) == -1;
}

static h2o_iovec_t build_request(h2o_req_t *req, int keepalive, int is_websocket_handshake, int use_proxy_protocol)
{
    h2o_iovec_t buf;
    size_t offset = 0, remote_addr_len = SIZE_MAX;
    char remote_addr[NI_MAXHOST];
    struct sockaddr_storage ss;
    socklen_t sslen;
    h2o_iovec_t cookie_buf = {NULL}, xff_buf = {NULL}, via_buf = {NULL};
    int preserve_x_forwarded_proto = req->conn->ctx->globalconf->proxy.preserve_x_forwarded_proto;
    int emit_x_forwarded_headers = req->conn->ctx->globalconf->proxy.emit_x_forwarded_headers;

    /* for x-f-f */
    if ((sslen = req->conn->callbacks->get_peername(req->conn, (void *)&ss)) != 0)
        remote_addr_len = h2o_socket_getnumerichost((void *)&ss, sslen, remote_addr);

    /* build response */
    buf.len = req->method.len + req->path.len + req->authority.len + 512;
    if (use_proxy_protocol)
        buf.len += H2O_PROXY_HEADER_MAX_LENGTH;
    buf.base = h2o_mem_alloc_pool(&req->pool, buf.len);

#define RESERVE(sz)                                                                                                                \
    do {                                                                                                                           \
        size_t required = offset + sz + 4 /* for "\r\n\r\n" */;                                                                    \
        if (required > buf.len) {                                                                                                  \
            do {                                                                                                                   \
                buf.len *= 2;                                                                                                      \
            } while (required > buf.len);                                                                                          \
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

    if (use_proxy_protocol)
        offset += h2o_stringify_proxy_header(req->conn, buf.base + offset);

    APPEND(req->method.base, req->method.len);
    buf.base[offset++] = ' ';
    APPEND(req->path.base, req->path.len);
    APPEND_STRLIT(" HTTP/1.1\r\nconnection: ");
    if (is_websocket_handshake) {
        APPEND_STRLIT("upgrade\r\nupgrade: websocket\r\nhost: ");
    } else if (keepalive) {
        APPEND_STRLIT("keep-alive\r\nhost: ");
    } else {
        APPEND_STRLIT("close\r\nhost: ");
    }
    APPEND(req->authority.base, req->authority.len);
    buf.base[offset++] = '\r';
    buf.base[offset++] = '\n';
    assert(offset <= buf.len);
    if (req->entity.base != NULL || req_requires_content_length(req)) {
        RESERVE(sizeof("content-length: " H2O_UINT64_LONGEST_STR) - 1);
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
                } else if (token == H2O_TOKEN_X_FORWARDED_FOR) {
                    if (!emit_x_forwarded_headers) {
                        goto AddHeader;
                    }
                    xff_buf = build_request_merge_headers(&req->pool, xff_buf, h->value, ',');
                    continue;
                }
            }
            if (!preserve_x_forwarded_proto && h2o_lcstris(h->name->base, h->name->len, H2O_STRLIT("x-forwarded-proto")))
                continue;
        AddHeader:
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
    if (emit_x_forwarded_headers) {
        if (!preserve_x_forwarded_proto) {
            FLATTEN_PREFIXED_VALUE("x-forwarded-proto: ", req->input.scheme->name, 0);
            buf.base[offset++] = '\r';
            buf.base[offset++] = '\n';
        }
        if (remote_addr_len != SIZE_MAX) {
            FLATTEN_PREFIXED_VALUE("x-forwarded-for: ", xff_buf, remote_addr_len);
            APPEND(remote_addr, remote_addr_len);
        } else {
            FLATTEN_PREFIXED_VALUE("x-forwarded-for: ", xff_buf, 0);
        }
        buf.base[offset++] = '\r';
        buf.base[offset++] = '\n';
    }
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

static void do_send(struct rp_generator_t *self)
{
    h2o_iovec_t vecs[1];
    size_t veccnt;
    h2o_send_state_t ststate;

    assert(self->sending.bytes_inflight == 0);

    vecs[0] = h2o_doublebuffer_prepare(&self->sending,
                                       self->client != NULL ? &self->client->sock->input : &self->last_content_before_send,
                                       self->src_req->preferred_chunk_size);

    if (self->client == NULL && vecs[0].len == self->sending.buf->size && self->last_content_before_send->size == 0) {
        veccnt = vecs[0].len != 0 ? 1 : 0;
        ststate = H2O_SEND_STATE_FINAL;
    } else {
        if (vecs[0].len == 0)
            return;
        veccnt = 1;
        ststate = H2O_SEND_STATE_IN_PROGRESS;
    }

    if (self->had_body_error)
        ststate = H2O_SEND_STATE_ERROR;

    h2o_send(self->src_req, vecs, veccnt, ststate);
}

static void do_proceed(h2o_generator_t *generator, h2o_req_t *req)
{
    struct rp_generator_t *self = (void *)generator;

    h2o_doublebuffer_consume(&self->sending);
    do_send(self);
}

static void on_websocket_upgrade_complete(void *_info, h2o_socket_t *sock, size_t reqsize)
{
    struct rp_ws_upgrade_info_t *info = _info;

    if (sock != NULL) {
        h2o_tunnel_establish(info->ctx, sock, info->upstream_sock, info->timeout);
    } else {
        h2o_socket_close(info->upstream_sock);
    }
    free(info);
}

static inline void on_websocket_upgrade(struct rp_generator_t *self, h2o_timeout_t *timeout)
{
    h2o_req_t *req = self->src_req;
    h2o_socket_t *sock = h2o_http1client_steal_socket(self->client);
    struct rp_ws_upgrade_info_t *info = h2o_mem_alloc(sizeof(*info));
    info->upstream_sock = sock;
    info->timeout = timeout;
    info->ctx = req->conn->ctx;
    h2o_http1_upgrade(req, NULL, 0, on_websocket_upgrade_complete, info);
}

static int on_body(h2o_http1client_t *client, const char *errstr)
{
    struct rp_generator_t *self = client->data;

    if (errstr != NULL) {
        /* detach the content */
        self->last_content_before_send = self->client->sock->input;
        h2o_buffer_init(&self->client->sock->input, &h2o_socket_buffer_prototype);
        self->client = NULL;
        if (errstr != h2o_http1client_error_is_eos) {
            h2o_req_log_error(self->src_req, "lib/core/proxy.c", "%s", errstr);
            self->had_body_error = 1;
        }
    }
    if (self->sending.bytes_inflight == 0)
        do_send(self);

    return 0;
}

static char compress_hint_to_enum(const char *val, size_t len)
{
    if (h2o_lcstris(val, len, H2O_STRLIT("on"))) {
        return H2O_COMPRESS_HINT_ENABLE;
    }
    if (h2o_lcstris(val, len, H2O_STRLIT("off"))) {
        return H2O_COMPRESS_HINT_DISABLE;
    }
    return H2O_COMPRESS_HINT_AUTO;
}

static h2o_http1client_body_cb on_head(h2o_http1client_t *client, const char *errstr, int minor_version, int status,
                                       h2o_iovec_t msg, h2o_http1client_header_t *headers, size_t num_headers)
{
    struct rp_generator_t *self = client->data;
    h2o_req_t *req = self->src_req;
    size_t i;

    if (errstr != NULL && errstr != h2o_http1client_error_is_eos) {
        self->client = NULL;
        h2o_req_log_error(req, "lib/core/proxy.c", "%s", errstr);
        h2o_send_error_502(req, "Gateway Error", errstr, 0);
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
                    h2o_req_log_error(req, "lib/core/proxy.c", "%s", "invalid response from upstream (malformed content-length)");
                    h2o_send_error_502(req, "Gateway Error", "invalid response from upstream", 0);
                    return NULL;
                }
                goto Skip;
            } else if (token == H2O_TOKEN_LOCATION) {
                if (req->res_is_delegated && (300 <= status && status <= 399) && status != 304) {
                    self->client = NULL;
                    h2o_iovec_t method = h2o_get_redirect_method(req->method, status);
                    h2o_send_redirect_internal(req, method, headers[i].value, headers[i].value_len, 1);
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
            } else if (token == H2O_TOKEN_LINK) {
                h2o_push_path_in_link_header(req, headers[i].value, headers[i].value_len);
            } else if (token == H2O_TOKEN_X_COMPRESS_HINT) {
                req->compress_hint = compress_hint_to_enum(headers[i].value, headers[i].value_len);
                goto Skip;
            }
        /* default behaviour, transfer the header downstream */
        AddHeaderDuped:
            value = h2o_strdup(&req->pool, headers[i].value, headers[i].value_len);
        AddHeader:
            h2o_add_header(&req->pool, &req->res.headers, token, value.base, value.len);
        Skip:;
        } else {
            h2o_iovec_t name = h2o_strdup(&req->pool, headers[i].name, headers[i].name_len);
            h2o_iovec_t value = h2o_strdup(&req->pool, headers[i].value, headers[i].value_len);
            h2o_add_header_by_str(&req->pool, &req->res.headers, name.base, name.len, 0, value.base, value.len);
        }
    }

    if (self->is_websocket_handshake && req->res.status == 101) {
        h2o_http1client_ctx_t *client_ctx = get_client_ctx(req);
        assert(client_ctx->websocket_timeout != NULL);
        h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_UPGRADE, H2O_STRLIT("websocket"));
        on_websocket_upgrade(self, client_ctx->websocket_timeout);
        self->client = NULL;
        return NULL;
    }
    /* declare the start of the response */
    h2o_start_response(req, &self->super);

    if (errstr == h2o_http1client_error_is_eos) {
        self->client = NULL;
        h2o_send(req, NULL, 0, H2O_SEND_STATE_FINAL);
        return NULL;
    }

    return on_body;
}

static int on_1xx(h2o_http1client_t *client, int minor_version, int status, h2o_iovec_t msg, h2o_http1client_header_t *headers,
                  size_t num_headers)
{
    struct rp_generator_t *self = client->data;
    size_t i;

    for (i = 0; i != num_headers; ++i) {
        if (h2o_memis(headers[i].name, headers[i].name_len, H2O_STRLIT("link")))
            h2o_push_path_in_link_header(self->src_req, headers[i].value, headers[i].value_len);
    }

    return 0;
}

static h2o_http1client_head_cb on_connect(h2o_http1client_t *client, const char *errstr, h2o_iovec_t **reqbufs, size_t *reqbufcnt,
                                          int *method_is_head)
{
    struct rp_generator_t *self = client->data;

    if (errstr != NULL) {
        self->client = NULL;
        h2o_req_log_error(self->src_req, "lib/core/proxy.c", "%s", errstr);
        h2o_send_error_502(self->src_req, "Gateway Error", errstr, 0);
        return NULL;
    }

    *reqbufs = self->up_req.bufs;
    *reqbufcnt = self->up_req.bufs[1].base != NULL ? 2 : 1;
    *method_is_head = self->up_req.is_head;
    self->client->informational_cb = on_1xx;
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
    h2o_doublebuffer_dispose(&self->sending);
}

static struct rp_generator_t *proxy_send_prepare(h2o_req_t *req, int keepalive, int use_proxy_protocol)
{
    struct rp_generator_t *self = h2o_mem_alloc_shared(&req->pool, sizeof(*self), on_generator_dispose);
    h2o_http1client_ctx_t *client_ctx = get_client_ctx(req);

    self->super.proceed = do_proceed;
    self->super.stop = do_close;
    self->src_req = req;
    if (client_ctx->websocket_timeout != NULL && h2o_lcstris(req->upgrade.base, req->upgrade.len, H2O_STRLIT("websocket"))) {
        self->is_websocket_handshake = 1;
    } else {
        self->is_websocket_handshake = 0;
    }
    self->had_body_error = 0;
    self->up_req.bufs[0] = build_request(req, keepalive, self->is_websocket_handshake, use_proxy_protocol);
    self->up_req.bufs[1] = req->entity;
    self->up_req.is_head = h2o_memis(req->method.base, req->method.len, H2O_STRLIT("HEAD"));
    h2o_buffer_init(&self->last_content_before_send, &h2o_socket_buffer_prototype);
    h2o_doublebuffer_init(&self->sending, &h2o_socket_buffer_prototype);

    return self;
}

void h2o__proxy_process_request(h2o_req_t *req)
{
    h2o_req_overrides_t *overrides = req->overrides;
    h2o_http1client_ctx_t *client_ctx = get_client_ctx(req);
    struct rp_generator_t *self;

    if (overrides != NULL) {
        if (overrides->socketpool != NULL) {
            if (overrides->use_proxy_protocol)
                assert(!"proxy protocol cannot be used for a persistent upstream connection");
            self = proxy_send_prepare(req, 1, 0);
            h2o_http1client_connect_with_pool(&self->client, self, client_ctx, overrides->socketpool, on_connect);
            return;
        } else if (overrides->hostport.host.base != NULL) {
            self = proxy_send_prepare(req, 0, overrides->use_proxy_protocol);
            h2o_http1client_connect(&self->client, self, client_ctx, req->overrides->hostport.host, req->overrides->hostport.port,
                                    0, on_connect);
            return;
        }
    }
    { /* default logic */
        h2o_iovec_t host;
        uint16_t port;
        if (h2o_url_parse_hostport(req->authority.base, req->authority.len, &host, &port) == NULL) {
            h2o_req_log_error(req, "lib/core/proxy.c", "invalid URL supplied for internal redirection:%s://%.*s%.*s",
                              req->scheme->name.base, (int)req->authority.len, req->authority.base, (int)req->path.len,
                              req->path.base);
            h2o_send_error_502(req, "Gateway Error", "internal error", 0);
            return;
        }
        if (port == 65535)
            port = req->scheme->default_port;
        self = proxy_send_prepare(req, 0, overrides != NULL && overrides->use_proxy_protocol);
        h2o_http1client_connect(&self->client, self, client_ctx, host, port, req->scheme == &H2O_URL_SCHEME_HTTPS, on_connect);
        return;
    }
}
