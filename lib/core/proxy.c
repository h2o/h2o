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
    h2o_httpclient_t *client;
    struct {
        h2o_iovec_t bufs[2]; /* first buf is the request line and headers, the second is the POST content */
        int is_head;
    } up_req;
    h2o_buffer_t *last_content_before_send;
    h2o_doublebuffer_t sending;
    int is_websocket_handshake;
    int had_body_error; /* set if an error happened while fetching the body so that we can propagate the error */
    void (*await_send)(h2o_httpclient_t *);
};

struct rp_ws_upgrade_info_t {
    h2o_context_t *ctx;
    h2o_timeout_t *timeout;
    h2o_socket_t *upstream_sock;
};

static h2o_httpclient_ctx_t *get_client_ctx(h2o_req_t *req)
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
    if (!h2o_url_hosts_are_equal(&loc_parsed, match))
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
    char *buf = h2o_mem_alloc_pool(pool, *buf, newlen);
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
    int is_put_or_post = (req->method.len >= 1 && req->method.base[0] == 'P' &&
                          (h2o_memis(req->method.base, req->method.len, H2O_STRLIT("POST")) ||
                           h2o_memis(req->method.base, req->method.len, H2O_STRLIT("PUT"))));

    return is_put_or_post && h2o_find_header(&req->res.headers, H2O_TOKEN_TRANSFER_ENCODING, -1) == -1;
}

static h2o_iovec_t build_content_length(h2o_mem_pool_t *pool, size_t cl)
{
    h2o_iovec_t cl_buf;
    cl_buf.base = h2o_mem_alloc_pool(pool, char, sizeof(H2O_UINT64_LONGEST_STR) - 1);
    cl_buf.len = sprintf(cl_buf.base, "%zu", cl);
    return cl_buf;
}

static void build_request(h2o_req_t *req, h2o_iovec_t *method, h2o_url_t *url, h2o_headers_t *headers,
                          h2o_httpclient_features_t features, int keepalive, int is_websocket_handshake, int use_proxy_protocol,
                          int *reprocess_if_too_early, h2o_url_t *origin)
{
    size_t remote_addr_len = SIZE_MAX;
    char remote_addr[NI_MAXHOST];
    struct sockaddr_storage ss;
    socklen_t sslen;
    h2o_iovec_t cookie_buf = {NULL}, xff_buf = {NULL}, via_buf = {NULL};
    int preserve_x_forwarded_proto = req->conn->ctx->globalconf->proxy.preserve_x_forwarded_proto;
    int emit_x_forwarded_headers = req->conn->ctx->globalconf->proxy.emit_x_forwarded_headers;
    int emit_via_header = req->conn->ctx->globalconf->proxy.emit_via_header;

    /* for x-f-f */
    if ((sslen = req->conn->callbacks->get_peername(req->conn, (void *)&ss)) != 0)
        remote_addr_len = h2o_socket_getnumerichost((void *)&ss, sslen, remote_addr);

    if (use_proxy_protocol && features.proxy_protocol != NULL) {
        features.proxy_protocol->base = h2o_mem_alloc_pool(&req->pool, char, H2O_PROXY_HEADER_MAX_LENGTH);
        features.proxy_protocol->len = h2o_stringify_proxy_header(req->conn, features.proxy_protocol->base);
    }

    /* method */
    *method = h2o_strdup(&req->pool, req->method.base, req->method.len);

    /* url */
    h2o_url_init(url, origin->scheme, req->authority, h2o_strdup(&req->pool, req->path.base, req->path.len));

    if (features.connection_header) {
        if (is_websocket_handshake) {
            h2o_add_header(&req->pool, headers, H2O_TOKEN_CONNECTION, NULL, H2O_STRLIT("upgrade"));
            h2o_add_header(&req->pool, headers, H2O_TOKEN_UPGRADE, NULL, H2O_STRLIT("websocket"));
        } else if (keepalive) {
            h2o_add_header(&req->pool, headers, H2O_TOKEN_CONNECTION, NULL, H2O_STRLIT("keep-alive"));
        } else {
            h2o_add_header(&req->pool, headers, H2O_TOKEN_CONNECTION, NULL, H2O_STRLIT("close"));
        }
    }

    /* CL or TE? Depends on whether we're streaming the request body or
       not, and if CL was advertised in the original request */
    if (req->proceed_req == NULL) {
        if (req->entity.base != NULL || req_requires_content_length(req)) {
            h2o_iovec_t cl_buf = build_content_length(&req->pool, req->entity.len);
            h2o_add_header(&req->pool, headers, H2O_TOKEN_CONTENT_LENGTH, NULL, cl_buf.base, cl_buf.len);
        }
    } else {
        if (req->content_length != SIZE_MAX) {
            h2o_iovec_t cl_buf = build_content_length(&req->pool, req->content_length);
            h2o_add_header(&req->pool, headers, H2O_TOKEN_CONTENT_LENGTH, NULL, cl_buf.base, cl_buf.len);
        } else if (features.chunked != NULL) {
            *(features.chunked) = 1;
            h2o_add_header(&req->pool, headers, H2O_TOKEN_TRANSFER_ENCODING, NULL, H2O_STRLIT("chunked"));
        }
    }

    /* headers */
    /* rewrite headers if necessary */
    h2o_headers_t req_headers = req->headers;
    if (req->overrides != NULL && req->overrides->headers_cmds != NULL) {
        req_headers.entries = NULL;
        req_headers.size = 0;
        req_headers.capacity = 0;
        h2o_headers_command_t *cmd;
        h2o_vector_reserve(&req->pool, &req_headers, req->headers.capacity);
        memcpy(req_headers.entries, req->headers.entries, sizeof(req->headers.entries[0]) * req->headers.size);
        req_headers.size = req->headers.size;
        for (cmd = req->overrides->headers_cmds; cmd->cmd != H2O_HEADERS_CMD_NULL; ++cmd)
            h2o_rewrite_headers(&req->pool, &req_headers, cmd);
    }

    {
        const h2o_header_t *h, *h_end;
        int found_early_data = 0;
        for (h = req_headers.entries, h_end = h + req_headers.size; h != h_end; ++h) {
            if (h2o_iovec_is_token(h->name)) {
                const h2o_token_t *token = (void *)h->name;
                if (token->proxy_should_drop_for_req) {
                    continue;
                } else if (token == H2O_TOKEN_COOKIE) {
                    /* merge the cookie headers; see HTTP/2 8.1.2.5 and HTTP/1 (RFC6265 5.4) */
                    /* FIXME current algorithm is O(n^2) against the number of cookie headers */
                    cookie_buf = build_request_merge_headers(&req->pool, cookie_buf, h->value, ';');
                    continue;
                } else if (token == H2O_TOKEN_VIA) {
                    if (!emit_via_header) {
                        goto AddHeader;
                    }
                    via_buf = build_request_merge_headers(&req->pool, via_buf, h->value, ',');
                    continue;
                } else if (token == H2O_TOKEN_X_FORWARDED_FOR) {
                    if (!emit_x_forwarded_headers) {
                        goto AddHeader;
                    }
                    xff_buf = build_request_merge_headers(&req->pool, xff_buf, h->value, ',');
                    continue;
                } else if (token == H2O_TOKEN_EARLY_DATA) {
                    found_early_data = 1;
                    goto AddHeader;
                }
            }
            if (!preserve_x_forwarded_proto && h2o_lcstris(h->name->base, h->name->len, H2O_STRLIT("x-forwarded-proto")))
                continue;
        AddHeader:
            if (h2o_iovec_is_token(h->name)) {
                const h2o_token_t *token = (void *)h->name;
                h2o_add_header(&req->pool, headers, token, h->orig_name, h->value.base, h->value.len);
            } else {
                h2o_add_header_by_str(&req->pool, headers, h->name->base, h->name->len, 0, h->orig_name, h->value.base,
                                      h->value.len);
            }
        }
        if (found_early_data) {
            *reprocess_if_too_early = 0;
        } else if (*reprocess_if_too_early) {
            h2o_add_header(&req->pool, headers, H2O_TOKEN_EARLY_DATA, NULL, H2O_STRLIT("1"));
        }
    }

    if (cookie_buf.len != 0) {
        h2o_add_header(&req->pool, headers, H2O_TOKEN_COOKIE, NULL, cookie_buf.base, cookie_buf.len);
    }
    if (emit_x_forwarded_headers) {
        if (!preserve_x_forwarded_proto)
            h2o_add_header_by_str(&req->pool, headers, H2O_STRLIT("x-forwarded-proto"), 0, NULL, req->input.scheme->name.base,
                                  req->input.scheme->name.len);
        if (remote_addr_len != SIZE_MAX)
            xff_buf = build_request_merge_headers(&req->pool, xff_buf, h2o_iovec_init(remote_addr, remote_addr_len), ',');
        if (xff_buf.len != 0)
            h2o_add_header(&req->pool, headers, H2O_TOKEN_X_FORWARDED_FOR, NULL, xff_buf.base, xff_buf.len);
    }
    if (emit_via_header) {
        h2o_iovec_t added;
        added.base = h2o_mem_alloc_pool(&req->pool, char, sizeof("1.1 ") - 1 + req->input.authority.len);
        added.len = 0;

        if (req->version < 0x200) {
            added.base[added.len++] = '1';
            added.base[added.len++] = '.';
            added.base[added.len++] = '0' + (0x100 <= req->version && req->version <= 0x109 ? req->version - 0x100 : 0);
        } else {
            added.base[added.len++] = '2';
        }
        added.base[added.len++] = ' ';
        memcpy(added.base + added.len, req->input.authority.base, req->input.authority.len);
        added.len += req->input.authority.len;

        via_buf = build_request_merge_headers(&req->pool, via_buf, added, ',');
        h2o_add_header(&req->pool, headers, H2O_TOKEN_VIA, NULL, via_buf.base, via_buf.len);
    }
}
static void do_close(h2o_generator_t *generator, h2o_req_t *req)
{
    struct rp_generator_t *self = (void *)generator;

    if (self->client != NULL) {
        self->client->cancel(self->client);
        self->client = NULL;
    }
}

static void do_send(struct rp_generator_t *self)
{
    h2o_iovec_t vecs[1];
    size_t veccnt;
    h2o_send_state_t ststate;

    vecs[0] = h2o_doublebuffer_prepare(&self->sending, self->client != NULL ? self->client->buf : &self->last_content_before_send,
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
    if (self->await_send) {
        self->await_send(self->client);
        self->await_send = NULL;
    }
}

static void on_websocket_upgrade_complete(void *_info, h2o_socket_t *sock, size_t reqsize)
{
    struct rp_ws_upgrade_info_t *info = _info;

    if (sock != NULL) {
        h2o_buffer_consume(&sock->input, reqsize); // It is detached from conn. Let's trash unused data.
        h2o_tunnel_establish(info->ctx, sock, info->upstream_sock, info->timeout);
    } else {
        h2o_socket_close(info->upstream_sock);
    }
    free(info);
}

static inline void on_websocket_upgrade(struct rp_generator_t *self, h2o_timeout_t *timeout, int rlen)
{
    h2o_req_t *req = self->src_req;
    h2o_socket_t *sock = self->client->steal_socket(self->client);
    h2o_buffer_consume(&sock->input, rlen); // trash data after stealing sock.
    struct rp_ws_upgrade_info_t *info = h2o_mem_alloc(sizeof(*info));
    info->upstream_sock = sock;
    info->timeout = timeout;
    info->ctx = req->conn->ctx;
    h2o_http1_upgrade(req, NULL, 0, on_websocket_upgrade_complete, info);
}

static void await_send(h2o_httpclient_t *client)
{
    if (client)
        client->resume_read(client);
}

static int on_body(h2o_httpclient_t *client, const char *errstr)
{
    struct rp_generator_t *self = client->data;
    h2o_req_overrides_t *overrides = self->src_req->overrides;

    if (errstr != NULL) {
        /* detach the content */
        self->last_content_before_send = *self->client->buf;
        h2o_buffer_init(self->client->buf, &h2o_socket_buffer_prototype);
        self->client = NULL;
        if (errstr != h2o_httpclient_error_is_eos) {
            h2o_req_log_error(self->src_req, "lib/core/proxy.c", "%s", errstr);
            self->had_body_error = 1;
        }
    }
    if (!self->sending.inflight)
        do_send(self);

    if (self->client && *self->client->buf && overrides && (*self->client->buf)->size > overrides->max_buffer_size) {
        self->await_send = await_send;
        self->client->stop_read(self->client);
    }

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

static h2o_httpclient_body_cb on_head(h2o_httpclient_t *client, const char *errstr, int minor_version, int status, h2o_iovec_t msg,
                                      h2o_header_t *headers, size_t num_headers, int rlen)
{
    struct rp_generator_t *self = client->data;
    h2o_req_t *req = self->src_req;
    size_t i;
    int emit_missing_date_header = req->conn->ctx->globalconf->proxy.emit_missing_date_header;
    int seen_date_header = 0;

    if (errstr != NULL && errstr != h2o_httpclient_error_is_eos) {
        self->client = NULL;
        h2o_req_log_error(req, "lib/core/proxy.c", "%s", errstr);
        h2o_send_error_502(req, "Gateway Error", errstr, 0);
        return NULL;
    }

    /* copy the response (note: all the headers must be copied; http1client discards the input once we return from this callback) */
    req->res.status = status;
    req->res.reason = h2o_strdup(&req->pool, msg.base, msg.len).base;
    for (i = 0; i != num_headers; ++i) {
        if (h2o_iovec_is_token(headers[i].name)) {
            const h2o_token_t *token = H2O_STRUCT_FROM_MEMBER(h2o_token_t, buf, headers[i].name);
            h2o_iovec_t value;
            if (token->proxy_should_drop_for_res) {
                goto Skip;
            }
            if (token == H2O_TOKEN_CONTENT_LENGTH) {
                if (req->res.content_length != SIZE_MAX ||
                    (req->res.content_length = h2o_strtosize(headers[i].value.base, headers[i].value.len)) == SIZE_MAX) {
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
                    h2o_send_redirect_internal(req, method, headers[i].value.base, headers[i].value.len, 1);
                    return NULL;
                }
                if (req->overrides != NULL && req->overrides->location_rewrite.match != NULL) {
                    value = rewrite_location(&req->pool, headers[i].value.base, headers[i].value.len,
                                             req->overrides->location_rewrite.match, req->input.scheme, req->input.authority,
                                             req->overrides->location_rewrite.path_prefix);
                    if (value.base != NULL)
                        goto AddHeader;
                }
                goto AddHeaderDuped;
            } else if (token == H2O_TOKEN_LINK) {
                h2o_iovec_t new_value;
                new_value = h2o_push_path_in_link_header(req, headers[i].value.base, headers[i].value.len);
                if (!new_value.len)
                    goto Skip;
                headers[i].value.base = new_value.base;
                headers[i].value.len = new_value.len;
            } else if (token == H2O_TOKEN_SERVER) {
                if (!req->conn->ctx->globalconf->proxy.preserve_server_header)
                    goto Skip;
            } else if (token == H2O_TOKEN_X_COMPRESS_HINT) {
                req->compress_hint = compress_hint_to_enum(headers[i].value.base, headers[i].value.len);
                goto Skip;
            } else if (token == H2O_TOKEN_DATE) {
                seen_date_header = 1;
            }
        /* default behaviour, transfer the header downstream */
        AddHeaderDuped:
            value = h2o_strdup(&req->pool, headers[i].value.base, headers[i].value.len);
        AddHeader:
            h2o_add_header(&req->pool, &req->res.headers, token, headers[i].orig_name, value.base, value.len);
        Skip:;
        } else {
            h2o_iovec_t name = h2o_strdup(&req->pool, headers[i].name->base, headers[i].name->len);
            h2o_iovec_t value = h2o_strdup(&req->pool, headers[i].value.base, headers[i].value.len);
            h2o_add_header_by_str(&req->pool, &req->res.headers, name.base, name.len, 0, headers[i].orig_name, value.base,
                                  value.len);
        }
    }

    if (!seen_date_header && emit_missing_date_header)
        h2o_resp_add_date_header(req);

    if (self->is_websocket_handshake && req->res.status == 101) {
        h2o_httpclient_ctx_t *client_ctx = get_client_ctx(req);
        assert(client_ctx->websocket_timeout != NULL);
        h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_UPGRADE, NULL, H2O_STRLIT("websocket"));
        on_websocket_upgrade(self, client_ctx->websocket_timeout, rlen);
        self->client = NULL;
        return NULL;
    }
    /* declare the start of the response */
    h2o_start_response(req, &self->super);

    if (errstr == h2o_httpclient_error_is_eos) {
        self->client = NULL;
        h2o_send(req, NULL, 0, H2O_SEND_STATE_FINAL);
        return NULL;
    }

    /* We currently fail to notify the protocol handler that the headers are complete (by invoking h2o_send(NULL, 0)) if the body
     * received from upstream is using chunked encoding and if only an incomplete chunk header (i.e. chunk-size CR LF CR LF) was
     * received along with the HTTP headers. However it is not a big deal; we are only failing to "optimize" for a theoretical
     * corner case.
     */
    if ((*self->client->buf)->size == rlen) {
        h2o_doublebuffer_prepare_empty(&self->sending);
        h2o_send(req, NULL, 0, H2O_SEND_STATE_IN_PROGRESS);
    }

    return on_body;
}

static int on_1xx(h2o_httpclient_t *client, int minor_version, int status, h2o_iovec_t msg, h2o_header_t *headers,
                  size_t num_headers)
{
    struct rp_generator_t *self = client->data;
    size_t i;

    for (i = 0; i != num_headers; ++i) {
        if (headers[i].name == &H2O_TOKEN_LINK->buf)
            h2o_push_path_in_link_header(self->src_req, headers[i].value.base, headers[i].value.len);
    }

    return 0;
}

static void proceed_request(h2o_httpclient_t *client, size_t written, int is_end_stream)
{
    struct rp_generator_t *self = client->data;
    if (self->src_req->proceed_req != NULL)
        self->src_req->proceed_req(self->src_req, written, is_end_stream);
}

static int write_req(void *ctx, h2o_iovec_t chunk, int is_end_stream)
{
    struct rp_generator_t *self = ctx;

    if (is_end_stream) {
        self->src_req->write_req.cb = NULL;
    }
    return self->client->write_req(self->client, chunk, is_end_stream);
}

static h2o_httpclient_head_cb on_connect(h2o_httpclient_t *client, const char *errstr, h2o_iovec_t *method, h2o_url_t *url,
                                         h2o_headers_t *headers, h2o_iovec_t *body, h2o_httpclient_proceed_req_cb *proceed_req_cb,
                                         h2o_httpclient_features_t features, h2o_url_t *origin)
{
    struct rp_generator_t *self = client->data;
    h2o_req_t *req = self->src_req;
    int use_proxy_protocol = 0, reprocess_if_too_early = 0;

    if (errstr != NULL) {
        self->client = NULL;
        h2o_req_log_error(self->src_req, "lib/core/proxy.c", "%s", errstr);
        h2o_send_error_502(self->src_req, "Gateway Error", errstr, 0);
        return NULL;
    }

    assert(origin != NULL);

    if (req->overrides != NULL) {
        use_proxy_protocol = req->overrides->use_proxy_protocol;
        req->overrides->location_rewrite.match = origin;
        if (!req->overrides->proxy_preserve_host) {
            req->scheme = origin->scheme;
            req->authority = origin->authority;
        }
        h2o_iovec_t append = req->path;
        if (origin->path.base[origin->path.len - 1] == '/' && append.base[0] == '/') {
            append.base += 1;
            append.len -= 1;
        }
        req->path = h2o_concat(&req->pool, origin->path, append);
        req->path_normalized =
            h2o_url_normalize_path(&req->pool, req->path.base, req->path.len, &req->query_at, &req->norm_indexes);
    }

    reprocess_if_too_early = h2o_conn_is_early_data(req->conn);
    build_request(req, method, url, headers, features, !use_proxy_protocol && h2o_socketpool_can_keepalive(client->sockpool.pool),
                  self->is_websocket_handshake, use_proxy_protocol, &reprocess_if_too_early, origin);
    if (reprocess_if_too_early)
        req->reprocess_if_too_early = 1;

    if (self->src_req->entity.base != NULL) {
        *body = self->src_req->entity;
        if (self->src_req->proceed_req != NULL) {
            *proceed_req_cb = proceed_request;
            self->src_req->write_req.cb = write_req;
            self->src_req->write_req.ctx = self;
        }
    }
    self->client->informational_cb = on_1xx;
    return on_head;
}

static void on_generator_dispose(void *_self)
{
    struct rp_generator_t *self = _self;

    if (self->client != NULL) {
        self->client->cancel(self->client);
        self->client = NULL;
    }
    h2o_buffer_dispose(&self->last_content_before_send);
    h2o_doublebuffer_dispose(&self->sending);
}

static struct rp_generator_t *proxy_send_prepare(h2o_req_t *req)
{
    struct rp_generator_t *self = h2o_mem_alloc_shared(&req->pool, sizeof(*self), on_generator_dispose);
    h2o_httpclient_ctx_t *client_ctx = get_client_ctx(req);

    self->super.proceed = do_proceed;
    self->super.stop = do_close;
    self->src_req = req;
    if (client_ctx->websocket_timeout != NULL && h2o_lcstris(req->upgrade.base, req->upgrade.len, H2O_STRLIT("websocket"))) {
        self->is_websocket_handshake = 1;
    } else {
        self->is_websocket_handshake = 0;
    }
    self->had_body_error = 0;
    self->await_send = NULL;
    self->up_req.is_head = h2o_memis(req->method.base, req->method.len, H2O_STRLIT("HEAD"));
    h2o_buffer_init(&self->last_content_before_send, &h2o_socket_buffer_prototype);
    h2o_doublebuffer_init(&self->sending, &h2o_socket_buffer_prototype);

    return self;
}

void h2o__proxy_process_request(h2o_req_t *req)
{
    h2o_req_overrides_t *overrides = req->overrides;
    h2o_httpclient_ctx_t *client_ctx = get_client_ctx(req);
    h2o_url_t target_buf, *target = &target_buf;

    h2o_socketpool_t *socketpool = &req->conn->ctx->globalconf->proxy.global_socketpool;
    if (overrides != NULL && overrides->socketpool != NULL) {
        socketpool = overrides->socketpool;
        if (!overrides->proxy_preserve_host)
            target = NULL;
    }
    if (target == &target_buf)
        h2o_url_init(&target_buf, req->scheme, req->authority, h2o_iovec_init(H2O_STRLIT("/")));

    struct rp_generator_t *self = proxy_send_prepare(req);

    /*
      When the PROXY protocol is being used (i.e. when overrides->use_proxy_protocol is set), the client needs to establish a new
     connection even when there is a pooled connection to the peer, since the header (as defined in
     https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt) needs to be sent at the beginning of the connection.

     However, currently h2o_http1client_connect doesn't provide an interface to enforce estabilishing a new connection. In other
     words, there is a chance that we would use a pool connection here.

     OTOH, the probability of seeing such issue is rare; it would only happen if the same destination identified by its host:port is
     accessed in both ways (i.e. in one path with use_proxy_protocol set and in the other path without).

     So I leave this as it is for the time being.
     */
    h2o_http1client_connect(&self->client, self, client_ctx, socketpool, target, on_connect);
}
