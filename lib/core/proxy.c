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
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include "picohttpparser.h"
#include "h2o.h"
#include "h2o/http1.h"
#include "h2o/httpclient.h"

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
    h2o_timer_t send_headers_timeout;
    size_t body_bytes_read, body_bytes_sent;
    struct {
        int fds[2]; /* fd[0] set to -1 unless used */
    } pipe_reader;
    unsigned had_body_error : 1; /* set if an error happened while fetching the body so that we can propagate the error */
    unsigned req_done : 1;
    unsigned res_done : 1;
    unsigned pipe_inflight : 1;
    int *generator_disposed;
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

    if (h2o_url_parse(pool, location, location_len, &loc_parsed) != 0)
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
    cl_buf.base = h2o_mem_alloc_pool(pool, char, sizeof(H2O_SIZE_T_LONGEST_STR));
    cl_buf.len = sprintf(cl_buf.base, "%zu", cl);
    return cl_buf;
}

static void build_request(h2o_req_t *req, h2o_iovec_t *method, h2o_url_t *url, h2o_headers_t *headers,
                          h2o_httpclient_properties_t *props, int keepalive, const char *upgrade_to, int use_proxy_protocol,
                          int *reprocess_if_too_early, h2o_url_t *origin)
{
    size_t remote_addr_len = SIZE_MAX;
    char remote_addr[NI_MAXHOST];
    struct sockaddr_storage ss;
    socklen_t sslen;
    h2o_iovec_t xff_buf = {NULL}, via_buf = {NULL};
    int preserve_x_forwarded_proto = req->conn->ctx->globalconf->proxy.preserve_x_forwarded_proto;
    int emit_x_forwarded_headers = req->conn->ctx->globalconf->proxy.emit_x_forwarded_headers;
    int emit_via_header = req->conn->ctx->globalconf->proxy.emit_via_header;

    /* for x-f-f */
    if ((sslen = req->conn->callbacks->get_peername(req->conn, (void *)&ss)) != 0)
        remote_addr_len = h2o_socket_getnumerichost((void *)&ss, sslen, remote_addr);

    if (props->proxy_protocol != NULL && use_proxy_protocol) {
        props->proxy_protocol->base = h2o_mem_alloc_pool(&req->pool, char, H2O_PROXY_HEADER_MAX_LENGTH);
        props->proxy_protocol->len = h2o_stringify_proxy_header(req->conn, props->proxy_protocol->base);
    }

    /* copy method (if it is an extended CONNECT switching versions, convert as appropriate) */
    *method = h2o_strdup(&req->pool, req->method.base, req->method.len);
    if (upgrade_to != NULL && upgrade_to != h2o_httpclient_upgrade_to_connect) {
        if (req->version >= 0x200 && h2o_memis(method->base, method->len, H2O_STRLIT("CONNECT")) &&
            props->connection_header != NULL) {
            *method = h2o_iovec_init(H2O_STRLIT("GET"));
        } else if (req->version < 0x200 && h2o_memis(method->base, method->len, H2O_STRLIT("GET")) &&
                   props->connection_header == NULL) {
            *method = h2o_iovec_init(H2O_STRLIT("CONNECT"));
        }
    }

    /* url */
    if (h2o_url_init(url, origin->scheme, req->authority, h2o_strdup(&req->pool, req->path.base, req->path.len)) != 0)
        h2o_fatal("h2o_url_init failed");

    if (props->connection_header != NULL) {
        if (keepalive) {
            *props->connection_header = h2o_iovec_init(H2O_STRLIT("keep-alive"));
        } else {
            *props->connection_header = h2o_iovec_init(H2O_STRLIT("close"));
        }
    }

    /* setup CL or TE, if necessary; chunked encoding is used when the request body is stream and content-length is unknown */
    if (!req->is_tunnel_req) {
        if (req->proceed_req == NULL) {
            if (req->entity.base != NULL || req_requires_content_length(req)) {
                h2o_iovec_t cl_buf = build_content_length(&req->pool, req->entity.len);
                h2o_add_header(&req->pool, headers, H2O_TOKEN_CONTENT_LENGTH, NULL, cl_buf.base, cl_buf.len);
            }
        } else {
            if (req->content_length != SIZE_MAX) {
                h2o_iovec_t cl_buf = build_content_length(&req->pool, req->content_length);
                h2o_add_header(&req->pool, headers, H2O_TOKEN_CONTENT_LENGTH, NULL, cl_buf.base, cl_buf.len);
            } else if (props->chunked != NULL) {
                *props->chunked = 1;
                h2o_add_header(&req->pool, headers, H2O_TOKEN_TRANSFER_ENCODING, NULL, H2O_STRLIT("chunked"));
            }
        }
    }

    /* headers */
    h2o_iovec_vector_t cookie_values = {NULL};
    int found_early_data = 0;
    if (H2O_LIKELY(req->headers.size != 0)) {
        for (const h2o_header_t *h = req->headers.entries, *h_end = h + req->headers.size; h != h_end; ++h) {
            if (h2o_iovec_is_token(h->name)) {
                const h2o_token_t *token = (void *)h->name;
                if (token->flags.proxy_should_drop_for_req)
                    continue;
                if (token == H2O_TOKEN_COOKIE) {
                    h2o_vector_reserve(&req->pool, &cookie_values, cookie_values.size + 1);
                    cookie_values.entries[cookie_values.size++] = h->value;
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
    }
    if (found_early_data) {
        *reprocess_if_too_early = 0;
    } else if (*reprocess_if_too_early) {
        h2o_add_header(&req->pool, headers, H2O_TOKEN_EARLY_DATA, NULL, H2O_STRLIT("1"));
    }

    if (cookie_values.size == 1) {
        /* fast path */
        h2o_add_header(&req->pool, headers, H2O_TOKEN_COOKIE, NULL, cookie_values.entries[0].base, cookie_values.entries[0].len);
    } else if (cookie_values.size > 1) {
        /* merge the cookie headers; see HTTP/2 8.1.2.5 and HTTP/1 (RFC6265 5.4) */
        h2o_iovec_t cookie_buf =
            h2o_join_list(&req->pool, cookie_values.entries, cookie_values.size, h2o_iovec_init(H2O_STRLIT("; ")));
        h2o_add_header(&req->pool, headers, H2O_TOKEN_COOKIE, NULL, cookie_buf.base, cookie_buf.len);
    }
    if (emit_x_forwarded_headers) {
        if (!preserve_x_forwarded_proto)
            h2o_add_header_by_str(&req->pool, headers, H2O_STRLIT("x-forwarded-proto"), 0, NULL, req->input.scheme->name.base,
                                  req->input.scheme->name.len);
        if (remote_addr_len != SIZE_MAX)
            xff_buf = build_request_merge_headers(&req->pool, xff_buf, h2o_strdup(&req->pool, remote_addr, remote_addr_len), ',');
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
            added.base[added.len++] = '0' + req->version / 0x100;
        }
        added.base[added.len++] = ' ';
        memcpy(added.base + added.len, req->input.authority.base, req->input.authority.len);
        added.len += req->input.authority.len;

        via_buf = build_request_merge_headers(&req->pool, via_buf, added, ',');
        h2o_add_header(&req->pool, headers, H2O_TOKEN_VIA, NULL, via_buf.base, via_buf.len);
    }

    /* rewrite headers if necessary */
    if (req->overrides != NULL && req->overrides->headers_cmds != NULL) {
        h2o_headers_command_t *cmd;
        for (cmd = req->overrides->headers_cmds; cmd->cmd != H2O_HEADERS_CMD_NULL; ++cmd)
            h2o_rewrite_headers(&req->pool, headers, cmd);
    }
}

static h2o_httpclient_t *detach_client(struct rp_generator_t *self)
{
    h2o_httpclient_t *client = self->client;
    assert(client != NULL);
    client->data = NULL;
    self->client = NULL;
    return client;
}

static int empty_pipe(int fd)
{
    ssize_t ret;
    char buf[1024];

drain_more:
    while ((ret = read(fd, buf, sizeof(buf))) == -1 && errno == EINTR)
        ;
    if (ret == 0) {
        return 0;
    } else if (ret == -1) {
        if (errno == EAGAIN)
            return 1;
        return 0;
    } else if (ret == sizeof(buf)) {
        goto drain_more;
    }

    return 1;
}

static void do_close(struct rp_generator_t *self)
{
    /**
     * This can be called in the following three scenarios:
     *   1. Downstream timeout before receiving header from upstream
     *        dispose callback calls this function, but stop callback doesn't
     *   2. Reprocess
     *        stop callback calls this, but dispose callback does it later (after reprocessed request gets finished)
     *   3. Others
     *        Both of stop and dispose callbacks call this function in order
     * Thus, to ensure to do closing things, both of dispose and stop callbacks call this function (reminder: that means that this
     * function might get called multiple times).
     */
    if (self->client != NULL) {
        h2o_httpclient_t *client = detach_client(self);
        client->cancel(client);
    }
    h2o_timer_unlink(&self->send_headers_timeout);
    if (self->pipe_reader.fds[0] != -1) {
        h2o_context_t *ctx = self->src_req->conn->ctx;
        if (ctx->proxy.spare_pipes.count < ctx->globalconf->proxy.max_spare_pipes && empty_pipe(self->pipe_reader.fds[0])) {
            int *dst = ctx->proxy.spare_pipes.pipes[ctx->proxy.spare_pipes.count++];
            dst[0] = self->pipe_reader.fds[0];
            dst[1] = self->pipe_reader.fds[1];
        } else {
            close(self->pipe_reader.fds[0]);
            close(self->pipe_reader.fds[1]);
        }

        self->pipe_reader.fds[0] = -1;
    }
}

static void do_stop(h2o_generator_t *generator, h2o_req_t *req)
{
    struct rp_generator_t *self = (void *)generator;
    do_close(self);
}

static void do_send(struct rp_generator_t *self)
{
    h2o_iovec_t vecs[1];
    size_t veccnt;
    h2o_send_state_t ststate;

    vecs[0] = h2o_doublebuffer_prepare(&self->sending,
                                       self->last_content_before_send != NULL ? &self->last_content_before_send : self->client->buf,
                                       self->src_req->preferred_chunk_size);

    if (self->last_content_before_send != NULL && vecs[0].len == self->sending.buf->size &&
        self->last_content_before_send->size == 0) {
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

    if (veccnt != 0)
        self->body_bytes_sent += vecs[0].len;
    h2o_send(self->src_req, vecs, veccnt, ststate);
}

static int from_pipe_read(h2o_sendvec_t *vec, void *dst, size_t len)
{
    struct rp_generator_t *self = (void *)vec->cb_arg[0];

    while (len != 0) {
        ssize_t ret;
        while ((ret = read(self->pipe_reader.fds[0], dst, len)) == -1 && errno == EINTR)
            ;
        if (ret <= 0) {
            assert(errno != EAGAIN);
            return 0;
        }
        dst += ret;
        len -= ret;
        vec->len -= ret;
    }

    return 1;
}

static size_t from_pipe_send(h2o_sendvec_t *vec, int sockfd, size_t len)
{
#ifdef __linux__
    struct rp_generator_t *self = (void *)vec->cb_arg[0];

    ssize_t bytes_sent;
    while ((bytes_sent = splice(self->pipe_reader.fds[0], NULL, sockfd, NULL, len, SPLICE_F_NONBLOCK)) == -1 && errno == EINTR)
        ;
    if (bytes_sent == -1 && errno == EAGAIN)
        return 0;
    if (bytes_sent <= 0)
        return SIZE_MAX;

    vec->len -= bytes_sent;

    return bytes_sent;
#else
    h2o_fatal("%s:not implemented", __FUNCTION__);
#endif
}

static void do_send_from_pipe(struct rp_generator_t *self)
{
    h2o_send_state_t send_state = self->had_body_error ? H2O_SEND_STATE_ERROR
                                  : self->res_done     ? H2O_SEND_STATE_FINAL
                                                       : H2O_SEND_STATE_IN_PROGRESS;

    if (self->body_bytes_read == self->body_bytes_sent) {
        if (h2o_send_state_is_in_progress(send_state)) {
            /* resume reading only when we know that the pipe (to which we read) has become empty */
            self->client->update_window(self->client);
        } else {
            h2o_send(self->src_req, NULL, 0, send_state);
        }
        return;
    }

    static const h2o_sendvec_callbacks_t callbacks = {.read_ = from_pipe_read, .send_ = from_pipe_send};
    h2o_sendvec_t vec = {.callbacks = &callbacks};
    if ((vec.len = self->body_bytes_read - self->body_bytes_sent) > H2O_PULL_SENDVEC_MAX_SIZE)
        vec.len = H2O_PULL_SENDVEC_MAX_SIZE;
    vec.cb_arg[0] = (uint64_t)self;
    vec.cb_arg[1] = 0; /* unused */

    self->body_bytes_sent += vec.len;
    self->pipe_inflight = 1;
    h2o_sendvec(self->src_req, &vec, 1, send_state);
}

static void do_proceed(h2o_generator_t *generator, h2o_req_t *req)
{
    struct rp_generator_t *self = (void *)generator;

    if (self->sending.inflight) {
        h2o_doublebuffer_consume(&self->sending);
    } else {
        assert(self->pipe_reader.fds[0] != -1);
        assert(self->pipe_inflight);
        self->pipe_inflight = 0;
    }

    if (self->pipe_reader.fds[0] != -1 && self->sending.buf->size == 0) {
        do_send_from_pipe(self);
    } else {
        do_send(self);
        if (!(self->res_done || self->had_body_error))
            self->client->update_window(self->client);
    }
}

static void copy_stats(struct rp_generator_t *self)
{
    self->src_req->proxy_stats.timestamps = self->client->timings;
    self->src_req->proxy_stats.bytes_written.total = self->client->bytes_written.total;
    self->src_req->proxy_stats.bytes_written.header = self->client->bytes_written.header;
    self->src_req->proxy_stats.bytes_written.body = self->client->bytes_written.body;
    self->src_req->proxy_stats.bytes_read.total = self->client->bytes_read.total;
    self->src_req->proxy_stats.bytes_read.header = self->client->bytes_read.header;
    self->src_req->proxy_stats.bytes_read.body = self->client->bytes_read.body;
}

static void on_body_on_close(struct rp_generator_t *self, const char *errstr)
{
    copy_stats(self);

    /* detach the content */
    self->last_content_before_send = *self->client->buf;
    h2o_buffer_init(self->client->buf, &h2o_socket_buffer_prototype);
    if (errstr == h2o_httpclient_error_is_eos) {
        self->res_done = 1;
        if (self->req_done)
            detach_client(self);
    } else {
        detach_client(self);
        h2o_req_log_error(self->src_req, "lib/core/proxy.c", "%s", errstr);
        self->had_body_error = 1;
        if (self->src_req->proceed_req != NULL)
            self->src_req->proceed_req(self->src_req, errstr);
    }
}

static int on_body(h2o_httpclient_t *client, const char *errstr, h2o_header_t *trailers, size_t num_trailers)
{
    int generator_disposed = 0;
    struct rp_generator_t *self = client->data;

    self->body_bytes_read = client->bytes_read.body;
    h2o_timer_unlink(&self->send_headers_timeout);

    if (num_trailers != 0) {
        assert(errstr == h2o_httpclient_error_is_eos);
        self->src_req->res.trailers = (h2o_headers_t){trailers, num_trailers, num_trailers};
    }

    if (errstr != NULL) {
        /* Call `on_body_on_close`. This function might dispose `self`, in which case `generator_disposed` would be set to true. */
        self->generator_disposed = &generator_disposed;
        on_body_on_close(self, errstr);
        if (!generator_disposed)
            self->generator_disposed = NULL;
    }
    if (!generator_disposed && !self->sending.inflight)
        do_send(self);

    return 0;
}

static int on_body_piped(h2o_httpclient_t *client, const char *errstr, h2o_header_t *trailers, size_t num_trailers)
{
    struct rp_generator_t *self = client->data;

    self->body_bytes_read = client->bytes_read.body;
    h2o_timer_unlink(&self->send_headers_timeout);

    if (num_trailers != 0) {
        assert(errstr == h2o_httpclient_error_is_eos);
        self->src_req->res.trailers = (h2o_headers_t){trailers, num_trailers, num_trailers};
    }

    if (errstr != NULL)
        on_body_on_close(self, errstr);
    if (!self->sending.inflight && !self->pipe_inflight)
        do_send_from_pipe(self);

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
    if (h2o_lcstris(val, len, H2O_STRLIT("gzip"))) {
        return H2O_COMPRESS_HINT_ENABLE_GZIP;
    }
    if (h2o_lcstris(val, len, H2O_STRLIT("br"))) {
        return H2O_COMPRESS_HINT_ENABLE_BR;
    }
    if (h2o_lcstris(val, len, H2O_STRLIT("zstd"))) {
        return H2O_COMPRESS_HINT_ENABLE_ZSTD;
    }
    return H2O_COMPRESS_HINT_AUTO;
}

static void on_send_headers_timeout(h2o_timer_t *entry)
{
    struct rp_generator_t *self = H2O_STRUCT_FROM_MEMBER(struct rp_generator_t, send_headers_timeout, entry);
    h2o_doublebuffer_prepare_empty(&self->sending);
    h2o_send(self->src_req, NULL, 0, H2O_SEND_STATE_IN_PROGRESS);
}

static h2o_httpclient_body_cb on_head(h2o_httpclient_t *client, const char *errstr, h2o_httpclient_on_head_t *args)
{
    struct rp_generator_t *self = client->data;
    h2o_req_t *req = self->src_req;
    size_t i;
    int emit_missing_date_header = req->conn->ctx->globalconf->proxy.emit_missing_date_header;
    int seen_date_header = 0;

    copy_stats(self);

    if (errstr != NULL && errstr != h2o_httpclient_error_is_eos) {
        detach_client(self);
        h2o_req_log_error(req, "lib/core/proxy.c", "%s", errstr);

        if (errstr == h2o_httpclient_error_refused_stream) {
            req->upstream_refused = 1;
            static h2o_generator_t generator = {NULL, NULL};
            h2o_start_response(req, &generator);
            h2o_send(req, NULL, 0, H2O_SEND_STATE_ERROR);
        } else {
            h2o_send_error_502(req, "Gateway Error", errstr, 0);
            if (self->src_req->proceed_req != NULL)
                self->src_req->proceed_req(self->src_req, h2o_httpclient_error_refused_stream);
        }

        return NULL;
    }

    /* copy the response (note: all the headers must be copied; http1client discards the input once we return from this callback) */
    req->res.status = args->status;
    req->res.reason = h2o_strdup(&req->pool, args->msg.base, args->msg.len).base;
    for (i = 0; i != args->num_headers; ++i) {
        h2o_iovec_t value = args->headers[i].value;
        if (h2o_iovec_is_token(args->headers[i].name)) {
            const h2o_token_t *token = H2O_STRUCT_FROM_MEMBER(h2o_token_t, buf, args->headers[i].name);
            if (token->flags.proxy_should_drop_for_res) {
                if (token == H2O_TOKEN_CONNECTION && self->src_req->version < 0x200 && req->overrides != NULL &&
                    req->overrides->forward_close_connection) {
                    if (h2o_lcstris(args->headers[i].value.base, args->headers[i].value.len, H2O_STRLIT("close")))
                        self->src_req->http1_is_persistent = 0;
                }
                continue;
            }
            if (token == H2O_TOKEN_CONTENT_LENGTH) {
                if (req->res.content_length != SIZE_MAX ||
                    (req->res.content_length = h2o_strtosize(args->headers[i].value.base, args->headers[i].value.len)) ==
                        SIZE_MAX) {
                    detach_client(self);
                    h2o_req_log_error(req, "lib/core/proxy.c", "%s", "invalid response from upstream (malformed content-length)");
                    h2o_send_error_502(req, "Gateway Error", "invalid response from upstream", 0);
                    if (self->src_req->proceed_req != NULL)
                        self->src_req->proceed_req(self->src_req, h2o_httpclient_error_io);
                    return NULL;
                }
                goto Skip;
            } else if (token == H2O_TOKEN_LOCATION) {
                if (req->res_is_delegated && (300 <= args->status && args->status <= 399) && args->status != 304) {
                    detach_client(self);
                    h2o_iovec_t method = h2o_get_redirect_method(req->method, args->status);
                    h2o_send_redirect_internal(req, method, args->headers[i].value.base, args->headers[i].value.len, 1);
                    return NULL;
                }
                if (req->overrides != NULL && req->overrides->location_rewrite.match != NULL) {
                    h2o_iovec_t new_value =
                        rewrite_location(&req->pool, value.base, value.len, req->overrides->location_rewrite.match,
                                         req->input.scheme, req->input.authority, req->overrides->location_rewrite.path_prefix);
                    if (new_value.base != NULL) {
                        value = new_value;
                        goto AddHeader;
                    }
                }
            } else if (token == H2O_TOKEN_LINK) {
                value = h2o_push_path_in_link_header(req, value.base, value.len);
                if (!value.len)
                    goto Skip;
            } else if (token == H2O_TOKEN_SERVER) {
                if (!req->conn->ctx->globalconf->proxy.preserve_server_header)
                    goto Skip;
            } else if (token == H2O_TOKEN_X_COMPRESS_HINT) {
                req->compress_hint = compress_hint_to_enum(value.base, value.len);
                goto Skip;
            } else if (token == H2O_TOKEN_DATE) {
                seen_date_header = 1;
            }
            if (args->header_requires_dup)
                value = h2o_strdup(&req->pool, value.base, value.len);
        AddHeader:
            h2o_add_header(&req->pool, &req->res.headers, token, args->headers[i].orig_name, value.base, value.len);
        Skip:;
        } else {
            h2o_iovec_t name = *args->headers[i].name;
            if (args->header_requires_dup) {
                name = h2o_strdup(&req->pool, name.base, name.len);
                value = h2o_strdup(&req->pool, value.base, value.len);
            }
            h2o_add_header_by_str(&req->pool, &req->res.headers, name.base, name.len, 0, args->headers[i].orig_name, value.base,
                                  value.len);
        }
    }

    if (!seen_date_header && emit_missing_date_header)
        h2o_resp_add_date_header(req);

    /* extended CONNECT: adjust response based on the HTTP versions being used (TODO proper check of status code based on upstream
     * HTTP version) */
    if (req->upgrade.base != NULL && (req->res.status == 101 || (200 <= req->res.status && req->res.status <= 299))) {
        assert(req->is_tunnel_req);
        if (req->version < 0x200) {
            req->res.status = 101;
            h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_UPGRADE, NULL, req->upgrade.base, req->upgrade.len);
        } else {
            req->res.status = 200;
        }
    }

    /* declare the start of the response */
    h2o_start_response(req, &self->super);

    if (errstr == h2o_httpclient_error_is_eos) {
        self->res_done = 1;
        if (self->req_done)
            detach_client(self);
        h2o_send(req, NULL, 0, H2O_SEND_STATE_FINAL);
        return NULL; /* TODO this returning NULL causes keepalive to be disabled in http1client. is this what we intended? */
    }

    /* switch to using pipe reader, if the opportunity is provided */
    if (args->pipe_reader != NULL) {
#ifdef __linux__
        if (req->conn->ctx->proxy.spare_pipes.count > 0) {
            int *src = req->conn->ctx->proxy.spare_pipes.pipes[--req->conn->ctx->proxy.spare_pipes.count];
            self->pipe_reader.fds[0] = src[0];
            self->pipe_reader.fds[1] = src[1];
        } else {
            if (pipe2(self->pipe_reader.fds, O_NONBLOCK | O_CLOEXEC) != 0) {
                char errbuf[256];
                h2o_fatal("pipe2(2) failed:%s", h2o_strerror_r(errno, errbuf, sizeof(errbuf)));
            }
        }
        args->pipe_reader->fd = self->pipe_reader.fds[1];
        args->pipe_reader->on_body_piped = on_body_piped;
#endif
    }

    /* if httpclient has no received body at this time, immediately send only headers using zero timeout */
    h2o_timer_link(req->conn->ctx->loop, 0, &self->send_headers_timeout);

    return on_body;
}

static int on_informational(h2o_httpclient_t *client, int version, int status, h2o_iovec_t msg, h2o_header_t *headers,
                            size_t num_headers)
{
    struct rp_generator_t *self = client->data;
    size_t i;

    for (i = 0; i != num_headers; ++i) {
        if (headers[i].name == &H2O_TOKEN_LINK->buf)
            h2o_push_path_in_link_header(self->src_req, headers[i].value.base, headers[i].value.len);
    }

    assert(status != 101 && "101 has to be notified as final");

    if (status == 100) {
        /* we don't need to forward 100 since protocol handlers have already done */
    } else {
        self->src_req->res.status = status;
        self->src_req->res.headers = (h2o_headers_t){headers, num_headers, num_headers};
        h2o_send_informational(self->src_req);
    }

    return 0;
}

static void proceed_request(h2o_httpclient_t *client, const char *errstr)
{
    struct rp_generator_t *self = client->data;
    if (self == NULL)
        return;
    if (errstr != NULL)
        detach_client(self);
    if (self->src_req->proceed_req != NULL)
        self->src_req->proceed_req(self->src_req, errstr);
}

static int write_req(void *ctx, int is_end_stream)
{
    struct rp_generator_t *self = ctx;
    h2o_httpclient_t *client = self->client;
    h2o_iovec_t chunk = self->src_req->entity;

    assert(chunk.len != 0 || is_end_stream);

    if (client == NULL) {
        return -1;
    }

    if (is_end_stream) {
        self->src_req->write_req.cb = NULL;
        self->req_done = 1;
        if (self->res_done)
            detach_client(self);
    }

    return client->write_req(client, chunk, is_end_stream);
}

static h2o_httpclient_head_cb on_connect(h2o_httpclient_t *client, const char *errstr, h2o_iovec_t *method, h2o_url_t *url,
                                         const h2o_header_t **headers, size_t *num_headers, h2o_iovec_t *body,
                                         h2o_httpclient_proceed_req_cb *proceed_req_cb, h2o_httpclient_properties_t *props,
                                         h2o_url_t *origin)
{
    struct rp_generator_t *self = client->data;
    h2o_req_t *req = self->src_req;
    int use_proxy_protocol = 0, reprocess_if_too_early = 0;

    copy_stats(self);

    if (errstr != NULL) {
        detach_client(self);
        h2o_req_log_error(self->src_req, "lib/core/proxy.c", "%s", errstr);
        h2o_send_error_502(self->src_req, "Gateway Error", errstr, 0);
        return NULL;
    }

    assert(origin != NULL);

    if (req->overrides != NULL) {
        use_proxy_protocol = req->overrides->use_proxy_protocol;
        props->use_expect = req->overrides->proxy_use_expect;
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
    h2o_headers_t headers_vec = (h2o_headers_t){NULL};
    build_request(req, method, url, &headers_vec, props,
                  !use_proxy_protocol && h2o_socketpool_can_keepalive(client->connpool->socketpool), self->client->upgrade_to,
                  use_proxy_protocol, &reprocess_if_too_early, origin);
    *headers = headers_vec.entries;
    *num_headers = headers_vec.size;

    if (reprocess_if_too_early)
        req->reprocess_if_too_early = 1;

    *body = h2o_iovec_init(NULL, 0);
    *proceed_req_cb = NULL;
    self->req_done = 1;
    if (self->src_req->entity.base != NULL) {
        *body = self->src_req->entity;
        if (self->src_req->proceed_req != NULL) {
            *proceed_req_cb = proceed_request;
            self->src_req->write_req.cb = write_req;
            self->src_req->write_req.ctx = self;
            self->req_done = 0;
        }
    }
    self->client->informational_cb = on_informational;

    client->get_conn_properties(client, &req->proxy_stats.conn);

    { /* indicate to httpclient if use of pipe is preferred */
        h2o_conn_t *conn = self->src_req->conn;
        switch (conn->ctx->globalconf->proxy.zerocopy) {
        case H2O_PROXY_ZEROCOPY_ALWAYS:
            props->prefer_pipe_reader = 1;
            break;
        case H2O_PROXY_ZEROCOPY_ENABLED:
            if (conn->callbacks->can_zerocopy != NULL && conn->callbacks->can_zerocopy(conn))
                props->prefer_pipe_reader = 1;
            break;
        default:
            break;
        }
    }

    return on_head;
}

static void on_generator_dispose(void *_self)
{
    struct rp_generator_t *self = _self;
    do_close(self);

    if (self->last_content_before_send != NULL) {
        h2o_buffer_dispose(&self->last_content_before_send);
    }
    h2o_doublebuffer_dispose(&self->sending);
    if (self->generator_disposed != NULL)
        *self->generator_disposed = 1;
}

static struct rp_generator_t *proxy_send_prepare(h2o_req_t *req)
{
    struct rp_generator_t *self = h2o_mem_alloc_shared(&req->pool, sizeof(*self), on_generator_dispose);

    self->super.proceed = do_proceed;
    self->super.stop = do_stop;
    self->src_req = req;
    self->generator_disposed = NULL;
    self->client = NULL; /* when connection establish timeouts, self->client remains unset by `h2o_httpclient_connect` */
    self->had_body_error = 0;
    self->up_req.is_head = h2o_memis(req->method.base, req->method.len, H2O_STRLIT("HEAD"));
    self->last_content_before_send = NULL;
    h2o_doublebuffer_init(&self->sending, &h2o_socket_buffer_prototype);
    memset(&req->proxy_stats, 0, sizeof(req->proxy_stats));
    h2o_timer_init(&self->send_headers_timeout, on_send_headers_timeout);
    self->body_bytes_read = 0;
    self->body_bytes_sent = 0;
    self->pipe_reader.fds[0] = -1;
    self->pipe_inflight = 0;
    self->req_done = 0;
    self->res_done = 0;

    return self;
}

void h2o__proxy_process_request(h2o_req_t *req)
{
    h2o_req_overrides_t *overrides = req->overrides;
    h2o_httpclient_ctx_t *client_ctx = get_client_ctx(req);
    h2o_url_t target_buf, *target = &target_buf;

    h2o_httpclient_connection_pool_t *connpool = &req->conn->ctx->proxy.connpool;
    if (overrides != NULL && overrides->connpool != NULL) {
        connpool = overrides->connpool;
        if (!overrides->proxy_preserve_host)
            target = NULL;
    }
    if (target == &target_buf && h2o_url_init(&target_buf, req->scheme, req->authority, h2o_iovec_init(H2O_STRLIT("/"))) != 0) {
        h2o_send_error_400(req, "Invalid Request", "Invalid Request", H2O_SEND_ERROR_HTTP1_CLOSE_CONNECTION);
        return;
    }

    const char *upgrade_to = NULL;
    if (req->is_tunnel_req) {
        if (req->upgrade.base != NULL) {
            /* Upgrade requests (e.g. websocket) are either tunnelled, rejected, or converted to an ordinary request depending on
             * the configuration. */
            if (client_ctx->tunnel_enabled) {
                /* Support for H3_DATAGRAM is advertised by the HTTP/3 handler but the proxy handler does not support forwarding
                 * datagrams nor conversion to/from capsules. Hence we send 421 to let the client retry using a different version of
                 * HTTP. */
                if (req->version == 0x300 && h2o_lcstris(req->upgrade.base, req->upgrade.len, H2O_STRLIT("connect-udp"))) {
                    h2o_send_error_421(req, "Misdirected Request", "connect-udp tunneling is only supported in HTTP/1 and 2", 0);
                    return;
                }
                upgrade_to = h2o_strdup(&req->pool, req->upgrade.base, req->upgrade.len).base;
            } else {
                /* When recieving a websocket request over HTTP/1.x but tunneling is disabled, convert the request to an ordinary
                 * HTTP request, as we have always done. Otherwise, refuse the request. */
                if (!(req->version < 0x200 && h2o_lcstris(req->upgrade.base, req->upgrade.len, H2O_STRLIT("websocket")))) {
                    h2o_send_error_403(req, "Forbidden", "The proxy act as a gateway.", H2O_SEND_ERROR_HTTP1_CLOSE_CONNECTION);
                    return;
                }
            }
        } else {
            /* CONNECT request; process as a CONNECT upgrade or reject */
            if (client_ctx->tunnel_enabled) {
                upgrade_to = h2o_httpclient_upgrade_to_connect;
            } else {
                h2o_send_error_405(req, "Method Not Allowed", "refusing CONNECT", H2O_SEND_ERROR_HTTP1_CLOSE_CONNECTION);
                return;
            }
        }
    }
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
    h2o_httpclient_connect(&self->client, &req->pool, self, client_ctx, connpool, target, upgrade_to, on_connect);
}
