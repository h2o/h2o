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
#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "h2o.h"
#include "h2o/http1.h"
#include "h2o/http2.h"

struct st_h2o_accept_data_t {
    h2o_accept_ctx_t *ctx;
    h2o_socket_t *sock;
    h2o_timeout_entry_t timeout;
    h2o_memcached_req_t *async_resumption_get_req;
};

static void on_accept_timeout(h2o_timeout_entry_t *entry);

static struct st_h2o_accept_data_t *create_accept_data(h2o_accept_ctx_t *ctx, h2o_socket_t *sock)
{
    struct st_h2o_accept_data_t *data = h2o_mem_alloc(sizeof(*data));

    data->ctx = ctx;
    data->sock = sock;
    data->timeout = (h2o_timeout_entry_t){};
    data->timeout.cb = on_accept_timeout;
    h2o_timeout_link(ctx->ctx->loop, &ctx->ctx->handshake_timeout, &data->timeout);
    data->async_resumption_get_req = NULL;

    sock->data = data;
    return data;
}

static h2o_accept_ctx_t *free_accept_data(struct st_h2o_accept_data_t *data)
{
    h2o_accept_ctx_t *ctx = data->ctx;
    assert(data->async_resumption_get_req == NULL);
    h2o_timeout_unlink(&data->timeout);
    free(data);
    return ctx;
}

static struct {
    h2o_memcached_context_t *memc;
    unsigned expiration;
} async_resumption_context;

static void async_resumption_on_get(h2o_iovec_t session_data, void *_accept_data)
{
    struct st_h2o_accept_data_t *accept_data = _accept_data;
    accept_data->async_resumption_get_req = NULL;
    h2o_socket_ssl_resume_server_handshake(accept_data->sock, session_data);
}

static void async_resumption_get(h2o_socket_t *sock, h2o_iovec_t session_id)
{
    struct st_h2o_accept_data_t *data = sock->data;

    data->async_resumption_get_req =
        h2o_memcached_get(async_resumption_context.memc, data->ctx->libmemcached_receiver, session_id, async_resumption_on_get,
                          data, H2O_MEMCACHED_ENCODE_KEY | H2O_MEMCACHED_ENCODE_VALUE);
}

static void async_resumption_new(h2o_iovec_t session_id, h2o_iovec_t session_data)
{
    h2o_memcached_set(async_resumption_context.memc, session_id, session_data,
                      (uint32_t)time(NULL) + async_resumption_context.expiration,
                      H2O_MEMCACHED_ENCODE_KEY | H2O_MEMCACHED_ENCODE_VALUE);
}

static void async_resumption_remove(h2o_iovec_t session_id)
{
    h2o_memcached_delete(async_resumption_context.memc, session_id, H2O_MEMCACHED_ENCODE_KEY);
}

void h2o_accept_setup_async_ssl_resumption(h2o_memcached_context_t *memc, unsigned expiration)
{
    async_resumption_context.memc = memc;
    async_resumption_context.expiration = expiration;
    h2o_socket_ssl_async_resumption_init(async_resumption_get, async_resumption_new, async_resumption_remove);
}

void on_accept_timeout(h2o_timeout_entry_t *entry)
{
    /* TODO log */
    struct st_h2o_accept_data_t *data = H2O_STRUCT_FROM_MEMBER(struct st_h2o_accept_data_t, timeout, entry);
    if (data->async_resumption_get_req != NULL) {
        h2o_memcached_cancel_get(async_resumption_context.memc, data->async_resumption_get_req);
        data->async_resumption_get_req = NULL;
    }
    h2o_socket_t *sock = data->sock;
    free_accept_data(data);
    h2o_socket_close(sock);
}

static void on_ssl_handshake_complete(h2o_socket_t *sock, int status)
{
    h2o_accept_ctx_t *ctx = free_accept_data(sock->data);
    sock->data = NULL;

    if (status != 0) {
        h2o_socket_close(sock);
        return;
    }

    h2o_iovec_t proto = h2o_socket_ssl_get_selected_protocol(sock);
    const h2o_iovec_t *ident;
    for (ident = h2o_http2_alpn_protocols; ident->len != 0; ++ident) {
        if (proto.len == ident->len && memcmp(proto.base, ident->base, proto.len) == 0) {
            goto Is_Http2;
        }
    }
    /* connect as http1 */
    h2o_http1_accept(ctx, sock);
    return;

Is_Http2:
    /* connect as http2 */
    h2o_http2_accept(ctx, sock);
}

static ssize_t parse_proxy_line(char *src, size_t len, struct sockaddr *sa, socklen_t *salen)
{
#define CHECK_EOF()                                                                                                                \
    if (p == end)                                                                                                                  \
    return -2
#define EXPECT_CHAR(ch)                                                                                                            \
    do {                                                                                                                           \
        CHECK_EOF();                                                                                                               \
        if (*p++ != ch)                                                                                                            \
            return -1;                                                                                                             \
    } while (0)
#define SKIP_TO_WS()                                                                                                               \
    do {                                                                                                                           \
        do {                                                                                                                       \
            CHECK_EOF();                                                                                                           \
        } while (*p++ != ' ');                                                                                                     \
        --p;                                                                                                                       \
    } while (0)

    char *p = src, *end = p + len;
    void *addr;
    in_port_t *port;

    /* "PROXY "*/
    EXPECT_CHAR('P');
    EXPECT_CHAR('R');
    EXPECT_CHAR('O');
    EXPECT_CHAR('X');
    EXPECT_CHAR('Y');
    EXPECT_CHAR(' ');

    /* "TCP[46] " */
    CHECK_EOF();
    if (*p++ != 'T') {
        *salen = 0; /* indicate that no data has been obtained */
        goto SkipToEOL;
    }
    EXPECT_CHAR('C');
    EXPECT_CHAR('P');
    CHECK_EOF();
    switch (*p++) {
    case '4':
        *salen = sizeof(struct sockaddr_in);
        *((struct sockaddr_in *)sa) = (struct sockaddr_in){};
        sa->sa_family = AF_INET;
        addr = &((struct sockaddr_in *)sa)->sin_addr;
        port = &((struct sockaddr_in *)sa)->sin_port;
        break;
    case '6':
        *salen = sizeof(struct sockaddr_in6);
        *((struct sockaddr_in6 *)sa) = (struct sockaddr_in6){};
        sa->sa_family = AF_INET6;
        addr = &((struct sockaddr_in6 *)sa)->sin6_addr;
        port = &((struct sockaddr_in6 *)sa)->sin6_port;
        break;
    default:
        return -1;
    }
    EXPECT_CHAR(' ');

    /* parse peer address */
    char *addr_start = p;
    SKIP_TO_WS();
    *p = '\0';
    if (inet_pton(sa->sa_family, addr_start, addr) != 1)
        return -1;
    *p++ = ' ';

    /* skip local address */
    SKIP_TO_WS();
    ++p;

    /* parse peer port */
    char *port_start = p;
    SKIP_TO_WS();
    *p = '\0';
    unsigned short usval;
    if (sscanf(port_start, "%hu", &usval) != 1)
        return -1;
    *port = htons(usval);
    *p++ = ' ';

SkipToEOL:
    do {
        CHECK_EOF();
    } while (*p++ != '\r');
    CHECK_EOF();
    if (*p++ != '\n')
        return -2;
    return p - src;

#undef CHECK_EOF
#undef EXPECT_CHAR
#undef SKIP_TO_WS
}

static void on_read_proxy_line(h2o_socket_t *sock, int status)
{
    struct st_h2o_accept_data_t *data = sock->data;

    if (status != 0) {
        free_accept_data(data);
        h2o_socket_close(sock);
        return;
    }

    struct sockaddr_storage addr;
    socklen_t addrlen;
    ssize_t r = parse_proxy_line(sock->input->bytes, sock->input->size, (void *)&addr, &addrlen);
    switch (r) {
    case -1: /* error, just pass the input to the next handler */
        break;
    case -2: /* incomplete */
        return;
    default:
        h2o_buffer_consume(&sock->input, r);
        if (addrlen != 0)
            h2o_socket_setpeername(sock, (void *)&addr, addrlen);
        break;
    }

    if (data->ctx->ssl_ctx != NULL) {
        h2o_socket_ssl_server_handshake(sock, data->ctx->ssl_ctx, on_ssl_handshake_complete);
    } else {
        h2o_accept_ctx_t *ctx = free_accept_data(data);
        sock->data = NULL;
        h2o_http1_accept(ctx, sock);
    }
}

void h2o_accept(h2o_accept_ctx_t *ctx, h2o_socket_t *sock)
{
    if (ctx->expect_proxy_line || ctx->ssl_ctx != NULL) {
        create_accept_data(ctx, sock);
        if (ctx->expect_proxy_line) {
            h2o_socket_read_start(sock, on_read_proxy_line);
        } else {
            h2o_socket_ssl_server_handshake(sock, ctx->ssl_ctx, on_ssl_handshake_complete);
        }
    } else {
        h2o_http1_accept(ctx, sock);
    }
}

size_t h2o_stringify_protocol_version(char *dst, int version)
{
    char *p = dst;

    if (version < 0x200) {
        assert(version <= 0x109);
#define PREFIX "HTTP/1."
        memcpy(p, PREFIX, sizeof(PREFIX) - 1);
        p += sizeof(PREFIX) - 1;
#undef PREFIX
        *p++ = '0' + (version & 0xff);
    } else {
#define PROTO "HTTP/2"
        memcpy(p, PROTO, sizeof(PROTO) - 1);
        p += sizeof(PROTO) - 1;
#undef PROTO
    }

    *p = '\0';
    return p - dst;
}

h2o_iovec_t h2o_extract_push_path_from_link_header(h2o_mem_pool_t *pool, const char *value, size_t value_len,
                                                   const h2o_url_scheme_t *base_scheme, h2o_iovec_t *base_authority,
                                                   h2o_iovec_t *base_path)
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

    /* return the URL found in Link header, if it is an absolute path-only URL */
    if (parsed.scheme == NULL && parsed.authority.base == NULL && url.len != 0 && url.base[0] == '/')
        return h2o_strdup(pool, url.base, url.len);

    /* check scheme and authority if given URL contains either of the two */
    h2o_url_t base = {base_scheme, *base_authority, {}, *base_path, 65535};
    h2o_url_resolve(pool, &base, &parsed, &resolved);
    if (base.scheme != resolved.scheme)
        goto None;
    if (parsed.authority.base != NULL &&
        !h2o_lcstris(base.authority.base, base.authority.len, resolved.authority.base, resolved.authority.len))
        goto None;
    return resolved.path;

None:
    return (h2o_iovec_t){};
}

/* h2-14 and h2-16 are kept for backwards compatibility, as they are often used */
#define H2O_HTTP2_ALPN_PROTOCOLS_CORE {H2O_STRLIT("h2")},{H2O_STRLIT("h2-16")},{H2O_STRLIT("h2-14")}
#define H2O_HTTP2_NPN_PROTOCOLS_CORE "\x02" "h2" "\x05" "h2-16" "\x05" "h2-14"

static const h2o_iovec_t http2_alpn_protocols[] = {H2O_HTTP2_ALPN_PROTOCOLS_CORE, {}};
const h2o_iovec_t *h2o_http2_alpn_protocols = http2_alpn_protocols;

static const h2o_iovec_t alpn_protocols[] = {H2O_HTTP2_ALPN_PROTOCOLS_CORE, {H2O_STRLIT("http/1.1")}, {}};
const h2o_iovec_t *h2o_alpn_protocols = alpn_protocols;

const char *h2o_http2_npn_protocols = H2O_HTTP2_NPN_PROTOCOLS_CORE;
const char *h2o_npn_protocols = H2O_HTTP2_NPN_PROTOCOLS_CORE "\x08"
                                                             "http/1.1";
