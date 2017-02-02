/*
 * Copyright (c) 2014-2016 DeNA Co., Ltd., Kazuho Oku, Satoh Hiroh
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
#include <inttypes.h>
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
    struct timeval connected_at;
};

static void on_accept_timeout(h2o_timeout_entry_t *entry);

static struct st_h2o_accept_data_t *create_accept_data(h2o_accept_ctx_t *ctx, h2o_socket_t *sock, struct timeval connected_at)
{
    struct st_h2o_accept_data_t *data = h2o_mem_alloc(sizeof(*data));

    data->ctx = ctx;
    data->sock = sock;
    data->timeout = (h2o_timeout_entry_t){0};
    data->timeout.cb = on_accept_timeout;
    h2o_timeout_link(ctx->ctx->loop, &ctx->ctx->handshake_timeout, &data->timeout);
    data->async_resumption_get_req = NULL;
    data->connected_at = connected_at;

    sock->data = data;
    return data;
}

static void free_accept_data(struct st_h2o_accept_data_t *data)
{
    assert(data->async_resumption_get_req == NULL);
    h2o_timeout_unlink(&data->timeout);
    free(data);
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

void h2o_accept_setup_async_ssl_resumption(h2o_memcached_context_t *memc, unsigned expiration)
{
    async_resumption_context.memc = memc;
    async_resumption_context.expiration = expiration;
    h2o_socket_ssl_async_resumption_init(async_resumption_get, async_resumption_new);
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

static void on_ssl_handshake_complete(h2o_socket_t *sock, const char *err)
{
    struct st_h2o_accept_data_t *data = sock->data;
    sock->data = NULL;

    if (err != NULL) {
        h2o_socket_close(sock);
        goto Exit;
    }

    h2o_iovec_t proto = h2o_socket_ssl_get_selected_protocol(sock);
    const h2o_iovec_t *ident;
    for (ident = h2o_http2_alpn_protocols; ident->len != 0; ++ident) {
        if (proto.len == ident->len && memcmp(proto.base, ident->base, proto.len) == 0) {
            /* connect as http2 */
            h2o_http2_accept(data->ctx, sock, data->connected_at);
            goto Exit;
        }
    }
    /* connect as http1 */
    h2o_http1_accept(data->ctx, sock, data->connected_at);

Exit:
    free_accept_data(data);
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
        memset(sa, 0, sizeof(struct sockaddr_in));
        sa->sa_family = AF_INET;
        addr = &((struct sockaddr_in *)sa)->sin_addr;
        port = &((struct sockaddr_in *)sa)->sin_port;
        break;
    case '6':
        *salen = sizeof(struct sockaddr_in6);
        memset(sa, 0, sizeof(struct sockaddr_in6));
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

static void on_read_proxy_line(h2o_socket_t *sock, const char *err)
{
    struct st_h2o_accept_data_t *data = sock->data;

    if (err != NULL) {
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
        h2o_socket_ssl_handshake(sock, data->ctx->ssl_ctx, NULL, on_ssl_handshake_complete);
    } else {
        struct st_h2o_accept_data_t *data = sock->data;
        sock->data = NULL;
        h2o_http1_accept(data->ctx, sock, data->connected_at);
        free_accept_data(data);
    }
}

void h2o_accept(h2o_accept_ctx_t *ctx, h2o_socket_t *sock)
{
    struct timeval connected_at = *h2o_get_timestamp(ctx->ctx, NULL, NULL);

    if (ctx->expect_proxy_line || ctx->ssl_ctx != NULL) {
        create_accept_data(ctx, sock, connected_at);
        if (ctx->expect_proxy_line) {
            h2o_socket_read_start(sock, on_read_proxy_line);
        } else {
            h2o_socket_ssl_handshake(sock, ctx->ssl_ctx, NULL, on_ssl_handshake_complete);
        }
    } else {
        h2o_http1_accept(ctx, sock, connected_at);
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

size_t h2o_stringify_proxy_header(h2o_conn_t *conn, char *buf)
{
    struct sockaddr_storage ss;
    socklen_t sslen;
    size_t strlen;
    uint16_t peerport;
    char *dst = buf;

    if ((sslen = conn->callbacks->get_peername(conn, (void *)&ss)) == 0)
        goto Unknown;
    switch (ss.ss_family) {
    case AF_INET:
        memcpy(dst, "PROXY TCP4 ", 11);
        dst += 11;
        break;
    case AF_INET6:
        memcpy(dst, "PROXY TCP6 ", 11);
        dst += 11;
        break;
    default:
        goto Unknown;
    }
    if ((strlen = h2o_socket_getnumerichost((void *)&ss, sslen, dst)) == SIZE_MAX)
        goto Unknown;
    dst += strlen;
    *dst++ = ' ';

    peerport = h2o_socket_getport((void *)&ss);

    if ((sslen = conn->callbacks->get_sockname(conn, (void *)&ss)) == 0)
        goto Unknown;
    if ((strlen = h2o_socket_getnumerichost((void *)&ss, sslen, dst)) == SIZE_MAX)
        goto Unknown;
    dst += strlen;
    *dst++ = ' ';

    dst += sprintf(dst, "%" PRIu16 " %" PRIu16 "\r\n", peerport, (uint16_t)h2o_socket_getport((void *)&ss));

    return dst - buf;

Unknown:
    memcpy(buf, "PROXY UNKNOWN\r\n", 15);
    return 15;
}

static void push_one_path(h2o_mem_pool_t *pool, h2o_iovec_vector_t *paths_to_push, h2o_iovec_t url, h2o_iovec_t base_path,
                          const h2o_url_scheme_t *input_scheme, h2o_iovec_t input_authority, const h2o_url_scheme_t *base_scheme,
                          h2o_iovec_t *base_authority)
{
    h2o_url_t parsed, resolved;

    /* check the authority, and extract absolute path */
    if (h2o_url_parse_relative(url.base, url.len, &parsed) != 0)
        return;

    /* fast-path for abspath form */
    if (base_scheme == NULL && parsed.scheme == NULL && parsed.authority.base == NULL && url.len != 0 && url.base[0] == '/') {
        h2o_vector_reserve(pool, paths_to_push, paths_to_push->size + 1);
        paths_to_push->entries[paths_to_push->size++] = h2o_strdup(pool, url.base, url.len);
        return;
    }

    /* check scheme and authority if given URL contains either of the two, or if base is specified */
    h2o_url_t base = {input_scheme, input_authority, {NULL}, base_path, 65535};
    if (base_scheme != NULL) {
        base.scheme = base_scheme;
        base.authority = *base_authority;
    }
    h2o_url_resolve(pool, &base, &parsed, &resolved);
    if (input_scheme != resolved.scheme)
        return;
    if (!h2o_lcstris(input_authority.base, input_authority.len, resolved.authority.base, resolved.authority.len))
        return;

    h2o_vector_reserve(pool, paths_to_push, paths_to_push->size + 1);
    paths_to_push->entries[paths_to_push->size++] = resolved.path;
}

h2o_iovec_vector_t h2o_extract_push_path_from_link_header(h2o_mem_pool_t *pool, const char *value, size_t value_len,
                                                          h2o_iovec_t base_path, const h2o_url_scheme_t *input_scheme,
                                                          h2o_iovec_t input_authority, const h2o_url_scheme_t *base_scheme,
                                                          h2o_iovec_t *base_authority, h2o_iovec_t *filtered_value)
{
    h2o_iovec_vector_t paths_to_push = {NULL};
    h2o_iovec_t iter = h2o_iovec_init(value, value_len), token_value;
    const char *token;
    size_t token_len;
    *filtered_value = h2o_iovec_init(NULL, 0);

#define PUSH_FILTERED_VALUE(s, e)                                                                                                  \
    do {                                                                                                                           \
        if (filtered_value->len != 0) {                                                                                            \
            memcpy(filtered_value->base + filtered_value->len, ", ", 2);                                                           \
            filtered_value->len += 2;                                                                                              \
        }                                                                                                                          \
        memcpy(filtered_value->base + filtered_value->len, (s), (e) - (s));                                                        \
        filtered_value->len += (e) - (s);                                                                                          \
    } while (0)

    /* extract URL values from Link: </pushed.css>; rel=preload */
    do {
        if ((token = h2o_next_token(&iter, ';', &token_len, NULL)) == NULL)
            break;
        /* first element should be <URL> */
        if (!(token_len >= 2 && token[0] == '<' && token[token_len - 1] == '>'))
            break;
        h2o_iovec_t url_with_brackets = h2o_iovec_init(token, token_len);
        /* find rel=preload */
        int preload = 0, nopush = 0, push_only = 0;
        while ((token = h2o_next_token(&iter, ';', &token_len, &token_value)) != NULL &&
               !h2o_memis(token, token_len, H2O_STRLIT(","))) {
            if (h2o_lcstris(token, token_len, H2O_STRLIT("rel")) &&
                h2o_lcstris(token_value.base, token_value.len, H2O_STRLIT("preload"))) {
                preload++;
            } else if (h2o_lcstris(token, token_len, H2O_STRLIT("nopush"))) {
                nopush++;
            } else if (h2o_lcstris(token, token_len, H2O_STRLIT("x-http2-push-only"))) {
                push_only++;
            }
        }
        /* push the path */
        if (!nopush && preload)
            push_one_path(pool, &paths_to_push, h2o_iovec_init(url_with_brackets.base + 1, url_with_brackets.len - 2), base_path,
                          input_scheme, input_authority, base_scheme, base_authority);
        /* store the elements that needs to be preserved to filtered_value */
        if (push_only) {
            if (filtered_value->base == NULL) {
                /* the max. size of filtered_value would be x2 in the worst case, when "," is converted to ", " */
                filtered_value->base = h2o_mem_alloc_pool(pool, value_len * 2);
                const char *prev_comma = h2o_memrchr(value, ',', url_with_brackets.base - value);
                if (prev_comma != NULL)
                    PUSH_FILTERED_VALUE(value, prev_comma);
            }
        } else if (filtered_value->base != NULL) {
            PUSH_FILTERED_VALUE(url_with_brackets.base, token != NULL ? token : value + value_len);
        }
    } while (token != NULL);

    if (filtered_value->base != NULL) {
        if (token != NULL)
            PUSH_FILTERED_VALUE(token, value + value_len);
    } else {
        *filtered_value = h2o_iovec_init(value, value_len);
    }

    return paths_to_push;

#undef PUSH_FILTERED_VALUE
}

int h2o_get_compressible_types(const h2o_headers_t *headers)
{
    size_t header_index;
    int compressible_types = 0;

    for (header_index = 0; header_index != headers->size; ++header_index) {
        const h2o_header_t *header = headers->entries + header_index;
        if (H2O_UNLIKELY(header->name == &H2O_TOKEN_ACCEPT_ENCODING->buf)) {
            h2o_iovec_t iter = h2o_iovec_init(header->value.base, header->value.len);
            const char *token = NULL;
            size_t token_len = 0;
            while ((token = h2o_next_token(&iter, ',', &token_len, NULL)) != NULL) {
                if (h2o_lcstris(token, token_len, H2O_STRLIT("gzip")))
                    compressible_types |= H2O_COMPRESSIBLE_GZIP;
                else if (h2o_lcstris(token, token_len, H2O_STRLIT("br")))
                    compressible_types |= H2O_COMPRESSIBLE_BROTLI;
            }
        }
    }

    return compressible_types;
}

h2o_iovec_t h2o_build_destination(h2o_req_t *req, const char *prefix, size_t prefix_len, int use_path_normalized)
{
    h2o_iovec_t parts[4];
    size_t num_parts = 0;
    int conf_ends_with_slash = req->pathconf->path.base[req->pathconf->path.len - 1] == '/';
    int prefix_ends_with_slash = prefix[prefix_len - 1] == '/';

    /* destination starts with given prefix */
    parts[num_parts++] = h2o_iovec_init(prefix, prefix_len);

    /* make adjustments depending on the trailing slashes */
    if (conf_ends_with_slash != prefix_ends_with_slash) {
        if (conf_ends_with_slash) {
            parts[num_parts++] = h2o_iovec_init(H2O_STRLIT("/"));
        } else {
            if (req->path_normalized.len != req->pathconf->path.len)
                parts[num_parts - 1].len -= 1;
        }
    }

    /* append suffix path and query */

    if (use_path_normalized) {
        parts[num_parts++] = h2o_uri_escape(&req->pool, req->path_normalized.base + req->pathconf->path.len,
                                            req->path_normalized.len - req->pathconf->path.len, "/@:");
        if (req->query_at != SIZE_MAX) {
            parts[num_parts++] = h2o_iovec_init(req->path.base + req->query_at, req->path.len - req->query_at);
        }
    } else {
        if (req->path.len > 1) {
            /*
             * When proxying, we want to modify the input URL as little
             * as possible. We use norm_indexes to find the start of
             * the path we want to forward.
             */
            size_t next_unnormalized;
            if (req->norm_indexes && req->pathconf->path.len > 1) {
                next_unnormalized = req->norm_indexes[req->pathconf->path.len - 1];
            } else {
                next_unnormalized = req->pathconf->path.len;
            }

            /*
             * Special case: the input path didn't have any '/' including the first,
             * so the first character is actually found at '0'
             */
            if (req->path.base[0] != '/' && next_unnormalized == 1) {
                next_unnormalized = 0;
            }
            parts[num_parts++] = (h2o_iovec_t){req->path.base + next_unnormalized, req->path.len - next_unnormalized};
        }
    }

    return h2o_concat_list(&req->pool, parts, num_parts);
}

/* h2-14 and h2-16 are kept for backwards compatibility, as they are often used */
#define ALPN_ENTRY(s)                                                                                                              \
    {                                                                                                                              \
        H2O_STRLIT(s)                                                                                                              \
    }
#define ALPN_PROTOCOLS_CORE ALPN_ENTRY("h2"), ALPN_ENTRY("h2-16"), ALPN_ENTRY("h2-14")
#define NPN_PROTOCOLS_CORE                                                                                                         \
    "\x02"                                                                                                                         \
    "h2"                                                                                                                           \
    "\x05"                                                                                                                         \
    "h2-16"                                                                                                                        \
    "\x05"                                                                                                                         \
    "h2-14"

static const h2o_iovec_t http2_alpn_protocols[] = {ALPN_PROTOCOLS_CORE, {NULL}};
const h2o_iovec_t *h2o_http2_alpn_protocols = http2_alpn_protocols;

static const h2o_iovec_t alpn_protocols[] = {ALPN_PROTOCOLS_CORE, {H2O_STRLIT("http/1.1")}, {NULL}};
const h2o_iovec_t *h2o_alpn_protocols = alpn_protocols;

const char *h2o_http2_npn_protocols = NPN_PROTOCOLS_CORE;
const char *h2o_npn_protocols = NPN_PROTOCOLS_CORE "\x08"
                                                   "http/1.1";

uint64_t h2o_connection_id = 0;
