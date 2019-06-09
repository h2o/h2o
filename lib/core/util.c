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
#include "h2o/hiredis_.h"

struct st_h2o_accept_data_t {
    h2o_accept_ctx_t *ctx;
    h2o_socket_t *sock;
    h2o_timer_t timeout;
    struct timeval connected_at;
};

struct st_h2o_memcached_resumption_accept_data_t {
    struct st_h2o_accept_data_t super;
    h2o_memcached_req_t *get_req;
};

struct st_h2o_redis_resumption_accept_data_t {
    struct st_h2o_accept_data_t super;
    h2o_redis_command_t *get_command;
};

static void on_accept_timeout(h2o_timer_t *entry);
static void on_redis_accept_timeout(h2o_timer_t *entry);
static void on_memcached_accept_timeout(h2o_timer_t *entry);

static struct {
    struct {
        h2o_memcached_context_t *ctx;
    } memcached;
    struct {
        h2o_iovec_t host;
        uint16_t port;
        h2o_iovec_t prefix;
    } redis;
    unsigned expiration;
} async_resumption_context;

static struct st_h2o_accept_data_t *create_accept_data(h2o_accept_ctx_t *ctx, h2o_socket_t *sock, struct timeval connected_at,
                                                       h2o_timer_cb timeout_cb, size_t sz)
{
    struct st_h2o_accept_data_t *data = h2o_mem_alloc(sz);
    data->ctx = ctx;
    data->sock = sock;
    h2o_timer_init(&data->timeout, timeout_cb);
    h2o_timer_link(ctx->ctx->loop, ctx->ctx->globalconf->handshake_timeout, &data->timeout);
    data->connected_at = connected_at;
    return data;
}

static struct st_h2o_accept_data_t *create_default_accept_data(h2o_accept_ctx_t *ctx, h2o_socket_t *sock,
                                                               struct timeval connected_at)
{
    struct st_h2o_accept_data_t *data =
        create_accept_data(ctx, sock, connected_at, on_accept_timeout, sizeof(struct st_h2o_accept_data_t));
    return data;
}

static struct st_h2o_accept_data_t *create_redis_accept_data(h2o_accept_ctx_t *ctx, h2o_socket_t *sock, struct timeval connected_at)
{
    struct st_h2o_redis_resumption_accept_data_t *data = (struct st_h2o_redis_resumption_accept_data_t *)create_accept_data(
        ctx, sock, connected_at, on_redis_accept_timeout, sizeof(struct st_h2o_redis_resumption_accept_data_t));
    data->get_command = NULL;
    return &data->super;
}

static struct st_h2o_accept_data_t *create_memcached_accept_data(h2o_accept_ctx_t *ctx, h2o_socket_t *sock,
                                                                 struct timeval connected_at)
{
    struct st_h2o_memcached_resumption_accept_data_t *data = (struct st_h2o_memcached_resumption_accept_data_t *)create_accept_data(
        ctx, sock, connected_at, on_memcached_accept_timeout, sizeof(struct st_h2o_memcached_resumption_accept_data_t));
    data->get_req = NULL;
    return &data->super;
}

static void destroy_accept_data(struct st_h2o_accept_data_t *data)
{
    h2o_timer_unlink(&data->timeout);
    free(data);
}

static void destroy_default_accept_data(struct st_h2o_accept_data_t *_accept_data)
{
    destroy_accept_data(_accept_data);
}

static void destroy_redis_accept_data(struct st_h2o_accept_data_t *_accept_data)
{
    struct st_h2o_redis_resumption_accept_data_t *accept_data = (struct st_h2o_redis_resumption_accept_data_t *)_accept_data;
    assert(accept_data->get_command == NULL);
    destroy_accept_data(&accept_data->super);
}

static void destroy_memcached_accept_data(struct st_h2o_accept_data_t *_accept_data)
{
    struct st_h2o_memcached_resumption_accept_data_t *accept_data =
        (struct st_h2o_memcached_resumption_accept_data_t *)_accept_data;
    assert(accept_data->get_req == NULL);
    destroy_accept_data(&accept_data->super);
}

static struct {
    struct st_h2o_accept_data_t *(*create)(h2o_accept_ctx_t *ctx, h2o_socket_t *sock, struct timeval connected_at);
    void (*destroy)(struct st_h2o_accept_data_t *accept_data);
} accept_data_callbacks = {
    create_default_accept_data,
    destroy_default_accept_data,
};

static void memcached_resumption_on_get(h2o_iovec_t session_data, void *_accept_data)
{
    struct st_h2o_memcached_resumption_accept_data_t *accept_data = _accept_data;
    accept_data->get_req = NULL;
    h2o_socket_ssl_resume_server_handshake(accept_data->super.sock, session_data);
}

static void memcached_resumption_get(h2o_socket_t *sock, h2o_iovec_t session_id)
{
    struct st_h2o_memcached_resumption_accept_data_t *data = sock->data;

    data->get_req = h2o_memcached_get(async_resumption_context.memcached.ctx, data->super.ctx->libmemcached_receiver, session_id,
                                      memcached_resumption_on_get, data, H2O_MEMCACHED_ENCODE_KEY | H2O_MEMCACHED_ENCODE_VALUE);
}

static void memcached_resumption_new(h2o_socket_t *sock, h2o_iovec_t session_id, h2o_iovec_t session_data)
{
    h2o_memcached_set(async_resumption_context.memcached.ctx, session_id, session_data,
                      (uint32_t)time(NULL) + async_resumption_context.expiration,
                      H2O_MEMCACHED_ENCODE_KEY | H2O_MEMCACHED_ENCODE_VALUE);
}

void h2o_accept_setup_memcached_ssl_resumption(h2o_memcached_context_t *memc, unsigned expiration)
{
    async_resumption_context.memcached.ctx = memc;
    async_resumption_context.expiration = expiration;
    h2o_socket_ssl_async_resumption_init(memcached_resumption_get, memcached_resumption_new);
    accept_data_callbacks.create = create_memcached_accept_data;
    accept_data_callbacks.destroy = destroy_memcached_accept_data;
}

static void on_redis_connect(void)
{
    h2o_error_printf("connected to redis at %s:%" PRIu16 "\n", async_resumption_context.redis.host.base,
                     async_resumption_context.redis.port);
}

static void on_redis_close(const char *errstr)
{
    if (errstr == NULL) {
        h2o_error_printf("disconnected from redis at %s:%" PRIu16 "\n", async_resumption_context.redis.host.base,
                         async_resumption_context.redis.port);
    } else {
        h2o_error_printf("redis connection failure: %s\n", errstr);
    }
}

static void dispose_redis_connection(void *client)
{
    h2o_redis_free((h2o_redis_client_t *)client);
}

static h2o_redis_client_t *get_redis_client(h2o_context_t *ctx)
{
    static size_t key = SIZE_MAX;
    h2o_redis_client_t **client = (h2o_redis_client_t **)h2o_context_get_storage(ctx, &key, dispose_redis_connection);
    if (*client == NULL) {
        *client = h2o_redis_create_client(ctx->loop, sizeof(h2o_redis_client_t));
        (*client)->on_connect = on_redis_connect;
        (*client)->on_close = on_redis_close;
    }
    return *client;
}

#define BASE64_LENGTH(len) (((len) + 2) / 3 * 4 + 1)

static h2o_iovec_t build_redis_key(h2o_iovec_t session_id, h2o_iovec_t prefix)
{
    h2o_iovec_t key;
    key.base = h2o_mem_alloc(prefix.len + BASE64_LENGTH(session_id.len));
    if (prefix.len != 0) {
        memcpy(key.base, prefix.base, prefix.len);
    }
    key.len = prefix.len;
    key.len += h2o_base64_encode(key.base + key.len, session_id.base, session_id.len, 1);
    return key;
}

static h2o_iovec_t build_redis_value(h2o_iovec_t session_data)
{
    h2o_iovec_t value;
    value.base = h2o_mem_alloc(BASE64_LENGTH(session_data.len));
    value.len = h2o_base64_encode(value.base, session_data.base, session_data.len, 1);
    return value;
}

#undef BASE64_LENGTH

static void redis_resumption_on_get(redisReply *reply, void *_accept_data, const char *errstr)
{
    struct st_h2o_redis_resumption_accept_data_t *accept_data = _accept_data;
    accept_data->get_command = NULL;

    h2o_iovec_t session_data;
    if (reply != NULL && reply->type == REDIS_REPLY_STRING) {
        session_data = h2o_decode_base64url(NULL, reply->str, reply->len);
    } else {
        session_data = h2o_iovec_init(NULL, 0);
    }

    h2o_socket_ssl_resume_server_handshake(accept_data->super.sock, session_data);

    if (session_data.base != NULL)
        free(session_data.base);
}

static void on_redis_resumption_get_failed(h2o_timer_t *timeout_entry)
{
    struct st_h2o_redis_resumption_accept_data_t *accept_data =
        H2O_STRUCT_FROM_MEMBER(struct st_h2o_redis_resumption_accept_data_t, super.timeout, timeout_entry);
    accept_data->get_command = NULL;
    h2o_socket_ssl_resume_server_handshake(accept_data->super.sock, h2o_iovec_init(NULL, 0));
    h2o_timer_unlink(timeout_entry);
}

static void redis_resumption_get(h2o_socket_t *sock, h2o_iovec_t session_id)
{
    struct st_h2o_redis_resumption_accept_data_t *accept_data = sock->data;
    h2o_redis_client_t *client = get_redis_client(accept_data->super.ctx->ctx);

    if (client->state == H2O_REDIS_CONNECTION_STATE_CONNECTED) {
        h2o_iovec_t key = build_redis_key(session_id, async_resumption_context.redis.prefix);
        accept_data->get_command = h2o_redis_command(client, redis_resumption_on_get, accept_data, "GET %s", key.base);
        free(key.base);
    } else {
        if (client->state == H2O_REDIS_CONNECTION_STATE_CLOSED) {
            // try to connect
            h2o_redis_connect(client, async_resumption_context.redis.host.base, async_resumption_context.redis.port);
        }
        // abort resumption
        h2o_timer_unlink(&accept_data->super.timeout);
        accept_data->super.timeout.cb = on_redis_resumption_get_failed;
        h2o_timer_link(accept_data->super.ctx->ctx->loop, 0, &accept_data->super.timeout);
    }
}

static void redis_resumption_new(h2o_socket_t *sock, h2o_iovec_t session_id, h2o_iovec_t session_data)
{
    struct st_h2o_redis_resumption_accept_data_t *accept_data = sock->data;
    h2o_redis_client_t *client = get_redis_client(accept_data->super.ctx->ctx);

    if (client->state == H2O_REDIS_CONNECTION_STATE_CLOSED) {
        // try to connect
        h2o_redis_connect(client, async_resumption_context.redis.host.base, async_resumption_context.redis.port);
    }

    h2o_iovec_t key = build_redis_key(session_id, async_resumption_context.redis.prefix);
    h2o_iovec_t value = build_redis_value(session_data);
    h2o_redis_command(client, NULL, NULL, "SETEX %s %d %s", key.base, async_resumption_context.expiration * 10, value.base);
    free(key.base);
    free(value.base);
}

void h2o_accept_setup_redis_ssl_resumption(const char *host, uint16_t port, unsigned expiration, const char *prefix)
{
    async_resumption_context.redis.host = h2o_strdup(NULL, host, SIZE_MAX);
    async_resumption_context.redis.port = port;
    async_resumption_context.redis.prefix = h2o_strdup(NULL, prefix, SIZE_MAX);
    async_resumption_context.expiration = expiration;

    h2o_socket_ssl_async_resumption_init(redis_resumption_get, redis_resumption_new);

    accept_data_callbacks.create = create_redis_accept_data;
    accept_data_callbacks.destroy = destroy_redis_accept_data;
}

static void accept_timeout(struct st_h2o_accept_data_t *data)
{
    /* TODO log */
    h2o_socket_t *sock = data->sock;
    accept_data_callbacks.destroy(data);
    h2o_socket_close(sock);
}

static void on_accept_timeout(h2o_timer_t *entry)
{
    struct st_h2o_accept_data_t *data = H2O_STRUCT_FROM_MEMBER(struct st_h2o_accept_data_t, timeout, entry);
    accept_timeout(data);
}

static void on_redis_accept_timeout(h2o_timer_t *entry)
{
    struct st_h2o_redis_resumption_accept_data_t *data =
        H2O_STRUCT_FROM_MEMBER(struct st_h2o_redis_resumption_accept_data_t, super.timeout, entry);
    if (data->get_command != NULL) {
        data->get_command->cb = NULL;
        data->get_command = NULL;
    }
    accept_timeout(&data->super);
}

static void on_memcached_accept_timeout(h2o_timer_t *entry)
{
    struct st_h2o_memcached_resumption_accept_data_t *data =
        H2O_STRUCT_FROM_MEMBER(struct st_h2o_memcached_resumption_accept_data_t, super.timeout, entry);
    if (data->get_req != NULL) {
        h2o_memcached_cancel_get(async_resumption_context.memcached.ctx, data->get_req);
        data->get_req = NULL;
    }
    accept_timeout(&data->super);
}

static void on_ssl_handshake_complete(h2o_socket_t *sock, const char *err)
{
    struct st_h2o_accept_data_t *data = sock->data;
    sock->data = NULL;

    if (err != NULL) {
        ++data->ctx->ctx->ssl.errors;
        h2o_socket_close(sock);
        goto Exit;
    }

    /* stats for handshake */
    struct timeval handshake_completed_at = h2o_gettimeofday(data->ctx->ctx->loop);
    int64_t handshake_time = h2o_timeval_subtract(&data->connected_at, &handshake_completed_at);
    if (h2o_socket_get_ssl_session_reused(sock)) {
        ++data->ctx->ctx->ssl.handshake_resume;
        data->ctx->ctx->ssl.handshake_accum_time_resume += handshake_time;
    } else {
        ++data->ctx->ctx->ssl.handshake_full;
        data->ctx->ctx->ssl.handshake_accum_time_full += handshake_time;
    }

    h2o_iovec_t proto = h2o_socket_ssl_get_selected_protocol(sock);
    const h2o_iovec_t *ident;
    for (ident = h2o_http2_alpn_protocols; ident->len != 0; ++ident) {
        if (proto.len == ident->len && memcmp(proto.base, ident->base, proto.len) == 0) {
            /* connect as http2 */
            ++data->ctx->ctx->ssl.alpn_h2;
            h2o_http2_accept(data->ctx, sock, data->connected_at);
            goto Exit;
        }
    }
    /* connect as http1 */
    if (proto.len != 0)
        ++data->ctx->ctx->ssl.alpn_h1;
    h2o_http1_accept(data->ctx, sock, data->connected_at);

Exit:
    accept_data_callbacks.destroy(data);
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
        accept_data_callbacks.destroy(data);
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
        h2o_socket_ssl_handshake(sock, data->ctx->ssl_ctx, NULL, h2o_iovec_init(NULL, 0), on_ssl_handshake_complete);
    } else {
        struct st_h2o_accept_data_t *data = sock->data;
        sock->data = NULL;
        h2o_http1_accept(data->ctx, sock, data->connected_at);
        accept_data_callbacks.destroy(data);
    }
}

void h2o_accept(h2o_accept_ctx_t *ctx, h2o_socket_t *sock)
{
    struct timeval connected_at = h2o_gettimeofday(ctx->ctx->loop);

    if (ctx->expect_proxy_line || ctx->ssl_ctx != NULL) {
        sock->data = accept_data_callbacks.create(ctx, sock, connected_at);
        if (ctx->expect_proxy_line) {
            h2o_socket_read_start(sock, on_read_proxy_line);
        } else {
            h2o_socket_ssl_handshake(sock, ctx->ssl_ctx, NULL, h2o_iovec_init(NULL, 0), on_ssl_handshake_complete);
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

static h2o_iovec_t to_push_path(h2o_mem_pool_t *pool, h2o_iovec_t url, h2o_iovec_t base_path, const h2o_url_scheme_t *input_scheme,
                                h2o_iovec_t input_authority, const h2o_url_scheme_t *base_scheme, h2o_iovec_t *base_authority,
                                int allow_cross_origin_push)
{
    h2o_url_t parsed, resolved;

    /* check the authority, and extract absolute path */
    if (h2o_url_parse_relative(url.base, url.len, &parsed) != 0)
        goto Invalid;

    /* fast-path for abspath form */
    if (base_scheme == NULL && parsed.scheme == NULL && parsed.authority.base == NULL && url.len != 0 && url.base[0] == '/') {
        return h2o_strdup(pool, url.base, url.len);
    }

    /* check scheme and authority if given URL contains either of the two, or if base is specified */
    h2o_url_t base = {input_scheme, input_authority, {NULL}, base_path, 65535};
    if (base_scheme != NULL) {
        base.scheme = base_scheme;
        base.authority = *base_authority;
    }
    h2o_url_resolve(pool, &base, &parsed, &resolved);
    if (input_scheme != resolved.scheme)
        goto Invalid;
    if (!allow_cross_origin_push &&
        !h2o_lcstris(input_authority.base, input_authority.len, resolved.authority.base, resolved.authority.len))
        goto Invalid;

    return resolved.path;

Invalid:
    return h2o_iovec_init(NULL, 0);
}

void h2o_extract_push_path_from_link_header(h2o_mem_pool_t *pool, const char *value, size_t value_len, h2o_iovec_t base_path,
                                            const h2o_url_scheme_t *input_scheme, h2o_iovec_t input_authority,
                                            const h2o_url_scheme_t *base_scheme, h2o_iovec_t *base_authority,
                                            void (*cb)(void *ctx, const char *path, size_t path_len, int is_critical), void *cb_ctx,
                                            h2o_iovec_t *filtered_value, int allow_cross_origin_push)
{
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
        int preload = 0, nopush = 0, push_only = 0, critical = 0;
        while ((token = h2o_next_token(&iter, ';', &token_len, &token_value)) != NULL &&
               !h2o_memis(token, token_len, H2O_STRLIT(","))) {
            if (h2o_lcstris(token, token_len, H2O_STRLIT("rel")) &&
                h2o_lcstris(token_value.base, token_value.len, H2O_STRLIT("preload"))) {
                preload = 1;
            } else if (h2o_lcstris(token, token_len, H2O_STRLIT("nopush"))) {
                nopush = 1;
            } else if (h2o_lcstris(token, token_len, H2O_STRLIT("x-http2-push-only"))) {
                push_only = 1;
            } else if (h2o_lcstris(token, token_len, H2O_STRLIT("critical"))) {
                critical = 1;
            }
        }
        /* push the path */
        if (!nopush && preload) {
            h2o_iovec_t path = to_push_path(pool, h2o_iovec_init(url_with_brackets.base + 1, url_with_brackets.len - 2), base_path,
                                            input_scheme, input_authority, base_scheme, base_authority, allow_cross_origin_push);
            if (path.len != 0)
                (*cb)(cb_ctx, path.base, path.len, critical);
        }
        /* store the elements that needs to be preserved to filtered_value */
        if (push_only) {
            if (filtered_value->base == NULL) {
                /* the max. size of filtered_value would be x2 in the worst case, when "," is converted to ", " */
                filtered_value->base = h2o_mem_alloc_pool(pool, char, value_len * 2);
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
    int conf_ends_with_slash = req->pathconf->path.base[req->pathconf->path.len - 1] == '/', prefix_ends_with_slash;

    /* destination starts with given prefix, if any */
    if (prefix_len != 0) {
        parts[num_parts++] = h2o_iovec_init(prefix, prefix_len);
        prefix_ends_with_slash = prefix[prefix_len - 1] == '/';
    } else {
        prefix_ends_with_slash = 0;
    }

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

#define SERVER_TIMING_DURATION_LONGEST_STR "dur=" H2O_INT32_LONGEST_STR ".000"

size_t stringify_duration(char *buf, int64_t usec)
{
    int32_t msec = (int32_t)(usec / 1000);
    usec -= ((int64_t)msec * 1000);
    char *pos = buf;
    pos += sprintf(pos, "dur=%" PRId32, msec);
    if (usec != 0) {
        *pos++ = '.';
        int denom;
        for (denom = 100; denom != 0; denom /= 10) {
            int d = (int)usec / denom;
            *pos++ = '0' + d;
            usec -= d * denom;
            if (usec == 0)
                break;
        }
    }
    return pos - buf;
}

#define DELIMITER ", "
#define ELEMENT_LONGEST_STR(name) name "; " SERVER_TIMING_DURATION_LONGEST_STR

static void emit_server_timing_element(h2o_req_t *req, h2o_iovec_t *dst, const char *name,
                                       int (*compute_func)(h2o_req_t *, int64_t *), size_t max_len)
{
    int64_t usec;
    if (compute_func(req, &usec) == 0)
        return;
    if (dst->len == 0) {
        if (max_len != SIZE_MAX)
            dst->base = h2o_mem_alloc_pool(&req->pool, *dst->base, max_len);
    } else {
        dst->base[dst->len++] = ',';
        dst->base[dst->len++] = ' ';
    }
    size_t name_len = strlen(name);
    memcpy(dst->base + dst->len, name, name_len);
    dst->len += name_len;
    dst->base[dst->len++] = ';';
    dst->base[dst->len++] = ' ';
    dst->len += stringify_duration(dst->base + dst->len, usec);
}

void h2o_add_server_timing_header(h2o_req_t *req, int uses_trailer)
{
    /* caller needs to make sure that trailers can be used */
    if (0x101 <= req->version && req->version < 0x200)
        assert(req->content_length == SIZE_MAX);

    /* emit timings */
    h2o_iovec_t dst = {NULL};

#define LONGEST_STR                                                                                                                \
    ELEMENT_LONGEST_STR("connect")                                                                                                 \
    DELIMITER ELEMENT_LONGEST_STR("request-header") DELIMITER ELEMENT_LONGEST_STR("request-body")                                  \
        DELIMITER ELEMENT_LONGEST_STR("request-total") DELIMITER ELEMENT_LONGEST_STR("process")                                    \
            DELIMITER ELEMENT_LONGEST_STR("proxy-idle") DELIMITER ELEMENT_LONGEST_STR("proxy-connect")                             \
                DELIMITER ELEMENT_LONGEST_STR("proxy-request") DELIMITER ELEMENT_LONGEST_STR("proxy-process")
    size_t max_len = sizeof(LONGEST_STR) - 1;

    if ((req->send_server_timing & H2O_SEND_SERVER_TIMING_BASIC) != 0) {
        emit_server_timing_element(req, &dst, "connect", h2o_time_compute_connect_time, max_len);
        emit_server_timing_element(req, &dst, "request-header", h2o_time_compute_header_time, max_len);
        emit_server_timing_element(req, &dst, "request-body", h2o_time_compute_body_time, max_len);
        emit_server_timing_element(req, &dst, "request-total", h2o_time_compute_request_total_time, max_len);
        emit_server_timing_element(req, &dst, "process", h2o_time_compute_process_time, max_len);
    }
    if ((req->send_server_timing & H2O_SEND_SERVER_TIMING_PROXY) != 0) {
        emit_server_timing_element(req, &dst, "proxy-idle", h2o_time_compute_proxy_idle_time, max_len);
        emit_server_timing_element(req, &dst, "proxy-connect", h2o_time_compute_proxy_connect_time, max_len);
        emit_server_timing_element(req, &dst, "proxy-request", h2o_time_compute_proxy_request_time, max_len);
        emit_server_timing_element(req, &dst, "proxy-process", h2o_time_compute_proxy_process_time, max_len);
    }

#undef LONGEST_STR

    if (uses_trailer)
        h2o_add_header_by_str(&req->pool, &req->res.headers, H2O_STRLIT("trailer"), 0, NULL, H2O_STRLIT("server-timing"));
    if (dst.len != 0)
        h2o_add_header_by_str(&req->pool, &req->res.headers, H2O_STRLIT("server-timing"), 0, NULL, dst.base, dst.len);
}

h2o_iovec_t h2o_build_server_timing_trailer(h2o_req_t *req, const char *prefix, size_t prefix_len, const char *suffix,
                                            size_t suffix_len)
{
    h2o_iovec_t value;

#define LONGEST_STR                                                                                                                \
    ELEMENT_LONGEST_STR("response")                                                                                                \
    DELIMITER ELEMENT_LONGEST_STR("total") DELIMITER ELEMENT_LONGEST_STR("proxy-response")                                         \
        DELIMITER ELEMENT_LONGEST_STR("proxy-total")

    value.base = h2o_mem_alloc_pool(&req->pool, *value.base, prefix_len + suffix_len + sizeof(LONGEST_STR) - 1);
    value.len = 0;

    if (prefix_len != 0) {
        memcpy(value.base + value.len, prefix, prefix_len);
        value.len += prefix_len;
    }

    h2o_iovec_t dst = h2o_iovec_init(value.base + value.len, 0);

    if ((req->send_server_timing & H2O_SEND_SERVER_TIMING_BASIC) != 0) {
        emit_server_timing_element(req, &dst, "response", h2o_time_compute_response_time, SIZE_MAX);
        emit_server_timing_element(req, &dst, "total", h2o_time_compute_total_time, SIZE_MAX);
    }
    if ((req->send_server_timing & H2O_SEND_SERVER_TIMING_PROXY) != 0) {
        emit_server_timing_element(req, &dst, "proxy-response", h2o_time_compute_proxy_response_time, SIZE_MAX);
        emit_server_timing_element(req, &dst, "proxy-total", h2o_time_compute_proxy_total_time, SIZE_MAX);
    }

    if (dst.len == 0)
        return h2o_iovec_init(NULL, 0);
    value.len += dst.len;

    if (suffix_len != 0) {
        memcpy(value.base + value.len, suffix, suffix_len);
        value.len += suffix_len;
    }

    return value;

#undef LONGEST_STR
}

#undef ELEMENT_LONGEST_STR
#undef DELIMITER

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

const h2o_iovec_t h2o_http2_alpn_protocols[] = {ALPN_PROTOCOLS_CORE, {NULL}};
const h2o_iovec_t h2o_alpn_protocols[] = {ALPN_PROTOCOLS_CORE, ALPN_ENTRY("http/1.1"), {NULL}};

const char h2o_http2_npn_protocols[] = NPN_PROTOCOLS_CORE;
const char h2o_npn_protocols[] = NPN_PROTOCOLS_CORE "\x08"
                                                    "http/1.1";

uint64_t h2o_connection_id = 0;

void h2o_cleanup_thread(void)
{
    h2o_mem_clear_recycle(&h2o_mem_pool_allocator);
    h2o_mem_clear_recycle(&h2o_http2_wbuf_buffer_prototype.allocator);
    h2o_mem_clear_recycle(&h2o_socket_buffer_prototype.allocator);
}
