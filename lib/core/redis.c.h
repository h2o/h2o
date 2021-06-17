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
#include "h2o/socket.h"

#undef async_resumption_context
#define async_resumption_context redis_async_resumption_context

static struct {
    struct {
        h2o_iovec_t host;
        uint16_t port;
        h2o_iovec_t prefix;
    } redis;
    unsigned expiration;
} async_resumption_context;

struct st_h2o_redis_resumption_accept_data_t {
    struct st_h2o_accept_data_t super;
    h2o_redis_command_t *get_command;
};

static void on_redis_accept_timeout(h2o_timer_t *entry);

static struct st_h2o_accept_data_t *create_redis_accept_data(h2o_accept_ctx_t *ctx, h2o_socket_t *sock, struct timeval connected_at)
{
    struct st_h2o_redis_resumption_accept_data_t *data = (struct st_h2o_redis_resumption_accept_data_t *)create_accept_data(
        ctx, sock, connected_at, on_redis_accept_timeout, sizeof(struct st_h2o_redis_resumption_accept_data_t));
    data->get_command = NULL;
    return &data->super;
}

static void destroy_redis_accept_data(struct st_h2o_accept_data_t *_accept_data)
{
    struct st_h2o_redis_resumption_accept_data_t *accept_data = (struct st_h2o_redis_resumption_accept_data_t *)_accept_data;
    assert(accept_data->get_command == NULL);
    destroy_accept_data(&accept_data->super);
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
