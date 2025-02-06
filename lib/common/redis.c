/*
 * Copyright (c) 2016 DeNA Co., Ltd., Ichito Nagata
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
#include <errno.h>
#include "h2o.h"
#include "h2o/redis.h"
#include "h2o/hiredis_.h"
#include "h2o/socket.h"

const char h2o_redis_error_connection[] = "Connection Error";
const char h2o_redis_error_protocol[] = "Protocol Error";
const char h2o_redis_error_connect_timeout[] = "Connection Timeout";
const char h2o_redis_error_command_timeout[] = "Command Timeout";

struct st_redis_socket_data_t {
    redisAsyncContext *context;
    const char *errstr;
    h2o_socket_t *socket;
};

static void attach_loop(redisAsyncContext *ac, h2o_loop_t *loop);

static void invoke_deferred(h2o_redis_client_t *client, uint64_t tick, h2o_timer_t *entry, h2o_timer_cb cb)
{
    entry->cb = cb;
    h2o_timer_link(client->loop, tick, entry);
}

static void close_and_detach_connection(h2o_redis_client_t *client, const char *errstr)
{
    assert(client->_redis != NULL);
    client->state = H2O_REDIS_CONNECTION_STATE_CLOSED;
    if (client->on_close != NULL)
        client->on_close(errstr);

    client->_redis->data = NULL;
    client->_redis = NULL;
    h2o_timer_unlink(&client->_timeout_entry);
}

static void disconnect(h2o_redis_client_t *client, const char *errstr)
{
    assert(client->state != H2O_REDIS_CONNECTION_STATE_CLOSED);
    assert(client->_redis != NULL);

    redisAsyncContext *redis = client->_redis;
    struct st_redis_socket_data_t *data = redis->ev.data;
    data->errstr = errstr;
    close_and_detach_connection(client, errstr);
    redisAsyncFree(redis); /* immediately call all callbacks of pending commands with nil replies */
}

static const char *get_error(const redisAsyncContext *redis)
{
    switch (redis->err) {
    case REDIS_OK:
        return NULL;
    case REDIS_ERR_IO:
        /* hiredis internally checks socket error and set errno */
        if (errno == ETIMEDOUT) {
            return h2o_redis_error_connect_timeout;
        } else {
            return h2o_redis_error_connection;
        }
    case REDIS_ERR_EOF:
        return h2o_redis_error_connection;
    case REDIS_ERR_PROTOCOL:
        return h2o_redis_error_protocol;
    case REDIS_ERR_OOM:
    case REDIS_ERR_OTHER:
        return redis->errstr;
    default:
        h2o_fatal("FIXME");
    }
}

static void on_connect(const redisAsyncContext *redis, int status)
{
    h2o_redis_client_t *client = (h2o_redis_client_t *)redis->data;
    if (client == NULL)
        return;

    if (status != REDIS_OK) {
        close_and_detach_connection(client, h2o_redis_error_connection);
        return;
    }
    h2o_timer_unlink(&client->_timeout_entry);

    client->state = H2O_REDIS_CONNECTION_STATE_CONNECTED;
    if (client->on_connect != NULL)
        client->on_connect();
}

static void on_disconnect(const redisAsyncContext *redis, int status)
{
    h2o_redis_client_t *client = (h2o_redis_client_t *)redis->data;
    if (client == NULL)
        return;

    close_and_detach_connection(client, get_error(redis));
}

static void on_connect_timeout(h2o_timer_t *entry)
{
    h2o_redis_client_t *client = H2O_STRUCT_FROM_MEMBER(h2o_redis_client_t, _timeout_entry, entry);
    assert((client->_redis->c.flags & REDIS_CONNECTED) == 0);
    assert(client->state != H2O_REDIS_CONNECTION_STATE_CLOSED);

    disconnect(client, h2o_redis_error_connect_timeout);
}

h2o_redis_client_t *h2o_redis_create_client(h2o_loop_t *loop, size_t sz)
{
    h2o_redis_client_t *client = h2o_mem_alloc(sz);
    memset(client, 0, sz);

    client->loop = loop;
    client->state = H2O_REDIS_CONNECTION_STATE_CLOSED;
    h2o_timer_init(&client->_timeout_entry, on_connect_timeout);

    return client;
}

void h2o_redis_connect(h2o_redis_client_t *client, const char *host, uint16_t port)
{
    if (client->state != H2O_REDIS_CONNECTION_STATE_CLOSED) {
        return;
    }

    redisAsyncContext *redis = redisAsyncConnect(host, port);
    if (redis == NULL) {
        h2o_fatal("no memory");
    }

    client->_redis = redis;
    client->_redis->data = client;
    client->state = H2O_REDIS_CONNECTION_STATE_CONNECTING;

    attach_loop(redis, client->loop);
    redisAsyncSetConnectCallback(redis, on_connect);
    redisAsyncSetDisconnectCallback(redis, on_disconnect);

    if (redis->err != REDIS_OK) {
        /* some connection failures can be detected at this time */
        disconnect(client, h2o_redis_error_connection);
        return;
    }

    if (client->connect_timeout != 0)
        h2o_timer_link(client->loop, client->connect_timeout, &client->_timeout_entry);
}

void h2o_redis_disconnect(h2o_redis_client_t *client)
{
    if (client->state != H2O_REDIS_CONNECTION_STATE_CLOSED)
        disconnect(client, NULL);
}

static void dispose_command(h2o_redis_command_t *command)
{
    h2o_timer_unlink(&command->_command_timeout);
    free(command);
}

static void handle_reply(h2o_redis_command_t *command, redisReply *reply, const char *errstr)
{
    if (command->cb != NULL)
        command->cb(reply, command->data, errstr);

    switch (command->type) {
    case H2O_REDIS_COMMAND_TYPE_SUBSCRIBE:
    case H2O_REDIS_COMMAND_TYPE_PSUBSCRIBE:
        if (reply != NULL && reply->type == REDIS_REPLY_ARRAY) {
            char *unsub = command->type == H2O_REDIS_COMMAND_TYPE_SUBSCRIBE ? "unsubscribe" : "punsubscribe";
            if (strncasecmp(reply->element[0]->str, unsub, reply->element[0]->len) == 0) {
                dispose_command(command);
            } else {
                /* (p)subscribe commands doesn't get freed until (p)unsubscribe or disconnect */
            }
        } else {
            dispose_command(command);
        }
        break;
    default:
        dispose_command(command);
    }
}

static void on_command(redisAsyncContext *redis, void *_reply, void *privdata)
{
    redisReply *reply = (redisReply *)_reply;
    h2o_redis_command_t *command = (h2o_redis_command_t *)privdata;
    struct st_redis_socket_data_t *sockdata = redis->ev.data;
    const char *errstr = NULL;

    if (sockdata != NULL)
        errstr = sockdata->errstr;
    if (errstr == NULL)
        errstr = get_error(redis);
    handle_reply(command, reply, errstr);
}

static void on_command_timeout(h2o_timer_t *entry)
{
    h2o_redis_command_t *command = H2O_STRUCT_FROM_MEMBER(h2o_redis_command_t, _command_timeout, entry);

    /* invoke disconnect to finalize inflight commands */
    disconnect(command->client, h2o_redis_error_command_timeout);
}

static h2o_redis_command_t *create_command(h2o_redis_client_t *client, h2o_redis_command_cb cb, void *cb_data,
                                           h2o_redis_command_type_t type)
{
    h2o_redis_command_t *command = h2o_mem_alloc(sizeof(h2o_redis_command_t));
    *command = (h2o_redis_command_t){NULL};
    command->client = client;
    command->cb = cb;
    command->data = cb_data;
    command->type = type;
    h2o_timer_init(&command->_command_timeout, on_command_timeout);

    if (client->command_timeout != 0 && (type == H2O_REDIS_COMMAND_TYPE_NORMAL || type == H2O_REDIS_COMMAND_TYPE_UNSUBSCRIBE ||
                                         type == H2O_REDIS_COMMAND_TYPE_PUNSUBSCRIBE))
        h2o_timer_link(client->loop, client->command_timeout, &command->_command_timeout);

    return command;
}

static void send_command(h2o_redis_client_t *client, h2o_redis_command_t *command, const char *cmd, size_t len)
{
    if (cmd == NULL) {
        handle_reply(command, NULL, "Failed to create command");
        return;
    }

    if (client->state == H2O_REDIS_CONNECTION_STATE_CLOSED) {
        handle_reply(command, NULL, h2o_redis_error_connection);
        return;
    }

    if (command->type == H2O_REDIS_COMMAND_TYPE_MONITOR) {
        /* monitor command implementation in hiredis asynchronous API is absolutely dangerous, so don't use it! */
        handle_reply(command, NULL, "Unsupported command");
        return;
    }

    int ret = redisAsyncFormattedCommand(client->_redis, on_command, command, cmd, len);
    if (ret != REDIS_OK) {
        handle_reply(command, NULL, "Failed to send command");
    }
}

/*
  hiredis doesn't expose any information about the command, so parse here.
  this function assumes that formatted is NULL-terminated
 */
static h2o_redis_command_type_t detect_command_type(const char *formatted)
{
#define CHECK(c)                                                                                                                   \
    if (c == NULL)                                                                                                                 \
    return H2O_REDIS_COMMAND_TYPE_ERROR

    char *p = (char *)formatted;
    CHECK(p);

    assert(p[0] == '*');

    p = strchr(p, '$');
    CHECK(p);
    p = strchr(p, '\n');
    CHECK(p);
    ++p;
    CHECK(p);

#define MATCH(c, target) strncasecmp(c, target, sizeof(target) - 1) == 0
    if (MATCH(p, "subscribe\r\n"))
        return H2O_REDIS_COMMAND_TYPE_SUBSCRIBE;
    if (MATCH(p, "unsubscribe\r\n"))
        return H2O_REDIS_COMMAND_TYPE_UNSUBSCRIBE;
    if (MATCH(p, "psubscribe\r\n"))
        return H2O_REDIS_COMMAND_TYPE_PSUBSCRIBE;
    if (MATCH(p, "punsubscribe\r\n"))
        return H2O_REDIS_COMMAND_TYPE_PUNSUBSCRIBE;
    if (MATCH(p, "monitor\r\n"))
        return H2O_REDIS_COMMAND_TYPE_MONITOR;
#undef MATCH
    return H2O_REDIS_COMMAND_TYPE_NORMAL;
#undef CHECK
}

h2o_redis_command_t *h2o_redis_command(h2o_redis_client_t *client, h2o_redis_command_cb cb, void *cb_data, const char *format, ...)
{
    char *cmd;
    int len;
    va_list ap;
    va_start(ap, format);
    len = redisvFormatCommand(&cmd, format, ap);
    va_end(ap);
    if (len <= 0) {
        cmd = NULL;
        len = 0;
    }

    h2o_redis_command_t *command = create_command(client, cb, cb_data, detect_command_type(cmd));
    send_command(client, command, cmd, len);
    free(cmd);
    return command;
}

h2o_redis_command_t *h2o_redis_command_argv(h2o_redis_client_t *client, h2o_redis_command_cb cb, void *cb_data, int argc,
                                            const char **argv, const size_t *argvlen)
{
    sds sdscmd;
    int len;
    len = redisFormatSdsCommandArgv(&sdscmd, argc, argv, argvlen);
    if (len < 0) {
        sdscmd = NULL;
        len = 0;
    }

    h2o_redis_command_t *command = create_command(client, cb, cb_data, detect_command_type(sdscmd));
    send_command(client, command, sdscmd, len);
    sdsfree(sdscmd);
    return command;
}

void h2o_redis_free(h2o_redis_client_t *client)
{
    if (client->state != H2O_REDIS_CONNECTION_STATE_CLOSED)
        disconnect(client, NULL);
    h2o_timer_unlink(&client->_timeout_entry);
    free(client);
}

/* redis socket adapter */

static void on_read(h2o_socket_t *sock, const char *err)
{
    struct st_redis_socket_data_t *p = (struct st_redis_socket_data_t *)sock->data;
    redisAsyncHandleRead(p->context);
}

static void on_write(h2o_socket_t *sock, const char *err)
{
    struct st_redis_socket_data_t *p = (struct st_redis_socket_data_t *)sock->data;
    redisAsyncHandleWrite(p->context);
}

static void socket_add_read(void *privdata)
{
    struct st_redis_socket_data_t *p = (struct st_redis_socket_data_t *)privdata;
    h2o_socket_read_start(p->socket, on_read);
}

static void socket_del_read(void *privdata)
{
    struct st_redis_socket_data_t *p = (struct st_redis_socket_data_t *)privdata;
    h2o_socket_read_stop(p->socket);
}

static void socket_add_write(void *privdata)
{
    struct st_redis_socket_data_t *p = (struct st_redis_socket_data_t *)privdata;
    if (!h2o_socket_is_writing(p->socket)) {
        h2o_socket_notify_write(p->socket, on_write);
    }
}

static void socket_cleanup(void *privdata)
{
    struct st_redis_socket_data_t *p = (struct st_redis_socket_data_t *)privdata;
    h2o_socket_close(p->socket);
    p->context->c.fd = -1;      /* prevent hiredis from closing fd twice */
    p->context->ev.data = NULL; /* remove reference to `st_redis_socket_data_t` now that it is being freed */
    free(p);
}

static void attach_loop(redisAsyncContext *ac, h2o_loop_t *loop)
{
    redisContext *c = &(ac->c);

    struct st_redis_socket_data_t *p = h2o_mem_alloc(sizeof(*p));
    *p = (struct st_redis_socket_data_t){NULL};

    ac->ev.addRead = socket_add_read;
    ac->ev.delRead = socket_del_read;
    ac->ev.addWrite = socket_add_write;
    ac->ev.cleanup = socket_cleanup;
    ac->ev.data = p;

#if H2O_USE_LIBUV
    p->socket = h2o_uv__poll_create(loop, c->fd, (uv_close_cb)free);
#else
    p->socket = h2o_evloop_socket_create(loop, c->fd, H2O_SOCKET_FLAG_DONT_READ);
#endif

    p->socket->data = p;
    p->context = ac;
}

struct st_h2o_redis_resumption_accept_data_t {
    struct st_h2o_accept_data_t super;
    h2o_redis_command_t *get_command;
};

static void on_redis_accept_timeout(h2o_timer_t *entry);

static struct {
    struct {
        h2o_iovec_t host;
        uint16_t port;
        h2o_iovec_t prefix;
    } redis;
    unsigned expiration;
} async_resumption_context;

static struct st_h2o_accept_data_t *create_redis_accept_data(h2o_accept_ctx_t *ctx, h2o_socket_t *sock, struct timeval connected_at)
{
    struct st_h2o_redis_resumption_accept_data_t *data = (struct st_h2o_redis_resumption_accept_data_t *)h2o_accept_data_create(
        ctx, sock, connected_at, on_redis_accept_timeout, sizeof(struct st_h2o_redis_resumption_accept_data_t));
    data->get_command = NULL;
    return &data->super;
}

static void destroy_redis_accept_data(struct st_h2o_accept_data_t *_accept_data)
{
    struct st_h2o_redis_resumption_accept_data_t *accept_data = (struct st_h2o_redis_resumption_accept_data_t *)_accept_data;
    assert(accept_data->get_command == NULL);
    h2o_accept_data_destroy(&accept_data->super);
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
    h2o_accept_data_set_callbacks(create_redis_accept_data, destroy_redis_accept_data);
}

static void on_redis_accept_timeout(h2o_timer_t *entry)
{
    struct st_h2o_redis_resumption_accept_data_t *data =
        H2O_STRUCT_FROM_MEMBER(struct st_h2o_redis_resumption_accept_data_t, super.timeout, entry);
    if (data->get_command != NULL) {
        data->get_command->cb = NULL;
        data->get_command = NULL;
    }
    h2o_accept_data_timeout(&data->super);
}
