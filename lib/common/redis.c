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
#include "async.h"
#include "h2o/redis.h"
#include "h2o/socket.h"

static void attach_loop(redisAsyncContext* ac, h2o_loop_t* loop);

struct st_h2o_redis_conn_t {
    h2o_loop_t *loop;
    redisAsyncContext *redis;
    h2o_redis_callbacks_t cb;
    void *cb_data;
    h2o_redis_connection_state_t state;
};

struct st_h2o_redis_callback_args_t {
    h2o_redis_command_cb cb;
    void *data;
};

static void on_command(redisAsyncContext *redis, void *reply, void *privdata)
{
    struct st_h2o_redis_callback_args_t *args = (struct st_h2o_redis_callback_args_t *)privdata;
    if (args != NULL) {
        args->cb((redisReply *)reply, args->data);
        free(args);
    }
}

void h2o_redis_command(h2o_redis_conn_t *conn, h2o_redis_command_cb cb, void *cb_data, const char *format, ...)
{
    if (conn->state == H2O_REDIS_CONNECTION_STATE_CLOSED) {
        if (cb) {
            cb(NULL, cb_data);
        }
        return;
    }

    struct st_h2o_redis_callback_args_t *args = NULL;
    if (cb != NULL) {
        args = h2o_mem_alloc(sizeof(struct st_h2o_redis_callback_args_t));
        args->cb = cb;
        args->data = cb_data;
    }

    va_list ap;
    va_start(ap, format);
    if (redisvAsyncCommand(conn->redis, on_command, args, format, ap) != REDIS_OK) {
        /* the case that redisAsyncContext is disconnecting or freeing */
        /* call the callback immediately with NULL reply */
        on_command(conn->redis, NULL, args);
    }
    va_end(ap);
}

static void on_redis_connect(const redisAsyncContext *redis, int status)
{
    h2o_redis_conn_t *conn = (h2o_redis_conn_t *)redis->data;
    if (status == REDIS_OK) {
        conn->state = H2O_REDIS_CONNECTION_STATE_CONNECTED;
        if (conn->cb.on_connect != NULL) {
            conn->cb.on_connect(conn->cb_data);
        }
    } else {
        conn->state = H2O_REDIS_CONNECTION_STATE_CLOSED;
        conn->redis = NULL;
        if (conn->cb.on_close != NULL) {
            conn->cb.on_close(redis->errstr, conn->cb_data);
        }
    }
}

static void on_redis_disconnect(const redisAsyncContext *redis, int status)
{
    h2o_redis_conn_t *conn = (h2o_redis_conn_t *)redis->data;
    conn->state = H2O_REDIS_CONNECTION_STATE_CLOSED;
    conn->redis = NULL;
    if (conn->cb.on_close != NULL) {
        conn->cb.on_close(redis->errstr, conn->cb_data);
    }
}

h2o_redis_conn_t *h2o_redis_create_connection(h2o_loop_t *loop, h2o_redis_callbacks_t cb, void *cb_data)
{
    h2o_redis_conn_t *conn = h2o_mem_alloc(sizeof(*conn));
    *conn = (h2o_redis_conn_t){NULL};

    conn->loop = loop;
    conn->cb = cb;
    conn->cb_data = cb_data;
    conn->state = H2O_REDIS_CONNECTION_STATE_CLOSED;

    return conn;
}

void h2o_redis_connect(h2o_redis_conn_t *conn, const char *host, uint16_t port)
{
    redisAsyncContext *redis = redisAsyncConnect(host, port);
    if (redis == NULL) {
        h2o_fatal("no memory");
    }

    if (redis->err != REDIS_OK) {
        /* some connection failures can be detected at this time */
        if (conn->cb.on_close != NULL) {
            conn->cb.on_close(redis->errstr, conn->cb_data);
        }
        redisAsyncFree(redis);
        return;
    }

    attach_loop(redis, conn->loop);
    redisAsyncSetConnectCallback(redis, on_redis_connect);
    redisAsyncSetDisconnectCallback(redis, on_redis_disconnect);
    conn->redis = redis;
    conn->redis->data = conn;
    conn->state = H2O_REDIS_CONNECTION_STATE_CONNECTING;
}

void h2o_redis_disconnect(h2o_redis_conn_t *conn)
{
    if (conn->state != H2O_REDIS_CONNECTION_STATE_CLOSED) {
        assert(conn->redis != NULL);
        conn->state = H2O_REDIS_CONNECTION_STATE_CLOSED;
        redisAsyncDisconnect(conn->redis);
    }
}

void h2o_redis_free(h2o_redis_conn_t *conn)
{
    if (conn->state != H2O_REDIS_CONNECTION_STATE_CLOSED) {
        assert(conn->redis != NULL);
        redisAsyncDisconnect(conn->redis);
    }
    free(conn);
}

h2o_redis_connection_state_t h2o_redis_get_connection_state(h2o_redis_conn_t *conn)
{
    return conn->state;
}

/* redis socket adapter */

struct st_redis_socket_data_t {
    redisAsyncContext *context;
    h2o_socket_t *socket;
};

static void on_read(h2o_socket_t* sock, const char *err)
{
    struct st_redis_socket_data_t *p = (struct st_redis_socket_data_t *)sock->data;
    redisAsyncHandleRead(p->context);
}

static void on_write(h2o_socket_t *sock, const char *err)
{
    struct st_redis_socket_data_t *p = (struct st_redis_socket_data_t *)sock->data;
    redisAsyncHandleWrite(p->context);
}

static void socket_add_read(void *privdata) {
    struct st_redis_socket_data_t *p = (struct st_redis_socket_data_t *)privdata;
    h2o_socket_read_start(p->socket, on_read);
}


static void socket_del_read(void *privdata) {
    struct st_redis_socket_data_t *p = (struct st_redis_socket_data_t *)privdata;
    h2o_socket_read_stop(p->socket);
}


static void socket_add_write(void *privdata) {
    struct st_redis_socket_data_t *p = (struct st_redis_socket_data_t *)privdata;
    if (! h2o_socket_is_writing(p->socket)) {
        h2o_socket_notify_write(p->socket, on_write);
    }
}

static void socket_cleanup(void *privdata) {
    struct st_redis_socket_data_t *p = (struct st_redis_socket_data_t *)privdata;
    h2o_socket_close(p->socket);
    p->context->c.fd = -1; /* prevent hiredis from closing fd twice */
    free(p);
}

static void attach_loop(redisAsyncContext* ac, h2o_loop_t* loop) {
    redisContext *c = &(ac->c);

    struct st_redis_socket_data_t *p = h2o_mem_alloc(sizeof(*p));
    *p = (struct st_redis_socket_data_t){NULL};

    ac->ev.addRead  = socket_add_read;
    ac->ev.delRead  = socket_del_read;
    ac->ev.addWrite = socket_add_write;
    ac->ev.cleanup  = socket_cleanup;
    ac->ev.data = p;

#if H2O_USE_LIBUV
    p->socket = h2o_uv__poll_create(loop, c->fd, (uv_close_cb)free);
#else
    p->socket = h2o_evloop_socket_create(loop, c->fd, H2O_SOCKET_FLAG_DONT_READ);
#endif

    p->socket->data = p;
    p->context = ac;
}
