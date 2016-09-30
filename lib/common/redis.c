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
#include <inttypes.h>
#include <pthread.h>
#include <unistd.h>
#include "async.h"
#include "h2o/linklist.h"
#include "h2o/redis.h"
#include "h2o/string_.h"
#include "h2o/socket.h"
#include "redis/socket.c.h"

struct st_h2o_redis_conn_t {
    struct {
        h2o_redis_connect_cb on_connect;
        h2o_redis_disconnect_cb on_disconnect;
    } cb;
    redisAsyncContext *redis;
};

struct st_h2o_redis_callback_args_t {
    h2o_redis_command_cb cb;
    void *data;
};

void on_command(redisAsyncContext *redis, void *reply, void *privdata)
{
    struct st_h2o_redis_callback_args_t *args = (struct st_h2o_redis_callback_args_t *)privdata;
    if (args != NULL) {
        args->cb((redisReply *)reply, args->data);
        free(args);
    }
}

int h2o_redis_command(h2o_redis_conn_t *conn, h2o_redis_command_cb cb, void *cb_data, const char *format, ...)
{
    va_list ap;

    struct st_h2o_redis_callback_args_t *args = NULL;
    if (cb != NULL) {
        args = h2o_mem_alloc(sizeof(struct st_h2o_redis_callback_args_t));
        args->cb = cb;
        args->data = cb_data;
    }

    int ret = 0;
    va_start(ap, format);
    if (redisvAsyncCommand(conn->redis, on_command, args, format, ap) != REDIS_OK) {
        ret = -1;
    }
    va_end(ap);

    return -1;
}

static void on_redis_connect(const redisAsyncContext *redis, int status)
{
    h2o_redis_conn_t *conn = (h2o_redis_conn_t *)redis->data;
    if (conn->cb.on_connect) {
        conn->cb.on_connect(status == REDIS_OK ? NULL : redis->errstr);
    }
    if (status != REDIS_OK)
        free(conn);
}

static void on_redis_disconnect(const redisAsyncContext *redis, int status)
{
    h2o_redis_conn_t *conn = (h2o_redis_conn_t *)redis->data;
    if (conn->cb.on_disconnect) {
        conn->cb.on_disconnect(status == REDIS_OK ? NULL : redis->errstr);
    }
    free(conn);
}

h2o_redis_conn_t *h2o_redis_connect(h2o_loop_t *loop, const char *host, uint16_t port, h2o_redis_connect_cb on_connect, h2o_redis_disconnect_cb on_disconnect)
{
    h2o_redis_conn_t *conn = h2o_mem_alloc(sizeof(*conn));
    *conn = (h2o_redis_conn_t){{NULL}};

    redisAsyncContext *redis = redisAsyncConnect(host, port);
    if (redis == NULL || redis->err != REDIS_OK) {
        goto Error;
    }
    redisSocketAttach(redis, loop);

    if (redisAsyncSetConnectCallback(redis, on_redis_connect) != REDIS_OK) {
        goto Error;
    }
    if (redisAsyncSetDisconnectCallback(redis, on_redis_disconnect) != REDIS_OK) {
        goto Error;
    }

    conn->redis = redis;
    conn->cb.on_connect = on_connect;
    conn->cb.on_disconnect = on_disconnect;
    redis->data = conn;

    return conn;

Error:
    if (redis != NULL)
        redisAsyncFree(redis);
    free(conn);
    return NULL;
}

int h2o_redis_disconnect(h2o_redis_conn_t *conn)
{
    if (conn->redis == NULL) {
        return -1;
    }
    redisAsyncDisconnect(conn->redis);
    return 0;
}
