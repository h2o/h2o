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

#if H2O_USE_LIBUV
#include "libuv.h"
#else
#include "redis/evloop.c.h"
#endif

struct st_h2o_redis_context_t {
    char *host;
    uint16_t port;
    h2o_loop_t *loop;
    struct {
        h2o_redis_connect_cb connect;
        h2o_redis_disconnect_cb disconnect;
    } cb;
    redisAsyncContext *redis;
};

struct st_h2o_redis_callback_args_t {
    h2o_redis_command_cb cb;
    void *data;
};

void on_command(redisAsyncContext *redis, void *reply, void *privdata)
{
    h2o_redis_context_t *ctx = (h2o_redis_context_t *)redis->data;
    struct st_h2o_redis_callback_args_t *args = (struct st_h2o_redis_callback_args_t *)privdata;
    if (args != NULL) {
        args->cb(ctx, (redisReply *)reply, args->data);
        free(args);
    }
}

int h2o_redis_command(h2o_redis_context_t *ctx, h2o_redis_command_cb cb, void *cb_data, const char *format, ...)
{
    if (ctx->redis == NULL) {
        return -1;
    }

    va_list ap;

    struct st_h2o_redis_callback_args_t *args = NULL;
    if (cb != NULL) {
        args = h2o_mem_alloc(sizeof(struct st_h2o_redis_callback_args_t));
        args->cb = cb;
        args->data = cb_data;
    }

    int ret = 0;
    va_start(ap, format);
    if (redisvAsyncCommand(ctx->redis, on_command, args, format, ap) != REDIS_OK) {
        ret = -1;
    }
    va_end(ap);

    return -1;
}

static void on_redis_connect(const redisAsyncContext *redis, int status)
{
    h2o_redis_context_t *ctx = (h2o_redis_context_t *)redis->data;
    if (status != REDIS_OK) {
        ctx->redis = NULL;
    }

    if (ctx->cb.connect) {
        ctx->cb.connect(ctx, status == REDIS_OK ? NULL : redis->errstr);
    }
}

static void on_redis_disconnect(const redisAsyncContext *redis, int status)
{
    h2o_redis_context_t *ctx = (h2o_redis_context_t *)redis->data;
    ctx->redis = NULL;

    if (ctx->cb.disconnect) {
        ctx->cb.disconnect(ctx, status == REDIS_OK ? NULL : redis->errstr);
    }
}

h2o_redis_context_t *h2o_redis_create_context(h2o_loop_t *loop, const char *host, uint16_t port)
{
    h2o_redis_context_t *ctx = h2o_mem_alloc(sizeof(*ctx));
    *ctx = (h2o_redis_context_t){NULL};

    ctx->host = h2o_strdup(NULL, host, SIZE_MAX).base;
    ctx->port = port;
    ctx->loop = loop;

    return ctx;
}

int h2o_redis_connect(h2o_redis_context_t *ctx, h2o_redis_connect_cb on_connect, h2o_redis_disconnect_cb on_disconnect)
{
    redisAsyncContext *redis = NULL;

    if (ctx->redis != NULL) {
        goto Error;
    }

    redis = redisAsyncConnect(ctx->host, ctx->port);
    if (redis == NULL || redis->err != REDIS_OK) {
        goto Error;
    }
#if H2O_USE_LIBUV
    redisLibuvAttach(redis, ctx->loop);
#else
    redisEvloopAttach(redis, ctx->loop);
#endif

    if (redisAsyncSetConnectCallback(redis, on_redis_connect) != REDIS_OK) {
        goto Error;
    }
    if (redisAsyncSetDisconnectCallback(redis, on_redis_disconnect) != REDIS_OK) {
        goto Error;
    }
    ctx->redis = redis;
    ctx->cb.connect = on_connect;
    ctx->cb.disconnect = on_disconnect;
    redis->data = ctx;

    return 0;

Error:
    if (redis != NULL)
        redisAsyncFree(redis);
    ctx->redis = NULL;
    return -1;
}

int h2o_redis_disconnect(h2o_redis_context_t *ctx)
{
    if (ctx->redis == NULL) {
        return -1;
    }
    redisAsyncDisconnect(ctx->redis);
    return 0;
}
