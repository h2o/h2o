/*
 * Copyright (c) 2016 DeNA Co., Ltd.
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
#include <inttypes.h>
#include <unistd.h>
#include "h2o/redis.h"

static h2o_loop_t *loop;
static int exit_loop;
const char *host;
uint16_t port;
h2o_redis_conn_t *conn;

static void usage(const char *cmd)
{
    fprintf(stderr, "Usage: %s <host> <port>\n", cmd);
    exit(1);
}

static void dump_reply(redisReply *reply, unsigned indent)
{
    for (int i = 0; i != indent; ++i)
        fprintf(stderr, "  ");

    switch (reply->type) {
    case REDIS_REPLY_STRING:

        fprintf(stderr, "string: %.*s\n", reply->len, reply->str);
        break;
    case REDIS_REPLY_ARRAY:
        fprintf(stderr, "array: %zu\n", reply->elements);
        for (size_t i = 0; i != reply->elements; ++i) {
            dump_reply(reply->element[i], indent + 1);
        }
        break;
    case REDIS_REPLY_NIL:
        fprintf(stderr, "nil");
        break;
    case REDIS_REPLY_INTEGER:
        fprintf(stderr, "integer: %lld\n", reply->integer);
        break;
    case REDIS_REPLY_STATUS:
        fprintf(stderr, "status: %.*s\n", reply->len, reply->str);
        break;
    case REDIS_REPLY_ERROR:
        fprintf(stderr, "error: %.*s\n", reply->len, reply->str);
        break;
    default:
        fprintf(stderr, "invalid reply type: %d\n", reply->type);
    }
}

static void on_redis_command(redisReply *reply, void *cb_data)
{
    if (reply == NULL) {
        fprintf(stderr, "redis command failed due to some connection problems\n");
        return;
    }
    dump_reply(reply, 0);
}

static void on_redis_connect(void)
{
    fprintf(stderr, "connected to redis\n");
    h2o_redis_command(conn, on_redis_command, "get server info", "INFO");
}

static void on_redis_close(const char *errstr)
{
    if (errstr == NULL) {
        fprintf(stderr, "disconnected from redis\n");
    } else {
        fprintf(stderr, "redis connection failure: %s\n", errstr);
        /* try to reconnect after 1 second */
        usleep(1000000);
        h2o_redis_connect(conn, host, port);
    }
}

int main(int argc, char **argv)
{
    int ret = 1;

    const char *cmd = (--argc, *argv++);
    if (argc < 2)
        usage(cmd);
    if (argc != 2)
        usage(cmd);
    host = (--argc, *argv++);
    const char *_port = (--argc, *argv++);
    if (sscanf(_port, "%" SCNu16, &port) != 1) {
        goto Exit;
    }

#if H2O_USE_LIBUV
    loop = uv_loop_new();
#else
    loop = h2o_evloop_create();
#endif

    conn = h2o_redis_create_connection(loop, sizeof(*conn));
    conn->on_connect = on_redis_connect;
    conn->on_close = on_redis_close;

    h2o_redis_connect(conn, host, port);
    h2o_redis_command(conn, on_redis_command, "list all keys", "KEYS *");

    while (!exit_loop) {
#if H2O_USE_LIBUV
        uv_run(loop, UV_RUN_DEFAULT);
#else
        h2o_evloop_run(loop);
#endif
    }

    ret = 0;

Exit:

    h2o_redis_free(conn);

    if (loop != NULL) {
#if H2O_USE_LIBUV
        uv_loop_delete(loop);
#else
// FIXME
// h2o_evloop_destroy(loop);
#endif
    }
    return ret;
}
