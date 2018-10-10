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
#ifndef h2o__redis_h
#define h2o__redis_h

#include "h2o/socket.h"

struct redisAsyncContext;
struct redisReply;

extern const char h2o_redis_error_connection[];
extern const char h2o_redis_error_protocol[];
extern const char h2o_redis_error_connect_timeout[];
extern const char h2o_redis_error_command_timeout[];

typedef enum {
    H2O_REDIS_CONNECTION_STATE_CLOSED = 0,
    H2O_REDIS_CONNECTION_STATE_CONNECTING,
    H2O_REDIS_CONNECTION_STATE_CONNECTED,
} h2o_redis_connection_state_t;

typedef struct st_h2o_redis_client_t {
    h2o_loop_t *loop;
    h2o_redis_connection_state_t state;
    void (*on_connect)(void);
    void (*on_close)(const char *errstr);
    uint64_t connect_timeout;
    uint64_t command_timeout;

    struct redisAsyncContext *_redis;
    h2o_timer_t _timeout_entry;
} h2o_redis_client_t;

typedef void (*h2o_redis_command_cb)(struct redisReply *reply, void *cb_data, const char *errstr);

typedef enum enum_h2o_redis_command_type_t {
    H2O_REDIS_COMMAND_TYPE_NORMAL = 1,
    H2O_REDIS_COMMAND_TYPE_SUBSCRIBE,
    H2O_REDIS_COMMAND_TYPE_UNSUBSCRIBE,
    H2O_REDIS_COMMAND_TYPE_PSUBSCRIBE,
    H2O_REDIS_COMMAND_TYPE_PUNSUBSCRIBE,
    H2O_REDIS_COMMAND_TYPE_MONITOR,
    H2O_REDIS_COMMAND_TYPE_ERROR
} h2o_redis_command_type_t;

typedef struct st_h2o_redis_command_t {
    h2o_redis_client_t *client;
    h2o_redis_command_cb cb;
    void *data;
    h2o_redis_command_type_t type;
    h2o_timer_t _command_timeout;
} h2o_redis_command_t;

h2o_redis_client_t *h2o_redis_create_client(h2o_loop_t *loop, size_t sz);
void h2o_redis_connect(h2o_redis_client_t *client, const char *host, uint16_t port);
void h2o_redis_disconnect(h2o_redis_client_t *client);
void h2o_redis_free(h2o_redis_client_t *client);

h2o_redis_command_t *h2o_redis_command(h2o_redis_client_t *client, h2o_redis_command_cb cb, void *cb_data, const char *format, ...);
h2o_redis_command_t *h2o_redis_command_argv(h2o_redis_client_t *client, h2o_redis_command_cb cb, void *cb_data, int argc,
                                            const char **argv, const size_t *argvlen);

#endif
