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

#include "hiredis.h"
#include "h2o/socket.h"

typedef struct st_h2o_redis_conn_t h2o_redis_conn_t;
typedef struct st_h2o_redis_callbacks_t {
    void (*on_connect)(void *cb_data);
    void (*on_disconnect)(void *cb_data);
    void (*on_connection_failure)(const char *errstr, void *cb_data);
} h2o_redis_callbacks_t;
typedef void (*h2o_redis_command_cb)(redisReply *reply, void *cb_data);

h2o_redis_conn_t *h2o_redis_connect(h2o_loop_t *loop, const char *host, uint16_t port, h2o_redis_callbacks_t cb, void *cb_data);
int h2o_redis_disconnect(h2o_redis_conn_t *conn);
int h2o_redis_command(h2o_redis_conn_t *conn, h2o_redis_command_cb cb, void *cb_data, const char *format, ...);

#endif
