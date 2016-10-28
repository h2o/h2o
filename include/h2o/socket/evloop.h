/*
 * Copyright (c) 2014 DeNA Co., Ltd.
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
#ifndef h2o__evloop_h
#define h2o__evloop_h

#include "h2o/linklist.h"

#define H2O_SOCKET_FLAG_IS_DISPOSED 0x1
#define H2O_SOCKET_FLAG_IS_READ_READY 0x2
#define H2O_SOCKET_FLAG_IS_WRITE_NOTIFY 0x4
#define H2O_SOCKET_FLAG_IS_POLLED_FOR_READ 0x8
#define H2O_SOCKET_FLAG_IS_POLLED_FOR_WRITE 0x10
#define H2O_SOCKET_FLAG_DONT_READ 0x20
#define H2O_SOCKET_FLAG_IS_CONNECTING 0x40
#define H2O_SOCKET_FLAG_IS_ACCEPTED_CONNECTION 0x80
#define H2O_SOCKET_FLAG__EPOLL_IS_REGISTERED 0x1000

typedef struct st_h2o_evloop_t {
    struct st_h2o_evloop_socket_t *_pending_as_client;
    struct st_h2o_evloop_socket_t *_pending_as_server;
    struct {
        struct st_h2o_evloop_socket_t *head;
        struct st_h2o_evloop_socket_t **tail_ref;
    } _statechanged;
    uint64_t _now;
    h2o_linklist_t _timeouts; /* list of h2o_timeout_t */
    h2o_sliding_counter_t exec_time_counter;
} h2o_evloop_t;

typedef h2o_evloop_t h2o_loop_t;

struct st_h2o_timeout_backend_properties_t {
    char _dummy; /* sizeof(empty_struct) differs bet. C (GCC extension) and C++ */
};

h2o_socket_t *h2o_evloop_socket_create(h2o_evloop_t *loop, int fd, int flags);
h2o_socket_t *h2o_evloop_socket_accept(h2o_socket_t *listener);

h2o_evloop_t *h2o_evloop_create(void);
void h2o_evloop_destroy(h2o_evloop_t *loop);
int h2o_evloop_run(h2o_evloop_t *loop, int32_t max_wait);

/* inline definitions */

static inline uint64_t h2o_now(h2o_evloop_t *loop)
{
    return loop->_now;
}

static inline uint64_t h2o_evloop_get_execution_time(h2o_evloop_t *loop)
{
    return loop->exec_time_counter.average;
}

#endif
