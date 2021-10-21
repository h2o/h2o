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
#include "h2o/timerwheel.h"

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
    uint64_t _now_millisec;
    uint64_t _now_nanosec;
    struct timeval _tv_at;
    h2o_timerwheel_t *_timeouts;
    h2o_sliding_counter_t exec_time_nanosec_counter;
} h2o_evloop_t;

typedef h2o_evloop_t h2o_loop_t;

typedef h2o_timerwheel_entry_t h2o_timer_t;
typedef h2o_timerwheel_cb h2o_timer_cb;

h2o_socket_t *h2o_evloop_socket_create(h2o_evloop_t *loop, int fd, int flags);
h2o_socket_t *h2o_evloop_socket_accept(h2o_socket_t *listener);
/**
 * Sets number of bytes that can be read at once (default: 1MB).
 */
void h2o_evloop_socket_set_max_read_size(h2o_socket_t *sock, size_t max_size);

h2o_evloop_t *h2o_evloop_create(void);
void h2o_evloop_destroy(h2o_evloop_t *loop);
/**
 * runs a event loop once. The function returns 0 if successful, or -1 if it aborts the operation due to a system call returning an
 * error (typcially due to an interrupt setting errno to EINTR). When an error is returned, the application can consult errno and
 * rerun the event loop.
 */
int h2o_evloop_run(h2o_evloop_t *loop, int32_t max_wait);

#define h2o_timer_init h2o_timerwheel_init_entry
#define h2o_timer_is_linked h2o_timerwheel_is_linked
static void h2o_timer_link(h2o_evloop_t *loop, uint64_t delay_ticks, h2o_timer_t *timer);
#define h2o_timer_unlink h2o_timerwheel_unlink

/* inline definitions */

static inline struct timeval h2o_gettimeofday(h2o_evloop_t *loop)
{
    return loop->_tv_at;
}

static inline uint64_t h2o_now(h2o_evloop_t *loop)
{
    return loop->_now_millisec;
}

static inline uint64_t h2o_now_nanosec(h2o_evloop_t *loop)
{
    return loop->_now_nanosec;
}

static inline uint64_t h2o_evloop_get_execution_time_millisec(h2o_evloop_t *loop)
{
    return loop->exec_time_nanosec_counter.average / 1000000;
}

static inline uint64_t h2o_evloop_get_execution_time_nanosec(h2o_evloop_t *loop)
{
    return loop->exec_time_nanosec_counter.average;
}

inline void h2o_timer_link(h2o_evloop_t *loop, uint64_t delay_ticks, h2o_timer_t *timer)
{
    h2o_timerwheel_link_abs(loop->_timeouts, timer, loop->_now_millisec + delay_ticks);
}

#endif
