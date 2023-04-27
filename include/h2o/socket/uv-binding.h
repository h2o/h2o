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
#ifndef h2o__uv_binding_h
#define h2o__uv_binding_h

#include <string.h>
#include <sys/time.h>
#include <uv.h>

#if !(defined(UV_VERSION_MAJOR) && UV_VERSION_MAJOR == 1)
#error "libh2o (libuv binding) requires libuv version 1.x.y"
#endif

typedef uv_loop_t h2o_loop_t;

h2o_socket_t *h2o_uv_socket_create(uv_handle_t *handle, uv_close_cb close_cb);
h2o_socket_t *h2o_uv__poll_create(h2o_loop_t *loop, int fd, uv_close_cb close_cb);

typedef struct st_h2o_timer_t h2o_timer_t;
typedef void (*h2o_timer_cb)(h2o_timer_t *timer);
struct st_h2o_timer_t {
    uv_timer_t *uv_timer;
    int is_linked;
    h2o_timer_cb cb;
};

static void h2o_timer_init(h2o_timer_t *timer, h2o_timer_cb cb);
void h2o_timer_link(h2o_loop_t *l, uint64_t delay_ticks, h2o_timer_t *timer);
static int h2o_timer_is_linked(h2o_timer_t *timer);
void h2o_timer_unlink(h2o_timer_t *timer);

/* inline definitions */

static inline struct timeval h2o_gettimeofday(uv_loop_t *loop)
{
    struct timeval tv_at;
    gettimeofday(&tv_at, NULL);
    return tv_at;
}

static inline uint64_t h2o_now(h2o_loop_t *loop)
{
    return uv_now(loop);
}

static inline uint64_t h2o_now_nanosec(h2o_loop_t *loop)
{
    return uv_now(loop) * 1000000;
}

inline void h2o_timer_init(h2o_timer_t *timer, h2o_timer_cb cb)
{
    memset(timer, 0, sizeof(*timer));
    timer->cb = cb;
}

inline int h2o_timer_is_linked(h2o_timer_t *entry)
{
    return entry->is_linked;
}

#endif
