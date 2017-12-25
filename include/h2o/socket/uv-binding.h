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
#include <uv.h>

#if !(defined(UV_VERSION_MAJOR) && UV_VERSION_MAJOR == 1)
#error "libh2o (libuv binding) requires libuv version 1.x.y"
#endif

typedef uv_loop_t h2o_loop_t;

h2o_socket_t *h2o_uv_socket_create(uv_handle_t *handle, uv_close_cb close_cb);
h2o_socket_t *h2o_uv__poll_create(h2o_loop_t *loop, int fd, uv_close_cb close_cb);

typedef struct st_h2o_timeout_t h2o_timeout_t;
typedef void (*h2o_timeout_cb)(h2o_timeout_t *timer);
struct st_h2o_timeout_t {
    uv_timer_t uv_timer;
    int is_linked;
    h2o_timeout_cb cb;
};

void h2o_timeout_link(h2o_loop_t *l, h2o_timer_tick_t rel_expire, h2o_timeout_t *timer);
int h2o_timeout_is_linked(h2o_timeout_t *timer);
void h2o_timeout_unlink(h2o_timeout_t *timer);

/* inline definitions */

static inline uint64_t h2o_now(h2o_loop_t *loop)
{
    return uv_now(loop);
}

static inline void h2o_timeout_init(h2o_timeout_t *timer, h2o_timeout_cb cb)
{
    memset(timer, 0, sizeof(*timer));
    timer->cb = cb;
}

#endif
