/*
 * Copyright (c) 2017 Fastly, Inc.
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
#include <string.h>
#include <stdio.h>
#include <inttypes.h>
#include <sys/time.h>
#include "h2o/memory.h"
#include "h2o/socket.h"
#include "h2o/timer.h"

#if H2O_USE_LIBUV

static void on_timeout(uv_timer_t *uv_timer)
{
    h2o_timer_t *timer = H2O_STRUCT_FROM_MEMBER(h2o_timer_t, _backend.timer, uv_timer);
    timer->cb(timer);
}

int h2o_timer_link(h2o_loop_t *l, h2o_timer_t *timer, h2o_timer_val_t t_rel_expire)
{
    uv_timer_init(l, &timer->_backend.timer);
    uv_timer_start(&timer->_backend.timer, on_timeout, h2o_now(l) + t_rel_expire, 0);
    return 1;
}

void h2o_timer_unlink(h2o_timer_t *timer)
{
    uv_timer_stop(&timer->_backend.timer);
}

h2o_timer_t *h2o_timer_create(h2o_timer_cb cb)
{
    return calloc(1, sizeof(h2o_timer_t));
}

#else

#endif
