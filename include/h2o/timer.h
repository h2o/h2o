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
#ifndef h2o__timer_h
#define h2o__timer_h

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <string.h>

#include "h2o/linklist.h"
#include "h2o/socket.h"

struct st_h2o_timeout_t;
typedef void (*h2o_timer_cb)(struct st_h2o_timeout_t *timer);
typedef struct st_h2o_timeout_t {
#if H2O_USE_LIBUV
    uv_timer_t uv_timer;
    int is_linked;
#else
    h2o_linklist_t _link;
    uint64_t expire_at; /* absolute expiration time*/
#endif
    h2o_timer_cb cb;
} h2o_timeout_t;

#if H2O_USE_LIBUV
static inline h2o_timeout_t h2o_timeout_init(h2o_timer_cb cb)
{
    h2o_timeout_t ret = {};
    ret.cb = cb;
    return ret;
}
#else
static inline h2o_timeout_t h2o_timeout_init(h2o_timer_cb cb)
{
    return (h2o_timeout_t){
        {},
        0,
        cb,
    };
}
#endif

int h2o_timeout_is_linked(h2o_timeout_t *timer);
void h2o_timeout_unlink(h2o_timeout_t *timer);

typedef uint32_t h2o_timer_tick_t;
typedef uint64_t h2o_timer_abs_t;

#ifdef __cplusplus
}
#endif

#endif
