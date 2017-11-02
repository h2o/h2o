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

struct st_h2o_timer_t;
typedef void (*h2o_timer_cb)(struct st_h2o_timer_t *timer);
typedef struct st_h2o_timer_t {
    h2o_linklist_t _link;
    h2o_timer_cb cb;
    uint64_t expire_at; /* absolute expiration time*/
    struct st_h2o_timer_backend_properties_t _backend;
} h2o_timer_t;


/**
 * creates a timer
 */
h2o_timer_t *h2o_timer_create(h2o_timer_cb cb);
/**
 * adds a timer to a timerwheel
 */

int h2o_timer_is_linked(h2o_timer_t *timer);
void h2o_timeout_unlink(h2o_timer_t *timer);

typedef uint32_t h2o_timer_tick_t;
typedef uint64_t h2o_timer_abs_t;

#ifdef __cplusplus
}
#endif

#endif
