/*
 * Copyright (c) 2017 Fastly Inc., Ltd.
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

#include "h2o/linklist.h"

#define H2O_TIMERWHEEL_BITS_PER_WHEEL 5
#define H2O_TIMERWHEEL_SLOTS_PER_WHEEL (1 << H2O_TIMERWHEEL_BITS_PER_WHEEL)

typedef struct st_h2o_timer_context_t h2o_timer_context_t;

struct st_h2o_timer_t;

typedef void (*h2o_timer_cb)(struct st_h2o_timer_t *timer);

typedef struct st_h2o_timer_t {
    h2o_linklist_t _link;
    uint64_t expire_at; /* absolute expiration time*/
    h2o_timer_cb cb;
} h2o_timer_t;

/**
 * initializes a timer
 */
static void h2o_timer_init(h2o_timer_t *timer, h2o_timer_cb cb);
/**
 * activates a timer
 */
void h2o_timer_link_abs(h2o_timer_context_t *ctx, h2o_timer_t *timer, uint64_t at);
/**
 * disactivates a timer
 */
static void h2o_timer_unlink(h2o_timer_t *timer);
/**
 * returns whether a timer is active
 */
static int h2o_timer_is_linked(h2o_timer_t *timer);

/**
 * creates a timerwheel
 */
h2o_timer_context_t *h2o_timer_create_context(size_t num_wheels, uint64_t now);
/**
 * destroys a timerwheel
 */
void h2o_timer_destroy_context(h2o_timer_context_t *ctx);
/**
 * display the contents of the timerwheel
 */
void h2o_timer_dump_context(h2o_timer_context_t *ctx);
/**
 * validates the timerwheel and returns the result as a boolean value
 */
int h2o_timer_validate_context(h2o_timer_context_t *ctx);
/**
 * find out the time ramaining until the next timer triggers
 */
uint64_t h2o_timer_get_wake_at(h2o_timer_context_t *ctx);

size_t h2o_timer_run(h2o_timer_context_t *ctx, uint64_t now);

/* inline definitions */

inline void h2o_timer_init(h2o_timer_t *timer, h2o_timer_cb cb)
{
    *timer = (h2o_timer_t){{NULL}, 0, cb};
}

inline int h2o_timer_is_linked(h2o_timer_t *entry)
{
    return h2o_linklist_is_linked(&entry->_link);
}

inline void h2o_timer_unlink(h2o_timer_t *timer)
{
    if (h2o_linklist_is_linked(&timer->_link))
        h2o_linklist_unlink(&timer->_link);
}

#endif
