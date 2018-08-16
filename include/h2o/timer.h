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

/* link list of h2o_timer_t */
typedef h2o_linklist_t h2o_timer_wheel_slot_t;

#define H2O_TIMERWHEEL_BITS_PER_WHEEL 6
#define H2O_TIMERWHEEL_SLOTS_PER_WHEEL (1 << H2O_TIMERWHEEL_BITS_PER_WHEEL)

typedef struct st_h2o_timer_wheel_t h2o_timer_wheel_t;

typedef struct st_h2o_timer_t h2o_timer_t;
typedef void (*h2o_timer_cb)(h2o_timer_t *timer);
typedef uint32_t h2o_timer_tick_t;
typedef uint64_t h2o_timer_abs_t;

struct st_h2o_timer_t {
    h2o_linklist_t _link;
    uint64_t expire_at; /* absolute expiration time*/
    h2o_timer_cb cb;
};

/**
 * initializes a timer
 */
static void h2o_timer_init(h2o_timer_t *timer, h2o_timer_cb cb);
/**
 * activates a timer
 */
void h2o_timer_link(h2o_timer_wheel_t *w, h2o_timer_t *timer, h2o_timer_abs_t abs_expire);
/**
 * disactivates a timer
 */
void h2o_timer_unlink(h2o_timer_t *timer);
/**
 * returns whether a timer is active
 */
static int h2o_timer_is_linked(h2o_timer_t *timer);

/**
 * creates a timerwheel
 */
h2o_timer_wheel_t *h2o_timer_create_wheel(size_t num_wheels, uint64_t now);
/**
 * destroys a timerwheel
 */
void h2o_timer_destroy_wheel(h2o_timer_wheel_t *wheel);
/**
 * display the contents of the timerwheel
 */
void h2o_timer_show_wheel(h2o_timer_wheel_t *wheel);
/**
 * find out the time ramaining until the next timer triggers
 */
uint64_t h2o_timer_get_wake_at(h2o_timer_wheel_t *wheel);

size_t h2o_timer_run_wheel(h2o_timer_wheel_t *w, uint64_t now);

/* inline definitions */

inline void h2o_timer_init(h2o_timer_t *timer, h2o_timer_cb cb)
{
    *timer = (h2o_timer_t){
        {NULL},
        0,
        cb,
    };
}

inline int h2o_timer_is_linked(h2o_timer_t *entry)
{
    return h2o_linklist_is_linked(&entry->_link);
}

#endif
