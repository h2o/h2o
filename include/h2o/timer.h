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

typedef uint64_t wheelmask_t;
/* link list of h2o_timeout_t */
typedef h2o_linklist_t h2o_timer_wheel_slot_t;

#define H2O_TIMERWHEEL_MAX_WHEELS 6
#define H2O_TIMERWHEEL_BITS_PER_WHEEL 6
#define H2O_TIMERWHEEL_SLOTS_PER_WHEEL (1 << H2O_TIMERWHEEL_BITS_PER_WHEEL)

typedef struct st_h2o_timer_wheel_t {
    h2o_timer_wheel_slot_t wheel[H2O_TIMERWHEEL_MAX_WHEELS][H2O_TIMERWHEEL_SLOTS_PER_WHEEL];
    uint64_t last_run; /* the last time h2o_timer_run_wheel was called */
} h2o_timer_wheel_t;

struct st_h2o_timer_t;
typedef void (*h2o_timer_cb)(struct st_h2o_timer_t *timer);
typedef struct st_h2o_timer_t {
    h2o_linklist_t _link;
    uint64_t expire_at; /* absolute expiration time*/
    h2o_timer_cb cb;
} h2o_timer_t;
/**
 * initializes a timerwheel
 */
void h2o_timer_init_wheel(h2o_timer_wheel_t *w, uint64_t now);
/**
 * display the contents of the timerwheel
 */
void h2o_timer_show_wheel(h2o_timer_wheel_t *wheel);
/**
 * find out the time ramaining until the next timer triggers
 */
uint64_t h2o_timer_get_wake_at_wheel(h2o_timer_wheel_t *wheel);

typedef uint64_t h2o_timer_abs_t;
void h2o_timer_link_(h2o_timer_wheel_t *w, h2o_timer_t *timer, h2o_timer_abs_t abs_expire);
size_t h2o_timer_run_wheel(h2o_timer_wheel_t *w, uint64_t now);
int h2o_timer_is_empty_wheel(h2o_timer_wheel_t *w);

#endif
