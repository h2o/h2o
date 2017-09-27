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
#ifndef h2o__timerwheel_h
#define h2o__timerwheel_h

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include "h2o/linklist.h"

typedef uint64_t wheelmask_t;
typedef struct st_h2o_timerwheel_timer_t h2o_timerwheel_timer_t;
typedef void (*h2o_timerwheel_cb)(h2o_timerwheel_timer_t *timer);
/* link list of h2o_timerwheel_timer_t */
typedef h2o_linklist_t h2o_timerwheel_slot_t;

#define H2O_TIMERWHEEL_MAX_WHEELS 4
#define H2O_TIMERWHEEL_BITS_PER_WHEEL 6
#define H2O_TIMERWHEEL_SLOTS_PER_WHEEL (1 << H2O_TIMERWHEEL_BITS_PER_WHEEL)
#define H2O_TIMERWHEEL_SLOTS_MASK (H2O_TIMERWHEEL_SLOTS_PER_WHEEL - 1)
#define H2O_TIMERWHEEL_MAX_TIMER ((1LU << (H2O_TIMERWHEEL_BITS_PER_WHEEL * H2O_TIMERWHEEL_MAX_WHEELS)) - 1)

typedef struct st_h2o_timerwheel_t {
    h2o_timerwheel_slot_t wheel[H2O_TIMERWHEEL_MAX_WHEELS][H2O_TIMERWHEEL_SLOTS_PER_WHEEL], expired;
    uint64_t last_run; /* the last time h2o_timerwheel_run was called */
} h2o_timerwheel_t;

/**
 * Modules willing to use timers should embed this object as part of itself,
 * and link it to timer wheel slot.
 */
struct st_h2o_timerwheel_timer_t {
    h2o_linklist_t _link;
    h2o_timerwheel_cb cb;
    uint64_t expire_at; /* absolute expiration time*/
};

/**
 * initializes a timerwheel
 */
void h2o_timerwheel_init(h2o_timerwheel_t *wheel);
/**
 * run the timerwheel to absolute time "now"
 */
size_t h2o_timerwheel_run(h2o_timerwheel_t *wheel, uint64_t now);
/**
 * display the contents of the timerwheel
 */
void h2o_timerwheel_show(h2o_timerwheel_t *wheel);
/**
 * find out the time ramaining until the next timer triggers
 */
uint64_t h2o_timerwheel_get_wake_at(h2o_timerwheel_t *wheel);
/**
 * creates a timer
 */
h2o_timerwheel_timer_t *h2o_timerwheel_create_timer(h2o_timerwheel_cb cb);
/**
 * initializes a timer
 */
void h2o_timerwheel_init_timer(h2o_timerwheel_timer_t *t, h2o_timerwheel_cb cb);
/**
 * adds a timer to a timerwheel
 */
int h2o_timerwheel_add_timer(h2o_timerwheel_t *w, h2o_timerwheel_timer_t *timer, uint64_t abs_expire);
/**
 * cancels an existing timer
 */
void h2o_timerwheel_del_timer(h2o_timerwheel_timer_t *timer);

int h2o_timer_is_linked(h2o_timerwheel_timer_t *timer);

#ifdef __cplusplus
}
#endif

#endif
