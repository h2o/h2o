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

#define H2O_TIMERWHEEL_SLOTS_MASK (H2O_TIMERWHEEL_SLOTS_PER_WHEEL - 1)
#define H2O_TIMERWHEEL_MAX_TIMER(num_wheels) ((1LU << (H2O_TIMERWHEEL_BITS_PER_WHEEL * (num_wheels))) - 1)

struct st_h2o_timer_wheel_t {
    uint64_t last_run; /* the last time h2o_timer_run_wheel was called */
    size_t num_wheels;
    h2o_timer_wheel_slot_t wheel[1][H2O_TIMERWHEEL_SLOTS_PER_WHEEL];
};

/* debug macros and functions */
//#define WANT_DEBUG
#ifdef WANT_DEBUG
#define WHEEL_DEBUG(fmt, args...)                                                                                                  \
    do {                                                                                                                           \
        fprintf(stderr, "[%s:%d %s]:" fmt, __FILE__, __LINE__, __FUNCTION__, ##args);                                              \
    } while (0)

#else
#define WHEEL_DEBUG(...)
#endif

static void h2o_timer_show(h2o_timer_t *timer, int wid, int sid)
{
    WHEEL_DEBUG("timer with expire_at %" PRIu64 ", wid: %d, sid: %d\n", timer->expire_at, wid, sid);
#ifdef TW_DEBUG_VERBOSE
    WHEEL_DEBUG("_link.next: %p\n", timer->_link.next);
    WHEEL_DEBUG("_link.prev: %p\n", timer->_link.prev);
    WHEEL_DEBUG("callback: %p\n", timer->cb);
#endif
}

static void h2o_timer_slot_show_wheel(h2o_timer_wheel_slot_t *slot, int wid, int sid)
{
    h2o_linklist_t *node;

    for (node = slot->next; node != slot; node = node->next) {
        h2o_timer_t *entry = H2O_STRUCT_FROM_MEMBER(h2o_timer_t, _link, node);
        h2o_timer_show(entry, wid, sid);
    }
}

void h2o_timer_show_wheel(h2o_timer_wheel_t *w)
{
    int i, slot;

    for (i = 0; i < w->num_wheels; i++) {
        for (slot = 0; slot < H2O_TIMERWHEEL_SLOTS_PER_WHEEL; slot++) {
            h2o_timer_wheel_slot_t *s = &(w->wheel[i][slot]);
            h2o_timer_slot_show_wheel(s, i, slot);
        }
    }
}



/* timer APIs */

static int timer_wheel(size_t num_wheels, uint64_t delta)
{
    delta &= H2O_TIMERWHEEL_MAX_TIMER(num_wheels);
    if (delta == 0)
        return 0;

    H2O_BUILD_ASSERT(sizeof(unsigned long long) == 8);
    return (63 - __builtin_clzll(delta)) / H2O_TIMERWHEEL_BITS_PER_WHEEL;
}

/* calculate slot number based on the absolute expiration time */
static int timer_slot(int wheel, uint64_t expire)
{
    return H2O_TIMERWHEEL_SLOTS_MASK & (expire >> (wheel * H2O_TIMERWHEEL_BITS_PER_WHEEL));
}

uint64_t h2o_timer_get_wake_at(h2o_timer_wheel_t *w)
{
    int i, j;
    uint64_t ret;

    for (i = 0; i < H2O_TIMERWHEEL_SLOTS_PER_WHEEL; i++) {
        int real_slot = (w->last_run + i) & H2O_TIMERWHEEL_SLOTS_MASK;
        h2o_timer_wheel_slot_t *slot = &w->wheel[0][real_slot];
        if (!h2o_linklist_is_empty(slot)) {
            return w->last_run + i;
        }
    }
    ret = w->last_run;
    for (i = 1; i < w->num_wheels; i++) {
        for (j = 0; j < H2O_TIMERWHEEL_SLOTS_PER_WHEEL; j++) {
            h2o_timer_wheel_slot_t *slot = &w->wheel[i][j];
            if (!h2o_linklist_is_empty(slot)) {
                /* return an approximation for the expiry */
                ret = (1 << ((i - 1) * H2O_TIMERWHEEL_BITS_PER_WHEEL));
                while (--i > 0) {
                    ret -= (1 << ((i - 1) * H2O_TIMERWHEEL_BITS_PER_WHEEL));
                }
                return ret;
            }
        }
    }
    return UINT64_MAX;
}

static void link_timer(h2o_timer_wheel_t *w, h2o_timer_t *timer, h2o_timer_abs_t abs_expire)
{
    h2o_timer_wheel_slot_t *slot;
    int wid, sid;

    if (abs_expire < w->last_run)
        abs_expire = w->last_run;

    timer->expire_at = abs_expire;

    wid = timer_wheel(w->num_wheels, abs_expire - w->last_run);
    sid = timer_slot(wid, abs_expire);
    slot = &(w->wheel[wid][sid]);

    WHEEL_DEBUG("timer(expire_at %" PRIu64 ") added: wheel %d, slot %d, now:%" PRIu64 "\n", abs_expire, wid, sid, w->last_run);

    h2o_linklist_insert(slot, &timer->_link);
}

void h2o_timer_unlink(h2o_timer_t *timer)
{
    if (h2o_linklist_is_linked(&timer->_link)) {
        h2o_linklist_unlink(&timer->_link);
    }
}

/* timer wheel APIs */

/**
 * initializes a timerwheel
 */
h2o_timer_wheel_t *h2o_timer_create_wheel(size_t num_wheels, uint64_t now)
{
    h2o_timer_wheel_t *w = h2o_mem_alloc(offsetof(h2o_timer_wheel_t, wheel) + sizeof(w->wheel[0]) * num_wheels);
    size_t i, j;

    w->last_run = now;
    w->num_wheels = num_wheels;
    for (i = 0; i < w->num_wheels; i++) {
        memset(&w->wheel[i], 0, sizeof(w->wheel[i]));
        for (j = 0; j < H2O_TIMERWHEEL_SLOTS_PER_WHEEL; j++) {
            h2o_linklist_init_anchor(&w->wheel[i][j]);
        }
    }

    return w;
}

void h2o_timer_destroy_wheel(h2o_timer_wheel_t *w)
{
    size_t i, j;

    for (i = 0; i < w->num_wheels; ++i) {
        for (j = 0; j < H2O_TIMERWHEEL_SLOTS_PER_WHEEL; ++j) {
            while (!h2o_linklist_is_empty(&w->wheel[i][j])) {
                h2o_timer_t *entry = H2O_STRUCT_FROM_MEMBER(h2o_timer_t, _link, w->wheel[i][j].next);
                h2o_timer_unlink(entry);
            }
        }
    }

    free(w);
}

/**
 * cascading happens when the lower wheel wraps around and ticks the next
 * higher wheel
 */
static void cascade(h2o_timer_wheel_t *w, int wheel, int slot)
{
    /* cannot cascade timers on wheel 0 */
    assert(wheel > 0);

    WHEEL_DEBUG("cascade timers on wheel %d slot %d\n", wheel, slot);
    h2o_timer_wheel_slot_t *s = &w->wheel[wheel][slot];
    while (!h2o_linklist_is_empty(s)) {
        h2o_timer_t *entry = H2O_STRUCT_FROM_MEMBER(h2o_timer_t, _link, s->next);
        h2o_linklist_unlink(&entry->_link);
        link_timer(w, entry, entry->expire_at);
        assert(&entry->_link != s->prev); /* detect the entry reassigned to the same slot */
    }
}

int h2o_timer_wheel_is_empty(h2o_timer_wheel_t *w)
{
    int i, slot;

    for (i = 0; i < w->num_wheels; i++)
        for (slot = 0; slot < H2O_TIMERWHEEL_SLOTS_PER_WHEEL; slot++)
            if (!h2o_linklist_is_empty(&w->wheel[i][slot]))
                return 0;

    return 1;
}

size_t h2o_timer_run_wheel(h2o_timer_wheel_t *w, uint64_t now)
{
    size_t count = 0;
    h2o_linklist_t todo;

    assert(w->last_run <= now);

    h2o_linklist_init_anchor(&todo);

    while (1) {
        /* collect slots on the first wheel */
        int slot = w->last_run & H2O_TIMERWHEEL_SLOTS_MASK;
        do {
            h2o_linklist_insert_list(&todo, &w->wheel[0][slot]);
            if (w->last_run == now)
                goto Collected;
            ++w->last_run;
        } while (++slot < H2O_TIMERWHEEL_SLOTS_PER_WHEEL);
        /* cascade */
        int wheel = 1;
        do {
            slot = (w->last_run >> (wheel * H2O_TIMERWHEEL_BITS_PER_WHEEL)) & H2O_TIMERWHEEL_SLOTS_MASK;
            cascade(w, wheel, slot);
        } while (slot == 0 && ++wheel < w->num_wheels);
    }
Collected:

    /* expiration processing */
    while (!h2o_linklist_is_empty(&todo)) {
        h2o_timer_t *timer = H2O_STRUCT_FROM_MEMBER(h2o_timer_t, _link, todo.next);
        /* remove this timer from todo list */
        h2o_linklist_unlink(&timer->_link);
        timer->cb(timer);
        count++;
    }

    return count;
}

void h2o_timer_link(h2o_timer_wheel_t *w, h2o_timer_t *timer, h2o_timer_abs_t abs_expire)
{
    link_timer(w, timer, abs_expire);
}
