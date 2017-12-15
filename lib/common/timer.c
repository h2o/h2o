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

#if H2O_USE_LIBUV

static void on_timeout(uv_timer_t *uv_timer)
{
    h2o_timeout_t *timer = H2O_STRUCT_FROM_MEMBER(h2o_timeout_t, uv_timer, uv_timer);
    timer->cb(timer);
}

void h2o_timeout_link(h2o_loop_t *l, h2o_timer_tick_t rel_expire, h2o_timeout_t *timer)
{
    timer->is_linked = 1;
    uv_timer_init(l, &timer->uv_timer);
    uv_timer_start(&timer->uv_timer, on_timeout, h2o_now(l) + rel_expire, 0);
}

void h2o_timeout_unlink(h2o_timeout_t *timer)
{
    timer->is_linked = 0;
    uv_timer_stop(&timer->uv_timer);
}

#else

#define H2O_TIMERWHEEL_SLOTS_MASK (H2O_TIMERWHEEL_SLOTS_PER_WHEEL - 1)
#define H2O_TIMERWHEEL_MAX_TIMER ((1LU << (H2O_TIMERWHEEL_BITS_PER_WHEEL * H2O_TIMERWHEEL_MAX_WHEELS)) - 1)

static int clz(uint64_t n)
{
    H2O_BUILD_ASSERT(sizeof(unsigned long long) == 8);
    return __builtin_clzll(n);
}

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

static void h2o_timer_show(h2o_timeout_t *timer, int wid, int sid)
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
        h2o_timeout_t *entry = H2O_STRUCT_FROM_MEMBER(h2o_timeout_t, _link, node);
        h2o_timer_show(entry, wid, sid);
    }
}

void h2o_timer_show_wheel(h2o_timer_wheel_t *w)
{
    int i, slot;

    for (i = 0; i < H2O_TIMERWHEEL_MAX_WHEELS; i++) {
        for (slot = 0; slot < H2O_TIMERWHEEL_SLOTS_PER_WHEEL; slot++) {
            h2o_timer_wheel_slot_t *s = &(w->wheel[i][slot]);
            h2o_timer_slot_show_wheel(s, i, slot);
        }
    }
}



/* timer APIs */

static int timer_wheel(uint64_t abs_wtime, uint64_t abs_expire)
{
    uint64_t delta = (abs_expire ^ abs_wtime) & H2O_TIMERWHEEL_MAX_TIMER;
    if (delta == 0)
        return 0;
    return (H2O_TIMERWHEEL_SLOTS_MASK - clz(delta)) / H2O_TIMERWHEEL_BITS_PER_WHEEL;
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
    for (i = 1; i < H2O_TIMERWHEEL_MAX_WHEELS; i++) {
        for (j = 0; j < H2O_TIMERWHEEL_SLOTS_PER_WHEEL; j++) {
            h2o_timer_wheel_slot_t *slot = &w->wheel[i][j];
            if (!h2o_linklist_is_empty(slot)) {
                h2o_timeout_t *entry = H2O_STRUCT_FROM_MEMBER(h2o_timeout_t, _link, slot->next);
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

void h2o_timer_link_(h2o_timer_wheel_t *w, h2o_timeout_t *timer, h2o_timer_abs_t abs_expire)
{
    h2o_timer_wheel_slot_t *slot;
    int wid, sid;

    if (abs_expire < w->last_run)
        abs_expire = w->last_run;

    timer->expire_at = abs_expire;

    wid = timer_wheel(w->last_run, abs_expire);
    sid = timer_slot(wid, abs_expire);
    slot = &(w->wheel[wid][sid]);

    WHEEL_DEBUG("timer(expire_at %" PRIu64 ") added: wheel %d, slot %d, now:%" PRIu64 "\n", abs_expire, wid, sid, w->last_run);

    h2o_linklist_insert(slot, &timer->_link);
}

void h2o_timeout_unlink(h2o_timeout_t *timer)
{
    if (h2o_linklist_is_linked(&timer->_link)) {
        h2o_linklist_unlink(&timer->_link);
    }
}

inline int h2o_timeout_is_linked(h2o_timeout_t *entry)
{
    return h2o_linklist_is_linked(&entry->_link);
}

/* timer wheel APIs */

/**
 * initializes a timerwheel
 */
void h2o_timer_init_wheel(h2o_timer_wheel_t *w, uint64_t now)
{
    int i, j;
    memset(w, 0, sizeof(h2o_timer_wheel_t));

    w->last_run = now;
    for (i = 0; i < H2O_TIMERWHEEL_MAX_WHEELS; i++) {
        for (j = 0; j < H2O_TIMERWHEEL_SLOTS_PER_WHEEL; j++) {
            h2o_linklist_init_anchor(&w->wheel[i][j]);
        }
    }
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
        h2o_timeout_t *entry = H2O_STRUCT_FROM_MEMBER(h2o_timeout_t, _link, s->next);
        h2o_linklist_unlink(&entry->_link);
        h2o_timer_link_(w, entry, entry->expire_at);
    }
}

int h2o_timer_wheel_is_empty(h2o_timer_wheel_t *w)
{
    int i, slot;

    for (i = 0; i < H2O_TIMERWHEEL_MAX_WHEELS; i++)
        for (slot = 0; slot < H2O_TIMERWHEEL_SLOTS_PER_WHEEL; slot++)
            if (!h2o_linklist_is_empty(&w->wheel[i][slot]))
                return 0;

    return 1;
}

size_t h2o_timer_run_wheel(h2o_timer_wheel_t *w, uint64_t now)
{
    int i, j, now_slot, prev_slot, end_slot;
    uint64_t abs_wtime = w->last_run;
    size_t count = 0;
    h2o_linklist_t todo;
    h2o_linklist_init_anchor(&todo);
    /* update the timestamp for the timerwheel */
    assert(now >= w->last_run);

    w->last_run = now;

    /* how the wheel is run: based on abs_wtime and now, we should be able
     * to figure out the wheel id on which most update happens. Most likely
     * the operating wheel is wheel 0 (wid == 0), since we optimize the case
     * where h2o_timer_run_wheel() is called very frequently, i.e the gap
     * between abs_wtime and now is normally small. */
    int wid = timer_wheel(abs_wtime, now);
    WHEEL_DEBUG(" wtime %" PRIu64 ", now %" PRIu64 " wid %d\n", abs_wtime, now, wid);

    if (wid > 0) {
        /* now collect all the expired timers on wheels [0, wid-1] */
        for (j = 0; j <= wid; j++) {
            prev_slot = timer_slot(j, abs_wtime);
            now_slot = timer_slot(j, now);
            end_slot = j == wid ? now_slot : H2O_TIMERWHEEL_SLOTS_MASK;
            /* all slots between 0 and end_slot are expired */
            /* FIXME: we could start from prev_slot, but the logic is currently broken */
            for (i = /*prev_slot*/ 0; i <= end_slot; i++) {
                if (i == end_slot) {
                    h2o_linklist_t *node, *next;
                    h2o_timer_wheel_slot_t *slot = &w->wheel[j][i];
                    for (node = slot->next; node != slot; node = next) {
                        next = node->next;
                        h2o_timeout_t *entry = H2O_STRUCT_FROM_MEMBER(h2o_timeout_t, _link, node);
                        if (entry->expire_at <= now) {
                            h2o_linklist_unlink(&entry->_link);
                            h2o_linklist_insert(&todo, node);
                        }
                    }
                } else {
                    h2o_linklist_insert_list(&todo, &w->wheel[j][i]);
                }
            }
        }

        /* cascade the timers on wheel[wid][now_slot] */
        cascade(w, wid, now_slot);
    } else {
        prev_slot = timer_slot(0, abs_wtime);
        now_slot = timer_slot(0, now);
        for (i = prev_slot; i <= now_slot; i++) {
            h2o_linklist_insert_list(&todo, &w->wheel[0][i]);
        }
    }

    /* expiration processing */
    while (!h2o_linklist_is_empty(&todo)) {
        h2o_timeout_t *timer = H2O_STRUCT_FROM_MEMBER(h2o_timeout_t, _link, todo.next);
        /* remove this timer from todo list */
        h2o_linklist_unlink(&timer->_link);
        timer->cb(timer);
        count++;
    }

    return count;
}

static h2o_timer_abs_t h2o_timer_now_plus(h2o_loop_t *loop, h2o_timer_tick_t timeout)
{
    return timeout + h2o_now(loop);
}

void h2o_timer_link(h2o_timer_wheel_t *w, h2o_timeout_t *timer, h2o_timer_abs_t abs_expire)
{
    h2o_timer_link_(w, timer, abs_expire);
}

void h2o_timeout_link(h2o_loop_t *l, h2o_timer_tick_t rel_expire, h2o_timeout_t *timer)
{
    h2o_timer_link(&l->_timerwheel, timer, h2o_timer_now_plus(l, rel_expire));
}

#endif
