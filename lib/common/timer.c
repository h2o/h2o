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

void h2o_timer_link(h2o_loop_t *l, h2o_timer_t *timer, h2o_timer_val_t rel_expire)
{
    uv_timer_init(l, &timer->_backend.timer);
    uv_timer_start(&timer->_backend.timer, on_timeout, h2o_now(l) + rel_expire, 0);
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

static inline int clz(uint64_t n)
{
    H2O_BUILD_ASSERT(sizeof(unsigned long long) == 8);
    return __builtin_clzll(n);
}

/* debug macros and functions */
#ifdef WANT_DEBUG
#define WHEEL_DEBUG(fmt, args...)                                                                                                  \
    do {                                                                                                                           \
        fprintf(stdout, "[%s:%d %s]:" fmt, __FILE__, __LINE__, __FUNCTION__, ##args);                                              \
    } while (0)

#else
#define WHEEL_DEBUG(...)
#endif

static void h2o_timer_show(h2o_timer_t *timer)
{
    WHEEL_DEBUG("timer with expire_at %" PRIu64 "\n", timer->expire_at);
#ifdef TW_DEBUG_VERBOSE
    WHEEL_DEBUG("_link.next: %p\n", timer->_link.next);
    WHEEL_DEBUG("_link.prev: %p\n", timer->_link.prev);
    WHEEL_DEBUG("callback: %p\n", timer->cb);
#endif
}

static void h2o_timer_wheel_slot_show(h2o_timer_wheel_slot_t *slot)
{
    h2o_linklist_t *node;
    if (h2o_linklist_is_empty(slot))
        return;

    for (node = slot->next; node != slot; node = node->next) {
        h2o_timer_t *entry = H2O_STRUCT_FROM_MEMBER(h2o_timer_t, _link, node);
        h2o_timer_show(entry);
    }
}

void h2o_timer_wheel_show(h2o_timer_wheel_t *w)
{
    int i, slot;

    for (i = 0; i < H2O_TIMERWHEEL_MAX_WHEELS; i++) {
        for (slot = 0; slot < H2O_TIMERWHEEL_SLOTS_PER_WHEEL; slot++) {
            h2o_timer_wheel_slot_t *s = &(w->wheel[i][slot]);
            h2o_timer_wheel_slot_show(s);
        }
    }
}

uint64_t h2o_timer_wheel_get_wake_at(h2o_timer_wheel_t *w)
{
    int i = 0;

    for (; i < 64; i++) {
        int real_slot = (w->last_run + i) & H2O_TIMERWHEEL_SLOTS_MASK;
        h2o_timer_wheel_slot_t *slot = &w->wheel[0][real_slot];
        if (!h2o_linklist_is_empty(slot)) {
            return w->last_run + i;
        }
    }
    return w->last_run + H2O_TIMERWHEEL_SLOTS_PER_WHEEL;
}

/* timer APIs */
h2o_timer_t *h2o_timer_create(h2o_timer_cb cb)
{
    h2o_timer_t *t = h2o_mem_alloc(sizeof(h2o_timer_t));
    *t = (h2o_timer_t){{}, cb};
    return t;
}

/* calculate wheel number base on the absolute expiration time */
static inline int timer_wheel(uint64_t abs_wtime, uint64_t abs_expire)
{
    uint64_t delta = (abs_wtime ^ abs_expire) & H2O_TIMERWHEEL_MAX_TIMER;
    if (delta == 0)
        return 0;
    return (H2O_TIMERWHEEL_SLOTS_MASK - clz(delta)) / H2O_TIMERWHEEL_BITS_PER_WHEEL;
}

/* calculate slot number based on the absolute expiration time */
static inline int timer_slot(int wheel, uint64_t expire)
{
    return H2O_TIMERWHEEL_SLOTS_MASK & (expire >> wheel * H2O_TIMERWHEEL_BITS_PER_WHEEL);
}

static h2o_timer_wheel_slot_t *compute_slot(h2o_timer_wheel_t *w, h2o_timer_t *timer)
{
    h2o_timer_wheel_slot_t *slot;
    uint32_t diff = timer->expire_at - w->last_run;

#define SLOT(idx_) \
        slot = &w->wheel[(idx_)][0] + ((timer->expire_at >> ((idx_) * H2O_TIMERWHEEL_BITS_PER_WHEEL)) & H2O_TIMERWHEEL_SLOTS_MASK);
#define IF_SLOT(idx_) \
    if (diff < 1 << (((idx_) + 1) * H2O_TIMERWHEEL_BITS_PER_WHEEL)) { \
        SLOT((idx_)) \
    }

    IF_SLOT(0)
    else IF_SLOT(1)
    else IF_SLOT(2)
    else IF_SLOT(3)
    else IF_SLOT(4)
    else SLOT(5)

#undef SLOT
#undef IF_SLOT

    return slot;
}

void h2o_timer_link_(h2o_timer_wheel_t *w, h2o_timer_t *timer, h2o_timer_abs_t abs_expire)
{
    h2o_timer_wheel_slot_t *slot;
    int wid, sid;

    if (abs_expire < w->last_run)
        abs_expire = w->last_run;

    if (abs_expire - w->last_run > 0xffffffff)
        abort();

    timer->expire_at = abs_expire;

    wid = timer_wheel(w->last_run, abs_expire);
    sid = timer_slot(wid, abs_expire);
    slot = &(w->wheel[wid][sid]);

    WHEEL_DEBUG("timer(expire_at %" PRIu64 ") is added to wheel %d, slot %d\n", abs_expire, wid, sid);

    h2o_linklist_insert(slot, &timer->_link);
}

void h2o_timer_unlink(h2o_timer_t *timer)
{
    if (h2o_linklist_is_linked(&timer->_link)) {
        h2o_linklist_unlink(&timer->_link);
    }
}

inline int h2o_timer_is_linked(h2o_timer_t *entry)
{
    return h2o_linklist_is_linked(&entry->_link);
}

/* timer wheel APIs */

/**
 * initializes a timerwheel
 */
void h2o_timer_wheel_init(h2o_timer_wheel_t *w)
{
    int i, j;
    memset(w, 0, sizeof(h2o_timer_wheel_t));

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
        h2o_timer_t *entry = H2O_STRUCT_FROM_MEMBER(h2o_timer_t, _link, s->next);
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

size_t h2o_timer_wheel_run(h2o_timer_wheel_t *w, uint64_t now)
{
    int i, j, now_slot, prev_slot, end_slot;
    uint64_t abs_wtime = w->last_run;
    size_t count = 0;
    h2o_linklist_t todo;
    h2o_linklist_init_anchor(&todo);
    /* update the timestamp for the timerwheel */
    w->last_run = now;

    /* how the wheel is run: based on abs_wtime and now, we should be able
     * to figure out the wheel id on which most update happens. Most likely
     * the operating wheel is wheel 0 (wid == 0), since we optimize the case
     * where h2o_timer_wheel_run() is called very frequently, i.e the gap
     * between abs_wtime and now is normally small. */
    int wid = timer_wheel(abs_wtime, now);
    WHEEL_DEBUG(" wtime %" PRIu64 ", now %" PRIu64 " wid %d\n", abs_wtime, now, wid);

    if (wid > 0) {
        /* now collect all the expired timers on wheels [0, wid-1] */
        for (j = 0; j <= wid; j++) {
            prev_slot = timer_slot(j, abs_wtime);
            now_slot = timer_slot(j, now);
            end_slot = j == wid ? now_slot - 1 : H2O_TIMERWHEEL_SLOTS_MASK;
            /* all slots between prev_slot and end_slot are expired */
            for (i = prev_slot; i <= end_slot; i++) {
                h2o_linklist_insert_list(&todo, &w->wheel[j][i]);
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
        h2o_timer_t *timer = H2O_STRUCT_FROM_MEMBER(h2o_timer_t, _link, todo.next);
        /* remove this timer from todo list */
        h2o_linklist_unlink(&timer->_link);
        timer->cb(timer);
        count++;
    }

    return count;
}

static h2o_timer_abs_t h2o_timer_now_plus(h2o_loop_t *loop, h2o_timer_val_t timeout)
{
    return timeout + h2o_now(loop);
}

void h2o_timer_link(h2o_loop_t *l, h2o_timer_t *timer, h2o_timer_val_t rel_expire)
{
    h2o_timer_link_(&l->_timerwheel, timer, h2o_timer_now_plus(l, rel_expire));
}

#endif
