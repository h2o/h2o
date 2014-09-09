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
#include <assert.h>
#include "h2o.h"

static inline int timer_is_empty(h2o_timeout_t *timer)
{
    return timer->_link._prev == &timer->_link;
}

static void unlink_timer(h2o_timeout_entry_t *entry)
{
    assert(entry->_prev != NULL);
    entry->_prev->_next = entry->_next;
    entry->_next->_prev = entry->_prev;
    entry->_prev = NULL;
    entry->_next = NULL;
    entry->wake_at = 0;
}

static void timer_cb(uv_timer_t *_timer)
{
    h2o_timeout_t *timer = (void*)_timer;
    h2o_timeout_entry_t detached_root;
    uint64_t now;

    if (timer_is_empty(timer)) {
        return;
    }

    /* For zero timeout, we should only invoke the timers that were added prior to entering this function.
     * To fullfill the purpose we detach all the linked entries from timer->_link and then iterate them.
     */
    detached_root = timer->_link;
    detached_root._next->_prev = &detached_root;
    detached_root._prev->_next = &detached_root;
    timer->_link._prev = timer->_link._next = &timer->_link;

    now = uv_now(timer->timer.loop);
    while (1) {
        h2o_timeout_entry_t *entry = detached_root._next;
        if (entry->wake_at > now) {
            break;
        }
        unlink_timer(entry);
        entry->cb(entry);
    }

    if (! timer_is_empty(timer)) {
        /* not empty, schedule next timer */
        uv_timer_start(&timer->timer, timer_cb, timer->_link._next->wake_at - now, 0);
    }
}

void h2o_timeout_init(h2o_timeout_t *timer, uint64_t timeout, uv_loop_t *loop)
{
    uv_timer_init(loop, &timer->timer);
    uv_unref((uv_handle_t*)&timer->timer);

    timer->timeout = timeout;
    timer->_link.wake_at = UINT64_MAX;
    timer->_link._prev = timer->_link._next = &timer->_link;
}

void h2o_timeout_link_entry(h2o_timeout_t *timer, h2o_timeout_entry_t *entry)
{
    int was_empty = timer_is_empty(timer);

    assert(entry->_prev == NULL);
    /* set data */
    entry->wake_at = uv_now(timer->timer.loop) + timer->timeout;
    /* insert at tail, so the entries are sorted in ascending order */
    entry->_prev = timer->_link._prev;
    entry->_next = &timer->_link;
    entry->_prev->_next = entry;
    entry->_next->_prev = entry;

    if (was_empty) {
        uv_timer_start(&timer->timer, timer_cb, timer->timeout, 0);
    }
}

void h2o_timeout_unlink_entry(h2o_timeout_t *timer, h2o_timeout_entry_t *entry)
{
    if (entry->_prev != NULL) {
        unlink_timer(entry);
        /* note: timer is left scheduled even if no more entries are in linked to the list;
         * because we think having timer fired every `timer->timeout` seconds at worst
         * case is better than calling uv_timer_start / uv_timer_stop many many times
         * for every loop
         */
    }
}
