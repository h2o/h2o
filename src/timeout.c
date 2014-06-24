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

static void timer_cb(uv_timer_t *_timer, int status)
{
    h2o_timeout_t *timer = (void*)_timer;
    uint64_t now;

    if (status != 0) {
        return;
    }

    now = uv_now(timer->timer.loop);
    while (1) {
        h2o_timeout_entry_t *entry = timer->_link._next;
        if (entry->wake_at > now) {
            break;
        }
        unlink_timer(entry);
        (*timer->_cb)(entry);
    }

    if (! timer_is_empty(timer)) {
        /* not empty, schedule next timer */
        uv_timer_start(&timer->timer, timer_cb, timer->_link._next->wake_at - now, 0);
    }
}

void h2o_timeout_init(h2o_timeout_t *timer, uint64_t timeout, void (*cb)(h2o_timeout_entry_t *entry), uv_loop_t *loop)
{
    uv_timer_init(loop, &timer->timer);
    uv_unref((uv_handle_t*)&timer->timer);

    timer->timeout = timeout;
    timer->_cb = cb;
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
