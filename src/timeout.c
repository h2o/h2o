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
#include "h2o.h"

static size_t proceed_timeout(h2o_timeout_t *timeout, uint64_t now)
{
    size_t n = 0;

    for (; timeout->_entries != NULL; ++n) {
        h2o_timeout_entry_t *entry = h2o_linklist_get_first(h2o_timeout_entry_t, _link, timeout->_entries);
        if (entry->wake_at > now) {
            break;
        }
        h2o_linklist_unlink(&timeout->_entries, &entry->_link);
        entry->wake_at = 0;
        entry->cb(entry);
    }

    return n;
}

#ifdef H2O_USE_LIBUV
#else

void h2o_timeout_update_now(h2o_timeout_manager_t *manager)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    manager->now = (uint64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

size_t h2o_timeout_run(h2o_timeout_manager_t *manager, int zero_timeout_only)
{
    size_t n = 0;

    if (! zero_timeout_only && manager->_timeouts != NULL) {
        h2o_timeout_t *timeout = h2o_linklist_get_first(h2o_timeout_t, _link, manager->_timeouts);
        do {
            n += proceed_timeout(timeout, manager->now);
        } while ((timeout = h2o_linklist_get_next(h2o_timeout_t, _link, timeout))
            != h2o_linklist_get_first(h2o_timeout_t, _link, manager->_timeouts));
    }
    n += proceed_timeout(&manager->zero_timeout, manager->now);

    return n;
}

int32_t h2o_timeout_get_max_wait(h2o_timeout_manager_t *manager)
{
    uint64_t wake_at = UINT64_MAX, max_wait;

    /* change wake_at to the minimum value of the timeouts */
    if (manager->_timeouts != NULL) {
        h2o_timeout_t *timeout = h2o_linklist_get_first(h2o_timeout_t, _link, manager->_timeouts);
        do {
            if (timeout->_entries != NULL) {
                h2o_timeout_entry_t *entry = h2o_linklist_get_first(h2o_timeout_entry_t, _link, timeout->_entries);
                if (entry->wake_at < wake_at)
                    wake_at = entry->wake_at;
            }
        } while ((timeout = h2o_linklist_get_next(h2o_timeout_t, _link, timeout))
            != h2o_linklist_get_first(h2o_timeout_t, _link, manager->_timeouts));
    }

    h2o_timeout_update_now(manager);

    if (manager->now < wake_at) {
        max_wait = wake_at - manager->now;
        if (max_wait > INT32_MAX)
            max_wait = INT32_MAX;
    } else {
        max_wait = 0;
    }

    return (int32_t)max_wait;
}

#endif

void h2o_timeout_init(h2o_timeout_manager_t *manager, h2o_timeout_t *timeout, uint64_t millis)
{
    assert(millis != 0 && "use loop->zero_timeout for delayed tasks");
    memset(timeout, 0, sizeof(*timeout));
    timeout->timeout = millis;
#ifdef H2O_USE_LIBUV
#else
    h2o_linklist_insert(&manager->_timeouts, manager->_timeouts, &timeout->_link);
#endif
}

void h2o_timeout_link(h2o_timeout_manager_t *manager, h2o_timeout_t *timeout, h2o_timeout_entry_t *entry)
{
#ifdef H2O_USE_LIBUV
    uint64_t now = uv_now(manager->loop);
#else
    uint64_t now = manager->now;
#endif

    /* insert at tail, so the entries are sorted in ascending order */
    h2o_linklist_insert(&timeout->_entries, timeout->_entries, &entry->_link);
    /* set data */
    entry->wake_at = now + timeout->timeout;
}

void h2o_timeout_unlink(h2o_timeout_t *timeout, h2o_timeout_entry_t *entry)
{
    if (h2o_linklist_is_linked(&entry->_link)) {
        h2o_linklist_unlink(&timeout->_entries, &entry->_link);
        entry->wake_at = 0;
    }
}
