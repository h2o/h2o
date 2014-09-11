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

size_t h2o_timeout_run(h2o_timeout_t *timeout, uint64_t now)
{
    uint64_t max_registered_at = now - timeout->timeout;
    size_t n = 0;

    for (; timeout->_entries != NULL; ++n) {
        h2o_timeout_entry_t *entry = h2o_linklist_get_first(h2o_timeout_entry_t, _link, timeout->_entries);
        if (entry->registered_at > max_registered_at) {
            break;
        }
        h2o_linklist_unlink(&timeout->_entries, &entry->_link);
        entry->registered_at = 0;
        entry->cb(entry);
    }

    return n;
}

size_t h2o_timeout_run_all(h2o_linklist_t *timeouts, uint64_t now)
{
    size_t n = 0;

    if (timeouts != NULL) {
        h2o_timeout_t *timeout = h2o_linklist_get_first(h2o_timeout_t, _link, timeouts);
        do {
            n += h2o_timeout_run(timeout, now);
        } while ((timeout = h2o_linklist_get_next(h2o_timeout_t, _link, timeout))
            != h2o_linklist_get_first(h2o_timeout_t, _link, timeouts));
    }

    return n;
}

uint64_t h2o_timeout_get_wake_at(h2o_linklist_t *timeouts)
{
    uint64_t wake_at = UINT64_MAX;

    /* change wake_at to the minimum value of the timeouts */
    if (timeouts != NULL) {
        h2o_timeout_t *timeout = h2o_linklist_get_first(h2o_timeout_t, _link, timeouts);
        do {
            if (timeout->_entries != NULL) {
                h2o_timeout_entry_t *entry = h2o_linklist_get_first(h2o_timeout_entry_t, _link, timeout->_entries);
                uint64_t entry_wake_at = entry->registered_at + timeout->timeout;
                if (entry_wake_at < wake_at)
                    wake_at = entry_wake_at;
            }
        } while ((timeout = h2o_linklist_get_next(h2o_timeout_t, _link, timeout))
            != h2o_linklist_get_first(h2o_timeout_t, _link, timeouts));
    }

    return wake_at;
}

void h2o_timeout_init(h2o_loop_t *loop, h2o_timeout_t *timeout, uint64_t millis)
{
    memset(timeout, 0, sizeof(*timeout));
    timeout->timeout = millis;

    h2o_timeout__do_init(loop, timeout);
}

void h2o_timeout_link(h2o_loop_t *loop, h2o_timeout_t *timeout, h2o_timeout_entry_t *entry)
{
    /* insert at tail, so the entries are sorted in ascending order */
    h2o_linklist_insert(&timeout->_entries, timeout->_entries, &entry->_link);
    /* set data */
    entry->registered_at = h2o_now(loop);

    h2o_timeout__do_link(loop, timeout, entry);
}

void h2o_timeout_unlink(h2o_timeout_t *timeout, h2o_timeout_entry_t *entry)
{
    if (h2o_linklist_is_linked(&entry->_link)) {
        h2o_linklist_unlink(&timeout->_entries, &entry->_link);
        entry->registered_at = 0;
    }
}
