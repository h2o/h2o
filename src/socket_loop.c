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
#include <errno.h>
#include "h2o.h"

static void update_now(h2o_socket_loop_t *loop)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    loop->now = (uint64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

static void run_socket(h2o_socket_t* sock)
{
    if ((sock->_flags & H2O_SOCKET_FLAG_IS_DISPOSED) != 0) {
        /* is freed in updatestates phase */
        return;
    }

    if (sock->_cb.write != NULL && sock->_wreq.cnt == 0) {
        h2o_socket__write_on_complete(sock, (sock->_flags & H2O_SOCKET_FLAG_IS_WRITE_ERROR) != 0 ? -1 : 0);
    }

    if ((sock->_flags & H2O_SOCKET_FLAG_IS_READ_READY) != 0) {
        sock->_flags &= ~H2O_SOCKET_FLAG_IS_READ_READY;
        h2o_socket__read_on_ready(sock);
    }
}

static h2o_socket_loop_t *create_socket_loop(size_t sz, h2o_socket_loop_proceed_cb proceed, h2o_socket_loop_socket_state_change_cb on_create, h2o_socket_loop_socket_state_change_cb on_close)
{
    h2o_socket_loop_t *loop = h2o_malloc(sz);

    memset(loop, 0, sz);
    loop->_proceed = proceed;
    loop->_on_create = on_create;
    loop->_on_close = on_close;
    loop->_statechanged.tail_ref = &loop->_statechanged.head;

    return loop;
}

static size_t run_pending(h2o_socket_loop_t *loop)
{
    size_t n = 0;

    for (; loop->_pending != NULL; ++n) {
        /* detach the first sock and run */
        h2o_socket_t *sock = loop->_pending;
        loop->_pending = sock->_next_pending;
        sock->_next_pending = sock;
        run_socket(sock);
    }

    return n;
}

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

int h2o_socket_loop_run(h2o_socket_loop_t *loop, uint64_t wake_at)
{
    /* change wake_at to the minimum value of the timeouts */
    if (loop->_timeouts != NULL) {
        h2o_timeout_t *timeout = h2o_linklist_get_first(h2o_timeout_t, _link, loop->_timeouts);
        do {
            if (timeout->_entries != NULL) {
                h2o_timeout_entry_t *entry = h2o_linklist_get_first(h2o_timeout_entry_t, _link, timeout->_entries);
                if (entry->wake_at < wake_at)
                    wake_at = entry->wake_at;
            }
        } while ((timeout = h2o_linklist_get_next(h2o_timeout_t, _link, timeout))
            != h2o_linklist_get_first(h2o_timeout_t, _link, loop->_timeouts));
    }

    /* update socket states, poll, set readable flags, perform pending writes */
    if (loop->_proceed(loop, wake_at) != 0)
        return -1;

    /* call the pending callbacks */
    run_pending(loop);

    /* run the timeouts */
    if (loop->_timeouts != NULL) {
        h2o_timeout_t *timeout = h2o_linklist_get_first(h2o_timeout_t, _link, loop->_timeouts);
        do {
            proceed_timeout(timeout, loop->now);
        } while ((timeout = h2o_linklist_get_next(h2o_timeout_t, _link, timeout))
            != h2o_linklist_get_first(h2o_timeout_t, _link, loop->_timeouts));
    }
    /* run deferred tasks and pending callbacks */
    while (proceed_timeout(&loop->zero_timeout, loop->now) + run_pending(loop) != 0)
        ;

    return 0;
}

void h2o_timeout_init(h2o_socket_loop_t *loop, h2o_timeout_t *timeout, uint64_t millis)
{
    assert(millis != 0 && "use loop->zero_timeout for delayed tasks");
    memset(timeout, 0, sizeof(*timeout));
    timeout->timeout = millis;
    h2o_linklist_insert(&loop->_timeouts, loop->_timeouts, &timeout->_link);
}

void h2o_timeout_link(h2o_socket_loop_t *loop, h2o_timeout_t *timeout, h2o_timeout_entry_t *entry)
{
    /* insert at tail, so the entries are sorted in ascending order */
    h2o_linklist_insert(&timeout->_entries, timeout->_entries, &entry->_link);
    /* set data */
    entry->wake_at = loop->now + timeout->timeout;
}

void h2o_timeout_unlink(h2o_timeout_t *timeout, h2o_timeout_entry_t *entry)
{
    if (h2o_linklist_is_linked(&entry->_link)) {
        h2o_linklist_unlink(&timeout->_entries, &entry->_link);
        entry->wake_at = 0;
    }
}

#if H2O_USE_SELECT || H2O_USE_EPOLL || H2O_USE_KQUEUE
/* explicitely specified */
#else
# if defined(__APPLE__)
#  define H2O_USE_KQUEUE 1
# elif defined(__linux)
#  define H2O_USE_EPOLL 1
# else
#  define H2O_USE_SELECT 1
# endif
#endif

#if H2O_USE_SELECET
# include "socket_loop/select.h"
#elif H2O_USE_EPOLL
# include "socket_loop/epoll.h"
#elif H2O_USE_KQUEUE
# include "socket_loop/kqueue.h"
#else
# error "poller not specified"
#endif
