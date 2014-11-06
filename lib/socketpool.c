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
#include <stdlib.h>
#include "h2o/linklist.h"
#include "h2o/socketpool.h"

struct pool_entry_t {
    h2o_socket_t *sock;
    h2o_linklist_t link;
    h2o_timeout_entry_t timeout;
};

static void detach(struct pool_entry_t *entry)
{
    entry->sock->data = NULL;
    h2o_linklist_unlink(&entry->link);
    h2o_timeout_unlink(&entry->timeout);
    free(entry);
}

static void detach_and_close(struct pool_entry_t *entry)
{
    h2o_socket_t *sock = entry->sock;
    detach(entry);
    h2o_socket_close(sock);
}

static void on_read(h2o_socket_t *sock, int status)
{
    detach_and_close(sock->data);
}

static void on_timeout(h2o_timeout_entry_t *timeout_entry)
{
    struct pool_entry_t *entry = H2O_STRUCT_FROM_MEMBER(struct pool_entry_t, timeout, timeout_entry);
    detach_and_close(entry);
}

static void setup(h2o_socketpool_t *pool, h2o_socket_t *sock, h2o_timeout_t *timeout)
{
    struct pool_entry_t *entry = h2o_malloc(sizeof(*entry));

    memset(entry, 0, sizeof(*entry));
    entry->sock = sock;
    entry->timeout.cb = on_timeout;
    h2o_linklist_insert(&pool->_sockets, &entry->link);
    h2o_timeout_link(h2o_socket_get_loop(sock), timeout, &entry->timeout);
    h2o_socket_read_start(sock, on_read);

    sock->data = entry;
}

void h2o_socketpool_init(h2o_socketpool_t *pool, int multiloop)
{
    assert(! multiloop);
    memset(pool, 0, sizeof(*pool));
    h2o_linklist_init_anchor(&pool->_sockets);
}

void h2o_socketpool_dispose(h2o_socketpool_t *pool)
{
    while (! h2o_linklist_is_empty(&pool->_sockets)) {
        struct pool_entry_t *entry = H2O_STRUCT_FROM_MEMBER(struct pool_entry_t, link, pool->_sockets.next);
        detach_and_close(entry);
    }
}

void h2o_socketpool_register(h2o_socketpool_t *pool, h2o_socket_t *sock, h2o_timeout_t *timeout)
{
    assert(sock->_cb.write == NULL);
    setup(pool, sock, timeout);
}

h2o_socket_t *h2o_socketpool_acquire(h2o_socketpool_t *pool, h2o_loop_t *loop)
{
    struct pool_entry_t *entry;
    h2o_socket_t *sock;

    /* early exit if no sockets in the pool */
    if (h2o_linklist_is_empty(&pool->_sockets))
        return NULL;

    /* first, try to return a socket that belongs to the same loop */
    entry = H2O_STRUCT_FROM_MEMBER(struct pool_entry_t, link, pool->_sockets.next);
    sock = entry->sock;
    assert(h2o_socket_get_loop(sock) == loop);
    detach(entry);

    return sock;
}
