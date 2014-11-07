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
    h2o_socket_export_t sockinfo;
    h2o_linklist_t link;
    uint64_t added_at;
};

static void destroy_attached(struct pool_entry_t *entry)
{
    h2o_linklist_unlink(&entry->link);
    h2o_socket_dispose_export(&entry->sockinfo);
    free(entry);
}

static void on_timeout(h2o_timeout_entry_t *timeout_entry)
{
    h2o_socketpool_t *pool = H2O_STRUCT_FROM_MEMBER(h2o_socketpool_t, _timeout_entry, timeout_entry);
    uint64_t expire_before;

    pthread_mutex_lock(&pool->_mutex);

    expire_before = h2o_now(pool->loop) - pool->_timeout.timeout;
    while (! h2o_linklist_is_empty(&pool->_shared.sockets)) {
        struct pool_entry_t *entry = H2O_STRUCT_FROM_MEMBER(struct pool_entry_t, link, pool->_shared.sockets.next);
        if (entry->added_at > expire_before)
            break;
        destroy_attached(entry);
        --pool->_shared.count;
    }

    pthread_mutex_unlock(&pool->_mutex);
}

void h2o_socketpool_init(h2o_socketpool_t *pool, h2o_loop_t *loop, size_t capacity, uint64_t timeout)
{
    memset(pool, 0, sizeof(*pool));

    pool->loop = loop;
    pool->capacity = capacity;
    h2o_timeout_init(loop, &pool->_timeout, timeout);
    pool->_timeout_entry.cb = on_timeout;

    pthread_mutex_init(&pool->_mutex, NULL);
    h2o_linklist_init_anchor(&pool->_shared.sockets);
}

void h2o_socketpool_dispose(h2o_socketpool_t *pool)
{
    pthread_mutex_lock(&pool->_mutex);
    while (! h2o_linklist_is_empty(&pool->_shared.sockets)) {
        struct pool_entry_t *entry = H2O_STRUCT_FROM_MEMBER(struct pool_entry_t, link, pool->_shared.sockets.next);
        destroy_attached(entry);
        --pool->_shared.count;
    }
    pthread_mutex_unlock(&pool->_mutex);
    pthread_mutex_destroy(&pool->_mutex);

    h2o_timeout_unlink(&pool->_timeout_entry);
    h2o_timeout_dispose(pool->loop, &pool->_timeout);
}

int h2o_socketpool_register(h2o_socketpool_t *pool, h2o_socket_t *sock)
{
    struct pool_entry_t *entry = h2o_malloc(sizeof(*entry));

    if (h2o_socket_export(sock, &entry->sockinfo) != 0) {
        free(entry);
        return -1;
    }
    memset(&entry->link, 0, sizeof(entry->link));

    pthread_mutex_lock(&pool->_mutex);
    h2o_linklist_insert(&pool->_shared.sockets, &entry->link);
    ++pool->_shared.count;
    pthread_mutex_unlock(&pool->_mutex);

    return 0;
}

h2o_socket_t *h2o_socketpool_acquire(h2o_socketpool_t *pool, h2o_loop_t *loop)
{
    struct pool_entry_t *entry = NULL;

    /* fetch an entry */
    pthread_mutex_lock(&pool->_mutex);
    if (! h2o_linklist_is_empty(&pool->_shared.sockets)) {
        entry = H2O_STRUCT_FROM_MEMBER(struct pool_entry_t, link, pool->_shared.sockets.next);
        h2o_linklist_unlink(&entry->link);
    }
    pthread_mutex_unlock(&pool->_mutex);

    if (entry != NULL) {
        h2o_socket_t *sock = h2o_socket_import(loop, &entry->sockinfo);
        free(entry);
        return sock;
    } else {
        return NULL;
    }
}
