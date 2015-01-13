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
#include <netdb.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include "h2o/linklist.h"
#include "h2o/socketpool.h"
#include "h2o/string_.h"
#include "h2o/timeout.h"

struct pool_entry_t {
    h2o_socket_export_t sockinfo;
    h2o_linklist_t link;
    uint64_t added_at;
};

struct connect_callback_t {
    h2o_socketpool_connect_cb cb;
    h2o_socket_t *sock;
    const char *errstr;
    void *data;
    h2o_timeout_entry_t timeout;
};

static void destroy_attached(struct pool_entry_t *entry)
{
    h2o_linklist_unlink(&entry->link);
    h2o_socket_dispose_export(&entry->sockinfo);
    free(entry);
}

static void destroy_expired(h2o_socketpool_t *pool)
{
    /* caller should lock the mutex */
    uint64_t expire_before = h2o_now(pool->_interval_cb.loop) - pool->timeout;
    while (! h2o_linklist_is_empty(&pool->_shared.sockets)) {
        struct pool_entry_t *entry = H2O_STRUCT_FROM_MEMBER(struct pool_entry_t, link, pool->_shared.sockets.next);
        if (entry->added_at > expire_before)
            break;
        destroy_attached(entry);
        __sync_sub_and_fetch(&pool->_shared.count, 1);
    }
}

static void on_timeout(h2o_timeout_entry_t *timeout_entry)
{
    /* FIXME decrease the frequency of this function being called; the expiration
     * check can be (should be) performed in the `connect` fuction as well
     */
    h2o_socketpool_t *pool = H2O_STRUCT_FROM_MEMBER(h2o_socketpool_t, _interval_cb.entry, timeout_entry);

    if (pthread_mutex_trylock(&pool->_shared.mutex) == 0) {
        destroy_expired(pool);
        pthread_mutex_unlock(&pool->_shared.mutex);
    }

    h2o_timeout_link(pool->_interval_cb.loop, &pool->_interval_cb.timeout, &pool->_interval_cb.entry);
}

void h2o_socketpool_init(h2o_socketpool_t *pool, const char *host, uint16_t port, size_t capacity)
{
    memset(pool, 0, sizeof(*pool));

    pool->host = h2o_strdup(NULL, host, SIZE_MAX);
    pool->port.n = port;
    sprintf(pool->port.s, "%u", (unsigned)port);
    pool->capacity = capacity;
    pool->timeout = UINT64_MAX;

    pthread_mutex_init(&pool->_shared.mutex, NULL);
    h2o_linklist_init_anchor(&pool->_shared.sockets);
}

void h2o_socketpool_dispose(h2o_socketpool_t *pool)
{
    pthread_mutex_lock(&pool->_shared.mutex);
    while (! h2o_linklist_is_empty(&pool->_shared.sockets)) {
        struct pool_entry_t *entry = H2O_STRUCT_FROM_MEMBER(struct pool_entry_t, link, pool->_shared.sockets.next);
        destroy_attached(entry);
        __sync_sub_and_fetch(&pool->_shared.count, 1);
    }
    pthread_mutex_unlock(&pool->_shared.mutex);
    pthread_mutex_destroy(&pool->_shared.mutex);

    if (pool->_interval_cb.loop != NULL) {
        h2o_timeout_unlink(&pool->_interval_cb.entry);
        h2o_timeout_dispose(pool->_interval_cb.loop, &pool->_interval_cb.timeout);
    }
    free(pool->host.base);
}

void h2o_socketpool_set_timeout(h2o_socketpool_t *pool, h2o_loop_t *loop, uint64_t msec)
{
    pool->timeout = msec;

    pool->_interval_cb.loop = loop;
    h2o_timeout_init(loop, &pool->_interval_cb.timeout, 1000);
    pool->_interval_cb.entry.cb = on_timeout;

    h2o_timeout_link(loop, &pool->_interval_cb.timeout, &pool->_interval_cb.entry);
}

static void on_deferred_connect_cb(h2o_timeout_entry_t *timeout)
{
    struct connect_callback_t *cbinfo = H2O_STRUCT_FROM_MEMBER(struct connect_callback_t, timeout, timeout);
    (cbinfo->cb)(cbinfo->sock, cbinfo->errstr, cbinfo->data);
    free(cbinfo);
}

static struct connect_callback_t *setup_connect_callback(h2o_socketpool_connect_cb cb, h2o_socket_t *sock, const char *errstr, void *data)
{
    struct connect_callback_t *cbinfo = h2o_mem_alloc(sizeof(*cbinfo));

    cbinfo->cb = cb;
    cbinfo->sock = sock;
    cbinfo->errstr = errstr;
    cbinfo->data = data;
    memset(&cbinfo->timeout, 0, sizeof(cbinfo->timeout));
    cbinfo->timeout.cb = on_deferred_connect_cb;

    return cbinfo;
}

static void on_connect(h2o_socket_t *sock, int status)
{
    struct connect_callback_t *cbinfo = sock->data;

    if (status != 0) {
        h2o_socket_close(sock);
        cbinfo->sock = NULL;
        cbinfo->errstr = "connection failed";
    }
    on_deferred_connect_cb(&cbinfo->timeout);
}

static void on_close(void *data)
{
    h2o_socketpool_t *pool = data;
    __sync_sub_and_fetch(&pool->_shared.count, 1);
}

void h2o_socketpool_connect(h2o_socketpool_t *pool, h2o_loop_t *loop, h2o_timeout_t *zero_timeout, h2o_socketpool_connect_cb cb, void *data)
{
    struct pool_entry_t *entry = NULL;

    /* fetch an entry */
    pthread_mutex_lock(&pool->_shared.mutex);
    destroy_expired(pool);
    if (! h2o_linklist_is_empty(&pool->_shared.sockets)) {
        entry = H2O_STRUCT_FROM_MEMBER(struct pool_entry_t, link, pool->_shared.sockets.next);
        h2o_linklist_unlink(&entry->link);
    }
    pthread_mutex_unlock(&pool->_shared.mutex);

    /* return the socket deferred, if any */
    if (entry != NULL) {
        h2o_socket_t *sock = h2o_socket_import(loop, &entry->sockinfo);
        struct connect_callback_t *cbinfo = setup_connect_callback(cb, sock, NULL, data);
        h2o_timeout_link(loop, zero_timeout, &cbinfo->timeout);
        sock->on_close.cb = on_close;
        sock->on_close.data = pool;
        free(entry);
        return;
    }

    { /* connect and return (FIXME repsect the `capacity`, timeout) */
        struct addrinfo hints, *res;
        int err;
        h2o_socket_t *sock;
        memset(&hints, 0, sizeof(hints));
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;
        hints.ai_flags = AI_ADDRCONFIG | AI_NUMERICSERV;
        if ((err = getaddrinfo(pool->host.base, pool->port.s, &hints, &res)) != 0) {
            struct connect_callback_t *cbinfo = setup_connect_callback(cb, NULL, "failed to resolve host", data);
            h2o_timeout_link(loop, zero_timeout, &cbinfo->timeout);
            goto ExitConnect;
        }
        /* start connecting */
        if ((sock = h2o_socket_connect(loop, res->ai_addr, res->ai_addrlen, on_connect)) == NULL) {
            struct connect_callback_t *cbinfo = setup_connect_callback(cb, NULL, "failed to connect to host", data);
            h2o_timeout_link(loop, zero_timeout, &cbinfo->timeout);
            goto ExitConnect;
        }
        { /* socket is ready, setup callbacks and update pool counter */
            struct connect_callback_t *cbinfo = setup_connect_callback(cb, sock, NULL, data);
            sock->data = cbinfo;
            sock->on_close.cb = on_close;
            sock->on_close.data = pool;
            __sync_add_and_fetch(&pool->_shared.count, 1);
        }
        freeaddrinfo(res);
        return;
    ExitConnect:
        freeaddrinfo(res);
    }
}

int h2o_socketpool_return(h2o_socketpool_t *pool, h2o_socket_t *sock)
{
    struct pool_entry_t *entry;

    /* reset the on_close callback */
    assert(sock->on_close.data == pool);
    sock->on_close.cb = NULL;
    sock->on_close.data = NULL;

    entry = h2o_mem_alloc(sizeof(*entry));
    if (h2o_socket_export(sock, &entry->sockinfo) != 0) {
        free(entry);
        __sync_sub_and_fetch(&pool->_shared.count, 1);
        return -1;
    }
    memset(&entry->link, 0, sizeof(entry->link));
    entry->added_at = h2o_now(h2o_socket_get_loop(sock));

    pthread_mutex_lock(&pool->_shared.mutex);
    destroy_expired(pool);
    h2o_linklist_insert(&pool->_shared.sockets, &entry->link);
    pthread_mutex_unlock(&pool->_shared.mutex);

    return 0;
}
