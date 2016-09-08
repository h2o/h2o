/*
 * Copyright (c) 2014-2016 DeNA Co., Ltd., Kazuho Oku
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
#include <netdb.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <netinet/in.h>
#include "h2o/hostinfo.h"
#include "h2o/linklist.h"
#include "h2o/socketpool.h"
#include "h2o/string_.h"
#include "h2o/timeout.h"

struct pool_entry_t {
    h2o_socket_export_t sockinfo;
    h2o_linklist_t link;
    uint64_t added_at;
};

struct st_h2o_socketpool_connect_request_t {
    void *data;
    h2o_socketpool_connect_cb cb;
    h2o_socketpool_t *pool;
    h2o_loop_t *loop;
    h2o_hostinfo_getaddr_req_t *getaddr_req;
    h2o_socket_t *sock;
};

static void destroy_detached(struct pool_entry_t *entry)
{
    h2o_socket_dispose_export(&entry->sockinfo);
    free(entry);
}

static void destroy_attached(struct pool_entry_t *entry)
{
    h2o_linklist_unlink(&entry->link);
    destroy_detached(entry);
}

static void destroy_expired(h2o_socketpool_t *pool)
{
    /* caller should lock the mutex */
    uint64_t expire_before = h2o_now(pool->_interval_cb.loop) - pool->timeout;
    while (!h2o_linklist_is_empty(&pool->_shared.sockets)) {
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

static void common_init(h2o_socketpool_t *pool, h2o_socketpool_type_t type, h2o_iovec_t host, int is_ssl, size_t capacity)
{
    memset(pool, 0, sizeof(*pool));

    pool->type = type;
    pool->peer.host = h2o_strdup(NULL, host.base, host.len);
    pool->is_ssl = is_ssl;
    pool->capacity = capacity;
    pool->timeout = UINT64_MAX;

    pthread_mutex_init(&pool->_shared.mutex, NULL);
    h2o_linklist_init_anchor(&pool->_shared.sockets);
}

void h2o_socketpool_init_by_address(h2o_socketpool_t *pool, struct sockaddr *sa, socklen_t salen, int is_ssl, size_t capacity)
{
    char host[NI_MAXHOST];
    size_t host_len;

    assert(salen <= sizeof(pool->peer.sockaddr.bytes));

    if ((host_len = h2o_socket_getnumerichost(sa, salen, host)) == SIZE_MAX) {
        if (sa->sa_family != AF_UNIX)
            h2o_fatal("failed to convert a non-unix socket address to a numerical representation");
        /* use the sockaddr_un::sun_path as the SNI indicator (is that the right thing to do?) */
        strcpy(host, ((struct sockaddr_un *)sa)->sun_path);
        host_len = strlen(host);
    }

    common_init(pool, H2O_SOCKETPOOL_TYPE_SOCKADDR, h2o_iovec_init(host, host_len), is_ssl, capacity);
    memcpy(&pool->peer.sockaddr.bytes, sa, salen);
    pool->peer.sockaddr.len = salen;
}

void h2o_socketpool_init_by_hostport(h2o_socketpool_t *pool, h2o_iovec_t host, uint16_t port, int is_ssl, size_t capacity)
{
    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));

    if (h2o_hostinfo_aton(host, &sin.sin_addr) == 0) {
        sin.sin_family = AF_INET;
        sin.sin_port = htons(port);
        h2o_socketpool_init_by_address(pool, (void *)&sin, sizeof(sin), is_ssl, capacity);
        return;
    }

    common_init(pool, H2O_SOCKETPOOL_TYPE_NAMED, host, is_ssl, capacity);
    pool->peer.named_serv.base = h2o_mem_alloc(sizeof(H2O_UINT16_LONGEST_STR));
    pool->peer.named_serv.len = sprintf(pool->peer.named_serv.base, "%u", (unsigned)port);
}

void h2o_socketpool_dispose(h2o_socketpool_t *pool)
{
    pthread_mutex_lock(&pool->_shared.mutex);
    while (!h2o_linklist_is_empty(&pool->_shared.sockets)) {
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
    free(pool->peer.host.base);
    switch (pool->type) {
    case H2O_SOCKETPOOL_TYPE_NAMED:
        free(pool->peer.named_serv.base);
        break;
    case H2O_SOCKETPOOL_TYPE_SOCKADDR:
        break;
    }
}

void h2o_socketpool_set_timeout(h2o_socketpool_t *pool, h2o_loop_t *loop, uint64_t msec)
{
    pool->timeout = msec;

    pool->_interval_cb.loop = loop;
    h2o_timeout_init(loop, &pool->_interval_cb.timeout, 1000);
    pool->_interval_cb.entry.cb = on_timeout;

    h2o_timeout_link(loop, &pool->_interval_cb.timeout, &pool->_interval_cb.entry);
}

static void call_connect_cb(h2o_socketpool_connect_request_t *req, const char *errstr)
{
    h2o_socketpool_connect_cb cb = req->cb;
    h2o_socket_t *sock = req->sock;
    void *data = req->data;

    free(req);
    cb(sock, errstr, data);
}

static void on_connect(h2o_socket_t *sock, const char *err)
{
    h2o_socketpool_connect_request_t *req = sock->data;
    const char *errstr = NULL;

    assert(req->sock == sock);

    if (err != NULL) {
        h2o_socket_close(sock);
        req->sock = NULL;
        errstr = "connection failed";
    }
    call_connect_cb(req, errstr);
}

static void on_close(void *data)
{
    h2o_socketpool_t *pool = data;
    __sync_sub_and_fetch(&pool->_shared.count, 1);
}

static void start_connect(h2o_socketpool_connect_request_t *req, struct sockaddr *addr, socklen_t addrlen)
{
    req->sock = h2o_socket_connect(req->loop, addr, addrlen, on_connect);
    if (req->sock == NULL) {
        __sync_sub_and_fetch(&req->pool->_shared.count, 1);
        call_connect_cb(req, "failed to connect to host");
        return;
    }
    req->sock->data = req;
    req->sock->on_close.cb = on_close;
    req->sock->on_close.data = req->pool;
}

static void on_getaddr(h2o_hostinfo_getaddr_req_t *getaddr_req, const char *errstr, struct addrinfo *res, void *_req)
{
    h2o_socketpool_connect_request_t *req = _req;

    assert(getaddr_req == req->getaddr_req);
    req->getaddr_req = NULL;

    if (errstr != NULL) {
        __sync_sub_and_fetch(&req->pool->_shared.count, 1);
        call_connect_cb(req, errstr);
        return;
    }

    struct addrinfo *selected = h2o_hostinfo_select_one(res);
    start_connect(req, selected->ai_addr, selected->ai_addrlen);
}

void h2o_socketpool_connect(h2o_socketpool_connect_request_t **_req, h2o_socketpool_t *pool, h2o_loop_t *loop,
                            h2o_multithread_receiver_t *getaddr_receiver, h2o_socketpool_connect_cb cb, void *data)
{
    struct pool_entry_t *entry = NULL;

    if (_req != NULL)
        *_req = NULL;

    /* fetch an entry and return it */
    pthread_mutex_lock(&pool->_shared.mutex);
    destroy_expired(pool);
    while (1) {
        if (h2o_linklist_is_empty(&pool->_shared.sockets))
            break;
        entry = H2O_STRUCT_FROM_MEMBER(struct pool_entry_t, link, pool->_shared.sockets.next);
        h2o_linklist_unlink(&entry->link);
        pthread_mutex_unlock(&pool->_shared.mutex);

        /* test if the connection is still alive */
        char buf[1];
        ssize_t rret = recv(entry->sockinfo.fd, buf, 1, MSG_PEEK);
        if (rret == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            /* yes! return it */
            h2o_socket_t *sock = h2o_socket_import(loop, &entry->sockinfo);
            free(entry);
            sock->on_close.cb = on_close;
            sock->on_close.data = pool;
            cb(sock, NULL, data);
            return;
        }

        /* connection is dead, report, close, and retry */
        if (rret <= 0) {
            static long counter = 0;
            if (__sync_fetch_and_add(&counter, 1) == 0)
                fprintf(stderr, "[WARN] detected close by upstream before the expected timeout (see issue #679)\n");
        } else {
            static long counter = 0;
            if (__sync_fetch_and_add(&counter, 1) == 0)
                fprintf(stderr, "[WARN] unexpectedly received data to a pooled socket (see issue #679)\n");
        }
        destroy_detached(entry);
        pthread_mutex_lock(&pool->_shared.mutex);
    }
    pthread_mutex_unlock(&pool->_shared.mutex);

    /* FIXME repsect `capacity` */
    __sync_add_and_fetch(&pool->_shared.count, 1);

    /* prepare request object */
    h2o_socketpool_connect_request_t *req = h2o_mem_alloc(sizeof(*req));
    *req = (h2o_socketpool_connect_request_t){data, cb, pool, loop};
    if (_req != NULL)
        *_req = req;

    switch (pool->type) {
    case H2O_SOCKETPOOL_TYPE_NAMED:
        /* resolve the name, and connect */
        req->getaddr_req = h2o_hostinfo_getaddr(getaddr_receiver, pool->peer.host, pool->peer.named_serv, AF_UNSPEC, SOCK_STREAM,
                                                IPPROTO_TCP, AI_ADDRCONFIG | AI_NUMERICSERV, on_getaddr, req);
        break;
    case H2O_SOCKETPOOL_TYPE_SOCKADDR:
        /* connect (using sockaddr_in) */
        start_connect(req, (void *)&pool->peer.sockaddr.bytes, pool->peer.sockaddr.len);
        break;
    }
}

void h2o_socketpool_cancel_connect(h2o_socketpool_connect_request_t *req)
{
    if (req->getaddr_req != NULL) {
        h2o_hostinfo_getaddr_cancel(req->getaddr_req);
        req->getaddr_req = NULL;
    }
    if (req->sock != NULL)
        h2o_socket_close(req->sock);
    free(req);
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
