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
    size_t target;
    h2o_linklist_t all_link;
    h2o_linklist_t target_link;
    uint64_t added_at;
};

struct st_h2o_socketpool_connect_request_t {
    void *data;
    h2o_socketpool_connect_cb cb;
    h2o_socketpool_t *pool;
    h2o_loop_t *loop;
    h2o_hostinfo_getaddr_req_t *getaddr_req;
    h2o_socket_t *sock;
    h2o_multithread_receiver_t *getaddr_receiver;
    size_t selected_target;
    struct {
        int *tried;
        size_t try_count;
    } lb;
};

struct on_close_data_t {
    h2o_socketpool_t *pool;
    size_t target;
};

struct round_robin_t {
    size_t next_pos;
    pthread_mutex_t mutex;
};

static void start_connect(h2o_socketpool_connect_request_t *req, struct sockaddr *addr, socklen_t addrlen);
static void on_getaddr(h2o_hostinfo_getaddr_req_t *getaddr_req, const char *errstr, struct addrinfo *res, void *_req);

static void destroy_detached(struct pool_entry_t *entry)
{
    h2o_socket_dispose_export(&entry->sockinfo);
    free(entry);
}

static void destroy_attached(struct pool_entry_t *entry)
{
    h2o_linklist_unlink(&entry->all_link);
    h2o_linklist_unlink(&entry->target_link);
    destroy_detached(entry);
}

static void destroy_expired(h2o_socketpool_t *pool)
{
    if (pool->_interval_cb.loop == NULL)
        return;

    /* caller should lock the mutex */
    uint64_t expire_before = h2o_now(pool->_interval_cb.loop) - pool->timeout;
    while (!h2o_linklist_is_empty(&pool->_shared.sockets)) {
        struct pool_entry_t *entry = H2O_STRUCT_FROM_MEMBER(struct pool_entry_t, all_link, pool->_shared.sockets.next);
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

static void common_init(h2o_socketpool_t *pool, h2o_socketpool_target_vector_t targets, size_t capacity,
                        h2o_socketpool_lb_initializer lb_init, h2o_socketpool_lb_selector lb_selector,
                        h2o_socketpool_lb_dispose_cb lb_dispose)
{
    memset(pool, 0, sizeof(*pool));

    pool->capacity = capacity;
    pool->timeout = UINT64_MAX;

    pthread_mutex_init(&pool->_shared.mutex, NULL);
    h2o_linklist_init_anchor(&pool->_shared.sockets);
    memcpy(&pool->targets, &targets, sizeof(targets));

    if (lb_init != NULL)
        lb_init(&pool->targets, &pool->_lb.data);
    pool->_lb.selector = lb_selector;
    pool->_lb.dispose = lb_dispose;
}

static void lb_rr_init(h2o_socketpool_target_vector_t *targets, void **data)
{
    struct round_robin_t *self = h2o_mem_alloc(sizeof(*self));
    self->next_pos = 0;
    pthread_mutex_init(&self->mutex, NULL);
    *data = self;
}

static size_t lb_rr_selector(h2o_socketpool_target_vector_t *targets, void *_data, int *tried)
{
    size_t i;
    size_t result = 0;
    struct round_robin_t *self = _data;

    pthread_mutex_lock(&self->mutex);

    for (i = 0; i < targets->size; i++) {
        if (!tried[self->next_pos]) {
            result = self->next_pos;
            break;
        }
        self->next_pos++;
        self->next_pos %= targets->size;
    }

    assert(i < targets->size);
    self->next_pos++;
    self->next_pos %= targets->size;
    pthread_mutex_unlock(&self->mutex);
    return result;
}

static void lb_rr_dispose(void *data)
{
    struct round_robin_t *self = data;
    pthread_mutex_destroy(&self->mutex);
    free(data);
}

h2o_socketpool_target_type_t detect_target_type(h2o_url_t *url, h2o_iovec_t *host, uint16_t *port, struct sockaddr_storage *sa,
                                                socklen_t *salen)
{
    const char *to_sun_err = h2o_url_host_to_sun(url->host, (struct sockaddr_un *)sa);
    if (to_sun_err == h2o_url_host_to_sun_err_is_not_unix_socket) {
        sa->ss_family = AF_INET;
        struct sockaddr_in *sin = (struct sockaddr_in *)sa;
        *salen = sizeof(*sin);
        *host = url->host;
        *port = h2o_url_get_port(url);

        if (h2o_hostinfo_aton(url->host, &sin->sin_addr) == 0) {
            sin->sin_port = htons(h2o_url_get_port(url));
            return H2O_SOCKETPOOL_TYPE_SOCKADDR;
        } else {
            return H2O_SOCKETPOOL_TYPE_NAMED;
        }
    } else {
        assert(to_sun_err == NULL);
        struct sockaddr_un *sun = (struct sockaddr_un *)sa;
        *salen = sizeof(*sun);
        *host = h2o_iovec_init(sun->sun_path, strlen(sun->sun_path));
        *port = 0;
        return H2O_SOCKETPOOL_TYPE_SOCKADDR;
    }
}

void init_target(h2o_socketpool_target_t *target, h2o_url_t *origin)
{
    assert(origin != NULL);

    struct sockaddr_storage sa;
    socklen_t salen;
    h2o_iovec_t host;
    uint16_t port;

    memset(&sa, 0, sizeof(sa));

    target->is_ssl = origin->scheme->is_ssl;
    target->type = detect_target_type(origin, &host, &port, &sa, &salen);
    target->peer.host = h2o_strdup(NULL, host.base, host.len);
    target->peer.port = port;

    switch (target->type) {
    case H2O_SOCKETPOOL_TYPE_NAMED:
        target->peer.named_serv.base = h2o_mem_alloc(sizeof(H2O_UINT16_LONGEST_STR));
        target->peer.named_serv.len = sprintf(target->peer.named_serv.base, "%u", (unsigned)port);
        break;
    case H2O_SOCKETPOOL_TYPE_SOCKADDR:
        assert(salen <= sizeof(target->peer.sockaddr.bytes));
        memcpy(&target->peer.sockaddr.bytes, &sa, salen);
        target->peer.sockaddr.len = salen;
        break;
    }

    target->url = h2o_mem_alloc(sizeof(*target->url));
    h2o_url_copy(NULL, target->url, origin);
    h2o_linklist_init_anchor(&target->_shared.sockets);
}

void h2o_socketpool_init_specific(h2o_socketpool_t *pool, size_t capacity, h2o_url_t *origins, size_t origin_len)
{
    int i;
    h2o_socketpool_target_vector_t targets = {};

    h2o_vector_reserve(NULL, &targets, origin_len);
    for (i = 0; i != origin_len; ++i) {
        init_target(&targets.entries[i], &origins[i]);
    }
    targets.size = origin_len;

    common_init(pool, targets, capacity, lb_rr_init, lb_rr_selector, lb_rr_dispose);
}

static inline int is_global_pool(h2o_socketpool_t *pool)
{
    return pool->_lb.selector == NULL;
}

static size_t add_target(h2o_socketpool_t *pool, h2o_url_t *origin)
{
    assert(is_global_pool(pool));
    h2o_vector_reserve(NULL, &pool->targets, pool->targets.size + 1);
    init_target(&pool->targets.entries[pool->targets.size++], origin);
    return pool->targets.size - 1;
}

void h2o_socketpool_init_global(h2o_socketpool_t *pool, size_t capacity)
{
    common_init(pool, (h2o_socketpool_target_vector_t){}, capacity, NULL, NULL, NULL);
}

void dispose_target(h2o_socketpool_target_t *target)
{
    free(target->peer.host.base);
    switch (target->type) {
    case H2O_SOCKETPOOL_TYPE_NAMED:
        free(target->peer.named_serv.base);
        break;
    case H2O_SOCKETPOOL_TYPE_SOCKADDR:
        break;
    }
    if (target->url != NULL) {
        free(target->url->authority.base);
        free(target->url->host.base);
        free(target->url->path.base);
        free(target->url);
    }
}

void h2o_socketpool_dispose(h2o_socketpool_t *pool)
{
    size_t i;

    pthread_mutex_lock(&pool->_shared.mutex);
    while (!h2o_linklist_is_empty(&pool->_shared.sockets)) {
        struct pool_entry_t *entry = H2O_STRUCT_FROM_MEMBER(struct pool_entry_t, all_link, pool->_shared.sockets.next);
        destroy_attached(entry);
        __sync_sub_and_fetch(&pool->_shared.count, 1);
    }
    pthread_mutex_unlock(&pool->_shared.mutex);
    pthread_mutex_destroy(&pool->_shared.mutex);

    if (pool->_lb.dispose != NULL)
        pool->_lb.dispose(pool->_lb.data);

    if (pool->_interval_cb.loop != NULL) {
        h2o_timeout_unlink(&pool->_interval_cb.entry);
        h2o_timeout_dispose(pool->_interval_cb.loop, &pool->_interval_cb.timeout);
    }

    for (i = 0; i < pool->targets.size; i++) {
        dispose_target(&pool->targets.entries[i]);
    }
    free(pool->targets.entries);
}

void h2o_socketpool_set_timeout(h2o_socketpool_t *pool, h2o_loop_t *loop, uint64_t msec)
{
    assert(pool->_interval_cb.loop == NULL);

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
    h2o_socketpool_target_t *selected_target = &req->pool->targets.entries[req->selected_target];

    if (req->lb.tried != NULL) {
        free(req->lb.tried);
    }

    free(req);
    cb(sock, errstr, data, selected_target->url);
}

static void try_connect(h2o_socketpool_connect_request_t *req)
{
    h2o_socketpool_target_t *target;

    if (req->lb.tried != NULL) {
        /* do load balancing */
        req->selected_target = req->pool->_lb.selector(&req->pool->targets, req->pool->_lb.data, req->lb.tried);
        assert(!req->lb.tried[req->selected_target]);
        req->lb.try_count++;
        req->lb.tried[req->selected_target] = 1;
    }
    target = &req->pool->targets.entries[req->selected_target];

    switch (target->type) {
    case H2O_SOCKETPOOL_TYPE_NAMED:
        /* resolve the name, and connect */
        req->getaddr_req = h2o_hostinfo_getaddr(req->getaddr_receiver, target->peer.host, target->peer.named_serv, AF_UNSPEC,
                                                SOCK_STREAM, IPPROTO_TCP, AI_ADDRCONFIG | AI_NUMERICSERV, on_getaddr, req);
        break;
    case H2O_SOCKETPOOL_TYPE_SOCKADDR:
        /* connect (using sockaddr_in) */
        start_connect(req, (void *)&target->peer.sockaddr.bytes, target->peer.sockaddr.len);
        break;
    }
}

static void on_connect(h2o_socket_t *sock, const char *err)
{
    h2o_socketpool_connect_request_t *req = sock->data;
    const char *errstr = NULL;

    assert(req->sock == sock);

    if (err != NULL) {
        h2o_socket_close(sock);
        if (is_global_pool(req->pool) || req->lb.try_count == req->pool->targets.size) {
            req->sock = NULL;
            errstr = "connection failed";
        } else {
            try_connect(req);
            return;
        }
    }
    call_connect_cb(req, errstr);
}

static void on_close(void *data)
{
    struct on_close_data_t *close_data = data;
    h2o_socketpool_t *pool = close_data->pool;
    free(close_data);
    __sync_sub_and_fetch(&pool->_shared.count, 1);
}

static void start_connect(h2o_socketpool_connect_request_t *req, struct sockaddr *addr, socklen_t addrlen)
{
    struct on_close_data_t *close_data;

    req->sock = h2o_socket_connect(req->loop, addr, addrlen, on_connect);
    if (req->sock == NULL) {
        __sync_sub_and_fetch(&req->pool->_shared.count, 1);
        call_connect_cb(req, "failed to connect to host");
        return;
    }
    close_data = h2o_mem_alloc(sizeof(*close_data));
    close_data->pool = req->pool;
    close_data->target = req->selected_target;
    req->sock->data = req;
    req->sock->on_close.cb = on_close;
    req->sock->on_close.data = close_data;
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

static size_t lookup_target(h2o_socketpool_t *pool, h2o_url_t *url)
{
    uint16_t port = h2o_url_get_port(url);
    size_t i = 0;
    for (; i != pool->targets.size; ++i) {
        h2o_socketpool_target_t *target = &pool->targets.entries[i];
        if (target->is_ssl != url->scheme->is_ssl)
            continue;
        if (target->peer.port == 0 || target->peer.port != port)
            continue;
        if (memcmp(target->peer.host.base, url->host.base, url->host.len) != 0)
            continue;
        return i;
    }
    return SIZE_MAX;
}

void h2o_socketpool_connect(h2o_socketpool_connect_request_t **_req, h2o_socketpool_t *pool, h2o_url_t *url, h2o_loop_t *loop,
                            h2o_multithread_receiver_t *getaddr_receiver, h2o_socketpool_connect_cb cb, void *data)
{
    struct pool_entry_t *entry = NULL;
    struct on_close_data_t *close_data;

    if (_req != NULL)
        *_req = NULL;

    size_t target = SIZE_MAX;
    h2o_linklist_t *sockets = NULL;

    /* fetch an entry and return it */
    pthread_mutex_lock(&pool->_shared.mutex);
    destroy_expired(pool);

    /* TODO is this needed in this critical section? */
    if (is_global_pool(pool)) {
        target = lookup_target(pool, url);
        if (target == SIZE_MAX) {
            target = add_target(pool, url);
        }
        sockets = &pool->targets.entries[target]._shared.sockets;
    } else {
        sockets = &pool->_shared.sockets;
    }
    assert(pool->targets.size != 0);

    while (!h2o_linklist_is_empty(sockets)) {
        if (is_global_pool(pool)) {
            entry = H2O_STRUCT_FROM_MEMBER(struct pool_entry_t, target_link, sockets->next);
        } else {
            entry = H2O_STRUCT_FROM_MEMBER(struct pool_entry_t, all_link, sockets->next);
        }
        h2o_linklist_unlink(&entry->all_link);
        h2o_linklist_unlink(&entry->target_link);
        pthread_mutex_unlock(&pool->_shared.mutex);

        /* test if the connection is still alive */
        char buf[1];
        ssize_t rret = recv(entry->sockinfo.fd, buf, 1, MSG_PEEK);
        if (rret == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            /* yes! return it */
            size_t entry_target = entry->target;
            h2o_socket_t *sock = h2o_socket_import(loop, &entry->sockinfo);
            free(entry);
            close_data = h2o_mem_alloc(sizeof(*close_data));
            close_data->pool = pool;
            close_data->target = entry_target;
            sock->on_close.cb = on_close;
            sock->on_close.data = close_data;
            cb(sock, NULL, data, pool->targets.entries[entry_target].url);
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
    req->getaddr_receiver = getaddr_receiver;

    req->selected_target = target;
    if (target == SIZE_MAX) {
        req->lb.tried = h2o_mem_alloc(sizeof(int) * pool->targets.size);
        memset(req->lb.tried, 0, sizeof(int) * pool->targets.size);
        req->lb.try_count = 0;
    }
    try_connect(req);
}

void h2o_socketpool_cancel_connect(h2o_socketpool_connect_request_t *req)
{
    if (req->getaddr_req != NULL) {
        h2o_hostinfo_getaddr_cancel(req->getaddr_req);
        req->getaddr_req = NULL;
    }
    if (req->sock != NULL)
        h2o_socket_close(req->sock);
    if (req->lb.tried != NULL)
        free(req->lb.tried);
    free(req);
}

int h2o_socketpool_return(h2o_socketpool_t *pool, h2o_socket_t *sock)
{
    struct pool_entry_t *entry;
    struct on_close_data_t *close_data;
    size_t target;

    close_data = sock->on_close.data;
    target = close_data->target;
    /* reset the on_close callback */
    assert(close_data->pool == pool);
    free(close_data);
    sock->on_close.cb = NULL;
    sock->on_close.data = NULL;

    entry = h2o_mem_alloc(sizeof(*entry));
    if (h2o_socket_export(sock, &entry->sockinfo) != 0) {
        free(entry);
        __sync_sub_and_fetch(&pool->_shared.count, 1);
        return -1;
    }
    memset(&entry->all_link, 0, sizeof(entry->all_link));
    memset(&entry->target_link, 0, sizeof(entry->target_link));
    entry->added_at = h2o_now(h2o_socket_get_loop(sock));
    entry->target = target;

    pthread_mutex_lock(&pool->_shared.mutex);
    destroy_expired(pool);
    h2o_linklist_insert(&pool->_shared.sockets, &entry->all_link);
    h2o_linklist_insert(&pool->targets.entries[target]._shared.sockets, &entry->target_link);
    pthread_mutex_unlock(&pool->_shared.mutex);
    return 0;
}

static pthread_mutex_t init_lock = PTHREAD_MUTEX_INITIALIZER;
static h2o_socketpool_t *default_socketpool = NULL;

h2o_socketpool_t *h2o_socketpool_get_default_socketpool(h2o_loop_t *loop)
{
    if (default_socketpool == NULL) {
        pthread_mutex_lock(&init_lock);
        if (default_socketpool == NULL) {
            h2o_socketpool_t *sockpool = h2o_mem_alloc(sizeof(*sockpool));
            h2o_socketpool_init_global(sockpool, SIZE_MAX /* FIXME */);
            h2o_socketpool_set_timeout(sockpool, loop, 2000);
            __sync_synchronize();
            default_socketpool = sockpool;
        }
        pthread_mutex_unlock(&init_lock);
    }
    return default_socketpool;
}

void h2o_socketpool_set_default_socketpool(h2o_socketpool_t *socketpool)
{
    pthread_mutex_lock(&init_lock);
    if (default_socketpool != NULL)
        h2o_socketpool_dispose(default_socketpool);
    default_socketpool = socketpool;
    pthread_mutex_unlock(&init_lock);
}

int h2o_socketpool_can_keepalive(h2o_socketpool_t *pool)
{
    return pool->timeout > 0;
}
