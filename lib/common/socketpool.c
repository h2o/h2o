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
#include "h2o/socket.h"
#include "h2o/balancer.h"

/**
 * timeout will be set to this value when calculated less than this value
 */
#define CHECK_EXPIRATION_MIN_INTERVAL 1000

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
    size_t remaining_try_count;
    struct {
        char *tried;
    } lb;
    h2o_iovec_t alpn_protos;
};

struct on_close_data_t {
    h2o_socketpool_t *pool;
    size_t target;
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

/* caller should lock the mutex */
static uint64_t destroy_expired_locked(h2o_socketpool_t *pool)
{
    if (pool->_interval_cb.loop != NULL) {
        uint64_t now_ms = h2o_now(pool->_interval_cb.loop);
        uint64_t expire_before = now_ms - pool->timeout;
        while (!h2o_linklist_is_empty(&pool->_shared.sockets)) {
            struct pool_entry_t *entry = H2O_STRUCT_FROM_MEMBER(struct pool_entry_t, all_link, pool->_shared.sockets.next);
            if (entry->added_at > expire_before) {
                return entry->added_at + pool->timeout - now_ms;
            }
            destroy_attached(entry);
            __sync_sub_and_fetch(&pool->_shared.count, 1);
            __sync_sub_and_fetch(&pool->_shared.pooled_count, 1);
        }
    }
    return UINT64_MAX;
}

/* caller should lock the mutex */
static void check_pool_expired_locked(h2o_socketpool_t *pool)
{
    uint64_t next_expired = destroy_expired_locked(pool);
    if (next_expired != UINT64_MAX) {
        if (!h2o_timer_is_linked(&pool->_interval_cb.timeout)) {
            if (next_expired < CHECK_EXPIRATION_MIN_INTERVAL)
                next_expired = CHECK_EXPIRATION_MIN_INTERVAL;
            h2o_timer_link(pool->_interval_cb.loop, next_expired, &pool->_interval_cb.timeout);
        }
    }
}

static void on_timeout(h2o_timer_t *timeout)
{
    /* decrease the frequency of this function being called; the expiration
     * check can be (should be) performed in the `connect` fuction as well
     */
    h2o_socketpool_t *pool = H2O_STRUCT_FROM_MEMBER(h2o_socketpool_t, _interval_cb.timeout, timeout);

    if (pthread_mutex_trylock(&pool->_shared.mutex) == 0) {
        check_pool_expired_locked(pool);
        pthread_mutex_unlock(&pool->_shared.mutex);
    }
}

static void common_init(h2o_socketpool_t *pool, h2o_socketpool_target_t **targets, size_t num_targets, size_t capacity,
                        h2o_balancer_t *balancer)
{
    memset(pool, 0, sizeof(*pool));

    pool->capacity = capacity;
    pool->timeout = 2000;

    pthread_mutex_init(&pool->_shared.mutex, NULL);
    h2o_linklist_init_anchor(&pool->_shared.sockets);

    h2o_vector_reserve(NULL, &pool->targets, num_targets);
    for (; pool->targets.size < num_targets; ++pool->targets.size)
        pool->targets.entries[pool->targets.size] = targets[pool->targets.size];

    pool->balancer = balancer;
}

h2o_socketpool_target_type_t detect_target_type(h2o_url_t *url, struct sockaddr_storage *sa, socklen_t *salen)
{
    memset(sa, 0, sizeof(*sa));
    const char *to_sun_err = h2o_url_host_to_sun(url->host, (struct sockaddr_un *)sa);
    if (to_sun_err == h2o_url_host_to_sun_err_is_not_unix_socket) {
        sa->ss_family = AF_INET;
        struct sockaddr_in *sin = (struct sockaddr_in *)sa;
        *salen = sizeof(*sin);

        if (h2o_hostinfo_aton(url->host, &sin->sin_addr) == 0) {
            sin->sin_port = htons(h2o_url_get_port(url));
            return H2O_SOCKETPOOL_TYPE_SOCKADDR;
        } else {
            return H2O_SOCKETPOOL_TYPE_NAMED;
        }
    } else {
        assert(to_sun_err == NULL);
        *salen = sizeof(struct sockaddr_un);
        return H2O_SOCKETPOOL_TYPE_SOCKADDR;
    }
}

h2o_socketpool_target_t *h2o_socketpool_create_target(h2o_url_t *origin, h2o_socketpool_target_conf_t *lb_target_conf)
{
    struct sockaddr_storage sa;
    socklen_t salen;

    h2o_socketpool_target_t *target = h2o_mem_alloc(sizeof(*target));
    h2o_url_copy(NULL, &target->url, origin);
    assert(target->url.host.base[target->url.host.len] == '\0'); /* needs to be null-terminated in order to be used in SNI */
    target->type = detect_target_type(origin, &sa, &salen);
    if (!(target->type == H2O_SOCKETPOOL_TYPE_SOCKADDR && sa.ss_family == AF_UNIX)) {
        h2o_strtolower(target->url.authority.base, target->url.authority.len);
        h2o_strtolower(target->url.host.base, target->url.host.len);
    }

    switch (target->type) {
    case H2O_SOCKETPOOL_TYPE_NAMED:
        target->peer.named_serv.base = h2o_mem_alloc(sizeof(H2O_UINT16_LONGEST_STR));
        target->peer.named_serv.len = sprintf(target->peer.named_serv.base, "%u", (unsigned)h2o_url_get_port(&target->url));
        break;
    case H2O_SOCKETPOOL_TYPE_SOCKADDR:
        assert(salen <= sizeof(target->peer.sockaddr.bytes));
        memcpy(&target->peer.sockaddr.bytes, &sa, salen);
        target->peer.sockaddr.len = salen;
        break;
    }
    target->_shared.leased_count = 0;
    if (lb_target_conf != NULL)
        target->conf.weight_m1 = lb_target_conf->weight_m1;
    else {
        target->conf.weight_m1 = 0;
    }

    h2o_linklist_init_anchor(&target->_shared.sockets);
    return target;
}

void h2o_socketpool_init_specific(h2o_socketpool_t *pool, size_t capacity, h2o_socketpool_target_t **targets, size_t num_targets,
                                  h2o_balancer_t *balancer)
{
    if (balancer == NULL)
        balancer = h2o_balancer_create_rr();
    common_init(pool, targets, num_targets, capacity, balancer);
}

static inline int is_global_pool(h2o_socketpool_t *pool)
{
    return pool->balancer == NULL;
}

void h2o_socketpool_init_global(h2o_socketpool_t *pool, size_t capacity)
{
    common_init(pool, NULL, 0, capacity, NULL);
}

void h2o_socketpool_destroy_target(h2o_socketpool_target_t *target)
{
    switch (target->type) {
    case H2O_SOCKETPOOL_TYPE_NAMED:
        free(target->peer.named_serv.base);
        break;
    case H2O_SOCKETPOOL_TYPE_SOCKADDR:
        break;
    }
    free(target->url.authority.base);
    free(target->url.host.base);
    free(target->url.path.base);
    free(target);
}

void h2o_socketpool_dispose(h2o_socketpool_t *pool)
{
    size_t i;

    pthread_mutex_lock(&pool->_shared.mutex);
    while (!h2o_linklist_is_empty(&pool->_shared.sockets)) {
        struct pool_entry_t *entry = H2O_STRUCT_FROM_MEMBER(struct pool_entry_t, all_link, pool->_shared.sockets.next);
        destroy_attached(entry);
        __sync_sub_and_fetch(&pool->_shared.count, 1);
        __sync_sub_and_fetch(&pool->_shared.pooled_count, 1);
    }
    pthread_mutex_unlock(&pool->_shared.mutex);
    pthread_mutex_destroy(&pool->_shared.mutex);

    if (pool->balancer != NULL) {
        pool->balancer->callbacks->destroy(pool->balancer);
    }

    if (pool->_ssl_ctx != NULL)
        SSL_CTX_free(pool->_ssl_ctx);

    if (pool->_interval_cb.loop != NULL)
        h2o_socketpool_unregister_loop(pool, pool->_interval_cb.loop);

    for (i = 0; i < pool->targets.size; i++) {
        h2o_socketpool_destroy_target(pool->targets.entries[i]);
    }
    free(pool->targets.entries);
}

void h2o_socketpool_set_ssl_ctx(h2o_socketpool_t *pool, SSL_CTX *ssl_ctx)
{
    if (pool->_ssl_ctx != NULL)
        SSL_CTX_free(pool->_ssl_ctx);
    if (ssl_ctx != NULL)
        SSL_CTX_up_ref(ssl_ctx);
    pool->_ssl_ctx = ssl_ctx;
}

void h2o_socketpool_register_loop(h2o_socketpool_t *pool, h2o_loop_t *loop)
{
    if (pool->_interval_cb.loop != NULL)
        return;

    pool->_interval_cb.loop = loop;
    h2o_timer_init(&pool->_interval_cb.timeout, on_timeout);
    h2o_timer_link(loop, CHECK_EXPIRATION_MIN_INTERVAL, &pool->_interval_cb.timeout);
}

void h2o_socketpool_unregister_loop(h2o_socketpool_t *pool, h2o_loop_t *loop)
{
    if (pool->_interval_cb.loop != loop)
        return;
    h2o_timer_unlink(&pool->_interval_cb.timeout);
    pool->_interval_cb.loop = NULL;
}

static void call_connect_cb(h2o_socketpool_connect_request_t *req, const char *errstr)
{
    h2o_socketpool_connect_cb cb = req->cb;
    h2o_socket_t *sock = req->sock;
    void *data = req->data;
    h2o_socketpool_target_t *selected_target = req->pool->targets.entries[req->selected_target];

    if (req->lb.tried != NULL) {
        free(req->lb.tried);
    }

    free(req);

    if (sock != NULL)
        sock->data = NULL;
    cb(sock, errstr, data, &selected_target->url);
}

static void try_connect(h2o_socketpool_connect_request_t *req)
{
    h2o_socketpool_target_t *target;

    req->remaining_try_count--;

    if (req->lb.tried != NULL) {
        if (req->pool->targets.size > 1) {
            req->selected_target = req->pool->balancer->callbacks->select_(req->pool->balancer, &req->pool->targets, req->lb.tried);
            assert(!req->lb.tried[req->selected_target]);
            req->lb.tried[req->selected_target] = 1;
        } else {
            req->selected_target = 0;
        }
    }
    target = req->pool->targets.entries[req->selected_target];
    __sync_add_and_fetch(&req->pool->targets.entries[req->selected_target]->_shared.leased_count, 1);

    switch (target->type) {
    case H2O_SOCKETPOOL_TYPE_NAMED:
        /* resolve the name, and connect */
        req->getaddr_req = h2o_hostinfo_getaddr(req->getaddr_receiver, target->url.host, target->peer.named_serv, AF_UNSPEC,
                                                SOCK_STREAM, IPPROTO_TCP, AI_ADDRCONFIG | AI_NUMERICSERV, on_getaddr, req);
        break;
    case H2O_SOCKETPOOL_TYPE_SOCKADDR:
        /* connect (using sockaddr_in) */
        start_connect(req, (void *)&target->peer.sockaddr.bytes, target->peer.sockaddr.len);
        break;
    }
}

static void on_handshake_complete(h2o_socket_t *sock, const char *err)
{
    h2o_socketpool_connect_request_t *req = sock->data;

    assert(req->sock == sock);

    if (err == h2o_socket_error_ssl_cert_name_mismatch && (SSL_CTX_get_verify_mode(req->pool->_ssl_ctx) & SSL_VERIFY_PEER) == 0) {
        /* ignore CN mismatch if we are not verifying peer */
    } else if (err != NULL) {
        h2o_socket_close(sock);
        req->sock = NULL;
    }

    call_connect_cb(req, err);
}

static void on_connect(h2o_socket_t *sock, const char *err)
{
    h2o_socketpool_connect_request_t *req = sock->data;

    assert(req->sock == sock);

    if (err != NULL) {
        __sync_sub_and_fetch(&req->pool->targets.entries[req->selected_target]->_shared.leased_count, 1);
        h2o_socket_close(sock);
        if (req->remaining_try_count > 0) {
            try_connect(req);
            return;
        }
        __sync_sub_and_fetch(&req->pool->_shared.count, 1);
        req->sock = NULL;
    } else {
        h2o_url_t *target_url = &req->pool->targets.entries[req->selected_target]->url;
        if (target_url->scheme->is_ssl) {
            assert(req->pool->_ssl_ctx != NULL && "h2o_socketpool_set_ssl_ctx must be called for a pool that contains SSL target");
            h2o_socket_ssl_handshake(sock, req->pool->_ssl_ctx, target_url->host.base, req->alpn_protos, on_handshake_complete);
            return;
        }
    }

    call_connect_cb(req, err);
}

static void on_close(void *data)
{
    struct on_close_data_t *close_data = data;
    h2o_socketpool_t *pool = close_data->pool;
    __sync_sub_and_fetch(&pool->targets.entries[close_data->target]->_shared.leased_count, 1);
    free(close_data);
    __sync_sub_and_fetch(&pool->_shared.count, 1);
}

static void start_connect(h2o_socketpool_connect_request_t *req, struct sockaddr *addr, socklen_t addrlen)
{
    struct on_close_data_t *close_data;

    req->sock = h2o_socket_connect(req->loop, addr, addrlen, on_connect);
    if (req->sock == NULL) {
        __sync_sub_and_fetch(&req->pool->targets.entries[req->selected_target]->_shared.leased_count, 1);
        if (req->remaining_try_count > 0) {
            try_connect(req);
            return;
        }
        __sync_sub_and_fetch(&req->pool->_shared.count, 1);
        call_connect_cb(req, h2o_socket_error_conn_fail);
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
        __sync_sub_and_fetch(&req->pool->targets.entries[req->selected_target]->_shared.leased_count, 1);
        if (req->remaining_try_count > 0) {
            try_connect(req);
            return;
        }
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
        h2o_socketpool_target_t *target = pool->targets.entries[i];
        if (target->url.scheme != url->scheme)
            continue;
        if (h2o_url_get_port(&target->url) != port)
            continue;
        if (!h2o_url_hosts_are_equal(&target->url, url))
            continue;
        return i;
    }
    return SIZE_MAX;
}

void h2o_socketpool_connect(h2o_socketpool_connect_request_t **_req, h2o_socketpool_t *pool, h2o_url_t *url, h2o_loop_t *loop,
                            h2o_multithread_receiver_t *getaddr_receiver, h2o_iovec_t alpn_protos, h2o_socketpool_connect_cb cb,
                            void *data)
{
    struct pool_entry_t *entry = NULL;
    struct on_close_data_t *close_data;

    if (_req != NULL)
        *_req = NULL;

    size_t target = SIZE_MAX;
    h2o_linklist_t *sockets = NULL;

    /* fetch an entry and return it */
    pthread_mutex_lock(&pool->_shared.mutex);
    check_pool_expired_locked(pool);

    /* TODO lookup outside this critical section */
    if (is_global_pool(pool)) {
        target = lookup_target(pool, url);
        if (target == SIZE_MAX) {
            h2o_vector_reserve(NULL, &pool->targets, pool->targets.size + 1);
            pool->targets.entries[pool->targets.size++] = h2o_socketpool_create_target(url, NULL);
            target = pool->targets.size - 1;
        }
        sockets = &pool->targets.entries[target]->_shared.sockets;
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

        __sync_sub_and_fetch(&pool->_shared.pooled_count, 1);

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
            __sync_add_and_fetch(&pool->targets.entries[entry_target]->_shared.leased_count, 1);
            cb(sock, NULL, data, &pool->targets.entries[entry_target]->url);
            return;
        }

        /* connection is dead, report, close, and retry */
        if (rret <= 0) {
            static long counter = 0;
            if (__sync_fetch_and_add(&counter, 1) == 0)
                h2o_error_printf("[WARN] detected close by upstream before the expected timeout (see issue #679)\n");
        } else {
            static long counter = 0;
            if (__sync_fetch_and_add(&counter, 1) == 0)
                h2o_error_printf("[WARN] unexpectedly received data to a pooled socket (see issue #679)\n");
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
    req->alpn_protos = alpn_protos;

    req->selected_target = target;
    if (target == SIZE_MAX) {
        req->lb.tried = h2o_mem_alloc(sizeof(req->lb.tried[0]) * pool->targets.size);
        memset(req->lb.tried, 0, sizeof(req->lb.tried[0]) * pool->targets.size);
        req->remaining_try_count = pool->targets.size;
    } else {
        req->remaining_try_count = 1;
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
    if (req->lb.tried != NULL) {
        free(req->lb.tried);
        __sync_sub_and_fetch(&req->pool->targets.entries[req->selected_target]->_shared.leased_count, 1);
    }
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
    __sync_sub_and_fetch(&pool->targets.entries[close_data->target]->_shared.leased_count, 1);
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

    __sync_add_and_fetch(&pool->_shared.pooled_count, 1);

    pthread_mutex_lock(&pool->_shared.mutex);
    check_pool_expired_locked(pool);
    h2o_linklist_insert(&pool->_shared.sockets, &entry->all_link);
    h2o_linklist_insert(&pool->targets.entries[target]->_shared.sockets, &entry->target_link);
    pthread_mutex_unlock(&pool->_shared.mutex);
    return 0;
}

void h2o_socketpool_detach(h2o_socketpool_t *pool, h2o_socket_t *sock)
{
    struct on_close_data_t *close_data = sock->on_close.data;
    assert(close_data->pool == pool);

    __sync_sub_and_fetch(&pool->targets.entries[close_data->target]->_shared.leased_count, 1);
    __sync_sub_and_fetch(&pool->_shared.count, 1);

    sock->on_close.cb = NULL;
    sock->on_close.data = NULL;
    free(close_data);
}

int h2o_socketpool_can_keepalive(h2o_socketpool_t *pool)
{
    return pool->timeout > 0;
}
