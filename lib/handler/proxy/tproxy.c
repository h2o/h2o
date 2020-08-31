/*
 * Copyright (c) 2020 Chul-Woong Yang
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

#include "khash.h"
#include "h2o.h"
#include "h2o/tproxy.h"

/*
 * The main purpose of tproxy module is to keep per-client connpool & sockpool.
 *
 * Connpool holds links to h1 sockpool and links to h2 sock lists.
 * Connpool is per-thread structure (h2o decision), while sockpool is not. (sockpool is shared)
 *
 * New req lookups connpool. create if not exist.
 * Connpool lookups sockpool. create if not exist.
 * h2o_cache keeps connpool and sockpool and free idle pools for regular interval.
 * sockpool must not be freed when connpool is exist
 */

typedef uint32_t /* eq. khint_t */ h2o_connpool_hashcode_t;
static h2o_cache_t *sockpool_cache = NULL;

typedef struct st_h2o_connpool_key_t
{
    uint8_t saddr[16];
    uint8_t daddr[16];
    uint16_t dport;
} h2o_connpool_key_t;

static int make_connpool_key(h2o_req_t *req, h2o_connpool_key_t *key)
{
    h2o_sockaddr_pair_t sp;
    if (!req->conn)
        return -1;
    sp.src.len = req->conn->callbacks->get_sockname(req->conn, (void *)&sp.src.bytes);
    sp.dst.len = req->conn->callbacks->get_sockname(req->conn, (void *)&sp.dst.bytes);

    if (sp.src.bytes.ss_family == AF_INET6) {
        memcpy(key->saddr, (void *)&((struct sockaddr_in6 *) &sp.src.bytes)->sin6_addr, 16);
        memcpy(key->daddr, (void *)&((struct sockaddr_in6 *) &sp.dst.bytes)->sin6_addr, 16);
        key->dport = ((struct sockaddr_in6 *) &sp.dst.bytes)->sin6_port;
    } else {
        *key = (h2o_connpool_key_t) {};
        memcpy(key->saddr+12, (void *)&((struct sockaddr_in *) &sp.src.bytes)->sin_addr, 4);
        memcpy(key->daddr+12, (void *)&((struct sockaddr_in *) &sp.dst.bytes)->sin_addr, 4);
        key->dport = ((struct sockaddr_in *) &sp.dst.bytes)->sin_port;
    }
    return 0;
}

/*
 * create per-client sockpool and shallow copy socketpool_target from base_sockpool
 */
static h2o_socketpool_t *create_per_client_sockpool(h2o_socketpool_t *base_sockpool,
                                                    h2o_conn_t *conn,
                                                    size_t capacity, uint64_t keepalive_ms)
{
    assert(base_sockpool->targets.size == 1);
    h2o_socketpool_target_t *target;
    target = h2o_mem_alloc(sizeof(*target));
    *target = *(base_sockpool->targets.entries[0]);
    target->spoof_srcaddr = 1;
    target->_shared.leased_count = 0;
    target->conf.weight_m1 = 0;
    h2o_linklist_init_anchor(&target->_shared.sockets);

    h2o_socketpool_t *s = h2o_mem_alloc(sizeof(*s));
    memset(s, 0, sizeof(*s));
    /* init socket pool */
    h2o_socketpool_init_specific(s, capacity, &target, 1, NULL);
    h2o_socketpool_set_timeout(s, keepalive_ms);
    h2o_socketpool_set_ssl_ctx(s, base_sockpool->_ssl_ctx);
    s->sockpair.src.len = conn->callbacks->get_peername(conn, (void *)&s->sockpair.src.bytes);
    s->sockpair.dst.len = conn->callbacks->get_sockname(conn, (void *)&s->sockpair.dst.bytes);
    h2o_socket_setport((struct sockaddr *)&s->sockpair.src.bytes, 0);
    s->refcnt = 1;
    return s;
}

h2o_httpclient_connection_pool_t *h2o_tproxy_get_connpool(h2o_cache_t *cache, h2o_req_t *req,
                                                          h2o_proxy_config_vars_t *config,
                                                          h2o_socketpool_t *base_sockpool)
{
    h2o_connpool_key_t key;
    if (make_connpool_key(req, &key) < 0)
        return NULL;

    h2o_iovec_t cache_key = {.base = (char *) &key, .len = sizeof(key) };
    h2o_cache_hashcode_t hash = h2o_cache_calchash(cache_key.base, cache_key.len);
    h2o_cache_ref_t *cp_ref = h2o_cache_fetch(cache, h2o_now(req->conn->ctx->loop),
                                                cache_key, hash);
    h2o_httpclient_connection_pool_t *connpool;
    if (cp_ref != NULL) {
        connpool = (void *) cp_ref->value.base;
        connpool->refcnt++;
        h2o_cache_release(cache, cp_ref);
        return connpool;
    }

    h2o_cache_ref_t *sp_ref = h2o_cache_fetch(sockpool_cache, h2o_now(req->conn->ctx->loop),
                                              cache_key, hash);
    h2o_socketpool_t *sockpool;
    int new_sockpool = 0;
    if (sp_ref != NULL) {
        sockpool = (void *) sp_ref->value.base;
        __sync_add_and_fetch(&sockpool->refcnt, 1);
        h2o_cache_release(cache, sp_ref);
    } else {
        new_sockpool = 1;
        sockpool = create_per_client_sockpool(base_sockpool, req->conn, SIZE_MAX, config->keepalive_timeout);
        sockpool->refcnt ++;
        /* when race happens, previous sockpool gets out from cache and released when corresponding
           connpool puts the sockpool */
        /* But socketpool_detach() aborts at that case! */
        h2o_cache_set(sockpool_cache, h2o_now(req->conn->ctx->loop),
                      cache_key, hash,
                      h2o_iovec_init(sockpool, 1));
        /* use the loop of first context for handling socketpool timeouts */
        //sockpool->ctx = req->conn->ctx;
        h2o_socketpool_register_loop(sockpool, req->conn->ctx->loop);
    }

    connpool = h2o_httpclient_connection_pool_create(sockpool);
    connpool->refcnt++;
    h2o_cache_set(cache, h2o_now(req->conn->ctx->loop),
                  cache_key, hash,
                  h2o_iovec_init(connpool, 1));

    return connpool;
}

static void destroy_connpool_entry(h2o_iovec_t value)
{
    h2o_httpclient_connection_pool_t *connpool = (void *) value.base;
    h2o_httpclient_connection_pool_dispose(connpool);
}

static void destroy_sockpool_entry(h2o_iovec_t value)
{
    h2o_socketpool_t *sockpool = (void *) value.base;
    h2o_socketpool_dispose(sockpool);
}

h2o_cache_t *h2o_tproxy_create_connpool_cache(size_t pool_duration)
{
    if (!sockpool_cache) {
        sockpool_cache = h2o_cache_create(H2O_CACHE_FLAG_MULTITHREADED | H2O_CACHE_FLAG_AGE_UPDATE,
                                          SIZE_MAX,                 /* unlimited size cache*/
                                          pool_duration,           /* duration check */
                                          destroy_sockpool_entry);
    }
    h2o_cache_t *ret = h2o_cache_create(H2O_CACHE_FLAG_AGE_UPDATE,
                                        SIZE_MAX /* unlimited size cache*/,
                                        pool_duration /* duration check */,
                                        destroy_connpool_entry);
    return ret;
}
