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
#ifndef h2o__socket_pool_h
#define h2o__socket_pool_h

#ifdef __cplusplus
extern "C" {
#endif

#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include "h2o/linklist.h"
#include "h2o/multithread.h"
#include "h2o/socket.h"
#include "h2o/timeout.h"
#include "h2o/url.h"

typedef enum en_h2o_socketpool_target_type_t {
    H2O_SOCKETPOOL_TYPE_NAMED,
    H2O_SOCKETPOOL_TYPE_SOCKADDR
} h2o_socketpool_target_type_t;

/**
 * TODO: support subclassing for adding balancer-specific properties
 */
typedef struct st_h2o_socketpool_target_conf_t {
    /**
     * weight - 1 for load balancer, where weight is an integer within range [1, 256]
     */
    uint8_t weight_m1;
} h2o_socketpool_target_conf_t;

#define H2O_SOCKETPOOL_TARGET_MAX_WEIGHT 256

typedef struct st_h2o_socketpool_target_t {
    /**
     * target URL
     */
    h2o_url_t url;
    /**
     * target type (extracted from url)
     */
    h2o_socketpool_target_type_t type;
    /**
     * peer address (extracted from url)
     */
    union {
        /* used to specify servname passed to getaddrinfo */
        h2o_iovec_t named_serv;
        /* if type is sockaddr, the `host` is not resolved but is used for TLS SNI and hostname verification */
        struct {
            struct sockaddr_storage bytes;
            socklen_t len;
        } sockaddr;
    } peer;
    /**
     * per-target lb configuration
     */
    h2o_socketpool_target_conf_t conf;

    /**
     * the per-target portion of h2o_socketpool_t::_shared
     */
    struct {
        h2o_linklist_t sockets;
        /**
         * number of connections being _leased_ to the applications (i.e. not including the number of connections being pooled).
         * Synchronous operation must be used to access the variable.
         */
        size_t leased_count;
    } _shared;
} h2o_socketpool_target_t;

typedef H2O_VECTOR(h2o_socketpool_target_t *) h2o_socketpool_target_vector_t;

typedef struct st_h2o_balancer_t h2o_balancer_t;

typedef struct st_h2o_socketpool_t {

    /* read-only vars */
    h2o_socketpool_target_vector_t targets;
    size_t capacity;
    uint64_t timeout; /* in milliseconds */
    struct {
        h2o_loop_t *loop;
        h2o_timeout_t timeout;
        h2o_timeout_entry_t entry;
    } _interval_cb;
    SSL_CTX *_ssl_ctx;

    /**
     * variables shared between threads. Unless otherwise noted, the mutex should be acquired before accessing them.
     */
    struct {
        pthread_mutex_t mutex;
        /**
         * list of struct pool_entry_t
         */
        h2o_linklist_t sockets;
        /**
         * number of connections governed by the pool, includes sockets being pool and the ones trying to connect. Synchronous
         * operation must be used to access the variable.
         */
        size_t count;
        /**
         * number of pooled connections governed by the pool
         */
        size_t pooled_count;
    } _shared;

    /* load balancer */
    h2o_balancer_t *balancer;
} h2o_socketpool_t;

typedef struct st_h2o_socketpool_connect_request_t h2o_socketpool_connect_request_t;

typedef void (*h2o_socketpool_connect_cb)(h2o_socket_t *sock, const char *errstr, void *data, h2o_url_t *url, h2o_iovec_t alpn_proto);
/**
 * initializes a specific socket pool
 */
void h2o_socketpool_init_specific(h2o_socketpool_t *pool, size_t capacity, h2o_socketpool_target_t **targets, size_t num_targets,
                                  h2o_balancer_t *balancer);
/**
 * initializes a global socket pool
 */
void h2o_socketpool_init_global(h2o_socketpool_t *pool, size_t capacity);
/**
 * disposes of a socket loop
 */
void h2o_socketpool_dispose(h2o_socketpool_t *pool);
/**
 * create a target. If lb_target_conf is NULL, a default target conf would be created.
 */
h2o_socketpool_target_t *h2o_socketpool_create_target(h2o_url_t *origin, h2o_socketpool_target_conf_t *lb_target_conf);
/**
 * destroy a target
 */
void h2o_socketpool_destroy_target(h2o_socketpool_target_t *target);
/**
 *
 */
static uint64_t h2o_socketpool_get_timeout(h2o_socketpool_t *pool);
/**
 *
 */
static void h2o_socketpool_set_timeout(h2o_socketpool_t *pool, uint64_t msec);
/**
 *
 */
void h2o_socketpool_set_ssl_ctx(h2o_socketpool_t *pool, SSL_CTX *ssl_ctx);
/**
 * associates a loop
 */
void h2o_socketpool_register_loop(h2o_socketpool_t *pool, h2o_loop_t *loop);
/**
 * unregisters the associated loop
 */
void h2o_socketpool_unregister_loop(h2o_socketpool_t *pool, h2o_loop_t *loop);
/**
 * connects to the peer (or returns a pooled connection)
 */
void h2o_socketpool_connect(h2o_socketpool_connect_request_t **_req, h2o_socketpool_t *pool, h2o_url_t *url, h2o_loop_t *loop,
                            h2o_multithread_receiver_t *getaddr_receiver, h2o_iovec_t alpn_protos, h2o_socketpool_connect_cb cb, void *data);
/**
 * cancels a connect request
 */
void h2o_socketpool_cancel_connect(h2o_socketpool_connect_request_t *req);
/**
 * returns an idling socket to the socket pool
 */
int h2o_socketpool_return(h2o_socketpool_t *pool, h2o_socket_t *sock);
/**
 * detach a socket from the socket pool
 */
void h2o_socketpool_detach(h2o_socketpool_t *pool, h2o_socket_t *sock);
/**
 * determines if a socket belongs to the socket pool
 */
static int h2o_socketpool_is_owned_socket(h2o_socketpool_t *pool, h2o_socket_t *sock);

/* inline defs */

inline uint64_t h2o_socketpool_get_timeout(h2o_socketpool_t *pool)
{
    return pool->timeout;
}

inline void h2o_socketpool_set_timeout(h2o_socketpool_t *pool, uint64_t msec)
{
    pool->timeout = msec;
}

inline int h2o_socketpool_is_owned_socket(h2o_socketpool_t *pool, h2o_socket_t *sock)
{
    return sock->on_close.data == pool;
}

int h2o_socketpool_can_keepalive(h2o_socketpool_t *pool);

#ifdef __cplusplus
}
#endif

#endif
