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

typedef enum en_h2o_socketpool_type_t { H2O_SOCKETPOOL_TYPE_NAMED, H2O_SOCKETPOOL_TYPE_SOCKADDR } h2o_socketpool_type_t;

typedef struct st_h2o_socketpool_t {

    /* read-only vars */
    h2o_socketpool_type_t type;
    struct {
        h2o_iovec_t host;
        union {
            /* used to specify servname passed to getaddrinfo */
            h2o_iovec_t named_serv;
            /* if type is sockaddr, the `host` is not resolved but is used for TLS SNI and hostname verification */
            struct {
                struct sockaddr_storage bytes;
                socklen_t len;
            } sockaddr;
        };
    } peer;
    int is_ssl;
    size_t capacity;
    uint64_t timeout; /* in milliseconds (UINT64_MAX if not set) */
    struct {
        h2o_loop_t *loop;
        h2o_timeout_t timeout;
        h2o_timeout_entry_t entry;
    } _interval_cb;

    /* vars that are modified by multiple threads */
    struct {
        size_t count; /* synchronous operations should be used to access the variable */
        pthread_mutex_t mutex;
        h2o_linklist_t sockets; /* guarded by the mutex; list of struct pool_entry_t defined in socket/pool.c */
    } _shared;
} h2o_socketpool_t;

typedef struct st_h2o_socketpool_connect_request_t h2o_socketpool_connect_request_t;

typedef void (*h2o_socketpool_connect_cb)(h2o_socket_t *sock, const char *errstr, void *data);
/**
 * initializes a socket loop
 */
void h2o_socketpool_init_by_address(h2o_socketpool_t *pool, struct sockaddr *sa, socklen_t salen, int is_ssl, size_t capacity);
/**
 * initializes a socket loop
 */
void h2o_socketpool_init_by_hostport(h2o_socketpool_t *pool, h2o_iovec_t host, uint16_t port, int is_ssl, size_t capacity);
/**
 * disposes of a socket loop
 */
void h2o_socketpool_dispose(h2o_socketpool_t *pool);
/**
 * sets a close timeout for the sockets being pooled
 */
void h2o_socketpool_set_timeout(h2o_socketpool_t *pool, h2o_loop_t *loop, uint64_t msec);
/**
 * connects to the peer (or returns a pooled connection)
 */
void h2o_socketpool_connect(h2o_socketpool_connect_request_t **req, h2o_socketpool_t *pool, h2o_loop_t *loop,
                            h2o_multithread_receiver_t *getaddr_receiver, h2o_socketpool_connect_cb cb, void *data);
/**
 * cancels a connect request
 */
void h2o_socketpool_cancel_connect(h2o_socketpool_connect_request_t *req);
/**
 * returns an idling socket to the socket pool
 */
int h2o_socketpool_return(h2o_socketpool_t *pool, h2o_socket_t *sock);
/**
 * determines if a socket belongs to the socket pool
 */
static int h2o_socketpool_is_owned_socket(h2o_socketpool_t *pool, h2o_socket_t *sock);

/* inline defs */

inline int h2o_socketpool_is_owned_socket(h2o_socketpool_t *pool, h2o_socket_t *sock)
{
    return sock->on_close.data == pool;
}

#ifdef __cplusplus
}
#endif

#endif
