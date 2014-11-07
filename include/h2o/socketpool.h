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

#include <pthread.h>
#include "h2o/linklist.h"
#include "h2o/socket.h"
#include "h2o/timeout.h"

typedef struct st_h2o_socketpool_t {
    /* read-only vars */
    h2o_loop_t *loop;
    size_t capacity;
    h2o_timeout_t _timeout;
    h2o_timeout_entry_t _timeout_entry;
    /* mutex */
    pthread_mutex_t _mutex;
    /* vars that are modified by multiple threads */
    struct {
        size_t count;
        h2o_linklist_t sockets; /* list of struct pool_entry_t defined in socket/pool.c */
    } _shared;
} h2o_socketpool_t;

/**
 * initializes a socket loop
 */
void h2o_socketpool_init(h2o_socketpool_t *pool, h2o_loop_t *loop, size_t capacity, uint64_t timeout);
/**
 * disposes of a socket loop
 */
void h2o_socketpool_dispose(h2o_socketpool_t *pool);
/**
 * registers an idling socket to the socket pool
 */
int h2o_socketpool_register(h2o_socketpool_t *pool, h2o_socket_t *sock);
/**
 * fetches an idling socket from the socket pool to the given loop
 */
h2o_socket_t *h2o_socketpool_acquire(h2o_socketpool_t *pool, h2o_loop_t *loop);

#endif
