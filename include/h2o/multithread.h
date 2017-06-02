/*
 * Copyright (c) 2015 DeNA Co., Ltd., Kazuho Oku, Tatsuhiko Kubo
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
#ifndef h2o__multithread_h
#define h2o__multithread_h

#include <pthread.h>
#include "h2o/linklist.h"
#include "h2o/socket.h"

typedef struct st_h2o_multithread_receiver_t h2o_multithread_receiver_t;
typedef struct st_h2o_multithread_queue_t h2o_multithread_queue_t;
typedef struct st_h2o_multithread_request_t h2o_multithread_request_t;

typedef void (*h2o_multithread_receiver_cb)(h2o_multithread_receiver_t *receiver, h2o_linklist_t *messages);
typedef void (*h2o_multithread_response_cb)(h2o_multithread_request_t *req);

struct st_h2o_multithread_receiver_t {
    h2o_multithread_queue_t *queue;
    h2o_linklist_t _link;
    h2o_linklist_t _messages;
    h2o_multithread_receiver_cb cb;
};

typedef struct st_h2o_multithread_message_t {
    h2o_linklist_t link;
} h2o_multithread_message_t;

struct st_h2o_multithread_request_t {
    h2o_multithread_message_t super;
    h2o_multithread_receiver_t *source;
    h2o_multithread_response_cb cb;
};

typedef struct st_h2o_sem_t {
    pthread_mutex_t _mutex;
    pthread_cond_t _cond;
    ssize_t _cur;
    ssize_t _capacity;
} h2o_sem_t;

typedef struct st_h2o_barrier_t {
    pthread_mutex_t _mutex;
    pthread_cond_t _cond;
    size_t _count;
} h2o_barrier_t;

/**
 * creates a queue that is used for inter-thread communication
 */
h2o_multithread_queue_t *h2o_multithread_create_queue(h2o_loop_t *loop);
/**
 * destroys the queue
 */
void h2o_multithread_destroy_queue(h2o_multithread_queue_t *queue);
/**
 * registers a receiver for specific type of message
 */
void h2o_multithread_register_receiver(h2o_multithread_queue_t *queue, h2o_multithread_receiver_t *receiver,
                                       h2o_multithread_receiver_cb cb);
/**
 * unregisters a receiver
 */
void h2o_multithread_unregister_receiver(h2o_multithread_queue_t *queue, h2o_multithread_receiver_t *receiver);
/**
 * sends a message (or set message to NULL to just wake up the receiving thread)
 */
void h2o_multithread_send_message(h2o_multithread_receiver_t *receiver, h2o_multithread_message_t *message);
/**
 * sends a request
 */
void h2o_multithread_send_request(h2o_multithread_receiver_t *receiver, h2o_multithread_request_t *req);
/**
 * create a thread
 */
void h2o_multithread_create_thread(pthread_t *tid, const pthread_attr_t *attr, void *(*func)(void *), void *arg);

void h2o_sem_init(h2o_sem_t *sem, ssize_t capacity);
void h2o_sem_destroy(h2o_sem_t *sem);
void h2o_sem_wait(h2o_sem_t *sem);
void h2o_sem_post(h2o_sem_t *sem);
void h2o_sem_set_capacity(h2o_sem_t *sem, ssize_t new_capacity);

#define H2O_BARRIER_INITIALIZER(count_) {PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER, count_}
void h2o_barrier_init(h2o_barrier_t *barrier, size_t count);
int h2o_barrier_wait(h2o_barrier_t *barrier);
int h2o_barrier_done(h2o_barrier_t *barrier);

#endif
