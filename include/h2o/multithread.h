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

typedef void (*h2o_multithread_receiver_cb)(h2o_multithread_receiver_t *receiver, h2o_linklist_t *messages);

struct st_h2o_multithread_receiver_t {
    h2o_multithread_queue_t *queue;
    h2o_linklist_t _link;
    h2o_linklist_t _messages;
    h2o_multithread_receiver_cb cb;
};

typedef struct st_h2o_multithread_message_t {
    h2o_linklist_t link;
} h2o_multithread_message_t;

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
    size_t _out_of_wait;
} h2o_barrier_t;

/**
 * This structure is used to rate-limit the emission of error messages.
 * When something succeeds, the user calls `h2o_error_reporter_record_success`. When something fails, the user calls
 * `h2o_error_reporter_record_error`, along with how long the emission of the warning message should be delayed. When the delayed
 * timer expires, the cusmo callback (registered using `H2O_ERROR_REPORTER_INITIALIZER` macro) is invoked, so that the user can emit
 * whatever message that's necessary, alongside the number of successes and errors within the delayed period.
 *
 * Fields that do not start with `_` can be directly accessed / modified by the `report_errors` callback. In other occasions,
 * modifications MUST be made through the "record" functions. Fields that start with `_` are private and must not be touched by the
 * user.
 */
typedef struct st_h2o_error_reporter_t {
    uint64_t cur_errors;
    uint64_t prev_successes;
    uintptr_t data;
    uint64_t _total_successes;
    pthread_mutex_t _mutex;
    h2o_timer_t _timer;
    void (*_report_errors)(struct st_h2o_error_reporter_t *reporter, uint64_t tocal_succeses, uint64_t cur_successes);
} h2o_error_reporter_t;

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
 * create a thread
 */
void h2o_multithread_create_thread(pthread_t *tid, const pthread_attr_t *attr, void *(*func)(void *), void *arg);

/**
 * a variant of pthread_once, that does not require you to declare a callback, nor have a global variable
 */
#define H2O_MULTITHREAD_ONCE(block)                                                                                                \
    do {                                                                                                                           \
        static volatile int lock = 0;                                                                                              \
        int lock_loaded = lock;                                                                                                    \
        __sync_synchronize();                                                                                                      \
        if (!lock_loaded) {                                                                                                        \
            static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;                                                              \
            pthread_mutex_lock(&mutex);                                                                                            \
            if (!lock) {                                                                                                           \
                do {                                                                                                               \
                    block                                                                                                          \
                } while (0);                                                                                                       \
                __sync_synchronize();                                                                                              \
                lock = 1;                                                                                                          \
            }                                                                                                                      \
            pthread_mutex_unlock(&mutex);                                                                                          \
        }                                                                                                                          \
    } while (0)

void h2o_sem_init(h2o_sem_t *sem, ssize_t capacity);
void h2o_sem_destroy(h2o_sem_t *sem);
void h2o_sem_wait(h2o_sem_t *sem);
void h2o_sem_post(h2o_sem_t *sem);
void h2o_sem_set_capacity(h2o_sem_t *sem, ssize_t new_capacity);

#define H2O_BARRIER_INITIALIZER(count_)                                                                                            \
    {                                                                                                                              \
        PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER, count_                                                                \
    }
void h2o_barrier_init(h2o_barrier_t *barrier, size_t count);
int h2o_barrier_wait(h2o_barrier_t *barrier);
int h2o_barrier_done(h2o_barrier_t *barrier);
void h2o_barrier_add(h2o_barrier_t *barrier, size_t delta);
void h2o_barrier_destroy(h2o_barrier_t *barrier);

void h2o_error_reporter__on_timeout(h2o_timer_t *timer);
#define H2O_ERROR_REPORTER_INITIALIZER(s)                                                                                          \
    ((h2o_error_reporter_t){                                                                                                       \
        ._mutex = PTHREAD_MUTEX_INITIALIZER, ._timer = {.cb = h2o_error_reporter__on_timeout}, ._report_errors = (s)})
static void h2o_error_reporter_record_success(h2o_error_reporter_t *reporter);
/**
 * This function records an error event, sets a delayed timer (if not yet have been set), replaces the value of
 * `h2o_error_reporter_t::data` with `new_data`, returning the old value.
 */
uintptr_t h2o_error_reporter_record_error(h2o_loop_t *loop, h2o_error_reporter_t *reporter, uint64_t delay_ticks,
                                          uintptr_t new_data);

/* inline functions */

inline void h2o_error_reporter_record_success(h2o_error_reporter_t *reporter)
{
    __sync_fetch_and_add(&reporter->_total_successes, 1);
}

#endif
