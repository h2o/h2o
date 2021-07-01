/*
 * Copyright (c) 2015-2016 DeNA Co., Ltd., Kazuho Oku, Tatsuhiko Kubo,
 *                         Chul-Woong Yang
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
#include <pthread.h>
#ifdef __linux__
#include <sys/eventfd.h>
#endif
#include "cloexec.h"
#include "h2o/multithread.h"

struct st_h2o_multithread_queue_t {
#if H2O_USE_LIBUV
    uv_async_t async;
#else
    struct {
        int write;
        h2o_socket_t *read;
    } async;
#endif
    pthread_mutex_t mutex;
    struct {
        h2o_linklist_t active;
        h2o_linklist_t inactive;
    } receivers;
};

static void queue_cb(h2o_multithread_queue_t *queue)
{
    pthread_mutex_lock(&queue->mutex);

    while (!h2o_linklist_is_empty(&queue->receivers.active)) {
        h2o_multithread_receiver_t *receiver =
            H2O_STRUCT_FROM_MEMBER(h2o_multithread_receiver_t, _link, queue->receivers.active.next);
        /* detach all the messages from the receiver */
        h2o_linklist_t messages;
        h2o_linklist_init_anchor(&messages);
        h2o_linklist_insert_list(&messages, &receiver->_messages);
        /* relink the receiver to the inactive list */
        h2o_linklist_unlink(&receiver->_link);
        h2o_linklist_insert(&queue->receivers.inactive, &receiver->_link);

        /* dispatch the messages */
        pthread_mutex_unlock(&queue->mutex);
        receiver->cb(receiver, &messages);
        assert(h2o_linklist_is_empty(&messages));
        pthread_mutex_lock(&queue->mutex);
    }

    pthread_mutex_unlock(&queue->mutex);
}

#ifdef H2O_NO_64BIT_ATOMICS
pthread_mutex_t h2o_conn_id_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif

#if H2O_USE_LIBUV
#else

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

static void on_read(h2o_socket_t *sock, const char *err)
{
    if (err != NULL) {
        h2o_fatal("on_read: %s", err);
    }

    h2o_buffer_consume(&sock->input, sock->input->size);
    queue_cb(sock->data);
}

static void init_async(h2o_multithread_queue_t *queue, h2o_loop_t *loop)
{
#if defined(__linux__)
    /**
     * The kernel overhead of an eventfd file descriptor is
     * much lower than that of a pipe, and only one file descriptor is required
     */
    int fd;
    char buf[128];

    fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (fd == -1) {
        h2o_fatal("eventfd: %s", h2o_strerror_r(errno, buf, sizeof(buf)));
    }
    queue->async.write = fd;
    queue->async.read = h2o_evloop_socket_create(loop, fd, 0);
#else
    int fds[2];
    char buf[128];

    if (cloexec_pipe(fds) != 0) {
        h2o_fatal("pipe: %s", h2o_strerror_r(errno, buf, sizeof(buf)));
    }
    fcntl(fds[1], F_SETFL, O_NONBLOCK);
    queue->async.write = fds[1];
    queue->async.read = h2o_evloop_socket_create(loop, fds[0], 0);
#endif
    queue->async.read->data = queue;
    h2o_socket_read_start(queue->async.read, on_read);
}

#endif

h2o_multithread_queue_t *h2o_multithread_create_queue(h2o_loop_t *loop)
{
    h2o_multithread_queue_t *queue = h2o_mem_alloc(sizeof(*queue));
    memset(queue, 0, sizeof(*queue));

#if H2O_USE_LIBUV
    uv_async_init(loop, &queue->async, (uv_async_cb)queue_cb);
#else
    init_async(queue, loop);
#endif
    pthread_mutex_init(&queue->mutex, NULL);
    h2o_linklist_init_anchor(&queue->receivers.active);
    h2o_linklist_init_anchor(&queue->receivers.inactive);

    return queue;
}

#if H2O_USE_LIBUV
static void libuv_destroy_delayed(uv_handle_t *handle)
{
    h2o_multithread_queue_t *queue = H2O_STRUCT_FROM_MEMBER(h2o_multithread_queue_t, async, (uv_async_t *)handle);
    free(queue);
}
#endif

void h2o_multithread_destroy_queue(h2o_multithread_queue_t *queue)
{
    assert(h2o_linklist_is_empty(&queue->receivers.active));
    assert(h2o_linklist_is_empty(&queue->receivers.inactive));
    pthread_mutex_destroy(&queue->mutex);

#if H2O_USE_LIBUV
    uv_close((uv_handle_t *)&queue->async, libuv_destroy_delayed);
#else
    h2o_socket_read_stop(queue->async.read);
    h2o_socket_close(queue->async.read);
#ifndef __linux__
    /* only one file descriptor is required for eventfd and already closed by h2o_socket_close() */
    close(queue->async.write);
#endif
    free(queue);
#endif
}

void h2o_multithread_register_receiver(h2o_multithread_queue_t *queue, h2o_multithread_receiver_t *receiver,
                                       h2o_multithread_receiver_cb cb)
{
    receiver->queue = queue;
    receiver->_link = (h2o_linklist_t){NULL};
    h2o_linklist_init_anchor(&receiver->_messages);
    receiver->cb = cb;

    pthread_mutex_lock(&queue->mutex);
    h2o_linklist_insert(&queue->receivers.inactive, &receiver->_link);
    pthread_mutex_unlock(&queue->mutex);
}

void h2o_multithread_unregister_receiver(h2o_multithread_queue_t *queue, h2o_multithread_receiver_t *receiver)
{
    assert(queue == receiver->queue);
    assert(h2o_linklist_is_empty(&receiver->_messages));
    pthread_mutex_lock(&queue->mutex);
    h2o_linklist_unlink(&receiver->_link);
    pthread_mutex_unlock(&queue->mutex);
}

void h2o_multithread_send_message(h2o_multithread_receiver_t *receiver, h2o_multithread_message_t *message)
{
    int do_send = 0;

    pthread_mutex_lock(&receiver->queue->mutex);
    if (message != NULL) {
        assert(!h2o_linklist_is_linked(&message->link));
        if (h2o_linklist_is_empty(&receiver->_messages)) {
            h2o_linklist_unlink(&receiver->_link);
            h2o_linklist_insert(&receiver->queue->receivers.active, &receiver->_link);
            do_send = 1;
        }
        h2o_linklist_insert(&receiver->_messages, &message->link);
    } else {
        if (h2o_linklist_is_empty(&receiver->_messages))
            do_send = 1;
    }
    pthread_mutex_unlock(&receiver->queue->mutex);

    if (do_send) {
#if H2O_USE_LIBUV
        uv_async_send(&receiver->queue->async);
#else
#ifdef __linux__
        uint64_t tmp = 1;
        while (write(receiver->queue->async.write, &tmp, sizeof(tmp)) == -1 && errno == EINTR)
#else
        while (write(receiver->queue->async.write, "", 1) == -1 && errno == EINTR)
#endif
            ;
#endif
    }
}

void h2o_multithread_create_thread(pthread_t *tid, const pthread_attr_t *attr, void *(*func)(void *), void *arg)
{
    int ret;
    if ((ret = pthread_create(tid, attr, func, arg)) != 0) {
        char buf[128];
        h2o_fatal("pthread_create: %s", h2o_strerror_r(ret, buf, sizeof(buf)));
    }
}

void h2o_sem_init(h2o_sem_t *sem, ssize_t capacity)
{
    pthread_mutex_init(&sem->_mutex, NULL);
    pthread_cond_init(&sem->_cond, NULL);
    sem->_cur = capacity;
    sem->_capacity = capacity;
}

void h2o_sem_destroy(h2o_sem_t *sem)
{
    assert(sem->_cur == sem->_capacity);
    pthread_cond_destroy(&sem->_cond);
    pthread_mutex_destroy(&sem->_mutex);
}

void h2o_sem_wait(h2o_sem_t *sem)
{
    pthread_mutex_lock(&sem->_mutex);
    while (sem->_cur <= 0)
        pthread_cond_wait(&sem->_cond, &sem->_mutex);
    --sem->_cur;
    pthread_mutex_unlock(&sem->_mutex);
}

void h2o_sem_post(h2o_sem_t *sem)
{
    pthread_mutex_lock(&sem->_mutex);
    ++sem->_cur;
    pthread_cond_signal(&sem->_cond);
    pthread_mutex_unlock(&sem->_mutex);
}

void h2o_sem_set_capacity(h2o_sem_t *sem, ssize_t new_capacity)
{
    pthread_mutex_lock(&sem->_mutex);
    sem->_cur += new_capacity - sem->_capacity;
    sem->_capacity = new_capacity;
    pthread_cond_broadcast(&sem->_cond);
    pthread_mutex_unlock(&sem->_mutex);
}

/* barrier */

void h2o_barrier_init(h2o_barrier_t *barrier, size_t count)
{
    pthread_mutex_init(&barrier->_mutex, NULL);
    pthread_cond_init(&barrier->_cond, NULL);
    barrier->_count = count;
    barrier->_out_of_wait = count;
}

int h2o_barrier_wait(h2o_barrier_t *barrier)
{
    int ret;
    pthread_mutex_lock(&barrier->_mutex);
    barrier->_count--;
    if (barrier->_count == 0) {
        pthread_cond_broadcast(&barrier->_cond);
        ret = 1;
    } else {
        while (barrier->_count)
            pthread_cond_wait(&barrier->_cond, &barrier->_mutex);
        ret = 0;
    }
    pthread_mutex_unlock(&barrier->_mutex);
    /*
     * this is needed to synchronize h2o_barrier_destroy with the
     * exit of this function, so make sure that we can't destroy the
     * mutex or the condition before all threads have exited wait()
     */
    __sync_sub_and_fetch(&barrier->_out_of_wait, 1);
    return ret;
}

int h2o_barrier_done(h2o_barrier_t *barrier)
{
    return __sync_add_and_fetch(&barrier->_count, 0) == 0;
}

void h2o_barrier_add(h2o_barrier_t *barrier, size_t delta)
{
    __sync_add_and_fetch(&barrier->_count, delta);
}

void h2o_barrier_destroy(h2o_barrier_t *barrier)
{
    while (__sync_add_and_fetch(&barrier->_out_of_wait, 0) != 0) {
        sched_yield();
    }
    pthread_mutex_destroy(&barrier->_mutex);
    pthread_cond_destroy(&barrier->_cond);
}

void h2o_error_reporter__on_timeout(h2o_timer_t *_timer)
{
    h2o_error_reporter_t *reporter = H2O_STRUCT_FROM_MEMBER(h2o_error_reporter_t, _timer, _timer);

    pthread_mutex_lock(&reporter->_mutex);

    uint64_t total_successes = __sync_fetch_and_add(&reporter->_total_successes, 0),
             cur_successes = total_successes - reporter->prev_successes;

    reporter->_report_errors(reporter, total_successes, cur_successes);

    reporter->prev_successes = total_successes;
    reporter->cur_errors = 0;

    pthread_mutex_unlock(&reporter->_mutex);
}

uintptr_t h2o_error_reporter_record_error(h2o_loop_t *loop, h2o_error_reporter_t *reporter, uint64_t delay_ticks,
                                          uintptr_t new_data)
{
    uintptr_t old_data;

    pthread_mutex_lock(&reporter->_mutex);

    if (reporter->cur_errors == 0) {
        reporter->prev_successes = __sync_fetch_and_add_8(&reporter->_total_successes, 0);
        assert(!h2o_timer_is_linked(&reporter->_timer));
        h2o_timer_link(loop, delay_ticks, &reporter->_timer);
    }
    ++reporter->cur_errors;
    old_data = reporter->data;
    reporter->data = new_data;

    pthread_mutex_unlock(&reporter->_mutex);

    return old_data;
}
