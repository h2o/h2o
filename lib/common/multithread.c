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

#if H2O_USE_LIBUV
#else

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

static void on_read(h2o_socket_t *sock, int status)
{
    if (status != 0) {
        fprintf(stderr, "pipe error\n");
        abort();
    }

    h2o_buffer_consume(&sock->input, sock->input->size);
    queue_cb(sock->data);
}

static void init_async(h2o_multithread_queue_t *queue, h2o_loop_t *loop)
{
    int fds[2];

    if (cloexec_pipe(fds) != 0) {
        perror("pipe");
        abort();
    }
    fcntl(fds[1], F_SETFL, O_NONBLOCK);
    queue->async.write = fds[1];
    queue->async.read = h2o_evloop_socket_create(loop, fds[0], 0);
    queue->async.read->data = queue;
    h2o_socket_read_start(queue->async.read, on_read);
}

#endif

h2o_multithread_queue_t *h2o_multithread_create_queue(h2o_loop_t *loop)
{
    h2o_multithread_queue_t *queue = h2o_mem_alloc(sizeof(*queue));
    *queue = (h2o_multithread_queue_t){};

#if H2O_USE_LIBUV
    uv_async_init(loop, &queue->async, (void *)queue_cb);
#else
    init_async(queue, loop);
#endif
    pthread_mutex_init(&queue->mutex, NULL);
    h2o_linklist_init_anchor(&queue->receivers.active);
    h2o_linklist_init_anchor(&queue->receivers.inactive);

    return queue;
}

void h2o_multithread_destroy_queue(h2o_multithread_queue_t *queue)
{
    assert(h2o_linklist_is_empty(&queue->receivers.active));
    assert(h2o_linklist_is_empty(&queue->receivers.inactive));
#if H2O_USE_LIBUV
    uv_close((uv_handle_t *)&queue->async, (void *)free);
#else
    h2o_socket_read_stop(queue->async.read);
    h2o_socket_close(queue->async.read);
    close(queue->async.write);
    free(queue->async.read);
#endif
    pthread_mutex_destroy(&queue->mutex);
}

void h2o_multithread_register_receiver(h2o_multithread_queue_t *queue, h2o_multithread_receiver_t *receiver,
                                       h2o_multithread_receiver_cb cb)
{
    receiver->queue = queue;
    receiver->_link = (h2o_linklist_t){};
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

    assert(!h2o_linklist_is_linked(&message->link));

    pthread_mutex_lock(&receiver->queue->mutex);
    if (h2o_linklist_is_empty(&receiver->_messages)) {
        h2o_linklist_unlink(&receiver->_link);
        h2o_linklist_insert(&receiver->queue->receivers.active, &receiver->_link);
        do_send = 1;
    }
    h2o_linklist_insert(&receiver->_messages, &message->link);
    pthread_mutex_unlock(&receiver->queue->mutex);

    if (do_send) {
#if H2O_USE_LIBUV
        uv_async_send(&receiver->queue->async);
#else
        while (write(receiver->queue->async.write, "", 1) == -1 && errno == EINTR)
            ;
#endif
    }
}

void h2o_multithread_create_thread(pthread_t *tid, const pthread_attr_t *attr, void *(*func)(void *), void *arg)
{
    if (pthread_create(tid, attr, func, arg) != 0) {
        perror("pthread_create");
        abort();
    }
}
