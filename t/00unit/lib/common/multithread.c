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
#include <stdlib.h>
#include "../../test.h"
#include "../../../../lib/common/multithread.c"

struct st_thread_t {
    h2o_loop_t *loop;
    h2o_multithread_queue_t *queue;
};

struct {
    h2o_loop_t *loop;
    h2o_multithread_queue_t *queue;
    h2o_multithread_receiver_t pong_receiver;
    h2o_multithread_receiver_t shutdown_receiver;
    int received_shutdown;
} main_thread;

struct {
    h2o_loop_t *loop;
    h2o_multithread_queue_t *queue;
    h2o_multithread_receiver_t ping_receiver;
    size_t num_ping_received;
    int should_exit;
} worker_thread;

static void send_empty_message(h2o_multithread_receiver_t *receiver)
{
    h2o_multithread_message_t *message = h2o_mem_alloc(sizeof(*message));
    *message = (h2o_multithread_message_t){{NULL}};
    h2o_multithread_send_message(receiver, message);
}

static void pop_empty_message(h2o_linklist_t *list)
{
    h2o_multithread_message_t *message = H2O_STRUCT_FROM_MEMBER(h2o_multithread_message_t, link, list->next);
    h2o_linklist_unlink(&message->link);
    free(message);
}

static void on_ping(h2o_multithread_receiver_t *receiver, h2o_linklist_t *list)
{
    while (!h2o_linklist_is_empty(list)) {
        pop_empty_message(list);
        if (++worker_thread.num_ping_received < 100) {
            send_empty_message(&main_thread.pong_receiver);
        } else {
            send_empty_message(&main_thread.shutdown_receiver);
            worker_thread.should_exit = 1;
        }
    }
}

static void on_pong(h2o_multithread_receiver_t *receiver, h2o_linklist_t *list)
{
    while (!h2o_linklist_is_empty(list)) {
        pop_empty_message(list);
        send_empty_message(&worker_thread.ping_receiver);
    }
}

static void on_shutdown(h2o_multithread_receiver_t *receiver, h2o_linklist_t *list)
{
    while (!h2o_linklist_is_empty(list))
        pop_empty_message(list);
    main_thread.received_shutdown = 1;
}

#if H2O_USE_LIBUV
static h2o_loop_t *create_loop(void)
{
    h2o_loop_t *loop = h2o_mem_alloc(sizeof(*loop));
    uv_loop_init(loop);
    return loop;
}

static void destroy_loop(h2o_loop_t *loop)
{
    uv_run(loop, UV_RUN_NOWAIT);
    uv_loop_close(loop);
    free(loop);
}
#else
#define create_loop h2o_evloop_create
#define destroy_loop(loop) (0) /* FIXME */
#endif

static void *worker_main(void *_unused)
{
    while (!worker_thread.should_exit) {
#if H2O_USE_LIBUV
        uv_run(worker_thread.loop, UV_RUN_ONCE);
#else
        h2o_evloop_run(worker_thread.loop, INT32_MAX);
#endif
    }

    return NULL;
}

void test_lib__common__multithread_c(void)
{
    pthread_t tid;

    main_thread.loop = create_loop();
    main_thread.queue = h2o_multithread_create_queue(main_thread.loop);
    h2o_multithread_register_receiver(main_thread.queue, &main_thread.pong_receiver, on_pong);
    h2o_multithread_register_receiver(main_thread.queue, &main_thread.shutdown_receiver, on_shutdown);
    worker_thread.loop = create_loop();
    worker_thread.queue = h2o_multithread_create_queue(worker_thread.loop);
    h2o_multithread_register_receiver(worker_thread.queue, &worker_thread.ping_receiver, on_ping);

    pthread_create(&tid, NULL, worker_main, NULL);

    /* send first message */
    send_empty_message(&worker_thread.ping_receiver);

    while (!main_thread.received_shutdown) {
#if H2O_USE_LIBUV
        uv_run(main_thread.loop, UV_RUN_ONCE);
#else
        h2o_evloop_run(main_thread.loop, INT32_MAX);
#endif
    }

    pthread_join(tid, NULL);

    h2o_multithread_unregister_receiver(worker_thread.queue, &worker_thread.ping_receiver);
    h2o_multithread_destroy_queue(worker_thread.queue);
    destroy_loop(worker_thread.loop);
    h2o_multithread_unregister_receiver(main_thread.queue, &main_thread.pong_receiver);
    h2o_multithread_unregister_receiver(main_thread.queue, &main_thread.shutdown_receiver);
    h2o_multithread_destroy_queue(main_thread.queue);
    destroy_loop(main_thread.loop);

    ok(1);
}
