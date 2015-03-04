/*
 * Copyright (c) 2015 DeNA Co., Ltd., Kazuho Oku
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
#include "h2o/hostinfo.h"

static struct {
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    h2o_linklist_t pending; /* anchor of h2o_hostinfo_getaddr_req_t::_pending */
    size_t num_workers;
    size_t num_idle;
    size_t max_workers;
} queue = {PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER, {&queue.pending, &queue.pending}, 0, 0, 32};

static void lookup_and_respond(h2o_hostinfo_getaddr_req_t *req)
{
    struct addrinfo *res;

    int ret = getaddrinfo(req->_in.name, req->_in.serv, &req->_in.hints, &res);
    if (ret != 0) {
        req->_out.errstr = gai_strerror(ret);
        req->_out.ai = NULL;
    } else {
        req->_out.message = (h2o_multithread_message_t){};
        req->_out.errstr = NULL;
        req->_out.ai = res;
    }

    h2o_multithread_send_message(req->_receiver, &req->_out.message);
}

static void *lookup_thread_main(void *_unused)
{
    pthread_mutex_lock(&queue.mutex);

    while (1) {
        while (!h2o_linklist_is_empty(&queue.pending)) {
            h2o_hostinfo_getaddr_req_t *req = H2O_STRUCT_FROM_MEMBER(h2o_hostinfo_getaddr_req_t, _pending, queue.pending.next);
            h2o_linklist_unlink(&req->_pending);
            pthread_mutex_unlock(&queue.mutex);
            lookup_and_respond(req);
            pthread_mutex_lock(&queue.mutex);
        }
        pthread_cond_wait(&queue.cond, &queue.mutex);
    }

    pthread_mutex_unlock(&queue.mutex);

    return NULL;
}

static void create_lookup_thread(void)
{
    pthread_t tid;
    pthread_attr_t attr;
    int ret;

    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, 1);
    pthread_attr_setstacksize(&attr, 100 * 1024);
    if ((ret = pthread_create(&tid, NULL, lookup_thread_main, NULL)) != 0) {
        if (queue.num_workers == 0) {
            fprintf(stderr, "failed to start first thread for getaddrinfo:%s\n", strerror(ret));
            abort();
        } else {
            perror("pthread_create(for getaddrinfo)");
        }
        return;
    }

    ++queue.num_workers;
    ++queue.num_idle;
}

void h2o__hostinfo_getaddr_dispatch(h2o_hostinfo_getaddr_req_t *req)
{
    pthread_mutex_lock(&queue.mutex);

    h2o_linklist_insert(&queue.pending, &req->_pending);

    if (queue.num_idle == 0 && queue.num_workers < queue.max_workers)
        create_lookup_thread();

    pthread_cond_signal(&queue.cond);
    pthread_mutex_unlock(&queue.mutex);
}

void h2o_hostinfo_getaddr_cancel(h2o_hostinfo_getaddr_req_t *req)
{
    pthread_mutex_lock(&queue.mutex);

    if (h2o_linklist_is_linked(&req->_pending)) {
        h2o_linklist_unlink(&req->_pending);
    } else {
        req->_cb = NULL;
    }

    pthread_mutex_unlock(&queue.mutex);
}

void h2o_hostinfo_getaddr_receiver(h2o_multithread_receiver_t *receiver, h2o_linklist_t *messages)
{
    while (!h2o_linklist_is_empty(messages)) {
        h2o_hostinfo_getaddr_req_t *req = H2O_STRUCT_FROM_MEMBER(h2o_hostinfo_getaddr_req_t, _out.message.link, messages->next);
        h2o_linklist_unlink(&req->_out.message.link);
        if (req->_cb != NULL)
            req->_cb(req, req->_out.errstr, req->_out.ai);
    }
}
