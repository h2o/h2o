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
#include <libmemcached/memcached.h>
#include "h2o/linklist.h"
#include "h2o/libmemcached.h"

struct st_h2o_libmemcached_context_t {
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    h2o_linklist_t pending;
    struct {
        size_t cur;
        size_t max;
        size_t idle;
    } num_threads;
    char config[1];
};

enum en_h2o_libmemcached_req_type_t { REQ_TYPE_GET, REQ_TYPE_SET, REQ_TYPE_DELETE };

struct st_h2o_libmemcached_req_t {
    enum en_h2o_libmemcached_req_type_t type;
    h2o_linklist_t pending;
    union {
        struct {
            h2o_multithread_receiver_t *receiver;
            h2o_multithread_message_t message;
            h2o_libmemcached_get_cb cb;
            void *cb_data;
            h2o_iovec_t value;
        } get;
        struct {
            h2o_iovec_t value;
            time_t expiration;
        } set;
    } data;
    struct {
        size_t len;
        char base[1];
    } key;
};

static h2o_libmemcached_req_t *create_req(enum en_h2o_libmemcached_req_type_t type, h2o_iovec_t key)
{
    h2o_libmemcached_req_t *req = h2o_mem_alloc(offsetof(h2o_libmemcached_req_t, key.base) + key.len);
    req->type = type;
    req->pending = (h2o_linklist_t){};
    memset(&req->data, 0, sizeof(req->data));
    req->key.len = key.len;
    memcpy(req->key.base, key.base, key.len);
    return req;
}

static void free_req(h2o_libmemcached_req_t *req)
{
    assert(!h2o_linklist_is_linked(&req->pending));
    switch (req->type) {
    case REQ_TYPE_GET:
        assert(!h2o_linklist_is_linked(&req->data.get.message.link));
        free(req->data.get.value.base);
        break;
    case REQ_TYPE_SET:
        free(req->data.set.value.base);
        break;
    case REQ_TYPE_DELETE:
        break;
    default:
        assert(!"FIXME");
        break;
    }
    free(req);
}

static void *thread_main(void *_ctx)
{
    h2o_libmemcached_context_t *ctx = _ctx;
    memcached_st *memc = memcached(ctx->config, strlen(ctx->config));

    pthread_mutex_lock(&ctx->mutex);

    while (1) {
        while (!h2o_linklist_is_empty(&ctx->pending)) {
            h2o_libmemcached_req_t *req = H2O_STRUCT_FROM_MEMBER(h2o_libmemcached_req_t, pending, ctx->pending.next);
            h2o_linklist_unlink(&req->pending);
            pthread_mutex_unlock(&ctx->mutex);

            memcached_return_t memc_ret;
            switch (req->type) {
            case REQ_TYPE_GET:
                req->data.get.value.base =
                    memcached_get(memc, req->key.base, req->key.len, &req->data.get.value.len, NULL, &memc_ret);
                h2o_multithread_send_message(req->data.get.receiver, &req->data.get.message);
                break;
            case REQ_TYPE_SET:
                memc_ret = memcached_set(memc, req->key.base, req->key.len, req->data.set.value.base, req->data.set.value.len,
                                         req->data.set.expiration, 0);
                break;
            case REQ_TYPE_DELETE:
                memc_ret = memcached_delete(memc, req->key.base, req->key.len, 0);
                break;
            }

            pthread_mutex_lock(&ctx->mutex);
        }
        pthread_cond_wait(&ctx->cond, &ctx->mutex);
    }
}

static void dispatch(h2o_libmemcached_context_t *ctx, h2o_libmemcached_req_t *req)
{
    pthread_mutex_lock(&ctx->mutex);

    h2o_linklist_insert(&ctx->pending, &req->pending);

    if (ctx->num_threads.idle == 0 && ctx->num_threads.cur < ctx->num_threads.max) {
        pthread_t tid;
        int ret;
        if ((ret = pthread_create(&tid, NULL, thread_main, ctx)) == 0) {
            ++ctx->num_threads.cur;
        } else {
            if (ctx->num_threads.cur == 0) {
                fprintf(stderr, "failed to start first thread for libmemcached:%s\n", strerror(ret));
                abort();
            } else {
                perror("pthread_create(for libmemcached)");
            }
        }
    }

    pthread_cond_signal(&ctx->cond);
    pthread_mutex_unlock(&ctx->mutex);
}

void h2o_libmemcached_receiver(h2o_multithread_receiver_t *receiver, h2o_linklist_t *messages)
{
    while (!h2o_linklist_is_empty(messages)) {
        h2o_libmemcached_req_t *req = H2O_STRUCT_FROM_MEMBER(h2o_libmemcached_req_t, data.get.message.link, messages->next);
        h2o_linklist_unlink(&req->data.get.message.link);
        assert(req->type == REQ_TYPE_GET);
        if (req->data.get.cb != NULL)
            req->data.get.cb(req->data.get.value, req->data.get.cb_data);
        free_req(req);
    }
}

h2o_libmemcached_req_t *h2o_libmemcached_get(h2o_libmemcached_context_t *ctx, h2o_multithread_receiver_t *receiver, h2o_iovec_t key,
                                             h2o_libmemcached_get_cb cb, void *cb_data)
{
    h2o_libmemcached_req_t *req = create_req(REQ_TYPE_GET, key);
    req->data.get.receiver = receiver;
    req->data.get.cb = cb;
    req->data.get.cb_data = cb_data;
    dispatch(ctx, req);
    return req;
}

void h2o_libmemcached_cancel_get(h2o_libmemcached_context_t *ctx, h2o_libmemcached_req_t *req)
{
    int do_free = 0;

    pthread_mutex_lock(&ctx->mutex);
    req->data.get.cb = NULL;
    if (h2o_linklist_is_linked(&req->pending)) {
        h2o_linklist_unlink(&req->pending);
        do_free = 1;
    }
    pthread_mutex_unlock(&ctx->mutex);

    if (do_free)
        free_req(req);
}

void h2o_libmemcached_set(h2o_libmemcached_context_t *ctx, h2o_iovec_t key, h2o_iovec_t value, time_t expiration)
{
    h2o_libmemcached_req_t *req = create_req(REQ_TYPE_SET, key);
    req->data.set.value = h2o_iovec_init(h2o_mem_alloc(value.len), value.len);
    memcpy(req->data.set.value.base, value.base, value.len);
    req->data.set.expiration = expiration;
    dispatch(ctx, req);
}

void h2o_libmemcached_delete(h2o_libmemcached_context_t *ctx, h2o_iovec_t key)
{
    h2o_libmemcached_req_t *req = create_req(REQ_TYPE_DELETE, key);
    dispatch(ctx, req);
}

h2o_libmemcached_context_t *h2o_libmemcached_create_context(const char *config, size_t max_threads)
{
    h2o_libmemcached_context_t *ctx = h2o_mem_alloc(offsetof(h2o_libmemcached_context_t, config) + strlen(config) + 1);
    pthread_mutex_init(&ctx->mutex, NULL);
    pthread_cond_init(&ctx->cond, NULL);
    h2o_linklist_init_anchor(&ctx->pending);
    ctx->num_threads.cur = 0;
    ctx->num_threads.max = max_threads;
    ctx->num_threads.idle = 0;
    strcpy(ctx->config, config);
    return ctx;
}
