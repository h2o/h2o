/*
 * Copyright (c) 2016 DeNA Co., Ltd., Kazuho Oku
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
#include "h2o.h"

extern h2o_status_handler_t events_status_handler;
extern h2o_status_handler_t requests_status_handler;
extern h2o_status_handler_t durations_status_handler;

struct st_h2o_status_logger_t {
    h2o_logger_t super;
};

struct st_h2o_root_status_handler_t {
    h2o_handler_t super;
    H2O_VECTOR(h2o_multithread_receiver_t *) receivers;
};

struct st_h2o_status_context_t {
    h2o_context_t *ctx;
    h2o_multithread_receiver_t receiver;
};

struct st_status_ctx_t {
    int active;
    void *ctx;
};
struct st_h2o_status_collector_t {
    struct {
        h2o_req_t *req;
        h2o_multithread_receiver_t *receiver;
    } src;
    size_t num_remaining_threads_atomic;
    H2O_VECTOR(struct st_status_ctx_t) status_ctx;
};

struct st_h2o_status_message_t {
    h2o_multithread_message_t super;
    struct st_h2o_status_collector_t *collector;
};

static void collect_reqs_of_context(struct st_h2o_status_collector_t *collector, h2o_context_t *ctx)
{
    int i;

    for (i = 0; i < ctx->globalconf->statuses.size; i++) {
        struct st_status_ctx_t *sc = collector->status_ctx.entries + i;
        h2o_status_handler_t *sh = ctx->globalconf->statuses.entries + i;
        if (sc->active && sh->per_thread != NULL)
            sh->per_thread(sc->ctx, ctx);
    }

    if (__sync_sub_and_fetch(&collector->num_remaining_threads_atomic, 1) == 0) {
        struct st_h2o_status_message_t *message = h2o_mem_alloc(sizeof(*message));
        message->super = (h2o_multithread_message_t){{NULL}};
        message->collector = collector;
        h2o_multithread_send_message(collector->src.receiver, &message->super);
    }
}

static void send_response(struct st_h2o_status_collector_t *collector)
{
    static h2o_generator_t generator = {NULL, NULL};
    h2o_req_t *req;
    size_t nr_statuses;
    int i;
    int cur_resp = 0;

    req = collector->src.req;
    if (!req) {
        h2o_mem_release_shared(collector);
        return;
    }

    nr_statuses = req->conn->ctx->globalconf->statuses.size;
    size_t nr_resp = nr_statuses + 2; // 2 for the footer and header
    h2o_iovec_t resp[nr_resp];

    memset(resp, 0, sizeof(resp[0]) * nr_resp);
    resp[cur_resp++] = (h2o_iovec_t){H2O_STRLIT("{\n")};

    int coma_removed = 0;
    for (i = 0; i < req->conn->ctx->globalconf->statuses.size; i++) {
        h2o_status_handler_t *sh = &req->conn->ctx->globalconf->statuses.entries[i];
        if (!collector->status_ctx.entries[i].active) {
            continue;
        }
        resp[cur_resp++] = sh->final(collector->status_ctx.entries[i].ctx, req->conn->ctx->globalconf, req);
        if (resp[cur_resp - 1].len > 0 && !coma_removed) {
            /* requests come in with a leading coma, replace if with a space */
            resp[cur_resp - 1].base[0] = ' ';
            coma_removed = 1;
        }
    }
    resp[cur_resp++] = (h2o_iovec_t){H2O_STRLIT("\n}\n")};

    req->res.status = 200;
    h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_CONTENT_TYPE, H2O_STRLIT("text/plain; charset=utf-8"));
    h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_CACHE_CONTROL, H2O_STRLIT("no-cache, no-store"));
    h2o_start_response(req, &generator);
    h2o_send(req, resp, h2o_memis(req->input.method.base, req->input.method.len, H2O_STRLIT("HEAD")) ? 0 : nr_resp,
             H2O_SEND_STATE_FINAL);
    h2o_mem_release_shared(collector);
}

static void on_collect_notify(h2o_multithread_receiver_t *receiver, h2o_linklist_t *messages)
{
    struct st_h2o_status_context_t *status_ctx = H2O_STRUCT_FROM_MEMBER(struct st_h2o_status_context_t, receiver, receiver);

    while (!h2o_linklist_is_empty(messages)) {
        struct st_h2o_status_message_t *message = H2O_STRUCT_FROM_MEMBER(struct st_h2o_status_message_t, super, messages->next);
        struct st_h2o_status_collector_t *collector = message->collector;
        h2o_linklist_unlink(&message->super.link);
        free(message);

        if (__sync_add_and_fetch(&collector->num_remaining_threads_atomic, 0) != 0) {
            collect_reqs_of_context(collector, status_ctx->ctx);
        } else {
            send_response(collector);
        }
    }
}

static void on_collector_dispose(void *_collector)
{
}

static void on_req_close(void *p)
{
    struct st_h2o_status_collector_t *collector = *(void **)p;
    collector->src.req = NULL;
    h2o_mem_release_shared(collector);
}

static int on_req_json(struct st_h2o_root_status_handler_t *self, h2o_req_t *req, h2o_iovec_t status_list)
{
    { /* construct collector and send request to every thread */
        struct st_h2o_status_context_t *status_ctx = h2o_context_get_handler_context(req->conn->ctx, &self->super);
        struct st_h2o_status_collector_t *collector = h2o_mem_alloc_shared(NULL, sizeof(*collector), on_collector_dispose);
        size_t i;

        memset(collector, 0, sizeof(*collector));
        for (i = 0; i < req->conn->ctx->globalconf->statuses.size; i++) {
            h2o_status_handler_t *sh;

            h2o_vector_reserve(&req->pool, &collector->status_ctx, collector->status_ctx.size + 1);
            sh = &req->conn->ctx->globalconf->statuses.entries[i];

            if (status_list.base) {
                if (!h2o_contains_token(status_list.base, status_list.len, sh->name.base, sh->name.len, ',')) {
                    collector->status_ctx.entries[collector->status_ctx.size].active = 0;
                    goto Skip;
                }
            }
            if (sh->init) {
                collector->status_ctx.entries[collector->status_ctx.size].ctx = sh->init();
            }
            collector->status_ctx.entries[collector->status_ctx.size].active = 1;
        Skip:
            collector->status_ctx.size++;
        }
        collector->src.req = req;
        collector->src.receiver = &status_ctx->receiver;
        collector->num_remaining_threads_atomic = self->receivers.size;

        for (i = 0; i != self->receivers.size; ++i) {
            struct st_h2o_status_message_t *message = h2o_mem_alloc(sizeof(*message));
            *message = (struct st_h2o_status_message_t){{{NULL}}, collector};
            h2o_multithread_send_message(self->receivers.entries[i], &message->super);
        }

        /* collector is also retained by the on_req_close callback */
        *(struct st_h2o_status_collector_t **)h2o_mem_alloc_shared(&req->pool, sizeof(collector), on_req_close) = collector;
        h2o_mem_addref_shared(collector);
    }

    return 0;
}

static int on_req(h2o_handler_t *_self, h2o_req_t *req)
{
    struct st_h2o_root_status_handler_t *self = (void *)_self;
    size_t prefix_len = req->pathconf->path.len - (req->pathconf->path.base[req->pathconf->path.len - 1] == '/');
    h2o_iovec_t local_path = h2o_iovec_init(req->path_normalized.base + prefix_len, req->path_normalized.len - prefix_len);

    if (local_path.len == 0 || h2o_memis(local_path.base, local_path.len, H2O_STRLIT("/"))) {
        /* root of the handler returns HTML that renders the status */
        h2o_iovec_t fn;
        const char *root = getenv("H2O_ROOT");
        if (root == NULL)
            root = H2O_TO_STR(H2O_ROOT);
        fn = h2o_concat(&req->pool, h2o_iovec_init(root, strlen(root)), h2o_iovec_init(H2O_STRLIT("/share/h2o/status/index.html")));
        h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_CACHE_CONTROL, H2O_STRLIT("no-cache"));
        return h2o_file_send(req, 200, "OK", fn.base, h2o_iovec_init(H2O_STRLIT("text/html; charset=utf-8")), 0);
    } else if (h2o_memis(local_path.base, local_path.len, H2O_STRLIT("/json"))) {
        int ret;
        /* "/json" maps to the JSON API */
        h2o_iovec_t status_list = {NULL, 0}; /* NULL means we'll show all statuses */
        if (req->query_at != SIZE_MAX && (req->path.len - req->query_at > 6)) {
            if (h2o_memis(&req->path.base[req->query_at], 6, "?show=", 6)) {
                status_list = h2o_iovec_init(&req->path.base[req->query_at + 6], req->path.len - req->query_at - 6);
            }
        }
        ret = on_req_json(self, req, status_list);
        return ret;
    }

    return -1;
}

static void on_context_init(h2o_handler_t *_self, h2o_context_t *ctx)
{
    struct st_h2o_root_status_handler_t *self = (void *)_self;
    struct st_h2o_status_context_t *status_ctx = h2o_mem_alloc(sizeof(*status_ctx));

    status_ctx->ctx = ctx;
    h2o_multithread_register_receiver(ctx->queue, &status_ctx->receiver, on_collect_notify);

    h2o_vector_reserve(NULL, &self->receivers, self->receivers.size + 1);
    self->receivers.entries[self->receivers.size++] = &status_ctx->receiver;

    h2o_context_set_handler_context(ctx, &self->super, status_ctx);
}

static void on_context_dispose(h2o_handler_t *_self, h2o_context_t *ctx)
{
    struct st_h2o_root_status_handler_t *self = (void *)_self;
    struct st_h2o_status_context_t *status_ctx = h2o_context_get_handler_context(ctx, &self->super);
    size_t i;

    for (i = 0; i != self->receivers.size; ++i)
        if (self->receivers.entries[i] == &status_ctx->receiver)
            break;
    assert(i != self->receivers.size);
    memmove(self->receivers.entries + i + 1, self->receivers.entries + i, self->receivers.size - i - 1);
    --self->receivers.size;

    h2o_multithread_unregister_receiver(ctx->queue, &status_ctx->receiver);

    free(status_ctx);
}

void h2o_status_register(h2o_pathconf_t *conf)
{
    struct st_h2o_root_status_handler_t *self = (void *)h2o_create_handler(conf, sizeof(*self));
    self->super.on_context_init = on_context_init;
    self->super.on_context_dispose = on_context_dispose;
    self->super.on_req = on_req;
    h2o_config_register_status_handler(conf->global, requests_status_handler);
    h2o_config_register_status_handler(conf->global, events_status_handler);
    h2o_config_register_status_handler(conf->global, durations_status_handler);
}
