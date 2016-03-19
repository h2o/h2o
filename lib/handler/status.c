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

struct st_h2o_status_handler_t {
    h2o_handler_t super;
    H2O_VECTOR(h2o_multithread_receiver_t *) receivers;
};

struct st_h2o_status_context_t {
    h2o_context_t *ctx;
    h2o_multithread_receiver_t receiver;
};

struct st_h2o_status_collector_t {
    struct {
        h2o_req_t *req;
        h2o_multithread_receiver_t *receiver;
    } src;
    h2o_logconf_t *logconf;
    pthread_mutex_t mutex;
    h2o_iovec_t data;
    size_t num_remaining_threads;
};

struct st_h2o_status_message_t {
    h2o_multithread_message_t super;
    struct st_h2o_status_collector_t *collector;
};

struct st_collect_req_status_cbdata_t {
    h2o_logconf_t *logconf;
    h2o_buffer_t *buffer;
};

static int collect_req_status(h2o_req_t *req, void *_cbdata)
{
    struct st_collect_req_status_cbdata_t *cbdata = _cbdata;

    /* collect log */
    char buf[4096];
    size_t len = sizeof(buf);
    char *logline = h2o_log_request(cbdata->logconf, req, &len, buf);

    /* append to buffer */
    assert(len != 0);
    --len; /* omit trailing LF */
    h2o_buffer_reserve(&cbdata->buffer, len + 3);
    cbdata->buffer->bytes[cbdata->buffer->size++] = ',';
    cbdata->buffer->bytes[cbdata->buffer->size++] = '\n';
    cbdata->buffer->bytes[cbdata->buffer->size++] = ' ';
    memcpy(cbdata->buffer->bytes + cbdata->buffer->size, logline, len);
    cbdata->buffer->size += len;

    if (logline != buf)
        free(logline);

    return 0;
}

static void collect_reqs_of_context(struct st_h2o_status_collector_t *collector, h2o_context_t *ctx)
{
    struct st_collect_req_status_cbdata_t cbdata = {collector->logconf};
    int was_last_thread;

    h2o_buffer_init(&cbdata.buffer, &h2o_socket_buffer_prototype);
    ctx->globalconf->http1.callbacks.foreach_request(ctx, collect_req_status, &cbdata);
    ctx->globalconf->http2.callbacks.foreach_request(ctx, collect_req_status, &cbdata);

    pthread_mutex_lock(&collector->mutex);
    if (cbdata.buffer->size != 0) {
        collector->data.base = h2o_mem_realloc(collector->data.base, collector->data.len + cbdata.buffer->size);
        memcpy(collector->data.base + collector->data.len, cbdata.buffer->bytes, cbdata.buffer->size);
        collector->data.len += cbdata.buffer->size;
    }
    was_last_thread = --collector->num_remaining_threads == 0;
    pthread_mutex_unlock(&collector->mutex);

    h2o_buffer_dispose(&cbdata.buffer);

    if (was_last_thread) {
        struct st_h2o_status_message_t *message = h2o_mem_alloc(sizeof(*message));
        message->super = (h2o_multithread_message_t){};
        message->collector = collector;
        h2o_multithread_send_message(collector->src.receiver, &message->super);
    }
}

static void send_response(struct st_h2o_status_collector_t *collector)
{
    static h2o_generator_t generator = {NULL, NULL};
    h2o_req_t *req;

    if ((req = collector->src.req) != NULL) {
        h2o_iovec_t resp[2] = {collector->data, {H2O_STRLIT("\n]\n")}};
        resp[0].base[0] = '[';
        req->res.status = 200;
        req->res.content_length = resp[0].len + resp[1].len;
        h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_CONTENT_TYPE, H2O_STRLIT("text/plain; charset=utf-8"));
        h2o_start_response(req, &generator);
        h2o_send(req, resp,
                 h2o_memis(req->input.method.base, req->input.method.len, H2O_STRLIT("HEAD")) ? 0 : sizeof(resp) / sizeof(resp[0]),
                 1);
    }
    h2o_mem_release_shared(collector);
}

static void on_collect_notify(h2o_multithread_receiver_t *receiver, h2o_linklist_t *messages)
{
    struct st_h2o_status_context_t *status_ctx = H2O_STRUCT_FROM_MEMBER(struct st_h2o_status_context_t, receiver, receiver);

    while (!h2o_linklist_is_empty(messages)) {
        struct st_h2o_status_message_t *message = H2O_STRUCT_FROM_MEMBER(struct st_h2o_status_message_t, super, messages->next);
        struct st_h2o_status_collector_t *collector = message->collector;
        int do_collect;
        h2o_linklist_unlink(&message->super.link);
        free(message);

        /* determine the action */
        pthread_mutex_lock(&collector->mutex);
        do_collect = collector->num_remaining_threads != 0;
        pthread_mutex_unlock(&collector->mutex);

        /* do it */
        if (do_collect) {
            collect_reqs_of_context(collector, status_ctx->ctx);
        } else {
            send_response(collector);
        }
    }
}

static void on_collector_dispose(void *_collector)
{
    struct st_h2o_status_collector_t *collector = _collector;

    h2o_logconf_dispose(collector->logconf);
    pthread_mutex_destroy(&collector->mutex);
    free(collector->data.base);
}

static void on_req_close(void *p)
{
    struct st_h2o_status_collector_t *collector = *(void **)p;
    collector->src.req = NULL;
    h2o_mem_release_shared(collector);
}

static int on_req_json(struct st_h2o_status_handler_t *self, h2o_req_t *req)
{
    h2o_logconf_t *logconf;

#define ELEMENT(key, expr) "\"" key "\": \"" expr "\""
#define X_ELEMENT(id) ELEMENT(id, "%{" id "}x")
#define SEPARATOR ", "
    const char *fmt = "{"
        /* combined_log */
        ELEMENT("host", "%h") SEPARATOR ELEMENT("user", "%u") SEPARATOR ELEMENT("at", "%{%Y%m%dT%H%M%S}t.%{usec_frac}t%{%z}t")
            SEPARATOR ELEMENT("method", "%m") SEPARATOR ELEMENT("path", "%U") SEPARATOR ELEMENT("query", "%q")
                SEPARATOR ELEMENT("protocol", "%H") SEPARATOR ELEMENT("referer", "%{Referer}i")
                    SEPARATOR ELEMENT("user-agent", "%{User-agent}i") SEPARATOR
        /* time */
        X_ELEMENT("connect-time") SEPARATOR X_ELEMENT("request-header-time") SEPARATOR X_ELEMENT("request-body-time")
            SEPARATOR X_ELEMENT("request-total-time") SEPARATOR X_ELEMENT("process-time") SEPARATOR X_ELEMENT("response-time")
                SEPARATOR
        /* connection */
        X_ELEMENT("connection-id") SEPARATOR X_ELEMENT("ssl.protocol-version") SEPARATOR X_ELEMENT("ssl.session-reused")
            SEPARATOR X_ELEMENT("ssl.cipher") SEPARATOR X_ELEMENT("ssl.cipher-bits") SEPARATOR
        /* http2 */
        X_ELEMENT("http2.stream-id") SEPARATOR X_ELEMENT("http2.priority.received.exclusive")
            SEPARATOR X_ELEMENT("http2.priority.received.parent") SEPARATOR X_ELEMENT("http2.priority.received.weight")
        /* end */
        "}";
#undef ELEMENT
#undef X_ELEMENT
#undef SEPARATOR

    { /* compile logconf */
        char errbuf[256];
        if ((logconf = h2o_logconf_compile(fmt, H2O_LOGCONF_ESCAPE_JSON, errbuf)) == NULL) {
            h2o_iovec_t resp = h2o_concat(&req->pool, h2o_iovec_init(H2O_STRLIT("failed to compile log format:")),
                                          h2o_iovec_init(errbuf, strlen(errbuf)));
            h2o_send_error(req, 400, "Invalid Request", resp.base, 0);
            return 0;
        }
    }

    { /* construct collector and send request to every thread */
        struct st_h2o_status_context_t *status_ctx = h2o_context_get_handler_context(req->conn->ctx, &self->super);
        struct st_h2o_status_collector_t *collector = h2o_mem_alloc_shared(NULL, sizeof(*collector), on_collector_dispose);
        size_t i;

        collector->src.req = req;
        collector->src.receiver = &status_ctx->receiver;
        collector->logconf = logconf;
        pthread_mutex_init(&collector->mutex, NULL);
        collector->data = h2o_iovec_init(NULL, 0);
        collector->num_remaining_threads = self->receivers.size;

        for (i = 0; i != self->receivers.size; ++i) {
            struct st_h2o_status_message_t *message = h2o_mem_alloc(sizeof(*message));
            *message = (struct st_h2o_status_message_t){{}, collector};
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
    struct st_h2o_status_handler_t *self = (void *)_self;
    size_t prefix_len = req->pathconf->path.len - (req->pathconf->path.base[req->pathconf->path.len - 1] == '/');
    h2o_iovec_t local_path = h2o_iovec_init(req->path_normalized.base + prefix_len, req->path_normalized.len - prefix_len);

    if (local_path.len == 0 || h2o_memis(local_path.base, local_path.len, H2O_STRLIT("/"))) {
        /* root of the handler returns HTML that renders the status */
        h2o_iovec_t fn;
        const char *root = getenv("H2O_ROOT");
        if (root == NULL)
            root = H2O_TO_STR(H2O_ROOT);
        fn = h2o_concat(&req->pool, h2o_iovec_init(root, strlen(root)), h2o_iovec_init(H2O_STRLIT("/share/h2o/status/index.html")));
        return h2o_file_send(req, 200, "OK", fn.base, h2o_iovec_init(H2O_STRLIT("text/html; charset=utf-8")), 0);
    } else if (h2o_memis(local_path.base, local_path.len, H2O_STRLIT("/json"))) {
        /* "/json" maps to the JSON API */
        return on_req_json(self, req);
    }

    return -1;
}

static void on_context_init(h2o_handler_t *_self, h2o_context_t *ctx)
{
    struct st_h2o_status_handler_t *self = (void *)_self;
    struct st_h2o_status_context_t *status_ctx = h2o_mem_alloc(sizeof(*status_ctx));

    status_ctx->ctx = ctx;
    h2o_multithread_register_receiver(ctx->queue, &status_ctx->receiver, on_collect_notify);

    h2o_vector_reserve(NULL, &self->receivers, self->receivers.size + 1);
    self->receivers.entries[self->receivers.size++] = &status_ctx->receiver;

    h2o_context_set_handler_context(ctx, &self->super, status_ctx);
}

static void on_context_dispose(h2o_handler_t *_self, h2o_context_t *ctx)
{
    struct st_h2o_status_handler_t *self = (void *)_self;
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

void h2o_status_register(h2o_pathconf_t *pathconf)
{
    struct st_h2o_status_handler_t *self = (void *)h2o_create_handler(pathconf, sizeof(*self));
    self->super.on_context_init = on_context_init;
    self->super.on_context_dispose = on_context_dispose;
    self->super.on_req = on_req;
}
