/*
 * Copyright (c) 2015-2016 DeNA Co., Ltd., Kazuho Oku
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
#include <mruby.h>
#include <mruby/array.h>
#include <mruby/error.h>
#include <mruby/hash.h>
#include <mruby/string.h>
#include <mruby_input_stream.h>
#include "h2o/mruby_.h"
#include "embedded.c.h"

struct st_h2o_mruby_http_request_context_t {
    h2o_mruby_context_t *ctx;
    h2o_httpclient_t *client;
    mrb_value receiver;
    unsigned consumed : 1; /* flag to check that the response body is consumed only once */
    struct {
        h2o_iovec_t method;
        h2o_url_t url;
        h2o_headers_t headers;
        h2o_iovec_t body; /* body.base != NULL indicates that post content exists (and the length MAY be zero) */
        unsigned method_is_head : 1;
        unsigned has_transfer_encoding : 1;
        unsigned can_keepalive : 1;
    } req;
    struct {
        h2o_buffer_t *after_closed; /* when client becomes NULL, rest of the data will be stored to this pointer */
        int has_content;
    } resp;
    struct {
        mrb_value request;
        mrb_value input_stream;
    } refs;
    h2o_mruby_generator_t *shortcut;
    h2o_mem_pool_t pool;
};

struct st_h2o_mruby_http_sender_t {
    h2o_mruby_sender_t super;
    h2o_mruby_http_request_context_t *client;
    h2o_doublebuffer_t sending;
    h2o_buffer_t *remaining;
};

static void attach_receiver(struct st_h2o_mruby_http_request_context_t *ctx, mrb_value receiver)
{
    assert(mrb_nil_p(ctx->receiver));
    ctx->receiver = receiver;
    mrb_gc_register(ctx->ctx->shared->mrb, receiver);
}

static mrb_value detach_receiver(struct st_h2o_mruby_http_request_context_t *ctx)
{
    mrb_value ret = ctx->receiver;
    assert(!mrb_nil_p(ret));
    ctx->receiver = mrb_nil_value();
    mrb_gc_unregister(ctx->ctx->shared->mrb, ret);
    mrb_gc_protect(ctx->ctx->shared->mrb, ret);
    return ret;
}

static void dispose_context(h2o_mruby_http_request_context_t *ctx)
{
    /* ctx must be alive until generator gets disposed when shortcut used */
    assert(ctx->shortcut == NULL);

    /* clear the refs */
    if (ctx->client != NULL) {
        ctx->client->cancel(ctx->client);
    }

    if (!mrb_nil_p(ctx->refs.request))
        DATA_PTR(ctx->refs.request) = NULL;
    if (!mrb_nil_p(ctx->refs.input_stream))
        DATA_PTR(ctx->refs.input_stream) = NULL;

    /* clear bufs */
    h2o_buffer_dispose(&ctx->resp.after_closed);

    h2o_mem_clear_pool(&ctx->pool);

    free(ctx);
}

static int try_dispose_context(h2o_mruby_http_request_context_t *ctx)
{
#define IS_NIL_OR_DEAD(o) (mrb_nil_p(o) || mrb_object_dead_p(ctx->ctx->shared->mrb, mrb_basic_ptr(o)))
    if (IS_NIL_OR_DEAD(ctx->refs.request) && IS_NIL_OR_DEAD(ctx->refs.input_stream)) {
        dispose_context(ctx);
        return 1;
    }
    return 0;
#undef IS_NIL_OR_DEAD
}

static void on_gc_dispose_request(mrb_state *mrb, void *_ctx)
{
    struct st_h2o_mruby_http_request_context_t *ctx = _ctx;
    if (ctx == NULL)
        return;
    ctx->refs.request = mrb_nil_value();
    if (mrb_nil_p(ctx->refs.input_stream))
        dispose_context(ctx);
}

const static struct mrb_data_type request_type = {"http_request", on_gc_dispose_request};

static void on_gc_dispose_input_stream(mrb_state *mrb, void *_ctx)
{
    struct st_h2o_mruby_http_request_context_t *ctx = _ctx;
    if (ctx == NULL)
        return;
    ctx->refs.input_stream = mrb_nil_value();
    if (mrb_nil_p(ctx->refs.request))
        dispose_context(ctx);
}

const static struct mrb_data_type input_stream_type = {"http_input_stream", on_gc_dispose_input_stream};

static mrb_value create_already_consumed_error(mrb_state *mrb)
{
    return mrb_exc_new_str_lit(mrb, E_RUNTIME_ERROR, "http response body is already consumed");
}

static h2o_buffer_t **peek_content(h2o_mruby_http_request_context_t *ctx, int *is_final)
{
    *is_final = ctx->client == NULL;
    return ctx->client != NULL && ctx->resp.has_content ? ctx->client->buf : &ctx->resp.after_closed;
}

static void on_shortcut_notify(h2o_mruby_generator_t *generator)
{
    struct st_h2o_mruby_http_sender_t *sender = (void *)generator->sender;
    assert(sender->client->shortcut == generator);

    int is_final;
    h2o_buffer_t **input = peek_content(sender->client, &is_final);

    if (sender->super.bytes_left != SIZE_MAX && sender->super.bytes_left < (*input)->size)
        (*input)->size = sender->super.bytes_left; /* trim data too long */

    /* if final, steal socket input buffer to shortcut.remaining, and reset pointer to client */
    if (is_final) {
        sender->remaining = *input;
        h2o_buffer_init(input, &h2o_socket_buffer_prototype);
        input = &sender->remaining;
        sender->client->shortcut = NULL;
    }

    if (!sender->super.final_sent && !sender->sending.inflight)
        h2o_mruby_sender_do_send_buffer(generator, &sender->sending, input, is_final);
}

static void do_sender_start(h2o_mruby_generator_t *generator)
{
    struct st_h2o_mruby_http_sender_t *sender = (void *)generator->sender;

    on_shortcut_notify(generator);

    if (!sender->super.final_sent && !sender->sending.inflight) {
        h2o_doublebuffer_prepare_empty(&sender->sending);
        h2o_mruby_sender_do_send(generator, NULL, 0, H2O_SEND_STATE_IN_PROGRESS);
    }
}

static void do_sender_proceed(h2o_generator_t *_generator, h2o_req_t *req)
{
    h2o_mruby_generator_t *generator = (void *)_generator;
    struct st_h2o_mruby_http_sender_t *sender = (void *)generator->sender;
    h2o_buffer_t **input;
    int is_final;

    h2o_doublebuffer_consume(&sender->sending);

    if (sender->client != NULL) {
        input = peek_content(sender->client, &is_final);
        assert(!is_final);
    } else {
        input = &sender->remaining;
        is_final = 1;
    }

    if (!sender->super.final_sent && !sender->sending.inflight)
        h2o_mruby_sender_do_send_buffer(generator, &sender->sending, input, is_final);
}

static void do_sender_dispose(h2o_mruby_generator_t *generator)
{
    struct st_h2o_mruby_http_sender_t *sender = (void *)generator->sender;

    h2o_doublebuffer_dispose(&sender->sending);

    /* note: no need to free reference from sender->client, since it is disposed at the same moment */
    if (sender->remaining != NULL)
        h2o_buffer_dispose(&sender->remaining);

    if (sender->client != NULL) {
        assert(sender->client->shortcut == generator);
        sender->client->shortcut = NULL;
    }

    h2o_mruby_sender_close_body(generator);
}

h2o_mruby_sender_t *h2o_mruby_http_sender_create(h2o_mruby_generator_t *generator, mrb_value body)
{
    mrb_state *mrb = generator->ctx->shared->mrb;
    struct st_h2o_mruby_http_request_context_t *ctx;

    assert(mrb->exc == NULL);

    if ((ctx = mrb_data_check_get_ptr(mrb, body, &input_stream_type)) == NULL)
        return NULL;
    assert(ctx->shortcut == NULL);

    if (ctx->consumed) {
        mrb->exc = mrb_ptr(create_already_consumed_error(mrb));
        return NULL;
    }
    ctx->consumed = 1;

    struct st_h2o_mruby_http_sender_t *sender =
        (void *)h2o_mruby_sender_create(generator, body, H2O_ALIGNOF(*sender), sizeof(*sender));
    h2o_doublebuffer_init(&sender->sending, &h2o_socket_buffer_prototype);
    sender->client = ctx;
    sender->remaining = NULL;

    sender->super.start = do_sender_start;
    sender->super.proceed = do_sender_proceed;
    sender->super.dispose = do_sender_dispose;

    ctx->shortcut = generator;

    return &sender->super;
}

static void post_response(struct st_h2o_mruby_http_request_context_t *ctx, int status, const h2o_header_t *headers_sorted,
                          size_t num_headers, int header_requires_dup)
{
    mrb_state *mrb = ctx->ctx->shared->mrb;
    int gc_arena = mrb_gc_arena_save(mrb);
    size_t i;

    mrb_value resp = mrb_ary_new_capa(mrb, 3);

    /* set status */
    mrb_ary_set(mrb, resp, 0, mrb_fixnum_value(status));

    /* set headers */
    mrb_value headers_hash = mrb_hash_new_capa(mrb, (int)num_headers);
    for (i = 0; i < num_headers; ++i) {
        /* skip the headers, we determine the eos! */
        if (h2o_memis(headers_sorted[i].name, headers_sorted[i].name->len, H2O_STRLIT("content-length")) ||
            h2o_memis(headers_sorted[i].name, headers_sorted[i].name->len, H2O_STRLIT("transfer-encoding")))
            continue;
        /* build and set the hash entry */
        mrb_value k, v;
        if (header_requires_dup) {
            k = h2o_mruby_new_str(mrb, headers_sorted[i].name->base, headers_sorted[i].name->len);
            v = h2o_mruby_new_str(mrb, headers_sorted[i].value.base, headers_sorted[i].value.len);
        } else {
            k = h2o_mruby_new_str_static(mrb, headers_sorted[i].name->base, headers_sorted[i].name->len);
            v = h2o_mruby_new_str_static(mrb, headers_sorted[i].value.base, headers_sorted[i].value.len);
        }
        while (i + 1 < num_headers && h2o_memis(headers_sorted[i].name->base, headers_sorted[i].name->len,
                                                headers_sorted[i + 1].name->base, headers_sorted[i + 1].name->len)) {
            ++i;
            v = mrb_str_cat_lit(mrb, v, "\n");
            v = mrb_str_cat(mrb, v, headers_sorted[i].value.base, headers_sorted[i].value.len);
        }
        mrb_hash_set(mrb, headers_hash, k, v);
    }
    mrb_ary_set(mrb, resp, 1, headers_hash);

    /* set input stream */
    assert(mrb_nil_p(ctx->refs.input_stream));
    mrb_value input_stream_class;
    if (ctx->req.method_is_head || status == 101 || status == 204 || status == 304) {
        input_stream_class = mrb_ary_entry(ctx->ctx->shared->constants, H2O_MRUBY_HTTP_EMPTY_INPUT_STREAM_CLASS);
    } else {
        input_stream_class = mrb_ary_entry(ctx->ctx->shared->constants, H2O_MRUBY_HTTP_INPUT_STREAM_CLASS);
    }
    ctx->refs.input_stream = h2o_mruby_create_data_instance(mrb, input_stream_class, ctx, &input_stream_type);
    mrb_ary_set(mrb, resp, 2, ctx->refs.input_stream);

    if (mrb_nil_p(ctx->receiver)) {
        /* is async */
        mrb_funcall(mrb, ctx->refs.request, "_set_response", 1, resp);
        if (mrb->exc != NULL) {
            fprintf(stderr, "_set_response failed\n");
            abort();
        }
    } else {
        /* send response to the waiting receiver */
        h2o_mruby_run_fiber(ctx->ctx, detach_receiver(ctx), resp, NULL);
    }

    mrb_gc_arena_restore(mrb, gc_arena);
}

static void post_error(struct st_h2o_mruby_http_request_context_t *ctx, const char *errstr)
{
    size_t errstr_len = strlen(errstr);
    h2o_buffer_reserve(&ctx->resp.after_closed, errstr_len);
    memcpy(ctx->resp.after_closed->bytes + ctx->resp.after_closed->size, errstr, errstr_len);
    ctx->resp.after_closed->size += errstr_len;
    ctx->resp.has_content = 1;

    static const h2o_iovec_t client_warning = {H2O_STRLIT("client-warning")};
    h2o_header_t headers_sorted[] = {
        {(h2o_iovec_t *)&client_warning, NULL, h2o_iovec_init(errstr, errstr_len)},
        {&H2O_TOKEN_CONTENT_TYPE->buf, NULL, h2o_iovec_init(H2O_STRLIT("text/plain; charset=utf-8"))},
    };

    post_response(ctx, 500, headers_sorted, sizeof(headers_sorted) / sizeof(headers_sorted[0]), 1);
}

static mrb_value build_chunk(struct st_h2o_mruby_http_request_context_t *ctx)
{
    mrb_value chunk;

    assert(ctx->resp.has_content);

    if (ctx->client != NULL) {
        assert((*ctx->client->buf)->size != 0);
        chunk = h2o_mruby_new_str(ctx->ctx->shared->mrb, (*ctx->client->buf)->bytes, (*ctx->client->buf)->size);
        h2o_buffer_consume(ctx->client->buf, (*ctx->client->buf)->size);
        ctx->resp.has_content = 0;
    } else {
        if (ctx->resp.after_closed->size == 0) {
            chunk = mrb_nil_value();
        } else {
            chunk = h2o_mruby_new_str(ctx->ctx->shared->mrb, ctx->resp.after_closed->bytes, ctx->resp.after_closed->size);
            h2o_buffer_consume(&ctx->resp.after_closed, ctx->resp.after_closed->size);
        }
        /* has_content is retained as true, so that repeated calls will return nil immediately */
    }

    return chunk;
}

static int do_on_body(h2o_httpclient_t *client, const char *errstr)
{
    struct st_h2o_mruby_http_request_context_t *ctx = client->data;

    if (errstr != NULL) {
        h2o_buffer_t *tmp = ctx->resp.after_closed;
        ctx->resp.after_closed = *client->buf;
        *client->buf = tmp;
        ctx->client = NULL;
        ctx->resp.has_content = 1;
    } else if ((*client->buf)->size != 0) {
        ctx->resp.has_content = 1;
    }

    if (ctx->resp.has_content) {
        if (ctx->shortcut != NULL) {
            on_shortcut_notify(ctx->shortcut);
        } else if (!mrb_nil_p(ctx->receiver)) {
            mrb_value chunk = build_chunk(ctx);
            h2o_mruby_run_fiber(ctx->ctx, detach_receiver(ctx), chunk, NULL);
        }
    }

    return 0;
}

static int on_body(h2o_httpclient_t *client, const char *errstr)
{
    struct st_h2o_mruby_http_request_context_t *ctx = client->data;
    if (try_dispose_context(ctx))
        return -1;

    int gc_arena = mrb_gc_arena_save(ctx->ctx->shared->mrb);
    mrb_gc_protect(ctx->ctx->shared->mrb, ctx->refs.input_stream);

    int ret = do_on_body(client, errstr);

    mrb_gc_arena_restore(ctx->ctx->shared->mrb, gc_arena);

    return ret;
}

static int headers_sort_cb(const void *_x, const void *_y)
{
    const h2o_header_t *x = _x, *y = _y;

    if (x->name->len < y->name->len)
        return -1;
    if (x->name->len > y->name->len)
        return 1;
    return memcmp(x->name->base, y->name->base, x->name->len);
}

static h2o_httpclient_body_cb do_on_head(h2o_httpclient_t *client, const char *errstr, int version, int status, h2o_iovec_t msg,
                                      h2o_header_t *headers, size_t num_headers, int header_requires_dup)
{
    struct st_h2o_mruby_http_request_context_t *ctx = client->data;

    if (errstr != NULL) {
        if (errstr != h2o_httpclient_error_is_eos) {
            /* error */
            post_error(ctx, errstr);
            return NULL;
        }
        /* closed without body */
        ctx->client = NULL;
    }

    qsort(headers, num_headers, sizeof(headers[0]), headers_sort_cb);
    post_response(ctx, status, headers, num_headers, header_requires_dup);

    return on_body;
}

static h2o_httpclient_body_cb on_head(h2o_httpclient_t *client, const char *errstr, int version, int status, h2o_iovec_t msg,
                                      h2o_header_t *headers, size_t num_headers, int header_requires_dup)
{
    struct st_h2o_mruby_http_request_context_t *ctx = client->data;
    if (try_dispose_context(ctx))
        return NULL;

    int gc_arena = mrb_gc_arena_save(ctx->ctx->shared->mrb);
    mrb_gc_protect(ctx->ctx->shared->mrb, ctx->refs.request);

    h2o_httpclient_body_cb cb = do_on_head(client, errstr, version, status, msg, headers, num_headers, header_requires_dup);

    mrb_gc_arena_restore(ctx->ctx->shared->mrb, gc_arena);

    return cb;
}

static h2o_httpclient_head_cb do_on_connect(h2o_httpclient_t *client, const char *errstr, h2o_iovec_t *method, h2o_url_t *url,
                                         const h2o_header_t **headers, size_t *num_headers, h2o_iovec_t *body,
                                         h2o_httpclient_proceed_req_cb *proceed_req_cb, h2o_httpclient_properties_t *props,
                                         h2o_url_t *origin)
{
    struct st_h2o_mruby_http_request_context_t *ctx = client->data;

    if (errstr != NULL) {
        post_error(ctx, errstr);
        return NULL;
    }

    if (props->connection_header && !ctx->req.can_keepalive) {
        *props->connection_header = h2o_iovec_init(H2O_STRLIT("close"));
    }

    *method = ctx->req.method;
    *url = ctx->req.url;
    *headers = ctx->req.headers.entries;
    *num_headers = ctx->req.headers.size;

    if (ctx->req.body.base != NULL) {
        *body = ctx->req.body;
    } else {
        *body = h2o_iovec_init(NULL, 0);
    }

    return on_head;
}

static h2o_httpclient_head_cb on_connect(h2o_httpclient_t *client, const char *errstr, h2o_iovec_t *method, h2o_url_t *url,
                                         const h2o_header_t **headers, size_t *num_headers, h2o_iovec_t *body,
                                         h2o_httpclient_proceed_req_cb *proceed_req_cb, h2o_httpclient_properties_t *props,
                                         h2o_url_t *origin)
{
    struct st_h2o_mruby_http_request_context_t *ctx = client->data;
    if (try_dispose_context(ctx))
        return NULL;

    int gc_arena = mrb_gc_arena_save(ctx->ctx->shared->mrb);
    mrb_gc_protect(ctx->ctx->shared->mrb, ctx->refs.request);

    h2o_httpclient_head_cb cb = do_on_connect(client, errstr, method, url, headers, num_headers, body, proceed_req_cb, props, origin);

    mrb_gc_arena_restore(ctx->ctx->shared->mrb, gc_arena);

    return cb;
}

static int flatten_request_header(h2o_mruby_shared_context_t *shared_ctx, h2o_iovec_t *name, h2o_iovec_t value, void *_ctx)
{
    struct st_h2o_mruby_http_request_context_t *ctx = _ctx;

    /* ignore certain headers */
    if (h2o_lcstris(name->base, name->len, H2O_STRLIT("content-length")) || h2o_lcstris(name->base, name->len, H2O_STRLIT("host")))
        return 0;

    if (h2o_lcstris(name->base, name->len, H2O_STRLIT("connection"))) {
        if (!ctx->req.can_keepalive)
            return 0;
    }

    /* mark the existence of transfer-encoding in order to prevent us from adding content-length header */
    if (h2o_lcstris(name->base, name->len, H2O_STRLIT("transfer-encoding")))
        ctx->req.has_transfer_encoding = 1;

    h2o_add_header_by_str(&ctx->pool, &ctx->req.headers, name->base, name->len, 1, NULL, value.base, value.len);

    return 0;
}

static mrb_value http_request_method(mrb_state *mrb, mrb_value self)
{
    struct st_h2o_mruby_http_request_context_t *ctx;
    const char *arg_url;
    mrb_int arg_url_len;
    mrb_value arg_hash;
    h2o_iovec_t method;
    h2o_url_t url;

    h2o_mruby_shared_context_t *shared_ctx = mrb->ud;
    assert(shared_ctx->current_context != NULL);

    /* parse args */
    arg_hash = mrb_nil_value();
    mrb_get_args(mrb, "s|H", &arg_url, &arg_url_len, &arg_hash);

    /* allocate context and initialize */
    ctx = h2o_mem_alloc(sizeof(*ctx));
    memset(ctx, 0, offsetof(struct st_h2o_mruby_http_request_context_t, pool));
    h2o_mem_init_pool(&ctx->pool);

    ctx->ctx = shared_ctx->current_context;
    ctx->receiver = mrb_nil_value();
    h2o_buffer_init(&ctx->resp.after_closed, &h2o_socket_buffer_prototype);
    ctx->refs.request = mrb_nil_value();
    ctx->refs.input_stream = mrb_nil_value();
    ctx->req.can_keepalive = h2o_socketpool_can_keepalive(&shared_ctx->ctx->globalconf->proxy.global_socketpool);

    /* uri */
    if (h2o_url_parse(arg_url, arg_url_len, &url) != 0)
        mrb_raise(mrb, E_ARGUMENT_ERROR, "invaild URL");
    h2o_url_copy(&ctx->pool, &ctx->req.url, &url);

    /* method */
    method = h2o_iovec_init(H2O_STRLIT("GET"));
    if (mrb_hash_p(arg_hash)) {
        mrb_value t = mrb_hash_get(mrb, arg_hash, mrb_symbol_value(ctx->ctx->shared->symbols.sym_method));
        if (!mrb_nil_p(t)) {
            t = mrb_str_to_str(mrb, t);
            method = h2o_iovec_init(RSTRING_PTR(t), RSTRING_LEN(t));
            if (h2o_memis(method.base, method.len, H2O_STRLIT("HEAD"))) {
                ctx->req.method_is_head = 1;
            }
        }
    }
    ctx->req.method = h2o_strdup(&ctx->pool, method.base, method.len);

    /* headers */
    if (mrb_hash_p(arg_hash)) {
        mrb_value headers = mrb_hash_get(mrb, arg_hash, mrb_symbol_value(ctx->ctx->shared->symbols.sym_headers));
        if (!mrb_nil_p(headers)) {
            if (h2o_mruby_iterate_rack_headers(ctx->ctx->shared, headers, flatten_request_header, ctx) != 0) {
                mrb_value exc = mrb_obj_value(mrb->exc);
                mrb->exc = NULL;
                mrb_exc_raise(mrb, exc);
            }
        }
    }

    /* body */
    if (mrb_hash_p(arg_hash)) {
        mrb_value body = mrb_hash_get(mrb, arg_hash, mrb_symbol_value(ctx->ctx->shared->symbols.sym_body));
        if (!mrb_nil_p(body)) {
            if (!mrb_string_p(body)) {
                body = mrb_funcall(mrb, body, "read", 0);
                if (!mrb_string_p(body))
                    mrb_raise(mrb, E_ARGUMENT_ERROR, "body.read did not return string");
            }
            // FIXME: how to handle fastpath and who frees this?
            ctx->req.body = h2o_strdup(&ctx->pool, RSTRING_PTR(body), RSTRING_LEN(body));
            if (!ctx->req.has_transfer_encoding) {
                char *buf = h2o_mem_alloc_pool(&ctx->pool, char, sizeof(H2O_UINT64_LONGEST_STR) - 1);
                size_t l = (size_t)sprintf(buf, "%zu", ctx->req.body.len);
                h2o_add_header(&ctx->pool, &ctx->req.headers, H2O_TOKEN_CONTENT_LENGTH, NULL, buf, l);
            }
        }
    }

    /* build request and connect */
    ctx->refs.request = h2o_mruby_create_data_instance(
        mrb, mrb_ary_entry(ctx->ctx->shared->constants, H2O_MRUBY_HTTP_REQUEST_CLASS), ctx, &request_type);

    h2o_httpclient_connect(&ctx->client, &ctx->pool, ctx, &shared_ctx->ctx->proxy.client_ctx, &shared_ctx->ctx->proxy.connpool,
                           &url, on_connect);

    return ctx->refs.request;
}

static mrb_value http_join_response_callback(h2o_mruby_context_t *mctx, mrb_value input, mrb_value *receiver, mrb_value args,
                                             int *run_again)
{
    mrb_state *mrb = mctx->shared->mrb;
    struct st_h2o_mruby_http_request_context_t *ctx;

    if ((ctx = mrb_data_check_get_ptr(mrb, mrb_ary_entry(args, 0), &request_type)) == NULL) {
        *run_again = 1;
        return mrb_exc_new_str_lit(mrb, E_ARGUMENT_ERROR, "HttpRequest#join wrong self");
    }

    attach_receiver(ctx, *receiver);
    return mrb_nil_value();
}

static mrb_value http_fetch_chunk_callback(h2o_mruby_context_t *mctx, mrb_value input, mrb_value *receiver, mrb_value args,
                                           int *run_again)
{
    mrb_state *mrb = mctx->shared->mrb;
    struct st_h2o_mruby_http_request_context_t *ctx;
    mrb_value ret;

    if ((ctx = mrb_data_check_get_ptr(mrb, mrb_ary_entry(args, 0), &input_stream_type)) == NULL) {
        *run_again = 1;
        return mrb_exc_new_str_lit(mrb, E_ARGUMENT_ERROR, "_HttpInputStream#each wrong self");
    }

    mrb_value first = mrb_ary_entry(args, 1);
    if (mrb_bool(first)) {
        /* check the body hasn't already consumed */
        if (ctx->consumed) {
            *run_again = 1;
            return create_already_consumed_error(mrb);
        }
        ctx->consumed = 1;
    }

    if (ctx->resp.has_content) {
        ret = build_chunk(ctx);
        *run_again = 1;
    } else {
        attach_receiver(ctx, *receiver);
        ret = mrb_nil_value();
    }

    return ret;
}

void h2o_mruby_http_request_init_context(h2o_mruby_shared_context_t *ctx)
{
    mrb_state *mrb = ctx->mrb;

    h2o_mruby_eval_expr_location(mrb, H2O_MRUBY_CODE_HTTP_REQUEST, "(h2o)lib/handler/mruby/embedded/http_request.rb", 1);
    h2o_mruby_assert(mrb);

    struct RClass *module, *klass;
    module = mrb_define_module(mrb, "H2O");

    mrb_define_method(mrb, mrb->kernel_module, "http_request", http_request_method, MRB_ARGS_ARG(1, 2));

    klass = mrb_class_get_under(mrb, module, "HttpRequest");
    mrb_ary_set(mrb, ctx->constants, H2O_MRUBY_HTTP_REQUEST_CLASS, mrb_obj_value(klass));

    klass = mrb_class_get_under(mrb, module, "HttpInputStream");
    mrb_ary_set(mrb, ctx->constants, H2O_MRUBY_HTTP_INPUT_STREAM_CLASS, mrb_obj_value(klass));

    klass = mrb_class_get_under(mrb, klass, "Empty");
    mrb_ary_set(mrb, ctx->constants, H2O_MRUBY_HTTP_EMPTY_INPUT_STREAM_CLASS, mrb_obj_value(klass));

    h2o_mruby_define_callback(mrb, "_h2o__http_join_response", http_join_response_callback);
    h2o_mruby_define_callback(mrb, "_h2o__http_fetch_chunk", http_fetch_chunk_callback);
}
