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
#include <stdlib.h>
#include <mruby.h>
#include <mruby/array.h>
#include <mruby/error.h>
#include <mruby/string.h>
#include "h2o/mruby_.h"
#include "embedded.c.h"

struct st_h2o_mruby_chunked_t {
    h2o_doublebuffer_t sending;
    size_t bytes_left; /* SIZE_MAX indicates that the number is undermined */
    enum { H2O_MRUBY_CHUNKED_TYPE_CALLBACK, H2O_MRUBY_CHUNKED_TYPE_SHORTCUT } type;
    mrb_value body_obj; /* becomes nil on eos */
    union {
        struct {
            h2o_buffer_t *receiving;
        } callback;
        struct {
            h2o_mruby_http_request_context_t *client;
            h2o_buffer_t *remaining;
        } shortcut;
    };
};

static void do_send(h2o_mruby_generator_t *generator, h2o_buffer_t **input, int is_final)
{
    h2o_mruby_chunked_t *chunked = generator->chunked;

    assert(!chunked->sending.inflight);

    h2o_iovec_t buf = h2o_doublebuffer_prepare(&chunked->sending, input, generator->req->preferred_chunk_size);
    size_t bufcnt = 1;
    h2o_send_state_t send_state;

    if (is_final && buf.len == chunked->sending.buf->size && (*input)->size == 0) {
        if (buf.len == 0)
            --bufcnt;
        /* send error if the length of content served is smaller than content-length header value */
        if (chunked->bytes_left == 0 || chunked->bytes_left == SIZE_MAX) {
            send_state = H2O_SEND_STATE_FINAL;
        } else {
            send_state = H2O_SEND_STATE_ERROR;
        }
    } else {
        if (buf.len == 0)
            return;
        send_state = H2O_SEND_STATE_IN_PROGRESS;
    }

    h2o_send(generator->req, &buf, bufcnt, send_state);
}

static void do_proceed(h2o_generator_t *_generator, h2o_req_t *req)
{
    h2o_mruby_generator_t *generator = (void *)_generator;
    h2o_mruby_chunked_t *chunked = generator->chunked;
    h2o_buffer_t **input;
    int is_final;

    h2o_doublebuffer_consume(&chunked->sending);

    switch (chunked->type) {
    case H2O_MRUBY_CHUNKED_TYPE_CALLBACK:
        input = &chunked->callback.receiving;
        is_final = mrb_nil_p(chunked->body_obj);
        break;
    case H2O_MRUBY_CHUNKED_TYPE_SHORTCUT:
        if (chunked->shortcut.client != NULL) {
            input = h2o_mruby_http_peek_content(chunked->shortcut.client, &is_final);
            assert(!is_final);
        } else {
            input = &chunked->shortcut.remaining;
            is_final = 1;
        }
        break;
    default:
        h2o_fatal("unexpected type");
        break;
    }

    do_send(generator, input, is_final);
}

static void on_shortcut_notify(h2o_mruby_generator_t *generator)
{
    h2o_mruby_chunked_t *chunked = generator->chunked;
    int is_final;
    h2o_buffer_t **input = h2o_mruby_http_peek_content(chunked->shortcut.client, &is_final);

    if (chunked->bytes_left != SIZE_MAX) {
        if (chunked->bytes_left < (*input)->size)
            (*input)->size = chunked->bytes_left; /* trim data too long */
        chunked->bytes_left -= (*input)->size;
    }

    /* if final, steal socket input buffer to shortcut.remaining, and reset pointer to client */
    if (is_final) {
        chunked->shortcut.remaining = *input;
        h2o_buffer_init(input, get_socket_buffer_prototype());
        input = &chunked->shortcut.remaining;
        h2o_mruby_http_unset_shortcut(generator->ctx->shared->mrb, chunked->shortcut.client, generator);
        chunked->shortcut.client = NULL;
    }

    if (!chunked->sending.inflight)
        do_send(generator, input, is_final);
}

static void close_body_obj(h2o_mruby_generator_t *generator)
{
    h2o_mruby_chunked_t *chunked = generator->chunked;
    mrb_state *mrb = generator->ctx->shared->mrb;

    if (!mrb_nil_p(chunked->body_obj)) {
        /* call close and throw away error */
        if (mrb_respond_to(mrb, chunked->body_obj, generator->ctx->shared->symbols.sym_close))
            mrb_funcall_argv(mrb, chunked->body_obj, generator->ctx->shared->symbols.sym_close, 0, NULL);
        mrb->exc = NULL;
        mrb_gc_unregister(mrb, chunked->body_obj);
        chunked->body_obj = mrb_nil_value();
    }
}

mrb_value h2o_mruby_send_chunked_init(h2o_mruby_generator_t *generator, mrb_value body)
{
    mrb_state *mrb = generator->ctx->shared->mrb;

    h2o_mruby_http_request_context_t *client = h2o_mruby_http_set_shortcut(mrb, body, on_shortcut_notify, generator);
    if (mrb->exc != NULL) {
        return mrb_nil_value();
    }

    h2o_mruby_chunked_t *chunked = h2o_mem_alloc_pool(&generator->req->pool, *chunked, 1);
    h2o_doublebuffer_init(&chunked->sending, get_socket_buffer_prototype());
    chunked->bytes_left = h2o_memis(generator->req->method.base, generator->req->method.len, H2O_STRLIT("HEAD"))
                              ? 0
                              : generator->req->res.content_length;
    generator->super.proceed = do_proceed;
    generator->chunked = chunked;
    mrb_value ret;

    h2o_start_response(generator->req, &generator->super);

    if (client != NULL) {
        chunked->type = H2O_MRUBY_CHUNKED_TYPE_SHORTCUT;
        chunked->shortcut.client = client;
        chunked->shortcut.remaining = NULL;
        on_shortcut_notify(generator);
        ret = mrb_nil_value();
    } else {
        chunked->type = H2O_MRUBY_CHUNKED_TYPE_CALLBACK;
        h2o_buffer_init(&chunked->callback.receiving, get_socket_buffer_prototype());
        ret = mrb_ary_entry(generator->ctx->shared->constants, H2O_MRUBY_CHUNKED_PROC_EACH_TO_FIBER);
    }

    mrb_gc_register(generator->ctx->shared->mrb, body);
    chunked->body_obj = body;
    return ret;
}

void h2o_mruby_send_chunked_dispose(h2o_mruby_generator_t *generator)
{
    h2o_mruby_chunked_t *chunked = generator->chunked;

    h2o_doublebuffer_dispose(&chunked->sending);

    switch (chunked->type) {
    case H2O_MRUBY_CHUNKED_TYPE_CALLBACK:
        h2o_buffer_dispose(&chunked->callback.receiving);
        break;
    case H2O_MRUBY_CHUNKED_TYPE_SHORTCUT:
        /* note: no need to free reference from chunked->client, since it is disposed at the same moment */
        if (chunked->shortcut.remaining != NULL)
            h2o_buffer_dispose(&chunked->shortcut.remaining);
        break;
    }

    if (chunked->shortcut.client != NULL)
        h2o_mruby_http_unset_shortcut(generator->ctx->shared->mrb, chunked->shortcut.client, generator);
    close_body_obj(generator);
}

static mrb_value check_precond(mrb_state *mrb, h2o_mruby_generator_t *generator)
{
    if (generator == NULL || generator->req == NULL)
        return mrb_exc_new_str_lit(mrb, E_RUNTIME_ERROR, "downstream HTTP closed");
    if (generator->req->_generator == NULL)
        return mrb_exc_new_str_lit(mrb, E_RUNTIME_ERROR, "cannot send chunk before sending headers");
    return mrb_nil_value();
}

static mrb_value send_chunked_method(mrb_state *mrb, mrb_value self)
{
    const char *s;
    mrb_int len;
    mrb_value gen;

    /* parse args */
    mrb_get_args(mrb, "so", &s, &len, &gen);

    h2o_mruby_generator_t *generator = h2o_mruby_get_generator(mrb, gen);

    { /* precond check */
        mrb_value exc = check_precond(mrb, generator);
        if (!mrb_nil_p(exc))
            mrb_exc_raise(mrb, exc);
    }

    /* append to send buffer, and send out immediately if necessary */
    if (len != 0) {
        h2o_mruby_chunked_t *chunked = generator->chunked;
        if (chunked->bytes_left != SIZE_MAX) {
            if (len > chunked->bytes_left)
                len = (mrb_int)chunked->bytes_left;
            chunked->bytes_left -= len;
        }
        if (len != 0) {
            h2o_buffer_reserve(&chunked->callback.receiving, len);
            memcpy(chunked->callback.receiving->bytes + chunked->callback.receiving->size, s, len);
            chunked->callback.receiving->size += len;
            if (!chunked->sending.inflight)
                do_send(generator, &chunked->callback.receiving, 0);
        }
    }

    return mrb_nil_value();
}

static mrb_value send_chunked_eos_callback(h2o_mruby_context_t *mctx, mrb_value input, mrb_value *receiver, mrb_value args,
                                           int *run_again)
{
    mrb_state *mrb = mctx->shared->mrb;
    h2o_mruby_generator_t *generator = h2o_mruby_get_generator(mrb, mrb_ary_entry(args, 0));

    { /* precond check */
        mrb_value exc = check_precond(mrb, generator);
        if (!mrb_nil_p(exc)) {
            *run_again = 1;
            return exc;
        }
    }

    h2o_mruby_send_chunked_close(generator);

    return mrb_nil_value();
}

void h2o_mruby_send_chunked_close(h2o_mruby_generator_t *generator)
{
    h2o_mruby_chunked_t *chunked = generator->chunked;

    /* run_fiber will never be called once we enter the fast path, and therefore this function will never get called in that case */
    assert(chunked->type == H2O_MRUBY_CHUNKED_TYPE_CALLBACK);

    close_body_obj(generator);

    if (!chunked->sending.inflight)
        do_send(generator, &chunked->callback.receiving, 1);
}

void h2o_mruby_send_chunked_init_context(h2o_mruby_shared_context_t *shared_ctx)
{
    mrb_state *mrb = shared_ctx->mrb;

    h2o_mruby_eval_expr_location(mrb, H2O_MRUBY_CODE_CHUNKED, "(h2o)lib/handler/mruby/embedded/chunked.rb", 1);
    h2o_mruby_assert(mrb);

    mrb_define_method(mrb, mrb->kernel_module, "_h2o_send_chunk", send_chunked_method, MRB_ARGS_ARG(1, 0));
    h2o_mruby_define_callback(mrb, "_h2o_send_chunk_eos", send_chunked_eos_callback);

    mrb_ary_set(mrb, shared_ctx->constants, H2O_MRUBY_CHUNKED_PROC_EACH_TO_FIBER,
                mrb_funcall(mrb, mrb_top_self(mrb), "_h2o_chunked_proc_each_to_fiber", 0));
    h2o_mruby_assert(mrb);
}
