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

struct st_h2o_mruby_callback_sender_t {
    h2o_mruby_sender_t super;
    h2o_doublebuffer_t sending;
    h2o_buffer_t *receiving;
    unsigned has_error : 1;
};

void h2o_mruby_sender_do_send(h2o_mruby_generator_t *generator, h2o_sendvec_t *bufs, size_t bufcnt, h2o_send_state_t state)
{
    h2o_mruby_sender_t *sender = generator->sender;
    assert(!sender->final_sent);

    if (sender->bytes_left != SIZE_MAX) {
        int i = 0;
        for (i = 0; i != bufcnt && sender->bytes_left > 0; ++i) {
            if (sender->bytes_left < bufs[i].len)
                bufs[i].len = sender->bytes_left;
            sender->bytes_left -= bufs[i].len;
        }
        bufcnt = i;
    }

    if (state == H2O_SEND_STATE_FINAL) {
        if (!(sender->bytes_left == 0 || sender->bytes_left == SIZE_MAX)) {
            /* send error if the length of content served is smaller than content-length header value */
            state = H2O_SEND_STATE_ERROR;
        }
    }

    if (!h2o_send_state_is_in_progress(state))
        sender->final_sent = 1;

    h2o_sendvec(generator->req, bufs, bufcnt, state);
}

void h2o_mruby_sender_do_send_buffer(h2o_mruby_generator_t *generator, h2o_doublebuffer_t *db, h2o_buffer_t **input, int is_final)
{
    assert(!db->inflight);

    h2o_iovec_t buf = h2o_doublebuffer_prepare(db, input, generator->req->preferred_chunk_size);
    size_t bufcnt = 1;
    h2o_send_state_t send_state;

    if (is_final && buf.len == db->buf->size && (*input)->size == 0) {
        if (buf.len == 0)
            --bufcnt;
        send_state = H2O_SEND_STATE_FINAL;
    } else {
        if (buf.len == 0)
            return;
        send_state = H2O_SEND_STATE_IN_PROGRESS;
    }

    h2o_sendvec_t vec;
    h2o_sendvec_init_raw(&vec, buf.base, buf.len);
    h2o_mruby_sender_do_send(generator, &vec, bufcnt, send_state);
}

void h2o_mruby_sender_close_body(h2o_mruby_generator_t *generator)
{
    h2o_mruby_sender_t *sender = generator->sender;
    mrb_state *mrb = generator->ctx->shared->mrb;

    if (!mrb_nil_p(sender->body_obj)) {
        /* call close and throw away error */
        if (mrb_respond_to(mrb, sender->body_obj, generator->ctx->shared->symbols.sym_close))
            mrb_funcall_argv(mrb, sender->body_obj, generator->ctx->shared->symbols.sym_close, 0, NULL);
        mrb->exc = NULL;
        mrb_gc_unregister(mrb, sender->body_obj);
        sender->body_obj = mrb_nil_value();
    }
}

h2o_mruby_sender_t *h2o_mruby_sender_create(h2o_mruby_generator_t *generator, mrb_value body, size_t alignment, size_t sz)
{
    h2o_mruby_sender_t *sender = h2o_mem_alloc_pool_aligned(&generator->req->pool, alignment, sz);
    memset(sender, 0, sz);
    sender->body_obj = body;
    if (!mrb_nil_p(body))
        mrb_gc_register(generator->ctx->shared->mrb, body);
    sender->bytes_left = h2o_memis(generator->req->method.base, generator->req->method.len, H2O_STRLIT("HEAD"))
                             ? 0
                             : generator->req->res.content_length;
    return sender;
}

static void do_callback_sender_start(h2o_mruby_generator_t *generator)
{
    struct st_h2o_mruby_callback_sender_t *sender = (void *)generator->sender;
    mrb_state *mrb = generator->ctx->shared->mrb;
    mrb_value proc = mrb_ary_entry(generator->ctx->shared->constants, H2O_MRUBY_SENDER_PROC_EACH_TO_FIBER);
    mrb_value input = mrb_ary_new_capa(mrb, 2);
    mrb_ary_set(mrb, input, 0, sender->super.body_obj);
    mrb_ary_set(mrb, input, 1, generator->refs.generator);
    h2o_mruby_run_fiber(generator->ctx, proc, input, 0);

    if (!sender->super.final_sent && !sender->sending.inflight) {
        h2o_doublebuffer_prepare_empty(&sender->sending);
        h2o_mruby_sender_do_send(generator, NULL, 0, H2O_SEND_STATE_IN_PROGRESS);
    }
}

static void do_callback_proceed(h2o_generator_t *_generator, h2o_req_t *req)
{
    h2o_mruby_generator_t *generator = (void *)_generator;
    struct st_h2o_mruby_callback_sender_t *sender = (void *)generator->sender;

    assert(!sender->super.final_sent);

    h2o_doublebuffer_consume(&sender->sending);

    if (sender->has_error) {
        h2o_mruby_sender_do_send(generator, NULL, 0, H2O_SEND_STATE_ERROR);
    } else {
        int is_final = mrb_nil_p(sender->super.body_obj);
        h2o_mruby_sender_do_send_buffer(generator, &sender->sending, &sender->receiving, is_final);
    }
}

static void do_callback_sender_dispose(h2o_mruby_generator_t *generator)
{
    struct st_h2o_mruby_callback_sender_t *sender = (void *)generator->sender;
    h2o_doublebuffer_dispose(&sender->sending);
    h2o_buffer_dispose(&sender->receiving);
    h2o_mruby_sender_close_body(generator);
}

h2o_mruby_sender_t *callback_sender_create(h2o_mruby_generator_t *generator, mrb_value body)
{
    struct st_h2o_mruby_callback_sender_t *sender =
        (void *)h2o_mruby_sender_create(generator, body, H2O_ALIGNOF(*sender), sizeof(*sender));
    h2o_doublebuffer_init(&sender->sending, &h2o_socket_buffer_prototype);
    h2o_buffer_init(&sender->receiving, &h2o_socket_buffer_prototype);

    sender->super.start = do_callback_sender_start;
    sender->super.proceed = do_callback_proceed;
    sender->super.dispose = do_callback_sender_dispose;

    return &sender->super;
}

int h2o_mruby_init_sender(h2o_mruby_generator_t *generator, mrb_value body)
{
    mrb_state *mrb = generator->ctx->shared->mrb;
    h2o_mruby_sender_t *sender;

#define TRY(func)                                                                                                                  \
    do {                                                                                                                           \
        sender = func(generator, body);                                                                                            \
        if (mrb->exc != NULL)                                                                                                      \
            return -1;                                                                                                             \
        if (sender != NULL)                                                                                                        \
            goto Found;                                                                                                            \
    } while (0)

    TRY(h2o_mruby_http_sender_create);
    TRY(h2o_mruby_middleware_sender_create);
    TRY(callback_sender_create);

#undef TRY

    return -1;

Found:
    generator->sender = sender;
    generator->super.proceed = sender->proceed;
    return 0;
}

static mrb_value check_precond(mrb_state *mrb, h2o_mruby_generator_t *generator)
{
    if (generator == NULL || generator->req == NULL)
        return mrb_exc_new_str_lit(mrb, E_RUNTIME_ERROR, "downstream HTTP closed");
    if (generator->req->_generator == NULL)
        return mrb_exc_new_str_lit(mrb, E_RUNTIME_ERROR, "cannot send chunk before sending headers");
    return mrb_nil_value();
}

static mrb_value send_chunk_method(mrb_state *mrb, mrb_value self)
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
        struct st_h2o_mruby_callback_sender_t *sender = (void *)generator->sender;
        if (sender->super.bytes_left != SIZE_MAX && sender->super.bytes_left < len)
            len = sender->super.bytes_left; /* trim data too long */
        if (len != 0) {
            if ((h2o_buffer_try_reserve(&sender->receiving, len)).base == NULL) {
                mrb_value exc = mrb_exc_new_str_lit(mrb, E_RUNTIME_ERROR, "failed to allocate memory");
                mrb_exc_raise(mrb, exc);
            }
            memcpy(sender->receiving->bytes + sender->receiving->size, s, len);
            sender->receiving->size += len;
            if (!sender->super.final_sent && !sender->sending.inflight)
                h2o_mruby_sender_do_send_buffer(generator, &sender->sending, &sender->receiving, 0);
        }
    }

    return mrb_nil_value();
}

static mrb_value send_chunk_eos_callback(h2o_mruby_context_t *mctx, mrb_value input, mrb_value *receiver, mrb_value args,
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

    struct st_h2o_mruby_callback_sender_t *sender = (void *)generator->sender;
    if (!sender->super.final_sent && !sender->sending.inflight)
        h2o_mruby_sender_do_send_buffer(generator, &sender->sending, &sender->receiving, 1);
    h2o_mruby_sender_close_body(generator);

    return mrb_nil_value();
}

static mrb_value handle_error_callback(h2o_mruby_context_t *mctx, mrb_value input, mrb_value *receiver, mrb_value args,
                                       int *run_again)
{
    mrb_state *mrb = mctx->shared->mrb;
    mrb_value err = mrb_ary_entry(args, 0);
    mrb_value gen = mrb_ary_entry(args, 1);
    h2o_mruby_generator_t *generator = h2o_mruby_get_generator(mrb, gen);

    *run_again = 1;

    mrb_value exc = check_precond(mrb, generator);
    if (!mrb_nil_p(exc))
        return exc;

    struct st_h2o_mruby_callback_sender_t *sender = (void *)generator->sender;
    if (!sender->super.final_sent) {
        if (sender->sending.inflight) {
            sender->has_error = 1;
        } else {
            h2o_mruby_sender_do_send(generator, NULL, 0, H2O_SEND_STATE_ERROR);
        }
    }
    h2o_mruby_sender_close_body(generator);

    return err;
}

void h2o_mruby_sender_init_context(h2o_mruby_shared_context_t *shared_ctx)
{
    mrb_state *mrb = shared_ctx->mrb;

    h2o_mruby_eval_expr_location(mrb, H2O_MRUBY_CODE_SENDER, "(h2o)lib/handler/mruby/embedded/sender.rb", 1);
    h2o_mruby_assert(mrb);

    mrb_define_method(mrb, mrb->kernel_module, "_h2o_sender_send_chunk", send_chunk_method, MRB_ARGS_ARG(1, 0));
    h2o_mruby_define_callback(mrb, "_h2o_sender_send_chunk_eos", send_chunk_eos_callback);
    h2o_mruby_define_callback(mrb, "_h2o_sender_handle_error", handle_error_callback);

    mrb_ary_set(mrb, shared_ctx->constants, H2O_MRUBY_SENDER_PROC_EACH_TO_FIBER,
                mrb_funcall(mrb, mrb_top_self(mrb), "_h2o_sender_proc_each_to_fiber", 0));
    h2o_mruby_assert(mrb);
}
