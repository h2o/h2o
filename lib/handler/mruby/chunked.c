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

struct st_h2o_mruby_callback_chunked_t {
    h2o_mruby_chunked_t super;
    h2o_doublebuffer_t sending;
    h2o_buffer_t *receiving;
};

void h2o_mruby_chunked_send(h2o_mruby_generator_t *generator, h2o_iovec_t *bufs, size_t bufcnt, h2o_send_state_t state)
{
    h2o_mruby_chunked_t *chunked = generator->chunked;

    if (chunked->bytes_left != SIZE_MAX) {
        int i = 0;
        for (i = 0; i != bufcnt && chunked->bytes_left > 0; ++i) {
            if (chunked->bytes_left < bufs[i].len)
                bufs[i].len = chunked->bytes_left;
            chunked->bytes_left -= bufs[i].len;
        }
        bufcnt = i;
    }

    if (state == H2O_SEND_STATE_FINAL) {
        if (!(chunked->bytes_left == 0 || chunked->bytes_left == SIZE_MAX)) {
            /* send error if the length of content served is smaller than content-length header value */
            state = H2O_SEND_STATE_ERROR;
        }
    }

    h2o_send(generator->req, bufs, bufcnt, state);
}

void h2o_mruby_chunked_send_buffer(h2o_mruby_generator_t *generator, h2o_doublebuffer_t *db, h2o_buffer_t **input, int is_final)
{
    assert(db->bytes_inflight == 0);

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

    h2o_mruby_chunked_send(generator, &buf, bufcnt, send_state);
}

void h2o_mruby_chunked_close_body(h2o_mruby_generator_t *generator)
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

h2o_mruby_chunked_t *h2o_mruby_chunked_create(h2o_mruby_generator_t *generator, mrb_value body, size_t sz)
{
    h2o_mruby_chunked_t *chunked = h2o_mem_alloc_pool(&generator->req->pool, sz);
    mrb_gc_register(generator->ctx->shared->mrb, body);
    chunked->body_obj = body;
    chunked->bytes_left = h2o_memis(generator->req->method.base, generator->req->method.len, H2O_STRLIT("HEAD"))
                          ? 0
                          : generator->req->res.content_length;
    return chunked;
}

static void do_callback_chunked_start(h2o_mruby_generator_t *generator)
{
    struct st_h2o_mruby_callback_chunked_t *chunked = (void *)generator->chunked;
    mrb_state *mrb = generator->ctx->shared->mrb;
    mrb_value proc = mrb_ary_entry(generator->ctx->shared->constants, H2O_MRUBY_CHUNKED_PROC_EACH_TO_FIBER);
    mrb_value input = mrb_ary_new_capa(mrb, 2);
    mrb_ary_set(mrb, input, 0, chunked->super.body_obj);
    mrb_ary_set(mrb, input, 1, generator->refs.generator);
    h2o_mruby_run_fiber(generator->ctx, proc, input, 0);
}

static void do_callback_proceed(h2o_generator_t *_generator, h2o_req_t *req)
{
    h2o_mruby_generator_t *generator = (void *)_generator;
    struct st_h2o_mruby_callback_chunked_t *chunked = (void *)generator->chunked;
    h2o_buffer_t **input;
    int is_final;

    h2o_doublebuffer_consume(&chunked->sending);

    input = &chunked->receiving;
    is_final = mrb_nil_p(chunked->super.body_obj);

    h2o_mruby_chunked_send_buffer(generator, &chunked->sending, input, is_final);
}

static void do_callback_chunked_stop(h2o_mruby_generator_t *generator)
{
    struct st_h2o_mruby_callback_chunked_t *chunked = (void *)generator->chunked;

    h2o_mruby_chunked_close_body(generator);

    if (chunked->sending.bytes_inflight == 0)
        h2o_mruby_chunked_send_buffer(generator, &chunked->sending, &chunked->receiving, 1);
}

static void do_callback_chunked_dispose(h2o_mruby_generator_t *generator)
{
    struct st_h2o_mruby_callback_chunked_t *chunked = (void *)generator->chunked;
    h2o_doublebuffer_dispose(&chunked->sending);
    h2o_buffer_dispose(&chunked->receiving);
    h2o_mruby_chunked_close_body(generator);
}

h2o_mruby_chunked_t *callback_chunked_create(h2o_mruby_generator_t *generator, mrb_value body)
{
    struct st_h2o_mruby_callback_chunked_t *chunked = (void *)h2o_mruby_chunked_create(generator, body, sizeof(*chunked));
    h2o_doublebuffer_init(&chunked->sending, &h2o_socket_buffer_prototype);
    h2o_buffer_init(&chunked->receiving, &h2o_socket_buffer_prototype);

    chunked->super.start = do_callback_chunked_start;
    chunked->super.proceed = do_callback_proceed;
    chunked->super.stop = do_callback_chunked_stop;
    chunked->super.dispose = do_callback_chunked_dispose;

    return &chunked->super;
}

int h2o_mruby_chunked_init(h2o_mruby_generator_t *generator, mrb_value body)
{
    mrb_state *mrb = generator->ctx->shared->mrb;
    h2o_mruby_chunked_t *chunked;

#define TRY(func) \
    do { \
        chunked = func(generator, body); \
        if (mrb->exc != NULL) \
            return -1; \
        if (chunked != NULL) \
            goto Found; \
    } while (0)

    TRY(h2o_mruby_http_chunked_create);
    TRY(h2o_mruby_middleware_chunked_create);
    TRY(callback_chunked_create);

#undef TRY

    return -1;

Found:
    generator->chunked = chunked;
    generator->super.proceed = chunked->proceed;
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
        struct st_h2o_mruby_callback_chunked_t *chunked = (void *)generator->chunked;
        if (chunked->super.bytes_left != SIZE_MAX && chunked->super.bytes_left < len)
            len = chunked->super.bytes_left; /* trim data too long */
        if (len != 0) {
            h2o_buffer_reserve(&chunked->receiving, len);
            memcpy(chunked->receiving->bytes + chunked->receiving->size, s, len);
            chunked->receiving->size += len;
            if (chunked->sending.bytes_inflight == 0)
                h2o_mruby_chunked_send_buffer(generator, &chunked->sending, &chunked->receiving, 0);
        }
    }

    return mrb_nil_value();
}

static mrb_value send_chunked_eos_callback(h2o_mruby_context_t *mctx, mrb_value input, mrb_value receiver, mrb_value args, int *run_again)
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

    /* run_fiber will never be called once we enter the fast path, and therefore the close callback will never get called in that case */
    assert(generator->chunked->stop != NULL);
    generator->chunked->stop(generator);

    return mrb_nil_value();
}

void h2o_mruby_chunked_init_context(h2o_mruby_shared_context_t *shared_ctx)
{
    mrb_state *mrb = shared_ctx->mrb;

    h2o_mruby_eval_expr(mrb, H2O_MRUBY_CODE_CHUNKED);
    h2o_mruby_assert(mrb);

    mrb_define_method(mrb, mrb->kernel_module, "_h2o_send_chunk", send_chunked_method, MRB_ARGS_ARG(1, 0));
    h2o_mruby_define_callback(mrb, "_h2o_send_chunk_eos", send_chunked_eos_callback);

    mrb_ary_set(mrb, shared_ctx->constants, H2O_MRUBY_CHUNKED_PROC_EACH_TO_FIBER,
                mrb_funcall(mrb, mrb_top_self(mrb), "_h2o_chunked_proc_each_to_fiber", 0));
    h2o_mruby_assert(mrb);
}
