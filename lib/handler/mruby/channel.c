/*
 * Copyright (c) 2017 Ritta Narita
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
#include <mruby/class.h>
#include <mruby/variable.h>
#include "h2o/mruby_.h"
#include "embedded.c.h"

struct st_h2o_mruby_channel_context_t {
    h2o_mruby_context_t *ctx;
    mrb_value receiver;
};

static void attach_receiver(struct st_h2o_mruby_channel_context_t *ctx, mrb_value receiver)
{
    assert(mrb_nil_p(ctx->receiver));
    ctx->receiver = receiver;
    mrb_gc_register(ctx->ctx->shared->mrb, receiver);
}

static mrb_value detach_receiver(struct st_h2o_mruby_channel_context_t *ctx)
{
    mrb_value ret = ctx->receiver;
    assert(!mrb_nil_p(ret));
    ctx->receiver = mrb_nil_value();
    mrb_gc_unregister(ctx->ctx->shared->mrb, ret);
    mrb_gc_protect(ctx->ctx->shared->mrb, ret);
    return ret;
}

static void on_gc_dispose_channel(mrb_state *mrb, void *_ctx)
{
    struct st_h2o_mruby_channel_context_t *ctx = _ctx;
    assert(ctx != NULL); /* ctx can only be disposed by gc, so data binding has been never removed */
    mrb_gc_unregister(mrb, ctx->receiver);
    free(ctx);
}

const static struct mrb_data_type channel_type = {"channel", on_gc_dispose_channel};

static mrb_value channel_initialize_method(mrb_state *mrb, mrb_value self)
{
    h2o_mruby_shared_context_t *shared_ctx = mrb->ud;

    struct st_h2o_mruby_channel_context_t *ctx;
    ctx = h2o_mem_alloc(sizeof(*ctx));

    memset(ctx, 0, sizeof(*ctx));
    assert(shared_ctx->current_context != NULL);
    ctx->ctx = shared_ctx->current_context;
    ctx->receiver = mrb_nil_value();

    mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@queue"), mrb_ary_new(mrb));

    mrb_data_init(self, ctx, &channel_type);

    return self;
}

static mrb_value channel_notify_method(mrb_state *mrb, mrb_value self)
{
    struct st_h2o_mruby_channel_context_t *ctx;
    ctx = mrb_data_check_get_ptr(mrb, self, &channel_type);

    if (!mrb_nil_p(ctx->receiver)) {
        int gc_arena = mrb_gc_arena_save(mrb);
        h2o_mruby_run_fiber(ctx->ctx, detach_receiver(ctx), mrb_nil_value(), NULL);
        mrb_gc_arena_restore(mrb, gc_arena);
    }

    return mrb_nil_value();
}

static mrb_value wait_callback(h2o_mruby_context_t *mctx, mrb_value input, mrb_value *receiver, mrb_value args, int *run_again)
{
    mrb_state *mrb = mctx->shared->mrb;

    struct st_h2o_mruby_channel_context_t *ctx;

    if ((ctx = mrb_data_check_get_ptr(mrb, mrb_ary_entry(args, 0), &channel_type)) == NULL)
        return mrb_exc_new_str_lit(mrb, E_ARGUMENT_ERROR, "Channel#shift wrong self");

    if (!mrb_nil_p(ctx->receiver)) {
        return mrb_exc_new_str_lit(mrb, E_RUNTIME_ERROR, "This channel has already been waiting. It can't be called multiple times for same channel object concurrently");
    }

    attach_receiver(ctx, *receiver);

    return mrb_nil_value();
}

void h2o_mruby_channel_init_context(h2o_mruby_shared_context_t *shared_ctx)
{
    mrb_state *mrb = shared_ctx->mrb;

    h2o_mruby_eval_expr(mrb, H2O_MRUBY_CODE_CHANNEL);
    h2o_mruby_assert(mrb);

    struct RClass *module, *klass;
    module = mrb_define_module(mrb, "H2O");

    klass = mrb_class_get_under(mrb, module, "Channel");
    MRB_SET_INSTANCE_TT(klass, MRB_TT_DATA);
    mrb_ary_set(mrb, shared_ctx->constants, H2O_MRUBY_CHANNEL_CLASS, mrb_obj_value(klass));
    mrb_define_method(mrb, klass, "initialize", channel_initialize_method, MRB_ARGS_NONE());
    mrb_define_method(mrb, klass, "_notify", channel_notify_method, MRB_ARGS_NONE());
    h2o_mruby_define_callback(mrb, "_h2o__channel_wait", wait_callback);
}
