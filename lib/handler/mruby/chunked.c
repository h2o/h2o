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

static void do_send(h2o_mruby_ostream_t *ostream, h2o_buffer_t **input, int is_final)
{
    h2o_mruby_chunked_t *chunked = ostream->chunked;

    assert(chunked->sending.bytes_inflight == 0);

    h2o_iovec_t buf = h2o_doublebuffer_prepare(&chunked->sending, input, ostream->super.req->preferred_chunk_size);
    size_t bufcnt = 1;

    if (is_final && buf.len == chunked->sending.buf->size && (*input)->size == 0) {
        if (buf.len == 0)
            --bufcnt;
        /* terminate the H1 connection if the length of content served did not match the value sent in content-length header */
        if (chunked->bytes_left != SIZE_MAX && chunked->bytes_left != 0)
            ostream->super.req->http1_is_persistent = 0;
    } else {
        if (buf.len == 0)
            return;
        is_final = 0;
    }

    h2o_send(&ostream->super, &buf, bufcnt, is_final ? H2O_SEND_STATE_FINAL : H2O_SEND_STATE_IN_PROGRESS);
}

static void do_proceed(h2o_ostream_t *_ostream, h2o_req_t *req)
{
    h2o_mruby_ostream_t *ostream = (void *)_ostream;
    h2o_mruby_chunked_t *chunked = ostream->chunked;
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

    do_send(ostream, input, is_final);
}

static void on_shortcut_notify(h2o_mruby_ostream_t *ostream)
{
    h2o_mruby_chunked_t *chunked = ostream->chunked;
    int is_final;
    h2o_buffer_t **input = h2o_mruby_http_peek_content(chunked->shortcut.client, &is_final);

    /* trim data too long */
    if (chunked->bytes_left != SIZE_MAX && chunked->bytes_left < (*input)->size)
        (*input)->size = chunked->bytes_left;

    /* if final, steal socket input buffer to shortcut.remaining, and reset pointer to client */
    if (is_final) {
        chunked->shortcut.remaining = *input;
        h2o_buffer_init(input, &h2o_socket_buffer_prototype);
        input = &chunked->shortcut.remaining;
        h2o_mruby_http_unset_shortcut(ostream->ctx->shared->mrb, chunked->shortcut.client, ostream);
        chunked->shortcut.client = NULL;
    }

    if (chunked->sending.bytes_inflight == 0)
        do_send(ostream, input, is_final);
}

static void close_body_obj(h2o_mruby_ostream_t *ostream)
{
    h2o_mruby_chunked_t *chunked = ostream->chunked;
    mrb_state *mrb = ostream->ctx->shared->mrb;

    if (!mrb_nil_p(chunked->body_obj)) {
        /* call close and throw away error */
        if (mrb_respond_to(mrb, chunked->body_obj, ostream->ctx->shared->symbols.sym_close))
            mrb_funcall_argv(mrb, chunked->body_obj, ostream->ctx->shared->symbols.sym_close, 0, NULL);
        mrb->exc = NULL;
        mrb_gc_unregister(mrb, chunked->body_obj);
        chunked->body_obj = mrb_nil_value();
    }
}

mrb_value h2o_mruby_send_chunked_init(h2o_mruby_ostream_t *ostream, mrb_value body)
{
    mrb_state *mrb = ostream->ctx->shared->mrb;

    h2o_mruby_http_request_context_t *client = h2o_mruby_http_set_shortcut(mrb, body, on_shortcut_notify, ostream);
    if (mrb->exc != NULL) {
        return mrb_nil_value();
    }

    h2o_req_t *req = ostream->super.req;
    h2o_mruby_chunked_t *chunked = h2o_mem_alloc_pool(&req->pool, sizeof(*chunked));
    h2o_doublebuffer_init(&chunked->sending, &h2o_socket_buffer_prototype);
    chunked->bytes_left = h2o_memis(req->method.base, req->method.len, H2O_STRLIT("HEAD"))
                              ? 0
                              : req->res.content_length;
    ostream->super.proceed = do_proceed;
    ostream->chunked = chunked;
    mrb_value ret;

    h2o_start_response(req);
    ostream->response_is_started = 1;
    h2o_insert_ostream(&ostream->super, &req->_ostr_top);

    if (client != NULL) {
        chunked->type = H2O_MRUBY_CHUNKED_TYPE_SHORTCUT;
        chunked->shortcut.client = client;
        chunked->shortcut.remaining = NULL;
        on_shortcut_notify(ostream);
        ret = mrb_nil_value();
    } else {
        chunked->type = H2O_MRUBY_CHUNKED_TYPE_CALLBACK;
        h2o_buffer_init(&chunked->callback.receiving, &h2o_socket_buffer_prototype);
        ret = mrb_ary_entry(ostream->ctx->shared->constants, H2O_MRUBY_CHUNKED_PROC_EACH_TO_FIBER);
    }

    mrb_gc_register(ostream->ctx->shared->mrb, body);
    chunked->body_obj = body;
    return ret;
}

void h2o_mruby_send_chunked_dispose(h2o_mruby_ostream_t *ostream)
{
    h2o_mruby_chunked_t *chunked = ostream->chunked;

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
        h2o_mruby_http_unset_shortcut(ostream->ctx->shared->mrb, chunked->shortcut.client, ostream);
    close_body_obj(ostream);
}

static mrb_value check_precond(mrb_state *mrb, h2o_mruby_ostream_t *ostream)
{
    if (ostream == NULL)
        return mrb_exc_new_str_lit(mrb, E_RUNTIME_ERROR, "downstream HTTP closed");
    if (! ostream->response_is_started)
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

    h2o_mruby_ostream_t *ostream = h2o_mruby_get_ostream(mrb, gen);

    { /* precond check */
        mrb_value exc = check_precond(mrb, ostream);
        if (!mrb_nil_p(exc))
            mrb_exc_raise(mrb, exc);
    }

    /* append to send buffer, and send out immediately if necessary */
    if (len != 0) {
        h2o_mruby_chunked_t *chunked = ostream->chunked;
        if (chunked->bytes_left != SIZE_MAX) {
            if (len > chunked->bytes_left)
                len = (mrb_int)chunked->bytes_left;
            chunked->bytes_left -= len;
        }
        if (len != 0) {
            h2o_buffer_reserve(&chunked->callback.receiving, len);
            memcpy(chunked->callback.receiving->bytes + chunked->callback.receiving->size, s, len);
            chunked->callback.receiving->size += len;
            if (chunked->sending.bytes_inflight == 0)
                do_send(ostream, &chunked->callback.receiving, 0);
        }
    }

    return mrb_nil_value();
}

mrb_value h2o_mruby_send_chunked_eos_callback(h2o_mruby_context_t *mctx, mrb_value receiver, mrb_value args, int *run_again)
{
    mrb_state *mrb = mctx->shared->mrb;
    h2o_mruby_ostream_t *ostream = h2o_mruby_get_ostream(mrb, mrb_ary_entry(args, 0));

    { /* precond check */
        mrb_value exc = check_precond(mrb, ostream);
        if (!mrb_nil_p(exc)) {
            *run_again = 1;
            return exc;
        }
    }

    h2o_mruby_send_chunked_close(ostream);

    return mrb_nil_value();
}

void h2o_mruby_send_chunked_close(h2o_mruby_ostream_t *ostream)
{
    h2o_mruby_chunked_t *chunked = ostream->chunked;

    /* run_fiber will never be called once we enter the fast path, and therefore this function will never get called in that case */
    assert(chunked->type == H2O_MRUBY_CHUNKED_TYPE_CALLBACK);

    close_body_obj(ostream);

    if (chunked->sending.bytes_inflight == 0)
        do_send(ostream, &chunked->callback.receiving, 1);
}

void h2o_mruby_send_chunked_init_context(h2o_mruby_shared_context_t *shared_ctx)
{
    mrb_state *mrb = shared_ctx->mrb;

    h2o_mruby_eval_expr(mrb, H2O_MRUBY_CODE_CHUNKED);
    h2o_mruby_assert(mrb);

    mrb_define_method(mrb, mrb->kernel_module, "_h2o_send_chunk", send_chunked_method, MRB_ARGS_ARG(1, 0));
    h2o_mruby_define_callback(mrb, "_h2o_send_chunk_eos", H2O_MRUBY_CALLBACK_ID_SEND_CHUNKED_EOS);

    mrb_ary_set(mrb, shared_ctx->constants, H2O_MRUBY_CHUNKED_PROC_EACH_TO_FIBER,
                mrb_funcall(mrb, mrb_top_self(mrb), "_h2o_chunked_proc_each_to_fiber", 0));
    h2o_mruby_assert(mrb);
}
