/*
 * Copyright (c) 2019 Ichito Nagata
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

static void on_gc_dispose_input_stream(mrb_state *mrb, void *_is)
{
    h2o_mruby_input_stream_t *is = _is;
    /* input stream never be freed by gc before the request ended and it's generator gets disposed */
    assert(is == NULL);
}

const static struct mrb_data_type input_stream_type = {"input_stream", on_gc_dispose_input_stream};

static mrb_value create_io_error(mrb_state *mrb, const char *msg)
{
    struct RClass *klass = mrb_class_get(mrb, "IOError");
    mrb_value str = mrb_str_new_static(mrb, msg, strlen(msg));
    return mrb_exc_new_str(mrb, klass, str);
}

static h2o_mruby_input_stream_t *get_input_stream(mrb_state *mrb, mrb_value obj)
{
    h2o_mruby_input_stream_t *is = mrb_data_check_get_ptr(mrb, obj, &input_stream_type);
    return is;
}

static mrb_value detach_receiver(h2o_mruby_input_stream_t *is)
{
    mrb_value receiver = is->receiver;
    assert(!mrb_nil_p(receiver));
    is->receiver = mrb_nil_value();
    mrb_gc_unregister(is->generator->ctx->shared->mrb, receiver);
    mrb_gc_protect(is->generator->ctx->shared->mrb, receiver);
    return receiver;
}

static h2o_iovec_t get_buffer(h2o_mruby_input_stream_t *is)
{
    if (is->buf != NULL) {
        return h2o_iovec_init(is->buf->bytes + is->pos, is->buf->size - is->pos);
    } else {
        return h2o_iovec_init(is->entity.base + is->pos, is->entity.len - is->pos);
    }
}

static void consume_buffer(h2o_mruby_input_stream_t *is, size_t len)
{
    if (is->rewindable) {
        is->pos += len;
    } else {
        if (is->buf != NULL) {
            h2o_buffer_consume(&is->buf, len);
        } else {
            is->entity.base += len;
            is->entity.len -= len;
        }
    }
}

static void clear_args(h2o_mruby_input_stream_t *is)
{
    is->args.length = SIZE_MAX;
    is->args.buffer = mrb_nil_value();
    is->args.delimiter = mrb_nil_value();
}

static int prepare_chunk(h2o_mruby_input_stream_t *is, mrb_value *chunk)
{
    mrb_state *mrb = is->generator->ctx->shared->mrb;
    *chunk = mrb_nil_value();

    h2o_iovec_t buf = get_buffer(is);

    if (!mrb_nil_p(is->args.delimiter)) {
        /* prepare for gets */

        char *p = memmem(buf.base, buf.len, RSTRING_PTR(is->args.delimiter), RSTRING_LEN(is->args.delimiter));
        if (p == NULL) {
            if (!is->seen_eos) {
                return -1;
            } else if (buf.len == 0) {
                return 0;
            } else {
                *chunk = h2o_mruby_new_str(mrb, buf.base, buf.len);
                consume_buffer(is, buf.len);
                return 0;
            }
        }
        size_t len = p - buf.base + RSTRING_LEN(is->args.delimiter);
        *chunk = h2o_mruby_new_str(mrb, buf.base, len);
        consume_buffer(is, len);
        return 0;
    } else {
        /* prepare for read */

        if (buf.len < is->args.length && !is->seen_eos) {
            return -1;
        }

        /* rack spec states that "When EOF is reached, this method returns nil if length is given and not nil" */
        if (is->seen_eos && buf.len == 0 && is->args.length != SIZE_MAX) {
            /* but even in this case, the buffer argument must be set empty string */
            if (!mrb_nil_p(is->args.buffer) && RSTRING_LEN(is->args.buffer) != 0) {
                mrb_str_resize(mrb, is->args.buffer, 0);
            }
            return 0;
        }

        size_t len = is->args.length < buf.len ? is->args.length : buf.len;
        *chunk = is->args.buffer;
        if (mrb_nil_p(*chunk)) {
            *chunk = h2o_mruby_new_str(mrb, NULL, len);
        }
        mrb_str_resize(mrb, *chunk, len);
        memcpy(RSTRING_PTR(*chunk), buf.base, len);
        consume_buffer(is, len);
        return 0;
    }
}

static int do_write_req(void *_is, h2o_iovec_t chunk, int is_end_stream)
{
    h2o_mruby_input_stream_t *is = _is;
    h2o_buffer_append(&is->buf, chunk.base, chunk.len);
    is->seen_eos = is_end_stream;

    if (!mrb_nil_p(is->receiver)) {
        mrb_value chunk_str;
        if (prepare_chunk(is, &chunk_str) == 0) {
            h2o_mruby_run_fiber(is->generator->ctx, detach_receiver(is), chunk_str, NULL);
            clear_args(is);
        }
    }

    if (is->generator->req->proceed_req != NULL) {
        is->generator->req->proceed_req(is->generator->req, chunk.len, is_end_stream);
    }

    return 0; // FIXME: 0 is ok while mruby mode, but how handle proxy mode?
}

static mrb_value input_stream_read_callback(h2o_mruby_context_t *mctx, mrb_value input, mrb_value *receiver, mrb_value args,
                                                int *run_again)
{
    mrb_state *mrb = mctx->shared->mrb;
    struct st_h2o_mruby_input_stream_t *is;

    mrb_value obj = mrb_ary_entry(args, 0);
    if (DATA_PTR(obj) == NULL) {
        *run_again = 1;
        return create_io_error(mrb, "downstream HTTP closed");
    } else if ((is = get_input_stream(mrb, obj)) == NULL) {
        *run_again = 1;
        return mrb_exc_new_str_lit(mrb, E_ARGUMENT_ERROR, "InputStream#each wrong self");
    }

    mrb_value length = mrb_ary_entry(args, 1);
    if (mrb_nil_p(length)) {
        is->args.length = SIZE_MAX;
    } else {
        length = h2o_mruby_to_int(mrb, length);
        if (mrb->exc != NULL)
            return mrb_obj_value(mrb->exc);
        if (mrb_fixnum(length) < 0) {
            return mrb_exc_new_str_lit(mrb, E_ARGUMENT_ERROR, "length must be a non-negative Integer (>= 0) or nil");
        }
        is->args.length = mrb_fixnum(length);
    }

    mrb_value buffer = mrb_ary_entry(args, 2);
    if (mrb_nil_p(buffer)) {
        is->args.buffer = mrb_nil_value();
    } else {
        if (!mrb_string_p(buffer)) {
            return mrb_exc_new_str_lit(mrb, E_ARGUMENT_ERROR, "buffer must be a String or nil");
        }
        is->args.buffer = buffer;
    }

    assert(mrb_nil_p(is->receiver));

    mrb_value chunk;
    if (prepare_chunk(is, &chunk) == 0) {
        *run_again = 1;
        clear_args(is);
        return chunk;
    } else {
        is->receiver = *receiver;
        mrb_gc_register(mrb, *receiver);
        return mrb_nil_value();
    }
}

static mrb_value input_stream_gets_callback(h2o_mruby_context_t *mctx, mrb_value input, mrb_value *receiver, mrb_value args,
                                            int *run_again)
{
    mrb_state *mrb = mctx->shared->mrb;
    struct st_h2o_mruby_input_stream_t *is;

    mrb_value obj = mrb_ary_entry(args, 0);
    if (DATA_PTR(obj) == NULL) {
        *run_again = 1;
        return create_io_error(mrb, "downstream HTTP closed");
    } else if ((is = get_input_stream(mrb, obj)) == NULL) {
        *run_again = 1;
        return mrb_exc_new_str_lit(mrb, E_ARGUMENT_ERROR, "InputStream#each wrong self");
    }

    mrb_value delimiter = mrb_ary_entry(args, 1);
    if (!mrb_nil_p(delimiter)) {
        if (!mrb_string_p(delimiter)) {
            return mrb_exc_new_str_lit(mrb, E_ARGUMENT_ERROR, "delimiter must be a String or nil");
        }
    }
    is->args.delimiter = delimiter;

    assert(mrb_nil_p(is->receiver));

    mrb_value chunk;
    if (prepare_chunk(is, &chunk) == 0) {
        *run_again = 1;
        clear_args(is);
        return chunk;
    } else {
        is->receiver = *receiver;
        mrb_gc_register(mrb, *receiver);
        return mrb_nil_value();
    }
}

static mrb_value rewindable_getter_method(mrb_state *mrb, mrb_value self)
{
    h2o_mruby_input_stream_t *is = get_input_stream(mrb, self);
    assert(is != NULL);
    return mrb_bool_value(is->rewindable);
}

static mrb_value rewindable_setter_method(mrb_state *mrb, mrb_value self)
{
    h2o_mruby_input_stream_t *is = get_input_stream(mrb, self);
    assert(is != NULL);

    mrb_bool value;
    mrb_get_args(mrb, "b", &value);

    is->rewindable = value;
    if (!is->rewindable) {
        consume_buffer(is, is->pos);
        is->pos = 0;
    }
    return mrb_bool_value(is->rewindable);
}

static mrb_value rewind_method(mrb_state *mrb, mrb_value self)
{
    h2o_mruby_input_stream_t *is = get_input_stream(mrb, self);
    assert(is != NULL);

    if (!is->rewindable) {
        mrb_raise(mrb, mrb_class_get(mrb, "IOError"), "this input stream is not rewindable");
    }

    is->pos = 0;

    return mrb_fixnum_value(0);
}

h2o_mruby_input_stream_t *h2o_mruby_input_stream_create(h2o_mruby_generator_t *generator)
{
    h2o_mruby_shared_context_t *shared = generator->ctx->shared;
    h2o_mruby_input_stream_t *is = h2o_mem_alloc(sizeof(*is));
    is->generator = generator;
    is->buf = NULL;
    is->entity = h2o_iovec_init(NULL, 0);
    is->pos = 0;
    is->receiver = mrb_nil_value();
    clear_args(is);
    is->seen_eos = 0;
    is->rewindable = 1;

    if (generator->req->proceed_req != NULL) {
        h2o_buffer_init(&is->buf, &h2o_socket_buffer_prototype);
        if (generator->req->entity.len != 0) {
            h2o_buffer_append(&is->buf, generator->req->entity.base, generator->req->entity.len);
        }
        generator->req->write_req.cb = do_write_req;
        generator->req->write_req.ctx = is;
    } else {
        is->entity = h2o_iovec_init(generator->req->entity.base, generator->req->entity.len);
        is->seen_eos = 1;
    }

    is->ref = h2o_mruby_create_data_instance(shared->mrb, mrb_ary_entry(shared->constants, H2O_MRUBY_INPUT_STREAM_CLASS), is, &input_stream_type);
    return is;
}

void h2o_mruby_input_stream_dispose(h2o_mruby_input_stream_t *is)
{
    DATA_PTR(is->ref) = NULL;

    if (!mrb_nil_p(is->receiver)) {
        mrb_value exc = create_io_error(is->generator->ctx->shared->mrb, "downstream HTTP closed");
        h2o_mruby_run_fiber(is->generator->ctx, detach_receiver(is), exc, NULL);
    }

    if (is->buf != NULL)
        h2o_buffer_dispose(&is->buf);

    free(is);
}

void h2o_mruby_input_stream_init_context(h2o_mruby_shared_context_t *shared_ctx)
{
    mrb_state *mrb = shared_ctx->mrb;

    h2o_mruby_eval_expr_location(mrb, H2O_MRUBY_CODE_INPUT_STREAM, "(h2o)lib/handler/mruby/embedded/input_stream.rb", 1);
    h2o_mruby_assert(mrb);

    struct RClass *module, *klass;
    module = mrb_define_module(mrb, "H2O");

    klass = mrb_class_get_under(mrb, module, "InputStream");
    MRB_SET_INSTANCE_TT(klass, MRB_TT_DATA);
    mrb_ary_set(mrb, shared_ctx->constants, H2O_MRUBY_INPUT_STREAM_CLASS, mrb_obj_value(klass));

    h2o_mruby_define_callback(mrb, "_h2o_input_stream_read", input_stream_read_callback);
    h2o_mruby_define_callback(mrb, "_h2o_input_stream_gets", input_stream_gets_callback);

    mrb_define_method(mrb, klass, "rewindable?", rewindable_getter_method, MRB_ARGS_NONE());
    mrb_define_method(mrb, klass, "rewindable=", rewindable_setter_method,MRB_ARGS_ARG(1, 0));
    mrb_define_method(mrb, klass, "rewind", rewind_method, MRB_ARGS_NONE());
}
