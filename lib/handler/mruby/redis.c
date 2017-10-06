/*
 * Copyright (c) 2016 DeNA Co., Ltd., Ichito Nagata
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
#include <mruby/variable.h>
#include "h2o/mruby_.h"
#include "h2o/redis.h"
#include "hiredis.h"


struct st_h2o_mruby_redis_conn_t {
    h2o_redis_conn_t super;
    h2o_mruby_context_t *ctx;
    struct {
        mrb_value redis;
    } refs;
};

struct st_h2o_mruby_redis_command_context_t {
    struct st_h2o_mruby_redis_conn_t *conn;
    mrb_value receiver;
    struct {
        mrb_value command;
    } refs;
};

static void attach_receiver(struct st_h2o_mruby_redis_command_context_t *ctx, mrb_value receiver)
{
    assert(mrb_nil_p(ctx->receiver));
    ctx->receiver = receiver;
    mrb_gc_register(ctx->conn->ctx->shared->mrb, receiver);
}

static mrb_value detach_receiver(struct st_h2o_mruby_redis_command_context_t *ctx, int protect)
{
    mrb_value ret = ctx->receiver;
    assert(!mrb_nil_p(ret));
    ctx->receiver = mrb_nil_value();
    mrb_gc_unregister(ctx->conn->ctx->shared->mrb, ret);
    if (protect) mrb_gc_protect(ctx->conn->ctx->shared->mrb, ret);
    return ret;
}

static void on_gc_dispose_redis(mrb_state *mrb, void *_conn)
{
    struct st_h2o_mruby_redis_conn_t *conn = _conn;
    if (conn == NULL) return;

    conn->refs.redis = mrb_nil_value();
    h2o_redis_free(&conn->super);
}

static void on_gc_dispose_command(mrb_state *mrb, void *_ctx)
{
    struct st_h2o_mruby_redis_command_context_t *ctx = _ctx;
    if (ctx == NULL) return;
    if (! mrb_nil_p(ctx->receiver)) {
        detach_receiver(ctx, 0);
    }
    free(ctx);
}

static struct RClass *get_error_class(mrb_state *mrb, const char *name)
{
    h2o_mruby_shared_context_t *shared = mrb->ud;
    mrb_value h2o = mrb_ary_entry(shared->constants, H2O_MRUBY_H2O_MODULE);
    struct RClass *redis_klass = mrb_class_get_under(mrb, (struct RClass *)mrb_obj_ptr(h2o), "Redis");
    struct RClass *error_klass = mrb_class_get_under(mrb, redis_klass, name);
    return error_klass;
}

static void pass_reply(struct st_h2o_mruby_redis_command_context_t *ctx, mrb_value reply)
{
    mrb_state *mrb = ctx->conn->ctx->shared->mrb;
    if (mrb_nil_p(ctx->receiver)) {
        mrb_funcall(mrb, ctx->refs.command, "_on_reply", 1, reply);
        h2o_mruby_assert(mrb);
    } else {
        int gc_arena = mrb_gc_arena_save(mrb);
        h2o_mruby_run_fiber(ctx->conn->ctx, detach_receiver(ctx, 1), reply, NULL);
        mrb_gc_arena_restore(mrb, gc_arena);
    }
}

const static struct mrb_data_type redis_type = {"redis", on_gc_dispose_redis};
const static struct mrb_data_type command_type = {"redis_command", on_gc_dispose_command};

static mrb_value setup_method(mrb_state *mrb, mrb_value self)
{
    h2o_mruby_shared_context_t *shared = mrb->ud;
    assert(shared->current_context != NULL);

    struct st_h2o_mruby_redis_conn_t *conn = (struct st_h2o_mruby_redis_conn_t *)h2o_redis_create_connection(shared->ctx->loop, sizeof(*conn));
    conn->ctx = shared->current_context;

    mrb_value _connect_timeout = mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "@connect_timeout"));
    if (! mrb_nil_p(_connect_timeout)) {
        uint64_t connect_timeout = mrb_float(_connect_timeout) * 1000;
        conn->super.connect_timeout = connect_timeout;
    }

    mrb_value _command_timeout = mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "@command_timeout"));
    if (! mrb_nil_p(_command_timeout)) {
        uint64_t command_timeout = mrb_float(_command_timeout) * 1000;
        conn->super.command_timeout = command_timeout;
    }

    DATA_TYPE(self) = &redis_type;
    DATA_PTR(self) = conn;

    return self;
}

static mrb_value connect_method(mrb_state *mrb, mrb_value self)
{
    struct st_h2o_mruby_redis_conn_t *conn = DATA_PTR(self);
    if (conn->super.state != H2O_REDIS_CONNECTION_STATE_CLOSED)
        return self;

    mrb_value _host = mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "@host"));
    mrb_value _port = mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "@port"));
    const char *host = mrb_string_value_cstr(mrb, &_host);
    uint16_t port = mrb_fixnum(_port);

    h2o_redis_connect(&conn->super, host, port);

    return self;
}

static mrb_value disconnected_method(mrb_state *mrb, mrb_value self)
{
    struct st_h2o_mruby_redis_conn_t *conn = DATA_PTR(self);
    return mrb_bool_value(conn->super.state == H2O_REDIS_CONNECTION_STATE_CLOSED);
}

static mrb_value disconnect_method(mrb_state *mrb, mrb_value self)
{
    struct st_h2o_mruby_redis_conn_t *conn = DATA_PTR(self);
    h2o_redis_disconnect(&conn->super);
    return self;
}

/*
   don't use redisReader here, because..
     1) hiredis's pub/sub doesn't accept custom reply
     2) needless memory allocation must happen without using some tricky ways
 */
static mrb_value decode_redis_reply(mrb_state *mrb, redisReply *reply, mrb_value command)
{
    mrb_value decoded;

    switch (reply->type) {
    case REDIS_REPLY_STRING:
    case REDIS_REPLY_STATUS:
        decoded = mrb_str_new(mrb, reply->str, reply->len);
        break;
    case REDIS_REPLY_ARRAY:
        decoded = mrb_ary_new_capa(mrb, (mrb_int)reply->elements);
        mrb_int i;
        for (i = 0; i != reply->elements; ++i)
            mrb_ary_set(mrb, decoded, i, decode_redis_reply(mrb, reply->element[i], command));
        break;
    case REDIS_REPLY_INTEGER:
        decoded = mrb_fixnum_value((mrb_int)reply->integer);
        break;
    case REDIS_REPLY_NIL:
        decoded = mrb_nil_value();
        break;
    case REDIS_REPLY_ERROR: {
        mrb_value error_klass = mrb_obj_value(get_error_class(mrb, "CommandError"));
        decoded = mrb_funcall(mrb, error_klass, "new", 2, mrb_str_new(mrb, reply->str, reply->len), command);
    } break;
    default:
        assert(!"FIXME");
    }

    return decoded;
}

static void on_redis_command(redisReply *_reply, void *_ctx, int err, const char *errstr)
{
    struct st_h2o_mruby_redis_command_context_t *ctx = _ctx;
    mrb_state *mrb = ctx->conn->ctx->shared->mrb;
    mrb_value reply = mrb_nil_value();

    if (err == H2O_REDIS_ERROR_NONE) {
        if (_reply == NULL) return;
        reply = decode_redis_reply(mrb, _reply, ctx->refs.command);
    } else {
        struct RClass *error_klass = NULL;
        switch(err) {
        case H2O_REDIS_ERROR_CONNECTION:
            error_klass = get_error_class(mrb, "ConnectionError");
            break;
        case H2O_REDIS_ERROR_PROTOCOL:
            error_klass = get_error_class(mrb, "ProtocolError");
            break;
        case H2O_REDIS_ERROR_UNKNOWN:
            error_klass = get_error_class(mrb, "UnknownError");
            break;
        case H2O_REDIS_ERROR_CONNECT_TIMEOUT:
            error_klass = get_error_class(mrb, "ConnectTimeoutError");
            break;
        case H2O_REDIS_ERROR_COMMAND_TIMEOUT:
            error_klass = get_error_class(mrb, "CommandTimeoutError");
            break;
        default:
            assert(!"FIXME");
        }
        reply = mrb_exc_new(mrb, error_klass, errstr, strlen(errstr));
    }

    pass_reply(ctx, reply);
    mrb_gc_unregister(mrb, ctx->refs.command);
}

static mrb_value call_method(mrb_state *mrb, mrb_value self)
{
    struct st_h2o_mruby_redis_conn_t *conn = DATA_PTR(self);
    mrb_int i = 0;

    mrb_value command_args;
    mrb_value command_klass;
    mrb_value command_block = mrb_nil_value();
    mrb_get_args(mrb, "AC&", &command_args, &command_klass, &command_block);
    mrb_int command_len = RARRAY_LEN(command_args);

    /* allocate context and initialize */
    struct st_h2o_mruby_redis_command_context_t *command_ctx = h2o_mem_alloc(sizeof(*command_ctx));
    memset(command_ctx, 0, sizeof(*command_ctx));
    command_ctx->conn = conn;
    command_ctx->receiver = mrb_nil_value();
    command_ctx->refs.command = h2o_mruby_create_data_instance(mrb, command_klass, command_ctx, &command_type);
    mrb_funcall_with_block(mrb, command_ctx->refs.command, mrb_intern_lit(mrb, "initialize"), 1, &command_args, command_block);
    mrb_gc_register(mrb, command_ctx->refs.command);

    const char **argv = h2o_mem_alloc(command_len * sizeof(char *));
    size_t *argvlen = h2o_mem_alloc(command_len * sizeof(size_t));

    int gc_arena = mrb_gc_arena_save(mrb);

    /* retrieve argument array */
    for (i = 0; i != command_len; ++i) {
        mrb_value command_arg = mrb_ary_entry(command_args, i);
        if (mrb_symbol_p(command_arg)) {
            mrb_int len;
            argv[i] = mrb_sym2name_len(mrb, mrb_symbol(command_arg), &len);
            argvlen[i] = len;
        } else {
            mrb_value s = mrb_obj_as_string(mrb, command_arg);
            argv[i] = mrb_string_value_cstr(mrb, &s);
            argvlen[i] = mrb_string_value_len(mrb, s);
        }
    }

    /* send command to redis */
    h2o_redis_command_argv(&conn->super, on_redis_command, command_ctx, (int)command_len, argv, argvlen);

    mrb_gc_arena_restore(mrb, gc_arena);

    free(argv);
    free(argvlen);

    return command_ctx->refs.command;
}

void h2o_mruby_redis_init_context(h2o_mruby_shared_context_t *ctx)
{
    mrb_state *mrb = ctx->mrb;

    struct RClass *module = mrb_define_module(mrb, "H2O");

    h2o_mruby_define_callback(mrb, "_h2o__redis_join_reply", H2O_MRUBY_CALLBACK_ID_REDIS_JOIN_REPLY);

    struct RClass *redis_klass = mrb_class_get_under(mrb, module, "Redis");
    mrb_define_method(mrb, redis_klass, "__setup", setup_method, MRB_ARGS_NONE());
    mrb_define_method(mrb, redis_klass, "__connect", connect_method, MRB_ARGS_NONE());
    mrb_define_method(mrb, redis_klass, "disconnected?", disconnected_method, MRB_ARGS_NONE());
    mrb_define_method(mrb, redis_klass, "disconnect", disconnect_method, MRB_ARGS_NONE());
    mrb_define_method(mrb, redis_klass, "__call", call_method, MRB_ARGS_ARG(1, 0));
}

mrb_value h2o_mruby_redis_join_reply_callback(h2o_mruby_context_t *mctx, mrb_value receiver, mrb_value args,
                                                int *run_again)
{
    mrb_state *mrb = mctx->shared->mrb;
    struct st_h2o_mruby_redis_command_context_t *ctx;

    if ((ctx = mrb_data_check_get_ptr(mrb, mrb_ary_entry(args, 0), &command_type)) == NULL)
        return mrb_exc_new_str_lit(mrb, E_ARGUMENT_ERROR, "Redis::Command#join wrong self");

    attach_receiver(ctx, receiver);
    return mrb_nil_value();
}

