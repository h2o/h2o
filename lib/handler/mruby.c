/*
 * Copyright (c) 2014-2016 DeNA Co., Ltd., Kazuho Oku, Ryosuke Matsumoto,
 *                         Masayoshi Takahashi
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
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <mruby.h>
#include <mruby/proc.h>
#include <mruby/array.h>
#include <mruby/class.h>
#include <mruby/compile.h>
#include <mruby/error.h>
#include <mruby/hash.h>
#include <mruby/opcode.h>
#include <mruby/string.h>
#include <mruby/throw.h>
#include <mruby/variable.h>
#include <mruby_input_stream.h>
#include "h2o.h"
#include "h2o/mruby_.h"
#include "mruby/embedded.c.h"

#define STATUS_FALLTHRU 399
#define FALLTHRU_SET_PREFIX "x-fallthru-set-"

#define FREEZE_STRING(v) MRB_SET_FROZEN_FLAG(mrb_obj_ptr(v))

struct st_mruby_output_prefilter_t {
    h2o_req_prefilter_t super;
    h2o_mruby_context_t *ctx;
    h2o_mruby_generator_t *generator;
    mrb_value receiver;

    struct {
        h2o_timeout_entry_t timeout_entry;
        mrb_value resp;
    } defer_resume;
};

struct st_mruby_output_ostream_t {
    h2o_ostream_t super;
    h2o_mruby_context_t *ctx;
    h2o_mruby_generator_t *generator;
    mrb_value receiver;
    mrb_value ref;
};

static void on_gc_dispose_output_filter(mrb_state *mrb, void *_ostream)
{
    struct st_mruby_output_ostream_t *ostream = _ostream;
    if (ostream == NULL) return;
    ostream->ref = mrb_nil_value();
}

const static struct mrb_data_type output_filter_stream_type = {"output_filter", on_gc_dispose_output_filter};

void h2o_mruby__assert_failed(mrb_state *mrb, const char *file, int line)
{
    fprintf(stderr, "unexpected ruby error at file: \"%s\", line %d: %s", file, line,
            RSTRING_PTR(mrb_inspect(mrb, mrb_obj_value(mrb->exc))));
    abort();
}

static void on_gc_dispose_generator(mrb_state *mrb, void *_generator)
{
    h2o_mruby_generator_t *generator = _generator;
    if (generator == NULL)
        return;
    generator->refs.generator = mrb_nil_value();
}

const static struct mrb_data_type generator_type = {"generator", on_gc_dispose_generator};

h2o_mruby_generator_t *h2o_mruby_get_generator(mrb_state *mrb, mrb_value obj)
{
    h2o_mruby_generator_t *generator = mrb_data_check_get_ptr(mrb, obj, &generator_type);
    return generator;
}

void h2o_mruby_setup_globals(mrb_state *mrb)
{
    const char *root = getenv("H2O_ROOT");
    if (root == NULL)
        root = H2O_TO_STR(H2O_ROOT);
    mrb_gv_set(mrb, mrb_intern_lit(mrb, "$H2O_ROOT"), mrb_str_new(mrb, root, strlen(root)));

    h2o_mruby_eval_expr(mrb, "$LOAD_PATH << \"#{$H2O_ROOT}/share/h2o/mruby\"");
    h2o_mruby_assert(mrb);

    /* require core modules and include built-in libraries */
    h2o_mruby_eval_expr(mrb, "require \"#{$H2O_ROOT}/share/h2o/mruby/preloads.rb\"");
    if (mrb->exc != NULL) {
        if (mrb_obj_is_instance_of(mrb, mrb_obj_value(mrb->exc), mrb_class_get(mrb, "LoadError"))) {
            fprintf(stderr, "file \"%s/%s\" not found. Did you forget to run `make install` ?", root,
                    "share/h2o/mruby/preloads.rb");
        } else {
            fprintf(stderr, "an error occurred while loading %s/%s: %s", root, "share/h2o/mruby/preloads.rb",
                    RSTRING_PTR(mrb_inspect(mrb, mrb_obj_value(mrb->exc))));
        }
        abort();
    }
}

mrb_value h2o_mruby_to_str(mrb_state *mrb, mrb_value v)
{
    if (!mrb_string_p(v))
        H2O_MRUBY_EXEC_GUARD({ v = mrb_str_to_str(mrb, v); });
    return v;
}

mrb_value h2o_mruby_eval_expr(mrb_state *mrb, const char *expr)
{
    return mrb_funcall(mrb, mrb_top_self(mrb), "eval", 1, mrb_str_new_cstr(mrb, expr));
}

void h2o_mruby_define_callback(mrb_state *mrb, const char *name, int id)
{
    mrb_value args[2];
    args[0] = mrb_str_new_cstr(mrb, name);
    args[1] = mrb_fixnum_value(id);
    mrb_funcall_argv(mrb, mrb_top_self(mrb), mrb_intern_lit(mrb, "_h2o_define_callback"), 2, args);

    if (mrb->exc != NULL) {
        fprintf(stderr, "failed to define mruby function: %s\n", name);
        h2o_mruby_assert(mrb);
    }
}

mrb_value h2o_mruby_create_data_instance(mrb_state *mrb, mrb_value class_obj, void *ptr, const mrb_data_type *type)
{
    struct RClass *klass = mrb_class_ptr(class_obj);
    struct RData *data = mrb_data_object_alloc(mrb, klass, ptr, type);
    return mrb_obj_value(data);
}

struct RProc *h2o_mruby_compile_code(mrb_state *mrb, h2o_mruby_config_vars_t *config, char *errbuf)
{
    mrbc_context *cxt;
    struct mrb_parser_state *parser;
    struct RProc *proc = NULL;

    /* parse */
    if ((cxt = mrbc_context_new(mrb)) == NULL) {
        fprintf(stderr, "%s: no memory\n", H2O_MRUBY_MODULE_NAME);
        abort();
    }
    if (config->path != NULL)
        mrbc_filename(mrb, cxt, config->path);
    cxt->capture_errors = 1;
    cxt->lineno = config->lineno;
    if ((parser = mrb_parse_nstring(mrb, config->source.base, (int)config->source.len, cxt)) == NULL) {
        fprintf(stderr, "%s: no memory\n", H2O_MRUBY_MODULE_NAME);
        abort();
    }
    /* return erro if errbuf is supplied, or abort */
    if (parser->nerr != 0) {
        if (errbuf == NULL) {
            fprintf(stderr, "%s: internal error (unexpected state)\n", H2O_MRUBY_MODULE_NAME);
            abort();
        }
        snprintf(errbuf, 256, "line %d:%s", parser->error_buffer[0].lineno, parser->error_buffer[0].message);
        strcat(errbuf, "\n\n");
        if (h2o_str_at_position(errbuf + strlen(errbuf), config->source.base, config->source.len,
                                parser->error_buffer[0].lineno - config->lineno + 1, parser->error_buffer[0].column) != 0) {
            /* remove trailing "\n\n" in case we failed to append the source code at the error location */
            errbuf[strlen(errbuf) - 2] = '\0';
        }
        goto Exit;
    }
    /* generate code */
    if ((proc = mrb_generate_code(mrb, parser)) == NULL) {
        fprintf(stderr, "%s: internal error (mrb_generate_code failed)\n", H2O_MRUBY_MODULE_NAME);
        abort();
    }

Exit:
    mrb_parser_free(parser);
    mrbc_context_free(mrb, cxt);
    return proc;
}

#define KEY_PREFIX "HTTP_"
#define KEY_PREFIX_LEN (sizeof(KEY_PREFIX) - 1)

static h2o_iovec_t convert_header_name_to_env(h2o_mem_pool_t *pool, const char *name, size_t len)
{
    h2o_iovec_t ret;

    ret.len = len + KEY_PREFIX_LEN;
    ret.base = h2o_mem_alloc_pool(pool, ret.len);

    memcpy(ret.base, KEY_PREFIX, KEY_PREFIX_LEN);

    char *d = ret.base + KEY_PREFIX_LEN;
    for (; len != 0; ++name, --len)
        *d++ = *name == '-' ? '_' : h2o_toupper(*name);

    return ret;
}

static h2o_iovec_t convert_env_to_header_name(h2o_mem_pool_t *pool, const char *name, size_t len)
{
    if (len < KEY_PREFIX_LEN || ! h2o_memis(name, KEY_PREFIX_LEN, KEY_PREFIX, KEY_PREFIX_LEN)) {
        return h2o_iovec_init(NULL, 0);
    }

    h2o_iovec_t ret;

    ret.len = len - KEY_PREFIX_LEN;
    ret.base = h2o_mem_alloc_pool(pool, ret.len);

    name += KEY_PREFIX_LEN;
    char *d = ret.base;
    for (; len != 0; ++name, --len)
        *d++ = *name == '_' ? '-' : h2o_tolower(*name);

    return ret;
}

#undef KEY_PREFIX
#undef KEY_PREFIX_LEN

static mrb_value build_constants(mrb_state *mrb, const char *server_name, size_t server_name_len)
{
    mrb_value ary = mrb_ary_new_capa(mrb, H2O_MRUBY_NUM_CONSTANTS);
    mrb_int i;

    int gc_arena = mrb_gc_arena_save(mrb);

    {
        h2o_mem_pool_t pool;
        h2o_mem_init_pool(&pool);
        for (i = 0; i != H2O_MAX_TOKENS; ++i) {
            const h2o_token_t *token = h2o__tokens + i;
            mrb_value lit = mrb_nil_value();
            if (token == H2O_TOKEN_CONTENT_TYPE) {
                lit = mrb_str_new_lit(mrb, "CONTENT_TYPE");
            } else if (token->buf.len != 0) {
                h2o_iovec_t n = convert_header_name_to_env(&pool, token->buf.base, token->buf.len);
                lit = mrb_str_new(mrb, n.base, n.len);
            }
            if (mrb_string_p(lit)) {
                FREEZE_STRING(lit);
                mrb_ary_set(mrb, ary, i, lit);
            }
        }
        h2o_mem_clear_pool(&pool);
    }

#define SET_STRING(idx, value)                                                                                                     \
    do {                                                                                                                           \
        mrb_value lit = (value);                                                                                                   \
        FREEZE_STRING(lit);                                                                                                        \
        mrb_ary_set(mrb, ary, idx, lit);                                                                                           \
    } while (0)
#define SET_LITERAL(idx, str) SET_STRING(idx, mrb_str_new_lit(mrb, str))

    SET_LITERAL(H2O_MRUBY_LIT_REQUEST_METHOD, "REQUEST_METHOD");
    SET_LITERAL(H2O_MRUBY_LIT_SCRIPT_NAME, "SCRIPT_NAME");
    SET_LITERAL(H2O_MRUBY_LIT_PATH_INFO, "PATH_INFO");
    SET_LITERAL(H2O_MRUBY_LIT_QUERY_STRING, "QUERY_STRING");
    SET_LITERAL(H2O_MRUBY_LIT_SERVER_NAME, "SERVER_NAME");
    SET_LITERAL(H2O_MRUBY_LIT_SERVER_ADDR, "SERVER_ADDR");
    SET_LITERAL(H2O_MRUBY_LIT_SERVER_PORT, "SERVER_PORT");
    SET_LITERAL(H2O_MRUBY_LIT_SERVER_PROTOCOL, "SERVER_PROTOCOL");
    SET_LITERAL(H2O_MRUBY_LIT_CONTENT_LENGTH, "CONTENT_LENGTH");
    SET_LITERAL(H2O_MRUBY_LIT_REMOTE_ADDR, "REMOTE_ADDR");
    SET_LITERAL(H2O_MRUBY_LIT_REMOTE_PORT, "REMOTE_PORT");
    SET_LITERAL(H2O_MRUBY_LIT_REMOTE_USER, "REMOTE_USER");
    SET_LITERAL(H2O_MRUBY_LIT_RACK_URL_SCHEME, "rack.url_scheme");
    SET_LITERAL(H2O_MRUBY_LIT_RACK_MULTITHREAD, "rack.multithread");
    SET_LITERAL(H2O_MRUBY_LIT_RACK_MULTIPROCESS, "rack.multiprocess");
    SET_LITERAL(H2O_MRUBY_LIT_RACK_RUN_ONCE, "rack.run_once");
    SET_LITERAL(H2O_MRUBY_LIT_RACK_HIJACK_, "rack.hijack?");
    SET_LITERAL(H2O_MRUBY_LIT_RACK_INPUT, "rack.input");
    SET_LITERAL(H2O_MRUBY_LIT_RACK_ERRORS, "rack.errors");
    SET_LITERAL(H2O_MRUBY_LIT_SERVER_SOFTWARE, "SERVER_SOFTWARE");
    SET_STRING(H2O_MRUBY_LIT_SERVER_SOFTWARE_VALUE, mrb_str_new(mrb, server_name, server_name_len));
    SET_LITERAL(H2O_MRUBY_LIT_SEPARATOR_COMMA, ", ");
    SET_LITERAL(H2O_MRUBY_LIT_SEPARATOR_SEMICOLON, "; ");

#undef SET_LITERAL
#undef SET_STRING

    h2o_mruby_eval_expr(mrb, H2O_MRUBY_CODE_CORE);
    h2o_mruby_assert(mrb);

    mrb_ary_set(mrb, ary, H2O_MRUBY_PROC_EACH_TO_ARRAY,
                mrb_funcall(mrb, mrb_obj_value(mrb->kernel_module), "_h2o_proc_each_to_array", 0));
    h2o_mruby_assert(mrb);

    mrb_gc_arena_restore(mrb, gc_arena);
    return ary;
}

static h2o_mruby_shared_context_t *create_shared_context(h2o_context_t *ctx)
{
    /* init mruby in every thread */
    h2o_mruby_shared_context_t *shared_ctx = h2o_mem_alloc(sizeof(*shared_ctx));
    if ((shared_ctx->mrb = mrb_open()) == NULL) {
        fprintf(stderr, "%s: no memory\n", H2O_MRUBY_MODULE_NAME);
        abort();
    }
    shared_ctx->mrb->ud = shared_ctx;
    shared_ctx->ctx = ctx;
    shared_ctx->current_context = NULL;

    h2o_mruby_setup_globals(shared_ctx->mrb);
    shared_ctx->constants = build_constants(shared_ctx->mrb, ctx->globalconf->server_name.base, ctx->globalconf->server_name.len);
    shared_ctx->symbols.sym_call = mrb_intern_lit(shared_ctx->mrb, "call");
    shared_ctx->symbols.sym_close = mrb_intern_lit(shared_ctx->mrb, "close");
    shared_ctx->symbols.sym_method = mrb_intern_lit(shared_ctx->mrb, "method");
    shared_ctx->symbols.sym_headers = mrb_intern_lit(shared_ctx->mrb, "headers");
    shared_ctx->symbols.sym_body = mrb_intern_lit(shared_ctx->mrb, "body");
    shared_ctx->symbols.sym_async = mrb_intern_lit(shared_ctx->mrb, "async");

    h2o_mruby_send_chunked_init_context(shared_ctx);
    h2o_mruby_http_request_init_context(shared_ctx);
    h2o_mruby_sleep_init_context(shared_ctx);

    struct RClass *module = mrb_define_module(shared_ctx->mrb, "H2O");
    struct RClass *generator_klass = mrb_define_class_under(shared_ctx->mrb, module, "Generator", shared_ctx->mrb->object_class);
    mrb_ary_set(shared_ctx->mrb, shared_ctx->constants, H2O_MRUBY_GENERATOR_CLASS, mrb_obj_value(generator_klass));


    h2o_mruby_define_callback(shared_ctx->mrb, "_h2o_invoke_app", H2O_MRUBY_CALLBACK_ID_INVOKE_APP);

    h2o_mruby_define_callback(shared_ctx->mrb, "_h2o_output_filter_wait_chunk", H2O_MRUBY_CALLBACK_ID_OUTPUT_FILTER_WAIT_CHUNK);
    struct RClass *klass = mrb_class_get_under(shared_ctx->mrb, module, "OutputFilterStream");
    mrb_ary_set(shared_ctx->mrb, shared_ctx->constants, H2O_MRUBY_OUTPUT_FILTER_STREAM_CLASS, mrb_obj_value(klass));

    return shared_ctx;
}

static void dispose_shared_context(void *data)
{
    if (data == NULL)
        return;
    h2o_mruby_shared_context_t *shared_ctx = (h2o_mruby_shared_context_t *)data;
    mrb_close(shared_ctx->mrb);
    free(shared_ctx);
}

static h2o_mruby_shared_context_t *get_shared_context(h2o_context_t *ctx)
{
    static size_t key = SIZE_MAX;
    void **data = h2o_context_get_storage(ctx, &key, dispose_shared_context);
    if (*data == NULL) {
        *data = create_shared_context(ctx);
    }
    return *data;
}

mrb_value prepare_fibers(h2o_mruby_context_t *ctx)
{
    mrb_state *mrb = ctx->shared->mrb;

    h2o_mruby_config_vars_t config = ctx->handler->config;
    mrb_value conf = mrb_hash_new_capa(mrb, 3);
    mrb_hash_set(mrb, conf, mrb_symbol_value(mrb_intern_lit(mrb, "code")), mrb_str_new(mrb, config.source.base, config.source.len));
    mrb_hash_set(mrb, conf, mrb_symbol_value(mrb_intern_lit(mrb, "file")), mrb_str_new(mrb, config.path, strlen(config.path)));
    mrb_hash_set(mrb, conf, mrb_symbol_value(mrb_intern_lit(mrb, "line")), mrb_fixnum_value(config.lineno));

    /* run code and generate handler */
    mrb_value result = mrb_funcall(mrb, mrb_obj_value(mrb->kernel_module), "_h2o_prepare_app", 1, conf);
    h2o_mruby_assert(mrb);
    assert(mrb_array_p(result));

    return result;
}

static void on_context_init(h2o_handler_t *_handler, h2o_context_t *ctx)
{
    h2o_mruby_handler_t *handler = (void *)_handler;
    h2o_mruby_context_t *handler_ctx = h2o_mem_alloc(sizeof(*handler_ctx));

    handler_ctx->handler = handler;
    handler_ctx->shared = get_shared_context(ctx);

    mrb_state *mrb = handler_ctx->shared->mrb;

    handler_ctx->pendings = mrb_ary_new(mrb);

    /* compile code (must be done for each thread) */
    int arena = mrb_gc_arena_save(mrb);

    mrb_value fibers = prepare_fibers(handler_ctx);
    assert(mrb_array_p(fibers));

    handler_ctx->proc = mrb_ary_entry(fibers, 0);

    /* run configurator */
    mrb_value configurator = mrb_ary_entry(fibers, 1);
    h2o_mruby_run_fiber(handler_ctx, configurator, mrb_nil_value(), NULL);
    h2o_mruby_assert(handler_ctx->shared->mrb);

    mrb_gc_arena_restore(mrb, arena);
    mrb_gc_protect(mrb, handler_ctx->proc);
    mrb_gc_protect(mrb, configurator);

    h2o_context_set_handler_context(ctx, &handler->super, handler_ctx);
}

static void on_context_dispose(h2o_handler_t *_handler, h2o_context_t *ctx)
{
    h2o_mruby_handler_t *handler = (void *)_handler;
    h2o_mruby_context_t *handler_ctx = h2o_context_get_handler_context(ctx, &handler->super);

    if (handler_ctx == NULL)
        return;

    free(handler_ctx);
}

static void on_handler_dispose(h2o_handler_t *_handler)
{
    h2o_mruby_handler_t *handler = (void *)_handler;

    free(handler->config.source.base);
    free(handler->config.path);
    free(handler);
}

static void report_exception(h2o_req_t *req, mrb_state *mrb)
{
    h2o_req_log_error(req, H2O_MRUBY_MODULE_NAME, "mruby raised: %s\n", RSTRING_PTR(mrb_inspect(mrb, mrb_obj_value(mrb->exc))));
    mrb->exc = NULL;
}

static void stringify_address(h2o_conn_t *conn, socklen_t (*cb)(h2o_conn_t *conn, struct sockaddr *), mrb_state *mrb,
                              mrb_value *host, mrb_value *port)
{
    struct sockaddr_storage ss;
    socklen_t sslen;
    char buf[NI_MAXHOST];

    *host = mrb_nil_value();
    *port = mrb_nil_value();

    if ((sslen = cb(conn, (void *)&ss)) == 0)
        return;
    size_t l = h2o_socket_getnumerichost((void *)&ss, sslen, buf);
    if (l != SIZE_MAX)
        *host = mrb_str_new(mrb, buf, l);
    int32_t p = h2o_socket_getport((void *)&ss);
    if (p != -1) {
        l = (int)sprintf(buf, "%" PRIu16, (uint16_t)p);
        *port = mrb_str_new(mrb, buf, l);
    }
}

static void on_rack_input_free(mrb_state *mrb, const char *base, mrb_int len, void *_input_stream)
{
    /* reset ref to input_stream */
    mrb_value *input_stream = _input_stream;
    *input_stream = mrb_nil_value();
}

static int build_env_sort_header_cb(const void *_x, const void *_y)
{
    const h2o_header_t *x = *(const h2o_header_t **)_x, *y = *(const h2o_header_t **)_y;
    if (x->name->len < y->name->len)
        return -1;
    if (x->name->len > y->name->len)
        return 1;
    if (x->name->base != y->name->base) {
        int r = memcmp(x->name->base, y->name->base, x->name->len);
        if (r != 0)
            return r;
    }
    assert(x != y);
    /* the order of the headers having the same name needs to be retained */
    return x < y ? -1 : 1;
}

static mrb_value build_env(h2o_mruby_generator_t *generator)
{
    h2o_mruby_shared_context_t *shared = generator->ctx->shared;
    mrb_state *mrb = shared->mrb;
    mrb_value env = mrb_hash_new_capa(mrb, 16);
    char http_version[sizeof("HTTP/1.0")];
    size_t http_version_sz;

    /* environment */
    mrb_hash_set(mrb, env, mrb_ary_entry(shared->constants, H2O_MRUBY_LIT_REQUEST_METHOD),
                 mrb_str_new(mrb, generator->req->method.base, generator->req->method.len));
    size_t confpath_len_wo_slash = generator->req->pathconf->path.len;
    if (generator->req->pathconf->path.base[generator->req->pathconf->path.len - 1] == '/')
        --confpath_len_wo_slash;
    mrb_hash_set(mrb, env, mrb_ary_entry(shared->constants, H2O_MRUBY_LIT_SCRIPT_NAME),
                 mrb_str_new(mrb, generator->req->pathconf->path.base, confpath_len_wo_slash));
    mrb_hash_set(mrb, env, mrb_ary_entry(shared->constants, H2O_MRUBY_LIT_PATH_INFO),
                 mrb_str_new(mrb, generator->req->path_normalized.base + confpath_len_wo_slash,
                             generator->req->path_normalized.len - confpath_len_wo_slash));
    mrb_hash_set(mrb, env, mrb_ary_entry(shared->constants, H2O_MRUBY_LIT_QUERY_STRING),
                 generator->req->query_at != SIZE_MAX ? mrb_str_new(mrb, generator->req->path.base + generator->req->query_at + 1,
                                                                    generator->req->path.len - (generator->req->query_at + 1))
                                                      : mrb_str_new_lit(mrb, ""));
    mrb_hash_set(mrb, env, mrb_ary_entry(shared->constants, H2O_MRUBY_LIT_SERVER_NAME),
                 mrb_str_new(mrb, generator->req->hostconf->authority.host.base, generator->req->hostconf->authority.host.len));
    http_version_sz = h2o_stringify_protocol_version(http_version, generator->req->version);
    mrb_hash_set(mrb, env, mrb_ary_entry(shared->constants, H2O_MRUBY_LIT_SERVER_PROTOCOL),
                 mrb_str_new(mrb, http_version, http_version_sz));
    {
        mrb_value h, p;
        stringify_address(generator->req->conn, generator->req->conn->callbacks->get_sockname, mrb, &h, &p);
        if (!mrb_nil_p(h))
            mrb_hash_set(mrb, env, mrb_ary_entry(shared->constants, H2O_MRUBY_LIT_SERVER_ADDR), h);
        if (!mrb_nil_p(p))
            mrb_hash_set(mrb, env, mrb_ary_entry(shared->constants, H2O_MRUBY_LIT_SERVER_PORT), p);
    }
    mrb_hash_set(mrb, env, mrb_ary_entry(shared->constants, H2O_TOKEN_HOST - h2o__tokens),
                 mrb_str_new(mrb, generator->req->authority.base, generator->req->authority.len));
    if (generator->req->entity.base != NULL) {
        char buf[32];
        int l = sprintf(buf, "%zu", generator->req->entity.len);
        mrb_hash_set(mrb, env, mrb_ary_entry(shared->constants, H2O_MRUBY_LIT_CONTENT_LENGTH), mrb_str_new(mrb, buf, l));
        generator->rack_input = mrb_input_stream_value(mrb, NULL, 0);
        mrb_input_stream_set_data(mrb, generator->rack_input, generator->req->entity.base, (mrb_int)generator->req->entity.len, 0,
                                  on_rack_input_free, &generator->rack_input);
        mrb_hash_set(mrb, env, mrb_ary_entry(shared->constants, H2O_MRUBY_LIT_RACK_INPUT), generator->rack_input);
    }
    {
        mrb_value h, p;
        stringify_address(generator->req->conn, generator->req->conn->callbacks->get_peername, mrb, &h, &p);
        if (!mrb_nil_p(h))
            mrb_hash_set(mrb, env, mrb_ary_entry(shared->constants, H2O_MRUBY_LIT_REMOTE_ADDR), h);
        if (!mrb_nil_p(p))
            mrb_hash_set(mrb, env, mrb_ary_entry(shared->constants, H2O_MRUBY_LIT_REMOTE_PORT), p);
    }
    {
        size_t i;
        for (i = 0; i != generator->req->env.size; i += 2) {
            h2o_iovec_t *name = generator->req->env.entries + i, *value = name + 1;
            mrb_hash_set(mrb, env, mrb_str_new(mrb, name->base, name->len), mrb_str_new(mrb, value->base, value->len));
        }
    }

    { /* headers */
        h2o_header_t **headers_sorted = alloca(sizeof(*headers_sorted) * generator->req->headers.size);
        size_t i;
        for (i = 0; i != generator->req->headers.size; ++i)
            headers_sorted[i] = generator->req->headers.entries + i;
        qsort(headers_sorted, generator->req->headers.size, sizeof(*headers_sorted), build_env_sort_header_cb);
        for (i = 0; i != generator->req->headers.size; ++i) {
            const h2o_header_t *header = headers_sorted[i];
            mrb_value n, v;
            if (h2o_iovec_is_token(header->name)) {
                const h2o_token_t *token = H2O_STRUCT_FROM_MEMBER(h2o_token_t, buf, header->name);
                if (token == H2O_TOKEN_TRANSFER_ENCODING)
                    continue;
                n = mrb_ary_entry(shared->constants, (mrb_int)(token - h2o__tokens));
            } else {
                h2o_iovec_t vec = convert_header_name_to_env(&generator->req->pool, header->name->base, header->name->len);
                n = mrb_str_new(mrb, vec.base, vec.len);
            }
            v = mrb_str_new(mrb, header->value.base, header->value.len);
            while (i < generator->req->headers.size - 1) {
                if (!h2o_memis(headers_sorted[i + 1]->name->base, headers_sorted[i + 1]->name->len, header->name->base,
                               header->name->len))
                    break;
                header = headers_sorted[++i];
                v = mrb_str_append(mrb, v, mrb_ary_entry(shared->constants,
                                                         header->name == &H2O_TOKEN_COOKIE->buf ? H2O_MRUBY_LIT_SEPARATOR_SEMICOLON
                                                                                                : H2O_MRUBY_LIT_SEPARATOR_COMMA));
                v = mrb_str_append(mrb, v, mrb_str_new(mrb, header->value.base, header->value.len));
            }
            mrb_hash_set(mrb, env, n, v);
        }
    }

    /* rack.* */
    /* TBD rack.version? */
    mrb_hash_set(mrb, env, mrb_ary_entry(shared->constants, H2O_MRUBY_LIT_RACK_URL_SCHEME),
                 mrb_str_new(mrb, generator->req->scheme->name.base, generator->req->scheme->name.len));
    /* we are using shared-none architecture, and therefore declare ourselves as multiprocess */
    mrb_hash_set(mrb, env, mrb_ary_entry(shared->constants, H2O_MRUBY_LIT_RACK_MULTITHREAD), mrb_false_value());
    mrb_hash_set(mrb, env, mrb_ary_entry(shared->constants, H2O_MRUBY_LIT_RACK_MULTIPROCESS), mrb_true_value());
    mrb_hash_set(mrb, env, mrb_ary_entry(shared->constants, H2O_MRUBY_LIT_RACK_RUN_ONCE), mrb_false_value());
    mrb_hash_set(mrb, env, mrb_ary_entry(shared->constants, H2O_MRUBY_LIT_RACK_HIJACK_), mrb_false_value());
    mrb_hash_set(mrb, env, mrb_ary_entry(shared->constants, H2O_MRUBY_LIT_RACK_ERRORS),
                 mrb_gv_get(mrb, mrb_intern_lit(mrb, "$stderr")));

    /* server name */
    mrb_hash_set(mrb, env, mrb_ary_entry(shared->constants, H2O_MRUBY_LIT_SERVER_SOFTWARE),
                 mrb_ary_entry(shared->constants, H2O_MRUBY_LIT_SERVER_SOFTWARE_VALUE));

    return env;
}

static int handle_response_header(h2o_mruby_shared_context_t *shared_ctx, h2o_iovec_t name, h2o_iovec_t value, void *_req)
{
    h2o_req_t *req = _req;
    const h2o_token_t *token;
    static const h2o_iovec_t fallthru_set_prefix = {H2O_STRLIT(FALLTHRU_SET_PREFIX)};

    /* convert name to lowercase */
    name = h2o_strdup(&req->pool, name.base, name.len);
    h2o_strtolower(name.base, name.len);

    if ((token = h2o_lookup_token(name.base, name.len)) != NULL) {
        if (token->proxy_should_drop_for_res) {
            /* skip */
        } else if (token == H2O_TOKEN_CONTENT_LENGTH) {
            req->res.content_length = h2o_strtosize(value.base, value.len);
        } else {
            value = h2o_strdup(&req->pool, value.base, value.len);
            if (token == H2O_TOKEN_LINK) {
                h2o_iovec_t new_value = h2o_push_path_in_link_header(req, value.base, value.len);
                if (new_value.len)
                    h2o_add_header(&req->pool, &req->res.headers, token, NULL, new_value.base, new_value.len);
            } else {
                h2o_add_header(&req->pool, &req->res.headers, token, NULL, value.base, value.len);
            }
        }
    } else if (name.len > fallthru_set_prefix.len &&
               h2o_memis(name.base, fallthru_set_prefix.len, fallthru_set_prefix.base, fallthru_set_prefix.len)) {
        /* register environment variables (with the name converted to uppercase, and using `_`) */
        size_t i;
        name.base += fallthru_set_prefix.len;
        name.len -= fallthru_set_prefix.len;
        for (i = 0; i != name.len; ++i)
            name.base[i] = name.base[i] == '-' ? '_' : h2o_toupper(name.base[i]);
        h2o_iovec_t *slot = h2o_req_getenv(req, name.base, name.len, 1);
        *slot = h2o_strdup(&req->pool, value.base, value.len);
    } else {
        value = h2o_strdup(&req->pool, value.base, value.len);
        h2o_add_header_by_str(&req->pool, &req->res.headers, name.base, name.len, 0, NULL, value.base, value.len);
    }

    return 0;
}

static void clear_rack_input(h2o_mruby_generator_t *generator)
{
    if (!mrb_nil_p(generator->rack_input))
        mrb_input_stream_set_data(generator->ctx->shared->mrb, generator->rack_input, NULL, -1, 0, NULL, NULL);
}

static void on_generator_dispose(void *_generator)
{
    h2o_mruby_generator_t *generator = _generator;

    clear_rack_input(generator);
    generator->req = NULL;
    if (h2o_timeout_is_linked(&generator->output_filter.defer_proceed_timeout_entry))
        h2o_timeout_unlink(&generator->output_filter.defer_proceed_timeout_entry);
    if (h2o_timeout_is_linked(&generator->output_filter.defer_close_timeout_entry))
        h2o_timeout_unlink(&generator->output_filter.defer_close_timeout_entry);

    if (!mrb_nil_p(generator->refs.generator))
        DATA_PTR(generator->refs.generator) = NULL;

    if (generator->chunked != NULL)
        h2o_mruby_send_chunked_dispose(generator);
}

static int output_filter_is_registered(h2o_mruby_generator_t *generator)
{
    return generator->output_filter.prefilter != NULL;
}

static void do_generator_proceed(h2o_generator_t *_generator, h2o_req_t *req)
{
    h2o_mruby_generator_t *generator = (void *)_generator;

    if (generator->chunked != NULL) {
        generator->chunked->proceed(_generator, req);
    }
}

static void do_generator_stop(h2o_generator_t *_generator, h2o_req_t *req)
{
    h2o_mruby_generator_t *generator = (void *)_generator;

    if (output_filter_is_registered(generator)) {
        h2o_generator_t *prev = generator->output_filter.prev;
        if (prev != NULL && prev->stop != NULL) {
            prev->stop(prev, req);
        }
    }
}

static void on_prev_defer_close_timeout(h2o_timeout_entry_t *entry)
{
    h2o_mruby_generator_t *generator = H2O_STRUCT_FROM_MEMBER(h2o_mruby_generator_t, output_filter.defer_close_timeout_entry, entry);
    h2o_generator_t *prev = generator->output_filter.prev;
    assert(prev != NULL);
    assert(prev->stop != NULL);
    prev->stop(prev, generator->req);
}

static int on_req(h2o_handler_t *_handler, h2o_req_t *req)
{
    h2o_mruby_handler_t *handler = (void *)_handler;
    h2o_mruby_shared_context_t *shared = get_shared_context(req->conn->ctx);
    int gc_arena = mrb_gc_arena_save(shared->mrb);

    h2o_mruby_context_t *ctx = h2o_context_get_handler_context(req->conn->ctx, &handler->super);

    h2o_mruby_generator_t *generator = h2o_mem_alloc_shared(&req->pool, sizeof(*generator), on_generator_dispose);
    memset(generator, 0, sizeof(*generator));
    generator->super.proceed = do_generator_proceed;
    generator->super.stop = do_generator_stop;
    generator->req = req;
    generator->ctx = ctx;
    generator->rack_input = mrb_nil_value();
    generator->chunked = NULL;
    generator->output_filter.ostream = NULL;
    generator->output_filter.prefilter = NULL;
    generator->output_filter.slot = NULL;
    generator->output_filter.defer_close_timeout_entry.cb = on_prev_defer_close_timeout;

    mrb_value env = build_env(generator);

    mrb_value gen = h2o_mruby_create_data_instance(shared->mrb, mrb_ary_entry(shared->constants, H2O_MRUBY_GENERATOR_CLASS),
                                                   generator, &generator_type);
    generator->refs.generator = gen;

    mrb_value args = mrb_ary_new(shared->mrb);
    mrb_ary_set(shared->mrb, args, 0, env);
    mrb_ary_set(shared->mrb, args, 1, gen);

    int is_delegate = 0;
    h2o_mruby_run_fiber(ctx, ctx->proc, args, &is_delegate);

    mrb_gc_arena_restore(shared->mrb, gc_arena);

    if (is_delegate)
        return -1;
    return 0;
}

void h2o_mruby_start_response(h2o_mruby_generator_t *generator)
{
    /* the response may have been already initiated by other handlers if H2O.app.call was called */
    if (output_filter_is_registered(generator)) {
        h2o_setup_next_prefilter(generator->output_filter.prefilter, generator->req, generator->output_filter.slot);
    } else {
        h2o_start_response(generator->req, &generator->super);
    }
}

static void close_response(h2o_mruby_generator_t *generator)
{
    if (generator->req->_generator != NULL) {
        h2o_mruby_send_chunked_close(generator);
    } else {
        h2o_send_error_500(generator->req, "Internal Server Error", "Internal Server Error", 0);
    }
}

static void send_response(h2o_mruby_generator_t *generator, mrb_int status, mrb_value resp, int *is_delegate)
{
    mrb_state *mrb = generator->ctx->shared->mrb;
    mrb_value body;
    h2o_iovec_t content = {NULL};

    /* set status */
    generator->req->res.status = (int)status;

    /* set headers */
    if (h2o_mruby_iterate_headers(generator->ctx->shared, mrb_ary_entry(resp, 1), handle_response_header, generator->req) != 0) {
        assert(mrb->exc != NULL);
        goto GotException;
    }

    /* return without processing body, if status is fallthru */
    if (generator->req->res.status == STATUS_FALLTHRU) {
        if (is_delegate != NULL)
            *is_delegate = 1;
        else
            h2o_delegate_request_deferred(generator->req, &generator->ctx->handler->super);
        return;
    }

    /* obtain body */
    body = mrb_ary_entry(resp, 2);

    /* flatten body if possible */
    if (mrb_array_p(body)) {
        mrb_int i, len = RARRAY_LEN(body);
        /* calculate the length of the output, while at the same time converting the elements of the output array to string */
        content.len = 0;
        for (i = 0; i != len; ++i) {
            mrb_value e = mrb_ary_entry(body, i);
            if (!mrb_string_p(e)) {
                e = h2o_mruby_to_str(mrb, e);
                if (mrb->exc != NULL)
                    goto GotException;
                mrb_ary_set(mrb, body, i, e);
            }
            content.len += RSTRING_LEN(e);
        }
        /* allocate memory, and copy the response */
        char *dst = content.base = h2o_mem_alloc_pool(&generator->req->pool, content.len);
        for (i = 0; i != len; ++i) {
            mrb_value e = mrb_ary_entry(body, i);
            assert(mrb_string_p(e));
            memcpy(dst, RSTRING_PTR(e), RSTRING_LEN(e));
            dst += RSTRING_LEN(e);
        }
        /* reset body to nil, now that we have read all data */
        body = mrb_nil_value();
    }

    if (mrb_nil_p(body)) {
        h2o_mruby_start_response(generator);

        /* send the entire response immediately */
        if (status == 101 || status == 204 || status == 304 ||
            h2o_memis(generator->req->input.method.base, generator->req->input.method.len, H2O_STRLIT("HEAD"))) {
            h2o_mruby_send(generator, NULL, 0, H2O_SEND_STATE_FINAL);
        } else {
            if (content.len < generator->req->res.content_length) {
                generator->req->res.content_length = content.len;
            } else {
                content.len = generator->req->res.content_length;
            }
            h2o_mruby_send(generator, &content, 1, H2O_SEND_STATE_FINAL);
        }

    } else {
        /* body is each-able ruby object */
        mrb_value receiver = h2o_mruby_send_chunked_init(generator, body);
        if (mrb->exc) {
            goto GotException;
        }

        if (!mrb_nil_p(receiver)) {
            /* use fiber in case we need to call #each */
            mrb_value input = mrb_ary_new_capa(mrb, 2);
            mrb_ary_set(mrb, input, 0, body);
            mrb_ary_set(mrb, input, 1, generator->refs.generator);
            h2o_mruby_run_fiber(generator->ctx, receiver, input, 0);
        }
    }

    return;

GotException:
    report_exception(generator->req, mrb);
    close_response(generator);
    mrb->exc = NULL;
}

static mrb_value build_app_response(struct st_mruby_output_ostream_t *ostream, h2o_req_t *req)
{
    h2o_mruby_context_t *ctx = ostream->ctx;
    mrb_state *mrb = ctx->shared->mrb;
    size_t i;

    /* build response array */
    mrb_value resp = mrb_ary_new_capa(mrb, 3);

    /* status */
    mrb_ary_set(mrb, resp, 0, mrb_fixnum_value(req->res.status));

    /* headers */
    {
        mrb_value headers_hash = mrb_hash_new_capa(mrb, (int)req->res.headers.size);
        h2o_header_t **headers_sorted = alloca(sizeof(*headers_sorted) * req->res.headers.size);
        for (i = 0; i != req->res.headers.size; ++i)
            headers_sorted[i] = req->res.headers.entries + i;
        qsort(headers_sorted, req->res.headers.size, sizeof(*headers_sorted), build_env_sort_header_cb);
        for (i = 0; i != req->res.headers.size; ++i) {
            const h2o_header_t *header = headers_sorted[i];
            mrb_value n, v;
            if (h2o_iovec_is_token(header->name)) {
                const h2o_token_t *token = H2O_STRUCT_FROM_MEMBER(h2o_token_t, buf, header->name);
                if (token == H2O_TOKEN_TRANSFER_ENCODING)
                    continue;
                n = mrb_str_new(mrb, token->buf.base, token->buf.len);
            } else {
                n = mrb_str_new(mrb, header->name->base, header->name->len);
            }
            v = mrb_str_new(mrb, header->value.base, header->value.len);
            while (i + 1 < req->res.headers.size) {

                if (!h2o_memis(headers_sorted[i]->name->base, headers_sorted[i]->name->len, headers_sorted[i + 1]->name->base,
                                                    headers_sorted[i + 1]->name->len))
                    break;
                ++i;
                v = mrb_str_cat_lit(mrb, v, "\n");
                v = mrb_str_cat(mrb, v, headers_sorted[i]->value.base, headers_sorted[i]->value.len);
            }
            mrb_hash_set(mrb, headers_hash, n, v);
        }
        mrb_ary_set(mrb, resp, 1, headers_hash);
    }

    /* body */
    {
        mrb_value body = h2o_mruby_create_data_instance(mrb, mrb_ary_entry(ctx->shared->constants, H2O_MRUBY_OUTPUT_FILTER_STREAM_CLASS), ostream, &output_filter_stream_type);
        mrb_funcall(mrb, body, "initialize", 0);
        mrb_ary_set(mrb, resp, 2, body);
    }

    return resp;
}

static void on_defer_proceed_timeout(h2o_timeout_entry_t *entry)
{
    h2o_mruby_generator_t *generator = H2O_STRUCT_FROM_MEMBER(h2o_mruby_generator_t, output_filter.defer_proceed_timeout_entry, entry);
    assert(generator->output_filter.prev != NULL);
    generator->output_filter.prev->proceed(generator->output_filter.prev, generator->req);
}

static void ostream_send(h2o_ostream_t *_self, h2o_req_t *req, h2o_iovec_t *inbufs, size_t inbufcnt, h2o_send_state_t state)
{
    struct st_mruby_output_ostream_t *self = (void *)_self;
    mrb_state *mrb = self->ctx->shared->mrb;
    mrb_value receiver = self->receiver;

    if (inbufcnt > 0) {
        /* push incoming chunks to ostream */
        int gc_arena = mrb_gc_arena_save(mrb);

        mrb_value incoming_chunks = mrb_ary_new_capa(mrb, (mrb_int)inbufcnt);
        mrb_int i;
        for (i = 0; i < inbufcnt; ++i) {
            mrb_value chunk = mrb_str_new(mrb, inbufs[i].base, inbufs[i].len);
            mrb_ary_set(mrb, incoming_chunks, i, chunk);
        }

        mrb_value chunks = mrb_iv_get(mrb, self->ref, mrb_intern_lit(mrb, "@chunks"));
        mrb_ary_concat(mrb, chunks, incoming_chunks);
        h2o_mruby_assert(mrb);

        mrb_gc_arena_restore(mrb, gc_arena);
    }

    if (h2o_send_state_is_in_progress(state)) {
        h2o_generator_t *prev = self->generator->output_filter.prev;
        assert(prev != NULL);
        h2o_context_t *ctx = self->generator->ctx->shared->ctx;
        self->generator->output_filter.defer_proceed_timeout_entry.cb = on_defer_proceed_timeout;
        h2o_timeout_link(ctx->loop, &ctx->zero_timeout, &self->generator->output_filter.defer_proceed_timeout_entry);
    } else {
        /* NOTE: at this point, we assume that prev has done finalization (i.e. free, close something, etc..) */

        /* when the following handler finished sending it's response and call h2o_send, req->_generator is set NULL, but we want to keep processing here, so fulfill req->_generator again. This may be a bit tricky code.. */
        assert(req->_generator == NULL);
        h2o_mruby_generator_t *last = self->generator;
        while (last->output_filter.next != NULL) {
            last = last->output_filter.next;
            assert(output_filter_is_registered(last));
        }
        req->_generator = &last->super;
        self->generator->output_filter.prev = NULL;

        if (! mrb_nil_p(self->ref)) {
            mrb_iv_set(mrb, self->ref, mrb_intern_lit(mrb, "@finished"), mrb_true_value());
        }
    }

    /* detach receiver */
    if (! mrb_nil_p(receiver)) {
        int gc_arena = mrb_gc_arena_save(mrb);

        mrb_gc_unregister(mrb, receiver);
        mrb_gc_protect(mrb, receiver);
        self->receiver = mrb_nil_value();

        /* resume _h2o_output_filter_wait_chunk (which expects no arguments) */
        /* TODO: fast path */

        h2o_mruby_run_fiber(self->ctx, receiver, mrb_nil_value(), NULL);
        mrb_gc_arena_restore(mrb, gc_arena);
    }
}

static int handle_request_header(h2o_mruby_shared_context_t *shared_ctx, h2o_iovec_t name, h2o_iovec_t value, void *_req)
{
    h2o_req_t *req = _req;
    const h2o_token_t *token;

    /* convert env key to header name (lower case) */
    name = convert_env_to_header_name(&req->pool, name.base, name.len);
    if (name.base == NULL)
        return 0;

    if ((token = h2o_lookup_token(name.base, name.len)) != NULL) {
        if (token == H2O_TOKEN_TRANSFER_ENCODING) {
            /* skip */
        } else {
            if (token == H2O_TOKEN_CONTENT_LENGTH) {
                /* TODO: truncate body? */
            }
            value = h2o_strdup(&req->pool, value.base, value.len);
            h2o_add_header(&req->pool, &req->headers, token, NULL, value.base, value.len);
        }
    } else {
        value = h2o_strdup(&req->pool, value.base, value.len);
        h2o_add_header_by_str(&req->pool, &req->headers, name.base, name.len, 0, NULL, value.base, value.len);
    }

    return 0;
}

static mrb_value setup_req_for_env(h2o_mruby_context_t *ctx, h2o_req_t *req, mrb_value env, int reprocess)
{
    mrb_state *mrb = ctx->shared->mrb;


#define RETRIEVE_ENV(key, v) do { \
    v = mrb_hash_get(mrb, env, mrb_ary_entry(ctx->shared->constants, H2O_MRUBY_LIT_ ## key)); \
    if (mrb_nil_p(v)) { \
        return mrb_exc_new_str_lit(mrb, E_RUNTIME_ERROR, "http response body is already consumed"); \
    } \
    v = h2o_mruby_to_str(mrb, v); \
} while (0)

    /* TODO: use Rack::Request? */
    h2o_url_t url_parsed;
    mrb_value scheme, method, server_addr, server_port, script_name, path_info, query_string;
    RETRIEVE_ENV(RACK_URL_SCHEME, scheme);
    RETRIEVE_ENV(REQUEST_METHOD, method);
    RETRIEVE_ENV(SERVER_ADDR, server_addr);
    RETRIEVE_ENV(SERVER_PORT, server_port);
    RETRIEVE_ENV(SCRIPT_NAME, script_name);
    RETRIEVE_ENV(PATH_INFO, path_info);
    RETRIEVE_ENV(QUERY_STRING, query_string);
#undef RETRIEVE_ENV

    mrb_value url = mrb_obj_dup(mrb, scheme);
    mrb_str_concat(mrb, url, mrb_str_new_lit(mrb, "://"));
    mrb_str_concat(mrb, url, server_addr);
    mrb_str_concat(mrb, url, mrb_str_new_lit(mrb, ":"));
    mrb_str_concat(mrb, url, server_port);
    if (reprocess) {
        mrb_str_concat(mrb, url, script_name);
        mrb_str_concat(mrb, url, path_info);
    } else {
        mrb_str_concat(mrb, url, mrb_str_new(mrb, req->path_normalized.base, req->path_normalized.len));
    }
    if (RSTRING_LEN(query_string) != 0) {
        mrb_str_concat(mrb, url, mrb_str_new_lit(mrb, "?"));
        mrb_str_concat(mrb, url, query_string);
    }
    if (h2o_url_parse(RSTRING_PTR(url), RSTRING_LEN(url), &url_parsed) != 0) {
        /* TODO is there any other way to show better error message? */
        return mrb_exc_new_str_lit(mrb, E_ARGUMENT_ERROR, "env variable contains invalid values");
    }

    req->scheme = url_parsed.scheme;
    req->method = h2o_strdup(&req->pool, RSTRING_PTR(method), RSTRING_LEN(method));
    req->authority = url_parsed.authority;
    req->path = url_parsed.path;
    req->path_normalized = h2o_url_normalize_path(&req->pool, req->path.base, req->path.len, &req->query_at, &req->norm_indexes);
    req->headers = (h2o_headers_t){NULL};
    h2o_mruby_iterate_headers(ctx->shared, env, handle_request_header, req);

    return mrb_nil_value();
}

static void on_prefilter_defer_resume_timeout(h2o_timeout_entry_t *entry)
{
    struct st_mruby_output_prefilter_t *self = H2O_STRUCT_FROM_MEMBER(struct st_mruby_output_prefilter_t, defer_resume.timeout_entry, entry);
    mrb_state *mrb = self->generator->ctx->shared->mrb;

    int gc_arena = mrb_gc_arena_save(mrb);

    /* detach receiver */
    mrb_value receiver = self->receiver;
    mrb_gc_unregister(mrb, receiver);
    mrb_gc_protect(mrb, receiver);
    self->receiver = mrb_nil_value();

    /* detach resp */
    mrb_value resp = self->defer_resume.resp;
    mrb_gc_unregister(mrb, resp);
    mrb_gc_protect(mrb, resp);
    self->defer_resume.resp = mrb_nil_value();

    h2o_mruby_run_fiber(self->ctx, receiver, resp, NULL);

    mrb_gc_arena_restore(mrb, gc_arena);
}

static void on_prefilter_setup_stream(h2o_req_prefilter_t *_self, h2o_req_t *req, h2o_ostream_t **slot)
{
    struct st_mruby_output_prefilter_t *self = (void *)_self;
    mrb_state *mrb = self->generator->ctx->shared->mrb;

    assert(req->_generator != NULL && req->_generator != &self->generator->super);

    /* wrap generator and swap */
    self->generator->output_filter.prev = req->_generator;
    if (self->generator->output_filter.prev->proceed == do_generator_proceed) {
        h2o_mruby_generator_t *prev_generator = (h2o_mruby_generator_t *)self->generator->output_filter.prev;
        prev_generator->output_filter.next = self->generator;
    }
    req->_generator = &self->generator->super;

    /* setup ostream */
    assert(self->generator->output_filter.ostream == NULL);
    struct st_mruby_output_ostream_t *ostream  = (void *)h2o_add_ostream(req, sizeof(struct st_mruby_output_ostream_t), slot);
    ostream->super.do_send = ostream_send;
    slot = &ostream->super.next;
    ostream->ctx = self->ctx;
    ostream->generator = self->generator;
    ostream->receiver = mrb_nil_value();
    self->generator->output_filter.ostream = &ostream->super;
    self->generator->output_filter.slot = slot;

    int gc_arena = mrb_gc_arena_save(mrb);

    /* build app response */
    mrb_value resp = build_app_response(ostream, req);
    mrb_gc_register(mrb, resp);
    ostream->ref = mrb_ary_entry(resp, 2);

    mrb_gc_arena_restore(mrb, gc_arena);

    /* clear the response except for original */
    req->res.status = 0;
    req->res.reason = "OK";
    req->res.content_length = SIZE_MAX;
    req->res.headers = (h2o_headers_t){NULL};
    req->res.mime_attr = NULL;

    self->defer_resume.resp = resp;
    self->defer_resume.timeout_entry.cb = on_prefilter_defer_resume_timeout;
    h2o_timeout_link(req->conn->ctx->loop, &req->conn->ctx->zero_timeout, &self->defer_resume.timeout_entry);
}

static void on_defer_invoke_timeout(h2o_timeout_entry_t *entry)
{
    h2o_mruby_generator_t *generator = H2O_STRUCT_FROM_MEMBER(h2o_mruby_generator_t, defer_invoke.timeout_entry, entry);

    h2o_req_t *req = generator->req;
    h2o_mruby_context_t *ctx = generator->ctx;
    mrb_state *mrb = ctx->shared->mrb;
    mrb_value receiver = generator->defer_invoke.receiver;
    mrb_value args = generator->defer_invoke.args;
    mrb_value reprocess = mrb_ary_entry(args, 2);
    generator->defer_invoke.receiver = mrb_nil_value();
    generator->defer_invoke.args = mrb_nil_value();
    mrb_gc_unregister(mrb, receiver);
    mrb_gc_unregister(mrb, args);

    struct st_mruby_output_prefilter_t *prefilter = (struct st_mruby_output_prefilter_t *)generator->output_filter.prefilter;

    if (prefilter == NULL) {
        prefilter = (void *)h2o_add_prefilter(req, sizeof(*prefilter));
        prefilter->super.on_setup_ostream = on_prefilter_setup_stream;
        prefilter->ctx = ctx;
        prefilter->generator = generator;
        prefilter->receiver = mrb_nil_value();
        prefilter->defer_resume.timeout_entry = (h2o_timeout_entry_t){0};
        prefilter->defer_resume.resp = mrb_nil_value();
        generator->output_filter.prefilter = &prefilter->super;

    } else {
        /* cancel former call */
        assert(mrb_nil_p(prefilter->receiver));
        assert(generator->output_filter.ostream != NULL);

        /* clear ostream */
        struct st_mruby_output_ostream_t *ostream = (struct st_mruby_output_ostream_t *)generator->output_filter.ostream;
        assert(ostream != NULL);
        assert(&ostream->super == req->_ostr_top);
        if (! mrb_nil_p(ostream->ref)) {
            /* mark canceled to raise error when body.join is called since now */
            mrb_iv_set(mrb, ostream->ref, mrb_intern_lit(mrb, "@canceled"), mrb_true_value());
            ostream->ref = mrb_nil_value();
        }
        if (! mrb_nil_p(ostream->receiver)) {
            mrb_gc_unregister(mrb, ostream->receiver);
            ostream->receiver = mrb_nil_value();
        }
        generator->output_filter.ostream = NULL;
        req->_ostr_top = req->_ostr_top->next;

        /* clear timeouts */
        if (h2o_timeout_is_linked(&generator->output_filter.defer_proceed_timeout_entry))
            h2o_timeout_unlink(&generator->output_filter.defer_proceed_timeout_entry);
        assert(! h2o_timeout_is_linked(&generator->output_filter.defer_close_timeout_entry));

        /* clear prev */
        h2o_generator_t *prev = generator->output_filter.prev;
        if (prev != NULL) {
            if (prev->stop != NULL)
                prev->stop(prev, req);
            generator->output_filter.prev = NULL;
        }

        /* clear req->_generator (it'll be set again in h2o_start_response and on_prefilter_setup_ostream */
        if (req->_generator != NULL) {
            assert(req->_generator == &generator->super);
            req->_generator = NULL;
        }
    }
    prefilter->receiver = receiver;
    mrb_gc_register(mrb, receiver);

    if (mrb_bool(reprocess)) {
        h2o_reprocess_request(req, req->method, req->scheme, req->authority, req->path, req->overrides, 0);
    } else {
        h2o_delegate_request(req, &generator->ctx->handler->super);
    }

}

static mrb_value invoke_app_callback(h2o_mruby_context_t *ctx, mrb_value receiver, mrb_value args, int *run_again)
{
    mrb_value genref = mrb_ary_entry(args, 1);
    mrb_state *mrb = ctx->shared->mrb;
    h2o_mruby_generator_t *generator = h2o_mruby_get_generator(mrb, genref);

    if (generator == NULL) {
        *run_again = 1;
        return mrb_exc_new_str_lit(mrb, E_RUNTIME_ERROR, "downstream HTTP closed");
    }
    assert(generator->req != NULL);
    h2o_req_t *req = generator->req;

    mrb_value env = mrb_ary_entry(args, 0);
    if (! mrb_hash_p(env)) {
        *run_again = 1;
        return mrb_exc_new_str_lit(mrb, E_ARGUMENT_ERROR, "env must be a hash");
    }

    mrb_value reprocess = mrb_ary_entry(args, 2);
    mrb_value exc = setup_req_for_env(ctx, req, env, mrb_bool(reprocess));
    if (! mrb_nil_p(exc)) {
        *run_again = 1;
        return exc;
    }

    generator->defer_invoke.timeout_entry.cb = on_defer_invoke_timeout;
    generator->defer_invoke.receiver = receiver;
    generator->defer_invoke.args = args;
    h2o_timeout_link(req->conn->ctx->loop, &req->conn->ctx->zero_timeout, &generator->defer_invoke.timeout_entry);
    mrb_gc_register(mrb, receiver);
    mrb_gc_register(mrb, args);

    return mrb_nil_value();
}

static mrb_value output_filter_wait_chunk_callback(h2o_mruby_context_t *mctx, mrb_value receiver, mrb_value args, int *run_again)
{
    mrb_state *mrb = mctx->shared->mrb;
    struct st_mruby_output_ostream_t *ostream;

    if ((ostream = mrb_data_check_get_ptr(mrb, mrb_ary_entry(args, 0), &output_filter_stream_type)) == NULL) {
        return mrb_exc_new_str_lit(mrb, E_ARGUMENT_ERROR, "OutputFilterStream#each wrong self");
    }

    assert(mrb_nil_p(ostream->receiver));
    ostream->receiver = receiver;
    mrb_gc_register(mrb, receiver);
    return mrb_nil_value();
}

void h2o_mruby_send(h2o_mruby_generator_t *generator, h2o_iovec_t *bufs, size_t bufcnt, h2o_send_state_t state)
{
    h2o_req_t *req = generator->req;
    if (output_filter_is_registered(generator)) {
        assert(generator->output_filter.ostream != NULL);

        if (!h2o_send_state_is_in_progress(state)) {
            assert(req->_generator != NULL);
            req->_generator = NULL; /* do the same behavior as h2o_send */

            if (generator->output_filter.prev != NULL && generator->output_filter.prev->stop != NULL) {
                /* this means that original generator haven't send final yet (see ostream_send), so we should defer close it */
                h2o_context_t *ctx = generator->ctx->shared->ctx;
                h2o_timeout_link(ctx->loop, &ctx->zero_timeout, &generator->output_filter.defer_close_timeout_entry);
            }
        }

        h2o_ostream_send_next(generator->output_filter.ostream, req, bufs, bufcnt, state);

    } else {
        h2o_send(req, bufs, bufcnt, state);
    }
}

void h2o_mruby_run_fiber(h2o_mruby_context_t *ctx, mrb_value receiver, mrb_value input, int *is_delegate)
{
    ctx->shared->current_context = ctx;

    mrb_state *mrb = ctx->shared->mrb;
    mrb_value output;
    mrb_int status;
    h2o_mruby_generator_t *generator = NULL;

    while (1) {
        /* send input to fiber */
        output = mrb_funcall_argv(mrb, receiver, ctx->shared->symbols.sym_call, 1, &input);
        if (mrb->exc != NULL)
            goto GotException;
        if (!mrb_array_p(output)) {
            mrb->exc = mrb_obj_ptr(mrb_exc_new_str_lit(mrb, E_RUNTIME_ERROR, "rack app did not return an array"));
            goto GotException;
        }
        /* fetch status */
        mrb_value v = mrb_to_int(mrb, mrb_ary_entry(output, 0));
        if (mrb->exc != NULL)
            goto GotException;
        status = mrb_fixnum(v);

        /* if no special actions were necessary, then the output is a rack response */
        if (status >= 0)
            break;

        /* take special action depending on the status code */
        if (status == H2O_MRUBY_CALLBACK_ID_EXCEPTION_RAISED) {
            mrb->exc = mrb_obj_ptr(mrb_ary_entry(output, 1));
            generator = h2o_mruby_get_generator(mrb, mrb_ary_entry(output, 2));
            goto GotException;
        } else if (status == H2O_MRUBY_CALLBACK_ID_CONFIGURING_APP) {
            mrb_value pending = mrb_ary_new_capa(mrb, 2);
            mrb_ary_set(mrb, pending, 0, receiver);
            mrb_ary_set(mrb, pending, 1, input);
            mrb_ary_push(mrb, ctx->pendings, pending);
            goto Exit;
        } else if (status == H2O_MRUBY_CALLBACK_ID_CONFIGURED_APP) {
            mrb_int i;
            mrb_int len = RARRAY_LEN(ctx->pendings);
            for (i = 0; i != len; ++i) {
                mrb_value pending = mrb_ary_entry(ctx->pendings, i);
                mrb_value resumer = mrb_ary_entry(pending, 0);
                mrb_value args = mrb_ary_entry(pending, 1);
                h2o_mruby_run_fiber(ctx, resumer, args, NULL);
            }
            ctx->pendings = mrb_nil_value();

            mrb_value exc = mrb_ary_entry(output, 1);
            if (!mrb_nil_p(exc)) {
                mrb->exc = mrb_obj_ptr(exc);
                goto GotException;
            }

            goto Exit;
        }

        receiver = mrb_ary_entry(output, 1);
        mrb_value args = mrb_ary_entry(output, 2);

        if (mrb_array_p(args)) {
            int run_again = 0;
            switch (status) {
            case H2O_MRUBY_CALLBACK_ID_SEND_CHUNKED_EOS:
                input = h2o_mruby_send_chunked_eos_callback(ctx, receiver, args, &run_again);
                break;
            case H2O_MRUBY_CALLBACK_ID_HTTP_JOIN_RESPONSE:
                input = h2o_mruby_http_join_response_callback(ctx, receiver, args, &run_again);
                break;
            case H2O_MRUBY_CALLBACK_ID_HTTP_FETCH_CHUNK:
                input = h2o_mruby_http_fetch_chunk_callback(ctx, receiver, args, &run_again);
                break;
            case H2O_MRUBY_CALLBACK_ID_INVOKE_APP:
                input = invoke_app_callback(ctx, receiver, args, &run_again);
                break;
            case H2O_MRUBY_CALLBACK_ID_OUTPUT_FILTER_WAIT_CHUNK:
                input = output_filter_wait_chunk_callback(ctx, receiver, args, &run_again);
                break;
            case H2O_MRUBY_CALLBACK_ID_SLEEP:
                input = h2o_mruby_sleep_callback(ctx, receiver, args, &run_again);
                break;
            default:
                input = mrb_exc_new_str_lit(mrb, E_RUNTIME_ERROR, "unexpected callback id sent from rack app");
                run_again = 1;
                break;
            }
            if (run_again == 0)
                goto Exit;

        } else {
            input = mrb_exc_new_str_lit(mrb, E_RUNTIME_ERROR, "callback from rack app did not receive an array arg");
        }

        mrb_gc_protect(mrb, receiver);
        mrb_gc_protect(mrb, input);
    }

    if (!(100 <= status && status <= 999)) {
        mrb->exc = mrb_obj_ptr(mrb_exc_new_str_lit(mrb, E_RUNTIME_ERROR, "status returned from rack app is out of range"));
        goto GotException;
    }

    generator = h2o_mruby_get_generator(mrb, mrb_ary_entry(output, 3));

    /* send the response (unless req is already closed) */
    if (generator == NULL)
        goto Exit;
    assert(generator->req != NULL);

    send_response(generator, status, output, is_delegate);
    goto Exit;

GotException:
    if (generator == NULL) {
        fprintf(stderr, "mruby raised: %s\n", RSTRING_PTR(mrb_inspect(mrb, mrb_obj_value(mrb->exc))));
        mrb->exc = NULL;
        goto Exit;
    } else {
        assert(generator->req != NULL);
        report_exception(generator->req, mrb);
        close_response(generator);
    }
    mrb->exc = NULL;

Exit:
    ctx->shared->current_context = NULL;
}

h2o_mruby_handler_t *h2o_mruby_register(h2o_pathconf_t *pathconf, h2o_mruby_config_vars_t *vars)
{
    h2o_mruby_handler_t *handler = (void *)h2o_create_handler(pathconf, sizeof(*handler));

    handler->super.on_context_init = on_context_init;
    handler->super.on_context_dispose = on_context_dispose;
    handler->super.dispose = on_handler_dispose;
    handler->super.on_req = on_req;
    handler->config.source = h2o_strdup(NULL, vars->source.base, vars->source.len);
    if (vars->path != NULL)
        handler->config.path = h2o_strdup(NULL, vars->path, SIZE_MAX).base;
    handler->config.lineno = vars->lineno;

    return handler;
}

mrb_value h2o_mruby_each_to_array(h2o_mruby_shared_context_t *shared_ctx, mrb_value src)
{
    return mrb_funcall_argv(shared_ctx->mrb, mrb_ary_entry(shared_ctx->constants, H2O_MRUBY_PROC_EACH_TO_ARRAY),
                            shared_ctx->symbols.sym_call, 1, &src);
}

static int iterate_headers_handle_pair(h2o_mruby_shared_context_t *shared_ctx, mrb_value name, mrb_value value,
                                       int (*cb)(h2o_mruby_shared_context_t *, h2o_iovec_t, h2o_iovec_t, void *), void *cb_data)
{
    mrb_state *mrb = shared_ctx->mrb;

    /* convert name and value to string */
    name = h2o_mruby_to_str(mrb, name);
    if (mrb->exc != NULL)
        return -1;
    value = h2o_mruby_to_str(mrb, value);
    if (mrb->exc != NULL)
        return -1;

    /* call the callback, splitting the values with '\n' */
    const char *vstart = RSTRING_PTR(value), *vend = vstart + RSTRING_LEN(value), *eol;
    while (1) {
        for (eol = vstart; eol != vend; ++eol)
            if (*eol == '\n')
                break;
        if (cb(shared_ctx, h2o_iovec_init(RSTRING_PTR(name), RSTRING_LEN(name)), h2o_iovec_init(vstart, eol - vstart), cb_data) !=
            0)
            return -1;
        if (eol == vend)
            break;
        vstart = eol + 1;
    }

    return 0;
}

int h2o_mruby_iterate_headers(h2o_mruby_shared_context_t *shared_ctx, mrb_value headers,
                              int (*cb)(h2o_mruby_shared_context_t *, h2o_iovec_t, h2o_iovec_t, void *), void *cb_data)
{
    mrb_state *mrb = shared_ctx->mrb;

    if (!(mrb_hash_p(headers) || mrb_array_p(headers))) {
        headers = h2o_mruby_each_to_array(shared_ctx, headers);
        if (mrb->exc != NULL)
            return -1;
        assert(mrb_array_p(headers));
    }

    if (mrb_hash_p(headers)) {
        mrb_value keys = mrb_hash_keys(mrb, headers);
        mrb_int i, len = RARRAY_LEN(keys);
        for (i = 0; i != len; ++i) {
            mrb_value k = mrb_ary_entry(keys, i);
            mrb_value v = mrb_hash_get(mrb, headers, k);
            if (iterate_headers_handle_pair(shared_ctx, k, v, cb, cb_data) != 0)
                return -1;
        }
    } else {
        assert(mrb_array_p(headers));
        mrb_int i, len = RARRAY_LEN(headers);
        for (i = 0; i != len; ++i) {
            mrb_value pair = mrb_ary_entry(headers, i);
            if (!mrb_array_p(pair)) {
                mrb->exc = mrb_obj_ptr(mrb_exc_new_str_lit(mrb, E_ARGUMENT_ERROR, "array element of headers MUST by an array"));
                return -1;
            }
            if (iterate_headers_handle_pair(shared_ctx, mrb_ary_entry(pair, 0), mrb_ary_entry(pair, 1), cb, cb_data) != 0)
                return -1;
        }
    }

    return 0;
}
