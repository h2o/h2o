/*
 * Copyright (c) 2014-2016 DeNA Co., Ltd., Kazuho Oku, Ryosuke Matsumoto
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
#ifndef H20_MRUBY_H
#define H20_MRUBY_H

#include "h2o.h"
#include <mruby.h>
#include <mruby/data.h>
#include <mruby/proc.h>
#include <mruby/compile.h>

#define H2O_MRUBY_MODULE_NAME "h2o_mruby"

enum {
    H2O_MRUBY_LIT_REQUEST_METHOD = H2O_MAX_TOKENS,
    H2O_MRUBY_LIT_SCRIPT_NAME,
    H2O_MRUBY_LIT_PATH_INFO,
    H2O_MRUBY_LIT_QUERY_STRING,
    H2O_MRUBY_LIT_SERVER_NAME,
    H2O_MRUBY_LIT_SERVER_ADDR,
    H2O_MRUBY_LIT_SERVER_PORT,
    H2O_MRUBY_LIT_CONTENT_LENGTH,
    H2O_MRUBY_LIT_REMOTE_ADDR,
    H2O_MRUBY_LIT_REMOTE_PORT,
    H2O_MRUBY_LIT_REMOTE_USER,
    H2O_MRUBY_LIT_RACK_URL_SCHEME,
    H2O_MRUBY_LIT_RACK_MULTITHREAD,
    H2O_MRUBY_LIT_RACK_MULTIPROCESS,
    H2O_MRUBY_LIT_RACK_RUN_ONCE,
    H2O_MRUBY_LIT_RACK_HIJACK_,
    H2O_MRUBY_LIT_RACK_INPUT,
    H2O_MRUBY_LIT_RACK_ERRORS,
    H2O_MRUBY_LIT_SERVER_SOFTWARE,
    H2O_MRUBY_LIT_SERVER_SOFTWARE_VALUE,
    H2O_MRUBY_LIT_SEPARATOR_COMMA,
    H2O_MRUBY_LIT_SEPARATOR_SEMICOLON,
    H2O_MRUBY_PROC_EACH_TO_ARRAY,
    H2O_MRUBY_PROC_APP_TO_FIBER,

    H2O_MRUBY_GENERATOR_CLASS,

    /* used by chunked.c */
    H2O_MRUBY_CHUNKED_PROC_EACH_TO_FIBER,

    /* used by http_request.c */
    H2O_MRUBY_HTTP_REQUEST_CLASS,
    H2O_MRUBY_HTTP_INPUT_STREAM_CLASS,

    H2O_MRUBY_NUM_CONSTANTS
};

typedef struct st_h2o_mruby_config_vars_t {
    h2o_iovec_t source;
    char *path;
    int lineno;
} h2o_mruby_config_vars_t;

typedef struct st_h2o_mruby_handler_t {
    h2o_handler_t super;
    h2o_mruby_config_vars_t config;
} h2o_mruby_handler_t;

typedef struct st_h2o_mruby_shared_context_t {
    h2o_context_t *ctx;
    mrb_state *mrb;
    mrb_value constants;
    struct {
        mrb_sym sym_call;
        mrb_sym sym_close;
        mrb_sym sym_method;
        mrb_sym sym_headers;
        mrb_sym sym_body;
        mrb_sym sym_async;
    } symbols;
    mrb_value pendings;
} h2o_mruby_shared_context_t;

typedef struct st_h2o_mruby_context_t {
    h2o_mruby_handler_t *handler;
    mrb_value proc;
    h2o_mruby_shared_context_t *shared;
} h2o_mruby_context_t;

typedef struct st_h2o_mruby_chunked_t h2o_mruby_chunked_t;
typedef struct st_h2o_mruby_http_request_context_t h2o_mruby_http_request_context_t;

typedef struct st_h2o_mruby_generator_t {
    h2o_generator_t super;
    h2o_req_t *req; /* becomes NULL once the underlying connection gets terminated */
    h2o_mruby_context_t *ctx;
    mrb_value rack_input;
    h2o_mruby_chunked_t *chunked;
    struct {
        mrb_value generator;
    } refs;
} h2o_mruby_generator_t;

#define H2O_MRUBY_CALLBACK_ID_EXCEPTION_RAISED -1 /* used to notify exception, does not execution to mruby code */
#define H2O_MRUBY_CALLBACK_ID_SEND_CHUNKED_EOS -2
#define H2O_MRUBY_CALLBACK_ID_HTTP_JOIN_RESPONSE -3
#define H2O_MRUBY_CALLBACK_ID_HTTP_FETCH_CHUNK -4
#define H2O_MRUBY_CALLBACK_ID_CONFIGURING_APP -5
#define H2O_MRUBY_CALLBACK_ID_CONFIGURED_APP -6

#define h2o_mruby_assert(mrb)                                                                                                      \
    if (mrb->exc != NULL)                                                                                                          \
    h2o_mruby__assert_failed(mrb, __FILE__, __LINE__)

/* source files using this macro should include mruby/throw.h */
#define H2O_MRUBY_EXEC_GUARD(block)                                                                                                \
    do {                                                                                                                           \
        struct mrb_jmpbuf *prev_jmp = mrb->jmp;                                                                                    \
        struct mrb_jmpbuf c_jmp;                                                                                                   \
        MRB_TRY(&c_jmp)                                                                                                            \
        {                                                                                                                          \
            mrb->jmp = &c_jmp;                                                                                                     \
            do {                                                                                                                   \
                block                                                                                                              \
            } while (0);                                                                                                           \
            mrb->jmp = prev_jmp;                                                                                                   \
        }                                                                                                                          \
        MRB_CATCH(&c_jmp)                                                                                                          \
        {                                                                                                                          \
            mrb->jmp = prev_jmp;                                                                                                   \
        }                                                                                                                          \
        MRB_END_EXC(&c_jmp);                                                                                                       \
    } while (0)

/* handler/mruby.c */
void h2o_mruby__assert_failed(mrb_state *mrb, const char *file, int line);
mrb_value h2o_mruby_to_str(mrb_state *mrb, mrb_value v);
mrb_value h2o_mruby_eval_expr(mrb_state *mrb, const char *expr);
void h2o_mruby_define_callback(mrb_state *mrb, const char *name, int id);
mrb_value h2o_mruby_create_data_instance(mrb_state *mrb, mrb_value class_obj, void *ptr, const mrb_data_type *type);
void h2o_mruby_setup_globals(mrb_state *mrb);
struct RProc *h2o_mruby_compile_code(mrb_state *mrb, h2o_mruby_config_vars_t *config, char *errbuf);
h2o_mruby_handler_t *h2o_mruby_register(h2o_pathconf_t *pathconf, h2o_mruby_config_vars_t *config);

void h2o_mruby_run_fiber(h2o_mruby_shared_context_t *shared_ctx, mrb_value receiver, mrb_value input, int *is_delegate);
mrb_value h2o_mruby_each_to_array(h2o_mruby_shared_context_t *shared_ctx, mrb_value src);
int h2o_mruby_iterate_headers(h2o_mruby_shared_context_t *shared_ctx, mrb_value headers,
                              int (*cb)(h2o_mruby_shared_context_t *, h2o_iovec_t, h2o_iovec_t, void *), void *cb_data);

/* handler/mruby/chunked.c */
void h2o_mruby_send_chunked_init_context(h2o_mruby_shared_context_t *ctx);
void h2o_mruby_send_chunked_close(h2o_mruby_generator_t *generator);
mrb_value h2o_mruby_send_chunked_init(h2o_mruby_generator_t *generator, mrb_value body);
void h2o_mruby_send_chunked_dispose(h2o_mruby_generator_t *generator);

mrb_value h2o_mruby_send_chunked_eos_callback(h2o_mruby_shared_context_t *shared_ctx, mrb_value receiver, mrb_value input,
                                              int *next_action);

/* handler/mruby/http_request.c */
void h2o_mruby_http_request_init_context(h2o_mruby_shared_context_t *ctx);

mrb_value h2o_mruby_http_join_response_callback(h2o_mruby_shared_context_t *shared_ctx, mrb_value receiver, mrb_value args,
                                                int *next_action);
mrb_value h2o_mruby_http_fetch_chunk_callback(h2o_mruby_shared_context_t *shared_ctx, mrb_value receiver, mrb_value input,
                                              int *next_action);

h2o_mruby_http_request_context_t *h2o_mruby_http_set_shortcut(mrb_state *mrb, mrb_value obj, void (*cb)(h2o_mruby_generator_t *), h2o_mruby_generator_t *generator);
h2o_buffer_t **h2o_mruby_http_peek_content(h2o_mruby_http_request_context_t *ctx, int *is_final);

/* handler/configurator/mruby.c */
void h2o_mruby_register_configurator(h2o_globalconf_t *conf);

h2o_mruby_generator_t *h2o_mruby_get_generator(mrb_state *mrb, mrb_value obj);

#endif
