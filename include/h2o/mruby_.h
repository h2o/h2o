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
    /* [0 .. H2O_MAX_TOKENS-1] are header names */
    /* [H2O_MAX_TOKENS .. H2O_MAX_TOKENS*2-1] are header names in environment variable style (i.e, "HTTP_FOO_BAR") */
    H2O_MRUBY_LIT_REQUEST_METHOD = H2O_MAX_TOKENS * 2,
    H2O_MRUBY_LIT_SCRIPT_NAME,
    H2O_MRUBY_LIT_PATH_INFO,
    H2O_MRUBY_LIT_QUERY_STRING,
    H2O_MRUBY_LIT_SERVER_NAME,
    H2O_MRUBY_LIT_SERVER_ADDR,
    H2O_MRUBY_LIT_SERVER_PORT,
    H2O_MRUBY_LIT_SERVER_PROTOCOL,
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
    H2O_MRUBY_LIT_RACK_EARLY_HINTS,
    H2O_MRUBY_LIT_SERVER_SOFTWARE,
    H2O_MRUBY_LIT_SERVER_SOFTWARE_VALUE,
    H2O_MRUBY_LIT_H2O_REMAINING_DELEGATIONS,
    H2O_MRUBY_LIT_H2O_REMAINING_REPROCESSES,
    H2O_MRUBY_PROC_EACH_TO_ARRAY,
    H2O_MRUBY_PROC_APP_TO_FIBER,

    H2O_MRUBY_H2O_MODULE,
    H2O_MRUBY_GENERATOR_CLASS,
    H2O_MRUBY_ERROR_STREAM_CLASS,
    H2O_MRUBY_APP_REQUEST_CLASS,
    H2O_MRUBY_APP_INPUT_STREAM_CLASS,

    /* used by sender.c */
    H2O_MRUBY_SENDER_PROC_EACH_TO_FIBER,

    /* used by input_stream.c */
    H2O_MRUBY_INPUT_STREAM_CLASS,

    /* used by http_request.c */
    H2O_MRUBY_HTTP_REQUEST_CLASS,
    H2O_MRUBY_HTTP_INPUT_STREAM_CLASS,
    H2O_MRUBY_HTTP_EMPTY_INPUT_STREAM_CLASS,
    H2O_MRUBY_HTTP_REQUEST_BODY_FIBER_PROC,

    /* used by channel.c */
    H2O_MRUBY_CHANNEL_CLASS,

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
    h2o_pathconf_t *pathconf;
} h2o_mruby_handler_t;

typedef struct st_h2o_mruby_context_t h2o_mruby_context_t;
typedef mrb_value (*h2o_mruby_callback_t)(h2o_mruby_context_t *ctx, mrb_value input, mrb_value *receiver, mrb_value args,
                                          int *run_again);
typedef H2O_VECTOR(h2o_mruby_callback_t) h2o_mruby_callbacks_t;

typedef struct st_h2o_mruby_shared_context_t {
    h2o_context_t *ctx;
    mrb_state *mrb;
    mrb_value constants;
    struct st_h2o_mruby_context_t *current_context;
    struct {
        mrb_sym sym_call;
        mrb_sym sym_close;
        mrb_sym sym_method;
        mrb_sym sym_headers;
        mrb_sym sym_body;
        mrb_sym sym_async;
    } symbols;
    h2o_mruby_callbacks_t callbacks;
} h2o_mruby_shared_context_t;

struct st_h2o_mruby_context_t {
    h2o_mruby_handler_t *handler;
    mrb_value proc;
    h2o_mruby_shared_context_t *shared;
    mrb_value blocking_reqs;
    mrb_value resumers;
};

typedef struct st_h2o_mruby_sender_t h2o_mruby_sender_t;
typedef struct st_h2o_mruby_input_stream_t h2o_mruby_input_stream_t;
typedef struct st_h2o_mruby_http_request_context_t h2o_mruby_http_request_context_t;
typedef struct st_h2o_mruby_channel_context_t h2o_mruby_channel_context_t;
typedef struct st_h2o_mruby_generator_t h2o_mruby_generator_t;

typedef int (*h2o_mruby_send_response_callback_t)(h2o_mruby_generator_t *generator, mrb_int status, mrb_value resp,
                                                  int *is_delegate);

struct st_h2o_mruby_sender_t {
    /**
     * The body object being sent to the native side. Becomes nil on eos.
     */
    mrb_value body_obj;
    /**
     * Size of the body being sent. SIZE_MAX indicates that the number is undetermined (i.e. no Content-Length).
     */
    size_t bytes_left;
    /**
     * Initializes the subclass. called immediately after h2o_start_response is called
     */
    void (*start)(h2o_mruby_generator_t *generator);
    /**
     * called directly by protocol handler
     */
    void (*proceed)(h2o_generator_t *generator, h2o_req_t *req);
    /**
     * called when the generator is disposed
     */
    void (*dispose)(h2o_mruby_generator_t *generator);
    /**
     * if `h2o_send` has been closed (by passing any other flag than in-progress
     */
    unsigned char final_sent : 1;
};

struct st_h2o_mruby_input_stream_t {
    h2o_mruby_generator_t *generator;
    mrb_value ref;
    h2o_buffer_t *buf; /* for streaming mode */
    h2o_iovec_t entity; /* for non-streaming mode */
    size_t pos;
    mrb_value receiver;
    struct {
        size_t length;
        mrb_value buffer;
        mrb_value delimiter;
    } args;
    unsigned seen_eos : 1;
    unsigned rewindable : 1;
};

typedef struct st_h2o_mruby_error_stream_t {
    h2o_mruby_context_t *ctx;
    h2o_mruby_generator_t *generator;
} h2o_mruby_error_stream_t;

typedef struct st_h2o_mruby_generator_t {
    h2o_generator_t super;
    h2o_req_t *req; /* becomes NULL once the underlying connection gets terminated */
    h2o_mruby_context_t *ctx;
    h2o_mruby_input_stream_t *rack_input;
    h2o_mruby_sender_t *sender;
    h2o_mruby_error_stream_t *error_stream;
    struct {
        mrb_value generator;
        mrb_value error_stream;
    } refs;
} h2o_mruby_generator_t;

#define h2o_mruby_assert(mrb)                                                                                                      \
    do {                                                                                                                           \
        if (mrb->exc != NULL)                                                                                                      \
            h2o_mruby__abort_exc(mrb, "unexpected ruby error", __FILE__, __LINE__);                                                \
    } while (0)

#define h2o_mruby_new_str(mrb, s, l) h2o_mruby__new_str((mrb), (s), (l), 0, __FILE__, __LINE__)
#define h2o_mruby_new_str_static(mrb, s, l) h2o_mruby__new_str((mrb), (s), (l), 1, __FILE__, __LINE__)

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
void h2o_mruby__abort_exc(mrb_state *mrb, const char *mess, const char *file, int line);
mrb_value h2o_mruby__new_str(mrb_state *mrb, const char *s, size_t len, int is_static, const char *file, int line);
mrb_value h2o_mruby_to_str(mrb_state *mrb, mrb_value v);
mrb_value h2o_mruby_to_int(mrb_state *mrb, mrb_value v);
mrb_value h2o_mruby_eval_expr(mrb_state *mrb, const char *expr);
mrb_value h2o_mruby_eval_expr_location(mrb_state *mrb, const char *expr, const char *path, const int lineno);
void h2o_mruby_define_callback(mrb_state *mrb, const char *name, h2o_mruby_callback_t callback);
mrb_value h2o_mruby_create_data_instance(mrb_state *mrb, mrb_value class_obj, void *ptr, const mrb_data_type *type);
void h2o_mruby_setup_globals(mrb_state *mrb);
struct RProc *h2o_mruby_compile_code(mrb_state *mrb, h2o_mruby_config_vars_t *config, char *errbuf);
h2o_mruby_handler_t *h2o_mruby_register(h2o_pathconf_t *pathconf, h2o_mruby_config_vars_t *config);

void h2o_mruby_run_fiber(h2o_mruby_context_t *ctx, mrb_value receiver, mrb_value input, int *is_delegate);
mrb_value h2o_mruby_each_to_array(h2o_mruby_shared_context_t *shared_ctx, mrb_value src);
int h2o_mruby_iterate_rack_headers(h2o_mruby_shared_context_t *shared_ctx, mrb_value headers,
                                   int (*cb)(h2o_mruby_shared_context_t *, h2o_iovec_t *, h2o_iovec_t, void *), void *cb_data);
int h2o_mruby_iterate_header_values(h2o_mruby_shared_context_t *shared_ctx, mrb_value name, mrb_value value,
                                    int (*cb)(h2o_mruby_shared_context_t *, h2o_iovec_t *, h2o_iovec_t, void *), void *cb_data);
int h2o_mruby_iterate_native_headers(h2o_mruby_shared_context_t *shared_ctx, h2o_mem_pool_t *pool, h2o_headers_t *headers,
                                     int (*cb)(h2o_mruby_shared_context_t *, h2o_mem_pool_t *, h2o_header_t *, void *),
                                     void *cb_data);
int h2o_mruby_set_response_header(h2o_mruby_shared_context_t *shared_ctx, h2o_iovec_t *name, h2o_iovec_t value, void *req);

mrb_value h2o_mruby_token_string(h2o_mruby_shared_context_t *shared, const h2o_token_t *token);
mrb_value h2o_mruby_token_env_key(h2o_mruby_shared_context_t *shared, const h2o_token_t *token);

/* handler/mruby/sender.c */
void h2o_mruby_sender_init_context(h2o_mruby_shared_context_t *ctx);
/**
 * create and set new sender object corresponding the body argument. called only from send_response in mruby.c
 */
int h2o_mruby_init_sender(h2o_mruby_generator_t *generator, mrb_value body);
/**
 * create base sender object, called by subclasses (http_request, middleware, etc)
 */
h2o_mruby_sender_t *h2o_mruby_sender_create(h2o_mruby_generator_t *generator, mrb_value body, size_t alignment, size_t sz);
/**
 * a wrapper of h2o_send with counting and checking content-length
 */
void h2o_mruby_sender_do_send(h2o_mruby_generator_t *generator, h2o_iovec_t *bufs, size_t bufcnt, h2o_send_state_t state);
/**
 * utility function used by sender implementations that needs buffering
 */
void h2o_mruby_sender_do_send_buffer(h2o_mruby_generator_t *generator, h2o_doublebuffer_t *db, h2o_buffer_t **input, int is_final);
/**
 * close body object, called when responding is stopped or finally disposed
 */
void h2o_mruby_sender_close_body(h2o_mruby_generator_t *generator);

/* handler/mruby/input_stream.c */
void h2o_mruby_input_stream_init_context(h2o_mruby_shared_context_t *ctx);
h2o_mruby_input_stream_t *h2o_mruby_input_stream_create(h2o_mruby_generator_t *generator);
void h2o_mruby_input_stream_dispose(h2o_mruby_input_stream_t *is);

/* handler/mruby/http_request.c */
void h2o_mruby_http_request_init_context(h2o_mruby_shared_context_t *ctx);
h2o_mruby_sender_t *h2o_mruby_http_sender_create(h2o_mruby_generator_t *generator, mrb_value body);

/* handler/mruby/redis.c */
void h2o_mruby_redis_init_context(h2o_mruby_shared_context_t *ctx);

/* handler/mruby/sleep.c */
void h2o_mruby_sleep_init_context(h2o_mruby_shared_context_t *ctx);

/* handler/mruby/middleware.c */
void h2o_mruby_middleware_init_context(h2o_mruby_shared_context_t *ctx);
h2o_mruby_sender_t *h2o_mruby_middleware_sender_create(h2o_mruby_generator_t *generator, mrb_value body);
h2o_mruby_send_response_callback_t h2o_mruby_middleware_get_send_response_callback(h2o_mruby_context_t *ctx, mrb_value resp);

/* handler/mruby/channel.c */
void h2o_mruby_channel_init_context(h2o_mruby_shared_context_t *ctx);

/* handler/configurator/mruby.c */
void h2o_mruby_register_configurator(h2o_globalconf_t *conf);

h2o_mruby_generator_t *h2o_mruby_get_generator(mrb_state *mrb, mrb_value obj);
h2o_mruby_error_stream_t *h2o_mruby_get_error_stream(mrb_state *mrb, mrb_value obj);

#endif
