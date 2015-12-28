#ifndef H20_MRUBY_H
#define H20_MRUBY_H

#include "h2o.h"
#include <mruby.h>
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
    H2O_MRUBY_LIT_RACK_URL_SCHEME,
    H2O_MRUBY_LIT_RACK_MULTITHREAD,
    H2O_MRUBY_LIT_RACK_MULTIPROCESS,
    H2O_MRUBY_LIT_RACK_RUN_ONCE,
    H2O_MRUBY_LIT_RACK_HIJACK_,
    H2O_MRUBY_LIT_RACK_INPUT,
    H2O_MRUBY_LIT_RACK_ERRORS,
    H2O_MRUBY_LIT_SERVER_SOFTWARE,
    H2O_MRUBY_LIT_SERVER_SOFTWARE_VALUE,
    H2O_MRUBY_PROC_EACH_TO_ARRAY,
    H2O_MRUBY_PROC_APP_TO_FIBER,
    /* used by chunked.c */
    H2O_MRUBY_CHUNKED_PROC_EACH_TO_FIBER,
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

typedef struct st_h2o_mruby_context_t {
    h2o_mruby_handler_t *handler;
    mrb_state *mrb;
    mrb_value proc;
    mrb_value constants;
    struct {
        mrb_sym sym_call;
        mrb_sym sym_close;
    } symbols;
} h2o_mruby_context_t;

typedef struct st_h2o_mruby_chunked_t h2o_mruby_chunked_t;
typedef struct st_h2o_mruby_generator_t {
    h2o_generator_t super;
    h2o_req_t *req;/* becomes NULL once the underlying connection gets terminated */
    h2o_mruby_context_t *ctx;
    mrb_value rack_input;
    struct {
        void (*cb)(struct st_h2o_mruby_generator_t *);
        void *data;
    } async_dispose;
    h2o_mruby_chunked_t *chunked;
} h2o_mruby_generator_t;

#define H2O_MRUBY_CALLBACK_ID_EXCEPTION_RAISED -1 /* used to notify exception, does not execution to mruby code */
#define H2O_MRUBY_CALLBACK_ID_SEND_BODY_CHUNK -2
#define H2O_MRUBY_CALLBACK_ID_HTTP_REQUEST -3

enum {
    H2O_MRUBY_CALLBACK_NEXT_ACTION_STOP,
    H2O_MRUBY_CALLBACK_NEXT_ACTION_IMMEDIATE,
    H2O_MRUBY_CALLBACK_NEXT_ACTION_ASYNC
};

#define h2o_mruby_assert(mrb)                                                                                                          \
    if (mrb->exc != NULL)                                                                                                          \
    h2o_mruby__assert_failed(mrb, __FILE__, __LINE__)

/* handler/mruby.c */
void h2o_mruby__assert_failed(mrb_state *mrb, const char *file, int line);
mrb_value h2o_mruby_eval_expr(mrb_state *mrb, const char *expr);
void h2o_mruby_define_callback(mrb_state *mrb, const char *name, int id);
mrb_value h2o_mruby_compile_code(mrb_state *mrb, h2o_mruby_config_vars_t *config, char *errbuf);
h2o_mruby_handler_t *h2o_mruby_register(h2o_pathconf_t *pathconf, h2o_mruby_config_vars_t *config);
void h2o_mruby_run_fiber(h2o_mruby_generator_t *generator, mrb_value receiver, mrb_value input, int gc_arena, int *is_delegate);
mrb_value h2o_mruby_each_to_array(h2o_mruby_context_t *handler_ctx, mrb_value src);
int h2o_mruby_iterate_headers(h2o_mruby_context_t *handler_ctx, mrb_value headers,
                              int (*cb)(h2o_mruby_context_t *, h2o_iovec_t, h2o_iovec_t, void *), void *cb_data);

/* handler/mruby/chunked.c */
void h2o_mruby_send_chunked_init_context(h2o_mruby_context_t *ctx);
mrb_value h2o_mruby_send_chunked_init(h2o_mruby_generator_t *generator);
void h2o_mruby_send_chunked_dispose(h2o_mruby_generator_t *generator);
mrb_value h2o_mruby_send_chunked_callback(h2o_mruby_generator_t *generator, mrb_value receiver, mrb_value input, int *next_action);

/* handler/mruby/http_request.c */
void h2o_mruby_http_request_init_context(h2o_mruby_context_t *ctx);
mrb_value h2o_mruby_http_request_callback(h2o_mruby_generator_t *generator, mrb_value receiver, mrb_value input, int *next_action);

/* handler/configurator/mruby.c */
void h2o_mruby_register_configurator(h2o_globalconf_t *conf);

#endif
