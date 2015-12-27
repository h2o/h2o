#ifndef H20_MRUBY_H
#define H20_MRUBY_H

#include "h2o.h"
#include <mruby.h>
#include <mruby/proc.h>
#include <mruby/compile.h>

#define H2O_MRUBY_MODULE_NAME "h2o_mruby"

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

typedef struct st_h2o_mruby_generator_t {
    h2o_generator_t super;
    h2o_req_t *req;
    h2o_mruby_context_t *ctx;
    mrb_value rack_input;
    mrb_value receiver;
} h2o_mruby_generator_t;

#define H2O_MRUBY_CALLBACK_ID_EXCEPTION_RAISED -1 /* used to notify exception, does not execution to mruby code */
#define H2O_MRUBY_CALLBACK_ID_HTTP_REQUEST -2

/* handler/mruby.c */
mrb_value h2o_mruby_compile_code(mrb_state *mrb_state, h2o_mruby_config_vars_t *config, char *errbuf);
h2o_mruby_handler_t *h2o_mruby_register(h2o_pathconf_t *pathconf, h2o_mruby_config_vars_t *config);
void h2o_mruby_run_fiber(h2o_mruby_generator_t *generator, mrb_value input, int gc_arena, int *is_delegate);
mrb_value h2o_mruby_each_to_array(h2o_mruby_context_t *handler_ctx, mrb_value src);
int h2o_mruby_iterate_headers(h2o_mruby_context_t *handler_ctx, mrb_value headers,
                              int (*cb)(h2o_mruby_context_t *, h2o_iovec_t, h2o_iovec_t, void *), void *cb_data);

/* handler/mruby/http_request.c */
mrb_value h2o_mruby_http_request_callback(h2o_mruby_generator_t *generator, mrb_value input);

/* handler/configurator/mruby.c */
void h2o_mruby_register_configurator(h2o_globalconf_t *conf);

#endif
