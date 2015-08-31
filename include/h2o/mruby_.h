#ifndef H20_MRUBY_H
#define H20_MRUBY_H

#include "h2o.h"
#include <mruby.h>
#include <mruby/proc.h>
#include <mruby/compile.h>

#define H2O_MRUBY_MODULE_NAME "h2o_mruby"
#define H2O_MRUBY_MODULE_VERSION "0.0.1"
#define H2O_MRUBY_MODULE_DESCRIPTION H2O_MRUBY_MODULE_NAME "/" H2O_MRUBY_MODULE_VERSION

#define H2O_MRUBY_DEFAULT_CONTENT_TYPE "text/plain; charset=utf-8"

struct st_h2o_mruby_config_vars_t {
    h2o_iovec_t source;
    char *path;
    int lineno;
};

typedef struct st_h2o_mruby_config_vars_t h2o_mruby_config_vars_t;

struct st_h2o_mruby_handler_t {
    h2o_handler_t super;
    h2o_mruby_config_vars_t config;
};

typedef struct st_h2o_mruby_handler_t h2o_mruby_handler_t;

struct st_h2o_mruby_internal_context_t {
    h2o_req_t *req;
    enum {
        H2O_MRUBY_STATE_UNDETERMINED,
        H2O_MRUBY_STATE_FALLTHRU,
        H2O_MRUBY_STATE_RESPONSE_SENT
    } state;
};

typedef struct st_h2o_mruby_internal_context_t h2o_mruby_internal_context_t;

/* handler/mruby.c */
struct RProc *h2o_mruby_compile_code(mrb_state *mrb_state, h2o_mruby_config_vars_t *config, char *errbuf);
h2o_mruby_handler_t *h2o_mruby_register(h2o_pathconf_t *pathconf, h2o_mruby_config_vars_t *config);
void h2o_mruby_fixup_and_send(h2o_req_t *req, const char *body, size_t len);

void h2o_mrb_class_init(mrb_state *mrb);
void h2o_mrb_core_class_init(mrb_state *mrb, struct RClass *class);
void h2o_mrb_request_class_init(mrb_state *mrb, struct RClass *class);
void h2o_mrb_conn_class_init(mrb_state *mrb, struct RClass *class);

/* handler/configurator/mruby.c */
void h2o_mruby_register_configurator(h2o_globalconf_t *conf);

static mrb_value h2o_mrb_str_new(mrb_state *mrb, const h2o_iovec_t *str);

inline mrb_value h2o_mrb_str_new(mrb_state *mrb, const h2o_iovec_t *str)
{
    return mrb_str_new(mrb, str->base, str->len);
}
#endif
