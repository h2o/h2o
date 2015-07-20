#ifndef H20_MRUBY_H
#define H20_MRUBY_H

#include "h2o.h"
#include <mruby.h>

#define H2O_MRUBY_MODULE_NAME "h2o_mruby"
#define H2O_MRUBY_MODULE_VERSION "0.0.1"
#define H2O_MRUBY_MODULE_DESCRIPTION H2O_MRUBY_MODULE_NAME "/" H2O_MRUBY_MODULE_VERSION

struct st_h2o_mruby_config_vars_t {
    h2o_iovec_t mruby_handler_path;
};

typedef struct st_h2o_mruby_config_vars_t h2o_mruby_config_vars_t;

struct st_h2o_mruby_handler_t {
    h2o_handler_t super;
    h2o_mruby_config_vars_t config;
};

typedef struct st_h2o_mruby_handler_t h2o_mruby_handler_t;

struct st_h2o_mruby_internal_context_t {
    h2o_req_t *req;
    int is_last;
};

typedef struct st_h2o_mruby_internal_context_t h2o_mruby_internal_context_t;

/* handler/mruby.c */
h2o_mruby_handler_t *h2o_mruby_register(h2o_pathconf_t *pathconf, h2o_mruby_config_vars_t *vars);

/* handler/configurator/mruby.c */
void h2o_mruby_register_configurator(h2o_globalconf_t *conf);

#endif
