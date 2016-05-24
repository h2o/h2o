#include "h2o.h"
#include "h2o/configurator.h"

struct throttle_resp_config_vars_t {
    int on;
};

struct throttle_resp_configurator_t {
    h2o_configurator_t super;
    struct throttle_resp_config_vars_t *vars, _vars_stack[H2O_CONFIGURATOR_NUM_LEVELS + 1];
};

static int on_config_throttle_resp(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node) {
    struct throttle_resp_configurator_t *self = (void *)cmd->configurator;

    if ((self->vars->on = (int)h2o_configurator_get_one_of(cmd, node, "OFF,ON")) == -1)
        return -1;
    return 0;
}

static int on_config_enter(h2o_configurator_t *configurator, h2o_configurator_context_t *ctx, yoml_t *node) {
    struct throttle_resp_configurator_t *self = (void *)configurator;

    ++self->vars;
    self->vars[0] = self->vars[-1];
    return 0;
}

static int on_config_exit(h2o_configurator_t *configurator, h2o_configurator_context_t *ctx, yoml_t *node) {
    struct throttle_resp_configurator_t *self = (void *)configurator;

    if (ctx->pathconf != NULL && self->vars->on)
        h2o_throttle_resp_register(ctx->pathconf);

    --self->vars;
    return 0;
}

void h2o_throttle_resp_register_configurator(h2o_globalconf_t *conf) {
    struct throttle_resp_configurator_t *c = (void *)h2o_configurator_create(conf, sizeof(*c));

    c->super.enter = on_config_enter;
    c->super.exit = on_config_exit;
    h2o_configurator_define_command(&c->super, "throttle-response", H2O_CONFIGURATOR_FLAG_ALL_LEVELS | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR,
                                    on_config_throttle_resp);
    c->vars = c->_vars_stack;
}
