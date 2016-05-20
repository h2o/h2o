#include "h2o.h"
#include "h2o/configurator.h"

struct traffic_config_vars_t {
    int on;
};

struct traffic_configurator_t {
    h2o_configurator_t super;
    struct traffic_config_vars_t *vars, _vars_stack[H2O_CONFIGURATOR_NUM_LEVELS + 1];
};

static int on_config_traffic(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node) {
    struct traffic_configurator_t *self = (void *)cmd->configurator;

    if ((self->vars->on = (int)h2o_configurator_get_one_of(cmd, node, "OFF,ON")) == -1)
        return -1;
    return 0;
}

static int on_config_enter(h2o_configurator_t *configurator, h2o_configurator_context_t *ctx, yoml_t *node) {
    struct traffic_configurator_t *self = (void *)configurator;

    ++self->vars;
    self->vars[0] = self->vars[-1];
    return 0;
}

static int on_config_exit(h2o_configurator_t *configurator, h2o_configurator_context_t *ctx, yoml_t *node) {
    struct traffic_configurator_t *self = (void *)configurator;

    if (ctx->pathconf != NULL && self->vars->on)
        h2o_traffic_register(ctx->pathconf);

    --self->vars;
    return 0;
}

void h2o_traffic_register_configurator(h2o_globalconf_t *conf) {
    struct traffic_configurator_t *c = (void *)h2o_configurator_create(conf, sizeof(*c));

    c->super.enter = on_config_enter;
    c->super.exit = on_config_exit;
    h2o_configurator_define_command(&c->super, "traffic-shaper", H2O_CONFIGURATOR_FLAG_ALL_LEVELS | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR,
                                    on_config_traffic);
    c->vars = c->_vars_stack;
}
