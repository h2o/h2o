#include <inttypes.h>
#include "h2o.h"
#include "h2o/configurator.h"

struct reproxy_configurator_t {
    h2o_configurator_t super;
    h2o_reproxy_config_vars_t *vars;
    h2o_reproxy_config_vars_t _vars_stack[H2O_CONFIGURATOR_NUM_LEVELS + 1];
};

static int on_config_reproxy(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    ssize_t ret = h2o_configurator_get_one_of(cmd, node, "OFF,ON");
fprintf(stderr, "check if ret == -1\n");
    if (ret == -1)
        return -1;

fprintf(stderr, "check if ret == 0\n");
    /* Disabled, just return */
    if (ret == 0)
        return 0;
    
    /* register */
    h2o_reproxy_register(ctx->pathconf);
    return 0;
}

static int on_config_enter(h2o_configurator_t *_self, h2o_configurator_context_t *ctx, yoml_t *node)
{
    struct reproxy_configurator_t *self = (void *)_self;

    memcpy(self->vars + 1, self->vars, sizeof(*self->vars));
    ++self->vars;
    return 0;
}

static int on_config_exit(h2o_configurator_t *_self, h2o_configurator_context_t *ctx, yoml_t *node)
{
    struct reproxy_configurator_t *self = (void *)_self;

    --self->vars;
    return 0;
}

void h2o_reproxy_register_configurator(h2o_globalconf_t *conf)
{
    struct reproxy_configurator_t *c = (void *)h2o_configurator_create(conf, sizeof(*c));

    /* set default vars */
    c->vars = c->_vars_stack;
    c->vars->enabled = 0; /* TODO: How to inherit this from parent scope? */

    /* setup handlers */
    c->super.enter = on_config_enter;
    c->super.exit = on_config_exit;

    /* reproxy: ON | OFF */
    h2o_configurator_define_command(&c->super, "reproxy",
                                    H2O_CONFIGURATOR_FLAG_GLOBAL | H2O_CONFIGURATOR_FLAG_HOST | H2O_CONFIGURATOR_FLAG_PATH |
                                        H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR,
                                    on_config_reproxy, "boolean flag (ON/OFF) indicating whether or not to accept Reproxy-URL\n"
                                                       "response headers from upstream (default: OFF)");
}
