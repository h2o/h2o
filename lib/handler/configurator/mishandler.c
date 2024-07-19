#include "h2o.h"
#include "h2o/configurator.h"

static int on_config(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    h2o_mishandler_register(ctx->pathconf);
    return 0;
}

void h2o_mishandler_register_configurator(h2o_globalconf_t *globalconf)
{
    h2o_configurator_t *self = h2o_configurator_create(globalconf, sizeof(*self));
    h2o_configurator_define_command(self, "mishandler", H2O_CONFIGURATOR_FLAG_PATH | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR,
                                    on_config);
}
