/*
 * Copyright (c) 2015 Daisuke Maki, DeNA Co., Ltd., Kazuho Oku
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
#include <inttypes.h>
#include "h2o.h"
#include "h2o/configurator.h"

struct config_t {
    int enabled;
};

struct reproxy_configurator_t {
    h2o_configurator_t super;
    struct config_t *vars, _vars_stack[H2O_CONFIGURATOR_NUM_LEVELS + 1];
};

static int on_config_reproxy(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    struct reproxy_configurator_t *self = (void *)cmd->configurator;

    ssize_t ret = h2o_configurator_get_one_of(cmd, node, "OFF,ON");
    if (ret == -1)
        return -1;
    self->vars->enabled = (int)ret;

    return 0;
}

static int on_config_reproxy_allowed_hosts(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    /* The hosts that the reproxy filter is allowed to redirect a request to. When the list is empty,
     * any host may be requested, which is what the filter did before this directive existed. */
    if (node->type != YOML_TYPE_SEQUENCE) {
        h2o_configurator_errprintf(cmd, node, "reproxy.allowed-hosts must be a sequence of host names");
        return -1;
    }
    size_t n = node->data.sequence.size;
    char **hosts = h2o_mem_alloc(sizeof(char *) * (n + 1));
    for (size_t i = 0; i < n; ++i) {
        yoml_t *item = node->data.sequence.elements[i];
        if (item->type != YOML_TYPE_SCALAR) {
            h2o_configurator_errprintf(cmd, item, "reproxy.allowed-hosts must be a sequence of host names");
            free(hosts);
            return -1;
        }
        hosts[i] = h2o_strdup(NULL, item->data.scalar, SIZE_MAX).base;
    }
    hosts[n] = NULL;
    ctx->globalconf->reproxy.allowed_hosts = hosts;
    return 0;
}

static int on_config_enter(h2o_configurator_t *_self, h2o_configurator_context_t *ctx, yoml_t *node)
{
    struct reproxy_configurator_t *self = (void *)_self;

    self->vars[1] = self->vars[0];
    ++self->vars;
    return 0;
}

static int on_config_exit(h2o_configurator_t *_self, h2o_configurator_context_t *ctx, yoml_t *node)
{
    struct reproxy_configurator_t *self = (void *)_self;

    if (ctx->pathconf != NULL && !h2o_configurator_at_extension_level(ctx) && self->vars->enabled != 0)
        h2o_reproxy_register(ctx->pathconf);

    --self->vars;
    return 0;
}

void h2o_reproxy_register_configurator(h2o_globalconf_t *conf)
{
    struct reproxy_configurator_t *c = (void *)h2o_configurator_create(conf, sizeof(*c));

    /* set default vars */
    c->vars = c->_vars_stack;

    /* setup handlers */
    c->super.enter = on_config_enter;
    c->super.exit = on_config_exit;

    /* reproxy: ON | OFF */
    h2o_configurator_define_command(&c->super, "reproxy.allowed-hosts", H2O_CONFIGURATOR_FLAG_GLOBAL,
                                    on_config_reproxy_allowed_hosts);
    h2o_configurator_define_command(&c->super, "reproxy",
                                    H2O_CONFIGURATOR_FLAG_GLOBAL | H2O_CONFIGURATOR_FLAG_HOST | H2O_CONFIGURATOR_FLAG_PATH |
                                        H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR,
                                    on_config_reproxy);
}
