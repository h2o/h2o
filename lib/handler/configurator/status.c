/*
 * Copyright (c) 2016 DeNA Co., Ltd., Kazuho Oku
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
#include "h2o.h"
#include "h2o/configurator.h"

static int on_config_status(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    switch (h2o_configurator_get_one_of(cmd, node, "OFF,ON")) {
    case 0: /* OFF */
        return 0;
    case 1: /* ON */
        h2o_status_register(ctx->pathconf);
        return 0;
    default: /* error */
        return -1;
    }
}

struct st_status_configurator {
    h2o_configurator_t super;
    int stack;
    int duration_stats;
};

static int on_config_duration_stats(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    struct st_status_configurator *c = (void *)cmd->configurator;
    ssize_t ret;
    switch (ret = h2o_configurator_get_one_of(cmd, node, "OFF,ON")) {
    case 0: /* OFF */
    case 1: /* ON */
        c->duration_stats = (int)ret;
        return 0;
    default: /* error */
        return -1;
    }
}

int on_enter_status(h2o_configurator_t *_conf, h2o_configurator_context_t *ctx, yoml_t *node)
{
    struct st_status_configurator *c = (void *)_conf;
    c->stack++;
    return 0;
}

int on_exit_status(h2o_configurator_t *_conf, h2o_configurator_context_t *ctx, yoml_t *node)
{
    struct st_status_configurator *c = (void *)_conf;
    c->stack--;
    if (!c->stack && c->duration_stats) {
        h2o_duration_stats_register(ctx->globalconf);
    }
    return 0;
}

void h2o_status_register_configurator(h2o_globalconf_t *conf)
{
    struct st_status_configurator *c = (void *)h2o_configurator_create(conf, sizeof(*c));
    c->super.enter = on_enter_status;
    c->super.exit = on_exit_status;

    h2o_configurator_define_command(&c->super, "status", H2O_CONFIGURATOR_FLAG_PATH | H2O_CONFIGURATOR_FLAG_DEFERRED |
                                                             H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR,
                                    on_config_status);

    h2o_configurator_define_command(&c->super, "duration-stats", H2O_CONFIGURATOR_FLAG_GLOBAL | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR,
                                    on_config_duration_stats);
}
