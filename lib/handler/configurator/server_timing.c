/*
 * Copyright (c) 2018 Fastly, Ichito Nagata
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

enum {
    SERVER_TIMING_MODE_OFF,
    SERVER_TIMING_MODE_ON,
    SERVER_TIMING_MODE_ENFORCE
};

struct st_server_timing_config_t {
    int mode;
};

struct server_timing_configurator_t {
    h2o_configurator_t super;
    struct st_server_timing_config_t *vars, _vars_stack[H2O_CONFIGURATOR_NUM_LEVELS + 1];
};

static int on_config_server_timing(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    struct server_timing_configurator_t *self = (void *)cmd->configurator;

    ssize_t ret = h2o_configurator_get_one_of(cmd, node, "OFF,ON,ENFORCE");
    if (ret == -1)
        return -1;
    self->vars->mode = (int)ret;

    return 0;
}

static int on_config_enter(h2o_configurator_t *_self, h2o_configurator_context_t *ctx, yoml_t *node)
{
    struct server_timing_configurator_t *self = (void *)_self;

    self->vars[1] = self->vars[0];
    ++self->vars;
    return 0;
}

static int on_config_exit(h2o_configurator_t *_self, h2o_configurator_context_t *ctx, yoml_t *node)
{
    struct server_timing_configurator_t *self = (void *)_self;

    if (ctx->pathconf != NULL && self->vars->mode != SERVER_TIMING_MODE_OFF)
        h2o_server_timing_register(ctx->pathconf, self->vars->mode == SERVER_TIMING_MODE_ENFORCE);

    --self->vars;
    return 0;
}

void h2o_server_timing_register_configurator(h2o_globalconf_t *conf)
{
    struct server_timing_configurator_t *c = (void *)h2o_configurator_create(conf, sizeof(*c));

    /* set default vars */
    c->vars = c->_vars_stack;

    /* setup handlers */
    c->super.enter = on_config_enter;
    c->super.exit = on_config_exit;

    /* server_timing: ON | OFF */
    h2o_configurator_define_command(&c->super, "server-timing", H2O_CONFIGURATOR_FLAG_ALL_LEVELS, on_config_server_timing);
}
