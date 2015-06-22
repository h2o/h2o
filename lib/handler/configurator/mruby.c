/*
 * Copyright (c) 2015 DeNA Co., Ltd., Kazuho Oku, Ryosuke Matsumoto
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
#include "h2o/mruby.h"

struct mruby_configurator_t {
    h2o_configurator_t super;
    h2o_mruby_config_vars_t *vars;
    h2o_mruby_config_vars_t _vars_stack[H2O_CONFIGURATOR_NUM_LEVELS + 1];
};

static int on_config_mruby_handler_path(h2o_configurator_command_t *cmd,
    h2o_configurator_context_t *ctx, yoml_t *node)
{
    struct mruby_configurator_t *self = (void *)cmd->configurator;

    if (node->data.scalar[0] == '\0') {
        self->vars->mruby_handler_path = h2o_iovec_init(NULL, 0);
    } else {
        self->vars->mruby_handler_path = h2o_strdup(NULL, node->data.scalar,
            strlen(node->data.scalar));
        h2o_mruby_register(ctx->pathconf, self->vars);
    }
    return 0;
}

static int on_config_enter(h2o_configurator_t *_self, h2o_configurator_context_t
    *ctx, yoml_t *node)
{
    struct mruby_configurator_t *self = (void *)_self;

    memcpy(self->vars + 1, self->vars, sizeof(*self->vars));
    ++self->vars;
    return 0;
}

static int on_config_exit(h2o_configurator_t *_self, h2o_configurator_context_t
    *ctx, yoml_t *node)
{
    struct mruby_configurator_t *self = (void *)_self;

    --self->vars;
    return 0;
}

void h2o_mruby_register_configurator(h2o_globalconf_t *conf)
{
    struct mruby_configurator_t *c = (void *)h2o_configurator_create(conf,
        sizeof(*c));

    c->vars = c->_vars_stack;
    c->super.enter = on_config_enter;
    c->super.exit = on_config_exit;

    /* set mruby script path */
    h2o_configurator_define_command(&c->super, "mruby.handler_path",
        H2O_CONFIGURATOR_FLAG_PATH | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR,
        on_config_mruby_handler_path);
}
