/*
 * Copyright (c) 2015 DeNA Co., Ltd., Kazuho Oku
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
#include <string.h>
#include "h2o.h"
#include "h2o/configurator.h"

struct headers_configurator_t {
    h2o_configurator_t super;
    h2o_headers_command_t **cmds, *_cmd_stack[H2O_CONFIGURATOR_NUM_LEVELS + 1];
};

static int on_config_enter(h2o_configurator_t *_self, h2o_configurator_context_t *ctx, yoml_t *node)
{
    struct headers_configurator_t *self = (void *)_self;

    self->cmds[1] = self->cmds[0];
    if (self->cmds[1] != NULL)
        h2o_mem_addref_shared(self->cmds[1]);

    ++self->cmds;
    return 0;
}

static int on_config_exit(h2o_configurator_t *_self, h2o_configurator_context_t *ctx, yoml_t *node)
{
    struct headers_configurator_t *self = (void *)_self;

    if (ctx->pathconf != NULL && *self->cmds != NULL) {
        if (*self->cmds != NULL)
            h2o_mem_addref_shared(*self->cmds);
        h2o_headers_register(ctx->pathconf, *self->cmds);
    }

    if (*self->cmds != NULL)
        h2o_mem_release_shared(*self->cmds);
    --self->cmds;
    return 0;
}

static h2o_headers_command_t **get_headers_commands(h2o_configurator_t *_self)
{
    struct headers_configurator_t *self = (void *)_self;
    return self->cmds;
}

void h2o_headers_register_configurator(h2o_globalconf_t *conf)
{
    struct headers_configurator_t *c = (void *)h2o_configurator_create(conf, sizeof(*c));

    c->super.enter = on_config_enter;
    c->super.exit = on_config_exit;

    h2o_configurator_define_headers_commands(conf, &c->super, "header", get_headers_commands);
    c->cmds = c->_cmd_stack;
}
