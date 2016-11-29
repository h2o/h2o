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
    H2O_VECTOR(h2o_headers_command_t) * cmds, _cmd_stack[H2O_CONFIGURATOR_NUM_LEVELS + 1];
};

#define DEFINE_2ARG(fn, cmd_id)                                                                                                    \
    static int fn(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)                                  \
    {                                                                                                                              \
        struct headers_configurator_t *self = (void *)cmd->configurator;\
        return h2o_on_config_header_2arg(cmd, ctx, cmd_id, node, self->cmds);                                                                      \
    }

DEFINE_2ARG(on_config_header_add, H2O_HEADERS_CMD_ADD)
DEFINE_2ARG(on_config_header_append, H2O_HEADERS_CMD_APPEND)
DEFINE_2ARG(on_config_header_merge, H2O_HEADERS_CMD_MERGE)
DEFINE_2ARG(on_config_header_set, H2O_HEADERS_CMD_SET)
DEFINE_2ARG(on_config_header_setifempty, H2O_HEADERS_CMD_SETIFEMPTY)

#undef DEFINE_2ARG

static int on_config_header_unset(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    struct headers_configurator_t *self = (void *)cmd->configurator;
    return h2o_on_config_header_unset(cmd, ctx, node, self->cmds);
}

static int on_config_enter(h2o_configurator_t *_self, h2o_configurator_context_t *ctx, yoml_t *node)
{
    struct headers_configurator_t *self = (void *)_self;

    h2o_vector_reserve(NULL, &self->cmds[1], self->cmds[0].size);
    memcpy(self->cmds[1].entries, self->cmds[0].entries, sizeof(self->cmds->entries[0]) * self->cmds->size);
    self->cmds[1].size = self->cmds[0].size;
    ++self->cmds;
    return 0;
}

static int on_config_exit(h2o_configurator_t *_self, h2o_configurator_context_t *ctx, yoml_t *node)
{
    struct headers_configurator_t *self = (void *)_self;

    if (ctx->pathconf != NULL && self->cmds->size != 0) {
        h2o_vector_reserve(NULL, self->cmds, self->cmds->size + 1);
        self->cmds->entries[self->cmds->size] = (h2o_headers_command_t){H2O_HEADERS_CMD_NULL};
        h2o_headers_register(ctx->pathconf, self->cmds->entries);
    } else {
        free(self->cmds->entries);
    }
    memset(self->cmds, 0, sizeof(*self->cmds));

    --self->cmds;
    return 0;
}

void h2o_headers_register_configurator(h2o_globalconf_t *conf)
{
    struct headers_configurator_t *c = (void *)h2o_configurator_create(conf, sizeof(*c));

    c->super.enter = on_config_enter;
    c->super.exit = on_config_exit;
#define DEFINE_CMD(name, cb)                                                                                                       \
    h2o_configurator_define_command(&c->super, name, H2O_CONFIGURATOR_FLAG_ALL_LEVELS | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR, cb)
    DEFINE_CMD("header.add", on_config_header_add);
    DEFINE_CMD("header.append", on_config_header_append);
    DEFINE_CMD("header.merge", on_config_header_merge);
    DEFINE_CMD("header.set", on_config_header_set);
    DEFINE_CMD("header.setifempty", on_config_header_setifempty);
    DEFINE_CMD("header.unset", on_config_header_unset);
#undef DEFINE_CMD

    c->cmds = c->_cmd_stack;
}
