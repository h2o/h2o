/*
 * Copyright (c) 2014 DeNA Co., Ltd.
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

struct st_h2o_file_config_vars_t {
    const char **index_files;
    int flags;
};

struct st_h2o_file_configurator_t {
    h2o_configurator_t super;
    struct st_h2o_file_config_vars_t *vars;
    struct st_h2o_file_config_vars_t _vars_stack[H2O_CONFIGURATOR_NUM_LEVELS + 1];
};

static int on_config_dir(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    struct st_h2o_file_configurator_t *self = (void *)cmd->configurator;

    h2o_file_register(ctx->pathconf, node->data.scalar, self->vars->index_files, *ctx->mimemap, self->vars->flags);
    return 0;
}

static int on_config_file(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    struct st_h2o_file_configurator_t *self = (void *)cmd->configurator;
    h2o_mimemap_type_t *mime_type =
        h2o_mimemap_get_type_by_extension(*ctx->mimemap, h2o_get_filext(node->data.scalar, strlen(node->data.scalar)));
    h2o_file_register_file(ctx->pathconf, node->data.scalar, mime_type, self->vars->flags);
    return 0;
}

static int on_config_index(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    struct st_h2o_file_configurator_t *self = (void *)cmd->configurator;
    size_t i;

    free(self->vars->index_files);
    self->vars->index_files = h2o_mem_alloc(sizeof(self->vars->index_files[0]) * (node->data.sequence.size + 1));
    for (i = 0; i != node->data.sequence.size; ++i) {
        yoml_t *element = node->data.sequence.elements[i];
        if (element->type != YOML_TYPE_SCALAR) {
            h2o_configurator_errprintf(cmd, element, "argument must be a sequence of scalars");
            return -1;
        }
        self->vars->index_files[i] = element->data.scalar;
    }
    self->vars->index_files[i] = NULL;

    return 0;
}

static int on_config_etag(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    struct st_h2o_file_configurator_t *self = (void *)cmd->configurator;

    switch (h2o_configurator_get_one_of(cmd, node, "OFF,ON")) {
    case 0: /* off */
        self->vars->flags |= H2O_FILE_FLAG_NO_ETAG;
        break;
    case 1: /* on */
        self->vars->flags &= ~H2O_FILE_FLAG_NO_ETAG;
        break;
    default: /* error */
        return -1;
    }

    return 0;
}

static int on_config_send_compressed(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    struct st_h2o_file_configurator_t *self = (void *)cmd->configurator;

    switch (h2o_configurator_get_one_of(cmd, node, "OFF,ON,gunzip")) {
    case 0: /* off */
        self->vars->flags &= ~H2O_FILE_FLAG_SEND_COMPRESSED;
        break;
    case 1: /* on */
        self->vars->flags |= H2O_FILE_FLAG_SEND_COMPRESSED;
        break;
    case 2: /* gunzip */
        self->vars->flags |= (H2O_FILE_FLAG_SEND_COMPRESSED | H2O_FILE_FLAG_GUNZIP);
        break;
    default: /* error */
        return -1;
    }

    return 0;
}

static int on_config_dir_listing(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    struct st_h2o_file_configurator_t *self = (void *)cmd->configurator;

    switch (h2o_configurator_get_one_of(cmd, node, "OFF,ON")) {
    case 0: /* off */
        self->vars->flags &= ~H2O_FILE_FLAG_DIR_LISTING;
        break;
    case 1: /* on */
        self->vars->flags |= H2O_FILE_FLAG_DIR_LISTING;
        break;
    default: /* error */
        return -1;
    }

    return 0;
}

static const char **dup_strlist(const char **s)
{
    size_t i;
    const char **ret;

    for (i = 0; s[i] != NULL; ++i)
        ;
    ret = h2o_mem_alloc(sizeof(*ret) * (i + 1));
    for (i = 0; s[i] != NULL; ++i)
        ret[i] = s[i];
    ret[i] = NULL;

    return ret;
}

static int on_config_enter(h2o_configurator_t *_self, h2o_configurator_context_t *ctx, yoml_t *node)
{
    struct st_h2o_file_configurator_t *self = (void *)_self;
    ++self->vars;
    self->vars[0].index_files = dup_strlist(self->vars[-1].index_files);
    self->vars[0].flags = self->vars[-1].flags;
    return 0;
}

static int on_config_exit(h2o_configurator_t *_self, h2o_configurator_context_t *ctx, yoml_t *node)
{
    struct st_h2o_file_configurator_t *self = (void *)_self;
    free(self->vars->index_files);
    --self->vars;
    return 0;
}

void h2o_file_register_configurator(h2o_globalconf_t *globalconf)
{
    struct st_h2o_file_configurator_t *self = (void *)h2o_configurator_create(globalconf, sizeof(*self));

    self->super.enter = on_config_enter;
    self->super.exit = on_config_exit;
    self->vars = self->_vars_stack;
    self->vars->index_files = h2o_file_default_index_files;

    h2o_configurator_define_command(&self->super, "file.dir", H2O_CONFIGURATOR_FLAG_PATH | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR |
                                                                  H2O_CONFIGURATOR_FLAG_DEFERRED,
                                    on_config_dir);
    h2o_configurator_define_command(&self->super, "file.file", H2O_CONFIGURATOR_FLAG_PATH | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR |
                                                                   H2O_CONFIGURATOR_FLAG_DEFERRED,
                                    on_config_file);
    h2o_configurator_define_command(&self->super, "file.index",
                                    (H2O_CONFIGURATOR_FLAG_ALL_LEVELS & ~H2O_CONFIGURATOR_FLAG_EXTENSION) |
                                        H2O_CONFIGURATOR_FLAG_EXPECT_SEQUENCE,
                                    on_config_index);
    h2o_configurator_define_command(&self->super, "file.etag",
                                    (H2O_CONFIGURATOR_FLAG_ALL_LEVELS & ~H2O_CONFIGURATOR_FLAG_EXTENSION) |
                                        H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR,
                                    on_config_etag);
    h2o_configurator_define_command(&self->super, "file.send-compressed",
                                    (H2O_CONFIGURATOR_FLAG_ALL_LEVELS & ~H2O_CONFIGURATOR_FLAG_EXTENSION) |
                                        H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR,
                                    on_config_send_compressed);
    h2o_configurator_define_command(&self->super, "file.send-gzip",
                                    (H2O_CONFIGURATOR_FLAG_ALL_LEVELS & ~H2O_CONFIGURATOR_FLAG_EXTENSION) |
                                        H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR,
                                    on_config_send_compressed);
    h2o_configurator_define_command(&self->super, "file.dirlisting",
                                    (H2O_CONFIGURATOR_FLAG_ALL_LEVELS & ~H2O_CONFIGURATOR_FLAG_EXTENSION) |
                                        H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR,
                                    on_config_dir_listing);
}
