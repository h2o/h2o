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
    h2o_mimemap_t *mimemap;
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

    h2o_file_register(ctx->pathconf, node->data.scalar, self->vars->index_files, self->vars->mimemap, self->vars->flags);
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

static int assert_is_mimetype(h2o_configurator_command_t *cmd, yoml_t *node)
{
    if (node->type != YOML_TYPE_SCALAR) {
        h2o_configurator_errprintf(cmd, node, "expected a scalar (mime-type)");
        return -1;
    }
    if (strchr(node->data.scalar, '/') == NULL) {
        h2o_configurator_errprintf(cmd, node, "the string \"%s\" does not look like a mime-type", node->data.scalar);
        return -1;
    }
    return 0;
}

static int assert_is_extension(h2o_configurator_command_t *cmd, yoml_t *node)
{
    if (node->type != YOML_TYPE_SCALAR) {
        h2o_configurator_errprintf(cmd, node, "expected a scalar (extension)");
        return -1;
    }
    if (node->data.scalar[0] != '.') {
        h2o_configurator_errprintf(cmd, node, "given extension \"%s\" does not start with a \".\"", node->data.scalar);
        return -1;
    }
    return 0;
}

static int set_mimetypes(h2o_configurator_command_t *cmd, h2o_mimemap_t *mimemap, yoml_t *node)
{
    size_t i, j;

    assert(node->type == YOML_TYPE_MAPPING);

    for (i = 0; i != node->data.mapping.size; ++i) {
        yoml_t *key = node->data.mapping.elements[i].key;
        yoml_t *value = node->data.mapping.elements[i].value;
        if (assert_is_mimetype(cmd, key) != 0)
            return -1;
        switch (value->type) {
        case YOML_TYPE_SCALAR:
            if (assert_is_extension(cmd, value) != 0)
                return -1;
            h2o_mimemap_define_mimetype(mimemap, value->data.scalar + 1, key->data.scalar);
            break;
        case YOML_TYPE_SEQUENCE:
            for (j = 0; j != value->data.sequence.size; ++j) {
                yoml_t *ext_node = value->data.sequence.elements[j];
                if (assert_is_extension(cmd, ext_node) != 0)
                    return -1;
                h2o_mimemap_define_mimetype(mimemap, ext_node->data.scalar + 1, key->data.scalar);
            }
            break;
        default:
            h2o_configurator_errprintf(cmd, value,
                                       "only scalar or sequence of scalar is permitted at the value part of the argument");
            return -1;
        }
    }

    return 0;
}

static int on_config_mime_settypes(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    struct st_h2o_file_configurator_t *self = (void *)cmd->configurator;
    h2o_mimemap_t *newmap = h2o_mimemap_create();

    h2o_mimemap_set_default_type(newmap, h2o_mimemap_get_default_type(self->vars->mimemap)->data.mimetype.base);
    if (set_mimetypes(cmd, newmap, node) != 0) {
        h2o_mem_release_shared(newmap);
        return -1;
    }

    h2o_mem_release_shared(self->vars->mimemap);
    self->vars->mimemap = newmap;
    return 0;
}

static void clone_mimemap_if_clean(struct st_h2o_file_configurator_t *self)
{
    if (self->vars->mimemap != self->vars[-1].mimemap)
        return;
    h2o_mem_release_shared(self->vars->mimemap);
    self->vars->mimemap = h2o_mimemap_clone(self->vars->mimemap);
}

static int on_config_mime_addtypes(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    struct st_h2o_file_configurator_t *self = (void *)cmd->configurator;

    clone_mimemap_if_clean(self);

    return set_mimetypes(cmd, self->vars->mimemap, node);
}

static int on_config_mime_removetypes(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    struct st_h2o_file_configurator_t *self = (void *)cmd->configurator;
    size_t i;

    clone_mimemap_if_clean(self);

    for (i = 0; i != node->data.sequence.size; ++i) {
        yoml_t *ext_node = node->data.sequence.elements[i];
        if (assert_is_extension(cmd, ext_node) != 0)
            return -1;
        h2o_mimemap_remove_type(self->vars->mimemap, ext_node->data.scalar + 1);
    }

    return 0;
}

static int on_config_mime_setdefaulttype(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    struct st_h2o_file_configurator_t *self = (void *)cmd->configurator;

    if (assert_is_mimetype(cmd, node) != 0)
        return -1;

    clone_mimemap_if_clean(self);
    h2o_mimemap_set_default_type(self->vars->mimemap, node->data.scalar);

    return 0;
}

static int on_config_custom_handler(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    static const char *ignore_commands[] = {"extension", NULL};
    struct st_h2o_file_configurator_t *self = (void *)cmd->configurator;
    h2o_pathconf_t *prev_pathconf = ctx->pathconf;
    yoml_t *ext_node;
    const char **exts;
    h2o_mimemap_type_t *type = NULL;
    int ret = -1;

    if (node->type != YOML_TYPE_MAPPING) {
        h2o_configurator_errprintf(cmd, node, "argument must be a MAPPING");
        goto Exit;
    }
    if ((ext_node = yoml_get(node, "extension")) == NULL) {
        h2o_configurator_errprintf(cmd, node, "mandatory key `extension` is missing");
        goto Exit;
    }

    clone_mimemap_if_clean(self);

    switch (ext_node->type) {
    case YOML_TYPE_SCALAR:
        if (assert_is_extension(cmd, ext_node) != 0)
            goto Exit;
        exts = alloca(2 * sizeof(*exts));
        exts[0] = ext_node->data.scalar + 1;
        exts[1] = NULL;
        break;
    case YOML_TYPE_SEQUENCE: {
        exts = alloca((ext_node->data.sequence.size + 1) * sizeof(*exts));
        size_t i;
        for (i = 0; i != ext_node->data.sequence.size; ++i) {
            yoml_t *n = ext_node->data.sequence.elements[i];
            if (assert_is_extension(cmd, n) != 0)
                goto Exit;
            exts[i] = n->data.scalar + 1;
        }
        exts[i] = NULL;
    } break;
    default:
        h2o_configurator_errprintf(cmd, ext_node,
                                   "only scalar or sequence of scalar is permitted at the value part of the argument");
        goto Exit;
    }

    type = h2o_mimemap_define_dynamic(self->vars->mimemap, exts, ctx->globalconf);
    ctx->pathconf = &type->data.dynamic.pathconf;

    if (h2o_configurator_apply_commands(ctx, node, H2O_CONFIGURATOR_FLAG_EXTENSION, ignore_commands) != 0)
        goto Exit;
    switch (type->data.dynamic.pathconf.handlers.size) {
    case 1:
        break;
    case 0:
        h2o_configurator_errprintf(cmd, node, "no handler declared for given extension");
        goto Exit;
    default:
        h2o_configurator_errprintf(cmd, node, "cannot assign more than one handler for given extension");
        goto Exit;
    }

    ret = 0;
Exit:
    ctx->pathconf = prev_pathconf;
    return ret;
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

static int on_config_send_gzip(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    struct st_h2o_file_configurator_t *self = (void *)cmd->configurator;

    switch (h2o_configurator_get_one_of(cmd, node, "OFF,ON")) {
    case 0: /* off */
        self->vars->flags &= ~H2O_FILE_FLAG_SEND_GZIP;
        break;
    case 1: /* on */
        self->vars->flags |= H2O_FILE_FLAG_SEND_GZIP;
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
    self->vars[0].mimemap = self->vars[-1].mimemap;
    self->vars[0].flags = self->vars[-1].flags;
    h2o_mem_addref_shared(self->vars[0].mimemap);
    return 0;
}

static int on_config_exit(h2o_configurator_t *_self, h2o_configurator_context_t *ctx, yoml_t *node)
{
    struct st_h2o_file_configurator_t *self = (void *)_self;
    free(self->vars->index_files);
    h2o_mem_release_shared(self->vars->mimemap);
    --self->vars;
    return 0;
}

void h2o_file_register_configurator(h2o_globalconf_t *globalconf)
{
    struct st_h2o_file_configurator_t *self = (void *)h2o_configurator_create(globalconf, sizeof(*self));

    self->super.enter = on_config_enter;
    self->super.exit = on_config_exit;
    self->vars = self->_vars_stack;
    self->vars->mimemap = h2o_mimemap_create();
    self->vars->index_files = h2o_file_default_index_files;

    h2o_configurator_define_command(&self->super, "file.dir", H2O_CONFIGURATOR_FLAG_PATH | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR |
                                                                  H2O_CONFIGURATOR_FLAG_DEFERRED,
                                    on_config_dir);
    h2o_configurator_define_command(&self->super, "file.index",
                                    (H2O_CONFIGURATOR_FLAG_ALL_LEVELS & ~H2O_CONFIGURATOR_FLAG_EXTENSION) |
                                        H2O_CONFIGURATOR_FLAG_EXPECT_SEQUENCE,
                                    on_config_index);
    h2o_configurator_define_command(&self->super, "file.mime.settypes",
                                    (H2O_CONFIGURATOR_FLAG_ALL_LEVELS & ~H2O_CONFIGURATOR_FLAG_EXTENSION) |
                                        H2O_CONFIGURATOR_FLAG_EXPECT_MAPPING,
                                    on_config_mime_settypes);
    h2o_configurator_define_command(&self->super, "file.mime.addtypes",
                                    (H2O_CONFIGURATOR_FLAG_ALL_LEVELS & ~H2O_CONFIGURATOR_FLAG_EXTENSION) |
                                        H2O_CONFIGURATOR_FLAG_EXPECT_MAPPING,
                                    on_config_mime_addtypes);
    h2o_configurator_define_command(&self->super, "file.mime.removetypes",
                                    (H2O_CONFIGURATOR_FLAG_ALL_LEVELS & ~H2O_CONFIGURATOR_FLAG_EXTENSION) |
                                        H2O_CONFIGURATOR_FLAG_EXPECT_SEQUENCE,
                                    on_config_mime_removetypes);
    h2o_configurator_define_command(&self->super, "file.mime.setdefaulttype",
                                    (H2O_CONFIGURATOR_FLAG_ALL_LEVELS & ~H2O_CONFIGURATOR_FLAG_EXTENSION) |
                                        H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR,
                                    on_config_mime_setdefaulttype);
    h2o_configurator_define_command(&self->super, "file.custom-handler",
                                    (H2O_CONFIGURATOR_FLAG_ALL_LEVELS & ~H2O_CONFIGURATOR_FLAG_EXTENSION) |
                                        H2O_CONFIGURATOR_FLAG_SEMI_DEFERRED,
                                    on_config_custom_handler);
    h2o_configurator_define_command(&self->super, "file.etag",
                                    (H2O_CONFIGURATOR_FLAG_ALL_LEVELS & ~H2O_CONFIGURATOR_FLAG_EXTENSION) |
                                        H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR,
                                    on_config_etag);
    h2o_configurator_define_command(&self->super, "file.send-gzip",
                                    (H2O_CONFIGURATOR_FLAG_ALL_LEVELS & ~H2O_CONFIGURATOR_FLAG_EXTENSION) |
                                        H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR,
                                    on_config_send_gzip);
    h2o_configurator_define_command(&self->super, "file.dirlisting",
                                    (H2O_CONFIGURATOR_FLAG_ALL_LEVELS & ~H2O_CONFIGURATOR_FLAG_EXTENSION) |
                                        H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR,
                                    on_config_dir_listing);
}
