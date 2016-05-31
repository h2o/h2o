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
#include "h2o.h"
#include "h2o/configurator.h"

#define DEFAULT_GZIP_QUALITY 1
#define DEFAULT_BROTLI_QUALITY 1

struct compress_configurator_t {
    h2o_configurator_t super;
    h2o_compress_args_t *vars, _vars_stack[H2O_CONFIGURATOR_NUM_LEVELS + 1];
};

static const h2o_compress_args_t all_off = {0, {-1}, {-1}}, all_on = {100, {DEFAULT_GZIP_QUALITY}, {DEFAULT_BROTLI_QUALITY}};

static int on_config_gzip(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    struct compress_configurator_t *self = (void *)cmd->configurator;
    int mode;

    if ((mode = (int)h2o_configurator_get_one_of(cmd, node, "OFF,ON")) == -1)
        return -1;

    *self->vars = all_off;
    if (mode != 0)
        self->vars->gzip.quality = DEFAULT_GZIP_QUALITY;

    return 0;
}

static int obtain_quality(yoml_t *node, int min_quality, int max_quality, int default_quality, int *slot)
{
    int tmp;
    if (node->type != YOML_TYPE_SCALAR)
        return -1;
    if (strcasecmp(node->data.scalar, "OFF") == 0) {
        *slot = -1;
        return 0;
    }
    if (strcasecmp(node->data.scalar, "ON") == 0) {
        *slot = default_quality;
        return 0;
    }
    if (sscanf(node->data.scalar, "%d", &tmp) == 1 && (min_quality <= tmp && tmp <= max_quality)) {
        *slot = tmp;
        return 0;
    }
    return -1;
}

static int on_config_compress_min_size(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    struct compress_configurator_t *self = (void *)cmd->configurator;
    return h2o_configurator_scanf(cmd, node, "%zu", &self->vars->min_size);
}

static int on_config_compress(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    struct compress_configurator_t *self = (void *)cmd->configurator;
    size_t i;

    switch (node->type) {
    case YOML_TYPE_SCALAR:
        if (strcasecmp(node->data.scalar, "OFF") == 0) {
            *self->vars = all_off;
        } else if (strcasecmp(node->data.scalar, "ON") == 0) {
            *self->vars = all_on;
        } else {
            h2o_configurator_errprintf(cmd, node, "scalar argument must be either of: `OFF`, `ON`");
            return -1;
        }
        break;
    case YOML_TYPE_SEQUENCE:
        *self->vars = all_off;
        for (i = 0; i != node->data.sequence.size; ++i) {
            yoml_t *element = node->data.sequence.elements[i];
            if (element->type == YOML_TYPE_SCALAR && strcasecmp(element->data.scalar, "gzip") == 0) {
                self->vars->gzip.quality = DEFAULT_GZIP_QUALITY;
            } else if (element->type == YOML_TYPE_SCALAR && strcasecmp(element->data.scalar, "br") == 0) {
                self->vars->brotli.quality = DEFAULT_BROTLI_QUALITY;
            } else {
                h2o_configurator_errprintf(cmd, element, "element of the sequence must be either of: `gzip`, `br`");
                return -1;
            }
        }
        break;
    case YOML_TYPE_MAPPING:
        *self->vars = all_off;
        for (i = 0; i != node->data.mapping.size; ++i) {
            yoml_t *key = node->data.mapping.elements[i].key;
            yoml_t *value = node->data.mapping.elements[i].value;
            if (key->type == YOML_TYPE_SCALAR && strcasecmp(key->data.scalar, "gzip") == 0) {
                if (obtain_quality(node, 1, 9, DEFAULT_GZIP_QUALITY, &self->vars->gzip.quality) != 0) {
                    h2o_configurator_errprintf(
                        cmd, value, "value of gzip attribute must be either of `OFF`, `ON` or an integer value between 1 and 9");
                    return -1;
                }
            } else if (key->type == YOML_TYPE_SCALAR && strcasecmp(key->data.scalar, "br") == 0) {
                if (obtain_quality(node, 0, 11, DEFAULT_BROTLI_QUALITY, &self->vars->brotli.quality) != 0) {
                    h2o_configurator_errprintf(
                        cmd, value, "value of br attribute must be either of `OFF`, `ON` or an integer between 0 and 11");
                    return -1;
                }
            } else {
                h2o_configurator_errprintf(cmd, key, "key must be either of: `gzip`, `br`");
                return -1;
            }
        }
        break;
    default:
        h2o_fatal("unexpected node type");
        break;
    }

    return 0;
}

static int on_config_enter(h2o_configurator_t *configurator, h2o_configurator_context_t *ctx, yoml_t *node)
{
    struct compress_configurator_t *self = (void *)configurator;

    ++self->vars;
    self->vars[0] = self->vars[-1];
    return 0;
}

static int on_config_exit(h2o_configurator_t *configurator, h2o_configurator_context_t *ctx, yoml_t *node)
{
    struct compress_configurator_t *self = (void *)configurator;

    if (ctx->pathconf != NULL && (self->vars->gzip.quality != -1 || self->vars->brotli.quality != -1))
        h2o_compress_register(ctx->pathconf, self->vars);

    --self->vars;
    return 0;
}

void h2o_compress_register_configurator(h2o_globalconf_t *conf)
{
    struct compress_configurator_t *c = (void *)h2o_configurator_create(conf, sizeof(*c));

    c->super.enter = on_config_enter;
    c->super.exit = on_config_exit;
    h2o_configurator_define_command(&c->super, "compress", H2O_CONFIGURATOR_FLAG_ALL_LEVELS, on_config_compress);
    h2o_configurator_define_command(&c->super, "compress-minimum-size",
                                    H2O_CONFIGURATOR_FLAG_ALL_LEVELS | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR,
                                    on_config_compress_min_size);
    h2o_configurator_define_command(&c->super, "gzip", H2O_CONFIGURATOR_FLAG_ALL_LEVELS | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR,
                                    on_config_gzip);
    c->vars = c->_vars_stack;
    c->vars->gzip.quality = -1;
    c->vars->brotli.quality = -1;
}
