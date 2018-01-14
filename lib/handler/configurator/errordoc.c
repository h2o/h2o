/*
 * Copyright (c) 2015-2016 DeNA Co., Ltd., Kazuho Oku
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

struct errordoc_configurator_t {
    h2o_configurator_t super;
    h2o_mem_pool_t pool;
    H2O_VECTOR(h2o_errordoc_t) * vars, _vars_stack[H2O_CONFIGURATOR_NUM_LEVELS + 1];
};

static int scan_and_check_status(h2o_configurator_command_t *cmd, yoml_t *value, int *slot)
{
    if (value->type != YOML_TYPE_SCALAR) {
        h2o_configurator_errprintf(cmd, value, "status must be must be either of: scalar, sequence of scalar");
        return -1;
    }
    if (h2o_configurator_scanf(cmd, value, "%d", slot) != 0)
        return -1;
    if (!(400 <= *slot && *slot <= 599)) {
        h2o_configurator_errprintf(cmd, value, "status must be within range of 400 to 599");
        return -1;
    }
    return 0;
}

static int register_errordoc(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *hash)
{
    struct errordoc_configurator_t *self = (void *)cmd->configurator;
    yoml_t **url_node, **status_nodes;
    size_t i, j, num_status;

    /* extract the nodes to handle */
    if (h2o_configurator_parse_mapping(cmd, hash, "url,status", NULL, &url_node, &status_nodes) != 0)
        return -1;
    if ((*url_node)->type != YOML_TYPE_SCALAR) {
        h2o_configurator_errprintf(cmd, *url_node, "URL must be a scalar");
        return -1;
    }
    switch ((*status_nodes)->type) {
    case YOML_TYPE_SCALAR:
        num_status = 1;
        break;
    case YOML_TYPE_SEQUENCE:
        if ((*status_nodes)->data.sequence.size == 0) {
            h2o_configurator_errprintf(cmd, *status_nodes, "status cannot be an empty sequence");
            return -1;
        }
        num_status = (*status_nodes)->data.sequence.size;
        status_nodes = (*status_nodes)->data.sequence.elements;
        break;
    default:
        h2o_configurator_errprintf(cmd, *status_nodes, "status must be a 3-digit scalar or a sequence of 3-digit scalars");
        return -1;
    }

    /* convert list of status_nodes (in string) to list of 3-digit codes */
    int *status_codes = alloca(sizeof(*status_codes) * num_status);
    for (i = 0; i != num_status; ++i) {
        if (h2o_configurator_scanf(cmd, status_nodes[i], "%d", &status_codes[i]) != 0)
            return -1;
        if (!(400 <= status_codes[i] && status_codes[i] <= 599)) {
            h2o_configurator_errprintf(cmd, status_nodes[i], "status must be within range of 400 to 599");
            return -1;
        }
        /* check the scanned status hasn't already appeared */
        for (j = 0; j != i; ++j) {
            if (status_codes[j] == status_codes[i]) {
                h2o_configurator_errprintf(cmd, status_nodes[i], "status %d appears multiple times", status_codes[i]);
                return -1;
            }
        }
    }

    h2o_iovec_t url = h2o_strdup(&self->pool, (*url_node)->data.scalar, SIZE_MAX);
    for (i = 0; i != num_status; ++i) {
        /* register */
        h2o_vector_reserve(&self->pool, self->vars, self->vars->size + 1);
        h2o_errordoc_t *errordoc = self->vars->entries + self->vars->size++;
        errordoc->status = status_codes[i];
        errordoc->url = url;
    }

    return 0;
}

static int on_config_errordoc(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    switch (node->type) {
    case YOML_TYPE_SEQUENCE: {
        size_t i;
        for (i = 0; i != node->data.sequence.size; ++i) {
            yoml_t *e = node->data.sequence.elements[i];
            if (e->type != YOML_TYPE_MAPPING) {
                h2o_configurator_errprintf(cmd, e, "element must be a mapping");
                return -1;
            }
            if (register_errordoc(cmd, ctx, e) != 0)
                return -1;
        }
        return 0;
    }
    case YOML_TYPE_MAPPING:
        return register_errordoc(cmd, ctx, node);
    default:
        break;
    }

    h2o_configurator_errprintf(cmd, node, "argument must be either of: sequence, mapping");
    return -1;
}

static int on_config_enter(h2o_configurator_t *_self, h2o_configurator_context_t *ctx, yoml_t *node)
{
    struct errordoc_configurator_t *self = (void *)_self;

    if (self->vars == self->_vars_stack) {
        /* entering global level */
        h2o_mem_init_pool(&self->pool);
    }

    /* copy vars */
    memset(&self->vars[1], 0, sizeof(self->vars[1]));
    h2o_vector_reserve(&self->pool, &self->vars[1], self->vars[0].size);
    h2o_memcpy(self->vars[1].entries, self->vars[0].entries, sizeof(self->vars[0].entries[0]) * self->vars[0].size);
    self->vars[1].size = self->vars[0].size;

    ++self->vars;
    return 0;
}

static int on_config_exit(h2o_configurator_t *_self, h2o_configurator_context_t *ctx, yoml_t *node)
{
    struct errordoc_configurator_t *self = (void *)_self;

    if (ctx->pathconf != NULL && self->vars->size != 0)
        h2o_errordoc_register(ctx->pathconf, self->vars->entries, self->vars->size);

    --self->vars;
    if (self->vars == self->_vars_stack) {
        /* exitting global level */
        h2o_mem_clear_pool(&self->pool);
    }

    return 0;
}

void h2o_errordoc_register_configurator(h2o_globalconf_t *conf)
{
    struct errordoc_configurator_t *c = (void *)h2o_configurator_create(conf, sizeof(*c));

    /* set default vars */
    c->vars = c->_vars_stack;

    /* setup handlers */
    c->super.enter = on_config_enter;
    c->super.exit = on_config_exit;

    /* reproxy: ON | OFF */
    h2o_configurator_define_command(&c->super, "error-doc", H2O_CONFIGURATOR_FLAG_ALL_LEVELS, on_config_errordoc);
}
