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
#include <stdio.h>
#include "h2o.h"

static int on_config_files(h2o_configurator_t *configurator, h2o_context_t *ctx, const char *config_file, yoml_t *config_node)
{
    size_t i;

    if (config_node->type != YOML_TYPE_MAPPING) {
        h2o_context_print_config_error(configurator, config_file, config_node, "argument must be a mapping");
        return -1;
    }

    for (i = 0; i != config_node->data.mapping.size; ++i) {
        yoml_t *key = config_node->data.mapping.elements[i].key;
        yoml_t *value = config_node->data.mapping.elements[i].value;
        if (key->type != YOML_TYPE_SCALAR) {
            h2o_context_print_config_error(configurator, config_file, key, "key (representing the virtual path) must be a string");
            return -1;
        }
        if (value->type != YOML_TYPE_SCALAR) {
            h2o_context_print_config_error(configurator, config_file, key, "value (representing the local path) must be a string");
            return -1;
        }
        h2o_register_file_handler(ctx, key->data.scalar, value->data.scalar, "index.html" /* FIXME */);
    }

    return 0;
}

static int on_config_request_timeout(h2o_configurator_t *configurator, h2o_context_t *ctx, const char *config_file, yoml_t *config_node)
{
    unsigned timeout_in_secs;

    if (config_node->type != YOML_TYPE_SCALAR
        || sscanf(config_node->data.scalar, "%u", &timeout_in_secs) != 1) {
        h2o_context_print_config_error(configurator, config_file, config_node, "argument must be a non-negative number");
        return -1;
    }

    ctx->req_timeout.timeout = timeout_in_secs * 1000;
    return 0;
}

static int on_config_mime_types(h2o_configurator_t *configurator, h2o_context_t *ctx, const char *config_file, yoml_t *config_node)
{
    size_t i;

    if (config_node->type != YOML_TYPE_MAPPING) {
        h2o_context_print_config_error(configurator, config_file, config_node, "argument must be a mapping");
        return -1;
    }

    for (i = 0; i != config_node->data.mapping.size; ++i) {
        yoml_t *key = config_node->data.mapping.elements[i].key;
        yoml_t *value = config_node->data.mapping.elements[i].value;
        if (key->type != YOML_TYPE_SCALAR) {
            h2o_context_print_config_error(configurator, config_file, key, "key (representing the extension) must be a string");
            return -1;
        }
        if (value->type != YOML_TYPE_SCALAR) {
            h2o_context_print_config_error(configurator, config_file, config_node, "value (representing the mime-type) must be a string");
            return -1;
        }
        h2o_define_mimetype(&ctx->mimemap, key->data.scalar, value->data.scalar);
    }

    return 0;
}

static void setup_global_configurator(h2o_context_t *context, const char *cmd, int (*on_cmd)(h2o_configurator_t *, h2o_context_t *, const char *, yoml_t*))
{
    h2o_configurator_t *configurator = h2o_malloc(sizeof(*configurator));

    memset(configurator, 0, sizeof(*configurator));
    configurator->cmd = cmd;
    configurator->destroy = (void*)free;
    configurator->on_cmd = on_cmd;

    h2o_linklist_insert(&context->configurators, &configurator->_link);
}

void h2o_context_init_global_configurators(h2o_context_t *context)
{
    setup_global_configurator(context, "files", on_config_files);
    setup_global_configurator(context, "request-timeout", on_config_request_timeout);
    setup_global_configurator(context, "mime-types", on_config_mime_types);
}
