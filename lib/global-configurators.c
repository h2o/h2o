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
#include <stdarg.h>
#include <stdio.h>
#include "h2o.h"

static int complete_configurators(h2o_linklist_t *configurators, void *ctx)
{
    h2o_linklist_t *node;
    for (node = configurators->next; node != configurators; node = node->next) {
        h2o_configurator_t *configurator = H2O_STRUCT_FROM_MEMBER(h2o_configurator_t, _link, node);
        if (configurator->on_complete != NULL)
            if (configurator->on_complete(configurator, ctx) != 0)
                return -1;
    }
    return 0;
}

static int complete_host_configurators(h2o_host_context_t *host_ctx, void *_host_configurators)
{
    h2o_linklist_t *host_configurators = _host_configurators;
    return complete_configurators(host_configurators, host_ctx);
}

static int for_each_host_context(h2o_context_t *context, int (*cb)(h2o_host_context_t *host_ctx, void *cb_arg), void *cb_arg)
{
    h2o_linklist_t *node;
    int ret;

    if ((ret = cb(&context->default_host_context, cb_arg)) != 0)
        return ret;
    for (node = context->virtual_host_contexts.next; node != &context->virtual_host_contexts; node = node->next) {
        h2o_host_context_t *host_ctx = H2O_STRUCT_FROM_MEMBER(h2o_host_context_t, _link, node);
        if ((ret = cb(host_ctx, cb_arg)) != 0)
            return ret;
    }

    return 0;
}

static int apply_commands(void *ctx, const char *config_file, yoml_t *config_node, h2o_context_t *global_ctx)
{
    yoml_t *key, *value;
    size_t i;

    if (config_node->type != YOML_TYPE_MAPPING) {
        h2o_context_print_config_error(NULL, config_file, config_node, "node must be a MAPPING");
        return -1;
    }

    for (i = 0; i != config_node->data.mapping.size; ++i) {
        h2o_configurator_t *configurator;
        key = config_node->data.mapping.elements[i].key;
        value = config_node->data.mapping.elements[i].value;
        if (key->type != YOML_TYPE_SCALAR) {
            h2o_context_print_config_error(NULL, config_file, key, "command must be a string");
            return -1;
        }
        if (ctx == global_ctx) {
            if ((configurator = h2o_context_get_configurator(&global_ctx->global_configurators, key->data.scalar)) != NULL) {
                if (configurator->on_cmd(configurator, ctx, config_file, value) != 0)
                    return -1;
            } else if ((configurator = h2o_context_get_configurator(&global_ctx->host_configurators, key->data.scalar)) != NULL) {
                if (configurator->on_cmd(configurator, &global_ctx->default_host_context, config_file, value) != 0)
                    return -1;
            } else {
                goto UnknownCommand;
            }
        } else {
            if ((configurator = h2o_context_get_configurator(&global_ctx->host_configurators, key->data.scalar)) == NULL)
                goto UnknownCommand;
            if (configurator->on_cmd(configurator, ctx, config_file, value) != 0)
                return -1;
        }
    }

    return 0;

UnknownCommand:
    h2o_context_print_config_error(NULL, config_file, key, "unknown command: %s", key->data.scalar);
    return -1;
}

static int on_config_files(h2o_configurator_t *configurator, void *_ctx, const char *config_file, yoml_t *config_node)
{
    h2o_host_context_t *host_ctx = _ctx;
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
        h2o_register_file_handler(host_ctx, key->data.scalar, value->data.scalar, "index.html" /* FIXME */);
    }

    return 0;
}

static int on_config_mime_types(h2o_configurator_t *configurator, void *_ctx, const char *config_file, yoml_t *config_node)
{
    h2o_host_context_t *host_ctx = _ctx;
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
        h2o_define_mimetype(&host_ctx->mimemap, key->data.scalar, value->data.scalar);
    }

    return 0;
}

static int on_config_virtual_host(h2o_configurator_t *configurator, void *_ctx, const char *config_file, yoml_t *config_node)
{
    h2o_context_t *ctx = _ctx;
    size_t i;

    if (config_node->type != YOML_TYPE_MAPPING) {
        h2o_context_print_config_error(configurator, config_file, config_node, "argument must be a mapping");
        return -1;
    }

    for (i = 0; i != config_node->data.mapping.size; ++i) {
        yoml_t *key = config_node->data.mapping.elements[i].key;
        yoml_t *value = config_node->data.mapping.elements[i].value;
        h2o_host_context_t *host_ctx;
        if (key->type != YOML_TYPE_SCALAR) {
            h2o_context_print_config_error(configurator, config_file, key, "key (representing the hostname) must be a string");
            return -1;
        }
        host_ctx = h2o_context_register_virtual_host(ctx, key->data.scalar);
        if (apply_commands(host_ctx, config_file, value, ctx) != 0)
            return -1;
    }

    return 0;
}

static int on_config_request_timeout(h2o_configurator_t *configurator, void *_ctx, const char *config_file, yoml_t *config_node)
{
    h2o_context_t *ctx = _ctx;
    unsigned timeout_in_secs;

    if (h2o_config_scanf(configurator, config_file, config_node, "%u", &timeout_in_secs) != 0)
        return -1;

    ctx->req_timeout.timeout = timeout_in_secs * 1000;
    return 0;
}

static int on_config_limit_request_body(h2o_configurator_t *configurator, void *_ctx, const char *config_file, yoml_t *config_node)
{
    h2o_context_t *ctx = _ctx;
    return h2o_config_scanf(configurator, config_file, config_node, "%zu", &ctx->max_request_entity_size);
}

static int on_config_http1_upgrade_to_http2(h2o_configurator_t *configurator, void *_ctx, const char *config_file, yoml_t *config_node)
{
    h2o_context_t *ctx = _ctx;
    ssize_t ret = h2o_config_get_one_of(configurator, config_file, config_node, "OFF,ON");
    if (ret == -1)
        return -1;
    ctx->http1_upgrade_to_http2 = (int)ret;
    return 0;
}

static int on_config_http2_max_concurrent_requests_per_connection(h2o_configurator_t *configurator, void *_ctx, const char *config_file, yoml_t *config_node)
{
    h2o_context_t *ctx = _ctx;
    return h2o_config_scanf(configurator, config_file, config_node, "%zu", &ctx->http2_max_concurrent_requests_per_connection);
}

static void setup_configurator(h2o_linklist_t *anchor, const char *cmd, int (*on_cmd)(h2o_configurator_t *, void *, const char *, yoml_t*))
{
    h2o_configurator_t *configurator = h2o_malloc(sizeof(*configurator));

    memset(configurator, 0, sizeof(*configurator));
    configurator->cmd = cmd;
    configurator->destroy = (void*)free;
    configurator->on_cmd = on_cmd;

    h2o_linklist_insert(anchor, &configurator->_link);
}

void init_core_configurators(h2o_context_t *ctx)
{
    /* check if already initialized */
    if (h2o_context_get_configurator(&ctx->host_configurators, "files") != NULL)
        return;

    setup_configurator(&ctx->host_configurators, "files", on_config_files);
    setup_configurator(&ctx->host_configurators, "mime-types", on_config_mime_types);
    setup_configurator(&ctx->global_configurators, "virtual-host", on_config_virtual_host);
    setup_configurator(&ctx->global_configurators, "request-timeout", on_config_request_timeout);
    setup_configurator(&ctx->global_configurators, "limit-request-body", on_config_limit_request_body);
    setup_configurator(&ctx->global_configurators, "http1-upgrade-to-http2", on_config_http1_upgrade_to_http2);
    setup_configurator(&ctx->global_configurators, "http2-max-concurrent-requests-per-connection", on_config_http2_max_concurrent_requests_per_connection);
}

h2o_configurator_t *h2o_context_get_configurator(h2o_linklist_t *anchor, const char *cmd)
{
    h2o_linklist_t *node;

    for (node = anchor->next; node != anchor; node = node->next) {
        h2o_configurator_t *configurator = H2O_STRUCT_FROM_MEMBER(h2o_configurator_t, _link, node);
        if (strcmp(configurator->cmd, cmd) == 0)
            return configurator;
    }

    return NULL;
}

int h2o_context_configure(h2o_context_t *context, const char *config_file, yoml_t *config_node)
{
    init_core_configurators(context);

    /* apply the configuration */
    if (apply_commands(context, config_file, config_node, context) != 0)
        return -1;

    /* call the complete callbacks */
    if (complete_configurators(&context->global_configurators, context) != 0)
        return -1;
    if (for_each_host_context(context, complete_host_configurators, &context->host_configurators) != 0)
        return -1;

    return 0;
}

void h2o_context_print_config_error(h2o_configurator_t *configurator, const char *config_file, yoml_t *config_node, const char *reason, ...)
{
    va_list args;

    fprintf(stderr, "[%s:%zu] ", config_file, config_node->line + 1);
    if (configurator != NULL)
        fprintf(stderr, "in command %s, ", configurator->cmd);
    va_start(args, reason);
    vfprintf(stderr, reason, args);
    va_end(args);
    fputc('\n', stderr);
}
