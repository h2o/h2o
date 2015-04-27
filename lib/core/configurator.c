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
#include <stdlib.h>
#include "h2o.h"
#include "h2o/configurator.h"

static void destroy_configurator(h2o_configurator_t *configurator)
{
    if (configurator->dispose != NULL)
        configurator->dispose(configurator);
    free(configurator->commands.entries);
    free(configurator);
}

static int setup_configurators(h2o_configurator_context_t *ctx, int is_enter, yoml_t *node)
{
    h2o_linklist_t *n;

    for (n = ctx->globalconf->configurators.next; n != &ctx->globalconf->configurators; n = n->next) {
        h2o_configurator_t *c = H2O_STRUCT_FROM_MEMBER(h2o_configurator_t, _link, n);
        if (is_enter) {
            if (c->enter != NULL && c->enter(c, ctx, node) != 0)
                return -1;
        } else {
            if (c->exit != NULL && c->exit(c, ctx, node) != 0)
                return -1;
        }
    }

    return 0;
}

static int apply_commands(h2o_configurator_context_t *ctx, int flags_mask, yoml_t *node)
{
    struct {
        h2o_configurator_command_t *cmd;
        yoml_t *value;
    } *deferred;
    size_t num_deferred = 0, i;

    if (node->type != YOML_TYPE_MAPPING) {
        h2o_configurator_errprintf(NULL, node, "node must be a MAPPING");
        return -1;
    }
    deferred = alloca(sizeof(*deferred) * node->data.mapping.size);

    /* call on_enter of every configurator */
    if (setup_configurators(ctx, 1, node) != 0)
        return -1;

    /* handle the configuration commands */
    for (i = 0; i != node->data.mapping.size; ++i) {
        yoml_t *key = node->data.mapping.elements[i].key, *value = node->data.mapping.elements[i].value;
        h2o_configurator_command_t *cmd;
        /* obtain the target command */
        if (key->type != YOML_TYPE_SCALAR) {
            h2o_configurator_errprintf(NULL, key, "command must be a string");
            return -1;
        }
        if ((cmd = h2o_configurator_get_command(ctx->globalconf, key->data.scalar)) == NULL) {
            h2o_configurator_errprintf(NULL, key, "unknown command: %s", key->data.scalar);
            return -1;
        }
        if ((cmd->flags & flags_mask) == 0) {
            h2o_configurator_errprintf(cmd, key, "the command cannot be used at this level");
            return -1;
        }
        /* check value type */
        if ((cmd->flags & (H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR | H2O_CONFIGURATOR_FLAG_EXPECT_SEQUENCE |
                           H2O_CONFIGURATOR_FLAG_EXPECT_MAPPING)) != 0) {
            switch (value->type) {
            case YOML_TYPE_SCALAR:
                if ((cmd->flags & H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR) == 0) {
                    h2o_configurator_errprintf(cmd, value, "argument cannot be a scalar");
                    return -1;
                }
                break;
            case YOML_TYPE_SEQUENCE:
                if ((cmd->flags & H2O_CONFIGURATOR_FLAG_EXPECT_SEQUENCE) == 0) {
                    h2o_configurator_errprintf(cmd, value, "argument cannot be a sequence");
                    return -1;
                }
                break;
            case YOML_TYPE_MAPPING:
                if ((cmd->flags & H2O_CONFIGURATOR_FLAG_EXPECT_MAPPING) == 0) {
                    h2o_configurator_errprintf(cmd, value, "argument cannot be a mapping");
                    return -1;
                }
                break;
            default:
                assert(!"unreachable");
                break;
            }
        }
        /* handle the command (or keep it for later execution) */
        if ((cmd->flags & H2O_CONFIGURATOR_FLAG_DEFERRED) != 0) {
            deferred[num_deferred].cmd = cmd;
            deferred[num_deferred].value = value;
            ++num_deferred;
        } else {
            if (cmd->cb(cmd, ctx, value) != 0)
                return -1;
        }
    }
    for (i = 0; i != num_deferred; ++i) {
        if (deferred[i].cmd->cb(deferred[i].cmd, ctx, deferred[i].value) != 0)
            return -1;
    }

    /* call on_enter of every configurator */
    if (setup_configurators(ctx, 0, node) != 0)
        return -1;

    return 0;
}

static int sort_from_longer_paths(const yoml_mapping_element_t *x, const yoml_mapping_element_t *y)
{
    size_t xlen = strlen(x->key->data.scalar), ylen = strlen(y->key->data.scalar);
    if (xlen < ylen)
        return 1;
    else if (xlen > ylen)
        return -1;
    /* apply strcmp for stable sort */
    return strcmp(x->key->data.scalar, y->key->data.scalar);
}

static int on_config_paths(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    size_t i;

    /* sort by the length of the path (descending) */
    for (i = 0; i != node->data.mapping.size; ++i) {
        yoml_t *key = node->data.mapping.elements[i].key;
        if (key->type != YOML_TYPE_SCALAR) {
            h2o_configurator_errprintf(cmd, key, "key (representing the virtual path) must be a string");
            return -1;
        }
    }
    qsort(node->data.mapping.elements, node->data.mapping.size, sizeof(node->data.mapping.elements[0]),
          (void *)sort_from_longer_paths);

    for (i = 0; i != node->data.mapping.size; ++i) {
        yoml_t *key = node->data.mapping.elements[i].key;
        yoml_t *value = node->data.mapping.elements[i].value;
        ctx->pathconf = h2o_config_register_path(ctx->hostconf, key->data.scalar);
        if (apply_commands(ctx, H2O_CONFIGURATOR_FLAG_PATH, value) != 0)
            return -1;
        ctx->pathconf = NULL;
    }

    return 0;
}

static int on_config_hosts(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    size_t i;

    if (node->data.mapping.size == 0) {
        h2o_configurator_errprintf(cmd, node, "the mapping cannot be empty");
        return -1;
    }

    for (i = 0; i != node->data.mapping.size; ++i) {
        yoml_t *key = node->data.mapping.elements[i].key;
        yoml_t *value = node->data.mapping.elements[i].value;
        h2o_iovec_t hostname;
        uint16_t port;
        if (key->type != YOML_TYPE_SCALAR) {
            h2o_configurator_errprintf(cmd, key, "key (representing the hostname) must be a string");
            return -1;
        }
        if (h2o_url_parse_hostport(key->data.scalar, strlen(key->data.scalar), &hostname, &port) == NULL) {
            h2o_configurator_errprintf(cmd, key, "invalid key (must be either `host` or `host:port`)");
            return -1;
        }
        ctx->hostconf = h2o_config_register_host(ctx->globalconf, hostname, port);
        if (apply_commands(ctx, H2O_CONFIGURATOR_FLAG_HOST, value) != 0)
            return -1;
        if (yoml_get(value, "paths") == NULL) {
            h2o_configurator_errprintf(NULL, value, "mandatory configuration directive `paths` is missing");
            return -1;
        }
        ctx->hostconf = NULL;
    }

    return 0;
}

static int on_config_limit_request_body(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    return h2o_configurator_scanf(cmd, node, "%zu", &ctx->globalconf->max_request_entity_size);
}

static int on_config_max_delegations(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    return h2o_configurator_scanf(cmd, node, "%u", &ctx->globalconf->max_delegations);
}

static int on_config_http1_request_timeout(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    unsigned timeout_in_secs;

    if (h2o_configurator_scanf(cmd, node, "%u", &timeout_in_secs) != 0)
        return -1;

    ctx->globalconf->http1.req_timeout = timeout_in_secs * 1000;
    return 0;
}

static int on_config_http1_upgrade_to_http2(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    ssize_t ret = h2o_configurator_get_one_of(cmd, node, "OFF,ON");
    if (ret == -1)
        return -1;
    ctx->globalconf->http1.upgrade_to_http2 = (int)ret;
    return 0;
}

static int on_config_http2_idle_timeout(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    unsigned timeout_in_secs;

    if (h2o_configurator_scanf(cmd, node, "%u", &timeout_in_secs) != 0)
        return -1;

    ctx->globalconf->http2.idle_timeout = timeout_in_secs * 1000;
    return 0;
}

static int on_config_http2_max_concurrent_requests_per_connection(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx,
                                                                  yoml_t *node)
{
    return h2o_configurator_scanf(cmd, node, "%zu", &ctx->globalconf->http2.max_concurrent_requests_per_connection);
}

void h2o_configurator__init_core(h2o_globalconf_t *conf)
{
    /* check if already initialized */
    if (h2o_configurator_get_command(conf, "files") != NULL)
        return;

    { /* `hosts` and `paths` */
        h2o_configurator_t *c = h2o_configurator_create(conf, sizeof(*c));
        h2o_configurator_define_command(c, "hosts", H2O_CONFIGURATOR_FLAG_GLOBAL | H2O_CONFIGURATOR_FLAG_EXPECT_MAPPING |
                                                        H2O_CONFIGURATOR_FLAG_DEFERRED,
                                        on_config_hosts, "map of `host[:port]` -> map of per-host configs");
        h2o_configurator_define_command(c, "paths", H2O_CONFIGURATOR_FLAG_HOST | H2O_CONFIGURATOR_FLAG_EXPECT_MAPPING |
                                                        H2O_CONFIGURATOR_FLAG_DEFERRED,
                                        on_config_paths, "map of URL-path -> configuration");
    };

    { /* setup global configurators */
        h2o_configurator_t *c = h2o_configurator_create(conf, sizeof(*c));
        h2o_configurator_define_command(c, "limit-request-body", H2O_CONFIGURATOR_FLAG_GLOBAL | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR,
                                        on_config_limit_request_body,
                                        "maximum size of request body in bytes (e.g. content of POST)\n"
                                        "(default: unlimited)");
        h2o_configurator_define_command(c, "max-delegations", H2O_CONFIGURATOR_FLAG_GLOBAL | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR,
                                        on_config_max_delegations,
                                        "limits the number of delegations (i.e. internal redirects using the\n"
                                        "`X-Reproxy-URL` header) (default: " H2O_TO_STR(H2O_DEFAULT_MAX_DELEGATIONS) ")");
        h2o_configurator_define_command(
            c, "http1-request-timeout", H2O_CONFIGURATOR_FLAG_GLOBAL | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR,
            on_config_http1_request_timeout,
            "timeout for incoming requests in seconds (default: " H2O_TO_STR(H2O_DEFAULT_HTTP1_REQ_TIMEOUT_IN_SECS) ")");
        h2o_configurator_define_command(
            c, "http1-upgrade-to-http2", H2O_CONFIGURATOR_FLAG_GLOBAL | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR,
            on_config_http1_upgrade_to_http2, "boolean flag (ON/OFF) indicating whether or not to allow upgrade to HTTP/2\n"
                                              "(default: ON)");
        h2o_configurator_define_command(
            c, "http2-idle-timeout", H2O_CONFIGURATOR_FLAG_GLOBAL | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR,
            on_config_http2_idle_timeout,
            "timeout for idle connections in seconds (default: " H2O_TO_STR(H2O_DEFAULT_HTTP2_IDLE_TIMEOUT_IN_SECS) ")");
        h2o_configurator_define_command(c, "http2-max-concurrent-requests-per-connection",
                                        H2O_CONFIGURATOR_FLAG_GLOBAL | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR,
                                        on_config_http2_max_concurrent_requests_per_connection,
                                        "max. number of requests to be handled concurrently within a single HTTP/2\n"
                                        "stream (default: 16)");
    }
}

void h2o_configurator__dispose_configurators(h2o_globalconf_t *conf)
{
    while (!h2o_linklist_is_empty(&conf->configurators)) {
        h2o_configurator_t *c = H2O_STRUCT_FROM_MEMBER(h2o_configurator_t, _link, conf->configurators.next);
        h2o_linklist_unlink(&c->_link);
        if (c->dispose != NULL)
            c->dispose(c);
        destroy_configurator(c);
    }
}

h2o_configurator_t *h2o_configurator_create(h2o_globalconf_t *conf, size_t sz)
{
    h2o_configurator_t *c;

    assert(sz >= sizeof(*c));

    c = h2o_mem_alloc(sz);
    memset(c, 0, sz);
    h2o_linklist_insert(&conf->configurators, &c->_link);

    return c;
}

void h2o_configurator_define_command(h2o_configurator_t *configurator, const char *name, int flags, h2o_configurator_command_cb cb,
                                     const char *desc)
{
    h2o_configurator_command_t *cmd;

    h2o_vector_reserve(NULL, (void *)&configurator->commands, sizeof(configurator->commands.entries[0]),
                       configurator->commands.size + 1);
    cmd = configurator->commands.entries + configurator->commands.size++;
    cmd->configurator = configurator;
    cmd->flags = flags;
    cmd->name = name;
    cmd->cb = cb;
    cmd->description = desc;
}

h2o_configurator_command_t *h2o_configurator_get_command(h2o_globalconf_t *conf, const char *name)
{
    h2o_linklist_t *node;
    size_t i;

    for (node = conf->configurators.next; node != &conf->configurators; node = node->next) {
        h2o_configurator_t *configurator = H2O_STRUCT_FROM_MEMBER(h2o_configurator_t, _link, node);
        for (i = 0; i != configurator->commands.size; ++i) {
            h2o_configurator_command_t *cmd = configurator->commands.entries + i;
            if (strcmp(cmd->name, name) == 0) {
                return cmd;
            }
        }
    }

    return NULL;
}

int h2o_configurator_apply(h2o_globalconf_t *config, yoml_t *node)
{
    h2o_configurator_context_t ctx = {config};

    if (apply_commands(&ctx, H2O_CONFIGURATOR_FLAG_GLOBAL, node) != 0)
        return -1;
    if (config->hosts[0] == NULL) {
        h2o_configurator_errprintf(NULL, node, "mandatory configuration directive `hosts` is missing");
        return -1;
    }

    return 0;
}

void h2o_configurator_errprintf(h2o_configurator_command_t *cmd, yoml_t *node, const char *reason, ...)
{
    va_list args;

    fprintf(stderr, "[%s:%zu] ", node->filename ? node->filename : "-", node->line + 1);
    if (cmd != NULL)
        fprintf(stderr, "in command %s, ", cmd->name);
    va_start(args, reason);
    vfprintf(stderr, reason, args);
    va_end(args);
    fputc('\n', stderr);
}

int h2o_configurator_scanf(h2o_configurator_command_t *cmd, yoml_t *node, const char *fmt, ...)
{
    va_list args;
    int sscan_ret;

    if (node->type != YOML_TYPE_SCALAR)
        goto Error;
    va_start(args, fmt);
    sscan_ret = vsscanf(node->data.scalar, fmt, args);
    va_end(args);
    if (sscan_ret != 1)
        goto Error;

    return 0;
Error:
    h2o_configurator_errprintf(cmd, node, "argument must match the format: %s", fmt);
    return -1;
}

ssize_t h2o_configurator_get_one_of(h2o_configurator_command_t *cmd, yoml_t *node, const char *candidates)
{
    const char *config_str, *cand_str;
    ssize_t config_str_len, cand_index;

    if (node->type != YOML_TYPE_SCALAR)
        goto Error;

    config_str = node->data.scalar;
    config_str_len = strlen(config_str);

    cand_str = candidates;
    for (cand_index = 0;; ++cand_index) {
        if (strncasecmp(cand_str, config_str, config_str_len) == 0 &&
            (cand_str[config_str_len] == '\0' || cand_str[config_str_len] == ',')) {
            /* found */
            return cand_index;
        }
        cand_str = strchr(cand_str, ',');
        if (cand_str == NULL)
            goto Error;
        cand_str += 1; /* skip ',' */
    }
/* not reached */

Error:
    h2o_configurator_errprintf(cmd, node, "argument must be one of: %s", candidates);
    return -1;
}
