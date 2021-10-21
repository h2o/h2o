/*
 * Copyright (c) 2014-2016 DeNA Co., Ltd., Kazuho Oku, Fastly, Inc.
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
#include <inttypes.h>
#include "h2o.h"
#include "h2o/configurator.h"

struct st_core_config_vars_t {
    struct {
        unsigned reprioritize_blocking_assets : 1;
        unsigned push_preload : 1;
        unsigned allow_cross_origin_push : 1;
        h2o_casper_conf_t casper;
    } http2;
    struct {
        unsigned emit_request_errors : 1;
    } error_log;
};

struct st_core_configurator_t {
    h2o_configurator_t super;
    struct st_core_config_vars_t *vars, _vars_stack[H2O_CONFIGURATOR_NUM_LEVELS + 1];
};

static h2o_configurator_context_t *create_context(h2o_configurator_context_t *parent, int is_custom_handler)
{
    h2o_configurator_context_t *ctx = h2o_mem_alloc(sizeof(*ctx));
    if (parent == NULL) {
        *ctx = (h2o_configurator_context_t){NULL};
        return ctx;
    }
    *ctx = *parent;
    if (ctx->env != NULL)
        h2o_mem_addref_shared(ctx->env);
    ctx->parent = parent;
    return ctx;
}

static void destroy_context(h2o_configurator_context_t *ctx)
{
    if (ctx->env != NULL) {
        if (ctx->pathconf != NULL)
            ctx->pathconf->env = ctx->env;
        else
            h2o_mem_release_shared(ctx->env);
    }
    free(ctx);
}

static int on_core_enter(h2o_configurator_t *_self, h2o_configurator_context_t *ctx, yoml_t *node)
{
    struct st_core_configurator_t *self = (void *)_self;

    ++self->vars;
    self->vars[0] = self->vars[-1];
    return 0;
}

static int on_core_exit(h2o_configurator_t *_self, h2o_configurator_context_t *ctx, yoml_t *node)
{
    struct st_core_configurator_t *self = (void *)_self;

    if (ctx->hostconf != NULL && ctx->pathconf == NULL) {
        /* exitting from host-level configuration */
        ctx->hostconf->http2.reprioritize_blocking_assets = self->vars->http2.reprioritize_blocking_assets;
        ctx->hostconf->http2.push_preload = self->vars->http2.push_preload;
        ctx->hostconf->http2.allow_cross_origin_push = self->vars->http2.allow_cross_origin_push;
        ctx->hostconf->http2.casper = self->vars->http2.casper;
    } else if (ctx->pathconf != NULL) {
        /* exitting from path or extension-level configuration */
        ctx->pathconf->error_log.emit_request_errors = self->vars->error_log.emit_request_errors;
    }

    --self->vars;
    return 0;
}

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

static int config_timeout(h2o_configurator_command_t *cmd, yoml_t *node, uint64_t *slot)
{
    uint64_t timeout_in_secs;

    if (h2o_configurator_scanf(cmd, node, "%" SCNu64, &timeout_in_secs) != 0)
        return -1;

    *slot = timeout_in_secs * 1000;
    return 0;
}

int h2o_configurator_apply_commands(h2o_configurator_context_t *ctx, yoml_t *node, int flags_mask, const char **ignore_commands)
{
    struct st_cmd_value_t {
        h2o_configurator_command_t *cmd;
        yoml_t *value;
    };
    H2O_VECTOR(struct st_cmd_value_t) deferred = {NULL}, semi_deferred = {NULL};
    int ret = -1;

    if (node != NULL && node->type != YOML_TYPE_MAPPING) {
        h2o_configurator_errprintf(NULL, node, "node must be a MAPPING");
        goto Exit;
    }

    /* call on_enter of every configurator */
    if (setup_configurators(ctx, 1, node) != 0)
        goto Exit;

    /* handle the configuration commands */
    if (node != NULL) {
        size_t i;
        for (i = 0; i != node->data.mapping.size; ++i) {
            yoml_t *key = node->data.mapping.elements[i].key, *value = node->data.mapping.elements[i].value;
            h2o_configurator_command_t *cmd;
            /* obtain the target command */
            if (key->type != YOML_TYPE_SCALAR) {
                h2o_configurator_errprintf(NULL, key, "command must be a string");
                goto Exit;
            }
            if (ignore_commands != NULL) {
                size_t i;
                for (i = 0; ignore_commands[i] != NULL; ++i)
                    if (strcmp(ignore_commands[i], key->data.scalar) == 0)
                        goto SkipCommand;
            }
            if ((cmd = h2o_configurator_get_command(ctx->globalconf, key->data.scalar)) == NULL) {
                h2o_configurator_errprintf(NULL, key, "unknown command: %s", key->data.scalar);
                goto Exit;
            }
            if ((cmd->flags & flags_mask) == 0) {
                h2o_configurator_errprintf(cmd, key, "the command cannot be used at this level");
                goto Exit;
            }
            /* check value type */
            if ((cmd->flags & (H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR | H2O_CONFIGURATOR_FLAG_EXPECT_SEQUENCE |
                               H2O_CONFIGURATOR_FLAG_EXPECT_MAPPING)) != 0) {
                switch (value->type) {
                case YOML_TYPE_SCALAR:
                    if ((cmd->flags & H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR) == 0) {
                        h2o_configurator_errprintf(cmd, value, "argument cannot be a scalar");
                        goto Exit;
                    }
                    break;
                case YOML_TYPE_SEQUENCE:
                    if ((cmd->flags & H2O_CONFIGURATOR_FLAG_EXPECT_SEQUENCE) == 0) {
                        h2o_configurator_errprintf(cmd, value, "argument cannot be a sequence");
                        goto Exit;
                    }
                    break;
                case YOML_TYPE_MAPPING:
                    if ((cmd->flags & H2O_CONFIGURATOR_FLAG_EXPECT_MAPPING) == 0) {
                        h2o_configurator_errprintf(cmd, value, "argument cannot be a mapping");
                        goto Exit;
                    }
                    break;
                default:
                    assert(!"unreachable");
                    break;
                }
            }
            /* handle the command (or keep it for later execution) */
            if ((cmd->flags & H2O_CONFIGURATOR_FLAG_SEMI_DEFERRED) != 0) {
                h2o_vector_reserve(NULL, &semi_deferred, semi_deferred.size + 1);
                semi_deferred.entries[semi_deferred.size++] = (struct st_cmd_value_t){cmd, value};
            } else if ((cmd->flags & H2O_CONFIGURATOR_FLAG_DEFERRED) != 0) {
                h2o_vector_reserve(NULL, &deferred, deferred.size + 1);
                deferred.entries[deferred.size++] = (struct st_cmd_value_t){cmd, value};
            } else {
                if (cmd->cb(cmd, ctx, value) != 0)
                    goto Exit;
            }
        SkipCommand:;
        }
        for (i = 0; i != semi_deferred.size; ++i) {
            struct st_cmd_value_t *pair = semi_deferred.entries + i;
            if (pair->cmd->cb(pair->cmd, ctx, pair->value) != 0)
                goto Exit;
        }
        for (i = 0; i != deferred.size; ++i) {
            struct st_cmd_value_t *pair = deferred.entries + i;
            if (pair->cmd->cb(pair->cmd, ctx, pair->value) != 0)
                goto Exit;
        }
    }

    /* call on_exit of every configurator */
    if (setup_configurators(ctx, 0, node) != 0)
        goto Exit;

    ret = 0;
Exit:
    free(deferred.entries);
    free(semi_deferred.entries);
    return ret;
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

static yoml_t *convert_path_config_node(h2o_configurator_command_t *cmd, yoml_t *node)
{
    size_t i, j;

    switch (node->type) {
    case YOML_TYPE_MAPPING:
        break;
    case YOML_TYPE_SEQUENCE: {
        /* convert to mapping */
        yoml_t *map = h2o_mem_alloc(sizeof(yoml_t));
        *map = (yoml_t){YOML_TYPE_MAPPING};
        if (node->filename != NULL)
            map->filename = h2o_strdup(NULL, node->filename, SIZE_MAX).base;
        map->line = node->line;
        map->column = node->column;
        if (node->anchor != NULL)
            map->anchor = h2o_strdup(NULL, node->anchor, SIZE_MAX).base;
        map->_refcnt = 1;

        for (i = 0; i != node->data.sequence.size; ++i) {
            yoml_t *elem = node->data.sequence.elements[i];
            if (elem->type != YOML_TYPE_MAPPING) {
                yoml_free(map, NULL);
                goto Error;
            }
            for (j = 0; j != elem->data.mapping.size; ++j) {
                yoml_t *elemkey = elem->data.mapping.elements[j].key;
                yoml_t *elemvalue = elem->data.mapping.elements[j].value;
                map = h2o_mem_realloc(map, offsetof(yoml_t, data.mapping.elements) +
                                               sizeof(yoml_mapping_element_t) * (map->data.mapping.size + 1));
                map->data.mapping.elements[map->data.mapping.size].key = elemkey;
                map->data.mapping.elements[map->data.mapping.size].value = elemvalue;
                ++map->data.mapping.size;
                ++elemkey->_refcnt;
                ++elemvalue->_refcnt;
            }
        }
        return map;
    } break;
    default:
    Error:
        h2o_configurator_errprintf(cmd, node, "value must be a mapping or sequence of mapping");
        return NULL;
    }

    ++node->_refcnt;
    return node;
}

static int config_path(h2o_configurator_context_t *parent_ctx, h2o_pathconf_t *pathconf, yoml_t *node)
{
    h2o_configurator_context_t *path_ctx = create_context(parent_ctx, 0);
    path_ctx->pathconf = pathconf;
    path_ctx->mimemap = &pathconf->mimemap;

    int ret = h2o_configurator_apply_commands(path_ctx, node, H2O_CONFIGURATOR_FLAG_PATH, NULL);

    destroy_context(path_ctx);
    return ret;
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
        if (strlen(key->data.scalar) == 0) {
            h2o_configurator_errprintf(cmd, key, "key (representing the virtual path) must not be an empty string");
            return -1;
        }
    }
    qsort(node->data.mapping.elements, node->data.mapping.size, sizeof(node->data.mapping.elements[0]),
          (int (*)(const void *, const void *))sort_from_longer_paths);

    for (i = 0; i != node->data.mapping.size; ++i) {
        yoml_t *key = node->data.mapping.elements[i].key, *value;
        if ((value = convert_path_config_node(cmd, node->data.mapping.elements[i].value)) == NULL)
            return -1;
        h2o_pathconf_t *pathconf = h2o_config_register_path(ctx->hostconf, key->data.scalar, 0);
        int cmd_ret = config_path(ctx, pathconf, value);
        yoml_free(value, NULL);
        if (cmd_ret != 0)
            return cmd_ret;
    }

    /* configure fallback path along with ordinary paths */
    return config_path(ctx, &ctx->hostconf->fallback_path, NULL);
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
        assert(hostname.len != 0);
        if ((hostname.base[0] == '*' && !(hostname.len == 1 || hostname.base[1] == '.')) ||
            memchr(hostname.base + 1, '*', hostname.len - 1) != NULL) {
            h2o_configurator_errprintf(cmd, key, "wildcard (*) can only be used at the start of the hostname");
            return -1;
        }
        h2o_configurator_context_t *host_ctx = create_context(ctx, 0);
        if ((host_ctx->hostconf = h2o_config_register_host(host_ctx->globalconf, hostname, port)) == NULL) {
            h2o_configurator_errprintf(cmd, key, "duplicate host entry");
            destroy_context(host_ctx);
            return -1;
        }
        host_ctx->mimemap = &host_ctx->hostconf->mimemap;
        int cmd_ret = h2o_configurator_apply_commands(host_ctx, value, H2O_CONFIGURATOR_FLAG_HOST, NULL);
        destroy_context(host_ctx);
        if (cmd_ret != 0)
            return -1;
        if (yoml_get(value, "paths") == NULL) {
            h2o_configurator_errprintf(NULL, value, "mandatory configuration directive `paths` is missing");
            return -1;
        }
    }

    return 0;
}

static int on_config_strict_match(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    h2o_hostconf_t *hostconf = ctx->hostconf;
    ssize_t on;

    if ((on = h2o_configurator_get_one_of(cmd, node, "OFF,ON")) == -1)
        return -1;
    hostconf->strict_match = (uint8_t)on;
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

static int on_config_handshake_timeout(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    return config_timeout(cmd, node, &ctx->globalconf->handshake_timeout);
}

static int on_config_http1_request_timeout(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    return config_timeout(cmd, node, &ctx->globalconf->http1.req_timeout);
}

static int on_config_http1_request_io_timeout(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    return config_timeout(cmd, node, &ctx->globalconf->http1.req_io_timeout);
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
    return config_timeout(cmd, node, &ctx->globalconf->http2.idle_timeout);
}

static int on_config_http2_graceful_shutdown_timeout(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    return config_timeout(cmd, node, &ctx->globalconf->http2.graceful_shutdown_timeout);
}

static int on_config_http2_max_concurrent_requests_per_connection(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx,
                                                                  yoml_t *node)
{
    return h2o_configurator_scanf(cmd, node, "%zu", &ctx->globalconf->http2.max_concurrent_requests_per_connection);
}

static int on_config_http2_max_concurrent_streaming_requests_per_connection(h2o_configurator_command_t *cmd,
                                                                            h2o_configurator_context_t *ctx, yoml_t *node)
{
    return h2o_configurator_scanf(cmd, node, "%zu", &ctx->globalconf->http2.max_concurrent_streaming_requests_per_connection);
}

static int on_config_http2_input_window_size(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    uint32_t v;
    if (h2o_configurator_scanf(cmd, node, "%" SCNu32, &v) != 0)
        return -1;
    if (!(H2O_HTTP2_MIN_STREAM_WINDOW_SIZE <= v && v <= H2O_HTTP2_MAX_STREAM_WINDOW_SIZE)) {
        h2o_configurator_errprintf(cmd, node, "window size must be between %" PRIu32 " and %" PRIu32,
                                   (uint32_t)H2O_HTTP2_MIN_STREAM_WINDOW_SIZE, (uint32_t)H2O_HTTP2_MAX_STREAM_WINDOW_SIZE);
        return -1;
    }
    ctx->globalconf->http2.active_stream_window_size = v;
    return 0;
}

static int on_config_http2_latency_optimization_min_rtt(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx,
                                                        yoml_t *node)
{
    return h2o_configurator_scanf(cmd, node, "%u", &ctx->globalconf->http2.latency_optimization.min_rtt);
}

static int on_config_http2_latency_optimization_max_additional_delay(h2o_configurator_command_t *cmd,
                                                                     h2o_configurator_context_t *ctx, yoml_t *node)
{
    double ratio;
    if (h2o_configurator_scanf(cmd, node, "%lf", &ratio) != 0)
        return -1;
    if (!(0.0 < ratio)) {
        h2o_configurator_errprintf(cmd, node, "ratio must be a positive number");
        return -1;
    }
    ctx->globalconf->http2.latency_optimization.max_additional_delay = 100 * ratio;
    return 0;
}

static int on_config_http2_latency_optimization_max_cwnd(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx,
                                                         yoml_t *node)
{
    return h2o_configurator_scanf(cmd, node, "%u", &ctx->globalconf->http2.latency_optimization.max_cwnd);
}

static int on_config_http2_reprioritize_blocking_assets(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx,
                                                        yoml_t *node)
{
    struct st_core_configurator_t *self = (void *)cmd->configurator;
    ssize_t on;

    if ((on = h2o_configurator_get_one_of(cmd, node, "OFF,ON")) == -1)
        return -1;
    self->vars->http2.reprioritize_blocking_assets = (int)on;

    return 0;
}

static int on_config_http2_push_preload(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    struct st_core_configurator_t *self = (void *)cmd->configurator;
    ssize_t on;

    if ((on = h2o_configurator_get_one_of(cmd, node, "OFF,ON")) == -1)
        return -1;
    self->vars->http2.push_preload = (int)on;

    return 0;
}

static int on_config_http2_allow_cross_origin_push(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    struct st_core_configurator_t *self = (void *)cmd->configurator;
    ssize_t on;

    if ((on = h2o_configurator_get_one_of(cmd, node, "OFF,ON")) == -1)
        return -1;
    self->vars->http2.allow_cross_origin_push = (int)on;

    return 0;
}

static int on_config_http2_casper(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    static const h2o_casper_conf_t defaults = {
        13, /* casper_bits: default (2^13 ~= 100 assets * 1/0.01 collision probability) */
        0   /* track blocking assets only */
    };

    struct st_core_configurator_t *self = (void *)cmd->configurator;

    switch (node->type) {
    case YOML_TYPE_SCALAR:
        if (strcasecmp(node->data.scalar, "OFF") == 0) {
            self->vars->http2.casper = (h2o_casper_conf_t){0};
        } else if (strcasecmp(node->data.scalar, "ON") == 0) {
            self->vars->http2.casper = defaults;
        }
        break;
    case YOML_TYPE_MAPPING: {
        /* set to default */
        self->vars->http2.casper = defaults;
        /* override the attributes defined */
        yoml_t **capacity_bits, **tracking_types;
        if (h2o_configurator_parse_mapping(cmd, node, NULL, "capacity-bits:s,tracking-types:*", &capacity_bits, &tracking_types) !=
            0)
            return -1;
        if (capacity_bits != NULL) {
            if (!(sscanf((*capacity_bits)->data.scalar, "%u", &self->vars->http2.casper.capacity_bits) == 1 &&
                  self->vars->http2.casper.capacity_bits < 16)) {
                h2o_configurator_errprintf(cmd, *capacity_bits, "value of `capacity-bits` must be an integer between 0 to 15");
                return -1;
            }
        }
        if (tracking_types != NULL && (self->vars->http2.casper.track_all_types =
                                           (int)h2o_configurator_get_one_of(cmd, *tracking_types, "blocking-assets,all")) == -1)
            return -1;
    } break;
    default:
        h2o_configurator_errprintf(cmd, node, "value must be `OFF`,`ON` or a mapping containing the necessary attributes");
        return -1;
    }

    return 0;
}

static int on_config_http3_idle_timeout(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    return config_timeout(cmd, node, &ctx->globalconf->http3.idle_timeout);
}

static int on_config_http3_graceful_shutdown_timeout(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    return config_timeout(cmd, node, &ctx->globalconf->http3.graceful_shutdown_timeout);
}

static int on_config_http3_input_window_size(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    uint32_t v;
    if (h2o_configurator_scanf(cmd, node, "%" SCNu32, &v) != 0)
        return -1;
    if (v < H2O_HTTP3_INITIAL_REQUEST_STREAM_WINDOW_SIZE) {
        h2o_configurator_errprintf(cmd, node, "window size must be no less than %u",
                                   (unsigned)H2O_HTTP3_INITIAL_REQUEST_STREAM_WINDOW_SIZE);
        return -1;
    }
    ctx->globalconf->http3.active_stream_window_size = v;
    return 0;
}

static int on_config_http3_delayed_ack(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    ssize_t on;

    if ((on = h2o_configurator_get_one_of(cmd, node, "OFF,ON")) == -1)
        return -1;
    ctx->globalconf->http3.use_delayed_ack = (uint8_t)on;
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
    if (node->data.scalar[1] == '\0') {
        h2o_configurator_errprintf(cmd, node, "given extension \".\" is invalid: at least 2 characters are required");
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
            h2o_mimemap_define_mimetype(mimemap, value->data.scalar + 1, key->data.scalar, NULL);
            break;
        case YOML_TYPE_SEQUENCE:
            for (j = 0; j != value->data.sequence.size; ++j) {
                yoml_t *ext_node = value->data.sequence.elements[j];
                if (assert_is_extension(cmd, ext_node) != 0)
                    return -1;
                h2o_mimemap_define_mimetype(mimemap, ext_node->data.scalar + 1, key->data.scalar, NULL);
            }
            break;
        case YOML_TYPE_MAPPING: {
            yoml_t **is_compressible, **priority, **extensions;
            h2o_mime_attributes_t attr;
            h2o_mimemap_get_default_attributes(key->data.scalar, &attr);
            if (h2o_configurator_parse_mapping(cmd, value, "extensions:a", "is_compressible:*,priority:*", &extensions,
                                               &is_compressible, &priority) != 0)
                return -1;
            if (is_compressible != NULL) {
                switch (h2o_configurator_get_one_of(cmd, *is_compressible, "YES,NO")) {
                case 0:
                    attr.is_compressible = 1;
                    break;
                case 1:
                    attr.is_compressible = 0;
                    break;
                default:
                    return -1;
                }
            }
            if (priority != NULL) {
                switch (h2o_configurator_get_one_of(cmd, *priority, "normal,highest")) {
                case 0:
                    attr.priority = H2O_MIME_ATTRIBUTE_PRIORITY_NORMAL;
                    break;
                case 1:
                    attr.priority = H2O_MIME_ATTRIBUTE_PRIORITY_HIGHEST;
                    break;
                default:
                    return -1;
                }
            }
            for (j = 0; j != (*extensions)->data.sequence.size; ++j) {
                yoml_t *ext_node = (*extensions)->data.sequence.elements[j];
                if (assert_is_extension(cmd, ext_node) != 0)
                    return -1;
                h2o_mimemap_define_mimetype(mimemap, ext_node->data.scalar + 1, key->data.scalar, &attr);
            }
        } break;
        default:
            h2o_fatal("logic flaw");
        }
    }

    return 0;
}

static int on_config_mime_settypes(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    h2o_mimemap_t *newmap = h2o_mimemap_create();
    h2o_mimemap_clear_types(newmap);
    h2o_mimemap_set_default_type(newmap, h2o_mimemap_get_default_type(*ctx->mimemap)->data.mimetype.base, NULL);
    if (set_mimetypes(cmd, newmap, node) != 0) {
        h2o_mem_release_shared(newmap);
        return -1;
    }

    h2o_mem_release_shared(*ctx->mimemap);
    *ctx->mimemap = newmap;
    return 0;
}

static void clone_mimemap_if_clean(h2o_configurator_context_t *ctx)
{
    if (ctx->parent == NULL)
        return;
    if (*ctx->mimemap != *ctx->parent->mimemap)
        return;
    h2o_mem_release_shared(*ctx->mimemap);
    /* even after release, ctx->mimemap is still retained by the parent and therefore we can use it as the argument to clone */
    *ctx->mimemap = h2o_mimemap_clone(*ctx->mimemap);
}

static int on_config_mime_addtypes(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    clone_mimemap_if_clean(ctx);
    return set_mimetypes(cmd, *ctx->mimemap, node);
}

static int on_config_mime_removetypes(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    size_t i;

    clone_mimemap_if_clean(ctx);
    for (i = 0; i != node->data.sequence.size; ++i) {
        yoml_t *ext_node = node->data.sequence.elements[i];
        if (assert_is_extension(cmd, ext_node) != 0)
            return -1;
        h2o_mimemap_remove_type(*ctx->mimemap, ext_node->data.scalar + 1);
    }

    return 0;
}

static int on_config_mime_setdefaulttype(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    if (assert_is_mimetype(cmd, node) != 0)
        return -1;

    clone_mimemap_if_clean(ctx);
    h2o_mimemap_set_default_type(*ctx->mimemap, node->data.scalar, NULL);

    return 0;
}

static const char *normalize_ext(h2o_configurator_command_t *cmd, yoml_t *node)
{
    if (strcmp(node->data.scalar, "default") == 0) {
        /* empty string means default */
        return "";
    } else if (assert_is_extension(cmd, node) == 0) {
        return node->data.scalar + 1;
    } else {
        return NULL;
    }
}

static int on_config_custom_handler(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    static const char *ignore_commands[] = {"extension", NULL};
    yoml_t *ext_node;
    const char **exts;
    h2o_mimemap_type_t *type = NULL;

    if (node->type != YOML_TYPE_MAPPING) {
        h2o_configurator_errprintf(cmd, node, "argument must be a MAPPING");
        return -1;
    }
    if ((ext_node = yoml_get(node, "extension")) == NULL) {
        h2o_configurator_errprintf(cmd, node, "mandatory key `extension` is missing");
        return -1;
    }

    /* create dynamic type */
    switch (ext_node->type) {
    case YOML_TYPE_SCALAR:
        exts = alloca(2 * sizeof(*exts));
        if ((exts[0] = normalize_ext(cmd, ext_node)) == NULL)
            return -1;
        exts[1] = NULL;
        break;
    case YOML_TYPE_SEQUENCE: {
        exts = alloca((ext_node->data.sequence.size + 1) * sizeof(*exts));
        size_t i;
        for (i = 0; i != ext_node->data.sequence.size; ++i) {
            yoml_t *n = ext_node->data.sequence.elements[i];
            if ((exts[i] = normalize_ext(cmd, n)) == NULL)
                return -1;
        }
        exts[i] = NULL;
    } break;
    default:
        h2o_configurator_errprintf(cmd, ext_node, "`extensions` must be a scalar or sequence of scalar");
        return -1;
    }
    clone_mimemap_if_clean(ctx);
    type = h2o_mimemap_define_dynamic(*ctx->mimemap, exts, ctx->globalconf);

    /* apply the configuration commands */
    h2o_configurator_context_t *ext_ctx = create_context(ctx, 1);
    ext_ctx->pathconf = &type->data.dynamic.pathconf;
    ext_ctx->mimemap = NULL;
    int cmd_ret = h2o_configurator_apply_commands(ext_ctx, node, H2O_CONFIGURATOR_FLAG_EXTENSION, ignore_commands);
    destroy_context(ext_ctx);
    if (cmd_ret != 0)
        return cmd_ret;
    switch (type->data.dynamic.pathconf.handlers.size) {
    case 1:
        break;
    case 0:
        h2o_configurator_errprintf(cmd, node, "no handler declared for given extension");
        return -1;
    default:
        h2o_configurator_errprintf(cmd, node, "cannot assign more than one handler for given extension");
        return -1;
    }

    return 0;
}

static void inherit_env_if_necessary(h2o_configurator_context_t *ctx)
{
    if (ctx->env == (ctx->parent != NULL ? ctx->parent->env : NULL))
        ctx->env = h2o_config_create_envconf(ctx->env);
}

static int on_config_setenv(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    size_t i;

    inherit_env_if_necessary(ctx);

    for (i = 0; i != node->data.mapping.size; ++i) {
        yoml_t *key = node->data.mapping.elements[i].key, *value = node->data.mapping.elements[i].value;
        if (key->type != YOML_TYPE_SCALAR) {
            h2o_configurator_errprintf(cmd, key, "key must be a scalar");
            return -1;
        }
        if (value->type != YOML_TYPE_SCALAR) {
            h2o_configurator_errprintf(cmd, value, "value must be a scalar");
            return -1;
        }
        h2o_config_setenv(ctx->env, key->data.scalar, value->data.scalar);
    }

    return 0;
}

static int on_config_unsetenv(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    inherit_env_if_necessary(ctx);

    switch (node->type) {
    case YOML_TYPE_SCALAR:
        h2o_config_unsetenv(ctx->env, node->data.scalar);
        break;
    case YOML_TYPE_SEQUENCE: {
        size_t i;
        for (i = 0; i != node->data.sequence.size; ++i) {
            yoml_t *element = node->data.sequence.elements[i];
            if (element->type != YOML_TYPE_SCALAR) {
                h2o_configurator_errprintf(cmd, element, "element of a sequence passed to unsetenv must be a scalar");
                return -1;
            }
            h2o_config_unsetenv(ctx->env, element->data.scalar);
        }
    } break;
    default:
        h2o_configurator_errprintf(cmd, node, "argument to unsetenv must be either a scalar or a sequence");
        return -1;
    }

    return 0;
}

static int on_config_server_name(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    ctx->globalconf->server_name = h2o_strdup(NULL, node->data.scalar, SIZE_MAX);
    return 0;
}

static int on_config_send_server_name(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    switch (h2o_configurator_get_one_of(cmd, node, "OFF,ON,preserve")) {
    case 0: /* off */
        ctx->globalconf->server_name = h2o_iovec_init(H2O_STRLIT(""));
        break;
    case 1: /* on */
        break;
    case 2: /* preserve */
        ctx->globalconf->server_name = h2o_iovec_init(H2O_STRLIT(""));
        ctx->globalconf->proxy.preserve_server_header = 1;
        break;
    default:
        return -1;
    }
    return 0;
}

static int on_config_error_log_emit_request_errors(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    struct st_core_configurator_t *self = (void *)cmd->configurator;
    ssize_t on;

    if ((on = h2o_configurator_get_one_of(cmd, node, "OFF,ON")) == -1)
        return -1;

    self->vars->error_log.emit_request_errors = (int)on;
    return 0;
}

static int on_config_send_informational(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    switch (h2o_configurator_get_one_of(cmd, node, "except-h1,none,all")) {
    case 0:
        ctx->globalconf->send_informational_mode = H2O_SEND_INFORMATIONAL_MODE_EXCEPT_H1;
        break;
    case 1:
        ctx->globalconf->send_informational_mode = H2O_SEND_INFORMATIONAL_MODE_NONE;
        break;
    case 2:
        ctx->globalconf->send_informational_mode = H2O_SEND_INFORMATIONAL_MODE_ALL;
        break;
    default:
        return -1;
    }
    return 0;
}

static int on_config_stash(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    /* do nothing */
    return 0;
}

static int on_config_usdt_selective_tracing(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    ssize_t on;
    if ((on = h2o_configurator_get_one_of(cmd, node, "OFF,ON")) == -1)
        return -1;
    ctx->globalconf->usdt_selective_tracing = (int)on;
    return 0;
}

void h2o_configurator__init_core(h2o_globalconf_t *conf)
{
    /* check if already initialized */
    if (h2o_configurator_get_command(conf, "files") != NULL)
        return;

    { /* `hosts` and `paths` */
        h2o_configurator_t *c = h2o_configurator_create(conf, sizeof(*c));
        h2o_configurator_define_command(
            c, "hosts", H2O_CONFIGURATOR_FLAG_GLOBAL | H2O_CONFIGURATOR_FLAG_EXPECT_MAPPING | H2O_CONFIGURATOR_FLAG_DEFERRED,
            on_config_hosts);
        h2o_configurator_define_command(
            c, "paths", H2O_CONFIGURATOR_FLAG_HOST | H2O_CONFIGURATOR_FLAG_EXPECT_MAPPING | H2O_CONFIGURATOR_FLAG_DEFERRED,
            on_config_paths);
        h2o_configurator_define_command(c, "strict-match", H2O_CONFIGURATOR_FLAG_HOST | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR,
                                        on_config_strict_match);
    };

    { /* setup global configurators */
        struct st_core_configurator_t *c = (void *)h2o_configurator_create(conf, sizeof(*c));
        c->super.enter = on_core_enter;
        c->super.exit = on_core_exit;
        c->vars = c->_vars_stack;
        c->vars->http2.reprioritize_blocking_assets = 1; /* defaults to ON */
        c->vars->http2.push_preload = 1;                 /* defaults to ON */
        c->vars->error_log.emit_request_errors = 1;      /* defaults to ON */
        h2o_configurator_define_command(&c->super, "limit-request-body",
                                        H2O_CONFIGURATOR_FLAG_GLOBAL | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR,
                                        on_config_limit_request_body);
        h2o_configurator_define_command(&c->super, "max-delegations",
                                        H2O_CONFIGURATOR_FLAG_GLOBAL | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR,
                                        on_config_max_delegations);
        h2o_configurator_define_command(&c->super, "handshake-timeout",
                                        H2O_CONFIGURATOR_FLAG_GLOBAL | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR,
                                        on_config_handshake_timeout);
        h2o_configurator_define_command(&c->super, "http1-request-timeout",
                                        H2O_CONFIGURATOR_FLAG_GLOBAL | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR,
                                        on_config_http1_request_timeout);
        h2o_configurator_define_command(&c->super, "http1-request-io-timeout",
                                        H2O_CONFIGURATOR_FLAG_GLOBAL | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR,
                                        on_config_http1_request_io_timeout);
        h2o_configurator_define_command(&c->super, "http1-upgrade-to-http2",
                                        H2O_CONFIGURATOR_FLAG_GLOBAL | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR,
                                        on_config_http1_upgrade_to_http2);
        h2o_configurator_define_command(&c->super, "http2-idle-timeout",
                                        H2O_CONFIGURATOR_FLAG_GLOBAL | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR,
                                        on_config_http2_idle_timeout);
        h2o_configurator_define_command(&c->super, "http2-graceful-shutdown-timeout",
                                        H2O_CONFIGURATOR_FLAG_GLOBAL | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR,
                                        on_config_http2_graceful_shutdown_timeout);
        h2o_configurator_define_command(&c->super, "http2-max-concurrent-requests-per-connection",
                                        H2O_CONFIGURATOR_FLAG_GLOBAL | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR,
                                        on_config_http2_max_concurrent_requests_per_connection);
        h2o_configurator_define_command(&c->super, "http2-max-concurrent-streaming-requests-per-connection",
                                        H2O_CONFIGURATOR_FLAG_GLOBAL | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR,
                                        on_config_http2_max_concurrent_streaming_requests_per_connection);
        h2o_configurator_define_command(&c->super, "http2-input-window-size",
                                        H2O_CONFIGURATOR_FLAG_GLOBAL | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR,
                                        on_config_http2_input_window_size);
        h2o_configurator_define_command(&c->super, "http2-latency-optimization-min-rtt",
                                        H2O_CONFIGURATOR_FLAG_GLOBAL | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR,
                                        on_config_http2_latency_optimization_min_rtt);
        h2o_configurator_define_command(&c->super, "http2-latency-optimization-max-additional-delay",
                                        H2O_CONFIGURATOR_FLAG_GLOBAL | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR,
                                        on_config_http2_latency_optimization_max_additional_delay);
        h2o_configurator_define_command(&c->super, "http2-latency-optimization-max-cwnd",
                                        H2O_CONFIGURATOR_FLAG_GLOBAL | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR,
                                        on_config_http2_latency_optimization_max_cwnd);
        h2o_configurator_define_command(&c->super, "http2-reprioritize-blocking-assets",
                                        H2O_CONFIGURATOR_FLAG_GLOBAL | H2O_CONFIGURATOR_FLAG_HOST |
                                            H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR,
                                        on_config_http2_reprioritize_blocking_assets);
        h2o_configurator_define_command(&c->super, "http2-push-preload",
                                        H2O_CONFIGURATOR_FLAG_GLOBAL | H2O_CONFIGURATOR_FLAG_HOST |
                                            H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR,
                                        on_config_http2_push_preload);
        h2o_configurator_define_command(&c->super, "http2-allow-cross-origin-push",
                                        H2O_CONFIGURATOR_FLAG_GLOBAL | H2O_CONFIGURATOR_FLAG_PATH |
                                            H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR,
                                        on_config_http2_allow_cross_origin_push);
        h2o_configurator_define_command(&c->super, "http2-casper", H2O_CONFIGURATOR_FLAG_GLOBAL | H2O_CONFIGURATOR_FLAG_HOST,
                                        on_config_http2_casper);
        h2o_configurator_define_command(&c->super, "http3-idle-timeout",
                                        H2O_CONFIGURATOR_FLAG_GLOBAL | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR,
                                        on_config_http3_idle_timeout);
        h2o_configurator_define_command(&c->super, "http3-graceful-shutdown-timeout",
                                        H2O_CONFIGURATOR_FLAG_GLOBAL | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR,
                                        on_config_http3_graceful_shutdown_timeout);
        h2o_configurator_define_command(&c->super, "http3-input-window-size",
                                        H2O_CONFIGURATOR_FLAG_GLOBAL | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR,
                                        on_config_http3_input_window_size);
        h2o_configurator_define_command(&c->super, "http3-delayed-ack",
                                        H2O_CONFIGURATOR_FLAG_GLOBAL | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR,
                                        on_config_http3_delayed_ack);
        h2o_configurator_define_command(&c->super, "file.mime.settypes",
                                        (H2O_CONFIGURATOR_FLAG_ALL_LEVELS & ~H2O_CONFIGURATOR_FLAG_EXTENSION) |
                                            H2O_CONFIGURATOR_FLAG_EXPECT_MAPPING,
                                        on_config_mime_settypes);
        h2o_configurator_define_command(&c->super, "file.mime.addtypes",
                                        (H2O_CONFIGURATOR_FLAG_ALL_LEVELS & ~H2O_CONFIGURATOR_FLAG_EXTENSION) |
                                            H2O_CONFIGURATOR_FLAG_EXPECT_MAPPING,
                                        on_config_mime_addtypes);
        h2o_configurator_define_command(&c->super, "file.mime.removetypes",
                                        (H2O_CONFIGURATOR_FLAG_ALL_LEVELS & ~H2O_CONFIGURATOR_FLAG_EXTENSION) |
                                            H2O_CONFIGURATOR_FLAG_EXPECT_SEQUENCE,
                                        on_config_mime_removetypes);
        h2o_configurator_define_command(&c->super, "file.mime.setdefaulttype",
                                        (H2O_CONFIGURATOR_FLAG_ALL_LEVELS & ~H2O_CONFIGURATOR_FLAG_EXTENSION) |
                                            H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR,
                                        on_config_mime_setdefaulttype);
        h2o_configurator_define_command(&c->super, "file.custom-handler",
                                        (H2O_CONFIGURATOR_FLAG_ALL_LEVELS & ~H2O_CONFIGURATOR_FLAG_EXTENSION) |
                                            H2O_CONFIGURATOR_FLAG_SEMI_DEFERRED,
                                        on_config_custom_handler);
        h2o_configurator_define_command(&c->super, "setenv",
                                        H2O_CONFIGURATOR_FLAG_ALL_LEVELS | H2O_CONFIGURATOR_FLAG_EXPECT_MAPPING, on_config_setenv);
        h2o_configurator_define_command(&c->super, "unsetenv", H2O_CONFIGURATOR_FLAG_ALL_LEVELS, on_config_unsetenv);
        h2o_configurator_define_command(&c->super, "server-name",
                                        H2O_CONFIGURATOR_FLAG_GLOBAL | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR, on_config_server_name);
        h2o_configurator_define_command(&c->super, "send-server-name",
                                        H2O_CONFIGURATOR_FLAG_GLOBAL | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR |
                                            H2O_CONFIGURATOR_FLAG_DEFERRED,
                                        on_config_send_server_name);
        h2o_configurator_define_command(&c->super, "error-log.emit-request-errors",
                                        H2O_CONFIGURATOR_FLAG_ALL_LEVELS | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR,
                                        on_config_error_log_emit_request_errors);
        h2o_configurator_define_command(&c->super, "send-informational",
                                        H2O_CONFIGURATOR_FLAG_GLOBAL | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR,
                                        on_config_send_informational);
        h2o_configurator_define_command(&c->super, "stash", H2O_CONFIGURATOR_FLAG_ALL_LEVELS, on_config_stash);
        h2o_configurator_define_command(&c->super, "usdt-selective-tracing",
                                        H2O_CONFIGURATOR_FLAG_GLOBAL | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR,
                                        on_config_usdt_selective_tracing);
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

void h2o_configurator_define_command(h2o_configurator_t *configurator, const char *name, int flags, h2o_configurator_command_cb cb)
{
    h2o_configurator_command_t *cmd;

    h2o_vector_reserve(NULL, &configurator->commands, configurator->commands.size + 1);
    cmd = configurator->commands.entries + configurator->commands.size++;
    cmd->configurator = configurator;
    cmd->flags = flags;
    cmd->name = name;
    cmd->cb = cb;
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

int h2o_configurator_apply(h2o_globalconf_t *config, yoml_t *node, int dry_run)
{
    h2o_configurator_context_t *ctx = create_context(NULL, 0);
    ctx->globalconf = config;
    ctx->mimemap = &ctx->globalconf->mimemap;
    ctx->dry_run = dry_run;
    int cmd_ret = h2o_configurator_apply_commands(ctx, node, H2O_CONFIGURATOR_FLAG_GLOBAL, NULL);
    destroy_context(ctx);

    if (cmd_ret != 0)
        return cmd_ret;
    if (config->hosts[0] == NULL) {
        h2o_configurator_errprintf(NULL, node, "mandatory configuration directive `hosts` is missing");
        return -1;
    }
    return 0;
}

void h2o_configurator_errprintf(h2o_configurator_command_t *cmd, yoml_t *node, const char *reason, ...)
{
    char buf[1024];
    va_list args;

    h2o_error_printf("[%s:%zu] ", node->filename ? node->filename : "-", node->line + 1);
    if (cmd != NULL)
        h2o_error_printf("in command %s, ", cmd->name);
    va_start(args, reason);
    vsnprintf(buf, sizeof(buf), reason, args);
    va_end(args);
    h2o_error_printf("%s\n", buf);
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

static const char *get_next_key(const char *start, h2o_iovec_t *output, unsigned *type_mask)
{
    const char *p = strchr(start, ':');
    if (p == NULL)
        goto Error;

    /* set output */
    *output = h2o_iovec_init(start, p - start);

    /* parse attributes */
    *type_mask = 0;
    for (++p; *p != '\0'; ++p) {
        switch (*p) {
        case ',':
            return p + 1;
        case 's':
            *type_mask |= 1u << YOML_TYPE_SCALAR;
            break;
        case 'a':
            *type_mask |= 1u << YOML_TYPE_SEQUENCE;
            break;
        case 'm':
            *type_mask |= 1u << YOML_TYPE_MAPPING;
            break;
        case '*':
            *type_mask |= (1u << YOML_TYPE_SCALAR) | (1u << YOML_TYPE_SEQUENCE) | (1u << YOML_TYPE_MAPPING);
            break;
        default:
            goto Error;
        }
    }

    return NULL;

Error:
    h2o_fatal("detected invalid or missing type specifier; input is: %s\n", start);
}

int h2o_configurator__do_parse_mapping(h2o_configurator_command_t *cmd, yoml_t *node, const char *keys_required,
                                       const char *keys_optional, yoml_t ****values, size_t num_values)
{
    struct {
        h2o_iovec_t key;
        int is_required;
        unsigned type_mask;
    } *keys = alloca(sizeof(keys[0]) * num_values);
    size_t i, j;

    assert(node->type == YOML_TYPE_MAPPING);

    /* parse keys */
    i = 0;
    if (keys_required != NULL) {
        const char *p = keys_required;
        for (; p != NULL; ++i) {
            assert(i < num_values);
            p = get_next_key(p, &keys[i].key, &keys[i].type_mask);
            keys[i].is_required = 1;
        }
    }
    if (keys_optional != NULL) {
        const char *p = keys_optional;
        for (; p != NULL; ++i) {
            assert(i < num_values);
            p = get_next_key(p, &keys[i].key, &keys[i].type_mask);
            keys[i].is_required = 0;
        }
    }
    assert(i == num_values);

    /* clear the output */
    for (i = 0; i != num_values; ++i)
        *values[i] = NULL;

    /* extract the attributes */
    for (i = 0; i != node->data.mapping.size; ++i) {
        yoml_mapping_element_t *element = node->data.mapping.elements + i;
        if (element->key->type != YOML_TYPE_SCALAR) {
            h2o_configurator_errprintf(cmd, element->key, "key must be a scalar");
            return -1;
        }
        size_t element_key_len = strlen(element->key->data.scalar);
        for (j = 0; j != num_values; ++j)
            if (keys[j].key.len == element_key_len &&
                strncasecmp(keys[j].key.base, element->key->data.scalar, element_key_len) == 0)
                goto Found;
        /* not found */
        h2o_configurator_errprintf(cmd, element->key, "unexpected key:%s", element->key->data.scalar);
        return -1;
    Found:
        if (*values[j] != NULL) {
            h2o_configurator_errprintf(cmd, element->key, "duplicate key found");
            return -1;
        }
        if ((keys[j].type_mask & (1u << element->value->type)) == 0) {
            char permitted_types[sizeof(" or a scalar or a sequence or a mapping")] = "";
            snprintf(permitted_types, sizeof(permitted_types), "%s%s%s",
                     (keys[j].type_mask & (1u << YOML_TYPE_SCALAR)) != 0 ? " or a scalar" : "",
                     (keys[j].type_mask & (1u << YOML_TYPE_SEQUENCE)) != 0 ? " or a sequence" : "",
                     (keys[j].type_mask & (1u << YOML_TYPE_MAPPING)) != 0 ? " or a mapping" : "");
            assert(strlen(permitted_types) != 0);
            h2o_configurator_errprintf(cmd, element->value, "attribute `%s` must be %s", element->key->data.scalar,
                                       permitted_types + 4);
            return -1;
        }
        *values[j] = &element->value;
    }

    /* check if any of the required keys are missing */
    for (i = 0; i < num_values && keys[i].is_required; ++i) {
        if (*values[i] == NULL) {
            h2o_configurator_errprintf(cmd, node, "cannot find mandatory attribute: %.*s", (int)keys[i].key.len, keys[i].key.base);
            return -1;
        }
    }

    return 0;
}

char *h2o_configurator_get_cmd_path(const char *cmd)
{
    char *root, *cmd_fullpath;

    /* just return the cmd (being strdup'ed) in case we do not need to prefix the value */
    if (cmd[0] == '/' || strchr(cmd, '/') == NULL)
        goto ReturnOrig;

    /* obtain root */
    if ((root = getenv("H2O_ROOT")) == NULL) {
        root = H2O_TO_STR(H2O_ROOT);
    }

    /* build full-path and return */
    cmd_fullpath = h2o_mem_alloc(strlen(root) + strlen(cmd) + 2);
    sprintf(cmd_fullpath, "%s/%s", root, cmd);
    return cmd_fullpath;

ReturnOrig:
    return h2o_strdup(NULL, cmd, SIZE_MAX).base;
}
