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
#include <inttypes.h>
#include <errno.h>
#include <stdio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include "h2o.h"
#include "h2o/configurator.h"
#include "h2o/balancer.h"

struct proxy_config_vars_t {
    h2o_proxy_config_vars_t conf;
    uint64_t keepalive_timeout; /* in milliseconds; set to zero to disable keepalive */
    SSL_CTX *ssl_ctx;
};

struct proxy_configurator_t {
    h2o_configurator_t super;
    unsigned connect_timeout_set : 1;
    unsigned first_byte_timeout_set : 1;
    struct proxy_config_vars_t *vars;
    struct proxy_config_vars_t _vars_stack[H2O_CONFIGURATOR_NUM_LEVELS + 1];
};

static int on_config_timeout_io(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    int ret;
    struct proxy_configurator_t *self = (void *)cmd->configurator;
    ret = h2o_configurator_scanf(cmd, node, "%" SCNu64, &self->vars->conf.io_timeout);
    if (ret < 0)
        return ret;
    if (!self->connect_timeout_set)
        self->vars->conf.connect_timeout = self->vars->conf.io_timeout;
    if (!self->first_byte_timeout_set)
        self->vars->conf.first_byte_timeout = self->vars->conf.io_timeout;
    return ret;
}

static int on_config_timeout_connect(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    struct proxy_configurator_t *self = (void *)cmd->configurator;
    self->connect_timeout_set = 1;
    return h2o_configurator_scanf(cmd, node, "%" SCNu64, &self->vars->conf.connect_timeout);
}

static int on_config_timeout_first_byte(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    struct proxy_configurator_t *self = (void *)cmd->configurator;
    self->first_byte_timeout_set = 1;
    return h2o_configurator_scanf(cmd, node, "%" SCNu64, &self->vars->conf.first_byte_timeout);
}

static int on_config_timeout_keepalive(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    struct proxy_configurator_t *self = (void *)cmd->configurator;
    return h2o_configurator_scanf(cmd, node, "%" SCNu64, &self->vars->keepalive_timeout);
}

static int on_config_preserve_host(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    struct proxy_configurator_t *self = (void *)cmd->configurator;
    ssize_t ret = h2o_configurator_get_one_of(cmd, node, "OFF,ON");
    if (ret == -1)
        return -1;
    self->vars->conf.preserve_host = (int)ret;
    return 0;
}

static int on_config_proxy_protocol(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    struct proxy_configurator_t *self = (void *)cmd->configurator;
    ssize_t ret = h2o_configurator_get_one_of(cmd, node, "OFF,ON");
    if (ret == -1)
        return -1;
    self->vars->conf.use_proxy_protocol = (int)ret;
    return 0;
}

static int on_config_websocket_timeout(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    struct proxy_configurator_t *self = (void *)cmd->configurator;
    return h2o_configurator_scanf(cmd, node, "%" SCNu64, &self->vars->conf.websocket.timeout);
}

static int on_config_websocket(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    struct proxy_configurator_t *self = (void *)cmd->configurator;
    ssize_t ret = h2o_configurator_get_one_of(cmd, node, "OFF,ON");
    if (ret == -1)
        return -1;
    self->vars->conf.websocket.enabled = (int)ret;
    return 0;
}

static SSL_CTX *create_ssl_ctx(void)
{
    SSL_CTX *ctx = SSL_CTX_new(SSLv23_client_method());
    SSL_CTX_set_options(ctx, SSL_CTX_get_options(ctx) | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
    return ctx;
}

static h2o_cache_t *create_ssl_session_cache(size_t capacity, uint64_t duration)
{
    return h2o_cache_create(H2O_CACHE_FLAG_MULTITHREADED, capacity, duration, h2o_socket_ssl_destroy_session_cache_entry);
}

static void update_ssl_ctx(SSL_CTX **ctx, X509_STORE *cert_store, int verify_mode, h2o_cache_t **session_cache)
{
    assert(*ctx != NULL);

    /* inherit the properties that weren't specified */
    if (cert_store == NULL)
        cert_store = SSL_CTX_get_cert_store(*ctx);
    X509_STORE_up_ref(cert_store);
    if (verify_mode == -1)
        verify_mode = SSL_CTX_get_verify_mode(*ctx);
    h2o_cache_t *new_session_cache;
    if (session_cache == NULL) {
        h2o_cache_t *current = h2o_socket_ssl_get_session_cache(*ctx);
        new_session_cache =
            current == NULL ? NULL : create_ssl_session_cache(h2o_cache_get_capacity(current), h2o_cache_get_duration(current));
    } else {
        new_session_cache = *session_cache;
    }

    /* free the existing context */
    if (*ctx != NULL)
        SSL_CTX_free(*ctx);

    /* create new ctx */
    *ctx = create_ssl_ctx();
    SSL_CTX_set_cert_store(*ctx, cert_store);
    SSL_CTX_set_verify(*ctx, verify_mode, NULL);
    if (new_session_cache != NULL)
        h2o_socket_ssl_set_session_cache(*ctx, new_session_cache);
}

static int on_config_ssl_verify_peer(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    struct proxy_configurator_t *self = (void *)cmd->configurator;
    ssize_t ret = h2o_configurator_get_one_of(cmd, node, "OFF,ON");
    if (ret == -1)
        return -1;

    update_ssl_ctx(&self->vars->ssl_ctx, NULL, ret != 0 ? SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT : SSL_VERIFY_NONE,
                   NULL);

    return 0;
}

static int on_config_ssl_cafile(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    struct proxy_configurator_t *self = (void *)cmd->configurator;
    X509_STORE *store = X509_STORE_new();
    int ret = -1;

    if (X509_STORE_load_locations(store, node->data.scalar, NULL) == 1) {
        update_ssl_ctx(&self->vars->ssl_ctx, store, -1, NULL);
        ret = 0;
    } else {
        h2o_configurator_errprintf(cmd, node, "failed to load certificates file:%s", node->data.scalar);
        ERR_print_errors_fp(stderr);
    }

    X509_STORE_free(store);
    return ret;
}

static int on_config_ssl_session_cache(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    struct proxy_configurator_t *self = (void *)cmd->configurator;
    size_t capacity = 0;
    uint64_t duration = 0;
    h2o_cache_t *current_cache = h2o_socket_ssl_get_session_cache(self->vars->ssl_ctx);

    switch (node->type) {
    case YOML_TYPE_SCALAR:
        if (strcasecmp(node->data.scalar, "OFF") == 0) {
            if (current_cache != NULL) {
                /* set the cache NULL */
                h2o_cache_t *empty_cache = NULL;
                update_ssl_ctx(&self->vars->ssl_ctx, NULL, -1, &empty_cache);
            }
            return 0;
        } else if (strcasecmp(node->data.scalar, "ON") == 0) {
            /* use default values */
            capacity = H2O_DEFAULT_PROXY_SSL_SESSION_CACHE_CAPACITY;
            duration = H2O_DEFAULT_PROXY_SSL_SESSION_CACHE_DURATION;
        } else {
            h2o_configurator_errprintf(cmd, node, "scalar argument must be either of: `OFF`, `ON`");
            return -1;
        }
        break;
    case YOML_TYPE_MAPPING: {
        size_t i;
        for (i = 0; i != node->data.mapping.size; ++i) {
            yoml_t *key = node->data.mapping.elements[i].key;
            yoml_t *value = node->data.mapping.elements[i].value;
            if (key->type != YOML_TYPE_SCALAR) {
                h2o_configurator_errprintf(cmd, key, "key must be a scalar");
                return -1;
            }
            if (strcasecmp(key->data.scalar, "capacity") == 0) {
                if (h2o_configurator_scanf(cmd, value, "%zu", &capacity) != 0)
                    return -1;
                if (capacity == 0) {
                    h2o_configurator_errprintf(cmd, key, "capacity must be greater than zero");
                    return -1;
                }
            } else if (strcasecmp(key->data.scalar, "lifetime") == 0) {
                unsigned lifetime = 0;
                if (h2o_configurator_scanf(cmd, value, "%u", &lifetime) != 0)
                    return -1;
                if (lifetime == 0) {
                    h2o_configurator_errprintf(cmd, key, "lifetime must be greater than zero");
                    return -1;
                }
                duration = (uint64_t)lifetime * 1000;
            } else {
                h2o_configurator_errprintf(cmd, key, "key must be either of: `capacity`, `lifetime`");
                return -1;
            }
        }
        if (capacity == 0 || duration == 0) {
            h2o_configurator_errprintf(cmd, node, "`capacity` and `lifetime` are required");
            return -1;
        }
    } break;
    default:
        h2o_configurator_errprintf(cmd, node, "node must be a scalar or a mapping");
        return -1;
    }

    if (current_cache != NULL) {
        size_t current_capacity = h2o_cache_get_capacity(current_cache);
        uint64_t current_duration = h2o_cache_get_duration(current_cache);
        if (capacity == current_capacity && duration == current_duration) {
            /* parameters aren't changed, so reuse it */
            return 0;
        }
    }

    h2o_cache_t *new_cache = create_ssl_session_cache(capacity, duration);
    update_ssl_ctx(&self->vars->ssl_ctx, NULL, -1, &new_cache);
    return 0;
}

static int parse_balancer(h2o_configurator_command_t *cmd, yoml_t *node, h2o_socketpool_target_t **targets, size_t target_len)
{
    struct proxy_configurator_t *self = (void *)cmd->configurator;
    yoml_t *lb_type_node = NULL;
    size_t i;
    switch (node->type) {
    case YOML_TYPE_SCALAR:
        lb_type_node = node;
        break;
    case YOML_TYPE_MAPPING:
        for (i = 0; i < node->data.mapping.size; i++) {
            yoml_t *key = node->data.mapping.elements[i].key;
            yoml_t *value = node->data.mapping.elements[i].value;
            if (key->type != YOML_TYPE_SCALAR) {
                h2o_configurator_errprintf(cmd, key, "key must be a scalar");
                return -1;
            }
            if (strcasecmp(key->data.scalar, "type") == 0) {
                if (value->type != YOML_TYPE_SCALAR) {
                    h2o_configurator_errprintf(cmd, value, "value must be a scalar");
                    return -1;
                }
                lb_type_node = value;
                break;
            }
        }
        if (lb_type_node == NULL) {
            h2o_configurator_errprintf(cmd, node, "`type` must exist when proxy.reverse.balancer configured with a mapping");
            return -1;
        }
        break;
    default:
        h2o_configurator_errprintf(cmd, node, "proxy.reverse.balancer must be either a scalar or a mapping");
        return -1;
    }

    if (strcmp(lb_type_node->data.scalar, "round-robin") == 0) {
        self->vars->conf.balancer = h2o_balancer_create_rr();
    } else if (strcmp(lb_type_node->data.scalar, "least-conn") == 0) {
        self->vars->conf.balancer = h2o_balancer_create_lc();
    } else {
        h2o_configurator_errprintf(cmd, node,
                                   "specified balancer is currently not supported. supported balancers are: "
                                   "round-robin least-conn");
        return -1;
    }

    return 0;
}

static int parse_backends(h2o_configurator_command_t *cmd, yoml_t **inputs, size_t num_upstreams, h2o_socketpool_target_t **targets)
{
    struct proxy_configurator_t *self = (void *)cmd->configurator;
    size_t i, j;
    h2o_url_t upstream;
    h2o_socketpool_target_conf_t *lb_per_target_conf = alloca(self->vars->conf.balancer->target_conf_len);
    for (i = 0; i != num_upstreams; ++i) {
        yoml_t *url_node = NULL;
        yoml_t *node_for_parsing;
        memset(lb_per_target_conf, 0, sizeof(*lb_per_target_conf));
        lb_per_target_conf->weight = 1; /* default weight of each target */
        switch (inputs[i]->type) {
            case YOML_TYPE_SCALAR:
                url_node = inputs[i];
                node_for_parsing = NULL;
                break;
            case YOML_TYPE_MAPPING:
                node_for_parsing = inputs[i];
                for (j = 0; j < inputs[i]->data.mapping.size; j++) {
                    yoml_t *key = inputs[i]->data.mapping.elements[j].key;
                    yoml_t *value = inputs[i]->data.mapping.elements[j].value;
                    if (key->type != YOML_TYPE_SCALAR) {
                        h2o_configurator_errprintf(cmd, key, "key must be a scalar");
                        return -1;
                    }
                    if (strcasecmp(key->data.scalar, "url") == 0) {
                        if (value->type != YOML_TYPE_SCALAR) {
                            h2o_configurator_errprintf(cmd, value, "value must be a scalar");
                            return -1;
                        }
                        url_node = value;
                        continue;
                    }
                    if (strcasecmp(key->data.scalar, "weight") == 0) {
                        if (value->type != YOML_TYPE_SCALAR) {
                            h2o_configurator_errprintf(cmd, value, "value must be a scalar");
                            return -1;
                        }
                        lb_per_target_conf->weight = h2o_strtosize(value->data.scalar, strlen(value->data.scalar));
                        if (lb_per_target_conf->weight == SIZE_MAX || lb_per_target_conf->weight == 0) {
                            h2o_configurator_errprintf(cmd, value, "value of weight must be an unsigned integer greater than 0");
                            return -1;
                        }
                    }
                }
                
                if (url_node == NULL) {
                    h2o_configurator_errprintf(
                                               cmd, inputs[i], "mapping element of a sequence passed to proxy.reverse.url must have `url` configured.");
                    return -1;
                }
                
                break;
            default:
                h2o_configurator_errprintf(cmd, inputs[i],
                                           "items of arguments passed to proxy.reverse.url must"
                                           "be either a scalar or a mapping");
                return -1;
        }
        if (h2o_url_parse(url_node->data.scalar, SIZE_MAX, &upstream) != 0) {
            h2o_configurator_errprintf(cmd, url_node, "failed to parse URL: %s\n", url_node->data.scalar);
            return -1;
        }
        targets[i] = h2o_socketpool_target_create(&upstream, lb_per_target_conf, self->vars->conf.balancer->target_conf_len);
    }
    return 0;
}

static int on_config_reverse_url(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    struct proxy_configurator_t *self = (void *)cmd->configurator;

    yoml_t **inputs = NULL;
    yoml_t *balancer_conf = NULL;
    size_t num_upstreams = 0;
    size_t i;

    /* parse the URL(s) */
    switch (node->type) {
    case YOML_TYPE_SCALAR:
        inputs = &node;
        num_upstreams = 1;
        break;
    case YOML_TYPE_SEQUENCE:
        inputs = node->data.sequence.elements;
        num_upstreams = node->data.sequence.size;
        break;
    case YOML_TYPE_MAPPING:
        for (i = 0; i < node->data.mapping.size; i++) {
            yoml_t *key = node->data.mapping.elements[i].key;
            yoml_t *value = node->data.mapping.elements[i].value;
            if (key->type != YOML_TYPE_SCALAR) {
                h2o_configurator_errprintf(cmd, key, "key must be a scalar");
                return -1;
            }
            if (strcasecmp(key->data.scalar, "backends") == 0) {
                switch (value->type) {
                case YOML_TYPE_SCALAR:
                    inputs = &value;
                    num_upstreams = 1;
                    break;
                case YOML_TYPE_SEQUENCE:
                    inputs = value->data.sequence.elements;
                    num_upstreams = value->data.sequence.size;
                    break;
                default:
                    h2o_configurator_errprintf(cmd, value, "value for backends must be either a scalar or a sequence");
                    return -1;
                }
                continue;
            }
            if (strcasecmp(key->data.scalar, "balancer") == 0) {
                balancer_conf = value;
            }
        }
        break;
    default:
        h2o_fatal("unexpected node type");
        return -1;
    }

    h2o_socketpool_target_t **targets = alloca(sizeof(*targets) * num_upstreams);

    if (inputs == NULL) {
        h2o_configurator_errprintf(cmd, node, "No backend is defined.");
    }
    if (balancer_conf != NULL) {
        if (parse_balancer(cmd, balancer_conf, targets, num_upstreams) != 0) {
            return -1;
        }
    } else {
        self->vars->conf.balancer = h2o_balancer_create_rr(targets, num_upstreams);
    }

    if (parse_backends(cmd, inputs, num_upstreams, targets) != 0)
        return -1;

    if (self->vars->keepalive_timeout != 0 && self->vars->conf.use_proxy_protocol) {
        h2o_configurator_errprintf(cmd, node, "please either set `proxy.use-proxy-protocol` to `OFF` or disable keep-alive by "
                                              "setting `proxy.timeout.keepalive` to zero; the features are mutually exclusive");
        return -1;
    }

    if (num_upstreams == 0) {
        h2o_configurator_errprintf(cmd, node, "please set at least one backend url for reverse proxy");
        return -1;
    }

    if (self->vars->conf.headers_cmds != NULL)
        h2o_mem_addref_shared(self->vars->conf.headers_cmds);

    h2o_socketpool_t *sockpool = malloc(sizeof(*sockpool));
    memset(sockpool, 0, sizeof(*sockpool));
    /* init socket pool */
    h2o_socketpool_init_specific(sockpool, SIZE_MAX /* FIXME */, targets, num_upstreams, self->vars->conf.balancer);
    h2o_socketpool_set_timeout(sockpool, self->vars->keepalive_timeout);
    h2o_socketpool_set_ssl_ctx(sockpool, self->vars->ssl_ctx);
    h2o_proxy_register_reverse_proxy(ctx->pathconf, &self->vars->conf, sockpool);
    return 0;
}

static int on_config_emit_x_forwarded_headers(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    ssize_t ret = h2o_configurator_get_one_of(cmd, node, "OFF,ON");
    if (ret == -1)
        return -1;
    ctx->globalconf->proxy.emit_x_forwarded_headers = (int)ret;
    return 0;
}

static int on_config_emit_via_header(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    ssize_t ret = h2o_configurator_get_one_of(cmd, node, "OFF,ON");
    if (ret == -1)
        return -1;
    ctx->globalconf->proxy.emit_via_header = (int)ret;
    return 0;
}

static int on_config_emit_missing_date_header(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    ssize_t ret = h2o_configurator_get_one_of(cmd, node, "OFF,ON");
    if (ret == -1)
        return -1;
    ctx->globalconf->proxy.emit_missing_date_header = (int)ret;
    return 0;
}

static int on_config_preserve_x_forwarded_proto(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    ssize_t ret = h2o_configurator_get_one_of(cmd, node, "OFF,ON");
    if (ret == -1)
        return -1;
    ctx->globalconf->proxy.preserve_x_forwarded_proto = (int)ret;
    return 0;
}

static int on_config_max_buffer_size(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    struct proxy_configurator_t *self = (void *)cmd->configurator;
    return h2o_configurator_scanf(cmd, node, "%zu", &self->vars->conf.max_buffer_size);
}

static int on_config_enter(h2o_configurator_t *_self, h2o_configurator_context_t *ctx, yoml_t *node)
{
    struct proxy_configurator_t *self = (void *)_self;

    memcpy(self->vars + 1, self->vars, sizeof(*self->vars));
    if (self->vars[1].conf.headers_cmds != NULL)
        h2o_mem_addref_shared(self->vars[1].conf.headers_cmds);
    ++self->vars;
    self->connect_timeout_set = 0;
    self->first_byte_timeout_set = 0;

    if (ctx->pathconf == NULL && ctx->hostconf == NULL) {
        /* is global conf, setup the default SSL context */
        self->vars->ssl_ctx = create_ssl_ctx();
        char *ca_bundle = h2o_configurator_get_cmd_path("share/h2o/ca-bundle.crt");
        if (SSL_CTX_load_verify_locations(self->vars->ssl_ctx, ca_bundle, NULL) != 1)
            fprintf(stderr, "Warning: failed to load the default certificates file at %s. Proxying to HTTPS servers may fail.\n",
                    ca_bundle);
        free(ca_bundle);
        SSL_CTX_set_verify(self->vars->ssl_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
        h2o_cache_t *ssl_session_cache =
            create_ssl_session_cache(H2O_DEFAULT_PROXY_SSL_SESSION_CACHE_CAPACITY, H2O_DEFAULT_PROXY_SSL_SESSION_CACHE_DURATION);
        h2o_socket_ssl_set_session_cache(self->vars->ssl_ctx, ssl_session_cache);
    } else {
        SSL_CTX_up_ref(self->vars->ssl_ctx);
    }

    return 0;
}

static int on_config_exit(h2o_configurator_t *_self, h2o_configurator_context_t *ctx, yoml_t *node)
{
    struct proxy_configurator_t *self = (void *)_self;

    if (ctx->pathconf == NULL && ctx->hostconf == NULL) {
        /* is global conf */
        ctx->globalconf->proxy.io_timeout = self->vars->conf.io_timeout;
        ctx->globalconf->proxy.connect_timeout = self->vars->conf.connect_timeout;
        ctx->globalconf->proxy.first_byte_timeout = self->vars->conf.first_byte_timeout;
        h2o_socketpool_set_ssl_ctx(&ctx->globalconf->proxy.global_socketpool, self->vars->ssl_ctx);
        h2o_socketpool_set_timeout(&ctx->globalconf->proxy.global_socketpool, self->vars->keepalive_timeout);
    }
    SSL_CTX_free(self->vars->ssl_ctx);

    if (self->vars->conf.headers_cmds != NULL)
        h2o_mem_release_shared(self->vars->conf.headers_cmds);

    --self->vars;
    return 0;
}

static h2o_headers_command_t **get_headers_commands(h2o_configurator_t *_self)
{
    struct proxy_configurator_t *self = (void *)_self;
    return &self->vars->conf.headers_cmds;
}

void h2o_proxy_register_configurator(h2o_globalconf_t *conf)
{
    struct proxy_configurator_t *c = (void *)h2o_configurator_create(conf, sizeof(*c));

    /* set default vars */
    c->vars = c->_vars_stack;
    c->vars->conf.io_timeout = H2O_DEFAULT_PROXY_IO_TIMEOUT;
    c->vars->conf.connect_timeout = H2O_DEFAULT_PROXY_IO_TIMEOUT;
    c->vars->conf.first_byte_timeout = H2O_DEFAULT_PROXY_IO_TIMEOUT;
    c->vars->conf.websocket.enabled = 0; /* have websocket proxying disabled by default; until it becomes non-experimental */
    c->vars->conf.websocket.timeout = H2O_DEFAULT_PROXY_WEBSOCKET_TIMEOUT;
    c->vars->conf.max_buffer_size = SIZE_MAX;
    c->vars->keepalive_timeout = h2o_socketpool_get_timeout(&conf->proxy.global_socketpool);

    /* setup handlers */
    c->super.enter = on_config_enter;
    c->super.exit = on_config_exit;
    h2o_configurator_define_command(&c->super, "proxy.reverse.url",
                                    H2O_CONFIGURATOR_FLAG_PATH | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR |
                                        H2O_CONFIGURATOR_FLAG_EXPECT_SEQUENCE | H2O_CONFIGURATOR_FLAG_EXPECT_MAPPING |
                                        H2O_CONFIGURATOR_FLAG_DEFERRED, on_config_reverse_url);
    h2o_configurator_define_command(&c->super, "proxy.preserve-host",
                                    H2O_CONFIGURATOR_FLAG_ALL_LEVELS | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR,
                                    on_config_preserve_host);
    h2o_configurator_define_command(&c->super, "proxy.proxy-protocol",
                                    H2O_CONFIGURATOR_FLAG_ALL_LEVELS | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR,
                                    on_config_proxy_protocol);
    h2o_configurator_define_command(&c->super, "proxy.timeout.io",
                                    H2O_CONFIGURATOR_FLAG_ALL_LEVELS | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR, on_config_timeout_io);
    h2o_configurator_define_command(&c->super, "proxy.timeout.connect",
                                    H2O_CONFIGURATOR_FLAG_ALL_LEVELS | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR,
                                    on_config_timeout_connect);
    h2o_configurator_define_command(&c->super, "proxy.timeout.first_byte",
                                    H2O_CONFIGURATOR_FLAG_ALL_LEVELS | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR,
                                    on_config_timeout_first_byte);
    h2o_configurator_define_command(&c->super, "proxy.timeout.keepalive",
                                    H2O_CONFIGURATOR_FLAG_ALL_LEVELS | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR,
                                    on_config_timeout_keepalive);
    h2o_configurator_define_command(&c->super, "proxy.websocket",
                                    H2O_CONFIGURATOR_FLAG_ALL_LEVELS | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR, on_config_websocket);
    h2o_configurator_define_command(&c->super, "proxy.websocket.timeout",
                                    H2O_CONFIGURATOR_FLAG_ALL_LEVELS | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR,
                                    on_config_websocket_timeout);
    h2o_configurator_define_command(&c->super, "proxy.ssl.verify-peer",
                                    H2O_CONFIGURATOR_FLAG_ALL_LEVELS | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR,
                                    on_config_ssl_verify_peer);
    h2o_configurator_define_command(&c->super, "proxy.ssl.cafile",
                                    H2O_CONFIGURATOR_FLAG_ALL_LEVELS | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR, on_config_ssl_cafile);
    h2o_configurator_define_command(&c->super, "proxy.ssl.session-cache", H2O_CONFIGURATOR_FLAG_ALL_LEVELS,
                                    on_config_ssl_session_cache);
    h2o_configurator_define_command(&c->super, "proxy.preserve-x-forwarded-proto",
                                    H2O_CONFIGURATOR_FLAG_GLOBAL | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR,
                                    on_config_preserve_x_forwarded_proto);
    h2o_configurator_define_command(&c->super, "proxy.emit-x-forwarded-headers",
                                    H2O_CONFIGURATOR_FLAG_GLOBAL | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR,
                                    on_config_emit_x_forwarded_headers);
    h2o_configurator_define_command(&c->super, "proxy.emit-via-header",
                                    H2O_CONFIGURATOR_FLAG_GLOBAL | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR, on_config_emit_via_header);
    h2o_configurator_define_command(&c->super, "proxy.emit-missing-date-header",
                                    H2O_CONFIGURATOR_FLAG_GLOBAL | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR, on_config_emit_missing_date_header);
    h2o_configurator_define_headers_commands(conf, &c->super, "proxy.header", get_headers_commands);
    h2o_configurator_define_command(&c->super, "proxy.max-buffer-size",
                                    H2O_CONFIGURATOR_FLAG_ALL_LEVELS | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR,
                                    on_config_max_buffer_size);
}
