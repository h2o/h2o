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
    return h2o_configurator_scanf(cmd, node, "%" SCNu64, &self->vars->conf.keepalive_timeout);
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
    long options;
    SSL_CTX *ctx = SSL_CTX_new(SSLv23_client_method());
    options = SSL_CTX_get_options(ctx) | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3;
#ifdef SSL_OP_NO_RENEGOTIATION
    /* introduced in openssl 1.1.0h */
    options |= SSL_OP_NO_RENEGOTIATION;
#endif
    SSL_CTX_set_options(ctx, options);
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
        yoml_t **capacity_node, **lifetime_node;
        if (h2o_configurator_parse_mapping(cmd, node, "capacity:*,lifetime:*", NULL, &capacity_node, &lifetime_node) != 0)
            return -1;
        if (h2o_configurator_scanf(cmd, *capacity_node, "%zu", &capacity) != 0)
            return -1;
        if (capacity == 0) {
            h2o_configurator_errprintf(cmd, *capacity_node, "capacity must be greater than zero");
            return -1;
        }
        unsigned lifetime = 0;
        if (h2o_configurator_scanf(cmd, *lifetime_node, "%u", &lifetime) != 0)
            return -1;
        if (lifetime == 0) {
            h2o_configurator_errprintf(cmd, *lifetime_node, "lifetime must be greater than zero");
            return -1;
        }
        duration = (uint64_t)lifetime * 1000;
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

static h2o_socketpool_target_t *parse_backend(h2o_configurator_command_t *cmd, yoml_t *backend)
{
    yoml_t **url_node;
    h2o_socketpool_target_conf_t lb_per_target_conf = {0}; /* default weight of each target */

    switch (backend->type) {
    case YOML_TYPE_SCALAR:
        url_node = &backend;
        break;
    case YOML_TYPE_MAPPING: {
        yoml_t **weight_node;
        if (h2o_configurator_parse_mapping(cmd, backend, "url:s", "weight:*", &url_node, &weight_node) != 0)
            return NULL;
        if (weight_node != NULL) {
            unsigned weight;
            if (h2o_configurator_scanf(cmd, *weight_node, "%u", &weight) != 0)
                return NULL;
            if (!(1 <= weight && weight <= H2O_SOCKETPOOL_TARGET_MAX_WEIGHT)) {
                h2o_configurator_errprintf(cmd, *weight_node, "weight must be an integer in range 1 - 256");
                return NULL;
            }
            lb_per_target_conf.weight_m1 = weight - 1;
        }
    } break;
    default:
        h2o_configurator_errprintf(cmd, backend,
                                   "items of arguments passed to proxy.reverse.url must be either a scalar or a mapping");
        return NULL;
    }

    h2o_url_t url;
    if (h2o_url_parse((*url_node)->data.scalar, SIZE_MAX, &url) != 0) {
        h2o_configurator_errprintf(cmd, *url_node, "failed to parse URL: %s\n", (*url_node)->data.scalar);
        return NULL;
    }
    return h2o_socketpool_create_target(&url, &lb_per_target_conf);
}

static int on_config_reverse_url(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    struct proxy_configurator_t *self = (void *)cmd->configurator;

    yoml_t **backends, **balancer_conf = NULL;
    size_t i, num_backends = 0;
    h2o_balancer_t *balancer = NULL;

    /* collect the nodes */
    switch (node->type) {
    case YOML_TYPE_SCALAR:
        backends = &node;
        num_backends = 1;
        break;
    case YOML_TYPE_SEQUENCE:
        backends = node->data.sequence.elements;
        num_backends = node->data.sequence.size;
        break;
    case YOML_TYPE_MAPPING:
        if (h2o_configurator_parse_mapping(cmd, node, "backends:*", "balancer:s", &backends, &balancer_conf) != 0)
            return -1;
        switch ((*backends)->type) {
        case YOML_TYPE_SCALAR:
            num_backends = 1;
            break;
        case YOML_TYPE_SEQUENCE:
            num_backends = (*backends)->data.sequence.size;
            backends = (*backends)->data.sequence.elements;
            break;
        default:
            h2o_configurator_errprintf(cmd, *backends, "value for the `backends` property must be either a scalar or a sequence");
            return -1;
        }
        break;
    default:
        h2o_fatal("unexpected node type");
        return -1;
    }
    if (num_backends == 0) {
        h2o_configurator_errprintf(cmd, node, "at least one backend url must be set");
        return -1;
    }

    /* determine the balancer */
    if (balancer_conf != NULL) {
        if (strcmp((*balancer_conf)->data.scalar, "round-robin") == 0) {
            balancer = h2o_balancer_create_rr();
        } else if (strcmp((*balancer_conf)->data.scalar, "least-conn") == 0) {
            balancer = h2o_balancer_create_lc();
        } else {
            h2o_configurator_errprintf(
                cmd, node, "specified balancer is not supported. Currently supported ones are: round-robin, least-conn");
            return -1;
        }
    }

    /* parse the backends */
    h2o_socketpool_target_t **targets = alloca(sizeof(*targets) * num_backends);
    for (i = 0; i != num_backends; ++i)
        if ((targets[i] = parse_backend(cmd, backends[i])) == NULL)
            return -1;

    if (self->vars->conf.keepalive_timeout != 0 && self->vars->conf.use_proxy_protocol) {
        h2o_configurator_errprintf(cmd, node, "please either set `proxy.use-proxy-protocol` to `OFF` or disable keep-alive by "
                                              "setting `proxy.timeout.keepalive` to zero; the features are mutually exclusive");
        return -1;
    }

    if (self->vars->conf.headers_cmds != NULL)
        h2o_mem_addref_shared(self->vars->conf.headers_cmds);

    h2o_socketpool_t *sockpool = h2o_mem_alloc(sizeof(*sockpool));
    memset(sockpool, 0, sizeof(*sockpool));
    /* init socket pool */
    h2o_socketpool_init_specific(sockpool, SIZE_MAX /* FIXME */, targets, num_backends, balancer);
    h2o_socketpool_set_timeout(sockpool, self->vars->conf.keepalive_timeout);
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

static int on_config_http2_max_concurrent_streams(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    struct proxy_configurator_t *self = (void *)cmd->configurator;
    return h2o_configurator_scanf(cmd, node, "%u", &self->vars->conf.http2.max_concurrent_strams);
}

static int on_config_http2_ratio(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    struct proxy_configurator_t *self = (void *)cmd->configurator;
    int ret = h2o_configurator_scanf(cmd, node, "%" SCNd32, &self->vars->conf.http2.ratio);
    if (ret < 0)
        return ret;
    if (self->vars->conf.http2.ratio < 0 || 100 < self->vars->conf.http2.ratio) {
        h2o_configurator_errprintf(cmd, node, "proxy.http2.ratio must be between 0 and 100");
        return -1;
    }
    return 0;
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
        ctx->globalconf->proxy.keepalive_timeout = self->vars->conf.keepalive_timeout;
        ctx->globalconf->proxy.max_buffer_size = self->vars->conf.max_buffer_size;
        ctx->globalconf->proxy.http2.max_concurrent_streams = self->vars->conf.http2.max_concurrent_strams;
        ctx->globalconf->proxy.http2.ratio = self->vars->conf.http2.ratio;
        h2o_socketpool_set_ssl_ctx(&ctx->globalconf->proxy.global_socketpool, self->vars->ssl_ctx);
        h2o_socketpool_set_timeout(&ctx->globalconf->proxy.global_socketpool, self->vars->conf.keepalive_timeout);
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
    c->vars->conf.http2.max_concurrent_strams = H2O_DEFAULT_PROXY_HTTP2_MAX_CONCURRENT_STREAMS;
    c->vars->conf.http2.ratio = -1;
    c->vars->conf.keepalive_timeout = h2o_socketpool_get_timeout(&conf->proxy.global_socketpool);

    /* setup handlers */
    c->super.enter = on_config_enter;
    c->super.exit = on_config_exit;
    h2o_configurator_define_command(&c->super, "proxy.reverse.url",
                                    H2O_CONFIGURATOR_FLAG_PATH | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR |
                                        H2O_CONFIGURATOR_FLAG_EXPECT_SEQUENCE | H2O_CONFIGURATOR_FLAG_EXPECT_MAPPING |
                                        H2O_CONFIGURATOR_FLAG_DEFERRED,
                                    on_config_reverse_url);
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
                                    H2O_CONFIGURATOR_FLAG_GLOBAL | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR,
                                    on_config_emit_missing_date_header);
    h2o_configurator_define_headers_commands(conf, &c->super, "proxy.header", get_headers_commands);
    h2o_configurator_define_command(&c->super, "proxy.max-buffer-size",
                                    H2O_CONFIGURATOR_FLAG_ALL_LEVELS | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR,
                                    on_config_max_buffer_size);
    h2o_configurator_define_command(&c->super, "proxy.http2.max-concurrent_streams",
                                    H2O_CONFIGURATOR_FLAG_ALL_LEVELS | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR,
                                    on_config_http2_max_concurrent_streams);
    h2o_configurator_define_command(&c->super, "proxy.http2.ratio",
                                    H2O_CONFIGURATOR_FLAG_ALL_LEVELS | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR, on_config_http2_ratio);
}
