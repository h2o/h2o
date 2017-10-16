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
#include "h2o/dyn_backends.h"

struct proxy_configurator_t {
    h2o_configurator_t super;
    unsigned connect_timeout_set : 1;
    unsigned first_byte_timeout_set : 1;
    h2o_proxy_config_vars_t *vars;
    h2o_proxy_config_vars_t _vars_stack[H2O_CONFIGURATOR_NUM_LEVELS + 1];
};

static int on_config_timeout_io(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    int ret;
    struct proxy_configurator_t *self = (void *)cmd->configurator;
    ret = h2o_configurator_scanf(cmd, node, "%" SCNu64, &self->vars->io_timeout);
    if (ret < 0)
        return ret;
    if (!self->connect_timeout_set)
        self->vars->connect_timeout = self->vars->io_timeout;
    if (!self->first_byte_timeout_set)
        self->vars->first_byte_timeout = self->vars->io_timeout;
    return ret;
}

static int on_config_timeout_connect(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    struct proxy_configurator_t *self = (void *)cmd->configurator;
    self->connect_timeout_set = 1;
    return h2o_configurator_scanf(cmd, node, "%" SCNu64, &self->vars->connect_timeout);
}

static int on_config_timeout_first_byte(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    struct proxy_configurator_t *self = (void *)cmd->configurator;
    self->first_byte_timeout_set = 1;
    return h2o_configurator_scanf(cmd, node, "%" SCNu64, &self->vars->first_byte_timeout);
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
    self->vars->preserve_host = (int)ret;
    return 0;
}

static int on_config_proxy_protocol(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    struct proxy_configurator_t *self = (void *)cmd->configurator;
    ssize_t ret = h2o_configurator_get_one_of(cmd, node, "OFF,ON");
    if (ret == -1)
        return -1;
    self->vars->use_proxy_protocol = (int)ret;
    return 0;
}

static int on_config_websocket_timeout(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    struct proxy_configurator_t *self = (void *)cmd->configurator;
    return h2o_configurator_scanf(cmd, node, "%" SCNu64, &self->vars->websocket.timeout);
}

static int on_config_websocket(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    struct proxy_configurator_t *self = (void *)cmd->configurator;
    ssize_t ret = h2o_configurator_get_one_of(cmd, node, "OFF,ON");
    if (ret == -1)
        return -1;
    self->vars->websocket.enabled = (int)ret;
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

static int on_config_reverse_url(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    struct proxy_configurator_t *self = (void *)cmd->configurator;
    h2o_url_t parsed, *reg = NULL;

    switch (node->type) {
    case YOML_TYPE_SCALAR:
        if (h2o_url_parse(node->data.scalar, SIZE_MAX, &parsed) != 0) {
            h2o_configurator_errprintf(cmd, node, "failed to parse URL: %s\n", node->data.scalar);
            return -1;
        }
        reg = &parsed;
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
            if (strcasecmp(key->data.scalar, "header") == 0) {
                h2o_iovec_t *hn = h2o_mem_alloc(sizeof(*hn));
                *hn = h2o_strdup(NULL, value->data.scalar, strlen(value->data.scalar));
                self->vars->get_upstream.ctx = hn;
            } else {
                h2o_configurator_errprintf(cmd, key, "key must be `header`");
                return -1;
            }
        }
        if (!self->vars->get_upstream.ctx) {
            h2o_configurator_errprintf(cmd, node, "`header` is required");
            return -1;
        }
        self->vars->get_upstream.cb = h2o_dyn_backend_get_upstream;
    } break;
    default:
        h2o_configurator_errprintf(cmd, node, "argument to proxy.reverse.url must be either a scalar or a mapping");
        return -1;
    }

    if (self->vars->keepalive_timeout != 0 && self->vars->use_proxy_protocol) {
        h2o_configurator_errprintf(cmd, node, "please either set `proxy.use-proxy-protocol` to `OFF` or disable keep-alive by "
                                              "setting `proxy.timeout.keepalive` to zero; the features are mutually exclusive");
        return -1;
    }
    if (self->vars->reverse_path.base != NULL || self->vars->registered_as_backends) {
        h2o_configurator_errprintf(cmd, node,
                                   "please either set `proxy.reverse.backends` with `proxy.reverse.path` to support "
                                   "multiple backends or only set `proxy.reverse.url`; the features are mutually exclusive");
        return -1;
    }

    if (self->vars->headers_cmds != NULL)
        h2o_mem_addref_shared(self->vars->headers_cmds);

    /* register */
    self->vars->registered_as_url = 1;
    h2o_proxy_register_reverse_proxy(ctx->pathconf, reg, reg ? 1 : 0, self->vars);

    return 0;
}

static int on_config_reverse_path(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    struct proxy_configurator_t *self = (void *)cmd->configurator;

    self->vars->reverse_path = h2o_strdup(NULL, node->data.scalar, strlen(node->data.scalar));
    /* we should check if path is legal here */
    return 0;
}

static int on_config_reverse_backends(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    struct proxy_configurator_t *self = (void *)cmd->configurator;

    h2o_url_t parsed;
    h2o_url_t *upstreams;
    size_t count;
    size_t i;
    int sequence = 0;

    switch (node->type) {
    case YOML_TYPE_SCALAR:
        if (h2o_url_parse(node->data.scalar, SIZE_MAX, &parsed) != 0) {
            h2o_configurator_errprintf(cmd, node, "failed to parse URL: %s\n", node->data.scalar);
            return -1;
        }
        if (parsed.path.len != 1 || parsed.path.base[0] != '/') {
            h2o_configurator_errprintf(cmd, node, "backends should have no path");
            return -1;
        }
        upstreams = &parsed;
        count = 1;

        break;
    case YOML_TYPE_SEQUENCE:
        sequence = 1;
        count = node->data.sequence.size;
        if (self->vars->keepalive_timeout == 0 && count > 1) {
            h2o_configurator_errprintf(cmd, node, "currently we do not support multiple backends with keep-alive disabled");
            return -1;
        }
        upstreams = alloca(count * sizeof(h2o_url_t));
        for (i = 0; i != node->data.sequence.size; ++i) {
            yoml_t *element = node->data.sequence.elements[i];
            if (element->type != YOML_TYPE_SCALAR) {
                h2o_configurator_errprintf(cmd, element, "element of a sequence passed to proxy.reverse.backends must be a scalar");
                return -1;
            }
            if (h2o_url_parse(element->data.scalar, SIZE_MAX, &upstreams[i]) != 0) {
                h2o_configurator_errprintf(cmd, node, "failed to parse URL: %s\n", element->data.scalar);
                return -1;
            }
            if (upstreams[i].path.len != 1 || upstreams[i].path.base[0] != '/') {
                h2o_configurator_errprintf(cmd, node, "backends should have no path");
                return -1;
            }
        }

        break;
    default:
        h2o_configurator_errprintf(cmd, node, "argument to proxy.reverse.backends must be either a scalar or a sequence");
        return -1;
    }

    if (self->vars->use_proxy_protocol) {
        h2o_configurator_errprintf(cmd, node,
                                   "currently we do not support multiple backends with `proxy.use-proxy-protocol` enabled");
        return -1;
    }

    if (self->vars->registered_as_url) {
        h2o_configurator_errprintf(cmd, node,
                                   "please either set `proxy.reverse.backends` with `proxy.reverse.path` to support "
                                   "multiple backends or only set `proxy.reverse.url`; the features are mutually exclusive");
        return -1;
    }

    if (self->vars->headers_cmds != NULL)
        h2o_mem_addref_shared(self->vars->headers_cmds);

    /* register */
    self->vars->registered_as_backends = 1;
    h2o_proxy_register_reverse_proxy(ctx->pathconf, upstreams, count, self->vars);

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
    return h2o_configurator_scanf(cmd, node, "%zu", &self->vars->max_buffer_size);
}

static int on_config_enter(h2o_configurator_t *_self, h2o_configurator_context_t *ctx, yoml_t *node)
{
    struct proxy_configurator_t *self = (void *)_self;

    memcpy(self->vars + 1, self->vars, sizeof(*self->vars));
    if (self->vars[1].headers_cmds != NULL)
        h2o_mem_addref_shared(self->vars[1].headers_cmds);
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
        ctx->globalconf->proxy.io_timeout = self->vars->io_timeout;
        ctx->globalconf->proxy.connect_timeout = self->vars->connect_timeout;
        ctx->globalconf->proxy.first_byte_timeout = self->vars->first_byte_timeout;
        ctx->globalconf->proxy.ssl_ctx = self->vars->ssl_ctx;
    } else {
        SSL_CTX_free(self->vars->ssl_ctx);
    }

    if (self->vars->headers_cmds != NULL)
        h2o_mem_release_shared(self->vars->headers_cmds);

    if (self->vars->reverse_path.base != NULL)
        free(self->vars->reverse_path.base);

    --self->vars;
    return 0;
}

static h2o_headers_command_t **get_headers_commands(h2o_configurator_t *_self)
{
    struct proxy_configurator_t *self = (void *)_self;
    return &self->vars->headers_cmds;
}

static int on_config_backend(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    int ret;
    yoml_t *turl, *tid;
    const char *id;

    if (node->type != YOML_TYPE_MAPPING) {
        fprintf(stderr, "%s: exected a node backend\n", __func__);
        return -1;
    }

    if ((turl = yoml_get(node, "url")) == NULL) {
        fprintf(stderr, "%s: missing mandatory attribute `url`\n", __func__);
        return -1;
    }
    if ((tid = yoml_get(node, "id")) == NULL) {
        fprintf(stderr, "%s: missing mandatory attribute `id`\n", __func__);
        return -1;
    }

    h2o_dyn_backend_config_t bconfig;
    ret = h2o_url_parse(turl->data.scalar, strlen(turl->data.scalar), &bconfig.upstream);
    if (ret < 0) {
        fprintf(stderr, "%s: failed to parse url\n", __func__);
        return -1;
    }

    id = h2o_dyn_backend_add(tid->data.scalar, &bconfig);
    return 0;
}

void h2o_proxy_register_configurator(h2o_globalconf_t *conf)
{
    struct proxy_configurator_t *c = (void *)h2o_configurator_create(conf, sizeof(*c));

    /* set default vars */
    c->vars = c->_vars_stack;
    c->vars->reverse_path.base = NULL;
    c->vars->reverse_path.len = 0;
    c->vars->io_timeout = H2O_DEFAULT_PROXY_IO_TIMEOUT;
    c->vars->connect_timeout = H2O_DEFAULT_PROXY_IO_TIMEOUT;
    c->vars->first_byte_timeout = H2O_DEFAULT_PROXY_IO_TIMEOUT;
    c->vars->keepalive_timeout = 2000;
    c->vars->websocket.enabled = 0; /* have websocket proxying disabled by default; until it becomes non-experimental */
    c->vars->websocket.timeout = H2O_DEFAULT_PROXY_WEBSOCKET_TIMEOUT;
    c->vars->registered_as_url = 0;
    c->vars->registered_as_backends = 0;
    c->vars->max_buffer_size = SIZE_MAX;

    /* setup handlers */
    c->super.enter = on_config_enter;
    c->super.exit = on_config_exit;
    h2o_configurator_define_command(&c->super, "proxy.reverse.url",
                                    H2O_CONFIGURATOR_FLAG_PATH | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR |
                                        H2O_CONFIGURATOR_FLAG_EXPECT_MAPPING | H2O_CONFIGURATOR_FLAG_DEFERRED,
                                    on_config_reverse_url);
    /* if reverse proxy with multiple backends, they should be equivalent. then use backends & path instead of url. */
    h2o_configurator_define_command(&c->super, "proxy.reverse.backends",
                                    H2O_CONFIGURATOR_FLAG_PATH | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR |
                                        H2O_CONFIGURATOR_FLAG_EXPECT_SEQUENCE | H2O_CONFIGURATOR_FLAG_DEFERRED,
                                    on_config_reverse_backends);
    h2o_configurator_define_command(&c->super, "proxy.reverse.path",
                                    H2O_CONFIGURATOR_FLAG_PATH | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR, on_config_reverse_path);
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
    h2o_configurator_define_headers_commands(conf, &c->super, "proxy.header", get_headers_commands);
    h2o_configurator_define_command(&c->super, "proxy.max-buffer-size",
                                    H2O_CONFIGURATOR_FLAG_ALL_LEVELS | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR,
                                    on_config_max_buffer_size);
    h2o_configurator_define_command(&c->super, "backend", H2O_CONFIGURATOR_FLAG_GLOBAL | H2O_CONFIGURATOR_FLAG_EXPECT_MAPPING,
                                    on_config_backend);
}
