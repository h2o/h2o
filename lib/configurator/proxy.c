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
#include "h2o.h"
#include "h2o/configurator.h"

struct proxy_configurator_t {
    h2o_configurator_t super;
    h2o_proxy_config_vars_t *vars;
    h2o_proxy_config_vars_t _vars_stack[H2O_CONFIGURATOR_NUM_LEVELS + 1];
};


static int on_config_timeout_io(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, const char *file, yoml_t *node)
{
    struct proxy_configurator_t *self = (void*)cmd->configurator;
    return h2o_config_scanf(cmd, file, node, "%" PRIu64, &self->vars->io_timeout);
}

static int on_config_timeout_keepalive(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, const char *file, yoml_t *node)
{
    struct proxy_configurator_t *self = (void*)cmd->configurator;
    return h2o_config_scanf(cmd, file, node, "%" PRIu64, &self->vars->keepalive_timeout);
}

static int on_config_keepalive(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, const char *file, yoml_t *node)
{
    struct proxy_configurator_t *self = (void*)cmd->configurator;
    ssize_t ret = h2o_config_get_one_of(cmd, file, node, "OFF,ON");
    if (ret == -1)
        return -1;
    self->vars->use_keepalive = (int)ret;
    return 0;
}

static int on_config_reverse_url(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, const char *file, yoml_t *node)
{
    struct proxy_configurator_t *self = (void*)cmd->configurator;
    h2o_mempool_t pool;
    h2o_iovec_t scheme, host, path;
    uint16_t port;

    h2o_mempool_init(&pool);

    if (h2o_parse_url(node->data.scalar, SIZE_MAX, &scheme, &host, &port, &path) != 0) {
        h2o_config_print_error(cmd, file, node, "failed to parse URL: %s\n", node->data.scalar);
        goto ErrExit;
    }
    if (! h2o_memis(scheme.base, scheme.len, H2O_STRLIT("http"))) {
        h2o_config_print_error(cmd, file, node, "only HTTP URLs are supported");
        goto ErrExit;
    }
    /* register */
    h2o_proxy_register_reverse_proxy(
        ctx->hostconf,
        ctx->path != NULL ? ctx->path->base : "",
        h2o_strdup(&pool, host.base, host.len).base,
        port,
        h2o_strdup(&pool, path.base, path.len).base,
        self->vars);

    h2o_mempool_clear(&pool);
    return 0;

ErrExit:
    h2o_mempool_clear(&pool);
    return -1;
}

static int on_config_enter(h2o_configurator_t *_self, h2o_configurator_context_t *ctx, const char *file, yoml_t *node)
{
    struct proxy_configurator_t *self = (void*)_self;

    memcpy(self->vars + 1, self->vars, sizeof(*self->vars));
    ++self->vars;
    return 0;
}

static int on_config_exit(h2o_configurator_t *_self, h2o_configurator_context_t *ctx, const char *file, yoml_t *node)
{
    struct proxy_configurator_t *self = (void*)_self;

    --self->vars;
    return 0;
}

void h2o_proxy_register_configurator(h2o_globalconf_t *conf)
{
    struct proxy_configurator_t *c = (void*)h2o_config_create_configurator(conf, sizeof(*c));

    /* set default vars */
    c->vars = c->_vars_stack;
    c->vars->io_timeout = 5000;
    c->vars->keepalive_timeout = 2000;

    /* setup handlers */
    c->super.enter = on_config_enter;
    c->super.exit = on_config_exit;
    h2o_config_define_command(&c->super, "proxy.reverse.url",
        H2O_CONFIGURATOR_FLAG_PATH | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR | H2O_CONFIGURATOR_FLAG_DEFERRED,
        on_config_reverse_url,
        "upstream URL (only HTTP is suppported)");
    h2o_config_define_command(&c->super, "proxy.keepalive",
        H2O_CONFIGURATOR_FLAG_GLOBAL | H2O_CONFIGURATOR_FLAG_HOST | H2O_CONFIGURATOR_FLAG_PATH | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR,
        on_config_keepalive,
        "boolean flag (ON/OFF) indicating whether or not to use persistent connections",
        "to upstream (default: OFF)");
    h2o_config_define_command(&c->super, "proxy.timeout.io",
        H2O_CONFIGURATOR_FLAG_GLOBAL | H2O_CONFIGURATOR_FLAG_HOST | H2O_CONFIGURATOR_FLAG_PATH | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR,
        on_config_timeout_io,
        "sets upstream I/O timeout (in milliseconds, default: 5000)");
    h2o_config_define_command(&c->super, "proxy.timeout.keepalive",
        H2O_CONFIGURATOR_FLAG_GLOBAL | H2O_CONFIGURATOR_FLAG_HOST | H2O_CONFIGURATOR_FLAG_PATH | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR,
        on_config_timeout_keepalive,
        "timeout for idle conncections (in milliseconds, default: 2000)");
}
