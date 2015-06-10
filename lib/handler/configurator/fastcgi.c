/*
 * Copyright (c) 2015 DeNA Co., Ltd. Kazuho Oku
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
#include <arpa/inet.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/un.h>
#include "h2o.h"
#include "h2o/configurator.h"

struct fastcgi_configurator_t {
    h2o_configurator_t super;
    h2o_fastcgi_config_vars_t *vars;
    h2o_fastcgi_config_vars_t _vars_stack[H2O_CONFIGURATOR_NUM_LEVELS + 1];
};

static int on_config_timeout_io(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    struct fastcgi_configurator_t *self = (void *)cmd->configurator;
    return h2o_configurator_scanf(cmd, node, "%" PRIu64, &self->vars->io_timeout);
}

static int on_config_timeout_keepalive(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    struct fastcgi_configurator_t *self = (void *)cmd->configurator;
    return h2o_configurator_scanf(cmd, node, "%" PRIu64, &self->vars->keepalive_timeout);
}

static int on_config_connect(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    struct fastcgi_configurator_t *self = (void *)cmd->configurator;
    const char *hostname = "127.0.0.1", *servname = NULL, *type = "tcp";

    /* fetch servname (and hostname) */
    switch (node->type) {
    case YOML_TYPE_SCALAR:
        servname = node->data.scalar;
        break;
    case YOML_TYPE_MAPPING: {
        yoml_t *t;
        if ((t = yoml_get(node, "host")) != NULL) {
            if (t->type != YOML_TYPE_SCALAR) {
                h2o_configurator_errprintf(cmd, t, "`host` is not a string");
                return -1;
            }
            hostname = t->data.scalar;
        }
        if ((t = yoml_get(node, "port")) == NULL) {
            h2o_configurator_errprintf(cmd, node, "cannot find mandatory property `port`");
            return -1;
        }
        if (t->type != YOML_TYPE_SCALAR) {
            h2o_configurator_errprintf(cmd, node, "`port` is not a string");
            return -1;
        }
        servname = t->data.scalar;
        if ((t = yoml_get(node, "type")) != NULL) {
            if (t->type != YOML_TYPE_SCALAR) {
                h2o_configurator_errprintf(cmd, t, "`type` is not a string");
                return -1;
            }
            type = t->data.scalar;
        }
    } break;
    default:
        h2o_configurator_errprintf(cmd, node,
                                   "value must be a string or a mapping (with keys: `port` and optionally `host` and `type`)");
        return -1;
    }

    if (strcmp(type, "unix") == 0) {
        /* unix socket */
        struct sockaddr_un sun = {};
        if (strlen(servname) >= sizeof(sun.sun_path)) {
            h2o_configurator_errprintf(cmd, node, "path:%s is too long as a unix socket name", servname);
            return -1;
        }
        sun.sun_family = AF_UNIX;
        strcpy(sun.sun_path, servname);
        h2o_fastcgi_register_by_address(ctx->pathconf, (void *)&sun, sizeof(sun), self->vars);
    } else if (strcmp(type, "tcp") == 0) {
        /* tcp socket */
        uint16_t port;
        if (sscanf(servname, "%" SCNu16, &port) != 1) {
            h2o_configurator_errprintf(cmd, node, "invaild port number:%s", servname);
            return -1;
        }
        h2o_fastcgi_register_by_hostport(ctx->pathconf, hostname, port, self->vars);
    } else {
        h2o_configurator_errprintf(cmd, node, "unknown listen type: %s", type);
        return -1;
    }

    return 0;
}

static int on_config_enter(h2o_configurator_t *_self, h2o_configurator_context_t *ctx, yoml_t *node)
{
    struct fastcgi_configurator_t *self = (void *)_self;

    memcpy(self->vars + 1, self->vars, sizeof(*self->vars));
    ++self->vars;
    return 0;
}

static int on_config_exit(h2o_configurator_t *_self, h2o_configurator_context_t *ctx, yoml_t *node)
{
    struct fastcgi_configurator_t *self = (void *)_self;

    --self->vars;
    return 0;
}

void h2o_fastcgi_register_configurator(h2o_globalconf_t *conf)
{
    struct fastcgi_configurator_t *c = (void *)h2o_configurator_create(conf, sizeof(*c));

    /* set default vars */
    c->vars = c->_vars_stack;
    c->vars->io_timeout = H2O_DEFAULT_FASTCGI_IO_TIMEOUT;
    c->vars->keepalive_timeout = 0;

    /* setup handlers */
    c->super.enter = on_config_enter;
    c->super.exit = on_config_exit;

    h2o_configurator_define_command(&c->super, "fastcgi.connect", H2O_CONFIGURATOR_FLAG_PATH, on_config_connect);
    h2o_configurator_define_command(&c->super, "fastcgi.timeout.io",
                                    H2O_CONFIGURATOR_FLAG_GLOBAL | H2O_CONFIGURATOR_FLAG_HOST | H2O_CONFIGURATOR_FLAG_PATH |
                                        H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR,
                                    on_config_timeout_io);
    h2o_configurator_define_command(&c->super, "fastcgi.timeout.keepalive",
                                    H2O_CONFIGURATOR_FLAG_GLOBAL | H2O_CONFIGURATOR_FLAG_HOST | H2O_CONFIGURATOR_FLAG_PATH |
                                        H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR,
                                    on_config_timeout_keepalive);
}
