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
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdlib.h>
#include <sys/stat.h>
#ifndef _WIN32
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/un.h>
#endif
#include "h2o.h"
#include "h2o/configurator.h"
#include "h2o/serverutil.h"

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

static int on_config_document_root(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    struct fastcgi_configurator_t *self = (void *)cmd->configurator;

    if (node->data.scalar[0] == '\0') {
        /* unset */
        self->vars->document_root = h2o_iovec_init(NULL, 0);
    } else if (node->data.scalar[0] == '/') {
        /* set */
        self->vars->document_root = h2o_iovec_init(node->data.scalar, strlen(node->data.scalar));
    } else {
        h2o_configurator_errprintf(cmd, node, "value does not start from `/`");
        return -1;
    }
    return 0;
}

static int on_config_send_delegated_uri(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    struct fastcgi_configurator_t *self = (void *)cmd->configurator;
    ssize_t v;

    if ((v = h2o_configurator_get_one_of(cmd, node, "OFF,ON")) == -1)
        return -1;
    self->vars->send_delegated_uri = (int)v;
    return 0;
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

#ifndef _WIN32
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
    } else
#endif

    if (strcmp(type, "tcp") == 0) {
        /* tcp socket */
        uint16_t port;
        if (sscanf(servname, "%" SCNu16, &port) != 1) {
            h2o_configurator_errprintf(cmd, node, "invalid port number:%s", servname);
            return -1;
        }
        h2o_fastcgi_register_by_hostport(ctx->pathconf, hostname, port, self->vars);
    } else {
        h2o_configurator_errprintf(cmd, node, "unknown listen type: %s", type);
        return -1;
    }

    return 0;
}

#ifndef _WIN32
static int create_spawnproc(h2o_configurator_command_t *cmd, yoml_t *node, const char *dirname, char **argv,
                            struct sockaddr_un *sun)
{
    int listen_fd, pipe_fds[2] = {-1, -1};

    /* build socket path */
    sun->sun_family = AF_UNIX;
    strcpy(sun->sun_path, dirname);
    strcat(sun->sun_path, "/_");

    /* create socket */
    if ((listen_fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        h2o_configurator_errprintf(cmd, node, "socket(2) failed: %s", strerror(errno));
        goto Error;
    }
    if (bind(listen_fd, (void *)sun, sizeof(*sun)) != 0) {
        h2o_configurator_errprintf(cmd, node, "bind(2) failed: %s", strerror(errno));
        goto Error;
    }
    if (listen(listen_fd, SOMAXCONN) != 0) {
        h2o_configurator_errprintf(cmd, node, "listen(2) failed: %s", strerror(errno));
        goto Error;
    }

    /* create pipe which is used to notify the termination of the server */
    if (pipe(pipe_fds) != 0) {
        h2o_configurator_errprintf(cmd, node, "pipe(2) failed: %s", strerror(errno));
        pipe_fds[0] = -1;
        pipe_fds[1] = -1;
        goto Error;
    }
    fcntl(pipe_fds[1], F_SETFD, FD_CLOEXEC);

    /* spawn */
    int mapped_fds[] = {listen_fd, 0,   /* listen_fd to 0 */
                        pipe_fds[0], 5, /* pipe_fds[0] to 5 */
                        -1};
    pid_t pid = h2o_spawnp(argv[0], argv, mapped_fds, 0);
    if (pid == -1) {
        fprintf(stderr, "[lib/handler/fastcgi.c] failed to launch helper program %s:%s\n", argv[0], strerror(errno));
        goto Error;
    }

    close(listen_fd);
    listen_fd = -1;
    close(pipe_fds[0]);
    pipe_fds[0] = -1;

    return pipe_fds[1];

Error:
    if (pipe_fds[0] != -1)
        close(pipe_fds[0]);
    if (pipe_fds[1] )
        close(pipe_fds[1]);
    if (listen_fd != -1)
        close(listen_fd);
    unlink(sun->sun_path);
    return -1;
}
#endif

void spawnproc_on_dispose(h2o_fastcgi_handler_t *handler, void *data)
{
    int pipe_fd = (int)((char *)data - (char *)NULL);
    close(pipe_fd);
}

#ifndef _WIN32
static int on_config_spawn(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    struct fastcgi_configurator_t *self = (void *)cmd->configurator;
    char dirname[] = "/tmp/h2o.fcgisock.XXXXXX";
    char *argv[] = {h2o_configurator_get_cmd_path("share/h2o/kill-on-close"), "--rm", dirname, "--", "/bin/sh", "-c",
                    node->data.scalar, NULL};
    int spawner_fd;
    struct sockaddr_un sun = {};
    h2o_fastcgi_config_vars_t config_vars;
    int ret = -1;

    /* create temporary directory */
    if (mkdtemp(dirname) == NULL) {
        h2o_configurator_errprintf(cmd, node, "mkdtemp(3) failed to create temporary directory:%s:%s", dirname, strerror(errno));
        dirname[0] = '\0';
        goto Exit;
    }

    /* launch spawnfcgi command */
    if ((spawner_fd = create_spawnproc(cmd, node, dirname, argv, &sun)) == -1) {
        goto Exit;
    }

    config_vars = *self->vars;
    config_vars.callbacks.dispose = spawnproc_on_dispose;
    config_vars.callbacks.data = (char *)NULL + spawner_fd;
    h2o_fastcgi_register_by_address(ctx->pathconf, (void *)&sun, sizeof(sun), &config_vars);

    ret = 0;
Exit:
    if (dirname[0] != '\0')
        unlink(dirname);
    free(argv[0]);
    return ret;
}
#endif

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

    h2o_configurator_define_command(&c->super, "fastcgi.connect",
                                    H2O_CONFIGURATOR_FLAG_PATH | H2O_CONFIGURATOR_FLAG_EXTENSION | H2O_CONFIGURATOR_FLAG_DEFERRED,
                                    on_config_connect);
#ifndef _WIN32
    h2o_configurator_define_command(&c->super, "fastcgi.spawn",
                                    H2O_CONFIGURATOR_FLAG_PATH | H2O_CONFIGURATOR_FLAG_EXTENSION | H2O_CONFIGURATOR_FLAG_DEFERRED
                                        | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR,
                                    on_config_spawn);
#endif
    h2o_configurator_define_command(&c->super, "fastcgi.timeout.io",
                                    H2O_CONFIGURATOR_FLAG_ALL_LEVELS | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR, on_config_timeout_io);
    h2o_configurator_define_command(&c->super, "fastcgi.timeout.keepalive",
                                    H2O_CONFIGURATOR_FLAG_ALL_LEVELS | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR,
                                    on_config_timeout_keepalive);
    h2o_configurator_define_command(&c->super, "fastcgi.document_root",
                                    H2O_CONFIGURATOR_FLAG_ALL_LEVELS | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR,
                                    on_config_document_root);
    h2o_configurator_define_command(&c->super, "fastcgi.send-delegated-uri",
                                    H2O_CONFIGURATOR_FLAG_ALL_LEVELS | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR,
                                    on_config_send_delegated_uri);
}
