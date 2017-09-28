#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pwd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/un.h>
#include "h2o.h"
#include "h2o/configurator.h"
#include "h2o/serverutil.h"

struct websocket_configurator_t {
    h2o_configurator_t super;
    h2o_websocket_config_vars_t *vars;
    h2o_websocket_config_vars_t _vars_stack[H2O_CONFIGURATOR_NUM_LEVELS + 1];
};

static int on_config_connect(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    struct websocket_configurator_t *self = (void *)cmd->configurator;
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
        struct sockaddr_un sa;
        memset(&sa, 0, sizeof(sa));
        if (strlen(servname) >= sizeof(sa.sun_path)) {
            h2o_configurator_errprintf(cmd, node, "path:%s is too long as a unix socket name", servname);
            return -1;
        }
        sa.sun_family = AF_UNIX;
        strcpy(sa.sun_path, servname);
        h2o_websocket_register_by_address(ctx->pathconf, (void *)&sa, sizeof(sa), self->vars);
    } else if (strcmp(type, "tcp") == 0) {
        /* tcp socket */
        uint16_t port;
        if (sscanf(servname, "%" SCNu16, &port) != 1) {
            h2o_configurator_errprintf(cmd, node, "invalid port number:%s", servname);
            return -1;
        }
        h2o_websocket_register_by_hostport(ctx->pathconf, hostname, port, self->vars);
    } else {
        h2o_configurator_errprintf(cmd, node, "unknown listen type: %s", type);
        return -1;
    }

    return 0;
}

static int on_config_accept_protocol(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    struct websocket_configurator_t *self = (void *)cmd->configurator;

    if (node->data.scalar[0] == '\0') {
        /* unset */
        self->vars->accept_protocol = h2o_iovec_init(NULL, 0);
    } else {
        /* set */
        self->vars->accept_protocol = h2o_iovec_init(node->data.scalar, strlen(node->data.scalar));
    }
    return 0;
}

static int on_config_enter(h2o_configurator_t *_self, h2o_configurator_context_t *ctx, yoml_t *node)
{
    struct websocket_configurator_t *self = (void *)_self;

    memcpy(self->vars + 1, self->vars, sizeof(*self->vars));
    ++self->vars;
    return 0;
}

static int on_config_exit(h2o_configurator_t *_self, h2o_configurator_context_t *ctx, yoml_t *node)
{
    struct websocket_configurator_t *self = (void *)_self;

    --self->vars;
    return 0;
}

void h2o_websocket_register_configurator(h2o_globalconf_t *conf)
{
    struct websocket_configurator_t *c = (void *)h2o_configurator_create(conf, sizeof(*c));

    /* set default vars */
    c->vars = c->_vars_stack;

    /* setup handlers */
    c->super.enter = on_config_enter;
    c->super.exit = on_config_exit;

    h2o_configurator_define_command(&c->super, "websocket.connect",
                                    H2O_CONFIGURATOR_FLAG_PATH | H2O_CONFIGURATOR_FLAG_EXTENSION | H2O_CONFIGURATOR_FLAG_DEFERRED,
                                    on_config_connect);
    h2o_configurator_define_command(&c->super, "websocket.accept_protocol",
                                    H2O_CONFIGURATOR_FLAG_ALL_LEVELS | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR,
									on_config_accept_protocol);
}


