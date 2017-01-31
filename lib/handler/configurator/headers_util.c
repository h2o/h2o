#include "h2o.h"
#include "h2o/configurator.h"

struct headers_util_configurator_t {
    h2o_configurator_t super;
    h2o_configurator_t *child;
    h2o_configurator_get_headers_commands_cb get_commands;
};

static int extract_name(const char *src, size_t len, h2o_iovec_t **_name)
{
    h2o_iovec_t name;
    const h2o_token_t *name_token;

    name = h2o_str_stripws(src, len);
    if (name.len == 0)
        return -1;

    name = h2o_strdup(NULL, name.base, name.len);
    h2o_strtolower(name.base, name.len);

    if ((name_token = h2o_lookup_token(name.base, name.len)) != NULL) {
        *_name = (h2o_iovec_t *)&name_token->buf;
        free(name.base);
    } else {
        *_name = h2o_mem_alloc(sizeof(**_name));
        **_name = name;
    }

    return 0;
}

static int extract_name_value(const char *src, h2o_iovec_t **name, h2o_iovec_t *value)
{
    const char *colon = strchr(src, ':');

    if (colon == NULL)
        return -1;

    if (extract_name(src, colon - src, name) != 0)
        return -1;
    *value = h2o_str_stripws(colon + 1, strlen(colon + 1));
    *value = h2o_strdup(NULL, value->base, value->len);

    return 0;
}

static int add_cmd(h2o_configurator_command_t *cmd, yoml_t *node, int cmd_id, h2o_iovec_t *name, h2o_iovec_t value,
                   h2o_headers_command_t **cmds)
{
    if (h2o_iovec_is_token(name)) {
        const h2o_token_t *token = (void *)name;
        if (h2o_headers_is_prohibited_name(token)) {
            h2o_configurator_errprintf(cmd, node, "the named header cannot be rewritten");
            return -1;
        }
    }

    h2o_headers_append_command(cmds, cmd_id, name, value);
    return 0;
}

static int on_config_header_2arg(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, int cmd_id, yoml_t *node,
                                 h2o_headers_command_t **headers_cmds)
{
    h2o_iovec_t *name, value;

    if (extract_name_value(node->data.scalar, &name, &value) != 0) {
        h2o_configurator_errprintf(cmd, node, "failed to parse the value; should be in form of `name: value`");
        return -1;
    }
    if (add_cmd(cmd, node, cmd_id, name, value, headers_cmds) != 0) {
        if (!h2o_iovec_is_token(name))
            free(name->base);
        free(value.base);
        return -1;
    }
    return 0;
}

static int on_config_header_unset(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    h2o_iovec_t *name;
    struct headers_util_configurator_t *self = (void *)cmd->configurator;

    if (extract_name(node->data.scalar, strlen(node->data.scalar), &name) != 0) {
        h2o_configurator_errprintf(cmd, node, "invalid header name");
        return -1;
    }
    if (add_cmd(cmd, node, H2O_HEADERS_CMD_UNSET, name, (h2o_iovec_t){NULL}, self->get_commands(self->child)) != 0) {
        if (!h2o_iovec_is_token(name))
            free(name->base);
        return -1;
    }
    return 0;
}

#define DEFINE_2ARG(fn, cmd_id)                                                                                                    \
    static int fn(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)                                  \
    {                                                                                                                              \
        struct headers_util_configurator_t *self = (void *)cmd->configurator;                                                      \
        return on_config_header_2arg(cmd, ctx, cmd_id, node, self->get_commands(self->child));                                     \
    }

DEFINE_2ARG(on_config_header_add, H2O_HEADERS_CMD_ADD)
DEFINE_2ARG(on_config_header_append, H2O_HEADERS_CMD_APPEND)
DEFINE_2ARG(on_config_header_merge, H2O_HEADERS_CMD_MERGE)
DEFINE_2ARG(on_config_header_set, H2O_HEADERS_CMD_SET)
DEFINE_2ARG(on_config_header_setifempty, H2O_HEADERS_CMD_SETIFEMPTY)

#undef DEFINE_2ARG

void h2o_configurator_define_headers_commands(h2o_globalconf_t *global_conf, h2o_configurator_t *conf, const char *prefix,
                                              h2o_configurator_get_headers_commands_cb get_commands)
{
    struct headers_util_configurator_t *c = (void *)h2o_configurator_create(global_conf, sizeof(*c));
    c->child = conf;
    c->get_commands = get_commands;
    size_t prefix_len = strlen(prefix);

#define DEFINE_CMD_NAME(name, suffix)                                                                                              \
    char *name = h2o_mem_alloc(prefix_len + sizeof(suffix));                                                                       \
    memcpy(name, prefix, prefix_len);                                                                                              \
    memcpy(name + prefix_len, suffix, sizeof(suffix))

    DEFINE_CMD_NAME(add_directive, ".add");
    DEFINE_CMD_NAME(append_directive, ".append");
    DEFINE_CMD_NAME(merge_directive, ".merge");
    DEFINE_CMD_NAME(set_directive, ".set");
    DEFINE_CMD_NAME(setifempty_directive, ".setifempty");
    DEFINE_CMD_NAME(unset_directive, ".unset");
#undef DEFINE_CMD_NAME

#define DEFINE_CMD(name, cb)                                                                                                       \
    h2o_configurator_define_command(&c->super, name, H2O_CONFIGURATOR_FLAG_ALL_LEVELS | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR, cb)
    DEFINE_CMD(add_directive, on_config_header_add);
    DEFINE_CMD(append_directive, on_config_header_append);
    DEFINE_CMD(merge_directive, on_config_header_merge);
    DEFINE_CMD(set_directive, on_config_header_set);
    DEFINE_CMD(setifempty_directive, on_config_header_setifempty);
    DEFINE_CMD(unset_directive, on_config_header_unset);
#undef DEFINE_CMD
}
