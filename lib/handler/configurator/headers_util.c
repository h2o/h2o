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

static int add_single_cmd(h2o_configurator_command_t *cmd, yoml_t *node, int cmd_id, h2o_iovec_t *name, h2o_iovec_t value,
                   h2o_headers_command_when_t when, h2o_headers_command_t **cmds)
{
    if (h2o_iovec_is_token(name)) {
        const h2o_token_t *token = (void *)name;
        if (h2o_headers_is_prohibited_name(token)) {
            h2o_configurator_errprintf(cmd, node, "the named header cannot be rewritten");
            return -1;
        }
    }

    h2o_headers_append_single_command(cmds, cmd_id, name, value, when);
    return 0;
}

static int add_list_cmd(h2o_configurator_command_t *cmd, yoml_t *node, int cmd_id, h2o_iovec_vector_t *list,
                   h2o_headers_command_when_t when, h2o_headers_command_t **cmds, int normalize_header)
{
    int i;

    if (normalize_header) {
        for (i = 0; i != list->size; i++) {
            h2o_iovec_t name = list->entries[i];
            const h2o_token_t *name_token;
            if ((name_token = h2o_lookup_token(name.base, name.len)) != NULL) {
                free(name.base);
                list->entries[i] = name_token->buf;
            }
        }
    }
    h2o_headers_append_list_command(cmds, cmd_id, list, when);

    return 0;
}

static int parse_header_node(h2o_configurator_command_t *cmd, yoml_t **node, yoml_t ***headers, size_t *num_headers,
                             h2o_headers_command_when_t *when)
{

    if ((*node)->type == YOML_TYPE_SCALAR) {
        *headers = node;
        *num_headers = 1;
        *when = H2O_HEADERS_CMD_WHEN_FINAL;
    } else {
        yoml_t **header_node;
        yoml_t **when_node = NULL;
        if ((*node)->type == YOML_TYPE_SEQUENCE) {
            header_node = node;
        } else {
            if (h2o_configurator_parse_mapping(cmd, *node, "header:sa", "when:*", &header_node, &when_node) != 0)
                return -1;
        }
        if ((*header_node)->type == YOML_TYPE_SEQUENCE) {
            *headers = (*header_node)->data.sequence.elements;
            *num_headers = (*header_node)->data.sequence.size;
        } else {
            *headers = header_node;
            *num_headers = 1;
        }
        if (when_node == NULL) {
            *when = H2O_HEADERS_CMD_WHEN_FINAL;
        } else {
            switch (h2o_configurator_get_one_of(cmd, *when_node, "final,early,all")) {
            case 0:
                *when = H2O_HEADERS_CMD_WHEN_FINAL;
                break;
            case 1:
                *when = H2O_HEADERS_CMD_WHEN_EARLY;
                break;
            case 2:
                *when = H2O_HEADERS_CMD_WHEN_ALL;
                break;
            default:
                return -1;
            }
        }
    }
    return 0;
}

static int on_config_header_2arg(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, int cmd_id, yoml_t *node,
                                 h2o_headers_command_t **headers_cmds)
{
    h2o_iovec_t *name, value;
    yoml_t **headers;
    size_t num_headers;
    h2o_headers_command_when_t when;

    if (parse_header_node(cmd, &node, &headers, &num_headers, &when) != 0)
        return -1;

    int i;
    for (i = 0; i != num_headers; ++i) {
        yoml_t *header = headers[i];
        if (extract_name_value(header->data.scalar, &name, &value) != 0) {
            h2o_configurator_errprintf(cmd, header, "failed to parse the value; should be in form of `name: value`");
            return -1;
        }
        if (add_single_cmd(cmd, header, cmd_id, name, value, when, headers_cmds) != 0) {
            if (!h2o_iovec_is_token(name))
                free(name->base);
            free(value.base);
            return -1;
        }
    }

    return 0;
}

static int on_config_header_unset(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    h2o_iovec_t *name;
    yoml_t **headers;
    size_t num_headers;
    h2o_headers_command_when_t when;
    struct headers_util_configurator_t *self = (void *)cmd->configurator;

    if (parse_header_node(cmd, &node, &headers, &num_headers, &when) != 0)
        return -1;

    int i;
    for (i = 0; i != num_headers; ++i) {
        yoml_t *header = headers[i];
        if (extract_name(header->data.scalar, strlen(header->data.scalar), &name) != 0) {
            h2o_configurator_errprintf(cmd, header, "invalid header name");
            return -1;
        }
        if (add_single_cmd(cmd, header, H2O_HEADERS_CMD_UNSET, name, (h2o_iovec_t){NULL}, when, self->get_commands(self->child)) != 0) {
            if (!h2o_iovec_is_token(name))
                free(name->base);
            return -1;
        }
    }

    return 0;
}

static int on_config_list_core(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node, int action, int header)
{
    yoml_t **headers;
    size_t num_headers;
    h2o_headers_command_when_t when;
    struct headers_util_configurator_t *self = (void *)cmd->configurator;
    h2o_iovec_vector_t list;

    if (parse_header_node(cmd, &node, &headers, &num_headers, &when) != 0)
        return -1;
    list = (h2o_iovec_vector_t){h2o_mem_alloc(num_headers * sizeof(list.entries[0])), num_headers, num_headers};
    int i;
    for (i = 0; i != num_headers; i++) {
        list.entries[i] = h2o_strdup(NULL, headers[i]->data.scalar, strlen(headers[i]->data.scalar));
        if (header) {
            h2o_strtolower(list.entries[i].base, list.entries[i].len);
        }
    }


    if (add_list_cmd(cmd, node, action, &list, when, self->get_commands(self->child), header) != 0)
        return -1;
    return 0;
}

static int on_config_header_list_allow(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    return on_config_list_core(cmd, ctx, node, H2O_HEADER_LIST_ALLOW, 1);
}

static int on_config_header_list_deny(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    return on_config_list_core(cmd, ctx, node, H2O_HEADER_LIST_DENY, 1);
}

static int on_config_cookie_list_allow(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    return on_config_list_core(cmd, ctx, node, H2O_COOKIE_LIST_ALLOW, 0);
}

static int on_config_cookie_list_deny(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    return on_config_list_core(cmd, ctx, node, H2O_COOKIE_LIST_DENY, 0);
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
    DEFINE_CMD_NAME(header_list_allow_directive, ".list_allow");
    DEFINE_CMD_NAME(header_list_deny_directive, ".list_deny");
    DEFINE_CMD_NAME(cookie_list_allow_directive, ".cookie.list_allow");
    DEFINE_CMD_NAME(cookie_list_deny_directive, ".cookie.list_deny");
#undef DEFINE_CMD_NAME

#define DEFINE_CMD(name, cb, type)                                                                                                       \
    h2o_configurator_define_command(                                                                                               \
        &c->super, name,                                                                                                           \
        H2O_CONFIGURATOR_FLAG_ALL_LEVELS | H2O_CONFIGURATOR_FLAG_EXPECT_ ## type | H2O_CONFIGURATOR_FLAG_EXPECT_MAPPING, cb)
    DEFINE_CMD(add_directive, on_config_header_add, SCALAR);
    DEFINE_CMD(append_directive, on_config_header_append, SCALAR);
    DEFINE_CMD(merge_directive, on_config_header_merge, SCALAR);
    DEFINE_CMD(set_directive, on_config_header_set, SCALAR);
    DEFINE_CMD(setifempty_directive, on_config_header_setifempty, SCALAR);
    DEFINE_CMD(unset_directive, on_config_header_unset, SCALAR);
    DEFINE_CMD(header_list_allow_directive, on_config_header_list_allow, SEQUENCE);
    DEFINE_CMD(header_list_deny_directive, on_config_header_list_deny, SEQUENCE);
    DEFINE_CMD(cookie_list_allow_directive, on_config_cookie_list_allow, SEQUENCE);
    DEFINE_CMD(cookie_list_deny_directive, on_config_cookie_list_deny, SEQUENCE);
#undef DEFINE_CMD
}
