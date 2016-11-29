#include "h2o.h"
#include "h2o/configurator.h"

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

int add_cmd(h2o_configurator_command_t *cmd, yoml_t *node, int cmd_id, h2o_iovec_t *name, h2o_iovec_t value, void *header_cmd_vector)
{
    H2O_VECTOR(h2o_headers_command_t) *header_cmds = header_cmd_vector;
    if (h2o_iovec_is_token(name)) {
        const h2o_token_t *token = (void *)name;
        if (h2o_headers_is_prohibited_name(token)) {
            h2o_configurator_errprintf(cmd, node, "the named header cannot be rewritten");
            return -1;
        }
    }

    h2o_vector_reserve(NULL, header_cmds, header_cmds->size + 1);
    header_cmds->entries[header_cmds->size++] = (h2o_headers_command_t){cmd_id, name, value};
    return 0;
}

int h2o_on_config_header_2arg(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, int cmd_id, yoml_t *node, void *header_cmd_vector)
{
    h2o_iovec_t *name, value;

    if (extract_name_value(node->data.scalar, &name, &value) != 0) {
        h2o_configurator_errprintf(cmd, node, "failed to parse the value; should be in form of `name: value`");
        return -1;
    }
    if (add_cmd(cmd, node, cmd_id, name, value, header_cmd_vector) != 0) {
        if (!h2o_iovec_is_token(name))
            free(name->base);
        free(value.base);
        return -1;
    }
    return 0;
}

int h2o_on_config_header_unset(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node, void *header_cmd_vector)
{
    h2o_iovec_t *name;

    if (extract_name(node->data.scalar, strlen(node->data.scalar), &name) != 0) {
        h2o_configurator_errprintf(cmd, node, "invalid header name");
        return -1;
    }
    if (add_cmd(cmd, node, H2O_HEADERS_CMD_UNSET, name, (h2o_iovec_t){NULL}, header_cmd_vector) != 0) {
        if (!h2o_iovec_is_token(name))
            free(name->base);
        return -1;
    }
    return 0;
}
