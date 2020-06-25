#include "h2o.h"

static h2o_header_t *find_header(h2o_headers_t *headers, h2o_iovec_t *name)
{
    ssize_t index;

    if (h2o_iovec_is_token(name)) {
        index = h2o_find_header(headers, (void *)name, -1);
    } else {
        index = h2o_find_header_by_str(headers, name->base, name->len, -1);
    }
    if (index == -1)
        return NULL;
    return headers->entries + index;
}

static int is_in_list(const char *base, size_t len, h2o_headers_command_t *cmd)
{
    size_t i;
    h2o_iovec_t name = h2o_iovec_init(base, len);
    for (i = 0; i != cmd->num_args; ++i) {
        if (h2o_iovec_is_token(cmd->args[i].name)) {
            if (cmd->args[i].name->base == name.base) {
                return 1;
            }
        } else {
            if (h2o_memis(cmd->args[i].name->base, cmd->args[i].name->len, name.base, name.len))
                return 1;
        }
    }
    return 0;
}

static void filter_cookie(h2o_mem_pool_t *pool, char **base, size_t *len, h2o_headers_command_t *cmd)
{
    h2o_iovec_t iter = h2o_iovec_init(*base, *len), token_value;
    const char *token;
    size_t token_len;
    char dst[*len * 2];
    size_t dst_len = 0;

    do {
        if ((token = h2o_next_token(&iter, ';', ';', &token_len, &token_value)) == NULL)
            break;
        int found = is_in_list(token, token_len, cmd);
        if ((cmd->cmd == H2O_HEADERS_CMD_COOKIE_UNSETUNLESS && found) || (cmd->cmd == H2O_HEADERS_CMD_COOKIE_UNSET && !found)) {
            if (dst_len != 0) {
                memcpy(dst + dst_len, H2O_STRLIT("; "));
                dst_len += 2;
            }
            memcpy(dst + dst_len, token, token_len);
            dst_len += token_len;
            if (token_value.len > 0) {
                memcpy(dst + dst_len, H2O_STRLIT("="));
                dst_len++;
                memcpy(dst + dst_len, token_value.base, token_value.len);
                dst_len += token_value.len;
            }
        }
    } while (1);
    if (dst_len > *len) {
        if (pool == NULL) {
            free(*base);
            *base = malloc(dst_len);
        } else {
            *base = h2o_mem_alloc_pool(pool, *dst, dst_len);
        }
    }
    memcpy(*base, dst, dst_len);
    *len = dst_len;
}

static void cookie_cmd(h2o_mem_pool_t *pool, h2o_headers_t *headers, h2o_headers_command_t *cmd)
{
    ssize_t header_index;
    for (header_index = -1; (header_index = h2o_find_header(headers, H2O_TOKEN_COOKIE, header_index)) != -1;) {
        h2o_header_t *header = headers->entries + header_index;
        filter_cookie(pool, &header->value.base, &header->value.len, cmd);
    }
}

static void remove_header_unless(h2o_headers_t *headers, h2o_headers_command_t *cmd)
{
    size_t src, dst = 0;

    for (src = 0; src != headers->size; ++src) {
        if (!is_in_list(headers->entries[src].name->base, headers->entries[src].name->len, cmd))
            continue;
        /* not matched */
        if (dst != src)
            headers->entries[dst] = headers->entries[src];
        ++dst;
    }
    headers->size = dst;
}

static void remove_header(h2o_headers_t *headers, h2o_headers_command_t *cmd)
{
    size_t src, dst = 0;

    for (src = 0; src != headers->size; ++src) {
        if (h2o_iovec_is_token(cmd->args[0].name)) {
            if (headers->entries[src].name == cmd->args[0].name)
                continue;
        } else {
            if (h2o_memis(headers->entries[src].name->base, headers->entries[src].name->len, cmd->args[0].name->base, cmd->args[0].name->len))
                continue;
        }
        /* not matched */
        if (dst != src)
            headers->entries[dst] = headers->entries[src];
        ++dst;
    }
    headers->size = dst;
}

void h2o_headers_append_command(h2o_headers_command_t **cmds, int cmd, h2o_headers_add_arg_t *args,
                                size_t num_args, h2o_headers_command_when_t when)
{
    h2o_headers_command_t *new_cmds;
    size_t i, cnt;

    if (*cmds != NULL) {
        for (cnt = 0; (*cmds)[cnt].cmd != H2O_HEADERS_CMD_NULL; ++cnt)
            ;
    } else {
        cnt = 0;
    }

    new_cmds = h2o_mem_alloc_shared(NULL, (cnt + 2) * sizeof(*new_cmds), NULL);
    if (*cmds != NULL)
        memcpy(new_cmds, *cmds, cnt * sizeof(*new_cmds));
    new_cmds[cnt] = (h2o_headers_command_t){};
    new_cmds[cnt].cmd = cmd;
    new_cmds[cnt].when = when;
    new_cmds[cnt].args = h2o_mem_alloc_shared(NULL, sizeof(*new_cmds->args) * num_args, NULL);
    for (i = 0; i < num_args; i++) {
        new_cmds[cnt].args[i].name = args[i].name;
        new_cmds[cnt].args[i].value = args[i].value;
    }
    new_cmds[cnt].num_args = num_args;
    new_cmds[cnt + 1] = (h2o_headers_command_t){H2O_HEADERS_CMD_NULL};

    if (*cmds != NULL)
        h2o_mem_release_shared(*cmds);
    *cmds = new_cmds;
}

void h2o_rewrite_headers(h2o_mem_pool_t *pool, h2o_headers_t *headers, h2o_headers_command_t *cmd)
{
    h2o_header_t *target;

    switch (cmd->cmd) {
    case H2O_HEADERS_CMD_ADD:
        goto AddHeader;
    case H2O_HEADERS_CMD_APPEND:
        assert(cmd->num_args == 1);
        if ((target = find_header(headers, cmd->args[0].name)) == NULL)
            goto AddHeader;
        goto AppendToken;
    case H2O_HEADERS_CMD_MERGE:
        assert(cmd->num_args == 1);
        if ((target = find_header(headers, cmd->args[0].name)) == NULL)
            goto AddHeader;
        if (h2o_contains_token(target->value.base, target->value.len, cmd->args[0].value.base, cmd->args[0].value.len, ','))
            return;
        goto AppendToken;
    case H2O_HEADERS_CMD_SET:
        remove_header(headers, cmd);
        goto AddHeader;
    case H2O_HEADERS_CMD_SETIFEMPTY:
        assert(cmd->num_args == 1);
        if (find_header(headers, cmd->args[0].name) != NULL)
            return;
        goto AddHeader;
    case H2O_HEADERS_CMD_UNSET:
        remove_header(headers, cmd);
        return;
    case H2O_HEADERS_CMD_UNSETUNLESS:
        remove_header_unless(headers, cmd);
        return;
    case H2O_HEADERS_CMD_COOKIE_UNSET:
    case H2O_HEADERS_CMD_COOKIE_UNSETUNLESS:
        cookie_cmd(pool, headers, cmd);
        return;
    }

    assert(!"FIXME");
    return;

AddHeader:
    assert(cmd->num_args == 1);
    if (h2o_iovec_is_token(cmd->args[0].name)) {
        h2o_add_header(pool, headers, (void *)cmd->args[0].name, NULL, cmd->args[0].value.base, cmd->args[0].value.len);
    } else {
        h2o_add_header_by_str(pool, headers, cmd->args[0].name->base, cmd->args[0].name->len, 0, NULL, cmd->args[0].value.base, cmd->args[0].value.len);
    }
    return;

AppendToken:
    assert(cmd->num_args == 1);
    if (target->value.len != 0) {
        h2o_iovec_t v;
        v.len = target->value.len + 2 + cmd->args[0].value.len;
        v.base = h2o_mem_alloc_pool(pool, char, v.len);
        memcpy(v.base, target->value.base, target->value.len);
        v.base[target->value.len] = ',';
        v.base[target->value.len + 1] = ' ';
        memcpy(v.base + target->value.len + 2, cmd->args[0].value.base, cmd->args[0].value.len);
        target->value = v;
    } else {
        target->value = cmd->args[0].value;
    }
    return;
}
