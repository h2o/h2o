#include "h2o.h"

static h2o_header_t *find_header(h2o_headers_t *headers, h2o_headers_command_t *cmd)
{
    size_t index;

    if (h2o_iovec_is_token(cmd->name)) {
        index = h2o_find_header(headers, (void *)cmd->name, SIZE_MAX);
    } else {
        index = h2o_find_header_by_str(headers, cmd->name->base, cmd->name->len, SIZE_MAX);
    }
    if (index == SIZE_MAX)
        return NULL;
    return headers->entries + index;
}

static void remove_header(h2o_headers_t *headers, h2o_headers_command_t *cmd)
{
    size_t src, dst = 0;

    for (src = 0; src != headers->size; ++src) {
        if (h2o_iovec_is_token(cmd->name)) {
            if (headers->entries[src].name == cmd->name)
                continue;
        } else {
            if (h2o_memis(headers->entries[src].name->base, headers->entries[src].name->len, cmd->name->base, cmd->name->len))
                continue;
        }
        /* not matched */
        if (dst != src)
            headers->entries[dst] = headers->entries[src];
        ++dst;
    }
    headers->size = dst;
}

void h2o_headers_append_command(h2o_headers_command_t **cmds, int cmd, h2o_iovec_t *name, h2o_iovec_t value)
{
    h2o_headers_command_t *new_cmds;
    size_t cnt;

    if (*cmds != NULL) {
        for (cnt = 0; (*cmds)[cnt].cmd != H2O_HEADERS_CMD_NULL; ++cnt)
            ;
    } else {
        cnt = 0;
    }

    new_cmds = h2o_mem_alloc_shared(NULL, (cnt + 2) * sizeof(*new_cmds), NULL);
    if (*cmds != NULL)
        memcpy(new_cmds, *cmds, cnt * sizeof(*new_cmds));
    new_cmds[cnt] = (h2o_headers_command_t){cmd, name, value};
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
        if ((target = find_header(headers, cmd)) == NULL)
            goto AddHeader;
        goto AppendToken;
    case H2O_HEADERS_CMD_MERGE:
        if ((target = find_header(headers, cmd)) == NULL)
            goto AddHeader;
        if (h2o_contains_token(target->value.base, target->value.len, cmd->value.base, cmd->value.len, ','))
            return;
        goto AppendToken;
    case H2O_HEADERS_CMD_SET:
        remove_header(headers, cmd);
        goto AddHeader;
    case H2O_HEADERS_CMD_SETIFEMPTY:
        if (find_header(headers, cmd) != NULL)
            return;
        goto AddHeader;
    case H2O_HEADERS_CMD_UNSET:
        remove_header(headers, cmd);
        return;
    }

    assert(!"FIXME");
    return;

AddHeader:
    if (h2o_iovec_is_token(cmd->name)) {
        h2o_add_header(pool, headers, (void *)cmd->name, NULL, cmd->value.base, cmd->value.len);
    } else {
        h2o_add_header_by_str(pool, headers, cmd->name->base, cmd->name->len, 0, NULL, cmd->value.base, cmd->value.len);
    }
    return;

AppendToken:
    if (target->value.len != 0) {
        h2o_iovec_t v;
        v.len = target->value.len + 2 + cmd->value.len;
        v.base = h2o_mem_alloc_pool(pool, v.len);
        memcpy(v.base, target->value.base, target->value.len);
        v.base[target->value.len] = ',';
        v.base[target->value.len + 1] = ' ';
        memcpy(v.base + target->value.len + 2, cmd->value.base, cmd->value.len);
        target->value = v;
    } else {
        target->value = cmd->value;
    }
    return;
}
