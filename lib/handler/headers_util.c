#include "h2o.h"

static h2o_header_t *find_header(h2o_headers_t *headers, h2o_headers_command_t *cmd)
{
    ssize_t index;

    if (h2o_iovec_is_token(cmd->data.single.name)) {
        index = h2o_find_header(headers, (void *)cmd->data.single.name, -1);
    } else {
        index = h2o_find_header_by_str(headers, cmd->data.single.name->base, cmd->data.single.name->len, -1);
    }
    if (index == -1)
        return NULL;
    return headers->entries + index;
}

static void remove_header(h2o_headers_t *headers, h2o_headers_command_t *cmd)
{
    size_t src, dst = 0;

    for (src = 0; src != headers->size; ++src) {
        if (h2o_iovec_is_token(cmd->data.single.name)) {
            if (headers->entries[src].name == cmd->data.single.name)
                continue;
        } else {
            if (h2o_memis(headers->entries[src].name->base, headers->entries[src].name->len, cmd->data.single.name->base,
                          cmd->data.single.name->len))
                continue;
        }
        /* not matched */
        if (dst != src)
            headers->entries[dst] = headers->entries[src];
        ++dst;
    }
    headers->size = dst;
}

static int is_in_list(const char *base, size_t len, h2o_iovec_vector_t *list, int header)
{
    size_t i;
    h2o_iovec_t name = h2o_iovec_init(base, len);
    for (i = 0; i != list->size; ++i) {
        if (header && h2o_iovec_is_token(&name)) {
            if (list->entries[i].base == name.base) {
                return 1;
            }
        } else {
            if (h2o_memis(list->entries[i].base, list->entries[i].len, name.base, name.len))
                return 1;
        }
    }
    return 0;
}

static void header_list_allow(h2o_headers_t *headers, h2o_headers_command_t *cmd)
{
    size_t src, dst = 0;

    for (src = 0; src != headers->size; ++src) {
        if (!is_in_list(headers->entries[src].name->base, headers->entries[src].name->len, &cmd->data.name_list, 1))
            continue;
        /* not matched */
        if (dst != src)
            headers->entries[dst] = headers->entries[src];
        ++dst;
    }
    headers->size = dst;
}

static void header_list_deny(h2o_headers_t *headers, h2o_headers_command_t *cmd)
{
    size_t src, dst = 0;

    for (src = 0; src != headers->size; ++src) {
        if (is_in_list(headers->entries[src].name->base, headers->entries[src].name->len, &cmd->data.name_list, 1))
            continue;
        /* not matched */
        if (dst != src)
            headers->entries[dst] = headers->entries[src];
        ++dst;
    }
    headers->size = dst;
}

enum { ALLOW, DENY };

static void filter_cookie(h2o_mem_pool_t *pool, char **base, size_t *len, h2o_iovec_vector_t *list, int action)
{
    h2o_iovec_t iter = h2o_iovec_init(*base, *len), token_value;
    const char *token;
    size_t token_len;
    char dst[*len * 2];
    size_t dst_len = 0;

    do {
        if ((token = h2o_next_token(&iter, ';', &token_len, &token_value, 0)) == NULL)
            break;
        int found = is_in_list(token, token_len, list, 0);
        if ((action == ALLOW && found) || (action == DENY && !found)) {
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

static void cookie_list_allow(h2o_mem_pool_t *pool, h2o_headers_t *headers, h2o_headers_command_t *cmd)
{
    ssize_t header_index;
    for (header_index = -1; (header_index = h2o_find_header(headers, H2O_TOKEN_COOKIE, header_index)) != -1;) {
        h2o_header_t *header = headers->entries + header_index;
        filter_cookie(pool, &header->value.base, &header->value.len, &cmd->data.name_list, ALLOW);
    }
}

static void cookie_list_deny(h2o_mem_pool_t *pool, h2o_headers_t *headers, h2o_headers_command_t *cmd)
{
    ssize_t header_index;
    for (header_index = -1; (header_index = h2o_find_header(headers, H2O_TOKEN_COOKIE, header_index)) != -1;) {
        h2o_header_t *header = headers->entries + header_index;
        filter_cookie(pool, &header->value.base, &header->value.len, &cmd->data.name_list, DENY);
    }
}

void h2o_headers_append_list_command(h2o_headers_command_t **cmds, int cmd, h2o_iovec_vector_t *list,
                                     h2o_headers_command_when_t when)
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
    new_cmds[cnt] = (h2o_headers_command_t){cmd, {}, when};
    new_cmds[cnt].data.name_list = *list;
    new_cmds[cnt + 1] = (h2o_headers_command_t){H2O_HEADERS_CMD_NULL};

    if (*cmds != NULL)
        h2o_mem_release_shared(*cmds);
    *cmds = new_cmds;
}

void h2o_headers_append_single_command(h2o_headers_command_t **cmds, int cmd, h2o_iovec_t *name, h2o_iovec_t value,
                                       h2o_headers_command_when_t when)
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
    new_cmds[cnt] = (h2o_headers_command_t){cmd, {}, when};
    new_cmds[cnt].data.single.name = name;
    new_cmds[cnt].data.single.value = value;
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
        if (h2o_contains_token(target->value.base, target->value.len, cmd->data.single.value.base, cmd->data.single.value.len, ','))
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
    case H2O_HEADER_LIST_ALLOW:
        header_list_allow(headers, cmd);
        return;
    case H2O_HEADER_LIST_DENY:
        header_list_deny(headers, cmd);
        return;
    case H2O_COOKIE_LIST_ALLOW:
        cookie_list_allow(pool, headers, cmd);
        return;
    case H2O_COOKIE_LIST_DENY:
        cookie_list_deny(pool, headers, cmd);
        return;
    }

    assert(!"FIXME");
    return;

AddHeader:
    if (h2o_iovec_is_token(cmd->data.single.name)) {
        h2o_add_header(pool, headers, (void *)cmd->data.single.name, NULL, cmd->data.single.value.base, cmd->data.single.value.len);
    } else {
        h2o_add_header_by_str(pool, headers, cmd->data.single.name->base, cmd->data.single.name->len, 0, NULL,
                              cmd->data.single.value.base, cmd->data.single.value.len);
    }
    return;

AppendToken:
    if (target->value.len != 0) {
        h2o_iovec_t v;
        v.len = target->value.len + 2 + cmd->data.single.value.len;
        v.base = h2o_mem_alloc_pool(pool, char, v.len);
        memcpy(v.base, target->value.base, target->value.len);
        v.base[target->value.len] = ',';
        v.base[target->value.len + 1] = ' ';
        memcpy(v.base + target->value.len + 2, cmd->data.single.value.base, cmd->data.single.value.len);
        target->value = v;
    } else {
        target->value = cmd->data.single.value;
    }
    return;
}
