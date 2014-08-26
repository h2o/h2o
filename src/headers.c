#include <stddef.h>
#include <stdio.h>
#include "h2o.h"

static h2o_header_t *add_header(h2o_mempool_t *pool, h2o_headers_t *headers, uv_buf_t *name, const char *value, size_t value_len)
{
    h2o_header_t *slot;

    h2o_vector_reserve(pool, (h2o_vector_t*)headers, sizeof(h2o_header_t), headers->size + 1);
    slot = headers->entries + headers->size++;

    slot->name.str = name;
    slot->value.base = (char*)value;
    slot->value.len = value_len;

    return slot;
}

ssize_t h2o_init_headers(h2o_mempool_t *pool, h2o_headers_t *headers, const struct phr_header *src, size_t len, uv_buf_t *connection, uv_buf_t *host, uv_buf_t *upgrade)
{
    ssize_t entity_header_index = -1;

    assert(headers->size == 0);

    /* setup */
    if (len != 0) {
        size_t i;
        h2o_vector_reserve(pool, (h2o_vector_t*)headers, sizeof(h2o_header_t), len);
        for (i = 0; i != len; ++i) {
            const h2o_token_t *name_token = h2o_lookup_token(src[i].name, src[i].name_len);
            if (name_token != NULL) {
                if (name_token == H2O_TOKEN_HOST) {
                    host->base = (char*)src[i].value;
                    host->len = src[i].value_len;
                } else if (name_token == H2O_TOKEN_UPGRADE) {
                    upgrade->base = (char*)src[i].value;
                    upgrade->len = src[i].value_len;
                } else if (name_token == H2O_TOKEN_CONTENT_LENGTH) {
                    if (entity_header_index == -1)
                        entity_header_index = i;
                } else if (name_token == H2O_TOKEN_CONTENT_ENCODING) {
                    entity_header_index = i;
                } else {
                    h2o_header_t *added = add_header(pool, headers, (uv_buf_t*)name_token, src[i].value, src[i].value_len);
                    if (name_token == H2O_TOKEN_CONNECTION)
                        *connection = added->value;
                }
            } else {
                h2o_add_header_by_str(pool, headers, src[i].name, src[i].name_len, 0, src[i].value, src[i].value_len);
            }
        }
    }

    return entity_header_index;
}

ssize_t h2o_find_header(const h2o_headers_t *headers, const h2o_token_t *token, ssize_t cursor)
{
    for (++cursor; cursor < headers->size; ++cursor) {
        if (headers->entries[cursor].name.token == token) {
            return cursor;
        }
    }
    return -1;
}

ssize_t h2o_find_header_by_str(const h2o_headers_t *headers, const char *name, size_t name_len, ssize_t cursor)
{
    for (++cursor; cursor < headers->size; ++cursor) {
        h2o_header_t *t = headers->entries + cursor;
        if (h2o_lcstris(t->name.str->base, t->name.str->len, name, name_len)) {
            return cursor;
        }
    }
    return -1;
}

void h2o_add_header(h2o_mempool_t *pool, h2o_headers_t *headers, const h2o_token_t *token, const char *value, size_t value_len)
{
    add_header(pool, headers, (uv_buf_t*)&token->buf, value, value_len);
}

void h2o_add_header_by_str(h2o_mempool_t *pool, h2o_headers_t *headers, const char *name, size_t name_len, int maybe_token, const char *value, size_t value_len)
{
    uv_buf_t *name_buf;

    if (maybe_token) {
        const h2o_token_t *token = h2o_lookup_token(name, name_len);
        if (token != NULL) {
            add_header(pool, headers, (uv_buf_t*)token, value, value_len);
            return;
        }
    }
    name_buf = h2o_mempool_alloc(pool, sizeof(uv_buf_t));
    name_buf->base = (char*)name;
    name_buf->len = name_len;
    add_header(pool, headers, name_buf, value, value_len);
}

void h2o_set_header(h2o_mempool_t *pool, h2o_headers_t *headers, const h2o_token_t *token, const char *value, size_t value_len, int overwrite_if_exists)
{
    ssize_t cursor = h2o_find_header(headers, token, -1);
    if (cursor != -1) {
        if (overwrite_if_exists) {
            uv_buf_t *slot = &headers->entries[cursor].value;
            slot->base = (char*)value;
            slot->len = value_len;
        }
    } else {
        h2o_add_header(pool, headers, token, value, value_len);
    }
}

void h2o_set_header_by_str(h2o_mempool_t *pool, h2o_headers_t *headers, const char *name, size_t name_len, int maybe_token, const char *value, size_t value_len, int overwrite_if_exists)
{
    ssize_t cursor;

    if (maybe_token) {
        const h2o_token_t *token = h2o_lookup_token(name, name_len);
        if (token != NULL) {
            h2o_set_header(pool, headers, token ,value, value_len, overwrite_if_exists);
            return;
        }
    }

    cursor = h2o_find_header_by_str(headers, name, name_len, -1);
    if (cursor != -1) {
        if (overwrite_if_exists) {
            uv_buf_t *slot = &headers->entries[cursor].value;
            slot->base = (char*)value;
            slot->len = value_len;
        }
    } else {
        uv_buf_t *name_buf = h2o_mempool_alloc(pool, sizeof(uv_buf_t));
        name_buf->base = (char*)name;
        name_buf->len = name_len;
        add_header(pool, headers, name_buf, value, value_len);
    }
}

ssize_t h2o_delete_header(h2o_headers_t *headers, ssize_t cursor)
{
    assert(cursor != -1);

    --headers->size;
    memmove(headers->entries + cursor, headers->entries + cursor + 1, sizeof(h2o_header_t) * (headers->size - cursor));

    return cursor;
}

uv_buf_t h2o_flatten_headers(h2o_mempool_t *pool, const h2o_headers_t *headers)
{
    const h2o_header_t *header, * header_end = headers->entries + headers->size;
    uv_buf_t ret;
    char *dst;

    /* determine the length */
    ret.len = 0;
    for (header = headers->entries; header != header_end; ++header) {
        ret.len += header->name.str->len + header->value.len + 4;
    }
    ret.len += 2;

    /* build */
    dst = ret.base = h2o_mempool_alloc(pool, ret.len);
    for (header = headers->entries; header != header_end; ++header) {
        memcpy(dst, header->name.str->base, header->name.str->len);
        dst += header->name.str->len;
        *dst++ = ':';
        *dst++ = ' ';
        memcpy(dst, header->value.base, header->value.len);
        dst += header->value.len;
        *dst++ = '\r';
        *dst++ = '\n';
    }
    *dst++ = '\r';
    *dst++ = '\n';
    assert(ret.len == dst - ret.base);

    return ret;
}
