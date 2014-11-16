/*
 * Copyright (c) 2014 DeNA Co., Ltd.
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
#include <stddef.h>
#include <stdio.h>
#include "h2o.h"

static h2o_header_t *add_header(h2o_mempool_t *pool, h2o_headers_t *headers, h2o_buf_t *name, const char *value, size_t value_len)
{
    h2o_header_t *slot;

    h2o_vector_reserve(pool, (h2o_vector_t*)headers, sizeof(h2o_header_t), headers->size + 1);
    slot = headers->entries + headers->size++;

    slot->name = name;
    slot->value.base = (char*)value;
    slot->value.len = value_len;

    return slot;
}

ssize_t h2o_init_headers(h2o_mempool_t *pool, h2o_headers_t *headers, const struct phr_header *src, size_t len, h2o_buf_t *connection, h2o_buf_t *host, h2o_buf_t *upgrade, h2o_buf_t *expect)
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
                if (name_token->is_init_header_special) {
                    if (name_token == H2O_TOKEN_HOST) {
                        host->base = (char*)src[i].value;
                        host->len = src[i].value_len;
                    } else if (name_token == H2O_TOKEN_CONTENT_LENGTH) {
                        if (entity_header_index == -1)
                            entity_header_index = i;
                    } else if (name_token == H2O_TOKEN_TRANSFER_ENCODING) {
                        entity_header_index = i;
                    } else if (name_token == H2O_TOKEN_EXPECT) {
                        expect->base = (char*)src[i].value;
                        expect->len = src[i].value_len;
                    } else if (name_token == H2O_TOKEN_UPGRADE) {
                        upgrade->base = (char*)src[i].value;
                        upgrade->len = src[i].value_len;
                    } else {
                        assert(!"logic flaw");
                    }
                } else {
                    h2o_header_t *added = add_header(pool, headers, (h2o_buf_t*)name_token, src[i].value, src[i].value_len);
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
        if (headers->entries[cursor].name == &token->buf) {
            return cursor;
        }
    }
    return -1;
}

ssize_t h2o_find_header_by_str(const h2o_headers_t *headers, const char *name, size_t name_len, ssize_t cursor)
{
    for (++cursor; cursor < headers->size; ++cursor) {
        h2o_header_t *t = headers->entries + cursor;
        if (h2o_lcstris(t->name->base, t->name->len, name, name_len)) {
            return cursor;
        }
    }
    return -1;
}

void h2o_add_header(h2o_mempool_t *pool, h2o_headers_t *headers, const h2o_token_t *token, const char *value, size_t value_len)
{
    add_header(pool, headers, (h2o_buf_t*)&token->buf, value, value_len);
}

void h2o_add_header_by_str(h2o_mempool_t *pool, h2o_headers_t *headers, const char *name, size_t name_len, int maybe_token, const char *value, size_t value_len)
{
    h2o_buf_t *name_buf;

    if (maybe_token) {
        const h2o_token_t *token = h2o_lookup_token(name, name_len);
        if (token != NULL) {
            add_header(pool, headers, (h2o_buf_t*)token, value, value_len);
            return;
        }
    }
    name_buf = h2o_mempool_alloc(pool, sizeof(h2o_buf_t));
    name_buf->base = (char*)name;
    name_buf->len = name_len;
    add_header(pool, headers, name_buf, value, value_len);
}

void h2o_set_header(h2o_mempool_t *pool, h2o_headers_t *headers, const h2o_token_t *token, const char *value, size_t value_len, int overwrite_if_exists)
{
    ssize_t cursor = h2o_find_header(headers, token, -1);
    if (cursor != -1) {
        if (overwrite_if_exists) {
            h2o_buf_t *slot = &headers->entries[cursor].value;
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
            h2o_buf_t *slot = &headers->entries[cursor].value;
            slot->base = (char*)value;
            slot->len = value_len;
        }
    } else {
        h2o_buf_t *name_buf = h2o_mempool_alloc(pool, sizeof(h2o_buf_t));
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
