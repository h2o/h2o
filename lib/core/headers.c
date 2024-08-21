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

static ssize_t add_header(h2o_mem_pool_t *pool, h2o_headers_t *headers, h2o_iovec_t *name, const char *orig_name, const char *value,
                          size_t value_len, h2o_header_flags_t flags)
{
    h2o_header_t *slot;

    h2o_vector_reserve(pool, headers, headers->size + 1);
    slot = headers->entries + headers->size++;

    slot->name = name;
    slot->value.base = (char *)value;
    slot->value.len = value_len;
    slot->orig_name = orig_name ? h2o_strdup(pool, orig_name, name->len).base : NULL;
    slot->flags = flags;
    return headers->size - 1;
}

static inline h2o_iovec_t *alloc_and_init_iovec(h2o_mem_pool_t *pool, const char *base, size_t len)
{
    h2o_iovec_t *iov = h2o_mem_alloc_pool(pool, *iov, 1);
    iov->base = (char *)base;
    iov->len = len;
    return iov;
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
        if (h2o_memis(t->name->base, t->name->len, name, name_len)) {
            return cursor;
        }
    }
    return -1;
}

ssize_t h2o_add_header(h2o_mem_pool_t *pool, h2o_headers_t *headers, const h2o_token_t *token, const char *orig_name,
                       const char *value, size_t value_len)
{
    return add_header(pool, headers, (h2o_iovec_t *)&token->buf, orig_name, value, value_len, (h2o_header_flags_t){0});
}

ssize_t h2o_add_header_by_str(h2o_mem_pool_t *pool, h2o_headers_t *headers, const char *lowercase_name, size_t lowercase_name_len,
                              int maybe_token, const char *orig_name, const char *value, size_t value_len)
{
    if (maybe_token) {
        const h2o_token_t *token = h2o_lookup_token(lowercase_name, lowercase_name_len);
        if (token != NULL) {
            return add_header(pool, headers, (h2o_iovec_t *)token, orig_name, value, value_len, (h2o_header_flags_t){0});
        }
    }
    return add_header(pool, headers, alloc_and_init_iovec(pool, lowercase_name, lowercase_name_len), orig_name, value, value_len,
                      (h2o_header_flags_t){0});
}

ssize_t h2o_set_header(h2o_mem_pool_t *pool, h2o_headers_t *headers, const h2o_token_t *token, const char *value, size_t value_len,
                       int overwrite_if_exists)
{
    ssize_t cursor = h2o_find_header(headers, token, -1);
    if (cursor != -1) {
        if (overwrite_if_exists) {
            headers->entries[cursor].value = h2o_iovec_init(value, value_len);
        }
        return cursor;
    } else {
        return h2o_add_header(pool, headers, token, NULL, value, value_len);
    }
}

ssize_t h2o_set_header_by_str(h2o_mem_pool_t *pool, h2o_headers_t *headers, const char *lowercase_name, size_t lowercase_name_len,
                              int maybe_token, const char *value, size_t value_len, int overwrite_if_exists)
{
    ssize_t cursor;

    if (maybe_token) {
        const h2o_token_t *token = h2o_lookup_token(lowercase_name, lowercase_name_len);
        if (token != NULL) {
            return h2o_set_header(pool, headers, token, value, value_len, overwrite_if_exists);
        }
    }

    cursor = h2o_find_header_by_str(headers, lowercase_name, lowercase_name_len, -1);
    if (cursor != -1) {
        if (overwrite_if_exists) {
            headers->entries[cursor].value = h2o_iovec_init(value, value_len);
        }
        return cursor;
    } else {
        return add_header(pool, headers, alloc_and_init_iovec(pool, lowercase_name, lowercase_name_len), NULL, value, value_len,
                          (h2o_header_flags_t){0});
    }
}

ssize_t h2o_set_header_token(h2o_mem_pool_t *pool, h2o_headers_t *headers, const h2o_token_t *token, const char *value,
                             size_t value_len)
{
    ssize_t found = -1;
    size_t i;
    for (i = 0; i != headers->size; ++i) {
        if (headers->entries[i].name == &token->buf) {
            if (h2o_contains_token(headers->entries[i].value.base, headers->entries[i].value.len, value, value_len, ','))
                return -1;
            found = i;
        }
    }
    if (found != -1) {
        h2o_header_t *dest = headers->entries + found;
        dest->value = h2o_concat(pool, dest->value, h2o_iovec_init(H2O_STRLIT(", ")), h2o_iovec_init(value, value_len));
        return found;
    } else {
        return h2o_add_header(pool, headers, token, NULL, value, value_len);
    }
}

ssize_t h2o_delete_header(h2o_headers_t *headers, ssize_t cursor)
{
    assert(cursor != -1);

    --headers->size;
    memmove(headers->entries + cursor, headers->entries + cursor + 1, sizeof(h2o_header_t) * (headers->size - cursor));

    return cursor;
}
