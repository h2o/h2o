#include <stddef.h>
#include "h2o.h"

struct st_h2o_header_t {
    union {
        h2o_token_t *token;
        uv_buf_t *str;
    } name;
    uv_buf_t value;
};

struct st_h2o_headers_chunk_t {
    size_t capacity;
    size_t size;
    struct st_h2o_headers_chunk_t *next;
    struct st_h2o_header_t headers[1];
};

static struct st_h2o_headers_chunk_t *allocate_headers_chunk(h2o_mempool_t *pool, size_t capacity)
{
    struct st_h2o_headers_chunk_t *chunk = h2o_mempool_alloc(pool, offsetof(struct st_h2o_headers_chunk_t, headers) + sizeof(struct st_h2o_header_t) * capacity);
    chunk->capacity = capacity;
    chunk->size = 0;
    chunk->next = NULL;
    return chunk;
}

static inline size_t iterator_get_next(const h2o_headers_t *headers, h2o_header_iterator_t *iter)
{
    size_t index;

    if (iter->value == NULL) {
        /* search from top */
        iter->_chunk_ref = (struct st_h2o_headers_chunk_t**)&headers->_first;
        index = 0;
    } else {
        /* advance to next pos */
        index = H2O_STRUCT_FROM_MEMBER(struct st_h2o_header_t, value, iter->value) - (*iter->_chunk_ref)->headers;
        assert(index < (*iter->_chunk_ref)->size);
        ++index;
    }

    return index;
}

static struct st_h2o_header_t *add_header(h2o_mempool_t *pool, h2o_headers_t *headers, uv_buf_t *name, const char *value, size_t value_len)
{
    struct st_h2o_headers_chunk_t *chunk;
    struct st_h2o_header_t *slot;

    /* determine the chunk to which we should add the header */
    if (*headers->_last_ref == NULL || (*headers->_last_ref)->size == (*headers->_last_ref)->capacity) {
        chunk = allocate_headers_chunk(pool, 8);
        if (*headers->_last_ref == NULL) {
            *headers->_last_ref = chunk;
        } else {
            (*headers->_last_ref)->next = chunk;
            headers->_last_ref = &(*headers->_last_ref)->next;
        }
    } else {
        chunk = *headers->_last_ref;
    }

    /* set */
    slot = chunk->headers + chunk->size++;
    slot->name.str = name;
    slot->value.base = (char*)value;
    slot->value.len = value_len;
    ++headers->count;

    return slot;
}

void h2o_clear_headers(h2o_headers_t *headers)
{
    headers->count = 0;
    headers->_first = NULL;
    headers->_last_ref = &headers->_first;
}

void h2o_init_headers(h2o_mempool_t *pool, h2o_headers_t *headers, const struct phr_header *src, size_t len, size_t extra, uv_buf_t *connection, uv_buf_t *host, uv_buf_t *upgrade)
{
    size_t i;

    assert(headers->count == 0);
    headers->_last_ref = &headers->_first;

    /* setup */
    if (len + extra != 0) {
        *headers->_last_ref = allocate_headers_chunk(pool, len + extra);
        for (i = 0; i != len; ++i) {
            const h2o_token_t *name_token = h2o_lookup_token(src[i].name, src[i].name_len);
            if (name_token != NULL) {
                if (name_token == H2O_TOKEN_HOST) {
                    host->base = (char*)src[i].value;
                    host->len = src[i].value_len;
                } else if (name_token == H2O_TOKEN_UPGRADE) {
                    upgrade->base = (char*)src[i].value;
                    upgrade->len = src[i].value_len;
                } else {
                    struct st_h2o_header_t *added = add_header(pool, headers, (uv_buf_t*)name_token, src[i].value, src[i].value_len);
                    if (name_token == H2O_TOKEN_CONNECTION)
                        *connection = added->value;
                }
            } else {
                h2o_add_header_by_str(pool, headers, src[i].name, src[i].name_len, 0, src[i].value, src[i].value_len);
            }
        }
    }
}

h2o_header_iterator_t h2o_next_header(const h2o_headers_t *headers, h2o_header_iterator_t iter, uv_buf_t **name)
{
    size_t index = iterator_get_next(headers, &iter);
    if (*iter._chunk_ref != NULL && index < (*iter._chunk_ref)->size) {
        struct st_h2o_header_t *header = (*iter._chunk_ref)->headers + index;
        iter.value = &header->value;
        *name = header->name.str;
    } else {
        iter.value = NULL;
    }
    return iter;
}

h2o_header_iterator_t h2o_find_next_header(const h2o_headers_t *headers, const h2o_token_t *token, h2o_header_iterator_t iter)
{
    size_t index = iterator_get_next(headers, &iter);

    for (; *iter._chunk_ref != NULL; iter._chunk_ref = &(*iter._chunk_ref)->next) {
        for (; index < (*iter._chunk_ref)->size; ++index) {
            struct st_h2o_header_t *t = (*iter._chunk_ref)->headers + index;
            if (t->name.token == token) {
                /* found */
                iter.value = &t->value;
                return iter;
            }
        }
    }

    /* not found */
    iter._chunk_ref = NULL;
    iter.value = NULL;
    return iter;
}

h2o_header_iterator_t h2o_find_next_header_by_str(const h2o_headers_t *headers, const char *name, size_t name_len, h2o_header_iterator_t iter)
{
    size_t index = iterator_get_next(headers, &iter);

    for (; *iter._chunk_ref != NULL; iter._chunk_ref = &(*iter._chunk_ref)->next) {
        for (; index < (*iter._chunk_ref)->size; ++index) {
            struct st_h2o_header_t *t = (*iter._chunk_ref)->headers + index;
            if (h2o_lcstris(t->name.str->base, t->name.str->len, name, name_len)) {
                /* found */
                iter.value = &t->value;
                return iter;
            }
        }
    }

    /* not found */
    iter._chunk_ref = NULL;
    iter.value = NULL;
    return iter;
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
    h2o_header_iterator_t iter = h2o_find_header(headers, token);
    if (iter.value != NULL) {
        if (overwrite_if_exists) {
            iter.value->base = (char*)value;
            iter.value->len = value_len;
        }
    } else {
        h2o_add_header(pool, headers, token, value, value_len);
    }
}

void h2o_set_header_by_str(h2o_mempool_t *pool, h2o_headers_t *headers, const char *name, size_t name_len, int maybe_token, const char *value, size_t value_len, int overwrite_if_exists)
{
    h2o_header_iterator_t iter;

    if (maybe_token) {
        const h2o_token_t *token = h2o_lookup_token(name, name_len);
        if (token != NULL) {
            h2o_set_header(pool, headers, token ,value, value_len, overwrite_if_exists);
            return;
        }
    }

    iter = h2o_find_header_by_str(headers, name, name_len);
    if (iter.value != NULL) {
        if (overwrite_if_exists) {
            iter.value->base = (char*)value;
            iter.value->len = value_len;
        }
    } else {
        uv_buf_t *name_buf = h2o_mempool_alloc(pool, sizeof(uv_buf_t));
        name_buf->base = (char*)name;
        name_buf->len = name_len;
        add_header(pool, headers, name_buf, value, value_len);
    }
}

h2o_header_iterator_t h2o_delete_header(h2o_headers_t *headers, h2o_header_iterator_t iter)
{
    assert(iter._chunk_ref != NULL);

    --headers->count;
    if (--(*iter._chunk_ref)->size == 0) {
        struct st_h2o_headers_chunk_t *new_next = (*iter._chunk_ref)->next;
        if (*headers->_last_ref == *iter._chunk_ref) {
            *headers->_last_ref = new_next;
        }
        *iter._chunk_ref = (*iter._chunk_ref)->next;
        if (*iter._chunk_ref != NULL) {
            iter.value = &(*iter._chunk_ref)->headers[0].value;
        } else {
            iter._chunk_ref = NULL;
            iter.value = NULL;
        }
    } else {
        size_t index = H2O_STRUCT_FROM_MEMBER(struct st_h2o_header_t, value, iter.value) - (*iter._chunk_ref)->headers;
        memmove((*iter._chunk_ref)->headers + index, (*iter._chunk_ref)->headers + index + 1, ((*iter._chunk_ref)->size - index) * sizeof(struct st_h2o_header_t));
    }

    return iter;
}

uv_buf_t h2o_flatten_headers(h2o_mempool_t *pool, const h2o_headers_t *headers)
{
    struct st_h2o_headers_chunk_t *chunk;
    size_t index;
    uv_buf_t ret;
    char *dst;

    /* determine the length */
    ret.len = 0;
    if (headers->_first != NULL) {
        for (chunk = headers->_first; chunk != NULL; chunk = chunk->next) {
            for (index = 0; index != chunk->size; ++index) {
                ret.len += chunk->headers[index].name.str->len + chunk->headers[index].value.len + 4;
            }
        }
    }
    ret.len += 2;

    /* build */
    dst = ret.base = h2o_mempool_alloc(pool, ret.len);
    if (headers->_first != NULL) {
        for (chunk = headers->_first; chunk != NULL; chunk = chunk->next) {
            for (index = 0; index != chunk->size; ++index) {
                memcpy(dst, chunk->headers[index].name.str->base, chunk->headers[index].name.str->len);
                dst += chunk->headers[index].name.str->len;
                *dst++ = ':';
                *dst++ = ' ';
                memcpy(dst, chunk->headers[index].value.base, chunk->headers[index].value.len);
                dst += chunk->headers[index].value.len;
                *dst++ = '\r';
                *dst++ = '\n';
            }
        }
    }
    *dst++ = '\r';
    *dst++ = '\n';
    assert(ret.len == dst - ret.base);

    return ret;
}
