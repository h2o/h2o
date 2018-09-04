/*
 * Copyright (c) 2018 Fastly, Kazuho Oku
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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "h2o.h"
#include "h2o/hpack.h"
#include "h2o/qpack.h"

/**
 * a mem-shared object that contains the name and value of a header field
 */
struct st_h2o_qpack_header_t {
    h2o_iovec_t *name;
    size_t value_len;
    h2o_iovec_t _name_buf;
    char value[1];
};

struct st_h2o_qpack_header_table_t {
    /**
     * pointers to the buffer structure; [buf_start, buf_end) is the memory allocated, [first, last) are the active entries
     */
    struct st_h2o_qpack_header_t **buf_start, **first, **last, **buf_end;
    /**
     * index of `first`
     */
    int64_t base_offset;
    /**
     * current and maximum size
     */
    size_t num_bytes, max_size;
};

struct st_h2o_qpack_blocked_streams_t {
    int64_t stream_id;
    int64_t largest_ref;
};

struct st_h2o_qpack_decoder_t {
    /**
     *
     */
    h2o_qpack_context_t *ctx;
    /**
     *
     */
    struct st_h2o_qpack_header_table_t table;
    /**
     * number of updates since last sync
     */
    uint32_t insert_count;
    /**
     * contains list of blocked streams (sorted in the ascending order of largest_ref)
     */
    H2O_VECTOR(struct st_h2o_qpack_blocked_streams_t) blocked_streams;
};

#define MAX_HEADER_NAME_LENGTH 128
#define MAX_HEADER_VALUE_LENGTH 4096

const char *h2o_qpack_err_header_name_too_long = "header name too long";
const char *h2o_qpack_err_header_value_too_long = "header value too long";
const char *h2o_qpack_err_header_exceeds_table_size = "header exceeds table size";
const char *h2o_qpack_err_invalid_max_size = "invalid max size";
const char *h2o_qpack_err_invalid_static_reference = "invalid static reference";
const char *h2o_qpack_err_invalid_dynamic_reference = "invalid dynamic reference";
const char *h2o_qpack_err_invalid_duplicate = "invalid duplicate";
const char *h2o_qpack_err_invalid_pseudo_header = "invalid pseudo header";

static void header_table_init(struct st_h2o_qpack_header_table_t *table, size_t max_size)
{
    *table = (struct st_h2o_qpack_header_table_t){NULL, NULL, NULL, NULL, 1, 0, max_size};
}

static void header_table_dispose(struct st_h2o_qpack_header_table_t *table)
{
    while (table->first != table->last)
        h2o_mem_release_shared(*table->first++);
    free(table->buf_start);
}

static void header_table_evict(struct st_h2o_qpack_header_table_t *table, size_t delta)
{
    while (table->first != table->last) {
        if (table->num_bytes + delta <= table->max_size)
            return;
        table->num_bytes -= (*table->first)->name->len + (*table->first)->value_len;
        h2o_mem_release_shared(*table->first);
        *table->first++ = NULL;
        ++table->base_offset;
    }
    assert(table->num_bytes == 0);
}

static void header_table_insert(struct st_h2o_qpack_header_table_t *table, struct st_h2o_qpack_header_t *added)
{
    header_table_evict(table, added->name->len + added->value_len);

    if (table->last == table->buf_end) {
        size_t count = table->last - table->first, new_capacity = count <= 2 ? 4 : count * 2;
        if (new_capacity > table->buf_end - table->buf_start) {
            struct st_h2o_qpack_header_t **newbuf = h2o_mem_alloc(sizeof(*newbuf) * new_capacity);
            memcpy(newbuf, table->first, sizeof(*newbuf) * count);
            free(table->buf_start);
            table->buf_start = newbuf;
            table->first = newbuf;
            table->last = newbuf + count;
            table->buf_end = newbuf + new_capacity;
        } else {
            assert(table->buf_start != table->first);
            memmove(table->buf_start, table->first, sizeof(*table->buf_start) * count);
            table->first = table->buf_start;
            table->last = table->buf_start + count;
        }
        memset(table->last, 0, sizeof(*table->last) * (table->buf_end - table->last));
    }
    *table->last++ = added;
    table->num_bytes += added->name->len + added->value_len;
}

static const h2o_hpack_static_table_entry_t *resolve_static_abs(int64_t index, const char **err_desc)
{
    if (index == 0 || index > sizeof(h2o_hpack_static_table) / sizeof(h2o_hpack_static_table[0])) {
        *err_desc = h2o_qpack_err_invalid_static_reference;
        return NULL;
    }
    return h2o_hpack_static_table + index - 1;
}

static struct st_h2o_qpack_header_t *resolve_dynamic_abs(struct st_h2o_qpack_header_table_t *table, int64_t index,
                                                         const char **err_desc)
{
    if (index < table->base_offset || index >= table->last - table->first) {
        *err_desc = h2o_qpack_err_invalid_dynamic_reference;
        return NULL;
    }
    return table->first[index];
}

static size_t decode_value(int is_huff, const uint8_t *src, size_t srclen, char *outbuf, const char **err_desc)
{
    size_t outlen;

    if (is_huff) {
        if ((outlen = h2o_hpack_decode_huffman(outbuf, src, srclen, 0, err_desc)) == SIZE_MAX)
            return SIZE_MAX;
    } else {
        h2o_hpack_validate_header_value((void *)src, srclen, err_desc);
        memcpy(outbuf, src, srclen);
        outlen = srclen;
    }
    outbuf[outlen] = '\0';

    return outlen;
}

h2o_qpack_decoder_t *h2o_qpack_create_decoder(h2o_qpack_context_t *ctx)
{
    h2o_qpack_decoder_t *qpack = h2o_mem_alloc(sizeof(*qpack));

    qpack->ctx = ctx;
    header_table_init(&qpack->table, ctx->header_table_size);
    qpack->insert_count = 0;
    memset(&qpack->blocked_streams, 0, sizeof(qpack->blocked_streams));

    return qpack;
}

void h2o_qpack_destroy_decoder(h2o_qpack_decoder_t *qpack)
{
    header_table_dispose(&qpack->table);
    free(qpack->blocked_streams.entries);
    free(qpack);
}

static void decoder_link_blocked(h2o_qpack_decoder_t *qpack, int64_t stream_id, int64_t largest_ref)
{
    size_t i;

    h2o_vector_reserve(NULL, &qpack->blocked_streams, qpack->blocked_streams.size + 1);
    for (i = qpack->blocked_streams.size; i != 0; --i)
        if (qpack->blocked_streams.entries[i - 1].largest_ref <= largest_ref)
            break;
    if (i != qpack->blocked_streams.size)
        memmove(qpack->blocked_streams.entries + i + 1, qpack->blocked_streams.entries + i,
                sizeof(qpack->blocked_streams.entries[0]) * (qpack->blocked_streams.size - i));
    qpack->blocked_streams.entries[i] = (struct st_h2o_qpack_blocked_streams_t){stream_id, largest_ref};
    ++qpack->blocked_streams.size;
}

size_t h2o_qpack_decoder_shift_unblocked_stream(h2o_qpack_decoder_t *qpack, int64_t *stream_ids, size_t capacity)
{
    int64_t largest_ref = qpack->table.base_offset + (qpack->table.last - qpack->table.first) - 1;
    size_t i, imax;

    imax = qpack->blocked_streams.size;
    if (imax > capacity)
        imax = capacity;

    for (i = 0; i < imax && qpack->blocked_streams.entries[i].largest_ref <= largest_ref; ++i)
        stream_ids[i] = qpack->blocked_streams.entries[i].stream_id;

    if (i != qpack->blocked_streams.size)
        memmove(qpack->blocked_streams.entries, qpack->blocked_streams.entries + i,
                sizeof(qpack->blocked_streams.entries[0]) * (qpack->blocked_streams.size - i));
    qpack->blocked_streams.size -= i;

    return i;
}

static void decoder_insert(h2o_qpack_decoder_t *qpack, struct st_h2o_qpack_header_t *added)
{
    ++qpack->insert_count;
    header_table_insert(&qpack->table, added);
}

static int decode_value_and_insert(h2o_qpack_decoder_t *qpack, struct st_h2o_qpack_header_t *header, int is_huff,
                                   const uint8_t *qstr, size_t qstrlen, const char **err_desc)
{
    if ((header->value_len = decode_value(is_huff, qstr, qstrlen, header->value, err_desc)) == SIZE_MAX)
        goto Fail;
    if (header->name->len + header->value_len > qpack->table.max_size) {
        *err_desc = h2o_qpack_err_header_exceeds_table_size;
        goto Fail;
    }
    decoder_insert(qpack, header);
    return 0;
Fail:
    h2o_mem_release_shared(header);
    return H2O_HTTP2_ERROR_COMPRESSION;
}

static int insert_token_header(h2o_qpack_decoder_t *qpack, const h2o_token_t *name, int value_is_huff, const uint8_t *value,
                               size_t value_len, const char **err_desc)
{
    struct st_h2o_qpack_header_t *header =
        h2o_mem_alloc_shared(NULL, offsetof(struct st_h2o_qpack_header_t, value) + (value_len * 2) + 1, NULL);

    header->name = (h2o_iovec_t *)&name->buf;
    return decode_value_and_insert(qpack, header, value_is_huff, value, value_len, err_desc);
}

static int insert_literal_header(h2o_qpack_decoder_t *qpack, const char *name, size_t name_len, int value_is_huff,
                                 const uint8_t *value, size_t value_len, const char **err_desc)
{
    size_t value_capacity = (value_is_huff ? value_len * 2 : value_len) + 1;
    struct st_h2o_qpack_header_t *header =
        h2o_mem_alloc_shared(NULL, offsetof(struct st_h2o_qpack_header_t, value) + value_capacity + name_len + 1, NULL);

    header->_name_buf = h2o_iovec_init(header->value + value_capacity, name_len);
    memcpy(header->_name_buf.base, name, name_len);
    header->_name_buf.base[name_len] = '\0';
    header->_name_buf.len = name_len;
    header->name = &header->_name_buf;

    return decode_value_and_insert(qpack, header, value_is_huff, value, value_len, err_desc);
}

static int insert_with_name_reference(h2o_qpack_decoder_t *qpack, int name_is_static, int64_t name_index, int value_is_huff,
                                      const uint8_t *value, int64_t value_len, const char **err_desc)
{
    if (value_len >= MAX_HEADER_VALUE_LENGTH) {
        *err_desc = h2o_qpack_err_header_value_too_long;
        return H2O_HTTP2_ERROR_COMPRESSION;
    }

    if (name_is_static) {
        const struct st_h2o_hpack_static_table_entry_t *ref;
        if ((ref = resolve_static_abs(name_index, err_desc)) == NULL)
            return H2O_HTTP2_ERROR_COMPRESSION;
        return insert_token_header(qpack, ref->name, value_is_huff, value, value_len, err_desc);
    } else {
        struct st_h2o_qpack_header_t *ref;
        int64_t base_index = qpack->table.base_offset + (qpack->table.last - qpack->table.first) - 1;
        if (name_index > base_index) {
            *err_desc = h2o_qpack_err_invalid_dynamic_reference;
            return H2O_HTTP2_ERROR_COMPRESSION;
        }
        if ((ref = resolve_dynamic_abs(&qpack->table, base_index - name_index, err_desc)) == NULL)
            return H2O_HTTP2_ERROR_COMPRESSION;
        if (h2o_iovec_is_token(ref->name)) {
            return insert_token_header(qpack, (h2o_token_t *)ref->name, value_is_huff, value, value_len, err_desc);
        } else {
            return insert_literal_header(qpack, ref->name->base, ref->name->len, value_is_huff, value, value_len, err_desc);
        }
    }
}

static int insert_without_name_reference(h2o_qpack_decoder_t *qpack, int qnhuff, const uint8_t *qn, int64_t qnlen, int qvhuff,
                                         const uint8_t *qv, int64_t qvlen, const char **err_desc)
{
    h2o_iovec_t name;

    if (qnlen >= MAX_HEADER_NAME_LENGTH) {
        *err_desc = h2o_qpack_err_header_name_too_long;
        return H2O_HTTP2_ERROR_COMPRESSION;
    }
    if (qvlen >= MAX_HEADER_VALUE_LENGTH) {
        *err_desc = h2o_qpack_err_header_value_too_long;
        return H2O_HTTP2_ERROR_COMPRESSION;
    }

    if (qnhuff) {
        name.base = alloca(qnlen * 2);
        if ((name.len = h2o_hpack_decode_huffman(name.base, qn, qnlen, 1, err_desc)) == SIZE_MAX)
            return H2O_HTTP2_ERROR_COMPRESSION;
    } else {
        if (!h2o_hpack_validate_header_name((void *)qn, qnlen, err_desc))
            return H2O_HTTP2_ERROR_COMPRESSION;
        name = h2o_iovec_init(qn, qnlen);
    }

    const h2o_token_t *token;
    if ((token = h2o_lookup_token(name.base, name.len)) != NULL) {
        return insert_token_header(qpack, token, qvhuff, qv, qvlen, err_desc);
    } else {
        return insert_literal_header(qpack, name.base, name.len, qvhuff, qv, qvlen, err_desc);
    }
}

static int duplicate(h2o_qpack_decoder_t *qpack, int64_t name_index, const char **err_desc)
{
    if (name_index >= qpack->table.last - qpack->table.first) {
        *err_desc = h2o_qpack_err_invalid_duplicate;
        return H2O_HTTP2_ERROR_COMPRESSION;
    }

    struct st_h2o_qpack_header_t *header = qpack->table.first[name_index];
    h2o_mem_addref_shared(header);
    decoder_insert(qpack, header);
    return 0;
}

static int dynamic_table_size_update(h2o_qpack_decoder_t *qpack, int64_t max_size, const char **err_desc)
{
    if (max_size > qpack->ctx->header_table_size) {
        *err_desc = h2o_qpack_err_invalid_max_size;
        return H2O_HTTP2_ERROR_COMPRESSION;
    }

    qpack->table.max_size = max_size;
    header_table_evict(&qpack->table, 0);
    return 0;
}

int h2o_qpack_decoder_update(h2o_qpack_decoder_t *qpack, const uint8_t **input, size_t input_len, const char **err_desc)
{
    const uint8_t *src = *input, *src_end = src + input_len;
    int ret = 0;

    while (src != src_end && ret == 0) {
        switch (*src >> 5) {
        default: /* insert with name reference */ {
            int64_t name_index, value_len;
            int name_is_static = (*src & 0x40) != 0;
            if ((name_index = h2o_hpack_decode_int(&src, src_end, 6)) == -1)
                goto Exit;
            if (src == src_end)
                goto Exit;
            int value_is_huff = (*src & 0x80) != 0;
            if ((value_len = h2o_hpack_decode_int(&src, src_end, 7)) == -1)
                goto Exit;
            if (!(src + value_len <= src_end))
                goto Exit;
            ret = insert_with_name_reference(qpack, name_is_static, name_index, value_is_huff, src, value_len, err_desc);
            src += value_len;
        } break;
        case 2:
        case 3: /* insert without name reference */ {
            int64_t name_len, value_len;
            int name_is_huff = (*src & 0x20) != 0;
            if ((name_len = h2o_hpack_decode_int(&src, src_end, 5)) == -1)
                goto Exit;
            if (!(src + name_len < src_end))
                goto Exit;
            const uint8_t *name = src;
            int value_is_huff = (*src & 0x80) != 0;
            if ((value_len = h2o_hpack_decode_int(&src, src_end, 7)) == -1)
                goto Exit;
            if (!(src + value_len <= src_end))
                goto Exit;
            ret = insert_without_name_reference(qpack, name_is_huff, name, name_len, value_is_huff, src, value_len, err_desc);
            src += value_len;
        } break;
        case 0: /* duplicate */ {
            int64_t name_index;
            if ((name_index = h2o_hpack_decode_int(&src, src_end, 5)) == -1)
                goto Exit;
            ret = duplicate(qpack, name_index, err_desc);
        } break;
        case 1: /* dynamic table size update */ {
            int64_t max_size;
            if ((max_size = h2o_hpack_decode_int(&src, src_end, 5)) == -1)
                goto Exit;
            ret = dynamic_table_size_update(qpack, max_size, err_desc);
        } break;
        }
        *input = src;
    }

Exit:
    return ret;
}

/* enough space for ack or cancellation and sync */
#define DECODER_SEND_BUF_SIZE ((1 + H2O_HPACK_ENCODE_INT_MAX_LENGTH) * 2)

static uint8_t *emit_state_sync(h2o_qpack_decoder_t *qpack, uint8_t *dst)
{
    if (qpack->insert_count != 0) {
        *dst = 0;
        dst = h2o_hpack_encode_int(dst, qpack->insert_count, 6);
        qpack->insert_count = 0;
    }
    return dst;
}

int h2o_qpack_decoder_send_state_sync(h2o_qpack_decoder_t *qpack, quicly_sendbuf_t *sendbuf)
{
    uint8_t buf[DECODER_SEND_BUF_SIZE], *dst = buf;

    dst = emit_state_sync(qpack, dst);
    if (dst == buf)
        return 0;
    return quicly_sendbuf_write(sendbuf, buf, dst - buf, NULL);
}

int h2o_qpack_decoder_send_header_ack(h2o_qpack_decoder_t *qpack, quicly_sendbuf_t *sendbuf, int64_t stream_id)
{
    uint8_t buf[DECODER_SEND_BUF_SIZE], *dst = buf;

    *dst = 0x80;
    dst = h2o_hpack_encode_int(dst, stream_id, 7);
    emit_state_sync(qpack, dst);

    return quicly_sendbuf_write(sendbuf, buf, dst - buf, NULL);
}

int h2o_qpack_decoder_send_stream_cancel(h2o_qpack_decoder_t *qpack, quicly_sendbuf_t *sendbuf, int64_t stream_id)
{
    uint8_t buf[DECODER_SEND_BUF_SIZE], *dst = buf;

    *dst = 0x40;
    dst = h2o_hpack_encode_int(dst, stream_id, 6);
    emit_state_sync(qpack, dst);

    return quicly_sendbuf_write(sendbuf, buf, dst - buf, NULL);
}

static const h2o_hpack_static_table_entry_t *resolve_static(const uint8_t **src, const uint8_t *src_end, unsigned prefix_bits,
                                                            const char **err_desc)
{
    int64_t index;

    if ((index = h2o_hpack_decode_int(src, src_end, prefix_bits)) == -1)
        goto Fail;
    if (index == 0)
        goto Fail;
    --index;
    if (!(index < sizeof(h2o_hpack_static_table) / sizeof(h2o_hpack_static_table[0])))
        goto Fail;
    return h2o_hpack_static_table + index;

Fail:
    *err_desc = h2o_qpack_err_invalid_static_reference;
    return NULL;
}

static struct st_h2o_qpack_header_t *resolve_dynamic(struct st_h2o_qpack_header_table_t *table, int64_t base_index,
                                                     const uint8_t **src, const uint8_t *src_end, unsigned prefix_bits,
                                                     const char **err_desc)
{
    int64_t off;

    if ((off = h2o_hpack_decode_int(src, src_end, prefix_bits)) == -1 || off >= base_index) {
        *err_desc = h2o_qpack_err_invalid_dynamic_reference;
        return NULL;
    }
    return resolve_dynamic_abs(table, base_index - off, err_desc);
}

static struct st_h2o_qpack_header_t *resolve_dynamic_postbase(struct st_h2o_qpack_header_table_t *table, int64_t base_index,
                                                              const uint8_t **src, const uint8_t *src_end, unsigned prefix_bits,
                                                              const char **err_desc)
{
    int64_t off;

    if ((off = h2o_hpack_decode_int(src, src_end, prefix_bits)) == -1 || INT64_MAX - off < base_index + 1) {
        *err_desc = h2o_qpack_err_invalid_dynamic_reference;
        return NULL;
    }
    return resolve_dynamic_abs(table, base_index + off + 1, err_desc);
}

static h2o_iovec_t *decode_header_name_literal(h2o_mem_pool_t *pool, const uint8_t **src, const uint8_t *src_end,
                                               unsigned prefix_bits, const char **err_desc)
{
    h2o_iovec_t buf = {NULL};
    const h2o_token_t *token;
    int is_huff;
    int64_t len;

    /* obtain flags and length */
    is_huff = (**src >> prefix_bits) & 1;
    if ((len = h2o_hpack_decode_int(src, src_end, prefix_bits)) == -1 || len > MAX_HEADER_NAME_LENGTH) {
        *err_desc = h2o_qpack_err_header_name_too_long;
        goto Fail;
    }
    if (src_end - *src < len)
        goto Fail;

    /* decode and convert to token (if possible) */
    if (is_huff) {
        buf.base = h2o_mem_alloc_pool(pool, char, len * 2 + 1);
        if ((buf.len = h2o_hpack_decode_huffman(buf.base, *src, len, 1, err_desc)) == SIZE_MAX)
            goto Fail;
        buf.base[buf.len] = '\0';
        token = h2o_lookup_token(buf.base, buf.len);
    } else if ((token = h2o_lookup_token((const char *)*src, len)) != NULL) {
        /* was an uncompressed token */
    } else {
        if (!h2o_hpack_validate_header_name((void *)*src, len, err_desc))
            goto Fail;
        buf = h2o_strdup(pool, (void *)src, len);
    }
    *src += len;

    /* return the result */
    if (token != NULL)
        return (h2o_iovec_t *)&token->buf;
    h2o_iovec_t *ret = h2o_mem_alloc_pool(pool, h2o_iovec_t, 1);
    *ret = buf;
    return ret;

Fail:
    return NULL;
}

static h2o_iovec_t decode_header_value_literal(h2o_mem_pool_t *pool, const uint8_t **src, const uint8_t *src_end,
                                               const char **err_desc)
{
    h2o_iovec_t buf;
    int is_huff = (**src & 0x80) != 0;
    int64_t len;

    if ((len = h2o_hpack_decode_int(src, src_end, 7)) == -1 || len > MAX_HEADER_VALUE_LENGTH) {
        *err_desc = h2o_qpack_err_header_value_too_long;
        goto Fail;
    }
    if (src_end - *src < len)
        goto Fail;

    buf.base = h2o_mem_alloc_pool(pool, char, is_huff ? len * 2 + 1 : len + 1);
    if ((buf.len = decode_value(is_huff, *src, len, buf.base, err_desc)) == SIZE_MAX)
        goto Fail;
    *src += len;

    return buf;
Fail:
    return h2o_iovec_init(NULL, 0);
}

struct st_h2o_qpack_decode_header_ctx_t {
    h2o_qpack_decoder_t *qpack;
    int64_t base_index;
};

static int decode_header(void *_ctx, h2o_mem_pool_t *pool, h2o_iovec_t **name, h2o_iovec_t *value, const uint8_t **src,
                         const uint8_t *src_end, const char **err_desc)
{
    struct st_h2o_qpack_decode_header_ctx_t *ctx = _ctx;
    h2o_qpack_decoder_t *qpack = ctx->qpack;
    int64_t base_index = ctx->base_index;

    switch (**src >> 4) {
    case 12:
    case 13:
    case 14:
    case 15: /* indexed static header field */ {
        const h2o_hpack_static_table_entry_t *entry;
        if ((entry = resolve_static(src, src_end, 6, err_desc)) == NULL)
            goto Fail;
        *name = (h2o_iovec_t *)&entry->name->buf;
        *value = entry->value;
    } break;
    case 8:
    case 9:
    case 10:
    case 11: /* indexed dynamic header field */ {
        struct st_h2o_qpack_header_t *entry;
        if ((entry = resolve_dynamic(&qpack->table, base_index, src, src_end, 6, err_desc)) == NULL)
            goto Fail;
        h2o_mem_link_shared(pool, entry);
        *name = entry->name;
        *value = h2o_iovec_init(entry->value, entry->value_len);
    } break;
    case 5:
    case 7: /* literal header field with static name reference */ {
        const h2o_hpack_static_table_entry_t *entry;
        if ((entry = resolve_static(src, src_end, 4, err_desc)) == NULL)
            goto Fail;
        *name = (h2o_iovec_t *)&entry->name->buf;
        if ((*value = decode_header_value_literal(pool, src, src_end, err_desc)).base == NULL)
            goto Fail;
    } break;
    case 4:
    case 6: /* literal header field with dynamic name reference */ {
        struct st_h2o_qpack_header_t *entry;
        if ((entry = resolve_dynamic(&qpack->table, base_index, src, src_end, 6, err_desc)) == NULL)
            goto Fail;
        h2o_mem_link_shared(pool, entry);
        *name = entry->name;
        if ((*value = decode_header_value_literal(pool, src, src_end, err_desc)).base == NULL)
            goto Fail;
    } break;
    case 2:
    case 3: /* literal header field without name reference */ {
        if ((*name = decode_header_name_literal(pool, src, src_end, 3, err_desc)) == NULL)
            goto Fail;
        if ((*value = decode_header_value_literal(pool, src, src_end, err_desc)).base == NULL)
            goto Fail;
    } break;
    case 1: /* indexed header field with post-base index */ {
        struct st_h2o_qpack_header_t *entry;
        if ((entry = resolve_dynamic_postbase(&qpack->table, base_index, src, src_end, 3, err_desc)) == NULL)
            goto Fail;
        h2o_mem_link_shared(pool, entry);
        *name = entry->name;
        *value = h2o_iovec_init(entry->value, entry->value_len);
    } break;
    case 0: /* literal header field with post-base name reference */ {
        struct st_h2o_qpack_header_t *entry;
        if ((entry = resolve_dynamic_postbase(&qpack->table, base_index, src, src_end, 3, err_desc)) == NULL)
            goto Fail;
        h2o_mem_link_shared(pool, entry);
        *name = entry->name;
        if ((*value = decode_header_value_literal(pool, src, src_end, err_desc)).base == NULL)
            goto Fail;
    } break;
    }

    return 0;
Fail:
    return H2O_HTTP2_ERROR_COMPRESSION;
}

int h2o_qpack_parse_headers(h2o_req_t *req, h2o_qpack_decoder_t *qpack, int64_t stream_id, const uint8_t *_src, size_t len,
                            int *pseudo_header_exists_map, size_t *content_length, h2o_cache_digests_t **digests,
                            const char **err_desc)
{
    const uint8_t *src = _src, *src_end = src + len;
    int64_t largest_ref, base_index;

    /* decode prefix */
    if ((largest_ref = h2o_hpack_decode_int(&src, src_end, 8)) == -1)
        return H2O_HTTP2_ERROR_COMPRESSION;
    {
        if (src >= src_end)
            return H2O_HTTP2_ERROR_COMPRESSION;
        int sign = (*src & 0x80) != 0;
        if ((base_index = h2o_hpack_decode_int(&src, src_end, 7)) == -1)
            return H2O_HTTP2_ERROR_COMPRESSION;
        base_index = sign == 0 ? largest_ref + base_index : largest_ref - base_index;
    }

    /* is the stream blocked? */
    if (largest_ref >= qpack->table.base_offset + qpack->table.last - qpack->table.first) {
        decoder_link_blocked(qpack, stream_id, largest_ref);
        return H2O_HTTP2_ERROR_INCOMPLETE;
    }

    struct st_h2o_qpack_decode_header_ctx_t ctx = {qpack, base_index};
    return h2o_hpack_parse_headers(req, decode_header, &ctx, src, src_end - src, pseudo_header_exists_map, content_length, digests,
                                   err_desc);
}

h2o_qpack_encoder_t *h2o_qpack_create_encoder(h2o_qpack_context_t *ctx)
{
    return h2o_mem_alloc(1);
}

void h2o_qpack_destroy_encoder(h2o_qpack_encoder_t *qpack)
{
    free(qpack);
}

static uint8_t *flatten_string(uint8_t *dst, const char *src, size_t len, unsigned prefix_bits, int dont_compress)
{
    size_t hufflen;

    if (dont_compress || (hufflen = h2o_hpack_encode_huffman(dst + 1, (void *)src, len)) == SIZE_MAX) {
        /* uncompressed */
        *dst &= ~((2 << prefix_bits) - 1); /* clear huffman mark */
        dst = h2o_hpack_encode_int(dst, len, prefix_bits);
        memcpy(dst, src, len);
        dst += len;
    } else {
        /* build huffman header and adjust the location (if necessary) */
        uint8_t buf[H2O_HPACK_ENCODE_INT_MAX_LENGTH], *p = buf;
        *p = *dst & ~((1 << prefix_bits) - 1);
        *p |= (1 << prefix_bits); /* huffman mark */
        p = h2o_hpack_encode_int(p, hufflen, prefix_bits);
        if (p - buf == 1) {
            dst[0] = buf[0];
        } else {
            memmove(dst + (p - buf), dst + 1, hufflen);
            memcpy(dst, buf, p - buf);
        }
        dst += p - buf + hufflen;
    }

    return dst;
}

int h2o_qpack_flatten_headers(h2o_qpack_encoder_t *qpack, quicly_sendbuf_t *sendbuf, h2o_header_t *headers, size_t num_headers)
{
    uint8_t buf[MAX_HEADER_VALUE_LENGTH + 16], *dst = buf;
    size_t i;
    int ret = 0;

#define FLUSH()                                                                                                                    \
    do {                                                                                                                           \
        if ((ret = quicly_sendbuf_write(sendbuf, buf, dst - buf, NULL)) != 0)                                                      \
            goto Exit;                                                                                                             \
        dst = buf;                                                                                                                 \
    } while (0)
#define RESERVE(capacity)                                                                                                          \
    do {                                                                                                                           \
        if (buf + sizeof(buf) - dst < (capacity))                                                                                  \
            FLUSH();                                                                                                               \
    } while (0)

    *dst++ = 0; /* largest_ref */
    *dst++ = 0; /* base_index */
    for (i = 0; i != num_headers; ++i) {
        if (headers[i].flags.http2_static_table_name_index != 0) {
            /* TODO optimize for cases where multiple values exist for single name (e.g., ":scheme: https") */
            const h2o_hpack_static_table_entry_t *entry =
                h2o_hpack_static_table + headers[i].flags.http2_static_table_name_index - 1;
            if (h2o_memis(headers[i].value.base, headers[i].value.len, entry->value.base, entry->value.len)) {
                /* static indexed header field */
                RESERVE(H2O_HPACK_ENCODE_INT_MAX_LENGTH);
                *dst = 0xc0;
                dst = h2o_hpack_encode_int(dst, headers[i].flags.http2_static_table_name_index, 6);
            } else {
                /* literal header field with static name reference */
                RESERVE(H2O_HPACK_ENCODE_INT_MAX_LENGTH * 2 + headers[i].value.len);
                *dst = 0x50;
                dst = h2o_hpack_encode_int(dst, headers[i].flags.http2_static_table_name_index, 4);
                dst = flatten_string(dst, headers[i].value.base, headers[i].value.len, 7, headers[i].flags.dont_compress);
            }
        } else {
            /* literal header field without name reference */
            RESERVE(H2O_HPACK_ENCODE_INT_MAX_LENGTH * 2 + headers[i].name->len + headers[i].value.len);
            *dst = 0x20;
            dst = flatten_string(dst, headers[i].name->base, headers[i].name->len, 3, 0);
            dst = flatten_string(dst, headers[i].value.base, headers[i].value.len, 7, headers[i].flags.dont_compress);
        }
    }

    assert(dst != buf);
    FLUSH();

Exit:
    return ret;

#undef FLUSH
#undef RESERVE
}
