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
#include "h2o/hq_common.h"

#define HEADER_ENTRY_SIZE_OFFSET_LOG2 5
#define HEADER_ENTRY_SIZE_OFFSET (1 << HEADER_ENTRY_SIZE_OFFSET_LOG2)

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
    struct st_h2o_qpack_header_table_t table;
    /**
     *
     */
    uint32_t header_table_size;
    /**
     *
     */
    unsigned max_entries_shift;
    /**
     * number of updates since last sync
     */
    uint32_t insert_count;
    /**
     *
     */
    uint64_t total_inserts;
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
        table->num_bytes -= (*table->first)->name->len + (*table->first)->value_len + HEADER_ENTRY_SIZE_OFFSET;
        h2o_mem_release_shared(*table->first);
        *table->first++ = NULL;
        ++table->base_offset;
    }
    assert(table->num_bytes == 0);
}

static void header_table_insert(struct st_h2o_qpack_header_table_t *table, struct st_h2o_qpack_header_t *added)
{
    header_table_evict(table, added->name->len + added->value_len + HEADER_ENTRY_SIZE_OFFSET);

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
    table->num_bytes += added->name->len + added->value_len + HEADER_ENTRY_SIZE_OFFSET;
}

static const h2o_qpack_static_table_entry_t *resolve_static_abs(int64_t index, const char **err_desc)
{
    if (index >= sizeof(h2o_qpack_static_table) / sizeof(h2o_qpack_static_table[0])) {
        *err_desc = h2o_qpack_err_invalid_static_reference;
        return NULL;
    }
    return h2o_qpack_static_table + index;
}

static struct st_h2o_qpack_header_t *resolve_dynamic_abs(struct st_h2o_qpack_header_table_t *table, int64_t index,
                                                         const char **err_desc)
{
    if (index < table->base_offset)
        goto Invalid;
    index -= table->base_offset;
    if (index >= table->last - table->first)
        goto Invalid;
    return table->first[index];
Invalid:
    *err_desc = h2o_qpack_err_invalid_dynamic_reference;
    return NULL;
}

static int decode_int(int64_t *value, const uint8_t **src, const uint8_t *src_end, unsigned prefix_bits)
{
    if ((*value = h2o_hpack_decode_int(src, src_end, prefix_bits)) < 0)
        return *value == H2O_HTTP2_ERROR_INCOMPLETE ? H2O_HQ_ERROR_INCOMPLETE : H2O_HQ_ERROR_QPACK_DECOMPRESSION;
    return 0;
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

h2o_qpack_decoder_t *h2o_qpack_create_decoder(unsigned header_table_size_bits)
{
    assert(header_table_size_bits >= HEADER_ENTRY_SIZE_OFFSET_LOG2);

    h2o_qpack_decoder_t *qpack = h2o_mem_alloc(sizeof(*qpack));

    qpack->insert_count = 0;
    qpack->header_table_size = (uint32_t)1 << header_table_size_bits;
    qpack->max_entries_shift = header_table_size_bits - HEADER_ENTRY_SIZE_OFFSET_LOG2;
    qpack->total_inserts = 0;
    header_table_init(&qpack->table, qpack->header_table_size);
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
    ++qpack->total_inserts;
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
    return H2O_HQ_ERROR_QPACK_DECOMPRESSION;
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
        return H2O_HQ_ERROR_QPACK_DECOMPRESSION;
    }

    if (name_is_static) {
        const h2o_qpack_static_table_entry_t *ref;
        if ((ref = resolve_static_abs(name_index, err_desc)) == NULL)
            return H2O_HQ_ERROR_QPACK_DECOMPRESSION;
        return insert_token_header(qpack, ref->name, value_is_huff, value, value_len, err_desc);
    } else {
        struct st_h2o_qpack_header_t *ref;
        int64_t base_index = qpack->table.base_offset + (qpack->table.last - qpack->table.first) - 1;
        if (name_index > base_index) {
            *err_desc = h2o_qpack_err_invalid_dynamic_reference;
            return H2O_HQ_ERROR_QPACK_DECOMPRESSION;
        }
        if ((ref = resolve_dynamic_abs(&qpack->table, base_index - name_index, err_desc)) == NULL)
            return H2O_HQ_ERROR_QPACK_DECOMPRESSION;
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
        return H2O_HQ_ERROR_QPACK_DECOMPRESSION;
    }
    if (qvlen >= MAX_HEADER_VALUE_LENGTH) {
        *err_desc = h2o_qpack_err_header_value_too_long;
        return H2O_HQ_ERROR_QPACK_DECOMPRESSION;
    }

    if (qnhuff) {
        name.base = alloca(qnlen * 2);
        if ((name.len = h2o_hpack_decode_huffman(name.base, qn, qnlen, 1, err_desc)) == SIZE_MAX)
            return H2O_HQ_ERROR_QPACK_DECOMPRESSION;
    } else {
        if (!h2o_hpack_validate_header_name((void *)qn, qnlen, err_desc))
            return H2O_HQ_ERROR_QPACK_DECOMPRESSION;
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
        return H2O_HQ_ERROR_QPACK_DECOMPRESSION;
    }

    struct st_h2o_qpack_header_t *header = qpack->table.first[name_index];
    h2o_mem_addref_shared(header);
    decoder_insert(qpack, header);
    return 0;
}

static int dynamic_table_size_update(h2o_qpack_decoder_t *qpack, int64_t max_size, const char **err_desc)
{
    if (max_size > qpack->header_table_size) {
        *err_desc = h2o_qpack_err_invalid_max_size;
        return H2O_HQ_ERROR_QPACK_DECOMPRESSION;
    }

    qpack->table.max_size = max_size;
    header_table_evict(&qpack->table, 0);
    return 0;
}

int h2o_qpack_decoder_handle_input(h2o_qpack_decoder_t *qpack, const uint8_t **_src, const uint8_t *src_end, const char **err_desc)
{
    const uint8_t *src = *_src;
    int ret = 0;

    while (src != src_end && ret == 0) {
        switch (*src >> 5) {
        default: /* insert with name reference */ {
            int64_t name_index, value_len;
            int name_is_static = (*src & 0x40) != 0;
            if ((ret = decode_int(&name_index, &src, src_end, 6)) != 0)
                goto Exit;
            if (src == src_end)
                goto Exit;
            int value_is_huff = (*src & 0x80) != 0;
            if ((ret = decode_int(&value_len, &src, src_end, 7)) != 0)
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
            if ((ret = decode_int(&name_len, &src, src_end, 5)) != 0)
                goto Exit;
            if (!(src + name_len < src_end))
                goto Exit;
            const uint8_t *name = src;
            int value_is_huff = (*src & 0x80) != 0;
            if ((ret = decode_int(&value_len, &src, src_end, 7)) != 0)
                goto Exit;
            if (!(src + value_len <= src_end))
                goto Exit;
            ret = insert_without_name_reference(qpack, name_is_huff, name, name_len, value_is_huff, src, value_len, err_desc);
            src += value_len;
        } break;
        case 0: /* duplicate */ {
            int64_t name_index;
            if ((ret = decode_int(&name_index, &src, src_end, 5)) != 0)
                goto Exit;
            ret = duplicate(qpack, name_index, err_desc);
        } break;
        case 1: /* dynamic table size update */ {
            int64_t max_size;
            if ((ret = decode_int(&max_size, &src, src_end, 5)) != 0)
                goto Exit;
            ret = dynamic_table_size_update(qpack, max_size, err_desc);
        } break;
        }
        *_src = src;
    }

Exit:
    if (ret == H2O_HTTP2_ERROR_INCOMPLETE)
        ret = 0;
    return (int)ret;
}

size_t h2o_qpack_decoder_send_state_sync(h2o_qpack_decoder_t *qpack, uint8_t *outbuf)
{
    if (qpack->insert_count == 0)
        return 0;

    uint8_t *dst = outbuf;
    *dst = 0;
    dst = h2o_hpack_encode_int(dst, qpack->insert_count, 6);
    qpack->insert_count = 0;

    return dst - outbuf;
}

size_t h2o_qpack_decoder_send_stream_cancel(h2o_qpack_decoder_t *qpack, uint8_t *outbuf, int64_t stream_id)
{
    outbuf[0] = 0x40;
    return h2o_hpack_encode_int(outbuf, stream_id, 6) - outbuf;
}

static const h2o_qpack_static_table_entry_t *resolve_static(const uint8_t **src, const uint8_t *src_end, unsigned prefix_bits,
                                                            const char **err_desc)
{
    int64_t index;

    if (decode_int(&index, src, src_end, prefix_bits) != 0)
        goto Fail;
    assert(index >= 0);
    if (!(index < sizeof(h2o_qpack_static_table) / sizeof(h2o_qpack_static_table[0])))
        goto Fail;
    return h2o_qpack_static_table + index;

Fail:
    *err_desc = h2o_qpack_err_invalid_static_reference;
    return NULL;
}

static struct st_h2o_qpack_header_t *resolve_dynamic(struct st_h2o_qpack_header_table_t *table, int64_t base_index,
                                                     const uint8_t **src, const uint8_t *src_end, unsigned prefix_bits,
                                                     const char **err_desc)
{
    int64_t off;

    if (decode_int(&off, src, src_end, prefix_bits) != 0 || off >= base_index) {
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

    if (decode_int(&off, src, src_end, prefix_bits) != 0 || INT64_MAX - off < base_index + 1) {
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
    if (decode_int(&len, src, src_end, prefix_bits) != 0 || len > MAX_HEADER_NAME_LENGTH) {
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

    if (decode_int(&len, src, src_end, 7) != 0 || len > MAX_HEADER_VALUE_LENGTH) {
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
    int64_t largest_ref, base_index;
};

static size_t send_header_ack(h2o_qpack_decoder_t *qpack, struct st_h2o_qpack_decode_header_ctx_t *ctx, uint8_t *outbuf,
                              int64_t stream_id)
{
    if (ctx->largest_ref == 0)
        return 0;
    outbuf[0] = 0x80;
    return h2o_hpack_encode_int(outbuf, stream_id, 7) - outbuf;
}

static int decode_header(h2o_mem_pool_t *pool, void *_ctx, h2o_iovec_t **name, h2o_iovec_t *value, const uint8_t **src,
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
        const h2o_qpack_static_table_entry_t *entry;
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
        const h2o_qpack_static_table_entry_t *entry;
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
    return H2O_HQ_ERROR_QPACK_DECOMPRESSION;
}

static int parse_decode_context(h2o_qpack_decoder_t *qpack, struct st_h2o_qpack_decode_header_ctx_t *ctx, int64_t stream_id,
                                const uint8_t **src, const uint8_t *src_end)
{
    ctx->qpack = qpack;

    /* largest reference */
    if (decode_int(&ctx->largest_ref, src, src_end, 8) != 0)
        return H2O_HQ_ERROR_QPACK_DECOMPRESSION;
    if (ctx->largest_ref > 0) {
        const uint64_t max_entries = (uint64_t)1 << qpack->max_entries_shift, full_range = 2 * max_entries;
        uint64_t max_value = qpack->total_inserts + max_entries;
        uint64_t rounded = max_value & -full_range;
        ctx->largest_ref += rounded - 1;
        if (ctx->largest_ref > max_value && ctx->largest_ref >= full_range)
            ctx->largest_ref -= full_range;
        ctx->largest_ref += 1;
    }

    /* base index */
    if (*src >= src_end)
        return H2O_HQ_ERROR_QPACK_DECOMPRESSION;
    int sign = (**src & 0x80) != 0;
    if (decode_int(&ctx->base_index, src, src_end, 7) != 0)
        return H2O_HQ_ERROR_QPACK_DECOMPRESSION;
    ctx->base_index = sign == 0 ? ctx->largest_ref + ctx->base_index : ctx->largest_ref - ctx->base_index;

    /* is the stream blocked? */
    if (ctx->largest_ref >= qpack->table.base_offset + qpack->table.last - qpack->table.first) {
        decoder_link_blocked(qpack, stream_id, ctx->largest_ref);
        return H2O_HQ_ERROR_INCOMPLETE;
    }

    return 0;
}

static int normalize_error_code(int err)
{
    /* convert H2 errors (except invaild_header_char) to QPACK error code */
    if (err < 0 && err != H2O_HTTP2_ERROR_INVALID_HEADER_CHAR)
        err = H2O_HQ_ERROR_QPACK_DECOMPRESSION;
    return err;
}

int h2o_qpack_parse_request(h2o_mem_pool_t *pool, h2o_qpack_decoder_t *qpack, int64_t stream_id, h2o_iovec_t *method,
                            const h2o_url_scheme_t **scheme, h2o_iovec_t *authority, h2o_iovec_t *path, h2o_headers_t *headers,
                            int *pseudo_header_exists_map, size_t *content_length, h2o_cache_digests_t **digests, uint8_t *outbuf,
                            size_t *outbufsize, const uint8_t *_src, size_t len, const char **err_desc)
{
    struct st_h2o_qpack_decode_header_ctx_t ctx;
    const uint8_t *src = _src, *src_end = src + len;
    int ret;

    if ((ret = parse_decode_context(qpack, &ctx, stream_id, &src, src_end)) != 0)
        return ret;
    if ((ret = h2o_hpack_parse_request(pool, decode_header, &ctx, method, scheme, authority, path, headers,
                                       pseudo_header_exists_map, content_length, digests, src, src_end - src, err_desc)) != 0)
        return normalize_error_code(ret);

    *outbufsize = send_header_ack(qpack, &ctx, outbuf, stream_id);
    return 0;
}

int h2o_qpack_parse_response(h2o_mem_pool_t *pool, h2o_qpack_decoder_t *qpack, int64_t stream_id, int *status,
                             h2o_headers_t *headers, uint8_t *outbuf, size_t *outbufsize, const uint8_t *_src, size_t len,
                             const char **err_desc)
{
    struct st_h2o_qpack_decode_header_ctx_t ctx;
    const uint8_t *src = _src, *src_end = src + len;
    int ret;

    if ((ret = parse_decode_context(qpack, &ctx, stream_id, &src, src_end)) != 0)
        return ret;
    if ((ret = h2o_hpack_parse_response(pool, decode_header, &ctx, status, headers, src, src_end - src, err_desc)) != 0)
        return normalize_error_code(ret);

    *outbufsize = send_header_ack(qpack, &ctx, outbuf, stream_id);
    return 0;
}

h2o_qpack_encoder_t *h2o_qpack_create_encoder(unsigned header_table_size_bits)
{
    return h2o_mem_alloc(1);
}

void h2o_qpack_destroy_encoder(h2o_qpack_encoder_t *qpack)
{
    free(qpack);
}

static int handle_table_state_synchronize(h2o_qpack_encoder_t *qpack, int64_t insert_count, const char **err_desc)
{
    if (insert_count != 0) {
        *err_desc = "unexpected message: Table State Synchronize";
        return H2O_HQ_ERROR_QPACK_DECOMPRESSION;
    }
    /* FIXME is insert_count=0 considered a valid argument? */
    return 0;
}

static int handle_header_ack(h2o_qpack_encoder_t *qpack, int64_t stream_id, const char **err_desc)
{
    *err_desc = "unexpected message: Header Acknowledgement";
    return H2O_HQ_ERROR_QPACK_DECOMPRESSION;
}

static int handle_stream_cancellation(h2o_qpack_encoder_t *qpack, int64_t stream_id, const char **err_desc)
{
    return 0;
}

int h2o_qpack_encoder_handle_input(h2o_qpack_encoder_t *qpack, const uint8_t **_src, const uint8_t *src_end, const char **err_desc)
{
    const uint8_t *src = *_src;
    int ret = 0;

    while (src != src_end && ret == 0) {
        switch (*src >> 6) {
        case 0: /* table state synchronize */ {
            int64_t insert_count;
            if ((ret = decode_int(&insert_count, &src, src_end, 6)) != 0)
                goto Exit;
            ret = handle_table_state_synchronize(qpack, insert_count, err_desc);
        } break;
        default: /* header ack */ {
            int64_t stream_id;
            if ((ret = decode_int(&stream_id, &src, src_end, 7)) != 0)
                goto Exit;
            ret = handle_header_ack(qpack, stream_id, err_desc);
        } break;
        case 1: /* stream cancellation */ {
            int64_t stream_id;
            if ((ret = decode_int(&stream_id, &src, src_end, 6)) != 0)
                goto Exit;
            ret = handle_stream_cancellation(qpack, stream_id, err_desc);
        } break;
        }
        *_src = src;
    }

Exit:
    if (ret == H2O_HQ_ERROR_INCOMPLETE)
        ret = 0;
    return (int)ret;
}

static void flatten_int(h2o_byte_vector_t *buf, int64_t value, unsigned prefix_bits)
{
    uint8_t *p = h2o_hpack_encode_int(buf->entries + buf->size, value, prefix_bits);
    buf->size = p - buf->entries;
}

static void flatten_string(h2o_byte_vector_t *buf, const char *src, size_t len, unsigned prefix_bits, int dont_compress)
{
    size_t hufflen;

    if (dont_compress || (hufflen = h2o_hpack_encode_huffman(buf->entries + buf->size + 1, (void *)src, len)) == SIZE_MAX) {
        /* uncompressed */
        buf->entries[buf->size] &= ~((2 << prefix_bits) - 1); /* clear huffman mark */
        flatten_int(buf, len, prefix_bits);
        memcpy(buf->entries + buf->size, src, len);
        buf->size += len;
    } else {
        /* build huffman header and adjust the location (if necessary) */
        uint8_t tmpbuf[H2O_HPACK_ENCODE_INT_MAX_LENGTH], *p = tmpbuf;
        *p = buf->entries[buf->size] & ~((1 << prefix_bits) - 1);
        *p |= (1 << prefix_bits); /* huffman mark */
        p = h2o_hpack_encode_int(p, hufflen, prefix_bits);
        if (p - tmpbuf == 1) {
            buf->entries[buf->size] = tmpbuf[0];
        } else {
            memmove(buf->entries + buf->size + (p - tmpbuf), buf->entries + buf->size + 1, hufflen);
            memcpy(buf->entries + buf->size, tmpbuf, p - tmpbuf);
        }
        buf->size += p - tmpbuf + hufflen;
    }
}

static void flatten_header(h2o_qpack_encoder_t *qpack, h2o_mem_pool_t *pool, h2o_byte_vector_t *buf, const h2o_header_t *header)
{
    if (header->flags.qpack_static_table_index != 0) {
        /* TODO optimize for cases where multiple values exist for single name (e.g., ":scheme: https") */
        const h2o_qpack_static_table_entry_t *entry = h2o_qpack_static_table + header->flags.qpack_static_table_index;
        if (h2o_memis(header->value.base, header->value.len, entry->value.base, entry->value.len)) {
            /* static indexed header field */
            h2o_vector_reserve(pool, buf, buf->size + H2O_HPACK_ENCODE_INT_MAX_LENGTH);
            buf->entries[buf->size] = 0xc0;
            flatten_int(buf, header->flags.qpack_static_table_index, 6);
        } else {
            h2o_vector_reserve(pool, buf, buf->size + H2O_HPACK_ENCODE_INT_MAX_LENGTH * 2 + header->value.len);
            buf->entries[buf->size] = 0x50;
            flatten_int(buf, header->flags.qpack_static_table_index, 4);
            flatten_string(buf, header->value.base, header->value.len, 7, header->flags.dont_compress);
        }
    } else {
        /* literal header field without name reference */
        h2o_vector_reserve(pool, buf, buf->size + H2O_HPACK_ENCODE_INT_MAX_LENGTH * 2 + header->name->len + header->value.len);
        buf->entries[buf->size] = 0x20;
        flatten_string(buf, header->name->base, header->name->len, 3, 0);
        flatten_string(buf, header->value.base, header->value.len, 7, header->flags.dont_compress);
    }
}

static void flatten_token_header(h2o_qpack_encoder_t *qpack, h2o_mem_pool_t *pool, h2o_byte_vector_t *buf, const h2o_token_t *token,
                                 h2o_iovec_t value)
{
    h2o_header_t h = {(h2o_iovec_t *)&token->buf, NULL, value, token->flags};
    flatten_header(qpack, pool, buf, &h);
}

void h2o_qpack_flatten_request(h2o_qpack_encoder_t *qpack, h2o_mem_pool_t *pool, h2o_byte_vector_t *buf, h2o_iovec_t method,
                               const h2o_url_scheme_t *scheme, h2o_iovec_t authority, h2o_iovec_t path, const h2o_header_t *headers,
                               size_t num_headers)
{
    static const uint8_t STATIC_TABLE_BASE = 0xc0;
    h2o_vector_reserve(pool, buf, buf->size + 3);

    /* largest_ref and base_index */
    buf->entries[buf->size++] = 0;
    buf->entries[buf->size++] = 0;

    /* pseudo headers */
    if (h2o_memis(method.base, method.len, H2O_STRLIT("GET"))) {
        buf->entries[buf->size++] = STATIC_TABLE_BASE + 17;
    } else if (h2o_memis(method.base, method.len, H2O_STRLIT("POST"))) {
        buf->entries[buf->size++] = STATIC_TABLE_BASE + 20;
    } else {
        flatten_token_header(qpack, pool, buf, H2O_TOKEN_METHOD, method);
    }
    if (scheme == &H2O_URL_SCHEME_HTTP) {
        h2o_vector_reserve(pool, buf, buf->size + 1);
        buf->entries[buf->size++] = STATIC_TABLE_BASE + 22;
    } else if (scheme == &H2O_URL_SCHEME_HTTPS) {
        h2o_vector_reserve(pool, buf, buf->size + 1);
        buf->entries[buf->size++] = STATIC_TABLE_BASE + 23;
    } else {
        flatten_token_header(qpack, pool, buf, H2O_TOKEN_SCHEME, scheme->name);
    }
    flatten_token_header(qpack, pool, buf, H2O_TOKEN_AUTHORITY, authority);
    flatten_token_header(qpack, pool, buf, H2O_TOKEN_PATH, path);

    /* flatten headers */
    size_t i;
    for (i = 0; i != num_headers; ++i)
        flatten_header(qpack, pool, buf, headers + i);
}

void h2o_qpack_flatten_response(h2o_qpack_encoder_t *qpack, h2o_mem_pool_t *pool, h2o_byte_vector_t *buf, int status,
                                const h2o_header_t *headers, size_t num_headers, const h2o_iovec_t *server_name,
                                size_t content_length)
{
    h2o_vector_reserve(pool, buf, buf->size + 3);

    /* largest_ref and base_index */
    buf->entries[buf->size++] = 0;
    buf->entries[buf->size++] = 0;

    /* pseudo headers */
    switch (status) {
#define SHORT_STATUS(st, cp)                                                                                                       \
    case st:                                                                                                                       \
        buf->entries[buf->size++] = 0xc0 | cp;                                                                                     \
        break
        SHORT_STATUS(200, 8);
        SHORT_STATUS(204, 9);
        SHORT_STATUS(206, 10);
        SHORT_STATUS(304, 11);
        SHORT_STATUS(400, 12);
        SHORT_STATUS(404, 13);
        SHORT_STATUS(500, 14);
#undef SHORT_STATUS
    default: {
        char status_str[sizeof(H2O_UINT16_LONGEST_STR)];
        sprintf(status_str, "%" PRIu16, (uint16_t)status);
        flatten_token_header(qpack, pool, buf, H2O_TOKEN_STATUS, h2o_iovec_init(status_str, strlen(status_str)));
    } break;
    }

    /* TODO keep some kind of reference to the indexed Server header, and reuse it */
    if (server_name != NULL && server_name->len != 0)
        flatten_token_header(qpack, pool, buf, H2O_TOKEN_SERVER, *server_name);

    /* content-length */
    if (content_length != SIZE_MAX) {
        char cl_str[sizeof(H2O_UINT64_LONGEST_STR)];
        sprintf(cl_str, "%" PRIu64, (uint64_t)content_length);
        flatten_token_header(qpack, pool, buf, H2O_TOKEN_CONTENT_LENGTH, h2o_iovec_init(cl_str, strlen(cl_str)));
    }

    /* flatten headers */
    size_t i;
    for (i = 0; i != num_headers; ++i)
        flatten_header(qpack, pool, buf, headers + i);
}
