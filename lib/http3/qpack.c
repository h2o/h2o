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
#include "picotls.h"
#include "h2o.h"
#include "h2o/hpack.h"
#include "h2o/qpack.h"
#include "h2o/http3_common.h"

#define HEADER_ENTRY_SIZE_OFFSET 32

/**
 * a mem-shared object that contains the name and value of a header field
 */
struct st_h2o_qpack_header_t {
    h2o_iovec_t *name;
    size_t value_len;
    h2o_iovec_t _name_buf;
    unsigned soft_errors;
    char value[1];
};

struct st_h2o_qpack_header_table_t {
    /**
     * pointers to the buffer structure; [buf_start, buf_end) is the memory allocated, [first, last) are the active entries
     */
    struct st_h2o_qpack_header_t **buf_start, **first, **last, **buf_end;
    /**
     * absolute index of `first`
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
    union {
        struct {
            uint8_t is_blocking;
        } encoder_flags;
    };
};

struct st_h2o_qpack_decoder_t {
    /**
     *
     */
    struct st_h2o_qpack_header_table_t table;
    /**
     * maximum header table size declared by itself. Current max set by peer is available in `table.max_size`.
     */
    uint32_t header_table_size;
    /**
     *
     */
    uint32_t max_entries;
    /**
     * number of updates since last sync
     */
    uint32_t insert_count;
    /**
     *
     */
    uint64_t total_inserts;
    /**
     *
     */
    uint16_t max_blocked;
    struct {
        /**
         * contains list of blocked streams (sorted in the ascending order of largest_ref)
         */
        H2O_VECTOR(struct st_h2o_qpack_blocked_streams_t) list;
        /**
         * number of blocked streams that are unblocked. They are evicted parse_request / response is being called.
         */
        size_t num_unblocked;
    } blocked_streams;
};

struct st_h2o_qpack_encoder_t {
    /**
     * the header table
     */
    struct st_h2o_qpack_header_table_t table;
    /**
     * maximum id of the insertion being acked (inclusive)
     */
    int64_t largest_known_received;
    /**
     * SETTINGS_QPACK_BLOCKED_STREAMS
     */
    uint16_t max_blocked;
    /**
     * number of potentially blocked HEADERS (not streams, sorry!) We count header blocks rather than streams because it is easier.
     * Hopefully it would work well.
     */
    uint16_t num_blocked;
    /**
     * list of unacked streams
     */
    H2O_VECTOR(struct st_h2o_qpack_blocked_streams_t) inflight;
};

struct st_h2o_qpack_flatten_context_t {
    h2o_qpack_encoder_t *qpack;
    h2o_mem_pool_t *pool;
    int64_t stream_id;
    h2o_byte_vector_t *encoder_buf;
    h2o_byte_vector_t headers_buf;
    int64_t base_index;
    int64_t largest_ref;
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
        return *value == H2O_HTTP2_ERROR_INCOMPLETE ? H2O_HTTP3_ERROR_INCOMPLETE : H2O_HTTP3_ERROR_QPACK_DECOMPRESSION_FAILED;
    return 0;
}

static size_t decode_value(char *outbuf, unsigned *soft_errors, int is_huff, const uint8_t *src, size_t srclen,
                           const char **err_desc)
{
    size_t outlen;

    if (is_huff) {
        if ((outlen = h2o_hpack_decode_huffman(outbuf, soft_errors, src, srclen, 0, err_desc)) == SIZE_MAX)
            return SIZE_MAX;
    } else {
        h2o_hpack_validate_header_value(soft_errors, (void *)src, srclen);
        memcpy(outbuf, src, srclen);
        outlen = srclen;
    }
    outbuf[outlen] = '\0';

    return outlen;
}

h2o_qpack_decoder_t *h2o_qpack_create_decoder(uint32_t header_table_size, uint16_t max_blocked)
{
    h2o_qpack_decoder_t *qpack = h2o_mem_alloc(sizeof(*qpack));

    qpack->insert_count = 0;
    qpack->header_table_size = header_table_size;
    qpack->max_entries = header_table_size / 32;
    qpack->total_inserts = 0;
    qpack->max_blocked = max_blocked;
    header_table_init(&qpack->table, qpack->header_table_size);
    memset(&qpack->blocked_streams, 0, sizeof(qpack->blocked_streams));

    return qpack;
}

void h2o_qpack_destroy_decoder(h2o_qpack_decoder_t *qpack)
{
    header_table_dispose(&qpack->table);
    free(qpack->blocked_streams.list.entries);
    free(qpack);
}

static void decoder_link_blocked(h2o_qpack_decoder_t *qpack, int64_t stream_id, int64_t largest_ref)
{
    size_t i;

    h2o_vector_reserve(NULL, &qpack->blocked_streams.list, qpack->blocked_streams.list.size + 1);
    for (i = qpack->blocked_streams.list.size; i != 0; --i)
        if (qpack->blocked_streams.list.entries[i - 1].largest_ref <= largest_ref)
            break;
    if (i != qpack->blocked_streams.list.size)
        memmove(qpack->blocked_streams.list.entries + i + 1, qpack->blocked_streams.list.entries + i,
                sizeof(qpack->blocked_streams.list.entries[0]) * (qpack->blocked_streams.list.size - i));
    qpack->blocked_streams.list.entries[i] = (struct st_h2o_qpack_blocked_streams_t){stream_id, largest_ref};
    ++qpack->blocked_streams.list.size;
}

static void decoder_insert(h2o_qpack_decoder_t *qpack, struct st_h2o_qpack_header_t *added)
{
    ++qpack->insert_count;
    ++qpack->total_inserts;
    fprintf(stderr, "#%s:%" PRIu64 ":%.*s\t%.*s\n", __FUNCTION__, qpack->total_inserts, (int)added->name->len, added->name->base,
            (int)added->value_len, added->value);
    header_table_insert(&qpack->table, added);
}

static int decode_value_and_insert(h2o_qpack_decoder_t *qpack, struct st_h2o_qpack_header_t *header, int is_huff,
                                   const uint8_t *qstr, size_t qstrlen, const char **err_desc)
{
    if ((header->value_len = decode_value(header->value, &header->soft_errors, is_huff, qstr, qstrlen, err_desc)) == SIZE_MAX)
        goto Fail;
    if (header->name->len + header->value_len + HEADER_ENTRY_SIZE_OFFSET > qpack->table.max_size) {
        *err_desc = h2o_qpack_err_header_exceeds_table_size;
        goto Fail;
    }
    decoder_insert(qpack, header);
    return 0;
Fail:
    h2o_mem_release_shared(header);
    return H2O_HTTP3_ERROR_QPACK_DECOMPRESSION_FAILED;
}

static int insert_token_header(h2o_qpack_decoder_t *qpack, const h2o_token_t *name, int value_is_huff, const uint8_t *value,
                               size_t value_len, const char **err_desc)
{
    struct st_h2o_qpack_header_t *header =
        h2o_mem_alloc_shared(NULL, offsetof(struct st_h2o_qpack_header_t, value) + (value_len * 2) + 1, NULL);

    header->name = (h2o_iovec_t *)&name->buf;
    header->soft_errors = 0;
    return decode_value_and_insert(qpack, header, value_is_huff, value, value_len, err_desc);
}

static int insert_literal_header(h2o_qpack_decoder_t *qpack, const char *name, size_t name_len, int value_is_huff,
                                 const uint8_t *value, size_t value_len, unsigned soft_errors, const char **err_desc)
{
    size_t value_capacity = (value_is_huff ? value_len * 2 : value_len) + 1;
    struct st_h2o_qpack_header_t *header =
        h2o_mem_alloc_shared(NULL, offsetof(struct st_h2o_qpack_header_t, value) + value_capacity + name_len + 1, NULL);

    header->_name_buf = h2o_iovec_init(header->value + value_capacity, name_len);
    memcpy(header->_name_buf.base, name, name_len);
    header->_name_buf.base[name_len] = '\0';
    header->_name_buf.len = name_len;
    header->name = &header->_name_buf;
    header->soft_errors = soft_errors;

    return decode_value_and_insert(qpack, header, value_is_huff, value, value_len, err_desc);
}

static int64_t qpack_table_total_inserts(struct st_h2o_qpack_header_table_t *table)
{
    return table->base_offset + (table->last - table->first);
}

static int insert_with_name_reference(h2o_qpack_decoder_t *qpack, int name_is_static, int64_t name_index, int value_is_huff,
                                      const uint8_t *value, int64_t value_len, const char **err_desc)
{
    if (value_len >= MAX_HEADER_VALUE_LENGTH) {
        *err_desc = h2o_qpack_err_header_value_too_long;
        return H2O_HTTP3_ERROR_QPACK_DECOMPRESSION_FAILED;
    }

    if (name_is_static) {
        const h2o_qpack_static_table_entry_t *ref;
        if ((ref = resolve_static_abs(name_index, err_desc)) == NULL)
            return H2O_HTTP3_ERROR_QPACK_DECOMPRESSION_FAILED;
        return insert_token_header(qpack, ref->name, value_is_huff, value, value_len, err_desc);
    } else {
        struct st_h2o_qpack_header_t *ref;
        int64_t base_index = qpack_table_total_inserts(&qpack->table) - 1;
        if (name_index > base_index) {
            *err_desc = h2o_qpack_err_invalid_dynamic_reference;
            return H2O_HTTP3_ERROR_QPACK_DECOMPRESSION_FAILED;
        }
        if ((ref = resolve_dynamic_abs(&qpack->table, base_index - name_index, err_desc)) == NULL)
            return H2O_HTTP3_ERROR_QPACK_DECOMPRESSION_FAILED;
        if (h2o_iovec_is_token(ref->name)) {
            return insert_token_header(qpack, (h2o_token_t *)ref->name, value_is_huff, value, value_len, err_desc);
        } else {
            return insert_literal_header(qpack, ref->name->base, ref->name->len, value_is_huff, value, value_len,
                                         ref->soft_errors & H2O_HPACK_SOFT_ERROR_BIT_INVALID_NAME, err_desc);
        }
    }
}

static int insert_without_name_reference(h2o_qpack_decoder_t *qpack, int qnhuff, const uint8_t *qn, int64_t qnlen, int qvhuff,
                                         const uint8_t *qv, int64_t qvlen, const char **err_desc)
{
    h2o_iovec_t name;
    unsigned soft_errors = 0;

    if (qnlen >= MAX_HEADER_NAME_LENGTH) {
        *err_desc = h2o_qpack_err_header_name_too_long;
        return H2O_HTTP3_ERROR_QPACK_DECOMPRESSION_FAILED;
    }
    if (qvlen >= MAX_HEADER_VALUE_LENGTH) {
        *err_desc = h2o_qpack_err_header_value_too_long;
        return H2O_HTTP3_ERROR_QPACK_DECOMPRESSION_FAILED;
    }

    if (qnhuff) {
        name.base = alloca(qnlen * 2);
        if ((name.len = h2o_hpack_decode_huffman(name.base, &soft_errors, qn, qnlen, 1, err_desc)) == SIZE_MAX)
            return H2O_HTTP3_ERROR_QPACK_DECOMPRESSION_FAILED;
    } else {
        if (!h2o_hpack_validate_header_name(&soft_errors, (void *)qn, qnlen, err_desc))
            return H2O_HTTP3_ERROR_QPACK_DECOMPRESSION_FAILED;
        name = h2o_iovec_init(qn, qnlen);
    }

    const h2o_token_t *token;
    if ((token = h2o_lookup_token(name.base, name.len)) != NULL) {
        return insert_token_header(qpack, token, qvhuff, qv, qvlen, err_desc);
    } else {
        return insert_literal_header(qpack, name.base, name.len, qvhuff, qv, qvlen, soft_errors, err_desc);
    }
}

static int duplicate(h2o_qpack_decoder_t *qpack, int64_t index, const char **err_desc)
{
    if (index >= qpack->table.last - qpack->table.first) {
        *err_desc = h2o_qpack_err_invalid_duplicate;
        return H2O_HTTP3_ERROR_QPACK_DECOMPRESSION_FAILED;
    }

    struct st_h2o_qpack_header_t *header = qpack->table.last[-index - 1];
    h2o_mem_addref_shared(header);
    decoder_insert(qpack, header);
    return 0;
}

static int dynamic_table_size_update(h2o_qpack_decoder_t *qpack, int64_t max_size, const char **err_desc)
{
    if (max_size > qpack->header_table_size) {
        *err_desc = h2o_qpack_err_invalid_max_size;
        return H2O_HTTP3_ERROR_QPACK_DECOMPRESSION_FAILED;
    }

    qpack->table.max_size = max_size;
    header_table_evict(&qpack->table, 0);
    return 0;
}

int h2o_qpack_decoder_handle_input(h2o_qpack_decoder_t *qpack, int64_t **unblocked_stream_ids, size_t *num_unblocked,
                                   const uint8_t **_src, const uint8_t *src_end, const char **err_desc)
{
    if (qpack->blocked_streams.num_unblocked != 0) {
        size_t remaining = qpack->blocked_streams.list.size - qpack->blocked_streams.num_unblocked;
        if (remaining != 0)
            memmove(qpack->blocked_streams.list.entries, qpack->blocked_streams.list.entries + remaining,
                    sizeof(qpack->blocked_streams.list.entries[0]) * remaining);
        qpack->blocked_streams.list.size = remaining;
        qpack->blocked_streams.num_unblocked = 0;
    }

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
            src += name_len;
            int value_is_huff = (*src & 0x80) != 0;
            if ((ret = decode_int(&value_len, &src, src_end, 7)) != 0)
                goto Exit;
            if (!(src + value_len <= src_end))
                goto Exit;
            ret = insert_without_name_reference(qpack, name_is_huff, name, name_len, value_is_huff, src, value_len, err_desc);
            src += value_len;
        } break;
        case 0: /* duplicate */ {
            int64_t index;
            if ((ret = decode_int(&index, &src, src_end, 5)) != 0)
                goto Exit;
            ret = duplicate(qpack, index, err_desc);
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
    if (ret == 0) {
        /* build list of newly unblocked streams ids reusing the memory of the blocked streams list (nasty!) */
        *unblocked_stream_ids = &qpack->blocked_streams.list.entries[0].stream_id;
        for (qpack->blocked_streams.num_unblocked = 0; qpack->blocked_streams.num_unblocked < qpack->blocked_streams.list.size;
             ++qpack->blocked_streams.num_unblocked) {
            if (qpack->blocked_streams.list.entries[qpack->blocked_streams.num_unblocked].largest_ref > qpack->total_inserts)
                break;
            (*unblocked_stream_ids)[qpack->blocked_streams.num_unblocked] =
                qpack->blocked_streams.list.entries[qpack->blocked_streams.num_unblocked].stream_id;
        }
        *num_unblocked = qpack->blocked_streams.num_unblocked;
    }
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

    if (decode_int(&off, src, src_end, prefix_bits) != 0 || off > INT64_MAX - base_index - 1) {
        *err_desc = h2o_qpack_err_invalid_dynamic_reference;
        return NULL;
    }
    return resolve_dynamic_abs(table, base_index + off + 1, err_desc);
}

static h2o_iovec_t *decode_header_name_literal(h2o_mem_pool_t *pool, unsigned *soft_errors, const uint8_t **src,
                                               const uint8_t *src_end, unsigned prefix_bits, const char **err_desc)
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
        if ((buf.len = h2o_hpack_decode_huffman(buf.base, soft_errors, *src, len, 1, err_desc)) == SIZE_MAX)
            goto Fail;
        buf.base[buf.len] = '\0';
        token = h2o_lookup_token(buf.base, buf.len);
    } else if ((token = h2o_lookup_token((const char *)*src, len)) != NULL) {
        /* was an uncompressed token */
    } else {
        if (!h2o_hpack_validate_header_name(soft_errors, (void *)*src, len, err_desc))
            goto Fail;
        buf = h2o_strdup(pool, (void *)*src, len);
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

static h2o_iovec_t decode_header_value_literal(h2o_mem_pool_t *pool, unsigned *soft_errors, const uint8_t **src,
                                               const uint8_t *src_end, const char **err_desc)
{
    h2o_iovec_t buf;
    int64_t len;

    /* validate *src pointer before dereferencing it for the huffman bit check */
    if (!(*src < src_end))
        goto Fail;
    int is_huff = (**src & 0x80) != 0;

    if (decode_int(&len, src, src_end, 7) != 0 || len > MAX_HEADER_VALUE_LENGTH) {
        *err_desc = h2o_qpack_err_header_value_too_long;
        goto Fail;
    }
    if (src_end - *src < len)
        goto Fail;

    buf.base = h2o_mem_alloc_pool(pool, char, is_huff ? len * 2 + 1 : len + 1);
    if ((buf.len = decode_value(buf.base, soft_errors, is_huff, *src, len, err_desc)) == SIZE_MAX)
        goto Fail;
    *src += len;

    return buf;
Fail:
    return h2o_iovec_init(NULL, 0);
}

struct st_h2o_qpack_decode_header_ctx_t {
    h2o_qpack_decoder_t *qpack;
    /**
     * These values are non-negative.
     */
    int64_t req_insert_count, base_index;
};

static size_t send_header_ack(h2o_qpack_decoder_t *qpack, struct st_h2o_qpack_decode_header_ctx_t *ctx, uint8_t *outbuf,
                              int64_t stream_id)
{
    if (ctx->req_insert_count == 0)
        return 0;
    outbuf[0] = 0x80;
    return h2o_hpack_encode_int(outbuf, stream_id, 7) - outbuf;
}

static int decode_header(h2o_mem_pool_t *pool, void *_ctx, h2o_iovec_t **name, h2o_iovec_t *value, const uint8_t **src,
                         const uint8_t *src_end, const char **err_desc)
{
    struct st_h2o_qpack_decode_header_ctx_t *ctx = _ctx;
    unsigned soft_errors;

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
        soft_errors = 0;
    } break;
    case 8:
    case 9:
    case 10:
    case 11: /* indexed dynamic header field */ {
        struct st_h2o_qpack_header_t *entry;
        if ((entry = resolve_dynamic(&ctx->qpack->table, ctx->base_index, src, src_end, 6, err_desc)) == NULL)
            goto Fail;
        h2o_mem_link_shared(pool, entry);
        *name = entry->name;
        *value = h2o_iovec_init(entry->value, entry->value_len);
        soft_errors = entry->soft_errors;
    } break;
    case 5:
    case 7: /* literal header field with static name reference */ {
        const h2o_qpack_static_table_entry_t *entry;
        if ((entry = resolve_static(src, src_end, 4, err_desc)) == NULL)
            goto Fail;
        *name = (h2o_iovec_t *)&entry->name->buf;
        soft_errors = 0;
        if ((*value = decode_header_value_literal(pool, &soft_errors, src, src_end, err_desc)).base == NULL)
            goto Fail;
    } break;
    case 4:
    case 6: /* literal header field with dynamic name reference */ {
        struct st_h2o_qpack_header_t *entry;
        if ((entry = resolve_dynamic(&ctx->qpack->table, ctx->base_index, src, src_end, 4, err_desc)) == NULL)
            goto Fail;
        h2o_mem_link_shared(pool, entry);
        *name = entry->name;
        soft_errors = (entry->soft_errors) & H2O_HPACK_SOFT_ERROR_BIT_INVALID_NAME;
        if ((*value = decode_header_value_literal(pool, &soft_errors, src, src_end, err_desc)).base == NULL)
            goto Fail;
    } break;
    case 2:
    case 3: /* literal header field without name reference */ {
        soft_errors = 0;
        if ((*name = decode_header_name_literal(pool, &soft_errors, src, src_end, 3, err_desc)) == NULL)
            goto Fail;
        if ((*value = decode_header_value_literal(pool, &soft_errors, src, src_end, err_desc)).base == NULL)
            goto Fail;
    } break;
    case 1: /* indexed header field with post-base index */ {
        struct st_h2o_qpack_header_t *entry;
        if ((entry = resolve_dynamic_postbase(&ctx->qpack->table, ctx->base_index, src, src_end, 4, err_desc)) == NULL)
            goto Fail;
        h2o_mem_link_shared(pool, entry);
        *name = entry->name;
        *value = h2o_iovec_init(entry->value, entry->value_len);
        soft_errors = entry->soft_errors;
    } break;
    case 0: /* literal header field with post-base name reference */ {
        struct st_h2o_qpack_header_t *entry;
        if ((entry = resolve_dynamic_postbase(&ctx->qpack->table, ctx->base_index, src, src_end, 3, err_desc)) == NULL)
            goto Fail;
        h2o_mem_link_shared(pool, entry);
        *name = entry->name;
        soft_errors = (entry->soft_errors) & H2O_HPACK_SOFT_ERROR_BIT_INVALID_NAME;
        if ((*value = decode_header_value_literal(pool, &soft_errors, src, src_end, err_desc)).base == NULL)
            goto Fail;
    } break;
    default:
        h2o_fatal("unreachable");
        soft_errors = 0;
        break;
    }

    if (soft_errors != 0) {
        *err_desc = (soft_errors & H2O_HPACK_SOFT_ERROR_BIT_INVALID_NAME) != 0
                        ? h2o_hpack_soft_err_found_invalid_char_in_header_name
                        : h2o_hpack_soft_err_found_invalid_char_in_header_value;
        return H2O_HTTP2_ERROR_INVALID_HEADER_CHAR;
    }
    return 0;
Fail:
    return H2O_HTTP3_ERROR_QPACK_DECOMPRESSION_FAILED;
}

static int parse_decode_context(h2o_qpack_decoder_t *qpack, struct st_h2o_qpack_decode_header_ctx_t *ctx, int64_t stream_id,
                                const uint8_t **src, const uint8_t *src_end)
{
    ctx->qpack = qpack;

    /* largest reference */
    if (decode_int(&ctx->req_insert_count, src, src_end, 8) != 0)
        return H2O_HTTP3_ERROR_QPACK_DECOMPRESSION_FAILED;
    if (ctx->req_insert_count > 0) {
        if (qpack->max_entries == 0)
            return H2O_HTTP3_ERROR_QPACK_DECOMPRESSION_FAILED;
        const uint32_t full_range = 2 * qpack->max_entries;
        uint64_t max_value = qpack->total_inserts + qpack->max_entries;
        uint64_t rounded = max_value / full_range * full_range;
        ctx->req_insert_count += rounded - 1;
        if (ctx->req_insert_count > max_value) {
            if (ctx->req_insert_count <= full_range)
                return H2O_HTTP3_ERROR_QPACK_DECOMPRESSION_FAILED;
            ctx->req_insert_count -= full_range;
        }
        if (ctx->req_insert_count == 0)
            return H2O_HTTP3_ERROR_QPACK_DECOMPRESSION_FAILED;
        /* Peer cannot send no more than PTLS_QUICINT_MAX instructions. That is because one QPACK instruction is no smaller than one
         * byte, and the maximum length of a QUIC stream (that conveys QPACK instructions) is 2^62 bytes in QUIC v1. */
        if (ctx->req_insert_count > PTLS_QUICINT_MAX)
            return H2O_HTTP3_ERROR_QPACK_DECOMPRESSION_FAILED;
    }

    /* sign and base index */
    if (*src >= src_end)
        return H2O_HTTP3_ERROR_QPACK_DECOMPRESSION_FAILED;
    int sign = (**src & 0x80) != 0;
    int64_t delta_base;
    if (decode_int(&delta_base, src, src_end, 7) != 0)
        return H2O_HTTP3_ERROR_QPACK_DECOMPRESSION_FAILED;
    if (delta_base > PTLS_QUICINT_MAX)
        return H2O_HTTP3_ERROR_QPACK_DECOMPRESSION_FAILED;
    ctx->base_index = sign == 0 ? ctx->req_insert_count + delta_base : ctx->req_insert_count - delta_base - 1;
    if (ctx->base_index < 0) {
        /* Reject negative base index though current QPACK specification doesn't mention such case; let's keep our eyes on
         * https://github.com/quicwg/base-drafts/issues/4938 */
        return H2O_HTTP3_ERROR_QPACK_DECOMPRESSION_FAILED;
    }

    /* is the stream blocked? */
    if (ctx->req_insert_count >= qpack_table_total_inserts(&qpack->table)) {
        if (qpack->blocked_streams.list.size + 1 >= qpack->max_blocked)
            return H2O_HTTP3_ERROR_QPACK_DECOMPRESSION_FAILED;
        decoder_link_blocked(qpack, stream_id, ctx->req_insert_count);
        return H2O_HTTP3_ERROR_INCOMPLETE;
    }

    return 0;
}

static int normalize_error_code(int err)
{
    /* convert H2 errors (except invaild_header_char) to QPACK error code */
    if (err < 0 && err != H2O_HTTP2_ERROR_INVALID_HEADER_CHAR)
        err = H2O_HTTP3_ERROR_QPACK_DECOMPRESSION_FAILED;
    return err;
}

int h2o_qpack_parse_request(h2o_mem_pool_t *pool, h2o_qpack_decoder_t *qpack, int64_t stream_id, h2o_iovec_t *method,
                            const h2o_url_scheme_t **scheme, h2o_iovec_t *authority, h2o_iovec_t *path, h2o_headers_t *headers,
                            int *pseudo_header_exists_map, size_t *content_length, h2o_cache_digests_t **digests,
                            h2o_iovec_t *datagram_flow_id, uint8_t *outbuf, size_t *outbufsize, const uint8_t *_src, size_t len,
                            const char **err_desc)
{
    struct st_h2o_qpack_decode_header_ctx_t ctx;
    const uint8_t *src = _src, *src_end = src + len;
    int ret;

    if ((ret = parse_decode_context(qpack, &ctx, stream_id, &src, src_end)) != 0)
        return ret;
    if ((ret = h2o_hpack_parse_request(pool, decode_header, &ctx, method, scheme, authority, path, headers,
                                       pseudo_header_exists_map, content_length, digests, datagram_flow_id, src, src_end - src, err_desc)) != 0) {
        /* bail out if the error is a hard error, otherwise build header ack then return */
        if (ret != H2O_HTTP2_ERROR_INVALID_HEADER_CHAR)
            return normalize_error_code(ret);
    }

    *outbufsize = send_header_ack(qpack, &ctx, outbuf, stream_id);
    return ret;
}

int h2o_qpack_parse_response(h2o_mem_pool_t *pool, h2o_qpack_decoder_t *qpack, int64_t stream_id, int *status,
                             h2o_headers_t *headers, h2o_iovec_t *datagram_flow_id, uint8_t *outbuf, size_t *outbufsize,
                             const uint8_t *_src, size_t len, const char **err_desc)
{
    struct st_h2o_qpack_decode_header_ctx_t ctx;
    const uint8_t *src = _src, *src_end = src + len;
    int ret;

    if ((ret = parse_decode_context(qpack, &ctx, stream_id, &src, src_end)) != 0)
        return ret;
    if ((ret = h2o_hpack_parse_response(pool, decode_header, &ctx, status, headers, datagram_flow_id, src, src_end - src,
                                        err_desc)) != 0)
        return normalize_error_code(ret);

    *outbufsize = send_header_ack(qpack, &ctx, outbuf, stream_id);
    return 0;
}

h2o_qpack_encoder_t *h2o_qpack_create_encoder(uint32_t header_table_size, uint16_t max_blocked)
{
    h2o_qpack_encoder_t *qpack = h2o_mem_alloc(sizeof(*qpack));
    header_table_init(&qpack->table, header_table_size);
    qpack->largest_known_received = 0;
    qpack->max_blocked = max_blocked;
    qpack->num_blocked = 0;
    memset(&qpack->inflight, 0, sizeof(qpack->inflight));
    return qpack;
}

void h2o_qpack_destroy_encoder(h2o_qpack_encoder_t *qpack)
{
    header_table_dispose(&qpack->table);
    free(qpack->inflight.entries);
    free(qpack);
}

static int handle_table_state_synchronize(h2o_qpack_encoder_t *qpack, int64_t insert_count, const char **err_desc)
{
    if (qpack == NULL || insert_count == 0)
        goto Error;

    int64_t new_value = qpack->largest_known_received + insert_count;
    if (new_value >= qpack_table_total_inserts(&qpack->table))
        goto Error;
    qpack->largest_known_received = new_value;

    return 0;
Error:
    *err_desc = "Table State Synchronize: invalid argument";
    return H2O_HTTP3_ERROR_QPACK_DECODER_STREAM;
}

static void evict_inflight_by_index(h2o_qpack_encoder_t *qpack, size_t index)
{
    if (qpack->inflight.entries[index].encoder_flags.is_blocking)
        --qpack->num_blocked;
    --qpack->inflight.size;

    if (qpack->inflight.size == 0) {
        free(qpack->inflight.entries);
        memset(&qpack->inflight, 0, sizeof(qpack->inflight));
    } else if (index < qpack->inflight.size) {
        memmove(qpack->inflight.entries + index, qpack->inflight.entries + index + 1, qpack->inflight.size - index);
    }
}

static int handle_header_ack(h2o_qpack_encoder_t *qpack, int64_t stream_id, const char **err_desc)
{
    size_t i;

    if (qpack != NULL) {
        for (i = 0; i < qpack->inflight.size; ++i)
            if (qpack->inflight.entries[i].stream_id == stream_id)
                goto Found;
    }
    /* not found */
    *err_desc = "Header Acknowledgement: invalid stream id";
    return H2O_HTTP3_ERROR_QPACK_DECODER_STREAM;

Found:
    /* update largest reference */
    if (qpack->largest_known_received < qpack->inflight.entries[i].largest_ref)
        qpack->largest_known_received = qpack->inflight.entries[i].largest_ref;
    /* evict the found entry */
    evict_inflight_by_index(qpack, i);

    return 0;
}

static int handle_stream_cancellation(h2o_qpack_encoder_t *qpack, int64_t stream_id, const char **err_desc)
{
    size_t index = 0;

    if (qpack != NULL) {
        while (index < qpack->inflight.size) {
            if (qpack->inflight.entries[index].stream_id == stream_id) {
                evict_inflight_by_index(qpack, index);
            } else {
                ++index;
            }
        }
    }

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
    if (ret == H2O_HTTP3_ERROR_INCOMPLETE)
        ret = 0;
    return (int)ret;
}

static int64_t lookup_dynamic(h2o_qpack_encoder_t *qpack, const h2o_iovec_t *name, h2o_iovec_t value, int acked_only, int *is_exact)
{
    size_t i;
    int64_t name_found = -1;

    for (i = acked_only ? qpack->largest_known_received : qpack_table_total_inserts(&qpack->table) - 1;
         i >= qpack->table.base_offset; --i) {
        struct st_h2o_qpack_header_t *entry = qpack->table.first[i - qpack->table.base_offset];
        /* compare names (and continue unless they match) */
        if (h2o_iovec_is_token(name)) {
            if (name != entry->name)
                continue;
        } else {
            if (!h2o_memis(name->base, name->len, entry->name->base, entry->name->len))
                continue;
        }
        /* compare values */
        if (h2o_memis(value.base, value.len, entry->value, entry->value_len)) {
            *is_exact = 1;
            return i;
        }
        if (name_found == -1)
            name_found = i;
    }

    *is_exact = 0;
    return name_found;
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

static void emit_insert_with_nameref(h2o_qpack_encoder_t *qpack, h2o_mem_pool_t *pool, h2o_byte_vector_t *buf, int is_static,
                                     int64_t index, h2o_iovec_t value)
{
    h2o_vector_reserve(pool, buf, buf->size + (H2O_HPACK_ENCODE_INT_MAX_LENGTH * 2) + value.len);
    buf->entries[buf->size] = 0x80 | (is_static ? 0x40 : 0);
    flatten_int(buf, index, 6);
    flatten_string(buf, value.base, value.len, 7, 0);
}

static void emit_insert_without_nameref(h2o_qpack_encoder_t *qpack, h2o_mem_pool_t *pool, h2o_byte_vector_t *buf,
                                        const h2o_iovec_t *name, h2o_iovec_t value)
{
    h2o_vector_reserve(pool, buf, buf->size + (H2O_HPACK_ENCODE_INT_MAX_LENGTH * 2) + name->len + value.len);
    buf->entries[buf->size] = 0x40;
    flatten_string(buf, name->base, name->len, 5, 0);
    flatten_string(buf, value.base, value.len, 7, 0);
}

static void flatten_static_indexed(struct st_h2o_qpack_flatten_context_t *ctx, int32_t index)
{
    h2o_vector_reserve(ctx->pool, &ctx->headers_buf, ctx->headers_buf.size + H2O_HPACK_ENCODE_INT_MAX_LENGTH);
    ctx->headers_buf.entries[ctx->headers_buf.size] = 0xc0;
    flatten_int(&ctx->headers_buf, index, 6);
}

static void flatten_dynamic_indexed(struct st_h2o_qpack_flatten_context_t *ctx, int64_t index)
{
    h2o_vector_reserve(ctx->pool, &ctx->headers_buf, ctx->headers_buf.size + H2O_HPACK_ENCODE_INT_MAX_LENGTH);

    if (index > ctx->largest_ref)
        ctx->largest_ref = index;

    if (index <= ctx->base_index) {
        /* indexed */
        ctx->headers_buf.entries[ctx->headers_buf.size] = 0x80;
        flatten_int(&ctx->headers_buf, ctx->base_index - index, 6);
    } else {
        /* indexed (post-base) */
        ctx->headers_buf.entries[ctx->headers_buf.size] = 0x10;
        flatten_int(&ctx->headers_buf, index - ctx->base_index - 1, 4);
    }
}

static void flatten_static_nameref(struct st_h2o_qpack_flatten_context_t *ctx, int32_t index, h2o_iovec_t value, int dont_compress)
{
    h2o_vector_reserve(ctx->pool, &ctx->headers_buf, ctx->headers_buf.size + H2O_HPACK_ENCODE_INT_MAX_LENGTH * 2 + value.len);
    ctx->headers_buf.entries[ctx->headers_buf.size] = 0x50 | (dont_compress ? 0x20 : 0);
    flatten_int(&ctx->headers_buf, index, 4);
    flatten_string(&ctx->headers_buf, value.base, value.len, 7, dont_compress);
}

static void flatten_dynamic_nameref(struct st_h2o_qpack_flatten_context_t *ctx, int64_t index, h2o_iovec_t value, int dont_compress)
{
    if (index > ctx->largest_ref)
        ctx->largest_ref = index;

    h2o_vector_reserve(ctx->pool, &ctx->headers_buf, ctx->headers_buf.size + H2O_HPACK_ENCODE_INT_MAX_LENGTH * 2 + value.len);
    if (index <= ctx->base_index) {
        ctx->headers_buf.entries[ctx->headers_buf.size] = 0x40 | (dont_compress ? 0x20 : 0);
        flatten_int(&ctx->headers_buf, ctx->base_index - index, 4);
    } else {
        ctx->headers_buf.entries[ctx->headers_buf.size] = dont_compress ? 0x8 : 0;
        flatten_int(&ctx->headers_buf, index - ctx->base_index - 1, 3);
    }
    flatten_string(&ctx->headers_buf, value.base, value.len, 7, dont_compress);
}

static void flatten_without_nameref(struct st_h2o_qpack_flatten_context_t *ctx, const h2o_iovec_t *name, h2o_iovec_t value,
                                    int dont_compress)
{
    h2o_vector_reserve(ctx->pool, &ctx->headers_buf,
                       ctx->headers_buf.size + H2O_HPACK_ENCODE_INT_MAX_LENGTH * 2 + name->len + value.len);
    ctx->headers_buf.entries[ctx->headers_buf.size] = 0x20 | (dont_compress ? 0x10 : 0);
    flatten_string(&ctx->headers_buf, name->base, name->len, 3, 0);
    flatten_string(&ctx->headers_buf, value.base, value.len, 7, dont_compress);
}

static void do_flatten_header(struct st_h2o_qpack_flatten_context_t *ctx, int32_t static_index, int is_exact, int likely_to_repeat,
                              const h2o_iovec_t *name, h2o_iovec_t value, h2o_header_flags_t flags)
{
    int64_t dynamic_index;

    if (static_index >= 0 && is_exact) {
        flatten_static_indexed(ctx, static_index);
        return;
    }

    if (ctx->qpack != NULL) {
        /* try dynamic indexed */
        if ((dynamic_index = lookup_dynamic(ctx->qpack, name, value, ctx->encoder_buf == NULL, &is_exact)) >= 0 && is_exact) {
            flatten_dynamic_indexed(ctx, dynamic_index);
            return;
        }
        /* emit to encoder buf and dynamic index?
         * At the moment the strategy is dumb; we emit encoder stream data until the table becomes full. Never triggers eviction.
         */
        if (likely_to_repeat && ctx->encoder_buf != NULL && ((static_index < 0 && dynamic_index < 0) || value.len >= 8) &&
            name->len + value.len + HEADER_ENTRY_SIZE_OFFSET <= ctx->qpack->table.max_size - ctx->qpack->table.num_bytes) {
            /* emit instruction to decoder stream */
            if (static_index >= 0) {
                emit_insert_with_nameref(ctx->qpack, ctx->pool, ctx->encoder_buf, 1, static_index, value);
            } else if (dynamic_index >= 0) {
                emit_insert_with_nameref(ctx->qpack, ctx->pool, ctx->encoder_buf, 0, dynamic_index, value);
            } else {
                emit_insert_without_nameref(ctx->qpack, ctx->pool, ctx->encoder_buf, name, value);
            }
            /* register the entry to table */
            struct st_h2o_qpack_header_t *added;
            if (h2o_iovec_is_token(name)) {
                added = h2o_mem_alloc_shared(NULL, offsetof(struct st_h2o_qpack_header_t, value) + value.len + 1, NULL);
                added->name = (h2o_iovec_t *)name;
            } else {
                added =
                    h2o_mem_alloc_shared(NULL, offsetof(struct st_h2o_qpack_header_t, value) + name->len + 1 + value.len + 1, NULL);
                added->name = &added->_name_buf;
                added->_name_buf = h2o_iovec_init(added->value + added->value_len + 1, name->len);
                memcpy(added->_name_buf.base, name->base, name->len);
                added->_name_buf.base[name->len] = '\0';
            }
            added->value_len = value.len;
            memcpy(added->value, value.base, value.len);
            added->value[value.len] = '\0';
            header_table_insert(&ctx->qpack->table, added);
            /* emit header field to headers block */
            flatten_dynamic_indexed(ctx, qpack_table_total_inserts(&ctx->qpack->table) - 1);
            return;
        }
    } else {
        dynamic_index = -1;
    }

    if (static_index >= 0) {
        flatten_static_nameref(ctx, static_index, value, flags.dont_compress);
    } else if (dynamic_index >= 0) {
        flatten_dynamic_nameref(ctx, dynamic_index, value, flags.dont_compress);
    } else {
        flatten_without_nameref(ctx, name, value, flags.dont_compress);
    }
}

static void flatten_header(struct st_h2o_qpack_flatten_context_t *ctx, const h2o_header_t *header)
{
    int32_t static_index = -1;
    int is_exact = 0, likely_to_repeat = 0;

    /* obtain static index if possible */
    if (h2o_iovec_is_token(header->name)) {
        const h2o_token_t *token = H2O_STRUCT_FROM_MEMBER(h2o_token_t, buf, header->name);
        static_index = h2o_qpack_lookup_static[token - h2o__tokens](header->value, &is_exact);
        likely_to_repeat = token->flags.likely_to_repeat;
    }

    return do_flatten_header(ctx, static_index, is_exact, likely_to_repeat, header->name, header->value, header->flags);
}

static void flatten_known_header_with_static_lookup(struct st_h2o_qpack_flatten_context_t *ctx,
                                                    h2o_qpack_lookup_static_cb lookup_cb, const h2o_token_t *name,
                                                    h2o_iovec_t value)
{
    int is_exact;
    int32_t static_index = lookup_cb(value, &is_exact);
    assert(index >= 0);

    do_flatten_header(ctx, static_index, is_exact, name->flags.likely_to_repeat, &name->buf, value, (h2o_header_flags_t){0});
}

/* header of the qpack message that are written afterwards */
static const size_t PREFIX_CAPACITY =
    1 /* frame header */ + 8 /* frame payload len */ + H2O_HPACK_ENCODE_INT_MAX_LENGTH + H2O_HPACK_ENCODE_INT_MAX_LENGTH;

static void prepare_flatten(struct st_h2o_qpack_flatten_context_t *ctx, h2o_qpack_encoder_t *qpack, h2o_mem_pool_t *pool,
                            int64_t stream_id, h2o_byte_vector_t *encoder_buf)
{
    ctx->qpack = qpack;
    ctx->pool = pool;
    ctx->stream_id = stream_id;
    ctx->encoder_buf = qpack != NULL && qpack->num_blocked < qpack->max_blocked ? encoder_buf : NULL;
    ctx->headers_buf = (h2o_byte_vector_t){NULL};
    ctx->base_index = qpack != NULL ? qpack_table_total_inserts(&qpack->table) - 1 : 0;
    ctx->largest_ref = 0;

    /* allocate some space, hoping to avoid realloc, but not wasting too much */
    h2o_vector_reserve(ctx->pool, &ctx->headers_buf, PREFIX_CAPACITY + 100);
    ctx->headers_buf.size = PREFIX_CAPACITY;
}

static h2o_iovec_t finalize_flatten(struct st_h2o_qpack_flatten_context_t *ctx)
{
    if (ctx->largest_ref == 0) {
        ctx->base_index = 0;
    } else {
        int is_blocking = 0;
        /* adjust largest reference to achieve more compact representation on wire without risking blocking */
        if (ctx->largest_ref < ctx->qpack->largest_known_received) {
            ctx->largest_ref = ctx->qpack->largest_known_received;
        } else if (ctx->largest_ref > ctx->qpack->largest_known_received) {
            assert(ctx->qpack->num_blocked < ctx->qpack->max_blocked);
            ++ctx->qpack->num_blocked;
            is_blocking = 1;
        }
        /* mark as inflight */
        h2o_vector_reserve(NULL, &ctx->qpack->inflight, ctx->qpack->inflight.size + 1);
        ctx->qpack->inflight.entries[ctx->qpack->inflight.size++] =
            (struct st_h2o_qpack_blocked_streams_t){ctx->stream_id, ctx->largest_ref, {{is_blocking}}};
    }

    size_t start_off = PREFIX_CAPACITY;

    { /* prepend largest ref and delta base index */
        uint8_t buf[H2O_HPACK_ENCODE_INT_MAX_LENGTH * 2], *p = buf;
        /* largest_ref */
        *p = 0;
        p = h2o_hpack_encode_int(p, ctx->largest_ref != 0 ? ctx->largest_ref + 1 : 0, 8);
        /* delta base index */
        if (ctx->largest_ref <= ctx->base_index) {
            *p = 0;
            p = h2o_hpack_encode_int(p, ctx->base_index - ctx->largest_ref, 7);
        } else {
            *p = 0x80;
            p = h2o_hpack_encode_int(p, ctx->largest_ref - ctx->base_index - 1, 7);
        }
        memcpy(ctx->headers_buf.entries + start_off - (p - buf), buf, p - buf);
        start_off -= p - buf;
    }

    /* prepend frame header */
    size_t len_len = quicly_encodev_capacity(ctx->headers_buf.size - start_off);
    quicly_encodev(ctx->headers_buf.entries + start_off - len_len, ctx->headers_buf.size - start_off);
    start_off -= len_len;
    ctx->headers_buf.entries[--start_off] = H2O_HTTP3_FRAME_TYPE_HEADERS;

    return h2o_iovec_init(ctx->headers_buf.entries + start_off, ctx->headers_buf.size - start_off);
}

h2o_iovec_t h2o_qpack_flatten_request(h2o_qpack_encoder_t *_qpack, h2o_mem_pool_t *_pool, int64_t _stream_id,
                                      h2o_byte_vector_t *_encoder_buf, h2o_iovec_t method, const h2o_url_scheme_t *scheme,
                                      h2o_iovec_t authority, h2o_iovec_t path, const h2o_header_t *headers, size_t num_headers,
                                      h2o_iovec_t datagram_flow_id)
{
    struct st_h2o_qpack_flatten_context_t ctx;

    prepare_flatten(&ctx, _qpack, _pool, _stream_id, _encoder_buf);

    /* pseudo headers */
    flatten_known_header_with_static_lookup(&ctx, h2o_qpack_lookup_method, H2O_TOKEN_METHOD, method);
    int is_connect = h2o_memis(method.base, method.len, H2O_STRLIT("CONNECT"));
    if (!is_connect) {
        if (scheme == &H2O_URL_SCHEME_HTTP) {
            flatten_static_indexed(&ctx, 22);
        } else if (scheme == &H2O_URL_SCHEME_HTTPS) {
            flatten_static_indexed(&ctx, 23);
        } else {
            flatten_known_header_with_static_lookup(&ctx, h2o_qpack_lookup_scheme, H2O_TOKEN_SCHEME, scheme->name);
        }
    }
    flatten_known_header_with_static_lookup(&ctx, h2o_qpack_lookup_authority, H2O_TOKEN_AUTHORITY, authority);
    if (!is_connect)
        flatten_known_header_with_static_lookup(&ctx, h2o_qpack_lookup_path, H2O_TOKEN_PATH, path);

    /* flatten headers */
    size_t i;
    for (i = 0; i != num_headers; ++i)
        flatten_header(&ctx, headers + i);

    if (datagram_flow_id.base != NULL)
        flatten_known_header_with_static_lookup(&ctx, h2o_qpack_lookup_datagram_flow_id, H2O_TOKEN_DATAGRAM_FLOW_ID,
                                                datagram_flow_id);

    return finalize_flatten(&ctx);
}

h2o_iovec_t h2o_qpack_flatten_response(h2o_qpack_encoder_t *_qpack, h2o_mem_pool_t *_pool, int64_t _stream_id,
                                       h2o_byte_vector_t *_encoder_buf, int status, const h2o_header_t *headers, size_t num_headers,
                                       const h2o_iovec_t *server_name, size_t content_length, h2o_iovec_t datagram_flow_id)
{
    struct st_h2o_qpack_flatten_context_t ctx;

    prepare_flatten(&ctx, _qpack, _pool, _stream_id, _encoder_buf);

    /* pseudo headers */
    switch (status) {
#define INDEXED_STATUS(cp, st)                                                                                                     \
    case st:                                                                                                                       \
        flatten_static_indexed(&ctx, cp);                                                                                          \
        break
        INDEXED_STATUS(24, 103);
        INDEXED_STATUS(25, 200);
        INDEXED_STATUS(26, 304);
        INDEXED_STATUS(27, 404);
        INDEXED_STATUS(28, 503);
        INDEXED_STATUS(63, 100);
        INDEXED_STATUS(64, 204);
        INDEXED_STATUS(65, 206);
        INDEXED_STATUS(66, 302);
        INDEXED_STATUS(67, 400);
        INDEXED_STATUS(68, 403);
        INDEXED_STATUS(69, 421);
        INDEXED_STATUS(70, 425);
        INDEXED_STATUS(71, 500);
#undef INDEXED_STATUS
    default: {
        char status_str[sizeof(H2O_UINT16_LONGEST_STR)];
        sprintf(status_str, "%" PRIu16, (uint16_t)status);
        do_flatten_header(&ctx, 24, 0, H2O_TOKEN_STATUS->flags.likely_to_repeat, &H2O_TOKEN_STATUS->buf,
                          h2o_iovec_init(status_str, strlen(status_str)), (h2o_header_flags_t){0});
    } break;
    }

    /* TODO keep some kind of reference to the indexed Server header, and reuse it */
    if (server_name != NULL && server_name->len != 0)
        do_flatten_header(&ctx, 92, 0, H2O_TOKEN_SERVER->flags.likely_to_repeat, &H2O_TOKEN_SERVER->buf, *server_name,
                          (h2o_header_flags_t){0});

    /* content-length */
    if (content_length != SIZE_MAX) {
        if (content_length == 0) {
            flatten_static_indexed(&ctx, 4);
        } else {
            char cl_str[sizeof(H2O_SIZE_T_LONGEST_STR)];
            size_t cl_len = (size_t)sprintf(cl_str, "%zu", content_length);
            do_flatten_header(&ctx, 4, 0, H2O_TOKEN_CONTENT_LENGTH->flags.likely_to_repeat, &H2O_TOKEN_CONTENT_LENGTH->buf,
                              h2o_iovec_init(cl_str, cl_len), (h2o_header_flags_t){0});
        }
    }

    /* flatten headers */
    size_t i;
    for (i = 0; i != num_headers; ++i)
        flatten_header(&ctx, headers + i);

    if (datagram_flow_id.base != NULL)
        flatten_known_header_with_static_lookup(&ctx, h2o_qpack_lookup_datagram_flow_id, H2O_TOKEN_DATAGRAM_FLOW_ID,
                                                datagram_flow_id);

    return finalize_flatten(&ctx);
}
