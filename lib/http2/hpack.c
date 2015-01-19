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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "h2o.h"
#include "h2o/http2.h"

#define HEADER_TABLE_OFFSET 62
#define HEADER_TABLE_ENTRY_SIZE_OFFSET 32
#define STATUS_HEADER_MAX_SIZE 5

struct st_h2o_hpack_static_table_entry_t {
    const h2o_token_t *name;
    const h2o_iovec_t value;
};

struct st_h2o_hpack_header_table_entry_t {
    h2o_iovec_t *name;
    h2o_iovec_t *value;
};

struct st_h2o_decode_header_result_t {
    h2o_iovec_t *name;
    h2o_iovec_t *value;
};

#include "hpack_huffman_table.h"
#include "hpack_static_table.h"

static inline int value_is_part_of_static_table(const h2o_iovec_t *value)
{
    return &h2o_hpack_static_table[0].value <= value &&
           value < &h2o_hpack_static_table[sizeof(h2o_hpack_static_table) / sizeof(h2o_hpack_static_table[0])].value;
}

static h2o_iovec_t *alloc_buf(h2o_mem_pool_t *pool, size_t len)
{
    h2o_iovec_t *buf = h2o_mem_alloc_shared(pool, sizeof(h2o_iovec_t) + len + 1, NULL);
    buf->base = (char *)buf + sizeof(h2o_iovec_t);
    buf->len = len;
    return buf;
}

static int contains_uppercase(const char *s, size_t len)
{
    for (; len != 0; ++s, --len) {
        unsigned ch = *(unsigned char*)s;
        if (ch - 'A' < 26U)
            return 1;
    }
    return 0;
}

static int32_t decode_int(const uint8_t **src, const uint8_t *src_end, size_t prefix_bits)
{
    int32_t value, mult;
    uint8_t prefix_max = (1 << prefix_bits) - 1;

    if (*src == src_end)
        return -1;

    value = (uint8_t) * (*src)++ & prefix_max;
    if (value != prefix_max) {
        return value;
    }

    /* we only allow at most 4 octets (excluding prefix) to be used as int (== 2**(4*7) == 2**28) */
    if (src_end - *src > 4)
        src_end = *src + 4;

    value = prefix_max;
    for (mult = 1;; mult *= 128) {
        if (*src == src_end)
            return -1;
        value += (**src & 127) * mult;
        if ((*(*src)++ & 128) == 0)
            return value;
    }
}

static char *huffdecode4(char *dst, uint8_t in, uint8_t *state, int *maybe_eos)
{
    const nghttp2_huff_decode *entry = huff_decode_table[*state] + in;

    if ((entry->flags & NGHTTP2_HUFF_FAIL) != 0)
        return NULL;
    if ((entry->flags & NGHTTP2_HUFF_SYM) != 0)
        *dst++ = entry->sym;
    *state = entry->state;
    *maybe_eos = (entry->flags & NGHTTP2_HUFF_ACCEPTED) != 0;

    return dst;
}

static h2o_iovec_t *decode_huffman(h2o_mem_pool_t *pool, const uint8_t *src, size_t len)
{
    const uint8_t *src_end = src + len;
    char *dst;
    uint8_t state = 0;
    int maybe_eos = 1;
    h2o_iovec_t *dst_buf = alloc_buf(pool, len * 2); /* max compression ratio is >= 0.5 */

    dst = dst_buf->base;
    for (; src != src_end; src++) {
        if ((dst = huffdecode4(dst, *src >> 4, &state, &maybe_eos)) == NULL)
            return NULL;
        if ((dst = huffdecode4(dst, *src & 0xf, &state, &maybe_eos)) == NULL)
            return NULL;
    }

    if (!maybe_eos)
        return NULL;

    *dst = '\0';
    dst_buf->len = dst - dst_buf->base;
    return dst_buf;
}

static h2o_iovec_t *decode_string(h2o_mem_pool_t *pool, const uint8_t **src, const uint8_t *src_end)
{
    h2o_iovec_t *ret;
    int is_huffman;
    int32_t len;

    if (*src == src_end)
        return NULL;

    is_huffman = (**src & 0x80) != 0;
    if ((len = decode_int(src, src_end, 7)) == -1)
        return NULL;

    if (is_huffman) {
        if ((ret = decode_huffman(pool, *src, len)) == NULL)
            return NULL;
    } else {
        if (*src + len > src_end)
            return NULL;
        ret = alloc_buf(pool, len);
        memcpy(ret->base, *src, len);
        ret->base[len] = '\0';
    }
    *src += len;

    return ret;
}

static inline struct st_h2o_hpack_header_table_entry_t *header_table_get(h2o_hpack_header_table_t *table, size_t index)
{
    size_t entry_index = (index + table->entry_start_index) % table->entry_capacity;
    struct st_h2o_hpack_header_table_entry_t *entry = table->entries + entry_index;
    assert(entry->name != NULL);
    return entry;
}

static void header_table_evict_one(h2o_hpack_header_table_t *table)
{
    struct st_h2o_hpack_header_table_entry_t *entry;
    assert(table->num_entries != 0);

    entry = header_table_get(table, --table->num_entries);
    table->hpack_size -= entry->name->len + entry->value->len + HEADER_TABLE_ENTRY_SIZE_OFFSET;
    if (!h2o_iovec_is_token(entry->name))
        h2o_mem_release_shared(entry->name);
    if (!value_is_part_of_static_table(entry->value))
        h2o_mem_release_shared(entry->value);
    entry->name = NULL;
    entry->value = NULL;
}

static struct st_h2o_hpack_header_table_entry_t *header_table_add(h2o_hpack_header_table_t *table, size_t size_add,
                                                                  size_t max_num_entries)
{
    /* adjust the size */
    while (table->num_entries != 0 && table->hpack_size + size_add > table->hpack_capacity)
        header_table_evict_one(table);
    while (max_num_entries <= table->num_entries)
        header_table_evict_one(table);
    if (table->num_entries == 0) {
        assert(table->hpack_size == 0);
        if (size_add > table->hpack_capacity)
            return NULL;
    }
    table->hpack_size += size_add;

    /* grow the entries if full */
    if (table->num_entries == table->entry_capacity) {
        size_t new_capacity = table->num_entries * 2;
        if (new_capacity < 16)
            new_capacity = 16;
        struct st_h2o_hpack_header_table_entry_t *new_entries =
            h2o_mem_alloc(new_capacity * sizeof(struct st_h2o_hpack_header_table_entry_t));
        if (table->num_entries != 0) {
            size_t src_index = table->entry_start_index, dst_index = 0;
            do {
                new_entries[dst_index] = table->entries[src_index];
                ++dst_index;
                src_index = (src_index + 1) % table->entry_capacity;
            } while (dst_index != table->num_entries);
        }
        memset(new_entries + table->num_entries, 0, sizeof(*new_entries) * (new_capacity - table->num_entries));
        free(table->entries);
        table->entries = new_entries;
        table->entry_capacity = new_capacity;
        table->entry_start_index = 0;
    }

    ++table->num_entries;
    table->entry_start_index = (table->entry_start_index - 1 + table->entry_capacity) % table->entry_capacity;
    return table->entries + table->entry_start_index;
}

static int decode_header(h2o_mem_pool_t *pool, struct st_h2o_decode_header_result_t *result,
                         h2o_hpack_header_table_t *hpack_header_table, const uint8_t **const src, const uint8_t *src_end,
                         const char **err_desc)
{
    int32_t index = 0;
    int value_is_indexed = 0, do_index = 0;

Redo:
    if (*src == src_end)
        return H2O_HTTP2_ERROR_COMPRESSION;

    /* determine the mode and handle accordingly */
    if (**src >= 128) {
        /* indexed header field representation */
        if ((index = decode_int(src, src_end, 7)) <= 0)
            return H2O_HTTP2_ERROR_COMPRESSION;
        value_is_indexed = 1;
    } else if (**src >= 64) {
        /* literal header field with incremental handling */
        if (**src == 64) {
            ++*src;
        } else if ((index = decode_int(src, src_end, 6)) <= 0) {
            return H2O_HTTP2_ERROR_COMPRESSION;
        }
        do_index = 1;
    } else if (**src < 32) {
        /* literal header field without indexing / never indexed */
        if ((**src & 0xf) == 0) {
            ++*src;
        } else if ((index = decode_int(src, src_end, 4)) <= 0) {
            return H2O_HTTP2_ERROR_COMPRESSION;
        }
    } else {
        /* size update */
        int new_apacity;
        if ((new_apacity = decode_int(src, src_end, 5)) < 0) {
            return H2O_HTTP2_ERROR_COMPRESSION;
        }
        if (new_apacity > hpack_header_table->hpack_max_capacity) {
            return H2O_HTTP2_ERROR_COMPRESSION;
        }
        hpack_header_table->hpack_capacity = new_apacity;
        while (hpack_header_table->num_entries != 0 && hpack_header_table->hpack_size > hpack_header_table->hpack_capacity) {
            header_table_evict_one(hpack_header_table);
        }
        goto Redo;
    }

    /* determine the header */
    if (index != 0) {
        /* existing name (and value?) */
        if (index < HEADER_TABLE_OFFSET) {
            result->name = (h2o_iovec_t *)h2o_hpack_static_table[index - 1].name;
            if (value_is_indexed) {
                result->value = (h2o_iovec_t *)&h2o_hpack_static_table[index - 1].value;
            }
        } else if (index - HEADER_TABLE_OFFSET < hpack_header_table->num_entries) {
            struct st_h2o_hpack_header_table_entry_t *entry = header_table_get(hpack_header_table, index - HEADER_TABLE_OFFSET);
            result->name = entry->name;
            if (!h2o_iovec_is_token(result->name))
                h2o_mem_link_shared(pool, result->name);
            if (value_is_indexed) {
                result->value = entry->value;
                h2o_mem_link_shared(pool, result->value);
            }
        } else {
            return H2O_HTTP2_ERROR_COMPRESSION;
        }
    } else {
        /* non-existing name */
        const h2o_token_t *name_token;
        if ((result->name = decode_string(pool, src, src_end)) == NULL)
            return H2O_HTTP2_ERROR_COMPRESSION;
        if (contains_uppercase(result->name->base, result->name->len)) {
            *err_desc = "found an upper-case letter in header name";
            return H2O_HTTP2_ERROR_PROTOCOL;
        }
        /* predefined header names should be interned */
        if ((name_token = h2o_lookup_token(result->name->base, result->name->len)) != NULL)
            result->name = (h2o_iovec_t *)&name_token->buf;
    }

    /* determine the value (if necessary) */
    if (!value_is_indexed) {
        if ((result->value = decode_string(pool, src, src_end)) == NULL)
            return H2O_HTTP2_ERROR_COMPRESSION;
    }

    /* add the decoded header to the header table if necessary */
    if (do_index) {
        struct st_h2o_hpack_header_table_entry_t *entry =
            header_table_add(hpack_header_table, result->name->len + result->value->len + HEADER_TABLE_ENTRY_SIZE_OFFSET, SIZE_MAX);
        if (entry != NULL) {
            entry->name = result->name;
            if (!h2o_iovec_is_token(entry->name))
                h2o_mem_addref_shared(entry->name);
            entry->value = result->value;
            if (!value_is_part_of_static_table(entry->value))
                h2o_mem_addref_shared(entry->value);
        }
    }

    return 0;
}

static uint8_t *encode_status(uint8_t *dst, int status)
{
    /* see also: STATUS_HEADER_MAX_SIZE */

    assert(100 <= status && status <= 999);

    switch (status) {
#define COMMON_CODE(code, st)                                                                                                      \
    case st:                                                                                                                       \
        *dst++ = 0x80 | code;                                                                                                      \
        break
        COMMON_CODE(8, 200);
        COMMON_CODE(9, 204);
        COMMON_CODE(10, 206);
        COMMON_CODE(11, 304);
        COMMON_CODE(12, 400);
        COMMON_CODE(13, 404);
        COMMON_CODE(14, 500);
#undef COMMON_CODE
    default:
        /* use literal header field without indexing - indexed name */
        *dst++ = 8;
        *dst++ = 3;
        sprintf((char *)dst, "%d", status);
        dst += 3;
        break;
    }

    return dst;
}

void h2o_hpack_dispose_header_table(h2o_hpack_header_table_t *header_table)
{
    if (header_table->num_entries != 0) {
        size_t index = header_table->entry_start_index;
        do {
            struct st_h2o_hpack_header_table_entry_t *entry = header_table->entries + index;
            if (!h2o_iovec_is_token(entry->name))
                h2o_mem_release_shared(entry->name);
            if (!value_is_part_of_static_table(entry->value))
                h2o_mem_release_shared(entry->value);
            index = (index + 1) % header_table->entry_capacity;
        } while (--header_table->num_entries != 0);
    }
    free(header_table->entries);
}

int h2o_hpack_parse_headers(h2o_req_t *req, h2o_hpack_header_table_t *header_table, const uint8_t *src, size_t len,
                            const char **err_desc, int *err_is_stream_level)
{
    const uint8_t *src_end = src + len;
    int allow_pseudo = 1;

    while (src != src_end) {
        struct st_h2o_decode_header_result_t r;
        int ret = decode_header(&req->pool, &r, header_table, &src, src_end, err_desc);
        if (ret != 0) {
            *err_is_stream_level = 0;
            return ret;
        }
        if (r.name->base[0] == ':') {
            if (allow_pseudo) {
                /* FIXME validate the chars in the value (e.g. reject SP in path) */
                if (r.name == &H2O_TOKEN_AUTHORITY->buf) {
                    /* FIXME should we perform this check? */
                    if (req->authority.base != NULL)
                        goto StreamLevelProcotolError;
                    req->authority = *r.value;
                } else if (r.name == &H2O_TOKEN_METHOD->buf) {
                    if (req->method.base != NULL)
                        goto StreamLevelProcotolError;
                    req->method = *r.value;
                } else if (r.name == &H2O_TOKEN_PATH->buf) {
                    if (req->path.base != NULL)
                        goto StreamLevelProcotolError;
                    req->path = *r.value;
                } else if (r.name == &H2O_TOKEN_SCHEME->buf) {
                    if (req->scheme.base != NULL)
                        goto StreamLevelProcotolError;
                    req->scheme = *r.value;
                } else {
                    goto StreamLevelProcotolError;
                }
            } else {
                goto StreamLevelProcotolError;
            }
        } else {
            allow_pseudo = 0;
            if (h2o_iovec_is_token(r.name)) {
                if (r.name == &H2O_TOKEN_CONTENT_LENGTH->buf) {
                    /* ignore (draft 15 8.1.2.6 says: a server MAY send an HTTP response prior to closing or resetting the stream if
                     * content-length and the actual length differs) */
                } else if (r.name == &H2O_TOKEN_TRANSFER_ENCODING->buf) {
                    /* Transfer-Encoding is not supported in HTTP/2 */
                    goto StreamLevelProcotolError;
                } else {
                    h2o_add_header(&req->pool, &req->headers, H2O_STRUCT_FROM_MEMBER(h2o_token_t, buf, r.name), r.value->base,
                                   r.value->len);
                }
            } else {
                h2o_add_header_by_str(&req->pool, &req->headers, r.name->base, r.name->len, 0, r.value->base, r.value->len);
            }
        }
    }

    return 0;

StreamLevelProcotolError:
    *err_is_stream_level = 1;
    return H2O_HTTP2_ERROR_PROTOCOL;
}

static uint8_t *encode_int(uint8_t *dst, uint32_t value, size_t prefix_bits)
{
    if (value < (1 << prefix_bits)) {
        *dst++ |= value;
    } else {
        /* see also: MAX_ENCODE_INT_LENGTH */
        value -= (1 << prefix_bits) - 1;
        if (value > 0x0fffffff)
            h2o_fatal("value out of range");
        *dst++ |= (1 << prefix_bits) - 1;
        for (; value >= 256; value >>= 8) {
            *dst++ = 0x80 | value;
        }
        *dst++ = value;
    }
    return dst;
}

static size_t encode_huffman(uint8_t *_dst, const uint8_t *src, size_t len)
{
    uint8_t *dst = _dst, *dst_end = dst + len;
    const uint8_t *src_end = src + len;
    uint64_t bits = 0;
    int bits_left = 40;

    while (src != src_end) {
        const nghttp2_huff_sym *sym = huff_sym_table + *src++;
        bits |= (uint64_t)sym->code << (bits_left - sym->nbits);
        bits_left -= sym->nbits;
        while (bits_left <= 32) {
            *dst++ = bits >> 32;
            bits <<= 8;
            bits_left += 8;
            if (dst == dst_end) {
                return -1;
            }
        }
    }

    if (bits_left != 40) {
        bits |= ((uint64_t)1 << bits_left) - 1;
        *dst++ = bits >> 32;
    }
    if (dst == dst_end) {
        return 0;
    }

    return dst - _dst;
}

size_t h2o_hpack_encode_string(uint8_t *_dst, const char *s, size_t len)
{
    uint8_t *dst = _dst;
    uint8_t huffbuf[4096];

    /* try to encode in huffman */
    if (0 < len && len < sizeof(huffbuf)) {
        size_t hufflen = encode_huffman(huffbuf, (const uint8_t *)s, len);
        if (hufflen != 0) {
            *dst = '\x80';
            dst = encode_int(dst, (uint32_t)hufflen, 7);
            memcpy(dst, huffbuf, hufflen);
            dst += hufflen;
            goto Exit;
        }
    }

    /* encode as-is */
    *dst = '\0';
    dst = encode_int(dst, (uint32_t)len, 7);
    memcpy(dst, s, len);
    dst += len;

Exit:
    return dst - _dst;
}

static uint8_t *encode_header(h2o_hpack_header_table_t *header_table, uint8_t *dst, const h2o_iovec_t *name,
                              const h2o_iovec_t *value)
{
    int static_table_name_index, name_is_token = h2o_iovec_is_token(name);

    /* try to send as indexed */
    {
        size_t header_table_index = header_table->entry_start_index, n;
        for (n = header_table->num_entries; n != 0; --n) {
            struct st_h2o_hpack_header_table_entry_t *entry = header_table->entries + header_table_index;
            if (name_is_token) {
                if (name != entry->name)
                    goto Next;
            } else {
                if (!h2o_memis(name->base, name->len, entry->name->base, entry->name->len))
                    goto Next;
            }
            /* name matched! */
            if (!h2o_memis(value->base, value->len, entry->value->base, entry->value->len))
                continue;
            /* name and value matched! */
            *dst = 0x80;
            dst = encode_int(dst, (uint32_t)(header_table->num_entries - n + HEADER_TABLE_OFFSET), 7);
            return dst;
        Next:
            ++header_table_index;
            if (header_table_index == header_table->entry_capacity)
                header_table_index = 0;
        }
    }

    if (h2o_iovec_is_token(name)) {
        const h2o_token_t *name_token = H2O_STRUCT_FROM_MEMBER(h2o_token_t, buf, name);
        static_table_name_index = name_token->http2_static_table_name_index;
    } else {
        static_table_name_index = 0;
    }

    if (static_table_name_index != 0) {
        /* literal header field with indexing (indexed name) */
        *dst = 0x40;
        dst = encode_int(dst, static_table_name_index, 6);
    } else {
        /* literal header field with indexing (new name) */
        *dst++ = 0x40;
        dst += h2o_hpack_encode_string(dst, name->base, name->len);
    }
    dst += h2o_hpack_encode_string(dst, value->base, value->len);

    { /* add to header table (maximum number of entries in output header table is limited to 32 so that the search (see above) would
         not take too long) */
        struct st_h2o_hpack_header_table_entry_t *entry =
            header_table_add(header_table, name->len + value->len + HEADER_TABLE_ENTRY_SIZE_OFFSET, 32);
        if (entry != NULL) {
            if (static_table_name_index != 0) {
                entry->name = (h2o_iovec_t *)h2o_hpack_static_table[static_table_name_index - 1].name;
            } else {
                entry->name = alloc_buf(NULL, name->len);
                entry->name->base[name->len] = '\0';
                memcpy(entry->name->base, name, name->len);
            }
            entry->value = alloc_buf(NULL, value->len);
            entry->value->base[value->len] = '\0';
            memcpy(entry->value->base, value->base, value->len);
        }
    }

    return dst;
}

int h2o_hpack_flatten_headers(h2o_buffer_t **buf, h2o_hpack_header_table_t *header_table, uint32_t stream_id, size_t max_frame_size,
                              h2o_res_t *res, h2o_timestamp_t *ts, const h2o_iovec_t *server_name)
{
    const h2o_header_t *header, *header_end;
    size_t max_capacity = 0;
    uint8_t *base, *dst;

    {                                                      /* calculate maximum required memory */
        size_t max_cur_frame_size = STATUS_HEADER_MAX_SIZE /* for :status: */
#ifndef H2O_UNITTEST
                                    + 2 + H2O_TIMESTR_RFC1123_LEN /* for Date: */
                                    + 5 + server_name->len        /* for Server: */
#endif
            ;

        for (header = res->headers.entries, header_end = header + res->headers.size; header != header_end; ++header) {
            size_t max_header_size = header->name->len + header->value.len + 1 + H2O_HTTP2_ENCODE_INT_MAX_LENGTH * 2;
            if (max_header_size > 16383)
                return -1;
            if (max_cur_frame_size + max_header_size > max_frame_size) {
                max_capacity += H2O_HTTP2_FRAME_HEADER_SIZE + max_cur_frame_size;
                max_cur_frame_size = max_header_size;
            } else {
                max_cur_frame_size += max_header_size;
            }
        }
        max_capacity += H2O_HTTP2_FRAME_HEADER_SIZE + max_cur_frame_size;
    }

    /* allocate */
    base = dst = (void *)h2o_buffer_reserve(buf, max_capacity).base;

    { /* encode */
        uint8_t *cur_frame;
        h2o_iovec_t date_value;

#define EMIT_HEADER(end_headers)                                                                                                   \
    h2o_http2_encode_frame_header(cur_frame, dst - cur_frame - H2O_HTTP2_FRAME_HEADER_SIZE,                                        \
                                  cur_frame == (uint8_t *)base ? H2O_HTTP2_FRAME_TYPE_HEADERS : H2O_HTTP2_FRAME_TYPE_CONTINUATION, \
                                  end_headers ? H2O_HTTP2_FRAME_FLAG_END_HEADERS : 0, stream_id)

        cur_frame = dst;
        dst += H2O_HTTP2_FRAME_HEADER_SIZE;
        dst = encode_status(dst, res->status);
/* TODO keep some kind of reference to the indexed headers of Server and Date, and reuse them */
#ifndef H2O_UNITTEST
        dst = encode_header(header_table, dst, &H2O_TOKEN_SERVER->buf, server_name);
        date_value = h2o_iovec_init(ts->str->rfc1123, H2O_TIMESTR_RFC1123_LEN);
        dst = encode_header(header_table, dst, &H2O_TOKEN_DATE->buf, &date_value);
#endif
        for (header = res->headers.entries, header_end = header + res->headers.size; header != header_end; ++header) {
            size_t max_header_size = header->name->len + header->value.len + 1 + H2O_HTTP2_ENCODE_INT_MAX_LENGTH * 2;
            if (dst - cur_frame - H2O_HTTP2_FRAME_HEADER_SIZE + max_header_size > max_frame_size) {
                EMIT_HEADER(0);
                cur_frame = dst;
                dst += H2O_HTTP2_FRAME_HEADER_SIZE;
            }
            dst = encode_header(header_table, dst, header->name, &header->value);
        }
        EMIT_HEADER(1);

#undef EMIT_HEADER
    }

    assert(dst - base < max_capacity);
    (*buf)->size += dst - base;

    return 0;
}
