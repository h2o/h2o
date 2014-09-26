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
    const h2o_buf_t value;
};

struct st_h2o_hpack_header_table_entry_t {
    union {
        const h2o_token_t *token;
        h2o_buf_t *buf;
    } name;
    h2o_buf_t *value;
    char name_is_token, value_is_const;
};

struct st_h2o_decode_header_result_t {
    const h2o_token_t *name_token;
    h2o_buf_t *name_not_token, *value;
};

#include "hpack_huffman_table.h"
#include "hpack_static_table.h"

static h2o_buf_t *alloc_buf(h2o_mempool_t *pool, size_t len)
{
    h2o_buf_t *buf = h2o_mempool_alloc_shared(pool, sizeof(h2o_buf_t) + len + 1);
    buf->base = (char*)buf + sizeof(h2o_buf_t);
    buf->len = len;
    return buf;
}

static int32_t decode_int(const uint8_t **src, const uint8_t *src_end, size_t prefix_bits)
{
    int32_t value, mult;
    uint8_t prefix_max = (1 << prefix_bits) - 1;

    if (*src == src_end)
        return -1;

    value = (uint8_t)*(*src)++ & prefix_max;
    if (value != prefix_max) {
        return value;
    }

    /* we only allow at most 4 octets (excluding prefix) to be used as int (== 2**(4*7) == 2**28) */
    if (src_end - *src > 4)
        src_end = *src + 4;

    value = prefix_max;
    for (mult = 1; ; mult *= 128) {
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

static h2o_buf_t *decode_huffman(h2o_mempool_t *pool, const uint8_t *src, size_t len)
{
    const uint8_t *src_end = src + len;
    char *dst;
    uint8_t state = 0;
    int maybe_eos = 1;
    h2o_buf_t *dst_buf = alloc_buf(pool, len * 2); /* max compression ratio is >= 0.5 */

    dst = dst_buf->base;
    for (; src != src_end; src++) {
        if ((dst = huffdecode4(dst, *src >> 4, &state, &maybe_eos)) == NULL)
            return NULL;
        if ((dst = huffdecode4(dst, *src & 0xf, &state, &maybe_eos)) == NULL)
            return NULL;
    }

    if (! maybe_eos)
        return NULL;

    *dst = '\0';
    dst_buf->len = dst - dst_buf->base;
    return dst_buf;
}

static h2o_buf_t *decode_string(h2o_mempool_t *pool, const uint8_t **src, const uint8_t *src_end)
{
    h2o_buf_t *ret;
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
    return table->entries + entry_index;
}

static void header_table_evict_one(h2o_hpack_header_table_t *table)
{
    struct st_h2o_hpack_header_table_entry_t *entry;
    assert(table->num_entries != 0);

    entry = header_table_get(table, --table->num_entries);
    if (! entry->name_is_token)
        h2o_mempool_release_shared(entry->name.buf);
    if (! entry->value_is_const)
        h2o_mempool_release_shared(entry->value);
}

static struct st_h2o_hpack_header_table_entry_t *header_table_add(h2o_hpack_header_table_t *table, size_t size_add, size_t max_num_entries)
{
    /* adjust the size */
    while (table->num_entries != 0 && table->hpack_size + size_add > table->hpack_capacity)
        header_table_evict_one(table);
    while (max_num_entries < table->num_entries)
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
        struct st_h2o_hpack_header_table_entry_t *new_entries = h2o_malloc(new_capacity * sizeof(struct st_h2o_hpack_header_table_entry_t));
        if (table->num_entries != 0) {
            size_t src_index = 0, dst_index = table->entry_start_index;
            do {
                new_entries[dst_index] = table->entries[src_index];
                ++dst_index;
                src_index = (src_index + 1) % table->entry_capacity;
            } while (dst_index != table->num_entries);
        }
        free(table->entries);
        table->entries = new_entries;
        table->entry_capacity = new_capacity;
        table->entry_start_index = 0;
    }

    ++table->num_entries;
    table->entry_start_index = (table->entry_start_index - 1 + table->entry_capacity) % table->entry_capacity;
    return table->entries + table->entry_start_index;
}

static int decode_header(h2o_mempool_t *pool, struct st_h2o_decode_header_result_t *result, h2o_hpack_header_table_t *hpack_header_table, const uint8_t ** const src, const uint8_t *src_end)
{
    int32_t index = 0;
    int value_is_indexed = 0, value_is_const = 0, do_index = 0;

    if (*src == src_end)
        return -1;

    /* determine the mode and handle accordingly */
    if (**src >= 128) {
        /* indexed header field representation */
        if ((index = decode_int(src, src_end, 7)) <= 0)
            return -1;
        value_is_indexed = 1;
    } else if (**src >= 64) {
        /* literal header field with incremental handling */
        if (**src == 64) {
            ++*src;
        } else if ((index = decode_int(src, src_end, 6)) <= 0) {
            return -1;
        }
        do_index = 1;
    } else if (**src < 32) {
        /* literal header field without indexing / never indexed */
        if ((**src & 0xf) == 0) {
            ++*src;
        } else if ((index = decode_int(src, src_end, 4)) <= 0) {
            return -1;
        }
    } else {
        /* size update */
        assert(!"FIXME");
    }

    /* determine the header */
    if (index != 0) {
        /* existing name (and value?) */
        if (index < HEADER_TABLE_OFFSET) {
            result->name_token = h2o_hpack_static_table[index - 1].name;
            result->name_not_token = NULL;
            if (value_is_indexed) {
                result->value = (h2o_buf_t*)&h2o_hpack_static_table[index - 1].value;
                value_is_const = 1;
            }
        } else if (index - HEADER_TABLE_OFFSET < hpack_header_table->num_entries) {
            struct st_h2o_hpack_header_table_entry_t *entry = header_table_get(hpack_header_table, index - HEADER_TABLE_OFFSET);
            if (entry->name_is_token) {
                result->name_token = entry->name.token;
                result->name_not_token = NULL;
            } else {
                result->name_token = NULL;
                result->name_not_token = entry->name.buf;
                h2o_mempool_link_shared(pool, result->name_not_token);
            }
            if (value_is_indexed) {
                result->value = entry->value;
                h2o_mempool_link_shared(pool, result->value);
            }
        } else {
            return -1;
        }
    } else {
        /* non-existing name */
        if ((result->name_not_token = decode_string(pool, src, src_end)) == NULL)
            return -1;
        result->name_token = h2o_lookup_token(result->name_not_token->base, result->name_not_token->len);
    }

    /* determine the value (if necessary) */
    if (! value_is_indexed) {
        if ((result->value = decode_string(pool, src, src_end)) == NULL)
            return -1;
    }

    /* add the decoded header to the header table if necessary */
    if (do_index) {
        if (result->name_token != NULL) {
            struct st_h2o_hpack_header_table_entry_t *entry = header_table_add(hpack_header_table, result->name_token->buf.len + result->value->len + HEADER_TABLE_ENTRY_SIZE_OFFSET, SIZE_MAX);
            if (entry != NULL) {
                entry->name.token = result->name_token;
                entry->name_is_token = 1;
                entry->value = result->value;
                if (! value_is_const)
                    h2o_mempool_addref_shared(entry->value);
            }
        } else {
            struct st_h2o_hpack_header_table_entry_t *entry = header_table_add(hpack_header_table, result->name_not_token->len + result->value->len + HEADER_TABLE_ENTRY_SIZE_OFFSET, SIZE_MAX);
            if (entry != NULL) {
                entry->name.buf = result->name_not_token;
                entry->name_is_token = 0;
                entry->value = result->value;
                h2o_mempool_addref_shared(entry->name.buf);
                if (! value_is_const)
                    h2o_mempool_addref_shared(entry->value);
            }
        }
    }

    return 0;
}

static uint8_t *encode_status(uint8_t *dst, int status)
{
    /* see also: STATUS_HEADER_MAX_SIZE */

    assert(100 <= status && status <= 999);

    switch (status) {
#define COMMON_CODE(code, st) case st: *dst++ = 0x80 | code; break
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
        sprintf((char*)dst, "%d", status);
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
            if (! entry->name_is_token)
                h2o_mempool_release_shared(entry->name.buf);
            h2o_mempool_release_shared(entry->value);
            index = (index + 1) % header_table->entry_capacity;
        } while (--header_table->num_entries != 0);
    }
    free(header_table->entries);
}

int h2o_hpack_parse_headers(h2o_req_t *req, h2o_hpack_header_table_t *header_table, int *allow_psuedo, const uint8_t *src, size_t len)
{
    const uint8_t *src_end = src + len;

    while (src != src_end) {
        struct st_h2o_decode_header_result_t r;
        if (decode_header(&req->pool, &r, header_table, &src, src_end) != 0)
            return -1;
        if (r.name_token != NULL) {
            if (r.name_token->buf.base[0] == ':') {
                if (*allow_psuedo) {
                    /* FIXME validate the chars in the value (e.g. reject SP in path) */
                    if (r.name_token == H2O_TOKEN_AUTHORITY) {
                        /* FIXME should we perform this check? */
                        if (req->authority.base != NULL)
                            return -1;
                        req->authority = *r.value;
                    } else if (r.name_token == H2O_TOKEN_METHOD) {
                        if (req->method.base != NULL)
                            return -1;
                        req->method = *r.value;
                    } else if (r.name_token == H2O_TOKEN_PATH) {
                        if (req->path.base != NULL)
                            return -1;
                        req->path = *r.value;
                    } else if (r.name_token == H2O_TOKEN_SCHEME) {
                        if (req->scheme.base != NULL)
                            return -1;
                        req->scheme = *r.value;
                    } else {
                        return -1;
                    }
                } else {
                    return -1;
                }
            } else {
                *allow_psuedo = 0;
                h2o_add_header(&req->pool, &req->headers, r.name_token, r.value->base, r.value->len);
            }
        } else {
            if (r.name_not_token->len >= 1 && r.name_not_token->base[0] == ':') {
                /* unknown psuedo header is never accepted */
                return -1;
            }
            *allow_psuedo = 0;
            h2o_add_header_by_str(&req->pool, &req->headers, r.name_not_token->base, r.name_not_token->len, 0, r.value->base, r.value->len);
        }
    }

    return 0;
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
        size_t hufflen = encode_huffman(huffbuf, (const uint8_t*)s, len);
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

static uint8_t *encode_header(h2o_hpack_header_table_t *header_table, uint8_t *dst, const h2o_buf_t *name, const h2o_buf_t *value)
{
    int static_table_name_index, name_is_token = h2o_buf_is_token(name);

    /* try to send as indexed */
    {
        size_t header_table_index = header_table->entry_start_index, n;
        for (n = header_table->num_entries; n != 0; --n) {
            struct st_h2o_hpack_header_table_entry_t *entry = header_table->entries + header_table_index;
            if (name_is_token) {
                if (name != entry->name.buf)
                    goto Next;
            } else {
                if (! h2o_memis(name->base, name->len, entry->name.buf->base, entry->name.buf->len))
                    goto Next;
            }
            /* name matched! */
            if (! h2o_memis(value->base, value->len, entry->value->base, entry->value->len))
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

    if (h2o_buf_is_token(name)) {
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

    { /* add to header table (maximum number of entries in output header table is limited to 32 so that the search (see above) would not take too long) */
        struct st_h2o_hpack_header_table_entry_t *entry = header_table_add(header_table, name->len + value->len + HEADER_TABLE_ENTRY_SIZE_OFFSET, 32);
        if (entry != NULL) {
            if (static_table_name_index != 0) {
                entry->name_is_token = 1;
                entry->name.token = h2o_hpack_static_table[static_table_name_index - 1].name;
            } else {
                entry->name_is_token = 0;
                entry->name.buf = alloc_buf(NULL, name->len);
                entry->name.buf->base[name->len] = '\0';
                memcpy(entry->name.buf->base, name, name->len);
            }
            entry->value = alloc_buf(NULL, value->len);
            entry->value->base[value->len] = '\0';
            memcpy(entry->value->base, value->base, value->len);
        }
    }

    return dst;
}

h2o_buf_t h2o_hpack_flatten_headers(h2o_mempool_t *pool, h2o_hpack_header_table_t *header_table, uint32_t stream_id, size_t max_frame_size, h2o_res_t *res)
{
    const h2o_header_t *header, *header_end;
    size_t max_capacity = 0;
    h2o_buf_t ret;
    uint8_t *dst;

    { /* calculate maximum required memory */
        size_t max_cur_frame_size = STATUS_HEADER_MAX_SIZE; /* for :status: */

        for (header = res->headers.entries, header_end = header + res->headers.size; header != header_end; ++header) {
            size_t max_header_size = header->name->len + header->value.len + 1 + H2O_HTTP2_ENCODE_INT_MAX_LENGTH * 2;
            if (max_header_size > 16383)
                goto Error;
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
    ret.base = h2o_mempool_alloc(pool, max_capacity);
    dst = (uint8_t*)ret.base;

    { /* encode */
        uint8_t *cur_frame;
        
#define EMIT_HEADER(end_headers) h2o_http2_encode_frame_header( \
    cur_frame, \
    dst - cur_frame - H2O_HTTP2_FRAME_HEADER_SIZE, \
    cur_frame == (uint8_t*)ret.base ? H2O_HTTP2_FRAME_TYPE_HEADERS : H2O_HTTP2_FRAME_TYPE_CONTINUATION, \
    end_headers ? H2O_HTTP2_FRAME_FLAG_END_HEADERS : 0, \
    stream_id)

        cur_frame = dst;
        dst += H2O_HTTP2_FRAME_HEADER_SIZE;
        dst = encode_status(dst, res->status);
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

    ret.len = (char*)dst - ret.base;
    assert(ret.len < max_capacity);

    return ret;

Error:
    return h2o_buf_init(NULL, 0);
}

#ifdef PICOTEST_FUNCS

#include "picotest.h"

static void test_request(h2o_buf_t first_req, h2o_buf_t second_req, h2o_buf_t third_req)
{
    h2o_hpack_header_table_t header_table;
    h2o_req_t req;
    h2o_buf_t in, flattened;
    int r, allow_psuedo;

    memset(&header_table, 0, sizeof(header_table));
    header_table.hpack_capacity = 4096;

    memset(&req, 0, sizeof(req));
    h2o_mempool_init(&req.pool);
    allow_psuedo = 1;
    in = first_req;
    r = h2o_hpack_parse_headers(&req, &header_table, &allow_psuedo, (const uint8_t*)in.base, in.len);
    ok(r == 0);
    ok(allow_psuedo == 1);
    ok(req.authority.len == 15);
    ok(memcmp(req.authority.base, H2O_STRLIT("www.example.com")) == 0);
    ok(req.method.len == 3);
    ok(memcmp(req.method.base, H2O_STRLIT("GET")) == 0);
    ok(req.path.len == 1);
    ok(memcmp(req.path.base, H2O_STRLIT("/")) == 0);
    ok(req.scheme.len == 4);
    ok(memcmp(req.scheme.base, H2O_STRLIT("http")) == 0);
    ok(req.headers.size == 0);

    h2o_mempool_clear(&req.pool);

    memset(&req, 0, sizeof(req));
    h2o_mempool_init(&req.pool);
    allow_psuedo = 1;
    in = second_req;
    r = h2o_hpack_parse_headers(&req, &header_table, &allow_psuedo, (const uint8_t*)in.base, in.len);
    ok(r == 0);
    ok(allow_psuedo == 0);
    ok(req.authority.len == 15);
    ok(memcmp(req.authority.base, H2O_STRLIT("www.example.com")) == 0);
    ok(req.method.len == 3);
    ok(memcmp(req.method.base, H2O_STRLIT("GET")) == 0);
    ok(req.path.len == 1);
    ok(memcmp(req.path.base, H2O_STRLIT("/")) == 0);
    ok(req.scheme.len == 4);
    ok(memcmp(req.scheme.base, H2O_STRLIT("http")) == 0);
    flattened = h2o_flatten_headers(&req.pool, &req.headers);
    ok(h2o_lcstris(flattened.base, flattened.len, H2O_STRLIT("cache-control: no-cache\r\n\r\n")));

    h2o_mempool_clear(&req.pool);

    memset(&req, 0, sizeof(req));
    h2o_mempool_init(&req.pool);
    allow_psuedo = 1;
    in = third_req;
    r = h2o_hpack_parse_headers(&req, &header_table, &allow_psuedo, (const uint8_t*)in.base, in.len);
    ok(r == 0);
    ok(allow_psuedo == 0);
    ok(req.authority.len == 15);
    ok(memcmp(req.authority.base, H2O_STRLIT("www.example.com")) == 0);
    ok(req.method.len == 3);
    ok(memcmp(req.method.base, H2O_STRLIT("GET")) == 0);
    ok(req.path.len == 11);
    ok(memcmp(req.path.base, H2O_STRLIT("/index.html")) == 0);
    ok(req.scheme.len == 5);
    ok(memcmp(req.scheme.base, H2O_STRLIT("https")) == 0);
    flattened = h2o_flatten_headers(&req.pool, &req.headers);
    ok(h2o_lcstris(flattened.base, flattened.len, H2O_STRLIT("custom-key: custom-value\r\n\r\n")));

    h2o_hpack_dispose_header_table(&header_table);
    h2o_mempool_clear(&req.pool);
}

static void check_flatten(h2o_mempool_t *pool, h2o_hpack_header_table_t *header_table, h2o_res_t *res, const char *expected, size_t expected_len)
{
    h2o_buf_t flattened = h2o_hpack_flatten_headers(pool, header_table, 1, H2O_HTTP2_SETTINGS_DEFAULT.max_frame_size, res);
    h2o_http2_frame_t frame;

    ok(h2o_http2_decode_frame(&frame, (uint8_t*)flattened.base, flattened.len, &H2O_HTTP2_SETTINGS_DEFAULT) > 0);
    ok(h2o_memis(frame.payload, frame.length, expected, expected_len));
}

void hpack_test()
{
    h2o_mempool_t pool;
    h2o_mempool_init(&pool);

    note("decode_int");
    {
        h2o_buf_t in;
        const uint8_t *p;
        int32_t out;
#define TEST(input, output) \
    in = h2o_buf_init(H2O_STRLIT(input)); \
    p = (const uint8_t*)in.base; \
    out = decode_int(&p, p + in.len, 7); \
    ok(out == output); \
    ok(p == (const uint8_t*)in.base + in.len);
        TEST("\x00", 0);
        TEST("\x03", 3);
        TEST("\x81", 1);
        TEST("\x7f\x00", 127);
        TEST("\x7f\x01", 128);
        TEST("\x7f\x7f", 254);
        TEST("\x7f\x81\x00", 128);
        TEST("\x7f\x80\x01", 255);
        TEST("\x7f\xff\xff\xff\x7f", 0xfffffff + 127);
        /* failures */
        TEST("", -1);
        TEST("\x7f", -1);
        TEST("\x7f\xff", -1);
        TEST("\x7f\xff\xff\xff\xff", -1);
#undef TEST
    }

    note("decode_huffman");
    {
        h2o_buf_t huffcode = { H2O_STRLIT("\xf1\xe3\xc2\xe5\xf2\x3a\x6b\xa0\xab\x90\xf4\xff") };
        h2o_buf_t *decoded = decode_huffman(&pool, (const uint8_t*)huffcode.base, huffcode.len);
        ok(decoded->len == sizeof("www.example.com") -1);
        ok(strcmp(decoded->base, "www.example.com") == 0);
    }
    h2o_mempool_clear(&pool);

    note("decode_header (literal header field with indexing)");
    {
        struct st_h2o_decode_header_result_t result;
        h2o_hpack_header_table_t header_table;
        h2o_buf_t in;
        int r;

        memset(&header_table, 0, sizeof(header_table));
        header_table.hpack_capacity = 4096;
        in = h2o_buf_init(H2O_STRLIT("\x40\x0a\x63\x75\x73\x74\x6f\x6d\x2d\x6b\x65\x79\x0d\x63\x75\x73\x74\x6f\x6d\x2d\x68\x65\x61\x64\x65\x72"));
        const uint8_t *p = (const uint8_t*)in.base;
        r = decode_header(&pool, &result, &header_table, &p, p + in.len);
        ok(r == 0);
        ok(result.name_token == NULL);
        ok(result.name_not_token->len == 10);
        ok(strcmp(result.name_not_token->base, "custom-key") == 0);
        ok(result.value->len == 13);
        ok(strcmp(result.value->base, "custom-header") == 0);
        ok(header_table.hpack_size == 55);
    }
    h2o_mempool_clear(&pool);

    note("decode_header (literal header field without indexing)");
    {
        struct st_h2o_decode_header_result_t result;
        h2o_hpack_header_table_t header_table;
        h2o_buf_t in;
        int r;

        memset(&header_table, 0, sizeof(header_table));
        header_table.hpack_capacity = 4096;
        in = h2o_buf_init(H2O_STRLIT("\x04\x0c\x2f\x73\x61\x6d\x70\x6c\x65\x2f\x70\x61\x74\x68"));
        const uint8_t *p = (const uint8_t*)in.base;
        r = decode_header(&pool, &result, &header_table, &p, p + in.len);
        ok(r == 0);
        ok(result.name_token == H2O_TOKEN_PATH);
        ok(result.value->len == 12);
        ok(strcmp(result.value->base, "/sample/path") == 0);
        ok(header_table.hpack_size == 0);
    }
    h2o_mempool_clear(&pool);

    note("decode_header (literal header field never indexed)");
    {
        struct st_h2o_decode_header_result_t result;
        h2o_hpack_header_table_t header_table;
        h2o_buf_t in;
        int r;

        memset(&header_table, 0, sizeof(header_table));
        header_table.hpack_capacity = 4096;
        in = h2o_buf_init(H2O_STRLIT("\x10\x08\x70\x61\x73\x73\x77\x6f\x72\x64\x06\x73\x65\x63\x72\x65\x74"));
        const uint8_t *p = (const uint8_t*)in.base;
        r = decode_header(&pool, &result, &header_table, &p, p + in.len);
        ok(r == 0);
        ok(result.name_token == NULL);
        ok(result.name_not_token->len == 8);
        ok(strcmp(result.name_not_token->base, "password") == 0);
        ok(result.value->len == 6);
        ok(strcmp(result.value->base, "secret") == 0);
        ok(header_table.hpack_size == 0);
    }
    h2o_mempool_clear(&pool);

    note("decode_header (indexed header field)");
    {
        struct st_h2o_decode_header_result_t result;
        h2o_hpack_header_table_t header_table;
        h2o_buf_t in;
        int r;

        memset(&header_table, 0, sizeof(header_table));
        header_table.hpack_capacity = 4096;
        in = h2o_buf_init(H2O_STRLIT("\x82"));
        const uint8_t *p = (const uint8_t*)in.base;
        r = decode_header(&pool, &result, &header_table, &p, p + in.len);
        ok(r == 0);
        ok(result.name_token == H2O_TOKEN_METHOD);
        ok(result.value->len == 3);
        ok(strcmp(result.value->base, "GET") == 0);
        ok(header_table.hpack_size == 0);
    }
    h2o_mempool_clear(&pool);

    note("request examples without huffman coding");
    test_request(
        h2o_buf_init(H2O_STRLIT("\x82\x86\x84\x41\x0f\x77\x77\x77\x2e\x65\x78\x61\x6d\x70\x6c\x65\x2e\x63\x6f\x6d")),
        h2o_buf_init(H2O_STRLIT("\x82\x86\x84\xbe\x58\x08\x6e\x6f\x2d\x63\x61\x63\x68\x65")),
        h2o_buf_init(H2O_STRLIT("\x82\x87\x85\xbf\x40\x0a\x63\x75\x73\x74\x6f\x6d\x2d\x6b\x65\x79\x0c\x63\x75\x73\x74\x6f\x6d\x2d\x76\x61\x6c\x75\x65")));

    note("request examples with huffman coding");
    test_request(
        h2o_buf_init(H2O_STRLIT("\x82\x86\x84\x41\x8c\xf1\xe3\xc2\xe5\xf2\x3a\x6b\xa0\xab\x90\xf4\xff")),
        h2o_buf_init(H2O_STRLIT("\x82\x86\x84\xbe\x58\x86\xa8\xeb\x10\x64\x9c\xbf")),
        h2o_buf_init(H2O_STRLIT("\x82\x87\x85\xbf\x40\x88\x25\xa8\x49\xe9\x5b\xa9\x7d\x7f\x89\x25\xa8\x49\xe9\x5b\xb8\xe8\xb4\xbf")));

    note("encode_huffman");
    {
        h2o_buf_t huffcode = { H2O_STRLIT("\xf1\xe3\xc2\xe5\xf2\x3a\x6b\xa0\xab\x90\xf4\xff") };
        char buf[sizeof("www.example.com")];
        size_t l = encode_huffman((uint8_t*)buf, (uint8_t*)H2O_STRLIT("www.example.com"));
        ok(l == huffcode.len);
        ok(memcmp(buf, huffcode.base, huffcode.len) == 0);
    }

    note("response examples with huffmann coding");
    {
        h2o_hpack_header_table_t header_table;
        h2o_res_t res;

        memset(&header_table, 0, sizeof(header_table));
        header_table.hpack_capacity = 256;

        memset(&res, 0, sizeof(res));
        res.status = 302;
        res.reason = "Found";
        h2o_add_header(&pool, &res.headers, H2O_TOKEN_CACHE_CONTROL, H2O_STRLIT("private"));
        h2o_add_header(&pool, &res.headers, H2O_TOKEN_DATE, H2O_STRLIT("Mon, 21 Oct 2013 20:13:21 GMT"));
        h2o_add_header(&pool, &res.headers, H2O_TOKEN_LOCATION, H2O_STRLIT("https://www.example.com"));
        check_flatten(&pool, &header_table, &res,
            H2O_STRLIT("\x08\x03\x33\x30\x32\x58\x85\xae\xc3\x77\x1a\x4b\x61\x96\xd0\x7a\xbe\x94\x10\x54\xd4\x44\xa8\x20\x05\x95\x04\x0b\x81\x66\xe0\x82\xa6\x2d\x1b\xff\x6e\x91\x9d\x29\xad\x17\x18\x63\xc7\x8f\x0b\x97\xc8\xe9\xae\x82\xae\x43\xd3"));

        memset(&res, 0, sizeof(res));
        res.status = 307;
        res.reason = "Temporary Redirect";
        h2o_add_header(&pool, &res.headers, H2O_TOKEN_CACHE_CONTROL, H2O_STRLIT("private"));
        h2o_add_header(&pool, &res.headers, H2O_TOKEN_DATE, H2O_STRLIT("Mon, 21 Oct 2013 20:13:21 GMT"));
        h2o_add_header(&pool, &res.headers, H2O_TOKEN_LOCATION, H2O_STRLIT("https://www.example.com"));
        check_flatten(&pool, &header_table, &res,
            H2O_STRLIT("\x08\x03\x33\x30\x37\xc0\xbf\xbe"));
#if 0
        h2o_buf_init(H2O_STRLIT("\x48\x03\x33\x30\x37\xc1\xc0\xbf")),
        h2o_buf_init(H2O_STRLIT("\x88\xc1\x61\x1d\x4d\x6f\x6e\x2c\x20\x32\x31\x20\x4f\x63\x74\x20\x32\x30\x31\x33\x20\x32\x30\x3a\x31\x33\x3a\x32\x32\x20\x47\x4d\x54\xc0\x5a\x04\x67\x7a\x69\x70\x77\x38\x66\x6f\x6f\x3d\x41\x53\x44\x4a\x4b\x48\x51\x4b\x42\x5a\x58\x4f\x51\x57\x45\x4f\x50\x49\x55\x41\x58\x51\x57\x45\x4f\x49\x55\x3b\x20\x6d\x61\x78\x2d\x61\x67\x65\x3d\x33\x36\x30\x30\x3b\x20\x76\x65\x72\x73\x69\x6f\x6e\x3d\x31")));
#endif
    }

    h2o_mempool_clear(&pool);
}
#endif
