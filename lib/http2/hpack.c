/*
 * Copyright (c) 2014-2016 DeNA Co., Ltd., Kazuho Oku, Fastly, Inc.
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
#include "h2o/http2_internal.h"

#define HEADER_TABLE_OFFSET 62
#define HEADER_TABLE_ENTRY_SIZE_OFFSET 32
#define STATUS_HEADER_MAX_SIZE 5
#define CONTENT_LENGTH_HEADER_MAX_SIZE                                                                                             \
    (3 + sizeof(H2O_UINT64_LONGEST_STR) - 1) /* uses Literal Header Field without Indexing (RFC7541 6.2.2) */

struct st_h2o_hpack_static_table_entry_t {
    const h2o_token_t *name;
    const h2o_iovec_t value;
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
           value <= &h2o_hpack_static_table[sizeof(h2o_hpack_static_table) / sizeof(h2o_hpack_static_table[0]) - 1].value;
}

static h2o_iovec_t *alloc_buf(h2o_mem_pool_t *pool, size_t len)
{
    h2o_iovec_t *buf = h2o_mem_alloc_shared(pool, sizeof(h2o_iovec_t) + len + 1, NULL);
    buf->base = (char *)buf + sizeof(h2o_iovec_t);
    buf->len = len;
    return buf;
}

/* validate a header value against https://tools.ietf.org/html/rfc7230#section-3.2 */
static int contains_invalid_field_value_char(const char *s, size_t len)
{
    /* all printable chars + horizontal tab */
    static const char valid_h2_field_value_char[] = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /*    0-31 */
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, /*   32-63 */
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, /*   64-95 */
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, /*  96-127 */
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, /* 128-159 */
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, /* 160-191 */
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, /* 192-223 */
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, /* 224-255 */
    };

    for (; len != 0; ++s, --len) {
        unsigned char ch = (unsigned char)*s;
        if (!valid_h2_field_value_char[ch]) {
            return 1;
        }
    }
    return 0;
}

static const char *err_found_upper_case_in_header_name = "found an upper-case letter in header name";
static const char *soft_err_found_invalid_char_in_header_name = "found an invalid character in header name";
static const char *soft_err_found_invalid_char_in_header_value = "found an invalid character in header value";

/* validate a header name against https://tools.ietf.org/html/rfc7230#section-3.2,
 * in addition to that, we disallow upper case chars as well.
 * This sets @err_desc for all invalid characters, but only returns true
 * for upper case characters, this is because we return a protocol error
 * in that case. */
static const char *validate_header_name(const char *s, size_t len)
{
    const char *ret = NULL;
    /* all printable chars, except upper case and separator characters */
    static const char valid_h2_header_name_char[] = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /*    0-31 */
        0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, /*   32-63 */
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, /*   64-95 */
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 0, /*  96-127 */
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 128-159 */
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 160-191 */
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 192-223 */
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 224-255 */
    };

    for (; len != 0; ++s, --len) {
        unsigned char ch = (unsigned char)*s;
        if (!valid_h2_header_name_char[ch]) {
            if (ch - 'A' < 26U) {
                return err_found_upper_case_in_header_name;
            }
            ret = soft_err_found_invalid_char_in_header_name;
        }
    }
    return ret;
}

static int32_t decode_int(const uint8_t **src, const uint8_t *src_end, size_t prefix_bits)
{
    int32_t value, mult;
    uint8_t prefix_max = (1 << prefix_bits) - 1;

    if (*src >= src_end)
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
        if (*src >= src_end)
            return -1;
        value += (**src & 127) * mult;
        if ((*(*src)++ & 128) == 0)
            return value;
    }
}

static char *huffdecode4(char *dst, uint8_t in, uint8_t *state, int *maybe_eos, uint8_t *seen_char_types)
{
    const nghttp2_huff_decode *entry = huff_decode_table[*state] + in;

    if ((entry->flags & NGHTTP2_HUFF_FAIL) != 0)
        return NULL;
    if ((entry->flags & NGHTTP2_HUFF_SYM) != 0) {
        *dst++ = entry->sym;
        *seen_char_types |= (entry->flags & NGHTTP2_HUFF_INVALID_CHARS);
    }
    *state = entry->state;
    *maybe_eos = (entry->flags & NGHTTP2_HUFF_ACCEPTED) != 0;

    return dst;
}

static h2o_iovec_t *decode_huffman(h2o_mem_pool_t *pool, const uint8_t *src, size_t len, uint8_t *seen_char_types)
{
    const uint8_t *src_end = src + len;
    char *dst;
    uint8_t state = 0;
    int maybe_eos = 1;
    h2o_iovec_t *dst_buf = alloc_buf(pool, len * 2); /* max compression ratio is >= 0.5 */

    dst = dst_buf->base;
    for (; src < src_end; src++) {
        if ((dst = huffdecode4(dst, *src >> 4, &state, &maybe_eos, seen_char_types)) == NULL)
            return NULL;
        if ((dst = huffdecode4(dst, *src & 0xf, &state, &maybe_eos, seen_char_types)) == NULL)
            return NULL;
    }

    if (!maybe_eos)
        return NULL;

    *dst = '\0';
    dst_buf->len = dst - dst_buf->base;
    return dst_buf;
}

static h2o_iovec_t *decode_string(h2o_mem_pool_t *pool, const uint8_t **src, const uint8_t *src_end, int is_header_name,
                                  const char **err_desc)
{
    h2o_iovec_t *ret;
    int is_huffman;
    int32_t len;

    if (*src >= src_end)
        return NULL;

    is_huffman = (**src & 0x80) != 0;
    if ((len = decode_int(src, src_end, 7)) == -1)
        return NULL;

    if (is_huffman) {
        uint8_t hflags = 0;
        if (*src + len > src_end)
            return NULL;
        if ((ret = decode_huffman(pool, *src, len, &hflags)) == NULL)
            return NULL;
        if (is_header_name) {
            if (ret->len <= 0) {
                return NULL;
            }
            /* pseudo-headers are checked later in `decode_header` */
            if (hflags & NGHTTP2_HUFF_INVALID_FOR_HEADER_NAME && ret->base[0] != ':') {
                if (hflags & NGHTTP2_HUFF_UPPER_CASE_CHAR) {
                    *err_desc = err_found_upper_case_in_header_name;
                    return NULL;
                } else {
                    *err_desc = soft_err_found_invalid_char_in_header_name;
                }
            }
        } else {
            if (hflags & NGHTTP2_HUFF_INVALID_FOR_HEADER_VALUE) {
                *err_desc = soft_err_found_invalid_char_in_header_value;
            }
        }
    } else {
        if (*src + len > src_end)
            return NULL;
        if (is_header_name) {
            /* pseudo-headers are checked later in `decode_header` */
            if (**src != (uint8_t)':') {
                *err_desc = validate_header_name((char *)*src, len);
                if (*err_desc == err_found_upper_case_in_header_name) {
                    return NULL;
                }
            }
        } else {
            if (contains_invalid_field_value_char((char *)*src, len)) {
                *err_desc = soft_err_found_invalid_char_in_header_value;
            }
        }
        ret = alloc_buf(pool, len);
        memcpy(ret->base, *src, len);
        ret->base[len] = '\0';
    }
    *src += len;

    return ret;
}

static void header_table_evict_one(h2o_hpack_header_table_t *table)
{
    struct st_h2o_hpack_header_table_entry_t *entry;
    assert(table->num_entries != 0);

    entry = h2o_hpack_header_table_get(table, --table->num_entries);
    table->hpack_size -= entry->name->len + entry->value->len + HEADER_TABLE_ENTRY_SIZE_OFFSET;
    if (!h2o_iovec_is_token(entry->name))
        h2o_mem_release_shared(entry->name);
    if (!value_is_part_of_static_table(entry->value))
        h2o_mem_release_shared(entry->value);
    memset(entry, 0, sizeof(*entry));
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
    table->entry_start_index = (table->entry_start_index + table->entry_capacity - 1) % table->entry_capacity;
    return table->entries + table->entry_start_index;
}

static int decode_header(h2o_mem_pool_t *pool, struct st_h2o_decode_header_result_t *result,
                         h2o_hpack_header_table_t *hpack_header_table, const uint8_t **const src, const uint8_t *src_end,
                         const char **err_desc)
{
    int32_t index = 0;
    int value_is_indexed = 0, do_index = 0;

Redo:
    if (*src >= src_end)
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
    if (index > 0) {
        /* existing name (and value?) */
        if (index < HEADER_TABLE_OFFSET) {
            result->name = (h2o_iovec_t *)h2o_hpack_static_table[index - 1].name;
            if (value_is_indexed) {
                result->value = (h2o_iovec_t *)&h2o_hpack_static_table[index - 1].value;
            }
        } else if (index - HEADER_TABLE_OFFSET < hpack_header_table->num_entries) {
            struct st_h2o_hpack_header_table_entry_t *entry =
                h2o_hpack_header_table_get(hpack_header_table, index - HEADER_TABLE_OFFSET);
            *err_desc = entry->err_desc;
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
        if ((result->name = decode_string(pool, src, src_end, 1, err_desc)) == NULL) {
            if (*err_desc == err_found_upper_case_in_header_name) {
                return H2O_HTTP2_ERROR_PROTOCOL;
            }
            return H2O_HTTP2_ERROR_COMPRESSION;
        }
        if (!*err_desc) {
            /* predefined header names should be interned */
            if ((name_token = h2o_lookup_token(result->name->base, result->name->len)) != NULL) {
                result->name = (h2o_iovec_t *)&name_token->buf;
            }
        }
    }

    /* determine the value (if necessary) */
    if (!value_is_indexed) {
        if ((result->value = decode_string(pool, src, src_end, 0, err_desc)) == NULL) {
            return H2O_HTTP2_ERROR_COMPRESSION;
        }
    }

    /* add the decoded header to the header table if necessary */
    if (do_index) {
        struct st_h2o_hpack_header_table_entry_t *entry =
            header_table_add(hpack_header_table, result->name->len + result->value->len + HEADER_TABLE_ENTRY_SIZE_OFFSET, SIZE_MAX);
        if (entry != NULL) {
            entry->err_desc = *err_desc;
            entry->name = result->name;
            if (!h2o_iovec_is_token(entry->name))
                h2o_mem_addref_shared(entry->name);
            entry->value = result->value;
            if (!value_is_part_of_static_table(entry->value))
                h2o_mem_addref_shared(entry->value);
        }
    }

    return *err_desc ? H2O_HTTP2_ERROR_INVALID_HEADER_CHAR : 0;
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

static uint8_t *encode_content_length(uint8_t *dst, size_t value)
{
    char buf[32], *p = buf + sizeof(buf);
    size_t l;

    do {
        *--p = '0' + value % 10;
    } while ((value /= 10) != 0);
    l = buf + sizeof(buf) - p;
    *dst++ = 0x0f;
    *dst++ = 0x0d;
    *dst++ = (uint8_t)l;
    memcpy(dst, p, l);
    dst += l;

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
                            int *pseudo_header_exists_map, size_t *content_length, h2o_cache_digests_t **digests,
                            const char **err_desc)
{
    const uint8_t *src_end = src + len;

    *content_length = SIZE_MAX;

    while (src != src_end) {
        struct st_h2o_decode_header_result_t r;
        const char *decode_err = NULL;
        int ret = decode_header(&req->pool, &r, header_table, &src, src_end, &decode_err);
        if (ret != 0) {
            if (ret == H2O_HTTP2_ERROR_INVALID_HEADER_CHAR) {
                /* this is a soft error, we continue parsing, but register only the first error */
                if (*err_desc == NULL) {
                    *err_desc = decode_err;
                }
            } else {
                *err_desc = decode_err;
                return ret;
            }
        }
        if (r.name->base[0] == ':') {
            if (pseudo_header_exists_map != NULL) {
                /* FIXME validate the chars in the value (e.g. reject SP in path) */
                if (r.name == &H2O_TOKEN_AUTHORITY->buf) {
                    /* FIXME should we perform this check? */
                    if (req->input.authority.base != NULL)
                        return H2O_HTTP2_ERROR_PROTOCOL;
                    req->input.authority = *r.value;
                    *pseudo_header_exists_map |= H2O_HPACK_PARSE_HEADERS_AUTHORITY_EXISTS;
                } else if (r.name == &H2O_TOKEN_METHOD->buf) {
                    if (req->input.method.base != NULL)
                        return H2O_HTTP2_ERROR_PROTOCOL;
                    req->input.method = *r.value;
                    *pseudo_header_exists_map |= H2O_HPACK_PARSE_HEADERS_METHOD_EXISTS;
                } else if (r.name == &H2O_TOKEN_PATH->buf) {
                    if (req->input.path.base != NULL)
                        return H2O_HTTP2_ERROR_PROTOCOL;
                    req->input.path = *r.value;
                    *pseudo_header_exists_map |= H2O_HPACK_PARSE_HEADERS_PATH_EXISTS;
                } else if (r.name == &H2O_TOKEN_SCHEME->buf) {
                    if (req->input.scheme != NULL)
                        return H2O_HTTP2_ERROR_PROTOCOL;
                    if (h2o_memis(r.value->base, r.value->len, H2O_STRLIT("https"))) {
                        req->input.scheme = &H2O_URL_SCHEME_HTTPS;
                    } else {
                        /* draft-16 8.1.2.3 suggests quote: ":scheme is not restricted to http and https schemed URIs" */
                        req->input.scheme = &H2O_URL_SCHEME_HTTP;
                    }
                    *pseudo_header_exists_map |= H2O_HPACK_PARSE_HEADERS_SCHEME_EXISTS;
                } else {
                    return H2O_HTTP2_ERROR_PROTOCOL;
                }
            } else {
                return H2O_HTTP2_ERROR_PROTOCOL;
            }
        } else {
            pseudo_header_exists_map = NULL;
            if (h2o_iovec_is_token(r.name)) {
                h2o_token_t *token = H2O_STRUCT_FROM_MEMBER(h2o_token_t, buf, r.name);
                if (token == H2O_TOKEN_CONTENT_LENGTH) {
                    if ((*content_length = h2o_strtosize(r.value->base, r.value->len)) == SIZE_MAX)
                        return H2O_HTTP2_ERROR_PROTOCOL;
                } else {
                    /* reject headers as defined in draft-16 8.1.2.2 */
                    if (token->http2_should_reject) {
                        if (token == H2O_TOKEN_HOST) {
                            /* just skip (and :authority is used) */
                            goto Next;
                        } else if (token == H2O_TOKEN_TE && h2o_lcstris(r.value->base, r.value->len, H2O_STRLIT("trailers"))) {
                            /* do not reject */
                        } else {
                            return H2O_HTTP2_ERROR_PROTOCOL;
                        }
                    }
                    if (token == H2O_TOKEN_CACHE_DIGEST && digests != NULL) {
                        /* TODO cache the decoded result in HPACK, as well as delay the decoding of the digest until being used */
                        h2o_cache_digests_load_header(digests, r.value->base, r.value->len);
                    }
                    h2o_add_header(&req->pool, &req->headers, token, NULL, r.value->base, r.value->len);
                }
            } else {
                h2o_add_header_by_str(&req->pool, &req->headers, r.name->base, r.name->len, 0, NULL, r.value->base, r.value->len);
            }
        }
    Next:;
    }

    if (*err_desc) {
        return H2O_HTTP2_ERROR_INVALID_HEADER_CHAR;
    }
    return 0;
}

static inline int encode_int_is_onebyte(uint32_t value, size_t prefix_bits)
{
    return value < (1 << prefix_bits) - 1;
}

static uint8_t *encode_int(uint8_t *dst, uint32_t value, size_t prefix_bits)
{
    if (encode_int_is_onebyte(value, prefix_bits)) {
        *dst++ |= value;
    } else {
        /* see also: MAX_ENCODE_INT_LENGTH */
        value -= (1 << prefix_bits) - 1;
        if (value > 0x0fffffff)
            h2o_fatal("value out of range");
        *dst++ |= (1 << prefix_bits) - 1;
        for (; value >= 128; value >>= 7) {
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
                return 0;
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

static size_t encode_as_is(uint8_t *dst, const char *s, size_t len)
{
    uint8_t *start = dst;
    *dst = '\0';
    dst = encode_int(dst, (uint32_t)len, 7);
    memcpy(dst, s, len);
    dst += len;
    return dst - start;
}

size_t h2o_hpack_encode_string(uint8_t *dst, const char *s, size_t len)
{
    if (H2O_LIKELY(len != 0)) {
        /* try to encode using huffman */
        size_t hufflen = encode_huffman(dst + 1, (const uint8_t *)s, len);
        if (H2O_LIKELY(hufflen != 0)) {
            size_t head_len;
            if (H2O_LIKELY(encode_int_is_onebyte((uint32_t)hufflen, 7))) {
                dst[0] = (uint8_t)(0x80 | hufflen);
                head_len = 1;
            } else {
                uint8_t head[8];
                head[0] = '\x80';
                head_len = encode_int(head, (uint32_t)hufflen, 7) - head;
                memmove(dst + head_len, dst + 1, hufflen);
                memcpy(dst, head, head_len);
            }
            return head_len + hufflen;
        }
    }
    return encode_as_is(dst, s, len);
}

static uint8_t *encode_header(h2o_hpack_header_table_t *header_table, uint8_t *dst, const h2o_iovec_t *name,
                              const h2o_iovec_t *value)
{
    int name_index = 0, dont_compress = 0, name_is_token = h2o_iovec_is_token(name);

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
                if (name_index == 0)
                    name_index = (int)(header_table->num_entries - n + HEADER_TABLE_OFFSET);
            }
            /* name matched! */
            if (!h2o_memis(value->base, value->len, entry->value->base, entry->value->len))
                goto Next;
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

    if (name_is_token) {
        const h2o_token_t *name_token = H2O_STRUCT_FROM_MEMBER(h2o_token_t, buf, name);
        name_index = name_token->http2_static_table_name_index;
        dont_compress = (name_token->dont_compress == 1 && value->len < 20) ? 1 : 0;
    }

    if (name_index != 0) {
        /* literal header field with indexing (indexed name). */
        if (dont_compress == 1) {
            /* mark the field as 'never indexed' */
            *dst = 0x10;
            dst = encode_int(dst, name_index, 4);
        } else {
            *dst = 0x40;
            dst = encode_int(dst, name_index, 6);
        }
    } else {
        /* literal header field with indexing (new name) */
        *dst++ = 0x40;
        dst += h2o_hpack_encode_string(dst, name->base, name->len);
    }
    if (dont_compress == 1) {
        /* bypass huffman encoding */
        dst += encode_as_is(dst, value->base, value->len);
    } else {
        /* add to header table (maximum number of entries in output header table is limited to 32 so that the search (see above) would
           not take too long) */
        dst += h2o_hpack_encode_string(dst, value->base, value->len);
        struct st_h2o_hpack_header_table_entry_t *entry =
            header_table_add(header_table, name->len + value->len + HEADER_TABLE_ENTRY_SIZE_OFFSET, 32);
        if (entry != NULL) {
            if (name_is_token) {
                entry->name = (h2o_iovec_t *)name;
            } else {
                entry->name = alloc_buf(NULL, name->len);
                entry->name->base[name->len] = '\0';
                memcpy(entry->name->base, name->base, name->len);
            }
            entry->value = alloc_buf(NULL, value->len);
            entry->value->base[value->len] = '\0';
            memcpy(entry->value->base, value->base, value->len);
        }
    }

    return dst;
}

static uint8_t *encode_method(h2o_hpack_header_table_t *header_table, uint8_t *dst, h2o_iovec_t value)
{
    if (h2o_memis(value.base, value.len, H2O_STRLIT("GET"))) {
        *dst++ = 0x82;
        return dst;
    }
    if (h2o_memis(value.base, value.len, H2O_STRLIT("POST"))) {
        *dst++ = 0x83;
        return dst;
    }
    return encode_header(header_table, dst, &H2O_TOKEN_METHOD->buf, &value);
}

static uint8_t *encode_scheme(h2o_hpack_header_table_t *header_table, uint8_t *dst, const h2o_url_scheme_t *scheme)
{
    if (scheme == &H2O_URL_SCHEME_HTTPS) {
        *dst++ = 0x87;
        return dst;
    }
    if (scheme == &H2O_URL_SCHEME_HTTP) {
        *dst++ = 0x86;
        return dst;
    }
    return encode_header(header_table, dst, &H2O_TOKEN_SCHEME->buf, &scheme->name);
}

static uint8_t *encode_path(h2o_hpack_header_table_t *header_table, uint8_t *dst, h2o_iovec_t value)
{
    if (h2o_memis(value.base, value.len, H2O_STRLIT("/"))) {
        *dst++ = 0x84;
        return dst;
    }
    if (h2o_memis(value.base, value.len, H2O_STRLIT("/index.html"))) {
        *dst++ = 0x85;
        return dst;
    }
    return encode_header(header_table, dst, &H2O_TOKEN_PATH->buf, &value);
}

static uint8_t *encode_literal_header_without_indexing(uint8_t *dst, const h2o_iovec_t *name, const h2o_iovec_t *value)
{
    /* literal header field without indexing / never indexed */
    *dst++ = 0;
    dst += h2o_hpack_encode_string(dst, name->base, name->len);
    dst += h2o_hpack_encode_string(dst, value->base, value->len);
    return dst;
}

static size_t calc_capacity(size_t name_len, size_t value_len)
{
    return name_len + value_len + 1 + H2O_HTTP2_ENCODE_INT_MAX_LENGTH * 2;
}

static size_t calc_headers_capacity(const h2o_header_t *headers, size_t num_headers)
{
    const h2o_header_t *header;
    size_t capacity = 0;
    for (header = headers; num_headers != 0; ++header, --num_headers)
        capacity += calc_capacity(header->name->len, header->value.len);
    return capacity;
}

static void fixup_frame_headers(h2o_buffer_t **buf, size_t start_at, uint8_t type, uint32_t stream_id, size_t max_frame_size)
{
    /* try to fit all data into single frame, using the preallocated space for the frame header */
    size_t payload_size = (*buf)->size - start_at - H2O_HTTP2_FRAME_HEADER_SIZE;
    if (payload_size <= max_frame_size) {
        h2o_http2_encode_frame_header((uint8_t *)((*buf)->bytes + start_at), payload_size, type, H2O_HTTP2_FRAME_FLAG_END_HEADERS,
                                      stream_id);
        return;
    }

    /* need to setup continuation frames */
    size_t off;
    h2o_http2_encode_frame_header((uint8_t *)((*buf)->bytes + start_at), max_frame_size, type, 0, stream_id);
    off = start_at + H2O_HTTP2_FRAME_HEADER_SIZE + max_frame_size;
    while (1) {
        size_t left = (*buf)->size - off;
        h2o_buffer_reserve(buf, H2O_HTTP2_FRAME_HEADER_SIZE);
        memmove((*buf)->bytes + off + H2O_HTTP2_FRAME_HEADER_SIZE, (*buf)->bytes + off, left);
        (*buf)->size += H2O_HTTP2_FRAME_HEADER_SIZE;
        if (left <= max_frame_size) {
            h2o_http2_encode_frame_header((uint8_t *)((*buf)->bytes + off), left, H2O_HTTP2_FRAME_TYPE_CONTINUATION,
                                          H2O_HTTP2_FRAME_FLAG_END_HEADERS, stream_id);
            break;
        } else {
            h2o_http2_encode_frame_header((uint8_t *)((*buf)->bytes + off), max_frame_size, H2O_HTTP2_FRAME_TYPE_CONTINUATION, 0,
                                          stream_id);
            off += H2O_HTTP2_FRAME_HEADER_SIZE + max_frame_size;
        }
    }
}

void h2o_hpack_flatten_request(h2o_buffer_t **buf, h2o_hpack_header_table_t *header_table, uint32_t stream_id,
                               size_t max_frame_size, h2o_req_t *req, uint32_t parent_stream_id)
{
    size_t capacity = calc_headers_capacity(req->headers.entries, req->headers.size);
    capacity += H2O_HTTP2_FRAME_HEADER_SIZE /* first frame header */
                + 4;                        /* promised stream id */
    capacity += calc_capacity(H2O_TOKEN_METHOD->buf.len, req->input.method.len);
    capacity += calc_capacity(H2O_TOKEN_SCHEME->buf.len, req->input.scheme->name.len);
    capacity += calc_capacity(H2O_TOKEN_AUTHORITY->buf.len, req->input.authority.len);
    capacity += calc_capacity(H2O_TOKEN_PATH->buf.len, req->input.path.len);

    size_t start_at = (*buf)->size;
    uint8_t *dst = (void *)(h2o_buffer_reserve(buf, capacity).base + H2O_HTTP2_FRAME_HEADER_SIZE);

    /* encode */
    dst = h2o_http2_encode32u(dst, stream_id);
    dst = encode_method(header_table, dst, req->input.method);
    dst = encode_scheme(header_table, dst, req->input.scheme);
    dst = encode_header(header_table, dst, &H2O_TOKEN_AUTHORITY->buf, &req->input.authority);
    dst = encode_path(header_table, dst, req->input.path);
    size_t i;
    for (i = 0; i != req->headers.size; ++i) {
        const h2o_header_t *header = req->headers.entries + i;
        if (header->name == &H2O_TOKEN_ACCEPT_ENCODING->buf &&
            h2o_memis(header->value.base, header->value.len, H2O_STRLIT("gzip, deflate"))) {
            *dst++ = 0x90;
        } else {
            dst = encode_header(header_table, dst, header->name, &header->value);
        }
    }
    (*buf)->size = (char *)dst - (*buf)->bytes;

    /* setup the frame headers */
    fixup_frame_headers(buf, start_at, H2O_HTTP2_FRAME_TYPE_PUSH_PROMISE, parent_stream_id, max_frame_size);
}

void h2o_hpack_flatten_response(h2o_buffer_t **buf, h2o_hpack_header_table_t *header_table, uint32_t stream_id,
                                size_t max_frame_size, h2o_res_t *res, h2o_timestamp_t *ts, const h2o_iovec_t *server_name,
                                size_t content_length)
{
    size_t capacity = calc_headers_capacity(res->headers.entries, res->headers.size);
    capacity += H2O_HTTP2_FRAME_HEADER_SIZE; /* for the first header */
    capacity += STATUS_HEADER_MAX_SIZE;      /* for :status: */
#ifndef H2O_UNITTEST
    capacity += 2 + H2O_TIMESTR_RFC1123_LEN; /* for Date: */
    if (server_name->len) {
        capacity += 5 + server_name->len; /* for Server: */
    }
#endif
    if (content_length != SIZE_MAX)
        capacity += CONTENT_LENGTH_HEADER_MAX_SIZE; /* for content-length: UINT64_MAX (with huffman compression applied) */

    size_t start_at = (*buf)->size;
    uint8_t *dst = (void *)(h2o_buffer_reserve(buf, capacity).base + H2O_HTTP2_FRAME_HEADER_SIZE); /* skip frame header */

    /* encode */
    dst = encode_status(dst, res->status);
#ifndef H2O_UNITTEST
    /* TODO keep some kind of reference to the indexed headers of Server and Date, and reuse them */
    if (server_name->len) {
        dst = encode_header(header_table, dst, &H2O_TOKEN_SERVER->buf, server_name);
    }
    h2o_iovec_t date_value = {ts->str->rfc1123, H2O_TIMESTR_RFC1123_LEN};
    dst = encode_header(header_table, dst, &H2O_TOKEN_DATE->buf, &date_value);
#endif
    size_t i;
    for (i = 0; i != res->headers.size; ++i)
        dst = encode_header(header_table, dst, res->headers.entries[i].name, &res->headers.entries[i].value);
    if (content_length != SIZE_MAX)
        dst = encode_content_length(dst, content_length);
    (*buf)->size = (char *)dst - (*buf)->bytes;

    /* setup the frame headers */
    fixup_frame_headers(buf, start_at, H2O_HTTP2_FRAME_TYPE_HEADERS, stream_id, max_frame_size);
}
