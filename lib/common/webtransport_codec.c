/*
 * Copyright (c) 2026 Fastly, Inc.
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
#include <assert.h>
#include <string.h>
#include "picotls.h"
#include "h2o/string_.h"
#include "h2o/webtransport.h"

static size_t quicint_size(uint64_t v)
{
    return v <= 0x3f ? 1 : v <= 0x3fff ? 2 : v <= 0x3fffffff ? 4 : 8;
}

static int is_valid_session_id(uint64_t id)
{
    return id <= H2O_WEBTRANSPORT_H3_MAX_SESSION_ID && (id & 3) == 0;
}

uint8_t *h2o_webtransport_encode_stream_prefix(uint8_t *dst, uint64_t type, uint64_t session_id)
{
    assert(type == H2O_WEBTRANSPORT_H3_STREAM_TYPE_UNI || type == H2O_WEBTRANSPORT_H3_SIGNAL_BIDI);
    assert(is_valid_session_id(session_id));

    dst = ptls_encode_quicint(dst, type);
    dst = ptls_encode_quicint(dst, session_id);
    return dst;
}

int h2o_webtransport_decode_stream_prefix(const uint8_t **src, const uint8_t *end, uint64_t type, uint64_t *session_id)
{
    const uint8_t *p = *src;
    uint64_t v;

    /* type; non-minimal encodings are accepted, as HTTP/3 does not require the shortest form for stream types or frame types */
    if ((v = ptls_decode_quicint(&p, end)) == UINT64_MAX)
        return H2O_WEBTRANSPORT_DECODE_INCOMPLETE;
    if (v != type)
        return H2O_WEBTRANSPORT_DECODE_INVALID;
    /* session ID */
    if ((v = ptls_decode_quicint(&p, end)) == UINT64_MAX)
        return H2O_WEBTRANSPORT_DECODE_INCOMPLETE;
    if (!is_valid_session_id(v))
        return H2O_WEBTRANSPORT_DECODE_INVALID;

    *session_id = v;
    *src = p;
    return 0;
}

uint8_t *h2o_webtransport_encode_datagram_prefix(uint8_t *dst, uint64_t quarter_stream_id)
{
    assert(quarter_stream_id <= H2O_WEBTRANSPORT_H3_MAX_QUARTER_STREAM_ID);
    return ptls_encode_quicint(dst, quarter_stream_id);
}

int h2o_webtransport_decode_datagram(h2o_iovec_t datagram, uint64_t *quarter_stream_id, h2o_iovec_t *payload)
{
    const uint8_t *src = (const uint8_t *)datagram.base, *end = src + datagram.len;
    uint64_t qsid;

    if ((qsid = ptls_decode_quicint(&src, end)) == UINT64_MAX || qsid > H2O_WEBTRANSPORT_H3_MAX_QUARTER_STREAM_ID)
        return H2O_WEBTRANSPORT_DECODE_INVALID;

    *quarter_stream_id = qsid;
    *payload = h2o_iovec_init(src, end - src);
    return 0;
}

uint64_t h2o_webtransport_h3_error_from_application(uint32_t app_error)
{
    /* every block of 31 codes contains one reserved codepoint (0x1f * N + 0x21), leaving 30 for applications */
    return H2O_WEBTRANSPORT_H3_ERROR_APPLICATION_FIRST + app_error + app_error / 30;
}

int h2o_webtransport_h3_error_to_application(uint64_t h3_error, uint32_t *app_error)
{
    if (!(H2O_WEBTRANSPORT_H3_ERROR_APPLICATION_FIRST <= h3_error && h3_error <= H2O_WEBTRANSPORT_H3_ERROR_APPLICATION_LAST))
        return -1;
    if ((h3_error - 0x21) % 0x1f == 0)
        return -1;

    uint64_t off = h3_error - H2O_WEBTRANSPORT_H3_ERROR_APPLICATION_FIRST;
    *app_error = (uint32_t)(off - off / 31);
    return 0;
}

int h2o_webtransport_is_valid_utf8(const uint8_t *src, size_t len)
{
    if (len == 0)
        return 1;

    const uint8_t *end = src + len;

    while (src != end) {
        uint8_t first = *src++;
        if (first < 0x80)
            continue;
        size_t num_cont;
        uint32_t value, min_value;
        if (0xc2 <= first && first <= 0xdf) {
            num_cont = 1;
            value = first & 0x1f;
            min_value = 0x80;
        } else if (0xe0 <= first && first <= 0xef) {
            num_cont = 2;
            value = first & 0x0f;
            min_value = 0x800;
        } else if (0xf0 <= first && first <= 0xf4) {
            num_cont = 3;
            value = first & 0x07;
            min_value = 0x10000;
        } else {
            return 0;
        }
        if ((size_t)(end - src) < num_cont)
            return 0;
        for (; num_cont != 0; --num_cont) {
            if ((*src & 0xc0) != 0x80)
                return 0;
            value = (value << 6) | (*src++ & 0x3f);
        }
        if (value < min_value || value > 0x10ffff || (0xd800 <= value && value <= 0xdfff))
            return 0;
    }

    return 1;
}

uint8_t *h2o_webtransport_encode_capsule_header(uint8_t *dst, uint64_t type, uint64_t length)
{
    dst = ptls_encode_quicint(dst, type);
    dst = ptls_encode_quicint(dst, length);
    return dst;
}

void h2o_webtransport_encode_varint_capsule(h2o_buffer_t **buf, uint64_t type, const uint64_t *fields, size_t num_fields)
{
    uint8_t *dst = (uint8_t *)h2o_buffer_reserve(buf, H2O_WEBTRANSPORT_MAX_CAPSULE_HEADER_SIZE + num_fields * 8).base;
    size_t length = 0;

    for (size_t i = 0; i != num_fields; ++i)
        length += quicint_size(fields[i]);
    dst = h2o_webtransport_encode_capsule_header(dst, type, length);
    for (size_t i = 0; i != num_fields; ++i)
        dst = ptls_encode_quicint(dst, fields[i]);

    (*buf)->size = (char *)dst - (*buf)->bytes;
}

int h2o_webtransport_encode_close_session(h2o_buffer_t **buf, uint32_t app_error, h2o_iovec_t reason)
{
    if (reason.len > H2O_WEBTRANSPORT_MAX_CLOSE_REASON_SIZE ||
        !h2o_webtransport_is_valid_utf8((const uint8_t *)reason.base, reason.len))
        return -1;

    uint8_t *dst = (uint8_t *)h2o_buffer_reserve(buf, H2O_WEBTRANSPORT_MAX_CAPSULE_HEADER_SIZE + 4 + reason.len).base;
    dst = h2o_webtransport_encode_capsule_header(dst, H2O_WEBTRANSPORT_CAPSULE_CLOSE_SESSION, 4 + reason.len);
    *dst++ = (uint8_t)(app_error >> 24);
    *dst++ = (uint8_t)(app_error >> 16);
    *dst++ = (uint8_t)(app_error >> 8);
    *dst++ = (uint8_t)app_error;
    h2o_memcpy(dst, reason.base, reason.len);
    dst += reason.len;

    (*buf)->size = (char *)dst - (*buf)->bytes;
    return 0;
}

void h2o_webtransport_encode_drain_session(h2o_buffer_t **buf)
{
    h2o_webtransport_encode_varint_capsule(buf, H2O_WEBTRANSPORT_CAPSULE_DRAIN_SESSION, NULL, 0);
}

int h2o_webtransport_decode_capsule_header(const uint8_t **src, const uint8_t *end, uint64_t *type, uint64_t *length)
{
    const uint8_t *p = *src;

    if ((*type = ptls_decode_quicint(&p, end)) == UINT64_MAX || (*length = ptls_decode_quicint(&p, end)) == UINT64_MAX)
        return H2O_WEBTRANSPORT_DECODE_INCOMPLETE;

    *src = p;
    return 0;
}

int h2o_webtransport_decode_varint_capsule(h2o_iovec_t payload, uint64_t *fields, size_t num_fields)
{
    const uint8_t *src = (const uint8_t *)payload.base, *end = src + payload.len;

    for (size_t i = 0; i != num_fields; ++i)
        if ((fields[i] = ptls_decode_quicint(&src, end)) == UINT64_MAX)
            return H2O_WEBTRANSPORT_DECODE_INVALID;
    if (src != end)
        return H2O_WEBTRANSPORT_DECODE_INVALID;

    return 0;
}

int h2o_webtransport_decode_close_session(h2o_iovec_t payload, uint32_t *app_error, h2o_iovec_t *reason)
{
    const uint8_t *src = (const uint8_t *)payload.base;

    if (payload.len < 4 || payload.len - 4 > H2O_WEBTRANSPORT_MAX_CLOSE_REASON_SIZE ||
        !h2o_webtransport_is_valid_utf8(src + 4, payload.len - 4))
        return H2O_WEBTRANSPORT_DECODE_INVALID;

    *app_error = (uint32_t)src[0] << 24 | (uint32_t)src[1] << 16 | (uint32_t)src[2] << 8 | src[3];
    *reason = h2o_iovec_init(src + 4, payload.len - 4);
    return 0;
}

/* The following functions implement the subset of RFC 9651 section 4.2 that is necessary for parsing WT-Available-Protocols and
 * WebTransport-Init. Each function advances `*src` only when successful. */

static int sf_is_digit(uint8_t c)
{
    return '0' <= c && c <= '9';
}

static int sf_is_lcalpha(uint8_t c)
{
    return 'a' <= c && c <= 'z';
}

static int sf_is_alpha(uint8_t c)
{
    return sf_is_lcalpha(c) || ('A' <= c && c <= 'Z');
}

static int sf_is_tchar(uint8_t c)
{
    return sf_is_alpha(c) || sf_is_digit(c) || (c != '\0' && strchr("!#$%&'*+-.^_`|~", c) != NULL);
}

static void sf_skip_sp(const uint8_t **src, const uint8_t *end)
{
    while (*src != end && **src == ' ')
        ++*src;
}

static void sf_skip_ows(const uint8_t **src, const uint8_t *end)
{
    while (*src != end && (**src == ' ' || **src == '\t'))
        ++*src;
}

/**
 * upon success, `*raw` refers to the (still escaped) octets between the quotes
 */
static int sf_parse_string(const uint8_t **src, const uint8_t *end, h2o_iovec_t *raw)
{
    const uint8_t *p = *src;

    if (p == end || *p++ != '"')
        return 0;
    const uint8_t *start = p;
    for (; p != end; ++p) {
        if (*p == '\\') {
            if (++p == end || (*p != '"' && *p != '\\'))
                return 0;
        } else if (*p == '"') {
            *raw = h2o_iovec_init(start, p - start);
            *src = p + 1;
            return 1;
        } else if (*p < 0x20 || *p > 0x7e) {
            return 0;
        }
    }
    return 0;
}

/**
 * Integer or Decimal (section 4.2.4). When `integer` is non-NULL, only Integers are accepted and the value is stored there.
 */
static int sf_parse_number(const uint8_t **src, const uint8_t *end, int64_t *integer)
{
    const uint8_t *p = *src;
    int negative = 0, is_decimal = 0;
    size_t num_int_digits = 0, num_frac_digits = 0;
    int64_t value = 0;

    if (p != end && *p == '-') {
        negative = 1;
        ++p;
    }
    if (p == end || !sf_is_digit(*p))
        return 0;
    for (; p != end; ++p) {
        if (sf_is_digit(*p)) {
            if (is_decimal) {
                ++num_frac_digits;
            } else {
                ++num_int_digits;
                value = value * 10 + (*p - '0');
            }
        } else if (*p == '.' && !is_decimal && integer == NULL) {
            if (num_int_digits > 12)
                return 0;
            is_decimal = 1;
        } else {
            break;
        }
        if (is_decimal ? num_int_digits + num_frac_digits > 15 || num_frac_digits > 3 : num_int_digits > 15)
            return 0;
    }
    if (is_decimal && num_frac_digits == 0)
        return 0;

    if (integer != NULL)
        *integer = negative ? -value : value;
    *src = p;
    return 1;
}

/**
 * Display String (section 4.2.10); percent-encoded octets must use lowercase hex digits, and the decoded octets must be UTF-8
 */
static int sf_parse_display_string(const uint8_t **src, const uint8_t *end)
{
    const uint8_t *p = *src;
    uint8_t seq[4];
    size_t seq_len = 0, seq_expected = 0;

    if (end - p < 2 || p[0] != '%' || p[1] != '"')
        return 0;
    for (p += 2; p != end; ++p) {
        uint8_t octet;
        if (*p == '"') {
            if (seq_len != 0)
                return 0;
            *src = p + 1;
            return 1;
        } else if (*p < 0x20 || *p > 0x7e) {
            return 0;
        } else if (*p == '%') {
            if (end - p < 3)
                return 0;
            octet = 0;
            for (size_t i = 1; i <= 2; ++i) {
                uint8_t c = p[i];
                if (sf_is_digit(c)) {
                    octet = octet << 4 | (c - '0');
                } else if ('a' <= c && c <= 'f') {
                    octet = octet << 4 | (c - 'a' + 10);
                } else {
                    return 0;
                }
            }
            p += 2;
        } else {
            octet = *p;
        }
        /* validate one scalar value at a time, so that the entire string need not be buffered */
        if (seq_len == 0)
            seq_expected = octet < 0x80 ? 1 : octet < 0xe0 ? 2 : octet < 0xf0 ? 3 : 4;
        seq[seq_len++] = octet;
        if (seq_len == seq_expected) {
            if (!h2o_webtransport_is_valid_utf8(seq, seq_len))
                return 0;
            seq_len = 0;
        }
    }
    return 0;
}

/**
 * upon success, `*integer` is set if the item is an Integer, and `*is_integer` indicates so; both can be NULL
 */
static int sf_parse_bare_item(const uint8_t **src, const uint8_t *end, int *is_integer, int64_t *integer)
{
    const uint8_t *p = *src;
    h2o_iovec_t raw;

    if (is_integer != NULL)
        *is_integer = 0;
    if (p == end)
        return 0;

    switch (*p) {
    case '"':
        return sf_parse_string(src, end, &raw);
    case '?':
        if (end - p < 2 || (p[1] != '0' && p[1] != '1'))
            return 0;
        *src = p + 2;
        return 1;
    case '@': {
        int64_t unused;
        ++p;
        if (!sf_parse_number(&p, end, &unused))
            return 0;
        *src = p;
        return 1;
    }
    case '%':
        return sf_parse_display_string(src, end);
    case ':':
        for (++p; p != end && *p != ':'; ++p)
            if (!(sf_is_alpha(*p) || sf_is_digit(*p) || *p == '+' || *p == '/' || *p == '='))
                return 0;
        if (p == end)
            return 0;
        *src = p + 1;
        return 1;
    default:
        if (*p == '-' || sf_is_digit(*p)) {
            /* try Integer first, then Decimal */
            int64_t value;
            const uint8_t *q = p;
            if (sf_parse_number(&q, end, &value) && (q == end || *q != '.')) {
                if (is_integer != NULL) {
                    *is_integer = 1;
                    *integer = value;
                }
                *src = q;
                return 1;
            }
            return sf_parse_number(src, end, NULL);
        }
        if (sf_is_alpha(*p) || *p == '*') {
            for (++p; p != end && (sf_is_tchar(*p) || *p == ':' || *p == '/'); ++p)
                ;
            *src = p;
            return 1;
        }
        return 0;
    }
}

static int sf_parse_key(const uint8_t **src, const uint8_t *end, h2o_iovec_t *key)
{
    const uint8_t *p = *src;

    if (p == end || !(sf_is_lcalpha(*p) || *p == '*'))
        return 0;
    for (++p; p != end && (sf_is_lcalpha(*p) || sf_is_digit(*p) || *p == '_' || *p == '-' || *p == '.' || *p == '*'); ++p)
        ;

    *key = h2o_iovec_init(*src, p - *src);
    *src = p;
    return 1;
}

static int sf_parse_parameters(const uint8_t **src, const uint8_t *end)
{
    const uint8_t *p = *src;
    h2o_iovec_t key;

    while (p != end && *p == ';') {
        ++p;
        sf_skip_sp(&p, end);
        if (!sf_parse_key(&p, end, &key))
            return 0;
        if (p != end && *p == '=') {
            ++p;
            if (!sf_parse_bare_item(&p, end, NULL, NULL))
                return 0;
        }
    }

    *src = p;
    return 1;
}

static int sf_parse_inner_list(const uint8_t **src, const uint8_t *end)
{
    const uint8_t *p = *src;

    if (p == end || *p++ != '(')
        return 0;
    while (1) {
        sf_skip_sp(&p, end);
        if (p == end)
            return 0;
        if (*p == ')') {
            ++p;
            break;
        }
        if (!sf_parse_bare_item(&p, end, NULL, NULL) || !sf_parse_parameters(&p, end))
            return 0;
        if (p == end || (*p != ' ' && *p != ')'))
            return 0;
    }
    if (!sf_parse_parameters(&p, end))
        return 0;

    *src = p;
    return 1;
}

/**
 * Consumes the separator between members of a List or a Dictionary. Returns 1 if another member follows, 0 at the end of the
 * line, or -1 if the input is malformed.
 */
static int sf_parse_member_separator(const uint8_t **src, const uint8_t *end)
{
    sf_skip_ows(src, end);
    if (*src == end)
        return 0;
    if (**src != ',')
        return -1;
    ++*src;
    sf_skip_ows(src, end);
    if (*src == end)
        return -1; /* trailing comma */
    return 1;
}

static int sf_string_equals(h2o_iovec_t raw, h2o_iovec_t value)
{
    size_t j = 0;

    for (size_t i = 0; i != raw.len; ++i, ++j) {
        char c = raw.base[i];
        if (c == '\\')
            c = raw.base[++i]; /* sf_parse_string admits only \" and \\ */
        if (j == value.len || value.base[j] != c)
            return 0;
    }
    return j == value.len;
}

h2o_webtransport_protocol_selection_t h2o_webtransport_select_protocol(const h2o_iovec_t *lines, size_t num_lines,
                                                                       const h2o_iovec_t *supported, size_t num_supported,
                                                                       size_t *selected)
{
    size_t found = SIZE_MAX;

    for (size_t l = 0; l != num_lines; ++l) {
        const uint8_t *src = (const uint8_t *)lines[l].base, *end = src + lines[l].len;
        sf_skip_sp(&src, end);
        if (src == end)
            continue; /* an empty line is an empty List */
        int more;
        do {
            h2o_iovec_t raw;
            if (!sf_parse_string(&src, end, &raw) || !sf_parse_parameters(&src, end))
                return H2O_WEBTRANSPORT_PROTOCOL_INVALID;
            for (size_t i = 0; found == SIZE_MAX && i != num_supported; ++i)
                if (sf_string_equals(raw, supported[i]))
                    found = i;
        } while ((more = sf_parse_member_separator(&src, end)) == 1);
        if (more < 0)
            return H2O_WEBTRANSPORT_PROTOCOL_INVALID;
    }

    if (found == SIZE_MAX)
        return H2O_WEBTRANSPORT_PROTOCOL_NONE;
    *selected = found;
    return H2O_WEBTRANSPORT_PROTOCOL_SELECTED;
}

int h2o_webtransport_parse_init_header(const h2o_iovec_t *lines, size_t num_lines, h2o_webtransport_init_params_t *params)
{
    h2o_webtransport_init_params_t parsed = *params;

    for (size_t l = 0; l != num_lines; ++l) {
        const uint8_t *src = (const uint8_t *)lines[l].base, *end = src + lines[l].len;
        sf_skip_sp(&src, end);
        if (src == end)
            continue;
        int more;
        do {
            h2o_iovec_t key;
            int is_integer = 0;
            int64_t value = 0;
            if (!sf_parse_key(&src, end, &key))
                return -1;
            if (src != end && *src == '=') {
                ++src;
                if (src != end && *src == '(') {
                    if (!sf_parse_inner_list(&src, end))
                        return -1;
                } else {
                    if (!sf_parse_bare_item(&src, end, &is_integer, &value) || !sf_parse_parameters(&src, end))
                        return -1;
                }
            } else {
                /* a member without a value is Boolean true */
                if (!sf_parse_parameters(&src, end))
                    return -1;
            }
            /* when a key appears more than once, the last value wins (RFC 9651 section 4.2.2) */
            uint64_t *slot = NULL;
            if (h2o_memis(key.base, key.len, H2O_STRLIT("u"))) {
                slot = &parsed.max_stream_data_uni;
            } else if (h2o_memis(key.base, key.len, H2O_STRLIT("bl"))) {
                slot = &parsed.max_stream_data_bidi_local;
            } else if (h2o_memis(key.base, key.len, H2O_STRLIT("br"))) {
                slot = &parsed.max_stream_data_bidi_remote;
            }
            if (slot != NULL) {
                if (!is_integer || value < 0)
                    return -1;
                *slot = (uint64_t)value;
            }
        } while ((more = sf_parse_member_separator(&src, end)) == 1);
        if (more < 0)
            return -1;
    }

    *params = parsed;
    return 0;
}
