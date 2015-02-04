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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "h2o/string_.h"

h2o_iovec_t h2o_strdup(h2o_mem_pool_t *pool, const char *s, size_t slen)
{
    h2o_iovec_t ret;

    if (slen == SIZE_MAX)
        slen = strlen(s);

    if (pool != NULL) {
        ret.base = h2o_mem_alloc_pool(pool, slen + 1);
    } else {
        ret.base = h2o_mem_alloc(slen + 1);
    }
    memcpy(ret.base, s, slen);
    ret.base[slen] = '\0';
    ret.len = slen;
    return ret;
}

h2o_iovec_t h2o_strdup_slashed(h2o_mem_pool_t *pool, const char *src, size_t len)
{
    h2o_iovec_t ret;

    ret.len = len != SIZE_MAX ? len : strlen(src);
    ret.base = pool != NULL ? h2o_mem_alloc_pool(pool, ret.len + 2) : h2o_mem_alloc(ret.len + 2);
    memcpy(ret.base, src, ret.len);
    if (ret.len != 0 && ret.base[ret.len - 1] != '/')
        ret.base[ret.len++] = '/';
    ret.base[ret.len] = '\0';

    return ret;
}

int h2o__lcstris_core(const char *target, const char *test, size_t test_len)
{
    for (; test_len != 0; --test_len)
        if (h2o_tolower(*target++) != *test++)
            return 0;
    return 1;
}

size_t h2o_strtosize(const char *s, size_t len)
{
    uint64_t v = 0, m = 1;
    const char *p = s + len;

    if (len == 0)
        goto Error;

    while (1) {
        int ch = *--p;
        if (!('0' <= ch && ch <= '9'))
            goto Error;
        v += (ch - '0') * m;
        if (p == s)
            break;
        m *= 10;
        /* do not even try to overflow */
        if (m == 10000000000000000000ULL)
            goto Error;
    }

    if (v >= SIZE_MAX)
        goto Error;
    return v;

Error:
    return SIZE_MAX;
}

static uint32_t decode_base64url_quad(const char *src)
{
    const char *src_end = src + 4;
    uint32_t decoded = 0;

    while (1) {
        if ('A' <= *src && *src <= 'Z') {
            decoded |= *src - 'A';
        } else if ('a' <= *src && *src <= 'z') {
            decoded |= *src - 'a' + 26;
        } else if ('0' <= *src && *src <= '9') {
            decoded |= *src - '0' + 52;
        } else if (*src == '-') {
            decoded |= 62;
        } else if (*src == '_') {
            decoded |= 63;
#if 1 /* curl uses normal base64 */
        } else if (*src == '+') {
            decoded |= 62;
        } else if (*src == '/') {
            decoded |= 63;
#endif
        } else {
            return UINT32_MAX;
        }
        if (++src == src_end)
            break;
        decoded <<= 6;
    }

    return decoded;
}

h2o_iovec_t h2o_decode_base64url(h2o_mem_pool_t *pool, const char *src, size_t len)
{
    h2o_iovec_t decoded;
    uint32_t t;
    uint8_t *dst;
    char remaining_input[4];

    decoded.len = len * 3 / 4;
    decoded.base = h2o_mem_alloc_pool(pool, decoded.len + 1);
    dst = (uint8_t *)decoded.base;

    while (len >= 4) {
        if ((t = decode_base64url_quad(src)) == UINT32_MAX)
            goto Error;
        *dst++ = t >> 16;
        *dst++ = t >> 8;
        *dst++ = t;
        src += 4;
        len -= 4;
    }
    switch (len) {
    case 0:
        break;
    case 1:
        goto Error;
    case 2:
        remaining_input[0] = *src++;
        remaining_input[1] = *src++;
        remaining_input[2] = 'A';
        remaining_input[3] = 'A';
        if ((t = decode_base64url_quad(remaining_input)) == UINT32_MAX)
            goto Error;
        *dst++ = t >> 16;
        break;
    case 3:
        remaining_input[0] = *src++;
        remaining_input[1] = *src++;
        remaining_input[2] = *src++;
        remaining_input[3] = 'A';
        if ((t = decode_base64url_quad(remaining_input)) == UINT32_MAX)
            goto Error;
        *dst++ = t >> 16;
        *dst++ = t >> 8;
        break;
    }

    assert((char *)dst - decoded.base == decoded.len);
    decoded.base[decoded.len] = '\0';

    return decoded;

Error:
    return h2o_iovec_init(NULL, 0);
}

void h2o_base64_encode(char *dst, const void *_src, size_t len, int url_encoded)
{
    static const char *MAP = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                             "abcdefghijklmnopqrstuvwxyz"
                             "0123456789+/";
    static const char *MAP_URL_ENCODED = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                         "abcdefghijklmnopqrstuvwxyz"
                                         "0123456789-_";

    const uint8_t *src = _src;
    const char *map = url_encoded ? MAP_URL_ENCODED : MAP;
    uint32_t quad;

    for (; len >= 3; src += 3, len -= 3) {
        quad = ((uint32_t)src[0] << 16) | ((uint32_t)src[1] << 8) | src[2];
        *dst++ = map[quad >> 18];
        *dst++ = map[(quad >> 12) & 63];
        *dst++ = map[(quad >> 6) & 63];
        *dst++ = map[quad & 63];
    }
    if (len != 0) {
        quad = (uint32_t)src[0] << 16;
        *dst++ = map[quad >> 18];
        if (len == 2) {
            quad |= (uint32_t)src[1] << 8;
            *dst++ = map[(quad >> 12) & 63];
            *dst++ = map[(quad >> 6) & 63];
            if (!url_encoded)
                *dst++ = '=';
        } else {
            *dst++ = map[(quad >> 12) & 63];
            if (!url_encoded) {
                *dst++ = '=';
                *dst++ = '=';
            }
        }
    }

    *dst = '\0';
}

const char *h2o_get_filext(const char *path, size_t len)
{
    const char *p = path + len;

    while (--p != path) {
        if (*p == '.') {
            return p + 1;
        } else if (*p == '/') {
            break;
        }
    }
    return NULL;
}

size_t h2o_strstr(const char *haysack, size_t haysack_len, const char *needle, size_t needle_len)
{
    /* TODO optimize */
    if (haysack_len >= needle_len) {
        size_t off, max = haysack_len - needle_len;
        if (needle_len == 0)
            return 0;
        for (off = 0; off != max; ++off)
            if (haysack[off] == needle[0] && memcmp(haysack + off + 1, needle + 1, needle_len - 1) == 0)
                return off;
    }
    return SIZE_MAX;
}

/* note: returns a zero-width match as well */
const char *h2o_next_token(const char *elements, size_t elements_len, size_t *element_len, const char *cur)
{
    const char *elements_end = elements + elements_len;
    size_t off, off_non_ws;

    /* skip through current token */
    if (cur == NULL) {
        cur = elements;
    } else {
        while (*cur != ',') {
            if (cur == elements_end) {
                return NULL;
            }
            ++cur;
        }
        ++cur;
    }

    /* find start */
    while (*cur == ' ' || *cur == '\t') {
        if (cur == elements_end) {
            *element_len = 0;
            return cur;
        }
        ++cur;
    }

    /* find last */
    off_non_ws = 0;
    for (off = 0; off != elements_end - cur; ++off) {
        if (cur[off] == ',') {
            break;
        } else if (cur[off] == ' ' || cur[off] == '\t') {
            /* is ws */
        } else {
            off_non_ws = off + 1;
        }
    }

    *element_len = off_non_ws;
    return cur;
}

int h2o_contains_token(const char *haysack, size_t haysack_len, const char *needle, size_t needle_len)
{
    const char *token = NULL;
    size_t token_len = 0;

    while ((token = h2o_next_token(haysack, haysack_len, &token_len, token + token_len)) != NULL) {
        if (h2o_lcstris(token, token_len, needle, needle_len)) {
            return 1;
        }
    }
    return 0;
}

static int decode_hex(int ch)
{
    if ('0' <= ch && ch <= '9')
        return ch - '0';
    if ('A' <= ch && ch <= 'F')
        return ch - 'A' + 0xa;
    if ('a' <= ch && ch <= 'f')
        return ch - 'a' + 0xa;
    return -1;
}

static h2o_iovec_t rebuild_path(h2o_mem_pool_t *pool, const char *path, size_t len)
{
    const char *src = path, *src_end = path + len;
    char *dst;
    h2o_iovec_t ret;

    dst = ret.base = h2o_mem_alloc_pool(pool, len + 1);
    if (len == 0 || path[0] != '/')
        *dst++ = '/';
    while (src != src_end) {
        if (*src == '?')
            break;
        if ((src_end - src == 3 && memcmp(src, H2O_STRLIT("/..")) == 0) ||
            (src_end - src > 3 && memcmp(src, H2O_STRLIT("/../")) == 0)) {
            /* go back the previous "/" */
            if (ret.base < dst)
                --dst;
            for (; ret.base < dst && *dst != '/'; --dst)
                ;
            src += 3;
            if (src == src_end)
                *dst++ = '/';
            goto Next;
        }
        if ((src_end - src == 2 && memcmp(src, H2O_STRLIT("/.")) == 0) ||
            (src_end - src > 2 && memcmp(src, H2O_STRLIT("/./")) == 0)) {
            src += 2;
            if (src == src_end)
                *dst++ = '/';
            goto Next;
        }
        if (src_end - src >= 3 && *src == '%') {
            int hi, lo;
            if ((hi = decode_hex(src[1])) != -1 && (lo = decode_hex(src[2])) != -1) {
                *dst++ = (hi << 4) | lo;
                src += 3;
                goto Next;
            }
        }
        *dst++ = *src++;
    Next:
        ;
    }
    if (dst == ret.base)
        *dst++ = '/';
    ret.len = dst - ret.base;

    return ret;
}

h2o_iovec_t h2o_normalize_path(h2o_mem_pool_t *pool, const char *path, size_t len)
{
    const char *p = path, *end = path + len;
    h2o_iovec_t ret;

    if (len == 0 || path[0] != '/')
        goto Rewrite;

    for (; p + 1 < end; ++p) {
        if ((p[0] == '/' && p[1] == '.') || p[0] == '%') {
            /* detect false positives as well */
            goto Rewrite;
        } else if (p[0] == '?') {
            goto Return;
        }
    }
    for (; p < end; ++p) {
        if (p[0] == '?') {
            goto Return;
        }
    }

Return:
    ret.base = (char *)path;
    ret.len = p - path;
    return ret;

Rewrite:
    return rebuild_path(pool, path, len);
}

int h2o_parse_url(const char *url, size_t url_len, h2o_parse_url_t *parsed)
{
    const char *url_end, *token_start, *token_end;

    if (url_len == SIZE_MAX)
        url_len = strlen(url);
    url_end = url + url_len;

    /* check and skip scheme */
    if (url_len >= 7 && memcmp(url, "http://", 7) == 0) {
        parsed->scheme = h2o_iovec_init(H2O_STRLIT("http"));
        token_start = url + 7;
        parsed->port = 80;
    } else if (url_len >= 8 && memcmp(url, "https://", 8) == 0) {
        parsed->scheme = h2o_iovec_init(H2O_STRLIT("https"));
        token_start = url + 8;
        parsed->port = 443;
    } else {
        return -1;
    }

    /* parse host */
    if (token_start == url_end)
        return -1;
    parsed->authority.base = (char *)token_start;
    if (*token_start == '[') {
        /* is IPv6 address */
        ++token_start;
        if ((token_end = memchr(token_start, ']', url_end - token_start)) == NULL)
            return -1;
        parsed->host = h2o_iovec_init(token_start, token_end - token_start);
        token_start = token_end + 1;
    } else {
        for (token_end = token_start; !(token_end == url_end || *token_end == '/' || *token_end == ':'); ++token_end)
            ;
        parsed->host = h2o_iovec_init(token_start, token_end - token_start);
        token_start = token_end;
    }
    if (token_start == url_end)
        goto PathOmitted;

    /* parse port */
    if (*token_start == ':') {
        size_t p;
        ++token_start;
        if ((token_end = memchr(token_start, '/', url_end - token_start)) == NULL)
            token_end = url_end;
        if ((p = h2o_strtosize(token_start, token_end - token_start)) >= 65535)
            return -1;
        parsed->port = p;
        token_start = token_end;
        if (token_start == url_end)
            goto PathOmitted;
    }

    /* a non-empty path */
    parsed->authority.len = token_start - parsed->authority.base;
    parsed->path = h2o_iovec_init(token_start, url_end - token_start);

    return 0;
PathOmitted:
    parsed->authority.len = url_end - parsed->authority.base;
    parsed->path = h2o_iovec_init(H2O_STRLIT("/"));
    return 0;
}

h2o_iovec_t h2o_htmlescape(h2o_mem_pool_t *pool, const char *src, size_t len)
{
    const char *s, *end = src + len;
    size_t add_size = 0;

#define ENTITY_MAP()                                                                                                               \
    ENTITY('"', "&quot;");                                                                                                         \
    ENTITY('&', "&amp;");                                                                                                          \
    ENTITY('\'', "&#39;");                                                                                                         \
    ENTITY('<', "&lt;");                                                                                                           \
    ENTITY('>', "&gt;");

    for (s = src; s != end; ++s) {
        if ((unsigned)(unsigned char)*s - '"' <= '>' - '"') {
            switch (*s) {
#define ENTITY(code, quoted)                                                                                                       \
    case code:                                                                                                                     \
        add_size += sizeof(quoted) - 2;                                                                                            \
        break
                ENTITY_MAP()
#undef ENTITY
            }
        }
    }

    /* escape and return the result if necessary */
    if (add_size != 0) {
        /* allocate buffer and fill in the chars that are known not to require escaping */
        h2o_iovec_t escaped = {h2o_mem_alloc_pool(pool, len + add_size + 1), 0};
        /* fill-in the rest */
        for (s = src; s != end; ++s) {
            switch (*s) {
#define ENTITY(code, quoted)                                                                                                       \
    case code:                                                                                                                     \
        memcpy(escaped.base + escaped.len, quoted, sizeof(quoted) - 1);                                                            \
        escaped.len += sizeof(quoted) - 1;                                                                                         \
        break
                ENTITY_MAP()
#undef ENTITY
            default:
                escaped.base[escaped.len++] = *s;
                break;
            }
        }
        assert(escaped.len == len + add_size);
        escaped.base[escaped.len] = '\0';

        return escaped;
    }

#undef ENTITY_MAP

    /* no need not escape; return the original */
    return h2o_iovec_init(src, len);
}

h2o_iovec_t h2o_concat_list(h2o_mem_pool_t *pool, h2o_iovec_t *list, size_t count)
{
    h2o_iovec_t ret = {NULL, 0};
    size_t i;

    /* calc the length */
    for (i = 0; i != count; ++i) {
        ret.len += list[i].len;
    }

    /* allocate memory */
    if (pool != NULL)
        ret.base = h2o_mem_alloc_pool(pool, ret.len + 1);
    else
        ret.base = h2o_mem_alloc(ret.len + 1);

    /* concatenate */
    ret.len = 0;
    for (i = 0; i != count; ++i) {
        memcpy(ret.base + ret.len, list[i].base, list[i].len);
        ret.len += list[i].len;
    }
    ret.base[ret.len] = '\0';

    return ret;
}
