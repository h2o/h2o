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
#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "h2o.h"

void h2o_fatal(const char *msg)
{
    fprintf(stderr, "fatal:%s\n", msg);
    abort();
}

int h2o_lcstris_core(const char *target, const char *test, size_t test_len)
{
    for (; test_len != 0; --test_len)
        if (h2o_tolower(*target++) != *test++)
            return 0;
    return 1;
}

h2o_buf_t h2o_strdup(h2o_mempool_t *pool, const char *s, size_t slen)
{
    h2o_buf_t ret;

    if (slen == SIZE_MAX)
        slen = strlen(s);

    if (pool != NULL) {
        ret.base = h2o_mempool_alloc(pool, slen + 1);
    } else {
        ret.base = h2o_malloc(slen + 1);
    }
    memcpy(ret.base, s, slen);
    ret.base[slen] = '\0';
    ret.len = slen;
    return ret;
}

__attribute__((format (printf, 2, 3)))
h2o_buf_t h2o_sprintf(h2o_mempool_t *pool, const char *fmt, ...)
{
    char smallbuf[1024];
    va_list arg;
    int len;
    h2o_buf_t ret;

    ret.base = NULL;
    ret.len = 0;

    // determine the length (as well as fill-in the small buf)
    va_start(arg, fmt);
    len = vsnprintf(smallbuf, sizeof(smallbuf), fmt, arg);
    va_end(arg);
    if (len == -1)
        h2o_fatal("sprintf usage error");

    // allocate
    if (pool != NULL) {
        ret.base = h2o_mempool_alloc(pool, len + 1);
    } else {
        ret.base = h2o_malloc(len + 1);
    }
    ret.len = len;

    // copy from small buf or reprint
    if (len < sizeof(smallbuf)) {
            memcpy(ret.base, smallbuf, len + 1);
    } else {
            va_start(arg, fmt);
            vsnprintf(ret.base, len + 1, fmt, arg);
            va_end(arg);
    }

    return ret;
}

__attribute__((format (printf, 3, 4)))
size_t h2o_snprintf(char *buf, size_t bufsz, const char *fmt, ...)
{
    va_list arg;
    int len;

    va_start(arg, fmt);
    len = vsnprintf(buf, bufsz, fmt, arg);
    va_end(arg);
    if (len == -1)
        h2o_fatal("sprintf usage error");
    else if (len + 1 > bufsz)
        h2o_fatal("buffer too small");
    return len;
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

h2o_buf_t h2o_decode_base64url(h2o_mempool_t *pool, const char *src, size_t len)
{
    h2o_buf_t decoded;
    uint32_t t;
    uint8_t* dst;
    char remaining_input[4];

    decoded.len = len * 3 / 4;
    decoded.base = h2o_mempool_alloc(pool, decoded.len + 1);
    dst = (uint8_t*)decoded.base;

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

    assert((char*)dst - decoded.base == decoded.len);
    decoded.base[decoded.len] = '\0';

    return decoded;

Error:
    return h2o_buf_init(NULL, 0);
}

void h2o_base64_encode(char *dst, const uint8_t *src, size_t len, int url_encoded)
{
    static const char *MAP =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";
    static const char *MAP_URL_ENCODED =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789-_";

    const char *map = url_encoded ? MAP_URL_ENCODED : MAP;
    uint32_t quad;

    for (; len >= 3; src += 3, len -= 3) {
        quad = ((uint32_t)src[0] << 16)
            | ((uint32_t)src[1] << 8)
            | src[2];
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
            if (! url_encoded)
                *dst++ = '=';
        } else {
            *dst++ = map[(quad >> 12) & 63];
            if (! url_encoded) {
                *dst++ = '=';
                *dst++ = '=';
            }
        }
    }

    *dst = '\0';
}

void h2o_time2str_rfc1123(char *buf, time_t time)
{
    struct tm gmt;
    gmtime_r(&time, &gmt);

    int len = sprintf(
        buf,
        "%s, %02d %s %d %02d:%02d:%02d GMT",
        ("Sun\0Mon\0Tue\0Wed\0Thu\0Fri\0Sat") + gmt.tm_wday * 4,
        gmt.tm_mday,
        ("Jan\0Feb\0Mar\0Apr\0May\0Jun\0Jul\0Aug\0Sep\0Oct\0Nov\0Dec\0") + gmt.tm_mon * 4,
        gmt.tm_year + 1900,
        gmt.tm_hour,
        gmt.tm_min,
        gmt.tm_sec);
    assert(len == H2O_TIMESTR_RFC1123_LEN);
}

void h2o_time2str_log(char *buf, time_t time)
{
    struct tm localt;
    localtime_r(&time, &localt);
    int gmt_off = (int)(localt.tm_gmtoff / 60);
    int gmt_sign;

    if (gmt_off >= 0) {
        gmt_sign = '+';
    } else {
        gmt_off = -gmt_off;
        gmt_sign = '-';
    }

    int len = sprintf(
        buf,
        "%02d/%s/%d:%02d:%02d:%02d %c%02d%02d",
        localt.tm_mday,
        ("Jan\0Feb\0Mar\0Apr\0May\0Jun\0Jul\0Aug\0Sep\0Oct\0Nov\0Dec\0") + localt.tm_mon * 4,
        localt.tm_year + 1900,
        localt.tm_hour,
        localt.tm_min,
        localt.tm_sec,
        gmt_sign,
        gmt_off / 60,
        gmt_off % 60);
    assert(len == H2O_TIMESTR_LOG_LEN);
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

/* note: returns a zero-width match as well */
const char *h2o_next_token(const char* elements, size_t elements_len, size_t *element_len, const char *cur)
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

static h2o_buf_t rewrite_traversal(h2o_mempool_t *pool, const char *path, size_t len)
{
    const char *src = path, *src_end = path + len;
    char *dst;
    h2o_buf_t ret;

    dst = ret.base = h2o_mempool_alloc(pool, len + 1);
    if (len == 0 || path[0] != '/')
        *dst++ = '/';
    while (src != src_end) {
        if (*src == '?')
            break;
        if ((src_end - src == 3 && memcmp(src, H2O_STRLIT("/..")) == 0)
            || (src_end - src > 3 && memcmp(src, H2O_STRLIT("/../")) == 0)) {
            /* go back the previous "/" */
            if (ret.base < dst)
                --dst;
            for (; ret.base < dst && *dst != '/'; --dst)
                ;
            src += 3;
            if (src == src_end)
                *dst++ = '/';
        } else if ((src_end - src == 2 && memcmp(src, H2O_STRLIT("/.")) == 0)
            || (src_end - src > 2 && memcmp(src, H2O_STRLIT("/./")) == 0)) {
            src += 2;
            if (src == src_end)
                *dst++ = '/';
        } else {
            *dst++ = *src++;
        }
    }
    if (dst == ret.base)
        *dst++ = '/';
    ret.len = dst - ret.base;

    return ret;
}

h2o_buf_t h2o_normalize_path(h2o_mempool_t *pool, const char *path, size_t len)
{
    const char *p = path, *end = path + len;
    h2o_buf_t ret;

    if (len == 0 || path[0] != '/')
        goto Rewrite;

    for (; p + 1 < end; ++p) {
        if (p[0] == '/' && p[1] == '.') {
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
    ret.base = (char*)path;
    ret.len = p - path;
    return ret;

Rewrite:
    return rewrite_traversal(pool, path, len);
}

void h2o_send_inline(h2o_req_t *req, const char *body, size_t len)
{
    h2o_buf_t buf = h2o_strdup(&req->pool, body, len);

    req->res.content_length = buf.len;
    h2o_start_response(req, sizeof(h2o_generator_t));

    h2o_send(req, &buf, 1, 1);
}

void h2o_send_error(h2o_req_t *req, int status, const char *reason, const char *body)
{
    req->http1_is_persistent = 0;

    req->res.status = status;
    req->res.reason = reason;
    memset(&req->res.headers, 0, sizeof(req->res.headers));
    h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_CONTENT_TYPE, H2O_STRLIT("text/plain; charset=utf-8"));

    h2o_send_inline(req, body, SIZE_MAX);
}

int h2o_config_scanf(h2o_configurator_t *configurator, const char *config_file, yoml_t *config_node, const char *fmt, ...)
{
    va_list args;
    int sscan_ret;

    if (config_node->type != YOML_TYPE_SCALAR)
        goto Error;
    va_start(args, fmt);
    sscan_ret = vsscanf(config_node->data.scalar, fmt, args);
    va_end(args);
    if (sscan_ret != 1)
        goto Error;

    return 0;
Error:
    h2o_context_print_config_error(configurator, config_file, config_node, "argument must match the format: %s", fmt);
    return -1;
}

ssize_t h2o_config_get_one_of(h2o_configurator_t *configurator, const char *config_file, yoml_t *config_node, const char *candidates)
{
    const char *config_str, *cand_str;
    ssize_t config_str_len, cand_index;

    if (config_node->type != YOML_TYPE_SCALAR)
        goto Error;

    config_str = config_node->data.scalar;
    config_str_len = strlen(config_str);

    cand_str = candidates;
    for (cand_index = 0; ; ++cand_index) {
        if (strncasecmp(cand_str, config_str, config_str_len) == 0
            && (cand_str[config_str_len] == '\0' || cand_str[config_str_len] == ',')) {
            /* found */
            return cand_index;
        }
        cand_str = strchr(cand_str, ',');
        if (cand_str == NULL)
            goto Error;
        cand_str += 1; /* skip ',' */
    }
    /* not reached */

Error:
    h2o_context_print_config_error(configurator, config_file, config_node, "argument must be one of: %s", candidates);
    return -1;
}

#ifdef PICOTEST_FUNCS

#include "picotest.h"

void util_test(void)
{
    h2o_mempool_t pool;

    h2o_mempool_init(&pool);

    note("base64");
    {
        char buf[256];
        h2o_buf_t src = { H2O_STRLIT("The quick brown fox jumps over the lazy dog.") }, decoded;
        h2o_base64_encode(buf, (const uint8_t*)src.base, src.len, 1);
        ok(strcmp(buf, "VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZy4") == 0);
        decoded = h2o_decode_base64url(&pool, buf, strlen(buf));
        ok(src.len == decoded.len);
        ok(strcmp(decoded.base, src.base) == 0);
    }
    h2o_mempool_clear(&pool);

    note("h2o_normalize_path");
    {
        h2o_buf_t b = h2o_normalize_path(&pool, H2O_STRLIT("/"));
        ok(b.len == 1);
        ok(memcmp(b.base, H2O_STRLIT("/")) == 0);

        b = h2o_normalize_path(&pool, H2O_STRLIT("/abc"));
        ok(b.len == 4);
        ok(memcmp(b.base, H2O_STRLIT("/abc")) == 0);

        b = h2o_normalize_path(&pool, H2O_STRLIT("/abc"));
        ok(b.len == 4);
        ok(memcmp(b.base, H2O_STRLIT("/abc")) == 0);

        b = h2o_normalize_path(&pool, H2O_STRLIT("/abc/../def"));
        ok(b.len == 4);
        ok(memcmp(b.base, H2O_STRLIT("/def")) == 0);

        b = h2o_normalize_path(&pool, H2O_STRLIT("/abc/../../def"));
        ok(b.len == 4);
        ok(memcmp(b.base, H2O_STRLIT("/def")) == 0);

        b = h2o_normalize_path(&pool, H2O_STRLIT("/abc/./def"));
        ok(b.len == 8);
        ok(memcmp(b.base, H2O_STRLIT("/abc/def")) == 0);

        b = h2o_normalize_path(&pool, H2O_STRLIT("/abc/def/.."));
        ok(b.len == 5);
        ok(memcmp(b.base, H2O_STRLIT("/abc/")) == 0);

        b = h2o_normalize_path(&pool, H2O_STRLIT("/abc/def/."));
        ok(b.len == 9);
        ok(memcmp(b.base, H2O_STRLIT("/abc/def/")) == 0);

        b = h2o_normalize_path(&pool, H2O_STRLIT("/abc?xx"));
        ok(b.len == 4);
        ok(memcmp(b.base, H2O_STRLIT("/abc")) == 0);

        b = h2o_normalize_path(&pool, H2O_STRLIT("/abc/../def?xx"));
        ok(b.len == 4);
        ok(memcmp(b.base, H2O_STRLIT("/def")) == 0);
    }
    h2o_mempool_clear(&pool);
}

#endif
