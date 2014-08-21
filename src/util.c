#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "h2o.h"

void h2o_fatal(const char *msg)
{
    fprintf(stderr, "fatal:%s\n", msg);
    abort();
}

uv_buf_t h2o_allocate_input_buffer(h2o_input_buffer_t **_inbuf, size_t initial_size)
{
    h2o_input_buffer_t *inbuf = *_inbuf;
    uv_buf_t ret;

    if (inbuf == NULL) {
        if ((inbuf = malloc(offsetof(h2o_input_buffer_t, bytes) + initial_size)) == NULL)
            h2o_fatal("no memory");
        *_inbuf = inbuf;
        inbuf->size = 0;
        inbuf->capacity = initial_size;
    } else if (inbuf->size == inbuf->capacity) {
        inbuf->capacity *= 2;
        if ((inbuf = realloc(inbuf, offsetof(h2o_input_buffer_t, bytes) + inbuf->capacity)) == NULL)
            h2o_fatal("no memory");
        *_inbuf = inbuf;
    }

    ret.base = inbuf->bytes + inbuf->size;
    ret.len = inbuf->capacity - inbuf->size;

    return ret;
}

void h2o_consume_input_buffer(h2o_input_buffer_t **_inbuf, size_t delta)
{
    h2o_input_buffer_t *inbuf = *_inbuf;

    if (delta != 0) {
        assert(inbuf != NULL);
        memmove(inbuf->bytes, inbuf->bytes + delta, inbuf->size - delta);
        /* TODO shrink the size */
        inbuf->size -= delta;
    }
}

int h2o_lcstris_core(const char *target, const char *test, size_t test_len)
{
    for (; test_len != 0; --test_len)
        if (h2o_tolower(*target++) != *test++)
            return 0;
    return 1;
}

uv_buf_t h2o_strdup(h2o_mempool_t *pool, const char *s, size_t slen)
{
    uv_buf_t ret;

    if (slen == SIZE_MAX)
        slen = strlen(s);

    if (pool != NULL) {
        ret.base = h2o_mempool_alloc(pool, slen + 1);
    } else {
        if ((ret.base = malloc(slen + 1)) == NULL)
            h2o_fatal("no memory");
    }
    memcpy(ret.base, s, slen);
    ret.base[slen] = '\0';
    ret.len = strlen(s);
    return ret;
}

__attribute__((format (printf, 2, 3)))
uv_buf_t h2o_sprintf(h2o_mempool_t *pool, const char *fmt, ...)
{
    char smallbuf[1024];
    va_list arg;
    int len;
    uv_buf_t ret;

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
        if ((ret.base = malloc(len + 1)) == NULL)
            h2o_fatal("");
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
    uint32_t decoded = 0;
    int i;

    for (i = 0; i != 4; ++i, ++src, decoded <<= 6) {
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
#ifdef HTTP2_BUGGY_CLIENT
        } else if (*src == '+') {
            decoded |= 62;
        } else if (*src == '/') {
            decoded |= 63;
#endif
        } else {
            return UINT32_MAX;
        }
    }

    return decoded;
}

uv_buf_t h2o_decode_base64url(h2o_mempool_t *pool, const char *src, size_t len)
{
    uv_buf_t decoded;
    uint32_t t;
    uint8_t* dst;
    char remaining_input[4];

    decoded.len = len * 3 / 4;
    decoded.base = h2o_mempool_alloc(pool, decoded.len);
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
        if ((t = decode_base64url_quad(src)) == UINT32_MAX)
            goto Error;
        *dst++ = t >> 16;
        break;
    case 3:
        remaining_input[0] = *src++;
        remaining_input[1] = *src++;
        remaining_input[2] = *src++;
        remaining_input[3] = 'A';
        if ((t = decode_base64url_quad(src)) == UINT32_MAX)
            goto Error;
        *dst++ = t >> 16;
        *dst++ = t >> 8;
        break;
    }

    assert((char*)dst - decoded.base == decoded.len);

    return decoded;

Error:
    return uv_buf_init(NULL, 0);
}

uv_buf_t h2o_data2str(h2o_mempool_t *pool, time_t time)
{
    struct tm gmt;
    gmtime_r(&time, &gmt);

    return h2o_sprintf(
        pool,
        "%s, %02d %s %d %02d:%02d:%02d GMT",
        ("Sun\0Mon\0Tue\0Wed\0Thu\0Fri\0Sat") + gmt.tm_wday * 4,
        gmt.tm_mday,
        ("Jan\0Feb\0Mar\0Apr\0May\0Jun\0Jul\0Aug\0Sep\0Oct\0Nov\0Dec\0") + gmt.tm_mon * 4,
        gmt.tm_year + 1900,
        gmt.tm_hour,
        gmt.tm_min,
        gmt.tm_sec);
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

static uv_buf_t rewrite_traversal(h2o_mempool_t *pool, const char *path, size_t len)
{
    const char *src = path, *src_end = path + len;
    char *dst;
    uv_buf_t ret;

    dst = ret.base = h2o_mempool_alloc(pool, len + 1);
    if (len == 0 || path[0] != '/')
        *dst++ = '/';
    while (src != src_end) {
        if ((src_end - src == 3 && memcmp(src, H2O_STRLIT("/..")) == 0)
            || (src_end - src > 3 && memcmp(src, H2O_STRLIT("/../")) == 0)) {
            for (--dst; ret.base < dst; --dst)
                if (*dst == '/')
                    break;
            ++dst;
            src += src + 3 == src_end ? 3 : 4;
        } else {
            *dst++ = *src++;
        }
    }
    ret.len = dst - ret.base;

    return ret;
}

uv_buf_t h2o_normalize_path(h2o_mempool_t *pool, const char *path, size_t len)
{
    const char *p = path, *end = path + len;
    uv_buf_t ret;

    if (len == 0 || path[0] != '/')
        goto Rewrite;

    while (p + 3 <= end) {
        if (p[0] == '/')
            if (p[1] == '.')
                if (p[2] == '.')
                    if (p + 3 == end || p[3] == '/')
                        goto Rewrite;
                    else
                        p += 4;
                else
                    p += 3;
            else
                p += 2;
        else
            p += 1;
    }

    ret.base = (char*)path;
    ret.len = len;
    return ret;

Rewrite:
    return rewrite_traversal(pool, path, len);
}

void h2o_vector__expand(h2o_mempool_t *pool, h2o_vector_t *vector, size_t element_size, size_t new_capacity)
{
    void *new_entries;
    assert(vector->capacity < new_capacity);
    if (vector->capacity == 0)
        vector->capacity = 4;
    while (vector->capacity < new_capacity)
        vector->capacity *= 2;
    new_entries = h2o_mempool_alloc(pool, element_size * vector->capacity);
    memcpy(new_entries, vector->entries, element_size * vector->size);
    vector->entries = new_entries;
}

void h2o_send_inline(h2o_req_t *req, const char *body)
{
    h2o_generator_t *self;
    uv_buf_t buf = h2o_strdup(&req->pool, body, SIZE_MAX);

    req->res.content_length = buf.len;
    self = h2o_start_response(req, sizeof(h2o_generator_t));

    h2o_send(req, &buf, 1, 1);
}

void h2o_send_error(h2o_req_t *req, int status, const char *reason, const char *body)
{
    req->http1_is_persistent = 0;

    req->res.status = status;
    req->res.reason = reason;
    memset(&req->res.headers, 0, sizeof(req->res.headers));
    h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_CONTENT_TYPE, H2O_STRLIT("text/plain; charset=utf-8"));

    h2o_send_inline(req, body);
}
