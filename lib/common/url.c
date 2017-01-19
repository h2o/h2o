/*
 * Copyright (c) 2014,2015 DeNA Co., Ltd.
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
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include "h2o/memory.h"
#include "h2o/string_.h"
#include "h2o/url.h"

const h2o_url_scheme_t H2O_URL_SCHEME_HTTP = {{H2O_STRLIT("http")}, 80};
const h2o_url_scheme_t H2O_URL_SCHEME_HTTPS = {{H2O_STRLIT("https")}, 443};

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

static size_t handle_special_paths(const char *path, size_t off, size_t last_slash)
{
    size_t orig_off = off, part_size = off - last_slash;

    if (part_size == 2 && path[off - 1] == '.') {
        --off;
    } else if (part_size == 3 && path[off - 2] == '.' && path[off - 1] == '.') {
        off -= 2;
        if (off > 1) {
            for (--off; path[off - 1] != '/'; --off)
                ;
        }
    }
    return orig_off - off;
}

/* Perform path normalization and URL decoding in one pass.
 * See h2o_req_t for the purpose of @norm_indexes. */
static h2o_iovec_t rebuild_path(h2o_mem_pool_t *pool, const char *src, size_t src_len, size_t *query_at, size_t **norm_indexes)
{
    char *dst;
    size_t src_off = 0, dst_off = 0, last_slash, rewind;

    { /* locate '?', and set len to the end of input path */
        const char *q = memchr(src, '?', src_len);
        if (q != NULL) {
            src_len = *query_at = q - src;
        } else {
            *query_at = SIZE_MAX;
        }
    }

    /* dst can be 1 byte more than src if src is missing the prefixing '/' */
    dst = h2o_mem_alloc_pool(pool, src_len + 1);
    *norm_indexes = h2o_mem_alloc_pool(pool, (src_len + 1) * sizeof(*norm_indexes[0]));

    if (src[0] == '/')
        src_off++;
    last_slash = dst_off;
    dst[dst_off] = '/';
    (*norm_indexes)[dst_off] = src_off;
    dst_off++;

    /* decode %xx */
    while (src_off < src_len) {
        int hi, lo;
        char decoded;

        if (src[src_off] == '%' && (src_off + 2 < src_len) && (hi = decode_hex(src[src_off + 1])) != -1 &&
            (lo = decode_hex(src[src_off + 2])) != -1) {
            decoded = (hi << 4) | lo;
            src_off += 3;
        } else {
            decoded = src[src_off++];
        }
        if (decoded == '/') {
            rewind = handle_special_paths(dst, dst_off, last_slash);
            if (rewind > 0) {
                dst_off -= rewind;
                last_slash = dst_off - 1;
                continue;
            }
            last_slash = dst_off;
        }
        dst[dst_off] = decoded;
        (*norm_indexes)[dst_off] = src_off;
        dst_off++;
    }
    rewind = handle_special_paths(dst, dst_off, last_slash);
    dst_off -= rewind;

    return h2o_iovec_init(dst, dst_off);
}

h2o_iovec_t h2o_url_normalize_path(h2o_mem_pool_t *pool, const char *path, size_t len, size_t *query_at, size_t **norm_indexes)
{
    const char *p = path, *end = path + len;
    h2o_iovec_t ret;

    *query_at = SIZE_MAX;
    *norm_indexes = NULL;

    if (len == 0) {
        ret = h2o_iovec_init("/", 1);
        return ret;
    }

    if (path[0] != '/')
        goto Rewrite;

    for (; p + 1 < end; ++p) {
        if ((p[0] == '/' && p[1] == '.') || p[0] == '%') {
            /* detect false positives as well */
            goto Rewrite;
        } else if (p[0] == '?') {
            *query_at = p - path;
            goto Return;
        }
    }
    for (; p < end; ++p) {
        if (p[0] == '?') {
            *query_at = p - path;
            goto Return;
        }
    }

Return:
    ret.base = (char *)path;
    ret.len = p - path;
    return ret;

Rewrite:
    ret = rebuild_path(pool, path, len, query_at, norm_indexes);
    if (ret.len == 0)
        goto RewriteError;
    if (ret.base[0] != '/')
        goto RewriteError;
    if (h2o_strstr(ret.base, ret.len, H2O_STRLIT("/../")) != SIZE_MAX)
        goto RewriteError;
    if (ret.len >= 3 && memcmp(ret.base + ret.len - 3, "/..", 3) == 0)
        goto RewriteError;
    return ret;
RewriteError:
    fprintf(stderr, "failed to normalize path: `%.*s` => `%.*s`\n", (int)len, path, (int)ret.len, ret.base);
    ret = h2o_iovec_init("/", 1);
    return ret;
}

static const char *parse_scheme(const char *s, const char *end, const h2o_url_scheme_t **scheme)
{
    if (end - s >= 5 && memcmp(s, "http:", 5) == 0) {
        *scheme = &H2O_URL_SCHEME_HTTP;
        return s + 5;
    } else if (end - s >= 6 && memcmp(s, "https:", 6) == 0) {
        *scheme = &H2O_URL_SCHEME_HTTPS;
        return s + 6;
    }
    return NULL;
}

const char *h2o_url_parse_hostport(const char *s, size_t len, h2o_iovec_t *host, uint16_t *port)
{
    const char *token_start = s, *token_end, *end = s + len;

    *port = 65535;

    if (token_start == end)
        return NULL;

    if (*token_start == '[') {
        /* is IPv6 address */
        ++token_start;
        if ((token_end = memchr(token_start, ']', end - token_start)) == NULL)
            return NULL;
        *host = h2o_iovec_init(token_start, token_end - token_start);
        token_start = token_end + 1;
    } else {
        for (token_end = token_start; !(token_end == end || *token_end == '/' || *token_end == ':'); ++token_end)
            ;
        *host = h2o_iovec_init(token_start, token_end - token_start);
        token_start = token_end;
    }

    /* disallow zero-length host */
    if (host->len == 0)
        return NULL;

    /* parse port */
    if (token_start != end && *token_start == ':') {
        size_t p;
        ++token_start;
        if ((token_end = memchr(token_start, '/', end - token_start)) == NULL)
            token_end = end;
        if ((p = h2o_strtosize(token_start, token_end - token_start)) >= 65535)
            return NULL;
        *port = (uint16_t)p;
        token_start = token_end;
    }

    return token_start;
}

static int parse_authority_and_path(const char *src, const char *url_end, h2o_url_t *parsed)
{
    const char *p = h2o_url_parse_hostport(src, url_end - src, &parsed->host, &parsed->_port);
    if (p == NULL)
        return -1;
    parsed->authority = h2o_iovec_init(src, p - src);
    if (p == url_end) {
        parsed->path = h2o_iovec_init(H2O_STRLIT("/"));
    } else {
        if (*p != '/')
            return -1;
        parsed->path = h2o_iovec_init(p, url_end - p);
    }
    return 0;
}

int h2o_url_parse(const char *url, size_t url_len, h2o_url_t *parsed)
{
    const char *url_end, *p;

    if (url_len == SIZE_MAX)
        url_len = strlen(url);
    url_end = url + url_len;

    /* check and skip scheme */
    if ((p = parse_scheme(url, url_end, &parsed->scheme)) == NULL)
        return -1;

    /* skip "//" */
    if (!(url_end - p >= 2 && p[0] == '/' && p[1] == '/'))
        return -1;
    p += 2;

    return parse_authority_and_path(p, url_end, parsed);
}

int h2o_url_parse_relative(const char *url, size_t url_len, h2o_url_t *parsed)
{
    const char *url_end, *p;

    if (url_len == SIZE_MAX)
        url_len = strlen(url);
    url_end = url + url_len;

    /* obtain scheme and port number */
    if ((p = parse_scheme(url, url_end, &parsed->scheme)) == NULL) {
        parsed->scheme = NULL;
        p = url;
    }

    /* handle "//" */
    if (url_end - p >= 2 && p[0] == '/' && p[1] == '/')
        return parse_authority_and_path(p + 2, url_end, parsed);

    /* reset authority, host, port, and set path */
    parsed->authority = (h2o_iovec_t){NULL};
    parsed->host = (h2o_iovec_t){NULL};
    parsed->_port = 65535;
    parsed->path = h2o_iovec_init(p, url_end - p);

    return 0;
}

h2o_iovec_t h2o_url_resolve(h2o_mem_pool_t *pool, const h2o_url_t *base, const h2o_url_t *relative, h2o_url_t *dest)
{
    h2o_iovec_t base_path, relative_path, ret;

    assert(base->path.len != 0);
    assert(base->path.base[0] == '/');

    if (relative == NULL) {
        /* build URL using base copied to dest */
        *dest = *base;
        base_path = base->path;
        relative_path = h2o_iovec_init(NULL, 0);
        goto Build;
    }

    /* scheme */
    dest->scheme = relative->scheme != NULL ? relative->scheme : base->scheme;

    /* authority (and host:port) */
    if (relative->authority.base != NULL) {
        assert(relative->host.base != NULL);
        dest->authority = relative->authority;
        dest->host = relative->host;
        dest->_port = relative->_port;
    } else {
        assert(relative->host.base == NULL);
        assert(relative->_port == 65535);
        dest->authority = base->authority;
        dest->host = base->host;
        dest->_port = base->_port;
    }

    /* path */
    base_path = base->path;
    if (relative->path.base != NULL) {
        relative_path = relative->path;
        h2o_url_resolve_path(&base_path, &relative_path);
    } else {
        assert(relative->path.len == 0);
        relative_path = (h2o_iovec_t){NULL};
    }

Build:
    /* build the output */
    ret = h2o_concat(pool, dest->scheme->name, h2o_iovec_init(H2O_STRLIT("://")), dest->authority, base_path, relative_path);
    /* adjust dest */
    dest->authority.base = ret.base + dest->scheme->name.len + 3;
    dest->host.base = dest->authority.base;
    if (dest->authority.len != 0 && dest->authority.base[0] == '[')
        ++dest->host.base;
    dest->path.base = dest->authority.base + dest->authority.len;
    dest->path.len = ret.base + ret.len - dest->path.base;

    return ret;
}

void h2o_url_resolve_path(h2o_iovec_t *base, h2o_iovec_t *relative)
{
    size_t base_path_len = base->len, rel_path_offset = 0;

    if (relative->len != 0 && relative->base[0] == '/') {
        base_path_len = 0;
    } else {
        /* relative path */
        while (base->base[--base_path_len] != '/')
            ;
        while (rel_path_offset != relative->len) {
            if (relative->base[rel_path_offset] == '.') {
                if (relative->len - rel_path_offset >= 2 && relative->base[rel_path_offset + 1] == '.' &&
                    (relative->len - rel_path_offset == 2 || relative->base[rel_path_offset + 2] == '/')) {
                    if (base_path_len != 0) {
                        while (base->base[--base_path_len] != '/')
                            ;
                    }
                    rel_path_offset += relative->len - rel_path_offset == 2 ? 2 : 3;
                    continue;
                }
                if (relative->len - rel_path_offset == 1) {
                    rel_path_offset += 1;
                    continue;
                } else if (relative->base[rel_path_offset + 1] == '/') {
                    rel_path_offset += 2;
                    continue;
                }
            }
            break;
        }
        base_path_len += 1;
    }

    base->len = base_path_len;
    *relative = h2o_iovec_init(relative->base + rel_path_offset, relative->len - rel_path_offset);
}

void h2o_url_copy(h2o_mem_pool_t *pool, h2o_url_t *dest, const h2o_url_t *src)
{
    dest->scheme = src->scheme;
    dest->authority = h2o_strdup(pool, src->authority.base, src->authority.len);
    dest->host = h2o_strdup(pool, src->host.base, src->host.len);
    dest->path = h2o_strdup(pool, src->path.base, src->path.len);
    dest->_port = src->_port;
}

const char *h2o_url_host_to_sun(h2o_iovec_t host, struct sockaddr_un *sa)
{
#define PREFIX "unix:"

    if (host.len < sizeof(PREFIX) - 1 || memcmp(host.base, PREFIX, sizeof(PREFIX) - 1) != 0)
        return h2o_url_host_to_sun_err_is_not_unix_socket;

    if (host.len - sizeof(PREFIX) - 1 >= sizeof(sa->sun_path))
        return "unix-domain socket path is too long";

    memset(sa, 0, sizeof(*sa));
    sa->sun_family = AF_UNIX;
    memcpy(sa->sun_path, host.base + sizeof(PREFIX) - 1, host.len - (sizeof(PREFIX) - 1));
    return NULL;

#undef PREFIX
}

const char *h2o_url_host_to_sun_err_is_not_unix_socket = "supplied name does not look like an unix-domain socket";
