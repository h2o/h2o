/*
 * Copyright (c) 2015 DeNA Co., Ltd., Kazuho Oku
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
#include <stdlib.h>
#include "h2o.h"

#define MODULE_NAME "lib/handler/redirect.c"

typedef H2O_VECTOR(char *) char_vec;

struct st_h2o_redirect_handler_t {
    h2o_handler_t super;
    int internal;
    int status;
    h2o_iovec_t prefix;
    char_vec wildcard_chars;
};

static void on_dispose(h2o_handler_t *_self)
{
    h2o_redirect_handler_t *self = (void *)_self;
    free(self->prefix.base);
    if (self->wildcard_chars.entries != NULL) {
        free(self->wildcard_chars.entries);
    }
}

static void redirect_internally(h2o_redirect_handler_t *self, h2o_req_t *req, h2o_iovec_t dest)
{
    h2o_iovec_t method;
    h2o_url_t input, resolved;

    /* resolve the URL */
    if (h2o_url_parse_relative(dest.base, dest.len, &input) != 0) {
        h2o_req_log_error(req, MODULE_NAME, "invalid destination:%.*s", (int)dest.len, dest.base);
        goto SendInternalError;
    }
    if (input.scheme != NULL && input.authority.base != NULL) {
        resolved = input;
    } else {
        h2o_url_t base;
        /* we MUST to set authority to that of hostconf, or internal redirect might create a TCP connection */
        if (h2o_url_init(&base, req->scheme, req->hostconf->authority.hostport, req->path) != 0) {
            h2o_req_log_error(req, MODULE_NAME, "failed to parse current authority:%.*s", (int)req->authority.len,
                              req->authority.base);
            goto SendInternalError;
        }
        h2o_url_resolve(&req->pool, &base, &input, &resolved);
    }

    /* determine the method */
    switch (self->status) {
    case 307:
    case 308:
        method = req->method;
        break;
    default:
        method = h2o_iovec_init(H2O_STRLIT("GET"));
        req->entity = (h2o_iovec_t){NULL};
        break;
    }

    h2o_reprocess_request_deferred(req, method, resolved.scheme, resolved.authority, resolved.path, NULL, 1);
    return;

SendInternalError:
    h2o_send_error_503(req, "Internal Server Error", "internal server error", 0);
}

static h2o_iovec_t replace_wildcard(h2o_mem_pool_t *pool, h2o_iovec_t target, char_vec *wildcard_chars, h2o_iovec_t replacement)
{
    h2o_iovec_t replaced;
    replaced.len = target.len + wildcard_chars->size * (replacement.len - 1);
    replaced.base = h2o_mem_alloc_pool(pool, char, replaced.len);
    char *src = target.base;
    char *dst = replaced.base;
    size_t i;
    for (i = 0; i != wildcard_chars->size; ++i) {
        size_t plen = wildcard_chars->entries[i] - src;
        memcpy(dst, src, plen);
        dst += plen;
        src += plen;
        memcpy(dst, replacement.base, replacement.len);
        dst += replacement.len;
        src += 1;
    }
    memcpy(dst, src, target.len - (src - target.base));
    return replaced;
}

static int on_req(h2o_handler_t *_self, h2o_req_t *req)
{
    h2o_redirect_handler_t *self = (void *)_self;

    h2o_iovec_t prefix;
    if (self->wildcard_chars.entries != NULL && req->authority_wildcard_match.base != NULL) {
        prefix = replace_wildcard(&req->pool, self->prefix, &self->wildcard_chars, req->authority_wildcard_match);
    } else {
        prefix = self->prefix;
    }

    h2o_iovec_t dest = h2o_build_destination(req, prefix.base, prefix.len, 1);

    /* redirect */
    if (self->internal) {
        redirect_internally(self, req, dest);
    } else {
        h2o_send_redirect(req, self->status, "Redirected", dest.base, dest.len);
    }

    return 0;
}

static void collect_wildcard_chars(h2o_iovec_t str, char_vec *dest)
{
    *dest = (char_vec){ 0 };
    if (str.base == NULL) {
        return;
    }
    char *start = str.base;
    char *end = start + str.len;
    char *p = start;
    while (p < end && (p = memchr(p, '*', end - p)) != NULL) {
        h2o_vector_reserve(NULL, dest, dest->size + 1);
        dest->entries[dest->size++] = p;
        ++p;
    }
}

h2o_redirect_handler_t *h2o_redirect_register(h2o_pathconf_t *pathconf, int internal, int status, const char *prefix)
{
    h2o_redirect_handler_t *self = (void *)h2o_create_handler(pathconf, sizeof(*self));
    self->super.dispose = on_dispose;
    self->super.on_req = on_req;
    self->internal = internal;
    self->status = status;
    self->prefix = h2o_strdup(NULL, prefix, SIZE_MAX);
    collect_wildcard_chars(self->prefix, &self->wildcard_chars);

    return self;
}
