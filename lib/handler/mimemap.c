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
#include "khash.h"
#include "h2o.h"

KHASH_MAP_INIT_STR(exttable, h2o_iovec_t)

struct st_h2o_mimemap_t {
    khash_t(exttable) * table;
    h2o_iovec_t default_type;
};

static h2o_iovec_t dupref(const char *s)
{
    h2o_iovec_t ret;
    ret.len = strlen(s);
    ret.base = h2o_mem_alloc_shared(NULL, ret.len + 1, NULL);
    memcpy(ret.base, s, ret.len + 1);
    return ret;
}

static void on_dispose(void *_mimemap)
{
    h2o_mimemap_t *mimemap = _mimemap;
    const char *ext;
    h2o_iovec_t type;

    kh_foreach(mimemap->table, ext, type, {
        h2o_mem_release_shared((char *)ext);
        h2o_mem_release_shared(type.base);
    });
    kh_destroy(exttable, mimemap->table);
    h2o_mem_release_shared(mimemap->default_type.base);
}

h2o_mimemap_t *h2o_mimemap_create()
{
    h2o_mimemap_t *mimemap = h2o_mem_alloc_shared(NULL, sizeof(*mimemap), on_dispose);

    mimemap->table = kh_init(exttable);
    mimemap->default_type = dupref("application/octet-stream");

    { /* setup the tiny default */
        static const char *default_types[] = {"txt", "text/plain", "html", "text/html", "gif", "image/gif", "png", "image/png",
                                              "jpg", "image/jpeg", "jpeg", "image/jpeg", "webp", "image/webp",
                                              "css", "text/css", "js", "application/javascript",
                                              "json", "application/json", NULL};
        const char **p;
        for (p = default_types; *p != NULL; p += 2)
            h2o_mimemap_set_type(mimemap, p[0], p[1]);
    }

    return mimemap;
}

h2o_mimemap_t *h2o_mimemap_clone(h2o_mimemap_t *src)
{
    h2o_mimemap_t *dst = h2o_mem_alloc_shared(NULL, sizeof(*dst), on_dispose);
    const char *ext;
    h2o_iovec_t type;

    dst->table = kh_init(exttable);
    kh_foreach(src->table, ext, type, {
        int r;
        khiter_t iter = kh_put(exttable, dst->table, ext, &r);
        kh_val(dst->table, iter) = type;
        h2o_mem_addref_shared((char *)ext);
        h2o_mem_addref_shared(type.base);
    });
    dst->default_type = src->default_type;
    h2o_mem_addref_shared(dst->default_type.base);

    return dst;
}

void h2o_mimemap_set_default_type(h2o_mimemap_t *mimemap, const char *type)
{
    h2o_mem_release_shared(mimemap->default_type.base);
    mimemap->default_type = dupref(type);
}

void h2o_mimemap_set_type(h2o_mimemap_t *mimemap, const char *ext, const char *type)
{
    khiter_t iter = kh_get(exttable, mimemap->table, ext);
    if (iter != kh_end(mimemap->table)) {
        h2o_mem_release_shared(kh_val(mimemap->table, iter).base);
    } else {
        int ret;
        iter = kh_put(exttable, mimemap->table, dupref(ext).base, &ret);
        assert(iter != kh_end(mimemap->table));
    }
    kh_val(mimemap->table, iter) = dupref(type);
}

void h2o_mimemap_remove_type(h2o_mimemap_t *mimemap, const char *ext)
{
    khiter_t iter = kh_get(exttable, mimemap->table, ext);
    if (iter != kh_end(mimemap->table)) {
        const char *key = kh_key(mimemap->table, iter);
        h2o_mem_release_shared(kh_val(mimemap->table, iter).base);
        kh_del(exttable, mimemap->table, iter);
        h2o_mem_release_shared((char *)key);
    }
}

h2o_iovec_t h2o_mimemap_get_default_type(h2o_mimemap_t *mimemap)
{
    return mimemap->default_type;
}

h2o_iovec_t h2o_mimemap_get_type(h2o_mimemap_t *mimemap, const char *ext)
{
    if (ext != NULL) {
        khiter_t iter = kh_get(exttable, mimemap->table, ext);
        if (iter != kh_end(mimemap->table))
            return kh_val(mimemap->table, iter);
    }
    return mimemap->default_type;
}
