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

KHASH_MAP_INIT_STR(exttable, h2o_mimemap_type_t *)

struct st_h2o_mimemap_t {
    khash_t(exttable) * table;
    h2o_mimemap_type_t *default_type;
    size_t num_dynamic;
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
    h2o_mimemap_type_t *type;

    kh_foreach(mimemap->table, ext, type, {
        h2o_mem_release_shared((char *)ext);
        h2o_mem_release_shared(type);
    });
    kh_destroy(exttable, mimemap->table);
    h2o_mem_release_shared(mimemap->default_type);
}

static void on_unlink(h2o_mimemap_t *mimemap, h2o_mimemap_type_t *type)
{
    switch (type->type) {
    case H2O_MIMEMAP_TYPE_MIMETYPE:
        break;
    case H2O_MIMEMAP_TYPE_DYNAMIC:
        --mimemap->num_dynamic;
        break;
    }
}

static void on_link(h2o_mimemap_t *mimemap, h2o_mimemap_type_t *type)
{
    switch (type->type) {
    case H2O_MIMEMAP_TYPE_MIMETYPE:
        break;
    case H2O_MIMEMAP_TYPE_DYNAMIC:
        ++mimemap->num_dynamic;
        break;
    }
}

h2o_mimemap_type_t *h2o_mimemap_create_extension_type(const char *mime)
{
    size_t mimelen = strlen(mime);
    h2o_mimemap_type_t *type = h2o_mem_alloc_shared(NULL, sizeof(*type) + mimelen + 1, NULL);

    type->type = H2O_MIMEMAP_TYPE_MIMETYPE;
    type->data.mimetype.base = (char *)type + sizeof(*type);
    type->data.mimetype.len = mimelen;
    memcpy(type->data.mimetype.base, mime, mimelen + 1);

    return type;
}

h2o_mimemap_type_t *h2o_mimemap_create_dynamic_type(h2o_globalconf_t *globalconf)
{
    h2o_mimemap_type_t *type = h2o_mem_alloc_shared(NULL, sizeof(*type), NULL);

    type->type = H2O_MIMEMAP_TYPE_DYNAMIC;
    memset(&type->data.dynamic, 0, sizeof(type->data.dynamic));
    h2o_config_init_pathconf(&type->data.dynamic.pathconf, globalconf, (void *)h2o_config_dispose_pathconf);

    return type;
}

h2o_mimemap_t *h2o_mimemap_create()
{
    h2o_mimemap_t *mimemap = h2o_mem_alloc_shared(NULL, sizeof(*mimemap), on_dispose);

    mimemap->table = kh_init(exttable);
    mimemap->default_type = h2o_mimemap_create_extension_type("application/octet-stream");
    mimemap->num_dynamic = 0;
    on_link(mimemap, mimemap->default_type);

    { /* setup the tiny default */
        static const char *default_types[] = {
#define MIMEMAP(ext, mime) ext, mime,
#include "mimemap/defaults.c.h"
#undef MIMEMAP
            NULL};
        const char **p;
        for (p = default_types; *p != NULL; p += 2)
            h2o_mimemap_set_type(mimemap, p[0], h2o_mimemap_create_extension_type(p[1]), 0);
    }

    return mimemap;
}

h2o_mimemap_t *h2o_mimemap_clone(h2o_mimemap_t *src)
{
    h2o_mimemap_t *dst = h2o_mem_alloc_shared(NULL, sizeof(*dst), on_dispose);
    const char *ext;
    h2o_mimemap_type_t *type;

    dst->table = kh_init(exttable);
    kh_foreach(src->table, ext, type, {
        int r;
        khiter_t iter = kh_put(exttable, dst->table, ext, &r);
        kh_val(dst->table, iter) = type;
        h2o_mem_addref_shared((char *)ext);
        h2o_mem_addref_shared(type);
        on_link(dst, type);
    });
    dst->default_type = src->default_type;
    h2o_mem_addref_shared(dst->default_type);
    on_link(dst, dst->default_type);

    return dst;
}

void h2o_mimemap_on_context_init(h2o_mimemap_t *mimemap, h2o_context_t *ctx)
{
    const char *ext;
    h2o_mimemap_type_t *type;

    kh_foreach(mimemap->table, ext, type, {
        switch (type->type) {
        case H2O_MIMEMAP_TYPE_DYNAMIC:
            if (!type->data.dynamic._context_inited) {
                type->data.dynamic._context_inited = 1;
                h2o_context_init_pathconf_context(ctx, &type->data.dynamic.pathconf);
            }
            break;
        case H2O_MIMEMAP_TYPE_MIMETYPE:
            break;
        }
    });
}

void h2o_mimemap_on_context_dispose(h2o_mimemap_t *mimemap, h2o_context_t *ctx)
{
    const char *ext;
    h2o_mimemap_type_t *type;

    kh_foreach(mimemap->table, ext, type, {
        switch (type->type) {
        case H2O_MIMEMAP_TYPE_DYNAMIC:
            if (!type->data.dynamic._context_disposed) {
                type->data.dynamic._context_disposed = 1;
                h2o_context_dispose_pathconf_context(ctx, &type->data.dynamic.pathconf);
            }
            break;
        case H2O_MIMEMAP_TYPE_MIMETYPE:
            break;
        }
    });
}

int h2o_mimemap_has_dynamic_type(h2o_mimemap_t *mimemap)
{
    return mimemap->num_dynamic != 0;
}

void h2o_mimemap_set_default_type(h2o_mimemap_t *mimemap, h2o_mimemap_type_t *type, int incref)
{
    on_unlink(mimemap, mimemap->default_type);
    h2o_mem_release_shared(mimemap->default_type);

    mimemap->default_type = type;
    on_link(mimemap, type);
    if (incref)
        h2o_mem_addref_shared(type);
}

void h2o_mimemap_set_type(h2o_mimemap_t *mimemap, const char *ext, h2o_mimemap_type_t *type, int incref)
{
    khiter_t iter = kh_get(exttable, mimemap->table, ext);
    if (iter != kh_end(mimemap->table)) {
        h2o_mimemap_type_t *oldtype = kh_val(mimemap->table, iter);
        on_unlink(mimemap, oldtype);
        h2o_mem_release_shared(oldtype);
    } else {
        int ret;
        iter = kh_put(exttable, mimemap->table, dupref(ext).base, &ret);
        assert(iter != kh_end(mimemap->table));
    }
    kh_val(mimemap->table, iter) = type;
    on_link(mimemap, type);
    if (incref)
        h2o_mem_addref_shared(type);
}

void h2o_mimemap_remove_type(h2o_mimemap_t *mimemap, const char *ext)
{
    khiter_t iter = kh_get(exttable, mimemap->table, ext);
    if (iter != kh_end(mimemap->table)) {
        const char *key = kh_key(mimemap->table, iter);
        h2o_mimemap_type_t *type = kh_val(mimemap->table, iter);
        on_unlink(mimemap, type);
        h2o_mem_release_shared(type);
        kh_del(exttable, mimemap->table, iter);
        h2o_mem_release_shared((char *)key);
    }
}

h2o_mimemap_type_t *h2o_mimemap_get_default_type(h2o_mimemap_t *mimemap)
{
    return mimemap->default_type;
}

h2o_mimemap_type_t *h2o_mimemap_get_type(h2o_mimemap_t *mimemap, const char *ext)
{
    if (ext != NULL) {
        khiter_t iter = kh_get(exttable, mimemap->table, ext);
        if (iter != kh_end(mimemap->table))
            return kh_val(mimemap->table, iter);
    }
    return mimemap->default_type;
}
