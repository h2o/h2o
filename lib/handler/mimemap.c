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
#include <stdlib.h>
#include <string.h>
#include "khash.h"
#include "h2o.h"

KHASH_MAP_INIT_STR(extmap, h2o_mimemap_type_t *)

static inline khint_t hash_mimemap_type(h2o_mimemap_type_t *mimetype)
{
    khint_t h = 0;
    size_t i;
    for (i = 0; i != mimetype->data.mimetype.len; ++i)
        h = (h << 5) - h + (khint_t)mimetype->data.mimetype.base[i];
    return h;
}

static inline int mimemap_type_equals(h2o_mimemap_type_t *x, h2o_mimemap_type_t *y)
{
    return h2o_memis(x->data.mimetype.base, x->data.mimetype.len, y->data.mimetype.base, y->data.mimetype.len);
}

KHASH_INIT(typeset, h2o_mimemap_type_t *, char, 0, hash_mimemap_type, mimemap_type_equals)

h2o_mime_attributes_t h2o_mime_attributes_as_is;

struct st_h2o_mimemap_t {
    khash_t(extmap) * extmap;
    khash_t(typeset) * typeset; /* refs point to the entries in extmap */
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

    kh_destroy(typeset, mimemap->typeset);
    kh_foreach(mimemap->extmap, ext, type, {
        h2o_mem_release_shared((char *)ext);
        h2o_mem_release_shared(type);
    });
    kh_destroy(extmap, mimemap->extmap);
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

static void rebuild_typeset(h2o_mimemap_t *mimemap)
{
    kh_clear(typeset, mimemap->typeset);

    const char *ext;
    h2o_mimemap_type_t *mime;
    kh_foreach(mimemap->extmap, ext, mime, {
        if (mime->type == H2O_MIMEMAP_TYPE_MIMETYPE) {
            khiter_t iter = kh_get(typeset, mimemap->typeset, mime);
            if (iter == kh_end(mimemap->typeset)) {
                int r;
                kh_put(typeset, mimemap->typeset, mime, &r);
            }
        }
    });
}

static h2o_mimemap_type_t *create_extension_type(const char *mime, h2o_mime_attributes_t *attr)
{
    h2o_mimemap_type_t *type = h2o_mem_alloc_shared(NULL, sizeof(*type) + strlen(mime) + 1, NULL);
    size_t i;

    memset(type, 0, sizeof(*type));

    type->type = H2O_MIMEMAP_TYPE_MIMETYPE;

    /* normalize-copy type->data.mimetype */
    type->data.mimetype.base = (char *)type + sizeof(*type);
    for (i = 0; mime[i] != '\0' && mime[i] != ';'; ++i)
        type->data.mimetype.base[i] = h2o_tolower(mime[i]);
    for (; mime[i] != '\0'; ++i)
        type->data.mimetype.base[i] = mime[i];
    type->data.mimetype.base[i] = '\0';
    type->data.mimetype.len = i;

    if (attr != NULL) {
        type->data.attr = *attr;
    } else {
        h2o_mimemap_get_default_attributes(mime, &type->data.attr);
    }

    return type;
}

static void dispose_dynamic_type(h2o_mimemap_type_t *type)
{
    h2o_config_dispose_pathconf(&type->data.dynamic.pathconf);
}

static h2o_mimemap_type_t *create_dynamic_type(h2o_globalconf_t *globalconf, h2o_mimemap_t *mimemap)
{
    h2o_mimemap_type_t *type = h2o_mem_alloc_shared(NULL, sizeof(*type), (void (*)(void *))dispose_dynamic_type);

    type->type = H2O_MIMEMAP_TYPE_DYNAMIC;
    memset(&type->data.dynamic, 0, sizeof(type->data.dynamic));
    h2o_config_init_pathconf(&type->data.dynamic.pathconf, globalconf, NULL, mimemap);

    return type;
}

h2o_mimemap_t *h2o_mimemap_create()
{
    h2o_mimemap_t *mimemap = h2o_mem_alloc_shared(NULL, sizeof(*mimemap), on_dispose);

    mimemap->extmap = kh_init(extmap);
    mimemap->typeset = kh_init(typeset);
    mimemap->default_type = create_extension_type("application/octet-stream", NULL);
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
            h2o_mimemap_define_mimetype(mimemap, p[0], p[1], NULL);
    }
    rebuild_typeset(mimemap);

    return mimemap;
}

h2o_mimemap_t *h2o_mimemap_clone(h2o_mimemap_t *src)
{
    h2o_mimemap_t *dst = h2o_mem_alloc_shared(NULL, sizeof(*dst), on_dispose);
    const char *ext;
    h2o_mimemap_type_t *type;

    dst->extmap = kh_init(extmap);
    dst->typeset = kh_init(typeset);
    kh_foreach(src->extmap, ext, type, {
        int r;
        khiter_t iter = kh_put(extmap, dst->extmap, ext, &r);
        kh_val(dst->extmap, iter) = type;
        h2o_mem_addref_shared((char *)ext);
        h2o_mem_addref_shared(type);
        on_link(dst, type);
    });
    dst->default_type = src->default_type;
    h2o_mem_addref_shared(dst->default_type);
    on_link(dst, dst->default_type);
    rebuild_typeset(dst);

    return dst;
}

void h2o_mimemap_on_context_init(h2o_mimemap_t *mimemap, h2o_context_t *ctx)
{
    const char *ext;
    h2o_mimemap_type_t *type;

    kh_foreach(mimemap->extmap, ext, type, {
        switch (type->type) {
        case H2O_MIMEMAP_TYPE_DYNAMIC:
            h2o_context_init_pathconf_context(ctx, &type->data.dynamic.pathconf);
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

    kh_foreach(mimemap->extmap, ext, type, {
        switch (type->type) {
        case H2O_MIMEMAP_TYPE_DYNAMIC:
            h2o_context_dispose_pathconf_context(ctx, &type->data.dynamic.pathconf);
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

void h2o_mimemap_set_default_type(h2o_mimemap_t *mimemap, const char *mime, h2o_mime_attributes_t *attr)
{
    h2o_mimemap_type_t *new_type;

    /* obtain or create new type */
    if ((new_type = h2o_mimemap_get_type_by_mimetype(mimemap, h2o_iovec_init(mime, strlen(mime)), 1)) != NULL &&
        (attr == NULL || memcmp(&new_type->data.attr, attr, sizeof(*attr)) == 0)) {
        h2o_mem_addref_shared(new_type);
    } else {
        new_type = create_extension_type(mime, attr);
    }

    /* unlink the old one */
    on_unlink(mimemap, mimemap->default_type);
    h2o_mem_release_shared(mimemap->default_type);

    /* update */
    mimemap->default_type = new_type;
    on_link(mimemap, new_type);
    rebuild_typeset(mimemap);
}

static void set_type(h2o_mimemap_t *mimemap, const char *ext, h2o_mimemap_type_t *type)
{
    /* obtain key, and remove the old value */
    khiter_t iter = kh_get(extmap, mimemap->extmap, ext);
    if (iter != kh_end(mimemap->extmap)) {
        h2o_mimemap_type_t *oldtype = kh_val(mimemap->extmap, iter);
        on_unlink(mimemap, oldtype);
        h2o_mem_release_shared(oldtype);
    } else {
        int ret;
        iter = kh_put(extmap, mimemap->extmap, dupref(ext).base, &ret);
        assert(iter != kh_end(mimemap->extmap));
    }

    /* update */
    h2o_mem_addref_shared(type);
    kh_val(mimemap->extmap, iter) = type;
    on_link(mimemap, type);
    rebuild_typeset(mimemap);
}

void h2o_mimemap_define_mimetype(h2o_mimemap_t *mimemap, const char *ext, const char *mime, h2o_mime_attributes_t *attr)
{
    h2o_mimemap_type_t *new_type;

    if ((new_type = h2o_mimemap_get_type_by_mimetype(mimemap, h2o_iovec_init(mime, strlen(mime)), 1)) != NULL &&
        (attr == NULL || memcmp(&new_type->data.attr, attr, sizeof(*attr)) == 0)) {
        h2o_mem_addref_shared(new_type);
    } else {
        new_type = create_extension_type(mime, attr);
    }
    set_type(mimemap, ext, new_type);
    h2o_mem_release_shared(new_type);
}

h2o_mimemap_type_t *h2o_mimemap_define_dynamic(h2o_mimemap_t *mimemap, const char **exts, h2o_globalconf_t *globalconf)
{
    /* FIXME: fix memory leak introduced by this a cyclic link (mimemap -> new_type -> mimemap)
     * note also that we may want to update the reference from the dynamic type to the mimemap as we clone the mimemap,
     * but doing so naively would cause unnecessary copies of fastcgi.spawns... */
    h2o_mimemap_type_t *new_type = create_dynamic_type(globalconf, mimemap);
    size_t i;

    for (i = 0; exts[i] != NULL; ++i)
        set_type(mimemap, exts[i], new_type);
    h2o_mem_release_shared(new_type);
    return new_type;
}

void h2o_mimemap_remove_type(h2o_mimemap_t *mimemap, const char *ext)
{
    khiter_t iter = kh_get(extmap, mimemap->extmap, ext);
    if (iter != kh_end(mimemap->extmap)) {
        const char *key = kh_key(mimemap->extmap, iter);
        h2o_mimemap_type_t *type = kh_val(mimemap->extmap, iter);
        on_unlink(mimemap, type);
        h2o_mem_release_shared(type);
        kh_del(extmap, mimemap->extmap, iter);
        h2o_mem_release_shared((char *)key);
        rebuild_typeset(mimemap);
    }
}

h2o_mimemap_type_t *h2o_mimemap_get_default_type(h2o_mimemap_t *mimemap)
{
    return mimemap->default_type;
}

h2o_mimemap_type_t *h2o_mimemap_get_type_by_extension(h2o_mimemap_t *mimemap, h2o_iovec_t ext)
{
    char lcbuf[256];

    if (0 < ext.len && ext.len < sizeof(lcbuf)) {
        memcpy(lcbuf, ext.base, ext.len);
        h2o_strtolower(lcbuf, ext.len);
        lcbuf[ext.len] = '\0';
        khiter_t iter = kh_get(extmap, mimemap->extmap, lcbuf);
        if (iter != kh_end(mimemap->extmap))
            return kh_val(mimemap->extmap, iter);
    }
    return mimemap->default_type;
}

h2o_mimemap_type_t *h2o_mimemap_get_type_by_mimetype(h2o_mimemap_t *mimemap, h2o_iovec_t mime, int exact_match_only)
{
    h2o_mimemap_type_t key = {H2O_MIMEMAP_TYPE_MIMETYPE};
    khiter_t iter;
    size_t type_end_at;

    /* exact match */
    key.data.mimetype = mime;
    if ((iter = kh_get(typeset, mimemap->typeset, &key)) != kh_end(mimemap->typeset))
        return kh_key(mimemap->typeset, iter);

    if (!exact_match_only) {
        /* determine the end of the type */
        for (type_end_at = 0; type_end_at != mime.len; ++type_end_at)
            if (mime.base[type_end_at] == ';' || mime.base[type_end_at] == ' ')
                goto HasAttributes;
    }
    return NULL;

HasAttributes:
    /* perform search without attributes */
    key.data.mimetype.len = type_end_at;
    if ((iter = kh_get(typeset, mimemap->typeset, &key)) != kh_end(mimemap->typeset))
        return kh_key(mimemap->typeset, iter);

    return NULL;
}

void h2o_mimemap_get_default_attributes(const char *_mime, h2o_mime_attributes_t *attr)
{
    char *mime = alloca(strlen(_mime) + 1);
    strcpy(mime, _mime);

    const char *type_end_at;

    if ((type_end_at = strchr(mime, ';')) == NULL)
        type_end_at = mime + strlen(mime);

    *attr = (h2o_mime_attributes_t){0};

    if (h2o_memis(mime, type_end_at - mime, H2O_STRLIT("text/css")) ||
        h2o_memis(mime, type_end_at - mime, H2O_STRLIT("application/ecmascript")) ||
        h2o_memis(mime, type_end_at - mime, H2O_STRLIT("application/javascript")) ||
        h2o_memis(mime, type_end_at - mime, H2O_STRLIT("text/ecmascript")) ||
        h2o_memis(mime, type_end_at - mime, H2O_STRLIT("text/javascript"))) {
        attr->is_compressible = 1;
        attr->priority = H2O_MIME_ATTRIBUTE_PRIORITY_HIGHEST;
    } else if (h2o_memis(mime, type_end_at - mime, H2O_STRLIT("application/json")) || strncmp(mime, "text/", 5) == 0 ||
               h2o_strstr(mime, type_end_at - mime, H2O_STRLIT("+xml")) != SIZE_MAX) {
        attr->is_compressible = 1;
    }
}
