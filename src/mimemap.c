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

KHASH_MAP_INIT_STR(exttable, h2o_buf_t)

struct st_h2o_mimemap_entry_t {
    /* struct st_h2o_mimemap_entry_t *next; */
    khash_t(exttable) *table;
};

void h2o_init_mimemap(h2o_mimemap_t *mimemap, const char *default_type)
{
    mimemap->top = h2o_malloc(sizeof(*mimemap->top));
    mimemap->top->table = kh_init(exttable);
    mimemap->default_type = h2o_strdup(NULL, default_type, SIZE_MAX);
}

void h2o_dispose_mimemap(h2o_mimemap_t *mimemap)
{
    const char *ext;
    h2o_buf_t type;

    kh_foreach(mimemap->top->table, ext, type, {
        free((char*)ext);
        free(type.base);
    });
    kh_destroy(exttable, mimemap->top->table);
    free(mimemap->top);
    free(mimemap->default_type.base);
}

void h2o_define_mimetype(h2o_mimemap_t *mimemap, const char *ext, const char *type)
{
    khiter_t iter;

    iter = kh_get(exttable, mimemap->top->table, ext);
    if (iter != kh_end(mimemap->top->table)) {
        free(kh_val(mimemap->top->table, iter).base);
    } else {
        int ret;
        iter = kh_put(exttable, mimemap->top->table, ext, &ret);
        assert(iter != kh_end(mimemap->top->table));
    }
    kh_val(mimemap->top->table, iter) = h2o_strdup(NULL, type, SIZE_MAX);
}

h2o_buf_t h2o_get_mimetype(h2o_mimemap_t *mimemap, const char *ext)
{
    if (ext != NULL) {
        khiter_t iter = kh_get(exttable, mimemap->top->table, ext);
        if (iter != kh_end(mimemap->top->table))
            return kh_val(mimemap->top->table, iter);
    }
    return mimemap->default_type;
}
