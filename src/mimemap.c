#include <assert.h>
#include "khash.h"
#include "h2o.h"

KHASH_MAP_INIT_STR(exttable, uv_buf_t)

struct st_h2o_mimemap_entry_t {
    /* struct st_h2o_mimemap_entry_t *next; */
    khash_t(exttable) *table;
};

void h2o_init_mimemap(h2o_mimemap_t *mimemap, const char *default_type)
{
    mimemap->top = malloc(sizeof(struct st_h2o_mimemap_entry_t));
    if (mimemap->top == NULL)
        h2o_fatal("no memory");
    mimemap->top->table = kh_init(exttable);
    mimemap->default_type = h2o_strdup(NULL, default_type, SIZE_MAX);
}

void h2o_dispose_mimemap(h2o_mimemap_t *mimemap)
{
    const char *ext;
    uv_buf_t type;

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

uv_buf_t h2o_get_mimetype(h2o_mimemap_t *mimemap, const char *ext)
{
    if (ext != NULL) {
        khiter_t iter = kh_get(exttable, mimemap->top->table, ext);
        if (iter != kh_end(mimemap->top->table))
            return kh_val(mimemap->top->table, iter);
    }
    return mimemap->default_type;
}
