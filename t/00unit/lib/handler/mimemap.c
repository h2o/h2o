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
#include "../../test.h"
#include "../../../../lib/handler/mimemap.c"

static int is_mimetype(h2o_mimemap_type_t *type, const char *expected)
{
    return type->type == H2O_MIMEMAP_TYPE_MIMETYPE && type->data.mimetype.len == strlen(expected) &&
           memcmp(type->data.mimetype.base, expected, type->data.mimetype.len) == 0;
}

void test_lib__handler__mimemap_c()
{
    h2o_mimemap_t *mimemap = h2o_mimemap_create(), *mimemap2;

    /* default and set default */
    ok(is_mimetype(h2o_mimemap_get_default_type(mimemap), "application/octet-stream"));
    {
        char buf[sizeof("text/plain")];
        strcpy(buf, "text/plain");
        h2o_mimemap_set_default_type(mimemap, buf);
        memset(buf, 0, sizeof(buf));
    }
    ok(is_mimetype(h2o_mimemap_get_default_type(mimemap), "text/plain"));

    /* set and overwrite */
    h2o_mimemap_define_mimetype(mimemap, "foo", "example/foo");
    ok(is_mimetype(h2o_mimemap_get_type_by_extension(mimemap, "foo"), "example/foo"));
    ok(h2o_mimemap_get_type_by_extension(mimemap, "foo") ==
       h2o_mimemap_get_type_by_mimetype(mimemap, h2o_iovec_init(H2O_STRLIT("example/foo"))));
    h2o_mimemap_define_mimetype(mimemap, "foo", "example/overwritten");
    ok(is_mimetype(h2o_mimemap_get_type_by_extension(mimemap, "foo"), "example/overwritten"));
    ok(h2o_mimemap_get_type_by_extension(mimemap, "foo") ==
       h2o_mimemap_get_type_by_mimetype(mimemap, h2o_iovec_init(H2O_STRLIT("example/overwritten"))));
    ok(h2o_mimemap_get_type_by_mimetype(mimemap, h2o_iovec_init(H2O_STRLIT("example/foo"))) == NULL);

    /* clone and release */
    mimemap2 = h2o_mimemap_clone(mimemap);
    ok(is_mimetype(h2o_mimemap_get_default_type(mimemap2), "text/plain"));
    ok(is_mimetype(h2o_mimemap_get_type_by_extension(mimemap2, "foo"), "example/overwritten"));
    ok(h2o_mimemap_get_type_by_extension(mimemap, "foo") ==
       h2o_mimemap_get_type_by_mimetype(mimemap, h2o_iovec_init(H2O_STRLIT("example/overwritten"))));
    h2o_mem_release_shared(mimemap2);

    /* check original */
    ok(is_mimetype(h2o_mimemap_get_default_type(mimemap), "text/plain"));
    ok(is_mimetype(h2o_mimemap_get_type_by_extension(mimemap, "foo"), "example/overwritten"));

    /* remove */
    h2o_mimemap_remove_type(mimemap, "foo");
    ok(is_mimetype(h2o_mimemap_get_type_by_extension(mimemap, "foo"), "text/plain"));
    ok(h2o_mimemap_get_type_by_mimetype(mimemap, h2o_iovec_init(H2O_STRLIT("example/overwritten"))) == NULL);
    h2o_mimemap_remove_type(mimemap, "foo");
    ok(is_mimetype(h2o_mimemap_get_type_by_extension(mimemap, "foo"), "text/plain"));

    h2o_mem_release_shared(mimemap);
}
