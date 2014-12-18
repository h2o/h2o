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
#include "../test.h"
#include "../../../lib/mimemap.c"

void test_lib__mimemap_c()
{
    h2o_mimemap_t *mimemap = h2o_mimemap_create(), *mimemap2;

    /* default and set default */
    ok(strcmp(h2o_mimemap_get_default_type(mimemap).base, "application/octet-stream") == 0);
    {
        char buf[sizeof("text/plain")];
        strcpy(buf, "text/plain");
        h2o_mimemap_set_default_type(mimemap, buf);
        memset(buf, 0, sizeof(buf));
    }
    ok(strcmp(h2o_mimemap_get_default_type(mimemap).base, "text/plain") == 0);

    /* set and overwrite */
    h2o_mimemap_set_type(mimemap, "foo", "example/foo");
    ok(strcmp(h2o_mimemap_get_type(mimemap, "foo").base, "example/foo") == 0);
    h2o_mimemap_set_type(mimemap, "foo", "example/overwritten");
    ok(strcmp(h2o_mimemap_get_type(mimemap, "foo").base, "example/overwritten") == 0);

    /* clone and release */
    mimemap2 = h2o_mimemap_clone(mimemap);
    ok(strcmp(h2o_mimemap_get_default_type(mimemap2).base, "text/plain") == 0);
    ok(strcmp(h2o_mimemap_get_type(mimemap2, "foo").base, "example/overwritten") == 0);
    h2o_mem_release_shared(mimemap2);

    /* check original */
    ok(strcmp(h2o_mimemap_get_default_type(mimemap).base, "text/plain") == 0);
    ok(strcmp(h2o_mimemap_get_type(mimemap, "foo").base, "example/overwritten") == 0);

    /* remove */
    h2o_mimemap_remove_type(mimemap, "foo");
    ok(strcmp(h2o_mimemap_get_type(mimemap, "foo").base, "text/plain") == 0);
    h2o_mimemap_remove_type(mimemap, "foo");
    ok(strcmp(h2o_mimemap_get_type(mimemap, "foo").base, "text/plain") == 0);

    h2o_mem_release_shared(mimemap);
}
