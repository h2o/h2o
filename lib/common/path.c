/*
 * Copyright (c) 2017 DeNA Co., Ltd., Ichito Nagata
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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "h2o/path_.h"
#include "h2o/string_.h"
#include "h2o/version.h"

const char *h2o_get_root(void)
{
    const char *root = getenv("H2O_ROOT");
    if (root == NULL)
        root = H2O_TO_STR(H2O_ROOT);
    return root;
}

char *h2o_get_absolute_path(h2o_mem_pool_t *pool, const char *path)
{
    /* just return the cmd (being strdup'ed) in case we do not need to prefix the value */
    if (path[0] == '/')
        goto ReturnOrig;

    /* build full-path and return */
    const char *root = h2o_get_root();
    size_t len = strlen(root) + strlen(path) + 2;
    char *abspath;
    if (pool != NULL) {
        abspath = (char *)h2o_mem_alloc_pool(pool, len);
    } else {
        abspath = (char *)h2o_mem_alloc(len);
    }
    sprintf(abspath, "%s/%s", root, path);
    return abspath;

ReturnOrig:
    return h2o_strdup(NULL, path, SIZE_MAX).base;
}

char *h2o_get_shared_path(h2o_mem_pool_t *pool, const char *path)
{
    const char *share_dir = getenv("H2O_SHARE_DIR");
    if (share_dir == NULL)
        share_dir = "share/h2o/" H2O_VERSION;

    char *relative = (char *)h2o_mem_alloc(strlen(share_dir) + strlen(path) + 2);
    sprintf(relative, "%s/%s", share_dir, path);
    char *fullpath = h2o_get_absolute_path(pool, relative);
    free(relative);
    return fullpath;
}
