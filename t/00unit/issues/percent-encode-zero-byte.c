/*
 * Copyright (c) 2016 DeNA Co., Fastly, Inc.
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

#include <inttypes.h>
#include <stdio.h>
#include "../test.h"

void test_percent_encode_zero_byte(void)
{
    h2o_pathconf_t pathconf = {NULL, {H2O_STRLIT("/abc")}};
    h2o_req_t req;
    h2o_iovec_t dest;

    h2o_init_request(&req, NULL, NULL);

    /* basic pattern */
    req.path_normalized = h2o_iovec_init(H2O_STRLIT("/abc/mno\0xyz"));
    req.query_at = req.path_normalized.len;
    req.path = h2o_concat(&req.pool, req.path_normalized, h2o_iovec_init(H2O_STRLIT("?q")));
    req.pathconf = &pathconf;
    dest = h2o_build_destination(&req, H2O_STRLIT("/def"), 1);
    ok(h2o_memis(dest.base, dest.len, H2O_STRLIT("/def/mno%00xyz?q")));
    dest = h2o_build_destination(&req, H2O_STRLIT("/def/"), 1);
    ok(h2o_memis(dest.base, dest.len, H2O_STRLIT("/def/mno%00xyz?q")));

    h2o_mem_clear_pool(&req.pool);
}
