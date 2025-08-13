/*
 * Copyright (c) 2024
 *
 * Test for issue #3483: NULL byte (%00) in path causing infinite 301 redirects
 * instead of 400 Bad Request
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

void test_null_byte_path_rejection(void)
{
    h2o_globalconf_t globalconf;
    h2o_hostconf_t *hostconf;
    h2o_pathconf_t *pathconf;
    h2o_context_t ctx;
    h2o_loopback_conn_t *conn;

    h2o_config_init(&globalconf);
    hostconf = h2o_config_register_host(&globalconf, h2o_iovec_init(H2O_STRLIT("default")), 65535);
    pathconf = h2o_config_register_path(hostconf, "/", 0);
    h2o_file_register(pathconf, "/tmp", NULL, NULL, 0);

    h2o_context_init(&ctx, test_loop, &globalconf);

    /* Test case: path with %00 should result in 400 Bad Request */
    conn = h2o_loopback_create(&ctx, ctx.globalconf->hosts);
    conn->req.input.method = h2o_iovec_init(H2O_STRLIT("GET"));
    conn->req.input.path = h2o_iovec_init(H2O_STRLIT("/test%00/file"));
    h2o_loopback_run_loop(conn);
    
    /* Verify that the response is 400 Bad Request, not 301 redirect */
    ok(conn->req.res.status == 400);
    ok(h2o_memis(conn->req.res.reason, strlen(conn->req.res.reason), H2O_STRLIT("Bad Request")));
    
    h2o_loopback_destroy(conn);

    /* Test case: normal path should work fine */
    conn = h2o_loopback_create(&ctx, ctx.globalconf->hosts);
    conn->req.input.method = h2o_iovec_init(H2O_STRLIT("GET"));
    conn->req.input.path = h2o_iovec_init(H2O_STRLIT("/test/file"));
    h2o_loopback_run_loop(conn);
    
    /* Verify that normal paths don't get 400 errors (should get 404 or other, but not 400) */
    ok(conn->req.res.status != 400);
    
    h2o_loopback_destroy(conn);

    h2o_context_dispose(&ctx);
    h2o_config_dispose(&globalconf);
}
