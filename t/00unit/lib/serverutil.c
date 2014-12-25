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
#include <stdlib.h>
#include "../test.h"
#include "../../../lib/serverutil.c"

void test_lib__serverutil_c(void)
{
    int *fds;
    size_t num_fds;

    unsetenv("SERVER_STARTER_PORT");
    num_fds = h2o_server_starter_get_fds(&fds);
    ok(num_fds == 0);

    setenv("SERVER_STARTER_PORT", "0.0.0.0:80=3", 1);
    num_fds = h2o_server_starter_get_fds(&fds);
    ok(num_fds == 1);
    ok(fds[0] == 3);

    setenv("SERVER_STARTER_PORT", "0.0.0.0:80=3;/tmp/foo.sock=4", 1);
    num_fds = h2o_server_starter_get_fds(&fds);
    ok(num_fds == 2);
    ok(fds[0] == 3);
    ok(fds[1] == 4);

    setenv("SERVER_STARTER_PORT", "0.0.0.0:80=foo", 1);
    num_fds = h2o_server_starter_get_fds(&fds);
    ok(num_fds == -1);

    /* without bind address */
    setenv("SERVER_STARTER_PORT", "50908=4", 1);
    num_fds = h2o_server_starter_get_fds(&fds);
    ok(num_fds == 1);
    ok(fds[0] == 4);
}
