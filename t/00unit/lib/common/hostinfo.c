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
#include <arpa/inet.h>
#include "../../test.h"
#include "../../../../lib/common/hostinfo.c"

static void test_aton(void)
{
    struct in_addr addr;

    memset(&addr, 0x55, sizeof(addr));
    ok(h2o_hostinfo_aton((h2o_iovec_t){H2O_STRLIT("127.0.0.1")}, &addr) == 0);
    ok(ntohl(addr.s_addr) == 0x7f000001);

    memset(&addr, 0x55, sizeof(addr));
    ok(h2o_hostinfo_aton((h2o_iovec_t){"127.0.0.12", sizeof("127.0.0.1") - 1}, &addr) == 0);
    ok(ntohl(addr.s_addr) == 0x7f000001);

    memset(&addr, 0x55, sizeof(addr));
    ok(h2o_hostinfo_aton((h2o_iovec_t){H2O_STRLIT("255.001.002.128")}, &addr) == 0);
    ok(ntohl(addr.s_addr) == 0xff010280);

    ok(h2o_hostinfo_aton((h2o_iovec_t){H2O_STRLIT("127.0.0.z")}, &addr) != 0);
    ok(h2o_hostinfo_aton((h2o_iovec_t){H2O_STRLIT("256.0.0.0")}, &addr) != 0);
    ok(h2o_hostinfo_aton((h2o_iovec_t){H2O_STRLIT("0001.0.0.0")}, &addr) != 0);
    ok(h2o_hostinfo_aton((h2o_iovec_t){H2O_STRLIT("0.0..1")}, &addr) != 0);
    ok(h2o_hostinfo_aton((h2o_iovec_t){H2O_STRLIT("1.0.0.0.")}, &addr) != 0);
}

void test_lib__common__hostinfo_c(void)
{
    /* TODO add tests for h2o_hostinfo_getaddr and related */
    subtest("aton", test_aton);
}
