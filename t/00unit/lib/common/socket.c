/*
 * Copyright (c) 2015 DeNA Co., Ltd.
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
#include "../../test.h"
#include "../../../../lib/common/socket.c"

static void test_on_alpn_select(void)
{
    static const h2o_iovec_t protocols[] = {{H2O_STRLIT("h2")}, {H2O_STRLIT("h2-16")}, {H2O_STRLIT("h2-14")}, {}};
    const unsigned char *out;
    unsigned char outlen;
    int ret;

    ret = on_alpn_select(NULL, &out, &outlen, (const unsigned char *)H2O_STRLIT("\3foo"), (void *)protocols);
    ok(ret == SSL_TLSEXT_ERR_NOACK);

    ret = on_alpn_select(NULL, &out, &outlen, (const unsigned char *)H2O_STRLIT("\2h2"), (void *)protocols);
    ok(ret == SSL_TLSEXT_ERR_OK);
    ok(h2o_memis(out, outlen, H2O_STRLIT("h2")));

    ret = on_alpn_select(NULL, &out, &outlen, (const unsigned char *)H2O_STRLIT("\5h2-14\5h2-16\2h2"), (void *)protocols);
    ok(ret == SSL_TLSEXT_ERR_OK);
    ok(h2o_memis(out, outlen, H2O_STRLIT("h2")));

    ret = on_alpn_select(NULL, &out, &outlen, (const unsigned char *)H2O_STRLIT("\5h2-14\5h2-16"), (void *)protocols);
    ok(ret == SSL_TLSEXT_ERR_OK);
    ok(h2o_memis(out, outlen, H2O_STRLIT("h2-16")));
}

void test_lib__common__socket_c(void)
{
    subtest("on_alpn_select", test_on_alpn_select);
}
