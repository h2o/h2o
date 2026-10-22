/*
 * Copyright (c) 2026 Leodmanx2
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
#include "../../../../lib/common/session-store.c"

static void test_seal_unseal(void)
{
    h2o_session_store_integrity_t ctx, other;
    h2o_iovec_t payload = h2o_iovec_init(H2O_STRLIT("a value of the session store"));
    h2o_iovec_t sealed, unsealed;

    h2o_session_store_init_integrity(&ctx, h2o_iovec_init(H2O_STRLIT("the secret")));
    sealed = h2o_session_store_seal(&ctx, payload);
    ok(sealed.len == 1 + H2O_SESSION_STORE_MAC_SIZE + payload.len);

    /* the value opens with the key that it was sealed with */
    unsealed = h2o_session_store_unseal(&ctx, sealed);
    ok(h2o_memis(unsealed.base, unsealed.len, payload.base, payload.len));

    /* the value does not open with another key */
    h2o_session_store_init_integrity(&other, h2o_iovec_init(H2O_STRLIT("another secret")));
    unsealed = h2o_session_store_unseal(&other, sealed);
    ok(unsealed.base == NULL);

    /* a value that carries no seal does not open */
    unsealed = h2o_session_store_unseal(&ctx, payload);
    ok(unsealed.base == NULL);

    /* a value that is truncated does not open */
    unsealed = h2o_session_store_unseal(&ctx, h2o_iovec_init(sealed.base, 10));
    ok(unsealed.base == NULL);

    /* a bit flipped anywhere in the envelope makes the value unusable */
    sealed.base[5] ^= 1;
    unsealed = h2o_session_store_unseal(&ctx, sealed);
    ok(unsealed.base == NULL);
    sealed.base[5] ^= 1;
    sealed.base[H2O_SESSION_STORE_MAC_SIZE + 2] ^= 1;
    unsealed = h2o_session_store_unseal(&ctx, sealed);
    ok(unsealed.base == NULL);
    sealed.base[H2O_SESSION_STORE_MAC_SIZE + 2] ^= 1;
    unsealed = h2o_session_store_unseal(&ctx, sealed);
    ok(h2o_memis(unsealed.base, unsealed.len, payload.base, payload.len));

    free(sealed.base);
}

void test_lib__common__session_store_c(void)
{
    subtest("seal-unseal", test_seal_unseal);
}
