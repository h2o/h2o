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
#include <assert.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <string.h>
#include "h2o/socket.h"

void h2o_session_store_init_integrity(h2o_session_store_integrity_t *ctx, h2o_iovec_t secret)
{
    SHA256((const unsigned char *)secret.base, secret.len, ctx->key);
    ctx->configured = 1;
}

h2o_iovec_t h2o_session_store_seal(h2o_session_store_integrity_t *ctx, h2o_iovec_t payload)
{
    h2o_iovec_t sealed;
    unsigned maclen = 0;

    if (!ctx->configured)
        return h2o_iovec_init(NULL, 0);

    sealed.base = h2o_mem_alloc(1 + H2O_SESSION_STORE_MAC_SIZE + payload.len);
    sealed.base[0] = 1; /* the version of the envelope */
    HMAC(EVP_sha256(), ctx->key, H2O_SESSION_STORE_MAC_SIZE, (const unsigned char *)payload.base, payload.len,
         (unsigned char *)sealed.base + 1, &maclen);
    assert(maclen == H2O_SESSION_STORE_MAC_SIZE);
    memcpy(sealed.base + 1 + H2O_SESSION_STORE_MAC_SIZE, payload.base, payload.len);
    sealed.len = 1 + H2O_SESSION_STORE_MAC_SIZE + payload.len;
    return sealed;
}

h2o_iovec_t h2o_session_store_unseal(h2o_session_store_integrity_t *ctx, h2o_iovec_t sealed)
{
    unsigned char mac[H2O_SESSION_STORE_MAC_SIZE];
    unsigned maclen = 0;

    /* an instance that does not hold the key refuses the values of the store; a value that is written without a seal is refused by
     * the instances that hold it, so that the store of a fleet that is configured halfway yields nothing rather than the keys of
     * whoever wrote last */
    if (!ctx->configured)
        return h2o_iovec_init(NULL, 0);
    if (sealed.len < 1 + H2O_SESSION_STORE_MAC_SIZE || sealed.base[0] != 1)
        return h2o_iovec_init(NULL, 0);
    HMAC(EVP_sha256(), ctx->key, H2O_SESSION_STORE_MAC_SIZE, (const unsigned char *)sealed.base + 1 + H2O_SESSION_STORE_MAC_SIZE,
         sealed.len - (1 + H2O_SESSION_STORE_MAC_SIZE), mac, &maclen);
    assert(maclen == H2O_SESSION_STORE_MAC_SIZE);
    if (CRYPTO_memcmp(mac, sealed.base + 1, H2O_SESSION_STORE_MAC_SIZE) != 0)
        return h2o_iovec_init(NULL, 0);
    return h2o_iovec_init(sealed.base + 1 + H2O_SESSION_STORE_MAC_SIZE, sealed.len - (1 + H2O_SESSION_STORE_MAC_SIZE));
}
