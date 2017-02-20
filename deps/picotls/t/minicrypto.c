/*
 * Copyright (c) 2016 DeNA Co., Ltd., Kazuho Oku
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
#include <stdio.h>
#include <string.h>
#include "../deps/picotest/picotest.h"
#include "../lib/cifra.c"
#include "../lib/uecc.c"
#include "test.h"

static void test_secp256r1_key_exchange(void)
{
    test_key_exchange(&ptls_minicrypto_secp256r1);
}

static void test_x25519_key_exchange(void)
{
    test_key_exchange(&ptls_minicrypto_x25519);
}

static void test_secp256r1_sign(void)
{
    const char *msg = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef";
    ptls_minicrypto_secp256r1sha256_sign_certificate_t signer = {{secp256r1sha256_sign}};
    uint8_t pub[SECP256R1_PUBLIC_KEY_SIZE];
    uint16_t selected;
    ptls_buffer_t sigbuf;
    uint32_t sigbuf_small[128];

    uECC_make_key(pub, signer.key, uECC_secp256r1());
    ptls_buffer_init(&sigbuf, sigbuf_small, sizeof(sigbuf_small));

    ok(secp256r1sha256_sign(&signer.super, NULL, &selected, &sigbuf, ptls_iovec_init(msg, 32),
                            (uint16_t[]){PTLS_SIGNATURE_ECDSA_SECP256R1_SHA256}, 1) == 0);
    ok(selected == PTLS_SIGNATURE_ECDSA_SECP256R1_SHA256);

    /* FIXME verify sign */

    ptls_buffer_dispose(&sigbuf);
}

int main(int argc, char **argv)
{
    subtest("secp256r1", test_secp256r1_key_exchange);
    subtest("x25519", test_x25519_key_exchange);
    subtest("secp256r1-sign", test_secp256r1_sign);

    ptls_iovec_t cert = ptls_iovec_init(SECP256R1_CERTIFICATE, sizeof(SECP256R1_CERTIFICATE) - 1);

    ptls_minicrypto_secp256r1sha256_sign_certificate_t sign_certificate;
    ptls_minicrypto_init_secp256r1sha256_sign_certificate(&sign_certificate,
                                                          ptls_iovec_init(SECP256R1_PRIVATE_KEY, SECP256R1_PRIVATE_KEY_SIZE));

    ptls_context_t ctxbuf = {
        ptls_minicrypto_random_bytes, ptls_minicrypto_key_exchanges, ptls_minicrypto_cipher_suites, {&cert, 1}, NULL, NULL,
        &sign_certificate.super};
    ctx = ctx_peer = &ctxbuf;

    subtest("picotls", test_picotls);

    return done_testing();
    return done_testing();
}
