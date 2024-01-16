/*
 * Copyright (c) 2023, Christian Huitema
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

#ifdef _WINDOWS
#include "wincompat.h"
#endif

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <picotls.h>
#include "picotls/mbedtls.h"
#include "picotls/minicrypto.h"
#include "../deps/picotest/picotest.h"
#include "test.h"

static int random_trial()
{
    /* The random test is just trying to check that we call the API properly.
     * This is done by getting a vector of 1021 bytes, computing the sum of
     * all values, and comparing to theoretical min and max,
     * computed as average +- 8*standard deviation for sum of 1021 terms.
     * 8 random deviations results in an extremely low probability of random
     * failure.
     * Note that this does not actually test the random generator.
     */

    uint8_t buf[1021];
    uint64_t sum = 0;
    const uint64_t max_sum_1021 = 149505;
    const uint64_t min_sum_1021 = 110849;
    int ret = 0;

    ptls_mbedtls_random_bytes(buf, sizeof(buf));
    for (size_t i = 0; i < sizeof(buf); i++) {
        sum += buf[i];
    }
    if (sum > max_sum_1021 || sum < min_sum_1021) {
        ret = -1;
    }

    return ret;
}

static void test_random(void)
{
    if (random_trial() != 0) {
        ok(!"fail");
        return;
    }
    ok(!!"success");
}

static void test_secp256r1(void)
{
    test_key_exchange(&ptls_mbedtls_secp256r1, &ptls_minicrypto_secp256r1);
    test_key_exchange(&ptls_minicrypto_secp256r1, &ptls_mbedtls_secp256r1);
}

static void test_x25519(void)
{
    test_key_exchange(&ptls_mbedtls_x25519, &ptls_minicrypto_x25519);
    test_key_exchange(&ptls_minicrypto_x25519, &ptls_mbedtls_x25519);
}

static void test_key_exchanges(void)
{
    subtest("secp256r1", test_secp256r1);
    subtest("x25519", test_x25519);
}

DEFINE_FFX_AES128_ALGORITHMS(mbedtls);
DEFINE_FFX_CHACHA20_ALGORITHMS(mbedtls);

int main(int argc, char **argv)
{
    /* Initialize the PSA crypto library. */
    if (psa_crypto_init() != PSA_SUCCESS) {
        note("psa_crypto_init fails.");
        return done_testing();
    }

    /* Test of the port of the mbedtls random generator */
    subtest("random", test_random);
    subtest("key_exchanges", test_key_exchanges);

    ADD_FFX_AES128_ALGORITHMS(mbedtls);
    ADD_FFX_CHACHA20_ALGORITHMS(mbedtls);

    /* minicrypto contexts used as peer for valiation */
    ptls_iovec_t secp256r1_certificate = ptls_iovec_init(SECP256R1_CERTIFICATE, sizeof(SECP256R1_CERTIFICATE) - 1);
    ptls_minicrypto_secp256r1sha256_sign_certificate_t minicrypto_sign_certificate;
    ptls_minicrypto_init_secp256r1sha256_sign_certificate(
        &minicrypto_sign_certificate, ptls_iovec_init(SECP256R1_PRIVATE_KEY, sizeof(SECP256R1_PRIVATE_KEY) - 1));
    ptls_context_t minicrypto_ctx = {ptls_minicrypto_random_bytes,
                                     &ptls_get_time,
                                     ptls_minicrypto_key_exchanges,
                                     ptls_minicrypto_cipher_suites,
                                     {&secp256r1_certificate, 1},
                                     {{NULL}},
                                     NULL,
                                     NULL,
                                     &minicrypto_sign_certificate.super};

    /* context using mbedtls as backend; minicrypto is used for signing certificate as the mbedtls backend does not (yet) have the
     * capability */
    ptls_minicrypto_secp256r1sha256_sign_certificate_t mbedtls_sign_certificate;
    ptls_minicrypto_init_secp256r1sha256_sign_certificate(
        &mbedtls_sign_certificate, ptls_iovec_init(SECP256R1_PRIVATE_KEY, sizeof(SECP256R1_PRIVATE_KEY) - 1));
    ptls_context_t mbedtls_ctx = {ptls_mbedtls_random_bytes,
                                  &ptls_get_time,
                                  ptls_mbedtls_key_exchanges,
                                  ptls_mbedtls_cipher_suites,
                                  {&secp256r1_certificate, 1},
                                  {{NULL}},
                                  NULL,
                                  NULL,
                                  &mbedtls_sign_certificate.super};

    ctx = &mbedtls_ctx;
    ctx_peer = &mbedtls_ctx;
    subtest("selt-test", test_picotls);

    ctx = &mbedtls_ctx;
    ctx_peer = &minicrypto_ctx;
    subtest("vs. minicrypto", test_picotls);

    ctx = &minicrypto_ctx;
    ctx_peer = &mbedtls_ctx;
    subtest("minicrypto vs.", test_picotls);

    /* Deinitialize the PSA crypto library. */
    mbedtls_psa_crypto_free();

    return done_testing();
}
