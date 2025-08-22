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

typedef struct st_ptls_mbedtls_signature_scheme_t {
    uint16_t scheme_id;
    psa_algorithm_t hash_algo;
} ptls_mbedtls_signature_scheme_t;

typedef struct st_ptls_mbedtls_sign_certificate_t {
    ptls_sign_certificate_t super;
    mbedtls_svc_key_id_t key_id;
    psa_key_attributes_t attributes;
    const ptls_mbedtls_signature_scheme_t *schemes;
} ptls_mbedtls_sign_certificate_t;

int ptls_mbedtls_sign_certificate(ptls_sign_certificate_t *_self, ptls_t *tls, ptls_async_job_t **async,
                                  uint16_t *selected_algorithm, ptls_buffer_t *outbuf, ptls_iovec_t input,
                                  const uint16_t *algorithms, size_t num_algorithms);

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

/*
Sign certificate implements a callback:

if ((ret = tls->ctx->sign_certificate->cb(
tls->ctx->sign_certificate, tls, tls->is_server ? &tls->server.async_job : NULL, &algo, sendbuf,
ptls_iovec_init(data, datalen), signature_algorithms != NULL ? signature_algorithms->list : NULL,
signature_algorithms != NULL ? signature_algorithms->count : 0)) != 0) {

or:

static int sign_certificate(ptls_sign_certificate_t *_self, ptls_t *tls, ptls_async_job_t **async, uint16_t *selected_algorithm,
ptls_buffer_t *outbuf, ptls_iovec_t input, const uint16_t *algorithms, size_t num_algorithms)

The callback "super" type is ptls_sign_certificate_t, defined by the macro:
PTLS_CALLBACK_TYPE(int, sign_certificate, ptls_t *tls, ptls_async_job_t **async, uint16_t *selected_algorithm,
ptls_buffer_t *output, ptls_iovec_t input, const uint16_t *algorithms, size_t num_algorithms);

The notation is simple: input buffer and supported algorithms as input, selected algo and output buffer as output.
Output buffer is already partially filled.

*/

#define ASSET_RSA_KEY "t/assets/rsa/key.pem"
#define ASSET_RSA_PKCS8_KEY "t/assets/rsa-pkcs8/key.pem"
#define ASSET_SECP256R1_KEY "t/assets/secp256r1/key.pem"
#define ASSET_SECP384R1_KEY "t/assets/secp384r1/key.pem"
#define ASSET_SECP521R1_KEY "t/assets/secp521r1/key.pem"
#define ASSET_SECP256R1_PKCS8_KEY "t/assets/secp256r1-pkcs8/key.pem"

int test_load_one_der_key(char const *path)
{
    int ret = -1;
    unsigned char hash[32];
    const unsigned char h0[32] = {1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15, 16,
                                  17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};
    ptls_context_t ctx = {0};

    ret = ptls_mbedtls_load_private_key(&ctx, path);
    if (ret != 0) {
        printf("Cannot create sign_certificate from: %s\n", path);
        ret = -1;
    } else if (ctx.sign_certificate == NULL) {
        printf("Sign_certificate not set in ptls context for: %s\n", path);
        ret = -1;
    } else {
        /* Try to sign something */
        int ret;
        ptls_mbedtls_sign_certificate_t *signer =
            (ptls_mbedtls_sign_certificate_t *)(((unsigned char *)ctx.sign_certificate) -
                                                offsetof(struct st_ptls_mbedtls_sign_certificate_t, super));
        /* get the key algorithm */
        ptls_buffer_t outbuf;
        uint8_t outbuf_smallbuf[256];
        ptls_iovec_t input = {hash, sizeof(hash)};
        uint16_t selected_algorithm = 0;
        int num_algorithms = 0;
        uint16_t algorithms[16];
        memcpy(hash, h0, 32);
        while (signer->schemes[num_algorithms].scheme_id != UINT16_MAX && num_algorithms < 16) {
            algorithms[num_algorithms] = signer->schemes[num_algorithms].scheme_id;
            num_algorithms++;
        }

        ptls_buffer_init(&outbuf, outbuf_smallbuf, sizeof(outbuf_smallbuf));

        ret = ptls_mbedtls_sign_certificate(ctx.sign_certificate, NULL, NULL, &selected_algorithm, &outbuf, input, algorithms,
                                            num_algorithms);
        if (ret == 0) {
            printf("Signed a message, key: %s, scheme: %x, signature size: %zu\n", path, selected_algorithm, outbuf.off);
        } else {
            printf("Sign failed, key: %s, scheme: %x, signature size: %zu\n", path, selected_algorithm, outbuf.off);
        }
        ptls_buffer_dispose(&outbuf);
        ptls_mbedtls_dispose_sign_certificate(&signer->super);
    }
    return ret;
}

static void test_load_rsa_key()
{
    int ret = test_load_one_der_key(ASSET_RSA_KEY);

    if (ret != 0) {
        ok(!"fail");
        return;
    }
    ok(!!"success");
}

static void test_load_secp256r1_key()
{
    int ret = test_load_one_der_key(ASSET_SECP256R1_KEY);
    if (ret != 0) {
        ok(!"fail");
        return;
    }
    ok(!!"success");
}

static void test_load_secp384r1_key()
{
    int ret = test_load_one_der_key(ASSET_SECP384R1_KEY);
    if (ret != 0) {
        ok(!"fail");
        return;
    }
    ok(!!"success");
}

static void test_load_secp521r1_key()
{
    int ret = test_load_one_der_key(ASSET_SECP521R1_KEY);
    if (ret != 0) {
        ok(!"fail");
        return;
    }
    ok(!!"success");
}

static void test_load_secp256r1_pkcs8_key()
{
    int ret = test_load_one_der_key(ASSET_SECP256R1_PKCS8_KEY);
    if (ret != 0) {
        ok(!"fail");
        return;
    }
    ok(!!"success");
}

static void test_load_rsa_pkcs8_key()
{
    int ret = test_load_one_der_key(ASSET_RSA_PKCS8_KEY);
    if (ret != 0) {
        ok(!"fail");
        return;
    }
    ok(!!"success");
}

void test_sign_certificate(void)
{
    subtest("load rsa key", test_load_rsa_key);
    subtest("load secp256r1 key", test_load_secp256r1_key);
    subtest("load secp384r1 key", test_load_secp384r1_key);
    subtest("load secp521r1 key", test_load_secp521r1_key);
    subtest("load secp521r1-pkcs8 key", test_load_secp256r1_pkcs8_key);
    subtest("load rsa-pkcs8 key", test_load_rsa_pkcs8_key);

    /* we do not test EDDSA keys, because they are not yet supported */
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
    ptls_context_t minicrypto_ctx = {.random_bytes = ptls_minicrypto_random_bytes,
                                     .get_time = &ptls_get_time,
                                     .key_exchanges = ptls_minicrypto_key_exchanges,
                                     .cipher_suites = ptls_minicrypto_cipher_suites,
                                     .certificates = {&secp256r1_certificate, 1},
                                     .sign_certificate = &minicrypto_sign_certificate.super};

    /* context using mbedtls as backend; minicrypto is used for signing certificate as the mbedtls backend does not (yet) have the
     * capability */
    ptls_minicrypto_secp256r1sha256_sign_certificate_t mbedtls_sign_certificate;
    ptls_minicrypto_init_secp256r1sha256_sign_certificate(
        &mbedtls_sign_certificate, ptls_iovec_init(SECP256R1_PRIVATE_KEY, sizeof(SECP256R1_PRIVATE_KEY) - 1));
    ptls_context_t mbedtls_ctx = {.random_bytes = ptls_mbedtls_random_bytes,
                                  .get_time = &ptls_get_time,
                                  .key_exchanges = ptls_mbedtls_key_exchanges,
                                  .cipher_suites = ptls_mbedtls_cipher_suites,
                                  .certificates = {&secp256r1_certificate, 1},
                                  .sign_certificate = &mbedtls_sign_certificate.super};

    ctx = &mbedtls_ctx;
    ctx_peer = &mbedtls_ctx;
    subtest("selt-test", test_picotls);

    ctx = &mbedtls_ctx;
    ctx_peer = &minicrypto_ctx;
    subtest("vs. minicrypto", test_picotls);

    ctx = &minicrypto_ctx;
    ctx_peer = &mbedtls_ctx;
    subtest("minicrypto vs.", test_picotls);

    /* test the sign certificate */
    subtest("sign certificate", test_sign_certificate);

    /* Deinitialize the PSA crypto library. */
    mbedtls_psa_crypto_free();

    return done_testing();
}
