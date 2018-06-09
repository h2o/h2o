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
#ifdef _WINDOWS
#include "wincompat.h"
#endif
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/engine.h>
#include "picotls.h"
#include "picotls/minicrypto.h"
#include "../deps/picotest/picotest.h"
#include "../lib/openssl.c"
#include "test.h"

#define RSA_PRIVATE_KEY                                                                                                            \
    "-----BEGIN RSA PRIVATE KEY-----\n"                                                                                            \
    "MIIEowIBAAKCAQEA5soWzSG7iyawQlHM1yaX2dUAATUkhpbg2WPFOEem7E3zYzc6\n"                                                           \
    "A/Z+bViFlfEgL37cbDUb4pnOAHrrsjGgkyBYh5i9iCTVfCk+H6SOHZJORO1Tq8X9\n"                                                           \
    "C7WcNcshpSdm2Pa8hmv9hsHbLSeoPNeg8NkTPwMVaMZ2GpdmiyAmhzSZ2H9mzNI7\n"                                                           \
    "ntPW/XCchVf+ax2yt9haZ+mQE2NPYwHDjqCtdGkP5ZXXnYhJSBzSEhxfGckIiKDy\n"                                                           \
    "OxiNkLFLvUdT4ERSFBjauP2cSI0XoOUsiBxJNwHH310AU8jZbveSTcXGYgEuu2MI\n"                                                           \
    "uDo7Vhkq5+TCqXsIFNbjy0taOoPRvUbPsbqFlQIDAQABAoIBAQCWcUv1wjR/2+Nw\n"                                                           \
    "B+Swp267R9bt8pdxyK6f5yKrskGErremiFygMrFtVBQYjws9CsRjISehSkN4GqjE\n"                                                           \
    "CweygJZVJeL++YvUmQnvFJSzgCjXU6GEStbOKD/A7T5sa0fmzMhOE907V+kpAT3x\n"                                                           \
    "E1rNRaP/ImJ1X1GjuefVb0rOPiK/dehFQWfsUkOvh+J3PU76wcnexxzJgxhVxdfX\n"                                                           \
    "qNa7UDsWzTImUjcHIfnhXc1K/oSKk6HjImQi/oE4lgoJUCEDaUbq0nXNrM0EmTTv\n"                                                           \
    "OQ5TVP5Lds9p8UDEa55eZllGXam0zKjhDKtkQ/5UfnxsAv2adY5cuH+XN0ExfKD8\n"                                                           \
    "wIZ5qINtAoGBAPRbQGZZkP/HOYA4YZ9HYAUQwFS9IZrQ8Y7C/UbL01Xli13nKalH\n"                                                           \
    "xXdG6Zv6Yv0FCJKA3N945lEof9rwriwhuZbyrA1TcKok/s7HR8Bhcsm2DzRD5OiC\n"                                                           \
    "3HK+Xy+6fBaMebffqBPp3Lfj/lSPNt0w/8DdrKBTw/cAy40g0n1zEu07AoGBAPHJ\n"                                                           \
    "V4IfQBiblCqDh77FfQRUNR4hVbbl00Gviigiw563nk7sxdrOJ1edTyTOUBHtM3zg\n"                                                           \
    "AT9sYz2CUXvsyEPqzMDANWMb9e2R//NcP6aM4k7WQRnwkZkp0WOIH95U2o1MHCYc\n"                                                           \
    "5meAHVf2UMl+64xU2ZfY3rjMmPLjWMt0hKYsOmtvAoGAClIQVkJSLXtsok2/Ucrh\n"                                                           \
    "81TRysJyOOe6TB1QNT1Gn8oiKMUqrUuqu27zTvM0WxtrUUTAD3A7yhG71LN1p8eE\n"                                                           \
    "3ytAuQ9dItKNMI6aKTX0czCNU9fKQ0fDp9UCkDGALDOisHFx1+V4vQuUIl4qIw1+\n"                                                           \
    "v9adA+iFzljqP/uy6DmEAyECgYAyWCgecf9YoFxzlbuYH2rukdIVmf9M/AHG9ZQg\n"                                                           \
    "00xEKhuOd4KjErXiamDmWwcVFHzaDZJ08E6hqhbpZN42Nhe4Ms1q+5FzjCjtNVIT\n"                                                           \
    "jdY5cCdSDWNjru9oeBmao7R2I1jhHrdi6awyeplLu1+0cp50HbYSaJeYS3pbssFE\n"                                                           \
    "EIWBhQKBgG3xleD4Sg9rG2OWQz5IrvLFg/Hy7YWyushVez61kZeLDnt9iM2um76k\n"                                                           \
    "/xFNIW0a+eL2VxRTCbXr9z86hjc/6CeSJHKYFQl4zsSAZkaIJ0+HbrhDNBAYh9b2\n"                                                           \
    "mRdX+OMdZ7Z5J3Glt8ENFRqe8RlESMpAKxjR+dID0bjwAjVr2KCh\n"                                                                       \
    "-----END RSA PRIVATE KEY-----\n"

#define RSA_CERTIFICATE                                                                                                            \
    "-----BEGIN CERTIFICATE-----\n"                                                                                                \
    "MIICqDCCAZACCQDI5jeEvExN+TANBgkqhkiG9w0BAQUFADAWMRQwEgYDVQQDEwtl\n"                                                           \
    "eGFtcGxlLmNvbTAeFw0xNjA5MzAwMzQ0NTFaFw0yNjA5MjgwMzQ0NTFaMBYxFDAS\n"                                                           \
    "BgNVBAMTC2V4YW1wbGUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC\n"                                                           \
    "AQEA5soWzSG7iyawQlHM1yaX2dUAATUkhpbg2WPFOEem7E3zYzc6A/Z+bViFlfEg\n"                                                           \
    "L37cbDUb4pnOAHrrsjGgkyBYh5i9iCTVfCk+H6SOHZJORO1Tq8X9C7WcNcshpSdm\n"                                                           \
    "2Pa8hmv9hsHbLSeoPNeg8NkTPwMVaMZ2GpdmiyAmhzSZ2H9mzNI7ntPW/XCchVf+\n"                                                           \
    "ax2yt9haZ+mQE2NPYwHDjqCtdGkP5ZXXnYhJSBzSEhxfGckIiKDyOxiNkLFLvUdT\n"                                                           \
    "4ERSFBjauP2cSI0XoOUsiBxJNwHH310AU8jZbveSTcXGYgEuu2MIuDo7Vhkq5+TC\n"                                                           \
    "qXsIFNbjy0taOoPRvUbPsbqFlQIDAQABMA0GCSqGSIb3DQEBBQUAA4IBAQAwZQsG\n"                                                           \
    "E/3DQFBOnmBITFsaIVJVXU0fbfIjy3p1r6O9z2zvrfB1i8AMxOORAVjE5wHstGnK\n"                                                           \
    "3sLMjkMYXqu1XEfQbStQN+Bsi8m+nE/x9MmuLthpzJHXUmPYZ4TKs0KJmFPLTXYi\n"                                                           \
    "j0OrP0a5BNcyGj/B4Z33aaU9N3z0TWBwx4OPjJoK3iInBx80sC1Ig2PE6mDBxLOg\n"                                                           \
    "5Ohm/XU/43MrtH8SgYkxr3OyzXTm8J0RFMWhYlo1uqR+pWV3TgacixNnUq5w5h4m\n"                                                           \
    "sqXcikh+j8ReNXsKnMOAfFo+HbRqyKWNE3DekCIiiQ5ds4A4SfT7pYyGAmBkAxht\n"                                                           \
    "sS919x2o8l97kaYf\n"                                                                                                           \
    "-----END CERTIFICATE-----\n"

static void test_ecdh_key_exchange(void)
{
    test_key_exchange(&ptls_openssl_secp256r1);
}

static void test_rsa_sign(void)
{
    ptls_openssl_sign_certificate_t *sc = (ptls_openssl_sign_certificate_t *)ctx->sign_certificate;

    const void *message = "hello world";
    ptls_buffer_t sigbuf;
    uint8_t sigbuf_small[1024];

    ptls_buffer_init(&sigbuf, sigbuf_small, sizeof(sigbuf_small));
    ok(do_sign(sc->key, &sigbuf, ptls_iovec_init(message, strlen(message)), EVP_sha256()) == 0);
    EVP_PKEY_up_ref(sc->key);
    ok(verify_sign(sc->key, ptls_iovec_init(message, strlen(message)), ptls_iovec_init(sigbuf.base, sigbuf.off)) == 0);

    ptls_buffer_dispose(&sigbuf);
}

static void test_ecdsa_sign(void)
{
    EVP_PKEY *pkey;

    { /* create pkey */
        EC_KEY *eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
        EC_KEY_generate_key(eckey);
        pkey = EVP_PKEY_new();
        EVP_PKEY_set1_EC_KEY(pkey, eckey);
        EC_KEY_free(eckey);
    }

    const char *message = "hello world";
    ptls_buffer_t sigbuf;
    uint8_t sigbuf_small[1024];

    ptls_buffer_init(&sigbuf, sigbuf_small, sizeof(sigbuf_small));
    ok(do_sign(pkey, &sigbuf, ptls_iovec_init(message, strlen(message)), EVP_sha256()) == 0);
    EVP_PKEY_up_ref(pkey);
    ok(verify_sign(pkey, ptls_iovec_init(message, strlen(message)), ptls_iovec_init(sigbuf.base, sigbuf.off)) == 0);

    ptls_buffer_dispose(&sigbuf);
    EVP_PKEY_free(pkey);
}

static void setup_certificate(ptls_iovec_t *dst)
{
    BIO *bio = BIO_new_mem_buf(RSA_CERTIFICATE, strlen(RSA_CERTIFICATE));
    X509 *cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    assert(cert != NULL || !!"failed to load certificate");
    BIO_free(bio);

    dst->base = NULL;
    dst->len = i2d_X509(cert, &dst->base);

    X509_free(cert);
}

static void setup_sign_certificate(ptls_openssl_sign_certificate_t *sc)
{
    BIO *bio = BIO_new_mem_buf(RSA_PRIVATE_KEY, strlen(RSA_PRIVATE_KEY));
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    assert(pkey != NULL || !"failed to load private key");
    BIO_free(bio);

    ptls_openssl_init_sign_certificate(sc, pkey);

    EVP_PKEY_free(pkey);
}

int main(int argc, char **argv)
{
    ptls_openssl_sign_certificate_t openssl_sign_certificate;
    ptls_openssl_verify_certificate_t openssl_verify_certificate;

    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
#if !defined(OPENSSL_NO_ENGINE)
    /* Load all compiled-in ENGINEs */
    ENGINE_load_builtin_engines();
    ENGINE_register_all_ciphers();
    ENGINE_register_all_digests();
#endif

    ptls_iovec_t cert;
    setup_certificate(&cert);
    setup_sign_certificate(&openssl_sign_certificate);
    ptls_openssl_init_verify_certificate(&openssl_verify_certificate, NULL);
    ptls_context_t openssl_ctx = {ptls_openssl_random_bytes,
                                  &ptls_get_time,
                                  ptls_openssl_key_exchanges,
                                  ptls_openssl_cipher_suites,
                                  {&cert, 1},
                                  NULL,
                                  NULL,
                                  &openssl_sign_certificate.super,
                                  &openssl_verify_certificate.super};
    assert(openssl_ctx.cipher_suites[0]->hash->digest_size == 48); /* sha384 */
    ptls_context_t openssl_ctx_sha256only = openssl_ctx;
    ++openssl_ctx_sha256only.cipher_suites;
    assert(openssl_ctx_sha256only.cipher_suites[0]->hash->digest_size == 32); /* sha256 */

    ctx = ctx_peer = &openssl_ctx;

    subtest("ecdh-key-exchange", test_ecdh_key_exchange);
    subtest("rsa-sign", test_rsa_sign);
    subtest("ecdsa-sign", test_ecdsa_sign);
    subtest("picotls", test_picotls);

    ctx = ctx_peer = &openssl_ctx_sha256only;
    subtest("picotls", test_picotls);

    ctx = &openssl_ctx_sha256only;
    ctx_peer = &openssl_ctx;
    subtest("picotls", test_picotls);

    ctx = &openssl_ctx;
    ctx_peer = &openssl_ctx_sha256only;
    subtest("picotls", test_picotls);

    ptls_minicrypto_secp256r1sha256_sign_certificate_t minicrypto_sign_certificate;
    ptls_iovec_t minicrypto_certificate = ptls_iovec_init(SECP256R1_CERTIFICATE, sizeof(SECP256R1_CERTIFICATE) - 1);
    ptls_minicrypto_init_secp256r1sha256_sign_certificate(
        &minicrypto_sign_certificate, ptls_iovec_init(SECP256R1_PRIVATE_KEY, sizeof(SECP256R1_PRIVATE_KEY) - 1));
    ptls_context_t minicrypto_ctx = {ptls_minicrypto_random_bytes,
                                     &ptls_get_time,
                                     ptls_minicrypto_key_exchanges,
                                     ptls_minicrypto_cipher_suites,
                                     {&minicrypto_certificate, 1},
                                     NULL,
                                     NULL,
                                     &minicrypto_sign_certificate.super};
    ctx = &openssl_ctx;
    ctx_peer = &minicrypto_ctx;
    subtest("vs. minicrypto", test_picotls);

    ctx = &minicrypto_ctx;
    ctx_peer = &openssl_ctx;
    subtest("minicrypto vs.", test_picotls);

    return done_testing();
}
