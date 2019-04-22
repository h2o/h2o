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
    "MIIDKzCCAhOgAwIBAgIBADANBgkqhkiG9w0BAQsFADAaMRgwFgYDVQQDEw9waWNv\n"                                                           \
    "dGxzIHRlc3QgY2EwHhcNMTgwMjIzMDIzODEyWhcNMjgwMjIxMDIzODEyWjAbMRkw\n"                                                           \
    "FwYDVQQDExB0ZXN0LmV4YW1wbGUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n"                                                           \
    "MIIBCgKCAQEA5soWzSG7iyawQlHM1yaX2dUAATUkhpbg2WPFOEem7E3zYzc6A/Z+\n"                                                           \
    "bViFlfEgL37cbDUb4pnOAHrrsjGgkyBYh5i9iCTVfCk+H6SOHZJORO1Tq8X9C7Wc\n"                                                           \
    "NcshpSdm2Pa8hmv9hsHbLSeoPNeg8NkTPwMVaMZ2GpdmiyAmhzSZ2H9mzNI7ntPW\n"                                                           \
    "/XCchVf+ax2yt9haZ+mQE2NPYwHDjqCtdGkP5ZXXnYhJSBzSEhxfGckIiKDyOxiN\n"                                                           \
    "kLFLvUdT4ERSFBjauP2cSI0XoOUsiBxJNwHH310AU8jZbveSTcXGYgEuu2MIuDo7\n"                                                           \
    "Vhkq5+TCqXsIFNbjy0taOoPRvUbPsbqFlQIDAQABo3sweTAJBgNVHRMEAjAAMCwG\n"                                                           \
    "CWCGSAGG+EIBDQQfFh1PcGVuU1NMIEdlbmVyYXRlZCBDZXJ0aWZpY2F0ZTAdBgNV\n"                                                           \
    "HQ4EFgQUE1vXDjBT8j2etP4brfHQ9DeKnpgwHwYDVR0jBBgwFoAUv3nKl7JgeCCW\n"                                                           \
    "qkZXnN+nsiP1JWMwDQYJKoZIhvcNAQELBQADggEBAKwARsxOCiGPXU1xhvs+pq9I\n"                                                           \
    "63mLi4rfnssOGzGnnAfuEaxggpozf3fOSgfyTaDbACdRPTZEStjQ5HMCcHvY7CH0\n"                                                           \
    "8EYA+lkmFbuXXL8uHby1JBTzbTGf8pkRUsuF/Ie0SLChoDgt8oF3mY5pyU4HUaAw\n"                                                           \
    "Zp6HBpIRMdmbwGcwm25bl9MQYTrTX3dBfp3XPzfXbVwjJ7bsiTwAGq+dKwzwOQeM\n"                                                           \
    "2ZMZt4BQBoevsNopPrqG0S6kGUmJOIax0t13bKwDj21+Hp/O90HTFVCtAaDxRC56\n"                                                           \
    "k0O8Q62ZxzjGJ7Zw6K3azXlH/BYE+CajxTUF+FKRRkkWL1GrFVUsYd9KLDAVry0=\n"                                                           \
    "-----END CERTIFICATE-----\n"

static void test_bf(void)
{
#if PTLS_OPENSSL_HAVE_BF
    /* vectors from http://www.herongyang.com/Blowfish/Perl-Crypt-Blowfish-Test-Vector-128-Bit-Key.html */
    static const uint8_t key[PTLS_BLOWFISH_KEY_SIZE] = {0},
                         plaintext[PTLS_BLOWFISH_BLOCK_SIZE] = {0x4e, 0xf9, 0x97, 0x45, 0x61, 0x98, 0xdd, 0x78},
                         expected[PTLS_BLOWFISH_BLOCK_SIZE] = {0xe1, 0xc0, 0x30, 0xe7, 0x4c, 0x14, 0xd2, 0x61};
    uint8_t encrypted[PTLS_BLOWFISH_BLOCK_SIZE], decrypted[PTLS_BLOWFISH_BLOCK_SIZE];

    /* encrypt */
    ptls_cipher_context_t *ctx = ptls_cipher_new(&ptls_openssl_bfecb, 1, key);
    ptls_cipher_encrypt(ctx, encrypted, plaintext, PTLS_BLOWFISH_BLOCK_SIZE);
    ptls_cipher_free(ctx);
    ok(memcmp(encrypted, expected, PTLS_BLOWFISH_BLOCK_SIZE) == 0);

    /* decrypt */
    ctx = ptls_cipher_new(&ptls_openssl_bfecb, 0, key);
    ptls_cipher_encrypt(ctx, decrypted, "deadbeef", PTLS_BLOWFISH_BLOCK_SIZE);
    ptls_cipher_encrypt(ctx, decrypted, encrypted, PTLS_BLOWFISH_BLOCK_SIZE);
    ptls_cipher_free(ctx);
    ok(memcmp(decrypted, plaintext, PTLS_BLOWFISH_BLOCK_SIZE) == 0);
#endif
}

static void test_key_exchanges(void)
{
    test_key_exchange(&ptls_openssl_secp256r1, &ptls_openssl_secp256r1);
    test_key_exchange(&ptls_openssl_secp256r1, &ptls_minicrypto_secp256r1);
    test_key_exchange(&ptls_minicrypto_secp256r1, &ptls_openssl_secp256r1);

#if PTLS_OPENSSL_HAVE_SECP384R1
    test_key_exchange(&ptls_openssl_secp384r1, &ptls_openssl_secp384r1);
#endif

#if PTLS_OPENSSL_HAVE_SECP521R1
    test_key_exchange(&ptls_openssl_secp521r1, &ptls_openssl_secp521r1);
#endif

#if PTLS_OPENSSL_HAVE_X25519
    test_key_exchange(&ptls_openssl_x25519, &ptls_openssl_x25519);
    test_key_exchange(&ptls_openssl_x25519, &ptls_minicrypto_x25519);
    test_key_exchange(&ptls_minicrypto_x25519, &ptls_openssl_x25519);
#endif
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

static X509 *x509_from_pem(const char *pem)
{
    BIO *bio = BIO_new_mem_buf((void *)pem, (int)strlen(pem));
    X509 *cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    assert(cert != NULL && "failed to load certificate");
    BIO_free(bio);
    return cert;
}

static ptls_key_exchange_context_t *key_from_pem(const char *pem)
{
    BIO *bio = BIO_new_mem_buf((void *)pem, (int)strlen(pem));
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    assert(pkey != NULL && "failed to load private key");
    BIO_free(bio);

    ptls_key_exchange_context_t *ctx;
    int ret = ptls_openssl_create_key_exchange(&ctx, pkey);
    assert(ret == 0 && "failed to setup private key");

    EVP_PKEY_free(pkey);
    return ctx;
}

static void test_cert_verify(void)
{
    X509 *cert = x509_from_pem(RSA_CERTIFICATE);
    STACK_OF(X509) *chain = sk_X509_new_null();
    X509_STORE *store = X509_STORE_new();
    int ret;

    /* expect fail when no CA is registered */
    ret = verify_cert_chain(store, cert, chain, 0, "test.example.com");
    ok(ret == PTLS_ALERT_UNKNOWN_CA);

    /* expect success after registering the CA */
    X509_LOOKUP *lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());
    ret = X509_LOOKUP_load_file(lookup, "t/assets/test-ca.crt", X509_FILETYPE_PEM);
    ok(ret);
    ret = verify_cert_chain(store, cert, chain, 0, "test.example.com");
    ok(ret == 0);

#ifdef X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS
    /* different server_name */
    ret = verify_cert_chain(store, cert, chain, 0, "test2.example.com");
    ok(ret == PTLS_ALERT_BAD_CERTIFICATE);
#else
    fprintf(stderr, "**** skipping test for hostname validation failure ***\n");
#endif

    X509_free(cert);
    sk_X509_free(chain);
    X509_STORE_free(store);
}

static void setup_certificate(ptls_iovec_t *dst)
{
    X509 *cert = x509_from_pem(RSA_CERTIFICATE);

    dst->base = NULL;
    dst->len = i2d_X509(cert, &dst->base);

    X509_free(cert);
}

static void setup_sign_certificate(ptls_openssl_sign_certificate_t *sc)
{
    BIO *bio = BIO_new_mem_buf(RSA_PRIVATE_KEY, (int)strlen(RSA_PRIVATE_KEY));
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    assert(pkey != NULL || !"failed to load private key");
    BIO_free(bio);

    ptls_openssl_init_sign_certificate(sc, pkey);

    EVP_PKEY_free(pkey);
}

static int verify_cert_cb(int ok, X509_STORE_CTX *ctx)
{
    /* ignore certificate verification errors */
    return 1;
}

DEFINE_FFX_AES128_ALGORITHMS(openssl);
#if PTLS_OPENSSL_HAVE_CHACHA20_POLY1305
DEFINE_FFX_CHACHA20_ALGORITHMS(openssl);
#endif

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

    subtest("bf", test_bf);

    subtest("key-exchange", test_key_exchanges);

    ptls_iovec_t cert;
    setup_certificate(&cert);
    setup_sign_certificate(&openssl_sign_certificate);
    X509_STORE *cert_store = X509_STORE_new();
    X509_STORE_set_verify_cb(cert_store, verify_cert_cb);
    ptls_openssl_init_verify_certificate(&openssl_verify_certificate, cert_store);
    /* we should call X509_STORE_free on OpenSSL 1.1 or in prior versions decrement refount then call _free */
    ptls_context_t openssl_ctx = {ptls_openssl_random_bytes,
                                  &ptls_get_time,
                                  ptls_openssl_key_exchanges,
                                  ptls_openssl_cipher_suites,
                                  {&cert, 1},
                                  NULL,
                                  NULL,
                                  NULL,
                                  &openssl_sign_certificate.super};
    assert(openssl_ctx.cipher_suites[0]->hash->digest_size == 48); /* sha384 */
    ptls_context_t openssl_ctx_sha256only = openssl_ctx;
    ++openssl_ctx_sha256only.cipher_suites;
    assert(openssl_ctx_sha256only.cipher_suites[0]->hash->digest_size == 32); /* sha256 */

    ptls_key_exchange_context_t *esni_private_keys[2] = {key_from_pem(ESNI_SECP256R1KEY), NULL};

    ctx = ctx_peer = &openssl_ctx;
    verify_certificate = &openssl_verify_certificate.super;
    ADD_FFX_AES128_ALGORITHMS(openssl);
#if PTLS_OPENSSL_HAVE_CHACHA20_POLY1305
    ADD_FFX_CHACHA20_ALGORITHMS(openssl);
#endif

    subtest("rsa-sign", test_rsa_sign);
    subtest("ecdsa-sign", test_ecdsa_sign);
    subtest("cert-verify", test_cert_verify);
    subtest("picotls", test_picotls);
    test_picotls_esni(esni_private_keys);

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
                                     NULL,
                                     &minicrypto_sign_certificate.super};
    ctx = &openssl_ctx;
    ctx_peer = &minicrypto_ctx;
    subtest("vs. minicrypto", test_picotls);

    ctx = &minicrypto_ctx;
    ctx_peer = &openssl_ctx;
    subtest("minicrypto vs.", test_picotls);

    esni_private_keys[0]->on_exchange(esni_private_keys, 1, NULL, ptls_iovec_init(NULL, 0));
    return done_testing();
}
