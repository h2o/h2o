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
#define OPENSSL_API_COMPAT 0x00908000L
#include <openssl/opensslv.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/engine.h>
#if !defined(LIBRESSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/provider.h>
#endif
#include "picotls.h"
#include "picotls/minicrypto.h"
#include "picotls/openssl.h"
#if PTLS_OPENSSL_HAVE_ASYNC && PTLS_OPENSSL_HAVE_X25519 && !defined(_WINDOWS)
#include <sys/select.h>
#include <sys/time.h>
#define ASYNC_TESTS 1
#endif
#include "../deps/picotest/picotest.h"
#undef OPENSSL_API_COMPAT
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
    "MIIDQjCCAiqgAwIBAgIBBTANBgkqhkiG9w0BAQsFADAaMRgwFgYDVQQDEw9waWNv\n"                                                           \
    "dGxzIHRlc3QgY2EwHhcNMjExMjEzMDY1MzQwWhcNMzExMjExMDY1MzQwWjAbMRkw\n"                                                           \
    "FwYDVQQDExB0ZXN0LmV4YW1wbGUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n"                                                           \
    "MIIBCgKCAQEA5soWzSG7iyawQlHM1yaX2dUAATUkhpbg2WPFOEem7E3zYzc6A/Z+\n"                                                           \
    "bViFlfEgL37cbDUb4pnOAHrrsjGgkyBYh5i9iCTVfCk+H6SOHZJORO1Tq8X9C7Wc\n"                                                           \
    "NcshpSdm2Pa8hmv9hsHbLSeoPNeg8NkTPwMVaMZ2GpdmiyAmhzSZ2H9mzNI7ntPW\n"                                                           \
    "/XCchVf+ax2yt9haZ+mQE2NPYwHDjqCtdGkP5ZXXnYhJSBzSEhxfGckIiKDyOxiN\n"                                                           \
    "kLFLvUdT4ERSFBjauP2cSI0XoOUsiBxJNwHH310AU8jZbveSTcXGYgEuu2MIuDo7\n"                                                           \
    "Vhkq5+TCqXsIFNbjy0taOoPRvUbPsbqFlQIDAQABo4GRMIGOMAkGA1UdEwQCMAAw\n"                                                           \
    "LAYJYIZIAYb4QgENBB8WHU9wZW5TU0wgR2VuZXJhdGVkIENlcnRpZmljYXRlMB0G\n"                                                           \
    "A1UdDgQWBBQTW9cOMFPyPZ60/hut8dD0N4qemDAfBgNVHSMEGDAWgBS/ecqXsmB4\n"                                                           \
    "IJaqRlec36eyI/UlYzATBgNVHSUEDDAKBggrBgEFBQcDATANBgkqhkiG9w0BAQsF\n"                                                           \
    "AAOCAQEAYTglgIYqxhbmErQar8yFmRRJp93Zul+PnCuq1nkGPokJoytszoQtGBfw\n"                                                           \
    "ftgcMyTH3TOR22XThQafi/qWj3gz//oicZ09AuDfk/GMweWPjPGSs2lNUCbC9FqW\n"                                                           \
    "75JpYWsKqk8s0GwetZ710rX/65wJQAb4EcibMdWq98C/HUwQspXiXBXkEMDbMF5Q\n"                                                           \
    "s41vyeASk03jff+ofvTZl33sPurltO2oyRtDfUKWFAMBS7Bk/h/d3ZIwmv7DjXVw\n"                                                           \
    "ZKjxMZbXSmlgdngzBCBYZb5p+VkGXHqVjd07KhZd4nn5sqLy2i1COWB4OCb0xUHr\n"                                                           \
    "QxHvmJiqQ57FTFDypV0sKZRLuY9ovQ==\n"                                                                                           \
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
    subtest("secp256r1-self", test_key_exchange, &ptls_openssl_secp256r1, &ptls_openssl_secp256r1);
    subtest("secp256r1-to-minicrypto", test_key_exchange, &ptls_openssl_secp256r1, &ptls_minicrypto_secp256r1);
    subtest("secp256r1-from-minicrypto", test_key_exchange, &ptls_minicrypto_secp256r1, &ptls_openssl_secp256r1);

#if PTLS_OPENSSL_HAVE_SECP384R1
    subtest("secp384r1", test_key_exchange, &ptls_openssl_secp384r1, &ptls_openssl_secp384r1);
#endif

#if PTLS_OPENSSL_HAVE_SECP521R1
    subtest("secp521r1", test_key_exchange, &ptls_openssl_secp521r1, &ptls_openssl_secp521r1);
#endif

#if PTLS_OPENSSL_HAVE_X25519
    subtest("x25519-self", test_key_exchange, &ptls_openssl_x25519, &ptls_openssl_x25519);
    subtest("x25519-to-minicrypto", test_key_exchange, &ptls_openssl_x25519, &ptls_minicrypto_x25519);
    subtest("x25519-from-minicrypto", test_key_exchange, &ptls_minicrypto_x25519, &ptls_openssl_x25519);
#endif

#if PTLS_OPENSSL_HAVE_X25519MLKEM768
    subtest("x25519mlkem768", test_key_exchange, &ptls_openssl_x25519mlkem768, &ptls_openssl_x25519mlkem768);
#endif
}

static void test_sign_verify(EVP_PKEY *key, const ptls_openssl_signature_scheme_t *schemes)
{
    for (size_t i = 0; schemes[i].scheme_id != UINT16_MAX; ++i) {
        note("scheme 0x%04x", schemes[i].scheme_id);
        const void *message = "hello world";
        ptls_buffer_t sigbuf;
        uint8_t sigbuf_small[1024];

        ptls_buffer_init(&sigbuf, sigbuf_small, sizeof(sigbuf_small));
        ok(do_sign(key, schemes + i, &sigbuf, ptls_iovec_init(message, strlen(message)), NULL) == 0);
        EVP_PKEY_up_ref(key);
        ok(verify_sign(key, schemes[i].scheme_id, ptls_iovec_init(message, strlen(message)),
                       ptls_iovec_init(sigbuf.base, sigbuf.off)) == 0);

        ptls_buffer_dispose(&sigbuf);
    }
}

static void test_sha(void)
{
    static const char *text =
        "Alice was beginning to get very tired of sitting by her sister on the bank, and of having nothing to do: once or twice "
        "she had peeped into the book her sister was reading, but it had no pictures or conversations in it, and where is the use "
        "of a book, thought Alice, without pictures or conversations?";
    static const struct {
        ptls_hash_algorithm_t *algo;
        uint8_t expected[PTLS_MAX_DIGEST_SIZE];
    } all[] = {
        {&ptls_openssl_sha256, {0x9b, 0x5d, 0x38, 0x9a, 0xa5, 0xfd, 0xc8, 0x3a, 0xf5, 0x59, 0x8e, 0x90, 0xd7, 0x4e, 0x99, 0xb2,
                                0xbc, 0xeb, 0x97, 0x45, 0x7a, 0xc5, 0xda, 0xde, 0xd5, 0xd2, 0x18, 0x1c, 0x33, 0x5c, 0x93, 0x41}},
        {&ptls_openssl_sha384, {0x41, 0x7a, 0x7e, 0xda, 0x89, 0x55, 0xc6, 0xb4, 0x31, 0xde, 0x73, 0x2c, 0x8d, 0xc9, 0x3b, 0xcc,
                                0xc7, 0xbc, 0xe8, 0x96, 0x91, 0x7a, 0xa6, 0xa2, 0xf8, 0x73, 0x7e, 0xb9, 0xff, 0x09, 0xc6, 0x32,
                                0x31, 0x7b, 0xe1, 0x5b, 0xd7, 0xaa, 0xf2, 0xbd, 0x2a, 0x5c, 0x3a, 0xda, 0x3b, 0x24, 0x75, 0x92}},
        {&ptls_openssl_sha512, {0x40, 0x9d, 0x7f, 0x12, 0x8e, 0x32, 0x96, 0x89, 0xdc, 0xa5, 0x72, 0xe4, 0xa5, 0x39, 0xb4, 0x2b,
                                0xf0, 0x24, 0xe5, 0x42, 0x7a, 0x61, 0x77, 0x69, 0xda, 0xd5, 0xfd, 0x72, 0x85, 0x83, 0x39, 0x01,
                                0x31, 0xa6, 0xc8, 0x2f, 0x6a, 0x09, 0xfe, 0xa0, 0x54, 0x0c, 0xe3, 0x89, 0xdb, 0x8c, 0x4a, 0x83,
                                0x2f, 0x90, 0x94, 0x54, 0x93, 0x3f, 0xe9, 0x8a, 0x32, 0x3f, 0x85, 0x24, 0xa5, 0x9b, 0x5b, 0x02}},

        {NULL}};

    for (size_t i = 0; all[i].algo != NULL; ++i) {
        uint8_t actual[PTLS_MAX_DIGEST_SIZE];
        note("%s", all[i].algo->name);
        int ret = ptls_calc_hash(all[i].algo, actual, text, strlen(text));
        ok(ret == 0);
        ok(memcmp(actual, all[i].expected, all[i].algo->digest_size) == 0);
    }
}

static void test_rsa_sign(void)
{
    ptls_openssl_sign_certificate_t *sc = (ptls_openssl_sign_certificate_t *)ctx->sign_certificate;
    test_sign_verify(sc->key, sc->schemes);
}

static void do_test_ecdsa_sign(int nid, const ptls_openssl_signature_scheme_t *schemes)
{
    EVP_PKEY *pkey;

    { /* create pkey */
        EC_KEY *eckey = EC_KEY_new_by_curve_name(nid);
        EC_KEY_generate_key(eckey);
        pkey = EVP_PKEY_new();
        EVP_PKEY_set1_EC_KEY(pkey, eckey);
        EC_KEY_free(eckey);
    }

    test_sign_verify(pkey, schemes);
    EVP_PKEY_free(pkey);
}

static void test_ecdsa_sign(void)
{
    do_test_ecdsa_sign(NID_X9_62_prime256v1, secp256r1_signature_schemes);
#if PTLS_OPENSSL_HAVE_SECP384R1
    do_test_ecdsa_sign(NID_secp384r1, secp384r1_signature_schemes);
#endif
#if PTLS_OPENSSL_HAVE_SECP521R1
    do_test_ecdsa_sign(NID_secp521r1, secp521r1_signature_schemes);
#endif
}

static void test_ed25519_sign(void)
{
#if PTLS_OPENSSL_HAVE_ED25519
    EVP_PKEY *pkey = NULL;

    { /* create pkey */
        EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
        EVP_PKEY_keygen_init(pctx);
        EVP_PKEY_keygen(pctx, &pkey);
        EVP_PKEY_CTX_free(pctx);
    }

    test_sign_verify(pkey, ed25519_signature_schemes);
    EVP_PKEY_free(pkey);
#endif
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
    int ret, ossl_x509_err;

    /* expect fail when no CA is registered */
    ret = verify_cert_chain(store, cert, chain, 0, "test.example.com", &ossl_x509_err);
    ok(ret == PTLS_ALERT_UNKNOWN_CA);

    /* expect success after registering the CA */
    X509_LOOKUP *lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());
    ret = X509_LOOKUP_load_file(lookup, "t/assets/test-ca.crt", X509_FILETYPE_PEM);
    ok(ret);
    ret = verify_cert_chain(store, cert, chain, 0, "test.example.com", &ossl_x509_err);
    ok(ret == 0);

#ifdef X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS
    /* different server_name */
    ret = verify_cert_chain(store, cert, chain, 0, "test2.example.com", &ossl_x509_err);
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

static void test_all_hpke(void)
{
    test_hpke(ptls_openssl_hpke_kems, ptls_openssl_hpke_cipher_suites);
}

static ptls_aead_context_t *create_ech_opener(ptls_ech_create_opener_t *self, ptls_hpke_kem_t **kem,
                                              ptls_hpke_cipher_suite_t **cipher, ptls_t *tls, uint8_t config_id,
                                              ptls_hpke_cipher_suite_id_t cipher_id, ptls_iovec_t enc, ptls_iovec_t info_prefix)
{
    static ptls_key_exchange_context_t *pem = NULL;
    if (pem == NULL) {
        pem = key_from_pem(ECH_PRIVATE_KEY);
        assert(pem != NULL);
    }

    *cipher = NULL;
    for (size_t i = 0; ptls_openssl_hpke_cipher_suites[i] != NULL; ++i) {
        if (ptls_openssl_hpke_cipher_suites[i]->id.kdf == cipher_id.kdf &&
            ptls_openssl_hpke_cipher_suites[i]->id.aead == cipher_id.aead) {
            *cipher = ptls_openssl_hpke_cipher_suites[i];
            break;
        }
    }
    if (*cipher == NULL)
        return NULL;

    ptls_aead_context_t *aead = NULL;
    ptls_buffer_t infobuf;
    int ret;

    ptls_buffer_init(&infobuf, "", 0);
    ptls_buffer_pushv(&infobuf, info_prefix.base, info_prefix.len);
    ptls_buffer_pushv(&infobuf, (const uint8_t *)ECH_CONFIG_LIST + 2,
                      sizeof(ECH_CONFIG_LIST) - 3); /* choose the only ECHConfig from the list */
    ret = ptls_hpke_setup_base_r(&ptls_openssl_hpke_kem_p256sha256, *cipher, pem, &aead, enc,
                                 ptls_iovec_init(infobuf.base, infobuf.off));

Exit:
    ptls_buffer_dispose(&infobuf);
    return aead;
}

#if ASYNC_TESTS

static ENGINE *load_engine(const char *name)
{
    ENGINE *e;

    if ((e = ENGINE_by_id("dynamic")) == NULL)
        return NULL;
    if (!ENGINE_ctrl_cmd_string(e, "SO_PATH", name, 0) || !ENGINE_ctrl_cmd_string(e, "LOAD", NULL, 0)) {
        ENGINE_free(e);
        return NULL;
    }

    return e;
}

static struct {
    struct {
        size_t next_pending;
        ptls_t *tls;
        int wait_fd;
    } conns[10];
    size_t first_pending;
} qat;

static void qat_set_pending(size_t index)
{
    qat.conns[index].next_pending = qat.first_pending;
    qat.first_pending = index;
}

static void many_handshakes(void)
{
    ptls_t *client = ptls_new(ctx, 0), *resp_sample_conn = NULL;
    ptls_buffer_t clientbuf, resp_sample;
    int ret;

    { /* generate ClientHello that we would be sent to all the server-side objects */
        ptls_buffer_init(&clientbuf, "", 0);
        ret = ptls_handshake(client, &clientbuf, NULL, NULL, NULL);
        ok(ret == PTLS_ERROR_IN_PROGRESS);
    }

    ptls_buffer_init(&resp_sample, "", 0);

    qat.first_pending = 0;
    for (size_t i = 0; i < PTLS_ELEMENTSOF(qat.conns); ++i) {
        qat.conns[i].next_pending = i + 1;
        qat.conns[i].tls = NULL;
        qat.conns[i].wait_fd = -1;
    }
    qat.conns[PTLS_ELEMENTSOF(qat.conns) - 1].next_pending = SIZE_MAX;

    struct timeval start, end;
    gettimeofday(&start, NULL);

    static const size_t num_total = 10000;
    size_t num_issued = 0, num_running = 0;
    while (1) {
        while (qat.first_pending != SIZE_MAX) {
            size_t offending = qat.first_pending;
            /* detach the offending entry from pending list */
            qat.first_pending = qat.conns[offending].next_pending;
            qat.conns[offending].next_pending = SIZE_MAX;
            /* run the offending entry */
            if (qat.conns[offending].tls == NULL) {
                qat.conns[offending].tls = ptls_new(ctx_peer, 1);
                if (resp_sample_conn == NULL)
                    resp_sample_conn = qat.conns[offending].tls;
                ++num_issued;
                ++num_running;
            }
            ptls_buffer_t hsbuf;
            uint8_t hsbuf_small[8192];
            ptls_buffer_init(&hsbuf, hsbuf_small, sizeof(hsbuf_small));
            size_t inlen = ptls_get_cipher(qat.conns[offending].tls) == NULL ? clientbuf.off : 0; /* feed CH only as first flight */
            int hsret = ptls_handshake(qat.conns[offending].tls, &hsbuf, clientbuf.base, &inlen, NULL);
            if (resp_sample_conn == qat.conns[offending].tls) {
                ptls_buffer_pushv(&resp_sample, hsbuf.base, hsbuf.off);
            }
            ptls_buffer_dispose(&hsbuf);
            /* advance the handshake context */
            switch (hsret) {
            case 0:
                if (qat.conns[offending].tls == resp_sample_conn)
                    resp_sample_conn = (void *)1;
                ptls_free(qat.conns[offending].tls);
                qat.conns[offending].tls = NULL;
                --num_running;
                if (num_issued < num_total)
                    qat_set_pending(offending);
                break;
            case PTLS_ERROR_ASYNC_OPERATION: {
                ptls_async_job_t *job = ptls_get_async_job(qat.conns[offending].tls);
                assert(job->get_fd != NULL);
                qat.conns[offending].wait_fd = job->get_fd(job);
                assert(qat.conns[offending].wait_fd != -1);
            } break;
            default:
                fprintf(stderr, "ptls_handshake returned %d\n", hsret);
                abort();
                break;
            }
        }
        if (num_running == 0)
            break;
        /* poll for next action */
        fd_set rfds;
        FD_ZERO(&rfds);
        int nfds = 0;
        for (size_t i = 0; i < PTLS_ELEMENTSOF(qat.conns); ++i) {
            if (qat.conns[i].wait_fd != -1) {
                FD_SET(qat.conns[i].wait_fd, &rfds);
                if (nfds <= qat.conns[i].wait_fd)
                    nfds = qat.conns[i].wait_fd + 1;
            }
        }
        if (select(nfds, &rfds, NULL, NULL, NULL) > 0) {
            for (size_t i = 0; i < PTLS_ELEMENTSOF(qat.conns); ++i) {
                if (qat.conns[i].wait_fd != -1 && FD_ISSET(qat.conns[i].wait_fd, &rfds)) {
                    qat.conns[i].wait_fd = -1;
                    qat_set_pending(i);
                }
            }
        }
    }

    gettimeofday(&end, NULL);

    note("run %zu handshakes in %f seconds", num_total,
         (end.tv_sec + end.tv_usec / 1000000.) - (start.tv_sec + start.tv_usec / 1000000.));

    clientbuf.off = 0;

    /* confirm that the response looks okay */
    size_t resplen = resp_sample.off;
    ok(ptls_handshake(client, &clientbuf, resp_sample.base, &resplen, NULL) == 0);

    ptls_buffer_dispose(&clientbuf);
    ptls_buffer_dispose(&resp_sample);
    ptls_free(client);

    return;
Exit:
    assert("unreachable");
}

#endif

int main(int argc, char **argv)
{
    ptls_openssl_sign_certificate_t openssl_sign_certificate;
    ptls_openssl_verify_certificate_t openssl_verify_certificate;
    ptls_ech_create_opener_t ech_create_opener = {.cb = create_ech_opener};

    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

#if !defined(LIBRESSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x30000000L
    /* Explicitly load the legacy provider in addition to default, as we test Blowfish in one of the tests. */
    OSSL_PROVIDER *legacy = OSSL_PROVIDER_load(NULL, "legacy");
    OSSL_PROVIDER *dflt = OSSL_PROVIDER_load(NULL, "default");
#elif !defined(OPENSSL_NO_ENGINE)
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
    ptls_context_t openssl_ctx = {.random_bytes = ptls_openssl_random_bytes,
                                  .get_time = &ptls_get_time,
                                  .key_exchanges = ptls_openssl_key_exchanges,
                                  .cipher_suites = ptls_openssl_cipher_suites_all,
                                  .tls12_cipher_suites = ptls_openssl_tls12_cipher_suites,
                                  .certificates = {&cert, 1},
                                  .ech = {.client = {.ciphers = ptls_openssl_hpke_cipher_suites, .kems = ptls_openssl_hpke_kems},
                                          .server = {.create_opener = &ech_create_opener,
                                                     .retry_configs = {(uint8_t *)ECH_CONFIG_LIST, sizeof(ECH_CONFIG_LIST) - 1}}},
                                  .sign_certificate = &openssl_sign_certificate.super};
    ptls_context_t openssl_ctx_sha256only = openssl_ctx;
    while (openssl_ctx_sha256only.cipher_suites[0]->hash->digest_size != 32) {
        assert(openssl_ctx.cipher_suites[0]->hash->digest_size == 64 || /* sha512 */
               openssl_ctx.cipher_suites[0]->hash->digest_size == 48);  /* sha384 */
        ++openssl_ctx_sha256only.cipher_suites;
    }
    assert(openssl_ctx_sha256only.cipher_suites[0]->hash->digest_size == 32); /* sha256 */

    ctx = ctx_peer = &openssl_ctx;
    verify_certificate = &openssl_verify_certificate.super;
    ADD_FFX_AES128_ALGORITHMS(openssl);
#if PTLS_OPENSSL_HAVE_CHACHA20_POLY1305
    ADD_FFX_CHACHA20_ALGORITHMS(openssl);
#endif

    subtest("sha", test_sha);
    subtest("rsa-sign", test_rsa_sign);
    subtest("ecdsa-sign", test_ecdsa_sign);
    subtest("ed25519-sign", test_ed25519_sign);
    subtest("cert-verify", test_cert_verify);
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
    ptls_context_t minicrypto_ctx = {.random_bytes = ptls_minicrypto_random_bytes,
                                     .get_time = &ptls_get_time,
                                     .key_exchanges = ptls_minicrypto_key_exchanges,
                                     .cipher_suites = ptls_minicrypto_cipher_suites,
                                     .certificates = {&minicrypto_certificate, 1},
                                     .sign_certificate = &minicrypto_sign_certificate.super};
    ctx = &openssl_ctx;
    ctx_peer = &minicrypto_ctx;
    subtest("vs. minicrypto", test_picotls);

    ctx = &minicrypto_ctx;
    ctx_peer = &openssl_ctx;
    subtest("minicrypto vs.", test_picotls);

    subtest("hpke", test_all_hpke);

#if ASYNC_TESTS
    // switch to x25519 / aes128gcmsha256 as we run benchmarks
    static ptls_key_exchange_algorithm_t *fast_keyex[] = {&ptls_openssl_x25519, NULL}; // use x25519 for speed
    static ptls_cipher_suite_t *fast_cipher[] = {&ptls_openssl_aes128gcmsha256, NULL};
    openssl_ctx.key_exchanges = fast_keyex;
    openssl_ctx.cipher_suites = fast_cipher;
    ctx = &openssl_ctx;
    ctx_peer = &openssl_ctx;
    openssl_sign_certificate.async = 0;
    subtest("many-handshakes-non-async", many_handshakes);
    openssl_sign_certificate.async = 0;
    subtest("many-handshakes-async", many_handshakes);
    { /* qatengine should be tested at last, because we do not have the code to unload or un-default it */
        const char *engine_name = "qatengine";
        ENGINE *qatengine;
        if ((qatengine = ENGINE_by_id(engine_name)) != NULL || (qatengine = load_engine(engine_name)) != NULL) {
            ENGINE_set_default_RSA(qatengine);
            ptls_openssl_dispose_sign_certificate(&openssl_sign_certificate); // reload cert to use qatengine
            setup_sign_certificate(&openssl_sign_certificate);
            subtest("many-handshakes-qatengine", many_handshakes);
        } else {
            note("%s not found", engine_name);
        }
    }
#endif

    int ret = done_testing();
#if !defined(LIBRESSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x30000000L
    OSSL_PROVIDER_unload(dflt);
    OSSL_PROVIDER_unload(legacy);
#endif
    return ret;
}
