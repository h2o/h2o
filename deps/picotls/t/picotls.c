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
#include <string.h>
#include <stdio.h>
#include "picotls.h"
#include "picotls/ffx.h"
#include "picotls/minicrypto.h"
#include "picotls/pembase64.h"
#include "../deps/picotest/picotest.h"
#include "../lib/picotls.c"
#include "test.h"

static void test_is_ipaddr(void)
{
    ok(!ptls_server_name_is_ipaddr("www.google.com"));
    ok(!ptls_server_name_is_ipaddr("www.google.com."));
    ok(!ptls_server_name_is_ipaddr("www"));
    ok(!ptls_server_name_is_ipaddr(""));
    ok(!ptls_server_name_is_ipaddr("123"));
    ok(ptls_server_name_is_ipaddr("1.1.1.1"));
    ok(ptls_server_name_is_ipaddr("2001:db8::2:1"));
}

ptls_context_t *ctx, *ctx_peer;
ptls_verify_certificate_t *verify_certificate;
struct st_ptls_ffx_test_variants_t ffx_variants[7];

static ptls_cipher_suite_t *find_cipher(ptls_context_t *ctx, uint16_t id)
{
    ptls_cipher_suite_t **cs;
    for (cs = ctx->cipher_suites; *cs != NULL; ++cs)
        if ((*cs)->id == id)
            return *cs;
    return NULL;
}

static void test_hash(ptls_hash_algorithm_t *hash)
{
    uint8_t digest[PTLS_MAX_DIGEST_SIZE];
    int ret = ptls_calc_hash(hash, digest, "", 0);
    ok(ret == 0);
    ok(memcmp(digest, hash->empty_digest, hash->digest_size) == 0);
}

static void test_sha256(void)
{
    test_hash(find_cipher(ctx, PTLS_CIPHER_SUITE_AES_128_GCM_SHA256)->hash);
}

static void test_sha384(void)
{
    ptls_cipher_suite_t *cs = find_cipher(ctx, PTLS_CIPHER_SUITE_AES_256_GCM_SHA384);
    if (cs != NULL)
        test_hash(cs->hash);
}

static void test_hmac_sha256(void)
{
    /* test vector from RFC 4231 */
    const char *secret = "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b", *message = "Hi There",
               *expected =
                   "\xb0\x34\x4c\x61\xd8\xdb\x38\x53\x5c\xa8\xaf\xce\xaf\x0b\xf1\x2b\x88\x1d\xc2\x00\xc9\x83\x3d\xa7\x26\xe9\x37"
                   "\x6c\x2e\x32\xcf\xf7";
    uint8_t digest[32];

    ptls_hash_context_t *hctx =
        ptls_hmac_create(find_cipher(ctx, PTLS_CIPHER_SUITE_AES_128_GCM_SHA256)->hash, secret, strlen(secret));

    memset(digest, 0, sizeof(digest));
    hctx->update(hctx, message, strlen(message));
    hctx->final(hctx, digest, PTLS_HASH_FINAL_MODE_RESET);
    ok(memcmp(digest, expected, 32) == 0);

    memset(digest, 0, sizeof(digest));
    hctx->update(hctx, message, strlen(message));
    hctx->final(hctx, digest, PTLS_HASH_FINAL_MODE_RESET);
    ok(memcmp(digest, expected, 32) == 0);

    memset(digest, 0, sizeof(digest));
    hctx->update(hctx, message, strlen(message));
    hctx->final(hctx, digest, PTLS_HASH_FINAL_MODE_FREE);
    ok(memcmp(digest, expected, 32) == 0);
}

static void test_hkdf(void)
{
    ptls_hash_algorithm_t *sha256 = find_cipher(ctx, PTLS_CIPHER_SUITE_AES_128_GCM_SHA256)->hash;
    const char salt[] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c";
    const char ikm[] = "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b";
    const char info[] = "\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9";
    uint8_t prk[PTLS_MAX_DIGEST_SIZE];
    uint8_t okm[42];

    ptls_hkdf_extract(sha256, prk, ptls_iovec_init(salt, sizeof(salt) - 1), ptls_iovec_init(ikm, sizeof(ikm) - 1));
    ok(memcmp(prk,
              "\x07\x77\x09\x36\x2c\x2e\x32\xdf\x0d\xdc\x3f\x0d\xc4\x7b\xba\x63\x90\xb6\xc7\x3b\xb5\x0f\x9c\x31\x22\xec\x84"
              "\x4a\xd7\xc2\xb3\xe5",
              32) == 0);

    ptls_hkdf_expand(sha256, okm, sizeof(okm), ptls_iovec_init(prk, sha256->digest_size), ptls_iovec_init(info, sizeof(info) - 1));
    ok(memcmp(okm,
              "\x3c\xb2\x5f\x25\xfa\xac\xd5\x7a\x90\x43\x4f\x64\xd0\x36\x2f\x2a\x2d\x2d\x0a\x90\xcf\x1a\x5a\x4c\x5d\xb0\x2d"
              "\x56\xec\xc4\xc5\xbf\x34\x00\x72\x08\xd5\xb8\x87\x18\x58\x65",
              sizeof(okm)) == 0);
}

static void test_ciphersuite(ptls_cipher_suite_t *cs1, ptls_cipher_suite_t *cs2)
{
    const char *traffic_secret = "012345678901234567890123456789012345678901234567", *src1 = "hello world", *src2 = "good bye, all";
    ptls_aead_context_t *c;
    char enc1[256], enc2[256], dec1[256], dec2[256];
    size_t enc1len, enc2len, dec1len, dec2len;

    /* encrypt */
    c = ptls_aead_new(cs1->aead, cs1->hash, 1, traffic_secret, NULL);
    assert(c != NULL);
    ptls_aead_encrypt_init(c, 0, NULL, 0);
    enc1len = ptls_aead_encrypt_update(c, enc1, src1, strlen(src1));
    enc1len += ptls_aead_encrypt_final(c, enc1 + enc1len);
    ptls_aead_encrypt_init(c, 1, NULL, 0);
    enc2len = ptls_aead_encrypt_update(c, enc2, src2, strlen(src2));
    enc2len += ptls_aead_encrypt_final(c, enc2 + enc2len);
    ptls_aead_free(c);

    c = ptls_aead_new(cs2->aead, cs2->hash, 0, traffic_secret, NULL);
    assert(c != NULL);

    /* decrypt and compare */
    dec1len = ptls_aead_decrypt(c, dec1, enc1, enc1len, 0, NULL, 0);
    ok(dec1len != SIZE_MAX);
    dec2len = ptls_aead_decrypt(c, dec2, enc2, enc2len, 1, NULL, 0);
    ok(dec2len != SIZE_MAX);
    ok(strlen(src1) == dec1len);
    ok(memcmp(src1, dec1, dec1len) == 0);
    ok(strlen(src2) == dec2len);
    ok(memcmp(src2, dec2, dec2len - 1) == 0);

    /* alter and decrypt to detect failure */
    enc1[0] ^= 1;
    dec1len = ptls_aead_decrypt(c, dec1, enc1, enc1len, 0, NULL, 0);
    ok(dec1len == SIZE_MAX);

    ptls_aead_free(c);
}

static void test_aad_ciphersuite(ptls_cipher_suite_t *cs1, ptls_cipher_suite_t *cs2)
{
    const char *traffic_secret = "012345678901234567890123456789012345678901234567", *src = "hello world", *aad = "my true aad";
    ptls_aead_context_t *c;
    char enc[256], dec[256];
    size_t enclen, declen;

    /* encrypt */
    c = ptls_aead_new(cs1->aead, cs1->hash, 1, traffic_secret, NULL);
    assert(c != NULL);
    ptls_aead_encrypt_init(c, 123, aad, strlen(aad));
    enclen = ptls_aead_encrypt_update(c, enc, src, strlen(src));
    enclen += ptls_aead_encrypt_final(c, enc + enclen);
    ptls_aead_free(c);

    /* decrypt */
    c = ptls_aead_new(cs2->aead, cs2->hash, 0, traffic_secret, NULL);
    assert(c != NULL);
    declen = ptls_aead_decrypt(c, dec, enc, enclen, 123, aad, strlen(aad));
    ok(declen == strlen(src));
    ok(memcmp(src, dec, declen) == 0);
    declen = ptls_aead_decrypt(c, dec, enc, enclen, 123, "my fake aad", strlen(aad));
    ok(declen == SIZE_MAX);
    ptls_aead_free(c);
}

static void test_ecb(ptls_cipher_algorithm_t *algo, const void *expected, size_t expected_len)
{
    static const uint8_t key[] = {0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15,
                                  16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31},
                         plaintext[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                                        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};

    uint8_t *actual = malloc(expected_len);
    assert(actual != NULL);
    /* encrypt */
    memset(actual, 0, expected_len);
    ptls_cipher_context_t *ctx = ptls_cipher_new(algo, 1, key);
    ptls_cipher_encrypt(ctx, actual, plaintext, expected_len);
    ptls_cipher_free(ctx);
    ok(memcmp(actual, expected, expected_len) == 0);

    /* decrypt */
    ctx = ptls_cipher_new(algo, 0, key);
    ptls_cipher_encrypt(ctx, actual, actual, expected_len);
    ptls_cipher_free(ctx);
    ok(memcmp(actual, plaintext, expected_len) == 0);

    free(actual);
}

static void test_aes128ecb(void)
{
    static const uint8_t expected[] = {0x69, 0xC4, 0xE0, 0xD8, 0x6A, 0x7B, 0x04, 0x30,
                                       0xD8, 0xCD, 0xB7, 0x80, 0x70, 0xB4, 0xC5, 0x5A};

    test_ecb(find_cipher(ctx, PTLS_CIPHER_SUITE_AES_128_GCM_SHA256)->aead->ecb_cipher, expected, sizeof(expected));
}

static void test_aes256ecb(void)
{
    static const uint8_t expected[] = {0x8E, 0xA2, 0xB7, 0xCA, 0x51, 0x67, 0x45, 0xBF,
                                       0xEA, 0xFC, 0x49, 0x90, 0x4B, 0x49, 0x60, 0x89};
    ptls_cipher_suite_t *cipher = find_cipher(ctx, PTLS_CIPHER_SUITE_AES_256_GCM_SHA384);

    if (cipher != NULL)
        test_ecb(cipher->aead->ecb_cipher, expected, sizeof(expected));
}

static void test_ctr(ptls_cipher_suite_t *cs, const uint8_t *key, size_t key_len, const void *iv, size_t iv_len,
                     const void *expected, size_t expected_len)
{
    static const uint8_t zeroes[64] = {0};

    if (cs == NULL)
        return;

    ptls_cipher_algorithm_t *algo = cs->aead->ctr_cipher;
    uint8_t buf[sizeof(zeroes)];

    assert(expected_len <= sizeof(zeroes));
    ok(algo->key_size == key_len);
    ok(algo->iv_size == iv_len);

    ptls_cipher_context_t *ctx = ptls_cipher_new(algo, 1, key);
    assert(ctx != NULL);
    ptls_cipher_init(ctx, iv);
    ptls_cipher_encrypt(ctx, buf, zeroes, expected_len);
    ptls_cipher_free(ctx);

    ok(memcmp(buf, expected, expected_len) == 0);
}

static void test_aes128ctr(void)
{
    static const uint8_t key[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c},
                         iv[] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a},
                         expected[] = {0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60,
                                       0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97};

    test_ctr(find_cipher(ctx, PTLS_CIPHER_SUITE_AES_128_GCM_SHA256), key, sizeof(key), iv, sizeof(iv), expected, sizeof(expected));
}

static void test_chacha20(void)
{
    static const uint8_t key[] = {0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15,
                                  16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31},
                         iv[] = {1, 0, 0, 0, 0, 0, 0, 9, 0, 0, 0, 0x4a, 0, 0, 0, 0},
                         expected[] = {0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15, 0x50, 0x0f, 0xdd,
                                       0x1f, 0xa3, 0x20, 0x71, 0xc4, 0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0,
                                       0x68, 0x03, 0x04, 0x22, 0xaa, 0x9a, 0xc3, 0xd4, 0x6c, 0x4e};

    test_ctr(find_cipher(ctx, PTLS_CIPHER_SUITE_CHACHA20_POLY1305_SHA256), key, sizeof(key), iv, sizeof(iv), expected,
             sizeof(expected));
}

static void test_aes128gcm(void)
{
    ptls_cipher_suite_t *cs = find_cipher(ctx, PTLS_CIPHER_SUITE_AES_128_GCM_SHA256),
                        *cs_peer = find_cipher(ctx, PTLS_CIPHER_SUITE_AES_128_GCM_SHA256);

    test_ciphersuite(cs, cs_peer);
    test_aad_ciphersuite(cs, cs_peer);
}

static void test_aes256gcm(void)
{
    ptls_cipher_suite_t *cs = find_cipher(ctx, PTLS_CIPHER_SUITE_AES_256_GCM_SHA384),
                        *cs_peer = find_cipher(ctx, PTLS_CIPHER_SUITE_AES_256_GCM_SHA384);

    if (cs != NULL && cs_peer != NULL) {
        test_ciphersuite(cs, cs_peer);
        test_aad_ciphersuite(cs, cs_peer);
    }
}

static void test_chacha20poly1305(void)
{
    ptls_cipher_suite_t *cs = find_cipher(ctx, PTLS_CIPHER_SUITE_CHACHA20_POLY1305_SHA256),
                        *cs_peer = find_cipher(ctx, PTLS_CIPHER_SUITE_CHACHA20_POLY1305_SHA256);

    if (cs != NULL && cs_peer != NULL) {
        test_ciphersuite(cs, cs_peer);
        test_aad_ciphersuite(cs, cs_peer);
    }
}

static void test_ffx(void)
{
    static uint8_t ffx_test_source[32] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
                                          'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v'};

    static uint8_t ffx_test_key[32] = {1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15, 16,
                                       17, 18, 19, 20, 21, 22, 23, 24, 25, 27, 28, 29, 30, 31, 32};
    static uint8_t ffx_test_bad_key[32] = {0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15,
                                           16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 27, 28, 29, 30, 31};

    static uint8_t ffx_test_iv[16] = {10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25};
    static uint8_t ffx_test_bad_iv[16] = {11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26};

    static uint8_t ffx_test_mask[8] = {0x00, 0x01, 0x03, 0x07, 0x0F, 0x1F, 0x3F, 0x7F};
    ptls_cipher_context_t *ffx_enc = NULL;
    ptls_cipher_context_t *ffx_dec = NULL;
    ptls_cipher_context_t *ffx_dec_bad = NULL;
    uint8_t encrypted[32];
    uint8_t result[32];

    for (int i = 0; ffx_variants[i].algo != NULL; i++) {
        ffx_enc = ptls_cipher_new(ffx_variants[i].algo, 1, ffx_test_key);
        ffx_dec = ptls_cipher_new(ffx_variants[i].algo, 0, ffx_test_key);
        ffx_dec_bad = ptls_cipher_new(ffx_variants[i].algo, 0, ffx_test_bad_key);
        ok(ffx_enc != NULL && ffx_dec != NULL && ffx_dec_bad != NULL);
        if (ffx_enc != NULL && ffx_dec != NULL && ffx_dec_bad != NULL) {
            int bit_length = ffx_variants[i].bit_length;
            int len = (bit_length + 7) / 8;
            /* test that encoding works and last byte is correct */
            ptls_cipher_init(ffx_enc, ffx_test_iv);
            ptls_cipher_encrypt(ffx_enc, encrypted, ffx_test_source, len);
            ok((encrypted[len - 1] & ffx_test_mask[bit_length % 8]) == (ffx_test_source[len - 1] & ffx_test_mask[bit_length % 8]));
            /* Test that decoding with good key and IV works*/
            ptls_cipher_init(ffx_dec, ffx_test_iv);
            ptls_cipher_encrypt(ffx_dec, result, encrypted, len);
            ok(memcmp(ffx_test_source, result, len) == 0);
            /* Test that decoding with bad IV fails */
            ptls_cipher_init(ffx_dec, ffx_test_bad_iv);
            ptls_cipher_encrypt(ffx_dec, result, encrypted, len);
            ok(memcmp(ffx_test_source, result, len) != 0);
            /* Test that decoding with bad key fails */
            ptls_cipher_init(ffx_dec_bad, ffx_test_iv);
            ptls_cipher_encrypt(ffx_dec_bad, result, encrypted, len);
            ok(memcmp(ffx_test_source, result, len) != 0);
        }
        if (ffx_enc != NULL) {
            ptls_cipher_free(ffx_enc);
        }
        if (ffx_dec != NULL) {
            ptls_cipher_free(ffx_dec);
        }
        if (ffx_dec_bad != NULL) {
            ptls_cipher_free(ffx_dec_bad);
        }
    }

    /* Test the direct usage of the API with the "ptls_ffx_new" function.
     * The test verifies that ptls_ffx_new is compatible with
     * creating an ffx variant with the macro, then creating the cipher.
     */
    assert(ffx_variants[2].bit_length == 53); /* assumes that ffx_variants[0] is ffx_aes128ctr_b53_r4 */
    ffx_enc = ptls_ffx_new(&ptls_minicrypto_aes128ctr, 1, 4, 53, ffx_test_key);
    ffx_dec = ptls_cipher_new(ffx_variants[2].algo, 0, ffx_test_key);
    ok(ffx_enc != NULL && ffx_dec != NULL);
    if (ffx_enc != NULL && ffx_dec != NULL) {
        ptls_cipher_init(ffx_enc, ffx_test_iv);
        ptls_cipher_encrypt(ffx_enc, encrypted, ffx_test_source, 7);
        ptls_cipher_init(ffx_dec, ffx_test_iv);
        ptls_cipher_encrypt(ffx_dec, result, encrypted, 7);
        ok(memcmp(ffx_test_source, result, 7) == 0);
    }
    if (ffx_enc != NULL) {
        ptls_cipher_free(ffx_enc);
    }
    if (ffx_dec != NULL) {
        ptls_cipher_free(ffx_dec);
    }
}

static void test_base64_decode(void)
{
    ptls_base64_decode_state_t state;
    ptls_buffer_t buf;
    int ret;

    ptls_buffer_init(&buf, "", 0);

    ptls_base64_decode_init(&state);
    ret = ptls_base64_decode("aGVsbG8gd29ybGQ=", &state, &buf);
    ok(ret == 0);
    ok(buf.off == 11);
    ok(memcmp(buf.base, "hello world", 11) == 0);

    buf.off = 0;

    ptls_base64_decode_init(&state);
    ret = ptls_base64_decode("a$b", &state, &buf);
    ok(ret != 0);

    buf.off = 0;

    ptls_base64_decode_init(&state);
    ret = ptls_base64_decode("a\xFF"
                             "b",
                             &state, &buf);
    ok(ret != 0);

    ptls_buffer_dispose(&buf);
}

static struct {
    struct {
        uint8_t buf[32];
        size_t len;
        int is_end_of_record;
    } vec[16];
    size_t count;
} test_fragmented_message_queue = {{{{0}}}};

static int test_fragmented_message_record(ptls_t *tls, struct st_ptls_message_emitter_t *emitter, ptls_iovec_t message,
                                          int is_end_of_record, ptls_handshake_properties_t *properties)
{
    memcpy(test_fragmented_message_queue.vec[test_fragmented_message_queue.count].buf, message.base, message.len);
    test_fragmented_message_queue.vec[test_fragmented_message_queue.count].len = message.len;
    test_fragmented_message_queue.vec[test_fragmented_message_queue.count].is_end_of_record = is_end_of_record;
    ++test_fragmented_message_queue.count;

    return 0;
}

static void test_fragmented_message(void)
{
    ptls_context_t tlsctx = {NULL};
    ptls_t tls = {&tlsctx};
    struct st_ptls_record_t rec = {PTLS_CONTENT_TYPE_HANDSHAKE, 0x0301};
    int ret;

    tlsctx.max_buffer_size = 14;

#define SET_RECORD(lit)                                                                                                            \
    do {                                                                                                                           \
        rec.length = sizeof(lit) - 1;                                                                                              \
        rec.fragment = (const uint8_t *)(lit);                                                                                     \
    } while (0)

    /* not fragmented */
    test_fragmented_message_queue.count = 0;
    SET_RECORD("\x01\x00\x00\x03"
               "abc");
    ret = handle_handshake_record(&tls, test_fragmented_message_record, NULL, &rec, NULL);
    ok(ret == 0);
    ok(test_fragmented_message_queue.count == 1);
    ok(test_fragmented_message_queue.vec[0].len == rec.length);
    ok(memcmp(test_fragmented_message_queue.vec[0].buf, rec.fragment, rec.length) == 0);
    ok(test_fragmented_message_queue.vec[0].is_end_of_record);
    ok(tls.recvbuf.mess.base == NULL);

    /* fragmented */
    test_fragmented_message_queue.count = 0;
    SET_RECORD("\x01\x00\x00\x03"
               "a");
    ret = handle_handshake_record(&tls, test_fragmented_message_record, NULL, &rec, NULL);
    ok(ret == PTLS_ERROR_IN_PROGRESS);
    ok(tls.recvbuf.mess.base != NULL);
    ok(test_fragmented_message_queue.count == 0);
    SET_RECORD("bc\x02\x00\x00\x02"
               "de"
               "\x03");
    ret = handle_handshake_record(&tls, test_fragmented_message_record, NULL, &rec, NULL);
    ok(ret == PTLS_ERROR_IN_PROGRESS);
    ok(test_fragmented_message_queue.count == 2);
    ok(test_fragmented_message_queue.vec[0].len == 7);
    ok(memcmp(test_fragmented_message_queue.vec[0].buf,
              "\x01\x00\x00\x03"
              "abc",
              7) == 0);
    ok(!test_fragmented_message_queue.vec[0].is_end_of_record);
    ok(test_fragmented_message_queue.vec[1].len == 6);
    ok(memcmp(test_fragmented_message_queue.vec[1].buf,
              "\x02\x00\x00\x02"
              "de",
              6) == 0);
    ok(!test_fragmented_message_queue.vec[1].is_end_of_record);
    SET_RECORD("\x00\x00\x03"
               "end");
    ret = handle_handshake_record(&tls, test_fragmented_message_record, NULL, &rec, NULL);
    ok(ret == 0);
    ok(tls.recvbuf.mess.base == NULL);
    ok(test_fragmented_message_queue.count == 3);
    ok(test_fragmented_message_queue.vec[2].len == 7);
    ok(memcmp(test_fragmented_message_queue.vec[2].buf,
              "\x03\x00\x00\x03"
              "end",
              7) == 0);
    ok(test_fragmented_message_queue.vec[2].is_end_of_record);

    /* overflow (post-cb) */
    test_fragmented_message_queue.count = 0;
    SET_RECORD("\x01\x00\x00\xff"
               "0123456789ab");
    ret = handle_handshake_record(&tls, test_fragmented_message_record, NULL, &rec, NULL);
    ok(ret == PTLS_ALERT_HANDSHAKE_FAILURE);
    ok(test_fragmented_message_queue.count == 0);

    /* overflow (pre-cb) */
    SET_RECORD("\x01\x00\x00\xff"
               "0123456789");
    ret = handle_handshake_record(&tls, test_fragmented_message_record, NULL, &rec, NULL);
    ok(ret == PTLS_ERROR_IN_PROGRESS);
    SET_RECORD("abcdef");
    ret = handle_handshake_record(&tls, test_fragmented_message_record, NULL, &rec, NULL);
    ok(ret == PTLS_ALERT_HANDSHAKE_FAILURE);
    ok(test_fragmented_message_queue.count == 0);

#undef SET_RECORD
}

static int was_esni;

static int save_client_hello(ptls_on_client_hello_t *self, ptls_t *tls, ptls_on_client_hello_parameters_t *params)
{
    ptls_set_server_name(tls, (const char *)params->server_name.base, params->server_name.len);
    if (params->negotiated_protocols.count != 0)
        ptls_set_negotiated_protocol(tls, (const char *)params->negotiated_protocols.list[0].base,
                                     params->negotiated_protocols.list[0].len);
    if (params->esni)
        ++was_esni;
    return 0;
}

enum {
    TEST_HANDSHAKE_1RTT,
    TEST_HANDSHAKE_2RTT,
    TEST_HANDSHAKE_HRR,
    TEST_HANDSHAKE_HRR_STATELESS,
    TEST_HANDSHAKE_EARLY_DATA,
    TEST_HANDSHAKE_KEY_UPDATE
};

static int on_extension_cb(ptls_on_extension_t *self, ptls_t *tls, uint8_t hstype, uint16_t exttype, ptls_iovec_t extdata)
{
    assert(extdata.base);
    return 0;
}

static void test_handshake(ptls_iovec_t ticket, int mode, int expect_ticket, int check_ch, int require_client_authentication)
{
    ptls_t *client, *server;
    ptls_handshake_properties_t client_hs_prop = {{{{NULL}, ticket}}}, server_hs_prop = {{{{NULL}}}};
    uint8_t cbuf_small[16384], sbuf_small[16384], decbuf_small[16384];
    ptls_buffer_t cbuf, sbuf, decbuf;
    size_t consumed, max_early_data_size = 0;
    int ret;
    const char *req = "GET / HTTP/1.0\r\n\r\n";
    const char *resp = "HTTP/1.0 200 OK\r\n\r\nhello world\n";

    if (check_ch)
        ctx->verify_certificate = verify_certificate;

    client = ptls_new(ctx, 0);
    server = ptls_new(ctx_peer, 1);
    ptls_buffer_init(&cbuf, cbuf_small, sizeof(cbuf_small));
    ptls_buffer_init(&sbuf, sbuf_small, sizeof(sbuf_small));
    ptls_buffer_init(&decbuf, decbuf_small, sizeof(decbuf_small));

    if (check_ch) {
        static ptls_on_client_hello_t cb = {save_client_hello};
        ctx_peer->on_client_hello = &cb;
        static const ptls_iovec_t protocols[] = {{(uint8_t *)"h2", 2}, {(uint8_t *)"http/1.1", 8}};
        client_hs_prop.client.negotiated_protocols.list = protocols;
        client_hs_prop.client.negotiated_protocols.count = PTLS_ELEMENTSOF(protocols);
        ptls_set_server_name(client, "test.example.com", 0);
    }

    static ptls_on_extension_t cb = {on_extension_cb};
    ctx_peer->on_extension = &cb;

    if (require_client_authentication) {
        ctx_peer->require_client_authentication = 1;
    }

    if (ctx_peer->esni != NULL) {
        was_esni = 0;
        client_hs_prop.client.esni_keys = ptls_iovec_init(ESNIKEYS, sizeof(ESNIKEYS) - 1);
    }

    switch (mode) {
    case TEST_HANDSHAKE_HRR:
        client_hs_prop.client.negotiate_before_key_exchange = 1;
        break;
    case TEST_HANDSHAKE_HRR_STATELESS:
        client_hs_prop.client.negotiate_before_key_exchange = 1;
        server_hs_prop.server.cookie.key = "0123456789abcdef0123456789abcdef0123456789abcdef";
        server_hs_prop.server.retry_uses_cookie = 1;
        break;
    case TEST_HANDSHAKE_EARLY_DATA:
        assert(ctx_peer->max_early_data_size != 0);
        client_hs_prop.client.max_early_data_size = &max_early_data_size;
        break;
    }

    ret = ptls_handshake(client, &cbuf, NULL, NULL, &client_hs_prop);
    ok(ret == PTLS_ERROR_IN_PROGRESS);
    ok(cbuf.off != 0);

    switch (mode) {
    case TEST_HANDSHAKE_2RTT:
    case TEST_HANDSHAKE_HRR:
    case TEST_HANDSHAKE_HRR_STATELESS:
        consumed = cbuf.off;
        ret = ptls_handshake(server, &sbuf, cbuf.base, &consumed, &server_hs_prop);
        if (mode == TEST_HANDSHAKE_HRR_STATELESS) {
            ok(ret == PTLS_ERROR_STATELESS_RETRY);
            ptls_free(server);
            server = ptls_new(ctx_peer, 1);
        } else {
            ok(ret == PTLS_ERROR_IN_PROGRESS);
        }
        ok(cbuf.off == consumed);
        ok(sbuf.off != 0);
        cbuf.off = 0;
        consumed = sbuf.off;
        ret = ptls_handshake(client, &cbuf, sbuf.base, &consumed, &client_hs_prop);
        ok(ret == PTLS_ERROR_IN_PROGRESS);
        ok(sbuf.off == consumed);
        ok(cbuf.off != 0);
        sbuf.off = 0;
        break;
    case TEST_HANDSHAKE_EARLY_DATA:
        ok(max_early_data_size == ctx_peer->max_early_data_size);
        ret = ptls_send(client, &cbuf, req, strlen(req));
        ok(ret == 0);
        break;
    }

    consumed = cbuf.off;
    ret = ptls_handshake(server, &sbuf, cbuf.base, &consumed, &server_hs_prop);

    if (require_client_authentication == 1) {
        ok(ptls_is_psk_handshake(server) == 0);
        ok(ret == PTLS_ERROR_IN_PROGRESS);
    } else {
        ok(ret == 0);
    }

    ok(sbuf.off != 0);
    if (check_ch) {
        ok(ptls_get_server_name(server) != NULL);
        ok(strcmp(ptls_get_server_name(server), "test.example.com") == 0);
        ok(ptls_get_negotiated_protocol(server) != NULL);
        ok(strcmp(ptls_get_negotiated_protocol(server), "h2") == 0);
        ok(was_esni == (ctx_peer->esni != NULL));
    } else {
        ok(ptls_get_server_name(server) == NULL);
        ok(ptls_get_negotiated_protocol(server) == NULL);
    }

    if (mode == TEST_HANDSHAKE_EARLY_DATA && require_client_authentication == 0) {
        ok(consumed < cbuf.off);
        memmove(cbuf.base, cbuf.base + consumed, cbuf.off - consumed);
        cbuf.off -= consumed;

        consumed = cbuf.off;
        ret = ptls_receive(server, &decbuf, cbuf.base, &consumed);
        ok(ret == 0);
        ok(consumed == cbuf.off);
        ok(decbuf.off == strlen(req));
        ok(memcmp(decbuf.base, req, decbuf.off) == 0);
        ok(!ptls_handshake_is_complete(server));
        cbuf.off = 0;
        decbuf.off = 0;

        ret = ptls_send(server, &sbuf, resp, strlen(resp));
        ok(ret == 0);
    } else {
        ok(consumed == cbuf.off);
        cbuf.off = 0;
    }

    consumed = sbuf.off;
    ret = ptls_handshake(client, &cbuf, sbuf.base, &consumed, NULL);
    ok(ret == 0);
    ok(cbuf.off != 0);
    if (check_ch) {
        ok(ptls_get_server_name(client) != NULL);
        ok(strcmp(ptls_get_server_name(client), "test.example.com") == 0);
        ok(ptls_get_negotiated_protocol(client) != NULL);
        ok(strcmp(ptls_get_negotiated_protocol(client), "h2") == 0);
    } else {
        ok(ptls_get_server_name(server) == NULL);
        ok(ptls_get_negotiated_protocol(server) == NULL);
    }

    if (expect_ticket) {
        ok(consumed < sbuf.off);
        memmove(sbuf.base, sbuf.base + consumed, sbuf.off - consumed);
        sbuf.off -= consumed;
    } else {
        ok(consumed == sbuf.off);
        sbuf.off = 0;
    }

    if (require_client_authentication == 1) {
        ok(!ptls_handshake_is_complete(server));
        consumed = cbuf.off;
        ret = ptls_handshake(server, &sbuf, cbuf.base, &consumed, &server_hs_prop);
        ok(ret == 0);
        ok(ptls_handshake_is_complete(server));
        cbuf.off = 0;
    }

    if (mode != TEST_HANDSHAKE_EARLY_DATA || require_client_authentication == 1) {
        ret = ptls_send(client, &cbuf, req, strlen(req));
        ok(ret == 0);

        consumed = cbuf.off;
        ret = ptls_receive(server, &decbuf, cbuf.base, &consumed);
        ok(ret == 0);
        ok(consumed == cbuf.off);
        ok(decbuf.off == strlen(req));
        ok(memcmp(decbuf.base, req, strlen(req)) == 0);
        ok(ptls_handshake_is_complete(server));
        decbuf.off = 0;
        cbuf.off = 0;

        ret = ptls_send(server, &sbuf, resp, strlen(resp));
        ok(ret == 0);
    }

    consumed = sbuf.off;
    ret = ptls_receive(client, &decbuf, sbuf.base, &consumed);
    ok(ret == 0);
    ok(consumed == sbuf.off);
    ok(decbuf.off == strlen(resp));
    ok(memcmp(decbuf.base, resp, strlen(resp)) == 0);
    ok(ptls_handshake_is_complete(client));
    decbuf.off = 0;
    sbuf.off = 0;

    if (mode == TEST_HANDSHAKE_EARLY_DATA) {
        consumed = cbuf.off;
        ret = ptls_receive(server, &decbuf, cbuf.base, &consumed);
        ok(ret == 0);
        ok(cbuf.off == consumed);
        ok(decbuf.off == 0);
        ok(ptls_handshake_is_complete(client));
        cbuf.off = 0;
    }

    if (mode == TEST_HANDSHAKE_KEY_UPDATE) {
        /* server -> client with update_request */
        ret = ptls_update_key(server, 1);
        ok(ret == 0);
        ok(server->needs_key_update);
        ok(server->key_update_send_request);
        ret = ptls_send(server, &sbuf, "good bye", 8);
        ok(ret == 0);
        ok(!server->needs_key_update);
        ok(!server->key_update_send_request);
        consumed = sbuf.off;
        ret = ptls_receive(client, &decbuf, sbuf.base, &consumed);
        ok(ret == 0);
        ok(sbuf.off == consumed);
        ok(decbuf.off == 8);
        ok(memcmp(decbuf.base, "good bye", 8) == 0);
        ok(client->needs_key_update);
        ok(!client->key_update_send_request);
        sbuf.off = 0;
        decbuf.off = 0;
        ret = ptls_send(client, &cbuf, "hello", 5);
        ok(ret == 0);
        consumed = cbuf.off;
        ret = ptls_receive(server, &decbuf, cbuf.base, &consumed);
        ok(ret == 0);
        ok(cbuf.off == consumed);
        ok(decbuf.off == 5);
        ok(memcmp(decbuf.base, "hello", 5) == 0);
        cbuf.off = 0;
        decbuf.off = 0;
    }

    ptls_buffer_dispose(&cbuf);
    ptls_buffer_dispose(&sbuf);
    ptls_buffer_dispose(&decbuf);
    ptls_free(client);
    ptls_free(server);

    if (check_ch)
        ctx_peer->on_client_hello = NULL;

    ctx->verify_certificate = NULL;
    if (require_client_authentication)
        ctx_peer->require_client_authentication = 0;
}

static ptls_sign_certificate_t *sc_orig;
size_t sc_callcnt;

static int sign_certificate(ptls_sign_certificate_t *self, ptls_t *tls, uint16_t *selected_algorithm, ptls_buffer_t *output,
                            ptls_iovec_t input, const uint16_t *algorithms, size_t num_algorithms)
{
    ++sc_callcnt;
    return sc_orig->cb(sc_orig, tls, selected_algorithm, output, input, algorithms, num_algorithms);
}

static ptls_sign_certificate_t *second_sc_orig;

static int second_sign_certificate(ptls_sign_certificate_t *self, ptls_t *tls, uint16_t *selected_algorithm, ptls_buffer_t *output,
                                   ptls_iovec_t input, const uint16_t *algorithms, size_t num_algorithms)
{
    ++sc_callcnt;
    return second_sc_orig->cb(second_sc_orig, tls, selected_algorithm, output, input, algorithms, num_algorithms);
}

static void test_full_handshake_impl(int require_client_authentication)
{
    sc_callcnt = 0;

    test_handshake(ptls_iovec_init(NULL, 0), TEST_HANDSHAKE_1RTT, 0, 0, require_client_authentication);
    if (require_client_authentication) {
        ok(sc_callcnt == 2);
    } else {
        ok(sc_callcnt == 1);
    }

    test_handshake(ptls_iovec_init(NULL, 0), TEST_HANDSHAKE_1RTT, 0, 0, require_client_authentication);
    if (require_client_authentication) {
        ok(sc_callcnt == 4);
    } else {
        ok(sc_callcnt == 2);
    }

    test_handshake(ptls_iovec_init(NULL, 0), TEST_HANDSHAKE_1RTT, 0, 1, require_client_authentication);
    if (require_client_authentication) {
        ok(sc_callcnt == 6);
    } else {
        ok(sc_callcnt == 3);
    }
}

static void test_full_handshake(void)
{
    test_full_handshake_impl(0);
}

static void test_full_handshake_with_client_authentication(void)
{
    test_full_handshake_impl(1);
}

static void test_key_update(void)
{
    test_handshake(ptls_iovec_init(NULL, 0), TEST_HANDSHAKE_KEY_UPDATE, 0, 0, 0);
}

static void test_hrr_handshake(void)
{
    sc_callcnt = 0;
    test_handshake(ptls_iovec_init(NULL, 0), TEST_HANDSHAKE_HRR, 0, 0, 0);
    ok(sc_callcnt == 1);
}

static void test_hrr_stateless_handshake(void)
{
    sc_callcnt = 0;
    test_handshake(ptls_iovec_init(NULL, 0), TEST_HANDSHAKE_HRR_STATELESS, 0, 0, 0);
    ok(sc_callcnt == 1);
}

static int on_copy_ticket(ptls_encrypt_ticket_t *self, ptls_t *tls, int is_encrypt, ptls_buffer_t *dst, ptls_iovec_t src)
{
    int ret;

    if ((ret = ptls_buffer_reserve(dst, src.len)) != 0)
        return ret;
    memcpy(dst->base + dst->off, src.base, src.len);
    dst->off += src.len;

    return 0;
}

static ptls_iovec_t saved_ticket = {NULL};

static int on_save_ticket(ptls_save_ticket_t *self, ptls_t *tls, ptls_iovec_t src)
{
    saved_ticket.base = malloc(src.len);
    memcpy(saved_ticket.base, src.base, src.len);
    saved_ticket.len = src.len;
    return 0;
}

static void test_resumption_impl(int different_preferred_key_share, int require_client_authentication)
{
    assert(ctx->key_exchanges[0]->id == ctx_peer->key_exchanges[0]->id);
    assert(ctx->key_exchanges[1] == NULL);
    assert(ctx_peer->key_exchanges[1] == NULL);
    assert(ctx->key_exchanges[0]->id != ptls_minicrypto_x25519.id);
    ptls_key_exchange_algorithm_t *different_key_exchanges[] = {&ptls_minicrypto_x25519, ctx->key_exchanges[0], NULL},
                                  **key_exchanges_orig = ctx->key_exchanges;

    if (different_preferred_key_share)
        ctx->key_exchanges = different_key_exchanges;

    ptls_encrypt_ticket_t et = {on_copy_ticket};
    ptls_save_ticket_t st = {on_save_ticket};

    assert(ctx_peer->ticket_lifetime == 0);
    assert(ctx_peer->max_early_data_size == 0);
    assert(ctx_peer->encrypt_ticket == NULL);
    assert(ctx_peer->save_ticket == NULL);
    saved_ticket = ptls_iovec_init(NULL, 0);

    ctx_peer->ticket_lifetime = 86400;
    ctx_peer->max_early_data_size = 8192;
    ctx_peer->encrypt_ticket = &et;
    ctx->save_ticket = &st;

    sc_callcnt = 0;
    test_handshake(saved_ticket, different_preferred_key_share ? TEST_HANDSHAKE_2RTT : TEST_HANDSHAKE_1RTT, 1, 0, 0);
    ok(sc_callcnt == 1);
    ok(saved_ticket.base != NULL);

    /* psk using saved ticket */
    test_handshake(saved_ticket, TEST_HANDSHAKE_1RTT, 1, 0, require_client_authentication);
    if (require_client_authentication == 1) {
        ok(sc_callcnt == 3);
    } else {
        ok(sc_callcnt == 1);
    }

    /* 0-rtt psk using saved ticket */
    test_handshake(saved_ticket, TEST_HANDSHAKE_EARLY_DATA, 1, 0, require_client_authentication);
    if (require_client_authentication == 1) {
        ok(sc_callcnt == 5);
    } else {
        ok(sc_callcnt == 1);
    }

    ctx->require_dhe_on_psk = 1;

    /* psk-dhe using saved ticket */
    test_handshake(saved_ticket, TEST_HANDSHAKE_1RTT, 1, 0, require_client_authentication);
    if (require_client_authentication == 1) {
        ok(sc_callcnt == 7);
    } else {
        ok(sc_callcnt == 1);
    }

    /* 0-rtt psk-dhe using saved ticket */
    test_handshake(saved_ticket, TEST_HANDSHAKE_EARLY_DATA, 1, 0, require_client_authentication);
    if (require_client_authentication == 1) {
        ok(sc_callcnt == 9);
    } else {
        ok(sc_callcnt == 1);
    }

    ctx->require_dhe_on_psk = 0;
    ctx_peer->ticket_lifetime = 0;
    ctx_peer->max_early_data_size = 0;
    ctx_peer->encrypt_ticket = NULL;
    ctx->save_ticket = NULL;
    ctx->key_exchanges = key_exchanges_orig;
}

static void test_resumption(void)
{
    test_resumption_impl(0, 0);
}

static void test_resumption_different_preferred_key_share(void)
{
    if (ctx == ctx_peer)
        return;
    test_resumption_impl(1, 0);
}

static void test_resumption_with_client_authentication(void)
{
    test_resumption_impl(0, 1);
}

static void test_enforce_retry(int use_cookie)
{
    ptls_t *client, *server;
    ptls_handshake_properties_t server_hs_prop = {{{{NULL}}}};
    ptls_buffer_t cbuf, sbuf, decbuf;
    size_t consumed;
    int ret;

    server_hs_prop.server.cookie.key = "0123456789abcdef0123456789abcdef0123456789abcdef";
    server_hs_prop.server.cookie.additional_data = ptls_iovec_init("1.2.3.4:1234", 12);
    server_hs_prop.server.enforce_retry = 1;
    server_hs_prop.server.retry_uses_cookie = use_cookie;

    ptls_buffer_init(&cbuf, "", 0);
    ptls_buffer_init(&sbuf, "", 0);
    ptls_buffer_init(&decbuf, "", 0);

    client = ptls_new(ctx, 0);

    ret = ptls_handshake(client, &cbuf, NULL, NULL, NULL);
    ok(ret == PTLS_ERROR_IN_PROGRESS);
    ok(cbuf.off != 0);

    server = ptls_new(ctx, 1);

    consumed = cbuf.off;
    ret = ptls_handshake(server, &sbuf, cbuf.base, &consumed, &server_hs_prop);
    cbuf.off = 0;

    if (use_cookie) {
        ok(ret == PTLS_ERROR_STATELESS_RETRY);
        ptls_free(server);
        server = ptls_new(ctx, 1);
    } else {
        ok(ret == PTLS_ERROR_IN_PROGRESS);
    }

    consumed = sbuf.off;
    ret = ptls_handshake(client, &cbuf, sbuf.base, &consumed, NULL);
    ok(ret == PTLS_ERROR_IN_PROGRESS);
    ok(sbuf.off == consumed);
    sbuf.off = 0;

    consumed = cbuf.off;
    ret = ptls_handshake(server, &sbuf, cbuf.base, &consumed, &server_hs_prop);
    ok(ret == 0);
    ok(cbuf.off == consumed);
    cbuf.off = 0;

    consumed = sbuf.off;
    ret = ptls_handshake(client, &cbuf, sbuf.base, &consumed, NULL);
    ok(ret == 0);
    ok(sbuf.off == consumed);
    sbuf.off = 0;

    ret = ptls_send(client, &cbuf, "hello world", 11);
    ok(ret == 0);

    consumed = cbuf.off;
    ret = ptls_receive(server, &decbuf, cbuf.base, &consumed);
    ok(ret == 0);
    ok(cbuf.off == consumed);
    cbuf.off = 0;

    ok(decbuf.off == 11);
    ok(memcmp(decbuf.base, "hello world", 11) == 0);
    decbuf.off = 0;

    ptls_free(client);
    ptls_free(server);

    ptls_buffer_dispose(&cbuf);
    ptls_buffer_dispose(&sbuf);
    ptls_buffer_dispose(&decbuf);
}

static void test_enforce_retry_stateful(void)
{
    test_enforce_retry(0);
}

static void test_enforce_retry_stateless(void)
{
    test_enforce_retry(1);
}

static ptls_t *stateless_hrr_prepare(ptls_buffer_t *sbuf, ptls_handshake_properties_t *server_hs_prop)
{
    ptls_t *client = ptls_new(ctx, 0), *server = ptls_new(ctx_peer, 1);
    ptls_buffer_t cbuf;
    size_t consumed;
    int ret;

    ptls_buffer_init(&cbuf, "", 0);
    ptls_buffer_init(sbuf, "", 0);

    ret = ptls_handshake(client, &cbuf, NULL, NULL, NULL);
    ok(ret == PTLS_ERROR_IN_PROGRESS);

    consumed = cbuf.off;
    ret = ptls_handshake(server, sbuf, cbuf.base, &consumed, server_hs_prop);
    ok(ret == PTLS_ERROR_STATELESS_RETRY);

    ptls_buffer_dispose(&cbuf);
    ptls_free(server);

    return client;
}

static void test_stateless_hrr_aad_change(void)
{
    ptls_t *client, *server;
    ptls_handshake_properties_t server_hs_prop = {{{{NULL}}}};
    ptls_buffer_t cbuf, sbuf;
    size_t consumed;
    int ret;

    server_hs_prop.server.cookie.key = "0123456789abcdef0123456789abcdef0123456789abcdef";
    server_hs_prop.server.cookie.additional_data = ptls_iovec_init("1.2.3.4:1234", 12);
    server_hs_prop.server.enforce_retry = 1;
    server_hs_prop.server.retry_uses_cookie = 1;

    client = stateless_hrr_prepare(&sbuf, &server_hs_prop);
    ptls_buffer_init(&cbuf, "", 0);

    consumed = sbuf.off;
    ret = ptls_handshake(client, &cbuf, sbuf.base, &consumed, NULL);
    ok(ret == PTLS_ERROR_IN_PROGRESS);
    ok(sbuf.off == consumed);
    sbuf.off = 0;

    server = ptls_new(ctx_peer, 1);
    server_hs_prop.server.cookie.additional_data = ptls_iovec_init("1.2.3.4:4321", 12);

    consumed = cbuf.off;
    ret = ptls_handshake(server, &sbuf, cbuf.base, &consumed, &server_hs_prop);
    ok(ret == PTLS_ALERT_HANDSHAKE_FAILURE);

    ptls_free(client);
    ptls_free(server);

    ptls_buffer_dispose(&cbuf);
    ptls_buffer_dispose(&sbuf);
}

typedef uint8_t traffic_secrets_t[2 /* is_enc */][4 /* epoch */][PTLS_MAX_DIGEST_SIZE /* octets */];

static int on_update_traffic_key(ptls_update_traffic_key_t *self, ptls_t *tls, int is_enc, size_t epoch, const void *secret)
{
    traffic_secrets_t *secrets = *ptls_get_data_ptr(tls);
    ok(memcmp((*secrets)[is_enc][epoch], zeroes_of_max_digest_size, PTLS_MAX_DIGEST_SIZE) == 0);

    size_t size = ptls_get_cipher(tls)->hash->digest_size;
    memcpy((*secrets)[is_enc][epoch], secret, size);
    return 0;
}

static int feed_messages(ptls_t *tls, ptls_buffer_t *outbuf, size_t *out_epoch_offsets, const uint8_t *input,
                         const size_t *in_epoch_offsets, ptls_handshake_properties_t *props)
{
    size_t i;
    int ret = PTLS_ERROR_IN_PROGRESS;

    outbuf->off = 0;
    memset(out_epoch_offsets, 0, sizeof(*out_epoch_offsets) * 5);

    for (i = 0; i != 4; ++i) {
        size_t len = in_epoch_offsets[i + 1] - in_epoch_offsets[i];
        if (len != 0) {
            ret = ptls_handle_message(tls, outbuf, out_epoch_offsets, i, input + in_epoch_offsets[i], len, props);
            if (!(ret == 0 || ret == PTLS_ERROR_IN_PROGRESS))
                break;
        }
    }

    return ret;
}

static void test_handshake_api(void)
{
    ptls_t *client, *server;
    traffic_secrets_t client_secrets = {{{0}}}, server_secrets = {{{0}}};
    ptls_buffer_t cbuf, sbuf;
    size_t coffs[5] = {0}, soffs[5];
    ptls_update_traffic_key_t update_traffic_key = {on_update_traffic_key};
    ptls_encrypt_ticket_t encrypt_ticket = {on_copy_ticket};
    ptls_save_ticket_t save_ticket = {on_save_ticket};
    int ret;

    ctx->update_traffic_key = &update_traffic_key;
    ctx->omit_end_of_early_data = 1;
    ctx->save_ticket = &save_ticket;
    ctx_peer->update_traffic_key = &update_traffic_key;
    ctx_peer->omit_end_of_early_data = 1;
    ctx_peer->encrypt_ticket = &encrypt_ticket;
    ctx_peer->ticket_lifetime = 86400;
    ctx_peer->max_early_data_size = 8192;

    saved_ticket = ptls_iovec_init(NULL, 0);

    ptls_buffer_init(&cbuf, "", 0);
    ptls_buffer_init(&sbuf, "", 0);

    client = ptls_new(ctx, 0);
    *ptls_get_data_ptr(client) = &client_secrets;
    server = ptls_new(ctx_peer, 1);
    *ptls_get_data_ptr(server) = &server_secrets;

    /* full handshake */
    ret = ptls_handle_message(client, &cbuf, coffs, 0, NULL, 0, NULL);
    ok(ret == PTLS_ERROR_IN_PROGRESS);
    ret = feed_messages(server, &sbuf, soffs, cbuf.base, coffs, NULL);
    ok(ret == 0);
    ok(sbuf.off != 0);
    ok(!ptls_handshake_is_complete(server));
    ok(memcmp(server_secrets[1][2], zeroes_of_max_digest_size, PTLS_MAX_DIGEST_SIZE) != 0);
    ok(memcmp(server_secrets[1][3], zeroes_of_max_digest_size, PTLS_MAX_DIGEST_SIZE) != 0);
    ok(memcmp(server_secrets[0][2], zeroes_of_max_digest_size, PTLS_MAX_DIGEST_SIZE) != 0);
    ok(memcmp(server_secrets[0][3], zeroes_of_max_digest_size, PTLS_MAX_DIGEST_SIZE) == 0);
    ret = feed_messages(client, &cbuf, coffs, sbuf.base, soffs, NULL);
    ok(ret == 0);
    ok(cbuf.off != 0);
    ok(ptls_handshake_is_complete(client));
    ok(memcmp(client_secrets[0][2], server_secrets[1][2], PTLS_MAX_DIGEST_SIZE) == 0);
    ok(memcmp(client_secrets[1][2], server_secrets[0][2], PTLS_MAX_DIGEST_SIZE) == 0);
    ok(memcmp(client_secrets[0][3], server_secrets[1][3], PTLS_MAX_DIGEST_SIZE) == 0);
    ok(memcmp(client_secrets[1][3], zeroes_of_max_digest_size, PTLS_MAX_DIGEST_SIZE) != 0);
    ret = feed_messages(server, &sbuf, soffs, cbuf.base, coffs, NULL);
    ok(ret == 0);
    ok(sbuf.off == 0);
    ok(ptls_handshake_is_complete(server));
    ok(memcmp(client_secrets[1][3], server_secrets[0][3], PTLS_MAX_DIGEST_SIZE) == 0);

    ptls_free(client);
    ptls_free(server);

    cbuf.off = 0;
    sbuf.off = 0;
    memset(client_secrets, 0, sizeof(client_secrets));
    memset(server_secrets, 0, sizeof(server_secrets));
    memset(coffs, 0, sizeof(coffs));
    memset(soffs, 0, sizeof(soffs));

    ctx->save_ticket = NULL; /* don't allow further test to update the saved ticket */

    /* 0-RTT resumption */
    size_t max_early_data_size = 0;
    ptls_handshake_properties_t client_hs_prop = {{{{NULL}, saved_ticket, &max_early_data_size}}};
    client = ptls_new(ctx, 0);
    *ptls_get_data_ptr(client) = &client_secrets;
    server = ptls_new(ctx_peer, 1);
    *ptls_get_data_ptr(server) = &server_secrets;
    ret = ptls_handle_message(client, &cbuf, coffs, 0, NULL, 0, &client_hs_prop);
    ok(ret == PTLS_ERROR_IN_PROGRESS);
    ok(max_early_data_size != 0);
    ok(memcmp(client_secrets[1][1], zeroes_of_max_digest_size, PTLS_MAX_DIGEST_SIZE) != 0);
    ret = feed_messages(server, &sbuf, soffs, cbuf.base, coffs, NULL);
    ok(ret == 0);
    ok(sbuf.off != 0);
    ok(!ptls_handshake_is_complete(server));
    ok(memcmp(client_secrets[1][1], server_secrets[0][1], PTLS_MAX_DIGEST_SIZE) == 0);
    ok(memcmp(server_secrets[0][2], zeroes_of_max_digest_size, PTLS_MAX_DIGEST_SIZE) != 0); /* !!!overlap!!! */
    ok(memcmp(server_secrets[1][2], zeroes_of_max_digest_size, PTLS_MAX_DIGEST_SIZE) != 0);
    ok(memcmp(server_secrets[1][3], zeroes_of_max_digest_size, PTLS_MAX_DIGEST_SIZE) != 0);
    ok(memcmp(server_secrets[0][3], zeroes_of_max_digest_size, PTLS_MAX_DIGEST_SIZE) == 0);
    ret = feed_messages(client, &cbuf, coffs, sbuf.base, soffs, &client_hs_prop);
    ok(ret == 0);
    ok(cbuf.off != 0);
    ok(ptls_handshake_is_complete(client));
    ok(memcmp(client_secrets[0][3], server_secrets[1][3], PTLS_MAX_DIGEST_SIZE) == 0);
    ok(memcmp(client_secrets[1][3], zeroes_of_max_digest_size, PTLS_MAX_DIGEST_SIZE) != 0);
    ret = feed_messages(server, &sbuf, soffs, cbuf.base, coffs, NULL);
    ok(ret == 0);
    ok(sbuf.off == 0);
    ok(ptls_handshake_is_complete(server));
    ok(memcmp(server_secrets[0][3], zeroes_of_max_digest_size, PTLS_MAX_DIGEST_SIZE) != 0);

    ptls_free(client);
    ptls_free(server);

    cbuf.off = 0;
    sbuf.off = 0;
    memset(client_secrets, 0, sizeof(client_secrets));
    memset(server_secrets, 0, sizeof(server_secrets));
    memset(coffs, 0, sizeof(coffs));
    memset(soffs, 0, sizeof(soffs));

    /* 0-RTT rejection */
    ctx_peer->max_early_data_size = 0;
    client_hs_prop = (ptls_handshake_properties_t){{{{NULL}, saved_ticket, &max_early_data_size}}};
    client = ptls_new(ctx, 0);
    *ptls_get_data_ptr(client) = &client_secrets;
    server = ptls_new(ctx_peer, 1);
    *ptls_get_data_ptr(server) = &server_secrets;
    ret = ptls_handle_message(client, &cbuf, coffs, 0, NULL, 0, &client_hs_prop);
    ok(ret == PTLS_ERROR_IN_PROGRESS);
    ok(max_early_data_size != 0);
    ok(memcmp(client_secrets[1][1], zeroes_of_max_digest_size, PTLS_MAX_DIGEST_SIZE) != 0);
    ret = feed_messages(server, &sbuf, soffs, cbuf.base, coffs, NULL);
    ok(ret == 0);
    ok(sbuf.off != 0);
    ok(!ptls_handshake_is_complete(server));
    ret = feed_messages(client, &cbuf, coffs, sbuf.base, soffs, &client_hs_prop);
    ok(ret == 0);
    ok(cbuf.off != 0);
    ok(ptls_handshake_is_complete(client));
    ok(client_hs_prop.client.early_data_acceptance == PTLS_EARLY_DATA_REJECTED);
    ok(memcmp(server_secrets[0][1], zeroes_of_max_digest_size, PTLS_MAX_DIGEST_SIZE) == 0);
    ret = feed_messages(server, &sbuf, soffs, cbuf.base, coffs, NULL);
    ok(ret == 0);
    ok(sbuf.off == 0);
    ok(ptls_handshake_is_complete(server));

    ptls_free(client);
    ptls_free(server);

    cbuf.off = 0;
    sbuf.off = 0;
    memset(client_secrets, 0, sizeof(client_secrets));
    memset(server_secrets, 0, sizeof(server_secrets));
    memset(coffs, 0, sizeof(coffs));
    memset(soffs, 0, sizeof(soffs));

    /* HRR rejects 0-RTT */
    ctx_peer->max_early_data_size = 8192;
    ptls_handshake_properties_t server_hs_prop = {{{{NULL}}}};
    server_hs_prop.server.enforce_retry = 1;
    client_hs_prop = (ptls_handshake_properties_t){{{{NULL}, saved_ticket, &max_early_data_size}}};
    client = ptls_new(ctx, 0);
    *ptls_get_data_ptr(client) = &client_secrets;
    server = ptls_new(ctx_peer, 1);
    *ptls_get_data_ptr(server) = &server_secrets;
    ret = ptls_handle_message(client, &cbuf, coffs, 0, NULL, 0, &client_hs_prop); /* -> CH */
    ok(ret == PTLS_ERROR_IN_PROGRESS);
    ok(max_early_data_size != 0);
    ok(memcmp(client_secrets[1][1], zeroes_of_max_digest_size, PTLS_MAX_DIGEST_SIZE) != 0);
    ret = feed_messages(server, &sbuf, soffs, cbuf.base, coffs, &server_hs_prop); /* CH -> HRR */
    ok(ret == PTLS_ERROR_IN_PROGRESS);
    ok(sbuf.off != 0);
    ok(!ptls_handshake_is_complete(server));
    ret = feed_messages(client, &cbuf, coffs, sbuf.base, soffs, &client_hs_prop); /* HRR  -> CH */
    ok(ret == PTLS_ERROR_IN_PROGRESS);
    ok(cbuf.off != 0);
    ok(!ptls_handshake_is_complete(client));
    ok(client_hs_prop.client.early_data_acceptance == PTLS_EARLY_DATA_REJECTED);
    ret = feed_messages(server, &sbuf, soffs, cbuf.base, coffs, &server_hs_prop); /* CH -> SH..SF */
    ok(ret == 0);
    ok(!ptls_handshake_is_complete(server));
    ok(memcmp(server_secrets[0][1], zeroes_of_max_digest_size, PTLS_MAX_DIGEST_SIZE) == 0);
    ok(sbuf.off != 0);
    ret = feed_messages(client, &cbuf, coffs, sbuf.base, soffs, &client_hs_prop); /* SH..SF -> CF */
    ok(ret == 0);
    ok(ptls_handshake_is_complete(client));
    ok(cbuf.off != 0);
    ret = feed_messages(server, &sbuf, soffs, cbuf.base, coffs, &server_hs_prop); /* CF -> */
    ok(ret == 0);
    ok(ptls_handshake_is_complete(server));

    ptls_free(client);
    ptls_free(server);

    cbuf.off = 0;
    sbuf.off = 0;

    /* shamelessly reuse this subtest for testing ordinary TLS 0-RTT with HRR rejection */
    ctx->update_traffic_key = NULL;
    ctx->omit_end_of_early_data = 0;
    ctx_peer->update_traffic_key = NULL;
    ctx_peer->omit_end_of_early_data = 0;
    client_hs_prop = (ptls_handshake_properties_t){{{{NULL}, saved_ticket, &max_early_data_size}}};
    server_hs_prop = (ptls_handshake_properties_t){{{{NULL}}}};
    server_hs_prop.server.enforce_retry = 1;
    client = ptls_new(ctx, 0);
    server = ptls_new(ctx_peer, 1);
    ret = ptls_handshake(client, &cbuf, NULL, NULL, &client_hs_prop); /* -> CH */
    ok(ret == PTLS_ERROR_IN_PROGRESS);
    ok(client_hs_prop.client.max_early_data_size != 0);
    ok(client_hs_prop.client.early_data_acceptance == PTLS_EARLY_DATA_ACCEPTANCE_UNKNOWN);
    ok(cbuf.off != 0);
    ret = ptls_send(client, &cbuf, "hello world", 11); /* send 0-RTT data that'll be rejected */
    ok(ret == 0);
    size_t inlen = cbuf.off;
    ret = ptls_handshake(server, &sbuf, cbuf.base, &inlen, &server_hs_prop); /* CH -> HRR */
    ok(ret == PTLS_ERROR_IN_PROGRESS);
    ok(cbuf.off == inlen);
    cbuf.off = 0;
    ok(sbuf.off != 0);
    inlen = sbuf.off;
    ret = ptls_handshake(client, &cbuf, sbuf.base, &inlen, &client_hs_prop); /* HRR -> CH */
    ok(ret == PTLS_ERROR_IN_PROGRESS);
    ok(client_hs_prop.client.early_data_acceptance == PTLS_EARLY_DATA_REJECTED);
    ok(sbuf.off == inlen);
    sbuf.off = 0;
    ok(cbuf.off != 0);
    inlen = cbuf.off;
    ret = ptls_handshake(server, &sbuf, cbuf.base, &inlen, &server_hs_prop); /* CH -> SH..SF,NST */
    ok(ret == 0);
    ok(!ptls_handshake_is_complete(server));
    ok(cbuf.off == inlen);
    cbuf.off = 0;
    ok(sbuf.off != 0);
    inlen = sbuf.off;
    ret = ptls_handshake(client, &cbuf, sbuf.base, &inlen, &client_hs_prop); /* SH..SF -> CF */
    ok(ret == 0);
    ok(ptls_handshake_is_complete(client));
    ok(inlen < sbuf.off); /* ignore NST */
    sbuf.off = 0;
    inlen = cbuf.off;
    ret = ptls_handshake(server, &sbuf, cbuf.base, &inlen, &server_hs_prop); /* CF -> */
    ok(ret == 0);
    ok(ptls_handshake_is_complete(server));
    ok(sbuf.off == 0);

    ptls_free(client);
    ptls_free(server);

    ptls_buffer_dispose(&cbuf);
    ptls_buffer_dispose(&sbuf);

    ctx->update_traffic_key = NULL;
    ctx->omit_end_of_early_data = 0;
    ctx->save_ticket = NULL;
    ctx_peer->update_traffic_key = NULL;
    ctx_peer->omit_end_of_early_data = 0;
    ctx_peer->encrypt_ticket = NULL;
    ctx_peer->save_ticket = NULL;
    ctx_peer->ticket_lifetime = 0;
    ctx_peer->max_early_data_size = 0;
}

static void test_all_handshakes(void)
{
    ptls_sign_certificate_t server_sc = {sign_certificate};
    sc_orig = ctx_peer->sign_certificate;
    ctx_peer->sign_certificate = &server_sc;

    ptls_sign_certificate_t client_sc = {second_sign_certificate};
    if (ctx_peer != ctx) {
        second_sc_orig = ctx->sign_certificate;
        ctx->sign_certificate = &client_sc;
    }

    subtest("full-handshake", test_full_handshake);
    subtest("full-handshake-with-client-authentication", test_full_handshake_with_client_authentication);
    subtest("hrr-handshake", test_hrr_handshake);
    subtest("hrr-stateless-handshake", test_hrr_stateless_handshake);
    subtest("resumption", test_resumption);
    subtest("resumption-different-preferred-key-share", test_resumption_different_preferred_key_share);
    subtest("resumption-with-client-authentication", test_resumption_with_client_authentication);

    subtest("enforce-retry-stateful", test_enforce_retry_stateful);
    subtest("enforce-retry-stateless", test_enforce_retry_stateless);

    subtest("stateless-hrr-aad-change", test_stateless_hrr_aad_change);

    subtest("key-update", test_key_update);

    subtest("handshake-api", test_handshake_api);

    ctx_peer->sign_certificate = sc_orig;

    if (ctx_peer != ctx)
        ctx->sign_certificate = second_sc_orig;
}

static void test_quicint(void)
{
#define CHECK_PATTERN(output, ...)                                                                                                 \
    do {                                                                                                                           \
        const uint8_t pat[] = {__VA_ARGS__}, *p = pat;                                                                             \
        ok(output == ptls_decode_quicint(&p, pat + sizeof(pat)));                                                                  \
        ok(p == pat + sizeof(pat));                                                                                                \
    } while (0)
    CHECK_PATTERN(0, 0);
    CHECK_PATTERN(0, 0x40, 0);
    CHECK_PATTERN(0, 0x80, 0, 0, 0);
    CHECK_PATTERN(0, 0xc0, 0, 0, 0, 0, 0, 0, 0);
    CHECK_PATTERN(9, 9);
    CHECK_PATTERN(9, 0x40, 9);
    CHECK_PATTERN(9, 0x80, 0, 0, 9);
    CHECK_PATTERN(9, 0xc0, 0, 0, 0, 0, 0, 0, 9);
    CHECK_PATTERN(0x1234, 0x52, 0x34);
    CHECK_PATTERN(0x1234, 0x80, 0, 0x12, 0x34);
    CHECK_PATTERN(0x1234, 0xc0, 0, 0, 0, 0, 0, 0x12, 0x34);
    CHECK_PATTERN(0x12345678, 0x92, 0x34, 0x56, 0x78);
    CHECK_PATTERN(0x12345678, 0xc0, 0, 0, 0, 0x12, 0x34, 0x56, 0x78);
    CHECK_PATTERN(0x123456789abcdef, 0xc1, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef);
#undef CHECK_PATTERN

    static uint64_t inputs[] = {0, 1, 63, 64, 16383, 16384, 1073741823, 1073741824, UINT64_MAX};
    size_t i;

    for (i = 0; inputs[i] != UINT64_MAX; ++i) {
        uint8_t buf[PTLS_ENCODE_QUICINT_CAPACITY + 1];
        memset(buf, 123, sizeof(buf));
        uint8_t *enc_end = ptls_encode_quicint(buf, inputs[i]);
        assert(enc_end - buf <= PTLS_ENCODE_QUICINT_CAPACITY);
        const uint8_t *src = buf;
        uint64_t decoded = ptls_decode_quicint(&src, buf + sizeof(buf));
        ok(inputs[i] == decoded);
        ok(src == enc_end);
        ok(*src == 123);
    }
}

static void test_quicblock(void)
{
    ptls_buffer_t buf;
    const uint8_t *src, *end;
    int ret;

    ptls_buffer_init(&buf, "", 0);

    ptls_buffer_push_block(&buf, -1, { ptls_buffer_pushv(&buf, "abc", 3); });
    src = buf.base;
    end = buf.base + buf.off;
    ptls_decode_block(src, end, -1, {
        ok(end - src == 3);
        ok(memcmp(src, "abc", 3) == 0);
        src += 3;
    });

    buf.off = 0;
    ptls_buffer_push_block(&buf, -1, {
        if ((ret = ptls_buffer_reserve(&buf, 123)) != 0)
            goto Exit;
        memset(buf.base + buf.off, 0x55, 123);
        buf.off += 123;
    });
    src = buf.base;
    end = buf.base + buf.off;
    ptls_decode_block(src, end, -1, {
        ok(end - src == 123);
        size_t i;
        for (i = 0; i != 123; ++i)
            ok(*src++ == 0x55);
    });

Exit:
    if (ret != 0)
        ok(!"fail");
    ptls_buffer_dispose(&buf);
}

static void test_quic(void)
{
    subtest("varint", test_quicint);
    subtest("block", test_quicblock);
}

static int test_legacy_ch_callback_called = 0;

static const uint8_t legacy_ch_tls12[] = {
    0x16, 0x03, 0x01, 0x00, 0xd2, 0x01, 0x00, 0x00, 0xce, 0x03, 0x03, 0xd1, 0x01, 0x0e, 0x39, 0xea, 0x22, 0x28, 0x89, 0x99,
    0x42, 0xec, 0x70, 0xfa, 0xb3, 0x47, 0x01, 0xce, 0x61, 0x8d, 0xee, 0x0e, 0x3e, 0xf7, 0xe9, 0x4f, 0x0a, 0x8e, 0x94, 0x28,
    0xe5, 0xe3, 0xd3, 0x00, 0x00, 0x5c, 0xc0, 0x30, 0xc0, 0x2c, 0xc0, 0x28, 0xc0, 0x24, 0xc0, 0x14, 0xc0, 0x0a, 0x00, 0x9f,
    0x00, 0x6b, 0x00, 0x39, 0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0xaa, 0xff, 0x85, 0x00, 0xc4, 0x00, 0x88, 0x00, 0x81, 0x00, 0x9d,
    0x00, 0x3d, 0x00, 0x35, 0x00, 0xc0, 0x00, 0x84, 0xc0, 0x2f, 0xc0, 0x2b, 0xc0, 0x27, 0xc0, 0x23, 0xc0, 0x13, 0xc0, 0x09,
    0x00, 0x9e, 0x00, 0x67, 0x00, 0x33, 0x00, 0xbe, 0x00, 0x45, 0x00, 0x9c, 0x00, 0x3c, 0x00, 0x2f, 0x00, 0xba, 0x00, 0x41,
    0xc0, 0x11, 0xc0, 0x07, 0x00, 0x05, 0x00, 0x04, 0xc0, 0x12, 0xc0, 0x08, 0x00, 0x16, 0x00, 0x0a, 0x00, 0xff, 0x01, 0x00,
    0x00, 0x49, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x0d, 0x00, 0x00, 0x0a, 0x69, 0x5f, 0x6e, 0x65, 0x65, 0x64, 0x5f, 0x73, 0x6e,
    0x69, 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x06, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00,
    0x23, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x1c, 0x00, 0x1a, 0x06, 0x01, 0x06, 0x03, 0xef, 0xef, 0x05, 0x01, 0x05, 0x03, 0x04,
    0x01, 0x04, 0x03, 0xee, 0xee, 0xed, 0xed, 0x03, 0x01, 0x03, 0x03, 0x02, 0x01, 0x02, 0x03};

static int test_legacy_ch_tls12_callback(ptls_on_client_hello_t *self, ptls_t *tls, ptls_on_client_hello_parameters_t *params)
{
    test_legacy_ch_callback_called = 1;
    ok(params->incompatible_version);
    ok(sizeof(legacy_ch_tls12) - 5 == params->raw_message.len);
    ok(memcmp(legacy_ch_tls12 + 5, params->raw_message.base, params->raw_message.len) == 0);
    ok(params->server_name.len == sizeof("i-need_sni") - 1);
    ok(memcmp(params->server_name.base, "i_need_sni", sizeof("i-need_sni") - 1) == 0);
    return 0;
}

static const uint8_t legacy_ch_tls11[] = {
    0x16, 0x03, 0x01, 0x00, 0x71, 0x01, 0x00, 0x00, 0x6d, 0x03, 0x02, 0xa5, 0xac, 0xfc, 0xef, 0x36, 0xa0, 0x4e, 0x1b, 0xa1,
    0x9d, 0x01, 0x98, 0x3e, 0xae, 0x07, 0x2e, 0x23, 0xdc, 0xce, 0x62, 0xc8, 0xb6, 0x7e, 0xd0, 0x5c, 0x2e, 0xeb, 0x63, 0x26,
    0x74, 0xe7, 0x61, 0x00, 0x00, 0x2e, 0xc0, 0x14, 0xc0, 0x0a, 0x00, 0x39, 0xff, 0x85, 0x00, 0x88, 0x00, 0x81, 0x00, 0x35,
    0x00, 0x84, 0xc0, 0x13, 0xc0, 0x09, 0x00, 0x33, 0x00, 0x45, 0x00, 0x2f, 0x00, 0x41, 0xc0, 0x11, 0xc0, 0x07, 0x00, 0x05,
    0x00, 0x04, 0xc0, 0x12, 0xc0, 0x08, 0x00, 0x16, 0x00, 0x0a, 0x00, 0xff, 0x01, 0x00, 0x00, 0x16, 0x00, 0x0b, 0x00, 0x02,
    0x01, 0x00, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x06, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x23, 0x00, 0x00};

static int test_legacy_ch_tls11_callback(ptls_on_client_hello_t *self, ptls_t *tls, ptls_on_client_hello_parameters_t *params)
{
    test_legacy_ch_callback_called = 1;
    ok(params->incompatible_version);
    ok(sizeof(legacy_ch_tls11) - 5 == params->raw_message.len);
    ok(memcmp(legacy_ch_tls11 + 5, params->raw_message.base, params->raw_message.len) == 0);
    ok(params->server_name.len == 0);
    ok(params->server_name.base == NULL);
    return 0;
}

static void test_tls12_hello(void)
{
    ptls_on_client_hello_t on_client_hello = {test_legacy_ch_tls12_callback}, *orig = ctx->on_client_hello;
    ctx->on_client_hello = &on_client_hello;

    ptls_buffer_t sendbuf;
    ptls_buffer_init(&sendbuf, "", 0);

    test_legacy_ch_callback_called = 0;
    ptls_t *tls = ptls_new(ctx, 1);
    size_t len = sizeof(legacy_ch_tls12);
    int ret = ptls_handshake(tls, &sendbuf, legacy_ch_tls12, &len, NULL);
    ptls_free(tls);
    ok(ret == PTLS_ALERT_PROTOCOL_VERSION);
    ok(test_legacy_ch_callback_called);

    on_client_hello.cb = test_legacy_ch_tls11_callback;
    test_legacy_ch_callback_called = 0;
    tls = ptls_new(ctx, 1);
    len = sizeof(legacy_ch_tls11);
    ret = ptls_handshake(tls, &sendbuf, legacy_ch_tls11, &len, NULL);
    ptls_free(tls);
    ok(ret == PTLS_ALERT_PROTOCOL_VERSION);

    ctx->on_client_hello = orig;
}

void test_picotls(void)
{
    subtest("is_ipaddr", test_is_ipaddr);
    subtest("sha256", test_sha256);
    subtest("sha384", test_sha384);
    subtest("hmac-sha256", test_hmac_sha256);
    subtest("hkdf", test_hkdf);
    subtest("aes128gcm", test_aes128gcm);
    subtest("aes256gcm", test_aes256gcm);
    subtest("chacha20poly1305", test_chacha20poly1305);
    subtest("aes128ecb", test_aes128ecb);
    subtest("aes256ecb", test_aes256ecb);
    subtest("aes128ctr", test_aes128ctr);
    subtest("chacha20", test_chacha20);
    subtest("ffx", test_ffx);
    subtest("base64-decode", test_base64_decode);
    subtest("fragmented-message", test_fragmented_message);
    subtest("handshake", test_all_handshakes);
    subtest("quic", test_quic);
    subtest("tls12-hello", test_tls12_hello);
}

void test_picotls_esni(ptls_key_exchange_context_t **keys)
{
    ptls_esni_context_t esni, *esni_list[] = {&esni, NULL};
    ptls_esni_init_context(ctx_peer, &esni, ptls_iovec_init(ESNIKEYS, sizeof(ESNIKEYS) - 1), keys);
    ctx_peer->esni = esni_list;

    subtest("esni-handshake", test_picotls);

    ctx_peer->esni = NULL;
}

void test_key_exchange(ptls_key_exchange_algorithm_t *client, ptls_key_exchange_algorithm_t *server)
{
    ptls_key_exchange_context_t *ctx;
    ptls_iovec_t client_secret, server_pubkey, server_secret;
    int ret;

    /* fail */
    ret = server->exchange(server, &server_pubkey, &server_secret, (ptls_iovec_t){NULL});
    ok(ret != 0);

    /* perform ecdh */
    ret = client->create(client, &ctx);
    ok(ret == 0);
    ret = server->exchange(server, &server_pubkey, &server_secret, ctx->pubkey);
    ok(ret == 0);
    ret = ctx->on_exchange(&ctx, 1, &client_secret, server_pubkey);
    ok(ret == 0);
    ok(client_secret.len == server_secret.len);
    ok(memcmp(client_secret.base, server_secret.base, client_secret.len) == 0);

    free(client_secret.base);
    free(server_pubkey.base);
    free(server_secret.base);

    /* client abort */
    ret = client->create(client, &ctx);
    ok(ret == 0);
    ret = ctx->on_exchange(&ctx, 1, NULL, ptls_iovec_init(NULL, 0));
    ok(ret == 0);
    ok(ctx == NULL);
}
