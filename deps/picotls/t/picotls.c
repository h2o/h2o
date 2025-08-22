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

static void test_extension_bitmap(void)
{
    struct st_ptls_extension_bitmap_t bitmap = {0};

    /* disallowed extension is rejected */
    ok(!extension_bitmap_testandset(&bitmap, PTLS_HANDSHAKE_TYPE_SERVER_HELLO, PTLS_EXTENSION_TYPE_COOKIE));

    /* allowed extension is accepted first, rejected upon repetition */
    ok(extension_bitmap_testandset(&bitmap, PTLS_HANDSHAKE_TYPE_SERVER_HELLO, PTLS_EXTENSION_TYPE_KEY_SHARE));
    ok(!extension_bitmap_testandset(&bitmap, PTLS_HANDSHAKE_TYPE_SERVER_HELLO, PTLS_EXTENSION_TYPE_KEY_SHARE));
}

static void test_select_cipher(void)
{
#define C(x) ((x) >> 8) & 0xff, (x) & 0xff

    ptls_cipher_suite_t *selected;

    {
        ptls_cipher_suite_t *candidates[] = {&ptls_minicrypto_chacha20poly1305sha256, &ptls_minicrypto_aes128gcmsha256, NULL};
        static const uint8_t input; /* `input[0]` is preferable, but prohibited by MSVC */
        ok(select_cipher(&selected, candidates, &input, &input, 0, 0, 0) == PTLS_ALERT_HANDSHAKE_FAILURE);
    }

    {
        ptls_cipher_suite_t *candidates[] = {&ptls_minicrypto_chacha20poly1305sha256, &ptls_minicrypto_aes128gcmsha256, NULL};
        static const uint8_t input[] = {C(PTLS_CIPHER_SUITE_AES_128_GCM_SHA256), C(PTLS_CIPHER_SUITE_CHACHA20_POLY1305_SHA256)};
        ok(select_cipher(&selected, candidates, input, input + sizeof(input), 0, 0, 0) == 0);
        ok(selected == &ptls_minicrypto_aes128gcmsha256);
        ok(select_cipher(&selected, candidates, input, input + sizeof(input), 1, 0, 0) == 0);
        ok(selected == &ptls_minicrypto_chacha20poly1305sha256);
    }

    {
        ptls_cipher_suite_t *candidates[] = {&ptls_minicrypto_chacha20poly1305sha256, &ptls_minicrypto_aes128gcmsha256, NULL};
        static const uint8_t input[] = {C(PTLS_CIPHER_SUITE_AES_256_GCM_SHA384), C(PTLS_CIPHER_SUITE_AES_128_GCM_SHA256)};
        ok(select_cipher(&selected, candidates, input, input + sizeof(input), 0, 0, 0) == 0);
        ok(selected == &ptls_minicrypto_aes128gcmsha256);
        ok(select_cipher(&selected, candidates, input, input + sizeof(input), 1, 0, 0) == 0);
        ok(selected == &ptls_minicrypto_aes128gcmsha256);
    }

    {
        ptls_cipher_suite_t *candidates[] = {&ptls_minicrypto_aes128gcmsha256, &ptls_minicrypto_aes256gcmsha384,
                                             &ptls_minicrypto_chacha20poly1305sha256, NULL};
        static const uint8_t input[] = {C(PTLS_CIPHER_SUITE_CHACHA20_POLY1305_SHA256), C(PTLS_CIPHER_SUITE_AES_128_GCM_SHA256)};
        ok(select_cipher(&selected, candidates, input, input + sizeof(input), 1, 0, 0) == 0);
        ok(selected == &ptls_minicrypto_aes128gcmsha256);
        ok(select_cipher(&selected, candidates, input, input + sizeof(input), 1, 1, 0) == 0);
        ok(selected == &ptls_minicrypto_chacha20poly1305sha256);
    }

    {
        ptls_cipher_suite_t *candidates[] = {&ptls_minicrypto_aes256gcmsha384, &ptls_minicrypto_chacha20poly1305sha256,
                                             &ptls_minicrypto_aes128gcmsha256, NULL};
        static const uint8_t input[] = {C(PTLS_CIPHER_SUITE_CHACHA20_POLY1305_SHA256), C(PTLS_CIPHER_SUITE_AES_128_GCM_SHA256),
                                        C(PTLS_CIPHER_SUITE_AES_256_GCM_SHA384)};
        ok(select_cipher(&selected, candidates, input, input + sizeof(input), 1, 0, 0) == 0);
        ok(selected == &ptls_minicrypto_aes256gcmsha384);
        ok(select_cipher(&selected, candidates, input, input + sizeof(input), 1, 1, 0) == 0);
        ok(selected == &ptls_minicrypto_chacha20poly1305sha256);
        ok(select_cipher(&selected, candidates, input, input + sizeof(input), 0, 1, 0) == 0);
        ok(selected == &ptls_minicrypto_chacha20poly1305sha256);
    }

    {
        ptls_cipher_suite_t *candidates[] = {&ptls_minicrypto_aes256gcmsha384, &ptls_minicrypto_chacha20poly1305sha256,
                                             &ptls_minicrypto_aes128gcmsha256, NULL};
        static const uint8_t input[] = {C(PTLS_CIPHER_SUITE_AES_128_GCM_SHA256), C(PTLS_CIPHER_SUITE_CHACHA20_POLY1305_SHA256),
                                        C(PTLS_CIPHER_SUITE_AES_256_GCM_SHA384)};
        ok(select_cipher(&selected, candidates, input, input + sizeof(input), 1, 1, 0) == 0);
        ok(selected == &ptls_minicrypto_aes256gcmsha384);
        ok(select_cipher(&selected, candidates, input, input + sizeof(input), 1, 1, 0) == 0);
        ok(selected == &ptls_minicrypto_aes256gcmsha384);
    }

    {
        ptls_cipher_suite_t *candidates[] = {&ptls_minicrypto_aes256gcmsha384, &ptls_minicrypto_aes128gcmsha256, NULL};
        static const uint8_t input[] = {C(PTLS_CIPHER_SUITE_CHACHA20_POLY1305_SHA256), C(PTLS_CIPHER_SUITE_AES_128_GCM_SHA256),
                                        C(PTLS_CIPHER_SUITE_AES_256_GCM_SHA384)};
        ok(select_cipher(&selected, candidates, input, input + sizeof(input), 1, 0, 0) == 0);
        ok(selected == &ptls_minicrypto_aes256gcmsha384);
        ok(select_cipher(&selected, candidates, input, input + sizeof(input), 1, 1, 0) == 0);
        ok(selected == &ptls_minicrypto_aes256gcmsha384);
        ok(select_cipher(&selected, candidates, input, input + sizeof(input), 0, 0, 0) == 0);
        ok(selected == &ptls_minicrypto_aes128gcmsha256);
        ok(select_cipher(&selected, candidates, input, input + sizeof(input), 0, 1, 0) == 0);
        ok(selected == &ptls_minicrypto_aes128gcmsha256);
    }

#undef C
}

ptls_context_t *ctx, *ctx_peer;
ptls_verify_certificate_t *verify_certificate;
struct st_ptls_ffx_test_variants_t ffx_variants[7];
static unsigned server_sc_callcnt, client_sc_callcnt, async_sc_callcnt;

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
    enc1len = ptls_aead_encrypt(c, enc1, src1, strlen(src1), 0, NULL, 0);
    enc2len = ptls_aead_encrypt(c, enc2, src2, strlen(src2), 1, NULL, 0);
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

static void test_ciphersuite_stream(ptls_cipher_suite_t *cs1, ptls_cipher_suite_t *cs2)
{
    const char *traffic_secret = "012345678901234567890123456789012345678901234567",
               *text[] = {
                   "CHAPTER I.\n",
                   "Down the Rabbit-Hole\n",
                   "Alice was beginning to get very tired of sitting by her sister on the bank, and of having nothing to do: once "
                   "or twice she had peeped into the book her sister was reading, but it had no pictures or conversations in it, "
                   "“and what is the use of a book,” thought Alice “without pictures or conversations?”\n",
                   "So she was considering in her own mind (as well as she could, for the hot day made her feel very sleepy and "
                   "stupid), whether the pleasure of making a daisy-chain would be worth the trouble of getting up and picking the "
                   "daisies, when suddenly a White Rabbit with pink eyes ran close by her.\n",
                   NULL,
               };
    ptls_aead_context_t *c;
    char enc[1024], dec[1024];
    size_t enclen, declen;

    /* encrypt */
    c = ptls_aead_new(cs1->aead, cs1->hash, 1, traffic_secret, NULL);
    assert(c != NULL);
    if (c->do_encrypt_init == NULL) {
        note("new ciphers may omit support for init-update-final");
        return;
    }
    ptls_aead_encrypt_init(c, 0, NULL, 0);
    enclen = 0;
    for (size_t i = 0; text[i] != NULL; ++i)
        enclen += ptls_aead_encrypt_update(c, enc + enclen, text[i], strlen(text[i]));
    enclen += ptls_aead_encrypt_final(c, enc + enclen);
    ptls_aead_free(c);

    /* decrypt */
    c = ptls_aead_new(cs2->aead, cs2->hash, 0, traffic_secret, NULL);
    declen = ptls_aead_decrypt(c, dec, enc, enclen, 0, NULL, 0);
    ok(declen != SIZE_MAX);
    ok(declen == enclen - cs1->aead->tag_size);
    ptls_aead_free(c);

    /* check text */
    for (size_t i = 0, decoff = 0;; ++i) {
        if (text[i] == NULL) {
            ok(decoff == declen);
            break;
        }
        ok(decoff + strlen(text[i]) <= declen);
        ok(memcmp(dec + decoff, text[i], strlen(text[i])) == 0);
        decoff += strlen(text[i]);
    }
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
    enclen = ptls_aead_encrypt(c, enc, src, strlen(src), 123, aad, strlen(aad));
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

static void test_aad96_ciphersuite(ptls_cipher_suite_t *cs1, ptls_cipher_suite_t *cs2)
{
    const char *traffic_secret = "012345678901234567890123456789012345678901234567", *src = "hello world", *aad = "my true aad";
    ptls_aead_context_t *c;
    char enc[256], dec[256];
    uint8_t seq32[4] = {0xa1, 0xb2, 0xc3, 0xd4};
    uint8_t seq32_bad[4] = {0xa2, 0xb3, 0xc4, 0xe5};
    size_t enclen, declen;

    /* encrypt */
    c = ptls_aead_new(cs1->aead, cs1->hash, 1, traffic_secret, NULL);
    assert(c != NULL);
    ptls_aead_xor_iv(c, seq32, sizeof(seq32));
    enclen = ptls_aead_encrypt(c, enc, src, strlen(src), 123, aad, strlen(aad));
    ptls_aead_free(c);

    /* decrypt */
    c = ptls_aead_new(cs2->aead, cs2->hash, 0, traffic_secret, NULL);
    assert(c != NULL);
    /* test first decryption */
    ptls_aead_xor_iv(c, seq32, sizeof(seq32));
    declen = ptls_aead_decrypt(c, dec, enc, enclen, 123, aad, strlen(aad));
    ptls_aead_xor_iv(c, seq32, sizeof(seq32));
    ok(declen == strlen(src));
    ok(memcmp(src, dec, declen) == 0);
    /* test that setting the wrong IV creates an error */
    ptls_aead_xor_iv(c, seq32_bad, sizeof(seq32_bad));
    declen = ptls_aead_decrypt(c, dec, enc, enclen, 123, aad, strlen(aad));
    ptls_aead_xor_iv(c, seq32_bad, sizeof(seq32_bad));
    ok(declen == SIZE_MAX);
    /* test second decryption with correct IV to verify no side effect */
    ptls_aead_xor_iv(c, seq32, sizeof(seq32));
    declen = ptls_aead_decrypt(c, dec, enc, enclen, 123, aad, strlen(aad));
    ok(declen == strlen(src));
    ok(memcmp(src, dec, declen) == 0);
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
                        *cs_peer = find_cipher(ctx_peer, PTLS_CIPHER_SUITE_AES_128_GCM_SHA256);

    test_ciphersuite(cs, cs_peer);
    test_ciphersuite_stream(cs, cs_peer);
    test_aad_ciphersuite(cs, cs_peer);
    test_aad96_ciphersuite(cs, cs_peer);
}

static void test_aes256gcm(void)
{
    ptls_cipher_suite_t *cs = find_cipher(ctx, PTLS_CIPHER_SUITE_AES_256_GCM_SHA384),
                        *cs_peer = find_cipher(ctx_peer, PTLS_CIPHER_SUITE_AES_256_GCM_SHA384);

    if (cs != NULL && cs_peer != NULL) {
        test_ciphersuite(cs, cs_peer);
        test_ciphersuite_stream(cs, cs_peer);
        test_aad_ciphersuite(cs, cs_peer);
        test_aad96_ciphersuite(cs, cs_peer);
    }
}

static void test_chacha20poly1305(void)
{
    ptls_cipher_suite_t *cs = find_cipher(ctx, PTLS_CIPHER_SUITE_CHACHA20_POLY1305_SHA256),
                        *cs_peer = find_cipher(ctx_peer, PTLS_CIPHER_SUITE_CHACHA20_POLY1305_SHA256);

    if (cs != NULL && cs_peer != NULL) {
        test_ciphersuite(cs, cs_peer);
        test_ciphersuite_stream(cs, cs_peer);
        test_aad_ciphersuite(cs, cs_peer);
        test_aad96_ciphersuite(cs, cs_peer);
    }
}

#ifdef PTLS_HAVE_AEGIS
static void test_aegis128l(void)
{
    ptls_cipher_suite_t *cs = find_cipher(ctx, PTLS_CIPHER_SUITE_AEGIS128L_SHA256),
                        *cs_peer = find_cipher(ctx_peer, PTLS_CIPHER_SUITE_AEGIS128L_SHA256);

    if (cs != NULL && cs_peer != NULL) {
        test_ciphersuite(cs, cs_peer);
        test_ciphersuite_stream(cs, cs_peer);
        test_aad_ciphersuite(cs, cs_peer);
        test_aad96_ciphersuite(cs, cs_peer);
    }
}

static void test_aegis256(void)
{
    ptls_cipher_suite_t *cs = find_cipher(ctx, PTLS_CIPHER_SUITE_AEGIS256_SHA512),
                        *cs_peer = find_cipher(ctx_peer, PTLS_CIPHER_SUITE_AEGIS256_SHA512);

    if (cs != NULL && cs_peer != NULL) {
        test_ciphersuite(cs, cs_peer);
        test_ciphersuite_stream(cs, cs_peer);
        test_aad_ciphersuite(cs, cs_peer);
        test_aad96_ciphersuite(cs, cs_peer);
    }
}
#endif

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

static void test_ech_decode_config(void)
{
    static ptls_hpke_kem_t p256 = {PTLS_HPKE_KEM_P256_SHA256}, *kems[] = {&p256, NULL};
    static ptls_hpke_cipher_suite_t aes128gcmsha256 = {{PTLS_HPKE_HKDF_SHA256, PTLS_HPKE_AEAD_AES_128_GCM}},
                                    *ciphers[] = {&aes128gcmsha256, NULL};
    struct st_decoded_ech_config_t decoded;

    { /* broken list */
        const uint8_t *src = (const uint8_t *)"a", *end = src + 1;
        int ret = decode_one_ech_config(kems, ciphers, &decoded, &src, end);
        ok(ret == PTLS_ALERT_DECODE_ERROR);
    }

    {
        ptls_iovec_t input = ptls_iovec_init(ECH_CONFIG_LIST, sizeof(ECH_CONFIG_LIST) - 1);
        const uint8_t *src = input.base + 6 /* dive into ECHConfigContents */, *const end = input.base + input.len;
        int ret = decode_one_ech_config(kems, ciphers, &decoded, &src, end);
        ok(ret == 0);
        ok(decoded.id == 0x12);
        ok(decoded.kem == &p256);
        ok(decoded.public_key.len == 65);
        ok(decoded.public_key.base == input.base + 11);
        ok(decoded.cipher == &aes128gcmsha256);
        ok(decoded.max_name_length == 64);
        ok(decoded.public_name.len == sizeof("example.com") - 1);
        ok(memcmp(decoded.public_name.base, "example.com", sizeof("example.com") - 1) == 0);
    }
}

static void test_rebuild_ch_inner(void)
{
    ptls_buffer_t buf;
    ptls_buffer_init(&buf, "", 0);

#define TEST(_expected_err)                                                                                                        \
    do {                                                                                                                           \
        const uint8_t *src = encoded_inner;                                                                                        \
        buf.off = 0;                                                                                                               \
        ok(rebuild_ch_inner_extensions(&buf, &src, encoded_inner + sizeof(encoded_inner), outer, outer + sizeof(outer)) ==         \
           _expected_err);                                                                                                         \
        if (_expected_err == 0) {                                                                                                  \
            ok(src == encoded_inner + sizeof(encoded_inner));                                                                      \
            ok(buf.off == sizeof(expected));                                                                                       \
            ok(memcmp(buf.base, expected, sizeof(expected)) == 0);                                                                 \
        }                                                                                                                          \
    } while (0)

    { /* replace none */
        static const uint8_t encoded_inner[] = {0x00, 0x09, 0x12, 0x34, 0x00, 0x05, 0x68, 0x65, 0x6c, 0x6c, 0x6f},
                             outer[] = {0xde, 0xad},
                             expected[] = {0x00, 0x09, 0x12, 0x34, 0x00, 0x05, 0x68, 0x65, 0x6c, 0x6c, 0x6f};
        TEST(0);
    }

    { /* replace one */
        static const uint8_t encoded_inner[] = {0x00, 0x07, 0xfd, 0x00, 0x00, 0x03, 0x02, 0x00, 0x01},
                             outer[] = {0x00, 0x01, 0x00, 0x05, 0x68, 0x65, 0x6c, 0x6c, 0x6f},
                             expected[] = {0x00, 0x09, 0x00, 0x01, 0x00, 0x05, 0x68, 0x65, 0x6c, 0x6c, 0x6f};
        TEST(0);
    }

    { /* replace multi */
        static const uint8_t encoded_inner[] = {0x00, 0x13, 0x00, 0x01, 0x00, 0x01, 0x31, 0xfd, 0x00, 0x00, 0x05,
                                                0x04, 0x00, 0x02, 0x00, 0x04, 0x00, 0x05, 0x00, 0x01, 0x35},
                             outer[] = {0x00, 0x01, 0x00, 0x01, 0x41, 0x00, 0x02, 0x00, 0x01, 0x42, 0x00, 0x03, 0x00,
                                        0x01, 0x43, 0x00, 0x04, 0x00, 0x01, 0x44, 0x00, 0x05, 0x00, 0x01, 0x45},
                             expected[] = {0x00, 0x14, 0x00, 0x01, 0x00, 0x01, 0x31, 0x00, 0x02, 0x00, 0x01,
                                           0x42, 0x00, 0x04, 0x00, 0x01, 0x44, 0x00, 0x05, 0x00, 0x01, 0x35};
        TEST(0);
    }

    { /* outer extension not found */
        static const uint8_t encoded_inner[] = {0x00, 0x13, 0x00, 0x01, 0x00, 0x01, 0x31, 0xfd, 0x00, 0x00, 0x05,
                                                0x04, 0x00, 0x02, 0x00, 0x04, 0x00, 0x05, 0x00, 0x01, 0x35},
                             outer[] = {0x00, 0x01, 0x00, 0x01, 0x41, 0x00, 0x02, 0x00, 0x01, 0x42, 0x00, 0x03, 0x00, 0x01, 0x43},
                             expected[] = {0x00, 0x14, 0x00, 0x01, 0x00, 0x01, 0x31, 0x00, 0x02, 0x00, 0x01,
                                           0x42, 0x00, 0x04, 0x00, 0x01, 0x44, 0x00, 0x05, 0x00, 0x01, 0x35};
        TEST(PTLS_ALERT_ILLEGAL_PARAMETER);
    }

#undef TEST
    ptls_buffer_dispose(&buf);
}

static void test_ech(void)
{
    subtest("decode-config", test_ech_decode_config);
    subtest("rebuild_ch_inner", test_rebuild_ch_inner);
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

static int save_client_hello(ptls_on_client_hello_t *self, ptls_t *tls, ptls_on_client_hello_parameters_t *params)
{
    ptls_set_server_name(tls, (const char *)params->server_name.base, params->server_name.len);
    if (params->negotiated_protocols.count != 0)
        ptls_set_negotiated_protocol(tls, (const char *)params->negotiated_protocols.list[0].base,
                                     params->negotiated_protocols.list[0].len);
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

static int can_ech(ptls_context_t *ctx, int is_server)
{
    if (is_server) {
        return ctx->ech.server.create_opener != NULL;
    } else {
        return ctx->ech.client.ciphers != NULL;
    }
}

static void check_clone(ptls_t *src, ptls_t *dest)
{
    ok(src->cipher_suite->hash->digest_size == dest->cipher_suite->hash->digest_size);
    size_t digest_size = dest->cipher_suite->hash->digest_size;
    ok(memcmp(src->traffic_protection.enc.secret, dest->traffic_protection.enc.secret, digest_size) == 0);
    ok(memcmp(src->traffic_protection.dec.secret, dest->traffic_protection.dec.secret, digest_size) == 0);
    const unsigned enc_idx = 0;
    const unsigned dec_idx = 1;
    struct {
        uint8_t key[PTLS_MAX_SECRET_SIZE];
        uint8_t iv[PTLS_MAX_IV_SIZE];
        uint64_t seq;
    } src_keys[2] = {0}, dest_keys[2] = {0};
    ok(ptls_get_traffic_keys(src, 1, src_keys[enc_idx].key, src_keys[enc_idx].iv, &src_keys[enc_idx].seq) == 0);
    ok(ptls_get_traffic_keys(src, 0, src_keys[dec_idx].key, src_keys[dec_idx].iv, &src_keys[dec_idx].seq) == 0);
    ok(ptls_get_traffic_keys(dest, 1, dest_keys[enc_idx].key, dest_keys[enc_idx].iv, &dest_keys[enc_idx].seq) == 0);
    ok(ptls_get_traffic_keys(dest, 0, dest_keys[dec_idx].key, dest_keys[dec_idx].iv, &dest_keys[dec_idx].seq) == 0);
    ok(src_keys[enc_idx].seq == dest_keys[enc_idx].seq);
    ok(src_keys[dec_idx].seq == dest_keys[dec_idx].seq);
    ok(memcmp(src_keys[enc_idx].key, dest_keys[enc_idx].key, PTLS_MAX_SECRET_SIZE) == 0);
    ok(memcmp(src_keys[dec_idx].key, dest_keys[dec_idx].key, PTLS_MAX_SECRET_SIZE) == 0);
    ok(memcmp(src_keys[enc_idx].iv, dest_keys[enc_idx].iv, PTLS_MAX_IV_SIZE) == 0);
    ok(memcmp(src_keys[dec_idx].iv, dest_keys[dec_idx].iv, PTLS_MAX_IV_SIZE) == 0);
}

static ptls_t *clone_tls(ptls_t *src)
{
    ptls_t *dest = NULL;
    ptls_buffer_t sess_data;

    ptls_buffer_init(&sess_data, "", 0);
    int r = ptls_export(src, &sess_data);
    assert(r == 0);
    r = ptls_import(ctx_peer, &dest, (ptls_iovec_t){.base = sess_data.base, .len = sess_data.off});
    assert(r == 0);
    ptls_buffer_dispose(&sess_data);

    check_clone(src, dest);

    return dest;
}

static void test_handshake(ptls_iovec_t ticket, int mode, int expect_ticket, int check_ch, int require_client_authentication,
                           int transfer_session)
{
    ptls_t *client, *server;
    ptls_handshake_properties_t client_hs_prop = {{{{NULL}, ticket}}}, server_hs_prop = {{{{NULL}}}};
    uint8_t cbuf_small[16384], sbuf_small[16384], decbuf_small[16384];
    ptls_buffer_t cbuf, sbuf, decbuf;
    size_t consumed, max_early_data_size = 0;
    int ret;
    const char *req = "GET / HTTP/1.0\r\n\r\n";
    const char *resp = "HTTP/1.0 200 OK\r\n\r\nhello world\n";

    client_sc_callcnt = 0;
    server_sc_callcnt = 0;
    async_sc_callcnt = 0;

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

    if (can_ech(ctx, 0)) {
        ptls_set_server_name(client, "test.example.com", 0);
        client_hs_prop.client.ech.configs = ptls_iovec_init(ECH_CONFIG_LIST, sizeof(ECH_CONFIG_LIST) - 1);
    }

    static ptls_on_extension_t cb = {on_extension_cb};
    ctx_peer->on_extension = &cb;

    if (require_client_authentication)
        ctx_peer->require_client_authentication = 1;

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

    if (require_client_authentication) {
        /* at the moment, async sign-certificate is not supported in this path, neither on the client-side or the server-side */
        ok(ptls_is_psk_handshake(server) == 0);
        ok(ret == PTLS_ERROR_IN_PROGRESS);
    } else if (mode == TEST_HANDSHAKE_EARLY_DATA) {
        ok(ret == 0);
    } else {
        ok(ret == 0 || ret == PTLS_ERROR_ASYNC_OPERATION);
    }

    ok(sbuf.off != 0);
    if (check_ch) {
        ok(ptls_get_server_name(server) != NULL);
        if (can_ech(ctx, 0) && !can_ech(ctx_peer, 1)) {
            /* server should be using CHouter.sni that includes the public name of the ECH extension */
            ok(strcmp(ptls_get_server_name(server), "example.com") == 0);
        } else {
            ok(strcmp(ptls_get_server_name(server), "test.example.com") == 0);
        }
        ok(ptls_get_negotiated_protocol(server) != NULL);
        ok(strcmp(ptls_get_negotiated_protocol(server), "h2") == 0);
    } else {
        ok(ptls_get_server_name(server) == NULL);
        ok(ptls_get_negotiated_protocol(server) == NULL);
    }

    if (mode == TEST_HANDSHAKE_EARLY_DATA && !require_client_authentication) {
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

    while (ret == PTLS_ERROR_ASYNC_OPERATION) {
        consumed = sbuf.off;
        ret = ptls_handshake(client, &cbuf, sbuf.base, &consumed, NULL);
        ok(ret == PTLS_ERROR_IN_PROGRESS);
        ok(consumed == sbuf.off);
        ok(cbuf.off == 0);
        sbuf.off = 0;
        ret = ptls_handshake(server, &sbuf, NULL, NULL, &server_hs_prop);
    }
    if (require_client_authentication) {
        ok(ret == PTLS_ERROR_IN_PROGRESS);
    } else {
        ok(ret == 0);
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

    if (require_client_authentication) {
        ok(!ptls_handshake_is_complete(server));
        consumed = cbuf.off;
        ret = ptls_handshake(server, &sbuf, cbuf.base, &consumed, &server_hs_prop);
        ok(ret == 0);
        ok(ptls_handshake_is_complete(server));
        cbuf.off = 0;
    }

    /* holds the ptls_t pointer of server prior to migration */
    ptls_t *original_server = server;

    if (mode != TEST_HANDSHAKE_EARLY_DATA || require_client_authentication) {
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
        if (transfer_session)
            server = clone_tls(original_server);

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

    /* original_server is used for the server-side checks because handshake data is never migrated */
    if (can_ech(ctx_peer, 1) && can_ech(ctx, 0)) {
        ok(ptls_is_ech_handshake(client, NULL, NULL, NULL));
        ok(ptls_is_ech_handshake(original_server, NULL, NULL, NULL));
    } else {
        ok(!ptls_is_ech_handshake(client, NULL, NULL, NULL));
        ok(!ptls_is_ech_handshake(original_server, NULL, NULL, NULL));
    }

    ptls_buffer_dispose(&cbuf);
    ptls_buffer_dispose(&sbuf);
    ptls_buffer_dispose(&decbuf);
    ptls_free(client);
    if (original_server != server)
        ptls_free(original_server);
    ptls_free(server);

    if (check_ch)
        ctx_peer->on_client_hello = NULL;

    ctx->verify_certificate = NULL;
    if (require_client_authentication)
        ctx_peer->require_client_authentication = 0;
}

static ptls_sign_certificate_t *sc_orig;

static int sign_certificate(ptls_sign_certificate_t *self, ptls_t *tls, ptls_async_job_t **async, uint16_t *selected_algorithm,
                            ptls_buffer_t *output, ptls_iovec_t input, const uint16_t *algorithms, size_t num_algorithms)
{
    ++*(ptls_is_server(tls) ? &server_sc_callcnt : &client_sc_callcnt);
    return sc_orig->cb(sc_orig, tls, async, selected_algorithm, output, input, algorithms, num_algorithms);
}

static int async_sign_certificate(ptls_sign_certificate_t *self, ptls_t *tls, ptls_async_job_t **async,
                                  uint16_t *selected_algorithm, ptls_buffer_t *output, ptls_iovec_t input,
                                  const uint16_t *algorithms, size_t num_algorithms)
{
    static struct {
        ptls_async_job_t super;
        uint16_t selected_algorithm;
    } async_ctx;

    if (async != NULL) {
        if (*async == NULL) {
            /* first invocation, make a fake call to the backend and obtain the algorithm, return it, but not the signature */
            ptls_buffer_t fakebuf;
            ptls_buffer_init(&fakebuf, "", 0);
            int ret = sign_certificate(self, tls, NULL, selected_algorithm, &fakebuf, input, algorithms, num_algorithms);
            assert(ret == 0);
            ptls_buffer_dispose(&fakebuf);
            async_ctx.super.destroy_ = (void (*)(ptls_async_job_t *))0xdeadbeef;
            async_ctx.selected_algorithm = *selected_algorithm;
            *async = &async_ctx.super;
            --server_sc_callcnt;
            ++async_sc_callcnt;
            return PTLS_ERROR_ASYNC_OPERATION;
        } else {
            /* second invocation, restore algorithm, and delegate the call */
            assert(*async == &async_ctx.super);
            assert(algorithms == NULL);
            algorithms = &async_ctx.selected_algorithm;
            num_algorithms = 1;
            *async = NULL;
        }
    }

    return sign_certificate(self, tls, NULL, selected_algorithm, output, input, algorithms, num_algorithms);
}

static ptls_sign_certificate_t *second_sc_orig;

static int second_sign_certificate(ptls_sign_certificate_t *self, ptls_t *tls, ptls_async_job_t **async,
                                   uint16_t *selected_algorithm, ptls_buffer_t *output, ptls_iovec_t input,
                                   const uint16_t *algorithms, size_t num_algorithms)
{
    ++*(ptls_is_server(tls) ? &server_sc_callcnt : &client_sc_callcnt);
    return second_sc_orig->cb(second_sc_orig, tls, async, selected_algorithm, output, input, algorithms, num_algorithms);
}

static void test_full_handshake_impl(int require_client_authentication, int is_async, int transfer_session)
{
    test_handshake(ptls_iovec_init(NULL, 0), TEST_HANDSHAKE_1RTT, 0, 0, require_client_authentication, transfer_session);
    ok(server_sc_callcnt == 1);
    ok(async_sc_callcnt == is_async);
    ok(client_sc_callcnt == require_client_authentication);

    test_handshake(ptls_iovec_init(NULL, 0), TEST_HANDSHAKE_1RTT, 0, 0, require_client_authentication, transfer_session);
    ok(server_sc_callcnt == 1);
    ok(async_sc_callcnt == is_async);
    ok(client_sc_callcnt == require_client_authentication);

    test_handshake(ptls_iovec_init(NULL, 0), TEST_HANDSHAKE_1RTT, 0, 1, require_client_authentication, transfer_session);
    ok(server_sc_callcnt == 1);
    ok(async_sc_callcnt == is_async);
    ok(client_sc_callcnt == require_client_authentication);
}

static void test_full_handshake(void)
{
    test_full_handshake_impl(0, 0, 0);
    test_full_handshake_impl(0, 0, 0);
}

static void test_full_handshake_with_client_authentication(void)
{
    test_full_handshake_impl(1, 0, 0);
    test_full_handshake_impl(1, 0, 1);
}

static void test_key_update(void)
{
    test_handshake(ptls_iovec_init(NULL, 0), TEST_HANDSHAKE_KEY_UPDATE, 0, 0, 0, 0);
    test_handshake(ptls_iovec_init(NULL, 0), TEST_HANDSHAKE_KEY_UPDATE, 0, 0, 0, 1);
}

static void test_hrr_handshake(void)
{
    test_handshake(ptls_iovec_init(NULL, 0), TEST_HANDSHAKE_HRR, 0, 0, 0, 0);
    ok(server_sc_callcnt == 1);
    test_handshake(ptls_iovec_init(NULL, 0), TEST_HANDSHAKE_HRR, 0, 0, 0, 0);
}

static void test_hrr_stateless_handshake(void)
{
    test_handshake(ptls_iovec_init(NULL, 0), TEST_HANDSHAKE_HRR_STATELESS, 0, 0, 0, 0);
    ok(server_sc_callcnt == 1);
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

static ptls_iovec_t saved_tickets[8] = {{NULL}};

static int on_save_ticket(ptls_save_ticket_t *self, ptls_t *tls, ptls_iovec_t src)
{
    memmove(saved_tickets + 1, saved_tickets, sizeof(saved_tickets[0]) * (PTLS_ELEMENTSOF(saved_tickets) - 1));
    saved_tickets[0].base = malloc(src.len);
    memcpy(saved_tickets[0].base, src.base, src.len);
    saved_tickets[0].len = src.len;
    return 0;
}

static void test_resumption_impl(int different_preferred_key_share, int require_client_authentication, int use_ticket_request,
                                 int transfer_session)
{
    assert(ctx->key_exchanges[0]->id == ctx_peer->key_exchanges[0]->id);
    assert(ctx->key_exchanges[1] == NULL);
    assert(ctx_peer->key_exchanges[1] == NULL);
    assert(ctx->key_exchanges[0]->id != ptls_minicrypto_x25519.id);
    ptls_key_exchange_algorithm_t *different_key_exchanges[] = {&ptls_minicrypto_x25519, ctx->key_exchanges[0], NULL},
                                  **key_exchanges_orig = ctx->key_exchanges;

    if (different_preferred_key_share)
        ctx->key_exchanges = different_key_exchanges;
    if (use_ticket_request) {
        ctx->ticket_requests.client.new_session_count = 3;
        ctx->ticket_requests.client.resumption_count = 2;
    }

    ptls_encrypt_ticket_t et = {on_copy_ticket};
    ptls_save_ticket_t st = {on_save_ticket};

    assert(ctx_peer->ticket_lifetime == 0);
    assert(ctx_peer->max_early_data_size == 0);
    assert(ctx_peer->encrypt_ticket == NULL);
    assert(ctx_peer->save_ticket == NULL);
    memset(saved_tickets, 0, sizeof(saved_tickets));

    ctx_peer->ticket_lifetime = 86400;
    ctx_peer->max_early_data_size = 8192;
    ctx_peer->encrypt_ticket = &et;
    ctx->save_ticket = &st;

    test_handshake(ptls_iovec_init(NULL, 0), different_preferred_key_share ? TEST_HANDSHAKE_2RTT : TEST_HANDSHAKE_1RTT, 1, 0, 0,
                   transfer_session);
    ok(server_sc_callcnt == 1);
    if (use_ticket_request) {
        /* should have received 3 tickets */
        ok(saved_tickets[2].base != NULL);
        ok(saved_tickets[3].base == NULL);
    } else {
        ok(saved_tickets[0].base != NULL);
    }

    /* psk using saved ticket */
    test_handshake(saved_tickets[0], TEST_HANDSHAKE_1RTT, 1, 0, require_client_authentication, transfer_session);
    ok(server_sc_callcnt == require_client_authentication); /* client authentication turns off resumption */
    ok(client_sc_callcnt == require_client_authentication);
    if (use_ticket_request && !require_client_authentication) {
        /* should have received 2 tickets */
        ok(saved_tickets[4].base != NULL);
        ok(saved_tickets[5].base == NULL);
    }

    /* 0-rtt psk using saved ticket */
    test_handshake(saved_tickets[0], TEST_HANDSHAKE_EARLY_DATA, 1, 0, require_client_authentication, transfer_session);
    ok(server_sc_callcnt == require_client_authentication); /* client authentication turns off resumption */
    ok(client_sc_callcnt == require_client_authentication);

    ctx->require_dhe_on_psk = 1;

    /* psk-dhe using saved ticket */
    test_handshake(saved_tickets[0], TEST_HANDSHAKE_1RTT, 1, 0, require_client_authentication, transfer_session);
    ok(server_sc_callcnt == require_client_authentication); /* client authentication turns off resumption */
    ok(client_sc_callcnt == require_client_authentication);

    /* 0-rtt psk-dhe using saved ticket */
    test_handshake(saved_tickets[0], TEST_HANDSHAKE_EARLY_DATA, 1, 0, require_client_authentication, transfer_session);
    ok(server_sc_callcnt == require_client_authentication); /* client authentication turns off resumption */
    ok(client_sc_callcnt == require_client_authentication);

    ctx->require_dhe_on_psk = 0;
    ctx->ticket_requests.client.new_session_count = 0;
    ctx->ticket_requests.client.resumption_count = 0;
    ctx_peer->ticket_lifetime = 0;
    ctx_peer->max_early_data_size = 0;
    ctx_peer->encrypt_ticket = NULL;
    ctx->save_ticket = NULL;
    ctx->key_exchanges = key_exchanges_orig;
}

static void test_resumption(int different_preferred_key_share, int require_client_authentication)
{
    subtest("basic", test_resumption_impl, different_preferred_key_share, require_client_authentication, 0, 0);
    subtest("transfer-session", test_resumption_impl, different_preferred_key_share, require_client_authentication, 0, 1);
    subtest("ticket-request", test_resumption_impl, different_preferred_key_share, require_client_authentication, 1, 0);
}

static void test_async_sign_certificate(void)
{
    assert(ctx_peer->sign_certificate->cb == sign_certificate);

    ptls_sign_certificate_t async_sc = {async_sign_certificate}, *orig_sc = ctx_peer->sign_certificate;
    ctx_peer->sign_certificate = &async_sc;

    test_full_handshake_impl(0, 1, 0);

    ctx_peer->sign_certificate = orig_sc;
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

static void test_ech_config_mismatch(void)
{
    ptls_t *client, *server;
    ptls_buffer_t cbuf, sbuf, decryptbuf;
    size_t consumed;
    int ret;
    ptls_iovec_t retry_configs = {NULL};
    ptls_handshake_properties_t client_hs_prop = {
        .client.ech = {
            .configs = ptls_iovec_init((void *)ECH_ALTERNATIVE_CONFIG_LIST, sizeof(ECH_ALTERNATIVE_CONFIG_LIST) - 1),
            .retry_configs = &retry_configs,
        }};

    client = ptls_new(ctx, 0);
    ptls_set_server_name(client, "test.example.com", 0);
    server = ptls_new(ctx_peer, 1);
    ptls_buffer_init(&cbuf, "", 0);
    ptls_buffer_init(&sbuf, "", 0);
    ptls_buffer_init(&decryptbuf, "", 0);

    ret = ptls_handshake(client, &cbuf, NULL, NULL, &client_hs_prop);
    ok(ret == PTLS_ERROR_IN_PROGRESS);

    consumed = cbuf.off;
    ret = ptls_handshake(server, &sbuf, cbuf.base, &consumed, NULL);
    ok(ret == 0);
    ok(cbuf.off == consumed);
    cbuf.off = 0;

    consumed = sbuf.off;
    ret = ptls_handshake(client, &cbuf, sbuf.base, &consumed, &client_hs_prop);
    ok(ret == PTLS_ALERT_ECH_REQUIRED);
    ok(sbuf.off == consumed);
    ok(retry_configs.len == sizeof(ECH_CONFIG_LIST) - 1);
    ok(memcmp(retry_configs.base, ECH_CONFIG_LIST, retry_configs.len) == 0);
    sbuf.off = 0;

    consumed = cbuf.off;
    ret = ptls_handshake(server, &sbuf, cbuf.base, &consumed, NULL);
    ok(ret == 0);
    ok(consumed < cbuf.off);
    memmove(cbuf.base, cbuf.base + consumed, cbuf.off - consumed);
    cbuf.off -= consumed;

    consumed = cbuf.off;
    ret = ptls_receive(server, &decryptbuf, cbuf.base, &consumed);
    ok(ret == PTLS_ALERT_TO_PEER_ERROR(PTLS_ALERT_ECH_REQUIRED));
    ok(cbuf.off == consumed);

    ptls_free(client);
    ptls_free(server);
    ptls_buffer_dispose(&cbuf);
    ptls_buffer_dispose(&sbuf);
    ptls_buffer_dispose(&decryptbuf);
    free(retry_configs.base);
}

static void do_test_pre_shared_key(int mode)
{
    ptls_context_t ctx_client = *ctx;
    ptls_key_exchange_algorithm_t *alternate_keyex[3];
    size_t client_max_early_data_size = 0;
    ptls_handshake_properties_t client_prop = {.client.max_early_data_size = &client_max_early_data_size};

    switch (mode) {
    case 0: /* no keyex */
        ctx_client.key_exchanges = NULL;
        break;
    case 1: /* keyex match */
        break;
    case 2: /* server has no keyex */
        break;
    case 3: /* keyex mismatch */
        if (!(ctx_client.key_exchanges[0] != NULL && ctx_client.key_exchanges[1] != NULL)) {
            note("keyex mismatch test requires two key exchange algorithms");
            return;
        }
        alternate_keyex[0] = ctx_client.key_exchanges[1];
        alternate_keyex[1] = ctx_client.key_exchanges[0];
        alternate_keyex[2] = NULL;
        ctx_client.key_exchanges = alternate_keyex;
        break;
    case 4: /* negotiate */
        client_prop.client.negotiate_before_key_exchange = 1;
        break;
    case -1: /* fail:requires-psk-dhe */
        ctx_client.key_exchanges = NULL;
        break;
    default:
        assert(!"FIXME");
    }

    ctx_client.max_early_data_size = 16384;
    assert(ctx_client.pre_shared_key.identity.len == 0 && ctx_client.pre_shared_key.secret.len == 0);
    ctx_client.pre_shared_key.identity = ptls_iovec_init("", 1);
    ctx_client.pre_shared_key.secret = ptls_iovec_init("hello world", 11);
    for (size_t i = 0; ctx_client.cipher_suites[i] != NULL; ++i) {
        if (strcmp(ctx_client.cipher_suites[i]->hash->name, "sha256") == 0) {
            ctx_client.pre_shared_key.hash = ctx_client.cipher_suites[i]->hash;
            break;
        }
    }
    assert(ctx_client.pre_shared_key.hash != NULL);

    ptls_context_t ctx_server = ctx_client;
    switch (mode) {
    case 2: /* server has no keyex */
        ctx_server.key_exchanges = NULL;
        break;
    case -1: /* fail:requires-psk-dhe */
        ctx_server.require_dhe_on_psk = 1;
        break;
    default:
        break;
    }

    ptls_t *client = ptls_new(&ctx_client, 0), *server = ptls_new(&ctx_server, 1);
    ptls_buffer_t cbuf, sbuf, decbuf;
    ptls_buffer_init(&cbuf, "", 0);
    ptls_buffer_init(&sbuf, "", 0);
    ptls_buffer_init(&decbuf, "", 0);

    /* [client] send CH and early data */
    int ret = ptls_handshake(client, &cbuf, NULL, NULL, &client_prop);
    ok(ret == PTLS_ERROR_IN_PROGRESS);
    ok(client_prop.client.early_data_acceptance == PTLS_EARLY_DATA_ACCEPTANCE_UNKNOWN);
    ok(client_max_early_data_size == SIZE_MAX);
    ret = ptls_send(client, &cbuf, "hello", 5);
    ok(ret == 0);

    /* [server] read CH and generate up to ServerFinished */
    size_t consumed = cbuf.off;
    ret = ptls_handshake(server, &sbuf, cbuf.base, &consumed, NULL);
    if (mode < 0) {
        ok(ret == PTLS_ALERT_HANDSHAKE_FAILURE);
        goto Exit;
    }
    ok(consumed <= cbuf.off);
    memmove(cbuf.base, cbuf.base + consumed, cbuf.off - consumed);
    cbuf.off -= consumed;
    if (mode >= 3) {
        ok(ret == PTLS_ERROR_IN_PROGRESS);
        ok(cbuf.off == 0);
        consumed = sbuf.off;
        ret = ptls_handshake(client, &cbuf, sbuf.base, &consumed, &client_prop);
        ok(ret == PTLS_ERROR_IN_PROGRESS);
        ok(client_prop.client.early_data_acceptance == PTLS_EARLY_DATA_REJECTED);
        ok(consumed == sbuf.off);
        sbuf.off = 0;
        consumed = cbuf.off;
        ret = ptls_handshake(server, &sbuf, cbuf.base, &consumed, NULL);
        ok(ret == 0);
        ok(consumed == cbuf.off);
        cbuf.off = 0;
    } else {
        ok(ret == 0);
        /* [server] read early data */
        consumed = cbuf.off;
        ret = ptls_receive(server, &decbuf, cbuf.base, &consumed);
        ok(ret == 0);
        ok(consumed == cbuf.off);
        cbuf.off = 0;
        ok(decbuf.off == 5);
        ok(memcmp(decbuf.base, "hello", 5) == 0);
        decbuf.off = 0;
    }

    /* [server] write 0.5-RTT data */
    ret = ptls_send(server, &sbuf, "hi", 2);
    ok(ret == 0);

    /* [client] read up to ServerFinished */
    consumed = sbuf.off;
    ret = ptls_handshake(client, &cbuf, sbuf.base, &consumed, &client_prop);
    ok(ret == 0);
    ok(client_prop.client.early_data_acceptance == (mode < 3 ? PTLS_EARLY_DATA_ACCEPTED : PTLS_EARLY_DATA_REJECTED));
    ok(consumed < sbuf.off);
    memmove(sbuf.base, sbuf.base + consumed, sbuf.off - consumed);
    sbuf.off -= consumed;

    /* [client] read 0.5-RTT data */
    consumed = sbuf.off;
    ret = ptls_receive(client, &decbuf, sbuf.base, &consumed);
    ok(ret == 0);
    ok(consumed == sbuf.off);
    sbuf.off = 0;
    ok(decbuf.off == 2);
    ok(memcmp(decbuf.base, "hi", 2) == 0);
    decbuf.off = 0;

    /* [client] write 1-RTT data */
    ret = ptls_send(client, &cbuf, "bye", 3);
    ok(ret == 0);

    /* [server] read ClientFinished and 1-RTT data */
    ok(!ptls_handshake_is_complete(server));
    consumed = cbuf.off;
    ret = ptls_receive(server, &decbuf, cbuf.base, &consumed);
    ok(ret == 0);
    ok(ptls_handshake_is_complete(server));
    ok(consumed == cbuf.off);
    cbuf.off = 0;
    ok(decbuf.off == 3);
    ok(memcmp(decbuf.base, "bye", 3) == 0);

Exit:
    ptls_buffer_dispose(&cbuf);
    ptls_buffer_dispose(&sbuf);
    ptls_buffer_dispose(&decbuf);
    ptls_free(client);
    ptls_free(server);
}

static void test_pre_shared_key(void)
{
    if (ctx != ctx_peer) {
        note("psk tests use `ctx` only");
        return;
    }

    subtest("key-share:no", do_test_pre_shared_key, 0);
    subtest("key-share:yes", do_test_pre_shared_key, 1);
    subtest("key-share:server-wo-key-share", do_test_pre_shared_key, 2);
    subtest("key-share:mismatch", do_test_pre_shared_key, 3);
    subtest("key-share:negotiate", do_test_pre_shared_key, 4);

    subtest("fail:requires-psk-dhe", do_test_pre_shared_key, -1);
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

    memset(saved_tickets, 0, sizeof(saved_tickets));

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
    ptls_handshake_properties_t client_hs_prop = {{{{NULL}, saved_tickets[0], &max_early_data_size}}};
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
    client_hs_prop = (ptls_handshake_properties_t){{{{NULL}, saved_tickets[0], &max_early_data_size}}};
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
    client_hs_prop = (ptls_handshake_properties_t){{{{NULL}, saved_tickets[0], &max_early_data_size}}};
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
    client_hs_prop = (ptls_handshake_properties_t){{{{NULL}, saved_tickets[0], &max_early_data_size}}};
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

static void test_all_handshakes_core(void)
{
    subtest("full-handshake", test_full_handshake);
    subtest("full-handshake+client-auth", test_full_handshake_with_client_authentication);
    subtest("hrr-handshake", test_hrr_handshake);
    /* resumption does not work when the client offers ECH but the server does not recognize that */
    if (!(can_ech(ctx, 0) && !can_ech(ctx_peer, 1))) {
        subtest("resumption", test_resumption, 0, 0);
        if (ctx != ctx_peer)
            subtest("resumption-different-preferred-key-share", test_resumption, 1, 0);
        subtest("resumption-with-client-authentication", test_resumption, 0, 1);
    }
    subtest("async-sign-certificate", test_async_sign_certificate);
    subtest("enforce-retry-stateful", test_enforce_retry_stateful);
    if (!(can_ech(ctx_peer, 1) && can_ech(ctx, 0))) {
        subtest("hrr-stateless-handshake", test_hrr_stateless_handshake);
        subtest("enforce-retry-stateless", test_enforce_retry_stateless);
        subtest("stateless-hrr-aad-change", test_stateless_hrr_aad_change);
    }
    subtest("key-update", test_key_update);
    subtest("pre-shared-key", test_pre_shared_key);
    subtest("handshake-api", test_handshake_api);
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

    struct {
        ptls_ech_create_opener_t *create_opener;
        ptls_hpke_cipher_suite_t **client_ciphers;
    } orig_ech = {ctx_peer->ech.server.create_opener, ctx->ech.client.ciphers};

    /* first run tests wo. ECH */
    ctx_peer->ech.server.create_opener = NULL;
    ctx->ech.client.ciphers = NULL;
    subtest("no-ech", test_all_handshakes_core);
    ctx_peer->ech.server.create_opener = orig_ech.create_opener;
    ctx->ech.client.ciphers = orig_ech.client_ciphers;

    if (can_ech(ctx_peer, 1) && can_ech(ctx, 0)) {
        subtest("ech", test_all_handshakes_core);
        if (ctx != ctx_peer) {
            ctx->ech.client.ciphers = NULL;
            subtest("ech (server-only)", test_all_handshakes_core);
            ctx->ech.client.ciphers = orig_ech.client_ciphers;
        }
        subtest("ech-config-mismatch", test_ech_config_mismatch);
    }

    ctx_peer->sign_certificate = sc_orig;

    if (ctx_peer != ctx)
        ctx->sign_certificate = second_sc_orig;
}

static void do_test_tlsblock(size_t len_encoded, size_t max_bytes)
{
    ptls_buffer_t buf;
    const uint8_t *src, *end;
    int expect_overflow = 0, ret;

    /* block that fits in */
    ptls_buffer_init(&buf, "", 0);
    ptls_buffer_push_block(&buf, len_encoded, {
        for (size_t i = 0; i < max_bytes; ++i)
            ptls_buffer_push(&buf, (uint8_t)i);
    });
    src = buf.base;
    end = buf.base + buf.off;
    ptls_decode_block(src, end, len_encoded, {
        ok(end - src == max_bytes);
        int bytes_eq = 1;
        for (size_t i = 0; i < max_bytes; ++i) {
            if (src[i] != (uint8_t)i)
                bytes_eq = 0;
        }
        ok(bytes_eq);
        src = end;
    });

    /* block that does not fit in */
    ptls_buffer_push_block(&buf, len_encoded, {
        for (size_t i = 0; i < max_bytes + 1; i++)
            ptls_buffer_push(&buf, 1);
        expect_overflow = 1;
    });
    ok(!"fail");

Exit:
    if (ret != 0) {
        if (expect_overflow) {
            ok(ret == PTLS_ERROR_BLOCK_OVERFLOW);
        } else {
            ok(!"fail");
        }
    }
    ptls_buffer_dispose(&buf);
}

static void test_tlsblock8(void)
{
    do_test_tlsblock(1, 255);
}

static void test_tlsblock16(void)
{
    do_test_tlsblock(2, 65535);
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

static ptls_on_client_hello_parameters_t *legacy_params;

static int test_legacy_ch_tls12_callback(ptls_on_client_hello_t *self, ptls_t *tls, ptls_on_client_hello_parameters_t *params)
{
    assert(legacy_params == NULL);
    legacy_params = malloc(sizeof(*legacy_params));
    *legacy_params = *params;
    return 0;
}

static void test_legacy_ch(void)
{
    static const uint8_t tls12[] = {
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
    static const uint8_t tls11[] = {
        0x16, 0x03, 0x01, 0x00, 0x71, 0x01, 0x00, 0x00, 0x6d, 0x03, 0x02, 0xa5, 0xac, 0xfc, 0xef, 0x36, 0xa0, 0x4e, 0x1b, 0xa1,
        0x9d, 0x01, 0x98, 0x3e, 0xae, 0x07, 0x2e, 0x23, 0xdc, 0xce, 0x62, 0xc8, 0xb6, 0x7e, 0xd0, 0x5c, 0x2e, 0xeb, 0x63, 0x26,
        0x74, 0xe7, 0x61, 0x00, 0x00, 0x2e, 0xc0, 0x14, 0xc0, 0x0a, 0x00, 0x39, 0xff, 0x85, 0x00, 0x88, 0x00, 0x81, 0x00, 0x35,
        0x00, 0x84, 0xc0, 0x13, 0xc0, 0x09, 0x00, 0x33, 0x00, 0x45, 0x00, 0x2f, 0x00, 0x41, 0xc0, 0x11, 0xc0, 0x07, 0x00, 0x05,
        0x00, 0x04, 0xc0, 0x12, 0xc0, 0x08, 0x00, 0x16, 0x00, 0x0a, 0x00, 0xff, 0x01, 0x00, 0x00, 0x16, 0x00, 0x0b, 0x00, 0x02,
        0x01, 0x00, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x06, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x23, 0x00, 0x00};
    static const uint8_t tls10_no_exts[] = {
        0x16, 0x03, 0x01, 0x00, 0x4b, 0x01, 0x00, 0x00, 0x47, 0x03, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x04, 0x00, 0x05, 0x00, 0x2f, 0x00, 0x33, 0x00, 0x32, 0x00, 0x0a, 0x00, 0x16,
        0x00, 0x13, 0x00, 0x09, 0x00, 0x15, 0x00, 0x12, 0x00, 0x03, 0x00, 0x08, 0x00, 0x14, 0x00, 0x11, 0x00, 0xff, 0x01, 0x00};
    static const uint8_t tls12_no_exts[] = {
        0x16, 0x03, 0x01, 0x00, 0x67, 0x01, 0x00, 0x00, 0x63, 0x03, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0xee, 0x8a, 0x29, 0xdd, 0xcf, 0x6d, 0x64, 0xfd, 0xd0, 0xcd,
        0xa0, 0x9b, 0xc1, 0x32, 0x46, 0xbf, 0x53, 0xda, 0x29, 0x23, 0x81, 0x5f, 0x54, 0x1f, 0xbd, 0xe0, 0x8e, 0x97,
        0x17, 0x5b, 0x03, 0x5d, 0x00, 0x1c, 0x00, 0xff, 0x00, 0x9c, 0xc0, 0x2b, 0xc0, 0x2f, 0xc0, 0x0a, 0xc0, 0x09,
        0xc0, 0x13, 0xc0, 0x14, 0x00, 0x2f, 0x00, 0x35, 0x00, 0x9e, 0x00, 0x33, 0x00, 0x39, 0x00, 0x0a, 0x01, 0x00};
    /* client hello generated by openssl 1.0.0s; s_client -bugs -no_ticket -cipher DES-CBC-SHA -connect */
    static const uint8_t tls10_with_exts[] = {0x16, 0x03, 0x01, 0x00, 0x2f, 0x01, 0x00, 0x00, 0x2b, 0x03, 0x01, 0x63, 0xfc,
                                              0x5a, 0x16, 0xde, 0x7a, 0xfc, 0xc1, 0x0c, 0x54, 0x12, 0xa6, 0xd3, 0x8c, 0xcf,
                                              0xda, 0xd3, 0xcc, 0x50, 0x19, 0x42, 0x5c, 0xb0, 0x81, 0xf6, 0xe2, 0xf9, 0x4b,
                                              0x06, 0x71, 0x68, 0x38, 0x00, 0x00, 0x04, 0x00, 0x09, 0x00, 0xff, 0x01, 0x00};
    /* client hello generated by openssl 0.9.8; we do not bother parsing it */
    static const uint8_t ssl2[] = {
        0x80, 0x80, 0x01, 0x03, 0x01, 0x00, 0x57, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x16, 0x00, 0x00, 0x13, 0x00, 0x00,
        0x0a, 0x07, 0x00, 0xc0, 0x00, 0x00, 0x66, 0x00, 0x00, 0x07, 0x00, 0x00, 0x05, 0x00, 0x00, 0x04, 0x05, 0x00, 0x80,
        0x03, 0x00, 0x80, 0x01, 0x00, 0x80, 0x08, 0x00, 0x80, 0x00, 0x00, 0x65, 0x00, 0x00, 0x64, 0x00, 0x00, 0x63, 0x00,
        0x00, 0x62, 0x00, 0x00, 0x61, 0x00, 0x00, 0x60, 0x00, 0x00, 0x15, 0x00, 0x00, 0x12, 0x00, 0x00, 0x09, 0x06, 0x00,
        0x40, 0x00, 0x00, 0x14, 0x00, 0x00, 0x11, 0x00, 0x00, 0x08, 0x00, 0x00, 0x06, 0x00, 0x00, 0x03, 0x04, 0x00, 0x80,
        0x02, 0x00, 0x80, 0xfb, 0xb8, 0x0c, 0x85, 0xac, 0x46, 0x33, 0x39, 0x70, 0x40, 0x8e, 0x39, 0x05, 0x92, 0x9f, 0xa6,
        0x6d, 0x34, 0xd3, 0x91, 0x23, 0xaf, 0xbe, 0x51, 0x50, 0x72, 0x32, 0xbb, 0xda, 0x8c, 0xf4, 0x35};

    ptls_on_client_hello_t on_client_hello = {test_legacy_ch_tls12_callback}, *orig = ctx->on_client_hello;
    ctx->on_client_hello = &on_client_hello;

    ptls_buffer_t sendbuf;
    ptls_buffer_init(&sendbuf, "", 0);

    ptls_t *tls = ptls_new(ctx, 1);
    size_t len = sizeof(tls12);
    int ret = ptls_handshake(tls, &sendbuf, tls12, &len, NULL);
    ptls_free(tls);
    ok(ret == PTLS_ALERT_PROTOCOL_VERSION);
    ok(legacy_params != NULL);
    ok(legacy_params->incompatible_version);
    ok(sizeof(tls12) - 5 == legacy_params->raw_message.len);
    ok(memcmp(tls12 + 5, legacy_params->raw_message.base, legacy_params->raw_message.len) == 0);
    ok(legacy_params->server_name.len == sizeof("i-need_sni") - 1);
    ok(memcmp(legacy_params->server_name.base, "i_need_sni", sizeof("i-need_sni") - 1) == 0);
    free(legacy_params);
    legacy_params = NULL;

    tls = ptls_new(ctx, 1);
    len = sizeof(tls11);
    ret = ptls_handshake(tls, &sendbuf, tls11, &len, NULL);
    ptls_free(tls);
    ok(ret == PTLS_ALERT_PROTOCOL_VERSION);
    ok(legacy_params->incompatible_version);
    ok(sizeof(tls11) - 5 == legacy_params->raw_message.len);
    ok(memcmp(tls11 + 5, legacy_params->raw_message.base, legacy_params->raw_message.len) == 0);
    ok(legacy_params->server_name.len == 0);
    ok(legacy_params->server_name.base == NULL);
    free(legacy_params);
    legacy_params = NULL;

    tls = ptls_new(ctx, 1);
    len = sizeof(tls10_no_exts);
    ret = ptls_handshake(tls, &sendbuf, tls10_no_exts, &len, NULL);
    ptls_free(tls);
    ok(ret == PTLS_ALERT_PROTOCOL_VERSION);
    ok(legacy_params->incompatible_version);
    ok(sizeof(tls10_no_exts) - 5 == legacy_params->raw_message.len);
    ok(memcmp(tls10_no_exts + 5, legacy_params->raw_message.base, legacy_params->raw_message.len) == 0);
    ok(legacy_params->server_name.len == 0);
    ok(legacy_params->server_name.base == NULL);
    free(legacy_params);
    legacy_params = NULL;

    tls = ptls_new(ctx, 1);
    len = sizeof(tls12_no_exts);
    ret = ptls_handshake(tls, &sendbuf, tls12_no_exts, &len, NULL);
    ptls_free(tls);
    ok(ret == PTLS_ALERT_PROTOCOL_VERSION);
    free(legacy_params);
    legacy_params = NULL;

    tls = ptls_new(ctx, 1);
    len = sizeof(tls10_with_exts);
    ret = ptls_handshake(tls, &sendbuf, tls10_with_exts, &len, NULL);
    ptls_free(tls);
    ok(ret == PTLS_ALERT_PROTOCOL_VERSION);
    ok(legacy_params->incompatible_version);
    ok(sizeof(tls10_with_exts) - 5 == legacy_params->raw_message.len);
    ok(memcmp(tls10_with_exts + 5, legacy_params->raw_message.base, legacy_params->raw_message.len) == 0);
    ok(legacy_params->server_name.len == 0);
    ok(legacy_params->server_name.base == NULL);
    free(legacy_params);
    legacy_params = NULL;

    tls = ptls_new(ctx, 1);
    len = sizeof(ssl2);
    ret = ptls_handshake(tls, &sendbuf, ssl2, &len, NULL);
    ptls_free(tls);
    ok(ret == PTLS_ALERT_DECODE_ERROR);
    ok(legacy_params == NULL); /* SSL2 is not even parsed */

    ctx->on_client_hello = orig;
}

static void test_escape_json_unsafe_string(void)
{
#define STRLIT(s) s, sizeof(s) - 1
    char buf[100];
    size_t escaped_len;

    escaped_len = ptls_jsonescape(buf, STRLIT("\" \\ / \b \f \n \r \t foo bar")) - buf;
    ok(escaped_len == strlen(buf));
    ok(strcmp(buf, "\\\" \\\\ \\/ \\b \\f \\n \\r \\t foo bar") == 0);

    escaped_len = ptls_jsonescape(buf, STRLIT("こんにちは、🌏！")) - buf;
    ok(strcmp(buf, "こんにちは、🌏！") == 0);

    escaped_len = ptls_jsonescape(buf, STRLIT("\x00 \x1f \x7f")) - buf;
    ok(strcmp(buf, "\\u0000 \\u001f \\u007f") == 0);
#undef STRLIT
}

void test_picotls(void)
{
    subtest("is_ipaddr", test_is_ipaddr);
    subtest("extension_bitmap", test_extension_bitmap);
    subtest("select_cipher", test_select_cipher);
    subtest("sha256", test_sha256);
    subtest("sha384", test_sha384);
    subtest("hmac-sha256", test_hmac_sha256);
    subtest("hkdf", test_hkdf);
    subtest("aes128gcm", test_aes128gcm);
    subtest("aes256gcm", test_aes256gcm);
    subtest("chacha20poly1305", test_chacha20poly1305);
#ifdef PTLS_HAVE_AEGIS
    subtest("aegis-128l", test_aegis128l);
    subtest("aegis-256", test_aegis256);
#endif
    subtest("aes128ecb", test_aes128ecb);
    subtest("aes256ecb", test_aes256ecb);
    subtest("aes128ctr", test_aes128ctr);
    subtest("chacha20", test_chacha20);
    subtest("ffx", test_ffx);
    subtest("base64-decode", test_base64_decode);
    subtest("tls-block8", test_tlsblock8);
    subtest("tls-block16", test_tlsblock16);
    subtest("ech", test_ech);
    subtest("fragmented-message", test_fragmented_message);
    subtest("handshake", test_all_handshakes);
    subtest("quic", test_quic);
    subtest("legacy-ch", test_legacy_ch);
    subtest("ptls_escape_json_unsafe_string", test_escape_json_unsafe_string);
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

    /* client invalid input */
    ret = client->create(client, &ctx);
    ok(ret == 0);
    client_secret = ptls_iovec_init(NULL, 0);
    ret = ctx->on_exchange(&ctx, 1, &client_secret, ptls_iovec_init(ctx->pubkey.base, ctx->pubkey.len - 1));
    ok(ret != 0);
    ok(ctx == NULL);
    ok(client_secret.base == NULL);

    /* test derivation failure. In case of X25519, the outcome is derived key becoming all-zero and rejected. In case of others, it
     * is most likely that the provided key would be rejected. */
    server_pubkey = ptls_iovec_init(NULL, 0);
    server_secret = ptls_iovec_init(NULL, 0);
    static uint8_t zeros[32] = {0};
    ret = server->exchange(server, &server_pubkey, &server_secret, ptls_iovec_init(zeros, sizeof(zeros)));
    ok(ret != 0);
    ok(server_pubkey.base == NULL);
    ok(server_secret.base == NULL);
}
