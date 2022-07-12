/*
 * Copyright (c) 2020 Fastly, Kazuho Oku
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
#include "picotls/fusion.h"
#include "picotls/minicrypto.h"
#include "../deps/picotest/picotest.h"
#include "../lib/fusion.c"

static const char *tostr(const void *_p, size_t len)
{
    static char *buf;

    if (buf != NULL)
        free(buf);
    buf = malloc(len * 2 + 1);

    const uint8_t *s = _p;
    char *d = buf;

    for (; len != 0; --len) {
        *d++ = "0123456789abcdef"[*s >> 4];
        *d++ = "0123456789abcdef"[*s & 0xf];
        ++s;
    }
    *d = '\0';

    return buf;
}

static void test_loadn128(void)
{
    uint8_t buf[8192] = {0};

    for (size_t off = 0; off < 8192 - 15; ++off) {
        uint8_t *src = buf + off;
        memcpy(src, "hello world12345", 16);
        __m128i v = loadn128(src, 11);
        if (memcmp(&v, "hello world\0\0\0\0\0", 16) != 0) {
            ok(!"fail");
            return;
        }
        memset(src, 0, 11);
    }
    ok(!!"success");
}

static const uint8_t zero[16384] = {0};

static void test_ecb(void)
{
    ptls_fusion_aesecb_context_t ecb;
    uint8_t encrypted[16];

    ptls_fusion_aesecb_init(&ecb, 1, zero, 16, 0);
    ptls_fusion_aesecb_encrypt(&ecb, encrypted, "hello world!!!!!");
    ptls_fusion_aesecb_dispose(&ecb);
    ok(strcmp(tostr(encrypted, 16), "172afecb50b5f1237814b2f7cb51d0f7") == 0);

    ptls_fusion_aesecb_init(&ecb, 1, zero, 32, 0);
    ptls_fusion_aesecb_encrypt(&ecb, encrypted, "hello world!!!!!");
    ptls_fusion_aesecb_dispose(&ecb);
    ok(strcmp(tostr(encrypted, 16), "2a033f0627b3554aa4fe5786550736ff") == 0);
}

static void test_gfmul(void)
{
    ptls_fusion_aesgcm_context_t *ctx;
    size_t ghash_cnt = 4;

    ctx = malloc(calc_aesgcm_context_size(&ghash_cnt, ptls_fusion_can_aesni256));
    *ctx = (ptls_fusion_aesgcm_context_t){
        .ecb = {.aesni256 = ptls_fusion_can_aesni256},
        .capacity = ghash_cnt * 16,
    };

    __m128i H0 = _mm_loadu_si128((void *)"hello world bye");
    if (ctx->ecb.aesni256) {
        ((struct ptls_fusion_aesgcm_context256 *)ctx)->ghash[0].H[1] = H0;
    } else {
        ((struct ptls_fusion_aesgcm_context128 *)ctx)->ghash[0].H = H0;
    }

    while (ctx->ghash_cnt < ghash_cnt)
        setup_one_ghash_entry(ctx);

#define GHASH128 (((struct ptls_fusion_aesgcm_context128 *)ctx)->ghash)
#define GHASH256 (((struct ptls_fusion_aesgcm_context256 *)ctx)->ghash)

    {                                                     /* one block */
        static const char input[32] = "deaddeadbeefbeef"; /* latter 16-bytes are NUL */
        __m128i hash;
        if (ctx->ecb.aesni256) {
            struct ptls_fusion_gfmul_state256 state;
            state.lo = _mm256_setzero_si256();
            gfmul_firststep256(&state, _mm256_loadu_si256((void *)input), 1, GHASH256);
            gfmul_reduce256(&state);
            hash = _mm256_castsi256_si128(state.lo);
        } else {
            struct ptls_fusion_gfmul_state128 state;
            state.lo = _mm_setzero_si128();
            gfmul_firststep128(&state, _mm_loadu_si128((void *)input), GHASH128);
            gfmul_reduce128(&state);
            hash = state.lo;
        }
        ok(memcmp(&hash, "\x12\xd9\xd9\x14\x8b\x3f\x20\xbd\x20\x2a\xa5\x9e\x17\xa8\xb0\x7b", 16) == 0);
    }

    { /* two blocks */
        static const char input[32] = "Lorem ipsum dolor sit amet, con";
        __m128i hash;
        if (ctx->ecb.aesni256) {
            struct ptls_fusion_gfmul_state256 state;
            state.lo = _mm256_setzero_si256();
            gfmul_firststep256(&state, _mm256_loadu_si256((void *)input), 0, GHASH256);
            gfmul_reduce256(&state);
            hash = _mm256_castsi256_si128(state.lo);
        } else {
            struct ptls_fusion_gfmul_state128 state;
            state.lo = _mm_setzero_si128();
            gfmul_firststep128(&state, _mm_loadu_si128((void *)input), GHASH128 + 1);
            gfmul_nextstep128(&state, _mm_loadu_si128((void *)(input + 16)), GHASH128);
            gfmul_reduce128(&state);
            hash = state.lo;
        }
        ok(memcmp(&hash, "\xda\xdf\xe8\x9b\xc7\x8c\xbd\x5c\xa7\xc1\x83\x9a\xa2\x9f\x80\x55", 16) == 0);
    }

    { /* three blocks */
        static const char input[64] = "The quick brown fox jumps over the lazy dog.";
        __m128i hash;
        if (ctx->ecb.aesni256) {
            struct ptls_fusion_gfmul_state256 state;
            state.lo = _mm256_setzero_si256();
            gfmul_firststep256(&state, _mm256_loadu_si256((void *)input), 1, GHASH256 + 1);
            gfmul_nextstep256(&state, _mm256_loadu_si256((void *)(input + 16)), GHASH256);
            gfmul_reduce256(&state);
            hash = _mm256_castsi256_si128(state.lo);
        } else {
            struct ptls_fusion_gfmul_state128 state;
            state.lo = _mm_setzero_si128();
            gfmul_firststep128(&state, _mm_loadu_si128((void *)input), GHASH128 + 2);
            gfmul_nextstep128(&state, _mm_loadu_si128((void *)(input + 16)), GHASH128 + 1);
            gfmul_nextstep128(&state, _mm_loadu_si128((void *)(input + 32)), GHASH128);
            gfmul_reduce128(&state);
            hash = state.lo;
        }
        ok(memcmp(&hash, "\xad\xdf\x91\x52\x38\x40\xf7\xc3\x85\xaf\x41\xb1\x7d\xed\x4b\x56", 16) == 0);
    }

    { /* five blocks */
        static const char input[96] =
            "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor "; /* last 16 bytes are NUL */
        __m128i hash;
        if (ctx->ecb.aesni256) {
            struct ptls_fusion_gfmul_state256 state;
            state.lo = _mm256_setzero_si256();
            gfmul_firststep256(&state, _mm256_loadu_si256((void *)input), 0, GHASH256 + 1);
            gfmul_nextstep256(&state, _mm256_loadu_si256((void *)(input + 32)), GHASH256);
            gfmul_reduce256(&state);
            gfmul_firststep256(&state, _mm256_loadu_si256((void *)(input + 64)), 1, GHASH256);
            gfmul_reduce256(&state);
            hash = _mm256_castsi256_si128(state.lo);
        } else {
            struct ptls_fusion_gfmul_state128 state;
            state.lo = _mm_setzero_si128();
            gfmul_firststep128(&state, _mm_loadu_si128((void *)input), GHASH128 + 3);
            gfmul_nextstep128(&state, _mm_loadu_si128((void *)(input + 16)), GHASH128 + 2);
            gfmul_nextstep128(&state, _mm_loadu_si128((void *)(input + 32)), GHASH128 + 1);
            gfmul_nextstep128(&state, _mm_loadu_si128((void *)(input + 48)), GHASH128);
            gfmul_reduce128(&state);
            gfmul_firststep128(&state, _mm_loadu_si128((void *)(input + 64)), GHASH128);
            gfmul_reduce128(&state);
            hash = state.lo;
        }
        ok(memcmp(&hash, "\xb8\xab\x1b\xa8\xf2\x92\xf3\x89\x44\x9d\x39\xf6\xb6\x37\xca\x5d", 16) == 0);
    }

    { /* six blocks */
        static const char input[96] =
            "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut la";
        __m128i hash;
        if (ctx->ecb.aesni256) {
            struct ptls_fusion_gfmul_state256 state;
            state.lo = _mm256_setzero_si256();
            gfmul_firststep256(&state, _mm256_loadu_si256((void *)input), 0, GHASH256 + 1);
            gfmul_nextstep256(&state, _mm256_loadu_si256((void *)(input + 32)), GHASH256);
            gfmul_reduce256(&state);
            gfmul_firststep256(&state, _mm256_loadu_si256((void *)(input + 64)), 0, GHASH256);
            gfmul_reduce256(&state);
            hash = _mm256_castsi256_si128(state.lo);
        } else {
            struct ptls_fusion_gfmul_state128 state;
            state.lo = _mm_setzero_si128();
            gfmul_firststep128(&state, _mm_loadu_si128((void *)input), GHASH128 + 3);
            gfmul_nextstep128(&state, _mm_loadu_si128((void *)(input + 16)), GHASH128 + 2);
            gfmul_nextstep128(&state, _mm_loadu_si128((void *)(input + 32)), GHASH128 + 1);
            gfmul_nextstep128(&state, _mm_loadu_si128((void *)(input + 48)), GHASH128);
            gfmul_reduce128(&state);
            gfmul_firststep128(&state, _mm_loadu_si128((void *)(input + 64)), GHASH128 + 1);
            gfmul_nextstep128(&state, _mm_loadu_si128((void *)(input + 80)), GHASH128);
            gfmul_reduce128(&state);
            hash = state.lo;
        }
        ok(memcmp(&hash, "\x52\xce\x25\x22\x86\x2c\x91\xa4\xe7\x4e\xf9\x9a\x32\x77\xbd\x3e", 16) == 0);
    }

    free(ctx);

#undef GHASH128
#undef GHASH256
}

static void gcm_basic(void)
{
    {
        static const uint8_t expected[] = {0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92, 0xf3, 0x28, 0xc2,
                                           0xb9, 0x71, 0xb2, 0xfe, 0x78, 0x97, 0x3f, 0xbc, 0xa6, 0x54, 0x77,
                                           0xbf, 0x47, 0x85, 0xb0, 0xd5, 0x61, 0xf7, 0xe3, 0xfd, 0x6c};
        ptls_fusion_aesgcm_context_t *ctx = ptls_fusion_aesgcm_new(zero, PTLS_AES128_KEY_SIZE, 5 + 16);
        uint8_t encrypted[sizeof(expected)], decrypted[sizeof(expected) - 16];
        ptls_fusion_aesgcm_encrypt(ctx, encrypted, zero, 16, _mm_setzero_si128(), "hello", 5, NULL);
        ok(memcmp(expected, encrypted, sizeof(expected)) == 0);
        memset(decrypted, 0x55, sizeof(decrypted));
        ok(ptls_fusion_aesgcm_decrypt(ctx, decrypted, expected, 16, _mm_setzero_si128(), "hello", 5, expected + 16));
        ok(memcmp(decrypted, zero, sizeof(decrypted)) == 0);
        ptls_fusion_aesgcm_free(ctx);
    }

    {
        static const uint8_t key[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                                        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
                             aad[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19},
                             iv[] = {20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31},
                             plaintext[] =
                                 "hello world\nhello world\nhello world\nhello world\nhello world\nhello world\nhello world\n";
        static const uint8_t expected[] = {0xd3, 0xa8, 0x1d, 0x96, 0x4c, 0x9b, 0x02, 0xd7, 0x9a, 0xb0, 0x41, 0x07, 0x4c, 0x8c, 0xe2,
                                           0xe0, 0x2e, 0x83, 0x54, 0x52, 0x45, 0xcb, 0xd4, 0x68, 0xc8, 0x43, 0x45, 0xca, 0x91, 0xfb,
                                           0xa3, 0x7a, 0x67, 0xed, 0xe8, 0xd7, 0x5e, 0xe2, 0x33, 0xd1, 0x3e, 0xbf, 0x50, 0xc2, 0x4b,
                                           0x86, 0x83, 0x55, 0x11, 0xbb, 0x17, 0x4f, 0xf5, 0x78, 0xb8, 0x65, 0xeb, 0x9a, 0x2b, 0x8f,
                                           0x77, 0x08, 0xa9, 0x60, 0x17, 0x73, 0xc5, 0x07, 0xf3, 0x04, 0xc9, 0x3f, 0x67, 0x4d, 0x12,
                                           0xa1, 0x02, 0x93, 0xc2, 0x3c, 0xd3, 0xf8, 0x59, 0x33, 0xd5, 0x01, 0xc3, 0xbb, 0xaa, 0xe6,
                                           0x3f, 0xbb, 0x23, 0x66, 0x94, 0x26, 0x28, 0x43, 0xa5, 0xfd, 0x2f};
        ptls_aead_context_t *aead = ptls_aead_new_direct(&ptls_fusion_aes128gcm, 0, key, iv);
        uint8_t encrypted[sizeof(plaintext) + 16], decrypted[sizeof(plaintext)];
        ptls_aead_encrypt(aead, encrypted, plaintext, sizeof(plaintext), 0, aad, sizeof(aad));
        ok(memcmp(expected, encrypted, sizeof(plaintext)) == 0);
        ok(memcmp(expected + sizeof(plaintext), encrypted + sizeof(plaintext), 16) == 0);
        ok(ptls_aead_decrypt(aead, decrypted, encrypted, sizeof(encrypted), 0, aad, sizeof(aad)) == sizeof(plaintext));
        ok(memcmp(decrypted, plaintext, sizeof(plaintext)) == 0);
        ptls_aead_free(aead);
    }
}

static void gcm_capacity(void)
{
    static const uint8_t expected[17] = {0x5b, 0x27, 0x21, 0x5e, 0xd8, 0x1a, 0x70, 0x2e, 0x39,
                                         0x41, 0xc8, 0x05, 0x77, 0xd5, 0x2f, 0xcb, 0x57};
    ptls_fusion_aesgcm_context_t *ctx = ptls_fusion_aesgcm_new(zero, PTLS_AES128_KEY_SIZE, 2);
    uint8_t encrypted[17], decrypted[1] = {0x55};
    ptls_fusion_aesgcm_encrypt(ctx, encrypted, "X", 1, _mm_setzero_si128(), "a", 1, NULL);
    ok(memcmp(expected, encrypted, 17) == 0);
    ok(ptls_fusion_aesgcm_decrypt(ctx, decrypted, expected, 1, _mm_setzero_si128(), "a", 1, expected + 1));
    ok('X' == decrypted[0]);
    ptls_fusion_aesgcm_free(ctx);
}

static void gcm_test_vectors(void)
{
    static const uint8_t one[16] = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
    ptls_fusion_aesgcm_context_t *aead = ptls_fusion_aesgcm_new(zero, PTLS_AES128_KEY_SIZE, sizeof(zero));
    ptls_aead_supplementary_encryption_t *supp = NULL;

    for (int i = 0; i < 2; ++i) {
        uint8_t encrypted[sizeof(zero) + 16], decrypted[sizeof(zero)];
#define DOIT(aad, aadlen, ptlen, expected_tag, expected_supp)                                                                      \
    do {                                                                                                                           \
        memset(encrypted, 0xcc, sizeof(encrypted));                                                                                \
        ptls_fusion_aesgcm_encrypt(aead, encrypted, zero, ptlen, _mm_setzero_si128(), aad, aadlen, supp);                          \
        ok(strcmp(tostr(encrypted + ptlen, 16), expected_tag) == 0);                                                               \
        if (supp != NULL)                                                                                                          \
            ok(strcmp(tostr(supp->output, sizeof(supp->output)), expected_supp) == 0);                                             \
        memset(decrypted, 0x55, sizeof(decrypted));                                                                                \
        ok(ptls_fusion_aesgcm_decrypt(aead, decrypted, encrypted, ptlen, _mm_setzero_si128(), aad, aadlen, encrypted + ptlen));    \
        ok(memcmp(decrypted, zero, ptlen) == 0);                                                                                   \
    } while (0)

        DOIT(zero, 13, 17, "1b4e515384e8aa5bb781ee12549a2ccf", "4576f18ef3ae9dfd37cf72c4592da874");
        DOIT(zero, 13, 32, "84030586f55adf8ac3c145913c6fd0f8", "a062016e90dcc316d061fde5424cf34f");
        DOIT(zero, 13, 64, "66165d39739c50c90727e7d49127146b", "a062016e90dcc316d061fde5424cf34f");
        DOIT(zero, 13, 65, "eb3b75e1d4431e1bb67da46f6a1a0edd", "a062016e90dcc316d061fde5424cf34f");
        DOIT(zero, 13, 79, "8f4a96c7390c26bb15b68865e6a861b9", "a062016e90dcc316d061fde5424cf34f");
        DOIT(zero, 13, 80, "5cc2554857b19e7a9e18d015feac61fd", "a062016e90dcc316d061fde5424cf34f");
        DOIT(zero, 13, 81, "5a65f0d4db36c981bf7babd11691fe78", "a062016e90dcc316d061fde5424cf34f");
        DOIT(zero, 13, 95, "6a8a51152efe928999a610d8a7b1df9d", "a062016e90dcc316d061fde5424cf34f");
        DOIT(zero, 13, 96, "6b9c468e24ed96010687f3880a044d42", "a062016e90dcc316d061fde5424cf34f");
        DOIT(zero, 13, 97, "1b4eb785b884a7d4fdebaff81c1c12e8", "a062016e90dcc316d061fde5424cf34f");

        DOIT(zero, 22, 1328, "0507baaece8d573774c94e8103821316", "a062016e90dcc316d061fde5424cf34f");
        DOIT(zero, 21, 1329, "dd70d59030eadb6313e778046540a253", "a062016e90dcc316d061fde5424cf34f");
        DOIT(zero, 20, 1330, "f1b456b955afde7603188af0124a32ef", "a062016e90dcc316d061fde5424cf34f");

        DOIT(zero, 13, 1337, "a22deec51250a7eb1f4384dea5f2e890", "a062016e90dcc316d061fde5424cf34f");
        DOIT(zero, 12, 1338, "42102b0a499b2efa89702ece4b0c5789", "a062016e90dcc316d061fde5424cf34f");
        DOIT(zero, 11, 1339, "9827f0b34252160d0365ffaa9364bedc", "a062016e90dcc316d061fde5424cf34f");

        DOIT(zero, 0, 80, "98885a3a22bd4742fe7b72172193b163", "a062016e90dcc316d061fde5424cf34f");
        DOIT(zero, 0, 96, "afd649fc51e14f3966e4518ad53b9ddc", "a062016e90dcc316d061fde5424cf34f");

        DOIT(zero, 20, 85, "afe8b727057c804a0525c2914ef856b0", "a062016e90dcc316d061fde5424cf34f");

#undef DOIT

        supp = malloc(sizeof(*supp));
        supp->ctx = ptls_cipher_new(&ptls_fusion_aes128ctr, 1, one);
        supp->input = encrypted + 2;
    }

    ptls_cipher_free(supp->ctx);
    free(supp);
    ptls_fusion_aesgcm_free(aead);
}

static void gcm_iv96(void)
{
    static const uint8_t key[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
                         aad[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19},
                         iv[] = {20, 20, 20, 20, 24, 25, 26, 27, 28, 29, 30, 31},
                         plaintext[] =
                             "hello world\nhello world\nhello world\nhello world\nhello world\nhello world\nhello world\n";
    static const uint8_t expected[] = {0xd3, 0xa8, 0x1d, 0x96, 0x4c, 0x9b, 0x02, 0xd7, 0x9a, 0xb0, 0x41, 0x07, 0x4c, 0x8c, 0xe2,
                                       0xe0, 0x2e, 0x83, 0x54, 0x52, 0x45, 0xcb, 0xd4, 0x68, 0xc8, 0x43, 0x45, 0xca, 0x91, 0xfb,
                                       0xa3, 0x7a, 0x67, 0xed, 0xe8, 0xd7, 0x5e, 0xe2, 0x33, 0xd1, 0x3e, 0xbf, 0x50, 0xc2, 0x4b,
                                       0x86, 0x83, 0x55, 0x11, 0xbb, 0x17, 0x4f, 0xf5, 0x78, 0xb8, 0x65, 0xeb, 0x9a, 0x2b, 0x8f,
                                       0x77, 0x08, 0xa9, 0x60, 0x17, 0x73, 0xc5, 0x07, 0xf3, 0x04, 0xc9, 0x3f, 0x67, 0x4d, 0x12,
                                       0xa1, 0x02, 0x93, 0xc2, 0x3c, 0xd3, 0xf8, 0x59, 0x33, 0xd5, 0x01, 0xc3, 0xbb, 0xaa, 0xe6,
                                       0x3f, 0xbb, 0x23, 0x66, 0x94, 0x26, 0x28, 0x43, 0xa5, 0xfd, 0x2f};

    ptls_aead_context_t *aead = ptls_aead_new_direct(&ptls_fusion_aes128gcm, 0, key, iv);
    uint8_t encrypted[sizeof(plaintext) + 16], decrypted[sizeof(plaintext)];
    uint8_t seq32[4] = {0, 1, 2, 3};
    uint8_t seq32_bad[4] = {0x89, 0xab, 0xcd, 0xef};

    ptls_aead_xor_iv(aead, seq32, sizeof(seq32));
    ptls_aead_encrypt(aead, encrypted, plaintext, sizeof(plaintext), 0, aad, sizeof(aad));
    ok(memcmp(expected, encrypted, sizeof(plaintext)) == 0);
    ok(memcmp(expected + sizeof(plaintext), encrypted + sizeof(plaintext), 16) == 0);
    ok(ptls_aead_decrypt(aead, decrypted, encrypted, sizeof(encrypted), 0, aad, sizeof(aad)) == sizeof(plaintext));
    ok(memcmp(decrypted, plaintext, sizeof(plaintext)) == 0);
    ptls_aead_xor_iv(aead, seq32, sizeof(seq32));
    ptls_aead_xor_iv(aead, seq32_bad, sizeof(seq32_bad));
    ok(ptls_aead_decrypt(aead, decrypted, encrypted, sizeof(encrypted), 0, aad, sizeof(aad)) == SIZE_MAX);
    ptls_aead_xor_iv(aead, seq32_bad, sizeof(seq32_bad));
    ptls_aead_xor_iv(aead, seq32, sizeof(seq32));
    ok(ptls_aead_decrypt(aead, decrypted, encrypted, sizeof(encrypted), 0, aad, sizeof(aad)) == sizeof(plaintext));
    ok(memcmp(decrypted, plaintext, sizeof(plaintext)) == 0);
    ptls_aead_free(aead);
}

static ptls_aead_algorithm_t *test_generated_encryptor, *test_generated_decryptor;
static int test_generated_iv96, test_generated_multivec;

static void test_generated(void)
{
    ptls_cipher_context_t *rand = ptls_cipher_new(&ptls_minicrypto_aes128ctr, 1, zero);
    ptls_cipher_init(rand, zero);
    int i;
#ifdef _WINDOWS
    const int nb_runs = 1000;
#else
    const int nb_runs = 10000;
#endif
    for (i = 0; i < nb_runs; ++i) {
        if (i % 100 == 0) {
            fputc('.', stderr);
            fflush(stderr);
        }
        /* generate input using RNG */
        uint8_t key[32], iv[12], seq32[4], aadlen, textlen;
        uint64_t seq;
        ptls_cipher_encrypt(rand, key, zero, sizeof(key));
        ptls_cipher_encrypt(rand, iv, zero, sizeof(iv));
        ptls_cipher_encrypt(rand, &aadlen, zero, sizeof(aadlen));
        ptls_cipher_encrypt(rand, &textlen, zero, sizeof(textlen));
        ptls_cipher_encrypt(rand, &seq, zero, sizeof(seq));
        ptls_cipher_encrypt(rand, seq32, zero, sizeof(seq32));

        uint8_t aad[256], text[256];

        ptls_cipher_encrypt(rand, aad, zero, sizeof(aad));
        ptls_cipher_encrypt(rand, text, zero, sizeof(text));

        uint8_t encrypted[272], decrypted[256];

        memset(encrypted, 0x55, sizeof(encrypted));
        memset(decrypted, 0xcc, sizeof(decrypted));

        { /* check using fusion */
            ptls_aead_context_t *ctx = ptls_aead_new_direct(test_generated_encryptor, 1, key, iv);
            if (test_generated_iv96)
                ptls_aead_xor_iv(ctx, seq32, sizeof(seq32));
            if (test_generated_multivec) {
                uint8_t pos1, pos2;
                do {
                    ptls_cipher_encrypt(rand, &pos2, zero, sizeof(pos2));
                } while (pos2 > textlen);
                do {
                    ptls_cipher_encrypt(rand, &pos1, zero, sizeof(pos1));
                } while (pos1 > pos2);
                ptls_iovec_t textvec[3] = {{text, pos1}, {text + pos1, pos2 - pos1}, {text + pos2, textlen - pos2}};
                ptls_aead_encrypt_v(ctx, encrypted, textvec, 3, seq, aad, aadlen);
            } else {
                ptls_aead_encrypt(ctx, encrypted, text, textlen, seq, aad, aadlen);
            }
            ptls_aead_free(ctx);
        }

        memset(decrypted, 0xcc, sizeof(decrypted));

        { /* check that the encrypted text can be decrypted by the decryptor */
            ptls_aead_context_t *ctx = ptls_aead_new_direct(test_generated_decryptor, 0, key, iv);
            if (test_generated_iv96)
                ptls_aead_xor_iv(ctx, seq32, sizeof(seq32));
            if (ptls_aead_decrypt(ctx, decrypted, encrypted, textlen + 16, seq, aad, aadlen) != textlen)
                goto Fail;
            if (memcmp(decrypted, text, textlen) != 0)
                goto Fail;
            ptls_aead_free(ctx);
        }
    }

    fputc('\n', stderr);
    fflush(stderr);

    ok(1);
    ptls_cipher_free(rand);
    return;

Fail:
    fputc('\n', stderr);
    fflush(stderr);
    note("mismatch at index=%d", i);
    ok(0);
}

static void test_generated_all(ptls_aead_algorithm_t *e1, ptls_aead_algorithm_t *e2, int can_multivec)
{
    test_generated_encryptor = e1;
    test_generated_decryptor = e2;

    test_generated_iv96 = 0;
    subtest("encrypt", test_generated);
    test_generated_iv96 = 1;
    subtest("encrypt-iv96", test_generated);

    if (can_multivec) {
        test_generated_multivec = 1;
        test_generated_iv96 = 0;
        subtest("encrypt", test_generated);
        test_generated_iv96 = 1;
        subtest("encrypt-iv96", test_generated);
        test_generated_multivec = 0;
    }

    test_generated_encryptor = e2;
    test_generated_decryptor = e1;

    test_generated_iv96 = 0;
    subtest("decrypt", test_generated);
    test_generated_iv96 = 1;
    subtest("decrypt-iv96", test_generated);
}

static void test_fusion_aes128gcm(void)
{
    test_generated_all(&ptls_fusion_aes128gcm, &ptls_minicrypto_aes128gcm, 0);
}

static void test_fusion_aes256gcm(void)
{
    test_generated_all(&ptls_fusion_aes256gcm, &ptls_minicrypto_aes256gcm, 0);
}

static void test_fusion_aesgcm(void)
{
    subtest("128", test_fusion_aes128gcm);
    subtest("256", test_fusion_aes256gcm);
}

static void test_non_temporal_aes128gcm(void)
{
    test_generated_all(&ptls_non_temporal_aes128gcm, &ptls_minicrypto_aes128gcm, 1);
}

static void test_non_temporal_aes256gcm(void)
{
    test_generated_all(&ptls_non_temporal_aes256gcm, &ptls_minicrypto_aes256gcm, 1);
}

static void test_non_temporal(void)
{
    subtest("128", test_non_temporal_aes128gcm);
    subtest("256", test_non_temporal_aes256gcm);
}

int main(int argc, char **argv)
{
    if (!ptls_fusion_is_supported_by_cpu()) {
        note("CPU does have the necessary features (avx2, aes, pclmul)\n");
        return done_testing();
    }
    int can256bit = ptls_fusion_can_aesni256;
    ptls_fusion_can_aesni256 = 0;

    subtest("loadn128", test_loadn128);
    subtest("ecb", test_ecb);
    subtest("gfmul128", test_gfmul);
    subtest("gcm-basic", gcm_basic);
    subtest("gcm-capacity", gcm_capacity);
    subtest("gcm-test-vectors", gcm_test_vectors);
    subtest("gcm-iv96", gcm_iv96);
    subtest("fusion-aesgcm", test_fusion_aesgcm);
    subtest("non-temporal-avx128", test_non_temporal);

    if (can256bit) {
        ptls_fusion_can_aesni256 = 1;
        subtest("gfmul256", test_gfmul);
        subtest("non-temporal-avx256", test_non_temporal);
        ptls_fusion_can_aesni256 = 0;
    } else {
        note("gfmul256: skipping, CPU does not support 256-bit aes / clmul");
    }

    return done_testing();
}
