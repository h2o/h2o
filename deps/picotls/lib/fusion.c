/*
 * This source file is licensed under the Apache License 2.0 *and* the MIT
 * License. Please agree to *both* of the licensing terms!
 *
 *
 * `transformH` function is a derivative work of OpenSSL. The original work
 * is covered by the following license:
 *
 * Copyright 2013-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 *
 * All other work, including modifications to the `transformH` function is
 * covered by the following MIT license:
 *
 * Copyright (c) 2020-2022 Fastly, Kazuho Oku
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
#include <stdint.h>

#include <stdlib.h>
#include <string.h>
#include <immintrin.h>
#include <tmmintrin.h>
#include <nmmintrin.h>
#include <wmmintrin.h>
#include "picotls.h"
#include "picotls/fusion.h"

#if defined(__clang__)
#if __has_feature(address_sanitizer)
#define NO_SANITIZE_ADDRESS __attribute__((no_sanitize("address")))
#endif
#elif __SANITIZE_ADDRESS__ /* gcc */
#define NO_SANITIZE_ADDRESS __attribute__((no_sanitize_address))
#endif
#ifndef NO_SANITIZE_ADDRESS
#define NO_SANITIZE_ADDRESS
#endif

#ifdef _WINDOWS
#define aligned_alloc(a, s) _aligned_malloc((s), (a))
#endif

struct ptls_fusion_aesgcm_context {
    ptls_fusion_aesecb_context_t ecb;
    size_t capacity;
    size_t ghash_cnt;
};

struct ptls_fusion_aesgcm_context128 {
    struct ptls_fusion_aesgcm_context super;
    struct ptls_fusion_aesgcm_ghash_precompute128 {
        __m128i H;
        __m128i r;
    } ghash[0];
};

struct ptls_fusion_aesgcm_context256 {
    struct ptls_fusion_aesgcm_context super;
    union ptls_fusion_aesgcm_ghash_precompute256 {
        struct {
            __m128i H[2];
            __m128i r[2];
        };
        struct {
            __m256i Hx2;
            __m256i rx2;
        };
    } ghash[0];
};

struct ctr_context {
    ptls_cipher_context_t super;
    ptls_fusion_aesecb_context_t fusion;
    __m128i bits;
    uint8_t is_ready;
};

struct aesgcm_context {
    ptls_aead_context_t super;
    ptls_fusion_aesgcm_context_t *aesgcm;
    /**
     * retains the static IV in the upper 96 bits (in little endian)
     */
    __m128i static_iv;
};

static const uint64_t poly_[2] __attribute__((aligned(16))) = {1, 0xc200000000000000};
#define poly (*(__m128i *)poly_)
static const uint8_t byteswap_[32] __attribute__((aligned(32))) = {15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0,
                                                                   15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0};
#define byteswap128 (*(__m128i *)byteswap_)
#define byteswap256 (*(__m256i *)byteswap_)
static const uint8_t one_[16] __attribute__((aligned(16))) = {1};
#define one8 (*(__m128i *)one_)
static const uint8_t incr128x2_[32] __attribute__((aligned(32))) = {2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2};
#define incr128x2 (*(__m256i *)incr128x2_)

/* This function is covered by the Apache License and the MIT License. The origin is crypto/modes/asm/ghash-x86_64.pl of openssl
 * at commit 33388b4. */
static __m128i transformH(__m128i H)
{
    //  # <<1 twist
    //  pshufd          \$0b11111111,$Hkey,$T2  # broadcast uppermost dword
    __m128i t2 = _mm_shuffle_epi32(H, 0xff);
    // movdqa          $Hkey,$T1
    __m128i t1 = H;
    // psllq           \$1,$Hkey
    H = _mm_slli_epi64(H, 1);
    // pxor            $T3,$T3                 #
    __m128i t3 = _mm_setzero_si128();
    // psrlq           \$63,$T1
    t1 = _mm_srli_epi64(t1, 63);
    // pcmpgtd         $T2,$T3                 # broadcast carry bit
    t3 = _mm_cmplt_epi32(t2, t3);
    //     pslldq          \$8,$T1
    t1 = _mm_slli_si128(t1, 8);
    // por             $T1,$Hkey               # H<<=1
    H = _mm_or_si128(t1, H);

    // # magic reduction
    // pand            .L0x1c2_polynomial(%rip),$T3
    t3 = _mm_and_si128(t3, poly);
    // pxor            $T3,$Hkey               # if(carry) H^=0x1c2_polynomial
    H = _mm_xor_si128(t3, H);

    return H;
}
// end of Apache License code

static __m128i gfmul(__m128i x, __m128i y)
{
    __m128i lo = _mm_clmulepi64_si128(x, y, 0x00);
    __m128i hi = _mm_clmulepi64_si128(x, y, 0x11);

    __m128i a = _mm_shuffle_epi32(x, 78);
    __m128i b = _mm_shuffle_epi32(y, 78);
    a = _mm_xor_si128(a, x);
    b = _mm_xor_si128(b, y);

    a = _mm_clmulepi64_si128(a, b, 0x00);
    a = _mm_xor_si128(a, lo);
    a = _mm_xor_si128(a, hi);

    b = _mm_slli_si128(a, 8);
    a = _mm_srli_si128(a, 8);

    lo = _mm_xor_si128(lo, b);
    hi = _mm_xor_si128(hi, a);

    // from https://crypto.stanford.edu/RealWorldCrypto/slides/gueron.pdf
    __m128i t = _mm_clmulepi64_si128(lo, poly, 0x10);
    lo = _mm_shuffle_epi32(lo, 78);
    lo = _mm_xor_si128(lo, t);
    t = _mm_clmulepi64_si128(lo, poly, 0x10);
    lo = _mm_shuffle_epi32(lo, 78);
    lo = _mm_xor_si128(lo, t);

    return _mm_xor_si128(hi, lo);
}

static inline __m128i gfmul_do_reduce(__m128i hi, __m128i lo, __m128i mid)
{
    mid = _mm_xor_si128(mid, hi);
    mid = _mm_xor_si128(mid, lo);
    lo = _mm_xor_si128(lo, _mm_slli_si128(mid, 8));
    hi = _mm_xor_si128(hi, _mm_srli_si128(mid, 8));

    /* fast reduction, using https://crypto.stanford.edu/RealWorldCrypto/slides/gueron.pdf */
    __m128i r = _mm_clmulepi64_si128(lo, poly, 0x10);
    lo = _mm_shuffle_epi32(lo, 78);
    lo = _mm_xor_si128(lo, r);
    r = _mm_clmulepi64_si128(lo, poly, 0x10);
    lo = _mm_shuffle_epi32(lo, 78);
    lo = _mm_xor_si128(lo, r);
    lo = _mm_xor_si128(hi, lo);

    return lo;
}

struct ptls_fusion_gfmul_state128 {
    __m128i hi, lo, mid;
};

#if defined(__GNUC__) && !defined(__clang__)
static inline __m128i xor128(__m128i x, __m128i y)
{
    __m128i ret;
    __asm__("vpxor %2, %1, %0" : "=x"(ret) : "x"(x), "xm"(y));
    return ret;
}
#else
#define xor128 _mm_xor_si128
#endif

static inline void gfmul_do_step128(struct ptls_fusion_gfmul_state128 *gstate, __m128i X,
                                    struct ptls_fusion_aesgcm_ghash_precompute128 *precompute)
{
    __m128i t1 = _mm_clmulepi64_si128(precompute->H, X, 0x00);
    __m128i t2 = _mm_clmulepi64_si128(precompute->H, X, 0x11);
    __m128i t3 = _mm_shuffle_epi32(X, 78);
    t3 = _mm_xor_si128(t3, X);
    t3 = _mm_clmulepi64_si128(precompute->r, t3, 0x00);
    gstate->lo = xor128(gstate->lo, t1);
    gstate->hi = xor128(gstate->hi, t2);
    gstate->mid = xor128(gstate->mid, t3);
}

#undef xor128

static inline void gfmul_firststep128(struct ptls_fusion_gfmul_state128 *gstate, __m128i X,
                                      struct ptls_fusion_aesgcm_ghash_precompute128 *precompute)
{
    X = _mm_shuffle_epi8(X, byteswap128);
    X = _mm_xor_si128(gstate->lo, X);
    gstate->lo = _mm_setzero_si128();
    gstate->hi = _mm_setzero_si128();
    gstate->mid = _mm_setzero_si128();
    gfmul_do_step128(gstate, X, precompute);
}

static inline void gfmul_nextstep128(struct ptls_fusion_gfmul_state128 *gstate, __m128i X,
                                     struct ptls_fusion_aesgcm_ghash_precompute128 *precompute)
{
    X = _mm_shuffle_epi8(X, byteswap128);
    gfmul_do_step128(gstate, X, precompute);
}

static inline void gfmul_reduce128(struct ptls_fusion_gfmul_state128 *gstate)
{
    gstate->lo = gfmul_do_reduce(gstate->hi, gstate->lo, gstate->mid);
}

static inline __m128i gfmul_get_tag128(struct ptls_fusion_gfmul_state128 *gstate, __m128i ek0)
{
    __m128i tag = _mm_shuffle_epi8(gstate->lo, byteswap128);
    tag = _mm_xor_si128(tag, ek0);
    return tag;
}

struct ptls_fusion_gfmul_state256 {
    __m256i hi, lo, mid;
};

static inline void gfmul_do_step256(struct ptls_fusion_gfmul_state256 *gstate, __m256i X,
                                    union ptls_fusion_aesgcm_ghash_precompute256 *precompute)
{
    __m256i t = _mm256_clmulepi64_epi128(precompute->Hx2, X, 0x00);
    gstate->lo = _mm256_xor_si256(gstate->lo, t);
    t = _mm256_clmulepi64_epi128(precompute->Hx2, X, 0x11);
    gstate->hi = _mm256_xor_si256(gstate->hi, t);
    t = _mm256_shuffle_epi32(X, 78);
    t = _mm256_xor_si256(t, X);
    t = _mm256_clmulepi64_epi128(precompute->rx2, t, 0x00);
    gstate->mid = _mm256_xor_si256(gstate->mid, t);
}

static inline void gfmul_firststep256(struct ptls_fusion_gfmul_state256 *gstate, __m256i X, int half,
                                      union ptls_fusion_aesgcm_ghash_precompute256 *precompute)
{
    X = _mm256_shuffle_epi8(X, byteswap256);
    X = _mm256_xor_si256(gstate->lo, X);
    if (half)
        X = _mm256_permute2f128_si256(X, X, 0x08);
    gstate->lo = _mm256_setzero_si256();
    gstate->hi = _mm256_setzero_si256();
    gstate->mid = _mm256_setzero_si256();
    gfmul_do_step256(gstate, X, precompute);
}

static inline void gfmul_nextstep256(struct ptls_fusion_gfmul_state256 *gstate, __m256i X,
                                     union ptls_fusion_aesgcm_ghash_precompute256 *precompute)
{
    X = _mm256_shuffle_epi8(X, byteswap256);
    gfmul_do_step256(gstate, X, precompute);
}

static inline void gfmul_reduce256(struct ptls_fusion_gfmul_state256 *gstate)
{
#define XOR_256TO128(y) _mm_xor_si128(_mm256_castsi256_si128(y), _mm256_extractf128_si256((y), 1))
    __m128i hi = XOR_256TO128(gstate->hi);
    __m128i lo = XOR_256TO128(gstate->lo);
    __m128i mid = XOR_256TO128(gstate->mid);
#undef XOR_256TO128

    lo = gfmul_do_reduce(hi, lo, mid);
    gstate->lo = _mm256_castsi128_si256(lo);
}

static inline __m128i gfmul_get_tag256(struct ptls_fusion_gfmul_state256 *gstate, __m128i ek0)
{
    __m128i tag = _mm_shuffle_epi8(_mm256_castsi256_si128(gstate->lo), byteswap128);
    tag = _mm_xor_si128(tag, ek0);
    return tag;
}

static inline __m128i aesecb_encrypt(ptls_fusion_aesecb_context_t *ctx, __m128i v)
{
#define ROUNDKEY(i) (ctx->aesni256 ? _mm256_castsi256_si128(ctx->keys.m256[i]) : ctx->keys.m128[i])

    v = _mm_xor_si128(v, ROUNDKEY(0));
    for (size_t i = 1; i < ctx->rounds; ++i)
        v = _mm_aesenc_si128(v, ROUNDKEY(i));
    v = _mm_aesenclast_si128(v, ROUNDKEY(ctx->rounds));

    return v;

#undef ROUNDKEY
}

// 32-bytes of 0xff followed by 31-bytes of 0x00
static const uint8_t loadn_mask[63] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                       0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                       0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
static const uint8_t loadn_shuffle[31] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                          0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, // first 16 bytes map to byte offsets
                                          0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
                                          0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80}; // latter 15 bytes map to zero

NO_SANITIZE_ADDRESS
static inline __m128i loadn_end_of_page(const void *p, size_t l)
{
    uintptr_t shift = (uintptr_t)p & 15;
    __m128i pattern = _mm_loadu_si128((const __m128i *)(loadn_shuffle + shift));
    return _mm_shuffle_epi8(_mm_load_si128((const __m128i *)((uintptr_t)p - shift)), pattern);
}

NO_SANITIZE_ADDRESS
static inline __m128i loadn128(const void *p, size_t l)
{
    __m128i v, mask = _mm_loadu_si128((__m128i *)(loadn_mask + 32 - l));
    uintptr_t mod4k = (uintptr_t)p % 4096;

    if (PTLS_LIKELY(mod4k <= 4096 - 16) || mod4k + l > 4096) {
        v = _mm_loadu_si128(p);
    } else {
        v = loadn_end_of_page(p, l);
    }
    v = _mm_and_si128(v, mask);

    return v;
}

NO_SANITIZE_ADDRESS
static inline __m256i loadn256(const void *p, size_t l)
{
    __m256i v, mask = _mm256_loadu_si256((__m256i *)(loadn_mask + 32 - l));
    uintptr_t mod4k = (uintptr_t)p % 4096;

    if (PTLS_LIKELY(mod4k < 4096 - 32) || mod4k + l > 4096) {
        v = _mm256_loadu_si256(p);
    } else if (l > 16) {
        __m128i first16 = _mm_loadu_si128(p), second16 = loadn128((uint8_t *)p + 16, l - 16);
        v = _mm256_permute2f128_si256(_mm256_castsi128_si256(first16), _mm256_castsi128_si256(second16), 0x20);
    } else if (l == 16) {
        v = _mm256_castsi128_si256(_mm_loadu_si128(p));
    } else {
        v = _mm256_castsi128_si256(loadn_end_of_page(p, l));
    }
    v = _mm256_and_si256(v, mask);

    return v;
}

static inline void storen128(void *_p, size_t l, __m128i v)
{
    uint8_t buf[16], *p = _p;

    *(__m128i *)buf = v;

    for (size_t i = 0; i != l; ++i)
        p[i] = buf[i];
}

void ptls_fusion_aesgcm_encrypt(ptls_fusion_aesgcm_context_t *_ctx, void *output, const void *input, size_t inlen, __m128i ctr,
                                const void *_aad, size_t aadlen, ptls_aead_supplementary_encryption_t *supp)
{
/* init the bits (we can always run in full), but use the last slot for calculating ek0, if possible */
#define AESECB6_INIT()                                                                                                             \
    do {                                                                                                                           \
        ctr = _mm_add_epi64(ctr, one8);                                                                                            \
        bits0 = _mm_shuffle_epi8(ctr, byteswap128);                                                                                \
        ctr = _mm_add_epi64(ctr, one8);                                                                                            \
        bits1 = _mm_shuffle_epi8(ctr, byteswap128);                                                                                \
        ctr = _mm_add_epi64(ctr, one8);                                                                                            \
        bits2 = _mm_shuffle_epi8(ctr, byteswap128);                                                                                \
        ctr = _mm_add_epi64(ctr, one8);                                                                                            \
        bits3 = _mm_shuffle_epi8(ctr, byteswap128);                                                                                \
        ctr = _mm_add_epi64(ctr, one8);                                                                                            \
        bits4 = _mm_shuffle_epi8(ctr, byteswap128);                                                                                \
        if (PTLS_LIKELY(srclen > 16 * 5)) {                                                                                        \
            ctr = _mm_add_epi64(ctr, one8);                                                                                        \
            bits5 = _mm_shuffle_epi8(ctr, byteswap128);                                                                            \
        } else {                                                                                                                   \
            if ((state & STATE_EK0_BEEN_FED) == 0) {                                                                               \
                bits5 = ek0;                                                                                                       \
                state |= STATE_EK0_BEEN_FED;                                                                                       \
            }                                                                                                                      \
            if ((state & STATE_SUPP_USED) != 0 && srclen <= 16 * 4 && (const __m128i *)supp->input + 1 <= dst_ghash) {             \
                bits4 = _mm_loadu_si128(supp->input);                                                                              \
                bits4keys = ((struct ctr_context *)supp->ctx)->fusion.keys.m128;                                                   \
                state |= STATE_SUPP_IN_PROCESS;                                                                                    \
            }                                                                                                                      \
        }                                                                                                                          \
        __m128i k = ctx->super.ecb.keys.m128[0];                                                                                   \
        bits0 = _mm_xor_si128(bits0, k);                                                                                           \
        bits1 = _mm_xor_si128(bits1, k);                                                                                           \
        bits2 = _mm_xor_si128(bits2, k);                                                                                           \
        bits3 = _mm_xor_si128(bits3, k);                                                                                           \
        bits4 = _mm_xor_si128(bits4, bits4keys[0]);                                                                                \
        bits5 = _mm_xor_si128(bits5, k);                                                                                           \
    } while (0)

/* aes block update */
#define AESECB6_UPDATE(i)                                                                                                          \
    do {                                                                                                                           \
        __m128i k = ctx->super.ecb.keys.m128[i];                                                                                   \
        bits0 = _mm_aesenc_si128(bits0, k);                                                                                        \
        bits1 = _mm_aesenc_si128(bits1, k);                                                                                        \
        bits2 = _mm_aesenc_si128(bits2, k);                                                                                        \
        bits3 = _mm_aesenc_si128(bits3, k);                                                                                        \
        bits4 = _mm_aesenc_si128(bits4, bits4keys[i]);                                                                             \
        bits5 = _mm_aesenc_si128(bits5, k);                                                                                        \
    } while (0)

/* aesenclast */
#define AESECB6_FINAL(i)                                                                                                           \
    do {                                                                                                                           \
        __m128i k = ctx->super.ecb.keys.m128[i];                                                                                   \
        bits0 = _mm_aesenclast_si128(bits0, k);                                                                                    \
        bits1 = _mm_aesenclast_si128(bits1, k);                                                                                    \
        bits2 = _mm_aesenclast_si128(bits2, k);                                                                                    \
        bits3 = _mm_aesenclast_si128(bits3, k);                                                                                    \
        bits4 = _mm_aesenclast_si128(bits4, bits4keys[i]);                                                                         \
        bits5 = _mm_aesenclast_si128(bits5, k);                                                                                    \
    } while (0)

    struct ptls_fusion_aesgcm_context128 *ctx = (void *)_ctx;
    __m128i ek0, bits0, bits1, bits2, bits3, bits4, bits5 = _mm_setzero_si128();
    const __m128i *bits4keys = ctx->super.ecb.keys.m128; /* is changed to supp->ctx.keys when calcurating suppout */
    struct ptls_fusion_gfmul_state128 gstate = {0};
    __m128i gdatabuf[6];
    __m128i ac = _mm_shuffle_epi8(_mm_set_epi32(0, (int)aadlen * 8, 0, (int)inlen * 8), byteswap128);

    // src and dst are updated after the chunk is processed
    const __m128i *src = input;
    __m128i *dst = output;
    size_t srclen = inlen;
    // aad and src_ghash are updated before the chunk is processed (i.e., when the pointers are fed indo the processor)
    const __m128i *aad = _aad, *dst_ghash = dst;
    size_t dst_ghashlen = srclen;

    struct ptls_fusion_aesgcm_ghash_precompute128 *ghash_precompute = ctx->ghash + (aadlen + 15) / 16 + (srclen + 15) / 16 + 1;

#define STATE_EK0_BEEN_FED 0x3
#define STATE_EK0_INCOMPLETE 0x2
#define STATE_EK0_READY() ((state & STATE_EK0_BEEN_FED) == 0x1)
#define STATE_SUPP_USED 0x4
#define STATE_SUPP_IN_PROCESS 0x8
    int32_t state = supp != NULL ? STATE_SUPP_USED : 0;

    /* build counter */
    ctr = _mm_insert_epi32(ctr, 1, 0);
    ek0 = _mm_shuffle_epi8(ctr, byteswap128);

    /* start preparing AES */
    AESECB6_INIT();
    AESECB6_UPDATE(1);

    /* build first ghash data (only AAD can be fed at this point, as this would be calculated alongside the first AES block) */
    const __m128i *gdata = gdatabuf; // points to the elements fed into GHASH
    size_t gdata_cnt = 0;
    if (PTLS_LIKELY(aadlen != 0)) {
        while (gdata_cnt < 6) {
            if (PTLS_LIKELY(aadlen < 16)) {
                if (aadlen != 0) {
                    gdatabuf[gdata_cnt++] = loadn128(aad, aadlen);
                    aadlen = 0;
                }
                goto MainLoop;
            }
            gdatabuf[gdata_cnt++] = _mm_loadu_si128(aad++);
            aadlen -= 16;
        }
    }

    /* the main loop */
MainLoop:
    while (1) {
        /* run AES and multiplication in parallel */
        size_t i;
        for (i = 2; i < gdata_cnt + 2; ++i) {
            AESECB6_UPDATE(i);
            gfmul_nextstep128(&gstate, _mm_loadu_si128(gdata++), --ghash_precompute);
        }
        for (; i < ctx->super.ecb.rounds; ++i)
            AESECB6_UPDATE(i);
        AESECB6_FINAL(i);

        /* apply the bit stream to src and write to dest */
        if (PTLS_LIKELY(srclen >= 6 * 16)) {
#define APPLY(i) _mm_storeu_si128(dst + i, _mm_xor_si128(_mm_loadu_si128(src + i), bits##i))
            APPLY(0);
            APPLY(1);
            APPLY(2);
            APPLY(3);
            APPLY(4);
            APPLY(5);
#undef APPLY
            dst += 6;
            src += 6;
            srclen -= 6 * 16;
        } else {
            if ((state & STATE_EK0_BEEN_FED) == STATE_EK0_BEEN_FED) {
                ek0 = bits5;
                state &= ~STATE_EK0_INCOMPLETE;
            }
            if ((state & STATE_SUPP_IN_PROCESS) != 0) {
                _mm_storeu_si128((__m128i *)supp->output, bits4);
                state &= ~(STATE_SUPP_USED | STATE_SUPP_IN_PROCESS);
            }
            if (srclen != 0) {
#define APPLY(i)                                                                                                                   \
    do {                                                                                                                           \
        if (PTLS_LIKELY(srclen >= 16)) {                                                                                           \
            _mm_storeu_si128(dst++, _mm_xor_si128(_mm_loadu_si128(src++), bits##i));                                               \
            srclen -= 16;                                                                                                          \
        } else if (PTLS_LIKELY(srclen != 0)) {                                                                                     \
            bits0 = bits##i;                                                                                                       \
            goto ApplyRemainder;                                                                                                   \
        } else {                                                                                                                   \
            goto ApplyEnd;                                                                                                         \
        }                                                                                                                          \
    } while (0)
                APPLY(0);
                APPLY(1);
                APPLY(2);
                APPLY(3);
                APPLY(4);
                APPLY(5);
#undef APPLY
                goto ApplyEnd;
            ApplyRemainder:
                storen128(dst, srclen, _mm_xor_si128(loadn128(src, srclen), bits0));
                dst = (__m128i *)((uint8_t *)dst + srclen);
                srclen = 0;
            ApplyEnd:;
            }
        }

        /* next block AES starts here */
        AESECB6_INIT();

        AESECB6_UPDATE(1);

        /* setup gdata */
        if (PTLS_UNLIKELY(aadlen != 0)) {
            gdata_cnt = 0;
            while (gdata_cnt < 6) {
                if (aadlen < 16) {
                    if (aadlen != 0) {
                        gdatabuf[gdata_cnt++] = loadn128(aad, aadlen);
                        aadlen = 0;
                    }
                    goto GdataFillDST;
                }
                gdatabuf[gdata_cnt++] = _mm_loadu_si128(aad++);
                aadlen -= 16;
            }
            gdata = gdatabuf;
        } else if (PTLS_LIKELY(dst_ghashlen >= 6 * 16)) {
            gdata = dst_ghash;
            gdata_cnt = 6;
            dst_ghash += 6;
            dst_ghashlen -= 96;
        } else {
            gdata_cnt = 0;
        GdataFillDST:
            while (gdata_cnt < 6) {
                if (dst_ghashlen < 16) {
                    if (dst_ghashlen != 0) {
                        gdatabuf[gdata_cnt++] = loadn128(dst_ghash, dst_ghashlen);
                        dst_ghashlen = 0;
                    }
                    if (gdata_cnt < 6)
                        goto Finish;
                    break;
                }
                gdatabuf[gdata_cnt++] = _mm_loadu_si128(dst_ghash++);
                dst_ghashlen -= 16;
            }
            gdata = gdatabuf;
        }
    }

Finish:
    gdatabuf[gdata_cnt++] = ac;

    /* We have complete set of data to be fed into GHASH. Let's finish the remaining calculation.
     * Note that by now, all AES operations for payload encryption and ek0 are complete. This is is because it is necessary for GCM
     * to process at least the same amount of data (i.e. payload-blocks + AC), and because AES is at least one 96-byte block ahead.
     */
    assert(STATE_EK0_READY());
    for (size_t i = 0; i < gdata_cnt; ++i)
        gfmul_nextstep128(&gstate, gdatabuf[i], --ghash_precompute);

    gfmul_reduce128(&gstate);
    _mm_storeu_si128(dst, gfmul_get_tag128(&gstate, ek0));

    /* Finish the calculation of supplemental vector. Done at the very last, because the sample might cover the GCM tag. */
    if ((state & STATE_SUPP_USED) != 0) {
        size_t i;
        if ((state & STATE_SUPP_IN_PROCESS) == 0) {
            bits4keys = ((struct ctr_context *)supp->ctx)->fusion.keys.m128;
            bits4 = _mm_xor_si128(_mm_loadu_si128(supp->input), bits4keys[0]);
            i = 1;
        } else {
            i = 2;
        }
        do {
            bits4 = _mm_aesenc_si128(bits4, bits4keys[i++]);
        } while (i != ctx->super.ecb.rounds);
        bits4 = _mm_aesenclast_si128(bits4, bits4keys[i]);
        _mm_storeu_si128((__m128i *)supp->output, bits4);
    }

#undef AESECB6_INIT
#undef AESECB6_UPDATE
#undef AESECB6_FINAL
#undef STATE_EK0_BEEN_FOUND
#undef STATE_EK0_READY
#undef STATE_SUPP_IN_PROCESS
}

int ptls_fusion_aesgcm_decrypt(ptls_fusion_aesgcm_context_t *_ctx, void *output, const void *input, size_t inlen, __m128i ctr,
                               const void *_aad, size_t aadlen, const void *tag)
{
    struct ptls_fusion_aesgcm_context128 *ctx = (void *)_ctx;
    __m128i ek0 = _mm_setzero_si128(), bits0, bits1 = _mm_setzero_si128(), bits2 = _mm_setzero_si128(), bits3 = _mm_setzero_si128(),
            bits4 = _mm_setzero_si128(), bits5 = _mm_setzero_si128();
    struct ptls_fusion_gfmul_state128 gstate = {0};
    __m128i gdatabuf[6];
    __m128i ac = _mm_shuffle_epi8(_mm_set_epi32(0, (int)aadlen * 8, 0, (int)inlen * 8), byteswap128);
    struct ptls_fusion_aesgcm_ghash_precompute128 *ghash_precompute = ctx->ghash + (aadlen + 15) / 16 + (inlen + 15) / 16 + 1;

    const __m128i *gdata; // points to the elements fed into GHASH
    size_t gdata_cnt;

    const __m128i *src_ghash = input, *src_aes = input, *aad = _aad;
    __m128i *dst = output;
    size_t nondata_aes_cnt = 0, src_ghashlen = inlen, src_aeslen = inlen;

    /* schedule ek0 and suppkey */
    ctr = _mm_add_epi64(ctr, one8);
    bits0 = _mm_xor_si128(_mm_shuffle_epi8(ctr, byteswap128), ctx->super.ecb.keys.m128[0]);
    ++nondata_aes_cnt;

#define STATE_IS_FIRST_RUN 0x1
#define STATE_GHASH_HAS_MORE 0x2
    int state = STATE_IS_FIRST_RUN | STATE_GHASH_HAS_MORE;

    /* the main loop */
    while (1) {

        /* setup gdata */
        if (PTLS_UNLIKELY(aadlen != 0)) {
            gdata = gdatabuf;
            gdata_cnt = 0;
            while (gdata_cnt < 6) {
                if (aadlen < 16) {
                    if (aadlen != 0) {
                        gdatabuf[gdata_cnt++] = loadn128(aad, aadlen);
                        aadlen = 0;
                        ++nondata_aes_cnt;
                    }
                    goto GdataFillSrc;
                }
                gdatabuf[gdata_cnt++] = _mm_loadu_si128(aad++);
                aadlen -= 16;
                ++nondata_aes_cnt;
            }
        } else if (PTLS_LIKELY(src_ghashlen >= 6 * 16)) {
            gdata = src_ghash;
            gdata_cnt = 6;
            src_ghash += 6;
            src_ghashlen -= 6 * 16;
        } else {
            gdata = gdatabuf;
            gdata_cnt = 0;
        GdataFillSrc:
            while (gdata_cnt < 6) {
                if (src_ghashlen < 16) {
                    if (src_ghashlen != 0) {
                        gdatabuf[gdata_cnt++] = loadn128(src_ghash, src_ghashlen);
                        src_ghash = (__m128i *)((uint8_t *)src_ghash + src_ghashlen);
                        src_ghashlen = 0;
                    }
                    if (gdata_cnt < 6 && (state & STATE_GHASH_HAS_MORE) != 0) {
                        gdatabuf[gdata_cnt++] = ac;
                        state &= ~STATE_GHASH_HAS_MORE;
                    }
                    break;
                }
                gdatabuf[gdata_cnt++] = _mm_loadu_si128(src_ghash++);
                src_ghashlen -= 16;
            }
        }

        /* setup aes bits */
        if (PTLS_LIKELY(nondata_aes_cnt == 0))
            goto InitAllBits;
        switch (nondata_aes_cnt) {
#define INIT_BITS(n, keys)                                                                                                         \
    case n:                                                                                                                        \
        ctr = _mm_add_epi64(ctr, one8);                                                                                            \
        bits##n = _mm_xor_si128(_mm_shuffle_epi8(ctr, byteswap128), keys.m128[0]);
        InitAllBits:
            INIT_BITS(0, ctx->super.ecb.keys);
            INIT_BITS(1, ctx->super.ecb.keys);
            INIT_BITS(2, ctx->super.ecb.keys);
            INIT_BITS(3, ctx->super.ecb.keys);
            INIT_BITS(4, ctx->super.ecb.keys);
            INIT_BITS(5, ctx->super.ecb.keys);
#undef INIT_BITS
        }

        { /* run aes and ghash */
#define AESECB6_UPDATE(i)                                                                                                          \
    do {                                                                                                                           \
        __m128i k = ctx->super.ecb.keys.m128[i];                                                                                   \
        bits0 = _mm_aesenc_si128(bits0, k);                                                                                        \
        bits1 = _mm_aesenc_si128(bits1, k);                                                                                        \
        bits2 = _mm_aesenc_si128(bits2, k);                                                                                        \
        bits3 = _mm_aesenc_si128(bits3, k);                                                                                        \
        bits4 = _mm_aesenc_si128(bits4, k);                                                                                        \
        bits5 = _mm_aesenc_si128(bits5, k);                                                                                        \
    } while (0)

            size_t aesi;
            for (aesi = 1; aesi <= gdata_cnt; ++aesi) {
                AESECB6_UPDATE(aesi);
                gfmul_nextstep128(&gstate, _mm_loadu_si128(gdata++), --ghash_precompute);
            }
            for (; aesi < ctx->super.ecb.rounds; ++aesi)
                AESECB6_UPDATE(aesi);
            __m128i k = ctx->super.ecb.keys.m128[aesi];
            bits0 = _mm_aesenclast_si128(bits0, k);
            bits1 = _mm_aesenclast_si128(bits1, k);
            bits2 = _mm_aesenclast_si128(bits2, k);
            bits3 = _mm_aesenclast_si128(bits3, k);
            bits4 = _mm_aesenclast_si128(bits4, k);
            bits5 = _mm_aesenclast_si128(bits5, k);

#undef AESECB6_UPDATE
        }

        /* apply aes bits */
        if (PTLS_LIKELY(nondata_aes_cnt == 0 && src_aeslen >= 6 * 16)) {
#define APPLY(i) _mm_storeu_si128(dst + i, _mm_xor_si128(_mm_loadu_si128(src_aes + i), bits##i))
            APPLY(0);
            APPLY(1);
            APPLY(2);
            APPLY(3);
            APPLY(4);
            APPLY(5);
#undef APPLY
            dst += 6;
            src_aes += 6;
            src_aeslen -= 6 * 16;
        } else {
            if ((state & STATE_IS_FIRST_RUN) != 0) {
                ek0 = bits0;
                state &= ~STATE_IS_FIRST_RUN;
            }
            switch (nondata_aes_cnt) {
#define APPLY(i)                                                                                                                   \
    case i:                                                                                                                        \
        if (PTLS_LIKELY(src_aeslen > 16)) {                                                                                        \
            _mm_storeu_si128(dst++, _mm_xor_si128(_mm_loadu_si128(src_aes++), bits##i));                                           \
            src_aeslen -= 16;                                                                                                      \
        } else {                                                                                                                   \
            bits0 = bits##i;                                                                                                       \
            goto Finish;                                                                                                           \
        }
                APPLY(0);
                APPLY(1);
                APPLY(2);
                APPLY(3);
                APPLY(4);
                APPLY(5);
#undef APPLY
            }
            nondata_aes_cnt = 0;
        }
    }

Finish:
    if (src_aeslen == 16) {
        _mm_storeu_si128(dst, _mm_xor_si128(_mm_loadu_si128(src_aes), bits0));
    } else if (src_aeslen != 0) {
        storen128(dst, src_aeslen, _mm_xor_si128(loadn128(src_aes, src_aeslen), bits0));
    }

    assert((state & STATE_IS_FIRST_RUN) == 0);

    /* the only case where AES operation is complete and GHASH is not is when the application of AC is remaining */
    if ((state & STATE_GHASH_HAS_MORE) != 0) {
        assert(ghash_precompute - 1 == ctx->ghash);
        gfmul_nextstep128(&gstate, ac, --ghash_precompute);
    }

    gfmul_reduce128(&gstate);
    __m128i calctag = gfmul_get_tag128(&gstate, ek0);

    return _mm_movemask_epi8(_mm_cmpeq_epi8(calctag, _mm_loadu_si128(tag))) == 0xffff;

#undef STATE_IS_FIRST_RUN
#undef STATE_GHASH_HAS_MORE
}

static __m128i expand_key(__m128i key, __m128i temp)
{
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));

    key = _mm_xor_si128(key, temp);

    return key;
}

void ptls_fusion_aesecb_init(ptls_fusion_aesecb_context_t *ctx, int is_enc, const void *key, size_t key_size, int aesni256)
{
    assert(is_enc && "decryption is not supported (yet)");

    size_t i = 0;

    switch (key_size) {
    case 16: /* AES128 */
        ctx->rounds = 10;
        break;
    case 32: /* AES256 */
        ctx->rounds = 14;
        break;
    default:
        assert(!"invalid key size; AES128 / AES256 are supported");
        break;
    }
    ctx->aesni256 = aesni256;

    /* load and expand keys using keys.m128 */
    ctx->keys.m128[i++] = _mm_loadu_si128((__m128i *)key);
    if (key_size == 32)
        ctx->keys.m128[i++] = _mm_loadu_si128((__m128i *)key + 1);
    while (1) {
#define EXPAND(R)                                                                                                                  \
    {                                                                                                                              \
        ctx->keys.m128[i] =                                                                                                        \
            expand_key(ctx->keys.m128[i - key_size / 16],                                                                          \
                       _mm_shuffle_epi32(_mm_aeskeygenassist_si128(ctx->keys.m128[i - 1], R), _MM_SHUFFLE(3, 3, 3, 3)));           \
        if (i == ctx->rounds)                                                                                                      \
            break;                                                                                                                 \
        ++i;                                                                                                                       \
        if (key_size > 24) {                                                                                                       \
            ctx->keys.m128[i] =                                                                                                    \
                expand_key(ctx->keys.m128[i - key_size / 16],                                                                      \
                           _mm_shuffle_epi32(_mm_aeskeygenassist_si128(ctx->keys.m128[i - 1], R), _MM_SHUFFLE(2, 2, 2, 2)));       \
            ++i;                                                                                                                   \
        }                                                                                                                          \
    }
        EXPAND(0x1);
        EXPAND(0x2);
        EXPAND(0x4);
        EXPAND(0x8);
        EXPAND(0x10);
        EXPAND(0x20);
        EXPAND(0x40);
        EXPAND(0x80);
        EXPAND(0x1b);
        EXPAND(0x36);
#undef EXPAND
    }

    /* convert to keys.m256 if aesni256 is used */
    if (ctx->aesni256) {
        size_t i = ctx->rounds;
        do {
            ctx->keys.m256[i] = _mm256_broadcastsi128_si256(ctx->keys.m128[i]);
        } while (i-- != 0);
    }
}

void ptls_fusion_aesecb_dispose(ptls_fusion_aesecb_context_t *ctx)
{
    ptls_clear_memory(ctx, sizeof(*ctx));
}

void ptls_fusion_aesecb_encrypt(ptls_fusion_aesecb_context_t *ctx, void *dst, const void *src)
{
    __m128i v = _mm_loadu_si128(src);
    v = aesecb_encrypt(ctx, v);
    _mm_storeu_si128(dst, v);
}

/**
 * returns the number of ghash entries that is required to handle an AEAD block of given size
 */
static size_t aesgcm_calc_ghash_cnt(size_t capacity)
{
    // round-up by block size, add to handle worst split of the size between AAD and payload, plus context to hash AC
    return (capacity + 15) / 16 + 2;
}

static void setup_one_ghash_entry(ptls_fusion_aesgcm_context_t *ctx)
{
    __m128i *H, *r, *Hprev, H0;

    if (ctx->ecb.aesni256) {
        struct ptls_fusion_aesgcm_context256 *ctx256 = (void *)ctx;
#define GET_SLOT(i, mem) (&ctx256->ghash[(i) / 2].mem[(i) % 2 == 0])
        H = GET_SLOT(ctx->ghash_cnt, H);
        r = GET_SLOT(ctx->ghash_cnt, r);
        Hprev = ctx->ghash_cnt == 0 ? NULL : GET_SLOT(ctx->ghash_cnt - 1, H);
#undef GET_SLOT
        H0 = ctx256->ghash[0].H[1];
    } else {
        struct ptls_fusion_aesgcm_context128 *ctx128 = (void *)ctx;
        H = &ctx128->ghash[ctx->ghash_cnt].H;
        r = &ctx128->ghash[ctx->ghash_cnt].r;
        Hprev = ctx->ghash_cnt == 0 ? NULL : &ctx128->ghash[ctx->ghash_cnt - 1].H;
        H0 = ctx128->ghash[0].H;
    }

    if (Hprev != NULL)
        *H = gfmul(*Hprev, H0);

    *r = _mm_shuffle_epi32(*H, 78);
    *r = _mm_xor_si128(*r, *H);

    ++ctx->ghash_cnt;
}

static size_t calc_aesgcm_context_size(size_t *ghash_cnt, int aesni256)
{
    size_t sz;

    if (aesni256) {
        if (*ghash_cnt % 2 != 0)
            ++*ghash_cnt;
        sz = offsetof(struct ptls_fusion_aesgcm_context256, ghash) +
             sizeof(union ptls_fusion_aesgcm_ghash_precompute256) * *ghash_cnt / 2;
    } else {
        sz = offsetof(struct ptls_fusion_aesgcm_context128, ghash) +
             sizeof(struct ptls_fusion_aesgcm_ghash_precompute128) * *ghash_cnt;
    }
    return sz;
}

static ptls_fusion_aesgcm_context_t *new_aesgcm(const void *key, size_t key_size, size_t capacity, int aesni256)
{
    ptls_fusion_aesgcm_context_t *ctx;
    size_t ghash_cnt = aesgcm_calc_ghash_cnt(capacity), ctx_size = calc_aesgcm_context_size(&ghash_cnt, aesni256);

    if ((ctx = aligned_alloc(32, ctx_size)) == NULL)
        return NULL;

    ptls_fusion_aesecb_init(&ctx->ecb, 1, key, key_size, aesni256);

    ctx->capacity = capacity;

    __m128i H0 = aesecb_encrypt(&ctx->ecb, _mm_setzero_si128());
    H0 = _mm_shuffle_epi8(H0, byteswap128);
    H0 = transformH(H0);
    if (ctx->ecb.aesni256) {
        ((struct ptls_fusion_aesgcm_context256 *)ctx)->ghash[0].H[1] = H0;
    } else {
        ((struct ptls_fusion_aesgcm_context128 *)ctx)->ghash[0].H = H0;
    }

    ctx->ghash_cnt = 0;
    while (ctx->ghash_cnt < ghash_cnt)
        setup_one_ghash_entry(ctx);

    return ctx;
}

ptls_fusion_aesgcm_context_t *ptls_fusion_aesgcm_new(const void *key, size_t key_size, size_t capacity)
{
    return new_aesgcm(key, key_size, capacity, 0);
}

ptls_fusion_aesgcm_context_t *ptls_fusion_aesgcm_set_capacity(ptls_fusion_aesgcm_context_t *ctx, size_t capacity)
{
    size_t ghash_cnt = aesgcm_calc_ghash_cnt(capacity);

    if (ghash_cnt <= ctx->ghash_cnt)
        return ctx;

    size_t ctx_size = calc_aesgcm_context_size(&ghash_cnt, ctx->ecb.aesni256);
    ptls_fusion_aesgcm_context_t *newp;
    if ((newp = aligned_alloc(32, ctx_size)) == NULL)
        return NULL;
    memcpy(newp, ctx, ctx_size);
    free(ctx);
    ctx = newp;

    ctx->capacity = capacity;
    while (ghash_cnt < ctx->ghash_cnt)
        setup_one_ghash_entry(ctx);

    return ctx;
}

void ptls_fusion_aesgcm_free(ptls_fusion_aesgcm_context_t *ctx)
{
    ptls_clear_memory(ctx, calc_aesgcm_context_size(&ctx->ghash_cnt, ctx->ecb.aesni256));
    /* skip ptls_fusion_aesecb_dispose, based on the knowledge that it does not allocate memory elsewhere */

    free(ctx);
}

static void ctr_dispose(ptls_cipher_context_t *_ctx)
{
    struct ctr_context *ctx = (struct ctr_context *)_ctx;
    ptls_fusion_aesecb_dispose(&ctx->fusion);
    _mm_storeu_si128(&ctx->bits, _mm_setzero_si128());
}

static void ctr_init(ptls_cipher_context_t *_ctx, const void *iv)
{
    struct ctr_context *ctx = (struct ctr_context *)_ctx;
    _mm_storeu_si128(&ctx->bits, aesecb_encrypt(&ctx->fusion, _mm_loadu_si128(iv)));
    ctx->is_ready = 1;
}

static void ctr_transform(ptls_cipher_context_t *_ctx, void *output, const void *input, size_t len)
{
    struct ctr_context *ctx = (struct ctr_context *)_ctx;

    assert((ctx->is_ready && len <= 16) ||
           !"CTR transfomation is supported only once per call to `init` and the maximum size is limited  to 16 bytes");
    ctx->is_ready = 0;

    if (len < 16) {
        storen128(output, len, _mm_xor_si128(_mm_loadu_si128(&ctx->bits), loadn128(input, len)));
    } else {
        _mm_storeu_si128(output, _mm_xor_si128(_mm_loadu_si128(&ctx->bits), _mm_loadu_si128(input)));
    }
}

static int aesctr_setup(ptls_cipher_context_t *_ctx, int is_enc, const void *key, size_t key_size)
{
    struct ctr_context *ctx = (struct ctr_context *)_ctx;

    ctx->super.do_dispose = ctr_dispose;
    ctx->super.do_init = ctr_init;
    ctx->super.do_transform = ctr_transform;
    ptls_fusion_aesecb_init(&ctx->fusion, 1, key, key_size, 0 /* probably we do not need aesni256 for CTR? */);
    ctx->is_ready = 0;

    return 0;
}

static int aes128ctr_setup(ptls_cipher_context_t *ctx, int is_enc, const void *key)
{
    return aesctr_setup(ctx, is_enc, key, PTLS_AES128_KEY_SIZE);
}

static int aes256ctr_setup(ptls_cipher_context_t *ctx, int is_enc, const void *key)
{
    return aesctr_setup(ctx, is_enc, key, PTLS_AES256_KEY_SIZE);
}

static void aesgcm_dispose_crypto(ptls_aead_context_t *_ctx)
{
    struct aesgcm_context *ctx = (struct aesgcm_context *)_ctx;

    ptls_fusion_aesgcm_free(ctx->aesgcm);
}

static void aead_do_encrypt_init(ptls_aead_context_t *_ctx, uint64_t seq, const void *aad, size_t aadlen)
{
    assert(!"FIXME");
}

static size_t aead_do_encrypt_update(ptls_aead_context_t *_ctx, void *output, const void *input, size_t inlen)
{
    assert(!"FIXME");
    return SIZE_MAX;
}

static size_t aead_do_encrypt_final(ptls_aead_context_t *_ctx, void *_output)
{
    assert(!"FIXME");
    return SIZE_MAX;
}

static inline __m128i calc_counter(struct aesgcm_context *ctx, uint64_t seq)
{
    __m128i ctr = _mm_setzero_si128();
    ctr = _mm_insert_epi64(ctr, seq, 0);
    ctr = _mm_slli_si128(ctr, 4);
    ctr = _mm_xor_si128(ctx->static_iv, ctr);
    return ctr;
}

void aead_do_encrypt(struct st_ptls_aead_context_t *_ctx, void *output, const void *input, size_t inlen, uint64_t seq,
                     const void *aad, size_t aadlen, ptls_aead_supplementary_encryption_t *supp)
{
    struct aesgcm_context *ctx = (void *)_ctx;

    if (inlen + aadlen > ctx->aesgcm->capacity)
        ctx->aesgcm = ptls_fusion_aesgcm_set_capacity(ctx->aesgcm, inlen + aadlen);
    ptls_fusion_aesgcm_encrypt(ctx->aesgcm, output, input, inlen, calc_counter(ctx, seq), aad, aadlen, supp);
}

static void aead_do_encrypt_v(struct st_ptls_aead_context_t *ctx, void *output, ptls_iovec_t *input, size_t incnt, uint64_t seq,
                              const void *aad, size_t aadlen)
{
    assert(!"FIXME");
}

static size_t aead_do_decrypt(ptls_aead_context_t *_ctx, void *output, const void *input, size_t inlen, uint64_t seq,
                              const void *aad, size_t aadlen)
{
    struct aesgcm_context *ctx = (void *)_ctx;

    if (inlen < 16)
        return SIZE_MAX;

    size_t enclen = inlen - 16;
    if (enclen + aadlen > ctx->aesgcm->capacity)
        ctx->aesgcm = ptls_fusion_aesgcm_set_capacity(ctx->aesgcm, enclen + aadlen);
    if (!ptls_fusion_aesgcm_decrypt(ctx->aesgcm, output, input, enclen, calc_counter(ctx, seq), aad, aadlen,
                                    (const uint8_t *)input + enclen))
        return SIZE_MAX;
    return enclen;
}

static inline void aesgcm_xor_iv(ptls_aead_context_t *_ctx, const void *_bytes, size_t len)
{
    struct aesgcm_context *ctx = (struct aesgcm_context *)_ctx;
    __m128i xor_mask = loadn128(_bytes, len);
    xor_mask = _mm_shuffle_epi8(xor_mask, byteswap128);
    ctx->static_iv = _mm_xor_si128(ctx->static_iv, xor_mask);
}

static int aesgcm_setup(ptls_aead_context_t *_ctx, int is_enc, const void *key, const void *iv, size_t key_size)
{
    struct aesgcm_context *ctx = (struct aesgcm_context *)_ctx;

    ctx->static_iv = loadn128(iv, PTLS_AESGCM_IV_SIZE);
    ctx->static_iv = _mm_shuffle_epi8(ctx->static_iv, byteswap128);
    if (key == NULL)
        return 0;

    ctx->super.dispose_crypto = aesgcm_dispose_crypto;
    ctx->super.do_xor_iv = aesgcm_xor_iv;
    ctx->super.do_encrypt_init = aead_do_encrypt_init;
    ctx->super.do_encrypt_update = aead_do_encrypt_update;
    ctx->super.do_encrypt_final = aead_do_encrypt_final;
    ctx->super.do_encrypt = aead_do_encrypt;
    ctx->super.do_encrypt_v = aead_do_encrypt_v;
    ctx->super.do_decrypt = aead_do_decrypt;

    ctx->aesgcm = new_aesgcm(key, key_size, 1500 /* assume ordinary packet size */, 0 /* no support for aesni256 yet */);

    return 0;
}

static int aes128gcm_setup(ptls_aead_context_t *ctx, int is_enc, const void *key, const void *iv)
{
    return aesgcm_setup(ctx, is_enc, key, iv, PTLS_AES128_KEY_SIZE);
}

static int aes256gcm_setup(ptls_aead_context_t *ctx, int is_enc, const void *key, const void *iv)
{
    return aesgcm_setup(ctx, is_enc, key, iv, PTLS_AES256_KEY_SIZE);
}

int ptls_fusion_can_aesni256 = 0;
ptls_cipher_algorithm_t ptls_fusion_aes128ctr = {"AES128-CTR",
                                                 PTLS_AES128_KEY_SIZE,
                                                 1, // block size
                                                 PTLS_AES_IV_SIZE,
                                                 sizeof(struct ctr_context),
                                                 aes128ctr_setup};
ptls_cipher_algorithm_t ptls_fusion_aes256ctr = {"AES256-CTR",
                                                 PTLS_AES256_KEY_SIZE,
                                                 1, // block size
                                                 PTLS_AES_IV_SIZE,
                                                 sizeof(struct ctr_context),
                                                 aes256ctr_setup};
ptls_aead_algorithm_t ptls_fusion_aes128gcm = {"AES128-GCM",
                                               PTLS_AESGCM_CONFIDENTIALITY_LIMIT,
                                               PTLS_AESGCM_INTEGRITY_LIMIT,
                                               &ptls_fusion_aes128ctr,
                                               NULL, // &ptls_fusion_aes128ecb,
                                               PTLS_AES128_KEY_SIZE,
                                               PTLS_AESGCM_IV_SIZE,
                                               PTLS_AESGCM_TAG_SIZE,
                                               0,
                                               0,
                                               sizeof(struct aesgcm_context),
                                               aes128gcm_setup};
ptls_aead_algorithm_t ptls_fusion_aes256gcm = {"AES256-GCM",
                                               PTLS_AESGCM_CONFIDENTIALITY_LIMIT,
                                               PTLS_AESGCM_INTEGRITY_LIMIT,
                                               &ptls_fusion_aes256ctr,
                                               NULL, // &ptls_fusion_aes256ecb,
                                               PTLS_AES256_KEY_SIZE,
                                               PTLS_AESGCM_IV_SIZE,
                                               PTLS_AESGCM_TAG_SIZE,
                                               0,
                                               0,
                                               sizeof(struct aesgcm_context),
                                               aes256gcm_setup};

static inline size_t calc_total_length(ptls_iovec_t *input, size_t incnt)
{
    size_t totlen = 0;
    for (size_t i = 0; i < incnt; ++i)
        totlen += input[i].len;
    return totlen;
}

static inline void reduce_aad128(struct ptls_fusion_gfmul_state128 *gstate, struct ptls_fusion_aesgcm_ghash_precompute128 *ghash,
                                 const void *_aad, size_t aadlen)
{
    struct ptls_fusion_aesgcm_ghash_precompute128 *ghash_precompute;
    const uint8_t *aad = _aad;

    while (PTLS_UNLIKELY(aadlen >= 6 * 16)) {
        ghash_precompute = ghash + 6;
        gfmul_firststep128(gstate, _mm_loadu_si128((void *)aad), --ghash_precompute);
        aad += 16;
        aadlen -= 16;
        for (int i = 1; i < 6; ++i) {
            gfmul_nextstep128(gstate, _mm_loadu_si128((void *)aad), --ghash_precompute);
            aad += 16;
            aadlen -= 16;
        }
        gfmul_reduce128(gstate);
    }

    if (PTLS_LIKELY(aadlen != 0)) {
        ghash_precompute = ghash + (aadlen + 15) / 16;
        if (PTLS_UNLIKELY(aadlen >= 16)) {
            gfmul_firststep128(gstate, _mm_loadu_si128((void *)aad), --ghash_precompute);
            aad += 16;
            aadlen -= 16;
            while (aadlen >= 16) {
                gfmul_nextstep128(gstate, _mm_loadu_si128((void *)aad), --ghash_precompute);
                aad += 16;
                aadlen -= 16;
            }
            if (PTLS_LIKELY(aadlen != 0))
                gfmul_nextstep128(gstate, loadn128(aad, aadlen), --ghash_precompute);
        } else {
            gfmul_firststep128(gstate, loadn128(aad, aadlen), --ghash_precompute);
        }
        assert(ghash == ghash_precompute);
        gfmul_reduce128(gstate);
    }
}

NO_SANITIZE_ADDRESS
static inline uint8_t *load_preceding_unaligned(uint8_t *encbuf, uint8_t **output)
{
    uint8_t *encp;

    if ((encp = encbuf + ((uintptr_t)*output & 63)) != encbuf) {
        _mm256_store_si256((void *)encbuf, _mm256_load_si256((void *)(*output - (encp - encbuf))));
        _mm256_store_si256((void *)(encbuf + 32), _mm256_load_si256((void *)(*output - (encp - encbuf) + 32)));
        *output -= encp - encbuf;
    }

    return encp;
}

NO_SANITIZE_ADDRESS
static inline void write_remaining_bytes(uint8_t *dst, const uint8_t *src, const uint8_t *end)
{
    /* Write in 64-byte chunks, using NT store instructions. Last partial block, if any, is written to cache, as that cache line
     * would likely be read when the next TLS record is being built. */

    for (; end - src >= 64; dst += 64, src += 64) {
        _mm256_stream_si256((void *)dst, _mm256_load_si256((void *)src));
        _mm256_stream_si256((void *)(dst + 32), _mm256_load_si256((void *)(src + 32)));
    }
    _mm_sfence(); /* weakly ordered writes have to be synced before being passed to NIC */
    if (src != end) {
        for (; end - src >= 16; dst += 16, src += 16)
            _mm_store_si128((void *)dst, _mm_load_si128((void *)src));
        if (src != end)
            storen128((void *)dst, end - src, loadn128((void *)src, end - src));
    }
}

NO_SANITIZE_ADDRESS
static void non_temporal_encrypt_v128(struct st_ptls_aead_context_t *_ctx, void *_output, ptls_iovec_t *input, size_t incnt,
                                      uint64_t seq, const void *aad, size_t aadlen)
{
/* init the bits (we can always run in full), but use the last slot for calculating ek0, if possible */
#define AESECB6_INIT()                                                                                                             \
    do {                                                                                                                           \
        ctr = _mm_add_epi64(ctr, one8);                                                                                            \
        bits0 = _mm_shuffle_epi8(ctr, byteswap128);                                                                                \
        ctr = _mm_add_epi64(ctr, one8);                                                                                            \
        bits1 = _mm_shuffle_epi8(ctr, byteswap128);                                                                                \
        ctr = _mm_add_epi64(ctr, one8);                                                                                            \
        bits2 = _mm_shuffle_epi8(ctr, byteswap128);                                                                                \
        ctr = _mm_add_epi64(ctr, one8);                                                                                            \
        bits3 = _mm_shuffle_epi8(ctr, byteswap128);                                                                                \
        ctr = _mm_add_epi64(ctr, one8);                                                                                            \
        bits4 = _mm_shuffle_epi8(ctr, byteswap128);                                                                                \
        if (PTLS_LIKELY(srclen > 16 * 5) || src_vecleft != 0) {                                                                    \
            ctr = _mm_add_epi64(ctr, one8);                                                                                        \
            bits5 = _mm_shuffle_epi8(ctr, byteswap128);                                                                            \
        } else {                                                                                                                   \
            bits5 = ek0;                                                                                                           \
            state |= STATE_EK0_READY;                                                                                              \
        }                                                                                                                          \
        __m128i k = ctx->super.ecb.keys.m128[0];                                                                                   \
        bits0 = _mm_xor_si128(bits0, k);                                                                                           \
        bits1 = _mm_xor_si128(bits1, k);                                                                                           \
        bits2 = _mm_xor_si128(bits2, k);                                                                                           \
        bits3 = _mm_xor_si128(bits3, k);                                                                                           \
        bits4 = _mm_xor_si128(bits4, k);                                                                                           \
        bits5 = _mm_xor_si128(bits5, k);                                                                                           \
    } while (0)

/* aes block update */
#define AESECB6_UPDATE(i)                                                                                                          \
    do {                                                                                                                           \
        __m128i k = ctx->super.ecb.keys.m128[i];                                                                                   \
        bits0 = _mm_aesenc_si128(bits0, k);                                                                                        \
        bits1 = _mm_aesenc_si128(bits1, k);                                                                                        \
        bits2 = _mm_aesenc_si128(bits2, k);                                                                                        \
        bits3 = _mm_aesenc_si128(bits3, k);                                                                                        \
        bits4 = _mm_aesenc_si128(bits4, k);                                                                                        \
        bits5 = _mm_aesenc_si128(bits5, k);                                                                                        \
    } while (0)

/* aesenclast */
#define AESECB6_FINAL(i)                                                                                                           \
    do {                                                                                                                           \
        __m128i k = ctx->super.ecb.keys.m128[i];                                                                                   \
        bits0 = _mm_aesenclast_si128(bits0, k);                                                                                    \
        bits1 = _mm_aesenclast_si128(bits1, k);                                                                                    \
        bits2 = _mm_aesenclast_si128(bits2, k);                                                                                    \
        bits3 = _mm_aesenclast_si128(bits3, k);                                                                                    \
        bits4 = _mm_aesenclast_si128(bits4, k);                                                                                    \
        bits5 = _mm_aesenclast_si128(bits5, k);                                                                                    \
    } while (0)

    struct aesgcm_context *agctx = (void *)_ctx;
    uint8_t *output = _output;

#define STATE_EK0_READY 0x1
#define STATE_COPY_128B 0x2
    int32_t state = 0;

    /* Bytes are written here first then written using NT store instructions, 64 bytes at a time. */
    uint8_t encbuf[32 * 6] __attribute__((aligned(32))), *encp;

    /* `encbuf` should be large enough to store up to 63-bytes of unaligned bytes, 6 16-byte AES blocks, plus AEAD tag that is
     * append to the ciphertext before writing the bytes to main memory using NT store instructions. */
    PTLS_BUILD_ASSERT(sizeof(encbuf) >= 64 + 6 * 16 + 16);

    /* load unaligned data within same cache line preceding `output`, adjusting pointers accordingly */
    encp = load_preceding_unaligned(encbuf, &output);

    /* First write would be 128 bytes (32+6*16), if encbuf contains no less than 32 bytes already. */
    if (encp - encbuf >= 32)
        state |= STATE_COPY_128B;

    /* setup ctr, retain Ek(0), len(A) | len(C) to be fed into GCM */
    __m128i ctr = calc_counter(agctx, seq);
    ctr = _mm_insert_epi32(ctr, 1, 0);
    __m128i ek0 = _mm_shuffle_epi8(ctr, byteswap128);
    __m128i ac = _mm_shuffle_epi8(_mm_set_epi32(0, (int)aadlen * 8, 0, (int)calc_total_length(input, incnt) * 8), byteswap128);

    struct ptls_fusion_aesgcm_context128 *ctx = (void *)agctx->aesgcm;
    __m128i bits0, bits1, bits2, bits3, bits4, bits5 = _mm_setzero_si128();
    struct ptls_fusion_gfmul_state128 gstate = {0};

    /* find the first non-empty vec */
    const uint8_t *src = NULL;
    size_t srclen = 0, src_vecleft = incnt;
    while (srclen == 0 && src_vecleft != 0) {
        src = (void *)input[0].base;
        srclen = input[0].len;
        ++input;
        --src_vecleft;
    }

    /* Prepare first 6 blocks of bit stream, at the same time calculating ghash of AAD. */
    AESECB6_INIT();
    AESECB6_UPDATE(1);
    AESECB6_UPDATE(2);
    reduce_aad128(&gstate, ctx->ghash, aad, aadlen);
    for (size_t i = 3; i < ctx->super.ecb.rounds; ++i)
        AESECB6_UPDATE(i);
    AESECB6_FINAL(ctx->super.ecb.rounds);

    /* Main loop. This loop:
     *  1. using current keystream (bits0..bits5), xors a up to 6 * 16 bytes and writes to encbuf,
     *  2. then if there is no more data to be encrypted, exit the loop, otherwise,
     *  3. calculate ghash of the blocks being written to encbuf,
     *  4. calculate next 6 * 16 bytes of keystream,
     *  5. writes encbuf in 64-byte blocks
     * When exitting the loop, `remaining_ghash_from` represents the offset within `encbuf` from where ghash remains to be
     * calculated. */
    size_t remaining_ghash_from = encp - encbuf;
    if (srclen != 0) {
        while (1) {
            /* apply the bit stream to input, writing to encbuf */
            if (PTLS_LIKELY(srclen >= 6 * 16)) {
#define APPLY(i) _mm_storeu_si128((void *)(encp + i * 16), _mm_xor_si128(_mm_loadu_si128((void *)(src + i * 16)), bits##i))
                APPLY(0);
                APPLY(1);
                APPLY(2);
                APPLY(3);
                APPLY(4);
                APPLY(5);
#undef APPLY
                encp += 6 * 16;
                src += 6 * 16;
                srclen -= 6 * 16;
                if (PTLS_UNLIKELY(srclen == 0)) {
                    if (src_vecleft == 0) {
                        remaining_ghash_from = (encp - encbuf) - 96;
                        break;
                    }
                    src = (void *)input[0].base;
                    srclen = input[0].len;
                    ++input;
                    --src_vecleft;
                }
            } else {
                /* slow path, load at most 6 * 16 bytes to encbuf then encrypt in-place */
                size_t bytes_copied = 0;
                do {
                    if (srclen >= 16 && bytes_copied < 5 * 16) {
                        _mm_storeu_si128((void *)(encp + bytes_copied), _mm_loadu_si128((void *)src));
                        bytes_copied += 16;
                        src += 16;
                        srclen -= 16;
                    } else {
                        encp[bytes_copied++] = *src++;
                        --srclen;
                    }
                    if (PTLS_UNLIKELY(srclen == 0)) {
                        do {
                            if (src_vecleft == 0)
                                break;
                            src = (void *)input[0].base;
                            srclen = input[0].len;
                            ++input;
                            --src_vecleft;
                        } while (srclen == 0);
                        if (srclen == 0)
                            break;
                    }
                } while (bytes_copied < 6 * 16);
#define APPLY(i) _mm_storeu_si128((void *)(encp + i * 16), _mm_xor_si128(_mm_loadu_si128((void *)(encp + i * 16)), bits##i))
                APPLY(0);
                APPLY(1);
                APPLY(2);
                APPLY(3);
                APPLY(4);
                APPLY(5);
#undef APPLY
                encp += bytes_copied;
                if (PTLS_UNLIKELY(srclen == 0)) {
                    /* Calculate amonut of data left to be ghashed, as well as zero-clearing the remainedr of partial block, as it
                     * will be fed into ghash. */
                    remaining_ghash_from = (encp - encbuf) - bytes_copied;
                    if ((bytes_copied & 15) != 0)
                        _mm_storeu_si128((void *)encp, _mm_setzero_si128());
                    break;
                }
            }

            /* Next 96-byte block starts here. Run AES and ghash in while writing output using non-temporal stores in 64-byte
             * blocks. */
            AESECB6_INIT();
            struct ptls_fusion_aesgcm_ghash_precompute128 *ghash_precompute = ctx->ghash + 6;
            gfmul_firststep128(&gstate, _mm_loadu_si128((void *)(encp - 6 * 16)), --ghash_precompute);
            AESECB6_UPDATE(1);
            gfmul_nextstep128(&gstate, _mm_loadu_si128((void *)(encp - 5 * 16)), --ghash_precompute);
            AESECB6_UPDATE(2);
            gfmul_nextstep128(&gstate, _mm_loadu_si128((void *)(encp - 4 * 16)), --ghash_precompute);
            AESECB6_UPDATE(3);
            _mm256_stream_si256((void *)output, _mm256_load_si256((void *)encbuf));
            _mm256_stream_si256((void *)(output + 32), _mm256_load_si256((void *)(encbuf + 32)));
            AESECB6_UPDATE(4);
            gfmul_nextstep128(&gstate, _mm_loadu_si128((void *)(encp - 3 * 16)), --ghash_precompute);
            AESECB6_UPDATE(5);
            gfmul_nextstep128(&gstate, _mm_loadu_si128((void *)(encp - 2 * 16)), --ghash_precompute);
            AESECB6_UPDATE(6);
            gfmul_nextstep128(&gstate, _mm_loadu_si128((void *)(encp - 1 * 16)), --ghash_precompute);
            AESECB6_UPDATE(7);
            if ((state & STATE_COPY_128B) != 0) {
                _mm256_stream_si256((void *)(output + 64), _mm256_load_si256((void *)(encbuf + 64)));
                _mm256_stream_si256((void *)(output + 96), _mm256_load_si256((void *)(encbuf + 96)));
                output += 128;
                encp -= 128;
                AESECB6_UPDATE(8);
                _mm256_store_si256((void *)encbuf, _mm256_load_si256((void *)(encbuf + 128)));
                _mm256_store_si256((void *)(encbuf + 32), _mm256_load_si256((void *)(encbuf + 160)));
            } else {
                output += 64;
                encp -= 64;
                _mm256_store_si256((void *)encbuf, _mm256_load_si256((void *)(encbuf + 64)));
                _mm256_store_si256((void *)(encbuf + 32), _mm256_load_si256((void *)(encbuf + 96)));
                AESECB6_UPDATE(8);
            }
            state ^= STATE_COPY_128B;
            AESECB6_UPDATE(9);
            if (PTLS_UNLIKELY(ctx->super.ecb.rounds != 10)) {
                for (size_t i = 10; PTLS_LIKELY(i < ctx->super.ecb.rounds); ++i)
                    AESECB6_UPDATE(i);
            }
            assert(ctx->ghash == ghash_precompute);
            gfmul_reduce128(&gstate);
            AESECB6_FINAL(ctx->super.ecb.rounds);
        }
    }

    /* Now, All the encrypted bits are built in encbuf. Calculate AEAD tag and append to encbuf. */

    { /* Run ghash against the remaining bytes, after appending `ac` (i.e., len(A) | len(C)). At this point, we might be ghashing 7
       * blocks at once. */
        size_t ac_off = remaining_ghash_from + ((encp - encbuf) - remaining_ghash_from + 15) / 16 * 16;
        _mm_storeu_si128((void *)(encbuf + ac_off), ac);
        size_t blocks = ((encp - encbuf) - remaining_ghash_from + 15) / 16 + 1; /* round up, +1 for AC */
        assert(blocks <= 7);
        struct ptls_fusion_aesgcm_ghash_precompute128 *ghash_precompute = ctx->ghash + blocks;
        gfmul_firststep128(&gstate, _mm_loadu_si128((void *)(encbuf + remaining_ghash_from)), --ghash_precompute);
        remaining_ghash_from += 16;
        while (ghash_precompute != ctx->ghash) {
            gfmul_nextstep128(&gstate, _mm_loadu_si128((void *)(encbuf + remaining_ghash_from)), --ghash_precompute);
            remaining_ghash_from += 16;
        }
        gfmul_reduce128(&gstate);
    }

    /* Calculate EK0, if in the unlikely case on not been done yet. When encoding in full size (16K), EK0 will be ready. */
    if (PTLS_UNLIKELY((state & STATE_EK0_READY) == 0)) {
        bits5 = _mm_xor_si128(ek0, ctx->super.ecb.keys.m128[0]);
        for (size_t i = 1; i < ctx->super.ecb.rounds; ++i)
            bits5 = _mm_aesenc_si128(bits5, ctx->super.ecb.keys.m128[i]);
        bits5 = _mm_aesenclast_si128(bits5, ctx->super.ecb.keys.m128[ctx->super.ecb.rounds]);
    }

    /* append tag to encbuf */
    _mm_storeu_si128((void *)encp, gfmul_get_tag128(&gstate, bits5));
    encp += 16;

    /* write remaining bytes */
    write_remaining_bytes(output, encbuf, encp);

#undef AESECB6_INIT
#undef AESECB6_UPDATE
#undef AESECB6_FINAL
#undef STATE_EK0_READY
#undef STATE_COPY_128B
}

static size_t non_temporal_decrypt128(ptls_aead_context_t *_ctx, void *_output, const void *_input, size_t inlen, uint64_t seq,
                                      const void *aad, size_t aadlen)
{
    /* Bail out if the input is too short, or remove tag from range. */
    if (inlen < 16)
        return SIZE_MAX;
    inlen -= 16;
    size_t textlen = inlen;

/* init the bits (we can always run in full), but use the last slot for calculating ek0, if possible */
#define AESECB6_INIT()                                                                                                             \
    do {                                                                                                                           \
        ctr = _mm_add_epi64(ctr, one8);                                                                                            \
        bits0 = _mm_shuffle_epi8(ctr, byteswap128);                                                                                \
        ctr = _mm_add_epi64(ctr, one8);                                                                                            \
        bits1 = _mm_shuffle_epi8(ctr, byteswap128);                                                                                \
        ctr = _mm_add_epi64(ctr, one8);                                                                                            \
        bits2 = _mm_shuffle_epi8(ctr, byteswap128);                                                                                \
        ctr = _mm_add_epi64(ctr, one8);                                                                                            \
        bits3 = _mm_shuffle_epi8(ctr, byteswap128);                                                                                \
        ctr = _mm_add_epi64(ctr, one8);                                                                                            \
        bits4 = _mm_shuffle_epi8(ctr, byteswap128);                                                                                \
        if (PTLS_LIKELY(inlen > 16 * 5)) {                                                                                         \
            ctr = _mm_add_epi64(ctr, one8);                                                                                        \
            bits5 = _mm_shuffle_epi8(ctr, byteswap128);                                                                            \
        } else {                                                                                                                   \
            bits5 = ek0;                                                                                                           \
            state |= STATE_EK0_READY;                                                                                              \
        }                                                                                                                          \
        __m128i k = ctx->super.ecb.keys.m128[0];                                                                                   \
        bits0 = _mm_xor_si128(bits0, k);                                                                                           \
        bits1 = _mm_xor_si128(bits1, k);                                                                                           \
        bits2 = _mm_xor_si128(bits2, k);                                                                                           \
        bits3 = _mm_xor_si128(bits3, k);                                                                                           \
        bits4 = _mm_xor_si128(bits4, k);                                                                                           \
        bits5 = _mm_xor_si128(bits5, k);                                                                                           \
    } while (0)

/* aes block update */
#define AESECB6_UPDATE(i)                                                                                                          \
    do {                                                                                                                           \
        __m128i k = ctx->super.ecb.keys.m128[i];                                                                                   \
        bits0 = _mm_aesenc_si128(bits0, k);                                                                                        \
        bits1 = _mm_aesenc_si128(bits1, k);                                                                                        \
        bits2 = _mm_aesenc_si128(bits2, k);                                                                                        \
        bits3 = _mm_aesenc_si128(bits3, k);                                                                                        \
        bits4 = _mm_aesenc_si128(bits4, k);                                                                                        \
        bits5 = _mm_aesenc_si128(bits5, k);                                                                                        \
    } while (0)

/* aesenclast */
#define AESECB6_FINAL(i)                                                                                                           \
    do {                                                                                                                           \
        __m128i k = ctx->super.ecb.keys.m128[i];                                                                                   \
        bits0 = _mm_aesenclast_si128(bits0, k);                                                                                    \
        bits1 = _mm_aesenclast_si128(bits1, k);                                                                                    \
        bits2 = _mm_aesenclast_si128(bits2, k);                                                                                    \
        bits3 = _mm_aesenclast_si128(bits3, k);                                                                                    \
        bits4 = _mm_aesenclast_si128(bits4, k);                                                                                    \
        bits5 = _mm_aesenclast_si128(bits5, k);                                                                                    \
    } while (0)

    struct aesgcm_context *agctx = (void *)_ctx;
    uint8_t *output = _output;
    const uint8_t *input = _input;

#define STATE_EK0_READY 0x1
    int32_t state = 0;

    /* setup ctr, retain Ek(0), len(A) | len(C) to be fed into GCM */
    __m128i ctr = calc_counter(agctx, seq);
    ctr = _mm_insert_epi32(ctr, 1, 0);
    __m128i ek0 = _mm_shuffle_epi8(ctr, byteswap128);
    __m128i ac = _mm_shuffle_epi8(_mm_set_epi32(0, (int)aadlen * 8, 0, (int)inlen * 8), byteswap128);

    struct ptls_fusion_aesgcm_context128 *ctx = (void *)agctx->aesgcm;
    __m128i bits0, bits1, bits2, bits3, bits4, bits5 = _mm_setzero_si128();
    struct ptls_fusion_gfmul_state128 gstate = {0};

    /* Prepare first 6 blocks of bit stream, at the same time calculating ghash of AAD. */
    AESECB6_INIT();
    AESECB6_UPDATE(1);
    AESECB6_UPDATE(2);
    reduce_aad128(&gstate, ctx->ghash, aad, aadlen);
    for (size_t i = 3; i < ctx->super.ecb.rounds; ++i)
        AESECB6_UPDATE(i);
    AESECB6_FINAL(ctx->super.ecb.rounds);

    /* Main loop. Operate in full blocks (6 * 16 bytes). */
    while (PTLS_LIKELY(inlen >= 6 * 16)) {
#define DECRYPT(i) _mm_storeu_si128((void *)(output + i * 16), _mm_xor_si128(bits##i, _mm_loadu_si128((void *)(input + i * 16))))
        DECRYPT(0);
        DECRYPT(1);
        DECRYPT(2);
        DECRYPT(3);
        DECRYPT(4);
        DECRYPT(5);
#undef DECRYPT
#define GFMUL_NEXT(i) gfmul_nextstep128(&gstate, _mm_loadu_si128((void *)(input + i * 16)), ctx->ghash + 5 - i)
        AESECB6_INIT();
        AESECB6_UPDATE(1);
        AESECB6_UPDATE(2);
        AESECB6_UPDATE(3);
        gfmul_firststep128(&gstate, _mm_loadu_si128((void *)input), ctx->ghash + 5);
        AESECB6_UPDATE(4);
        GFMUL_NEXT(1);
        AESECB6_UPDATE(5);
        GFMUL_NEXT(2);
        AESECB6_UPDATE(6);
        GFMUL_NEXT(3);
        AESECB6_UPDATE(7);
        GFMUL_NEXT(4);
        AESECB6_UPDATE(8);
        GFMUL_NEXT(5);
        AESECB6_UPDATE(9);
        gfmul_reduce128(&gstate);
        if (PTLS_UNLIKELY(ctx->super.ecb.rounds != 10)) {
            size_t i = 10;
            do {
                AESECB6_UPDATE(i);
            } while (++i < ctx->super.ecb.rounds);
        }
        AESECB6_FINAL(ctx->super.ecb.rounds);
        output += 6 * 16;
        input += 6 * 16;
        inlen -= 6 * 16;
#undef GFMUL_NEXT
    }

    /* Decrypt the remainder as well as finishing GHASH calculation. */
    if (inlen != 0) {
        struct ptls_fusion_aesgcm_ghash_precompute128 *ghash_precompute = ctx->ghash + (inlen + 15) / 16 + 1;
#define ONEBLOCK(i)                                                                                                                \
    do {                                                                                                                           \
        if (inlen != 0) {                                                                                                          \
            __m128i b = inlen >= 16 ? _mm_loadu_si128((void *)input) : loadn128(input, inlen);                                     \
            if (i == 0) {                                                                                                          \
                gfmul_firststep128(&gstate, b, --ghash_precompute);                                                                \
            } else {                                                                                                               \
                gfmul_nextstep128(&gstate, b, --ghash_precompute);                                                                 \
            }                                                                                                                      \
            b = _mm_xor_si128(b, bits##i);                                                                                         \
            if (inlen >= 16) {                                                                                                     \
                _mm_storeu_si128((void *)output, b);                                                                               \
                output += 16;                                                                                                      \
                input += 16;                                                                                                       \
                inlen -= 16;                                                                                                       \
            } else {                                                                                                               \
                storen128(output, inlen, b);                                                                                       \
                output += inlen;                                                                                                   \
                input += inlen;                                                                                                    \
                inlen = 0;                                                                                                         \
            }                                                                                                                      \
        }                                                                                                                          \
    } while (0)
        ONEBLOCK(0);
        ONEBLOCK(1);
        ONEBLOCK(2);
        ONEBLOCK(3);
        ONEBLOCK(4);
        ONEBLOCK(5);
#undef ONEBLOCK
        gfmul_nextstep128(&gstate, ac, --ghash_precompute);
        assert(ghash_precompute == ctx->ghash);
    } else {
        gfmul_firststep128(&gstate, ac, ctx->ghash);
    }
    gfmul_reduce128(&gstate);

    /* Calculate EK0 if not yet available in bits5. */
    if ((state & STATE_EK0_READY) == 0) {
        bits5 = _mm_xor_si128(ek0, ctx->super.ecb.keys.m128[0]);
        for (size_t i = 1; i < ctx->super.ecb.rounds; ++i)
            bits5 = _mm_aesenc_si128(bits5, ctx->super.ecb.keys.m128[i]);
        bits5 = _mm_aesenclast_si128(bits5, ctx->super.ecb.keys.m128[ctx->super.ecb.rounds]);
    }

    /* Calculate GCM tag and compare. */
    __m128i calctag = gfmul_get_tag128(&gstate, bits5);
    __m128i recvtag = _mm_loadu_si128((void *)input);
    if (_mm_movemask_epi8(_mm_cmpeq_epi8(calctag, recvtag)) != 0xffff)
        return SIZE_MAX;

    return textlen;

#undef AESECB6_INIT
#undef AESECB6_UPDATE
#undef AESECB6_FINAL
#undef STATE_EK0_READY
}

NO_SANITIZE_ADDRESS
static void non_temporal_encrypt_v256(struct st_ptls_aead_context_t *_ctx, void *_output, ptls_iovec_t *input, size_t incnt,
                                      uint64_t seq, const void *_aad, size_t aadlen)
{
/* init the bits (we can always run in full), but use the last slot for calculating ek0, if possible */
#define AESECB6_INIT()                                                                                                             \
    do {                                                                                                                           \
        ctr = _mm256_add_epi64(ctr, incr128x2);                                                                                    \
        bits0 = _mm256_shuffle_epi8(ctr, byteswap256);                                                                             \
        ctr = _mm256_add_epi64(ctr, incr128x2);                                                                                    \
        bits1 = _mm256_shuffle_epi8(ctr, byteswap256);                                                                             \
        ctr = _mm256_add_epi64(ctr, incr128x2);                                                                                    \
        bits2 = _mm256_shuffle_epi8(ctr, byteswap256);                                                                             \
        ctr = _mm256_add_epi64(ctr, incr128x2);                                                                                    \
        bits3 = _mm256_shuffle_epi8(ctr, byteswap256);                                                                             \
        ctr = _mm256_add_epi64(ctr, incr128x2);                                                                                    \
        bits4 = _mm256_shuffle_epi8(ctr, byteswap256);                                                                             \
        ctr = _mm256_add_epi64(ctr, incr128x2);                                                                                    \
        bits5 = _mm256_shuffle_epi8(ctr, byteswap256);                                                                             \
        if (PTLS_UNLIKELY(srclen <= 32 * 6 - 16) && src_vecleft == 0) {                                                            \
            bits5 = _mm256_permute2f128_si256(bits5, ac_ek0, 0x30);                                                                \
            state |= STATE_EK0_READY;                                                                                              \
        }                                                                                                                          \
        __m256i k = ctx->super.ecb.keys.m256[0];                                                                                   \
        bits0 = _mm256_xor_si256(bits0, k);                                                                                        \
        bits1 = _mm256_xor_si256(bits1, k);                                                                                        \
        bits2 = _mm256_xor_si256(bits2, k);                                                                                        \
        bits3 = _mm256_xor_si256(bits3, k);                                                                                        \
        bits4 = _mm256_xor_si256(bits4, k);                                                                                        \
        bits5 = _mm256_xor_si256(bits5, k);                                                                                        \
    } while (0)

/* aes block update */
#define AESECB6_UPDATE(i)                                                                                                          \
    do {                                                                                                                           \
        __m256i k = ctx->super.ecb.keys.m256[i];                                                                                   \
        bits0 = _mm256_aesenc_epi128(bits0, k);                                                                                    \
        bits1 = _mm256_aesenc_epi128(bits1, k);                                                                                    \
        bits2 = _mm256_aesenc_epi128(bits2, k);                                                                                    \
        bits3 = _mm256_aesenc_epi128(bits3, k);                                                                                    \
        bits4 = _mm256_aesenc_epi128(bits4, k);                                                                                    \
        bits5 = _mm256_aesenc_epi128(bits5, k);                                                                                    \
    } while (0)

/* aesenclast */
#define AESECB6_FINAL(i)                                                                                                           \
    do {                                                                                                                           \
        __m256i k = ctx->super.ecb.keys.m256[i];                                                                                   \
        bits0 = _mm256_aesenclast_epi128(bits0, k);                                                                                \
        bits1 = _mm256_aesenclast_epi128(bits1, k);                                                                                \
        bits2 = _mm256_aesenclast_epi128(bits2, k);                                                                                \
        bits3 = _mm256_aesenclast_epi128(bits3, k);                                                                                \
        bits4 = _mm256_aesenclast_epi128(bits4, k);                                                                                \
        bits5 = _mm256_aesenclast_epi128(bits5, k);                                                                                \
    } while (0)

    struct aesgcm_context *agctx = (void *)_ctx;
    uint8_t *output = _output;
    const uint8_t *aad = _aad;

#define STATE_EK0_READY 0x1
    int32_t state = 0;

    /* Bytes are written here first then written using NT store instructions, 64 bytes at a time. */
    uint8_t encbuf[32 * 9] __attribute__((aligned(32))), *encp;

    /* `encbuf` should be large enough to store up to 63-bytes of unaligned bytes, 6 16-byte AES blocks, plus AEAD tag that is
     * append to the ciphertext before writing the bytes to main memory using NT store instructions. */
    PTLS_BUILD_ASSERT(sizeof(encbuf) >= 64 + 6 * 32 + 16);

    /* load unaligned data within same cache line preceding `output`, adjusting pointers accordingly */
    encp = load_preceding_unaligned(encbuf, &output);

    /* setup ctr, retaining Ek(0), len(A) | len(C) to be fed into GCM */
    __m256i ctr = _mm256_broadcastsi128_si256(calc_counter(agctx, seq));
    ctr = _mm256_insert_epi32(ctr, 1, 4);
    __m256i ac_ek0 = _mm256_permute2f128_si256(
        /* first half: ac */
        _mm256_castsi128_si256(
            _mm_shuffle_epi8(_mm_set_epi32(0, (int)aadlen * 8, 0, (int)calc_total_length(input, incnt) * 8), byteswap128)),
        /* second half: ek0 */
        _mm256_shuffle_epi8(ctr, byteswap256), 0x30);

    struct ptls_fusion_aesgcm_context256 *ctx = (void *)agctx->aesgcm;
    __m256i bits0, bits1, bits2, bits3, bits4, bits5 = _mm256_setzero_si256();
    struct ptls_fusion_gfmul_state256 gstate = {0};

    /* find the first non-empty vec */
    const uint8_t *src = NULL;
    size_t srclen = 0, src_vecleft = incnt;
    while (srclen == 0 && src_vecleft != 0) {
        src = (void *)input[0].base;
        srclen = input[0].len;
        ++input;
        --src_vecleft;
    }

    /* Prepare first 6 blocks of bit stream, at the same time calculating ghash of AAD. */
    AESECB6_INIT();
    AESECB6_UPDATE(1);
    AESECB6_UPDATE(2);
    if (PTLS_LIKELY(aadlen != 0)) {
        union ptls_fusion_aesgcm_ghash_precompute256 *ghash_precompute;
        while (PTLS_UNLIKELY(aadlen >= 6 * 32)) {
            ghash_precompute = ctx->ghash + 6;
            gfmul_firststep256(&gstate, _mm256_loadu_si256((void *)aad), 0, --ghash_precompute);
            aad += 32;
            aadlen -= 32;
            for (int i = 1; i < 6; ++i) {
                gfmul_nextstep256(&gstate, _mm256_loadu_si256((void *)aad), --ghash_precompute);
                aad += 32;
                aadlen -= 32;
            }
            gfmul_reduce256(&gstate);
        }
        if (PTLS_LIKELY(aadlen != 0)) {
            ghash_precompute = ctx->ghash + (aadlen + 31) / 32;
            if (PTLS_UNLIKELY(aadlen >= 32)) {
                if (aadlen % 32 == 0 || aadlen % 32 > 16) {
                    gfmul_firststep256(&gstate, _mm256_loadu_si256((void *)aad), 0, --ghash_precompute);
                    aad += 32;
                    aadlen -= 32;
                } else {
                    gfmul_firststep256(&gstate, _mm256_loadu_si256((void *)aad), 1, --ghash_precompute);
                    aad += 16;
                    aadlen -= 16;
                }
                while (aadlen >= 32) {
                    gfmul_nextstep256(&gstate, _mm256_loadu_si256((void *)aad), --ghash_precompute);
                    aad += 32;
                    aadlen -= 32;
                }
                if (PTLS_LIKELY(aadlen != 0)) {
                    assert(aadlen > 16);
                    gfmul_nextstep256(&gstate, loadn256(aad, aadlen), --ghash_precompute);
                }
            } else {
                gfmul_firststep256(&gstate, loadn256(aad, aadlen), aadlen <= 16, --ghash_precompute);
            }
            assert(ctx->ghash == ghash_precompute);
            gfmul_reduce256(&gstate);
        }
    }
    for (size_t i = 3; i < ctx->super.ecb.rounds; ++i)
        AESECB6_UPDATE(i);
    AESECB6_FINAL(ctx->super.ecb.rounds);

    /* Main loop. This loop:
     *  1. using current keystream (bits0..bits5), xors a up to 6 * 16 bytes and writes to encbuf,
     *  2. then if there is no more data to be encrypted, exit the loop, otherwise,
     *  3. calculate ghash of the blocks being written to encbuf,
     *  4. calculate next 6 * 16 bytes of keystream,
     *  5. writes encbuf in 64-byte blocks
     * When exitting the loop, `remaining_ghash_from` represents the offset within `encbuf` from where ghash remains to be
     * calculated. */
    size_t remaining_ghash_from = encp - encbuf;
    if (srclen != 0) {
        while (1) {
            /* apply the bit stream to input, writing to encbuf */
            if (PTLS_LIKELY(srclen >= 6 * 32)) {
#define APPLY(i) _mm256_storeu_si256((void *)(encp + i * 32), _mm256_xor_si256(_mm256_loadu_si256((void *)(src + i * 32)), bits##i))
                APPLY(0);
                APPLY(1);
                APPLY(2);
                APPLY(3);
                APPLY(4);
                APPLY(5);
#undef APPLY
                encp += 6 * 32;
                src += 6 * 32;
                srclen -= 6 * 32;
                if (PTLS_UNLIKELY(srclen == 0)) {
                    if (src_vecleft == 0) {
                        remaining_ghash_from = (encp - encbuf) - 6 * 32;
                        break;
                    }
                    src = (void *)input[0].base;
                    srclen = input[0].len;
                    ++input;
                    --src_vecleft;
                }
            } else {
                /* slow path, load at most 6 * 32 bytes to encbuf then encrypt in-place */
                size_t bytes_copied = 0;
                do {
                    if (srclen >= 32 && bytes_copied < 5 * 32) {
                        _mm256_storeu_si256((void *)(encp + bytes_copied), _mm256_loadu_si256((void *)src));
                        bytes_copied += 32;
                        src += 32;
                        srclen -= 32;
                    } else {
                        encp[bytes_copied++] = *src++;
                        --srclen;
                    }
                    if (PTLS_UNLIKELY(srclen == 0)) {
                        do {
                            if (src_vecleft == 0)
                                break;
                            src = (void *)input[0].base;
                            srclen = input[0].len;
                            ++input;
                            --src_vecleft;
                        } while (srclen == 0);
                        if (srclen == 0)
                            break;
                    }
                } while (bytes_copied < 6 * 32);
#define APPLY(i)                                                                                                                   \
    _mm256_storeu_si256((void *)(encp + i * 32), _mm256_xor_si256(_mm256_loadu_si256((void *)(encp + i * 32)), bits##i))
                APPLY(0);
                APPLY(1);
                APPLY(2);
                APPLY(3);
                APPLY(4);
                APPLY(5);
#undef APPLY
                encp += bytes_copied;
                if (PTLS_UNLIKELY(srclen == 0)) {
                    /* Calculate amonut of data left to be ghashed, as well as zero-clearing the remainedr of partial block, as it
                     * will be fed into ghash. */
                    remaining_ghash_from = (encp - encbuf) - bytes_copied;
                    if ((bytes_copied & 15) != 0)
                        _mm_storeu_si128((void *)encp, _mm_setzero_si128());
                    break;
                }
            }

            /* Next 96-byte block starts here. Run AES and ghash in parallel while writing output using non-temporal store
             * instructions. */
            AESECB6_INIT();
            union ptls_fusion_aesgcm_ghash_precompute256 *ghash_precompute = ctx->ghash + 6;
            gfmul_firststep256(&gstate, _mm256_loadu_si256((void *)(encp - 6 * 32)), 0, --ghash_precompute);
            AESECB6_UPDATE(1);
            gfmul_nextstep256(&gstate, _mm256_loadu_si256((void *)(encp - 5 * 32)), --ghash_precompute);
            AESECB6_UPDATE(2);
            gfmul_nextstep256(&gstate, _mm256_loadu_si256((void *)(encp - 4 * 32)), --ghash_precompute);
            AESECB6_UPDATE(3);
            gfmul_nextstep256(&gstate, _mm256_loadu_si256((void *)(encp - 3 * 32)), --ghash_precompute);
            AESECB6_UPDATE(4);
            _mm256_stream_si256((void *)output, _mm256_load_si256((void *)encbuf));
            _mm256_stream_si256((void *)(output + 32), _mm256_load_si256((void *)(encbuf + 32)));
            _mm256_stream_si256((void *)(output + 64), _mm256_load_si256((void *)(encbuf + 64)));
            _mm256_stream_si256((void *)(output + 96), _mm256_load_si256((void *)(encbuf + 96)));
            _mm256_stream_si256((void *)(output + 128), _mm256_load_si256((void *)(encbuf + 128)));
            _mm256_stream_si256((void *)(output + 160), _mm256_load_si256((void *)(encbuf + 160)));
            AESECB6_UPDATE(5);
            gfmul_nextstep256(&gstate, _mm256_loadu_si256((void *)(encp - 2 * 32)), --ghash_precompute);
            AESECB6_UPDATE(6);
            gfmul_nextstep256(&gstate, _mm256_loadu_si256((void *)(encp - 1 * 32)), --ghash_precompute);
            output += 192;
            encp -= 192;
            AESECB6_UPDATE(7);
            _mm256_store_si256((void *)encbuf, _mm256_load_si256((void *)(encbuf + 192)));
            AESECB6_UPDATE(8);
            _mm256_store_si256((void *)(encbuf + 32), _mm256_load_si256((void *)(encbuf + 224)));
            AESECB6_UPDATE(9);
            if (PTLS_UNLIKELY(ctx->super.ecb.rounds != 10)) {
                for (size_t i = 10; PTLS_LIKELY(i < ctx->super.ecb.rounds); ++i)
                    AESECB6_UPDATE(i);
            }
            assert(ctx->ghash == ghash_precompute);
            gfmul_reduce256(&gstate);
            AESECB6_FINAL(ctx->super.ecb.rounds);
        }
    }

    /* Now, All the encrypted bits are built in encbuf. Calculate AEAD tag and append to encbuf. */

    { /* Run ghash against the remaining bytes, after appending `ac` (i.e., len(A) | len(C)). At this point, we might be ghashing 7
       * blocks at once. */
        size_t ac_off = remaining_ghash_from + ((encp - encbuf) - remaining_ghash_from + 15) / 16 * 16;
        _mm_storeu_si128((void *)(encbuf + ac_off), _mm256_castsi256_si128(ac_ek0));
        size_t blocks = ((encp - encbuf) - remaining_ghash_from + 15) / 16 + 1; /* round up, +1 for AC */
        assert(blocks <= 13);
        union ptls_fusion_aesgcm_ghash_precompute256 *ghash_precompute = ctx->ghash + blocks / 2;
        if (blocks % 2 != 0) {
            gfmul_firststep256(&gstate, _mm256_loadu_si256((void *)(encbuf + remaining_ghash_from)), 1, ghash_precompute);
            remaining_ghash_from += 16;
        } else {
            gfmul_firststep256(&gstate, _mm256_loadu_si256((void *)(encbuf + remaining_ghash_from)), 0, --ghash_precompute);
            remaining_ghash_from += 32;
        }
        while (ghash_precompute != ctx->ghash) {
            gfmul_nextstep256(&gstate, _mm256_loadu_si256((void *)(encbuf + remaining_ghash_from)), --ghash_precompute);
            remaining_ghash_from += 32;
        }
        gfmul_reduce256(&gstate);
    }

    /* Calculate EK0, if in the unlikely case on not been done yet. When encoding in full size (16K), EK0 will be ready. */
    if (PTLS_UNLIKELY((state & STATE_EK0_READY) == 0)) {
        bits5 = ac_ek0;
        bits5 = _mm256_xor_si256(bits5, ctx->super.ecb.keys.m256[0]);
        for (size_t i = 1; i < ctx->super.ecb.rounds; ++i)
            bits5 = _mm256_aesenc_epi128(bits5, ctx->super.ecb.keys.m256[i]);
        bits5 = _mm256_aesenclast_epi128(bits5, ctx->super.ecb.keys.m256[ctx->super.ecb.rounds]);
    }

    /* append tag to encbuf */
    _mm_storeu_si128((void *)encp,
                     gfmul_get_tag256(&gstate, _mm256_castsi256_si128(_mm256_permute2f128_si256(bits5, bits5, 0x11))));
    encp += 16;

    /* write remaining bytes */
    write_remaining_bytes(output, encbuf, encp);
}

static int non_temporal_setup(ptls_aead_context_t *_ctx, int is_enc, const void *key, const void *iv, size_t key_size)
{
    struct aesgcm_context *ctx = (struct aesgcm_context *)_ctx;
    int aesni256 = is_enc && ptls_fusion_can_aesni256;

    ctx->static_iv = loadn128(iv, PTLS_AESGCM_IV_SIZE);
    ctx->static_iv = _mm_shuffle_epi8(ctx->static_iv, byteswap128);
    if (key == NULL)
        return 0;

    ctx->super.dispose_crypto = aesgcm_dispose_crypto;
    ctx->super.do_xor_iv = aesgcm_xor_iv;
    ctx->super.do_encrypt_init = NULL;
    ctx->super.do_encrypt_update = NULL;
    ctx->super.do_encrypt_final = NULL;
    if (is_enc) {
        ctx->super.do_encrypt = ptls_aead__do_encrypt;
        ctx->super.do_encrypt_v = aesni256 ? non_temporal_encrypt_v256 : non_temporal_encrypt_v128;
        ctx->super.do_decrypt = NULL;
    } else {
        assert(!aesni256);
        ctx->super.do_encrypt = NULL;
        ctx->super.do_encrypt_v = NULL;
        ctx->super.do_decrypt = non_temporal_decrypt128;
    }

    ctx->aesgcm =
        new_aesgcm(key, key_size,
                   7 * (ptls_fusion_can_aesni256 ? 32 : 16), // 6 blocks at once, plus len(A) | len(C) that we might append
                   aesni256);

    return 0;
}

static int non_temporal_aes128gcm_setup(ptls_aead_context_t *ctx, int is_enc, const void *key, const void *iv)
{
    return non_temporal_setup(ctx, is_enc, key, iv, PTLS_AES128_KEY_SIZE);
}

static int non_temporal_aes256gcm_setup(ptls_aead_context_t *ctx, int is_enc, const void *key, const void *iv)
{
    return non_temporal_setup(ctx, is_enc, key, iv, PTLS_AES256_KEY_SIZE);
}

ptls_aead_algorithm_t ptls_non_temporal_aes128gcm = {"AES128-GCM",
                                                     PTLS_AESGCM_CONFIDENTIALITY_LIMIT,
                                                     PTLS_AESGCM_INTEGRITY_LIMIT,
                                                     &ptls_fusion_aes128ctr,
                                                     NULL, // &ptls_fusion_aes128ecb,
                                                     PTLS_AES128_KEY_SIZE,
                                                     PTLS_AESGCM_IV_SIZE,
                                                     PTLS_AESGCM_TAG_SIZE,
                                                     1,
                                                     PTLS_X86_CACHE_LINE_ALIGN_BITS,
                                                     sizeof(struct aesgcm_context),
                                                     non_temporal_aes128gcm_setup};
ptls_aead_algorithm_t ptls_non_temporal_aes256gcm = {"AES256-GCM",
                                                     PTLS_AESGCM_CONFIDENTIALITY_LIMIT,
                                                     PTLS_AESGCM_INTEGRITY_LIMIT,
                                                     &ptls_fusion_aes256ctr,
                                                     NULL, // &ptls_fusion_aes128ecb,
                                                     PTLS_AES256_KEY_SIZE,
                                                     PTLS_AESGCM_IV_SIZE,
                                                     PTLS_AESGCM_TAG_SIZE,
                                                     1,
                                                     PTLS_X86_CACHE_LINE_ALIGN_BITS,
                                                     sizeof(struct aesgcm_context),
                                                     non_temporal_aes256gcm_setup};

#ifdef _WINDOWS
/**
 * ptls_fusion_is_supported_by_cpu:
 * Check that the CPU has extended instructions for PCMUL, AES and AVX2.
 * This test assumes that the CPU is following the x86/x64 architecture.
 * A slightly more refined test could check that the cpu_info spells out
 * "genuineIntel" or "authenticAMD", but would fail in presence of
 * little known CPU brands or some VM */
int ptls_fusion_is_supported_by_cpu(void)
{
    uint32_t cpu_info[4];
    uint32_t nb_ids;
    int is_supported = 0;

    __cpuid(cpu_info, 0);
    nb_ids = cpu_info[0];

    if (nb_ids >= 7) {
        uint32_t leaf1_ecx;
        __cpuid(cpu_info, 1);
        leaf1_ecx = cpu_info[2];

        if (/* PCLMUL */ (leaf1_ecx & (1 << 5)) != 0 && /* AES */ (leaf1_ecx & (1 << 25)) != 0) {
            uint32_t leaf7_ebx, leaf7_ecx;
            __cpuid(cpu_info, 7);
            leaf7_ebx = cpu_info[1];
            leaf7_ecx = cpu_info[2];

            is_supported = /* AVX2 */ (leaf7_ebx & (1 << 5)) != 0;

            /* enable 256-bit mode if possible */
            if (is_supported && (leaf7_ecx & 0x600) != 0 && !ptls_fusion_can_aesni256)
                ptls_fusion_can_aesni256 = 1;
        }
    }

    return is_supported;
}
#else
int ptls_fusion_is_supported_by_cpu(void)
{
    unsigned leaf1_ecx, leaf7_ebx, leaf7_ecx;

    { /* GCC-specific code to obtain CPU features */
        unsigned leaf_cnt;
        __asm__("cpuid" : "=a"(leaf_cnt) : "a"(0) : "ebx", "ecx", "edx");
        if (leaf_cnt < 7)
            return 0;
        __asm__("cpuid" : "=c"(leaf1_ecx) : "a"(1) : "ebx", "edx");
        __asm__("cpuid" : "=b"(leaf7_ebx), "=c"(leaf7_ecx) : "a"(7), "c"(0) : "edx");
    }

    /* AVX2 */
    if ((leaf7_ebx & (1 << 5)) == 0)
        return 0;
    /* AES */
    if ((leaf1_ecx & (1 << 25)) == 0)
        return 0;
    /* PCLMUL */
    if ((leaf1_ecx & (1 << 1)) == 0)
        return 0;

    /* enable 256-bit mode if possible */
    if ((leaf7_ecx & 0x600) != 0 && !ptls_fusion_can_aesni256)
        ptls_fusion_can_aesni256 = 1;

    return 1;
}
#endif
