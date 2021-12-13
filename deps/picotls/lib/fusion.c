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
#include <stdint.h>

#include <stdlib.h>
#include <string.h>
#include <immintrin.h>
#include <tmmintrin.h>
#include <nmmintrin.h>
#include <wmmintrin.h>
#include "picotls.h"
#include "picotls/fusion.h"

struct ptls_fusion_aesgcm_context {
    ptls_fusion_aesecb_context_t ecb;
    size_t capacity;
    size_t ghash_cnt;
    struct ptls_fusion_aesgcm_ghash_precompute {
        __m128i H;
        __m128i r;
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
static const uint8_t bswap8_[16] __attribute__((aligned(16))) = {15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0};
#define bswap8 (*(__m128i *)bswap8_)
static const uint8_t one8_[16] __attribute__((aligned(16))) = {1};
#define one8 (*(__m128i *)one8_)

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

struct ptls_fusion_gfmul_state {
    __m128i hi, lo, mid;
};

static inline void gfmul_onestep(struct ptls_fusion_gfmul_state *gstate, __m128i X,
                                 struct ptls_fusion_aesgcm_ghash_precompute *precompute)
{
    X = _mm_shuffle_epi8(X, bswap8);
    __m128i t = _mm_clmulepi64_si128(precompute->H, X, 0x00);
    gstate->lo = _mm_xor_si128(gstate->lo, t);
    t = _mm_clmulepi64_si128(precompute->H, X, 0x11);
    gstate->hi = _mm_xor_si128(gstate->hi, t);
    t = _mm_shuffle_epi32(X, 78);
    t = _mm_xor_si128(t, X);
    t = _mm_clmulepi64_si128(precompute->r, t, 0x00);
    gstate->mid = _mm_xor_si128(gstate->mid, t);
}

static inline __m128i gfmul_final(struct ptls_fusion_gfmul_state *gstate, __m128i ek0)
{
    /* finish multiplication */
    gstate->mid = _mm_xor_si128(gstate->mid, gstate->hi);
    gstate->mid = _mm_xor_si128(gstate->mid, gstate->lo);
    gstate->lo = _mm_xor_si128(gstate->lo, _mm_slli_si128(gstate->mid, 8));
    gstate->hi = _mm_xor_si128(gstate->hi, _mm_srli_si128(gstate->mid, 8));

    /* fast reduction, using https://crypto.stanford.edu/RealWorldCrypto/slides/gueron.pdf */
    __m128i r = _mm_clmulepi64_si128(gstate->lo, poly, 0x10);
    gstate->lo = _mm_shuffle_epi32(gstate->lo, 78);
    gstate->lo = _mm_xor_si128(gstate->lo, r);
    r = _mm_clmulepi64_si128(gstate->lo, poly, 0x10);
    gstate->lo = _mm_shuffle_epi32(gstate->lo, 78);
    gstate->lo = _mm_xor_si128(gstate->lo, r);
    __m128i tag = _mm_xor_si128(gstate->hi, gstate->lo);
    tag = _mm_shuffle_epi8(tag, bswap8);
    tag = _mm_xor_si128(tag, ek0);

    return tag;
}

static inline __m128i aesecb_encrypt(ptls_fusion_aesecb_context_t *ctx, __m128i v)
{
    size_t i;

    v = _mm_xor_si128(v, ctx->keys[0]);
    for (i = 1; i < ctx->rounds; ++i)
        v = _mm_aesenc_si128(v, ctx->keys[i]);
    v = _mm_aesenclast_si128(v, ctx->keys[i]);

    return v;
}

static const uint8_t loadn_mask[31] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                       0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
static const uint8_t loadn_shuffle[31] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                          0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, // first 16 bytes map to byte offsets
                                          0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
                                          0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80}; // latter 15 bytes map to zero

#if defined(__clang__)
#if __has_feature(address_sanitizer)
__attribute__((no_sanitize("address")))
#endif
#elif __SANITIZE_ADDRESS__ /* gcc */
__attribute__((no_sanitize_address))
#endif
static inline __m128i loadn(const void *p, size_t l)
{
    __m128i v, mask = _mm_loadu_si128((__m128i *)(loadn_mask + 16 - l));
    uintptr_t mod4k = (uintptr_t)p % 4096;

    if (PTLS_LIKELY(mod4k <= 4080) || mod4k + l > 4096) {
        v = _mm_loadu_si128(p);
    } else {
        uintptr_t shift = (uintptr_t)p & 15;
        __m128i pattern = _mm_loadu_si128((const __m128i *)(loadn_shuffle + shift));
        v = _mm_shuffle_epi8(_mm_load_si128((const __m128i *)((uintptr_t)p - shift)), pattern);
    }
    v = _mm_and_si128(v, mask);
    return v;
}

static inline void storen(void *_p, size_t l, __m128i v)
{
    uint8_t buf[16], *p = _p;

    *(__m128i *)buf = v;

    for (size_t i = 0; i != l; ++i)
        p[i] = buf[i];
}

void ptls_fusion_aesgcm_encrypt(ptls_fusion_aesgcm_context_t *ctx, void *output, const void *input, size_t inlen, __m128i ctr,
                                const void *_aad, size_t aadlen, ptls_aead_supplementary_encryption_t *supp)
{
/* init the bits (we can always run in full), but use the last slot for calculating ek0, if possible */
#define AESECB6_INIT()                                                                                                             \
    do {                                                                                                                           \
        ctr = _mm_add_epi64(ctr, one8);                                                                                            \
        bits0 = _mm_shuffle_epi8(ctr, bswap8);                                                                                     \
        ctr = _mm_add_epi64(ctr, one8);                                                                                            \
        bits1 = _mm_shuffle_epi8(ctr, bswap8);                                                                                     \
        ctr = _mm_add_epi64(ctr, one8);                                                                                            \
        bits2 = _mm_shuffle_epi8(ctr, bswap8);                                                                                     \
        ctr = _mm_add_epi64(ctr, one8);                                                                                            \
        bits3 = _mm_shuffle_epi8(ctr, bswap8);                                                                                     \
        ctr = _mm_add_epi64(ctr, one8);                                                                                            \
        bits4 = _mm_shuffle_epi8(ctr, bswap8);                                                                                     \
        if (PTLS_LIKELY(srclen > 16 * 5)) {                                                                                        \
            ctr = _mm_add_epi64(ctr, one8);                                                                                        \
            bits5 = _mm_shuffle_epi8(ctr, bswap8);                                                                                 \
        } else {                                                                                                                   \
            if ((state & STATE_EK0_BEEN_FED) == 0) {                                                                               \
                bits5 = ek0;                                                                                                       \
                state |= STATE_EK0_BEEN_FED;                                                                                       \
            }                                                                                                                      \
            if ((state & STATE_SUPP_USED) != 0 && srclen <= 16 * 4 && (const __m128i *)supp->input + 1 <= dst_ghash) {             \
                bits4 = _mm_loadu_si128(supp->input);                                                                              \
                bits4keys = ((struct ctr_context *)supp->ctx)->fusion.keys;                                                        \
                state |= STATE_SUPP_IN_PROCESS;                                                                                    \
            }                                                                                                                      \
        }                                                                                                                          \
        __m128i k = ctx->ecb.keys[0];                                                                                              \
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
        __m128i k = ctx->ecb.keys[i];                                                                                              \
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
        __m128i k = ctx->ecb.keys[i];                                                                                              \
        bits0 = _mm_aesenclast_si128(bits0, k);                                                                                    \
        bits1 = _mm_aesenclast_si128(bits1, k);                                                                                    \
        bits2 = _mm_aesenclast_si128(bits2, k);                                                                                    \
        bits3 = _mm_aesenclast_si128(bits3, k);                                                                                    \
        bits4 = _mm_aesenclast_si128(bits4, bits4keys[i]);                                                                         \
        bits5 = _mm_aesenclast_si128(bits5, k);                                                                                    \
    } while (0)

    __m128i ek0, bits0, bits1, bits2, bits3, bits4, bits5 = _mm_setzero_si128();
    const __m128i *bits4keys = ctx->ecb.keys; /* is changed to supp->ctx.keys when calcurating suppout */
    struct ptls_fusion_gfmul_state gstate = {0};
    __m128i gdatabuf[6];
    __m128i ac = _mm_shuffle_epi8(_mm_set_epi32(0, (int)aadlen * 8, 0, (int)inlen * 8), bswap8);

    // src and dst are updated after the chunk is processed
    const __m128i *src = input;
    __m128i *dst = output;
    size_t srclen = inlen;
    // aad and src_ghash are updated before the chunk is processed (i.e., when the pointers are fed indo the processor)
    const __m128i *aad = _aad, *dst_ghash = dst;
    size_t dst_ghashlen = srclen;

    struct ptls_fusion_aesgcm_ghash_precompute *ghash_precompute = ctx->ghash + (aadlen + 15) / 16 + (srclen + 15) / 16 + 1;

#define STATE_EK0_BEEN_FED 0x3
#define STATE_EK0_INCOMPLETE 0x2
#define STATE_EK0_READY() ((state & STATE_EK0_BEEN_FED) == 0x1)
#define STATE_SUPP_USED 0x4
#define STATE_SUPP_IN_PROCESS 0x8
    int32_t state = supp != NULL ? STATE_SUPP_USED : 0;

    /* build counter */
    ctr = _mm_insert_epi32(ctr, 1, 0);
    ek0 = _mm_shuffle_epi8(ctr, bswap8);

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
                    gdatabuf[gdata_cnt++] = loadn(aad, aadlen);
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
            gfmul_onestep(&gstate, _mm_loadu_si128(gdata++), --ghash_precompute);
        }
        for (; i < ctx->ecb.rounds; ++i)
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
                storen(dst, srclen, _mm_xor_si128(loadn(src, srclen), bits0));
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
                        gdatabuf[gdata_cnt++] = loadn(aad, aadlen);
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
                        gdatabuf[gdata_cnt++] = loadn(dst_ghash, dst_ghashlen);
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
        gfmul_onestep(&gstate, gdatabuf[i], --ghash_precompute);

    _mm_storeu_si128(dst, gfmul_final(&gstate, ek0));

    /* Finish the calculation of supplemental vector. Done at the very last, because the sample might cover the GCM tag. */
    if ((state & STATE_SUPP_USED) != 0) {
        size_t i;
        if ((state & STATE_SUPP_IN_PROCESS) == 0) {
            bits4keys = ((struct ctr_context *)supp->ctx)->fusion.keys;
            bits4 = _mm_xor_si128(_mm_loadu_si128(supp->input), bits4keys[0]);
            i = 1;
        } else {
            i = 2;
        }
        do {
            bits4 = _mm_aesenc_si128(bits4, bits4keys[i++]);
        } while (i != ctx->ecb.rounds);
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

int ptls_fusion_aesgcm_decrypt(ptls_fusion_aesgcm_context_t *ctx, void *output, const void *input, size_t inlen, __m128i ctr,
                               const void *_aad, size_t aadlen, const void *tag)
{
    __m128i ek0 = _mm_setzero_si128(), bits0, bits1 = _mm_setzero_si128(), bits2 = _mm_setzero_si128(), bits3 = _mm_setzero_si128(),
            bits4 = _mm_setzero_si128(), bits5 = _mm_setzero_si128();
    struct ptls_fusion_gfmul_state gstate = {0};
    __m128i gdatabuf[6];
    __m128i ac = _mm_shuffle_epi8(_mm_set_epi32(0, (int)aadlen * 8, 0, (int)inlen * 8), bswap8);
    struct ptls_fusion_aesgcm_ghash_precompute *ghash_precompute = ctx->ghash + (aadlen + 15) / 16 + (inlen + 15) / 16 + 1;

    const __m128i *gdata; // points to the elements fed into GHASH
    size_t gdata_cnt;

    const __m128i *src_ghash = input, *src_aes = input, *aad = _aad;
    __m128i *dst = output;
    size_t nondata_aes_cnt = 0, src_ghashlen = inlen, src_aeslen = inlen;

    /* schedule ek0 and suppkey */
    ctr = _mm_add_epi64(ctr, one8);
    bits0 = _mm_xor_si128(_mm_shuffle_epi8(ctr, bswap8), ctx->ecb.keys[0]);
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
                        gdatabuf[gdata_cnt++] = loadn(aad, aadlen);
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
                        gdatabuf[gdata_cnt++] = loadn(src_ghash, src_ghashlen);
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
        bits##n = _mm_xor_si128(_mm_shuffle_epi8(ctr, bswap8), keys[0]);
        InitAllBits:
            INIT_BITS(0, ctx->ecb.keys);
            INIT_BITS(1, ctx->ecb.keys);
            INIT_BITS(2, ctx->ecb.keys);
            INIT_BITS(3, ctx->ecb.keys);
            INIT_BITS(4, ctx->ecb.keys);
            INIT_BITS(5, ctx->ecb.keys);
#undef INIT_BITS
        }

        { /* run aes and ghash */
#define AESECB6_UPDATE(i)                                                                                                          \
    do {                                                                                                                           \
        __m128i k = ctx->ecb.keys[i];                                                                                              \
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
                gfmul_onestep(&gstate, _mm_loadu_si128(gdata++), --ghash_precompute);
            }
            for (; aesi < ctx->ecb.rounds; ++aesi)
                AESECB6_UPDATE(aesi);
            __m128i k = ctx->ecb.keys[aesi];
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
        storen(dst, src_aeslen, _mm_xor_si128(loadn(src_aes, src_aeslen), bits0));
    }

    assert((state & STATE_IS_FIRST_RUN) == 0);

    /* the only case where AES operation is complete and GHASH is not is when the application of AC is remaining */
    if ((state & STATE_GHASH_HAS_MORE) != 0) {
        assert(ghash_precompute - 1 == ctx->ghash);
        gfmul_onestep(&gstate, ac, --ghash_precompute);
    }

    __m128i calctag = gfmul_final(&gstate, ek0);

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

void ptls_fusion_aesecb_init(ptls_fusion_aesecb_context_t *ctx, int is_enc, const void *key, size_t key_size)
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

    ctx->keys[i++] = _mm_loadu_si128((__m128i *)key);
    if (key_size == 32)
        ctx->keys[i++] = _mm_loadu_si128((__m128i *)key + 1);

#define EXPAND(R)                                                                                                                  \
    do {                                                                                                                           \
        ctx->keys[i] = expand_key(ctx->keys[i - key_size / 16],                                                                    \
                                  _mm_shuffle_epi32(_mm_aeskeygenassist_si128(ctx->keys[i - 1], R), _MM_SHUFFLE(3, 3, 3, 3)));     \
        if (i == ctx->rounds)                                                                                                      \
            goto Done;                                                                                                             \
        ++i;                                                                                                                       \
        if (key_size > 24) {                                                                                                       \
            ctx->keys[i] = expand_key(ctx->keys[i - key_size / 16],                                                                \
                                      _mm_shuffle_epi32(_mm_aeskeygenassist_si128(ctx->keys[i - 1], R), _MM_SHUFFLE(2, 2, 2, 2))); \
            ++i;                                                                                                                   \
        }                                                                                                                          \
    } while (0)
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
Done:
    assert(i == ctx->rounds);
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
    if (ctx->ghash_cnt != 0)
        ctx->ghash[ctx->ghash_cnt].H = gfmul(ctx->ghash[ctx->ghash_cnt - 1].H, ctx->ghash[0].H);

    __m128i r = _mm_shuffle_epi32(ctx->ghash[ctx->ghash_cnt].H, 78);
    r = _mm_xor_si128(r, ctx->ghash[ctx->ghash_cnt].H);
    ctx->ghash[ctx->ghash_cnt].r = r;

    ++ctx->ghash_cnt;
}

ptls_fusion_aesgcm_context_t *ptls_fusion_aesgcm_new(const void *key, size_t key_size, size_t capacity)
{
    ptls_fusion_aesgcm_context_t *ctx;
    size_t ghash_cnt = aesgcm_calc_ghash_cnt(capacity);

    if ((ctx = malloc(sizeof(*ctx) + sizeof(ctx->ghash[0]) * ghash_cnt)) == NULL)
        return NULL;

    ptls_fusion_aesecb_init(&ctx->ecb, 1, key, key_size);

    ctx->capacity = capacity;

    ctx->ghash[0].H = aesecb_encrypt(&ctx->ecb, _mm_setzero_si128());
    ctx->ghash[0].H = _mm_shuffle_epi8(ctx->ghash[0].H, bswap8);
    ctx->ghash[0].H = transformH(ctx->ghash[0].H);
    ctx->ghash_cnt = 0;
    while (ctx->ghash_cnt < ghash_cnt)
        setup_one_ghash_entry(ctx);

    return ctx;
}

ptls_fusion_aesgcm_context_t *ptls_fusion_aesgcm_set_capacity(ptls_fusion_aesgcm_context_t *ctx, size_t capacity)
{
    size_t ghash_cnt = aesgcm_calc_ghash_cnt(capacity);

    if (ghash_cnt <= ctx->ghash_cnt)
        return ctx;

    if ((ctx = realloc(ctx, sizeof(*ctx) + sizeof(ctx->ghash[0]) * ghash_cnt)) == NULL)
        return NULL;

    ctx->capacity = capacity;
    while (ghash_cnt < ctx->ghash_cnt)
        setup_one_ghash_entry(ctx);

    return ctx;
}

void ptls_fusion_aesgcm_free(ptls_fusion_aesgcm_context_t *ctx)
{
    ptls_clear_memory(ctx->ghash, sizeof(ctx->ghash[0]) * ctx->ghash_cnt);
    ctx->ghash_cnt = 0;
    ptls_fusion_aesecb_dispose(&ctx->ecb);
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
        storen(output, len, _mm_xor_si128(_mm_loadu_si128(&ctx->bits), loadn(input, len)));
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
    ptls_fusion_aesecb_init(&ctx->fusion, 1, key, key_size);
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
    __m128i xor_mask = loadn(_bytes, len);
    xor_mask = _mm_shuffle_epi8(xor_mask, bswap8);
    ctx->static_iv = _mm_xor_si128(ctx->static_iv, xor_mask);
}

static int aesgcm_setup(ptls_aead_context_t *_ctx, int is_enc, const void *key, const void *iv, size_t key_size)
{
    struct aesgcm_context *ctx = (struct aesgcm_context *)_ctx;

    ctx->static_iv = loadn(iv, PTLS_AESGCM_IV_SIZE);
    ctx->static_iv = _mm_shuffle_epi8(ctx->static_iv, bswap8);
    if (key == NULL)
        return 0;

    ctx->super.dispose_crypto = aesgcm_dispose_crypto;
    ctx->super.do_xor_iv = aesgcm_xor_iv;
    ctx->super.do_encrypt_init = aead_do_encrypt_init;
    ctx->super.do_encrypt_update = aead_do_encrypt_update;
    ctx->super.do_encrypt_final = aead_do_encrypt_final;
    ctx->super.do_encrypt = aead_do_encrypt;
    ctx->super.do_decrypt = aead_do_decrypt;

    ctx->aesgcm = ptls_fusion_aesgcm_new(key, key_size, 1500 /* assume ordinary packet size */);

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
                                               sizeof(struct aesgcm_context),
                                               aes256gcm_setup};

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
            uint32_t leaf7_ebx;
            __cpuid(cpu_info, 7);
            leaf7_ebx = cpu_info[1];

            is_supported = /* AVX2 */ (leaf7_ebx & (1 << 5)) != 0;
        }
    }

    return is_supported;
}
#else
int ptls_fusion_is_supported_by_cpu(void)
{
    unsigned leaf1_ecx, leaf7_ebx;

    { /* GCC-specific code to obtain CPU features */
        unsigned leaf_cnt;
        __asm__("cpuid" : "=a"(leaf_cnt) : "a"(0) : "ebx", "ecx", "edx");
        if (leaf_cnt < 7)
            return 0;
        __asm__("cpuid" : "=c"(leaf1_ecx) : "a"(1) : "ebx", "edx");
        __asm__("cpuid" : "=b"(leaf7_ebx) : "a"(7), "c"(0) : "edx");
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

    return 1;
}
#endif
