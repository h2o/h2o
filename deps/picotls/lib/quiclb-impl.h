/*
 * Copyright (c) 2025 Fastly, Kazuho Oku
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
#ifndef picotls_quiclb_h
#define picotls_quiclb_h

#if defined(__x86_64__) || defined(_M_X64)
#include <emmintrin.h>
#define PICOTLS_QUICLB_HAVE_SSE2 1
#endif

union picotls_quiclb_block {
    uint8_t bytes[PTLS_AES_BLOCK_SIZE];
    uint64_t u64[PTLS_AES_BLOCK_SIZE / sizeof(uint64_t)];
#if PICOTLS_QUICLB_HAVE_SSE2
    __m128i m128;
#endif
};

/**
 * encrypts one block of AES, assuming the context is `ptls_cipher_context_t` backed by ptls_foo_aes128ecb
 */
static inline void picotls_quiclb_cipher_aes(void *aesecb, union picotls_quiclb_block *block)
{
    ptls_cipher_encrypt(aesecb, block->bytes, block->bytes, PTLS_AES_BLOCK_SIZE);
}

/**
 * calculates X ^ AES(mask_and_expand(Y))
 */
static inline void picotls_quiclb_one_round(void (*aesecb_func)(void *aesecb, union picotls_quiclb_block *), void *aesecb_ctx,
                                            union picotls_quiclb_block *dest, const union picotls_quiclb_block *x,
                                            const union picotls_quiclb_block *y, const union picotls_quiclb_block *mask,
                                            const union picotls_quiclb_block *len_pass)
{
#if PICOTLS_QUICLB_HAVE_SSE2
    dest->m128 = _mm_or_si128(_mm_and_si128(y->m128, mask->m128), len_pass->m128);
#else
    for (size_t i = 0; i < PTLS_ELEMENTSOF(dest->u64); ++i)
        dest->u64[i] = (y->u64[i] & mask->u64[i]) | len_pass->u64[i];
#endif

    aesecb_func(aesecb_ctx, dest);

#if PICOTLS_QUICLB_HAVE_SSE2
    dest->m128 = _mm_xor_si128(dest->m128, x->m128);
#else
    for (size_t i = 0; i < PTLS_ELEMENTSOF(dest->u64); ++i)
        dest->u64[i] ^= x->u64[i];
#endif
}

static inline void picotls_quiclb_split_input(union picotls_quiclb_block *l, union picotls_quiclb_block *r, const uint8_t *input,
                                              size_t len)
{
    size_t i;
    for (i = 0; i < (len + 1) / 2; ++i)
        l->bytes[i] = input[i];
    for (; i < PTLS_ELEMENTSOF(l->bytes); ++i)
        l->bytes[i] = 0;
    for (i = 0; i < (len + 1) / 2; ++i)
        r->bytes[i] = input[i + len / 2];
    for (; i < PTLS_ELEMENTSOF(r->bytes); ++i)
        r->bytes[i] = 0;
}

static inline void picotls_quiclb_merge_output(uint8_t *output, size_t len, const union picotls_quiclb_block *l,
                                               const union picotls_quiclb_block *r)
{
    uint8_t *outp = output;

    for (size_t i = 0; i < len / 2; ++i)
        *outp++ = l->bytes[i];

    if (len % 2 == 0) {
        for (size_t i = 0; i < len / 2; ++i)
            *outp++ = r->bytes[i];
    } else {
        *outp++ = (l->bytes[len / 2] & 0xf0) | (r->bytes[0] & 0x0f);
        for (size_t i = 0; i < len / 2; ++i)
            *outp++ = r->bytes[i + 1];
    }
}

static inline void picotls_quiclb_do_init(ptls_cipher_context_t *ctx, const void *iv)
{
    /* no-op */
}

static inline void picotls_quiclb_transform(void (*aesecb_func)(void *aesecb, union picotls_quiclb_block *), void *aesecb_ctx,
                                            void *output, const void *input, size_t len, int encrypt)
{
    static const struct quiclb_mask_t {
        union picotls_quiclb_block l, r;
    } masks[] = {
        {{{0xff, 0xff, 0xff, 0xf0}}, {{0x0f, 0xff, 0xff, 0xff}}},                                                 /* 7 (MIN_LEN) */
        {{{0xff, 0xff, 0xff, 0xff}}, {{0xff, 0xff, 0xff, 0xff}}},                                                 /* 8 */
        {{{0xff, 0xff, 0xff, 0xff, 0xf0}}, {{0x0f, 0xff, 0xff, 0xff, 0xff}}},                                     /* 9 */
        {{{0xff, 0xff, 0xff, 0xff, 0xff}}, {{0xff, 0xff, 0xff, 0xff, 0xff}}},                                     /* 10 */
        {{{0xff, 0xff, 0xff, 0xff, 0xff, 0xf0}}, {{0x0f, 0xff, 0xff, 0xff, 0xff, 0xff}}},                         /* 11 */
        {{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}}, {{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}}},                         /* 12 */
        {{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf0}}, {{0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}}},             /* 13 */
        {{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}}, {{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}}},             /* 14 */
        {{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf0}}, {{0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}}}, /* 15 */
        {{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}}, {{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}}}, /* 16 */
        {{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf0}},
         {{0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}}}, /* 17 */
        {{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
         {{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}}}, /* 18 */
        {{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf0}},
         {{0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}}} /* 19 */
    };

    assert(PTLS_QUICLB_MIN_BLOCK_SIZE <= len && len <= PTLS_QUICLB_MAX_BLOCK_SIZE);
    PTLS_BUILD_ASSERT(PTLS_QUICLB_MAX_BLOCK_SIZE == PTLS_QUICLB_MIN_BLOCK_SIZE + PTLS_ELEMENTSOF(masks) - 1);

    const struct quiclb_mask_t *mask = &masks[len - PTLS_QUICLB_MIN_BLOCK_SIZE];
    union picotls_quiclb_block l0, r0, r1, l1, r2, l2, len_pass = {{0}};
    len_pass.bytes[14] = (uint8_t)len;

#define ROUND(rnd, dest, x, y, mask_side)                                                                                          \
    do {                                                                                                                           \
        len_pass.bytes[15] = (rnd);                                                                                                \
        picotls_quiclb_one_round(aesecb_func, aesecb_ctx, &dest, &x, &y, &mask->mask_side, &len_pass);                             \
    } while (0)

    if (encrypt) {
        picotls_quiclb_split_input(&l0, &r0, input, len);
        ROUND(1, r1, r0, l0, l);
        ROUND(2, l1, l0, r1, r);
        ROUND(3, r2, r1, l1, l);
        ROUND(4, l2, l1, r2, r);
        picotls_quiclb_merge_output(output, len, &l2, &r2);
    } else {
        picotls_quiclb_split_input(&l2, &r2, input, len);
        ROUND(4, l1, l2, r2, r);
        ROUND(3, r1, r2, l1, l);
        ROUND(2, l0, l1, r1, r);
        ROUND(1, r0, r1, l0, l);
        picotls_quiclb_merge_output(output, len, &l0, &r0);
    }

#undef ROUND
}

#endif
