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
#ifndef picotls_fusion_h
#define picotls_fusion_h

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <emmintrin.h>
#include <immintrin.h>
#include "../picotls.h"

#define PTLS_FUSION_AES128_ROUNDS 10
#define PTLS_FUSION_AES256_ROUNDS 14

#ifndef PTLS_X86_CACHE_LINE_ALIGN_BITS
#define PTLS_X86_CACHE_LINE_ALIGN_BITS 6 /* 64-bytes */
#endif

typedef struct ptls_fusion_aesecb_context {
    union {
        __m128i m128[PTLS_FUSION_AES256_ROUNDS + 1];
        __m256i m256[PTLS_FUSION_AES256_ROUNDS + 1];
    } keys;
    unsigned rounds;
    uint8_t aesni256;
} __attribute__((aligned(32))) ptls_fusion_aesecb_context_t;

typedef struct ptls_fusion_aesgcm_context ptls_fusion_aesgcm_context_t;

void ptls_fusion_aesecb_init(ptls_fusion_aesecb_context_t *ctx, int is_enc, const void *key, size_t key_size, int avx256);
void ptls_fusion_aesecb_dispose(ptls_fusion_aesecb_context_t *ctx);
void ptls_fusion_aesecb_encrypt(ptls_fusion_aesecb_context_t *ctx, void *dst, const void *src);

/**
 * Creates an AES-GCM context.
 * @param key       the AES key (128 bits)
 * @param capacity  maximum size of AEAD record (i.e. AAD + encrypted payload)
 */
ptls_fusion_aesgcm_context_t *ptls_fusion_aesgcm_new(const void *key, size_t key_size, size_t capacity);
/**
 * Updates the capacity.
 */
ptls_fusion_aesgcm_context_t *ptls_fusion_aesgcm_set_capacity(ptls_fusion_aesgcm_context_t *ctx, size_t capacity);
/**
 * Destroys an AES-GCM context.
 */
void ptls_fusion_aesgcm_free(ptls_fusion_aesgcm_context_t *ctx);
/**
 * Encrypts an AEAD block, and in parallel, optionally encrypts one block using AES-ECB.
 * @param ctx      context
 * @param output   output buffer
 * @param input    payload to be encrypted
 * @param inlen    size of the payload to be encrypted
 * @param counter
 * @param aad      AAD
 * @param aadlen   size of AAD
 * @param supp     (optional) supplementary encryption context
 */
void ptls_fusion_aesgcm_encrypt(ptls_fusion_aesgcm_context_t *ctx, void *output, const void *input, size_t inlen, __m128i ctr,
                                const void *aad, size_t aadlen, ptls_aead_supplementary_encryption_t *supp);
/**
 * Decrypts an AEAD block, an in parallel, optionally encrypts one block using AES-ECB. Returns if decryption was successful.
 * @param iv       initialization vector of 12 bytes
 * @param output   output buffer
 * @param input    payload to be decrypted
 * @param inlen    size of the payload to be decrypted
 * @param aad      AAD
 * @param aadlen   size of AAD
 * @param tag      the AEAD tag being received from peer
 */
int ptls_fusion_aesgcm_decrypt(ptls_fusion_aesgcm_context_t *ctx, void *output, const void *input, size_t inlen, __m128i ctr,
                               const void *aad, size_t aadlen, const void *tag);

/**
 * A boolean flag indicating if vaes and vpclmulqdq (256-bit crypto instructions) should be used. This flag is set automatically
 * when `ptls_fusion_is_supported_by_cpu` is called. Users can update the flag to enforce behavior. Engines that do not have support
 * for these 256-bit instructions will continue using the 128-bit ones, even when this flag is set.
 */
extern int ptls_fusion_can_aesni256;
extern ptls_cipher_algorithm_t ptls_fusion_aes128ctr, ptls_fusion_aes256ctr;
extern ptls_aead_algorithm_t ptls_fusion_aes128gcm, ptls_fusion_aes256gcm;
extern ptls_aead_algorithm_t ptls_non_temporal_aes128gcm, ptls_non_temporal_aes256gcm;

/**
 * Returns a boolean indicating if fusion can be used.
 */
int ptls_fusion_is_supported_by_cpu(void);

#ifdef __cplusplus
}
#endif

#endif
