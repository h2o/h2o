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
#include "aes-common.h"

static int aes128ecb_setup_crypto(ptls_cipher_context_t *ctx, int is_enc, const void *key)
{
    return aesecb_setup_crypto(ctx, is_enc, key);
}

static int aes128ctr_setup_crypto(ptls_cipher_context_t *ctx, int is_enc, const void *key)
{
    return aesctr_setup_crypto(ctx, is_enc, key);
}

static int aead_aes128gcm_setup_crypto(ptls_aead_context_t *ctx, int is_enc, const void *key, const void *iv)
{
    return aead_aesgcm_setup_crypto(ctx, is_enc, key, iv);
}

ptls_define_hash(sha256, cf_sha256_context, cf_sha256_init, cf_sha256_update, cf_sha256_digest_final);

ptls_hash_algorithm_t ptls_minicrypto_sha256 = {PTLS_SHA256_BLOCK_SIZE, PTLS_SHA256_DIGEST_SIZE, sha256_create,
                                                PTLS_ZERO_DIGEST_SHA256};

ptls_cipher_algorithm_t ptls_minicrypto_aes128ecb = {
    "AES128-ECB",          PTLS_AES128_KEY_SIZE, PTLS_AES_BLOCK_SIZE, 0 /* iv size */, sizeof(struct aesecb_context_t),
    aes128ecb_setup_crypto};
ptls_cipher_algorithm_t ptls_minicrypto_aes128ctr = {
    "AES128-CTR",          PTLS_AES128_KEY_SIZE, 1 /* block size */, PTLS_AES_IV_SIZE, sizeof(struct aesctr_context_t),
    aes128ctr_setup_crypto};
ptls_aead_algorithm_t ptls_minicrypto_aes128gcm = {
    "AES128-GCM",        &ptls_minicrypto_aes128ctr, &ptls_minicrypto_aes128ecb,      PTLS_AES128_KEY_SIZE,
    PTLS_AESGCM_IV_SIZE, PTLS_AESGCM_TAG_SIZE,       sizeof(struct aesgcm_context_t), aead_aes128gcm_setup_crypto};
ptls_cipher_suite_t ptls_minicrypto_aes128gcmsha256 = {PTLS_CIPHER_SUITE_AES_128_GCM_SHA256, &ptls_minicrypto_aes128gcm,
                                                       &ptls_minicrypto_sha256};
