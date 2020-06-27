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

static int aes256ecb_setup_crypto(ptls_cipher_context_t *ctx, int is_enc, const void *key)
{
    return aesecb_setup_crypto(ctx, is_enc, key);
}

static int aes256ctr_setup_crypto(ptls_cipher_context_t *ctx, int is_enc, const void *key)
{
    return aesctr_setup_crypto(ctx, is_enc, key);
}

static int aead_aes256gcm_setup_crypto(ptls_aead_context_t *ctx, int is_enc, const void *key, const void *iv)
{
    return aead_aesgcm_setup_crypto(ctx, is_enc, key, iv);
}

ptls_define_hash(sha384, cf_sha512_context, cf_sha384_init, cf_sha384_update, cf_sha384_digest_final);

ptls_hash_algorithm_t ptls_minicrypto_sha384 = {PTLS_SHA384_BLOCK_SIZE, PTLS_SHA384_DIGEST_SIZE, sha384_create,
                                                PTLS_ZERO_DIGEST_SHA384};

ptls_cipher_algorithm_t ptls_minicrypto_aes256ecb = {
    "AES256-ECB",          PTLS_AES256_KEY_SIZE, PTLS_AES_BLOCK_SIZE, 0 /* iv size */, sizeof(struct aesecb_context_t),
    aes256ecb_setup_crypto};
ptls_cipher_algorithm_t ptls_minicrypto_aes256ctr = {
    "AES256-CTR",          PTLS_AES256_KEY_SIZE, 1 /* block size */, PTLS_AES_IV_SIZE, sizeof(struct aesctr_context_t),
    aes256ctr_setup_crypto};
ptls_aead_algorithm_t ptls_minicrypto_aes256gcm = {
    "AES256-GCM",        &ptls_minicrypto_aes256ctr, &ptls_minicrypto_aes256ecb,      PTLS_AES256_KEY_SIZE,
    PTLS_AESGCM_IV_SIZE, PTLS_AESGCM_TAG_SIZE,       sizeof(struct aesgcm_context_t), aead_aes256gcm_setup_crypto};
ptls_cipher_suite_t ptls_minicrypto_aes256gcmsha384 = {PTLS_CIPHER_SUITE_AES_256_GCM_SHA384, &ptls_minicrypto_aes256gcm,
                                                       &ptls_minicrypto_sha384};
