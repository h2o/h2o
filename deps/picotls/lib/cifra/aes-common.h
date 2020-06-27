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
#include <stdlib.h>
#include <string.h>
#include "aes.h"
#include "modes.h"
#include "sha2.h"
#include "picotls.h"
#include "picotls/minicrypto.h"

struct aesecb_context_t {
    ptls_cipher_context_t super;
    cf_aes_context aes;
};

static inline void aesecb_dispose(ptls_cipher_context_t *_ctx)
{
    struct aesecb_context_t *ctx = (struct aesecb_context_t *)_ctx;
    ptls_clear_memory(ctx, sizeof(*ctx));
}

static inline void aesecb_encrypt(ptls_cipher_context_t *_ctx, void *output, const void *input, size_t len)
{
    struct aesecb_context_t *ctx = (struct aesecb_context_t *)_ctx;
    assert(len % AES_BLOCKSZ == 0);
    cf_aes_encrypt(&ctx->aes, input, output);
}

static inline void aesecb_decrypt(ptls_cipher_context_t *_ctx, void *output, const void *input, size_t len)
{
    struct aesecb_context_t *ctx = (struct aesecb_context_t *)_ctx;
    assert(len % AES_BLOCKSZ == 0);
    cf_aes_decrypt(&ctx->aes, input, output);
}

static inline int aesecb_setup_crypto(ptls_cipher_context_t *_ctx, int is_enc, const void *key)
{
    struct aesecb_context_t *ctx = (struct aesecb_context_t *)_ctx;
    ctx->super.do_dispose = aesecb_dispose;
    ctx->super.do_init = NULL;
    ctx->super.do_transform = is_enc ? aesecb_encrypt : aesecb_decrypt;
    cf_aes_init(&ctx->aes, key, ctx->super.algo->key_size);
    return 0;
}

struct aesctr_context_t {
    ptls_cipher_context_t super;
    cf_aes_context aes;
    cf_ctr ctr;
};

static inline void aesctr_dispose(ptls_cipher_context_t *_ctx)
{
    struct aesctr_context_t *ctx = (struct aesctr_context_t *)_ctx;
    ptls_clear_memory(ctx, sizeof(*ctx));
}

static inline void aesctr_init(ptls_cipher_context_t *_ctx, const void *iv)
{
    struct aesctr_context_t *ctx = (struct aesctr_context_t *)_ctx;
    cf_ctr_init(&ctx->ctr, &cf_aes, &ctx->aes, iv);
}

static inline void aesctr_transform(ptls_cipher_context_t *_ctx, void *output, const void *input, size_t len)
{
    struct aesctr_context_t *ctx = (struct aesctr_context_t *)_ctx;
    cf_ctr_cipher(&ctx->ctr, input, output, len);
}

static inline int aesctr_setup_crypto(ptls_cipher_context_t *_ctx, int is_enc, const void *key)
{
    struct aesctr_context_t *ctx = (struct aesctr_context_t *)_ctx;
    ctx->super.do_dispose = aesctr_dispose;
    ctx->super.do_init = aesctr_init;
    ctx->super.do_transform = aesctr_transform;
    cf_aes_init(&ctx->aes, key, ctx->super.algo->key_size);
    return 0;
}

struct aesgcm_context_t {
    ptls_aead_context_t super;
    cf_aes_context aes;
    cf_gcm_ctx gcm;
    uint8_t static_iv[PTLS_AESGCM_IV_SIZE];
};

static inline void aesgcm_dispose_crypto(ptls_aead_context_t *_ctx)
{
    struct aesgcm_context_t *ctx = (struct aesgcm_context_t *)_ctx;

    /* clear all memory except super */
    ptls_clear_memory((uint8_t *)ctx + sizeof(ctx->super), sizeof(*ctx) - sizeof(ctx->super));
}

static inline void aesgcm_encrypt_init(ptls_aead_context_t *_ctx, uint64_t seq, const void *aad, size_t aadlen)
{
    struct aesgcm_context_t *ctx = (struct aesgcm_context_t *)_ctx;
    uint8_t iv[PTLS_AES_BLOCK_SIZE];

    ptls_aead__build_iv(ctx->super.algo, iv, ctx->static_iv, seq);
    cf_gcm_encrypt_init(&cf_aes, &ctx->aes, &ctx->gcm, aad, aadlen, iv, PTLS_AESGCM_IV_SIZE);
}

static inline size_t aesgcm_encrypt_update(ptls_aead_context_t *_ctx, void *output, const void *input, size_t inlen)
{
    struct aesgcm_context_t *ctx = (struct aesgcm_context_t *)_ctx;

    cf_gcm_encrypt_update(&ctx->gcm, input, inlen, output);
    return inlen;
}

static inline size_t aesgcm_encrypt_final(ptls_aead_context_t *_ctx, void *output)
{
    struct aesgcm_context_t *ctx = (struct aesgcm_context_t *)_ctx;

    cf_gcm_encrypt_final(&ctx->gcm, output, PTLS_AESGCM_TAG_SIZE);
    return PTLS_AESGCM_TAG_SIZE;
}

static inline size_t aesgcm_decrypt(ptls_aead_context_t *_ctx, void *output, const void *input, size_t inlen, uint64_t seq,
                                    const void *aad, size_t aadlen)
{
    struct aesgcm_context_t *ctx = (struct aesgcm_context_t *)_ctx;
    uint8_t iv[PTLS_AES_BLOCK_SIZE];

    if (inlen < PTLS_AESGCM_TAG_SIZE)
        return SIZE_MAX;
    size_t tag_offset = inlen - PTLS_AESGCM_TAG_SIZE;

    ptls_aead__build_iv(ctx->super.algo, iv, ctx->static_iv, seq);
    if (cf_gcm_decrypt(&cf_aes, &ctx->aes, input, tag_offset, aad, aadlen, iv, PTLS_AESGCM_IV_SIZE, (uint8_t *)input + tag_offset,
                       PTLS_AESGCM_TAG_SIZE, output) != 0)
        return SIZE_MAX;

    return tag_offset;
}

static inline int aead_aesgcm_setup_crypto(ptls_aead_context_t *_ctx, int is_enc, const void *key, const void *iv)
{
    struct aesgcm_context_t *ctx = (struct aesgcm_context_t *)_ctx;

    ctx->super.dispose_crypto = aesgcm_dispose_crypto;
    if (is_enc) {
        ctx->super.do_encrypt_init = aesgcm_encrypt_init;
        ctx->super.do_encrypt_update = aesgcm_encrypt_update;
        ctx->super.do_encrypt_final = aesgcm_encrypt_final;
        ctx->super.do_encrypt = ptls_aead__do_encrypt;
        ctx->super.do_decrypt = NULL;
    } else {
        ctx->super.do_encrypt_init = NULL;
        ctx->super.do_encrypt_update = NULL;
        ctx->super.do_encrypt_final = NULL;
        ctx->super.do_decrypt = aesgcm_decrypt;
    }

    cf_aes_init(&ctx->aes, key, ctx->super.algo->key_size);
    memcpy(ctx->static_iv, iv, sizeof(ctx->static_iv));
    return 0;
}
