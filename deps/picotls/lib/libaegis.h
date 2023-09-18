/*
 * Copyright (c) 2023 Frank Denis
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
#include <aegis.h>

#include "picotls.h"

// AEGIS-128L

struct aegis128l_context_t {
    ptls_aead_context_t super;
    aegis128l_state st;
    uint8_t key[PTLS_AEGIS128L_KEY_SIZE];
    uint8_t static_iv[PTLS_AEGIS128L_IV_SIZE];
};

static void aegis128l_get_iv(ptls_aead_context_t *_ctx, void *iv)
{
    struct aegis128l_context_t *ctx = (struct aegis128l_context_t *)_ctx;

    memcpy(iv, ctx->static_iv, sizeof(ctx->static_iv));
}

static void aegis128l_set_iv(ptls_aead_context_t *_ctx, const void *iv)
{
    struct aegis128l_context_t *ctx = (struct aegis128l_context_t *)_ctx;

    memcpy(ctx->static_iv, iv, sizeof(ctx->static_iv));
}

static void aegis128l_init(ptls_aead_context_t *_ctx, uint64_t seq, const void *aad, size_t aadlen)
{
    struct aegis128l_context_t *ctx = (struct aegis128l_context_t *)_ctx;
    uint8_t iv[PTLS_AEGIS128L_IV_SIZE];

    ptls_aead__build_iv(ctx->super.algo, iv, ctx->static_iv, seq);

    aegis128l_state_init(&ctx->st, (const uint8_t *)aad, aadlen, iv, ctx->key);

    return;
}

static size_t aegis128l_encrypt_update(ptls_aead_context_t *_ctx, void *output, const void *input, size_t inlen)
{
    struct aegis128l_context_t *ctx = (struct aegis128l_context_t *)_ctx;
    size_t written;

    aegis128l_state_encrypt_update(&ctx->st, (uint8_t *)output, inlen + aegis128l_TAILBYTES_MAX, &written, (const uint8_t *)input, inlen);

    return written;
}

static size_t aegis128l_encrypt_final(ptls_aead_context_t *_ctx, void *output)
{
    struct aegis128l_context_t *ctx = (struct aegis128l_context_t *)_ctx;
    size_t written;

    aegis128l_state_encrypt_final(&ctx->st, (uint8_t *)output, aegis128l_TAILBYTES_MAX + PTLS_AEGIS128L_TAG_SIZE, &written, PTLS_AEGIS128L_TAG_SIZE);

    return written;
}

static size_t aegis128l_decrypt_oneshot(ptls_aead_context_t *_ctx, void *output, const void *input, size_t inlen, uint64_t seq,
                                        const void *aad, size_t aadlen)
{
    struct aegis128l_context_t *ctx = (struct aegis128l_context_t *)_ctx;
    uint8_t iv[PTLS_AEGIS128L_IV_SIZE] = {0};

    if (inlen < PTLS_AEGIS128L_TAG_SIZE) {
        return SIZE_MAX;
    }

    ptls_aead__build_iv(ctx->super.algo, iv, ctx->static_iv, seq);

    if (aegis128l_decrypt((uint8_t *)output, (const uint8_t *)input, inlen, PTLS_AEGIS128L_TAG_SIZE, (const uint8_t *)aad, aadlen,
                          iv, ctx->key) != 0) {
        return SIZE_MAX;
    }

    return inlen - PTLS_AEGIS128L_TAG_SIZE;
}

static void aegis128l_dispose_crypto(ptls_aead_context_t *_ctx)
{
    struct aegis128l_context_t *ctx = (struct aegis128l_context_t *)_ctx;

    ptls_clear_memory(ctx->key, sizeof(ctx->key));

    return;
}

static int aegis128l_setup_crypto(ptls_aead_context_t *_ctx, int is_enc, const void *key, const void *iv)
{
    struct aegis128l_context_t *ctx = (struct aegis128l_context_t *)_ctx;

    ctx->super.dispose_crypto = aegis128l_dispose_crypto;
    ctx->super.do_get_iv = aegis128l_get_iv;
    ctx->super.do_set_iv = aegis128l_set_iv;

    if (is_enc) {
        ctx->super.do_encrypt_init = aegis128l_init;
        ctx->super.do_encrypt_update = aegis128l_encrypt_update;
        ctx->super.do_encrypt_final = aegis128l_encrypt_final;
        ctx->super.do_encrypt = ptls_aead__do_encrypt;
        ctx->super.do_encrypt_v = ptls_aead__do_encrypt_v;
        ctx->super.do_decrypt = NULL;
    } else {
        ctx->super.do_encrypt_init = NULL;
        ctx->super.do_encrypt_update = NULL;
        ctx->super.do_encrypt_final = NULL;
        ctx->super.do_encrypt = NULL;
        ctx->super.do_encrypt_v = NULL;
        ctx->super.do_decrypt = aegis128l_decrypt_oneshot;
    }

    memcpy(ctx->key, key, sizeof(ctx->key));
    memcpy(ctx->static_iv, iv, sizeof(ctx->static_iv));

    return 0;
}

// AEGIS-256

struct aegis256_context_t {
    ptls_aead_context_t super;
    aegis256_state st;
    uint8_t key[PTLS_AEGIS256_KEY_SIZE];
    uint8_t static_iv[PTLS_AEGIS256_IV_SIZE];
};

static void aegis256_get_iv(ptls_aead_context_t *_ctx, void *iv)
{
    struct aegis256_context_t *ctx = (struct aegis256_context_t *)_ctx;

    memcpy(iv, ctx->static_iv, sizeof(ctx->static_iv));
}

static void aegis256_set_iv(ptls_aead_context_t *_ctx, const void *iv)
{
    struct aegis256_context_t *ctx = (struct aegis256_context_t *)_ctx;

    memcpy(ctx->static_iv, iv, sizeof(ctx->static_iv));
}

static void aegis256_init(ptls_aead_context_t *_ctx, uint64_t seq, const void *aad, size_t aadlen)
{
    struct aegis256_context_t *ctx = (struct aegis256_context_t *)_ctx;
    uint8_t iv[PTLS_AEGIS256_IV_SIZE] = {0};

    ptls_aead__build_iv(ctx->super.algo, iv, ctx->static_iv, seq);

    aegis256_state_init(&ctx->st, (const uint8_t *)aad, aadlen, iv, ctx->key);

    return;
}

static size_t aegis256_encrypt_update(ptls_aead_context_t *_ctx, void *output, const void *input, size_t inlen)
{
    struct aegis256_context_t *ctx = (struct aegis256_context_t *)_ctx;
    size_t written;

    aegis256_state_encrypt_update(&ctx->st, (uint8_t *)output, inlen + aegis256_TAILBYTES_MAX, &written, (const uint8_t *)input, inlen);

    return written;
}

static size_t aegis256_encrypt_final(ptls_aead_context_t *_ctx, void *output)
{
    struct aegis256_context_t *ctx = (struct aegis256_context_t *)_ctx;
    size_t written;

    aegis256_state_encrypt_final(&ctx->st, (uint8_t *)output, aegis256_TAILBYTES_MAX + PTLS_AEGIS256_TAG_SIZE, &written, PTLS_AEGIS256_TAG_SIZE);

    return written;
}

static size_t aegis256_decrypt_oneshot(ptls_aead_context_t *_ctx, void *output, const void *input, size_t inlen, uint64_t seq,
                                       const void *aad, size_t aadlen)
{
    struct aegis256_context_t *ctx = (struct aegis256_context_t *)_ctx;
    uint8_t iv[PTLS_AEGIS256_IV_SIZE];

    if (inlen < PTLS_AEGIS256_TAG_SIZE) {
        return SIZE_MAX;
    }

    ptls_aead__build_iv(ctx->super.algo, iv, ctx->static_iv, seq);

    if (aegis256_decrypt((uint8_t *)output, (const uint8_t *)input, inlen, PTLS_AEGIS256_TAG_SIZE, (const uint8_t *)aad, aadlen, iv,
                         ctx->key) != 0) {
        return SIZE_MAX;
    }

    return inlen - PTLS_AEGIS256_TAG_SIZE;
}

static void aegis256_dispose_crypto(ptls_aead_context_t *_ctx)
{
    struct aegis256_context_t *ctx = (struct aegis256_context_t *)_ctx;

    ptls_clear_memory(ctx->key, sizeof(ctx->key));

    return;
}

static int aegis256_setup_crypto(ptls_aead_context_t *_ctx, int is_enc, const void *key, const void *iv)
{
    struct aegis256_context_t *ctx = (struct aegis256_context_t *)_ctx;

    ctx->super.dispose_crypto = aegis256_dispose_crypto;
    ctx->super.do_get_iv = aegis256_get_iv;
    ctx->super.do_set_iv = aegis256_set_iv;

    if (is_enc) {
        ctx->super.do_encrypt_init = aegis256_init;
        ctx->super.do_encrypt_update = aegis256_encrypt_update;
        ctx->super.do_encrypt_final = aegis256_encrypt_final;
        ctx->super.do_encrypt = ptls_aead__do_encrypt;
        ctx->super.do_encrypt_v = ptls_aead__do_encrypt_v;
        ctx->super.do_decrypt = NULL;
    } else {
        ctx->super.do_encrypt_init = NULL;
        ctx->super.do_encrypt_update = NULL;
        ctx->super.do_encrypt_final = NULL;
        ctx->super.do_encrypt = NULL;
        ctx->super.do_encrypt_v = NULL;
        ctx->super.do_decrypt = aegis256_decrypt_oneshot;
    }

    memcpy(ctx->key, key, sizeof(ctx->key));
    memcpy(ctx->static_iv, iv, sizeof(ctx->static_iv));

    return 0;
}
