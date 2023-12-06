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
#include "bitops.h"
#include "../deps/cifra/src/ext/handy.h"
#include "poly1305.h"
#include "salsa20.h"
#include "sha2.h"
#include "picotls.h"
#include "picotls/minicrypto.h"
#include "../chacha20poly1305.h"

struct chacha20_context_t {
    ptls_cipher_context_t super;
    cf_chacha20_ctx chacha;
    uint8_t key[PTLS_CHACHA20_KEY_SIZE];
};

static void chacha20_dispose(ptls_cipher_context_t *_ctx)
{
    struct chacha20_context_t *ctx = (struct chacha20_context_t *)_ctx;
    ptls_clear_memory(ctx, sizeof(*ctx));
}

static void chacha20_init(ptls_cipher_context_t *_ctx, const void *iv)
{
    struct chacha20_context_t *ctx = (struct chacha20_context_t *)_ctx;
    ctx->chacha.nblock = 0;
    ctx->chacha.ncounter = 0;
    memcpy(ctx->chacha.nonce, iv, sizeof ctx->chacha.nonce);
}

static void chacha20_transform(ptls_cipher_context_t *_ctx, void *output, const void *input, size_t len)
{
    struct chacha20_context_t *ctx = (struct chacha20_context_t *)_ctx;
    cf_chacha20_cipher(&ctx->chacha, input, output, len);
}

static int chacha20_setup_crypto(ptls_cipher_context_t *_ctx, int is_enc, const void *key)
{
    struct chacha20_context_t *ctx = (struct chacha20_context_t *)_ctx;
    ctx->super.do_dispose = chacha20_dispose;
    ctx->super.do_init = chacha20_init;
    ctx->super.do_transform = chacha20_transform;
    cf_chacha20_init(&ctx->chacha, key, PTLS_CHACHA20_KEY_SIZE, (const uint8_t *)"01234567" /* not used */);
    return 0;
}

struct cifra_chacha20poly1305_context_t {
    struct chacha20poly1305_context_t super;
    cf_poly1305 poly;
};

static void cifra_poly1305_init(struct chacha20poly1305_context_t *_ctx, const void *rs)
{
    struct cifra_chacha20poly1305_context_t *ctx = (struct cifra_chacha20poly1305_context_t *)_ctx;
    cf_poly1305_init(&ctx->poly, rs, (const uint8_t *)rs + 16);
}

static void cifra_poly1305_update(struct chacha20poly1305_context_t *_ctx, const void *input, size_t len)
{
    struct cifra_chacha20poly1305_context_t *ctx = (struct cifra_chacha20poly1305_context_t *)_ctx;
    cf_poly1305_update(&ctx->poly, input, len);
}

static void cifra_poly1305_finish(struct chacha20poly1305_context_t *_ctx, void *tag)
{
    struct cifra_chacha20poly1305_context_t *ctx = (struct cifra_chacha20poly1305_context_t *)_ctx;
    cf_poly1305_finish(&ctx->poly, tag);
}

static int cifra_chacha20poly1305_setup_crypto(ptls_aead_context_t *ctx, int is_enc, const void *key, const void *iv)
{
    return chacha20poly1305_setup_crypto(ctx, is_enc, key, iv, &ptls_minicrypto_chacha20, cifra_poly1305_init,
                                         cifra_poly1305_update, cifra_poly1305_finish);
}

ptls_cipher_algorithm_t ptls_minicrypto_chacha20 = {
    "CHACHA20",           PTLS_CHACHA20_KEY_SIZE, 1 /* block size */, PTLS_CHACHA20_IV_SIZE, sizeof(struct chacha20_context_t),
    chacha20_setup_crypto};
ptls_aead_algorithm_t ptls_minicrypto_chacha20poly1305 = {
    "CHACHA20-POLY1305",
    PTLS_CHACHA20POLY1305_CONFIDENTIALITY_LIMIT,
    PTLS_CHACHA20POLY1305_INTEGRITY_LIMIT,
    &ptls_minicrypto_chacha20,
    NULL,
    PTLS_CHACHA20_KEY_SIZE,
    PTLS_CHACHA20POLY1305_IV_SIZE,
    PTLS_CHACHA20POLY1305_TAG_SIZE,
    {PTLS_TLS12_CHACHAPOLY_FIXED_IV_SIZE, PTLS_TLS12_CHACHAPOLY_RECORD_IV_SIZE},
    0,
    0,
    sizeof(struct cifra_chacha20poly1305_context_t),
    cifra_chacha20poly1305_setup_crypto};
ptls_cipher_suite_t ptls_minicrypto_chacha20poly1305sha256 = {.id = PTLS_CIPHER_SUITE_CHACHA20_POLY1305_SHA256,
                                                              .name = PTLS_CIPHER_SUITE_NAME_CHACHA20_POLY1305_SHA256,
                                                              .aead = &ptls_minicrypto_chacha20poly1305,
                                                              .hash = &ptls_minicrypto_sha256};
