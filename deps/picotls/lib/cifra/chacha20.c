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

struct chacha20poly1305_context_t {
    ptls_aead_context_t super;
    uint8_t key[PTLS_CHACHA20_KEY_SIZE];
    uint8_t static_iv[PTLS_CHACHA20POLY1305_IV_SIZE];
    cf_chacha20_ctx chacha;
    cf_poly1305 poly;
    size_t aadlen;
    size_t textlen;
};

static void chacha20poly1305_dispose_crypto(ptls_aead_context_t *_ctx)
{
    struct chacha20poly1305_context_t *ctx = (struct chacha20poly1305_context_t *)_ctx;

    /* clear all memory except super */
    ptls_clear_memory(&ctx->key, sizeof(*ctx) - offsetof(struct chacha20poly1305_context_t, key));
}

static const uint8_t zeros64[64] = {0};

static void chacha20poly1305_encrypt_pad(cf_poly1305 *poly, size_t n)
{
    if (n % 16 != 0)
        cf_poly1305_update(poly, zeros64, 16 - (n % 16));
}

static void chacha20poly1305_finalize(struct chacha20poly1305_context_t *ctx, uint8_t *tag)
{
    uint8_t lenbuf[16];

    chacha20poly1305_encrypt_pad(&ctx->poly, ctx->textlen);

    write64_le(ctx->aadlen, lenbuf);
    write64_le(ctx->textlen, lenbuf + 8);
    cf_poly1305_update(&ctx->poly, lenbuf, sizeof(lenbuf));

    cf_poly1305_finish(&ctx->poly, tag);
}

static void chacha20poly1305_init(ptls_aead_context_t *_ctx, uint64_t seq, const void *aad, size_t aadlen)
{
    struct chacha20poly1305_context_t *ctx = (struct chacha20poly1305_context_t *)_ctx;
    uint8_t tmpbuf[64];

    /* init chacha */
    memset(tmpbuf, 0, 16 - PTLS_CHACHA20POLY1305_IV_SIZE);
    ptls_aead__build_iv(ctx->super.algo, tmpbuf + 16 - PTLS_CHACHA20POLY1305_IV_SIZE, ctx->static_iv, seq);
    cf_chacha20_init_custom(&ctx->chacha, ctx->key, sizeof(ctx->key), tmpbuf, 4);

    /* init poly1305 (by using first 16 bytes of the key stream of the first block) */
    cf_chacha20_cipher(&ctx->chacha, zeros64, tmpbuf, 64);
    cf_poly1305_init(&ctx->poly, tmpbuf, tmpbuf + 16);

    ptls_clear_memory(tmpbuf, sizeof(tmpbuf));

    /* aad */
    if (aadlen != 0) {
        cf_poly1305_update(&ctx->poly, aad, aadlen);
        chacha20poly1305_encrypt_pad(&ctx->poly, aadlen);
    }

    ctx->aadlen = aadlen;
    ctx->textlen = 0;
}

static size_t chacha20poly1305_encrypt_update(ptls_aead_context_t *_ctx, void *output, const void *input, size_t inlen)
{
    struct chacha20poly1305_context_t *ctx = (struct chacha20poly1305_context_t *)_ctx;

    cf_chacha20_cipher(&ctx->chacha, input, output, inlen);
    cf_poly1305_update(&ctx->poly, output, inlen);
    ctx->textlen += inlen;

    return inlen;
}

static size_t chacha20poly1305_encrypt_final(ptls_aead_context_t *_ctx, void *output)
{
    struct chacha20poly1305_context_t *ctx = (struct chacha20poly1305_context_t *)_ctx;

    chacha20poly1305_finalize(ctx, output);

    ptls_clear_memory(&ctx->chacha, sizeof(ctx->chacha));
    return PTLS_CHACHA20POLY1305_TAG_SIZE;
}

static size_t chacha20poly1305_decrypt(ptls_aead_context_t *_ctx, void *output, const void *input, size_t inlen, uint64_t seq,
                                       const void *aad, size_t aadlen)
{
    struct chacha20poly1305_context_t *ctx = (struct chacha20poly1305_context_t *)_ctx;
    uint8_t tag[PTLS_CHACHA20POLY1305_TAG_SIZE];
    size_t ret;

    if (inlen < sizeof(tag))
        return SIZE_MAX;

    chacha20poly1305_init(&ctx->super, seq, aad, aadlen);

    cf_poly1305_update(&ctx->poly, input, inlen - sizeof(tag));
    ctx->textlen = inlen - sizeof(tag);

    chacha20poly1305_finalize(ctx, tag);
    if (mem_eq(tag, (const uint8_t *)input + inlen - sizeof(tag), sizeof(tag))) {
        cf_chacha20_cipher(&ctx->chacha, input, output, inlen - sizeof(tag));
        ret = inlen - sizeof(tag);
    } else {
        ret = SIZE_MAX;
    }

    ptls_clear_memory(tag, sizeof(tag));
    ptls_clear_memory(&ctx->poly, sizeof(ctx->poly));

    return ret;
}

static int aead_chacha20poly1305_setup_crypto(ptls_aead_context_t *_ctx, int is_enc, const void *key, const void *iv)
{
    struct chacha20poly1305_context_t *ctx = (struct chacha20poly1305_context_t *)_ctx;

    ctx->super.dispose_crypto = chacha20poly1305_dispose_crypto;
    if (is_enc) {
        ctx->super.do_encrypt_init = chacha20poly1305_init;
        ctx->super.do_encrypt_update = chacha20poly1305_encrypt_update;
        ctx->super.do_encrypt_final = chacha20poly1305_encrypt_final;
        ctx->super.do_encrypt = ptls_aead__do_encrypt;
        ctx->super.do_decrypt = NULL;
    } else {
        ctx->super.do_encrypt_init = NULL;
        ctx->super.do_encrypt_update = NULL;
        ctx->super.do_encrypt_final = NULL;
        ctx->super.do_decrypt = chacha20poly1305_decrypt;
    }

    memcpy(ctx->key, key, sizeof(ctx->key));
    memcpy(ctx->static_iv, iv, sizeof(ctx->static_iv));
    return 0;
}

ptls_cipher_algorithm_t ptls_minicrypto_chacha20 = {
    "CHACHA20",           PTLS_CHACHA20_KEY_SIZE, 1 /* block size */, PTLS_CHACHA20_IV_SIZE, sizeof(struct chacha20_context_t),
    chacha20_setup_crypto};
ptls_aead_algorithm_t ptls_minicrypto_chacha20poly1305 = {"CHACHA20-POLY1305",
                                                          &ptls_minicrypto_chacha20,
                                                          NULL,
                                                          PTLS_CHACHA20_KEY_SIZE,
                                                          PTLS_CHACHA20POLY1305_IV_SIZE,
                                                          PTLS_CHACHA20POLY1305_TAG_SIZE,
                                                          sizeof(struct chacha20poly1305_context_t),
                                                          aead_chacha20poly1305_setup_crypto};
ptls_cipher_suite_t ptls_minicrypto_chacha20poly1305sha256 = {PTLS_CIPHER_SUITE_CHACHA20_POLY1305_SHA256,
                                                              &ptls_minicrypto_chacha20poly1305, &ptls_minicrypto_sha256};
