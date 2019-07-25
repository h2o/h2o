/*
 * Copyright (c) 2016 Christian Huitema <huitema@huitema.net>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#ifdef _WINDOWS
#include "wincompat.h"
#else
#include <unistd.h>
#endif
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include "picotls.h"
#include "picotls/minicrypto.h"
#include "picotls/ffx.h"

static void ffx_dispose(ptls_cipher_context_t *_ctx);
static void ffx_encrypt(ptls_cipher_context_t *_ctx, void *output, const void *input, size_t len);
static void ffx_init(struct st_ptls_cipher_context_t *ctx, const void *iv);

int ptls_ffx_setup_crypto(ptls_cipher_context_t *_ctx, ptls_cipher_algorithm_t *algo, int is_enc, int nb_rounds, size_t bit_length,
                          const void *key)
{
    int ret = 0;
    ptls_ffx_context_t *ctx = (ptls_ffx_context_t *)_ctx;
    ptls_cipher_context_t *enc_ctx = NULL;
    size_t len = (bit_length + 7) / 8;
    uint8_t last_byte_mask[8] = {0xFF, 0xFE, 0xFC, 0xF8, 0xF0, 0xE0, 0xC0, 0x80};

    assert(len <= 32 && len >= 2);
    assert(ctx->super.do_dispose == NULL);
    assert(ctx->super.do_init == NULL);
    assert(ctx->super.do_transform == NULL);
    assert(ctx->super.algo == NULL || algo->key_size == ctx->super.algo->key_size);
    assert(ctx->super.algo == NULL || algo->iv_size == ctx->super.algo->iv_size);
    assert(ctx->super.algo == NULL || ctx->super.algo->block_size == len);
    assert(algo->iv_size == 16);

    if (len <= 32 && len >= 2) {
        /* len must be lower than 32 */
        enc_ctx = ptls_cipher_new(algo, 1, key);

        if (enc_ctx == NULL) {
            ret = PTLS_ERROR_LIBRARY;
        }
    } else {
        ret = PTLS_ERROR_LIBRARY;
    }

    if (ret == 0) {
        ctx->enc_ctx = enc_ctx;
        ctx->nb_rounds = nb_rounds;
        ctx->is_enc = is_enc;
        ctx->byte_length = len;
        ctx->nb_left = (int)len / 2;
        ctx->nb_right = (int)len - ctx->nb_left;
        ctx->mask_last_byte = last_byte_mask[bit_length % 8];
        ptls_clear_memory(ctx->tweaks, sizeof(ctx->tweaks));

        ctx->super.do_dispose = ffx_dispose;
        ctx->super.do_init = ffx_init;
        ctx->super.do_transform = ffx_encrypt;
    } else {
        ffx_dispose(_ctx);
    }

    return ret;
}

static void ffx_dispose(ptls_cipher_context_t *_ctx)
{
    ptls_ffx_context_t *ctx = (ptls_ffx_context_t *)_ctx;

    assert(ctx->super.do_dispose == ffx_dispose);

    if (ctx->enc_ctx != NULL) {
        ptls_cipher_free(ctx->enc_ctx);
    }

    ctx->enc_ctx = NULL;
    ctx->nb_rounds = 0;
    ctx->byte_length = 0;
    ctx->nb_left = 0;
    ctx->nb_right = 0;
    ctx->mask_last_byte = 0;
    ctx->is_enc = 0;

    ctx->super.do_dispose = NULL;
    ctx->super.do_init = NULL;
    ctx->super.do_transform = NULL;
}

ptls_cipher_context_t *ptls_ffx_new(ptls_cipher_algorithm_t *algo, int is_enc, int nb_rounds, size_t bit_length, const void *key)
{
    ptls_cipher_context_t *ctx = (ptls_cipher_context_t *)malloc(sizeof(ptls_ffx_context_t));

    if (ctx != NULL) {
        memset(ctx, 0, sizeof(ptls_ffx_context_t));
        if (ptls_ffx_setup_crypto(ctx, algo, is_enc, nb_rounds, bit_length, key) != 0) {
            free(ctx);
            ctx = NULL;
        }
    }

    return ctx;
}

static void ptls_ffx_one_pass(ptls_cipher_context_t *enc_ctx, uint8_t *source, size_t source_size, uint8_t *target,
                              size_t target_size, uint8_t mask_last_byte, uint8_t *confusion, uint8_t *iv, uint8_t *tweaks,
                              uint8_t round, uint8_t nb_rounds)
{
    static const uint8_t zeros[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

    memcpy(iv, tweaks, 16);
    iv[round & 15] ^= nb_rounds;
    for (size_t i = 0; i < source_size; i++) {
        iv[i] ^= source[i];
    }
    ptls_cipher_init(enc_ctx, iv);
    ptls_cipher_encrypt(enc_ctx, confusion, zeros, 16);
    for (size_t j = 0; j < target_size - 1; j++) {
        target[j] ^= confusion[j];
    }
    target[target_size - 1] ^= (confusion[target_size - 1] & mask_last_byte);
}

static void ffx_encrypt(ptls_cipher_context_t *_ctx, void *output, const void *input, size_t len)
{
    ptls_ffx_context_t *ctx = (ptls_ffx_context_t *)_ctx;
    uint8_t left[16], right[16], confusion[32], iv[16];
    uint8_t last_byte;

    assert(ctx->super.do_transform == ffx_encrypt);

    /* len must match context definition */
    assert(len == ctx->byte_length);
    if (len != ctx->byte_length) {
        memset(output, 0, len); /* so that we do not leak anything in production mode */
        return;
    }

    /* Split the input in two halves */
    memcpy(left, input, ctx->nb_left);
    memcpy(right, ((uint8_t *)input) + ctx->nb_left, ctx->nb_right);
    memset(left + ctx->nb_left, 0, 16 - ctx->nb_left);
    memset(right + ctx->nb_right, 0, 16 - ctx->nb_right);
    last_byte = right[ctx->nb_right - 1];
    right[ctx->nb_right - 1] &= ctx->mask_last_byte;

    if (ctx->is_enc) {
        /* Feistel construct, using the specified algorithm as S-Box */
        for (int i = 0; i < ctx->nb_rounds; i += 2) {
            /* Each pass encrypts a zero field with a cipher using one
             * half of the message as IV. This construct lets us use
             * either AES or chacha 20 */
            ptls_ffx_one_pass(ctx->enc_ctx, right, ctx->nb_right, left, ctx->nb_left, 0xFF, confusion, iv, ctx->tweaks, i,
                              ctx->nb_rounds);
            ptls_ffx_one_pass(ctx->enc_ctx, left, ctx->nb_left, right, ctx->nb_right, ctx->mask_last_byte, confusion, iv,
                              ctx->tweaks, i + 1, ctx->nb_rounds);
        }
    } else {
        /* Feistel construct, using the specified algorithm as S-Box,
         * in the opposite order of the encryption */

        for (int i = 0; i < ctx->nb_rounds; i += 2) {
            /* Each pass encrypts a zero field with a cipher using one
             * half of the message as IV. This construct lets us use
             * either AES or chacha 20 */

            ptls_ffx_one_pass(ctx->enc_ctx, left, ctx->nb_left, right, ctx->nb_right, ctx->mask_last_byte, confusion, iv,
                              ctx->tweaks, ctx->nb_rounds - 1 - i, ctx->nb_rounds);
            ptls_ffx_one_pass(ctx->enc_ctx, right, ctx->nb_right, left, ctx->nb_left, 0xFF, confusion, iv, ctx->tweaks,
                              ctx->nb_rounds - 2 - i, ctx->nb_rounds);
        }
    }
    /* After enough passes, we have a very strong length preserving
     * encryption, only that many times slower than the underlying
     * algorithm. We copy the result to the output */
    memcpy(output, left, ctx->nb_left);

    right[ctx->nb_right - 1] &= ctx->mask_last_byte;
    right[ctx->nb_right - 1] |= (last_byte & ~ctx->mask_last_byte);

    memcpy(((uint8_t *)output) + ctx->nb_left, right, ctx->nb_right);

    ptls_clear_memory(left, sizeof(left));
    ptls_clear_memory(right, sizeof(right));
    ptls_clear_memory(confusion, sizeof(confusion));
}

static void ffx_init(struct st_ptls_cipher_context_t *_ctx, const void *iv)
{
    ptls_ffx_context_t *ctx = (ptls_ffx_context_t *)_ctx;
    assert(ctx->super.do_init == ffx_init);
    memcpy(ctx->tweaks, iv, 16);
}
