/*
 * Copyright (c) 2016-2023 DeNA Co., Ltd., Kazuho Oku, Lars Eggert, Christian
                           Huitema, Fastly
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
#include <stddef.h>
#include "picotls.h"

#define CHACHA20POLY1305_BLOCKSIZE 64

struct chacha20poly1305_context_t {
    ptls_aead_context_t super;
    ptls_cipher_context_t *chacha;
    uint8_t static_iv[PTLS_CHACHA20POLY1305_IV_SIZE];
    size_t aadlen;
    size_t textlen;
    void (*poly1305_init)(struct chacha20poly1305_context_t *, const void *);
    void (*poly1305_update)(struct chacha20poly1305_context_t *, const void *, size_t);
    void (*poly1305_finish)(struct chacha20poly1305_context_t *, void *);
};

static void chacha20poly1305_write_u64(uint8_t *buf, uint64_t v)
{
    *buf++ = v & 0xff;
    *buf++ = (v >> 8) & 0xff;
    *buf++ = (v >> 16) & 0xff;
    *buf++ = (v >> 24) & 0xff;
    *buf++ = (v >> 32) & 0xff;
    *buf++ = (v >> 40) & 0xff;
    *buf++ = (v >> 48) & 0xff;
    *buf = (v >> 56) & 0xff;
}

static void chacha20poly1305_encrypt_pad(struct chacha20poly1305_context_t *ctx, size_t n)
{
    static const uint8_t zeros[16] = {0};
    if (n % 16 != 0)
        ctx->poly1305_update(ctx, zeros, 16 - (n % 16));
}

static void chacha20poly1305_finalize(struct chacha20poly1305_context_t *ctx, uint8_t *tag)
{
    uint8_t lenbuf[16];

    chacha20poly1305_encrypt_pad(ctx, ctx->textlen);

    chacha20poly1305_write_u64(lenbuf, ctx->aadlen);
    chacha20poly1305_write_u64(lenbuf + 8, ctx->textlen);
    ctx->poly1305_update(ctx, lenbuf, sizeof(lenbuf));

    ctx->poly1305_finish(ctx, tag);
}

static void chacha20poly1305_dispose_crypto(ptls_aead_context_t *_ctx)
{
    struct chacha20poly1305_context_t *ctx = (struct chacha20poly1305_context_t *)_ctx;
    ptls_cipher_free(ctx->chacha);
}

static void chacha20poly1305_init(ptls_aead_context_t *_ctx, uint64_t seq, const void *aad, size_t aadlen)
{
    struct chacha20poly1305_context_t *ctx = (struct chacha20poly1305_context_t *)_ctx;
    uint8_t tmpbuf[CHACHA20POLY1305_BLOCKSIZE];

    /* init chacha */
    memset(tmpbuf, 0, 16 - PTLS_CHACHA20POLY1305_IV_SIZE);
    ptls_aead__build_iv(ctx->super.algo, tmpbuf + 16 - PTLS_CHACHA20POLY1305_IV_SIZE, ctx->static_iv, seq);
    ptls_cipher_init(ctx->chacha, tmpbuf);

    /* init poly1305 */
    memset(tmpbuf, 0, sizeof(tmpbuf));
    ptls_cipher_encrypt(ctx->chacha, tmpbuf, tmpbuf, CHACHA20POLY1305_BLOCKSIZE);
    ctx->poly1305_init(ctx, tmpbuf);

    ptls_clear_memory(tmpbuf, sizeof(tmpbuf));

    /* aad */
    if (aadlen != 0) {
        ctx->poly1305_update(ctx, aad, aadlen);
        chacha20poly1305_encrypt_pad(ctx, aadlen);
    }

    ctx->aadlen = aadlen;
    ctx->textlen = 0;
}

static size_t chacha20poly1305_encrypt_update(ptls_aead_context_t *_ctx, void *output, const void *input, size_t inlen)
{
    struct chacha20poly1305_context_t *ctx = (struct chacha20poly1305_context_t *)_ctx;

    ptls_cipher_encrypt(ctx->chacha, output, input, inlen);
    ctx->poly1305_update(ctx, output, inlen);
    ctx->textlen += inlen;

    return inlen;
}

static size_t chacha20poly1305_encrypt_final(ptls_aead_context_t *_ctx, void *output)
{
    struct chacha20poly1305_context_t *ctx = (struct chacha20poly1305_context_t *)_ctx;

    chacha20poly1305_finalize(ctx, output);

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

    ctx->poly1305_update(ctx, input, inlen - sizeof(tag));
    ctx->textlen = inlen - sizeof(tag);

    chacha20poly1305_finalize(ctx, tag);
    if (ptls_mem_equal(tag, (const uint8_t *)input + inlen - sizeof(tag), sizeof(tag))) {
        ptls_cipher_encrypt(ctx->chacha, output, input, inlen - sizeof(tag));
        ret = inlen - sizeof(tag);
    } else {
        ret = SIZE_MAX;
    }

    ptls_clear_memory(tag, sizeof(tag));

    return ret;
}

static void chacha20poly1305_get_iv(ptls_aead_context_t *_ctx, void *iv)
{
    struct chacha20poly1305_context_t *ctx = (struct chacha20poly1305_context_t *)_ctx;

    memcpy(iv, ctx->static_iv, sizeof(ctx->static_iv));
}

static void chacha20poly1305_set_iv(ptls_aead_context_t *_ctx, const void *iv)
{
    struct chacha20poly1305_context_t *ctx = (struct chacha20poly1305_context_t *)_ctx;

    memcpy(ctx->static_iv, iv, sizeof(ctx->static_iv));
}

static int chacha20poly1305_setup_crypto(ptls_aead_context_t *_ctx, int is_enc, const void *key, const void *iv,
                                         ptls_cipher_algorithm_t *chacha,
                                         void (*poly1305_init)(struct chacha20poly1305_context_t *, const void *),
                                         void (*poly1305_update)(struct chacha20poly1305_context_t *, const void *, size_t),
                                         void (*poly1305_finish)(struct chacha20poly1305_context_t *, void *))
{
    struct chacha20poly1305_context_t *ctx = (struct chacha20poly1305_context_t *)_ctx;

    ctx->super.dispose_crypto = chacha20poly1305_dispose_crypto;
    ctx->super.do_get_iv = chacha20poly1305_get_iv;
    ctx->super.do_set_iv = chacha20poly1305_set_iv;
    if (is_enc) {
        ctx->super.do_encrypt_init = chacha20poly1305_init;
        ctx->super.do_encrypt_update = chacha20poly1305_encrypt_update;
        ctx->super.do_encrypt_final = chacha20poly1305_encrypt_final;
        ctx->super.do_encrypt = ptls_aead__do_encrypt;
        ctx->super.do_encrypt_v = ptls_aead__do_encrypt_v;
        ctx->super.do_decrypt = NULL;
    } else {
        ctx->super.do_encrypt_init = NULL;
        ctx->super.do_encrypt_update = NULL;
        ctx->super.do_encrypt_final = NULL;
        ctx->super.do_encrypt = NULL;
        ctx->super.do_encrypt_v = NULL;
        ctx->super.do_decrypt = chacha20poly1305_decrypt;
    }

    if ((ctx->chacha = ptls_cipher_new(chacha, is_enc, key)) == NULL)
        return PTLS_ERROR_LIBRARY;

    memcpy(ctx->static_iv, iv, sizeof(ctx->static_iv));
    ctx->poly1305_init = poly1305_init;
    ctx->poly1305_update = poly1305_update;
    ctx->poly1305_finish = poly1305_finish;

    return 0;
}
