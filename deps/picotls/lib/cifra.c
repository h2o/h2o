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
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700 /* required for glibc to use getaddrinfo, etc. */
#endif
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "aes.h"
#include "drbg.h"
#include "curve25519.h"
#include "modes.h"
#include "sha2.h"
#include "picotls.h"
#include "picotls/minicrypto.h"

static void read_entropy(uint8_t *entropy, size_t size)
{
    int fd;

    if ((fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC)) == -1) {
        if ((fd = open("/dev/random", O_RDONLY | O_CLOEXEC)) == -1) {
            perror("ptls_minicrypto_random_bytes: could not open neither /dev/random or /dev/urandom");
            abort();
        }
    }

    while (size != 0) {
        ssize_t rret;
        while ((rret = read(fd, entropy, size)) == -1 && errno == EINTR)
            ;
        if (rret < 0) {
            perror("ptls_minicrypto_random_bytes");
            abort();
        }
        entropy += rret;
        size -= rret;
    }

    close(fd);
}

void ptls_minicrypto_random_bytes(void *buf, size_t len)
{
    static __thread cf_hash_drbg_sha256 ctx;

    if (cf_hash_drbg_sha256_needs_reseed(&ctx)) {
        uint8_t entropy[256];
        read_entropy(entropy, sizeof(entropy));
        cf_hash_drbg_sha256_init(&ctx, entropy, sizeof(entropy) / 2, entropy + sizeof(entropy) / 2, sizeof(entropy) / 2, "ptls", 4);
    }
    cf_hash_drbg_sha256_gen(&ctx, buf, len);
}

#define X25519_KEY_SIZE 32

struct st_x25519_key_exchange_t {
    ptls_key_exchange_context_t super;
    uint8_t priv[X25519_KEY_SIZE];
    uint8_t pub[X25519_KEY_SIZE];
};

static void x25519_create_keypair(uint8_t *priv, uint8_t *pub)
{
    ptls_minicrypto_random_bytes(priv, X25519_KEY_SIZE);
    cf_curve25519_mul_base(pub, priv);
}

static int x25519_derive_secret(ptls_iovec_t *secret, const uint8_t *clientpriv, const uint8_t *clientpub,
                                const uint8_t *serverpriv, const uint8_t *serverpub)
{
    if ((secret->base = malloc(X25519_KEY_SIZE)) == NULL)
        return PTLS_ERROR_NO_MEMORY;

    cf_curve25519_mul(secret->base, clientpriv != NULL ? clientpriv : serverpriv, clientpriv != NULL ? serverpub : clientpub);
    secret->len = X25519_KEY_SIZE;
    return 0;
}

static int x25519_on_exchange(ptls_key_exchange_context_t **_ctx, ptls_iovec_t *secret, ptls_iovec_t peerkey)
{
    struct st_x25519_key_exchange_t *ctx = (struct st_x25519_key_exchange_t *)*_ctx;
    int ret;

    *_ctx = NULL;

    if (secret == NULL) {
        ret = 0;
        goto Exit;
    }

    if (peerkey.len != X25519_KEY_SIZE) {
        ret = PTLS_ALERT_DECRYPT_ERROR;
        goto Exit;
    }
    ret = x25519_derive_secret(secret, ctx->priv, ctx->pub, NULL, peerkey.base);

Exit:
    ptls_clear_memory(ctx->priv, sizeof(ctx->priv));
    free(ctx);
    return ret;
}

static int x25519_create_key_exchange(ptls_key_exchange_context_t **_ctx, ptls_iovec_t *pubkey)
{
    struct st_x25519_key_exchange_t *ctx;

    if ((ctx = (struct st_x25519_key_exchange_t *)malloc(sizeof(*ctx))) == NULL)
        return PTLS_ERROR_NO_MEMORY;
    ctx->super = (ptls_key_exchange_context_t){x25519_on_exchange};
    x25519_create_keypair(ctx->priv, ctx->pub);

    *_ctx = &ctx->super;
    *pubkey = ptls_iovec_init(ctx->pub, sizeof(ctx->pub));
    return 0;
}

static int x25519_key_exchange(ptls_iovec_t *pubkey, ptls_iovec_t *secret, ptls_iovec_t peerkey)
{
    uint8_t priv[X25519_KEY_SIZE], *pub = NULL;
    int ret;

    if (peerkey.len != X25519_KEY_SIZE) {
        ret = PTLS_ALERT_DECRYPT_ERROR;
        goto Exit;
    }
    if ((pub = malloc(X25519_KEY_SIZE)) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }

    x25519_create_keypair(priv, pub);
    if ((ret = x25519_derive_secret(secret, NULL, peerkey.base, priv, pub)) != 0)
        goto Exit;

    *pubkey = ptls_iovec_init(pub, X25519_KEY_SIZE);
    ret = 0;

Exit:
    ptls_clear_memory(priv, sizeof(priv));
    if (pub != NULL && ret != 0)
        ptls_clear_memory(pub, X25519_KEY_SIZE);
    return ret;
}

#define AES128GCM_KEY_SIZE 16
#define AES128GCM_IV_SIZE 12
#define AES128GCM_TAG_SIZE 16

struct aes128gcm_context_t {
    ptls_aead_context_t super;
    cf_aes_context ctx;
};

static void aes128gcm_dispose_crypto(ptls_aead_context_t *_ctx)
{
    struct aes128gcm_context_t *ctx = (struct aes128gcm_context_t *)_ctx;
    ptls_clear_memory(&ctx->ctx, sizeof(ctx->ctx));
}

static int aes128gcm_encrypt(ptls_aead_context_t *_ctx, void *_output, size_t *outlen, const void *input, size_t inlen,
                             const void *iv, uint8_t enc_content_type)
{
    struct aes128gcm_context_t *ctx = (struct aes128gcm_context_t *)_ctx;
    uint8_t *output = (uint8_t *)_output;
    cf_gcm_ctx gcm;

    cf_gcm_encrypt_init(&cf_aes, &ctx->ctx, &gcm, NULL, 0, iv, AES128GCM_IV_SIZE);
    cf_gcm_encrypt_update(&gcm, input, inlen, output);
    output += inlen;
    cf_gcm_encrypt_update(&gcm, &enc_content_type, 1, output);
    output += 1;
    cf_gcm_encrypt_final(&gcm, output, AES128GCM_TAG_SIZE);
    output += AES128GCM_TAG_SIZE;

    *outlen = output - (uint8_t *)_output;
    return 0;
}

static int aes128gcm_decrypt(ptls_aead_context_t *_ctx, void *output, size_t *outlen, const void *input, size_t inlen,
                             const void *iv, uint8_t unused)
{
    struct aes128gcm_context_t *ctx = (struct aes128gcm_context_t *)_ctx;

    if (inlen < AES128GCM_TAG_SIZE)
        return PTLS_ALERT_BAD_RECORD_MAC;
    size_t tag_offset = inlen - AES128GCM_TAG_SIZE;

    if (cf_gcm_decrypt(&cf_aes, &ctx->ctx, input, tag_offset, NULL, 0, iv, AES128GCM_IV_SIZE, (uint8_t *)input + tag_offset,
                       AES128GCM_TAG_SIZE, output) != 0)
        return PTLS_ALERT_BAD_RECORD_MAC;

    *outlen = tag_offset;
    return 0;
}

static int aead_aes128gcm_setup_crypto(ptls_aead_context_t *_ctx, int is_enc, const void *key)
{
    struct aes128gcm_context_t *ctx = (struct aes128gcm_context_t *)_ctx;

    ctx->super.dispose_crypto = aes128gcm_dispose_crypto;
    ctx->super.do_transform = is_enc ? aes128gcm_encrypt : aes128gcm_decrypt;

    cf_aes_init(&ctx->ctx, key, AES128GCM_KEY_SIZE);
    return 0;
}

struct sha256_context_t {
    ptls_hash_context_t super;
    cf_sha256_context ctx;
};

static void sha256_update(ptls_hash_context_t *_ctx, const void *src, size_t len)
{
    struct sha256_context_t *ctx = (struct sha256_context_t *)_ctx;

    cf_sha256_update(&ctx->ctx, src, len);
}

static void sha256_final(ptls_hash_context_t *_ctx, void *md, ptls_hash_final_mode_t mode)
{
    struct sha256_context_t *ctx = (struct sha256_context_t *)_ctx;

    if (mode == PTLS_HASH_FINAL_MODE_SNAPSHOT) {
        cf_sha256_context copy = ctx->ctx;
        cf_sha256_digest_final(&copy, md);
        ptls_clear_memory(&copy, sizeof(copy));
        return;
    }

    if (md != NULL)
        cf_sha256_digest_final(&ctx->ctx, md);

    switch (mode) {
    case PTLS_HASH_FINAL_MODE_FREE:
        ptls_clear_memory(&ctx->ctx, sizeof(ctx->ctx));
        free(ctx);
        break;
    case PTLS_HASH_FINAL_MODE_RESET:
        cf_sha256_init(&ctx->ctx);
        break;
    default:
        assert(!"FIXME");
        break;
    }
}

static ptls_hash_context_t *sha256_clone(ptls_hash_context_t *_src)
{
    struct sha256_context_t *dst, *src = (struct sha256_context_t *)_src;

    if ((dst = malloc(sizeof(*dst))) == NULL)
        return NULL;
    *dst = *src;
    return &dst->super;
}

static ptls_hash_context_t *sha256_create(void)
{
    struct sha256_context_t *ctx;

    if ((ctx = malloc(sizeof(*ctx))) == NULL)
        return NULL;
    ctx->super = (ptls_hash_context_t){sha256_update, sha256_final, sha256_clone};
    cf_sha256_init(&ctx->ctx);
    return &ctx->super;
}

ptls_key_exchange_algorithm_t ptls_minicrypto_x25519 = {PTLS_GROUP_X25519, x25519_create_key_exchange, x25519_key_exchange};
ptls_aead_algorithm_t ptls_minicrypto_aes128gcm = {"AES128-GCM",
                                                   AES128GCM_KEY_SIZE,
                                                   AES128GCM_IV_SIZE,
                                                   AES128GCM_TAG_SIZE,
                                                   sizeof(struct aes128gcm_context_t),
                                                   aead_aes128gcm_setup_crypto};
ptls_hash_algorithm_t ptls_minicrypto_sha256 = {64, 32, sha256_create};
ptls_cipher_suite_t ptls_minicrypto_aes128gcmsha256 = {PTLS_CIPHER_SUITE_AES_128_GCM_SHA256, &ptls_minicrypto_aes128gcm,
                                                       &ptls_minicrypto_sha256};
ptls_cipher_suite_t *ptls_minicrypto_cipher_suites[] = {&ptls_minicrypto_aes128gcmsha256, NULL};
