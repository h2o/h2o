/*
 * Copyright (c) 2023, Christian Huitema
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

#ifdef _WINDOWS
#include "wincompat.h"
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <psa/crypto.h>
#include <mbedtls/chacha20.h>
#include <mbedtls/ecdh.h>
#include "picotls.h"

#define PSA_FUNC_FAILED(fn, ret)                                                                                                   \
    do {                                                                                                                           \
        fprintf(stderr, "in %s at line %d, " PTLS_TO_STR(fn) " failed (%d)\n", __FUNCTION__, __LINE__, (int)ret);                  \
        abort();                                                                                                                   \
    } while (0)

#define CALL_WITH_CHECK(fn, ...)                                                                                                   \
    do {                                                                                                                           \
        psa_status_t ret;                                                                                                          \
        if ((ret = fn(__VA_ARGS__)) != PSA_SUCCESS)                                                                                \
            PSA_FUNC_FAILED(fn, ret);                                                                                              \
    } while (0)

void ptls_mbedtls_random_bytes(void *buf, size_t len)
{
    CALL_WITH_CHECK(psa_generate_random, buf, len);
}

#define DEFINE_HASH(name, name_upcase, psa_alg)                                                                                    \
    static void name##_do_init(psa_hash_operation_t *op)                                                                           \
    {                                                                                                                              \
        *op = psa_hash_operation_init();                                                                                           \
        CALL_WITH_CHECK(psa_hash_setup, op, psa_alg);                                                                              \
    }                                                                                                                              \
    static void name##_do_update(psa_hash_operation_t *op, const void *src, size_t len)                                            \
    {                                                                                                                              \
        CALL_WITH_CHECK(psa_hash_update, op, src, len);                                                                            \
    }                                                                                                                              \
    static void name##_do_final(psa_hash_operation_t *op, void *md)                                                                \
    {                                                                                                                              \
        size_t unused;                                                                                                             \
        CALL_WITH_CHECK(psa_hash_finish, op, md, PTLS_##name_upcase##_DIGEST_SIZE, &unused);                                       \
    }                                                                                                                              \
    static void name##_do_clone(psa_hash_operation_t *dst, psa_hash_operation_t *src, size_t unused)                               \
    {                                                                                                                              \
        CALL_WITH_CHECK(psa_hash_clone, src, dst);                                                                                 \
    }                                                                                                                              \
    ptls_define_hash6(name, psa_hash_operation_t, name##_do_init, name##_do_update, name##_do_final, name##_do_clone);             \
    ptls_hash_algorithm_t ptls_mbedtls_##name = {PTLS_TO_STR(name), PTLS_##name_upcase##_BLOCK_SIZE,                               \
                                                 PTLS_##name_upcase##_DIGEST_SIZE, name##_create, PTLS_ZERO_DIGEST_##name_upcase};
DEFINE_HASH(sha256, SHA256, PSA_ALG_SHA_256);
DEFINE_HASH(sha512, SHA512, PSA_ALG_SHA_512);
#if defined(MBEDTLS_SHA384_C)
DEFINE_HASH(sha384, SHA384, PSA_ALG_SHA_384);
#endif

/**
 * Generic implementation of a cipher using the PSA API
 */
struct st_ptls_mbedtls_cipher_context_t {
    ptls_cipher_context_t super;
    psa_algorithm_t alg;
    unsigned is_enc : 1;
    unsigned is_op_in_progress : 1;
    mbedtls_svc_key_id_t key;
    psa_cipher_operation_t op;
};

static void cipher_init(ptls_cipher_context_t *_ctx, const void *iv)
{
    struct st_ptls_mbedtls_cipher_context_t *ctx = (struct st_ptls_mbedtls_cipher_context_t *)_ctx;

    if (ctx->is_op_in_progress) {
        psa_cipher_abort(&ctx->op);
        ctx->is_op_in_progress = 0;
    }

    ctx->op = psa_cipher_operation_init();
    if (ctx->is_enc) {
        CALL_WITH_CHECK(psa_cipher_encrypt_setup, &ctx->op, ctx->key, ctx->alg);
    } else {
        CALL_WITH_CHECK(psa_cipher_decrypt_setup, &ctx->op, ctx->key, ctx->alg);
    }
    ctx->is_op_in_progress = 1;
    if (ctx->super.algo->iv_size > 0)
        CALL_WITH_CHECK(psa_cipher_set_iv, &ctx->op, iv, ctx->super.algo->iv_size);
}

static void cipher_transform(ptls_cipher_context_t *_ctx, void *output, const void *input, size_t len)
{
    struct st_ptls_mbedtls_cipher_context_t *ctx = (struct st_ptls_mbedtls_cipher_context_t *)_ctx;
    size_t unused = 0;

    CALL_WITH_CHECK(psa_cipher_update, &ctx->op, input, len, output, len, &unused);
}

static void cipher_dispose(ptls_cipher_context_t *_ctx)
{
    struct st_ptls_mbedtls_cipher_context_t *ctx = (struct st_ptls_mbedtls_cipher_context_t *)_ctx;

    if (ctx->is_op_in_progress)
        psa_cipher_abort(&ctx->op);
    psa_destroy_key(ctx->key);
}

static int cipher_setup(ptls_cipher_context_t *_ctx, int is_enc, const void *key_bytes, psa_algorithm_t alg,
                        psa_key_type_t key_type)
{
    struct st_ptls_mbedtls_cipher_context_t *ctx = (struct st_ptls_mbedtls_cipher_context_t *)_ctx;

    { /* import key or fail immediately */
        psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
        psa_set_key_usage_flags(&attributes, is_enc ? PSA_KEY_USAGE_ENCRYPT : PSA_KEY_USAGE_DECRYPT);
        psa_set_key_algorithm(&attributes, alg);
        psa_set_key_type(&attributes, key_type);
        psa_set_key_bits(&attributes, ctx->super.algo->key_size * 8);
        if (psa_import_key(&attributes, key_bytes, ctx->super.algo->key_size, &ctx->key) != PSA_SUCCESS)
            return PTLS_ERROR_LIBRARY;
    }

    /* init the rest that are guaranteed to succeed */
    ctx->super.do_dispose = cipher_dispose;
    ctx->super.do_init = cipher_init;
    ctx->super.do_transform = cipher_transform;
    ctx->alg = alg;
    ctx->is_enc = is_enc;
    ctx->is_op_in_progress = 0;
    ctx->op = psa_cipher_operation_init();

    return 0;
}

static int ecb_setup(ptls_cipher_context_t *ctx, int is_enc, const void *key_bytes, psa_key_type_t key_type)
{
    int ret;

    if ((ret = cipher_setup(ctx, is_enc, key_bytes, PSA_ALG_ECB_NO_PADDING, key_type)) != 0)
        return ret;
    /* ECB mode does not necessary call `ptls_cipher_init` */
    cipher_init(ctx, NULL);

    return 0;
}

static int setup_aes128ecb(ptls_cipher_context_t *ctx, int is_enc, const void *key_bytes)
{
    return ecb_setup(ctx, is_enc, key_bytes, PSA_KEY_TYPE_AES);
}

ptls_cipher_algorithm_t ptls_mbedtls_aes128ecb = {
    "AES128-ECB",   PTLS_AES128_KEY_SIZE, PTLS_AES_BLOCK_SIZE, 0 /* iv size */, sizeof(struct st_ptls_mbedtls_cipher_context_t),
    setup_aes128ecb};

static int setup_aes256ecb(ptls_cipher_context_t *ctx, int is_enc, const void *key_bytes)
{
    return ecb_setup(ctx, is_enc, key_bytes, PSA_KEY_TYPE_AES);
}

ptls_cipher_algorithm_t ptls_mbedtls_aes256ecb = {
    "AES256-ECB",   PTLS_AES256_KEY_SIZE, PTLS_AES_BLOCK_SIZE, 0 /* iv size */, sizeof(struct st_ptls_mbedtls_cipher_context_t),
    setup_aes256ecb};

static int setup_aes128ctr(ptls_cipher_context_t *ctx, int is_enc, const void *key_bytes)
{
    return cipher_setup(ctx, is_enc, key_bytes, PSA_ALG_CTR, PSA_KEY_TYPE_AES);
}

ptls_cipher_algorithm_t ptls_mbedtls_aes128ctr = {
    "AES128-CTR",   PTLS_AES128_KEY_SIZE, PTLS_AES_BLOCK_SIZE, 16 /* iv size */, sizeof(struct st_ptls_mbedtls_cipher_context_t),
    setup_aes128ctr};

static int setup_aes256ctr(ptls_cipher_context_t *ctx, int is_enc, const void *key_bytes)
{
    return cipher_setup(ctx, is_enc, key_bytes, PSA_ALG_CTR, PSA_KEY_TYPE_AES);
}

ptls_cipher_algorithm_t ptls_mbedtls_aes256ctr = {
    "AES128-CTR",   PTLS_AES256_KEY_SIZE, PTLS_AES_BLOCK_SIZE, 16 /* iv size */, sizeof(struct st_ptls_mbedtls_cipher_context_t),
    setup_aes256ctr};

#if 0
/* CHACHA20 backend using PSA API is disabled for now, as there seems to be an issue when setting the 16 bytes long IV that we
 * need. */
static int setup_chacha20(ptls_cipher_context_t *ctx, int is_enc, const void *key_bytes)
{
    return cipher_setup(ctx, is_enc, key_bytes, PSA_ALG_CTR, PSA_KEY_TYPE_CHACHA20);
}

ptls_cipher_algorithm_t ptls_mbedtls_chacha20 = {
    "CHACHA20", PTLS_CHACHA20_KEY_SIZE, 1 /* block size */, PTLS_CHACHA20_IV_SIZE, sizeof(struct st_ptls_mbedtls_cipher_context_t),
    setup_chacha20};
#else
/* Implementation of ChaCha20 using the low level ChaCha20 API.
 * TODO: remove this and the reference to chacha20.h as soon as the IV bug in the generic implementation is fixed. */
struct st_ptls_mbedtls_chacha20_context_t {
    ptls_cipher_context_t super;
    mbedtls_chacha20_context mctx;
};

static void chacha20_init(ptls_cipher_context_t *_ctx, const void *v_iv)
{
    struct st_ptls_mbedtls_chacha20_context_t *ctx = (struct st_ptls_mbedtls_chacha20_context_t *)_ctx;
    const uint8_t *iv = (const uint8_t *)v_iv;
    uint32_t ctr = iv[0] | ((uint32_t)iv[1] << 8) | ((uint32_t)iv[2] << 16) | ((uint32_t)iv[3] << 24);

    int ret = mbedtls_chacha20_starts(&ctx->mctx, (const uint8_t *)(iv + 4), ctr);
    if (ret != 0)
        PSA_FUNC_FAILED(mbedtls_chacha20_starts, ret);
}

static void chacha20_transform(ptls_cipher_context_t *_ctx, void *output, const void *input, size_t len)
{
    struct st_ptls_mbedtls_chacha20_context_t *ctx = (struct st_ptls_mbedtls_chacha20_context_t *)_ctx;

    int ret = mbedtls_chacha20_update(&ctx->mctx, len, (const uint8_t *)input, (uint8_t *)output);
    if (ret != 0)
        PSA_FUNC_FAILED(mbedtls_chacha20_update, ret);
}

static void chacha20_dispose(ptls_cipher_context_t *_ctx)
{
    struct st_ptls_mbedtls_chacha20_context_t *ctx = (struct st_ptls_mbedtls_chacha20_context_t *)_ctx;

    mbedtls_chacha20_free(&ctx->mctx);
}

static int setup_chacha20(ptls_cipher_context_t *_ctx, int is_enc, const void *key)
{
    struct st_ptls_mbedtls_chacha20_context_t *ctx = (struct st_ptls_mbedtls_chacha20_context_t *)_ctx;

    mbedtls_chacha20_init(&ctx->mctx);
    if (mbedtls_chacha20_setkey(&ctx->mctx, key) != 0)
        return PTLS_ERROR_LIBRARY;

    ctx->super.do_dispose = chacha20_dispose;
    ctx->super.do_init = chacha20_init;
    ctx->super.do_transform = chacha20_transform;

    return 0;
}

ptls_cipher_algorithm_t ptls_mbedtls_chacha20 = {"CHACHA20",
                                                 PTLS_CHACHA20_KEY_SIZE,
                                                 1 /* block size */,
                                                 PTLS_CHACHA20_IV_SIZE,
                                                 sizeof(struct st_ptls_mbedtls_chacha20_context_t),
                                                 setup_chacha20};
#endif

struct ptls_mbedtls_aead_context_t {
    struct st_ptls_aead_context_t super;
    uint8_t static_iv[PTLS_MAX_IV_SIZE];
    psa_algorithm_t alg;
    psa_key_id_t key;
};

static void aead_dispose_crypto(struct st_ptls_aead_context_t *_ctx)
{
    struct ptls_mbedtls_aead_context_t *ctx = (struct ptls_mbedtls_aead_context_t *)_ctx;

    psa_destroy_key(ctx->key);
}

static void aead_get_iv(ptls_aead_context_t *_ctx, void *iv)
{
    struct ptls_mbedtls_aead_context_t *ctx = (struct ptls_mbedtls_aead_context_t *)_ctx;

    memcpy(iv, ctx->static_iv, ctx->super.algo->iv_size);
}

static void aead_set_iv(ptls_aead_context_t *_ctx, const void *iv)
{
    struct ptls_mbedtls_aead_context_t *ctx = (struct ptls_mbedtls_aead_context_t *)_ctx;

    memcpy(ctx->static_iv, iv, ctx->super.algo->iv_size);
}

static void aead_encrypt_v(struct st_ptls_aead_context_t *_ctx, void *output, ptls_iovec_t *input, size_t incnt, uint64_t seq,
                           const void *aad, size_t aadlen)
{
    struct ptls_mbedtls_aead_context_t *ctx = (struct ptls_mbedtls_aead_context_t *)_ctx;
    psa_aead_operation_t op = psa_aead_operation_init();
    uint8_t *dst = output, iv[PTLS_MAX_IV_SIZE], tag[PSA_AEAD_TAG_MAX_SIZE];
    size_t outlen, taglen;

    /* setup op */
    CALL_WITH_CHECK(psa_aead_encrypt_setup, &op, ctx->key, ctx->alg);
    ptls_aead__build_iv(ctx->super.algo, iv, ctx->static_iv, seq);
    CALL_WITH_CHECK(psa_aead_set_nonce, &op, iv, ctx->super.algo->iv_size);
    CALL_WITH_CHECK(psa_aead_update_ad, &op, aad, aadlen);

    /* encrypt */
    for (size_t i = 0; i < incnt; i++) {
        CALL_WITH_CHECK(psa_aead_update, &op, input[i].base, input[i].len, dst, SIZE_MAX, &outlen);
        dst += outlen;
    }
    CALL_WITH_CHECK(psa_aead_finish, &op, dst, SIZE_MAX, &outlen, tag, sizeof(tag), &taglen);
    dst += outlen;
    memcpy(dst, tag, taglen);

    /* destroy op */
    psa_aead_abort(&op);
}

static size_t aead_decrypt(struct st_ptls_aead_context_t *_ctx, void *output, const void *input, size_t inlen, uint64_t seq,
                           const void *aad, size_t aadlen)
{
    struct ptls_mbedtls_aead_context_t *ctx = (struct ptls_mbedtls_aead_context_t *)_ctx;
    uint8_t iv[PTLS_MAX_IV_SIZE];
    size_t outlen;

    ptls_aead__build_iv(ctx->super.algo, iv, ctx->static_iv, seq);

    psa_status_t ret =
        psa_aead_decrypt(ctx->key, ctx->alg, iv, ctx->super.algo->iv_size, aad, aadlen, input, inlen, output, inlen, &outlen);
    switch (ret) {
    case PSA_SUCCESS:
        break;
    case PSA_ERROR_INVALID_SIGNATURE:
        outlen = SIZE_MAX;
        break;
    default:
        PSA_FUNC_FAILED(psa_aead_decrypt, ret);
        break;
    }

    return outlen;
}

static int aead_setup(ptls_aead_context_t *_ctx, int is_enc, const void *key_bytes, const void *iv, psa_algorithm_t psa_alg,
                      size_t key_bits, psa_key_type_t key_type)
{
    struct ptls_mbedtls_aead_context_t *ctx = (struct ptls_mbedtls_aead_context_t *)_ctx;

    { /* setup key */
        psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
        psa_set_key_usage_flags(&attributes, is_enc ? PSA_KEY_USAGE_ENCRYPT : PSA_KEY_USAGE_DECRYPT);
        psa_set_key_algorithm(&attributes, psa_alg);
        psa_set_key_type(&attributes, key_type);
        psa_set_key_bits(&attributes, key_bits);
        if (psa_import_key(&attributes, key_bytes, key_bits / 8, &ctx->key) != PSA_SUCCESS)
            return PTLS_ERROR_LIBRARY;
    }

    /* setup the rest */
    ctx->super.dispose_crypto = aead_dispose_crypto;
    ctx->super.do_get_iv = aead_get_iv;
    ctx->super.do_set_iv = aead_set_iv;
    if (is_enc) {
        ctx->super.do_encrypt = ptls_aead__do_encrypt;
        ctx->super.do_encrypt_v = aead_encrypt_v;
    } else {
        ctx->super.do_decrypt = aead_decrypt;
    }
    memcpy(ctx->static_iv, iv, ctx->super.algo->iv_size);
    ctx->alg = psa_alg;

    return 0;
}

static int aead_setup_aes128gcm(ptls_aead_context_t *_ctx, int is_enc, const void *key_bytes, const void *iv)
{
    return aead_setup(_ctx, is_enc, key_bytes, iv, PSA_ALG_GCM, 128, PSA_KEY_TYPE_AES);
}

ptls_aead_algorithm_t ptls_mbedtls_aes128gcm = {"AES128-GCM",
                                                PTLS_AESGCM_CONFIDENTIALITY_LIMIT,
                                                PTLS_AESGCM_INTEGRITY_LIMIT,
                                                &ptls_mbedtls_aes128ctr,
                                                &ptls_mbedtls_aes128ecb,
                                                PTLS_AES128_KEY_SIZE,
                                                PTLS_AESGCM_IV_SIZE,
                                                PTLS_AESGCM_TAG_SIZE,
                                                {PTLS_TLS12_AESGCM_FIXED_IV_SIZE, PTLS_TLS12_AESGCM_RECORD_IV_SIZE},
                                                0,
                                                0,
                                                sizeof(struct ptls_mbedtls_aead_context_t),
                                                aead_setup_aes128gcm};

ptls_cipher_suite_t ptls_mbedtls_aes128gcmsha256 = {.id = PTLS_CIPHER_SUITE_AES_128_GCM_SHA256,
                                                    .name = PTLS_CIPHER_SUITE_NAME_AES_128_GCM_SHA256,
                                                    .aead = &ptls_mbedtls_aes128gcm,
                                                    .hash = &ptls_mbedtls_sha256};

static int aead_setup_aes256gcm(ptls_aead_context_t *_ctx, int is_enc, const void *key_bytes, const void *iv)
{
    return aead_setup(_ctx, is_enc, key_bytes, iv, PSA_ALG_GCM, 256, PSA_KEY_TYPE_AES);
}

ptls_aead_algorithm_t ptls_mbedtls_aes256gcm = {"AES256-GCM",
                                                PTLS_AESGCM_CONFIDENTIALITY_LIMIT,
                                                PTLS_AESGCM_INTEGRITY_LIMIT,
                                                &ptls_mbedtls_aes256ctr,
                                                &ptls_mbedtls_aes256ecb,
                                                PTLS_AES256_KEY_SIZE,
                                                PTLS_AESGCM_IV_SIZE,
                                                PTLS_AESGCM_TAG_SIZE,
                                                {PTLS_TLS12_AESGCM_FIXED_IV_SIZE, PTLS_TLS12_AESGCM_RECORD_IV_SIZE},
                                                0,
                                                0,
                                                sizeof(struct ptls_mbedtls_aead_context_t),
                                                aead_setup_aes256gcm};

#if defined(MBEDTLS_SHA384_C)
ptls_cipher_suite_t ptls_mbedtls_aes256gcmsha384 = {.id = PTLS_CIPHER_SUITE_AES_256_GCM_SHA384,
                                                    .name = PTLS_CIPHER_SUITE_NAME_AES_256_GCM_SHA384,
                                                    .aead = &ptls_mbedtls_aes256gcm,
                                                    .hash = &ptls_mbedtls_sha384};
#endif

static int aead_setup_chacha20poly1305(ptls_aead_context_t *_ctx, int is_enc, const void *key_bytes, const void *iv)
{
    return aead_setup(_ctx, is_enc, key_bytes, iv, PSA_ALG_CHACHA20_POLY1305, 256, PSA_KEY_TYPE_CHACHA20);
}

ptls_aead_algorithm_t ptls_mbedtls_chacha20poly1305 = {"CHACHA20-POLY1305",
                                                       PTLS_CHACHA20POLY1305_CONFIDENTIALITY_LIMIT,
                                                       PTLS_CHACHA20POLY1305_INTEGRITY_LIMIT,
                                                       &ptls_mbedtls_chacha20,
                                                       NULL,
                                                       PTLS_CHACHA20_KEY_SIZE,
                                                       PTLS_CHACHA20POLY1305_IV_SIZE,
                                                       PTLS_CHACHA20POLY1305_TAG_SIZE,
                                                       {PTLS_TLS12_CHACHAPOLY_FIXED_IV_SIZE, PTLS_TLS12_CHACHAPOLY_RECORD_IV_SIZE},
                                                       0,
                                                       0,
                                                       sizeof(struct ptls_mbedtls_aead_context_t),
                                                       aead_setup_chacha20poly1305};

ptls_cipher_suite_t ptls_mbedtls_chacha20poly1305sha256 = {.id = PTLS_CIPHER_SUITE_CHACHA20_POLY1305_SHA256,
                                                           .name = PTLS_CIPHER_SUITE_NAME_CHACHA20_POLY1305_SHA256,
                                                           .aead = &ptls_mbedtls_chacha20poly1305,
                                                           .hash = &ptls_mbedtls_sha256};

ptls_cipher_suite_t *ptls_mbedtls_cipher_suites[] = {
#if defined(MBEDTLS_SHA384_C)
    &ptls_mbedtls_aes256gcmsha384,
#endif
    &ptls_mbedtls_aes128gcmsha256, &ptls_mbedtls_chacha20poly1305sha256, NULL};

#define PTLS_MBEDTLS_ECDH_PUBKEY_MAX 129

static const struct ptls_mbedtls_key_exchange_params_t {
    psa_algorithm_t alg;
    psa_ecc_family_t curve;
    size_t curve_bits;
    size_t secret_size;
} secp256r1_params = {PSA_ALG_ECDH, PSA_ECC_FAMILY_SECP_R1, 256, 32},
  x25519_params = {PSA_ALG_ECDH, PSA_ECC_FAMILY_MONTGOMERY, 255, 32};

struct ptls_mbedtls_key_exchange_context_t {
    ptls_key_exchange_context_t super;
    const struct ptls_mbedtls_key_exchange_params_t *params;
    psa_key_id_t private_key;
    uint8_t pubkeybuf[PTLS_MBEDTLS_ECDH_PUBKEY_MAX];
};

/**
 * Generates a private key. For now, we only support ECC.
 */
static int generate_private_key(psa_key_id_t *private_key, const struct ptls_mbedtls_key_exchange_params_t *params)
{
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    int ret = 0;

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attributes, params->alg);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(params->curve));
    psa_set_key_bits(&attributes, params->curve_bits);
    if (psa_generate_key(&attributes, private_key) != 0) {
        ret = -1;
    }
    return ret;
}

static int key_exchange_on_exchange(struct st_ptls_key_exchange_context_t **_keyex, int release, ptls_iovec_t *secret,
                                    ptls_iovec_t peerkey)
{
    struct ptls_mbedtls_key_exchange_context_t *keyex = (struct ptls_mbedtls_key_exchange_context_t *)*_keyex;
    int ret = 0;

    if (secret == NULL)
        goto Exit;

    /* derive shared secret */
    if ((secret->base = malloc(keyex->params->secret_size)) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }
    if (psa_raw_key_agreement(keyex->params->alg, keyex->private_key, peerkey.base, peerkey.len, secret->base,
                              keyex->params->secret_size, &secret->len) != 0) {
        ret = PTLS_ERROR_LIBRARY;
        goto Exit;
    }
    assert(keyex->params->secret_size == secret->len);
    ret = 0;

Exit:
    if (ret != 0 && secret != NULL) {
        free(secret->base);
        *secret = ptls_iovec_init(NULL, 0);
    }
    if (release) {
        psa_destroy_key(keyex->private_key);
        free(keyex);
        *_keyex = NULL;
    }
    return ret;
}

static int key_exchange_create(ptls_key_exchange_algorithm_t *algo, ptls_key_exchange_context_t **ctx,
                               const struct ptls_mbedtls_key_exchange_params_t *params)
{
    struct ptls_mbedtls_key_exchange_context_t *keyex;

    *ctx = NULL;

    /* setup context */
    if ((keyex = malloc(sizeof(*keyex))) == NULL)
        return PTLS_ERROR_NO_MEMORY;
    *keyex = (struct ptls_mbedtls_key_exchange_context_t){
        .super.algo = algo,
        .super.pubkey.base = keyex->pubkeybuf,
        .super.on_exchange = key_exchange_on_exchange,
        .params = params,
    };

    /* generate private key */
    if (generate_private_key(&keyex->private_key, keyex->params) != 0) {
        free(keyex);
        return PTLS_ERROR_LIBRARY;
    }
    { /* export public key */
        psa_status_t ret =
            psa_export_public_key(keyex->private_key, keyex->pubkeybuf, sizeof(keyex->pubkeybuf), &keyex->super.pubkey.len);
        if (ret != 0)
            PSA_FUNC_FAILED(psa_export_public_key, ret);
    }

    *ctx = &keyex->super;
    return 0;
}

static int key_exchange_exchange(ptls_key_exchange_algorithm_t *algo, ptls_iovec_t *pubkey, ptls_iovec_t *secret,
                                 ptls_iovec_t peerkey, const struct ptls_mbedtls_key_exchange_params_t *params)
{
    psa_key_id_t private_key;
    int ret;

    *pubkey = ptls_iovec_init(NULL, 0);
    *secret = ptls_iovec_init(NULL, 0);

    /* generate private key (and return immediately upon failure) */
    if (generate_private_key(&private_key, params) != 0)
        return PTLS_ERROR_LIBRARY;

    /* allocate buffers */
    if ((secret->base = malloc(params->secret_size)) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }
    if ((pubkey->base = malloc(PTLS_MBEDTLS_ECDH_PUBKEY_MAX)) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }

    /* export public key and call key agrement function */
    if (psa_export_public_key(private_key, pubkey->base, PTLS_MBEDTLS_ECDH_PUBKEY_MAX, &pubkey->len) != 0 ||
        psa_raw_key_agreement(params->alg, private_key, peerkey.base, peerkey.len, secret->base, params->secret_size,
                              &secret->len) != 0) {
        ret = PTLS_ERROR_LIBRARY;
        goto Exit;
    }

    ret = 0;

Exit:
    if (ret != 0) {
        free(pubkey->base);
        *pubkey = ptls_iovec_init(NULL, 0);
        free(secret->base);
        *secret = ptls_iovec_init(NULL, 0);
    }
    psa_destroy_key(private_key);

    return ret;
}

static int secp256r1_create(const struct st_ptls_key_exchange_algorithm_t *algo, ptls_key_exchange_context_t **ctx)
{
    return key_exchange_create(algo, ctx, &secp256r1_params);
}

static int secp256r1_exchange(const struct st_ptls_key_exchange_algorithm_t *algo, ptls_iovec_t *pubkey, ptls_iovec_t *secret,
                              ptls_iovec_t peerkey)
{
    return key_exchange_exchange(algo, pubkey, secret, peerkey, &secp256r1_params);
}

ptls_key_exchange_algorithm_t ptls_mbedtls_secp256r1 = {
    .id = PTLS_GROUP_SECP256R1, .name = PTLS_GROUP_NAME_SECP256R1, .create = secp256r1_create, .exchange = secp256r1_exchange};

static int x25519_create(const struct st_ptls_key_exchange_algorithm_t *algo, ptls_key_exchange_context_t **ctx)
{
    return key_exchange_create(algo, ctx, &x25519_params);
}

static int x25519_exchange(const struct st_ptls_key_exchange_algorithm_t *algo, ptls_iovec_t *pubkey, ptls_iovec_t *secret,
                           ptls_iovec_t peerkey)
{
    return key_exchange_exchange(algo, pubkey, secret, peerkey, &x25519_params);
}

ptls_key_exchange_algorithm_t ptls_mbedtls_x25519 = {
    .id = PTLS_GROUP_X25519, .name = PTLS_GROUP_NAME_X25519, .create = x25519_create, .exchange = x25519_exchange};

ptls_key_exchange_algorithm_t *ptls_mbedtls_key_exchanges[] = {&ptls_mbedtls_secp256r1, NULL};
