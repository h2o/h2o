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

#ifdef _WINDOWS
#include "wincompat.h"
#else
#include <unistd.h>
#endif
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#include "picotls.h"
#include "picotls/openssl.h"

#if !defined(LIBRESSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x10100000L
#define OPENSSL_1_1_API 1
#elif defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER >= 0x2070000fL
#define OPENSSL_1_1_API 1
#else
#define OPENSSL_1_1_API 0
#endif

#if !OPENSSL_1_1_API

#define EVP_PKEY_up_ref(p) CRYPTO_add(&(p)->references, 1, CRYPTO_LOCK_EVP_PKEY)
#define X509_STORE_up_ref(p) CRYPTO_add(&(p)->references, 1, CRYPTO_LOCK_X509_STORE)

static HMAC_CTX *HMAC_CTX_new(void)
{
    HMAC_CTX *ctx;

    if ((ctx = OPENSSL_malloc(sizeof(*ctx))) == NULL)
        return NULL;
    HMAC_CTX_init(ctx);
    return ctx;
}

static void HMAC_CTX_free(HMAC_CTX *ctx)
{
    HMAC_CTX_cleanup(ctx);
    OPENSSL_free(ctx);
}

#endif

void ptls_openssl_random_bytes(void *buf, size_t len)
{
    RAND_bytes(buf, (int)len);
}

static EC_KEY *ecdh_gerenate_key(EC_GROUP *group)
{
    EC_KEY *key;

    if ((key = EC_KEY_new()) == NULL)
        return NULL;
    if (!EC_KEY_set_group(key, group) || !EC_KEY_generate_key(key)) {
        EC_KEY_free(key);
        return NULL;
    }

    return key;
}

static int ecdh_calc_secret(ptls_iovec_t *out, EC_GROUP *group, EC_KEY *privkey, EC_POINT *peer_point)
{
    ptls_iovec_t secret;
    int ret;

    secret.len = (EC_GROUP_get_degree(group) + 7) / 8;
    if ((secret.base = malloc(secret.len)) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }
    if (ECDH_compute_key(secret.base, secret.len, peer_point, privkey, NULL) <= 0) {
        ret = PTLS_ALERT_HANDSHAKE_FAILURE; /* ??? */
        goto Exit;
    }
    ret = 0;

Exit:
    if (ret == 0) {
        *out = secret;
    } else {
        free(secret.base);
        *out = (ptls_iovec_t){NULL};
    }
    return ret;
}

static EC_POINT *x9_62_decode_point(EC_GROUP *group, ptls_iovec_t vec, BN_CTX *bn_ctx)
{
    EC_POINT *point = NULL;

    if ((point = EC_POINT_new(group)) == NULL)
        return NULL;
    if (!EC_POINT_oct2point(group, point, vec.base, vec.len, bn_ctx)) {
        EC_POINT_free(point);
        return NULL;
    }

    return point;
}

static ptls_iovec_t x9_62_encode_point(EC_GROUP *group, const EC_POINT *point, BN_CTX *bn_ctx)
{
    ptls_iovec_t vec;

    if ((vec.len = EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, bn_ctx)) == 0)
        return (ptls_iovec_t){NULL};
    if ((vec.base = malloc(vec.len)) == NULL)
        return (ptls_iovec_t){NULL};
    if (EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, vec.base, vec.len, bn_ctx) != vec.len) {
        free(vec.base);
        return (ptls_iovec_t){NULL};
    }

    return vec;
}

struct st_x9_62_keyex_context_t {
    ptls_key_exchange_context_t super;
    BN_CTX *bn_ctx;
    EC_GROUP *group;
    EC_KEY *privkey;
    ptls_iovec_t pubkey;
};

static void x9_62_free_context(struct st_x9_62_keyex_context_t *ctx)
{
    free(ctx->pubkey.base);
    if (ctx->privkey != NULL)
        EC_KEY_free(ctx->privkey);
    if (ctx->group != NULL)
        EC_GROUP_free(ctx->group);
    if (ctx->bn_ctx != NULL)
        BN_CTX_free(ctx->bn_ctx);
    free(ctx);
}

static int x9_62_on_exchange(ptls_key_exchange_context_t **_ctx, ptls_iovec_t *secret, ptls_iovec_t peerkey)
{
    struct st_x9_62_keyex_context_t *ctx = (struct st_x9_62_keyex_context_t *)*_ctx;
    EC_POINT *peer_point = NULL;
    int ret;

    *_ctx = NULL;

    if ((peer_point = x9_62_decode_point(ctx->group, peerkey, ctx->bn_ctx)) == NULL) {
        ret = PTLS_ALERT_DECODE_ERROR;
        goto Exit;
    }
    if ((ret = ecdh_calc_secret(secret, ctx->group, ctx->privkey, peer_point)) != 0)
        goto Exit;

Exit:
    if (peer_point != NULL)
        EC_POINT_free(peer_point);
    x9_62_free_context(ctx);
    return ret;
}

static int x9_62_create_key_exchange(ptls_key_exchange_context_t **_ctx, ptls_iovec_t *pubkey, int nid)
{
    struct st_x9_62_keyex_context_t *ctx = NULL;
    int ret;

    if ((ctx = (struct st_x9_62_keyex_context_t *)malloc(sizeof(*ctx))) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }
    *ctx = (struct st_x9_62_keyex_context_t){{x9_62_on_exchange}};

    if ((ctx->bn_ctx = BN_CTX_new()) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }
    if ((ctx->group = EC_GROUP_new_by_curve_name(nid)) == NULL) {
        ret = PTLS_ERROR_LIBRARY;
        goto Exit;
    }
    if ((ctx->privkey = ecdh_gerenate_key(ctx->group)) == NULL) {
        ret = PTLS_ERROR_LIBRARY;
        goto Exit;
    }

    if ((ctx->pubkey = x9_62_encode_point(ctx->group, EC_KEY_get0_public_key(ctx->privkey), ctx->bn_ctx)).base == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }

    *pubkey = ctx->pubkey;
    ret = 0;

Exit:
    if (ret == 0) {
        *_ctx = &ctx->super;
    } else {
        if (ctx != NULL)
            x9_62_free_context(ctx);
        *_ctx = NULL;
        *pubkey = (ptls_iovec_t){NULL};
    }

    return ret;
}

static int secp256r1_create_key_exchange(ptls_key_exchange_context_t **ctx, ptls_iovec_t *pubkey)
{
    return x9_62_create_key_exchange(ctx, pubkey, NID_X9_62_prime256v1);
}

static int x9_62_key_exchange(EC_GROUP *group, ptls_iovec_t *pubkey, ptls_iovec_t *secret, ptls_iovec_t peerkey, BN_CTX *bn_ctx)
{
    EC_POINT *peer_point = NULL;
    EC_KEY *privkey = NULL;
    int ret;

    *pubkey = (ptls_iovec_t){NULL};
    *secret = (ptls_iovec_t){NULL};

    /* decode peer key */
    if ((peer_point = x9_62_decode_point(group, peerkey, bn_ctx)) == NULL) {
        ret = PTLS_ALERT_DECODE_ERROR;
        goto Exit;
    }

    /* create private key */
    if ((privkey = ecdh_gerenate_key(group)) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }

    /* encode public key */
    if ((*pubkey = x9_62_encode_point(group, EC_KEY_get0_public_key(privkey), bn_ctx)).base == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }

    /* calc secret */
    secret->len = (EC_GROUP_get_degree(group) + 7) / 8;
    if ((secret->base = malloc(secret->len)) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }

    /* ecdh! */
    if (ECDH_compute_key(secret->base, secret->len, peer_point, privkey, NULL) <= 0) {
        ret = PTLS_ALERT_HANDSHAKE_FAILURE; /* ??? */
        goto Exit;
    }

    ret = 0;

Exit:
    if (peer_point != NULL)
        EC_POINT_free(peer_point);
    if (privkey != NULL)
        EC_KEY_free(privkey);
    if (ret != 0) {
        free(pubkey->base);
        *pubkey = (ptls_iovec_t){NULL};
        free(secret->base);
        *secret = (ptls_iovec_t){NULL};
    }
    return ret;
}

static int secp_key_exchange(int nid, ptls_iovec_t *pubkey, ptls_iovec_t *secret, ptls_iovec_t peerkey)
{
    EC_GROUP *group = NULL;
    BN_CTX *bn_ctx = NULL;
    int ret;

    if ((group = EC_GROUP_new_by_curve_name(nid)) == NULL) {
        ret = PTLS_ERROR_LIBRARY;
        goto Exit;
    }
    if ((bn_ctx = BN_CTX_new()) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }

    ret = x9_62_key_exchange(group, pubkey, secret, peerkey, bn_ctx);

Exit:
    if (bn_ctx != NULL)
        BN_CTX_free(bn_ctx);
    if (group != NULL)
        EC_GROUP_free(group);
    return ret;
}

static int secp256r1_key_exchange(ptls_iovec_t *pubkey, ptls_iovec_t *secret, ptls_iovec_t peerkey)
{
    return secp_key_exchange(NID_X9_62_prime256v1, pubkey, secret, peerkey);
}

static int do_sign(EVP_PKEY *key, ptls_buffer_t *outbuf, ptls_iovec_t input, const EVP_MD *md)
{
    EVP_MD_CTX *ctx = NULL;
    EVP_PKEY_CTX *pkey_ctx;
    size_t siglen;
    int ret;

    if ((ctx = EVP_MD_CTX_create()) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }
    if (EVP_DigestSignInit(ctx, &pkey_ctx, md, NULL, key) != 1) {
        ret = PTLS_ERROR_LIBRARY;
        goto Exit;
    }
    if (EVP_PKEY_id(key) == EVP_PKEY_RSA) {
        if (EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING) != 1) {
            ret = PTLS_ERROR_LIBRARY;
            goto Exit;
        }
        if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, -1) != 1) {
            ret = PTLS_ERROR_LIBRARY;
            goto Exit;
        }
        if (EVP_PKEY_CTX_set_rsa_mgf1_md(pkey_ctx, EVP_sha256()) != 1) {
            ret = PTLS_ERROR_LIBRARY;
            goto Exit;
        }
    }
    if (EVP_DigestSignUpdate(ctx, input.base, input.len) != 1) {
        ret = PTLS_ERROR_LIBRARY;
        goto Exit;
    }
    if (EVP_DigestSignFinal(ctx, NULL, &siglen) != 1) {
        ret = PTLS_ERROR_LIBRARY;
        goto Exit;
    }
    if ((ret = ptls_buffer_reserve(outbuf, siglen)) != 0)
        goto Exit;
    if (EVP_DigestSignFinal(ctx, outbuf->base + outbuf->off, &siglen) != 1) {
        ret = PTLS_ERROR_LIBRARY;
        goto Exit;
    }
    outbuf->off += siglen;

    ret = 0;
Exit:
    if (ctx != NULL)
        EVP_MD_CTX_destroy(ctx);
    return ret;
}

struct cipher_context_t {
    ptls_cipher_context_t super;
    EVP_CIPHER_CTX *evp;
};

static void cipher_dispose(ptls_cipher_context_t *_ctx)
{
    struct cipher_context_t *ctx = (struct cipher_context_t *)_ctx;
    EVP_CIPHER_CTX_free(ctx->evp);
}

static void cipher_do_init(ptls_cipher_context_t *_ctx, const void *iv)
{
    struct cipher_context_t *ctx = (struct cipher_context_t *)_ctx;
    int ret;
    ret = EVP_EncryptInit_ex(ctx->evp, NULL, NULL, NULL, iv);
    assert(ret);
}

static int cipher_setup_crypto(ptls_cipher_context_t *_ctx, const void *key, const EVP_CIPHER *cipher,
                               void (*do_transform)(ptls_cipher_context_t *, void *, const void *, size_t))
{
    struct cipher_context_t *ctx = (struct cipher_context_t *)_ctx;

    ctx->super.do_dispose = cipher_dispose;
    ctx->super.do_init = cipher_do_init;
    ctx->super.do_transform = do_transform;

    if ((ctx->evp = EVP_CIPHER_CTX_new()) == NULL)
        return PTLS_ERROR_NO_MEMORY;
    if (!EVP_EncryptInit_ex(ctx->evp, cipher, NULL, key, NULL)) {
        EVP_CIPHER_CTX_free(ctx->evp);
        return PTLS_ERROR_LIBRARY;
    }

    return 0;
}

static void cipher_encrypt(ptls_cipher_context_t *_ctx, void *output, const void *input, size_t _len)
{
    struct cipher_context_t *ctx = (struct cipher_context_t *)_ctx;
    int len = (int)_len, ret = EVP_EncryptUpdate(ctx->evp, output, &len, input, len);
    assert(ret);
}

static int aes128ctr_setup_crypto(ptls_cipher_context_t *ctx, int is_enc, const void *key)
{
    return cipher_setup_crypto(ctx, key, EVP_aes_128_ctr(), cipher_encrypt);
}

static int aes256ctr_setup_crypto(ptls_cipher_context_t *ctx, int is_enc, const void *key)
{
    return cipher_setup_crypto(ctx, key, EVP_aes_256_ctr(), cipher_encrypt);
}

#if defined(PTLS_OPENSSL_HAVE_CHACHA20_POLY1305)

static int chacha20_setup_crypto(ptls_cipher_context_t *ctx, int is_enc, const void *key)
{
    return cipher_setup_crypto(ctx, key, EVP_chacha20(), cipher_encrypt);
}

#endif

struct aead_crypto_context_t {
    ptls_aead_context_t super;
    EVP_CIPHER_CTX *evp_ctx;
};

static void aead_dispose_crypto(ptls_aead_context_t *_ctx)
{
    struct aead_crypto_context_t *ctx = (struct aead_crypto_context_t *)_ctx;

    if (ctx->evp_ctx != NULL)
        EVP_CIPHER_CTX_free(ctx->evp_ctx);
}

static void aead_do_encrypt_init(ptls_aead_context_t *_ctx, const void *iv, const void *aad, size_t aadlen)
{
    struct aead_crypto_context_t *ctx = (struct aead_crypto_context_t *)_ctx;
    int ret;

    /* FIXME for performance, preserve the expanded key instead of the raw key */
    ret = EVP_EncryptInit_ex(ctx->evp_ctx, NULL, NULL, NULL, iv);
    assert(ret);

    if (aadlen != 0) {
        int blocklen;
        ret = EVP_EncryptUpdate(ctx->evp_ctx, NULL, &blocklen, aad, (int)aadlen);
        assert(ret);
    }
}

static size_t aead_do_encrypt_update(ptls_aead_context_t *_ctx, void *output, const void *input, size_t inlen)
{
    struct aead_crypto_context_t *ctx = (struct aead_crypto_context_t *)_ctx;
    int blocklen, ret;

    ret = EVP_EncryptUpdate(ctx->evp_ctx, output, &blocklen, input, (int)inlen);
    assert(ret);

    return blocklen;
}

static size_t aead_do_encrypt_final(ptls_aead_context_t *_ctx, void *_output)
{
    struct aead_crypto_context_t *ctx = (struct aead_crypto_context_t *)_ctx;
    uint8_t *output = _output;
    size_t off = 0, tag_size = ctx->super.algo->tag_size;
    int blocklen, ret;

    ret = EVP_EncryptFinal_ex(ctx->evp_ctx, output + off, &blocklen);
    assert(ret);
    off += blocklen;
    ret = EVP_CIPHER_CTX_ctrl(ctx->evp_ctx, EVP_CTRL_GCM_GET_TAG, (int)tag_size, output + off);
    assert(ret);
    off += tag_size;

    return off;
}

static size_t aead_do_decrypt(ptls_aead_context_t *_ctx, void *_output, const void *input, size_t inlen, const void *iv,
                              const void *aad, size_t aadlen)
{
    struct aead_crypto_context_t *ctx = (struct aead_crypto_context_t *)_ctx;
    uint8_t *output = _output;
    size_t off = 0, tag_size = ctx->super.algo->tag_size;
    int blocklen, ret;

    if (inlen < tag_size)
        return SIZE_MAX;

    ret = EVP_DecryptInit_ex(ctx->evp_ctx, NULL, NULL, NULL, iv);
    assert(ret);
    if (aadlen != 0) {
        ret = EVP_DecryptUpdate(ctx->evp_ctx, NULL, &blocklen, aad, (int)aadlen);
        assert(ret);
    }
    ret = EVP_DecryptUpdate(ctx->evp_ctx, output + off, &blocklen, input, (int)(inlen - tag_size));
    assert(ret);
    off += blocklen;
    if (!EVP_CIPHER_CTX_ctrl(ctx->evp_ctx, EVP_CTRL_GCM_SET_TAG, (int)tag_size, (void *)((uint8_t *)input + inlen - tag_size)))
        return SIZE_MAX;
    if (!EVP_DecryptFinal_ex(ctx->evp_ctx, output + off, &blocklen))
        return SIZE_MAX;
    off += blocklen;

    return off;
}

static int aead_setup_crypto(ptls_aead_context_t *_ctx, int is_enc, const void *key, const EVP_CIPHER *cipher)
{
    struct aead_crypto_context_t *ctx = (struct aead_crypto_context_t *)_ctx;
    int ret;

    ctx->super.dispose_crypto = aead_dispose_crypto;
    if (is_enc) {
        ctx->super.do_encrypt_init = aead_do_encrypt_init;
        ctx->super.do_encrypt_update = aead_do_encrypt_update;
        ctx->super.do_encrypt_final = aead_do_encrypt_final;
        ctx->super.do_decrypt = NULL;
    } else {
        ctx->super.do_encrypt_init = NULL;
        ctx->super.do_encrypt_update = NULL;
        ctx->super.do_encrypt_final = NULL;
        ctx->super.do_decrypt = aead_do_decrypt;
    }
    ctx->evp_ctx = NULL;

    if ((ctx->evp_ctx = EVP_CIPHER_CTX_new()) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Error;
    }
    if (is_enc) {
        if (!EVP_EncryptInit_ex(ctx->evp_ctx, cipher, NULL, key, NULL)) {
            ret = PTLS_ERROR_LIBRARY;
            goto Error;
        }
    } else {
        if (!EVP_DecryptInit_ex(ctx->evp_ctx, cipher, NULL, key, NULL)) {
            ret = PTLS_ERROR_LIBRARY;
            goto Error;
        }
    }
    if (!EVP_CIPHER_CTX_ctrl(ctx->evp_ctx, EVP_CTRL_GCM_SET_IVLEN, (int)ctx->super.algo->iv_size, NULL)) {
        ret = PTLS_ERROR_LIBRARY;
        goto Error;
    }

    return 0;

Error:
    aead_dispose_crypto(&ctx->super);
    return ret;
}

static int aead_aes128gcm_setup_crypto(ptls_aead_context_t *ctx, int is_enc, const void *key)
{
    return aead_setup_crypto(ctx, is_enc, key, EVP_aes_128_gcm());
}

static int aead_aes256gcm_setup_crypto(ptls_aead_context_t *ctx, int is_enc, const void *key)
{
    return aead_setup_crypto(ctx, is_enc, key, EVP_aes_256_gcm());
}

#if defined(PTLS_OPENSSL_HAVE_CHACHA20_POLY1305)
static int aead_chacha20poly1305_setup_crypto(ptls_aead_context_t *ctx, int is_enc, const void *key)
{
    return aead_setup_crypto(ctx, is_enc, key, EVP_chacha20_poly1305());
}
#endif

#define _sha256_final(ctx, md) SHA256_Final((md), (ctx))
ptls_define_hash(sha256, SHA256_CTX, SHA256_Init, SHA256_Update, _sha256_final);

#define _sha384_final(ctx, md) SHA384_Final((md), (ctx))
ptls_define_hash(sha384, SHA512_CTX, SHA384_Init, SHA384_Update, _sha384_final);

static int sign_certificate(ptls_sign_certificate_t *_self, ptls_t *tls, uint16_t *selected_algorithm, ptls_buffer_t *outbuf,
                            ptls_iovec_t input, const uint16_t *algorithms, size_t num_algorithms)
{
    ptls_openssl_sign_certificate_t *self = (ptls_openssl_sign_certificate_t *)_self;
    const struct st_ptls_openssl_signature_scheme_t *scheme;

    /* select the algorithm */
    for (scheme = self->schemes; scheme->scheme_id != UINT16_MAX; ++scheme) {
        size_t i;
        for (i = 0; i != num_algorithms; ++i)
            if (algorithms[i] == scheme->scheme_id)
                goto Found;
    }
    return PTLS_ALERT_HANDSHAKE_FAILURE;

Found:
    *selected_algorithm = scheme->scheme_id;
    return do_sign(self->key, outbuf, input, scheme->scheme_md);
}

static X509 *to_x509(ptls_iovec_t vec)
{
    const uint8_t *p = vec.base;
    return d2i_X509(NULL, &p, vec.len);
}

static int verify_sign(void *verify_ctx, ptls_iovec_t data, ptls_iovec_t signature)
{
    EVP_PKEY *key = verify_ctx;
    EVP_MD_CTX *ctx = NULL;
    EVP_PKEY_CTX *pkey_ctx = NULL;
    int ret = 0;

    if (data.base == NULL)
        goto Exit;

    if ((ctx = EVP_MD_CTX_create()) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }
    if (EVP_DigestVerifyInit(ctx, &pkey_ctx, EVP_sha256(), NULL, key) != 1) {
        ret = PTLS_ERROR_LIBRARY;
        goto Exit;
    }
    if (EVP_PKEY_id(key) == EVP_PKEY_RSA) {
        if (EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING) != 1) {
            ret = PTLS_ERROR_LIBRARY;
            goto Exit;
        }
        if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, -1) != 1) {
            ret = PTLS_ERROR_LIBRARY;
            goto Exit;
        }
        if (EVP_PKEY_CTX_set_rsa_mgf1_md(pkey_ctx, EVP_sha256()) != 1) {
            ret = PTLS_ERROR_LIBRARY;
            goto Exit;
        }
    }
    if (EVP_DigestVerifyUpdate(ctx, data.base, data.len) != 1) {
        ret = PTLS_ERROR_LIBRARY;
        goto Exit;
    }
    if (EVP_DigestVerifyFinal(ctx, signature.base, signature.len) != 1) {
        ret = PTLS_ALERT_DECRYPT_ERROR;
        goto Exit;
    }
    ret = 0;

Exit:
    if (ctx != NULL)
        EVP_MD_CTX_destroy(ctx);
    EVP_PKEY_free(key);
    return ret;
}

int ptls_openssl_init_sign_certificate(ptls_openssl_sign_certificate_t *self, EVP_PKEY *key)
{
    *self = (ptls_openssl_sign_certificate_t){{sign_certificate}};
    size_t scheme_index = 0;

#define PUSH_SCHEME(id, md)                                                                                                        \
    self->schemes[scheme_index++] = (struct st_ptls_openssl_signature_scheme_t)                                                    \
    {                                                                                                                              \
        id, md                                                                                                                     \
    }

    switch (EVP_PKEY_id(key)) {
    case EVP_PKEY_RSA:
        PUSH_SCHEME(PTLS_SIGNATURE_RSA_PSS_RSAE_SHA256, EVP_sha256());
        PUSH_SCHEME(PTLS_SIGNATURE_RSA_PSS_RSAE_SHA384, EVP_sha384());
        PUSH_SCHEME(PTLS_SIGNATURE_RSA_PSS_RSAE_SHA512, EVP_sha512());
        break;
    case EVP_PKEY_EC: {
        EC_KEY *eckey = EVP_PKEY_get1_EC_KEY(key);
        switch (EC_GROUP_get_curve_name(EC_KEY_get0_group(eckey))) {
        case NID_X9_62_prime256v1:
            PUSH_SCHEME(PTLS_SIGNATURE_ECDSA_SECP256R1_SHA256, EVP_sha256());
            break;
#if defined(NID_secp384r1) && !OPENSSL_NO_SHA384
        case NID_secp384r1:
            PUSH_SCHEME(PTLS_SIGNATURE_ECDSA_SECP384R1_SHA384, EVP_sha384());
            break;
#endif
#if defined(NID_secp384r1) && !OPENSSL_NO_SHA512
        case NID_secp521r1:
            PUSH_SCHEME(PTLS_SIGNATURE_ECDSA_SECP521R1_SHA512, EVP_sha512());
            break;
#endif
        default:
            EC_KEY_free(eckey);
            return PTLS_ERROR_INCOMPATIBLE_KEY;
        }
        EC_KEY_free(eckey);
    } break;
    default:
        return PTLS_ERROR_INCOMPATIBLE_KEY;
    }
    PUSH_SCHEME(UINT16_MAX, NULL);
    assert(scheme_index <= sizeof(self->schemes) / sizeof(self->schemes[0]));

#undef PUSH_SCHEME

    EVP_PKEY_up_ref(key);
    self->key = key;

    return 0;
}

void ptls_openssl_dispose_sign_certificate(ptls_openssl_sign_certificate_t *self)
{
    EVP_PKEY_free(self->key);
}

static int serialize_cert(X509 *cert, ptls_iovec_t *dst)
{
    int len = i2d_X509(cert, NULL);
    assert(len > 0);

    if ((dst->base = malloc(len)) == NULL)
        return PTLS_ERROR_NO_MEMORY;
    unsigned char *p = dst->base;
    dst->len = i2d_X509(cert, &p);
    assert(len == dst->len);

    return 0;
}

int ptls_openssl_load_certificates(ptls_context_t *ctx, X509 *cert, STACK_OF(X509) * chain)
{
    ptls_iovec_t *list = NULL;
    size_t slot = 0, count = (cert != NULL) + (chain != NULL ? sk_X509_num(chain) : 0);
    int ret;

    assert(ctx->certificates.list == NULL);

    if ((list = malloc(sizeof(*list) * count)) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }
    if (cert != NULL) {
        if ((ret = serialize_cert(cert, list + slot++)) != 0)
            goto Exit;
    }
    if (chain != NULL) {
        int i;
        for (i = 0; i != sk_X509_num(chain); ++i) {
            if ((ret = serialize_cert(sk_X509_value(chain, i), list + slot++)) != 0)
                goto Exit;
        }
    }

    assert(slot == count);

    ctx->certificates.list = list;
    ctx->certificates.count = count;
    ret = 0;

Exit:
    if (ret != 0 && list != NULL) {
        size_t i;
        for (i = 0; i != slot; ++i)
            free(list[i].base);
        free(list);
    }
    return ret;
}

static int verify_certificate(ptls_verify_certificate_t *_self, ptls_t *tls, int (**verifier)(void *, ptls_iovec_t, ptls_iovec_t),
                              void **verify_data, ptls_iovec_t *certs, size_t num_certs)
{
    ptls_openssl_verify_certificate_t *self = (ptls_openssl_verify_certificate_t *)_self;
    X509 *cert = NULL;
    STACK_OF(X509) *chain = NULL;
    X509_STORE_CTX *verify_ctx = NULL;
    int ret = 0;

    assert(num_certs != 0);

    if ((cert = to_x509(certs[0])) == NULL) {
        ret = PTLS_ALERT_BAD_CERTIFICATE;
        goto Exit;
    }

    if (self->cert_store != NULL) {
        size_t i;
        for (i = 1; i != num_certs; ++i) {
            X509 *interm = to_x509(certs[i]);
            if (interm == NULL) {
                ret = PTLS_ALERT_BAD_CERTIFICATE;
                goto Exit;
            }
        }
        if ((verify_ctx = X509_STORE_CTX_new()) == NULL) {
            ret = PTLS_ERROR_NO_MEMORY;
            goto Exit;
        }
        if (X509_STORE_CTX_init(verify_ctx, self->cert_store, cert, chain) != 1) {
            ret = PTLS_ERROR_LIBRARY;
            goto Exit;
        }
        X509_STORE_CTX_set_purpose(verify_ctx, X509_PURPOSE_SSL_CLIENT);
        if (X509_verify_cert(verify_ctx) == 1) {
            ret = 0;
        } else {
            switch (X509_STORE_CTX_get_error(verify_ctx)) {
            case X509_V_ERR_OUT_OF_MEM:
                ret = PTLS_ERROR_NO_MEMORY;
                goto Exit;
            case X509_V_ERR_CERT_REVOKED:
                ret = PTLS_ALERT_CERTIFICATE_REVOKED;
                goto Exit;
            case X509_V_ERR_CERT_HAS_EXPIRED:
                ret = PTLS_ALERT_CERTIFICATE_EXPIRED;
                goto Exit;
            default:
                ret = PTLS_ALERT_CERTIFICATE_UNKNOWN;
                goto Exit;
            }
        }
    }

    if ((*verify_data = X509_get_pubkey(cert)) == NULL) {
        ret = PTLS_ALERT_BAD_CERTIFICATE;
        goto Exit;
    }
    *verifier = verify_sign;

Exit:
    if (verify_ctx != NULL)
        X509_STORE_CTX_free(verify_ctx);
    if (chain != NULL)
        sk_X509_free(chain);
    if (cert != NULL)
        X509_free(cert);
    return ret;
}

int ptls_openssl_init_verify_certificate(ptls_openssl_verify_certificate_t *self, X509_STORE *store)
{
    *self = (ptls_openssl_verify_certificate_t){{verify_certificate}};

    if (store != NULL) {
        if (store != PTLS_OPENSSL_DEFAULT_CERTIFICATE_STORE) {
            X509_STORE_up_ref(store);
            self->cert_store = store;
        } else {
            X509_LOOKUP *lookup;
            if ((self->cert_store = X509_STORE_new()) == NULL)
                return -1;
            if ((lookup = X509_STORE_add_lookup(self->cert_store, X509_LOOKUP_file())) == NULL)
                return -1;
            X509_LOOKUP_load_file(lookup, NULL, X509_FILETYPE_DEFAULT);
            if ((lookup = X509_STORE_add_lookup(self->cert_store, X509_LOOKUP_hash_dir())) == NULL)
                return -1;
            X509_LOOKUP_add_dir(lookup, NULL, X509_FILETYPE_DEFAULT);
        }
    }

    return 0;
}

void ptls_openssl_dispose_verify_certificate(ptls_openssl_verify_certificate_t *self)
{
    X509_STORE_free(self->cert_store);
    free(self);
}

#define TICKET_LABEL_SIZE 16
#define TICKET_IV_SIZE EVP_MAX_IV_LENGTH

int ptls_openssl_encrypt_ticket(ptls_buffer_t *buf, ptls_iovec_t src,
                                int (*cb)(unsigned char *key_name, unsigned char *iv, EVP_CIPHER_CTX *ctx, HMAC_CTX *hctx, int enc))
{
    EVP_CIPHER_CTX *cctx = NULL;
    HMAC_CTX *hctx = NULL;
    uint8_t *dst;
    int clen, ret;

    if ((cctx = EVP_CIPHER_CTX_new()) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }
    if ((hctx = HMAC_CTX_new()) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }

    if ((ret = ptls_buffer_reserve(buf, TICKET_LABEL_SIZE + TICKET_IV_SIZE + src.len + EVP_MAX_BLOCK_LENGTH + EVP_MAX_MD_SIZE)) !=
        0)
        goto Exit;
    dst = buf->base + buf->off;

    /* fill label and iv, as well as obtaining the keys */
    if (!(*cb)(dst, dst + TICKET_LABEL_SIZE, cctx, hctx, 1)) {
        ret = PTLS_ERROR_LIBRARY;
        goto Exit;
    }
    dst += TICKET_LABEL_SIZE + TICKET_IV_SIZE;

    /* encrypt */
    if (!EVP_EncryptUpdate(cctx, dst, &clen, src.base, (int)src.len)) {
        ret = PTLS_ERROR_LIBRARY;
        goto Exit;
    }
    dst += clen;
    if (!EVP_EncryptFinal_ex(cctx, dst, &clen)) {
        ret = PTLS_ERROR_LIBRARY;
        goto Exit;
    }
    dst += clen;

    /* append hmac */
    if (!HMAC_Update(hctx, buf->base + buf->off, dst - (buf->base + buf->off)) || !HMAC_Final(hctx, dst, NULL)) {
        ret = PTLS_ERROR_LIBRARY;
        goto Exit;
    }
    dst += HMAC_size(hctx);

    assert(dst <= buf->base + buf->capacity);
    buf->off += dst - (buf->base + buf->off);
    ret = 0;

Exit:
    if (cctx != NULL)
        EVP_CIPHER_CTX_cleanup(cctx);
    if (hctx != NULL)
        HMAC_CTX_free(hctx);
    return ret;
}

int ptls_openssl_decrypt_ticket(ptls_buffer_t *buf, ptls_iovec_t src,
                                int (*cb)(unsigned char *key_name, unsigned char *iv, EVP_CIPHER_CTX *ctx, HMAC_CTX *hctx, int enc))
{
    EVP_CIPHER_CTX *cctx = NULL;
    HMAC_CTX *hctx = NULL;
    int clen, ret;

    if ((cctx = EVP_CIPHER_CTX_new()) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }
    if ((hctx = HMAC_CTX_new()) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }

    /* obtain cipher and hash context.
     * Note: no need to handle renew, since in picotls we always send a new ticket to minimize the chance of ticket reuse */
    if (src.len < TICKET_LABEL_SIZE + TICKET_IV_SIZE) {
        ret = PTLS_ALERT_DECODE_ERROR;
        goto Exit;
    }
    if (!(*cb)(src.base, src.base + TICKET_LABEL_SIZE, cctx, hctx, 0)) {
        ret = PTLS_ERROR_LIBRARY;
        goto Exit;
    }

    /* check hmac, and exclude label, iv, hmac */
    size_t hmac_size = HMAC_size(hctx);
    if (src.len < TICKET_LABEL_SIZE + TICKET_IV_SIZE + hmac_size) {
        ret = PTLS_ALERT_DECODE_ERROR;
        goto Exit;
    }
    src.len -= hmac_size;
    uint8_t hmac[EVP_MAX_MD_SIZE];
    if (!HMAC_Update(hctx, src.base, src.len) || !HMAC_Final(hctx, hmac, NULL)) {
        ret = PTLS_ERROR_LIBRARY;
        goto Exit;
    }
    if (memcmp(src.base + src.len, hmac, hmac_size) != 0) {
        ret = PTLS_ALERT_HANDSHAKE_FAILURE;
        goto Exit;
    }
    src.base += TICKET_LABEL_SIZE + TICKET_IV_SIZE;
    src.len -= TICKET_LABEL_SIZE + TICKET_IV_SIZE;

    /* decrypt */
    if ((ret = ptls_buffer_reserve(buf, src.len)) != 0)
        goto Exit;
    if (!EVP_DecryptUpdate(cctx, buf->base + buf->off, &clen, src.base, (int)src.len)) {
        ret = PTLS_ERROR_LIBRARY;
        goto Exit;
    }
    buf->off += clen;
    if (!EVP_DecryptFinal_ex(cctx, buf->base + buf->off, &clen)) {
        ret = PTLS_ERROR_LIBRARY;
        goto Exit;
    }
    buf->off += clen;

    ret = 0;

Exit:
    if (cctx != NULL)
        EVP_CIPHER_CTX_cleanup(cctx);
    if (hctx != NULL)
        HMAC_CTX_free(hctx);
    return ret;
}

ptls_key_exchange_algorithm_t ptls_openssl_secp256r1 = {PTLS_GROUP_SECP256R1, secp256r1_create_key_exchange,
                                                        secp256r1_key_exchange};
ptls_key_exchange_algorithm_t *ptls_openssl_key_exchanges[] = {&ptls_openssl_secp256r1, NULL};
ptls_cipher_algorithm_t ptls_openssl_aes128ctr = {"AES128-CTR", PTLS_AES128_KEY_SIZE, PTLS_AES_IV_SIZE,
                                                  sizeof(struct cipher_context_t), aes128ctr_setup_crypto};
ptls_aead_algorithm_t ptls_openssl_aes128gcm = {"AES128-GCM",
                                                &ptls_openssl_aes128ctr,
                                                PTLS_AES128_KEY_SIZE,
                                                PTLS_AESGCM_IV_SIZE,
                                                PTLS_AESGCM_TAG_SIZE,
                                                sizeof(struct aead_crypto_context_t),
                                                aead_aes128gcm_setup_crypto};
ptls_cipher_algorithm_t ptls_openssl_aes256ctr = {"AES256-CTR", PTLS_AES256_KEY_SIZE, PTLS_AES_IV_SIZE,
                                                  sizeof(struct cipher_context_t), aes256ctr_setup_crypto};
ptls_aead_algorithm_t ptls_openssl_aes256gcm = {"AES256-GCM",
                                                &ptls_openssl_aes256ctr,
                                                PTLS_AES256_KEY_SIZE,
                                                PTLS_AESGCM_IV_SIZE,
                                                PTLS_AESGCM_TAG_SIZE,
                                                sizeof(struct aead_crypto_context_t),
                                                aead_aes256gcm_setup_crypto};
ptls_hash_algorithm_t ptls_openssl_sha256 = {PTLS_SHA256_BLOCK_SIZE, PTLS_SHA256_DIGEST_SIZE, sha256_create,
                                             PTLS_ZERO_DIGEST_SHA256};
ptls_hash_algorithm_t ptls_openssl_sha384 = {PTLS_SHA384_BLOCK_SIZE, PTLS_SHA384_DIGEST_SIZE, sha384_create,
                                             PTLS_ZERO_DIGEST_SHA384};
ptls_cipher_suite_t ptls_openssl_aes128gcmsha256 = {PTLS_CIPHER_SUITE_AES_128_GCM_SHA256, &ptls_openssl_aes128gcm,
                                                    &ptls_openssl_sha256};
ptls_cipher_suite_t ptls_openssl_aes256gcmsha384 = {PTLS_CIPHER_SUITE_AES_256_GCM_SHA384, &ptls_openssl_aes256gcm,
                                                    &ptls_openssl_sha384};
#if defined(PTLS_OPENSSL_HAVE_CHACHA20_POLY1305)
ptls_cipher_algorithm_t ptls_openssl_chacha20 = {"CHACHA20", PTLS_CHACHA20_KEY_SIZE, PTLS_CHACHA20_IV_SIZE,
                                                 sizeof(struct cipher_context_t), chacha20_setup_crypto};
ptls_aead_algorithm_t ptls_openssl_chacha20poly1305 = {"CHACHA20-POLY1305",
                                                       &ptls_openssl_chacha20,
                                                       PTLS_CHACHA20_KEY_SIZE,
                                                       PTLS_CHACHA20POLY1305_IV_SIZE,
                                                       PTLS_CHACHA20POLY1305_TAG_SIZE,
                                                       sizeof(struct aead_crypto_context_t),
                                                       aead_chacha20poly1305_setup_crypto};
ptls_cipher_suite_t ptls_openssl_chacha20poly1305sha256 = {PTLS_CIPHER_SUITE_CHACHA20_POLY1305_SHA256,
                                                           &ptls_openssl_chacha20poly1305, &ptls_openssl_sha256};
#endif
ptls_cipher_suite_t *ptls_openssl_cipher_suites[] = {&ptls_openssl_aes256gcmsha384, &ptls_openssl_aes128gcmsha256,
#if defined(PTLS_OPENSSL_HAVE_CHACHA20_POLY1305)
                                                     &ptls_openssl_chacha20poly1305sha256,
#endif
                                                     NULL};
