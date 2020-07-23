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

#ifndef _WINDOWS
/* This module is only defined for windows.
 * It is an implementation of the main crypto algorithms
 * using windows crypto libraries */

int ptls_bcrypt_init()
{
    return -1;
}

void ptlc_bcrypt_dispose()
{
}

#else

#include "wincompat.h"
#include <bcrypt.h>
#include "picotls.h"

/**
 * Initialize the brcrypt libraries, creates the
 * required common variables, etc. */
int ptls_bcrypt_init()
{
    return 0;
}

/**
 * Clear the initialization of the bcrypt libraries */

void ptlc_bcrypt_dispose()
{
}

/**
 * Random number generation */

void ptls_bcrypt_random_bytes(void *buf, size_t len)
{
    /* TODO: Crypto gen random */
}

/*
 * Support for symmetric ciphers
*/

struct ptls_bcrypt_symmetric_param_t {
    HANDLE hKey;
    DWORD dwFlags;
    ULONG cbKeyObject;
    uint8_t iv[PTLS_MAX_IV_SIZE];
    uint8_t *key_object;
    int is_enc;
};

struct ptls_bcrypt_symmetric_context_t {
    ptls_cipher_context_t super;
    struct ptls_bcrypt_symmetric_param_t bctx;
};

static void ptls_bcrypt_cipher_init_ctr(ptls_cipher_context_t *_ctx, const void *iv)
{
    struct ptls_bcrypt_symmetric_context_t *ctx = (struct ptls_bcrypt_symmetric_context_t *)_ctx;
    /* Copy the IV to inside structure */
    if (iv != NULL) {
        memcpy(ctx->bctx.iv, iv, ctx->super.algo->block_size);
    } else {
        memset(ctx->bctx.iv, 0, ctx->super.algo->block_size);
    }
}

static void ptls_bcrypt_cipher_dispose(ptls_cipher_context_t *_ctx)
{
    struct ptls_bcrypt_symmetric_context_t *ctx = (struct ptls_bcrypt_symmetric_context_t *)_ctx;

    if (ctx->bctx.hKey != NULL) {
        (void)BCryptDestroyKey(ctx->bctx.hKey);
    }

    if (ctx->bctx.key_object != NULL) {
        free(ctx->bctx.key_object);
    }

    memset(&ctx->bctx, 0, sizeof(struct ptls_bcrypt_symmetric_param_t));
}

static void ptls_bcrypt_cipher_transform_ecb(ptls_cipher_context_t *_ctx, void *output, const void *input, size_t len)
{
    struct ptls_bcrypt_symmetric_context_t *ctx = (struct ptls_bcrypt_symmetric_context_t *)_ctx;
    ULONG cbResult;
    NTSTATUS ret;

    assert((len % ctx->super.algo->block_size) == 0);

    /* Call the encryption */
    if (ctx->bctx.is_enc) {
        ret = BCryptEncrypt(ctx->bctx.hKey, (PUCHAR)input, (ULONG)len, NULL, NULL, 0, output, (ULONG)len, &cbResult, 0);
    } else {
        ret = BCryptDecrypt(ctx->bctx.hKey, (PUCHAR)input, (ULONG)len, NULL, NULL, 0, output, (ULONG)len, &cbResult, 0);
    }

    assert(BCRYPT_SUCCESS(ret));

    if (!BCRYPT_SUCCESS(ret)) {
        memset(output, 0, cbResult);
    }
}

static void ptls_bcrypt_cipher_transform_ctr(ptls_cipher_context_t *_ctx, void *output, const void *input, size_t len)
{
    struct ptls_bcrypt_symmetric_context_t *ctx = (struct ptls_bcrypt_symmetric_context_t *)_ctx;
    ULONG cbResult;
    NTSTATUS ret;
    uint8_t eiv[PTLS_MAX_IV_SIZE];
    int i;
    uint64_t seq = 0;
    size_t processed = 0;
    uint8_t const *v_in = input;
    uint8_t *v_out = output;

    assert(ctx->super.algo->block_size > 0);
    assert(ctx->super.algo->block_size <= PTLS_MAX_IV_SIZE);

    while (processed < len) {

        ret = BCryptEncrypt(ctx->bctx.hKey, (PUCHAR)ctx->bctx.iv, (ULONG)ctx->super.algo->block_size, NULL, NULL, 0, eiv,
                            (ULONG)(ULONG)ctx->super.algo->block_size, &cbResult, 0);
        assert(BCRYPT_SUCCESS(ret));

        if (BCRYPT_SUCCESS(ret)) {
            for (i = 0; processed < len && i < ctx->super.algo->block_size; i++, processed++) {
                v_out[processed] = v_in[processed] ^ eiv[i];
            }

            /* Increment the iv block */
            i = (int)ctx->super.algo->block_size - 1;
            while (i >= 0) {
                ctx->bctx.iv[i] += 1;
                if (ctx->bctx.iv[i] > 0) {
                    break;
                }
                i--;
            }
        }
    }
}

static int ptls_bcrypt_cipher_setup_crypto(ptls_cipher_context_t *_ctx, int is_enc, const void *key, wchar_t const *bcrypt_name,
                                           int is_ctr)
{
    struct ptls_bcrypt_symmetric_context_t *ctx = (struct ptls_bcrypt_symmetric_context_t *)_ctx;
    HANDLE hAlgorithm = NULL;
    NTSTATUS ret;

    memset(&ctx->bctx, 0, sizeof(struct ptls_bcrypt_symmetric_param_t));

    ret = BCryptOpenAlgorithmProvider(&hAlgorithm, bcrypt_name, NULL, 0);

    if (BCRYPT_SUCCESS(ret)) {
        DWORD ko_size = 0;
        ULONG cbResult = 0;

        ret = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, (PUCHAR)&ko_size, (ULONG)sizeof(ko_size), &cbResult, 0);

        if (BCRYPT_SUCCESS(ret)) {
            ctx->bctx.key_object = (uint8_t *)malloc(ko_size);
            if (ctx->bctx.key_object == NULL) {
                ret = STATUS_NO_MEMORY;
            } else {
                ctx->bctx.cbKeyObject = ko_size;
            }
        }
    }

    if (BCRYPT_SUCCESS(ret)) {
        ret = BCryptSetProperty(hAlgorithm, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_ECB, sizeof(BCRYPT_CHAIN_MODE_ECB), 0);
    }

    if (BCRYPT_SUCCESS(ret)) {
        ret = BCryptGenerateSymmetricKey(hAlgorithm, &ctx->bctx.hKey, ctx->bctx.key_object, ctx->bctx.cbKeyObject, (PUCHAR)key,
                                         (ULONG)ctx->super.algo->key_size, 0);
    }

    if (hAlgorithm != NULL) {
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
    }

    if (BCRYPT_SUCCESS(ret)) {

        ctx->super.do_dispose = ptls_bcrypt_cipher_dispose;
        if (is_ctr) {
            ctx->super.do_init = ptls_bcrypt_cipher_init_ctr;
            ctx->super.do_transform = ptls_bcrypt_cipher_transform_ctr;
        } else {
            ctx->super.do_init = NULL; 
            ctx->super.do_transform = ptls_bcrypt_cipher_transform_ecb;
        }
        ctx->bctx.is_enc = is_enc;
        return 0;
    } else {
        ptls_bcrypt_cipher_dispose(_ctx);
        return PTLS_ERROR_LIBRARY;
    }
}

static int ptls_bcrypt_cipher_setup_crypto_aes_ecb(ptls_cipher_context_t *_ctx, int is_enc, const void *key)
{
    return ptls_bcrypt_cipher_setup_crypto(_ctx, is_enc, key, BCRYPT_AES_ALGORITHM, 0);
}

static int ptls_bcrypt_cipher_setup_crypto_aes_ctr(ptls_cipher_context_t *_ctx, int is_enc, const void *key)
{
    return ptls_bcrypt_cipher_setup_crypto(_ctx, is_enc, key, BCRYPT_AES_ALGORITHM, 1);
}


/* Picotls assumes that AEAD encryption works as:
 * - an "init" call that prepares the encryption context.
 * - a series of "update" calls that encrypt segments of the message
 * - a "final" call that completes the encryption.
 *
 * In Bcrypt, the update calls will be implemented as a series of calls
 * to BCryptEncrypt. The state necessary to pass these calls is provided
 * to the Bcrypt function in two parameters:
 *  - the "padding info" points to a BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO
 *    structure
 *  - the "IV" parameter points to a buffer holding intermediate updates
 *    of the IV. That buffer shall be initialize to zero before the 
 *    first call.
 * The documentation of the AEAD mode on MSDN is slightly obscure, and
 * also slightly wrong. After trial and errors and web searches, we find
 * that:
 *  - the Nonce parameter (pbNonce, cbNonce) points to the initial
 *    vector for the encryption, as passed by Picotls. Picotls combines
 *    per session IV and sequence number in that nonce prior to the call.
 *  - The Authdata parameter (pbAuthData, cbAuthData) points to the
 *    authenticated data passed to the API as aad, aadlen.
 *  - The cbAAd parameter contains the length of auth data that needs
 *    to be processed. It is initialized before the first call.
 *  - The tag parameter (pbTag, cbTag) points to a buffer that
 *    holds intermediate tag values during chaining. The size must be
 *    the size of the tag for the algorithm. It must be
 *    initialized to zero before first call.
 *  - The Mac Context parameter (pbMacContext, cbMacContext) contains
 *    a working buffer for the computation of the tag. The size
 *    must be the maxLength parameter returned retrieved in the 
 *    BCRYPT_AUTH_TAG_LENGTH property of the algorithm. It must be
 *    initialized to zero before first call.
 *  - The dwflag parameters must be set to 
 *    BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG on first call. (The
 *    MSDN documentation says BCRYPT_AUTH_MODE_IN_PROGRESS_FLAG,
 *    but that's an error.)
 *
 * The members of the BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO struct
 * should not be modified between calls, except for:
 *  - the BCRYPT_AUTH_MODE_IN_PROGRESS_FLAG should be cleared
 *    before the final call.
 *
 * The Picotls API does not constrain the length of the segments
 * passed in the "update" calls, but BCryptEncrypt will fail with
 * error STATUS_INVALID_BUFFER_SIZE if the length passed in the
 * chained calls is not an integer multiple of block size. This forces
 * us to maintain an intermediate buffer of "extra bytes".
 *    
 */

struct ptls_bcrypt_aead_param_t {
    HANDLE hKey;
    ULONG cbKeyObject;
    ULONG maxTagLength;
    ULONG nbExtraBytes;
    uint8_t *key_object;
    uint8_t iv_static[PTLS_MAX_IV_SIZE];
    uint8_t extraBytes[PTLS_MAX_DIGEST_SIZE];
    uint8_t iv[PTLS_MAX_IV_SIZE];
    uint8_t ivbuf[PTLS_MAX_IV_SIZE];
    uint8_t tag[PTLS_MAX_DIGEST_SIZE];
    uint8_t auth_tag[PTLS_MAX_DIGEST_SIZE];
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO aead_params;
};

struct ptls_bcrypt_aead_context_t {
    struct st_ptls_aead_context_t super;
    struct ptls_bcrypt_aead_param_t bctx;
};

static void ptls_bcrypt_aead_dispose_crypto(struct st_ptls_aead_context_t *_ctx)
{
    struct ptls_bcrypt_aead_context_t *ctx = (struct ptls_bcrypt_aead_context_t *)_ctx;

    if (ctx->bctx.hKey != NULL) {
        (void)BCryptDestroyKey(ctx->bctx.hKey);
    }

    if (ctx->bctx.key_object != NULL) {
        free(ctx->bctx.key_object);
    }

    memset(&ctx->bctx, 0, sizeof(struct ptls_bcrypt_aead_param_t));
}

static void ptls_bcrypt_aead_do_encrypt_init(struct st_ptls_aead_context_t *_ctx, uint64_t seq, const void *aad, size_t aadlen)
{
    struct ptls_bcrypt_aead_context_t *ctx = (struct ptls_bcrypt_aead_context_t *)_ctx;

    /* Build the IV for this encryption */
    ptls_aead__build_iv(ctx->super.algo, ctx->bctx.iv, ctx->bctx.iv_static, seq);
    /* Auth tag to NULL */
    memset(ctx->bctx.tag, 0, sizeof(ctx->super.algo->tag_size));
    BCRYPT_INIT_AUTH_MODE_INFO(ctx->bctx.aead_params);

    assert(ctx->super.algo->iv_size <= sizeof(ctx->bctx.ivbuf));
    assert(ctx->super.algo->tag_size <= sizeof(ctx->bctx.tag));
    assert(ctx->bctx.maxTagLength <= sizeof(ctx->bctx.auth_tag));

    memset(ctx->bctx.ivbuf, 0, ctx->super.algo->iv_size);
    memset(ctx->bctx.tag, 0, ctx->super.algo->tag_size);
    memset(ctx->bctx.auth_tag, 0, sizeof(ctx->bctx.auth_tag));

    ctx->bctx.nbExtraBytes = 0;

    ctx->bctx.aead_params.pbNonce = (PUCHAR)&ctx->bctx.iv;
    ctx->bctx.aead_params.cbNonce = (ULONG)ctx->super.algo->iv_size;
    ctx->bctx.aead_params.pbAuthData = (PUCHAR)aad;
    ctx->bctx.aead_params.cbAuthData = (ULONG)aadlen;
    ctx->bctx.aead_params.pbTag = (PUCHAR)ctx->bctx.tag;
    ctx->bctx.aead_params.cbTag = (ULONG) ctx->super.algo->tag_size;
    // ctx->bctx.aead_params.cbAAD = (ULONG)aadlen;
    ctx->bctx.aead_params.pbMacContext = (PUCHAR) ctx->bctx.auth_tag;
    ctx->bctx.aead_params.cbMacContext = (ULONG)ctx->bctx.maxTagLength;
    ctx->bctx.aead_params.dwFlags = BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG;
}

static size_t ptls_bcrypt_aead_do_encrypt_update(struct st_ptls_aead_context_t *_ctx, void *output, const void *input, size_t inlen)
{
    struct ptls_bcrypt_aead_context_t *ctx = (struct ptls_bcrypt_aead_context_t *)_ctx;
    size_t outlenMax = inlen + ctx->super.algo->tag_size + ctx->bctx.nbExtraBytes;
    ULONG cbResult1 = 0;
    ULONG cbResult2 = 0;
    NTSTATUS ret;

    /* If there are extra bytes, complement and encrypt */
    if (ctx->bctx.nbExtraBytes > 0) {
        ULONG requiredBytes = (ULONG)(ctx->super.algo->ecb_cipher->block_size - ctx->bctx.nbExtraBytes);

        if (inlen < requiredBytes) {
            memcpy(&ctx->bctx.extraBytes[ctx->bctx.nbExtraBytes], input, inlen);
            ctx->bctx.nbExtraBytes += (ULONG) inlen;
            inlen = 0;
        } else {
            memcpy(&ctx->bctx.extraBytes[ctx->bctx.nbExtraBytes], input, requiredBytes);
            inlen -= requiredBytes;
            input = (void*)(((uint8_t *)input) + requiredBytes);
            ret = BCryptEncrypt(ctx->bctx.hKey, (PUCHAR)ctx->bctx.extraBytes, (ULONG)ctx->super.algo->ecb_cipher->block_size,
                                (void *)&ctx->bctx.aead_params, ctx->bctx.ivbuf, (ULONG)ctx->super.algo->iv_size, output, (ULONG)outlenMax, &cbResult1, 0);

            assert(BCRYPT_SUCCESS(ret));
            if (!BCRYPT_SUCCESS(ret)) {
                memset(output, 0, cbResult1);
            }
            outlenMax -= cbResult1;
            output = (void *)(((uint8_t *)output) + cbResult1);
        }
    }

    /* If there are trailing bytes, store them in the extra bytes */
    ctx->bctx.nbExtraBytes = (ULONG)(inlen % ctx->super.algo->ecb_cipher->block_size);
    if (ctx->bctx.nbExtraBytes > 0) {
        inlen -= ctx->bctx.nbExtraBytes;
        memcpy(&ctx->bctx.extraBytes, (void *)(((uint8_t *)input) + inlen), ctx->bctx.nbExtraBytes);
    }

    if (inlen > 0) {
        ret = BCryptEncrypt(ctx->bctx.hKey, (PUCHAR)input, (ULONG)inlen, (void *)&ctx->bctx.aead_params, ctx->bctx.ivbuf,
                            (ULONG)ctx->super.algo->iv_size, output, (ULONG)outlenMax, &cbResult2, 0);
        assert(BCRYPT_SUCCESS(ret));

        if (!BCRYPT_SUCCESS(ret)) {
            memset(output, 0, cbResult2);
        }
    }
    return (size_t)cbResult1 + cbResult2;
}

static size_t ptls_bcrypt_aead_do_encrypt_final(struct st_ptls_aead_context_t *_ctx, void *output)
{
    struct ptls_bcrypt_aead_context_t *ctx = (struct ptls_bcrypt_aead_context_t *)_ctx;
    size_t outlenMax = ctx->super.algo->tag_size + ctx->bctx.nbExtraBytes;
    ULONG cbResult = 0;
    NTSTATUS ret;

    ctx->bctx.aead_params.dwFlags &= ~BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG;

    ret = BCryptEncrypt(ctx->bctx.hKey, (PUCHAR)ctx->bctx.extraBytes, (ULONG)ctx->bctx.nbExtraBytes, (void *)&ctx->bctx.aead_params, ctx->bctx.ivbuf,
                        (ULONG)ctx->super.algo->iv_size, output, (ULONG)outlenMax, &cbResult, 0);
    assert(BCRYPT_SUCCESS(ret));

    if (BCRYPT_SUCCESS(ret)) {
        /* Find the tag in the aead parameters and append it to the output */
        assert(cbResult + ctx->bctx.aead_params.cbTag <= outlenMax);
        memcpy(((uint8_t *)output) + cbResult, ctx->bctx.aead_params.pbTag, ctx->bctx.aead_params.cbTag);
        cbResult += ctx->bctx.aead_params.cbTag;
    }
    return cbResult;
}

static size_t ptls_bcrypt_aead_do_decrypt(struct st_ptls_aead_context_t *_ctx, void *output, const void *input, size_t inlen,
                                          uint64_t seq, const void *aad, size_t aadlen)
{
    struct ptls_bcrypt_aead_context_t *ctx = (struct ptls_bcrypt_aead_context_t *)_ctx;
    ULONG cbResult;
    size_t textLen = inlen - ctx->super.algo->tag_size;
    NTSTATUS ret;

    /* Build the IV for this decryption */
    ptls_aead__build_iv(ctx->super.algo, ctx->bctx.iv, ctx->bctx.iv_static, seq);

    /* TODO: pPaddingInfo must point to BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO structure. */
    BCRYPT_INIT_AUTH_MODE_INFO(ctx->bctx.aead_params);
    /* TODO: find clarity on handling of ivbuf */
    memset(ctx->bctx.tag, 0, sizeof(ctx->super.algo->tag_size));
    ctx->bctx.aead_params.pbNonce = (PUCHAR)&ctx->bctx.iv;
    ctx->bctx.aead_params.cbNonce = (ULONG)ctx->super.algo->iv_size;
    ctx->bctx.aead_params.pbAuthData = (PUCHAR)aad;
    ctx->bctx.aead_params.cbAuthData = (ULONG)aadlen;
    ctx->bctx.aead_params.pbTag = (PUCHAR)(((uint8_t *)input) + textLen);
    ctx->bctx.aead_params.cbTag = (ULONG)(ULONG)ctx->super.algo->tag_size;

    /* Call the decryption */
    ret = BCryptDecrypt(ctx->bctx.hKey, (PUCHAR)input, (ULONG)textLen, (void *)&ctx->bctx.aead_params,
                        NULL, 0, (PUCHAR)output, (ULONG)textLen, &cbResult, 0);

    if (BCRYPT_SUCCESS(ret)) {
        return (size_t)cbResult;
    } else {
        return SIZE_MAX;
    }
}

static int ptls_bcrypt_aead_setup_crypto(ptls_aead_context_t *_ctx, int is_enc, const void *key, 
    const void * iv, wchar_t const *bcrypt_name, wchar_t const *bcrypt_mode, size_t bcrypt_mode_size)
{
    struct ptls_bcrypt_aead_context_t *ctx = (struct ptls_bcrypt_aead_context_t *)_ctx;
    HANDLE hAlgorithm = NULL;
    NTSTATUS ret;

    memset(&ctx->bctx, 0, sizeof(struct ptls_bcrypt_symmetric_param_t));

    ret = BCryptOpenAlgorithmProvider(&hAlgorithm, bcrypt_name, NULL, 0);

    if (BCRYPT_SUCCESS(ret)) {
        ret = BCryptSetProperty(hAlgorithm, BCRYPT_CHAINING_MODE, (PBYTE)bcrypt_mode, (ULONG)bcrypt_mode_size, 0);
    }

    if (BCRYPT_SUCCESS(ret)) {
        DWORD ko_size = 0;
        ULONG cbResult = 0;

        ret = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, (PUCHAR)&ko_size, (ULONG)sizeof(ko_size), &cbResult, 0);

        if (BCRYPT_SUCCESS(ret)) {
            ctx->bctx.key_object = (uint8_t *)malloc(ko_size);
            if (ctx->bctx.key_object == NULL) {
                ret = STATUS_NO_MEMORY;
            } else {
                ctx->bctx.cbKeyObject = ko_size;
            }
        }
    }

    if (BCRYPT_SUCCESS(ret)) {
        BCRYPT_KEY_LENGTHS_STRUCT atl_st;
        ULONG cbResult = 0;

        ret = BCryptGetProperty(hAlgorithm, BCRYPT_AUTH_TAG_LENGTH, (PUCHAR)&atl_st, (ULONG)sizeof(atl_st), &cbResult, 0);
        if (BCRYPT_SUCCESS(ret)) {
            ctx->bctx.maxTagLength = atl_st.dwMaxLength;
        }
    }

    if (BCRYPT_SUCCESS(ret)) {
        ret = BCryptGenerateSymmetricKey(hAlgorithm, &ctx->bctx.hKey, ctx->bctx.key_object, ctx->bctx.cbKeyObject, (PUCHAR)key,
                                         (ULONG)ctx->super.algo->key_size, 0);
    }

    if (hAlgorithm != NULL) {
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
    }

    if (BCRYPT_SUCCESS(ret)) {
        memcpy(ctx->bctx.iv_static, iv, ctx->super.algo->iv_size);
        if (is_enc) {
            ctx->super.dispose_crypto = ptls_bcrypt_aead_dispose_crypto;
            ctx->super.do_decrypt = NULL;
            ctx->super.do_encrypt_init = ptls_bcrypt_aead_do_encrypt_init;
            ctx->super.do_encrypt_update = ptls_bcrypt_aead_do_encrypt_update;
            ctx->super.do_encrypt_final = ptls_bcrypt_aead_do_encrypt_final;
            ctx->super.do_encrypt = ptls_aead__do_encrypt;
        } else {
            ctx->super.dispose_crypto = ptls_bcrypt_aead_dispose_crypto;
            ctx->super.do_decrypt = ptls_bcrypt_aead_do_decrypt;
            ctx->super.do_encrypt_init = NULL;
            ctx->super.do_encrypt_update = NULL;
            ctx->super.do_encrypt_final = NULL;
        }
        return 0;
    } else {
        ptls_bcrypt_aead_dispose_crypto(_ctx);
        return PTLS_ERROR_LIBRARY;
    }
}

static int ptls_bcrypt_aead_setup_crypto_aesgcm(ptls_aead_context_t *_ctx, int is_enc, const void *key, const void * iv)
{
    return ptls_bcrypt_aead_setup_crypto(_ctx, is_enc, key, iv, BCRYPT_AES_ALGORITHM, BCRYPT_CHAIN_MODE_GCM,
                                         sizeof(BCRYPT_CHAIN_MODE_GCM));
}

/* Hash algorithms */

struct st_ptls_bcrypt_hash_param_t {
    wchar_t const *bcrypt_name;
    BCRYPT_HASH_HANDLE hHash;
    PUCHAR pbHashObject;
    ULONG cbHashObject;
    ULONG hash_size;
    int has_error;
};

struct st_ptls_bcrypt_hash_context_t {
    ptls_hash_context_t super;
    struct st_ptls_bcrypt_hash_param_t ctx;
};

static void ptls_bcrypt_hash_update(struct st_ptls_hash_context_t *_ctx, const void *src, size_t len)
{
    struct st_ptls_bcrypt_hash_context_t *ctx = (struct st_ptls_bcrypt_hash_context_t *)_ctx;
    NTSTATUS ret = BCryptHashData(ctx->ctx.hHash, (PUCHAR)src, (ULONG)len, 0);
    assert(BCRYPT_SUCCESS(ret));

    if (!BCRYPT_SUCCESS(ret)) {
        ctx->ctx.has_error = 1;
    }
}

static struct st_ptls_bcrypt_hash_context_t *ptls_bcrypt_hash_context_free(struct st_ptls_bcrypt_hash_context_t *ctx)
{
    if (ctx->ctx.pbHashObject != NULL) {
        ptls_clear_memory(ctx->ctx.pbHashObject, ctx->ctx.cbHashObject);
        free(ctx->ctx.pbHashObject);
    }
    ptls_clear_memory(&ctx->ctx, sizeof(ctx->ctx));

    return NULL;
}

static ptls_hash_context_t *ptls_bcrypt_hash_clone(struct st_ptls_hash_context_t *_ctx);

static void ptls_bcrypt_hash_final(struct st_ptls_hash_context_t *_ctx, void *md, ptls_hash_final_mode_t mode)
{
    if (mode == PTLS_HASH_FINAL_MODE_SNAPSHOT) {
        /* TODO: Copying handle does not change the handle! */
        struct st_ptls_hash_context_t *clone_ctx = ptls_bcrypt_hash_clone(_ctx);

        if (clone_ctx != NULL) {
            ptls_bcrypt_hash_final(clone_ctx, md, PTLS_HASH_FINAL_MODE_FREE);
        } else {
            assert(clone_ctx != NULL);
        }
    } else {
        NTSTATUS ret;
        struct st_ptls_bcrypt_hash_context_t *ctx = (struct st_ptls_bcrypt_hash_context_t *)_ctx;

        if (md != NULL) {
            ret = BCryptFinishHash(ctx->ctx.hHash, md, ctx->ctx.hash_size, 0);
            assert(BCRYPT_SUCCESS(ret));
            if (!BCRYPT_SUCCESS(ret) || ctx->ctx.has_error) {
                memset(md, 0, ctx->ctx.hash_size);
            }
        }

        ret = BCryptDestroyHash(ctx->ctx.hHash);
        assert(BCRYPT_SUCCESS(ret));

        switch (mode) {
        case PTLS_HASH_FINAL_MODE_FREE:
            ctx = ptls_bcrypt_hash_context_free(ctx);
            break;
        case PTLS_HASH_FINAL_MODE_RESET: {
            BCRYPT_ALG_HANDLE hAlgorithm = NULL;
            ret = BCryptOpenAlgorithmProvider(&hAlgorithm, ctx->ctx.bcrypt_name, NULL, 0);
            if (BCRYPT_SUCCESS(ret)) {
                ctx->ctx.hHash = NULL;
                ret = BCryptCreateHash(hAlgorithm, &ctx->ctx.hHash, ctx->ctx.pbHashObject, ctx->ctx.cbHashObject, NULL, 0, 0);
                BCryptCloseAlgorithmProvider(hAlgorithm, 0);
            }
            assert(BCRYPT_SUCCESS(ret));
            if (!BCRYPT_SUCCESS(ret)) {
                ctx->ctx.hHash = NULL;   
            }
            break;
        }
        default:
            assert(!"FIXME");
            break;
        }
    }
}

static ptls_hash_context_t *ptls_bcrypt_hash_clone(struct st_ptls_hash_context_t *_ctx)
{
    struct st_ptls_bcrypt_hash_context_t *ctx = (struct st_ptls_bcrypt_hash_context_t *)_ctx;
    struct st_ptls_bcrypt_hash_context_t *clone_ctx;

    if ((clone_ctx = (struct st_ptls_bcrypt_hash_context_t *)malloc(sizeof(*ctx))) != NULL) {
        NTSTATUS ret;

        ptls_clear_memory(&clone_ctx->ctx, sizeof(clone_ctx->ctx));
        clone_ctx->super = (ptls_hash_context_t){ptls_bcrypt_hash_update, ptls_bcrypt_hash_final, ptls_bcrypt_hash_clone};
        clone_ctx->ctx.pbHashObject = (uint8_t *)malloc(ctx->ctx.cbHashObject);
        clone_ctx->ctx.cbHashObject = ctx->ctx.cbHashObject;
        clone_ctx->ctx.bcrypt_name = ctx->ctx.bcrypt_name;
        clone_ctx->ctx.hash_size = ctx->ctx.hash_size;
        clone_ctx->ctx.has_error = ctx->ctx.has_error;

        if (clone_ctx->ctx.pbHashObject == NULL) {
            ret = STATUS_NO_MEMORY;
        } else {
            clone_ctx->ctx.hHash = NULL;
            ptls_clear_memory(&clone_ctx->ctx.pbHashObject, clone_ctx->ctx.cbHashObject);
            ret = BCryptDuplicateHash(ctx->ctx.hHash, &clone_ctx->ctx.hHash, clone_ctx->ctx.pbHashObject,
                                      clone_ctx->ctx.cbHashObject, 0);
        }

        if (!BCRYPT_SUCCESS(ret)) {
            clone_ctx = ptls_bcrypt_hash_context_free(clone_ctx);
        }
    }

    return (ptls_hash_context_t *)clone_ctx;
}

static ptls_hash_context_t *ptls_bcrypt_hash_create(wchar_t const *bcrypt_name, ULONG hash_size)
{
    BCRYPT_ALG_HANDLE hAlgorithm = NULL;
    NTSTATUS ret;
    struct st_ptls_bcrypt_hash_context_t *ctx;

    if ((ctx = (struct st_ptls_bcrypt_hash_context_t *)malloc(sizeof(*ctx))) != NULL) {
        ctx->super = (ptls_hash_context_t){ptls_bcrypt_hash_update, ptls_bcrypt_hash_final, ptls_bcrypt_hash_clone};
        memset(&ctx->ctx, 0, sizeof(struct st_ptls_bcrypt_hash_param_t));
        ctx->ctx.hash_size = hash_size;
        ctx->ctx.bcrypt_name = bcrypt_name;

        ret = BCryptOpenAlgorithmProvider(&hAlgorithm, bcrypt_name, NULL, 0);

        if (BCRYPT_SUCCESS(ret)) {
            DWORD hb_length = 0;
            ULONG cbResult = 0;

            ret = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, (PUCHAR)&hb_length, (ULONG)sizeof(hb_length), &cbResult, 0);

            if (BCRYPT_SUCCESS(ret)) {
                ctx->ctx.pbHashObject = (uint8_t *)malloc(hb_length);
                if (ctx->ctx.pbHashObject == NULL) {
                    ret = STATUS_NO_MEMORY;
                } else {
                    ctx->ctx.cbHashObject = hb_length;
                }
            }
        }

        if (BCRYPT_SUCCESS(ret)) {
            ret = BCryptCreateHash(hAlgorithm, &ctx->ctx.hHash, ctx->ctx.pbHashObject, ctx->ctx.cbHashObject, NULL, 0, 0);
        }

        if (!BCRYPT_SUCCESS(ret)) {
            ctx = ptls_bcrypt_hash_context_free(ctx);
        }
    }

    if (hAlgorithm != NULL) {
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
    }

    return (ptls_hash_context_t *)ctx;
}

static ptls_hash_context_t *ptls_bcrypt_sha256_create(void)
{
    return ptls_bcrypt_hash_create(BCRYPT_SHA256_ALGORITHM, PTLS_SHA256_DIGEST_SIZE);
}

static ptls_hash_context_t *ptls_bcrypt_sha384_create(void)
{
    return ptls_bcrypt_hash_create(BCRYPT_SHA384_ALGORITHM, PTLS_SHA384_DIGEST_SIZE);
}

/* Declaration of algorithms
 */

ptls_cipher_algorithm_t ptls_bcrypt_aes128ecb = {"AES128-ECB",
                                                 PTLS_AES128_KEY_SIZE,
                                                 PTLS_AES_BLOCK_SIZE,
                                                 0 /* iv size */,
                                                 sizeof(struct ptls_bcrypt_symmetric_context_t),
                                                 ptls_bcrypt_cipher_setup_crypto_aes_ecb};
ptls_cipher_algorithm_t ptls_bcrypt_aes256ecb = {"AES256-ECB",
                                                 PTLS_AES256_KEY_SIZE,
                                                 PTLS_AES_BLOCK_SIZE,
                                                 0 /* iv size */,
                                                 sizeof(struct ptls_bcrypt_symmetric_context_t),
                                                 ptls_bcrypt_cipher_setup_crypto_aes_ecb};

ptls_cipher_algorithm_t ptls_bcrypt_aes128ctr = {"AES128-CTR",
                                                 PTLS_AES128_KEY_SIZE,
                                                 PTLS_AES_BLOCK_SIZE,
                                                 0 /* iv size */,
                                                 sizeof(struct ptls_bcrypt_symmetric_context_t),
                                                 ptls_bcrypt_cipher_setup_crypto_aes_ctr};

ptls_cipher_algorithm_t ptls_bcrypt_aes256ctr = {"AES256-CTR",
                                                 PTLS_AES256_KEY_SIZE,
                                                 PTLS_AES_BLOCK_SIZE,
                                                 0 /* iv size */,
                                                 sizeof(struct ptls_bcrypt_symmetric_context_t),
                                                 ptls_bcrypt_cipher_setup_crypto_aes_ctr};

ptls_aead_algorithm_t ptls_bcrypt_aes128gcm = {"AES128-GCM",
                                               &ptls_bcrypt_aes128ecb,
                                               &ptls_bcrypt_aes128ctr,
                                               PTLS_AES128_KEY_SIZE,
                                               PTLS_AESGCM_IV_SIZE,
                                               PTLS_AESGCM_TAG_SIZE,
                                               sizeof(struct ptls_bcrypt_aead_context_t),
                                               ptls_bcrypt_aead_setup_crypto_aesgcm};

ptls_aead_algorithm_t ptls_bcrypt_aes256gcm = {"AES256-GCM",
                                               &ptls_bcrypt_aes256ecb,
                                               &ptls_bcrypt_aes256ctr,
                                               PTLS_AES256_KEY_SIZE,
                                               PTLS_AESGCM_IV_SIZE,
                                               PTLS_AESGCM_TAG_SIZE,
                                               sizeof(struct ptls_bcrypt_aead_context_t),
                                               ptls_bcrypt_aead_setup_crypto_aesgcm};

ptls_hash_algorithm_t ptls_bcrypt_sha256 = {PTLS_SHA256_BLOCK_SIZE, PTLS_SHA256_DIGEST_SIZE, ptls_bcrypt_sha256_create,
                                            PTLS_ZERO_DIGEST_SHA256};
ptls_hash_algorithm_t ptls_bcrypt_sha384 = {PTLS_SHA384_BLOCK_SIZE, PTLS_SHA384_DIGEST_SIZE, ptls_bcrypt_sha384_create,
                                            PTLS_ZERO_DIGEST_SHA384};

ptls_cipher_suite_t ptls_bcrypt_aes128gcmsha256 = {PTLS_CIPHER_SUITE_AES_128_GCM_SHA256, &ptls_bcrypt_aes128gcm,
                                                   &ptls_bcrypt_sha256};
ptls_cipher_suite_t ptls_bcrypt_aes256gcmsha384 = {PTLS_CIPHER_SUITE_AES_256_GCM_SHA384, &ptls_bcrypt_aes256gcm,
                                                   &ptls_bcrypt_sha384};

#ifdef PRLS_BCRYPT_TODO
/* TODO: develp these bcrypt functions */
ptls_key_exchange_algorithm_t ptls_bcrypt_secp256r1 = {PTLS_GROUP_SECP256R1, x9_62_create_key_exchange, secp_key_exchange,
                                                       NID_X9_62_prime256v1};
#if ptls_bcrypt_HAVE_SECP384R1
ptls_key_exchange_algorithm_t ptls_bcrypt_secp384r1 = {PTLS_GROUP_SECP384R1, x9_62_create_key_exchange, secp_key_exchange,
                                                       NID_secp384r1};
#endif
#if ptls_bcrypt_HAVE_SECP521R1
ptls_key_exchange_algorithm_t ptls_bcrypt_secp521r1 = {PTLS_GROUP_SECP521R1, x9_62_create_key_exchange, secp_key_exchange,
                                                       NID_secp521r1};
#endif
#if ptls_bcrypt_HAVE_X25519
ptls_key_exchange_algorithm_t ptls_bcrypt_x25519 = {PTLS_GROUP_X25519, evp_keyex_create, evp_keyex_exchange, NID_X25519};
#endif

ptls_key_exchange_algorithm_t *ptls_bcrypt_key_exchanges[] = {&ptls_bcrypt_secp256r1, NULL};
#endif

#endif /* _WINDOWS */