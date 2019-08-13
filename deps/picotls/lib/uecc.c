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
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WINDOWS
#include "wincompat.h"
#else
#include <unistd.h>
#endif
#include "sha2.h"
#include "uECC.h"
#include "uECC_vli.h"
#include "picotls.h"
#include "picotls/minicrypto.h"

#define TYPE_UNCOMPRESSED_PUBLIC_KEY 4

struct st_secp256r1_key_exhchange_t {
    ptls_key_exchange_context_t super;
    uint8_t priv[SECP256R1_PRIVATE_KEY_SIZE];
    uint8_t pub[SECP256R1_PUBLIC_KEY_SIZE];
};

static int secp256r1_on_exchange(ptls_key_exchange_context_t **_ctx, int release, ptls_iovec_t *secret, ptls_iovec_t peerkey)
{
    struct st_secp256r1_key_exhchange_t *ctx = (struct st_secp256r1_key_exhchange_t *)*_ctx;
    uint8_t *secbytes = NULL;
    int ret;

    if (secret == NULL) {
        ret = 0;
        goto Exit;
    }

    if (peerkey.len != SECP256R1_PUBLIC_KEY_SIZE || peerkey.base[0] != TYPE_UNCOMPRESSED_PUBLIC_KEY) {
        ret = PTLS_ALERT_DECRYPT_ERROR;
        goto Exit;
    }
    if ((secbytes = (uint8_t *)malloc(SECP256R1_SHARED_SECRET_SIZE)) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }
    if (!uECC_shared_secret(peerkey.base + 1, ctx->priv, secbytes, uECC_secp256r1())) {
        ret = PTLS_ALERT_DECRYPT_ERROR;
        goto Exit;
    }
    *secret = ptls_iovec_init(secbytes, SECP256R1_SHARED_SECRET_SIZE);
    ret = 0;

Exit:
    if (ret != 0)
        free(secbytes);
    if (release) {
        ptls_clear_memory(ctx->priv, sizeof(ctx->priv));
        free(ctx);
        *_ctx = NULL;
    }
    return ret;
}

static int secp256r1_create_key_exchange(ptls_key_exchange_algorithm_t *algo, ptls_key_exchange_context_t **_ctx)
{
    struct st_secp256r1_key_exhchange_t *ctx;

    if ((ctx = (struct st_secp256r1_key_exhchange_t *)malloc(sizeof(*ctx))) == NULL)
        return PTLS_ERROR_NO_MEMORY;
    ctx->super = (ptls_key_exchange_context_t){algo, ptls_iovec_init(ctx->pub, sizeof(ctx->pub)), secp256r1_on_exchange};
    ctx->pub[0] = TYPE_UNCOMPRESSED_PUBLIC_KEY;
    uECC_make_key(ctx->pub + 1, ctx->priv, uECC_secp256r1());

    *_ctx = &ctx->super;
    return 0;
}

static int secp256r1_key_exchange(ptls_key_exchange_algorithm_t *algo, ptls_iovec_t *pubkey, ptls_iovec_t *secret,
                                  ptls_iovec_t peerkey)
{
    uint8_t priv[SECP256R1_PRIVATE_KEY_SIZE], *pub = NULL, *secbytes = NULL;
    int ret;

    if (peerkey.len != SECP256R1_PUBLIC_KEY_SIZE || peerkey.base[0] != TYPE_UNCOMPRESSED_PUBLIC_KEY) {
        ret = PTLS_ALERT_DECRYPT_ERROR;
        goto Exit;
    }
    if ((pub = malloc(SECP256R1_PUBLIC_KEY_SIZE)) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }
    if ((secbytes = malloc(SECP256R1_SHARED_SECRET_SIZE)) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }

    pub[0] = TYPE_UNCOMPRESSED_PUBLIC_KEY;
    uECC_make_key(pub + 1, priv, uECC_secp256r1());
    if (!uECC_shared_secret(peerkey.base + 1, priv, secbytes, uECC_secp256r1())) {
        ret = PTLS_ALERT_DECRYPT_ERROR;
        goto Exit;
    }
    *pubkey = ptls_iovec_init(pub, SECP256R1_PUBLIC_KEY_SIZE);
    *secret = ptls_iovec_init(secbytes, SECP256R1_SHARED_SECRET_SIZE);
    ret = 0;

Exit:
    ptls_clear_memory(priv, sizeof(priv));
    if (ret != 0) {
        free(secbytes);
        free(pub);
    }
    return ret;
}

static int secp256r1sha256_sign(ptls_sign_certificate_t *_self, ptls_t *tls, uint16_t *selected_algorithm, ptls_buffer_t *outbuf,
                                ptls_iovec_t input, const uint16_t *algorithms, size_t num_algorithms)
{
    ptls_minicrypto_secp256r1sha256_sign_certificate_t *self = (ptls_minicrypto_secp256r1sha256_sign_certificate_t *)_self;
    uint8_t hash[32], sig[64];
    size_t i;
    int ret;

    /* check algorithm */
    for (i = 0; i != num_algorithms; ++i)
        if (algorithms[i] == PTLS_SIGNATURE_ECDSA_SECP256R1_SHA256)
            break;
    if (i == num_algorithms)
        return PTLS_ALERT_HANDSHAKE_FAILURE;

    { /* calc hash */
        cf_sha256_context ctx;
        cf_sha256_init(&ctx);
        cf_sha256_update(&ctx, input.base, input.len);
        cf_sha256_digest_final(&ctx, hash);
        ptls_clear_memory(&ctx, sizeof(ctx));
    }

    /* sign */
    uECC_sign(self->key, hash, sizeof(hash), sig, uECC_secp256r1());

    /* encode using DER */
    ptls_buffer_push_asn1_sequence(outbuf, {
        if ((ret = ptls_buffer_push_asn1_ubigint(outbuf, sig, 32)) != 0)
            goto Exit;
        if ((ret = ptls_buffer_push_asn1_ubigint(outbuf, sig + 32, 32)) != 0)
            goto Exit;
    });

    *selected_algorithm = PTLS_SIGNATURE_ECDSA_SECP256R1_SHA256;
    ret = 0;

Exit:
    ptls_clear_memory(hash, sizeof(hash));
    ptls_clear_memory(sig, sizeof(sig));
    return ret;
}

int ptls_minicrypto_init_secp256r1sha256_sign_certificate(ptls_minicrypto_secp256r1sha256_sign_certificate_t *self,
                                                          ptls_iovec_t key)
{
    if (key.len != sizeof(self->key))
        return PTLS_ERROR_INCOMPATIBLE_KEY;

    self->super.cb = secp256r1sha256_sign;
    memcpy(self->key, key.base, sizeof(self->key));

    return 0;
}

ptls_key_exchange_algorithm_t ptls_minicrypto_secp256r1 = {PTLS_GROUP_SECP256R1, secp256r1_create_key_exchange,
                                                           secp256r1_key_exchange};
ptls_key_exchange_algorithm_t *ptls_minicrypto_key_exchanges[] = {&ptls_minicrypto_secp256r1, NULL};
