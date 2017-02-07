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
#include <unistd.h>
#include "sha2.h"
#include "uECC.h"
#include "uECC_vli.h"
#include "picotls.h"
#include "picotls/minicrypto.h"

#define SECP256R1_PRIVATE_KEY_SIZE 32
#define SECP256R1_PUBLIC_KEY_SIZE 65 /* including the header */
#define SECP256R1_SHARED_SECRET_SIZE 32

#define TYPE_UNCOMPRESSED_PUBLIC_KEY 4

struct st_secp256r1_key_exhchange_t {
    ptls_key_exchange_context_t super;
    uint8_t priv[SECP256R1_PRIVATE_KEY_SIZE];
    uint8_t pub[SECP256R1_PUBLIC_KEY_SIZE];
};

static int secp256r1_on_exchange(ptls_key_exchange_context_t **_ctx, ptls_iovec_t *secret, ptls_iovec_t peerkey)
{
    struct st_secp256r1_key_exhchange_t *ctx = (struct st_secp256r1_key_exhchange_t *)*_ctx;
    uint8_t *secbytes = NULL;
    int ret;

    *_ctx = NULL;

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
    ptls_clear_memory(ctx->priv, sizeof(ctx->priv));
    free(ctx);
    return ret;
}

static int secp256r1_create_key_exchange(ptls_key_exchange_context_t **_ctx, ptls_iovec_t *pubkey)
{
    struct st_secp256r1_key_exhchange_t *ctx;

    if ((ctx = (struct st_secp256r1_key_exhchange_t *)malloc(sizeof(*ctx))) == NULL)
        return PTLS_ERROR_NO_MEMORY;
    ctx->super = (ptls_key_exchange_context_t){secp256r1_on_exchange};
    ctx->pub[0] = TYPE_UNCOMPRESSED_PUBLIC_KEY;
    uECC_make_key(ctx->pub + 1, ctx->priv, uECC_secp256r1());

    *_ctx = &ctx->super;
    *pubkey = ptls_iovec_init(ctx->pub, sizeof(ctx->pub));
    return 0;
}

static int secp256r1_key_exchange(ptls_iovec_t *pubkey, ptls_iovec_t *secret, ptls_iovec_t peerkey)
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

struct st_ptls_minicrypto_identity_t {
    ptls_iovec_t name;
    uint8_t key[SECP256R1_PRIVATE_KEY_SIZE];
    size_t num_certs;
    ptls_iovec_t certs[1];
};

static void free_identity(struct st_ptls_minicrypto_identity_t *identity)
{
    size_t i;
    free(identity->name.base);
    for (i = 0; i != identity->num_certs; ++i)
        free(identity->certs[i].base);
    ptls_clear_memory(identity->key, sizeof(identity->key));
    free(identity);
}

static int ascii_tolower(int ch)
{
    return ('A' <= ch && ch <= 'Z') ? ch + 0x20 : ch;
}

static int ascii_streq_caseless(ptls_iovec_t x, ptls_iovec_t y)
{
    size_t i;
    if (x.len != y.len)
        return 0;
    for (i = 0; i != x.len; ++i)
        if (ascii_tolower(x.base[i]) != ascii_tolower(y.base[i]))
            return 0;
    return 0;
}

static int secp256r1sha256_sign(void *data, ptls_buffer_t *outbuf, ptls_iovec_t input)
{
    uint8_t hash[32], sig[64];
    int ret;

    { /* calc hash */
        cf_sha256_context ctx;
        cf_sha256_init(&ctx);
        cf_sha256_update(&ctx, input.base, input.len);
        cf_sha256_digest_final(&ctx, hash);
        ptls_clear_memory(&ctx, sizeof(ctx));
    }

    /* sign */
    uECC_sign(data, hash, sizeof(hash), sig, uECC_secp256r1());

    /* encode using DER */
    ptls_buffer_push_asn1_sequence(outbuf, {
        if ((ret = ptls_buffer_push_asn1_ubigint(outbuf, sig, 32)) != 0)
            goto Exit;
        if ((ret = ptls_buffer_push_asn1_ubigint(outbuf, sig + 32, 32)) != 0)
            goto Exit;
    });

    ret = 0;

Exit:
    ptls_clear_memory(hash, sizeof(hash));
    ptls_clear_memory(sig, sizeof(sig));
    return ret;
}

static int lookup_certificate(ptls_lookup_certificate_t *_self, ptls_t *tls, uint16_t *sign_algorithm,
                              int (**signer)(void *sign_ctx, ptls_buffer_t *outbuf, ptls_iovec_t input), void **signer_data,
                              ptls_iovec_t **certs, size_t *num_certs, const char *server_name,
                              const uint16_t *signature_algorithms, size_t num_signature_algorithms)
{
    ptls_minicrypto_lookup_certificate_t *self = (ptls_minicrypto_lookup_certificate_t *)_self;
    struct st_ptls_minicrypto_identity_t *identity;
    size_t i;

    if (self->count == 0)
        return PTLS_ALERT_HANDSHAKE_FAILURE;

    for (i = 0; i != num_signature_algorithms; ++i)
        if (signature_algorithms[i] == PTLS_SIGNATURE_ECDSA_SECP256R1_SHA256)
            goto FoundMatchingSig;
    return PTLS_ALERT_HANDSHAKE_FAILURE;

FoundMatchingSig:
    if (server_name != NULL) {
        size_t server_name_len = strlen(server_name);
        for (i = 0; i != self->count; ++i) {
            identity = self->identities[i];
            if (ascii_streq_caseless(ptls_iovec_init(server_name, server_name_len), identity->name))
                goto FoundIdentity;
        }
    }
    identity = self->identities[0]; /* use default */

FoundIdentity:
    /* setup the rest */
    *sign_algorithm = PTLS_SIGNATURE_ECDSA_SECP256R1_SHA256;
    *signer = secp256r1sha256_sign;
    *signer_data = identity->key;
    *certs = identity->certs;
    *num_certs = identity->num_certs;

    return 0;
}

void ptls_minicrypto_init_lookup_certificate(ptls_minicrypto_lookup_certificate_t *self)
{
    *self = (ptls_minicrypto_lookup_certificate_t){{lookup_certificate}};
}

void ptls_minicrypto_dispose_lookup_certificate(ptls_minicrypto_lookup_certificate_t *self)
{
    size_t i;
    for (i = 0; i != self->count; ++i)
        free_identity(self->identities[i]);
}

int ptls_minicrypto_lookup_certificate_add_identity(ptls_minicrypto_lookup_certificate_t *self, const char *server_name,
                                                    uint16_t signature_algorithm, ptls_iovec_t key, ptls_iovec_t *certs,
                                                    size_t num_certs)
{
    struct st_ptls_minicrypto_identity_t *identity = NULL, **list;
    int ret;

    /* check args */
    if (!(signature_algorithm == PTLS_SIGNATURE_ECDSA_SECP256R1_SHA256 && key.len == sizeof(identity->key))) {
        ret = PTLS_ERROR_INCOMPATIBLE_KEY;
        goto Exit;
    }

    /* create new identity object */
    if ((identity = (struct st_ptls_minicrypto_identity_t *)malloc(offsetof(struct st_ptls_minicrypto_identity_t, certs) +
                                                                   sizeof(identity->certs[0]) * num_certs)) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }
    *identity = (struct st_ptls_minicrypto_identity_t){{NULL}};
    if ((identity->name.base = (uint8_t *)strdup(server_name)) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }
    identity->name.len = strlen(server_name);
    memcpy(identity->key, key.base, key.len);
    for (; identity->num_certs != num_certs; ++identity->num_certs) {
        if ((identity->certs[identity->num_certs].base = (uint8_t *)malloc(certs[identity->num_certs].len)) == NULL) {
            ret = PTLS_ERROR_NO_MEMORY;
            goto Exit;
        }
        memcpy(identity->certs[identity->num_certs].base, certs[identity->num_certs].base, certs[identity->num_certs].len);
        identity->certs[identity->num_certs].len = certs[identity->num_certs].len;
    }

    /* add to the list */
    if ((list = realloc(self->identities, sizeof(self->identities[0]) * (self->count + 1))) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }
    self->identities = list;
    self->identities[self->count++] = identity;

    ret = 0;
Exit:
    if (ret != 0 && identity != NULL)
        free_identity(identity);
    return ret;
}

ptls_key_exchange_algorithm_t ptls_minicrypto_secp256r1 = {PTLS_GROUP_SECP256R1, secp256r1_create_key_exchange,
                                                           secp256r1_key_exchange};
ptls_key_exchange_algorithm_t *ptls_minicrypto_key_exchanges[] = {&ptls_minicrypto_secp256r1, NULL};
