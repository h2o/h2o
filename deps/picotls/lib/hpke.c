/*
 * Copyright (c) 2022 Fastly, Kazuho Oku
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
#include "picotls.h"

#define HPKE_V1_LABEL "HPKE-v1"

static int build_suite_id(ptls_buffer_t *buf, ptls_hpke_kem_t *kem, ptls_hpke_cipher_suite_t *cipher)
{
    int ret;

    if (cipher == NULL) {
        ptls_buffer_pushv(buf, "KEM", 3);
        ptls_buffer_push16(buf, kem->id);
    } else {
        ptls_buffer_pushv(buf, "HPKE", 4);
        ptls_buffer_push16(buf, kem->id);
        ptls_buffer_push16(buf, cipher->id.kdf);
        ptls_buffer_push16(buf, cipher->id.aead);
    }

    ret = 0;

Exit:
    return ret;
}

static int labeled_extract(ptls_hpke_kem_t *kem, ptls_hpke_cipher_suite_t *cipher, void *output, ptls_iovec_t salt,
                           const char *label, ptls_iovec_t ikm)
{
    ptls_buffer_t labeled_ikm;
    uint8_t labeled_ikm_smallbuf[64];
    int ret;

    ptls_buffer_init(&labeled_ikm, labeled_ikm_smallbuf, sizeof(labeled_ikm_smallbuf));

    ptls_buffer_pushv(&labeled_ikm, HPKE_V1_LABEL, strlen(HPKE_V1_LABEL));
    if ((ret = build_suite_id(&labeled_ikm, kem, cipher)) != 0)
        goto Exit;
    ptls_buffer_pushv(&labeled_ikm, label, strlen(label));
    ptls_buffer_pushv(&labeled_ikm, ikm.base, ikm.len);

    ret = ptls_hkdf_extract(cipher != NULL ? cipher->hash : kem->hash, output, salt,
                            ptls_iovec_init(labeled_ikm.base, labeled_ikm.off));

Exit:
    ptls_buffer_dispose(&labeled_ikm);
    return ret;
}

static int labeled_expand(ptls_hpke_kem_t *kem, ptls_hpke_cipher_suite_t *cipher, void *output, size_t outlen, ptls_iovec_t prk,
                          const char *label, ptls_iovec_t info)
{
    ptls_buffer_t labeled_info;
    uint8_t labeled_info_smallbuf[64];
    int ret;

    assert(outlen < UINT16_MAX);

    ptls_buffer_init(&labeled_info, labeled_info_smallbuf, sizeof(labeled_info_smallbuf));

    ptls_buffer_push16(&labeled_info, (uint16_t)outlen);
    ptls_buffer_pushv(&labeled_info, HPKE_V1_LABEL, strlen(HPKE_V1_LABEL));
    if ((ret = build_suite_id(&labeled_info, kem, cipher)) != 0)
        goto Exit;
    ptls_buffer_pushv(&labeled_info, label, strlen(label));
    ptls_buffer_pushv(&labeled_info, info.base, info.len);

    ret = ptls_hkdf_expand(cipher != NULL ? cipher->hash : kem->hash, output, outlen, prk,
                           ptls_iovec_init(labeled_info.base, labeled_info.off));

Exit:
    ptls_buffer_dispose(&labeled_info);
    return ret;
}

static int extract_and_expand(ptls_hpke_kem_t *kem, void *secret, size_t secret_len, ptls_iovec_t pk_s, ptls_iovec_t pk_r,
                              ptls_iovec_t dh)
{
    ptls_buffer_t kem_context;
    uint8_t kem_context_smallbuf[128], eae_prk[PTLS_MAX_DIGEST_SIZE];
    int ret;

    ptls_buffer_init(&kem_context, kem_context_smallbuf, sizeof(kem_context_smallbuf));

    ptls_buffer_pushv(&kem_context, pk_s.base, pk_s.len);
    ptls_buffer_pushv(&kem_context, pk_r.base, pk_r.len);

    if ((ret = labeled_extract(kem, NULL, eae_prk, ptls_iovec_init("", 0), "eae_prk", dh)) != 0)
        goto Exit;
    if ((ret = labeled_expand(kem, NULL, secret, secret_len, ptls_iovec_init(eae_prk, kem->hash->digest_size), "shared_secret",
                              ptls_iovec_init(kem_context.base, kem_context.off))) != 0)
        goto Exit;

Exit:
    ptls_buffer_dispose(&kem_context);
    ptls_clear_memory(eae_prk, sizeof(eae_prk));
    return ret;
}

static int dh_derive(ptls_hpke_kem_t *kem, void *secret, ptls_iovec_t pk_s, ptls_iovec_t pk_r, ptls_iovec_t dh)
{
    return extract_and_expand(kem, secret, kem->hash->digest_size, pk_s, pk_r, dh);
}

static int dh_encap(ptls_hpke_kem_t *kem, void *secret, ptls_iovec_t *pk_s, ptls_iovec_t pk_r)
{
    ptls_iovec_t dh = {NULL};
    int ret;

    *pk_s = ptls_iovec_init(NULL, 0);

    if ((ret = kem->keyex->exchange(kem->keyex, pk_s, &dh, pk_r)) != 0)
        goto Exit;

    if ((ret = dh_derive(kem, secret, *pk_s, pk_r, dh)) != 0)
        goto Exit;

Exit:
    if (dh.base != NULL) {
        ptls_clear_memory(dh.base, dh.len);
        free(dh.base);
    }
    if (ret != 0) {
        free(pk_s->base);
        *pk_s = ptls_iovec_init(NULL, 0);
    }
    return ret;
}

static int dh_decap(ptls_hpke_kem_t *kem, void *secret, ptls_key_exchange_context_t *keyex, ptls_iovec_t pk_s, ptls_iovec_t pk_r)
{
    ptls_iovec_t dh = {NULL};
    int ret;

    if ((ret = keyex->on_exchange(&keyex, 0, &dh, pk_s)) != 0)
        goto Exit;

    if ((ret = dh_derive(kem, secret, pk_s, pk_r, dh)) != 0)
        goto Exit;

Exit:
    if (dh.base != NULL) {
        ptls_clear_memory(dh.base, dh.len);
        free(dh.base);
    }
    return ret;
}

#include <stdio.h>

static int key_schedule(ptls_hpke_kem_t *kem, ptls_hpke_cipher_suite_t *cipher, ptls_aead_context_t **ctx, int is_enc,
                        const void *shared_secret, ptls_iovec_t info)
{
    ptls_buffer_t key_schedule_context;
    uint8_t key_schedule_context_smallbuf[128], secret[PTLS_MAX_DIGEST_SIZE], key[PTLS_MAX_SECRET_SIZE],
        base_nonce[PTLS_MAX_IV_SIZE];
    int ret;

    *ctx = NULL;

    ptls_buffer_init(&key_schedule_context, key_schedule_context_smallbuf, sizeof(key_schedule_context_smallbuf));

    /* key_schedule_context = concat(mode, LabeledExtract("", "psk_id_hash", psk_id), LabeledExtract("", "info_hash", info)) */
    ptls_buffer_push(&key_schedule_context, PTLS_HPKE_MODE_BASE);
    if ((ret = ptls_buffer_reserve(&key_schedule_context, cipher->hash->digest_size)) != 0 ||
        (ret = labeled_extract(kem, cipher, key_schedule_context.base + key_schedule_context.off, ptls_iovec_init(NULL, 0),
                               "psk_id_hash", ptls_iovec_init(NULL, 0))) != 0)
        goto Exit;
    key_schedule_context.off += cipher->hash->digest_size;
    if ((ret = ptls_buffer_reserve(&key_schedule_context, cipher->hash->digest_size)) != 0 ||
        (ret = labeled_extract(kem, cipher, key_schedule_context.base + key_schedule_context.off, ptls_iovec_init(NULL, 0),
                               "info_hash", info)) != 0)
        goto Exit;
    key_schedule_context.off += cipher->hash->digest_size;

    /* secret = LabeledExtract(shared_secret, "secret", psk) */
    if ((ret = labeled_extract(kem, cipher, secret, ptls_iovec_init(shared_secret, kem->hash->digest_size), "secret",
                               ptls_iovec_init("", 0))) != 0)
        goto Exit;

    /* key, base_nonce */
    if ((ret = labeled_expand(kem, cipher, key, cipher->aead->key_size, ptls_iovec_init(secret, cipher->hash->digest_size), "key",
                              ptls_iovec_init(key_schedule_context.base, key_schedule_context.off))) != 0)
        goto Exit;
    if ((ret = labeled_expand(kem, cipher, base_nonce, cipher->aead->iv_size, ptls_iovec_init(secret, cipher->hash->digest_size),
                              "base_nonce", ptls_iovec_init(key_schedule_context.base, key_schedule_context.off))) != 0)
        goto Exit;

    *ctx = ptls_aead_new_direct(cipher->aead, is_enc, key, base_nonce);

Exit:
    ptls_buffer_dispose(&key_schedule_context);
    ptls_clear_memory(secret, sizeof(secret));
    ptls_clear_memory(key, sizeof(key));
    ptls_clear_memory(base_nonce, sizeof(base_nonce));
    return ret;
}

int ptls_hpke_setup_base_s(ptls_hpke_kem_t *kem, ptls_hpke_cipher_suite_t *cipher, ptls_iovec_t *pk_s, ptls_aead_context_t **ctx,
                           ptls_iovec_t pk_r, ptls_iovec_t info)
{
    uint8_t secret[PTLS_MAX_DIGEST_SIZE];
    int ret;

    *pk_s = ptls_iovec_init(NULL, 0);

    if ((ret = dh_encap(kem, secret, pk_s, pk_r)) != 0)
        goto Exit;

    if ((ret = key_schedule(kem, cipher, ctx, 1, secret, info)) != 0)
        goto Exit;

Exit:
    if (ret != 0 && pk_s->len != 0) {
        ptls_clear_memory(pk_s->base, pk_s->len);
        free(pk_s->base);
        *pk_s = ptls_iovec_init(NULL, 0);
    }
    ptls_clear_memory(secret, sizeof(secret));
    return ret;
}

int ptls_hpke_setup_base_r(ptls_hpke_kem_t *kem, ptls_hpke_cipher_suite_t *cipher, ptls_key_exchange_context_t *keyex,
                           ptls_aead_context_t **ctx, ptls_iovec_t pk_s, ptls_iovec_t info)
{
    uint8_t secret[PTLS_MAX_DIGEST_SIZE];
    int ret;

    if ((ret = dh_decap(kem, secret, keyex, pk_s, keyex->pubkey)) != 0)
        goto Exit;

    if ((ret = key_schedule(kem, cipher, ctx, 0, secret, info)) != 0)
        goto Exit;

Exit:
    ptls_clear_memory(secret, sizeof(secret));
    return ret;
}
