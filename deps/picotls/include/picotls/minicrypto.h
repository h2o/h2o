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
#ifndef picotls_minicrypto_h
#define picotls_minicrypto_h

#ifdef __cplusplus
extern "C" {
#endif

#include "picotls.h"

#define SECP256R1_PRIVATE_KEY_SIZE 32
#define SECP256R1_PUBLIC_KEY_SIZE 65 /* including the header */
#define SECP256R1_SHARED_SECRET_SIZE 32

typedef struct st_ptls_minicrypto_secp256r1sha256_sign_certificate_t {
    ptls_sign_certificate_t super;
    uint8_t key[SECP256R1_PRIVATE_KEY_SIZE];
} ptls_minicrypto_secp256r1sha256_sign_certificate_t;

void ptls_minicrypto_random_bytes(void *buf, size_t len);

int ptls_minicrypto_init_secp256r1sha256_sign_certificate(ptls_minicrypto_secp256r1sha256_sign_certificate_t *self,
                                                          ptls_iovec_t key);

extern ptls_key_exchange_algorithm_t ptls_minicrypto_secp256r1, ptls_minicrypto_x25519;
extern ptls_key_exchange_algorithm_t *ptls_minicrypto_key_exchanges[];
extern ptls_cipher_algorithm_t ptls_minicrypto_aes128ecb, ptls_minicrypto_aes256ecb, ptls_minicrypto_aes128ctr,
    ptls_minicrypto_aes256ctr, ptls_minicrypto_chacha20;
extern ptls_aead_algorithm_t ptls_minicrypto_aes128gcm, ptls_minicrypto_aes256gcm, ptls_minicrypto_chacha20poly1305;
extern ptls_hash_algorithm_t ptls_minicrypto_sha256, ptls_minicrypto_sha384;
extern ptls_cipher_suite_t ptls_minicrypto_aes128gcmsha256, ptls_minicrypto_aes256gcmsha384, ptls_minicrypto_chacha20poly1305sha256;
extern ptls_cipher_suite_t *ptls_minicrypto_cipher_suites[];

typedef struct st_ptls_asn1_pkcs8_private_key_t {
    ptls_iovec_t vec;
    size_t algorithm_index;
    uint32_t algorithm_length;
    size_t parameters_index;
    uint32_t parameters_length;
    size_t key_data_index;
    uint32_t key_data_length;
} ptls_asn1_pkcs8_private_key_t;

int ptls_minicrypto_load_private_key(ptls_context_t *ctx, char const *pem_fname);

#ifdef __cplusplus
}
#endif

#endif
