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

#include "picotls.h"

void ptls_minicrypto_random_bytes(void *buf, size_t len);

typedef struct st_ptls_minicrypto_lookup_certificate_t {
    ptls_lookup_certificate_t super;
    struct st_ptls_minicrypto_identity_t **identities;
    size_t count;
} ptls_minicrypto_lookup_certificate_t;

void ptls_minicrypto_init_lookup_certificate(ptls_minicrypto_lookup_certificate_t *self);
void ptls_minicrypto_dispose_lookup_certificate(ptls_minicrypto_lookup_certificate_t *self);
int ptls_minicrypto_lookup_certificate_add_identity(ptls_minicrypto_lookup_certificate_t *self, const char *server_name,
                                                    uint16_t signature_algorithm, ptls_iovec_t key, ptls_iovec_t *certs,
                                                    size_t num_certs);

extern ptls_key_exchange_algorithm_t ptls_minicrypto_secp256r1, ptls_minicrypto_x25519;
extern ptls_key_exchange_algorithm_t *ptls_minicrypto_key_exchanges[];
extern ptls_aead_algorithm_t ptls_minicrypto_aes128gcm;
extern ptls_hash_algorithm_t ptls_minicrypto_sha256;
extern ptls_cipher_suite_t ptls_minicrypto_aes128gcmsha256;
extern ptls_cipher_suite_t *ptls_minicrypto_cipher_suites[];

#endif
