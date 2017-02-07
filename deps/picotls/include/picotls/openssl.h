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
#ifndef picotls_openssl_h
#define picotls_openssl_h

#include <openssl/evp.h>
#include <openssl/x509.h>
#include "picotls.h"

extern ptls_key_exchange_algorithm_t ptls_openssl_secp256r1;
extern ptls_key_exchange_algorithm_t *ptls_openssl_key_exchanges[];
extern ptls_aead_algorithm_t ptls_openssl_aes128gcm;
extern ptls_hash_algorithm_t ptls_openssl_sha256;
extern ptls_cipher_suite_t ptls_openssl_aes128gcmsha256;
extern ptls_cipher_suite_t *ptls_openssl_cipher_suites[];

void ptls_openssl_random_bytes(void *buf, size_t len);

struct st_ptls_openssl_identity_t {
    ptls_iovec_t name;
    EVP_PKEY *key;
    size_t num_certs;
    ptls_iovec_t certs[1];
};

typedef struct st_ptls_openssl_lookup_certificate_t {
    ptls_lookup_certificate_t super;
    struct st_ptls_openssl_identity_t **identities;
    size_t count;
} ptls_openssl_lookup_certificate_t;

void ptls_openssl_init_lookup_certificate(ptls_openssl_lookup_certificate_t *self);
void ptls_openssl_dispose_lookup_certificate(ptls_openssl_lookup_certificate_t *self);
int ptls_openssl_lookup_certificate_add_identity(ptls_openssl_lookup_certificate_t *self, const char *server_name, EVP_PKEY *key,
                                                 STACK_OF(X509) * certs);
typedef struct st_ptls_openssl_verify_certificate_t {
    ptls_verify_certificate_t super;
    X509_STORE *cert_store;
} ptls_openssl_verify_certificate_t;

#define PTLS_OPENSSL_DEFAULT_CERTIFICATE_STORE ((X509_STORE *)1)

int ptls_openssl_init_verify_certificate(ptls_openssl_verify_certificate_t *self, X509_STORE *store);
void ptls_openssl_dispose_verify_certificate(ptls_openssl_verify_certificate_t *self);

#endif
