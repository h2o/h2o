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

#ifdef __cplusplus
extern "C" {
#endif

#include <openssl/opensslv.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/x509.h>
#include <openssl/opensslconf.h>
#include "../picotls.h"

#if OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(LIBRESSL_VERSION_NUMBER)
#if !defined(OPENSSL_NO_CHACHA) && !defined(OPENSSL_NO_POLY1305)
#define PTLS_OPENSSL_HAVE_CHACHA20_POLY1305 1
#endif
#endif

extern ptls_key_exchange_algorithm_t ptls_openssl_secp256r1;
#ifdef NID_secp384r1
#define PTLS_OPENSSL_HAVE_SECP384R1 1
#define PTLS_OPENSSL_HAS_SECP384R1 1 /* deprecated; use HAVE_ */
extern ptls_key_exchange_algorithm_t ptls_openssl_secp384r1;
#endif
#ifdef NID_secp521r1
#define PTLS_OPENSSL_HAVE_SECP521R1 1
#define PTLS_OPENSSL_HAS_SECP521R1 1 /* deprecated; use HAVE_ */
extern ptls_key_exchange_algorithm_t ptls_openssl_secp521r1;
#endif
#if defined(NID_X25519) && !defined(LIBRESSL_VERSION_NUMBER)
#define PTLS_OPENSSL_HAVE_X25519 1
#define PTLS_OPENSSL_HAS_X25519 1  /* deprecated; use HAVE_ */
extern ptls_key_exchange_algorithm_t ptls_openssl_x25519;
#endif
#ifndef OPENSSL_NO_BF
#define PTLS_OPENSSL_HAVE_BF 1
#endif

extern ptls_key_exchange_algorithm_t *ptls_openssl_key_exchanges[];

extern ptls_cipher_algorithm_t ptls_openssl_aes128ecb;
extern ptls_cipher_algorithm_t ptls_openssl_aes128ctr;
extern ptls_aead_algorithm_t ptls_openssl_aes128gcm;
extern ptls_cipher_algorithm_t ptls_openssl_aes256ecb;
extern ptls_cipher_algorithm_t ptls_openssl_aes256ctr;
extern ptls_aead_algorithm_t ptls_openssl_aes256gcm;
extern ptls_hash_algorithm_t ptls_openssl_sha256;
extern ptls_hash_algorithm_t ptls_openssl_sha384;
extern ptls_cipher_suite_t ptls_openssl_aes128gcmsha256;
extern ptls_cipher_suite_t ptls_openssl_aes256gcmsha384;
extern ptls_cipher_suite_t *ptls_openssl_cipher_suites[];

#if defined(PTLS_OPENSSL_HAVE_CHACHA20_POLY1305)
extern ptls_cipher_algorithm_t ptls_openssl_chacha20;
extern ptls_aead_algorithm_t ptls_openssl_chacha20poly1305;
extern ptls_cipher_suite_t ptls_openssl_chacha20poly1305sha256;
#endif

#if PTLS_OPENSSL_HAVE_BF
extern ptls_cipher_algorithm_t ptls_openssl_bfecb;
#endif

void ptls_openssl_random_bytes(void *buf, size_t len);
/**
 * constructs a key exchange context. pkey's reference count is incremented.
 */
int ptls_openssl_create_key_exchange(ptls_key_exchange_context_t **ctx, EVP_PKEY *pkey);

struct st_ptls_openssl_signature_scheme_t {
    uint16_t scheme_id;
    const EVP_MD *scheme_md;
};

typedef struct st_ptls_openssl_sign_certificate_t {
    ptls_sign_certificate_t super;
    EVP_PKEY *key;
    struct st_ptls_openssl_signature_scheme_t schemes[4]; /* terminated by .scheme_id == UINT16_MAX */
} ptls_openssl_sign_certificate_t;

int ptls_openssl_init_sign_certificate(ptls_openssl_sign_certificate_t *self, EVP_PKEY *key);
void ptls_openssl_dispose_sign_certificate(ptls_openssl_sign_certificate_t *self);
int ptls_openssl_load_certificates(ptls_context_t *ctx, X509 *cert, STACK_OF(X509) * chain);

typedef struct st_ptls_openssl_verify_certificate_t {
    ptls_verify_certificate_t super;
    X509_STORE *cert_store;
} ptls_openssl_verify_certificate_t;

int ptls_openssl_init_verify_certificate(ptls_openssl_verify_certificate_t *self, X509_STORE *store);
void ptls_openssl_dispose_verify_certificate(ptls_openssl_verify_certificate_t *self);
X509_STORE *ptls_openssl_create_default_certificate_store(void);

int ptls_openssl_encrypt_ticket(ptls_buffer_t *dst, ptls_iovec_t src,
                                int (*cb)(unsigned char *, unsigned char *, EVP_CIPHER_CTX *, HMAC_CTX *, int));
int ptls_openssl_decrypt_ticket(ptls_buffer_t *dst, ptls_iovec_t src,
                                int (*cb)(unsigned char *, unsigned char *, EVP_CIPHER_CTX *, HMAC_CTX *, int));

#ifdef __cplusplus
}
#endif

#endif
