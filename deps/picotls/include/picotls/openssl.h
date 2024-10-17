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

#if OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(OPENSSL_NO_CHACHA) && !defined(OPENSSL_NO_POLY1305)
#define PTLS_OPENSSL_HAVE_CHACHA20_POLY1305 1
#else
#define PTLS_OPENSSL_HAVE_CHACHA20_POLY1305 0
#endif

#if OPENSSL_VERSION_NUMBER >= 0x10100010L && !defined(LIBRESSL_VERSION_NUMBER) && \
    !defined(OPENSSL_NO_ASYNC)
#include <openssl/async.h>
#define PTLS_OPENSSL_HAVE_ASYNC 1
#else
#define PTLS_OPENSSL_HAVE_ASYNC 0
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
#ifdef EVP_PKEY_ED25519
#define PTLS_OPENSSL_HAVE_ED25519 1
#endif
#if defined(NID_X25519) && !defined(LIBRESSL_VERSION_NUMBER)
#define PTLS_OPENSSL_HAVE_X25519 1
#define PTLS_OPENSSL_HAS_X25519 1 /* deprecated; use HAVE_ */
extern ptls_key_exchange_algorithm_t ptls_openssl_x25519;
#else
#define PTLS_OPENSSL_HAVE_X25519 0
#define PTLS_OPENSSL_HAS_X25519 0 /* deprecated; use HAVE_ */
#endif

/* when boringssl is used, existence of libdecrepit is assumed */
#if !defined(OPENSSL_NO_BF) || defined(OPENSSL_IS_BORINGSSL)
#define PTLS_OPENSSL_HAVE_BF 1
#else
#define PTLS_OPENSSL_HAVE_BF 0
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
extern ptls_hash_algorithm_t ptls_openssl_sha512;
extern ptls_cipher_suite_t ptls_openssl_aes128gcmsha256;
extern ptls_cipher_suite_t ptls_openssl_aes256gcmsha384;
extern ptls_cipher_suite_t *ptls_openssl_cipher_suites[];
extern ptls_cipher_suite_t *ptls_openssl_cipher_suites_all[];
extern ptls_cipher_suite_t *ptls_openssl_tls12_cipher_suites[];

#if PTLS_OPENSSL_HAVE_CHACHA20_POLY1305
extern ptls_cipher_algorithm_t ptls_openssl_chacha20;
extern ptls_aead_algorithm_t ptls_openssl_chacha20poly1305;
extern ptls_cipher_suite_t ptls_openssl_chacha20poly1305sha256;
#endif

#ifdef PTLS_HAVE_AEGIS
extern ptls_aead_algorithm_t ptls_openssl_aegis128l;
extern ptls_aead_algorithm_t ptls_openssl_aegis256;
extern ptls_cipher_suite_t ptls_openssl_aegis128lsha256;
extern ptls_cipher_suite_t ptls_openssl_aegis256sha512;
#endif

extern ptls_cipher_suite_t ptls_openssl_tls12_ecdhe_rsa_aes128gcmsha256;
extern ptls_cipher_suite_t ptls_openssl_tls12_ecdhe_ecdsa_aes128gcmsha256;
extern ptls_cipher_suite_t ptls_openssl_tls12_ecdhe_rsa_aes256gcmsha384;
extern ptls_cipher_suite_t ptls_openssl_tls12_ecdhe_ecdsa_aes256gcmsha384;
#if PTLS_OPENSSL_HAVE_CHACHA20_POLY1305
extern ptls_cipher_suite_t ptls_openssl_tls12_ecdhe_rsa_chacha20poly1305sha256;
extern ptls_cipher_suite_t ptls_openssl_tls12_ecdhe_ecdsa_chacha20poly1305sha256;
#endif

#if PTLS_OPENSSL_HAVE_BF
extern ptls_cipher_algorithm_t ptls_openssl_bfecb;
#endif

extern ptls_hpke_kem_t ptls_openssl_hpke_kem_p256sha256;
extern ptls_hpke_kem_t ptls_openssl_hpke_kem_p384sha384;
#if PTLS_OPENSSL_HAVE_X25519
extern ptls_hpke_kem_t ptls_openssl_hpke_kem_x25519sha256;
#endif
extern ptls_hpke_kem_t *ptls_openssl_hpke_kems[];

extern ptls_hpke_cipher_suite_t ptls_openssl_hpke_aes128gcmsha256;
extern ptls_hpke_cipher_suite_t ptls_openssl_hpke_aes128gcmsha512;
extern ptls_hpke_cipher_suite_t ptls_openssl_hpke_aes256gcmsha384;
#if PTLS_OPENSSL_HAVE_CHACHA20_POLY1305
extern ptls_hpke_cipher_suite_t ptls_openssl_hpke_chacha20poly1305sha256;
#endif
extern ptls_hpke_cipher_suite_t *ptls_openssl_hpke_cipher_suites[];

void ptls_openssl_random_bytes(void *buf, size_t len);
/**
 * constructs a key exchange context. pkey's reference count is incremented.
 */
int ptls_openssl_create_key_exchange(ptls_key_exchange_context_t **ctx, EVP_PKEY *pkey);

typedef struct st_ptls_openssl_signature_scheme_t {
    uint16_t scheme_id;
    const EVP_MD *(*scheme_md)(void);
} ptls_openssl_signature_scheme_t;

/**
 * Given a private key, returns a list of compatible signature schemes. This list is terminated by scheme_id of UINT16_MAX.
 */
const ptls_openssl_signature_scheme_t *ptls_openssl_lookup_signature_schemes(EVP_PKEY *key);
/**
 * Given available schemes and input, choses one, or returns NULL if none is available.
 */
const ptls_openssl_signature_scheme_t *ptls_openssl_select_signature_scheme(const ptls_openssl_signature_scheme_t *available,
                                                                            const uint16_t *algorithms, size_t num_algorithms);

typedef struct st_ptls_openssl_sign_certificate_t {
    ptls_sign_certificate_t super;
    EVP_PKEY *key;
    const ptls_openssl_signature_scheme_t *schemes; /* terminated by .scheme_id == UINT16_MAX */
    /**
     * When set to true, indicates to the backend that the signature can be generated asynchronously. When the backend decides to
     * generate the signature asynchronously, `ptls_handshake` will return PTLS_ERROR_ASYNC_OPERATION. When receiving that error
     * code, the user should call `ptls_openssl_get_async_fd` to obtain the file descriptor that represents the asynchronous
     * operation and poll it for read. Once the file descriptor becomes readable, the user calls `ptls_handshake` once again to
     * obtain the handshake messages being generated, or call `ptls_free` to discard TLS state.
     */
    unsigned async : 1;
} ptls_openssl_sign_certificate_t;

int ptls_openssl_init_sign_certificate(ptls_openssl_sign_certificate_t *self, EVP_PKEY *key);
void ptls_openssl_dispose_sign_certificate(ptls_openssl_sign_certificate_t *self);
int ptls_openssl_load_certificates(ptls_context_t *ctx, X509 *cert, STACK_OF(X509) * chain);

typedef struct st_ptls_openssl_raw_pubkey_verify_certificate_t {
    ptls_verify_certificate_t super;
    EVP_PKEY *expected_pubkey;
} ptls_openssl_raw_pubkey_verify_certificate_t;

/**
 * When verifying the certificate chain, this optional callback can be used to store necessary information (e.g., client certificate
 * chain being provided) or to override the result.
 * To give an example, when `ptls_context_t::require_client_authentication` is set but the client does not provide a certificate,
 * the default behavior of the verifier is to reject the handshake. That can be overridden by supplying an overriding callback that
 * returns `0` (i.e., success) under such condition (as indicated by `ret == PTLS_ALERT_CERTIFICATE_REQUIRED`).
 */
PTLS_CALLBACK_TYPE(int, openssl_override_verify_certificate, ptls_t *tls, int ret, int ossl_ret, X509 *cert,
                   STACK_OF(X509) * chain);

typedef struct st_ptls_openssl_verify_certificate_t {
    ptls_verify_certificate_t super;
    X509_STORE *cert_store;
    ptls_openssl_override_verify_certificate_t *override_callback;
} ptls_openssl_verify_certificate_t;

int ptls_openssl_init_verify_certificate(ptls_openssl_verify_certificate_t *self, X509_STORE *store);
void ptls_openssl_dispose_verify_certificate(ptls_openssl_verify_certificate_t *self);
X509_STORE *ptls_openssl_create_default_certificate_store(void);

int ptls_openssl_raw_pubkey_init_verify_certificate(ptls_openssl_raw_pubkey_verify_certificate_t *self, EVP_PKEY *pubkey);
void ptls_openssl_raw_pubkey_dispose_verify_certificate(ptls_openssl_raw_pubkey_verify_certificate_t *self);

int ptls_openssl_encrypt_ticket(ptls_buffer_t *dst, ptls_iovec_t src,
                                int (*cb)(unsigned char *, unsigned char *, EVP_CIPHER_CTX *, HMAC_CTX *, int));
int ptls_openssl_decrypt_ticket(ptls_buffer_t *dst, ptls_iovec_t src,
                                int (*cb)(unsigned char *, unsigned char *, EVP_CIPHER_CTX *, HMAC_CTX *, int));

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
int ptls_openssl_encrypt_ticket_evp(ptls_buffer_t *dst, ptls_iovec_t src,
                                    int (*cb)(unsigned char *, unsigned char *, EVP_CIPHER_CTX *, EVP_MAC_CTX *, int));
int ptls_openssl_decrypt_ticket_evp(ptls_buffer_t *dst, ptls_iovec_t src,
                                    int (*cb)(unsigned char *, unsigned char *, EVP_CIPHER_CTX *, EVP_MAC_CTX *, int));
#endif

#ifdef __cplusplus
}
#endif

#endif
