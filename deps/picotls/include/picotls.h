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
#ifndef picotls_h
#define picotls_h

#ifdef __cplusplus
extern "C" {
#endif

#include <assert.h>
#include <inttypes.h>
#include <sys/types.h>

#define PTLS_AES128_KEY_SIZE 16
#define PTLS_AES256_KEY_SIZE 32
#define PTLS_AES_IV_SIZE 16
#define PTLS_AESGCM_IV_SIZE 12
#define PTLS_AESGCM_TAG_SIZE 16

#define PTLS_CHACHA20_KEY_SIZE 32
#define PTLS_CHACHA20_IV_SIZE 16
#define PTLS_CHACHA20POLY1305_IV_SIZE 12
#define PTLS_CHACHA20POLY1305_TAG_SIZE 16

#define PTLS_SHA256_BLOCK_SIZE 64
#define PTLS_SHA256_DIGEST_SIZE 32

#define PTLS_SHA384_BLOCK_SIZE 128
#define PTLS_SHA384_DIGEST_SIZE 48

#define PTLS_MAX_SECRET_SIZE 32
#define PTLS_MAX_IV_SIZE 16
#define PTLS_MAX_DIGEST_SIZE 64

/* cipher-suites */
#define PTLS_CIPHER_SUITE_AES_128_GCM_SHA256 0x1301
#define PTLS_CIPHER_SUITE_AES_256_GCM_SHA384 0x1302
#define PTLS_CIPHER_SUITE_CHACHA20_POLY1305_SHA256 0x1303

/* negotiated_groups */
#define PTLS_GROUP_SECP256R1 23
#define PTLS_GROUP_X25519 29

/* signature algorithms */
#define PTLS_SIGNATURE_RSA_PKCS1_SHA1 0x0201
#define PTLS_SIGNATURE_RSA_PKCS1_SHA256 0x0401
#define PTLS_SIGNATURE_ECDSA_SECP256R1_SHA256 0x0403
#define PTLS_SIGNATURE_ECDSA_SECP384R1_SHA384 0x0503
#define PTLS_SIGNATURE_ECDSA_SECP521R1_SHA512 0x0603
#define PTLS_SIGNATURE_RSA_PSS_RSAE_SHA256 0x0804
#define PTLS_SIGNATURE_RSA_PSS_RSAE_SHA384 0x0805
#define PTLS_SIGNATURE_RSA_PSS_RSAE_SHA512 0x0806

/* error classes and macros */
#define PTLS_ERROR_CLASS_SELF_ALERT 0
#define PTLS_ERROR_CLASS_PEER_ALERT 0x100
#define PTLS_ERROR_CLASS_INTERNAL 0x200

#define PTLS_ERROR_GET_CLASS(e) ((e) & ~0xff)
#define PTLS_ALERT_TO_SELF_ERROR(e) ((e) + PTLS_ERROR_CLASS_SELF_ALERT)
#define PTLS_ALERT_TO_PEER_ERROR(e) ((e) + PTLS_ERROR_CLASS_PEER_ALERT)
#define PTLS_ERROR_TO_ALERT(e) ((e)&0xff)

/* alerts */
#define PTLS_ALERT_LEVEL_WARNING 1
#define PTLS_ALERT_LEVEL_FATAL 2

#define PTLS_ALERT_CLOSE_NOTIFY 0
#define PTLS_ALERT_UNEXPECTED_MESSAGE 10
#define PTLS_ALERT_BAD_RECORD_MAC 20
#define PTLS_ALERT_HANDSHAKE_FAILURE 40
#define PTLS_ALERT_BAD_CERTIFICATE 42
#define PTLS_ALERT_CERTIFICATE_REVOKED 44
#define PTLS_ALERT_CERTIFICATE_EXPIRED 45
#define PTLS_ALERT_CERTIFICATE_UNKNOWN 46
#define PTLS_ALERT_ILLEGAL_PARAMETER 47
#define PTLS_ALERT_DECODE_ERROR 50
#define PTLS_ALERT_DECRYPT_ERROR 51
#define PTLS_ALERT_PROTOCOL_VERSION 70
#define PTLS_ALERT_INTERNAL_ERROR 80
#define PTLS_ALERT_USER_CANCELED 90
#define PTLS_ALERT_MISSING_EXTENSION 109
#define PTLS_ALERT_UNRECOGNIZED_NAME 112
#define PTLS_ALERT_NO_APPLICATION_PROTOCOL 120

/* internal errors */
#define PTLS_ERROR_NO_MEMORY (PTLS_ERROR_CLASS_INTERNAL + 1)
#define PTLS_ERROR_IN_PROGRESS (PTLS_ERROR_CLASS_INTERNAL + 2)
#define PTLS_ERROR_LIBRARY (PTLS_ERROR_CLASS_INTERNAL + 3)
#define PTLS_ERROR_INCOMPATIBLE_KEY (PTLS_ERROR_CLASS_INTERNAL + 4)
#define PTLS_ERROR_SESSION_NOT_FOUND (PTLS_ERROR_CLASS_INTERNAL + 5)
#define PTLS_ERROR_STATELESS_RETRY (PTLS_ERROR_CLASS_INTERNAL + 6)

#define PTLS_ERROR_INCORRECT_BASE64 (PTLS_ERROR_CLASS_INTERNAL + 50)
#define PTLS_ERROR_PEM_LABEL_NOT_FOUND (PTLS_ERROR_CLASS_INTERNAL + 51)
#define PTLS_ERROR_BER_INCORRECT_ENCODING (PTLS_ERROR_CLASS_INTERNAL + 52)
#define PTLS_ERROR_BER_MALFORMED_TYPE (PTLS_ERROR_CLASS_INTERNAL + 53)
#define PTLS_ERROR_BER_MALFORMED_LENGTH (PTLS_ERROR_CLASS_INTERNAL + 54)
#define PTLS_ERROR_BER_EXCESSIVE_LENGTH (PTLS_ERROR_CLASS_INTERNAL + 55)
#define PTLS_ERROR_BER_ELEMENT_TOO_SHORT (PTLS_ERROR_CLASS_INTERNAL + 56)
#define PTLS_ERROR_BER_UNEXPECTED_EOC (PTLS_ERROR_CLASS_INTERNAL + 57)
#define PTLS_ERROR_DER_INDEFINITE_LENGTH (PTLS_ERROR_CLASS_INTERNAL + 58)
#define PTLS_ERROR_INCORRECT_ASN1_SYNTAX (PTLS_ERROR_CLASS_INTERNAL + 59)
#define PTLS_ERROR_INCORRECT_PEM_KEY_VERSION (PTLS_ERROR_CLASS_INTERNAL + 60)
#define PTLS_ERROR_INCORRECT_PEM_ECDSA_KEY_VERSION (PTLS_ERROR_CLASS_INTERNAL + 61)
#define PTLS_ERROR_INCORRECT_PEM_ECDSA_CURVE (PTLS_ERROR_CLASS_INTERNAL + 62)
#define PTLS_ERROR_INCORRECT_PEM_ECDSA_KEYSIZE (PTLS_ERROR_CLASS_INTERNAL + 63)
#define PTLS_ERROR_INCORRECT_ASN1_ECDSA_KEY_SYNTAX (PTLS_ERROR_CLASS_INTERNAL + 64)

#define PTLS_ZERO_DIGEST_SHA256                                                                                                    \
    {                                                                                                                              \
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4,    \
            0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55                                                 \
    }

#define PTLS_ZERO_DIGEST_SHA384                                                                                                    \
    {                                                                                                                              \
        0x38, 0xb0, 0x60, 0xa7, 0x51, 0xac, 0x96, 0x38, 0x4c, 0xd9, 0x32, 0x7e, 0xb1, 0xb1, 0xe3, 0x6a, 0x21, 0xfd, 0xb7, 0x11,    \
            0x14, 0xbe, 0x07, 0x43, 0x4c, 0x0c, 0xc7, 0xbf, 0x63, 0xf6, 0xe1, 0xda, 0x27, 0x4e, 0xde, 0xbf, 0xe7, 0x6f, 0x65,      \
            0xfb, 0xd5, 0x1a, 0xd2, 0xf1, 0x48, 0x98, 0xb9, 0x5b                                                                   \
    }

typedef struct st_ptls_t ptls_t;
typedef struct st_ptls_context_t ptls_context_t;

/**
 * represents a sequence of octets
 */
typedef struct st_ptls_iovec_t {
    uint8_t *base;
    size_t len;
} ptls_iovec_t;

/**
 * used for storing output
 */
typedef struct st_ptls_buffer_t {
    uint8_t *base;
    size_t capacity;
    size_t off;
    int is_allocated;
} ptls_buffer_t;

/**
 * key exchange context built by ptls_key_exchange_algorithm::create.
 */
typedef struct st_ptls_key_exchange_context_t {
    /**
     * called once per created context. Callee must free resources allocated to the context and set *keyex to NULL. Secret and
     * peerkey will be NULL in case the exchange never happened.
     */
    int (*on_exchange)(struct st_ptls_key_exchange_context_t **keyex, ptls_iovec_t *secret, ptls_iovec_t peerkey);
} ptls_key_exchange_context_t;

/**
 * A key exchange algorithm.
 */
typedef const struct st_ptls_key_exchange_algorithm_t {
    /**
     * ID defined by the TLS specification
     */
    uint16_t id;
    /**
     * creates a context for asynchronous key exchange. The function is called when ClientHello is generated. The on_exchange
     * callback of the created context is called when the client receives ServerHello.
     */
    int (*create)(ptls_key_exchange_context_t **ctx, ptls_iovec_t *pubkey);
    /**
     * implements synchronous key exchange. Called when receiving a ServerHello.
     */
    int (*exchange)(ptls_iovec_t *pubkey, ptls_iovec_t *secret, ptls_iovec_t peerkey);
} ptls_key_exchange_algorithm_t;

/**
 * context of a symmetric cipher
 */
typedef struct st_ptls_cipher_context_t {
    const struct st_ptls_cipher_algorithm_t *algo;
    /* field above this line must not be altered by the crypto binding */
    void (*do_dispose)(struct st_ptls_cipher_context_t *ctx);
    void (*do_init)(struct st_ptls_cipher_context_t *ctx, const void *iv);
    void (*do_transform)(struct st_ptls_cipher_context_t *ctx, void *output, const void *input, size_t len);
} ptls_cipher_context_t;

/**
 * a symmetric cipher
 */
typedef const struct st_ptls_cipher_algorithm_t {
    const char *name;
    size_t key_size;
    size_t iv_size;
    size_t context_size;
    int (*setup_crypto)(ptls_cipher_context_t *ctx, int is_enc, const void *key);
} ptls_cipher_algorithm_t;

/**
 * AEAD context. AEAD implementations are allowed to stuff data at the end of the struct. The size of the memory allocated for the
 * struct is governed by ptls_aead_algorithm_t::context_size.
 */
typedef struct st_ptls_aead_context_t {
    const struct st_ptls_aead_algorithm_t *algo;
    uint8_t static_iv[PTLS_MAX_IV_SIZE];
    /* field above this line must not be altered by the crypto binding */
    void (*dispose_crypto)(struct st_ptls_aead_context_t *ctx);
    void (*do_encrypt_init)(struct st_ptls_aead_context_t *ctx, const void *iv, const void *aad, size_t aadlen);
    size_t (*do_encrypt_update)(struct st_ptls_aead_context_t *ctx, void *output, const void *input, size_t inlen);
    size_t (*do_encrypt_final)(struct st_ptls_aead_context_t *ctx, void *output);
    size_t (*do_decrypt)(struct st_ptls_aead_context_t *ctx, void *output, const void *input, size_t inlen, const void *iv,
                         const void *aad, size_t aadlen);
} ptls_aead_context_t;

/**
 * An AEAD cipher.
 */
typedef const struct st_ptls_aead_algorithm_t {
    /**
     * name (following the convention of `openssl ciphers -v ALL`)
     */
    const char *name;
    /**
     * the underlying key stream
     */
    ptls_cipher_algorithm_t *ctr_cipher;
    /**
     * key size
     */
    size_t key_size;
    /**
     * size of the IV
     */
    size_t iv_size;
    /**
     * size of the tag
     */
    size_t tag_size;
    /**
     * size of memory allocated for ptls_aead_context_t. AEAD implementations can set this value to something greater than
     * sizeof(ptls_aead_context_t) and stuff additional data at the bottom of the struct.
     */
    size_t context_size;
    /**
     * callback that sets up the crypto
     */
    int (*setup_crypto)(ptls_aead_context_t *ctx, int is_enc, const void *key);
} ptls_aead_algorithm_t;

/**
 *
 */
typedef enum en_ptls_hash_final_mode_t {
    /**
     * obtains the digest and frees the context
     */
    PTLS_HASH_FINAL_MODE_FREE = 0,
    /**
     * obtains the digest and reset the context to initial state
     */
    PTLS_HASH_FINAL_MODE_RESET = 1,
    /**
     * obtains the digest while leaving the context as-is
     */
    PTLS_HASH_FINAL_MODE_SNAPSHOT = 2
} ptls_hash_final_mode_t;

/**
 * A hash context.
 */
typedef struct st_ptls_hash_context_t {
    /**
     * feeds additional data into the hash context
     */
    void (*update)(struct st_ptls_hash_context_t *ctx, const void *src, size_t len);
    /**
     * returns the digest and performs necessary operation specified by mode
     */
    void (* final)(struct st_ptls_hash_context_t *ctx, void *md, ptls_hash_final_mode_t mode);
    /**
     * creates a copy of the hash context
     */
    struct st_ptls_hash_context_t *(*clone_)(struct st_ptls_hash_context_t *src);
} ptls_hash_context_t;

/**
 * A hash algorithm and its properties.
 */
typedef const struct st_ptls_hash_algorithm_t {
    /**
     * block size
     */
    size_t block_size;
    /**
     * digest size
     */
    size_t digest_size;
    /**
     * constructor that creates the hash context
     */
    ptls_hash_context_t *(*create)(void);
    /**
     * digest of zero-length octets
     */
    uint8_t empty_digest[PTLS_MAX_DIGEST_SIZE];
} ptls_hash_algorithm_t;

typedef const struct st_ptls_cipher_suite_t {
    uint16_t id;
    ptls_aead_algorithm_t *aead;
    ptls_hash_algorithm_t *hash;
} ptls_cipher_suite_t;

#define PTLS_CALLBACK_TYPE0(ret, name)                                                                                             \
    typedef struct st_ptls_##name##_t {                                                                                            \
        ret (*cb)(struct st_ptls_##name##_t * self);                                                                               \
    } ptls_##name##_t

#define PTLS_CALLBACK_TYPE(ret, name, ...)                                                                                         \
    typedef struct st_ptls_##name##_t {                                                                                            \
        ret (*cb)(struct st_ptls_##name##_t * self, __VA_ARGS__);                                                                  \
    } ptls_##name##_t

/**
 * returns current time in milliseconds (ptls_get_time can be used to return the physical time)
 */
PTLS_CALLBACK_TYPE0(uint64_t, get_time);
/**
 * after receiving ClientHello, the core calls the optional callback to give a chance to the swap the context depending on the input
 * values. The callback is required to call `ptls_set_server_name` if an SNI extension needs to be sent to the client.
 */
PTLS_CALLBACK_TYPE(int, on_client_hello, ptls_t *tls, ptls_iovec_t server_name, const ptls_iovec_t *negotiated_protocols,
                   size_t num_negotiated_protocols, const uint16_t *signature_algorithms, size_t num_signature_algorithms);
/**
 * when generating Certificate, the core calls the callback to obtain the OCSP response for stapling.
 */
PTLS_CALLBACK_TYPE(int, staple_ocsp, ptls_t *tls, ptls_buffer_t *output, size_t cert_index);
/**
 * when gerenating CertificateVerify, the core calls the callback to sign the handshake context using the certificate.
 */
PTLS_CALLBACK_TYPE(int, sign_certificate, ptls_t *tls, uint16_t *selected_algorithm, ptls_buffer_t *output, ptls_iovec_t input,
                   const uint16_t *algorithms, size_t num_algorithms);
/**
 * after receiving Certificate, the core calls the callback to verify the certificate chain and to obtain a pointer to a
 * callback that should be used for verifying CertificateVerify. If an error occurs between a successful return from this
 * callback to the invocation of the verify_sign callback, verify_sign is called with both data and sign set to an empty buffer.
 * The implementor of the callback should use that as the opportunity to free any temporary data allocated for the verify_sign
 * callback.
 */
PTLS_CALLBACK_TYPE(int, verify_certificate, ptls_t *tls,
                   int (**verify_sign)(void *verify_ctx, ptls_iovec_t data, ptls_iovec_t sign), void **verify_data,
                   ptls_iovec_t *certs, size_t num_certs);
/**
 * encrypt-and-signs (or verify-and-decrypts) a ticket (server-only)
 */
PTLS_CALLBACK_TYPE(int, encrypt_ticket, ptls_t *tls, int is_encrypt, ptls_buffer_t *dst, ptls_iovec_t src);
/**
 * saves a ticket (client-only)
 */
PTLS_CALLBACK_TYPE(int, save_ticket, ptls_t *tls, ptls_iovec_t input);
/**
 * secret logginng
 */
PTLS_CALLBACK_TYPE(void, log_secret, ptls_t *tls, const char *label, ptls_iovec_t secret);
/**
 * reference counting
 */
PTLS_CALLBACK_TYPE(void, update_open_count, ssize_t delta);

/**
 * the configuration
 */
struct st_ptls_context_t {
    /**
     * PRNG to be used
     */
    void (*random_bytes)(void *buf, size_t len);
    /**
     *
     */
    ptls_get_time_t *get_time;
    /**
     * list of supported key-exchange algorithms terminated by NULL
     */
    ptls_key_exchange_algorithm_t **key_exchanges;
    /**
     * list of supported cipher-suites terminated by NULL
     */
    ptls_cipher_suite_t **cipher_suites;
    /**
     * list of certificates
     */
    struct {
        ptls_iovec_t *list;
        size_t count;
    } certificates;
    /**
     *
     */
    ptls_on_client_hello_t *on_client_hello;
    /**
     *
     */
    ptls_staple_ocsp_t *staple_ocsp;
    /**
     *
     */
    ptls_sign_certificate_t *sign_certificate;
    /**
     *
     */
    ptls_verify_certificate_t *verify_certificate;
    /**
     * lifetime of a session ticket (server-only)
     */
    uint32_t ticket_lifetime;
    /**
     * maximum permitted size of early data (server-only)
     */
    uint32_t max_early_data_size;
    /**
     * if set, psk handshakes use (ec)dhe
     */
    unsigned require_dhe_on_psk : 1;
    /**
     * if exporter master secrets should be recorded
     */
    unsigned use_exporter : 1;
    /**
     * if ChangeCipherSpec message should be sent during handshake
     */
    unsigned send_change_cipher_spec : 1;
    /**
     *
     */
    ptls_encrypt_ticket_t *encrypt_ticket;
    /**
     *
     */
    ptls_save_ticket_t *save_ticket;
    /**
     *
     */
    ptls_log_secret_t *log_secret;
    /**
     *
     */
    ptls_update_open_count_t *update_open_count;
};

typedef struct st_ptls_raw_extension_t {
    uint16_t type;
    ptls_iovec_t data;
} ptls_raw_extension_t;

/**
 * optional arguments to client-driven handshake
 */
#ifdef _WINDOWS
/* suppress warning C4201: nonstandard extension used: nameless struct/union */
#pragma warning(push)
#pragma warning(disable : 4201)
#endif
typedef struct st_ptls_handshake_properties_t {
    union {
        struct {
            /**
             * list of protocols offered through ALPN
             */
            struct {
                const ptls_iovec_t *list;
                size_t count;
            } negotiated_protocols;
            /**
             * session ticket sent to the application via save_ticket callback
             */
            ptls_iovec_t session_ticket;
            /**
             * pointer to store the maximum size of early-data that can be sent immediately (if NULL, early data is not used)
             */
            size_t *max_early_data_size;
            /**
             *
             */
            unsigned early_data_accepted_by_peer : 1;
            /**
             * negotiate the key exchange method before sending key_share
             */
            unsigned negotiate_before_key_exchange : 1;
        } client;
        struct {
            /**
             * psk binder being selected (len is set to zero if none)
             */
            struct {
                uint8_t base[PTLS_MAX_DIGEST_SIZE];
                size_t len;
            } selected_psk_binder;
            /**
             * parameters related to use of the Cookie extension
             */
            struct {
                /**
                 * HMAC key to protect the integrity of the cookie. The key should be as long as the digest size of the first
                 * ciphersuite specified in ptls_context_t (i.e. the hash algorithm of the best ciphersuite that can be chosen).
                 */
                const void *key;
                /**
                 * additional data to be used for verifying the cookie
                 */
                ptls_iovec_t additional_data;
            } cookie;
            /**
             * if HRR should always be sent
             */
            unsigned enforce_retry : 1;
            /**
             * if retry should be stateless (cookie.key MUST be set when this option is used)
             */
            unsigned retry_uses_cookie : 1;
        } server;
    };
    /**
     * an optional list of additional extensions to send either in CH or EE, terminated by type == UINT16_MAX
     */
    ptls_raw_extension_t *additional_extensions;
    /**
     * an optional callback that returns a boolean value indicating if a particular extension should be collected
     */
    int (*collect_extension)(ptls_t *tls, struct st_ptls_handshake_properties_t *properties, uint16_t type);
    /**
     * an optional callback that reports the extensions being collected
     */
    int (*collected_extensions)(ptls_t *tls, struct st_ptls_handshake_properties_t *properties, ptls_raw_extension_t *extensions);
} ptls_handshake_properties_t;
#ifdef _WINDOWS
#pragma warning(pop)
#endif

/**
 * builds a new ptls_iovec_t instance using the supplied parameters
 */
static ptls_iovec_t ptls_iovec_init(const void *p, size_t len);
/**
 * initializes a buffer, setting the default destination to the small buffer provided as the argument.
 */
static void ptls_buffer_init(ptls_buffer_t *buf, void *smallbuf, size_t smallbuf_size);
/**
 * disposes a buffer, freeing resources allocated by the buffer itself (if any)
 */
static void ptls_buffer_dispose(ptls_buffer_t *buf);
/**
 * internal
 */
void ptls_buffer__release_memory(ptls_buffer_t *buf);
/**
 * reserves space for additional amount of memory
 */
int ptls_buffer_reserve(ptls_buffer_t *buf, size_t delta);
/**
 * internal
 */
int ptls_buffer__do_pushv(ptls_buffer_t *buf, const void *src, size_t len);
/**
 * internal
 */
int ptls_buffer__adjust_asn1_blocksize(ptls_buffer_t *buf, size_t body_size);
/**
 * pushes an unsigned bigint
 */
int ptls_buffer_push_asn1_ubigint(ptls_buffer_t *buf, const void *bignum, size_t size);

#define ptls_buffer_pushv(buf, src, len)                                                                                           \
    do {                                                                                                                           \
        if ((ret = ptls_buffer__do_pushv((buf), (src), (len))) != 0)                                                               \
            goto Exit;                                                                                                             \
    } while (0)

#define ptls_buffer_push(buf, ...)                                                                                                 \
    do {                                                                                                                           \
        if ((ret = ptls_buffer__do_pushv((buf), (uint8_t[]){__VA_ARGS__}, sizeof((uint8_t[]){__VA_ARGS__}))) != 0)                 \
            goto Exit;                                                                                                             \
    } while (0)

#define ptls_buffer_push16(buf, v)                                                                                                 \
    do {                                                                                                                           \
        uint16_t _v = (v);                                                                                                         \
        ptls_buffer_push(buf, (uint8_t)(_v >> 8), (uint8_t)_v);                                                                    \
    } while (0)

#define ptls_buffer_push32(buf, v)                                                                                                 \
    do {                                                                                                                           \
        uint32_t _v = (v);                                                                                                         \
        ptls_buffer_push(buf, (uint8_t)(_v >> 24), (uint8_t)(_v >> 16), (uint8_t)(_v >> 8), (uint8_t)_v);                          \
    } while (0)

#define ptls_buffer_push64(buf, v)                                                                                                 \
    do {                                                                                                                           \
        uint64_t _v = (v);                                                                                                         \
        ptls_buffer_push(buf, (uint8_t)(_v >> 56), (uint8_t)(_v >> 48), (uint8_t)(_v >> 40), (uint8_t)(_v >> 32),                  \
                         (uint8_t)(_v >> 24), (uint8_t)(_v >> 16), (uint8_t)(_v >> 8), (uint8_t)_v);                               \
    } while (0)

#define ptls_buffer_push_block(buf, _capacity, block)                                                                              \
    do {                                                                                                                           \
        size_t capacity = (_capacity);                                                                                             \
        ptls_buffer_pushv((buf), (uint8_t *)"\0\0\0\0\0\0\0", capacity);                                                           \
        size_t body_start = (buf)->off;                                                                                            \
        do {                                                                                                                       \
            block                                                                                                                  \
        } while (0);                                                                                                               \
        size_t body_size = (buf)->off - body_start;                                                                                \
        for (; capacity != 0; --capacity)                                                                                          \
            (buf)->base[body_start - capacity] = (uint8_t)(body_size >> (8 * (capacity - 1)));                                     \
    } while (0)

#define ptls_buffer_push_asn1_block(buf, block)                                                                                    \
    do {                                                                                                                           \
        ptls_buffer_push((buf), 0xff); /* dummy */                                                                                 \
        size_t body_start = (buf)->off;                                                                                            \
        do {                                                                                                                       \
            block                                                                                                                  \
        } while (0);                                                                                                               \
        size_t body_size = (buf)->off - body_start;                                                                                \
        if (body_size < 128) {                                                                                                     \
            (buf)->base[body_start - 1] = (uint8_t)body_size;                                                                      \
        } else {                                                                                                                   \
            if ((ret = ptls_buffer__adjust_asn1_blocksize((buf), body_size)) != 0)                                                 \
                goto Exit;                                                                                                         \
        }                                                                                                                          \
    } while (0)

#define ptls_buffer_push_asn1_sequence(buf, block)                                                                                 \
    do {                                                                                                                           \
        ptls_buffer_push((buf), 0x30);                                                                                             \
        ptls_buffer_push_asn1_block((buf), block);                                                                                 \
    } while (0)

int ptls_decode16(uint16_t *value, const uint8_t **src, const uint8_t *end);
int ptls_decode32(uint32_t *value, const uint8_t **src, const uint8_t *end);
int ptls_decode64(uint64_t *value, const uint8_t **src, const uint8_t *end);

#define ptls_decode_open_block(src, end, capacity, block)                                                                          \
    do {                                                                                                                           \
        size_t _capacity = (capacity);                                                                                             \
        if (_capacity > (size_t)(end - (src))) {                                                                                   \
            ret = PTLS_ALERT_DECODE_ERROR;                                                                                         \
            goto Exit;                                                                                                             \
        }                                                                                                                          \
        size_t _block_size = 0;                                                                                                    \
        do {                                                                                                                       \
            _block_size = _block_size << 8 | *(src)++;                                                                             \
        } while (--_capacity != 0);                                                                                                \
        if (_block_size > (size_t)(end - (src))) {                                                                                 \
            ret = PTLS_ALERT_DECODE_ERROR;                                                                                         \
            goto Exit;                                                                                                             \
        }                                                                                                                          \
        do {                                                                                                                       \
            const uint8_t *const end = (src) + _block_size;                                                                        \
            do {                                                                                                                   \
                block                                                                                                              \
            } while (0);                                                                                                           \
            if ((src) != end) {                                                                                                    \
                ret = PTLS_ALERT_DECODE_ERROR;                                                                                     \
                goto Exit;                                                                                                         \
            }                                                                                                                      \
        } while (0);                                                                                                               \
    } while (0)

#define ptls_decode_assert_block_close(src, end)                                                                                   \
    do {                                                                                                                           \
        if ((src) != end) {                                                                                                        \
            ret = PTLS_ALERT_DECODE_ERROR;                                                                                         \
            goto Exit;                                                                                                             \
        }                                                                                                                          \
    } while (0);

#define ptls_decode_block(src, end, capacity, block)                                                                               \
    do {                                                                                                                           \
        ptls_decode_open_block((src), end, capacity, block);                                                                       \
        ptls_decode_assert_block_close((src), end);                                                                                \
    } while (0)

/**
 * create a object to handle new TLS connection. Client-side of a TLS connection is created if server_name is non-NULL. Otherwise,
 * a server-side connection is created.
 */
ptls_t *ptls_new(ptls_context_t *ctx, int is_server);
/**
 * releases all resources associated to the object
 */
void ptls_free(ptls_t *tls);
/**
 * returns address of the crypto callbacks that the connection is using
 */
ptls_context_t *ptls_get_context(ptls_t *tls);
/**
 * updates the context of a connection. Can be called from `on_client_hello` callback.
 */
void ptls_set_context(ptls_t *tls, ptls_context_t *ctx);
/**
 * returns the client-random
 */
ptls_iovec_t ptls_get_client_random(ptls_t *tls);
/**
 * returns the cipher-suite being used
 */
ptls_cipher_suite_t *ptls_get_cipher(ptls_t *tls);
/**
 * returns the server-name (NULL if SNI is not used or failed to negotiate)
 */
const char *ptls_get_server_name(ptls_t *tls);
/**
 * sets the server-name (for client the value sent in SNI). If server_name_len is zero, then strlen(server_name) is called to
 * determine
 * the length of the name.
 */
int ptls_set_server_name(ptls_t *tls, const char *server_name, size_t server_name_len);
/**
 * returns the negotiated protocol (or NULL)
 */
const char *ptls_get_negotiated_protocol(ptls_t *tls);
/**
 * sets the negotiated protocol. If protocol_len is zero, strlen(protocol) is called to determine the length of the protocol name.
 */
int ptls_set_negotiated_protocol(ptls_t *tls, const char *protocol, size_t protocol_len);
/**
 * returns if the handshake has been completed
 */
int ptls_handshake_is_complete(ptls_t *tls);
/**
 * returns if a PSK (or PSK-DHE) handshake was performed
 */
int ptls_is_psk_handshake(ptls_t *tls);
/**
 * returns a pointer to user data pointer (client is reponsible for freeing the associated data prior to calling ptls_free)
 */
void **ptls_get_data_ptr(ptls_t *tls);
/**
 * proceeds with the handshake, optionally taking some input from peer. The function returns zero in case the handshake completed
 * successfully. PTLS_ERROR_IN_PROGRESS is returned in case the handshake is incomplete. Otherwise, an error value is returned. The
 * contents of sendbuf should be sent to the client, regardless of whether if an error is returned. inlen is an argument used for
 * both input and output. As an input, the arguments takes the size of the data available as input. Upon return the value is updated
 * to the number of bytes consumed by the handshake. In case the returned value is PTLS_ERROR_IN_PROGRESS there is a guarantee that
 * all the input are consumed (i.e. the value of inlen does not change).
 */
int ptls_handshake(ptls_t *tls, ptls_buffer_t *sendbuf, const void *input, size_t *inlen, ptls_handshake_properties_t *args);
/**
 * decrypts the first record within given buffer
 */
int ptls_receive(ptls_t *tls, ptls_buffer_t *plaintextbuf, const void *input, size_t *len);
/**
 * encrypts given buffer into multiple TLS records
 */
int ptls_send(ptls_t *tls, ptls_buffer_t *sendbuf, const void *input, size_t inlen);
/**
 * returns per-record overhead
 */
size_t ptls_get_record_overhead(ptls_t *tls);
/**
 * sends an alert
 */
int ptls_send_alert(ptls_t *tls, ptls_buffer_t *sendbuf, uint8_t level, uint8_t description);
/**
 *
 */
int ptls_export_secret(ptls_t *tls, void *output, size_t outlen, const char *label, ptls_iovec_t context_value, int is_early);
/**
 *
 */
ptls_hash_context_t *ptls_hmac_create(ptls_hash_algorithm_t *algo, const void *key, size_t key_size);
/**
 *
 */
int ptls_hkdf_extract(ptls_hash_algorithm_t *hash, void *output, ptls_iovec_t salt, ptls_iovec_t ikm);
/**
 *
 */
int ptls_hkdf_expand(ptls_hash_algorithm_t *hash, void *output, size_t outlen, ptls_iovec_t prk, ptls_iovec_t info);
/**
 *
 */
int ptls_hkdf_expand_label(ptls_hash_algorithm_t *algo, void *output, size_t outlen, ptls_iovec_t secret, const char *label,
                           ptls_iovec_t hash_value, const char *base_label);
/**
 * instantiates a symmetric cipher
 */
ptls_cipher_context_t *ptls_cipher_new(ptls_cipher_algorithm_t *algo, int is_enc, const void *key);
/**
 * destroys a symmetric cipher
 */
void ptls_cipher_free(ptls_cipher_context_t *ctx);
/**
 * initializes the IV; this function must be called prior to calling ptls_cipher_encrypt
 */
static void ptls_cipher_init(ptls_cipher_context_t *ctx, const void *iv);
/**
 * encrypts given text
 */
static void ptls_cipher_encrypt(ptls_cipher_context_t *ctx, void *output, const void *input, size_t len);
/**
 * instantiates an AEAD cipher given a secret, which is expanded using hkdf to a set of key and iv
 * @param aead
 * @param hash
 * @param is_enc 1 if creating a context for encryption, 0 if creating a context for decryption
 * @param secret the secret. The size must be the digest length of the hash algorithm
 * @return pointer to an AEAD context if successful, otherwise NULL
 */
ptls_aead_context_t *ptls_aead_new(ptls_aead_algorithm_t *aead, ptls_hash_algorithm_t *hash, int is_enc, const void *secret,
                                   const char *base_label);
/**
 * destroys an AEAD cipher context
 */
void ptls_aead_free(ptls_aead_context_t *ctx);
/**
 *
 */
size_t ptls_aead_encrypt(ptls_aead_context_t *ctx, void *output, const void *input, size_t inlen, uint64_t seq, const void *aad,
                         size_t aadlen);
/**
 * initializes the internal state of the encryptor
 */
static void ptls_aead_encrypt_init(ptls_aead_context_t *ctx, uint64_t seq, const void *aad, size_t aadlen);
/**
 * encrypts the input and updates the GCM state
 * @return number of bytes emitted to output
 */
static size_t ptls_aead_encrypt_update(ptls_aead_context_t *ctx, void *output, const void *input, size_t inlen);
/**
 * emits buffered data (if any) and the GCM tag
 * @return number of bytes emitted to output
 */
static size_t ptls_aead_encrypt_final(ptls_aead_context_t *ctx, void *output);
/**
 * decrypts an AEAD record
 * @return number of bytes emitted to output if successful, or SIZE_MAX if the input is invalid (e.g. broken MAC)
 */
static size_t ptls_aead_decrypt(ptls_aead_context_t *ctx, void *output, const void *input, size_t inlen, uint64_t seq,
                                const void *aad, size_t aadlen);
/**
 * internal
 */
void ptls_aead__build_iv(ptls_aead_context_t *ctx, uint8_t *iv, uint64_t seq);
/**
 * clears memory
 */
extern void (*volatile ptls_clear_memory)(void *p, size_t len);
/**
 *
 */
static ptls_iovec_t ptls_iovec_init(const void *p, size_t len);

/* inline functions */
inline ptls_iovec_t ptls_iovec_init(const void *p, size_t len)
{
    /* avoid the "return (ptls_iovec_t){(uint8_t *)p, len};" construct because it requires C99
     * and triggers a warning "C4204: nonstandard extension used: non-constant aggregate initializer"
     * in Visual Studio */
    ptls_iovec_t r;
    r.base = (uint8_t *)p;
    r.len = len;
    return r;
}

inline void ptls_buffer_init(ptls_buffer_t *buf, void *smallbuf, size_t smallbuf_size)
{
    assert(smallbuf != NULL);
    buf->base = (uint8_t *)smallbuf;
    buf->off = 0;
    buf->capacity = smallbuf_size;
    buf->is_allocated = 0;
}

inline void ptls_buffer_dispose(ptls_buffer_t *buf)
{
    ptls_buffer__release_memory(buf);
    *buf = (ptls_buffer_t){NULL};
}

inline void ptls_cipher_init(ptls_cipher_context_t *ctx, const void *iv)
{
    ctx->do_init(ctx, iv);
}

inline void ptls_cipher_encrypt(ptls_cipher_context_t *ctx, void *output, const void *input, size_t len)
{
    ctx->do_transform(ctx, output, input, len);
}

inline void ptls_aead_encrypt_init(ptls_aead_context_t *ctx, uint64_t seq, const void *aad, size_t aadlen)
{
    uint8_t iv[PTLS_MAX_IV_SIZE];

    ptls_aead__build_iv(ctx, iv, seq);
    ctx->do_encrypt_init(ctx, iv, aad, aadlen);
}

inline size_t ptls_aead_encrypt_update(ptls_aead_context_t *ctx, void *output, const void *input, size_t inlen)
{
    return ctx->do_encrypt_update(ctx, output, input, inlen);
}

inline size_t ptls_aead_encrypt_final(ptls_aead_context_t *ctx, void *output)
{
    return ctx->do_encrypt_final(ctx, output);
}

inline size_t ptls_aead_decrypt(ptls_aead_context_t *ctx, void *output, const void *input, size_t inlen, uint64_t seq,
                                const void *aad, size_t aadlen)
{
    uint8_t iv[PTLS_MAX_IV_SIZE];

    ptls_aead__build_iv(ctx, iv, seq);
    return ctx->do_decrypt(ctx, output, input, inlen, iv, aad, aadlen);
}

int ptls_load_certificates(ptls_context_t *ctx, char *cert_pem_file);

extern ptls_get_time_t ptls_get_time;

#define ptls_define_hash(name, ctx_type, init_func, update_func, final_func)                                                       \
                                                                                                                                   \
    struct name##_context_t {                                                                                                      \
        ptls_hash_context_t super;                                                                                                 \
        ctx_type ctx;                                                                                                              \
    };                                                                                                                             \
                                                                                                                                   \
    static void name##_update(ptls_hash_context_t *_ctx, const void *src, size_t len)                                              \
    {                                                                                                                              \
        struct name##_context_t *ctx = (struct name##_context_t *)_ctx;                                                            \
        update_func(&ctx->ctx, src, len);                                                                                          \
    }                                                                                                                              \
                                                                                                                                   \
    static void name##_final(ptls_hash_context_t *_ctx, void *md, ptls_hash_final_mode_t mode)                                     \
    {                                                                                                                              \
        struct name##_context_t *ctx = (struct name##_context_t *)_ctx;                                                            \
        if (mode == PTLS_HASH_FINAL_MODE_SNAPSHOT) {                                                                               \
            ctx_type copy = ctx->ctx;                                                                                              \
            final_func(&copy, md);                                                                                                 \
            ptls_clear_memory(&copy, sizeof(copy));                                                                                \
            return;                                                                                                                \
        }                                                                                                                          \
        if (md != NULL)                                                                                                            \
            final_func(&ctx->ctx, md);                                                                                             \
        switch (mode) {                                                                                                            \
        case PTLS_HASH_FINAL_MODE_FREE:                                                                                            \
            ptls_clear_memory(&ctx->ctx, sizeof(ctx->ctx));                                                                        \
            free(ctx);                                                                                                             \
            break;                                                                                                                 \
        case PTLS_HASH_FINAL_MODE_RESET:                                                                                           \
            init_func(&ctx->ctx);                                                                                                  \
            break;                                                                                                                 \
        default:                                                                                                                   \
            assert(!"FIXME");                                                                                                      \
            break;                                                                                                                 \
        }                                                                                                                          \
    }                                                                                                                              \
                                                                                                                                   \
    static ptls_hash_context_t *name##_clone(ptls_hash_context_t *_src)                                                            \
    {                                                                                                                              \
        struct name##_context_t *dst, *src = (struct name##_context_t *)_src;                                                      \
        if ((dst = malloc(sizeof(*dst))) == NULL)                                                                                  \
            return NULL;                                                                                                           \
        *dst = *src;                                                                                                               \
        return &dst->super;                                                                                                        \
    }                                                                                                                              \
                                                                                                                                   \
    static ptls_hash_context_t *name##_create(void)                                                                                \
    {                                                                                                                              \
        struct name##_context_t *ctx;                                                                                              \
        if ((ctx = malloc(sizeof(*ctx))) == NULL)                                                                                  \
            return NULL;                                                                                                           \
        ctx->super = (ptls_hash_context_t){name##_update, name##_final, name##_clone};                                             \
        init_func(&ctx->ctx);                                                                                                      \
        return &ctx->super;                                                                                                        \
    }

#ifdef __cplusplus
}
#endif

#endif
