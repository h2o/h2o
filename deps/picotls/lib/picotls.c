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
#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WINDOWS
#include "wincompat.h"
#else
#include <arpa/inet.h>
#include <sys/time.h>
#endif
#include "picotls.h"
#if PICOTLS_USE_DTRACE
#include "picotls-probes.h"
#endif

#define PTLS_MAX_PLAINTEXT_RECORD_SIZE 16384
#define PTLS_MAX_ENCRYPTED_RECORD_SIZE (16384 + 256)

#define PTLS_RECORD_VERSION_MAJOR 3
#define PTLS_RECORD_VERSION_MINOR 3

#define PTLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC 20
#define PTLS_CONTENT_TYPE_ALERT 21
#define PTLS_CONTENT_TYPE_HANDSHAKE 22
#define PTLS_CONTENT_TYPE_APPDATA 23

#define PTLS_PSK_KE_MODE_PSK 0
#define PTLS_PSK_KE_MODE_PSK_DHE 1

#define PTLS_HANDSHAKE_HEADER_SIZE 4

#define PTLS_EXTENSION_TYPE_SERVER_NAME 0
#define PTLS_EXTENSION_TYPE_STATUS_REQUEST 5
#define PTLS_EXTENSION_TYPE_SUPPORTED_GROUPS 10
#define PTLS_EXTENSION_TYPE_SIGNATURE_ALGORITHMS 13
#define PTLS_EXTENSION_TYPE_ALPN 16
#define PTLS_EXTENSION_TYPE_COMPRESS_CERTIFICATE 27
#define PTLS_EXTENSION_TYPE_PRE_SHARED_KEY 41
#define PTLS_EXTENSION_TYPE_EARLY_DATA 42
#define PTLS_EXTENSION_TYPE_SUPPORTED_VERSIONS 43
#define PTLS_EXTENSION_TYPE_COOKIE 44
#define PTLS_EXTENSION_TYPE_PSK_KEY_EXCHANGE_MODES 45
#define PTLS_EXTENSION_TYPE_KEY_SHARE 51
#define PTLS_EXTENSION_TYPE_ENCRYPTED_SERVER_NAME 0xffce

#define PTLS_PROTOCOL_VERSION_TLS13_FINAL 0x0304
#define PTLS_PROTOCOL_VERSION_TLS13_DRAFT26 0x7f1a
#define PTLS_PROTOCOL_VERSION_TLS13_DRAFT27 0x7f1b
#define PTLS_PROTOCOL_VERSION_TLS13_DRAFT28 0x7f1c

#define PTLS_SERVER_NAME_TYPE_HOSTNAME 0

#define PTLS_SERVER_CERTIFICATE_VERIFY_CONTEXT_STRING "TLS 1.3, server CertificateVerify"
#define PTLS_CLIENT_CERTIFICATE_VERIFY_CONTEXT_STRING "TLS 1.3, client CertificateVerify"
#define PTLS_MAX_CERTIFICATE_VERIFY_SIGNDATA_SIZE                                                                                  \
    (64 + sizeof(PTLS_SERVER_CERTIFICATE_VERIFY_CONTEXT_STRING) + PTLS_MAX_DIGEST_SIZE * 2)

#define PTLS_EARLY_DATA_MAX_DELAY 10000 /* max. RTT (in msec) to permit early data */

#ifndef PTLS_MAX_EARLY_DATA_SKIP_SIZE
#define PTLS_MAX_EARLY_DATA_SKIP_SIZE 65536
#endif
#if defined(PTLS_DEBUG) && PTLS_DEBUG
#define PTLS_DEBUGF(...) fprintf(stderr, __VA_ARGS__)
#else
#define PTLS_DEBUGF(...)
#endif

#ifndef PTLS_MEMORY_DEBUG
#define PTLS_MEMORY_DEBUG 0
#endif

#if PICOTLS_USE_DTRACE
#define PTLS_SHOULD_PROBE(LABEL, tls) (PTLS_UNLIKELY(PICOTLS_##LABEL##_ENABLED()) && !(tls)->skip_tracing)
#define PTLS_PROBE0(LABEL, tls)                                                                                                    \
    do {                                                                                                                           \
        ptls_t *_tls = (tls);                                                                                                      \
        if (PTLS_SHOULD_PROBE(LABEL, _tls))                                                                                        \
            PICOTLS_##LABEL(_tls);                                                                                                 \
    } while (0)
#define PTLS_PROBE(LABEL, tls, ...)                                                                                                \
    do {                                                                                                                           \
        ptls_t *_tls = (tls);                                                                                                      \
        if (PTLS_SHOULD_PROBE(LABEL, _tls))                                                                                        \
            PICOTLS_##LABEL(_tls, __VA_ARGS__);                                                                                    \
    } while (0)
#else
#define PTLS_PROBE0(LABEL, tls)
#define PTLS_PROBE(LABEL, tls, ...)
#endif

/**
 * list of supported versions in the preferred order
 */
static const uint16_t supported_versions[] = {PTLS_PROTOCOL_VERSION_TLS13_FINAL, PTLS_PROTOCOL_VERSION_TLS13_DRAFT28,
                                              PTLS_PROTOCOL_VERSION_TLS13_DRAFT27, PTLS_PROTOCOL_VERSION_TLS13_DRAFT26};

static const uint8_t hello_retry_random[PTLS_HELLO_RANDOM_SIZE] = {0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C,
                                                                   0x02, 0x1E, 0x65, 0xB8, 0x91, 0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB,
                                                                   0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C};

struct st_ptls_traffic_protection_t {
    uint8_t secret[PTLS_MAX_DIGEST_SIZE];
    size_t epoch;
    /* the following fields are not used if the key_change callback is set */
    ptls_aead_context_t *aead;
    uint64_t seq;
};

struct st_ptls_record_message_emitter_t {
    ptls_message_emitter_t super;
    size_t rec_start;
};

struct st_ptls_signature_algorithms_t {
    uint16_t list[16]; /* expand? */
    size_t count;
};

struct st_ptls_certificate_request_t {
    /**
     * context.base becomes non-NULL when a CertificateRequest is pending for processing
     */
    ptls_iovec_t context;
    struct st_ptls_signature_algorithms_t signature_algorithms;
};

struct st_ptls_t {
    /**
     * the context
     */
    ptls_context_t *ctx;
    /**
     * the state
     */
    enum en_ptls_state_t {
        PTLS_STATE_CLIENT_HANDSHAKE_START,
        PTLS_STATE_CLIENT_EXPECT_SERVER_HELLO,
        PTLS_STATE_CLIENT_EXPECT_SECOND_SERVER_HELLO,
        PTLS_STATE_CLIENT_EXPECT_ENCRYPTED_EXTENSIONS,
        PTLS_STATE_CLIENT_EXPECT_CERTIFICATE_REQUEST_OR_CERTIFICATE,
        PTLS_STATE_CLIENT_EXPECT_CERTIFICATE,
        PTLS_STATE_CLIENT_EXPECT_CERTIFICATE_VERIFY,
        PTLS_STATE_CLIENT_EXPECT_FINISHED,
        PTLS_STATE_SERVER_EXPECT_CLIENT_HELLO,
        PTLS_STATE_SERVER_EXPECT_SECOND_CLIENT_HELLO,
        PTLS_STATE_SERVER_EXPECT_CERTIFICATE,
        PTLS_STATE_SERVER_EXPECT_CERTIFICATE_VERIFY,
        /* ptls_send can be called if the state is below here */
        PTLS_STATE_SERVER_EXPECT_END_OF_EARLY_DATA,
        PTLS_STATE_SERVER_EXPECT_FINISHED,
        PTLS_STATE_POST_HANDSHAKE_MIN,
        PTLS_STATE_CLIENT_POST_HANDSHAKE = PTLS_STATE_POST_HANDSHAKE_MIN,
        PTLS_STATE_SERVER_POST_HANDSHAKE
    } state;
    /**
     * receive buffers
     */
    struct {
        ptls_buffer_t rec;
        ptls_buffer_t mess;
    } recvbuf;
    /**
     * key schedule
     */
    ptls_key_schedule_t *key_schedule;
    /**
     * values used for record protection
     */
    struct {
        struct st_ptls_traffic_protection_t dec;
        struct st_ptls_traffic_protection_t enc;
    } traffic_protection;
    /**
     * server-name passed using SNI
     */
    char *server_name;
    /**
     * result of ALPN
     */
    char *negotiated_protocol;
    /**
     * selected key-exchange
     */
    ptls_key_exchange_algorithm_t *key_share;
    /**
     * selected cipher-suite
     */
    ptls_cipher_suite_t *cipher_suite;
    /**
     * clienthello.random
     */
    uint8_t client_random[PTLS_HELLO_RANDOM_SIZE];
    /**
     * esni
     */
    ptls_esni_secret_t *esni;
    /**
     * exporter master secret (either 0rtt or 1rtt)
     */
    struct {
        uint8_t *early;
        uint8_t *one_rtt;
    } exporter_master_secret;
    /* flags */
    unsigned is_server : 1;
    unsigned is_psk_handshake : 1;
    unsigned send_change_cipher_spec : 1;
    unsigned needs_key_update : 1;
    unsigned key_update_send_request : 1;
    unsigned skip_tracing : 1;
    /**
     * misc.
     */
    union {
        struct {
            ptls_iovec_t legacy_session_id;
            uint8_t legacy_session_id_buf[32];
            ptls_key_exchange_context_t *key_share_ctx;
            unsigned offered_psk : 1;
            /**
             * if 1-RTT write key is active
             */
            unsigned using_early_data : 1;
            struct st_ptls_certificate_request_t certificate_request;
        } client;
        struct {
            uint8_t pending_traffic_secret[PTLS_MAX_DIGEST_SIZE];
            uint32_t early_data_skipped_bytes; /* if not UINT32_MAX, the server is skipping early data */
        } server;
    };
    /**
     * certificate verify
     * will be used by the client and the server (if require_client_authentication is set).
     */
    struct {
        int (*cb)(void *verify_ctx, ptls_iovec_t data, ptls_iovec_t signature);
        void *verify_ctx;
    } certificate_verify;
    /**
     * handshake traffic secret to be commisioned (an array of `uint8_t [PTLS_MAX_DIGEST_SIZE]` or NULL)
     */
    uint8_t *pending_handshake_secret;
    /**
     * user data
     */
    void *data_ptr;
};

struct st_ptls_record_t {
    uint8_t type;
    uint16_t version;
    size_t length;
    const uint8_t *fragment;
};

struct st_ptls_client_hello_psk_t {
    ptls_iovec_t identity;
    uint32_t obfuscated_ticket_age;
    ptls_iovec_t binder;
};

#define MAX_UNKNOWN_EXTENSIONS 16
#define MAX_CLIENT_CIPHERS 32

struct st_ptls_client_hello_t {
    uint16_t legacy_version;
    const uint8_t *random_bytes;
    ptls_iovec_t legacy_session_id;
    struct {
        const uint8_t *ids;
        size_t count;
    } compression_methods;
    uint16_t selected_version;
    ptls_iovec_t cipher_suites;
    ptls_iovec_t negotiated_groups;
    ptls_iovec_t key_shares;
    struct st_ptls_signature_algorithms_t signature_algorithms;
    ptls_iovec_t server_name;
    struct {
        ptls_cipher_suite_t *cipher; /* selected cipher-suite, or NULL if esni extension is not used */
        ptls_key_exchange_algorithm_t *key_share;
        ptls_iovec_t peer_key;
        const uint8_t *record_digest;
        ptls_iovec_t encrypted_sni;
    } esni;
    struct {
        ptls_iovec_t list[16];
        size_t count;
    } alpn;
    struct {
        uint16_t list[16];
        size_t count;
    } cert_compression_algos;
    struct {
        uint16_t list[MAX_CLIENT_CIPHERS];
        size_t count;
    } client_ciphers;
    struct {
        ptls_iovec_t all;
        ptls_iovec_t tbs;
        ptls_iovec_t ch1_hash;
        ptls_iovec_t signature;
        unsigned sent_key_share : 1;
    } cookie;
    struct {
        const uint8_t *hash_end;
        struct {
            struct st_ptls_client_hello_psk_t list[4];
            size_t count;
        } identities;
        unsigned ke_modes;
        unsigned early_data_indication : 1;
        unsigned is_last_extension : 1;
    } psk;
    ptls_raw_extension_t unknown_extensions[MAX_UNKNOWN_EXTENSIONS + 1];
    unsigned status_request : 1;
};

struct st_ptls_server_hello_t {
    uint8_t random_[PTLS_HELLO_RANDOM_SIZE];
    ptls_iovec_t legacy_session_id;
    int is_retry_request;
    union {
        ptls_iovec_t peerkey;
        struct {
            uint16_t selected_group;
            ptls_iovec_t cookie;
        } retry_request;
    };
};

struct st_ptls_key_schedule_t {
    unsigned generation; /* early secret (1), hanshake secret (2), master secret (3) */
    const char *hkdf_label_prefix;
    uint8_t secret[PTLS_MAX_DIGEST_SIZE];
    size_t num_hashes;
    struct {
        ptls_hash_algorithm_t *algo;
        ptls_hash_context_t *ctx;
    } hashes[1];
};

struct st_ptls_extension_decoder_t {
    uint16_t type;
    int (*cb)(ptls_t *tls, void *arg, const uint8_t *src, const uint8_t *const end);
};

struct st_ptls_extension_bitmap_t {
    uint8_t bits[8]; /* only ids below 64 is tracked */
};

static const uint8_t zeroes_of_max_digest_size[PTLS_MAX_DIGEST_SIZE] = {0};

static int hkdf_expand_label(ptls_hash_algorithm_t *algo, void *output, size_t outlen, ptls_iovec_t secret, const char *label,
                             ptls_iovec_t hash_value, const char *label_prefix);
static ptls_aead_context_t *new_aead(ptls_aead_algorithm_t *aead, ptls_hash_algorithm_t *hash, int is_enc, const void *secret,
                                     ptls_iovec_t hash_value, const char *label_prefix);

static int is_supported_version(uint16_t v)
{
    size_t i;
    for (i = 0; i != PTLS_ELEMENTSOF(supported_versions); ++i)
        if (supported_versions[i] == v)
            return 1;
    return 0;
}

static inline int extension_bitmap_is_set(struct st_ptls_extension_bitmap_t *bitmap, uint16_t id)
{
    if (id < sizeof(bitmap->bits) * 8)
        return (bitmap->bits[id / 8] & (1 << (id % 8))) != 0;
    return 0;
}

static inline void extension_bitmap_set(struct st_ptls_extension_bitmap_t *bitmap, uint16_t id)
{
    if (id < sizeof(bitmap->bits) * 8)
        bitmap->bits[id / 8] |= 1 << (id % 8);
}

static inline void init_extension_bitmap(struct st_ptls_extension_bitmap_t *bitmap, uint8_t hstype)
{
    *bitmap = (struct st_ptls_extension_bitmap_t){{0}};

#define EXT(extid, proc)                                                                                                           \
    do {                                                                                                                           \
        int _found = 0;                                                                                                            \
        do {                                                                                                                       \
            proc                                                                                                                   \
        } while (0);                                                                                                               \
        if (!_found)                                                                                                               \
            extension_bitmap_set(bitmap, PTLS_EXTENSION_TYPE_##extid);                                                             \
    } while (0)
#define ALLOW(allowed_hstype) _found = _found || hstype == PTLS_HANDSHAKE_TYPE_##allowed_hstype

    /* Implements the table found in section 4.2 of draft-19; "If an implementation receives an extension which it recognizes and
     * which is not specified for the message in which it appears it MUST abort the handshake with an “illegal_parameter” alert."
     */
    EXT(SERVER_NAME, {
        ALLOW(CLIENT_HELLO);
        ALLOW(ENCRYPTED_EXTENSIONS);
    });
    EXT(STATUS_REQUEST, {
        ALLOW(CLIENT_HELLO);
        ALLOW(CERTIFICATE);
        ALLOW(CERTIFICATE_REQUEST);
    });
    EXT(SUPPORTED_GROUPS, {
        ALLOW(CLIENT_HELLO);
        ALLOW(ENCRYPTED_EXTENSIONS);
    });
    EXT(SIGNATURE_ALGORITHMS, {
        ALLOW(CLIENT_HELLO);
        ALLOW(CERTIFICATE_REQUEST);
    });
    EXT(ALPN, {
        ALLOW(CLIENT_HELLO);
        ALLOW(ENCRYPTED_EXTENSIONS);
    });
    EXT(KEY_SHARE, {
        ALLOW(CLIENT_HELLO);
        ALLOW(SERVER_HELLO);
    });
    EXT(PRE_SHARED_KEY, {
        ALLOW(CLIENT_HELLO);
        ALLOW(SERVER_HELLO);
    });
    EXT(PSK_KEY_EXCHANGE_MODES, { ALLOW(CLIENT_HELLO); });
    EXT(EARLY_DATA, {
        ALLOW(CLIENT_HELLO);
        ALLOW(ENCRYPTED_EXTENSIONS);
        ALLOW(NEW_SESSION_TICKET);
    });
    EXT(COOKIE, {
        ALLOW(CLIENT_HELLO);
        ALLOW(SERVER_HELLO);
    });
    EXT(SUPPORTED_VERSIONS, {
        ALLOW(CLIENT_HELLO);
        ALLOW(SERVER_HELLO);
    });

#undef ALLOW
#undef EXT
}

#ifndef ntoh16
static uint16_t ntoh16(const uint8_t *src)
{
    return (uint16_t)src[0] << 8 | src[1];
}
#endif

#ifndef ntoh24
static uint32_t ntoh24(const uint8_t *src)
{
    return (uint32_t)src[0] << 16 | (uint32_t)src[1] << 8 | src[2];
}
#endif

#ifndef ntoh32
static uint32_t ntoh32(const uint8_t *src)
{
    return (uint32_t)src[0] << 24 | (uint32_t)src[1] << 16 | (uint32_t)src[2] << 8 | src[3];
}
#endif

#ifndef ntoh64
static uint64_t ntoh64(const uint8_t *src)
{
    return (uint64_t)src[0] << 56 | (uint64_t)src[1] << 48 | (uint64_t)src[2] << 40 | (uint64_t)src[3] << 32 |
           (uint64_t)src[4] << 24 | (uint64_t)src[5] << 16 | (uint64_t)src[6] << 8 | src[7];
}
#endif

void ptls_buffer__release_memory(ptls_buffer_t *buf)
{
    ptls_clear_memory(buf->base, buf->off);
    if (buf->is_allocated)
        free(buf->base);
}

int ptls_buffer_reserve(ptls_buffer_t *buf, size_t delta)
{
    if (buf->base == NULL)
        return PTLS_ERROR_NO_MEMORY;

    if (PTLS_MEMORY_DEBUG || buf->capacity < buf->off + delta) {
        uint8_t *newp;
        size_t new_capacity = buf->capacity;
        if (new_capacity < 1024)
            new_capacity = 1024;
        while (new_capacity < buf->off + delta) {
            new_capacity *= 2;
        }
        if ((newp = malloc(new_capacity)) == NULL)
            return PTLS_ERROR_NO_MEMORY;
        memcpy(newp, buf->base, buf->off);
        ptls_buffer__release_memory(buf);
        buf->base = newp;
        buf->capacity = new_capacity;
        buf->is_allocated = 1;
    }

    return 0;
}

int ptls_buffer__do_pushv(ptls_buffer_t *buf, const void *src, size_t len)
{
    int ret;

    if (len == 0)
        return 0;
    if ((ret = ptls_buffer_reserve(buf, len)) != 0)
        return ret;
    memcpy(buf->base + buf->off, src, len);
    buf->off += len;
    return 0;
}

int ptls_buffer__adjust_quic_blocksize(ptls_buffer_t *buf, size_t body_size)
{
    uint8_t sizebuf[PTLS_ENCODE_QUICINT_CAPACITY];
    size_t sizelen = ptls_encode_quicint(sizebuf, body_size) - sizebuf;

    /* adjust amount of space before body_size to `sizelen` bytes */
    if (sizelen != 1) {
        int ret;
        if ((ret = ptls_buffer_reserve(buf, sizelen - 1)) != 0)
            return ret;
        memmove(buf->base + buf->off - body_size - 1 + sizelen, buf->base + buf->off - body_size, body_size);
        buf->off += sizelen - 1;
    }

    /* write the size */
    memcpy(buf->base + buf->off - body_size - sizelen, sizebuf, sizelen);

    return 0;
}

int ptls_buffer__adjust_asn1_blocksize(ptls_buffer_t *buf, size_t body_size)
{
    fprintf(stderr, "unimplemented\n");
    abort();
}

int ptls_buffer_push_asn1_ubigint(ptls_buffer_t *buf, const void *bignum, size_t size)
{
    const uint8_t *p = bignum, *const end = p + size;
    int ret;

    /* skip zeroes */
    for (; end - p >= 1; ++p)
        if (*p != 0)
            break;

    /* emit */
    ptls_buffer_push(buf, 2);
    ptls_buffer_push_asn1_block(buf, {
        if (*p >= 0x80)
            ptls_buffer_push(buf, 0);
        if (p != end) {
            ptls_buffer_pushv(buf, p, end - p);
        } else {
            ptls_buffer_pushv(buf, "", 1);
        }
    });
    ret = 0;

Exit:
    return ret;
}

#if PTLS_FUZZ_HANDSHAKE

static size_t aead_encrypt(struct st_ptls_traffic_protection_t *ctx, void *output, const void *input, size_t inlen,
                           uint8_t content_type)
{
    memcpy(output, input, inlen);
    memcpy(output + inlen, &content_type, 1);
    return inlen + 1 + 16;
}

static int aead_decrypt(struct st_ptls_traffic_protection_t *ctx, void *output, size_t *outlen, const void *input, size_t inlen)
{
    if (inlen < 16) {
        return PTLS_ALERT_BAD_RECORD_MAC;
    }
    memcpy(output, input, inlen - 16);
    *outlen = inlen - 16; /* removing the 16 bytes of tag */
    return 0;
}

#else

static void build_aad(uint8_t aad[5], size_t reclen)
{
    aad[0] = PTLS_CONTENT_TYPE_APPDATA;
    aad[1] = PTLS_RECORD_VERSION_MAJOR;
    aad[2] = PTLS_RECORD_VERSION_MINOR;
    aad[3] = (uint8_t)(reclen >> 8);
    aad[4] = (uint8_t)reclen;
}

static size_t aead_encrypt(struct st_ptls_traffic_protection_t *ctx, void *output, const void *input, size_t inlen,
                           uint8_t content_type)
{
    uint8_t aad[5];
    size_t off = 0;

    build_aad(aad, inlen + 1 + ctx->aead->algo->tag_size);
    ptls_aead_encrypt_init(ctx->aead, ctx->seq++, aad, sizeof(aad));
    off += ptls_aead_encrypt_update(ctx->aead, ((uint8_t *)output) + off, input, inlen);
    off += ptls_aead_encrypt_update(ctx->aead, ((uint8_t *)output) + off, &content_type, 1);
    off += ptls_aead_encrypt_final(ctx->aead, ((uint8_t *)output) + off);

    return off;
}

static int aead_decrypt(struct st_ptls_traffic_protection_t *ctx, void *output, size_t *outlen, const void *input, size_t inlen)
{
    uint8_t aad[5];

    build_aad(aad, inlen);
    if ((*outlen = ptls_aead_decrypt(ctx->aead, output, input, inlen, ctx->seq, aad, sizeof(aad))) == SIZE_MAX)
        return PTLS_ALERT_BAD_RECORD_MAC;
    ++ctx->seq;
    return 0;
}

#endif /* #if PTLS_FUZZ_HANDSHAKE */

#define buffer_push_record(buf, type, block)                                                                                       \
    do {                                                                                                                           \
        ptls_buffer_push((buf), (type), PTLS_RECORD_VERSION_MAJOR, PTLS_RECORD_VERSION_MINOR);                                     \
        ptls_buffer_push_block((buf), 2, block);                                                                                   \
    } while (0)

static int buffer_push_encrypted_records(ptls_buffer_t *buf, uint8_t type, const uint8_t *src, size_t len,
                                         struct st_ptls_traffic_protection_t *enc)
{
    int ret = 0;

    while (len != 0) {
        size_t chunk_size = len;
        if (chunk_size > PTLS_MAX_PLAINTEXT_RECORD_SIZE)
            chunk_size = PTLS_MAX_PLAINTEXT_RECORD_SIZE;
        buffer_push_record(buf, PTLS_CONTENT_TYPE_APPDATA, {
            if ((ret = ptls_buffer_reserve(buf, chunk_size + enc->aead->algo->tag_size + 1)) != 0)
                goto Exit;
            buf->off += aead_encrypt(enc, buf->base + buf->off, src, chunk_size, type);
        });
        src += chunk_size;
        len -= chunk_size;
    }

Exit:
    return ret;
}

static int buffer_encrypt_record(ptls_buffer_t *buf, size_t rec_start, struct st_ptls_traffic_protection_t *enc)
{
    size_t bodylen = buf->off - rec_start - 5;
    uint8_t *tmpbuf, type = buf->base[rec_start];
    int ret;

    /* fast path: do in-place encryption if only one record needs to be emitted */
    if (bodylen <= PTLS_MAX_PLAINTEXT_RECORD_SIZE) {
        size_t overhead = 1 + enc->aead->algo->tag_size;
        if ((ret = ptls_buffer_reserve(buf, overhead)) != 0)
            return ret;
        size_t encrypted_len = aead_encrypt(enc, buf->base + rec_start + 5, buf->base + rec_start + 5, bodylen, type);
        assert(encrypted_len == bodylen + overhead);
        buf->off += overhead;
        buf->base[rec_start] = PTLS_CONTENT_TYPE_APPDATA;
        buf->base[rec_start + 3] = (encrypted_len >> 8) & 0xff;
        buf->base[rec_start + 4] = encrypted_len & 0xff;
        return 0;
    }

    /* move plaintext to temporary buffer */
    if ((tmpbuf = malloc(bodylen)) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }
    memcpy(tmpbuf, buf->base + rec_start + 5, bodylen);
    ptls_clear_memory(buf->base + rec_start, bodylen + 5);
    buf->off = rec_start;

    /* push encrypted records */
    ret = buffer_push_encrypted_records(buf, type, tmpbuf, bodylen, enc);

Exit:
    if (tmpbuf != NULL) {
        ptls_clear_memory(tmpbuf, bodylen);
        free(tmpbuf);
    }
    return ret;
}

static int begin_record_message(ptls_message_emitter_t *_self)
{
    struct st_ptls_record_message_emitter_t *self = (void *)_self;
    int ret;

    self->rec_start = self->super.buf->off;
    ptls_buffer_push(self->super.buf, PTLS_CONTENT_TYPE_HANDSHAKE, PTLS_RECORD_VERSION_MAJOR, PTLS_RECORD_VERSION_MINOR, 0, 0);
    ret = 0;
Exit:
    return ret;
}

static int commit_record_message(ptls_message_emitter_t *_self)
{
    struct st_ptls_record_message_emitter_t *self = (void *)_self;
    int ret;

    if (self->super.enc->aead != NULL) {
        ret = buffer_encrypt_record(self->super.buf, self->rec_start, self->super.enc);
    } else {
        /* TODO allow CH,SH,HRR above 16KB */
        size_t sz = self->super.buf->off - self->rec_start - 5;
        assert(sz <= PTLS_MAX_PLAINTEXT_RECORD_SIZE);
        self->super.buf->base[self->rec_start + 3] = (uint8_t)(sz >> 8);
        self->super.buf->base[self->rec_start + 4] = (uint8_t)(sz);
        ret = 0;
    }

    return ret;
}

#define buffer_push_extension(buf, type, block)                                                                                    \
    do {                                                                                                                           \
        ptls_buffer_push16((buf), (type));                                                                                         \
        ptls_buffer_push_block((buf), 2, block);                                                                                   \
    } while (0);

#define decode_open_extensions(src, end, hstype, exttype, block)                                                                   \
    do {                                                                                                                           \
        struct st_ptls_extension_bitmap_t bitmap;                                                                                  \
        init_extension_bitmap(&bitmap, (hstype));                                                                                  \
        ptls_decode_open_block((src), end, 2, {                                                                                    \
            while ((src) != end) {                                                                                                 \
                if ((ret = ptls_decode16((exttype), &(src), end)) != 0)                                                            \
                    goto Exit;                                                                                                     \
                if (extension_bitmap_is_set(&bitmap, *(exttype)) != 0) {                                                           \
                    ret = PTLS_ALERT_ILLEGAL_PARAMETER;                                                                            \
                    goto Exit;                                                                                                     \
                }                                                                                                                  \
                extension_bitmap_set(&bitmap, *(exttype));                                                                         \
                ptls_decode_open_block((src), end, 2, block);                                                                      \
            }                                                                                                                      \
        });                                                                                                                        \
    } while (0)

#define decode_extensions(src, end, hstype, exttype, block)                                                                        \
    do {                                                                                                                           \
        decode_open_extensions((src), end, hstype, exttype, block);                                                                \
        ptls_decode_assert_block_close((src), end);                                                                                \
    } while (0)

int ptls_decode16(uint16_t *value, const uint8_t **src, const uint8_t *end)
{
    if (end - *src < 2)
        return PTLS_ALERT_DECODE_ERROR;
    *value = ntoh16(*src);
    *src += 2;
    return 0;
}

int ptls_decode24(uint32_t *value, const uint8_t **src, const uint8_t *end)
{
    if (end - *src < 3)
        return PTLS_ALERT_DECODE_ERROR;
    *value = ((uint32_t)(*src)[0] << 16) | ((uint32_t)(*src)[1] << 8) | (*src)[2];
    *src += 3;
    return 0;
}

int ptls_decode32(uint32_t *value, const uint8_t **src, const uint8_t *end)
{
    if (end - *src < 4)
        return PTLS_ALERT_DECODE_ERROR;
    *value = ntoh32(*src);
    *src += 4;
    return 0;
}

int ptls_decode64(uint64_t *value, const uint8_t **src, const uint8_t *end)
{
    if (end - *src < 8)
        return PTLS_ALERT_DECODE_ERROR;
    *value = ntoh64(*src);
    *src += 8;
    return 0;
}

uint64_t ptls_decode_quicint(const uint8_t **src, const uint8_t *end)
{
    if (PTLS_UNLIKELY(*src == end))
        return UINT64_MAX;

    uint8_t b = *(*src)++;

    if (PTLS_LIKELY(b <= 0x3f))
        return b;

    uint64_t v = b & 0x3f;
    unsigned bytes_left = (1 << (b >> 6)) - 1;
    if (PTLS_UNLIKELY((size_t)(end - *src) < bytes_left))
        return UINT64_MAX;
    do {
        v = (v << 8) | *(*src)++;
    } while (--bytes_left != 0);
    return v;
}

static void log_secret(ptls_t *tls, const char *type, ptls_iovec_t secret)
{
    char hexbuf[PTLS_MAX_DIGEST_SIZE * 2 + 1];

    PTLS_PROBE(NEW_SECRET, tls, type, ptls_hexdump(hexbuf, secret.base, secret.len));

    if (tls->ctx->log_event != NULL)
        tls->ctx->log_event->cb(tls->ctx->log_event, tls, type, "%s", ptls_hexdump(hexbuf, secret.base, secret.len));
}

static void key_schedule_free(ptls_key_schedule_t *sched)
{
    size_t i;
    ptls_clear_memory(sched->secret, sizeof(sched->secret));
    for (i = 0; i != sched->num_hashes; ++i)
        sched->hashes[i].ctx->final(sched->hashes[i].ctx, NULL, PTLS_HASH_FINAL_MODE_FREE);
    free(sched);
}

static ptls_key_schedule_t *key_schedule_new(ptls_cipher_suite_t *preferred, ptls_cipher_suite_t **offered,
                                             const char *hkdf_label_prefix)
{
#define FOREACH_HASH(block)                                                                                                        \
    do {                                                                                                                           \
        ptls_cipher_suite_t *cs;                                                                                                   \
        if ((cs = preferred) != NULL) {                                                                                            \
            block                                                                                                                  \
        }                                                                                                                          \
        if (offered != NULL) {                                                                                                     \
            size_t i, j;                                                                                                           \
            for (i = 0; (cs = offered[i]) != NULL; ++i) {                                                                          \
                if (preferred == NULL || cs->hash != preferred->hash) {                                                            \
                    for (j = 0; j != i; ++j)                                                                                       \
                        if (cs->hash == offered[j]->hash)                                                                          \
                            break;                                                                                                 \
                    if (j == i) {                                                                                                  \
                        block                                                                                                      \
                    }                                                                                                              \
                }                                                                                                                  \
            }                                                                                                                      \
        }                                                                                                                          \
    } while (0)

    ptls_key_schedule_t *sched;

    if (hkdf_label_prefix == NULL)
        hkdf_label_prefix = PTLS_HKDF_EXPAND_LABEL_PREFIX;

    { /* allocate */
        size_t num_hashes = 0;
        FOREACH_HASH({ ++num_hashes; });
        if ((sched = malloc(offsetof(ptls_key_schedule_t, hashes) + sizeof(sched->hashes[0]) * num_hashes)) == NULL)
            return NULL;
        *sched = (ptls_key_schedule_t){0, hkdf_label_prefix};
    }

    /* setup the hash algos and contexts */
    FOREACH_HASH({
        sched->hashes[sched->num_hashes].algo = cs->hash;
        if ((sched->hashes[sched->num_hashes].ctx = cs->hash->create()) == NULL)
            goto Fail;
        ++sched->num_hashes;
    });

    return sched;
Fail:
    key_schedule_free(sched);
    return NULL;

#undef FOREACH_HASH
}

static int key_schedule_extract(ptls_key_schedule_t *sched, ptls_iovec_t ikm)
{
    int ret;

    if (ikm.base == NULL)
        ikm = ptls_iovec_init(zeroes_of_max_digest_size, sched->hashes[0].algo->digest_size);

    if (sched->generation != 0 &&
        (ret = hkdf_expand_label(sched->hashes[0].algo, sched->secret, sched->hashes[0].algo->digest_size,
                                 ptls_iovec_init(sched->secret, sched->hashes[0].algo->digest_size), "derived",
                                 ptls_iovec_init(sched->hashes[0].algo->empty_digest, sched->hashes[0].algo->digest_size),
                                 sched->hkdf_label_prefix)) != 0)
        return ret;

    ++sched->generation;
    ret = ptls_hkdf_extract(sched->hashes[0].algo, sched->secret,
                            ptls_iovec_init(sched->secret, sched->hashes[0].algo->digest_size), ikm);
    PTLS_DEBUGF("%s: %u, %02x%02x\n", __FUNCTION__, sched->generation, (int)sched->secret[0], (int)sched->secret[1]);
    return ret;
}

static int key_schedule_select_one(ptls_key_schedule_t *sched, ptls_cipher_suite_t *cs, int reset)
{
    size_t found_slot = SIZE_MAX, i;
    int ret;

    assert(sched->generation == 1);

    /* find the one, while freeing others */
    for (i = 0; i != sched->num_hashes; ++i) {
        if (sched->hashes[i].algo == cs->hash) {
            assert(found_slot == SIZE_MAX);
            found_slot = i;
        } else {
            sched->hashes[i].ctx->final(sched->hashes[i].ctx, NULL, PTLS_HASH_FINAL_MODE_FREE);
        }
    }
    if (found_slot != 0) {
        sched->hashes[0] = sched->hashes[found_slot];
        reset = 1;
    }
    sched->num_hashes = 1;

    /* recalculate the hash if a different hash as been selected than the one we used for calculating the early secrets */
    if (reset) {
        --sched->generation;
        memset(sched->secret, 0, sizeof(sched->secret));
        if ((ret = key_schedule_extract(sched, ptls_iovec_init(NULL, 0))) != 0)
            goto Exit;
    }

    ret = 0;
Exit:
    return ret;
}

void ptls__key_schedule_update_hash(ptls_key_schedule_t *sched, const uint8_t *msg, size_t msglen)
{
    size_t i;

    PTLS_DEBUGF("%s:%zu\n", __FUNCTION__, msglen);
    for (i = 0; i != sched->num_hashes; ++i)
        sched->hashes[i].ctx->update(sched->hashes[i].ctx, msg, msglen);
}

static void key_schedule_update_ch1hash_prefix(ptls_key_schedule_t *sched)
{
    uint8_t prefix[4] = {PTLS_HANDSHAKE_TYPE_MESSAGE_HASH, 0, 0, (uint8_t)sched->hashes[0].algo->digest_size};
    ptls__key_schedule_update_hash(sched, prefix, sizeof(prefix));
}

static void key_schedule_extract_ch1hash(ptls_key_schedule_t *sched, uint8_t *hash)
{
    sched->hashes[0].ctx->final(sched->hashes[0].ctx, hash, PTLS_HASH_FINAL_MODE_RESET);
}

static void key_schedule_transform_post_ch1hash(ptls_key_schedule_t *sched)
{
    uint8_t ch1hash[PTLS_MAX_DIGEST_SIZE];

    key_schedule_extract_ch1hash(sched, ch1hash);

    key_schedule_update_ch1hash_prefix(sched);
    ptls__key_schedule_update_hash(sched, ch1hash, sched->hashes[0].algo->digest_size);
}

static int derive_secret_with_hash(ptls_key_schedule_t *sched, void *secret, const char *label, const uint8_t *hash)
{
    int ret = hkdf_expand_label(sched->hashes[0].algo, secret, sched->hashes[0].algo->digest_size,
                                ptls_iovec_init(sched->secret, sched->hashes[0].algo->digest_size), label,
                                ptls_iovec_init(hash, sched->hashes[0].algo->digest_size), sched->hkdf_label_prefix);
    PTLS_DEBUGF("%s: (label=%s, hash=%02x%02x) => %02x%02x\n", __FUNCTION__, label, hash[0], hash[1], ((uint8_t *)secret)[0],
                ((uint8_t *)secret)[1]);
    return ret;
}

static int derive_secret(ptls_key_schedule_t *sched, void *secret, const char *label)
{
    uint8_t hash_value[PTLS_MAX_DIGEST_SIZE];

    sched->hashes[0].ctx->final(sched->hashes[0].ctx, hash_value, PTLS_HASH_FINAL_MODE_SNAPSHOT);
    int ret = derive_secret_with_hash(sched, secret, label, hash_value);
    ptls_clear_memory(hash_value, sizeof(hash_value));
    return ret;
}

static int derive_secret_with_empty_digest(ptls_key_schedule_t *sched, void *secret, const char *label)
{
    return derive_secret_with_hash(sched, secret, label, sched->hashes[0].algo->empty_digest);
}

static int derive_exporter_secret(ptls_t *tls, int is_early)
{
    int ret;

    if (!tls->ctx->use_exporter)
        return 0;

    uint8_t **slot = is_early ? &tls->exporter_master_secret.early : &tls->exporter_master_secret.one_rtt;
    assert(*slot == NULL);
    if ((*slot = malloc(tls->key_schedule->hashes[0].algo->digest_size)) == NULL)
        return PTLS_ERROR_NO_MEMORY;

    if ((ret = derive_secret(tls->key_schedule, *slot, is_early ? "e exp master" : "exp master")) != 0)
        return ret;

    log_secret(tls, is_early ? "EARLY_EXPORTER_SECRET" : "EXPORTER_SECRET",
               ptls_iovec_init(*slot, tls->key_schedule->hashes[0].algo->digest_size));

    return 0;
}

static void free_exporter_master_secret(ptls_t *tls, int is_early)
{
    uint8_t *slot = is_early ? tls->exporter_master_secret.early : tls->exporter_master_secret.one_rtt;
    if (slot == NULL)
        return;
    assert(tls->key_schedule != NULL);
    ptls_clear_memory(slot, tls->key_schedule->hashes[0].algo->digest_size);
    free(slot);
}

static int derive_resumption_secret(ptls_key_schedule_t *sched, uint8_t *secret, ptls_iovec_t nonce)
{
    int ret;

    if ((ret = derive_secret(sched, secret, "res master")) != 0)
        goto Exit;
    if ((ret = hkdf_expand_label(sched->hashes[0].algo, secret, sched->hashes[0].algo->digest_size,
                                 ptls_iovec_init(secret, sched->hashes[0].algo->digest_size), "resumption", nonce,
                                 sched->hkdf_label_prefix)) != 0)
        goto Exit;

Exit:
    if (ret != 0)
        ptls_clear_memory(secret, sched->hashes[0].algo->digest_size);
    return ret;
}

static int decode_new_session_ticket(ptls_t *tls, uint32_t *lifetime, uint32_t *age_add, ptls_iovec_t *nonce, ptls_iovec_t *ticket,
                                     uint32_t *max_early_data_size, const uint8_t *src, const uint8_t *const end)
{
    uint16_t exttype;
    int ret;

    if ((ret = ptls_decode32(lifetime, &src, end)) != 0)
        goto Exit;
    if ((ret = ptls_decode32(age_add, &src, end)) != 0)
        goto Exit;
    ptls_decode_open_block(src, end, 1, {
        *nonce = ptls_iovec_init(src, end - src);
        src = end;
    });
    ptls_decode_open_block(src, end, 2, {
        if (src == end) {
            ret = PTLS_ALERT_DECODE_ERROR;
            goto Exit;
        }
        *ticket = ptls_iovec_init(src, end - src);
        src = end;
    });

    *max_early_data_size = 0;
    decode_extensions(src, end, PTLS_HANDSHAKE_TYPE_NEW_SESSION_TICKET, &exttype, {
        if (tls->ctx->on_extension != NULL &&
            (ret = tls->ctx->on_extension->cb(tls->ctx->on_extension, tls, PTLS_HANDSHAKE_TYPE_NEW_SESSION_TICKET, exttype,
                                              ptls_iovec_init(src, end - src)) != 0))
            goto Exit;
        switch (exttype) {
        case PTLS_EXTENSION_TYPE_EARLY_DATA:
            if ((ret = ptls_decode32(max_early_data_size, &src, end)) != 0)
                goto Exit;
            break;
        default:
            src = end;
            break;
        }
    });

    ret = 0;
Exit:
    return ret;
}

static int decode_stored_session_ticket(ptls_t *tls, ptls_key_exchange_algorithm_t **key_share, ptls_cipher_suite_t **cs,
                                        ptls_iovec_t *secret, uint32_t *obfuscated_ticket_age, ptls_iovec_t *ticket,
                                        uint32_t *max_early_data_size, const uint8_t *src, const uint8_t *const end)
{
    uint16_t kxid, csid;
    uint32_t lifetime, age_add;
    uint64_t obtained_at, now;
    ptls_iovec_t nonce;
    int ret;

    /* decode */
    if ((ret = ptls_decode64(&obtained_at, &src, end)) != 0)
        goto Exit;
    if ((ret = ptls_decode16(&kxid, &src, end)) != 0)
        goto Exit;
    if ((ret = ptls_decode16(&csid, &src, end)) != 0)
        goto Exit;
    ptls_decode_open_block(src, end, 3, {
        if ((ret = decode_new_session_ticket(tls, &lifetime, &age_add, &nonce, ticket, max_early_data_size, src, end)) != 0)
            goto Exit;
        src = end;
    });
    ptls_decode_block(src, end, 2, {
        *secret = ptls_iovec_init(src, end - src);
        src = end;
    });

    { /* determine the key-exchange */
        ptls_key_exchange_algorithm_t **cand;
        for (cand = tls->ctx->key_exchanges; *cand != NULL; ++cand)
            if ((*cand)->id == kxid)
                break;
        if (*cand == NULL) {
            ret = PTLS_ERROR_LIBRARY;
            goto Exit;
        }
        *key_share = *cand;
    }

    { /* determine the cipher-suite */
        ptls_cipher_suite_t **cand;
        for (cand = tls->ctx->cipher_suites; *cand != NULL; ++cand)
            if ((*cand)->id == csid)
                break;
        if (*cand == NULL) {
            ret = PTLS_ERROR_LIBRARY;
            goto Exit;
        }
        *cs = *cand;
    }

    /* calculate obfuscated_ticket_age */
    now = tls->ctx->get_time->cb(tls->ctx->get_time);
    if (!(obtained_at <= now && now - obtained_at < 7 * 86400 * 1000)) {
        ret = PTLS_ERROR_LIBRARY;
        goto Exit;
    }
    *obfuscated_ticket_age = (uint32_t)(now - obtained_at) + age_add;

    ret = 0;
Exit:
    return ret;
}

static int get_traffic_key(ptls_hash_algorithm_t *algo, void *key, size_t key_size, int is_iv, const void *secret,
                           ptls_iovec_t hash_value, const char *label_prefix)
{
    return ptls_hkdf_expand_label(algo, key, key_size, ptls_iovec_init(secret, algo->digest_size), is_iv ? "iv" : "key", hash_value,
                                  label_prefix);
}

static int setup_traffic_protection(ptls_t *tls, int is_enc, const char *secret_label, size_t epoch, int skip_notify)
{
    static const char *log_labels[2][4] = {
        {NULL, "CLIENT_EARLY_TRAFFIC_SECRET", "CLIENT_HANDSHAKE_TRAFFIC_SECRET", "CLIENT_TRAFFIC_SECRET_0"},
        {NULL, NULL, "SERVER_HANDSHAKE_TRAFFIC_SECRET", "SERVER_TRAFFIC_SECRET_0"}};
    struct st_ptls_traffic_protection_t *ctx = is_enc ? &tls->traffic_protection.enc : &tls->traffic_protection.dec;

    if (secret_label != NULL) {
        int ret;
        if ((ret = derive_secret(tls->key_schedule, ctx->secret, secret_label)) != 0)
            return ret;
    }

    ctx->epoch = epoch;

    /* special path for applications having their own record layer */
    if (tls->ctx->update_traffic_key != NULL) {
        if (skip_notify)
            return 0;
        return tls->ctx->update_traffic_key->cb(tls->ctx->update_traffic_key, tls, is_enc, epoch, ctx->secret);
    }

    if (ctx->aead != NULL)
        ptls_aead_free(ctx->aead);
    if ((ctx->aead = ptls_aead_new(tls->cipher_suite->aead, tls->cipher_suite->hash, is_enc, ctx->secret,
                                   tls->ctx->hkdf_label_prefix__obsolete)) == NULL)
        return PTLS_ERROR_NO_MEMORY; /* TODO obtain error from ptls_aead_new */
    ctx->seq = 0;

    log_secret(tls, log_labels[ptls_is_server(tls) == is_enc][epoch],
               ptls_iovec_init(ctx->secret, tls->key_schedule->hashes[0].algo->digest_size));
    PTLS_DEBUGF("[%s] %02x%02x,%02x%02x\n", log_labels[ptls_is_server(tls)][epoch], (unsigned)ctx->secret[0],
                (unsigned)ctx->secret[1], (unsigned)ctx->aead->static_iv[0], (unsigned)ctx->aead->static_iv[1]);

    return 0;
}

static int commission_handshake_secret(ptls_t *tls)
{
    int is_enc = !ptls_is_server(tls);

    assert(tls->pending_handshake_secret != NULL);
    memcpy((is_enc ? &tls->traffic_protection.enc : &tls->traffic_protection.dec)->secret, tls->pending_handshake_secret,
           PTLS_MAX_DIGEST_SIZE);
    ptls_clear_memory(tls->pending_handshake_secret, PTLS_MAX_DIGEST_SIZE);
    free(tls->pending_handshake_secret);
    tls->pending_handshake_secret = NULL;

    return setup_traffic_protection(tls, is_enc, NULL, 2, 1);
}

static void log_client_random(ptls_t *tls)
{
    PTLS_PROBE(CLIENT_RANDOM, tls,
               ptls_hexdump(alloca(sizeof(tls->client_random) * 2 + 1), tls->client_random, sizeof(tls->client_random)));
}

#define SESSION_IDENTIFIER_MAGIC "ptls0001" /* the number should be changed upon incompatible format change */
#define SESSION_IDENTIFIER_MAGIC_SIZE (sizeof(SESSION_IDENTIFIER_MAGIC) - 1)

static int encode_session_identifier(ptls_context_t *ctx, ptls_buffer_t *buf, uint32_t ticket_age_add, ptls_iovec_t ticket_nonce,
                                     ptls_key_schedule_t *sched, const char *server_name, uint16_t key_exchange_id, uint16_t csid,
                                     const char *negotiated_protocol)
{
    int ret = 0;

    ptls_buffer_push_block(buf, 2, {
        /* format id */
        ptls_buffer_pushv(buf, SESSION_IDENTIFIER_MAGIC, SESSION_IDENTIFIER_MAGIC_SIZE);
        /* date */
        ptls_buffer_push64(buf, ctx->get_time->cb(ctx->get_time));
        /* resumption master secret */
        ptls_buffer_push_block(buf, 2, {
            if ((ret = ptls_buffer_reserve(buf, sched->hashes[0].algo->digest_size)) != 0)
                goto Exit;
            if ((ret = derive_resumption_secret(sched, buf->base + buf->off, ticket_nonce)) != 0)
                goto Exit;
            buf->off += sched->hashes[0].algo->digest_size;
        });
        /* key-exchange */
        ptls_buffer_push16(buf, key_exchange_id);
        /* cipher-suite */
        ptls_buffer_push16(buf, csid);
        /* ticket_age_add */
        ptls_buffer_push32(buf, ticket_age_add);
        /* server-name */
        ptls_buffer_push_block(buf, 2, {
            if (server_name != NULL)
                ptls_buffer_pushv(buf, server_name, strlen(server_name));
        });
        /* alpn */
        ptls_buffer_push_block(buf, 1, {
            if (negotiated_protocol != NULL)
                ptls_buffer_pushv(buf, negotiated_protocol, strlen(negotiated_protocol));
        });
    });

Exit:
    return ret;
}

int decode_session_identifier(uint64_t *issued_at, ptls_iovec_t *psk, uint32_t *ticket_age_add, ptls_iovec_t *server_name,
                              uint16_t *key_exchange_id, uint16_t *csid, ptls_iovec_t *negotiated_protocol, const uint8_t *src,
                              const uint8_t *const end)
{
    int ret = 0;

    ptls_decode_block(src, end, 2, {
        if (end - src < SESSION_IDENTIFIER_MAGIC_SIZE ||
            memcmp(src, SESSION_IDENTIFIER_MAGIC, SESSION_IDENTIFIER_MAGIC_SIZE) != 0) {
            ret = PTLS_ALERT_DECODE_ERROR;
            goto Exit;
        }
        src += SESSION_IDENTIFIER_MAGIC_SIZE;
        if ((ret = ptls_decode64(issued_at, &src, end)) != 0)
            goto Exit;
        ptls_decode_open_block(src, end, 2, {
            *psk = ptls_iovec_init(src, end - src);
            src = end;
        });
        if ((ret = ptls_decode16(key_exchange_id, &src, end)) != 0)
            goto Exit;
        if ((ret = ptls_decode16(csid, &src, end)) != 0)
            goto Exit;
        if ((ret = ptls_decode32(ticket_age_add, &src, end)) != 0)
            goto Exit;
        ptls_decode_open_block(src, end, 2, {
            *server_name = ptls_iovec_init(src, end - src);
            src = end;
        });
        ptls_decode_open_block(src, end, 1, {
            *negotiated_protocol = ptls_iovec_init(src, end - src);
            src = end;
        });
    });

Exit:
    return ret;
}

static size_t build_certificate_verify_signdata(uint8_t *data, ptls_key_schedule_t *sched, const char *context_string)
{
    size_t datalen = 0;

    memset(data + datalen, 32, 64);
    datalen += 64;
    memcpy(data + datalen, context_string, strlen(context_string) + 1);
    datalen += strlen(context_string) + 1;
    sched->hashes[0].ctx->final(sched->hashes[0].ctx, data + datalen, PTLS_HASH_FINAL_MODE_SNAPSHOT);
    datalen += sched->hashes[0].algo->digest_size;
    assert(datalen <= PTLS_MAX_CERTIFICATE_VERIFY_SIGNDATA_SIZE);

    return datalen;
}

static int calc_verify_data(void *output, ptls_key_schedule_t *sched, const void *secret)
{
    ptls_hash_context_t *hmac;
    uint8_t digest[PTLS_MAX_DIGEST_SIZE];
    int ret;

    if ((ret = hkdf_expand_label(sched->hashes[0].algo, digest, sched->hashes[0].algo->digest_size,
                                 ptls_iovec_init(secret, sched->hashes[0].algo->digest_size), "finished", ptls_iovec_init(NULL, 0),
                                 sched->hkdf_label_prefix)) != 0)
        return ret;
    if ((hmac = ptls_hmac_create(sched->hashes[0].algo, digest, sched->hashes[0].algo->digest_size)) == NULL) {
        ptls_clear_memory(digest, sizeof(digest));
        return PTLS_ERROR_NO_MEMORY;
    }

    sched->hashes[0].ctx->final(sched->hashes[0].ctx, digest, PTLS_HASH_FINAL_MODE_SNAPSHOT);
    PTLS_DEBUGF("%s: %02x%02x,%02x%02x\n", __FUNCTION__, ((uint8_t *)secret)[0], ((uint8_t *)secret)[1], digest[0], digest[1]);
    hmac->update(hmac, digest, sched->hashes[0].algo->digest_size);
    ptls_clear_memory(digest, sizeof(digest));
    hmac->final(hmac, output, PTLS_HASH_FINAL_MODE_FREE);

    return 0;
}

static int verify_finished(ptls_t *tls, ptls_iovec_t message)
{
    uint8_t verify_data[PTLS_MAX_DIGEST_SIZE];
    int ret;

    if (PTLS_HANDSHAKE_HEADER_SIZE + tls->key_schedule->hashes[0].algo->digest_size != message.len) {
        ret = PTLS_ALERT_DECODE_ERROR;
        goto Exit;
    }

    if ((ret = calc_verify_data(verify_data, tls->key_schedule, tls->traffic_protection.dec.secret)) != 0)
        goto Exit;
    if (!ptls_mem_equal(message.base + PTLS_HANDSHAKE_HEADER_SIZE, verify_data, tls->key_schedule->hashes[0].algo->digest_size)) {
        ret = PTLS_ALERT_HANDSHAKE_FAILURE;
        goto Exit;
    }

Exit:
    ptls_clear_memory(verify_data, sizeof(verify_data));
    return ret;
}

static int send_finished(ptls_t *tls, ptls_message_emitter_t *emitter)
{
    int ret;

    ptls_push_message(emitter, tls->key_schedule, PTLS_HANDSHAKE_TYPE_FINISHED, {
        if ((ret = ptls_buffer_reserve(emitter->buf, tls->key_schedule->hashes[0].algo->digest_size)) != 0)
            goto Exit;
        if ((ret = calc_verify_data(emitter->buf->base + emitter->buf->off, tls->key_schedule,
                                    tls->traffic_protection.enc.secret)) != 0)
            goto Exit;
        emitter->buf->off += tls->key_schedule->hashes[0].algo->digest_size;
    });

Exit:
    return ret;
}

static int send_session_ticket(ptls_t *tls, ptls_message_emitter_t *emitter)
{
    ptls_hash_context_t *msghash_backup = tls->key_schedule->hashes[0].ctx->clone_(tls->key_schedule->hashes[0].ctx);
    ptls_buffer_t session_id;
    char session_id_smallbuf[128];
    uint32_t ticket_age_add;
    int ret = 0;

    assert(tls->ctx->ticket_lifetime != 0);
    assert(tls->ctx->encrypt_ticket != NULL);

    { /* calculate verify-data that will be sent by the client */
        size_t orig_off = emitter->buf->off;
        if (tls->pending_handshake_secret != NULL && !tls->ctx->omit_end_of_early_data) {
            assert(tls->state == PTLS_STATE_SERVER_EXPECT_END_OF_EARLY_DATA);
            ptls_buffer_push_message_body(emitter->buf, tls->key_schedule, PTLS_HANDSHAKE_TYPE_END_OF_EARLY_DATA, {});
            emitter->buf->off = orig_off;
        }
        ptls_buffer_push_message_body(emitter->buf, tls->key_schedule, PTLS_HANDSHAKE_TYPE_FINISHED, {
            if ((ret = ptls_buffer_reserve(emitter->buf, tls->key_schedule->hashes[0].algo->digest_size)) != 0)
                goto Exit;
            if ((ret = calc_verify_data(emitter->buf->base + emitter->buf->off, tls->key_schedule,
                                        tls->pending_handshake_secret != NULL ? tls->pending_handshake_secret
                                                                              : tls->traffic_protection.dec.secret)) != 0)
                goto Exit;
            emitter->buf->off += tls->key_schedule->hashes[0].algo->digest_size;
        });
        emitter->buf->off = orig_off;
    }

    tls->ctx->random_bytes(&ticket_age_add, sizeof(ticket_age_add));

    /* build the raw nsk */
    ptls_buffer_init(&session_id, session_id_smallbuf, sizeof(session_id_smallbuf));
    ret = encode_session_identifier(tls->ctx, &session_id, ticket_age_add, ptls_iovec_init(NULL, 0), tls->key_schedule,
                                    tls->server_name, tls->key_share->id, tls->cipher_suite->id, tls->negotiated_protocol);
    if (ret != 0)
        goto Exit;

    /* encrypt and send */
    ptls_push_message(emitter, tls->key_schedule, PTLS_HANDSHAKE_TYPE_NEW_SESSION_TICKET, {
        ptls_buffer_push32(emitter->buf, tls->ctx->ticket_lifetime);
        ptls_buffer_push32(emitter->buf, ticket_age_add);
        ptls_buffer_push_block(emitter->buf, 1, {});
        ptls_buffer_push_block(emitter->buf, 2, {
            if ((ret = tls->ctx->encrypt_ticket->cb(tls->ctx->encrypt_ticket, tls, 1, emitter->buf,
                                                    ptls_iovec_init(session_id.base, session_id.off))) != 0)
                goto Exit;
        });
        ptls_buffer_push_block(emitter->buf, 2, {
            if (tls->ctx->max_early_data_size != 0)
                buffer_push_extension(emitter->buf, PTLS_EXTENSION_TYPE_EARLY_DATA,
                                      { ptls_buffer_push32(emitter->buf, tls->ctx->max_early_data_size); });
        });
    });

Exit:
    ptls_buffer_dispose(&session_id);

    /* restore handshake state */
    tls->key_schedule->hashes[0].ctx->final(tls->key_schedule->hashes[0].ctx, NULL, PTLS_HASH_FINAL_MODE_FREE);
    tls->key_schedule->hashes[0].ctx = msghash_backup;

    return ret;
}

static int push_change_cipher_spec(ptls_t *tls, ptls_message_emitter_t *emitter)
{
    int ret;

    /* check if we are requested to (or still need to) */
    if (!tls->send_change_cipher_spec) {
        ret = 0;
        goto Exit;
    }

    /* CCS is a record, can only be sent when using a record-based protocol. */
    if (emitter->begin_message != begin_record_message) {
        ret = PTLS_ALERT_UNEXPECTED_MESSAGE;
        goto Exit;
    }

    /* emit CCS */
    buffer_push_record(emitter->buf, PTLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC, { ptls_buffer_push(emitter->buf, 1); });

    tls->send_change_cipher_spec = 0;
    ret = 0;
Exit:
    return ret;
}

static int push_additional_extensions(ptls_handshake_properties_t *properties, ptls_buffer_t *sendbuf)
{
    int ret;

    if (properties != NULL && properties->additional_extensions != NULL) {
        ptls_raw_extension_t *ext;
        for (ext = properties->additional_extensions; ext->type != UINT16_MAX; ++ext) {
            buffer_push_extension(sendbuf, ext->type, { ptls_buffer_pushv(sendbuf, ext->data.base, ext->data.len); });
        }
    }
    ret = 0;
Exit:
    return ret;
}

static int push_signature_algorithms(ptls_buffer_t *sendbuf)
{
    int ret;

    ptls_buffer_push_block(sendbuf, 2, {
        ptls_buffer_push16(sendbuf, PTLS_SIGNATURE_RSA_PSS_RSAE_SHA256);
        ptls_buffer_push16(sendbuf, PTLS_SIGNATURE_ECDSA_SECP256R1_SHA256);
        ptls_buffer_push16(sendbuf, PTLS_SIGNATURE_RSA_PKCS1_SHA256);
        ptls_buffer_push16(sendbuf, PTLS_SIGNATURE_RSA_PKCS1_SHA1);
    });

    ret = 0;
Exit:
    return ret;
}

static int decode_signature_algorithms(struct st_ptls_signature_algorithms_t *sa, const uint8_t **src, const uint8_t *end)
{
    int ret;

    ptls_decode_block(*src, end, 2, {
        do {
            uint16_t id;
            if ((ret = ptls_decode16(&id, src, end)) != 0)
                goto Exit;
            if (sa->count < PTLS_ELEMENTSOF(sa->list))
                sa->list[sa->count++] = id;
        } while (*src != end);
    });

    ret = 0;
Exit:
    return ret;
}

static ptls_hash_context_t *create_sha256_context(ptls_context_t *ctx)
{
    ptls_cipher_suite_t **cs;

    for (cs = ctx->cipher_suites; *cs != NULL; ++cs) {
        switch ((*cs)->id) {
        case PTLS_CIPHER_SUITE_AES_128_GCM_SHA256:
        case PTLS_CIPHER_SUITE_CHACHA20_POLY1305_SHA256:
            return (*cs)->hash->create();
        }
    }

    return NULL;
}

static int select_cipher(ptls_cipher_suite_t **selected, ptls_cipher_suite_t **candidates, const uint8_t *src,
                         const uint8_t *const end)
{
    int ret;

    while (src != end) {
        uint16_t id;
        if ((ret = ptls_decode16(&id, &src, end)) != 0)
            goto Exit;
        ptls_cipher_suite_t **c = candidates;
        for (; *c != NULL; ++c) {
            if ((*c)->id == id) {
                *selected = *c;
                return 0;
            }
        }
    }

    ret = PTLS_ALERT_HANDSHAKE_FAILURE;

Exit:
    return ret;
}

static int push_key_share_entry(ptls_buffer_t *buf, uint16_t group, ptls_iovec_t pubkey)
{
    int ret;

    ptls_buffer_push16(buf, group);
    ptls_buffer_push_block(buf, 2, { ptls_buffer_pushv(buf, pubkey.base, pubkey.len); });
    ret = 0;
Exit:
    return ret;
}

static int decode_key_share_entry(uint16_t *group, ptls_iovec_t *key_exchange, const uint8_t **src, const uint8_t *const end)
{
    int ret;

    if ((ret = ptls_decode16(group, src, end)) != 0)
        goto Exit;
    ptls_decode_open_block(*src, end, 2, {
        *key_exchange = ptls_iovec_init(*src, end - *src);
        *src = end;
    });

Exit:
    return ret;
}

static int select_key_share(ptls_key_exchange_algorithm_t **selected, ptls_iovec_t *peer_key,
                            ptls_key_exchange_algorithm_t **candidates, const uint8_t **src, const uint8_t *const end,
                            int expect_one)
{
    int ret;

    *selected = NULL;

    if (expect_one && *src == end) {
        ret = PTLS_ALERT_ILLEGAL_PARAMETER;
        goto Exit;
    }

    while (*src != end) {
        uint16_t group;
        ptls_iovec_t key;
        if ((ret = decode_key_share_entry(&group, &key, src, end)) != 0)
            goto Exit;
        ptls_key_exchange_algorithm_t **c = candidates;
        for (; *c != NULL; ++c) {
            if (*selected == NULL && (*c)->id == group) {
                *selected = *c;
                *peer_key = key;
            }
        }
        if (expect_one) {
            ret = *selected != NULL ? 0 : PTLS_ALERT_ILLEGAL_PARAMETER;
            goto Exit;
        }
    }

    ret = 0;

Exit:
    return ret;
}

static int emit_server_name_extension(ptls_buffer_t *buf, const char *server_name)
{
    int ret;

    ptls_buffer_push_block(buf, 2, {
        ptls_buffer_push(buf, PTLS_SERVER_NAME_TYPE_HOSTNAME);
        ptls_buffer_push_block(buf, 2, { ptls_buffer_pushv(buf, server_name, strlen(server_name)); });
    });

    ret = 0;
Exit:
    return ret;
}

static int parse_esni_keys(ptls_context_t *ctx, uint16_t *esni_version, ptls_key_exchange_algorithm_t **selected_key_share,
                           ptls_cipher_suite_t **selected_cipher, ptls_iovec_t *peer_key, uint16_t *padded_length,
                           char **published_sni, ptls_iovec_t input)
{
    const uint8_t *src = input.base, *const end = input.base + input.len;
    uint16_t version;
    uint64_t not_before, not_after, now;
    int ret = 0;

    /* version */
    if ((ret = ptls_decode16(&version, &src, end)) != 0)
        goto Exit;
    if (version != PTLS_ESNI_VERSION_DRAFT03) {
        ret = PTLS_ALERT_DECODE_ERROR;
        goto Exit;
    }

    { /* verify checksum */
        ptls_hash_context_t *hctx;
        uint8_t digest[PTLS_SHA256_DIGEST_SIZE];
        if (end - src < 4) {
            ret = PTLS_ALERT_DECODE_ERROR;
            goto Exit;
        }
        if ((hctx = create_sha256_context(ctx)) == NULL) {
            ret = PTLS_ERROR_LIBRARY;
            goto Exit;
        }
        hctx->update(hctx, input.base, src - input.base);
        hctx->update(hctx, "\0\0\0\0", 4);
        hctx->update(hctx, src + 4, end - (src + 4));
        hctx->final(hctx, digest, PTLS_HASH_FINAL_MODE_FREE);
        if (memcmp(src, digest, 4) != 0) {
            ret = PTLS_ALERT_DECODE_ERROR;
            goto Exit;
        }
        src += 4;
    }
    *esni_version = version;
    /* published sni */
    ptls_decode_open_block(src, end, 2, {
        size_t len = end - src;
        *published_sni = malloc(len + 1);
        if (*published_sni == NULL) {
            ret = PTLS_ERROR_NO_MEMORY;
            goto Exit;
        }
        if (len > 0) {
            memcpy(*published_sni, src, len);
        }
        (*published_sni)[len] = 0;
        src = end;
    });
    /* key-shares */
    ptls_decode_open_block(src, end, 2, {
        if ((ret = select_key_share(selected_key_share, peer_key, ctx->key_exchanges, &src, end, 0)) != 0)
            goto Exit;
    });
    /* cipher-suite */
    ptls_decode_open_block(src, end, 2, {
        if ((ret = select_cipher(selected_cipher, ctx->cipher_suites, src, end)) != 0)
            goto Exit;
        src = end;
    });
    /* padded-length */
    if ((ret = ptls_decode16(padded_length, &src, end)) != 0)
        goto Exit;
    if (padded_length == 0)
        goto Exit;
    /* not-before, not_after */
    if ((ret = ptls_decode64(&not_before, &src, end)) != 0 || (ret = ptls_decode64(&not_after, &src, end)) != 0)
        goto Exit;
    /* extensions */
    ptls_decode_block(src, end, 2, {
        while (src != end) {
            uint16_t id;
            if ((ret = ptls_decode16(&id, &src, end)) != 0)
                goto Exit;
            ptls_decode_open_block(src, end, 2, { src = end; });
        }
    });

    /* check validity period */
    now = ctx->get_time->cb(ctx->get_time);
    if (!(not_before * 1000 <= now && now <= not_after * 1000)) {
        ret = PTLS_ALERT_DECODE_ERROR;
        goto Exit;
    }

    ret = 0;
Exit:
    return ret;
}

static int create_esni_aead(ptls_aead_context_t **aead_ctx, int is_enc, ptls_cipher_suite_t *cipher, ptls_iovec_t ecdh_secret,
                            const uint8_t *esni_contents_hash)
{
    uint8_t aead_secret[PTLS_MAX_DIGEST_SIZE];
    int ret;

    if ((ret = ptls_hkdf_extract(cipher->hash, aead_secret, ptls_iovec_init(NULL, 0), ecdh_secret)) != 0)
        goto Exit;
    if ((*aead_ctx = new_aead(cipher->aead, cipher->hash, is_enc, aead_secret,
                              ptls_iovec_init(esni_contents_hash, cipher->hash->digest_size), "tls13 esni ")) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }

    ret = 0;
Exit:
    ptls_clear_memory(aead_secret, sizeof(aead_secret));
    return ret;
}

static int build_esni_contents_hash(ptls_hash_algorithm_t *hash, uint8_t *digest, const uint8_t *record_digest, uint16_t group,
                                    ptls_iovec_t pubkey, const uint8_t *client_random)
{
    ptls_buffer_t buf;
    uint8_t smallbuf[256];
    int ret;

    /* build ESNIContents */
    ptls_buffer_init(&buf, smallbuf, sizeof(smallbuf));
    ptls_buffer_push_block(&buf, 2, { ptls_buffer_pushv(&buf, record_digest, hash->digest_size); });
    if ((ret = push_key_share_entry(&buf, group, pubkey)) != 0)
        goto Exit;
    ptls_buffer_pushv(&buf, client_random, PTLS_HELLO_RANDOM_SIZE);

    /* calculate digest */
    if ((ret = ptls_calc_hash(hash, digest, buf.base, buf.off)) != 0)
        goto Exit;

    ret = 0;
Exit:
    ptls_buffer_dispose(&buf);
    return ret;
}

static void free_esni_secret(ptls_esni_secret_t **esni, int is_server)
{
    assert(*esni != NULL);
    if ((*esni)->secret.base != NULL) {
        ptls_clear_memory((*esni)->secret.base, (*esni)->secret.len);
        free((*esni)->secret.base);
    }
    if (!is_server)
        free((*esni)->client.pubkey.base);
    ptls_clear_memory((*esni), sizeof(**esni));
    free(*esni);
    *esni = NULL;
}

static int client_setup_esni(ptls_context_t *ctx, ptls_esni_secret_t **esni, ptls_iovec_t esni_keys, char **published_sni,
                             const uint8_t *client_random)
{
    ptls_iovec_t peer_key;
    int ret;

    if ((*esni = malloc(sizeof(**esni))) == NULL)
        return PTLS_ERROR_NO_MEMORY;
    memset(*esni, 0, sizeof(**esni));

    /* parse ESNI_Keys (and return success while keeping *esni NULL) */
    if (parse_esni_keys(ctx, &(*esni)->version, &(*esni)->client.key_share, &(*esni)->client.cipher, &peer_key,
                        &(*esni)->client.padded_length, published_sni, esni_keys) != 0) {
        free(*esni);
        *esni = NULL;
        return 0;
    }

    ctx->random_bytes((*esni)->nonce, sizeof((*esni)->nonce));

    /* calc record digest */
    if ((ret = ptls_calc_hash((*esni)->client.cipher->hash, (*esni)->client.record_digest, esni_keys.base, esni_keys.len)) != 0)
        goto Exit;
    /* derive ECDH secret */
    if ((ret = (*esni)->client.key_share->exchange((*esni)->client.key_share, &(*esni)->client.pubkey, &(*esni)->secret,
                                                   peer_key)) != 0)
        goto Exit;
    /* calc H(ESNIContents) */
    if ((ret = build_esni_contents_hash((*esni)->client.cipher->hash, (*esni)->esni_contents_hash, (*esni)->client.record_digest,
                                        (*esni)->client.key_share->id, (*esni)->client.pubkey, client_random)) != 0)
        goto Exit;

    ret = 0;
Exit:
    if (ret != 0)
        free_esni_secret(esni, 0);
    return ret;
}

static int emit_esni_extension(ptls_esni_secret_t *esni, ptls_buffer_t *buf, ptls_iovec_t esni_keys, const char *server_name,
                               size_t key_share_ch_off, size_t key_share_ch_len)
{
    ptls_aead_context_t *aead = NULL;
    int ret;

    if ((ret = create_esni_aead(&aead, 1, esni->client.cipher, esni->secret, esni->esni_contents_hash)) != 0)
        goto Exit;

    /* cipher-suite id */
    ptls_buffer_push16(buf, esni->client.cipher->id);
    /* key-share */
    if ((ret = push_key_share_entry(buf, esni->client.key_share->id, esni->client.pubkey)) != 0)
        goto Exit;
    /* record-digest */
    ptls_buffer_push_block(buf, 2, { ptls_buffer_pushv(buf, esni->client.record_digest, esni->client.cipher->hash->digest_size); });
    /* encrypted sni */
    ptls_buffer_push_block(buf, 2, {
        size_t start_off = buf->off;
        /* nonce */
        ptls_buffer_pushv(buf, esni->nonce, PTLS_ESNI_NONCE_SIZE);
        /* emit server-name extension */
        if ((ret = emit_server_name_extension(buf, server_name)) != 0)
            goto Exit;
        /* pad */
        if (buf->off - start_off < (size_t)(esni->client.padded_length + PTLS_ESNI_NONCE_SIZE)) {
            size_t bytes_to_pad = esni->client.padded_length + PTLS_ESNI_NONCE_SIZE - (buf->off - start_off);
            if ((ret = ptls_buffer_reserve(buf, bytes_to_pad)) != 0)
                goto Exit;
            memset(buf->base + buf->off, 0, bytes_to_pad);
            buf->off += bytes_to_pad;
        }
        /* encrypt */
        if ((ret = ptls_buffer_reserve(buf, aead->algo->tag_size)) != 0)
            goto Exit;
        ptls_aead_encrypt(aead, buf->base + start_off, buf->base + start_off, buf->off - start_off, 0, buf->base + key_share_ch_off,
                          key_share_ch_len);
        buf->off += aead->algo->tag_size;
    });

    ret = 0;
Exit:
    if (aead != NULL)
        ptls_aead_free(aead);
    return ret;
}

static int send_client_hello(ptls_t *tls, ptls_message_emitter_t *emitter, ptls_handshake_properties_t *properties,
                             ptls_iovec_t *cookie)
{
    ptls_iovec_t resumption_secret = {NULL}, resumption_ticket;
    char *published_sni = NULL;
    uint32_t obfuscated_ticket_age = 0;
    size_t msghash_off;
    uint8_t binder_key[PTLS_MAX_DIGEST_SIZE];
    int ret, is_second_flight = tls->key_schedule != NULL,
             send_sni = tls->server_name != NULL && !ptls_server_name_is_ipaddr(tls->server_name);

    if (properties != NULL) {
        /* try to use ESNI */
        if (!is_second_flight && send_sni && properties->client.esni_keys.base != NULL) {
            if ((ret = client_setup_esni(tls->ctx, &tls->esni, properties->client.esni_keys, &published_sni, tls->client_random)) !=
                0) {
                goto Exit;
            }
            if (tls->ctx->update_esni_key != NULL) {
                if ((ret = tls->ctx->update_esni_key->cb(tls->ctx->update_esni_key, tls, tls->esni->secret,
                                                         tls->esni->client.cipher->hash, tls->esni->esni_contents_hash)) != 0)
                    goto Exit;
            }
        }
        /* setup resumption-related data. If successful, resumption_secret becomes a non-zero value. */
        if (properties->client.session_ticket.base != NULL) {
            ptls_key_exchange_algorithm_t *key_share = NULL;
            ptls_cipher_suite_t *cipher_suite = NULL;
            uint32_t max_early_data_size;
            if (decode_stored_session_ticket(tls, &key_share, &cipher_suite, &resumption_secret, &obfuscated_ticket_age,
                                             &resumption_ticket, &max_early_data_size, properties->client.session_ticket.base,
                                             properties->client.session_ticket.base + properties->client.session_ticket.len) == 0) {
                tls->client.offered_psk = 1;
                /* key-share selected by HRR should not be overridden */
                if (tls->key_share == NULL)
                    tls->key_share = key_share;
                tls->cipher_suite = cipher_suite;
                if (!is_second_flight && max_early_data_size != 0 && properties->client.max_early_data_size != NULL) {
                    tls->client.using_early_data = 1;
                    *properties->client.max_early_data_size = max_early_data_size;
                }
            } else {
                resumption_secret = ptls_iovec_init(NULL, 0);
            }
        }
        if (tls->client.using_early_data) {
            properties->client.early_data_acceptance = PTLS_EARLY_DATA_ACCEPTANCE_UNKNOWN;
        } else {
            if (properties->client.max_early_data_size != NULL)
                *properties->client.max_early_data_size = 0;
            properties->client.early_data_acceptance = PTLS_EARLY_DATA_REJECTED;
        }
    }

    /* use the default key share if still not undetermined */
    if (tls->key_share == NULL && !(properties != NULL && properties->client.negotiate_before_key_exchange))
        tls->key_share = tls->ctx->key_exchanges[0];

    if (!is_second_flight) {
        tls->key_schedule = key_schedule_new(tls->cipher_suite, tls->ctx->cipher_suites, tls->ctx->hkdf_label_prefix__obsolete);
        if ((ret = key_schedule_extract(tls->key_schedule, resumption_secret)) != 0)
            goto Exit;
    }

    msghash_off = emitter->buf->off + emitter->record_header_length;
    ptls_push_message(emitter, NULL, PTLS_HANDSHAKE_TYPE_CLIENT_HELLO, {
        ptls_buffer_t *sendbuf = emitter->buf;
        /* legacy_version */
        ptls_buffer_push16(sendbuf, 0x0303);
        /* random_bytes */
        ptls_buffer_pushv(sendbuf, tls->client_random, sizeof(tls->client_random));
        /* lecagy_session_id */
        ptls_buffer_push_block(
            sendbuf, 1, { ptls_buffer_pushv(sendbuf, tls->client.legacy_session_id.base, tls->client.legacy_session_id.len); });
        /* cipher_suites */
        ptls_buffer_push_block(sendbuf, 2, {
            ptls_cipher_suite_t **cs = tls->ctx->cipher_suites;
            for (; *cs != NULL; ++cs)
                ptls_buffer_push16(sendbuf, (*cs)->id);
        });
        /* legacy_compression_methods */
        ptls_buffer_push_block(sendbuf, 1, { ptls_buffer_push(sendbuf, 0); });
        /* extensions */
        ptls_buffer_push_block(sendbuf, 2, {
            struct {
                size_t off;
                size_t len;
            } key_share_client_hello;
            buffer_push_extension(sendbuf, PTLS_EXTENSION_TYPE_KEY_SHARE, {
                key_share_client_hello.off = sendbuf->off;
                ptls_buffer_push_block(sendbuf, 2, {
                    if (tls->key_share != NULL) {
                        if ((ret = tls->key_share->create(tls->key_share, &tls->client.key_share_ctx)) != 0)
                            goto Exit;
                        if ((ret = push_key_share_entry(sendbuf, tls->key_share->id, tls->client.key_share_ctx->pubkey)) != 0)
                            goto Exit;
                    }
                });
                key_share_client_hello.len = sendbuf->off - key_share_client_hello.off;
            });
            if (send_sni) {
                if (tls->esni != NULL) {
                    if (published_sni != NULL) {
                        buffer_push_extension(sendbuf, PTLS_EXTENSION_TYPE_SERVER_NAME, {
                            if ((ret = emit_server_name_extension(sendbuf, published_sni)) != 0)
                                goto Exit;
                        });
                    }
                    buffer_push_extension(sendbuf, PTLS_EXTENSION_TYPE_ENCRYPTED_SERVER_NAME, {
                        if ((ret = emit_esni_extension(tls->esni, sendbuf, properties->client.esni_keys, tls->server_name,
                                                       key_share_client_hello.off, key_share_client_hello.len)) != 0)
                            goto Exit;
                    });
                } else {
                    buffer_push_extension(sendbuf, PTLS_EXTENSION_TYPE_SERVER_NAME, {
                        if ((ret = emit_server_name_extension(sendbuf, tls->server_name)) != 0)
                            goto Exit;
                    });
                }
            }
            if (properties != NULL && properties->client.negotiated_protocols.count != 0) {
                buffer_push_extension(sendbuf, PTLS_EXTENSION_TYPE_ALPN, {
                    ptls_buffer_push_block(sendbuf, 2, {
                        size_t i;
                        for (i = 0; i != properties->client.negotiated_protocols.count; ++i) {
                            ptls_buffer_push_block(sendbuf, 1, {
                                ptls_iovec_t p = properties->client.negotiated_protocols.list[i];
                                ptls_buffer_pushv(sendbuf, p.base, p.len);
                            });
                        }
                    });
                });
            }
            if (tls->ctx->decompress_certificate != NULL) {
                buffer_push_extension(sendbuf, PTLS_EXTENSION_TYPE_COMPRESS_CERTIFICATE, {
                    ptls_buffer_push_block(sendbuf, 1, {
                        const uint16_t *algo = tls->ctx->decompress_certificate->supported_algorithms;
                        assert(*algo != UINT16_MAX);
                        for (; *algo != UINT16_MAX; ++algo)
                            ptls_buffer_push16(sendbuf, *algo);
                    });
                });
            }
            buffer_push_extension(sendbuf, PTLS_EXTENSION_TYPE_SUPPORTED_VERSIONS, {
                ptls_buffer_push_block(sendbuf, 1, {
                    size_t i;
                    for (i = 0; i != PTLS_ELEMENTSOF(supported_versions); ++i)
                        ptls_buffer_push16(sendbuf, supported_versions[i]);
                });
            });
            buffer_push_extension(sendbuf, PTLS_EXTENSION_TYPE_SIGNATURE_ALGORITHMS, {
                if ((ret = push_signature_algorithms(sendbuf)) != 0)
                    goto Exit;
            });
            buffer_push_extension(sendbuf, PTLS_EXTENSION_TYPE_SUPPORTED_GROUPS, {
                ptls_key_exchange_algorithm_t **algo = tls->ctx->key_exchanges;
                ptls_buffer_push_block(sendbuf, 2, {
                    for (; *algo != NULL; ++algo)
                        ptls_buffer_push16(sendbuf, (*algo)->id);
                });
            });
            if (cookie != NULL && cookie->base != NULL) {
                buffer_push_extension(sendbuf, PTLS_EXTENSION_TYPE_COOKIE, {
                    ptls_buffer_push_block(sendbuf, 2, { ptls_buffer_pushv(sendbuf, cookie->base, cookie->len); });
                });
            }
            if ((ret = push_additional_extensions(properties, sendbuf)) != 0)
                goto Exit;
            if (tls->ctx->save_ticket != NULL || resumption_secret.base != NULL) {
                buffer_push_extension(sendbuf, PTLS_EXTENSION_TYPE_PSK_KEY_EXCHANGE_MODES, {
                    ptls_buffer_push_block(sendbuf, 1, {
                        if (!tls->ctx->require_dhe_on_psk)
                            ptls_buffer_push(sendbuf, PTLS_PSK_KE_MODE_PSK);
                        ptls_buffer_push(sendbuf, PTLS_PSK_KE_MODE_PSK_DHE);
                    });
                });
            }
            if (resumption_secret.base != NULL) {
                if (tls->client.using_early_data && !is_second_flight)
                    buffer_push_extension(sendbuf, PTLS_EXTENSION_TYPE_EARLY_DATA, {});
                /* pre-shared key "MUST be the last extension in the ClientHello" (draft-17 section 4.2.6) */
                buffer_push_extension(sendbuf, PTLS_EXTENSION_TYPE_PRE_SHARED_KEY, {
                    ptls_buffer_push_block(sendbuf, 2, {
                        ptls_buffer_push_block(sendbuf, 2,
                                               { ptls_buffer_pushv(sendbuf, resumption_ticket.base, resumption_ticket.len); });
                        ptls_buffer_push32(sendbuf, obfuscated_ticket_age);
                    });
                    /* allocate space for PSK binder. the space is filled at the bottom of the function */
                    ptls_buffer_push_block(sendbuf, 2, {
                        ptls_buffer_push_block(sendbuf, 1, {
                            if ((ret = ptls_buffer_reserve(sendbuf, tls->key_schedule->hashes[0].algo->digest_size)) != 0)
                                goto Exit;
                            sendbuf->off += tls->key_schedule->hashes[0].algo->digest_size;
                        });
                    });
                });
            }
        });
    });

    /* update the message hash, filling in the PSK binder HMAC if necessary */
    if (resumption_secret.base != NULL) {
        size_t psk_binder_off = emitter->buf->off - (3 + tls->key_schedule->hashes[0].algo->digest_size);
        if ((ret = derive_secret_with_empty_digest(tls->key_schedule, binder_key, "res binder")) != 0)
            goto Exit;
        ptls__key_schedule_update_hash(tls->key_schedule, emitter->buf->base + msghash_off, psk_binder_off - msghash_off);
        msghash_off = psk_binder_off;
        if ((ret = calc_verify_data(emitter->buf->base + psk_binder_off + 3, tls->key_schedule, binder_key)) != 0)
            goto Exit;
    }
    ptls__key_schedule_update_hash(tls->key_schedule, emitter->buf->base + msghash_off, emitter->buf->off - msghash_off);

    if (tls->client.using_early_data) {
        assert(!is_second_flight);
        if ((ret = setup_traffic_protection(tls, 1, "c e traffic", 1, 0)) != 0)
            goto Exit;
        if ((ret = push_change_cipher_spec(tls, emitter)) != 0)
            goto Exit;
    }
    if (resumption_secret.base != NULL && !is_second_flight) {
        if ((ret = derive_exporter_secret(tls, 1)) != 0)
            goto Exit;
    }
    tls->state = cookie == NULL ? PTLS_STATE_CLIENT_EXPECT_SERVER_HELLO : PTLS_STATE_CLIENT_EXPECT_SECOND_SERVER_HELLO;
    ret = PTLS_ERROR_IN_PROGRESS;

Exit:
    if (published_sni != NULL) {
        free(published_sni);
    }
    ptls_clear_memory(binder_key, sizeof(binder_key));
    return ret;
}

static ptls_cipher_suite_t *find_cipher_suite(ptls_context_t *ctx, uint16_t id)
{
    ptls_cipher_suite_t **cs;

    for (cs = ctx->cipher_suites; *cs != NULL && (*cs)->id != id; ++cs)
        ;
    return *cs;
}

static int decode_server_hello(ptls_t *tls, struct st_ptls_server_hello_t *sh, const uint8_t *src, const uint8_t *const end)
{
    int ret;

    *sh = (struct st_ptls_server_hello_t){{0}};

    /* ignore legacy-version */
    if (end - src < 2) {
        ret = PTLS_ALERT_DECODE_ERROR;
        goto Exit;
    }
    src += 2;

    /* random */
    if (end - src < PTLS_HELLO_RANDOM_SIZE) {
        ret = PTLS_ALERT_DECODE_ERROR;
        goto Exit;
    }
    sh->is_retry_request = memcmp(src, hello_retry_random, PTLS_HELLO_RANDOM_SIZE) == 0;
    src += PTLS_HELLO_RANDOM_SIZE;

    /* legacy_session_id */
    ptls_decode_open_block(src, end, 1, {
        if (end - src > 32) {
            ret = PTLS_ALERT_DECODE_ERROR;
            goto Exit;
        }
        sh->legacy_session_id = ptls_iovec_init(src, end - src);
        src = end;
    });

    { /* select cipher_suite */
        uint16_t csid;
        if ((ret = ptls_decode16(&csid, &src, end)) != 0)
            goto Exit;
        if ((tls->cipher_suite = find_cipher_suite(tls->ctx, csid)) == NULL) {
            ret = PTLS_ALERT_ILLEGAL_PARAMETER;
            goto Exit;
        }
    }

    /* legacy_compression_method */
    if (src == end || *src++ != 0) {
        ret = PTLS_ALERT_ILLEGAL_PARAMETER;
        goto Exit;
    }

    if (sh->is_retry_request)
        sh->retry_request.selected_group = UINT16_MAX;

    uint16_t exttype, found_version = UINT16_MAX, selected_psk_identity = UINT16_MAX;
    decode_extensions(src, end, PTLS_HANDSHAKE_TYPE_SERVER_HELLO, &exttype, {
        if (tls->ctx->on_extension != NULL &&
            (ret = tls->ctx->on_extension->cb(tls->ctx->on_extension, tls, PTLS_HANDSHAKE_TYPE_SERVER_HELLO, exttype,
                                              ptls_iovec_init(src, end - src)) != 0))
            goto Exit;
        switch (exttype) {
        case PTLS_EXTENSION_TYPE_SUPPORTED_VERSIONS:
            if ((ret = ptls_decode16(&found_version, &src, end)) != 0)
                goto Exit;
            break;
        case PTLS_EXTENSION_TYPE_KEY_SHARE:
            if (sh->is_retry_request) {
                if ((ret = ptls_decode16(&sh->retry_request.selected_group, &src, end)) != 0)
                    goto Exit;
            } else {
                uint16_t group;
                if ((ret = decode_key_share_entry(&group, &sh->peerkey, &src, end)) != 0)
                    goto Exit;
                if (src != end) {
                    ret = PTLS_ALERT_DECODE_ERROR;
                    goto Exit;
                }
                if (tls->key_share == NULL || tls->key_share->id != group) {
                    ret = PTLS_ALERT_ILLEGAL_PARAMETER;
                    goto Exit;
                }
            }
            break;
        case PTLS_EXTENSION_TYPE_COOKIE:
            if (sh->is_retry_request) {
                ptls_decode_block(src, end, 2, {
                    if (src == end) {
                        ret = PTLS_ALERT_DECODE_ERROR;
                        goto Exit;
                    }
                    sh->retry_request.cookie = ptls_iovec_init(src, end - src);
                    src = end;
                });
            } else {
                ret = PTLS_ALERT_ILLEGAL_PARAMETER;
                goto Exit;
            }
            break;
        case PTLS_EXTENSION_TYPE_PRE_SHARED_KEY:
            if (sh->is_retry_request) {
                ret = PTLS_ALERT_ILLEGAL_PARAMETER;
                goto Exit;
            } else {
                if ((ret = ptls_decode16(&selected_psk_identity, &src, end)) != 0)
                    goto Exit;
            }
            break;
        default:
            src = end;
            break;
        }
    });

    if (!is_supported_version(found_version)) {
        ret = PTLS_ALERT_ILLEGAL_PARAMETER;
        goto Exit;
    }
    if (!sh->is_retry_request) {
        if (selected_psk_identity != UINT16_MAX) {
            if (!tls->client.offered_psk) {
                ret = PTLS_ALERT_ILLEGAL_PARAMETER;
                goto Exit;
            }
            if (selected_psk_identity != 0) {
                ret = PTLS_ALERT_ILLEGAL_PARAMETER;
                goto Exit;
            }
            tls->is_psk_handshake = 1;
        }
        if (sh->peerkey.base == NULL && !tls->is_psk_handshake) {
            ret = PTLS_ALERT_ILLEGAL_PARAMETER;
            goto Exit;
        }
    }

    ret = 0;
Exit:
    return ret;
}

static int handle_hello_retry_request(ptls_t *tls, ptls_message_emitter_t *emitter, struct st_ptls_server_hello_t *sh,
                                      ptls_iovec_t message, ptls_handshake_properties_t *properties)
{
    int ret;

    if (tls->client.key_share_ctx != NULL) {
        tls->client.key_share_ctx->on_exchange(&tls->client.key_share_ctx, 1, NULL, ptls_iovec_init(NULL, 0));
        tls->client.key_share_ctx = NULL;
    }
    if (tls->client.using_early_data) {
        /* release traffic encryption key so that 2nd CH goes out in cleartext, but keep the epoch at 1 since we've already
         * called derive-secret */
        if (tls->ctx->update_traffic_key == NULL) {
            assert(tls->traffic_protection.enc.aead != NULL);
            ptls_aead_free(tls->traffic_protection.enc.aead);
            tls->traffic_protection.enc.aead = NULL;
        }
        tls->client.using_early_data = 0;
    }

    if (sh->retry_request.selected_group != UINT16_MAX) {
        /* we offer the first key_exchanges[0] as KEY_SHARE unless client.negotiate_before_key_exchange is set */
        ptls_key_exchange_algorithm_t **cand;
        for (cand = tls->ctx->key_exchanges; *cand != NULL; ++cand)
            if ((*cand)->id == sh->retry_request.selected_group)
                break;
        if (*cand == NULL) {
            ret = PTLS_ALERT_ILLEGAL_PARAMETER;
            goto Exit;
        }
        tls->key_share = *cand;
    } else if (tls->key_share != NULL) {
        /* retain the key-share using in first CH, if server does not specify one */
    } else {
        ret = PTLS_ALERT_ILLEGAL_PARAMETER;
        goto Exit;
    }

    key_schedule_transform_post_ch1hash(tls->key_schedule);
    ptls__key_schedule_update_hash(tls->key_schedule, message.base, message.len);
    ret = send_client_hello(tls, emitter, properties, &sh->retry_request.cookie);

Exit:
    return ret;
}

static int client_handle_hello(ptls_t *tls, ptls_message_emitter_t *emitter, ptls_iovec_t message,
                               ptls_handshake_properties_t *properties)
{
    struct st_ptls_server_hello_t sh;
    ptls_iovec_t ecdh_secret = {NULL};
    int ret;

    if ((ret = decode_server_hello(tls, &sh, message.base + PTLS_HANDSHAKE_HEADER_SIZE, message.base + message.len)) != 0)
        goto Exit;
    if (!(sh.legacy_session_id.len == tls->client.legacy_session_id.len &&
          ptls_mem_equal(sh.legacy_session_id.base, tls->client.legacy_session_id.base, tls->client.legacy_session_id.len))) {
        ret = PTLS_ALERT_ILLEGAL_PARAMETER;
        goto Exit;
    }

    if (sh.is_retry_request) {
        if ((ret = key_schedule_select_one(tls->key_schedule, tls->cipher_suite, 0)) != 0)
            goto Exit;
        return handle_hello_retry_request(tls, emitter, &sh, message, properties);
    }

    if ((ret = key_schedule_select_one(tls->key_schedule, tls->cipher_suite, tls->client.offered_psk && !tls->is_psk_handshake)) !=
        0)
        goto Exit;

    if (sh.peerkey.base != NULL) {
        if ((ret = tls->client.key_share_ctx->on_exchange(&tls->client.key_share_ctx, 1, &ecdh_secret, sh.peerkey)) != 0)
            goto Exit;
    }

    ptls__key_schedule_update_hash(tls->key_schedule, message.base, message.len);

    if ((ret = key_schedule_extract(tls->key_schedule, ecdh_secret)) != 0)
        goto Exit;
    if ((ret = setup_traffic_protection(tls, 0, "s hs traffic", 2, 0)) != 0)
        goto Exit;
    if (tls->client.using_early_data) {
        if ((tls->pending_handshake_secret = malloc(PTLS_MAX_DIGEST_SIZE)) == NULL) {
            ret = PTLS_ERROR_NO_MEMORY;
            goto Exit;
        }
        if ((ret = derive_secret(tls->key_schedule, tls->pending_handshake_secret, "c hs traffic")) != 0)
            goto Exit;
        if (tls->ctx->update_traffic_key != NULL &&
            (ret = tls->ctx->update_traffic_key->cb(tls->ctx->update_traffic_key, tls, 1, 2, tls->pending_handshake_secret)) != 0)
            goto Exit;
    } else {
        if ((ret = setup_traffic_protection(tls, 1, "c hs traffic", 2, 0)) != 0)
            goto Exit;
    }

    tls->state = PTLS_STATE_CLIENT_EXPECT_ENCRYPTED_EXTENSIONS;
    ret = PTLS_ERROR_IN_PROGRESS;

Exit:
    if (ecdh_secret.base != NULL) {
        ptls_clear_memory(ecdh_secret.base, ecdh_secret.len);
        free(ecdh_secret.base);
    }
    return ret;
}

static int should_collect_unknown_extension(ptls_t *tls, ptls_handshake_properties_t *properties, uint16_t type)
{
    return properties != NULL && properties->collect_extension != NULL && properties->collect_extension(tls, properties, type);
}

static int collect_unknown_extension(ptls_t *tls, uint16_t type, const uint8_t *src, const uint8_t *const end,
                                     ptls_raw_extension_t *slots)
{
    size_t i;
    for (i = 0; slots[i].type != UINT16_MAX; ++i) {
        assert(i < MAX_UNKNOWN_EXTENSIONS);
        if (slots[i].type == type)
            return PTLS_ALERT_ILLEGAL_PARAMETER;
    }
    if (i < MAX_UNKNOWN_EXTENSIONS) {
        slots[i].type = type;
        slots[i].data = ptls_iovec_init(src, end - src);
        slots[i + 1].type = UINT16_MAX;
    }
    return 0;
}

static int report_unknown_extensions(ptls_t *tls, ptls_handshake_properties_t *properties, ptls_raw_extension_t *slots)
{
    if (properties != NULL && properties->collect_extension != NULL) {
        assert(properties->collected_extensions != NULL);
        return properties->collected_extensions(tls, properties, slots);
    } else {
        return 0;
    }
}

static int client_handle_encrypted_extensions(ptls_t *tls, ptls_iovec_t message, ptls_handshake_properties_t *properties)
{
    const uint8_t *src = message.base + PTLS_HANDSHAKE_HEADER_SIZE, *const end = message.base + message.len, *esni_nonce = NULL;
    uint16_t type;
    static const ptls_raw_extension_t no_unknown_extensions = {UINT16_MAX};
    ptls_raw_extension_t *unknown_extensions = (ptls_raw_extension_t *)&no_unknown_extensions;
    int ret, skip_early_data = 1;

    decode_extensions(src, end, PTLS_HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS, &type, {
        if (tls->ctx->on_extension != NULL &&
            (ret = tls->ctx->on_extension->cb(tls->ctx->on_extension, tls, PTLS_HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS, type,
                                              ptls_iovec_init(src, end - src)) != 0))
            goto Exit;
        switch (type) {
        case PTLS_EXTENSION_TYPE_SERVER_NAME:
            if (src != end) {
                ret = PTLS_ALERT_DECODE_ERROR;
                goto Exit;
            }
            if (!(tls->server_name != NULL && !ptls_server_name_is_ipaddr(tls->server_name))) {
                ret = PTLS_ALERT_ILLEGAL_PARAMETER;
                goto Exit;
            }
            break;
        case PTLS_EXTENSION_TYPE_ENCRYPTED_SERVER_NAME:
            if (*src == PTLS_ESNI_RESPONSE_TYPE_ACCEPT) {
                if (end - src != PTLS_ESNI_NONCE_SIZE + 1) {
                    ret = PTLS_ALERT_ILLEGAL_PARAMETER;
                    goto Exit;
                }
                esni_nonce = src + 1;
            } else {
                /* TODO: provide API to parse the RETRY REQUEST response */
                ret = PTLS_ERROR_ESNI_RETRY;
                goto Exit;
            }
            break;
        case PTLS_EXTENSION_TYPE_ALPN:
            ptls_decode_block(src, end, 2, {
                ptls_decode_open_block(src, end, 1, {
                    if (src == end) {
                        ret = PTLS_ALERT_DECODE_ERROR;
                        goto Exit;
                    }
                    if ((ret = ptls_set_negotiated_protocol(tls, (const char *)src, end - src)) != 0)
                        goto Exit;
                    src = end;
                });
                if (src != end) {
                    ret = PTLS_ALERT_HANDSHAKE_FAILURE;
                    goto Exit;
                }
            });
            break;
        case PTLS_EXTENSION_TYPE_EARLY_DATA:
            if (!tls->client.using_early_data) {
                ret = PTLS_ALERT_ILLEGAL_PARAMETER;
                goto Exit;
            }
            skip_early_data = 0;
            break;
        default:
            if (should_collect_unknown_extension(tls, properties, type)) {
                if (unknown_extensions == &no_unknown_extensions) {
                    if ((unknown_extensions = malloc(sizeof(*unknown_extensions) * (MAX_UNKNOWN_EXTENSIONS + 1))) == NULL) {
                        ret = PTLS_ERROR_NO_MEMORY;
                        goto Exit;
                    }
                    unknown_extensions[0].type = UINT16_MAX;
                }
                if ((ret = collect_unknown_extension(tls, type, src, end, unknown_extensions)) != 0)
                    goto Exit;
            }
            break;
        }
        src = end;
    });

    if (tls->esni != NULL) {
        if (esni_nonce == NULL || !ptls_mem_equal(esni_nonce, tls->esni->nonce, PTLS_ESNI_NONCE_SIZE)) {
            ret = PTLS_ALERT_ILLEGAL_PARAMETER;
            goto Exit;
        }
        free_esni_secret(&tls->esni, 0);
    } else {
        if (esni_nonce != NULL) {
            ret = PTLS_ALERT_ILLEGAL_PARAMETER;
            goto Exit;
        }
    }

    if (tls->client.using_early_data) {
        if (skip_early_data)
            tls->client.using_early_data = 0;
        if (properties != NULL)
            properties->client.early_data_acceptance = skip_early_data ? PTLS_EARLY_DATA_REJECTED : PTLS_EARLY_DATA_ACCEPTED;
    }
    if ((ret = report_unknown_extensions(tls, properties, unknown_extensions)) != 0)
        goto Exit;

    ptls__key_schedule_update_hash(tls->key_schedule, message.base, message.len);
    tls->state =
        tls->is_psk_handshake ? PTLS_STATE_CLIENT_EXPECT_FINISHED : PTLS_STATE_CLIENT_EXPECT_CERTIFICATE_REQUEST_OR_CERTIFICATE;
    ret = PTLS_ERROR_IN_PROGRESS;

Exit:
    if (unknown_extensions != &no_unknown_extensions)
        free(unknown_extensions);
    return ret;
}

static int decode_certificate_request(ptls_t *tls, struct st_ptls_certificate_request_t *cr, const uint8_t *src,
                                      const uint8_t *const end)
{
    int ret;
    uint16_t exttype = 0;

    /* certificate request context */
    ptls_decode_open_block(src, end, 1, {
        size_t len = end - src;
        if (len > 255) {
            ret = PTLS_ALERT_DECODE_ERROR;
            goto Exit;
        }
        if ((cr->context.base = malloc(len != 0 ? len : 1)) == NULL) {
            ret = PTLS_ERROR_NO_MEMORY;
            goto Exit;
        }
        cr->context.len = len;
        memcpy(cr->context.base, src, len);
        src = end;
    });

    /* decode extensions */
    decode_extensions(src, end, PTLS_HANDSHAKE_TYPE_CERTIFICATE_REQUEST, &exttype, {
        if (tls->ctx->on_extension != NULL &&
            (ret = tls->ctx->on_extension->cb(tls->ctx->on_extension, tls, PTLS_HANDSHAKE_TYPE_CERTIFICATE_REQUEST, exttype,
                                              ptls_iovec_init(src, end - src)) != 0))
            goto Exit;
        switch (exttype) {
        case PTLS_EXTENSION_TYPE_SIGNATURE_ALGORITHMS:
            if ((ret = decode_signature_algorithms(&cr->signature_algorithms, &src, end)) != 0)
                goto Exit;
            break;
        }
        src = end;
    });

    if (cr->signature_algorithms.count == 0) {
        ret = PTLS_ALERT_MISSING_EXTENSION;
        goto Exit;
    }

    ret = 0;
Exit:
    return ret;
}

int ptls_build_certificate_message(ptls_buffer_t *buf, ptls_iovec_t context, ptls_iovec_t *certificates, size_t num_certificates,
                                   ptls_iovec_t ocsp_status)
{
    int ret;

    ptls_buffer_push_block(buf, 1, { ptls_buffer_pushv(buf, context.base, context.len); });
    ptls_buffer_push_block(buf, 3, {
        size_t i;
        for (i = 0; i != num_certificates; ++i) {
            ptls_buffer_push_block(buf, 3, { ptls_buffer_pushv(buf, certificates[i].base, certificates[i].len); });
            ptls_buffer_push_block(buf, 2, {
                if (i == 0 && ocsp_status.len != 0) {
                    buffer_push_extension(buf, PTLS_EXTENSION_TYPE_STATUS_REQUEST, {
                        ptls_buffer_push(buf, 1); /* status_type == ocsp */
                        ptls_buffer_push_block(buf, 3, { ptls_buffer_pushv(buf, ocsp_status.base, ocsp_status.len); });
                    });
                }
            });
        }
    });

    ret = 0;
Exit:
    return ret;
}

static int default_emit_certificate_cb(ptls_emit_certificate_t *_self, ptls_t *tls, ptls_message_emitter_t *emitter,
                                       ptls_key_schedule_t *key_sched, ptls_iovec_t context, int push_status_request,
                                       const uint16_t *compress_algos, size_t num_compress_algos)
{
    int ret;

    ptls_push_message(emitter, key_sched, PTLS_HANDSHAKE_TYPE_CERTIFICATE, {
        if ((ret = ptls_build_certificate_message(emitter->buf, context, tls->ctx->certificates.list, tls->ctx->certificates.count,
                                                  ptls_iovec_init(NULL, 0))) != 0)
            goto Exit;
    });

    ret = 0;
Exit:
    return ret;
}

static int send_certificate_and_certificate_verify(ptls_t *tls, ptls_message_emitter_t *emitter,
                                                   struct st_ptls_signature_algorithms_t *signature_algorithms,
                                                   ptls_iovec_t context, const char *context_string, int push_status_request,
                                                   const uint16_t *compress_algos, size_t num_compress_algos)
{
    int ret;

    if (signature_algorithms->count == 0) {
        ret = PTLS_ALERT_MISSING_EXTENSION;
        goto Exit;
    }

    { /* send Certificate (or the equivalent) */
        static ptls_emit_certificate_t default_emit_certificate = {default_emit_certificate_cb};
        ptls_emit_certificate_t *emit_certificate =
            tls->ctx->emit_certificate != NULL ? tls->ctx->emit_certificate : &default_emit_certificate;
    Redo:
        if ((ret = emit_certificate->cb(emit_certificate, tls, emitter, tls->key_schedule, context, push_status_request,
                                        compress_algos, num_compress_algos)) != 0) {
            if (ret == PTLS_ERROR_DELEGATE) {
                assert(emit_certificate != &default_emit_certificate);
                emit_certificate = &default_emit_certificate;
                goto Redo;
            }
            goto Exit;
        }
    }

    /* build and send CertificateVerify */
    if (tls->ctx->sign_certificate != NULL) {
        ptls_push_message(emitter, tls->key_schedule, PTLS_HANDSHAKE_TYPE_CERTIFICATE_VERIFY, {
            ptls_buffer_t *sendbuf = emitter->buf;
            size_t algo_off = sendbuf->off;
            ptls_buffer_push16(sendbuf, 0); /* filled in later */
            ptls_buffer_push_block(sendbuf, 2, {
                uint16_t algo;
                uint8_t data[PTLS_MAX_CERTIFICATE_VERIFY_SIGNDATA_SIZE];
                size_t datalen = build_certificate_verify_signdata(data, tls->key_schedule, context_string);
                if ((ret = tls->ctx->sign_certificate->cb(tls->ctx->sign_certificate, tls, &algo, sendbuf,
                                                          ptls_iovec_init(data, datalen), signature_algorithms->list,
                                                          signature_algorithms->count)) != 0) {
                    goto Exit;
                }
                sendbuf->base[algo_off] = (uint8_t)(algo >> 8);
                sendbuf->base[algo_off + 1] = (uint8_t)algo;
            });
        });
    }

Exit:
    return ret;
}

static int client_handle_certificate_request(ptls_t *tls, ptls_iovec_t message, ptls_handshake_properties_t *properties)
{
    const uint8_t *src = message.base + PTLS_HANDSHAKE_HEADER_SIZE, *const end = message.base + message.len;
    int ret = 0;

    if ((ret = decode_certificate_request(tls, &tls->client.certificate_request, src, end)) != 0)
        return ret;

    /* This field SHALL be zero length unless used for the post-handshake authentication exchanges (section 4.3.2) */
    if (tls->client.certificate_request.context.len != 0)
        return PTLS_ALERT_ILLEGAL_PARAMETER;

    tls->state = PTLS_STATE_CLIENT_EXPECT_CERTIFICATE;
    ptls__key_schedule_update_hash(tls->key_schedule, message.base, message.len);

    return PTLS_ERROR_IN_PROGRESS;
}

static int handle_certificate(ptls_t *tls, const uint8_t *src, const uint8_t *end, int *got_certs)
{
    ptls_iovec_t certs[16];
    size_t num_certs = 0;
    int ret = 0;

    /* certificate request context */
    ptls_decode_open_block(src, end, 1, {
        if (src != end) {
            ret = PTLS_ALERT_ILLEGAL_PARAMETER;
            goto Exit;
        }
    });
    /* certificate_list */
    ptls_decode_block(src, end, 3, {
        while (src != end) {
            ptls_decode_open_block(src, end, 3, {
                if (num_certs < PTLS_ELEMENTSOF(certs))
                    certs[num_certs++] = ptls_iovec_init(src, end - src);
                src = end;
            });
            uint16_t type;
            decode_open_extensions(src, end, PTLS_HANDSHAKE_TYPE_CERTIFICATE, &type, {
                if (tls->ctx->on_extension != NULL &&
                    (ret = tls->ctx->on_extension->cb(tls->ctx->on_extension, tls, PTLS_HANDSHAKE_TYPE_CERTIFICATE, type,
                                                      ptls_iovec_init(src, end - src)) != 0))
                    goto Exit;
                src = end;
            });
        }
    });

    if (num_certs != 0 && tls->ctx->verify_certificate != NULL) {
        if ((ret = tls->ctx->verify_certificate->cb(tls->ctx->verify_certificate, tls, &tls->certificate_verify.cb,
                                                    &tls->certificate_verify.verify_ctx, certs, num_certs)) != 0)
            goto Exit;
    }

    *got_certs = num_certs != 0;

Exit:
    return ret;
}

static int client_do_handle_certificate(ptls_t *tls, const uint8_t *src, const uint8_t *end)
{
    int got_certs, ret;

    if ((ret = handle_certificate(tls, src, end, &got_certs)) != 0)
        return ret;
    if (!got_certs)
        return PTLS_ALERT_ILLEGAL_PARAMETER;

    return 0;
}

static int client_handle_certificate(ptls_t *tls, ptls_iovec_t message)
{
    int ret;

    if ((ret = client_do_handle_certificate(tls, message.base + PTLS_HANDSHAKE_HEADER_SIZE, message.base + message.len)) != 0)
        return ret;

    ptls__key_schedule_update_hash(tls->key_schedule, message.base, message.len);

    tls->state = PTLS_STATE_CLIENT_EXPECT_CERTIFICATE_VERIFY;
    return PTLS_ERROR_IN_PROGRESS;
}

static int client_handle_compressed_certificate(ptls_t *tls, ptls_iovec_t message)
{
    const uint8_t *src = message.base + PTLS_HANDSHAKE_HEADER_SIZE, *const end = message.base + message.len;
    uint16_t algo;
    uint32_t uncompressed_size;
    uint8_t *uncompressed = NULL;
    int ret;

    if (tls->ctx->decompress_certificate == NULL) {
        ret = PTLS_ALERT_UNEXPECTED_MESSAGE;
        goto Exit;
    }

    /* decode */
    if ((ret = ptls_decode16(&algo, &src, end)) != 0)
        goto Exit;
    if ((ret = ptls_decode24(&uncompressed_size, &src, end)) != 0)
        goto Exit;
    if (uncompressed_size > 65536) { /* TODO find a sensible number */
        ret = PTLS_ALERT_BAD_CERTIFICATE;
        goto Exit;
    }
    if ((uncompressed = malloc(uncompressed_size)) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }
    ptls_decode_block(src, end, 3, {
        if ((ret = tls->ctx->decompress_certificate->cb(tls->ctx->decompress_certificate, tls, algo,
                                                        ptls_iovec_init(uncompressed, uncompressed_size),
                                                        ptls_iovec_init(src, end - src))) != 0)
            goto Exit;
        src = end;
    });

    /* handle */
    if ((ret = client_do_handle_certificate(tls, uncompressed, uncompressed + uncompressed_size)) != 0)
        goto Exit;

    ptls__key_schedule_update_hash(tls->key_schedule, message.base, message.len);
    tls->state = PTLS_STATE_CLIENT_EXPECT_CERTIFICATE_VERIFY;
    ret = PTLS_ERROR_IN_PROGRESS;

Exit:
    free(uncompressed);
    return ret;
}

static int server_handle_certificate(ptls_t *tls, ptls_iovec_t message)
{
    int got_certs, ret;

    if ((ret = handle_certificate(tls, message.base + PTLS_HANDSHAKE_HEADER_SIZE, message.base + message.len, &got_certs)) != 0)
        return ret;
    if (!got_certs)
        return PTLS_ALERT_CERTIFICATE_REQUIRED;

    ptls__key_schedule_update_hash(tls->key_schedule, message.base, message.len);

    tls->state = PTLS_STATE_SERVER_EXPECT_CERTIFICATE_VERIFY;
    return PTLS_ERROR_IN_PROGRESS;
}

static int handle_certificate_verify(ptls_t *tls, ptls_iovec_t message, const char *context_string)
{
    const uint8_t *src = message.base + PTLS_HANDSHAKE_HEADER_SIZE, *const end = message.base + message.len;
    uint16_t algo;
    ptls_iovec_t signature;
    uint8_t signdata[PTLS_MAX_CERTIFICATE_VERIFY_SIGNDATA_SIZE];
    size_t signdata_size;
    int ret;

    /* decode */
    if ((ret = ptls_decode16(&algo, &src, end)) != 0)
        goto Exit;
    ptls_decode_block(src, end, 2, {
        signature = ptls_iovec_init(src, end - src);
        src = end;
    });

    /* validate */
    switch (algo) {
    case PTLS_SIGNATURE_RSA_PSS_RSAE_SHA256:
    case PTLS_SIGNATURE_ECDSA_SECP256R1_SHA256:
        /* ok */
        break;
    default:
        ret = PTLS_ALERT_ILLEGAL_PARAMETER;
        goto Exit;
    }
    signdata_size = build_certificate_verify_signdata(signdata, tls->key_schedule, context_string);
    if (tls->certificate_verify.cb != NULL) {
        ret = tls->certificate_verify.cb(tls->certificate_verify.verify_ctx, ptls_iovec_init(signdata, signdata_size), signature);
    } else {
        ret = 0;
    }
    ptls_clear_memory(signdata, signdata_size);
    tls->certificate_verify.cb = NULL;
    if (ret != 0) {
        goto Exit;
    }

    ptls__key_schedule_update_hash(tls->key_schedule, message.base, message.len);

Exit:
    return ret;
}

static int client_handle_certificate_verify(ptls_t *tls, ptls_iovec_t message)
{
    int ret = handle_certificate_verify(tls, message, PTLS_SERVER_CERTIFICATE_VERIFY_CONTEXT_STRING);

    if (ret == 0) {
        tls->state = PTLS_STATE_CLIENT_EXPECT_FINISHED;
        ret = PTLS_ERROR_IN_PROGRESS;
    }

    return ret;
}

static int server_handle_certificate_verify(ptls_t *tls, ptls_iovec_t message)
{
    int ret = handle_certificate_verify(tls, message, PTLS_CLIENT_CERTIFICATE_VERIFY_CONTEXT_STRING);

    if (ret == 0) {
        tls->state = PTLS_STATE_SERVER_EXPECT_FINISHED;
        ret = PTLS_ERROR_IN_PROGRESS;
    }

    return ret;
}

static int client_handle_finished(ptls_t *tls, ptls_message_emitter_t *emitter, ptls_iovec_t message)
{
    uint8_t send_secret[PTLS_MAX_DIGEST_SIZE];
    int ret;

    if ((ret = verify_finished(tls, message)) != 0)
        goto Exit;
    ptls__key_schedule_update_hash(tls->key_schedule, message.base, message.len);

    /* update traffic keys by using messages upto ServerFinished, but commission them after sending ClientFinished */
    if ((ret = key_schedule_extract(tls->key_schedule, ptls_iovec_init(NULL, 0))) != 0)
        goto Exit;
    if ((ret = setup_traffic_protection(tls, 0, "s ap traffic", 3, 0)) != 0)
        goto Exit;
    if ((ret = derive_secret(tls->key_schedule, send_secret, "c ap traffic")) != 0)
        goto Exit;
    if ((ret = derive_exporter_secret(tls, 0)) != 0)
        goto Exit;

    /* if sending early data, emit EOED and commision the client handshake traffic secret */
    if (tls->pending_handshake_secret != NULL) {
        assert(tls->traffic_protection.enc.aead != NULL || tls->ctx->update_traffic_key != NULL);
        if (tls->client.using_early_data && !tls->ctx->omit_end_of_early_data)
            ptls_push_message(emitter, tls->key_schedule, PTLS_HANDSHAKE_TYPE_END_OF_EARLY_DATA, {});
        tls->client.using_early_data = 0;
        if ((ret = commission_handshake_secret(tls)) != 0)
            goto Exit;
    }

    if ((ret = push_change_cipher_spec(tls, emitter)) != 0)
        goto Exit;

    if (tls->client.certificate_request.context.base != NULL) {
        /* If this is a resumed session, the server must not send the certificate request in the handshake */
        if (tls->is_psk_handshake) {
            ret = PTLS_ALERT_ILLEGAL_PARAMETER;
            goto Exit;
        }
        ret = send_certificate_and_certificate_verify(tls, emitter, &tls->client.certificate_request.signature_algorithms,
                                                      tls->client.certificate_request.context,
                                                      PTLS_CLIENT_CERTIFICATE_VERIFY_CONTEXT_STRING, 0, NULL, 0);
        free(tls->client.certificate_request.context.base);
        tls->client.certificate_request.context = ptls_iovec_init(NULL, 0);
        if (ret != 0)
            goto Exit;
    }

    ret = send_finished(tls, emitter);

    memcpy(tls->traffic_protection.enc.secret, send_secret, sizeof(send_secret));
    if ((ret = setup_traffic_protection(tls, 1, NULL, 3, 0)) != 0)
        goto Exit;

    tls->state = PTLS_STATE_CLIENT_POST_HANDSHAKE;

Exit:
    ptls_clear_memory(send_secret, sizeof(send_secret));
    return ret;
}

static int client_handle_new_session_ticket(ptls_t *tls, ptls_iovec_t message)
{
    const uint8_t *src = message.base + PTLS_HANDSHAKE_HEADER_SIZE, *const end = message.base + message.len;
    ptls_iovec_t ticket_nonce;
    int ret;

    { /* verify the format */
        uint32_t ticket_lifetime, ticket_age_add, max_early_data_size;
        ptls_iovec_t ticket;
        if ((ret = decode_new_session_ticket(tls, &ticket_lifetime, &ticket_age_add, &ticket_nonce, &ticket, &max_early_data_size,
                                             src, end)) != 0)
            return ret;
    }

    /* do nothing if use of session ticket is disabled */
    if (tls->ctx->save_ticket == NULL)
        return 0;

    /* save the extension, along with the key of myself */
    ptls_buffer_t ticket_buf;
    ptls_buffer_init(&ticket_buf, "", 0);
    ptls_buffer_push64(&ticket_buf, tls->ctx->get_time->cb(tls->ctx->get_time));
    ptls_buffer_push16(&ticket_buf, tls->key_share->id);
    ptls_buffer_push16(&ticket_buf, tls->cipher_suite->id);
    ptls_buffer_push_block(&ticket_buf, 3, { ptls_buffer_pushv(&ticket_buf, src, end - src); });
    ptls_buffer_push_block(&ticket_buf, 2, {
        if ((ret = ptls_buffer_reserve(&ticket_buf, tls->key_schedule->hashes[0].algo->digest_size)) != 0)
            goto Exit;
        if ((ret = derive_resumption_secret(tls->key_schedule, ticket_buf.base + ticket_buf.off, ticket_nonce)) != 0)
            goto Exit;
        ticket_buf.off += tls->key_schedule->hashes[0].algo->digest_size;
    });

    if ((ret = tls->ctx->save_ticket->cb(tls->ctx->save_ticket, tls, ptls_iovec_init(ticket_buf.base, ticket_buf.off))) != 0)
        goto Exit;

    ret = 0;
Exit:
    ptls_buffer_dispose(&ticket_buf);
    return ret;
}

static int client_hello_decode_server_name(ptls_iovec_t *name, const uint8_t **src, const uint8_t *const end)
{
    int ret = 0;

    ptls_decode_open_block(*src, end, 2, {
        if (*src == end) {
            ret = PTLS_ALERT_DECODE_ERROR;
            goto Exit;
        }
        do {
            uint8_t type = *(*src)++;
            ptls_decode_open_block(*src, end, 2, {
                switch (type) {
                case PTLS_SERVER_NAME_TYPE_HOSTNAME:
                    if (memchr(*src, '\0', end - *src) != 0) {
                        ret = PTLS_ALERT_ILLEGAL_PARAMETER;
                        goto Exit;
                    }
                    *name = ptls_iovec_init(*src, end - *src);
                    break;
                default:
                    break;
                }
                *src = end;
            });
        } while (*src != end);
    });

Exit:
    return ret;
}

static int client_hello_decrypt_esni(ptls_context_t *ctx, ptls_iovec_t *server_name, ptls_esni_secret_t **secret,
                                     struct st_ptls_client_hello_t *ch)
{
    ptls_esni_context_t **esni;
    ptls_key_exchange_context_t **key_share_ctx;
    uint8_t *decrypted = NULL;
    ptls_aead_context_t *aead = NULL;
    int ret;

    /* allocate secret */
    assert(*secret == NULL);
    if ((*secret = malloc(sizeof(**secret))) == NULL)
        return PTLS_ERROR_NO_MEMORY;
    memset(*secret, 0, sizeof(**secret));

    /* find the matching esni structure */
    for (esni = ctx->esni; *esni != NULL; ++esni) {
        size_t i;
        for (i = 0; (*esni)->cipher_suites[i].cipher_suite != NULL; ++i)
            if ((*esni)->cipher_suites[i].cipher_suite->id == ch->esni.cipher->id)
                break;
        if ((*esni)->cipher_suites[i].cipher_suite == NULL) {
            ret = PTLS_ALERT_ILLEGAL_PARAMETER;
            goto Exit;
        }
        if (memcmp((*esni)->cipher_suites[i].record_digest, ch->esni.record_digest, ch->esni.cipher->hash->digest_size) == 0) {
            (*secret)->version = (*esni)->version;
            break;
        }
    }
    if (*esni == NULL) {
        ret = PTLS_ALERT_ILLEGAL_PARAMETER;
        goto Exit;
    }

    /* find the matching private key for ESNI decryption */
    for (key_share_ctx = (*esni)->key_exchanges; *key_share_ctx != NULL; ++key_share_ctx)
        if ((*key_share_ctx)->algo->id == ch->esni.key_share->id)
            break;
    if (*key_share_ctx == NULL) {
        ret = PTLS_ALERT_ILLEGAL_PARAMETER;
        goto Exit;
    }

    /* calculate ESNIContents */
    if ((ret = build_esni_contents_hash(ch->esni.cipher->hash, (*secret)->esni_contents_hash, ch->esni.record_digest,
                                        ch->esni.key_share->id, ch->esni.peer_key, ch->random_bytes)) != 0)
        goto Exit;
    /* derive the shared secret */
    if ((ret = (*key_share_ctx)->on_exchange(key_share_ctx, 0, &(*secret)->secret, ch->esni.peer_key)) != 0)
        goto Exit;
    /* decrypt */
    if (ch->esni.encrypted_sni.len - ch->esni.cipher->aead->tag_size != (*esni)->padded_length + PTLS_ESNI_NONCE_SIZE) {
        ret = PTLS_ALERT_ILLEGAL_PARAMETER;
        goto Exit;
    }
    if ((decrypted = malloc((*esni)->padded_length + PTLS_ESNI_NONCE_SIZE)) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }
    if ((ret = create_esni_aead(&aead, 0, ch->esni.cipher, (*secret)->secret, (*secret)->esni_contents_hash)) != 0)
        goto Exit;
    if (ptls_aead_decrypt(aead, decrypted, ch->esni.encrypted_sni.base, ch->esni.encrypted_sni.len, 0, ch->key_shares.base,
                          ch->key_shares.len) != (*esni)->padded_length + PTLS_ESNI_NONCE_SIZE) {
        ret = PTLS_ALERT_DECRYPT_ERROR;
        goto Exit;
    }
    ptls_aead_free(aead);
    aead = NULL;

    { /* decode sni */
        const uint8_t *src = decrypted, *const end = src + (*esni)->padded_length;
        ptls_iovec_t found_name;
        if (end - src < PTLS_ESNI_NONCE_SIZE) {
            ret = PTLS_ALERT_ILLEGAL_PARAMETER;
            goto Exit;
        }
        memcpy((*secret)->nonce, src, PTLS_ESNI_NONCE_SIZE);
        src += PTLS_ESNI_NONCE_SIZE;
        if ((ret = client_hello_decode_server_name(&found_name, &src, end)) != 0)
            goto Exit;
        for (; src != end; ++src) {
            if (*src != '\0') {
                ret = PTLS_ALERT_ILLEGAL_PARAMETER;
                goto Exit;
            }
        }
        /* if successful, reuse memory allocated for padded_server_name for storing the found name (freed by the caller) */
        memmove(decrypted, found_name.base, found_name.len);
        *server_name = ptls_iovec_init(decrypted, found_name.len);
        decrypted = NULL;
    }

    ret = 0;
Exit:
    if (decrypted != NULL)
        free(decrypted);
    if (aead != NULL)
        ptls_aead_free(aead);
    if (ret != 0 && *secret != NULL)
        free_esni_secret(secret, 1);
    return ret;
}

static int select_negotiated_group(ptls_key_exchange_algorithm_t **selected, ptls_key_exchange_algorithm_t **candidates,
                                   const uint8_t *src, const uint8_t *const end)
{
    int ret;

    ptls_decode_block(src, end, 2, {
        while (src != end) {
            uint16_t group;
            if ((ret = ptls_decode16(&group, &src, end)) != 0)
                goto Exit;
            ptls_key_exchange_algorithm_t **c = candidates;
            for (; *c != NULL; ++c) {
                if ((*c)->id == group) {
                    *selected = *c;
                    return 0;
                }
            }
        }
    });

    ret = PTLS_ALERT_HANDSHAKE_FAILURE;

Exit:
    return ret;
}

static int decode_client_hello(ptls_t *tls, struct st_ptls_client_hello_t *ch, const uint8_t *src, const uint8_t *const end,
                               ptls_handshake_properties_t *properties)
{
    uint16_t exttype = 0;
    int ret;

    /* decode protocol version (do not bare to decode something older than TLS 1.0) */
    if ((ret = ptls_decode16(&ch->legacy_version, &src, end)) != 0)
        goto Exit;
    if (ch->legacy_version < 0x0301) {
        ret = PTLS_ALERT_PROTOCOL_VERSION;
        goto Exit;
    }

    /* skip random */
    if (end - src < PTLS_HELLO_RANDOM_SIZE) {
        ret = PTLS_ALERT_DECODE_ERROR;
        goto Exit;
    }
    ch->random_bytes = src;
    src += PTLS_HELLO_RANDOM_SIZE;

    /* skip legacy_session_id */
    ptls_decode_open_block(src, end, 1, {
        if (end - src > 32) {
            ret = PTLS_ALERT_DECODE_ERROR;
            goto Exit;
        }
        ch->legacy_session_id = ptls_iovec_init(src, end - src);
        src = end;
    });

    /* decode and select from ciphersuites */
    ptls_decode_open_block(src, end, 2, {
        ch->cipher_suites = ptls_iovec_init(src, end - src);
        uint16_t *id = ch->client_ciphers.list;
        do {
            if ((ret = ptls_decode16(id, &src, end)) != 0)
                goto Exit;
            id++;
            ch->client_ciphers.count++;
            if (id >= ch->client_ciphers.list + MAX_CLIENT_CIPHERS) {
                src = end;
                break;
            }
        } while (src != end);
    });

    /* decode legacy_compression_methods */
    ptls_decode_open_block(src, end, 1, {
        if (src == end) {
            ret = PTLS_ALERT_DECODE_ERROR;
            goto Exit;
        }
        ch->compression_methods.ids = src;
        ch->compression_methods.count = end - src;
        src = end;
    });

    /* decode extensions */
    decode_extensions(src, end, PTLS_HANDSHAKE_TYPE_CLIENT_HELLO, &exttype, {
        ch->psk.is_last_extension = 0;
        if (tls->ctx->on_extension != NULL &&
            (ret = tls->ctx->on_extension->cb(tls->ctx->on_extension, tls, PTLS_HANDSHAKE_TYPE_CLIENT_HELLO, exttype,
                                              ptls_iovec_init(src, end - src)) != 0))
            goto Exit;
        switch (exttype) {
        case PTLS_EXTENSION_TYPE_SERVER_NAME:
            if ((ret = client_hello_decode_server_name(&ch->server_name, &src, end)) != 0)
                goto Exit;
            if (src != end) {
                ret = PTLS_ALERT_DECODE_ERROR;
                goto Exit;
            }
            break;
        case PTLS_EXTENSION_TYPE_ENCRYPTED_SERVER_NAME: {
            ptls_cipher_suite_t **cipher;
            if (ch->esni.cipher != NULL) {
                ret = PTLS_ALERT_ILLEGAL_PARAMETER;
                goto Exit;
            }
            { /* cipher-suite */
                uint16_t csid;
                if ((ret = ptls_decode16(&csid, &src, end)) != 0)
                    goto Exit;
                for (cipher = tls->ctx->cipher_suites; *cipher != NULL; ++cipher)
                    if ((*cipher)->id == csid)
                        break;
                if (*cipher == NULL) {
                    ret = PTLS_ALERT_ILLEGAL_PARAMETER;
                    goto Exit;
                }
            }
            /* key-share (including peer-key) */
            if ((ret = select_key_share(&ch->esni.key_share, &ch->esni.peer_key, tls->ctx->key_exchanges, &src, end, 1)) != 0)
                goto Exit;
            ptls_decode_open_block(src, end, 2, {
                size_t len = end - src;
                if (len != (*cipher)->hash->digest_size) {
                    ret = PTLS_ALERT_ILLEGAL_PARAMETER;
                    goto Exit;
                }
                ch->esni.record_digest = src;
                src += len;
            });
            ptls_decode_block(src, end, 2, {
                size_t len = end - src;
                if (len < (*cipher)->aead->tag_size) {
                    ret = PTLS_ALERT_ILLEGAL_PARAMETER;
                    goto Exit;
                }
                ch->esni.encrypted_sni = ptls_iovec_init(src, len);
                src += len;
            });
            ch->esni.cipher = *cipher; /* set only after successful parsing */
        } break;
        case PTLS_EXTENSION_TYPE_ALPN:
            ptls_decode_block(src, end, 2, {
                do {
                    ptls_decode_open_block(src, end, 1, {
                        /* rfc7301 3.1: empty strings MUST NOT be included */
                        if (src == end) {
                            ret = PTLS_ALERT_DECODE_ERROR;
                            goto Exit;
                        }
                        if (ch->alpn.count < PTLS_ELEMENTSOF(ch->alpn.list))
                            ch->alpn.list[ch->alpn.count++] = ptls_iovec_init(src, end - src);
                        src = end;
                    });
                } while (src != end);
            });
            break;
        case PTLS_EXTENSION_TYPE_COMPRESS_CERTIFICATE:
            ptls_decode_block(src, end, 1, {
                do {
                    uint16_t id;
                    if ((ret = ptls_decode16(&id, &src, end)) != 0)
                        goto Exit;
                    if (ch->cert_compression_algos.count < PTLS_ELEMENTSOF(ch->cert_compression_algos.list))
                        ch->cert_compression_algos.list[ch->cert_compression_algos.count++] = id;
                } while (src != end);
            });
            break;
        case PTLS_EXTENSION_TYPE_SUPPORTED_GROUPS:
            ch->negotiated_groups = ptls_iovec_init(src, end - src);
            break;
        case PTLS_EXTENSION_TYPE_SIGNATURE_ALGORITHMS:
            if ((ret = decode_signature_algorithms(&ch->signature_algorithms, &src, end)) != 0)
                goto Exit;
            break;
        case PTLS_EXTENSION_TYPE_KEY_SHARE:
            ch->key_shares = ptls_iovec_init(src, end - src);
            break;
        case PTLS_EXTENSION_TYPE_SUPPORTED_VERSIONS:
            ptls_decode_block(src, end, 1, {
                size_t selected_index = PTLS_ELEMENTSOF(supported_versions);
                do {
                    size_t i;
                    uint16_t v;
                    if ((ret = ptls_decode16(&v, &src, end)) != 0)
                        goto Exit;
                    for (i = 0; i != selected_index; ++i) {
                        if (supported_versions[i] == v) {
                            selected_index = i;
                            break;
                        }
                    }
                } while (src != end);
                if (selected_index != PTLS_ELEMENTSOF(supported_versions))
                    ch->selected_version = supported_versions[selected_index];
            });
            break;
        case PTLS_EXTENSION_TYPE_COOKIE:
            if (properties == NULL || properties->server.cookie.key == NULL) {
                ret = PTLS_ALERT_ILLEGAL_PARAMETER;
                goto Exit;
            }
            ch->cookie.all = ptls_iovec_init(src, end - src);
            ptls_decode_block(src, end, 2, {
                ch->cookie.tbs.base = (void *)src;
                ptls_decode_open_block(src, end, 2, {
                    ptls_decode_open_block(src, end, 1, {
                        ch->cookie.ch1_hash = ptls_iovec_init(src, end - src);
                        src = end;
                    });
                    if (src == end) {
                        ret = PTLS_ALERT_DECODE_ERROR;
                        goto Exit;
                    }
                    switch (*src++) {
                    case 0:
                        assert(!ch->cookie.sent_key_share);
                        break;
                    case 1:
                        ch->cookie.sent_key_share = 1;
                        break;
                    default:
                        ret = PTLS_ALERT_DECODE_ERROR;
                        goto Exit;
                    }
                });
                ch->cookie.tbs.len = src - ch->cookie.tbs.base;
                ptls_decode_block(src, end, 1, {
                    ch->cookie.signature = ptls_iovec_init(src, end - src);
                    src = end;
                });
            });
            break;
        case PTLS_EXTENSION_TYPE_PRE_SHARED_KEY: {
            size_t num_identities = 0;
            ptls_decode_open_block(src, end, 2, {
                do {
                    struct st_ptls_client_hello_psk_t psk = {{NULL}};
                    ptls_decode_open_block(src, end, 2, {
                        psk.identity = ptls_iovec_init(src, end - src);
                        src = end;
                    });
                    if ((ret = ptls_decode32(&psk.obfuscated_ticket_age, &src, end)) != 0)
                        goto Exit;
                    if (ch->psk.identities.count < PTLS_ELEMENTSOF(ch->psk.identities.list))
                        ch->psk.identities.list[ch->psk.identities.count++] = psk;
                    ++num_identities;
                } while (src != end);
            });
            ch->psk.hash_end = src;
            ptls_decode_block(src, end, 2, {
                size_t num_binders = 0;
                do {
                    ptls_decode_open_block(src, end, 1, {
                        if (num_binders < ch->psk.identities.count)
                            ch->psk.identities.list[num_binders].binder = ptls_iovec_init(src, end - src);
                        src = end;
                    });
                    ++num_binders;
                } while (src != end);
                if (num_identities != num_binders) {
                    ret = PTLS_ALERT_ILLEGAL_PARAMETER;
                    goto Exit;
                }
            });
            ch->psk.is_last_extension = 1;
        } break;
        case PTLS_EXTENSION_TYPE_PSK_KEY_EXCHANGE_MODES:
            ptls_decode_block(src, end, 1, {
                if (src == end) {
                    ret = PTLS_ALERT_DECODE_ERROR;
                    goto Exit;
                }
                for (; src != end; ++src) {
                    if (*src < sizeof(ch->psk.ke_modes) * 8)
                        ch->psk.ke_modes |= 1u << *src;
                }
            });
            break;
        case PTLS_EXTENSION_TYPE_EARLY_DATA:
            ch->psk.early_data_indication = 1;
            break;
        case PTLS_EXTENSION_TYPE_STATUS_REQUEST:
            ch->status_request = 1;
            break;
        default:
            if (should_collect_unknown_extension(tls, properties, exttype)) {
                if ((ret = collect_unknown_extension(tls, exttype, src, end, ch->unknown_extensions)) != 0)
                    goto Exit;
            }
            break;
        }
        src = end;
    });

    ret = 0;
Exit:
    return ret;
}

static int vec_is_string(ptls_iovec_t x, const char *y)
{
    return strncmp((const char *)x.base, y, x.len) == 0 && y[x.len] == '\0';
}

static int try_psk_handshake(ptls_t *tls, size_t *psk_index, int *accept_early_data, struct st_ptls_client_hello_t *ch,
                             ptls_iovec_t ch_trunc)
{
    ptls_buffer_t decbuf;
    ptls_iovec_t ticket_psk, ticket_server_name, ticket_negotiated_protocol;
    uint64_t issue_at, now = tls->ctx->get_time->cb(tls->ctx->get_time);
    uint32_t age_add;
    uint16_t ticket_key_exchange_id, ticket_csid;
    uint8_t binder_key[PTLS_MAX_DIGEST_SIZE];
    int ret;

    ptls_buffer_init(&decbuf, "", 0);

    for (*psk_index = 0; *psk_index < ch->psk.identities.count; ++*psk_index) {
        struct st_ptls_client_hello_psk_t *identity = ch->psk.identities.list + *psk_index;
        /* decrypt and decode */
        int can_accept_early_data = 1;
        decbuf.off = 0;
        switch (tls->ctx->encrypt_ticket->cb(tls->ctx->encrypt_ticket, tls, 0, &decbuf, identity->identity)) {
        case 0: /* decrypted */
            break;
        case PTLS_ERROR_REJECT_EARLY_DATA: /* decrypted, but early data is rejected */
            can_accept_early_data = 0;
            break;
        default: /* decryption failure */
            continue;
        }
        if (decode_session_identifier(&issue_at, &ticket_psk, &age_add, &ticket_server_name, &ticket_key_exchange_id, &ticket_csid,
                                      &ticket_negotiated_protocol, decbuf.base, decbuf.base + decbuf.off) != 0)
            continue;
        /* check age */
        if (now < issue_at)
            continue;
        if (now - issue_at > (uint64_t)tls->ctx->ticket_lifetime * 1000)
            continue;
        *accept_early_data = 0;
        if (ch->psk.early_data_indication && can_accept_early_data) {
            /* accept early-data if abs(diff) between the reported age and the actual age is within += 10 seconds */
            int64_t delta = (now - issue_at) - (identity->obfuscated_ticket_age - age_add);
            if (delta < 0)
                delta = -delta;
            if (delta <= PTLS_EARLY_DATA_MAX_DELAY)
                *accept_early_data = 1;
        }
        /* check server-name */
        if (ticket_server_name.len != 0) {
            if (tls->server_name == NULL)
                continue;
            if (!vec_is_string(ticket_server_name, tls->server_name))
                continue;
        } else {
            if (tls->server_name != NULL)
                continue;
        }
        { /* check key-exchange */
            ptls_key_exchange_algorithm_t **a;
            for (a = tls->ctx->key_exchanges; *a != NULL && (*a)->id != ticket_key_exchange_id; ++a)
                ;
            if (*a == NULL)
                continue;
            tls->key_share = *a;
        }
        /* check cipher-suite */
        if (ticket_csid != tls->cipher_suite->id)
            continue;
        /* check negotiated-protocol */
        if (ticket_negotiated_protocol.len != 0) {
            if (tls->negotiated_protocol == NULL)
                continue;
            if (!vec_is_string(ticket_negotiated_protocol, tls->negotiated_protocol))
                continue;
        }
        /* check the length of the decrypted psk and the PSK binder */
        if (ticket_psk.len != tls->key_schedule->hashes[0].algo->digest_size)
            continue;
        if (ch->psk.identities.list[*psk_index].binder.len != tls->key_schedule->hashes[0].algo->digest_size)
            continue;

        /* found */
        goto Found;
    }

    /* not found */
    *psk_index = SIZE_MAX;
    *accept_early_data = 0;
    tls->key_share = NULL;
    ret = 0;
    goto Exit;

Found:
    if ((ret = key_schedule_extract(tls->key_schedule, ticket_psk)) != 0)
        goto Exit;
    if ((ret = derive_secret(tls->key_schedule, binder_key, "res binder")) != 0)
        goto Exit;
    ptls__key_schedule_update_hash(tls->key_schedule, ch_trunc.base, ch_trunc.len);
    if ((ret = calc_verify_data(binder_key /* to conserve space, reuse binder_key for storing verify_data */, tls->key_schedule,
                                binder_key)) != 0)
        goto Exit;
    if (!ptls_mem_equal(ch->psk.identities.list[*psk_index].binder.base, binder_key,
                        tls->key_schedule->hashes[0].algo->digest_size)) {
        ret = PTLS_ALERT_DECRYPT_ERROR;
        goto Exit;
    }
    ret = 0;

Exit:
    ptls_buffer_dispose(&decbuf);
    ptls_clear_memory(binder_key, sizeof(binder_key));
    return ret;
}

static int calc_cookie_signature(ptls_t *tls, ptls_handshake_properties_t *properties,
                                 ptls_key_exchange_algorithm_t *negotiated_group, ptls_iovec_t tbs, uint8_t *sig)
{
    ptls_hash_algorithm_t *algo = tls->ctx->cipher_suites[0]->hash;
    ptls_hash_context_t *hctx;

    if ((hctx = ptls_hmac_create(algo, properties->server.cookie.key, algo->digest_size)) == NULL)
        return PTLS_ERROR_NO_MEMORY;

#define UPDATE_BLOCK(p, _len)                                                                                                      \
    do {                                                                                                                           \
        size_t len = (_len);                                                                                                       \
        assert(len < UINT8_MAX);                                                                                                   \
        uint8_t len8 = (uint8_t)len;                                                                                               \
        hctx->update(hctx, &len8, 1);                                                                                              \
        hctx->update(hctx, (p), len);                                                                                              \
    } while (0)
#define UPDATE16(_v)                                                                                                               \
    do {                                                                                                                           \
        uint16_t v = (_v);                                                                                                         \
        uint8_t b[2] = {v >> 8, v & 0xff};                                                                                         \
        hctx->update(hctx, b, 2);                                                                                                  \
    } while (0)

    UPDATE_BLOCK(tls->client_random, sizeof(tls->client_random));
    UPDATE_BLOCK(tls->server_name, tls->server_name != NULL ? strlen(tls->server_name) : 0);
    UPDATE16(tls->cipher_suite->id);
    UPDATE16(negotiated_group->id);
    UPDATE_BLOCK(properties->server.cookie.additional_data.base, properties->server.cookie.additional_data.len);

    UPDATE_BLOCK(tbs.base, tbs.len);

#undef UPDATE_BLOCK
#undef UPDATE16

    hctx->final(hctx, sig, PTLS_HASH_FINAL_MODE_FREE);
    return 0;
}

static int server_handle_hello(ptls_t *tls, ptls_message_emitter_t *emitter, ptls_iovec_t message,
                               ptls_handshake_properties_t *properties)
{
#define EMIT_SERVER_HELLO(sched, fill_rand, extensions)                                                                            \
    ptls_push_message(emitter, (sched), PTLS_HANDSHAKE_TYPE_SERVER_HELLO, {                                                        \
        ptls_buffer_push16(emitter->buf, 0x0303 /* legacy version */);                                                             \
        if ((ret = ptls_buffer_reserve(emitter->buf, PTLS_HELLO_RANDOM_SIZE)) != 0)                                                \
            goto Exit;                                                                                                             \
        do {                                                                                                                       \
            fill_rand                                                                                                              \
        } while (0);                                                                                                               \
        emitter->buf->off += PTLS_HELLO_RANDOM_SIZE;                                                                               \
        ptls_buffer_push_block(emitter->buf, 1,                                                                                    \
                               { ptls_buffer_pushv(emitter->buf, ch->legacy_session_id.base, ch->legacy_session_id.len); });       \
        ptls_buffer_push16(emitter->buf, tls->cipher_suite->id);                                                                   \
        ptls_buffer_push(emitter->buf, 0);                                                                                         \
        ptls_buffer_push_block(emitter->buf, 2, {                                                                                  \
            buffer_push_extension(emitter->buf, PTLS_EXTENSION_TYPE_SUPPORTED_VERSIONS,                                            \
                                  { ptls_buffer_push16(emitter->buf, ch->selected_version); });                                    \
            do {                                                                                                                   \
                extensions                                                                                                         \
            } while (0);                                                                                                           \
        });                                                                                                                        \
    });

#define EMIT_HELLO_RETRY_REQUEST(sched, negotiated_group, additional_extensions)                                                   \
    EMIT_SERVER_HELLO((sched), { memcpy(emitter->buf->base + emitter->buf->off, hello_retry_random, PTLS_HELLO_RANDOM_SIZE); },    \
                      {                                                                                                            \
                          ptls_key_exchange_algorithm_t *_negotiated_group = (negotiated_group);                                   \
                          if (_negotiated_group != NULL) {                                                                         \
                              buffer_push_extension(emitter->buf, PTLS_EXTENSION_TYPE_KEY_SHARE,                                   \
                                                    { ptls_buffer_push16(emitter->buf, _negotiated_group->id); });                 \
                          }                                                                                                        \
                          do {                                                                                                     \
                              additional_extensions                                                                                \
                          } while (0);                                                                                             \
                      })
    struct st_ptls_client_hello_t *ch;
    struct {
        ptls_key_exchange_algorithm_t *algorithm;
        ptls_iovec_t peer_key;
    } key_share = {NULL};
    enum { HANDSHAKE_MODE_FULL, HANDSHAKE_MODE_PSK, HANDSHAKE_MODE_PSK_DHE } mode;
    size_t psk_index = SIZE_MAX;
    ptls_iovec_t pubkey = {0}, ecdh_secret = {0};
    int accept_early_data = 0, is_second_flight = tls->state == PTLS_STATE_SERVER_EXPECT_SECOND_CLIENT_HELLO, ret;

    if ((ch = malloc(sizeof(*ch))) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }
    *ch = (struct st_ptls_client_hello_t){0,      NULL,   {NULL},     {NULL}, 0,     {NULL},   {NULL}, {NULL},        {{0}},
                                          {NULL}, {NULL}, {{{NULL}}}, {{0}},  {{0}}, {{NULL}}, {NULL}, {{UINT16_MAX}}};

    /* decode ClientHello */
    if ((ret = decode_client_hello(tls, ch, message.base + PTLS_HANDSHAKE_HEADER_SIZE, message.base + message.len, properties)) !=
        0)
        goto Exit;

    /* bail out if CH cannot be handled as TLS 1.3, providing the application the raw CH and SNI, to help them fallback */
    if (!is_supported_version(ch->selected_version)) {
        if (!is_second_flight && tls->ctx->on_client_hello != NULL) {
            ptls_on_client_hello_parameters_t params = {
                .server_name = ch->server_name,
                .raw_message = message,
                .negotiated_protocols = {ch->alpn.list, ch->alpn.count},
                .incompatible_version = 1,
            };
            if ((ret = tls->ctx->on_client_hello->cb(tls->ctx->on_client_hello, tls, &params)) != 0)
                goto Exit;
        }
        ret = PTLS_ALERT_PROTOCOL_VERSION;
        goto Exit;
    }

    /* Check TLS 1.3-specific constraints. Hereafter, we might exit without calling on_client_hello. That's fine because this CH is
     * ought to be rejected. */
    if (ch->legacy_version <= 0x0300) {
        /* RFC 8446 Appendix D.5: any endpoint receiving a Hello message with legacy_version set to 0x0300 MUST abort the handshake
         * with a "protocol_version" alert. */
        ret = PTLS_ALERT_PROTOCOL_VERSION;
        goto Exit;
    }
    if (!(ch->compression_methods.count == 1 && ch->compression_methods.ids[0] == 0)) {
        ret = PTLS_ALERT_ILLEGAL_PARAMETER;
        goto Exit;
    }
    /* esni */
    if (ch->esni.cipher != NULL) {
        if (ch->key_shares.base == NULL) {
            ret = PTLS_ALERT_ILLEGAL_PARAMETER;
            goto Exit;
        }
    }
    /* pre-shared key */
    if (ch->psk.hash_end != NULL) {
        /* PSK must be the last extension */
        if (!ch->psk.is_last_extension) {
            ret = PTLS_ALERT_ILLEGAL_PARAMETER;
            goto Exit;
        }
    } else {
        if (ch->psk.early_data_indication) {
            ret = PTLS_ALERT_ILLEGAL_PARAMETER;
            goto Exit;
        }
    }

    if (tls->ctx->require_dhe_on_psk)
        ch->psk.ke_modes &= ~(1u << PTLS_PSK_KE_MODE_PSK);

    /* handle client_random, legacy_session_id, SNI, ESNI */
    if (!is_second_flight) {
        memcpy(tls->client_random, ch->random_bytes, sizeof(tls->client_random));
        log_client_random(tls);
        if (ch->legacy_session_id.len != 0)
            tls->send_change_cipher_spec = 1;
        ptls_iovec_t server_name = {NULL};
        int is_esni = 0;
        if (ch->esni.cipher != NULL && tls->ctx->esni != NULL) {
            if ((ret = client_hello_decrypt_esni(tls->ctx, &server_name, &tls->esni, ch)) != 0)
                goto Exit;
            if (tls->ctx->update_esni_key != NULL) {
                if ((ret = tls->ctx->update_esni_key->cb(tls->ctx->update_esni_key, tls, tls->esni->secret, ch->esni.cipher->hash,
                                                         tls->esni->esni_contents_hash)) != 0)
                    goto Exit;
            }
            is_esni = 1;
        } else if (ch->server_name.base != NULL) {
            server_name = ch->server_name;
        }
        if (tls->ctx->on_client_hello != NULL) {
            ptls_on_client_hello_parameters_t params = {server_name,
                                                        message,
                                                        {ch->alpn.list, ch->alpn.count},
                                                        {ch->signature_algorithms.list, ch->signature_algorithms.count},
                                                        {ch->cert_compression_algos.list, ch->cert_compression_algos.count},
                                                        {ch->client_ciphers.list, ch->client_ciphers.count},
                                                        is_esni};
            ret = tls->ctx->on_client_hello->cb(tls->ctx->on_client_hello, tls, &params);
        } else {
            ret = 0;
        }
        if (is_esni)
            free(server_name.base);
        if (ret != 0)
            goto Exit;
    } else {
        if (ch->psk.early_data_indication) {
            ret = PTLS_ALERT_DECODE_ERROR;
            goto Exit;
        }
        /* the following check is necessary so that we would be able to track the connection in SSLKEYLOGFILE, even though it
         * might not be for the safety of the protocol */
        if (!ptls_mem_equal(tls->client_random, ch->random_bytes, sizeof(tls->client_random))) {
            ret = PTLS_ALERT_HANDSHAKE_FAILURE;
            goto Exit;
        }
        /* We compare SNI only when the value is saved by the on_client_hello callback. This should be OK because we are
         * ignoring the value unless the callback saves the server-name. */
        if (tls->server_name != NULL) {
            size_t l = strlen(tls->server_name);
            if (!(ch->server_name.len == l && memcmp(ch->server_name.base, tls->server_name, l) == 0)) {
                ret = PTLS_ALERT_HANDSHAKE_FAILURE;
                goto Exit;
            }
        }
    }

    { /* select (or check) cipher-suite, create key_schedule */
        ptls_cipher_suite_t *cs;
        if ((ret = select_cipher(&cs, tls->ctx->cipher_suites, ch->cipher_suites.base,
                                 ch->cipher_suites.base + ch->cipher_suites.len)) != 0)
            goto Exit;
        if (!is_second_flight) {
            tls->cipher_suite = cs;
            tls->key_schedule = key_schedule_new(cs, NULL, tls->ctx->hkdf_label_prefix__obsolete);
        } else {
            if (tls->cipher_suite != cs) {
                ret = PTLS_ALERT_HANDSHAKE_FAILURE;
                goto Exit;
            }
        }
    }

    /* select key_share */
    if (key_share.algorithm == NULL && ch->key_shares.base != NULL) {
        const uint8_t *src = ch->key_shares.base, *const end = src + ch->key_shares.len;
        ptls_decode_block(src, end, 2, {
            if ((ret = select_key_share(&key_share.algorithm, &key_share.peer_key, tls->ctx->key_exchanges, &src, end, 0)) != 0)
                goto Exit;
        });
    }

    if (!is_second_flight) {
        if (ch->cookie.all.len != 0 && key_share.algorithm != NULL) {

            /* use cookie to check the integrity of the handshake, and update the context */
            size_t sigsize = tls->ctx->cipher_suites[0]->hash->digest_size;
            uint8_t *sig = alloca(sigsize);
            if ((ret = calc_cookie_signature(tls, properties, key_share.algorithm, ch->cookie.tbs, sig)) != 0)
                goto Exit;
            if (!(ch->cookie.signature.len == sigsize && ptls_mem_equal(ch->cookie.signature.base, sig, sigsize))) {
                ret = PTLS_ALERT_HANDSHAKE_FAILURE;
                goto Exit;
            }
            /* integrity check passed; update states */
            key_schedule_update_ch1hash_prefix(tls->key_schedule);
            ptls__key_schedule_update_hash(tls->key_schedule, ch->cookie.ch1_hash.base, ch->cookie.ch1_hash.len);
            key_schedule_extract(tls->key_schedule, ptls_iovec_init(NULL, 0));
            /* ... reusing sendbuf to rebuild HRR for hash calculation */
            size_t hrr_start = emitter->buf->off;
            EMIT_HELLO_RETRY_REQUEST(tls->key_schedule, ch->cookie.sent_key_share ? key_share.algorithm : NULL, {
                buffer_push_extension(emitter->buf, PTLS_EXTENSION_TYPE_COOKIE,
                                      { ptls_buffer_pushv(emitter->buf, ch->cookie.all.base, ch->cookie.all.len); });
            });
            emitter->buf->off = hrr_start;
            is_second_flight = 1;

        } else if (key_share.algorithm == NULL || (properties != NULL && properties->server.enforce_retry)) {

            /* send HelloRetryRequest  */
            if (ch->negotiated_groups.base == NULL) {
                ret = PTLS_ALERT_MISSING_EXTENSION;
                goto Exit;
            }
            ptls_key_exchange_algorithm_t *negotiated_group;
            if ((ret = select_negotiated_group(&negotiated_group, tls->ctx->key_exchanges, ch->negotiated_groups.base,
                                               ch->negotiated_groups.base + ch->negotiated_groups.len)) != 0)
                goto Exit;
            ptls__key_schedule_update_hash(tls->key_schedule, message.base, message.len);
            assert(tls->key_schedule->generation == 0);
            if (properties != NULL && properties->server.retry_uses_cookie) {
                /* emit HRR with cookie (note: we MUST omit KeyShare if the client has specified the correct one; see 46554f0)
                 */
                EMIT_HELLO_RETRY_REQUEST(NULL, key_share.algorithm != NULL ? NULL : negotiated_group, {
                    ptls_buffer_t *sendbuf = emitter->buf;
                    buffer_push_extension(sendbuf, PTLS_EXTENSION_TYPE_COOKIE, {
                        ptls_buffer_push_block(sendbuf, 2, {
                            /* push to-be-signed data */
                            size_t tbs_start = sendbuf->off;
                            ptls_buffer_push_block(sendbuf, 2, {
                                /* first block of the cookie data is the hash(ch1) */
                                ptls_buffer_push_block(sendbuf, 1, {
                                    size_t sz = tls->cipher_suite->hash->digest_size;
                                    if ((ret = ptls_buffer_reserve(sendbuf, sz)) != 0)
                                        goto Exit;
                                    key_schedule_extract_ch1hash(tls->key_schedule, sendbuf->base + sendbuf->off);
                                    sendbuf->off += sz;
                                });
                                /* second is if we have sent key_share extension */
                                ptls_buffer_push(sendbuf, key_share.algorithm == NULL);
                                /* we can add more data here */
                            });
                            size_t tbs_len = sendbuf->off - tbs_start;
                            /* push the signature */
                            ptls_buffer_push_block(sendbuf, 1, {
                                size_t sz = tls->ctx->cipher_suites[0]->hash->digest_size;
                                if ((ret = ptls_buffer_reserve(sendbuf, sz)) != 0)
                                    goto Exit;
                                if ((ret = calc_cookie_signature(tls, properties, negotiated_group,
                                                                 ptls_iovec_init(sendbuf->base + tbs_start, tbs_len),
                                                                 sendbuf->base + sendbuf->off)) != 0)
                                    goto Exit;
                                sendbuf->off += sz;
                            });
                        });
                    });
                });
                if ((ret = push_change_cipher_spec(tls, emitter)) != 0)
                    goto Exit;
                ret = PTLS_ERROR_STATELESS_RETRY;
            } else {
                /* invoking stateful retry; roll the key schedule and emit HRR */
                key_schedule_transform_post_ch1hash(tls->key_schedule);
                key_schedule_extract(tls->key_schedule, ptls_iovec_init(NULL, 0));
                EMIT_HELLO_RETRY_REQUEST(tls->key_schedule, key_share.algorithm != NULL ? NULL : negotiated_group, {});
                if ((ret = push_change_cipher_spec(tls, emitter)) != 0)
                    goto Exit;
                tls->state = PTLS_STATE_SERVER_EXPECT_SECOND_CLIENT_HELLO;
                if (ch->psk.early_data_indication)
                    tls->server.early_data_skipped_bytes = 0;
                ret = PTLS_ERROR_IN_PROGRESS;
            }
            goto Exit;
        }
    }

    /* handle unknown extensions */
    if ((ret = report_unknown_extensions(tls, properties, ch->unknown_extensions)) != 0)
        goto Exit;

    /* try psk handshake */
    if (!is_second_flight && ch->psk.hash_end != 0 &&
        (ch->psk.ke_modes & ((1u << PTLS_PSK_KE_MODE_PSK) | (1u << PTLS_PSK_KE_MODE_PSK_DHE))) != 0 &&
        tls->ctx->encrypt_ticket != NULL && !tls->ctx->require_client_authentication) {
        if ((ret = try_psk_handshake(tls, &psk_index, &accept_early_data, ch,
                                     ptls_iovec_init(message.base, ch->psk.hash_end - message.base))) != 0) {
            goto Exit;
        }
    }

    /* If client authentication is enabled, we always force a full handshake.
     * TODO: Check for `post_handshake_auth` extension and if that is present, do not force full handshake!
     *       Remove also the check `!require_client_authentication` above.
     *
     * adjust key_schedule, determine handshake mode
     */
    if (psk_index == SIZE_MAX || tls->ctx->require_client_authentication) {
        ptls__key_schedule_update_hash(tls->key_schedule, message.base, message.len);
        if (!is_second_flight) {
            assert(tls->key_schedule->generation == 0);
            key_schedule_extract(tls->key_schedule, ptls_iovec_init(NULL, 0));
        }
        mode = HANDSHAKE_MODE_FULL;
        if (properties != NULL)
            properties->server.selected_psk_binder.len = 0;
    } else {
        ptls__key_schedule_update_hash(tls->key_schedule, ch->psk.hash_end, message.base + message.len - ch->psk.hash_end);
        if ((ch->psk.ke_modes & (1u << PTLS_PSK_KE_MODE_PSK)) != 0) {
            mode = HANDSHAKE_MODE_PSK;
        } else {
            assert((ch->psk.ke_modes & (1u << PTLS_PSK_KE_MODE_PSK_DHE)) != 0);
            mode = HANDSHAKE_MODE_PSK_DHE;
        }
        tls->is_psk_handshake = 1;
        if (properties != NULL) {
            ptls_iovec_t *selected = &ch->psk.identities.list[psk_index].binder;
            memcpy(properties->server.selected_psk_binder.base, selected->base, selected->len);
            properties->server.selected_psk_binder.len = selected->len;
        }
    }

    if (accept_early_data && tls->ctx->max_early_data_size != 0 && psk_index == 0) {
        if ((tls->pending_handshake_secret = malloc(PTLS_MAX_DIGEST_SIZE)) == NULL) {
            ret = PTLS_ERROR_NO_MEMORY;
            goto Exit;
        }
        if ((ret = derive_exporter_secret(tls, 1)) != 0)
            goto Exit;
        if ((ret = setup_traffic_protection(tls, 0, "c e traffic", 1, 0)) != 0)
            goto Exit;
    }

    /* run key-exchange, to obtain pubkey and secret */
    if (mode != HANDSHAKE_MODE_PSK) {
        if (key_share.algorithm == NULL) {
            ret = ch->key_shares.base != NULL ? PTLS_ALERT_HANDSHAKE_FAILURE : PTLS_ALERT_MISSING_EXTENSION;
            goto Exit;
        }
        if ((ret = key_share.algorithm->exchange(key_share.algorithm, &pubkey, &ecdh_secret, key_share.peer_key)) != 0)
            goto Exit;
        tls->key_share = key_share.algorithm;
    }

    /* send ServerHello */
    EMIT_SERVER_HELLO(tls->key_schedule,
                      { tls->ctx->random_bytes(emitter->buf->base + emitter->buf->off, PTLS_HELLO_RANDOM_SIZE); },
                      {
                          ptls_buffer_t *sendbuf = emitter->buf;
                          if (mode != HANDSHAKE_MODE_PSK) {
                              buffer_push_extension(sendbuf, PTLS_EXTENSION_TYPE_KEY_SHARE, {
                                  ptls_buffer_push16(sendbuf, key_share.algorithm->id);
                                  ptls_buffer_push_block(sendbuf, 2, { ptls_buffer_pushv(sendbuf, pubkey.base, pubkey.len); });
                              });
                          }
                          if (mode != HANDSHAKE_MODE_FULL) {
                              buffer_push_extension(sendbuf, PTLS_EXTENSION_TYPE_PRE_SHARED_KEY,
                                                    { ptls_buffer_push16(sendbuf, (uint16_t)psk_index); });
                          }
                      });
    if ((ret = push_change_cipher_spec(tls, emitter)) != 0)
        goto Exit;

    /* create protection contexts for the handshake */
    assert(tls->key_schedule->generation == 1);
    key_schedule_extract(tls->key_schedule, ecdh_secret);
    if ((ret = setup_traffic_protection(tls, 1, "s hs traffic", 2, 0)) != 0)
        goto Exit;
    if (tls->pending_handshake_secret != NULL) {
        if ((ret = derive_secret(tls->key_schedule, tls->pending_handshake_secret, "c hs traffic")) != 0)
            goto Exit;
        if (tls->ctx->update_traffic_key != NULL &&
            (ret = tls->ctx->update_traffic_key->cb(tls->ctx->update_traffic_key, tls, 0, 2, tls->pending_handshake_secret)) != 0)
            goto Exit;
    } else {
        if ((ret = setup_traffic_protection(tls, 0, "c hs traffic", 2, 0)) != 0)
            goto Exit;
        if (ch->psk.early_data_indication)
            tls->server.early_data_skipped_bytes = 0;
    }

    /* send EncryptedExtensions */
    ptls_push_message(emitter, tls->key_schedule, PTLS_HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS, {
        ptls_buffer_t *sendbuf = emitter->buf;
        ptls_buffer_push_block(sendbuf, 2, {
            if (tls->esni != NULL) {
                /* the extension is sent even if the application does not handle server name, because otherwise the handshake
                 * would fail (FIXME ch->esni.nonce will be zero on HRR) */
                buffer_push_extension(sendbuf, PTLS_EXTENSION_TYPE_ENCRYPTED_SERVER_NAME, {
                    uint8_t response_type = PTLS_ESNI_RESPONSE_TYPE_ACCEPT;
                    ptls_buffer_pushv(sendbuf, &response_type, 1);
                    ptls_buffer_pushv(sendbuf, tls->esni->nonce, PTLS_ESNI_NONCE_SIZE);
                });
                free_esni_secret(&tls->esni, 1);
            } else if (tls->server_name != NULL) {
                /* In this event, the server SHALL include an extension of type "server_name" in the (extended) server hello.
                 * The "extension_data" field of this extension SHALL be empty. (RFC 6066 section 3) */
                buffer_push_extension(sendbuf, PTLS_EXTENSION_TYPE_SERVER_NAME, {});
            }
            if (tls->negotiated_protocol != NULL) {
                buffer_push_extension(sendbuf, PTLS_EXTENSION_TYPE_ALPN, {
                    ptls_buffer_push_block(sendbuf, 2, {
                        ptls_buffer_push_block(sendbuf, 1, {
                            ptls_buffer_pushv(sendbuf, tls->negotiated_protocol, strlen(tls->negotiated_protocol));
                        });
                    });
                });
            }
            if (tls->pending_handshake_secret != NULL)
                buffer_push_extension(sendbuf, PTLS_EXTENSION_TYPE_EARLY_DATA, {});
            if ((ret = push_additional_extensions(properties, sendbuf)) != 0)
                goto Exit;
        });
    });

    if (mode == HANDSHAKE_MODE_FULL) {
        /* send certificate request if client authentication is activated */
        if (tls->ctx->require_client_authentication) {
            ptls_push_message(emitter, tls->key_schedule, PTLS_HANDSHAKE_TYPE_CERTIFICATE_REQUEST, {
                /* certificate_request_context, this field SHALL be zero length, unless the certificate
                 * request is used for post-handshake authentication.
                 */
                ptls_buffer_t *sendbuf = emitter->buf;
                ptls_buffer_push(sendbuf, 0);
                /* extensions */
                ptls_buffer_push_block(sendbuf, 2, {
                    buffer_push_extension(sendbuf, PTLS_EXTENSION_TYPE_SIGNATURE_ALGORITHMS, {
                        if ((ret = push_signature_algorithms(sendbuf)) != 0)
                            goto Exit;
                    });
                });
            });

            if (ret != 0) {
                goto Exit;
            }
        }

        ret = send_certificate_and_certificate_verify(tls, emitter, &ch->signature_algorithms, ptls_iovec_init(NULL, 0),
                                                      PTLS_SERVER_CERTIFICATE_VERIFY_CONTEXT_STRING, ch->status_request,
                                                      ch->cert_compression_algos.list, ch->cert_compression_algos.count);

        if (ret != 0) {
            goto Exit;
        }
    }

    if ((ret = send_finished(tls, emitter)) != 0)
        goto Exit;

    assert(tls->key_schedule->generation == 2);
    if ((ret = key_schedule_extract(tls->key_schedule, ptls_iovec_init(NULL, 0))) != 0)
        goto Exit;
    if ((ret = setup_traffic_protection(tls, 1, "s ap traffic", 3, 0)) != 0)
        goto Exit;
    if ((ret = derive_secret(tls->key_schedule, tls->server.pending_traffic_secret, "c ap traffic")) != 0)
        goto Exit;
    if ((ret = derive_exporter_secret(tls, 0)) != 0)
        goto Exit;

    if (tls->pending_handshake_secret != NULL) {
        if (tls->ctx->omit_end_of_early_data) {
            if ((ret = commission_handshake_secret(tls)) != 0)
                goto Exit;
            tls->state = PTLS_STATE_SERVER_EXPECT_FINISHED;
        } else {
            tls->state = PTLS_STATE_SERVER_EXPECT_END_OF_EARLY_DATA;
        }
    } else if (tls->ctx->require_client_authentication) {
        tls->state = PTLS_STATE_SERVER_EXPECT_CERTIFICATE;
    } else {
        tls->state = PTLS_STATE_SERVER_EXPECT_FINISHED;
    }

    /* send session ticket if necessary */
    if (ch->psk.ke_modes != 0 && tls->ctx->ticket_lifetime != 0) {
        if ((ret = send_session_ticket(tls, emitter)) != 0)
            goto Exit;
    }

    if (tls->ctx->require_client_authentication) {
        ret = PTLS_ERROR_IN_PROGRESS;
    } else {
        ret = 0;
    }

Exit:
    free(pubkey.base);
    if (ecdh_secret.base != NULL) {
        ptls_clear_memory(ecdh_secret.base, ecdh_secret.len);
        free(ecdh_secret.base);
    }
    free(ch);
    return ret;

#undef EMIT_SERVER_HELLO
#undef EMIT_HELLO_RETRY_REQUEST
}

static int server_handle_end_of_early_data(ptls_t *tls, ptls_iovec_t message)
{
    int ret;

    if ((ret = commission_handshake_secret(tls)) != 0)
        goto Exit;

    ptls__key_schedule_update_hash(tls->key_schedule, message.base, message.len);
    tls->state = PTLS_STATE_SERVER_EXPECT_FINISHED;
    ret = PTLS_ERROR_IN_PROGRESS;

Exit:
    return ret;
}

static int server_handle_finished(ptls_t *tls, ptls_iovec_t message)
{
    int ret;

    if ((ret = verify_finished(tls, message)) != 0)
        return ret;

    memcpy(tls->traffic_protection.dec.secret, tls->server.pending_traffic_secret, sizeof(tls->server.pending_traffic_secret));
    ptls_clear_memory(tls->server.pending_traffic_secret, sizeof(tls->server.pending_traffic_secret));
    if ((ret = setup_traffic_protection(tls, 0, NULL, 3, 0)) != 0)
        return ret;

    ptls__key_schedule_update_hash(tls->key_schedule, message.base, message.len);

    tls->state = PTLS_STATE_SERVER_POST_HANDSHAKE;
    return 0;
}

static int update_traffic_key(ptls_t *tls, int is_enc)
{
    struct st_ptls_traffic_protection_t *tp = is_enc ? &tls->traffic_protection.enc : &tls->traffic_protection.dec;
    uint8_t secret[PTLS_MAX_DIGEST_SIZE];
    int ret;

    ptls_hash_algorithm_t *hash = tls->key_schedule->hashes[0].algo;
    if ((ret = hkdf_expand_label(hash, secret, hash->digest_size, ptls_iovec_init(tp->secret, hash->digest_size), "traffic upd",
                                 ptls_iovec_init(NULL, 0), tls->key_schedule->hkdf_label_prefix)) != 0)
        goto Exit;
    memcpy(tp->secret, secret, sizeof(secret));
    ret = setup_traffic_protection(tls, is_enc, NULL, 3, 1);

Exit:
    ptls_clear_memory(secret, sizeof(secret));
    return ret;
}

static int handle_key_update(ptls_t *tls, ptls_message_emitter_t *emitter, ptls_iovec_t message)
{
    const uint8_t *src = message.base + PTLS_HANDSHAKE_HEADER_SIZE, *const end = message.base + message.len;
    int ret;

    /* validate */
    if (end - src != 1 || *src > 1)
        return PTLS_ALERT_DECODE_ERROR;

    /* update receive key */
    if ((ret = update_traffic_key(tls, 0)) != 0)
        return ret;

    if (*src) {
        if (tls->ctx->update_traffic_key != NULL)
            return PTLS_ALERT_UNEXPECTED_MESSAGE;
        tls->needs_key_update = 1;
    }

    return 0;
}

static int parse_record_header(struct st_ptls_record_t *rec, const uint8_t *src)
{
    rec->type = src[0];
    rec->version = ntoh16(src + 1);
    rec->length = ntoh16(src + 3);

    if (rec->length >
        (size_t)(rec->type == PTLS_CONTENT_TYPE_APPDATA ? PTLS_MAX_ENCRYPTED_RECORD_SIZE : PTLS_MAX_PLAINTEXT_RECORD_SIZE))
        return PTLS_ALERT_DECODE_ERROR;

    return 0;
}

static int parse_record(ptls_t *tls, struct st_ptls_record_t *rec, const uint8_t *src, size_t *len)
{
    int ret;

    if (tls->recvbuf.rec.base == NULL && *len >= 5) {
        /* fast path */
        if ((ret = parse_record_header(rec, src)) != 0)
            return ret;
        if (5 + rec->length <= *len) {
            rec->fragment = src + 5;
            *len = rec->length + 5;
            return 0;
        }
    }

    /* slow path */
    const uint8_t *const end = src + *len;
    *rec = (struct st_ptls_record_t){0};

    if (tls->recvbuf.rec.base == NULL) {
        ptls_buffer_init(&tls->recvbuf.rec, "", 0);
        if ((ret = ptls_buffer_reserve(&tls->recvbuf.rec, 5)) != 0)
            return ret;
    }

    /* fill and parse the header */
    while (tls->recvbuf.rec.off < 5) {
        if (src == end)
            return PTLS_ERROR_IN_PROGRESS;
        tls->recvbuf.rec.base[tls->recvbuf.rec.off++] = *src++;
    }
    if ((ret = parse_record_header(rec, tls->recvbuf.rec.base)) != 0)
        return ret;

    /* fill the fragment */
    size_t addlen = rec->length + 5 - tls->recvbuf.rec.off;
    if (addlen != 0) {
        if ((ret = ptls_buffer_reserve(&tls->recvbuf.rec, addlen)) != 0)
            return ret;
        if (addlen > (size_t)(end - src))
            addlen = end - src;
        if (addlen != 0) {
            memcpy(tls->recvbuf.rec.base + tls->recvbuf.rec.off, src, addlen);
            tls->recvbuf.rec.off += addlen;
            src += addlen;
        }
    }

    /* set rec->fragment if a complete record has been parsed */
    if (tls->recvbuf.rec.off == rec->length + 5) {
        rec->fragment = tls->recvbuf.rec.base + 5;
        ret = 0;
    } else {
        ret = PTLS_ERROR_IN_PROGRESS;
    }

    *len -= end - src;
    return ret;
}

static void update_open_count(ptls_context_t *ctx, ssize_t delta)
{
    if (ctx->update_open_count != NULL)
        ctx->update_open_count->cb(ctx->update_open_count, delta);
}

static ptls_t *new_instance(ptls_context_t *ctx, int is_server)
{
    ptls_t *tls;

    assert(ctx->get_time != NULL && "please set ctx->get_time to `&ptls_get_time`; see #92");

    if ((tls = malloc(sizeof(*tls))) == NULL)
        return NULL;

    update_open_count(ctx, 1);
    *tls = (ptls_t){ctx};
    tls->is_server = is_server;
    tls->send_change_cipher_spec = ctx->send_change_cipher_spec;
    tls->skip_tracing = ptls_default_skip_tracing;
    return tls;
}

ptls_t *ptls_client_new(ptls_context_t *ctx)
{
    ptls_t *tls = new_instance(ctx, 0);
    tls->state = PTLS_STATE_CLIENT_HANDSHAKE_START;
    tls->ctx->random_bytes(tls->client_random, sizeof(tls->client_random));
    log_client_random(tls);
    if (tls->send_change_cipher_spec) {
        tls->client.legacy_session_id =
            ptls_iovec_init(tls->client.legacy_session_id_buf, sizeof(tls->client.legacy_session_id_buf));
        tls->ctx->random_bytes(tls->client.legacy_session_id.base, tls->client.legacy_session_id.len);
    }

    PTLS_PROBE(NEW, tls, 0);
    return tls;
}

ptls_t *ptls_server_new(ptls_context_t *ctx)
{
    ptls_t *tls = new_instance(ctx, 1);
    tls->state = PTLS_STATE_SERVER_EXPECT_CLIENT_HELLO;
    tls->server.early_data_skipped_bytes = UINT32_MAX;

    PTLS_PROBE(NEW, tls, 1);
    return tls;
}

void ptls_free(ptls_t *tls)
{
    PTLS_PROBE0(FREE, tls);
    ptls_buffer_dispose(&tls->recvbuf.rec);
    ptls_buffer_dispose(&tls->recvbuf.mess);
    free_exporter_master_secret(tls, 1);
    free_exporter_master_secret(tls, 0);
    if (tls->esni != NULL)
        free_esni_secret(&tls->esni, tls->is_server);
    if (tls->key_schedule != NULL)
        key_schedule_free(tls->key_schedule);
    if (tls->traffic_protection.dec.aead != NULL)
        ptls_aead_free(tls->traffic_protection.dec.aead);
    if (tls->traffic_protection.enc.aead != NULL)
        ptls_aead_free(tls->traffic_protection.enc.aead);
    free(tls->server_name);
    free(tls->negotiated_protocol);
    if (tls->is_server) {
        /* nothing to do */
    } else {
        if (tls->client.key_share_ctx != NULL)
            tls->client.key_share_ctx->on_exchange(&tls->client.key_share_ctx, 1, NULL, ptls_iovec_init(NULL, 0));
        if (tls->client.certificate_request.context.base != NULL)
            free(tls->client.certificate_request.context.base);
    }
    if (tls->certificate_verify.cb != NULL) {
        tls->certificate_verify.cb(tls->certificate_verify.verify_ctx, ptls_iovec_init(NULL, 0), ptls_iovec_init(NULL, 0));
    }
    if (tls->pending_handshake_secret != NULL) {
        ptls_clear_memory(tls->pending_handshake_secret, PTLS_MAX_DIGEST_SIZE);
        free(tls->pending_handshake_secret);
    }
    update_open_count(tls->ctx, -1);
    ptls_clear_memory(tls, sizeof(*tls));
    free(tls);
}

ptls_context_t *ptls_get_context(ptls_t *tls)
{
    return tls->ctx;
}

void ptls_set_context(ptls_t *tls, ptls_context_t *ctx)
{
    update_open_count(ctx, 1);
    update_open_count(tls->ctx, -1);
    tls->ctx = ctx;
}

ptls_iovec_t ptls_get_client_random(ptls_t *tls)
{
    return ptls_iovec_init(tls->client_random, PTLS_HELLO_RANDOM_SIZE);
}

ptls_cipher_suite_t *ptls_get_cipher(ptls_t *tls)
{
    return tls->cipher_suite;
}

const char *ptls_get_server_name(ptls_t *tls)
{
    return tls->server_name;
}

int ptls_set_server_name(ptls_t *tls, const char *server_name, size_t server_name_len)
{
    char *duped = NULL;

    if (server_name != NULL) {
        if (server_name_len == 0)
            server_name_len = strlen(server_name);
        if ((duped = malloc(server_name_len + 1)) == NULL)
            return PTLS_ERROR_NO_MEMORY;
        memcpy(duped, server_name, server_name_len);
        duped[server_name_len] = '\0';
    }

    free(tls->server_name);
    tls->server_name = duped;

    return 0;
}

const char *ptls_get_negotiated_protocol(ptls_t *tls)
{
    return tls->negotiated_protocol;
}

int ptls_set_negotiated_protocol(ptls_t *tls, const char *protocol, size_t protocol_len)
{
    char *duped = NULL;

    if (protocol != NULL) {
        if (protocol_len == 0)
            protocol_len = strlen(protocol);
        if ((duped = malloc(protocol_len + 1)) == NULL)
            return PTLS_ERROR_NO_MEMORY;
        memcpy(duped, protocol, protocol_len);
        duped[protocol_len] = '\0';
    }

    free(tls->negotiated_protocol);
    tls->negotiated_protocol = duped;

    return 0;
}

int ptls_handshake_is_complete(ptls_t *tls)
{
    return tls->state >= PTLS_STATE_POST_HANDSHAKE_MIN;
}

int ptls_is_psk_handshake(ptls_t *tls)
{
    return tls->is_psk_handshake;
}

void **ptls_get_data_ptr(ptls_t *tls)
{
    return &tls->data_ptr;
}

int ptls_skip_tracing(ptls_t *tls)
{
    return tls->skip_tracing;
}

void ptls_set_skip_tracing(ptls_t *tls, int skip_tracing)
{
    tls->skip_tracing = skip_tracing;
}

static int handle_client_handshake_message(ptls_t *tls, ptls_message_emitter_t *emitter, ptls_iovec_t message, int is_end_of_record,
                                           ptls_handshake_properties_t *properties)
{
    uint8_t type = message.base[0];
    int ret;

    switch (tls->state) {
    case PTLS_STATE_CLIENT_EXPECT_SERVER_HELLO:
    case PTLS_STATE_CLIENT_EXPECT_SECOND_SERVER_HELLO:
        if (type == PTLS_HANDSHAKE_TYPE_SERVER_HELLO && is_end_of_record) {
            ret = client_handle_hello(tls, emitter, message, properties);
        } else {
            ret = PTLS_ALERT_UNEXPECTED_MESSAGE;
        }
        break;
    case PTLS_STATE_CLIENT_EXPECT_ENCRYPTED_EXTENSIONS:
        if (type == PTLS_HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS) {
            ret = client_handle_encrypted_extensions(tls, message, properties);
        } else {
            ret = PTLS_ALERT_UNEXPECTED_MESSAGE;
        }
        break;
    case PTLS_STATE_CLIENT_EXPECT_CERTIFICATE_REQUEST_OR_CERTIFICATE:
        if (type == PTLS_HANDSHAKE_TYPE_CERTIFICATE_REQUEST) {
            ret = client_handle_certificate_request(tls, message, properties);
            break;
        }
    /* fall through */
    case PTLS_STATE_CLIENT_EXPECT_CERTIFICATE:
        switch (type) {
        case PTLS_HANDSHAKE_TYPE_CERTIFICATE:
            ret = client_handle_certificate(tls, message);
            break;
        case PTLS_HANDSHAKE_TYPE_COMPRESSED_CERTIFICATE:
            ret = client_handle_compressed_certificate(tls, message);
            break;
        default:
            ret = PTLS_ALERT_UNEXPECTED_MESSAGE;
            break;
        }
        break;
    case PTLS_STATE_CLIENT_EXPECT_CERTIFICATE_VERIFY:
        if (type == PTLS_HANDSHAKE_TYPE_CERTIFICATE_VERIFY) {
            ret = client_handle_certificate_verify(tls, message);
        } else {
            ret = PTLS_ALERT_UNEXPECTED_MESSAGE;
        }
        break;
    case PTLS_STATE_CLIENT_EXPECT_FINISHED:
        if (type == PTLS_HANDSHAKE_TYPE_FINISHED && is_end_of_record) {
            ret = client_handle_finished(tls, emitter, message);
        } else {
            ret = PTLS_ALERT_UNEXPECTED_MESSAGE;
        }
        break;
    case PTLS_STATE_CLIENT_POST_HANDSHAKE:
        switch (type) {
        case PTLS_HANDSHAKE_TYPE_NEW_SESSION_TICKET:
            ret = client_handle_new_session_ticket(tls, message);
            break;
        case PTLS_HANDSHAKE_TYPE_KEY_UPDATE:
            ret = handle_key_update(tls, emitter, message);
            break;
        default:
            ret = PTLS_ALERT_UNEXPECTED_MESSAGE;
            break;
        }
        break;
    default:
        assert(!"unexpected state");
        ret = PTLS_ALERT_INTERNAL_ERROR;
        break;
    }

    PTLS_PROBE(RECEIVE_MESSAGE, tls, message.base[0], message.base + PTLS_HANDSHAKE_HEADER_SIZE,
               message.len - PTLS_HANDSHAKE_HEADER_SIZE, ret);

    return ret;
}

static int handle_server_handshake_message(ptls_t *tls, ptls_message_emitter_t *emitter, ptls_iovec_t message, int is_end_of_record,
                                           ptls_handshake_properties_t *properties)
{
    uint8_t type = message.base[0];
    int ret;

    switch (tls->state) {
    case PTLS_STATE_SERVER_EXPECT_CLIENT_HELLO:
    case PTLS_STATE_SERVER_EXPECT_SECOND_CLIENT_HELLO:
        if (type == PTLS_HANDSHAKE_TYPE_CLIENT_HELLO && is_end_of_record) {
            ret = server_handle_hello(tls, emitter, message, properties);
        } else {
            ret = PTLS_ALERT_HANDSHAKE_FAILURE;
        }
        break;
    case PTLS_STATE_SERVER_EXPECT_CERTIFICATE:
        if (type == PTLS_HANDSHAKE_TYPE_CERTIFICATE) {
            ret = server_handle_certificate(tls, message);
        } else {
            ret = PTLS_ALERT_UNEXPECTED_MESSAGE;
        }
        break;
    case PTLS_STATE_SERVER_EXPECT_CERTIFICATE_VERIFY:
        if (type == PTLS_HANDSHAKE_TYPE_CERTIFICATE_VERIFY) {
            ret = server_handle_certificate_verify(tls, message);
        } else {
            ret = PTLS_ALERT_UNEXPECTED_MESSAGE;
        }
        break;
    case PTLS_STATE_SERVER_EXPECT_END_OF_EARLY_DATA:
        assert(!tls->ctx->omit_end_of_early_data);
        if (type == PTLS_HANDSHAKE_TYPE_END_OF_EARLY_DATA) {
            ret = server_handle_end_of_early_data(tls, message);
        } else {
            ret = PTLS_ALERT_UNEXPECTED_MESSAGE;
        }
        break;
    case PTLS_STATE_SERVER_EXPECT_FINISHED:
        if (type == PTLS_HANDSHAKE_TYPE_FINISHED && is_end_of_record) {
            ret = server_handle_finished(tls, message);
        } else {
            ret = PTLS_ALERT_HANDSHAKE_FAILURE;
        }
        break;
    case PTLS_STATE_SERVER_POST_HANDSHAKE:
        switch (type) {
        case PTLS_HANDSHAKE_TYPE_KEY_UPDATE:
            ret = handle_key_update(tls, emitter, message);
            break;
        default:
            ret = PTLS_ALERT_UNEXPECTED_MESSAGE;
            break;
        }
        break;
    default:
        assert(!"unexpected state");
        ret = PTLS_ALERT_INTERNAL_ERROR;
        break;
    }

    PTLS_PROBE(RECEIVE_MESSAGE, tls, message.base[0], message.base + PTLS_HANDSHAKE_HEADER_SIZE,
               message.len - PTLS_HANDSHAKE_HEADER_SIZE, ret);

    return ret;
}

static int handle_alert(ptls_t *tls, const uint8_t *src, size_t len)
{
    if (len != 2)
        return PTLS_ALERT_DECODE_ERROR;

    uint8_t desc = src[1];

    /* all fatal alerts and USER_CANCELLED warning tears down the connection immediately, regardless of the transmitted level */
    return PTLS_ALERT_TO_PEER_ERROR(desc);
}

static int message_buffer_is_overflow(ptls_context_t *ctx, size_t size)
{
    if (ctx->max_buffer_size == 0)
        return 0;
    if (size <= ctx->max_buffer_size)
        return 0;
    return 1;
}

static int handle_handshake_record(ptls_t *tls,
                                   int (*cb)(ptls_t *tls, ptls_message_emitter_t *emitter, ptls_iovec_t message,
                                             int is_end_of_record, ptls_handshake_properties_t *properties),
                                   ptls_message_emitter_t *emitter, struct st_ptls_record_t *rec,
                                   ptls_handshake_properties_t *properties)
{
    int ret;

    /* handshake */
    if (rec->type != PTLS_CONTENT_TYPE_HANDSHAKE)
        return PTLS_ALERT_DECODE_ERROR;

    /* flatten the unhandled messages */
    const uint8_t *src, *src_end;
    if (tls->recvbuf.mess.base == NULL) {
        src = rec->fragment;
        src_end = src + rec->length;
    } else {
        if (message_buffer_is_overflow(tls->ctx, tls->recvbuf.mess.off + rec->length))
            return PTLS_ALERT_HANDSHAKE_FAILURE;
        if ((ret = ptls_buffer_reserve(&tls->recvbuf.mess, rec->length)) != 0)
            return ret;
        memcpy(tls->recvbuf.mess.base + tls->recvbuf.mess.off, rec->fragment, rec->length);
        tls->recvbuf.mess.off += rec->length;
        src = tls->recvbuf.mess.base;
        src_end = src + tls->recvbuf.mess.off;
    }

    /* handle the messages */
    ret = PTLS_ERROR_IN_PROGRESS;
    while (src_end - src >= 4) {
        size_t mess_len = 4 + ntoh24(src + 1);
        if (src_end - src < (int)mess_len)
            break;
        ret = cb(tls, emitter, ptls_iovec_init(src, mess_len), src_end - src == mess_len, properties);
        switch (ret) {
        case 0:
        case PTLS_ERROR_IN_PROGRESS:
            break;
        default:
            ptls_buffer_dispose(&tls->recvbuf.mess);
            return ret;
        }
        src += mess_len;
    }

    /* keep last partial message in buffer */
    if (src != src_end) {
        size_t new_size = src_end - src;
        if (message_buffer_is_overflow(tls->ctx, new_size))
            return PTLS_ALERT_HANDSHAKE_FAILURE;
        if (tls->recvbuf.mess.base == NULL) {
            ptls_buffer_init(&tls->recvbuf.mess, "", 0);
            if ((ret = ptls_buffer_reserve(&tls->recvbuf.mess, new_size)) != 0)
                return ret;
            memcpy(tls->recvbuf.mess.base, src, new_size);
        } else {
            memmove(tls->recvbuf.mess.base, src, new_size);
        }
        tls->recvbuf.mess.off = new_size;
        ret = PTLS_ERROR_IN_PROGRESS;
    } else {
        ptls_buffer_dispose(&tls->recvbuf.mess);
    }

    return ret;
}

static int handle_input(ptls_t *tls, ptls_message_emitter_t *emitter, ptls_buffer_t *decryptbuf, const void *input, size_t *inlen,
                        ptls_handshake_properties_t *properties)
{
    struct st_ptls_record_t rec;
    int ret;

    /* extract the record */
    if ((ret = parse_record(tls, &rec, input, inlen)) != 0)
        return ret;
    assert(rec.fragment != NULL);

    /* decrypt the record */
    if (rec.type == PTLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC) {
        if (tls->state < PTLS_STATE_POST_HANDSHAKE_MIN) {
            if (!(rec.length == 1 && rec.fragment[0] == 0x01))
                return PTLS_ALERT_ILLEGAL_PARAMETER;
        } else {
            return PTLS_ALERT_HANDSHAKE_FAILURE;
        }
        ret = PTLS_ERROR_IN_PROGRESS;
        goto NextRecord;
    }
    if (tls->traffic_protection.dec.aead != NULL && rec.type != PTLS_CONTENT_TYPE_ALERT) {
        size_t decrypted_length;
        if (rec.type != PTLS_CONTENT_TYPE_APPDATA)
            return PTLS_ALERT_HANDSHAKE_FAILURE;
        if ((ret = ptls_buffer_reserve(decryptbuf, 5 + rec.length)) != 0)
            return ret;
        if ((ret = aead_decrypt(&tls->traffic_protection.dec, decryptbuf->base + decryptbuf->off, &decrypted_length, rec.fragment,
                                rec.length)) != 0) {
            if (tls->is_server && tls->server.early_data_skipped_bytes != UINT32_MAX)
                goto ServerSkipEarlyData;
            return ret;
        }
        rec.length = decrypted_length;
        rec.fragment = decryptbuf->base + decryptbuf->off;
        /* skip padding */
        for (; rec.length != 0; --rec.length)
            if (rec.fragment[rec.length - 1] != 0)
                break;
        if (rec.length == 0)
            return PTLS_ALERT_UNEXPECTED_MESSAGE;
        rec.type = rec.fragment[--rec.length];
    } else if (rec.type == PTLS_CONTENT_TYPE_APPDATA && tls->is_server && tls->server.early_data_skipped_bytes != UINT32_MAX) {
        goto ServerSkipEarlyData;
    }

    if (tls->recvbuf.mess.base != NULL || rec.type == PTLS_CONTENT_TYPE_HANDSHAKE) {
        /* handshake record */
        ret = handle_handshake_record(tls, tls->is_server ? handle_server_handshake_message : handle_client_handshake_message,
                                      emitter, &rec, properties);
    } else {
        /* handling of an alert or an application record */
        switch (rec.type) {
        case PTLS_CONTENT_TYPE_APPDATA:
            if (tls->state >= PTLS_STATE_POST_HANDSHAKE_MIN) {
                decryptbuf->off += rec.length;
                ret = 0;
            } else if (tls->state == PTLS_STATE_SERVER_EXPECT_END_OF_EARLY_DATA) {
                if (tls->traffic_protection.dec.aead != NULL)
                    decryptbuf->off += rec.length;
                ret = 0;
            } else {
                ret = PTLS_ALERT_UNEXPECTED_MESSAGE;
            }
            break;
        case PTLS_CONTENT_TYPE_ALERT:
            ret = handle_alert(tls, rec.fragment, rec.length);
            break;
        default:
            ret = PTLS_ALERT_UNEXPECTED_MESSAGE;
            break;
        }
    }

NextRecord:
    ptls_buffer_dispose(&tls->recvbuf.rec);
    return ret;

ServerSkipEarlyData:
    tls->server.early_data_skipped_bytes += (uint32_t)rec.length;
    if (tls->server.early_data_skipped_bytes > PTLS_MAX_EARLY_DATA_SKIP_SIZE)
        return PTLS_ALERT_HANDSHAKE_FAILURE;
    ret = PTLS_ERROR_IN_PROGRESS;
    goto NextRecord;
}

static void init_record_message_emitter(ptls_t *tls, struct st_ptls_record_message_emitter_t *emitter, ptls_buffer_t *sendbuf)
{
    *emitter = (struct st_ptls_record_message_emitter_t){
        {sendbuf, &tls->traffic_protection.enc, 5, begin_record_message, commit_record_message}};
}

int ptls_handshake(ptls_t *tls, ptls_buffer_t *_sendbuf, const void *input, size_t *inlen, ptls_handshake_properties_t *properties)
{
    struct st_ptls_record_message_emitter_t emitter;
    int ret;

    assert(tls->state < PTLS_STATE_POST_HANDSHAKE_MIN);

    init_record_message_emitter(tls, &emitter, _sendbuf);
    size_t sendbuf_orig_off = emitter.super.buf->off;

    /* special handlings */
    switch (tls->state) {
    case PTLS_STATE_CLIENT_HANDSHAKE_START: {
        assert(input == NULL || *inlen == 0);
        assert(tls->ctx->key_exchanges[0] != NULL);
        return send_client_hello(tls, &emitter.super, properties, NULL);
    }
    default:
        break;
    }

    const uint8_t *src = input, *const src_end = src + *inlen;
    ptls_buffer_t decryptbuf;

    ptls_buffer_init(&decryptbuf, "", 0);

    /* perform handhake until completion or until all the input has been swallowed */
    ret = PTLS_ERROR_IN_PROGRESS;
    while (ret == PTLS_ERROR_IN_PROGRESS && src != src_end) {
        size_t consumed = src_end - src;
        ret = handle_input(tls, &emitter.super, &decryptbuf, src, &consumed, properties);
        src += consumed;
        assert(decryptbuf.off == 0);
    }

    ptls_buffer_dispose(&decryptbuf);

    switch (ret) {
    case 0:
    case PTLS_ERROR_IN_PROGRESS:
    case PTLS_ERROR_STATELESS_RETRY:
        break;
    default:
        /* flush partially written response */
        ptls_clear_memory(emitter.super.buf->base + sendbuf_orig_off, emitter.super.buf->off - sendbuf_orig_off);
        emitter.super.buf->off = sendbuf_orig_off;
        /* send alert immediately */
        if (PTLS_ERROR_GET_CLASS(ret) != PTLS_ERROR_CLASS_PEER_ALERT)
            if (ptls_send_alert(tls, emitter.super.buf, PTLS_ALERT_LEVEL_FATAL,
                                PTLS_ERROR_GET_CLASS(ret) == PTLS_ERROR_CLASS_SELF_ALERT ? ret : PTLS_ALERT_INTERNAL_ERROR) != 0)
                emitter.super.buf->off = sendbuf_orig_off;
        break;
    }

    *inlen -= src_end - src;
    return ret;
}

int ptls_receive(ptls_t *tls, ptls_buffer_t *decryptbuf, const void *_input, size_t *inlen)
{
    const uint8_t *input = (const uint8_t *)_input, *const end = input + *inlen;
    size_t decryptbuf_orig_size = decryptbuf->off;
    int ret = 0;

    assert(tls->state >= PTLS_STATE_SERVER_EXPECT_END_OF_EARLY_DATA);

    /* loop until we decrypt some application data (or an error) */
    while (ret == 0 && input != end && decryptbuf_orig_size == decryptbuf->off) {
        size_t consumed = end - input;
        ret = handle_input(tls, NULL, decryptbuf, input, &consumed, NULL);
        input += consumed;

        switch (ret) {
        case 0:
            break;
        case PTLS_ERROR_IN_PROGRESS:
            ret = 0;
            break;
        case PTLS_ERROR_CLASS_PEER_ALERT + PTLS_ALERT_CLOSE_NOTIFY:
            /* TODO send close alert */
            break;
        default:
            if (PTLS_ERROR_GET_CLASS(ret) == PTLS_ERROR_CLASS_SELF_ALERT) {
                /* TODO send alert */
            }
            break;
        }
    }

    *inlen -= end - input;

    return ret;
}

static int update_send_key(ptls_t *tls, ptls_buffer_t *_sendbuf, int request_update)
{
    struct st_ptls_record_message_emitter_t emitter;
    int ret;

    init_record_message_emitter(tls, &emitter, _sendbuf);
    size_t sendbuf_orig_off = emitter.super.buf->off;

    ptls_push_message(&emitter.super, NULL, PTLS_HANDSHAKE_TYPE_KEY_UPDATE,
                      { ptls_buffer_push(emitter.super.buf, !!request_update); });
    if ((ret = update_traffic_key(tls, 1)) != 0)
        goto Exit;
    ret = 0;

Exit:
    if (ret != 0)
        emitter.super.buf->off = sendbuf_orig_off;
    return ret;
}

int ptls_send(ptls_t *tls, ptls_buffer_t *sendbuf, const void *input, size_t inlen)
{
    assert(tls->traffic_protection.enc.aead != NULL);

    /* "For AES-GCM, up to 2^24.5 full-size records (about 24 million) may be encrypted on a given connection while keeping a
     * safety margin of approximately 2^-57 for Authenticated Encryption (AE) security." (RFC 8446 section 5.5)
     */
    if (tls->traffic_protection.enc.seq >= 16777216)
        tls->needs_key_update = 1;

    if (tls->needs_key_update) {
        int ret;
        if ((ret = update_send_key(tls, sendbuf, tls->key_update_send_request)) != 0)
            return ret;
        tls->needs_key_update = 0;
        tls->key_update_send_request = 0;
    }

    return buffer_push_encrypted_records(sendbuf, PTLS_CONTENT_TYPE_APPDATA, input, inlen, &tls->traffic_protection.enc);
}

int ptls_update_key(ptls_t *tls, int request_update)
{
    assert(tls->ctx->update_traffic_key == NULL);
    tls->needs_key_update = 1;
    tls->key_update_send_request = request_update;
    return 0;
}

size_t ptls_get_record_overhead(ptls_t *tls)
{
    return 6 + tls->traffic_protection.enc.aead->algo->tag_size;
}

int ptls_send_alert(ptls_t *tls, ptls_buffer_t *sendbuf, uint8_t level, uint8_t description)
{
    size_t rec_start = sendbuf->off;
    int ret = 0;

    buffer_push_record(sendbuf, PTLS_CONTENT_TYPE_ALERT, { ptls_buffer_push(sendbuf, level, description); });
    /* encrypt the alert if we have the encryption keys, unless when it is the early data key */
    if (tls->traffic_protection.enc.aead != NULL && !(tls->state <= PTLS_STATE_CLIENT_EXPECT_FINISHED)) {
        if ((ret = buffer_encrypt_record(sendbuf, rec_start, &tls->traffic_protection.enc)) != 0)
            goto Exit;
    }

Exit:
    return ret;
}

int ptls_export_secret(ptls_t *tls, void *output, size_t outlen, const char *label, ptls_iovec_t context_value, int is_early)
{
    ptls_hash_algorithm_t *algo = tls->key_schedule->hashes[0].algo;
    uint8_t *master_secret = is_early ? tls->exporter_master_secret.early : tls->exporter_master_secret.one_rtt,
            derived_secret[PTLS_MAX_DIGEST_SIZE], context_value_hash[PTLS_MAX_DIGEST_SIZE];
    int ret;

    if (master_secret == NULL) {
        if (is_early) {
            switch (tls->state) {
            case PTLS_STATE_CLIENT_HANDSHAKE_START:
            case PTLS_STATE_SERVER_EXPECT_CLIENT_HELLO:
                ret = PTLS_ERROR_IN_PROGRESS;
                break;
            default:
                ret = PTLS_ERROR_NOT_AVAILABLE;
                break;
            }
        } else {
            ret = PTLS_ERROR_IN_PROGRESS;
        }
        return ret;
    }

    if ((ret = ptls_calc_hash(algo, context_value_hash, context_value.base, context_value.len)) != 0)
        return ret;

    if ((ret = hkdf_expand_label(algo, derived_secret, algo->digest_size, ptls_iovec_init(master_secret, algo->digest_size), label,
                                 ptls_iovec_init(algo->empty_digest, algo->digest_size), tls->key_schedule->hkdf_label_prefix)) !=
        0)
        goto Exit;
    ret = hkdf_expand_label(algo, output, outlen, ptls_iovec_init(derived_secret, algo->digest_size), "exporter",
                            ptls_iovec_init(context_value_hash, algo->digest_size), tls->key_schedule->hkdf_label_prefix);

Exit:
    ptls_clear_memory(derived_secret, sizeof(derived_secret));
    ptls_clear_memory(context_value_hash, sizeof(context_value_hash));
    return ret;
}

struct st_picotls_hmac_context_t {
    ptls_hash_context_t super;
    ptls_hash_algorithm_t *algo;
    ptls_hash_context_t *hash;
    uint8_t key[1];
};

static void hmac_update(ptls_hash_context_t *_ctx, const void *src, size_t len)
{
    struct st_picotls_hmac_context_t *ctx = (struct st_picotls_hmac_context_t *)_ctx;
    ctx->hash->update(ctx->hash, src, len);
}

static void hmac_apply_key(struct st_picotls_hmac_context_t *ctx, uint8_t pad)
{
    size_t i;

    for (i = 0; i != ctx->algo->block_size; ++i)
        ctx->key[i] ^= pad;
    ctx->hash->update(ctx->hash, ctx->key, ctx->algo->block_size);
    for (i = 0; i != ctx->algo->block_size; ++i)
        ctx->key[i] ^= pad;
}

static void hmac_final(ptls_hash_context_t *_ctx, void *md, ptls_hash_final_mode_t mode)
{
    struct st_picotls_hmac_context_t *ctx = (struct st_picotls_hmac_context_t *)_ctx;

    assert(mode != PTLS_HASH_FINAL_MODE_SNAPSHOT || !"not supported");

    if (md != NULL) {
        ctx->hash->final(ctx->hash, md, PTLS_HASH_FINAL_MODE_RESET);
        hmac_apply_key(ctx, 0x5c);
        ctx->hash->update(ctx->hash, md, ctx->algo->digest_size);
    }
    ctx->hash->final(ctx->hash, md, mode);

    switch (mode) {
    case PTLS_HASH_FINAL_MODE_FREE:
        ptls_clear_memory(ctx->key, ctx->algo->block_size);
        free(ctx);
        break;
    case PTLS_HASH_FINAL_MODE_RESET:
        hmac_apply_key(ctx, 0x36);
        break;
    default:
        assert(!"FIXME");
        break;
    }
}

int ptls_calc_hash(ptls_hash_algorithm_t *algo, void *output, const void *src, size_t len)
{
    ptls_hash_context_t *ctx;

    if ((ctx = algo->create()) == NULL)
        return PTLS_ERROR_NO_MEMORY;
    ctx->update(ctx, src, len);
    ctx->final(ctx, output, PTLS_HASH_FINAL_MODE_FREE);
    return 0;
}

ptls_hash_context_t *ptls_hmac_create(ptls_hash_algorithm_t *algo, const void *key, size_t key_size)
{
    struct st_picotls_hmac_context_t *ctx;

    assert(key_size <= algo->block_size);

    if ((ctx = malloc(offsetof(struct st_picotls_hmac_context_t, key) + algo->block_size)) == NULL)
        return NULL;

    *ctx = (struct st_picotls_hmac_context_t){{hmac_update, hmac_final}, algo};
    if ((ctx->hash = algo->create()) == NULL) {
        free(ctx);
        return NULL;
    }
    memset(ctx->key, 0, algo->block_size);
    memcpy(ctx->key, key, key_size);

    hmac_apply_key(ctx, 0x36);

    return &ctx->super;
}

int ptls_hkdf_extract(ptls_hash_algorithm_t *algo, void *output, ptls_iovec_t salt, ptls_iovec_t ikm)
{
    ptls_hash_context_t *hash;

    if (salt.len == 0)
        salt = ptls_iovec_init(zeroes_of_max_digest_size, algo->digest_size);

    if ((hash = ptls_hmac_create(algo, salt.base, salt.len)) == NULL)
        return PTLS_ERROR_NO_MEMORY;
    hash->update(hash, ikm.base, ikm.len);
    hash->final(hash, output, PTLS_HASH_FINAL_MODE_FREE);
    return 0;
}

int ptls_hkdf_expand(ptls_hash_algorithm_t *algo, void *output, size_t outlen, ptls_iovec_t prk, ptls_iovec_t info)
{
    ptls_hash_context_t *hmac = NULL;
    size_t i;
    uint8_t digest[PTLS_MAX_DIGEST_SIZE];

    for (i = 0; (i * algo->digest_size) < outlen; ++i) {
        if (hmac == NULL) {
            if ((hmac = ptls_hmac_create(algo, prk.base, prk.len)) == NULL)
                return PTLS_ERROR_NO_MEMORY;
        } else {
            hmac->update(hmac, digest, algo->digest_size);
        }
        hmac->update(hmac, info.base, info.len);
        uint8_t gen = (uint8_t)(i + 1);
        hmac->update(hmac, &gen, 1);
        hmac->final(hmac, digest, 1);

        size_t off_start = i * algo->digest_size, off_end = off_start + algo->digest_size;
        if (off_end > outlen)
            off_end = outlen;
        memcpy((uint8_t *)output + off_start, digest, off_end - off_start);
    }

    if (hmac != NULL)
        hmac->final(hmac, NULL, PTLS_HASH_FINAL_MODE_FREE);

    ptls_clear_memory(digest, algo->digest_size);

    return 0;
}

int hkdf_expand_label(ptls_hash_algorithm_t *algo, void *output, size_t outlen, ptls_iovec_t secret, const char *label,
                      ptls_iovec_t hash_value, const char *label_prefix)
{
    ptls_buffer_t hkdf_label;
    uint8_t hkdf_label_buf[80];
    int ret;

    assert(label_prefix != NULL);

    ptls_buffer_init(&hkdf_label, hkdf_label_buf, sizeof(hkdf_label_buf));

    ptls_buffer_push16(&hkdf_label, (uint16_t)outlen);
    ptls_buffer_push_block(&hkdf_label, 1, {
        ptls_buffer_pushv(&hkdf_label, label_prefix, strlen(label_prefix));
        ptls_buffer_pushv(&hkdf_label, label, strlen(label));
    });
    ptls_buffer_push_block(&hkdf_label, 1, { ptls_buffer_pushv(&hkdf_label, hash_value.base, hash_value.len); });

    ret = ptls_hkdf_expand(algo, output, outlen, secret, ptls_iovec_init(hkdf_label.base, hkdf_label.off));

Exit:
    ptls_buffer_dispose(&hkdf_label);
    return ret;
}

int ptls_hkdf_expand_label(ptls_hash_algorithm_t *algo, void *output, size_t outlen, ptls_iovec_t secret, const char *label,
                           ptls_iovec_t hash_value, const char *label_prefix)
{
    /* the handshake layer should call hkdf_expand_label directly, always setting key_schedule->hkdf_label_prefix as the
     * argument */
    if (label_prefix == NULL)
        label_prefix = PTLS_HKDF_EXPAND_LABEL_PREFIX;
    return hkdf_expand_label(algo, output, outlen, secret, label, hash_value, label_prefix);
}

ptls_cipher_context_t *ptls_cipher_new(ptls_cipher_algorithm_t *algo, int is_enc, const void *key)
{
    ptls_cipher_context_t *ctx;

    if ((ctx = (ptls_cipher_context_t *)malloc(algo->context_size)) == NULL)
        return NULL;
    *ctx = (ptls_cipher_context_t){algo};
    if (algo->setup_crypto(ctx, is_enc, key) != 0) {
        free(ctx);
        ctx = NULL;
    }
    return ctx;
}

void ptls_cipher_free(ptls_cipher_context_t *ctx)
{
    ctx->do_dispose(ctx);
    free(ctx);
}

ptls_aead_context_t *new_aead(ptls_aead_algorithm_t *aead, ptls_hash_algorithm_t *hash, int is_enc, const void *secret,
                              ptls_iovec_t hash_value, const char *label_prefix)
{
    ptls_aead_context_t *ctx = NULL;
    uint8_t key_iv[PTLS_MAX_SECRET_SIZE + PTLS_MAX_IV_SIZE];
    int ret;

    if ((ret = get_traffic_key(hash, key_iv, aead->key_size, 0, secret, hash_value, label_prefix)) != 0)
        goto Exit;
    if ((ret = get_traffic_key(hash, key_iv + aead->key_size, aead->iv_size, 1, secret, hash_value, label_prefix)) != 0)
        goto Exit;
    ctx = ptls_aead_new_direct(aead, is_enc, key_iv, key_iv + aead->key_size);

Exit:
    ptls_clear_memory(key_iv, sizeof(key_iv));
    return ctx;
}

ptls_aead_context_t *ptls_aead_new(ptls_aead_algorithm_t *aead, ptls_hash_algorithm_t *hash, int is_enc, const void *secret,
                                   const char *label_prefix)
{
    return new_aead(aead, hash, is_enc, secret, ptls_iovec_init(NULL, 0), label_prefix);
}

ptls_aead_context_t *ptls_aead_new_direct(ptls_aead_algorithm_t *aead, int is_enc, const void *key, const void *iv)
{
    ptls_aead_context_t *ctx;

    if ((ctx = (ptls_aead_context_t *)malloc(aead->context_size)) == NULL)
        return NULL;

    *ctx = (ptls_aead_context_t){aead};

    if (aead->setup_crypto(ctx, is_enc, key, iv) != 0) {
        free(ctx);
        return NULL;
    }

    return ctx;
}

void ptls_aead_free(ptls_aead_context_t *ctx)
{
    ctx->dispose_crypto(ctx);
    free(ctx);
}

void ptls_aead__build_iv(ptls_aead_algorithm_t *algo, uint8_t *iv, const uint8_t *static_iv, uint64_t seq)
{
    size_t iv_size = algo->iv_size, i;
    const uint8_t *s = static_iv;
    uint8_t *d = iv;

    /* build iv */
    for (i = iv_size - 8; i != 0; --i)
        *d++ = *s++;
    i = 64;
    do {
        i -= 8;
        *d++ = *s++ ^ (uint8_t)(seq >> i);
    } while (i != 0);
}

static void clear_memory(void *p, size_t len)
{
    if (len != 0)
        memset(p, 0, len);
}

void (*volatile ptls_clear_memory)(void *p, size_t len) = clear_memory;

static int mem_equal(const void *_x, const void *_y, size_t len)
{
    const volatile uint8_t *x = _x, *y = _y;
    uint8_t t = 0;

    for (; len != 0; --len)
        t |= *x++ ^ *y++;

    return t == 0;
}

int (*volatile ptls_mem_equal)(const void *x, const void *y, size_t len) = mem_equal;

static uint64_t get_time(ptls_get_time_t *self)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

ptls_get_time_t ptls_get_time = {get_time};
#if PICOTLS_USE_DTRACE
PTLS_THREADLOCAL unsigned ptls_default_skip_tracing = 0;
#endif

int ptls_is_server(ptls_t *tls)
{
    return tls->is_server;
}

struct st_ptls_raw_message_emitter_t {
    ptls_message_emitter_t super;
    size_t start_off;
    size_t *epoch_offsets;
};

static int begin_raw_message(ptls_message_emitter_t *_self)
{
    struct st_ptls_raw_message_emitter_t *self = (void *)_self;

    self->start_off = self->super.buf->off;
    return 0;
}

static int commit_raw_message(ptls_message_emitter_t *_self)
{
    struct st_ptls_raw_message_emitter_t *self = (void *)_self;
    size_t epoch;

    /* epoch is the key epoch, with the only exception being 2nd CH generated after 0-RTT key */
    epoch = self->super.enc->epoch;
    if (epoch == 1 && self->super.buf->base[self->start_off] == PTLS_HANDSHAKE_TYPE_CLIENT_HELLO)
        epoch = 0;

    for (++epoch; epoch < 5; ++epoch) {
        assert(self->epoch_offsets[epoch] == self->start_off);
        self->epoch_offsets[epoch] = self->super.buf->off;
    }

    self->start_off = SIZE_MAX;

    return 0;
}

size_t ptls_get_read_epoch(ptls_t *tls)
{
    switch (tls->state) {
    case PTLS_STATE_CLIENT_HANDSHAKE_START:
    case PTLS_STATE_CLIENT_EXPECT_SERVER_HELLO:
    case PTLS_STATE_CLIENT_EXPECT_SECOND_SERVER_HELLO:
    case PTLS_STATE_SERVER_EXPECT_CLIENT_HELLO:
    case PTLS_STATE_SERVER_EXPECT_SECOND_CLIENT_HELLO:
        return 0; /* plaintext */
    case PTLS_STATE_SERVER_EXPECT_END_OF_EARLY_DATA:
        assert(!tls->ctx->omit_end_of_early_data);
        return 1; /* 0-rtt */
    case PTLS_STATE_CLIENT_EXPECT_ENCRYPTED_EXTENSIONS:
    case PTLS_STATE_CLIENT_EXPECT_CERTIFICATE_REQUEST_OR_CERTIFICATE:
    case PTLS_STATE_CLIENT_EXPECT_CERTIFICATE:
    case PTLS_STATE_CLIENT_EXPECT_CERTIFICATE_VERIFY:
    case PTLS_STATE_CLIENT_EXPECT_FINISHED:
    case PTLS_STATE_SERVER_EXPECT_CERTIFICATE:
    case PTLS_STATE_SERVER_EXPECT_CERTIFICATE_VERIFY:
    case PTLS_STATE_SERVER_EXPECT_FINISHED:
        return 2; /* handshake */
    case PTLS_STATE_CLIENT_POST_HANDSHAKE:
    case PTLS_STATE_SERVER_POST_HANDSHAKE:
        return 3; /* 1-rtt */
    default:
        assert(!"invalid state");
        return SIZE_MAX;
    }
}

int ptls_handle_message(ptls_t *tls, ptls_buffer_t *sendbuf, size_t epoch_offsets[5], size_t in_epoch, const void *input,
                        size_t inlen, ptls_handshake_properties_t *properties)
{
    return tls->is_server ? ptls_server_handle_message(tls, sendbuf, epoch_offsets, in_epoch, input, inlen, properties)
                          : ptls_client_handle_message(tls, sendbuf, epoch_offsets, in_epoch, input, inlen, properties);
}

int ptls_client_handle_message(ptls_t *tls, ptls_buffer_t *sendbuf, size_t epoch_offsets[5], size_t in_epoch, const void *input,
                               size_t inlen, ptls_handshake_properties_t *properties)
{
    assert(!tls->is_server);

    struct st_ptls_raw_message_emitter_t emitter = {
        {sendbuf, &tls->traffic_protection.enc, 0, begin_raw_message, commit_raw_message}, SIZE_MAX, epoch_offsets};
    struct st_ptls_record_t rec = {PTLS_CONTENT_TYPE_HANDSHAKE, 0, inlen, input};

    if (input == NULL)
        return send_client_hello(tls, &emitter.super, properties, NULL);

    if (ptls_get_read_epoch(tls) != in_epoch)
        return PTLS_ALERT_UNEXPECTED_MESSAGE;

    return handle_handshake_record(tls, handle_client_handshake_message, &emitter.super, &rec, properties);
}

int ptls_server_handle_message(ptls_t *tls, ptls_buffer_t *sendbuf, size_t epoch_offsets[5], size_t in_epoch, const void *input,
                               size_t inlen, ptls_handshake_properties_t *properties)
{
    assert(tls->is_server);

    struct st_ptls_raw_message_emitter_t emitter = {
        {sendbuf, &tls->traffic_protection.enc, 0, begin_raw_message, commit_raw_message}, SIZE_MAX, epoch_offsets};
    struct st_ptls_record_t rec = {PTLS_CONTENT_TYPE_HANDSHAKE, 0, inlen, input};

    assert(input);

    if (ptls_get_read_epoch(tls) != in_epoch)
        return PTLS_ALERT_UNEXPECTED_MESSAGE;

    return handle_handshake_record(tls, handle_server_handshake_message, &emitter.super, &rec, properties);
}

int ptls_esni_init_context(ptls_context_t *ctx, ptls_esni_context_t *esni, ptls_iovec_t esni_keys,
                           ptls_key_exchange_context_t **key_exchanges)
{
    const uint8_t *src = esni_keys.base, *const end = src + esni_keys.len;
    size_t num_key_exchanges, num_cipher_suites = 0;
    int ret;

    for (num_key_exchanges = 0; key_exchanges[num_key_exchanges] != NULL; ++num_key_exchanges)
        ;

    memset(esni, 0, sizeof(*esni));
    if ((esni->key_exchanges = malloc(sizeof(*esni->key_exchanges) * (num_key_exchanges + 1))) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }
    memcpy(esni->key_exchanges, key_exchanges, sizeof(*esni->key_exchanges) * (num_key_exchanges + 1));

    /* ESNIKeys */
    if ((ret = ptls_decode16(&esni->version, &src, end)) != 0)
        goto Exit;
    /* Skip checksum fields */
    if (end - src < 4) {
        ret = PTLS_ALERT_DECRYPT_ERROR;
        goto Exit;
    }
    src += 4;
    /* Published SNI field */
    ptls_decode_open_block(src, end, 2, { src = end; });

    /* Process the list of KeyShareEntries, verify for each of them that the ciphersuite is supported. */
    ptls_decode_open_block(src, end, 2, {
        do {
            /* parse */
            uint16_t id;
            if ((ret = ptls_decode16(&id, &src, end)) != 0)
                goto Exit;
            ptls_decode_open_block(src, end, 2, { src = end; });
            /* check that matching key-share exists */
            ptls_key_exchange_context_t **found;
            for (found = key_exchanges; *found != NULL; ++found)
                if ((*found)->algo->id == id)
                    break;
            if (found == NULL) {
                ret = PTLS_ERROR_INCOMPATIBLE_KEY;
                goto Exit;
            }
        } while (src != end);
    });
    /* Process the list of cipher_suites. If they are supported, store in esni context  */
    ptls_decode_open_block(src, end, 2, {
        void *newp;
        do {
            uint16_t id;
            if ((ret = ptls_decode16(&id, &src, end)) != 0)
                goto Exit;
            size_t i;
            for (i = 0; ctx->cipher_suites[i] != NULL; ++i)
                if (ctx->cipher_suites[i]->id == id)
                    break;
            if (ctx->cipher_suites[i] != NULL) {
                if ((newp = realloc(esni->cipher_suites, sizeof(*esni->cipher_suites) * (num_cipher_suites + 1))) == NULL) {
                    ret = PTLS_ERROR_NO_MEMORY;
                    goto Exit;
                }
                esni->cipher_suites = newp;
                esni->cipher_suites[num_cipher_suites++].cipher_suite = ctx->cipher_suites[i];
            }
        } while (src != end);
        if ((newp = realloc(esni->cipher_suites, sizeof(*esni->cipher_suites) * (num_cipher_suites + 1))) == NULL) {
            ret = PTLS_ERROR_NO_MEMORY;
            goto Exit;
        }
        esni->cipher_suites = newp;
        esni->cipher_suites[num_cipher_suites].cipher_suite = NULL;
    });
    /* Parse the padded length, not before, not after parameters */
    if ((ret = ptls_decode16(&esni->padded_length, &src, end)) != 0)
        goto Exit;
    if ((ret = ptls_decode64(&esni->not_before, &src, end)) != 0)
        goto Exit;
    if ((ret = ptls_decode64(&esni->not_after, &src, end)) != 0)
        goto Exit;
    /* Skip the extension fields */
    ptls_decode_block(src, end, 2, {
        while (src != end) {
            uint16_t ext_type;
            if ((ret = ptls_decode16(&ext_type, &src, end)) != 0)
                goto Exit;
            ptls_decode_open_block(src, end, 2, { src = end; });
        }
    });

    { /* calculate digests for every cipher-suite */
        size_t i;
        for (i = 0; esni->cipher_suites[i].cipher_suite != NULL; ++i) {
            if ((ret = ptls_calc_hash(esni->cipher_suites[i].cipher_suite->hash, esni->cipher_suites[i].record_digest,
                                      esni_keys.base, esni_keys.len)) != 0)
                goto Exit;
        }
    }

    ret = 0;
Exit:
    if (ret != 0)
        ptls_esni_dispose_context(esni);
    return ret;
}

void ptls_esni_dispose_context(ptls_esni_context_t *esni)
{
    size_t i;

    if (esni->key_exchanges != NULL) {
        for (i = 0; esni->key_exchanges[i] != NULL; ++i)
            esni->key_exchanges[i]->on_exchange(esni->key_exchanges + i, 1, NULL, ptls_iovec_init(NULL, 0));
        free(esni->key_exchanges);
    }
    free(esni->cipher_suites);
}

/**
 * Obtain the ESNI secrets negotiated during the handshake.
 */
ptls_esni_secret_t *ptls_get_esni_secret(ptls_t *ctx)
{
    return ctx->esni;
}

/**
 * checks if given name looks like an IP address
 */
int ptls_server_name_is_ipaddr(const char *name)
{
#ifdef AF_INET
    struct sockaddr_in sin;
    if (inet_pton(AF_INET, name, &sin) == 1)
        return 1;
#endif
#ifdef AF_INET6
    struct sockaddr_in6 sin6;
    if (inet_pton(AF_INET6, name, &sin6) == 1)
        return 1;
#endif
    return 0;
}

char *ptls_hexdump(char *buf, const void *_src, size_t len)
{
    char *dst = buf;
    const uint8_t *src = _src;
    size_t i;

    for (i = 0; i != len; ++i) {
        *dst++ = "0123456789abcdef"[src[i] >> 4];
        *dst++ = "0123456789abcdef"[src[i] & 0xf];
    }
    *dst++ = '\0';
    return buf;
}
