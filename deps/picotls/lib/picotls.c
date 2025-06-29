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
#ifdef _WINDOWS
#include "wincompat.h"
#endif
#include <assert.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef _WINDOWS
#include <errno.h>
#include <pthread.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#endif
#ifdef __linux__
#include <sys/syscall.h>
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
#define PTLS_EXTENSION_TYPE_SERVER_CERTIFICATE_TYPE 20
#define PTLS_EXTENSION_TYPE_COMPRESS_CERTIFICATE 27
#define PTLS_EXTENSION_TYPE_PRE_SHARED_KEY 41
#define PTLS_EXTENSION_TYPE_EARLY_DATA 42
#define PTLS_EXTENSION_TYPE_SUPPORTED_VERSIONS 43
#define PTLS_EXTENSION_TYPE_COOKIE 44
#define PTLS_EXTENSION_TYPE_PSK_KEY_EXCHANGE_MODES 45
#define PTLS_EXTENSION_TYPE_CERTIFICATE_AUTHORITIES 47
#define PTLS_EXTENSION_TYPE_KEY_SHARE 51
#define PTLS_EXTENSION_TYPE_TICKET_REQUEST 58
#define PTLS_EXTENSION_TYPE_ECH_OUTER_EXTENSIONS 0xfd00
#define PTLS_EXTENSION_TYPE_ENCRYPTED_CLIENT_HELLO 0xfe0d

#define PTLS_SERVER_NAME_TYPE_HOSTNAME 0

#define PTLS_ECH_CONFIG_VERSION 0xfe0d
#define PTLS_ECH_CLIENT_HELLO_TYPE_OUTER 0
#define PTLS_ECH_CLIENT_HELLO_TYPE_INNER 1

#define PTLS_ECH_CONFIRM_LENGTH 8

static const char ech_info_prefix[8] = "tls ech";

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
#define PTLS_PROBE0(LABEL, tls)                                                                                                    \
    do {                                                                                                                           \
        if (PTLS_UNLIKELY(PICOTLS_##LABEL##_ENABLED()))                                                                            \
            PICOTLS_##LABEL(tls);                                                                                                  \
    } while (0)
#define PTLS_PROBE(LABEL, tls, ...)                                                                                                \
    do {                                                                                                                           \
        if (PTLS_UNLIKELY(PICOTLS_##LABEL##_ENABLED()))                                                                            \
            PICOTLS_##LABEL((tls), __VA_ARGS__);                                                                                   \
    } while (0)
#else
#define PTLS_PROBE0(LABEL, tls)
#define PTLS_PROBE(LABEL, tls, ...)
#endif

/**
 * list of supported versions in the preferred order
 */
static const uint16_t supported_versions[] = {PTLS_PROTOCOL_VERSION_TLS13};

static const uint8_t hello_retry_random[PTLS_HELLO_RANDOM_SIZE] = {0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C,
                                                                   0x02, 0x1E, 0x65, 0xB8, 0x91, 0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB,
                                                                   0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C};

struct st_ptls_traffic_protection_t {
    uint8_t secret[PTLS_MAX_DIGEST_SIZE];
    size_t epoch;
    /* the following fields are not used if the key_change callback is set */
    ptls_aead_context_t *aead;
    uint64_t seq;
    unsigned tls12 : 1;
    uint64_t tls12_enc_record_iv;
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

struct st_decoded_ech_config_t {
    uint8_t id;
    ptls_hpke_kem_t *kem;
    ptls_iovec_t public_key;
    ptls_hpke_cipher_suite_t *cipher;
    uint8_t max_name_length;
    ptls_iovec_t public_name;
    ptls_iovec_t bytes;
};

/**
 * Properties for ECH. Iff ECH is used and not rejected, `aead` is non-NULL.
 */
struct st_ptls_ech_t {
    uint8_t offered : 1;
    uint8_t offered_grease : 1;
    uint8_t accepted : 1;
    uint8_t config_id;
    ptls_hpke_kem_t *kem;
    ptls_hpke_cipher_suite_t *cipher;
    ptls_aead_context_t *aead;
    uint8_t inner_client_random[PTLS_HELLO_RANDOM_SIZE];
    struct {
        ptls_iovec_t enc;
        uint8_t max_name_length;
        char *public_name;
        /**
         * retains a copy of entire ECH extension so that it can be replayed in the 2nd CH when ECH is rejected via HRR
         */
        ptls_iovec_t first_ech;
    } client;
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
        PTLS_STATE_SERVER_GENERATING_CERTIFICATE_VERIFY,
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
     * ClientHello.random that appears on the wire. When ECH is used, that of inner CH is retained separately.
     */
    uint8_t client_random[PTLS_HELLO_RANDOM_SIZE];
    /**
     * exporter master secret (either 0rtt or 1rtt)
     */
    struct {
        uint8_t *early;
        uint8_t *one_rtt;
    } exporter_master_secret;
    /**
     * ECH
     */
    struct st_ptls_ech_t ech;
    /* flags */
    unsigned is_server : 1;
    unsigned is_psk_handshake : 1;
    unsigned send_change_cipher_spec : 1;
    unsigned needs_key_update : 1;
    unsigned key_update_send_request : 1;
#if PTLS_HAVE_LOG
    /**
     * see ptls_log
     */
    ptls_log_conn_state_t log_state;
#endif
    struct {
        uint32_t active_conns;
        uint32_t generation;
    } log_sni;
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
            uint8_t num_tickets_to_send;
            ptls_async_job_t *async_job;
        } server;
    };
    /**
     * certificate verify; will be used by the client and the server (if require_client_authentication is set)
     */
    struct {
        int (*cb)(void *verify_ctx, uint16_t algo, ptls_iovec_t data, ptls_iovec_t signature);
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

#define MAX_UNKNOWN_EXTENSIONS 16
#define MAX_CERTIFICATE_TYPES 8

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
        ptls_iovec_t list[16];
        size_t count;
    } alpn;
    struct {
        uint16_t list[16];
        size_t count;
    } cert_compression_algos;
    struct {
        ptls_iovec_t all;
        ptls_iovec_t tbs;
        ptls_iovec_t ch1_hash;
        ptls_iovec_t signature;
        unsigned sent_key_share : 1;
    } cookie;
    struct {
        uint8_t list[MAX_CERTIFICATE_TYPES];
        size_t count;
    } server_certificate_types;
    unsigned status_request : 1;
    struct {
        uint8_t new_session_count;
        uint8_t resumption_count;
    } ticket_request;
    /**
     * ECH: payload.base != NULL indicates that the extension was received
     */
    struct {
        uint8_t type;
        uint8_t config_id;
        ptls_hpke_cipher_suite_id_t cipher_suite;
        ptls_iovec_t enc;
        ptls_iovec_t payload;
    } ech;
    struct {
        const uint8_t *hash_end;
        struct {
            ptls_client_hello_psk_identity_t list[4];
            size_t count;
        } identities;
        unsigned ke_modes;
        unsigned early_data_indication : 1;
        unsigned is_last_extension : 1;
    } psk;
    ptls_raw_extension_t unknown_extensions[MAX_UNKNOWN_EXTENSIONS + 1];
    size_t first_extension_at;
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
            const uint8_t *ech;
        } retry_request;
    };
};

struct st_ptls_key_schedule_t {
    unsigned generation; /* early secret (1), hanshake secret (2), master secret (3) */
    uint8_t secret[PTLS_MAX_DIGEST_SIZE];
    size_t num_hashes;
    struct {
        ptls_hash_algorithm_t *algo;
        ptls_hash_context_t *ctx, *ctx_outer;
    } hashes[1];
};

struct st_ptls_extension_decoder_t {
    uint16_t type;
    int (*cb)(ptls_t *tls, void *arg, const uint8_t *src, const uint8_t *const end);
};

struct st_ptls_extension_bitmap_t {
    uint64_t bits;
};

static const uint8_t zeroes_of_max_digest_size[PTLS_MAX_DIGEST_SIZE] = {0};

static ptls_aead_context_t *new_aead(ptls_aead_algorithm_t *aead, ptls_hash_algorithm_t *hash, int is_enc, const void *secret,
                                     ptls_iovec_t hash_value, const char *label_prefix);
static int server_finish_handshake(ptls_t *tls, ptls_message_emitter_t *emitter, int send_cert_verify,
                                   struct st_ptls_signature_algorithms_t *signature_algorithms);

static int is_supported_version(uint16_t v)
{
    size_t i;
    for (i = 0; i != PTLS_ELEMENTSOF(supported_versions); ++i)
        if (supported_versions[i] == v)
            return 1;
    return 0;
}

static int extension_bitmap_testandset(struct st_ptls_extension_bitmap_t *bitmap, int hstype, uint16_t extid)
{
#define HSTYPE_TO_BIT(hstype) ((uint64_t)1 << ((hstype) + 1)) /* min(hstype) is -1 (PSEUDO_HRR) */
#define DEFINE_BIT(abbrev, hstype) static const uint64_t abbrev = HSTYPE_TO_BIT(PTLS_HANDSHAKE_TYPE_##hstype)
#define EXT(candext, allowed_bits)                                                                                                 \
    do {                                                                                                                           \
        if (PTLS_UNLIKELY(extid == PTLS_EXTENSION_TYPE_##candext)) {                                                               \
            allowed_hs_bits = allowed_bits;                                                                                        \
            goto Found;                                                                                                            \
        }                                                                                                                          \
        ext_bitmap_mask <<= 1;                                                                                                     \
    } while (0)

    DEFINE_BIT(CH, CLIENT_HELLO);
    DEFINE_BIT(SH, SERVER_HELLO);
    DEFINE_BIT(HRR, PSEUDO_HRR);
    DEFINE_BIT(EE, ENCRYPTED_EXTENSIONS);
    DEFINE_BIT(CR, CERTIFICATE_REQUEST);
    DEFINE_BIT(CT, CERTIFICATE);
    DEFINE_BIT(NST, NEW_SESSION_TICKET);

    uint64_t allowed_hs_bits, ext_bitmap_mask = 1;

    /* clang-format off */
    /* RFC 8446 section 4.2: "The table below indicates the messages where a given extension may appear... If an implementation
     * receives an extension which it recognizes and which is not specified for the message in which it appears, it MUST abort the
     * handshake with an "illegal_parameter" alert.
     *
     * +-------------------------+---------------+
     * +        Extension        |    Allowed    |
     * +-------------------------+---------------+ */
    EXT( SERVER_NAME             , CH + EE       );
    EXT( STATUS_REQUEST          , CH + CR + CT  );
    EXT( SUPPORTED_GROUPS        , CH + EE       );
    EXT( SIGNATURE_ALGORITHMS    , CH + CR       );
    EXT( ALPN                    , CH + EE       );
    EXT( SERVER_CERTIFICATE_TYPE , CH + EE       );
    EXT( KEY_SHARE               , CH + SH + HRR );
    EXT( PRE_SHARED_KEY          , CH + SH       );
    EXT( PSK_KEY_EXCHANGE_MODES  , CH            );
    EXT( EARLY_DATA              , CH + EE + NST );
    EXT( COOKIE                  , CH + HRR      );
    EXT( SUPPORTED_VERSIONS      , CH + SH + HRR );
    EXT( COMPRESS_CERTIFICATE    , CH + CR       ); /* from RFC 8879 */
    EXT( ENCRYPTED_CLIENT_HELLO  , CH + HRR + EE ); /* from draft-ietf-tls-esni-15 */
    EXT( ECH_OUTER_EXTENSIONS    , 0             );
    /* +-----------------------------------------+ */
    /* clang-format on */

    return 1;

Found:
    if ((allowed_hs_bits & HSTYPE_TO_BIT(hstype)) == 0)
        return 0;
    if ((bitmap->bits & ext_bitmap_mask) != 0)
        return 0;
    bitmap->bits |= ext_bitmap_mask;
    return 1;

#undef HSTYPE_TO_BIT
#undef DEFINE_ABBREV
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

static void encode64(uint8_t *dst, uint64_t v)
{
    for (size_t i = 0; i < 8; ++i)
        dst[i] = (uint8_t)(v >> (56 - 8 * i));
}

static char *duplicate_as_str(const void *src, size_t len)
{
    char *dst;

    if ((dst = malloc(len + 1)) == NULL)
        return NULL;
    memcpy(dst, src, len);
    dst[len] = '\0';
    return dst;
}

void ptls_buffer__release_memory(ptls_buffer_t *buf)
{
    ptls_clear_memory(buf->base, buf->off);
    if (buf->is_allocated) {
#ifdef _WINDOWS
        if (buf->align_bits != 0) {
            _aligned_free(buf->base);
        } else {
            free(buf->base);
        }
#else
        free(buf->base);
#endif
    }
}

int ptls_buffer_reserve(ptls_buffer_t *buf, size_t delta)
{
    return ptls_buffer_reserve_aligned(buf, delta, 0);
}

int ptls_buffer_reserve_aligned(ptls_buffer_t *buf, size_t delta, uint8_t align_bits)
{
    if (buf->base == NULL)
        return PTLS_ERROR_NO_MEMORY;

    if (PTLS_MEMORY_DEBUG || buf->capacity < buf->off + delta ||
        (buf->align_bits < align_bits && ((uintptr_t)buf->base & (((uintptr_t)1 << align_bits) - 1)) != 0)) {
        void *newp;
        size_t new_capacity = buf->capacity;
        if (new_capacity < 1024)
            new_capacity = 1024;
        while (new_capacity < buf->off + delta) {
            new_capacity *= 2;
        }
        if (align_bits != 0) {
#ifdef _WINDOWS
            if ((newp = _aligned_malloc(new_capacity, (size_t)1 << align_bits)) == NULL)
                return PTLS_ERROR_NO_MEMORY;
#else
            if (posix_memalign(&newp, 1 << align_bits, new_capacity) != 0)
                return PTLS_ERROR_NO_MEMORY;
#endif
        } else {
            if ((newp = malloc(new_capacity)) == NULL)
                return PTLS_ERROR_NO_MEMORY;
        }
        memcpy(newp, buf->base, buf->off);
        ptls_buffer__release_memory(buf);
        buf->base = newp;
        buf->capacity = new_capacity;
        buf->is_allocated = 1;
        buf->align_bits = align_bits;
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
    ptls_iovec_t invec[2] = {ptls_iovec_init(input, inlen), ptls_iovec_init(&content_type, 1)};
    uint8_t aad[5];

    build_aad(aad, inlen + 1 + ctx->aead->algo->tag_size);
    ptls_aead_encrypt_v(ctx->aead, output, invec, PTLS_ELEMENTSOF(invec), ctx->seq++, aad, sizeof(aad));

    return inlen + 1 + ctx->aead->algo->tag_size;
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

static void build_tls12_aad(uint8_t *aad, uint8_t type, uint64_t seq, uint16_t length)
{
    for (size_t i = 0; i < 8; ++i)
        aad[i] = (uint8_t)(seq >> (56 - i * 8));
    aad[8] = type;
    aad[9] = PTLS_RECORD_VERSION_MAJOR;
    aad[10] = PTLS_RECORD_VERSION_MINOR;
    aad[11] = length >> 8;
    aad[12] = (uint8_t)length;
}

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
        if (enc->tls12) {
            buffer_push_record(buf, type, {
                /* reserve memory */
                if ((ret = ptls_buffer_reserve_aligned(
                         buf, enc->aead->algo->tls12.record_iv_size + chunk_size + enc->aead->algo->tag_size,
                         enc->aead->algo->align_bits)) != 0)
                    goto Exit;
                /* determine nonce, as well as prepending that walue as the record IV (AES-GCM) */
                uint64_t nonce;
                if (enc->aead->algo->tls12.record_iv_size != 0) {
                    assert(enc->aead->algo->tls12.record_iv_size == 8);
                    nonce = enc->tls12_enc_record_iv++;
                    encode64(buf->base + buf->off, nonce);
                    buf->off += 8;
                } else {
                    nonce = enc->seq;
                }
                /* build AAD */
                uint8_t aad[PTLS_TLS12_AAD_SIZE];
                build_tls12_aad(aad, type, enc->seq, (uint16_t)chunk_size);
                /* encrypt */
                buf->off += ptls_aead_encrypt(enc->aead, buf->base + buf->off, src, chunk_size, nonce, aad, sizeof(aad));
                ++enc->seq;
            });
        } else {
            buffer_push_record(buf, PTLS_CONTENT_TYPE_APPDATA, {
                if ((ret = ptls_buffer_reserve_aligned(buf, chunk_size + enc->aead->algo->tag_size + 1,
                                                       enc->aead->algo->align_bits)) != 0)
                    goto Exit;
                buf->off += aead_encrypt(enc, buf->base + buf->off, src, chunk_size, type);
            });
        }
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

    /* Fast path: do in-place encryption if only one record needs to be emitted. (For simplicity, do not take this path if TLS 1.2
     * is used, as this function will be called no more than once per connection, for encrypting an alert.) */
    if (!enc->tls12 && bodylen <= PTLS_MAX_PLAINTEXT_RECORD_SIZE) {
        size_t overhead = 1 + enc->aead->algo->tag_size;
        if ((ret = ptls_buffer_reserve_aligned(buf, overhead, enc->aead->algo->align_bits)) != 0)
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
        struct st_ptls_extension_bitmap_t bitmap = {0};                                                                            \
        ptls_decode_open_block((src), end, 2, {                                                                                    \
            while ((src) != end) {                                                                                                 \
                if ((ret = ptls_decode16((exttype), &(src), end)) != 0)                                                            \
                    goto Exit;                                                                                                     \
                if (!extension_bitmap_testandset(&bitmap, (hstype), *(exttype))) {                                                 \
                    ret = PTLS_ALERT_ILLEGAL_PARAMETER;                                                                            \
                    goto Exit;                                                                                                     \
                }                                                                                                                  \
                ptls_decode_open_block((src), end, 2, block);                                                                      \
            }                                                                                                                      \
        });                                                                                                                        \
    } while (0)

#define decode_extensions(src, end, hstype, exttype, block)                                                                        \
    do {                                                                                                                           \
        decode_open_extensions((src), end, hstype, exttype, block);                                                                \
        ptls_decode_assert_block_close((src), end);                                                                                \
    } while (0)

int ptls_decode8(uint8_t *value, const uint8_t **src, const uint8_t *end)
{
    if (*src == end)
        return PTLS_ALERT_DECODE_ERROR;
    *value = *(*src)++;
    return 0;
}

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
    PTLS_LOG_CONN(new_secret, tls, { PTLS_LOG_ELEMENT_SAFESTR(label, type); });

    if (tls->ctx->log_event != NULL)
        tls->ctx->log_event->cb(tls->ctx->log_event, tls, type, "%s", ptls_hexdump(hexbuf, secret.base, secret.len));
}

/**
 * This function preserves the flags and  modes (e.g., `offered`, `accepted`, `cipher`), they can be used afterwards.
 */
static void clear_ech(struct st_ptls_ech_t *ech, int is_server)
{
    if (ech->aead != NULL) {
        ptls_aead_free(ech->aead);
        ech->aead = NULL;
    }
    ptls_clear_memory(ech->inner_client_random, PTLS_HELLO_RANDOM_SIZE);
    if (!is_server) {
        free(ech->client.enc.base);
        ech->client.enc = ptls_iovec_init(NULL, 0);
        if (ech->client.public_name != NULL) {
            free(ech->client.public_name);
            ech->client.public_name = NULL;
        }
        free(ech->client.first_ech.base);
        ech->client.first_ech = ptls_iovec_init(NULL, 0);
    }
}

/**
 * Decodes one ECHConfigContents (tls-esni-15 section 4). `decoded->kem` and `cipher` may be NULL even when the function returns
 * zero, if the corresponding entries are not found.
 */
static int decode_one_ech_config(ptls_hpke_kem_t **kems, ptls_hpke_cipher_suite_t **ciphers,
                                 struct st_decoded_ech_config_t *decoded, const uint8_t **src, const uint8_t *const end)
{
    char *public_name_buf = NULL;
    int ret;

    *decoded = (struct st_decoded_ech_config_t){0};

    if ((ret = ptls_decode8(&decoded->id, src, end)) != 0)
        goto Exit;
    uint16_t kem_id;
    if ((ret = ptls_decode16(&kem_id, src, end)) != 0)
        goto Exit;
    for (size_t i = 0; kems[i] != NULL; ++i) {
        if (kems[i]->id == kem_id) {
            decoded->kem = kems[i];
            break;
        }
    }
    ptls_decode_open_block(*src, end, 2, {
        if (*src == end) {
            ret = PTLS_ALERT_DECODE_ERROR;
            goto Exit;
        }
        decoded->public_key = ptls_iovec_init(*src, end - *src);
        *src = end;
    });
    ptls_decode_open_block(*src, end, 2, {
        do {
            uint16_t kdf_id;
            uint16_t aead_id;
            if ((ret = ptls_decode16(&kdf_id, src, end)) != 0)
                goto Exit;
            if ((ret = ptls_decode16(&aead_id, src, end)) != 0)
                goto Exit;
            if (decoded->cipher == NULL) {
                for (size_t i = 0; ciphers[i] != NULL; ++i) {
                    if (ciphers[i]->id.kdf == kdf_id && ciphers[i]->id.aead == aead_id) {
                        decoded->cipher = ciphers[i];
                        break;
                    }
                }
            }
        } while (*src != end);
    });
    if ((ret = ptls_decode8(&decoded->max_name_length, src, end)) != 0)
        goto Exit;

#define SKIP_DECODED()                                                                                                             \
    do {                                                                                                                           \
        decoded->kem = NULL;                                                                                                       \
        decoded->cipher = NULL;                                                                                                    \
    } while (0)

    /* Decode public_name. The specification requires clients to ignore (upon parsing ESNIConfigList) or reject (upon handshake)
     * public names that are not DNS names or IPv4 addresses. We ignore IPv4 and v6 addresses during parsing (IPv6 addresses never
     * looks like DNS names), and delegate the responsibility of rejecting non-DNS names to the certificate verify callback. */
    ptls_decode_open_block(*src, end, 1, {
        if (*src == end) {
            ret = PTLS_ALERT_DECODE_ERROR;
            goto Exit;
        }
        if ((public_name_buf = duplicate_as_str(*src, end - *src)) == NULL) {
            ret = PTLS_ERROR_NO_MEMORY;
            goto Exit;
        }
        if (ptls_server_name_is_ipaddr(public_name_buf)) {
            SKIP_DECODED();
        } else {
            decoded->public_name = ptls_iovec_init(*src, end - *src);
        }
        *src = end;
    });

    ptls_decode_block(*src, end, 2, {
        while (*src < end) {
            uint16_t type;
            if ((ret = ptls_decode16(&type, src, end)) != 0)
                goto Exit;
            ptls_decode_open_block(*src, end, 2, { *src = end; });
            /* if a critital extension is found, indicate that the config cannot be used */
            if ((type & 0x8000) != 0)
                SKIP_DECODED();
        }
    });

#undef SKIP_DECODED

Exit:
    free(public_name_buf);
    return ret;
}

static int client_decode_ech_config_list(ptls_context_t *ctx, struct st_decoded_ech_config_t *decoded, ptls_iovec_t config_list)
{
    const uint8_t *src = config_list.base, *const end = src + config_list.len;
    int match_found = 0, ret;

    *decoded = (struct st_decoded_ech_config_t){0};

    ptls_decode_block(src, end, 2, {
        do {
            const uint8_t *config_start = src;
            uint16_t version;
            if ((ret = ptls_decode16(&version, &src, end)) != 0)
                goto Exit;
            ptls_decode_open_block(src, end, 2, {
                /* If the block is the one that we recognize, parse it, then adopt if if possible. Otherwise, skip. */
                if (version == PTLS_ECH_CONFIG_VERSION) {
                    struct st_decoded_ech_config_t thisconf;
                    if ((ret = decode_one_ech_config(ctx->ech.client.kems, ctx->ech.client.ciphers, &thisconf, &src, end)) != 0)
                        goto Exit;
                    if (!match_found && thisconf.kem != NULL && thisconf.cipher != NULL) {
                        *decoded = thisconf;
                        decoded->bytes = ptls_iovec_init(config_start, end - config_start);
                        match_found = 1;
                    }
                } else {
                    src = end;
                }
            });
        } while (src != end);
    });
    ret = 0;

Exit:
    if (ret != 0)
        *decoded = (struct st_decoded_ech_config_t){0};
    return ret;
}

static int client_setup_ech(struct st_ptls_ech_t *ech, struct st_decoded_ech_config_t *decoded,
                            void (*random_bytes)(void *, size_t))
{
    ptls_buffer_t infobuf;
    uint8_t infobuf_smallbuf[256];
    int ret;

    /* setup `enc` and `aead` by running HPKE */
    ptls_buffer_init(&infobuf, infobuf_smallbuf, sizeof(infobuf_smallbuf));
    ptls_buffer_pushv(&infobuf, ech_info_prefix, sizeof(ech_info_prefix));
    ptls_buffer_pushv(&infobuf, decoded->bytes.base, decoded->bytes.len);
    if ((ret = ptls_hpke_setup_base_s(decoded->kem, decoded->cipher, &ech->client.enc, &ech->aead, decoded->public_key,
                                      ptls_iovec_init(infobuf.base, infobuf.off))) != 0)
        goto Exit;

    /* setup the rest */
    ech->config_id = decoded->id;
    ech->kem = decoded->kem;
    ech->cipher = decoded->cipher;
    random_bytes(ech->inner_client_random, PTLS_HELLO_RANDOM_SIZE);
    ech->client.max_name_length = decoded->max_name_length;
    if ((ech->client.public_name = duplicate_as_str(decoded->public_name.base, decoded->public_name.len)) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }

Exit:
    if (ret != 0)
        clear_ech(ech, 0);
    return ret;
}

static void client_setup_ech_grease(struct st_ptls_ech_t *ech, void (*random_bytes)(void *, size_t), ptls_hpke_kem_t **kems,
                                    ptls_hpke_cipher_suite_t **ciphers, const char *sni_name)
{
    static const size_t x25519_key_size = 32;
    uint8_t random_secret[PTLS_AES128_KEY_SIZE + PTLS_AES_IV_SIZE];

    /* pick up X25519, AES-128-GCM or bail out */
    for (size_t i = 0; kems[i] != NULL; ++i) {
        if (kems[i]->id == PTLS_HPKE_KEM_X25519_SHA256) {
            ech->kem = kems[i];
            break;
        }
    }
    for (size_t i = 0; ciphers[i] != NULL; ++i) {
        if (ciphers[i]->id.kdf == PTLS_HPKE_HKDF_SHA256 && ciphers[i]->id.aead == PTLS_HPKE_AEAD_AES_128_GCM) {
            ech->cipher = ciphers[i];
            break;
        }
    }
    if (ech->kem == NULL || ech->cipher == NULL)
        goto Fail;

    /* aead is generated from random */
    random_bytes(random_secret, sizeof(random_secret));
    ech->aead = ptls_aead_new_direct(ech->cipher->aead, 1, random_secret, random_secret + PTLS_AES128_KEY_SIZE);

    /* `enc` is random bytes */
    if ((ech->client.enc.base = malloc(x25519_key_size)) == NULL)
        goto Fail;
    ech->client.enc.len = x25519_key_size;
    random_bytes(ech->client.enc.base, ech->client.enc.len);

    /* setup the rest (inner_client_random is left zeros) */
    random_bytes(&ech->config_id, sizeof(ech->config_id));
    ech->client.max_name_length = 64;
    if ((ech->client.public_name = duplicate_as_str(sni_name, strlen(sni_name))) == NULL)
        goto Fail;

    return;

Fail:
    clear_ech(ech, 0);
}

#define ECH_CONFIRMATION_SERVER_HELLO "ech accept confirmation"
#define ECH_CONFIRMATION_HRR "hrr ech accept confirmation"
static int ech_calc_confirmation(ptls_key_schedule_t *sched, void *dst, const uint8_t *inner_random, const char *label,
                                 ptls_iovec_t message)
{
    ptls_hash_context_t *hash = NULL;
    uint8_t secret[PTLS_MAX_DIGEST_SIZE], transcript_hash[PTLS_MAX_DIGEST_SIZE];
    int ret;

    /* calc transcript hash using the modified ServerHello / HRR */
    if ((hash = sched->hashes[0].ctx->clone_(sched->hashes[0].ctx)) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }
    hash->update(hash, message.base, message.len);
    hash->final(hash, transcript_hash, PTLS_HASH_FINAL_MODE_FREE);
    hash = NULL;

    /* HKDF extract and expand */
    if ((ret = ptls_hkdf_extract(sched->hashes[0].algo, secret, ptls_iovec_init(NULL, 0),
                                 ptls_iovec_init(inner_random, PTLS_HELLO_RANDOM_SIZE))) != 0)
        goto Exit;
    if ((ret = ptls_hkdf_expand_label(sched->hashes[0].algo, dst, 8, ptls_iovec_init(secret, sched->hashes[0].algo->digest_size),
                                      label, ptls_iovec_init(transcript_hash, sched->hashes[0].algo->digest_size), NULL)) != 0)
        goto Exit;

Exit:
    ptls_clear_memory(secret, sizeof(secret));
    ptls_clear_memory(transcript_hash, sizeof(transcript_hash));
    if (hash != NULL)
        hash->final(hash, NULL, PTLS_HASH_FINAL_MODE_FREE);
    return ret;
}

static void key_schedule_free(ptls_key_schedule_t *sched)
{
    size_t i;
    ptls_clear_memory(sched->secret, sizeof(sched->secret));
    for (i = 0; i != sched->num_hashes; ++i) {
        sched->hashes[i].ctx->final(sched->hashes[i].ctx, NULL, PTLS_HASH_FINAL_MODE_FREE);
        if (sched->hashes[i].ctx_outer != NULL)
            sched->hashes[i].ctx_outer->final(sched->hashes[i].ctx_outer, NULL, PTLS_HASH_FINAL_MODE_FREE);
    }
    free(sched);
}

static ptls_key_schedule_t *key_schedule_new(ptls_cipher_suite_t *preferred, ptls_cipher_suite_t **offered, int use_outer)
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

    { /* allocate */
        size_t num_hashes = 0;
        FOREACH_HASH({ ++num_hashes; });
        if ((sched = malloc(offsetof(ptls_key_schedule_t, hashes) + sizeof(sched->hashes[0]) * num_hashes)) == NULL)
            return NULL;
        *sched = (ptls_key_schedule_t){0};
    }

    /* setup the hash algos and contexts */
    FOREACH_HASH({
        sched->hashes[sched->num_hashes].algo = cs->hash;
        if ((sched->hashes[sched->num_hashes].ctx = cs->hash->create()) == NULL)
            goto Fail;
        if (use_outer) {
            if ((sched->hashes[sched->num_hashes].ctx_outer = cs->hash->create()) == NULL)
                goto Fail;
        } else {
            sched->hashes[sched->num_hashes].ctx_outer = NULL;
        }
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
        (ret = ptls_hkdf_expand_label(sched->hashes[0].algo, sched->secret, sched->hashes[0].algo->digest_size,
                                      ptls_iovec_init(sched->secret, sched->hashes[0].algo->digest_size), "derived",
                                      ptls_iovec_init(sched->hashes[0].algo->empty_digest, sched->hashes[0].algo->digest_size),
                                      NULL)) != 0)
        return ret;

    ++sched->generation;
    ret = ptls_hkdf_extract(sched->hashes[0].algo, sched->secret,
                            ptls_iovec_init(sched->secret, sched->hashes[0].algo->digest_size), ikm);
    PTLS_DEBUGF("%s: %u, %02x%02x\n", __FUNCTION__, sched->generation, (int)sched->secret[0], (int)sched->secret[1]);
    return ret;
}

static int key_schedule_select_cipher(ptls_key_schedule_t *sched, ptls_cipher_suite_t *cs, int reset, ptls_iovec_t reset_ikm)
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
            if (sched->hashes[i].ctx_outer != NULL)
                sched->hashes[i].ctx_outer->final(sched->hashes[i].ctx_outer, NULL, PTLS_HASH_FINAL_MODE_FREE);
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
        if ((ret = key_schedule_extract(sched, reset_ikm)) != 0)
            goto Exit;
    }

    ret = 0;
Exit:
    return ret;
}

static void key_schedule_select_outer(ptls_key_schedule_t *sched)
{
    /* This function is called when receiving a cleartext message (Server Hello), after the cipher-suite is determined (and hence
     * the hash also), if ECH was offered */
    assert(sched->generation == 1);
    assert(sched->num_hashes == 1);
    assert(sched->hashes[0].ctx_outer != NULL);

    sched->hashes[0].ctx->final(sched->hashes[0].ctx, NULL, PTLS_HASH_FINAL_MODE_FREE);
    sched->hashes[0].ctx = sched->hashes[0].ctx_outer;
    sched->hashes[0].ctx_outer = NULL;
}

void ptls__key_schedule_update_hash(ptls_key_schedule_t *sched, const uint8_t *msg, size_t msglen, int use_outer)
{
    size_t i;

    PTLS_DEBUGF("%s:%p:len=%zu\n", __FUNCTION__, sched, msglen);
    for (i = 0; i != sched->num_hashes; ++i) {
        ptls_hash_context_t *ctx = use_outer ? sched->hashes[i].ctx_outer : sched->hashes[i].ctx;
        ctx->update(ctx, msg, msglen);
#if defined(PTLS_DEBUG) && PTLS_DEBUG
        {
            uint8_t digest[PTLS_MAX_DIGEST_SIZE];
            ctx->final(ctx, digest, PTLS_HASH_FINAL_MODE_SNAPSHOT);
            PTLS_DEBUGF("  %zu: %02x%02x%02x%02x\n", i, digest[0], digest[1], digest[2], digest[3]);
        }
#endif
    }
}

static void key_schedule_update_ch1hash_prefix(ptls_key_schedule_t *sched)
{
    uint8_t prefix[4] = {PTLS_HANDSHAKE_TYPE_MESSAGE_HASH, 0, 0, (uint8_t)sched->hashes[0].algo->digest_size};
    ptls__key_schedule_update_hash(sched, prefix, sizeof(prefix), 0);
}

static void key_schedule_extract_ch1hash(ptls_key_schedule_t *sched, uint8_t *hash)
{
    assert(sched->hashes[0].ctx_outer == NULL);
    sched->hashes[0].ctx->final(sched->hashes[0].ctx, hash, PTLS_HASH_FINAL_MODE_RESET);
}

static void key_schedule_transform_post_ch1hash(ptls_key_schedule_t *sched)
{
    size_t digest_size = sched->hashes[0].algo->digest_size;
    ptls_hash_context_t *hashes[3] = {sched->hashes[0].ctx, sched->hashes[0].ctx_outer, NULL};
    uint8_t ch1hash[PTLS_MAX_DIGEST_SIZE];
    uint8_t prefix[4] = {PTLS_HANDSHAKE_TYPE_MESSAGE_HASH, 0, 0, (uint8_t)digest_size};

    for (size_t i = 0; hashes[i] != NULL; ++i) {
        hashes[i]->final(hashes[i], ch1hash, PTLS_HASH_FINAL_MODE_RESET);
        hashes[i]->update(hashes[i], prefix, sizeof(prefix));
        hashes[i]->update(hashes[i], ch1hash, digest_size);
    }

    ptls_clear_memory(ch1hash, sizeof(ch1hash));
}

static int derive_secret_with_hash(ptls_key_schedule_t *sched, void *secret, const char *label, const uint8_t *hash)
{
    int ret = ptls_hkdf_expand_label(sched->hashes[0].algo, secret, sched->hashes[0].algo->digest_size,
                                     ptls_iovec_init(sched->secret, sched->hashes[0].algo->digest_size), label,
                                     ptls_iovec_init(hash, sched->hashes[0].algo->digest_size), NULL);
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
    if ((ret = ptls_hkdf_expand_label(sched->hashes[0].algo, secret, sched->hashes[0].algo->digest_size,
                                      ptls_iovec_init(secret, sched->hashes[0].algo->digest_size), "resumption", nonce, NULL)) != 0)
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

static int get_traffic_keys(ptls_aead_algorithm_t *aead, ptls_hash_algorithm_t *hash, void *key, void *iv, const void *secret,
                            ptls_iovec_t hash_value, const char *label_prefix)
{
    int ret;

    if ((ret = get_traffic_key(hash, key, aead->key_size, 0, secret, hash_value, label_prefix)) != 0 ||
        (ret = get_traffic_key(hash, iv, aead->iv_size, 1, secret, hash_value, label_prefix)) != 0) {
        ptls_clear_memory(key, aead->key_size);
        ptls_clear_memory(iv, aead->iv_size);
    }

    return ret;
}

static int setup_traffic_protection(ptls_t *tls, int is_enc, const char *secret_label, size_t epoch, uint64_t seq, int skip_notify)
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

    log_secret(tls, log_labels[ptls_is_server(tls) == is_enc][epoch],
               ptls_iovec_init(ctx->secret, tls->key_schedule->hashes[0].algo->digest_size));

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
    ctx->seq = seq;

#if defined(PTLS_DEBUG) && PTLS_DEBUG
    {
        uint8_t static_iv[PTLS_MAX_IV_SIZE];
        ptls_aead_get_iv(ctx->aead, static_iv);
        PTLS_DEBUGF("[%s] %02x%02x,%02x%02x\n", log_labels[ptls_is_server(tls)][epoch], (unsigned)ctx->secret[0],
                    (unsigned)ctx->secret[1], static_iv[0], static_iv[1]);
    }
#endif

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

    return setup_traffic_protection(tls, is_enc, NULL, 2, 0, 1);
}

static void log_client_random(ptls_t *tls)
{
#if PICOTLS_USE_DTRACE
    char buf[sizeof(tls->client_random) * 2 + 1];
#endif

    PTLS_PROBE(CLIENT_RANDOM, tls, ptls_hexdump(buf, tls->client_random, sizeof(tls->client_random)));
    PTLS_LOG_CONN(client_random, tls, { PTLS_LOG_ELEMENT_HEXDUMP(bytes, tls->client_random, sizeof(tls->client_random)); });
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
        /* session ID context */
        ptls_buffer_push_block(buf, 2, {
            if (ctx->ticket_context.is_set) {
                ptls_buffer_pushv(buf, ctx->ticket_context.bytes, sizeof(ctx->ticket_context.bytes));
            } else if (server_name != NULL) {
                ptls_buffer_pushv(buf, server_name, strlen(server_name));
            }
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

int decode_session_identifier(uint64_t *issued_at, ptls_iovec_t *psk, uint32_t *ticket_age_add, ptls_iovec_t *ticket_ctx,
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
            *ticket_ctx = ptls_iovec_init(src, end - src);
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

    if ((ret = ptls_hkdf_expand_label(sched->hashes[0].algo, digest, sched->hashes[0].algo->digest_size,
                                      ptls_iovec_init(secret, sched->hashes[0].algo->digest_size), "finished",
                                      ptls_iovec_init(NULL, 0), NULL)) != 0)
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

    ptls_buffer_init(&session_id, session_id_smallbuf, sizeof(session_id_smallbuf));

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
    if (tls->key_share != NULL && (ret = encode_session_identifier(tls->ctx, &session_id, ticket_age_add, ptls_iovec_init(NULL, 0),
                                                                   tls->key_schedule, tls->server_name, tls->key_share->id,
                                                                   tls->cipher_suite->id, tls->negotiated_protocol)) != 0)
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

static int push_signature_algorithms(ptls_verify_certificate_t *vc, ptls_buffer_t *sendbuf)
{
    /* The list sent when verify callback is not registered */
    static const uint16_t default_algos[] = {PTLS_SIGNATURE_RSA_PSS_RSAE_SHA256, PTLS_SIGNATURE_ECDSA_SECP256R1_SHA256,
                                             PTLS_SIGNATURE_RSA_PKCS1_SHA256, PTLS_SIGNATURE_RSA_PKCS1_SHA1, UINT16_MAX};
    int ret;

    ptls_buffer_push_block(sendbuf, 2, {
        for (const uint16_t *p = vc != NULL ? vc->algos : default_algos; *p != UINT16_MAX; ++p)
            ptls_buffer_push16(sendbuf, *p);
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

/**
 * @param hash optional argument for restricting the underlying hash algorithm
 */
static int select_cipher(ptls_cipher_suite_t **selected, ptls_cipher_suite_t **candidates, const uint8_t *src,
                         const uint8_t *const end, int server_preference, int server_chacha_priority, ptls_hash_algorithm_t *hash)
{
    size_t found_index = SIZE_MAX;
    int ret;

    while (src != end) {
        uint16_t id;
        if ((ret = ptls_decode16(&id, &src, end)) != 0)
            goto Exit;
        for (size_t i = 0; candidates[i] != NULL; ++i) {
            if (candidates[i]->id == id && (hash == NULL || candidates[i]->hash == hash)) {
                if (server_preference && !(server_chacha_priority && id == PTLS_CIPHER_SUITE_CHACHA20_POLY1305_SHA256)) {
                    /* preserve smallest matching index, and proceed to the next input */
                    if (i < found_index) {
                        found_index = i;
                        break;
                    }
                } else {
                    /* return the pointer matching to the first input that can be used */
                    *selected = candidates[i];
                    goto Exit;
                }
            }
        }
        /* first position of the server list matched (server_preference) */
        if (found_index == 0)
            break;
        /* server preference is overridden only if the first entry of client-provided list is chachapoly */
        server_chacha_priority = 0;
    }
    if (found_index != SIZE_MAX) {
        *selected = candidates[found_index];
        ret = 0;
    } else {
        ret = PTLS_ALERT_HANDSHAKE_FAILURE;
    }

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

/**
 * Within the outer ECH extension, returns the number of bytes that preceeds the AEAD-encrypted payload.
 */
static inline size_t outer_ech_header_size(size_t enc_size)
{
    return 10 + enc_size;
}

/**
 * Flag to indicate which of ClientHelloInner, EncodedClientHelloInner, ClientHelloOuter is to be generated. When ECH is inactive,
 * only ClientHelloInner is used.
 */
enum encode_ch_mode { ENCODE_CH_MODE_INNER, ENCODE_CH_MODE_ENCODED_INNER, ENCODE_CH_MODE_OUTER };

static int encode_client_hello(ptls_context_t *ctx, ptls_buffer_t *sendbuf, enum encode_ch_mode mode, int is_second_flight,
                               ptls_handshake_properties_t *properties, const void *client_random,
                               ptls_key_exchange_context_t *key_share_ctx, const char *sni_name, ptls_iovec_t legacy_session_id,
                               struct st_ptls_ech_t *ech, size_t *ech_size_offset, ptls_iovec_t ech_replay, ptls_iovec_t psk_secret,
                               ptls_iovec_t psk_identity, uint32_t obfuscated_ticket_age, size_t psk_binder_size,
                               ptls_iovec_t *cookie, int using_early_data)
{
    int ret;

    assert(mode == ENCODE_CH_MODE_INNER || ech != NULL);

    ptls_buffer_push_message_body(sendbuf, NULL, PTLS_HANDSHAKE_TYPE_CLIENT_HELLO, {
        /* legacy_version */
        ptls_buffer_push16(sendbuf, 0x0303);
        /* random_bytes */
        ptls_buffer_pushv(sendbuf, client_random, PTLS_HELLO_RANDOM_SIZE);
        /* lecagy_session_id */
        ptls_buffer_push_block(sendbuf, 1, {
            if (mode != ENCODE_CH_MODE_ENCODED_INNER)
                ptls_buffer_pushv(sendbuf, legacy_session_id.base, legacy_session_id.len);
        });
        /* cipher_suites */
        ptls_buffer_push_block(sendbuf, 2, {
            ptls_cipher_suite_t **cs = ctx->cipher_suites;
            for (; *cs != NULL; ++cs)
                ptls_buffer_push16(sendbuf, (*cs)->id);
        });
        /* legacy_compression_methods */
        ptls_buffer_push_block(sendbuf, 1, { ptls_buffer_push(sendbuf, 0); });
        /* extensions */
        ptls_buffer_push_block(sendbuf, 2, {
            if (mode == ENCODE_CH_MODE_OUTER) {
                buffer_push_extension(sendbuf, PTLS_EXTENSION_TYPE_ENCRYPTED_CLIENT_HELLO, {
                    size_t ext_payload_from = sendbuf->off;
                    ptls_buffer_push(sendbuf, PTLS_ECH_CLIENT_HELLO_TYPE_OUTER);
                    ptls_buffer_push16(sendbuf, ech->cipher->id.kdf);
                    ptls_buffer_push16(sendbuf, ech->cipher->id.aead);
                    ptls_buffer_push(sendbuf, ech->config_id);
                    ptls_buffer_push_block(sendbuf, 2, {
                        if (!is_second_flight)
                            ptls_buffer_pushv(sendbuf, ech->client.enc.base, ech->client.enc.len);
                    });
                    ptls_buffer_push_block(sendbuf, 2, {
                        assert(sendbuf->off - ext_payload_from ==
                               outer_ech_header_size(is_second_flight ? 0 : ech->client.enc.len));
                        if ((ret = ptls_buffer_reserve(sendbuf, *ech_size_offset)) != 0)
                            goto Exit;
                        memset(sendbuf->base + sendbuf->off, 0, *ech_size_offset);
                        sendbuf->off += *ech_size_offset;
                        *ech_size_offset = sendbuf->off - *ech_size_offset;
                    });
                });
            } else if (ech->aead != NULL) {
                buffer_push_extension(sendbuf, PTLS_EXTENSION_TYPE_ENCRYPTED_CLIENT_HELLO,
                                      { ptls_buffer_push(sendbuf, PTLS_ECH_CLIENT_HELLO_TYPE_INNER); });
            } else if (ech_replay.base != NULL) {
                buffer_push_extension(sendbuf, PTLS_EXTENSION_TYPE_ENCRYPTED_CLIENT_HELLO,
                                      { ptls_buffer_pushv(sendbuf, ech_replay.base, ech_replay.len); });
            }
            if (mode == ENCODE_CH_MODE_ENCODED_INNER) {
                buffer_push_extension(sendbuf, PTLS_EXTENSION_TYPE_ECH_OUTER_EXTENSIONS, {
                    ptls_buffer_push_block(sendbuf, 1, { ptls_buffer_push16(sendbuf, PTLS_EXTENSION_TYPE_KEY_SHARE); });
                });
            } else {
                buffer_push_extension(sendbuf, PTLS_EXTENSION_TYPE_KEY_SHARE, {
                    ptls_buffer_push_block(sendbuf, 2, {
                        if (key_share_ctx != NULL &&
                            (ret = push_key_share_entry(sendbuf, key_share_ctx->algo->id, key_share_ctx->pubkey)) != 0)
                            goto Exit;
                    });
                });
            }
            if (sni_name != NULL) {
                buffer_push_extension(sendbuf, PTLS_EXTENSION_TYPE_SERVER_NAME, {
                    if ((ret = emit_server_name_extension(sendbuf, sni_name)) != 0)
                        goto Exit;
                });
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
            if (ctx->decompress_certificate != NULL) {
                buffer_push_extension(sendbuf, PTLS_EXTENSION_TYPE_COMPRESS_CERTIFICATE, {
                    ptls_buffer_push_block(sendbuf, 1, {
                        const uint16_t *algo = ctx->decompress_certificate->supported_algorithms;
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
                if ((ret = push_signature_algorithms(ctx->verify_certificate, sendbuf)) != 0)
                    goto Exit;
            });
            if (ctx->key_exchanges != NULL) {
                buffer_push_extension(sendbuf, PTLS_EXTENSION_TYPE_SUPPORTED_GROUPS, {
                    ptls_key_exchange_algorithm_t **algo = ctx->key_exchanges;
                    ptls_buffer_push_block(sendbuf, 2, {
                        for (; *algo != NULL; ++algo)
                            ptls_buffer_push16(sendbuf, (*algo)->id);
                    });
                });
            }
            if (cookie != NULL && cookie->base != NULL) {
                buffer_push_extension(sendbuf, PTLS_EXTENSION_TYPE_COOKIE, {
                    ptls_buffer_push_block(sendbuf, 2, { ptls_buffer_pushv(sendbuf, cookie->base, cookie->len); });
                });
            }
            if (ctx->use_raw_public_keys) {
                buffer_push_extension(sendbuf, PTLS_EXTENSION_TYPE_SERVER_CERTIFICATE_TYPE, {
                    ptls_buffer_push_block(sendbuf, 1, { ptls_buffer_push(sendbuf, PTLS_CERTIFICATE_TYPE_RAW_PUBLIC_KEY); });
                });
            }
            if (ctx->save_ticket != NULL &&
                (ctx->ticket_requests.client.new_session_count != 0 || ctx->ticket_requests.client.resumption_count != 0)) {
                buffer_push_extension(sendbuf, PTLS_EXTENSION_TYPE_TICKET_REQUEST, {
                    ptls_buffer_push(sendbuf, ctx->ticket_requests.client.new_session_count,
                                     ctx->ticket_requests.client.resumption_count);
                });
            }
            if ((ret = push_additional_extensions(properties, sendbuf)) != 0)
                goto Exit;
            if (ctx->save_ticket != NULL || psk_secret.base != NULL) {
                buffer_push_extension(sendbuf, PTLS_EXTENSION_TYPE_PSK_KEY_EXCHANGE_MODES, {
                    ptls_buffer_push_block(sendbuf, 1, {
                        if (!ctx->require_dhe_on_psk)
                            ptls_buffer_push(sendbuf, PTLS_PSK_KE_MODE_PSK);
                        ptls_buffer_push(sendbuf, PTLS_PSK_KE_MODE_PSK_DHE);
                    });
                });
            }
            if (psk_secret.base != NULL) {
                if (using_early_data && !is_second_flight)
                    buffer_push_extension(sendbuf, PTLS_EXTENSION_TYPE_EARLY_DATA, {});
                /* pre-shared key "MUST be the last extension in the ClientHello" (draft-17 section 4.2.6) */
                buffer_push_extension(sendbuf, PTLS_EXTENSION_TYPE_PRE_SHARED_KEY, {
                    ptls_buffer_push_block(sendbuf, 2, {
                        ptls_buffer_push_block(sendbuf, 2, {
                            if (mode == ENCODE_CH_MODE_OUTER) {
                                if ((ret = ptls_buffer_reserve(sendbuf, psk_identity.len)) != 0)
                                    goto Exit;
                                ctx->random_bytes(sendbuf->base + sendbuf->off, psk_identity.len);
                                sendbuf->off += psk_identity.len;
                            } else {
                                ptls_buffer_pushv(sendbuf, psk_identity.base, psk_identity.len);
                            }
                        });
                        uint32_t age;
                        if (mode == ENCODE_CH_MODE_OUTER) {
                            ctx->random_bytes(&age, sizeof(age));
                        } else {
                            age = obfuscated_ticket_age;
                        }
                        ptls_buffer_push32(sendbuf, age);
                    });
                    /* allocate space for PSK binder. The space is filled initially filled by a random value (meeting the
                     * requirement of ClientHelloOuter), and later gets filled with the correct binder value if necessary. */
                    ptls_buffer_push_block(sendbuf, 2, {
                        ptls_buffer_push_block(sendbuf, 1, {
                            if ((ret = ptls_buffer_reserve(sendbuf, psk_binder_size)) != 0)
                                goto Exit;
                            ctx->random_bytes(sendbuf->base + sendbuf->off, psk_binder_size);
                            sendbuf->off += psk_binder_size;
                        });
                    });
                });
            }
        });
    });

Exit:
    return ret;
}

static int send_client_hello(ptls_t *tls, ptls_message_emitter_t *emitter, ptls_handshake_properties_t *properties,
                             ptls_iovec_t *cookie)
{
    struct {
        ptls_iovec_t secret;
        ptls_iovec_t identity;
        const char *label;
    } psk = {{NULL}};
    uint32_t obfuscated_ticket_age = 0;
    const char *sni_name = NULL;
    size_t mess_start, msghash_off;
    uint8_t binder_key[PTLS_MAX_DIGEST_SIZE];
    ptls_buffer_t encoded_ch_inner;
    int ret, is_second_flight = tls->key_schedule != NULL;

    ptls_buffer_init(&encoded_ch_inner, "", 0);

    if (tls->server_name != NULL && !ptls_server_name_is_ipaddr(tls->server_name))
        sni_name = tls->server_name;

    /* try to use ECH (ignore broken ECHConfigList; it is delivered insecurely) */
    if (properties != NULL) {
        if (!is_second_flight && sni_name != NULL && tls->ctx->ech.client.ciphers != NULL) {
            if (properties->client.ech.configs.len != 0) {
                struct st_decoded_ech_config_t decoded;
                client_decode_ech_config_list(tls->ctx, &decoded, properties->client.ech.configs);
                if (decoded.kem != NULL && decoded.cipher != NULL) {
                    if ((ret = client_setup_ech(&tls->ech, &decoded, tls->ctx->random_bytes)) != 0)
                        goto Exit;
                }
            } else {
                /* zero-length config indicates ECH greasing */
                client_setup_ech_grease(&tls->ech, tls->ctx->random_bytes, tls->ctx->ech.client.kems, tls->ctx->ech.client.ciphers,
                                        sni_name);
            }
        }
    }

    /* use external PSK if provided */
    if (tls->ctx->pre_shared_key.identity.base != NULL) {
        if (!is_second_flight) {
            tls->client.offered_psk = 1;
            for (size_t i = 0; tls->ctx->cipher_suites[i] != NULL; ++i) {
                if (tls->ctx->cipher_suites[i]->hash == tls->ctx->pre_shared_key.hash) {
                    tls->cipher_suite = tls->ctx->cipher_suites[i];
                    break;
                }
            }
            assert(tls->cipher_suite != NULL && "no compatible cipher-suite provided that matches psk.hash");
            if (properties != NULL && properties->client.max_early_data_size != NULL) {
                tls->client.using_early_data = 1;
                *properties->client.max_early_data_size = SIZE_MAX;
            }
        } else {
            assert(tls->cipher_suite != NULL && tls->cipher_suite->hash == tls->ctx->pre_shared_key.hash);
        }
        psk.secret = tls->ctx->pre_shared_key.secret;
        psk.identity = tls->ctx->pre_shared_key.identity;
        psk.label = "ext binder";
    }

    /* try to setup resumption-related data, unless external PSK is used */
    if (psk.secret.base == NULL && properties != NULL && properties->client.session_ticket.base != NULL &&
        tls->ctx->key_exchanges != NULL) {
        ptls_key_exchange_algorithm_t *key_share = NULL;
        ptls_cipher_suite_t *cipher_suite = NULL;
        uint32_t max_early_data_size;
        if (decode_stored_session_ticket(tls, &key_share, &cipher_suite, &psk.secret, &obfuscated_ticket_age, &psk.identity,
                                         &max_early_data_size, properties->client.session_ticket.base,
                                         properties->client.session_ticket.base + properties->client.session_ticket.len) == 0) {
            psk.label = "res binder";
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
            psk.secret = ptls_iovec_init(NULL, 0);
        }
    }

    /* send 0-RTT related signals back to the client */
    if (properties != NULL) {
        if (tls->client.using_early_data) {
            properties->client.early_data_acceptance = PTLS_EARLY_DATA_ACCEPTANCE_UNKNOWN;
        } else {
            if (properties->client.max_early_data_size != NULL)
                *properties->client.max_early_data_size = 0;
            properties->client.early_data_acceptance = PTLS_EARLY_DATA_REJECTED;
        }
    }

    /* use the default key share if still not undetermined */
    if (tls->key_share == NULL && tls->ctx->key_exchanges != NULL &&
        !(properties != NULL && properties->client.negotiate_before_key_exchange))
        tls->key_share = tls->ctx->key_exchanges[0];

    /* instantiate key share context */
    assert(tls->client.key_share_ctx == NULL);
    if (tls->key_share != NULL) {
        if ((ret = tls->key_share->create(tls->key_share, &tls->client.key_share_ctx)) != 0)
            goto Exit;
    }

    /* initialize key schedule */
    if (!is_second_flight) {
        if ((tls->key_schedule = key_schedule_new(tls->cipher_suite, tls->ctx->cipher_suites, tls->ech.aead != NULL)) == NULL) {
            ret = PTLS_ERROR_NO_MEMORY;
            goto Exit;
        }
        if ((ret = key_schedule_extract(tls->key_schedule, psk.secret)) != 0)
            goto Exit;
    }

    /* start generating CH */
    if ((ret = emitter->begin_message(emitter)) != 0)
        goto Exit;
    mess_start = msghash_off = emitter->buf->off;

    /* generate true (inner) CH */
    if ((ret = encode_client_hello(tls->ctx, emitter->buf, ENCODE_CH_MODE_INNER, is_second_flight, properties,
                                   tls->ech.aead != NULL ? tls->ech.inner_client_random : tls->client_random,
                                   tls->client.key_share_ctx, sni_name, tls->client.legacy_session_id, &tls->ech, NULL,
                                   tls->ech.client.first_ech, psk.secret, psk.identity, obfuscated_ticket_age,
                                   tls->key_schedule->hashes[0].algo->digest_size, cookie, tls->client.using_early_data)) != 0)
        goto Exit;

    /* update the message hash, filling in the PSK binder HMAC if necessary */
    if (psk.secret.base != NULL) {
        size_t psk_binder_off = emitter->buf->off - (3 + tls->key_schedule->hashes[0].algo->digest_size);
        if ((ret = derive_secret_with_empty_digest(tls->key_schedule, binder_key, psk.label)) != 0)
            goto Exit;
        ptls__key_schedule_update_hash(tls->key_schedule, emitter->buf->base + msghash_off, psk_binder_off - msghash_off, 0);
        msghash_off = psk_binder_off;
        if ((ret = calc_verify_data(emitter->buf->base + psk_binder_off + 3, tls->key_schedule, binder_key)) != 0)
            goto Exit;
    }
    ptls__key_schedule_update_hash(tls->key_schedule, emitter->buf->base + msghash_off, emitter->buf->off - msghash_off, 0);

    /* ECH */
    if (tls->ech.aead != NULL) {
        /* build EncodedCHInner */
        if ((ret = encode_client_hello(tls->ctx, &encoded_ch_inner, ENCODE_CH_MODE_ENCODED_INNER, is_second_flight, properties,
                                       tls->ech.inner_client_random, tls->client.key_share_ctx, sni_name,
                                       tls->client.legacy_session_id, &tls->ech, NULL, ptls_iovec_init(NULL, 0), psk.secret,
                                       psk.identity, obfuscated_ticket_age, tls->key_schedule->hashes[0].algo->digest_size, cookie,
                                       tls->client.using_early_data)) != 0)
            goto Exit;
        if (psk.secret.base != NULL)
            memcpy(encoded_ch_inner.base + encoded_ch_inner.off - tls->key_schedule->hashes[0].algo->digest_size,
                   emitter->buf->base + emitter->buf->off - tls->key_schedule->hashes[0].algo->digest_size,
                   tls->key_schedule->hashes[0].algo->digest_size);
        { /* pad EncodedCHInner (following draft-ietf-tls-esni-15 6.1.3) */
            size_t padding_len;
            if (sni_name != NULL) {
                padding_len = strlen(sni_name);
                if (padding_len < tls->ech.client.max_name_length)
                    padding_len = tls->ech.client.max_name_length;
            } else {
                padding_len = tls->ech.client.max_name_length + 9;
            }
            size_t final_len = encoded_ch_inner.off - PTLS_HANDSHAKE_HEADER_SIZE + padding_len;
            final_len = (final_len + 31) / 32 * 32;
            padding_len = final_len - (encoded_ch_inner.off - PTLS_HANDSHAKE_HEADER_SIZE);
            if (padding_len != 0) {
                if ((ret = ptls_buffer_reserve(&encoded_ch_inner, padding_len)) != 0)
                    goto Exit;
                memset(encoded_ch_inner.base + encoded_ch_inner.off, 0, padding_len);
                encoded_ch_inner.off += padding_len;
            }
        }
        /* flush CHInner, build CHOuterAAD */
        emitter->buf->off = mess_start;
        size_t ech_payload_size = encoded_ch_inner.off - PTLS_HANDSHAKE_HEADER_SIZE + tls->ech.aead->algo->tag_size,
               ech_size_offset = ech_payload_size;
        if ((ret = encode_client_hello(tls->ctx, emitter->buf, ENCODE_CH_MODE_OUTER, is_second_flight, properties,
                                       tls->client_random, tls->client.key_share_ctx, tls->ech.client.public_name,
                                       tls->client.legacy_session_id, &tls->ech, &ech_size_offset, ptls_iovec_init(NULL, 0),
                                       psk.secret, psk.identity, obfuscated_ticket_age,
                                       tls->key_schedule->hashes[0].algo->digest_size, cookie, tls->client.using_early_data)) != 0)
            goto Exit;
        /* overwrite ECH payload */
        ptls_aead_encrypt(tls->ech.aead, emitter->buf->base + ech_size_offset, encoded_ch_inner.base + PTLS_HANDSHAKE_HEADER_SIZE,
                          encoded_ch_inner.off - PTLS_HANDSHAKE_HEADER_SIZE, is_second_flight,
                          emitter->buf->base + mess_start + PTLS_HANDSHAKE_HEADER_SIZE,
                          emitter->buf->off - (mess_start + PTLS_HANDSHAKE_HEADER_SIZE));
        /* keep the copy of the 1st ECH extension so that we can send it again in 2nd CH in response to rejection with HRR */
        if (!is_second_flight) {
            size_t len = outer_ech_header_size(tls->ech.client.enc.len) + ech_payload_size;
            if ((tls->ech.client.first_ech.base = malloc(len)) == NULL) {
                ret = PTLS_ERROR_NO_MEMORY;
                goto Exit;
            }
            memcpy(tls->ech.client.first_ech.base,
                   emitter->buf->base + ech_size_offset - outer_ech_header_size(tls->ech.client.enc.len), len);
            tls->ech.client.first_ech.len = len;
            if (properties->client.ech.configs.len != 0) {
                tls->ech.offered = 1;
            } else {
                tls->ech.offered_grease = 1;
            }
        }
        /* update hash */
        ptls__key_schedule_update_hash(tls->key_schedule, emitter->buf->base + mess_start, emitter->buf->off - mess_start, 1);
    }

    /* commit CH to the record layer */
    if ((ret = emitter->commit_message(emitter)) != 0)
        goto Exit;

    if (tls->client.using_early_data) {
        assert(!is_second_flight);
        if ((ret = setup_traffic_protection(tls, 1, "c e traffic", 1, 0, 0)) != 0)
            goto Exit;
        if ((ret = push_change_cipher_spec(tls, emitter)) != 0)
            goto Exit;
    }
    if (psk.secret.base != NULL && !is_second_flight) {
        if ((ret = derive_exporter_secret(tls, 1)) != 0)
            goto Exit;
    }
    tls->state = cookie == NULL ? PTLS_STATE_CLIENT_EXPECT_SERVER_HELLO : PTLS_STATE_CLIENT_EXPECT_SECOND_SERVER_HELLO;
    ret = PTLS_ERROR_IN_PROGRESS;

Exit:
    ptls_buffer_dispose(&encoded_ch_inner);
    ptls_clear_memory(binder_key, sizeof(binder_key));
    return ret;
}

ptls_cipher_suite_t *ptls_find_cipher_suite(ptls_cipher_suite_t **cipher_suites, uint16_t id)
{
    ptls_cipher_suite_t **cs;
    if (cipher_suites == NULL)
        return NULL;
    for (cs = cipher_suites; *cs != NULL && (*cs)->id != id; ++cs)
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
        if ((tls->cipher_suite = ptls_find_cipher_suite(tls->ctx->cipher_suites, csid)) == NULL) {
            ret = PTLS_ALERT_ILLEGAL_PARAMETER;
            goto Exit;
        }
    }

    { /* legacy_compression_method */
        uint8_t method;
        if ((ret = ptls_decode8(&method, &src, end)) != 0)
            goto Exit;
        if (method != 0) {
            ret = PTLS_ALERT_ILLEGAL_PARAMETER;
            goto Exit;
        }
    }

    if (sh->is_retry_request)
        sh->retry_request.selected_group = UINT16_MAX;

    uint16_t exttype, found_version = UINT16_MAX, selected_psk_identity = UINT16_MAX;
    decode_extensions(src, end, sh->is_retry_request ? PTLS_HANDSHAKE_TYPE_PSEUDO_HRR : PTLS_HANDSHAKE_TYPE_SERVER_HELLO, &exttype,
                      {
                          if (tls->ctx->on_extension != NULL &&
                              (ret = tls->ctx->on_extension->cb(tls->ctx->on_extension, tls, PTLS_HANDSHAKE_TYPE_SERVER_HELLO,
                                                                exttype, ptls_iovec_init(src, end - src)) != 0))
                              goto Exit;
                          switch (exttype) {
                          case PTLS_EXTENSION_TYPE_SUPPORTED_VERSIONS:
                              if ((ret = ptls_decode16(&found_version, &src, end)) != 0)
                                  goto Exit;
                              break;
                          case PTLS_EXTENSION_TYPE_KEY_SHARE:
                              if (tls->ctx->key_exchanges == NULL) {
                                  ret = PTLS_ALERT_HANDSHAKE_FAILURE;
                                  goto Exit;
                              }
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
                              assert(sh->is_retry_request);
                              ptls_decode_block(src, end, 2, {
                                  if (src == end) {
                                      ret = PTLS_ALERT_DECODE_ERROR;
                                      goto Exit;
                                  }
                                  sh->retry_request.cookie = ptls_iovec_init(src, end - src);
                                  src = end;
                              });
                              break;
                          case PTLS_EXTENSION_TYPE_PRE_SHARED_KEY:
                              assert(!sh->is_retry_request);
                              if ((ret = ptls_decode16(&selected_psk_identity, &src, end)) != 0)
                                  goto Exit;
                              break;
                          case PTLS_EXTENSION_TYPE_ENCRYPTED_CLIENT_HELLO:
                              assert(sh->is_retry_request);
                              if (!(tls->ech.offered || tls->ech.offered_grease)) {
                                  ret = PTLS_ALERT_UNSUPPORTED_EXTENSION;
                                  goto Exit;
                              }
                              if (end - src != PTLS_ECH_CONFIRM_LENGTH) {
                                  ret = PTLS_ALERT_DECODE_ERROR;
                                  goto Exit;
                              }
                              sh->retry_request.ech = src;
                              src = end;
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

    ret = send_client_hello(tls, emitter, properties, &sh->retry_request.cookie);

Exit:
    return ret;
}

static int client_ech_select_hello(ptls_t *tls, ptls_iovec_t message, size_t confirm_hash_off, const char *label)
{
    uint8_t confirm_hash_delivered[PTLS_ECH_CONFIRM_LENGTH], confirm_hash_expected[PTLS_ECH_CONFIRM_LENGTH];
    int ret = 0;

    /* Determine if ECH has been accepted by checking the confirmation hash. `confirm_hash_off` set to zero indicates that HRR was
     * received wo. ECH extension, which is an indication that ECH was rejected. */
    if (confirm_hash_off != 0) {
        memcpy(confirm_hash_delivered, message.base + confirm_hash_off, sizeof(confirm_hash_delivered));
        memset(message.base + confirm_hash_off, 0, sizeof(confirm_hash_delivered));
        if ((ret = ech_calc_confirmation(tls->key_schedule, confirm_hash_expected, tls->ech.inner_client_random, label, message)) !=
            0)
            goto Exit;
        tls->ech.accepted = ptls_mem_equal(confirm_hash_delivered, confirm_hash_expected, sizeof(confirm_hash_delivered));
        memcpy(message.base + confirm_hash_off, confirm_hash_delivered, sizeof(confirm_hash_delivered));
        if (tls->ech.accepted)
            goto Exit;
    }

    /* dispose ECH AEAD state to indicate rejection, adopting outer CH for the rest of the handshake */
    ptls_aead_free(tls->ech.aead);
    tls->ech.aead = NULL;
    key_schedule_select_outer(tls->key_schedule);

Exit:
    PTLS_PROBE(ECH_SELECTION, tls, !!tls->ech.accepted);
    PTLS_LOG_CONN(ech_selection, tls, { PTLS_LOG_ELEMENT_BOOL(is_ech, tls->ech.accepted); });
    ptls_clear_memory(confirm_hash_expected, sizeof(confirm_hash_expected));
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
        if ((ret = key_schedule_select_cipher(tls->key_schedule, tls->cipher_suite, 0, tls->ctx->pre_shared_key.secret)) != 0)
            goto Exit;
        key_schedule_transform_post_ch1hash(tls->key_schedule);
        if (tls->ech.aead != NULL) {
            size_t confirm_hash_off = 0;
            if (tls->ech.offered) {
                if (sh.retry_request.ech != NULL)
                    confirm_hash_off = sh.retry_request.ech - message.base;
            } else {
                assert(tls->ech.offered_grease);
            }
            if ((ret = client_ech_select_hello(tls, message, confirm_hash_off, ECH_CONFIRMATION_HRR)) != 0)
                goto Exit;
        }
        ptls__key_schedule_update_hash(tls->key_schedule, message.base, message.len, 0);
        return handle_hello_retry_request(tls, emitter, &sh, message, properties);
    }

    if ((ret = key_schedule_select_cipher(tls->key_schedule, tls->cipher_suite, tls->client.offered_psk && !tls->is_psk_handshake,
                                          ptls_iovec_init(NULL, 0))) != 0)
        goto Exit;

    /* check if ECH is accepted */
    if (tls->ech.aead != NULL) {
        size_t confirm_hash_off = 0;
        if (tls->ech.offered) {
            confirm_hash_off =
                PTLS_HANDSHAKE_HEADER_SIZE + 2 /* legacy_version */ + PTLS_HELLO_RANDOM_SIZE - PTLS_ECH_CONFIRM_LENGTH;
        } else {
            assert(tls->ech.offered_grease);
        }
        if ((ret = client_ech_select_hello(tls, message, confirm_hash_off, ECH_CONFIRMATION_SERVER_HELLO)) != 0)
            goto Exit;
    }

    /* clear sensitive and space-consuming ECH state, now that are done with handling sending and decoding Hellos */
    clear_ech(&tls->ech, 0);
    if (tls->key_schedule->hashes[0].ctx_outer != NULL) {
        tls->key_schedule->hashes[0].ctx_outer->final(tls->key_schedule->hashes[0].ctx_outer, NULL, PTLS_HASH_FINAL_MODE_FREE);
        tls->key_schedule->hashes[0].ctx_outer = NULL;
    }

    /* if the client offered external PSK but the server did not use that, we call it a handshake failure */
    if (tls->ctx->pre_shared_key.identity.base != NULL && !tls->is_psk_handshake) {
        ret = PTLS_ALERT_HANDSHAKE_FAILURE;
        goto Exit;
    }

    ptls__key_schedule_update_hash(tls->key_schedule, message.base, message.len, 0);

    if (sh.peerkey.base != NULL) {
        if ((ret = tls->client.key_share_ctx->on_exchange(&tls->client.key_share_ctx, 1, &ecdh_secret, sh.peerkey)) != 0) {
            assert(ecdh_secret.base == NULL);
            goto Exit;
        }
    }

    if ((ret = key_schedule_extract(tls->key_schedule, ecdh_secret)) != 0)
        goto Exit;
    if ((ret = setup_traffic_protection(tls, 0, "s hs traffic", 2, 0, 0)) != 0)
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
        if ((ret = setup_traffic_protection(tls, 1, "c hs traffic", 2, 0, 0)) != 0)
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
    const uint8_t *src = message.base + PTLS_HANDSHAKE_HEADER_SIZE, *const end = message.base + message.len;
    uint16_t type;
    static const ptls_raw_extension_t no_unknown_extensions = {UINT16_MAX};
    ptls_raw_extension_t *unknown_extensions = (ptls_raw_extension_t *)&no_unknown_extensions;
    int ret, skip_early_data = 1;
    uint8_t server_offered_cert_type = PTLS_CERTIFICATE_TYPE_X509;

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
        case PTLS_EXTENSION_TYPE_SERVER_CERTIFICATE_TYPE:
            if (end - src != 1) {
                ret = PTLS_ALERT_DECODE_ERROR;
                goto Exit;
            }
            server_offered_cert_type = *src;
            src = end;
            break;
        case PTLS_EXTENSION_TYPE_ENCRYPTED_CLIENT_HELLO: {
            /* accept retry_configs only if we offered ECH but rejected */
            if (!((tls->ech.offered || tls->ech.offered_grease) && !ptls_is_ech_handshake(tls, NULL, NULL, NULL))) {
                ret = PTLS_ALERT_UNSUPPORTED_EXTENSION;
                goto Exit;
            }
            /* parse retry_config, and if it is applicable, provide that to the application */
            struct st_decoded_ech_config_t decoded;
            if ((ret = client_decode_ech_config_list(tls->ctx, &decoded, ptls_iovec_init(src, end - src))) != 0)
                goto Exit;
            if (decoded.kem != NULL && decoded.cipher != NULL && properties != NULL &&
                properties->client.ech.retry_configs != NULL) {
                if ((properties->client.ech.retry_configs->base = malloc(end - src)) == NULL) {
                    ret = PTLS_ERROR_NO_MEMORY;
                    goto Exit;
                }
                memcpy(properties->client.ech.retry_configs->base, src, end - src);
                properties->client.ech.retry_configs->len = end - src;
            }
            src = end;
        } break;
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

    if (server_offered_cert_type !=
        (tls->ctx->use_raw_public_keys ? PTLS_CERTIFICATE_TYPE_RAW_PUBLIC_KEY : PTLS_CERTIFICATE_TYPE_X509)) {
        ret = PTLS_ALERT_UNSUPPORTED_CERTIFICATE;
        goto Exit;
    }

    if (tls->client.using_early_data) {
        if (skip_early_data)
            tls->client.using_early_data = 0;
        if (properties != NULL)
            properties->client.early_data_acceptance = skip_early_data ? PTLS_EARLY_DATA_REJECTED : PTLS_EARLY_DATA_ACCEPTED;
    }
    if ((ret = report_unknown_extensions(tls, properties, unknown_extensions)) != 0)
        goto Exit;

    ptls__key_schedule_update_hash(tls->key_schedule, message.base, message.len, 0);
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

static int send_certificate(ptls_t *tls, ptls_message_emitter_t *emitter,
                            struct st_ptls_signature_algorithms_t *signature_algorithms, ptls_iovec_t context,
                            int push_status_request, const uint16_t *compress_algos, size_t num_compress_algos)
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

Exit:
    return ret;
}

static int send_certificate_verify(ptls_t *tls, ptls_message_emitter_t *emitter,
                                   struct st_ptls_signature_algorithms_t *signature_algorithms, const char *context_string)
{
    size_t start_off = emitter->buf->off;
    int ret;

    if (tls->ctx->sign_certificate == NULL)
        return 0;
    /* build and send CertificateVerify */
    ptls_push_message(emitter, tls->key_schedule, PTLS_HANDSHAKE_TYPE_CERTIFICATE_VERIFY, {
        ptls_buffer_t *sendbuf = emitter->buf;
        size_t algo_off = sendbuf->off;
        ptls_buffer_push16(sendbuf, 0); /* filled in later */
        ptls_buffer_push_block(sendbuf, 2, {
            uint16_t algo;
            uint8_t data[PTLS_MAX_CERTIFICATE_VERIFY_SIGNDATA_SIZE];
            size_t datalen = build_certificate_verify_signdata(data, tls->key_schedule, context_string);
            if ((ret = tls->ctx->sign_certificate->cb(
                     tls->ctx->sign_certificate, tls, tls->is_server ? &tls->server.async_job : NULL, &algo, sendbuf,
                     ptls_iovec_init(data, datalen), signature_algorithms != NULL ? signature_algorithms->list : NULL,
                     signature_algorithms != NULL ? signature_algorithms->count : 0)) != 0) {
                if (ret == PTLS_ERROR_ASYNC_OPERATION) {
                    assert(tls->is_server || !"async operation only supported on the server-side");
                    assert(tls->server.async_job != NULL);
                    /* Reset the output to the end of the previous handshake message. CertificateVerify will be rebuilt when the
                     * async operation completes. */
                    emitter->buf->off = start_off;
                } else {
                    assert(tls->server.async_job == NULL);
                }
                goto Exit;
            }
            assert(tls->server.async_job == NULL);
            sendbuf->base[algo_off] = (uint8_t)(algo >> 8);
            sendbuf->base[algo_off + 1] = (uint8_t)algo;
        });
    });
Exit:
    return ret;
}

static int client_handle_certificate_request(ptls_t *tls, ptls_iovec_t message, ptls_handshake_properties_t *properties)
{
    const uint8_t *src = message.base + PTLS_HANDSHAKE_HEADER_SIZE, *const end = message.base + message.len;
    int ret = 0;

    assert(!tls->is_psk_handshake && "state machine asserts that this message is never delivered when PSK is used");

    if ((ret = decode_certificate_request(tls, &tls->client.certificate_request, src, end)) != 0)
        return ret;

    /* This field SHALL be zero length unless used for the post-handshake authentication exchanges (section 4.3.2) */
    if (tls->client.certificate_request.context.len != 0)
        return PTLS_ALERT_ILLEGAL_PARAMETER;

    tls->state = PTLS_STATE_CLIENT_EXPECT_CERTIFICATE;
    ptls__key_schedule_update_hash(tls->key_schedule, message.base, message.len, 0);

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

    if (tls->ctx->verify_certificate != NULL) {
        const char *server_name = NULL;
        if (!ptls_is_server(tls)) {
            if (tls->ech.offered && !ptls_is_ech_handshake(tls, NULL, NULL, NULL)) {
                server_name = tls->ech.client.public_name;
            } else {
                server_name = tls->server_name;
            }
        }
        if ((ret = tls->ctx->verify_certificate->cb(tls->ctx->verify_certificate, tls, server_name, &tls->certificate_verify.cb,
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

    ptls__key_schedule_update_hash(tls->key_schedule, message.base, message.len, 0);

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

    ptls__key_schedule_update_hash(tls->key_schedule, message.base, message.len, 0);
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

    ptls__key_schedule_update_hash(tls->key_schedule, message.base, message.len, 0);

    if (got_certs) {
        tls->state = PTLS_STATE_SERVER_EXPECT_CERTIFICATE_VERIFY;
    } else {
        /* Client did not provide certificate, and the verifier says we can fail open. Therefore, the next message is Finished. */
        tls->state = PTLS_STATE_SERVER_EXPECT_FINISHED;
    }

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

    signdata_size = build_certificate_verify_signdata(signdata, tls->key_schedule, context_string);
    if (tls->certificate_verify.cb != NULL) {
        ret = tls->certificate_verify.cb(tls->certificate_verify.verify_ctx, algo, ptls_iovec_init(signdata, signdata_size),
                                         signature);
    } else {
        ret = 0;
    }
    ptls_clear_memory(signdata, signdata_size);
    tls->certificate_verify.cb = NULL;
    if (ret != 0) {
        goto Exit;
    }

    ptls__key_schedule_update_hash(tls->key_schedule, message.base, message.len, 0);

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
    int alert_ech_required = tls->ech.offered && !ptls_is_ech_handshake(tls, NULL, NULL, NULL), ret;

    if ((ret = verify_finished(tls, message)) != 0)
        goto Exit;
    ptls__key_schedule_update_hash(tls->key_schedule, message.base, message.len, 0);

    /* update traffic keys by using messages upto ServerFinished, but commission them after sending ClientFinished */
    if ((ret = key_schedule_extract(tls->key_schedule, ptls_iovec_init(NULL, 0))) != 0)
        goto Exit;
    if ((ret = setup_traffic_protection(tls, 0, "s ap traffic", 3, 0, 0)) != 0)
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

    if (!alert_ech_required && tls->client.certificate_request.context.base != NULL) {
        if ((ret = send_certificate(tls, emitter, &tls->client.certificate_request.signature_algorithms,
                                    tls->client.certificate_request.context, 0, NULL, 0)) == 0)
            ret = send_certificate_verify(tls, emitter, &tls->client.certificate_request.signature_algorithms,
                                          PTLS_CLIENT_CERTIFICATE_VERIFY_CONTEXT_STRING);
        free(tls->client.certificate_request.context.base);
        tls->client.certificate_request.context = ptls_iovec_init(NULL, 0);
        if (ret != 0)
            goto Exit;
    }

    ret = send_finished(tls, emitter);

    memcpy(tls->traffic_protection.enc.secret, send_secret, sizeof(send_secret));
    if ((ret = setup_traffic_protection(tls, 1, NULL, 3, 0, 0)) != 0)
        goto Exit;

    tls->state = PTLS_STATE_CLIENT_POST_HANDSHAKE;

    /* if ECH was rejected, close the connection with ECH_REQUIRED alert after verifying messages up to Finished */
    if (alert_ech_required)
        ret = PTLS_ALERT_ECH_REQUIRED;

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
        do {
            uint8_t type;
            if ((ret = ptls_decode8(&type, src, end)) != 0)
                goto Exit;
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

static int decode_client_hello(ptls_context_t *ctx, struct st_ptls_client_hello_t *ch, const uint8_t *src, const uint8_t *const end,
                               ptls_handshake_properties_t *properties, ptls_t *tls_cbarg)
{
    const uint8_t *start = src;
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
        if ((end - src) % 2 != 0) {
            ret = PTLS_ALERT_DECODE_ERROR;
            goto Exit;
        }
        ch->cipher_suites = ptls_iovec_init(src, end - src);
        src = end;
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

    /* In TLS versions 1.2 and earlier CH might not have an extensions block (or they might, see what OpenSSL 1.0.0 sends); so bail
     * out if that is the case after parsing the main variables. Zero is returned as it is a valid ClientHello. However
     * `ptls_t::selected_version` remains zero indicating that no compatible version were found. */
    if (src == end) {
        ret = 0;
        goto Exit;
    }

    /* decode extensions */
    ch->first_extension_at = src - start + 2;
    decode_extensions(src, end, PTLS_HANDSHAKE_TYPE_CLIENT_HELLO, &exttype, {
        ch->psk.is_last_extension = 0;
        if (ctx->on_extension != NULL && tls_cbarg != NULL &&
            (ret = ctx->on_extension->cb(ctx->on_extension, tls_cbarg, PTLS_HANDSHAKE_TYPE_CLIENT_HELLO, exttype,
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
        case PTLS_EXTENSION_TYPE_SERVER_CERTIFICATE_TYPE:
            ptls_decode_block(src, end, 1, {
                size_t list_size = end - src;

                /* RFC7250 4.1: No empty list, no list with single x509 element */
                if (list_size == 0 || (list_size == 1 && *src == PTLS_CERTIFICATE_TYPE_X509)) {
                    ret = PTLS_ALERT_DECODE_ERROR;
                    goto Exit;
                }

                do {
                    if (ch->server_certificate_types.count < PTLS_ELEMENTSOF(ch->server_certificate_types.list))
                        ch->server_certificate_types.list[ch->server_certificate_types.count++] = *src;
                    src++;
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
                    uint8_t sent_key_share;
                    if ((ret = ptls_decode8(&sent_key_share, &src, end)) != 0)
                        goto Exit;
                    switch (sent_key_share) {
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
                    ptls_client_hello_psk_identity_t psk = {{NULL}};
                    ptls_decode_open_block(src, end, 2, {
                        if (end - src < 1) {
                            ret = PTLS_ALERT_DECODE_ERROR;
                            goto Exit;
                        }
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
                do {
                    uint8_t mode;
                    if ((ret = ptls_decode8(&mode, &src, end)) != 0)
                        goto Exit;
                    if (mode < sizeof(ch->psk.ke_modes) * 8)
                        ch->psk.ke_modes |= 1u << mode;
                } while (src != end);
            });
            break;
        case PTLS_EXTENSION_TYPE_EARLY_DATA:
            ch->psk.early_data_indication = 1;
            break;
        case PTLS_EXTENSION_TYPE_STATUS_REQUEST:
            ch->status_request = 1;
            break;
        case PTLS_EXTENSION_TYPE_TICKET_REQUEST:
            if (end - src != 2) {
                ret = PTLS_ALERT_DECODE_ERROR;
                goto Exit;
            }
            ch->ticket_request.new_session_count = *src++;
            ch->ticket_request.resumption_count = *src++;
            break;
        case PTLS_EXTENSION_TYPE_ENCRYPTED_CLIENT_HELLO:
            if ((ret = ptls_decode8(&ch->ech.type, &src, end)) != 0)
                goto Exit;
            switch (ch->ech.type) {
            case PTLS_ECH_CLIENT_HELLO_TYPE_OUTER:
                if ((ret = ptls_decode16(&ch->ech.cipher_suite.kdf, &src, end)) != 0 ||
                    (ret = ptls_decode16(&ch->ech.cipher_suite.aead, &src, end)) != 0)
                    goto Exit;
                if ((ret = ptls_decode8(&ch->ech.config_id, &src, end)) != 0)
                    goto Exit;
                ptls_decode_open_block(src, end, 2, {
                    ch->ech.enc = ptls_iovec_init(src, end - src);
                    src = end;
                });
                ptls_decode_open_block(src, end, 2, {
                    if (src == end) {
                        ret = PTLS_ALERT_DECODE_ERROR;
                        goto Exit;
                    }
                    ch->ech.payload = ptls_iovec_init(src, end - src);
                    src = end;
                });
                break;
            case PTLS_ECH_CLIENT_HELLO_TYPE_INNER:
                if (src != end) {
                    ret = PTLS_ALERT_DECODE_ERROR;
                    goto Exit;
                }
                ch->ech.payload = ptls_iovec_init("", 0); /* non-zero base indicates that the extension was received */
                break;
            default:
                ret = PTLS_ALERT_ILLEGAL_PARAMETER;
                goto Exit;
            }
            src = end;
            break;
        default:
            if (tls_cbarg != NULL && should_collect_unknown_extension(tls_cbarg, properties, exttype)) {
                if ((ret = collect_unknown_extension(tls_cbarg, exttype, src, end, ch->unknown_extensions)) != 0)
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

static int rebuild_ch_inner_extensions(ptls_buffer_t *buf, const uint8_t **src, const uint8_t *const end, const uint8_t *outer_ext,
                                       const uint8_t *outer_ext_end)
{
    int ret;

    ptls_buffer_push_block(buf, 2, {
        ptls_decode_open_block(*src, end, 2, {
            while (*src != end) {
                uint16_t exttype;
                if ((ret = ptls_decode16(&exttype, src, end)) != 0)
                    goto Exit;
                ptls_decode_open_block(*src, end, 2, {
                    if (exttype == PTLS_EXTENSION_TYPE_ECH_OUTER_EXTENSIONS) {
                        ptls_decode_open_block(*src, end, 1, {
                            do {
                                uint16_t reftype;
                                uint16_t outertype;
                                uint16_t outersize;
                                if ((ret = ptls_decode16(&reftype, src, end)) != 0)
                                    goto Exit;
                                if (reftype == PTLS_EXTENSION_TYPE_ENCRYPTED_CLIENT_HELLO) {
                                    ret = PTLS_ALERT_ILLEGAL_PARAMETER;
                                    goto Exit;
                                }
                                while (1) {
                                    if (ptls_decode16(&outertype, &outer_ext, outer_ext_end) != 0 ||
                                        ptls_decode16(&outersize, &outer_ext, outer_ext_end) != 0) {
                                        ret = PTLS_ALERT_ILLEGAL_PARAMETER;
                                        goto Exit;
                                    }
                                    assert(outer_ext_end - outer_ext >= outersize);
                                    if (outertype == reftype)
                                        break;
                                    outer_ext += outersize;
                                }
                                buffer_push_extension(buf, reftype, {
                                    ptls_buffer_pushv(buf, outer_ext, outersize);
                                    outer_ext += outersize;
                                });
                            } while (*src != end);
                        });
                    } else {
                        buffer_push_extension(buf, exttype, {
                            ptls_buffer_pushv(buf, *src, end - *src);
                            *src = end;
                        });
                    }
                });
            }
        });
    });

Exit:
    return ret;
}

static int rebuild_ch_inner(ptls_buffer_t *buf, const uint8_t *src, const uint8_t *const end,
                            struct st_ptls_client_hello_t *outer_ch, const uint8_t *outer_ext, const uint8_t *outer_ext_end)
{
#define COPY_BLOCK(capacity)                                                                                                       \
    do {                                                                                                                           \
        ptls_decode_open_block(src, end, (capacity), {                                                                             \
            ptls_buffer_push_block(buf, (capacity), { ptls_buffer_pushv(buf, src, end - src); });                                  \
            src = end;                                                                                                             \
        });                                                                                                                        \
    } while (0)

    int ret;

    ptls_buffer_push_message_body(buf, NULL, PTLS_HANDSHAKE_TYPE_CLIENT_HELLO, {
        { /* legacy_version */
            uint16_t legacy_version;
            if ((ret = ptls_decode16(&legacy_version, &src, end)) != 0)
                goto Exit;
            ptls_buffer_push16(buf, legacy_version);
        }

        /* hello random */
        if (end - src < PTLS_HELLO_RANDOM_SIZE) {
            ret = PTLS_ALERT_DECODE_ERROR;
            goto Exit;
        }
        ptls_buffer_pushv(buf, src, PTLS_HELLO_RANDOM_SIZE);
        src += PTLS_HELLO_RANDOM_SIZE;

        ptls_decode_open_block(src, end, 1, {
            if (src != end) {
                ret = PTLS_ALERT_ILLEGAL_PARAMETER;
                goto Exit;
            }
        });
        ptls_buffer_push_block(buf, 1,
                               { ptls_buffer_pushv(buf, outer_ch->legacy_session_id.base, outer_ch->legacy_session_id.len); });

        /* cipher-suites and legacy-compression-methods */
        COPY_BLOCK(2);
        COPY_BLOCK(1);

        /* extensions */
        if ((ret = rebuild_ch_inner_extensions(buf, &src, end, outer_ext, outer_ext_end)) != 0)
            goto Exit;
    });

    /* padding must be all zero */
    for (; src != end; ++src) {
        if (*src != '\0') {
            ret = PTLS_ALERT_ILLEGAL_PARAMETER;
            goto Exit;
        }
    }

Exit:
    return ret;

#undef COPY_BLOCK
}

/* Wrapper function for invoking the on_client_hello callback, taking an exhaustive list of parameters as arguments. The intention
 * is to not miss setting them as we add new parameters to the struct. */
static inline int call_on_client_hello_cb(ptls_t *tls, ptls_iovec_t server_name, ptls_iovec_t raw_message,
                                          ptls_iovec_t cipher_suites, ptls_iovec_t *alpns, size_t num_alpns,
                                          const uint16_t *sig_algos, size_t num_sig_algos, const uint16_t *cert_comp_algos,
                                          size_t num_cert_comp_algos, const uint8_t *server_cert_types,
                                          size_t num_server_cert_types, const ptls_client_hello_psk_identity_t *psk_identities,
                                          size_t num_psk_identities, int incompatible_version)
{
    if (tls->ctx->on_client_hello == NULL)
        return 0;

    ptls_on_client_hello_parameters_t params = {server_name,
                                                raw_message,
                                                cipher_suites,
                                                {alpns, num_alpns},
                                                {sig_algos, num_sig_algos},
                                                {cert_comp_algos, num_cert_comp_algos},
                                                {server_cert_types, num_server_cert_types},
                                                {psk_identities, num_psk_identities},
                                                incompatible_version};
    return tls->ctx->on_client_hello->cb(tls->ctx->on_client_hello, tls, &params);
}

static int check_client_hello_constraints(ptls_context_t *ctx, struct st_ptls_client_hello_t *ch, const void *prev_random,
                                          int ech_is_inner_ch, ptls_iovec_t raw_message, ptls_t *tls_cbarg)
{
    int is_second_flight = prev_random != 0;

    /* The following check is necessary so that we would be able to track the connection in SSLKEYLOGFILE, even though it might not
     * be for the safety of the protocol. */
    if (is_second_flight && !ptls_mem_equal(ch->random_bytes, prev_random, PTLS_HELLO_RANDOM_SIZE))
        return PTLS_ALERT_HANDSHAKE_FAILURE;

    /* bail out if CH cannot be handled as TLS 1.3 */
    if (!is_supported_version(ch->selected_version)) {
        /* ECH: server MUST abort with an "illegal_parameter" alert if the client offers TLS 1.2 or below (draft-15 7.1) */
        if (ech_is_inner_ch)
            return PTLS_ALERT_ILLEGAL_PARAMETER;
        /* fail with PROTOCOL_VERSION alert, after providing the applications the raw CH and SNI to help them fallback */
        if (!is_second_flight) {
            int ret;
            if ((ret = call_on_client_hello_cb(tls_cbarg, ch->server_name, raw_message, ch->cipher_suites, ch->alpn.list,
                                               ch->alpn.count, NULL, 0, NULL, 0, NULL, 0, NULL, 0, 1)) != 0)
                return ret;
        }
        return PTLS_ALERT_PROTOCOL_VERSION;
    }

    /* Check TLS 1.3-specific constraints. Hereafter, we might exit without calling on_client_hello. That's fine because this CH is
     * ought to be rejected. */
    if (ch->legacy_version <= 0x0300) {
        /* RFC 8446 Appendix D.5: any endpoint receiving a Hello message with legacy_version set to 0x0300 MUST abort the handshake
         * with a "protocol_version" alert. */
        return PTLS_ALERT_PROTOCOL_VERSION;
    }
    if (!(ch->compression_methods.count == 1 && ch->compression_methods.ids[0] == 0))
        return PTLS_ALERT_ILLEGAL_PARAMETER;
    /* pre-shared key */
    if (ch->psk.hash_end != NULL) {
        /* PSK must be the last extension */
        if (!ch->psk.is_last_extension)
            return PTLS_ALERT_ILLEGAL_PARAMETER;
    } else {
        if (ch->psk.early_data_indication)
            return PTLS_ALERT_ILLEGAL_PARAMETER;
    }

    if (ech_is_inner_ch && ch->ech.payload.base == NULL)
        return PTLS_ALERT_ILLEGAL_PARAMETER;
    if (ch->ech.payload.base != NULL &&
        ch->ech.type != (ech_is_inner_ch ? PTLS_ECH_CLIENT_HELLO_TYPE_INNER : PTLS_ECH_CLIENT_HELLO_TYPE_OUTER))
        return PTLS_ALERT_ILLEGAL_PARAMETER;

    return 0;
}

static int vec_is_string(ptls_iovec_t x, const char *y)
{
    return strncmp((const char *)x.base, y, x.len) == 0 && y[x.len] == '\0';
}

/**
 * Looks for a PSK identity that can be used, and if found, updates the handshake state and returns the necessary variables. If
 * `ptls_context_t::pre_shared_key` is set, only tries handshake using those keys provided. Otherwise, tries resumption.
 */
static int try_psk_handshake(ptls_t *tls, size_t *psk_index, int *accept_early_data, struct st_ptls_client_hello_t *ch,
                             ptls_iovec_t ch_trunc, int is_second_flight)
{
    ptls_buffer_t decbuf;
    ptls_iovec_t secret, ticket_ctx, ticket_negotiated_protocol;
    uint64_t issue_at, now = tls->ctx->get_time->cb(tls->ctx->get_time);
    uint32_t age_add;
    uint16_t ticket_key_exchange_id, ticket_csid;
    uint8_t binder_key[PTLS_MAX_DIGEST_SIZE];
    int ret;

    ptls_buffer_init(&decbuf, "", 0);

    for (*psk_index = 0; *psk_index < ch->psk.identities.count; ++*psk_index) {
        ptls_client_hello_psk_identity_t *identity = ch->psk.identities.list + *psk_index;

        /* negotiate using fixed pre-shared key */
        if (tls->ctx->pre_shared_key.identity.base != NULL) {
            if (identity->identity.len == tls->ctx->pre_shared_key.identity.len &&
                memcmp(identity->identity.base, tls->ctx->pre_shared_key.identity.base, identity->identity.len) == 0) {
                *accept_early_data = ch->psk.early_data_indication && *psk_index == 0;
                tls->key_share = NULL;
                secret = tls->ctx->pre_shared_key.secret;
                goto Found;
            }
            continue;
        }

        /* decrypt ticket and decode */
        if (tls->ctx->encrypt_ticket == NULL || tls->ctx->key_exchanges == NULL)
            continue;
        int can_accept_early_data = *psk_index == 0;
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
        if (decode_session_identifier(&issue_at, &secret, &age_add, &ticket_ctx, &ticket_key_exchange_id, &ticket_csid,
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
            if (tls->ctx->max_early_data_size != 0 && delta <= PTLS_EARLY_DATA_MAX_DELAY)
                *accept_early_data = 1;
        }
        /* check ticket context */
        if (tls->ctx->ticket_context.is_set) {
            if (!(ticket_ctx.len == sizeof(tls->ctx->ticket_context.bytes) &&
                  memcmp(ticket_ctx.base, tls->ctx->ticket_context.bytes, ticket_ctx.len) == 0))
                continue;
        } else {
            /* check server-name */
            if (ticket_ctx.len != 0) {
                if (tls->server_name == NULL)
                    continue;
                if (!vec_is_string(ticket_ctx, tls->server_name))
                    continue;
            } else {
                if (tls->server_name != NULL)
                    continue;
            }
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
        if (secret.len != tls->key_schedule->hashes[0].algo->digest_size)
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
    if (!is_second_flight && (ret = key_schedule_extract(tls->key_schedule, secret)) != 0)
        goto Exit;
    if ((ret = derive_secret_with_empty_digest(tls->key_schedule, binder_key,
                                               tls->ctx->pre_shared_key.secret.base != NULL ? "ext binder" : "res binder")) != 0)
        goto Exit;
    ptls__key_schedule_update_hash(tls->key_schedule, ch_trunc.base, ch_trunc.len, 0);
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
    UPDATE16(negotiated_group != NULL ? negotiated_group->id : 0);
    UPDATE_BLOCK(properties->server.cookie.additional_data.base, properties->server.cookie.additional_data.len);

    UPDATE_BLOCK(tbs.base, tbs.len);

#undef UPDATE_BLOCK
#undef UPDATE16

    hctx->final(hctx, sig, PTLS_HASH_FINAL_MODE_FREE);
    return 0;
}

static int certificate_type_exists(uint8_t *list, size_t count, uint8_t desired_type)
{
    /* empty type list means that we default to x509 */
    if (desired_type == PTLS_CERTIFICATE_TYPE_X509 && count == 0)
        return 1;
    for (size_t i = 0; i < count; i++) {
        if (list[i] == desired_type)
            return 1;
    }
    return 0;
}

static int server_handle_hello(ptls_t *tls, ptls_message_emitter_t *emitter, ptls_iovec_t message,
                               ptls_handshake_properties_t *properties)
{
#define EMIT_SERVER_HELLO(sched, fill_rand, extensions, post_action)                                                               \
    do {                                                                                                                           \
        size_t sh_start_off;                                                                                                       \
        ptls_push_message(emitter, NULL, PTLS_HANDSHAKE_TYPE_SERVER_HELLO, {                                                       \
            sh_start_off = emitter->buf->off - PTLS_HANDSHAKE_HEADER_SIZE;                                                         \
            ptls_buffer_push16(emitter->buf, 0x0303 /* legacy version */);                                                         \
            if ((ret = ptls_buffer_reserve(emitter->buf, PTLS_HELLO_RANDOM_SIZE)) != 0)                                            \
                goto Exit;                                                                                                         \
            do {                                                                                                                   \
                fill_rand                                                                                                          \
            } while (0);                                                                                                           \
            emitter->buf->off += PTLS_HELLO_RANDOM_SIZE;                                                                           \
            ptls_buffer_push_block(emitter->buf, 1,                                                                                \
                                   { ptls_buffer_pushv(emitter->buf, ch->legacy_session_id.base, ch->legacy_session_id.len); });   \
            ptls_buffer_push16(emitter->buf, tls->cipher_suite->id);                                                               \
            ptls_buffer_push(emitter->buf, 0);                                                                                     \
            ptls_buffer_push_block(emitter->buf, 2, {                                                                              \
                buffer_push_extension(emitter->buf, PTLS_EXTENSION_TYPE_SUPPORTED_VERSIONS,                                        \
                                      { ptls_buffer_push16(emitter->buf, ch->selected_version); });                                \
                do {                                                                                                               \
                    extensions                                                                                                     \
                } while (0);                                                                                                       \
            });                                                                                                                    \
        });                                                                                                                        \
        do {                                                                                                                       \
            post_action                                                                                                            \
        } while (0);                                                                                                               \
        ptls__key_schedule_update_hash((sched), emitter->buf->base + sh_start_off, emitter->buf->off - sh_start_off, 0);           \
    } while (0)

#define EMIT_HELLO_RETRY_REQUEST(sched, negotiated_group, additional_extensions, post_action)                                      \
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
                      },                                                                                                           \
                      post_action)
    struct st_ptls_client_hello_t *ch;
    struct {
        ptls_key_exchange_algorithm_t *algorithm;
        ptls_iovec_t peer_key;
    } key_share = {NULL};
    struct {
        uint8_t *encoded_ch_inner;
        uint8_t *ch_outer_aad;
        ptls_buffer_t ch_inner;
    } ech = {NULL};
    enum { HANDSHAKE_MODE_FULL, HANDSHAKE_MODE_PSK, HANDSHAKE_MODE_PSK_DHE } mode;
    size_t psk_index = SIZE_MAX;
    ptls_iovec_t pubkey = {0}, ecdh_secret = {0};
    int accept_early_data = 0, is_second_flight = tls->state == PTLS_STATE_SERVER_EXPECT_SECOND_CLIENT_HELLO, ret;

    ptls_buffer_init(&ech.ch_inner, "", 0);

    if ((ch = malloc(sizeof(*ch))) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }

    *ch = (struct st_ptls_client_hello_t){.unknown_extensions = {{UINT16_MAX}}};

    /* decode ClientHello */
    if ((ret = decode_client_hello(tls->ctx, ch, message.base + PTLS_HANDSHAKE_HEADER_SIZE, message.base + message.len, properties,
                                   tls)) != 0)
        goto Exit;
    if ((ret = check_client_hello_constraints(tls->ctx, ch, is_second_flight ? tls->client_random : NULL, 0, message, tls)) != 0)
        goto Exit;
    if (!is_second_flight) {
        memcpy(tls->client_random, ch->random_bytes, PTLS_HELLO_RANDOM_SIZE);
        log_client_random(tls);
    } else {
        /* consistency check for ECH extension in response to HRR */
        if (tls->ech.aead != NULL) {
            if (ch->ech.payload.base == NULL) {
                ret = PTLS_ALERT_MISSING_EXTENSION;
                goto Exit;
            }
            if (!(ch->ech.config_id == tls->ech.config_id && ch->ech.cipher_suite.kdf == tls->ech.cipher->id.kdf &&
                  ch->ech.cipher_suite.aead == tls->ech.cipher->id.aead && ch->ech.enc.len == 0)) {
                ret = PTLS_ALERT_ILLEGAL_PARAMETER;
                goto Exit;
            }
        }
    }

    /* ECH */
    if (ch->ech.payload.base != NULL) {
        if (ch->ech.type != PTLS_ECH_CLIENT_HELLO_TYPE_OUTER) {
            ret = PTLS_ALERT_ILLEGAL_PARAMETER;
            goto Exit;
        }
        if (!is_second_flight)
            tls->ech.offered = 1;
        /* obtain AEAD context for opening inner CH */
        if (!is_second_flight && ch->ech.payload.base != NULL && tls->ctx->ech.server.create_opener != NULL) {
            if ((tls->ech.aead = tls->ctx->ech.server.create_opener->cb(
                     tls->ctx->ech.server.create_opener, &tls->ech.kem, &tls->ech.cipher, tls, ch->ech.config_id,
                     ch->ech.cipher_suite, ch->ech.enc, ptls_iovec_init(ech_info_prefix, sizeof(ech_info_prefix)))) != NULL)
                tls->ech.config_id = ch->ech.config_id;
        }
        if (!is_second_flight) {
            PTLS_PROBE(ECH_SELECTION, tls, tls->ech.aead != NULL);
            PTLS_LOG_CONN(ech_selection, tls, { PTLS_LOG_ELEMENT_BOOL(is_ech, tls->ech.aead != NULL); });
        }
        if (tls->ech.aead != NULL) {
            /* now that AEAD context is available, create AAD and decrypt inner CH */
            if ((ech.encoded_ch_inner = malloc(ch->ech.payload.len - tls->ech.aead->algo->tag_size)) == NULL ||
                (ech.ch_outer_aad = malloc(message.len - PTLS_HANDSHAKE_HEADER_SIZE)) == NULL) {
                ret = PTLS_ERROR_NO_MEMORY;
                goto Exit;
            }
            memcpy(ech.ch_outer_aad, message.base + PTLS_HANDSHAKE_HEADER_SIZE, message.len - PTLS_HANDSHAKE_HEADER_SIZE);
            memset(ech.ch_outer_aad + (ch->ech.payload.base - (message.base + PTLS_HANDSHAKE_HEADER_SIZE)), 0, ch->ech.payload.len);
            if (ptls_aead_decrypt(tls->ech.aead, ech.encoded_ch_inner, ch->ech.payload.base, ch->ech.payload.len, is_second_flight,
                                  ech.ch_outer_aad, message.len - PTLS_HANDSHAKE_HEADER_SIZE) != SIZE_MAX) {
                tls->ech.accepted = 1;
                /* successfully decrypted EncodedCHInner, build CHInner */
                if ((ret = rebuild_ch_inner(&ech.ch_inner, ech.encoded_ch_inner,
                                            ech.encoded_ch_inner + ch->ech.payload.len - tls->ech.aead->algo->tag_size, ch,
                                            message.base + PTLS_HANDSHAKE_HEADER_SIZE + ch->first_extension_at,
                                            message.base + message.len)) != 0)
                    goto Exit;
                /* treat inner ch as the message being received, re-decode it */
                message = ptls_iovec_init(ech.ch_inner.base, ech.ch_inner.off);
                *ch = (struct st_ptls_client_hello_t){.unknown_extensions = {{UINT16_MAX}}};
                if ((ret = decode_client_hello(tls->ctx, ch, ech.ch_inner.base + PTLS_HANDSHAKE_HEADER_SIZE,
                                               ech.ch_inner.base + ech.ch_inner.off, properties, tls)) != 0)
                    goto Exit;
                if ((ret = check_client_hello_constraints(tls->ctx, ch, is_second_flight ? tls->ech.inner_client_random : NULL, 1,
                                                          message, tls)) != 0)
                    goto Exit;
                if (!is_second_flight)
                    memcpy(tls->ech.inner_client_random, ch->random_bytes, PTLS_HELLO_RANDOM_SIZE);
            } else if (is_second_flight) {
                /* decryption failure of inner CH in 2nd CH is fatal */
                ret = PTLS_ALERT_DECRYPT_ERROR;
                goto Exit;
            } else {
                /* decryption failure of 1st CH indicates key mismatch; dispose of AEAD context to indicate adoption of outerCH */
                ptls_aead_free(tls->ech.aead);
                tls->ech.aead = NULL;
            }
        }
    } else if (tls->ech.offered) {
        assert(is_second_flight);
        ret = PTLS_ALERT_ILLEGAL_PARAMETER;
        goto Exit;
    }

    if (tls->ctx->require_dhe_on_psk)
        ch->psk.ke_modes &= ~(1u << PTLS_PSK_KE_MODE_PSK);

    /* handle client_random, legacy_session_id, SNI, ESNI */
    if (!is_second_flight) {
        if (ch->legacy_session_id.len != 0)
            tls->send_change_cipher_spec = 1;
        ptls_iovec_t server_name = {NULL};
        if (ch->server_name.base != NULL)
            server_name = ch->server_name;
        if ((ret = call_on_client_hello_cb(tls, server_name, message, ch->cipher_suites, ch->alpn.list, ch->alpn.count,
                                           ch->signature_algorithms.list, ch->signature_algorithms.count,
                                           ch->cert_compression_algos.list, ch->cert_compression_algos.count,
                                           ch->server_certificate_types.list, ch->server_certificate_types.count,
                                           ch->psk.identities.list, ch->psk.identities.count, 0)) != 0)
            goto Exit;
        if (!certificate_type_exists(ch->server_certificate_types.list, ch->server_certificate_types.count,
                                     tls->ctx->use_raw_public_keys ? PTLS_CERTIFICATE_TYPE_RAW_PUBLIC_KEY
                                                                   : PTLS_CERTIFICATE_TYPE_X509)) {
            ret = PTLS_ALERT_UNSUPPORTED_CERTIFICATE;
            goto Exit;
        }
    } else {
        if (ch->psk.early_data_indication) {
            ret = PTLS_ALERT_DECODE_ERROR;
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
                                 ch->cipher_suites.base + ch->cipher_suites.len, tls->ctx->server_cipher_preference,
                                 tls->ctx->server_cipher_chacha_priority, tls->ctx->pre_shared_key.hash)) != 0)
            goto Exit;
        if (!is_second_flight) {
            tls->cipher_suite = cs;
            if ((tls->key_schedule = key_schedule_new(cs, NULL, 0)) == NULL) {
                ret = PTLS_ERROR_NO_MEMORY;
                goto Exit;
            }
        } else {
            if (tls->cipher_suite != cs) {
                ret = PTLS_ALERT_HANDSHAKE_FAILURE;
                goto Exit;
            }
        }
    }

    /* select key_share */
    if (key_share.algorithm == NULL && ch->key_shares.base != NULL && tls->ctx->key_exchanges != NULL) {
        const uint8_t *src = ch->key_shares.base, *const end = src + ch->key_shares.len;
        ptls_decode_block(src, end, 2, {
            if ((ret = select_key_share(&key_share.algorithm, &key_share.peer_key, tls->ctx->key_exchanges, &src, end, 0)) != 0)
                goto Exit;
        });
    }

    if (!is_second_flight) {
        if (ch->cookie.all.len != 0 && key_share.algorithm != NULL) {

            { /* use cookie to check the integrity of the handshake, and update the context */
                uint8_t sig[PTLS_MAX_DIGEST_SIZE];
                size_t sigsize = tls->ctx->cipher_suites[0]->hash->digest_size;
                if ((ret = calc_cookie_signature(tls, properties, key_share.algorithm, ch->cookie.tbs, sig)) != 0)
                    goto Exit;
                if (!(ch->cookie.signature.len == sigsize && ptls_mem_equal(ch->cookie.signature.base, sig, sigsize))) {
                    ret = PTLS_ALERT_HANDSHAKE_FAILURE;
                    goto Exit;
                }
            }
            /* integrity check passed; update states */
            key_schedule_update_ch1hash_prefix(tls->key_schedule);
            ptls__key_schedule_update_hash(tls->key_schedule, ch->cookie.ch1_hash.base, ch->cookie.ch1_hash.len, 0);
            key_schedule_extract(tls->key_schedule,
                                 tls->ctx->pre_shared_key.secret /* this argument will be a zero-length vector unless external PSK
                                                                  is used, and that's fine; we never resume when sending HRR */);
            /* ... reusing sendbuf to rebuild HRR for hash calculation */
            size_t hrr_start = emitter->buf->off;
            EMIT_HELLO_RETRY_REQUEST(tls->key_schedule, ch->cookie.sent_key_share ? key_share.algorithm : NULL,
                                     {
                                         buffer_push_extension(emitter->buf, PTLS_EXTENSION_TYPE_COOKIE, {
                                             ptls_buffer_pushv(emitter->buf, ch->cookie.all.base, ch->cookie.all.len);
                                         });
                                     },
                                     {});
            emitter->buf->off = hrr_start;
            is_second_flight = 1;

        } else if (ch->key_shares.base != NULL && tls->ctx->key_exchanges != NULL &&
                   (key_share.algorithm == NULL || (properties != NULL && properties->server.enforce_retry))) {
            /* send HelloRetryRequest, when trying to negotiate the key share but enforced by config or upon key-share mismatch */
            if (ch->negotiated_groups.base == NULL) {
                ret = PTLS_ALERT_MISSING_EXTENSION;
                goto Exit;
            }
            ptls_key_exchange_algorithm_t *negotiated_group;
            if ((ret = select_negotiated_group(&negotiated_group, tls->ctx->key_exchanges, ch->negotiated_groups.base,
                                               ch->negotiated_groups.base + ch->negotiated_groups.len)) != 0)
                goto Exit;
            ptls__key_schedule_update_hash(tls->key_schedule, message.base, message.len, 0);
            assert(tls->key_schedule->generation == 0);

            /* Either send a stateless retry (w. cookies) or a stateful one. When sending the latter, run the state machine. At the
             * moment, stateless retry is disabled when ECH is used (do we need to support it?). */
            int retry_uses_cookie =
                properties != NULL && properties->server.retry_uses_cookie && !ptls_is_ech_handshake(tls, NULL, NULL, NULL);
            if (!retry_uses_cookie) {
                key_schedule_transform_post_ch1hash(tls->key_schedule);
                key_schedule_extract(tls->key_schedule, tls->ctx->pre_shared_key.secret /* see comment above */);
            }
            size_t ech_confirm_off = 0;
            EMIT_HELLO_RETRY_REQUEST(
                tls->key_schedule, key_share.algorithm != NULL ? NULL : negotiated_group,
                {
                    ptls_buffer_t *sendbuf = emitter->buf;
                    if (ptls_is_ech_handshake(tls, NULL, NULL, NULL)) {
                        buffer_push_extension(sendbuf, PTLS_EXTENSION_TYPE_ENCRYPTED_CLIENT_HELLO, {
                            if ((ret = ptls_buffer_reserve(sendbuf, PTLS_ECH_CONFIRM_LENGTH)) != 0)
                                goto Exit;
                            memset(sendbuf->base + sendbuf->off, 0, PTLS_ECH_CONFIRM_LENGTH);
                            ech_confirm_off = sendbuf->off;
                            sendbuf->off += PTLS_ECH_CONFIRM_LENGTH;
                        });
                    }
                    if (retry_uses_cookie) {
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
                    }
                },
                {
                    if (ech_confirm_off != 0 &&
                        (ret = ech_calc_confirmation(
                             tls->key_schedule, emitter->buf->base + ech_confirm_off, tls->ech.inner_client_random,
                             ECH_CONFIRMATION_HRR,
                             ptls_iovec_init(emitter->buf->base + sh_start_off, emitter->buf->off - sh_start_off))) != 0)
                        goto Exit;
                });
            if (retry_uses_cookie) {
                if ((ret = push_change_cipher_spec(tls, emitter)) != 0)
                    goto Exit;
                ret = PTLS_ERROR_STATELESS_RETRY;
            } else {
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
    if (ch->psk.hash_end != 0 && (ch->psk.ke_modes & ((1u << PTLS_PSK_KE_MODE_PSK) | (1u << PTLS_PSK_KE_MODE_PSK_DHE))) != 0 &&
        !tls->ctx->require_client_authentication &&
        ((!is_second_flight && tls->ctx->encrypt_ticket != NULL) || tls->ctx->pre_shared_key.identity.base != NULL)) {
        if ((ret = try_psk_handshake(tls, &psk_index, &accept_early_data, ch,
                                     ptls_iovec_init(message.base, ch->psk.hash_end - message.base), is_second_flight)) != 0) {
            goto Exit;
        }
    }

    /* If the server was setup to use an external PSK but failed to agree, abort the handshake. Because external PSK is a form of
     * mutual authentication, it makes sense to abort (at least as the default). */
    if (tls->ctx->pre_shared_key.identity.base != NULL && psk_index == SIZE_MAX) {
        ret = PTLS_ALERT_UNKNOWN_PSK_IDENTITY;
        goto Exit;
    }

    /* If client authentication is enabled, we always force a full handshake.
     * TODO: Check for `post_handshake_auth` extension and if that is present, do not force full handshake!
     *       Remove also the check `!require_client_authentication` above.
     *
     * adjust key_schedule, determine handshake mode
     */
    if (psk_index == SIZE_MAX || tls->ctx->require_client_authentication) {
        ptls__key_schedule_update_hash(tls->key_schedule, message.base, message.len, 0);
        if (!is_second_flight) {
            assert(tls->key_schedule->generation == 0);
            key_schedule_extract(tls->key_schedule, ptls_iovec_init(NULL, 0));
        }
        mode = HANDSHAKE_MODE_FULL;
        if (properties != NULL)
            properties->server.selected_psk_binder.len = 0;
    } else {
        ptls__key_schedule_update_hash(tls->key_schedule, ch->psk.hash_end, message.base + message.len - ch->psk.hash_end, 0);
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

    /* determine number of tickets to send */
    if (ch->psk.ke_modes != 0 && tls->ctx->ticket_lifetime != 0) {
        if (ch->ticket_request.new_session_count != 0) {
            tls->server.num_tickets_to_send =
                tls->is_psk_handshake ? ch->ticket_request.resumption_count : ch->ticket_request.new_session_count;
        } else {
            tls->server.num_tickets_to_send = 1;
        }
        uint8_t max_tickets = tls->ctx->ticket_requests.server.max_count;
        if (max_tickets == 0)
            max_tickets = PTLS_DEFAULT_MAX_TICKETS_TO_SERVE;
        if (tls->server.num_tickets_to_send > max_tickets)
            tls->server.num_tickets_to_send = max_tickets;
    } else {
        tls->server.num_tickets_to_send = 0;
    }

    if (accept_early_data && tls->ctx->max_early_data_size != 0 && psk_index == 0) {
        if ((tls->pending_handshake_secret = malloc(PTLS_MAX_DIGEST_SIZE)) == NULL) {
            ret = PTLS_ERROR_NO_MEMORY;
            goto Exit;
        }
        if ((ret = derive_exporter_secret(tls, 1)) != 0)
            goto Exit;
        if ((ret = setup_traffic_protection(tls, 0, "c e traffic", 1, 0, 0)) != 0)
            goto Exit;
    }

    /* run key-exchange, to obtain pubkey and secret */
    if (mode != HANDSHAKE_MODE_PSK) {
        if (key_share.algorithm == NULL) {
            ret = ch->key_shares.base != NULL ? PTLS_ALERT_HANDSHAKE_FAILURE : PTLS_ALERT_MISSING_EXTENSION;
            goto Exit;
        }
        if ((ret = key_share.algorithm->exchange(key_share.algorithm, &pubkey, &ecdh_secret, key_share.peer_key)) != 0) {
            assert(pubkey.base == NULL);
            assert(ecdh_secret.base == NULL);
            goto Exit;
        }
        tls->key_share = key_share.algorithm;
    }

    { /* send ServerHello */
        size_t ech_confirm_off = 0;
        EMIT_SERVER_HELLO(
            tls->key_schedule,
            {
                tls->ctx->random_bytes(emitter->buf->base + emitter->buf->off, PTLS_HELLO_RANDOM_SIZE);
                /* when accepting CHInner, last 8 byte of SH.random is zero for the handshake transcript */
                if (ptls_is_ech_handshake(tls, NULL, NULL, NULL)) {
                    ech_confirm_off = emitter->buf->off + PTLS_HELLO_RANDOM_SIZE - PTLS_ECH_CONFIRM_LENGTH;
                    memset(emitter->buf->base + ech_confirm_off, 0, PTLS_ECH_CONFIRM_LENGTH);
                }
            },
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
            },
            {
                if (ech_confirm_off != 0 &&
                    (ret = ech_calc_confirmation(
                         tls->key_schedule, emitter->buf->base + ech_confirm_off, tls->ech.inner_client_random,
                         ECH_CONFIRMATION_SERVER_HELLO,
                         ptls_iovec_init(emitter->buf->base + sh_start_off, emitter->buf->off - sh_start_off))) != 0)
                    goto Exit;
            });
    }

    /* processing of ECH is complete; dispose state */
    clear_ech(&tls->ech, 1);

    if ((ret = push_change_cipher_spec(tls, emitter)) != 0)
        goto Exit;

    /* create protection contexts for the handshake */
    assert(tls->key_schedule->generation == 1);
    key_schedule_extract(tls->key_schedule, ecdh_secret);
    if ((ret = setup_traffic_protection(tls, 1, "s hs traffic", 2, 0, 0)) != 0)
        goto Exit;
    if (tls->pending_handshake_secret != NULL) {
        if ((ret = derive_secret(tls->key_schedule, tls->pending_handshake_secret, "c hs traffic")) != 0)
            goto Exit;
        if (tls->ctx->update_traffic_key != NULL &&
            (ret = tls->ctx->update_traffic_key->cb(tls->ctx->update_traffic_key, tls, 0, 2, tls->pending_handshake_secret)) != 0)
            goto Exit;
    } else {
        if ((ret = setup_traffic_protection(tls, 0, "c hs traffic", 2, 0, 0)) != 0)
            goto Exit;
        if (ch->psk.early_data_indication)
            tls->server.early_data_skipped_bytes = 0;
    }

    /* send EncryptedExtensions */
    ptls_push_message(emitter, tls->key_schedule, PTLS_HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS, {
        ptls_buffer_t *sendbuf = emitter->buf;
        ptls_buffer_push_block(sendbuf, 2, {
            if (tls->server_name != NULL) {
                /* In this event, the server SHALL include an extension of type "server_name" in the (extended) server hello.
                 * The "extension_data" field of this extension SHALL be empty. (RFC 6066 section 3) */
                buffer_push_extension(sendbuf, PTLS_EXTENSION_TYPE_SERVER_NAME, {});
            }
            if (tls->ctx->use_raw_public_keys) {
                buffer_push_extension(sendbuf, PTLS_EXTENSION_TYPE_SERVER_CERTIFICATE_TYPE,
                                      { ptls_buffer_push(sendbuf, PTLS_CERTIFICATE_TYPE_RAW_PUBLIC_KEY); });
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
            /* send ECH retry_configs, if ECH was offered by rejected, even though we (the server) could have accepted ECH */
            if (tls->ech.offered && !ptls_is_ech_handshake(tls, NULL, NULL, NULL) && tls->ctx->ech.server.create_opener != NULL &&
                tls->ctx->ech.server.retry_configs.len != 0)
                buffer_push_extension(sendbuf, PTLS_EXTENSION_TYPE_ENCRYPTED_CLIENT_HELLO, {
                    ptls_buffer_pushv(sendbuf, tls->ctx->ech.server.retry_configs.base, tls->ctx->ech.server.retry_configs.len);
                });
            if (ch->ticket_request.new_session_count != 0 && tls->server.num_tickets_to_send != 0)
                buffer_push_extension(sendbuf, PTLS_EXTENSION_TYPE_TICKET_REQUEST,
                                      { ptls_buffer_push(sendbuf, tls->server.num_tickets_to_send); });
            if ((ret = push_additional_extensions(properties, sendbuf)) != 0)
                goto Exit;
        });
    });

    if (mode == HANDSHAKE_MODE_FULL) {
        /* send certificate request if client authentication is activated */
        if (tls->ctx->require_client_authentication) {
            ptls_push_message(emitter, tls->key_schedule, PTLS_HANDSHAKE_TYPE_CERTIFICATE_REQUEST, {
                ptls_buffer_t *sendbuf = emitter->buf;
                /* certificate_request_context: this field SHALL be zero length, unless the certificate request is used for post-
                 * handshake authentication. */
                ptls_buffer_push(sendbuf, 0);
                /* extensions */
                ptls_buffer_push_block(sendbuf, 2, {
                    buffer_push_extension(sendbuf, PTLS_EXTENSION_TYPE_SIGNATURE_ALGORITHMS, {
                        if ((ret = push_signature_algorithms(tls->ctx->verify_certificate, sendbuf)) != 0)
                            goto Exit;
                    });
                    /* certificate authorities entension */
                    if (tls->ctx->client_ca_names.count > 0) {
                        buffer_push_extension(sendbuf, PTLS_EXTENSION_TYPE_CERTIFICATE_AUTHORITIES, {
                            ptls_buffer_push_block(sendbuf, 2, {
                                for (size_t i = 0; i != tls->ctx->client_ca_names.count; ++i) {
                                    ptls_buffer_push_block(sendbuf, 2, {
                                        ptls_iovec_t name = tls->ctx->client_ca_names.list[i];
                                        ptls_buffer_pushv(sendbuf, name.base, name.len);
                                    });
                                }
                            });
                        });
                    }
                });
            });

            if (ret != 0) {
                goto Exit;
            }
        }

        /* send certificate */
        if ((ret = send_certificate(tls, emitter, &ch->signature_algorithms, ptls_iovec_init(NULL, 0), ch->status_request,
                                    ch->cert_compression_algos.list, ch->cert_compression_algos.count)) != 0)
            goto Exit;
        /* send certificateverify, finished, and complete the handshake */
        if ((ret = server_finish_handshake(tls, emitter, 1, &ch->signature_algorithms)) != 0)
            goto Exit;
    } else {
        /* send finished, and complete the handshake */
        if ((ret = server_finish_handshake(tls, emitter, 0, NULL)) != 0)
            goto Exit;
    }

Exit:
    free(pubkey.base);
    if (ecdh_secret.base != NULL) {
        ptls_clear_memory(ecdh_secret.base, ecdh_secret.len);
        free(ecdh_secret.base);
    }
    free(ech.encoded_ch_inner);
    free(ech.ch_outer_aad);
    ptls_buffer_dispose(&ech.ch_inner);
    free(ch);
    return ret;

#undef EMIT_SERVER_HELLO
#undef EMIT_HELLO_RETRY_REQUEST
}

static int server_finish_handshake(ptls_t *tls, ptls_message_emitter_t *emitter, int send_cert_verify,
                                   struct st_ptls_signature_algorithms_t *signature_algorithms)
{
    int ret;

    if (send_cert_verify) {
        if ((ret = send_certificate_verify(tls, emitter, signature_algorithms, PTLS_SERVER_CERTIFICATE_VERIFY_CONTEXT_STRING)) !=
            0) {
            if (ret == PTLS_ERROR_ASYNC_OPERATION) {
                tls->state = PTLS_STATE_SERVER_GENERATING_CERTIFICATE_VERIFY;
            }
            goto Exit;
        }
    }

    if ((ret = send_finished(tls, emitter)) != 0)
        goto Exit;

    assert(tls->key_schedule->generation == 2);
    if ((ret = key_schedule_extract(tls->key_schedule, ptls_iovec_init(NULL, 0))) != 0)
        goto Exit;
    if ((ret = setup_traffic_protection(tls, 1, "s ap traffic", 3, 0, 0)) != 0)
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
    if (tls->server.num_tickets_to_send != 0) {
        assert(tls->ctx->ticket_lifetime != 0);
        for (uint8_t i = 0; i < tls->server.num_tickets_to_send; ++i)
            if ((ret = send_session_ticket(tls, emitter)) != 0)
                goto Exit;
    }

    if (tls->ctx->require_client_authentication) {
        ret = PTLS_ERROR_IN_PROGRESS;
    } else {
        ret = 0;
    }

Exit:
    return ret;
}

static int server_handle_end_of_early_data(ptls_t *tls, ptls_iovec_t message)
{
    int ret;

    if ((ret = commission_handshake_secret(tls)) != 0)
        goto Exit;

    ptls__key_schedule_update_hash(tls->key_schedule, message.base, message.len, 0);
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
    if ((ret = setup_traffic_protection(tls, 0, NULL, 3, 0, 0)) != 0)
        return ret;

    ptls__key_schedule_update_hash(tls->key_schedule, message.base, message.len, 0);

    tls->state = PTLS_STATE_SERVER_POST_HANDSHAKE;
    return 0;
}

static int update_traffic_key(ptls_t *tls, int is_enc)
{
    struct st_ptls_traffic_protection_t *tp = is_enc ? &tls->traffic_protection.enc : &tls->traffic_protection.dec;
    uint8_t secret[PTLS_MAX_DIGEST_SIZE];
    int ret;

    ptls_hash_algorithm_t *hash = tls->key_schedule->hashes[0].algo;
    if ((ret = ptls_hkdf_expand_label(hash, secret, hash->digest_size, ptls_iovec_init(tp->secret, hash->digest_size),
                                      "traffic upd", ptls_iovec_init(NULL, 0), NULL)) != 0)
        goto Exit;
    memcpy(tp->secret, secret, sizeof(secret));
    ret = setup_traffic_protection(tls, is_enc, NULL, 3, 0, 1);

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

    assert(*len != 0);

    /* Check if the first byte is something that we can handle, otherwise do not bother parsing / buffering the entire record as it
     * is obviously broken. SSL 2.0 handshakes fall into this path as well. */
    if (tls->recvbuf.rec.base == NULL) {
        uint8_t type = src[0];
        switch (type) {
        case PTLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC:
        case PTLS_CONTENT_TYPE_ALERT:
        case PTLS_CONTENT_TYPE_HANDSHAKE:
        case PTLS_CONTENT_TYPE_APPDATA:
            break;
        default:
            return PTLS_ALERT_DECODE_ERROR;
        }
    }

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

    /* check consistency of `ptls_context_t` before instantiating a connection object */
    assert(ctx->get_time != NULL && "please set ctx->get_time to `&ptls_get_time`; see #92");
    if (ctx->pre_shared_key.identity.base != NULL) {
        assert(ctx->pre_shared_key.identity.len != 0 && ctx->pre_shared_key.secret.base != NULL &&
               ctx->pre_shared_key.secret.len != 0 && ctx->pre_shared_key.hash != NULL &&
               "`ptls_context_t::pre_shared_key` in incosistent state");
    } else {
        assert(ctx->pre_shared_key.identity.len == 0 && ctx->pre_shared_key.secret.base == NULL &&
               ctx->pre_shared_key.secret.len == 0 && ctx->pre_shared_key.hash == NULL &&
               "`ptls_context_t::pre_shared_key` in inconsitent state");
    }

    if ((tls = malloc(sizeof(*tls))) == NULL)
        return NULL;

    update_open_count(ctx, 1);
    *tls = (ptls_t){ctx};
    tls->is_server = is_server;
    tls->send_change_cipher_spec = ctx->send_change_cipher_spec;

#if PTLS_HAVE_LOG
    if (ptls_log_conn_state_override != NULL) {
        tls->log_state = *ptls_log_conn_state_override;
    } else {
        ptls_log_init_conn_state(&tls->log_state, ctx->random_bytes);
    }
#endif

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
    PTLS_LOG_CONN(new, tls, { PTLS_LOG_ELEMENT_BOOL(is_server, 0); });
    return tls;
}

ptls_t *ptls_server_new(ptls_context_t *ctx)
{
    ptls_t *tls = new_instance(ctx, 1);
    tls->state = PTLS_STATE_SERVER_EXPECT_CLIENT_HELLO;
    tls->server.early_data_skipped_bytes = UINT32_MAX;

    PTLS_PROBE(NEW, tls, 1);
    PTLS_LOG_CONN(new, tls, { PTLS_LOG_ELEMENT_BOOL(is_server, 1); });
    return tls;
}

#define export_tls_params(output, is_server, session_reused, protocol_version, cipher, client_random, server_name,                 \
                          negotiated_protocol, ver_block)                                                                          \
    do {                                                                                                                           \
        const char *_server_name = (server_name);                                                                                  \
        ptls_iovec_t _negotiated_protocol = (negotiated_protocol);                                                                 \
        ptls_buffer_push_block((output), 2, {                                                                                      \
            ptls_buffer_push((output), (is_server));                                                                               \
            ptls_buffer_push((output), (session_reused));                                                                          \
            ptls_buffer_push16((output), (protocol_version));                                                                      \
            ptls_buffer_push16((output), (cipher)->id);                                                                            \
            ptls_buffer_pushv((output), (client_random), PTLS_HELLO_RANDOM_SIZE);                                                  \
            ptls_buffer_push_block((output), 2, {                                                                                  \
                size_t len = _server_name != NULL ? strlen(_server_name) : 0;                                                      \
                ptls_buffer_pushv((output), _server_name, len);                                                                    \
            });                                                                                                                    \
            ptls_buffer_push_block((output), 2,                                                                                    \
                                   { ptls_buffer_pushv((output), _negotiated_protocol.base, _negotiated_protocol.len); });         \
            ptls_buffer_push_block((output), 2, {ver_block}); /* version-specific block */                                         \
            ptls_buffer_push_block((output), 2, {});          /* for future extensions */                                          \
        });                                                                                                                        \
    } while (0)

static int export_tls12_params(ptls_buffer_t *output, int is_server, int session_reused, ptls_cipher_suite_t *cipher,
                               const void *client_random, const char *server_name, ptls_iovec_t negotiated_protocol,
                               const void *enc_key, const void *enc_iv, uint64_t enc_seq, uint64_t enc_record_iv,
                               const void *dec_key, const void *dec_iv, uint64_t dec_seq)
{
    int ret;

    export_tls_params(output, is_server, session_reused, PTLS_PROTOCOL_VERSION_TLS12, cipher, client_random, server_name,
                      negotiated_protocol, {
                          ptls_buffer_pushv(output, enc_key, cipher->aead->key_size);
                          ptls_buffer_pushv(output, enc_iv, cipher->aead->tls12.fixed_iv_size);
                          ptls_buffer_push64(output, enc_seq);
                          if (cipher->aead->tls12.record_iv_size != 0)
                              ptls_buffer_push64(output, enc_record_iv);
                          ptls_buffer_pushv(output, dec_key, cipher->aead->key_size);
                          ptls_buffer_pushv(output, dec_iv, cipher->aead->tls12.fixed_iv_size);
                          ptls_buffer_push64(output, dec_seq);
                      });
    ret = 0;

Exit:
    return ret;
}

int ptls_build_tls12_export_params(ptls_context_t *ctx, ptls_buffer_t *output, int is_server, int session_reused,
                                   ptls_cipher_suite_t *cipher, const void *master_secret, const void *hello_randoms,
                                   uint64_t next_send_record_iv, const char *server_name, ptls_iovec_t negotiated_protocol)
{
    assert(cipher->aead->tls12.fixed_iv_size + cipher->aead->tls12.record_iv_size != 0 || !"given cipher-suite supports TLS/1.2");

    uint8_t key_block[(PTLS_MAX_SECRET_SIZE + PTLS_MAX_IV_SIZE) * 2];
    size_t key_block_len = (cipher->aead->key_size + cipher->aead->tls12.fixed_iv_size) * 2;
    int ret;

    assert(key_block_len <= sizeof(key_block));

    /* generate key block */
    if ((ret =
             ptls_tls12_phash(cipher->hash, key_block, key_block_len, ptls_iovec_init(master_secret, PTLS_TLS12_MASTER_SECRET_SIZE),
                              "key expansion", ptls_iovec_init(hello_randoms, PTLS_HELLO_RANDOM_SIZE * 2))) != 0)
        goto Exit;

    /* determine key locations */
    struct {
        const void *key;
        const void *iv;
    } client_secret, server_secret, *enc_secret = is_server ? &server_secret : &client_secret,
                                    *dec_secret = is_server ? &client_secret : &server_secret;
    client_secret.key = key_block;
    server_secret.key = key_block + cipher->aead->key_size;
    client_secret.iv = key_block + cipher->aead->key_size * 2;
    server_secret.iv = key_block + cipher->aead->key_size * 2 + cipher->aead->tls12.fixed_iv_size;

    /* Serialize prams. Sequence number of the first application record is 1, because Finished is the only message sent after
     * ChangeCipherSpec. */
    ret = export_tls12_params(output, is_server, session_reused, cipher, (uint8_t *)hello_randoms + PTLS_HELLO_RANDOM_SIZE,
                              server_name, negotiated_protocol, enc_secret->key, enc_secret->iv, 1, next_send_record_iv,
                              dec_secret->key, dec_secret->iv, 1);

Exit:
    ptls_clear_memory(key_block, sizeof(key_block));
    return ret;
}

int ptls_export(ptls_t *tls, ptls_buffer_t *output)
{
    ptls_iovec_t negotiated_protocol =
        ptls_iovec_init(tls->negotiated_protocol, tls->negotiated_protocol != NULL ? strlen(tls->negotiated_protocol) : 0);
    int ret;

    if (tls->state != PTLS_STATE_SERVER_POST_HANDSHAKE) {
        ret = PTLS_ERROR_LIBRARY;
        goto Exit;
    }

    if (ptls_get_protocol_version(tls) == PTLS_PROTOCOL_VERSION_TLS13) {
        export_tls_params(output, tls->is_server, tls->is_psk_handshake, PTLS_PROTOCOL_VERSION_TLS13, tls->cipher_suite,
                          tls->client_random, tls->server_name, negotiated_protocol, {
                              ptls_buffer_pushv(output, tls->traffic_protection.enc.secret, tls->cipher_suite->hash->digest_size);
                              ptls_buffer_push64(output, tls->traffic_protection.enc.seq);
                              ptls_buffer_pushv(output, tls->traffic_protection.dec.secret, tls->cipher_suite->hash->digest_size);
                              ptls_buffer_push64(output, tls->traffic_protection.dec.seq);
                          });
        ret = 0;
    } else {
        if ((ret = export_tls12_params(output, tls->is_server, tls->is_psk_handshake, tls->cipher_suite, tls->client_random,
                                       tls->server_name, negotiated_protocol, tls->traffic_protection.enc.secret,
                                       tls->traffic_protection.enc.secret + PTLS_MAX_SECRET_SIZE, tls->traffic_protection.enc.seq,
                                       tls->traffic_protection.enc.tls12_enc_record_iv, tls->traffic_protection.dec.secret,
                                       tls->traffic_protection.dec.secret + PTLS_MAX_SECRET_SIZE,
                                       tls->traffic_protection.dec.seq)) != 0)
            goto Exit;
    }

Exit:
    return ret;
}

static int import_tls12_traffic_protection(ptls_t *tls, int is_enc, const uint8_t **src, const uint8_t *const end)
{
    struct st_ptls_traffic_protection_t *tp = is_enc ? &tls->traffic_protection.enc : &tls->traffic_protection.dec;

    if ((size_t)(end - *src) < tls->cipher_suite->aead->key_size + tls->cipher_suite->aead->tls12.fixed_iv_size + sizeof(uint64_t))
        return PTLS_ALERT_DECODE_ERROR;

    /* set properties */
    memcpy(tp->secret, *src, tls->cipher_suite->aead->key_size);
    *src += tls->cipher_suite->aead->key_size;
    memcpy(tp->secret + PTLS_MAX_SECRET_SIZE, *src, tls->cipher_suite->aead->tls12.fixed_iv_size);
    *src += tls->cipher_suite->aead->tls12.fixed_iv_size;
    if (ptls_decode64(&tp->seq, src, end) != 0)
        return PTLS_ALERT_DECODE_ERROR;
    if (is_enc && tls->cipher_suite->aead->tls12.record_iv_size != 0) {
        if (ptls_decode64(&tp->tls12_enc_record_iv, src, end) != 0)
            return PTLS_ALERT_DECODE_ERROR;
    }
    tp->tls12 = 1;

    /* instantiate aead */
    if ((tp->aead = ptls_aead_new_direct(tls->cipher_suite->aead, is_enc, tp->secret, tp->secret + PTLS_MAX_SECRET_SIZE)) == NULL)
        return PTLS_ERROR_NO_MEMORY;

    return 0;
}

static int import_tls13_traffic_protection(ptls_t *tls, int is_enc, const uint8_t **src, const uint8_t *const end)
{
    struct st_ptls_traffic_protection_t *tp = is_enc ? &tls->traffic_protection.enc : &tls->traffic_protection.dec;

    /* set properties */
    memcpy(tp->secret, *src, tls->cipher_suite->hash->digest_size);
    *src += tls->cipher_suite->hash->digest_size;
    if (ptls_decode64(&tp->seq, src, end) != 0)
        return PTLS_ALERT_DECODE_ERROR;

    if (setup_traffic_protection(tls, is_enc, NULL, 3, tp->seq, 0) != 0)
        return PTLS_ERROR_INCOMPATIBLE_KEY;

    return 0;
}

int ptls_import(ptls_context_t *ctx, ptls_t **tls, ptls_iovec_t params)
{
    const uint8_t *src = params.base, *const end = src + params.len;
    uint16_t protocol_version, csid;
    int ret;

    *tls = NULL;

    /* TODO handle flags like psk_handshake, ech_handshake as we add support for TLS/1.3 import */
    ptls_decode_block(src, end, 2, {
        /* instantiate, based on the is_server flag */
        if (end - src < 2) {
            ret = PTLS_ALERT_DECODE_ERROR;
            goto Exit;
        }
        if ((*tls = new_instance(ctx, *src++)) == NULL) {
            ret = PTLS_ERROR_NO_MEMORY;
            goto Exit;
        }
        (*tls)->is_psk_handshake = *src++;
        /* determine protocol version and cipher suite */
        if ((ret = ptls_decode16(&protocol_version, &src, end)) != 0)
            goto Exit;
        if ((ret = ptls_decode16(&csid, &src, end)) != 0)
            goto Exit;
        /* other version-independent stuff */
        if (end - src < PTLS_HELLO_RANDOM_SIZE) {
            ret = PTLS_ALERT_DECODE_ERROR;
            goto Exit;
        }
        memcpy((*tls)->client_random, src, PTLS_HELLO_RANDOM_SIZE);
        src += PTLS_HELLO_RANDOM_SIZE;
        ptls_decode_open_block(src, end, 2, {
            if (src != end) {
                if ((ret = ptls_set_server_name(*tls, (const char *)src, end - src)) != 0)
                    goto Exit;
                src = end;
            }
        });
        ptls_decode_open_block(src, end, 2, {
            if (src != end) {
                if ((ret = ptls_set_negotiated_protocol(*tls, (const char *)src, end - src)) != 0)
                    goto Exit;
                src = end;
            }
        });
        /* version-dependent stuff */
        ptls_decode_open_block(src, end, 2, {
            switch (protocol_version) {
            case PTLS_PROTOCOL_VERSION_TLS12:
                (*tls)->cipher_suite = ptls_find_cipher_suite(ctx->tls12_cipher_suites, csid);
                if ((*tls)->cipher_suite == NULL) {
                    ret = PTLS_ALERT_HANDSHAKE_FAILURE;
                    goto Exit;
                }
                /* setup AEAD keys */
                if ((ret = import_tls12_traffic_protection(*tls, 1, &src, end)) != 0)
                    goto Exit;
                if ((ret = import_tls12_traffic_protection(*tls, 0, &src, end)) != 0)
                    goto Exit;
                break;
            case PTLS_PROTOCOL_VERSION_TLS13:
                (*tls)->cipher_suite = ptls_find_cipher_suite(ctx->cipher_suites, csid);
                if ((*tls)->cipher_suite == NULL) {
                    ret = PTLS_ALERT_HANDSHAKE_FAILURE;
                    goto Exit;
                }
                /* setup AEAD keys */
                if (((*tls)->key_schedule = key_schedule_new((*tls)->cipher_suite, NULL, (*tls)->ech.aead != NULL)) == NULL) {
                    ret = PTLS_ERROR_NO_MEMORY;
                    goto Exit;
                }
                if ((ret = import_tls13_traffic_protection(*tls, 1, &src, end)) != 0)
                    goto Exit;
                if ((ret = import_tls13_traffic_protection(*tls, 0, &src, end)) != 0)
                    goto Exit;
                break;
            default:
                ret = PTLS_ALERT_ILLEGAL_PARAMETER;
                goto Exit;
            }
        });
        /* extensions */
        ptls_decode_open_block(src, end, 2, {
            src = end; /* unused */
        });
    });

    (*tls)->state = ptls_is_server(*tls) ? PTLS_STATE_SERVER_POST_HANDSHAKE : PTLS_STATE_CLIENT_POST_HANDSHAKE;

Exit:
    if (ret != 0) {
        if (*tls != NULL) {
            ptls_free(*tls);
            *tls = NULL;
        }
    }
    return ret;
}

void ptls_free(ptls_t *tls)
{
    PTLS_PROBE0(FREE, tls);
    PTLS_LOG_CONN(free, tls, {});

    ptls_buffer_dispose(&tls->recvbuf.rec);
    ptls_buffer_dispose(&tls->recvbuf.mess);
    free_exporter_master_secret(tls, 1);
    free_exporter_master_secret(tls, 0);
    if (tls->key_schedule != NULL)
        key_schedule_free(tls->key_schedule);
    if (tls->traffic_protection.dec.aead != NULL)
        ptls_aead_free(tls->traffic_protection.dec.aead);
    if (tls->traffic_protection.enc.aead != NULL)
        ptls_aead_free(tls->traffic_protection.enc.aead);
    free(tls->server_name);
    free(tls->negotiated_protocol);
    clear_ech(&tls->ech, tls->is_server);
    if (tls->is_server) {
        if (tls->server.async_job != NULL)
            tls->server.async_job->destroy_(tls->server.async_job);
    } else {
        if (tls->client.key_share_ctx != NULL)
            tls->client.key_share_ctx->on_exchange(&tls->client.key_share_ctx, 1, NULL, ptls_iovec_init(NULL, 0));
        if (tls->client.certificate_request.context.base != NULL)
            free(tls->client.certificate_request.context.base);
    }
    if (tls->certificate_verify.cb != NULL)
        tls->certificate_verify.cb(tls->certificate_verify.verify_ctx, 0, ptls_iovec_init(NULL, 0), ptls_iovec_init(NULL, 0));
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

ptls_async_job_t *ptls_get_async_job(ptls_t *tls)
{
    return tls->server.async_job;
}

ptls_iovec_t ptls_get_client_random(ptls_t *tls)
{
    return ptls_iovec_init(tls->client_random, PTLS_HELLO_RANDOM_SIZE);
}

ptls_cipher_suite_t *ptls_get_cipher(ptls_t *tls)
{
    return tls->cipher_suite;
}

uint16_t ptls_get_protocol_version(ptls_t *tls)
{
    if (tls->traffic_protection.enc.tls12)
        return PTLS_PROTOCOL_VERSION_TLS12;

    return PTLS_PROTOCOL_VERSION_TLS13;
}

int ptls_get_traffic_keys(ptls_t *tls, int is_enc, uint8_t *key, uint8_t *iv, uint64_t *seq)
{
    struct st_ptls_traffic_protection_t *ctx = is_enc ? &tls->traffic_protection.enc : &tls->traffic_protection.dec;
    int ret;

    if ((ret = get_traffic_keys(tls->cipher_suite->aead, tls->cipher_suite->hash, key, iv, ctx->secret, ptls_iovec_init(NULL, 0),
                                NULL)) != 0)
        return ret;
    *seq = ctx->seq;
    return 0;
}

const char *ptls_get_server_name(ptls_t *tls)
{
    return tls->server_name;
}

int ptls_set_server_name(ptls_t *tls, const char *server_name, size_t server_name_len)
{
    char *duped = NULL;

    if (server_name != NULL &&
        (duped = duplicate_as_str(server_name, server_name_len != 0 ? server_name_len : strlen(server_name))) == NULL)
        return PTLS_ERROR_NO_MEMORY;

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

    if (protocol != NULL && (duped = duplicate_as_str(protocol, protocol_len != 0 ? protocol_len : strlen(protocol))) == NULL)
        return PTLS_ERROR_NO_MEMORY;

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

int ptls_is_ech_handshake(ptls_t *tls, uint8_t *config_id, ptls_hpke_kem_t **kem, ptls_hpke_cipher_suite_t **cipher)
{
    if (tls->ech.accepted) {
        if (config_id != NULL)
            *config_id = tls->ech.config_id;
        if (kem != NULL)
            *kem = tls->ech.kem;
        if (cipher != NULL)
            *cipher = tls->ech.cipher;
        return 1;
    }
    return 0;
}

void **ptls_get_data_ptr(ptls_t *tls)
{
    return &tls->data_ptr;
}

ptls_log_conn_state_t *ptls_get_log_state(ptls_t *tls)
{
#if PTLS_HAVE_LOG
    return &tls->log_state;
#else
    return &ptls_log.dummy_conn_state;
#endif
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
    PTLS_LOG_CONN(receive_message, tls, {
        PTLS_LOG_ELEMENT_UNSIGNED(message, message.base[0]);
        PTLS_LOG_ELEMENT_UNSIGNED(len, message.len - PTLS_HANDSHAKE_HEADER_SIZE);
        PTLS_LOG_ELEMENT_SIGNED(result, ret);
    });

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
    PTLS_LOG_CONN(receive_message, tls, {
        PTLS_LOG_ELEMENT_UNSIGNED(message, message.base[0]);
        PTLS_LOG_ELEMENT_UNSIGNED(len, message.len - PTLS_HANDSHAKE_HEADER_SIZE);
        PTLS_LOG_ELEMENT_SIGNED(result, ret);
    });

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
        case PTLS_ERROR_ASYNC_OPERATION:
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

static int handle_input_tls12(ptls_t *tls, ptls_buffer_t *decryptbuf, const void *input, size_t *inlen)
{
    struct st_ptls_record_t rec;
    int ret;

    /* extract the record, or bail out */
    if ((ret = parse_record(tls, &rec, input, inlen)) != 0)
        return ret;
    assert(rec.fragment != NULL);

    const uint8_t *src = rec.fragment, *end = src + rec.length;
    uint64_t nonce;
    uint8_t aad[PTLS_TLS12_AAD_SIZE];

    /* determine the nonce */
    if (tls->traffic_protection.dec.aead->algo->tls12.record_iv_size != 0) {
        assert(tls->traffic_protection.dec.aead->algo->tls12.record_iv_size == 8);
        if ((ret = ptls_decode64(&nonce, &src, end)) != 0)
            goto Exit;
    } else {
        nonce = tls->traffic_protection.dec.seq;
    }

    /* determine cleartext length */
    size_t textlen = end - src;
    if (textlen < tls->traffic_protection.dec.aead->algo->tag_size) {
        ret = PTLS_ALERT_BAD_RECORD_MAC;
        goto Exit;
    }
    textlen -= tls->traffic_protection.dec.aead->algo->tag_size;

    /* build aad */
    build_tls12_aad(aad, rec.type, tls->traffic_protection.dec.seq, (uint16_t)textlen);

    /* decrypt input to decryptbuf */
    if ((ret = ptls_buffer_reserve(decryptbuf, textlen)) != 0)
        goto Exit;
    if (ptls_aead_decrypt(tls->traffic_protection.dec.aead, decryptbuf->base + decryptbuf->off, src, end - src, nonce, aad,
                          sizeof(aad)) != textlen) {
        ret = PTLS_ALERT_BAD_RECORD_MAC;
        goto Exit;
    }
    ++tls->traffic_protection.dec.seq;

    /* record-type specific action */
    switch (rec.type) {
    case PTLS_CONTENT_TYPE_APPDATA:
        /* if application data, retain the bytes being decrypted */
        decryptbuf->off += textlen;
        break;
    case PTLS_CONTENT_TYPE_ALERT:
        /* submit alert without adjusting decryptbuf, so that the decrypted data would be dropped after handling the alert */
        ret = handle_alert(tls, decryptbuf->base + decryptbuf->off, textlen);
        break;
    default:
        ret = PTLS_ALERT_UNEXPECTED_MESSAGE;
        break;
    }

Exit:
    ptls_buffer_dispose(&tls->recvbuf.rec);
    ptls_clear_memory(aad, sizeof(aad));
    return 0;
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
        return send_client_hello(tls, &emitter.super, properties, NULL);
    }
    case PTLS_STATE_SERVER_GENERATING_CERTIFICATE_VERIFY:
        return server_finish_handshake(tls, &emitter.super, 1, NULL);
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
    case PTLS_ERROR_ASYNC_OPERATION:
        break;
    default:
        /* Flush handshake messages that have been written partially. ECH_REQUIRED sticks out because it is a message sent
         * post-handshake compared to other alerts that are generating *during* the handshake. */
        if (ret != PTLS_ALERT_ECH_REQUIRED) {
            ptls_clear_memory(emitter.super.buf->base + sendbuf_orig_off, emitter.super.buf->off - sendbuf_orig_off);
            emitter.super.buf->off = sendbuf_orig_off;
        }
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
        if (tls->traffic_protection.dec.tls12) {
            ret = handle_input_tls12(tls, decryptbuf, input, &consumed);
        } else {
            ret = handle_input(tls, NULL, decryptbuf, input, &consumed, NULL);
        }
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
     * safety margin of approximately 2^-57 for Authenticated Encryption (AE) security." (RFC 8446 section 5.5).
     *
     * Key updates do not happen with tls 1.2, check `key_schedule` to see if we are using tls/1.3
     */
    if (tls->traffic_protection.enc.seq >= 16777216 && tls->key_schedule != NULL)
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
    ptls_aead_algorithm_t *algo = tls->traffic_protection.enc.aead->algo;

    if (tls->traffic_protection.enc.tls12) {
        return 5 + algo->tls12.record_iv_size + algo->tag_size;
    } else {
        return 6 + algo->tag_size;
    }
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

    if ((ret = ptls_hkdf_expand_label(algo, derived_secret, algo->digest_size, ptls_iovec_init(master_secret, algo->digest_size),
                                      label, ptls_iovec_init(algo->empty_digest, algo->digest_size), NULL)) != 0)
        goto Exit;
    ret = ptls_hkdf_expand_label(algo, output, outlen, ptls_iovec_init(derived_secret, algo->digest_size), "exporter",
                                 ptls_iovec_init(context_value_hash, algo->digest_size), NULL);

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

int ptls_hkdf_expand_label(ptls_hash_algorithm_t *algo, void *output, size_t outlen, ptls_iovec_t secret, const char *label,
                           ptls_iovec_t hash_value, const char *label_prefix)
{
    ptls_buffer_t hkdf_label;
    uint8_t hkdf_label_buf[80];
    int ret;

    ptls_buffer_init(&hkdf_label, hkdf_label_buf, sizeof(hkdf_label_buf));

    ptls_buffer_push16(&hkdf_label, (uint16_t)outlen);
    ptls_buffer_push_block(&hkdf_label, 1, {
        if (label_prefix == NULL)
            label_prefix = PTLS_HKDF_EXPAND_LABEL_PREFIX;
        ptls_buffer_pushv(&hkdf_label, label_prefix, strlen(label_prefix));
        ptls_buffer_pushv(&hkdf_label, label, strlen(label));
    });
    ptls_buffer_push_block(&hkdf_label, 1, { ptls_buffer_pushv(&hkdf_label, hash_value.base, hash_value.len); });

    ret = ptls_hkdf_expand(algo, output, outlen, secret, ptls_iovec_init(hkdf_label.base, hkdf_label.off));

Exit:
    ptls_buffer_dispose(&hkdf_label);
    return ret;
}

int ptls_tls12_phash(ptls_hash_algorithm_t *algo, void *output, size_t outlen, ptls_iovec_t secret, const char *label,
                     ptls_iovec_t seed)
{
    ptls_hash_context_t *hmac;
    uint8_t An[PTLS_MAX_DIGEST_SIZE];
    size_t output_off = 0;

    if ((hmac = ptls_hmac_create(algo, secret.base, secret.len)) == NULL)
        return PTLS_ERROR_NO_MEMORY;

    /* A(1) = HMAC_hash(secret, label + seed) */
    if (label != NULL)
        hmac->update(hmac, label, strlen(label));
    hmac->update(hmac, seed.base, seed.len);
    hmac->final(hmac, An, PTLS_HASH_FINAL_MODE_RESET);

    while (1) {
        /* output += HMAC_hash(secret, A(i) + label + seed) */
        hmac->update(hmac, An, algo->digest_size);
        if (label != NULL)
            hmac->update(hmac, label, strlen(label));
        hmac->update(hmac, seed.base, seed.len);
        if (outlen - output_off <= algo->digest_size) {
            /* digest of last chunk is at first written to An then the necessary bytes are copied to output */
            hmac->final(hmac, An, PTLS_HASH_FINAL_MODE_FREE);
            memcpy((uint8_t *)output + output_off, An, outlen - output_off);
            break;
        }
        hmac->final(hmac, (uint8_t *)output + output_off, PTLS_HASH_FINAL_MODE_RESET);
        output_off += algo->digest_size;

        /* A(i) = HMAC_hash(secret, A(i-1)) */
        hmac->update(hmac, An, algo->digest_size);
        hmac->final(hmac, An, PTLS_HASH_FINAL_MODE_RESET);
    }

    ptls_clear_memory(An, algo->digest_size);

    return 0;
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
    struct {
        uint8_t key[PTLS_MAX_SECRET_SIZE];
        uint8_t iv[PTLS_MAX_IV_SIZE];
    } key_iv;
    int ret;

    if ((ret = get_traffic_keys(aead, hash, key_iv.key, key_iv.iv, secret, hash_value, label_prefix)) != 0)
        goto Exit;
    ctx = ptls_aead_new_direct(aead, is_enc, key_iv.key, key_iv.iv);
Exit:
    ptls_clear_memory(&key_iv, sizeof(key_iv));
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

void ptls_aead_xor_iv(ptls_aead_context_t *ctx, const void *_bytes, size_t len)
{
    const uint8_t *bytes = _bytes;
    uint8_t iv[PTLS_MAX_IV_SIZE];

    ptls_aead_get_iv(ctx, iv);
    for (size_t i = 0; i < len; ++i)
        iv[i] ^= bytes[i];
    ptls_aead_set_iv(ctx, iv);
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
    case PTLS_STATE_SERVER_GENERATING_CERTIFICATE_VERIFY:
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

    if (tls->state == PTLS_STATE_SERVER_GENERATING_CERTIFICATE_VERIFY) {
        assert(input == NULL || inlen == 0);
        return server_finish_handshake(tls, &emitter.super, 1, NULL);
    }

    assert(input != NULL);

    if (ptls_get_read_epoch(tls) != in_epoch)
        return PTLS_ALERT_UNEXPECTED_MESSAGE;

    return handle_handshake_record(tls, handle_server_handshake_message, &emitter.super, &rec, properties);
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

int ptls_ech_encode_config(ptls_buffer_t *buf, uint8_t config_id, ptls_hpke_kem_t *kem, ptls_iovec_t public_key,
                           ptls_hpke_cipher_suite_t **ciphers, uint8_t max_name_length, const char *public_name)
{
    int ret;

    ptls_buffer_push16(buf, PTLS_ECH_CONFIG_VERSION);
    ptls_buffer_push_block(buf, 2, {
        ptls_buffer_push(buf, config_id);
        ptls_buffer_push16(buf, kem->id);
        ptls_buffer_push_block(buf, 2, { ptls_buffer_pushv(buf, public_key.base, public_key.len); });
        ptls_buffer_push_block(buf, 2, {
            for (size_t i = 0; ciphers[i] != NULL; ++i) {
                ptls_buffer_push16(buf, ciphers[i]->id.kdf);
                ptls_buffer_push16(buf, ciphers[i]->id.aead);
            }
        });
        ptls_buffer_push(buf, max_name_length);
        ptls_buffer_push_block(buf, 1, { ptls_buffer_pushv(buf, public_name, strlen(public_name)); });
        ptls_buffer_push_block(buf, 2, {/* extensions */});
    });

Exit:
    return ret;
}

static char *byte_to_hex(char *dst, uint8_t v)
{
    *dst++ = "0123456789abcdef"[v >> 4];
    *dst++ = "0123456789abcdef"[v & 0xf];
    return dst;
}

char *ptls_hexdump(char *dst, const void *_src, size_t len)
{
    char *buf = dst;
    const uint8_t *src = _src;

    for (size_t i = 0; i != len; ++i)
        dst = byte_to_hex(dst, src[i]);
    *dst = '\0';
    return buf;
}

char *ptls_jsonescape(char *buf, const char *unsafe_str, size_t len)
{
    char *dst = buf;
    const uint8_t *src = (const uint8_t *)unsafe_str, *end = src + len;

    for (; src != end; ++src) {
        switch (*src) {
#define MAP(ch, escaped)                                                                                                           \
    case ch:                                                                                                                       \
        memcpy(dst, (escaped), sizeof(escaped) - 1);                                                                               \
        dst += sizeof(escaped) - 1;                                                                                                \
        break
            MAP('"', "\\\"");
            MAP('\\', "\\\\");
            MAP('/', "\\/");
            MAP('\b', "\\b");
            MAP('\f', "\\f");
            MAP('\n', "\\n");
            MAP('\r', "\\r");
            MAP('\t', "\\t");
#undef MAP
        default:
            if (*src < 0x20 || *src == 0x7f) {
                *dst++ = '\\';
                *dst++ = 'u';
                *dst++ = '0';
                *dst++ = '0';
                dst = byte_to_hex(dst, *src);
            } else {
                *dst++ = *src;
            }
            break;
        }
    }
    *dst = '\0';

    return dst;
}

void ptls_build_v4_mapped_v6_address(struct in6_addr *v6, const struct in_addr *v4)
{
    *v6 = (struct in6_addr){.s6_addr[10] = 0xff, .s6_addr[11] = 0xff};
    memcpy(&v6->s6_addr[12], &v4->s_addr, 4);
}

struct st_ptls_log_t ptls_log = {
    .dummy_conn_state = {.random_ = 1 /* never log */},
    ._generation = 1, /* starts from 1 so that recalc can be forced by setting to zero (i.e., the initial) */
};
PTLS_THREADLOCAL ptls_log_conn_state_t *ptls_log_conn_state_override = NULL;

#if PTLS_HAVE_LOG

static struct {
    /**
     * list of connections; the slot is connected if points != NULL
     */
    struct {
        /**
         * file descriptor
         */
        int fd;
        /**
         * see `ptls_log_add_fd`
         */
        char *points;
        /**
         *
         */
        char *snis;
        /**
         * list of addresses terminated by ip6addr_any
         */
        struct in6_addr *addresses;
        /**
         *
         */
        float sample_ratio;
        /**
         *
         */
        unsigned appdata : 1;
    } conns[sizeof(((struct st_ptls_log_state_t *)NULL)->active_conns) * 8];
    /**
     * counts the number of writes that failed
     */
    size_t num_lost;
    /**
     * anchor of the single-linked list of log points; the tail refers to itself (i.e., point->next == point)
     */
    struct st_ptls_log_point_t *points;
    /**
     *
     */
    pthread_mutex_t mutex;
} logctx = {.mutex = PTHREAD_MUTEX_INITIALIZER};

static PTLS_THREADLOCAL struct {
    ptls_buffer_t buf; /* buf.base == NULL upon failre */
    char smallbuf[128];
    struct {
        char buf[sizeof(",\"tid\":-9223372036854775808")];
        size_t len;
    } tid;
} logbuf;

static void close_log_fd(size_t slot)
{
    assert(logctx.conns[slot].fd >= 0 && logctx.conns[slot].points != NULL);

    close(logctx.conns[slot].fd);

    /* clear the connection information */
    logctx.conns[slot].fd = -1;
    logctx.conns[slot].sample_ratio = 0;
    free(logctx.conns[slot].points);
    logctx.conns[slot].points = NULL;
    free(logctx.conns[slot].snis);
    logctx.conns[slot].snis = NULL;
    free(logctx.conns[slot].addresses);
    logctx.conns[slot].addresses = NULL;
    logctx.conns[slot].appdata = 0;
    ++ptls_log._generation;
}

static char *duplicate_stringlist(const char *input)
{
    if (input == NULL)
        return strdup("");

    char *result;
    const char *in_tail;

    for (in_tail = input; in_tail[0] != '\0'; in_tail += strlen(in_tail) + 1)
        ;
    ++in_tail;
    if ((result = malloc(in_tail - input)) == NULL)
        return NULL;
    memcpy(result, input, in_tail - input);
    return result;
}

static int is_in_stringlist(const char *list, const char *search_for)
{
    if (list[0] == '\0')
        return 1;

    if (search_for == NULL)
        return 0;

    for (const char *element = list; element[0] != '\0'; element += strlen(element) + 1)
        if (strcmp(element, search_for) == 0)
            return 1;
    return 0;
}

static int is_in_addresslist(const struct in6_addr *list, const struct in6_addr *search_for)
{
#define IS_EQUAL(x, y) (memcmp((x), (y), sizeof(struct in6_addr)) == 0)

    if (IS_EQUAL(&list[0], &in6addr_any))
        return 1;

    if (IS_EQUAL(search_for, &in6addr_any))
        return 0;

    for (const struct in6_addr *element = list; !IS_EQUAL(element, &in6addr_any); ++element)
        if (IS_EQUAL(element, search_for))
            return 1;
    return 0;

#undef IS_EQUAL
}

void ptls_log__recalc_point(int caller_locked, struct st_ptls_log_point_t *point)
{
    if (!caller_locked)
        pthread_mutex_lock(&logctx.mutex);

    if (point->state.generation != ptls_log._generation) {
        /* update active bitmap */
        uint32_t new_active = 0;
        for (size_t slot = 0; slot < PTLS_ELEMENTSOF(logctx.conns); ++slot)
            if (logctx.conns[slot].points != NULL && is_in_stringlist(logctx.conns[slot].points, point->name))
                new_active |= (uint32_t)1 << slot;
        point->state.active_conns = new_active;
        point->state.generation = ptls_log._generation;
    }

    if (!caller_locked)
        pthread_mutex_unlock(&logctx.mutex);
}

void ptls_log__recalc_conn(int caller_locked, struct st_ptls_log_conn_state_t *conn, const char *(*get_sni)(void *),
                           void *get_sni_arg)
{
    if (!caller_locked)
        pthread_mutex_lock(&logctx.mutex);

    if (conn->state.generation != ptls_log._generation) {
        /* update active bitmap */
        uint32_t new_active = 0;
        const char *sni = get_sni != NULL ? get_sni(get_sni_arg) : NULL;
        for (size_t slot = 0; slot < PTLS_ELEMENTSOF(logctx.conns); ++slot) {
            if (logctx.conns[slot].points != NULL && conn->random_ < logctx.conns[slot].sample_ratio &&
                is_in_stringlist(logctx.conns[slot].snis, sni) && is_in_addresslist(logctx.conns[slot].addresses, &conn->address)) {
                new_active |= (uint32_t)1 << slot;
            }
        }
        conn->state.active_conns = new_active;
        conn->state.generation = ptls_log._generation;
    }

    if (!caller_locked)
        pthread_mutex_unlock(&logctx.mutex);
}

static int expand_logbuf_or_invalidate(const char *prefix, size_t prefix_len, size_t capacity)
{
    if (logbuf.buf.base == NULL)
        return 0;

    if (ptls_buffer_reserve(&logbuf.buf, prefix_len + capacity) != 0) {
        ptls_buffer_dispose(&logbuf.buf);
        assert(logbuf.buf.base == NULL);
        return 0;
    }

    memcpy(logbuf.buf.base + logbuf.buf.off, prefix, prefix_len);
    logbuf.buf.off += prefix_len;

    return 1;
}

__attribute__((format(printf, 4, 5))) static void pushf_logbuf_or_invalidate(const char *prefix, size_t prefix_len, size_t capacity,
                                                                             const char *fmt, ...)
{
    if (!expand_logbuf_or_invalidate(prefix, prefix_len, capacity))
        return;

    va_list args;
    va_start(args, fmt);
    int l = vsnprintf((char *)logbuf.buf.base + logbuf.buf.off, logbuf.buf.capacity - logbuf.buf.off, fmt, args);
    va_end(args);

    assert(l < logbuf.buf.capacity - logbuf.buf.off && "insufficent capacity");
    logbuf.buf.off += l;
}

void ptls_log__do_push_element_safestr(const char *prefix, size_t prefix_len, const char *s, size_t l)
{
    if (expand_logbuf_or_invalidate(prefix, prefix_len, l + 2)) {
        logbuf.buf.base[logbuf.buf.off++] = '"';
        memcpy(logbuf.buf.base + logbuf.buf.off, s, l);
        logbuf.buf.off += l;
        logbuf.buf.base[logbuf.buf.off++] = '"';
    }
}

void ptls_log__do_push_element_unsafestr(const char *prefix, size_t prefix_len, const char *s, size_t l)
{
    if (expand_logbuf_or_invalidate(prefix, prefix_len, l * (sizeof("\\uXXXX") - 1) + 2)) {
        logbuf.buf.base[logbuf.buf.off++] = '"';
        logbuf.buf.off = (uint8_t *)ptls_jsonescape((char *)logbuf.buf.base + logbuf.buf.off, s, l) - logbuf.buf.base;
        logbuf.buf.base[logbuf.buf.off++] = '"';
    }
}

void ptls_log__do_push_element_hexdump(const char *prefix, size_t prefix_len, const void *s, size_t l)
{
    if (expand_logbuf_or_invalidate(prefix, prefix_len, l * 2 + 2)) {
        logbuf.buf.base[logbuf.buf.off++] = '"';
        ptls_hexdump((char *)logbuf.buf.base + logbuf.buf.off, s, l);
        logbuf.buf.off += l * 2;
        logbuf.buf.base[logbuf.buf.off++] = '"';
    }
}

void ptls_log__do_push_element_signed32(const char *prefix, size_t prefix_len, int32_t v)
{
    pushf_logbuf_or_invalidate(prefix, prefix_len, sizeof("-2147483648"), "%" PRId32, v);
}

void ptls_log__do_push_element_signed64(const char *prefix, size_t prefix_len, int64_t v)
{
    pushf_logbuf_or_invalidate(prefix, prefix_len, sizeof("-9223372036854775808"), "%" PRId64, v);
}

void ptls_log__do_push_element_unsigned32(const char *prefix, size_t prefix_len, uint32_t v)
{
    pushf_logbuf_or_invalidate(prefix, prefix_len, sizeof("4294967295"), "%" PRIu32, v);
}

void ptls_log__do_push_element_unsigned64(const char *prefix, size_t prefix_len, uint64_t v)
{
    pushf_logbuf_or_invalidate(prefix, prefix_len, sizeof("18446744073709551615"), "%" PRIu64, v);
}

void ptls_log__do_push_element_bool(const char *prefix, size_t prefix_len, int v)
{
    if (expand_logbuf_or_invalidate(prefix, prefix_len, 5)) {
        if (v) {
            memcpy(logbuf.buf.base + logbuf.buf.off, "true", 4);
            logbuf.buf.off += 4;
        } else {
            memcpy(logbuf.buf.base + logbuf.buf.off, "false", 5);
            logbuf.buf.off += 5;
        }
    }
}

void ptls_log__do_write_start(struct st_ptls_log_point_t *point, int add_time)
{
    assert(logbuf.buf.base == NULL);
    ptls_buffer_init(&logbuf.buf, logbuf.smallbuf, sizeof(logbuf.smallbuf));

    /* add module and type name */
    const char *colon_at = strchr(point->name, ':');
    int written = snprintf((char *)logbuf.buf.base, logbuf.buf.capacity, "{\"module\":\"%.*s\",\"type\":\"%s\"",
                           (int)(colon_at - point->name), point->name, colon_at + 1);

    /* obtain and stringify thread id once */
    if (logbuf.tid.len == 0) {
#if defined(__linux__)
        logbuf.tid.len = sprintf(logbuf.tid.buf, ",\"tid\":%" PRId64, (int64_t)syscall(SYS_gettid));
#elif defined(__APPLE__)
        uint64_t t = 0;
        (void)pthread_threadid_np(NULL, &t);
        logbuf.tid.len = sprintf(logbuf.tid.buf, ",\"tid\":%" PRIu64, t);
#else
        /* other platforms: skip emitting tid, by keeping logbuf.tid.len == 0 */
#endif
    }
    /* append tid */
    assert(written > 0 && written + logbuf.tid.len < logbuf.buf.capacity);
    memcpy((char *)logbuf.buf.base + written, logbuf.tid.buf, logbuf.tid.len + 1);
    written += logbuf.tid.len;

    /* append time if requested */
    if (add_time) {
        struct timeval tv;
        gettimeofday(&tv, NULL);
        written += snprintf((char *)logbuf.buf.base + written, logbuf.buf.capacity - written, ",\"time\":%" PRIu64,
                            (uint64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000);
    }
    assert(written > 0 && written < logbuf.buf.capacity && "caller MUST provide smallbuf suffient to emit the prefix");

    logbuf.buf.off = (size_t)written;
}

int ptls_log__do_write_end(struct st_ptls_log_point_t *point, struct st_ptls_log_conn_state_t *conn, const char *(*get_sni)(void *),
                           void *get_sni_arg, int includes_appdata)
{
    if (!expand_logbuf_or_invalidate("}\n", 2, 0))
        return 0;

    int needs_appdata = 0;

    pthread_mutex_lock(&logctx.mutex);

    /* calc the active conn bits, updating stale information if necessary */
    if (point->state.generation != ptls_log._generation)
        ptls_log__recalc_point(1, point);
    uint32_t active = point->state.active_conns;
    if (conn != NULL && conn->state.generation != ptls_log._generation) {
        ptls_log__recalc_conn(1, conn, get_sni, get_sni_arg);
        active &= conn->state.active_conns;
    }

    /* iterate through the active connctions */
    for (size_t slot = 0; active != 0; ++slot, active >>= 1) {
        if ((active & 1) == 0)
            continue;

        assert(logctx.conns[slot].points != NULL);

        if (logctx.conns[slot].appdata != includes_appdata) {
            if (!includes_appdata && ptls_log.may_include_appdata)
                needs_appdata = 1;
            continue;
        }

        /* write */
        ssize_t wret;
        while ((wret = write(logctx.conns[slot].fd, logbuf.buf.base, logbuf.buf.off)) == -1 && errno == EINTR)
            ;
        if (wret == logbuf.buf.off) {
            /* success */
        } else if (wret > 0 || (wret == -1 && (errno == EAGAIN || errno == EWOULDBLOCK))) {
            /* partial write or buffer full */
            ++logctx.num_lost;
        } else {
            /* write error; close and unregister the connection */
            close_log_fd(slot);
        }
    }

    pthread_mutex_unlock(&logctx.mutex);

    if (includes_appdata)
        assert(!needs_appdata);

    ptls_buffer_dispose(&logbuf.buf);
    assert(logbuf.buf.base == NULL);
    return needs_appdata;
}

#endif

void ptls_log_init_conn_state(ptls_log_conn_state_t *state, void (*random_bytes)(void *, size_t))
{
    uint32_t r;
    random_bytes(&r, sizeof(r));

    *state = (ptls_log_conn_state_t){
        .random_ = (float)r / ((uint64_t)UINT32_MAX + 1), /* [0..1), so that any(r) < sample_ratio where sample_ratio is [0..1] */
        .address = in6addr_any,
    };
}

size_t ptls_log_num_lost(void)
{
#if PTLS_HAVE_LOG
    return logctx.num_lost;
#else
    return 0;
#endif
}

int ptls_log_add_fd(int fd, float sample_ratio, const char *_points, const char *_snis, const char *_addresses, int appdata)
{
#if PTLS_HAVE_LOG

    char *points = NULL, *snis = NULL;
    struct in6_addr *addresses = NULL;
    int ret;

    pthread_mutex_lock(&logctx.mutex);

    if ((points = duplicate_stringlist(_points)) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }
    if ((snis = duplicate_stringlist(_snis)) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }
    {
        size_t num_addresses = 0;
        for (const char *input = _addresses; input != NULL && *input != '\0'; input += strlen(input) + 1)
            ++num_addresses;
        if ((addresses = malloc(sizeof(*addresses) * (num_addresses + 1))) == NULL) {
            ret = PTLS_ERROR_NO_MEMORY;
            goto Exit;
        }
        size_t index = 0;
        for (const char *input = _addresses; input != NULL && *input != '\0'; input += strlen(input) + 1) {
            /* note: for consistency to the handling of points, erroneous input is ignored. V4 addresses will use the mapped form
             * (::ffff:192.0.2.1) */
            if (!inet_pton(AF_INET6, input, &addresses[index])) {
                struct in_addr v4;
                if (!inet_pton(AF_INET, input, &v4))
                    continue;
                ptls_build_v4_mapped_v6_address(&addresses[index], &v4);
            }
            if (memcmp(&addresses[index], &in6addr_any, sizeof(struct in6_addr)) == 0)
                continue;
            ++index;
        }
        addresses[index] = in6addr_any;
    }

    /* find slot, or return if not available */
    size_t slot_index;
    for (slot_index = 0; slot_index < PTLS_ELEMENTSOF(logctx.conns); ++slot_index)
        if (logctx.conns[slot_index].points == NULL)
            break;
    if (slot_index == PTLS_ELEMENTSOF(logctx.conns)) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }

    /* setup the slot */
    logctx.conns[slot_index].fd = fd;
    logctx.conns[slot_index].points = points;
    logctx.conns[slot_index].snis = snis;
    logctx.conns[slot_index].addresses = addresses;
    logctx.conns[slot_index].sample_ratio = sample_ratio;
    logctx.conns[slot_index].appdata = appdata;
    ++ptls_log._generation;

    ret = 0; /* success */

Exit:
    pthread_mutex_unlock(&logctx.mutex);
    if (ret != 0) {
        free(points);
        free(snis);
        free(addresses);
    }
    return ret;

#else
    return PTLS_ERROR_NOT_AVAILABLE;
#endif
}
