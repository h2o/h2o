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
#include <sys/time.h>
#endif
#include "picotls.h"

#define PTLS_MAX_PLAINTEXT_RECORD_SIZE 16384
#define PTLS_MAX_ENCRYPTED_RECORD_SIZE (16384 + 256)

#define PTLS_RECORD_VERSION_MAJOR 3
#define PTLS_RECORD_VERSION_MINOR 3

#define PTLS_HELLO_RANDOM_SIZE 32

#define PTLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC 20
#define PTLS_CONTENT_TYPE_ALERT 21
#define PTLS_CONTENT_TYPE_HANDSHAKE 22
#define PTLS_CONTENT_TYPE_APPDATA 23

#define PTLS_HANDSHAKE_TYPE_CLIENT_HELLO 1
#define PTLS_HANDSHAKE_TYPE_SERVER_HELLO 2
#define PTLS_HANDSHAKE_TYPE_NEW_SESSION_TICKET 4
#define PTLS_HANDSHAKE_TYPE_END_OF_EARLY_DATA 5
#define PTLS_HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS 8
#define PTLS_HANDSHAKE_TYPE_CERTIFICATE 11
#define PTLS_HANDSHAKE_TYPE_CERTIFICATE_REQUEST 13
#define PTLS_HANDSHAKE_TYPE_CERTIFICATE_VERIFY 15
#define PTLS_HANDSHAKE_TYPE_FINISHED 20
#define PTLS_HANDSHAKE_TYPE_KEY_UPDATE 24
#define PTLS_HANDSHAKE_TYPE_MESSAGE_HASH 254

#define PTLS_PSK_KE_MODE_PSK 0
#define PTLS_PSK_KE_MODE_PSK_DHE 1

#define PTLS_HANDSHAKE_HEADER_SIZE 4

#define PTLS_EXTENSION_TYPE_SERVER_NAME 0
#define PTLS_EXTENSION_TYPE_STATUS_REQUEST 5
#define PTLS_EXTENSION_TYPE_SUPPORTED_GROUPS 10
#define PTLS_EXTENSION_TYPE_SIGNATURE_ALGORITHMS 13
#define PTLS_EXTENSION_TYPE_ALPN 16
#define PTLS_EXTENSION_TYPE_PRE_SHARED_KEY 41
#define PTLS_EXTENSION_TYPE_EARLY_DATA 42
#define PTLS_EXTENSION_TYPE_SUPPORTED_VERSIONS 43
#define PTLS_EXTENSION_TYPE_COOKIE 44
#define PTLS_EXTENSION_TYPE_PSK_KEY_EXCHANGE_MODES 45
#define PTLS_EXTENSION_TYPE_KEY_SHARE 51

#define PTLS_PROTOCOL_VERSION_DRAFT26 0x7f1a
#define PTLS_PROTOCOL_VERSION_DRAFT27 0x7f1b
#define PTLS_PROTOCOL_VERSION_DRAFT28 0x7f1c

#define PTLS_SERVER_NAME_TYPE_HOSTNAME 0

#define PTLS_SERVER_CERTIFICATE_VERIFY_CONTEXT_STRING "TLS 1.3, server CertificateVerify"
#define PTLS_CLIENT_CERTIFICATE_VERIFY_CONTEXT_STRING "TLS 1.3, client CertificateVerify"
#define PTLS_MAX_CERTIFICATE_VERIFY_SIGNDATA_SIZE                                                                                  \
    (64 + sizeof(PTLS_SERVER_CERTIFICATE_VERIFY_CONTEXT_STRING) + PTLS_MAX_DIGEST_SIZE * 2)

#define PTLS_EARLY_DATA_MAX_DELAY 10000 /* max. RTT (in msec) to permit early data */

#if defined(PTLS_DEBUG) && PTLS_DEBUG
#define PTLS_DEBUGF(...) fprintf(stderr, __VA_ARGS__)
#else
#define PTLS_DEBUGF(...)
#endif

#ifndef PTLS_MEMORY_DEBUG
#define PTLS_MEMORY_DEBUG 0
#endif

/**
 * list of supported versions in the preferred order
 */
static const uint16_t supported_versions[] = {PTLS_PROTOCOL_VERSION_DRAFT28, PTLS_PROTOCOL_VERSION_DRAFT27,
                                              PTLS_PROTOCOL_VERSION_DRAFT26};

static const uint8_t hello_retry_random[PTLS_HELLO_RANDOM_SIZE] = {0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C,
                                                                   0x02, 0x1E, 0x65, 0xB8, 0x91, 0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB,
                                                                   0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C};

struct st_ptls_traffic_protection_t {
    uint8_t secret[PTLS_MAX_DIGEST_SIZE];
    ptls_aead_context_t *aead;
    uint64_t seq;
};

struct st_ptls_early_data_t {
    uint8_t next_secret[PTLS_MAX_DIGEST_SIZE];
};

struct st_ptls_t {
    /**
     * the context
     */
    ptls_context_t *ctx;
    /**
     * the state
     */
    enum {
        PTLS_STATE_CLIENT_HANDSHAKE_START,
        PTLS_STATE_CLIENT_EXPECT_SERVER_HELLO,
        PTLS_STATE_CLIENT_EXPECT_SECOND_SERVER_HELLO,
        PTLS_STATE_CLIENT_EXPECT_ENCRYPTED_EXTENSIONS,
        PTLS_STATE_CLIENT_EXPECT_CERTIFICATE,
        PTLS_STATE_CLIENT_EXPECT_CERTIFICATE_VERIFY,
        PTLS_STATE_CLIENT_EXPECT_FINISHED,
        PTLS_STATE_SERVER_EXPECT_CLIENT_HELLO,
        PTLS_STATE_SERVER_EXPECT_SECOND_CLIENT_HELLO,
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
    struct st_ptls_key_schedule_t *key_schedule;
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
    /* flags */
    unsigned is_server : 1;
    unsigned is_psk_handshake : 1;
    unsigned skip_early_data : 1; /* if early-data is not recognized by the server */
    unsigned send_change_cipher_spec : 1;
    /**
     * exporter master secret (either 0rtt or 1rtt)
     */
    struct {
        uint8_t *early;
        uint8_t *one_rtt;
    } exporter_master_secret;
    /**
     * misc.
     */
    union {
        struct {
            uint8_t legacy_session_id[16];
            ptls_key_exchange_context_t *key_share_ctx;
            struct {
                int (*cb)(void *verify_ctx, ptls_iovec_t data, ptls_iovec_t signature);
                void *verify_ctx;
            } certificate_verify;
            unsigned offered_psk : 1;
        } client;
        struct {
            uint8_t pending_traffic_secret[PTLS_MAX_DIGEST_SIZE];
        } server;
    };
    /**
     * the value contains the traffic secret to be commisioned after END_OF_EARLY_DATA
     * END_OF_EARLY_DATA
     */
    struct st_ptls_early_data_t *early_data;
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

struct st_ptls_client_hello_t {
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
    struct {
        uint16_t list[16]; /* expand? */
        size_t count;
    } signature_algorithms;
    ptls_iovec_t server_name;
    struct {
        ptls_iovec_t list[16];
        size_t count;
    } alpn;
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
        int early_data_indication;
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

static uint8_t zeroes_of_max_digest_size[PTLS_MAX_DIGEST_SIZE] = {0};

static int is_supported_version(uint16_t v)
{
    size_t i;
    for (i = 0; i != sizeof(supported_versions) / sizeof(supported_versions[0]); ++i)
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
    });
    EXT(SUPPORTED_GROUPS, {
        ALLOW(CLIENT_HELLO);
        ALLOW(ENCRYPTED_EXTENSIONS);
    });
    EXT(SIGNATURE_ALGORITHMS, { ALLOW(CLIENT_HELLO); });
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

static uint16_t ntoh16(const uint8_t *src)
{
    return (uint16_t)src[0] << 8 | src[1];
}

static uint32_t ntoh24(const uint8_t *src)
{
    return (uint32_t)src[0] << 16 | (uint32_t)src[1] << 8 | src[2];
}

static uint32_t ntoh32(const uint8_t *src)
{
    return (uint32_t)src[0] << 24 | (uint32_t)src[1] << 16 | (uint32_t)src[2] << 8 | src[3];
}

static uint64_t ntoh64(const uint8_t *src)
{
    return (uint64_t)src[0] << 56 | (uint64_t)src[1] << 48 | (uint64_t)src[2] << 40 | (uint64_t)src[3] << 32 |
           (uint64_t)src[4] << 24 | (uint64_t)src[5] << 16 | (uint64_t)src[6] << 8 | src[7];
}

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

#define buffer_push_handshake_body(buf, key_sched, type, block)                                                                    \
    do {                                                                                                                           \
        size_t mess_start = (buf)->off;                                                                                            \
        ptls_buffer_push((buf), (type));                                                                                           \
        ptls_buffer_push_block((buf), 3, {                                                                                         \
            do {                                                                                                                   \
                block                                                                                                              \
            } while (0);                                                                                                           \
        });                                                                                                                        \
        if ((key_sched) != NULL)                                                                                                   \
            key_schedule_update_hash((key_sched), (buf)->base + (mess_start), (buf)->off - (mess_start));                          \
    } while (0)

#define buffer_push_handshake(buf, key_sched, enc, type, block)                                                                    \
    do {                                                                                                                           \
        size_t rec_start = (buf)->off;                                                                                             \
        buffer_push_record((buf), PTLS_CONTENT_TYPE_HANDSHAKE,                                                                     \
                           { buffer_push_handshake_body((buf), (key_sched), (type), block); });                                    \
        if ((enc) != NULL) {                                                                                                       \
            if ((ret = buffer_encrypt_record((buf), rec_start, (enc))) != 0)                                                       \
                goto Exit;                                                                                                         \
        }                                                                                                                          \
    } while (0)

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

static void key_schedule_free(struct st_ptls_key_schedule_t *sched)
{
    size_t i;
    ptls_clear_memory(sched->secret, sizeof(sched->secret));
    for (i = 0; i != sched->num_hashes; ++i)
        sched->hashes[i].ctx->final(sched->hashes[i].ctx, NULL, PTLS_HASH_FINAL_MODE_FREE);
    free(sched);
}

static struct st_ptls_key_schedule_t *key_schedule_new(ptls_cipher_suite_t *preferred, ptls_cipher_suite_t **offered)
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

    struct st_ptls_key_schedule_t *sched;

    { /* allocate */
        size_t num_hashes = 0;
        FOREACH_HASH({ ++num_hashes; });
        if ((sched = malloc(offsetof(struct st_ptls_key_schedule_t, hashes) + sizeof(sched->hashes[0]) * num_hashes)) == NULL)
            return NULL;
        *sched = (struct st_ptls_key_schedule_t){0};
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

static int key_schedule_extract(struct st_ptls_key_schedule_t *sched, ptls_iovec_t ikm)
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

static int key_schedule_select_one(struct st_ptls_key_schedule_t *sched, ptls_cipher_suite_t *cs, int reset)
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

static void key_schedule_update_hash(struct st_ptls_key_schedule_t *sched, const uint8_t *msg, size_t msglen)
{
    size_t i;

    PTLS_DEBUGF("%s:%zu\n", __FUNCTION__, msglen);
    for (i = 0; i != sched->num_hashes; ++i)
        sched->hashes[i].ctx->update(sched->hashes[i].ctx, msg, msglen);
}

static void key_schedule_update_ch1hash_prefix(struct st_ptls_key_schedule_t *sched)
{
    uint8_t prefix[4] = {PTLS_HANDSHAKE_TYPE_MESSAGE_HASH, 0, 0, (uint8_t)sched->hashes[0].algo->digest_size};
    key_schedule_update_hash(sched, prefix, sizeof(prefix));
}

static void key_schedule_extract_ch1hash(struct st_ptls_key_schedule_t *sched, uint8_t *hash)
{
    sched->hashes[0].ctx->final(sched->hashes[0].ctx, hash, PTLS_HASH_FINAL_MODE_RESET);
}

static void key_schedule_transform_post_ch1hash(struct st_ptls_key_schedule_t *sched)
{
    uint8_t ch1hash[PTLS_MAX_DIGEST_SIZE];

    key_schedule_extract_ch1hash(sched, ch1hash);

    key_schedule_update_ch1hash_prefix(sched);
    key_schedule_update_hash(sched, ch1hash, sched->hashes[0].algo->digest_size);
}

static int derive_secret_with_hash(struct st_ptls_key_schedule_t *sched, void *secret, const char *label, const uint8_t *hash)
{
    int ret = ptls_hkdf_expand_label(sched->hashes[0].algo, secret, sched->hashes[0].algo->digest_size,
                                     ptls_iovec_init(sched->secret, sched->hashes[0].algo->digest_size), label,
                                     ptls_iovec_init(hash, sched->hashes[0].algo->digest_size), NULL);
    PTLS_DEBUGF("%s: (label=%s, hash=%02x%02x) => %02x%02x\n", __FUNCTION__, label, hash[0], hash[1], ((uint8_t *)secret)[0],
                ((uint8_t *)secret)[1]);
    return ret;
}

static int derive_secret(struct st_ptls_key_schedule_t *sched, void *secret, const char *label)
{
    uint8_t hash_value[PTLS_MAX_DIGEST_SIZE];

    sched->hashes[0].ctx->final(sched->hashes[0].ctx, hash_value, PTLS_HASH_FINAL_MODE_SNAPSHOT);
    int ret = derive_secret_with_hash(sched, secret, label, hash_value);
    ptls_clear_memory(hash_value, sizeof(hash_value));
    return ret;
}

static int derive_secret_with_empty_digest(struct st_ptls_key_schedule_t *sched, void *secret, const char *label)
{
    return derive_secret_with_hash(sched, secret, label, sched->hashes[0].algo->empty_digest);
}

static int derive_exporter_secret(ptls_t *tls, int is_early)
{
    if (tls->ctx->use_exporter)
        return 0;

    uint8_t **slot = is_early ? &tls->exporter_master_secret.early : &tls->exporter_master_secret.one_rtt;
    assert(*slot == NULL);
    if ((*slot = malloc(tls->key_schedule->hashes[0].algo->digest_size)) == NULL)
        return PTLS_ERROR_NO_MEMORY;
    return derive_secret(tls->key_schedule, *slot, is_early ? "e exp master" : "exp master");
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

static int derive_resumption_secret(struct st_ptls_key_schedule_t *sched, uint8_t *secret, ptls_iovec_t nonce)
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

static int decode_new_session_ticket(uint32_t *lifetime, uint32_t *age_add, ptls_iovec_t *nonce, ptls_iovec_t *ticket,
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

static int decode_stored_session_ticket(ptls_context_t *ctx, ptls_key_exchange_algorithm_t **key_share, ptls_cipher_suite_t **cs,
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
        if ((ret = decode_new_session_ticket(&lifetime, &age_add, &nonce, ticket, max_early_data_size, src, end)) != 0)
            goto Exit;
        src = end;
    });
    ptls_decode_block(src, end, 2, {
        *secret = ptls_iovec_init(src, end - src);
        src = end;
    });

    { /* determine the key-exchange */
        ptls_key_exchange_algorithm_t **cand;
        for (cand = ctx->key_exchanges; *cand != NULL; ++cand)
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
        for (cand = ctx->cipher_suites; *cand != NULL; ++cand)
            if ((*cand)->id == csid)
                break;
        if (*cand == NULL) {
            ret = PTLS_ERROR_LIBRARY;
            goto Exit;
        }
        *cs = *cand;
    }

    /* calculate obfuscated_ticket_age */
    now = ctx->get_time->cb(ctx->get_time);
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
                           const char *base_label)
{
    return ptls_hkdf_expand_label(algo, key, key_size, ptls_iovec_init(secret, algo->digest_size), is_iv ? "iv" : "key",
                                  ptls_iovec_init(NULL, 0), base_label);
}

static int setup_traffic_protection(ptls_t *tls, int is_enc, const char *secret_label, const char *log_label)
{
    struct st_ptls_traffic_protection_t *ctx = is_enc ? &tls->traffic_protection.enc : &tls->traffic_protection.dec;

    if (secret_label != NULL) {
        int ret;
        if ((ret = derive_secret(tls->key_schedule, ctx->secret, secret_label)) != 0)
            return ret;
    }

    if (ctx->aead != NULL)
        ptls_aead_free(ctx->aead);
    if ((ctx->aead = ptls_aead_new(tls->cipher_suite->aead, tls->cipher_suite->hash, is_enc, ctx->secret, NULL)) == NULL)
        return PTLS_ERROR_NO_MEMORY; /* TODO obtain error from ptls_aead_new */
    ctx->seq = 0;

    if (tls->ctx->log_secret != NULL)
        tls->ctx->log_secret->cb(tls->ctx->log_secret, tls, log_label,
                                 ptls_iovec_init(ctx->secret, tls->key_schedule->hashes[0].algo->digest_size));
    PTLS_DEBUGF("[%s] %02x%02x,%02x%02x\n", log_label, (unsigned)ctx->secret[0], (unsigned)ctx->secret[1],
                (unsigned)ctx->aead->static_iv[0], (unsigned)ctx->aead->static_iv[1]);

    return 0;
}

static int retire_early_data_secret(ptls_t *tls, int is_enc)
{
    assert(tls->early_data != NULL);
    memcpy((is_enc ? &tls->traffic_protection.enc : &tls->traffic_protection.dec)->secret, tls->early_data->next_secret,
           PTLS_MAX_DIGEST_SIZE);
    ptls_clear_memory(tls->early_data, sizeof(*tls->early_data));
    free(tls->early_data);
    tls->early_data = NULL;

    return setup_traffic_protection(tls, is_enc, NULL, "CLIENT_HANDSHAKE_TRAFFIC_SECRET");
}

#define SESSION_IDENTIFIER_MAGIC "ptls0001" /* the number should be changed upon incompatible format change */
#define SESSION_IDENTIFIER_MAGIC_SIZE (sizeof(SESSION_IDENTIFIER_MAGIC) - 1)

static int encode_session_identifier(ptls_context_t *ctx, ptls_buffer_t *buf, uint32_t ticket_age_add, ptls_iovec_t ticket_nonce,
                                     struct st_ptls_key_schedule_t *sched, const char *server_name, uint16_t key_exchange_id,
                                     uint16_t csid, const char *negotiated_protocol)
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

static size_t build_certificate_verify_signdata(uint8_t *data, struct st_ptls_key_schedule_t *sched, const char *context_string)
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

static int calc_verify_data(void *output, struct st_ptls_key_schedule_t *sched, const void *secret)
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
    if (memcmp(message.base + PTLS_HANDSHAKE_HEADER_SIZE, verify_data, tls->key_schedule->hashes[0].algo->digest_size) != 0) {
        ret = PTLS_ALERT_HANDSHAKE_FAILURE;
        goto Exit;
    }

Exit:
    ptls_clear_memory(verify_data, sizeof(verify_data));
    return ret;
}

static int send_finished(ptls_t *tls, ptls_buffer_t *sendbuf)
{
    int ret;

    buffer_push_handshake(sendbuf, tls->key_schedule, &tls->traffic_protection.enc, PTLS_HANDSHAKE_TYPE_FINISHED, {
        if ((ret = ptls_buffer_reserve(sendbuf, tls->key_schedule->hashes[0].algo->digest_size)) != 0)
            goto Exit;
        if ((ret = calc_verify_data(sendbuf->base + sendbuf->off, tls->key_schedule, tls->traffic_protection.enc.secret)) != 0)
            goto Exit;
        sendbuf->off += tls->key_schedule->hashes[0].algo->digest_size;
    });

Exit:
    return ret;
}

static int send_session_ticket(ptls_t *tls, ptls_buffer_t *sendbuf)
{
    ptls_hash_context_t *msghash_backup = tls->key_schedule->hashes[0].ctx->clone_(tls->key_schedule->hashes[0].ctx);
    ptls_buffer_t session_id;
    char session_id_smallbuf[128];
    uint32_t ticket_age_add;
    int ret = 0;

    assert(tls->ctx->ticket_lifetime != 0);
    assert(tls->ctx->encrypt_ticket != NULL);

    { /* calculate verify-data that will be sent by the client */
        size_t orig_off = sendbuf->off;
        if (tls->early_data != NULL) {
            assert(tls->state == PTLS_STATE_SERVER_EXPECT_END_OF_EARLY_DATA);
            buffer_push_handshake_body(sendbuf, tls->key_schedule, PTLS_HANDSHAKE_TYPE_END_OF_EARLY_DATA, {});
            sendbuf->off = orig_off;
        }
        buffer_push_handshake_body(sendbuf, tls->key_schedule, PTLS_HANDSHAKE_TYPE_FINISHED, {
            if ((ret = ptls_buffer_reserve(sendbuf, tls->key_schedule->hashes[0].algo->digest_size)) != 0)
                goto Exit;
            if ((ret = calc_verify_data(sendbuf->base + sendbuf->off, tls->key_schedule,
                                        tls->early_data != NULL ? tls->early_data->next_secret
                                                                : tls->traffic_protection.dec.secret)) != 0)
                goto Exit;
            sendbuf->off += tls->key_schedule->hashes[0].algo->digest_size;
        });
        sendbuf->off = orig_off;
    }

    tls->ctx->random_bytes(&ticket_age_add, sizeof(ticket_age_add));

    /* build the raw nsk */
    ptls_buffer_init(&session_id, session_id_smallbuf, sizeof(session_id_smallbuf));
    ret = encode_session_identifier(tls->ctx, &session_id, ticket_age_add, ptls_iovec_init(NULL, 0), tls->key_schedule,
                                    tls->server_name, tls->key_share->id, tls->cipher_suite->id, tls->negotiated_protocol);
    if (ret != 0)
        goto Exit;

    /* encrypt and send */
    buffer_push_handshake(sendbuf, tls->key_schedule, &tls->traffic_protection.enc, PTLS_HANDSHAKE_TYPE_NEW_SESSION_TICKET, {
        ptls_buffer_push32(sendbuf, tls->ctx->ticket_lifetime);
        ptls_buffer_push32(sendbuf, ticket_age_add);
        ptls_buffer_push_block(sendbuf, 1, {});
        ptls_buffer_push_block(sendbuf, 2, {
            if ((ret = tls->ctx->encrypt_ticket->cb(tls->ctx->encrypt_ticket, tls, 1, sendbuf,
                                                    ptls_iovec_init(session_id.base, session_id.off))) != 0)
                goto Exit;
        });
        ptls_buffer_push_block(sendbuf, 2, {
            if (tls->ctx->max_early_data_size != 0)
                buffer_push_extension(sendbuf, PTLS_EXTENSION_TYPE_EARLY_DATA,
                                      { ptls_buffer_push32(sendbuf, tls->ctx->max_early_data_size); });
        });
    });

Exit:
    ptls_buffer_dispose(&session_id);

    /* restore handshake state */
    tls->key_schedule->hashes[0].ctx->final(tls->key_schedule->hashes[0].ctx, NULL, PTLS_HASH_FINAL_MODE_FREE);
    tls->key_schedule->hashes[0].ctx = msghash_backup;

    return ret;
}

static int push_change_cipher_spec(ptls_t *tls, ptls_buffer_t *sendbuf)
{
    int ret = 0;

    if (!tls->send_change_cipher_spec)
        goto Exit;
    buffer_push_record(sendbuf, PTLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC, { ptls_buffer_push(sendbuf, 1); });
    tls->send_change_cipher_spec = 0;
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

static int send_client_hello(ptls_t *tls, ptls_buffer_t *sendbuf, ptls_handshake_properties_t *properties, ptls_iovec_t *cookie)
{
    ptls_iovec_t resumption_secret = {NULL}, resumption_ticket;
    uint32_t obfuscated_ticket_age = 0;
    size_t msghash_off;
    uint8_t binder_key[PTLS_MAX_DIGEST_SIZE];
    int ret, is_second_flight = tls->key_schedule != NULL;

    if (properties != NULL) {
        /* setup resumption-related data. If successful, resumption_secret becomes a non-zero value. */
        if (properties->client.session_ticket.base != NULL) {
            ptls_key_exchange_algorithm_t *key_share = NULL;
            ptls_cipher_suite_t *cipher_suite = NULL;
            uint32_t max_early_data_size;
            if (decode_stored_session_ticket(tls->ctx, &key_share, &cipher_suite, &resumption_secret, &obfuscated_ticket_age,
                                             &resumption_ticket, &max_early_data_size, properties->client.session_ticket.base,
                                             properties->client.session_ticket.base + properties->client.session_ticket.len) == 0) {
                tls->client.offered_psk = 1;
                tls->key_share = key_share;
                tls->cipher_suite = cipher_suite;
                if (!is_second_flight && max_early_data_size != 0 && properties->client.max_early_data_size != NULL) {
                    *properties->client.max_early_data_size = max_early_data_size;
                    if ((tls->early_data = malloc(sizeof(*tls->early_data))) == NULL) {
                        ret = PTLS_ERROR_NO_MEMORY;
                        goto Exit;
                    }
                }
            } else {
                resumption_secret = ptls_iovec_init(NULL, 0);
            }
        }
        if (properties->client.max_early_data_size != NULL && tls->early_data == NULL)
            *properties->client.max_early_data_size = 0;
    }

    /* use the default key share if still not undetermined */
    if (tls->key_share == NULL && !(properties != NULL && properties->client.negotiate_before_key_exchange))
        tls->key_share = tls->ctx->key_exchanges[0];

    if (!is_second_flight) {
        tls->key_schedule = key_schedule_new(tls->cipher_suite, tls->ctx->cipher_suites);
        if ((ret = key_schedule_extract(tls->key_schedule, resumption_secret)) != 0)
            goto Exit;
    }

    msghash_off = sendbuf->off + 5;
    buffer_push_handshake(sendbuf, NULL, NULL, PTLS_HANDSHAKE_TYPE_CLIENT_HELLO, {
        /* legacy_version */
        ptls_buffer_push16(sendbuf, 0x0303);
        /* random_bytes */
        ptls_buffer_pushv(sendbuf, tls->client_random, sizeof(tls->client_random));
        /* lecagy_session_id */
        ptls_buffer_push_block(
            sendbuf, 1, { ptls_buffer_pushv(sendbuf, tls->client.legacy_session_id, sizeof(tls->client.legacy_session_id)); });
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
            if (tls->server_name != NULL) {
                buffer_push_extension(sendbuf, PTLS_EXTENSION_TYPE_SERVER_NAME, {
                    ptls_buffer_push_block(sendbuf, 2, {
                        ptls_buffer_push(sendbuf, PTLS_SERVER_NAME_TYPE_HOSTNAME);
                        ptls_buffer_push_block(sendbuf, 2,
                                               { ptls_buffer_pushv(sendbuf, tls->server_name, strlen(tls->server_name)); });
                    });
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
            buffer_push_extension(sendbuf, PTLS_EXTENSION_TYPE_SUPPORTED_VERSIONS, {
                ptls_buffer_push_block(sendbuf, 1, {
                    size_t i;
                    for (i = 0; i != sizeof(supported_versions) / sizeof(supported_versions[0]); ++i)
                        ptls_buffer_push16(sendbuf, supported_versions[i]);
                });
            });
            buffer_push_extension(sendbuf, PTLS_EXTENSION_TYPE_SIGNATURE_ALGORITHMS, {
                ptls_buffer_push_block(sendbuf, 2, {
                    ptls_buffer_push16(sendbuf, PTLS_SIGNATURE_RSA_PSS_RSAE_SHA256);
                    ptls_buffer_push16(sendbuf, PTLS_SIGNATURE_ECDSA_SECP256R1_SHA256);
                    ptls_buffer_push16(sendbuf, PTLS_SIGNATURE_RSA_PKCS1_SHA256);
                    ptls_buffer_push16(sendbuf, PTLS_SIGNATURE_RSA_PKCS1_SHA1);
                });
            });
            buffer_push_extension(sendbuf, PTLS_EXTENSION_TYPE_SUPPORTED_GROUPS, {
                ptls_key_exchange_algorithm_t **algo = tls->ctx->key_exchanges;
                ptls_buffer_push_block(sendbuf, 2, {
                    for (; *algo != NULL; ++algo)
                        ptls_buffer_push16(sendbuf, (*algo)->id);
                });
            });
            buffer_push_extension(sendbuf, PTLS_EXTENSION_TYPE_KEY_SHARE, {
                ptls_buffer_push_block(sendbuf, 2, {
                    if (tls->key_share != NULL) {
                        ptls_iovec_t pubkey;
                        if ((ret = tls->key_share->create(&tls->client.key_share_ctx, &pubkey)) != 0)
                            goto Exit;
                        ptls_buffer_push16(sendbuf, tls->key_share->id);
                        ptls_buffer_push_block(sendbuf, 2, { ptls_buffer_pushv(sendbuf, pubkey.base, pubkey.len); });
                    }
                });
            });
            if (cookie != NULL && cookie->base != NULL) {
                buffer_push_extension(sendbuf, PTLS_EXTENSION_TYPE_COOKIE, {
                    ptls_buffer_push_block(sendbuf, 2, { ptls_buffer_pushv(sendbuf, cookie->base, cookie->len); });
                });
            }
            if ((ret = push_additional_extensions(properties, sendbuf)) != 0)
                goto Exit;
            if (tls->ctx->save_ticket != NULL) {
                buffer_push_extension(sendbuf, PTLS_EXTENSION_TYPE_PSK_KEY_EXCHANGE_MODES, {
                    ptls_buffer_push_block(sendbuf, 1, {
                        if (!tls->ctx->require_dhe_on_psk)
                            ptls_buffer_push(sendbuf, PTLS_PSK_KE_MODE_PSK);
                        ptls_buffer_push(sendbuf, PTLS_PSK_KE_MODE_PSK_DHE);
                    });
                });
                if (resumption_secret.base != NULL) {
                    if (tls->early_data != NULL && !is_second_flight)
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
            }
        });
    });

    /* update the message hash, filling in the PSK binder HMAC if necessary */
    if (resumption_secret.base != NULL) {
        size_t psk_binder_off = sendbuf->off - (3 + tls->key_schedule->hashes[0].algo->digest_size);
        if ((ret = derive_secret_with_empty_digest(tls->key_schedule, binder_key, "res binder")) != 0)
            goto Exit;
        key_schedule_update_hash(tls->key_schedule, sendbuf->base + msghash_off, psk_binder_off - msghash_off);
        msghash_off = psk_binder_off;
        if ((ret = calc_verify_data(sendbuf->base + psk_binder_off + 3, tls->key_schedule, binder_key)) != 0)
            goto Exit;
    }
    key_schedule_update_hash(tls->key_schedule, sendbuf->base + msghash_off, sendbuf->off - msghash_off);

    if (tls->early_data != NULL) {
        if ((ret = setup_traffic_protection(tls, 1, "c e traffic", "CLIENT_EARLY_TRAFFIC_SECRET")) != 0)
            goto Exit;
        if ((ret = push_change_cipher_spec(tls, sendbuf)) != 0)
            goto Exit;
    }
    if (resumption_secret.base != NULL && !is_second_flight) {
        if ((ret = derive_exporter_secret(tls, 1)) != 0)
            goto Exit;
    }
    tls->state = cookie == NULL ? PTLS_STATE_CLIENT_EXPECT_SERVER_HELLO : PTLS_STATE_CLIENT_EXPECT_SECOND_SERVER_HELLO;
    ret = PTLS_ERROR_IN_PROGRESS;

Exit:
    ptls_clear_memory(binder_key, sizeof(binder_key));
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

static int handle_hello_retry_request(ptls_t *tls, ptls_buffer_t *sendbuf, struct st_ptls_server_hello_t *sh, ptls_iovec_t message,
                                      ptls_handshake_properties_t *properties)
{
    int ret;

    if (tls->client.key_share_ctx != NULL) {
        tls->client.key_share_ctx->on_exchange(&tls->client.key_share_ctx, NULL, ptls_iovec_init(NULL, 0));
        tls->client.key_share_ctx = NULL;
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
    key_schedule_update_hash(tls->key_schedule, message.base, message.len);
    ret = send_client_hello(tls, sendbuf, properties, &sh->retry_request.cookie);

Exit:
    return ret;
}

static int client_handle_hello(ptls_t *tls, ptls_buffer_t *sendbuf, ptls_iovec_t message, ptls_handshake_properties_t *properties)
{
    struct st_ptls_server_hello_t sh;
    ptls_iovec_t ecdh_secret = {NULL};
    int ret;

    if ((ret = decode_server_hello(tls, &sh, message.base + PTLS_HANDSHAKE_HEADER_SIZE, message.base + message.len)) != 0)
        goto Exit;
    if (!(sh.legacy_session_id.len == sizeof(tls->client.legacy_session_id) &&
          memcmp(sh.legacy_session_id.base, tls->client.legacy_session_id, sizeof(tls->client.legacy_session_id)) == 0)) {
        ret = PTLS_ALERT_ILLEGAL_PARAMETER;
        goto Exit;
    }

    if (sh.is_retry_request) {
        if ((ret = key_schedule_select_one(tls->key_schedule, tls->cipher_suite, 0)) != 0)
            goto Exit;
        return handle_hello_retry_request(tls, sendbuf, &sh, message, properties);
    }

    if ((ret = key_schedule_select_one(tls->key_schedule, tls->cipher_suite, tls->client.offered_psk && !tls->is_psk_handshake)) !=
        0)
        goto Exit;

    if (sh.peerkey.base != NULL) {
        if ((ret = tls->client.key_share_ctx->on_exchange(&tls->client.key_share_ctx, &ecdh_secret, sh.peerkey)) != 0)
            goto Exit;
    }

    key_schedule_update_hash(tls->key_schedule, message.base, message.len);

    if ((ret = key_schedule_extract(tls->key_schedule, ecdh_secret)) != 0)
        goto Exit;
    if ((ret = setup_traffic_protection(tls, 0, "s hs traffic", "SERVER_HANDSHAKE_TRAFFIC_SECRET")) != 0)
        goto Exit;

    tls->state = PTLS_STATE_CLIENT_EXPECT_ENCRYPTED_EXTENSIONS;
    ret = PTLS_ERROR_IN_PROGRESS;

Exit:
    if (ecdh_secret.base != NULL) {
        ptls_clear_memory(ecdh_secret.base, ecdh_secret.len);
        free(ecdh_secret.base);
    }
    return ret;
}

static int handle_unknown_extension(ptls_t *tls, ptls_handshake_properties_t *properties, uint16_t type, const uint8_t *src,
                                    const uint8_t *const end, ptls_raw_extension_t *slots)
{

    if (properties != NULL && properties->collect_extension != NULL && properties->collect_extension(tls, properties, type)) {
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
    ptls_raw_extension_t unknown_extensions[MAX_UNKNOWN_EXTENSIONS + 1];
    int ret, skip_early_data = 1;

    unknown_extensions[0].type = UINT16_MAX;

    decode_extensions(src, end, PTLS_HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS, &type, {
        switch (type) {
        case PTLS_EXTENSION_TYPE_SERVER_NAME:
            if (src != end) {
                ret = PTLS_ALERT_DECODE_ERROR;
                goto Exit;
            }
            if (tls->server_name == NULL) {
                ret = PTLS_ALERT_ILLEGAL_PARAMETER;
                goto Exit;
            }
            break;
        case PTLS_EXTENSION_TYPE_ALPN:
            ptls_decode_block(src, end, 2, {
                ptls_decode_open_block(src, end, 1, {
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
            if (tls->early_data == NULL) {
                ret = PTLS_ALERT_ILLEGAL_PARAMETER;
                goto Exit;
            }
            skip_early_data = 0;
            break;
        default:
            handle_unknown_extension(tls, properties, type, src, end, unknown_extensions);
            break;
        }
        src = end;
    });

    if (tls->early_data != NULL) {
        tls->skip_early_data = skip_early_data;
        if (properties != NULL && !skip_early_data)
            properties->client.early_data_accepted_by_peer = 1;
        if ((ret = derive_secret(tls->key_schedule, tls->early_data->next_secret, "c hs traffic")) != 0)
            goto Exit;
    } else {
        if ((ret = setup_traffic_protection(tls, 1, "c hs traffic", "CLIENT_HANDSHAKE_TRAFFIC_SECRET")) != 0)
            goto Exit;
    }
    if ((ret = report_unknown_extensions(tls, properties, unknown_extensions)) != 0)
        goto Exit;

    key_schedule_update_hash(tls->key_schedule, message.base, message.len);
    tls->state = tls->is_psk_handshake ? PTLS_STATE_CLIENT_EXPECT_FINISHED : PTLS_STATE_CLIENT_EXPECT_CERTIFICATE;
    ret = PTLS_ERROR_IN_PROGRESS;

Exit:
    return ret;
}

static int client_handle_certificate(ptls_t *tls, ptls_iovec_t message)
{
    const uint8_t *src = message.base + PTLS_HANDSHAKE_HEADER_SIZE, *const end = message.base + message.len;
    ptls_iovec_t certs[16];
    size_t num_certs = 0;
    int ret;

    /* certificate request context */
    ptls_decode_open_block(src, end, 1, {
        if (src != end) {
            ret = PTLS_ALERT_ILLEGAL_PARAMETER;
            goto Exit;
        }
    });
    /* certificate_list */
    ptls_decode_block(src, end, 3, {
        do {
            ptls_decode_open_block(src, end, 3, {
                if (num_certs < sizeof(certs) / sizeof(certs[0]))
                    certs[num_certs++] = ptls_iovec_init(src, end - src);
                src = end;
            });
            uint16_t type;
            decode_open_extensions(src, end, PTLS_HANDSHAKE_TYPE_CERTIFICATE, &type, { src = end; });
        } while (src != end);
    });

    if (tls->ctx->verify_certificate != NULL) {
        if ((ret = tls->ctx->verify_certificate->cb(tls->ctx->verify_certificate, tls, &tls->client.certificate_verify.cb,
                                                    &tls->client.certificate_verify.verify_ctx, certs, num_certs)) != 0)
            goto Exit;
    }

    key_schedule_update_hash(tls->key_schedule, message.base, message.len);
    tls->state = PTLS_STATE_CLIENT_EXPECT_CERTIFICATE_VERIFY;
    ret = PTLS_ERROR_IN_PROGRESS;

Exit:
    return ret;
}

static int client_handle_certificate_verify(ptls_t *tls, ptls_iovec_t message)
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
    signdata_size = build_certificate_verify_signdata(signdata, tls->key_schedule, PTLS_SERVER_CERTIFICATE_VERIFY_CONTEXT_STRING);
    if (tls->client.certificate_verify.cb != NULL) {
        ret = tls->client.certificate_verify.cb(tls->client.certificate_verify.verify_ctx, ptls_iovec_init(signdata, signdata_size),
                                                signature);
    } else {
        ret = 0;
    }
    ptls_clear_memory(signdata, signdata_size);
    tls->client.certificate_verify.cb = NULL;
    if (ret != 0)
        goto Exit;

    key_schedule_update_hash(tls->key_schedule, message.base, message.len);
    tls->state = PTLS_STATE_CLIENT_EXPECT_FINISHED;
    ret = PTLS_ERROR_IN_PROGRESS;

Exit:
    return ret;
}

static int client_handle_finished(ptls_t *tls, ptls_buffer_t *sendbuf, ptls_iovec_t message)
{
    uint8_t send_secret[PTLS_MAX_DIGEST_SIZE];
    int ret;

    if ((ret = verify_finished(tls, message)) != 0)
        goto Exit;
    key_schedule_update_hash(tls->key_schedule, message.base, message.len);

    /* update traffic keys by using messages upto ServerFinished, but commission them after sending ClientFinished */
    if ((ret = key_schedule_extract(tls->key_schedule, ptls_iovec_init(NULL, 0))) != 0)
        goto Exit;
    if ((ret = setup_traffic_protection(tls, 0, "s ap traffic", "SERVER_TRAFFIC_SECRET_0")) != 0)
        goto Exit;
    if ((ret = derive_secret(tls->key_schedule, send_secret, "c ap traffic")) != 0)
        goto Exit;
    if ((ret = derive_exporter_secret(tls, 0)) != 0)
        goto Exit;

    /* if sending early data, emit EOED and commision the client handshake traffic secret */
    if (tls->early_data != NULL) {
        assert(tls->traffic_protection.enc.aead != NULL);
        if (!tls->skip_early_data) {
            buffer_push_handshake(sendbuf, tls->key_schedule, &tls->traffic_protection.enc, PTLS_HANDSHAKE_TYPE_END_OF_EARLY_DATA,
                                  {});
        }
        if ((ret = retire_early_data_secret(tls, 1)) != 0)
            goto Exit;
    }

    if ((ret = push_change_cipher_spec(tls, sendbuf)) != 0)
        goto Exit;
    ret = send_finished(tls, sendbuf);

    memcpy(tls->traffic_protection.enc.secret, send_secret, sizeof(send_secret));
    if ((ret = setup_traffic_protection(tls, 1, NULL, "CLIENT_TRAFFIC_SECRET_0")) != 0)
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
        if ((ret = decode_new_session_ticket(&ticket_lifetime, &ticket_age_add, &ticket_nonce, &ticket, &max_early_data_size, src,
                                             end)) != 0)
            return ret;
    }

    /* do nothing if use of session ticket is disabled */
    if (tls->ctx->save_ticket == NULL)
        return 0;

    /* save the extension, along with the key of myself */
    ptls_buffer_t ticket_buf;
    uint8_t ticket_buf_small[512];
    ptls_buffer_init(&ticket_buf, ticket_buf_small, sizeof(ticket_buf_small));
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

static int client_hello_decode_server_name(ptls_iovec_t *name, const uint8_t *src, const uint8_t *const end)
{
    int ret = 0;

    ptls_decode_block(src, end, 2, {
        if (src == end) {
            ret = PTLS_ALERT_DECODE_ERROR;
            goto Exit;
        }
        do {
            uint8_t type = *src++;
            ptls_decode_open_block(src, end, 2, {
                switch (type) {
                case PTLS_SERVER_NAME_TYPE_HOSTNAME:
                    if (memchr(src, '\0', end - src) != 0) {
                        ret = PTLS_ALERT_ILLEGAL_PARAMETER;
                        goto Exit;
                    }
                    *name = ptls_iovec_init(src, end - src);
                    break;
                default:
                    break;
                }
                src = end;
            });
        } while (src != end);
    });

Exit:
    return ret;
}

static int select_cipher_suite(ptls_cipher_suite_t **selected, ptls_cipher_suite_t **candidates, const uint8_t *src,
                               const uint8_t *const end)
{
    int ret;

    ptls_decode_block(src, end, 2, {
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
    });

    ret = PTLS_ALERT_HANDSHAKE_FAILURE;

Exit:
    return ret;
}

static int select_key_share(ptls_key_exchange_algorithm_t **selected, ptls_iovec_t *peer_key,
                            ptls_key_exchange_algorithm_t **candidates, const uint8_t *src, const uint8_t *const end)
{
    int ret;

    ptls_decode_block(src, end, 2, {
        while (src != end) {
            uint16_t group;
            ptls_iovec_t key;
            if ((ret = decode_key_share_entry(&group, &key, &src, end)) != 0)
                goto Exit;
            ptls_key_exchange_algorithm_t **c = candidates;
            for (; *c != NULL; ++c) {
                if ((*c)->id == group) {
                    *selected = *c;
                    *peer_key = key;
                    return 0;
                }
            }
        }
    });

    *selected = NULL;
    ret = 0;

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

static int decode_client_hello(ptls_t *tls, struct st_ptls_client_hello_t *ch, const uint8_t *src, const uint8_t *const end,
                               ptls_handshake_properties_t *properties)
{
    uint16_t exttype = 0;
    int ret;

    { /* check protocol version */
        uint16_t protver;
        if ((ret = ptls_decode16(&protver, &src, end)) != 0)
            goto Exit;
        if (protver != 0x0303) {
            ret = PTLS_ALERT_HANDSHAKE_FAILURE;
            goto Exit;
        }
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
        ch->cipher_suites = ptls_iovec_init(src - 2, end - src + 2);
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

    /* decode extensions */
    decode_extensions(src, end, PTLS_HANDSHAKE_TYPE_CLIENT_HELLO, &exttype, {
        switch (exttype) {
        case PTLS_EXTENSION_TYPE_SERVER_NAME:
            if ((ret = client_hello_decode_server_name(&ch->server_name, src, end)) != 0)
                goto Exit;
            break;
        case PTLS_EXTENSION_TYPE_ALPN:
            ptls_decode_block(src, end, 2, {
                do {
                    ptls_decode_open_block(src, end, 1, {
                        if (ch->alpn.count < sizeof(ch->alpn.list) / sizeof(ch->alpn.list[0]))
                            ch->alpn.list[ch->alpn.count++] = ptls_iovec_init(src, end - src);
                        src = end;
                    });
                } while (src != end);
            });
            break;
        case PTLS_EXTENSION_TYPE_SUPPORTED_GROUPS:
            ch->negotiated_groups = ptls_iovec_init(src, end - src);
            break;
        case PTLS_EXTENSION_TYPE_SIGNATURE_ALGORITHMS:
            ptls_decode_block(src, end, 2, {
                do {
                    uint16_t id;
                    if ((ret = ptls_decode16(&id, &src, end)) != 0)
                        goto Exit;
                    if (ch->signature_algorithms.count <
                        sizeof(ch->signature_algorithms.list) / sizeof(ch->signature_algorithms.list[0]))
                        ch->signature_algorithms.list[ch->signature_algorithms.count++] = id;
                } while (src != end);
            });
            break;
        case PTLS_EXTENSION_TYPE_KEY_SHARE:
            ch->key_shares = ptls_iovec_init(src, end - src);
            break;
        case PTLS_EXTENSION_TYPE_SUPPORTED_VERSIONS:
            ptls_decode_block(src, end, 1, {
                size_t selected_index = sizeof(supported_versions) / sizeof(supported_versions[0]);
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
                if (selected_index != sizeof(supported_versions) / sizeof(supported_versions[0]))
                    ch->selected_version = supported_versions[selected_index];
            });
            break;
        case PTLS_EXTENSION_TYPE_COOKIE:
            if (properties->server.cookie.key == NULL) {
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
                    if (ch->psk.identities.count < sizeof(ch->psk.identities.list) / sizeof(ch->psk.identities.list[0]))
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
            handle_unknown_extension(tls, properties, exttype, src, end, ch->unknown_extensions);
            break;
        }
        src = end;
    });

    /* check if client hello make sense */
    if (is_supported_version(ch->selected_version)) {
        if (!(ch->compression_methods.count == 1 && ch->compression_methods.ids[0] == 0)) {
            ret = PTLS_ALERT_ILLEGAL_PARAMETER;
            goto Exit;
        }
        /* pre-shared key */
        if (ch->psk.hash_end != NULL) {
            /* PSK must be the last extension */
            if (exttype != PTLS_EXTENSION_TYPE_PRE_SHARED_KEY) {
                ret = PTLS_ALERT_ILLEGAL_PARAMETER;
                goto Exit;
            }
        } else {
            if (ch->psk.early_data_indication) {
                ret = PTLS_ALERT_ILLEGAL_PARAMETER;
                goto Exit;
            }
        }
    } else {
        ret = PTLS_ALERT_PROTOCOL_VERSION;
        goto Exit;
    }

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
    uint8_t decbuf_small[256], binder_key[PTLS_MAX_DIGEST_SIZE], verify_data[PTLS_MAX_DIGEST_SIZE];
    int ret;

    ptls_buffer_init(&decbuf, decbuf_small, sizeof(decbuf_small));

    for (*psk_index = 0; *psk_index < ch->psk.identities.count; ++*psk_index) {
        struct st_ptls_client_hello_psk_t *identity = ch->psk.identities.list + *psk_index;
        /* decrypt and decode */
        decbuf.off = 0;
        if ((tls->ctx->encrypt_ticket->cb(tls->ctx->encrypt_ticket, tls, 0, &decbuf, identity->identity)) != 0)
            continue;
        if (decode_session_identifier(&issue_at, &ticket_psk, &age_add, &ticket_server_name, &ticket_key_exchange_id, &ticket_csid,
                                      &ticket_negotiated_protocol, decbuf.base, decbuf.base + decbuf.off) != 0)
            continue;
        /* check age */
        if (now < issue_at)
            continue;
        if (now - issue_at > (uint64_t)tls->ctx->ticket_lifetime * 1000)
            continue;
        *accept_early_data = 0;
        if (ch->psk.early_data_indication) {
            int64_t delta = (now - issue_at) - (identity->obfuscated_ticket_age - age_add);
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
    key_schedule_update_hash(tls->key_schedule, ch_trunc.base, ch_trunc.len);
    if ((ret = calc_verify_data(verify_data, tls->key_schedule, binder_key)) != 0)
        goto Exit;
    if (memcmp(ch->psk.identities.list[*psk_index].binder.base, verify_data, tls->key_schedule->hashes[0].algo->digest_size) != 0) {
        ret = PTLS_ALERT_DECRYPT_ERROR;
        goto Exit;
    }
    ret = 0;

Exit:
    ptls_buffer_dispose(&decbuf);
    ptls_clear_memory(binder_key, sizeof(binder_key));
    ptls_clear_memory(verify_data, sizeof(verify_data));
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

static int server_handle_hello(ptls_t *tls, ptls_buffer_t *sendbuf, ptls_iovec_t message, ptls_handshake_properties_t *properties)
{
#define EMIT_SERVER_HELLO(sched, fill_rand, extensions)                                                                            \
    buffer_push_handshake(sendbuf, (sched), NULL, PTLS_HANDSHAKE_TYPE_SERVER_HELLO, {                                              \
        ptls_buffer_push16(sendbuf, 0x0303 /* legacy version */);                                                                  \
        if ((ret = ptls_buffer_reserve(sendbuf, PTLS_HELLO_RANDOM_SIZE)) != 0)                                                     \
            goto Exit;                                                                                                             \
        do {                                                                                                                       \
            fill_rand                                                                                                              \
        } while (0);                                                                                                               \
        sendbuf->off += PTLS_HELLO_RANDOM_SIZE;                                                                                    \
        ptls_buffer_push_block(sendbuf, 1, { ptls_buffer_pushv(sendbuf, ch.legacy_session_id.base, ch.legacy_session_id.len); });  \
        ptls_buffer_push16(sendbuf, tls->cipher_suite->id);                                                                        \
        ptls_buffer_push(sendbuf, 0);                                                                                              \
        ptls_buffer_push_block(sendbuf, 2, {                                                                                       \
            buffer_push_extension(sendbuf, PTLS_EXTENSION_TYPE_SUPPORTED_VERSIONS,                                                 \
                                  { ptls_buffer_push16(sendbuf, ch.selected_version); });                                          \
            do {                                                                                                                   \
                extensions                                                                                                         \
            } while (0);                                                                                                           \
        });                                                                                                                        \
    });

#define EMIT_HELLO_RETRY_REQUEST(sched, negotiated_group, additional_extensions)                                                   \
    EMIT_SERVER_HELLO((sched), { memcpy(sendbuf->base + sendbuf->off, hello_retry_random, PTLS_HELLO_RANDOM_SIZE); },              \
                      {                                                                                                            \
                          ptls_key_exchange_algorithm_t *_negotiated_group = (negotiated_group);                                   \
                          if (_negotiated_group != NULL) {                                                                         \
                              buffer_push_extension(sendbuf, PTLS_EXTENSION_TYPE_KEY_SHARE,                                        \
                                                    { ptls_buffer_push16(sendbuf, _negotiated_group->id); });                      \
                          }                                                                                                        \
                          do {                                                                                                     \
                              additional_extensions                                                                                \
                          } while (0);                                                                                             \
                      });

    struct st_ptls_client_hello_t ch = {NULL,  {NULL}, {NULL},     0,        {NULL}, {NULL},        {NULL},
                                        {{0}}, {NULL}, {{{NULL}}}, {{NULL}}, {NULL}, {{UINT16_MAX}}};
    struct {
        ptls_key_exchange_algorithm_t *algorithm;
        ptls_iovec_t peer_key;
    } key_share = {NULL};
    enum { HANDSHAKE_MODE_FULL, HANDSHAKE_MODE_PSK, HANDSHAKE_MODE_PSK_DHE } mode;
    size_t psk_index = SIZE_MAX;
    ptls_iovec_t pubkey = {0}, ecdh_secret = {0};
    uint8_t finished_key[PTLS_MAX_DIGEST_SIZE];
    int accept_early_data = 0, is_second_flight = tls->state == PTLS_STATE_SERVER_EXPECT_SECOND_CLIENT_HELLO, ret;

    /* decode ClientHello */
    if ((ret = decode_client_hello(tls, &ch, message.base + PTLS_HANDSHAKE_HEADER_SIZE, message.base + message.len, properties)) !=
        0)
        goto Exit;
    if (tls->ctx->require_dhe_on_psk)
        ch.psk.ke_modes &= ~(1u << PTLS_PSK_KE_MODE_PSK);

    /* handle client_random and SNI */
    if (!is_second_flight) {
        memcpy(tls->client_random, ch.random_bytes, sizeof(tls->client_random));
        if (ch.server_name.base != NULL) {
            if ((tls->server_name = malloc(ch.server_name.len + 1)) == NULL) {
                ret = PTLS_ERROR_NO_MEMORY;
                goto Exit;
            }
            memcpy(tls->server_name, ch.server_name.base, ch.server_name.len);
            tls->server_name[ch.server_name.len] = '\0';
        }
        if (tls->ctx->on_client_hello != NULL &&
            (ret = tls->ctx->on_client_hello->cb(tls->ctx->on_client_hello, tls, ch.server_name, ch.alpn.list, ch.alpn.count,
                                                 ch.signature_algorithms.list, ch.signature_algorithms.count)) != 0)
            goto Exit;
    } else {
        if (ch.psk.early_data_indication) {
            ret = PTLS_ALERT_DECODE_ERROR;
            goto Exit;
        }
        if (memcmp(tls->client_random, ch.random_bytes, sizeof(tls->client_random)) != 0 ||
            (tls->server_name != NULL) != (ch.server_name.base != NULL) ||
            (tls->server_name != NULL &&
             !(strncmp(tls->server_name, (char *)ch.server_name.base, ch.server_name.len) == 0 &&
               tls->server_name[ch.server_name.len] == '\0'))) {
            ret = PTLS_ALERT_HANDSHAKE_FAILURE;
            goto Exit;
        }
    }

    { /* select (or check) cipher-suite, create key_schedule */
        ptls_cipher_suite_t *cs;
        if ((ret = select_cipher_suite(&cs, tls->ctx->cipher_suites, ch.cipher_suites.base,
                                       ch.cipher_suites.base + ch.cipher_suites.len)) != 0)
            goto Exit;
        if (!is_second_flight) {
            tls->cipher_suite = cs;
            tls->key_schedule = key_schedule_new(cs, NULL);
        } else {
            if (tls->cipher_suite != cs) {
                ret = PTLS_ALERT_HANDSHAKE_FAILURE;
                goto Exit;
            }
        }
    }

    /* select key_share */
    if (ch.key_shares.base != NULL &&
        (ret = select_key_share(&key_share.algorithm, &key_share.peer_key, tls->ctx->key_exchanges, ch.key_shares.base,
                                ch.key_shares.base + ch.key_shares.len)) != 0)
        goto Exit;

    if (!is_second_flight) {
        if (ch.cookie.all.len != 0 && key_share.algorithm != NULL) {

            /* use cookie to check the integrity of the handshake, and update the context */
            uint8_t sig[PTLS_MAX_DIGEST_SIZE];
            size_t sigsize = tls->ctx->cipher_suites[0]->hash->digest_size;
            if ((ret = calc_cookie_signature(tls, properties, key_share.algorithm, ch.cookie.tbs, sig)) != 0)
                goto Exit;
            if (!(ch.cookie.signature.len == sigsize && memcmp(ch.cookie.signature.base, sig, sigsize) == 0)) {
                ret = PTLS_ALERT_HANDSHAKE_FAILURE;
                goto Exit;
            }
            /* integrity check passed; update states */
            key_schedule_update_ch1hash_prefix(tls->key_schedule);
            key_schedule_update_hash(tls->key_schedule, ch.cookie.ch1_hash.base, ch.cookie.ch1_hash.len);
            key_schedule_extract(tls->key_schedule, ptls_iovec_init(NULL, 0));
            /* ... reusing sendbuf to rebuild HRR for hash calculation */
            size_t hrr_start = sendbuf->off;
            EMIT_HELLO_RETRY_REQUEST(tls->key_schedule, ch.cookie.sent_key_share ? key_share.algorithm : NULL, {
                buffer_push_extension(sendbuf, PTLS_EXTENSION_TYPE_COOKIE,
                                      { ptls_buffer_pushv(sendbuf, ch.cookie.all.base, ch.cookie.all.len); });
            });
            sendbuf->off = hrr_start;
            is_second_flight = 1;

        } else if (key_share.algorithm == NULL || (properties != NULL && properties->server.enforce_retry)) {

            /* send HelloRetryRequest  */
            if (ch.negotiated_groups.base == NULL) {
                ret = PTLS_ALERT_MISSING_EXTENSION;
                goto Exit;
            }
            ptls_key_exchange_algorithm_t *negotiated_group;
            if ((ret = select_negotiated_group(&negotiated_group, tls->ctx->key_exchanges, ch.negotiated_groups.base,
                                               ch.negotiated_groups.base + ch.negotiated_groups.len)) != 0)
                goto Exit;
            key_schedule_update_hash(tls->key_schedule, message.base, message.len);
            assert(tls->key_schedule->generation == 0);
            if (properties != NULL && properties->server.retry_uses_cookie) {
                /* emit HRR with cookie (note: we MUST omit KeyShare if the client has specified the correct one; see 46554f0) */
                EMIT_HELLO_RETRY_REQUEST(NULL, key_share.algorithm != NULL ? NULL : negotiated_group, {
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
                if ((ret = push_change_cipher_spec(tls, sendbuf)) != 0)
                    goto Exit;
                ret = PTLS_ERROR_STATELESS_RETRY;
            } else {
                /* invoking stateful retry; roll the key schedule and emit HRR */
                key_schedule_transform_post_ch1hash(tls->key_schedule);
                key_schedule_extract(tls->key_schedule, ptls_iovec_init(NULL, 0));
                EMIT_HELLO_RETRY_REQUEST(tls->key_schedule, key_share.algorithm != NULL ? NULL : negotiated_group, {});
                if ((ret = push_change_cipher_spec(tls, sendbuf)) != 0)
                    goto Exit;
                tls->state = PTLS_STATE_SERVER_EXPECT_SECOND_CLIENT_HELLO;
                if (ch.psk.early_data_indication)
                    tls->skip_early_data = 1;
                ret = PTLS_ERROR_IN_PROGRESS;
            }
            goto Exit;
        }
    }

    /* handle unknown extensions */
    if ((ret = report_unknown_extensions(tls, properties, ch.unknown_extensions)) != 0)
        goto Exit;

    /* try psk handshake */
    if (!is_second_flight && ch.psk.hash_end != 0 &&
        (ch.psk.ke_modes & ((1u << PTLS_PSK_KE_MODE_PSK) | (1u << PTLS_PSK_KE_MODE_PSK_DHE))) != 0 &&
        tls->ctx->encrypt_ticket != NULL) {
        if ((ret = try_psk_handshake(tls, &psk_index, &accept_early_data, &ch,
                                     ptls_iovec_init(message.base, ch.psk.hash_end - message.base))) != 0)
            goto Exit;
    }

    /* adjust key_schedule, determine handshake mode */
    if (psk_index == SIZE_MAX) {
        key_schedule_update_hash(tls->key_schedule, message.base, message.len);
        if (!is_second_flight) {
            assert(tls->key_schedule->generation == 0);
            key_schedule_extract(tls->key_schedule, ptls_iovec_init(NULL, 0));
        }
        mode = HANDSHAKE_MODE_FULL;
        if (properties != NULL)
            properties->server.selected_psk_binder.len = 0;
    } else {
        key_schedule_update_hash(tls->key_schedule, ch.psk.hash_end, message.base + message.len - ch.psk.hash_end);
        if ((ch.psk.ke_modes & (1u << PTLS_PSK_KE_MODE_PSK)) != 0) {
            mode = HANDSHAKE_MODE_PSK;
        } else {
            assert((ch.psk.ke_modes & (1u << PTLS_PSK_KE_MODE_PSK_DHE)) != 0);
            mode = HANDSHAKE_MODE_PSK_DHE;
        }
        tls->is_psk_handshake = 1;
        if (properties != NULL) {
            ptls_iovec_t *selected = &ch.psk.identities.list[psk_index].binder;
            memcpy(properties->server.selected_psk_binder.base, selected->base, selected->len);
            properties->server.selected_psk_binder.len = selected->len;
        }
        if ((ret = derive_exporter_secret(tls, 1)) != 0)
            goto Exit;
    }

    if (accept_early_data && tls->ctx->max_early_data_size != 0 && psk_index == 0) {
        if ((tls->early_data = malloc(sizeof(*tls->early_data))) == NULL) {
            ret = PTLS_ERROR_NO_MEMORY;
            goto Exit;
        }
        if ((ret = setup_traffic_protection(tls, 0, "c e traffic", "CLIENT_EARLY_TRAFFIC_SECRET")) != 0)
            goto Exit;
    }

    /* run key-exchange, to obtain pubkey and secret */
    if (mode != HANDSHAKE_MODE_PSK) {
        if (key_share.algorithm == NULL) {
            ret = ch.key_shares.base != NULL ? PTLS_ALERT_HANDSHAKE_FAILURE : PTLS_ALERT_MISSING_EXTENSION;
            goto Exit;
        }
        if ((ret = key_share.algorithm->exchange(&pubkey, &ecdh_secret, key_share.peer_key)) != 0)
            goto Exit;
        tls->key_share = key_share.algorithm;
    }

    /* send ServerHello */
    EMIT_SERVER_HELLO(tls->key_schedule, { tls->ctx->random_bytes(sendbuf->base + sendbuf->off, PTLS_HELLO_RANDOM_SIZE); },
                      {
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
    if ((ret = push_change_cipher_spec(tls, sendbuf)) != 0)
        goto Exit;

    /* create protection contexts for the handshake */
    assert(tls->key_schedule->generation == 1);
    key_schedule_extract(tls->key_schedule, ecdh_secret);
    if ((ret = setup_traffic_protection(tls, 1, "s hs traffic", "SERVER_HANDSHAKE_TRAFFIC_SECRET")) != 0)
        goto Exit;
    if (tls->early_data != NULL) {
        if ((ret = derive_secret(tls->key_schedule, tls->early_data->next_secret, "c hs traffic")) != 0)
            goto Exit;
    } else {
        if ((ret = setup_traffic_protection(tls, 0, "c hs traffic", "CLIENT_HANDSHAKE_TRAFFIC_SECRET")) != 0)
            goto Exit;
        if (ch.psk.early_data_indication)
            tls->skip_early_data = 1;
    }

    /* send EncryptedExtensions */
    buffer_push_handshake(sendbuf, tls->key_schedule, &tls->traffic_protection.enc, PTLS_HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS, {
        ptls_buffer_push_block(sendbuf, 2, {
            if (tls->server_name != NULL) {
                /* In this event, the server SHALL include an extension of type "server_name" in the (extended) server
                 * hello. The "extension_data" field of this extension SHALL be empty. (RFC 6066 section 3) */
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
            if (tls->early_data != NULL && tls->traffic_protection.dec.aead != NULL)
                buffer_push_extension(sendbuf, PTLS_EXTENSION_TYPE_EARLY_DATA, {});
            if ((ret = push_additional_extensions(properties, sendbuf)) != 0)
                goto Exit;
        });
    });

    if (mode == HANDSHAKE_MODE_FULL) {
        if (ch.signature_algorithms.count == 0) {
            ret = PTLS_ALERT_MISSING_EXTENSION;
            goto Exit;
        }
        /* send Certificate */
        buffer_push_handshake(sendbuf, tls->key_schedule, &tls->traffic_protection.enc, PTLS_HANDSHAKE_TYPE_CERTIFICATE, {
            ptls_buffer_push(sendbuf, 0);
            ptls_buffer_push_block(sendbuf, 3, {
                size_t i;
                for (i = 0; i != tls->ctx->certificates.count; ++i) {
                    ptls_buffer_push_block(sendbuf, 3, {
                        ptls_buffer_pushv(sendbuf, tls->ctx->certificates.list[i].base, tls->ctx->certificates.list[i].len);
                    });
                    ptls_buffer_push_block(sendbuf, 2, {
                        /* emit OCSP stapling only when requested and when the callback successfully returns one */
                        if (ch.status_request && i == 0 && tls->ctx->staple_ocsp != NULL) {
                            size_t reset_off_to = sendbuf->off;
                            buffer_push_extension(sendbuf, PTLS_EXTENSION_TYPE_STATUS_REQUEST, {
                                ptls_buffer_push(sendbuf, 1); /* status_type == ocsp */
                                ptls_buffer_push_block(sendbuf, 3, {
                                    if ((ret = tls->ctx->staple_ocsp->cb(tls->ctx->staple_ocsp, tls, sendbuf, i)) == 0)
                                        reset_off_to = 0;
                                });
                            });
                            if (reset_off_to != 0)
                                sendbuf->off = reset_off_to;
                        }
                    });
                }
            });
        });
        /* build and send CertificateVerify */
        buffer_push_handshake(sendbuf, tls->key_schedule, &tls->traffic_protection.enc, PTLS_HANDSHAKE_TYPE_CERTIFICATE_VERIFY, {
            size_t algo_off = sendbuf->off;
            ptls_buffer_push16(sendbuf, 0); /* filled in later */
            ptls_buffer_push_block(sendbuf, 2, {
                uint16_t algo;
                uint8_t data[PTLS_MAX_CERTIFICATE_VERIFY_SIGNDATA_SIZE];
                size_t datalen =
                    build_certificate_verify_signdata(data, tls->key_schedule, PTLS_SERVER_CERTIFICATE_VERIFY_CONTEXT_STRING);
                if ((ret = tls->ctx->sign_certificate->cb(tls->ctx->sign_certificate, tls, &algo, sendbuf,
                                                          ptls_iovec_init(data, datalen), ch.signature_algorithms.list,
                                                          ch.signature_algorithms.count)) != 0)
                    goto Exit;
                sendbuf->base[algo_off] = (uint8_t)(algo >> 8);
                sendbuf->base[algo_off + 1] = (uint8_t)algo;
            });
        });
    }

    send_finished(tls, sendbuf);

    assert(tls->key_schedule->generation == 2);
    if ((ret = key_schedule_extract(tls->key_schedule, ptls_iovec_init(NULL, 0))) != 0)
        goto Exit;
    if ((ret = setup_traffic_protection(tls, 1, "s ap traffic", "SERVER_TRAFFIC_SECRET_0")) != 0)
        goto Exit;
    if ((ret = derive_secret(tls->key_schedule, tls->server.pending_traffic_secret, "c ap traffic")) != 0)
        goto Exit;
    if ((ret = derive_exporter_secret(tls, 0)) != 0)
        goto Exit;

    tls->state = tls->early_data != NULL ? PTLS_STATE_SERVER_EXPECT_END_OF_EARLY_DATA : PTLS_STATE_SERVER_EXPECT_FINISHED;

    /* send session ticket if necessary */
    if (ch.psk.ke_modes != 0 && tls->ctx->ticket_lifetime != 0) {
        if ((ret = send_session_ticket(tls, sendbuf)) != 0)
            goto Exit;
    }

    ret = 0;

Exit:
    free(pubkey.base);
    free(ecdh_secret.base);
    ptls_clear_memory(finished_key, sizeof(finished_key));
    return ret;

#undef EMIT_SERVER_HELLO
#undef EMIT_HELLO_RETRY_REQUEST
}

static int server_handle_end_of_early_data(ptls_t *tls, ptls_iovec_t message)
{
    int ret;

    if ((ret = retire_early_data_secret(tls, 0)) != 0)
        goto Exit;

    key_schedule_update_hash(tls->key_schedule, message.base, message.len);
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
    if ((ret = setup_traffic_protection(tls, 0, NULL, "CLIENT_TRAFFIC_SECRET_0")) != 0)
        return ret;

    key_schedule_update_hash(tls->key_schedule, message.base, message.len);

    tls->state = PTLS_STATE_SERVER_POST_HANDSHAKE;
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

ptls_t *ptls_new(ptls_context_t *ctx, int is_server)
{
    ptls_t *tls;

    assert(ctx->get_time != NULL && "please set ctx->get_time to `&ptls_get_time`; see #92");

    if ((tls = malloc(sizeof(*tls))) == NULL)
        return NULL;

    update_open_count(ctx, 1);
    *tls = (ptls_t){ctx};
    tls->is_server = is_server;
    tls->send_change_cipher_spec = ctx->send_change_cipher_spec;
    if (!is_server) {
        tls->state = PTLS_STATE_CLIENT_HANDSHAKE_START;
        tls->ctx->random_bytes(tls->client_random, sizeof(tls->client_random));
        tls->ctx->random_bytes(tls->client.legacy_session_id, sizeof(tls->client.legacy_session_id));
    } else {
        tls->state = PTLS_STATE_SERVER_EXPECT_CLIENT_HELLO;
    }

    return tls;
}

void ptls_free(ptls_t *tls)
{
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
    if (tls->is_server) {
        /* nothing to do */
    } else {
        if (tls->client.key_share_ctx != NULL)
            tls->client.key_share_ctx->on_exchange(&tls->client.key_share_ctx, NULL, ptls_iovec_init(NULL, 0));
        if (tls->client.certificate_verify.cb != NULL)
            tls->client.certificate_verify.cb(tls->client.certificate_verify.verify_ctx, ptls_iovec_init(NULL, 0),
                                              ptls_iovec_init(NULL, 0));
    }
    if (tls->early_data != NULL) {
        ptls_clear_memory(tls->early_data, sizeof(*tls->early_data));
        free(tls->early_data);
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

static int handle_handshake_message(ptls_t *tls, ptls_buffer_t *sendbuf, ptls_iovec_t message, int is_end_of_record,
                                    ptls_handshake_properties_t *properties)
{
    uint8_t type = message.base[0];
    int ret;

    switch (tls->state) {
    case PTLS_STATE_CLIENT_EXPECT_SERVER_HELLO:
    case PTLS_STATE_CLIENT_EXPECT_SECOND_SERVER_HELLO:
        if (type == PTLS_HANDSHAKE_TYPE_SERVER_HELLO && is_end_of_record) {
            ret = client_handle_hello(tls, sendbuf, message, properties);
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
    case PTLS_STATE_CLIENT_EXPECT_CERTIFICATE:
        if (type == PTLS_HANDSHAKE_TYPE_CERTIFICATE) {
            ret = client_handle_certificate(tls, message);
        } else {
            ret = PTLS_ALERT_UNEXPECTED_MESSAGE;
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
            ret = client_handle_finished(tls, sendbuf, message);
        } else {
            ret = PTLS_ALERT_UNEXPECTED_MESSAGE;
        }
        break;
    case PTLS_STATE_SERVER_EXPECT_CLIENT_HELLO:
    case PTLS_STATE_SERVER_EXPECT_SECOND_CLIENT_HELLO:
        if (type == PTLS_HANDSHAKE_TYPE_CLIENT_HELLO && is_end_of_record) {
            ret = server_handle_hello(tls, sendbuf, message, properties);
        } else {
            ret = PTLS_ALERT_HANDSHAKE_FAILURE;
        }
        break;
    case PTLS_STATE_SERVER_EXPECT_END_OF_EARLY_DATA:
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
    case PTLS_STATE_CLIENT_POST_HANDSHAKE:
        switch (type) {
        case PTLS_HANDSHAKE_TYPE_NEW_SESSION_TICKET:
            ret = client_handle_new_session_ticket(tls, message);
            break;
        default:
            ret = PTLS_ALERT_UNEXPECTED_MESSAGE;
            break;
        }
        break;
    case PTLS_STATE_SERVER_POST_HANDSHAKE:
        ret = PTLS_ALERT_UNEXPECTED_MESSAGE;
        break;
    default:
        assert(!"unexpected state");
        break;
    }

    return ret;
}

static int handle_alert(ptls_t *tls, const uint8_t *src, size_t len)
{
    if (len != 2)
        return PTLS_ALERT_DECODE_ERROR;

    uint8_t level = src[0], desc = src[1];

    /* ignore certain warnings */
    if (level == PTLS_ALERT_LEVEL_WARNING) {
        switch (desc) {
        case PTLS_ALERT_USER_CANCELED:
            return 0;
        default:
            break;
        }
    }

    /* all other alerts are considered fatal, regardless of the transmitted level (section 6) */
    return PTLS_ALERT_TO_PEER_ERROR(desc);
}

static int handle_handshake_record(ptls_t *tls, int (*cb)(ptls_t *tls, ptls_buffer_t *sendbuf, ptls_iovec_t message,
                                                          int is_end_of_record, ptls_handshake_properties_t *properties),
                                   ptls_buffer_t *sendbuf, struct st_ptls_record_t *rec, ptls_handshake_properties_t *properties)
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
        ret = cb(tls, sendbuf, ptls_iovec_init(src, mess_len), src_end - src == mess_len, properties);
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
        if (tls->recvbuf.mess.base == NULL) {
            ptls_buffer_init(&tls->recvbuf.mess, "", 0);
            if ((ret = ptls_buffer_reserve(&tls->recvbuf.mess, src_end - src)) != 0)
                return ret;
            memcpy(tls->recvbuf.mess.base, src, src_end - src);
        } else {
            memmove(tls->recvbuf.mess.base, src, src_end - src);
        }
        tls->recvbuf.mess.off = src_end - src;
        ret = PTLS_ERROR_IN_PROGRESS;
    } else {
        ptls_buffer_dispose(&tls->recvbuf.mess);
    }

    return ret;
}

static int handle_input(ptls_t *tls, ptls_buffer_t *sendbuf, ptls_buffer_t *decryptbuf, const void *input, size_t *inlen,
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
        if (rec.type != PTLS_CONTENT_TYPE_APPDATA)
            return PTLS_ALERT_HANDSHAKE_FAILURE;
        if ((ret = ptls_buffer_reserve(decryptbuf, 5 + rec.length)) != 0)
            return ret;
        if ((ret = aead_decrypt(&tls->traffic_protection.dec, decryptbuf->base + decryptbuf->off, &rec.length, rec.fragment,
                                rec.length)) != 0) {
            if (tls->skip_early_data) {
                ret = PTLS_ERROR_IN_PROGRESS;
                goto NextRecord;
            }
            return ret;
        }
        rec.fragment = decryptbuf->base + decryptbuf->off;
        /* skip padding */
        for (; rec.length != 0; --rec.length)
            if (rec.fragment[rec.length - 1] != 0)
                break;
        if (rec.length == 0)
            return PTLS_ALERT_UNEXPECTED_MESSAGE;
        rec.type = rec.fragment[--rec.length];
    } else if (rec.type == PTLS_CONTENT_TYPE_APPDATA && tls->skip_early_data) {
        ret = PTLS_ERROR_IN_PROGRESS;
        goto NextRecord;
    }

    if (tls->recvbuf.mess.base != NULL || rec.type == PTLS_CONTENT_TYPE_HANDSHAKE) {
        /* handshake record */
        ret = handle_handshake_record(tls, handle_handshake_message, sendbuf, &rec, properties);
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
}

int ptls_handshake(ptls_t *tls, ptls_buffer_t *sendbuf, const void *input, size_t *inlen, ptls_handshake_properties_t *properties)
{
    size_t sendbuf_orig_off = sendbuf->off;
    int ret;

    assert(tls->state < PTLS_STATE_POST_HANDSHAKE_MIN);

    /* special handlings */
    switch (tls->state) {
    case PTLS_STATE_CLIENT_HANDSHAKE_START:
        assert(input == NULL || *inlen == 0);
        assert(tls->ctx->key_exchanges[0] != NULL);
        return send_client_hello(tls, sendbuf, properties, NULL);
    default:
        break;
    }

    const uint8_t *src = input, *const src_end = src + *inlen;
    ptls_buffer_t decryptbuf;
    uint8_t decryptbuf_small[256];

    ptls_buffer_init(&decryptbuf, decryptbuf_small, sizeof(decryptbuf_small));

    /* perform handhake until completion or until all the input has been swallowed */
    ret = PTLS_ERROR_IN_PROGRESS;
    while (ret == PTLS_ERROR_IN_PROGRESS && src != src_end) {
        size_t consumed = src_end - src;
        ret = handle_input(tls, sendbuf, &decryptbuf, src, &consumed, properties);
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
        ptls_clear_memory(sendbuf->base + sendbuf_orig_off, sendbuf->off - sendbuf_orig_off);
        sendbuf->off = sendbuf_orig_off;
        /* send alert immediately */
        if (PTLS_ERROR_GET_CLASS(ret) != PTLS_ERROR_CLASS_PEER_ALERT)
            if (ptls_send_alert(tls, sendbuf, PTLS_ALERT_LEVEL_FATAL,
                                PTLS_ERROR_GET_CLASS(ret) == PTLS_ERROR_CLASS_SELF_ALERT ? ret : PTLS_ALERT_INTERNAL_ERROR) != 0)
                sendbuf->off = sendbuf_orig_off;
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

int ptls_send(ptls_t *tls, ptls_buffer_t *sendbuf, const void *input, size_t inlen)
{
    assert(tls->traffic_protection.enc.aead != NULL);
    return buffer_push_encrypted_records(sendbuf, PTLS_CONTENT_TYPE_APPDATA, input, inlen, &tls->traffic_protection.enc);
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
    ptls_hash_context_t *hctx;
    uint8_t *master_secret = is_early ? tls->exporter_master_secret.early : tls->exporter_master_secret.one_rtt,
            derived_secret[PTLS_MAX_DIGEST_SIZE], context_value_hash[PTLS_MAX_DIGEST_SIZE];
    int ret;

    if (master_secret == NULL)
        return PTLS_ERROR_IN_PROGRESS;

    if ((hctx = algo->create()) == NULL)
        return PTLS_ERROR_NO_MEMORY;
    hctx->update(hctx, context_value.base, context_value.len);
    hctx->final(hctx, context_value_hash, PTLS_HASH_FINAL_MODE_FREE);

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

ptls_hash_context_t *ptls_hmac_create(ptls_hash_algorithm_t *algo, const void *key, size_t key_size)
{
    struct st_picotls_hmac_context_t *ctx;

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
                           ptls_iovec_t hash_value, const char *base_label)
{
    ptls_buffer_t hkdf_label;
    uint8_t hkdf_label_buf[512];
    int ret;

    ptls_buffer_init(&hkdf_label, hkdf_label_buf, sizeof(hkdf_label_buf));

    ptls_buffer_push16(&hkdf_label, (uint16_t)outlen);
    ptls_buffer_push_block(&hkdf_label, 1, {
        if (base_label == NULL)
            base_label = "tls13 ";
        ptls_buffer_pushv(&hkdf_label, base_label, strlen(base_label));
        ptls_buffer_pushv(&hkdf_label, label, strlen(label));
    });
    ptls_buffer_push_block(&hkdf_label, 1, { ptls_buffer_pushv(&hkdf_label, hash_value.base, hash_value.len); });

    ret = ptls_hkdf_expand(algo, output, outlen, secret, ptls_iovec_init(hkdf_label.base, hkdf_label.off));

Exit:
    ptls_buffer_dispose(&hkdf_label);
    return ret;
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

ptls_aead_context_t *ptls_aead_new(ptls_aead_algorithm_t *aead, ptls_hash_algorithm_t *hash, int is_enc, const void *secret,
                                   const char *base_label)
{
    ptls_aead_context_t *ctx;
    uint8_t key[PTLS_MAX_SECRET_SIZE];
    int ret;

    if ((ctx = (ptls_aead_context_t *)malloc(aead->context_size)) == NULL)
        return NULL;

    *ctx = (ptls_aead_context_t){aead};
    if ((ret = get_traffic_key(hash, key, aead->key_size, 0, secret, base_label)) != 0)
        goto Exit;
    if ((ret = get_traffic_key(hash, ctx->static_iv, aead->iv_size, 1, secret, base_label)) != 0)
        goto Exit;
    ret = aead->setup_crypto(ctx, is_enc, key);

Exit:
    ptls_clear_memory(key, aead->key_size);
    if (ret != 0) {
        ptls_clear_memory(ctx->static_iv, aead->iv_size);
        free(ctx);
        ctx = NULL;
    }

    return ctx;
}

void ptls_aead_free(ptls_aead_context_t *ctx)
{
    ctx->dispose_crypto(ctx);
    ptls_clear_memory(ctx->static_iv, ctx->algo->iv_size);
    free(ctx);
}

size_t ptls_aead_encrypt(ptls_aead_context_t *ctx, void *output, const void *input, size_t inlen, uint64_t seq, const void *aad,
                         size_t aadlen)
{
    size_t off = 0;

    ptls_aead_encrypt_init(ctx, seq, aad, aadlen);
    off += ptls_aead_encrypt_update(ctx, ((uint8_t *)output) + off, input, inlen);
    off += ptls_aead_encrypt_final(ctx, ((uint8_t *)output) + off);

    return off;
}

void ptls_aead__build_iv(ptls_aead_context_t *ctx, uint8_t *iv, uint64_t seq)
{
    size_t iv_size = ctx->algo->iv_size, i;
    const uint8_t *s = ctx->static_iv;
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

static uint64_t get_time(ptls_get_time_t *self)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

ptls_get_time_t ptls_get_time = {get_time};

