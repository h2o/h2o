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
#include <sys/time.h>
#include "picotls.h"

#define PTLS_MAX_PLAINTEXT_RECORD_SIZE 16384
#define PTLS_MAX_ENCRYPTED_RECORD_SIZE (16384 + 256)

#define PTLS_RECORD_VERSION_MAJOR 3
#define PTLS_RECORD_VERSION_MINOR 1

#define PTLS_HELLO_RANDOM_SIZE 32

#define PTLS_CONTENT_TYPE_ALERT 21
#define PTLS_CONTENT_TYPE_HANDSHAKE 22
#define PTLS_CONTENT_TYPE_APPDATA 23

#define PTLS_HANDSHAKE_TYPE_CLIENT_HELLO 1
#define PTLS_HANDSHAKE_TYPE_SERVER_HELLO 2
#define PTLS_HANDSHAKE_TYPE_NEW_SESSION_TICKET 4
#define PTLS_HANDSHAKE_TYPE_HELLO_RETRY_REQUEST 6
#define PTLS_HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS 8
#define PTLS_HANDSHAKE_TYPE_CERTIFICATE 11
#define PTLS_HANDSHAKE_TYPE_CERTIFICATE_REQUEST 13
#define PTLS_HANDSHAKE_TYPE_CERTIFICATE_VERIFY 15
#define PTLS_HANDSHAKE_TYPE_FINISHED 20
#define PTLS_HANDSHAKE_TYPE_KEY_UPDATE 24

#define PTLS_PSK_KE_MODE_PSK 0
#define PTLS_PSK_KE_MODE_PSK_DHE 1

#define PTLS_HANDSHAKE_HEADER_SIZE 4

#define PTLS_EXTENSION_TYPE_SERVER_NAME 0
#define PTLS_EXTENSION_TYPE_STATUS_REQUEST 5
#define PTLS_EXTENSION_TYPE_SUPPORTED_GROUPS 10
#define PTLS_EXTENSION_TYPE_SIGNATURE_ALGORITHMS 13
#define PTLS_EXTENSION_TYPE_ALPN 16
#define PTLS_EXTENSION_TYPE_KEY_SHARE 40
#define PTLS_EXTENSION_TYPE_PRE_SHARED_KEY 41
#define PTLS_EXTENSION_TYPE_EARLY_DATA 42
#define PTLS_EXTENSION_TYPE_SUPPORTED_VERSIONS 43
#define PTLS_EXTENSION_TYPE_COOKIE 44
#define PTLS_EXTENSION_TYPE_PSK_KEY_EXCHANGE_MODES 45
#define PTLS_EXTENSION_TYPE_TICKET_EARLY_DATA_INFO 46

#define PTLS_PROTOCOL_VERSION_DRAFT18 0x7f12

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

struct st_ptls_traffic_protection_t {
    uint8_t secret[PTLS_MAX_DIGEST_SIZE];
    ptls_aead_context_t *aead;
};

struct st_ptls_early_data_receiver_t {
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
        PTLS_STATE_CLIENT_SEND_EARLY_DATA,
        PTLS_STATE_CLIENT_EXPECT_SERVER_HELLO,
        PTLS_STATE_CLIENT_EXPECT_SECOND_SERVER_HELLO,
        PTLS_STATE_CLIENT_EXPECT_ENCRYPTED_EXTENSIONS,
        PTLS_STATE_CLIENT_EXPECT_CERTIFICATE,
        PTLS_STATE_CLIENT_EXPECT_CERTIFICATE_VERIFY,
        PTLS_STATE_CLIENT_EXPECT_FINISHED,
        PTLS_STATE_SERVER_EXPECT_CLIENT_HELLO,
        PTLS_STATE_SERVER_EXPECT_SECOND_CLIENT_HELLO,
        /* ptls_send can be called if the state is below here */
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
     * selected cipher-suite
     */
    ptls_cipher_suite_t *cipher_suite;
    /**
     * clienthello.random
     */
    uint8_t client_random[PTLS_HELLO_RANDOM_SIZE];
    /* flags */
    unsigned is_psk_handshake : 1;
    /**
     * misc.
     */
    struct {
        struct {
            ptls_key_exchange_algorithm_t *algo;
            ptls_key_exchange_context_t *ctx;
        } key_exchange;
        struct {
            int (*cb)(void *verify_ctx, ptls_iovec_t data, ptls_iovec_t signature);
            void *verify_ctx;
        } certificate_verify;
        unsigned offered_psk : 1;
        unsigned send_early_data : 1;
    } client;
    struct {
        /**
         * expecting to recieve undecrytable early-data packets
         */
        unsigned skip_early_data : 1;
        /**
         * if accepting early-data, the value contains the receiving traffic secret to be commisioned after receiving
         * END_OF_EARLY_DATA
         */
        struct st_ptls_early_data_receiver_t *early_data;
    } server;
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

struct st_ptls_client_hello_t {
    const uint8_t *random_bytes;
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
    ptls_iovec_t cookie;
    struct {
        const uint8_t *hash_end;
        struct {
            struct st_ptls_client_hello_psk_t list[4];
            size_t count;
        } identities;
        unsigned ke_modes;
        int early_data_indication;
    } psk;
    unsigned status_request : 1;
};

struct st_ptls_server_hello_t {
    uint8_t random[PTLS_HELLO_RANDOM_SIZE];
    ptls_iovec_t peerkey;
};

struct st_ptls_key_schedule_t {
    ptls_hash_algorithm_t *algo;
    ptls_hash_context_t *msghash;
    unsigned generation; /* early secret (1), hanshake secret (2), master secret (3) */
    uint8_t secret[PTLS_MAX_DIGEST_SIZE];
};

struct st_ptls_extension_decoder_t {
    uint16_t type;
    int (*cb)(ptls_t *tls, void *arg, const uint8_t *src, const uint8_t *end);
};

struct st_ptls_extension_bitmap_t {
    uint8_t bits[8]; /* only ids below 64 is tracked */
};

static uint8_t zeroes_of_max_digest_size[PTLS_MAX_DIGEST_SIZE] = {};

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
        ALLOW(HELLO_RETRY_REQUEST);
    });
    EXT(PRE_SHARED_KEY, {
        ALLOW(CLIENT_HELLO);
        ALLOW(SERVER_HELLO);
    });
    EXT(PSK_KEY_EXCHANGE_MODES, { ALLOW(CLIENT_HELLO); });
    EXT(EARLY_DATA, {
        ALLOW(CLIENT_HELLO);
        ALLOW(ENCRYPTED_EXTENSIONS);
    });
    EXT(COOKIE, {
        ALLOW(CLIENT_HELLO);
        ALLOW(HELLO_RETRY_REQUEST);
    });
    EXT(SUPPORTED_VERSIONS, { ALLOW(CLIENT_HELLO); });
    EXT(TICKET_EARLY_DATA_INFO, { ALLOW(NEW_SESSION_TICKET); });

#undef ALLOW
#undef EXT
}

static uint64_t gettime_millis(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
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
    const uint8_t *p = bignum, *end = p + size;
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

static int buffer_encrypt_record(ptls_buffer_t *buf, size_t rec_start, ptls_aead_context_t *aead)
{
    uint8_t encrypted[PTLS_MAX_ENCRYPTED_RECORD_SIZE];
    size_t enclen, bodylen = buf->off - rec_start - 5;
    int ret;

    assert(bodylen <= PTLS_MAX_PLAINTEXT_RECORD_SIZE);

    if ((ret = ptls_aead_transform(aead, encrypted, &enclen, buf->base + rec_start + 5, bodylen, buf->base[rec_start])) != 0)
        goto Exit;
    buf->off = rec_start;
    ptls_buffer_push(buf, PTLS_CONTENT_TYPE_APPDATA, 3, 1);
    ptls_buffer_push16(buf, enclen);
    ptls_buffer_pushv(buf, encrypted, enclen);

Exit:
    return ret;
}

#define buffer_push_record(buf, type, block)                                                                                       \
    do {                                                                                                                           \
        ptls_buffer_push((buf), (type), PTLS_RECORD_VERSION_MAJOR, PTLS_RECORD_VERSION_MINOR);                                     \
        ptls_buffer_push_block((buf), 2, block);                                                                                   \
    } while (0)

#define buffer_encrypt(buf, enc, block)                                                                                            \
    do {                                                                                                                           \
        size_t rec_start = (buf)->off;                                                                                             \
        do {                                                                                                                       \
            block                                                                                                                  \
        } while (0);                                                                                                               \
        if ((ret = buffer_encrypt_record((buf), rec_start, (enc))) != 0)                                                           \
            goto Exit;                                                                                                             \
    } while (0);

#define buffer_push_handshake_core(buf, key_sched, type, mess_start, block)                                                        \
    do {                                                                                                                           \
        ptls_buffer_push((buf), (type));                                                                                           \
        ptls_buffer_push_block((buf), 3, {                                                                                         \
            do {                                                                                                                   \
                block                                                                                                              \
            } while (0);                                                                                                           \
        });                                                                                                                        \
        if ((key_sched) != NULL)                                                                                                   \
            key_schedule_update_hash((key_sched), (buf)->base + mess_start, (buf)->off - (mess_start));                            \
    } while (0)

#define buffer_push_handshake(buf, key_sched, type, block)                                                                         \
    buffer_push_record((buf), PTLS_CONTENT_TYPE_HANDSHAKE, {                                                                       \
        size_t mess_start = (buf)->off;                                                                                            \
        buffer_push_handshake_core((buf), (key_sched), (type), mess_start, block);                                                 \
    })

#define buffer_calc_handshake_hash(buf, key_sched, type, block)                                                                    \
    do {                                                                                                                           \
        size_t mess_start = (buf)->off;                                                                                            \
        buffer_push_handshake_core((buf), (key_sched), (type), mess_start, block);                                                 \
        (buf)->off = mess_start;                                                                                                   \
    } while (0)

#define buffer_push_extension(buf, type, block)                                                                                    \
    do {                                                                                                                           \
        ptls_buffer_push16((buf), (type));                                                                                         \
        ptls_buffer_push_block((buf), 2, block);                                                                                   \
    } while (0);

#define decode_open_block(src, end, capacity, block)                                                                               \
    do {                                                                                                                           \
        size_t _capacity = (capacity);                                                                                             \
        if (_capacity > end - (src)) {                                                                                             \
            ret = PTLS_ALERT_DECODE_ERROR;                                                                                         \
            goto Exit;                                                                                                             \
        }                                                                                                                          \
        size_t _block_size = 0;                                                                                                    \
        do {                                                                                                                       \
            _block_size = _block_size << 8 | *(src)++;                                                                             \
        } while (--_capacity != 0);                                                                                                \
        if (_block_size > end - (src)) {                                                                                           \
            ret = PTLS_ALERT_DECODE_ERROR;                                                                                         \
            goto Exit;                                                                                                             \
        }                                                                                                                          \
        do {                                                                                                                       \
            const uint8_t *end = (src) + _block_size;                                                                              \
            do {                                                                                                                   \
                block                                                                                                              \
            } while (0);                                                                                                           \
            if ((src) != end) {                                                                                                    \
                ret = PTLS_ALERT_DECODE_ERROR;                                                                                     \
                goto Exit;                                                                                                         \
            }                                                                                                                      \
        } while (0);                                                                                                               \
    } while (0)

#define decode_assert_block_close(src, end)                                                                                        \
    do {                                                                                                                           \
        if ((src) != end) {                                                                                                        \
            ret = PTLS_ALERT_DECODE_ERROR;                                                                                         \
            goto Exit;                                                                                                             \
        }                                                                                                                          \
    } while (0);

#define decode_block(src, end, capacity, block)                                                                                    \
    do {                                                                                                                           \
        decode_open_block((src), end, capacity, block);                                                                            \
        decode_assert_block_close((src), end);                                                                                     \
    } while (0)

#define decode_open_extensions(src, end, hstype, exttype, block)                                                                   \
    do {                                                                                                                           \
        struct st_ptls_extension_bitmap_t bitmap;                                                                                  \
        init_extension_bitmap(&bitmap, (hstype));                                                                                  \
        decode_open_block((src), end, 2, {                                                                                         \
            while ((src) != end) {                                                                                                 \
                if ((ret = decode16((exttype), &(src), end)) != 0)                                                                 \
                    goto Exit;                                                                                                     \
                if (extension_bitmap_is_set(&bitmap, *(exttype)) != 0) {                                                           \
                    ret = PTLS_ALERT_ILLEGAL_PARAMETER;                                                                            \
                    goto Exit;                                                                                                     \
                }                                                                                                                  \
                extension_bitmap_set(&bitmap, *(exttype));                                                                         \
                decode_open_block((src), end, 2, block);                                                                           \
            }                                                                                                                      \
        });                                                                                                                        \
    } while (0)

#define decode_extensions(src, end, hstype, exttype, block)                                                                        \
    do {                                                                                                                           \
        decode_open_extensions((src), end, hstype, exttype, block);                                                                \
        decode_assert_block_close((src), end);                                                                                     \
    } while (0)

static int decode16(uint16_t *value, const uint8_t **src, const uint8_t *end)
{
    if (end - *src < 2)
        return PTLS_ALERT_DECODE_ERROR;
    *value = ntoh16(*src);
    *src += 2;
    return 0;
}

static int decode32(uint32_t *value, const uint8_t **src, const uint8_t *end)
{
    if (end - *src < 4)
        return PTLS_ALERT_DECODE_ERROR;
    *value = ntoh32(*src);
    *src += 4;
    return 0;
}

static int decode64(uint64_t *value, const uint8_t **src, const uint8_t *end)
{
    if (end - *src < 8)
        return PTLS_ALERT_DECODE_ERROR;
    *value = ntoh64(*src);
    *src += 8;
    return 0;
}

static int hkdf_expand_label(ptls_hash_algorithm_t *algo, void *output, size_t outlen, ptls_iovec_t secret, const char *label,
                             ptls_iovec_t hash_value)
{
    ptls_buffer_t hkdf_label;
    uint8_t hkdf_label_buf[512];
    int ret;

    ptls_buffer_init(&hkdf_label, hkdf_label_buf, sizeof(hkdf_label_buf));

    ptls_buffer_push16(&hkdf_label, outlen);
    ptls_buffer_push_block(&hkdf_label, 1, {
        const char *prefix = "TLS 1.3, ";
        ptls_buffer_pushv(&hkdf_label, prefix, strlen(prefix));
        ptls_buffer_pushv(&hkdf_label, label, strlen(label));
    });
    ptls_buffer_push_block(&hkdf_label, 1, { ptls_buffer_pushv(&hkdf_label, hash_value.base, hash_value.len); });

    ret = ptls_hkdf_expand(algo, output, outlen, secret, ptls_iovec_init(hkdf_label.base, hkdf_label.off));

Exit:
    ptls_buffer_dispose(&hkdf_label);
    return ret;
}

static struct st_ptls_key_schedule_t *key_schedule_new(ptls_hash_algorithm_t *algo)
{
    struct st_ptls_key_schedule_t *sched = NULL;
    ptls_hash_context_t *hash = NULL;

    if ((sched = malloc(sizeof(*sched))) == NULL)
        return NULL;
    if ((hash = algo->create()) == NULL) {
        free(sched);
        return NULL;
    }

    *sched = (struct st_ptls_key_schedule_t){algo, hash};
    return sched;
}

static void key_schedule_free(struct st_ptls_key_schedule_t *sched)
{
    sched->msghash->final(sched->msghash, NULL, PTLS_HASH_FINAL_MODE_FREE);
    free(sched);
}

static int key_schedule_extract(struct st_ptls_key_schedule_t *sched, ptls_iovec_t ikm)
{
    if (ikm.base == NULL)
        ikm = ptls_iovec_init(zeroes_of_max_digest_size, sched->algo->digest_size);

    ++sched->generation;
    int ret = ptls_hkdf_extract(sched->algo, sched->secret, ptls_iovec_init(sched->secret, sched->algo->digest_size), ikm);
    PTLS_DEBUGF("%s: %u, %02x%02x\n", __FUNCTION__, sched->generation, (int)sched->secret[0], (int)sched->secret[1]);
    return ret;
}

static int key_schedule_reset_psk(struct st_ptls_key_schedule_t *sched)
{
    assert(sched->generation == 1);

    --sched->generation;
    memset(sched->secret, 0, sizeof(sched->secret));
    return key_schedule_extract(sched, ptls_iovec_init(NULL, 0));
}

static void key_schedule_update_hash(struct st_ptls_key_schedule_t *sched, const uint8_t *msg, size_t msglen)
{
    PTLS_DEBUGF("%s:%zu\n", __FUNCTION__, msglen);
    sched->msghash->update(sched->msghash, msg, msglen);
}

static int derive_secret(struct st_ptls_key_schedule_t *sched, void *secret, const char *label)
{
    uint8_t hash_value[PTLS_MAX_DIGEST_SIZE];

    sched->msghash->final(sched->msghash, hash_value, PTLS_HASH_FINAL_MODE_SNAPSHOT);

    int ret =
        hkdf_expand_label(sched->algo, secret, sched->algo->digest_size, ptls_iovec_init(sched->secret, sched->algo->digest_size),
                          label, ptls_iovec_init(hash_value, sched->algo->digest_size));

    ptls_clear_memory(hash_value, sizeof(hash_value));
    return ret;
}

static int derive_resumption_secret(struct st_ptls_key_schedule_t *sched, uint8_t *secret)
{
    return derive_secret(sched, secret, "resumption master secret");
}

static int decode_new_session_ticket(uint32_t *lifetime, uint32_t *age_add, ptls_iovec_t *ticket, uint32_t *max_early_data_size,
                                     const uint8_t *src, const uint8_t *end)
{
    uint16_t exttype;
    int ret;

    if ((ret = decode32(lifetime, &src, end)) != 0)
        goto Exit;
    if ((ret = decode32(age_add, &src, end)) != 0)
        goto Exit;
    decode_open_block(src, end, 2, {
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
        case PTLS_EXTENSION_TYPE_TICKET_EARLY_DATA_INFO:
            if ((ret = decode32(max_early_data_size, &src, end)) != 0)
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

static int decode_stored_session_ticket(ptls_context_t *ctx, ptls_cipher_suite_t **cs, ptls_iovec_t *secret,
                                        uint32_t *obfuscated_ticket_age, ptls_iovec_t *ticket, uint32_t *max_early_data_size,
                                        const uint8_t *src, const uint8_t *end)
{
    uint16_t csid;
    uint32_t lifetime, age_add;
    uint64_t obtained_at, now;
    int ret;

    /* decode */
    if ((ret = decode64(&obtained_at, &src, end)) != 0)
        goto Exit;
    if ((ret = decode16(&csid, &src, end)) != 0)
        goto Exit;
    decode_open_block(src, end, 3, {
        if ((ret = decode_new_session_ticket(&lifetime, &age_add, ticket, max_early_data_size, src, end)) != 0)
            goto Exit;
        src = end;
    });
    decode_block(src, end, 2, {
        *secret = ptls_iovec_init(src, end - src);
        src = end;
    });

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
    now = gettime_millis();
    if (!(obtained_at <= now && now - obtained_at < 7 * 86400 * 1000)) {
        ret = PTLS_ERROR_LIBRARY;
        goto Exit;
    }
    *obfuscated_ticket_age = (uint32_t)(now - obtained_at) + age_add;

    ret = 0;
Exit:
    return ret;
}

static int get_traffic_key(ptls_hash_algorithm_t *algo, void *key, size_t key_size, int is_iv, const void *secret)
{
    return hkdf_expand_label(algo, key, key_size, ptls_iovec_init(secret, algo->digest_size), is_iv ? "iv" : "key",
                             ptls_iovec_init(NULL, 0));
}

static int setup_traffic_protection(ptls_t *tls, ptls_cipher_suite_t *cs, int is_enc, const char *secret_label,
                                    const char *log_label)
{
    struct st_ptls_traffic_protection_t *ctx = is_enc ? &tls->traffic_protection.enc : &tls->traffic_protection.dec;

    if (secret_label != NULL) {
        int ret;
        if ((ret = derive_secret(tls->key_schedule, ctx->secret, secret_label)) != 0)
            return ret;
    }

    if (ctx->aead != NULL)
        ptls_aead_free(ctx->aead);
    if ((ctx->aead = ptls_aead_new(cs->aead, cs->hash, is_enc, ctx->secret)) == NULL)
        return PTLS_ERROR_NO_MEMORY; /* TODO obtain error from ptls_aead_new */

    if (tls->ctx->log_secret != NULL)
        tls->ctx->log_secret->cb(tls->ctx->log_secret, tls, log_label,
                                 ptls_iovec_init(ctx->secret, tls->key_schedule->algo->digest_size));
    PTLS_DEBUGF("[%s] %02x%02x,%02x%02x\n", secret_label, (unsigned)ctx->secret[0], (unsigned)ctx->secret[1],
                (unsigned)ctx->aead->static_iv[0], (unsigned)ctx->aead->static_iv[1]);

    return 0;
}

#define SESSION_IDENTIFIER_MAGIC "ptls0000" /* the number should be changed upon incompatible format change */
#define SESSION_IDENTIFIER_MAGIC_SIZE (sizeof(SESSION_IDENTIFIER_MAGIC) - 1)

int encode_session_identifier(ptls_buffer_t *buf, uint32_t ticket_age_add, struct st_ptls_key_schedule_t *sched,
                              const char *server_name, uint16_t csid, const char *negotiated_protocol)
{
    int ret = 0;

    ptls_buffer_push_block(buf, 2, {
        /* format id */
        ptls_buffer_pushv(buf, SESSION_IDENTIFIER_MAGIC, SESSION_IDENTIFIER_MAGIC_SIZE);
        /* date */
        ptls_buffer_push64(buf, gettime_millis());
        /* resumption master secret */
        ptls_buffer_push_block(buf, 2, {
            if ((ret = ptls_buffer_reserve(buf, sched->algo->digest_size)) != 0)
                goto Exit;
            if ((ret = derive_resumption_secret(sched, buf->base + buf->off)) != 0)
                goto Exit;
            buf->off += sched->algo->digest_size;
        });
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
                              uint16_t *csid, ptls_iovec_t *negotiated_protocol, const uint8_t *src, const uint8_t *end)
{
    int ret = 0;

    decode_block(src, end, 2, {
        if (end - src < SESSION_IDENTIFIER_MAGIC_SIZE ||
            memcmp(src, SESSION_IDENTIFIER_MAGIC, SESSION_IDENTIFIER_MAGIC_SIZE) != 0) {
            ret = PTLS_ALERT_DECODE_ERROR;
            goto Exit;
        }
        src += SESSION_IDENTIFIER_MAGIC_SIZE;
        if ((ret = decode64(issued_at, &src, end)) != 0)
            goto Exit;
        decode_open_block(src, end, 2, {
            *psk = ptls_iovec_init(src, end - src);
            src = end;
        });
        if ((ret = decode16(csid, &src, end)) != 0)
            goto Exit;
        if ((ret = decode32(ticket_age_add, &src, end)) != 0)
            goto Exit;
        decode_open_block(src, end, 2, {
            *server_name = ptls_iovec_init(src, end - src);
            src = end;
        });
        decode_open_block(src, end, 1, {
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
    sched->msghash->final(sched->msghash, data + datalen, PTLS_HASH_FINAL_MODE_SNAPSHOT);
    datalen += sched->algo->digest_size;
    assert(datalen <= PTLS_MAX_CERTIFICATE_VERIFY_SIGNDATA_SIZE);

    return datalen;
}

static int calc_verify_data(void *output, struct st_ptls_key_schedule_t *sched, const void *secret)
{
    ptls_hash_context_t *hmac;
    uint8_t digest[PTLS_MAX_DIGEST_SIZE];
    int ret;

    if ((ret = hkdf_expand_label(sched->algo, digest, sched->algo->digest_size, ptls_iovec_init(secret, sched->algo->digest_size),
                                 "finished", ptls_iovec_init(NULL, 0))) != 0)
        return ret;
    if ((hmac = ptls_hmac_create(sched->algo, digest, sched->algo->digest_size)) == NULL) {
        ptls_clear_memory(digest, sizeof(digest));
        return PTLS_ERROR_NO_MEMORY;
    }

    sched->msghash->final(sched->msghash, digest, PTLS_HASH_FINAL_MODE_SNAPSHOT);
    PTLS_DEBUGF("%s: %02x%02x,%02x%02x\n", __FUNCTION__, ((uint8_t *)secret)[0], ((uint8_t *)secret)[1], digest[0], digest[1]);
    hmac->update(hmac, digest, sched->algo->digest_size);
    ptls_clear_memory(digest, sizeof(digest));
    hmac->final(hmac, output, PTLS_HASH_FINAL_MODE_FREE);

    return 0;
}

static int verify_finished(ptls_t *tls, ptls_iovec_t message)
{
    uint8_t verify_data[PTLS_MAX_DIGEST_SIZE];
    int ret;

    if (PTLS_HANDSHAKE_HEADER_SIZE + tls->key_schedule->algo->digest_size != message.len) {
        ret = PTLS_ALERT_DECODE_ERROR;
        goto Exit;
    }

    if ((ret = calc_verify_data(verify_data, tls->key_schedule, tls->traffic_protection.dec.secret)) != 0)
        goto Exit;
    if (memcmp(message.base + PTLS_HANDSHAKE_HEADER_SIZE, verify_data, tls->key_schedule->algo->digest_size) != 0) {
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

    buffer_encrypt(sendbuf, tls->traffic_protection.enc.aead, {
        buffer_push_handshake(sendbuf, tls->key_schedule, PTLS_HANDSHAKE_TYPE_FINISHED, {
            if ((ret = ptls_buffer_reserve(sendbuf, tls->key_schedule->algo->digest_size)) != 0)
                goto Exit;
            if ((ret = calc_verify_data(sendbuf->base + sendbuf->off, tls->key_schedule, tls->traffic_protection.enc.secret)) != 0)
                goto Exit;
            sendbuf->off += tls->key_schedule->algo->digest_size;
        });
    });

Exit:
    return ret;
}

static int send_session_ticket(ptls_t *tls, ptls_buffer_t *sendbuf)
{
    ptls_hash_context_t *msghash_backup = tls->key_schedule->msghash->clone_(tls->key_schedule->msghash);
    ptls_buffer_t session_id;
    char session_id_smallbuf[128];
    uint32_t ticket_age_add;
    int ret = 0;

    assert(tls->ctx->ticket_lifetime != 0);
    assert(tls->ctx->encrypt_ticket != NULL);

    /* calculate verify-data that will be sent by the client */
    buffer_calc_handshake_hash(sendbuf, tls->key_schedule, PTLS_HANDSHAKE_TYPE_FINISHED, {
        if ((ret = ptls_buffer_reserve(sendbuf, tls->key_schedule->algo->digest_size)) != 0)
            goto Exit;
        if ((ret = calc_verify_data(sendbuf->base + sendbuf->off, tls->key_schedule,
                                    tls->server.early_data != NULL ? tls->server.early_data->next_secret
                                                                   : tls->traffic_protection.dec.secret)) != 0)
            goto Exit;
        sendbuf->off += tls->key_schedule->algo->digest_size;
    });

    tls->ctx->random_bytes(&ticket_age_add, sizeof(ticket_age_add));

    /* build the raw nsk */
    ptls_buffer_init(&session_id, session_id_smallbuf, sizeof(session_id_smallbuf));
    ret = encode_session_identifier(&session_id, ticket_age_add, tls->key_schedule, tls->server_name, tls->cipher_suite->id,
                                    tls->negotiated_protocol);
    if (ret != 0)
        goto Exit;

    /* encrypt and send */
    buffer_encrypt(sendbuf, tls->traffic_protection.enc.aead, {
        buffer_push_handshake(sendbuf, tls->key_schedule, PTLS_HANDSHAKE_TYPE_NEW_SESSION_TICKET, {
            ptls_buffer_push32(sendbuf, tls->ctx->ticket_lifetime);
            ptls_buffer_push32(sendbuf, ticket_age_add);
            ptls_buffer_push_block(sendbuf, 2, {
                if ((ret = tls->ctx->encrypt_ticket->cb(tls->ctx->encrypt_ticket, tls, sendbuf,
                                                        ptls_iovec_init(session_id.base, session_id.off))) != 0)
                    goto Exit;
            });
            ptls_buffer_push_block(sendbuf, 2, {
                if (tls->ctx->max_early_data_size != 0)
                    buffer_push_extension(sendbuf, PTLS_EXTENSION_TYPE_TICKET_EARLY_DATA_INFO,
                                          { ptls_buffer_push32(sendbuf, tls->ctx->max_early_data_size); });
            });
        });
    });

Exit:
    ptls_buffer_dispose(&session_id);

    /* restore handshake state */
    tls->key_schedule->msghash->final(tls->key_schedule->msghash, NULL, PTLS_HASH_FINAL_MODE_FREE);
    tls->key_schedule->msghash = msghash_backup;

    return ret;
}

static int send_client_hello(ptls_t *tls, ptls_buffer_t *sendbuf, ptls_handshake_properties_t *properties,
                             ptls_key_exchange_algorithm_t *key_share, ptls_iovec_t cookie)
{
    ptls_iovec_t resumption_secret = {NULL}, resumption_ticket;
    ptls_cipher_suite_t *resumption_cipher_suite = NULL;
    uint32_t obfuscated_ticket_age = 0;
    size_t msghash_off;
    uint8_t binder_key[PTLS_MAX_DIGEST_SIZE];
    int ret, is_second_flight = tls->key_schedule != NULL;

    /* TODO postpone the designation of the  digest alrogithm until we receive ServerHello so that we can choose the best hash algo
     * (note: we'd need to retain the entire ClientHello) */
    ptls_hash_algorithm_t *key_schedule_hash = tls->ctx->cipher_suites[0]->hash;

    if (properties != NULL) {
        /* setup resumption-related data. If successful, resumption_secret becomes a non-zero value. */
        if (properties->client.session_ticket.base != NULL) {
            uint32_t max_early_data_size;
            if (decode_stored_session_ticket(tls->ctx, &resumption_cipher_suite, &resumption_secret, &obfuscated_ticket_age,
                                             &resumption_ticket, &max_early_data_size, properties->client.session_ticket.base,
                                             properties->client.session_ticket.base + properties->client.session_ticket.len) == 0 &&
                resumption_cipher_suite->hash == key_schedule_hash) {
                tls->client.offered_psk = 1;
                if (max_early_data_size != 0 && properties->client.max_early_data_size != NULL) {
                    *properties->client.max_early_data_size = max_early_data_size;
                    tls->client.send_early_data = 1;
                }
            } else {
                resumption_secret = ptls_iovec_init(NULL, 0);
            }
        }
        if (properties->client.max_early_data_size != NULL && !tls->client.send_early_data)
            *properties->client.max_early_data_size = 0;
    }

    if (!is_second_flight) {
        tls->key_schedule = key_schedule_new(key_schedule_hash);
        if ((ret = key_schedule_extract(tls->key_schedule, resumption_secret)) != 0)
            goto Exit;
    }

    msghash_off = sendbuf->off + 5;
    buffer_push_handshake(sendbuf, NULL, PTLS_HANDSHAKE_TYPE_CLIENT_HELLO, {
        /* legacy_version */
        ptls_buffer_push16(sendbuf, 0x0303);
        /* random_bytes */
        ptls_buffer_pushv(sendbuf, tls->client_random, sizeof(tls->client_random));
        /* lecagy_session_id */
        ptls_buffer_push_block(sendbuf, 1, {});
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
                ptls_buffer_push_block(sendbuf, 1, { ptls_buffer_push16(sendbuf, PTLS_PROTOCOL_VERSION_DRAFT18); });
            });
            buffer_push_extension(sendbuf, PTLS_EXTENSION_TYPE_SIGNATURE_ALGORITHMS, {
                ptls_buffer_push_block(sendbuf, 2, {
                    ptls_buffer_push16(sendbuf, PTLS_SIGNATURE_RSA_PSS_SHA256);
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
                    if (key_share != NULL) {
                        ptls_iovec_t pubkey;
                        if ((ret = key_share->create(&tls->client.key_exchange.ctx, &pubkey)) != 0)
                            goto Exit;
                        tls->client.key_exchange.algo = key_share;
                        ptls_buffer_push16(sendbuf, tls->client.key_exchange.algo->id);
                        ptls_buffer_push_block(sendbuf, 2, { ptls_buffer_pushv(sendbuf, pubkey.base, pubkey.len); });
                    }
                });
            });
            if (tls->ctx->save_ticket != NULL) {
                buffer_push_extension(sendbuf, PTLS_EXTENSION_TYPE_PSK_KEY_EXCHANGE_MODES, {
                    ptls_buffer_push_block(sendbuf, 1, {
                        if (!tls->ctx->require_dhe_on_psk)
                            ptls_buffer_push(sendbuf, PTLS_PSK_KE_MODE_PSK);
                        ptls_buffer_push(sendbuf, PTLS_PSK_KE_MODE_PSK_DHE);
                    });
                });
                if (resumption_secret.base != NULL) {
                    if (tls->client.send_early_data && !is_second_flight)
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
                                if ((ret = ptls_buffer_reserve(sendbuf, tls->key_schedule->algo->digest_size)) != 0)
                                    goto Exit;
                                sendbuf->off += tls->key_schedule->algo->digest_size;
                            });
                        });
                    });
                }
            }
            if (cookie.base != NULL) {
                buffer_push_extension(sendbuf, PTLS_EXTENSION_TYPE_COOKIE, {
                    ptls_buffer_push_block(sendbuf, 2, { ptls_buffer_pushv(sendbuf, cookie.base, cookie.len); });
                });
            }
        });
    });

    /* update the message hash, filling in the PSK binder HMAC if necessary */
    if (resumption_secret.base != NULL) {
        size_t psk_binder_off = sendbuf->off - (3 + tls->key_schedule->algo->digest_size);
        if ((ret = derive_secret(tls->key_schedule, binder_key, "resumption psk binder key")) != 0)
            goto Exit;
        key_schedule_update_hash(tls->key_schedule, sendbuf->base + msghash_off, psk_binder_off - msghash_off);
        msghash_off = psk_binder_off;
        if ((ret = calc_verify_data(sendbuf->base + psk_binder_off + 3, tls->key_schedule, binder_key)) != 0)
            goto Exit;
    }
    key_schedule_update_hash(tls->key_schedule, sendbuf->base + msghash_off, sendbuf->off - msghash_off);

    if (tls->client.send_early_data) {
        if ((ret = setup_traffic_protection(tls, resumption_cipher_suite, 1, "client early traffic secret",
                                            "CLIENT_EARLY_TRAFFIC_SECRET")) != 0)
            goto Exit;
        tls->state = PTLS_STATE_CLIENT_SEND_EARLY_DATA;
    } else {
        tls->state = PTLS_STATE_CLIENT_EXPECT_SERVER_HELLO;
    }
    ret = PTLS_ERROR_IN_PROGRESS;

Exit:
    ptls_clear_memory(binder_key, sizeof(binder_key));
    return ret;
}

static int decode_key_share_entry(uint16_t *group, ptls_iovec_t *key_exchange, const uint8_t **src, const uint8_t *end)
{
    int ret;

    if ((ret = decode16(group, src, end)) != 0)
        goto Exit;
    decode_open_block(*src, end, 2, {
        *key_exchange = ptls_iovec_init(*src, end - *src);
        *src = end;
    });

Exit:
    return ret;
}

static int check_server_hello_version(uint16_t ver)
{
    if (ver != PTLS_PROTOCOL_VERSION_DRAFT18)
        return PTLS_ALERT_HANDSHAKE_FAILURE;
    return 0;
}

static int client_handle_hello_retry_request(ptls_t *tls, ptls_buffer_t *sendbuf, ptls_iovec_t message,
                                             ptls_handshake_properties_t *properties)
{
    const uint8_t *src = message.base + PTLS_HANDSHAKE_HEADER_SIZE, *end = message.base + message.len;
    uint16_t type;
    ptls_key_exchange_algorithm_t **selected_group = NULL;
    ptls_iovec_t cookie = {NULL};
    int ret;

    { /* check protocol version */
        uint16_t ver;
        if ((ret = decode16(&ver, &src, end)) != 0 || (ret = check_server_hello_version(ver)) != 0)
            goto Exit;
    }

    decode_extensions(src, end, PTLS_HANDSHAKE_TYPE_HELLO_RETRY_REQUEST, &type, {
        switch (type) {
        case PTLS_EXTENSION_TYPE_KEY_SHARE: {
            uint16_t id;
            if ((ret = decode16(&id, &src, end)) != 0)
                goto Exit;
            /* we offer the first key_exchanges[0] as KEY_SHARE unless client.negotiate_before_key_exchange is set */
            for (selected_group =
                     tls->ctx->key_exchanges + (properties != NULL && properties->client.negotiate_before_key_exchange ? 0 : 1);
                 *selected_group != NULL; ++selected_group)
                if ((*selected_group)->id == id)
                    break;
            if (*selected_group == NULL) {
                ret = PTLS_ALERT_ILLEGAL_PARAMETER;
                goto Exit;
            }
        } break;
        case PTLS_EXTENSION_TYPE_COOKIE:
            decode_block(src, end, 2, {
                if (src == end) {
                    ret = PTLS_ALERT_DECODE_ERROR;
                    goto Exit;
                }
                cookie = ptls_iovec_init(src, end - src);
                end = src;
            });
            break;
        }
    });

    if (selected_group == NULL) {
        ret = PTLS_ALERT_DECODE_ERROR;
        goto Exit;
    }

    key_schedule_update_hash(tls->key_schedule, message.base, message.len);
    ret = send_client_hello(tls, sendbuf, properties, *selected_group, cookie);

Exit:
    return ret;
}

static int decode_server_hello(ptls_t *tls, struct st_ptls_server_hello_t *sh, const uint8_t *src, const uint8_t *end)
{
    uint16_t selected_psk_identity = UINT16_MAX;
    int ret;

    *sh = (struct st_ptls_server_hello_t){};

    { /* check protocol version */
        uint16_t ver;
        if ((ret = decode16(&ver, &src, end)) != 0 || (ret = check_server_hello_version(ver)) != 0)
            goto Exit;
    }

    /* skip random */
    if (end - src < PTLS_HELLO_RANDOM_SIZE) {
        ret = PTLS_ALERT_DECODE_ERROR;
        goto Exit;
    }
    src += PTLS_HELLO_RANDOM_SIZE;

    { /* select cipher_suite */
        uint16_t csid;
        ptls_cipher_suite_t **cs;
        if ((ret = decode16(&csid, &src, end)) != 0)
            goto Exit;
        for (cs = tls->ctx->cipher_suites; *cs != NULL; ++cs)
            if ((*cs)->id == csid)
                break;
        if (*cs == NULL) {
            ret = PTLS_ALERT_HANDSHAKE_FAILURE;
            goto Exit;
        }
        tls->cipher_suite = *cs;
    }

    uint16_t type;
    decode_extensions(src, end, PTLS_HANDSHAKE_TYPE_SERVER_HELLO, &type, {
        switch (type) {
        case PTLS_EXTENSION_TYPE_SUPPORTED_VERSIONS:
            ret = PTLS_ALERT_DECODE_ERROR;
            goto Exit;
        case PTLS_EXTENSION_TYPE_KEY_SHARE: {
            uint16_t group;
            if ((ret = decode_key_share_entry(&group, &sh->peerkey, &src, end)) != 0)
                goto Exit;
            if (src != end) {
                ret = PTLS_ALERT_DECODE_ERROR;
                goto Exit;
            }
            if (tls->client.key_exchange.algo == NULL || tls->client.key_exchange.algo->id != group) {
                ret = PTLS_ALERT_ILLEGAL_PARAMETER;
                goto Exit;
            }
        } break;
        case PTLS_EXTENSION_TYPE_PRE_SHARED_KEY:
            if ((ret = decode16(&selected_psk_identity, &src, end)) != 0)
                goto Exit;
            break;
        default:
            src = end;
            break;
        }
    });

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

    ret = 0;
Exit:
    return ret;
}

static int client_handle_hello(ptls_t *tls, ptls_iovec_t message)
{
    struct st_ptls_server_hello_t sh;
    ptls_iovec_t ecdh_secret = {NULL};
    int ret;

    if ((ret = decode_server_hello(tls, &sh, message.base + PTLS_HANDSHAKE_HEADER_SIZE, message.base + message.len)) != 0)
        goto Exit;

    if (sh.peerkey.base != NULL) {
        if ((ret = tls->client.key_exchange.ctx->on_exchange(&tls->client.key_exchange.ctx, &ecdh_secret, sh.peerkey)) != 0)
            goto Exit;
    }

    if (tls->client.offered_psk && !tls->is_psk_handshake)
        key_schedule_reset_psk(tls->key_schedule);
    key_schedule_update_hash(tls->key_schedule, message.base, message.len);

    if ((ret = key_schedule_extract(tls->key_schedule, ecdh_secret)) != 0)
        goto Exit;
    if ((ret = setup_traffic_protection(tls, tls->cipher_suite, 1, "client handshake traffic secret",
                                        "CLIENT_HANDSHAKE_TRAFFIC_SECRET")) != 0)
        goto Exit;
    if ((ret = setup_traffic_protection(tls, tls->cipher_suite, 0, "server handshake traffic secret",
                                        "SERVER_HANDSHAKE_TRAFFIC_SECRET")) != 0)
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

static int client_handle_encrypted_extensions(ptls_t *tls, ptls_iovec_t message, ptls_handshake_properties_t *properties)
{
    const uint8_t *src = message.base + PTLS_HANDSHAKE_HEADER_SIZE, *end = message.base + message.len;
    uint16_t type;
    int ret;

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
            decode_block(src, end, 2, {
                decode_open_block(src, end, 1, {
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
            if (!tls->client.send_early_data) {
                ret = PTLS_ALERT_ILLEGAL_PARAMETER;
                goto Exit;
            }
            if (properties != NULL)
                properties->client.early_data_accepted_by_peer = 1;
            break;
        default:
            break;
        }
        src = end;
    });

    key_schedule_update_hash(tls->key_schedule, message.base, message.len);
    tls->state = tls->is_psk_handshake ? PTLS_STATE_CLIENT_EXPECT_FINISHED : PTLS_STATE_CLIENT_EXPECT_CERTIFICATE;
    ret = PTLS_ERROR_IN_PROGRESS;

Exit:
    return ret;
}

static int client_handle_certificate(ptls_t *tls, ptls_iovec_t message)
{
    const uint8_t *src = message.base + PTLS_HANDSHAKE_HEADER_SIZE, *end = message.base + message.len;
    ptls_iovec_t certs[16];
    size_t num_certs = 0;
    int ret;

    /* certificate request context */
    decode_open_block(src, end, 1, {
        if (src != end) {
            ret = PTLS_ALERT_ILLEGAL_PARAMETER;
            goto Exit;
        }
    });
    /* certificate_list */
    decode_block(src, end, 3, {
        do {
            decode_open_block(src, end, 3, {
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
    const uint8_t *src = message.base + PTLS_HANDSHAKE_HEADER_SIZE, *end = message.base + message.len;
    uint16_t algo;
    ptls_iovec_t signature;
    uint8_t signdata[PTLS_MAX_CERTIFICATE_VERIFY_SIGNDATA_SIZE];
    size_t signdata_size;
    int ret;

    /* decode */
    if ((ret = decode16(&algo, &src, end)) != 0)
        goto Exit;
    decode_block(src, end, 2, {
        signature = ptls_iovec_init(src, end - src);
        src = end;
    });

    /* validate */
    switch (algo) {
    case PTLS_SIGNATURE_RSA_PSS_SHA256:
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
    if ((ret = setup_traffic_protection(tls, tls->cipher_suite, 0, "server application traffic secret",
                                        "SERVER_TRAFFIC_SECRET_0")) != 0)
        goto Exit;
    if ((ret = derive_secret(tls->key_schedule, send_secret, "client application traffic secret")) != 0)
        goto Exit;

    ret = send_finished(tls, sendbuf);

    memcpy(tls->traffic_protection.enc.secret, send_secret, sizeof(send_secret));
    if ((ret = setup_traffic_protection(tls, tls->cipher_suite, 1, NULL, "CLIENT_TRAFFIC_SECRET_0")) != 0)
        goto Exit;

    tls->state = PTLS_STATE_CLIENT_POST_HANDSHAKE;

Exit:
    ptls_clear_memory(send_secret, sizeof(send_secret));
    return ret;
}

static int client_handle_new_session_ticket(ptls_t *tls, ptls_iovec_t message)
{
    const uint8_t *src = message.base + PTLS_HANDSHAKE_HEADER_SIZE, *end = message.base + message.len;
    int ret;

    { /* verify the format */
        uint32_t ticket_lifetime, ticket_age_add, max_early_data_size;
        ptls_iovec_t ticket;
        if ((ret = decode_new_session_ticket(&ticket_lifetime, &ticket_age_add, &ticket, &max_early_data_size, src, end)) != 0)
            return ret;
    }

    /* do nothing if use of session ticket is disabled */
    if (tls->ctx->save_ticket == NULL)
        return 0;

    /* save the extension, along with the key of myself */
    ptls_buffer_t ticket_buf;
    uint8_t ticket_buf_small[512];
    ptls_buffer_init(&ticket_buf, ticket_buf_small, sizeof(ticket_buf_small));
    ptls_buffer_push64(&ticket_buf, gettime_millis());
    ptls_buffer_push16(&ticket_buf, tls->cipher_suite->id);
    ptls_buffer_push_block(&ticket_buf, 3, { ptls_buffer_pushv(&ticket_buf, src, end - src); });
    ptls_buffer_push_block(&ticket_buf, 2, {
        if ((ret = ptls_buffer_reserve(&ticket_buf, tls->key_schedule->algo->digest_size)) != 0)
            goto Exit;
        if ((ret = derive_resumption_secret(tls->key_schedule, ticket_buf.base + ticket_buf.off)) != 0)
            goto Exit;
        ticket_buf.off += tls->key_schedule->algo->digest_size;
    });

    if ((ret = tls->ctx->save_ticket->cb(tls->ctx->save_ticket, tls, ptls_iovec_init(ticket_buf.base, ticket_buf.off))) != 0)
        goto Exit;

    ret = 0;
Exit:
    ptls_buffer_dispose(&ticket_buf);
    return ret;
}

static int client_hello_decode_server_name(ptls_iovec_t *name, const uint8_t *src, const uint8_t *end)
{
    int ret = 0;

    decode_block(src, end, 2, {
        if (src == end) {
            ret = PTLS_ALERT_DECODE_ERROR;
            goto Exit;
        }
        do {
            uint8_t type = *src++;
            decode_open_block(src, end, 2, {
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
                               const uint8_t *end)
{
    int ret;

    decode_block(src, end, 2, {
        while (src != end) {
            uint16_t id;
            if ((ret = decode16(&id, &src, end)) != 0)
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
                            ptls_key_exchange_algorithm_t **candidates, const uint8_t *src, const uint8_t *end)
{
    int ret;

    decode_block(src, end, 2, {
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
                                   const uint8_t *src, const uint8_t *end)
{
    int ret;

    decode_block(src, end, 2, {
        while (src != end) {
            uint16_t group;
            if ((ret = decode16(&group, &src, end)) != 0)
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

static int decode_client_hello(struct st_ptls_client_hello_t *ch, const uint8_t *src, const uint8_t *end)
{
    uint16_t exttype = 0;
    int ret;

    { /* check protocol version */
        uint16_t protver;
        if ((ret = decode16(&protver, &src, end)) != 0)
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
    decode_open_block(src, end, 1, {
        if (end - src > 32) {
            ret = PTLS_ALERT_DECODE_ERROR;
            goto Exit;
        }
        src = end;
    });

    /* decode and select from ciphersuites */
    decode_open_block(src, end, 2, {
        ch->cipher_suites = ptls_iovec_init(src - 2, end - src + 2);
        src = end;
    });

    /* decode legacy_compression_methods */
    decode_open_block(src, end, 1, {
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
            decode_block(src, end, 2, {
                do {
                    decode_open_block(src, end, 1, {
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
            decode_block(src, end, 2, {
                do {
                    uint16_t id;
                    if ((ret = decode16(&id, &src, end)) != 0)
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
            decode_block(src, end, 1, {
                do {
                    uint16_t v;
                    if ((ret = decode16(&v, &src, end)) != 0)
                        goto Exit;
                    if (ch->selected_version == 0 && v == PTLS_PROTOCOL_VERSION_DRAFT18)
                        ch->selected_version = v;
                } while (src != end);
            });
            break;
        case PTLS_EXTENSION_TYPE_COOKIE:
            /* we never send cookie */
            ret = PTLS_ALERT_ILLEGAL_PARAMETER;
            goto Exit;
        case PTLS_EXTENSION_TYPE_PRE_SHARED_KEY: {
            size_t num_identities = 0;
            decode_open_block(src, end, 2, {
                do {
                    struct st_ptls_client_hello_psk_t psk = {{NULL}};
                    decode_open_block(src, end, 2, {
                        psk.identity = ptls_iovec_init(src, end - src);
                        src = end;
                    });
                    if ((ret = decode32(&psk.obfuscated_ticket_age, &src, end)) != 0)
                        goto Exit;
                    if (ch->psk.identities.count < sizeof(ch->psk.identities.list) / sizeof(ch->psk.identities.list[0]))
                        ch->psk.identities.list[ch->psk.identities.count++] = psk;
                    ++num_identities;
                } while (src != end);
            });
            ch->psk.hash_end = src;
            decode_block(src, end, 2, {
                size_t num_binders = 0;
                do {
                    decode_open_block(src, end, 1, {
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
            decode_block(src, end, 1, {
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
            break;
        }
        src = end;
    });

    /* check if client hello make sense */
    switch (ch->selected_version) {
    case PTLS_PROTOCOL_VERSION_DRAFT18:
        if (!(ch->compression_methods.count == 1 && ch->compression_methods.ids[0] == 0)) {
            ret = PTLS_ALERT_ILLEGAL_PARAMETER;
            goto Exit;
        }
        /* cookie can be missing, quote section 4.2.2: When sending a HelloRetryRequest, the server MAY provide a “cookie” extension
         * to the client (this is an exception to the usual rule that the only extensions that may be sent are those that appear in
         * the ClientHello). */
        if (ch->negotiated_groups.base == NULL || ch->key_shares.base == NULL || ch->signature_algorithms.count == 0) {
            ret = PTLS_ALERT_MISSING_EXTENSION;
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
        break;
    default:
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
    uint64_t issue_at, now = gettime_millis();
    uint32_t age_add;
    uint16_t ticket_csid;
    uint8_t decbuf_small[256], binder_key[PTLS_MAX_DIGEST_SIZE], verify_data[PTLS_MAX_DIGEST_SIZE];
    int ret;

    ptls_buffer_init(&decbuf, decbuf_small, sizeof(decbuf_small));

    for (*psk_index = 0; *psk_index < ch->psk.identities.count; ++*psk_index) {
        struct st_ptls_client_hello_psk_t *identity = ch->psk.identities.list + *psk_index;
        /* decrypt and decode */
        decbuf.off = 0;
        if ((tls->ctx->decrypt_ticket->cb(tls->ctx->decrypt_ticket, tls, &decbuf, identity->identity)) != 0)
            continue;
        if (decode_session_identifier(&issue_at, &ticket_psk, &age_add, &ticket_server_name, &ticket_csid,
                                      &ticket_negotiated_protocol, decbuf.base, decbuf.base + decbuf.off) != 0)
            continue;
        /* check age */
        if (now < issue_at)
            continue;
        if (now - issue_at > tls->ctx->ticket_lifetime)
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
        if (ticket_psk.len != tls->key_schedule->algo->digest_size)
            continue;
        if (ch->psk.identities.list[*psk_index].binder.len != tls->key_schedule->algo->digest_size)
            continue;

        /* found */
        goto Found;
    }

    /* not found */
    *psk_index = SIZE_MAX;
    *accept_early_data = 0;
    ret = 0;
    goto Exit;

Found:
    if ((ret = key_schedule_extract(tls->key_schedule, ticket_psk)) != 0)
        goto Exit;
    if ((ret = derive_secret(tls->key_schedule, binder_key, "resumption psk binder key")) != 0)
        goto Exit;
    key_schedule_update_hash(tls->key_schedule, ch_trunc.base, ch_trunc.len);
    if ((ret = calc_verify_data(verify_data, tls->key_schedule, binder_key)) != 0)
        goto Exit;
    if (memcmp(ch->psk.identities.list[*psk_index].binder.base, verify_data, tls->key_schedule->algo->digest_size) != 0) {
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

static int server_handle_hello(ptls_t *tls, ptls_buffer_t *sendbuf, ptls_iovec_t message, ptls_handshake_properties_t *properties,
                               int is_second_flight)
{
    struct st_ptls_client_hello_t ch = {NULL};
    struct {
        ptls_key_exchange_algorithm_t *algorithm;
        ptls_iovec_t peer_key;
    } key_share = {NULL};
    enum { HANDSHAKE_MODE_FULL, HANDSHAKE_MODE_PSK, HANDSHAKE_MODE_PSK_DHE } mode;
    size_t psk_index = SIZE_MAX;
    ptls_iovec_t pubkey = {}, ecdh_secret = {};
    uint8_t finished_key[PTLS_MAX_DIGEST_SIZE];
    int accept_early_data = 0, ret;

    /* decode ClientHello */
    if ((ret = decode_client_hello(&ch, message.base + PTLS_HANDSHAKE_HEADER_SIZE, message.base + message.len)) != 0)
        goto Exit;

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
            tls->key_schedule = key_schedule_new(cs->hash);
        } else {
            if (tls->cipher_suite != cs) {
                ret = PTLS_ALERT_HANDSHAKE_FAILURE;
                goto Exit;
            }
        }
    }

    /* select key_share */
    if ((ret = select_key_share(&key_share.algorithm, &key_share.peer_key, tls->ctx->key_exchanges, ch.key_shares.base,
                                ch.key_shares.base + ch.key_shares.len)) != 0)
        goto Exit;

    /* send HelloRetryRequest or abort the handshake if failed to obtain the key */
    if (key_share.algorithm == NULL) {
        if (!is_second_flight) {
            ptls_key_exchange_algorithm_t *negotiated_group;
            if ((ret = select_negotiated_group(&negotiated_group, tls->ctx->key_exchanges, ch.negotiated_groups.base,
                                               ch.negotiated_groups.base + ch.negotiated_groups.len)) != 0)
                goto Exit;
            key_schedule_update_hash(tls->key_schedule, message.base, message.len);
            assert(tls->key_schedule->generation == 0);
            key_schedule_extract(tls->key_schedule, ptls_iovec_init(NULL, 0));
            buffer_push_handshake(sendbuf, tls->key_schedule, PTLS_HANDSHAKE_TYPE_HELLO_RETRY_REQUEST, {
                ptls_buffer_push16(sendbuf, PTLS_PROTOCOL_VERSION_DRAFT18);
                ptls_buffer_push_block(sendbuf, 2, {
                    buffer_push_extension(sendbuf, PTLS_EXTENSION_TYPE_KEY_SHARE,
                                          { ptls_buffer_push16(sendbuf, negotiated_group->id); });
                });
            });
            tls->state = PTLS_STATE_SERVER_EXPECT_SECOND_CLIENT_HELLO;
            if (ch.psk.early_data_indication)
                tls->server.skip_early_data = 1;
            ret = PTLS_ERROR_IN_PROGRESS;
            goto Exit;
        } else {
            ret = PTLS_ALERT_HANDSHAKE_FAILURE;
            goto Exit;
        }
    }

    if (tls->ctx->require_dhe_on_psk)
        ch.psk.ke_modes &= ~(1u << PTLS_PSK_KE_MODE_PSK);

    /* try psk handshake */
    if (!is_second_flight && ch.psk.hash_end != 0 &&
        (ch.psk.ke_modes & ((1u << PTLS_PSK_KE_MODE_PSK) | (1u << PTLS_PSK_KE_MODE_PSK_DHE))) != 0 &&
        tls->ctx->decrypt_ticket != NULL) {
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
    }

    if (accept_early_data && tls->ctx->max_early_data_size != 0 && psk_index == 0) {
        if ((tls->server.early_data = malloc(sizeof(*tls->server.early_data))) == NULL) {
            ret = PTLS_ERROR_NO_MEMORY;
            goto Exit;
        }
        if ((ret = setup_traffic_protection(tls, tls->cipher_suite, 0, "client early traffic secret",
                                            "CLIENT_EARLY_TRAFFIC_SECRET")) != 0)
            goto Exit;
    }

    /* run key-exchange, to obtain pubkey and secret */
    if (mode != HANDSHAKE_MODE_PSK) {
        if ((ret = key_share.algorithm->exchange(&pubkey, &ecdh_secret, key_share.peer_key)) != 0)
            goto Exit;
    }

    /* send ServerHello */
    buffer_push_handshake(sendbuf, tls->key_schedule, PTLS_HANDSHAKE_TYPE_SERVER_HELLO, {
        ptls_buffer_push16(sendbuf, PTLS_PROTOCOL_VERSION_DRAFT18);
        if ((ret = ptls_buffer_reserve(sendbuf, PTLS_HELLO_RANDOM_SIZE)) != 0)
            goto Exit;
        tls->ctx->random_bytes(sendbuf->base + sendbuf->off, PTLS_HELLO_RANDOM_SIZE);
        sendbuf->off += PTLS_HELLO_RANDOM_SIZE;
        ptls_buffer_push16(sendbuf, tls->cipher_suite->id);
        ptls_buffer_push_block(sendbuf, 2, {
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
    });

    /* create protection contexts for the handshake */
    assert(tls->key_schedule->generation == 1);
    key_schedule_extract(tls->key_schedule, ecdh_secret);
    if ((ret = setup_traffic_protection(tls, tls->cipher_suite, 1, "server handshake traffic secret",
                                        "SERVER_HANDSHAKE_TRAFFIC_SECRET")) != 0)
        goto Exit;
    if (tls->server.early_data != NULL) {
        if ((ret = derive_secret(tls->key_schedule, tls->server.early_data->next_secret, "client handshake traffic secret")) != 0)
            goto Exit;
    } else {
        if ((ret = setup_traffic_protection(tls, tls->cipher_suite, 0, "client handshake traffic secret",
                                            "CLIENT_HANDSHAKE_TRAFFIC_SECRET")) != 0)
            goto Exit;
        if (ch.psk.early_data_indication)
            tls->server.skip_early_data = 1;
    }

    /* send EncryptedExtensions */
    buffer_encrypt(sendbuf, tls->traffic_protection.enc.aead, {
        buffer_push_handshake(sendbuf, tls->key_schedule, PTLS_HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS, {
            ptls_buffer_push_block(sendbuf, 2, {
                if (tls->server_name != NULL) {
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
                if (tls->server.early_data != NULL && tls->traffic_protection.dec.aead != NULL)
                    buffer_push_extension(sendbuf, PTLS_EXTENSION_TYPE_EARLY_DATA, {});
            });
        });
    });

    if (mode == HANDSHAKE_MODE_FULL) {
        /* send Certificate */
        buffer_encrypt(sendbuf, tls->traffic_protection.enc.aead, {
            buffer_push_handshake(sendbuf, tls->key_schedule, PTLS_HANDSHAKE_TYPE_CERTIFICATE, {
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
        });
        /* build and send CertificateVerify */
        buffer_encrypt(sendbuf, tls->traffic_protection.enc.aead, {
            buffer_push_handshake(sendbuf, tls->key_schedule, PTLS_HANDSHAKE_TYPE_CERTIFICATE_VERIFY, {
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
        });
    }

    send_finished(tls, sendbuf);

    assert(tls->key_schedule->generation == 2);
    if ((ret = key_schedule_extract(tls->key_schedule, ptls_iovec_init(NULL, 0))) != 0)
        return ret;
    if ((ret = setup_traffic_protection(tls, tls->cipher_suite, 1, "server application traffic secret",
                                        "SERVER_TRAFFIC_SECRET_0")) != 0)
        return ret;

    tls->state = PTLS_STATE_SERVER_EXPECT_FINISHED;

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
}

static int server_handle_finished(ptls_t *tls, ptls_iovec_t message)
{
    int ret;

    if ((ret = verify_finished(tls, message)) != 0)
        return ret;

    if ((ret = setup_traffic_protection(tls, tls->cipher_suite, 0, "client application traffic secret",
                                        "CLIENT_TRAFFIC_SECRET_0")) != 0)
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

    if (rec->length > (rec->type == PTLS_CONTENT_TYPE_APPDATA ? PTLS_MAX_ENCRYPTED_RECORD_SIZE : PTLS_MAX_PLAINTEXT_RECORD_SIZE))
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
    const uint8_t *end = src + *len;
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
        if (addlen > end - src)
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

    if ((tls = malloc(sizeof(*tls))) == NULL)
        return NULL;

    update_open_count(ctx, 1);
    *tls = (ptls_t){ctx};
    if (!is_server) {
        tls->state = PTLS_STATE_CLIENT_HANDSHAKE_START;
        tls->ctx->random_bytes(tls->client_random, sizeof(tls->client_random));
    } else {
        tls->state = PTLS_STATE_SERVER_EXPECT_CLIENT_HELLO;
    }

    return tls;
}

void ptls_free(ptls_t *tls)
{
    ptls_buffer_dispose(&tls->recvbuf.rec);
    ptls_buffer_dispose(&tls->recvbuf.mess);
    if (tls->key_schedule != NULL)
        key_schedule_free(tls->key_schedule);
    if (tls->traffic_protection.dec.aead != NULL)
        ptls_aead_free(tls->traffic_protection.dec.aead);
    if (tls->traffic_protection.enc.aead != NULL)
        ptls_aead_free(tls->traffic_protection.enc.aead);
    free(tls->server_name);
    free(tls->negotiated_protocol);
    if (tls->client.key_exchange.ctx != NULL)
        tls->client.key_exchange.ctx->on_exchange(&tls->client.key_exchange.ctx, NULL, ptls_iovec_init(NULL, 0));
    if (tls->client.certificate_verify.cb != NULL)
        tls->client.certificate_verify.cb(tls->client.certificate_verify.verify_ctx, ptls_iovec_init(NULL, 0),
                                          ptls_iovec_init(NULL, 0));
    if (tls->server.early_data != NULL) {
        ptls_clear_memory(tls->server.early_data, sizeof(*tls->server.early_data));
        free(tls->server.early_data);
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

int ptls_is_early_data(ptls_t *tls)
{
    return tls->server.early_data != NULL;
}

int ptls_is_psk_handshake(ptls_t *tls)
{
    return tls->is_psk_handshake;
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
            ret = client_handle_hello(tls, message);
        } else if (tls->state != PTLS_STATE_CLIENT_EXPECT_SECOND_SERVER_HELLO && type == PTLS_HANDSHAKE_TYPE_HELLO_RETRY_REQUEST) {
            ret = client_handle_hello_retry_request(tls, sendbuf, message, properties);
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
            ret =
                server_handle_hello(tls, sendbuf, message, properties, tls->state == PTLS_STATE_SERVER_EXPECT_SECOND_CLIENT_HELLO);
        } else {
            ret = PTLS_ALERT_HANDSHAKE_FAILURE;
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
        case PTLS_ALERT_END_OF_EARLY_DATA:
            /* switch to using the next traffic key */
            if (tls->server.early_data == NULL)
                return 0;
            memcpy(tls->traffic_protection.dec.secret, tls->server.early_data->next_secret, PTLS_MAX_DIGEST_SIZE);
            ptls_clear_memory(tls->server.early_data, sizeof(*tls->server.early_data));
            free(tls->server.early_data);
            tls->server.early_data = NULL;
            return setup_traffic_protection(tls, tls->cipher_suite, 0, NULL, "CLIENT_HANDSHAKE_TRAFFIC_SECRET");
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
        if (src_end - src < mess_len)
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
    if (tls->traffic_protection.dec.aead != NULL) {
        if (rec.type != PTLS_CONTENT_TYPE_APPDATA)
            return PTLS_ALERT_HANDSHAKE_FAILURE;
        if ((ret = ptls_buffer_reserve(decryptbuf, 5 + rec.length)) != 0)
            return ret;
        if ((ret = ptls_aead_transform(tls->traffic_protection.dec.aead, decryptbuf->base + decryptbuf->off, &rec.length,
                                       rec.fragment, rec.length, 0)) != 0) {
            if (tls->server.skip_early_data) {
                ret = PTLS_ERROR_IN_PROGRESS;
                goto NextRecord;
            }
            return ret;
        }
        tls->server.skip_early_data = 0;
        rec.fragment = decryptbuf->base + decryptbuf->off;
        /* skip padding */
        for (; rec.length != 0; --rec.length)
            if (rec.fragment[rec.length - 1] != 0)
                break;
        if (rec.length == 0)
            return PTLS_ALERT_UNEXPECTED_MESSAGE;
        rec.type = rec.fragment[--rec.length];
    } else if (rec.type == PTLS_CONTENT_TYPE_APPDATA && tls->server.skip_early_data) {
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
            } else if (tls->state == PTLS_STATE_SERVER_EXPECT_FINISHED) {
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
        return send_client_hello(
            tls, sendbuf, properties,
            properties != NULL && properties->client.negotiate_before_key_exchange ? NULL : tls->ctx->key_exchanges[0],
            ptls_iovec_init(NULL, 0));
    case PTLS_STATE_CLIENT_SEND_EARLY_DATA:
        if ((ret = ptls_send_alert(tls, sendbuf, PTLS_ALERT_LEVEL_WARNING, PTLS_ALERT_END_OF_EARLY_DATA)) != 0)
            return ret;
        tls->state = PTLS_STATE_CLIENT_EXPECT_SERVER_HELLO;
        break;
    default:
        break;
    }

    const uint8_t *src = input, *src_end = src + *inlen;
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

    if (!(ret == 0 || ret == PTLS_ERROR_IN_PROGRESS)) {
        /* flush partially written response */
        ptls_clear_memory(sendbuf->base + sendbuf_orig_off, sendbuf->off - sendbuf_orig_off);
        sendbuf->off = sendbuf_orig_off;
        /* send alert immediately */
        if (PTLS_ERROR_GET_CLASS(ret) != PTLS_ERROR_CLASS_PEER_ALERT)
            if (ptls_send_alert(tls, sendbuf, PTLS_ALERT_LEVEL_FATAL,
                                PTLS_ERROR_GET_CLASS(ret) == PTLS_ERROR_CLASS_SELF_ALERT ? ret : PTLS_ALERT_INTERNAL_ERROR) != 0)
                sendbuf->off = sendbuf_orig_off;
    }

    *inlen -= src_end - src;
    return ret;
}

int ptls_receive(ptls_t *tls, ptls_buffer_t *decryptbuf, const void *_input, size_t *inlen)
{
    const uint8_t *input = (const uint8_t *)_input, *end = input + *inlen;
    size_t decryptbuf_orig_size = decryptbuf->off;
    int ret = 0;

    assert(tls->state >= PTLS_STATE_SERVER_EXPECT_FINISHED);

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

int ptls_send(ptls_t *tls, ptls_buffer_t *sendbuf, const void *_input, size_t inlen)
{
    const uint8_t *input = (const uint8_t *)_input;
    size_t pt_size, enc_size;
    int ret = 0;

    assert(tls->state >= PTLS_STATE_SERVER_EXPECT_FINISHED || tls->state == PTLS_STATE_CLIENT_SEND_EARLY_DATA);

    for (; inlen != 0; input += pt_size, inlen -= pt_size) {
        pt_size = inlen;
        if (pt_size > PTLS_MAX_PLAINTEXT_RECORD_SIZE)
            pt_size = PTLS_MAX_PLAINTEXT_RECORD_SIZE;
        buffer_push_record(sendbuf, PTLS_CONTENT_TYPE_APPDATA, {
            if ((ret = ptls_buffer_reserve(sendbuf, pt_size + tls->traffic_protection.enc.aead->algo->tag_size + 1)) != 0)
                goto Exit;
            if ((ret = ptls_aead_transform(tls->traffic_protection.enc.aead, sendbuf->base + sendbuf->off, &enc_size, input,
                                           pt_size, PTLS_CONTENT_TYPE_APPDATA)) != 0)
                goto Exit;
            sendbuf->off += enc_size;
        });
    }

Exit:
    return ret;
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
    if (tls->traffic_protection.enc.aead != NULL &&
        (ret = buffer_encrypt_record(sendbuf, rec_start, tls->traffic_protection.enc.aead)) != 0)
        goto Exit;

Exit:
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
        uint8_t gen = i + 1;
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

ptls_aead_context_t *ptls_aead_new(ptls_aead_algorithm_t *aead, ptls_hash_algorithm_t *hash, int is_enc, const void *secret)
{
    ptls_aead_context_t *ctx;
    uint8_t key[PTLS_MAX_SECRET_SIZE];
    int ret;

    if ((ctx = (ptls_aead_context_t *)malloc(aead->context_size)) == NULL)
        return NULL;

    *ctx = (ptls_aead_context_t){aead};
    if ((ret = get_traffic_key(hash, key, aead->key_size, 0, secret)) != 0)
        goto Exit;
    if ((ret = get_traffic_key(hash, ctx->static_iv, aead->iv_size, 1, secret)) != 0)
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

int ptls_aead_transform(ptls_aead_context_t *ctx, void *output, size_t *outlen, const void *input, size_t inlen,
                        uint8_t enc_content_type)
{
    uint8_t iv[PTLS_MAX_IV_SIZE];
    size_t iv_size = ctx->algo->iv_size;
    int ret;

    { /* build iv */
        const uint8_t *s = ctx->static_iv;
        uint8_t *d = iv;
        size_t i = iv_size - 8;
        for (; i != 0; --i)
            *d++ = *s++;
        i = 64;
        do {
            i -= 8;
            *d++ = *s++ ^ (uint8_t)(ctx->seq >> i);
        } while (i != 0);
    }

    if ((ret = ctx->do_transform(ctx, output, outlen, input, inlen, iv, enc_content_type)) != 0)
        return ret;

    ++ctx->seq;
    return 0;
}

static void clear_memory(void *p, size_t len)
{
    if (len != 0)
        memset(p, 0, len);
}

void (*volatile ptls_clear_memory)(void *p, size_t len) = clear_memory;
