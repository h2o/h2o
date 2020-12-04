/*
 * Copyright (c) 2017 Fastly, Kazuho Oku
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
#include <inttypes.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/time.h>
#include "khash.h"
#include "quicly.h"
#include "quicly/defaults.h"
#include "quicly/sentmap.h"
#include "quicly/frame.h"
#include "quicly/streambuf.h"
#include "quicly/cc.h"
#if QUICLY_USE_EMBEDDED_PROBES
#include "embedded-probes.h"
#elif QUICLY_USE_DTRACE
#include "quicly-probes.h"
#endif
#include "quicly/retire_cid.h"

#define QUICLY_TLS_EXTENSION_TYPE_TRANSPORT_PARAMETERS 0xffa5
#define QUICLY_TRANSPORT_PARAMETER_ID_ORIGINAL_CONNECTION_ID 0
#define QUICLY_TRANSPORT_PARAMETER_ID_MAX_IDLE_TIMEOUT 1
#define QUICLY_TRANSPORT_PARAMETER_ID_STATELESS_RESET_TOKEN 2
#define QUICLY_TRANSPORT_PARAMETER_ID_MAX_UDP_PAYLOAD_SIZE 3
#define QUICLY_TRANSPORT_PARAMETER_ID_INITIAL_MAX_DATA 4
#define QUICLY_TRANSPORT_PARAMETER_ID_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL 5
#define QUICLY_TRANSPORT_PARAMETER_ID_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE 6
#define QUICLY_TRANSPORT_PARAMETER_ID_INITIAL_MAX_STREAM_DATA_UNI 7
#define QUICLY_TRANSPORT_PARAMETER_ID_INITIAL_MAX_STREAMS_BIDI 8
#define QUICLY_TRANSPORT_PARAMETER_ID_INITIAL_MAX_STREAMS_UNI 9
#define QUICLY_TRANSPORT_PARAMETER_ID_ACK_DELAY_EXPONENT 10
#define QUICLY_TRANSPORT_PARAMETER_ID_MAX_ACK_DELAY 11
#define QUICLY_TRANSPORT_PARAMETER_ID_DISABLE_ACTIVE_MIGRATION 12
#define QUICLY_TRANSPORT_PARAMETER_ID_PREFERRED_ADDRESS 13
#define QUICLY_TRANSPORT_PARAMETER_ID_ACTIVE_CONNECTION_ID_LIMIT 14
#define QUICLY_TRANSPORT_PARAMETER_ID_INITIAL_SOURCE_CONNECTION_ID 15
#define QUICLY_TRANSPORT_PARAMETER_ID_RETRY_SOURCE_CONNECTION_ID 16
#define QUICLY_TRANSPORT_PARAMETER_ID_MAX_DATAGRAM_FRAME_SIZE 0x20
#define QUICLY_TRANSPORT_PARAMETER_ID_MIN_ACK_DELAY 0xff02de1a

/**
 * maximum size of token that quicly accepts
 */
#define QUICLY_MAX_TOKEN_LEN 512
/**
 * sends ACK bundled with PING, when number of gaps in the ack queue reaches or exceeds this threshold. This value should be much
 * smaller than QUICLY_MAX_RANGES.
 */
#define QUICLY_NUM_ACK_BLOCKS_TO_INDUCE_ACKACK 8

KHASH_MAP_INIT_INT64(quicly_stream_t, quicly_stream_t *)

#if QUICLY_USE_EMBEDDED_PROBES || QUICLY_USE_DTRACE
#define QUICLY_PROBE(label, conn, ...)                                                                                             \
    do {                                                                                                                           \
        quicly_conn_t *_conn = (conn);                                                                                             \
        if (PTLS_UNLIKELY(QUICLY_##label##_ENABLED()) && !ptls_skip_tracing(_conn->crypto.tls))                                    \
            QUICLY_##label(_conn, __VA_ARGS__);                                                                                    \
    } while (0)
#define QUICLY_PROBE_HEXDUMP(s, l)                                                                                                 \
    ({                                                                                                                             \
        size_t _l = (l);                                                                                                           \
        ptls_hexdump(alloca(_l * 2 + 1), (s), _l);                                                                                 \
    })
#define QUICLY_PROBE_ESCAPE_UNSAFE_STRING(s, l)                                                                                    \
    ({                                                                                                                             \
        size_t _l = (l);                                                                                                           \
        quicly_escape_unsafe_string(alloca(_l * 4 + 1), (s), _l);                                                                  \
    })
#else
#define QUICLY_PROBE(label, conn, ...)
#define QUICLY_PROBE_HEXDUMP(s, l)
#define QUICLY_PROBE_ESCAPE_UNSAFE_STRING(s, l)
#endif

struct st_quicly_cipher_context_t {
    ptls_aead_context_t *aead;
    ptls_cipher_context_t *header_protection;
};

struct st_quicly_pending_path_challenge_t {
    struct st_quicly_pending_path_challenge_t *next;
    uint8_t is_response;
    uint8_t data[QUICLY_PATH_CHALLENGE_DATA_LEN];
};

struct st_quicly_pn_space_t {
    /**
     * acks to be sent to remote peer
     */
    quicly_ranges_t ack_queue;
    /**
     * time at when the largest pn in the ack_queue has been received (or INT64_MAX if none)
     */
    int64_t largest_pn_received_at;
    /**
     *
     */
    uint64_t next_expected_packet_number;
    /**
     * number of ACK-eliciting packets that have not been ACKed yet
     */
    uint32_t unacked_count;
    /**
     * maximum number of ACK-eliciting packets to be queued before sending an ACK
     */
    uint32_t packet_tolerance;
    /**
     * boolean indicating if reorder should NOT trigger an immediate ack
     */
    uint8_t ignore_order;
};

struct st_quicly_handshake_space_t {
    struct st_quicly_pn_space_t super;
    struct {
        struct st_quicly_cipher_context_t ingress;
        struct st_quicly_cipher_context_t egress;
    } cipher;
    uint16_t largest_ingress_udp_payload_size;
};

struct st_quicly_application_space_t {
    struct st_quicly_pn_space_t super;
    struct {
        struct {
            struct {
                ptls_cipher_context_t *zero_rtt, *one_rtt;
            } header_protection;
            ptls_aead_context_t *aead[2]; /* 0-RTT uses aead[1], 1-RTT uses aead[key_phase] */
            uint8_t secret[PTLS_MAX_DIGEST_SIZE];
            struct {
                uint64_t prepared;
                uint64_t decrypted;
            } key_phase;
        } ingress;
        struct {
            struct st_quicly_cipher_context_t key;
            uint8_t secret[PTLS_MAX_DIGEST_SIZE];
            uint64_t key_phase;
            struct {
                /**
                 * PN at which key update was initiated. Set to UINT64_MAX once key update is acked.
                 */
                uint64_t last;
                /**
                 * PN at which key update should be initiated. Set to UINT64_MAX when key update cannot be initiated.
                 */
                uint64_t next;
            } key_update_pn;
        } egress;
    } cipher;
    int one_rtt_writable;
};

struct st_quicly_conn_t {
    struct _st_quicly_conn_public_t super;
    /**
     * the initial context
     */
    struct st_quicly_handshake_space_t *initial;
    /**
     * the handshake context
     */
    struct st_quicly_handshake_space_t *handshake;
    /**
     * 0-RTT and 1-RTT context
     */
    struct st_quicly_application_space_t *application;
    /**
     * hashtable of streams
     */
    khash_t(quicly_stream_t) * streams;
    /**
     *
     */
    struct {
        /**
         *
         */
        struct {
            uint64_t bytes_consumed;
            quicly_maxsender_t sender;
        } max_data;
        /**
         *
         */
        struct {
            quicly_maxsender_t uni, bidi;
        } max_streams;
        /**
         *
         */
        struct {
            uint64_t next_sequence;
        } ack_frequency;
    } ingress;
    /**
     *
     */
    struct {
        /**
         * loss recovery
         */
        quicly_loss_t loss;
        /**
         * next or the currently encoding packet number
         */
        uint64_t packet_number;
        /**
         * next PN to be skipped
         */
        uint64_t next_pn_to_skip;
        /**
         *
         */
        uint16_t max_udp_payload_size;
        /**
         * valid if state is CLOSING
         */
        struct {
            uint16_t error_code;
            uint64_t frame_type; /* UINT64_MAX if application close */
            const char *reason_phrase;
            unsigned long num_packets_received;
        } connection_close;
        /**
         *
         */
        struct {
            uint64_t permitted;
            uint64_t sent;
        } max_data;
        /**
         *
         */
        struct {
            struct st_quicly_max_streams_t {
                uint64_t count;
                quicly_maxsender_t blocked_sender;
            } uni, bidi;
        } max_streams;
        /**
         *
         */
        struct {
            struct st_quicly_pending_path_challenge_t *head, **tail_ref;
        } path_challenge;
        /**
         *
         */
        struct {
            uint64_t generation;
            uint64_t max_acked;
            uint32_t num_inflight;
        } new_token;
        /**
         *
         */
        struct {
            int64_t update_at;
            uint64_t sequence;
        } ack_frequency;
        /**
         *
         */
        int64_t last_retransmittable_sent_at;
        /**
         * when to send an ACK, or other frames used for managing the connection
         */
        int64_t send_ack_at;
        /**
         * congestion control
         */
        quicly_cc_t cc;
        /**
         * things to be sent at the stream-level, that are not governed by the stream scheduler
         */
        struct {
            /**
             * list of blocked streams (sorted in ascending order of stream_ids)
             */
            struct {
                quicly_linklist_t uni;
                quicly_linklist_t bidi;
            } blocked;
            /**
             * list of streams with pending control data (e.g., RESET_STREAM)
             */
            quicly_linklist_t control;
        } pending_streams;
        /**
         * send state for DATA_BLOCKED frame that corresponds to the current value of `conn->egress.max_data.permitted`
         */
        quicly_sender_state_t data_blocked;
        /**
         * bit vector indicating if there's any pending crypto data (the insignificant 4 bits), or other non-stream data
         */
        uint8_t pending_flows;
#define QUICLY_PENDING_FLOW_NEW_TOKEN_BIT (1 << 5)
#define QUICLY_PENDING_FLOW_HANDSHAKE_DONE_BIT (1 << 6)
/**
 * is there a pending NEW_CONNECTION_ID or RETIRE_CONNECTION_ID frame?
 *
 * This single bit represents two frame types, to keep `pending_flows` within 8 bits, and to reduce `if` branch in `do_send`
 * function. If we had two separate bits, we would have to check each bit separately in `do_send` function. Given NEW_CONNECTION_ID
 * and RETIRE_CONNECTION_ID frames are expected to be rarely sent, folding two types into a single bit makes sense.
 */
#define QUICLY_PENDING_FLOW_CID_FRAME_BIT (1 << 7)
        /**
         * pending RETIRE_CONNECTION_ID frames to be sent
         */
        quicly_retire_cid_set_t retire_cid;
        /**
         * DATAGRAM frame payload to be sent
         */
        ptls_iovec_t datagram_frame_payload;
    } egress;
    /**
     * crypto data
     */
    struct {
        ptls_t *tls;
        ptls_handshake_properties_t handshake_properties;
        struct {
            ptls_raw_extension_t ext[2];
            ptls_buffer_t buf;
        } transport_params;
    } crypto;
    /**
     * token (if the token is a Retry token can be determined by consulting the length of retry_scid)
     */
    ptls_iovec_t token;
    /**
     * len=UINT8_MAX if Retry was not used, use client_received_retry() to check
     */
    quicly_cid_t retry_scid;
    /**
     *
     */
    struct {
        /**
         * The moment when the idle timeout fires (including the additional 3 PTO). The value is set to INT64_MAX while the
         * handshake is in progress.
         */
        int64_t at;
        /**
         * idle timeout
         */
        uint8_t should_rearm_on_send : 1;
    } idle_timeout;
    /**
     * structure to hold various data used internally
     */
    struct {
        /**
         * This value holds current time that remains constant while quicly functions that deal with time are running. Only
         * available when the lock is held using `lock_now`.
         */
        int64_t now;
        /**
         *
         */
        uint8_t lock_count;
        struct {
            /**
             * This cache is used to concatenate acked ranges of streams before processing them, reducing the frequency of function
             * calls to `quicly_sendstate_t` and to the application-level send window management callbacks. This approach works,
             * because in most cases acks will contain contiguous ranges of a single stream.
             */
            struct {
                /**
                 * set to INT64_MIN when the cache is invalid
                 */
                quicly_stream_id_t stream_id;
                quicly_sendstate_sent_t args;
            } active_acked_cache;
        } on_ack_stream;
    } stash;
};

struct st_quicly_handle_payload_state_t {
    const uint8_t *src, *const end;
    size_t epoch;
    uint64_t frame_type;
};

struct st_ptls_salt_t {
    uint8_t initial[20];
    struct {
        uint8_t key[PTLS_AES128_KEY_SIZE];
        uint8_t iv[PTLS_AESGCM_IV_SIZE];
    } retry;
};

static void crypto_stream_receive(quicly_stream_t *stream, size_t off, const void *src, size_t len);

static const quicly_stream_callbacks_t crypto_stream_callbacks = {quicly_streambuf_destroy, quicly_streambuf_egress_shift,
                                                                  quicly_streambuf_egress_emit, NULL, crypto_stream_receive};

static int update_traffic_key_cb(ptls_update_traffic_key_t *self, ptls_t *tls, int is_enc, size_t epoch, const void *secret);
static int initiate_close(quicly_conn_t *conn, int err, uint64_t frame_type, const char *reason_phrase);
static int handle_close(quicly_conn_t *conn, int err, uint64_t frame_type, ptls_iovec_t reason_phrase);
static int discard_sentmap_by_epoch(quicly_conn_t *conn, unsigned ack_epochs);

static const quicly_transport_parameters_t default_transport_params = {.max_udp_payload_size = QUICLY_DEFAULT_MAX_UDP_PAYLOAD_SIZE,
                                                                       .ack_delay_exponent = QUICLY_DEFAULT_ACK_DELAY_EXPONENT,
                                                                       .max_ack_delay = QUICLY_DEFAULT_MAX_ACK_DELAY,
                                                                       .min_ack_delay_usec = UINT64_MAX,
                                                                       .active_connection_id_limit =
                                                                           QUICLY_DEFAULT_ACTIVE_CONNECTION_ID_LIMIT};

static const struct st_ptls_salt_t *get_salt(uint32_t protocol_version)
{
    static const struct st_ptls_salt_t current = {.initial = {0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97,
                                                              0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0, 0x43, 0x90, 0xa8, 0x99},
                                                  .retry = {.key = {0xcc, 0xce, 0x18, 0x7e, 0xd0, 0x9a, 0x09, 0xd0, 0x57, 0x28,
                                                                    0x15, 0x5a, 0x6c, 0xb9, 0x6b, 0xe1},
                                                            .iv = {0xe5, 0x49, 0x30, 0xf9, 0x7f, 0x21, 0x36, 0xf0, 0x53, 0x0a, 0x8c,
                                                                   0x1c}}},
                                       draft27 = {.initial = {0xc3, 0xee, 0xf7, 0x12, 0xc7, 0x2e, 0xbb, 0x5a, 0x11, 0xa7,
                                                              0xd2, 0x43, 0x2b, 0xb4, 0x63, 0x65, 0xbe, 0xf9, 0xf5, 0x02},
                                                  .retry = {.key = {0x4d, 0x32, 0xec, 0xdb, 0x2a, 0x21, 0x33, 0xc8, 0x41, 0xe4,
                                                                    0x04, 0x3d, 0xf2, 0x7d, 0x44, 0x30},
                                                            .iv = {0x4d, 0x16, 0x11, 0xd0, 0x55, 0x13, 0xa5, 0x52, 0xc5, 0x87, 0xd5,
                                                                   0x75}}};

    switch (protocol_version) {
    case QUICLY_PROTOCOL_VERSION_CURRENT:
        return &current;
    case QUICLY_PROTOCOL_VERSION_DRAFT27:
        return &draft27;
        break;
    default:
        return NULL;
    }
}

static void lock_now(quicly_conn_t *conn, int is_reentrant)
{
    if (conn->stash.now == 0) {
        assert(conn->stash.lock_count == 0);
        conn->stash.now = conn->super.ctx->now->cb(conn->super.ctx->now);
    } else {
        assert(is_reentrant && "caller must be reentrant");
        assert(conn->stash.lock_count != 0);
    }

    ++conn->stash.lock_count;
}

static void unlock_now(quicly_conn_t *conn)
{
    assert(conn->stash.now != 0);

    if (--conn->stash.lock_count == 0)
        conn->stash.now = 0;
}

static void set_address(quicly_address_t *addr, struct sockaddr *sa)
{
    if (sa == NULL) {
        addr->sa.sa_family = AF_UNSPEC;
        return;
    }

    switch (sa->sa_family) {
    case AF_UNSPEC:
        addr->sa.sa_family = AF_UNSPEC;
        break;
    case AF_INET:
        addr->sin = *(struct sockaddr_in *)sa;
        break;
    case AF_INET6:
        addr->sin6 = *(struct sockaddr_in6 *)sa;
        break;
    default:
        memset(addr, 0xff, sizeof(*addr));
        assert(!"unexpected address type");
        break;
    }
}

static ptls_cipher_suite_t *get_aes128gcmsha256(quicly_context_t *ctx)
{
    ptls_cipher_suite_t **cs;

    for (cs = ctx->tls->cipher_suites;; ++cs) {
        assert(cs != NULL);
        if ((*cs)->id == PTLS_CIPHER_SUITE_AES_128_GCM_SHA256)
            break;
    }
    return *cs;
}

static inline uint8_t get_epoch(uint8_t first_byte)
{
    if (!QUICLY_PACKET_IS_LONG_HEADER(first_byte))
        return QUICLY_EPOCH_1RTT;

    switch (first_byte & QUICLY_PACKET_TYPE_BITMASK) {
    case QUICLY_PACKET_TYPE_INITIAL:
        return QUICLY_EPOCH_INITIAL;
    case QUICLY_PACKET_TYPE_HANDSHAKE:
        return QUICLY_EPOCH_HANDSHAKE;
    case QUICLY_PACKET_TYPE_0RTT:
        return QUICLY_EPOCH_0RTT;
    default:
        assert(!"FIXME");
    }
}

static ptls_aead_context_t *create_retry_aead(quicly_context_t *ctx, uint32_t protocol_version, int is_enc)
{
    const struct st_ptls_salt_t *salt = get_salt(protocol_version);
    assert(salt != NULL);

    ptls_cipher_suite_t *algo = get_aes128gcmsha256(ctx);
    ptls_aead_context_t *aead = ptls_aead_new_direct(algo->aead, is_enc, salt->retry.key, salt->retry.iv);
    assert(aead != NULL);
    return aead;
}

static void dispose_cipher(struct st_quicly_cipher_context_t *ctx)
{
    ptls_aead_free(ctx->aead);
    ptls_cipher_free(ctx->header_protection);
}

static int is_retry(quicly_conn_t *conn)
{
    return conn->retry_scid.len != UINT8_MAX;
}

static int needs_cid_auth(quicly_conn_t *conn)
{
    return conn->super.version > QUICLY_PROTOCOL_VERSION_DRAFT27;
}

static int recognize_delayed_ack(quicly_conn_t *conn)
{
    return conn->super.ctx->transport_params.min_ack_delay_usec != UINT64_MAX;
}

static int64_t get_sentmap_expiration_time(quicly_conn_t *conn)
{
    return quicly_loss_get_sentmap_expiration_time(&conn->egress.loss, conn->super.remote.transport_params.max_ack_delay);
}

static void ack_frequency_set_next_update_at(quicly_conn_t *conn)
{
    if (conn->super.remote.transport_params.min_ack_delay_usec != UINT64_MAX)
        conn->egress.ack_frequency.update_at = conn->stash.now + get_sentmap_expiration_time(conn);
}

size_t quicly_decode_packet(quicly_context_t *ctx, quicly_decoded_packet_t *packet, const uint8_t *datagram, size_t datagram_size,
                            size_t *off)
{
    const uint8_t *src = datagram, *src_end = datagram + datagram_size;

    assert(*off <= datagram_size);

    packet->octets = ptls_iovec_init(src + *off, datagram_size - *off);
    if (packet->octets.len < 2)
        goto Error;
    packet->datagram_size = *off == 0 ? datagram_size : 0;
    packet->token = ptls_iovec_init(NULL, 0);
    packet->decrypted.pn = UINT64_MAX;

    /* move the cursor to the second byte */
    src += *off + 1;

    if (QUICLY_PACKET_IS_LONG_HEADER(packet->octets.base[0])) {
        /* long header */
        uint64_t rest_length;
        if (src_end - src < 5)
            goto Error;
        packet->version = quicly_decode32(&src);
        packet->cid.dest.encrypted.len = *src++;
        if (src_end - src < packet->cid.dest.encrypted.len + 1)
            goto Error;
        packet->cid.dest.encrypted.base = (uint8_t *)src;
        src += packet->cid.dest.encrypted.len;
        packet->cid.src.len = *src++;
        if (src_end - src < packet->cid.src.len)
            goto Error;
        packet->cid.src.base = (uint8_t *)src;
        src += packet->cid.src.len;
        if (ctx->cid_encryptor != NULL) {
            ctx->cid_encryptor->decrypt_cid(ctx->cid_encryptor, &packet->cid.dest.plaintext, packet->cid.dest.encrypted.base,
                                            packet->cid.dest.encrypted.len);
        } else {
            packet->cid.dest.plaintext = (quicly_cid_plaintext_t){0};
        }
        switch (packet->octets.base[0] & QUICLY_PACKET_TYPE_BITMASK) {
        case QUICLY_PACKET_TYPE_INITIAL:
        case QUICLY_PACKET_TYPE_0RTT:
            packet->cid.dest.might_be_client_generated = 1;
            break;
        default:
            packet->cid.dest.might_be_client_generated = 0;
            break;
        }
        switch (packet->version) {
        case QUICLY_PROTOCOL_VERSION_CURRENT:
        case QUICLY_PROTOCOL_VERSION_DRAFT27:
            /* these are the recognized versions, and they share the same packet header format */
            if ((packet->octets.base[0] & QUICLY_PACKET_TYPE_BITMASK) == QUICLY_PACKET_TYPE_RETRY) {
                /* retry */
                if (src_end - src <= PTLS_AESGCM_TAG_SIZE)
                    goto Error;
                packet->token = ptls_iovec_init(src, src_end - src - PTLS_AESGCM_TAG_SIZE);
                src += packet->token.len;
                packet->encrypted_off = src - packet->octets.base;
            } else {
                /* coalescible long header packet */
                if ((packet->octets.base[0] & QUICLY_PACKET_TYPE_BITMASK) == QUICLY_PACKET_TYPE_INITIAL) {
                    /* initial has a token */
                    uint64_t token_len;
                    if ((token_len = quicly_decodev(&src, src_end)) == UINT64_MAX)
                        goto Error;
                    if (src_end - src < token_len)
                        goto Error;
                    packet->token = ptls_iovec_init(src, token_len);
                    src += token_len;
                }
                if ((rest_length = quicly_decodev(&src, src_end)) == UINT64_MAX)
                    goto Error;
                if (rest_length < 1)
                    goto Error;
                if (src_end - src < rest_length)
                    goto Error;
                packet->encrypted_off = src - packet->octets.base;
                packet->octets.len = packet->encrypted_off + rest_length;
            }
            break;
        default:
            /* VN packet or packets of unknown version cannot be parsed. `encrypted_off` is set to the first byte after SCID. */
            packet->encrypted_off = src - packet->octets.base;
        }
        packet->_is_stateless_reset_cached = QUICLY__DECODED_PACKET_CACHED_NOT_STATELESS_RESET;
    } else {
        /* short header */
        if (ctx->cid_encryptor != NULL) {
            if (src_end - src < QUICLY_MAX_CID_LEN_V1)
                goto Error;
            size_t local_cidl = ctx->cid_encryptor->decrypt_cid(ctx->cid_encryptor, &packet->cid.dest.plaintext, src, 0);
            if (local_cidl == SIZE_MAX)
                goto Error;
            packet->cid.dest.encrypted = ptls_iovec_init(src, local_cidl);
            src += local_cidl;
        } else {
            packet->cid.dest.encrypted = ptls_iovec_init(NULL, 0);
            packet->cid.dest.plaintext = (quicly_cid_plaintext_t){0};
        }
        packet->cid.dest.might_be_client_generated = 0;
        packet->cid.src = ptls_iovec_init(NULL, 0);
        packet->version = 0;
        packet->encrypted_off = src - packet->octets.base;
        packet->_is_stateless_reset_cached = QUICLY__DECODED_PACKET_CACHED_MAYBE_STATELESS_RESET;
    }

    *off += packet->octets.len;
    return packet->octets.len;

Error:
    return SIZE_MAX;
}

uint64_t quicly_determine_packet_number(uint32_t truncated, size_t num_bits, uint64_t expected)
{
    uint64_t win = (uint64_t)1 << num_bits, candidate = (expected & ~(win - 1)) | truncated;

    if (candidate + win / 2 <= expected)
        return candidate + win;
    if (candidate > expected + win / 2 && candidate >= win)
        return candidate - win;
    return candidate;
}

static void assert_consistency(quicly_conn_t *conn, int timer_must_be_in_future)
{
    if (conn->super.state >= QUICLY_STATE_CLOSING) {
        assert(!timer_must_be_in_future || conn->stash.now < conn->egress.send_ack_at);
        return;
    }

    if (conn->egress.loss.sentmap.bytes_in_flight != 0 || conn->super.remote.address_validation.send_probe) {
        assert(conn->egress.loss.alarm_at != INT64_MAX);
    } else {
        assert(conn->egress.loss.loss_time == INT64_MAX);
    }
    /* Allow timers not in the future when the remote peer is not yet validated, since we may not be able to send packets even when
     * timers fire. */
    if (timer_must_be_in_future && conn->super.remote.address_validation.validated)
        assert(conn->stash.now < conn->egress.loss.alarm_at);
}

static int on_invalid_ack(quicly_sentmap_t *map, const quicly_sent_packet_t *packet, int acked, quicly_sent_t *sent)
{
    if (acked)
        return QUICLY_TRANSPORT_ERROR_PROTOCOL_VIOLATION;
    return 0;
}

static uint64_t calc_next_pn_to_skip(ptls_context_t *tlsctx, uint64_t next_pn, uint32_t cwnd, uint64_t mtu)
{
    static __thread struct {
        uint32_t values[8];
        size_t off;
    } cached_rand;

    if (cached_rand.off == 0) {
        tlsctx->random_bytes(cached_rand.values, sizeof(cached_rand.values));
        cached_rand.off = PTLS_ELEMENTSOF(cached_rand.values);
    }

    /* on average, skip one PN per every min(256 packets, 8 * CWND) */
    uint32_t packet_cwnd = cwnd / mtu;
    if (packet_cwnd < 32)
        packet_cwnd = 32;
    uint64_t skip_after = cached_rand.values[--cached_rand.off] % (16 * packet_cwnd);
    return next_pn + 1 + skip_after;
}

static void init_max_streams(struct st_quicly_max_streams_t *m)
{
    m->count = 0;
    quicly_maxsender_init(&m->blocked_sender, -1);
}

static int update_max_streams(struct st_quicly_max_streams_t *m, uint64_t count)
{
    if (count > (uint64_t)1 << 60)
        return QUICLY_TRANSPORT_ERROR_STREAM_LIMIT;

    if (m->count < count) {
        m->count = count;
        if (m->blocked_sender.max_acked < count)
            m->blocked_sender.max_acked = count;
    }

    return 0;
}

int quicly_connection_is_ready(quicly_conn_t *conn)
{
    return conn->application != NULL;
}

static int stream_is_destroyable(quicly_stream_t *stream)
{
    if (!quicly_recvstate_transfer_complete(&stream->recvstate))
        return 0;
    if (!quicly_sendstate_transfer_complete(&stream->sendstate))
        return 0;
    switch (stream->_send_aux.reset_stream.sender_state) {
    case QUICLY_SENDER_STATE_NONE:
    case QUICLY_SENDER_STATE_ACKED:
        break;
    default:
        return 0;
    }
    return 1;
}

static void sched_stream_control(quicly_stream_t *stream)
{
    assert(stream->stream_id >= 0);

    if (!quicly_linklist_is_linked(&stream->_send_aux.pending_link.control))
        quicly_linklist_insert(stream->conn->egress.pending_streams.control.prev, &stream->_send_aux.pending_link.control);
}

static void resched_stream_data(quicly_stream_t *stream)
{
    if (stream->stream_id < 0) {
        assert(-4 <= stream->stream_id);
        uint8_t mask = 1 << -(1 + stream->stream_id);
        if (stream->sendstate.pending.num_ranges != 0) {
            stream->conn->egress.pending_flows |= mask;
        } else {
            stream->conn->egress.pending_flows &= ~mask;
        }
        return;
    }

    /* do nothing if blocked */
    if (stream->streams_blocked)
        return;

    quicly_stream_scheduler_t *scheduler = stream->conn->super.ctx->stream_scheduler;
    scheduler->update_state(scheduler, stream);
}

static int should_send_max_data(quicly_conn_t *conn)
{
    return quicly_maxsender_should_send_max(&conn->ingress.max_data.sender, conn->ingress.max_data.bytes_consumed,
                                            (uint32_t)conn->super.ctx->transport_params.max_data, 512);
}

static int should_send_max_stream_data(quicly_stream_t *stream)
{
    if (stream->recvstate.eos != UINT64_MAX)
        return 0;
    return quicly_maxsender_should_send_max(&stream->_send_aux.max_stream_data_sender, stream->recvstate.data_off,
                                            stream->_recv_aux.window, 512);
}

int quicly_stream_sync_sendbuf(quicly_stream_t *stream, int activate)
{
    int ret;

    if (activate) {
        if ((ret = quicly_sendstate_activate(&stream->sendstate)) != 0)
            return ret;
    }

    resched_stream_data(stream);
    return 0;
}

void quicly_stream_sync_recvbuf(quicly_stream_t *stream, size_t shift_amount)
{
    stream->recvstate.data_off += shift_amount;
    if (stream->stream_id >= 0) {
        if (should_send_max_stream_data(stream))
            sched_stream_control(stream);
    }
}

static int schedule_path_challenge_frame(quicly_conn_t *conn, int is_response, const uint8_t *data)
{
    struct st_quicly_pending_path_challenge_t *pending;

    if ((pending = malloc(sizeof(struct st_quicly_pending_path_challenge_t))) == NULL)
        return PTLS_ERROR_NO_MEMORY;

    pending->next = NULL;
    pending->is_response = is_response;
    memcpy(pending->data, data, QUICLY_PATH_CHALLENGE_DATA_LEN);

    *conn->egress.path_challenge.tail_ref = pending;
    conn->egress.path_challenge.tail_ref = &pending->next;
    return 0;
}

/**
 * calculate how many CIDs we provide to the remote peer
 */
static size_t local_cid_size(const quicly_conn_t *conn)
{
    PTLS_BUILD_ASSERT(QUICLY_LOCAL_ACTIVE_CONNECTION_ID_LIMIT < SIZE_MAX / sizeof(uint64_t));

    /* if we don't have an encryptor, the only CID we issue is the one we send during handshake */
    if (conn->super.ctx->cid_encryptor == NULL)
        return 1;

    uint64_t capacity = conn->super.remote.transport_params.active_connection_id_limit;
    if (capacity > QUICLY_LOCAL_ACTIVE_CONNECTION_ID_LIMIT)
        capacity = QUICLY_LOCAL_ACTIVE_CONNECTION_ID_LIMIT;
    return capacity;
}

/**
 * set up an internal record to send RETIRE_CONNECTION_ID frame later
 */
static void schedule_retire_connection_id_frame(quicly_conn_t *conn, uint64_t sequence)
{
    quicly_retire_cid_push(&conn->egress.retire_cid, sequence);
    conn->egress.pending_flows |= QUICLY_PENDING_FLOW_CID_FRAME_BIT;
}

static int write_crypto_data(quicly_conn_t *conn, ptls_buffer_t *tlsbuf, size_t epoch_offsets[5])
{
    size_t epoch;
    int ret;

    if (tlsbuf->off == 0)
        return 0;

    for (epoch = 0; epoch < 4; ++epoch) {
        size_t len = epoch_offsets[epoch + 1] - epoch_offsets[epoch];
        if (len == 0)
            continue;
        quicly_stream_t *stream = quicly_get_stream(conn, -(quicly_stream_id_t)(1 + epoch));
        assert(stream != NULL);
        if ((ret = quicly_streambuf_egress_write(stream, tlsbuf->base + epoch_offsets[epoch], len)) != 0)
            return ret;
    }

    return 0;
}

void crypto_stream_receive(quicly_stream_t *stream, size_t off, const void *src, size_t len)
{
    quicly_conn_t *conn = stream->conn;
    size_t in_epoch = -(1 + stream->stream_id), epoch_offsets[5] = {0};
    ptls_iovec_t input;
    ptls_buffer_t output;

    if (quicly_streambuf_ingress_receive(stream, off, src, len) != 0)
        return;

    ptls_buffer_init(&output, "", 0);

    /* send handshake messages to picotls, and let it fill in the response */
    while ((input = quicly_streambuf_ingress_get(stream)).len != 0) {
        int handshake_result = ptls_handle_message(conn->crypto.tls, &output, epoch_offsets, in_epoch, input.base, input.len,
                                                   &conn->crypto.handshake_properties);
        quicly_streambuf_ingress_shift(stream, input.len);
        QUICLY_PROBE(CRYPTO_HANDSHAKE, conn, conn->stash.now, handshake_result);
        switch (handshake_result) {
        case 0:
        case PTLS_ERROR_IN_PROGRESS:
            break;
        default:
            initiate_close(conn,
                           PTLS_ERROR_GET_CLASS(handshake_result) == PTLS_ERROR_CLASS_SELF_ALERT ? handshake_result
                                                                                                 : QUICLY_TRANSPORT_ERROR_INTERNAL,
                           QUICLY_FRAME_TYPE_CRYPTO, NULL);
            goto Exit;
        }
        /* drop 0-RTT write key if 0-RTT is rejected by remote peer */
        if (conn->application != NULL && !conn->application->one_rtt_writable &&
            conn->application->cipher.egress.key.aead != NULL) {
            assert(quicly_is_client(conn));
            if (conn->crypto.handshake_properties.client.early_data_acceptance == PTLS_EARLY_DATA_REJECTED) {
                dispose_cipher(&conn->application->cipher.egress.key);
                conn->application->cipher.egress.key = (struct st_quicly_cipher_context_t){NULL};
                discard_sentmap_by_epoch(
                    conn, 1u << QUICLY_EPOCH_1RTT); /* retire all packets with ack_epoch == 3; they are all 0-RTT packets */
            }
        }
    }
    write_crypto_data(conn, &output, epoch_offsets);

Exit:
    ptls_buffer_dispose(&output);
}

static void init_stream_properties(quicly_stream_t *stream, uint32_t initial_max_stream_data_local,
                                   uint64_t initial_max_stream_data_remote)
{
    int is_client = quicly_is_client(stream->conn);

    if (quicly_stream_has_send_side(is_client, stream->stream_id)) {
        quicly_sendstate_init(&stream->sendstate);
    } else {
        quicly_sendstate_init_closed(&stream->sendstate);
    }
    if (quicly_stream_has_receive_side(is_client, stream->stream_id)) {
        quicly_recvstate_init(&stream->recvstate);
    } else {
        quicly_recvstate_init_closed(&stream->recvstate);
    }
    stream->streams_blocked = 0;

    stream->_send_aux.max_stream_data = initial_max_stream_data_remote;
    stream->_send_aux.stop_sending.sender_state = QUICLY_SENDER_STATE_NONE;
    stream->_send_aux.stop_sending.error_code = 0;
    stream->_send_aux.reset_stream.sender_state = QUICLY_SENDER_STATE_NONE;
    stream->_send_aux.reset_stream.error_code = 0;
    quicly_maxsender_init(&stream->_send_aux.max_stream_data_sender, initial_max_stream_data_local);
    stream->_send_aux.blocked = QUICLY_SENDER_STATE_NONE;
    quicly_linklist_init(&stream->_send_aux.pending_link.control);
    quicly_linklist_init(&stream->_send_aux.pending_link.default_scheduler);

    stream->_recv_aux.window = initial_max_stream_data_local;

    /* Set the number of max ranges to be capable of handling following case:
     * * every one of the two packets being sent are lost
     * * average size of a STREAM frame found in a packet is >= ~512 bytes
     * See also: the doc-comment on `_recv_aux.max_ranges`.
     */
    if ((stream->_recv_aux.max_ranges = initial_max_stream_data_local / 1024) < 63)
        stream->_recv_aux.max_ranges = 63;
}

static void dispose_stream_properties(quicly_stream_t *stream)
{
    quicly_sendstate_dispose(&stream->sendstate);
    quicly_recvstate_dispose(&stream->recvstate);
    quicly_maxsender_dispose(&stream->_send_aux.max_stream_data_sender);
    quicly_linklist_unlink(&stream->_send_aux.pending_link.control);
    quicly_linklist_unlink(&stream->_send_aux.pending_link.default_scheduler);
}

static quicly_stream_t *open_stream(quicly_conn_t *conn, uint64_t stream_id, uint32_t initial_max_stream_data_local,
                                    uint64_t initial_max_stream_data_remote)
{
    quicly_stream_t *stream;

    if ((stream = malloc(sizeof(*stream))) == NULL)
        return NULL;
    stream->conn = conn;
    stream->stream_id = stream_id;
    stream->callbacks = NULL;
    stream->data = NULL;

    int r;
    khiter_t iter = kh_put(quicly_stream_t, conn->streams, stream_id, &r);
    assert(iter != kh_end(conn->streams));
    kh_val(conn->streams, iter) = stream;

    init_stream_properties(stream, initial_max_stream_data_local, initial_max_stream_data_remote);

    return stream;
}

static struct st_quicly_conn_streamgroup_state_t *get_streamgroup_state(quicly_conn_t *conn, quicly_stream_id_t stream_id)
{
    if (quicly_is_client(conn) == quicly_stream_is_client_initiated(stream_id)) {
        return quicly_stream_is_unidirectional(stream_id) ? &conn->super.local.uni : &conn->super.local.bidi;
    } else {
        return quicly_stream_is_unidirectional(stream_id) ? &conn->super.remote.uni : &conn->super.remote.bidi;
    }
}

static int should_send_max_streams(quicly_conn_t *conn, int uni)
{
    uint64_t concurrency;
    quicly_maxsender_t *maxsender;
    struct st_quicly_conn_streamgroup_state_t *group;

#define INIT_VARS(type)                                                                                                            \
    do {                                                                                                                           \
        concurrency = conn->super.ctx->transport_params.max_streams_##type;                                                        \
        maxsender = &conn->ingress.max_streams.type;                                                                               \
        group = &conn->super.remote.type;                                                                                          \
    } while (0)
    if (uni) {
        INIT_VARS(uni);
    } else {
        INIT_VARS(bidi);
    }
#undef INIT_VARS

    if (concurrency == 0)
        return 0;

    if (!quicly_maxsender_should_send_max(maxsender, group->next_stream_id / 4, group->num_streams, 768))
        return 0;

    return 1;
}

static void destroy_stream(quicly_stream_t *stream, int err)
{
    quicly_conn_t *conn = stream->conn;

    QUICLY_PROBE(STREAM_ON_DESTROY, conn, conn->stash.now, stream, err);

    if (stream->callbacks != NULL)
        stream->callbacks->on_destroy(stream, err);

    khiter_t iter = kh_get(quicly_stream_t, conn->streams, stream->stream_id);
    assert(iter != kh_end(conn->streams));
    kh_del(quicly_stream_t, conn->streams, iter);

    if (stream->stream_id < 0) {
        size_t epoch = -(1 + stream->stream_id);
        stream->conn->egress.pending_flows &= ~(uint8_t)(1 << epoch);
    } else {
        struct st_quicly_conn_streamgroup_state_t *group = get_streamgroup_state(conn, stream->stream_id);
        --group->num_streams;
    }

    dispose_stream_properties(stream);

    if (conn->application != NULL) {
        /* The function is normally invoked when receiving a packet, therefore just setting send_ack_at to zero is sufficient to
         * trigger the emission of the MAX_STREAMS frame. FWIW, the only case the function is invoked when not receiving a packet is
         * when the connection is being closed. In such case, the change will not have any bad side effects.
         */
        if (should_send_max_streams(conn, quicly_stream_is_unidirectional(stream->stream_id)))
            conn->egress.send_ack_at = 0;
    }

    free(stream);
}

static void destroy_all_streams(quicly_conn_t *conn, int err, int including_crypto_streams)
{
    quicly_stream_t *stream;
    kh_foreach_value(conn->streams, stream, {
        /* TODO do we need to send reset signals to open streams? */
        if (including_crypto_streams || stream->stream_id >= 0)
            destroy_stream(stream, err);
    });
    assert(quicly_num_streams(conn) == 0);
}

int quicly_foreach_stream(quicly_conn_t *conn, void *thunk, int (*cb)(void *thunk, quicly_stream_t *stream))
{
    quicly_stream_t *stream;
    kh_foreach_value(conn->streams, stream, {
        if (stream->stream_id >= 0) {
            int ret = cb(thunk, stream);
            if (ret != 0)
                return ret;
        }
    });
    return 0;
}

quicly_stream_t *quicly_get_stream(quicly_conn_t *conn, quicly_stream_id_t stream_id)
{
    khiter_t iter = kh_get(quicly_stream_t, conn->streams, stream_id);
    if (iter != kh_end(conn->streams))
        return kh_val(conn->streams, iter);
    return NULL;
}

ptls_t *quicly_get_tls(quicly_conn_t *conn)
{
    return conn->crypto.tls;
}

int quicly_get_stats(quicly_conn_t *conn, quicly_stats_t *stats)
{
    /* copy the pre-built stats fields */
    memcpy(stats, &conn->super.stats, sizeof(conn->super.stats));

    /* set or generate the non-pre-built stats fields here */
    stats->rtt = conn->egress.loss.rtt;
    stats->cc = conn->egress.cc;
    return 0;
}

quicly_stream_id_t quicly_get_ingress_max_streams(quicly_conn_t *conn, int uni)
{
    quicly_maxsender_t *maxsender = uni ? &conn->ingress.max_streams.uni : &conn->ingress.max_streams.bidi;
    return maxsender->max_committed;
}

void quicly_get_max_data(quicly_conn_t *conn, uint64_t *send_permitted, uint64_t *sent, uint64_t *consumed)
{
    if (send_permitted != NULL)
        *send_permitted = conn->egress.max_data.permitted;
    if (sent != NULL)
        *sent = conn->egress.max_data.sent;
    if (consumed != NULL)
        *consumed = conn->ingress.max_data.bytes_consumed;
}

static void update_idle_timeout(quicly_conn_t *conn, int is_in_receive)
{
    if (!is_in_receive && !conn->idle_timeout.should_rearm_on_send)
        return;

    /* calculate the minimum of the two max_idle_timeout */
    int64_t idle_msec = INT64_MAX;
    if (conn->initial == NULL && conn->handshake == NULL && conn->super.remote.transport_params.max_idle_timeout != 0)
        idle_msec = conn->super.remote.transport_params.max_idle_timeout;
    if (conn->super.ctx->transport_params.max_idle_timeout != 0 && conn->super.ctx->transport_params.max_idle_timeout < idle_msec)
        idle_msec = conn->super.ctx->transport_params.max_idle_timeout;

    if (idle_msec == INT64_MAX)
        return;

    uint32_t three_pto = 3 * quicly_rtt_get_pto(&conn->egress.loss.rtt, conn->super.ctx->transport_params.max_ack_delay,
                                                conn->egress.loss.conf->min_pto);
    conn->idle_timeout.at = conn->stash.now + (idle_msec > three_pto ? idle_msec : three_pto);
    conn->idle_timeout.should_rearm_on_send = is_in_receive;
}

static int scheduler_can_send(quicly_conn_t *conn)
{
    /* invoke the scheduler only when we are able to send stream data; skipping STATE_ACCEPTING is important as the application
     * would not have setup data pointer. */
    switch (conn->super.state) {
    case QUICLY_STATE_FIRSTFLIGHT:
    case QUICLY_STATE_CONNECTED:
        break;
    default:
        return 0;
    }

    /* scheduler would never have data to send, until application keys become available */
    if (conn->application == NULL)
        return 0;

    int conn_is_saturated = !(conn->egress.max_data.sent < conn->egress.max_data.permitted);
    return conn->super.ctx->stream_scheduler->can_send(conn->super.ctx->stream_scheduler, conn, conn_is_saturated);
}

static void update_loss_alarm(quicly_conn_t *conn, int is_after_send)
{
    int has_outstanding = conn->egress.loss.sentmap.bytes_in_flight != 0 || conn->super.remote.address_validation.send_probe,
        handshake_is_in_progress = conn->initial != NULL || conn->handshake != NULL;
    quicly_loss_update_alarm(&conn->egress.loss, conn->stash.now, conn->egress.last_retransmittable_sent_at, has_outstanding,
                             scheduler_can_send(conn), handshake_is_in_progress, conn->egress.max_data.sent, is_after_send);
}

static int create_handshake_flow(quicly_conn_t *conn, size_t epoch)
{
    quicly_stream_t *stream;
    int ret;

    if ((stream = open_stream(conn, -(quicly_stream_id_t)(1 + epoch), 65536, 65536)) == NULL)
        return PTLS_ERROR_NO_MEMORY;
    if ((ret = quicly_streambuf_create(stream, sizeof(quicly_streambuf_t))) != 0) {
        destroy_stream(stream, ret);
        return ret;
    }
    stream->callbacks = &crypto_stream_callbacks;

    return 0;
}

static void destroy_handshake_flow(quicly_conn_t *conn, size_t epoch)
{
    quicly_stream_t *stream = quicly_get_stream(conn, -(quicly_stream_id_t)(1 + epoch));
    if (stream != NULL)
        destroy_stream(stream, 0);
}

static struct st_quicly_pn_space_t *alloc_pn_space(size_t sz, uint32_t packet_tolerance)
{
    struct st_quicly_pn_space_t *space;

    if ((space = malloc(sz)) == NULL)
        return NULL;

    quicly_ranges_init(&space->ack_queue);
    space->largest_pn_received_at = INT64_MAX;
    space->next_expected_packet_number = 0;
    space->unacked_count = 0;
    space->packet_tolerance = packet_tolerance;
    space->ignore_order = 0;
    if (sz != sizeof(*space))
        memset((uint8_t *)space + sizeof(*space), 0, sz - sizeof(*space));

    return space;
}

static void do_free_pn_space(struct st_quicly_pn_space_t *space)
{
    quicly_ranges_clear(&space->ack_queue);
    free(space);
}

static int record_pn(quicly_ranges_t *ranges, uint64_t pn, int *is_out_of_order)
{
    int ret;

    *is_out_of_order = 0;

    if (ranges->num_ranges != 0) {
        /* fast path that is taken when we receive a packet in-order */
        if (ranges->ranges[ranges->num_ranges - 1].end == pn) {
            ranges->ranges[ranges->num_ranges - 1].end = pn + 1;
            return 0;
        }
        *is_out_of_order = 1;
    }

    /* slow path; we add, then remove the oldest ranges when the number of ranges exceed the maximum */
    if ((ret = quicly_ranges_add(ranges, pn, pn + 1)) != 0)
        return ret;
    if (ranges->num_ranges > QUICLY_MAX_ACK_BLOCKS)
        quicly_ranges_drop_by_range_indices(ranges, ranges->num_ranges - QUICLY_MAX_ACK_BLOCKS, ranges->num_ranges);

    return 0;
}

static int record_receipt(struct st_quicly_pn_space_t *space, uint64_t pn, int is_ack_only, int64_t now, int64_t *send_ack_at)
{
    int ret, ack_now, is_out_of_order;

    if ((ret = record_pn(&space->ack_queue, pn, &is_out_of_order)) != 0)
        goto Exit;

    ack_now = is_out_of_order && !space->ignore_order && !is_ack_only;

    /* update largest_pn_received_at (TODO implement deduplication at an earlier moment?) */
    if (space->ack_queue.ranges[space->ack_queue.num_ranges - 1].end == pn + 1)
        space->largest_pn_received_at = now;

    /* if the received packet is ack-eliciting, update / schedule transmission of ACK */
    if (!is_ack_only) {
        space->unacked_count++;
        if (space->unacked_count >= space->packet_tolerance)
            ack_now = 1;
    }

    if (ack_now) {
        *send_ack_at = now;
    } else if (*send_ack_at == INT64_MAX && space->unacked_count != 0) {
        *send_ack_at = now + QUICLY_DELAYED_ACK_TIMEOUT;
    }

    ret = 0;
Exit:
    return ret;
}

static void free_handshake_space(struct st_quicly_handshake_space_t **space)
{
    if (*space != NULL) {
        if ((*space)->cipher.ingress.aead != NULL)
            dispose_cipher(&(*space)->cipher.ingress);
        if ((*space)->cipher.egress.aead != NULL)
            dispose_cipher(&(*space)->cipher.egress);
        do_free_pn_space(&(*space)->super);
        *space = NULL;
    }
}

static int setup_cipher(quicly_conn_t *conn, size_t epoch, int is_enc, ptls_cipher_context_t **hp_ctx,
                        ptls_aead_context_t **aead_ctx, ptls_aead_algorithm_t *aead, ptls_hash_algorithm_t *hash,
                        const void *secret)
{
    /* quicly_accept builds cipher before instantitating a connection. In such case, we use the default crypto engine */
    quicly_crypto_engine_t *engine = conn != NULL ? conn->super.ctx->crypto_engine : &quicly_default_crypto_engine;

    return engine->setup_cipher(engine, conn, epoch, is_enc, hp_ctx, aead_ctx, aead, hash, secret);
}

static int setup_handshake_space_and_flow(quicly_conn_t *conn, size_t epoch)
{
    struct st_quicly_handshake_space_t **space = epoch == QUICLY_EPOCH_INITIAL ? &conn->initial : &conn->handshake;
    if ((*space = (void *)alloc_pn_space(sizeof(struct st_quicly_handshake_space_t), 1)) == NULL)
        return PTLS_ERROR_NO_MEMORY;
    return create_handshake_flow(conn, epoch);
}

static void free_application_space(struct st_quicly_application_space_t **space)
{
    if (*space != NULL) {
#define DISPOSE_INGRESS(label, func)                                                                                               \
    if ((*space)->cipher.ingress.label != NULL)                                                                                    \
    func((*space)->cipher.ingress.label)
        DISPOSE_INGRESS(header_protection.zero_rtt, ptls_cipher_free);
        DISPOSE_INGRESS(header_protection.one_rtt, ptls_cipher_free);
        DISPOSE_INGRESS(aead[0], ptls_aead_free);
        DISPOSE_INGRESS(aead[1], ptls_aead_free);
#undef DISPOSE_INGRESS
        if ((*space)->cipher.egress.key.aead != NULL)
            dispose_cipher(&(*space)->cipher.egress.key);
        ptls_clear_memory((*space)->cipher.egress.secret, sizeof((*space)->cipher.egress.secret));
        do_free_pn_space(&(*space)->super);
        *space = NULL;
    }
}

static int setup_application_space(quicly_conn_t *conn)
{
    if ((conn->application =
             (void *)alloc_pn_space(sizeof(struct st_quicly_application_space_t), QUICLY_DEFAULT_PACKET_TOLERANCE)) == NULL)
        return PTLS_ERROR_NO_MEMORY;

    /* prohibit key-update until receiving an ACK for an 1-RTT packet */
    conn->application->cipher.egress.key_update_pn.last = 0;
    conn->application->cipher.egress.key_update_pn.next = UINT64_MAX;

    return create_handshake_flow(conn, QUICLY_EPOCH_1RTT);
}

static int discard_handshake_context(quicly_conn_t *conn, size_t epoch)
{
    int ret;

    assert(epoch == QUICLY_EPOCH_INITIAL || epoch == QUICLY_EPOCH_HANDSHAKE);

    if ((ret = discard_sentmap_by_epoch(conn, 1u << epoch)) != 0)
        return ret;
    destroy_handshake_flow(conn, epoch);
    free_handshake_space(epoch == QUICLY_EPOCH_INITIAL ? &conn->initial : &conn->handshake);

    return 0;
}

static int apply_remote_transport_params(quicly_conn_t *conn)
{
    int ret;

    conn->egress.max_data.permitted = conn->super.remote.transport_params.max_data;
    if ((ret = update_max_streams(&conn->egress.max_streams.uni, conn->super.remote.transport_params.max_streams_uni)) != 0)
        return ret;
    if ((ret = update_max_streams(&conn->egress.max_streams.bidi, conn->super.remote.transport_params.max_streams_bidi)) != 0)
        return ret;

    return 0;
}

static int update_1rtt_key(quicly_conn_t *conn, ptls_cipher_suite_t *cipher, int is_enc, ptls_aead_context_t **aead,
                           uint8_t *secret)
{
    uint8_t new_secret[PTLS_MAX_DIGEST_SIZE];
    ptls_aead_context_t *new_aead = NULL;
    int ret;

    /* generate next AEAD key */
    if ((ret = ptls_hkdf_expand_label(cipher->hash, new_secret, cipher->hash->digest_size,
                                      ptls_iovec_init(secret, cipher->hash->digest_size), "quic ku", ptls_iovec_init(NULL, 0),
                                      NULL)) != 0)
        goto Exit;
    if ((ret = setup_cipher(conn, QUICLY_EPOCH_1RTT, is_enc, NULL, &new_aead, cipher->aead, cipher->hash, new_secret)) != 0)
        goto Exit;

    /* success! update AEAD and secret */
    if (*aead != NULL)
        ptls_aead_free(*aead);
    *aead = new_aead;
    new_aead = NULL;
    memcpy(secret, new_secret, cipher->hash->digest_size);

    ret = 0;
Exit:
    if (new_aead != NULL)
        ptls_aead_free(new_aead);
    ptls_clear_memory(new_secret, cipher->hash->digest_size);
    return ret;
}

static int update_1rtt_egress_key(quicly_conn_t *conn)
{
    struct st_quicly_application_space_t *space = conn->application;
    ptls_cipher_suite_t *cipher = ptls_get_cipher(conn->crypto.tls);
    int ret;

    /* generate next AEAD key, and increment key phase if it succeeds */
    if ((ret = update_1rtt_key(conn, cipher, 1, &space->cipher.egress.key.aead, space->cipher.egress.secret)) != 0)
        return ret;
    ++space->cipher.egress.key_phase;

    /* signal that we are waiting for an ACK */
    space->cipher.egress.key_update_pn.last = conn->egress.packet_number;
    space->cipher.egress.key_update_pn.next = UINT64_MAX;

    QUICLY_PROBE(CRYPTO_SEND_KEY_UPDATE, conn, conn->stash.now, space->cipher.egress.key_phase,
                 QUICLY_PROBE_HEXDUMP(space->cipher.egress.secret, cipher->hash->digest_size));

    return 0;
}

static int received_key_update(quicly_conn_t *conn, uint64_t newly_decrypted_key_phase)
{
    struct st_quicly_application_space_t *space = conn->application;

    assert(space->cipher.ingress.key_phase.decrypted < newly_decrypted_key_phase);
    assert(newly_decrypted_key_phase <= space->cipher.ingress.key_phase.prepared);

    space->cipher.ingress.key_phase.decrypted = newly_decrypted_key_phase;

    QUICLY_PROBE(CRYPTO_RECEIVE_KEY_UPDATE, conn, conn->stash.now, space->cipher.ingress.key_phase.decrypted,
                 QUICLY_PROBE_HEXDUMP(space->cipher.ingress.secret, ptls_get_cipher(conn->crypto.tls)->hash->digest_size));

    if (space->cipher.egress.key_phase < space->cipher.ingress.key_phase.decrypted) {
        return update_1rtt_egress_key(conn);
    } else {
        return 0;
    }
}

void quicly_free(quicly_conn_t *conn)
{
    lock_now(conn, 0);

    QUICLY_PROBE(FREE, conn, conn->stash.now);

#if QUICLY_USE_EMBEDDED_PROBES || QUICLY_USE_DTRACE
    if (QUICLY_CONN_STATS_ENABLED()) {
        quicly_stats_t stats;
        quicly_get_stats(conn, &stats);
        QUICLY_PROBE(CONN_STATS, conn, conn->stash.now, &stats, sizeof(stats));
    }
#endif

    destroy_all_streams(conn, 0, 1);

    quicly_maxsender_dispose(&conn->ingress.max_data.sender);
    quicly_maxsender_dispose(&conn->ingress.max_streams.uni);
    quicly_maxsender_dispose(&conn->ingress.max_streams.bidi);
    while (conn->egress.path_challenge.head != NULL) {
        struct st_quicly_pending_path_challenge_t *pending = conn->egress.path_challenge.head;
        conn->egress.path_challenge.head = pending->next;
        free(pending);
    }
    quicly_loss_dispose(&conn->egress.loss);

    kh_destroy(quicly_stream_t, conn->streams);

    assert(!quicly_linklist_is_linked(&conn->egress.pending_streams.blocked.uni));
    assert(!quicly_linklist_is_linked(&conn->egress.pending_streams.blocked.bidi));
    assert(!quicly_linklist_is_linked(&conn->egress.pending_streams.control));
    assert(!quicly_linklist_is_linked(&conn->super._default_scheduler.active));
    assert(!quicly_linklist_is_linked(&conn->super._default_scheduler.blocked));

    free_handshake_space(&conn->initial);
    free_handshake_space(&conn->handshake);
    free_application_space(&conn->application);

    ptls_buffer_dispose(&conn->crypto.transport_params.buf);
    ptls_free(conn->crypto.tls);

    unlock_now(conn);

    free(conn->token.base);
    free(conn);
}

static int setup_initial_key(struct st_quicly_cipher_context_t *ctx, ptls_cipher_suite_t *cs, const void *master_secret,
                             const char *label, int is_enc, quicly_conn_t *conn)
{
    uint8_t aead_secret[PTLS_MAX_DIGEST_SIZE];
    int ret;

    if ((ret = ptls_hkdf_expand_label(cs->hash, aead_secret, cs->hash->digest_size,
                                      ptls_iovec_init(master_secret, cs->hash->digest_size), label, ptls_iovec_init(NULL, 0),
                                      NULL)) != 0)
        goto Exit;
    if ((ret = setup_cipher(conn, QUICLY_EPOCH_INITIAL, is_enc, &ctx->header_protection, &ctx->aead, cs->aead, cs->hash,
                            aead_secret)) != 0)
        goto Exit;

Exit:
    ptls_clear_memory(aead_secret, sizeof(aead_secret));
    return ret;
}

/**
 * @param conn maybe NULL when called by quicly_accept
 */
static int setup_initial_encryption(ptls_cipher_suite_t *cs, struct st_quicly_cipher_context_t *ingress,
                                    struct st_quicly_cipher_context_t *egress, ptls_iovec_t cid, int is_client, ptls_iovec_t salt,
                                    quicly_conn_t *conn)
{
    static const char *labels[2] = {"client in", "server in"};
    uint8_t secret[PTLS_MAX_DIGEST_SIZE];
    int ret;

    /* extract master secret */
    if ((ret = ptls_hkdf_extract(cs->hash, secret, salt, cid)) != 0)
        goto Exit;

    /* create aead contexts */
    if (ingress != NULL && (ret = setup_initial_key(ingress, cs, secret, labels[is_client], 0, conn)) != 0)
        goto Exit;
    if (egress != NULL && (ret = setup_initial_key(egress, cs, secret, labels[!is_client], 1, conn)) != 0) {
        if (ingress != NULL)
            dispose_cipher(ingress);
        goto Exit;
    }

Exit:
    ptls_clear_memory(secret, sizeof(secret));
    return ret;
}

static int reinstall_initial_encryption(quicly_conn_t *conn, int err_code_if_unknown_version)
{
    const struct st_ptls_salt_t *salt;

    /* get salt */
    if ((salt = get_salt(conn->super.version)) == NULL)
        return err_code_if_unknown_version;

    /* dispose existing context */
    dispose_cipher(&conn->initial->cipher.ingress);
    dispose_cipher(&conn->initial->cipher.egress);

    /* setup encryption context */
    return setup_initial_encryption(
        get_aes128gcmsha256(conn->super.ctx), &conn->initial->cipher.ingress, &conn->initial->cipher.egress,
        ptls_iovec_init(conn->super.remote.cid_set.cids[0].cid.cid, conn->super.remote.cid_set.cids[0].cid.len), 1,
        ptls_iovec_init(salt->initial, sizeof(salt->initial)), NULL);
}

static int apply_stream_frame(quicly_stream_t *stream, quicly_stream_frame_t *frame)
{
    int ret;

    QUICLY_PROBE(STREAM_RECEIVE, stream->conn, stream->conn->stash.now, stream, frame->offset, frame->data.len);

    if (quicly_recvstate_transfer_complete(&stream->recvstate))
        return 0;

    /* flow control */
    if (stream->stream_id >= 0) {
        /* STREAMs */
        uint64_t max_stream_data = frame->offset + frame->data.len;
        if ((int64_t)stream->_recv_aux.window < (int64_t)max_stream_data - (int64_t)stream->recvstate.data_off)
            return QUICLY_TRANSPORT_ERROR_FLOW_CONTROL;
        if (stream->recvstate.received.ranges[stream->recvstate.received.num_ranges - 1].end < max_stream_data) {
            uint64_t newly_received =
                max_stream_data - stream->recvstate.received.ranges[stream->recvstate.received.num_ranges - 1].end;
            if (stream->conn->ingress.max_data.bytes_consumed + newly_received >
                stream->conn->ingress.max_data.sender.max_committed)
                return QUICLY_TRANSPORT_ERROR_FLOW_CONTROL;
            stream->conn->ingress.max_data.bytes_consumed += newly_received;
            /* FIXME send MAX_DATA if necessary */
        }
    } else {
        /* CRYPTO streams; maybe add different limit for 1-RTT CRYPTO? */
        if (frame->offset + frame->data.len > stream->conn->super.ctx->max_crypto_bytes)
            return QUICLY_TRANSPORT_ERROR_CRYPTO_BUFFER_EXCEEDED;
    }

    /* update recvbuf */
    size_t apply_len = frame->data.len;
    if ((ret = quicly_recvstate_update(&stream->recvstate, frame->offset, &apply_len, frame->is_fin,
                                       stream->_recv_aux.max_ranges)) != 0)
        return ret;

    if (apply_len != 0 || quicly_recvstate_transfer_complete(&stream->recvstate)) {
        uint64_t buf_offset = frame->offset + frame->data.len - apply_len - stream->recvstate.data_off;
        const void *apply_src = frame->data.base + frame->data.len - apply_len;
        QUICLY_PROBE(STREAM_ON_RECEIVE, stream->conn, stream->conn->stash.now, stream, (size_t)buf_offset, apply_src, apply_len);
        stream->callbacks->on_receive(stream, (size_t)buf_offset, apply_src, apply_len);
        if (stream->conn->super.state >= QUICLY_STATE_CLOSING)
            return QUICLY_ERROR_IS_CLOSING;
    }

    if (should_send_max_stream_data(stream))
        sched_stream_control(stream);

    if (stream_is_destroyable(stream))
        destroy_stream(stream, 0);

    return 0;
}

int quicly_encode_transport_parameter_list(ptls_buffer_t *buf, const quicly_transport_parameters_t *params,
                                           const quicly_cid_t *original_dcid, const quicly_cid_t *initial_scid,
                                           const quicly_cid_t *retry_scid, const void *stateless_reset_token, size_t expand_by)
{
    int ret;

#define PUSH_TP(buf, id, block)                                                                                                    \
    do {                                                                                                                           \
        ptls_buffer_push_quicint((buf), (id));                                                                                     \
        ptls_buffer_push_block((buf), -1, block);                                                                                  \
    } while (0)

    PUSH_TP(buf, QUICLY_TRANSPORT_PARAMETER_ID_MAX_UDP_PAYLOAD_SIZE,
            { ptls_buffer_push_quicint(buf, params->max_udp_payload_size); });
    if (params->max_stream_data.bidi_local != 0)
        PUSH_TP(buf, QUICLY_TRANSPORT_PARAMETER_ID_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
                { ptls_buffer_push_quicint(buf, params->max_stream_data.bidi_local); });
    if (params->max_stream_data.bidi_remote != 0)
        PUSH_TP(buf, QUICLY_TRANSPORT_PARAMETER_ID_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
                { ptls_buffer_push_quicint(buf, params->max_stream_data.bidi_remote); });
    if (params->max_stream_data.uni != 0)
        PUSH_TP(buf, QUICLY_TRANSPORT_PARAMETER_ID_INITIAL_MAX_STREAM_DATA_UNI,
                { ptls_buffer_push_quicint(buf, params->max_stream_data.uni); });
    if (params->max_data != 0)
        PUSH_TP(buf, QUICLY_TRANSPORT_PARAMETER_ID_INITIAL_MAX_DATA, { ptls_buffer_push_quicint(buf, params->max_data); });
    if (params->max_idle_timeout != 0)
        PUSH_TP(buf, QUICLY_TRANSPORT_PARAMETER_ID_MAX_IDLE_TIMEOUT, { ptls_buffer_push_quicint(buf, params->max_idle_timeout); });
    if (original_dcid != NULL)
        PUSH_TP(buf, QUICLY_TRANSPORT_PARAMETER_ID_ORIGINAL_CONNECTION_ID,
                { ptls_buffer_pushv(buf, original_dcid->cid, original_dcid->len); });
    if (initial_scid != NULL)
        PUSH_TP(buf, QUICLY_TRANSPORT_PARAMETER_ID_INITIAL_SOURCE_CONNECTION_ID,
                { ptls_buffer_pushv(buf, initial_scid->cid, initial_scid->len); });
    if (retry_scid != NULL)
        PUSH_TP(buf, QUICLY_TRANSPORT_PARAMETER_ID_RETRY_SOURCE_CONNECTION_ID,
                { ptls_buffer_pushv(buf, retry_scid->cid, retry_scid->len); });
    if (stateless_reset_token != NULL)
        PUSH_TP(buf, QUICLY_TRANSPORT_PARAMETER_ID_STATELESS_RESET_TOKEN,
                { ptls_buffer_pushv(buf, stateless_reset_token, QUICLY_STATELESS_RESET_TOKEN_LEN); });
    if (params->max_streams_bidi != 0)
        PUSH_TP(buf, QUICLY_TRANSPORT_PARAMETER_ID_INITIAL_MAX_STREAMS_BIDI,
                { ptls_buffer_push_quicint(buf, params->max_streams_bidi); });
    if (params->max_streams_uni != 0)
        PUSH_TP(buf, QUICLY_TRANSPORT_PARAMETER_ID_INITIAL_MAX_STREAMS_UNI,
                { ptls_buffer_push_quicint(buf, params->max_streams_uni); });
    if (QUICLY_LOCAL_ACK_DELAY_EXPONENT != QUICLY_DEFAULT_ACK_DELAY_EXPONENT)
        PUSH_TP(buf, QUICLY_TRANSPORT_PARAMETER_ID_ACK_DELAY_EXPONENT,
                { ptls_buffer_push_quicint(buf, QUICLY_LOCAL_ACK_DELAY_EXPONENT); });
    if (QUICLY_LOCAL_MAX_ACK_DELAY != QUICLY_DEFAULT_MAX_ACK_DELAY)
        PUSH_TP(buf, QUICLY_TRANSPORT_PARAMETER_ID_MAX_ACK_DELAY, { ptls_buffer_push_quicint(buf, QUICLY_LOCAL_MAX_ACK_DELAY); });
    if (params->min_ack_delay_usec != UINT64_MAX) {
        /* TODO consider the value we should advertise. */
        PUSH_TP(buf, QUICLY_TRANSPORT_PARAMETER_ID_MIN_ACK_DELAY,
                { ptls_buffer_push_quicint(buf, QUICLY_LOCAL_MAX_ACK_DELAY * 1000 /* in microseconds */); });
    }
    if (params->disable_active_migration)
        PUSH_TP(buf, QUICLY_TRANSPORT_PARAMETER_ID_DISABLE_ACTIVE_MIGRATION, {});
    if (QUICLY_LOCAL_ACTIVE_CONNECTION_ID_LIMIT != QUICLY_DEFAULT_ACTIVE_CONNECTION_ID_LIMIT)
        PUSH_TP(buf, QUICLY_TRANSPORT_PARAMETER_ID_ACTIVE_CONNECTION_ID_LIMIT,
                { ptls_buffer_push_quicint(buf, QUICLY_LOCAL_ACTIVE_CONNECTION_ID_LIMIT); });
    if (params->max_datagram_frame_size != 0)
        PUSH_TP(buf, QUICLY_TRANSPORT_PARAMETER_ID_MAX_DATAGRAM_FRAME_SIZE,
                { ptls_buffer_push_quicint(buf, params->max_datagram_frame_size); });
    /* if requested, add a greasing TP of 1 MTU size so that CH spans across multiple packets */
    if (expand_by != 0) {
        PUSH_TP(buf, 31 * 100 + 27, {
            if ((ret = ptls_buffer_reserve(buf, expand_by)) != 0)
                goto Exit;
            memset(buf->base + buf->off, 0, expand_by);
            buf->off += expand_by;
        });
    }

#undef PUSH_TP

    ret = 0;
Exit:
    return ret;
}

/**
 * sentinel used for indicating that the corresponding TP should be ignored
 */
static const quicly_cid_t _tp_cid_ignore;
#define tp_cid_ignore (*(quicly_cid_t *)&_tp_cid_ignore)

int quicly_decode_transport_parameter_list(quicly_transport_parameters_t *params, quicly_cid_t *original_dcid,
                                           quicly_cid_t *initial_scid, quicly_cid_t *retry_scid, void *stateless_reset_token,
                                           const uint8_t *src, const uint8_t *end, int recognize_delayed_ack)
{
/* When non-negative, tp_index contains the literal position within the list of transport parameters recognized by this function.
 * That index is being used to find duplicates using a 64-bit bitmap (found_bits). When the transport parameter is being processed,
 * tp_index is set to -1. */
#define DECODE_TP(_id, block)                                                                                                      \
    do {                                                                                                                           \
        if (tp_index >= 0) {                                                                                                       \
            if (id == (_id)) {                                                                                                     \
                if ((found_bits & ((uint64_t)1 << tp_index)) != 0) {                                                               \
                    ret = QUICLY_TRANSPORT_ERROR_TRANSPORT_PARAMETER;                                                              \
                    goto Exit;                                                                                                     \
                }                                                                                                                  \
                found_bits |= (uint64_t)1 << tp_index;                                                                             \
                {block} tp_index = -1;                                                                                             \
            } else {                                                                                                               \
                ++tp_index;                                                                                                        \
            }                                                                                                                      \
        }                                                                                                                          \
    } while (0)
#define DECODE_CID_TP(_id, dest)                                                                                                   \
    DECODE_TP(_id, {                                                                                                               \
        size_t cidl = end - src;                                                                                                   \
        if (cidl > QUICLY_MAX_CID_LEN_V1) {                                                                                        \
            ret = QUICLY_TRANSPORT_ERROR_TRANSPORT_PARAMETER;                                                                      \
            goto Exit;                                                                                                             \
        }                                                                                                                          \
        if (dest == NULL) {                                                                                                        \
            ret = QUICLY_TRANSPORT_ERROR_TRANSPORT_PARAMETER;                                                                      \
            goto Exit;                                                                                                             \
        } else if (dest != &tp_cid_ignore) {                                                                                       \
            quicly_set_cid(dest, ptls_iovec_init(src, cidl));                                                                      \
        }                                                                                                                          \
        src = end;                                                                                                                 \
    });

    uint64_t found_bits = 0;
    int ret;

    /* set parameters to their default values */
    *params = default_transport_params;

    /* Set optional parameters to UINT8_MAX. It is used to as a sentinel for detecting missing TPs. */
    if (original_dcid != NULL && original_dcid != &tp_cid_ignore)
        original_dcid->len = UINT8_MAX;
    if (initial_scid != NULL && initial_scid != &tp_cid_ignore)
        initial_scid->len = UINT8_MAX;
    if (retry_scid != NULL && retry_scid != &tp_cid_ignore)
        retry_scid->len = UINT8_MAX;

    /* decode the parameters block */
    while (src != end) {
        uint64_t id;
        if ((id = quicly_decodev(&src, end)) == UINT64_MAX) {
            ret = QUICLY_TRANSPORT_ERROR_TRANSPORT_PARAMETER;
            goto Exit;
        }
        int tp_index = 0;
        ptls_decode_open_block(src, end, -1, {
            DECODE_CID_TP(QUICLY_TRANSPORT_PARAMETER_ID_ORIGINAL_CONNECTION_ID, original_dcid);
            DECODE_CID_TP(QUICLY_TRANSPORT_PARAMETER_ID_INITIAL_SOURCE_CONNECTION_ID, initial_scid);
            DECODE_CID_TP(QUICLY_TRANSPORT_PARAMETER_ID_RETRY_SOURCE_CONNECTION_ID, retry_scid);
            DECODE_TP(QUICLY_TRANSPORT_PARAMETER_ID_MAX_UDP_PAYLOAD_SIZE, {
                uint64_t v;
                if ((v = ptls_decode_quicint(&src, end)) == UINT64_MAX) {
                    ret = QUICLY_TRANSPORT_ERROR_TRANSPORT_PARAMETER;
                    goto Exit;
                }
                if (v < 1200) {
                    ret = QUICLY_TRANSPORT_ERROR_TRANSPORT_PARAMETER;
                    goto Exit;
                }
                if (v > UINT16_MAX)
                    v = UINT16_MAX;
                params->max_udp_payload_size = (uint16_t)v;
            });
            DECODE_TP(QUICLY_TRANSPORT_PARAMETER_ID_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL, {
                if ((params->max_stream_data.bidi_local = ptls_decode_quicint(&src, end)) == UINT64_MAX) {
                    ret = QUICLY_TRANSPORT_ERROR_TRANSPORT_PARAMETER;
                    goto Exit;
                }
            });
            DECODE_TP(QUICLY_TRANSPORT_PARAMETER_ID_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE, {
                if ((params->max_stream_data.bidi_remote = ptls_decode_quicint(&src, end)) == UINT64_MAX) {
                    ret = QUICLY_TRANSPORT_ERROR_TRANSPORT_PARAMETER;
                    goto Exit;
                }
            });
            DECODE_TP(QUICLY_TRANSPORT_PARAMETER_ID_INITIAL_MAX_STREAM_DATA_UNI, {
                if ((params->max_stream_data.uni = ptls_decode_quicint(&src, end)) == UINT64_MAX) {
                    ret = QUICLY_TRANSPORT_ERROR_TRANSPORT_PARAMETER;
                    goto Exit;
                }
            });
            DECODE_TP(QUICLY_TRANSPORT_PARAMETER_ID_INITIAL_MAX_DATA, {
                if ((params->max_data = ptls_decode_quicint(&src, end)) == UINT64_MAX) {
                    ret = QUICLY_TRANSPORT_ERROR_TRANSPORT_PARAMETER;
                    goto Exit;
                }
            });
            DECODE_TP(QUICLY_TRANSPORT_PARAMETER_ID_STATELESS_RESET_TOKEN, {
                if (!(stateless_reset_token != NULL && end - src == QUICLY_STATELESS_RESET_TOKEN_LEN)) {
                    ret = QUICLY_TRANSPORT_ERROR_TRANSPORT_PARAMETER;
                    goto Exit;
                }
                memcpy(stateless_reset_token, src, QUICLY_STATELESS_RESET_TOKEN_LEN);
                src = end;
            });
            DECODE_TP(QUICLY_TRANSPORT_PARAMETER_ID_MAX_IDLE_TIMEOUT, {
                if ((params->max_idle_timeout = ptls_decode_quicint(&src, end)) == UINT64_MAX) {
                    ret = QUICLY_TRANSPORT_ERROR_TRANSPORT_PARAMETER;
                    goto Exit;
                }
            });
            DECODE_TP(QUICLY_TRANSPORT_PARAMETER_ID_INITIAL_MAX_STREAMS_BIDI, {
                if ((params->max_streams_bidi = ptls_decode_quicint(&src, end)) == UINT64_MAX) {
                    ret = QUICLY_TRANSPORT_ERROR_TRANSPORT_PARAMETER;
                    goto Exit;
                }
            });
            DECODE_TP(QUICLY_TRANSPORT_PARAMETER_ID_INITIAL_MAX_STREAMS_UNI, {
                if ((params->max_streams_uni = ptls_decode_quicint(&src, end)) == UINT64_MAX) {
                    ret = QUICLY_TRANSPORT_ERROR_TRANSPORT_PARAMETER;
                    goto Exit;
                }
            });
            DECODE_TP(QUICLY_TRANSPORT_PARAMETER_ID_ACK_DELAY_EXPONENT, {
                uint64_t v;
                if ((v = ptls_decode_quicint(&src, end)) == UINT64_MAX) {
                    ret = QUICLY_TRANSPORT_ERROR_TRANSPORT_PARAMETER;
                    goto Exit;
                }
                if (v > 20) {
                    ret = QUICLY_TRANSPORT_ERROR_TRANSPORT_PARAMETER;
                    goto Exit;
                }
                params->ack_delay_exponent = (uint8_t)v;
            });
            DECODE_TP(QUICLY_TRANSPORT_PARAMETER_ID_MAX_ACK_DELAY, {
                uint64_t v;
                if ((v = ptls_decode_quicint(&src, end)) == UINT64_MAX) {
                    ret = QUICLY_TRANSPORT_ERROR_TRANSPORT_PARAMETER;
                    goto Exit;
                }
                if (v >= 16384) { /* "values of 2^14 or greater are invalid" */
                    ret = QUICLY_TRANSPORT_ERROR_TRANSPORT_PARAMETER;
                    goto Exit;
                }
                params->max_ack_delay = (uint16_t)v;
            });
            /* min_ack_delay is recognized only if the support is enabled on this endpoint */
            if (recognize_delayed_ack) {
                DECODE_TP(QUICLY_TRANSPORT_PARAMETER_ID_MIN_ACK_DELAY, {
                    if ((params->min_ack_delay_usec = ptls_decode_quicint(&src, end)) == UINT64_MAX) {
                        ret = QUICLY_TRANSPORT_ERROR_TRANSPORT_PARAMETER;
                        goto Exit;
                    }
                    if (params->min_ack_delay_usec >= 16777216) { /* "values of 2^24 or greater are invalid" */
                        ret = QUICLY_TRANSPORT_ERROR_TRANSPORT_PARAMETER;
                        goto Exit;
                    }
                });
            }
            DECODE_TP(QUICLY_TRANSPORT_PARAMETER_ID_ACTIVE_CONNECTION_ID_LIMIT, {
                uint64_t v;
                if ((v = ptls_decode_quicint(&src, end)) == UINT64_MAX) {
                    ret = QUICLY_TRANSPORT_ERROR_TRANSPORT_PARAMETER;
                    goto Exit;
                }
                if (v < QUICLY_MIN_ACTIVE_CONNECTION_ID_LIMIT) {
                    ret = QUICLY_TRANSPORT_ERROR_TRANSPORT_PARAMETER;
                    goto Exit;
                }
                params->active_connection_id_limit = v;
            });
            DECODE_TP(QUICLY_TRANSPORT_PARAMETER_ID_DISABLE_ACTIVE_MIGRATION, { params->disable_active_migration = 1; });
            DECODE_TP(QUICLY_TRANSPORT_PARAMETER_ID_MAX_DATAGRAM_FRAME_SIZE, {
                uint64_t v;
                if ((v = ptls_decode_quicint(&src, end)) == UINT64_MAX) {
                    ret = QUICLY_TRANSPORT_ERROR_TRANSPORT_PARAMETER;
                    goto Exit;
                }
                if (v > UINT16_MAX)
                    v = UINT16_MAX;
                params->max_datagram_frame_size = (uint16_t)v;
            });
            /* skip unknown extension */
            if (tp_index >= 0)
                src = end;
        });
    }

    /* check consistency between the transpart parameters */
    if (params->min_ack_delay_usec != UINT64_MAX) {
        if (params->min_ack_delay_usec > params->max_ack_delay * 1000) {
            ret = QUICLY_TRANSPORT_ERROR_PROTOCOL_VIOLATION;
            goto Exit;
        }
    }

    /* check the absence of CIDs */
    if ((original_dcid != NULL && original_dcid->len == UINT8_MAX) || (initial_scid != NULL && initial_scid->len == UINT8_MAX) ||
        (retry_scid != NULL && retry_scid->len == UINT8_MAX)) {
        ret = QUICLY_TRANSPORT_ERROR_TRANSPORT_PARAMETER;
        goto Exit;
    }

    ret = 0;
Exit:
    if (ret == PTLS_ALERT_DECODE_ERROR)
        ret = QUICLY_TRANSPORT_ERROR_TRANSPORT_PARAMETER;
    return ret;

#undef DECODE_TP
#undef DECODE_CID_TP
}

static int collect_transport_parameters(ptls_t *tls, struct st_ptls_handshake_properties_t *properties, uint16_t type)
{
    return type == QUICLY_TLS_EXTENSION_TYPE_TRANSPORT_PARAMETERS;
}

static quicly_conn_t *create_connection(quicly_context_t *ctx, uint32_t protocol_version, const char *server_name,
                                        struct sockaddr *remote_addr, struct sockaddr *local_addr, ptls_iovec_t *remote_cid,
                                        const quicly_cid_plaintext_t *local_cid, ptls_handshake_properties_t *handshake_properties,
                                        uint32_t initcwnd)
{
    ptls_t *tls = NULL;
    quicly_conn_t *conn;

    /* consistency checks */
    assert(remote_addr != NULL && remote_addr->sa_family != AF_UNSPEC);
    if (ctx->transport_params.max_datagram_frame_size != 0)
        assert(ctx->receive_datagram_frame != NULL);

    /* create TLS context */
    if ((tls = ptls_new(ctx->tls, server_name == NULL)) == NULL)
        return NULL;
    if (server_name != NULL && ptls_set_server_name(tls, server_name, strlen(server_name)) != 0) {
        ptls_free(tls);
        return NULL;
    }

    /* allocate memory and start creating QUIC context */
    if ((conn = malloc(sizeof(*conn))) == NULL) {
        ptls_free(tls);
        return NULL;
    }
    memset(conn, 0, sizeof(*conn));
    conn->super.ctx = ctx;
    lock_now(conn, 0);
    set_address(&conn->super.local.address, local_addr);
    set_address(&conn->super.remote.address, remote_addr);
    quicly_local_cid_init_set(&conn->super.local.cid_set, ctx->cid_encryptor, local_cid);
    conn->super.local.long_header_src_cid = conn->super.local.cid_set.cids[0].cid;
    quicly_remote_cid_init_set(&conn->super.remote.cid_set, remote_cid, ctx->tls->random_bytes);
    conn->super.state = QUICLY_STATE_FIRSTFLIGHT;
    if (server_name != NULL) {
        conn->super.local.bidi.next_stream_id = 0;
        conn->super.local.uni.next_stream_id = 2;
        conn->super.remote.bidi.next_stream_id = 1;
        conn->super.remote.uni.next_stream_id = 3;
    } else {
        conn->super.local.bidi.next_stream_id = 1;
        conn->super.local.uni.next_stream_id = 3;
        conn->super.remote.bidi.next_stream_id = 0;
        conn->super.remote.uni.next_stream_id = 2;
    }
    conn->super.remote.transport_params = default_transport_params;
    conn->super.version = protocol_version;
    conn->super.remote.largest_retire_prior_to = 0;
    quicly_linklist_init(&conn->super._default_scheduler.active);
    quicly_linklist_init(&conn->super._default_scheduler.blocked);
    conn->streams = kh_init(quicly_stream_t);
    quicly_maxsender_init(&conn->ingress.max_data.sender, conn->super.ctx->transport_params.max_data);
    quicly_maxsender_init(&conn->ingress.max_streams.uni, conn->super.ctx->transport_params.max_streams_uni);
    quicly_maxsender_init(&conn->ingress.max_streams.bidi, conn->super.ctx->transport_params.max_streams_bidi);
    quicly_loss_init(&conn->egress.loss, &conn->super.ctx->loss,
                     conn->super.ctx->loss.default_initial_rtt /* FIXME remember initial_rtt in session ticket */,
                     &conn->super.remote.transport_params.max_ack_delay, &conn->super.remote.transport_params.ack_delay_exponent);
    conn->egress.next_pn_to_skip =
        calc_next_pn_to_skip(conn->super.ctx->tls, 0, initcwnd, conn->super.ctx->initial_egress_max_udp_payload_size);
    conn->egress.max_udp_payload_size = conn->super.ctx->initial_egress_max_udp_payload_size;
    init_max_streams(&conn->egress.max_streams.uni);
    init_max_streams(&conn->egress.max_streams.bidi);
    conn->egress.path_challenge.tail_ref = &conn->egress.path_challenge.head;
    conn->egress.ack_frequency.update_at = INT64_MAX;
    conn->egress.send_ack_at = INT64_MAX;
    conn->super.ctx->init_cc->cb(conn->super.ctx->init_cc, &conn->egress.cc, initcwnd, conn->stash.now);
    quicly_retire_cid_init(&conn->egress.retire_cid);
    quicly_linklist_init(&conn->egress.pending_streams.blocked.uni);
    quicly_linklist_init(&conn->egress.pending_streams.blocked.bidi);
    quicly_linklist_init(&conn->egress.pending_streams.control);
    conn->crypto.tls = tls;
    if (handshake_properties != NULL) {
        assert(handshake_properties->additional_extensions == NULL);
        assert(handshake_properties->collect_extension == NULL);
        assert(handshake_properties->collected_extensions == NULL);
        conn->crypto.handshake_properties = *handshake_properties;
    } else {
        conn->crypto.handshake_properties = (ptls_handshake_properties_t){{{{NULL}}}};
    }
    conn->crypto.handshake_properties.collect_extension = collect_transport_parameters;
    conn->retry_scid.len = UINT8_MAX;
    conn->idle_timeout.at = INT64_MAX;
    conn->idle_timeout.should_rearm_on_send = 1;
    conn->stash.on_ack_stream.active_acked_cache.stream_id = INT64_MIN;

    *ptls_get_data_ptr(tls) = conn;

    return conn;
}

static int client_collected_extensions(ptls_t *tls, ptls_handshake_properties_t *properties, ptls_raw_extension_t *slots)
{
    quicly_conn_t *conn = (void *)((char *)properties - offsetof(quicly_conn_t, crypto.handshake_properties));
    int ret;

    assert(properties->client.early_data_acceptance != PTLS_EARLY_DATA_ACCEPTANCE_UNKNOWN);

    if (slots[0].type == UINT16_MAX) {
        ret = PTLS_ALERT_MISSING_EXTENSION;
        goto Exit;
    }
    assert(slots[0].type == QUICLY_TLS_EXTENSION_TYPE_TRANSPORT_PARAMETERS);
    assert(slots[1].type == UINT16_MAX);

    const uint8_t *src = slots[0].data.base, *end = src + slots[0].data.len;
    quicly_transport_parameters_t params;
    quicly_cid_t original_dcid, initial_scid, retry_scid = {};

    /* obtain pointer to initial CID of the peer. It is guaranteeed to exist in the first slot, as TP is received before any frame
     * that updates the CID set. */
    quicly_remote_cid_t *remote_cid = &conn->super.remote.cid_set.cids[0];
    assert(remote_cid->sequence == 0);

    /* decode */
    if ((ret = quicly_decode_transport_parameter_list(&params, needs_cid_auth(conn) || is_retry(conn) ? &original_dcid : NULL,
                                                      needs_cid_auth(conn) ? &initial_scid : &tp_cid_ignore,
                                                      needs_cid_auth(conn) ? is_retry(conn) ? &retry_scid : NULL : &tp_cid_ignore,
                                                      remote_cid->stateless_reset_token, src, end, recognize_delayed_ack(conn))) !=
        0)
        goto Exit;

    /* validate CIDs */
    if (needs_cid_auth(conn) || is_retry(conn)) {
        if (!quicly_cid_is_equal(&conn->super.original_dcid, ptls_iovec_init(original_dcid.cid, original_dcid.len))) {
            ret = QUICLY_TRANSPORT_ERROR_TRANSPORT_PARAMETER;
            goto Exit;
        }
    }
    if (needs_cid_auth(conn)) {
        if (!quicly_cid_is_equal(&remote_cid->cid, ptls_iovec_init(initial_scid.cid, initial_scid.len))) {
            ret = QUICLY_TRANSPORT_ERROR_TRANSPORT_PARAMETER;
            goto Exit;
        }
        if (is_retry(conn)) {
            if (!quicly_cid_is_equal(&conn->retry_scid, ptls_iovec_init(retry_scid.cid, retry_scid.len))) {
                ret = QUICLY_TRANSPORT_ERROR_TRANSPORT_PARAMETER;
                goto Exit;
            }
        }
    }

    if (properties->client.early_data_acceptance == PTLS_EARLY_DATA_ACCEPTED) {
#define ZERORTT_VALIDATE(x)                                                                                                        \
    if (params.x < conn->super.remote.transport_params.x) {                                                                        \
        ret = QUICLY_TRANSPORT_ERROR_TRANSPORT_PARAMETER;                                                                          \
        goto Exit;                                                                                                                 \
    }
        ZERORTT_VALIDATE(max_data);
        ZERORTT_VALIDATE(max_stream_data.bidi_local);
        ZERORTT_VALIDATE(max_stream_data.bidi_remote);
        ZERORTT_VALIDATE(max_stream_data.uni);
        ZERORTT_VALIDATE(max_streams_bidi);
        ZERORTT_VALIDATE(max_streams_uni);
#undef ZERORTT_VALIDATE
    }

    /* store the results */
    conn->super.remote.transport_params = params;
    ack_frequency_set_next_update_at(conn);

Exit:
    return ret; /* negative error codes used to transmit QUIC errors through picotls */
}

int quicly_connect(quicly_conn_t **_conn, quicly_context_t *ctx, const char *server_name, struct sockaddr *dest_addr,
                   struct sockaddr *src_addr, const quicly_cid_plaintext_t *new_cid, ptls_iovec_t address_token,
                   ptls_handshake_properties_t *handshake_properties, const quicly_transport_parameters_t *resumed_transport_params)
{
    const struct st_ptls_salt_t *salt;
    quicly_conn_t *conn = NULL;
    const quicly_cid_t *server_cid;
    ptls_buffer_t buf;
    size_t epoch_offsets[5] = {0};
    size_t max_early_data_size = 0;
    int ret;

    if ((salt = get_salt(ctx->initial_version)) == NULL) {
        if ((ctx->initial_version & 0x0f0f0f0f) == 0x0a0a0a0a) {
            /* greasing version, use our own greasing salt */
            static const struct st_ptls_salt_t grease_salt = {.initial = {0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe,
                                                                          0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad,
                                                                          0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef}};
            salt = &grease_salt;
        } else {
            ret = QUICLY_ERROR_INVALID_INITIAL_VERSION;
            goto Exit;
        }
    }

    if ((conn = create_connection(ctx, ctx->initial_version, server_name, dest_addr, src_addr, NULL, new_cid, handshake_properties,
                                  quicly_cc_calc_initial_cwnd(ctx->transport_params.max_udp_payload_size))) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }
    conn->super.remote.address_validation.validated = 1;
    conn->super.remote.address_validation.send_probe = 1;
    if (address_token.len != 0) {
        if ((conn->token.base = malloc(address_token.len)) == NULL) {
            ret = PTLS_ERROR_NO_MEMORY;
            goto Exit;
        }
        memcpy(conn->token.base, address_token.base, address_token.len);
        conn->token.len = address_token.len;
    }
    server_cid = quicly_get_remote_cid(conn);
    conn->super.original_dcid = *server_cid;

    QUICLY_PROBE(CONNECT, conn, conn->stash.now, conn->super.version);

    if ((ret = setup_handshake_space_and_flow(conn, QUICLY_EPOCH_INITIAL)) != 0)
        goto Exit;
    if ((ret = setup_initial_encryption(get_aes128gcmsha256(ctx), &conn->initial->cipher.ingress, &conn->initial->cipher.egress,
                                        ptls_iovec_init(server_cid->cid, server_cid->len), 1,
                                        ptls_iovec_init(salt->initial, sizeof(salt->initial)), conn)) != 0)
        goto Exit;

    /* handshake (we always encode authentication CIDs, as we do not (yet) regenerate ClientHello when receiving Retry) */
    ptls_buffer_init(&conn->crypto.transport_params.buf, "", 0);
    if ((ret = quicly_encode_transport_parameter_list(
             &conn->crypto.transport_params.buf, &conn->super.ctx->transport_params, NULL, &conn->super.local.cid_set.cids[0].cid,
             NULL, NULL, conn->super.ctx->expand_client_hello ? conn->super.ctx->initial_egress_max_udp_payload_size : 0)) != 0)
        goto Exit;
    conn->crypto.transport_params.ext[0] =
        (ptls_raw_extension_t){QUICLY_TLS_EXTENSION_TYPE_TRANSPORT_PARAMETERS,
                               {conn->crypto.transport_params.buf.base, conn->crypto.transport_params.buf.off}};
    conn->crypto.transport_params.ext[1] = (ptls_raw_extension_t){UINT16_MAX};
    conn->crypto.handshake_properties.additional_extensions = conn->crypto.transport_params.ext;
    conn->crypto.handshake_properties.collected_extensions = client_collected_extensions;

    ptls_buffer_init(&buf, "", 0);
    if (resumed_transport_params != NULL)
        conn->crypto.handshake_properties.client.max_early_data_size = &max_early_data_size;
    ret = ptls_handle_message(conn->crypto.tls, &buf, epoch_offsets, 0, NULL, 0, &conn->crypto.handshake_properties);
    conn->crypto.handshake_properties.client.max_early_data_size = NULL;
    if (ret != PTLS_ERROR_IN_PROGRESS) {
        assert(ret > 0); /* no QUIC errors */
        goto Exit;
    }
    write_crypto_data(conn, &buf, epoch_offsets);
    ptls_buffer_dispose(&buf);

    if (max_early_data_size != 0) {
        /* when attempting 0-RTT, apply the remembered transport parameters */
#define APPLY(n) conn->super.remote.transport_params.n = resumed_transport_params->n
        APPLY(active_connection_id_limit);
        APPLY(max_data);
        APPLY(max_stream_data.bidi_local);
        APPLY(max_stream_data.bidi_remote);
        APPLY(max_stream_data.uni);
        APPLY(max_streams_bidi);
        APPLY(max_streams_uni);
#undef APPLY
        if ((ret = apply_remote_transport_params(conn)) != 0)
            goto Exit;
    }

    *_conn = conn;
    ret = 0;

Exit:
    if (conn != NULL)
        unlock_now(conn);
    if (ret != 0) {
        if (conn != NULL)
            quicly_free(conn);
    }
    return ret;
}

static int server_collected_extensions(ptls_t *tls, ptls_handshake_properties_t *properties, ptls_raw_extension_t *slots)
{
    quicly_conn_t *conn = (void *)((char *)properties - offsetof(quicly_conn_t, crypto.handshake_properties));
    quicly_cid_t initial_scid;
    int ret;

    if (slots[0].type == UINT16_MAX) {
        ret = PTLS_ALERT_MISSING_EXTENSION;
        goto Exit;
    }
    assert(slots[0].type == QUICLY_TLS_EXTENSION_TYPE_TRANSPORT_PARAMETERS);
    assert(slots[1].type == UINT16_MAX);

    { /* decode transport_parameters extension */
        const uint8_t *src = slots[0].data.base, *end = src + slots[0].data.len;
        if ((ret = quicly_decode_transport_parameter_list(
                 &conn->super.remote.transport_params, needs_cid_auth(conn) ? NULL : &tp_cid_ignore,
                 needs_cid_auth(conn) ? &initial_scid : &tp_cid_ignore, needs_cid_auth(conn) ? NULL : &tp_cid_ignore, NULL, src,
                 end, recognize_delayed_ack(conn))) != 0)
            goto Exit;
        if (needs_cid_auth(conn) &&
            !quicly_cid_is_equal(&conn->super.remote.cid_set.cids[0].cid, ptls_iovec_init(initial_scid.cid, initial_scid.len))) {
            ret = QUICLY_TRANSPORT_ERROR_PROTOCOL_VIOLATION;
            goto Exit;
        }
    }

    /* setup ack frequency */
    ack_frequency_set_next_update_at(conn);

    /* update UDP max payload size to:
     * max(current, min(max_the_remote_sent, remote.tp.max_udp_payload_size, local.tp.max_udp_payload_size)) */
    assert(conn->initial != NULL);
    if (conn->egress.max_udp_payload_size < conn->initial->largest_ingress_udp_payload_size) {
        uint16_t size = conn->initial->largest_ingress_udp_payload_size;
        if (size > conn->super.remote.transport_params.max_udp_payload_size)
            size = conn->super.remote.transport_params.max_udp_payload_size;
        if (size > conn->super.ctx->transport_params.max_udp_payload_size)
            size = conn->super.ctx->transport_params.max_udp_payload_size;
        conn->egress.max_udp_payload_size = size;
    }

    /* set transport_parameters extension to be sent in EE */
    assert(properties->additional_extensions == NULL);
    ptls_buffer_init(&conn->crypto.transport_params.buf, "", 0);
    assert(conn->super.local.cid_set.cids[0].sequence == 0 && "make sure that local_cid is in expected state before sending SRT");
    if ((ret = quicly_encode_transport_parameter_list(
             &conn->crypto.transport_params.buf, &conn->super.ctx->transport_params,
             needs_cid_auth(conn) || is_retry(conn) ? &conn->super.original_dcid : NULL,
             needs_cid_auth(conn) ? &conn->super.local.cid_set.cids[0].cid : NULL,
             needs_cid_auth(conn) && is_retry(conn) ? &conn->retry_scid : NULL,
             conn->super.ctx->cid_encryptor != NULL ? conn->super.local.cid_set.cids[0].stateless_reset_token : NULL, 0)) != 0)
        goto Exit;
    properties->additional_extensions = conn->crypto.transport_params.ext;
    conn->crypto.transport_params.ext[0] =
        (ptls_raw_extension_t){QUICLY_TLS_EXTENSION_TYPE_TRANSPORT_PARAMETERS,
                               {conn->crypto.transport_params.buf.base, conn->crypto.transport_params.buf.off}};
    conn->crypto.transport_params.ext[1] = (ptls_raw_extension_t){UINT16_MAX};
    conn->crypto.handshake_properties.additional_extensions = conn->crypto.transport_params.ext;

    ret = 0;

Exit:
    return ret;
}

static size_t aead_decrypt_core(ptls_aead_context_t *aead, uint64_t pn, quicly_decoded_packet_t *packet, size_t aead_off)
{
    return ptls_aead_decrypt(aead, packet->octets.base + aead_off, packet->octets.base + aead_off, packet->octets.len - aead_off,
                             pn, packet->octets.base, aead_off);
}

static int aead_decrypt_fixed_key(void *ctx, uint64_t pn, quicly_decoded_packet_t *packet, size_t aead_off, size_t *ptlen)
{
    ptls_aead_context_t *aead = ctx;

    if ((*ptlen = aead_decrypt_core(aead, pn, packet, aead_off)) == SIZE_MAX)
        return QUICLY_ERROR_PACKET_IGNORED;
    return 0;
}

static int aead_decrypt_1rtt(void *ctx, uint64_t pn, quicly_decoded_packet_t *packet, size_t aead_off, size_t *ptlen)
{
    quicly_conn_t *conn = ctx;
    struct st_quicly_application_space_t *space = conn->application;
    size_t aead_index = (packet->octets.base[0] & QUICLY_KEY_PHASE_BIT) != 0;
    int ret;

    /* prepare key, when not available (yet) */
    if (space->cipher.ingress.aead[aead_index] == NULL) {
    Retry_1RTT : {
        /* Replace the AEAD key at the alternative slot (note: decryption key slots are shared by 0-RTT and 1-RTT), at the same time
         * dropping 0-RTT header protection key. */
        if (conn->application->cipher.ingress.header_protection.zero_rtt != NULL) {
            ptls_cipher_free(conn->application->cipher.ingress.header_protection.zero_rtt);
            conn->application->cipher.ingress.header_protection.zero_rtt = NULL;
        }
        ptls_cipher_suite_t *cipher = ptls_get_cipher(conn->crypto.tls);
        if ((ret = update_1rtt_key(conn, cipher, 0, &space->cipher.ingress.aead[aead_index], space->cipher.ingress.secret)) != 0)
            return ret;
        ++space->cipher.ingress.key_phase.prepared;
        QUICLY_PROBE(CRYPTO_RECEIVE_KEY_UPDATE_PREPARE, conn, conn->stash.now, space->cipher.ingress.key_phase.prepared,
                     QUICLY_PROBE_HEXDUMP(space->cipher.ingress.secret, cipher->hash->digest_size));
    }
    }

    /* decrypt */
    ptls_aead_context_t *aead = space->cipher.ingress.aead[aead_index];
    if ((*ptlen = aead_decrypt_core(aead, pn, packet, aead_off)) == SIZE_MAX) {
        /* retry with a new key, if possible */
        if (space->cipher.ingress.key_phase.decrypted == space->cipher.ingress.key_phase.prepared &&
            space->cipher.ingress.key_phase.decrypted % 2 != aead_index) {
            /* reapply AEAD to revert payload to the encrypted form. This assumes that the cipher used in AEAD is CTR. */
            aead_decrypt_core(aead, pn, packet, aead_off);
            goto Retry_1RTT;
        }
        /* otherwise return failure */
        return QUICLY_ERROR_PACKET_IGNORED;
    }

    /* update the confirmed key phase and also the egress key phase, if necessary */
    if (space->cipher.ingress.key_phase.prepared != space->cipher.ingress.key_phase.decrypted &&
        space->cipher.ingress.key_phase.prepared % 2 == aead_index) {
        if ((ret = received_key_update(conn, space->cipher.ingress.key_phase.prepared)) != 0)
            return ret;
    }

    return 0;
}

static int do_decrypt_packet(ptls_cipher_context_t *header_protection,
                             int (*aead_cb)(void *, uint64_t, quicly_decoded_packet_t *, size_t, size_t *), void *aead_ctx,
                             uint64_t *next_expected_pn, quicly_decoded_packet_t *packet, uint64_t *pn, ptls_iovec_t *payload)
{
    size_t encrypted_len = packet->octets.len - packet->encrypted_off;
    uint8_t hpmask[5] = {0};
    uint32_t pnbits = 0;
    size_t pnlen, ptlen, i;
    int ret;

    /* decipher the header protection, as well as obtaining pnbits, pnlen */
    if (encrypted_len < header_protection->algo->iv_size + QUICLY_MAX_PN_SIZE) {
        *pn = UINT64_MAX;
        return QUICLY_ERROR_PACKET_IGNORED;
    }
    ptls_cipher_init(header_protection, packet->octets.base + packet->encrypted_off + QUICLY_MAX_PN_SIZE);
    ptls_cipher_encrypt(header_protection, hpmask, hpmask, sizeof(hpmask));
    packet->octets.base[0] ^= hpmask[0] & (QUICLY_PACKET_IS_LONG_HEADER(packet->octets.base[0]) ? 0xf : 0x1f);
    pnlen = (packet->octets.base[0] & 0x3) + 1;
    for (i = 0; i != pnlen; ++i) {
        packet->octets.base[packet->encrypted_off + i] ^= hpmask[i + 1];
        pnbits = (pnbits << 8) | packet->octets.base[packet->encrypted_off + i];
    }

    size_t aead_off = packet->encrypted_off + pnlen;
    *pn = quicly_determine_packet_number(pnbits, pnlen * 8, *next_expected_pn);

    /* AEAD decryption */
    if ((ret = (*aead_cb)(aead_ctx, *pn, packet, aead_off, &ptlen)) != 0) {
        if (QUICLY_DEBUG)
            fprintf(stderr, "%s: aead decryption failure (pn: %" PRIu64 ",code:%d)\n", __FUNCTION__, *pn, ret);
        return ret;
    }
    if (*next_expected_pn <= *pn)
        *next_expected_pn = *pn + 1;

    *payload = ptls_iovec_init(packet->octets.base + aead_off, ptlen);
    return 0;
}

static int decrypt_packet(ptls_cipher_context_t *header_protection,
                          int (*aead_cb)(void *, uint64_t, quicly_decoded_packet_t *, size_t, size_t *), void *aead_ctx,
                          uint64_t *next_expected_pn, quicly_decoded_packet_t *packet, uint64_t *pn, ptls_iovec_t *payload)
{
    int ret;

    /* decrypt ourselves, or use the pre-decrypted input */
    if (packet->decrypted.pn == UINT64_MAX) {
        if ((ret = do_decrypt_packet(header_protection, aead_cb, aead_ctx, next_expected_pn, packet, pn, payload)) != 0)
            return ret;
    } else {
        *payload = ptls_iovec_init(packet->octets.base + packet->encrypted_off, packet->octets.len - packet->encrypted_off);
        *pn = packet->decrypted.pn;
        if (aead_cb == aead_decrypt_1rtt) {
            quicly_conn_t *conn = aead_ctx;
            if (conn->application->cipher.ingress.key_phase.decrypted < packet->decrypted.key_phase) {
                if ((ret = received_key_update(conn, packet->decrypted.key_phase)) != 0)
                    return ret;
            }
        }
        if (*next_expected_pn < *pn)
            *next_expected_pn = *pn + 1;
    }

    /* check reserved bits after AEAD decryption */
    if ((packet->octets.base[0] & (QUICLY_PACKET_IS_LONG_HEADER(packet->octets.base[0]) ? QUICLY_LONG_HEADER_RESERVED_BITS
                                                                                        : QUICLY_SHORT_HEADER_RESERVED_BITS)) !=
        0) {
        if (QUICLY_DEBUG)
            fprintf(stderr, "%s: non-zero reserved bits (pn: %" PRIu64 ")\n", __FUNCTION__, *pn);
        return QUICLY_TRANSPORT_ERROR_PROTOCOL_VIOLATION;
    }
    if (payload->len == 0) {
        if (QUICLY_DEBUG)
            fprintf(stderr, "%s: payload length is zero (pn: %" PRIu64 ")\n", __FUNCTION__, *pn);
        return QUICLY_TRANSPORT_ERROR_PROTOCOL_VIOLATION;
    }

    if (QUICLY_DEBUG) {
        char *payload_hex = quicly_hexdump(payload->base, payload->len, 4);
        fprintf(stderr, "%s: AEAD payload:\n%s", __FUNCTION__, payload_hex);
        free(payload_hex);
    }

    return 0;
}

static int on_ack_ack(quicly_sentmap_t *map, const quicly_sent_packet_t *packet, int acked, quicly_sent_t *sent)
{
    quicly_conn_t *conn = (quicly_conn_t *)((char *)map - offsetof(quicly_conn_t, egress.loss.sentmap));

    /* TODO log */

    if (acked) {
        /* find the pn space */
        struct st_quicly_pn_space_t *space;
        switch (packet->ack_epoch) {
        case QUICLY_EPOCH_INITIAL:
            space = &conn->initial->super;
            break;
        case QUICLY_EPOCH_HANDSHAKE:
            space = &conn->handshake->super;
            break;
        case QUICLY_EPOCH_1RTT:
            space = &conn->application->super;
            break;
        default:
            assert(!"FIXME");
            return QUICLY_TRANSPORT_ERROR_INTERNAL;
        }
        /* subtract given ACK range, then make adjustments */
        int ret;
        if ((ret = quicly_ranges_subtract(&space->ack_queue, sent->data.ack.range.start, sent->data.ack.range.end)) != 0)
            return ret;
        if (space->ack_queue.num_ranges == 0) {
            space->largest_pn_received_at = INT64_MAX;
            space->unacked_count = 0;
        } else if (space->ack_queue.num_ranges > QUICLY_MAX_ACK_BLOCKS) {
            quicly_ranges_drop_by_range_indices(&space->ack_queue, space->ack_queue.num_ranges - QUICLY_MAX_ACK_BLOCKS,
                                                space->ack_queue.num_ranges);
        }
    }

    return 0;
}

static int on_ack_stream_ack_one(quicly_conn_t *conn, quicly_stream_id_t stream_id, quicly_sendstate_sent_t *sent, int is_active)
{
    quicly_stream_t *stream;
    int ret;

    if ((stream = quicly_get_stream(conn, stream_id)) == NULL)
        return 0;

    size_t bytes_to_shift;
    if ((ret = quicly_sendstate_acked(&stream->sendstate, sent, is_active, &bytes_to_shift)) != 0)
        return ret;
    if (bytes_to_shift != 0) {
        QUICLY_PROBE(STREAM_ON_SEND_SHIFT, stream->conn, stream->conn->stash.now, stream, bytes_to_shift);
        stream->callbacks->on_send_shift(stream, bytes_to_shift);
    }
    if (stream_is_destroyable(stream)) {
        destroy_stream(stream, 0);
    } else if (stream->_send_aux.reset_stream.sender_state == QUICLY_SENDER_STATE_NONE) {
        resched_stream_data(stream);
    }

    return 0;
}

static int on_ack_stream_ack_cached(quicly_conn_t *conn)
{
    int ret;

    if (conn->stash.on_ack_stream.active_acked_cache.stream_id == INT64_MIN)
        return 0;
    ret = on_ack_stream_ack_one(conn, conn->stash.on_ack_stream.active_acked_cache.stream_id,
                                &conn->stash.on_ack_stream.active_acked_cache.args, 1);
    conn->stash.on_ack_stream.active_acked_cache.stream_id = INT64_MIN;
    return ret;
}

static int on_ack_stream(quicly_sentmap_t *map, const quicly_sent_packet_t *packet, int acked, quicly_sent_t *sent)
{
    quicly_conn_t *conn = (quicly_conn_t *)((char *)map - offsetof(quicly_conn_t, egress.loss.sentmap));
    int ret;

    if (acked) {

        QUICLY_PROBE(STREAM_ACKED, conn, conn->stash.now, sent->data.stream.stream_id, sent->data.stream.args.start,
                     sent->data.stream.args.end - sent->data.stream.args.start);

        if (packet->frames_in_flight && conn->stash.on_ack_stream.active_acked_cache.stream_id == sent->data.stream.stream_id &&
            conn->stash.on_ack_stream.active_acked_cache.args.end == sent->data.stream.args.start) {
            /* Fast path: append the newly supplied range to the existing cached range. */
            conn->stash.on_ack_stream.active_acked_cache.args.end = sent->data.stream.args.end;
        } else {
            /* Slow path: submit the cached range, and if possible, cache the newly supplied range. Else submit the newly supplied
             * range directly. */
            if ((ret = on_ack_stream_ack_cached(conn)) != 0)
                return ret;
            if (packet->frames_in_flight) {
                conn->stash.on_ack_stream.active_acked_cache.stream_id = sent->data.stream.stream_id;
                conn->stash.on_ack_stream.active_acked_cache.args = sent->data.stream.args;
            } else {
                if ((ret = on_ack_stream_ack_one(conn, sent->data.stream.stream_id, &sent->data.stream.args,
                                                 packet->frames_in_flight)) != 0)
                    return ret;
            }
        }

    } else {

        QUICLY_PROBE(STREAM_LOST, conn, conn->stash.now, sent->data.stream.stream_id, sent->data.stream.args.start,
                     sent->data.stream.args.end - sent->data.stream.args.start);

        quicly_stream_t *stream;
        if ((stream = quicly_get_stream(conn, sent->data.stream.stream_id)) == NULL)
            return 0;
        /* FIXME handle rto error */
        if ((ret = quicly_sendstate_lost(&stream->sendstate, &sent->data.stream.args)) != 0)
            return ret;
        if (stream->_send_aux.reset_stream.sender_state == QUICLY_SENDER_STATE_NONE)
            resched_stream_data(stream);
    }

    return 0;
}

static int on_ack_max_stream_data(quicly_sentmap_t *map, const quicly_sent_packet_t *packet, int acked, quicly_sent_t *sent)
{
    quicly_conn_t *conn = (quicly_conn_t *)((char *)map - offsetof(quicly_conn_t, egress.loss.sentmap));
    quicly_stream_t *stream;

    if ((stream = quicly_get_stream(conn, sent->data.stream.stream_id)) != NULL) {
        if (acked) {
            quicly_maxsender_acked(&stream->_send_aux.max_stream_data_sender, &sent->data.max_stream_data.args);
        } else {
            quicly_maxsender_lost(&stream->_send_aux.max_stream_data_sender, &sent->data.max_stream_data.args);
            if (should_send_max_stream_data(stream))
                sched_stream_control(stream);
        }
    }

    return 0;
}

static int on_ack_max_data(quicly_sentmap_t *map, const quicly_sent_packet_t *packet, int acked, quicly_sent_t *sent)
{
    quicly_conn_t *conn = (quicly_conn_t *)((char *)map - offsetof(quicly_conn_t, egress.loss.sentmap));

    if (acked) {
        quicly_maxsender_acked(&conn->ingress.max_data.sender, &sent->data.max_data.args);
    } else {
        quicly_maxsender_lost(&conn->ingress.max_data.sender, &sent->data.max_data.args);
    }

    return 0;
}

static int on_ack_max_streams(quicly_sentmap_t *map, const quicly_sent_packet_t *packet, int acked, quicly_sent_t *sent)
{
    quicly_conn_t *conn = (quicly_conn_t *)((char *)map - offsetof(quicly_conn_t, egress.loss.sentmap));
    quicly_maxsender_t *maxsender = sent->data.max_streams.uni ? &conn->ingress.max_streams.uni : &conn->ingress.max_streams.bidi;
    assert(maxsender != NULL); /* we would only receive an ACK if we have sent the frame */

    if (acked) {
        quicly_maxsender_acked(maxsender, &sent->data.max_streams.args);
    } else {
        quicly_maxsender_lost(maxsender, &sent->data.max_streams.args);
    }

    return 0;
}

static void on_ack_stream_state_sender(quicly_sender_state_t *sender_state, int acked)
{
    *sender_state = acked ? QUICLY_SENDER_STATE_ACKED : QUICLY_SENDER_STATE_SEND;
}

static int on_ack_reset_stream(quicly_sentmap_t *map, const quicly_sent_packet_t *packet, int acked, quicly_sent_t *sent)
{
    quicly_conn_t *conn = (quicly_conn_t *)((char *)map - offsetof(quicly_conn_t, egress.loss.sentmap));
    quicly_stream_t *stream;

    if ((stream = quicly_get_stream(conn, sent->data.stream_state_sender.stream_id)) != NULL) {
        on_ack_stream_state_sender(&stream->_send_aux.reset_stream.sender_state, acked);
        if (stream_is_destroyable(stream))
            destroy_stream(stream, 0);
    }

    return 0;
}

static int on_ack_stop_sending(quicly_sentmap_t *map, const quicly_sent_packet_t *packet, int acked, quicly_sent_t *sent)
{
    quicly_conn_t *conn = (quicly_conn_t *)((char *)map - offsetof(quicly_conn_t, egress.loss.sentmap));
    quicly_stream_t *stream;

    if ((stream = quicly_get_stream(conn, sent->data.stream_state_sender.stream_id)) != NULL) {
        on_ack_stream_state_sender(&stream->_send_aux.stop_sending.sender_state, acked);
        if (stream->_send_aux.stop_sending.sender_state != QUICLY_SENDER_STATE_ACKED)
            sched_stream_control(stream);
    }

    return 0;
}

static int on_ack_streams_blocked(quicly_sentmap_t *map, const quicly_sent_packet_t *packet, int acked, quicly_sent_t *sent)
{
    quicly_conn_t *conn = (quicly_conn_t *)((char *)map - offsetof(quicly_conn_t, egress.loss.sentmap));
    struct st_quicly_max_streams_t *m =
        sent->data.streams_blocked.uni ? &conn->egress.max_streams.uni : &conn->egress.max_streams.bidi;

    if (acked) {
        quicly_maxsender_acked(&m->blocked_sender, &sent->data.streams_blocked.args);
    } else {
        quicly_maxsender_lost(&m->blocked_sender, &sent->data.streams_blocked.args);
    }

    return 0;
}

static int on_ack_handshake_done(quicly_sentmap_t *map, const quicly_sent_packet_t *packet, int acked, quicly_sent_t *sent)
{
    quicly_conn_t *conn = (quicly_conn_t *)((char *)map - offsetof(quicly_conn_t, egress.loss.sentmap));

    /* When lost, reschedule for transmission. When acked, suppress retransmission if scheduled. */
    if (acked) {
        conn->egress.pending_flows &= ~QUICLY_PENDING_FLOW_HANDSHAKE_DONE_BIT;
    } else {
        conn->egress.pending_flows |= QUICLY_PENDING_FLOW_HANDSHAKE_DONE_BIT;
    }
    return 0;
}

static int on_ack_data_blocked(quicly_sentmap_t *map, const quicly_sent_packet_t *packet, int acked, quicly_sent_t *sent)
{
    quicly_conn_t *conn = (quicly_conn_t *)((char *)map - offsetof(quicly_conn_t, egress.loss.sentmap));

    if (conn->egress.max_data.permitted == sent->data.data_blocked.offset) {
        if (acked) {
            conn->egress.data_blocked = QUICLY_SENDER_STATE_ACKED;
        } else if (packet->frames_in_flight && conn->egress.data_blocked == QUICLY_SENDER_STATE_UNACKED) {
            conn->egress.data_blocked = QUICLY_SENDER_STATE_SEND;
        }
    }

    return 0;
}

static int on_ack_stream_data_blocked_frame(quicly_sentmap_t *map, const quicly_sent_packet_t *packet, int acked,
                                            quicly_sent_t *sent)
{
    quicly_conn_t *conn = (quicly_conn_t *)((char *)map - offsetof(quicly_conn_t, egress.loss.sentmap));
    quicly_stream_t *stream;

    if ((stream = quicly_get_stream(conn, sent->data.stream_data_blocked.stream_id)) == NULL)
        return 0;

    if (stream->_send_aux.max_stream_data == sent->data.stream_data_blocked.offset) {
        if (acked) {
            stream->_send_aux.blocked = QUICLY_SENDER_STATE_ACKED;
        } else if (packet->frames_in_flight && stream->_send_aux.blocked == QUICLY_SENDER_STATE_UNACKED) {
            stream->_send_aux.blocked = QUICLY_SENDER_STATE_SEND;
            sched_stream_control(stream);
        }
    }

    return 0;
}

static int on_ack_new_token(quicly_sentmap_t *map, const quicly_sent_packet_t *packet, int acked, quicly_sent_t *sent)
{
    quicly_conn_t *conn = (quicly_conn_t *)((char *)map - offsetof(quicly_conn_t, egress.loss.sentmap));

    if (sent->data.new_token.is_inflight) {
        --conn->egress.new_token.num_inflight;
        sent->data.new_token.is_inflight = 0;
    }
    if (acked) {
        QUICLY_PROBE(NEW_TOKEN_ACKED, conn, conn->stash.now, sent->data.new_token.generation);
        if (conn->egress.new_token.max_acked < sent->data.new_token.generation)
            conn->egress.new_token.max_acked = sent->data.new_token.generation;
    }

    if (conn->egress.new_token.num_inflight == 0 && conn->egress.new_token.max_acked < conn->egress.new_token.generation)
        conn->egress.pending_flows |= QUICLY_PENDING_FLOW_NEW_TOKEN_BIT;

    return 0;
}

static int on_ack_new_connection_id(quicly_sentmap_t *map, const quicly_sent_packet_t *packet, int acked, quicly_sent_t *sent)
{
    quicly_conn_t *conn = (quicly_conn_t *)((char *)map - offsetof(quicly_conn_t, egress.loss.sentmap));
    uint64_t sequence = sent->data.new_connection_id.sequence;

    if (acked) {
        quicly_local_cid_on_acked(&conn->super.local.cid_set, sequence);
    } else {
        if (quicly_local_cid_on_lost(&conn->super.local.cid_set, sequence))
            conn->egress.pending_flows |= QUICLY_PENDING_FLOW_CID_FRAME_BIT;
    }

    return 0;
}

static int on_ack_retire_connection_id(quicly_sentmap_t *map, const quicly_sent_packet_t *packet, int acked, quicly_sent_t *sent)
{
    quicly_conn_t *conn = (quicly_conn_t *)((char *)map - offsetof(quicly_conn_t, egress.loss.sentmap));
    uint64_t sequence = sent->data.retire_connection_id.sequence;

    if (!acked)
        schedule_retire_connection_id_frame(conn, sequence);

    return 0;
}

static int should_send_datagram_frame(quicly_conn_t *conn)
{
    if (conn->egress.datagram_frame_payload.base == NULL)
        return 0;
    if (conn->application == NULL)
        return 0;
    if (conn->application->cipher.egress.key.aead == NULL)
        return 0;
    if (conn->super.remote.transport_params.max_datagram_frame_size < conn->egress.datagram_frame_payload.len)
        return 0;
    return 1;
}

static inline uint64_t calc_amplification_limit_allowance(quicly_conn_t *conn)
{
    if (conn->super.remote.address_validation.validated)
        return UINT64_MAX;
    uint64_t budget = conn->super.stats.num_bytes.received * conn->super.ctx->pre_validation_amplification_limit;
    if (budget <= conn->super.stats.num_bytes.sent)
        return 0;
    return budget - conn->super.stats.num_bytes.sent;
}

/* Helper function to compute send window based on:
 * * state of peer validation,
 * * current cwnd,
 * * minimum send requirements in |min_bytes_to_send|, and
 * * if sending is to be restricted to the minimum, indicated in |restrict_sending|
 */
static size_t calc_send_window(quicly_conn_t *conn, size_t min_bytes_to_send, uint64_t amp_window, int restrict_sending)
{
    uint64_t window = 0;
    if (restrict_sending) {
        /* Send min_bytes_to_send on PTO */
        window = min_bytes_to_send;
    } else {
        /* Limit to cwnd */
        if (conn->egress.cc.cwnd > conn->egress.loss.sentmap.bytes_in_flight)
            window = conn->egress.cc.cwnd - conn->egress.loss.sentmap.bytes_in_flight;
        /* Allow at least one packet on time-threshold loss detection */
        window = window > min_bytes_to_send ? window : min_bytes_to_send;
    }
    /* Cap the window by the amount allowed by address validation */
    if (amp_window < window)
        window = amp_window;

    return window;
}

/**
 * Checks if the server is waiting for ClientFinished. When that is the case, the loss timer is disactivated, to avoid repeatedly
 * sending 1-RTT packets while the client spends time verifying the certificate chain at the same time buffering 1-RTT packets.
 */
static int is_point5rtt_with_no_handshake_data_to_send(quicly_conn_t *conn)
{
    /* bail out unless this is a server-side connection waiting for ClientFinished */
    if (!(conn->handshake != NULL && conn->application != NULL && !quicly_is_client(conn)))
        return 0;
    quicly_stream_t *stream = quicly_get_stream(conn, (quicly_stream_id_t)-1 - QUICLY_EPOCH_HANDSHAKE);
    assert(stream != NULL);
    return stream->sendstate.pending.num_ranges == 0 && stream->sendstate.acked.ranges[0].end == stream->sendstate.size_inflight;
}

int64_t quicly_get_first_timeout(quicly_conn_t *conn)
{
    if (conn->super.state >= QUICLY_STATE_CLOSING)
        return conn->egress.send_ack_at;

    if (should_send_datagram_frame(conn))
        return 0;

    uint64_t amp_window = calc_amplification_limit_allowance(conn);

    if (calc_send_window(conn, 0, amp_window, 0) > 0) {
        if (conn->egress.pending_flows != 0)
            return 0;
        if (quicly_linklist_is_linked(&conn->egress.pending_streams.control))
            return 0;
        if (scheduler_can_send(conn))
            return 0;
    }

    /* if something can be sent, return the earliest timeout. Otherwise return the idle timeout. */
    int64_t at = conn->idle_timeout.at;
    if (amp_window > 0) {
        if (conn->egress.loss.alarm_at < at && !is_point5rtt_with_no_handshake_data_to_send(conn))
            at = conn->egress.loss.alarm_at;
        if (conn->egress.send_ack_at < at)
            at = conn->egress.send_ack_at;
    }

    return at;
}

uint64_t quicly_get_next_expected_packet_number(quicly_conn_t *conn)
{
    if (!conn->application)
        return UINT64_MAX;

    return conn->application->super.next_expected_packet_number;
}

/**
 * data structure that is used during one call through quicly_send()
 */
struct st_quicly_send_context_t {
    /**
     * current encryption context
     */
    struct {
        struct st_quicly_cipher_context_t *cipher;
        uint8_t first_byte;
    } current;
    /**
     * packet under construction
     */
    struct {
        struct st_quicly_cipher_context_t *cipher;
        /**
         * points to the first byte of the target QUIC packet. It will not point to packet->octets.base[0] when the datagram
         * contains multiple QUIC packet.
         */
        uint8_t *first_byte_at;
        uint8_t ack_eliciting : 1;
    } target;
    /**
     * output buffer into which list of datagrams is written
     */
    struct iovec *datagrams;
    /**
     * max number of datagrams that can be stored in |packets|
     */
    size_t max_datagrams;
    /**
     * number of datagrams currently stored in |packets|
     */
    size_t num_datagrams;
    /**
     * buffer in which packets are built
     */
    struct {
        /**
         * starting position of the current (or next) datagram
         */
        uint8_t *datagram;
        /**
         * end position of the payload buffer
         */
        uint8_t *end;
    } payload_buf;
    /**
     * the currently available window for sending (in bytes)
     */
    ssize_t send_window;
    /**
     * location where next frame should be written
     */
    uint8_t *dst;
    /**
     * end of the payload area, beyond which frames cannot be written
     */
    uint8_t *dst_end;
    /**
     * address at which payload starts
     */
    uint8_t *dst_payload_from;
};

enum en_quicly_send_packet_mode_t {
    QUICLY_COMMIT_SEND_PACKET_MODE_FULL_SIZE,
    QUICLY_COMMIT_SEND_PACKET_MODE_SMALL,
    QUICLY_COMMIT_SEND_PACKET_MODE_COALESCED,
};

static int commit_send_packet(quicly_conn_t *conn, quicly_send_context_t *s, enum en_quicly_send_packet_mode_t mode)
{
    size_t datagram_size, packet_bytes_in_flight;

    assert(s->target.cipher->aead != NULL);

    assert(s->dst != s->dst_payload_from);

    /* pad so that the pn + payload would be at least 4 bytes */
    while (s->dst - s->dst_payload_from < QUICLY_MAX_PN_SIZE - QUICLY_SEND_PN_SIZE)
        *s->dst++ = QUICLY_FRAME_TYPE_PADDING;

    if (mode == QUICLY_COMMIT_SEND_PACKET_MODE_FULL_SIZE) {
        assert(s->num_datagrams == 0 || s->datagrams[s->num_datagrams - 1].iov_len == conn->egress.max_udp_payload_size);
        const size_t max_size = conn->egress.max_udp_payload_size - QUICLY_AEAD_TAG_SIZE;
        assert(s->dst - s->payload_buf.datagram <= max_size);
        memset(s->dst, QUICLY_FRAME_TYPE_PADDING, s->payload_buf.datagram + max_size - s->dst);
        s->dst = s->payload_buf.datagram + max_size;
    }

    /* encode packet size, packet number, key-phase */
    if (QUICLY_PACKET_IS_LONG_HEADER(*s->target.first_byte_at)) {
        uint16_t length = s->dst - s->dst_payload_from + s->target.cipher->aead->algo->tag_size + QUICLY_SEND_PN_SIZE;
        /* length is always 2 bytes, see _do_prepare_packet */
        length |= 0x4000;
        quicly_encode16(s->dst_payload_from - QUICLY_SEND_PN_SIZE - 2, length);
    } else {
        if (conn->egress.packet_number >= conn->application->cipher.egress.key_update_pn.next) {
            int ret;
            if ((ret = update_1rtt_egress_key(conn)) != 0)
                return ret;
        }
        if ((conn->application->cipher.egress.key_phase & 1) != 0)
            *s->target.first_byte_at |= QUICLY_KEY_PHASE_BIT;
    }
    quicly_encode16(s->dst_payload_from - QUICLY_SEND_PN_SIZE, (uint16_t)conn->egress.packet_number);

    /* encrypt the packet */
    s->dst += s->target.cipher->aead->algo->tag_size;
    datagram_size = s->dst - s->payload_buf.datagram;
    assert(datagram_size <= conn->egress.max_udp_payload_size);

    conn->super.ctx->crypto_engine->encrypt_packet(conn->super.ctx->crypto_engine, conn, s->target.cipher->header_protection,
                                                   s->target.cipher->aead, ptls_iovec_init(s->payload_buf.datagram, datagram_size),
                                                   s->target.first_byte_at - s->payload_buf.datagram,
                                                   s->dst_payload_from - s->payload_buf.datagram, conn->egress.packet_number,
                                                   mode == QUICLY_COMMIT_SEND_PACKET_MODE_COALESCED);

    /* update CC, commit sentmap */
    if (s->target.ack_eliciting) {
        packet_bytes_in_flight = s->dst - s->target.first_byte_at;
        s->send_window -= packet_bytes_in_flight;
    } else {
        packet_bytes_in_flight = 0;
    }
    if (quicly_sentmap_is_open(&conn->egress.loss.sentmap))
        quicly_sentmap_commit(&conn->egress.loss.sentmap, (uint16_t)packet_bytes_in_flight);

    conn->egress.cc.impl->cc_on_sent(&conn->egress.cc, &conn->egress.loss, (uint32_t)packet_bytes_in_flight, conn->stash.now);
    QUICLY_PROBE(PACKET_SENT, conn, conn->stash.now, conn->egress.packet_number, s->dst - s->target.first_byte_at,
                 get_epoch(*s->target.first_byte_at), !s->target.ack_eliciting);

    ++conn->egress.packet_number;
    ++conn->super.stats.num_packets.sent;

    if (mode != QUICLY_COMMIT_SEND_PACKET_MODE_COALESCED) {
        conn->super.stats.num_bytes.sent += datagram_size;
        s->datagrams[s->num_datagrams++] = (struct iovec){.iov_base = s->payload_buf.datagram, .iov_len = datagram_size};
        s->payload_buf.datagram += datagram_size;
        s->target.cipher = NULL;
        s->target.first_byte_at = NULL;
    }

    /* insert PN gap if necessary, registering the PN to the ack queue so that we'd close the connection in the event of receiving
     * an ACK for that gap. */
    if (conn->egress.packet_number >= conn->egress.next_pn_to_skip && !QUICLY_PACKET_IS_LONG_HEADER(s->current.first_byte) &&
        conn->super.state < QUICLY_STATE_CLOSING) {
        int ret;
        if ((ret = quicly_sentmap_prepare(&conn->egress.loss.sentmap, conn->egress.packet_number, conn->stash.now,
                                          QUICLY_EPOCH_1RTT)) != 0)
            return ret;
        if (quicly_sentmap_allocate(&conn->egress.loss.sentmap, on_invalid_ack) == NULL)
            return PTLS_ERROR_NO_MEMORY;
        quicly_sentmap_commit(&conn->egress.loss.sentmap, 0);
        ++conn->egress.packet_number;
        conn->egress.next_pn_to_skip = calc_next_pn_to_skip(conn->super.ctx->tls, conn->egress.packet_number, conn->egress.cc.cwnd,
                                                            conn->egress.max_udp_payload_size);
    }

    return 0;
}

static inline uint8_t *emit_cid(uint8_t *dst, const quicly_cid_t *cid)
{
    if (cid->len != 0) {
        memcpy(dst, cid->cid, cid->len);
        dst += cid->len;
    }
    return dst;
}

static int _do_allocate_frame(quicly_conn_t *conn, quicly_send_context_t *s, size_t min_space, int ack_eliciting)
{
    int coalescible, ret;

    assert((s->current.first_byte & QUICLY_QUIC_BIT) != 0);

    /* allocate and setup the new packet if necessary */
    if (s->dst_end - s->dst < min_space || s->target.first_byte_at == NULL) {
        coalescible = 0;
    } else if (((*s->target.first_byte_at ^ s->current.first_byte) & QUICLY_PACKET_TYPE_BITMASK) != 0) {
        coalescible = QUICLY_PACKET_IS_LONG_HEADER(*s->target.first_byte_at);
    } else if (s->dst_end - s->dst < min_space) {
        coalescible = 0;
    } else {
        /* use the existing packet */
        goto TargetReady;
    }

    /* commit at the same time determining if we will coalesce the packets */
    if (s->target.first_byte_at != NULL) {
        if (coalescible) {
            size_t overhead = 1 /* type */ + conn->super.remote.cid_set.cids[0].cid.len + QUICLY_SEND_PN_SIZE +
                              s->current.cipher->aead->algo->tag_size;
            if (QUICLY_PACKET_IS_LONG_HEADER(s->current.first_byte))
                overhead += 4 /* version */ + 1 /* cidl */ + conn->super.remote.cid_set.cids[0].cid.len +
                            conn->super.local.long_header_src_cid.len +
                            (s->current.first_byte == QUICLY_PACKET_TYPE_INITIAL) /* token_length == 0 */ + 2 /* length */;
            size_t packet_min_space = QUICLY_MAX_PN_SIZE - QUICLY_SEND_PN_SIZE;
            if (packet_min_space < min_space)
                packet_min_space = min_space;
            if (overhead + packet_min_space > s->dst_end - s->dst)
                coalescible = 0;
        }
        /* close out packet under construction */
        if ((ret = commit_send_packet(
                 conn, s, coalescible ? QUICLY_COMMIT_SEND_PACKET_MODE_COALESCED : QUICLY_COMMIT_SEND_PACKET_MODE_FULL_SIZE)) != 0)
            return ret;
    } else {
        coalescible = 0;
    }

    /* allocate packet */
    if (coalescible) {
        s->dst_end += s->target.cipher->aead->algo->tag_size; /* restore the AEAD tag size (tag size can differ bet. epochs) */
        s->target.cipher = s->current.cipher;
    } else {
        if (s->num_datagrams >= s->max_datagrams)
            return QUICLY_ERROR_SENDBUF_FULL;
        if (ack_eliciting && s->send_window == 0)
            return QUICLY_ERROR_SENDBUF_FULL;
        if (s->payload_buf.end - s->payload_buf.datagram < conn->egress.max_udp_payload_size)
            return QUICLY_ERROR_SENDBUF_FULL;
        s->target.cipher = s->current.cipher;
        s->dst = s->payload_buf.datagram;
        s->dst_end = s->dst + conn->egress.max_udp_payload_size;
    }
    s->target.ack_eliciting = 0;

    QUICLY_PROBE(PACKET_PREPARE, conn, conn->stash.now, s->current.first_byte,
                 QUICLY_PROBE_HEXDUMP(conn->super.remote.cid_set.cids[0].cid.cid, conn->super.remote.cid_set.cids[0].cid.len));

    /* emit header */
    s->target.first_byte_at = s->dst;
    *s->dst++ = s->current.first_byte | 0x1 /* pnlen == 2 */;
    if (QUICLY_PACKET_IS_LONG_HEADER(s->current.first_byte)) {
        s->dst = quicly_encode32(s->dst, conn->super.version);
        *s->dst++ = conn->super.remote.cid_set.cids[0].cid.len;
        s->dst = emit_cid(s->dst, &conn->super.remote.cid_set.cids[0].cid);
        *s->dst++ = conn->super.local.long_header_src_cid.len;
        s->dst = emit_cid(s->dst, &conn->super.local.long_header_src_cid);
        /* token */
        if (s->current.first_byte == QUICLY_PACKET_TYPE_INITIAL) {
            s->dst = quicly_encodev(s->dst, conn->token.len);
            assert(s->dst_end - s->dst > conn->token.len);
            memcpy(s->dst, conn->token.base, conn->token.len);
            s->dst += conn->token.len;
        }
        /* payload length is filled laterwards (see commit_send_packet) */
        *s->dst++ = 0;
        *s->dst++ = 0;
    } else {
        s->dst = emit_cid(s->dst, &conn->super.remote.cid_set.cids[0].cid);
    }
    s->dst += QUICLY_SEND_PN_SIZE; /* space for PN bits, filled in at commit time */
    s->dst_payload_from = s->dst;
    assert(s->target.cipher->aead != NULL);
    s->dst_end -= s->target.cipher->aead->algo->tag_size;
    assert(s->dst_end - s->dst >= QUICLY_MAX_PN_SIZE - QUICLY_SEND_PN_SIZE);

    if (conn->super.state < QUICLY_STATE_CLOSING) {
        /* register to sentmap */
        uint8_t ack_epoch = get_epoch(s->current.first_byte);
        if (ack_epoch == QUICLY_EPOCH_0RTT)
            ack_epoch = QUICLY_EPOCH_1RTT;
        if ((ret = quicly_sentmap_prepare(&conn->egress.loss.sentmap, conn->egress.packet_number, conn->stash.now, ack_epoch)) != 0)
            return ret;
        /* adjust ack-frequency */
        if (conn->stash.now >= conn->egress.ack_frequency.update_at) {
            if (conn->egress.packet_number >= QUICLY_FIRST_ACK_FREQUENCY_PACKET_NUMBER && conn->initial == NULL &&
                conn->handshake == NULL) {
                uint32_t fraction_of_cwnd = conn->egress.cc.cwnd / QUICLY_ACK_FREQUENCY_CWND_FRACTION;
                if (fraction_of_cwnd >= conn->egress.max_udp_payload_size * 3) {
                    uint32_t packet_tolerance = fraction_of_cwnd / conn->egress.max_udp_payload_size;
                    if (packet_tolerance > QUICLY_MAX_PACKET_TOLERANCE)
                        packet_tolerance = QUICLY_MAX_PACKET_TOLERANCE;
                    s->dst = quicly_encode_ack_frequency_frame(s->dst, conn->egress.ack_frequency.sequence++, packet_tolerance,
                                                               conn->super.remote.transport_params.max_ack_delay * 1000, 0);
                    ++conn->super.stats.num_frames_sent.ack_frequency;
                }
            }
            ack_frequency_set_next_update_at(conn);
        }
    }

TargetReady:
    if (ack_eliciting) {
        s->target.ack_eliciting = 1;
        conn->egress.last_retransmittable_sent_at = conn->stash.now;
    }
    return 0;
}

static int allocate_frame(quicly_conn_t *conn, quicly_send_context_t *s, size_t min_space)
{
    return _do_allocate_frame(conn, s, min_space, 0);
}

static int allocate_ack_eliciting_frame(quicly_conn_t *conn, quicly_send_context_t *s, size_t min_space, quicly_sent_t **sent,
                                        quicly_sent_acked_cb acked)
{
    int ret;

    if ((ret = _do_allocate_frame(conn, s, min_space, 1)) != 0)
        return ret;
    if ((*sent = quicly_sentmap_allocate(&conn->egress.loss.sentmap, acked)) == NULL)
        return PTLS_ERROR_NO_MEMORY;

    return ret;
}

static int send_ack(quicly_conn_t *conn, struct st_quicly_pn_space_t *space, quicly_send_context_t *s)
{
    uint64_t ack_delay;
    int ret;

    if (space->ack_queue.num_ranges == 0)
        return 0;

    /* calc ack_delay */
    if (space->largest_pn_received_at < conn->stash.now) {
        /* We underreport ack_delay up to 1 milliseconds assuming that QUICLY_LOCAL_ACK_DELAY_EXPONENT is 10. It's considered a
         * non-issue because our time measurement is at millisecond granurality anyways. */
        ack_delay = ((conn->stash.now - space->largest_pn_received_at) * 1000) >> QUICLY_LOCAL_ACK_DELAY_EXPONENT;
    } else {
        ack_delay = 0;
    }

Emit: /* emit an ACK frame */
    if ((ret = allocate_frame(conn, s, QUICLY_ACK_FRAME_CAPACITY)) != 0)
        return ret;
    uint8_t *dst = s->dst;
    dst = quicly_encode_ack_frame(dst, s->dst_end, &space->ack_queue, ack_delay);

    /* when there's no space, retry with a new MTU-sized packet */
    if (dst == NULL) {
        /* [rare case] A coalesced packet might not have enough space to hold only an ACK. If so, pad it, as that's easier than
         * rolling back. */
        if (s->dst == s->dst_payload_from) {
            assert(s->target.first_byte_at != s->payload_buf.datagram);
            *s->dst++ = QUICLY_FRAME_TYPE_PADDING;
        }
        if ((ret = commit_send_packet(conn, s, QUICLY_COMMIT_SEND_PACKET_MODE_FULL_SIZE)) != 0)
            return ret;
        goto Emit;
    }

    ++conn->super.stats.num_frames_sent.ack;
    QUICLY_PROBE(ACK_SEND, conn, conn->stash.now, space->ack_queue.ranges[space->ack_queue.num_ranges - 1].end - 1, ack_delay);

    /* when there are no less than QUICLY_NUM_ACK_BLOCKS_TO_INDUCE_ACKACK (8) gaps, bundle PING once every 4 packets being sent */
    if (space->ack_queue.num_ranges >= QUICLY_NUM_ACK_BLOCKS_TO_INDUCE_ACKACK && conn->egress.packet_number % 4 == 0 &&
        dst < s->dst_end) {
        *dst++ = QUICLY_FRAME_TYPE_PING;
        ++conn->super.stats.num_frames_sent.ping;
        QUICLY_PROBE(PING_SEND, conn, conn->stash.now);
    }

    s->dst = dst;

    { /* save what's inflight */
        size_t i;
        for (i = 0; i != space->ack_queue.num_ranges; ++i) {
            quicly_sent_t *sent;
            if ((sent = quicly_sentmap_allocate(&conn->egress.loss.sentmap, on_ack_ack)) == NULL)
                return PTLS_ERROR_NO_MEMORY;
            sent->data.ack.range = space->ack_queue.ranges[i];
        }
    }

    space->unacked_count = 0;

    return ret;
}

static int prepare_stream_state_sender(quicly_stream_t *stream, quicly_sender_state_t *sender, quicly_send_context_t *s,
                                       size_t min_space, quicly_sent_acked_cb ack_cb)
{
    quicly_sent_t *sent;
    int ret;

    if ((ret = allocate_ack_eliciting_frame(stream->conn, s, min_space, &sent, ack_cb)) != 0)
        return ret;
    sent->data.stream_state_sender.stream_id = stream->stream_id;
    *sender = QUICLY_SENDER_STATE_UNACKED;

    return 0;
}

static int send_control_frames_of_stream(quicly_stream_t *stream, quicly_send_context_t *s)
{
    int ret;

    /* send STOP_SENDING if necessray */
    if (stream->_send_aux.stop_sending.sender_state == QUICLY_SENDER_STATE_SEND) {
        /* FIXME also send an empty STREAM frame */
        if ((ret = prepare_stream_state_sender(stream, &stream->_send_aux.stop_sending.sender_state, s,
                                               QUICLY_STOP_SENDING_FRAME_CAPACITY, on_ack_stop_sending)) != 0)
            return ret;
        s->dst = quicly_encode_stop_sending_frame(s->dst, stream->stream_id, stream->_send_aux.stop_sending.error_code);
        ++stream->conn->super.stats.num_frames_sent.stop_sending;
    }

    /* send MAX_STREAM_DATA if necessary */
    if (should_send_max_stream_data(stream)) {
        uint64_t new_value = stream->recvstate.data_off + stream->_recv_aux.window;
        quicly_sent_t *sent;
        /* prepare */
        if ((ret = allocate_ack_eliciting_frame(stream->conn, s, QUICLY_MAX_STREAM_DATA_FRAME_CAPACITY, &sent,
                                                on_ack_max_stream_data)) != 0)
            return ret;
        /* send */
        s->dst = quicly_encode_max_stream_data_frame(s->dst, stream->stream_id, new_value);
        /* register ack */
        sent->data.max_stream_data.stream_id = stream->stream_id;
        quicly_maxsender_record(&stream->_send_aux.max_stream_data_sender, new_value, &sent->data.max_stream_data.args);
        /* update stats */
        ++stream->conn->super.stats.num_frames_sent.max_stream_data;
        QUICLY_PROBE(MAX_STREAM_DATA_SEND, stream->conn, stream->conn->stash.now, stream, new_value);
    }

    /* send RESET_STREAM if necessary */
    if (stream->_send_aux.reset_stream.sender_state == QUICLY_SENDER_STATE_SEND) {
        if ((ret = prepare_stream_state_sender(stream, &stream->_send_aux.reset_stream.sender_state, s, QUICLY_RST_FRAME_CAPACITY,
                                               on_ack_reset_stream)) != 0)
            return ret;
        s->dst = quicly_encode_reset_stream_frame(s->dst, stream->stream_id, stream->_send_aux.reset_stream.error_code,
                                                  stream->sendstate.size_inflight);
        ++stream->conn->super.stats.num_frames_sent.reset_stream;
    }

    /* send STREAM_DATA_BLOCKED if necessary */
    if (stream->_send_aux.blocked == QUICLY_SENDER_STATE_SEND) {
        quicly_sent_t *sent;
        if ((ret = allocate_ack_eliciting_frame(stream->conn, s, QUICLY_STREAM_DATA_BLOCKED_FRAME_CAPACITY, &sent,
                                                on_ack_stream_data_blocked_frame)) != 0)
            return ret;
        uint64_t offset = stream->_send_aux.max_stream_data;
        sent->data.stream_data_blocked.stream_id = stream->stream_id;
        sent->data.stream_data_blocked.offset = offset;
        s->dst = quicly_encode_stream_data_blocked_frame(s->dst, stream->stream_id, offset);
        stream->_send_aux.blocked = QUICLY_SENDER_STATE_UNACKED;
        ++stream->conn->super.stats.num_frames_sent.stream_data_blocked;
        QUICLY_PROBE(STREAM_DATA_BLOCKED_SEND, stream->conn, stream->conn->stash.now, stream->stream_id, offset);
    }

    return 0;
}

static int send_stream_control_frames(quicly_conn_t *conn, quicly_send_context_t *s)
{
    int ret = 0;

    while (s->num_datagrams != s->max_datagrams && quicly_linklist_is_linked(&conn->egress.pending_streams.control)) {
        quicly_stream_t *stream =
            (void *)((char *)conn->egress.pending_streams.control.next - offsetof(quicly_stream_t, _send_aux.pending_link.control));
        if ((ret = send_control_frames_of_stream(stream, s)) != 0)
            goto Exit;
        quicly_linklist_unlink(&stream->_send_aux.pending_link.control);
    }

Exit:
    return ret;
}

int quicly_is_blocked(quicly_conn_t *conn)
{
    if (conn->egress.max_data.sent < conn->egress.max_data.permitted)
        return 0;

    /* schedule the transmission of DATA_BLOCKED frame, if it's new information */
    if (conn->egress.data_blocked == QUICLY_SENDER_STATE_NONE)
        conn->egress.data_blocked = QUICLY_SENDER_STATE_SEND;

    return 1;
}

int quicly_stream_can_send(quicly_stream_t *stream, int at_stream_level)
{
    /* return if there is nothing to be sent */
    if (stream->sendstate.pending.num_ranges == 0)
        return 0;

    /* return if flow is capped neither by MAX_STREAM_DATA nor (in case we are hitting connection-level flow control) by the number
     * of bytes we've already sent */
    uint64_t blocked_at = at_stream_level ? stream->_send_aux.max_stream_data : stream->sendstate.size_inflight;
    if (stream->sendstate.pending.ranges[0].start < blocked_at)
        return 1;
    /* we can always send EOS, if that is the only thing to be sent */
    if (stream->sendstate.pending.ranges[0].start >= stream->sendstate.final_size) {
        assert(stream->sendstate.pending.ranges[0].start == stream->sendstate.final_size);
        return 1;
    }

    /* if known to be blocked at stream-level, schedule the emission of STREAM_DATA_BLOCKED frame */
    if (at_stream_level && stream->_send_aux.blocked == QUICLY_SENDER_STATE_NONE) {
        stream->_send_aux.blocked = QUICLY_SENDER_STATE_SEND;
        sched_stream_control(stream);
    }

    return 0;
}

int quicly_can_send_data(quicly_conn_t *conn, quicly_send_context_t *s)
{
    return s->num_datagrams < s->max_datagrams;
}

int quicly_send_stream(quicly_stream_t *stream, quicly_send_context_t *s)
{
    uint64_t off = stream->sendstate.pending.ranges[0].start, end_off;
    quicly_sent_t *sent;
    uint8_t *frame_type_at;
    size_t capacity, len;
    int ret, wrote_all, is_fin;

    /* write frame type, stream_id and offset, calculate capacity */
    if (stream->stream_id < 0) {
        if ((ret = allocate_ack_eliciting_frame(stream->conn, s,
                                                1 + quicly_encodev_capacity(off) + 2 /* type + len + offset + 1-byte payload */,
                                                &sent, on_ack_stream)) != 0)
            return ret;
        frame_type_at = NULL;
        *s->dst++ = QUICLY_FRAME_TYPE_CRYPTO;
        s->dst = quicly_encodev(s->dst, off);
        capacity = s->dst_end - s->dst;
    } else {
        uint8_t header[18], *hp = header + 1;
        hp = quicly_encodev(hp, stream->stream_id);
        if (off != 0) {
            header[0] = QUICLY_FRAME_TYPE_STREAM_BASE | QUICLY_FRAME_TYPE_STREAM_BIT_OFF;
            hp = quicly_encodev(hp, off);
        } else {
            header[0] = QUICLY_FRAME_TYPE_STREAM_BASE;
        }
        if (!quicly_sendstate_is_open(&stream->sendstate) && off == stream->sendstate.final_size) {
            /* special case for emitting FIN only */
            header[0] |= QUICLY_FRAME_TYPE_STREAM_BIT_FIN;
            if ((ret = allocate_ack_eliciting_frame(stream->conn, s, hp - header, &sent, on_ack_stream)) != 0)
                return ret;
            if (hp - header != s->dst_end - s->dst) {
                header[0] |= QUICLY_FRAME_TYPE_STREAM_BIT_LEN;
                *hp++ = 0; /* empty length */
            }
            memcpy(s->dst, header, hp - header);
            s->dst += hp - header;
            end_off = off;
            wrote_all = 1;
            is_fin = 1;
            goto UpdateState;
        }
        if ((ret = allocate_ack_eliciting_frame(stream->conn, s, hp - header + 1, &sent, on_ack_stream)) != 0)
            return ret;
        frame_type_at = s->dst;
        memcpy(s->dst, header, hp - header);
        s->dst += hp - header;
        capacity = s->dst_end - s->dst;
        /* cap by max_stream_data */
        if (off + capacity > stream->_send_aux.max_stream_data)
            capacity = stream->_send_aux.max_stream_data - off;
        /* cap by max_data */
        if (off + capacity > stream->sendstate.size_inflight) {
            uint64_t new_bytes = off + capacity - stream->sendstate.size_inflight;
            if (new_bytes > stream->conn->egress.max_data.permitted - stream->conn->egress.max_data.sent) {
                size_t max_stream_data =
                    stream->sendstate.size_inflight + stream->conn->egress.max_data.permitted - stream->conn->egress.max_data.sent;
                capacity = max_stream_data - off;
            }
        }
    }
    { /* cap the capacity to the current range */
        uint64_t range_capacity = stream->sendstate.pending.ranges[0].end - off;
        if (!quicly_sendstate_is_open(&stream->sendstate) && off + range_capacity > stream->sendstate.final_size) {
            assert(range_capacity > 1); /* see the special case above */
            range_capacity -= 1;
        }
        if (capacity > range_capacity)
            capacity = range_capacity;
    }

    /* write payload */
    assert(capacity != 0);
    len = capacity;
    size_t emit_off = (size_t)(off - stream->sendstate.acked.ranges[0].end);
    QUICLY_PROBE(STREAM_ON_SEND_EMIT, stream->conn, stream->conn->stash.now, stream, emit_off, len);
    stream->callbacks->on_send_emit(stream, emit_off, s->dst, &len, &wrote_all);
    if (stream->conn->super.state >= QUICLY_STATE_CLOSING) {
        return QUICLY_ERROR_IS_CLOSING;
    } else if (stream->_send_aux.reset_stream.sender_state != QUICLY_SENDER_STATE_NONE) {
        return 0;
    }
    assert(len <= capacity);
    assert(len != 0);

    /* update s->dst, insert length if necessary */
    if (frame_type_at == NULL || len < s->dst_end - s->dst) {
        if (frame_type_at != NULL)
            *frame_type_at |= QUICLY_FRAME_TYPE_STREAM_BIT_LEN;
        size_t len_of_len = quicly_encodev_capacity(len);
        if (len_of_len + len > s->dst_end - s->dst) {
            len = s->dst_end - s->dst - len_of_len;
            wrote_all = 0;
        }
        memmove(s->dst + len_of_len, s->dst, len);
        s->dst = quicly_encodev(s->dst, len);
    }
    s->dst += len;
    end_off = off + len;

    /* determine if the frame incorporates FIN */
    if (!quicly_sendstate_is_open(&stream->sendstate) && end_off == stream->sendstate.final_size) {
        assert(frame_type_at != NULL);
        is_fin = 1;
        *frame_type_at |= QUICLY_FRAME_TYPE_STREAM_BIT_FIN;
    } else {
        is_fin = 0;
    }

UpdateState:
    if (stream->stream_id < 0) {
        ++stream->conn->super.stats.num_frames_sent.crypto;
    } else {
        ++stream->conn->super.stats.num_frames_sent.stream;
    }
    QUICLY_PROBE(STREAM_SEND, stream->conn, stream->conn->stash.now, stream, off, end_off - off, is_fin);
    QUICLY_PROBE(QUICTRACE_SEND_STREAM, stream->conn, stream->conn->stash.now, stream, off, end_off - off, is_fin);
    /* update sendstate (and also MAX_DATA counter) */
    if (stream->sendstate.size_inflight < end_off) {
        if (stream->stream_id >= 0)
            stream->conn->egress.max_data.sent += end_off - stream->sendstate.size_inflight;
        stream->sendstate.size_inflight = end_off;
    }
    if ((ret = quicly_ranges_subtract(&stream->sendstate.pending, off, end_off + is_fin)) != 0)
        return ret;
    if (wrote_all) {
        if ((ret = quicly_ranges_subtract(&stream->sendstate.pending, stream->sendstate.size_inflight, UINT64_MAX)) != 0)
            return ret;
    }

    /* setup sentmap */
    sent->data.stream.stream_id = stream->stream_id;
    sent->data.stream.args.start = off;
    sent->data.stream.args.end = end_off + is_fin;

    return 0;
}

static inline void init_acks_iter(quicly_conn_t *conn, quicly_sentmap_iter_t *iter)
{
    quicly_loss_init_sentmap_iter(&conn->egress.loss, iter, conn->stash.now, conn->super.remote.transport_params.max_ack_delay,
                                  conn->super.state >= QUICLY_STATE_CLOSING);
}

int discard_sentmap_by_epoch(quicly_conn_t *conn, unsigned ack_epochs)
{
    quicly_sentmap_iter_t iter;
    const quicly_sent_packet_t *sent;
    int ret = 0;

    init_acks_iter(conn, &iter);

    while ((sent = quicly_sentmap_get(&iter))->packet_number != UINT64_MAX) {
        if ((ack_epochs & (1u << sent->ack_epoch)) != 0) {
            if ((ret = quicly_sentmap_update(&conn->egress.loss.sentmap, &iter, QUICLY_SENTMAP_EVENT_EXPIRED)) != 0)
                return ret;
        } else {
            quicly_sentmap_skip(&iter);
        }
    }

    return ret;
}

/**
 * Mark frames of given epoch as pending, until `*bytes_to_mark` becomes zero.
 */
static int mark_frames_on_pto(quicly_conn_t *conn, uint8_t ack_epoch, size_t *bytes_to_mark)
{
    quicly_sentmap_iter_t iter;
    const quicly_sent_packet_t *sent;
    int ret;

    init_acks_iter(conn, &iter);

    while ((sent = quicly_sentmap_get(&iter))->packet_number != UINT64_MAX) {
        if (sent->ack_epoch == ack_epoch && sent->frames_in_flight) {
            *bytes_to_mark = *bytes_to_mark > sent->cc_bytes_in_flight ? *bytes_to_mark - sent->cc_bytes_in_flight : 0;
            if ((ret = quicly_sentmap_update(&conn->egress.loss.sentmap, &iter, QUICLY_SENTMAP_EVENT_PTO)) != 0)
                return ret;
            assert(!sent->frames_in_flight);
            if (*bytes_to_mark == 0)
                break;
        } else {
            quicly_sentmap_skip(&iter);
        }
    }

    return 0;
}

static void on_loss_detected(quicly_loss_t *loss, const quicly_sent_packet_t *lost_packet, int is_time_threshold)
{
    quicly_conn_t *conn = (void *)((char *)loss - offsetof(quicly_conn_t, egress.loss));

    ++conn->super.stats.num_packets.lost;
    if (is_time_threshold)
        ++conn->super.stats.num_packets.lost_time_threshold;
    conn->egress.cc.impl->cc_on_lost(&conn->egress.cc, &conn->egress.loss, lost_packet->cc_bytes_in_flight,
                                     lost_packet->packet_number, conn->egress.packet_number, conn->stash.now,
                                     conn->egress.max_udp_payload_size);
    QUICLY_PROBE(PACKET_LOST, conn, conn->stash.now, lost_packet->packet_number);
    QUICLY_PROBE(QUICTRACE_LOST, conn, conn->stash.now, lost_packet->packet_number);
    QUICLY_PROBE(CC_CONGESTION, conn, conn->stash.now, lost_packet->packet_number + 1, conn->egress.loss.sentmap.bytes_in_flight,
                 conn->egress.cc.cwnd);
    QUICLY_PROBE(QUICTRACE_CC_LOST, conn, conn->stash.now, &conn->egress.loss.rtt, conn->egress.cc.cwnd,
                 conn->egress.loss.sentmap.bytes_in_flight);
}

static int send_max_streams(quicly_conn_t *conn, int uni, quicly_send_context_t *s)
{
    if (!should_send_max_streams(conn, uni))
        return 0;

    quicly_maxsender_t *maxsender = uni ? &conn->ingress.max_streams.uni : &conn->ingress.max_streams.bidi;
    struct st_quicly_conn_streamgroup_state_t *group = uni ? &conn->super.remote.uni : &conn->super.remote.bidi;
    int ret;

    uint64_t new_count =
        group->next_stream_id / 4 +
        (uni ? conn->super.ctx->transport_params.max_streams_uni : conn->super.ctx->transport_params.max_streams_bidi) -
        group->num_streams;

    quicly_sent_t *sent;
    if ((ret = allocate_ack_eliciting_frame(conn, s, QUICLY_MAX_STREAMS_FRAME_CAPACITY, &sent, on_ack_max_streams)) != 0)
        return ret;
    s->dst = quicly_encode_max_streams_frame(s->dst, uni, new_count);
    sent->data.max_streams.uni = uni;
    quicly_maxsender_record(maxsender, new_count, &sent->data.max_streams.args);

    if (uni) {
        ++conn->super.stats.num_frames_sent.max_streams_uni;
    } else {
        ++conn->super.stats.num_frames_sent.max_streams_bidi;
    }
    QUICLY_PROBE(MAX_STREAMS_SEND, conn, conn->stash.now, new_count, uni);

    return 0;
}

static int send_streams_blocked(quicly_conn_t *conn, int uni, quicly_send_context_t *s)
{
    quicly_linklist_t *blocked_list = uni ? &conn->egress.pending_streams.blocked.uni : &conn->egress.pending_streams.blocked.bidi;
    int ret;

    if (!quicly_linklist_is_linked(blocked_list))
        return 0;

    struct st_quicly_max_streams_t *max_streams = uni ? &conn->egress.max_streams.uni : &conn->egress.max_streams.bidi;
    quicly_stream_t *oldest_blocked_stream =
        (void *)((char *)blocked_list->next - offsetof(quicly_stream_t, _send_aux.pending_link.control));
    assert(max_streams->count == oldest_blocked_stream->stream_id / 4);

    if (!quicly_maxsender_should_send_blocked(&max_streams->blocked_sender, max_streams->count))
        return 0;

    quicly_sent_t *sent;
    if ((ret = allocate_ack_eliciting_frame(conn, s, QUICLY_STREAMS_BLOCKED_FRAME_CAPACITY, &sent, on_ack_streams_blocked)) != 0)
        return ret;
    s->dst = quicly_encode_streams_blocked_frame(s->dst, uni, max_streams->count);
    sent->data.streams_blocked.uni = uni;
    quicly_maxsender_record(&max_streams->blocked_sender, max_streams->count, &sent->data.streams_blocked.args);

    ++conn->super.stats.num_frames_sent.streams_blocked;
    QUICLY_PROBE(STREAMS_BLOCKED_SEND, conn, conn->stash.now, max_streams->count, uni);

    return 0;
}

static void open_blocked_streams(quicly_conn_t *conn, int uni)
{
    uint64_t count;
    quicly_linklist_t *anchor;

    if (uni) {
        count = conn->egress.max_streams.uni.count;
        anchor = &conn->egress.pending_streams.blocked.uni;
    } else {
        count = conn->egress.max_streams.bidi.count;
        anchor = &conn->egress.pending_streams.blocked.bidi;
    }

    while (quicly_linklist_is_linked(anchor)) {
        quicly_stream_t *stream = (void *)((char *)anchor->next - offsetof(quicly_stream_t, _send_aux.pending_link.control));
        if (stream->stream_id / 4 >= count)
            break;
        assert(stream->streams_blocked);
        quicly_linklist_unlink(&stream->_send_aux.pending_link.control);
        stream->streams_blocked = 0;
        stream->_send_aux.max_stream_data = quicly_stream_is_unidirectional(stream->stream_id)
                                                ? conn->super.remote.transport_params.max_stream_data.uni
                                                : conn->super.remote.transport_params.max_stream_data.bidi_remote;
        /* TODO retain separate flags for stream states so that we do not always need to sched for both control and data */
        sched_stream_control(stream);
        resched_stream_data(stream);
    }
}

static int send_handshake_done(quicly_conn_t *conn, quicly_send_context_t *s)
{
    quicly_sent_t *sent;
    int ret;

    if ((ret = allocate_ack_eliciting_frame(conn, s, 1, &sent, on_ack_handshake_done)) != 0)
        goto Exit;
    *s->dst++ = QUICLY_FRAME_TYPE_HANDSHAKE_DONE;
    conn->egress.pending_flows &= ~QUICLY_PENDING_FLOW_HANDSHAKE_DONE_BIT;
    ++conn->super.stats.num_frames_sent.handshake_done;
    QUICLY_PROBE(HANDSHAKE_DONE_SEND, conn, conn->stash.now);

    ret = 0;
Exit:
    return ret;
}

static int send_data_blocked(quicly_conn_t *conn, quicly_send_context_t *s)
{
    quicly_sent_t *sent;
    int ret;

    uint64_t offset = conn->egress.max_data.permitted;
    if ((ret = allocate_ack_eliciting_frame(conn, s, QUICLY_DATA_BLOCKED_FRAME_CAPACITY, &sent, on_ack_data_blocked)) != 0)
        goto Exit;
    sent->data.data_blocked.offset = offset;
    s->dst = quicly_encode_data_blocked_frame(s->dst, offset);
    conn->egress.data_blocked = QUICLY_SENDER_STATE_UNACKED;

    ++conn->super.stats.num_frames_sent.data_blocked;
    QUICLY_PROBE(DATA_BLOCKED_SEND, conn, conn->stash.now, offset);

    ret = 0;
Exit:
    return ret;
}

static int send_resumption_token(quicly_conn_t *conn, quicly_send_context_t *s)
{
    quicly_address_token_plaintext_t token;
    ptls_buffer_t tokenbuf;
    uint8_t tokenbuf_small[128];
    quicly_sent_t *sent;
    int ret;

    ptls_buffer_init(&tokenbuf, tokenbuf_small, sizeof(tokenbuf_small));

    /* build token */
    token =
        (quicly_address_token_plaintext_t){QUICLY_ADDRESS_TOKEN_TYPE_RESUMPTION, conn->super.ctx->now->cb(conn->super.ctx->now)};
    token.remote = conn->super.remote.address;
    /* TODO fill token.resumption */

    /* encrypt */
    if ((ret = conn->super.ctx->generate_resumption_token->cb(conn->super.ctx->generate_resumption_token, conn, &tokenbuf,
                                                              &token)) != 0)
        goto Exit;
    assert(tokenbuf.off < QUICLY_MIN_CLIENT_INITIAL_SIZE / 2 && "this is a ballpark figure, but tokens ought to be small");

    /* emit frame */
    if ((ret = allocate_ack_eliciting_frame(conn, s, quicly_new_token_frame_capacity(ptls_iovec_init(tokenbuf.base, tokenbuf.off)),
                                            &sent, on_ack_new_token)) != 0)
        goto Exit;
    sent->data.new_token.generation = conn->egress.new_token.generation;
    s->dst = quicly_encode_new_token_frame(s->dst, ptls_iovec_init(tokenbuf.base, tokenbuf.off));
    conn->egress.pending_flows &= ~QUICLY_PENDING_FLOW_NEW_TOKEN_BIT;

    ++conn->super.stats.num_frames_sent.new_token;
    QUICLY_PROBE(NEW_TOKEN_SEND, conn, conn->stash.now, tokenbuf.base, tokenbuf.off, sent->data.new_token.generation);
    ret = 0;
Exit:
    ptls_buffer_dispose(&tokenbuf);
    return ret;
}

size_t quicly_send_version_negotiation(quicly_context_t *ctx, ptls_iovec_t dest_cid, ptls_iovec_t src_cid, const uint32_t *versions,
                                       void *payload)
{
    uint8_t *dst = payload;

    /* type_flags */
    ctx->tls->random_bytes(dst, 1);
    *dst |= QUICLY_LONG_HEADER_BIT;
    ++dst;
    /* version */
    dst = quicly_encode32(dst, 0);
    /* connection-id */
    *dst++ = dest_cid.len;
    if (dest_cid.len != 0) {
        memcpy(dst, dest_cid.base, dest_cid.len);
        dst += dest_cid.len;
    }
    *dst++ = src_cid.len;
    if (src_cid.len != 0) {
        memcpy(dst, src_cid.base, src_cid.len);
        dst += src_cid.len;
    }
    /* supported_versions */
    for (const uint32_t *v = versions; *v != 0; ++v)
        dst = quicly_encode32(dst, *v);
    /* add a greasing version. This also covers the case where an empty list is specified by the caller to indicate rejection. */
    uint32_t grease_version = 0;
    if (src_cid.len >= sizeof(grease_version))
        memcpy(&grease_version, src_cid.base, sizeof(grease_version));
    grease_version = (grease_version & 0xf0f0f0f0) | 0x0a0a0a0a;
    dst = quicly_encode32(dst, grease_version);

    return dst - (uint8_t *)payload;
}

int quicly_retry_calc_cidpair_hash(ptls_hash_algorithm_t *sha256, ptls_iovec_t client_cid, ptls_iovec_t server_cid, uint64_t *value)
{
    uint8_t digest[PTLS_SHA256_DIGEST_SIZE], buf[(QUICLY_MAX_CID_LEN_V1 + 1) * 2], *p = buf;
    int ret;

    *p++ = (uint8_t)client_cid.len;
    memcpy(p, client_cid.base, client_cid.len);
    p += client_cid.len;
    *p++ = (uint8_t)server_cid.len;
    memcpy(p, server_cid.base, server_cid.len);
    p += server_cid.len;

    if ((ret = ptls_calc_hash(sha256, digest, buf, p - buf)) != 0)
        return ret;
    p = digest;
    *value = quicly_decode64((void *)&p);

    return 0;
}

size_t quicly_send_retry(quicly_context_t *ctx, ptls_aead_context_t *token_encrypt_ctx, uint32_t protocol_version,
                         struct sockaddr *dest_addr, ptls_iovec_t dest_cid, struct sockaddr *src_addr, ptls_iovec_t src_cid,
                         ptls_iovec_t odcid, ptls_iovec_t token_prefix, ptls_iovec_t appdata,
                         ptls_aead_context_t **retry_aead_cache, uint8_t *datagram)
{
    quicly_address_token_plaintext_t token;
    ptls_buffer_t buf;
    int ret;

    assert(!(src_cid.len == odcid.len && memcmp(src_cid.base, odcid.base, src_cid.len) == 0));

    /* build token as plaintext */
    token = (quicly_address_token_plaintext_t){QUICLY_ADDRESS_TOKEN_TYPE_RETRY, ctx->now->cb(ctx->now)};
    set_address(&token.remote, dest_addr);
    set_address(&token.local, src_addr);

    quicly_set_cid(&token.retry.original_dcid, odcid);
    quicly_set_cid(&token.retry.client_cid, dest_cid);
    quicly_set_cid(&token.retry.server_cid, src_cid);
    if (appdata.len != 0) {
        assert(appdata.len <= sizeof(token.appdata.bytes));
        memcpy(token.appdata.bytes, appdata.base, appdata.len);
        token.appdata.len = appdata.len;
    }

    /* start building the packet */
    ptls_buffer_init(&buf, datagram, QUICLY_MIN_CLIENT_INITIAL_SIZE);

    /* first generate a pseudo packet */
    ptls_buffer_push_block(&buf, 1, { ptls_buffer_pushv(&buf, odcid.base, odcid.len); });
    ctx->tls->random_bytes(buf.base + buf.off, 1);
    buf.base[buf.off] = QUICLY_PACKET_TYPE_RETRY | (buf.base[buf.off] & 0x0f);
    ++buf.off;
    ptls_buffer_push32(&buf, protocol_version);
    ptls_buffer_push_block(&buf, 1, { ptls_buffer_pushv(&buf, dest_cid.base, dest_cid.len); });
    ptls_buffer_push_block(&buf, 1, { ptls_buffer_pushv(&buf, src_cid.base, src_cid.len); });
    if (token_prefix.len != 0) {
        assert(token_prefix.len <= buf.capacity - buf.off);
        memcpy(buf.base + buf.off, token_prefix.base, token_prefix.len);
        buf.off += token_prefix.len;
    }
    if ((ret = quicly_encrypt_address_token(ctx->tls->random_bytes, token_encrypt_ctx, &buf, buf.off - token_prefix.len, &token)) !=
        0)
        goto Exit;

    /* append AEAD tag */
    ret = ptls_buffer_reserve(&buf, PTLS_AESGCM_TAG_SIZE);
    assert(ret == 0);
    assert(!buf.is_allocated && "retry packet is too large");
    {
        ptls_aead_context_t *aead =
            retry_aead_cache != NULL && *retry_aead_cache != NULL ? *retry_aead_cache : create_retry_aead(ctx, protocol_version, 1);
        ptls_aead_encrypt(aead, buf.base + buf.off, "", 0, 0, buf.base, buf.off);
        if (retry_aead_cache != NULL) {
            *retry_aead_cache = aead;
        } else {
            ptls_aead_free(aead);
        }
    }
    buf.off += PTLS_AESGCM_TAG_SIZE;

    /* convert the image to a Retry packet, by stripping the ODCID field */
    memmove(buf.base, buf.base + odcid.len + 1, buf.off - (odcid.len + 1));
    buf.off -= odcid.len + 1;

    ret = 0;

Exit:
    return ret == 0 ? buf.off : SIZE_MAX;
}

static struct st_quicly_pn_space_t *setup_send_space(quicly_conn_t *conn, size_t epoch, quicly_send_context_t *s)
{
    struct st_quicly_pn_space_t *space = NULL;

    switch (epoch) {
    case QUICLY_EPOCH_INITIAL:
        if (conn->initial == NULL || (s->current.cipher = &conn->initial->cipher.egress)->aead == NULL)
            return NULL;
        s->current.first_byte = QUICLY_PACKET_TYPE_INITIAL;
        space = &conn->initial->super;
        break;
    case QUICLY_EPOCH_HANDSHAKE:
        if (conn->handshake == NULL || (s->current.cipher = &conn->handshake->cipher.egress)->aead == NULL)
            return NULL;
        s->current.first_byte = QUICLY_PACKET_TYPE_HANDSHAKE;
        space = &conn->handshake->super;
        break;
    case QUICLY_EPOCH_0RTT:
    case QUICLY_EPOCH_1RTT:
        if (conn->application == NULL || conn->application->cipher.egress.key.header_protection == NULL)
            return NULL;
        if ((epoch == QUICLY_EPOCH_0RTT) == conn->application->one_rtt_writable)
            return NULL;
        s->current.cipher = &conn->application->cipher.egress.key;
        s->current.first_byte = epoch == QUICLY_EPOCH_0RTT ? QUICLY_PACKET_TYPE_0RTT : QUICLY_QUIC_BIT;
        space = &conn->application->super;
        break;
    default:
        assert(!"logic flaw");
        break;
    }

    return space;
}

static int send_handshake_flow(quicly_conn_t *conn, size_t epoch, quicly_send_context_t *s, int ack_only, int send_probe)
{
    struct st_quicly_pn_space_t *space;
    int ret = 0;

    /* setup send epoch, or return if it's impossible to send in this epoch */
    if ((space = setup_send_space(conn, epoch, s)) == NULL)
        return 0;

    /* send ACK */
    if (space != NULL && (space->unacked_count != 0 || send_probe))
        if ((ret = send_ack(conn, space, s)) != 0)
            goto Exit;

    if (!ack_only) {
        /* send data */
        while ((conn->egress.pending_flows & (uint8_t)(1 << epoch)) != 0) {
            quicly_stream_t *stream = quicly_get_stream(conn, -(quicly_stream_id_t)(1 + epoch));
            assert(stream != NULL);
            if ((ret = quicly_send_stream(stream, s)) != 0)
                goto Exit;
            resched_stream_data(stream);
            send_probe = 0;
        }

        /* send probe if requested */
        if (send_probe) {
            if ((ret = _do_allocate_frame(conn, s, 1, 1)) != 0)
                goto Exit;
            *s->dst++ = QUICLY_FRAME_TYPE_PING;
            conn->egress.last_retransmittable_sent_at = conn->stash.now;
            ++conn->super.stats.num_frames_sent.ping;
            QUICLY_PROBE(PING_SEND, conn, conn->stash.now);
        }
    }

Exit:
    return ret;
}

static int send_connection_close(quicly_conn_t *conn, size_t epoch, quicly_send_context_t *s)
{
    uint64_t error_code, offending_frame_type;
    const char *reason_phrase;
    int ret;

    /* setup send epoch, or return if it's impossible to send in this epoch */
    if (setup_send_space(conn, epoch, s) == NULL)
        return 0;

    /* determine the payload, masking the application error when sending the frame using an unauthenticated epoch */
    error_code = conn->egress.connection_close.error_code;
    offending_frame_type = conn->egress.connection_close.frame_type;
    reason_phrase = conn->egress.connection_close.reason_phrase;
    if (offending_frame_type == UINT64_MAX) {
        switch (get_epoch(s->current.first_byte)) {
        case QUICLY_EPOCH_INITIAL:
        case QUICLY_EPOCH_HANDSHAKE:
            error_code = QUICLY_TRANSPORT_ERROR_APPLICATION;
            offending_frame_type = QUICLY_FRAME_TYPE_PADDING;
            reason_phrase = "";
            break;
        }
    }

    /* write frame */
    if ((ret = allocate_frame(conn, s, quicly_close_frame_capacity(error_code, offending_frame_type, reason_phrase))) != 0)
        return ret;
    s->dst = quicly_encode_close_frame(s->dst, error_code, offending_frame_type, reason_phrase);

    /* update counter, probe */
    if (offending_frame_type != UINT64_MAX) {
        ++conn->super.stats.num_frames_sent.transport_close;
        QUICLY_PROBE(TRANSPORT_CLOSE_SEND, conn, conn->stash.now, error_code, offending_frame_type, reason_phrase);
    } else {
        ++conn->super.stats.num_frames_sent.application_close;
        QUICLY_PROBE(APPLICATION_CLOSE_SEND, conn, conn->stash.now, error_code, reason_phrase);
    }

    return 0;
}

static int send_new_connection_id(quicly_conn_t *conn, quicly_send_context_t *s, struct st_quicly_local_cid_t *new_cid)
{
    int ret;
    quicly_sent_t *sent;
    uint64_t retire_prior_to = 0; /* TODO */

    ret = allocate_ack_eliciting_frame(
        conn, s, quicly_new_connection_id_frame_capacity(new_cid->sequence, retire_prior_to, new_cid->cid.len), &sent,
        on_ack_new_connection_id);
    if (ret != 0)
        return ret;
    sent->data.new_connection_id.sequence = new_cid->sequence;

    s->dst = quicly_encode_new_connection_id_frame(s->dst, new_cid->sequence, retire_prior_to, new_cid->cid.cid, new_cid->cid.len,
                                                   new_cid->stateless_reset_token);

    ++conn->super.stats.num_frames_sent.new_connection_id;
    QUICLY_PROBE(NEW_CONNECTION_ID_SEND, conn, conn->stash.now, new_cid->sequence, retire_prior_to,
                 QUICLY_PROBE_HEXDUMP(new_cid->cid.cid, new_cid->cid.len),
                 QUICLY_PROBE_HEXDUMP(new_cid->stateless_reset_token, QUICLY_STATELESS_RESET_TOKEN_LEN));

    return 0;
}

static int send_retire_connection_id(quicly_conn_t *conn, quicly_send_context_t *s, uint64_t sequence)
{
    int ret;
    quicly_sent_t *sent;

    ret = allocate_ack_eliciting_frame(conn, s, quicly_retire_connection_id_frame_capacity(sequence), &sent,
                                       on_ack_retire_connection_id);
    if (ret != 0)
        return ret;
    sent->data.retire_connection_id.sequence = sequence;

    s->dst = quicly_encode_retire_connection_id_frame(s->dst, sequence);

    ++conn->super.stats.num_frames_sent.retire_connection_id;
    QUICLY_PROBE(RETIRE_CONNECTION_ID_SEND, conn, conn->stash.now, sequence);

    return 0;
}

static int update_traffic_key_cb(ptls_update_traffic_key_t *self, ptls_t *tls, int is_enc, size_t epoch, const void *secret)
{
    quicly_conn_t *conn = *ptls_get_data_ptr(tls);
    ptls_context_t *tlsctx = ptls_get_context(tls);
    ptls_cipher_suite_t *cipher = ptls_get_cipher(tls);
    ptls_cipher_context_t **hp_slot;
    ptls_aead_context_t **aead_slot;
    int ret;
    static const char *log_labels[2][4] = {
        {NULL, "QUIC_CLIENT_EARLY_TRAFFIC_SECRET", "QUIC_CLIENT_HANDSHAKE_TRAFFIC_SECRET", "QUIC_CLIENT_TRAFFIC_SECRET_0"},
        {NULL, NULL, "QUIC_SERVER_HANDSHAKE_TRAFFIC_SECRET", "QUIC_SERVER_TRAFFIC_SECRET_0"}};
    const char *log_label = log_labels[ptls_is_server(tls) == is_enc][epoch];

    QUICLY_PROBE(CRYPTO_UPDATE_SECRET, conn, conn->stash.now, is_enc, epoch, log_label,
                 QUICLY_PROBE_HEXDUMP(secret, cipher->hash->digest_size));

    if (tlsctx->log_event != NULL) {
        char hexbuf[PTLS_MAX_DIGEST_SIZE * 2 + 1];
        ptls_hexdump(hexbuf, secret, cipher->hash->digest_size);
        tlsctx->log_event->cb(tlsctx->log_event, tls, log_label, "%s", hexbuf);
    }

#define SELECT_CIPHER_CONTEXT(p)                                                                                                   \
    do {                                                                                                                           \
        hp_slot = &(p)->header_protection;                                                                                         \
        aead_slot = &(p)->aead;                                                                                                    \
    } while (0)

    switch (epoch) {
    case QUICLY_EPOCH_0RTT:
        assert(is_enc == quicly_is_client(conn));
        if (conn->application == NULL && (ret = setup_application_space(conn)) != 0)
            return ret;
        if (is_enc) {
            SELECT_CIPHER_CONTEXT(&conn->application->cipher.egress.key);
        } else {
            hp_slot = &conn->application->cipher.ingress.header_protection.zero_rtt;
            aead_slot = &conn->application->cipher.ingress.aead[1];
        }
        break;
    case QUICLY_EPOCH_HANDSHAKE:
        if (conn->handshake == NULL && (ret = setup_handshake_space_and_flow(conn, QUICLY_EPOCH_HANDSHAKE)) != 0)
            return ret;
        SELECT_CIPHER_CONTEXT(is_enc ? &conn->handshake->cipher.egress : &conn->handshake->cipher.ingress);
        break;
    case QUICLY_EPOCH_1RTT: {
        if (is_enc)
            if ((ret = apply_remote_transport_params(conn)) != 0)
                return ret;
        if (conn->application == NULL && (ret = setup_application_space(conn)) != 0)
            return ret;
        uint8_t *secret_store;
        if (is_enc) {
            if (conn->application->cipher.egress.key.aead != NULL)
                dispose_cipher(&conn->application->cipher.egress.key);
            SELECT_CIPHER_CONTEXT(&conn->application->cipher.egress.key);
            secret_store = conn->application->cipher.egress.secret;
        } else {
            hp_slot = &conn->application->cipher.ingress.header_protection.one_rtt;
            aead_slot = &conn->application->cipher.ingress.aead[0];
            secret_store = conn->application->cipher.ingress.secret;
        }
        memcpy(secret_store, secret, cipher->hash->digest_size);
    } break;
    default:
        assert(!"logic flaw");
        break;
    }

#undef SELECT_CIPHER_CONTEXT

    if ((ret = setup_cipher(conn, epoch, is_enc, hp_slot, aead_slot, cipher->aead, cipher->hash, secret)) != 0)
        return ret;

    if (epoch == QUICLY_EPOCH_1RTT && is_enc) {
        /* update states now that we have 1-RTT write key */
        conn->application->one_rtt_writable = 1;
        open_blocked_streams(conn, 1);
        open_blocked_streams(conn, 0);
        /* send the first resumption token using the 0.5 RTT window */
        if (!quicly_is_client(conn) && conn->super.ctx->generate_resumption_token != NULL) {
            ret = quicly_send_resumption_token(conn);
            assert(ret == 0);
        }

        /* schedule NEW_CONNECTION_IDs */
        size_t size = local_cid_size(conn);
        if (quicly_local_cid_set_size(&conn->super.local.cid_set, size))
            conn->egress.pending_flows |= QUICLY_PENDING_FLOW_CID_FRAME_BIT;
    }

    return 0;
}

static int do_send(quicly_conn_t *conn, quicly_send_context_t *s)
{
    int restrict_sending = 0, ack_only = 0, ret;
    size_t min_packets_to_send = 0;

    /* handle timeouts */
    if (conn->idle_timeout.at <= conn->stash.now) {
        QUICLY_PROBE(IDLE_TIMEOUT, conn, conn->stash.now);
        conn->super.state = QUICLY_STATE_DRAINING;
        destroy_all_streams(conn, 0, 0);
        return QUICLY_ERROR_FREE_CONNECTION;
    }
    if (conn->egress.loss.alarm_at <= conn->stash.now) {
        if ((ret = quicly_loss_on_alarm(&conn->egress.loss, conn->stash.now, conn->super.remote.transport_params.max_ack_delay,
                                        conn->initial == NULL && conn->handshake == NULL, &min_packets_to_send, &restrict_sending,
                                        on_loss_detected)) != 0)
            goto Exit;
        assert(min_packets_to_send > 0);
        assert(min_packets_to_send <= s->max_datagrams);

        if (restrict_sending) {
            /* PTO: when handshake is in progress, send from the very first unacknowledged byte so as to maximize the chance of
             * making progress. When handshake is complete, transmit new data if any, else retransmit the oldest unacknowledged data
             * that is considered inflight. */
            QUICLY_PROBE(PTO, conn, conn->stash.now, conn->egress.loss.sentmap.bytes_in_flight, conn->egress.cc.cwnd,
                         conn->egress.loss.pto_count);
            ++conn->super.stats.num_ptos;
            size_t bytes_to_mark = min_packets_to_send * conn->egress.max_udp_payload_size;
            if (conn->initial != NULL && (ret = mark_frames_on_pto(conn, QUICLY_EPOCH_INITIAL, &bytes_to_mark)) != 0)
                goto Exit;
            if (bytes_to_mark != 0 && conn->handshake != NULL &&
                (ret = mark_frames_on_pto(conn, QUICLY_EPOCH_HANDSHAKE, &bytes_to_mark)) != 0)
                goto Exit;
            /* Mark already sent 1-RTT data for PTO only if there's no new data, i.e., when scheduler_can_send() return false. */
            if (bytes_to_mark != 0 && !scheduler_can_send(conn) &&
                (ret = mark_frames_on_pto(conn, QUICLY_EPOCH_1RTT, &bytes_to_mark)) != 0)
                goto Exit;
        }
    }

    s->send_window = calc_send_window(conn, min_packets_to_send * conn->egress.max_udp_payload_size,
                                      calc_amplification_limit_allowance(conn), restrict_sending);
    if (s->send_window == 0)
        ack_only = 1;

    /* send handshake flows; when PTO fires...
     *  * quicly running as a client sends either a Handshake probe (or data) if the handshake keys are available, or else an
     *    Initial probe (or data).
     *  * quicly running as a server sends both Initial and Handshake probes (or data) if the corresponding keys are available. */
    if ((ret = send_handshake_flow(conn, QUICLY_EPOCH_INITIAL, s, ack_only,
                                   min_packets_to_send != 0 && (!quicly_is_client(conn) || conn->handshake == NULL))) != 0)
        goto Exit;
    if ((ret = send_handshake_flow(conn, QUICLY_EPOCH_HANDSHAKE, s, ack_only, min_packets_to_send != 0)) != 0)
        goto Exit;

    /* setup 0-RTT or 1-RTT send context (as the availability of the two epochs are mutually exclusive, we can try 1-RTT first as an
     * optimization), then send application data if that succeeds */
    if (setup_send_space(conn, QUICLY_EPOCH_1RTT, s) != NULL || setup_send_space(conn, QUICLY_EPOCH_0RTT, s) != NULL) {
        /* acks */
        if (conn->application->one_rtt_writable && conn->egress.send_ack_at <= conn->stash.now &&
            conn->application->super.unacked_count != 0) {
            if ((ret = send_ack(conn, &conn->application->super, s)) != 0)
                goto Exit;
        }
        /* DATAGRAM frame. Notes regarding current implementation:
         * * Not limited by CC, nor the bytes counted by CC.
         * * When given payload is too large and does not fit into a QUIC packet, a packet containing only PADDING frames is sent.
         *   This is because we do not have a way to retract the generation of a QUIC packet.
         * * Does not notify the application that the frame was dropped internally. */
        if (should_send_datagram_frame(conn)) {
            size_t required_space = quicly_datagram_frame_capacity(conn->egress.datagram_frame_payload);
            if ((ret = _do_allocate_frame(conn, s, required_space, 1)) != 0)
                goto Exit;
            if (s->dst_end - s->dst >= required_space) {
                s->dst = quicly_encode_datagram_frame(s->dst, conn->egress.datagram_frame_payload);
                QUICLY_PROBE(DATAGRAM_SEND, conn, conn->stash.now, conn->egress.datagram_frame_payload.base,
                             conn->egress.datagram_frame_payload.len);
                conn->egress.datagram_frame_payload = ptls_iovec_init(NULL, 0);
                ++conn->super.stats.num_frames_sent.datagram;
            }
        }
        if (!ack_only) {
            /* PTO or loss detection timeout, always send PING. This is the easiest thing to do in terms of timer control. */
            if (min_packets_to_send != 0) {
                if ((ret = _do_allocate_frame(conn, s, 1, 1)) != 0)
                    goto Exit;
                *s->dst++ = QUICLY_FRAME_TYPE_PING;
                ++conn->super.stats.num_frames_sent.ping;
                QUICLY_PROBE(PING_SEND, conn, conn->stash.now);
            }
            /* take actions only permitted for short header packets */
            if (conn->application->one_rtt_writable) {
                /* send HANDSHAKE_DONE */
                if ((conn->egress.pending_flows & QUICLY_PENDING_FLOW_HANDSHAKE_DONE_BIT) != 0 &&
                    (ret = send_handshake_done(conn, s)) != 0)
                    goto Exit;
                /* post-handshake messages */
                if ((conn->egress.pending_flows & (uint8_t)(1 << QUICLY_EPOCH_1RTT)) != 0) {
                    quicly_stream_t *stream = quicly_get_stream(conn, -(1 + QUICLY_EPOCH_1RTT));
                    assert(stream != NULL);
                    if ((ret = quicly_send_stream(stream, s)) != 0)
                        goto Exit;
                    resched_stream_data(stream);
                }
                /* respond to all pending received PATH_CHALLENGE frames */
                if (conn->egress.path_challenge.head != NULL) {
                    do {
                        struct st_quicly_pending_path_challenge_t *c = conn->egress.path_challenge.head;
                        if ((ret = allocate_frame(conn, s, QUICLY_PATH_CHALLENGE_FRAME_CAPACITY)) != 0)
                            goto Exit;
                        s->dst = quicly_encode_path_challenge_frame(s->dst, c->is_response, c->data);
                        if (c->is_response) {
                            ++conn->super.stats.num_frames_sent.path_response;
                        } else {
                            ++conn->super.stats.num_frames_sent.path_challenge;
                        }
                        conn->egress.path_challenge.head = c->next;
                        free(c);
                    } while (conn->egress.path_challenge.head != NULL);
                    conn->egress.path_challenge.tail_ref = &conn->egress.path_challenge.head;
                }
                /* send max_streams frames */
                if ((ret = send_max_streams(conn, 1, s)) != 0)
                    goto Exit;
                if ((ret = send_max_streams(conn, 0, s)) != 0)
                    goto Exit;
                /* send connection-level flow control frames */
                if (should_send_max_data(conn)) {
                    quicly_sent_t *sent;
                    if ((ret = allocate_ack_eliciting_frame(conn, s, QUICLY_MAX_DATA_FRAME_CAPACITY, &sent, on_ack_max_data)) != 0)
                        goto Exit;
                    uint64_t new_value = conn->ingress.max_data.bytes_consumed + conn->super.ctx->transport_params.max_data;
                    s->dst = quicly_encode_max_data_frame(s->dst, new_value);
                    quicly_maxsender_record(&conn->ingress.max_data.sender, new_value, &sent->data.max_data.args);
                    ++conn->super.stats.num_frames_sent.max_data;
                    QUICLY_PROBE(MAX_DATA_SEND, conn, conn->stash.now, new_value);
                }
                if (conn->egress.data_blocked == QUICLY_SENDER_STATE_SEND && (ret = send_data_blocked(conn, s)) != 0)
                    goto Exit;
                /* send streams_blocked frames */
                if ((ret = send_streams_blocked(conn, 1, s)) != 0)
                    goto Exit;
                if ((ret = send_streams_blocked(conn, 0, s)) != 0)
                    goto Exit;
                /* send NEW_TOKEN */
                if ((conn->egress.pending_flows & QUICLY_PENDING_FLOW_NEW_TOKEN_BIT) != 0 &&
                    (ret = send_resumption_token(conn, s)) != 0)
                    goto Exit;
                if ((conn->egress.pending_flows & QUICLY_PENDING_FLOW_CID_FRAME_BIT) != 0) {
                    /* send NEW_CONNECTION_ID */
                    size_t i;
                    size_t size = quicly_local_cid_get_size(&conn->super.local.cid_set);
                    for (i = 0; i < size; i++) {
                        /* PENDING CIDs are located at the front */
                        struct st_quicly_local_cid_t *c = &conn->super.local.cid_set.cids[i];
                        if (c->state != QUICLY_LOCAL_CID_STATE_PENDING)
                            break;
                        if ((ret = send_new_connection_id(conn, s, c)) != 0)
                            break;
                    }
                    quicly_local_cid_on_sent(&conn->super.local.cid_set, i);
                    if (ret != 0)
                        goto Exit;
                    /* send RETIRE_CONNECTION_ID */
                    size = quicly_retire_cid_get_num_pending(&conn->egress.retire_cid);
                    for (i = 0; i < size; i++) {
                        uint64_t sequence = conn->egress.retire_cid.sequences[i];
                        if ((ret = send_retire_connection_id(conn, s, sequence)) != 0)
                            break;
                    }
                    quicly_retire_cid_shift(&conn->egress.retire_cid, i);
                    if (ret != 0)
                        goto Exit;
                    conn->egress.pending_flows &= ~QUICLY_PENDING_FLOW_CID_FRAME_BIT;
                }
            }
            /* send stream-level control frames */
            if ((ret = send_stream_control_frames(conn, s)) != 0)
                goto Exit;
            /* send STREAM frames */
            if ((ret = conn->super.ctx->stream_scheduler->do_send(conn->super.ctx->stream_scheduler, conn, s)) != 0)
                goto Exit;
            /* once more, send stream-level control frames, as the state might have changed */
            if ((ret = send_stream_control_frames(conn, s)) != 0)
                goto Exit;
        }
    }

Exit:
    if (ret == QUICLY_ERROR_SENDBUF_FULL)
        ret = 0;
    if (ret == 0 && s->target.first_byte_at != NULL) {
        /* last packet can be small-sized, unless it is the first flight sent from the client */
        enum en_quicly_send_packet_mode_t commit_mode = QUICLY_COMMIT_SEND_PACKET_MODE_SMALL;
        if ((s->payload_buf.datagram[0] & QUICLY_PACKET_TYPE_BITMASK) == QUICLY_PACKET_TYPE_INITIAL &&
            (quicly_is_client(conn) || !ack_only))
            commit_mode = QUICLY_COMMIT_SEND_PACKET_MODE_FULL_SIZE;
        commit_send_packet(conn, s, commit_mode);
    }
    if (ret == 0) {
        if (conn->application == NULL || conn->application->super.unacked_count == 0)
            conn->egress.send_ack_at = INT64_MAX; /* we have sent ACKs for every epoch (or before address validation) */
        update_loss_alarm(conn, 1);
        if (s->num_datagrams != 0)
            update_idle_timeout(conn, 0);
    }
    return ret;
}

void quicly_set_datagram_frame(quicly_conn_t *conn, ptls_iovec_t payload)
{
    conn->egress.datagram_frame_payload = payload;
}

int quicly_send(quicly_conn_t *conn, quicly_address_t *dest, quicly_address_t *src, struct iovec *datagrams, size_t *num_datagrams,
                void *buf, size_t bufsize)
{
    quicly_send_context_t s = {{NULL, -1}, {}, datagrams, *num_datagrams, 0, {buf, (uint8_t *)buf + bufsize}};
    int ret;

    lock_now(conn, 0);

    /* bail out if there's nothing is scheduled to be sent */
    if (conn->stash.now < quicly_get_first_timeout(conn)) {
        ret = 0;
        goto Exit;
    }

    QUICLY_PROBE(SEND, conn, conn->stash.now, conn->super.state,
                 QUICLY_PROBE_HEXDUMP(conn->super.remote.cid_set.cids[0].cid.cid, conn->super.remote.cid_set.cids[0].cid.len));

    if (conn->super.state >= QUICLY_STATE_CLOSING) {
        quicly_sentmap_iter_t iter;
        init_acks_iter(conn, &iter);
        /* check if the connection can be closed now (after 3 pto) */
        if (conn->super.state == QUICLY_STATE_DRAINING ||
            conn->super.stats.num_frames_sent.transport_close + conn->super.stats.num_frames_sent.application_close != 0) {
            if (quicly_sentmap_get(&iter)->packet_number == UINT64_MAX) {
                assert(quicly_num_streams(conn) == 0);
                ret = QUICLY_ERROR_FREE_CONNECTION;
                goto Exit;
            }
        }
        if (conn->super.state == QUICLY_STATE_CLOSING && conn->egress.send_ack_at <= conn->stash.now) {
            /* destroy all streams; doing so is delayed until the emission of CONNECTION_CLOSE frame to allow quicly_close to be
             * called from a stream handler */
            destroy_all_streams(conn, 0, 0);
            /* send CONNECTION_CLOSE in all possible epochs */
            for (size_t epoch = 0; epoch < QUICLY_NUM_EPOCHS; ++epoch) {
                if ((ret = send_connection_close(conn, epoch, &s)) != 0)
                    goto Exit;
            }
            if ((ret = commit_send_packet(conn, &s, QUICLY_COMMIT_SEND_PACKET_MODE_SMALL)) != 0)
                goto Exit;
        }
        /* wait at least 1ms */
        if ((conn->egress.send_ack_at = quicly_sentmap_get(&iter)->sent_at + get_sentmap_expiration_time(conn)) <= conn->stash.now)
            conn->egress.send_ack_at = conn->stash.now + 1;
        ret = 0;
        goto Exit;
    }

    /* emit packets */
    if ((ret = do_send(conn, &s)) != 0)
        goto Exit;

    assert_consistency(conn, 1);

Exit:
    conn->egress.datagram_frame_payload = ptls_iovec_init(NULL, 0);
    if (s.num_datagrams != 0) {
        *dest = conn->super.remote.address;
        *src = conn->super.local.address;
    }
    *num_datagrams = s.num_datagrams;
    unlock_now(conn);
    return ret;
}

size_t quicly_send_close_invalid_token(quicly_context_t *ctx, uint32_t protocol_version, ptls_iovec_t dest_cid,
                                       ptls_iovec_t src_cid, const char *err_desc, void *datagram)
{
    struct st_quicly_cipher_context_t egress = {};
    const struct st_ptls_salt_t *salt;

    /* setup keys */
    if ((salt = get_salt(protocol_version)) == NULL)
        return SIZE_MAX;
    if (setup_initial_encryption(get_aes128gcmsha256(ctx), NULL, &egress, src_cid, 0,
                                 ptls_iovec_init(salt->initial, sizeof(salt->initial)), NULL) != 0)
        return SIZE_MAX;

    uint8_t *dst = datagram, *length_at;

    /* build packet */
    PTLS_BUILD_ASSERT(QUICLY_SEND_PN_SIZE == 2);
    *dst++ = QUICLY_PACKET_TYPE_INITIAL | 0x1 /* 2-byte PN */;
    dst = quicly_encode32(dst, protocol_version);
    *dst++ = dest_cid.len;
    memcpy(dst, dest_cid.base, dest_cid.len);
    dst += dest_cid.len;
    *dst++ = src_cid.len;
    memcpy(dst, src_cid.base, src_cid.len);
    dst += src_cid.len;
    *dst++ = 0;        /* token_length = 0 */
    length_at = dst++; /* length_at to be filled in later as 1-byte varint */
    *dst++ = 0;        /* PN = 0 */
    *dst++ = 0;        /* ditto */
    uint8_t *payload_from = dst;
    dst = quicly_encode_close_frame(dst, QUICLY_ERROR_GET_ERROR_CODE(QUICLY_TRANSPORT_ERROR_INVALID_TOKEN),
                                    QUICLY_FRAME_TYPE_PADDING, err_desc);

    /* determine the size of the packet, make adjustments */
    dst += egress.aead->algo->tag_size;
    assert(dst - (uint8_t *)datagram <= QUICLY_MIN_CLIENT_INITIAL_SIZE);
    assert(dst - length_at - 1 < 64);
    *length_at = dst - length_at - 1;
    size_t datagram_len = dst - (uint8_t *)datagram;

    /* encrypt packet */
    quicly_default_crypto_engine.encrypt_packet(&quicly_default_crypto_engine, NULL, egress.header_protection, egress.aead,
                                                ptls_iovec_init(datagram, datagram_len), 0, payload_from - (uint8_t *)datagram, 0,
                                                0);

    dispose_cipher(&egress);
    return datagram_len;
}

size_t quicly_send_stateless_reset(quicly_context_t *ctx, const void *src_cid, void *payload)
{
    uint8_t *base = payload;

    /* build stateless reset packet */
    ctx->tls->random_bytes(base, QUICLY_STATELESS_RESET_PACKET_MIN_LEN - QUICLY_STATELESS_RESET_TOKEN_LEN);
    base[0] = (base[0] & ~QUICLY_LONG_HEADER_BIT) | QUICLY_QUIC_BIT;
    if (!ctx->cid_encryptor->generate_stateless_reset_token(
            ctx->cid_encryptor, base + QUICLY_STATELESS_RESET_PACKET_MIN_LEN - QUICLY_STATELESS_RESET_TOKEN_LEN, src_cid))
        return SIZE_MAX;

    return QUICLY_STATELESS_RESET_PACKET_MIN_LEN;
}

int quicly_send_resumption_token(quicly_conn_t *conn)
{
    if (conn->super.state <= QUICLY_STATE_CONNECTED) {
        ++conn->egress.new_token.generation;
        conn->egress.pending_flows |= QUICLY_PENDING_FLOW_NEW_TOKEN_BIT;
    }
    return 0;
}

static int on_end_closing(quicly_sentmap_t *map, const quicly_sent_packet_t *packet, int acked, quicly_sent_t *sent)
{
    /* we stop accepting frames by the time this ack callback is being registered */
    assert(!acked);
    return 0;
}

static int enter_close(quicly_conn_t *conn, int local_is_initiating, int wait_draining)
{
    int ret;

    assert(conn->super.state < QUICLY_STATE_CLOSING);

    /* release all inflight info, register a close timeout */
    if ((ret = discard_sentmap_by_epoch(conn, ~0u)) != 0)
        return ret;
    if ((ret = quicly_sentmap_prepare(&conn->egress.loss.sentmap, conn->egress.packet_number, conn->stash.now,
                                      QUICLY_EPOCH_INITIAL)) != 0)
        return ret;
    if (quicly_sentmap_allocate(&conn->egress.loss.sentmap, on_end_closing) == NULL)
        return PTLS_ERROR_NO_MEMORY;
    quicly_sentmap_commit(&conn->egress.loss.sentmap, 0);
    ++conn->egress.packet_number;

    if (local_is_initiating) {
        conn->super.state = QUICLY_STATE_CLOSING;
        conn->egress.send_ack_at = 0;
    } else {
        conn->super.state = QUICLY_STATE_DRAINING;
        conn->egress.send_ack_at = wait_draining ? conn->stash.now + get_sentmap_expiration_time(conn) : 0;
    }

    update_loss_alarm(conn, 0);

    return 0;
}

int initiate_close(quicly_conn_t *conn, int err, uint64_t frame_type, const char *reason_phrase)
{
    uint16_t quic_error_code;

    if (conn->super.state >= QUICLY_STATE_CLOSING)
        return 0;

    if (reason_phrase == NULL)
        reason_phrase = "";

    /* convert error code to QUIC error codes */
    if (err == 0) {
        quic_error_code = 0;
        frame_type = QUICLY_FRAME_TYPE_PADDING;
    } else if (QUICLY_ERROR_IS_QUIC_TRANSPORT(err)) {
        quic_error_code = QUICLY_ERROR_GET_ERROR_CODE(err);
    } else if (QUICLY_ERROR_IS_QUIC_APPLICATION(err)) {
        quic_error_code = QUICLY_ERROR_GET_ERROR_CODE(err);
        frame_type = UINT64_MAX;
    } else if (PTLS_ERROR_GET_CLASS(err) == PTLS_ERROR_CLASS_SELF_ALERT) {
        quic_error_code = QUICLY_TRANSPORT_ERROR_TLS_ALERT_BASE + PTLS_ERROR_TO_ALERT(err);
    } else {
        quic_error_code = QUICLY_ERROR_GET_ERROR_CODE(QUICLY_TRANSPORT_ERROR_INTERNAL);
    }

    conn->egress.connection_close.error_code = quic_error_code;
    conn->egress.connection_close.frame_type = frame_type;
    conn->egress.connection_close.reason_phrase = reason_phrase;
    return enter_close(conn, 1, 0);
}

int quicly_close(quicly_conn_t *conn, int err, const char *reason_phrase)
{
    int ret;

    assert(err == 0 || QUICLY_ERROR_IS_QUIC_APPLICATION(err) || QUICLY_ERROR_IS_CONCEALED(err));

    lock_now(conn, 1);
    ret = initiate_close(conn, err, QUICLY_FRAME_TYPE_PADDING /* used when err == 0 */, reason_phrase);
    unlock_now(conn);

    return ret;
}

int quicly_get_or_open_stream(quicly_conn_t *conn, uint64_t stream_id, quicly_stream_t **stream)
{
    int ret = 0;

    if ((*stream = quicly_get_stream(conn, stream_id)) != NULL)
        goto Exit;

    if (quicly_stream_is_client_initiated(stream_id) != quicly_is_client(conn)) {
        /* check if stream id is within the bounds */
        if (stream_id / 4 >= quicly_get_ingress_max_streams(conn, quicly_stream_is_unidirectional(stream_id))) {
            ret = QUICLY_TRANSPORT_ERROR_STREAM_LIMIT;
            goto Exit;
        }
        /* open new streams upto given id */
        struct st_quicly_conn_streamgroup_state_t *group = get_streamgroup_state(conn, stream_id);
        if (group->next_stream_id <= stream_id) {
            uint64_t max_stream_data_local, max_stream_data_remote;
            if (quicly_stream_is_unidirectional(stream_id)) {
                max_stream_data_local = conn->super.ctx->transport_params.max_stream_data.uni;
                max_stream_data_remote = 0;
            } else {
                max_stream_data_local = conn->super.ctx->transport_params.max_stream_data.bidi_remote;
                max_stream_data_remote = conn->super.remote.transport_params.max_stream_data.bidi_local;
            }
            do {
                if ((*stream = open_stream(conn, group->next_stream_id, (uint32_t)max_stream_data_local, max_stream_data_remote)) ==
                    NULL) {
                    ret = PTLS_ERROR_NO_MEMORY;
                    goto Exit;
                }
                QUICLY_PROBE(STREAM_ON_OPEN, conn, conn->stash.now, *stream);
                if ((ret = conn->super.ctx->stream_open->cb(conn->super.ctx->stream_open, *stream)) != 0) {
                    *stream = NULL;
                    goto Exit;
                }
                ++group->num_streams;
                group->next_stream_id += 4;
            } while (stream_id != (*stream)->stream_id);
        }
    }

Exit:
    return ret;
}

static int handle_crypto_frame(quicly_conn_t *conn, struct st_quicly_handle_payload_state_t *state)
{
    quicly_stream_frame_t frame;
    quicly_stream_t *stream;
    int ret;

    if ((ret = quicly_decode_crypto_frame(&state->src, state->end, &frame)) != 0)
        return ret;
    stream = quicly_get_stream(conn, -(quicly_stream_id_t)(1 + state->epoch));
    assert(stream != NULL);
    return apply_stream_frame(stream, &frame);
}

static int handle_stream_frame(quicly_conn_t *conn, struct st_quicly_handle_payload_state_t *state)
{
    quicly_stream_frame_t frame;
    quicly_stream_t *stream;
    int ret;

    if ((ret = quicly_decode_stream_frame(state->frame_type, &state->src, state->end, &frame)) != 0)
        return ret;
    QUICLY_PROBE(QUICTRACE_RECV_STREAM, conn, conn->stash.now, frame.stream_id, frame.offset, frame.data.len, (int)frame.is_fin);
    if ((ret = quicly_get_or_open_stream(conn, frame.stream_id, &stream)) != 0 || stream == NULL)
        return ret;
    return apply_stream_frame(stream, &frame);
}

static int handle_reset_stream_frame(quicly_conn_t *conn, struct st_quicly_handle_payload_state_t *state)
{
    quicly_reset_stream_frame_t frame;
    quicly_stream_t *stream;
    int ret;

    if ((ret = quicly_decode_reset_stream_frame(&state->src, state->end, &frame)) != 0)
        return ret;

    if ((ret = quicly_get_or_open_stream(conn, frame.stream_id, &stream)) != 0 || stream == NULL)
        return ret;

    if (!quicly_recvstate_transfer_complete(&stream->recvstate)) {
        uint64_t bytes_missing;
        if ((ret = quicly_recvstate_reset(&stream->recvstate, frame.final_size, &bytes_missing)) != 0)
            return ret;
        stream->conn->ingress.max_data.bytes_consumed += bytes_missing;
        int err = QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(frame.app_error_code);
        QUICLY_PROBE(STREAM_ON_RECEIVE_RESET, stream->conn, stream->conn->stash.now, stream, err);
        stream->callbacks->on_receive_reset(stream, err);
        if (stream->conn->super.state >= QUICLY_STATE_CLOSING)
            return QUICLY_ERROR_IS_CLOSING;
        if (stream_is_destroyable(stream))
            destroy_stream(stream, 0);
    }

    return 0;
}

static int handle_ack_frame(quicly_conn_t *conn, struct st_quicly_handle_payload_state_t *state)
{
    quicly_ack_frame_t frame;
    quicly_sentmap_iter_t iter;
    struct {
        uint64_t pn;
        int64_t sent_at;
    } largest_newly_acked = {UINT64_MAX, INT64_MAX};
    size_t bytes_acked = 0;
    int includes_ack_eliciting = 0, ret;

    if ((ret = quicly_decode_ack_frame(&state->src, state->end, &frame, state->frame_type == QUICLY_FRAME_TYPE_ACK_ECN)) != 0)
        return ret;

    uint64_t pn_acked = frame.smallest_acknowledged;

    switch (state->epoch) {
    case QUICLY_EPOCH_0RTT:
        return QUICLY_TRANSPORT_ERROR_PROTOCOL_VIOLATION;
    case QUICLY_EPOCH_HANDSHAKE:
        conn->super.remote.address_validation.send_probe = 0;
        break;
    default:
        break;
    }

    init_acks_iter(conn, &iter);

    /* TODO log PNs being ACKed too late */

    size_t gap_index = frame.num_gaps;
    while (1) {
        assert(frame.ack_block_lengths[gap_index] != 0);
        /* Ack blocks are organized in the ACK frame and consequently in the ack_block_lengths array from the largest acked down.
         * Processing acks in packet number order requires processing the ack blocks in reverse order. */
        uint64_t pn_block_max = pn_acked + frame.ack_block_lengths[gap_index] - 1;
        QUICLY_PROBE(QUICTRACE_RECV_ACK, conn, conn->stash.now, pn_acked, pn_block_max);
        while (quicly_sentmap_get(&iter)->packet_number < pn_acked)
            quicly_sentmap_skip(&iter);
        do {
            const quicly_sent_packet_t *sent = quicly_sentmap_get(&iter);
            uint64_t pn_sent = sent->packet_number;
            assert(pn_acked <= pn_sent);
            if (pn_acked < pn_sent) {
                /* set pn_acked to pn_sent; or past the end of the ack block, for use with the next ack block */
                if (pn_sent <= pn_block_max) {
                    pn_acked = pn_sent;
                } else {
                    pn_acked = pn_block_max + 1;
                    break;
                }
            }
            /* process newly acked packet */
            if (state->epoch != sent->ack_epoch)
                return QUICLY_TRANSPORT_ERROR_PROTOCOL_VIOLATION;
            int is_late_ack = 0;
            if (sent->ack_eliciting) {
                includes_ack_eliciting = 1;
                if (sent->cc_bytes_in_flight == 0) {
                    is_late_ack = 1;
                    ++conn->super.stats.num_packets.late_acked;
                }
            }
            ++conn->super.stats.num_packets.ack_received;
            largest_newly_acked.pn = pn_acked;
            largest_newly_acked.sent_at = sent->sent_at;
            QUICLY_PROBE(PACKET_ACKED, conn, conn->stash.now, pn_acked, is_late_ack);
            if (sent->cc_bytes_in_flight != 0) {
                bytes_acked += sent->cc_bytes_in_flight;
            }
            if ((ret = quicly_sentmap_update(&conn->egress.loss.sentmap, &iter, QUICLY_SENTMAP_EVENT_ACKED)) != 0)
                return ret;
            if (state->epoch == QUICLY_EPOCH_1RTT) {
                struct st_quicly_application_space_t *space = conn->application;
                if (space->cipher.egress.key_update_pn.last <= pn_acked) {
                    space->cipher.egress.key_update_pn.last = UINT64_MAX;
                    space->cipher.egress.key_update_pn.next = conn->egress.packet_number + conn->super.ctx->max_packets_per_key;
                    QUICLY_PROBE(CRYPTO_SEND_KEY_UPDATE_CONFIRMED, conn, conn->stash.now, space->cipher.egress.key_update_pn.next);
                }
            }
            ++pn_acked;
        } while (pn_acked <= pn_block_max);
        assert(pn_acked == pn_block_max + 1);
        if (gap_index-- == 0)
            break;
        pn_acked += frame.gaps[gap_index];
    }

    if ((ret = on_ack_stream_ack_cached(conn)) != 0)
        return ret;

    QUICLY_PROBE(QUICTRACE_RECV_ACK_DELAY, conn, conn->stash.now, frame.ack_delay);

    /* Update loss detection engine on ack. The function uses ack_delay only when the largest_newly_acked is also the largest acked
     * so far. So, it does not matter if the ack_delay being passed in does not apply to the largest_newly_acked. */
    quicly_loss_on_ack_received(&conn->egress.loss, largest_newly_acked.pn, state->epoch, conn->stash.now,
                                largest_newly_acked.sent_at, frame.ack_delay, includes_ack_eliciting);

    /* OnPacketAcked and OnPacketAckedCC */
    if (bytes_acked > 0) {
        conn->egress.cc.impl->cc_on_acked(&conn->egress.cc, &conn->egress.loss, (uint32_t)bytes_acked, frame.largest_acknowledged,
                                          (uint32_t)(conn->egress.loss.sentmap.bytes_in_flight + bytes_acked), conn->stash.now,
                                          conn->egress.max_udp_payload_size);
        QUICLY_PROBE(QUICTRACE_CC_ACK, conn, conn->stash.now, &conn->egress.loss.rtt, conn->egress.cc.cwnd,
                     conn->egress.loss.sentmap.bytes_in_flight);
    }

    QUICLY_PROBE(CC_ACK_RECEIVED, conn, conn->stash.now, frame.largest_acknowledged, bytes_acked, conn->egress.cc.cwnd,
                 conn->egress.loss.sentmap.bytes_in_flight);

    /* loss-detection  */
    quicly_loss_detect_loss(&conn->egress.loss, conn->stash.now, conn->super.remote.transport_params.max_ack_delay,
                            conn->initial == NULL && conn->handshake == NULL, on_loss_detected);
    update_loss_alarm(conn, 0);

    return 0;
}

static int handle_max_stream_data_frame(quicly_conn_t *conn, struct st_quicly_handle_payload_state_t *state)
{
    quicly_max_stream_data_frame_t frame;
    quicly_stream_t *stream;
    int ret;

    if ((ret = quicly_decode_max_stream_data_frame(&state->src, state->end, &frame)) != 0)
        return ret;

    QUICLY_PROBE(MAX_STREAM_DATA_RECEIVE, conn, conn->stash.now, frame.stream_id, frame.max_stream_data);

    if (!quicly_stream_has_send_side(quicly_is_client(conn), frame.stream_id))
        return QUICLY_TRANSPORT_ERROR_FRAME_ENCODING;

    if ((stream = quicly_get_stream(conn, frame.stream_id)) == NULL)
        return 0;

    if (frame.max_stream_data < stream->_send_aux.max_stream_data)
        return 0;
    stream->_send_aux.max_stream_data = frame.max_stream_data;
    stream->_send_aux.blocked = QUICLY_SENDER_STATE_NONE;

    if (stream->_send_aux.reset_stream.sender_state == QUICLY_SENDER_STATE_NONE)
        resched_stream_data(stream);

    return 0;
}

static int handle_data_blocked_frame(quicly_conn_t *conn, struct st_quicly_handle_payload_state_t *state)
{
    quicly_data_blocked_frame_t frame;
    int ret;

    if ((ret = quicly_decode_data_blocked_frame(&state->src, state->end, &frame)) != 0)
        return ret;

    QUICLY_PROBE(DATA_BLOCKED_RECEIVE, conn, conn->stash.now, frame.offset);

    quicly_maxsender_request_transmit(&conn->ingress.max_data.sender);
    if (should_send_max_data(conn))
        conn->egress.send_ack_at = 0;

    return 0;
}

static int handle_stream_data_blocked_frame(quicly_conn_t *conn, struct st_quicly_handle_payload_state_t *state)
{
    quicly_stream_data_blocked_frame_t frame;
    quicly_stream_t *stream;
    int ret;

    if ((ret = quicly_decode_stream_data_blocked_frame(&state->src, state->end, &frame)) != 0)
        return ret;

    QUICLY_PROBE(STREAM_DATA_BLOCKED_RECEIVE, conn, conn->stash.now, frame.stream_id, frame.offset);

    if (!quicly_stream_has_receive_side(quicly_is_client(conn), frame.stream_id))
        return QUICLY_TRANSPORT_ERROR_FRAME_ENCODING;

    if ((stream = quicly_get_stream(conn, frame.stream_id)) != NULL) {
        quicly_maxsender_request_transmit(&stream->_send_aux.max_stream_data_sender);
        if (should_send_max_stream_data(stream))
            sched_stream_control(stream);
    }

    return 0;
}

static int handle_streams_blocked_frame(quicly_conn_t *conn, struct st_quicly_handle_payload_state_t *state)
{
    quicly_streams_blocked_frame_t frame;
    int uni = state->frame_type == QUICLY_FRAME_TYPE_STREAMS_BLOCKED_UNI, ret;

    if ((ret = quicly_decode_streams_blocked_frame(&state->src, state->end, &frame)) != 0)
        return ret;

    QUICLY_PROBE(STREAMS_BLOCKED_RECEIVE, conn, conn->stash.now, frame.count, uni);

    if (should_send_max_streams(conn, uni)) {
        quicly_maxsender_t *maxsender = uni ? &conn->ingress.max_streams.uni : &conn->ingress.max_streams.bidi;
        quicly_maxsender_request_transmit(maxsender);
        conn->egress.send_ack_at = 0;
    }

    return 0;
}

static int handle_max_streams_frame(quicly_conn_t *conn, struct st_quicly_handle_payload_state_t *state, int uni)
{
    quicly_max_streams_frame_t frame;
    int ret;

    if ((ret = quicly_decode_max_streams_frame(&state->src, state->end, &frame)) != 0)
        return ret;

    QUICLY_PROBE(MAX_STREAMS_RECEIVE, conn, conn->stash.now, frame.count, uni);

    if ((ret = update_max_streams(uni ? &conn->egress.max_streams.uni : &conn->egress.max_streams.bidi, frame.count)) != 0)
        return ret;

    open_blocked_streams(conn, uni);

    return 0;
}

static int handle_max_streams_bidi_frame(quicly_conn_t *conn, struct st_quicly_handle_payload_state_t *state)
{
    return handle_max_streams_frame(conn, state, 0);
}

static int handle_max_streams_uni_frame(quicly_conn_t *conn, struct st_quicly_handle_payload_state_t *state)
{
    return handle_max_streams_frame(conn, state, 1);
}

static int handle_path_challenge_frame(quicly_conn_t *conn, struct st_quicly_handle_payload_state_t *state)
{
    quicly_path_challenge_frame_t frame;
    int ret;

    if ((ret = quicly_decode_path_challenge_frame(&state->src, state->end, &frame)) != 0)
        return ret;
    return schedule_path_challenge_frame(conn, 1, frame.data);
}

static int handle_path_response_frame(quicly_conn_t *conn, struct st_quicly_handle_payload_state_t *state)
{
    return QUICLY_TRANSPORT_ERROR_PROTOCOL_VIOLATION;
}

static int handle_new_token_frame(quicly_conn_t *conn, struct st_quicly_handle_payload_state_t *state)
{
    quicly_new_token_frame_t frame;
    int ret;

    if ((ret = quicly_decode_new_token_frame(&state->src, state->end, &frame)) != 0)
        return ret;
    QUICLY_PROBE(NEW_TOKEN_RECEIVE, conn, conn->stash.now, frame.token.base, frame.token.len);
    if (conn->super.ctx->save_resumption_token == NULL)
        return 0;
    return conn->super.ctx->save_resumption_token->cb(conn->super.ctx->save_resumption_token, conn, frame.token);
}

static int handle_stop_sending_frame(quicly_conn_t *conn, struct st_quicly_handle_payload_state_t *state)
{
    quicly_stop_sending_frame_t frame;
    quicly_stream_t *stream;
    int ret;

    if ((ret = quicly_decode_stop_sending_frame(&state->src, state->end, &frame)) != 0)
        return ret;

    if ((ret = quicly_get_or_open_stream(conn, frame.stream_id, &stream)) != 0 || stream == NULL)
        return ret;

    if (quicly_sendstate_is_open(&stream->sendstate)) {
        /* reset the stream, then notify the application */
        int err = QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(frame.app_error_code);
        quicly_reset_stream(stream, err);
        QUICLY_PROBE(STREAM_ON_SEND_STOP, stream->conn, stream->conn->stash.now, stream, err);
        stream->callbacks->on_send_stop(stream, err);
        if (stream->conn->super.state >= QUICLY_STATE_CLOSING)
            return QUICLY_ERROR_IS_CLOSING;
    }

    return 0;
}

static int handle_max_data_frame(quicly_conn_t *conn, struct st_quicly_handle_payload_state_t *state)
{
    quicly_max_data_frame_t frame;
    int ret;

    if ((ret = quicly_decode_max_data_frame(&state->src, state->end, &frame)) != 0)
        return ret;

    QUICLY_PROBE(MAX_DATA_RECEIVE, conn, conn->stash.now, frame.max_data);

    if (frame.max_data <= conn->egress.max_data.permitted)
        return 0;
    conn->egress.max_data.permitted = frame.max_data;
    conn->egress.data_blocked = QUICLY_SENDER_STATE_UNACKED; /* DATA_BLOCKED has not been sent for the new limit */

    return 0;
}

static int negotiate_using_version(quicly_conn_t *conn, uint32_t version)
{
    int ret;

    /* set selected version */
    conn->super.version = version;
    QUICLY_PROBE(VERSION_SWITCH, conn, conn->stash.now, version);

    /* replace initial keys */
    if ((ret = reinstall_initial_encryption(conn, PTLS_ERROR_LIBRARY)) != 0)
        return ret;

    /* reschedule all the packets that have been sent for immediate resend */
    if ((ret = discard_sentmap_by_epoch(conn, ~0u)) != 0)
        return ret;

    return 0;
}

static int handle_version_negotiation_packet(quicly_conn_t *conn, quicly_decoded_packet_t *packet)
{
    const uint8_t *src = packet->octets.base + packet->encrypted_off, *end = packet->octets.base + packet->octets.len;
    uint32_t selected_version = 0;

    if (src == end || (end - src) % 4 != 0)
        return QUICLY_TRANSPORT_ERROR_PROTOCOL_VIOLATION;

    /* select in the precedence of _CURRENT -> _DRAFT27 -> fail */
    while (src != end) {
        uint32_t supported_version = quicly_decode32(&src);
        switch (supported_version) {
        case QUICLY_PROTOCOL_VERSION_CURRENT:
            selected_version = QUICLY_PROTOCOL_VERSION_CURRENT;
            break;
        case QUICLY_PROTOCOL_VERSION_DRAFT27:
            if (selected_version == 0)
                selected_version = QUICLY_PROTOCOL_VERSION_DRAFT27;
            break;
        }
    }
    if (selected_version == 0)
        return handle_close(conn, QUICLY_ERROR_NO_COMPATIBLE_VERSION, UINT64_MAX, ptls_iovec_init("", 0));

    return negotiate_using_version(conn, selected_version);
}

static int compare_socket_address(struct sockaddr *x, struct sockaddr *y)
{
#define CMP(a, b)                                                                                                                  \
    if (a != b)                                                                                                                    \
    return a < b ? -1 : 1

    CMP(x->sa_family, y->sa_family);

    if (x->sa_family == AF_INET) {
        struct sockaddr_in *xin = (void *)x, *yin = (void *)y;
        CMP(ntohl(xin->sin_addr.s_addr), ntohl(yin->sin_addr.s_addr));
        CMP(ntohs(xin->sin_port), ntohs(yin->sin_port));
    } else if (x->sa_family == AF_INET6) {
        struct sockaddr_in6 *xin6 = (void *)x, *yin6 = (void *)y;
        int r = memcmp(xin6->sin6_addr.s6_addr, yin6->sin6_addr.s6_addr, sizeof(xin6->sin6_addr.s6_addr));
        if (r != 0)
            return r;
        CMP(ntohs(xin6->sin6_port), ntohs(yin6->sin6_port));
        CMP(xin6->sin6_flowinfo, yin6->sin6_flowinfo);
        CMP(xin6->sin6_scope_id, yin6->sin6_scope_id);
    } else if (x->sa_family == AF_UNSPEC) {
        return 1;
    } else {
        assert(!"unknown sa_family");
    }

#undef CMP
    return 0;
}

static int is_stateless_reset(quicly_conn_t *conn, quicly_decoded_packet_t *decoded)
{
    switch (decoded->_is_stateless_reset_cached) {
    case QUICLY__DECODED_PACKET_CACHED_IS_STATELESS_RESET:
        return 1;
    case QUICLY__DECODED_PACKET_CACHED_NOT_STATELESS_RESET:
        return 0;
    default:
        break;
    }

    if (!conn->super.remote.cid_set.cids[0].is_active)
        return 0;
    if (decoded->octets.len < QUICLY_STATELESS_RESET_PACKET_MIN_LEN)
        return 0;
    if (memcmp(decoded->octets.base + decoded->octets.len - QUICLY_STATELESS_RESET_TOKEN_LEN,
               conn->super.remote.cid_set.cids[0].stateless_reset_token, QUICLY_STATELESS_RESET_TOKEN_LEN) != 0)
        return 0;

    return 1;
}

int quicly_is_destination(quicly_conn_t *conn, struct sockaddr *dest_addr, struct sockaddr *src_addr,
                          quicly_decoded_packet_t *decoded)
{
    if (QUICLY_PACKET_IS_LONG_HEADER(decoded->octets.base[0])) {
        /* long header: validate address, then consult the CID */
        if (compare_socket_address(&conn->super.remote.address.sa, src_addr) != 0)
            return 0;
        if (conn->super.local.address.sa.sa_family != AF_UNSPEC &&
            compare_socket_address(&conn->super.local.address.sa, dest_addr) != 0)
            return 0;
        /* server may see the CID generated by the client for Initial and 0-RTT packets */
        if (!quicly_is_client(conn) && decoded->cid.dest.might_be_client_generated) {
            const quicly_cid_t *odcid = is_retry(conn) ? &conn->retry_scid : &conn->super.original_dcid;
            if (quicly_cid_is_equal(odcid, decoded->cid.dest.encrypted))
                goto Found;
        }
    }

    if (conn->super.ctx->cid_encryptor != NULL) {
        /* Note on multiple CIDs
         * Multiple CIDs issued by this host are always based on the same 3-tuple (master_id, thread_id, node_id)
         * and the only difference is path_id. Therefore comparing the 3-tuple is enough to cover all CIDs issued by
         * this host.
         */
        if (conn->super.local.cid_set.plaintext.master_id == decoded->cid.dest.plaintext.master_id &&
            conn->super.local.cid_set.plaintext.thread_id == decoded->cid.dest.plaintext.thread_id &&
            conn->super.local.cid_set.plaintext.node_id == decoded->cid.dest.plaintext.node_id)
            goto Found;
        if (is_stateless_reset(conn, decoded))
            goto Found_StatelessReset;
    } else {
        if (compare_socket_address(&conn->super.remote.address.sa, src_addr) == 0)
            goto Found;
        if (conn->super.local.address.sa.sa_family != AF_UNSPEC &&
            compare_socket_address(&conn->super.local.address.sa, dest_addr) != 0)
            return 0;
    }

    /* not found */
    return 0;

Found:
    decoded->_is_stateless_reset_cached = QUICLY__DECODED_PACKET_CACHED_NOT_STATELESS_RESET;
    return 1;

Found_StatelessReset:
    decoded->_is_stateless_reset_cached = QUICLY__DECODED_PACKET_CACHED_IS_STATELESS_RESET;
    return 1;
}

int handle_close(quicly_conn_t *conn, int err, uint64_t frame_type, ptls_iovec_t reason_phrase)
{
    int ret;

    if (conn->super.state >= QUICLY_STATE_CLOSING)
        return 0;

    /* switch to closing state, notify the app (at this moment the streams are accessible), then destroy the streams */
    if ((ret = enter_close(conn, 0,
                           !(err == QUICLY_ERROR_RECEIVED_STATELESS_RESET || err == QUICLY_ERROR_NO_COMPATIBLE_VERSION))) != 0)
        return ret;
    if (conn->super.ctx->closed_by_remote != NULL)
        conn->super.ctx->closed_by_remote->cb(conn->super.ctx->closed_by_remote, conn, err, frame_type,
                                              (const char *)reason_phrase.base, reason_phrase.len);
    destroy_all_streams(conn, err, 0);

    return 0;
}

static int handle_transport_close_frame(quicly_conn_t *conn, struct st_quicly_handle_payload_state_t *state)
{
    quicly_transport_close_frame_t frame;
    int ret;

    if ((ret = quicly_decode_transport_close_frame(&state->src, state->end, &frame)) != 0)
        return ret;

    QUICLY_PROBE(TRANSPORT_CLOSE_RECEIVE, conn, conn->stash.now, frame.error_code, frame.frame_type,
                 QUICLY_PROBE_ESCAPE_UNSAFE_STRING(frame.reason_phrase.base, frame.reason_phrase.len));
    return handle_close(conn, QUICLY_ERROR_FROM_TRANSPORT_ERROR_CODE(frame.error_code), frame.frame_type, frame.reason_phrase);
}

static int handle_application_close_frame(quicly_conn_t *conn, struct st_quicly_handle_payload_state_t *state)
{
    quicly_application_close_frame_t frame;
    int ret;

    if ((ret = quicly_decode_application_close_frame(&state->src, state->end, &frame)) != 0)
        return ret;

    QUICLY_PROBE(APPLICATION_CLOSE_RECEIVE, conn, conn->stash.now, frame.error_code,
                 QUICLY_PROBE_ESCAPE_UNSAFE_STRING(frame.reason_phrase.base, frame.reason_phrase.len));
    return handle_close(conn, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(frame.error_code), UINT64_MAX, frame.reason_phrase);
}

static int handle_padding_frame(quicly_conn_t *conn, struct st_quicly_handle_payload_state_t *state)
{
    return 0;
}

static int handle_ping_frame(quicly_conn_t *conn, struct st_quicly_handle_payload_state_t *state)
{
    QUICLY_PROBE(PING_RECEIVE, conn, conn->stash.now);

    return 0;
}

static int handle_new_connection_id_frame(quicly_conn_t *conn, struct st_quicly_handle_payload_state_t *state)
{
    int ret;
    quicly_new_connection_id_frame_t frame;

    /* TODO: return error when using zero-length CID */

    if ((ret = quicly_decode_new_connection_id_frame(&state->src, state->end, &frame)) != 0)
        return ret;

    QUICLY_PROBE(NEW_CONNECTION_ID_RECEIVE, conn, conn->stash.now, frame.sequence, frame.retire_prior_to,
                 QUICLY_PROBE_HEXDUMP(frame.cid.base, frame.cid.len),
                 QUICLY_PROBE_HEXDUMP(frame.stateless_reset_token, QUICLY_STATELESS_RESET_TOKEN_LEN));

    if (frame.sequence < conn->super.remote.largest_retire_prior_to) {
        /* An endpoint that receives a NEW_CONNECTION_ID frame with a sequence number smaller than the Retire Prior To
         * field of a previously received NEW_CONNECTION_ID frame MUST send a corresponding RETIRE_CONNECTION_ID frame
         * that retires the newly received connection ID, unless it has already done so for that sequence number. (19.15)
         * TODO: "unless ..." part may not be properly addressed here (we may already have sent the RCID frame for this
         * sequence) */
        schedule_retire_connection_id_frame(conn, frame.sequence);
        /* do not install this CID */
        return 0;
    }

    uint64_t unregistered_seqs[QUICLY_LOCAL_ACTIVE_CONNECTION_ID_LIMIT];
    size_t num_unregistered_seqs;
    if ((ret = quicly_remote_cid_register(&conn->super.remote.cid_set, frame.sequence, frame.cid.base, frame.cid.len,
                                          frame.stateless_reset_token, frame.retire_prior_to, unregistered_seqs,
                                          &num_unregistered_seqs)) != 0)
        return ret;

    for (size_t i = 0; i < num_unregistered_seqs; i++)
        schedule_retire_connection_id_frame(conn, unregistered_seqs[i]);

    if (frame.retire_prior_to > conn->super.remote.largest_retire_prior_to)
        conn->super.remote.largest_retire_prior_to = frame.retire_prior_to;

    return 0;
}

static int handle_retire_connection_id_frame(quicly_conn_t *conn, struct st_quicly_handle_payload_state_t *state)
{
    int ret, has_pending;
    quicly_retire_connection_id_frame_t frame;

    if ((ret = quicly_decode_retire_connection_id_frame(&state->src, state->end, &frame)) != 0)
        return ret;

    QUICLY_PROBE(RETIRE_CONNECTION_ID_RECEIVE, conn, conn->stash.now, frame.sequence);

    if (frame.sequence >= conn->super.local.cid_set.plaintext.path_id) {
        /* Receipt of a RETIRE_CONNECTION_ID frame containing a sequence number greater than any previously sent to the remote peer
         * MUST be treated as a connection error of type PROTOCOL_VIOLATION. (19.16) */
        return QUICLY_TRANSPORT_ERROR_PROTOCOL_VIOLATION;
    }

    if ((ret = quicly_local_cid_retire(&conn->super.local.cid_set, frame.sequence, &has_pending)) != 0)
        return ret;
    if (has_pending)
        conn->egress.pending_flows |= QUICLY_PENDING_FLOW_CID_FRAME_BIT;

    return 0;
}

static int handle_handshake_done_frame(quicly_conn_t *conn, struct st_quicly_handle_payload_state_t *state)
{
    int ret;

    QUICLY_PROBE(HANDSHAKE_DONE_RECEIVE, conn, conn->stash.now);

    if (!quicly_is_client(conn))
        return QUICLY_TRANSPORT_ERROR_PROTOCOL_VIOLATION;

    assert(conn->initial == NULL);
    if (conn->handshake == NULL)
        return 0;

    conn->super.remote.address_validation.send_probe = 0;
    if ((ret = discard_handshake_context(conn, QUICLY_EPOCH_HANDSHAKE)) != 0)
        return ret;
    update_loss_alarm(conn, 0);
    return 0;
}

static int handle_datagram_frame(quicly_conn_t *conn, struct st_quicly_handle_payload_state_t *state)
{
    quicly_datagram_frame_t frame;
    int ret;

    /* check if we advertised support for DATAGRAM frames on this connection */
    if (conn->super.ctx->transport_params.max_datagram_frame_size == 0)
        return QUICLY_TRANSPORT_ERROR_FRAME_ENCODING;

    /* decode the frame */
    if ((ret = quicly_decode_datagram_frame(state->frame_type, &state->src, state->end, &frame)) != 0)
        return ret;
    QUICLY_PROBE(DATAGRAM_RECEIVE, conn, conn->stash.now, frame.payload.base, frame.payload.len);

    /* handle the frame. Applications might call quicly_close or other functions that modify the connection state. */
    conn->super.ctx->receive_datagram_frame->cb(conn->super.ctx->receive_datagram_frame, conn, frame.payload);

    return 0;
}

static int handle_ack_frequency_frame(quicly_conn_t *conn, struct st_quicly_handle_payload_state_t *state)
{
    quicly_ack_frequency_frame_t frame;
    int ret;

    /* recognize the frame only when the support has been advertised */
    if (!recognize_delayed_ack(conn))
        return QUICLY_TRANSPORT_ERROR_FRAME_ENCODING;

    if ((ret = quicly_decode_ack_frequency_frame(&state->src, state->end, &frame)) != 0)
        return ret;

    QUICLY_PROBE(ACK_FREQUENCY_RECEIVE, conn, conn->stash.now, frame.sequence, frame.packet_tolerance, frame.max_ack_delay,
                 frame.ignore_order);

    /* At the moment, the only value that the remote peer would send is this value, because our TP.min_ack_delay and max_ack_delay
     * are equal. */
    if (frame.max_ack_delay != QUICLY_LOCAL_MAX_ACK_DELAY * 1000)
        return QUICLY_TRANSPORT_ERROR_PROTOCOL_VIOLATION;

    if (frame.sequence >= conn->ingress.ack_frequency.next_sequence) {
        conn->ingress.ack_frequency.next_sequence = frame.sequence + 1;
        conn->application->super.packet_tolerance =
            (uint32_t)(frame.packet_tolerance < QUICLY_MAX_PACKET_TOLERANCE ? frame.packet_tolerance : QUICLY_MAX_PACKET_TOLERANCE);
        conn->application->super.ignore_order = frame.ignore_order;
    }

    return 0;
}

static int handle_payload(quicly_conn_t *conn, size_t epoch, const uint8_t *_src, size_t _len, uint64_t *offending_frame_type,
                          int *is_ack_only)
{
    /* clang-format off */

    /* `frame_handlers` is an array of frame handlers and the properties of the frames, indexed by the ID of the frame. */
    static const struct st_quicly_frame_handler_t {
        int (*cb)(quicly_conn_t *, struct st_quicly_handle_payload_state_t *); /* callback function that handles the frame */
        uint8_t permitted_epochs;  /* the epochs the frame can appear, calculated as bitwise-or of `1 << epoch` */
        uint8_t ack_eliciting;     /* boolean indicating if the frame is ack-eliciting */
        size_t counter_offset;     /* offset of corresponding `conn->super.stats.num_frames_received.type` within quicly_conn_t */
    } frame_handlers[] = {
#define FRAME(n, i, z, h, o, ae)                                                                                                   \
    {                                                                                                                              \
        handle_##n##_frame,                                                                                                        \
        (i << QUICLY_EPOCH_INITIAL) | (z << QUICLY_EPOCH_0RTT) | (h << QUICLY_EPOCH_HANDSHAKE) | (o << QUICLY_EPOCH_1RTT),         \
        ae,                                                                                                                        \
        offsetof(quicly_conn_t, super.stats.num_frames_received.n)                                                                 \
    }
        /*   +----------------------+-------------------+---------------+
         *   |                      |  permitted epochs |               |
         *   |        frame         +----+----+----+----+ ack-eliciting |
         *   |                      | IN | 0R | HS | 1R |               |
         *   +----------------------+----+----+----+----+---------------+ */
        FRAME( padding              ,  1 ,  1 ,  1 ,  1 ,             0 ), /* 0 */
        FRAME( ping                 ,  1 ,  1 ,  1 ,  1 ,             1 ),
        FRAME( ack                  ,  1 ,  0 ,  1 ,  1 ,             0 ),
        FRAME( ack                  ,  1 ,  0 ,  1 ,  1 ,             0 ),
        FRAME( reset_stream         ,  0 ,  1 ,  0 ,  1 ,             1 ),
        FRAME( stop_sending         ,  0 ,  1 ,  0 ,  1 ,             1 ),
        FRAME( crypto               ,  1 ,  0 ,  1 ,  1 ,             1 ),
        FRAME( new_token            ,  0 ,  0 ,  0 ,  1 ,             1 ),
        FRAME( stream               ,  0 ,  1 ,  0 ,  1 ,             1 ), /* 8 */
        FRAME( stream               ,  0 ,  1 ,  0 ,  1 ,             1 ),
        FRAME( stream               ,  0 ,  1 ,  0 ,  1 ,             1 ),
        FRAME( stream               ,  0 ,  1 ,  0 ,  1 ,             1 ),
        FRAME( stream               ,  0 ,  1 ,  0 ,  1 ,             1 ),
        FRAME( stream               ,  0 ,  1 ,  0 ,  1 ,             1 ),
        FRAME( stream               ,  0 ,  1 ,  0 ,  1 ,             1 ),
        FRAME( stream               ,  0 ,  1 ,  0 ,  1 ,             1 ),
        FRAME( max_data             ,  0 ,  1 ,  0 ,  1 ,             1 ), /* 16 */
        FRAME( max_stream_data      ,  0 ,  1 ,  0 ,  1 ,             1 ),
        FRAME( max_streams_bidi     ,  0 ,  1 ,  0 ,  1 ,             1 ),
        FRAME( max_streams_uni      ,  0 ,  1 ,  0 ,  1 ,             1 ),
        FRAME( data_blocked         ,  0 ,  1 ,  0 ,  1 ,             1 ),
        FRAME( stream_data_blocked  ,  0 ,  1 ,  0 ,  1 ,             1 ),
        FRAME( streams_blocked      ,  0 ,  1 ,  0 ,  1 ,             1 ),
        FRAME( streams_blocked      ,  0 ,  1 ,  0 ,  1 ,             1 ),
        FRAME( new_connection_id    ,  0 ,  1 ,  0 ,  1 ,             1 ), /* 24 */
        FRAME( retire_connection_id ,  0 ,  0 ,  0 ,  1 ,             1 ),
        FRAME( path_challenge       ,  0 ,  1 ,  0 ,  1 ,             1 ),
        FRAME( path_response        ,  0 ,  0 ,  0 ,  1 ,             1 ),
        FRAME( transport_close      ,  1 ,  1 ,  1 ,  1 ,             0 ),
        FRAME( application_close    ,  0 ,  1 ,  0 ,  1 ,             0 ),
        FRAME( handshake_done       ,  0,   0 ,  0 ,  1 ,             1 ),
        /*   +----------------------+----+----+----+----+---------------+ */
#undef FRAME
    };
    static const struct {
        uint64_t type;
        struct st_quicly_frame_handler_t _;
    } ex_frame_handlers[] = {
#define FRAME(uc, lc, i, z, h, o, ae)                                                                                              \
    {                                                                                                                              \
        QUICLY_FRAME_TYPE_##uc,                                                                                                    \
        {                                                                                                                          \
            handle_##lc##_frame,                                                                                                   \
            (i << QUICLY_EPOCH_INITIAL) | (z << QUICLY_EPOCH_0RTT) | (h << QUICLY_EPOCH_HANDSHAKE) | (o << QUICLY_EPOCH_1RTT),     \
            ae,                                                                                                                    \
            offsetof(quicly_conn_t, super.stats.num_frames_received.lc) \
        },                                                                                                                         \
    }
        /*   +----------------------------------+-------------------+---------------+
         *   |               frame              |  permitted epochs |               |
         *   |------------------+---------------+----+----+----+----+ ack-eliciting |
         *   |    upper-case    |  lower-case   | IN | 0R | HS | 1R |               |
         *   +------------------+---------------+----+----+----+----+---------------+ */
        FRAME( DATAGRAM_NOLEN   , datagram      ,  0 ,  1,   0,   1 ,             1 ),
        FRAME( DATAGRAM_WITHLEN , datagram      ,  0 ,  1,   0,   1 ,             1 ),
        FRAME( ACK_FREQUENCY    , ack_frequency ,  0 ,  0 ,  0 ,  1 ,             1 ),
        /*   +------------------+---------------+-------------------+---------------+ */
#undef FRAME
        {UINT64_MAX},
    };
    /* clang-format on */

    struct st_quicly_handle_payload_state_t state = {_src, _src + _len, epoch};
    size_t num_frames_ack_eliciting = 0;
    int ret;

    do {
        /* determine the frame type; fast path is available for frame types below 64 */
        const struct st_quicly_frame_handler_t *frame_handler;
        state.frame_type = *state.src++;
        if (state.frame_type < PTLS_ELEMENTSOF(frame_handlers)) {
            frame_handler = frame_handlers + state.frame_type;
        } else {
            /* slow path */
            --state.src;
            if ((state.frame_type = quicly_decodev(&state.src, state.end)) == UINT64_MAX) {
                state.frame_type =
                    QUICLY_FRAME_TYPE_PADDING; /* we cannot signal the offending frame type when failing to decode the frame type */
                ret = QUICLY_TRANSPORT_ERROR_FRAME_ENCODING;
                break;
            }
            size_t i;
            for (i = 0; ex_frame_handlers[i].type < state.frame_type; ++i)
                ;
            if (ex_frame_handlers[i].type != state.frame_type) {
                ret = QUICLY_TRANSPORT_ERROR_FRAME_ENCODING; /* not found */
                break;
            }
            frame_handler = &ex_frame_handlers[i]._;
        }
        /* check if frame is allowed, then process */
        if ((frame_handler->permitted_epochs & (1 << epoch)) == 0) {
            ret = QUICLY_TRANSPORT_ERROR_PROTOCOL_VIOLATION;
            break;
        }
        ++*(uint64_t *)((uint8_t *)conn + frame_handler->counter_offset);
        num_frames_ack_eliciting += frame_handler->ack_eliciting;
        if ((ret = frame_handler->cb(conn, &state)) != 0)
            break;
    } while (state.src != state.end);

    *is_ack_only = num_frames_ack_eliciting == 0;
    if (ret != 0)
        *offending_frame_type = state.frame_type;
    return ret;
}

static int handle_stateless_reset(quicly_conn_t *conn)
{
    QUICLY_PROBE(STATELESS_RESET_RECEIVE, conn, conn->stash.now);
    return handle_close(conn, QUICLY_ERROR_RECEIVED_STATELESS_RESET, UINT64_MAX, ptls_iovec_init("", 0));
}

static int validate_retry_tag(quicly_decoded_packet_t *packet, quicly_cid_t *odcid, ptls_aead_context_t *retry_aead)
{
    size_t pseudo_packet_len = 1 + odcid->len + packet->encrypted_off;
    uint8_t pseudo_packet[pseudo_packet_len];
    pseudo_packet[0] = odcid->len;
    memcpy(pseudo_packet + 1, odcid->cid, odcid->len);
    memcpy(pseudo_packet + 1 + odcid->len, packet->octets.base, packet->encrypted_off);
    return ptls_aead_decrypt(retry_aead, packet->octets.base + packet->encrypted_off, packet->octets.base + packet->encrypted_off,
                             PTLS_AESGCM_TAG_SIZE, 0, pseudo_packet, pseudo_packet_len) == 0;
}

int quicly_accept(quicly_conn_t **conn, quicly_context_t *ctx, struct sockaddr *dest_addr, struct sockaddr *src_addr,
                  quicly_decoded_packet_t *packet, quicly_address_token_plaintext_t *address_token,
                  const quicly_cid_plaintext_t *new_cid, ptls_handshake_properties_t *handshake_properties)
{
    const struct st_ptls_salt_t *salt;
    struct st_quicly_cipher_context_t ingress_cipher = {NULL}, egress_cipher = {NULL};
    ptls_iovec_t payload;
    uint64_t next_expected_pn, pn, offending_frame_type = QUICLY_FRAME_TYPE_PADDING;
    int is_ack_only, ret;

    *conn = NULL;

    /* process initials only */
    if ((packet->octets.base[0] & QUICLY_PACKET_TYPE_BITMASK) != QUICLY_PACKET_TYPE_INITIAL) {
        ret = QUICLY_ERROR_PACKET_IGNORED;
        goto Exit;
    }
    if ((salt = get_salt(packet->version)) == NULL) {
        ret = QUICLY_ERROR_PACKET_IGNORED;
        goto Exit;
    }
    if (packet->datagram_size < QUICLY_MIN_CLIENT_INITIAL_SIZE) {
        ret = QUICLY_ERROR_PACKET_IGNORED;
        goto Exit;
    }
    if (packet->cid.dest.encrypted.len < 8) {
        ret = QUICLY_TRANSPORT_ERROR_PROTOCOL_VIOLATION;
        goto Exit;
    }
    if ((ret = setup_initial_encryption(get_aes128gcmsha256(ctx), &ingress_cipher, &egress_cipher, packet->cid.dest.encrypted, 0,
                                        ptls_iovec_init(salt->initial, sizeof(salt->initial)), NULL)) != 0)
        goto Exit;
    next_expected_pn = 0; /* is this correct? do we need to take care of underflow? */
    if ((ret = decrypt_packet(ingress_cipher.header_protection, aead_decrypt_fixed_key, ingress_cipher.aead, &next_expected_pn,
                              packet, &pn, &payload)) != 0) {
        ret = QUICLY_ERROR_DECRYPTION_FAILED;
        goto Exit;
    }

    /* create connection */
    if ((*conn = create_connection(ctx, packet->version, NULL, src_addr, dest_addr, &packet->cid.src, new_cid, handshake_properties,
                                   quicly_cc_calc_initial_cwnd(ctx->transport_params.max_udp_payload_size))) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }
    (*conn)->super.state = QUICLY_STATE_ACCEPTING;
    quicly_set_cid(&(*conn)->super.original_dcid, packet->cid.dest.encrypted);
    if (address_token != NULL) {
        (*conn)->super.remote.address_validation.validated = 1;
        if (address_token->type == QUICLY_ADDRESS_TOKEN_TYPE_RETRY) {
            (*conn)->retry_scid = (*conn)->super.original_dcid;
            (*conn)->super.original_dcid = address_token->retry.original_dcid;
        }
    }
    if ((ret = setup_handshake_space_and_flow(*conn, QUICLY_EPOCH_INITIAL)) != 0)
        goto Exit;
    (*conn)->initial->super.next_expected_packet_number = next_expected_pn;
    (*conn)->initial->cipher.ingress = ingress_cipher;
    ingress_cipher = (struct st_quicly_cipher_context_t){NULL};
    (*conn)->initial->cipher.egress = egress_cipher;
    egress_cipher = (struct st_quicly_cipher_context_t){NULL};
    (*conn)->crypto.handshake_properties.collected_extensions = server_collected_extensions;
    (*conn)->initial->largest_ingress_udp_payload_size = packet->datagram_size;

    QUICLY_PROBE(ACCEPT, *conn, (*conn)->stash.now,
                 QUICLY_PROBE_HEXDUMP(packet->cid.dest.encrypted.base, packet->cid.dest.encrypted.len), address_token);
    QUICLY_PROBE(PACKET_RECEIVED, *conn, (*conn)->stash.now, pn, payload.base, payload.len, get_epoch(packet->octets.base[0]));

    /* handle the input; we ignore is_ack_only, we consult if there's any output from TLS in response to CH anyways */
    (*conn)->super.stats.num_packets.received += 1;
    (*conn)->super.stats.num_bytes.received += packet->datagram_size;
    if ((ret = handle_payload(*conn, QUICLY_EPOCH_INITIAL, payload.base, payload.len, &offending_frame_type, &is_ack_only)) != 0)
        goto Exit;
    if ((ret = record_receipt(&(*conn)->initial->super, pn, 0, (*conn)->stash.now, &(*conn)->egress.send_ack_at)) != 0)
        goto Exit;

Exit:
    if (*conn != NULL) {
        if (ret == 0) {
            (*conn)->super.state = QUICLY_STATE_CONNECTED;
        } else {
            initiate_close(*conn, ret, offending_frame_type, "");
            ret = 0;
        }
        unlock_now(*conn);
    }
    return ret;
}

int quicly_receive(quicly_conn_t *conn, struct sockaddr *dest_addr, struct sockaddr *src_addr, quicly_decoded_packet_t *packet)
{
    ptls_cipher_context_t *header_protection;
    struct {
        int (*cb)(void *, uint64_t, quicly_decoded_packet_t *, size_t, size_t *);
        void *ctx;
    } aead;
    struct st_quicly_pn_space_t **space;
    size_t epoch;
    ptls_iovec_t payload;
    uint64_t pn, offending_frame_type = QUICLY_FRAME_TYPE_PADDING;
    int is_ack_only, ret;

    assert(src_addr->sa_family == AF_INET || src_addr->sa_family == AF_INET6);

    lock_now(conn, 0);

    QUICLY_PROBE(RECEIVE, conn, conn->stash.now,
                 QUICLY_PROBE_HEXDUMP(packet->cid.dest.encrypted.base, packet->cid.dest.encrypted.len), packet->octets.base,
                 packet->octets.len);

    if (is_stateless_reset(conn, packet)) {
        ret = handle_stateless_reset(conn);
        goto Exit;
    }

    /* FIXME check peer address */

    /* add unconditionally, as packet->datagram_size is set only for the first packet within the UDP datagram */
    conn->super.stats.num_bytes.received += packet->datagram_size;

    switch (conn->super.state) {
    case QUICLY_STATE_CLOSING:
        ++conn->egress.connection_close.num_packets_received;
        /* respond with a CONNECTION_CLOSE frame using exponential back-off */
        if (__builtin_popcountl(conn->egress.connection_close.num_packets_received) == 1)
            conn->egress.send_ack_at = 0;
        ret = 0;
        goto Exit;
    case QUICLY_STATE_DRAINING:
        ret = 0;
        goto Exit;
    default:
        break;
    }

    if (QUICLY_PACKET_IS_LONG_HEADER(packet->octets.base[0])) {
        if (conn->super.state == QUICLY_STATE_FIRSTFLIGHT) {
            if (packet->version == 0) {
                ret = handle_version_negotiation_packet(conn, packet);
                goto Exit;
            }
        }
        if (packet->version != conn->super.version) {
            ret = QUICLY_ERROR_PACKET_IGNORED;
            goto Exit;
        }
        switch (packet->octets.base[0] & QUICLY_PACKET_TYPE_BITMASK) {
        case QUICLY_PACKET_TYPE_RETRY: {
            assert(packet->encrypted_off + PTLS_AESGCM_TAG_SIZE == packet->octets.len);
            /* handle only if the connection is the client */
            if (!quicly_is_client(conn)) {
                ret = QUICLY_ERROR_PACKET_IGNORED;
                goto Exit;
            }
            /* server CID has to change */
            if (quicly_cid_is_equal(&conn->super.remote.cid_set.cids[0].cid, packet->cid.src)) {
                ret = QUICLY_ERROR_PACKET_IGNORED;
                goto Exit;
            }
            /* do not accept a second Retry */
            if (is_retry(conn)) {
                ret = QUICLY_ERROR_PACKET_IGNORED;
                goto Exit;
            }
            ptls_aead_context_t *retry_aead = create_retry_aead(conn->super.ctx, conn->super.version, 0);
            int retry_ok = validate_retry_tag(packet, &conn->super.remote.cid_set.cids[0].cid, retry_aead);
            ptls_aead_free(retry_aead);
            if (!retry_ok) {
                ret = QUICLY_ERROR_PACKET_IGNORED;
                goto Exit;
            }
            /* check size of the Retry packet */
            if (packet->token.len > QUICLY_MAX_TOKEN_LEN) {
                ret = QUICLY_ERROR_PACKET_IGNORED; /* TODO this is a immediate fatal error, chose a better error code */
                goto Exit;
            }
            /* store token and ODCID */
            free(conn->token.base);
            if ((conn->token.base = malloc(packet->token.len)) == NULL) {
                ret = PTLS_ERROR_NO_MEMORY;
                goto Exit;
            }
            memcpy(conn->token.base, packet->token.base, packet->token.len);
            conn->token.len = packet->token.len;
            /* update DCID */
            quicly_set_cid(&conn->super.remote.cid_set.cids[0].cid, packet->cid.src);
            conn->retry_scid = conn->super.remote.cid_set.cids[0].cid;
            /* replace initial keys, or drop the keys if this is a response packet to a greased version */
            if ((ret = reinstall_initial_encryption(conn, QUICLY_ERROR_PACKET_IGNORED)) != 0)
                goto Exit;
            /* schedule retransmit */
            ret = discard_sentmap_by_epoch(conn, ~0u);
            goto Exit;
        } break;
        case QUICLY_PACKET_TYPE_INITIAL:
            if (conn->initial == NULL || (header_protection = conn->initial->cipher.ingress.header_protection) == NULL) {
                ret = QUICLY_ERROR_PACKET_IGNORED;
                goto Exit;
            }
            if (quicly_is_client(conn)) {
                /* client: update cid if this is the first Initial packet that's being received */
                if (conn->super.state == QUICLY_STATE_FIRSTFLIGHT)
                    quicly_set_cid(&conn->super.remote.cid_set.cids[0].cid, packet->cid.src);
            } else {
                /* server: ignore packets that are too small */
                if (packet->datagram_size < QUICLY_MIN_CLIENT_INITIAL_SIZE) {
                    ret = QUICLY_ERROR_PACKET_IGNORED;
                    goto Exit;
                }
            }
            aead.cb = aead_decrypt_fixed_key;
            aead.ctx = conn->initial->cipher.ingress.aead;
            space = (void *)&conn->initial;
            epoch = QUICLY_EPOCH_INITIAL;
            break;
        case QUICLY_PACKET_TYPE_HANDSHAKE:
            if (conn->handshake == NULL || (header_protection = conn->handshake->cipher.ingress.header_protection) == NULL) {
                ret = QUICLY_ERROR_PACKET_IGNORED;
                goto Exit;
            }
            aead.cb = aead_decrypt_fixed_key;
            aead.ctx = conn->handshake->cipher.ingress.aead;
            space = (void *)&conn->handshake;
            epoch = QUICLY_EPOCH_HANDSHAKE;
            break;
        case QUICLY_PACKET_TYPE_0RTT:
            if (quicly_is_client(conn)) {
                ret = QUICLY_ERROR_PACKET_IGNORED;
                goto Exit;
            }
            if (conn->application == NULL ||
                (header_protection = conn->application->cipher.ingress.header_protection.zero_rtt) == NULL) {
                ret = QUICLY_ERROR_PACKET_IGNORED;
                goto Exit;
            }
            aead.cb = aead_decrypt_fixed_key;
            aead.ctx = conn->application->cipher.ingress.aead[1];
            space = (void *)&conn->application;
            epoch = QUICLY_EPOCH_0RTT;
            break;
        default:
            ret = QUICLY_ERROR_PACKET_IGNORED;
            goto Exit;
        }
    } else {
        /* short header packet */
        if (conn->application == NULL ||
            (header_protection = conn->application->cipher.ingress.header_protection.one_rtt) == NULL) {
            ret = QUICLY_ERROR_PACKET_IGNORED;
            goto Exit;
        }
        aead.cb = aead_decrypt_1rtt;
        aead.ctx = conn;
        space = (void *)&conn->application;
        epoch = QUICLY_EPOCH_1RTT;
    }

    /* decrypt */
    if ((ret = decrypt_packet(header_protection, aead.cb, aead.ctx, &(*space)->next_expected_packet_number, packet, &pn,
                              &payload)) != 0) {
        ++conn->super.stats.num_packets.decryption_failed;
        QUICLY_PROBE(PACKET_DECRYPTION_FAILED, conn, conn->stash.now, pn);
        goto Exit;
    }

    QUICLY_PROBE(PACKET_RECEIVED, conn, conn->stash.now, pn, payload.base, payload.len, get_epoch(packet->octets.base[0]));

    /* update states */
    if (conn->super.state == QUICLY_STATE_FIRSTFLIGHT)
        conn->super.state = QUICLY_STATE_CONNECTED;
    conn->super.stats.num_packets.received += 1;

    /* state updates, that are triggered by the receipt of a packet */
    switch (epoch) {
    case QUICLY_EPOCH_INITIAL:
        /* update max_ingress_udp_payload_size if necessary */
        if (conn->initial->largest_ingress_udp_payload_size < packet->datagram_size)
            conn->initial->largest_ingress_udp_payload_size = packet->datagram_size;
        break;
    case QUICLY_EPOCH_HANDSHAKE:
        /* Discard Initial space before processing the payload of the Handshake packet to avoid the chance of an ACK frame included
         * in the Handshake packet setting a loss timer for the Initial packet. */
        if (conn->initial != NULL) {
            if ((ret = discard_handshake_context(conn, QUICLY_EPOCH_INITIAL)) != 0)
                goto Exit;
            update_loss_alarm(conn, 0);
            conn->super.remote.address_validation.validated = 1;
        }
        break;
    default:
        break;
    }

    /* handle the payload */
    if ((ret = handle_payload(conn, epoch, payload.base, payload.len, &offending_frame_type, &is_ack_only)) != 0)
        goto Exit;
    if (*space != NULL && conn->super.state < QUICLY_STATE_CLOSING) {
        if ((ret = record_receipt(*space, pn, is_ack_only, conn->stash.now, &conn->egress.send_ack_at)) != 0)
            goto Exit;
    }

    /* state updates post payload processing */
    switch (epoch) {
    case QUICLY_EPOCH_INITIAL:
        assert(conn->initial != NULL);
        if (quicly_is_client(conn) && conn->handshake != NULL && conn->handshake->cipher.egress.aead != NULL) {
            if ((ret = discard_handshake_context(conn, QUICLY_EPOCH_INITIAL)) != 0)
                goto Exit;
            update_loss_alarm(conn, 0);
        }
        break;
    case QUICLY_EPOCH_HANDSHAKE:
        if (quicly_is_client(conn)) {
            /* Running as a client.
             * Respect "disable_migration" TP sent by the remote peer at the end of the TLS handshake. */
            if (conn->super.local.address.sa.sa_family == AF_UNSPEC && dest_addr != NULL && dest_addr->sa_family != AF_UNSPEC &&
                ptls_handshake_is_complete(conn->crypto.tls) && conn->super.remote.transport_params.disable_active_migration)
                set_address(&conn->super.local.address, dest_addr);
        } else {
            /* Running as a server.
             * If handshake was just completed, drop handshake context, schedule the first emission of HANDSHAKE_DONE frame. */
            if (ptls_handshake_is_complete(conn->crypto.tls)) {
                if ((ret = discard_handshake_context(conn, QUICLY_EPOCH_HANDSHAKE)) != 0)
                    goto Exit;
                assert(conn->handshake == NULL);
                conn->egress.pending_flows |= QUICLY_PENDING_FLOW_HANDSHAKE_DONE_BIT;
                update_loss_alarm(conn, 0);
            }
        }
        break;
    case QUICLY_EPOCH_1RTT:
        if (!is_ack_only && should_send_max_data(conn))
            conn->egress.send_ack_at = 0;
        break;
    default:
        break;
    }

    update_idle_timeout(conn, 1);

Exit:
    switch (ret) {
    case 0:
        /* Avoid time in the past being emitted by quicly_get_first_timeout. We hit the condition below when retransmission is
         * suspended by the 3x limit (in which case we have loss.alarm_at set but return INT64_MAX from quicly_get_first_timeout
         * until we receive something from the client).
         */
        if (conn->egress.loss.alarm_at < conn->stash.now)
            conn->egress.loss.alarm_at = conn->stash.now;
        assert_consistency(conn, 0);
        break;
    case QUICLY_ERROR_PACKET_IGNORED:
        break;
    default: /* close connection */
        initiate_close(conn, ret, offending_frame_type, "");
        ret = 0;
        break;
    }
    unlock_now(conn);
    return ret;
}

int quicly_open_stream(quicly_conn_t *conn, quicly_stream_t **_stream, int uni)
{
    quicly_stream_t *stream;
    struct st_quicly_conn_streamgroup_state_t *group;
    uint64_t *max_stream_count;
    uint32_t max_stream_data_local;
    uint64_t max_stream_data_remote;
    int ret;

    /* determine the states */
    if (uni) {
        group = &conn->super.local.uni;
        max_stream_count = &conn->egress.max_streams.uni.count;
        max_stream_data_local = 0;
        max_stream_data_remote = conn->super.remote.transport_params.max_stream_data.uni;
    } else {
        group = &conn->super.local.bidi;
        max_stream_count = &conn->egress.max_streams.bidi.count;
        max_stream_data_local = (uint32_t)conn->super.ctx->transport_params.max_stream_data.bidi_local;
        max_stream_data_remote = conn->super.remote.transport_params.max_stream_data.bidi_remote;
    }

    /* open */
    if ((stream = open_stream(conn, group->next_stream_id, max_stream_data_local, max_stream_data_remote)) == NULL)
        return PTLS_ERROR_NO_MEMORY;
    ++group->num_streams;
    group->next_stream_id += 4;

    /* adjust blocked */
    if (stream->stream_id / 4 >= *max_stream_count) {
        stream->streams_blocked = 1;
        quicly_linklist_insert((uni ? &conn->egress.pending_streams.blocked.uni : &conn->egress.pending_streams.blocked.bidi)->prev,
                               &stream->_send_aux.pending_link.control);
    }

    /* application-layer initialization */
    QUICLY_PROBE(STREAM_ON_OPEN, conn, conn->stash.now, stream);
    if ((ret = conn->super.ctx->stream_open->cb(conn->super.ctx->stream_open, stream)) != 0)
        return ret;

    *_stream = stream;
    return 0;
}

void quicly_reset_stream(quicly_stream_t *stream, int err)
{
    assert(quicly_stream_has_send_side(quicly_is_client(stream->conn), stream->stream_id));
    assert(QUICLY_ERROR_IS_QUIC_APPLICATION(err));
    assert(stream->_send_aux.reset_stream.sender_state == QUICLY_SENDER_STATE_NONE);
    assert(!quicly_sendstate_transfer_complete(&stream->sendstate));

    /* dispose sendbuf state */
    quicly_sendstate_reset(&stream->sendstate);

    /* setup RESET_STREAM */
    stream->_send_aux.reset_stream.sender_state = QUICLY_SENDER_STATE_SEND;
    stream->_send_aux.reset_stream.error_code = QUICLY_ERROR_GET_ERROR_CODE(err);

    /* schedule for delivery */
    sched_stream_control(stream);
    resched_stream_data(stream);
}

void quicly_request_stop(quicly_stream_t *stream, int err)
{
    assert(quicly_stream_has_receive_side(quicly_is_client(stream->conn), stream->stream_id));
    assert(QUICLY_ERROR_IS_QUIC_APPLICATION(err));

    /* send STOP_SENDING if the incoming side of the stream is still open */
    if (stream->recvstate.eos == UINT64_MAX && stream->_send_aux.stop_sending.sender_state == QUICLY_SENDER_STATE_NONE) {
        stream->_send_aux.stop_sending.sender_state = QUICLY_SENDER_STATE_SEND;
        stream->_send_aux.stop_sending.error_code = QUICLY_ERROR_GET_ERROR_CODE(err);
        sched_stream_control(stream);
    }
}

socklen_t quicly_get_socklen(struct sockaddr *sa)
{
    switch (sa->sa_family) {
    case AF_INET:
        return sizeof(struct sockaddr_in);
    case AF_INET6:
        return sizeof(struct sockaddr_in6);
    default:
        assert(!"unexpected socket type");
        return 0;
    }
}

char *quicly_escape_unsafe_string(char *buf, const void *bytes, size_t len)
{
    char *dst = buf;
    const char *src = bytes, *end = src + len;

    for (; src != end; ++src) {
        if ((0x20 <= *src && *src <= 0x7e) && !(*src == '"' || *src == '\'' || *src == '\\')) {
            *dst++ = *src;
        } else {
            *dst++ = '\\';
            *dst++ = 'x';
            quicly_byte_to_hex(dst, (uint8_t)*src);
            dst += 2;
        }
    }
    *dst = '\0';

    return buf;
}

char *quicly_hexdump(const uint8_t *bytes, size_t len, size_t indent)
{
    size_t i, line, row, bufsize = indent == SIZE_MAX ? len * 2 + 1 : (indent + 5 + 3 * 16 + 2 + 16 + 1) * ((len + 15) / 16) + 1;
    char *buf, *p;

    if ((buf = malloc(bufsize)) == NULL)
        return NULL;
    p = buf;
    if (indent == SIZE_MAX) {
        for (i = 0; i != len; ++i) {
            quicly_byte_to_hex(p, bytes[i]);
            p += 2;
        }
    } else {
        for (line = 0; line * 16 < len; ++line) {
            for (i = 0; i < indent; ++i)
                *p++ = ' ';
            quicly_byte_to_hex(p, (line >> 4) & 0xff);
            p += 2;
            quicly_byte_to_hex(p, (line << 4) & 0xff);
            p += 2;
            *p++ = ' ';
            for (row = 0; row < 16; ++row) {
                *p++ = row == 8 ? '-' : ' ';
                if (line * 16 + row < len) {
                    quicly_byte_to_hex(p, bytes[line * 16 + row]);
                    p += 2;
                } else {
                    *p++ = ' ';
                    *p++ = ' ';
                }
            }
            *p++ = ' ';
            *p++ = ' ';
            for (row = 0; row < 16; ++row) {
                if (line * 16 + row < len) {
                    int ch = bytes[line * 16 + row];
                    *p++ = 0x20 <= ch && ch < 0x7f ? ch : '.';
                } else {
                    *p++ = ' ';
                }
            }
            *p++ = '\n';
        }
    }
    *p++ = '\0';

    assert(p - buf <= bufsize);

    return buf;
}

void quicly_amend_ptls_context(ptls_context_t *ptls)
{
    static ptls_update_traffic_key_t update_traffic_key = {update_traffic_key_cb};

    ptls->omit_end_of_early_data = 1;
    ptls->max_early_data_size = UINT32_MAX;
    ptls->update_traffic_key = &update_traffic_key;
}

int quicly_encrypt_address_token(void (*random_bytes)(void *, size_t), ptls_aead_context_t *aead, ptls_buffer_t *buf,
                                 size_t start_off, const quicly_address_token_plaintext_t *plaintext)
{
    int ret;

    /* type and IV */
    if ((ret = ptls_buffer_reserve(buf, 1 + aead->algo->iv_size)) != 0)
        goto Exit;
    buf->base[buf->off++] = plaintext->type;
    random_bytes(buf->base + buf->off, aead->algo->iv_size);
    buf->off += aead->algo->iv_size;

    size_t enc_start = buf->off;

    /* data */
    ptls_buffer_push64(buf, plaintext->issued_at);
    {
        uint16_t port;
        ptls_buffer_push_block(buf, 1, {
            switch (plaintext->remote.sa.sa_family) {
            case AF_INET:
                ptls_buffer_pushv(buf, &plaintext->remote.sin.sin_addr.s_addr, 4);
                port = ntohs(plaintext->remote.sin.sin_port);
                break;
            case AF_INET6:
                ptls_buffer_pushv(buf, &plaintext->remote.sin6.sin6_addr, 16);
                port = ntohs(plaintext->remote.sin6.sin6_port);
                break;
            default:
                assert(!"unspported address type");
                break;
            }
        });
        ptls_buffer_push16(buf, port);
    }
    switch (plaintext->type) {
    case QUICLY_ADDRESS_TOKEN_TYPE_RETRY:
        ptls_buffer_push_block(buf, 1,
                               { ptls_buffer_pushv(buf, plaintext->retry.original_dcid.cid, plaintext->retry.original_dcid.len); });
        ptls_buffer_push_block(buf, 1,
                               { ptls_buffer_pushv(buf, plaintext->retry.client_cid.cid, plaintext->retry.client_cid.len); });
        ptls_buffer_push_block(buf, 1,
                               { ptls_buffer_pushv(buf, plaintext->retry.server_cid.cid, plaintext->retry.server_cid.len); });
        break;
    case QUICLY_ADDRESS_TOKEN_TYPE_RESUMPTION:
        ptls_buffer_push_block(buf, 1, { ptls_buffer_pushv(buf, plaintext->resumption.bytes, plaintext->resumption.len); });
        break;
    default:
        assert(!"unexpected token type");
        abort();
    }
    ptls_buffer_push_block(buf, 1, { ptls_buffer_pushv(buf, plaintext->appdata.bytes, plaintext->appdata.len); });

    /* encrypt, abusing the internal API to supply full IV */
    if ((ret = ptls_buffer_reserve(buf, aead->algo->tag_size)) != 0)
        goto Exit;
    aead->algo->setup_crypto(aead, 1, NULL, buf->base + enc_start - aead->algo->iv_size);
    ptls_aead_encrypt(aead, buf->base + enc_start, buf->base + enc_start, buf->off - enc_start, 0, buf->base + start_off,
                      enc_start - start_off);
    buf->off += aead->algo->tag_size;

Exit:
    return ret;
}

int quicly_decrypt_address_token(ptls_aead_context_t *aead, quicly_address_token_plaintext_t *plaintext, const void *_token,
                                 size_t len, size_t prefix_len, const char **err_desc)
{
    const uint8_t *const token = _token;
    uint8_t ptbuf[QUICLY_MIN_CLIENT_INITIAL_SIZE];
    size_t ptlen;

    *err_desc = NULL;

    /* check if we can get type and decrypt */
    if (len < prefix_len + 1 + aead->algo->iv_size + aead->algo->tag_size) {
        *err_desc = "token too small";
        return PTLS_ALERT_DECODE_ERROR;
    }
    if (prefix_len + 1 + aead->algo->iv_size + sizeof(ptbuf) + aead->algo->tag_size < len) {
        *err_desc = "token too large";
        return PTLS_ALERT_DECODE_ERROR;
    }

    /* check type */
    switch (token[prefix_len]) {
    case QUICLY_ADDRESS_TOKEN_TYPE_RETRY:
        plaintext->type = QUICLY_ADDRESS_TOKEN_TYPE_RETRY;
        break;
    case QUICLY_ADDRESS_TOKEN_TYPE_RESUMPTION:
        plaintext->type = QUICLY_ADDRESS_TOKEN_TYPE_RESUMPTION;
        break;
    default:
        *err_desc = "unknown token type";
        return PTLS_ALERT_DECODE_ERROR;
    }

    /* `goto Exit` can only happen below this line, and that is guaranteed by declaring `ret` here */
    int ret;

    /* decrypt */
    aead->algo->setup_crypto(aead, 0, NULL, token + prefix_len + 1);
    if ((ptlen = ptls_aead_decrypt(aead, ptbuf, token + prefix_len + 1 + aead->algo->iv_size,
                                   len - (prefix_len + 1 + aead->algo->iv_size), 0, token, prefix_len + 1 + aead->algo->iv_size)) ==
        SIZE_MAX) {
        ret = PTLS_ALERT_DECRYPT_ERROR;
        *err_desc = "token decryption failure";
        goto Exit;
    }

    /* parse */
    const uint8_t *src = ptbuf, *end = src + ptlen;
    if ((ret = ptls_decode64(&plaintext->issued_at, &src, end)) != 0)
        goto Exit;
    {
        in_port_t *portaddr;
        ptls_decode_open_block(src, end, 1, {
            switch (end - src) {
            case 4: /* ipv4 */
                plaintext->remote.sin.sin_family = AF_INET;
                memcpy(&plaintext->remote.sin.sin_addr.s_addr, src, 4);
                portaddr = &plaintext->remote.sin.sin_port;
                break;
            case 16: /* ipv6 */
                plaintext->remote.sin6.sin6_family = AF_INET6;
                memcpy(&plaintext->remote.sin6.sin6_addr, src, 16);
                portaddr = &plaintext->remote.sin6.sin6_port;
                break;
            default:
                ret = PTLS_ALERT_DECODE_ERROR;
                goto Exit;
            }
            src = end;
        });
        uint16_t port;
        if ((ret = ptls_decode16(&port, &src, end)) != 0)
            goto Exit;
        *portaddr = htons(port);
    }
    switch (plaintext->type) {
    case QUICLY_ADDRESS_TOKEN_TYPE_RETRY:
#define DECODE_CID(field)                                                                                                          \
    do {                                                                                                                           \
        ptls_decode_open_block(src, end, 1, {                                                                                      \
            if (end - src > sizeof(plaintext->retry.field.cid)) {                                                                  \
                ret = PTLS_ALERT_DECODE_ERROR;                                                                                     \
                goto Exit;                                                                                                         \
            }                                                                                                                      \
            quicly_set_cid(&plaintext->retry.field, ptls_iovec_init(src, end - src));                                              \
            src = end;                                                                                                             \
        });                                                                                                                        \
    } while (0)
        DECODE_CID(original_dcid);
        DECODE_CID(client_cid);
        DECODE_CID(server_cid);
#undef DECODE_CID
        break;
    case QUICLY_ADDRESS_TOKEN_TYPE_RESUMPTION:
        ptls_decode_open_block(src, end, 1, {
            PTLS_BUILD_ASSERT(sizeof(plaintext->resumption.bytes) >= 256);
            plaintext->resumption.len = end - src;
            memcpy(plaintext->resumption.bytes, src, plaintext->resumption.len);
            src = end;
        });
        break;
    default:
        assert(!"unexpected token type");
        abort();
    }
    ptls_decode_block(src, end, 1, {
        PTLS_BUILD_ASSERT(sizeof(plaintext->appdata.bytes) >= 256);
        plaintext->appdata.len = end - src;
        memcpy(plaintext->appdata.bytes, src, plaintext->appdata.len);
        src = end;
    });
    ret = 0;

Exit:
    if (ret != 0) {
        if (*err_desc == NULL)
            *err_desc = "token decode error";
        /* promote the error to one that triggers the emission of INVALID_TOKEN_ERROR, if the token looked like a retry */
        if (plaintext->type == QUICLY_ADDRESS_TOKEN_TYPE_RETRY)
            ret = QUICLY_TRANSPORT_ERROR_INVALID_TOKEN;
    }
    return ret;
}

int quicly_build_session_ticket_auth_data(ptls_buffer_t *auth_data, const quicly_context_t *ctx)
{
    int ret;

#define PUSH_TP(id, block)                                                                                                         \
    do {                                                                                                                           \
        ptls_buffer_push_quicint(auth_data, id);                                                                                   \
        ptls_buffer_push_block(auth_data, -1, block);                                                                              \
    } while (0)

    ptls_buffer_push_block(auth_data, -1, {
        PUSH_TP(QUICLY_TRANSPORT_PARAMETER_ID_ACTIVE_CONNECTION_ID_LIMIT,
                { ptls_buffer_push_quicint(auth_data, ctx->transport_params.active_connection_id_limit); });
        PUSH_TP(QUICLY_TRANSPORT_PARAMETER_ID_INITIAL_MAX_DATA,
                { ptls_buffer_push_quicint(auth_data, ctx->transport_params.max_data); });
        PUSH_TP(QUICLY_TRANSPORT_PARAMETER_ID_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
                { ptls_buffer_push_quicint(auth_data, ctx->transport_params.max_stream_data.bidi_local); });
        PUSH_TP(QUICLY_TRANSPORT_PARAMETER_ID_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
                { ptls_buffer_push_quicint(auth_data, ctx->transport_params.max_stream_data.bidi_remote); });
        PUSH_TP(QUICLY_TRANSPORT_PARAMETER_ID_INITIAL_MAX_STREAM_DATA_UNI,
                { ptls_buffer_push_quicint(auth_data, ctx->transport_params.max_stream_data.uni); });
        PUSH_TP(QUICLY_TRANSPORT_PARAMETER_ID_INITIAL_MAX_STREAMS_BIDI,
                { ptls_buffer_push_quicint(auth_data, ctx->transport_params.max_streams_bidi); });
        PUSH_TP(QUICLY_TRANSPORT_PARAMETER_ID_INITIAL_MAX_STREAMS_UNI,
                { ptls_buffer_push_quicint(auth_data, ctx->transport_params.max_streams_uni); });
    });

#undef PUSH_TP

    ret = 0;
Exit:
    return ret;
}

void quicly_stream_noop_on_destroy(quicly_stream_t *stream, int err)
{
}

void quicly_stream_noop_on_send_shift(quicly_stream_t *stream, size_t delta)
{
}

void quicly_stream_noop_on_send_emit(quicly_stream_t *stream, size_t off, void *dst, size_t *len, int *wrote_all)
{
}

void quicly_stream_noop_on_send_stop(quicly_stream_t *stream, int err)
{
}

void quicly_stream_noop_on_receive(quicly_stream_t *stream, size_t off, const void *src, size_t len)
{
}

void quicly_stream_noop_on_receive_reset(quicly_stream_t *stream, int err)
{
}

const quicly_stream_callbacks_t quicly_stream_noop_callbacks = {
    quicly_stream_noop_on_destroy,   quicly_stream_noop_on_send_shift, quicly_stream_noop_on_send_emit,
    quicly_stream_noop_on_send_stop, quicly_stream_noop_on_receive,    quicly_stream_noop_on_receive_reset};

void quicly__debug_printf(quicly_conn_t *conn, const char *function, int line, const char *fmt, ...)
{
#if QUICLY_USE_EMBEDDED_PROBES || QUICLY_USE_DTRACE
    char buf[1024];
    va_list args;

    if (!QUICLY_DEBUG_MESSAGE_ENABLED())
        return;

    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    QUICLY_DEBUG_MESSAGE(conn, function, line, buf);
#endif
}

const uint32_t quicly_supported_versions[] = {QUICLY_PROTOCOL_VERSION_CURRENT, QUICLY_PROTOCOL_VERSION_DRAFT27, 0};
