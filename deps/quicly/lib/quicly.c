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
#include <string.h>
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

#define QUICLY_MIN_INITIAL_DCID_LEN 8

#define QUICLY_TLS_EXTENSION_TYPE_TRANSPORT_PARAMETERS 0xffa5
#define QUICLY_TRANSPORT_PARAMETER_ID_ORIGINAL_CONNECTION_ID 0
#define QUICLY_TRANSPORT_PARAMETER_ID_MAX_IDLE_TIMEOUT 1
#define QUICLY_TRANSPORT_PARAMETER_ID_STATELESS_RESET_TOKEN 2
#define QUICLY_TRANSPORT_PARAMETER_ID_MAX_PACKET_SIZE 3
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

#define QUICLY_EPOCH_INITIAL 0
#define QUICLY_EPOCH_0RTT 1
#define QUICLY_EPOCH_HANDSHAKE 2
#define QUICLY_EPOCH_1RTT 3

/**
 * maximum size of token that quicly accepts
 */
#define QUICLY_MAX_TOKEN_LEN 512
/**
 * do not try to send ACK-eliciting frames if the available CWND is below this value
 */
#define MIN_SEND_WINDOW 64
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
     * acks to be sent to peer
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
     * packet count before ack is sent
     */
    uint32_t unacked_count;
};

struct st_quicly_handshake_space_t {
    struct st_quicly_pn_space_t super;
    struct {
        struct st_quicly_cipher_context_t ingress;
        struct st_quicly_cipher_context_t egress;
    } cipher;
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
            quicly_maxsender_t *uni, *bidi;
        } max_streams;
    } ingress;
    /**
     *
     */
    struct {
        /**
         * contains actions that needs to be performed when an ack is being received
         */
        quicly_sentmap_t sentmap;
        /**
         * all packets where pn < max_lost_pn are deemed lost
         */
        uint64_t max_lost_pn;
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
        int64_t last_retransmittable_sent_at;
        /**
         * when to send an ACK, or other frames used for managing the connection
         */
        int64_t send_ack_at;
        /**
         *
         */
        quicly_cc_t cc;
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
     * contains things to be sent, that are covered by flow control, but not by the stream scheduler
     */
    struct {
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
        } streams;
        /**
         * bit vector indicating if there's any pending crypto data (the insignificant 4 bits), or other non-stream data
         */
        uint8_t flows;
#define QUICLY_PENDING_FLOW_NEW_TOKEN_BIT (1 << 5)
#define QUICLY_PENDING_FLOW_HANDSHAKE_DONE_BIT (1 << 6)
    } pending;
    /**
     * retry token (if the token is a Retry token can be determined by consulting the length of retry_odcid)
     */
    ptls_iovec_t token;
    /**
     * len=0 if not used
     */
    quicly_cid_t retry_odcid;
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
};

struct st_quicly_handle_payload_state_t {
    const uint8_t *src, *const end;
    size_t epoch;
    uint64_t frame_type;
};

static void crypto_stream_receive(quicly_stream_t *stream, size_t off, const void *src, size_t len);

static const quicly_stream_callbacks_t crypto_stream_callbacks = {quicly_streambuf_destroy, quicly_streambuf_egress_shift,
                                                                  quicly_streambuf_egress_emit, NULL, crypto_stream_receive};

static int update_traffic_key_cb(ptls_update_traffic_key_t *self, ptls_t *tls, int is_enc, size_t epoch, const void *secret);
static int initiate_close(quicly_conn_t *conn, int err, uint64_t frame_type, const char *reason_phrase);
static int discard_sentmap_by_epoch(quicly_conn_t *conn, unsigned ack_epochs);

static const quicly_transport_parameters_t default_transport_params = {
    {0, 0, 0}, 0, 0, 0, 0, QUICLY_DEFAULT_ACK_DELAY_EXPONENT, QUICLY_DEFAULT_MAX_ACK_DELAY};

static __thread int64_t now;

static void update_now(quicly_context_t *ctx)
{
    int64_t newval = ctx->now->cb(ctx->now);

    if (now < newval)
        now = newval;
}

/**
 * USDT on cannot handle thread-local variables provided as arguments.  Hence this wrapper.
 */
static int64_t now_cb(void)
{
    return now;
}

static int64_t (*volatile probe_now)(void) = now_cb;

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

static void set_cid(quicly_cid_t *dest, ptls_iovec_t src)
{
    memcpy(dest->cid, src.base, src.len);
    dest->len = src.len;
}

static ptls_aead_context_t *create_retry_aead(quicly_context_t *ctx, int is_enc)
{
    static const uint8_t secret[] = {0x65, 0x6e, 0x61, 0xe3, 0x36, 0xae, 0x94, 0x17, 0xf7, 0xf0, 0xed,
                                     0xd8, 0xd7, 0x8d, 0x46, 0x1e, 0x2a, 0xa7, 0x08, 0x4a, 0xba, 0x7a,
                                     0x14, 0xc1, 0xe9, 0xf7, 0x26, 0xd5, 0x57, 0x09, 0x16, 0x9a};
    ptls_cipher_suite_t *algo = get_aes128gcmsha256(ctx);
    ptls_aead_context_t *aead = ptls_aead_new(algo->aead, algo->hash, is_enc, secret, QUICLY_AEAD_BASE_LABEL);
    assert(aead != NULL);
    return aead;
}

static void dispose_cipher(struct st_quicly_cipher_context_t *ctx)
{
    ptls_aead_free(ctx->aead);
    ptls_cipher_free(ctx->header_protection);
}

size_t quicly_decode_packet(quicly_context_t *ctx, quicly_decoded_packet_t *packet, const uint8_t *src, size_t len)
{
    const uint8_t *src_end = src + len;

    if (len < 2)
        goto Error;

    packet->octets = ptls_iovec_init(src, len);
    packet->datagram_size = len;
    packet->token = ptls_iovec_init(NULL, 0);
    packet->decrypted.pn = UINT64_MAX;
    ++src;

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
        if (!(packet->version == QUICLY_PROTOCOL_VERSION ||
              (packet->version & 0xffffff00) == 0xff000000 /* TODO remove this code that is used to test other draft versions */)) {
            /* version negotiation packet does not have the length field nor is ever coalesced */
            packet->encrypted_off = src - packet->octets.base;
        } else if ((packet->octets.base[0] & QUICLY_PACKET_TYPE_BITMASK) == QUICLY_PACKET_TYPE_RETRY) {
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
        packet->_is_stateless_reset_cached = QUICLY__DECODED_PACKET_CACHED_NOT_STATELESS_RESET;
    } else {
        /* short header */
        if (ctx->cid_encryptor != NULL) {
            if (src_end - src < QUICLY_MAX_CID_LEN_V1)
                goto Error;
            size_t host_cidl = ctx->cid_encryptor->decrypt_cid(ctx->cid_encryptor, &packet->cid.dest.plaintext, src, 0);
            if (host_cidl == SIZE_MAX)
                goto Error;
            packet->cid.dest.encrypted = ptls_iovec_init(src, host_cidl);
            src += host_cidl;
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
        assert(!timer_must_be_in_future || now < conn->egress.send_ack_at);
        return;
    }

    if (conn->egress.sentmap.bytes_in_flight != 0 || conn->super.peer.address_validation.send_probe) {
        assert(conn->egress.loss.alarm_at != INT64_MAX);
    } else {
        assert(conn->egress.loss.loss_time == INT64_MAX);
    }
    /* Allow timers not in the future when the peer is not yet validated, since we may not be able to send packets even when timers
     * fire. */
    if (timer_must_be_in_future && conn->super.peer.address_validation.validated)
        assert(now < conn->egress.loss.alarm_at);
}

static int on_invalid_ack(quicly_conn_t *conn, const quicly_sent_packet_t *packet, quicly_sent_t *sent,
                          quicly_sentmap_event_t event)
{
    if (event == QUICLY_SENTMAP_EVENT_ACKED)
        return QUICLY_TRANSPORT_ERROR_PROTOCOL_VIOLATION;
    return 0;
}

static uint64_t calc_next_pn_to_skip(ptls_context_t *tlsctx, uint64_t next_pn)
{
    static __thread struct {
        uint16_t values[32];
        size_t off;
    } cached_rand;

    if (cached_rand.off == 0) {
        tlsctx->random_bytes(cached_rand.values, sizeof(cached_rand.values));
        cached_rand.off = sizeof(cached_rand.values) / sizeof(cached_rand.values[0]);
    }

    /* on average, skip one PN per every 256 packets, by selecting one of the 511 packet numbers following next_pn */
    return next_pn + 1 + (cached_rand.values[--cached_rand.off] & 0x1ff);
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
    switch (stream->_send_aux.rst.sender_state) {
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
        quicly_linklist_insert(stream->conn->pending.streams.control.prev, &stream->_send_aux.pending_link.control);
}

static void resched_stream_data(quicly_stream_t *stream)
{
    if (stream->stream_id < 0) {
        assert(-4 <= stream->stream_id);
        uint8_t mask = 1 << -(1 + stream->stream_id);
        if (stream->sendstate.pending.num_ranges != 0) {
            stream->conn->pending.flows |= mask;
        } else {
            stream->conn->pending.flows &= ~mask;
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

static int schedule_path_challenge(quicly_conn_t *conn, int is_response, const uint8_t *data)
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
        QUICLY_PROBE(CRYPTO_HANDSHAKE, conn, handshake_result);
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
        /* drop 0-RTT write key if 0-RTT is rejected by peer */
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
    stream->_send_aux.rst.sender_state = QUICLY_SENDER_STATE_NONE;
    stream->_send_aux.rst.error_code = 0;
    quicly_maxsender_init(&stream->_send_aux.max_stream_data_sender, initial_max_stream_data_local);
    quicly_linklist_init(&stream->_send_aux.pending_link.control);
    quicly_linklist_init(&stream->_send_aux.pending_link.default_scheduler);

    stream->_recv_aux.window = initial_max_stream_data_local;
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
        return quicly_stream_is_unidirectional(stream_id) ? &conn->super.host.uni : &conn->super.host.bidi;
    } else {
        return quicly_stream_is_unidirectional(stream_id) ? &conn->super.peer.uni : &conn->super.peer.bidi;
    }
}

static int should_send_max_streams(quicly_conn_t *conn, int uni)
{
    quicly_maxsender_t *maxsender;
    if ((maxsender = uni ? conn->ingress.max_streams.uni : conn->ingress.max_streams.bidi) == NULL)
        return 0;

    struct st_quicly_conn_streamgroup_state_t *group = uni ? &conn->super.peer.uni : &conn->super.peer.bidi;
    if (!quicly_maxsender_should_send_max(maxsender, group->next_stream_id / 4, group->num_streams, 768))
        return 0;

    return 1;
}

static void destroy_stream(quicly_stream_t *stream, int err)
{
    quicly_conn_t *conn = stream->conn;

    if (stream->callbacks != NULL)
        stream->callbacks->on_destroy(stream, err);

    khiter_t iter = kh_get(quicly_stream_t, conn->streams, stream->stream_id);
    assert(iter != kh_end(conn->streams));
    kh_del(quicly_stream_t, conn->streams, iter);

    if (stream->stream_id < 0) {
        size_t epoch = -(1 + stream->stream_id);
        stream->conn->pending.flows &= ~(uint8_t)(1 << epoch);
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
    quicly_maxsender_t *maxsender = uni ? conn->ingress.max_streams.uni : conn->ingress.max_streams.bidi;
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
    if (conn->initial == NULL && conn->handshake == NULL && conn->super.peer.transport_params.max_idle_timeout != 0)
        idle_msec = conn->super.peer.transport_params.max_idle_timeout;
    if (conn->super.ctx->transport_params.max_idle_timeout != 0 && conn->super.ctx->transport_params.max_idle_timeout < idle_msec)
        idle_msec = conn->super.ctx->transport_params.max_idle_timeout;

    if (idle_msec == INT64_MAX)
        return;

    uint32_t three_pto = 3 * quicly_rtt_get_pto(&conn->egress.loss.rtt, conn->super.ctx->transport_params.max_ack_delay,
                                                conn->egress.loss.conf->min_pto);
    conn->idle_timeout.at = now + (idle_msec > three_pto ? idle_msec : three_pto);
    conn->idle_timeout.should_rearm_on_send = is_in_receive;
}

static int scheduler_can_send(quicly_conn_t *conn)
{
    /* scheduler would never have data to send, until application keys become available */
    if (conn->application == NULL)
        return 0;
    int conn_is_saturated = !(conn->egress.max_data.sent < conn->egress.max_data.permitted);
    return conn->super.ctx->stream_scheduler->can_send(conn->super.ctx->stream_scheduler, conn, conn_is_saturated);
}

static void update_loss_alarm(quicly_conn_t *conn)
{
    int has_outstanding = conn->egress.sentmap.bytes_in_flight != 0 || conn->super.peer.address_validation.send_probe,
        handshake_is_in_progress = conn->initial != NULL || conn->handshake != NULL;
    quicly_loss_update_alarm(&conn->egress.loss, now, conn->egress.last_retransmittable_sent_at, has_outstanding,
                             scheduler_can_send(conn), handshake_is_in_progress, conn->egress.max_data.sent);
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

static struct st_quicly_pn_space_t *alloc_pn_space(size_t sz)
{
    struct st_quicly_pn_space_t *space;

    if ((space = malloc(sz)) == NULL)
        return NULL;

    quicly_ranges_init(&space->ack_queue);
    space->largest_pn_received_at = INT64_MAX;
    space->next_expected_packet_number = 0;
    space->unacked_count = 0;
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
    *is_out_of_order = 0;

    if (ranges->num_ranges != 0) {
        /* fast path that is taken when we receive a packet in-order */
        if (ranges->ranges[ranges->num_ranges - 1].end == pn) {
            ranges->ranges[ranges->num_ranges - 1].end = pn + 1;
            return 0;
        }
        *is_out_of_order = 1;
    }

    /* slow path; we shrink then add, to avoid exceeding the QUICLY_MAX_RANGES */
    if (ranges->num_ranges == QUICLY_MAX_RANGES)
        quicly_ranges_drop_smallest_range(ranges);
    return quicly_ranges_add(ranges, pn, pn + 1);
}

static int record_receipt(quicly_conn_t *conn, struct st_quicly_pn_space_t *space, uint64_t pn, int is_ack_only, size_t epoch)
{
    int ret, ack_now, is_out_of_order;

    if ((ret = record_pn(&space->ack_queue, pn, &is_out_of_order)) != 0)
        goto Exit;

    ack_now = is_out_of_order && !is_ack_only;

    /* update largest_pn_received_at (TODO implement deduplication at an earlier moment?) */
    if (space->ack_queue.ranges[space->ack_queue.num_ranges - 1].end == pn + 1)
        space->largest_pn_received_at = now;

    /* if the received packet is ack-eliciting, update / schedule transmission of ACK */
    if (!is_ack_only) {
        space->unacked_count++;
        /* Ack after QUICLY_NUM_PACKETS_BEFORE_ACK packets or after the delayed ack timeout */
        if (space->unacked_count >= QUICLY_NUM_PACKETS_BEFORE_ACK || epoch == QUICLY_EPOCH_INITIAL ||
            epoch == QUICLY_EPOCH_HANDSHAKE)
            ack_now = 1;
    }

    if (ack_now) {
        conn->egress.send_ack_at = now;
    } else if (conn->egress.send_ack_at == INT64_MAX) {
        conn->egress.send_ack_at = now + QUICLY_DELAYED_ACK_TIMEOUT;
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
    if ((*space = (void *)alloc_pn_space(sizeof(struct st_quicly_handshake_space_t))) == NULL)
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
        memset((*space)->cipher.egress.secret, 0, sizeof((*space)->cipher.egress.secret));
        do_free_pn_space(&(*space)->super);
        *space = NULL;
    }
}

static int setup_application_space(quicly_conn_t *conn)
{
    if ((conn->application = (void *)alloc_pn_space(sizeof(struct st_quicly_application_space_t))) == NULL)
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

static int apply_peer_transport_params(quicly_conn_t *conn)
{
    int ret;

    conn->egress.max_data.permitted = conn->super.peer.transport_params.max_data;
    if ((ret = update_max_streams(&conn->egress.max_streams.uni, conn->super.peer.transport_params.max_streams_uni)) != 0)
        return ret;
    if ((ret = update_max_streams(&conn->egress.max_streams.bidi, conn->super.peer.transport_params.max_streams_bidi)) != 0)
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

    QUICLY_PROBE(CRYPTO_SEND_KEY_UPDATE, conn, space->cipher.egress.key_phase,
                 QUICLY_PROBE_HEXDUMP(space->cipher.egress.secret, cipher->hash->digest_size));

    return 0;
}

static int received_key_update(quicly_conn_t *conn, uint64_t newly_decrypted_key_phase)
{
    struct st_quicly_application_space_t *space = conn->application;

    assert(space->cipher.ingress.key_phase.decrypted < newly_decrypted_key_phase);
    assert(newly_decrypted_key_phase <= space->cipher.ingress.key_phase.prepared);

    space->cipher.ingress.key_phase.decrypted = newly_decrypted_key_phase;

    QUICLY_PROBE(CRYPTO_RECEIVE_KEY_UPDATE, conn, space->cipher.ingress.key_phase.decrypted,
                 QUICLY_PROBE_HEXDUMP(space->cipher.ingress.secret, ptls_get_cipher(conn->crypto.tls)->hash->digest_size));

    if (space->cipher.egress.key_phase < space->cipher.ingress.key_phase.decrypted) {
        return update_1rtt_egress_key(conn);
    } else {
        return 0;
    }
}

void quicly_free(quicly_conn_t *conn)
{
    QUICLY_PROBE(FREE, conn, probe_now());

    destroy_all_streams(conn, 0, 1);

    quicly_maxsender_dispose(&conn->ingress.max_data.sender);
    if (conn->ingress.max_streams.uni != NULL)
        quicly_maxsender_dispose(conn->ingress.max_streams.uni);
    if (conn->ingress.max_streams.bidi != NULL)
        quicly_maxsender_dispose(conn->ingress.max_streams.bidi);
    while (conn->egress.path_challenge.head != NULL) {
        struct st_quicly_pending_path_challenge_t *pending = conn->egress.path_challenge.head;
        conn->egress.path_challenge.head = pending->next;
        free(pending);
    }
    quicly_sentmap_dispose(&conn->egress.sentmap);

    kh_destroy(quicly_stream_t, conn->streams);

    assert(!quicly_linklist_is_linked(&conn->pending.streams.blocked.uni));
    assert(!quicly_linklist_is_linked(&conn->pending.streams.blocked.bidi));
    assert(!quicly_linklist_is_linked(&conn->pending.streams.control));
    assert(!quicly_linklist_is_linked(&conn->super._default_scheduler.active));
    assert(!quicly_linklist_is_linked(&conn->super._default_scheduler.blocked));

    free_handshake_space(&conn->initial);
    free_handshake_space(&conn->handshake);
    free_application_space(&conn->application);

    ptls_buffer_dispose(&conn->crypto.transport_params.buf);
    ptls_free(conn->crypto.tls);

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
                                    struct st_quicly_cipher_context_t *egress, ptls_iovec_t cid, int is_client, quicly_conn_t *conn)
{
    static const uint8_t salt[] = {0xc3, 0xee, 0xf7, 0x12, 0xc7, 0x2e, 0xbb, 0x5a, 0x11, 0xa7,
                                   0xd2, 0x43, 0x2b, 0xb4, 0x63, 0x65, 0xbe, 0xf9, 0xf5, 0x02};
    static const char *labels[2] = {"client in", "server in"};
    uint8_t secret[PTLS_MAX_DIGEST_SIZE];
    int ret;

    /* extract master secret */
    if ((ret = ptls_hkdf_extract(cs->hash, secret, ptls_iovec_init(salt, sizeof(salt)), cid)) != 0)
        goto Exit;

    /* create aead contexts */
    if ((ret = setup_initial_key(ingress, cs, secret, labels[is_client], 0, conn)) != 0)
        goto Exit;
    if ((ret = setup_initial_key(egress, cs, secret, labels[!is_client], 1, conn)) != 0)
        goto Exit;

Exit:
    ptls_clear_memory(secret, sizeof(secret));
    return ret;
}

static int apply_stream_frame(quicly_stream_t *stream, quicly_stream_frame_t *frame)
{
    int ret;

    QUICLY_PROBE(STREAM_RECEIVE, stream->conn, probe_now(), stream, frame->offset, frame->data.len);

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
    if ((ret = quicly_recvstate_update(&stream->recvstate, frame->offset, &apply_len, frame->is_fin)) != 0)
        return ret;

    if (apply_len != 0 || quicly_recvstate_transfer_complete(&stream->recvstate)) {
        uint64_t buf_offset = frame->offset + frame->data.len - apply_len - stream->recvstate.data_off;
        stream->callbacks->on_receive(stream, (size_t)buf_offset, frame->data.base + frame->data.len - apply_len, apply_len);
        if (stream->conn->super.state >= QUICLY_STATE_CLOSING)
            return QUICLY_ERROR_IS_CLOSING;
    }

    if (should_send_max_stream_data(stream))
        sched_stream_control(stream);

    if (stream_is_destroyable(stream))
        destroy_stream(stream, 0);

    return 0;
}

#define PUSH_TRANSPORT_PARAMETER(buf, id, block)                                                                                   \
    do {                                                                                                                           \
        ptls_buffer_push16((buf), (id));                                                                                           \
        ptls_buffer_push_block((buf), 2, block);                                                                                   \
    } while (0)

int quicly_encode_transport_parameter_list(ptls_buffer_t *buf, int is_client, const quicly_transport_parameters_t *params,
                                           const quicly_cid_t *odcid, const void *stateless_reset_token, int expand)
{
    int ret;

#define pushv(buf, v)                                                                                                              \
    if ((ret = quicly_tls_push_varint((buf), (v))) != 0)                                                                           \
    goto Exit
    ptls_buffer_push_block(buf, 2, {
        if (params->max_stream_data.bidi_local != 0)
            PUSH_TRANSPORT_PARAMETER(buf, QUICLY_TRANSPORT_PARAMETER_ID_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
                                     { pushv(buf, params->max_stream_data.bidi_local); });
        if (params->max_stream_data.bidi_remote != 0)
            PUSH_TRANSPORT_PARAMETER(buf, QUICLY_TRANSPORT_PARAMETER_ID_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
                                     { pushv(buf, params->max_stream_data.bidi_remote); });
        if (params->max_stream_data.uni != 0)
            PUSH_TRANSPORT_PARAMETER(buf, QUICLY_TRANSPORT_PARAMETER_ID_INITIAL_MAX_STREAM_DATA_UNI,
                                     { pushv(buf, params->max_stream_data.uni); });
        if (params->max_data != 0)
            PUSH_TRANSPORT_PARAMETER(buf, QUICLY_TRANSPORT_PARAMETER_ID_INITIAL_MAX_DATA, { pushv(buf, params->max_data); });
        if (params->max_idle_timeout != 0)
            PUSH_TRANSPORT_PARAMETER(buf, QUICLY_TRANSPORT_PARAMETER_ID_MAX_IDLE_TIMEOUT,
                                     { pushv(buf, params->max_idle_timeout); });
        if (is_client) {
            assert(odcid == NULL && stateless_reset_token == NULL);
        } else {
            if (odcid != NULL)
                PUSH_TRANSPORT_PARAMETER(buf, QUICLY_TRANSPORT_PARAMETER_ID_ORIGINAL_CONNECTION_ID,
                                         { ptls_buffer_pushv(buf, odcid->cid, odcid->len); });
            if (stateless_reset_token != NULL)
                PUSH_TRANSPORT_PARAMETER(buf, QUICLY_TRANSPORT_PARAMETER_ID_STATELESS_RESET_TOKEN,
                                         { ptls_buffer_pushv(buf, stateless_reset_token, QUICLY_STATELESS_RESET_TOKEN_LEN); });
        }
        if (params->max_streams_bidi != 0)
            PUSH_TRANSPORT_PARAMETER(buf, QUICLY_TRANSPORT_PARAMETER_ID_INITIAL_MAX_STREAMS_BIDI,
                                     { pushv(buf, params->max_streams_bidi); });
        if (params->max_streams_uni != 0)
            PUSH_TRANSPORT_PARAMETER(buf, QUICLY_TRANSPORT_PARAMETER_ID_INITIAL_MAX_STREAMS_UNI,
                                     { pushv(buf, params->max_streams_uni); });
        if (QUICLY_LOCAL_ACK_DELAY_EXPONENT != QUICLY_DEFAULT_ACK_DELAY_EXPONENT)
            PUSH_TRANSPORT_PARAMETER(buf, QUICLY_TRANSPORT_PARAMETER_ID_ACK_DELAY_EXPONENT,
                                     { pushv(buf, QUICLY_LOCAL_ACK_DELAY_EXPONENT); });
        if (QUICLY_LOCAL_MAX_ACK_DELAY != QUICLY_DEFAULT_MAX_ACK_DELAY)
            PUSH_TRANSPORT_PARAMETER(buf, QUICLY_TRANSPORT_PARAMETER_ID_MAX_ACK_DELAY, { pushv(buf, QUICLY_LOCAL_MAX_ACK_DELAY); });
        if (params->disable_active_migration)
            PUSH_TRANSPORT_PARAMETER(buf, QUICLY_TRANSPORT_PARAMETER_ID_DISABLE_ACTIVE_MIGRATION, {});
        /* if requested, add a greasing TP of 1 MTU size so that CH spans across multiple packets */
        if (expand) {
            PUSH_TRANSPORT_PARAMETER(buf, 31 * 100 + 27, {
                if ((ret = ptls_buffer_reserve(buf, QUICLY_MAX_PACKET_SIZE)) != 0)
                    goto Exit;
                memset(buf->base + buf->off, 0, QUICLY_MAX_PACKET_SIZE);
                buf->off += QUICLY_MAX_PACKET_SIZE;
            });
        }
    });
#undef pushv

    ret = 0;
Exit:
    return ret;
}

int quicly_decode_transport_parameter_list(quicly_transport_parameters_t *params, quicly_cid_t *odcid, void *stateless_reset_token,
                                           int is_client, const uint8_t *src, const uint8_t *end)
{
#define ID_TO_BIT(id) ((uint64_t)1 << (id))

    uint64_t found_id_bits = 0;
    int ret;

    /* set parameters to their default values */
    *params = default_transport_params;
    if (odcid != NULL)
        odcid->len = 0;
    if (stateless_reset_token != NULL)
        memset(stateless_reset_token, 0, QUICLY_STATELESS_RESET_TOKEN_LEN);

    /* decode the parameters block */
    ptls_decode_block(src, end, 2, {
        while (src != end) {
            uint16_t id;
            if ((ret = ptls_decode16(&id, &src, end)) != 0)
                goto Exit;
            if (id < sizeof(found_id_bits) * 8) {
                if ((found_id_bits & ID_TO_BIT(id)) != 0) {
                    ret = QUICLY_TRANSPORT_ERROR_TRANSPORT_PARAMETER;
                    goto Exit;
                }
                found_id_bits |= ID_TO_BIT(id);
            }
            ptls_decode_open_block(src, end, 2, {
                switch (id) {
                case QUICLY_TRANSPORT_PARAMETER_ID_ORIGINAL_CONNECTION_ID: {
                    size_t cidlen = end - src;
                    if (!(is_client && cidlen <= QUICLY_MAX_CID_LEN_V1)) {
                        ret = QUICLY_TRANSPORT_ERROR_TRANSPORT_PARAMETER;
                        goto Exit;
                    }
                    if (odcid != NULL)
                        set_cid(odcid, ptls_iovec_init(src, cidlen));
                    src = end;
                } break;
                case QUICLY_TRANSPORT_PARAMETER_ID_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL:
                    if ((ret = quicly_tls_decode_varint(&params->max_stream_data.bidi_local, &src, end)) != 0)
                        goto Exit;
                    break;
                case QUICLY_TRANSPORT_PARAMETER_ID_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE:
                    if ((ret = quicly_tls_decode_varint(&params->max_stream_data.bidi_remote, &src, end)) != 0)
                        goto Exit;
                    break;
                case QUICLY_TRANSPORT_PARAMETER_ID_INITIAL_MAX_STREAM_DATA_UNI:
                    if ((ret = quicly_tls_decode_varint(&params->max_stream_data.uni, &src, end)) != 0)
                        goto Exit;
                    break;
                case QUICLY_TRANSPORT_PARAMETER_ID_INITIAL_MAX_DATA:
                    if ((ret = quicly_tls_decode_varint(&params->max_data, &src, end)) != 0)
                        goto Exit;
                    break;
                case QUICLY_TRANSPORT_PARAMETER_ID_STATELESS_RESET_TOKEN:
                    if (!(is_client && end - src == QUICLY_STATELESS_RESET_TOKEN_LEN)) {
                        ret = QUICLY_TRANSPORT_ERROR_TRANSPORT_PARAMETER;
                        goto Exit;
                    }
                    memcpy(stateless_reset_token, src, QUICLY_STATELESS_RESET_TOKEN_LEN);
                    src = end;
                    break;
                case QUICLY_TRANSPORT_PARAMETER_ID_MAX_IDLE_TIMEOUT:
                    if ((ret = quicly_tls_decode_varint(&params->max_idle_timeout, &src, end)) != 0)
                        goto Exit;
                    break;
                case QUICLY_TRANSPORT_PARAMETER_ID_INITIAL_MAX_STREAMS_BIDI:
                    if ((ret = quicly_tls_decode_varint(&params->max_streams_bidi, &src, end)) != 0)
                        goto Exit;
                    break;
                case QUICLY_TRANSPORT_PARAMETER_ID_INITIAL_MAX_STREAMS_UNI:
                    if ((ret = quicly_tls_decode_varint(&params->max_streams_uni, &src, end)) != 0)
                        goto Exit;
                    break;
                case QUICLY_TRANSPORT_PARAMETER_ID_ACK_DELAY_EXPONENT: {
                    uint64_t v;
                    if ((ret = quicly_tls_decode_varint(&v, &src, end)) != 0)
                        goto Exit;
                    if (v > 20) {
                        ret = QUICLY_TRANSPORT_ERROR_TRANSPORT_PARAMETER;
                        goto Exit;
                    }
                    params->ack_delay_exponent = (uint8_t)v;
                } break;
                case QUICLY_TRANSPORT_PARAMETER_ID_MAX_ACK_DELAY: {
                    uint64_t v;
                    if ((ret = quicly_tls_decode_varint(&v, &src, end)) != 0)
                        goto Exit;
                    if (v >= 16384)
                        v = QUICLY_DEFAULT_MAX_ACK_DELAY;
                    params->max_ack_delay = (uint16_t)v;
                } break;
                case QUICLY_TRANSPORT_PARAMETER_ID_DISABLE_ACTIVE_MIGRATION:
                    params->disable_active_migration = 1;
                    break;
                default:
                    src = end;
                    break;
                }
            });
        }
    });

    ret = 0;
Exit:
    if (ret == PTLS_ALERT_DECODE_ERROR)
        ret = QUICLY_TRANSPORT_ERROR_TRANSPORT_PARAMETER;
    return ret;

#undef ID_TO_BIT
}

static int collect_transport_parameters(ptls_t *tls, struct st_ptls_handshake_properties_t *properties, uint16_t type)
{
    return type == QUICLY_TLS_EXTENSION_TYPE_TRANSPORT_PARAMETERS;
}

static quicly_conn_t *create_connection(quicly_context_t *ctx, const char *server_name, struct sockaddr *remote_addr,
                                        struct sockaddr *local_addr, const quicly_cid_plaintext_t *new_cid,
                                        ptls_handshake_properties_t *handshake_properties)
{
    ptls_t *tls = NULL;
    struct {
        quicly_conn_t _;
        quicly_maxsender_t max_streams_bidi;
        quicly_maxsender_t max_streams_uni;
    } * conn;

    assert(remote_addr != NULL && remote_addr->sa_family != AF_UNSPEC);

    if ((tls = ptls_new(ctx->tls, server_name == NULL)) == NULL)
        return NULL;
    if (server_name != NULL && ptls_set_server_name(tls, server_name, strlen(server_name)) != 0) {
        ptls_free(tls);
        return NULL;
    }
    if ((conn = malloc(sizeof(*conn))) == NULL) {
        ptls_free(tls);
        return NULL;
    }

    memset(conn, 0, sizeof(*conn));
    conn->_.super.ctx = ctx;
    conn->_.super.master_id = *new_cid;
    set_address(&conn->_.super.host.address, local_addr);
    set_address(&conn->_.super.peer.address, remote_addr);
    if (ctx->cid_encryptor != NULL) {
        conn->_.super.master_id.path_id = 0;
        ctx->cid_encryptor->encrypt_cid(ctx->cid_encryptor, &conn->_.super.host.src_cid, &conn->_.super.host.stateless_reset_token,
                                        &conn->_.super.master_id);
        conn->_.super.master_id.path_id = 1;
    } else {
        conn->_.super.master_id.path_id = QUICLY_MAX_PATH_ID;
    }
    conn->_.super.state = QUICLY_STATE_FIRSTFLIGHT;
    if (server_name != NULL) {
        ctx->tls->random_bytes(conn->_.super.peer.cid.cid, QUICLY_MIN_INITIAL_DCID_LEN);
        conn->_.super.peer.cid.len = QUICLY_MIN_INITIAL_DCID_LEN;
        conn->_.super.host.bidi.next_stream_id = 0;
        conn->_.super.host.uni.next_stream_id = 2;
        conn->_.super.peer.bidi.next_stream_id = 1;
        conn->_.super.peer.uni.next_stream_id = 3;
    } else {
        conn->_.super.host.bidi.next_stream_id = 1;
        conn->_.super.host.uni.next_stream_id = 3;
        conn->_.super.peer.bidi.next_stream_id = 0;
        conn->_.super.peer.uni.next_stream_id = 2;
    }
    conn->_.super.peer.transport_params = default_transport_params;
    if (server_name != NULL && ctx->enforce_version_negotiation) {
        ctx->tls->random_bytes(&conn->_.super.version, sizeof(conn->_.super.version));
        conn->_.super.version = (conn->_.super.version & 0xf0f0f0f0) | 0x0a0a0a0a;
    } else {
        conn->_.super.version = QUICLY_PROTOCOL_VERSION;
    }
    quicly_linklist_init(&conn->_.super._default_scheduler.active);
    quicly_linklist_init(&conn->_.super._default_scheduler.blocked);
    conn->_.streams = kh_init(quicly_stream_t);
    quicly_maxsender_init(&conn->_.ingress.max_data.sender, conn->_.super.ctx->transport_params.max_data);
    if (conn->_.super.ctx->transport_params.max_streams_uni != 0) {
        conn->_.ingress.max_streams.uni = &conn->max_streams_uni;
        quicly_maxsender_init(conn->_.ingress.max_streams.uni, conn->_.super.ctx->transport_params.max_streams_uni);
    }
    if (conn->_.super.ctx->transport_params.max_streams_bidi != 0) {
        conn->_.ingress.max_streams.bidi = &conn->max_streams_bidi;
        quicly_maxsender_init(conn->_.ingress.max_streams.bidi, conn->_.super.ctx->transport_params.max_streams_bidi);
    }
    quicly_sentmap_init(&conn->_.egress.sentmap);
    quicly_loss_init(&conn->_.egress.loss, &conn->_.super.ctx->loss,
                     conn->_.super.ctx->loss.default_initial_rtt /* FIXME remember initial_rtt in session ticket */,
                     &conn->_.super.peer.transport_params.max_ack_delay, &conn->_.super.peer.transport_params.ack_delay_exponent);
    conn->_.egress.next_pn_to_skip = calc_next_pn_to_skip(conn->_.super.ctx->tls, 0);
    init_max_streams(&conn->_.egress.max_streams.uni);
    init_max_streams(&conn->_.egress.max_streams.bidi);
    conn->_.egress.path_challenge.tail_ref = &conn->_.egress.path_challenge.head;
    conn->_.egress.send_ack_at = INT64_MAX;
    quicly_cc_init(&conn->_.egress.cc);
    conn->_.crypto.tls = tls;
    if (handshake_properties != NULL) {
        assert(handshake_properties->additional_extensions == NULL);
        assert(handshake_properties->collect_extension == NULL);
        assert(handshake_properties->collected_extensions == NULL);
        conn->_.crypto.handshake_properties = *handshake_properties;
    } else {
        conn->_.crypto.handshake_properties = (ptls_handshake_properties_t){{{{NULL}}}};
    }
    conn->_.crypto.handshake_properties.collect_extension = collect_transport_parameters;
    quicly_linklist_init(&conn->_.pending.streams.blocked.uni);
    quicly_linklist_init(&conn->_.pending.streams.blocked.bidi);
    quicly_linklist_init(&conn->_.pending.streams.control);
    conn->_.idle_timeout.at = INT64_MAX;
    conn->_.idle_timeout.should_rearm_on_send = 1;

    *ptls_get_data_ptr(tls) = &conn->_;

    return &conn->_;
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
    quicly_cid_t odcid;

    /* decode and validate */
    if ((ret = quicly_decode_transport_parameter_list(&params, &odcid, conn->super.peer.stateless_reset._buf, 1, src, end)) != 0)
        goto Exit;
    if (odcid.len != conn->retry_odcid.len || memcmp(odcid.cid, conn->retry_odcid.cid, odcid.len) != 0) {
        ret = QUICLY_TRANSPORT_ERROR_TRANSPORT_PARAMETER;
        goto Exit;
    }
    if (properties->client.early_data_acceptance == PTLS_EARLY_DATA_ACCEPTED) {
#define ZERORTT_VALIDATE(x)                                                                                                        \
    if (params.x < conn->super.peer.transport_params.x) {                                                                          \
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
    conn->super.peer.stateless_reset.token = conn->super.peer.stateless_reset._buf;
    conn->super.peer.transport_params = params;

Exit:
    return ret; /* negative error codes used to transmit QUIC errors through picotls */
}

int quicly_connect(quicly_conn_t **_conn, quicly_context_t *ctx, const char *server_name, struct sockaddr *dest_addr,
                   struct sockaddr *src_addr, const quicly_cid_plaintext_t *new_cid, ptls_iovec_t address_token,
                   ptls_handshake_properties_t *handshake_properties, const quicly_transport_parameters_t *resumed_transport_params)
{
    quicly_conn_t *conn = NULL;
    const quicly_cid_t *server_cid;
    ptls_buffer_t buf;
    size_t epoch_offsets[5] = {0};
    size_t max_early_data_size = 0;
    int ret;

    update_now(ctx);

    if ((conn = create_connection(ctx, server_name, dest_addr, src_addr, new_cid, handshake_properties)) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }
    conn->super.peer.address_validation.validated = 1;
    conn->super.peer.address_validation.send_probe = 1;
    if (address_token.len != 0) {
        if ((conn->token.base = malloc(address_token.len)) == NULL) {
            ret = PTLS_ERROR_NO_MEMORY;
            goto Exit;
        }
        memcpy(conn->token.base, address_token.base, address_token.len);
        conn->token.len = address_token.len;
    }
    server_cid = quicly_get_peer_cid(conn);

    QUICLY_PROBE(CONNECT, conn, probe_now(), conn->super.version);

    if ((ret = setup_handshake_space_and_flow(conn, QUICLY_EPOCH_INITIAL)) != 0)
        goto Exit;
    if ((ret = setup_initial_encryption(get_aes128gcmsha256(ctx), &conn->initial->cipher.ingress, &conn->initial->cipher.egress,
                                        ptls_iovec_init(server_cid->cid, server_cid->len), 1, conn)) != 0)
        goto Exit;

    /* handshake */
    ptls_buffer_init(&conn->crypto.transport_params.buf, "", 0);
    if ((ret = quicly_encode_transport_parameter_list(&conn->crypto.transport_params.buf, 1, &conn->super.ctx->transport_params,
                                                      NULL, NULL, conn->super.ctx->expand_client_hello)) != 0)
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
        conn->super.peer.transport_params = *resumed_transport_params;
        if ((ret = apply_peer_transport_params(conn)) != 0)
            goto Exit;
    }

    *_conn = conn;
    ret = 0;

Exit:
    if (ret != 0) {
        if (conn != NULL)
            quicly_free(conn);
    }
    return ret;
}

static int server_collected_extensions(ptls_t *tls, ptls_handshake_properties_t *properties, ptls_raw_extension_t *slots)
{
    quicly_conn_t *conn = (void *)((char *)properties - offsetof(quicly_conn_t, crypto.handshake_properties));
    int ret;

    if (slots[0].type == UINT16_MAX) {
        ret = PTLS_ALERT_MISSING_EXTENSION;
        goto Exit;
    }
    assert(slots[0].type == QUICLY_TLS_EXTENSION_TYPE_TRANSPORT_PARAMETERS);
    assert(slots[1].type == UINT16_MAX);

    { /* decode transport_parameters extension */
        const uint8_t *src = slots[0].data.base, *end = src + slots[0].data.len;
        if ((ret = quicly_decode_transport_parameter_list(&conn->super.peer.transport_params, NULL, NULL, 0, src, end)) != 0)
            goto Exit;
    }

    /* set transport_parameters extension to be sent in EE */
    assert(properties->additional_extensions == NULL);
    ptls_buffer_init(&conn->crypto.transport_params.buf, "", 0);
    if ((ret = quicly_encode_transport_parameter_list(
             &conn->crypto.transport_params.buf, 0, &conn->super.ctx->transport_params,
             conn->retry_odcid.len != 0 ? &conn->retry_odcid : NULL,
             conn->super.ctx->cid_encryptor != NULL ? conn->super.host.stateless_reset_token : NULL, 0)) != 0)
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
        QUICLY_PROBE(CRYPTO_RECEIVE_KEY_UPDATE_PREPARE, conn, space->cipher.ingress.key_phase.prepared,
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

static int on_ack_ack(quicly_conn_t *conn, const quicly_sent_packet_t *packet, quicly_sent_t *sent, quicly_sentmap_event_t event)
{
    /* TODO log */

    if (event == QUICLY_SENTMAP_EVENT_ACKED) {
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
        /* Subtracting an ACK range might end up in splitting an existing range. By shrinking the number of ranges to MAX-1, we make
         * sure that the potential split would not lead to an error. */
        if (space->ack_queue.num_ranges == QUICLY_MAX_RANGES)
            quicly_ranges_drop_smallest_range(&space->ack_queue);
        if (quicly_ranges_subtract(&space->ack_queue, sent->data.ack.range.start, sent->data.ack.range.end) != 0) {
            /* FIXME log error */
            return QUICLY_TRANSPORT_ERROR_PROTOCOL_VIOLATION;
        }
        if (space->ack_queue.num_ranges == 0) {
            space->largest_pn_received_at = INT64_MAX;
            space->unacked_count = 0;
        }
    }

    return 0;
}

static int on_ack_stream(quicly_conn_t *conn, const quicly_sent_packet_t *packet, quicly_sent_t *sent, quicly_sentmap_event_t event)
{
    quicly_stream_t *stream;
    int ret;

    if (event == QUICLY_SENTMAP_EVENT_EXPIRED)
        return 0;

    if (event == QUICLY_SENTMAP_EVENT_ACKED) {
        QUICLY_PROBE(STREAM_ACKED, conn, probe_now(), sent->data.stream.stream_id, sent->data.stream.args.start,
                     sent->data.stream.args.end - sent->data.stream.args.start);
    } else {
        QUICLY_PROBE(STREAM_LOST, conn, probe_now(), sent->data.stream.stream_id, sent->data.stream.args.start,
                     sent->data.stream.args.end - sent->data.stream.args.start);
    }

    /* TODO cache pointer to stream (using a generation counter?) */
    if ((stream = quicly_get_stream(conn, sent->data.stream.stream_id)) == NULL)
        return 0;

    if (event == QUICLY_SENTMAP_EVENT_ACKED) {
        size_t bytes_to_shift;
        if ((ret = quicly_sendstate_acked(&stream->sendstate, &sent->data.stream.args, packet->bytes_in_flight != 0,
                                          &bytes_to_shift)) != 0)
            return ret;
        if (bytes_to_shift != 0)
            stream->callbacks->on_send_shift(stream, bytes_to_shift);
        if (stream_is_destroyable(stream)) {
            destroy_stream(stream, 0);
        } else if (stream->_send_aux.rst.sender_state == QUICLY_SENDER_STATE_NONE) {
            resched_stream_data(stream);
        }
    } else {
        /* FIXME handle rto error */
        if ((ret = quicly_sendstate_lost(&stream->sendstate, &sent->data.stream.args)) != 0)
            return ret;
        if (stream->_send_aux.rst.sender_state == QUICLY_SENDER_STATE_NONE)
            resched_stream_data(stream);
    }

    return 0;
}

static int on_ack_max_stream_data(quicly_conn_t *conn, const quicly_sent_packet_t *packet, quicly_sent_t *sent,
                                  quicly_sentmap_event_t event)
{
    quicly_stream_t *stream;

    if (event == QUICLY_SENTMAP_EVENT_EXPIRED)
        return 0;

    /* TODO cache pointer to stream (using a generation counter?) */
    if ((stream = quicly_get_stream(conn, sent->data.stream.stream_id)) != NULL) {
        switch (event) {
        case QUICLY_SENTMAP_EVENT_ACKED:
            quicly_maxsender_acked(&stream->_send_aux.max_stream_data_sender, &sent->data.max_stream_data.args);
            break;
        case QUICLY_SENTMAP_EVENT_LOST:
            quicly_maxsender_lost(&stream->_send_aux.max_stream_data_sender, &sent->data.max_stream_data.args);
            if (should_send_max_stream_data(stream))
                sched_stream_control(stream);
            break;
        default:
            break;
        }
    }

    return 0;
}

static int on_ack_max_data(quicly_conn_t *conn, const quicly_sent_packet_t *packet, quicly_sent_t *sent,
                           quicly_sentmap_event_t event)
{
    switch (event) {
    case QUICLY_SENTMAP_EVENT_ACKED:
        quicly_maxsender_acked(&conn->ingress.max_data.sender, &sent->data.max_data.args);
        break;
    case QUICLY_SENTMAP_EVENT_LOST:
        quicly_maxsender_lost(&conn->ingress.max_data.sender, &sent->data.max_data.args);
        break;
    default:
        break;
    }

    return 0;
}

static int on_ack_max_streams(quicly_conn_t *conn, const quicly_sent_packet_t *packet, quicly_sent_t *sent,
                              quicly_sentmap_event_t event)
{
    quicly_maxsender_t *maxsender = sent->data.max_streams.uni ? conn->ingress.max_streams.uni : conn->ingress.max_streams.bidi;
    assert(maxsender != NULL); /* we would only receive an ACK if we have sent the frame */

    switch (event) {
    case QUICLY_SENTMAP_EVENT_ACKED:
        quicly_maxsender_acked(maxsender, &sent->data.max_streams.args);
        break;
    case QUICLY_SENTMAP_EVENT_LOST:
        quicly_maxsender_lost(maxsender, &sent->data.max_streams.args);
        break;
    default:
        break;
    }

    return 0;
}

static void on_ack_stream_state_sender(quicly_sender_state_t *sender_state, int acked)
{
    *sender_state = acked ? QUICLY_SENDER_STATE_ACKED : QUICLY_SENDER_STATE_SEND;
}

static int on_ack_rst_stream(quicly_conn_t *conn, const quicly_sent_packet_t *packet, quicly_sent_t *sent,
                             quicly_sentmap_event_t event)
{
    if (event != QUICLY_SENTMAP_EVENT_EXPIRED) {
        quicly_stream_t *stream;
        if ((stream = quicly_get_stream(conn, sent->data.stream_state_sender.stream_id)) != NULL) {
            on_ack_stream_state_sender(&stream->_send_aux.rst.sender_state, event == QUICLY_SENTMAP_EVENT_ACKED);
            if (stream_is_destroyable(stream))
                destroy_stream(stream, 0);
        }
    }

    return 0;
}

static int on_ack_stop_sending(quicly_conn_t *conn, const quicly_sent_packet_t *packet, quicly_sent_t *sent,
                               quicly_sentmap_event_t event)
{
    if (event != QUICLY_SENTMAP_EVENT_EXPIRED) {
        quicly_stream_t *stream;
        if ((stream = quicly_get_stream(conn, sent->data.stream_state_sender.stream_id)) != NULL) {
            on_ack_stream_state_sender(&stream->_send_aux.stop_sending.sender_state, event == QUICLY_SENTMAP_EVENT_ACKED);
            if (stream->_send_aux.stop_sending.sender_state != QUICLY_SENDER_STATE_ACKED)
                sched_stream_control(stream);
        }
    }

    return 0;
}

static int on_ack_streams_blocked(quicly_conn_t *conn, const quicly_sent_packet_t *packet, quicly_sent_t *sent,
                                  quicly_sentmap_event_t event)
{
    struct st_quicly_max_streams_t *m =
        sent->data.streams_blocked.uni ? &conn->egress.max_streams.uni : &conn->egress.max_streams.bidi;

    switch (event) {
    case QUICLY_SENTMAP_EVENT_ACKED:
        quicly_maxsender_acked(&m->blocked_sender, &sent->data.streams_blocked.args);
        break;
    case QUICLY_SENTMAP_EVENT_LOST:
        quicly_maxsender_lost(&m->blocked_sender, &sent->data.streams_blocked.args);
        break;
    default:
        break;
    }

    return 0;
}

static int on_ack_handshake_done(quicly_conn_t *conn, const quicly_sent_packet_t *packet, quicly_sent_t *sent,
                                 quicly_sentmap_event_t event)
{
    /* When HANDSHAKE_DONE is deemed lost, schedule retransmission. */
    if (event == QUICLY_SENTMAP_EVENT_LOST)
        conn->pending.flows |= QUICLY_PENDING_FLOW_HANDSHAKE_DONE_BIT;
    return 0;
}

static int on_ack_new_token(quicly_conn_t *conn, const quicly_sent_packet_t *packet, quicly_sent_t *sent,
                            quicly_sentmap_event_t event)
{
    if (sent->data.new_token.is_inflight) {
        --conn->egress.new_token.num_inflight;
        sent->data.new_token.is_inflight = 0;
    }
    switch (event) {
    case QUICLY_SENTMAP_EVENT_ACKED:
        QUICLY_PROBE(NEW_TOKEN_ACKED, conn, probe_now(), sent->data.new_token.generation);
        if (conn->egress.new_token.max_acked < sent->data.new_token.generation)
            conn->egress.new_token.max_acked = sent->data.new_token.generation;
        break;
    default:
        break;
    }

    if (conn->egress.new_token.num_inflight == 0 && conn->egress.new_token.max_acked < conn->egress.new_token.generation)
        conn->pending.flows |= QUICLY_PENDING_FLOW_NEW_TOKEN_BIT;

    return 0;
}

static ssize_t round_send_window(ssize_t window)
{
    if (window < MIN_SEND_WINDOW * 2) {
        if (window < MIN_SEND_WINDOW) {
            return 0;
        } else {
            return MIN_SEND_WINDOW * 2;
        }
    }
    return window;
}

/* Helper function to compute send window based on:
 * * state of peer validation,
 * * current cwnd,
 * * minimum send requirements in |min_bytes_to_send|, and
 * * if sending is to be restricted to the minimum, indicated in |restrict_sending|
 */
static size_t calc_send_window(quicly_conn_t *conn, size_t min_bytes_to_send, int restrict_sending)
{
    /* If address is unvalidated, limit sending to 3x bytes received */
    if (!conn->super.peer.address_validation.validated) {
        uint64_t total = conn->super.stats.num_bytes.received * 3;
        if (conn->super.stats.num_bytes.sent + MIN_SEND_WINDOW <= total)
            return total - conn->super.stats.num_bytes.sent;
        return 0;
    }

    /* Validated address. Ensure there's enough window to send minimum number of packets */
    uint64_t window = 0;
    if (!restrict_sending && conn->egress.cc.cwnd > conn->egress.sentmap.bytes_in_flight + min_bytes_to_send)
        window = conn->egress.cc.cwnd - conn->egress.sentmap.bytes_in_flight;
    if (window < MIN_SEND_WINDOW)
        window = 0;
    if (window < min_bytes_to_send)
        window = min_bytes_to_send;
    return window;
}

int64_t quicly_get_first_timeout(quicly_conn_t *conn)
{
    if (conn->super.state >= QUICLY_STATE_CLOSING)
        return conn->egress.send_ack_at;

    if (calc_send_window(conn, 0, 0) > 0) {
        if (conn->pending.flows != 0)
            return 0;
        if (quicly_linklist_is_linked(&conn->pending.streams.control))
            return 0;
        if (scheduler_can_send(conn))
            return 0;
    } else if (!conn->super.peer.address_validation.validated) {
        return conn->idle_timeout.at;
    }

    int64_t at = conn->egress.loss.alarm_at;
    if (conn->egress.send_ack_at < at)
        at = conn->egress.send_ack_at;
    if (conn->idle_timeout.at < at)
        at = conn->idle_timeout.at;

    return at;
}

uint64_t quicly_get_next_expected_packet_number(quicly_conn_t *conn)
{
    if (!conn->application)
        return UINT64_MAX;

    return conn->application->super.next_expected_packet_number;
}

/* data structure that is used during one call through quicly_send()
 */
struct st_quicly_send_context_t {
    /* current encryption context */
    struct {
        struct st_quicly_cipher_context_t *cipher;
        uint8_t first_byte;
    } current;

    /* packet under construction */
    struct {
        quicly_datagram_t *packet;
        struct st_quicly_cipher_context_t *cipher;
        /**
         * points to the first byte of the target QUIC packet. It will not point to packet->octets.base[0] when the datagram
         * contains multiple QUIC packet.
         */
        uint8_t *first_byte_at;
        uint8_t ack_eliciting : 1;
    } target;

    /* output buffer into which list of datagrams is written */
    quicly_datagram_t **packets;
    /* max number of datagrams that can be stored in |packets| */
    size_t max_packets;
    /* number of datagrams currently stored in |packets| */
    size_t num_packets;
    /* the currently available window for sending (in bytes) */
    ssize_t send_window;
    /* location where next frame should be written */
    uint8_t *dst;
    /* end of the payload area, beyond which frames cannot be written */
    uint8_t *dst_end;
    /* address at which payload starts */
    uint8_t *dst_payload_from;
};

static int commit_send_packet(quicly_conn_t *conn, quicly_send_context_t *s, int coalesced)
{
    size_t packet_bytes_in_flight;

    assert(s->target.cipher->aead != NULL);

    assert(s->dst != s->dst_payload_from);

    /* pad so that the pn + payload would be at least 4 bytes */
    while (s->dst - s->dst_payload_from < QUICLY_MAX_PN_SIZE - QUICLY_SEND_PN_SIZE)
        *s->dst++ = QUICLY_FRAME_TYPE_PADDING;

    /* the last packet of first-flight datagrams is padded to become 1280 bytes */
    if (!coalesced && quicly_is_client(conn) &&
        (s->target.packet->data.base[0] & QUICLY_PACKET_TYPE_BITMASK) == QUICLY_PACKET_TYPE_INITIAL) {
        const size_t max_size = QUICLY_MAX_PACKET_SIZE - QUICLY_AEAD_TAG_SIZE;
        assert(quicly_is_client(conn));
        assert(s->dst - s->target.packet->data.base <= max_size);
        memset(s->dst, QUICLY_FRAME_TYPE_PADDING, s->target.packet->data.base + max_size - s->dst);
        s->dst = s->target.packet->data.base + max_size;
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

    /* AEAD protection */
    s->dst = s->dst_payload_from + ptls_aead_encrypt(s->target.cipher->aead, s->dst_payload_from, s->dst_payload_from,
                                                     s->dst - s->dst_payload_from, conn->egress.packet_number,
                                                     s->target.first_byte_at, s->dst_payload_from - s->target.first_byte_at);
    s->target.packet->data.len = s->dst - s->target.packet->data.base;
    assert(s->target.packet->data.len <= conn->super.ctx->max_packet_size);

    conn->super.ctx->crypto_engine->finalize_send_packet(
        conn->super.ctx->crypto_engine, conn, s->target.cipher->header_protection, s->target.cipher->aead, s->target.packet,
        s->target.first_byte_at - s->target.packet->data.base, s->dst_payload_from - s->target.packet->data.base, coalesced);

    /* update CC, commit sentmap */
    if (s->target.ack_eliciting) {
        packet_bytes_in_flight = s->dst - s->target.first_byte_at;
        s->send_window -= packet_bytes_in_flight;
    } else {
        packet_bytes_in_flight = 0;
    }
    if (quicly_sentmap_is_open(&conn->egress.sentmap))
        quicly_sentmap_commit(&conn->egress.sentmap, (uint16_t)packet_bytes_in_flight);

    QUICLY_PROBE(PACKET_COMMIT, conn, probe_now(), conn->egress.packet_number, s->dst - s->target.first_byte_at,
                 !s->target.ack_eliciting);
    QUICLY_PROBE(QUICTRACE_SENT, conn, probe_now(), conn->egress.packet_number, s->target.packet->data.len,
                 get_epoch(*s->target.first_byte_at));

    ++conn->egress.packet_number;
    ++conn->super.stats.num_packets.sent;

    if (!coalesced) {
        conn->super.stats.num_bytes.sent += s->target.packet->data.len;
        s->packets[s->num_packets++] = s->target.packet;
        s->target.packet = NULL;
        s->target.cipher = NULL;
        s->target.first_byte_at = NULL;
    }

    /* insert PN gap if necessary, registering the PN to the ack queue so that we'd close the connection in the event of receiving
     * an ACK for that gap. */
    if (conn->egress.packet_number >= conn->egress.next_pn_to_skip && !QUICLY_PACKET_IS_LONG_HEADER(s->current.first_byte) &&
        conn->super.state < QUICLY_STATE_CLOSING) {
        int ret;
        if ((ret = quicly_sentmap_prepare(&conn->egress.sentmap, conn->egress.packet_number, now, QUICLY_EPOCH_1RTT)) != 0)
            return ret;
        if (quicly_sentmap_allocate(&conn->egress.sentmap, on_invalid_ack) == NULL)
            return PTLS_ERROR_NO_MEMORY;
        quicly_sentmap_commit(&conn->egress.sentmap, 0);
        ++conn->egress.packet_number;
        conn->egress.next_pn_to_skip = calc_next_pn_to_skip(conn->super.ctx->tls, conn->egress.packet_number);
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
    if (s->target.packet != NULL) {
        if (coalescible) {
            size_t overhead =
                1 /* type */ + conn->super.peer.cid.len + QUICLY_SEND_PN_SIZE + s->current.cipher->aead->algo->tag_size;
            if (QUICLY_PACKET_IS_LONG_HEADER(s->current.first_byte))
                overhead += 4 /* version */ + 1 /* cidl */ + conn->super.peer.cid.len + conn->super.host.src_cid.len +
                            (s->current.first_byte == QUICLY_PACKET_TYPE_INITIAL) /* token_length == 0 */ + 2 /* length */;
            size_t packet_min_space = QUICLY_MAX_PN_SIZE - QUICLY_SEND_PN_SIZE;
            if (packet_min_space < min_space)
                packet_min_space = min_space;
            if (overhead + packet_min_space > s->dst_end - s->dst)
                coalescible = 0;
        }
        /* close out packet under construction */
        if ((ret = commit_send_packet(conn, s, coalescible)) != 0)
            return ret;
    } else {
        coalescible = 0;
    }

    /* allocate packet */
    if (coalescible) {
        s->dst_end += s->target.cipher->aead->algo->tag_size; /* restore the AEAD tag size (tag size can differ bet. epochs) */
        s->target.cipher = s->current.cipher;
    } else {
        if (s->num_packets >= s->max_packets)
            return QUICLY_ERROR_SENDBUF_FULL;
        s->send_window = round_send_window(s->send_window);
        if (ack_eliciting && s->send_window < (ssize_t)min_space)
            return QUICLY_ERROR_SENDBUF_FULL;
        if ((s->target.packet = conn->super.ctx->packet_allocator->alloc_packet(conn->super.ctx->packet_allocator,
                                                                                conn->super.ctx->max_packet_size)) == NULL)
            return PTLS_ERROR_NO_MEMORY;
        s->target.packet->dest = conn->super.peer.address;
        s->target.packet->src = conn->super.host.address;
        s->target.cipher = s->current.cipher;
        s->dst = s->target.packet->data.base;
        s->dst_end = s->target.packet->data.base + conn->super.ctx->max_packet_size;
    }
    s->target.ack_eliciting = 0;

    QUICLY_PROBE(PACKET_PREPARE, conn, probe_now(), s->current.first_byte,
                 QUICLY_PROBE_HEXDUMP(conn->super.peer.cid.cid, conn->super.peer.cid.len));

    /* emit header */
    s->target.first_byte_at = s->dst;
    *s->dst++ = s->current.first_byte | 0x1 /* pnlen == 2 */;
    if (QUICLY_PACKET_IS_LONG_HEADER(s->current.first_byte)) {
        s->dst = quicly_encode32(s->dst, conn->super.version);
        *s->dst++ = conn->super.peer.cid.len;
        s->dst = emit_cid(s->dst, &conn->super.peer.cid);
        *s->dst++ = conn->super.host.src_cid.len;
        s->dst = emit_cid(s->dst, &conn->super.host.src_cid);
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
        s->dst = emit_cid(s->dst, &conn->super.peer.cid);
    }
    s->dst += QUICLY_SEND_PN_SIZE; /* space for PN bits, filled in at commit time */
    s->dst_payload_from = s->dst;
    assert(s->target.cipher->aead != NULL);
    s->dst_end -= s->target.cipher->aead->algo->tag_size;
    assert(s->dst_end - s->dst >= QUICLY_MAX_PN_SIZE - QUICLY_SEND_PN_SIZE);

    /* register to sentmap */
    if (conn->super.state < QUICLY_STATE_CLOSING) {
        uint8_t ack_epoch = get_epoch(s->current.first_byte);
        if (ack_epoch == QUICLY_EPOCH_0RTT)
            ack_epoch = QUICLY_EPOCH_1RTT;
        if ((ret = quicly_sentmap_prepare(&conn->egress.sentmap, conn->egress.packet_number, now, ack_epoch)) != 0)
            return ret;
    }

TargetReady:
    if (ack_eliciting) {
        s->target.ack_eliciting = 1;
        conn->egress.last_retransmittable_sent_at = now;
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
    if ((*sent = quicly_sentmap_allocate(&conn->egress.sentmap, acked)) == NULL)
        return PTLS_ERROR_NO_MEMORY;

    /* TODO return the remaining window that the sender can use */
    return ret;
}

static int send_ack(quicly_conn_t *conn, struct st_quicly_pn_space_t *space, quicly_send_context_t *s)
{
    uint64_t ack_delay;
    int ret;

    if (space->ack_queue.num_ranges == 0)
        return 0;

    /* calc ack_delay */
    if (space->largest_pn_received_at < now) {
        /* We underreport ack_delay up to 1 milliseconds assuming that QUICLY_LOCAL_ACK_DELAY_EXPONENT is 10. It's considered a
         * non-issue because our time measurement is at millisecond granurality anyways. */
        ack_delay = ((now - space->largest_pn_received_at) * 1000) >> QUICLY_LOCAL_ACK_DELAY_EXPONENT;
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
            assert(s->target.first_byte_at != s->target.packet->data.base);
            *s->dst++ = QUICLY_FRAME_TYPE_PADDING;
        }
        if ((ret = commit_send_packet(conn, s, 0)) != 0)
            return ret;
        goto Emit;
    }

    /* when there are no less than QUICLY_NUM_ACK_BLOCKS_TO_INDUCE_ACKACK (8) gaps, bundle PING once every 4 packets being sent */
    if (space->ack_queue.num_ranges >= QUICLY_NUM_ACK_BLOCKS_TO_INDUCE_ACKACK && conn->egress.packet_number % 4 == 0 &&
        dst < s->dst_end)
        *dst++ = QUICLY_FRAME_TYPE_PING;

    s->dst = dst;

    { /* save what's inflight */
        size_t i;
        for (i = 0; i != space->ack_queue.num_ranges; ++i) {
            quicly_sent_t *sent;
            if ((sent = quicly_sentmap_allocate(&conn->egress.sentmap, on_ack_ack)) == NULL)
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

static int send_stream_control_frames(quicly_stream_t *stream, quicly_send_context_t *s)
{
    int ret;

    /* send STOP_SENDING if necessray */
    if (stream->_send_aux.stop_sending.sender_state == QUICLY_SENDER_STATE_SEND) {
        /* FIXME also send an empty STREAM frame */
        if ((ret = prepare_stream_state_sender(stream, &stream->_send_aux.stop_sending.sender_state, s,
                                               QUICLY_STOP_SENDING_FRAME_CAPACITY, on_ack_stop_sending)) != 0)
            return ret;
        s->dst = quicly_encode_stop_sending_frame(s->dst, stream->stream_id, stream->_send_aux.stop_sending.error_code);
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
        QUICLY_PROBE(MAX_STREAM_DATA_SEND, stream->conn, probe_now(), stream, new_value);
    }

    /* send RST_STREAM if necessary */
    if (stream->_send_aux.rst.sender_state == QUICLY_SENDER_STATE_SEND) {
        if ((ret = prepare_stream_state_sender(stream, &stream->_send_aux.rst.sender_state, s, QUICLY_RST_FRAME_CAPACITY,
                                               on_ack_rst_stream)) != 0)
            return ret;
        s->dst = quicly_encode_rst_stream_frame(s->dst, stream->stream_id, stream->_send_aux.rst.error_code,
                                                stream->sendstate.size_inflight);
    }

    return 0;
}

int quicly_is_flow_capped(quicly_conn_t *conn)
{
    return !(conn->egress.max_data.sent < conn->egress.max_data.permitted);
}

int quicly_can_send_stream_data(quicly_conn_t *conn, quicly_send_context_t *s)
{
    return s->num_packets < s->max_packets;
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
    stream->callbacks->on_send_emit(stream, (size_t)(off - stream->sendstate.acked.ranges[0].end), s->dst, &len, &wrote_all);
    if (stream->conn->super.state >= QUICLY_STATE_CLOSING) {
        return QUICLY_ERROR_IS_CLOSING;
    } else if (stream->_send_aux.rst.sender_state != QUICLY_SENDER_STATE_NONE) {
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
        assert(end_off + 1 == stream->sendstate.pending.ranges[stream->sendstate.pending.num_ranges - 1].end);
        assert(frame_type_at != NULL);
        is_fin = 1;
        *frame_type_at |= QUICLY_FRAME_TYPE_STREAM_BIT_FIN;
    } else {
        is_fin = 0;
    }

UpdateState:
    QUICLY_PROBE(STREAM_SEND, stream->conn, probe_now(), stream, off, end_off - off, is_fin);
    QUICLY_PROBE(QUICTRACE_SEND_STREAM, stream->conn, probe_now(), stream, off, end_off - off, is_fin);
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

/**
 * Returns the timeout for sentmap entries. This timeout is also used as the duration of CLOSING / DRAINING state, and therefore be
 * longer than 3PTO. At the moment, the value is 4PTO.
 */
static int64_t get_sentmap_expiration_time(quicly_conn_t *conn)
{
    return quicly_rtt_get_pto(&conn->egress.loss.rtt, conn->super.peer.transport_params.max_ack_delay,
                              conn->egress.loss.conf->min_pto) *
           4;
}

static void init_acks_iter(quicly_conn_t *conn, quicly_sentmap_iter_t *iter)
{
    /* TODO find a better threshold */
    int64_t retire_before = now - get_sentmap_expiration_time(conn);
    const quicly_sent_packet_t *sent;

    quicly_sentmap_init_iter(&conn->egress.sentmap, iter);

    while ((sent = quicly_sentmap_get(iter))->sent_at <= retire_before && sent->bytes_in_flight == 0)
        quicly_sentmap_update(&conn->egress.sentmap, iter, QUICLY_SENTMAP_EVENT_EXPIRED, conn);
}

int discard_sentmap_by_epoch(quicly_conn_t *conn, unsigned ack_epochs)
{
    quicly_sentmap_iter_t iter;
    const quicly_sent_packet_t *sent;
    int ret = 0;

    init_acks_iter(conn, &iter);

    while ((sent = quicly_sentmap_get(&iter))->packet_number != UINT64_MAX) {
        if ((ack_epochs & (1u << sent->ack_epoch)) != 0) {
            if ((ret = quicly_sentmap_update(&conn->egress.sentmap, &iter, QUICLY_SENTMAP_EVENT_EXPIRED, conn)) != 0)
                return ret;
        } else {
            quicly_sentmap_skip(&iter);
        }
    }

    return ret;
}

/**
 * Determine frames to be retransmitted on crypto timeout or PTO.
 */
static int mark_packets_as_lost(quicly_conn_t *conn, size_t count)
{
    quicly_sentmap_iter_t iter;
    int ret;

    assert(count != 0);

    init_acks_iter(conn, &iter);

    while (quicly_sentmap_get(&iter)->packet_number < conn->egress.max_lost_pn)
        quicly_sentmap_skip(&iter);

    do {
        const quicly_sent_packet_t *sent = quicly_sentmap_get(&iter);
        uint64_t pn;
        if ((pn = sent->packet_number) == UINT64_MAX) {
            assert(conn->egress.sentmap.bytes_in_flight == 0);
            break;
        }
        if (sent->bytes_in_flight != 0)
            --count;
        if ((ret = quicly_sentmap_update(&conn->egress.sentmap, &iter, QUICLY_SENTMAP_EVENT_LOST, conn)) != 0)
            return ret;
        conn->egress.max_lost_pn = pn + 1;
    } while (count != 0);

    return 0;
}

/* this function ensures that the value returned in loss_time is when the next
 * application timer should be set for loss detection. if no timer is required,
 * loss_time is set to INT64_MAX.
 */
static int do_detect_loss(quicly_loss_t *ld, uint64_t largest_acked, uint32_t delay_until_lost, int64_t *loss_time)
{
    quicly_conn_t *conn = (void *)((char *)ld - offsetof(quicly_conn_t, egress.loss));
    quicly_sentmap_iter_t iter;
    const quicly_sent_packet_t *sent;
    uint64_t largest_newly_lost_pn = UINT64_MAX;
    int ret;

    *loss_time = INT64_MAX;

    init_acks_iter(conn, &iter);

    /* Mark packets as lost if they are smaller than the largest_acked and outside either time-threshold or packet-threshold
     * windows.
     */
    while ((sent = quicly_sentmap_get(&iter))->packet_number < largest_acked &&
           (sent->sent_at <= now - delay_until_lost || /* time threshold */
            (largest_acked >= QUICLY_LOSS_DEFAULT_PACKET_THRESHOLD &&
             sent->packet_number <= largest_acked - QUICLY_LOSS_DEFAULT_PACKET_THRESHOLD))) { /* packet threshold */
        if (sent->bytes_in_flight != 0 && conn->egress.max_lost_pn <= sent->packet_number) {
            if (sent->packet_number != largest_newly_lost_pn) {
                ++conn->super.stats.num_packets.lost;
                largest_newly_lost_pn = sent->packet_number;
                quicly_cc_on_lost(&conn->egress.cc, sent->bytes_in_flight, sent->packet_number, conn->egress.packet_number);
                QUICLY_PROBE(PACKET_LOST, conn, probe_now(), largest_newly_lost_pn);
                QUICLY_PROBE(QUICTRACE_LOST, conn, probe_now(), largest_newly_lost_pn);
            }
            if ((ret = quicly_sentmap_update(&conn->egress.sentmap, &iter, QUICLY_SENTMAP_EVENT_LOST, conn)) != 0)
                return ret;
        } else {
            quicly_sentmap_skip(&iter);
        }
    }
    if (largest_newly_lost_pn != UINT64_MAX) {
        conn->egress.max_lost_pn = largest_newly_lost_pn + 1;
        QUICLY_PROBE(CC_CONGESTION, conn, probe_now(), conn->egress.max_lost_pn, conn->egress.sentmap.bytes_in_flight,
                     conn->egress.cc.cwnd);
        QUICLY_PROBE(QUICTRACE_CC_LOST, conn, probe_now(), &conn->egress.loss.rtt, conn->egress.cc.cwnd,
                     conn->egress.sentmap.bytes_in_flight);
    }

    /* schedule time-threshold alarm if there is a packet outstanding that is smaller than largest_acked */
    while (sent->packet_number < largest_acked && sent->sent_at != INT64_MAX) {
        if (sent->bytes_in_flight != 0) {
            *loss_time = sent->sent_at + delay_until_lost;
            break;
        }
        quicly_sentmap_skip(&iter);
        sent = quicly_sentmap_get(&iter);
    }

    return 0;
}

static int send_max_streams(quicly_conn_t *conn, int uni, quicly_send_context_t *s)
{
    if (!should_send_max_streams(conn, uni))
        return 0;

    quicly_maxsender_t *maxsender = uni ? conn->ingress.max_streams.uni : conn->ingress.max_streams.bidi;
    struct st_quicly_conn_streamgroup_state_t *group = uni ? &conn->super.peer.uni : &conn->super.peer.bidi;
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

    QUICLY_PROBE(MAX_STREAMS_SEND, conn, probe_now(), new_count, uni);

    return 0;
}

static int send_streams_blocked(quicly_conn_t *conn, int uni, quicly_send_context_t *s)
{
    quicly_linklist_t *blocked_list = uni ? &conn->pending.streams.blocked.uni : &conn->pending.streams.blocked.bidi;
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

    QUICLY_PROBE(STREAMS_BLOCKED_SEND, conn, probe_now(), max_streams->count, uni);

    return 0;
}

static void open_blocked_streams(quicly_conn_t *conn, int uni)
{
    uint64_t count;
    quicly_linklist_t *anchor;

    if (uni) {
        count = conn->egress.max_streams.uni.count;
        anchor = &conn->pending.streams.blocked.uni;
    } else {
        count = conn->egress.max_streams.bidi.count;
        anchor = &conn->pending.streams.blocked.bidi;
    }

    while (quicly_linklist_is_linked(anchor)) {
        quicly_stream_t *stream = (void *)((char *)anchor->next - offsetof(quicly_stream_t, _send_aux.pending_link.control));
        if (stream->stream_id / 4 >= count)
            break;
        assert(stream->streams_blocked);
        quicly_linklist_unlink(&stream->_send_aux.pending_link.control);
        stream->streams_blocked = 0;
        stream->_send_aux.max_stream_data = quicly_stream_is_unidirectional(stream->stream_id)
                                                ? conn->super.peer.transport_params.max_stream_data.uni
                                                : conn->super.peer.transport_params.max_stream_data.bidi_remote;
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
    conn->pending.flows &= ~QUICLY_PENDING_FLOW_HANDSHAKE_DONE_BIT;
    QUICLY_PROBE(HANDSHAKE_DONE_SEND, conn, probe_now());

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
    token = (quicly_address_token_plaintext_t){0, conn->super.ctx->now->cb(conn->super.ctx->now)};
    token.remote = conn->super.peer.address;
    /* TODO fill token.resumption */

    /* encrypt */
    if ((ret = conn->super.ctx->generate_resumption_token->cb(conn->super.ctx->generate_resumption_token, conn, &tokenbuf,
                                                              &token)) != 0)
        goto Exit;

    /* emit frame */
    if ((ret = allocate_ack_eliciting_frame(conn, s, quicly_new_token_frame_capacity(ptls_iovec_init(tokenbuf.base, tokenbuf.off)),
                                            &sent, on_ack_new_token)) != 0)
        goto Exit;
    sent->data.new_token.generation = conn->egress.new_token.generation;
    s->dst = quicly_encode_new_token_frame(s->dst, ptls_iovec_init(tokenbuf.base, tokenbuf.off));
    conn->pending.flows &= ~QUICLY_PENDING_FLOW_NEW_TOKEN_BIT;

    QUICLY_PROBE(NEW_TOKEN_SEND, conn, probe_now(), tokenbuf.base, tokenbuf.off, sent->data.new_token.generation);
    ret = 0;
Exit:
    ptls_buffer_dispose(&tokenbuf);
    return ret;
}

quicly_datagram_t *quicly_send_version_negotiation(quicly_context_t *ctx, struct sockaddr *dest_addr, ptls_iovec_t dest_cid,
                                                   struct sockaddr *src_addr, ptls_iovec_t src_cid)
{
    quicly_datagram_t *packet;
    uint8_t *dst;

    if ((packet = ctx->packet_allocator->alloc_packet(ctx->packet_allocator, ctx->max_packet_size)) == NULL)
        return NULL;
    set_address(&packet->dest, dest_addr);
    set_address(&packet->src, src_addr);
    dst = packet->data.base;

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
    dst = quicly_encode32(dst, QUICLY_PROTOCOL_VERSION);

    packet->data.len = dst - packet->data.base;

    return packet;
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

quicly_datagram_t *quicly_send_retry(quicly_context_t *ctx, ptls_aead_context_t *token_encrypt_ctx, struct sockaddr *dest_addr,
                                     ptls_iovec_t dest_cid, struct sockaddr *src_addr, ptls_iovec_t src_cid, ptls_iovec_t odcid,
                                     ptls_iovec_t token_prefix, ptls_iovec_t appdata, ptls_aead_context_t **retry_aead_cache)
{
    quicly_address_token_plaintext_t token;
    quicly_datagram_t *packet = NULL;
    ptls_buffer_t buf;
    int ret;

    assert(!(src_cid.len == odcid.len && memcmp(src_cid.base, odcid.base, src_cid.len) == 0));

    /* build token as plaintext */
    token = (quicly_address_token_plaintext_t){1, ctx->now->cb(ctx->now)};
    set_address(&token.remote, dest_addr);
    set_address(&token.local, src_addr);

    set_cid(&token.retry.odcid, odcid);
    if ((ret = quicly_retry_calc_cidpair_hash(get_aes128gcmsha256(ctx)->hash, dest_cid, src_cid, &token.retry.cidpair_hash)) != 0)
        goto Exit;
    if (appdata.len != 0) {
        assert(appdata.len <= sizeof(token.appdata.bytes));
        memcpy(token.appdata.bytes, appdata.base, appdata.len);
        token.appdata.len = appdata.len;
    }

    /* start building the packet */
    if ((packet = ctx->packet_allocator->alloc_packet(ctx->packet_allocator, ctx->max_packet_size)) == NULL)
        goto Exit;
    set_address(&packet->dest, dest_addr);
    set_address(&packet->src, src_addr);
    ptls_buffer_init(&buf, packet->data.base, ctx->max_packet_size);

    /* first generate a pseudo packet */
    ptls_buffer_push_block(&buf, 1, { ptls_buffer_pushv(&buf, odcid.base, odcid.len); });
    ctx->tls->random_bytes(buf.base + buf.off, 1);
    buf.base[buf.off] = QUICLY_PACKET_TYPE_RETRY | (buf.base[buf.off] & 0x0f);
    ++buf.off;
    ptls_buffer_push32(&buf, QUICLY_PROTOCOL_VERSION);
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
    assert(!buf.is_allocated);
    {
        ptls_aead_context_t *aead =
            retry_aead_cache != NULL && *retry_aead_cache != NULL ? *retry_aead_cache : create_retry_aead(ctx, 1);
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

    packet->data.len = buf.off;
    ret = 0;

Exit:
    if (ret != 0) {
        if (packet != NULL)
            ctx->packet_allocator->free_packet(ctx->packet_allocator, packet);
    }
    return packet;
}

static int send_handshake_flow(quicly_conn_t *conn, size_t epoch, quicly_send_context_t *s, int ack_only, int send_probe)
{
    struct st_quicly_pn_space_t *ack_space = NULL;
    int ret = 0;

    switch (epoch) {
    case QUICLY_EPOCH_INITIAL:
        if (conn->initial == NULL || (s->current.cipher = &conn->initial->cipher.egress)->aead == NULL)
            return 0;
        s->current.first_byte = QUICLY_PACKET_TYPE_INITIAL;
        ack_space = &conn->initial->super;
        break;
    case QUICLY_EPOCH_HANDSHAKE:
        if (conn->handshake == NULL || (s->current.cipher = &conn->handshake->cipher.egress)->aead == NULL)
            return 0;
        s->current.first_byte = QUICLY_PACKET_TYPE_HANDSHAKE;
        ack_space = &conn->handshake->super;
        break;
    default:
        assert(!"logic flaw");
        return 0;
    }

    /* send ACK */
    if (ack_space != NULL && ack_space->unacked_count != 0)
        if ((ret = send_ack(conn, ack_space, s)) != 0)
            goto Exit;

    if (!ack_only) {
        /* send data */
        while ((conn->pending.flows & (uint8_t)(1 << epoch)) != 0) {
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
            conn->egress.last_retransmittable_sent_at = now;
        }
    }

Exit:
    return ret;
}

static int send_connection_close(quicly_conn_t *conn, quicly_send_context_t *s)
{
    uint8_t frame_header_buf[1 + 8 + 8 + 8], *p;
    size_t reason_phrase_len = strlen(conn->egress.connection_close.reason_phrase);
    int ret;

    /* build the frame excluding the reason_phrase */
    p = frame_header_buf;
    *p++ = conn->egress.connection_close.frame_type != UINT64_MAX ? QUICLY_FRAME_TYPE_TRANSPORT_CLOSE
                                                                  : QUICLY_FRAME_TYPE_APPLICATION_CLOSE;
    p = quicly_encodev(p, conn->egress.connection_close.error_code);
    if (conn->egress.connection_close.frame_type != UINT64_MAX)
        p = quicly_encodev(p, conn->egress.connection_close.frame_type);
    p = quicly_encodev(p, reason_phrase_len);

    /* allocate and write the frame */
    if ((ret = allocate_frame(conn, s, p - frame_header_buf + reason_phrase_len)) != 0)
        return ret;
    memcpy(s->dst, frame_header_buf, p - frame_header_buf);
    s->dst += p - frame_header_buf;
    memcpy(s->dst, conn->egress.connection_close.reason_phrase, reason_phrase_len);
    s->dst += reason_phrase_len;

    if (conn->egress.connection_close.frame_type != UINT64_MAX) {
        QUICLY_PROBE(TRANSPORT_CLOSE_SEND, conn, probe_now(), conn->egress.connection_close.error_code,
                     conn->egress.connection_close.frame_type, conn->egress.connection_close.reason_phrase);
    } else {
        QUICLY_PROBE(APPLICATION_CLOSE_SEND, conn, probe_now(), conn->egress.connection_close.error_code,
                     conn->egress.connection_close.reason_phrase);
    }
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

    QUICLY_PROBE(CRYPTO_UPDATE_SECRET, conn, is_enc, epoch, log_label, QUICLY_PROBE_HEXDUMP(secret, cipher->hash->digest_size));

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
            if ((ret = apply_peer_transport_params(conn)) != 0)
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
    }

    return 0;
}

static int do_send(quicly_conn_t *conn, quicly_send_context_t *s)
{
    int restrict_sending = 0, ack_only = 0, ret;
    size_t min_packets_to_send = 0;

    /* handle timeouts */
    if (conn->egress.loss.alarm_at <= now) {
        if ((ret = quicly_loss_on_alarm(&conn->egress.loss, conn->egress.packet_number - 1,
                                        conn->egress.loss.largest_acked_packet_plus1 - 1, do_detect_loss, &min_packets_to_send,
                                        &restrict_sending)) != 0)
            goto Exit;
        assert(min_packets_to_send > 0);
        assert(min_packets_to_send <= s->max_packets);

        if (restrict_sending) {
            /* PTO (try to send new data when handshake is done, otherwise retire oldest handshake packets and retransmit) */
            QUICLY_PROBE(PTO, conn, probe_now(), conn->egress.sentmap.bytes_in_flight, conn->egress.cc.cwnd,
                         conn->egress.loss.pto_count);
            if (ptls_handshake_is_complete(conn->crypto.tls) && scheduler_can_send(conn)) {
                /* we have something to send (TODO we might want to make sure that we emit something even when the stream scheduler
                 * in fact sends nothing) */
            } else {
                /* mark something inflight as lost */
                if ((ret = mark_packets_as_lost(conn, min_packets_to_send)) != 0)
                    goto Exit;
            }
        }
    } else if (conn->idle_timeout.at <= now) {
        QUICLY_PROBE(IDLE_TIMEOUT, conn, probe_now());
        conn->super.state = QUICLY_STATE_DRAINING;
        destroy_all_streams(conn, 0, 0);
        return QUICLY_ERROR_FREE_CONNECTION;
    }

    s->send_window = calc_send_window(conn, min_packets_to_send * conn->super.ctx->max_packet_size, restrict_sending);
    if (s->send_window == 0)
        ack_only = 1;

    /* send handshake flows */
    if ((ret = send_handshake_flow(conn, QUICLY_EPOCH_INITIAL, s, ack_only,
                                   restrict_sending ||
                                       (conn->super.peer.address_validation.send_probe && conn->handshake == NULL))) != 0)
        goto Exit;
    if ((ret = send_handshake_flow(conn, QUICLY_EPOCH_HANDSHAKE, s, ack_only,
                                   restrict_sending || conn->super.peer.address_validation.send_probe)) != 0)
        goto Exit;

    /* send encrypted frames */
    if (conn->application != NULL && (s->current.cipher = &conn->application->cipher.egress.key)->header_protection != NULL) {
        s->current.first_byte = conn->application->one_rtt_writable ? QUICLY_QUIC_BIT : QUICLY_PACKET_TYPE_0RTT;
        /* acks */
        if (conn->application->one_rtt_writable && conn->egress.send_ack_at <= now && conn->application->super.unacked_count != 0) {
            if ((ret = send_ack(conn, &conn->application->super, s)) != 0)
                goto Exit;
        }
        if (!ack_only) {
            /* PTO, always send PING. This is the easiest thing to do in terms of timer control. */
            if (restrict_sending) {
                if ((ret = _do_allocate_frame(conn, s, 1, 1)) != 0)
                    goto Exit;
                *s->dst++ = QUICLY_FRAME_TYPE_PING;
            }
            /* take actions only permitted for short header packets */
            if (conn->application->one_rtt_writable) {
                /* send HANDSHAKE_DONE */
                if ((conn->pending.flows & QUICLY_PENDING_FLOW_HANDSHAKE_DONE_BIT) != 0 &&
                    (ret = send_handshake_done(conn, s)) != 0)
                    goto Exit;
                /* post-handshake messages */
                if ((conn->pending.flows & (uint8_t)(1 << QUICLY_EPOCH_1RTT)) != 0) {
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
                /* send connection-level flow control frame */
                if (should_send_max_data(conn)) {
                    quicly_sent_t *sent;
                    if ((ret = allocate_ack_eliciting_frame(conn, s, QUICLY_MAX_DATA_FRAME_CAPACITY, &sent, on_ack_max_data)) != 0)
                        goto Exit;
                    uint64_t new_value = conn->ingress.max_data.bytes_consumed + conn->super.ctx->transport_params.max_data;
                    s->dst = quicly_encode_max_data_frame(s->dst, new_value);
                    quicly_maxsender_record(&conn->ingress.max_data.sender, new_value, &sent->data.max_data.args);
                    QUICLY_PROBE(MAX_DATA_SEND, conn, probe_now(), new_value);
                }
                /* send streams_blocked frames */
                if ((ret = send_streams_blocked(conn, 1, s)) != 0)
                    goto Exit;
                if ((ret = send_streams_blocked(conn, 0, s)) != 0)
                    goto Exit;
                /* send NEW_TOKEN */
                if ((conn->pending.flows & QUICLY_PENDING_FLOW_NEW_TOKEN_BIT) != 0 && (ret = send_resumption_token(conn, s)) != 0)
                    goto Exit;
            }
            /* send stream-level control frames */
            while (s->num_packets != s->max_packets && quicly_linklist_is_linked(&conn->pending.streams.control)) {
                quicly_stream_t *stream = (void *)((char *)conn->pending.streams.control.next -
                                                   offsetof(quicly_stream_t, _send_aux.pending_link.control));
                if ((ret = send_stream_control_frames(stream, s)) != 0)
                    goto Exit;
                quicly_linklist_unlink(&stream->_send_aux.pending_link.control);
            }
            /* send STREAM frames */
            if ((ret = conn->super.ctx->stream_scheduler->do_send(conn->super.ctx->stream_scheduler, conn, s)) != 0)
                goto Exit;
        }
    }

Exit:
    if (ret == QUICLY_ERROR_SENDBUF_FULL)
        ret = 0;
    if (ret == 0 && s->target.packet != NULL)
        commit_send_packet(conn, s, 0);
    if (ret == 0) {
        if (conn->application == NULL || conn->application->super.unacked_count == 0)
            conn->egress.send_ack_at = INT64_MAX; /* we have sent ACKs for every epoch (or before address validation) */
        update_loss_alarm(conn);
        if (s->num_packets != 0)
            update_idle_timeout(conn, 0);
    }
    return ret;
}

int quicly_send(quicly_conn_t *conn, quicly_datagram_t **packets, size_t *num_packets)
{
    quicly_send_context_t s = {{NULL, -1}, {NULL, NULL, NULL}, packets, *num_packets};
    int ret;

    update_now(conn->super.ctx);

    /* bail out if there's nothing is scheduled to be sent */
    if (now < quicly_get_first_timeout(conn)) {
        *num_packets = 0;
        return 0;
    }

    QUICLY_PROBE(SEND, conn, probe_now(), conn->super.state,
                 QUICLY_PROBE_HEXDUMP(conn->super.peer.cid.cid, conn->super.peer.cid.len));

    if (conn->super.state >= QUICLY_STATE_CLOSING) {
        /* check if the connection can be closed now (after 3 pto) */
        quicly_sentmap_iter_t iter;
        init_acks_iter(conn, &iter);
        if (quicly_sentmap_get(&iter)->packet_number == UINT64_MAX)
            return QUICLY_ERROR_FREE_CONNECTION;
        if (conn->super.state == QUICLY_STATE_CLOSING && conn->egress.send_ack_at <= now) {
            destroy_all_streams(conn, 0, 0); /* delayed until the emission of CONNECTION_CLOSE frame to allow quicly_close to be
                                              * called from a stream handler */
            if (conn->application != NULL && conn->application->one_rtt_writable) {
                s.current.cipher = &conn->application->cipher.egress.key;
                s.current.first_byte = QUICLY_QUIC_BIT;
            } else if (conn->handshake != NULL && (s.current.cipher = &conn->handshake->cipher.egress)->aead != NULL) {
                s.current.first_byte = QUICLY_PACKET_TYPE_HANDSHAKE;
            } else {
                s.current.cipher = &conn->initial->cipher.egress;
                assert(s.current.cipher->aead != NULL);
                s.current.first_byte = QUICLY_PACKET_TYPE_INITIAL;
            }
            if ((ret = send_connection_close(conn, &s)) != 0)
                return ret;
            if ((ret = commit_send_packet(conn, &s, 0)) != 0)
                return ret;
        }
        conn->egress.send_ack_at = quicly_sentmap_get(&iter)->sent_at + get_sentmap_expiration_time(conn);
        assert(conn->egress.send_ack_at > now);
        *num_packets = s.num_packets;
        return 0;
    }

    /* emit packets */
    if ((ret = do_send(conn, &s)) != 0)
        return ret;
    /* We might see the timer going back to the past, if time-threshold loss timer fires first without being able to make any
     * progress (i.e. due to the payload of lost packet being cancelled), then PTO for the previously sent packet.  To accomodate
     * that, we allow to rerun the do_send function just once.
     */
    if (s.num_packets == 0 && conn->egress.loss.alarm_at <= now) {
        assert(conn->egress.loss.alarm_at == now);
        if ((ret = do_send(conn, &s)) != 0)
            return ret;
    }
    assert_consistency(conn, 1);

    *num_packets = s.num_packets;
    return ret;
}

quicly_datagram_t *quicly_send_stateless_reset(quicly_context_t *ctx, struct sockaddr *dest_addr, struct sockaddr *src_addr,
                                               const void *src_cid)
{
    quicly_datagram_t *dgram;

    /* allocate packet, set peer address */
    if ((dgram = ctx->packet_allocator->alloc_packet(ctx->packet_allocator, QUICLY_STATELESS_RESET_PACKET_MIN_LEN)) == NULL)
        return NULL;
    set_address(&dgram->dest, dest_addr);
    set_address(&dgram->src, src_addr);

    /* build stateless reset packet */
    ctx->tls->random_bytes(dgram->data.base, QUICLY_STATELESS_RESET_PACKET_MIN_LEN - QUICLY_STATELESS_RESET_TOKEN_LEN);
    dgram->data.base[0] = (dgram->data.base[0] & ~QUICLY_LONG_HEADER_BIT) | QUICLY_QUIC_BIT;
    if (!ctx->cid_encryptor->generate_stateless_reset_token(
            ctx->cid_encryptor, dgram->data.base + QUICLY_STATELESS_RESET_PACKET_MIN_LEN - QUICLY_STATELESS_RESET_TOKEN_LEN,
            src_cid)) {
        ctx->packet_allocator->free_packet(ctx->packet_allocator, dgram);
        return NULL;
    }
    dgram->data.len = QUICLY_STATELESS_RESET_PACKET_MIN_LEN;

    return dgram;
}

int quicly_send_resumption_token(quicly_conn_t *conn)
{
    if (conn->super.state <= QUICLY_STATE_CONNECTED) {
        ++conn->egress.new_token.generation;
        conn->pending.flows |= QUICLY_PENDING_FLOW_NEW_TOKEN_BIT;
    }
    return 0;
}

static int on_end_closing(quicly_conn_t *conn, const quicly_sent_packet_t *packet, quicly_sent_t *sent,
                          quicly_sentmap_event_t event)
{
    /* we stop accepting frames by the time this ack callback is being registered */
    assert(event != QUICLY_SENTMAP_EVENT_ACKED);
    return 0;
}

static int enter_close(quicly_conn_t *conn, int host_is_initiating, int wait_draining)
{
    int ret;

    assert(conn->super.state < QUICLY_STATE_CLOSING);

    /* release all inflight info, register a close timeout */
    if ((ret = discard_sentmap_by_epoch(conn, ~0u)) != 0)
        return ret;
    if ((ret = quicly_sentmap_prepare(&conn->egress.sentmap, conn->egress.packet_number, now, QUICLY_EPOCH_INITIAL)) != 0)
        return ret;
    if (quicly_sentmap_allocate(&conn->egress.sentmap, on_end_closing) == NULL)
        return PTLS_ERROR_NO_MEMORY;
    quicly_sentmap_commit(&conn->egress.sentmap, 0);
    ++conn->egress.packet_number;

    if (host_is_initiating) {
        conn->super.state = QUICLY_STATE_CLOSING;
        conn->egress.send_ack_at = 0;
    } else {
        conn->super.state = QUICLY_STATE_DRAINING;
        conn->egress.send_ack_at = wait_draining ? now + get_sentmap_expiration_time(conn) : 0;
    }

    update_loss_alarm(conn);

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
    if (QUICLY_ERROR_IS_QUIC_TRANSPORT(err)) {
        quic_error_code = QUICLY_ERROR_GET_ERROR_CODE(err);
    } else if (QUICLY_ERROR_IS_QUIC_APPLICATION(err)) {
        quic_error_code = QUICLY_ERROR_GET_ERROR_CODE(err);
        frame_type = UINT64_MAX;
    } else if (PTLS_ERROR_GET_CLASS(err) == PTLS_ERROR_CLASS_SELF_ALERT) {
        quic_error_code = QUICLY_TRANSPORT_ERROR_TLS_ALERT_BASE + PTLS_ERROR_TO_ALERT(err);
    } else {
        quic_error_code = QUICLY_ERROR_GET_ERROR_CODE(QUICLY_TRANSPORT_ERROR_INTERNAL);
        frame_type = UINT64_MAX;
    }

    conn->egress.connection_close.error_code = quic_error_code;
    conn->egress.connection_close.frame_type = frame_type;
    conn->egress.connection_close.reason_phrase = reason_phrase;
    return enter_close(conn, 1, 0);
}

int quicly_close(quicly_conn_t *conn, int err, const char *reason_phrase)
{
    assert(err == 0 || QUICLY_ERROR_IS_QUIC_APPLICATION(err));
    update_now(conn->super.ctx);

    return initiate_close(conn, err, QUICLY_FRAME_TYPE_PADDING /* used when err == 0 */, reason_phrase);
}

static int get_stream_or_open_if_new(quicly_conn_t *conn, uint64_t stream_id, quicly_stream_t **stream)
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
                max_stream_data_remote = conn->super.peer.transport_params.max_stream_data.bidi_local;
            }
            do {
                if ((*stream = open_stream(conn, group->next_stream_id, (uint32_t)max_stream_data_local, max_stream_data_remote)) ==
                    NULL) {
                    ret = PTLS_ERROR_NO_MEMORY;
                    goto Exit;
                }
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
    QUICLY_PROBE(QUICTRACE_RECV_STREAM, conn, probe_now(), frame.stream_id, frame.offset, frame.data.len, (int)frame.is_fin);
    if ((ret = get_stream_or_open_if_new(conn, frame.stream_id, &stream)) != 0 || stream == NULL)
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

    if ((ret = get_stream_or_open_if_new(conn, frame.stream_id, &stream)) != 0 || stream == NULL)
        return ret;

    if (!quicly_recvstate_transfer_complete(&stream->recvstate)) {
        uint64_t bytes_missing;
        if ((ret = quicly_recvstate_reset(&stream->recvstate, frame.final_offset, &bytes_missing)) != 0)
            return ret;
        stream->conn->ingress.max_data.bytes_consumed += bytes_missing;
        stream->callbacks->on_receive_reset(stream, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(frame.app_error_code));
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
        uint64_t packet_number;
        int64_t sent_at;
    } largest_newly_acked = {UINT64_MAX, INT64_MAX};
    size_t bytes_acked = 0;
    int includes_ack_eliciting = 0, ret;

    if ((ret = quicly_decode_ack_frame(&state->src, state->end, &frame, state->frame_type == QUICLY_FRAME_TYPE_ACK_ECN)) != 0)
        return ret;

    uint64_t packet_number = frame.smallest_acknowledged;

    switch (state->epoch) {
    case QUICLY_EPOCH_0RTT:
        return QUICLY_TRANSPORT_ERROR_PROTOCOL_VIOLATION;
    case QUICLY_EPOCH_HANDSHAKE:
        conn->super.peer.address_validation.send_probe = 0;
        break;
    default:
        break;
    }

    init_acks_iter(conn, &iter);

    /* TODO log PNs being ACKed too late */

    size_t gap_index = frame.num_gaps;
    while (1) {
        uint64_t block_length = frame.ack_block_lengths[gap_index];
        if (block_length != 0) {
            QUICLY_PROBE(QUICTRACE_RECV_ACK, conn, probe_now(), packet_number, packet_number + block_length - 1);
            while (quicly_sentmap_get(&iter)->packet_number < packet_number)
                quicly_sentmap_skip(&iter);
            do {
                const quicly_sent_packet_t *sent;
                if ((sent = quicly_sentmap_get(&iter))->packet_number == packet_number) {
                    ++conn->super.stats.num_packets.ack_received;
                    if (state->epoch == sent->ack_epoch) {
                        largest_newly_acked.packet_number = packet_number;
                        largest_newly_acked.sent_at = sent->sent_at;
                        includes_ack_eliciting |= sent->ack_eliciting;
                        QUICLY_PROBE(PACKET_ACKED, conn, probe_now(), packet_number, 1);
                        if (sent->bytes_in_flight != 0) {
                            bytes_acked += sent->bytes_in_flight;
                        }
                        if ((ret = quicly_sentmap_update(&conn->egress.sentmap, &iter, QUICLY_SENTMAP_EVENT_ACKED, conn)) != 0)
                            return ret;
                        if (state->epoch == QUICLY_EPOCH_1RTT) {
                            struct st_quicly_application_space_t *space = conn->application;
                            if (space->cipher.egress.key_update_pn.last <= packet_number) {
                                space->cipher.egress.key_update_pn.last = UINT64_MAX;
                                space->cipher.egress.key_update_pn.next =
                                    conn->egress.packet_number + conn->super.ctx->max_packets_per_key;
                                QUICLY_PROBE(CRYPTO_SEND_KEY_UPDATE_CONFIRMED, conn, space->cipher.egress.key_update_pn.next);
                            }
                        }
                    } else {
                        quicly_sentmap_skip(&iter);
                    }
                }
                ++packet_number;
            } while (--block_length != 0);
        }
        if (gap_index-- == 0)
            break;
        packet_number += frame.gaps[gap_index];
    }

    QUICLY_PROBE(QUICTRACE_RECV_ACK_DELAY, conn, probe_now(), frame.ack_delay);

    /* Update loss detection engine on ack. The function uses ack_delay only when the largest_newly_acked is also the largest acked
     * so far. So, it does not matter if the ack_delay being passed in does not apply to the largest_newly_acked. */
    quicly_loss_on_ack_received(&conn->egress.loss, largest_newly_acked.packet_number, now, largest_newly_acked.sent_at,
                                frame.ack_delay, includes_ack_eliciting);

    /* OnPacketAcked and OnPacketAckedCC */
    if (bytes_acked > 0) {
        quicly_cc_on_acked(&conn->egress.cc, (uint32_t)bytes_acked, frame.largest_acknowledged,
                           (uint32_t)(conn->egress.sentmap.bytes_in_flight + bytes_acked));
        QUICLY_PROBE(QUICTRACE_CC_ACK, conn, probe_now(), &conn->egress.loss.rtt, conn->egress.cc.cwnd,
                     conn->egress.sentmap.bytes_in_flight);
    }

    QUICLY_PROBE(CC_ACK_RECEIVED, conn, probe_now(), frame.largest_acknowledged, bytes_acked, conn->egress.cc.cwnd,
                 conn->egress.sentmap.bytes_in_flight);

    /* loss-detection  */
    quicly_loss_detect_loss(&conn->egress.loss, frame.largest_acknowledged, do_detect_loss);
    update_loss_alarm(conn);

    return 0;
}

static int handle_max_stream_data_frame(quicly_conn_t *conn, struct st_quicly_handle_payload_state_t *state)
{
    quicly_max_stream_data_frame_t frame;
    quicly_stream_t *stream;
    int ret;

    if ((ret = quicly_decode_max_stream_data_frame(&state->src, state->end, &frame)) != 0)
        return ret;

    QUICLY_PROBE(MAX_STREAM_DATA_RECEIVE, conn, probe_now(), frame.stream_id, frame.max_stream_data);

    if (!quicly_stream_has_send_side(quicly_is_client(conn), frame.stream_id))
        return QUICLY_TRANSPORT_ERROR_FRAME_ENCODING;

    if ((stream = quicly_get_stream(conn, frame.stream_id)) == NULL)
        return 0;

    if (frame.max_stream_data < stream->_send_aux.max_stream_data)
        return 0;
    stream->_send_aux.max_stream_data = frame.max_stream_data;

    if (stream->_send_aux.rst.sender_state == QUICLY_SENDER_STATE_NONE)
        resched_stream_data(stream);

    return 0;
}

static int handle_data_blocked_frame(quicly_conn_t *conn, struct st_quicly_handle_payload_state_t *state)
{
    quicly_data_blocked_frame_t frame;
    int ret;

    if ((ret = quicly_decode_data_blocked_frame(&state->src, state->end, &frame)) != 0)
        return ret;

    QUICLY_PROBE(DATA_BLOCKED_RECEIVE, conn, probe_now(), frame.offset);

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

    QUICLY_PROBE(STREAM_DATA_BLOCKED_RECEIVE, conn, probe_now(), frame.stream_id, frame.offset);

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

    QUICLY_PROBE(STREAMS_BLOCKED_RECEIVE, conn, probe_now(), frame.count, uni);

    quicly_maxsender_t *maxsender = uni ? conn->ingress.max_streams.uni : conn->ingress.max_streams.bidi;
    if (maxsender != NULL) {
        quicly_maxsender_request_transmit(maxsender);
        if (should_send_max_streams(conn, uni))
            conn->egress.send_ack_at = 0;
    }

    return 0;
}

static int handle_max_streams_frame(quicly_conn_t *conn, struct st_quicly_handle_payload_state_t *state)
{
    quicly_max_streams_frame_t frame;
    int uni = state->frame_type == QUICLY_FRAME_TYPE_MAX_STREAMS_UNI, ret;

    if ((ret = quicly_decode_max_streams_frame(&state->src, state->end, &frame)) != 0)
        return ret;

    QUICLY_PROBE(MAX_STREAMS_RECEIVE, conn, probe_now(), frame.count, uni);

    if ((ret = update_max_streams(uni ? &conn->egress.max_streams.uni : &conn->egress.max_streams.bidi, frame.count)) != 0)
        return ret;

    open_blocked_streams(conn, uni);

    return 0;
}

static int handle_path_challenge_frame(quicly_conn_t *conn, struct st_quicly_handle_payload_state_t *state)
{
    quicly_path_challenge_frame_t frame;
    int ret;

    if ((ret = quicly_decode_path_challenge_frame(&state->src, state->end, &frame)) != 0)
        return ret;
    return schedule_path_challenge(conn, 1, frame.data);
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
    QUICLY_PROBE(NEW_TOKEN_RECEIVE, conn, probe_now(), frame.token.base, frame.token.len);
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

    if ((ret = get_stream_or_open_if_new(conn, frame.stream_id, &stream)) != 0 || stream == NULL)
        return ret;

    if (quicly_sendstate_is_open(&stream->sendstate)) {
        /* reset the stream, then notify the application */
        int err = QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(frame.app_error_code);
        quicly_reset_stream(stream, err);
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

    QUICLY_PROBE(MAX_DATA_RECEIVE, conn, probe_now(), frame.max_data);

    if (frame.max_data < conn->egress.max_data.permitted)
        return 0;
    conn->egress.max_data.permitted = frame.max_data;

    return 0;
}

static int negotiate_using_version(quicly_conn_t *conn, uint32_t version)
{
    /* set selected version */
    conn->super.version = version;
    QUICLY_PROBE(VERSION_SWITCH, conn, probe_now(), version);

    /* reschedule all the packets that have been sent for immediate resend */
    return discard_sentmap_by_epoch(conn, ~0u);
}

static int handle_version_negotiation_packet(quicly_conn_t *conn, quicly_decoded_packet_t *packet)
{
#define CAN_SELECT(v) ((v) != conn->super.version && (v) == QUICLY_PROTOCOL_VERSION)

    const uint8_t *src = packet->octets.base + packet->encrypted_off, *end = packet->octets.base + packet->octets.len;

    if (src == end || (end - src) % 4 != 0)
        return QUICLY_TRANSPORT_ERROR_PROTOCOL_VIOLATION;
    while (src != end) {
        uint32_t supported_version = quicly_decode32(&src);
        if (CAN_SELECT(supported_version))
            return negotiate_using_version(conn, supported_version);
    }
    return QUICLY_ERROR_NO_COMPATIBLE_VERSION;

#undef CAN_SELECT
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

    if (conn->super.peer.stateless_reset.token == NULL)
        return 0;
    if (decoded->octets.len < QUICLY_STATELESS_RESET_PACKET_MIN_LEN)
        return 0;
    if (memcmp(decoded->octets.base + decoded->octets.len - QUICLY_STATELESS_RESET_TOKEN_LEN,
               conn->super.peer.stateless_reset.token, QUICLY_STATELESS_RESET_TOKEN_LEN) != 0)
        return 0;

    return 1;
}

int quicly_is_destination(quicly_conn_t *conn, struct sockaddr *dest_addr, struct sockaddr *src_addr,
                          quicly_decoded_packet_t *decoded)
{
    if (QUICLY_PACKET_IS_LONG_HEADER(decoded->octets.base[0])) {
        /* long header: validate address, then consult the CID */
        if (compare_socket_address(&conn->super.peer.address.sa, src_addr) != 0)
            return 0;
        if (conn->super.host.address.sa.sa_family != AF_UNSPEC &&
            compare_socket_address(&conn->super.host.address.sa, dest_addr) != 0)
            return 0;
        /* server may see the CID generated by the client for Initial and 0-RTT packets */
        if (!quicly_is_client(conn) && decoded->cid.dest.might_be_client_generated) {
            if (quicly_cid_is_equal(&conn->super.host.offered_cid, decoded->cid.dest.encrypted))
                goto Found;
        }
    }

    if (conn->super.ctx->cid_encryptor != NULL) {
        if (conn->super.master_id.master_id == decoded->cid.dest.plaintext.master_id &&
            conn->super.master_id.thread_id == decoded->cid.dest.plaintext.thread_id &&
            conn->super.master_id.node_id == decoded->cid.dest.plaintext.node_id)
            goto Found;
        if (is_stateless_reset(conn, decoded))
            goto Found_StatelessReset;
    } else {
        if (compare_socket_address(&conn->super.peer.address.sa, src_addr) == 0)
            goto Found;
        if (conn->super.host.address.sa.sa_family != AF_UNSPEC &&
            compare_socket_address(&conn->super.host.address.sa, dest_addr) != 0)
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

static int handle_close(quicly_conn_t *conn, int err, uint64_t frame_type, ptls_iovec_t reason_phrase)
{
    int ret;

    if (conn->super.state >= QUICLY_STATE_CLOSING)
        return 0;

    /* switch to closing state, notify the app (at this moment the streams are accessible), then destroy the streams */
    if ((ret = enter_close(conn, 0, err != QUICLY_ERROR_RECEIVED_STATELESS_RESET)) != 0)
        return ret;
    if (conn->super.ctx->closed_by_peer != NULL)
        conn->super.ctx->closed_by_peer->cb(conn->super.ctx->closed_by_peer, conn, err, frame_type,
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

    QUICLY_PROBE(TRANSPORT_CLOSE_RECEIVE, conn, probe_now(), frame.error_code, frame.frame_type,
                 QUICLY_PROBE_ESCAPE_UNSAFE_STRING(frame.reason_phrase.base, frame.reason_phrase.len));
    return handle_close(conn, QUICLY_ERROR_FROM_TRANSPORT_ERROR_CODE(frame.error_code), frame.frame_type, frame.reason_phrase);
}

static int handle_application_close_frame(quicly_conn_t *conn, struct st_quicly_handle_payload_state_t *state)
{
    quicly_application_close_frame_t frame;
    int ret;

    if ((ret = quicly_decode_application_close_frame(&state->src, state->end, &frame)) != 0)
        return ret;

    QUICLY_PROBE(APPLICATION_CLOSE_RECEIVE, conn, probe_now(), frame.error_code,
                 QUICLY_PROBE_ESCAPE_UNSAFE_STRING(frame.reason_phrase.base, frame.reason_phrase.len));
    return handle_close(conn, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(frame.error_code), UINT64_MAX, frame.reason_phrase);
}

static int handle_padding_frame(quicly_conn_t *conn, struct st_quicly_handle_payload_state_t *state)
{
    return 0;
}

static int handle_ping_frame(quicly_conn_t *conn, struct st_quicly_handle_payload_state_t *state)
{
    return 0;
}

static int handle_new_connection_id_frame(quicly_conn_t *conn, struct st_quicly_handle_payload_state_t *state)
{
    quicly_new_connection_id_frame_t frame;
    return quicly_decode_new_connection_id_frame(&state->src, state->end, &frame);
}

static int handle_retire_connection_id_frame(quicly_conn_t *conn, struct st_quicly_handle_payload_state_t *state)
{
    return QUICLY_TRANSPORT_ERROR_PROTOCOL_VIOLATION;
}

static int handle_handshake_done_frame(quicly_conn_t *conn, struct st_quicly_handle_payload_state_t *state)
{
    int ret;

    QUICLY_PROBE(HANDSHAKE_DONE_RECEIVE, conn, probe_now());

    if (!quicly_is_client(conn))
        return QUICLY_TRANSPORT_ERROR_PROTOCOL_VIOLATION;

    assert(conn->initial == NULL);
    if (conn->handshake == NULL)
        return 0;

    conn->super.peer.address_validation.send_probe = 0;
    if ((ret = discard_handshake_context(conn, QUICLY_EPOCH_HANDSHAKE)) != 0)
        return ret;
    update_loss_alarm(conn);
    return 0;
}

static int handle_payload(quicly_conn_t *conn, size_t epoch, const uint8_t *_src, size_t _len, uint64_t *offending_frame_type,
                          int *is_ack_only)
{
    /* clang-format off */

    /* `frame_handlers` is an array of frame handlers and the properties of the frames, indexed by the ID of the frame. */
    static const struct {
        int (*cb)(quicly_conn_t *, struct st_quicly_handle_payload_state_t *); /* callback function that handles the frame */
        uint8_t permitted_epochs;  /* the epochs the frame can appear, calculated as bitwise-or of `1 << epoch` */
        uint8_t ack_eliciting;     /* boolean indicating if the frame is ack-eliciting */
    } frame_handlers[] = {
#define FRAME(n, i, z, h, o, ae)                                                                                                   \
    {                                                                                                                              \
        handle_##n##_frame,                                                                                                        \
        (i << QUICLY_EPOCH_INITIAL) | (z << QUICLY_EPOCH_0RTT) | (h << QUICLY_EPOCH_HANDSHAKE) | (o << QUICLY_EPOCH_1RTT),         \
        ae                                                                                                                         \
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
        FRAME( max_streams          ,  0 ,  1 ,  0 ,  1 ,             1 ),
        FRAME( max_streams          ,  0 ,  1 ,  0 ,  1 ,             1 ),
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
    /* clang-format on */

    struct st_quicly_handle_payload_state_t state = {_src, _src + _len, epoch};
    size_t num_frames = 0, num_frames_ack_eliciting = 0;
    int ret;

    do {
        state.frame_type = *state.src++;
        if (state.frame_type >= sizeof(frame_handlers) / sizeof(frame_handlers[0])) {
            ret = QUICLY_TRANSPORT_ERROR_FRAME_ENCODING;
            break;
        }
        if ((frame_handlers[state.frame_type].permitted_epochs & (1 << epoch)) == 0) {
            ret = QUICLY_TRANSPORT_ERROR_PROTOCOL_VIOLATION;
            break;
        }
        num_frames += 1;
        num_frames_ack_eliciting += frame_handlers[state.frame_type].ack_eliciting;
        if ((ret = (*frame_handlers[state.frame_type].cb)(conn, &state)) != 0)
            break;
    } while (state.src != state.end);

    *is_ack_only = num_frames_ack_eliciting == 0;
    if (ret != 0)
        *offending_frame_type = state.frame_type;
    return ret;
}

static int handle_stateless_reset(quicly_conn_t *conn)
{
    QUICLY_PROBE(STATELESS_RESET_RECEIVE, conn, probe_now());
    return handle_close(conn, QUICLY_ERROR_RECEIVED_STATELESS_RESET, UINT64_MAX, ptls_iovec_init("", 0));
}

int quicly_accept(quicly_conn_t **conn, quicly_context_t *ctx, struct sockaddr *dest_addr, struct sockaddr *src_addr,
                  quicly_decoded_packet_t *packet, quicly_address_token_plaintext_t *address_token,
                  const quicly_cid_plaintext_t *new_cid, ptls_handshake_properties_t *handshake_properties)
{
    struct st_quicly_cipher_context_t ingress_cipher = {NULL}, egress_cipher = {NULL};
    ptls_iovec_t payload;
    uint64_t next_expected_pn, pn, offending_frame_type = QUICLY_FRAME_TYPE_PADDING;
    int is_ack_only, ret;

    *conn = NULL;

    update_now(ctx);

    /* process initials only */
    if ((packet->octets.base[0] & QUICLY_PACKET_TYPE_BITMASK) != QUICLY_PACKET_TYPE_INITIAL) {
        ret = QUICLY_ERROR_PACKET_IGNORED;
        goto Exit;
    }
    if (packet->version != QUICLY_PROTOCOL_VERSION) {
        ret = QUICLY_ERROR_PACKET_IGNORED;
        goto Exit;
    }
    if (packet->cid.dest.encrypted.len < 8) {
        ret = QUICLY_TRANSPORT_ERROR_PROTOCOL_VIOLATION;
        goto Exit;
    }
    if ((ret = setup_initial_encryption(get_aes128gcmsha256(ctx), &ingress_cipher, &egress_cipher, packet->cid.dest.encrypted, 0,
                                        NULL)) != 0)
        goto Exit;
    next_expected_pn = 0; /* is this correct? do we need to take care of underflow? */
    if ((ret = decrypt_packet(ingress_cipher.header_protection, aead_decrypt_fixed_key, ingress_cipher.aead, &next_expected_pn,
                              packet, &pn, &payload)) != 0)
        goto Exit;

    /* create connection */
    if ((*conn = create_connection(ctx, NULL, src_addr, dest_addr, new_cid, handshake_properties)) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }
    (*conn)->super.state = QUICLY_STATE_CONNECTED;
    set_cid(&(*conn)->super.peer.cid, packet->cid.src);
    set_cid(&(*conn)->super.host.offered_cid, packet->cid.dest.encrypted);
    if (address_token != NULL) {
        (*conn)->super.peer.address_validation.validated = 1;
        if (address_token->is_retry)
            set_cid(&(*conn)->retry_odcid, ptls_iovec_init(address_token->retry.odcid.cid, address_token->retry.odcid.len));
    }
    if ((ret = setup_handshake_space_and_flow(*conn, QUICLY_EPOCH_INITIAL)) != 0)
        goto Exit;
    (*conn)->initial->super.next_expected_packet_number = next_expected_pn;
    (*conn)->initial->cipher.ingress = ingress_cipher;
    ingress_cipher = (struct st_quicly_cipher_context_t){NULL};
    (*conn)->initial->cipher.egress = egress_cipher;
    egress_cipher = (struct st_quicly_cipher_context_t){NULL};
    (*conn)->crypto.handshake_properties.collected_extensions = server_collected_extensions;

    QUICLY_PROBE(ACCEPT, *conn, probe_now(), QUICLY_PROBE_HEXDUMP(packet->cid.dest.encrypted.base, packet->cid.dest.encrypted.len),
                 address_token);
    QUICLY_PROBE(CRYPTO_DECRYPT, *conn, pn, payload.base, payload.len);
    QUICLY_PROBE(QUICTRACE_RECV, *conn, probe_now(), pn);

    /* handle the input; we ignore is_ack_only, we consult if there's any output from TLS in response to CH anyways */
    (*conn)->super.stats.num_packets.received += 1;
    (*conn)->super.stats.num_bytes.received += packet->octets.len;
    if ((ret = handle_payload(*conn, QUICLY_EPOCH_INITIAL, payload.base, payload.len, &offending_frame_type, &is_ack_only)) != 0)
        goto Exit;
    if ((ret = record_receipt(*conn, &(*conn)->initial->super, pn, 0, QUICLY_EPOCH_INITIAL)) != 0)
        goto Exit;

Exit:
    if (*conn != NULL && ret != 0) {
        initiate_close(*conn, ret, offending_frame_type, "");
        ret = 0;
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

    update_now(conn->super.ctx);

    QUICLY_PROBE(RECEIVE, conn, probe_now(), QUICLY_PROBE_HEXDUMP(packet->cid.dest.encrypted.base, packet->cid.dest.encrypted.len),
                 packet->octets.base, packet->octets.len);

    if (is_stateless_reset(conn, packet)) {
        ret = handle_stateless_reset(conn);
        goto Exit;
    }

    /* FIXME check peer address */

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
            if (packet->version == 0)
                return handle_version_negotiation_packet(conn, packet);
        }
        switch (packet->octets.base[0] & QUICLY_PACKET_TYPE_BITMASK) {
        case QUICLY_PACKET_TYPE_RETRY: {
            assert(packet->encrypted_off + PTLS_AESGCM_TAG_SIZE == packet->octets.len);
            /* check the packet */
            if (quicly_cid_is_equal(&conn->super.peer.cid, packet->cid.src)) {
                ret = QUICLY_ERROR_PACKET_IGNORED;
                goto Exit;
            }
            /* do not accept a second Retry */
            if (conn->retry_odcid.len != 0) {
                ret = QUICLY_ERROR_PACKET_IGNORED;
                goto Exit;
            }
            { /* validate the AEAD tag */
                size_t pseudo_packet_len = 1 + conn->super.peer.cid.len + packet->encrypted_off;
                uint8_t pseudo_packet[pseudo_packet_len];
                pseudo_packet[0] = (uint8_t)conn->super.peer.cid.len;
                memcpy(pseudo_packet + 1, conn->super.peer.cid.cid, conn->super.peer.cid.len);
                memcpy(pseudo_packet + 1 + conn->super.peer.cid.len, packet->octets.base, packet->encrypted_off);
                ptls_aead_context_t *aead = create_retry_aead(conn->super.ctx, 0);
                int aead_ok = ptls_aead_decrypt(aead, packet->octets.base + packet->encrypted_off,
                                                packet->octets.base + packet->encrypted_off, PTLS_AESGCM_TAG_SIZE, 0, pseudo_packet,
                                                pseudo_packet_len) == 0;
                ptls_aead_free(aead);
                if (!aead_ok) {
                    ret = QUICLY_ERROR_PACKET_IGNORED;
                    goto Exit;
                }
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
            conn->retry_odcid = conn->super.peer.cid;
            /* update DCID */
            set_cid(&conn->super.peer.cid, packet->cid.src);
            /* replace initial keys */
            dispose_cipher(&conn->initial->cipher.ingress);
            dispose_cipher(&conn->initial->cipher.egress);
            if ((ret = setup_initial_encryption(get_aes128gcmsha256(conn->super.ctx), &conn->initial->cipher.ingress,
                                                &conn->initial->cipher.egress,
                                                ptls_iovec_init(conn->super.peer.cid.cid, conn->super.peer.cid.len), 1, NULL)) != 0)
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
            /* update cid if this is the first Initial packet that's being received */
            if (conn->super.state == QUICLY_STATE_FIRSTFLIGHT) {
                assert(quicly_is_client(conn));
                memcpy(conn->super.peer.cid.cid, packet->cid.src.base, packet->cid.src.len);
                conn->super.peer.cid.len = packet->cid.src.len;
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
        QUICLY_PROBE(CRYPTO_DECRYPT, conn, pn, NULL, 0);
        goto Exit;
    }

    QUICLY_PROBE(CRYPTO_DECRYPT, conn, pn, payload.base, payload.len);
    QUICLY_PROBE(QUICTRACE_RECV, conn, probe_now(), pn);

    /* update states */
    if (conn->super.state == QUICLY_STATE_FIRSTFLIGHT)
        conn->super.state = QUICLY_STATE_CONNECTED;
    conn->super.stats.num_packets.received += 1;
    conn->super.stats.num_bytes.received += packet->octets.len;

    /* state updates, that are triggered by the receipt of a packet */
    if (epoch == QUICLY_EPOCH_HANDSHAKE && conn->initial != NULL) {
        /* Discard Initial space before processing the payload of the Handshake packet to avoid the chance of an ACK frame included
         * in the Handshake packet setting a loss timer for the Initial packet. */
        if ((ret = discard_handshake_context(conn, QUICLY_EPOCH_INITIAL)) != 0)
            goto Exit;
        update_loss_alarm(conn);
        conn->super.peer.address_validation.validated = 1;
    }

    /* handle the payload */
    if ((ret = handle_payload(conn, epoch, payload.base, payload.len, &offending_frame_type, &is_ack_only)) != 0)
        goto Exit;
    if (*space != NULL && conn->super.state < QUICLY_STATE_CLOSING) {
        if ((ret = record_receipt(conn, *space, pn, is_ack_only, epoch)) != 0)
            goto Exit;
    }

    /* state updates post payload processing */
    switch (epoch) {
    case QUICLY_EPOCH_INITIAL:
        assert(conn->initial != NULL);
        if (quicly_is_client(conn) && conn->handshake != NULL && conn->handshake->cipher.egress.aead != NULL) {
            if ((ret = discard_handshake_context(conn, QUICLY_EPOCH_INITIAL)) != 0)
                goto Exit;
            update_loss_alarm(conn);
        }
        break;
    case QUICLY_EPOCH_HANDSHAKE:
        if (quicly_is_client(conn)) {
            /* Running as a client.
             * Respect "disable_migration" TP sent by the peer at the end of the TLS handshake. */
            if (conn->super.host.address.sa.sa_family == AF_UNSPEC && dest_addr != NULL && dest_addr->sa_family != AF_UNSPEC &&
                ptls_handshake_is_complete(conn->crypto.tls) && conn->super.peer.transport_params.disable_active_migration)
                set_address(&conn->super.host.address, dest_addr);
        } else {
            /* Running as a server.
             * If handshake was just completed, drop handshake context, schedule the first emission of HANDSHAKE_DONE frame. */
            if (ptls_handshake_is_complete(conn->crypto.tls)) {
                if ((ret = discard_handshake_context(conn, QUICLY_EPOCH_HANDSHAKE)) != 0)
                    goto Exit;
                assert(conn->handshake == NULL);
                conn->pending.flows |= QUICLY_PENDING_FLOW_HANDSHAKE_DONE_BIT;
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
        if (conn->egress.loss.alarm_at < now)
            conn->egress.loss.alarm_at = now;
        assert_consistency(conn, 0);
        break;
    case QUICLY_ERROR_PACKET_IGNORED:
        break;
    default: /* close connection */
        initiate_close(conn, ret, offending_frame_type, "");
        ret = 0;
        break;
    }
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
        group = &conn->super.host.uni;
        max_stream_count = &conn->egress.max_streams.uni.count;
        max_stream_data_local = 0;
        max_stream_data_remote = conn->super.peer.transport_params.max_stream_data.uni;
    } else {
        group = &conn->super.host.bidi;
        max_stream_count = &conn->egress.max_streams.bidi.count;
        max_stream_data_local = (uint32_t)conn->super.ctx->transport_params.max_stream_data.bidi_local;
        max_stream_data_remote = conn->super.peer.transport_params.max_stream_data.bidi_remote;
    }

    /* open */
    if ((stream = open_stream(conn, group->next_stream_id, max_stream_data_local, max_stream_data_remote)) == NULL)
        return PTLS_ERROR_NO_MEMORY;
    ++group->num_streams;
    group->next_stream_id += 4;

    /* adjust blocked */
    if (stream->stream_id / 4 >= *max_stream_count) {
        stream->streams_blocked = 1;
        quicly_linklist_insert((uni ? &conn->pending.streams.blocked.uni : &conn->pending.streams.blocked.bidi)->prev,
                               &stream->_send_aux.pending_link.control);
    }

    /* application-layer initialization */
    if ((ret = conn->super.ctx->stream_open->cb(conn->super.ctx->stream_open, stream)) != 0)
        return ret;

    *_stream = stream;
    return 0;
}

void quicly_reset_stream(quicly_stream_t *stream, int err)
{
    assert(quicly_stream_has_send_side(quicly_is_client(stream->conn), stream->stream_id));
    assert(QUICLY_ERROR_IS_QUIC_APPLICATION(err));
    assert(stream->_send_aux.rst.sender_state == QUICLY_SENDER_STATE_NONE);
    assert(!quicly_sendstate_transfer_complete(&stream->sendstate));

    /* dispose sendbuf state */
    quicly_sendstate_reset(&stream->sendstate);

    /* setup RST_STREAM */
    stream->_send_aux.rst.sender_state = QUICLY_SENDER_STATE_SEND;
    stream->_send_aux.rst.error_code = QUICLY_ERROR_GET_ERROR_CODE(err);

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
        if (('0' <= *src && *src <= 0x7e) && !(*src == '"' || *src == '\'' || *src == '\\')) {
            *dst++ = *src;
        } else {
            *dst++ = '\\';
            *dst++ = 'x';
            quicly_byte_to_hex(dst, (uint8_t)*src);
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

    /* IV */
    if ((ret = ptls_buffer_reserve(buf, aead->algo->iv_size)) != 0)
        goto Exit;
    random_bytes(buf->base + buf->off, aead->algo->iv_size);
    buf->off += aead->algo->iv_size;

    size_t enc_start = buf->off;

    /* data */
    ptls_buffer_push64(buf, (!!plaintext->is_retry) | ((uint64_t)plaintext->issued_at << 1));
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
    if (plaintext->is_retry) {
        ptls_buffer_push_block(buf, 1, { ptls_buffer_pushv(buf, plaintext->retry.odcid.cid, plaintext->retry.odcid.len); });
        ptls_buffer_push64(buf, plaintext->retry.cidpair_hash);
    } else {
        ptls_buffer_push_block(buf, 1, { ptls_buffer_pushv(buf, plaintext->resumption.bytes, plaintext->resumption.len); });
    }
    ptls_buffer_push_block(buf, 1, { ptls_buffer_pushv(buf, plaintext->appdata.bytes, plaintext->appdata.len); });

    /* encrypt, abusing the internal API to supply full IV */
    if ((ret = ptls_buffer_reserve(buf, aead->algo->tag_size)) != 0)
        goto Exit;
    aead->do_encrypt_init(aead, buf->base + enc_start - aead->algo->iv_size, buf->base + start_off, enc_start - start_off);
    ptls_aead_encrypt_update(aead, buf->base + enc_start, buf->base + enc_start, buf->off - enc_start);
    ptls_aead_encrypt_final(aead, buf->base + buf->off);
    buf->off += aead->algo->tag_size;

Exit:
    return ret;
}

int quicly_decrypt_address_token(ptls_aead_context_t *aead, quicly_address_token_plaintext_t *plaintext, const void *token,
                                 size_t len, size_t prefix_len)
{
    uint8_t ptbuf[QUICLY_MAX_PACKET_SIZE];
    size_t ptlen;

    assert(len < QUICLY_MAX_PACKET_SIZE);

    /* decrypt */
    if (len - prefix_len < aead->algo->iv_size + aead->algo->tag_size)
        return PTLS_ALERT_DECODE_ERROR;
    if ((ptlen = aead->do_decrypt(aead, ptbuf, token + prefix_len + aead->algo->iv_size, len - (prefix_len + aead->algo->iv_size),
                                  token + prefix_len, token, prefix_len + aead->algo->iv_size)) == SIZE_MAX)
        return PTLS_ALERT_DECODE_ERROR;

    /* parse */
    const uint8_t *src = ptbuf, *end = src + ptlen;
    int ret;
    if ((ret = ptls_decode64(&plaintext->issued_at, &src, end)) != 0)
        goto Exit;
    plaintext->is_retry = plaintext->issued_at & 1;
    plaintext->issued_at >>= 1;
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
                return PTLS_ALERT_DECODE_ERROR;
            }
            src = end;
        });
        uint16_t port;
        if ((ret = ptls_decode16(&port, &src, end)) != 0)
            goto Exit;
        *portaddr = htons(port);
    }
    if (plaintext->is_retry) {
        ptls_decode_open_block(src, end, 1, {
            if ((plaintext->retry.odcid.len = end - src) >= sizeof(plaintext->retry.odcid.cid)) {
                ret = PTLS_ALERT_DECODE_ERROR;
                goto Exit;
            }
            memcpy(plaintext->retry.odcid.cid, src, plaintext->retry.odcid.len);
            src = end;
        });
        if ((ret = ptls_decode64(&plaintext->retry.cidpair_hash, &src, end)) != 0)
            goto Exit;
    } else {
        ptls_decode_open_block(src, end, 1, {
            QUICLY_BUILD_ASSERT(sizeof(plaintext->resumption.bytes) >= 256);
            plaintext->resumption.len = end - src;
            memcpy(plaintext->resumption.bytes, src, plaintext->resumption.len);
            src = end;
        });
    }
    ptls_decode_block(src, end, 1, {
        QUICLY_BUILD_ASSERT(sizeof(plaintext->appdata.bytes) >= 256);
        plaintext->appdata.len = end - src;
        memcpy(plaintext->appdata.bytes, src, plaintext->appdata.len);
        src = end;
    });
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
