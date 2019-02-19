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
#include "cc.h"
#include "quicly.h"
#include "quicly/sentmap.h"
#include "quicly/frame.h"
#include "quicly/streambuf.h"

#define QUICLY_QUIC_BIT 0x40
#define QUICLY_LONG_HEADER_RESERVED_BITS 0xc
#define QUICLY_SHORT_HEADER_RESERVED_BITS 0x18
#define QUICLY_KEY_PHASE_BIT 0x4

#define QUICLY_PACKET_TYPE_INITIAL (QUICLY_LONG_HEADER_BIT | QUICLY_QUIC_BIT | 0)
#define QUICLY_PACKET_TYPE_0RTT (QUICLY_LONG_HEADER_BIT | QUICLY_QUIC_BIT | 0x10)
#define QUICLY_PACKET_TYPE_HANDSHAKE (QUICLY_LONG_HEADER_BIT | QUICLY_QUIC_BIT | 0x20)
#define QUICLY_PACKET_TYPE_RETRY (QUICLY_LONG_HEADER_BIT | QUICLY_QUIC_BIT | 0x30)
#define QUICLY_PACKET_TYPE_BITMASK 0xf0

#define QUICLY_MAX_PN_SIZE 4  /* maximum defined by the RFC used for calculating header protection sampling offset */
#define QUICLY_SEND_PN_SIZE 2 /* size of PN used for sending */

#define QUICLY_TLS_EXTENSION_TYPE_TRANSPORT_PARAMETERS 0xffa5
#define QUICLY_TRANSPORT_PARAMETER_ID_ORIGINAL_CONNECTION_ID 0
#define QUICLY_TRANSPORT_PARAMETER_ID_IDLE_TIMEOUT 1
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
#define QUICLY_TRANSPORT_PARAMETER_ID_DISABLE_MIGRATION 12
#define QUICLY_TRANSPORT_PARAMETER_ID_PREFERRED_ADDRESS 13

#define QUICLY_ACK_DELAY_EXPONENT 10

#define QUICLY_EPOCH_INITIAL 0
#define QUICLY_EPOCH_0RTT 1
#define QUICLY_EPOCH_HANDSHAKE 2
#define QUICLY_EPOCH_1RTT 3

#define QUICLY_MAX_TOKEN_LEN 512 /* maximum length of token that we would accept */

/**
 * do not try to send frames that require ACK if the send window is below this value
 */
#define MIN_SEND_WINDOW 64

#define AEAD_BASE_LABEL "tls13 quic "

KHASH_MAP_INIT_INT64(quicly_stream_t, quicly_stream_t *)

#define INT_EVENT_ATTR(label, value) _int_event_attr(QUICLY_EVENT_ATTRIBUTE_##label, value)
#define VEC_EVENT_ATTR(label, value) _vec_event_attr(QUICLY_EVENT_ATTRIBUTE_##label, value)
#define LOG_IS_REQUIRED(ctx, type) (((ctx)->event_log.mask & ((uint64_t)1 << (type))) != 0)
#define LOG_EVENT(ctx, type, ...)                                                                                                  \
    do {                                                                                                                           \
        quicly_context_t *_ctx = (ctx);                                                                                            \
        quicly_event_type_t _type = (type);                                                                                        \
        if (LOG_IS_REQUIRED(_ctx, _type)) {                                                                                        \
            quicly_event_attribute_t attributes[] = {INT_EVENT_ATTR(TIME, now), __VA_ARGS__};                                      \
            _ctx->event_log.cb->cb(_ctx->event_log.cb, _type, attributes, sizeof(attributes) / sizeof(attributes[0]));             \
        }                                                                                                                          \
    } while (0)

#define LOG_CONNECTION_EVENT(conn, type, ...)                                                                                      \
    do {                                                                                                                           \
        quicly_conn_t *_conn = (conn);                                                                                             \
        LOG_EVENT(_conn->super.ctx, (type), INT_EVENT_ATTR(CONNECTION, quicly_get_master_id(_conn)->master_id), __VA_ARGS__);      \
    } while (0)
#define LOG_STREAM_EVENT(conn, stream_id, type, ...)                                                                               \
    LOG_CONNECTION_EVENT((conn), (type), INT_EVENT_ATTR(STREAM_ID, stream_id), __VA_ARGS__)

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
            ptls_aead_context_t *aead[2];
        } ingress;
        struct st_quicly_cipher_context_t egress;
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
         * next or the currently encoding packet number (TODO move to pnspace)
         */
        uint64_t packet_number;
        /**
         * valid if state is CLOSING
         */
        struct {
            uint16_t error_code;
            uint64_t frame_type; /* UINT64_MAX if application close */
            const char *reason_phrase;
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
        int64_t last_retransmittable_sent_at;
        /**
         *
         */
        int64_t send_ack_at;
        /**
         *
         */
        struct {
            struct cc_var ccv;
            uint64_t end_of_recovery;
            unsigned in_first_rto : 1;
        } cc;
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
        /**
         * bit vector indicating if there's any pending handshake data at epoch 0,1,2
         */
        uint8_t pending_flows;
        /**
         * whether if the timer to discard the handshake contexts has been activated
         */
        uint8_t handshake_scheduled_for_discard;
    } crypto;
    /**
     *
     */
    struct {
        /**
         * contains list of blocked streams (sorted in ascending order of stream_ids)
         */
        struct {
            quicly_linklist_t uni;
            quicly_linklist_t bidi;
        } streams_blocked;
        quicly_linklist_t control;
        quicly_linklist_t stream_fin_only;
        quicly_linklist_t stream_with_payload;
    } pending_link;
    /**
     * retry token
     */
    ptls_iovec_t token;
    /**
     * len=0 if not used
     */
    quicly_cid_t retry_odcid;
};

static int crypto_stream_receive(quicly_stream_t *stream, size_t off, const void *src, size_t len);

static const quicly_stream_callbacks_t crypto_stream_callbacks = {quicly_streambuf_destroy, quicly_streambuf_egress_shift,
                                                                  quicly_streambuf_egress_emit, NULL, crypto_stream_receive};

static int update_traffic_key_cb(ptls_update_traffic_key_t *self, ptls_t *tls, int is_enc, size_t epoch, const void *secret);
static int discard_sentmap_by_epoch(quicly_conn_t *conn, unsigned ack_epochs);

const quicly_context_t quicly_default_context = {
    NULL,                      /* tls */
    1280,                      /* max_packet_size */
    &quicly_loss_default_conf, /* loss */
    {
        {1 * 1024 * 1024, 1 * 1024 * 1024, 1 * 1024 * 1024}, /* max_stream_data */
        16 * 1024 * 1024,                                    /* max_data */
        600,                                                 /* idle_timeout */
        100,                                                 /* max_concurrent_streams_bidi */
        0                                                    /* max_concurrent_streams_uni */
    },
    0, /* enforce_version_negotiation */
    0, /* is_clustered */
    &quicly_default_packet_allocator,
    NULL,
    NULL, /* on_stream_open */
    NULL, /* on_conn_close */
    &quicly_default_now,
    {0, NULL}, /* event_log */
};

static const quicly_transport_parameters_t transport_params_before_handshake = {
    {0, 0, 0}, 0, 0, 0, 0, 3, QUICLY_DELAYED_ACK_TIMEOUT};

static __thread int64_t now;

static void update_now(quicly_context_t *ctx)
{
    static __thread int64_t base;

    now = ctx->now->cb(ctx->now);

    assert(cc_hz == 100);
    if (base == 0)
        base = now;
    int new_ticks = (int)((now - base) / 10);
    if (cc_ticks != new_ticks)
        cc_ticks = new_ticks;
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

static inline quicly_event_attribute_t _int_event_attr(quicly_event_attribute_type_t type, int64_t value)
{
    quicly_event_attribute_t t;

    assert(QUICLY_EVENT_ATTRIBUTE_TYPE_INT_MIN <= type && type < QUICLY_EVENT_ATTRIBUTE_TYPE_INT_MAX);
    t.type = type;
    t.value.i = value;
    return t;
}

static inline quicly_event_attribute_t _vec_event_attr(quicly_event_attribute_type_t type, ptls_iovec_t value)
{
    quicly_event_attribute_t t;

    assert(QUICLY_EVENT_ATTRIBUTE_TYPE_VEC_MIN <= type && type < QUICLY_EVENT_ATTRIBUTE_TYPE_VEC_MAX);
    t.type = type;
    t.value.v = value;
    return t;
}

static void dispose_cipher(struct st_quicly_cipher_context_t *ctx)
{
    ptls_aead_free(ctx->aead);
    ptls_cipher_free(ctx->header_protection);
}

static size_t decode_cid_length(uint8_t src)
{
    return src != 0 ? src + 3 : 0;
}

static uint8_t encode_cid_length(size_t len)
{
    return len != 0 ? (uint8_t)len - 3 : 0;
}

size_t quicly_decode_packet(quicly_context_t *ctx, quicly_decoded_packet_t *packet, const uint8_t *src, size_t len)
{
    const uint8_t *src_end = src + len;

    if (len < 2)
        goto Error;

    packet->octets = ptls_iovec_init(src, len);
    packet->datagram_size = len;
    packet->token = ptls_iovec_init(NULL, 0);
    ++src;

    if (QUICLY_PACKET_IS_LONG_HEADER(packet->octets.base[0])) {
        /* long header */
        uint64_t rest_length;
        if (src_end - src < 5)
            goto Error;
        packet->version = quicly_decode32(&src);
        packet->cid.dest.encrypted.len = decode_cid_length(*src >> 4);
        packet->cid.src.len = decode_cid_length(*src & 0xf);
        ++src;
        if (src_end - src < packet->cid.dest.encrypted.len + packet->cid.src.len)
            goto Error;
        packet->cid.dest.encrypted.base = (void *)src;
        src += packet->cid.dest.encrypted.len;
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
        packet->cid.src.base = (void *)src;
        src += packet->cid.src.len;
        if (!(packet->version == QUICLY_PROTOCOL_VERSION ||
              (packet->version & 0xffffff00) == 0xff000000 /* TODO remove this code that is used to test other draft versions */)) {
            /* version negotiation packet does not have the length field nor is ever coalesced */
            packet->encrypted_off = src - packet->octets.base;
        } else if ((packet->octets.base[0] & QUICLY_PACKET_TYPE_BITMASK) == QUICLY_PACKET_TYPE_RETRY) {
            /* retry */
            size_t odcid_len = decode_cid_length(packet->octets.base[0] & 0xf);
            packet->encrypted_off = src - packet->octets.base;
            if (src_end - src < odcid_len)
                goto Error;
            src += odcid_len;
            packet->token = ptls_iovec_init(src, src_end - src);
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
            if (src_end - src < QUICLY_MAX_CID_LEN)
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

uint64_t quicly_determine_packet_number(uint32_t bits, uint32_t mask, uint64_t next_expected)
{
    uint64_t actual = (next_expected & ~(uint64_t)mask) + bits;

    if (((bits - (uint32_t)next_expected) & mask) > (mask >> 1)) {
        if (actual >= (uint64_t)mask + 1)
            actual -= (uint64_t)mask + 1;
    }

    return actual;
}

static void assert_consistency(quicly_conn_t *conn, int run_timers)
{
    if (conn->egress.sentmap.bytes_in_flight != 0) {
        assert(conn->egress.loss.alarm_at != INT64_MAX);
    } else {
        assert(conn->egress.loss.loss_time == INT64_MAX);
    }
    if (run_timers)
        assert(now < conn->egress.loss.alarm_at);
}

static void init_max_streams(struct st_quicly_max_streams_t *m)
{
    m->count = 0;
    quicly_maxsender_init(&m->blocked_sender, -1);
}

static void update_max_streams(struct st_quicly_max_streams_t *m, uint64_t count)
{
    if (m->count < count) {
        m->count = count;
        if (m->blocked_sender.max_acked < count)
            m->blocked_sender.max_acked = count;
    }
}

int quicly_connection_is_ready(quicly_conn_t *conn)
{
    return conn->application != NULL;
}

static int set_peeraddr(quicly_conn_t *conn, struct sockaddr *addr, socklen_t addrlen)
{
    int ret;

    if (conn->super.peer.salen != addrlen) {
        struct sockaddr *newsa;
        if ((newsa = malloc(addrlen)) == NULL) {
            ret = PTLS_ERROR_NO_MEMORY;
            goto Exit;
        }
        free(conn->super.peer.sa);
        conn->super.peer.sa = newsa;
        conn->super.peer.salen = addrlen;
    }

    memcpy(conn->super.peer.sa, addr, addrlen);
    ret = 0;

Exit:
    return ret;
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
        quicly_linklist_insert(&stream->conn->pending_link.control, &stream->_send_aux.pending_link.control);
}

static void resched_stream_data(quicly_stream_t *stream)
{
    quicly_linklist_t *target = NULL;

    if (stream->stream_id < 0 && -3 <= stream->stream_id) {
        uint8_t mask = 1 << -(1 + stream->stream_id);
        if (stream->sendstate.pending.num_ranges != 0) {
            stream->conn->crypto.pending_flows |= mask;
        } else {
            stream->conn->crypto.pending_flows &= ~mask;
        }
        return;
    }

    /* do nothing if blocked */
    if (stream->streams_blocked)
        return;

    /* unlink so that we would round-robin the streams */
    if (quicly_linklist_is_linked(&stream->_send_aux.pending_link.stream))
        quicly_linklist_unlink(&stream->_send_aux.pending_link.stream);

    if (stream->sendstate.pending.num_ranges != 0) {
        if (!stream->sendstate.is_open && stream->sendstate.pending.ranges[0].start + 1 == stream->sendstate.size_committed) {
            /* fin is the only thing to be sent, and it can be sent if window size is zero */
            target = &stream->conn->pending_link.stream_fin_only;
        } else {
            /* check if we can send payload */
            if (stream->sendstate.pending.ranges[0].start < stream->_send_aux.max_stream_data)
                target = &stream->conn->pending_link.stream_with_payload;
        }
    }

    if (target != NULL)
        quicly_linklist_insert(target, &stream->_send_aux.pending_link.stream);
}

static int should_update_max_stream_data(quicly_stream_t *stream)
{
    if (stream->recvstate.eos != UINT64_MAX)
        return 0;
    return quicly_maxsender_should_update(&stream->_send_aux.max_stream_data_sender, stream->recvstate.data_off,
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
        if (should_update_max_stream_data(stream))
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

int crypto_stream_receive(quicly_stream_t *stream, size_t off, const void *src, size_t len)
{
    size_t in_epoch = -(1 + stream->stream_id), epoch_offsets[5] = {0};
    ptls_iovec_t input;
    ptls_buffer_t output;
    int ret;

    if ((ret = quicly_streambuf_ingress_receive(stream, off, src, len)) != 0)
        return ret;

    ptls_buffer_init(&output, "", 0);

    /* send handshake messages to picotls, and let it fill in the response */
    while ((input = quicly_streambuf_ingress_get(stream)).len != 0) {
        ret = ptls_handle_message(stream->conn->crypto.tls, &output, epoch_offsets, in_epoch, input.base, input.len,
                                  &stream->conn->crypto.handshake_properties);
        quicly_streambuf_ingress_shift(stream, input.len);
        LOG_CONNECTION_EVENT(stream->conn, QUICLY_EVENT_TYPE_CRYPTO_HANDSHAKE, INT_EVENT_ATTR(TLS_ERROR, ret));
        switch (ret) {
        case 0:
            break;
        case PTLS_ERROR_IN_PROGRESS:
            ret = 0;
            break;
        default:
            goto Exit;
        }
    }
    write_crypto_data(stream->conn, &output, epoch_offsets);

Exit:
    ptls_buffer_dispose(&output);
    return ret;
}

static void init_stream_properties(quicly_stream_t *stream, uint32_t initial_max_stream_data_local,
                                   uint64_t initial_max_stream_data_remote)
{
    int uni = quicly_stream_is_unidirectional(stream->stream_id),
        self_initiated = quicly_stream_is_client_initiated(stream->stream_id) == quicly_is_client(stream->conn);

    if (!uni || self_initiated) {
        quicly_sendstate_init(&stream->sendstate);
    } else {
        quicly_sendstate_init_closed(&stream->sendstate);
    }
    if (!uni || !self_initiated) {
        quicly_recvstate_init(&stream->recvstate);
    } else {
        quicly_recvstate_init_closed(&stream->recvstate);
    }
    stream->streams_blocked = 0;

    stream->_send_aux.max_stream_data = initial_max_stream_data_remote;
    stream->_send_aux.max_sent = 0;
    stream->_send_aux.stop_sending.sender_state = QUICLY_SENDER_STATE_NONE;
    stream->_send_aux.stop_sending.error_code = 0;
    stream->_send_aux.rst.sender_state = QUICLY_SENDER_STATE_NONE;
    stream->_send_aux.rst.error_code = 0;
    quicly_maxsender_init(&stream->_send_aux.max_stream_data_sender, initial_max_stream_data_local);
    quicly_linklist_init(&stream->_send_aux.pending_link.control);
    quicly_linklist_init(&stream->_send_aux.pending_link.stream);

    stream->_recv_aux.window = initial_max_stream_data_local;
}

static void dispose_stream_properties(quicly_stream_t *stream)
{
    quicly_sendstate_dispose(&stream->sendstate);
    quicly_recvstate_dispose(&stream->recvstate);
    quicly_maxsender_dispose(&stream->_send_aux.max_stream_data_sender);
    quicly_linklist_unlink(&stream->_send_aux.pending_link.control);
    quicly_linklist_unlink(&stream->_send_aux.pending_link.stream);
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

static void destroy_stream(quicly_stream_t *stream)
{
    quicly_conn_t *conn = stream->conn;

    if (stream->callbacks != NULL)
        stream->callbacks->on_destroy(stream);

    khiter_t iter = kh_get(quicly_stream_t, conn->streams, stream->stream_id);
    assert(iter != kh_end(conn->streams));
    kh_del(quicly_stream_t, conn->streams, iter);

    if (stream->stream_id < 0) {
        size_t epoch = -(1 + stream->stream_id);
        if (epoch <= 2)
            stream->conn->crypto.pending_flows &= ~(uint8_t)(1 << epoch);
    } else {
        struct st_quicly_conn_streamgroup_state_t *group = get_streamgroup_state(conn, stream->stream_id);
        --group->num_streams;
    }

    dispose_stream_properties(stream);
    free(stream);
}

static void destroy_all_streams(quicly_conn_t *conn)
{
    quicly_stream_t *stream;
    kh_foreach_value(conn->streams, stream, {
        /* TODO do we need to send reset signals to open streams? */
        destroy_stream(stream);
    });
}

quicly_stream_t *quicly_get_stream(quicly_conn_t *conn, quicly_stream_id_t stream_id)
{
    khiter_t iter = kh_get(quicly_stream_t, conn->streams, stream_id);
    if (iter != kh_end(conn->streams))
        return kh_val(conn->streams, iter);
    return NULL;
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

static void update_loss_alarm(quicly_conn_t *conn)
{
    quicly_loss_update_alarm(&conn->egress.loss, now, conn->egress.last_retransmittable_sent_at,
                             conn->egress.sentmap.bytes_in_flight != 0);
}

static int create_handshake_flow(quicly_conn_t *conn, size_t epoch)
{
    quicly_stream_t *stream;
    int ret;

    if ((stream = open_stream(conn, -(quicly_stream_id_t)(1 + epoch), 65536, 65536)) == NULL)
        return PTLS_ERROR_NO_MEMORY;
    if ((ret = quicly_streambuf_create(stream, sizeof(quicly_streambuf_t))) != 0) {
        destroy_stream(stream);
        return PTLS_ERROR_NO_MEMORY;
    }
    stream->callbacks = &crypto_stream_callbacks;

    return 0;
}

static void destroy_handshake_flow(quicly_conn_t *conn, size_t epoch)
{
    quicly_stream_t *stream = quicly_get_stream(conn, -(quicly_stream_id_t)(1 + epoch));
    if (stream != NULL)
        destroy_stream(stream);
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

static int record_receipt(quicly_conn_t *conn, struct st_quicly_pn_space_t *space, uint64_t pn, int is_ack_only, size_t epoch)
{
    int ret;

    if ((ret = quicly_ranges_add(&space->ack_queue, pn, pn + 1)) != 0)
        goto Exit;
    if (space->ack_queue.num_ranges >= QUICLY_ENCODE_ACK_MAX_BLOCKS) {
        assert(space->ack_queue.num_ranges == QUICLY_ENCODE_ACK_MAX_BLOCKS);
        quicly_ranges_shrink(&space->ack_queue, 0, 1);
    }
    if (space->ack_queue.ranges[space->ack_queue.num_ranges - 1].end == pn + 1) {
        /* FIXME implement deduplication at an earlier moment? */
        space->largest_pn_received_at = now;
    }
    /* TODO (jri): If not ack-only packet, then maintain count of such packets that are received.
     * Send ack immediately when this number exceeds the threshold.
     */
    if (!is_ack_only) {
        space->unacked_count++;
        /* Ack after QUICLY_NUM_PACKETS_BEFORE_ACK packets or after the delayed ack timeout */
        if (space->unacked_count >= QUICLY_NUM_PACKETS_BEFORE_ACK || epoch == QUICLY_EPOCH_INITIAL ||
            epoch == QUICLY_EPOCH_HANDSHAKE) {
            conn->egress.send_ack_at = now;
        } else if (conn->egress.send_ack_at == INT64_MAX) {
            /* FIXME use 1/4 minRTT */
            conn->egress.send_ack_at = now + QUICLY_DELAYED_ACK_TIMEOUT;
        }
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

static int setup_cipher(ptls_cipher_context_t **hp_ctx, ptls_aead_context_t **aead_ctx, ptls_aead_algorithm_t *aead,
                        ptls_hash_algorithm_t *hash, int is_enc, const void *secret)
{
    uint8_t hpkey[PTLS_MAX_SECRET_SIZE];
    int ret;

    *hp_ctx = NULL;
    *aead_ctx = NULL;

    if ((ret = ptls_hkdf_expand_label(hash, hpkey, aead->ctr_cipher->key_size, ptls_iovec_init(secret, hash->digest_size),
                                      "quic hp", ptls_iovec_init(NULL, 0), NULL)) != 0)
        goto Exit;
    if ((*hp_ctx = ptls_cipher_new(aead->ctr_cipher, is_enc, hpkey)) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }
    if ((*aead_ctx = ptls_aead_new(aead, hash, is_enc, secret, AEAD_BASE_LABEL)) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }
    if (QUICLY_DEBUG) {
        char *secret_hex = quicly_hexdump(secret, hash->digest_size, SIZE_MAX),
             *hpkey_hex = quicly_hexdump(hpkey, aead->ctr_cipher->key_size, SIZE_MAX);
        fprintf(stderr, "%s:\n  aead-secret: %s\n  hp-key: %s\n", __FUNCTION__, secret_hex, hpkey_hex);
        free(secret_hex);
        free(hpkey_hex);
    }

    ret = 0;
Exit:
    if (ret != 0) {
        if (*aead_ctx != NULL) {
            ptls_aead_free(*aead_ctx);
            *aead_ctx = NULL;
        }
        if (*hp_ctx != NULL) {
            ptls_cipher_free(*hp_ctx);
            *hp_ctx = NULL;
        }
    }
    ptls_clear_memory(hpkey, sizeof(hpkey));
    return ret;
}

static int setup_handshake_space_and_flow(quicly_conn_t *conn, size_t epoch)
{
    struct st_quicly_handshake_space_t **space = epoch == 0 ? &conn->initial : &conn->handshake;
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
        if ((*space)->cipher.egress.aead != NULL)
            dispose_cipher(&(*space)->cipher.egress);
        do_free_pn_space(&(*space)->super);
        *space = NULL;
    }
}

static int setup_application_space_and_flow(quicly_conn_t *conn, int setup_0rtt)
{
    if ((conn->application = (void *)alloc_pn_space(sizeof(struct st_quicly_application_space_t))) == NULL)
        return PTLS_ERROR_NO_MEMORY;
    if (setup_0rtt) {
        int ret;
        if ((ret = create_handshake_flow(conn, 1)) != 0)
            return ret;
    }
    return create_handshake_flow(conn, 3);
}

static int discard_initial_context(quicly_conn_t *conn)
{
    int ret;

    if ((ret = discard_sentmap_by_epoch(conn, 1u << QUICLY_EPOCH_INITIAL)) != 0)
        return ret;
    destroy_handshake_flow(conn, QUICLY_EPOCH_INITIAL);
    free_handshake_space(&conn->initial);

    return 0;
}

static int discard_handshake_context(quicly_conn_t *conn, const quicly_sent_packet_t *packet, quicly_sent_t *sent,
                                     quicly_sentmap_event_t event)
{
    switch (event) {
    case QUICLY_SENTMAP_EVENT_ACKED:
        return QUICLY_TRANSPORT_ERROR_PROTOCOL_VIOLATION;
    case QUICLY_SENTMAP_EVENT_LOST:
        break;
    case QUICLY_SENTMAP_EVENT_EXPIRED:
        /* discard Handshake */
        destroy_handshake_flow(conn, QUICLY_EPOCH_HANDSHAKE);
        free_handshake_space(&conn->handshake);
        /* discard 0-RTT receive context */
        if (!quicly_is_client(conn) && conn->application->cipher.ingress.header_protection.zero_rtt != NULL) {
            assert(conn->application->cipher.ingress.aead[0] != NULL);
            ptls_cipher_free(conn->application->cipher.ingress.header_protection.zero_rtt);
            conn->application->cipher.ingress.header_protection.zero_rtt = NULL;
            ptls_aead_free(conn->application->cipher.ingress.aead[0]);
            conn->application->cipher.ingress.aead[0] = NULL;
        }
        break;
    }
    return 0;
}

static void apply_peer_transport_params(quicly_conn_t *conn)
{
    conn->egress.max_data.permitted = conn->super.peer.transport_params.max_data;
    update_max_streams(&conn->egress.max_streams.uni, conn->super.peer.transport_params.max_streams_uni);
    update_max_streams(&conn->egress.max_streams.bidi, conn->super.peer.transport_params.max_streams_bidi);
}

void quicly_free(quicly_conn_t *conn)
{
    LOG_CONNECTION_EVENT(conn, QUICLY_EVENT_TYPE_FREE);

    destroy_all_streams(conn);

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
    cc_destroy(&conn->egress.cc.ccv);
    quicly_sentmap_dispose(&conn->egress.sentmap);

    kh_destroy(quicly_stream_t, conn->streams);

    assert(!quicly_linklist_is_linked(&conn->pending_link.streams_blocked.uni));
    assert(!quicly_linklist_is_linked(&conn->pending_link.streams_blocked.bidi));
    assert(!quicly_linklist_is_linked(&conn->pending_link.control));
    assert(!quicly_linklist_is_linked(&conn->pending_link.stream_fin_only));
    assert(!quicly_linklist_is_linked(&conn->pending_link.stream_with_payload));

    free_handshake_space(&conn->initial);
    free_handshake_space(&conn->handshake);
    free_application_space(&conn->application);

    free(conn->token.base);
    free(conn->super.peer.sa);
    free(conn);
}

static int setup_initial_key(struct st_quicly_cipher_context_t *ctx, ptls_cipher_suite_t *cs, const void *master_secret,
                             const char *label, int is_enc)
{
    uint8_t aead_secret[PTLS_MAX_DIGEST_SIZE];
    int ret;

    if ((ret = ptls_hkdf_expand_label(cs->hash, aead_secret, cs->hash->digest_size,
                                      ptls_iovec_init(master_secret, cs->hash->digest_size), label, ptls_iovec_init(NULL, 0),
                                      NULL)) != 0)
        goto Exit;
    if ((ret = setup_cipher(&ctx->header_protection, &ctx->aead, cs->aead, cs->hash, is_enc, aead_secret)) != 0)
        goto Exit;

Exit:
    ptls_clear_memory(aead_secret, sizeof(aead_secret));
    return ret;
}

static int setup_initial_encryption(struct st_quicly_cipher_context_t *ingress, struct st_quicly_cipher_context_t *egress,
                                    ptls_cipher_suite_t **cipher_suites, ptls_iovec_t cid, int is_client)
{
    static const uint8_t salt[] = {0xef, 0x4f, 0xb0, 0xab, 0xb4, 0x74, 0x70, 0xc4, 0x1b, 0xef,
                                   0xcf, 0x80, 0x31, 0x33, 0x4f, 0xae, 0x48, 0x5e, 0x09, 0xa0};
    static const char *labels[2] = {"client in", "server in"};
    ptls_cipher_suite_t **cs;
    uint8_t secret[PTLS_MAX_DIGEST_SIZE];
    int ret;

    /* find aes128gcm cipher */
    for (cs = cipher_suites;; ++cs) {
        assert(cs != NULL);
        if ((*cs)->id == PTLS_CIPHER_SUITE_AES_128_GCM_SHA256)
            break;
    }

    /* extract master secret */
    if ((ret = ptls_hkdf_extract((*cs)->hash, secret, ptls_iovec_init(salt, sizeof(salt)), cid)) != 0)
        goto Exit;

    /* create aead contexts */
    if ((ret = setup_initial_key(ingress, *cs, secret, labels[is_client], 0)) != 0)
        goto Exit;
    if ((ret = setup_initial_key(egress, *cs, secret, labels[!is_client], 1)) != 0)
        goto Exit;

Exit:
    ptls_clear_memory(secret, sizeof(secret));
    return ret;
}

static int apply_stream_frame(quicly_stream_t *stream, quicly_stream_frame_t *frame)
{
    int ret;

    LOG_STREAM_EVENT(stream->conn, stream->stream_id, QUICLY_EVENT_TYPE_STREAM_RECEIVE, INT_EVENT_ATTR(OFFSET, frame->offset),
                     INT_EVENT_ATTR(LENGTH, frame->data.len));

    if (quicly_recvstate_transfer_complete(&stream->recvstate))
        return 0;

    if (stream->stream_id >= 0) {
        /* flow control */
        uint64_t max_stream_data = frame->offset + frame->data.len;
        if ((int64_t)stream->_recv_aux.window < (int64_t)max_stream_data - (int64_t)stream->recvstate.data_off)
            return QUICLY_TRANSPORT_ERROR_FLOW_CONTROL;
        if (stream->recvstate.received.ranges[stream->recvstate.received.num_ranges - 1].end < max_stream_data) {
            uint64_t newly_received =
                max_stream_data - stream->recvstate.received.ranges[stream->recvstate.received.num_ranges - 1].end;
            if (stream->conn->ingress.max_data.bytes_consumed + newly_received > stream->conn->ingress.max_data.sender.max_sent)
                return QUICLY_TRANSPORT_ERROR_FLOW_CONTROL;
            stream->conn->ingress.max_data.bytes_consumed += newly_received;
            /* FIXME send MAX_DATA if necessary */
        }
    }

    /* update recvbuf */
    size_t apply_len = frame->data.len;
    if ((ret = quicly_recvstate_update(&stream->recvstate, frame->offset, &apply_len, frame->is_fin)) != 0)
        return ret;

    if (apply_len != 0 || quicly_recvstate_transfer_complete(&stream->recvstate)) {
        uint64_t buf_offset = frame->offset + frame->data.len - apply_len - stream->recvstate.data_off;
        if ((ret = stream->callbacks->on_receive(stream, (size_t)buf_offset, frame->data.base + frame->data.len - apply_len,
                                                 apply_len)) != 0)
            return ret;
    }

    if (should_update_max_stream_data(stream))
        sched_stream_control(stream);

    if (stream_is_destroyable(stream))
        destroy_stream(stream);

    return 0;
}

static int apply_handshake_flow(quicly_conn_t *conn, size_t epoch, quicly_stream_frame_t *frame)
{
    quicly_stream_t *stream = quicly_get_stream(conn, -(quicly_stream_id_t)(1 + epoch));

    return apply_stream_frame(stream, frame);
}

#define PUSH_TRANSPORT_PARAMETER(buf, id, block)                                                                                   \
    do {                                                                                                                           \
        ptls_buffer_push16((buf), (id));                                                                                           \
        ptls_buffer_push_block((buf), 2, block);                                                                                   \
    } while (0)

int quicly_encode_transport_parameter_list(ptls_buffer_t *buf, int is_client, const quicly_transport_parameters_t *params,
                                           const quicly_cid_t *odcid, const void *stateless_reset_token)
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
        if (params->idle_timeout != 0)
            PUSH_TRANSPORT_PARAMETER(buf, QUICLY_TRANSPORT_PARAMETER_ID_IDLE_TIMEOUT, { pushv(buf, params->idle_timeout); });
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
        if (params->max_streams_uni != 0) {
            PUSH_TRANSPORT_PARAMETER(buf, QUICLY_TRANSPORT_PARAMETER_ID_INITIAL_MAX_STREAMS_UNI,
                                     { pushv(buf, params->max_streams_uni); });
        }
        PUSH_TRANSPORT_PARAMETER(buf, QUICLY_TRANSPORT_PARAMETER_ID_ACK_DELAY_EXPONENT, { pushv(buf, QUICLY_ACK_DELAY_EXPONENT); });
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
    *params = (quicly_transport_parameters_t){{0}, 0, 0, 0, 0, 3, 25};
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
            found_id_bits |= ID_TO_BIT(id);
            ptls_decode_open_block(src, end, 2, {
                switch (id) {
                case QUICLY_TRANSPORT_PARAMETER_ID_ORIGINAL_CONNECTION_ID: {
                    size_t cidlen = end - src;
                    if (!(is_client && 4 <= cidlen && cidlen <= 18)) {
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
                case QUICLY_TRANSPORT_PARAMETER_ID_IDLE_TIMEOUT:
                    if ((ret = quicly_tls_decode_varint(&params->idle_timeout, &src, end)) != 0)
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
                    /* FIXME do we have a maximum? */
                    if (v > 255)
                        v = 255;
                    params->ack_delay_exponent = (uint8_t)v;
                } break;
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

static quicly_conn_t *create_connection(quicly_context_t *ctx, const char *server_name, struct sockaddr *sa, socklen_t salen,
                                        const quicly_cid_plaintext_t *new_cid, ptls_handshake_properties_t *handshake_properties)
{
    ptls_t *tls = NULL;
    struct {
        quicly_conn_t _;
        quicly_maxsender_t max_streams_bidi;
        quicly_maxsender_t max_streams_uni;
    } * conn;

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
        ctx->tls->random_bytes(conn->_.super.peer.cid.cid, 8);
        conn->_.super.peer.cid.len = 8;
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
    conn->_.super.peer.transport_params = transport_params_before_handshake;
    if (server_name != NULL && ctx->enforce_version_negotiation) {
        ctx->tls->random_bytes(&conn->_.super.version, sizeof(conn->_.super.version));
        conn->_.super.version = (conn->_.super.version & 0xf0f0f0f0) | 0x0a0a0a0a;
    } else {
        conn->_.super.version = QUICLY_PROTOCOL_VERSION;
    }
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
    quicly_loss_init(&conn->_.egress.loss, conn->_.super.ctx->loss,
                     conn->_.super.ctx->loss->default_initial_rtt /* FIXME remember initial_rtt in session ticket */,
                     &conn->_.super.peer.transport_params.max_ack_delay);
    init_max_streams(&conn->_.egress.max_streams.uni);
    init_max_streams(&conn->_.egress.max_streams.bidi);
    conn->_.egress.path_challenge.tail_ref = &conn->_.egress.path_challenge.head;
    conn->_.egress.send_ack_at = INT64_MAX;
    cc_init(&conn->_.egress.cc.ccv, &newreno_cc_algo, 1280 * 8, 1280);
    conn->_.egress.cc.ccv.ccvc.ccv.snd_scale = 14; /* FIXME */
    conn->_.egress.cc.end_of_recovery = UINT64_MAX;
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
    quicly_linklist_init(&conn->_.pending_link.streams_blocked.uni);
    quicly_linklist_init(&conn->_.pending_link.streams_blocked.bidi);
    quicly_linklist_init(&conn->_.pending_link.control);
    quicly_linklist_init(&conn->_.pending_link.stream_fin_only);
    quicly_linklist_init(&conn->_.pending_link.stream_with_payload);

    if (set_peeraddr(&conn->_, sa, salen) != 0) {
        quicly_free(&conn->_);
        return NULL;
    }

    *ptls_get_data_ptr(tls) = &conn->_;

    return &conn->_;
}

static int client_collected_extensions(ptls_t *tls, ptls_handshake_properties_t *properties, ptls_raw_extension_t *slots)
{
    quicly_conn_t *conn = (void *)((char *)properties - offsetof(quicly_conn_t, crypto.handshake_properties));
    int ret;

    if (slots[0].type == UINT16_MAX) {
        ret = 0; // FIXME whether not seeing TP is a fatal error depends on the outcome of the VN design
        goto Exit;
    }
    assert(slots[0].type == QUICLY_TLS_EXTENSION_TYPE_TRANSPORT_PARAMETERS);
    assert(slots[1].type == UINT16_MAX);

    const uint8_t *src = slots[0].data.base, *end = src + slots[0].data.len;

    uint32_t negotiated_version;
    if ((ret = ptls_decode32(&negotiated_version, &src, end)) != 0)
        goto Exit;
    if (negotiated_version != QUICLY_PROTOCOL_VERSION) {
        fprintf(stderr, "unexpected negotiated version\n");
        ret = QUICLY_TRANSPORT_ERROR_VERSION_NEGOTIATION;
        goto Exit;
    }

    ptls_decode_open_block(src, end, 1, {
        int found_negotiated_version = 0;
        do {
            uint32_t supported_version;
            if ((ret = ptls_decode32(&supported_version, &src, end)) != 0)
                goto Exit;
            if (supported_version == negotiated_version)
                found_negotiated_version = 1;
        } while (src != end);
        if (!found_negotiated_version) {
            ret = PTLS_ALERT_ILLEGAL_PARAMETER; /* FIXME is this the correct error code? */
            goto Exit;
        }
    });

    {
        quicly_transport_parameters_t params;
        quicly_cid_t odcid;
        if ((ret = quicly_decode_transport_parameter_list(&params, &odcid, conn->super.peer.stateless_reset_token, 1, src, end)) !=
            0)
            goto Exit;
        if (odcid.len != conn->retry_odcid.len || memcmp(odcid.cid, conn->retry_odcid.cid, odcid.len) != 0) {
            ret = QUICLY_TRANSPORT_ERROR_TRANSPORT_PARAMETER;
            goto Exit;
        }
#define VALIDATE(x)                                                                                                                \
    if (params.x < conn->super.peer.transport_params.x) {                                                                          \
        ret = QUICLY_TRANSPORT_ERROR_TRANSPORT_PARAMETER;                                                                          \
        goto Exit;                                                                                                                 \
    }
        VALIDATE(max_data);
        VALIDATE(max_stream_data.bidi_local);
        VALIDATE(max_stream_data.bidi_remote);
        VALIDATE(max_stream_data.uni);
        VALIDATE(max_streams_bidi);
        VALIDATE(max_streams_uni);
#undef VALIDATE
        conn->super.peer.transport_params = params;
    }

Exit:
    return ret; /* negative error codes used to transmit QUIC errors through picotls */
}

int quicly_connect(quicly_conn_t **_conn, quicly_context_t *ctx, const char *server_name, struct sockaddr *sa, socklen_t salen,
                   const quicly_cid_plaintext_t *new_cid, ptls_handshake_properties_t *handshake_properties,
                   const quicly_transport_parameters_t *resumed_transport_params)
{
    quicly_conn_t *conn = NULL;
    const quicly_cid_t *server_cid;
    ptls_buffer_t buf;
    size_t epoch_offsets[5] = {0};
    size_t max_early_data_size = 0;
    int ret;

    update_now(ctx);

    if ((conn = create_connection(ctx, server_name, sa, salen, new_cid, handshake_properties)) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }
    server_cid = quicly_get_peer_cid(conn);

    LOG_CONNECTION_EVENT(conn, QUICLY_EVENT_TYPE_CONNECT, VEC_EVENT_ATTR(DCID, ptls_iovec_init(server_cid->cid, server_cid->len)),
                         VEC_EVENT_ATTR(SCID, ptls_iovec_init(conn->super.host.src_cid.cid, conn->super.host.src_cid.len)),
                         INT_EVENT_ATTR(QUIC_VERSION, conn->super.version));

    if ((ret = setup_handshake_space_and_flow(conn, 0)) != 0)
        goto Exit;
    if ((ret = setup_initial_encryption(&conn->initial->cipher.ingress, &conn->initial->cipher.egress, ctx->tls->cipher_suites,
                                        ptls_iovec_init(server_cid->cid, server_cid->len), 1)) != 0)
        goto Exit;

    /* handshake */
    ptls_buffer_init(&conn->crypto.transport_params.buf, "", 0);
    ptls_buffer_push32(&conn->crypto.transport_params.buf, conn->super.version);
    if ((ret = quicly_encode_transport_parameter_list(&conn->crypto.transport_params.buf, 1, &conn->super.ctx->transport_params,
                                                      NULL, NULL)) != 0)
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
        apply_peer_transport_params(conn);
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
        ret = 0; // allow abcense of the extension for the time being PTLS_ALERT_MISSING_EXTENSION;
        goto Exit;
    }
    assert(slots[0].type == QUICLY_TLS_EXTENSION_TYPE_TRANSPORT_PARAMETERS);
    assert(slots[1].type == UINT16_MAX);

    { /* decode transport_parameters extension */
        const uint8_t *src = slots[0].data.base, *end = src + slots[0].data.len;
        uint32_t initial_version;
        if ((ret = ptls_decode32(&initial_version, &src, end)) != 0)
            goto Exit;
        /* TODO we need to check initial_version when supporting multiple versions */
        if ((ret = quicly_decode_transport_parameter_list(&conn->super.peer.transport_params, NULL, NULL, 0, src, end)) != 0)
            goto Exit;
    }

    /* set transport_parameters extension to be sent in EE */
    assert(properties->additional_extensions == NULL);
    ptls_buffer_init(&conn->crypto.transport_params.buf, "", 0);
    ptls_buffer_push32(&conn->crypto.transport_params.buf, QUICLY_PROTOCOL_VERSION);
    ptls_buffer_push_block(&conn->crypto.transport_params.buf, 1,
                           { ptls_buffer_push32(&conn->crypto.transport_params.buf, QUICLY_PROTOCOL_VERSION); });
    if ((ret = quicly_encode_transport_parameter_list(
             &conn->crypto.transport_params.buf, 0, &conn->super.ctx->transport_params,
             conn->retry_odcid.len != 0 ? &conn->retry_odcid : NULL,
             conn->super.ctx->cid_encryptor != NULL ? conn->super.host.stateless_reset_token : NULL)) != 0)
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

static ptls_iovec_t decrypt_packet(ptls_cipher_context_t *header_protection, ptls_aead_context_t **aead, uint64_t *next_expected_pn,
                                   quicly_decoded_packet_t *packet, uint64_t *pn)
{
    size_t encrypted_len = packet->octets.len - packet->encrypted_off;
    uint8_t hpmask[5] = {0};
    uint32_t pnbits = 0;
    size_t pnlen, aead_index, i;

    /* decipher the header protection, as well as obtaining pnbits, pnlen */
    if (encrypted_len < header_protection->algo->iv_size + QUICLY_MAX_PN_SIZE)
        goto Error;
    ptls_cipher_init(header_protection, packet->octets.base + packet->encrypted_off + QUICLY_MAX_PN_SIZE);
    ptls_cipher_encrypt(header_protection, hpmask, hpmask, sizeof(hpmask));
    packet->octets.base[0] ^= hpmask[0] & (QUICLY_PACKET_IS_LONG_HEADER(packet->octets.base[0]) ? 0xf : 0x1f);
    pnlen = (packet->octets.base[0] & 0x3) + 1;
    for (i = 0; i != pnlen; ++i) {
        packet->octets.base[packet->encrypted_off + i] ^= hpmask[i + 1];
        pnbits = (pnbits << 8) | packet->octets.base[packet->encrypted_off + i];
    }

    /* determine aead index (FIXME move AEAD key selection and decryption logic to the caller?) */
    if (QUICLY_PACKET_IS_LONG_HEADER(packet->octets.base[0])) {
        aead_index = 0;
    } else {
        /* note: aead index 0 is used by 0-RTT */
        aead_index = (packet->octets.base[0] & QUICLY_KEY_PHASE_BIT) == 0;
        if (aead[aead_index] == NULL)
            goto Error;
    }

    /* AEAD */
    *pn = quicly_determine_packet_number(pnbits, (uint32_t)UINT32_MAX >> ((4 - pnlen) * 8), *next_expected_pn);
    size_t aead_off = packet->encrypted_off + pnlen, ptlen;
    if ((ptlen = ptls_aead_decrypt(aead[aead_index], packet->octets.base + aead_off, packet->octets.base + aead_off,
                                   packet->octets.len - aead_off, *pn, packet->octets.base, aead_off)) == SIZE_MAX) {
        if (QUICLY_DEBUG)
            fprintf(stderr, "%s: aead decryption failure (pn: %" PRIu64 ")\n", __FUNCTION__, *pn);
        goto Error;
    }

    /* check reserved bits after AEAD decryption */
    if ((packet->octets.base[0] & (QUICLY_PACKET_IS_LONG_HEADER(packet->octets.base[0]) ? QUICLY_LONG_HEADER_RESERVED_BITS
                                                                                        : QUICLY_SHORT_HEADER_RESERVED_BITS)) !=
        0) {
        if (QUICLY_DEBUG)
            fprintf(stderr, "%s: non-zero reserved bits (pn: %" PRIu64 ")\n", __FUNCTION__, *pn);
        goto Error;
    }

    if (QUICLY_DEBUG) {
        char *payload_hex = quicly_hexdump(packet->octets.base + aead_off, ptlen, 4);
        fprintf(stderr, "%s: AEAD payload:\n%s", __FUNCTION__, payload_hex);
        free(payload_hex);
    }

    if (*next_expected_pn <= *pn)
        *next_expected_pn = *pn + 1;
    return ptls_iovec_init(packet->octets.base + aead_off, ptlen);

Error:
    return ptls_iovec_init(NULL, 0);
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
        }
        if (space != NULL) {
            quicly_ranges_subtract(&space->ack_queue, sent->data.ack.range.start, sent->data.ack.range.end);
            if (space->ack_queue.num_ranges == 0) {
                space->largest_pn_received_at = INT64_MAX;
                space->unacked_count = 0;
            }
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

    LOG_STREAM_EVENT(conn, sent->data.stream.stream_id,
                     event == QUICLY_SENTMAP_EVENT_ACKED ? QUICLY_EVENT_TYPE_STREAM_ACKED : QUICLY_EVENT_TYPE_STREAM_LOST,
                     INT_EVENT_ATTR(OFFSET, sent->data.stream.args.start),
                     INT_EVENT_ATTR(LENGTH, sent->data.stream.args.end - sent->data.stream.args.start));

    /* TODO cache pointer to stream (using a generation counter?) */
    if ((stream = quicly_get_stream(conn, sent->data.stream.stream_id)) == NULL)
        return 0;

    if (event == QUICLY_SENTMAP_EVENT_ACKED) {
        size_t bytes_to_shift;
        if ((ret = quicly_sendstate_acked(&stream->sendstate, &sent->data.stream.args, packet->bytes_in_flight != 0,
                                          &bytes_to_shift)) != 0)
            return ret;
        if (stream_is_destroyable(stream)) {
            destroy_stream(stream);
        } else if (bytes_to_shift != 0) {
            stream->callbacks->on_send_shift(stream, bytes_to_shift);
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
        if (event == QUICLY_SENTMAP_EVENT_ACKED) {
            quicly_maxsender_acked(&stream->_send_aux.max_stream_data_sender, &sent->data.max_stream_data.args);
        } else {
            quicly_maxsender_lost(&stream->_send_aux.max_stream_data_sender, &sent->data.max_stream_data.args);
            if (should_update_max_stream_data(stream))
                sched_stream_control(stream);
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
                destroy_stream(stream);
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

int64_t quicly_get_first_timeout(quicly_conn_t *conn)
{
    if (round_send_window((ssize_t)cc_get_cwnd(&conn->egress.cc.ccv) - (ssize_t)conn->egress.sentmap.bytes_in_flight) > 0) {
        if (conn->crypto.pending_flows != 0 || quicly_linklist_is_linked(&conn->pending_link.control) ||
            quicly_linklist_is_linked(&conn->pending_link.stream_fin_only) ||
            quicly_linklist_is_linked(&conn->pending_link.stream_with_payload))
            return 0;
    }

    int64_t at = conn->egress.loss.alarm_at;
    if (conn->egress.send_ack_at < at)
        at = conn->egress.send_ack_at;

    return at;
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
    /* minimum packets that need to be sent */
    size_t min_packets_to_send;
    /* the currently available window for sending (in bytes) */
    ssize_t send_window;
    /* location where next frame should be written */
    uint8_t *dst;
    /* end of the payload area, beyond which frames cannot be written */
    uint8_t *dst_end;
    /* address at which payload starts */
    uint8_t *dst_payload_from;
};

static int commit_send_packet(quicly_conn_t *conn, struct st_quicly_send_context_t *s, int coalesced)
{
    size_t packet_bytes_in_flight;

    assert(s->target.cipher->aead != NULL);

    assert(s->dst != s->dst_payload_from);

    /* pad so that the pn + payload would be at least 4 bytes */
    while (s->dst - s->dst_payload_from < QUICLY_MAX_PN_SIZE - QUICLY_SEND_PN_SIZE)
        *s->dst++ = QUICLY_FRAME_TYPE_PADDING;

    /* the last packet of first-flight datagrams is padded to become 1280 bytes */
    if (!coalesced && (s->target.packet->data.base[0] & QUICLY_PACKET_TYPE_BITMASK) == QUICLY_PACKET_TYPE_INITIAL &&
        conn->super.state == QUICLY_STATE_FIRSTFLIGHT) {
        const size_t max_size = 1264; /* max UDP packet size excluding aead tag */
        assert(quicly_is_client(conn));
        assert(s->dst - s->target.packet->data.base <= max_size);
        memset(s->dst, QUICLY_FRAME_TYPE_PADDING, s->target.packet->data.base + max_size - s->dst);
        s->dst = s->target.packet->data.base + max_size;
    }

    if (QUICLY_PACKET_IS_LONG_HEADER(*s->target.first_byte_at)) {
        uint16_t length = s->dst - s->dst_payload_from + s->target.cipher->aead->algo->tag_size + QUICLY_SEND_PN_SIZE;
        /* length is always 2 bytes, see _do_prepare_packet */
        length |= 0x4000;
        quicly_encode16(s->dst_payload_from - QUICLY_SEND_PN_SIZE - 2, length);
    }
    quicly_encode16(s->dst_payload_from - QUICLY_SEND_PN_SIZE, (uint16_t)conn->egress.packet_number);

    s->dst = s->dst_payload_from + ptls_aead_encrypt(s->target.cipher->aead, s->dst_payload_from, s->dst_payload_from,
                                                     s->dst - s->dst_payload_from, conn->egress.packet_number,
                                                     s->target.first_byte_at, s->dst_payload_from - s->target.first_byte_at);

    { /* apply header protection */
        uint8_t hpmask[1 + QUICLY_SEND_PN_SIZE] = {0};
        ptls_cipher_init(s->target.cipher->header_protection, s->dst_payload_from - QUICLY_SEND_PN_SIZE + QUICLY_MAX_PN_SIZE);
        ptls_cipher_encrypt(s->target.cipher->header_protection, hpmask, hpmask, sizeof(hpmask));
        *s->target.first_byte_at ^= hpmask[0] & (QUICLY_PACKET_IS_LONG_HEADER(*s->target.first_byte_at) ? 0xf : 0x1f);
        size_t i;
        for (i = 0; i != QUICLY_SEND_PN_SIZE; ++i)
            s->dst_payload_from[i - QUICLY_SEND_PN_SIZE] ^= hpmask[i + 1];
    }

    /* update CC, commit sentmap */
    if (s->target.ack_eliciting) {
        packet_bytes_in_flight = s->dst - s->target.first_byte_at;
        s->send_window -= packet_bytes_in_flight;
    } else {
        packet_bytes_in_flight = 0;
    }
    quicly_sentmap_commit(&conn->egress.sentmap, (uint16_t)packet_bytes_in_flight);

    s->target.packet->data.len = s->dst - s->target.packet->data.base;
    assert(s->target.packet->data.len <= conn->super.ctx->max_packet_size);

    LOG_CONNECTION_EVENT(conn, QUICLY_EVENT_TYPE_PACKET_COMMIT, INT_EVENT_ATTR(PACKET_NUMBER, conn->egress.packet_number),
                         INT_EVENT_ATTR(LENGTH, s->target.packet->data.len), INT_EVENT_ATTR(ACK_ONLY, !s->target.ack_eliciting));
    LOG_CONNECTION_EVENT(conn, QUICLY_EVENT_TYPE_QUICTRACE_SEND, INT_EVENT_ATTR(PACKET_NUMBER, conn->egress.packet_number),
                         INT_EVENT_ATTR(LENGTH, s->target.packet->data.len),
                         INT_EVENT_ATTR(PACKET_TYPE, get_epoch(s->target.packet->data.base[0])));

    ++conn->egress.packet_number;
    ++conn->super.num_packets.sent;
    conn->super.num_bytes_sent += s->target.packet->data.len;

    if (!coalesced) {
        s->packets[s->num_packets++] = s->target.packet;
        s->target.packet = NULL;
        s->target.cipher = NULL;
        s->target.first_byte_at = NULL;
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

static int _do_allocate_frame(quicly_conn_t *conn, struct st_quicly_send_context_t *s, size_t min_space, int ack_eliciting)
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
        s->target.cipher = s->current.cipher;
    } else {
        if (s->num_packets >= s->max_packets)
            return QUICLY_ERROR_SENDBUF_FULL;
        s->send_window = round_send_window(s->send_window);
        if (ack_eliciting && s->send_window < (ssize_t)min_space)
            return QUICLY_ERROR_SENDBUF_FULL;
        if ((s->target.packet = conn->super.ctx->packet_allocator->alloc_packet(
                 conn->super.ctx->packet_allocator, conn->super.peer.salen, conn->super.ctx->max_packet_size)) == NULL)
            return PTLS_ERROR_NO_MEMORY;
        s->target.packet->salen = conn->super.peer.salen;
        memcpy(&s->target.packet->sa, conn->super.peer.sa, conn->super.peer.salen);
        s->target.cipher = s->current.cipher;
        s->dst = s->target.packet->data.base;
        s->dst_end = s->target.packet->data.base + conn->super.ctx->max_packet_size;
    }
    s->target.ack_eliciting = 0;

    LOG_CONNECTION_EVENT(conn, QUICLY_EVENT_TYPE_PACKET_PREPARE, INT_EVENT_ATTR(FIRST_OCTET, s->current.first_byte),
                         VEC_EVENT_ATTR(DCID, ptls_iovec_init(conn->super.peer.cid.cid, conn->super.peer.cid.len)));

    /* emit header */
    s->target.first_byte_at = s->dst;
    *s->dst++ = s->current.first_byte | 0x1 /* pnlen == 2 */;
    if (QUICLY_PACKET_IS_LONG_HEADER(s->current.first_byte)) {
        s->dst = quicly_encode32(s->dst, conn->super.version);
        *s->dst++ = (encode_cid_length(conn->super.peer.cid.len) << 4) | encode_cid_length(conn->super.host.src_cid.len);
        s->dst = emit_cid(s->dst, &conn->super.peer.cid);
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

    {
        /* register to sentmap */
        uint8_t ack_epoch = get_epoch(s->current.first_byte);
        if (ack_epoch == QUICLY_EPOCH_0RTT)
            ack_epoch = QUICLY_EPOCH_1RTT;
        if ((ret = quicly_sentmap_prepare(&conn->egress.sentmap, conn->egress.packet_number, now, ack_epoch)) != 0)
            return ret;
    }

    /* add PING or empty CRYPTO for TLP, RTO packets so that last_retransmittable_sent_at changes */
    if (s->num_packets < s->min_packets_to_send) {
        if (QUICLY_PACKET_IS_LONG_HEADER(s->current.first_byte)) {
            size_t payload_len = 0;
            s->dst = quicly_encode_crypto_frame_header(s->dst, s->dst_end, 0, &payload_len);
        } else {
            *s->dst++ = QUICLY_FRAME_TYPE_PING;
        }
        ack_eliciting = 1;
    }

TargetReady:
    if (ack_eliciting) {
        s->target.ack_eliciting = 1;
        conn->egress.last_retransmittable_sent_at = now;
    }
    return 0;
}

static int allocate_frame(quicly_conn_t *conn, struct st_quicly_send_context_t *s, size_t min_space)
{
    return _do_allocate_frame(conn, s, min_space, 0);
}

static int allocate_ack_eliciting_frame(quicly_conn_t *conn, struct st_quicly_send_context_t *s, size_t min_space,
                                        quicly_sent_t **sent, quicly_sent_acked_cb acked)
{
    int ret;

    if ((ret = _do_allocate_frame(conn, s, min_space, 1)) != 0)
        return ret;
    if ((*sent = quicly_sentmap_allocate(&conn->egress.sentmap, acked)) == NULL)
        return PTLS_ERROR_NO_MEMORY;

    /* TODO return the remaining window that the sender can use */
    return ret;
}

static int send_ack(quicly_conn_t *conn, struct st_quicly_pn_space_t *space, struct st_quicly_send_context_t *s)
{
    uint64_t ack_delay;
    int ret;

    if (space->ack_queue.num_ranges == 0)
        return 0;

    /* calc ack_delay */
    if (space->largest_pn_received_at < now) {
        /* We underreport ack_delay up to 1 milliseconds assuming that QUICLY_ACK_DELAY_EXPONENT is 10. It's considered a non-issue
         * because our time measurement is at millisecond granurality anyways. */
        ack_delay = ((now - space->largest_pn_received_at) * 1000) >> QUICLY_ACK_DELAY_EXPONENT;
    } else {
        ack_delay = 0;
    }

    /* emit ack frame */
Emit:
    if ((ret = allocate_frame(conn, s, QUICLY_ACK_FRAME_CAPACITY)) != 0)
        return ret;
    uint8_t *new_dst = quicly_encode_ack_frame(s->dst, s->dst_end, &space->ack_queue, ack_delay);
    if (new_dst == NULL) {
        /* no space, retry with new MTU-sized packet */
        if ((ret = commit_send_packet(conn, s, 0)) != 0)
            return ret;
        goto Emit;
    }
    s->dst = new_dst;

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

static int prepare_stream_state_sender(quicly_stream_t *stream, quicly_sender_state_t *sender, struct st_quicly_send_context_t *s,
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

static int send_stream_control_frames(quicly_stream_t *stream, struct st_quicly_send_context_t *s)
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
    if (should_update_max_stream_data(stream)) {
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
    }

    /* send RST_STREAM if necessary */
    if (stream->_send_aux.rst.sender_state == QUICLY_SENDER_STATE_SEND) {
        if ((ret = prepare_stream_state_sender(stream, &stream->_send_aux.rst.sender_state, s, QUICLY_RST_FRAME_CAPACITY,
                                               on_ack_rst_stream)) != 0)
            return ret;
        s->dst =
            quicly_encode_rst_stream_frame(s->dst, stream->stream_id, stream->_send_aux.rst.error_code, stream->_send_aux.max_sent);
    }

    return 0;
}

static int send_stream_data(quicly_stream_t *stream, struct st_quicly_send_context_t *s)
{
    uint64_t off = stream->sendstate.pending.ranges[0].start, end_off;
    quicly_sent_t *sent;
    uint8_t *frame_type_at;
    size_t capacity, len;
    int ret, wrote_all;

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
        if (!stream->sendstate.is_open &&
            off + 1 == stream->sendstate.pending.ranges[stream->sendstate.pending.num_ranges - 1].end) {
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
            end_off = off + 1;
            wrote_all = 1;
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
        if (off + capacity > stream->_send_aux.max_sent) {
            uint64_t new_bytes = off + capacity - stream->_send_aux.max_sent;
            if (new_bytes > stream->conn->egress.max_data.permitted - stream->conn->egress.max_data.sent) {
                size_t max_stream_data =
                    stream->_send_aux.max_sent + stream->conn->egress.max_data.permitted - stream->conn->egress.max_data.sent;
                capacity = max_stream_data - off;
            }
        }
    }
    { /* cap the capacity to the current range */
        uint64_t range_capacity = stream->sendstate.pending.ranges[0].end - off;
        if (stream->sendstate.pending.num_ranges == 1)
            range_capacity -= !stream->sendstate.is_open;
        if (capacity > range_capacity)
            capacity = range_capacity;
    }

    /* write payload */
    assert(capacity != 0);
    len = capacity;
    if ((ret = stream->callbacks->on_send_emit(stream, (size_t)(off - stream->sendstate.acked.ranges[0].end), s->dst, &len,
                                               &wrote_all)) != 0)
        return ret;
    assert(len != 0);
    assert(len <= capacity);

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

    /* adjust max_stream_data, max_data */
    if (stream->stream_id >= 0 && end_off > stream->_send_aux.max_sent) {
        stream->conn->egress.max_data.sent += end_off - stream->_send_aux.max_sent;
        stream->_send_aux.max_sent = end_off;
    }

    /* determine if the frame incorporates FIN */
    int is_fin = 0;
    if (!stream->sendstate.is_open && end_off + 1 == stream->sendstate.size_committed) {
        assert(end_off + 1 == stream->sendstate.pending.ranges[stream->sendstate.pending.num_ranges - 1].end);
        assert(frame_type_at != NULL);
        is_fin = 1;
    }

    LOG_STREAM_EVENT(stream->conn, stream->stream_id, QUICLY_EVENT_TYPE_STREAM_SEND, INT_EVENT_ATTR(OFFSET, off),
                     INT_EVENT_ATTR(LENGTH, end_off - off), INT_EVENT_ATTR(FIN, is_fin));
    LOG_STREAM_EVENT(stream->conn, stream->stream_id, QUICLY_EVENT_TYPE_QUICTRACE_SEND_STREAM, INT_EVENT_ATTR(OFFSET, off),
                     INT_EVENT_ATTR(LENGTH, end_off - off), INT_EVENT_ATTR(FIN, is_fin));

    /* set FIN bit if necessary (also adjusts end_off to include EOS byte) */
    if (is_fin) {
        *frame_type_at |= QUICLY_FRAME_TYPE_STREAM_BIT_FIN;
        ++end_off;
    }

UpdateState:
    /* update sendstate */
    if (stream->sendstate.size_committed < end_off)
        stream->sendstate.size_committed = end_off;
    if ((ret = quicly_ranges_subtract(&stream->sendstate.pending, off, end_off)) != 0)
        return ret;
    if (wrote_all) {
        if ((ret = quicly_ranges_subtract(&stream->sendstate.pending, stream->sendstate.size_committed, UINT64_MAX)) != 0)
            return ret;
    }

    /* setup sentmap */
    sent->data.stream.stream_id = stream->stream_id;
    sent->data.stream.args.start = off;
    sent->data.stream.args.end = end_off;

    return 0;
}

static int64_t get_sentmap_expiration_time(quicly_conn_t *conn)
{
    /* TODO reconsider this (maybe 3 PTO? also not sure why we need to add ack-delay twice) */
    return (conn->egress.loss.rtt.smoothed + conn->egress.loss.rtt.variance) * 4 + conn->super.peer.transport_params.max_ack_delay +
           QUICLY_DELAYED_ACK_TIMEOUT;
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
 * Determine frames to be retransmitted on TLP and RTO.
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
        if ((ret = quicly_sentmap_update(&conn->egress.sentmap, &iter, QUICLY_SENTMAP_EVENT_LOST, conn)) != 0)
            return ret;
        conn->egress.max_lost_pn = pn + 1;
    } while (--count != 0);

    return 0;
}

/* this function ensures that the value returned in loss_time is when the next
 * application timer should be set for loss detection. if no timer is required,
 * loss_time is set to INT64_MAX.
 */
static int do_detect_loss(quicly_loss_t *ld, uint64_t largest_pn, uint32_t delay_until_lost, int64_t *loss_time)
{
    quicly_conn_t *conn = (void *)((char *)ld - offsetof(quicly_conn_t, egress.loss));
    quicly_sentmap_iter_t iter;
    const quicly_sent_packet_t *sent;
    int64_t sent_before = now - delay_until_lost;
    uint64_t largest_newly_lost_pn = UINT64_MAX;
    int is_loss = 0, ret;

    *loss_time = INT64_MAX;

    init_acks_iter(conn, &iter);

    /* mark packets as lost if they are smaller than the largest_pn and outside
     * the early retransmit window. in other words, packets that are not ready
     * to be marked as lost according to the early retransmit timer.
     */
    while ((sent = quicly_sentmap_get(&iter))->packet_number < largest_pn && sent->sent_at <= sent_before) {
        if (sent->bytes_in_flight != 0 && conn->egress.max_lost_pn <= sent->packet_number) {
            if (sent->packet_number != largest_newly_lost_pn) {
                ++conn->super.num_packets.lost;
                largest_newly_lost_pn = sent->packet_number;
                LOG_CONNECTION_EVENT(conn, QUICLY_EVENT_TYPE_PACKET_LOST, INT_EVENT_ATTR(PACKET_NUMBER, largest_newly_lost_pn));
            }
            if ((ret = quicly_sentmap_update(&conn->egress.sentmap, &iter, QUICLY_SENTMAP_EVENT_LOST, conn)) != 0)
                return ret;
            is_loss = 1;
        } else {
            quicly_sentmap_skip(&iter);
        }
    }
    if (largest_newly_lost_pn != UINT64_MAX) {
        conn->egress.max_lost_pn = largest_newly_lost_pn + 1;
        conn->egress.cc.end_of_recovery = conn->egress.packet_number - 1;
        if (is_loss && conn->egress.loss.rto_count == 0) {
            cc_cong_signal(&conn->egress.cc.ccv, CC_ECN, (uint32_t)conn->egress.sentmap.bytes_in_flight);
            LOG_CONNECTION_EVENT(conn, QUICLY_EVENT_TYPE_CC_CONGESTION, INT_EVENT_ATTR(MAX_LOST_PN, conn->egress.max_lost_pn),
                                 INT_EVENT_ATTR(END_OF_RECOVERY, conn->egress.cc.end_of_recovery),
                                 INT_EVENT_ATTR(BYTES_IN_FLIGHT, conn->egress.sentmap.bytes_in_flight),
                                 INT_EVENT_ATTR(CWND, cc_get_cwnd(&conn->egress.cc.ccv)));
        }
    }

    /* schedule early retransmit alarm if there is a packet outstanding that is smaller than largest_pn */
    while (sent->packet_number < largest_pn && sent->sent_at != INT64_MAX) {
        if (sent->bytes_in_flight != 0) {
            *loss_time = sent->sent_at + delay_until_lost;
            break;
        }
        quicly_sentmap_skip(&iter);
        sent = quicly_sentmap_get(&iter);
    }

    return 0;
}

static void open_id_blocked_streams(quicly_conn_t *conn, int uni)
{
    uint64_t count;
    quicly_linklist_t *anchor;

    if (uni) {
        count = conn->egress.max_streams.uni.count;
        anchor = &conn->pending_link.streams_blocked.uni;
    } else {
        count = conn->egress.max_streams.bidi.count;
        anchor = &conn->pending_link.streams_blocked.bidi;
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

static int send_stream_frames(quicly_conn_t *conn, struct st_quicly_send_context_t *s)
{
    int ret = 0;

    /* fin-only STREAM frames */
    while (s->num_packets != s->max_packets && quicly_linklist_is_linked(&conn->pending_link.stream_fin_only)) {
        quicly_stream_t *stream =
            (void *)((char *)conn->pending_link.stream_fin_only.next - offsetof(quicly_stream_t, _send_aux.pending_link.stream));
        if ((ret = send_stream_data(stream, s)) != 0)
            goto Exit;
        resched_stream_data(stream);
    }
    /* STREAM frames with payload */
    while (s->num_packets != s->max_packets && quicly_linklist_is_linked(&conn->pending_link.stream_with_payload) &&
           conn->egress.max_data.sent < conn->egress.max_data.permitted) {
        quicly_stream_t *stream = (void *)((char *)conn->pending_link.stream_with_payload.next -
                                           offsetof(quicly_stream_t, _send_aux.pending_link.stream));
        if ((ret = send_stream_data(stream, s)) != 0)
            goto Exit;
        resched_stream_data(stream);
    }

Exit:
    return 0;
}

quicly_datagram_t *quicly_send_version_negotiation(quicly_context_t *ctx, struct sockaddr *sa, socklen_t salen,
                                                   ptls_iovec_t dest_cid, ptls_iovec_t src_cid)
{
    quicly_datagram_t *packet;
    uint8_t *dst;

    if ((packet = ctx->packet_allocator->alloc_packet(ctx->packet_allocator, salen, ctx->max_packet_size)) == NULL)
        return NULL;
    packet->salen = salen;
    memcpy(&packet->sa, sa, salen);
    dst = packet->data.base;

    /* type_flags */
    ctx->tls->random_bytes(dst, 1);
    *dst |= QUICLY_LONG_HEADER_BIT;
    ++dst;
    /* version */
    dst = quicly_encode32(dst, 0);
    /* connection-id */
    *dst++ = (encode_cid_length(dest_cid.len) << 4) | encode_cid_length(src_cid.len);
    if (dest_cid.len != 0) {
        memcpy(dst, dest_cid.base, dest_cid.len);
        dst += dest_cid.len;
    }
    if (src_cid.len != 0) {
        memcpy(dst, src_cid.base, src_cid.len);
        dst += src_cid.len;
    }
    /* supported_versions */
    dst = quicly_encode32(dst, QUICLY_PROTOCOL_VERSION);

    packet->data.len = dst - packet->data.base;

    return packet;
}

quicly_datagram_t *quicly_send_retry(quicly_context_t *ctx, struct sockaddr *sa, socklen_t salen, ptls_iovec_t dcid,
                                     ptls_iovec_t scid, ptls_iovec_t odcid, ptls_iovec_t token)
{
    quicly_datagram_t *packet;
    uint8_t *dst;

    assert(!(scid.len == odcid.len && memcmp(scid.base, odcid.base, scid.len) == 0));

    if ((packet = ctx->packet_allocator->alloc_packet(ctx->packet_allocator, salen, ctx->max_packet_size)) == NULL)
        return NULL;
    packet->salen = salen;
    memcpy(&packet->sa, sa, salen);
    dst = packet->data.base;

    *dst++ = QUICLY_PACKET_TYPE_RETRY | encode_cid_length(odcid.len);
    dst = quicly_encode32(dst, QUICLY_PROTOCOL_VERSION);
    *dst++ = (encode_cid_length(dcid.len) << 4) | encode_cid_length(scid.len);
#define APPEND(x)                                                                                                                  \
    do {                                                                                                                           \
        if (x.len != 0) {                                                                                                          \
            memcpy(dst, x.base, x.len);                                                                                            \
            dst += x.len;                                                                                                          \
        }                                                                                                                          \
    } while (0)
    APPEND(dcid);
    APPEND(scid);
    APPEND(odcid);
    APPEND(token);
#undef APPEND

    packet->data.len = dst - packet->data.base;

    return packet;
}

static int send_handshake_flow(quicly_conn_t *conn, size_t epoch, struct st_quicly_send_context_t *s)
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
    case QUICLY_EPOCH_0RTT:
        if (conn->application == NULL || conn->application->one_rtt_writable ||
            (s->current.cipher = &conn->application->cipher.egress)->aead == NULL)
            return 0;
        s->current.first_byte = QUICLY_PACKET_TYPE_0RTT;
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

    /* send data */
    while ((conn->crypto.pending_flows & (uint8_t)(1 << epoch)) != 0) {
        quicly_stream_t *stream = quicly_get_stream(conn, -(quicly_stream_id_t)(1 + epoch));
        assert(stream != NULL);
        if ((ret = send_stream_data(stream, s)) != 0)
            goto Exit;
        resched_stream_data(stream);
    }

Exit:
    return ret;
}

static int send_connection_close(quicly_conn_t *conn, struct st_quicly_send_context_t *s)
{
    uint8_t frame_header_buf[1 + 2 + 8 + 8], *p;
    size_t reason_phrase_len = strlen(conn->egress.connection_close.reason_phrase);
    int ret;

    /* build the frame excluding the reason_phrase */
    p = frame_header_buf;
    *p++ = conn->egress.connection_close.frame_type != UINT64_MAX ? QUICLY_FRAME_TYPE_TRANSPORT_CLOSE
                                                                  : QUICLY_FRAME_TYPE_APPLICATION_CLOSE;
    p = quicly_encode16(p, conn->egress.connection_close.error_code);
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
        LOG_CONNECTION_EVENT(
            conn, QUICLY_EVENT_TYPE_TRANSPORT_CLOSE_SEND, INT_EVENT_ATTR(ERROR_CODE, conn->egress.connection_close.error_code),
            INT_EVENT_ATTR(FRAME_TYPE, (int64_t)conn->egress.connection_close.frame_type),
            VEC_EVENT_ATTR(REASON_PHRASE, ptls_iovec_init(conn->egress.connection_close.reason_phrase, reason_phrase_len)));
    } else {
        LOG_CONNECTION_EVENT(
            conn, QUICLY_EVENT_TYPE_APPLICATION_CLOSE_SEND, INT_EVENT_ATTR(ERROR_CODE, conn->egress.connection_close.error_code),
            VEC_EVENT_ATTR(REASON_PHRASE, ptls_iovec_init(conn->egress.connection_close.reason_phrase, reason_phrase_len)));
    }
    return 0;
}

static int update_traffic_key_cb(ptls_update_traffic_key_t *self, ptls_t *_tls, int is_enc, size_t epoch, const void *secret)
{
    quicly_conn_t *conn = *ptls_get_data_ptr(_tls);
    ptls_cipher_suite_t *cipher = ptls_get_cipher(conn->crypto.tls);
    ptls_cipher_context_t **hp_slot;
    ptls_aead_context_t **aead_slot;
    int ret;

    LOG_CONNECTION_EVENT(conn, QUICLY_EVENT_TYPE_CRYPTO_UPDATE_SECRET, INT_EVENT_ATTR(IS_ENC, is_enc),
                         INT_EVENT_ATTR(EPOCH, epoch));

#define SELECT_CIPHER_CONTEXT(p)                                                                                                   \
    do {                                                                                                                           \
        hp_slot = &(p)->header_protection;                                                                                         \
        aead_slot = &(p)->aead;                                                                                                    \
    } while (0)

    switch (epoch) {
    case QUICLY_EPOCH_0RTT:
        assert(is_enc == quicly_is_client(conn));
        if (conn->application == NULL && (ret = setup_application_space_and_flow(conn, 1)) != 0)
            return ret;
        if (is_enc) {
            SELECT_CIPHER_CONTEXT(&conn->application->cipher.egress);
        } else {
            hp_slot = &conn->application->cipher.ingress.header_protection.zero_rtt;
            aead_slot = &conn->application->cipher.ingress.aead[0];
        }
        break;
    case QUICLY_EPOCH_HANDSHAKE:
        if (is_enc && conn->application != NULL && quicly_is_client(conn) &&
            !conn->crypto.handshake_properties.client.early_data_accepted_by_peer) {
            /* 0-RTT is rejected */
            assert(conn->application->cipher.egress.aead != NULL);
            dispose_cipher(&conn->application->cipher.egress);
            conn->application->cipher.egress = (struct st_quicly_cipher_context_t){NULL};
            discard_sentmap_by_epoch(
                conn, 1u << QUICLY_EPOCH_1RTT); /* retire all packets with ack_epoch == 3; they are all 0-RTT packets */
        }
        if (conn->handshake == NULL && (ret = setup_handshake_space_and_flow(conn, 2)) != 0)
            return ret;
        SELECT_CIPHER_CONTEXT(is_enc ? &conn->handshake->cipher.egress : &conn->handshake->cipher.ingress);
        break;
    case QUICLY_EPOCH_1RTT:
        if (is_enc)
            apply_peer_transport_params(conn);
        if (conn->application == NULL && (ret = setup_application_space_and_flow(conn, 0)) != 0)
            return ret;
        if (is_enc) {
            if (conn->application->cipher.egress.aead != NULL)
                dispose_cipher(&conn->application->cipher.egress);
            SELECT_CIPHER_CONTEXT(&conn->application->cipher.egress);
        } else {
            hp_slot = &conn->application->cipher.ingress.header_protection.one_rtt;
            aead_slot = &conn->application->cipher.ingress.aead[1];
        }
        break;
    default:
        assert(!"logic flaw");
        break;
    }

#undef SELECT_CIPHER_CONTEXT

    if ((ret = setup_cipher(hp_slot, aead_slot, cipher->aead, cipher->hash, is_enc, secret)) != 0)
        return ret;

    if (epoch == QUICLY_EPOCH_1RTT && is_enc) {
        /* update states now that we have 1-RTT write key */
        conn->application->one_rtt_writable = 1;
        open_id_blocked_streams(conn, 1);
        open_id_blocked_streams(conn, 0);
    }

    return 0;
}

int quicly_send(quicly_conn_t *conn, quicly_datagram_t **packets, size_t *num_packets)
{
    struct st_quicly_send_context_t s = {{NULL, -1}, {NULL, NULL, NULL}, packets, *num_packets};
    int ret;

    update_now(conn->super.ctx);

    LOG_CONNECTION_EVENT(conn, QUICLY_EVENT_TYPE_SEND, INT_EVENT_ATTR(STATE, (int64_t)conn->super.state));

    if (conn->super.state >= QUICLY_STATE_CLOSING) {
        /* check if the connection can be closed now (after 3 pto) */
        quicly_sentmap_iter_t iter;
        init_acks_iter(conn, &iter);
        if (quicly_sentmap_get(&iter)->packet_number == UINT64_MAX)
            return QUICLY_ERROR_FREE_CONNECTION;
        if (conn->super.state == QUICLY_STATE_CLOSING && conn->egress.send_ack_at <= now) {
            destroy_all_streams(conn); /* delayed until the emission of CONNECTION_CLOSE frame to allow quicly_close to be called
                                        * from a stream handler */
            if (conn->application != NULL && conn->application->one_rtt_writable) {
                s.current.cipher = &conn->application->cipher.egress;
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

    /* handle timeouts */
    if (conn->egress.loss.alarm_at <= now) {
        if ((ret = quicly_loss_on_alarm(&conn->egress.loss, conn->egress.packet_number - 1, conn->egress.loss.largest_acked_packet,
                                        do_detect_loss, &s.min_packets_to_send)) != 0)
            goto Exit;
        switch (s.min_packets_to_send) {
        case 1: /* TLP (try to send new data when handshake is done, otherwise retire oldest handshake packets and retransmit) */
            LOG_CONNECTION_EVENT(conn, QUICLY_EVENT_TYPE_CC_TLP,
                                 INT_EVENT_ATTR(BYTES_IN_FLIGHT, conn->egress.sentmap.bytes_in_flight),
                                 INT_EVENT_ATTR(CWND, cc_get_cwnd(&conn->egress.cc.ccv)));
            if (!ptls_handshake_is_complete(conn->crypto.tls)) {
                if ((ret = mark_packets_as_lost(conn, s.min_packets_to_send)) != 0)
                    goto Exit;
            }
            break;
        case 2: /* RTO */ {
            uint32_t cc_type = 0;
            if (!conn->egress.cc.in_first_rto) {
                cc_type = CC_FIRST_RTO;
                cc_cong_signal(&conn->egress.cc.ccv, cc_type, (uint32_t)conn->egress.sentmap.bytes_in_flight);
                conn->egress.cc.in_first_rto = 1;
            }
            LOG_CONNECTION_EVENT(conn, QUICLY_EVENT_TYPE_CC_RTO, INT_EVENT_ATTR(CC_TYPE, cc_type),
                                 INT_EVENT_ATTR(BYTES_IN_FLIGHT, conn->egress.sentmap.bytes_in_flight),
                                 INT_EVENT_ATTR(CWND, cc_get_cwnd(&conn->egress.cc.ccv)));
            if ((ret = mark_packets_as_lost(conn, s.min_packets_to_send)) != 0)
                goto Exit;
        } break;
        default:
            break;
        }
    }

    { /* calculate send window */
        uint32_t cwnd = cc_get_cwnd(&conn->egress.cc.ccv);
        if (conn->egress.sentmap.bytes_in_flight < cwnd)
            s.send_window = cwnd - conn->egress.sentmap.bytes_in_flight;
    }

    /* If TLP or RTO, ensure there's enough send_window to send */
    if (s.min_packets_to_send != 0) {
        assert(s.min_packets_to_send <= s.max_packets);
        if (s.send_window < s.min_packets_to_send * conn->super.ctx->max_packet_size)
            s.send_window = s.min_packets_to_send * conn->super.ctx->max_packet_size;
    }

    { /* send handshake flows */
        size_t epoch;
        for (epoch = 0; epoch <= 2; ++epoch)
            if ((ret = send_handshake_flow(conn, epoch, &s)) != 0)
                goto Exit;
    }

    /* send encrypted frames */
    if (conn->application != NULL && (s.current.cipher = &conn->application->cipher.egress)->header_protection != NULL) {
        if (conn->application->one_rtt_writable) {
            s.current.first_byte = QUICLY_QUIC_BIT; /* short header */
            /* acks */
            if (conn->application->super.unacked_count != 0) {
                if ((ret = send_ack(conn, &conn->application->super, &s)) != 0)
                    goto Exit;
            }
            /* respond to all pending received PATH_CHALLENGE frames */
            if (conn->egress.path_challenge.head != NULL) {
                do {
                    struct st_quicly_pending_path_challenge_t *c = conn->egress.path_challenge.head;
                    if ((ret = allocate_frame(conn, &s, QUICLY_PATH_CHALLENGE_FRAME_CAPACITY)) != 0)
                        goto Exit;
                    s.dst = quicly_encode_path_challenge_frame(s.dst, c->is_response, c->data);
                    conn->egress.path_challenge.head = c->next;
                    free(c);
                } while (conn->egress.path_challenge.head != NULL);
                conn->egress.path_challenge.tail_ref = &conn->egress.path_challenge.head;
            }
/* send max_stream_id frames */
#define SEND_MAX_STREAMS(label, is_uni)                                                                                            \
    if (conn->ingress.max_streams.label != NULL) {                                                                                 \
        if (quicly_maxsender_should_update(conn->ingress.max_streams.label, conn->super.peer.label.next_stream_id / 4,             \
                                           conn->super.peer.label.num_streams, 768)) {                                             \
            uint64_t new_count = conn->super.peer.label.next_stream_id / 4 +                                                       \
                                 conn->super.ctx->transport_params.max_streams_##label - conn->super.peer.label.num_streams;       \
            quicly_sent_t *sent;                                                                                                   \
            if ((ret = allocate_ack_eliciting_frame(conn, &s, QUICLY_MAX_STREAMS_FRAME_CAPACITY, &sent, on_ack_max_streams)) != 0) \
                goto Exit;                                                                                                         \
            s.dst = quicly_encode_max_streams_frame(s.dst, is_uni, new_count);                                                     \
            sent->data.max_streams.uni = is_uni;                                                                                   \
            quicly_maxsender_record(conn->ingress.max_streams.label, new_count, &sent->data.max_streams.args);                     \
        }                                                                                                                          \
    }
            SEND_MAX_STREAMS(uni, 1);
            SEND_MAX_STREAMS(bidi, 0);
#undef SEND_MAX_STREAMS
            /* send connection-level flow control frame */
            if (quicly_maxsender_should_update(&conn->ingress.max_data.sender, conn->ingress.max_data.bytes_consumed,
                                               (uint32_t)conn->super.ctx->transport_params.max_data, 512)) {
                quicly_sent_t *sent;
                if ((ret = allocate_ack_eliciting_frame(conn, &s, QUICLY_MAX_DATA_FRAME_CAPACITY, &sent, on_ack_max_data)) != 0)
                    goto Exit;
                uint64_t new_value = conn->ingress.max_data.bytes_consumed + conn->super.ctx->transport_params.max_data;
                s.dst = quicly_encode_max_data_frame(s.dst, new_value);
                quicly_maxsender_record(&conn->ingress.max_data.sender, new_value, &sent->data.max_data.args);
            }
/* send streams_blocked frames */
#define SEND_STREAMS_BLOCKED(label, is_uni)                                                                                        \
    if (quicly_linklist_is_linked(&conn->pending_link.streams_blocked.label)) {                                                    \
        struct st_quicly_max_streams_t *max_streams = &conn->egress.max_streams.label;                                             \
        quicly_stream_t *max_stream = (void *)((char *)conn->pending_link.streams_blocked.label.prev -                             \
                                               offsetof(quicly_stream_t, _send_aux.pending_link.control));                         \
        assert(max_streams->count == max_stream->stream_id / 4);                                                                   \
        if (quicly_maxsender_should_send_blocked(&max_streams->blocked_sender, max_stream->stream_id / 4)) {                       \
            quicly_sent_t *sent;                                                                                                   \
            if ((ret = allocate_ack_eliciting_frame(conn, &s, QUICLY_STREAMS_BLOCKED_FRAME_CAPACITY, &sent,                        \
                                                    on_ack_streams_blocked)) != 0)                                                 \
                goto Exit;                                                                                                         \
            s.dst = quicly_encode_streams_blocked_frame(s.dst, is_uni, max_stream->stream_id / 4);                                 \
            sent->data.streams_blocked.uni = is_uni;                                                                               \
            quicly_maxsender_record(&max_streams->blocked_sender, max_stream->stream_id / 4, &sent->data.streams_blocked.args);    \
        }                                                                                                                          \
    }
            SEND_STREAMS_BLOCKED(uni, 1);
            SEND_STREAMS_BLOCKED(bidi, 0);
#undef SEND_STREAMS_BLOCKED
        } else {
            s.current.first_byte = QUICLY_PACKET_TYPE_0RTT;
        }
        /* send stream-level control frames */
        while (s.num_packets != s.max_packets && quicly_linklist_is_linked(&conn->pending_link.control)) {
            quicly_stream_t *stream =
                (void *)((char *)conn->pending_link.control.next - offsetof(quicly_stream_t, _send_aux.pending_link.control));
            if ((ret = send_stream_control_frames(stream, &s)) != 0)
                goto Exit;
            quicly_linklist_unlink(&stream->_send_aux.pending_link.control);
        }
        /* send STREAM frames */
        if ((ret = send_stream_frames(conn, &s)) != 0)
            goto Exit;
    }

    if (s.target.packet != NULL)
        commit_send_packet(conn, &s, 0);

    /* TLP (TODO use these packets to retransmit data) */
    if (s.min_packets_to_send != 0) {
        if (QUICLY_PACKET_IS_LONG_HEADER(s.current.first_byte)) {
            if (conn->handshake != NULL && (s.current.cipher = &conn->handshake->cipher.egress)->aead != NULL) {
                s.current.first_byte = QUICLY_PACKET_TYPE_HANDSHAKE;
            } else {
                s.current.cipher = &conn->initial->cipher.egress;
                s.current.first_byte = QUICLY_PACKET_TYPE_INITIAL;
            }
        }
        while (s.num_packets < s.min_packets_to_send) {
            if ((ret = allocate_frame(conn, &s, 1)) != 0)
                goto Exit;
            assert(s.target.ack_eliciting);
            commit_send_packet(conn, &s, 0);
        }
        assert(conn->egress.last_retransmittable_sent_at == now);
    }

    ret = 0;
Exit:
    if (ret == QUICLY_ERROR_SENDBUF_FULL)
        ret = 0;
    if (ret == 0) {
        conn->egress.send_ack_at = INT64_MAX; /* we have send ACKs for every epoch */
        update_loss_alarm(conn);
        *num_packets = s.num_packets;
    }
    if (ret == 0)
        assert_consistency(conn, 1);
    return ret;
}

quicly_datagram_t *quicly_send_stateless_reset(quicly_context_t *ctx, struct sockaddr *sa, socklen_t salen,
                                               const quicly_cid_plaintext_t *cid)
{
    quicly_datagram_t *dgram;

    /* allocate packet, set peer address */
    if ((dgram = ctx->packet_allocator->alloc_packet(ctx->packet_allocator, salen, QUICLY_STATELESS_RESET_PACKET_MIN_LEN)) == NULL)
        return NULL;
    dgram->salen = salen;
    memcpy(&dgram->sa, sa, salen);

    /* build stateless reset packet */
    ctx->tls->random_bytes(dgram->data.base, QUICLY_STATELESS_RESET_PACKET_MIN_LEN - QUICLY_STATELESS_RESET_TOKEN_LEN);
    dgram->data.base[0] = QUICLY_QUIC_BIT | (dgram->data.base[0] & ~QUICLY_LONG_HEADER_RESERVED_BITS);
    ctx->cid_encryptor->encrypt_cid(
        ctx->cid_encryptor, NULL, dgram->data.base + QUICLY_STATELESS_RESET_PACKET_MIN_LEN - QUICLY_STATELESS_RESET_TOKEN_LEN, cid);
    dgram->data.len = QUICLY_STATELESS_RESET_PACKET_MIN_LEN;

    return dgram;
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

static int initiate_close(quicly_conn_t *conn, int err, uint64_t frame_type, const char *reason_phrase)
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

    return initiate_close(conn, err, QUICLY_FRAME_TYPE_PADDING /* used when err == 0 */, reason_phrase);
}

static int get_stream_or_open_if_new(quicly_conn_t *conn, uint64_t stream_id, quicly_stream_t **stream)
{
    int ret = 0;

    if ((*stream = quicly_get_stream(conn, stream_id)) != NULL)
        goto Exit;

    if (quicly_stream_is_client_initiated(stream_id) != quicly_is_client(conn)) {
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

static int handle_stream_frame(quicly_conn_t *conn, quicly_stream_frame_t *frame)
{
    quicly_stream_t *stream;
    int ret;

    if ((ret = get_stream_or_open_if_new(conn, frame->stream_id, &stream)) != 0 || stream == NULL)
        return ret;
    return apply_stream_frame(stream, frame);
}

static int handle_reset_stream_frame(quicly_conn_t *conn, quicly_reset_stream_frame_t *frame)
{
    quicly_stream_t *stream;
    int ret;

    if ((ret = get_stream_or_open_if_new(conn, frame->stream_id, &stream)) != 0 || stream == NULL)
        return ret;

    if (!quicly_recvstate_transfer_complete(&stream->recvstate)) {
        uint64_t bytes_missing;
        if ((ret = quicly_recvstate_reset(&stream->recvstate, frame->final_offset, &bytes_missing)) != 0)
            return ret;
        conn->ingress.max_data.bytes_consumed += bytes_missing;
        if ((ret = stream->callbacks->on_receive_reset(stream, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(frame->app_error_code))) !=
            0)
            return ret;
        if (stream_is_destroyable(stream))
            destroy_stream(stream);
    }

    return 0;
}

static int handle_ack_frame(quicly_conn_t *conn, size_t epoch, quicly_ack_frame_t *frame)
{
    quicly_sentmap_iter_t iter;
    uint64_t packet_number = frame->smallest_acknowledged;
    struct {
        uint64_t packet_number;
        int64_t sent_at;
    } largest_newly_acked = {UINT64_MAX, INT64_MAX};
    uint64_t smallest_newly_acked = UINT64_MAX;
    size_t segs_acked = 0, bytes_acked = 0;
    int ret;

    if (epoch == 1)
        return QUICLY_TRANSPORT_ERROR_PROTOCOL_VIOLATION;

    init_acks_iter(conn, &iter);

    size_t gap_index = frame->num_gaps;
    while (1) {
        uint64_t block_length = frame->ack_block_lengths[gap_index];
        if (block_length != 0) {
            LOG_CONNECTION_EVENT(conn, QUICLY_EVENT_TYPE_QUICTRACE_RECV_ACK, INT_EVENT_ATTR(ACK_BLOCK_BEGIN, packet_number),
                                 INT_EVENT_ATTR(ACK_BLOCK_END, packet_number + block_length - 1));
            while (quicly_sentmap_get(&iter)->packet_number < packet_number)
                quicly_sentmap_skip(&iter);
            do {
                const quicly_sent_packet_t *sent;
                if ((sent = quicly_sentmap_get(&iter))->packet_number == packet_number) {
                    ++conn->super.num_packets.ack_received;
                    if (epoch == sent->ack_epoch) {
                        largest_newly_acked.packet_number = packet_number;
                        largest_newly_acked.sent_at = sent->sent_at;
                        if (smallest_newly_acked == UINT64_MAX)
                            smallest_newly_acked = packet_number;
                        LOG_CONNECTION_EVENT(conn, QUICLY_EVENT_TYPE_PACKET_ACKED, INT_EVENT_ATTR(PACKET_NUMBER, packet_number),
                                             INT_EVENT_ATTR(NEWLY_ACKED, 1));
                        if (sent->bytes_in_flight != 0) {
                            ++segs_acked;
                            bytes_acked += sent->bytes_in_flight;
                        }
                        if ((ret = quicly_sentmap_update(&conn->egress.sentmap, &iter, QUICLY_SENTMAP_EVENT_ACKED, conn)) != 0)
                            return ret;
                    } else {
                        quicly_sentmap_skip(&iter);
                    }
                }
                ++packet_number;
            } while (--block_length != 0);
        }
        if (gap_index-- == 0)
            break;
        packet_number += frame->gaps[gap_index];
    }

    LOG_CONNECTION_EVENT(conn, QUICLY_EVENT_TYPE_QUICTRACE_RECV_ACK, INT_EVENT_ATTR(ACK_DELAY, frame->ack_delay));

    /* OnPacketAcked */
    uint32_t latest_rtt = UINT32_MAX, ack_delay = 0;
    if (largest_newly_acked.packet_number == frame->largest_acknowledged) {
        int64_t t = now - largest_newly_acked.sent_at;
        if (0 <= t && t < 100000) { /* ignore RTT above 100 seconds */
            latest_rtt = (uint32_t)t;
            uint64_t ack_delay_microsecs = frame->ack_delay << conn->super.peer.transport_params.ack_delay_exponent;
            ack_delay = (uint32_t)((ack_delay_microsecs * 2 + 1000) / 2000);
        }
    }
    quicly_loss_on_ack_received(
        &conn->egress.loss, frame->largest_acknowledged, latest_rtt, ack_delay,
        0 /* this relies on the fact that we do not (yet) retransmit ACKs and therefore latest_rtt becoming UINT32_MAX */);
    /* OnPacketAckedCC */
    uint32_t cc_type = 0;
    /* TODO (jri): this function should be called for every packet newly acked. (kazuho) I do not think so;
     * quicly_loss_on_packet_acked is NOT OnPacketAcked */
    if (smallest_newly_acked != UINT64_MAX) {
        if (quicly_loss_on_packet_acked(&conn->egress.loss, smallest_newly_acked)) {
            cc_type = CC_RTO;
            conn->egress.cc.in_first_rto = 0;
        } else if (conn->egress.cc.in_first_rto) {
            cc_type = CC_RTO_ERR;
            conn->egress.cc.in_first_rto = 0;
        }
    }
    if (cc_type != 0)
        cc_cong_signal(&conn->egress.cc.ccv, cc_type, (uint32_t)(conn->egress.sentmap.bytes_in_flight + bytes_acked));
    int exit_recovery = frame->largest_acknowledged >= conn->egress.cc.end_of_recovery;
    cc_ack_received(&conn->egress.cc.ccv, CC_ACK, (uint32_t)(conn->egress.sentmap.bytes_in_flight + bytes_acked),
                    (uint16_t)segs_acked, (uint32_t)bytes_acked,
                    conn->egress.loss.rtt.smoothed / 10 /* TODO better way of converting to cc_ticks */, exit_recovery);
    LOG_CONNECTION_EVENT(conn, QUICLY_EVENT_TYPE_CC_ACK_RECEIVED, INT_EVENT_ATTR(PACKET_NUMBER, frame->largest_acknowledged),
                         INT_EVENT_ATTR(ACKED_PACKETS, segs_acked), INT_EVENT_ATTR(ACKED_BYTES, bytes_acked),
                         INT_EVENT_ATTR(CC_TYPE, cc_type), INT_EVENT_ATTR(CC_EXIT_RECOVERY, exit_recovery),
                         INT_EVENT_ATTR(CWND, cc_get_cwnd(&conn->egress.cc.ccv)),
                         INT_EVENT_ATTR(BYTES_IN_FLIGHT, conn->egress.sentmap.bytes_in_flight));
    if (exit_recovery)
        conn->egress.cc.end_of_recovery = UINT64_MAX;

    /* loss-detection  */
    quicly_loss_detect_loss(&conn->egress.loss, frame->largest_acknowledged, do_detect_loss);
    update_loss_alarm(conn);

    return 0;
}

static int handle_max_stream_data_frame(quicly_conn_t *conn, quicly_max_stream_data_frame_t *frame)
{
    quicly_stream_t *stream;

    if (quicly_stream_is_unidirectional(frame->stream_id) &&
        quicly_stream_is_client_initiated(frame->stream_id) == quicly_is_client(conn))
        return QUICLY_TRANSPORT_ERROR_FRAME_ENCODING;

    if ((stream = quicly_get_stream(conn, frame->stream_id)) == NULL)
        return 0;

    if (frame->max_stream_data < stream->_send_aux.max_stream_data)
        return 0;
    stream->_send_aux.max_stream_data = frame->max_stream_data;

    if (stream->_send_aux.rst.sender_state == QUICLY_SENDER_STATE_NONE)
        resched_stream_data(stream);

    return 0;
}

static int handle_stream_data_blocked_frame(quicly_conn_t *conn, quicly_stream_data_blocked_frame_t *frame)
{
    quicly_stream_t *stream;

    if (quicly_stream_is_unidirectional(frame->stream_id) &&
        quicly_stream_is_client_initiated(frame->stream_id) != quicly_is_client(conn))
        return QUICLY_TRANSPORT_ERROR_FRAME_ENCODING;

    if ((stream = quicly_get_stream(conn, frame->stream_id)) != NULL) {
        quicly_maxsender_reset(&stream->_send_aux.max_stream_data_sender, 0);
        if (should_update_max_stream_data(stream))
            sched_stream_control(stream);
    }

    return 0;
}

static int handle_max_streams_frame(quicly_conn_t *conn, int uni, quicly_max_streams_frame_t *frame)
{
    update_max_streams(uni ? &conn->egress.max_streams.uni : &conn->egress.max_streams.bidi, frame->count);
    open_id_blocked_streams(conn, uni);

    return 0;
}

static int handle_path_challenge_frame(quicly_conn_t *conn, quicly_path_challenge_frame_t *frame)
{
    return schedule_path_challenge(conn, 1, frame->data);
}

static int handle_new_token_frame(quicly_conn_t *conn, quicly_new_token_frame_t *frame)
{
    /* TODO save the token along with the session ticket */
    return 0;
}

static int handle_stop_sending_frame(quicly_conn_t *conn, quicly_stop_sending_frame_t *frame)
{
    quicly_stream_t *stream;
    int ret;

    if ((ret = get_stream_or_open_if_new(conn, frame->stream_id, &stream)) != 0 || stream == NULL)
        return ret;

    if (stream->sendstate.is_open) {
        /* reset the stream, then notify the application */
        int err = QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(frame->app_error_code);
        quicly_reset_stream(stream, err);
        if ((ret = stream->callbacks->on_send_stop(stream, err)) != 0)
            return ret;
    }

    return 0;
}

static int handle_max_data_frame(quicly_conn_t *conn, quicly_max_data_frame_t *frame)
{
    if (frame->max_data < conn->egress.max_data.permitted)
        return 0;
    conn->egress.max_data.permitted = frame->max_data;

    /* TODO schedule for delivery */
    return 0;
}

static int negotiate_using_version(quicly_conn_t *conn, uint32_t version)
{
    /* set selected version */
    conn->super.version = version;
    LOG_CONNECTION_EVENT(conn, QUICLY_EVENT_TYPE_QUIC_VERSION_SWITCH, INT_EVENT_ATTR(QUIC_VERSION, version));

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
    return QUICLY_TRANSPORT_ERROR_VERSION_NEGOTIATION;

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

    if (conn->application == NULL)
        return 0;
    if (QUICLY_PACKET_IS_LONG_HEADER(decoded->octets.base[0]))
        return 0;
    if ((decoded->octets.base[0] & QUICLY_QUIC_BIT) == 0)
        return 0;
    if (decoded->octets.len < QUICLY_STATELESS_RESET_PACKET_MIN_LEN)
        return 0;
    if (memcmp(decoded->octets.base + decoded->octets.len - QUICLY_STATELESS_RESET_TOKEN_LEN,
               conn->super.peer.stateless_reset_token, QUICLY_STATELESS_RESET_TOKEN_LEN) != 0)
        return 0;

    return 1;
}

int quicly_is_destination(quicly_conn_t *conn, struct sockaddr *sa, socklen_t salen, quicly_decoded_packet_t *decoded)
{
    if (QUICLY_PACKET_IS_LONG_HEADER(decoded->octets.base[0])) {
        /* long header: validate address, then consult the CID */
        if (compare_socket_address(conn->super.peer.sa, sa) != 0)
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
        if (compare_socket_address(conn->super.peer.sa, sa) == 0)
            goto Found;
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
    destroy_all_streams(conn);

    return 0;
}

static int handle_transport_close(quicly_conn_t *conn, uint16_t error_code, uint64_t frame_type, ptls_iovec_t reason_phrase)
{
    LOG_CONNECTION_EVENT(conn, QUICLY_EVENT_TYPE_TRANSPORT_CLOSE_RECEIVE, INT_EVENT_ATTR(ERROR_CODE, error_code),
                         INT_EVENT_ATTR(FRAME_TYPE, (int64_t)frame_type), VEC_EVENT_ATTR(REASON_PHRASE, reason_phrase));
    return handle_close(conn, QUICLY_ERROR_FROM_TRANSPORT_ERROR_CODE(error_code), frame_type, reason_phrase);
}

static int handle_application_close(quicly_conn_t *conn, uint16_t error_code, ptls_iovec_t reason_phrase)
{
    LOG_CONNECTION_EVENT(conn, QUICLY_EVENT_TYPE_APPLICATION_CLOSE_RECEIVE, INT_EVENT_ATTR(ERROR_CODE, error_code),
                         VEC_EVENT_ATTR(REASON_PHRASE, reason_phrase));
    return handle_close(conn, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(error_code), UINT64_MAX, reason_phrase);
}

static int handle_stateless_reset(quicly_conn_t *conn)
{
    LOG_CONNECTION_EVENT(conn, QUICLY_EVENT_TYPE_STATELESS_RESET_RECEIVE);
    return handle_close(conn, QUICLY_ERROR_RECEIVED_STATELESS_RESET, UINT64_MAX, ptls_iovec_init("", 0));
}

static int handle_payload(quicly_conn_t *conn, size_t epoch, const uint8_t *src, size_t _len, uint64_t *offending_frame_type,
                          int *is_ack_only)
{
    const uint8_t *end = src + _len;
    uint8_t frame_type;
    int ret = 0;

    *is_ack_only = 1;

    do {
        frame_type = *src++;
        switch (frame_type) {
        case QUICLY_FRAME_TYPE_PADDING:
            break;
        case QUICLY_FRAME_TYPE_TRANSPORT_CLOSE: {
            quicly_transport_close_frame_t frame;
            if ((ret = quicly_decode_transport_close_frame(&src, end, &frame)) != 0)
                goto Exit;
            if ((ret = handle_transport_close(conn, frame.error_code, frame.frame_type, frame.reason_phrase)) != 0)
                goto Exit;
        } break;
        case QUICLY_FRAME_TYPE_APPLICATION_CLOSE: {
            quicly_application_close_frame_t frame;
            if ((ret = quicly_decode_application_close_frame(&src, end, &frame)) != 0)
                goto Exit;
            if ((ret = handle_application_close(conn, frame.error_code, frame.reason_phrase)) != 0)
                goto Exit;
        } break;
        case QUICLY_FRAME_TYPE_ACK:
        case QUICLY_FRAME_TYPE_ACK_ECN: {
            quicly_ack_frame_t frame;
            if ((ret = quicly_decode_ack_frame(&src, end, &frame, frame_type == QUICLY_FRAME_TYPE_ACK_ECN)) != 0)
                goto Exit;
            if ((ret = handle_ack_frame(conn, epoch, &frame)) != 0)
                goto Exit;
        } break;
        case QUICLY_FRAME_TYPE_CRYPTO: {
            quicly_stream_frame_t frame;
            if ((ret = quicly_decode_crypto_frame(&src, end, &frame)) != 0)
                goto Exit;
            if ((ret = apply_handshake_flow(conn, epoch, &frame)) != 0)
                goto Exit;
            *is_ack_only = 0;
        } break;
        default:
            /* 0-rtt, 1-rtt only frames */
            if (!(epoch == 1 || epoch == 3)) {
                ret = QUICLY_TRANSPORT_ERROR_PROTOCOL_VIOLATION;
                goto Exit;
            }
            if ((frame_type & ~QUICLY_FRAME_TYPE_STREAM_BITS) == QUICLY_FRAME_TYPE_STREAM_BASE) {
                quicly_stream_frame_t frame;
                if ((ret = quicly_decode_stream_frame(frame_type, &src, end, &frame)) != 0)
                    goto Exit;
                LOG_STREAM_EVENT(conn, frame.stream_id, QUICLY_EVENT_TYPE_QUICTRACE_RECV_STREAM,
                                 INT_EVENT_ATTR(OFFSET, frame.offset), INT_EVENT_ATTR(LENGTH, frame.data.len),
                                 INT_EVENT_ATTR(FIN, frame.is_fin));
                if ((ret = handle_stream_frame(conn, &frame)) != 0)
                    goto Exit;
            } else {
                switch (frame_type) {
                case QUICLY_FRAME_TYPE_RESET_STREAM: {
                    quicly_reset_stream_frame_t frame;
                    if ((ret = quicly_decode_reset_stream_frame(&src, end, &frame)) != 0)
                        goto Exit;
                    if ((ret = handle_reset_stream_frame(conn, &frame)) != 0)
                        goto Exit;
                } break;
                case QUICLY_FRAME_TYPE_MAX_DATA: {
                    quicly_max_data_frame_t frame;
                    if ((ret = quicly_decode_max_data_frame(&src, end, &frame)) != 0)
                        goto Exit;
                    if ((ret = handle_max_data_frame(conn, &frame)) != 0)
                        goto Exit;
                } break;
                case QUICLY_FRAME_TYPE_MAX_STREAM_DATA: {
                    quicly_max_stream_data_frame_t frame;
                    if ((ret = quicly_decode_max_stream_data_frame(&src, end, &frame)) != 0)
                        goto Exit;
                    if ((ret = handle_max_stream_data_frame(conn, &frame)) != 0)
                        goto Exit;
                } break;
                case QUICLY_FRAME_TYPE_MAX_STREAMS_BIDI:
                case QUICLY_FRAME_TYPE_MAX_STREAMS_UNI: {
                    quicly_max_streams_frame_t frame;
                    if ((ret = quicly_decode_max_streams_frame(&src, end, &frame)) != 0)
                        goto Exit;
                    if ((ret = handle_max_streams_frame(conn, frame_type == QUICLY_FRAME_TYPE_MAX_STREAMS_UNI, &frame)) != 0)
                        goto Exit;
                } break;
                case QUICLY_FRAME_TYPE_PING:
                    ret = 0;
                    break;
                case QUICLY_FRAME_TYPE_DATA_BLOCKED: {
                    quicly_data_blocked_frame_t frame;
                    if ((ret = quicly_decode_data_blocked_frame(&src, end, &frame)) != 0)
                        goto Exit;
                    quicly_maxsender_reset(&conn->ingress.max_data.sender, 0);
                    /* TODO disable ack-delay to respond immediately (by sending MAX_DATA)? */
                    ret = 0;
                } break;
                case QUICLY_FRAME_TYPE_STREAM_DATA_BLOCKED: {
                    quicly_stream_data_blocked_frame_t frame;
                    if ((ret = quicly_decode_stream_data_blocked_frame(&src, end, &frame)) != 0)
                        goto Exit;
                    if ((ret = handle_stream_data_blocked_frame(conn, &frame)) != 0)
                        goto Exit;
                } break;
                case QUICLY_FRAME_TYPE_STREAMS_BLOCKED_BIDI:
                case QUICLY_FRAME_TYPE_STREAMS_BLOCKED_UNI: {
                    quicly_streams_blocked_frame_t frame;
                    if ((ret = quicly_decode_streams_blocked_frame(&src, end, &frame)) != 0)
                        goto Exit;
                    quicly_maxsender_t *maxsender = frame_type == QUICLY_FRAME_TYPE_STREAMS_BLOCKED_UNI
                                                        ? conn->ingress.max_streams.uni
                                                        : conn->ingress.max_streams.bidi;
                    if (maxsender != NULL)
                        quicly_maxsender_reset(maxsender, 0);
                    ret = 0;
                } break;
                case QUICLY_FRAME_TYPE_NEW_CONNECTION_ID: {
                    quicly_new_connection_id_frame_t frame;
                    if ((ret = quicly_decode_new_connection_id_frame(&src, end, &frame)) != 0)
                        goto Exit;
                    /* TODO */
                } break;
                case QUICLY_FRAME_TYPE_STOP_SENDING: {
                    quicly_stop_sending_frame_t frame;
                    if ((ret = quicly_decode_stop_sending_frame(&src, end, &frame)) != 0)
                        goto Exit;
                    if ((ret = handle_stop_sending_frame(conn, &frame)) != 0)
                        goto Exit;
                } break;
                case QUICLY_FRAME_TYPE_PATH_CHALLENGE: {
                    quicly_path_challenge_frame_t frame;
                    if ((ret = quicly_decode_path_challenge_frame(&src, end, &frame)) != 0)
                        goto Exit;
                    if ((ret = handle_path_challenge_frame(conn, &frame)) != 0)
                        goto Exit;
                } break;
                case QUICLY_FRAME_TYPE_NEW_TOKEN: {
                    quicly_new_token_frame_t frame;
                    if ((ret = quicly_decode_new_token_frame(&src, end, &frame)) != 0)
                        goto Exit;
                    if ((ret = handle_new_token_frame(conn, &frame)) != 0)
                        goto Exit;
                } break;
                default:
                    fprintf(stderr, "ignoring frame type:%02x\n", (unsigned)frame_type);
                    *is_ack_only = 0;
                    ret = QUICLY_TRANSPORT_ERROR_FRAME_ENCODING;
                    goto Exit;
                }
            }
            *is_ack_only = 0;
            break;
        }
    } while (src != end);

Exit:
    if (ret != 0)
        *offending_frame_type = frame_type;
    return ret;
}

int quicly_accept(quicly_conn_t **conn, quicly_context_t *ctx, struct sockaddr *sa, socklen_t salen,
                  quicly_decoded_packet_t *packet, ptls_iovec_t retry_odcid, const quicly_cid_plaintext_t *new_cid,
                  ptls_handshake_properties_t *handshake_properties)
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
    if ((ret = setup_initial_encryption(&ingress_cipher, &egress_cipher, ctx->tls->cipher_suites, packet->cid.dest.encrypted, 0)) !=
        0)
        goto Exit;
    next_expected_pn = 0; /* is this correct? do we need to take care of underflow? */
    if ((payload = decrypt_packet(ingress_cipher.header_protection, &ingress_cipher.aead, &next_expected_pn, packet, &pn)).base ==
        NULL) {
        ret = QUICLY_ERROR_PACKET_IGNORED;
        goto Exit;
    }

    /* create connection */
    if ((*conn = create_connection(ctx, NULL, sa, salen, new_cid, handshake_properties)) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }
    (*conn)->super.state = QUICLY_STATE_CONNECTED;
    set_cid(&(*conn)->super.peer.cid, packet->cid.src);
    set_cid(&(*conn)->super.host.offered_cid, packet->cid.dest.encrypted);
    if (retry_odcid.len != 0)
        set_cid(&(*conn)->retry_odcid, retry_odcid);
    if ((ret = setup_handshake_space_and_flow(*conn, 0)) != 0)
        goto Exit;
    (*conn)->initial->super.next_expected_packet_number = next_expected_pn;
    (*conn)->initial->cipher.ingress = ingress_cipher;
    ingress_cipher = (struct st_quicly_cipher_context_t){NULL};
    (*conn)->initial->cipher.egress = egress_cipher;
    egress_cipher = (struct st_quicly_cipher_context_t){NULL};
    (*conn)->crypto.handshake_properties.collected_extensions = server_collected_extensions;

    LOG_CONNECTION_EVENT(*conn, QUICLY_EVENT_TYPE_ACCEPT, VEC_EVENT_ATTR(DCID, packet->cid.dest.encrypted),
                         VEC_EVENT_ATTR(SCID, packet->cid.src));
    LOG_CONNECTION_EVENT(*conn, QUICLY_EVENT_TYPE_CRYPTO_DECRYPT, INT_EVENT_ATTR(PACKET_NUMBER, pn),
                         INT_EVENT_ATTR(LENGTH, payload.len));
    LOG_CONNECTION_EVENT(*conn, QUICLY_EVENT_TYPE_QUICTRACE_RECV, INT_EVENT_ATTR(PACKET_NUMBER, pn),
                         INT_EVENT_ATTR(LENGTH, payload.len), INT_EVENT_ATTR(ENC_LEVEL, QUICLY_EPOCH_INITIAL));

    /* handle the input; we ignore is_ack_only, we consult if there's any output from TLS in response to CH anyways */
    ++(*conn)->super.num_packets.received;
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

int quicly_receive(quicly_conn_t *conn, quicly_decoded_packet_t *packet)
{
    ptls_cipher_context_t *header_protection;
    ptls_aead_context_t **aead;
    struct st_quicly_pn_space_t **space;
    size_t epoch;
    ptls_iovec_t payload;
    uint64_t pn, offending_frame_type = QUICLY_FRAME_TYPE_PADDING;
    int is_ack_only, ret;

    update_now(conn->super.ctx);

    LOG_CONNECTION_EVENT(conn, QUICLY_EVENT_TYPE_RECEIVE, VEC_EVENT_ATTR(DCID, packet->cid.dest.encrypted),
                         QUICLY_PACKET_IS_LONG_HEADER(packet->octets.base[0])
                             ? VEC_EVENT_ATTR(SCID, packet->cid.src)
                             : (quicly_event_attribute_t){QUICLY_EVENT_ATTRIBUTE_NULL},
                         INT_EVENT_ATTR(LENGTH, packet->octets.len), INT_EVENT_ATTR(FIRST_OCTET, packet->octets.base[0]));

    if (is_stateless_reset(conn, packet)) {
        ret = handle_stateless_reset(conn);
        goto Exit;
    }

    /* FIXME check peer address */

    switch (conn->super.state) {
    case QUICLY_STATE_CLOSING:
        conn->super.state = QUICLY_STATE_DRAINING;
        conn->egress.send_ack_at = 0; /* send CONNECTION_CLOSE */
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
            /* check the packet */
            if (packet->token.len >= QUICLY_MAX_TOKEN_LEN) {
                ret = QUICLY_ERROR_PACKET_IGNORED;
                goto Exit;
            }
            ptls_iovec_t odcid = ptls_iovec_init(packet->octets.base + packet->encrypted_off,
                                                 packet->token.base - (packet->octets.base + packet->encrypted_off));
            if (!quicly_cid_is_equal(&conn->super.peer.cid, odcid)) {
                ret = QUICLY_ERROR_PACKET_IGNORED;
                goto Exit;
            }
            if (quicly_cid_is_equal(&conn->super.peer.cid, packet->cid.src)) {
                ret = QUICLY_ERROR_PACKET_IGNORED;
                goto Exit;
            }
            /* do not accept a second token (TODO allow 0-RTT token to be replaced) */
            if (conn->token.len != 0) {
                ret = QUICLY_ERROR_PACKET_IGNORED;
                goto Exit;
            }
            /* store token and ODCID */
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
            if ((ret = setup_initial_encryption(&conn->initial->cipher.ingress, &conn->initial->cipher.egress,
                                                conn->super.ctx->tls->cipher_suites,
                                                ptls_iovec_init(conn->super.peer.cid.cid, conn->super.peer.cid.len), 1)) != 0)
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
            aead = &conn->initial->cipher.ingress.aead;
            space = (void *)&conn->initial;
            epoch = 0;
            break;
        case QUICLY_PACKET_TYPE_HANDSHAKE:
            if (conn->handshake == NULL || (header_protection = conn->handshake->cipher.ingress.header_protection) == NULL) {
                ret = QUICLY_ERROR_PACKET_IGNORED;
                goto Exit;
            }
            aead = &conn->handshake->cipher.ingress.aead;
            space = (void *)&conn->handshake;
            epoch = 2;
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
            aead = &conn->application->cipher.ingress.aead[0];
            space = (void *)&conn->application;
            epoch = 1;
            break;
        default:
            ret = QUICLY_ERROR_PACKET_IGNORED;
            goto Exit;
        }
    } else {
        /* first 1-RTT keys is key_phase 1, see doc-comment of cipher.ingress */
        if (conn->application == NULL ||
            (header_protection = conn->application->cipher.ingress.header_protection.one_rtt) == NULL) {
            ret = QUICLY_ERROR_PACKET_IGNORED;
            goto Exit;
        }
        aead = conn->application->cipher.ingress.aead;
        space = (void *)&conn->application;
        epoch = 3;
    }

    if ((payload = decrypt_packet(header_protection, aead, &(*space)->next_expected_packet_number, packet, &pn)).base == NULL) {
        ret = QUICLY_ERROR_PACKET_IGNORED;
        goto Exit;
    }

    if (payload.len == 0) {
        ret = QUICLY_TRANSPORT_ERROR_PROTOCOL_VIOLATION;
        goto Exit;
    }

    LOG_CONNECTION_EVENT(conn, QUICLY_EVENT_TYPE_CRYPTO_DECRYPT, INT_EVENT_ATTR(PACKET_NUMBER, pn),
                         INT_EVENT_ATTR(LENGTH, payload.len));
    LOG_CONNECTION_EVENT(conn, QUICLY_EVENT_TYPE_QUICTRACE_RECV, INT_EVENT_ATTR(PACKET_NUMBER, pn),
                         INT_EVENT_ATTR(LENGTH, payload.len), INT_EVENT_ATTR(ENC_LEVEL, epoch));

    if (conn->super.state == QUICLY_STATE_FIRSTFLIGHT)
        conn->super.state = QUICLY_STATE_CONNECTED;

    ++conn->super.num_packets.received;
    if ((ret = handle_payload(conn, epoch, payload.base, payload.len, &offending_frame_type, &is_ack_only)) != 0)
        goto Exit;
    if (*space != NULL) {
        if ((ret = record_receipt(conn, *space, pn, is_ack_only, epoch)) != 0)
            goto Exit;
    }

    switch (epoch) {
    case QUICLY_EPOCH_INITIAL:
        assert(conn->initial != NULL);
        if (quicly_is_client(conn) && conn->handshake != NULL && conn->handshake->cipher.egress.aead != NULL) {
            if ((ret = discard_initial_context(conn)) != 0)
                goto Exit;
        }
        break;
    case QUICLY_EPOCH_HANDSHAKE:
        if (conn->initial != NULL && !quicly_is_client(conn)) {
            if ((ret = discard_initial_context(conn)) != 0)
                goto Exit;
            update_loss_alarm(conn);
        }
        /* schedule the timer to discard contexts related to the handshake if we have received all handshake messages and all the
         * messages we sent have been acked */
        if (!conn->crypto.handshake_scheduled_for_discard && ptls_handshake_is_complete(conn->crypto.tls)) {
            quicly_stream_t *stream = quicly_get_stream(conn, -(quicly_stream_id_t)(1 + 2));
            assert(stream != NULL);
            quicly_streambuf_t *buf = stream->data;
            if (buf->egress.buf.off == 0) {
                if ((ret = quicly_sentmap_prepare(&conn->egress.sentmap, conn->egress.packet_number, now,
                                                  QUICLY_EPOCH_HANDSHAKE)) != 0)
                    goto Exit;
                if (quicly_sentmap_allocate(&conn->egress.sentmap, discard_handshake_context) == NULL) {
                    ret = PTLS_ERROR_NO_MEMORY;
                    goto Exit;
                }
                quicly_sentmap_commit(&conn->egress.sentmap, 0);
                ++conn->egress.packet_number;
                conn->crypto.handshake_scheduled_for_discard = 1;
            }
        }
        break;
    default:
        break;
    }

Exit:
    switch (ret) {
    case 0:
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
        quicly_linklist_insert((uni ? &conn->pending_link.streams_blocked.uni : &conn->pending_link.streams_blocked.bidi)->prev,
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
    assert(!(quicly_stream_is_unidirectional(stream->stream_id) &&
             quicly_stream_is_client_initiated(stream->stream_id) != quicly_is_client(stream->conn)));
    assert(QUICLY_ERROR_IS_QUIC_APPLICATION(err));
    assert(stream->_send_aux.rst.sender_state == QUICLY_SENDER_STATE_NONE);
    assert(!quicly_sendstate_transfer_complete(&stream->sendstate));

    /* dispose sendbuf state */
    quicly_sendstate_dispose(&stream->sendstate);
    quicly_sendstate_init_closed(&stream->sendstate);

    /* setup RST_STREAM */
    stream->_send_aux.rst.sender_state = QUICLY_SENDER_STATE_SEND;
    stream->_send_aux.rst.error_code = QUICLY_ERROR_GET_ERROR_CODE(err);

    /* schedule for delivery */
    sched_stream_control(stream);
    resched_stream_data(stream);
}

void quicly_request_stop(quicly_stream_t *stream, int err)
{
    assert(!(quicly_stream_is_unidirectional(stream->stream_id) &&
             quicly_stream_is_client_initiated(stream->stream_id) == quicly_is_client(stream->conn)));
    assert(QUICLY_ERROR_IS_QUIC_APPLICATION(err));

    /* send STOP_SENDING if the incoming side of the stream is still open */
    if (stream->recvstate.eos == UINT64_MAX && stream->_send_aux.stop_sending.sender_state == QUICLY_SENDER_STATE_NONE) {
        stream->_send_aux.stop_sending.sender_state = QUICLY_SENDER_STATE_SEND;
        stream->_send_aux.stop_sending.error_code = QUICLY_ERROR_GET_ERROR_CODE(err);
        sched_stream_control(stream);
    }
}

static quicly_datagram_t *default_alloc_packet(quicly_packet_allocator_t *self, socklen_t salen, size_t payloadsize)
{
    quicly_datagram_t *packet;

    if ((packet = malloc(offsetof(quicly_datagram_t, sa) + salen + payloadsize)) == NULL)
        return NULL;
    packet->salen = salen;
    packet->data.base = (uint8_t *)packet + offsetof(quicly_datagram_t, sa) + salen;

    return packet;
}

static void default_free_packet(quicly_packet_allocator_t *self, quicly_datagram_t *packet)
{
    free(packet);
}

quicly_packet_allocator_t quicly_default_packet_allocator = {default_alloc_packet, default_free_packet};

struct st_quicly_default_encrypt_cid_t {
    quicly_cid_encryptor_t super;
    ptls_cipher_context_t *cid_encrypt_ctx, *cid_decrypt_ctx;
    ptls_hash_context_t *stateless_reset_token_ctx;
};

static int expand_cid_encryption_key(ptls_cipher_algorithm_t *cipher, ptls_hash_algorithm_t *hash, void *cid_key, ptls_iovec_t key)
{
    return ptls_hkdf_expand_label(hash, cid_key, cipher->key_size, key, "cid", ptls_iovec_init(NULL, 0), "");
}

static void default_encrypt_cid(quicly_cid_encryptor_t *_self, quicly_cid_t *encrypted, void *stateless_reset_token,
                                const quicly_cid_plaintext_t *plaintext)
{
    struct st_quicly_default_encrypt_cid_t *self = (void *)_self;
    uint8_t buf[16], *p;

    /* encode */
    p = buf;
    switch (self->cid_encrypt_ctx->algo->block_size) {
    case 8:
        break;
    case 16:
        p = quicly_encode64(p, plaintext->node_id);
        break;
    default:
        assert(!"unexpected block size");
        break;
    }
    p = quicly_encode32(p, plaintext->master_id);
    p = quicly_encode32(p, (plaintext->thread_id << 8) | plaintext->path_id);
    assert(p - buf == self->cid_encrypt_ctx->algo->block_size);

    /* generate CID */
    if (encrypted != NULL) {
        ptls_cipher_encrypt(self->cid_encrypt_ctx, encrypted->cid, buf, self->cid_encrypt_ctx->algo->block_size);
        encrypted->len = self->cid_encrypt_ctx->algo->block_size;
    }

    /* generate stateless reset token if requested */
    if (stateless_reset_token != NULL) {
        uint8_t md[PTLS_MAX_DIGEST_SIZE];
        self->stateless_reset_token_ctx->update(self->stateless_reset_token_ctx, buf, p - 1 - buf); /* exclude path_id */
        self->stateless_reset_token_ctx->final(self->stateless_reset_token_ctx, md, PTLS_HASH_FINAL_MODE_RESET);
        memcpy(stateless_reset_token, md, QUICLY_STATELESS_RESET_TOKEN_LEN);
    }
}

static size_t default_decrypt_cid(quicly_cid_encryptor_t *_self, quicly_cid_plaintext_t *plaintext, const void *encrypted,
                                  size_t len)
{
    struct st_quicly_default_encrypt_cid_t *self = (void *)_self;
    uint8_t buf[16];
    const uint8_t *p;
    size_t cid_len;

    cid_len = self->cid_decrypt_ctx->algo->block_size;

    /* decrypt */
    if (len != 0 && len != cid_len) {
        /* normalize the input, so that we would get consistent routing */
        if (len > cid_len)
            len = cid_len;
        memcpy(buf, encrypted, cid_len);
        if (len < cid_len)
            memset(buf + len, 0, cid_len - len);
        ptls_cipher_encrypt(self->cid_decrypt_ctx, buf, buf, cid_len);
    } else {
        ptls_cipher_encrypt(self->cid_decrypt_ctx, buf, encrypted, cid_len);
    }

    /* decode */
    p = buf;
    if (cid_len == 16) {
        plaintext->node_id = quicly_decode64(&p);
    } else {
        plaintext->node_id = 0;
    }
    plaintext->master_id = quicly_decode32(&p);
    plaintext->thread_id = quicly_decode24(&p);
    plaintext->path_id = *p++;
    assert(p - buf == cid_len);

    return cid_len;
}

quicly_cid_encryptor_t *quicly_new_default_cid_encryptor(ptls_cipher_algorithm_t *cipher, ptls_hash_algorithm_t *hash,
                                                         ptls_iovec_t key)
{
    uint8_t cid_keybuf[PTLS_MAX_SECRET_SIZE], reset_keybuf[PTLS_MAX_DIGEST_SIZE];
    ptls_cipher_context_t *cid_encrypt_ctx = NULL, *cid_decrypt_ctx = NULL;
    ptls_hash_context_t *stateless_reset_token_ctx = NULL;
    struct st_quicly_default_encrypt_cid_t *self = NULL;

    if (expand_cid_encryption_key(cipher, hash, cid_keybuf, key) != 0)
        goto Exit;
    if (ptls_hkdf_expand_label(hash, reset_keybuf, hash->digest_size, key, "reset", ptls_iovec_init(NULL, 0), "") != 0)
        goto Exit;
    if ((cid_encrypt_ctx = ptls_cipher_new(cipher, 1, cid_keybuf)) == NULL)
        goto Exit;
    if ((cid_decrypt_ctx = ptls_cipher_new(cipher, 0, cid_keybuf)) == NULL)
        goto Exit;
    if ((stateless_reset_token_ctx = ptls_hmac_create(hash, reset_keybuf, hash->digest_size)) == NULL)
        goto Exit;
    if ((self = malloc(sizeof(*self))) == NULL)
        goto Exit;

    *self = (struct st_quicly_default_encrypt_cid_t){
        {default_encrypt_cid, default_decrypt_cid}, cid_encrypt_ctx, cid_decrypt_ctx, stateless_reset_token_ctx};
    cid_encrypt_ctx = NULL;
    cid_decrypt_ctx = NULL;
    stateless_reset_token_ctx = NULL;

Exit:
    if (stateless_reset_token_ctx != NULL)
        stateless_reset_token_ctx->final(stateless_reset_token_ctx, NULL, PTLS_HASH_FINAL_MODE_FREE);
    if (cid_encrypt_ctx != NULL)
        ptls_cipher_free(cid_encrypt_ctx);
    if (cid_decrypt_ctx != NULL)
        ptls_cipher_free(cid_decrypt_ctx);
    ptls_clear_memory(cid_keybuf, sizeof(cid_keybuf));
    ptls_clear_memory(reset_keybuf, sizeof(reset_keybuf));
    return &self->super;
}

void quicly_free_default_cid_enncryptor(quicly_cid_encryptor_t *_self)
{
    struct st_quicly_default_encrypt_cid_t *self = (void *)_self;

    ptls_cipher_free(self->cid_encrypt_ctx);
    ptls_cipher_free(self->cid_decrypt_ctx);
    self->stateless_reset_token_ctx->final(self->stateless_reset_token_ctx, NULL, PTLS_HASH_FINAL_MODE_FREE);
    free(self);
}

quicly_stream_t *quicly_default_alloc_stream(quicly_context_t *ctx)
{
    return malloc(sizeof(quicly_stream_t));
}

void quicly_default_free_stream(quicly_stream_t *stream)
{
    free(stream);
}

static int64_t default_now(quicly_now_t *self)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (int64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

quicly_now_t quicly_default_now = {default_now};

struct st_quicly_default_event_log_t {
    quicly_event_logger_t super;
    FILE *fp;
};

static void tohex(char *dst, uint8_t v)
{
    dst[0] = "0123456789abcdef"[v >> 4];
    dst[1] = "0123456789abcdef"[v & 0xf];
}

static void default_event_log(quicly_event_logger_t *_self, quicly_event_type_t type, const quicly_event_attribute_t *attributes,
                              size_t num_attributes)
{
    struct st_quicly_default_event_log_t *self = (void *)_self;
    ptls_buffer_t buf;
    uint8_t smallbuf[256];
    size_t i, j;

    ptls_buffer_init(&buf, smallbuf, sizeof(smallbuf));

#define EMIT(s)                                                                                                                    \
    do {                                                                                                                           \
        const char *_s = (s);                                                                                                      \
        size_t _l = strlen(_s);                                                                                                    \
        if (ptls_buffer_reserve(&buf, _l) != 0)                                                                                    \
            goto Exit;                                                                                                             \
        memcpy(buf.base + buf.off, _s, _l);                                                                                        \
        buf.off += _l;                                                                                                             \
    } while (0)

    EMIT("{\"type\":\"");
    EMIT(quicly_event_type_names[type]);
    EMIT("\"");
    for (i = 0; i != num_attributes; ++i) {
        const quicly_event_attribute_t *attr = attributes + i;
        if (attr->type == QUICLY_EVENT_ATTRIBUTE_NULL)
            continue;
        EMIT(", \"");
        EMIT(quicly_event_attribute_names[attr->type]);
        if (QUICLY_EVENT_ATTRIBUTE_TYPE_INT_MIN <= attr->type && attr->type < QUICLY_EVENT_ATTRIBUTE_TYPE_INT_MAX) {
            char int64buf[sizeof("-9223372036854775808")];
            sprintf(int64buf, "\":%" PRId64, attr->value.i);
            EMIT(int64buf);
        } else if (QUICLY_EVENT_ATTRIBUTE_TYPE_VEC_MIN <= attr->type && attr->type < QUICLY_EVENT_ATTRIBUTE_TYPE_VEC_MAX) {
            EMIT("\":\"");
            if (ptls_buffer_reserve(&buf, attr->value.v.len * 2) != 0)
                goto Exit;
            for (j = 0; j != attr->value.v.len; ++j) {
                tohex((void *)(buf.base + buf.off), attr->value.v.base[j]);
                buf.off += 2;
            }
            EMIT("\"");
        } else {
            assert(!"unexpected type");
        }
    }
    EMIT("}\n");

#undef EMIT

    fwrite(buf.base, 1, buf.off, self->fp);

Exit:
    ptls_buffer_dispose(&buf);
}

quicly_event_logger_t *quicly_new_default_event_logger(FILE *fp)
{
    struct st_quicly_default_event_log_t *self;

    if ((self = malloc(sizeof(*self))) == NULL)
        return NULL;
    *self = (struct st_quicly_default_event_log_t){{default_event_log}, fp};
    return &self->super;
}

void quicly_free_default_event_logger(quicly_event_logger_t *_self)
{
    struct st_quicly_default_event_log_t *self = (void *)_self;
    free(self);
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
            tohex(p, bytes[i]);
            p += 2;
        }
    } else {
        for (line = 0; line * 16 < len; ++line) {
            for (i = 0; i < indent; ++i)
                *p++ = ' ';
            tohex(p, (line >> 4) & 0xff);
            p += 2;
            tohex(p, (line << 4) & 0xff);
            p += 2;
            *p++ = ' ';
            for (row = 0; row < 16; ++row) {
                *p++ = row == 8 ? '-' : ' ';
                if (line * 16 + row < len) {
                    tohex(p, bytes[line * 16 + row]);
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

/**
 * an array of event names corresponding to quicly_event_type_t
 */
const char *quicly_event_type_names[] = {"connect",
                                         "accept",
                                         "send",
                                         "send-stateless-reset",
                                         "receive",
                                         "free",
                                         "packet-prepare",
                                         "packet-commit",
                                         "packet-acked",
                                         "packet-lost",
                                         "crypto-decrypt",
                                         "crypto-handshake",
                                         "crypto-update-secret",
                                         "cc-tlp",
                                         "cc-rto",
                                         "cc-ack-received",
                                         "cc-congestion",
                                         "stream-send",
                                         "stream-receive",
                                         "stream-acked",
                                         "stream-lost",
                                         "quic-version-switch",
                                         "transport-close-send",
                                         "application-close-send",
                                         "transport-close-receive",
                                         "application-close-receive",
                                         "stateless-reset-receive",
                                         "quictrace-sent",
                                         "quictrace-recv",
                                         "quictrace-lost",
                                         "quictrace-send-stream",
                                         "quictrace-recv-stream",
                                         "quictrace-recv-ack"};

const char *quicly_event_attribute_names[] = {NULL,
                                              "time",
                                              "epoch",
                                              "packet-type",
                                              "pn",
                                              "packet-size",
                                              "conn",
                                              "tls-error",
                                              "off",
                                              "len",
                                              "stream-id",
                                              "fin",
                                              "is-enc",
                                              "encryptionLevel",
                                              "quic-version",
                                              "ack-only",
                                              "max-lost-pn",
                                              "end-of-recovery",
                                              "bytes-in-flight",
                                              "cwnd",
                                              "newly-acked",
                                              "first-octet",
                                              "cc-type",
                                              "cc-end-of-recovery",
                                              "cc-exit-recovery",
                                              "acked-packets",
                                              "acked-bytes",
                                              "state",
                                              "error-code",
                                              "frame-type",
                                              "ack-block-begin",
                                              "ack-block-end",
                                              "ack-delay",
                                              "dcid",
                                              "scid",
                                              "reason-phrase"};
