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
#ifndef quicly_h
#define quicly_h

#ifdef __cplusplus
extern "C" {
#endif

#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include "picotls.h"
#include "quicly/constants.h"
#include "quicly/frame.h"
#include "quicly/local_cid.h"
#include "quicly/linklist.h"
#include "quicly/loss.h"
#include "quicly/cc.h"
#include "quicly/recvstate.h"
#include "quicly/sendstate.h"
#include "quicly/maxsender.h"
#include "quicly/cid.h"
#include "quicly/remote_cid.h"

#ifndef QUICLY_DEBUG
#define QUICLY_DEBUG 0
#endif

/* invariants! */
#define QUICLY_LONG_HEADER_BIT 0x80
#define QUICLY_QUIC_BIT 0x40
#define QUICLY_KEY_PHASE_BIT 0x4
#define QUICLY_LONG_HEADER_RESERVED_BITS 0xc
#define QUICLY_SHORT_HEADER_RESERVED_BITS 0x18

#define QUICLY_PACKET_TYPE_INITIAL (QUICLY_LONG_HEADER_BIT | QUICLY_QUIC_BIT | 0)
#define QUICLY_PACKET_TYPE_0RTT (QUICLY_LONG_HEADER_BIT | QUICLY_QUIC_BIT | 0x10)
#define QUICLY_PACKET_TYPE_HANDSHAKE (QUICLY_LONG_HEADER_BIT | QUICLY_QUIC_BIT | 0x20)
#define QUICLY_PACKET_TYPE_RETRY (QUICLY_LONG_HEADER_BIT | QUICLY_QUIC_BIT | 0x30)
#define QUICLY_PACKET_TYPE_BITMASK 0xf0

#define QUICLY_PACKET_IS_LONG_HEADER(first_byte) (((first_byte)&QUICLY_LONG_HEADER_BIT) != 0)

#define QUICLY_PROTOCOL_VERSION 0xff00001d

#define QUICLY_PACKET_IS_INITIAL(first_byte) (((first_byte)&0xf0) == 0xc0)

#define QUICLY_STATELESS_RESET_PACKET_MIN_LEN 39

#define QUICLY_MAX_PN_SIZE 4  /* maximum defined by the RFC used for calculating header protection sampling offset */
#define QUICLY_SEND_PN_SIZE 2 /* size of PN used for sending */

#define QUICLY_AEAD_BASE_LABEL "tls13 quic "

typedef union st_quicly_address_t {
    struct sockaddr sa;
    struct sockaddr_in sin;
    struct sockaddr_in6 sin6;
} quicly_address_t;

typedef struct st_quicly_context_t quicly_context_t;
typedef struct st_quicly_stream_t quicly_stream_t;
typedef struct st_quicly_send_context_t quicly_send_context_t;
typedef struct st_quicly_address_token_plaintext_t quicly_address_token_plaintext_t;

#define QUICLY_CALLBACK_TYPE0(ret, name)                                                                                           \
    typedef struct st_quicly_##name##_t {                                                                                          \
        ret (*cb)(struct st_quicly_##name##_t * self);                                                                             \
    } quicly_##name##_t

#define QUICLY_CALLBACK_TYPE(ret, name, ...)                                                                                       \
    typedef struct st_quicly_##name##_t {                                                                                          \
        ret (*cb)(struct st_quicly_##name##_t * self, __VA_ARGS__);                                                                \
    } quicly_##name##_t

/**
 * stream scheduler
 */
typedef struct st_quicly_stream_scheduler_t {
    /**
     * returns if there's any data to send.
     * @param conn_is_flow_capped if the connection-level flow control window is currently saturated
     */
    int (*can_send)(struct st_quicly_stream_scheduler_t *sched, quicly_conn_t *conn, int conn_is_saturated);
    /**
     * Called by quicly to emit stream data.  The scheduler should repeatedly choose a stream and call `quicly_send_stream` until
     * `quicly_can_send_stream` returns false.
     */
    int (*do_send)(struct st_quicly_stream_scheduler_t *sched, quicly_conn_t *conn, quicly_send_context_t *s);
    /**
     *
     */
    int (*update_state)(struct st_quicly_stream_scheduler_t *sched, quicly_stream_t *stream);
} quicly_stream_scheduler_t;

/**
 * called when stream is being open. Application is expected to create it's corresponding state and tie it to stream->data.
 */
QUICLY_CALLBACK_TYPE(int, stream_open, quicly_stream_t *stream);
/**
 * called when the connection is closed by remote peer
 */
QUICLY_CALLBACK_TYPE(void, closed_by_remote, quicly_conn_t *conn, int err, uint64_t frame_type, const char *reason,
                     size_t reason_len);
/**
 * returns current time in milliseconds
 */
QUICLY_CALLBACK_TYPE0(int64_t, now);
/**
 * called when a NEW_TOKEN token is received on a connection
 */
QUICLY_CALLBACK_TYPE(int, save_resumption_token, quicly_conn_t *conn, ptls_iovec_t token);
/**
 *
 */
QUICLY_CALLBACK_TYPE(int, generate_resumption_token, quicly_conn_t *conn, ptls_buffer_t *buf,
                     quicly_address_token_plaintext_t *token);
/**
 * crypto offload API
 */
typedef struct st_quicly_crypto_engine_t {
    /**
     * Callback used for setting up the header protection keys / packet protection keys. The callback MUST initialize or replace
     * `header_protect_ctx` and `packet_protect_ctx` as specified by QUIC-TLS. This callback might be called more than once for
     * 1-RTT epoch, when the key is updated. In such case, there is no need to update the header protection context, and therefore
     * `header_protect_ctx` will be NULL.
     *
     * @param header_protect_ctx  address of where the header protection context should be written. Might be NULL when called to
     *                            handle 1-RTT Key Update.
     * @param packet_protect_ctx  address of where the packet protection context should be written.
     * @param secret              the secret from which the protection keys is derived. The length of the secret is
                                  `hash->digest_size`.
     * @note At the moment, the callback is not invoked for Initial keys when running as server.
     */
    int (*setup_cipher)(struct st_quicly_crypto_engine_t *engine, quicly_conn_t *conn, size_t epoch, int is_enc,
                        ptls_cipher_context_t **header_protect_ctx, ptls_aead_context_t **packet_protect_ctx,
                        ptls_aead_algorithm_t *aead, ptls_hash_algorithm_t *hash, const void *secret);
    /**
     * Callback used for encrypting the send packet. The engine must AEAD-encrypt the payload using `packet_protect_ctx` and apply
     * header protection using `header_protect_ctx`. Quicly does not read or write the content of the UDP datagram payload after
     * this function is called. Therefore, an engine might retain the information provided by this function, and protect the packet
     * and the header at a later moment (e.g., hardware crypto offload).
     */
    void (*encrypt_packet)(struct st_quicly_crypto_engine_t *engine, quicly_conn_t *conn, ptls_cipher_context_t *header_protect_ctx,
                           ptls_aead_context_t *packet_protect_ctx, ptls_iovec_t datagram, size_t first_byte_at,
                           size_t payload_from, uint64_t packet_number, int coalesced);
} quicly_crypto_engine_t;

typedef struct st_quicly_max_stream_data_t {
    uint64_t bidi_local, bidi_remote, uni;
} quicly_max_stream_data_t;

/**
 * Transport Parameters; the struct contains "configuration parameters", ODCID is managed separately
 */
typedef struct st_quicly_transport_parameters_t {
    /**
     * in octets
     */
    quicly_max_stream_data_t max_stream_data;
    /**
     * in octets
     */
    uint64_t max_data;
    /**
     * in milliseconds
     */
    uint64_t max_idle_timeout;
    /**
     *
     */
    uint64_t max_streams_bidi;
    /**
     *
     */
    uint64_t max_streams_uni;
    /**
     *
     */
    uint64_t max_udp_payload_size;
    /**
     * quicly ignores the value set for quicly_context_t::transport_parameters
     */
    uint8_t ack_delay_exponent;
    /**
     * in milliseconds; quicly ignores the value set for quicly_context_t::transport_parameters
     */
    uint16_t max_ack_delay;
    /**
     * quicly ignores the value set for quicly_context_t::transport_parameters. Set to UINT64_MAX when not specified by remote peer.
     */
    uint64_t min_ack_delay_usec;
    /**
     *
     */
    uint8_t disable_active_migration : 1;
    /**
     *
     */
    uint64_t active_connection_id_limit;
} quicly_transport_parameters_t;

struct st_quicly_context_t {
    /**
     * tls context to use
     */
    ptls_context_t *tls;
    /**
     * Maximum size of packets that we are willing to send when path-specific information is unavailable. As a path-specific
     * * optimization, quicly acting as a server expands this value to `min(local.tp.max_udp_payload_size,
     * * remote.tp.max_udp_payload_size, max_size_of_incoming_datagrams)` when it receives the Transport Parameters from the client.
     */
    uint16_t initial_egress_max_udp_payload_size;
    /**
     * loss detection parameters
     */
    quicly_loss_conf_t loss;
    /**
     * transport parameters
     */
    quicly_transport_parameters_t transport_params;
    /**
     * number of packets that can be sent without a key update
     */
    uint64_t max_packets_per_key;
    /**
     * maximum number of bytes that can be transmitted on a CRYPTO stream (per each epoch)
     */
    uint64_t max_crypto_bytes;
    /**
     * client-only
     */
    unsigned enforce_version_negotiation : 1;
    /**
     * if inter-node routing is used (by utilising quicly_cid_plaintext_t::node_id)
     */
    unsigned is_clustered : 1;
    /**
     * expand client hello so that it does not fit into one datagram
     */
    unsigned expand_client_hello : 1;
    /**
     *
     */
    quicly_cid_encryptor_t *cid_encryptor;
    /**
     * callback called when a new stream is opened by remote peer
     */
    quicly_stream_open_t *stream_open;
    /**
     * callbacks for scheduling stream data
     */
    quicly_stream_scheduler_t *stream_scheduler;
    /**
     * callback called when a connection is closed by remote peer
     */
    quicly_closed_by_remote_t *closed_by_remote;
    /**
     * returns current time in milliseconds
     */
    quicly_now_t *now;
    /**
     * called wen a NEW_TOKEN token is being received
     */
    quicly_save_resumption_token_t *save_resumption_token;
    /**
     *
     */
    quicly_generate_resumption_token_t *generate_resumption_token;
    /**
     * crypto engine (offload API)
     */
    quicly_crypto_engine_t *crypto_engine;
};

/**
 * connection state
 */
typedef enum {
    /**
     * before observing the first message from remote peer
     */
    QUICLY_STATE_FIRSTFLIGHT,
    /**
     * while connected
     */
    QUICLY_STATE_CONNECTED,
    /**
     * sending close, but haven't seen the remote peer sending close
     */
    QUICLY_STATE_CLOSING,
    /**
     * we do not send CLOSE (at the moment), enter draining mode when receiving CLOSE
     */
    QUICLY_STATE_DRAINING
} quicly_state_t;

struct st_quicly_conn_streamgroup_state_t {
    uint32_t num_streams;
    quicly_stream_id_t next_stream_id;
};

/**
 * Values that do not need to be gathered upon the invocation of `quicly_get_stats`. We use typedef to define the same fields in
 * the same order for quicly_stats_t and `struct st_quicly_conn_public_t::stats`.
 */
#define QUICLY_STATS_PREBUILT_FIELDS                                                                                               \
    struct {                                                                                                                       \
        /**                                                                                                                        \
         * Total number of packets received.                                                                                       \
         */                                                                                                                        \
        uint64_t received;                                                                                                         \
        /**                                                                                                                        \
         * Total number of packets that failed decryption.                                                                         \
         */                                                                                                                        \
        uint64_t decryption_failed;                                                                                                \
        /**                                                                                                                        \
         * Total number of packets sent.                                                                                           \
         */                                                                                                                        \
        uint64_t sent;                                                                                                             \
        /**                                                                                                                        \
         * Total number of packets marked lost.                                                                                    \
         */                                                                                                                        \
        uint64_t lost;                                                                                                             \
        /**                                                                                                                        \
         * Total number of packets marked lost via time-threshold loss detection.                                                  \
         */                                                                                                                        \
        uint64_t lost_time_threshold;                                                                                              \
        /**                                                                                                                        \
         * Total number of packets for which acknowledgements have been received.                                                  \
         */                                                                                                                        \
        uint64_t ack_received;                                                                                                     \
        /**                                                                                                                        \
         * Total number of packets for which acknowledgements were received after being marked lost.                               \
         */                                                                                                                        \
        uint64_t late_acked;                                                                                                       \
    } num_packets;                                                                                                                 \
    struct {                                                                                                                       \
        /**                                                                                                                        \
         * Total bytes received, at UDP datagram-level. Used for determining the amplification limit.                              \
         */                                                                                                                        \
        uint64_t received;                                                                                                         \
        /**                                                                                                                        \
         * Total bytes sent, at UDP datagram-level.                                                                                \
         */                                                                                                                        \
        uint64_t sent;                                                                                                             \
    } num_bytes;                                                                                                                   \
    /**                                                                                                                            \
     * Total number of PTOs during the connections.                                                                                \
     */                                                                                                                            \
    uint32_t num_ptos

typedef struct st_quicly_stats_t {
    /**
     * The pre-built fields. This MUST be the first member of `quicly_stats_t` so that we can use `memcpy`.
     */
    QUICLY_STATS_PREBUILT_FIELDS;
    /**
     * RTT stats.
     */
    quicly_rtt_t rtt;
    /**
     * Congestion control stats (experimental; TODO cherry-pick what can be exposed as part of a stable API).
     */
    quicly_cc_t cc;
} quicly_stats_t;

/**
 * The state of the default stream scheduler.
 * `active` is a linked-list of streams for which STREAM frames can be emitted.  `blocked` is a linked-list of streams that have
 * something to be sent but are currently blocked by the connection-level flow control.
 * When the `can_send` callback of the default stream scheduler is invoked with the `conn_is_saturated` flag set, connections that
 * are blocked are eventually moved to the `blocked` list. When the callback is invoked without the flag being set, all the
 * connections in the `blocked` list is moved to the `active` list and the `in_saturated_mode` is cleared.
 */
struct st_quicly_default_scheduler_state_t {
    quicly_linklist_t active;
    quicly_linklist_t blocked;
};

struct _st_quicly_conn_public_t {
    quicly_context_t *ctx;
    quicly_state_t state;
    struct {
        /**
         * connection IDs being issued to the remote peer.
         * `quicly_conn_public_t::local.cid_set.plaintext.master_id has to be located right after `ctx` and `state`, as probes rely
         * on that assumption.
         */
        quicly_local_cid_set_t cid_set;
        /**
         * the local address (may be AF_UNSPEC)
         */
        quicly_address_t address;
        /**
         * the SCID used in long header packets. Equiavalent to local_cid[seq=0]. Retaining the value separately is the easiest way
         * of staying away from the complexity caused by remote peer sending RCID frames before the handshake concludes.
         */
        quicly_cid_t long_header_src_cid;
        /**
         * stream-level limits
         */
        struct st_quicly_conn_streamgroup_state_t bidi, uni;
    } local;
    struct {
        /**
         * CIDs received from the remote peer
         */
        quicly_remote_cid_set_t cid_set;
        /**
         * the remote address (cannot be AF_UNSPEC)
         */
        quicly_address_t address;
        struct st_quicly_conn_streamgroup_state_t bidi, uni;
        quicly_transport_parameters_t transport_params;
        struct {
            unsigned validated : 1;
            unsigned send_probe : 1;
        } address_validation;
        /**
         * largest value of Retire Prior To field observed so far
         */
        uint64_t largest_retire_prior_to;
    } remote;
    /**
     * Retains the original DCID used by the client. Servers use this to route packets incoming packets. Clients use this when
     * validating the Transport Parameters sent by the server.
     */
    quicly_cid_t original_dcid;
    struct st_quicly_default_scheduler_state_t _default_scheduler;
    struct {
        QUICLY_STATS_PREBUILT_FIELDS;
    } stats;
    uint32_t version;
    void *data;
};

typedef enum {
    /**
     * initial state
     */
    QUICLY_SENDER_STATE_NONE,
    /**
     * to be sent. Changes to UNACKED when sent out by quicly_send
     */
    QUICLY_SENDER_STATE_SEND,
    /**
     * inflight. changes to SEND (when packet is deemed lost), or ACKED (when packet is ACKed)
     */
    QUICLY_SENDER_STATE_UNACKED,
    /**
     * the sent value acknowledged by remote peer
     */
    QUICLY_SENDER_STATE_ACKED,
} quicly_sender_state_t;

/**
 * API that allows applications to specify it's own send / receive buffer.  The callback should be assigned by the
 * `quicly_context_t::on_stream_open` callback.
 */
typedef struct st_quicly_stream_callbacks_t {
    /**
     * called when the stream is destroyed
     */
    void (*on_destroy)(quicly_stream_t *stream, int err);
    /**
     * called whenever data can be retired from the send buffer, specifying the amount that can be newly removed
     */
    void (*on_send_shift)(quicly_stream_t *stream, size_t delta);
    /**
     * asks the application to fill the frame payload.  `off` is the offset within the buffer (the beginning position of the buffer
     * changes as `on_send_shift` is invoked). `len` is an in/out argument that specifies the size of the buffer / amount of data
     * being written.  `wrote_all` is a boolean out parameter indicating if the application has written all the available data.
     * As this callback is triggered by calling quicly_stream_sync_sendbuf (stream, 1) when tx data is present, it assumes data
     * to be available - that is `len` return value should be non-zero.
     */
    void (*on_send_emit)(quicly_stream_t *stream, size_t off, void *dst, size_t *len, int *wrote_all);
    /**
     * called when a STOP_SENDING frame is received.  Do not call `quicly_reset_stream` in response.  The stream will be
     * automatically reset by quicly.
     */
    void (*on_send_stop)(quicly_stream_t *stream, int err);
    /**
     * called when data is newly received.  `off` is the offset within the buffer (the beginning position changes as the application
     * calls `quicly_stream_sync_recvbuf`.  Applications should consult `quicly_stream_t::recvstate` to see if it has contiguous
     * input.
     */
    void (*on_receive)(quicly_stream_t *stream, size_t off, const void *src, size_t len);
    /**
     * called when a RESET_STREAM frame is received
     */
    void (*on_receive_reset)(quicly_stream_t *stream, int err);
} quicly_stream_callbacks_t;

struct st_quicly_stream_t {
    /**
     *
     */
    quicly_conn_t *conn;
    /**
     * stream id
     */
    quicly_stream_id_t stream_id;
    /**
     *
     */
    const quicly_stream_callbacks_t *callbacks;
    /**
     * send buffer
     */
    quicly_sendstate_t sendstate;
    /**
     * receive buffer
     */
    quicly_recvstate_t recvstate;
    /**
     *
     */
    void *data;
    /**
     *
     */
    unsigned streams_blocked : 1;
    /**
     *
     */
    struct {
        /**
         * send window
         */
        uint64_t max_stream_data;
        /**
         *
         */
        struct {
            quicly_sender_state_t sender_state;
            uint16_t error_code;
        } stop_sending;
        /**
         * reset_stream
         */
        struct {
            /**
             * STATE_NONE until RST is generated
             */
            quicly_sender_state_t sender_state;
            uint16_t error_code;
        } reset_stream;
        /**
         * sends receive window updates to remote peer
         */
        quicly_maxsender_t max_stream_data_sender;
        /**
         * linklist of pending streams
         */
        struct {
            quicly_linklist_t control; /* links to conn_t::control (or to conn_t::streams_blocked if the blocked flag is set) */
            quicly_linklist_t default_scheduler;
        } pending_link;
    } _send_aux;
    /**
     *
     */
    struct {
        /**
         * size of the receive window
         */
        uint32_t window;
        /**
         * Maximum number of ranges (i.e. gaps + 1) permitted in `recvstate.ranges`.
         * As discussed in https://github.com/h2o/quicly/issues/278, this value should be propotional to the size of the receive
         * window, so that the receive window can be maintained even in the worst case, where every one of the two packets being
         * sent are received.
         */
        uint32_t max_ranges;
    } _recv_aux;
};

typedef struct st_quicly_decoded_packet_t {
    /**
     * octets of the entire packet
     */
    ptls_iovec_t octets;
    /**
     * Connection ID(s)
     */
    struct {
        /**
         * destination CID
         */
        struct {
            /**
             * CID visible on wire
             */
            ptls_iovec_t encrypted;
            /**
             * the decrypted CID; note that the value is not authenticated
             */
            quicly_cid_plaintext_t plaintext;
            /**
             *
             */
            unsigned might_be_client_generated : 1;
        } dest;
        /**
         * source CID; {NULL, 0} if is a short header packet
         */
        ptls_iovec_t src;
    } cid;
    /**
     * version; 0 if is a short header packet
     */
    uint32_t version;
    /**
     * token if available; otherwise {NULL, 0}
     */
    ptls_iovec_t token;
    /**
     * starting offset of data (i.e., version-dependent area of a long header packet (version numbers in case of VN), AEAD tag (in
     * case of retry), encrypted PN (if decrypted.pn is UINT64_MAX) or data (if decrypted_pn is not UINT64_MAX))
     */
    size_t encrypted_off;
    /**
     * size of the UDP datagram; set to zero if this is not the first QUIC packet within the datagram
     */
    size_t datagram_size;
    /**
     * when decrypted.pn is not UINT64_MAX, indicates that the packet has been decrypted prior to being passed to `quicly_receive`.
     */
    struct {
        uint64_t pn;
        uint64_t key_phase;
    } decrypted;
    /**
     *
     */
    enum {
        QUICLY__DECODED_PACKET_CACHED_MAYBE_STATELESS_RESET = 0,
        QUICLY__DECODED_PACKET_CACHED_IS_STATELESS_RESET,
        QUICLY__DECODED_PACKET_CACHED_NOT_STATELESS_RESET
    } _is_stateless_reset_cached;
} quicly_decoded_packet_t;

struct st_quicly_address_token_plaintext_t {
    enum { QUICLY_ADDRESS_TOKEN_TYPE_RETRY, QUICLY_ADDRESS_TOKEN_TYPE_RESUMPTION } type;
    uint64_t issued_at;
    quicly_address_t local, remote;
    union {
        struct {
            quicly_cid_t original_dcid;
            quicly_cid_t client_cid;
            quicly_cid_t server_cid;
        } retry;
        struct {
            uint8_t bytes[256];
            size_t len;
        } resumption;
    };
    struct {
        uint8_t bytes[256];
        size_t len;
    } appdata;
};

/**
 * Extracts QUIC packets from a datagram pointed to by `src` and `len`. If successful, the function returns the size of the QUIC
 * packet being decoded. Otherwise, SIZE_MAX is returned.
 * `off` is an I/O argument that takes starting offset of the QUIC packet to be decoded as input, and returns the starting offset of
 * the next QUIC packet. A typical loop that handles an UDP datagram would look like:
 *
 *     size_t off = 0;
 *     while (off < dgram.size) {
 *         if (quicly_decode_packet(ctx, &packet, dgram.bytes, dgram.size, &off) == SIZE_MAX)
 *             break;
 *         handle_quic_packet(&packet);
 *     }
 */
size_t quicly_decode_packet(quicly_context_t *ctx, quicly_decoded_packet_t *packet, const uint8_t *datagram, size_t datagram_size,
                            size_t *off);
/**
 *
 */
uint64_t quicly_determine_packet_number(uint32_t truncated, size_t num_bits, uint64_t expected);
/**
 *
 */
static quicly_context_t *quicly_get_context(quicly_conn_t *conn);
/**
 *
 */
static const quicly_cid_plaintext_t *quicly_get_master_id(quicly_conn_t *conn);
/**
 *
 */
static const quicly_cid_t *quicly_get_original_dcid(quicly_conn_t *conn);
/**
 *
 */
static const quicly_cid_t *quicly_get_remote_cid(quicly_conn_t *conn);
/**
 *
 */
static const quicly_transport_parameters_t *quicly_get_remote_transport_parameters(quicly_conn_t *conn);
/**
 *
 */
static quicly_state_t quicly_get_state(quicly_conn_t *conn);
/**
 *
 */
int quicly_connection_is_ready(quicly_conn_t *conn);
/**
 *
 */
static uint32_t quicly_num_streams(quicly_conn_t *conn);
/**
 *
 */
static int quicly_is_client(quicly_conn_t *conn);
/**
 *
 */
static quicly_stream_id_t quicly_get_local_next_stream_id(quicly_conn_t *conn, int uni);
/**
 *
 */
static quicly_stream_id_t quicly_get_remote_next_stream_id(quicly_conn_t *conn, int uni);
/**
 * Returns the local address of the connection. This may be AF_UNSPEC, indicating that the operating system is choosing the address.
 */
static struct sockaddr *quicly_get_sockname(quicly_conn_t *conn);
/**
 * Returns the remote address of the connection. This would never be AF_UNSPEC.
 */
static struct sockaddr *quicly_get_peername(quicly_conn_t *conn);
/**
 *
 */
int quicly_get_stats(quicly_conn_t *conn, quicly_stats_t *stats);
/**
 *
 */
void quicly_get_max_data(quicly_conn_t *conn, uint64_t *send_permitted, uint64_t *sent, uint64_t *consumed);
/**
 *
 */
static void **quicly_get_data(quicly_conn_t *conn);
/**
 * destroys a connection object.
 */
void quicly_free(quicly_conn_t *conn);
/**
 * closes the connection.  `err` is the application error code using the coalesced scheme (see QUICLY_ERROR_* macros), or zero (no
 * error; indicating idle close).  An application should continue calling quicly_recieve and quicly_send, until they return
 * QUICLY_ERROR_FREE_CONNECTION.  At this point, it is should call quicly_free.
 */
int quicly_close(quicly_conn_t *conn, int err, const char *reason_phrase);
/**
 *
 */
int64_t quicly_get_first_timeout(quicly_conn_t *conn);
/**
 *
 */
uint64_t quicly_get_next_expected_packet_number(quicly_conn_t *conn);
/**
 * returns if the connection is currently capped by connection-level flow control.
 */
int quicly_is_flow_capped(quicly_conn_t *conn);
/**
 * checks if quicly_send_stream can be invoked
 * @return a boolean indicating if quicly_send_stream can be called immediately
 */
int quicly_can_send_stream_data(quicly_conn_t *conn, quicly_send_context_t *s);
/**
 * Sends data of given stream.  Called by stream scheduler.  Only streams that can send some data or EOS should be specified.  It is
 * the responsibilty of the stream scheduler to maintain a list of such streams.
 */
int quicly_send_stream(quicly_stream_t *stream, quicly_send_context_t *s);
/**
 *
 */
size_t quicly_send_version_negotiation(quicly_context_t *ctx, struct sockaddr *dest_addr, ptls_iovec_t dest_cid,
                                       struct sockaddr *src_addr, ptls_iovec_t src_cid, void *payload);
/**
 *
 */
int quicly_retry_calc_cidpair_hash(ptls_hash_algorithm_t *sha256, ptls_iovec_t client_cid, ptls_iovec_t server_cid,
                                   uint64_t *value);
/**
 * Builds a UDP datagram containing a Retry packet.
 * @param retry_aead_cache  pointer to `ptls_aead_context_t *` that the function can store a AEAD context for future reuse. The
 *                          cache cannot be shared between multiple threads. Can be set to NULL when caching is unnecessary.
 * @param payload           buffer used for building the packet
 * @return size of the UDP datagram payload being built, or otherwise SIZE_MAX to indicate failure
 */
size_t quicly_send_retry(quicly_context_t *ctx, ptls_aead_context_t *token_encrypt_ctx, struct sockaddr *dest_addr,
                         ptls_iovec_t dest_cid, struct sockaddr *src_addr, ptls_iovec_t src_cid, ptls_iovec_t odcid,
                         ptls_iovec_t token_prefix, ptls_iovec_t appdata, ptls_aead_context_t **retry_aead_cache, uint8_t *payload);
/**
 * Builds UDP datagrams to be sent for given connection.
 * @param [out] dest              destination address
 * @param [out] src               source address
 * @param [out] datagrams         vector of iovecs pointing to the payloads of UDP datagrams. Each iovec represens a single UDP
 *                                datagram.
 * @param [in,out] num_datagrams  Upon entry, the application provides the number of entries that the `packets` vector can contain.
 *                                Upon return, contains the number of packet vectors emitted by `quicly_send`.
 * @param buf                     buffer used for building UDP datagrams. It is guaranteed that the first datagram would be built
 *                                from the address provided by `buf`, and that succeeding packets (if any) will be contiguously laid
 *                                out. This constraint reduces the number of vectors that need to be passed to the kernel when using
 *                                GSO.
 * @return 0 if successful, otherwise an error. When an error is returned, the caller must call `quicly_close` to discard the
 *         connection context.
 */
int quicly_send(quicly_conn_t *conn, quicly_address_t *dest, quicly_address_t *src, struct iovec *datagrams, size_t *num_datagrams,
                void *buf, size_t bufsize);
/**
 *
 */
size_t quicly_send_close_invalid_token(quicly_context_t *ctx, struct sockaddr *dest_addr, ptls_iovec_t dest_cid,
                                       struct sockaddr *src_addr, ptls_iovec_t src_cid, const char *err_desc, void *payload);
/**
 *
 */
size_t quicly_send_stateless_reset(quicly_context_t *ctx, struct sockaddr *dest_addr, struct sockaddr *src_addr,
                                   const void *src_cid, void *payload);
/**
 *
 */
int quicly_send_resumption_token(quicly_conn_t *conn);
/**
 *
 */
int quicly_receive(quicly_conn_t *conn, struct sockaddr *dest_addr, struct sockaddr *src_addr, quicly_decoded_packet_t *packet);
/**
 * consults if the incoming packet identified by (dest_addr, src_addr, decoded) belongs to the given connection
 */
int quicly_is_destination(quicly_conn_t *conn, struct sockaddr *dest_addr, struct sockaddr *src_addr,
                          quicly_decoded_packet_t *decoded);
/**
 *
 */
int quicly_encode_transport_parameter_list(ptls_buffer_t *buf, const quicly_transport_parameters_t *params,
                                           const quicly_cid_t *original_dcid, const quicly_cid_t *initial_scid,
                                           const quicly_cid_t *retry_scid, const void *stateless_reset_token, size_t expand_by);
/**
 * Decodes the Transport Parameters.
 * For the four optional output parameters (`original_dcid`, `initial_scid`, `retry_scid`, `stateless_reset_token`), this function
 * returns an error if NULL were supplied as the arguments and the corresponding Transport Parameters were received.
 * If corresponding Transport Parameters were not found for any of the non-null connection ID slots, an error is returned.
 * Stateless reset is an optional feature of QUIC, and therefore no error is returned when the vector for storing the token is
 * provided and the corresponding Transport Parameter is missing. In that case, the provided vector remains unmodified. The caller
 * pre-fills the vector with an unpredictable value (i.e. random), then calls this function to set the stateless reset token to the
 * value supplied by peer.
 */
int quicly_decode_transport_parameter_list(quicly_transport_parameters_t *params, quicly_cid_t *original_dcid,
                                           quicly_cid_t *initial_scid, quicly_cid_t *retry_scid, void *stateless_reset_token,
                                           const uint8_t *src, const uint8_t *end);
/**
 * Initiates a new connection.
 * @param new_cid the CID to be used for the connection. path_id is ignored.
 */
int quicly_connect(quicly_conn_t **conn, quicly_context_t *ctx, const char *server_name, struct sockaddr *dest_addr,
                   struct sockaddr *src_addr, const quicly_cid_plaintext_t *new_cid, ptls_iovec_t address_token,
                   ptls_handshake_properties_t *handshake_properties,
                   const quicly_transport_parameters_t *resumed_transport_params);
/**
 * accepts a new connection
 * @param new_cid        The CID to be used for the connection. When an error is being returned, the application can reuse the CID
 *                       provided to the function.
 * @param address_token  An validated address validation token, if any.  Applications MUST validate the address validation token
 *                       before calling this function, dropping the ones that failed to validate.  When a token is supplied,
 *                       `quicly_accept` will consult the values being supplied assuming that the remote peer's address has been
 * validated.
 */
int quicly_accept(quicly_conn_t **conn, quicly_context_t *ctx, struct sockaddr *dest_addr, struct sockaddr *src_addr,
                  quicly_decoded_packet_t *packet, quicly_address_token_plaintext_t *address_token,
                  const quicly_cid_plaintext_t *new_cid, ptls_handshake_properties_t *handshake_properties);
/**
 *
 */
ptls_t *quicly_get_tls(quicly_conn_t *conn);
/**
 *
 */
quicly_stream_id_t quicly_get_ingress_max_streams(quicly_conn_t *conn, int uni);
/**
 *
 */
quicly_stream_t *quicly_get_stream(quicly_conn_t *conn, quicly_stream_id_t stream_id);
/**
 *
 */
int quicly_open_stream(quicly_conn_t *conn, quicly_stream_t **stream, int unidirectional);
/**
 *
 */
void quicly_reset_stream(quicly_stream_t *stream, int err);
/**
 *
 */
void quicly_request_stop(quicly_stream_t *stream, int err);
/**
 *
 */
static int quicly_stop_requested(quicly_stream_t *stream);
/**
 *
 */
int quicly_stream_sync_sendbuf(quicly_stream_t *stream, int activate);
/**
 *
 */
void quicly_stream_sync_recvbuf(quicly_stream_t *stream, size_t shift_amount);
/**
 *
 */
static int quicly_stream_is_client_initiated(quicly_stream_id_t stream_id);
/**
 *
 */
static int quicly_stream_is_unidirectional(quicly_stream_id_t stream_id);
/**
 *
 */
static int quicly_stream_has_send_side(int is_client, quicly_stream_id_t stream_id);
/**
 *
 */
static int quicly_stream_has_receive_side(int is_client, quicly_stream_id_t stream_id);
/**
 *
 */
static int quicly_stream_is_self_initiated(quicly_stream_t *stream);
/**
 *
 */
void quicly_amend_ptls_context(ptls_context_t *ptls);
/**
 * Encrypts an address token by serializing the plaintext structure and appending an authentication tag.
 *
 * @param random_bytes  PRNG
 * @param aead          the AEAD context to be used for decrypting the token
 * @param buf           buffer to where the token being built is appended
 * @param start_off     Specifies the start offset of the token. When `start_off < buf->off`, the bytes in between will be
 *                      considered as part of the token and will be covered by the AEAD. Applications can use this location to embed
 *                      the identifier of the AEAD key being used.
 * @param plaintext     the token to be encrypted
 */
int quicly_encrypt_address_token(void (*random_bytes)(void *, size_t), ptls_aead_context_t *aead, ptls_buffer_t *buf,
                                 size_t start_off, const quicly_address_token_plaintext_t *plaintext);
/**
 * Decrypts an address token.
 * If decryption succeeds, returns zero. If the token is unusable due to decryption failure, returns PTLS_DECODE_ERROR. If the token
 * is unusable and the connection should be reset, returns QUICLY_ERROR_INVALID_TOKEN.
 */
int quicly_decrypt_address_token(ptls_aead_context_t *aead, quicly_address_token_plaintext_t *plaintext, const void *src,
                                 size_t len, size_t prefix_len, const char **err_desc);
/**
 * Builds authentication data for TLS session ticket. 0-RTT can be accepted only when the auth_data of the original connection and
 * the new connection are identical.
 */
int quicly_build_session_ticket_auth_data(ptls_buffer_t *auth_data, const quicly_context_t *ctx);
/**
 *
 */
static void quicly_byte_to_hex(char *dst, uint8_t v);
/**
 *
 */
socklen_t quicly_get_socklen(struct sockaddr *sa);
/**
 * Builds a safe string. Supplied buffer MUST be 4x + 1 bytes bigger than the input.
 */
char *quicly_escape_unsafe_string(char *dst, const void *bytes, size_t len);
/**
 *
 */
char *quicly_hexdump(const uint8_t *bytes, size_t len, size_t indent);
/**
 *
 */
void quicly_stream_noop_on_destroy(quicly_stream_t *stream, int err);
/**
 *
 */
void quicly_stream_noop_on_send_shift(quicly_stream_t *stream, size_t delta);
/**
 *
 */
void quicly_stream_noop_on_send_emit(quicly_stream_t *stream, size_t off, void *dst, size_t *len, int *wrote_all);
/**
 *
 */
void quicly_stream_noop_on_send_stop(quicly_stream_t *stream, int err);
/**
 *
 */
void quicly_stream_noop_on_receive(quicly_stream_t *stream, size_t off, const void *src, size_t len);
/**
 *
 */
void quicly_stream_noop_on_receive_reset(quicly_stream_t *stream, int err);

extern const quicly_stream_callbacks_t quicly_stream_noop_callbacks;

/* inline definitions */

inline quicly_state_t quicly_get_state(quicly_conn_t *conn)
{
    struct _st_quicly_conn_public_t *c = (struct _st_quicly_conn_public_t *)conn;
    return c->state;
}

inline uint32_t quicly_num_streams(quicly_conn_t *conn)
{
    struct _st_quicly_conn_public_t *c = (struct _st_quicly_conn_public_t *)conn;
    return c->local.bidi.num_streams + c->local.uni.num_streams + c->remote.bidi.num_streams + c->remote.uni.num_streams;
}

inline quicly_context_t *quicly_get_context(quicly_conn_t *conn)
{
    struct _st_quicly_conn_public_t *c = (struct _st_quicly_conn_public_t *)conn;
    return c->ctx;
}

inline const quicly_cid_plaintext_t *quicly_get_master_id(quicly_conn_t *conn)
{
    struct _st_quicly_conn_public_t *c = (struct _st_quicly_conn_public_t *)conn;
    return &c->local.cid_set.plaintext;
}

inline const quicly_cid_t *quicly_get_original_dcid(quicly_conn_t *conn)
{
    struct _st_quicly_conn_public_t *c = (struct _st_quicly_conn_public_t *)conn;
    return &c->original_dcid;
}

inline const quicly_cid_t *quicly_get_remote_cid(quicly_conn_t *conn)
{
    struct _st_quicly_conn_public_t *c = (struct _st_quicly_conn_public_t *)conn;
    return &c->remote.cid_set.cids[0].cid;
}

inline const quicly_transport_parameters_t *quicly_get_remote_transport_parameters(quicly_conn_t *conn)
{
    struct _st_quicly_conn_public_t *c = (struct _st_quicly_conn_public_t *)conn;
    return &c->remote.transport_params;
}

inline int quicly_is_client(quicly_conn_t *conn)
{
    struct _st_quicly_conn_public_t *c = (struct _st_quicly_conn_public_t *)conn;
    return (c->local.bidi.next_stream_id & 1) == 0;
}

inline quicly_stream_id_t quicly_get_local_next_stream_id(quicly_conn_t *conn, int uni)
{
    struct _st_quicly_conn_public_t *c = (struct _st_quicly_conn_public_t *)conn;
    return uni ? c->local.uni.next_stream_id : c->local.bidi.next_stream_id;
}

inline quicly_stream_id_t quicly_get_remote_next_stream_id(quicly_conn_t *conn, int uni)
{
    struct _st_quicly_conn_public_t *c = (struct _st_quicly_conn_public_t *)conn;
    return uni ? c->remote.uni.next_stream_id : c->remote.bidi.next_stream_id;
}

inline struct sockaddr *quicly_get_sockname(quicly_conn_t *conn)
{
    struct _st_quicly_conn_public_t *c = (struct _st_quicly_conn_public_t *)conn;
    return &c->local.address.sa;
}

inline struct sockaddr *quicly_get_peername(quicly_conn_t *conn)
{
    struct _st_quicly_conn_public_t *c = (struct _st_quicly_conn_public_t *)conn;
    return &c->remote.address.sa;
}

inline void **quicly_get_data(quicly_conn_t *conn)
{
    struct _st_quicly_conn_public_t *c = (struct _st_quicly_conn_public_t *)conn;
    return &c->data;
}

inline int quicly_stop_requested(quicly_stream_t *stream)
{
    return stream->_send_aux.stop_sending.sender_state != QUICLY_SENDER_STATE_NONE;
}

inline int quicly_stream_is_client_initiated(quicly_stream_id_t stream_id)
{
    if (stream_id < 0)
        return (stream_id & 1) != 0;
    return (stream_id & 1) == 0;
}

inline int quicly_stream_is_unidirectional(quicly_stream_id_t stream_id)
{
    if (stream_id < 0)
        return 0;
    return (stream_id & 2) != 0;
}

inline int quicly_stream_has_send_side(int is_client, quicly_stream_id_t stream_id)
{
    if (!quicly_stream_is_unidirectional(stream_id))
        return 1;
    return is_client == quicly_stream_is_client_initiated(stream_id);
}

inline int quicly_stream_has_receive_side(int is_client, quicly_stream_id_t stream_id)
{
    if (!quicly_stream_is_unidirectional(stream_id))
        return 1;
    return is_client != quicly_stream_is_client_initiated(stream_id);
}

inline int quicly_stream_is_self_initiated(quicly_stream_t *stream)
{
    return quicly_stream_is_client_initiated(stream->stream_id) == quicly_is_client(stream->conn);
}

inline void quicly_byte_to_hex(char *dst, uint8_t v)
{
    dst[0] = "0123456789abcdef"[v >> 4];
    dst[1] = "0123456789abcdef"[v & 0xf];
}

#ifdef __cplusplus
}
#endif

#endif
