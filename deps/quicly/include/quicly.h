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
#include "quicly/linklist.h"
#include "quicly/loss.h"
#include "quicly/recvstate.h"
#include "quicly/sendstate.h"
#include "quicly/maxsender.h"

#ifndef QUICLY_DEBUG
#define QUICLY_DEBUG 0
#endif

/* invariants! */
#define QUICLY_LONG_HEADER_BIT 0x80
#define QUICLY_PACKET_IS_LONG_HEADER(first_byte) (((first_byte)&QUICLY_LONG_HEADER_BIT) != 0)

#define QUICLY_PROTOCOL_VERSION 0xff000016

#define QUICLY_MAX_CID_LEN_V1 20
#define QUICLY_STATELESS_RESET_TOKEN_LEN 16
#define QUICLY_STATELESS_RESET_PACKET_MIN_LEN 39

typedef union st_quicly_address_t {
    struct sockaddr sa;
    struct sockaddr_in sin;
    struct sockaddr_in6 sin6;
} quicly_address_t;

typedef struct st_quicly_datagram_t {
    ptls_iovec_t data;
    quicly_address_t dest, src;
} quicly_datagram_t;

typedef struct st_quicly_cid_t quicly_cid_t;
typedef struct st_quicly_cid_plaintext_t quicly_cid_plaintext_t;
typedef struct st_quicly_context_t quicly_context_t;
typedef struct st_quicly_conn_t quicly_conn_t;
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
 * allocates a packet buffer
 */
typedef struct st_quicly_packet_allocator_t {
    quicly_datagram_t *(*alloc_packet)(struct st_quicly_packet_allocator_t *self, size_t payloadsize);
    void (*free_packet)(struct st_quicly_packet_allocator_t *self, quicly_datagram_t *packet);
} quicly_packet_allocator_t;

/**
 * CID encryption
 */
typedef struct st_quicly_cid_encryptor_t {
    /**
     * encrypts CID and optionally generates a stateless reset token
     */
    void (*encrypt_cid)(struct st_quicly_cid_encryptor_t *self, quicly_cid_t *encrypted, void *stateless_reset_token,
                        const quicly_cid_plaintext_t *plaintext);
    /**
     * decrypts CID. plaintext->thread_id should contain a randomly distributed number when validation fails, so that the value can
     * be used for distributing load among the threads within the process.
     * @param len length of encrypted bytes if known, or 0 if unknown (short header packet)
     * @return length of the CID, or SIZE_MAX if decryption failed
     */
    size_t (*decrypt_cid)(struct st_quicly_cid_encryptor_t *self, quicly_cid_plaintext_t *plaintext, const void *encrypted,
                          size_t len);
    /**
     * generates a stateless reset token (returns if generated)
     */
    int (*generate_stateless_reset_token)(struct st_quicly_cid_encryptor_t *self, void *token, const void *cid);
} quicly_cid_encryptor_t;

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
 * called when the connection is closed by peer
 */
QUICLY_CALLBACK_TYPE(void, closed_by_peer, quicly_conn_t *conn, int err, uint64_t frame_type, const char *reason,
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
    uint64_t idle_timeout;
    /**
     *
     */
    uint64_t max_streams_bidi;
    /**
     *
     */
    uint64_t max_streams_uni;
    /**
     * quicly ignores the value set for quicly_context_t::transport_parameters
     */
    uint8_t ack_delay_exponent;
    /**
     * in milliseconds; quicly ignores the value set for quicly_context_t::transport_parameters
     */
    uint16_t max_ack_delay;
    /**
     *
     */
    uint8_t disable_migration : 1;
} quicly_transport_parameters_t;

struct st_quicly_cid_t {
    uint8_t cid[QUICLY_MAX_CID_LEN_V1];
    uint8_t len;
};

/**
 * Guard value. We would never send path_id of this value.
 */
#define QUICLY_MAX_PATH_ID UINT8_MAX

/**
 * The structure of CID issued by quicly.
 *
 * Authentication of the CID can be done by validating if server_id and thread_id contain correct values.
 */
struct st_quicly_cid_plaintext_t {
    /**
     * the internal "connection ID" unique to each connection (rather than QUIC's CID being unique to each path)
     */
    uint32_t master_id;
    /**
     * path ID of the connection; we issue up to 255 CIDs per connection (see QUICLY_MAX_PATH_ID)
     */
    uint32_t path_id : 8;
    /**
     * for intra-node routing
     */
    uint32_t thread_id : 24;
    /**
     * for inter-node routing; available only when using a 16-byte cipher to encrypt CIDs, otherwise set to zero. See
     * quicly_context_t::is_clustered.
     */
    uint64_t node_id;
};

struct st_quicly_context_t {
    /**
     * tls context to use
     */
    ptls_context_t *tls;
    /**
     * MTU
     */
    uint16_t max_packet_size;
    /**
     * loss detection parameters
     */
    quicly_loss_conf_t loss;
    /**
     * transport parameters
     */
    quicly_transport_parameters_t transport_params;
    /**
     * client-only
     */
    unsigned enforce_version_negotiation : 1;
    /**
     * if inter-node routing is used (by utilising quicly_cid_plaintext_t::node_id)
     */
    unsigned is_clustered : 1;
    /**
     * callback for allocating memory for raw packet
     */
    quicly_packet_allocator_t *packet_allocator;
    /**
     *
     */
    quicly_cid_encryptor_t *cid_encryptor;
    /**
     * callback called when a new stream is opened by peer
     */
    quicly_stream_open_t *stream_open;
    /**
     * callbacks for scheduling stream data
     */
    quicly_stream_scheduler_t *stream_scheduler;
    /**
     * callback called when a connection is closed by peer
     */
    quicly_closed_by_peer_t *closed_by_peer;
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
};

/**
 * connection state
 */
typedef enum {
    /**
     * before observing the first message from peer
     */
    QUICLY_STATE_FIRSTFLIGHT,
    /**
     * while connected
     */
    QUICLY_STATE_CONNECTED,
    /**
     * sending close, but haven't seen the peer sending close
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
 * the same order for quicly_stats_t and `struct st_quicly_public_conn_t::stats`.
 */
#define QUICLY_STATS_PREBUILT_FIELDS                                                                                               \
    struct {                                                                                                                       \
        uint64_t received;                                                                                                         \
        uint64_t sent;                                                                                                             \
        uint64_t lost;                                                                                                             \
        uint64_t ack_received;                                                                                                     \
    } num_packets;                                                                                                                 \
    struct {                                                                                                                       \
        uint64_t received;                                                                                                         \
        uint64_t sent;                                                                                                             \
    } num_bytes

typedef struct st_quicly_stats_t {
    /**
     * The pre-built fields. This MUST be the first member of `quicly_stats_t` so that we can use `memcpy`.
     */
    QUICLY_STATS_PREBUILT_FIELDS;
    /**
     * RTT
     */
    quicly_rtt_t rtt;
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
    /**
     * identifier assigned by the application. `path_id` stores the next value to be issued
     */
    quicly_cid_plaintext_t master_id;
    struct {
        /**
         * the local address (may be AF_UNSPEC)
         */
        quicly_address_t address;
        /**
         * the SCID used in long header packets
         */
        quicly_cid_t src_cid;
        /**
         * stateless reset token announced by the host. We have only one token per connection. The token will cached in this
         * variable when the generate_stateless_reset_token is non-NULL.
         */
        uint8_t stateless_reset_token[QUICLY_STATELESS_RESET_TOKEN_LEN];
        /**
         * TODO clear this at some point (probably when the server releases all the keys below epoch=3)
         */
        quicly_cid_t offered_cid;
        struct st_quicly_conn_streamgroup_state_t bidi, uni;
    } host;
    struct {
        /**
         * the remote address (cannot be AF_UNSPEC)
         */
        quicly_address_t address;
        /**
         * CID used for emitting the packets
         */
        quicly_cid_t cid;
        /**
         * stateless reset token corresponding to the CID
         */
        struct {
            uint8_t *token;
            uint8_t _buf[QUICLY_STATELESS_RESET_TOKEN_LEN];
        } stateless_reset;
        struct st_quicly_conn_streamgroup_state_t bidi, uni;
        quicly_transport_parameters_t transport_params;
        struct {
            unsigned validated : 1;
            unsigned send_probe : 1;
        } address_validation;
    } peer;
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
     * the sent value acknowledged by peer
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
     * being written.  `wrote_all` is a boolean out parameter indicating if the application has written all the available data.  See
     * also quicly_stream_sync_sendbuf.
     */
    int (*on_send_emit)(quicly_stream_t *stream, size_t off, void *dst, size_t *len, int *wrote_all);
    /**
     * called when a STOP_SENDING frame is received.  Do not call `quicly_reset_stream` in response.  The stream will be
     * automatically reset by quicly.
     */
    int (*on_send_stop)(quicly_stream_t *stream, int err);
    /**
     * called when data is newly received.  `off` is the offset within the buffer (the beginning position changes as the application
     * calls `quicly_stream_sync_recvbuf`.  Applications should consult `quicly_stream_t::recvstate` to see if it has contiguous
     * input.
     */
    int (*on_receive)(quicly_stream_t *stream, size_t off, const void *src, size_t len);
    /**
     * called when a RESET_STREAM frame is received
     */
    int (*on_receive_reset)(quicly_stream_t *stream, int err);
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
         * rst_stream
         */
        struct {
            /**
             * STATE_NONE until RST is generated
             */
            quicly_sender_state_t sender_state;
            uint16_t error_code;
        } rst;
        /**
         * sends receive window updates to peer
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
     * starting offset of data (i.e., version-dependent area of a long header packet (version numbers in case of VN), odcid (in case
     * of retry), or encrypted PN)
     */
    size_t encrypted_off;
    /**
     * size of the datagram
     */
    size_t datagram_size;
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
    int is_retry;
    uint64_t issued_at;
    quicly_address_t local, remote;
    union {
        struct {
            quicly_cid_t odcid;
            uint64_t cidpair_hash;
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
 *
 */
size_t quicly_decode_packet(quicly_context_t *ctx, quicly_decoded_packet_t *packet, const uint8_t *src, size_t len);
/**
 *
 */
uint64_t quicly_determine_packet_number(uint32_t truncated, size_t num_bits, uint64_t expected);
/**
 *
 */
static int quicly_cid_is_equal(const quicly_cid_t *cid, ptls_iovec_t vec);
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
static const quicly_cid_t *quicly_get_offered_cid(quicly_conn_t *conn);
/**
 *
 */
static const quicly_cid_t *quicly_get_peer_cid(quicly_conn_t *conn);
/**
 *
 */
static const quicly_transport_parameters_t *quicly_get_peer_transport_parameters(quicly_conn_t *conn);
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
static quicly_stream_id_t quicly_get_host_next_stream_id(quicly_conn_t *conn, int uni);
/**
 *
 */
static quicly_stream_id_t quicly_get_peer_next_stream_id(quicly_conn_t *conn, int uni);
/**
 *
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
quicly_datagram_t *quicly_send_version_negotiation(quicly_context_t *ctx, struct sockaddr *dest_addr, ptls_iovec_t dest_cid,
                                                   struct sockaddr *src_addr, ptls_iovec_t src_cid);
/**
 *
 */
int quicly_retry_calc_cidpair_hash(ptls_hash_algorithm_t *sha256, ptls_iovec_t client_cid, ptls_iovec_t server_cid,
                                   uint64_t *value);
/**
 *
 */
quicly_datagram_t *quicly_send_retry(quicly_context_t *ctx, ptls_aead_context_t *token_encrypt_ctx, struct sockaddr *dest_addr,
                                     ptls_iovec_t dest_cid, struct sockaddr *src_addr, ptls_iovec_t src_cid, ptls_iovec_t odcid,
                                     ptls_iovec_t token);
/**
 *
 */
int quicly_send(quicly_conn_t *conn, quicly_datagram_t **packets, size_t *num_packets);
/**
 *
 */
quicly_datagram_t *quicly_send_stateless_reset(quicly_context_t *ctx, struct sockaddr *dest_addr, struct sockaddr *src_addr,
                                               const void *src_cid);
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
int quicly_encode_transport_parameter_list(ptls_buffer_t *buf, int is_client, const quicly_transport_parameters_t *params,
                                           const quicly_cid_t *odcid, const void *stateless_reset_token);
/**
 *
 */
int quicly_decode_transport_parameter_list(quicly_transport_parameters_t *params, quicly_cid_t *odcid, void *stateless_reset_token,
                                           int is_client, const uint8_t *src, const uint8_t *end);
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
 *                       `quicly_accept` will consult the values being supplied assuming that the peer's address has been validated.
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
 * Encrypts an address token by serializing the plaintext structure and appending an authentication tag.  Bytes between `start_off`
 * and `buf->off` (at the moment of invocation) is considered part of a token covered by AAD.
 */
int quicly_encrypt_address_token(void (*random_bytes)(void *, size_t), ptls_aead_context_t *aead, ptls_buffer_t *buf,
                                 size_t start_off, const quicly_address_token_plaintext_t *plaintext);
/**
 * Decrypts an address token.
 */
int quicly_decrypt_address_token(ptls_aead_context_t *aead, quicly_address_token_plaintext_t *plaintext, const void *src,
                                 size_t len, size_t prefix_len);
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
int quicly_stream_noop_on_send_emit(quicly_stream_t *stream, size_t off, void *dst, size_t *len, int *wrote_all);
/**
 *
 */
int quicly_stream_noop_on_send_stop(quicly_stream_t *stream, int err);
/**
 *
 */
int quicly_stream_noop_on_receive(quicly_stream_t *stream, size_t off, const void *src, size_t len);
/**
 *
 */
int quicly_stream_noop_on_receive_reset(quicly_stream_t *stream, int err);

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
    return c->host.bidi.num_streams + c->host.uni.num_streams + c->peer.bidi.num_streams + c->peer.uni.num_streams;
}

inline int quicly_cid_is_equal(const quicly_cid_t *cid, ptls_iovec_t vec)
{
    return cid->len == vec.len && memcmp(cid->cid, vec.base, vec.len) == 0;
}

inline quicly_context_t *quicly_get_context(quicly_conn_t *conn)
{
    struct _st_quicly_conn_public_t *c = (struct _st_quicly_conn_public_t *)conn;
    return c->ctx;
}

inline const quicly_cid_plaintext_t *quicly_get_master_id(quicly_conn_t *conn)
{
    struct _st_quicly_conn_public_t *c = (struct _st_quicly_conn_public_t *)conn;
    return &c->master_id;
}

inline const quicly_cid_t *quicly_get_offered_cid(quicly_conn_t *conn)
{
    struct _st_quicly_conn_public_t *c = (struct _st_quicly_conn_public_t *)conn;
    return &c->host.offered_cid;
}

inline const quicly_cid_t *quicly_get_peer_cid(quicly_conn_t *conn)
{
    struct _st_quicly_conn_public_t *c = (struct _st_quicly_conn_public_t *)conn;
    return &c->peer.cid;
}

inline const quicly_transport_parameters_t *quicly_get_peer_transport_parameters(quicly_conn_t *conn)
{
    struct _st_quicly_conn_public_t *c = (struct _st_quicly_conn_public_t *)conn;
    return &c->peer.transport_params;
}

inline int quicly_is_client(quicly_conn_t *conn)
{
    struct _st_quicly_conn_public_t *c = (struct _st_quicly_conn_public_t *)conn;
    return (c->host.bidi.next_stream_id & 1) == 0;
}

inline quicly_stream_id_t quicly_get_host_next_stream_id(quicly_conn_t *conn, int uni)
{
    struct _st_quicly_conn_public_t *c = (struct _st_quicly_conn_public_t *)conn;
    return uni ? c->host.uni.next_stream_id : c->host.bidi.next_stream_id;
}

inline quicly_stream_id_t quicly_get_peer_next_stream_id(quicly_conn_t *conn, int uni)
{
    struct _st_quicly_conn_public_t *c = (struct _st_quicly_conn_public_t *)conn;
    return uni ? c->peer.uni.next_stream_id : c->peer.bidi.next_stream_id;
}

inline struct sockaddr *quicly_get_peername(quicly_conn_t *conn)
{
    struct _st_quicly_conn_public_t *c = (struct _st_quicly_conn_public_t *)conn;
    return &c->peer.address.sa;
}

inline void **quicly_get_data(quicly_conn_t *conn)
{
    struct _st_quicly_conn_public_t *c = (struct _st_quicly_conn_public_t *)conn;
    return &c->data;
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
