/*
 * Copyright (c) 2018 Fastly, Kazuho
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
#ifndef h2o__http3_common_h
#define h2o__http3_common_h

#include <string.h>
#include <sys/socket.h>
#include "quicly.h"
#include "quicly/defaults.h"
#include "h2o/memory.h"
#include "h2o/socket.h"
#include "h2o/qpack.h"

#define H2O_HTTP3_FRAME_TYPE_DATA 0
#define H2O_HTTP3_FRAME_TYPE_HEADERS 1
#define H2O_HTTP3_FRAME_TYPE_CANCEL_PUSH 3
#define H2O_HTTP3_FRAME_TYPE_SETTINGS 4
#define H2O_HTTP3_FRAME_TYPE_PUSH_PROMISE 5
#define H2O_HTTP3_FRAME_TYPE_GOAWAY 7
#define H2O_HTTP3_FRAME_TYPE_MAX_PUSH_ID 13
#define H2O_HTTP3_FRAME_TYPE_PRIORITY_UPDATE_REQUEST 0xF0700
#define H2O_HTTP3_FRAME_TYPE_PRIORITY_UPDATE_PUSH 0xF0701

#define H2O_HTTP3_STREAM_TYPE_CONTROL 0
#define H2O_HTTP3_STREAM_TYPE_PUSH_STREAM 1
#define H2O_HTTP3_STREAM_TYPE_QPACK_ENCODER 2
#define H2O_HTTP3_STREAM_TYPE_QPACK_DECODER 3
#define H2O_HTTP3_STREAM_TYPE_REQUEST 0x4000000000000000 /* internal type */

#define H2O_HTTP3_SETTINGS_QPACK_MAX_TABLE_CAPACITY 1
#define H2O_HTTP3_SETTINGS_MAX_FIELD_SECTION_SIZE 6
#define H2O_HTTP3_SETTINGS_QPACK_BLOCKED_STREAMS 7
#define H2O_HTTP3_SETTINGS_ENABLE_CONNECT_PROTOCOL 8
#define H2O_HTTP3_SETTINGS_H3_DATAGRAM_DRAFT03 0x276
#define H2O_HTTP3_SETTINGS_H3_DATAGRAM 0x33

#define H2O_HTTP3_ERROR_NONE QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0x100)
#define H2O_HTTP3_ERROR_GENERAL_PROTOCOL QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0x101)
#define H2O_HTTP3_ERROR_INTERNAL QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0x102)
#define H2O_HTTP3_ERROR_STREAM_CREATION QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0x103)
#define H2O_HTTP3_ERROR_CLOSED_CRITICAL_STREAM QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0x104)
#define H2O_HTTP3_ERROR_FRAME_UNEXPECTED QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0x105)
#define H2O_HTTP3_ERROR_FRAME QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0x106)
#define H2O_HTTP3_ERROR_EXCESSIVE_LOAD QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0x107)
#define H2O_HTTP3_ERROR_ID QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0x108)
#define H2O_HTTP3_ERROR_SETTINGS QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0x109)
#define H2O_HTTP3_ERROR_MISSING_SETTINGS QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0x10a)
#define H2O_HTTP3_ERROR_REQUEST_REJECTED QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0x10b)
#define H2O_HTTP3_ERROR_REQUEST_CANCELLED QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0x10c)
#define H2O_HTTP3_ERROR_REQUEST_INCOMPLETE QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0x10d)
#define H2O_HTTP3_ERROR_EARLY_RESPONSE QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0x10e)
#define H2O_HTTP3_ERROR_CONNECT_ERROR QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0x10f)
#define H2O_HTTP3_ERROR_VERSION_FALLBACK QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0x110)
#define H2O_HTTP3_ERROR_QPACK_DECOMPRESSION_FAILED QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0x200)
#define H2O_HTTP3_ERROR_QPACK_ENCODER_STREAM QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0x201)
#define H2O_HTTP3_ERROR_QPACK_DECODER_STREAM QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0x202)

#define H2O_HTTP3_ERROR_INCOMPLETE -1
#define H2O_HTTP3_ERROR_TRANSPORT -2
#define H2O_HTTP3_ERROR_USER1 -256

#define H2O_HTTP3_DEFAULT_MAX_CONCURRENT_STREAMING_REQUESTS 1

typedef struct st_h2o_quic_ctx_t h2o_quic_ctx_t;
typedef struct st_h2o_quic_conn_t h2o_quic_conn_t;
typedef struct st_h2o_http3_conn_t h2o_http3_conn_t;
struct st_h2o_http3_ingress_unistream_t;
struct st_h2o_http3_egress_unistream_t;
struct kh_h2o_quic_idmap_s;
struct kh_h2o_http3_unauthmap_s;

typedef enum en_h2o_http3_priority_element_type_t {
    H2O_HTTP3_PRIORITY_ELEMENT_TYPE_REQUEST_STREAM,
    H2O_HTTP3_PRIORITY_ELEMENT_TYPE_PUSH_STREAM,
    H2O_HTTP3_PRIORITY_ELEMENT_TYPE_PLACEHOLDER,
    /**
     * root (when used as element dependency type)
     */
    H2O_HTTP3_PRIORITY_ELEMENT_TYPE_ROOT
} h2o_http3_priority_element_type_t;

typedef struct st_h2o_http3_priority_update_frame_t {
    uint64_t element_is_push : 1;
    uint64_t element : 63;
    h2o_iovec_t value;
} h2o_http3_priority_update_frame_t;

typedef struct st_h2o_http3_goaway_frame_t {
    uint64_t stream_or_push_id;
} h2o_http3_goaway_frame_t;

size_t h2o_http3_priority_update_frame_capacity(h2o_http3_priority_update_frame_t *frame);
uint8_t *h2o_http3_encode_priority_update_frame(uint8_t *dst, const h2o_http3_priority_update_frame_t *frame);
int h2o_http3_decode_priority_update_frame(h2o_http3_priority_update_frame_t *frame, int is_push, const uint8_t *payload,
                                           size_t len, const char **err_desc);
size_t h2o_http3_goaway_frame_capacity(quicly_stream_id_t stream_or_push_id);
uint8_t *h2o_http3_encode_goaway_frame(uint8_t *buff, quicly_stream_id_t stream_or_push_id);
int h2o_http3_decode_goaway_frame(h2o_http3_goaway_frame_t *frame, const uint8_t *payload, size_t len, const char **err_desc);

/**
 * special error object to be returned by h2o_quic_accept_cb, to indicate that packet decryption failed during quicly_accept
 */
extern h2o_quic_conn_t h2o_quic_accept_conn_decryption_failed;
/**
 * special error object to be returned by h2o_http3_server_accept, indicating that a connection was accepted but already closed due
 * to an error. In this case connection counter decrements are already done.
 */
extern h2o_http3_conn_t h2o_http3_accept_conn_closed;

/**
 * Accepts a new QUIC connection
 * @return a pointer to a new connection object upon success, NULL or H2O_QUIC_ACCEPT_CONN_DECRYPTION_FAILED upon failure.
 */
typedef h2o_quic_conn_t *(*h2o_quic_accept_cb)(h2o_quic_ctx_t *ctx, quicly_address_t *destaddr, quicly_address_t *srcaddr,
                                               quicly_decoded_packet_t *packet);
typedef void (*h2o_quic_notify_connection_update_cb)(h2o_quic_ctx_t *ctx, h2o_quic_conn_t *conn);
/**
 * Forwards a packet to given node/thread.
 * When `node_id` is NULL, the forwarded packet is an Initial or a 0-RTT packet.  Application should forward the packet to given
 * thread, or if the thread points to the current thread (which happens when acceptor is set to NULL) forward the packet to the
 * next generation process (graceful restart).
 * When `node_id` is not NULL, the forwarded packet is an Handshake or a 1-RTT packet.  Application should forward the packet to
 * given thread / node if the values are valid.  Otherwise, it should return false, which in turn triggers the code that checks if
 * the packet is a stateless reset.
 * @return true if packet was forwarded (or was forwardable), otherwise false
 */
typedef int (*h2o_quic_forward_packets_cb)(h2o_quic_ctx_t *ctx, const uint64_t *node_id, uint32_t thread_id,
                                           quicly_address_t *destaddr, quicly_address_t *srcaddr, uint8_t ttl,
                                           quicly_decoded_packet_t *packets, size_t num_packets);
/**
 * preprocess a received datagram (e.g., rewrite the sockaddr). Returns if the packet was modified.
 */
typedef int (*h2o_quic_preprocess_packet_cb)(h2o_quic_ctx_t *ctx, struct msghdr *msghdr, quicly_address_t *destaddr,
                                             quicly_address_t *srcaddr, uint8_t *ttl);

/**
 * Holds the counters. It is mere coincident that the members are equivalent with QUICLY_STATS_PREBUILT_FIELDS. The macro below can
 * be used for generating expression that take all the members equally.
 */
struct st_h2o_quic_aggregated_stats_t {
    QUICLY_STATS_PREBUILT_COUNTERS;
};

typedef struct st_h2o_quic_stats_t {
    /**
     * number of quic packets received
     */
    uint64_t packet_received;
    /**
     * number of quic packets successfully used for a connection
     */
    uint64_t packet_processed;
    /**
     * largest number of packets observed in quicly sentmap
     */
    size_t num_sentmap_packets_largest;

    /**
     * aggregated quicly stats
     */
    struct st_h2o_quic_aggregated_stats_t quicly;
} h2o_quic_stats_t;

/* clang-format off */
#define H2O_QUIC_AGGREGATED_STATS_APPLY(func) \
    func(num_packets.received, "num-packets.received") \
    func(num_packets.decryption_failed, "num-packets.decryption-failed") \
    func(num_packets.sent, "num-packets.sent") \
    func(num_packets.lost, "num-packets.lost") \
    func(num_packets.lost_time_threshold, "num-packets.lost-time-threshold") \
    func(num_packets.ack_received, "num-packets.ack-received") \
    func(num_packets.late_acked, "num-packets.late-acked") \
    func(num_packets.initial_received, "num-packets.initial-received") \
    func(num_packets.zero_rtt_received, "num-packets.zero-rtt-received") \
    func(num_packets.handshake_received, "num-packets.handshake-received") \
    func(num_packets.initial_sent, "num-packets.initial-sent") \
    func(num_packets.zero_rtt_sent, "num-packets.zero-rtt-sent") \
    func(num_packets.handshake_sent, "num-packets.handshake-sent") \
    func(num_packets.received_out_of_order, "num-packets.received-out-of-order") \
    func(num_packets.received_ecn_counts[0], "num-packets.received-ecn-ect0") \
    func(num_packets.received_ecn_counts[1], "num-packets.received-ecn-ect1") \
    func(num_packets.received_ecn_counts[2], "num-packets.received-ecn-ce") \
    func(num_packets.acked_ecn_counts[0], "num-packets.acked-ecn-ect0") \
    func(num_packets.acked_ecn_counts[1], "num-packets.acked-ecn-ect1") \
    func(num_packets.acked_ecn_counts[2], "num-packets.acked-ecn-ce") \
    func(num_packets.sent_promoted_paths, "num-packets.sent-promoted-paths") \
    func(num_packets.ack_received_promoted_paths, "num-packets.ack-received-promoted-paths") \
    func(num_bytes.received, "num-bytes.received") \
    func(num_bytes.sent, "num-bytes.sent") \
    func(num_bytes.lost, "num-bytes.lost") \
    func(num_bytes.stream_data_sent, "num-bytes.stream-data-sent") \
    func(num_bytes.stream_data_resent, "num-bytes.stream-data-resent") \
    func(num_paths.created, "num-paths.created") \
    func(num_paths.validated, "num-paths.validated") \
    func(num_paths.validation_failed, "num-paths.validation-failed") \
    func(num_paths.migration_elicited, "num-paths.migration-elicited") \
    func(num_paths.promoted, "num-paths.promoted") \
    func(num_paths.closed_no_dcid, "num-paths.closed-no-dcid") \
    func(num_paths.ecn_validated, "num-paths.ecn-validated") \
    func(num_paths.ecn_failed, "num-paths.ecn_failed") \
    func(num_frames_sent.padding, "num-frames-sent.padding") \
    func(num_frames_sent.ping, "num-frames-sent.ping") \
    func(num_frames_sent.ack, "num-frames-sent.ack") \
    func(num_frames_sent.reset_stream, "num-frames-sent.reset_stream") \
    func(num_frames_sent.stop_sending, "num-frames-sent.stop_sending") \
    func(num_frames_sent.crypto, "num-frames-sent.crypto") \
    func(num_frames_sent.new_token, "num-frames-sent.new_token") \
    func(num_frames_sent.stream, "num-frames-sent.stream") \
    func(num_frames_sent.max_data, "num-frames-sent.max_data") \
    func(num_frames_sent.max_stream_data, "num-frames-sent.max_stream_data") \
    func(num_frames_sent.max_streams_bidi, "num-frames-sent.max_streams_bidi") \
    func(num_frames_sent.max_streams_uni, "num-frames-sent.max_streams_uni") \
    func(num_frames_sent.data_blocked, "num-frames-sent.data_blocked") \
    func(num_frames_sent.stream_data_blocked, "num-frames-sent.stream_data_blocked") \
    func(num_frames_sent.streams_blocked, "num-frames-sent.streams_blocked") \
    func(num_frames_sent.new_connection_id, "num-frames-sent.new_connection_id") \
    func(num_frames_sent.retire_connection_id, "num-frames-sent.retire_connection_id") \
    func(num_frames_sent.path_challenge, "num-frames-sent.path_challenge") \
    func(num_frames_sent.path_response, "num-frames-sent.path_response") \
    func(num_frames_sent.transport_close, "num-frames-sent.transport_close") \
    func(num_frames_sent.application_close, "num-frames-sent.application_close") \
    func(num_frames_sent.handshake_done, "num-frames-sent.handshake_done") \
    func(num_frames_sent.datagram, "num-frames-sent.datagram") \
    func(num_frames_sent.ack_frequency, "num-frames-sent.ack_frequency") \
    func(num_frames_received.padding, "num-frames-received.padding") \
    func(num_frames_received.ping, "num-frames-received.ping") \
    func(num_frames_received.ack, "num-frames-received.ack") \
    func(num_frames_received.reset_stream, "num-frames-received.reset_stream") \
    func(num_frames_received.stop_sending, "num-frames-received.stop_sending") \
    func(num_frames_received.crypto, "num-frames-received.crypto") \
    func(num_frames_received.new_token, "num-frames-received.new_token") \
    func(num_frames_received.stream, "num-frames-received.stream") \
    func(num_frames_received.max_data, "num-frames-received.max_data") \
    func(num_frames_received.max_stream_data, "num-frames-received.max_stream_data") \
    func(num_frames_received.max_streams_bidi, "num-frames-received.max_streams_bidi") \
    func(num_frames_received.max_streams_uni, "num-frames-received.max_streams_uni") \
    func(num_frames_received.data_blocked, "num-frames-received.data_blocked") \
    func(num_frames_received.stream_data_blocked, "num-frames-received.stream_data_blocked") \
    func(num_frames_received.streams_blocked, "num-frames-received.streams_blocked") \
    func(num_frames_received.new_connection_id, "num-frames-received.new_connection_id") \
    func(num_frames_received.retire_connection_id, "num-frames-received.retire_connection_id") \
    func(num_frames_received.path_challenge, "num-frames-received.path_challenge") \
    func(num_frames_received.path_response, "num-frames-received.path_response") \
    func(num_frames_received.transport_close, "num-frames-received.transport_close") \
    func(num_frames_received.application_close, "num-frames-received.application_close") \
    func(num_frames_received.handshake_done, "num-frames-received.handshake_done") \
    func(num_frames_received.datagram, "num-frames-received.datagram") \
    func(num_frames_received.ack_frequency, "num-frames-received.ack_frequency") \
    func(num_ptos, "num-ptos") \
    func(num_handshake_timeouts, "num-handshake-timeouts") \
    func(num_initial_handshake_exceeded, "num-initial-handshake-exceeded")
/* clang-format on */

struct st_h2o_quic_ctx_t {
    /**
     * the event loop
     */
    h2o_loop_t *loop;
    /**
     * underlying unbound socket
     */
    struct {
        h2o_socket_t *sock;
        struct sockaddr_storage addr;
        socklen_t addrlen;
        in_port_t *port; /* points to the port number in addr */
    } sock;
    /**
     * quic context
     */
    quicly_context_t *quic;
    /**
     * Retains the next CID to be used for a connection being associated to this context. Also, `thread_id` and `node_id` are
     * constants that contain the identity of the current thread / node; packets targetted to other theads / nodes are forwarded.
     */
    quicly_cid_plaintext_t *next_cid;
    /**
     * hashmap of connections by quicly_cid_plaintext_t::master_id.
     */
    struct kh_h2o_quic_idmap_s *conns_by_id;
    /**
     * hashmap of connections being accepted. Keyed by 4-tuple. Exists to handle packets that do not use the server-generated CIDs.
     */
    struct kh_h2o_quic_acceptmap_s *conns_accepting;
    /**
     * callback to receive connection status changes (optional)
     */
    h2o_quic_notify_connection_update_cb notify_conn_update;
    /**
     * callback to accept new connections (optional)
     */
    h2o_quic_accept_cb acceptor;
    /**
     * 0 to disable load distribution of accepting connections by h2o (i.e. relies on the kernel's distribution based on 4-tuple)
     */
    uint32_t accept_thread_divisor;
    /**
     * callback to forward packets (optional)
     */
    h2o_quic_forward_packets_cb forward_packets;
    /**
     * TTL of a QUIC datagram. Used to prevent infinite forwarding of QUIC packets between nodes / threads.
     */
    uint8_t default_ttl;
    /**
     * boolean to indicate whether to use UDP GSO
     */
    uint8_t use_gso;
    /**
     * preprocessor that rewrites a forwarded datagram (optional)
     */
    h2o_quic_preprocess_packet_cb preprocess_packet;
    /**
     * quic stats
     */
    h2o_quic_stats_t *quic_stats;
};

typedef struct st_h2o_quic_conn_callbacks_t {
    void (*destroy_connection)(h2o_quic_conn_t *conn);
} h2o_quic_conn_callbacks_t;

/**
 * states of an HTTP/3 connection (not stream)
 * mainly to see if a new request can be accepted
 */
typedef enum enum_h2o_http3_conn_state_t {
    H2O_HTTP3_CONN_STATE_OPEN,        /* accepting new connections */
    H2O_HTTP3_CONN_STATE_HALF_CLOSED, /* no more accepting new streams */
    H2O_HTTP3_CONN_STATE_IS_CLOSING   /* nothing should be sent */
} h2o_http3_conn_state_t;

struct st_h2o_quic_conn_t {
    /**
     * context
     */
    h2o_quic_ctx_t *ctx;
    /**
     * underlying QUIC connection
     */
    quicly_conn_t *quic;
    /**
     * callbacks
     */
    const h2o_quic_conn_callbacks_t *callbacks;
    /**
     * the "transport" timer. Applications must have separate timer.
     */
    h2o_timer_t _timeout;
    /**
     *
     */
    uint64_t _accept_hashkey;
};

typedef struct st_h2o_http3_qpack_context_t {
    /**
     * Our preferred table capacity for the encoder. The value actually used is MIN(this_value,
     * peer_settings.encoder_table_capacity).
     */
    uint32_t encoder_table_capacity;
} h2o_http3_qpack_context_t;

typedef struct st_h2o_http3_conn_callbacks_t {
    h2o_quic_conn_callbacks_t super;
    void (*handle_control_stream_frame)(h2o_http3_conn_t *conn, uint64_t type, const uint8_t *payload, size_t len);
} h2o_http3_conn_callbacks_t;

struct st_h2o_http3_conn_t {
    /**
     *
     */
    h2o_quic_conn_t super;
    /**
     * connection state
     */
    h2o_http3_conn_state_t state;
    /**
     * QPACK states
     */
    struct {
        const h2o_http3_qpack_context_t *ctx;
        h2o_qpack_encoder_t *enc;
        h2o_qpack_decoder_t *dec;
    } qpack;
    /**
     *
     */
    struct {
        uint64_t max_field_section_size;
        unsigned h3_datagram : 1;
    } peer_settings;
    struct {
        struct {
            struct st_h2o_http3_ingress_unistream_t *control;
            struct st_h2o_http3_ingress_unistream_t *qpack_encoder;
            struct st_h2o_http3_ingress_unistream_t *qpack_decoder;
        } ingress;
        struct {
            struct st_h2o_http3_egress_unistream_t *control;
            struct st_h2o_http3_egress_unistream_t *qpack_encoder;
            struct st_h2o_http3_egress_unistream_t *qpack_decoder;
        } egress;
    } _control_streams;
    /**
     * Maximum frame payload size (excluding DATA); this property essentially limits the maximum size of HEADERS frame.
     * As `h2o_http3_read_frame` parses the frame inside the receive buffer, stream-level flow control credits specified in
     * `quicly_context_t::transport_params.max_stream_data` MUST be no less than
     * `h2o_http3_calc_min_flow_control_size(max_frame_payload_size)`.
     */
    size_t max_frame_payload_size;
};

#define H2O_HTTP3_CHECK_SUCCESS(expr)                                                                                              \
    do {                                                                                                                           \
        if (!(expr))                                                                                                               \
            h2o_fatal(H2O_TO_STR(expr));                                                                                           \
    } while (0)

typedef struct st_h2o_http3_read_frame_t {
    uint64_t type;
    uint8_t _header_size;
    const uint8_t *payload;
    uint64_t length;
} h2o_http3_read_frame_t;

extern const char h2o_http3_err_frame_too_large[];

extern const ptls_iovec_t h2o_http3_alpn[3];

/**
 * Sends UDP datagrams from specified source address to the specified destination. The returned value is a boolean indicating if the
 * connection is still maintainable (false is returned when not being able to send a packet from the designated source address).
 * When more than one datagram is provided, the size of all the datagrams must be the same except for the last datagram, so that
 * the datagrams can be sent using GSO.
 */
int h2o_quic_send_datagrams(h2o_quic_ctx_t *ctx, quicly_address_t *dest, quicly_address_t *src, struct iovec *datagrams,
                            size_t num_datagrams);
/**
 * creates a unidirectional stream object
 */
void h2o_http3_on_create_unidirectional_stream(quicly_stream_t *qs);
/**
 * returns a frame header (if BODY frame) or an entire frame
 */
int h2o_http3_read_frame(h2o_http3_read_frame_t *frame, int is_client, uint64_t stream_type, size_t max_frame_payload_size,
                         const uint8_t **src, const uint8_t *src_end, const char **err_desc);

/**
 * Initializes the QUIC context, binding the event loop, socket, quic, and other properties. `next_cid` should be a thread-local
 * that contains the CID seed to be used; see `h2o_quic_ctx_t::next_cid` for more information.
 */
void h2o_quic_init_context(h2o_quic_ctx_t *ctx, h2o_loop_t *loop, h2o_socket_t *sock, quicly_context_t *quic,
                           quicly_cid_plaintext_t *next_cid, h2o_quic_accept_cb acceptor,
                           h2o_quic_notify_connection_update_cb notify_conn_update, uint8_t use_gso, h2o_quic_stats_t *quic_stats);
/**
 *
 */
void h2o_quic_dispose_context(h2o_quic_ctx_t *ctx);
/**
 * When running QUIC on multiple threads / nodes, it becomes necessary to forward incoming packets between those threads / nodes
 * with encapsulation. This function makes adjustments to the context initialized by `h2o_quic_init_context` and registers the
 * callbacks necessary for forwarding with en(de)capsulation.
 */
void h2o_quic_set_forwarding_context(h2o_quic_ctx_t *ctx, uint32_t accept_thread_divisor, uint8_t ttl,
                                     h2o_quic_forward_packets_cb forward_cb, h2o_quic_preprocess_packet_cb preprocess_cb);
/**
 *
 */
void h2o_quic_read_socket(h2o_quic_ctx_t *ctx, h2o_socket_t *sock);
/**
 *
 */
void h2o_quic_close_connection(h2o_quic_conn_t *conn, int err, const char *reason_phrase);
/**
 *
 */
void h2o_quic_close_all_connections(h2o_quic_ctx_t *ctx);
/**
 *
 */
size_t h2o_quic_num_connections(h2o_quic_ctx_t *ctx);
/**
 *
 */
void h2o_quic_init_conn(h2o_quic_conn_t *conn, h2o_quic_ctx_t *ctx, const h2o_quic_conn_callbacks_t *callbacks);
/**
 *
 */
void h2o_quic_dispose_conn(h2o_quic_conn_t *conn);
/**
 *
 */
void h2o_quic_setup(h2o_quic_conn_t *conn, quicly_conn_t *quic);
/**
 * initializes a http3 connection
 */
void h2o_http3_init_conn(h2o_http3_conn_t *conn, h2o_quic_ctx_t *ctx, const h2o_http3_conn_callbacks_t *callbacks,
                         const h2o_http3_qpack_context_t *qpack_ctx, size_t max_frame_payload_size);
/**
 *
 */
void h2o_http3_dispose_conn(h2o_http3_conn_t *conn);
/**
 *
 */
int h2o_http3_setup(h2o_http3_conn_t *conn, quicly_conn_t *quic);
/**
 * sends packets immediately by calling quicly_send, sendmsg (returns true if success, false if the connection was destroyed)
 */
int h2o_quic_send(h2o_quic_conn_t *conn);
/**
 * updates receive buffer
 */
void h2o_http3_update_recvbuf(h2o_buffer_t **buf, size_t off, const void *src, size_t len);
/**
 * Schedules the transport timer. Application must call this function when it writes data to the connection (TODO better way to
 * handle this?). The function is automatically called when packets are sent or received.
 */
void h2o_quic_schedule_timer(h2o_quic_conn_t *conn);
/**
 *
 */
int h2o_http3_handle_settings_frame(h2o_http3_conn_t *conn, const uint8_t *payload, size_t length, const char **err_desc);
/**
 *
 */
void h2o_http3_send_qpack_stream_cancel(h2o_http3_conn_t *conn, quicly_stream_id_t stream_id);
/**
 *
 */
void h2o_http3_send_qpack_header_ack(h2o_http3_conn_t *conn, const void *bytes, size_t len);
/**
 * Enqueue GOAWAY frame crafted for graceful shutdown
 */
void h2o_http3_send_shutdown_goaway_frame(h2o_http3_conn_t *conn);
/**
 * Enqueue GOAWAY frame for sending
 */
void h2o_http3_send_goaway_frame(h2o_http3_conn_t *conn, uint64_t stream_or_push_id);
/**
 *
 */
static int h2o_http3_has_received_settings(h2o_http3_conn_t *conn);
/**
 * Sends H3 datagrams (RFC 9297).
 * To send RFC 9298-style UDP packets, callers should set Context ID (0) as part of the payload.
 */
void h2o_http3_send_h3_datagrams(h2o_http3_conn_t *conn, uint64_t flow_id, h2o_iovec_t *datagrams, size_t num_datagrams);
/**
 * Decodes an H3 datagram. Returns the flow id if successful, or UINT64_MAX if not.
 */
uint64_t h2o_http3_decode_h3_datagram(h2o_iovec_t *payload, const void *_src, size_t len);
/**
 * Given maximum payload size of headers block (e.g., `H2O_MAX_REQLEN`), returns the mimimum stream-level flow control credit that
 * have to be guaranteed.
 */
static uint64_t h2o_http3_calc_min_flow_control_size(size_t max_headers_length);

/* inline definitions */

inline int h2o_http3_has_received_settings(h2o_http3_conn_t *conn)
{
    return conn->qpack.enc != NULL;
}

inline uint64_t h2o_http3_calc_min_flow_control_size(size_t max_headers_length)
{
    return 8 /* max. type field */ + 8 /* max. length field */ + max_headers_length;
}

#endif
