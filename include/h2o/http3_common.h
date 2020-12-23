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
#include "h2o/absprio.h"
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
#define H2O_HTTP3_FRAME_TYPE_PRIORITY_UPDATE 15

#define H2O_HTTP3_STREAM_TYPE_CONTROL 0
#define H2O_HTTP3_STREAM_TYPE_PUSH_STREAM 1
#define H2O_HTTP3_STREAM_TYPE_QPACK_ENCODER 2
#define H2O_HTTP3_STREAM_TYPE_QPACK_DECODER 3
#define H2O_HTTP3_STREAM_TYPE_REQUEST 0x4000000000000000 /* internal type */

#define H2O_HTTP3_SETTINGS_QPACK_MAX_TABLE_CAPACITY 1
#define H2O_HTTP3_SETTINGS_MAX_FIELD_SECTION_SIZE 6
#define H2O_HTTP3_SETTINGS_QPACK_BLOCKED_STREAMS 7

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

/**
 * maximum payload size excluding DATA frame; stream receive window MUST be at least as big as this + 16 bytes to hold the type and
 * the length
 */
#define H2O_HTTP3_MAX_FRAME_PAYLOAD_SIZE 16384
#define H2O_HTTP3_INITIAL_REQUEST_STREAM_WINDOW_SIZE (H2O_HTTP3_MAX_FRAME_PAYLOAD_SIZE * 2)

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
    h2o_absprio_t priority;
} h2o_http3_priority_update_frame_t;

typedef struct st_h2o_http3_goaway_frame_t {
    uint64_t stream_or_push_id;
} h2o_http3_goaway_frame_t;

#define H2O_HTTP3_PRIORITY_UPDATE_FRAME_CAPACITY (1 /* len */ + 1 /* frame type */ + 8 + sizeof("u=1,i=?0") - 1)
uint8_t *h2o_http3_encode_priority_update_frame(uint8_t *dst, const h2o_http3_priority_update_frame_t *frame);
int h2o_http3_decode_priority_update_frame(h2o_http3_priority_update_frame_t *frame, const uint8_t *payload, size_t len,
                                           const char **err_desc);
size_t h2o_http3_goaway_frame_capacity(quicly_stream_id_t stream_or_push_id);
uint8_t *h2o_http3_encode_goaway_frame(uint8_t *buff, quicly_stream_id_t stream_or_push_id);
int h2o_http3_decode_goaway_frame(h2o_http3_goaway_frame_t *frame, const uint8_t *payload, size_t len, const char **err_desc);

/**
 * special error value to be returned by h2o_quic_accept_cb, to indicate that packet decryption failed during quicly_accept
 */
#define H2O_QUIC_ACCEPT_CONN_DECRYPTION_FAILED ((h2o_quic_conn_t *)1)

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
     *
     */
    quicly_cid_plaintext_t next_cid;
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
     * linklist of clients (see st_h2o_http3client_conn_t::clients_link)
     */
    h2o_linklist_t clients;
    /**
     * callback to accept new connections (optional)
     */
    h2o_quic_accept_cb acceptor;
    /**
     * 0 to disable load distribution of accepting connections by h2o (i.e. relies on the kernel's disbirution based on 4-tuple)
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
     * preprocessor that rewrites a forwarded datagram (optional)
     */
    h2o_quic_preprocess_packet_cb preprocess_packet;
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
    void (*handle_control_stream_frame)(h2o_http3_conn_t *conn, uint8_t type, const uint8_t *payload, size_t len);
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

extern const ptls_iovec_t h2o_http3_alpn[2];

/**
 * sends datagrams
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
int h2o_http3_read_frame(h2o_http3_read_frame_t *frame, int is_client, uint64_t stream_type, const uint8_t **src,
                         const uint8_t *src_end, const char **err_desc);
/**
 * initializes the context
 */
void h2o_quic_init_context(h2o_quic_ctx_t *ctx, h2o_loop_t *loop, h2o_socket_t *sock, quicly_context_t *quic,
                           h2o_quic_accept_cb acceptor, h2o_quic_notify_connection_update_cb notify_conn_update);
/**
 *
 */
void h2o_quic_dispose_context(h2o_quic_ctx_t *ctx);
/**
 *
 */
void h2o_quic_set_context_identifier(h2o_quic_ctx_t *ctx, uint32_t accept_thread_divisor, uint32_t thread_id, uint64_t node_id,
                                     uint8_t ttl, h2o_quic_forward_packets_cb forward_cb,
                                     h2o_quic_preprocess_packet_cb preprocess_cb);
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
                         const h2o_http3_qpack_context_t *qpack_ctx);
/**
 *
 */
void h2o_http3_dispose_conn(h2o_http3_conn_t *conn);
/**
 *
 */
int h2o_http3_setup(h2o_http3_conn_t *conn, quicly_conn_t *quic);
/**
 * sends packets immediately by calling quicly_send, sendmsg (returns 1 if success, 0 if the connection was destroyed)
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
 * Enqueue GOAWAY frame for sending
 */
void h2o_http3_send_goaway_frame(h2o_http3_conn_t *conn, uint64_t stream_or_push_id);
/**
 *
 */
static int h2o_http3_has_received_settings(h2o_http3_conn_t *conn);

/* inline definitions */

inline int h2o_http3_has_received_settings(h2o_http3_conn_t *conn)
{
    return conn->qpack.enc != NULL;
}

#endif
