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
#include "h2o/memory.h"
#include "h2o/socket.h"
#include "h2o/qpack.h"

#define H2O_HTTP3_FRAME_TYPE_DATA 0
#define H2O_HTTP3_FRAME_TYPE_HEADERS 1
#define H2O_HTTP3_FRAME_TYPE_PRIORITY 2
#define H2O_HTTP3_FRAME_TYPE_CANCEL_PUSH 3
#define H2O_HTTP3_FRAME_TYPE_SETTINGS 4
#define H2O_HTTP3_FRAME_TYPE_PUSH_PROMISE 5
#define H2O_HTTP3_FRAME_TYPE_GOAWAY 7
#define H2O_HTTP3_FRAME_TYPE_MAX_PUSH_ID 13

#define H2O_HTTP3_SETTINGS_HEADER_TABLE_SIZE 1
#define H2O_HTTP3_SETTINGS_NUM_PLACEHOLDERS 3
#define H2O_HTTP3_SETTINGS_MAX_HEADER_LIST_SIZE 6
#define H2O_HTTP3_SETTINGS_QPACK_BLOCKED_STREAMS 7
#define H2O_HTTP3_SETTINGS_GREASE_MASK 0xf0f0
#define H2O_HTTP3_SETTINGS_GREASE_PATTERN 0x0a0a

#define H2O_HTTP3_DEFAULT_HEADER_TABLE_SIZE 4096
#define H2O_HTTP3_MAX_HEADER_TABLE_SIZE ((1 << 30) + 1)

#define H2O_HTTP3_ERROR_STOPPING 0
#define H2O_HTTP3_ERROR_NO_ERROR 1
#define H2O_HTTP3_ERROR_PUSH_REFUSED 2
#define H2O_HTTP3_ERROR_INTERNAL 3
#define H2O_HTTP3_ERROR_PUSH_ALREADY_IN_CACHE 4
#define H2O_HTTP3_ERROR_REQUEST_CANCELLED 5
#define H2O_HTTP3_ERROR_INCOMPLETE_REQUEST 6
#define H2O_HTTP3_ERROR_CONNECT_ERROR 7
#define H2O_HTTP3_ERROR_EXCESSIVE_LOAD 8
#define H2O_HTTP3_ERROR_VERSION_FALLBACK 9
#define H2O_HTTP3_ERROR_WRONG_STREAM 10
#define H2O_HTTP3_ERROR_PUSH_LIMIT_EXCEEDED 11
#define H2O_HTTP3_ERROR_DUPLICATE_PUSH 12
#define H2O_HTTP3_ERROR_UNKNOWN_STREAM_TYPE 13
#define H2O_HTTP3_ERROR_WRONG_STREAM_COUNT 14
#define H2O_HTTP3_ERROR_CLOSED_CRITICAL_STREAM 15
#define H2O_HTTP3_ERROR_WRONG_STREAM_DIRECTION 16
#define H2O_HTTP3_ERROR_EARLY_RESPONSE 17
#define H2O_HTTP3_ERROR_GENERAL_PROTOCOL 18
#define H2O_HTTP3_ERROR_MALFORMED_FRAME(type) (256 + type)
#define H2O_HTTP3_ERROR_IS_MALFORMED_FRAME(type) (((type) >> 8) == 1)
#define H2O_HTTP3_ERROR_GET_MALFORMED_FRAME_TYPE(err) ((err)&0xff)
#define H2O_HTTP3_ERROR_INCOMPLETE 0xff000000
#define H2O_HTTP3_ERROR_QPACK_DECOMPRESSION 0xff000001 /* a.a.a. QPACK_DECOMPRESSION_FALIED TBD */

typedef struct st_h2o_http3_ctx_t h2o_http3_ctx_t;
typedef struct st_h2o_http3_conn_t h2o_http3_conn_t;
struct st_h2o_http3_ingress_unistream_t;
struct st_h2o_http3_egress_unistream_t;

typedef h2o_http3_conn_t *(*h2o_http3_accept_cb)(h2o_http3_ctx_t *ctx, struct sockaddr *sa, socklen_t salen,
                                                 quicly_decoded_packet_t *packets, size_t num_packets);

typedef int (*h2o_http3_handle_control_stream_frame_cb)(h2o_http3_conn_t *conn, uint8_t type, const uint8_t *payload, size_t len,
                                                        const char **err_desc);

struct st_h2o_http3_ctx_t {
    /**
     * the event loop
     */
    h2o_loop_t *loop;
    /**
     * underlying unbound socket
     */
    h2o_socket_t *sock;
    /**
     * quic context
     */
    quicly_context_t *quic;
    /**
     * list of connections (FIXME use hash or something)
     */
    h2o_linklist_t conns;
    /**
     * callback to accept new connections (optional)
     */
    h2o_http3_accept_cb acceptor;
};

struct st_h2o_http3_conn_t {
    /**
     * context
     */
    h2o_http3_ctx_t *ctx;
    /**
     * underlying QUIC connection
     */
    quicly_conn_t *quic;
    /**
     * QPACK states
     */
    struct {
        h2o_qpack_encoder_t *enc;
        h2o_qpack_decoder_t *dec;
    } qpack;
    /**
     * callback for handling control stream frames
     */
    h2o_http3_handle_control_stream_frame_cb handle_control_stream_frame;
    /**
     * linklist between connections, anchor is h2o_http3_ctx_t::conns
     */
    h2o_linklist_t conns_link;
    /**
     * the "transport" timer. Applications must have separate timer.
     */
    h2o_timer_t _timeout;
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

#define h2o_http3_encode_frame(_pool_, _buf_, _type, _block)                                                                       \
    do {                                                                                                                           \
        h2o_mem_pool_t *_pool = (_pool_);                                                                                          \
        h2o_byte_vector_t *_buf = (_buf_);                                                                                         \
        h2o_vector_reserve(_pool, _buf, _buf->size + 9);                                                                           \
        _buf->size += 2;                                                                                                           \
        size_t _payload_off = _buf->size;                                                                                          \
        do {                                                                                                                       \
            _block                                                                                                                 \
        } while (0);                                                                                                               \
        uint8_t _vbuf[8];                                                                                                          \
        size_t _vlen = quicly_encodev(_vbuf, _buf->size - _payload_off) - _vbuf;                                                   \
        if (_vlen != 1) {                                                                                                          \
            h2o_vector_reserve(_pool, _buf, _buf->size + _vlen - 1);                                                               \
            memmove(_buf->entries + _payload_off + _vlen - 1, _buf->entries + _payload_off, _buf->size - _payload_off);            \
            _payload_off += _vlen - 1;                                                                                             \
            _buf->size += _vlen - 1;                                                                                               \
            memmove(_buf->entries + _payload_off - _vlen - 1, _vbuf, _vlen);                                                       \
        } else {                                                                                                                   \
            _buf->entries[_payload_off - 2] = _vbuf[0];                                                                            \
        }                                                                                                                          \
        _buf->entries[_payload_off - 1] = (_type);                                                                                 \
    } while (0)

#define H2O_HTTP3_CHECK_SUCCESS(expr)                                                                                              \
    do {                                                                                                                           \
        if (!(expr))                                                                                                               \
            h2o_fatal(H2O_TO_STR(expr));                                                                                           \
    } while (0)

typedef struct st_h2o_http3_read_frame_t {
    uint8_t type;
    uint8_t _header_size;
    const uint8_t *payload;
    uint64_t length;
} h2o_http3_read_frame_t;

const ptls_iovec_t h2o_http3_alpn[1];

/**
 * creates a unidirectional stream object
 */
void h2o_http3_on_create_unidirectional_stream(quicly_stream_t *qs);
/**
 * returns a frame header (if BODY frame) or an entire frame
 */
int h2o_http3_read_frame(h2o_http3_read_frame_t *frame, const uint8_t **src, const uint8_t *src_end, const char **err_desc);
/**
 * initializes the context
 */
void h2o_http3_init_context(h2o_http3_ctx_t *ctx, h2o_loop_t *loop, h2o_socket_t *sock, quicly_context_t *quic,
                            h2o_http3_accept_cb acceptor);
/**
 * initializes a hq connection
 */
void h2o_http3_init_conn(h2o_http3_conn_t *conn, h2o_http3_ctx_t *ctx,
                         h2o_http3_handle_control_stream_frame_cb handle_control_stream_frame);
/**
 *
 */
void h2o_http3_dispose_conn(h2o_http3_conn_t *conn);
/**
 *
 */
int h2o_http3_setup(h2o_http3_conn_t *conn, quicly_conn_t *quic);
/**
 * sends packets immediately by calling quicly_send, sendmsg
 */
void h2o_http3_send(h2o_http3_conn_t *conn);
/**
 * updates receive buffer
 */
int h2o_http3_update_recvbuf(h2o_buffer_t **buf, size_t off, const void *src, size_t len);
/**
 * Schedules the transport timer. Application must call this function when it writes data to the connection (TODO better way to
 * handle this?). The function is automatically called when packets are sent or received.
 */
void h2o_http3_schedule_timer(h2o_http3_conn_t *conn);
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
 *
 */
static int h2o_http3_has_received_settings(h2o_http3_conn_t *conn);

/* inline definitions */

inline int h2o_http3_has_received_settings(h2o_http3_conn_t *conn)
{
    return conn->qpack.enc != NULL;
}

#endif
