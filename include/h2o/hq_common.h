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
#ifndef h2o__hq_common_h
#define h2o__hq_common_h

#include <string.h>
#include "quicly.h"
#include "h2o/memory.h"
#include "h2o/socket.h"
#include "h2o/qpack.h"

#define H2O_HQ_FRAME_TYPE_DATA 0
#define H2O_HQ_FRAME_TYPE_HEADERS 1
#define H2O_HQ_FRAME_TYPE_PRIORITY 2
#define H2O_HQ_FRAME_TYPE_CANCEL_PUSH 3
#define H2O_HQ_FRAME_TYPE_SETTINGS 4
#define H2O_HQ_FRAME_TYPE_PUSH_PROMISE 5
#define H2O_HQ_FRAME_TYPE_GOAWAY 7
#define H2O_HQ_FRAME_TYPE_MAX_PUSH_ID 13

#define H2O_HQ_SETTINGS_HEADER_TABLE_SIZE 1
#define H2O_HQ_SETTINGS_NUM_PLACEHOLDERS 3
#define H2O_HQ_SETTINGS_MAX_HEADER_LIST_SIZE 6
#define H2O_HQ_SETTINGS_QPACK_BLOCKED_STREAMS 7
#define H2O_HQ_SETTINGS_GREASE_MASK 0xf0f0
#define H2O_HQ_SETTINGS_GREASE_PATTERN 0x0a0a

#define H2O_HQ_ERROR_STOPPING 0
#define H2O_HQ_ERROR_NO_ERROR 1
#define H2O_HQ_ERROR_PUSH_REFUSED 2
#define H2O_HQ_ERROR_INTERNAL 3
#define H2O_HQ_ERROR_PUSH_ALREADY_IN_CACHE 4
#define H2O_HQ_ERROR_REQUEST_CANCELLED 5
#define H2O_HQ_ERROR_INCOMPLETE_REQUEST 6
#define H2O_HQ_ERROR_CONNECT_ERROR 7
#define H2O_HQ_ERROR_EXCESSIVE_LOAD 8
#define H2O_HQ_ERROR_VERSION_FALLBACK 9
#define H2O_HQ_ERROR_WRONG_STREAM 10
#define H2O_HQ_ERROR_PUSH_LIMIT_EXCEEDED 11
#define H2O_HQ_ERROR_DUPLICATE_PUSH 12
#define H2O_HQ_ERROR_UNKNOWN_STREAM_TYPE 13
#define H2O_HQ_ERROR_WRONG_STREAM_COUNT 14
#define H2O_HQ_ERROR_CLOSED_CRITICAL_STREAM 15
#define H2O_HQ_ERROR_WRONG_STREAM_DIRECTION 16
#define H2O_HQ_ERROR_EARLY_RESPONSE 17
#define H2O_HQ_ERROR_GENERAL_PROTOCOL 18
#define H2O_HQ_ERROR_MALFORMED_FRAME(type) (256 + type)
#define H2O_HQ_ERROR_IS_MALFORMED_FRAME(type) (((type) >> 8) == 1)
#define H2O_HQ_ERROR_GET_MALFORMED_FRAME_TYPE(err) ((err)&0xff)

typedef struct st_h2o_hq_conn_t h2o_hq_conn_t;
typedef struct st_h2o_hq_ctx_t h2o_hq_ctx_t;

typedef void (*h2o_hq_accept_cb)(h2o_hq_ctx_t *ctx, quicly_decoded_packet_t *packets, size_t num_packets);

struct st_h2o_hq_ctx_t {
    /**
     * quic context
     */
    quicly_context_t *quic;
    /**
     * qpack context
     */
    h2o_qpack_context_t *qpack;
    /**
     * underlying unbound socket
     */
    h2o_socket_t *sock;
    /**
     * list of connections (FIXME use hash or something)
     */
    h2o_linklist_t conns;
    /**
     * callback to accept new connections (optional)
     */
    h2o_hq_accept_cb acceptor;
};

typedef struct st_h2o_hq_conn_callback_t {
    void (*handle_input)(h2o_hq_conn_t *conn, quicly_decoded_packet_t *packets, size_t num_packets);
} h2o_hq_conn_callbacks_t;

struct st_h2o_hq_conn_t {
    h2o_hq_ctx_t *ctx;
    const h2o_hq_conn_callbacks_t *callbacks;
    h2o_linklist_t conns_link; /* linklist between connections, anchor is h2o_hq_ctx_t::conns */
    h2o_timer_t _timeout;
    quicly_conn_t *quic;
    struct {
        h2o_qpack_encoder_t *enc;
        h2o_qpack_decoder_t *dec;
    } qpack;
};

#define h2o_hq_encode_frame(_pool_, _buf_, _type, _block)                                                                          \
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

/**
 * initializes the context
 */
void h2o_hq_init_context(h2o_hq_ctx_t *ctx, quicly_context_t *quic, h2o_qpack_context_t *qpack, h2o_socket_t *sock,
                         h2o_hq_accept_cb acceptor);
/**
 * initializes a hq connection
 */
void h2o_hq_init_conn(h2o_hq_conn_t *conn, h2o_hq_ctx_t *ctx, const h2o_hq_conn_callbacks_t *callbacks);
/**
 *
 */
void h2o_hq_dispose_conn(h2o_hq_conn_t *conn);
/**
 * sends packets immediately by calling quicly_send, sendmsg
 */
void h2o_hq_send(h2o_hq_conn_t *conn);
/**
 *
 */
void h2o_hq_schedule_timer(h2o_hq_conn_t *conn);

#endif
