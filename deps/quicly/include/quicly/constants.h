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
#ifndef quicly_constants_h
#define quicly_constants_h

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include "picotls.h"

#define QUICLY_DELAYED_ACK_TIMEOUT 25   /* milliseconds */
#define QUICLY_DEFAULT_MAX_ACK_DELAY 25 /* milliseconds */
#define QUICLY_LOCAL_MAX_ACK_DELAY 25   /* milliseconds */
#define QUICLY_DEFAULT_ACK_DELAY_EXPONENT 3
#define QUICLY_LOCAL_ACK_DELAY_EXPONENT 10
#define QUICLY_MIN_INITIAL_DCID_LEN 8
#define QUICLY_DEFAULT_ACTIVE_CONNECTION_ID_LIMIT 2 /* If this transport parameter is absent, a default of 2 is assumed. (18.2) */
/**
 * how many CIDs is quicly willing to manage at the same time?
 * this value is used in two ways:
 * - active_connection_id_limit transport parameter advertised to the remote peer
 * - maximum number of connection IDs we issue to the remote peer at a moment
 */
#define QUICLY_LOCAL_ACTIVE_CONNECTION_ID_LIMIT 4
#define QUICLY_MIN_ACTIVE_CONNECTION_ID_LIMIT 2
#define QUICLY_DEFAULT_MAX_UDP_PAYLOAD_SIZE 65527
#define QUICLY_MIN_CLIENT_INITIAL_SIZE 1200
#define QUICLY_DEFAULT_MIN_PTO 1      /* milliseconds */
#define QUICLY_DEFAULT_INITIAL_RTT 66 /* initial retransmission timeout is *3, i.e. 200ms */
#define QUICLY_LOSS_DEFAULT_PACKET_THRESHOLD 3

#define QUICLY_DEFAULT_PACKET_TOLERANCE 2
#define QUICLY_MAX_PACKET_TOLERANCE 100
#define QUICLY_FIRST_ACK_FREQUENCY_PACKET_NUMBER 1000
#define QUICLY_ACK_FREQUENCY_CWND_FRACTION 8

#define QUICLY_AEAD_TAG_SIZE 16

#define QUICLY_MAX_CID_LEN_V1 20
#define QUICLY_STATELESS_RESET_TOKEN_LEN 16

#define QUICLY_EPOCH_INITIAL 0
#define QUICLY_EPOCH_0RTT 1
#define QUICLY_EPOCH_HANDSHAKE 2
#define QUICLY_EPOCH_1RTT 3
#define QUICLY_NUM_EPOCHS 4

/* coexists with picotls error codes, assuming that int is at least 32-bits */
#define QUICLY_ERROR_IS_QUIC(e) (((e) & ~0x1ffff) == 0x20000)
#define QUICLY_ERROR_IS_QUIC_TRANSPORT(e) (((e) & ~0xffff) == 0x20000)
#define QUICLY_ERROR_IS_QUIC_APPLICATION(e) (((e) & ~0xffff) == 0x30000)
#define QUICLY_ERROR_GET_ERROR_CODE(e) ((uint16_t)(e))
#define QUICLY_ERROR_FROM_TRANSPORT_ERROR_CODE(e) ((uint16_t)(e) + 0x20000)
#define QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(e) ((uint16_t)(e) + 0x30000)
/**
 * PTLS_ERROR_NO_MEMORY and QUICLY_ERROR_STATE_EXHAUSTION are special error codes that are internal but can be passed to
 * quicly_close. These are converted to QUICLY_TRANSPORT_ERROR_INTERNAL when sent over the wire.
 */
#define QUICLY_ERROR_IS_CONCEALED(err) ((err) == PTLS_ERROR_NO_MEMORY || (err) == QUICLY_ERROR_STATE_EXHAUSTION)

/* transport error codes */
#define QUICLY_TRANSPORT_ERROR_NONE QUICLY_ERROR_FROM_TRANSPORT_ERROR_CODE(0x0)
#define QUICLY_TRANSPORT_ERROR_INTERNAL QUICLY_ERROR_FROM_TRANSPORT_ERROR_CODE(0x1)
#define QUICLY_TRANSPORT_ERROR_CONNECTION_REFUSED QUICLY_ERROR_FROM_TRANSPORT_ERROR_CODE(0x2)
#define QUICLY_TRANSPORT_ERROR_FLOW_CONTROL QUICLY_ERROR_FROM_TRANSPORT_ERROR_CODE(0x3)
#define QUICLY_TRANSPORT_ERROR_STREAM_LIMIT QUICLY_ERROR_FROM_TRANSPORT_ERROR_CODE(0x4)
#define QUICLY_TRANSPORT_ERROR_STREAM_STATE QUICLY_ERROR_FROM_TRANSPORT_ERROR_CODE(0x5)
#define QUICLY_TRANSPORT_ERROR_FINAL_SIZE QUICLY_ERROR_FROM_TRANSPORT_ERROR_CODE(0x6)
#define QUICLY_TRANSPORT_ERROR_FRAME_ENCODING QUICLY_ERROR_FROM_TRANSPORT_ERROR_CODE(0x7)
#define QUICLY_TRANSPORT_ERROR_TRANSPORT_PARAMETER QUICLY_ERROR_FROM_TRANSPORT_ERROR_CODE(0x8)
#define QUICLY_TRANSPORT_ERROR_CONNECTION_ID_LIMIT QUICLY_ERROR_FROM_TRANSPORT_ERROR_CODE(0x9)
#define QUICLY_TRANSPORT_ERROR_PROTOCOL_VIOLATION QUICLY_ERROR_FROM_TRANSPORT_ERROR_CODE(0xa)
#define QUICLY_TRANSPORT_ERROR_INVALID_TOKEN QUICLY_ERROR_FROM_TRANSPORT_ERROR_CODE(0xb)
#define QUICLY_TRANSPORT_ERROR_APPLICATION QUICLY_ERROR_FROM_TRANSPORT_ERROR_CODE(0xc)
#define QUICLY_TRANSPORT_ERROR_CRYPTO_BUFFER_EXCEEDED QUICLY_ERROR_FROM_TRANSPORT_ERROR_CODE(0xd)
#define QUICLY_TRANSPORT_ERROR_TLS_ALERT_BASE QUICLY_ERROR_FROM_TRANSPORT_ERROR_CODE(0x100)

/* internal error codes, used purely for signaling status to the application */
#define QUICLY_ERROR_PACKET_IGNORED 0xff01
#define QUICLY_ERROR_SENDBUF_FULL 0xff02    /* internal use only; the error code is never exposed to the application */
#define QUICLY_ERROR_FREE_CONNECTION 0xff03 /* returned by quicly_send when the connection is freeable */
#define QUICLY_ERROR_RECEIVED_STATELESS_RESET 0xff04
#define QUICLY_ERROR_NO_COMPATIBLE_VERSION 0xff05
#define QUICLY_ERROR_IS_CLOSING 0xff06 /* indicates that the connection has already entered closing state */
#define QUICLY_ERROR_STATE_EXHAUSTION 0xff07
#define QUICLY_ERROR_INVALID_INITIAL_VERSION 0xff08
#define QUICLY_ERROR_DECRYPTION_FAILED 0xff09

typedef int64_t quicly_stream_id_t;

typedef struct st_quicly_conn_t quicly_conn_t;

/**
 * Used for emitting arbitrary debug message through probes. The debug message might get emitted unescaped as a JSON string,
 * therefore cannot contain characters that are required to be escaped as a JSON string (e.g., `\n`, `"`).
 */
void quicly__debug_printf(quicly_conn_t *conn, const char *function, int line, const char *fmt, ...)
    __attribute__((format(printf, 4, 5)));

#define quicly_debug_printf(conn, ...) quicly__debug_printf((conn), __FUNCTION__, __LINE__, __VA_ARGS__)

#ifdef __cplusplus
}
#endif

#endif
