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

#define QUICLY_NUM_PACKETS_BEFORE_ACK 2
#define QUICLY_DELAYED_ACK_TIMEOUT 25   /* milliseconds */
#define QUICLY_DEFAULT_MAX_ACK_DELAY 25 /* milliseconds */
#define QUICLY_LOCAL_MAX_ACK_DELAY 25   /* milliseconds */
#define QUICLY_DEFAULT_ACK_DELAY_EXPONENT 3
#define QUICLY_LOCAL_ACK_DELAY_EXPONENT 10
#define QUICLY_DEFAULT_MIN_PTO 1 /* milliseconds */
#define QUICLY_DEFAULT_INITIAL_RTT 100
#define QUICLY_MAX_PTO_COUNT 16 /* 65 seconds under 1ms granurality */

#define QUICLY_MAX_PACKET_SIZE 1280 /* must be >= 1200 bytes */
#define QUICLY_AEAD_TAG_SIZE 16

/* coexists with picotls error codes, assuming that int is at least 32-bits */
#define QUICLY_ERROR_IS_QUIC(e) (((e) & ~0x1ffff) == 0x20000)
#define QUICLY_ERROR_IS_QUIC_TRANSPORT(e) (((e) & ~0xffff) == 0x20000)
#define QUICLY_ERROR_IS_QUIC_APPLICATION(e) (((e) & ~0xffff) == 0x30000)
#define QUICLY_ERROR_GET_ERROR_CODE(e) ((uint16_t)(e))
#define QUICLY_ERROR_FROM_TRANSPORT_ERROR_CODE(e) ((uint16_t)(e) + 0x20000)
#define QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(e) ((uint16_t)(e) + 0x30000)

/* transport error codes */
#define QUICLY_TRANSPORT_ERROR_NONE QUICLY_ERROR_FROM_TRANSPORT_ERROR_CODE(0x0)
#define QUICLY_TRANSPORT_ERROR_INTERNAL QUICLY_ERROR_FROM_TRANSPORT_ERROR_CODE(0x1)
#define QUICLY_TRANSPORT_ERROR_SERVER_BUSY QUICLY_ERROR_FROM_TRANSPORT_ERROR_CODE(0x2)
#define QUICLY_TRANSPORT_ERROR_FLOW_CONTROL QUICLY_ERROR_FROM_TRANSPORT_ERROR_CODE(0x3)
#define QUICLY_TRANSPORT_ERROR_STREAM_ID QUICLY_ERROR_FROM_TRANSPORT_ERROR_CODE(0x4)
#define QUICLY_TRANSPORT_ERROR_STREAM_STATE QUICLY_ERROR_FROM_TRANSPORT_ERROR_CODE(0x5)
#define QUICLY_TRANSPORT_ERROR_FINAL_OFFSET QUICLY_ERROR_FROM_TRANSPORT_ERROR_CODE(0x6)
#define QUICLY_TRANSPORT_ERROR_FRAME_ENCODING QUICLY_ERROR_FROM_TRANSPORT_ERROR_CODE(0x7)
#define QUICLY_TRANSPORT_ERROR_TRANSPORT_PARAMETER QUICLY_ERROR_FROM_TRANSPORT_ERROR_CODE(0x8)
#define QUICLY_TRANSPORT_ERROR_VERSION_NEGOTIATION QUICLY_ERROR_FROM_TRANSPORT_ERROR_CODE(0x9)
#define QUICLY_TRANSPORT_ERROR_PROTOCOL_VIOLATION QUICLY_ERROR_FROM_TRANSPORT_ERROR_CODE(0xa)
#define QUICLY_TRANSPORT_ERROR_INVALID_MIGRATION QUICLY_ERROR_FROM_TRANSPORT_ERROR_CODE(0xc)
#define QUICLY_TRANSPORT_ERROR_TLS_ALERT_BASE QUICLY_ERROR_FROM_TRANSPORT_ERROR_CODE(0x100)

/* internal error codes, used purely for signaling status to the application */
#define QUICLY_ERROR_PACKET_IGNORED 0xff01
#define QUICLY_ERROR_SENDBUF_FULL 0xff02    /* internal use only; the error code is never exposed to the application */
#define QUICLY_ERROR_FREE_CONNECTION 0xff03 /* returned by quicly_send when the connection is freeable */
#define QUICLY_ERROR_RECEIVED_STATELESS_RESET 0xff04

#define QUICLY_BUILD_ASSERT(condition) ((void)sizeof(char[2 * !!(!__builtin_constant_p(condition) || (condition)) - 1]))

typedef int64_t quicly_stream_id_t;

#ifdef __cplusplus
}
#endif

#endif
