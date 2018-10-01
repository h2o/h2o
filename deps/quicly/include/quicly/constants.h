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

#include <stddef.h>
#include <stdint.h>

#define QUICLY_DELAYED_ACK_TIMEOUT 25 /* milliseconds */

/* transport error codes */
#define QUICLY_ERROR_NONE 0x0
#define QUICLY_ERROR_INTERNAL 0x1
#define QUICLY_ERROR_SERVER_BUSY 0x2
#define QUICLY_ERROR_FLOW_CONTROL 0x3
#define QUICLY_ERROR_STREAM_ID 0x4
#define QUICLY_ERROR_STREAM_STATE 0x5
#define QUICLY_ERROR_FINAL_OFFSET 0x6
#define QUICLY_ERROR_FRAME_ENCODING 0x7
#define QUICLY_ERROR_TRANSPORT_PARAMETER 0x8
#define QUICLY_ERROR_VERSION_NEGOTIATION 0x9
#define QUICLY_ERROR_PROTOCOL_VIOLATION 0xa
#define QUICLY_ERROR_INVALID_MIGRATION 0xc
#define QUICLY_ERROR_IS_TLS_ALERT(n) (((n)&0xff00) == 0x100)
#define QUICLY_ERROR_TO_TLS_ALERT(n) ((n)-0x100)
#define QUICLY_ERROR_FROM_TLS_ALERT(n) ((n) + 0x100)

/* internal errors */
#define QUICLY_ERROR_PACKET_IGNORED 0xff01
#define QUICLY_ERROR_FIN_CLOSED 0xff02
#define QUICLY_ERROR_SENDBUF_FULL 0xff03
#define QUICLY_ERROR_CONNECTION_CLOSED 0xff04
#define QUICLY_ERROR_TOO_MANY_OPEN_STREAMS 0xff05

/* application error codes returned by  */
#define QUICLY_STREAM_ERROR_IS_OPEN -1
#define QUICLY_STREAM_ERROR_FIN_CLOSED -2
#define QUICLY_STREAM_ERROR_STOPPED 0

typedef int32_t quicly_stream_error_t;

#define QUICLY_BUILD_ASSERT(condition) ((void)sizeof(char[2 * !!(!__builtin_constant_p(condition) || (condition)) - 1]))

typedef int64_t quicly_stream_id_t;

#endif
