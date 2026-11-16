/*
 * Copyright (c) 2026 Fastly, Inc.
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
#ifndef h2o__webtransport_h
#define h2o__webtransport_h

#include <stddef.h>
#include <stdint.h>
#include "quicly/constants.h"
#include "h2o/memory.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * WebTransport over HTTP/3 (draft-ietf-webtrans-http3-16)
 */
#define H2O_WEBTRANSPORT_H3_SETTINGS_WT_ENABLED UINT64_C(0x2c7cf000)
#define H2O_WEBTRANSPORT_H3_STREAM_TYPE_UNI UINT64_C(0x54)
#define H2O_WEBTRANSPORT_H3_SIGNAL_BIDI UINT64_C(0x41)
#define H2O_WEBTRANSPORT_H3_MAX_SESSION_ID UINT64_C(0x3ffffffffffffffc)
#define H2O_WEBTRANSPORT_H3_MAX_QUARTER_STREAM_ID UINT64_C(0x0fffffffffffffff)
/**
 * maximum size of the header (type + session ID) that precedes the payload of a WebTransport stream
 */
#define H2O_WEBTRANSPORT_H3_MAX_STREAM_PREFIX_SIZE 16
#define H2O_WEBTRANSPORT_H3_ERROR_APPLICATION_FIRST UINT64_C(0x52e4a40fa8db)
#define H2O_WEBTRANSPORT_H3_ERROR_APPLICATION_LAST UINT64_C(0x52e5ac983162)
#define H2O_WEBTRANSPORT_H3_ERROR_BUFFERED_STREAM_REJECTED UINT64_C(0x3994bd84)
#define H2O_WEBTRANSPORT_H3_ERROR_SESSION_GONE UINT64_C(0x170d7b68)
#define H2O_WEBTRANSPORT_H3_ERROR_FLOW_CONTROL UINT64_C(0x045d4487)

/**
 * capsule types (RFC 9297) that are carried on the extended CONNECT stream; others (including those of flow control, which is not
 * enabled) are ignored
 */
#define H2O_WEBTRANSPORT_CAPSULE_DATAGRAM UINT64_C(0x00)
#define H2O_WEBTRANSPORT_CAPSULE_CLOSE_SESSION UINT64_C(0x2843)
#define H2O_WEBTRANSPORT_CAPSULE_DRAIN_SESSION UINT64_C(0x78ae)

/**
 * maximum length of the reason phrase carried by WT_CLOSE_SESSION
 */
#define H2O_WEBTRANSPORT_MAX_CLOSE_REASON_SIZE 1024
/**
 * maximum size of a capsule header (type + length)
 */
#define H2O_WEBTRANSPORT_MAX_CAPSULE_HEADER_SIZE 16

/**
 * return values of the decoders
 */
#define H2O_WEBTRANSPORT_DECODE_INCOMPLETE -1
#define H2O_WEBTRANSPORT_DECODE_INVALID -2

/**
 * Encodes the header that precedes the payload of a WebTransport stream over HTTP/3. `type` must be either
 * H2O_WEBTRANSPORT_H3_STREAM_TYPE_UNI or H2O_WEBTRANSPORT_H3_SIGNAL_BIDI, and `session_id` must be a valid session ID (i.e., a
 * client-initiated bidirectional stream ID). The size of the buffer must be at least H2O_WEBTRANSPORT_H3_MAX_STREAM_PREFIX_SIZE.
 */
uint8_t *h2o_webtransport_encode_stream_prefix(uint8_t *dst, uint64_t type, uint64_t session_id);
/**
 * Decodes the header of a WebTransport stream over HTTP/3, expecting it to start with `type`. Returns zero if successful, or
 * H2O_WEBTRANSPORT_DECODE_INCOMPLETE / _INVALID. `*src` is advanced only when successful.
 */
int h2o_webtransport_decode_stream_prefix(const uint8_t **src, const uint8_t *end, uint64_t type, uint64_t *session_id);
/**
 * Encodes the Quarter Stream ID that prefixes an HTTP/3 datagram. The size of the buffer must be at least 8 bytes.
 */
uint8_t *h2o_webtransport_encode_datagram_prefix(uint8_t *dst, uint64_t quarter_stream_id);
/**
 * Decodes an HTTP/3 datagram, returning the Quarter Stream ID and the payload that follows. Returns zero if successful, or
 * H2O_WEBTRANSPORT_DECODE_INVALID.
 */
int h2o_webtransport_decode_datagram(h2o_iovec_t datagram, uint64_t *quarter_stream_id, h2o_iovec_t *payload);

/**
 * Maps a 32-bit WebTransport application error code to the HTTP/3 error code being sent in RESET_STREAM / STOP_SENDING.
 */
uint64_t h2o_webtransport_h3_error_from_application(uint32_t app_error);
/**
 * Maps an HTTP/3 error code to a WebTransport application error code. Returns zero if successful, or -1 if the code is outside
 * the application range (or is a reserved codepoint within the range).
 */
int h2o_webtransport_h3_error_to_application(uint64_t h3_error, uint32_t *app_error);

/**
 * Returns if the given octets are valid UTF-8 (RFC 3629); overlong encodings, surrogates and values above U+10FFFF are rejected.
 */
int h2o_webtransport_is_valid_utf8(const uint8_t *src, size_t len);

/**
 * Encodes a capsule header. The size of the buffer must be at least H2O_WEBTRANSPORT_MAX_CAPSULE_HEADER_SIZE.
 */
uint8_t *h2o_webtransport_encode_capsule_header(uint8_t *dst, uint64_t type, uint64_t length);
/**
 * Appends a capsule whose payload is a sequence of varints (e.g., WT_DRAIN_SESSION, which has none) to the buffer.
 */
void h2o_webtransport_encode_varint_capsule(h2o_buffer_t **buf, uint64_t type, const uint64_t *fields, size_t num_fields);
/**
 * Appends a WT_CLOSE_SESSION capsule to the buffer. Returns zero if successful, or -1 if the reason is too long or is not valid
 * UTF-8, in which case the buffer is left untouched.
 */
int h2o_webtransport_encode_close_session(h2o_buffer_t **buf, uint32_t app_error, h2o_iovec_t reason);
/**
 * Appends a WT_DRAIN_SESSION capsule to the buffer.
 */
void h2o_webtransport_encode_drain_session(h2o_buffer_t **buf);
/**
 * Decodes a capsule header. Returns zero if successful, or H2O_WEBTRANSPORT_DECODE_INCOMPLETE. `*src` is advanced only when
 * successful.
 */
int h2o_webtransport_decode_capsule_header(const uint8_t **src, const uint8_t *end, uint64_t *type, uint64_t *length);
/**
 * Decodes the payload of a WT_CLOSE_SESSION capsule. `reason` refers to the input. Returns zero if successful, or
 * H2O_WEBTRANSPORT_DECODE_INVALID.
 */
int h2o_webtransport_decode_close_session(h2o_iovec_t payload, uint32_t *app_error, h2o_iovec_t *reason);

typedef enum en_h2o_webtransport_protocol_selection_t {
    H2O_WEBTRANSPORT_PROTOCOL_SELECTED,
    /**
     * the field is absent, or none of the offered protocols is supported
     */
    H2O_WEBTRANSPORT_PROTOCOL_NONE,
    /**
     * the field is not a List of Strings (RFC 9651), in which case the entire field is to be ignored
     */
    H2O_WEBTRANSPORT_PROTOCOL_INVALID
} h2o_webtransport_protocol_selection_t;

/**
 * Selects the protocol from the field lines of WT-Available-Protocols. The members of all lines are treated as one list in the
 * client's order of preference, and the first String that matches one of the `supported` entries wins, in which case its index
 * is stored in `*selected`. The chosen value can be sent in WT-Protocol by using `h2o_encode_sf_string`.
 */
h2o_webtransport_protocol_selection_t h2o_webtransport_select_protocol(const h2o_iovec_t *lines, size_t num_lines,
                                                                       const h2o_iovec_t *supported, size_t num_supported,
                                                                       size_t *selected);

#ifdef __cplusplus
}
#endif

#endif
