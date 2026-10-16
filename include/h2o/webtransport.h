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
#include "quicly/recvstate.h"
#include "quicly/sendstate.h"
#include "quicly/streambuf.h"
#include "h2o/memory.h"

#ifdef __cplusplus
extern "C" {
#endif

struct st_h2o_req_t;

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
 * capsule types (RFC 9297); all but CLOSE_SESSION, DRAIN_SESSION and DATAGRAM are specific to the capsule protocol used by
 * draft-ietf-webtrans-http2 (or to flow control, which is not enabled), and are ignored when WebTransport runs on native HTTP/3
 * streams
 */
#define H2O_WEBTRANSPORT_CAPSULE_DATAGRAM UINT64_C(0x00)
#define H2O_WEBTRANSPORT_CAPSULE_CLOSE_SESSION UINT64_C(0x2843)
#define H2O_WEBTRANSPORT_CAPSULE_DRAIN_SESSION UINT64_C(0x78ae)
#define H2O_WEBTRANSPORT_CAPSULE_PADDING UINT64_C(0x190b4d38)
#define H2O_WEBTRANSPORT_CAPSULE_RESET_STREAM UINT64_C(0x190b4d39)
#define H2O_WEBTRANSPORT_CAPSULE_STOP_SENDING UINT64_C(0x190b4d3a)
#define H2O_WEBTRANSPORT_CAPSULE_STREAM_FIN UINT64_C(0x190b4d3b)
#define H2O_WEBTRANSPORT_CAPSULE_STREAM UINT64_C(0x190b4d3c)
#define H2O_WEBTRANSPORT_CAPSULE_MAX_DATA UINT64_C(0x190b4d3d)
#define H2O_WEBTRANSPORT_CAPSULE_MAX_STREAM_DATA UINT64_C(0x190b4d3e)
#define H2O_WEBTRANSPORT_CAPSULE_MAX_STREAMS_BIDI UINT64_C(0x190b4d3f)
#define H2O_WEBTRANSPORT_CAPSULE_MAX_STREAMS_UNI UINT64_C(0x190b4d40)
#define H2O_WEBTRANSPORT_CAPSULE_DATA_BLOCKED UINT64_C(0x190b4d41)
#define H2O_WEBTRANSPORT_CAPSULE_STREAM_DATA_BLOCKED UINT64_C(0x190b4d42)
#define H2O_WEBTRANSPORT_CAPSULE_STREAMS_BLOCKED_BIDI UINT64_C(0x190b4d43)
#define H2O_WEBTRANSPORT_CAPSULE_STREAMS_BLOCKED_UNI UINT64_C(0x190b4d44)

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
 * Appends a capsule whose payload is a sequence of varints (e.g., WT_MAX_STREAM_DATA, WT_RESET_STREAM) to the buffer.
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
 * Decodes the payload of a capsule that consists of exactly `num_fields` varints. Returns zero if successful, or
 * H2O_WEBTRANSPORT_DECODE_INVALID.
 */
int h2o_webtransport_decode_varint_capsule(h2o_iovec_t payload, uint64_t *fields, size_t num_fields);
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

/**
 * The flow control limits carried by the WebTransport-Init header field (draft-ietf-webtrans-http2 section 4.3.2). Each member
 * is left untouched when the corresponding key is absent.
 */
typedef struct st_h2o_webtransport_init_params_t {
    /**
     * `u`: limit for unidirectional streams opened by the recipient of the header field
     */
    uint64_t max_stream_data_uni;
    /**
     * `bl`: limit for bidirectional streams opened by the sender of the header field
     */
    uint64_t max_stream_data_bidi_local;
    /**
     * `br`: limit for bidirectional streams opened by the recipient of the header field
     */
    uint64_t max_stream_data_bidi_remote;
} h2o_webtransport_init_params_t;

/**
 * Parses the field lines of WebTransport-Init, being a Dictionary (RFC 9651). Unknown keys are ignored. Returns zero if
 * successful, or -1 if the field cannot be parsed or if any of the known keys is not a non-negative Integer.
 */
int h2o_webtransport_parse_init_header(const h2o_iovec_t *lines, size_t num_lines, h2o_webtransport_init_params_t *params);

/**
 * Errors being reported through `quicly_error_t`. Application errors are conveyed as
 * `QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(code)`, where `code` is a 32-bit WebTransport application error code, regardless of the
 * underlying transport. The values below occupy the space that is unused by picotls and quicly.
 */
/**
 * the stream is being destroyed because the session has ended (WT_SESSION_GONE on HTTP/3)
 */
#define H2O_WEBTRANSPORT_ERROR_SESSION_GONE ((quicly_error_t)0x2e701)
/**
 * the stream is being discarded because the associated session could not be found (WT_BUFFERED_STREAM_REJECTED on HTTP/3)
 */
#define H2O_WEBTRANSPORT_ERROR_BUFFERED_STREAM_REJECTED ((quicly_error_t)0x2e702)
/**
 * the peer violated the protocol (WT_ERROR on HTTP/2)
 */
#define H2O_WEBTRANSPORT_ERROR_PROTOCOL ((quicly_error_t)0x2e703)
/**
 * the peer violated flow control (WT_FLOW_CONTROL_ERROR on HTTP/2)
 */
#define H2O_WEBTRANSPORT_ERROR_FLOW_CONTROL ((quicly_error_t)0x2e704)
/**
 * the peer sent a capsule for a stream that is in an invalid state (WT_STREAM_STATE_ERROR on HTTP/2)
 */
#define H2O_WEBTRANSPORT_ERROR_STREAM_STATE ((quicly_error_t)0x2e705)
/**
 * the HTTP stream or the connection carrying the session was terminated without a WebTransport-level signal
 */
#define H2O_WEBTRANSPORT_ERROR_TRANSPORT ((quicly_error_t)0x2e706)

/**
 * default flow control limits being advertised
 */
#define H2O_WEBTRANSPORT_DEFAULT_MAX_DATA (4 * 1024 * 1024)
#define H2O_WEBTRANSPORT_DEFAULT_MAX_STREAM_DATA (256 * 1024)
#define H2O_WEBTRANSPORT_DEFAULT_MAX_STREAMS 100

/**
 * The flow control limits of a WebTransport session, as sent in SETTINGS by one endpoint (i.e., `bidi_local` applies to the
 * bidirectional streams opened by the sender of the settings, `bidi_remote` to those opened by the receiver). The number of streams
 * is a cumulative count, as is the case for QUIC.
 */
typedef struct st_h2o_webtransport_settings_t {
    uint64_t max_data;
    uint64_t max_stream_data_uni;
    uint64_t max_stream_data_bidi_local;
    uint64_t max_stream_data_bidi_remote;
    uint64_t max_streams_uni;
    uint64_t max_streams_bidi;
} h2o_webtransport_settings_t;

typedef struct st_h2o_webtransport_session_t h2o_webtransport_session_t;
typedef struct st_h2o_webtransport_stream_t h2o_webtransport_stream_t;

/**
 * Stream-level callbacks, having the same semantics as their counterparts in `quicly_stream_callbacks_t`.
 */
typedef struct st_h2o_webtransport_stream_callbacks_t {
    /**
     * called when the stream is destroyed; `err` is zero if both sides were closed cleanly
     */
    void (*on_destroy)(h2o_webtransport_stream_t *stream, quicly_error_t err);
    /**
     * called when the first `delta` bytes of the data being retained by the application are no longer needed
     */
    void (*on_send_shift)(h2o_webtransport_stream_t *stream, size_t delta);
    /**
     * asks the application to write up to `*len` bytes at offset `off` (relative to the retained data) into `dst`
     */
    void (*on_send_emit)(h2o_webtransport_stream_t *stream, size_t off, void *dst, size_t *len, int *wrote_all);
    /**
     * called when the peer sent STOP_SENDING; the send side has been reset with the same error code when this is invoked
     */
    void (*on_send_stop)(h2o_webtransport_stream_t *stream, quicly_error_t err);
    /**
     * called when data is received; `off` is relative to `recvstate.data_off`
     */
    void (*on_receive)(h2o_webtransport_stream_t *stream, size_t off, const void *src, size_t len);
    /**
     * called when the peer resets the send side
     */
    void (*on_receive_reset)(h2o_webtransport_stream_t *stream, quicly_error_t err);
} h2o_webtransport_stream_callbacks_t;

struct st_h2o_webtransport_stream_t {
    h2o_webtransport_session_t *session;
    /**
     * stream ID, using the numbering of QUIC regardless of the transport
     */
    quicly_stream_id_t stream_id;
    const h2o_webtransport_stream_callbacks_t *callbacks;
    /**
     * send-side state (offsets exclude any framing added by the transport); the application calls `quicly_sendstate_shutdown`
     * then `h2o_webtransport_stream_sync_sendbuf` to close the send side
     */
    quicly_sendstate_t sendstate;
    /**
     * receive-side state (offsets exclude any framing added by the transport)
     */
    quicly_recvstate_t recvstate;
    void *data;
};

typedef struct st_h2o_webtransport_session_callbacks_t {
    /**
     * Called when a stream is opened by either endpoint; the callback sets `stream->callbacks`. Returns zero if successful. When an
     * application error is returned for a stream opened by the peer, the stream is reset and / or STOP_SENDING is sent with that
     * error; other errors close the session. When a non-zero value is returned for a locally opened stream,
     * `h2o_webtransport_open_stream` returns that value.
     */
    quicly_error_t (*on_stream_open)(h2o_webtransport_stream_t *stream);
    /**
     * called when a datagram is received (optional)
     */
    void (*on_receive_datagram)(h2o_webtransport_session_t *session, h2o_iovec_t payload);
    /**
     * called when the peer asks for the session to be drained, or when the server starts shutting down the connection (optional)
     */
    void (*on_drain)(h2o_webtransport_session_t *session);
    /**
     * Called when the session is closed by the peer or due to an error. `err` is an application error when the peer closed the
     * session (being `QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0)` when no error code was provided), or one of the
     * `H2O_WEBTRANSPORT_ERROR_*` values. All streams are destroyed before this callback is invoked. The session object MUST NOT be
     * used once this callback returns.
     */
    void (*on_close)(h2o_webtransport_session_t *session, quicly_error_t err, h2o_iovec_t reason);
} h2o_webtransport_session_callbacks_t;

typedef struct st_h2o_webtransport_backend_t h2o_webtransport_backend_t;

struct st_h2o_webtransport_session_t {
    /**
     * the extended CONNECT request that established the session
     */
    struct st_h2o_req_t *req;
    const h2o_webtransport_session_callbacks_t *callbacks;
    void *data;
    /**
     * internal
     */
    const h2o_webtransport_backend_t *_backend;
};

/**
 * Implementation of the transport-specific operations. The functions are invoked by the `h2o_webtransport_*` wrappers below.
 */
struct st_h2o_webtransport_backend_t {
    quicly_error_t (*open_stream)(h2o_webtransport_session_t *session, h2o_webtransport_stream_t **stream, int unidirectional);
    quicly_error_t (*stream_sync_sendbuf)(h2o_webtransport_stream_t *stream, int activate);
    void (*stream_sync_recvbuf)(h2o_webtransport_stream_t *stream, size_t shift_amount);
    void (*reset_stream)(h2o_webtransport_stream_t *stream, quicly_error_t err);
    void (*request_stop)(h2o_webtransport_stream_t *stream, quicly_error_t err);
    void (*send_datagrams)(h2o_webtransport_session_t *session, h2o_iovec_t *datagrams, size_t num_datagrams);
    void (*drain)(h2o_webtransport_session_t *session);
    void (*close)(h2o_webtransport_session_t *session, uint32_t app_error, h2o_iovec_t reason);
};

/**
 * Operations provided by a protocol layer that carries the streams of WebTransport sessions natively (i.e., HTTP/3). The
 * stream-level operations have the same semantics as those of `h2o_webtransport_backend_t`. The capsules that remain on the
 * extended CONNECT stream (WT_CLOSE_SESSION, WT_DRAIN_SESSION, DATAGRAM) are handled by the core, as are the datagrams.
 */
typedef struct st_h2o_webtransport_native_t {
    quicly_error_t (*open_stream)(h2o_webtransport_session_t *session, h2o_webtransport_stream_t **stream, int unidirectional);
    quicly_error_t (*stream_sync_sendbuf)(h2o_webtransport_stream_t *stream, int activate);
    void (*stream_sync_recvbuf)(h2o_webtransport_stream_t *stream, size_t shift_amount);
    void (*reset_stream)(h2o_webtransport_stream_t *stream, quicly_error_t err);
    void (*request_stop)(h2o_webtransport_stream_t *stream, quicly_error_t err);
    /**
     * Called asynchronously after `h2o_webtransport_accept` returns. The protocol layer starts delivering the streams opened by the
     * peer (including the ones that have been buffered) by calling `on_stream_open`.
     */
    void (*start)(h2o_webtransport_session_t *session);
    /**
     * Called when the session ends. The protocol layer destroys all streams of the session with
     * H2O_WEBTRANSPORT_ERROR_SESSION_GONE, and stops referring to the session.
     */
    void (*detach)(h2o_webtransport_session_t *session);
} h2o_webtransport_native_t;

/**
 * Called by the protocol layer carrying the streams natively, when an error that is fatal to the session is detected (e.g., when
 * `on_stream_open` returned an error that is not an application error). The session is closed, and `detach` is invoked.
 */
void h2o_webtransport_native_error(h2o_webtransport_session_t *session, quicly_error_t err);
/**
 * Returns if the request is an extended CONNECT request that tries to establish a WebTransport session.
 */
int h2o_webtransport_is_request(struct st_h2o_req_t *req);
/**
 * Accepts a WebTransport session by sending a 2xx response. `protocol`, if non-empty, is the protocol chosen from those offered by
 * WT-Available-Protocols (see `h2o_webtransport_select_protocol`), to be sent in WT-Protocol. If the session cannot be established
 * (e.g., WebTransport is not enabled on the connection, or the request is malformed), an error response is sent and NULL is
 * returned.
 */
h2o_webtransport_session_t *h2o_webtransport_accept(struct st_h2o_req_t *req, const h2o_webtransport_session_callbacks_t *callbacks,
                                                    void *data, h2o_iovec_t protocol);
/**
 * Called by the protocol layer when the connection starts shutting down gracefully (i.e., GOAWAY is sent). If the request carries a
 * WebTransport session, WT_DRAIN_SESSION is sent to the peer and `on_drain` is invoked asynchronously so that the application can
 * wind the session down.
 */
void h2o_webtransport_notify_shutdown(struct st_h2o_req_t *req);
/**
 * Opens a stream. `on_stream_open` is invoked before this function returns. If the peer's stream limit has been reached, the
 * stream is opened locally but the transmission is deferred until the peer raises the limit.
 */
static quicly_error_t h2o_webtransport_open_stream(h2o_webtransport_session_t *session, h2o_webtransport_stream_t **stream,
                                                   int unidirectional);
/**
 * Notifies that new data has been added to (`activate` set to non-zero) or removed from the send buffer, like
 * `quicly_stream_sync_sendbuf`.
 */
static quicly_error_t h2o_webtransport_stream_sync_sendbuf(h2o_webtransport_stream_t *stream, int activate);
/**
 * Notifies that `shift_amount` bytes of received data have been consumed, like `quicly_stream_sync_recvbuf`.
 */
static void h2o_webtransport_stream_sync_recvbuf(h2o_webtransport_stream_t *stream, size_t shift_amount);
/**
 * Resets the send side of the stream; `err` must be an application error.
 */
static void h2o_webtransport_reset_stream(h2o_webtransport_stream_t *stream, quicly_error_t err);
/**
 * Asks the peer to stop sending; `err` must be an application error.
 */
static void h2o_webtransport_request_stop(h2o_webtransport_stream_t *stream, quicly_error_t err);
/**
 * Sends datagrams. Datagrams might be dropped.
 */
static void h2o_webtransport_send_datagrams(h2o_webtransport_session_t *session, h2o_iovec_t *datagrams, size_t num_datagrams);
/**
 * Asks the peer to drain the session.
 */
static void h2o_webtransport_drain(h2o_webtransport_session_t *session);
/**
 * Closes the session. All streams are destroyed (with H2O_WEBTRANSPORT_ERROR_SESSION_GONE) before the function returns, and
 * `on_close` is not invoked. The session object MUST NOT be used once this function returns.
 */
static void h2o_webtransport_close(h2o_webtransport_session_t *session, uint32_t app_error, h2o_iovec_t reason);
/**
 * Returns if the stream is unidirectional.
 */
static int h2o_webtransport_stream_is_unidirectional(quicly_stream_id_t stream_id);
/**
 * Returns if the stream was opened by the server.
 */
static int h2o_webtransport_stream_is_server_initiated(quicly_stream_id_t stream_id);
/**
 * Returns if the stream has the send side, when running as a server.
 */
static int h2o_webtransport_stream_has_send_side(h2o_webtransport_stream_t *stream);
/**
 * Returns if the stream has the receive side, when running as a server.
 */
static int h2o_webtransport_stream_has_receive_side(h2o_webtransport_stream_t *stream);

/**
 * A simple stream buffer, being the counterpart of `quicly_streambuf_t`. The functions below assume that `stream->data` points to
 * this structure.
 */
typedef struct st_h2o_webtransport_streambuf_t {
    quicly_sendbuf_t egress;
    ptls_buffer_t ingress;
} h2o_webtransport_streambuf_t;

/**
 * Allocates `sz` bytes (at least the size of `h2o_webtransport_streambuf_t`) and assigns it to `stream->data`.
 */
int h2o_webtransport_streambuf_create(h2o_webtransport_stream_t *stream, size_t sz);
void h2o_webtransport_streambuf_destroy(h2o_webtransport_stream_t *stream, quicly_error_t err);
void h2o_webtransport_streambuf_egress_shift(h2o_webtransport_stream_t *stream, size_t delta);
void h2o_webtransport_streambuf_egress_emit(h2o_webtransport_stream_t *stream, size_t off, void *dst, size_t *len, int *wrote_all);
int h2o_webtransport_streambuf_egress_write(h2o_webtransport_stream_t *stream, const void *src, size_t len);
int h2o_webtransport_streambuf_egress_write_vec(h2o_webtransport_stream_t *stream, quicly_sendbuf_vec_t *vec);
int h2o_webtransport_streambuf_egress_shutdown(h2o_webtransport_stream_t *stream);
void h2o_webtransport_streambuf_ingress_shift(h2o_webtransport_stream_t *stream, size_t delta);
ptls_iovec_t h2o_webtransport_streambuf_ingress_get(h2o_webtransport_stream_t *stream);
/**
 * The concrete function for `on_receive`. Returns zero if successful; upon failure, the stream is reset and STOP_SENDING is sent.
 */
int h2o_webtransport_streambuf_ingress_receive(h2o_webtransport_stream_t *stream, size_t off, const void *src, size_t len);

/* inline definitions */

inline quicly_error_t h2o_webtransport_open_stream(h2o_webtransport_session_t *session, h2o_webtransport_stream_t **stream,
                                                   int unidirectional)
{
    return session->_backend->open_stream(session, stream, unidirectional);
}

inline quicly_error_t h2o_webtransport_stream_sync_sendbuf(h2o_webtransport_stream_t *stream, int activate)
{
    return stream->session->_backend->stream_sync_sendbuf(stream, activate);
}

inline void h2o_webtransport_stream_sync_recvbuf(h2o_webtransport_stream_t *stream, size_t shift_amount)
{
    stream->session->_backend->stream_sync_recvbuf(stream, shift_amount);
}

inline void h2o_webtransport_reset_stream(h2o_webtransport_stream_t *stream, quicly_error_t err)
{
    stream->session->_backend->reset_stream(stream, err);
}

inline void h2o_webtransport_request_stop(h2o_webtransport_stream_t *stream, quicly_error_t err)
{
    stream->session->_backend->request_stop(stream, err);
}

inline void h2o_webtransport_send_datagrams(h2o_webtransport_session_t *session, h2o_iovec_t *datagrams, size_t num_datagrams)
{
    session->_backend->send_datagrams(session, datagrams, num_datagrams);
}

inline void h2o_webtransport_drain(h2o_webtransport_session_t *session)
{
    session->_backend->drain(session);
}

inline void h2o_webtransport_close(h2o_webtransport_session_t *session, uint32_t app_error, h2o_iovec_t reason)
{
    session->_backend->close(session, app_error, reason);
}

inline int h2o_webtransport_stream_is_unidirectional(quicly_stream_id_t stream_id)
{
    return (stream_id & 2) != 0;
}

inline int h2o_webtransport_stream_is_server_initiated(quicly_stream_id_t stream_id)
{
    return (stream_id & 1) != 0;
}

inline int h2o_webtransport_stream_has_send_side(h2o_webtransport_stream_t *stream)
{
    return !h2o_webtransport_stream_is_unidirectional(stream->stream_id) ||
           h2o_webtransport_stream_is_server_initiated(stream->stream_id);
}

inline int h2o_webtransport_stream_has_receive_side(h2o_webtransport_stream_t *stream)
{
    return !h2o_webtransport_stream_is_unidirectional(stream->stream_id) ||
           !h2o_webtransport_stream_is_server_initiated(stream->stream_id);
}

#ifdef __cplusplus
}
#endif

#endif
