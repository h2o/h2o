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
#ifndef quicly_frame_h
#define quicly_frame_h

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "picotls.h"
#include "quicly/constants.h"
#include "quicly/ranges.h"

#define QUICLY_FRAME_TYPE_PADDING 0
#define QUICLY_FRAME_TYPE_PING 1
#define QUICLY_FRAME_TYPE_ACK 2
#define QUICLY_FRAME_TYPE_ACK_ECN 3
#define QUICLY_FRAME_TYPE_RESET_STREAM 4 /* RESET_STREAM */
#define QUICLY_FRAME_TYPE_STOP_SENDING 5
#define QUICLY_FRAME_TYPE_CRYPTO 6
#define QUICLY_FRAME_TYPE_NEW_TOKEN 7
#define QUICLY_FRAME_TYPE_STREAM_BASE 8
#define QUICLY_FRAME_TYPE_MAX_DATA 16
#define QUICLY_FRAME_TYPE_MAX_STREAM_DATA 17
#define QUICLY_FRAME_TYPE_MAX_STREAMS_BIDI 18
#define QUICLY_FRAME_TYPE_MAX_STREAMS_UNI 19
#define QUICLY_FRAME_TYPE_DATA_BLOCKED 20
#define QUICLY_FRAME_TYPE_STREAM_DATA_BLOCKED 21
#define QUICLY_FRAME_TYPE_STREAMS_BLOCKED_BIDI 22
#define QUICLY_FRAME_TYPE_STREAMS_BLOCKED_UNI 23
#define QUICLY_FRAME_TYPE_NEW_CONNECTION_ID 24
#define QUICLY_FRAME_TYPE_RETIRE_CONNECTION_ID 25
#define QUICLY_FRAME_TYPE_PATH_CHALLENGE 26
#define QUICLY_FRAME_TYPE_PATH_RESPONSE 27
#define QUICLY_FRAME_TYPE_TRANSPORT_CLOSE 28
#define QUICLY_FRAME_TYPE_APPLICATION_CLOSE 29
#define QUICLY_FRAME_TYPE_HANDSHAKE_DONE 30

#define QUICLY_FRAME_TYPE_STREAM_BITS 0x7
#define QUICLY_FRAME_TYPE_STREAM_BIT_OFF 0x4
#define QUICLY_FRAME_TYPE_STREAM_BIT_LEN 0x2
#define QUICLY_FRAME_TYPE_STREAM_BIT_FIN 0x1

#define QUICLY_MAX_DATA_FRAME_CAPACITY (1 + 8)
#define QUICLY_MAX_STREAM_DATA_FRAME_CAPACITY (1 + 8 + 8)
#define QUICLY_MAX_STREAMS_FRAME_CAPACITY (1 + 8)
#define QUICLY_PING_FRAME_CAPACITY 1
#define QUICLY_RST_FRAME_CAPACITY (1 + 8 + 8 + 8)
#define QUICLY_STREAMS_BLOCKED_FRAME_CAPACITY (1 + 8)
#define QUICLY_STOP_SENDING_FRAME_CAPACITY (1 + 8 + 8)
#define QUICLY_ACK_MAX_GAPS 256
#define QUICLY_ACK_FRAME_CAPACITY (1 + 8 + 8 + 1)
#define QUICLY_PATH_CHALLENGE_FRAME_CAPACITY (1 + 8)
#define QUICLY_STREAM_FRAME_CAPACITY (1 + 8 + 8 + 1)

static uint16_t quicly_decode16(const uint8_t **src);
static uint32_t quicly_decode24(const uint8_t **src);
static uint32_t quicly_decode32(const uint8_t **src);
static uint64_t quicly_decode64(const uint8_t **src);
static uint64_t quicly_decodev(const uint8_t **src, const uint8_t *end);
static uint8_t *quicly_encode16(uint8_t *p, uint16_t v);
static uint8_t *quicly_encode32(uint8_t *p, uint32_t v);
static uint8_t *quicly_encode64(uint8_t *p, uint64_t v);
static uint8_t *quicly_encodev(uint8_t *p, uint64_t v);
static size_t quicly_encodev_capacity(uint64_t v);
static unsigned quicly_clz32(uint32_t v);
static unsigned quicly_clz64(uint64_t v);

typedef struct st_quicly_stream_frame_t {
    uint64_t stream_id;
    unsigned is_fin : 1;
    uint64_t offset;
    ptls_iovec_t data;
} quicly_stream_frame_t;

static int quicly_decode_stream_frame(uint8_t type_flags, const uint8_t **src, const uint8_t *end, quicly_stream_frame_t *frame);
static uint8_t *quicly_encode_crypto_frame_header(uint8_t *dst, uint8_t *dst_end, uint64_t offset, size_t *data_len);
static int quicly_decode_crypto_frame(const uint8_t **src, const uint8_t *end, quicly_stream_frame_t *frame);

static uint8_t *quicly_encode_rst_stream_frame(uint8_t *dst, uint64_t stream_id, uint16_t app_error_code, uint64_t final_offset);

typedef struct st_quicly_rst_stream_frame_t {
    uint64_t stream_id;
    uint16_t app_error_code;
    uint64_t final_offset;
} quicly_reset_stream_frame_t;

static int quicly_decode_reset_stream_frame(const uint8_t **src, const uint8_t *end, quicly_reset_stream_frame_t *frame);

typedef struct st_quicly_transport_close_frame_t {
    uint16_t error_code;
    uint64_t frame_type;
    ptls_iovec_t reason_phrase;
} quicly_transport_close_frame_t;

static int quicly_decode_transport_close_frame(const uint8_t **src, const uint8_t *end, quicly_transport_close_frame_t *frame);

typedef struct st_quicly_application_close_frame_t {
    uint16_t error_code;
    ptls_iovec_t reason_phrase;
} quicly_application_close_frame_t;

static int quicly_decode_application_close_frame(const uint8_t **src, const uint8_t *end, quicly_application_close_frame_t *frame);

static uint8_t *quicly_encode_max_data_frame(uint8_t *dst, uint64_t max_data);

typedef struct st_quicly_max_data_frame_t {
    uint64_t max_data;
} quicly_max_data_frame_t;

static int quicly_decode_max_data_frame(const uint8_t **src, const uint8_t *end, quicly_max_data_frame_t *frame);

static uint8_t *quicly_encode_max_stream_data_frame(uint8_t *dst, uint64_t stream_id, uint64_t max_stream_data);

typedef struct st_quicly_max_stream_data_frame_t {
    uint64_t stream_id;
    uint64_t max_stream_data;
} quicly_max_stream_data_frame_t;

static int quicly_decode_max_stream_data_frame(const uint8_t **src, const uint8_t *end, quicly_max_stream_data_frame_t *frame);

static uint8_t *quicly_encode_max_streams_frame(uint8_t *dst, int uni, uint64_t count);

typedef struct st_quicly_max_streams_frame_t {
    uint64_t count;
} quicly_max_streams_frame_t;

static int quicly_decode_max_streams_frame(const uint8_t **src, const uint8_t *end, quicly_max_streams_frame_t *frame);

#define QUICLY_PATH_CHALLENGE_DATA_LEN 8

uint8_t *quicly_encode_path_challenge_frame(uint8_t *dst, int is_response, const uint8_t *data);

typedef struct st_quicly_path_challenge_frame_t {
    const uint8_t *data;
} quicly_path_challenge_frame_t;

static int quicly_decode_path_challenge_frame(const uint8_t **src, const uint8_t *end, quicly_path_challenge_frame_t *frame);

typedef struct st_quicly_data_blocked_frame_t {
    uint64_t offset;
} quicly_data_blocked_frame_t;

static int quicly_decode_data_blocked_frame(const uint8_t **src, const uint8_t *end, quicly_data_blocked_frame_t *frame);

typedef struct st_quicly_stream_data_blocked_frame_t {
    quicly_stream_id_t stream_id;
    uint64_t offset;
} quicly_stream_data_blocked_frame_t;

static int quicly_decode_stream_data_blocked_frame(const uint8_t **src, const uint8_t *end,
                                                   quicly_stream_data_blocked_frame_t *frame);

static uint8_t *quicly_encode_streams_blocked_frame(uint8_t *dst, int uni, uint64_t count);

typedef struct st_quicly_streams_blocked_frame_t {
    uint64_t count;
} quicly_streams_blocked_frame_t;

static int quicly_decode_streams_blocked_frame(const uint8_t **src, const uint8_t *end, quicly_streams_blocked_frame_t *frame);

typedef struct st_quicly_new_connection_id_frame_t {
    uint64_t sequence;
    uint64_t retire_prior_to;
    ptls_iovec_t cid;
    const uint8_t *stateless_reset_token;
} quicly_new_connection_id_frame_t;

static int quicly_decode_new_connection_id_frame(const uint8_t **src, const uint8_t *end, quicly_new_connection_id_frame_t *frame);

static uint8_t *quicly_encode_stop_sending_frame(uint8_t *dst, uint64_t stream_id, uint16_t app_error_code);

typedef struct st_quicly_stop_sending_frame_t {
    uint64_t stream_id;
    uint16_t app_error_code;
} quicly_stop_sending_frame_t;

static int quicly_decode_stop_sending_frame(const uint8_t **src, const uint8_t *end, quicly_stop_sending_frame_t *frame);

uint8_t *quicly_encode_ack_frame(uint8_t *dst, uint8_t *dst_end, quicly_ranges_t *ranges, uint64_t ack_delay);

typedef struct st_quicly_ack_frame_t {
    uint64_t largest_acknowledged;
    uint64_t smallest_acknowledged;
    uint64_t ack_delay;
    uint64_t num_gaps;
    uint64_t ack_block_lengths[QUICLY_ACK_MAX_GAPS + 1];
    uint64_t gaps[QUICLY_ACK_MAX_GAPS];
} quicly_ack_frame_t;

int quicly_decode_ack_frame(const uint8_t **src, const uint8_t *end, quicly_ack_frame_t *frame, int is_ack_ecn);

static size_t quicly_new_token_frame_capacity(ptls_iovec_t token);
static uint8_t *quicly_encode_new_token_frame(uint8_t *dst, ptls_iovec_t token);

typedef struct st_quicly_new_token_frame_t {
    ptls_iovec_t token;
} quicly_new_token_frame_t;

static int quicly_decode_new_token_frame(const uint8_t **src, const uint8_t *end, quicly_new_token_frame_t *frame);

int quicly_tls_push_varint(ptls_buffer_t *buf, uint64_t v);
int quicly_tls_decode_varint(uint64_t *value, const uint8_t **src, const uint8_t *end);

/* inline definitions */

inline uint16_t quicly_decode16(const uint8_t **src)
{
    uint16_t v = (uint16_t)(*src)[0] << 8 | (*src)[1];
    *src += 2;
    return v;
}

inline uint32_t quicly_decode24(const uint8_t **src)
{
    uint32_t v = (uint32_t)(*src)[0] << 16 | (uint32_t)(*src)[1] << 8 | (uint32_t)(*src)[2];
    *src += 3;
    return v;
}

inline uint32_t quicly_decode32(const uint8_t **src)
{
    uint32_t v = (uint32_t)(*src)[0] << 24 | (uint32_t)(*src)[1] << 16 | (uint32_t)(*src)[2] << 8 | (*src)[3];
    *src += 4;
    return v;
}

inline uint64_t quicly_decode64(const uint8_t **src)
{
    uint64_t v = (uint64_t)(*src)[0] << 56 | (uint64_t)(*src)[1] << 48 | (uint64_t)(*src)[2] << 40 | (uint64_t)(*src)[3] << 32 |
                 (uint64_t)(*src)[4] << 24 | (uint64_t)(*src)[5] << 16 | (uint64_t)(*src)[6] << 8 | (*src)[7];
    *src += 8;
    return v;
}

inline uint64_t quicly_decodev(const uint8_t **src, const uint8_t *end)
{
    if (*src == end)
        return UINT64_MAX;
    if (**src >> 6 == 0)
        return *(*src)++;

    /* multi-byte */
    size_t len = 1 << (**src >> 6);
    if ((size_t)(end - *src) < len)
        return UINT64_MAX;
    uint64_t v = *(*src)++ & 0x3f;
    --len;
    do {
        v = (v << 8) | *(*src)++;
    } while (--len != 0);
    return v;
}

inline uint8_t *quicly_encode16(uint8_t *p, uint16_t v)
{
    *p++ = (uint8_t)(v >> 8);
    *p++ = (uint8_t)v;
    return p;
}

inline uint8_t *quicly_encode32(uint8_t *p, uint32_t v)
{
    *p++ = (uint8_t)(v >> 24);
    *p++ = (uint8_t)(v >> 16);
    *p++ = (uint8_t)(v >> 8);
    *p++ = (uint8_t)v;
    return p;
}

inline uint8_t *quicly_encode64(uint8_t *p, uint64_t v)
{
    *p++ = (uint8_t)(v >> 56);
    *p++ = (uint8_t)(v >> 48);
    *p++ = (uint8_t)(v >> 40);
    *p++ = (uint8_t)(v >> 32);
    *p++ = (uint8_t)(v >> 24);
    *p++ = (uint8_t)(v >> 16);
    *p++ = (uint8_t)(v >> 8);
    *p++ = (uint8_t)v;
    return p;
}

inline uint8_t *quicly_encodev(uint8_t *p, uint64_t v)
{
    if (v > 63) {
        if (v > 16383) {
            if (v > 1073741823) {
                assert(v <= 4611686018427387903);
                *p++ = 0xc0 | (uint8_t)(v >> 56);
                *p++ = (uint8_t)(v >> 48);
                *p++ = (uint8_t)(v >> 40);
                *p++ = (uint8_t)(v >> 32);
                *p++ = (uint8_t)(v >> 24);
            } else {
                *p++ = 0x80 | (uint8_t)(v >> 24);
            }
            *p++ = (uint8_t)(v >> 16);
            *p++ = (uint8_t)(v >> 8);
        } else {
            *p++ = 0x40 | (v >> 8);
        }
    }
    *p++ = (uint8_t)v;
    return p;
}

inline size_t quicly_encodev_capacity(uint64_t v)
{
    if (v > 63) {
        if (v > 16383) {
            if (v > 1073741823)
                return 8;
            return 4;
        }
        return 2;
    }
    return 1;
}

inline unsigned quicly_clz32(uint32_t v)
{
    QUICLY_BUILD_ASSERT(sizeof(unsigned) == 4);
    return v != 0 ? __builtin_clz(v) : 32;
}

inline unsigned quicly_clz64(uint64_t v)
{
    QUICLY_BUILD_ASSERT(sizeof(long long) == 8);
    return v != 0 ? __builtin_clzll(v) : 64;
}

inline int quicly_decode_stream_frame(uint8_t type_flags, const uint8_t **src, const uint8_t *end, quicly_stream_frame_t *frame)
{
    /* obtain stream id */
    if ((frame->stream_id = quicly_decodev(src, end)) == UINT64_MAX)
        goto Error;

    /* obtain offset */
    if ((type_flags & QUICLY_FRAME_TYPE_STREAM_BIT_OFF) != 0) {
        if ((frame->offset = quicly_decodev(src, end)) == UINT64_MAX)
            goto Error;
    } else {
        frame->offset = 0;
    }

    /* obtain data */
    if ((type_flags & QUICLY_FRAME_TYPE_STREAM_BIT_LEN) != 0) {
        uint64_t len;
        if ((len = quicly_decodev(src, end)) == UINT64_MAX)
            goto Error;
        if ((uint64_t)(end - *src) < len)
            goto Error;
        frame->data = ptls_iovec_init(*src, len);
        *src += len;
    } else {
        frame->data = ptls_iovec_init(*src, end - *src);
        *src = end;
    }

    /* fin bit */
    frame->is_fin = (type_flags & QUICLY_FRAME_TYPE_STREAM_BIT_FIN) != 0;

    return 0;
Error:
    return QUICLY_TRANSPORT_ERROR_FRAME_ENCODING;
}

inline uint8_t *quicly_encode_crypto_frame_header(uint8_t *dst, uint8_t *dst_end, uint64_t offset, size_t *data_len)
{
    size_t sizeleft, len_length;

    *dst++ = QUICLY_FRAME_TYPE_CRYPTO;
    dst = quicly_encodev(dst, offset);

    sizeleft = dst_end - dst;
    if (sizeleft <= 64 || *data_len < 64) {
        if (*data_len >= sizeleft)
            *data_len = sizeleft - 1;
        len_length = 1;
    } else {
        if (*data_len > 16383)
            *data_len = 16383;
        len_length = 2;
    }

    if (*data_len > sizeleft - len_length)
        *data_len = sizeleft - len_length;
    dst = quicly_encodev(dst, *data_len);
    return dst;
}

inline int quicly_decode_crypto_frame(const uint8_t **src, const uint8_t *end, quicly_stream_frame_t *frame)
{
    uint64_t len;

    frame->stream_id = 0;
    frame->is_fin = 0;

    if ((frame->offset = quicly_decodev(src, end)) == UINT64_MAX)
        goto Error;
    if ((len = quicly_decodev(src, end)) == UINT64_MAX)
        goto Error;
    if ((uint64_t)(end - *src) < len)
        goto Error;
    frame->data = ptls_iovec_init(*src, len);
    *src += len;

    return 0;
Error:
    return QUICLY_TRANSPORT_ERROR_FRAME_ENCODING;
}

inline uint8_t *quicly_encode_rst_stream_frame(uint8_t *dst, uint64_t stream_id, uint16_t app_error_code, uint64_t final_offset)
{
    *dst++ = QUICLY_FRAME_TYPE_RESET_STREAM;
    dst = quicly_encodev(dst, stream_id);
    dst = quicly_encodev(dst, app_error_code);
    dst = quicly_encodev(dst, final_offset);
    return dst;
}

inline int quicly_decode_reset_stream_frame(const uint8_t **src, const uint8_t *end, quicly_reset_stream_frame_t *frame)
{
    uint64_t error_code;

    if ((frame->stream_id = quicly_decodev(src, end)) == UINT64_MAX)
        goto Error;
    if ((error_code = quicly_decodev(src, end)) == UINT64_MAX)
        goto Error;
    frame->app_error_code = (uint16_t)error_code;
    frame->final_offset = quicly_decodev(src, end);
    return 0;
Error:
    return QUICLY_TRANSPORT_ERROR_FRAME_ENCODING;
}

inline int quicly_decode_application_close_frame(const uint8_t **src, const uint8_t *end, quicly_application_close_frame_t *frame)
{
    uint64_t error_code, reason_len;

    if ((error_code = quicly_decodev(src, end)) == UINT64_MAX)
        goto Error;
    frame->error_code = (uint16_t)error_code;
    if ((reason_len = quicly_decodev(src, end)) == UINT64_MAX)
        goto Error;
    if ((uint64_t)(end - *src) < reason_len)
        goto Error;
    frame->reason_phrase = ptls_iovec_init(*src, reason_len);
    *src += reason_len;
    return 0;
Error:
    return QUICLY_TRANSPORT_ERROR_FRAME_ENCODING;
}

inline int quicly_decode_transport_close_frame(const uint8_t **src, const uint8_t *end, quicly_transport_close_frame_t *frame)
{
    uint64_t error_code, reason_len;

    if ((error_code = quicly_decodev(src, end)) == UINT64_MAX)
        goto Error;
    frame->error_code = (uint16_t)error_code;
    if ((frame->frame_type = quicly_decodev(src, end)) == UINT64_MAX)
        goto Error;
    if ((reason_len = quicly_decodev(src, end)) == UINT64_MAX)
        goto Error;
    if ((uint64_t)(end - *src) < reason_len)
        goto Error;
    frame->reason_phrase = ptls_iovec_init(*src, reason_len);
    *src += reason_len;
    return 0;
Error:
    return QUICLY_TRANSPORT_ERROR_FRAME_ENCODING;
}

inline uint8_t *quicly_encode_max_data_frame(uint8_t *dst, uint64_t max_data)
{
    *dst++ = QUICLY_FRAME_TYPE_MAX_DATA;
    dst = quicly_encodev(dst, max_data);
    return dst;
}

inline int quicly_decode_max_data_frame(const uint8_t **src, const uint8_t *end, quicly_max_data_frame_t *frame)
{
    if ((frame->max_data = quicly_decodev(src, end)) == UINT64_MAX)
        return QUICLY_TRANSPORT_ERROR_FRAME_ENCODING;
    return 0;
}

inline uint8_t *quicly_encode_max_stream_data_frame(uint8_t *dst, uint64_t stream_id, uint64_t max_stream_data)
{
    *dst++ = QUICLY_FRAME_TYPE_MAX_STREAM_DATA;
    dst = quicly_encodev(dst, stream_id);
    dst = quicly_encodev(dst, max_stream_data);
    return dst;
}

inline int quicly_decode_max_stream_data_frame(const uint8_t **src, const uint8_t *end, quicly_max_stream_data_frame_t *frame)
{
    if ((frame->stream_id = quicly_decodev(src, end)) == UINT64_MAX)
        goto Error;
    if ((frame->max_stream_data = quicly_decodev(src, end)) == UINT64_MAX)
        goto Error;
    return 0;
Error:
    return QUICLY_TRANSPORT_ERROR_FRAME_ENCODING;
}

inline uint8_t *quicly_encode_max_streams_frame(uint8_t *dst, int uni, uint64_t count)
{
    *dst++ = uni ? QUICLY_FRAME_TYPE_MAX_STREAMS_UNI : QUICLY_FRAME_TYPE_MAX_STREAMS_BIDI;
    dst = quicly_encodev(dst, count);
    return dst;
}

inline int quicly_decode_max_streams_frame(const uint8_t **src, const uint8_t *end, quicly_max_streams_frame_t *frame)
{
    if ((frame->count = quicly_decodev(src, end)) == UINT64_MAX)
        return QUICLY_TRANSPORT_ERROR_FRAME_ENCODING;
    if (frame->count > (uint64_t)1 << 60)
        return QUICLY_TRANSPORT_ERROR_FRAME_ENCODING;
    return 0;
}

inline int quicly_decode_path_challenge_frame(const uint8_t **src, const uint8_t *end, quicly_path_challenge_frame_t *frame)
{
    if (end - *src < 1)
        goto Error;
    if (end - *src < QUICLY_PATH_CHALLENGE_DATA_LEN)
        goto Error;
    frame->data = *src;
    *src += QUICLY_PATH_CHALLENGE_DATA_LEN;
    return 0;
Error:
    return QUICLY_TRANSPORT_ERROR_FRAME_ENCODING;
}

inline int quicly_decode_data_blocked_frame(const uint8_t **src, const uint8_t *end, quicly_data_blocked_frame_t *frame)
{
    if ((frame->offset = quicly_decodev(src, end)) == UINT64_MAX)
        return QUICLY_TRANSPORT_ERROR_FRAME_ENCODING;
    return 0;
}

inline int quicly_decode_stream_data_blocked_frame(const uint8_t **src, const uint8_t *end,
                                                   quicly_stream_data_blocked_frame_t *frame)
{
    if ((frame->stream_id = quicly_decodev(src, end)) == UINT64_MAX)
        goto Error;
    if ((frame->offset = quicly_decodev(src, end)) == UINT64_MAX)
        goto Error;
    return 0;
Error:
    return QUICLY_TRANSPORT_ERROR_FRAME_ENCODING;
}

inline uint8_t *quicly_encode_streams_blocked_frame(uint8_t *dst, int uni, uint64_t count)
{
    *dst++ = uni ? QUICLY_FRAME_TYPE_STREAMS_BLOCKED_UNI : QUICLY_FRAME_TYPE_STREAMS_BLOCKED_BIDI;
    dst = quicly_encodev(dst, count);
    return dst;
}

inline int quicly_decode_streams_blocked_frame(const uint8_t **src, const uint8_t *end, quicly_streams_blocked_frame_t *frame)
{
    if ((frame->count = quicly_decodev(src, end)) == UINT64_MAX)
        return QUICLY_TRANSPORT_ERROR_FRAME_ENCODING;
    if (frame->count > (uint64_t)1 << 60)
        return QUICLY_TRANSPORT_ERROR_FRAME_ENCODING;
    return 0;
}

inline int quicly_decode_new_connection_id_frame(const uint8_t **src, const uint8_t *end, quicly_new_connection_id_frame_t *frame)
{
    /* sequence */
    if ((frame->sequence = quicly_decodev(src, end)) == UINT64_MAX)
        goto Fail;
    if ((frame->retire_prior_to = quicly_decodev(src, end)) == UINT64_MAX)
        goto Fail;
    if (end - *src < 1)
        goto Fail;

    { /* cid */
        uint8_t cid_len = *(*src)++;
        if (!(1 <= cid_len && cid_len <= QUICLY_MAX_CID_LEN_V1))
            goto Fail;
        frame->cid = ptls_iovec_init(src, cid_len);
        *src += cid_len;
    }

    /* stateless reset token */
    if (end - *src < QUICLY_STATELESS_RESET_TOKEN_LEN)
        goto Fail;
    frame->stateless_reset_token = *src;
    *src += QUICLY_STATELESS_RESET_TOKEN_LEN;

    return 0;
Fail:
    return QUICLY_TRANSPORT_ERROR_FRAME_ENCODING;
}

inline uint8_t *quicly_encode_stop_sending_frame(uint8_t *dst, uint64_t stream_id, uint16_t app_error_code)
{
    *dst++ = QUICLY_FRAME_TYPE_STOP_SENDING;
    dst = quicly_encodev(dst, stream_id);
    dst = quicly_encodev(dst, app_error_code);
    return dst;
}

inline int quicly_decode_stop_sending_frame(const uint8_t **src, const uint8_t *end, quicly_stop_sending_frame_t *frame)
{
    uint64_t error_code;

    if ((frame->stream_id = quicly_decodev(src, end)) == UINT64_MAX)
        goto Error;
    if ((error_code = quicly_decodev(src, end)) == UINT64_MAX)
        goto Error;
    frame->app_error_code = (uint16_t)error_code;
    return 0;
Error:
    return QUICLY_TRANSPORT_ERROR_FRAME_ENCODING;
}

inline size_t quicly_new_token_frame_capacity(ptls_iovec_t token)
{
    return 1 + quicly_encodev_capacity(token.len) + token.len;
}

inline uint8_t *quicly_encode_new_token_frame(uint8_t *dst, ptls_iovec_t token)
{
    *dst++ = QUICLY_FRAME_TYPE_NEW_TOKEN;
    dst = quicly_encodev(dst, token.len);
    memcpy(dst, token.base, token.len);
    dst += token.len;
    return dst;
}

inline int quicly_decode_new_token_frame(const uint8_t **src, const uint8_t *end, quicly_new_token_frame_t *frame)
{
    uint64_t token_len;
    if ((token_len = quicly_decodev(src, end)) == UINT64_MAX)
        goto Error;
    if (token_len == 0)
        goto Error;
    if ((uint64_t)(end - *src) < token_len)
        goto Error;
    frame->token = ptls_iovec_init(*src, (size_t)token_len);
    *src += frame->token.len;
    return 0;
Error:
    return QUICLY_TRANSPORT_ERROR_FRAME_ENCODING;
}

#ifdef __cplusplus
}
#endif

#endif
