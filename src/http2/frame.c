/*
 * Copyright (c) 2014 DeNA Co., Ltd.
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
#include "h2o.h"
#include "h2o/http2.h"
#include "internal.h"

const h2o_http2_settings_t H2O_HTTP2_SETTINGS_DEFAULT = {
    /* header_table_size */ 4096,
    /* enable_push */ 1,
    /* max_concurrent_streams */ UINT32_MAX,
    /* initial_window_size */ 65535,
    /* max_frame_size */ 16384
};

int h2o_http2_update_peer_settings(h2o_http2_settings_t *settings, const uint8_t *src, size_t len)
{
    for (; len >= 6; len -= 6, src += 6) {
        uint16_t identifier = decode16u(src);
        uint32_t value = decode32u(src + 2);
        switch (identifier) {
#define SET(label, member, min, max) \
    case H2O_HTTP2_SETTINGS_##label: \
        if (! (min <= value && value <= max)) return -1; \
        settings->member = value; \
        break
        SET(HEADER_TABLE_SIZE, header_table_size, 0, UINT32_MAX);
        SET(ENABLE_PUSH, enable_push, 0, 1);
        SET(MAX_CONCURRENT_STREAMS, max_concurrent_streams, 0, UINT32_MAX);
        SET(INITIAL_WINDOW_SIZE, initial_window_size, 0, 0x7fffffff);
        SET(MAX_FRAME_SIZE, max_frame_size, 16384, 16777215);
#undef SET
        default:
            /* ignore unknown (5.5) */
            break;
        }
    }

    if (len != 0)
        return -1;
    return 0;
}

uint8_t *h2o_http2_encode_frame_header(uint8_t *dst, size_t length, uint8_t type, uint8_t flags, int32_t stream_id)
{
    if (length > 0xffffff)
        h2o_fatal("invalid length");

    dst = encode24u(dst, (uint32_t)length);
    *dst++ = type;
    *dst++ = flags;
    dst = encode32u(dst, stream_id);

    return dst;
}

static uint8_t *allocate_frame(h2o_buf_t *outbuf, h2o_mempool_t *pool, size_t length, uint8_t type, uint8_t flags, int32_t stream_id)
{
    *outbuf = h2o_buf_init(h2o_mempool_alloc(pool, H2O_HTTP2_FRAME_HEADER_SIZE + length), H2O_HTTP2_FRAME_HEADER_SIZE + length);
    return h2o_http2_encode_frame_header((uint8_t*)outbuf->base, length, type, flags, stream_id);
}

h2o_buf_t h2o_http2_encode_rst_stream_frame(h2o_mempool_t *pool, uint32_t stream_id, int errnum)
{
    h2o_buf_t ret;
    uint8_t *dst = allocate_frame(&ret, pool, 4, H2O_HTTP2_FRAME_TYPE_GOAWAY, 0, stream_id);

    dst = encode32u(dst, errnum);

    assert(dst - (uint8_t*)ret.base == ret.len);
    return ret;
}

h2o_buf_t h2o_http2_encode_ping_frame(h2o_mempool_t *pool, int is_ack, const uint8_t *data)
{
    h2o_buf_t ret;
    uint8_t *dst = allocate_frame(&ret, pool, 8, H2O_HTTP2_FRAME_TYPE_PING, is_ack ? H2O_HTTP2_FRAME_FLAG_ACK : 0, 0);

    memcpy(dst, data, 8);
    dst += 8;

    assert(dst - (uint8_t*)ret.base == ret.len);
    return ret;
}

h2o_buf_t h2o_http2_encode_goaway_frame(h2o_mempool_t *pool, uint32_t last_stream_id, int errnum)
{
    h2o_buf_t ret;
    uint8_t *dst = allocate_frame(&ret, pool, 8, H2O_HTTP2_FRAME_TYPE_GOAWAY, 0, 0);

    dst = encode32u(dst, last_stream_id);
    dst = encode32u(dst, errnum);

    assert(dst - (uint8_t*)ret.base == ret.len);
    return ret;
}

h2o_buf_t h2o_http2_encode_window_update_frame(h2o_mempool_t *pool, uint32_t stream_id, int32_t window_size_increment)
{
    h2o_buf_t ret;
    uint8_t *dst = allocate_frame(&ret, pool, 4, H2O_HTTP2_FRAME_TYPE_WINDOW_UPDATE, 0, stream_id);

    dst = encode32u(dst, window_size_increment);

    assert(dst - (uint8_t*)ret.base == ret.len);
    return ret;
}

ssize_t h2o_http2_decode_frame(h2o_http2_frame_t *frame, const uint8_t *src, size_t len, const h2o_http2_settings_t *host_settings)
{
    if (len < H2O_HTTP2_FRAME_HEADER_SIZE)
        return H2O_HTTP2_ERROR_INCOMPLETE;

    frame->length = decode24u(src);
    frame->type = src[3];
    frame->flags = src[4];
    frame->stream_id = decode32u(src + 5);

    if (frame->length > host_settings->max_frame_size)
        return H2O_HTTP2_ERROR_FRAME_SIZE;

    if (len < H2O_HTTP2_FRAME_HEADER_SIZE + frame->length)
        return H2O_HTTP2_ERROR_INCOMPLETE;

    frame->payload = src + H2O_HTTP2_FRAME_HEADER_SIZE;

    return H2O_HTTP2_FRAME_HEADER_SIZE + frame->length;
}

int h2o_http2_decode_data_payload(h2o_http2_data_payload_t *payload, const h2o_http2_frame_t *frame)
{
    if ((frame->flags & H2O_HTTP2_FRAME_FLAG_PADDED) != 0) {
        uint8_t padding_length;
        if (frame->length < 1)
            return -1;
        padding_length = frame->payload[0];
        if (frame->length < 1 + padding_length)
            return -1;
        payload->data = frame->payload + 1;
        payload->length = frame->length - (1 + padding_length);
    } else {
        payload->data = frame->payload;
        payload->length = frame->length;
    }
    return 0;
}

int h2o_http2_decode_headers_payload(h2o_http2_headers_payload_t *payload, const h2o_http2_frame_t *frame)
{
    const uint8_t *src = frame->payload, *src_end = frame->payload + frame->length;

    if ((frame->flags & H2O_HTTP2_FRAME_FLAG_PADDED) != 0) {
        uint32_t padlen;
        if (src == src_end)
            return -1;
        padlen = *src++;
        if (src_end - src < padlen)
            return -1;
        src_end -= padlen;
    }

    if ((frame->flags & H2O_HTTP2_FRAME_FLAG_PRIORITY) != 0) {
        uint32_t u4;
        if (src_end - src < 5)
            return -1;
        u4 = decode32u(src);
        src += 4;
        payload->exclusive = u4 >> 31;
        payload->stream_dependency = u4 & 0x7fffffff;
        payload->weight = (uint16_t)*src++ + 1;
    } else {
        payload->exclusive = 0;
        payload->stream_dependency = 0;
        payload->weight = 0;
    }

    payload->headers = src;
    payload->headers_len = src_end - src;

    return 0;
}

int h2o_http2_decode_rst_stream_payload(h2o_http2_rst_stream_payload_t *payload, const h2o_http2_frame_t *frame)
{
    if (frame->length != sizeof(payload->error_code))
        return -1;

    payload->error_code = decode32u(frame->payload);
    return 0;
}

int h2o_http2_decode_ping_payload(h2o_http2_ping_payload_t *payload, const h2o_http2_frame_t *frame)
{
    if (frame->length != sizeof(payload->data))
        return -1;

    memcpy(payload->data, frame->payload, sizeof(payload->data));
    return 0;
}

int h2o_http2_decode_goaway_payload(h2o_http2_goaway_payload_t *payload, const h2o_http2_frame_t *frame)
{
    if (frame->length < 8)
        return -1;

    payload->last_stream_id = decode32u(frame->payload) & 0x7fffffff;
    payload->error_code = decode32u(frame->payload + 4);
    if ((payload->debug_data.len = frame->length - 8) != 0)
        payload->debug_data.base = (char*)frame->payload + 8;
    else
        payload->debug_data.base = NULL;

    return 0;
}

int h2o_http2_decode_window_update_payload(h2o_http2_window_update_payload_t *payload, const h2o_http2_frame_t *frame)
{
    if (frame->length != 4)
        return -1;

    payload->window_size_increment = decode32u(frame->payload) & 0x7fffffff;
    if (payload->window_size_increment == 0)
        return -1;

    return 0;
}
