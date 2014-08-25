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

void h2o_http2_encode_frame_header(uint8_t *dst, size_t length, uint8_t type, uint8_t flags, int32_t stream_id)
{
    if (length > 0xffffff)
        h2o_fatal("invalid length");
    encode24u(dst, (uint32_t)length);
    dst += 3;
    *dst++ = type;
    *dst++ = flags;
    encode32u(dst, stream_id);
}

ssize_t h2o_http2_decode_frame(h2o_http2_frame_t *frame, const uint8_t *src, size_t len, const h2o_http2_settings_t *host_settings)
{
    if (len < H2O_HTTP2_FRAME_HEADER_SIZE)
        return H2O_HTTP2_DECODE_INCOMPLETE;

    frame->length = decode24u(src);
    frame->type = src[3];
    frame->flags = src[4];
    frame->stream_id = decode32u(src + 5);

    if (frame->length > host_settings->max_frame_size)
        return H2O_HTTP2_DECODE_ERROR;

    if (len < H2O_HTTP2_FRAME_HEADER_SIZE + frame->length)
        return H2O_HTTP2_DECODE_INCOMPLETE;

    frame->payload = src + H2O_HTTP2_FRAME_HEADER_SIZE;

    return H2O_HTTP2_FRAME_HEADER_SIZE + frame->length;
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

int h2o_http2_decode_window_update_payload(h2o_http2_window_update_payload_t *payload, const h2o_http2_frame_t *frame)
{
    if (frame->length != 4)
        return -1;

    payload->window_size_increment = decode32u(frame->payload) & 0x7fffffff;

    return 0;
}
