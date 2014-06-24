#include "h2o.h"
#include "h2o/http2.h"
#include "internal.h"

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

void h2o_http2_settings_init(h2o_http2_settings_t* settings)
{
    settings->header_table_size = 4096;
    settings->enable_push = 1;
    settings->max_concurrent_streams = 100;
    settings->initial_window_size = 65535;
    settings->max_frame_size = 16384;

}

int h2o_http2_settings_set_header_table_size(h2o_http2_settings_t *settings, uint32_t value)
{
    settings->header_table_size = value;
    return 0;
}

int h2o_http2_settings_set_enable_push(h2o_http2_settings_t *settings, uint32_t value)
{
    if (! (value == 0 || value == 1))
        return -1;
    settings->enable_push = value;
    return 0;
}

int h2o_http2_settings_set_max_concurrent_streams(h2o_http2_settings_t *settings, uint32_t value)
{
    settings->max_concurrent_streams = value;
    return 0;
}

int h2o_http2_settings_set_initial_window_size(h2o_http2_settings_t *settings, uint32_t value)
{
    if (value > 0x7fffffff)
        return -1;
    settings->initial_window_size = value;
    return 0;
}

int h2o_http2_settings_set_max_frame_size(h2o_http2_settings_t *settings, uint32_t value)
{
    if (! (16384 <= value && value <= 16777215))
        return -1;
    settings->max_frame_size = value;
    return 0;
}

int h2o_http2_settings_decode_payload(h2o_http2_settings_t* settings, uint8_t* src, size_t len)
{
    h2o_http2_settings_init(settings);

    for (; len >= 6; len -= 6, src += 6) {
        uint16_t identifier = decode16u(src);
        uint32_t value = decode32u(src + 2);
        switch (identifier) {
#define SET(label, func) case H2O_HTTP2_SETTINGS_##label: if (h2o_http2_settings_set_##func(settings, value) != 0) return -1; break
        SET(HEADER_TABLE_SIZE, header_table_size);
        SET(ENABLE_PUSH, enable_push);
        SET(MAX_CONCURRENT_STREAMS, max_concurrent_streams);
        SET(INITIAL_WINDOW_SIZE, initial_window_size);
        SET(MAX_FRAME_SIZE, max_frame_size);
#undef SET
        case H2O_HTTP2_SETTINGS_MAX_HEADER_LIST_SIZE:
            /* ignored */
            break;
        default:
            /* ignore unknown (5.5) */
            break;
        }
    }

    if (len != 0)
        return -1;
    return 0;
}
