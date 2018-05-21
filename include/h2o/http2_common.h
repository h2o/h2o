/*
 * Copyright (c) 2018 Fastly Inc, Ichito Nagata
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
#ifndef h2o__foobar_h
#define h2o__foobar_h

#include "h2o/string_.h"
#include "h2o/header.h"
#include "h2o/url.h"
#include "h2o/memory.h"
#include "h2o/cache_digests.h"

#define H2O_HTTP2_SETTINGS_HEADER_TABLE_SIZE 1
#define H2O_HTTP2_SETTINGS_ENABLE_PUSH 2
#define H2O_HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS 3
#define H2O_HTTP2_SETTINGS_INITIAL_WINDOW_SIZE 4
#define H2O_HTTP2_SETTINGS_MAX_FRAME_SIZE 5
#define H2O_HTTP2_SETTINGS_MAX_HEADER_LIST_SIZE 6

/* defined as negated form of the error codes defined in HTTP2-spec section 7 */
#define H2O_HTTP2_ERROR_NONE 0
#define H2O_HTTP2_ERROR_PROTOCOL -1
#define H2O_HTTP2_ERROR_INTERNAL -2
#define H2O_HTTP2_ERROR_FLOW_CONTROL -3
#define H2O_HTTP2_ERROR_SETTINGS_TIMEOUT -4
#define H2O_HTTP2_ERROR_STREAM_CLOSED -5
#define H2O_HTTP2_ERROR_FRAME_SIZE -6
#define H2O_HTTP2_ERROR_REFUSED_STREAM -7
#define H2O_HTTP2_ERROR_CANCEL -8
#define H2O_HTTP2_ERROR_COMPRESSION -9
#define H2O_HTTP2_ERROR_CONNECT -10
#define H2O_HTTP2_ERROR_ENHANCE_YOUR_CALM -11
#define H2O_HTTP2_ERROR_INADEQUATE_SECURITY -12
#define H2O_HTTP2_ERROR_MAX 13
/* end of the HTT2-spec defined errors */
#define H2O_HTTP2_ERROR_INVALID_HEADER_CHAR                                                                                        \
-254 /* an internal value indicating that invalid characters were found in the header name or value */
#define H2O_HTTP2_ERROR_INCOMPLETE -255 /* an internal value indicating that all data is not ready */
#define H2O_HTTP2_ERROR_PROTOCOL_CLOSE_IMMEDIATELY -256

typedef struct st_h2o_http2_settings_t {
    uint32_t header_table_size;
    uint32_t enable_push;
    uint32_t max_concurrent_streams;
    uint32_t initial_window_size;
    uint32_t max_frame_size;
} h2o_http2_settings_t;

extern const h2o_http2_settings_t H2O_HTTP2_SETTINGS_DEFAULT;

int h2o_http2_update_peer_settings(h2o_http2_settings_t *settings, const uint8_t *src, size_t len, const char **err_desc);

typedef struct st_h2o_http2_priority_t {
    int exclusive;
    uint32_t dependency;
    uint16_t weight;
} h2o_http2_priority_t;

extern const h2o_http2_priority_t h2o_http2_default_priority;

/* connection flow control window + alpha */
#define H2O_HTTP2_DEFAULT_OUTBUF_SIZE 81920

/* hpack */

#define H2O_HTTP2_ENCODE_INT_MAX_LENGTH 5

typedef struct st_h2o_hpack_header_table_t {
    /* ring buffer */
    struct st_h2o_hpack_header_table_entry_t *entries;
    size_t num_entries, entry_capacity, entry_start_index;
    /* size and capacities are 32+name_len+value_len (as defined by hpack spec.) */
    size_t hpack_size;
    size_t hpack_capacity;     /* the value set by SETTINGS_HEADER_TABLE_SIZE _and_ dynamic table size update */
    size_t hpack_max_capacity; /* the value set by SETTINGS_HEADER_TABLE_SIZE */
} h2o_hpack_header_table_t;

typedef struct st_h2o_hpack_header_table_entry_t {
    h2o_iovec_t *name;
    h2o_iovec_t *value;
    const char *err_desc; /* the recorded soft error description */
} h2o_hpack_header_table_entry_t;

void h2o_hpack_dispose_header_table(h2o_hpack_header_table_t *header_table);

#define H2O_HPACK_PARSE_HEADERS_METHOD_EXISTS 1
#define H2O_HPACK_PARSE_HEADERS_SCHEME_EXISTS 2
#define H2O_HPACK_PARSE_HEADERS_PATH_EXISTS 4
#define H2O_HPACK_PARSE_HEADERS_AUTHORITY_EXISTS 8

int h2o_hpack_parse_headers(h2o_mem_pool_t *pool, const uint8_t *src, size_t len, h2o_hpack_header_table_t *header_table,
                            const h2o_url_scheme_t **scheme, h2o_iovec_t *authority, h2o_iovec_t *method, h2o_iovec_t *path, h2o_headers_t *headers,
                            int *pseudo_header_exists_map, size_t *content_length, h2o_cache_digests_t **digests,
                            const char **err_desc);
size_t h2o_hpack_encode_string(uint8_t *dst, const char *s, size_t len);
void h2o_hpack_flatten_push_promise(h2o_buffer_t **buf, h2o_hpack_header_table_t *header_table, uint32_t stream_id,
                                    size_t max_frame_size, const h2o_url_scheme_t *scheme, h2o_iovec_t authority, h2o_iovec_t method, h2o_iovec_t path, h2o_headers_t *headers, uint32_t parent_stream_id);
void h2o_hpack_flatten_response(h2o_buffer_t **buf, h2o_hpack_header_table_t *header_table, uint32_t stream_id,
                                size_t max_frame_size, int status, h2o_headers_t headers, const h2o_iovec_t *server_name, size_t content_length);
void h2o_hpack_flatten_request(h2o_buffer_t **buf, h2o_hpack_header_table_t *header_table, uint32_t stream_id,
                               size_t max_frame_size, h2o_iovec_t method, h2o_url_t *url, h2o_headers_t *headers, int is_end_stream);
int h2o_hpack_parse_response_headers(h2o_mem_pool_t *pool, int *status, h2o_headers_t *headers, size_t *content_length, h2o_hpack_header_table_t *header_table,
                                     const uint8_t *src, size_t len, const char **err_desc);
void h2o_hpack_flatten_trailers(h2o_buffer_t **buf, h2o_hpack_header_table_t *header_table, uint32_t stream_id,
                                size_t max_frame_size, h2o_header_t *headers, size_t num_headers);

/* frames */

#define H2O_HTTP2_FRAME_HEADER_SIZE 9

#define H2O_HTTP2_FRAME_TYPE_DATA 0
#define H2O_HTTP2_FRAME_TYPE_HEADERS 1
#define H2O_HTTP2_FRAME_TYPE_PRIORITY 2
#define H2O_HTTP2_FRAME_TYPE_RST_STREAM 3
#define H2O_HTTP2_FRAME_TYPE_SETTINGS 4
#define H2O_HTTP2_FRAME_TYPE_PUSH_PROMISE 5
#define H2O_HTTP2_FRAME_TYPE_PING 6
#define H2O_HTTP2_FRAME_TYPE_GOAWAY 7
#define H2O_HTTP2_FRAME_TYPE_WINDOW_UPDATE 8
#define H2O_HTTP2_FRAME_TYPE_CONTINUATION 9

#define H2O_HTTP2_FRAME_FLAG_END_STREAM 0x1
#define H2O_HTTP2_FRAME_FLAG_ACK 0x1
#define H2O_HTTP2_FRAME_FLAG_END_HEADERS 0x4
#define H2O_HTTP2_FRAME_FLAG_PADDED 0x8
#define H2O_HTTP2_FRAME_FLAG_PRIORITY 0x20

typedef struct st_h2o_http2_frame_t {
    uint32_t length;
    uint8_t type;
    uint8_t flags;
    uint32_t stream_id;
    const uint8_t *payload;
} h2o_http2_frame_t;

typedef struct st_h2o_http2_data_payload_t {
    const uint8_t *data;
    size_t length;
} h2o_http2_data_payload_t;

typedef struct st_h2o_http2_headers_payload_t {
    h2o_http2_priority_t priority;
    const uint8_t *headers;
    size_t headers_len;
} h2o_http2_headers_payload_t;

typedef struct st_h2o_http2_rst_stream_payload_t {
    uint32_t error_code;
} h2o_http2_rst_stream_payload_t;

typedef struct st_h2o_http2_ping_payload_t {
    uint8_t data[8];
} h2o_http2_ping_payload_t;

typedef struct st_h2o_http2_goaway_payload_t {
    uint32_t last_stream_id;
    uint32_t error_code;
    h2o_iovec_t debug_data;
} h2o_http2_goaway_payload_t;

typedef struct st_h2o_http2_window_update_payload_t {
    uint32_t window_size_increment;
} h2o_http2_window_update_payload_t;

uint8_t *h2o_http2_encode_frame_header(uint8_t *dst, size_t length, uint8_t type, uint8_t flags, int32_t stream_id);

#define h2o_http2_encode_rst_stream_frame(buf, stream_id, errnum)                                                                  \
h2o_http2__encode_rst_stream_frame(buf, stream_id, (H2O_BUILD_ASSERT((errnum) > 0), errnum))

void h2o_http2__encode_rst_stream_frame(h2o_buffer_t **buf, uint32_t stream_id, int errnum);
void h2o_http2_encode_ping_frame(h2o_buffer_t **buf, int is_ack, const uint8_t *data);
void h2o_http2_encode_goaway_frame(h2o_buffer_t **buf, uint32_t last_stream_id, int errnum, h2o_iovec_t additional_data);
void h2o_http2_encode_window_update_frame(h2o_buffer_t **buf, uint32_t stream_id, int32_t window_size_increment);
ssize_t h2o_http2_decode_frame(h2o_http2_frame_t *frame, const uint8_t *src, size_t len, size_t max_frame_size, const char **err_desc);
int h2o_http2_decode_data_payload(h2o_http2_data_payload_t *payload, const h2o_http2_frame_t *frame, const char **err_desc);
int h2o_http2_decode_headers_payload(h2o_http2_headers_payload_t *payload, const h2o_http2_frame_t *frame, const char **err_desc);
int h2o_http2_decode_priority_payload(h2o_http2_priority_t *payload, const h2o_http2_frame_t *frame, const char **err_desc);
int h2o_http2_decode_rst_stream_payload(h2o_http2_rst_stream_payload_t *payload, const h2o_http2_frame_t *frame,
                                        const char **err_desc);
int h2o_http2_decode_ping_payload(h2o_http2_ping_payload_t *payload, const h2o_http2_frame_t *frame, const char **err_desc);
int h2o_http2_decode_goaway_payload(h2o_http2_goaway_payload_t *payload, const h2o_http2_frame_t *frame, const char **err_desc);
int h2o_http2_decode_window_update_payload(h2o_http2_window_update_payload_t *paylaod, const h2o_http2_frame_t *frame,
                                           const char **err_desc, int *err_is_stream_level);

typedef struct st_h2o_http2_window_t {
    ssize_t _avail;
} h2o_http2_window_t;

static void h2o_http2_window_init(h2o_http2_window_t *window, uint32_t initial_window_size);
static int h2o_http2_window_update(h2o_http2_window_t *window, ssize_t delta);
static ssize_t h2o_http2_window_get_avail(h2o_http2_window_t *window);
static void h2o_http2_window_consume_window(h2o_http2_window_t *window, size_t bytes);

static h2o_hpack_header_table_entry_t *h2o_hpack_header_table_get(h2o_hpack_header_table_t *table, size_t index);

/* misc */

static uint16_t h2o_http2_decode16u(const uint8_t *src);
static uint32_t h2o_http2_decode24u(const uint8_t *src);
static uint32_t h2o_http2_decode32u(const uint8_t *src);
static uint8_t *h2o_http2_encode24u(uint8_t *dst, uint32_t value);
static uint8_t *h2o_http2_encode32u(uint8_t *dst, uint32_t value);

/* inline definitions */

inline void h2o_http2_window_init(h2o_http2_window_t *window, uint32_t initial_window_size)
{
    window->_avail = initial_window_size;
}

inline int h2o_http2_window_update(h2o_http2_window_t *window, ssize_t delta)
{
    ssize_t v = window->_avail + delta;
    if (v > INT32_MAX)
        return -1;
    window->_avail = v;
    return 0;
}

inline ssize_t h2o_http2_window_get_avail(h2o_http2_window_t *window)
{
    return window->_avail;
}

inline void h2o_http2_window_consume_window(h2o_http2_window_t *window, size_t bytes)
{
    window->_avail -= bytes;
}

inline uint16_t h2o_http2_decode16u(const uint8_t *src)
{
    return (uint16_t)src[0] << 8 | src[1];
}

inline uint32_t h2o_http2_decode24u(const uint8_t *src)
{
    return (uint32_t)src[0] << 16 | (uint32_t)src[1] << 8 | src[2];
}

inline uint32_t h2o_http2_decode32u(const uint8_t *src)
{
    return (uint32_t)src[0] << 24 | (uint32_t)src[1] << 16 | (uint32_t)src[2] << 8 | src[3];
}

inline uint8_t *h2o_http2_encode24u(uint8_t *dst, uint32_t value)
{
    *dst++ = value >> 16;
    *dst++ = value >> 8;
    *dst++ = value;
    return dst;
}

inline uint8_t *h2o_http2_encode32u(uint8_t *dst, uint32_t value)
{
    *dst++ = value >> 24;
    *dst++ = value >> 16;
    *dst++ = value >> 8;
    *dst++ = value;
    return dst;
}

inline h2o_hpack_header_table_entry_t *h2o_hpack_header_table_get(h2o_hpack_header_table_t *table, size_t index)
{
    size_t entry_index = (index + table->entry_start_index) % table->entry_capacity;
    struct st_h2o_hpack_header_table_entry_t *entry = table->entries + entry_index;
    assert(entry->name != NULL);
    return entry;
}

#endif
