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
#ifndef h2o__http2_h
#define h2o__http2_h

#ifdef __cplusplus
extern "C" {
#endif

extern const char *h2o_http2_npn_protocols;
extern const h2o_iovec_t *h2o_http2_alpn_protocols;

extern const h2o_protocol_callbacks_t H2O_HTTP2_CALLBACKS;

#define H2O_HTTP2_SETTINGS_HEADER_TABLE_SIZE 1
#define H2O_HTTP2_SETTINGS_ENABLE_PUSH 2
#define H2O_HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS 3
#define H2O_HTTP2_SETTINGS_INITIAL_WINDOW_SIZE 4
#define H2O_HTTP2_SETTINGS_MAX_FRAME_SIZE 5
#define H2O_HTTP2_SETTINGS_MAX_HEADER_LIST_SIZE 6

typedef struct st_h2o_http2_settings_t {
    uint32_t header_table_size;
    uint32_t enable_push;
    uint32_t max_concurrent_streams;
    uint32_t initial_window_size;
    uint32_t max_frame_size;
} h2o_http2_settings_t;

extern const h2o_http2_settings_t H2O_HTTP2_SETTINGS_DEFAULT;
extern const h2o_http2_settings_t H2O_HTTP2_SETTINGS_HOST;

typedef struct st_h2o_http2_priority_t {
    int exclusive;
    uint32_t dependency;
    uint16_t weight;
} h2o_http2_priority_t;

extern const h2o_http2_priority_t h2o_http2_default_priority;

void h2o_http2_accept(h2o_accept_ctx_t *ctx, h2o_socket_t *sock, struct timeval connected_at);
int h2o_http2_handle_upgrade(h2o_req_t *req, struct timeval connected_at);

#ifdef __cplusplus
}
#endif

#endif
