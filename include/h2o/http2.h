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

#include "http2_common.h"

extern const char *h2o_http2_npn_protocols;
extern const h2o_iovec_t *h2o_http2_alpn_protocols;

extern const h2o_protocol_callbacks_t H2O_HTTP2_CALLBACKS;

/* don't forget to update SERVER_PREFACE when choosing non-default parameters */
#define H2O_HTTP2_SETTINGS_HOST_HEADER_TABLE_SIZE 4096
#define H2O_HTTP2_SETTINGS_HOST_ENABLE_PUSH 0 /* _client_ is never allowed to push */
#define H2O_HTTP2_SETTINGS_HOST_MAX_CONCURRENT_STREAMS 100
#define H2O_HTTP2_SETTINGS_HOST_CONNECTION_WINDOW_SIZE H2O_HTTP2_MAX_STREAM_WINDOW_SIZE
#define H2O_HTTP2_SETTINGS_HOST_STREAM_INITIAL_WINDOW_SIZE H2O_HTTP2_MIN_STREAM_WINDOW_SIZE
#define H2O_HTTP2_SETTINGS_HOST_MAX_FRAME_SIZE 16384

extern __thread h2o_buffer_prototype_t h2o_http2_wbuf_buffer_prototype;

void h2o_http2_accept(h2o_accept_ctx_t *ctx, h2o_socket_t *sock, struct timeval connected_at);
int h2o_http2_handle_upgrade(h2o_req_t *req, struct timeval connected_at);

#ifdef __cplusplus
}
#endif

#endif
