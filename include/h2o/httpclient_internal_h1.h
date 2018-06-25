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
#ifndef h2o__http1client_h
#define h2o__http1client_h

#ifdef __cplusplus
extern "C" {
#endif

#include "h2o/httpclient_internal.h"
#include "picohttpparser.h"

struct st_h2o_http1client_t {
    struct st_h2o_httpclient_private_t super;
    h2o_socket_t *sock;
    h2o_url_t *_origin;
    h2o_timeout_entry_t _timeout;
    int _method_is_head;
    int _do_keepalive;
    union {
        struct {
            size_t bytesleft;
        } content_length;
        struct {
            struct phr_chunked_decoder decoder;
            size_t bytes_decoded_in_buf;
        } chunked;
    } _body_decoder;
    h2o_socket_cb reader;
    h2o_httpclient_proceed_req_cb proceed_req;
    char _chunk_len_str[(sizeof(H2O_UINT64_LONGEST_HEX_STR) - 1) + 2 + 1]; /* SIZE_MAX in hex + CRLF + '\0' */
    h2o_buffer_t *_body_buf;
    h2o_buffer_t *_body_buf_in_flight;
    unsigned _is_chunked : 1;
    unsigned _body_buf_is_done : 1;
};

void h2o_http1client_on_connect(struct st_h2o_httpclient_private_t *client, h2o_socket_t *sock, h2o_url_t *origin);

#ifdef __cplusplus
}
#endif

#endif
