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
#ifndef h2o__http1_h
#define h2o__http1_h

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_h2o_http1_conn_t h2o_http1_conn_t;
typedef void (*h2o_http1_upgrade_cb)(void *user_data, h2o_socket_t *sock, size_t reqsize);

typedef struct st_h2o_http1_finalostream_t {
    h2o_ostream_t super;
    int sent_headers;
    struct {
        void *buf;
        h2o_ostream_pull_cb cb;
    } pull;
} h2o_http1_finalostream_t;

struct st_h2o_http1_conn_t {
    h2o_conn_t super;
    h2o_socket_t *sock;
    /* internal structure */
    h2o_timeout_t *_timeout;
    h2o_timeout_entry_t _timeout_entry;
    size_t _prevreqlen;
    size_t _reqsize;
    struct st_h2o_http1_req_entity_reader *_req_entity_reader;
    h2o_http1_finalostream_t _ostr_final;
    struct {
        void *data;
        h2o_http1_upgrade_cb cb;
    } upgrade;
    /* the HTTP request / response (intentionally placed at the last, since it is a large structure and has it's own ctor) */
    h2o_req_t req;
};

/* http1 */

void h2o_http1_accept(h2o_context_t *ctx, h2o_socket_t *sock);
void h2o_http1_upgrade(h2o_http1_conn_t *conn, h2o_iovec_t *inbufs, size_t inbufcnt, h2o_http1_upgrade_cb on_complete, void *user_data);

#ifdef __cplusplus
}
#endif

#endif
