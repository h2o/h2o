/*
 * Copyright (c) 2018 Baodong Chen
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
#ifndef h2o__websocketclient_h
#define h2o__websocketclient_h

#ifdef __cplusplus
extern "C" {
#endif

#include <wslay/wslay.h>
#include "h2o.h"
#include "h2o/httpclient.h"

typedef struct st_h2o_websocket_client_conn_t h2o_websocket_client_conn_t;

/* if arg is NULL, the user should close connection by calling h2o_websocket_client_close() */
typedef void (*h2o_websocket_client_msg_callback)(h2o_websocket_client_conn_t *conn, const struct wslay_event_on_msg_recv_arg *arg);

struct st_h2o_websocket_client_conn_t {
    h2o_socket_t *sock;
    wslay_event_context_ptr ws_ctx;
    struct wslay_event_callbacks ws_callbacks;
    void *data;
    h2o_websocket_client_msg_callback cb;
    struct {
        size_t cnt;
        h2o_iovec_t bufs[4];
    } _write_buf;
    int fd;
};

/**
 * fill http headers needed for websocket client hand shake request
 * *fd* is ued for read random bytes for websocket sec key
 * @return number of headers for websocket client
 */
size_t h2o_websocket_client_create_headers(h2o_mem_pool_t *pool, const h2o_url_t *url_parsed, int fd, h2o_header_t **_headers,
                                           char **_sec_websock_key);

/**
 * judge websocket response header from server
 * @return 0 for ok or else -1
 */
int h2o_is_websocket_respheader(int version, int status, const char *sec_websock_key, h2o_header_t *_headers, size_t num_headers);

/**
 * upgrade to websocket connection from http client
 */
h2o_websocket_client_conn_t *h2o_upgrade_to_websocket_client(h2o_httpclient_t *client, void *user_data, int version, int fd,
                                                             h2o_websocket_client_msg_callback cb);
/**
 * close websocket client connection
 */
void h2o_websocket_client_close(h2o_websocket_client_conn_t *conn);

/**
 * process websocket I/O
 */
void h2o_websocket_client_proceed(h2o_websocket_client_conn_t *conn);

#ifdef __cplusplus
}
#endif

#endif
