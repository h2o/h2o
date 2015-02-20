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
#ifndef h2o__websocket_h
#define h2o__websocket_h

#ifdef __cplusplus
extern "C" {
#endif

#include <wslay/wslay.h>
#include "h2o.h"
#include "h2o/http1.h"

typedef struct st_h2o_websocket_conn_t h2o_websocket_conn_t;

/* arg is NULL if the connection has been closed */
typedef void (*h2o_websocket_msg_callback)(h2o_websocket_conn_t *conn, const struct wslay_event_on_msg_recv_arg *arg);

struct st_h2o_websocket_conn_t {
    h2o_socket_t *sock;
    wslay_event_context_ptr ws_ctx;
    struct wslay_event_callbacks ws_callbacks;
    void *data;
    h2o_websocket_msg_callback cb;
    void *_write_buf;
};

int h2o_is_websocket_handshake(h2o_req_t *req, const char **client_key);
void h2o_websocket_create_accept_key(char *dst, const char *client_key);
h2o_websocket_conn_t *h2o_upgrade_to_websocket(h2o_req_t *req, const char *client_key, void *user_data,
                                               h2o_websocket_msg_callback msg_cb);
void h2o_websocket_close(h2o_websocket_conn_t *conn);
void h2o_websocket_proceed(h2o_websocket_conn_t *conn);

#ifdef __cplusplus
}
#endif

#endif
