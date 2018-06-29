/*
 * Copyright (c) 2015 Justin Zhu, DeNA Co., Ltd., Kazuho Oku
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
#ifndef h2o__tunnel_h
#define h2o__tunnel_h

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_h2o_tunnel_t h2o_tunnel_t;
typedef struct st_h2o_tunnel_endpoint_t h2o_tunnel_endpoint_t;
typedef void (*h2o_tunnel_endpoint_open_cb)(h2o_tunnel_t *tunnel, h2o_tunnel_endpoint_t *end);
typedef void (*h2o_tunnel_endpoint_send_cb)(h2o_tunnel_t *tunnel, h2o_tunnel_endpoint_t *end, h2o_iovec_t *bufs, size_t bufcnt,
                                        int is_final);
typedef void (*h2o_tunnel_endpoint_on_peer_send_complete_cb)(h2o_tunnel_t *tunnel, h2o_tunnel_endpoint_t *end, h2o_tunnel_endpoint_t *peer);
typedef void (*h2o_tunnel_endpoint_close_cb)(h2o_tunnel_t *tunnel, h2o_tunnel_endpoint_t *end, const char *err);

typedef struct st_h2o_tunnel_endpoint_callbacks_t {
    /**
     * called when tunnel is initialized
     */
    h2o_tunnel_endpoint_open_cb open;
    /**
     * called when the peer wants to send data to this end
     */
    h2o_tunnel_endpoint_send_cb send;
    /**
     * called when the peer completed to send the data (maybe NULL)
     */
    h2o_tunnel_endpoint_on_peer_send_complete_cb on_peer_send_complete;
    /**
     * called when tunnel gets broken
     */
    h2o_tunnel_endpoint_close_cb close;
} h2o_tunnel_endpoint_callbacks_t;

struct st_h2o_tunnel_endpoint_t {
    const h2o_tunnel_endpoint_callbacks_t *callbacks;
    void *data;
    unsigned shutdowned : 1;
    unsigned sending : 1;
};

struct st_h2o_tunnel_t {
    h2o_context_t *ctx;
    h2o_timeout_entry_t timeout_entry;
    h2o_timeout_t *timeout;
    h2o_tunnel_endpoint_t endpoints[2];
    const char *err;
};

h2o_tunnel_t *h2o_tunnel_establish(h2o_context_t *ctx, const h2o_tunnel_endpoint_callbacks_t *cb1, void *data1, const h2o_tunnel_endpoint_callbacks_t *cb2, void *data2, h2o_timeout_t *timeout);
void h2o_tunnel_send(h2o_tunnel_t *tunnel, h2o_tunnel_endpoint_t *from, h2o_iovec_t *bufs, size_t bufcnt, int is_final);
void h2o_tunnel_notify_sent(h2o_tunnel_t *tunnel, h2o_tunnel_endpoint_t *from);
void h2o_tunnel_break(h2o_tunnel_t *tunnel, const char *err);

extern const h2o_tunnel_endpoint_callbacks_t h2o_tunnel_socket_endpoint_callbacks;

#ifdef __cplusplus
}
#endif

#endif
