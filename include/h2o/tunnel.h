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
typedef struct st_h2o_tunnel_end_t h2o_tunnel_end_t;
typedef void (*h2o_tunnel_end_open_cb)(h2o_tunnel_t *tunnel, h2o_tunnel_end_t *end);
typedef void (*h2o_tunnel_end_write_cb)(h2o_tunnel_t *tunnel, h2o_tunnel_end_t *end, h2o_iovec_t *bufs, size_t bufcnt,
                                        int is_final);
typedef void (*h2o_tunnel_end_peer_write_complete_cb)(h2o_tunnel_t *tunnel, h2o_tunnel_end_t *end, h2o_tunnel_end_t *peer);
typedef void (*h2o_tunnel_end_close_cb)(h2o_tunnel_t *tunnel, h2o_tunnel_end_t *end, const char *err);

struct st_h2o_tunnel_end_t {
    h2o_tunnel_end_open_cb open;
    h2o_tunnel_end_write_cb write;
    h2o_tunnel_end_peer_write_complete_cb peer_write_complete;
    h2o_tunnel_end_close_cb close;
    void *data;
    unsigned shutdowned : 1;
    unsigned sending : 1;
};

struct st_h2o_tunnel_t {
    h2o_context_t *ctx;
    h2o_timeout_entry_t timeout_entry;
    h2o_timeout_t *timeout;
    h2o_tunnel_end_t down;
    h2o_tunnel_end_t up;
    const char *err;
};

h2o_tunnel_t *h2o_tunnel_establish(h2o_context_t *ctx, h2o_tunnel_end_t down, h2o_tunnel_end_t up, h2o_timeout_t *timeout);
void h2o_tunnel_send(h2o_tunnel_t *tunnel, h2o_tunnel_end_t *from, h2o_iovec_t *bufs, size_t bufcnt, int is_final);
void h2o_tunnel_notify_sent(h2o_tunnel_t *tunnel, h2o_tunnel_end_t *from);
void h2o_tunnel_break(h2o_tunnel_t *tunnel, const char *err);

h2o_tunnel_end_t h2o_tunnel_socket_end_init(h2o_socket_t *sock);

#ifdef __cplusplus
}
#endif

#endif
