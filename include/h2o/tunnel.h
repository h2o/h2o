/*
 * Copyright (c) 2020, 2021 Kazuho Oku, Fastly
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

/**
 * bi-directional stream abstraction; used to represent tunnels created by HTTP (e.g., by successful CONNECT)
 */
typedef struct st_h2o_tunnel_t {
    /**
     * closes the tunnel and discards the object
     */
    void (*destroy)(struct st_h2o_tunnel_t *tunnel);
    /**
     * The write callback. The completion of a write is signalled by the invocation of the on_write callback. Until then, the user
     * must retain the buffer unmodified. As is the case of `h2o_socket_write`, only one write can be inflight at a time.
     */
    void (*write_)(struct st_h2o_tunnel_t *tunnel, const void *bytes, size_t len);
    /**
     * Callback asynchronously invoked by the user in response to `on_read`, to notify that the user has processed all data being
     * provided by the call to the `on_read` callback. Next chunk of data is provided to the user only after this callback is
     * called.
     */
    void (*proceed_read)(struct st_h2o_tunnel_t *tunnel);
    /**
     * User-supplied callback that is used to notify the user the completion of a write.
     */
    void (*on_write_complete)(struct st_h2o_tunnel_t *tunnel, const char *err);
    /**
     * The on-read callback to be set by the user.
     */
    void (*on_read)(struct st_h2o_tunnel_t *tunnel, const char *err, const void *bytes, size_t len);
    /**
     * User data pointer.
     */
    void *data;
} h2o_tunnel_t;

typedef struct st_h2o_socket_tunnel_t {
    h2o_tunnel_t super;
    h2o_socket_t *_sock;
    h2o_doublebuffer_t _buf;
} h2o_socket_tunnel_t;

h2o_socket_tunnel_t *h2o_socket_tunnel_create(h2o_socket_t *sock);
void h2o_socket_tunnel_start(h2o_socket_tunnel_t *tunnel, size_t bytes_to_consume);

#ifdef __cplusplus
}
#endif

#endif
