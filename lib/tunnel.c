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
#include <stdio.h>
#include <stdlib.h>
#include "h2o.h"
#include "h2o/tunnel.h"

struct st_h2o_socket_tunnel_t {
    h2o_tunnel_t super;
    h2o_socket_t *sock;
    h2o_doublebuffer_t buf;
};

static void socket_tunnel_on_read(h2o_socket_t *sock, const char *err);

static void socket_tunnel_on_destroy(h2o_tunnel_t *_tunnel)
{
    struct st_h2o_socket_tunnel_t *tunnel = (void *)_tunnel;

    h2o_socket_close(tunnel->sock);
    h2o_doublebuffer_dispose(&tunnel->buf);
    free(tunnel);
}

static void socket_tunnel_on_write_complete(h2o_socket_t *sock, const char *err)
{
    struct st_h2o_socket_tunnel_t *tunnel = sock->data;
    tunnel->super.on_write_complete(&tunnel->super, err);
}

static void socket_tunnel_on_write(h2o_tunnel_t *_tunnel, const void *bytes, size_t len)
{
    struct st_h2o_socket_tunnel_t *tunnel = (void *)_tunnel;

    h2o_iovec_t vec = h2o_iovec_init(bytes, len);
    h2o_socket_write(tunnel->sock, &vec, 1, socket_tunnel_on_write_complete);
}

static void socket_tunnel_proceed_read(h2o_tunnel_t *_tunnel)
{
    struct st_h2o_socket_tunnel_t *tunnel = (void *)_tunnel;
    h2o_iovec_t vec;

    /* if something was inflight, retire that */
    if (tunnel->buf.inflight)
        h2o_doublebuffer_consume(&tunnel->buf);

    /* send data if any, or start reading from the socket */
    if ((vec = h2o_doublebuffer_prepare(&tunnel->buf, &tunnel->sock->input, 65536)).len != 0) {
        tunnel->super.on_read(&tunnel->super, NULL, vec.base, vec.len);
    } else {
        h2o_socket_read_start(tunnel->sock, socket_tunnel_on_read);
    }
}

static void socket_tunnel_on_read(h2o_socket_t *sock, const char *err)
{
    struct st_h2o_socket_tunnel_t *tunnel = (void *)sock->data;
    assert(!tunnel->buf.inflight);

    if (err != NULL) {
        tunnel->super.on_read(&tunnel->super, err, NULL, 0);
    } else {
        h2o_socket_read_stop(tunnel->sock);
        socket_tunnel_proceed_read(&tunnel->super);
    }
}

h2o_tunnel_t *h2o_tunnel_create_from_socket(h2o_socket_t *sock)
{
    struct st_h2o_socket_tunnel_t *tunnel = h2o_mem_alloc(sizeof(*tunnel));

    *tunnel = (struct st_h2o_socket_tunnel_t){
        .super =
            {
                .destroy = socket_tunnel_on_destroy,
                .write_ = socket_tunnel_on_write,
                .proceed_read = socket_tunnel_proceed_read,
            },
        .sock = sock,
    };
    tunnel->sock->data = tunnel;
    h2o_doublebuffer_init(&tunnel->buf, &h2o_socket_buffer_prototype);

    return &tunnel->super;
}

void h2o_tunnel_finish_socket_upgrade(h2o_tunnel_t *_tunnel, size_t bytes_to_consume)
{
    struct st_h2o_socket_tunnel_t *tunnel = (void *)_tunnel;

    assert(tunnel->super.destroy == socket_tunnel_on_destroy ||
           !"only tunnels created by h2o_tunnel_create_from_socket can be upgraded");

    h2o_buffer_consume(&tunnel->sock->input, bytes_to_consume);
    h2o_socket_read_stop(tunnel->sock);
    socket_tunnel_proceed_read(&tunnel->super);
}
