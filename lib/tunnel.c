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
#include <stdio.h>
#include <stdlib.h>
#include "h2o.h"
#include "h2o/tunnel.h"

void h2o_tunnel_break(h2o_tunnel_t *tunnel, const char *err)
{
    h2o_timeout_unlink(&tunnel->timeout_entry);

    tunnel->down.close(tunnel, &tunnel->down, err);
    tunnel->up.close(tunnel, &tunnel->up, err);

    free(tunnel);
}

void h2o_tunnel_reset_timeout(h2o_tunnel_t *tunnel)
{
    h2o_timeout_unlink(&tunnel->timeout_entry);
    h2o_timeout_link(tunnel->ctx->loop, tunnel->timeout, &tunnel->timeout_entry);
}

static void on_timeout(h2o_timeout_entry_t *entry)
{
    h2o_tunnel_t *tunnel = H2O_STRUCT_FROM_MEMBER(struct st_h2o_tunnel_t, timeout_entry, entry);
    h2o_tunnel_break(tunnel, "tunnel timeout");
}

h2o_tunnel_t *h2o_tunnel_establish(h2o_context_t *ctx, h2o_tunnel_end_t down, h2o_tunnel_end_t up, h2o_timeout_t *timeout)
{
    h2o_tunnel_t *tunnel = h2o_mem_alloc(sizeof(*tunnel));
    tunnel->ctx = ctx;
    tunnel->timeout = timeout;
    tunnel->timeout_entry = (h2o_timeout_entry_t){0};
    tunnel->timeout_entry.cb = on_timeout;
    tunnel->down = down;
    tunnel->up = up;
    h2o_timeout_link(tunnel->ctx->loop, tunnel->timeout, &tunnel->timeout_entry);

    if (tunnel->up.open != NULL)
        tunnel->up.open(tunnel, &tunnel->up);
    if (tunnel->down.open != NULL)
        tunnel->down.open(tunnel, &tunnel->down);

    return tunnel;
}

/* simple socket end */

static void on_socket_read(h2o_socket_t *sock, const char *err)
{
    h2o_tunnel_t *tunnel = sock->data;

    if (err != NULL) {
        h2o_tunnel_break(tunnel, err == h2o_socket_error_closed ? NULL : err);
        return;
    }

    if (sock->bytes_read == 0)
        return;

    h2o_socket_read_stop(sock);
    h2o_tunnel_reset_timeout(tunnel);

    h2o_iovec_t buf;
    buf.base = sock->input->bytes;
    buf.len = sock->input->size;
    h2o_tunnel_end_t *peer = tunnel->down.data == sock ? &tunnel->up : &tunnel->down;
    peer->write(tunnel, peer, &buf, 1);
}

static void on_socket_write_complete(h2o_socket_t *sock, const char *err)
{
    h2o_tunnel_t *tunnel = sock->data;

    if (err != NULL) {
        h2o_tunnel_break(tunnel, err);
        return;
    }

    h2o_tunnel_reset_timeout(tunnel);

    h2o_tunnel_end_t *peer = tunnel->down.data == sock ? &tunnel->up : &tunnel->down;
    h2o_tunnel_end_t *end = tunnel->down.data == sock ? &tunnel->down : &tunnel->up;
    if (peer->peer_write_complete != NULL)
        peer->peer_write_complete(tunnel, peer, end);
}

static void on_socket_end_open(h2o_tunnel_t *tunnel, h2o_tunnel_end_t *end)
{
    h2o_socket_t *sock = end->data;
    sock->data = tunnel;
    if (sock->input->size)
        on_socket_read(sock, NULL);
    h2o_socket_read_start(sock, on_socket_read);
}
static void on_socket_end_write(h2o_tunnel_t *tunnel, h2o_tunnel_end_t *end, h2o_iovec_t *bufs, size_t bufcnt)
{
    h2o_socket_t *sock = end->data;
    h2o_socket_write(sock, bufs, bufcnt, on_socket_write_complete);
}
static void on_socket_end_peer_write_complete(h2o_tunnel_t *tunnel, h2o_tunnel_end_t *end, h2o_tunnel_end_t *peer)
{
    h2o_socket_t *sock = end->data;
    h2o_buffer_consume(&sock->input, sock->input->size);
    h2o_socket_read_start(sock, on_socket_read);
}
static void on_socket_end_close(h2o_tunnel_t *tunnel, h2o_tunnel_end_t *end, const char *err)
{
    h2o_socket_t *sock = end->data;
    h2o_socket_close(sock);
}

h2o_tunnel_end_t h2o_tunnel_socket_end_init(h2o_socket_t *sock)
{
    return (h2o_tunnel_end_t){on_socket_end_open, on_socket_end_write, on_socket_end_peer_write_complete, on_socket_end_close,
                              sock};
}
