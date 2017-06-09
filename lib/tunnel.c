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
#include "h2o/http1.h"
#include "h2o/tunnel.h"

struct st_h2o_tunnel_t {
    h2o_context_t *ctx;
    h2o_timeout_entry_t timeout_entry;
    h2o_timeout_t *timeout;
    h2o_socket_t *sock[2];
};

static void on_write_complete(h2o_socket_t *sock, const char *err);

static void close_connection(struct st_h2o_tunnel_t *tunnel)
{
    h2o_timeout_unlink(&tunnel->timeout_entry);

    h2o_socket_close(tunnel->sock[0]);
    h2o_socket_close(tunnel->sock[1]);

    free(tunnel);
}

static void on_timeout(h2o_timeout_entry_t *entry)
{
    struct st_h2o_tunnel_t *tunnel = H2O_STRUCT_FROM_MEMBER(struct st_h2o_tunnel_t, timeout_entry, entry);
    close_connection(tunnel);
}

static inline void reset_timeout(struct st_h2o_tunnel_t *tunnel)
{
    h2o_timeout_unlink(&tunnel->timeout_entry);
    h2o_timeout_link(tunnel->ctx->loop, tunnel->timeout, &tunnel->timeout_entry);
}

static inline void on_read(h2o_socket_t *sock, const char *err)
{
    struct st_h2o_tunnel_t *tunnel = sock->data;
    h2o_socket_t *dst;
    assert(tunnel != NULL);
    assert(tunnel->sock[0] == sock || tunnel->sock[1] == sock);

    if (err != NULL) {
        close_connection(tunnel);
        return;
    }

    if (sock->bytes_read == 0)
        return;

    h2o_socket_read_stop(sock);
    reset_timeout(tunnel);

    if (tunnel->sock[0] == sock)
        dst = tunnel->sock[1];
    else
        dst = tunnel->sock[0];

    h2o_iovec_t buf;
    buf.base = sock->input->bytes;
    buf.len = sock->input->size;
    h2o_socket_write(dst, &buf, 1, on_write_complete);
}

static void on_write_complete(h2o_socket_t *sock, const char *err)
{
    struct st_h2o_tunnel_t *tunnel = sock->data;
    h2o_socket_t *peer;
    assert(tunnel != NULL);
    assert(tunnel->sock[0] == sock || tunnel->sock[1] == sock);

    if (err != NULL) {
        close_connection(tunnel);
        return;
    }

    reset_timeout(tunnel);

    if (tunnel->sock[0] == sock)
        peer = tunnel->sock[1];
    else
        peer = tunnel->sock[0];

    h2o_buffer_consume(&peer->input, peer->input->size);
    h2o_socket_read_start(peer, on_read);
}

h2o_tunnel_t *h2o_tunnel_establish(h2o_context_t *ctx, h2o_socket_t *sock1, h2o_socket_t *sock2, h2o_timeout_t *timeout)
{
    h2o_tunnel_t *tunnel = h2o_mem_alloc(sizeof(*tunnel));
    tunnel->ctx = ctx;
    tunnel->timeout = timeout;
    tunnel->timeout_entry = (h2o_timeout_entry_t){0};
    tunnel->timeout_entry.cb = on_timeout;
    tunnel->sock[0] = sock1;
    tunnel->sock[1] = sock2;
    sock1->data = tunnel;
    sock2->data = tunnel;
    h2o_timeout_link(tunnel->ctx->loop, tunnel->timeout, &tunnel->timeout_entry);

    /* Bring up the tunnel. Note. Upstream always ready first. */
    if (sock2->input->size)
        on_read(sock2, NULL);
    if (sock1->input->size)
        on_read(sock1, NULL);
    h2o_socket_read_start(sock2, on_read);
    h2o_socket_read_start(sock1, on_read);

    return tunnel;
}

void h2o_tunnel_break(h2o_tunnel_t *tunnel)
{
    close_connection(tunnel);
}
