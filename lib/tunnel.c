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

static void break_now(h2o_tunnel_t *tunnel)
{
    h2o_timeout_unlink(&tunnel->timeout_entry);
    tunnel->endpoints[0].callbacks->on_close(tunnel, &tunnel->endpoints[0], tunnel->err);
    tunnel->endpoints[1].callbacks->on_close(tunnel, &tunnel->endpoints[1], tunnel->err);
    free(tunnel);
}

static int is_sending(h2o_tunnel_t *tunnel)
{
    return tunnel->endpoints[0].sending == 1 || tunnel->endpoints[1].sending == 1;
}

void h2o_tunnel_reset(h2o_tunnel_t *tunnel, const char *err)
{
    tunnel->err = err;
    tunnel->endpoints[0].shutdowned = 1;
    tunnel->endpoints[1].shutdowned = 1;
    if (!is_sending(tunnel)) {
        break_now(tunnel);
    } else {
        /* wait h2o_tunnel_notify_sent to be called */
    }
}

static void reset_timeout(h2o_tunnel_t *tunnel)
{
    h2o_timeout_unlink(&tunnel->timeout_entry);
    h2o_timeout_link(tunnel->ctx->loop, tunnel->timeout, &tunnel->timeout_entry);
}

static void on_timeout(h2o_timeout_entry_t *entry)
{
    h2o_tunnel_t *tunnel = H2O_STRUCT_FROM_MEMBER(struct st_h2o_tunnel_t, timeout_entry, entry);
    h2o_tunnel_reset(tunnel, "tunnel timeout");
}

h2o_tunnel_t *h2o_tunnel_establish(h2o_context_t *ctx, const h2o_tunnel_endpoint_callbacks_t *cb1, void *data1, const h2o_tunnel_endpoint_callbacks_t *cb2, void *data2, h2o_timeout_t *timeout)
{
    h2o_tunnel_t *tunnel = h2o_mem_alloc(sizeof(*tunnel));
    tunnel->ctx = ctx;
    tunnel->timeout = timeout;
    tunnel->timeout_entry = (h2o_timeout_entry_t){0};
    tunnel->timeout_entry.cb = on_timeout;
    tunnel->endpoints[0] = (h2o_tunnel_endpoint_t){cb1, data1};
    tunnel->endpoints[1] = (h2o_tunnel_endpoint_t){cb2, data2};
    tunnel->err = NULL;
    h2o_timeout_link(tunnel->ctx->loop, tunnel->timeout, &tunnel->timeout_entry);

    if (tunnel->endpoints[1].callbacks->on_open != NULL)
        tunnel->endpoints[1].callbacks->on_open(tunnel, &tunnel->endpoints[1]);
    if (tunnel->endpoints[0].callbacks->on_open != NULL)
        tunnel->endpoints[0].callbacks->on_open(tunnel, &tunnel->endpoints[0]);

    return tunnel;
}

void h2o_tunnel_send(h2o_tunnel_t *tunnel, h2o_tunnel_endpoint_t *from, h2o_iovec_t *bufs, size_t bufcnt, int is_final)
{
    reset_timeout(tunnel);
    h2o_tunnel_endpoint_t *to = from == &tunnel->endpoints[0] ? &tunnel->endpoints[1] : &tunnel->endpoints[0];
    if (is_final)
        from->shutdowned = 1;
    to->sending = 1;
    to->callbacks->send(tunnel, to, bufs, bufcnt, is_final);
}

void h2o_tunnel_notify_sent(h2o_tunnel_t *tunnel, h2o_tunnel_endpoint_t *end)
{
    assert(end->sending == 1);
    reset_timeout(tunnel);
    end->sending = 0;
    h2o_tunnel_endpoint_t *peer = end == &tunnel->endpoints[0] ? &tunnel->endpoints[1] : &tunnel->endpoints[0];
    if (peer->callbacks->on_peer_sent != NULL)
        peer->callbacks->on_peer_sent(tunnel, peer, end);

    if (!is_sending(tunnel) && tunnel->endpoints[0].shutdowned && tunnel->endpoints[1].shutdowned)
        break_now(tunnel);
}

/* simple socket end */

static void on_socket_read(h2o_socket_t *sock, const char *err)
{
    h2o_tunnel_t *tunnel = sock->data;

    h2o_tunnel_endpoint_t *end = tunnel->endpoints[0].data == sock ? &tunnel->endpoints[0] : &tunnel->endpoints[1];

    if (err != NULL) {
        h2o_socket_read_stop(sock);
        if (err == h2o_socket_error_closed) {
            h2o_tunnel_send(tunnel, end, NULL, 0, 1);
        } else {
            h2o_tunnel_reset(tunnel, err);
        }
        return;
    }

    if (sock->bytes_read == 0)
        return;

    h2o_socket_read_stop(sock);

    h2o_iovec_t buf;
    buf.base = sock->input->bytes;
    buf.len = sock->input->size;

    h2o_tunnel_send(tunnel, end, &buf, 1, 0);
}

static void on_socket_write_complete(h2o_socket_t *sock, const char *err)
{
    h2o_tunnel_t *tunnel = sock->data;

    if (err != NULL) {
        h2o_tunnel_reset(tunnel, err);
        return;
    }

    h2o_tunnel_endpoint_t *end = tunnel->endpoints[0].data == sock ? &tunnel->endpoints[0] : &tunnel->endpoints[1];
    h2o_tunnel_notify_sent(tunnel, end);
}

static void socket_endpoint_on_open(h2o_tunnel_t *tunnel, h2o_tunnel_endpoint_t *end)
{
    h2o_socket_t *sock = end->data;
    sock->data = tunnel;
    if (sock->input->size)
        on_socket_read(sock, NULL);
    h2o_socket_read_start(sock, on_socket_read);
}
static void socket_endpoint_send(h2o_tunnel_t *tunnel, h2o_tunnel_endpoint_t *end, h2o_iovec_t *bufs, size_t bufcnt, int is_final)
{
    h2o_socket_t *sock = end->data;
    if (bufcnt != 0)
        h2o_socket_write(sock, bufs, bufcnt, on_socket_write_complete);
    if (is_final)
        h2o_socket_shutdown(sock);
    if (bufcnt == 0)
        h2o_tunnel_notify_sent(tunnel, end);
}
static void socket_endpoint_on_notify_peer_sent(h2o_tunnel_t *tunnel, h2o_tunnel_endpoint_t *end, h2o_tunnel_endpoint_t *peer)
{
    h2o_socket_t *sock = end->data;
    h2o_buffer_consume(&sock->input, sock->input->size);
    h2o_socket_read_start(sock, on_socket_read);
}
static void socket_endpoint_on_close(h2o_tunnel_t *tunnel, h2o_tunnel_endpoint_t *end, const char *err)
{
    h2o_socket_t *sock = end->data;
    h2o_socket_close(sock);
}

const h2o_tunnel_endpoint_callbacks_t h2o_tunnel_socket_endpoint_callbacks = {
    socket_endpoint_on_open,
    socket_endpoint_send,
    socket_endpoint_on_notify_peer_sent,
    socket_endpoint_on_close,
};
