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
#include "probes_.h"

static void socket_tunnel_on_read(h2o_socket_t *sock, const char *err);

static void socket_tunnel_on_destroy(h2o_tunnel_t *_tunnel)
{
    h2o_socket_tunnel_t *tunnel = (void *)_tunnel;

    H2O_PROBE(TUNNEL_ON_DESTROY, &tunnel->super);

    if (tunnel->_sock != NULL) {
        h2o_socket_close(tunnel->_sock);
        tunnel->_sock = NULL;
    }
    h2o_doublebuffer_dispose(&tunnel->_buf);
    free(tunnel);
}

static void socket_tunnel_on_write_complete(h2o_socket_t *sock, const char *err)
{
    h2o_socket_tunnel_t *tunnel = sock->data;

    H2O_PROBE(TUNNEL_ON_WRITE_COMPLETE, &tunnel->super, err);

    if (err != NULL) {
        h2o_socket_close(tunnel->_sock);
        tunnel->_sock = NULL;
    }

    tunnel->super.on_write_complete(&tunnel->super, err);
}

static void socket_tunnel_on_write(h2o_tunnel_t *_tunnel, const void *bytes, size_t len)
{
    h2o_socket_tunnel_t *tunnel = (void *)_tunnel;

    H2O_PROBE(TUNNEL_WRITE, &tunnel->super, bytes, len);

    h2o_iovec_t vec = h2o_iovec_init(bytes, len);
    h2o_socket_write(tunnel->_sock, &vec, 1, socket_tunnel_on_write_complete);
}

static void call_on_read(h2o_socket_tunnel_t *tunnel, const char *err, const void *bytes, size_t len)
{
    H2O_PROBE(TUNNEL_ON_READ, &tunnel->super, err, bytes, len);
    tunnel->super.on_read(&tunnel->super, err, bytes, len);
}

static void socket_tunnel_proceed_read(h2o_tunnel_t *_tunnel)
{
    h2o_socket_tunnel_t *tunnel = (void *)_tunnel;
    h2o_iovec_t vec;

    /* if something was inflight, retire that */
    if (tunnel->_buf.inflight)
        h2o_doublebuffer_consume(&tunnel->_buf);

    /* send data if any, or start reading from the socket */
    if ((vec = h2o_doublebuffer_prepare(&tunnel->_buf, &tunnel->_sock->input, 65536)).len != 0) {
        call_on_read(tunnel, NULL, vec.base, vec.len);
    } else {
        h2o_socket_read_start(tunnel->_sock, socket_tunnel_on_read);
    }
}

static void socket_tunnel_on_read(h2o_socket_t *sock, const char *err)
{
    h2o_socket_tunnel_t *tunnel = (void *)sock->data;
    assert(!tunnel->_buf.inflight);

    if (err != NULL) {
        h2o_socket_close(tunnel->_sock);
        tunnel->_sock = NULL;
        call_on_read(tunnel, err, NULL, 0);
    } else {
        h2o_socket_read_stop(tunnel->_sock);
        socket_tunnel_proceed_read(&tunnel->super);
    }
}

h2o_socket_tunnel_t *h2o_socket_tunnel_create(h2o_socket_t *sock)
{
    h2o_socket_tunnel_t *tunnel = h2o_mem_alloc(sizeof(*tunnel));

    *tunnel = (struct st_h2o_socket_tunnel_t){
        .super =
            {
                .destroy = socket_tunnel_on_destroy,
                .write_ = socket_tunnel_on_write,
                .proceed_read = socket_tunnel_proceed_read,
            },
        ._sock = sock,
    };
    tunnel->_sock->data = tunnel;
    h2o_doublebuffer_init(&tunnel->_buf, &h2o_socket_buffer_prototype);

    H2O_PROBE(TUNNEL_CREATE, &tunnel->super);

    return tunnel;
}

void h2o_socket_tunnel_start(h2o_socket_tunnel_t *tunnel, size_t bytes_to_consume)
{
    H2O_PROBE(TUNNEL_START, &tunnel->super, bytes_to_consume);

    h2o_buffer_consume(&tunnel->_sock->input, bytes_to_consume);
    h2o_socket_read_stop(tunnel->_sock);
    socket_tunnel_proceed_read(&tunnel->super);
}
