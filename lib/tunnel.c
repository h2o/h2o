#include <stdio.h>
#include <stdlib.h>
#include "h2o.h"
#include "h2o/http1.h"
#include "h2o/tunnel.h"

#define MIN_TCP_BUF_SZ 65536

struct st_h2o_tunnel_t {
    h2o_socket_t *sock[2];
};

static void on_write_complete(h2o_socket_t *sock, int status);

static void close_connection(struct st_h2o_tunnel_t *tunnel)
{
    assert(tunnel);
    if (tunnel->sock[0] != NULL)
        h2o_socket_close(tunnel->sock[0]);
    if (tunnel->sock[1] != NULL)
        h2o_socket_close(tunnel->sock[1]);
    free(tunnel);
}

static inline
void on_read(h2o_socket_t *sock, int status)
{
    struct st_h2o_tunnel_t *tunnel = sock->data;
    h2o_socket_t *dst;
    assert(tunnel);
    assert(tunnel->sock[0] == sock || tunnel->sock[1] == sock);

    if (status != 0) {
        h2o_socket_read_stop(tunnel->sock[0]);
        h2o_socket_read_stop(tunnel->sock[1]);
        close_connection(tunnel);
        return;
    }

    if (sock->bytes_read == 0) return;

    h2o_socket_read_stop(sock);

    if (tunnel->sock[0] == sock) dst = tunnel->sock[1];
    else dst = tunnel->sock[0];

    assert(dst);

    h2o_iovec_t buf;
    buf.base = sock->input->bytes;
    buf.len = sock->input->size;
    h2o_socket_write(dst, &buf, 1, on_write_complete);
}

static void on_write_complete(h2o_socket_t *sock, int status)
{
    struct st_h2o_tunnel_t *tunnel = sock->data;
    h2o_socket_t *peer;
    assert(tunnel);
    assert(tunnel->sock[0] == sock || tunnel->sock[1] == sock);

    if (status != 0) {
        h2o_socket_read_stop(tunnel->sock[0]);
        h2o_socket_read_stop(tunnel->sock[1]);
        close_connection(tunnel);
        return;
    }

    if (tunnel->sock[0] == sock) peer = tunnel->sock[1];
    else peer = tunnel->sock[0];

    assert(peer);

    h2o_buffer_consume(&peer->input, peer->input->size);
    h2o_socket_read_start(peer, on_read);
}

h2o_tunnel_t *h2o_tunnel_establish(h2o_socket_t *sock1, h2o_socket_t *sock2)
{
    assert(sock1);
    assert(sock2);

    h2o_tunnel_t *tunnel = h2o_mem_alloc(sizeof(*tunnel));
    tunnel->sock[0] = sock1;
    tunnel->sock[1] = sock2;
    sock1->data = tunnel;
    sock2->data = tunnel;

    /* Trash all data read before tunnel establishment */
    h2o_buffer_consume(&sock1->input, sock1->input->size);
    h2o_buffer_consume(&sock2->input, sock2->input->size);

    /* Bring up the tunnel */
    h2o_socket_read_start(sock1, on_read);
    h2o_socket_read_start(sock2, on_read);

    return tunnel;
}

void h2o_tunnel_break(h2o_tunnel_t *tunnel)
{
    assert(tunnel);

    close_connection(tunnel);
}
