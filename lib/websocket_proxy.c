#include <stdio.h>
#include <stdlib.h>
#include "h2o.h"
#include "h2o/http1.h"
#include "h2o/websocket_proxy.h"

#define MIN_TCP_BUF_SZ 65536

struct st_h2o_websocket_proxy_info_t {
    h2o_socket_t *proxy_socket;
    h2o_socket_t *client_socket;
};

static void on_client_write_complete(h2o_socket_t *sock, int status);
static void on_proxy_write_complete(h2o_socket_t *sock, int status);

static void close_connection(struct st_h2o_websocket_proxy_info_t *socket_info)
{
    assert(socket_info);
    if (socket_info->proxy_socket != NULL)
        h2o_socket_close(socket_info->proxy_socket);
    if (socket_info->client_socket != NULL)
        h2o_socket_close(socket_info->client_socket);
    free(socket_info);
}

static inline void forward_data(h2o_socket_t *dst, h2o_socket_t *src, h2o_socket_cb cb)
{
    h2o_iovec_t buf;
    buf.base = src->input->bytes;
    buf.len = src->input->size;
    h2o_socket_write(dst, &buf, 1, cb);
}

static inline
struct st_h2o_websocket_proxy_info_t *on_read(h2o_socket_t *sock, int status)
{
    struct st_h2o_websocket_proxy_info_t *socket_info = sock->data;

    if (status != 0) {
        h2o_socket_read_stop(socket_info->client_socket);
        h2o_socket_read_stop(socket_info->proxy_socket);
        close_connection(socket_info);
        return NULL;
    }

    if (sock->bytes_read == 0) return NULL;

    h2o_socket_read_stop(sock);

    return socket_info;
}

static void on_client_read(h2o_socket_t *sock, int status)
{
    struct st_h2o_websocket_proxy_info_t *socket_info = on_read(sock, status);

    if (socket_info == NULL) return;

    forward_data(socket_info->proxy_socket, sock, on_proxy_write_complete);
}

static void on_proxy_read(h2o_socket_t *sock, int status)
{
    struct st_h2o_websocket_proxy_info_t *socket_info = on_read(sock, status);

    if (socket_info == NULL) return;

    forward_data(socket_info->client_socket, sock, on_client_write_complete);
}

static inline
struct st_h2o_websocket_proxy_info_t *on_write_complete(h2o_socket_t *sock, int status)
{
    struct st_h2o_websocket_proxy_info_t *socket_info = sock->data;

    if (status != 0) {
        h2o_socket_read_stop(socket_info->client_socket);
        h2o_socket_read_stop(socket_info->proxy_socket);
        close_connection(socket_info);
    }

    return socket_info;
}

static void on_client_write_complete(h2o_socket_t *sock, int status)
{
    struct st_h2o_websocket_proxy_info_t *socket_info = on_write_complete(sock, status);

    if (status != 0) return;
    h2o_buffer_consume(&socket_info->proxy_socket->input, socket_info->proxy_socket->input->size);
    h2o_socket_read_start(socket_info->proxy_socket, on_proxy_read);
}

static void on_proxy_write_complete(h2o_socket_t *sock, int status)
{
    struct st_h2o_websocket_proxy_info_t *socket_info = on_write_complete(sock, status);

    if (status != 0) return;
    h2o_buffer_consume(&socket_info->client_socket->input, socket_info->client_socket->input->size);
    h2o_socket_read_start(socket_info->client_socket, on_client_read);
}

static void on_upgrade_complete(void *_socket_info, h2o_socket_t *sock, size_t reqsize)
{
    struct st_h2o_websocket_proxy_info_t *socket_info = _socket_info;
    socket_info->client_socket = sock;
    sock->data = socket_info;
    h2o_buffer_consume(&sock->input, sock->input->size);
    h2o_socket_read_start(sock, on_client_read);
}

void h2o_websocket_proxy_hs_success(h2o_req_t *req, h2o_socket_t *sock)
{
    struct st_h2o_websocket_proxy_info_t *socket_info = h2o_mem_alloc(sizeof(*socket_info));
    socket_info->proxy_socket = sock;
    h2o_http1_upgrade(req, NULL, 0, on_upgrade_complete, socket_info);
    sock->data = socket_info;
    h2o_buffer_consume(&sock->input, sock->input->size);
    h2o_socket_read_start(sock, on_proxy_read);
}
