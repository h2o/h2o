#include "h2get.h"
#include <unistd.h>

static int plain_connect(struct h2get_conn *conn, void *unused)
{
    int ret;
    conn->fd = socket(conn->sa.sa->sa_family, conn->socktype, conn->protocol);
    if (conn->fd < 0) {
        return -1;
    }

    ret = connect(conn->fd, conn->sa.sa, conn->sa.len);
    if (ret < 0) {
        close(conn->fd);
        return -1;
    }

    conn->state = H2GET_CONN_STATE_CONNECT;
    return 0;
}

static int plain_close(struct h2get_conn *conn, void *unused)
{
    if (conn->state < H2GET_CONN_STATE_CONNECT) {
        return -1;
    }
    conn->state = H2GET_CONN_STATE_INIT;
    return close(conn->fd);
}

struct h2get_ops plain_ops = {
    H2GET_TRANSPORT_PLAIN, NULL, plain_connect, NULL, NULL, plain_close, NULL,
};
/* vim: set expandtab ts=4 sw=4: */
