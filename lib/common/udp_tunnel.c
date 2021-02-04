#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

#include "h2o/httpclient.h"

struct st_h2o_udp_tunnel_t {
    h2o_httpclient_udp_tunnel_t super;
    struct sockaddr_storage ss;
    socklen_t len;
    h2o_socket_t *sock;
    h2o_loop_t *loop;
};

static void tunnel_on_destroy(h2o_httpclient_udp_tunnel_t *_tunnel)
{
    struct st_h2o_udp_tunnel_t *tunnel = (void *)_tunnel;

    h2o_socket_close(tunnel->sock);
    free(tunnel);
}

static void tunnel_socket_on_read(h2o_socket_t *sock, const char *err)
{
    struct st_h2o_udp_tunnel_t *tunnel = sock->data;

    if (err != NULL) {
        tunnel->super.on_read(&tunnel->super, err, NULL, 0);
        return;
    }

    uint8_t buf[16384];
    struct msghdr mess;
    struct sockaddr sa;
    struct iovec vec;
    memset(&mess, 0, sizeof(mess));
    mess.msg_name = &sa;
    mess.msg_namelen = sizeof(sa);
    vec.iov_base = buf;
    vec.iov_len = sizeof(buf);
    mess.msg_iov = &vec;
    mess.msg_iovlen = 1;
    ssize_t rret;
    while ((rret = recvmsg(h2o_socket_get_fd(tunnel->sock), &mess, 0)) == -1 && errno == EINTR)
        ;
    h2o_iovec_t iov = h2o_iovec_init(vec.iov_base, vec.iov_len);
    tunnel->super.on_read(&tunnel->super, NULL, &iov, 1);
}


static void tunnel_on_writev(h2o_httpclient_udp_tunnel_t *_tunnel, h2o_iovec_t *iov, size_t iovlen)
{
    struct st_h2o_udp_tunnel_t *tunnel = (void *)_tunnel;
    int fd;
    if (!tunnel->sock) {
        struct sockaddr_in sin;
        if ((fd = socket(PF_INET, SOCK_DGRAM, 0)) == -1) {
            perror("failed to create UDP socket");
            exit(EXIT_FAILURE);
        }
        memset(&sin, 0, sizeof(sin));
        if (bind(fd, (void *)&sin, sizeof(sin)) != 0) {
            perror("failed to bind bind UDP socket");
            exit(EXIT_FAILURE);
        }
        tunnel->sock = h2o_evloop_socket_create(tunnel->loop, fd, H2O_SOCKET_FLAG_DONT_READ);
        tunnel->sock->data = tunnel;
    }
    fd = h2o_socket_get_fd(tunnel->sock);

    struct msghdr mess;
    struct iovec vec[iovlen];
    for (size_t i = 0; i < iovlen; i++)
        vec[i] = (struct iovec){ .iov_base = iov[i].base, .iov_len = iov[i].len, };
    memset(&mess, 0, sizeof(mess));
    mess.msg_name = &tunnel->ss;
    mess.msg_namelen = tunnel->len;
    mess.msg_iov = vec;
    mess.msg_iovlen = iovlen;
    while (sendmsg(fd, &mess, 0) == -1 && errno == EINTR)
        ;

    h2o_socket_read_start(tunnel->sock, tunnel_socket_on_read);
    return;
}

h2o_httpclient_udp_tunnel_t *h2o_open_udp_tunnel_from_sa(h2o_loop_t *loop, struct sockaddr *addr, socklen_t len)
{
    /* create tunnel */
    struct st_h2o_udp_tunnel_t *tunnel = h2o_mem_alloc(sizeof(*tunnel));
    *tunnel = (struct st_h2o_udp_tunnel_t){
        .super =
            (h2o_httpclient_udp_tunnel_t){
                .destroy = tunnel_on_destroy,
                .writev_ = tunnel_on_writev,
                .on_read = NULL,
            },
            .len = len,
            .loop = loop,
    };
    memcpy(&tunnel->ss, addr, len);

    return &tunnel->super;
}


