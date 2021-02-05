#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

#include "h2o/httpclient.h"

struct st_h2o_udp_tunnel_t {
    h2o_tunnel_t super;
    socklen_t len;
    h2o_socket_t *sock;
    h2o_loop_t *loop;
    h2o_buffer_t *inbuf; /* for datagram fragments */
};

static void tunnel_on_destroy(h2o_tunnel_t *_tunnel)
{
    struct st_h2o_udp_tunnel_t *tunnel = (void *)_tunnel;

    h2o_buffer_dispose(&tunnel->inbuf);
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
    struct iovec iov;
    memset(&mess, 0, sizeof(mess));
    mess.msg_name = &sa;
    mess.msg_namelen = sizeof(sa);
    iov.iov_base = buf;
    iov.iov_len = sizeof(buf);
    mess.msg_iov = &iov;
    mess.msg_iovlen = 1;
    ssize_t rret;
    while ((rret = recvmsg(h2o_socket_get_fd(tunnel->sock), &mess, 0)) == -1 && errno == EINTR)
        ;

    h2o_socket_read_stop(tunnel->sock);

    if (tunnel->super.on_udp_read) {
        h2o_iovec_t hiov = h2o_iovec_init(iov.iov_base, iov.iov_len);
        tunnel->super.on_udp_read(&tunnel->super, NULL, &hiov, 1);
    } else {
        struct {
            uint8_t buf[8];
            uint8_t *end;
        } varint;
        h2o_iovec_t vec[3];
        const uint8_t zero = 0;

        varint.end = ptls_encode_quicint(varint.buf, iov.iov_len);
        vec[0].base = (char *)&zero;
        vec[0].len = sizeof(zero);
        vec[1].base = (char *)varint.buf;
        vec[1].len = varint.end - varint.buf;
        vec[2] = h2o_iovec_init(iov.iov_base, iov.iov_len);
        tunnel->super.on_read(&tunnel->super, NULL, vec, sizeof(vec) / sizeof(vec[0]));
    }

    return;
}

h2o_iovec_t get_next_chunk(const uint8_t *bytes, size_t len, size_t *to_consume, int *skip)
{
    const uint8_t *start = bytes;
    const uint8_t *end = bytes + len;
    uint64_t chunk_type, chunk_length;

    chunk_type = ptls_decode_quicint(&bytes, end);
    if (chunk_type == UINT64_MAX)
        return h2o_iovec_init(NULL, 0);
    chunk_length = ptls_decode_quicint(&bytes, end);
    if (chunk_length == UINT64_MAX)
        return h2o_iovec_init(NULL, 0);

    /* chunk is incomplete */
    if (end - bytes < chunk_length)
        return h2o_iovec_init(NULL, 0);

    /*
     * https://tools.ietf.org/html/draft-ietf-masque-connect-udp-03#section-6
     * CONNECT-UDP Stream Chunks can be used to convey UDP payloads, by
     * using a CONNECT-UDP Stream Chunk Type of UDP_PACKET (value 0x00).
     */
    *skip = chunk_type != 0;
    *to_consume = (bytes + chunk_length) - start;

    return h2o_iovec_init(bytes, chunk_length);
}

static void tunnel_on_writev(h2o_tunnel_t *_tunnel, h2o_iovec_t *iov, size_t iovlen)
{
    struct st_h2o_udp_tunnel_t *tunnel = (void *)_tunnel;
    int fd;
    fd = h2o_socket_get_fd(tunnel->sock);

    struct msghdr mess;
    struct iovec vec[iovlen];
    for (size_t i = 0; i < iovlen; i++)
        vec[i] = (struct iovec){
            .iov_base = iov[i].base,
            .iov_len = iov[i].len,
        };
    memset(&mess, 0, sizeof(mess));
    mess.msg_iov = vec;
    mess.msg_iovlen = iovlen;
    while (sendmsg(fd, &mess, 0) == -1 && errno == EINTR)
        ;

    tunnel->super.on_write_complete(&tunnel->super, NULL);
    return;
}

static void tunnel_on_write(h2o_tunnel_t *_tunnel, const void *bytes, size_t len)
{
    int from_inbuf = 0;
    struct st_h2o_udp_tunnel_t *tunnel = (void *)_tunnel;
    h2o_iovec_t iovs[64];
    size_t iovlen = 0;
    size_t idx = 0;

    if (tunnel->inbuf->size != 0) {
        from_inbuf = 1;
        h2o_buffer_reserve(&tunnel->inbuf, len);
        memcpy(tunnel->inbuf->bytes + tunnel->inbuf->size, bytes, len);
        tunnel->inbuf->size += len;
        bytes = tunnel->inbuf->bytes;
        len = tunnel->inbuf->size;
    }
    do {
        int skip = 0;
        size_t to_consume;
        iovs[iovlen] = get_next_chunk(bytes + idx, len - idx, &to_consume, &skip);
        if (iovs[iovlen].len == 0)
            break;
        if (!skip)
            iovlen++;
        idx += to_consume;
    } while (1);

    if (iovlen > 0)
        tunnel_on_writev(_tunnel, iovs, iovlen);

    if (from_inbuf)
        h2o_buffer_consume(&tunnel->inbuf, idx);

    if (len != idx) {
        h2o_buffer_reserve(&tunnel->inbuf, len - idx);
        memcpy(tunnel->inbuf->bytes + tunnel->inbuf->size, bytes + idx, len - idx);
        tunnel->inbuf->size += (len - idx);
    }
}

void tunnel_proceed_read(struct st_h2o_tunnel_t *_tunnel)
{
    struct st_h2o_udp_tunnel_t *tunnel = (void *)_tunnel;
    h2o_socket_read_start(tunnel->sock, tunnel_socket_on_read);
}

h2o_tunnel_t *h2o_open_udp_tunnel_from_sa(h2o_loop_t *loop, struct sockaddr *addr, socklen_t len)
{
    int fd;
    if ((fd = socket(PF_INET, SOCK_DGRAM, 0)) == -1)
        return NULL;

    if (connect(fd, (void *)addr, len) != 0) {
        close(fd);
        return NULL;
    }
    /* create tunnel */
    struct st_h2o_udp_tunnel_t *tunnel = h2o_mem_alloc(sizeof(*tunnel));
    *tunnel = (struct st_h2o_udp_tunnel_t){
        .super =
            (h2o_tunnel_t){
                .destroy = tunnel_on_destroy,
                .write_ = tunnel_on_write,
                .proceed_read = tunnel_proceed_read,
                .on_read = NULL,
            },
        .len = len,
        .loop = loop,
    };
#if H2O_USE_LIBUV
    tunnel->sock = h2o_uv__poll_create(tunnel->loop, fd, (uv_close_cb)free);
#else
    tunnel->sock = h2o_evloop_socket_create(tunnel->loop, fd, H2O_SOCKET_FLAG_DONT_READ);
#endif

    tunnel->sock->data = tunnel;
    h2o_buffer_init(&tunnel->inbuf, &h2o_socket_buffer_prototype);
    h2o_socket_read_start(tunnel->sock, tunnel_socket_on_read);

    return &tunnel->super;
}
