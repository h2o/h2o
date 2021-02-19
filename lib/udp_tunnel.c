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
    h2o_socket_t *sock;
    h2o_loop_t *loop;
    struct {
        h2o_buffer_t *buf; /* for datagram fragments */
        h2o_timer_t delayed;
    } egress;
    struct {
        uint8_t buf[3 + 1500];
    } ingress;
};

static void tunnel_on_destroy(h2o_tunnel_t *_tunnel)
{
    struct st_h2o_udp_tunnel_t *tunnel = (void *)_tunnel;

    h2o_buffer_dispose(&tunnel->egress.buf);
    if (h2o_timer_is_linked(&tunnel->egress.delayed))
        h2o_timer_unlink(&tunnel->egress.delayed);
    h2o_socket_close(tunnel->sock);
    free(tunnel);
}

static void read_and_forward_udp(struct st_h2o_udp_tunnel_t *tunnel)
{
    uint8_t buf[1500];
    ssize_t rret;

    /* read UDP packet, or return */
    while ((rret = recv(h2o_socket_get_fd(tunnel->sock), buf, sizeof(buf), 0)) == -1 && errno == EINTR)
        ;
    if (rret == -1)
        return;

    /* forward UDP datagram as is; note that it might be zero-sized */
    if (rret >= 0) {
        h2o_iovec_t vec = h2o_iovec_init(buf, rret);
        tunnel->super.on_udp_read(&tunnel->super, &vec, 1);
    }
}

static void read_and_forward_stream(struct st_h2o_udp_tunnel_t *tunnel)
{
    ssize_t rret;

    /* read UDP packet, keeping the first three bytes empty */
    while ((rret = recv(h2o_socket_get_fd(tunnel->sock), tunnel->ingress.buf + 3, sizeof(tunnel->ingress.buf) - 3, 0)) == -1 &&
           errno == EINTR)
        ;
    if (rret == -1)
        return;

    /* Forward the UDP packet through tunnel, with the chunk header being appended. The operation is asynchronous, that is why we
     * stop reading from the socket, and use heap for building the payload. (TODO should we read & discard instead of stopping?) */
    h2o_socket_read_stop(tunnel->sock);
    ssize_t off = 0;
    tunnel->ingress.buf[off++] = 0; /* chunk type = UDP_PACKET */
    off = quicly_encodev(tunnel->ingress.buf + off, (uint64_t)rret) - tunnel->ingress.buf;
    assert(off <= 3);
    if (off != 3)
        memmove(tunnel->ingress.buf + off, tunnel->ingress.buf + 3, rret);
    off += rret;
    tunnel->super.on_read(&tunnel->super, NULL, tunnel->ingress.buf, off);
}

static void tunnel_socket_on_read(h2o_socket_t *sock, const char *err)
{
    struct st_h2o_udp_tunnel_t *tunnel = sock->data;

    if (err != NULL) {
        tunnel->super.on_read(&tunnel->super, err, NULL, 0);
        return;
    }

    if (tunnel->super.on_udp_read != NULL) {
        read_and_forward_udp(tunnel);
    } else {
        read_and_forward_stream(tunnel);
    }
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

static void tunnel_on_udp_write(h2o_tunnel_t *_tunnel, h2o_iovec_t *datagrams, size_t num_datagrams)
{
    struct st_h2o_udp_tunnel_t *tunnel = (void *)_tunnel;

    for (size_t i = 0; i != num_datagrams; ++i)
        while (send(h2o_socket_get_fd(tunnel->sock), datagrams[i].base, datagrams[i].len, 0) == -1 && errno == EINTR)
            ;
}

static void write_complete_delayed(h2o_timer_t *timer)
{
    struct st_h2o_udp_tunnel_t *tunnel = H2O_STRUCT_FROM_MEMBER(struct st_h2o_udp_tunnel_t, egress.delayed, timer);

    tunnel->super.on_write_complete(&tunnel->super, NULL);
}

static void tunnel_on_write(h2o_tunnel_t *_tunnel, const void *bytes, size_t len)
{
    int from_buf = 0;
    struct st_h2o_udp_tunnel_t *tunnel = (void *)_tunnel;
    h2o_iovec_t datagrams[64];
    size_t num_datagrams = 0;
    size_t off = 0;

    if (tunnel->egress.buf->size != 0) {
        from_buf = 1;
        h2o_buffer_reserve(&tunnel->egress.buf, len);
        memcpy(tunnel->egress.buf->bytes + tunnel->egress.buf->size, bytes, len);
        tunnel->egress.buf->size += len;
        bytes = tunnel->egress.buf->bytes;
        len = tunnel->egress.buf->size;
    }
    do {
        int skip = 0;
        size_t to_consume;
        datagrams[num_datagrams] = get_next_chunk(bytes + off, len - off, &to_consume, &skip);
        if (datagrams[num_datagrams].len == 0)
            break;
        if (!skip)
            num_datagrams++;
        off += to_consume;
    } while (1);

    if (num_datagrams > 0)
        tunnel_on_udp_write(&tunnel->super, datagrams, num_datagrams);

    if (from_buf)
        h2o_buffer_consume(&tunnel->egress.buf, off);

    if (len != off) {
        h2o_buffer_reserve(&tunnel->egress.buf, len - off);
        memcpy(tunnel->egress.buf->bytes + tunnel->egress.buf->size, bytes + off, len - off);
        tunnel->egress.buf->size += (len - off);
    }

    tunnel->super.on_write_complete(&tunnel->super, NULL);
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
                .udp_write = tunnel_on_udp_write,
            },
        .loop = loop,
        .egress = {.delayed = {.cb = write_complete_delayed}},
    };
#if H2O_USE_LIBUV
    tunnel->sock = h2o_uv__poll_create(tunnel->loop, fd, (uv_close_cb)free);
#else
    tunnel->sock = h2o_evloop_socket_create(tunnel->loop, fd, H2O_SOCKET_FLAG_DONT_READ);
#endif

    tunnel->sock->data = tunnel;
    h2o_buffer_init(&tunnel->egress.buf, &h2o_socket_buffer_prototype);
    h2o_socket_read_start(tunnel->sock, tunnel_socket_on_read);

    return &tunnel->super;
}
