/*
 * Copyright (c) 2018 Fastly, Kazuho Oku
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
#include <errno.h>
#include <stdio.h>
#include <sys/socket.h>
#include "h2o/hq_common.h"

static void on_read(h2o_socket_t *sock, const char *err);
static void on_timeout(h2o_timer_t *timeout);

void h2o_hq_init_context(h2o_hq_ctx_t *ctx, h2o_loop_t *loop, quicly_context_t *quic, h2o_socket_t *sock, h2o_hq_accept_cb acceptor)
{
    ctx->loop = loop;
    ctx->quic = quic;
    ctx->sock = sock;
    ctx->sock->data = ctx;
    h2o_linklist_init_anchor(&ctx->conns);
    ctx->acceptor = acceptor;

    h2o_socket_read_start(ctx->sock, on_read);
}

void h2o_hq_init_conn(h2o_hq_conn_t *conn, h2o_hq_ctx_t *ctx, const h2o_hq_conn_callbacks_t *callbacks)
{
    conn->ctx = ctx;
    conn->callbacks = callbacks;
    conn->conns_link = (h2o_linklist_t){NULL};
    h2o_linklist_insert(&conn->ctx->conns, &conn->conns_link);
    h2o_timer_init(&conn->_timeout, on_timeout);
    conn->quic = NULL;
}

void h2o_hq_dispose_conn(h2o_hq_conn_t *conn)
{
    if (conn->quic != NULL)
        quicly_free(conn->quic);
    h2o_linklist_unlink(&conn->conns_link);
    h2o_timer_unlink(&conn->_timeout);
}

static h2o_hq_conn_t *find_by_cid(h2o_hq_ctx_t *ctx, ptls_iovec_t dest)
{
    h2o_linklist_t *link;
    for (link = ctx->conns.next; link != &ctx->conns; link = link->next) {
        h2o_hq_conn_t *conn = H2O_STRUCT_FROM_MEMBER(h2o_hq_conn_t, conns_link, link);
        const quicly_cid_t *conn_cid = quicly_get_host_cid(conn->quic);
        if (h2o_memis(conn_cid->cid, conn_cid->len, dest.base, dest.len))
            return conn;
    }
    return NULL;
}

static void process_packets(h2o_hq_ctx_t *ctx, quicly_decoded_packet_t *packets, size_t num_packets)
{
    h2o_hq_conn_t *conn = find_by_cid(ctx, packets[0].cid.dest);
    if (conn != NULL) {
        conn->callbacks->handle_input(conn, packets, num_packets);
    } else if (ctx->acceptor != NULL) {
        ctx->acceptor(ctx, packets, num_packets);
    }
}

void on_read(h2o_socket_t *sock, const char *err)
{
    h2o_hq_ctx_t *ctx = sock->data;
    int fd = h2o_socket_get_fd(sock);

    while (1) {
        uint8_t buf[16384], *bufpt = buf;
        struct {
            struct msghdr mess;
            struct sockaddr sa;
            struct iovec vec;
        } dgrams[32];
        size_t dgram_index, num_dgrams;
        ssize_t rret;

        /* read datagrams */
        for (dgram_index = 0; dgram_index < sizeof(dgrams) / sizeof(dgrams[0]) && buf + sizeof(buf) - bufpt > 2048; ++dgram_index) {
            /* read datagram */
            memset(&dgrams[dgram_index].mess, 0, sizeof(dgrams[dgram_index].mess));
            dgrams[dgram_index].mess.msg_name = &dgrams[dgram_index].sa;
            dgrams[dgram_index].mess.msg_namelen = sizeof(dgrams[dgram_index].sa);
            dgrams[dgram_index].vec.iov_base = bufpt;
            dgrams[dgram_index].vec.iov_len = buf + sizeof(buf) - bufpt;
            dgrams[dgram_index].mess.msg_iov = &dgrams[dgram_index].vec;
            dgrams[dgram_index].mess.msg_iovlen = 1;
            while ((rret = recvmsg(fd, &dgrams[dgram_index].mess, 0)) <= 0 && errno == EINTR)
                ;
            if (rret <= 0)
                break;
            dgrams[dgram_index].vec.iov_len = rret;
            bufpt += rret;
        }
        num_dgrams = dgram_index;
        if (num_dgrams == 0)
            break;

        /* convert dgrams to decoded packets and process */
        quicly_decoded_packet_t packets[64];
        size_t packet_index = 0;
        for (dgram_index = 0; dgram_index != num_dgrams; ++dgram_index) {
            size_t off = 0;
            while (off != dgrams[dgram_index].vec.iov_len) {
                size_t plen = quicly_decode_packet(packets + packet_index, dgrams[dgram_index].vec.iov_base + off,
                                                   dgrams[dgram_index].vec.iov_len - off, 8);
                if (plen == SIZE_MAX)
                    break;
                off += plen;
                if (packet_index == sizeof(packets) / sizeof(packets[0]) - 1 ||
                    !(packet_index == 0 || h2o_memis(packets[0].cid.dest.base, packets[0].cid.dest.len,
                                                     packets[packet_index].cid.dest.base, packets[packet_index].cid.dest.len))) {
                    process_packets(ctx, packets, packet_index + 1);
                    packet_index = 0;
                } else {
                    ++packet_index;
                }
            }
        }
        if (packet_index != 0)
            process_packets(ctx, packets, packet_index);
    }
}

void on_timeout(h2o_timer_t *timeout)
{
    h2o_hq_conn_t *conn = H2O_STRUCT_FROM_MEMBER(h2o_hq_conn_t, _timeout, timeout);
    h2o_hq_send(conn);
}

static int send_one(int fd, quicly_datagram_t *p)
{
    int ret;
    struct msghdr mess;
    struct iovec vec;
    memset(&mess, 0, sizeof(mess));
    mess.msg_name = &p->sa;
    mess.msg_namelen = p->salen;
    vec.iov_base = p->data.base;
    vec.iov_len = p->data.len;
    mess.msg_iov = &vec;
    mess.msg_iovlen = 1;
    while ((ret = (int)sendmsg(fd, &mess, 0)) == -1 && errno == EINTR)
        ;
    return ret;
}

void h2o_hq_send(h2o_hq_conn_t *conn)
{
    quicly_datagram_t *packets[16];
    size_t num_packets, i;
    int fd = h2o_socket_get_fd(conn->ctx->sock), ret;

    do {
        num_packets = sizeof(packets) / sizeof(packets[0]);
        if ((ret = quicly_send(conn->quic, packets, &num_packets)) == 0 || ret == QUICLY_ERROR_CONNECTION_CLOSED) {
            for (i = 0; i != num_packets; ++i) {
                if (send_one(fd, packets[i]) == -1)
                    perror("sendmsg failed");
                quicly_default_free_packet(quicly_get_context(conn->quic), packets[i]);
            }
        } else {
            fprintf(stderr, "quicly_send returned %d\n", ret);
        }
    } while (ret == 0 && num_packets != 0);

    assert(ret == 0);
}
