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
#include "h2o/string_.h"
#include "h2o/hq_common.h"

/**
 * maximum payload size excluding DATA frame; stream receive window MUST be at least as big as this
 */
#define MAX_FRAME_SIZE 16384

static void on_read(h2o_socket_t *sock, const char *err);
static void on_timeout(h2o_timer_t *timeout);

const ptls_iovec_t h2o_hq_alpn[1] = {{(void *)H2O_STRLIT("hq-14")}};

int h2o_hq_peek_frame(quicly_recvbuf_t *recvbuf, h2o_hq_peek_frame_t *frame)
{
    /* FIXME what if recvbuf has split input to multiple buffers? do we need a option to flatten that? */
    ptls_iovec_t input = quicly_recvbuf_get(recvbuf);
    const uint8_t *src = input.base, *src_end = src + input.len;

    if ((frame->length = quicly_decodev(&src, src_end)) == UINT64_MAX)
        return H2O_HQ_ERROR_INCOMPLETE;
    if (src == src_end)
        return H2O_HQ_ERROR_INCOMPLETE;
    frame->type = *src++;
    frame->_header_size = (uint8_t)(src - input.base);
    if (frame->type != H2O_HQ_FRAME_TYPE_DATA) {
        if (frame->length >= MAX_FRAME_SIZE)
            return H2O_HQ_ERROR_MALFORMED_FRAME(frame->type); /* FIXME is this the correct code? */
        if (src_end - src < frame->length)
            return H2O_HQ_ERROR_INCOMPLETE;
        frame->payload = src;
    }

    return 0;
}

void h2o_hq_shift_frame(quicly_recvbuf_t *recvbuf, h2o_hq_peek_frame_t *frame)
{
    size_t sz = frame->_header_size;
    if (frame->type != H2O_HQ_FRAME_TYPE_DATA)
        sz += frame->length;
    quicly_recvbuf_shift(recvbuf, sz);
}

void h2o_hq_init_context(h2o_hq_ctx_t *ctx, h2o_loop_t *loop, h2o_socket_t *sock, quicly_context_t *quic, h2o_hq_accept_cb acceptor)
{
    assert(quic->on_stream_open != NULL && "on_stream_open MUST be set to h2o_hq_on_stream_open or its wrapper");

    ctx->loop = loop;
    ctx->sock = sock;
    ctx->sock->data = ctx;
    ctx->quic = quic;
    h2o_linklist_init_anchor(&ctx->conns);
    ctx->acceptor = acceptor;

    h2o_socket_read_start(ctx->sock, on_read);
}

void h2o_hq_init_conn(h2o_hq_conn_t *conn, h2o_hq_ctx_t *ctx, h2o_hq_handle_control_stream_frame_cb handle_control_stream_frame)
{
    memset(conn, 0, sizeof(*conn));
    conn->ctx = ctx;
    conn->handle_control_stream_frame = handle_control_stream_frame;
    h2o_linklist_insert(&conn->ctx->conns, &conn->conns_link);
    h2o_timer_init(&conn->_timeout, on_timeout);
}

void h2o_hq_dispose_conn(h2o_hq_conn_t *conn)
{
    if (conn->qpack.dec != NULL)
        h2o_qpack_destroy_decoder(conn->qpack.dec);
    if (conn->qpack.enc != NULL)
        h2o_qpack_destroy_encoder(conn->qpack.enc);
    if (conn->quic != NULL)
        quicly_free(conn->quic);
    h2o_linklist_unlink(&conn->conns_link);
    h2o_timer_unlink(&conn->_timeout);
}

static int open_unidirectional_stream(h2o_hq_conn_t *conn, quicly_stream_t **stream_slot, h2o_iovec_t initial_bytes)
{
    int ret;

    if ((ret = quicly_open_stream(conn->quic, stream_slot, 1)) != 0)
        return ret;
    return quicly_sendbuf_write(&(*stream_slot)->sendbuf, initial_bytes.base, initial_bytes.len, NULL);
}

int h2o_hq_setup(h2o_hq_conn_t *conn, quicly_conn_t *quic)
{
    int ret;

    conn->quic = quic;
    *quicly_get_data(conn->quic) = conn;
    conn->qpack.dec = h2o_qpack_create_decoder(H2O_HQ_DEFAULT_HEADER_TABLE_SIZE);

    if ((ret = open_unidirectional_stream(conn, &conn->_control_streams.egress.control, h2o_iovec_init(H2O_STRLIT("C\0\4")))) !=
            0 ||
        (ret = open_unidirectional_stream(conn, &conn->_control_streams.egress.qpack_encoder, h2o_iovec_init(H2O_STRLIT("H")))) !=
            0 ||
        (ret = open_unidirectional_stream(conn, &conn->_control_streams.egress.qpack_decoder, h2o_iovec_init(H2O_STRLIT("h")))) !=
            0)
        return ret;

    h2o_hq_schedule_timer(conn);
    return 0;
}

static int on_update_control_stream(quicly_stream_t *stream)
{
    h2o_hq_conn_t *conn = *quicly_get_data(stream->conn);
    h2o_hq_peek_frame_t frame;
    int ret;

    if (quicly_recvbuf_get_error(&stream->recvbuf) != QUICLY_STREAM_ERROR_IS_OPEN)
        return H2O_HQ_ERROR_CLOSED_CRITICAL_STREAM;
    if ((ret = h2o_hq_peek_frame(&stream->recvbuf, &frame)) != 0)
        return ret == H2O_HQ_ERROR_INCOMPLETE ? 0 : ret;

    if ((ret = conn->handle_control_stream_frame(conn, frame.type, frame.payload, frame.length)) != 0)
        return ret;

    h2o_hq_shift_frame(&stream->recvbuf, &frame);
    return 0;
}

static int on_update_qpack_stream(quicly_stream_t *stream, int is_encoder_stream)
{
    if (quicly_recvbuf_get_error(&stream->recvbuf) != QUICLY_STREAM_ERROR_IS_OPEN)
        return H2O_HQ_ERROR_CLOSED_CRITICAL_STREAM;

    h2o_hq_conn_t *conn = *quicly_get_data(stream->conn);
    ptls_iovec_t input = quicly_recvbuf_get(&stream->recvbuf);
    const uint8_t *src = input.base, *src_end = src + input.len;
    int64_t *unblocked_stream_ids;
    size_t num_unblocked;
    int ret = 0;

    while (src != src_end) {
        const char *err_desc = NULL;
        if (is_encoder_stream) {
            ret = h2o_qpack_decoder_handle_input(conn->qpack.dec, &unblocked_stream_ids, &num_unblocked, &src, src_end, &err_desc);
            /* TODO handle unblocked streams */
        } else {
            ret = h2o_qpack_encoder_handle_input(conn->qpack.enc, &src, src_end, &err_desc);
        }
        if (ret != 0)
            break;
        /* TODO save err_desc */
    }

    if (src != input.base)
        quicly_recvbuf_shift(&stream->recvbuf, src - input.base);

    return ret;
}

static int on_update_qpack_encoder_stream(quicly_stream_t *stream)
{
    return on_update_qpack_stream(stream, 1);
}

static int on_update_qpack_decoder_stream(quicly_stream_t *stream)
{
    return on_update_qpack_stream(stream, 0);
}

static int on_update_identify_unidirectional_stream_type(quicly_stream_t *stream)
{
    h2o_hq_conn_t *conn = *quicly_get_data(stream->conn);
    ptls_iovec_t input;
    quicly_stream_t **stream_slot;
    quicly_stream_update_cb on_update;

    if ((input = quicly_recvbuf_get(&stream->recvbuf)).len == 0)
        return 0;

    switch (input.base[0]) {
    case 'C':
        stream_slot = &conn->_control_streams.ingress.control;
        on_update = on_update_control_stream;
        break;
    case 'H':
        stream_slot = &conn->_control_streams.ingress.qpack_encoder;
        on_update = on_update_qpack_encoder_stream;
        break;
    case 'h':
        stream_slot = &conn->_control_streams.ingress.qpack_decoder;
        on_update = on_update_qpack_decoder_stream;
        break;
    default:
        return H2O_HQ_ERROR_WRONG_STREAM;
    }

    if (*stream_slot != NULL)
        return H2O_HQ_ERROR_WRONG_STREAM_COUNT;

    quicly_recvbuf_shift(&stream->recvbuf, 1);
    *stream_slot = stream;
    stream->on_update = on_update;

    return stream->on_update(stream);
}

int h2o_hq_on_stream_open(quicly_stream_t *stream)
{
    if (quicly_stream_is_unidirectional(stream->stream_id)) {
        stream->on_update = on_update_identify_unidirectional_stream_type;
        return stream->on_update(stream);
    }
    return H2O_HQ_ERROR_GENERAL_PROTOCOL;
}

static int handle_settings_frame(h2o_hq_conn_t *conn, const uint8_t *payload, size_t length)
{
    const uint8_t *src = payload, *src_end = src + length;
    uint32_t header_table_size = H2O_HQ_DEFAULT_HEADER_TABLE_SIZE;

    if (conn->qpack.enc != NULL)
        goto Malformed;

    while (src != src_end) {
        uint16_t id;
        uint64_t length;
        if (ptls_decode16(&id, &src, src_end) != 0)
            goto Malformed;
        if ((length = quicly_decodev(&src, src_end)) == UINT64_MAX)
            goto Malformed;
        if (src_end - src < length)
            goto Malformed;
        const uint8_t *content_end = src + length;
        switch (id) {
        case H2O_HQ_SETTINGS_HEADER_TABLE_SIZE: {
            uint64_t v;
            if ((v = quicly_decodev(&src, src_end)) == UINT64_MAX)
                goto Malformed;
            if (v > H2O_HQ_MAX_HEADER_TABLE_SIZE)
                goto Malformed;
            header_table_size = (uint32_t)v;
        } break;
        /* TODO add */
        default:
            src = content_end;
            break;
        }
        if (src != content_end)
            goto Malformed;
    }

    conn->qpack.enc = h2o_qpack_create_encoder(header_table_size);
    return 0;
Malformed:
    return H2O_HQ_ERROR_MALFORMED_FRAME(H2O_HQ_FRAME_TYPE_SETTINGS);
}

int h2o_hq_handle_control_stream_frame(h2o_hq_conn_t *conn, uint8_t type, const uint8_t *payload, size_t length)
{
    if (conn->qpack.enc == NULL) {
        if (type != H2O_HQ_FRAME_TYPE_SETTINGS)
            return H2O_HQ_ERROR_MALFORMED_FRAME(type);
        /* handle settings frame (and setup qpack.enc) */
        return handle_settings_frame(conn, payload, length);
    }

    /* SETTINGS has already been received */
    switch (type) {
    case H2O_HQ_FRAME_TYPE_SETTINGS:
        return H2O_HQ_ERROR_MALFORMED_FRAME(H2O_HQ_FRAME_TYPE_SETTINGS);
    case H2O_HQ_FRAME_TYPE_PRIORITY:
        if (quicly_is_client(conn->quic))
            return H2O_HQ_ERROR_GENERAL_PROTOCOL; /* FIXME? */
        return 0;
    case H2O_HQ_FRAME_TYPE_CANCEL_PUSH:
        return H2O_HQ_ERROR_GENERAL_PROTOCOL; /* TODO implement push? */
    case H2O_HQ_FRAME_TYPE_PUSH_PROMISE:
        if (!quicly_is_client(conn->quic))
            return H2O_HQ_ERROR_GENERAL_PROTOCOL; /* FIXME? */
        return 0;
    case H2O_HQ_FRAME_TYPE_GOAWAY:
        return 0; /* FIXME implement */
    case H2O_HQ_FRAME_TYPE_MAX_PUSH_ID:
        if (quicly_is_client(conn->quic))
            return H2O_HQ_ERROR_GENERAL_PROTOCOL; /* FIXME? */
        return 0;
    default:
        return 0;
    }
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

static void process_packets(h2o_hq_ctx_t *ctx, struct sockaddr *sa, socklen_t salen, quicly_decoded_packet_t *packets,
                            size_t num_packets)
{
    h2o_hq_conn_t *conn = find_by_cid(ctx, packets[0].cid.dest);

    if (conn != NULL) {
        size_t i;
        for (i = 0; i != num_packets; ++i) {
            /* FIXME process closure and errors */
            quicly_receive(conn->quic, packets + i);
        }
    } else if (ctx->acceptor != NULL) {
        conn = ctx->acceptor(ctx, sa, salen, packets, num_packets);
    }

    /* for locality, emit packets belonging to the same connection NOW! */
    if (conn != NULL)
        h2o_hq_send(conn);
}

void on_read(h2o_socket_t *sock, const char *err)
{
    h2o_hq_ctx_t *ctx = sock->data;
    int fd = h2o_socket_get_fd(sock);

    while (1) {
        uint8_t buf[16384], *bufpt = buf;
        struct {
            struct msghdr mess;
            struct sockaddr_storage sa;
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
            if (packet_index != 0 &&
                !(dgram_index == 0 ||
                  h2o_socket_compare_address(dgrams[dgram_index - 1].mess.msg_name, dgrams[dgram_index].mess.msg_name))) {
                process_packets(ctx, dgrams[dgram_index - 1].mess.msg_name, dgrams[dgram_index - 1].mess.msg_namelen, packets,
                                packet_index);
                packet_index = 0;
            }
            size_t off = 0;
            while (off != dgrams[dgram_index].vec.iov_len) {
                size_t plen = quicly_decode_packet(packets + packet_index, dgrams[dgram_index].vec.iov_base + off,
                                                   dgrams[dgram_index].vec.iov_len - off, ctx->acceptor != NULL ? 8 : 0);
                if (plen == SIZE_MAX)
                    break;
                off += plen;
                if (packet_index == sizeof(packets) / sizeof(packets[0]) - 1 ||
                    !(packet_index == 0 || h2o_memis(packets[0].cid.dest.base, packets[0].cid.dest.len,
                                                     packets[packet_index].cid.dest.base, packets[packet_index].cid.dest.len))) {
                    process_packets(ctx, dgrams[dgram_index].mess.msg_name, dgrams[dgram_index].mess.msg_namelen, packets,
                                    packet_index + 1);
                    packet_index = 0;
                } else {
                    ++packet_index;
                }
            }
        }
        if (packet_index != 0)
            process_packets(ctx, dgrams[dgram_index - 1].mess.msg_name, dgrams[dgram_index - 1].mess.msg_namelen, packets,
                            packet_index);
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
    } while (ret == 0 && num_packets == sizeof(packets) / sizeof(packets[0]));

    assert(ret == 0);

    h2o_hq_schedule_timer(conn);
}

void h2o_hq_schedule_timer(h2o_hq_conn_t *conn)
{
    int64_t timeout = quicly_get_first_timeout(conn->quic);
    if (h2o_timer_is_linked(&conn->_timeout)) {
#if !H2O_USE_LIBUV /* optimization to skip registering a timer specifying the same time */
        if (timeout == conn->_timeout.expire_at)
            return;
#endif
        h2o_timer_unlink(&conn->_timeout);
    }
    h2o_timer_link(conn->ctx->loop, timeout, &conn->_timeout);
}
