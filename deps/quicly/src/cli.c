/*
 * Copyright (c) 2017 Fastly, Kazuho Oku
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
#include <getopt.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include "quicly.h"
#include "quicly/defaults.h"
#include "quicly/streambuf.h"
#include "../deps/picotls/t/util.h"

static unsigned verbosity = 0;
static int64_t enqueue_requests_at = 0, request_interval = 0;

static void hexdump(const char *title, const uint8_t *p, size_t l)
{
    fprintf(stderr, "%s (%zu bytes):\n", title, l);

    while (l != 0) {
        int i;
        fputs("   ", stderr);
        for (i = 0; i < 16; ++i) {
            fprintf(stderr, " %02x", *p++);
            if (--l == 0)
                break;
        }
        fputc('\n', stderr);
    }
}

static int save_ticket_cb(ptls_save_ticket_t *_self, ptls_t *tls, ptls_iovec_t src);

static const char *ticket_file = NULL;
static ptls_handshake_properties_t hs_properties;
static quicly_transport_parameters_t resumed_transport_params;
static quicly_context_t ctx;
static quicly_cid_plaintext_t next_cid;
static ptls_save_ticket_t save_ticket = {save_ticket_cb};
static int enforce_retry;

ptls_key_exchange_algorithm_t *key_exchanges[128];
static ptls_context_t tlsctx = {.random_bytes = ptls_openssl_random_bytes,
                                .get_time = &ptls_get_time,
                                .key_exchanges = key_exchanges,
                                .cipher_suites = ptls_openssl_cipher_suites,
                                .require_dhe_on_psk = 1,
                                .save_ticket = &save_ticket};
static const char *req_paths[1024];

static int on_stop_sending(quicly_stream_t *stream, int err);
static int on_receive_reset(quicly_stream_t *stream, int err);
static int server_on_receive(quicly_stream_t *stream, size_t off, const void *src, size_t len);
static int client_on_receive(quicly_stream_t *stream, size_t off, const void *src, size_t len);

static const quicly_stream_callbacks_t server_stream_callbacks = {quicly_streambuf_destroy,
                                                                  quicly_streambuf_egress_shift,
                                                                  quicly_streambuf_egress_emit,
                                                                  on_stop_sending,
                                                                  server_on_receive,
                                                                  on_receive_reset},
                                       client_stream_callbacks = {quicly_streambuf_destroy,
                                                                  quicly_streambuf_egress_shift,
                                                                  quicly_streambuf_egress_emit,
                                                                  on_stop_sending,
                                                                  client_on_receive,
                                                                  on_receive_reset};

static int parse_request(ptls_iovec_t input, ptls_iovec_t *path, int *is_http1)
{
    size_t off = 0, path_start;

    for (off = 0; off != input.len; ++off)
        if (input.base[off] == ' ')
            goto EndOfMethod;
    return 0;

EndOfMethod:
    ++off;
    path_start = off;
    for (; off != input.len; ++off)
        if (input.base[off] == ' ' || input.base[off] == '\r' || input.base[off] == '\n')
            goto EndOfPath;
    return 0;

EndOfPath:
    *path = ptls_iovec_init(input.base + path_start, off - path_start);
    *is_http1 = input.base[off] == ' ';
    return 1;
}

static int path_is(ptls_iovec_t path, const char *expected)
{
    size_t expected_len = strlen(expected);
    if (path.len != expected_len)
        return 0;
    return memcmp(path.base, expected, path.len) == 0;
}

static void send_str(quicly_stream_t *stream, const char *s)
{
    quicly_streambuf_egress_write(stream, s, strlen(s));
}

static void send_header(quicly_stream_t *stream, int is_http1, int status, const char *mime_type)
{
    char buf[256];

    if (!is_http1)
        return;

    sprintf(buf, "HTTP/1.1 %03d OK\r\nConnection: close\r\nContent-Type: %s\r\n\r\n", status, mime_type);
    send_str(stream, buf);
}

static int send_file(quicly_stream_t *stream, int is_http1, const char *fn, const char *mime_type)
{
    FILE *fp;
    char buf[1024];
    size_t n;

    if ((fp = fopen(fn, "rb")) == NULL)
        return 0;
    send_header(stream, is_http1, 200, mime_type);
    while ((n = fread(buf, 1, sizeof(buf), fp)) != 0)
        quicly_streambuf_egress_write(stream, buf, n);
    fclose(fp);

    return 1;
}

static int send_sized_text(quicly_stream_t *stream, ptls_iovec_t path, int is_http1)
{
    if (!(path.len > 5 && path.base[0] == '/' && memcmp(path.base + path.len - 4, ".txt", 4) == 0))
        return 0;
    unsigned size = 0;
    {
        const char *p;
        for (p = (const char *)path.base + 1; *p != '.'; ++p) {
            if (!('0' <= *p && *p <= '9'))
                return 0;
            size = size * 10 + (*p - '0');
        }
    }

    send_header(stream, is_http1, 200, "text/plain; charset=utf-8");
    for (; size >= 12; size -= 12)
        quicly_streambuf_egress_write(stream, "hello world\n", 12);
    if (size != 0)
        quicly_streambuf_egress_write(stream, "hello world", size);
    return 1;
}

static int on_stop_sending(quicly_stream_t *stream, int err)
{
    assert(QUICLY_ERROR_IS_QUIC_APPLICATION(err));
    fprintf(stderr, "received STOP_SENDING: %" PRIu16 "\n", QUICLY_ERROR_GET_ERROR_CODE(err));
    return 0;
}

static int on_receive_reset(quicly_stream_t *stream, int err)
{
    assert(QUICLY_ERROR_IS_QUIC_APPLICATION(err));
    fprintf(stderr, "received RESET_STREAM: %" PRIu16 "\n", QUICLY_ERROR_GET_ERROR_CODE(err));
    return 0;
}

static int server_on_receive(quicly_stream_t *stream, size_t off, const void *src, size_t len)
{
    ptls_iovec_t path;
    int is_http1;
    int ret;

    if ((ret = quicly_streambuf_ingress_receive(stream, off, src, len)) != 0)
        return ret;

    if (!parse_request(quicly_streambuf_ingress_get(stream), &path, &is_http1)) {
        if (!quicly_recvstate_transfer_complete(&stream->recvstate))
            return 0;
        /* failed to parse request */
        send_header(stream, 1, 500, "text/plain; charset=utf-8");
        send_str(stream, "failed to parse HTTP request\n");
        goto Sent;
    }
    if (!quicly_recvstate_transfer_complete(&stream->recvstate))
        quicly_request_stop(stream, 0);

    if (path_is(path, "/logo.jpg") && send_file(stream, is_http1, "assets/logo.jpg", "image/jpeg"))
        goto Sent;
    if (path_is(path, "/main.jpg") && send_file(stream, is_http1, "assets/main.jpg", "image/jpeg"))
        goto Sent;
    if (send_sized_text(stream, path, is_http1))
        goto Sent;

    if (!quicly_sendstate_is_open(&stream->sendstate))
        return 0;

    send_header(stream, is_http1, 404, "text/plain; charset=utf-8");
    send_str(stream, "not found\n");
Sent:
    quicly_streambuf_egress_shutdown(stream);
    quicly_streambuf_ingress_shift(stream, len);
    return 0;
}

static int client_on_receive(quicly_stream_t *stream, size_t off, const void *src, size_t len)
{
    ptls_iovec_t input;
    int ret;

    if ((ret = quicly_streambuf_ingress_receive(stream, off, src, len)) != 0)
        return ret;

    if ((input = quicly_streambuf_ingress_get(stream)).len != 0) {
        fwrite(input.base, 1, input.len, stdout);
        fflush(stdout);
        quicly_streambuf_ingress_shift(stream, input.len);
    }

    if (quicly_recvstate_transfer_complete(&stream->recvstate)) {
        static size_t num_resp_received;
        ++num_resp_received;
        if (req_paths[num_resp_received] == NULL) {
            if (request_interval != 0) {
                enqueue_requests_at = ctx.now->cb(ctx.now) + request_interval;
            } else {
                uint64_t num_received, num_sent, num_lost, num_ack_received, num_bytes_sent;
                quicly_get_packet_stats(stream->conn, &num_received, &num_sent, &num_lost, &num_ack_received, &num_bytes_sent);
                fprintf(stderr,
                        "packets: received: %" PRIu64 ", sent: %" PRIu64 ", lost: %" PRIu64 ", ack-received: %" PRIu64
                        ", bytes-sent: %" PRIu64 "\n",
                        num_received, num_sent, num_lost, num_ack_received, num_bytes_sent);
                quicly_close(stream->conn, 0, "");
            }
        }
    }

    return 0;
}

static int on_stream_open(quicly_stream_open_t *self, quicly_stream_t *stream)
{
    int ret;

    if ((ret = quicly_streambuf_create(stream, sizeof(quicly_streambuf_t))) != 0)
        return ret;
    stream->callbacks = ctx.tls->certificates.count != 0 ? &server_stream_callbacks : &client_stream_callbacks;
    return 0;
}

static quicly_stream_open_t stream_open = {&on_stream_open};

static void on_closed_by_peer(quicly_closed_by_peer_t *self, quicly_conn_t *conn, int err, uint64_t frame_type, const char *reason,
                              size_t reason_len)
{
    if (QUICLY_ERROR_IS_QUIC_TRANSPORT(err)) {
        fprintf(stderr, "transport close:code=0x%" PRIx16 ";frame=%" PRIu64 ";reason=%.*s\n", QUICLY_ERROR_GET_ERROR_CODE(err),
                frame_type, (int)reason_len, reason);
    } else if (QUICLY_ERROR_IS_QUIC_APPLICATION(err)) {
        fprintf(stderr, "application close:code=0x%" PRIx16 ";reason=%.*s\n", QUICLY_ERROR_GET_ERROR_CODE(err), (int)reason_len,
                reason);
    } else if (err == QUICLY_ERROR_RECEIVED_STATELESS_RESET) {
        fprintf(stderr, "stateless reset\n");
    } else {
        fprintf(stderr, "unexpected close:code=%d\n", err);
    }
}

static quicly_closed_by_peer_t closed_by_peer = {&on_closed_by_peer};

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
    if (verbosity >= 2)
        hexdump("sendmsg", vec.iov_base, vec.iov_len);
    while ((ret = (int)sendmsg(fd, &mess, 0)) == -1 && errno == EINTR)
        ;
    return ret;
}

static int send_pending(int fd, quicly_conn_t *conn)
{
    quicly_datagram_t *packets[16];
    size_t num_packets, i;
    int ret;

    do {
        num_packets = sizeof(packets) / sizeof(packets[0]);
        if ((ret = quicly_send(conn, packets, &num_packets)) == 0) {
            for (i = 0; i != num_packets; ++i) {
                if ((ret = send_one(fd, packets[i])) == -1)
                    perror("sendmsg failed");
                ret = 0;
                quicly_packet_allocator_t *pa = quicly_get_context(conn)->packet_allocator;
                pa->free_packet(pa, packets[i]);
            }
        }
    } while (ret == 0 && num_packets == sizeof(packets) / sizeof(packets[0]));

    return ret;
}

static void set_alpn(ptls_handshake_properties_t *pro, const char *alpn_str)
{
    const char *start, *cur;
    ptls_iovec_t *list = NULL;
    size_t entries = 0;
    start = cur = alpn_str;
#define ADD_ONE()                                                                                                                  \
    if ((cur - start) > 0) {                                                                                                       \
        list = realloc(list, sizeof(*list) * (entries + 1));                                                                       \
        list[entries].base = (void *)strndup(start, cur - start);                                                                  \
        list[entries++].len = cur - start;                                                                                         \
    }

    while (*cur) {
        if (*cur == ',') {
            ADD_ONE();
            start = cur + 1;
        }
        cur++;
    }
    if (start != cur)
        ADD_ONE();

    pro->client.negotiated_protocols.list = list;
    pro->client.negotiated_protocols.count = entries;
}

static void enqueue_requests(quicly_conn_t *conn)
{
    size_t i;
    int ret;

    for (i = 0; req_paths[i] != NULL; ++i) {
        char req[1024];
        quicly_stream_t *stream;
        ret = quicly_open_stream(conn, &stream, 0);
        assert(ret == 0);
        sprintf(req, "GET %s\r\n", req_paths[i]);
        send_str(stream, req);
        quicly_streambuf_egress_shutdown(stream);
    }
    enqueue_requests_at = INT64_MAX;
}

static int run_client(struct sockaddr *sa, socklen_t salen, const char *host)
{
    int fd, ret;
    struct sockaddr_in local;
    quicly_conn_t *conn = NULL;

    if ((fd = socket(sa->sa_family, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
        perror("socket(2) failed");
        return 1;
    }
    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    if (bind(fd, (void *)&local, sizeof(local)) != 0) {
        perror("bind(2) failed");
        return 1;
    }
    ret = quicly_connect(&conn, &ctx, host, sa, salen, &next_cid, &hs_properties, &resumed_transport_params);
    assert(ret == 0);
    ++next_cid.master_id;
    enqueue_requests(conn);
    send_pending(fd, conn);

    while (1) {
        fd_set readfds;
        struct timeval *tv, tvbuf;
        do {
            int64_t timeout_at = conn != NULL ? quicly_get_first_timeout(conn) : INT64_MAX;
            if (enqueue_requests_at < timeout_at)
                timeout_at = enqueue_requests_at;
            if (timeout_at != INT64_MAX) {
                quicly_context_t *ctx = quicly_get_context(conn);
                int64_t delta = timeout_at - ctx->now->cb(ctx->now);
                if (delta > 0) {
                    tvbuf.tv_sec = delta / 1000;
                    tvbuf.tv_usec = (delta % 1000) * 1000;
                } else {
                    tvbuf.tv_sec = 0;
                    tvbuf.tv_usec = 0;
                }
                tv = &tvbuf;
            } else {
                tv = NULL;
            }
            FD_ZERO(&readfds);
            FD_SET(fd, &readfds);
        } while (select(fd + 1, &readfds, NULL, NULL, tv) == -1 && errno == EINTR);
        if (enqueue_requests_at <= ctx.now->cb(ctx.now))
            enqueue_requests(conn);
        if (FD_ISSET(fd, &readfds)) {
            uint8_t buf[4096];
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
            while ((rret = recvmsg(fd, &mess, 0)) <= 0)
                ;
            if (verbosity >= 2)
                hexdump("recvmsg", buf, rret);
            size_t off = 0;
            while (off != rret) {
                quicly_decoded_packet_t packet;
                size_t plen = quicly_decode_packet(&ctx, &packet, buf + off, rret - off);
                if (plen == SIZE_MAX)
                    break;
                quicly_receive(conn, &packet);
                off += plen;
            }
        }
        if (conn != NULL) {
            ret = send_pending(fd, conn);
            if (ret != 0) {
                quicly_free(conn);
                conn = NULL;
                if (ret == QUICLY_ERROR_FREE_CONNECTION) {
                    return 0;
                } else {
                    fprintf(stderr, "quicly_send returned %d\n", ret);
                    return 1;
                }
            }
        }
    }
}

static quicly_conn_t **conns;
static size_t num_conns = 0;

static void on_signal(int signo)
{
    size_t i;
    for (i = 0; i != num_conns; ++i) {
        const quicly_cid_plaintext_t *master_id = quicly_get_master_id(conns[i]);
        uint64_t num_received, num_sent, num_lost, num_ack_received, num_bytes_sent;
        quicly_get_packet_stats(conns[i], &num_received, &num_sent, &num_lost, &num_ack_received, &num_bytes_sent);
        fprintf(stderr,
                "conn:%08" PRIu32 ": received: %" PRIu64 ", sent: %" PRIu64 ", lost: %" PRIu64 ", ack-received: %" PRIu64
                ", bytes-sent: %" PRIu64 "\n",
                master_id->master_id, num_received, num_sent, num_lost, num_ack_received, num_bytes_sent);
    }
    if (signo == SIGINT)
        _exit(0);
}

static int run_server(struct sockaddr *sa, socklen_t salen)
{
    int fd;

    signal(SIGINT, on_signal);
    signal(SIGHUP, on_signal);

    if ((fd = socket(sa->sa_family, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
        perror("socket(2) failed");
        return 1;
    }
    int on = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) != 0) {
        perror("setsockopt(SO_REUSEADDR) failed");
        return 1;
    }
    if (bind(fd, sa, salen) != 0) {
        perror("bind(2) failed");
        return 1;
    }

    while (1) {
        fd_set readfds;
        struct timeval *tv, tvbuf;
        do {
            int64_t timeout_at = INT64_MAX;
            size_t i;
            for (i = 0; i != num_conns; ++i) {
                int64_t conn_to = quicly_get_first_timeout(conns[i]);
                if (conn_to < timeout_at)
                    timeout_at = conn_to;
            }
            if (timeout_at != INT64_MAX) {
                int64_t delta = timeout_at - ctx.now->cb(ctx.now);
                if (delta > 0) {
                    tvbuf.tv_sec = delta / 1000;
                    tvbuf.tv_usec = (delta % 1000) * 1000;
                } else {
                    tvbuf.tv_sec = 0;
                    tvbuf.tv_usec = 0;
                }
                tv = &tvbuf;
            } else {
                tv = NULL;
            }
            FD_ZERO(&readfds);
            FD_SET(fd, &readfds);
        } while (select(fd + 1, &readfds, NULL, NULL, tv) == -1 && errno == EINTR);
        if (FD_ISSET(fd, &readfds)) {
            uint8_t buf[4096];
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
            while ((rret = recvmsg(fd, &mess, 0)) <= 0)
                ;
            if (verbosity >= 2)
                hexdump("recvmsg", buf, rret);
            size_t off = 0;
            while (off != rret) {
                quicly_decoded_packet_t packet;
                size_t plen = quicly_decode_packet(&ctx, &packet, buf + off, rret - off);
                if (plen == SIZE_MAX)
                    break;
                if (QUICLY_PACKET_IS_LONG_HEADER(packet.octets.base[0])) {
                    if (packet.version != QUICLY_PROTOCOL_VERSION) {
                        quicly_datagram_t *rp =
                            quicly_send_version_negotiation(&ctx, &sa, salen, packet.cid.src, packet.cid.dest.encrypted);
                        assert(rp != NULL);
                        if (send_one(fd, rp) == -1)
                            perror("sendmsg failed");
                        break;
                    }
                }
                quicly_conn_t *conn = NULL;
                size_t i;
                for (i = 0; i != num_conns; ++i) {
                    if (quicly_is_destination(conns[i], &sa, salen, &packet)) {
                        conn = conns[i];
                        break;
                    }
                }
                if (conn != NULL) {
                    /* existing connection */
                    quicly_receive(conn, &packet);
                } else if (QUICLY_PACKET_IS_LONG_HEADER(packet.octets.base[0])) {
                    /* long header packet; potentially a new connection */
                    if (enforce_retry && packet.token.len == 0 && packet.cid.dest.encrypted.len >= 8) {
                        /* unbound connection; send a retry token unless the client has supplied the correct one, but not too many
                         */
                        uint8_t new_server_cid[8];
                        memcpy(new_server_cid, packet.cid.dest.encrypted.base, sizeof(new_server_cid));
                        new_server_cid[0] ^= 0xff;
                        quicly_datagram_t *rp = quicly_send_retry(
                            &ctx, &sa, salen, packet.cid.src, ptls_iovec_init(new_server_cid, sizeof(new_server_cid)),
                            packet.cid.dest.encrypted, packet.cid.dest.encrypted /* FIXME SMAC(odcid || sockaddr) */);
                        assert(rp != NULL);
                        if (send_one(fd, rp) == -1)
                            perror("sendmsg failed");
                        break;
                    } else {
                        /* new connection */
                        int ret = quicly_accept(&conn, &ctx, &sa, mess.msg_namelen, &packet,
                                                enforce_retry ? packet.token /* a production server should validate the token */
                                                              : ptls_iovec_init(NULL, 0),
                                                &next_cid, NULL);
                        if (ret == 0) {
                            assert(conn != NULL);
                            ++next_cid.master_id;
                            conns = realloc(conns, sizeof(*conns) * (num_conns + 1));
                            assert(conns != NULL);
                            conns[num_conns++] = conn;
                        } else {
                            assert(conn == NULL);
                        }
                    }
                } else {
                    /* short header packet; potentially a dead connection. No need to check the length of the incoming packet,
                     * because loop is prevented by authenticating the CID (by checking node_id and thread_id). If the peer is also
                     * sending a reset, then the next CID is highly likely to contain a non-authenticating CID, ... */
                    if (packet.cid.dest.plaintext.node_id == 0 && packet.cid.dest.plaintext.thread_id == 0) {
                        quicly_datagram_t *dgram = quicly_send_stateless_reset(&ctx, &sa, salen, packet.cid.dest.encrypted.base);
                        if (send_one(fd, dgram) == -1)
                            perror("sendmsg failed");
                    }
                }
                off += plen;
            }
        }
        {
            size_t i;
            for (i = 0; i != num_conns; ++i) {
                if (quicly_get_first_timeout(conns[i]) <= ctx.now->cb(ctx.now)) {
                    if (send_pending(fd, conns[i]) != 0) {
                        quicly_free(conns[i]);
                        memmove(conns + i, conns + i + 1, (num_conns - i - 1) * sizeof(*conns));
                        --i;
                        --num_conns;
                    }
                }
            }
        }
    }
}

int save_ticket_cb(ptls_save_ticket_t *_self, ptls_t *tls, ptls_iovec_t src)
{
    quicly_conn_t *conn = *ptls_get_data_ptr(tls);
    ptls_buffer_t buf;
    FILE *fp = NULL;
    int ret;

    if (ticket_file == NULL)
        return 0;

    ptls_buffer_init(&buf, "", 0);

    /* build data (session ticket and transport parameters) */
    ptls_buffer_push_block(&buf, 2, { ptls_buffer_pushv(&buf, src.base, src.len); });
    ptls_buffer_push_block(&buf, 2, {
        if ((ret = quicly_encode_transport_parameter_list(&buf, 1, quicly_get_peer_transport_parameters(conn), NULL, NULL)) != 0)
            goto Exit;
    });

    /* write file */
    if ((fp = fopen(ticket_file, "wb")) == NULL) {
        fprintf(stderr, "failed to open file:%s:%s\n", ticket_file, strerror(errno));
        ret = PTLS_ERROR_LIBRARY;
        goto Exit;
    }
    fwrite(buf.base, 1, buf.off, fp);

    ret = 0;
Exit:
    if (fp != NULL)
        fclose(fp);
    ptls_buffer_dispose(&buf);
    return 0;
}

static void load_ticket(void)
{
    static uint8_t buf[65536];
    size_t len;
    int ret;

    {
        FILE *fp;
        if ((fp = fopen(ticket_file, "rb")) == NULL)
            return;
        len = fread(buf, 1, sizeof(buf), fp);
        if (len == 0 || !feof(fp)) {
            fprintf(stderr, "failed to load ticket from file:%s\n", ticket_file);
            exit(1);
        }
        fclose(fp);
    }

    {
        const uint8_t *src = buf, *end = buf + len;
        ptls_iovec_t ticket;
        ptls_decode_open_block(src, end, 2, {
            ticket = ptls_iovec_init(src, end - src);
            src = end;
        });
        ptls_decode_block(src, end, 2, {
            if ((ret = quicly_decode_transport_parameter_list(&resumed_transport_params, NULL, NULL, 1, src, end)) != 0)
                goto Exit;
            src = end;
        });
        hs_properties.client.session_ticket = ticket;
    }

Exit:;
}

static void usage(const char *cmd)
{
    printf("Usage: %s [options] host port\n"
           "\n"
           "Options:\n"
           "  -a <alpn list>       a coma separated list of ALPN identifiers\n"
           "  -C <cid-key>         CID encryption key (server-only). Randomly generated\n"
           "                       if omitted.\n"
           "  -c certificate-file\n"
           "  -k key-file          specifies the credentials to be used for running the\n"
           "                       server. If omitted, the command runs as a client.\n"
           "  -e event-log-file    file to log events\n"
           "  -i interval          interval to reissue requests (in milliseconds)\n"
           "  -l log-file          file to log traffic secrets\n"
           "  -M <bytes>           max stream data (in bytes; default: 1MB)\n"
           "  -m <bytes>           max data (in bytes; default: 16MB)\n"
           "  -N                   enforce HelloRetryRequest (client-only)\n"
           "  -n                   enforce version negotiation (client-only)\n"
           "  -p path              path to request (can be set multiple times)\n"
           "  -R                   require Retry (server only)\n"
           "  -r [initial-rto]     initial RTO (in milliseconds)\n"
           "  -s session-file      file to load / store the session ticket\n"
           "  -V                   verify peer using the default certificates\n"
           "  -v                   verbose mode (-vv emits packet dumps as well)\n"
           "  -x named-group       named group to be used (default: secp256r1)\n"
           "  -X                   max bidirectional stream count (default: 100)\n"
           "  -h                   print this help\n"
           "\n",
           cmd);
}

int main(int argc, char **argv)
{
    const char *host, *port, *cid_key = NULL;
    struct sockaddr_storage sa;
    socklen_t salen;
    int ch;

    ctx = quicly_default_context;
    ctx.tls = &tlsctx;
    ctx.stream_open = &stream_open;
    ctx.closed_by_peer = &closed_by_peer;

    setup_session_cache(ctx.tls);
    quicly_amend_ptls_context(ctx.tls);

    while ((ch = getopt(argc, argv, "a:C:c:k:e:i:l:M:m:Nnp:Rr:s:Vvx:X:h")) != -1) {
        switch (ch) {
        case 'a':
            set_alpn(&hs_properties, optarg);
            break;
        case 'C':
            cid_key = optarg;
            break;
        case 'c':
            load_certificate_chain(ctx.tls, optarg);
            break;
        case 'k':
            load_private_key(ctx.tls, optarg);
            break;
        case 'e': {
            FILE *fp;
            if ((fp = fopen(optarg, "w")) == NULL) {
                fprintf(stderr, "failed to open file:%s:%s\n", optarg, strerror(errno));
                exit(1);
            }
            setvbuf(fp, NULL, _IONBF, 0);
            ctx.event_log.mask = UINT64_MAX;
            ctx.event_log.cb = quicly_new_default_event_logger(fp);
        } break;
        case 'i':
            if (sscanf(optarg, "%" PRId64, &request_interval) != 1) {
                fprintf(stderr, "failed to parse request interval: %s\n", optarg);
                exit(1);
            }
            break;
        case 'l':
            setup_log_event(ctx.tls, optarg);
            break;
        case 'M': {
            uint64_t v;
            if (sscanf(optarg, "%" PRIu64, &v) != 1) {
                fprintf(stderr, "failed to parse max stream data:%s\n", optarg);
                exit(1);
            }
            ctx.transport_params.max_stream_data.bidi_local = v;
            ctx.transport_params.max_stream_data.bidi_remote = v;
            ctx.transport_params.max_stream_data.uni = v;
        } break;
        case 'm':
            if (sscanf(optarg, "%" PRIu64, &ctx.transport_params.max_data) != 1) {
                fprintf(stderr, "failed to parse max data:%s\n", optarg);
                exit(1);
            }
            break;
        case 'N':
            hs_properties.client.negotiate_before_key_exchange = 1;
            break;
        case 'n':
            ctx.enforce_version_negotiation = 1;
            break;
        case 'p': {
            size_t i;
            for (i = 0; req_paths[i] != NULL; ++i)
                ;
            req_paths[i] = optarg;
        } break;
        case 'R':
            enforce_retry = 1;
            break;
        case 'r':
            if (sscanf(optarg, "%" PRIu32, &ctx.loss->default_initial_rtt) != 1) {
                fprintf(stderr, "invalid argument passed to `-r`\n");
                exit(1);
            }
            break;
        case 's':
            ticket_file = optarg;
            break;
        case 'V':
            setup_verify_certificate(ctx.tls);
            break;
        case 'v':
            ++verbosity;
            break;
        case 'x': {
            size_t i;
            for (i = 0; key_exchanges[i] != NULL; ++i)
                ;
#define MATCH(name)                                                                                                                \
    if (key_exchanges[i] == NULL && strcasecmp(optarg, #name) == 0)                                                                \
    key_exchanges[i] = &ptls_openssl_##name
            MATCH(secp256r1);
#if PTLS_OPENSSL_HAVE_SECP384R1
            MATCH(secp384r1);
#endif
#if PTLS_OPENSSL_HAVE_SECP521R1
            MATCH(secp521r1);
#endif
#if PTLS_OPENSSL_HAVE_X25519
            MATCH(x25519);
#endif
#undef MATCH
            if (key_exchanges[i] == NULL) {
                fprintf(stderr, "unknown key exchange: %s\n", optarg);
                exit(1);
            }
        } break;
        case 'X':
            if (sscanf(optarg, "%" PRIu64, &ctx.transport_params.max_streams_bidi) != 1) {
                fprintf(stderr, "failed to parse max streams count: %s\n", optarg);
                exit(1);
            }
            break;
        default:
            usage(argv[0]);
            exit(1);
        }
    }
    argc -= optind;
    argv += optind;

    if (req_paths[0] == NULL)
        req_paths[0] = "/";

    if (key_exchanges[0] == NULL)
        key_exchanges[0] = &ptls_openssl_secp256r1;

    if (ctx.tls->certificates.count != 0 || ctx.tls->sign_certificate != NULL) {
        /* server */
        if (ctx.tls->certificates.count == 0 || ctx.tls->sign_certificate == NULL) {
            fprintf(stderr, "-ck and -k options must be used together\n");
            exit(1);
        }
        if (cid_key == NULL) {
            static char random_key[17];
            tlsctx.random_bytes(random_key, sizeof(random_key) - 1);
            cid_key = random_key;
        }
        ctx.cid_encryptor =
            quicly_new_default_cid_encryptor(&ptls_openssl_bfecb, &ptls_openssl_sha256, ptls_iovec_init(cid_key, strlen(cid_key)));
    } else {
        /* client */
        if (ticket_file != NULL)
            load_ticket();
    }
    if (argc != 2) {
        fprintf(stderr, "missing host and port\n");
        exit(1);
    }
    host = (--argc, *argv++);
    port = (--argc, *argv++);

    if (resolve_address((void *)&sa, &salen, host, port, AF_INET, SOCK_DGRAM, IPPROTO_UDP) != 0)
        exit(1);

    return ctx.tls->certificates.count != 0 ? run_server((void *)&sa, salen) : run_client((void *)&sa, salen, host);
}
