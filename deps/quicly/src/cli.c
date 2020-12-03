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
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <getopt.h>
#include <netinet/udp.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <unistd.h>
#include <picotls.h>
#if QUICLY_HAVE_FUSION
#include "picotls/fusion.h"
#endif
#include "quicly.h"
#include "quicly/defaults.h"
#include "quicly/streambuf.h"
#include "../deps/picotls/t/util.h"

#define MAX_BURST_PACKETS 10

FILE *quicly_trace_fp = NULL;
static unsigned verbosity = 0;
static int suppress_output = 0, send_datagram_frame = 0;
static int64_t enqueue_requests_at = 0, request_interval = 0;
static void *datagram_frame_payload_buf;

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

static int save_session_ticket_cb(ptls_save_ticket_t *_self, ptls_t *tls, ptls_iovec_t src);
static int on_client_hello_cb(ptls_on_client_hello_t *_self, ptls_t *tls, ptls_on_client_hello_parameters_t *params);

static const char *session_file = NULL;
static ptls_handshake_properties_t hs_properties;
static quicly_transport_parameters_t resumed_transport_params;
static ptls_iovec_t resumption_token;
static quicly_context_t ctx;
static quicly_cid_plaintext_t next_cid;
static struct {
    ptls_aead_context_t *enc, *dec;
} address_token_aead;
static ptls_save_ticket_t save_session_ticket = {save_session_ticket_cb};
static ptls_on_client_hello_t on_client_hello = {on_client_hello_cb};
static int enforce_retry;

#if QUICLY_HAVE_FUSION
static const ptls_cipher_suite_t fusion_aes128gcmsha256 = {PTLS_CIPHER_SUITE_AES_128_GCM_SHA256, &ptls_fusion_aes128gcm,
                                                           &ptls_openssl_sha256},
                                 fusion_aes256gcmsha384 = {PTLS_CIPHER_SUITE_AES_256_GCM_SHA384, &ptls_fusion_aes256gcm,
                                                           &ptls_openssl_sha384};
#endif

static ptls_key_exchange_algorithm_t *key_exchanges[128];
static ptls_cipher_suite_t *cipher_suites[128];
static ptls_context_t tlsctx = {.random_bytes = ptls_openssl_random_bytes,
                                .get_time = &ptls_get_time,
                                .key_exchanges = key_exchanges,
                                .cipher_suites = cipher_suites,
                                .require_dhe_on_psk = 1,
                                .save_ticket = &save_session_ticket,
                                .on_client_hello = &on_client_hello};
static struct {
    ptls_iovec_t list[16];
    size_t count;
} negotiated_protocols;

/**
 * list of requests to be processed, terminated by reqs[N].path == NULL
 */
struct {
    const char *path;
    int to_file;
} * reqs;

struct st_stream_data_t {
    quicly_streambuf_t streambuf;
    FILE *outfp;
};

static void on_stop_sending(quicly_stream_t *stream, int err);
static void on_receive_reset(quicly_stream_t *stream, int err);
static void server_on_receive(quicly_stream_t *stream, size_t off, const void *src, size_t len);
static void client_on_receive(quicly_stream_t *stream, size_t off, const void *src, size_t len);

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

static void dump_stats(FILE *fp, quicly_conn_t *conn)
{
    quicly_stats_t stats;

    quicly_get_stats(conn, &stats);
    fprintf(fp,
            "packets-received: %" PRIu64 ", packets-decryption-failed: %" PRIu64 ", packets-sent: %" PRIu64
            ", packets-lost: %" PRIu64 ", ack-received: %" PRIu64 ", late-acked: %" PRIu64 ", bytes-received: %" PRIu64
            ", bytes-sent: %" PRIu64 ", srtt: %" PRIu32 "\n",
            stats.num_packets.received, stats.num_packets.decryption_failed, stats.num_packets.sent, stats.num_packets.lost,
            stats.num_packets.ack_received, stats.num_packets.late_acked, stats.num_bytes.received, stats.num_bytes.sent,
            stats.rtt.smoothed);
}

static int validate_path(const char *path)
{
    if (path[0] != '/')
        return 0;
    /* TODO avoid false positives on the client-side */
    if (strstr(path, "/.") != NULL)
        return 0;
    return 1;
}

static int parse_request(ptls_iovec_t input, char **path, int *is_http1)
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
    *path = (char *)(input.base + path_start);
    *is_http1 = input.base[off] == ' ';
    input.base[off] = '\0';
    return 1;
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

static int flatten_file_vec(quicly_sendbuf_vec_t *vec, void *dst, size_t off, size_t len)
{
    int fd = (intptr_t)vec->cbdata;
    ssize_t rret;

    /* FIXME handle partial read */
    while ((rret = pread(fd, dst, len, off)) == -1 && errno == EINTR)
        ;

    return rret == len ? 0 : QUICLY_TRANSPORT_ERROR_INTERNAL; /* should return application-level error */
}

static void discard_file_vec(quicly_sendbuf_vec_t *vec)
{
    int fd = (intptr_t)vec->cbdata;
    close(fd);
}

static int send_file(quicly_stream_t *stream, int is_http1, const char *fn, const char *mime_type)
{
    static const quicly_streambuf_sendvec_callbacks_t send_file_callbacks = {flatten_file_vec, discard_file_vec};
    int fd;
    struct stat st;

    if ((fd = open(fn, O_RDONLY)) == -1)
        return 0;
    if (fstat(fd, &st) != 0 || S_ISDIR(st.st_mode)) {
        close(fd);
        return 0;
    }

    send_header(stream, is_http1, 200, mime_type);
    quicly_sendbuf_vec_t vec = {&send_file_callbacks, (size_t)st.st_size, (void *)(intptr_t)fd};
    quicly_streambuf_egress_write_vec(stream, &vec);
    return 1;
}

/**
 * This function is an implementation of the quicly_sendbuf_flatten_vec_cb callback.  Refer to the doc-comments of the callback type
 * for the API.
 */
static int flatten_sized_text(quicly_sendbuf_vec_t *vec, void *dst, size_t off, size_t len)
{
    static const char pattern[] =
        "hello world\nhello world\nhello world\nhello world\nhello world\nhello world\nhello world\nhello world\nhello "
        "world\nhello world\nhello world\nhello world\nhello world\nhello world\nhello world\nhello world\nhello world\nhello "
        "world\nhello world\nhello world\nhello world\nhello world\nhello world\nhello world\nhello world\nhello world\nhello "
        "world\nhello world\nhello world\nhello world\nhello world\nhello world\nhello world\nhello world\nhello world\nhello "
        "world\nhello world\nhello world\nhello world\nhello world\nhello world\nhello world\nhello world\nhello world\nhello "
        "world\nhello world\nhello world\nhello world\nhello world\nhello world\nhello world\nhello world\nhello world\nhello "
        "world\nhello world\nhello world\nhello world\nhello world\nhello world\nhello world\nhello world\nhello world\nhello "
        "world\nhello world\nhello world\nhello world\nhello world\nhello world\nhello world\nhello world\nhello world\nhello "
        "world\nhello world\nhello world\nhello world\nhello world\nhello world\nhello world\nhello world\nhello world\nhello "
        "world\nhello world\nhello world\nhello world\nhello world\nhello world\nhello world\nhello world\nhello world\nhello "
        "world\nhello world\nhello world\nhello world\nhello world\nhello world\nhello world\nhello world\nhello world\nhello "
        "world\nhello world\nhello world\nhello world\nhello world\nhello world\nhello world\nhello world\nhello world\nhello "
        "world\nhello world\nhello world\nhello world\nhello world\nhello world\nhello world\nhello world\nhello world\nhello "
        "world\nhello world\nhello world\nhello world\nhello world\nhello world\nhello world\nhello world\nhello world\nhello "
        "world\nhello world\nhello world\nhello world\nhello world\nhello world\nhello world\nhello world\nhello world\nhello "
        "world\nhello world\nhello world\nhello world\nhello world\nhello world\n";

    while (len != 0) {
        const char *src = pattern + off % 12;
        if (src + len - pattern <= sizeof(pattern) - 1) {
            memcpy(dst, src, len);
            break;
        }
        memcpy(dst, src, sizeof(pattern) - 20);
        off += sizeof(pattern) - 20;
        dst += sizeof(pattern) - 20;
        len -= sizeof(pattern) - 20;
    }
    return 0;

#undef PATTERN
}

static int send_sized_text(quicly_stream_t *stream, const char *path, int is_http1)
{
    size_t size;
    int lastpos;

    if (sscanf(path, "/%zu%n", &size, &lastpos) != 1)
        return 0;
    if (lastpos != strlen(path))
        return 0;

    send_header(stream, is_http1, 200, "text/plain; charset=utf-8");
    static const quicly_streambuf_sendvec_callbacks_t callbacks = {flatten_sized_text};
    quicly_sendbuf_vec_t vec = {&callbacks, size, NULL};
    quicly_streambuf_egress_write_vec(stream, &vec);
    return 1;
}

static void on_stop_sending(quicly_stream_t *stream, int err)
{
    assert(QUICLY_ERROR_IS_QUIC_APPLICATION(err));
    fprintf(stderr, "received STOP_SENDING: %" PRIu16 "\n", QUICLY_ERROR_GET_ERROR_CODE(err));
}

static void on_receive_reset(quicly_stream_t *stream, int err)
{
    assert(QUICLY_ERROR_IS_QUIC_APPLICATION(err));
    fprintf(stderr, "received RESET_STREAM: %" PRIu16 "\n", QUICLY_ERROR_GET_ERROR_CODE(err));
}

static void server_on_receive(quicly_stream_t *stream, size_t off, const void *src, size_t len)
{
    char *path;
    int is_http1;

    if (!quicly_sendstate_is_open(&stream->sendstate))
        return;

    if (quicly_streambuf_ingress_receive(stream, off, src, len) != 0)
        return;

    if (!parse_request(quicly_streambuf_ingress_get(stream), &path, &is_http1)) {
        if (!quicly_recvstate_transfer_complete(&stream->recvstate))
            return;
        /* failed to parse request */
        send_header(stream, 1, 500, "text/plain; charset=utf-8");
        send_str(stream, "failed to parse HTTP request\n");
        goto Sent;
    }
    if (!quicly_recvstate_transfer_complete(&stream->recvstate))
        quicly_request_stop(stream, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0));

    if (strcmp(path, "/logo.jpg") == 0 && send_file(stream, is_http1, "assets/logo.jpg", "image/jpeg"))
        goto Sent;
    if (strcmp(path, "/main.jpg") == 0 && send_file(stream, is_http1, "assets/main.jpg", "image/jpeg"))
        goto Sent;
    if (send_sized_text(stream, path, is_http1))
        goto Sent;
    if (validate_path(path) && send_file(stream, is_http1, path + 1, "text/plain"))
        goto Sent;

    send_header(stream, is_http1, 404, "text/plain; charset=utf-8");
    send_str(stream, "not found\n");
Sent:
    quicly_streambuf_egress_shutdown(stream);
    quicly_streambuf_ingress_shift(stream, len);
}

static void client_on_receive(quicly_stream_t *stream, size_t off, const void *src, size_t len)
{
    struct st_stream_data_t *stream_data = stream->data;
    ptls_iovec_t input;

    if (quicly_streambuf_ingress_receive(stream, off, src, len) != 0)
        return;

    if ((input = quicly_streambuf_ingress_get(stream)).len != 0) {
        if (!suppress_output) {
            FILE *out = (stream_data->outfp == NULL) ? stdout : stream_data->outfp;
            fwrite(input.base, 1, input.len, out);
            fflush(out);
        }
        quicly_streambuf_ingress_shift(stream, input.len);
    }

    if (quicly_recvstate_transfer_complete(&stream->recvstate)) {
        if (stream_data->outfp != NULL)
            fclose(stream_data->outfp);
        static size_t num_resp_received;
        ++num_resp_received;
        if (reqs[num_resp_received].path == NULL) {
            if (request_interval != 0) {
                enqueue_requests_at = ctx.now->cb(ctx.now) + request_interval;
            } else {
                dump_stats(stderr, stream->conn);
                quicly_close(stream->conn, 0, "");
            }
        }
    }
}

static int on_stream_open(quicly_stream_open_t *self, quicly_stream_t *stream)
{
    int ret;

    if ((ret = quicly_streambuf_create(stream, sizeof(struct st_stream_data_t))) != 0)
        return ret;
    stream->callbacks = ctx.tls->certificates.count != 0 ? &server_stream_callbacks : &client_stream_callbacks;
    return 0;
}

static quicly_stream_open_t stream_open = {&on_stream_open};

static void on_closed_by_remote(quicly_closed_by_remote_t *self, quicly_conn_t *conn, int err, uint64_t frame_type,
                                const char *reason, size_t reason_len)
{
    if (QUICLY_ERROR_IS_QUIC_TRANSPORT(err)) {
        fprintf(stderr, "transport close:code=0x%" PRIx16 ";frame=%" PRIu64 ";reason=%.*s\n", QUICLY_ERROR_GET_ERROR_CODE(err),
                frame_type, (int)reason_len, reason);
    } else if (QUICLY_ERROR_IS_QUIC_APPLICATION(err)) {
        fprintf(stderr, "application close:code=0x%" PRIx16 ";reason=%.*s\n", QUICLY_ERROR_GET_ERROR_CODE(err), (int)reason_len,
                reason);
    } else if (err == QUICLY_ERROR_RECEIVED_STATELESS_RESET) {
        fprintf(stderr, "stateless reset\n");
    } else if (err == QUICLY_ERROR_NO_COMPATIBLE_VERSION) {
        fprintf(stderr, "no compatible version\n");
    } else {
        fprintf(stderr, "unexpected close:code=%d\n", err);
    }
}

static quicly_closed_by_remote_t closed_by_remote = {&on_closed_by_remote};

static int on_generate_resumption_token(quicly_generate_resumption_token_t *self, quicly_conn_t *conn, ptls_buffer_t *buf,
                                        quicly_address_token_plaintext_t *token)
{
    return quicly_encrypt_address_token(tlsctx.random_bytes, address_token_aead.enc, buf, buf->off, token);
}

static quicly_generate_resumption_token_t generate_resumption_token = {&on_generate_resumption_token};

static void send_packets_default(int fd, struct sockaddr *dest, struct iovec *packets, size_t num_packets)
{
    for (size_t i = 0; i != num_packets; ++i) {
        struct msghdr mess;
        memset(&mess, 0, sizeof(mess));
        mess.msg_name = dest;
        mess.msg_namelen = quicly_get_socklen(dest);
        mess.msg_iov = &packets[i];
        mess.msg_iovlen = 1;
        if (verbosity >= 2)
            hexdump("sendmsg", packets[i].iov_base, packets[i].iov_len);
        int ret;
        while ((ret = (int)sendmsg(fd, &mess, 0)) == -1 && errno == EINTR)
            ;
        if (ret == -1)
            perror("sendmsg failed");
    }
}

#ifdef __linux__

#ifndef UDP_SEGMENT
#define UDP_SEGMENT 103
#endif

static void send_packets_gso(int fd, struct sockaddr *dest, struct iovec *packets, size_t num_packets)
{
    struct iovec vec = {.iov_base = (void *)packets[0].iov_base,
                        .iov_len = packets[num_packets - 1].iov_base + packets[num_packets - 1].iov_len - packets[0].iov_base};
    struct msghdr mess = {
        .msg_name = dest,
        .msg_namelen = quicly_get_socklen(dest),
        .msg_iov = &vec,
        .msg_iovlen = 1,
    };

    union {
        struct cmsghdr hdr;
        char buf[CMSG_SPACE(sizeof(uint16_t))];
    } cmsg;
    if (num_packets != 1) {
        cmsg.hdr.cmsg_level = SOL_UDP;
        cmsg.hdr.cmsg_type = UDP_SEGMENT;
        cmsg.hdr.cmsg_len = CMSG_LEN(sizeof(uint16_t));
        *(uint16_t *)CMSG_DATA(&cmsg.hdr) = packets[0].iov_len;
        mess.msg_control = &cmsg;
        mess.msg_controllen = (socklen_t)CMSG_SPACE(sizeof(uint16_t));
    }

    int ret;
    while ((ret = sendmsg(fd, &mess, 0)) == -1 && errno == EINTR)
        ;
    if (ret == -1)
        perror("sendmsg failed");
}

#endif

static void (*send_packets)(int, struct sockaddr *, struct iovec *, size_t) = send_packets_default;

static void send_one_packet(int fd, struct sockaddr *dest, const void *payload, size_t payload_len)
{
    struct iovec vec = {.iov_base = (void *)payload, .iov_len = payload_len};
    send_packets(fd, dest, &vec, 1);
}

static int send_pending(int fd, quicly_conn_t *conn)
{
    quicly_address_t dest, src;
    struct iovec packets[MAX_BURST_PACKETS];
    uint8_t buf[MAX_BURST_PACKETS * quicly_get_context(conn)->transport_params.max_udp_payload_size];
    size_t num_packets = MAX_BURST_PACKETS;
    int ret;

    if ((ret = quicly_send(conn, &dest, &src, packets, &num_packets, buf, sizeof(buf))) == 0 && num_packets != 0)
        send_packets(fd, &dest.sa, packets, num_packets);

    if (datagram_frame_payload_buf != NULL) {
        free(datagram_frame_payload_buf);
        datagram_frame_payload_buf = NULL;
    }

    return ret;
}

static void set_datagram_frame(quicly_conn_t *conn, ptls_iovec_t payload)
{
    if (datagram_frame_payload_buf != NULL)
        free(datagram_frame_payload_buf);

    /* replace payload.base with an allocated buffer */
    datagram_frame_payload_buf = malloc(payload.len);
    memcpy(datagram_frame_payload_buf, payload.base, payload.len);
    payload.base = datagram_frame_payload_buf;

    /* set data to be sent. The buffer is being freed in `send_pending` after `quicly_send` is being called. */
    quicly_set_datagram_frame(conn, payload);
}

static void on_receive_datagram_frame(quicly_receive_datagram_frame_t *self, quicly_conn_t *conn, ptls_iovec_t payload)
{
    printf("DATAGRAM: %.*s\n", (int)payload.len, payload.base);
    /* send responds with a datagram frame */
    if (!quicly_is_client(conn))
        set_datagram_frame(conn, payload);
}

static void enqueue_requests(quicly_conn_t *conn)
{
    size_t i;
    int ret;

    for (i = 0; reqs[i].path != NULL; ++i) {
        char req[1024], destfile[1024];
        quicly_stream_t *stream;
        ret = quicly_open_stream(conn, &stream, 0);
        assert(ret == 0);
        sprintf(req, "GET %s\r\n", reqs[i].path);
        send_str(stream, req);
        quicly_streambuf_egress_shutdown(stream);

        if (reqs[i].to_file && !suppress_output) {
            struct st_stream_data_t *stream_data = stream->data;
            sprintf(destfile, "%s.downloaded", strrchr(reqs[i].path, '/') + 1);
            stream_data->outfp = fopen(destfile, "w");
            if (stream_data->outfp == NULL) {
                fprintf(stderr, "failed to open destination file:%s:%s\n", reqs[i].path, strerror(errno));
                exit(1);
            }
        }
    }
    enqueue_requests_at = INT64_MAX;
}

static int run_client(int fd, struct sockaddr *sa, const char *host)
{
    struct sockaddr_in local;
    int ret;
    quicly_conn_t *conn = NULL;

    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    if (bind(fd, (void *)&local, sizeof(local)) != 0) {
        perror("bind(2) failed");
        return 1;
    }
    ret = quicly_connect(&conn, &ctx, host, sa, NULL, &next_cid, resumption_token, &hs_properties, &resumed_transport_params);
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
            while (1) {
                uint8_t buf[ctx.transport_params.max_udp_payload_size];
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
                while ((rret = recvmsg(fd, &mess, 0)) == -1 && errno == EINTR)
                    ;
                if (rret <= 0)
                    break;
                if (verbosity >= 2)
                    hexdump("recvmsg", buf, rret);
                size_t off = 0;
                while (off != rret) {
                    quicly_decoded_packet_t packet;
                    if (quicly_decode_packet(&ctx, &packet, buf, rret, &off) == SIZE_MAX)
                        break;
                    quicly_receive(conn, NULL, &sa, &packet);
                    if (send_datagram_frame && quicly_connection_is_ready(conn)) {
                        const char *message = "hello datagram!";
                        set_datagram_frame(conn, ptls_iovec_init(message, strlen(message)));
                        send_datagram_frame = 0;
                    }
                }
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
        fprintf(stderr, "conn:%08" PRIu32 ": ", master_id->master_id);
        dump_stats(stderr, conns[i]);
    }
    if (signo == SIGINT)
        _exit(0);
}

static int validate_token(struct sockaddr *remote, ptls_iovec_t client_cid, ptls_iovec_t server_cid,
                          quicly_address_token_plaintext_t *token, const char **err_desc)
{
    int64_t age;
    int port_is_equal;

    /* calculate and normalize age */
    if ((age = ctx.now->cb(ctx.now) - token->issued_at) < 0)
        age = 0;

    /* check address, deferring the use of port number match to type-specific checks */
    if (remote->sa_family != token->remote.sa.sa_family)
        goto AddressMismatch;
    switch (remote->sa_family) {
    case AF_INET: {
        struct sockaddr_in *sin = (struct sockaddr_in *)remote;
        if (sin->sin_addr.s_addr != token->remote.sin.sin_addr.s_addr)
            goto AddressMismatch;
        port_is_equal = sin->sin_port == token->remote.sin.sin_port;
    } break;
    case AF_INET6: {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)remote;
        if (memcmp(&sin6->sin6_addr, &token->remote.sin6.sin6_addr, sizeof(sin6->sin6_addr)) != 0)
            goto AddressMismatch;
        port_is_equal = sin6->sin6_port == token->remote.sin6.sin6_port;
    } break;
    default:
        goto UnknownAddressType;
    }

    /* type-specific checks */
    switch (token->type) {
    case QUICLY_ADDRESS_TOKEN_TYPE_RETRY:
        if (age > 30000)
            goto Expired;
        if (!port_is_equal)
            goto AddressMismatch;
        if (!quicly_cid_is_equal(&token->retry.client_cid, client_cid))
            goto CIDMismatch;
        if (!quicly_cid_is_equal(&token->retry.server_cid, server_cid))
            goto CIDMismatch;
        break;
    case QUICLY_ADDRESS_TOKEN_TYPE_RESUMPTION:
        if (age > 10 * 60 * 1000)
            goto Expired;
        break;
    default:
        assert(!"unexpected token type");
        abort();
        break;
    }

    /* success */
    *err_desc = NULL;
    return 1;

AddressMismatch:
    *err_desc = "token address mismatch";
    return 0;
UnknownAddressType:
    *err_desc = "unknown address type";
    return 0;
Expired:
    *err_desc = "token expired";
    return 0;
CIDMismatch:
    *err_desc = "CID mismatch";
    return 0;
}

static int run_server(int fd, struct sockaddr *sa, socklen_t salen)
{
    signal(SIGINT, on_signal);
    signal(SIGHUP, on_signal);

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
            while (1) {
                uint8_t buf[ctx.transport_params.max_udp_payload_size];
                struct msghdr mess;
                quicly_address_t remote;
                struct iovec vec;
                memset(&mess, 0, sizeof(mess));
                mess.msg_name = &remote.sa;
                mess.msg_namelen = sizeof(remote);
                vec.iov_base = buf;
                vec.iov_len = sizeof(buf);
                mess.msg_iov = &vec;
                mess.msg_iovlen = 1;
                ssize_t rret;
                while ((rret = recvmsg(fd, &mess, 0)) == -1 && errno == EINTR)
                    ;
                if (rret == -1)
                    break;
                if (verbosity >= 2)
                    hexdump("recvmsg", buf, rret);
                size_t off = 0;
                while (off != rret) {
                    quicly_decoded_packet_t packet;
                    if (quicly_decode_packet(&ctx, &packet, buf, rret, &off) == SIZE_MAX)
                        break;
                    if (QUICLY_PACKET_IS_LONG_HEADER(packet.octets.base[0])) {
                        if (packet.version != 0 && !quicly_is_supported_version(packet.version)) {
                            uint8_t payload[ctx.transport_params.max_udp_payload_size];
                            size_t payload_len = quicly_send_version_negotiation(&ctx, packet.cid.src, packet.cid.dest.encrypted,
                                                                                 quicly_supported_versions, payload);
                            assert(payload_len != SIZE_MAX);
                            send_one_packet(fd, &remote.sa, payload, payload_len);
                            break;
                        }
                        /* there is no way to send response to these v1 packets */
                        if (packet.cid.dest.encrypted.len > QUICLY_MAX_CID_LEN_V1 || packet.cid.src.len > QUICLY_MAX_CID_LEN_V1)
                            break;
                    }

                    quicly_conn_t *conn = NULL;
                    size_t i;
                    for (i = 0; i != num_conns; ++i) {
                        if (quicly_is_destination(conns[i], NULL, &remote.sa, &packet)) {
                            conn = conns[i];
                            break;
                        }
                    }
                    if (conn != NULL) {
                        /* existing connection */
                        quicly_receive(conn, NULL, &remote.sa, &packet);
                    } else if (QUICLY_PACKET_IS_INITIAL(packet.octets.base[0])) {
                        /* long header packet; potentially a new connection */
                        quicly_address_token_plaintext_t *token = NULL, token_buf;
                        if (packet.token.len != 0) {
                            const char *err_desc = NULL;
                            int ret = quicly_decrypt_address_token(address_token_aead.dec, &token_buf, packet.token.base,
                                                                   packet.token.len, 0, &err_desc);
                            if (ret == 0 &&
                                validate_token(&remote.sa, packet.cid.src, packet.cid.dest.encrypted, &token_buf, &err_desc)) {
                                token = &token_buf;
                            } else if (enforce_retry && (ret == QUICLY_TRANSPORT_ERROR_INVALID_TOKEN ||
                                                         (ret == 0 && token_buf.type == QUICLY_ADDRESS_TOKEN_TYPE_RETRY))) {
                                /* Token that looks like retry was unusable, and we require retry. There's no chance of the
                                 * handshake succeeding. Therefore, send close without aquiring state. */
                                uint8_t payload[ctx.transport_params.max_udp_payload_size];
                                size_t payload_len = quicly_send_close_invalid_token(&ctx, packet.version, packet.cid.src,
                                                                                     packet.cid.dest.encrypted, err_desc, payload);
                                assert(payload_len != SIZE_MAX);
                                send_one_packet(fd, &remote.sa, payload, payload_len);
                            }
                        }
                        if (enforce_retry && token == NULL && packet.cid.dest.encrypted.len >= 8) {
                            /* unbound connection; send a retry token unless the client has supplied the correct one, but not too
                             * many
                             */
                            uint8_t new_server_cid[8], payload[ctx.transport_params.max_udp_payload_size];
                            memcpy(new_server_cid, packet.cid.dest.encrypted.base, sizeof(new_server_cid));
                            new_server_cid[0] ^= 0xff;
                            size_t payload_len = quicly_send_retry(
                                &ctx, address_token_aead.enc, packet.version, &remote.sa, packet.cid.src, NULL,
                                ptls_iovec_init(new_server_cid, sizeof(new_server_cid)), packet.cid.dest.encrypted,
                                ptls_iovec_init(NULL, 0), ptls_iovec_init(NULL, 0), NULL, payload);
                            assert(payload_len != SIZE_MAX);
                            send_one_packet(fd, &remote.sa, payload, payload_len);
                            break;
                        } else {
                            /* new connection */
                            int ret = quicly_accept(&conn, &ctx, NULL, &remote.sa, &packet, token, &next_cid, NULL);
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
                    } else if (!QUICLY_PACKET_IS_LONG_HEADER(packet.octets.base[0])) {
                        /* short header packet; potentially a dead connection. No need to check the length of the incoming packet,
                         * because loop is prevented by authenticating the CID (by checking node_id and thread_id). If the peer is
                         * also sending a reset, then the next CID is highly likely to contain a non-authenticating CID, ... */
                        if (packet.cid.dest.plaintext.node_id == 0 && packet.cid.dest.plaintext.thread_id == 0) {
                            uint8_t payload[ctx.transport_params.max_udp_payload_size];
                            size_t payload_len = quicly_send_stateless_reset(&ctx, packet.cid.dest.encrypted.base, payload);
                            assert(payload_len != SIZE_MAX);
                            send_one_packet(fd, &remote.sa, payload, payload_len);
                        }
                    }
                }
            }
        }
        {
            size_t i;
            for (i = 0; i != num_conns; ++i) {
                if (quicly_get_first_timeout(conns[i]) <= ctx.now->cb(ctx.now)) {
                    if (send_pending(fd, conns[i]) != 0) {
                        dump_stats(stderr, conns[i]);
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

static void load_session(void)
{
    static uint8_t buf[65536];
    size_t len;
    int ret;

    {
        FILE *fp;
        if ((fp = fopen(session_file, "rb")) == NULL)
            return;
        len = fread(buf, 1, sizeof(buf), fp);
        if (len == 0 || !feof(fp)) {
            fprintf(stderr, "failed to load ticket from file:%s\n", session_file);
            exit(1);
        }
        fclose(fp);
    }

    {
        const uint8_t *src = buf, *end = buf + len;
        ptls_iovec_t ticket;
        ptls_decode_open_block(src, end, 2, {
            if ((resumption_token.len = end - src) != 0) {
                resumption_token.base = malloc(resumption_token.len);
                memcpy(resumption_token.base, src, resumption_token.len);
            }
            src = end;
        });
        ptls_decode_open_block(src, end, 2, {
            ticket = ptls_iovec_init(src, end - src);
            src = end;
        });
        ptls_decode_open_block(src, end, 2, {
            if ((ret = quicly_decode_transport_parameter_list(&resumed_transport_params, NULL, NULL, NULL, NULL, src, end, 0)) != 0)
                goto Exit;
            src = end;
        });
        hs_properties.client.session_ticket = ticket;
    }

Exit:;
}

static struct {
    ptls_iovec_t tls_ticket;
    ptls_iovec_t address_token;
} session_info;

int save_session(const quicly_transport_parameters_t *transport_params)
{
    ptls_buffer_t buf;
    FILE *fp = NULL;
    int ret;

    if (session_file == NULL)
        return 0;

    ptls_buffer_init(&buf, "", 0);

    /* build data (session ticket and transport parameters) */
    ptls_buffer_push_block(&buf, 2, { ptls_buffer_pushv(&buf, session_info.address_token.base, session_info.address_token.len); });
    ptls_buffer_push_block(&buf, 2, { ptls_buffer_pushv(&buf, session_info.tls_ticket.base, session_info.tls_ticket.len); });
    ptls_buffer_push_block(&buf, 2, {
        if ((ret = quicly_encode_transport_parameter_list(&buf, transport_params, NULL, NULL, NULL, NULL, 0)) != 0)
            goto Exit;
    });

    /* write file */
    if ((fp = fopen(session_file, "wb")) == NULL) {
        fprintf(stderr, "failed to open file:%s:%s\n", session_file, strerror(errno));
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

int save_session_ticket_cb(ptls_save_ticket_t *_self, ptls_t *tls, ptls_iovec_t src)
{
    free(session_info.tls_ticket.base);
    session_info.tls_ticket = ptls_iovec_init(malloc(src.len), src.len);
    memcpy(session_info.tls_ticket.base, src.base, src.len);

    quicly_conn_t *conn = *ptls_get_data_ptr(tls);
    return save_session(quicly_get_remote_transport_parameters(conn));
}

static int save_resumption_token_cb(quicly_save_resumption_token_t *_self, quicly_conn_t *conn, ptls_iovec_t token)
{
    free(session_info.address_token.base);
    session_info.address_token = ptls_iovec_init(malloc(token.len), token.len);
    memcpy(session_info.address_token.base, token.base, token.len);

    return save_session(quicly_get_remote_transport_parameters(conn));
}

static quicly_save_resumption_token_t save_resumption_token = {save_resumption_token_cb};

static int on_client_hello_cb(ptls_on_client_hello_t *_self, ptls_t *tls, ptls_on_client_hello_parameters_t *params)
{
    int ret;

    if (negotiated_protocols.count != 0) {
        size_t i, j;
        const ptls_iovec_t *x, *y;
        for (i = 0; i != negotiated_protocols.count; ++i) {
            x = negotiated_protocols.list + i;
            for (j = 0; j != params->negotiated_protocols.count; ++j) {
                y = params->negotiated_protocols.list + j;
                if (x->len == y->len && memcmp(x->base, y->base, x->len) == 0)
                    goto ALPN_Found;
            }
        }
        return PTLS_ALERT_NO_APPLICATION_PROTOCOL;
    ALPN_Found:
        if ((ret = ptls_set_negotiated_protocol(tls, (const char *)x->base, x->len)) != 0)
            return ret;
    }

    return 0;
}

static void usage(const char *cmd)
{
    printf("Usage: %s [options] host port\n"
           "\n"
           "Options:\n"
           "  -a <alpn>                 ALPN identifier; repeat the option to set multiple\n"
           "                            candidates\n"
           "  -b <buffer-size>          specifies the size of the send / receive buffer in bytes\n"
           "  -B <cid-key>              CID encryption key (server-only). Randomly generated\n"
           "                            if omitted.\n"
           "  -c certificate-file\n"
           "  -k key-file               specifies the credentials to be used for running the\n"
           "                            server. If omitted, the command runs as a client.\n"
           "  -C <algorithm>            the congestion control algorithm; either \"reno\" (default) or\n"
           "                            \"cubic\"\n"
           "  -d draft-number           specifies the draft version number to be used (e.g., 29)\n"
           "  -e event-log-file         file to log events\n"
           "  -E                        expand Client Hello (sends multiple client Initials)\n"
           "  -G                        enable UDP generic segmentation offload\n"
           "  -i interval               interval to reissue requests (in milliseconds)\n"
           "  -I timeout                idle timeout (in milliseconds; default: 600,000)\n"
           "  -K num-packets            perform key update every num-packets packets\n"
           "  -l log-file               file to log traffic secrets\n"
           "  -M <bytes>                max stream data (in bytes; default: 1MB)\n"
           "  -m <bytes>                max data (in bytes; default: 16MB)\n"
           "  -N                        enforce HelloRetryRequest (client-only)\n"
           "  -n                        enforce version negotiation (client-only)\n"
           "  -O                        suppress output\n"
           "  -p path                   path to request (can be set multiple times)\n"
           "  -P path                   path to request, store response to file (can be set multiple times)\n"
           "  -R                        require Retry (server only)\n"
           "  -r [initial-pto]          initial PTO (in milliseconds)\n"
           "  -S [num-speculative-ptos] number of speculative PTOs\n"
           "  -s session-file           file to load / store the session ticket\n"
           "  -u size                   initial size of UDP datagram payload\n"
           "  -U size                   maximum size of UDP datagarm payload\n"
           "  -V                        verify peer using the default certificates\n"
           "  -v                        verbose mode (-vv emits packet dumps as well)\n"
           "  -x named-group            named group to be used (default: secp256r1)\n"
           "  -X                        max bidirectional stream count (default: 100)\n"
           "  -y cipher-suite           cipher-suite to be used (default: all)\n"
           "  -h                        print this help\n"
           "\n",
           cmd);
}

static void push_req(const char *path, int to_file)
{
    size_t i;
    for (i = 0; reqs[i].path != NULL; ++i)
        ;
    reqs = realloc(reqs, sizeof(*reqs) * (i + 2));
    reqs[i].path = path;
    reqs[i].to_file = to_file;
    memset(reqs + i + 1, 0, sizeof(*reqs));
}

int main(int argc, char **argv)
{
    const char *host, *port, *cid_key = NULL;
    struct sockaddr_storage sa;
    socklen_t salen;
    unsigned udpbufsize = 0;
    int ch, fd;

    reqs = malloc(sizeof(*reqs));
    memset(reqs, 0, sizeof(*reqs));
    ctx = quicly_spec_context;
    ctx.tls = &tlsctx;
    ctx.stream_open = &stream_open;
    ctx.closed_by_remote = &closed_by_remote;
    ctx.save_resumption_token = &save_resumption_token;
    ctx.generate_resumption_token = &generate_resumption_token;

    setup_session_cache(ctx.tls);
    quicly_amend_ptls_context(ctx.tls);

    {
        uint8_t secret[PTLS_MAX_DIGEST_SIZE];
        ctx.tls->random_bytes(secret, ptls_openssl_sha256.digest_size);
        address_token_aead.enc = ptls_aead_new(&ptls_openssl_aes128gcm, &ptls_openssl_sha256, 1, secret, "");
        address_token_aead.dec = ptls_aead_new(&ptls_openssl_aes128gcm, &ptls_openssl_sha256, 0, secret, "");
    }

    while ((ch = getopt(argc, argv, "a:b:B:c:C:Dd:k:Ee:Gi:I:K:l:M:m:NnOp:P:Rr:S:s:u:U:Vvx:X:y:h")) != -1) {
        switch (ch) {
        case 'a':
            assert(negotiated_protocols.count < PTLS_ELEMENTSOF(negotiated_protocols.list));
            negotiated_protocols.list[negotiated_protocols.count++] = ptls_iovec_init(optarg, strlen(optarg));
            break;
        case 'b':
            if (sscanf(optarg, "%u", &udpbufsize) != 1) {
                fprintf(stderr, "failed to parse buffer size: %s\n", optarg);
                exit(1);
            }
            break;
        case 'B':
            cid_key = optarg;
            break;
        case 'c':
            load_certificate_chain(ctx.tls, optarg);
            break;
        case 'C':
            if (strcmp(optarg, "reno") == 0) {
                ctx.init_cc = &quicly_cc_reno_init;
            } else if (strcmp(optarg, "cubic") == 0) {
                ctx.init_cc = &quicly_cc_cubic_init;
            } else {
                fprintf(stderr, "unknown congestion controller: %s\n", optarg);
                exit(1);
            }
            break;
        case 'G':
#ifdef __linux__
            send_packets = send_packets_gso;
#else
            fprintf(stderr, "UDP GSO only supported on linux\n");
            exit(1);
#endif
            break;
        case 'k':
            load_private_key(ctx.tls, optarg);
            break;
        case 'd': {
            uint8_t draft_ver;
            if (sscanf(optarg, "%" SCNu8, &draft_ver) != 1) {
                fprintf(stderr, "failed to parse draft number: %s\n", optarg);
                exit(1);
            }
            ctx.initial_version = 0xff000000 | draft_ver;
        } break;
        case 'D':
            send_datagram_frame = 1;
            break;
        case 'E':
            ctx.expand_client_hello = 1;
            break;
        case 'e':
            if ((quicly_trace_fp = fopen(optarg, "w")) == NULL) {
                fprintf(stderr, "failed to open file:%s:%s\n", optarg, strerror(errno));
                exit(1);
            }
            setvbuf(quicly_trace_fp, NULL, _IONBF, 0);
            break;
        case 'i':
            if (sscanf(optarg, "%" SCNd64, &request_interval) != 1) {
                fprintf(stderr, "failed to parse request interval: %s\n", optarg);
                exit(1);
            }
            break;
        case 'I':
            if (sscanf(optarg, "%" SCNd64, &ctx.transport_params.max_idle_timeout) != 1) {
                fprintf(stderr, "failed to parse idle timeout: %s\n", optarg);
                exit(1);
            }
        case 'K':
            if (sscanf(optarg, "%" SCNu64, &ctx.max_packets_per_key) != 1) {
                fprintf(stderr, "failed to parse key update interval: %s\n", optarg);
                exit(1);
            }
            break;
        case 'l':
            setup_log_event(ctx.tls, optarg);
            break;
        case 'M': {
            uint64_t v;
            if (sscanf(optarg, "%" SCNu64, &v) != 1) {
                fprintf(stderr, "failed to parse max stream data:%s\n", optarg);
                exit(1);
            }
            ctx.transport_params.max_stream_data.bidi_local = v;
            ctx.transport_params.max_stream_data.bidi_remote = v;
            ctx.transport_params.max_stream_data.uni = v;
        } break;
        case 'm':
            if (sscanf(optarg, "%" SCNu64, &ctx.transport_params.max_data) != 1) {
                fprintf(stderr, "failed to parse max data:%s\n", optarg);
                exit(1);
            }
            break;
        case 'N':
            hs_properties.client.negotiate_before_key_exchange = 1;
            break;
        case 'n':
            ctx.initial_version = 0xabababa;
            break;
        case 'O':
            suppress_output = 1;
            break;
        case 'p':
        case 'P': {
            if (!validate_path(optarg)) {
                fprintf(stderr, "invalid path:%s\n", optarg);
                exit(1);
            }
            push_req(optarg, ch == 'P');
        } break;
        case 'R':
            enforce_retry = 1;
            break;
        case 'r':
            if (sscanf(optarg, "%" SCNu32, &ctx.loss.default_initial_rtt) != 1) {
                fprintf(stderr, "invalid argument passed to `-r`\n");
                exit(1);
            }
            break;
        case 'S':
            if (sscanf(optarg, "%" SCNu8, &ctx.loss.num_speculative_ptos) != 1) {
                fprintf(stderr, "invalid argument passed to `-S`\n");
                exit(1);
            }
            break;
        case 's':
            session_file = optarg;
            break;
        case 'u':
            if (sscanf(optarg, "%" SCNu16, &ctx.initial_egress_max_udp_payload_size) != 1) {
                fprintf(stderr, "invalid argument passed to `-u`\n");
                exit(1);
            }
            break;
        case 'U':
            if (sscanf(optarg, "%" SCNu64, &ctx.transport_params.max_udp_payload_size) != 1) {
                fprintf(stderr, "invalid argument passed to `-U`\n");
                exit(1);
            }
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
            if (sscanf(optarg, "%" SCNu64, &ctx.transport_params.max_streams_bidi) != 1) {
                fprintf(stderr, "failed to parse max streams count: %s\n", optarg);
                exit(1);
            }
            break;
        case 'y': {
            size_t i;
            for (i = 0; cipher_suites[i] != NULL; ++i)
                ;
#define MATCH(name, engine)                                                                                                        \
    if (cipher_suites[i] == NULL && strcasecmp(optarg, #name) == 0)                                                                \
    cipher_suites[i] = &engine##_##name
#if QUICLY_HAVE_FUSION
            MATCH(aes128gcmsha256, fusion);
            MATCH(aes256gcmsha384, fusion);
#endif
            MATCH(aes128gcmsha256, ptls_openssl);
            MATCH(aes256gcmsha384, ptls_openssl);
#if PTLS_OPENSSL_HAVE_CHACHA20_POLY1305
            MATCH(chacha20poly1305sha256, ptls_openssl);
#endif
#undef MATCH
            if (cipher_suites[i] == NULL) {
                fprintf(stderr, "unknown cipher-suite: %s\n", optarg);
                exit(1);
            }
        } break;
        default:
            usage(argv[0]);
            exit(1);
        }
    }
    argc -= optind;
    argv += optind;

    if (reqs[0].path == NULL)
        push_req("/", 0);

    if (key_exchanges[0] == NULL)
        key_exchanges[0] = &ptls_openssl_secp256r1;

    /* Amend cipher-suites. Copy the defaults when `-y` option is not used. Otherwise, complain if aes128gcmsha256 is not specified
     */
    if (cipher_suites[0] == NULL) {
        size_t i;
        for (i = 0; ptls_openssl_cipher_suites[i] != NULL; ++i) {
            cipher_suites[i] = ptls_openssl_cipher_suites[i];
#if QUICLY_HAVE_FUSION
            if (cipher_suites[i]->id == PTLS_CIPHER_SUITE_AES_128_GCM_SHA256) {
                cipher_suites[i] = &fusion_aes128gcmsha256;
            } else if (cipher_suites[i]->id == PTLS_CIPHER_SUITE_AES_256_GCM_SHA384) {
                cipher_suites[i] = &fusion_aes256gcmsha384;
            }
#endif
        }
    } else {
        size_t i;
        for (i = 0; cipher_suites[i] != NULL; ++i) {
            if (cipher_suites[i]->id == PTLS_CIPHER_SUITE_AES_128_GCM_SHA256)
                goto MandatoryCipherFound;
        }
        fprintf(stderr, "aes128gcmsha256 MUST be one of the cipher-suites specified using `-y`\n");
        return 1;
    MandatoryCipherFound:;
    }

    /* make adjustments for datagram frame support */
    if (send_datagram_frame) {
        static quicly_receive_datagram_frame_t cb = {on_receive_datagram_frame};
        ctx.receive_datagram_frame = &cb;
        ctx.transport_params.max_datagram_frame_size = ctx.transport_params.max_udp_payload_size;
    }

    if (ctx.tls->certificates.count != 0 || ctx.tls->sign_certificate != NULL) {
        /* server */
        if (ctx.tls->certificates.count == 0 || ctx.tls->sign_certificate == NULL) {
            fprintf(stderr, "-c and -k options must be used together\n");
            exit(1);
        }
        if (cid_key == NULL) {
            static char random_key[17];
            tlsctx.random_bytes(random_key, sizeof(random_key) - 1);
            cid_key = random_key;
        }
        ctx.cid_encryptor = quicly_new_default_cid_encryptor(&ptls_openssl_bfecb, &ptls_openssl_aes128ecb, &ptls_openssl_sha256,
                                                             ptls_iovec_init(cid_key, strlen(cid_key)));
    } else {
        /* client */
        hs_properties.client.negotiated_protocols.list = negotiated_protocols.list;
        hs_properties.client.negotiated_protocols.count = negotiated_protocols.count;
        if (session_file != NULL)
            load_session();
    }
    if (argc != 2) {
        fprintf(stderr, "missing host and port\n");
        exit(1);
    }
    host = (--argc, *argv++);
    port = (--argc, *argv++);

    if (resolve_address((void *)&sa, &salen, host, port, AF_INET, SOCK_DGRAM, IPPROTO_UDP) != 0)
        exit(1);

    if ((fd = socket(sa.ss_family, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
        perror("socket(2) failed");
        return 1;
    }
    fcntl(fd, F_SETFL, O_NONBLOCK);
    {
        int on = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) != 0) {
            perror("setsockopt(SO_REUSEADDR) failed");
            return 1;
        }
    }
    if (udpbufsize != 0) {
        unsigned arg = udpbufsize;
        if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &arg, sizeof(arg)) != 0) {
            perror("setsockopt(SO_RCVBUF) failed");
            return 1;
        }
        arg = udpbufsize;
        if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &arg, sizeof(arg)) != 0) {
            perror("setsockopt(SO_RCVBUF) failed");
            return 1;
        }
    }
#if defined(IP_DONTFRAG)
    {
        int on = 1;
        if (setsockopt(fd, IPPROTO_IP, IP_DONTFRAG, &on, sizeof(on)) != 0)
            perror("Warning: setsockopt(IP_DONTFRAG) failed");
    }
#elif defined(IP_PMTUDISC_DO)
    {
        int opt = IP_PMTUDISC_DO;
        if (setsockopt(fd, IPPROTO_IP, IP_MTU_DISCOVER, &opt, sizeof(opt)) != 0)
            perror("Warning: setsockopt(IP_MTU_DISCOVER) failed");
    }
#endif

    return ctx.tls->certificates.count != 0 ? run_server(fd, (void *)&sa, salen) : run_client(fd, (void *)&sa, host);
}
