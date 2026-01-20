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
#ifdef __APPLE__
#define __APPLE_USE_RFC_3542 /* to use IPV6_PKTINFO */
#endif
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <getopt.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <fcntl.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <picotls.h>
#include <openssl/err.h>
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
static quicly_stream_scheduler_t stream_scheduler;
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
                                .ech.client = {ptls_openssl_hpke_cipher_suites, ptls_openssl_hpke_kems},
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
static struct {
    const char *path;
    int to_file;
} *reqs;

static int exit_after_handshake;

struct st_stream_data_t {
    quicly_streambuf_t streambuf;
    FILE *outfp;
};

static void on_stop_sending(quicly_stream_t *stream, quicly_error_t err);
static void on_receive_reset(quicly_stream_t *stream, quicly_error_t err);
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
            "packets-received: %" PRIu64 ", initial-packets-received: %" PRIu64 ", 0rtt-packets-received: %" PRIu64
            ", handshake-packets-received: %" PRIu64 ", received-ecn-ect0: %" PRIu64 ", received-ecn-ect1: %" PRIu64
            ", received-ecn-ce: %" PRIu64 ", packets-decryption-failed: %" PRIu64 ", packets-sent: %" PRIu64
            ", initial-packets-sent: %" PRIu64 ", 0rtt-packets-sent: %" PRIu64 ", handshake-packets-sent: %" PRIu64
            ", packets-lost: %" PRIu64 ", ack-received: %" PRIu64 ", ack-ecn-ect0: %" PRIu64 ", ack-ecn-ect1: %" PRIu64
            ", ack-ecn-ce: %" PRIu64 ", late-acked: %" PRIu64 ", bytes-received: %" PRIu64 ", bytes-sent: %" PRIu64
            ", paths-created %" PRIu64 ", paths-validated %" PRIu64 ", paths-promoted: %" PRIu64 ", srtt: %" PRIu32
            ", num-loss-episodes: %" PRIu32 ", num-ecn-loss-episodes: %" PRIu32 ", delivery-rate: %" PRIu64 ", cwnd: %" PRIu32
            ", cwnd-exiting-slow-start: %" PRIu32 ", slow-start-exit-at: %" PRId64 ", jumpstart-cwnd: %" PRIu32
            ", jumpstart-exit: %" PRIu32 ", jumpstart-prev-rate: %" PRIu64 ", jumpstart-prev-rtt: %" PRIu32
            ", token-sent-rate: %" PRIu64 ", token-sent-rtt: %" PRIu32 ", ack-frequency-frames-sent: %" PRIu64
            ", ack-frequency-frames-received: %" PRIu64 "\n",
            stats.num_packets.received, stats.num_packets.initial_received, stats.num_packets.zero_rtt_received,
            stats.num_packets.handshake_received, stats.num_packets.received_ecn_counts[0],
            stats.num_packets.received_ecn_counts[1], stats.num_packets.received_ecn_counts[2], stats.num_packets.decryption_failed,
            stats.num_packets.sent, stats.num_packets.initial_sent, stats.num_packets.zero_rtt_sent,
            stats.num_packets.handshake_sent, stats.num_packets.lost, stats.num_packets.ack_received,
            stats.num_packets.acked_ecn_counts[0], stats.num_packets.acked_ecn_counts[1], stats.num_packets.acked_ecn_counts[2],
            stats.num_packets.late_acked, stats.num_bytes.received, stats.num_bytes.sent, stats.num_paths.created,
            stats.num_paths.validated, stats.num_paths.promoted, stats.rtt.smoothed, stats.cc.num_loss_episodes,
            stats.cc.num_ecn_loss_episodes, stats.delivery_rate.smoothed, stats.cc.cwnd, stats.cc.cwnd_exiting_slow_start,
            stats.cc.exit_slow_start_at, stats.jumpstart.cwnd, stats.cc.cwnd_exiting_jumpstart, stats.jumpstart.prev_rate,
            stats.jumpstart.prev_rtt, stats.token_sent.rate, stats.token_sent.rtt, stats.num_frames_sent.ack_frequency,
            stats.num_frames_received.ack_frequency);
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

static quicly_error_t flatten_file_vec(quicly_sendbuf_vec_t *vec, void *dst, size_t off, size_t len)
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
static quicly_error_t flatten_sized_text(quicly_sendbuf_vec_t *vec, void *dst, size_t off, size_t len)
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

static void on_stop_sending(quicly_stream_t *stream, quicly_error_t err)
{
    assert(QUICLY_ERROR_IS_QUIC_APPLICATION(err));
    fprintf(stderr, "received STOP_SENDING: %" PRIu64 "\n", QUICLY_ERROR_GET_ERROR_CODE(err));
}

static void on_receive_reset(quicly_stream_t *stream, quicly_error_t err)
{
    assert(QUICLY_ERROR_IS_QUIC_APPLICATION(err));
    fprintf(stderr, "received RESET_STREAM: %" PRIu64 "\n", QUICLY_ERROR_GET_ERROR_CODE(err));
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
    }
}

static quicly_error_t on_stream_open(quicly_stream_open_t *self, quicly_stream_t *stream)
{
    int ret;

    if ((ret = quicly_streambuf_create(stream, sizeof(struct st_stream_data_t))) != 0)
        return ret;
    stream->callbacks = ctx.tls->certificates.count != 0 ? &server_stream_callbacks : &client_stream_callbacks;
    return 0;
}

static quicly_stream_open_t stream_open = {&on_stream_open};

static void on_closed_by_remote(quicly_closed_by_remote_t *self, quicly_conn_t *conn, quicly_error_t err, uint64_t frame_type,
                                const char *reason, size_t reason_len)
{
    if (QUICLY_ERROR_IS_QUIC_TRANSPORT(err)) {
        fprintf(stderr, "transport close:code=0x%" PRIx64 ";frame=%" PRIu64 ";reason=%.*s\n", QUICLY_ERROR_GET_ERROR_CODE(err),
                frame_type, (int)reason_len, reason);
    } else if (QUICLY_ERROR_IS_QUIC_APPLICATION(err)) {
        fprintf(stderr, "application close:code=0x%" PRIx64 ";reason=%.*s\n", QUICLY_ERROR_GET_ERROR_CODE(err), (int)reason_len,
                reason);
    } else if (err == QUICLY_ERROR_RECEIVED_STATELESS_RESET) {
        fprintf(stderr, "stateless reset\n");
    } else if (err == QUICLY_ERROR_NO_COMPATIBLE_VERSION) {
        fprintf(stderr, "no compatible version\n");
    } else {
        fprintf(stderr, "unexpected close:code=%" PRId64 "\n", err);
    }
}

static quicly_closed_by_remote_t closed_by_remote = {&on_closed_by_remote};

static quicly_error_t on_generate_resumption_token(quicly_generate_resumption_token_t *self, quicly_conn_t *conn,
                                                   ptls_buffer_t *buf, quicly_address_token_plaintext_t *token)
{
    return quicly_encrypt_address_token(tlsctx.random_bytes, address_token_aead.enc, buf, buf->off, token);
}

static quicly_generate_resumption_token_t generate_resumption_token = {&on_generate_resumption_token};

/* buf should be ctx.transport_params.max_udp_payload_size bytes long */
static ssize_t receive_datagram(int fd, void *buf, quicly_address_t *dest, quicly_address_t *src, uint8_t *ecn)
{
    struct iovec vec = {.iov_base = buf, .iov_len = ctx.transport_params.max_udp_payload_size};
    char cmsgbuf[CMSG_SPACE(sizeof(struct in6_pktinfo) /* == max(V4_TOS, V6_TCLASS) */) + CMSG_SPACE(1 /* TOS */)] = {};
    struct msghdr mess = {
        .msg_name = &src->sa,
        .msg_namelen = sizeof(*src),
        .msg_iov = &vec,
        .msg_iovlen = 1,
        .msg_control = cmsgbuf,
        .msg_controllen = sizeof(cmsgbuf),
    };
    quicly_address_t localaddr = {};
    socklen_t localaddrlen = sizeof(localaddr);
    ssize_t rret;

    if (getsockname(fd, &localaddr.sa, &localaddrlen) != 0)
        perror("getsockname failed");

    while ((rret = recvmsg(fd, &mess, 0)) == -1 && errno == EINTR)
        ;

    if (rret >= 0) {
        dest->sa.sa_family = AF_UNSPEC;
        *ecn = 0;
        for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&mess); cmsg != NULL; cmsg = CMSG_NXTHDR(&mess, cmsg)) {
#ifdef IP_PKTINFO
            if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_PKTINFO) {
                dest->sin.sin_family = AF_INET;
                memcpy(&dest->sin.sin_addr, CMSG_DATA(cmsg) + offsetof(struct in_pktinfo, ipi_addr), sizeof(dest->sin.sin_addr));
                dest->sin.sin_port = localaddr.sin.sin_port;
            }
#endif
#ifdef IP_RECVDSTADDR
            if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_RECVDSTADDR) {
                dest->sin.sin_family = AF_INET;
                memcpy(&dest->sin.sin_addr, CMSG_DATA(cmsg), sizeof(dest->sin.sin_addr));
                dest->sin.sin_port = localaddr.sin.sin_port;
            }
#endif
#ifdef IPV6_PKTINFO
            if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IPV6_PKTINFO) {
                dest->sin6.sin6_family = AF_INET6;
                memcpy(&dest->sin6.sin6_addr, CMSG_DATA(cmsg) + offsetof(struct in6_pktinfo, ipi6_addr),
                       sizeof(dest->sin6.sin6_addr));
                dest->sin6.sin6_port = localaddr.sin6.sin6_port;
            }
#endif
#ifdef IP_RECVTOS
            if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type ==
#ifdef __APPLE__
                                                      IP_RECVTOS
#else
                                                      IP_TOS
#endif
            ) {
                assert((char *)CMSG_DATA(cmsg) - (char *)cmsg + 1 == cmsg->cmsg_len);
                *ecn = *(uint8_t *)CMSG_DATA(cmsg) & IPTOS_ECN_MASK;
            }
#endif
        }
    }

    return rret;
}

/* in6_pktinfo would be the largest structure among the ones that might be stored */
static void set_srcaddr(struct msghdr *mess, quicly_address_t *addr)
{
    struct cmsghdr *cmsg = (struct cmsghdr *)((char *)mess->msg_control + mess->msg_controllen);

    switch (addr->sa.sa_family) {
    case AF_INET: {
#ifdef IP_PKTINFO
        struct in_pktinfo info = {.ipi_spec_dst = addr->sin.sin_addr};
        cmsg->cmsg_level = IPPROTO_IP;
        cmsg->cmsg_type = IP_PKTINFO;
        cmsg->cmsg_len = CMSG_LEN(sizeof(info));
        memcpy(CMSG_DATA(cmsg), &info, sizeof(info));
        mess->msg_controllen += CMSG_SPACE(sizeof(info));
#elif defined(IP_SENDSRCADDR)
        /* TODO FreeBSD: skip setting IP_SENDSRCADDR if the socket is not bound to INADDR_ANY, as doing so results in sendmsg
         * generating an error */
        cmsg->cmsg_level = IPPROTO_IP;
        cmsg->cmsg_type = IP_SENDSRCADDR;
        cmsg->cmsg_len = CMSG_LEN(sizeof(addr->sin.sin_addr));
        memcpy(CMSG_DATA(cmsg), &addr->sin.sin_addr, sizeof(addr->sin.sin_addr));
        mess->msg_controllen += CMSG_SPACE(sizeof(addr->sin.sin_addr));
#else
        assert(!"FIXME");
#endif
    } break;
    case AF_INET6: {
        struct in6_pktinfo info = {.ipi6_addr = addr->sin6.sin6_addr};
        cmsg->cmsg_level = IPPROTO_IP;
        cmsg->cmsg_type = IPV6_PKTINFO;
        cmsg->cmsg_len = CMSG_LEN(sizeof(info));
        memcpy(CMSG_DATA(cmsg), &info, sizeof(info));
        mess->msg_controllen += CMSG_SPACE(sizeof(info));
    } break;
    default:
        assert(!"FIXME");
        break;
    }
}

static void set_ecn(struct msghdr *mess, uint8_t ecn)
{
    if (ecn == 0)
        return;

    struct cmsghdr *cmsg = (struct cmsghdr *)((char *)mess->msg_control + mess->msg_controllen);

    cmsg->cmsg_level = IPPROTO_IP;
    cmsg->cmsg_type = IP_TOS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(ecn));
    memcpy(CMSG_DATA(cmsg), &ecn, sizeof(ecn));

    mess->msg_controllen += CMSG_SPACE(sizeof(ecn));
}

static void send_packets_default(int fd, quicly_address_t *dest, quicly_address_t *src, struct iovec *packets, size_t num_packets,
                                 uint8_t ecn)
{
    for (size_t i = 0; i != num_packets; ++i) {
        char cmsgbuf[CMSG_SPACE(sizeof(struct in6_pktinfo)) + CMSG_SPACE(sizeof(int))];
        struct msghdr mess = {
            .msg_name = dest,
            .msg_namelen = quicly_get_socklen(&dest->sa),
            .msg_iov = &packets[i],
            .msg_iovlen = 1,
            .msg_control = cmsgbuf,
        };
        if (src != NULL && src->sa.sa_family != AF_UNSPEC)
            set_srcaddr(&mess, src);
        set_ecn(&mess, ecn);
        assert(mess.msg_controllen <= sizeof(cmsgbuf));
        if (mess.msg_controllen == 0)
            mess.msg_control = NULL;
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

static void send_packets_gso(int fd, quicly_address_t *dest, quicly_address_t *src, struct iovec *packets, size_t num_packets,
                             uint8_t ecn)
{
    struct iovec vec = {.iov_base = (void *)packets[0].iov_base,
                        .iov_len = packets[num_packets - 1].iov_base + packets[num_packets - 1].iov_len - packets[0].iov_base};
    char cmsgbuf[CMSG_SPACE(sizeof(struct in6_pktinfo)) + CMSG_SPACE(sizeof(uint16_t)) /* UDP_SEGMENT */ +
                 CMSG_SPACE(sizeof(int)) /* IP_TOS */];
    struct msghdr mess = {
        .msg_name = dest,
        .msg_namelen = quicly_get_socklen(&dest->sa),
        .msg_iov = &vec,
        .msg_iovlen = 1,
        .msg_control = cmsgbuf,
    };

    if (src != NULL && src->sa.sa_family != AF_UNSPEC)
        set_srcaddr(&mess, src);
    if (num_packets != 1) {
        struct cmsghdr *cmsg = (struct cmsghdr *)((char *)mess.msg_control + mess.msg_controllen);
        cmsg->cmsg_level = SOL_UDP;
        cmsg->cmsg_type = UDP_SEGMENT;
        cmsg->cmsg_len = CMSG_LEN(sizeof(uint16_t));
        *(uint16_t *)CMSG_DATA(cmsg) = packets[0].iov_len;
        mess.msg_controllen += CMSG_SPACE(sizeof(uint16_t));
    }
    set_ecn(&mess, ecn);
    assert(mess.msg_controllen <= sizeof(cmsgbuf));
    if (mess.msg_controllen == 0)
        mess.msg_control = NULL;

    int ret;
    while ((ret = sendmsg(fd, &mess, 0)) == -1 && errno == EINTR)
        ;
    if (ret == -1)
        perror("sendmsg failed");
}

#endif

static void (*send_packets)(int, quicly_address_t *, quicly_address_t *, struct iovec *, size_t, uint8_t) = send_packets_default;

static void send_one_packet(int fd, quicly_address_t *dest, quicly_address_t *src, const void *payload, size_t payload_len)
{
    struct iovec vec = {.iov_base = (void *)payload, .iov_len = payload_len};
    send_packets(fd, dest, src, &vec, 1, 0);
}

static quicly_error_t send_pending(int fd, quicly_conn_t *conn)
{
    quicly_address_t dest, src;
    struct iovec packets[MAX_BURST_PACKETS];
    uint8_t buf[MAX_BURST_PACKETS * quicly_get_context(conn)->transport_params.max_udp_payload_size];
    size_t num_packets = MAX_BURST_PACKETS;
    quicly_error_t ret;

    if ((ret = quicly_send(conn, &dest, &src, packets, &num_packets, buf, sizeof(buf))) == 0 && num_packets != 0)
        send_packets(fd, &dest, &src, packets, num_packets, quicly_send_get_ecn_bits(conn));

    return ret;
}

static void on_receive_datagram_frame(quicly_receive_datagram_frame_t *self, quicly_conn_t *conn, ptls_iovec_t payload)
{
    printf("DATAGRAM: %.*s\n", (int)payload.len, payload.base);
    /* send responds with a datagram frame */
    if (!quicly_is_client(conn))
        quicly_send_datagram_frames(conn, &payload, 1);
}

static void enqueue_requests(quicly_conn_t *conn)
{
    size_t i;
    quicly_error_t ret;

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

static volatile int client_gotsig = 0;

static void on_client_signal(int signo)
{
    client_gotsig = signo;
}

static int run_client(int fd, struct sockaddr *sa, const char *host)
{
    quicly_address_t local;
    quicly_error_t ret;
    quicly_conn_t *conn = NULL;

    signal(SIGTERM, on_client_signal);

    memset(&local, 0, sizeof(local));
    local.sa.sa_family = sa->sa_family;
    if (bind(fd, &local.sa, local.sa.sa_family == AF_INET ? sizeof(local.sin) : sizeof(local.sin6)) != 0) {
        perror("bind(2) failed");
        return 1;
    }
    ret = quicly_connect(&conn, &ctx, host, sa, NULL, &next_cid, resumption_token, &hs_properties, &resumed_transport_params, NULL);
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
                uint8_t buf[ctx.transport_params.max_udp_payload_size], ecn;
                quicly_address_t dest, src;
                ssize_t rret = receive_datagram(fd, buf, &dest, &src, &ecn);
                if (rret <= 0)
                    break;
                if (verbosity >= 2)
                    hexdump("recvmsg", buf, rret);
                size_t off = 0;
                while (off != rret) {
                    quicly_decoded_packet_t packet;
                    if (quicly_decode_packet(&ctx, &packet, buf, rret, &off) == SIZE_MAX)
                        break;
                    packet.ecn = ecn;
                    quicly_receive(conn, &dest.sa, &src.sa, &packet);
                    if (send_datagram_frame && quicly_connection_is_ready(conn)) {
                        const char *message = "hello datagram!";
                        ptls_iovec_t datagram = ptls_iovec_init(message, strlen(message));
                        quicly_send_datagram_frames(conn, &datagram, 1);
                        send_datagram_frame = 0;
                    }
                    if (exit_after_handshake) {
                        quicly_stats_t stats;
                        if (quicly_get_stats(conn, &stats) == 0 && stats.handshake_confirmed_msec != UINT64_MAX)
                            exit(0);
                    } else {
                        if (quicly_num_streams(conn) == 0) {
                            if (request_interval != 0 && client_gotsig != SIGTERM) {
                                if (enqueue_requests_at == INT64_MAX)
                                    enqueue_requests_at = ctx.now->cb(ctx.now) + request_interval;
                            } else {
                                static int close_called;
                                if (!close_called) {
                                    dump_stats(stderr, conn);
                                    quicly_close(conn, 0, "");
                                    close_called = 1;
                                }
                            }
                        }
                    }
                }
            }
        }
        if (conn != NULL) {
            ret = send_pending(fd, conn);
            if (ret != 0) {
                ech_save_retry_configs();
                quicly_free(conn);
                conn = NULL;
                if (ret == QUICLY_ERROR_FREE_CONNECTION) {
                    return 0;
                } else {
                    fprintf(stderr, "quicly_send returned %" PRId64 "\n", ret);
                    return 1;
                }
            }
        }
    }
}

static quicly_conn_t **conns;
static size_t num_conns = 0;

static void on_server_signal(int signo)
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

    /* calculate and normalize age */
    if ((age = ctx.now->cb(ctx.now) - token->issued_at) < 0)
        age = 0;

    /* type-specific checks */
    switch (token->type) {
    case QUICLY_ADDRESS_TOKEN_TYPE_RETRY:
        if (age > 30000)
            goto Expired;
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

    /* check address, deferring the use of port number match to type-specific checks */
    if (remote->sa_family != token->remote.sa.sa_family)
        goto AddressMismatch;
    switch (remote->sa_family) {
    case AF_INET: {
        struct sockaddr_in *sin = (struct sockaddr_in *)remote;
        if (sin->sin_addr.s_addr != token->remote.sin.sin_addr.s_addr)
            goto AddressMismatch;
        if (token->type == QUICLY_ADDRESS_TOKEN_TYPE_RETRY && sin->sin_port != token->remote.sin.sin_port)
            goto AddressMismatch;
    } break;
    case AF_INET6: {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)remote;
        if (memcmp(&sin6->sin6_addr, &token->remote.sin6.sin6_addr, sizeof(sin6->sin6_addr)) != 0)
            goto AddressMismatch;
        if (token->type == QUICLY_ADDRESS_TOKEN_TYPE_RETRY && sin6->sin6_port != token->remote.sin6.sin6_port)
            goto AddressMismatch;
    } break;
    default:
        goto UnknownAddressType;
    }

    /* success */
    *err_desc = NULL;
    token->address_mismatch = 0;
    return 1;

AddressMismatch:
    token->address_mismatch = 1;
    *err_desc = NULL;
    return 1;

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
    signal(SIGINT, on_server_signal);
    signal(SIGHUP, on_server_signal);

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
                quicly_address_t local, remote;
                uint8_t buf[ctx.transport_params.max_udp_payload_size], ecn;
                ssize_t rret = receive_datagram(fd, buf, &local, &remote, &ecn);
                if (rret == -1)
                    break;
                if (verbosity >= 2)
                    hexdump("recvmsg", buf, rret);
                size_t off = 0;
                while (off != rret) {
                    quicly_decoded_packet_t packet;
                    if (quicly_decode_packet(&ctx, &packet, buf, rret, &off) == SIZE_MAX)
                        break;
                    packet.ecn = ecn;
                    if (QUICLY_PACKET_IS_LONG_HEADER(packet.octets.base[0])) {
                        if (packet.version != 0 && !quicly_is_supported_version(packet.version)) {
                            uint8_t payload[ctx.transport_params.max_udp_payload_size];
                            size_t payload_len = quicly_send_version_negotiation(&ctx, packet.cid.src, packet.cid.dest.encrypted,
                                                                                 quicly_supported_versions, payload);
                            assert(payload_len != SIZE_MAX);
                            send_one_packet(fd, &remote, &local, payload, payload_len);
                            break;
                        }
                        /* there is no way to send response to these v1 packets */
                        if (packet.cid.dest.encrypted.len > QUICLY_MAX_CID_LEN_V1 || packet.cid.src.len > QUICLY_MAX_CID_LEN_V1)
                            break;
                    }

                    quicly_conn_t *conn = NULL;
                    size_t i;
                    for (i = 0; i != num_conns; ++i) {
                        if (quicly_is_destination(conns[i], &local.sa, &remote.sa, &packet)) {
                            conn = conns[i];
                            break;
                        }
                    }
                    if (conn != NULL) {
                        /* existing connection */
                        quicly_receive(conn, &local.sa, &remote.sa, &packet);
                    } else if (QUICLY_PACKET_IS_INITIAL(packet.octets.base[0])) {
                        /* long header packet; potentially a new connection */
                        quicly_address_token_plaintext_t *token = NULL, token_buf;
                        if (packet.token.len != 0) {
                            const char *err_desc = NULL;
                            quicly_error_t ret = quicly_decrypt_address_token(address_token_aead.dec, &token_buf, packet.token.base,
                                                                              packet.token.len, 0, &err_desc);
                            if (ret == 0 &&
                                validate_token(&remote.sa, packet.cid.src, packet.cid.dest.encrypted, &token_buf, &err_desc)) {
                                token = &token_buf;
                            } else if (enforce_retry && (ret == QUICLY_TRANSPORT_ERROR_INVALID_TOKEN ||
                                                         (ret == 0 && token_buf.type == QUICLY_ADDRESS_TOKEN_TYPE_RETRY))) {
                                /* Token that looks like retry was unusable, and we require retry. There's no chance of the
                                 * handshake succeeding. Therefore, send close without acquiring state. */
                                uint8_t payload[ctx.transport_params.max_udp_payload_size];
                                size_t payload_len = quicly_send_close_invalid_token(&ctx, packet.version, packet.cid.src,
                                                                                     packet.cid.dest.encrypted, err_desc, payload);
                                assert(payload_len != SIZE_MAX);
                                send_one_packet(fd, &remote, NULL, payload, payload_len);
                            }
                        }
                        if (enforce_retry && (token == NULL || token->address_mismatch) && packet.cid.dest.encrypted.len >= 8) {
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
                            send_one_packet(fd, &remote, NULL, payload, payload_len);
                            break;
                        } else {
                            /* new connection */
                            quicly_error_t ret =
                                quicly_accept(&conn, &ctx, &local.sa, &remote.sa, &packet, token, &next_cid, NULL, NULL);
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
                            send_one_packet(fd, &remote, NULL, payload, payload_len);
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
    quicly_error_t ret;

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
            if ((ret = quicly_decode_transport_parameter_list(&resumed_transport_params, NULL, NULL, NULL, NULL, src, end)) != 0)
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

static quicly_error_t save_resumption_token_cb(quicly_save_resumption_token_t *_self, quicly_conn_t *conn, ptls_iovec_t token)
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

static int64_t stream_has_more_to_send(void *unused, quicly_stream_t *stream)
{
    int is_fully_inflight =
        !quicly_stream_has_send_side(0, stream->stream_id) || quicly_sendstate_is_fully_inflight(&stream->sendstate);
    return is_fully_inflight ? 0 : 1;
}

static int conn_has_more_to_send(quicly_conn_t *conn)
{
    return quicly_foreach_stream(conn, NULL, stream_has_more_to_send) != 0;
}

static quicly_error_t scheduler_do_send(quicly_stream_scheduler_t *sched, quicly_conn_t *conn, quicly_send_context_t *s)
{
    int had_more_to_send = conn_has_more_to_send(conn);
    quicly_error_t ret;

    /* call the default scheduler */
    if ((ret = quicly_default_stream_scheduler.do_send(&quicly_default_stream_scheduler, conn, s)) != 0)
        return ret;

    if (!quicly_is_client(conn) && had_more_to_send && !conn_has_more_to_send(conn))
        quicly_send_resumption_token(conn);

    return 0;
}

static void usage(const char *cmd)
{
    printf("Usage: %s [options] host port\n"
           "\n"
           "Options:\n"
           "  -a <alpn>                 ALPN identifier; repeat the option to set multiple\n"
           "                            candidates\n"
           "  -b <buffer-size>          specifies the size of the send / receive buffer in\n"
           "                            bytes\n"
           "  -B <cid-key>              CID encryption key (server-only). Randomly generated\n"
           "                            if omitted.\n"
           "  -c certificate-file\n"
           "  -k key-file               specifies the credentials to be used for running the\n"
           "                            server. If omitted, the command runs as a client.\n"
           "  -C <algo>[:<iw>[:<p>]]    specifies the congestion control algorithm (\"reno\"\n"
           "                            (default), \"cubic\", or \"pico\"), as well as\n"
           "                            initial congestion window size (in packets, default:\n"
           "                            10) and use of pacing.\n"
           "  -d draft-number           specifies the draft version number to be used (e.g.,\n"
           "                            29)\n"
           "  --disable-ecn             turns off ECN support (default is on)\n"
           "  --disregard-app-limited   instructs CC to increase CWND even when the flow is\n"
           "                            application limited\n"
           "  -e event-log-file         file to log events\n"
           "  -E                        expand Client Hello (sends multiple client Initials)\n"
           "  --ech-config <file>       file that contains ECHConfigList or an empty file to\n"
           "                            grease ECH; will be overwritten when receiving\n"
           "                            retry_configs from the server\n"
           "  --ech-key <file>          ECH private key for each ECH config provided by\n"
           "                            --ech-config\n"
           "  --exit-after-handshake    immediately exists one the handshake concludes,\n"
           "                            without sending application data\n"
           "  -f fraction               increases the induced ack frequency to specified\n"
           "                            fraction of CWND (default: 0)\n"
           "  -G                        enable UDP generic segmentation offload\n"
           "  -i interval               interval to reissue requests (in milliseconds)\n"
           "  --jumpstart-default <wnd> jumpstart CWND size for new connections, in packets\n"
           "  --jumpstart-max <wnd>     maximum jumpstart CWND size for resuming connections\n"
           "  -I timeout                idle timeout (in milliseconds; default: 600,000)\n"
           "  -K num-packets            perform key update every num-packets packets\n"
           "  -l log-file               file to log traffic secrets\n"
           "  -M <bytes>                max stream data (in bytes; default: 1MB)\n"
           "  -m <bytes>                max data (in bytes; default: 16MB)\n"
           "  -N                        enforce HelloRetryRequest (client-only)\n"
           "  -n                        enforce version negotiation (client-only)\n"
           "  -O                        suppress output\n"
           "  -p path                   path to request (can be set multiple times)\n"
           "  -P path                   path to request, store response to file (can be set\n"
           "                            multiple times)\n"
           "  -R                        require Retry (server only)\n"
           "  -r [initial-pto]          initial PTO (in milliseconds)\n"
           "  --rapid-start             turns on rapid start\n"
           "  -S [num-speculative-ptos] number of speculative PTOs\n"
           "  -s session-file           file to load / store the session ticket\n"
           "  --sockfd fd               specifies the UDP socket to be used\n"
           "  -u size                   initial size of UDP datagram payload\n"
           "  -U size                   maximum size of UDP datagram payload\n"
           "  -V                        verify peer using the default certificates\n"
           "  -v                        verbose mode (-vv emits packet dumps as well)\n"
           "  -W public-key-file        use raw public keys (RFC 7250). When set and running\n"
           "                            as a client, the argument specifies the public keys\n"
           "                            that the server is expected to use. When running as\n"
           "                            a server, the argument is ignored.\n"
           "  -x named-group            named group to be used (default: secp256r1)\n"
           "  -X                        max bidirectional stream count (default: 100)\n"
           "  -y cipher-suite           cipher-suite to be used (default: all)\n"
           "\n"
           "Miscellaneous Options:\n"
           "  -h                        print this help\n"
           "  --calc-initial-secret     calculate Initial client traffic secret given DCID\n"
           "  --decrypt-packet secret[:dcid-length]\n"
           "                            given a QUIC packet and a traffic secret, decrypts\n"
           "                            and prints the packet payload; to decode short\n"
           "                            header packets, DCID length must be supplied\n"
           "  --encrypt-packet secret   given a packet without encryption applied, emits a\n"
           "                            packet encrypted using the given traffic secret\n"
           "\n",
           cmd);
}

static int decode_hex(int ch)
{
    if ('0' <= ch && ch <= '9') {
        return ch - '0';
    } else if ('A' <= ch && ch <= 'F') {
        return ch - 'A' + 0xa;
    } else if ('a' <= ch && ch <= 'f') {
        return ch - 'a' + 0xa;
    }
    return -1;
}

static size_t decode_hexstring(uint8_t *dst, size_t capacity, const char *src, size_t srclen)
{
    if (srclen == SIZE_MAX)
        srclen = strlen(src);
    if (srclen > capacity * 2)
        return SIZE_MAX;

    size_t dst_off = 0;
    int hi, lo;

    while (*src != '\0' && dst_off < capacity) {
        if ((hi = decode_hex(*src++)) == -1 || (lo = decode_hex(*src++)) == -1)
            return SIZE_MAX;
        dst[dst_off++] = (uint8_t)(hi * 16 + lo);
    }

    return dst_off;
}

static int cmd_calc_initial_secret(const char *dcid_hex)
{
    static const ptls_cipher_suite_t *cs = &ptls_openssl_aes128gcmsha256;
    uint8_t dcid[QUICLY_MAX_CID_LEN_V1], server_secret[PTLS_MAX_DIGEST_SIZE], client_secret[PTLS_MAX_DIGEST_SIZE];
    size_t dcid_len;

    /* decode dcid_hex */
    if ((dcid_len = decode_hexstring(dcid, sizeof(dcid), dcid_hex, SIZE_MAX)) == SIZE_MAX) {
        fprintf(stderr, "Invalid DCID: %s\n", dcid_hex);
        return 1;
    }

    /* calc initial key */
    const quicly_salt_t *salt = quicly_get_salt(QUICLY_PROTOCOL_VERSION_1);
    if (quicly_calc_initial_keys(cs, server_secret, client_secret, ptls_iovec_init(dcid, dcid_len), 1,
                                 ptls_iovec_init(salt->initial, sizeof(salt->initial))) != 0) {
        fprintf(stderr, "Crypto failure.\n");
        return 1;
    }

    printf("client: %s\nserver: %s\n", quicly_hexdump(client_secret, cs->hash->digest_size, SIZE_MAX),
           quicly_hexdump(server_secret, cs->hash->digest_size, SIZE_MAX));

    return 0;
}

static size_t determine_pn_offset(ptls_iovec_t input, size_t *packet_size, size_t *epoch, size_t short_packet_dcid_len)
{
    if (input.len < 1)
        goto Broken;

    if ((input.base[0] & QUICLY_LONG_HEADER_BIT) == QUICLY_LONG_HEADER_BIT) {

        /* long header packet; at the moment, only Inital packets are supported */
        if ((input.base[0] & QUICLY_PACKET_TYPE_BITMASK) != QUICLY_PACKET_TYPE_INITIAL)
            goto UnexpectedType;

        if (input.len < 5)
            goto Broken;
        size_t off = 5;

        /* skip CIDs */
        for (int i = 0; i < 2; ++i) {
            if (off >= input.len || (off += 1 + input.base[off]) > input.len)
                goto Broken;
        }

        { /* skip token length */
            const uint8_t *p = input.base + off;
            uint64_t token_len = quicly_decodev(&p, input.base + input.len);
            if (token_len == UINT64_MAX || (off = p - input.base + token_len) > input.len)
                goto Broken;
        }

        { /* read packet length and adjust so that `*packet_size` contains  */
            const uint8_t *p = input.base + off;
            if ((*packet_size = quicly_decodev(&p, input.base + input.len)) == SIZE_MAX)
                goto Broken;
            off = p - input.base;
            *packet_size += off;
        }

        *epoch = QUICLY_EPOCH_INITIAL;
        return off;

    } else {

        /* short header packet */
        if (input.len < 1 + short_packet_dcid_len + 4 + 16)
            goto Broken;
        *packet_size = input.len;
        *epoch = QUICLY_EPOCH_1RTT;
        return 1 + short_packet_dcid_len;
    }

Broken:
    fprintf(stderr, "Invalid or unsupported type of QUIC packet.\n");
    return SIZE_MAX;

UnexpectedType:
    fprintf(stderr, "Unexpected QUIC packet type.\n"); /* TODO add support for other types */
    return SIZE_MAX;
}

static int cmd_encrypt_packet(int is_enc, const char *secret_dcid_len)
{
    quicly_crypto_engine_t *engine = &quicly_default_crypto_engine;
    ptls_cipher_suite_t *cs = &ptls_openssl_aes128gcmsha256;
    ptls_cipher_context_t *header_protect;
    ptls_aead_context_t *packet_protect;
    uint8_t buf[1500] = {}, secret[PTLS_MAX_DIGEST_SIZE];
    size_t inlen, pn_off, packet_size, short_header_dcid_len = 0, epoch;

    { /* decode secret and dcid length */
        const char *separator = strchr(secret_dcid_len, ':');
        if (decode_hexstring(secret, cs->hash->digest_size, secret_dcid_len,
                             separator != NULL ? separator - secret_dcid_len : strlen(secret_dcid_len)) != cs->hash->digest_size) {
            fprintf(stderr, "Invalid secret (must be of %zu bytes in hex)\n", cs->hash->digest_size);
            return 1;
        }
        if (separator != NULL &&
            (sscanf(separator + 1, "%zu", &short_header_dcid_len) != 1 || short_header_dcid_len > QUICLY_MAX_CID_LEN_V1)) {
            fprintf(stderr, "Invalid DCID length\n");
            return 1;
        }
    }

    /* read the packet */
    inlen = fread(buf, 1, sizeof(buf) - cs->aead->tag_size, stdin);
    if (ferror(stdin)) {
        perror("I/O error");
        return 1;
    } else if (!feof(stdin)) {
        fprintf(stderr, "Unexpected amount of input.\n");
        return 1;
    }
    if ((pn_off = determine_pn_offset(ptls_iovec_init(buf, inlen), &packet_size, &epoch, short_header_dcid_len)) == SIZE_MAX)
        return 1;
    if (packet_size - pn_off < QUICLY_MAX_PN_SIZE + cs->aead->tag_size) {
        fprintf(stderr, "encrypted part of the packet is too small.\n");
        return 1;
    }

    /* setup crypto */
    if (engine->setup_cipher(engine, NULL, epoch, is_enc, &header_protect, &packet_protect, cs->aead, cs->hash, secret) != 0) {
        fprintf(stderr, "Crypto faiure.\n");
        return 1;
    }

    if (is_enc) {
        /* packet size can be greater than the input, in which case PADDING frames will be appended. However, it cannot exceed the
         * size of the buffer. */
        if (packet_size > sizeof(buf)) {
            fprintf(stderr, "Length field value is too large.\n");
            return 1;
        }
        if ((buf[0] & 3) + 1 != QUICLY_SEND_PN_SIZE) {
            fprintf(stderr, "Unexpected packet number size\n");
            return 1;
        }
        engine->encrypt_packet(engine, NULL, header_protect, packet_protect, ptls_iovec_init(buf, packet_size), 0,
                               pn_off + QUICLY_SEND_PN_SIZE, buf[pn_off] * 256 + buf[pn_off + 1], 0);
        fwrite(buf, 1, packet_size, stdout);
    } else {
        if (packet_size > inlen) {
            fprintf(stderr, "Length field value is too large.\n");
            return 1;
        }
        /* unprotect header protection */
        uint8_t hpmask[5] = {};
        ptls_cipher_init(header_protect, buf + pn_off + QUICLY_MAX_PN_SIZE);
        ptls_cipher_encrypt(header_protect, hpmask, hpmask, sizeof(hpmask));
        buf[0] ^= hpmask[0] & (QUICLY_PACKET_IS_LONG_HEADER(buf[0]) ? 0xf : 0x1f);
        size_t pn_len = (buf[0] & 0x3) + 1;
        uint64_t pn = 0;
        for (int i = 0; i < pn_len; ++i) {
            buf[pn_off + i] ^= hpmask[i + 1];
            pn = (pn << 8) | buf[pn_off + i];
        }
        /* decrypt */
        if (ptls_aead_decrypt(packet_protect, buf + pn_off + pn_len, buf + pn_off + pn_len, packet_size - (pn_off + pn_len), pn,
                              buf, pn_off + pn_len) == SIZE_MAX) {
            fprintf(stderr, "AEAD decryption failed.\n");
            return 1;
        }
        /* print */
        fwrite(buf + pn_off + pn_len, 1, packet_size - (pn_off + pn_len + cs->aead->tag_size), stdout);
    }

    return 0;
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
    const char *cert_file = NULL, *raw_pubkey_file = NULL, *host, *port, *cid_key = NULL;
    struct sockaddr_storage sa;
    socklen_t salen;
    unsigned udpbufsize = 0;
    int ch, opt_index, fd = -1;

    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    reqs = malloc(sizeof(*reqs));
    memset(reqs, 0, sizeof(*reqs));
    ctx = quicly_spec_context;
    ctx.tls = &tlsctx;
    ctx.stream_open = &stream_open;
    ctx.closed_by_remote = &closed_by_remote;
    ctx.save_resumption_token = &save_resumption_token;
    ctx.generate_resumption_token = &generate_resumption_token;
    stream_scheduler = quicly_default_stream_scheduler;
    stream_scheduler.do_send = scheduler_do_send;
    ctx.stream_scheduler = &stream_scheduler;

    setup_session_cache(ctx.tls);
    quicly_amend_ptls_context(ctx.tls);

    {
        uint8_t secret[PTLS_MAX_DIGEST_SIZE];
        ctx.tls->random_bytes(secret, ptls_openssl_sha256.digest_size);
        address_token_aead.enc = ptls_aead_new(&ptls_openssl_aes128gcm, &ptls_openssl_sha256, 1, secret, "");
        address_token_aead.dec = ptls_aead_new(&ptls_openssl_aes128gcm, &ptls_openssl_sha256, 0, secret, "");
    }

    static const struct option longopts[] = {{"ech-key", required_argument, NULL, 0},
                                             {"ech-configs", required_argument, NULL, 0},
                                             {"disable-ecn", no_argument, NULL, 0},
                                             {"disregard-app-limited", no_argument, NULL, 0},
                                             {"jumpstart-default", required_argument, NULL, 0},
                                             {"jumpstart-max", required_argument, NULL, 0},
                                             {"rapid-start", no_argument, NULL, 0},
                                             {"sockfd", required_argument, NULL, 0},
                                             {"exit-after-handshake", no_argument, NULL, 0},
                                             {"calc-initial-secret", required_argument, NULL, 0},
                                             {"decrypt-packet", required_argument, NULL, 0},
                                             {"encrypt-packet", required_argument, NULL, 0},
                                             {NULL}};
    while ((ch = getopt_long(argc, argv, "a:b:B:c:C:Dd:k:Ee:f:Gi:I:K:l:M:m:NnOp:P:Rr:S:s:u:U:Vvw:W:x:X:y:h", longopts,
                             &opt_index)) != -1) {
        switch (ch) {
        case 0: /* longopts */
            if (strcmp(longopts[opt_index].name, "ech-key") == 0) {
                ech_setup_key(&tlsctx, optarg);
            } else if (strcmp(longopts[opt_index].name, "ech-configs") == 0) {
                ech_setup_configs(optarg);
            } else if (strcmp(longopts[opt_index].name, "disable-ecn") == 0) {
                ctx.enable_ratio.ecn = 0;
            } else if (strcmp(longopts[opt_index].name, "disregard-app-limited") == 0) {
                ctx.enable_ratio.respect_app_limited = 0;
            } else if (strcmp(longopts[opt_index].name, "jumpstart-default") == 0) {
                if (sscanf(optarg, "%" SCNu32, &ctx.default_jumpstart_cwnd_packets) != 1) {
                    fprintf(stderr, "failed to parse default jumpstart size: %s\n", optarg);
                    exit(1);
                }
            } else if (strcmp(longopts[opt_index].name, "jumpstart-max") == 0) {
                if (sscanf(optarg, "%" SCNu32, &ctx.max_jumpstart_cwnd_packets) != 1) {
                    fprintf(stderr, "failed to parse max jumpstart size: %s\n", optarg);
                    exit(1);
                }
            } else if (strcmp(longopts[opt_index].name, "rapid-start") == 0) {
                ctx.enable_ratio.rapid_start = 255;
            } else if (strcmp(longopts[opt_index].name, "sockfd") == 0) {
                if (sscanf(optarg, "%d", &fd) != 1) {
                    fprintf(stderr, "invalid argument passed to --sockfd\n");
                    exit(1);
                }
            } else if (strcmp(longopts[opt_index].name, "exit-after-handshake") == 0) {
                exit_after_handshake = 1;
            } else if (strcmp(longopts[opt_index].name, "calc-initial-secret") == 0) {
                return cmd_calc_initial_secret(optarg);
            } else if (strcmp(longopts[opt_index].name, "decrypt-packet") == 0) {
                return cmd_encrypt_packet(0, optarg);
            } else if (strcmp(longopts[opt_index].name, "encrypt-packet") == 0) {
                return cmd_encrypt_packet(1, optarg);
            } else {
                assert(!"unexpected longname");
            }
            break;
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
            cert_file = optarg;
            break;
        case 'C': {
            quicly_cc_type_t **cc;
            char *token, *buf = alloca(strlen(optarg) + 1);
            strcpy(buf, optarg);
            /* CC name */
            token = strsep(&buf, ":");
            for (cc = quicly_cc_all_types; *cc != NULL; ++cc)
                if (strcmp((*cc)->name, token) == 0)
                    break;
            if (*cc != NULL) {
                ctx.init_cc = (*cc)->cc_init;
            } else {
                fprintf(stderr, "unknown congestion controller: %s\n", token);
                exit(1);
            }
            /* initcwnd */
            if ((token = strsep(&buf, ":")) != NULL) {
                if (sscanf(token, "%" SCNu32, &ctx.initcwnd_packets) != 1) {
                    fprintf(stderr, "invalid initcwnd value: %s\n", token);
                    exit(1);
                }
            }
            /* pacing */
            if ((token = strsep(&buf, ":")) != NULL) {
                if (strcmp(token, "p") == 0) {
                    ctx.enable_ratio.pacing = 255;
                } else {
                    fprintf(stderr, "invalid pacing value: %s\n", token);
                    exit(1);
                }
            }
        } break;
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
        case 'e': {
            int fd;
            if ((fd = open(optarg, O_WRONLY | O_CREAT | O_TRUNC, 0666)) == -1) {
                fprintf(stderr, "failed to open file:%s:%s\n", optarg, strerror(errno));
                exit(1);
            }
            ptls_log_add_fd(fd, 1., NULL, NULL, NULL, 1);
            ptls_log.may_include_appdata = 1;
        } break;
        case 'f': {
            double fraction;
            if (sscanf(optarg, "%lf", &fraction) != 1) {
                fprintf(stderr, "failed to parse ack frequency: %s\n", optarg);
                exit(1);
            }
            ctx.ack_frequency = (uint32_t)(fraction * 1024);
        } break;
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
            setup_verify_certificate(ctx.tls, NULL);
            break;
        case 'v':
            ++verbosity;
            break;
        case 'W':
            raw_pubkey_file = optarg;
            break;
        case 'x': {
            ptls_key_exchange_algorithm_t **named, **slot;
            for (named = ptls_openssl_key_exchanges_all; *named != NULL; ++named)
                if (strcasecmp((*named)->name, optarg) == 0)
                    break;
            if (*named == NULL) {
                fprintf(stderr, "unknown key exchange: %s\n", optarg);
                exit(1);
            }
            for (slot = key_exchanges; *slot != NULL; ++slot)
                ;
            *slot = *named;
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

    if (exit_after_handshake) {
        if (reqs[0].path != NULL) {
            fprintf(stderr, "-p and --exit-after-handshake cannot be used together\n");
            exit(1);
        }
    } else {
        if (reqs[0].path == NULL)
            push_req("/", 0);
    }

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

    int use_cid_encryptor = 0;
    if (cert_file != NULL || ctx.tls->sign_certificate != NULL) {
        /* server */
        if (cert_file == NULL || ctx.tls->sign_certificate == NULL) {
            fprintf(stderr, "-c and -k options must be used together\n");
            exit(1);
        }
        if (raw_pubkey_file != NULL) {
            ctx.tls->certificates.list = malloc(sizeof(*ctx.tls->certificates.list));
            load_raw_public_key(ctx.tls->certificates.list, cert_file);
            ctx.tls->certificates.count = 1;
            ctx.tls->use_raw_public_keys = 1;
        } else {
            load_certificate_chain(ctx.tls, cert_file);
        }
        use_cid_encryptor = 1;
    } else {
        /* client */
        if (raw_pubkey_file != NULL) {
            ptls_iovec_t raw_pub_key;
            EVP_PKEY *pubkey;
            load_raw_public_key(&raw_pub_key, raw_pubkey_file);
            pubkey = d2i_PUBKEY(NULL, (const unsigned char **)&raw_pub_key.base, raw_pub_key.len);
            if (pubkey == NULL) {
                fprintf(stderr, "Failed to create an EVP_PKEY from the key found in %s\n", raw_pubkey_file);
                return 1;
            }
            setup_raw_pubkey_verify_certificate(ctx.tls, pubkey);
            EVP_PKEY_free(pubkey);
            ctx.tls->use_raw_public_keys = 1;
        }
        hs_properties.client.negotiated_protocols.list = negotiated_protocols.list;
        hs_properties.client.negotiated_protocols.count = negotiated_protocols.count;
        if (session_file != NULL)
            load_session();
        hs_properties.client.ech.configs = ech.config_list;
        hs_properties.client.ech.retry_configs = &ech.retry.configs;
        use_cid_encryptor = cid_key != NULL;
    }
    if (use_cid_encryptor) {
        if (cid_key == NULL) {
            static char random_key[17];
            tlsctx.random_bytes(random_key, sizeof(random_key) - 1);
            cid_key = random_key;
        }
        ctx.cid_encryptor = quicly_new_default_cid_encryptor(
#if QUICLY_HAVE_FUSION
            ptls_fusion_is_supported_by_cpu() ? &ptls_fusion_quiclb :
#endif
                                              &ptls_openssl_quiclb,
            &ptls_openssl_aes128ecb, &ptls_openssl_sha256, ptls_iovec_init(cid_key, strlen(cid_key)));
    }
    if (argc != 2) {
        fprintf(stderr, "missing host and port\n");
        exit(1);
    }
    host = (--argc, *argv++);
    port = (--argc, *argv++);

    if (resolve_address((void *)&sa, &salen, host, port, AF_INET, SOCK_DGRAM, IPPROTO_UDP) != 0)
        exit(1);

    if (fd == -1 && (fd = socket(sa.ss_family, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
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
#ifdef IP_RECVTOS
    {
        int on = 1;
        if (setsockopt(fd, IPPROTO_IP, IP_RECVTOS, &on, sizeof(on)) != 0)
            perror("Warning: setsockopt(IP_RECVTOS) failed");
    }
#endif
    switch (sa.ss_family) {
    case AF_INET: {
#ifdef IP_PKTINFO
        int on = 1;
        if (setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &on, sizeof(on)) != 0) {
            perror("setsockopt(IP_PKTINFO) failed");
            return 1;
        }
#elif defined(IP_RECVDSTADDR)
        int on = 1;
        if (setsockopt(fd, IPPROTO_IP, IP_RECVDSTADDR, &on, sizeof(on)) != 0) {
            perror("setsockopt(IP_RECVDSTADDR) failed");
            return 1;
        }
#endif
    } break;
    case AF_INET6: {
        int on = 1;
        if (setsockopt(fd, IPPROTO_IP, IPV6_RECVPKTINFO, &on, sizeof(on)) != 0) {
            perror("setsockopt(IPV6_RECVPKTINNFO) failed");
            return 1;
        }
    } break;
    default:
        break;
    }

    return ctx.tls->certificates.count != 0 ? run_server(fd, (void *)&sa, salen) : run_client(fd, (void *)&sa, host);
}
