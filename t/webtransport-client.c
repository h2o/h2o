/*
 * Copyright (c) 2026 Fastly, Inc.
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

/**
 * A WebTransport client used by t/40webtransport.t. It establishes one session, either over HTTP/3 (native streams,
 * draft-ietf-webtrans-http3) or over HTTP/2 (capsules, draft-ietf-webtrans-http2), runs the actions given on the command line, then
 * waits for the responses and closes the session. Events are printed to stdout, one per line:
 *
 *   response <status>
 *   settings wt-enabled=<0|1>                      (HTTP/3 only)
 *   <client|server>-<bidi|uni>[<id>] fin "<data>"  (data longer than 64 bytes is summarized as `<N bytes, pattern ok|ng>`)
 *   <client|server>-<bidi|uni>[<id>] reset <code>
 *   <client|server>-<bidi|uni>[<id>] stop-sending <code>
 *   datagram "<data>"
 *   drain
 *   close <code> "<reason>"
 *   session-fin                                    (the CONNECT stream was closed without WT_CLOSE_SESSION)
 *   done
 *
 * Error codes are WebTransport application error codes, or `session-gone` / `buffered-stream-rejected` / `h3:0x...` for the error
 * codes defined by HTTP/3 and WebTransport over HTTP/3.
 */
#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <netdb.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include "picotls/openssl.h"
#include "quicly.h"
#include "quicly/defaults.h"
#include "quicly/streambuf.h"
#include "h2o.h"
#include "h2o/http3_common.h"
#include "h2o/qpack.h"
#include "h2o/webtransport.h"

#define MAX_STREAMS 1024
#define MAX_HEADERS 16
#define PRINT_MAX 64
/**
 * receive windows advertised to the server
 */
#define RECV_WINDOW (16 * 1024 * 1024)

struct wt_stream {
    int64_t id;
    unsigned is_local : 1;
    unsigned is_uni : 1;
    /**
     * set if the stream has been opened by an action; the send side is the one to be reset or stopped
     */
    unsigned send_closed : 1;
    unsigned recv_done : 1;
    h2o_buffer_t *recvbuf;
    /**
     * the quicly stream (HTTP/3)
     */
    quicly_stream_t *quic;
    /**
     * bytes sent (HTTP/2)
     */
    uint64_t bytes_sent;
    /**
     * the action (`bidi-reset` or `bidi-stop`) to be taken once the server echoes the first byte; the action is deferred so that
     * the server receives the stream header before the reset
     */
    void (*deferred_action)(struct wt_stream *stream, uint32_t code);
    uint32_t deferred_code;
};

struct transport {
    struct wt_stream *(*open_stream)(int uni);
    void (*send)(struct wt_stream *stream, const void *data, size_t len, int fin);
    void (*reset)(struct wt_stream *stream, uint32_t code);
    void (*stop)(struct wt_stream *stream, uint32_t code);
    void (*send_datagram)(const void *data, size_t len);
    void (*send_capsule)(h2o_buffer_t **capsules, int fin);
};

static const struct transport *transport;
static const char *url_str;
static h2o_url_t url;
static h2o_mem_pool_t pool;
static h2o_header_t req_headers[MAX_HEADERS];
static size_t num_req_headers;
static char **actions;
static size_t num_actions;
static unsigned expected_server_streams;
static int wait_close;
static uint32_t close_code;
static int64_t timeout_ms = 10000;

static struct {
    struct wt_stream *list[MAX_STREAMS];
    size_t count;
    int64_t next_bidi, next_uni;
} streams;

static struct {
    int established;
    int closed; /* WT_CLOSE_SESSION received, or the session is otherwise terminated */
    int close_sent;
    int done;
    unsigned server_streams_done;
    unsigned datagrams_sent, datagrams_received;
    int64_t deadline;
    int exit_status;
} session = {.exit_status = 1};

static int64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void print_data(const char *data, size_t len)
{
    putchar('"');
    for (size_t i = 0; i != len; ++i) {
        if (data[i] == '\n') {
            fputs("\\n", stdout);
        } else if (data[i] == '"' || data[i] == '\\') {
            printf("\\%c", data[i]);
        } else if (0x20 <= data[i] && data[i] < 0x7f) {
            putchar(data[i]);
        } else {
            printf("\\x%02x", (uint8_t)data[i]);
        }
    }
    putchar('"');
}

static char pattern_byte(size_t off)
{
    return 'a' + off % 26;
}

static void print_stream_label(struct wt_stream *stream)
{
    printf("%s-%s[%" PRId64 "]", stream->is_local ? "client" : "server", stream->is_uni ? "uni" : "bidi", stream->id);
}

static struct wt_stream *find_stream(int64_t id)
{
    for (size_t i = 0; i != streams.count; ++i)
        if (streams.list[i]->id == id)
            return streams.list[i];
    return NULL;
}

static struct wt_stream *new_stream(int64_t id)
{
    if (streams.count == MAX_STREAMS) {
        fprintf(stderr, "too many streams\n");
        exit(1);
    }
    struct wt_stream *stream = h2o_mem_alloc(sizeof(*stream));
    *stream = (struct wt_stream){.id = id,
                                 .is_local = !h2o_webtransport_stream_is_server_initiated(id),
                                 .is_uni = h2o_webtransport_stream_is_unidirectional(id)};
    h2o_buffer_init(&stream->recvbuf, &h2o_socket_buffer_prototype);
    /* local unidirectional streams have no receive side */
    if (stream->is_local && stream->is_uni)
        stream->recv_done = 1;
    streams.list[streams.count++] = stream;
    return stream;
}

static void check_done(void);

static void on_session_closed(void)
{
    session.closed = 1;
    check_done();
}

static void on_stream_data(struct wt_stream *stream, const void *data, size_t len, int fin)
{
    if (stream->recv_done)
        return;
    if (len != 0)
        h2o_buffer_append(&stream->recvbuf, data, len);
    if (stream->deferred_action != NULL && stream->recvbuf->size != 0) {
        void (*action)(struct wt_stream *, uint32_t) = stream->deferred_action;
        stream->deferred_action = NULL;
        action(stream, stream->deferred_code);
    }
    if (!fin)
        return;

    stream->recv_done = 1;
    print_stream_label(stream);
    fputs(" fin ", stdout);
    if (stream->recvbuf->size <= PRINT_MAX) {
        print_data(stream->recvbuf->bytes, stream->recvbuf->size);
    } else {
        int ok = 1;
        for (size_t i = 0; i != stream->recvbuf->size; ++i) {
            if (stream->recvbuf->bytes[i] != pattern_byte(i)) {
                ok = 0;
                break;
            }
        }
        printf("<%zu bytes, pattern %s>", stream->recvbuf->size, ok ? "ok" : "ng");
    }
    putchar('\n');

    /* close the send side of the bidirectional streams opened by the server, so that they can be closed */
    if (!stream->is_local) {
        if (!stream->is_uni && !stream->send_closed) {
            stream->send_closed = 1;
            transport->send(stream, NULL, 0, 1);
        }
        ++session.server_streams_done;
    }
    check_done();
}

static void print_error_code(quicly_error_t err, int is_h3)
{
    if (!is_h3) {
        printf("%" PRIu32, (uint32_t)err);
        return;
    }
    uint32_t app;
    if (h2o_webtransport_h3_error_to_application((uint64_t)err, &app) == 0) {
        printf("%" PRIu32, app);
    } else if ((uint64_t)err == H2O_WEBTRANSPORT_H3_ERROR_SESSION_GONE) {
        fputs("session-gone", stdout);
    } else if ((uint64_t)err == H2O_WEBTRANSPORT_H3_ERROR_BUFFERED_STREAM_REJECTED) {
        fputs("buffered-stream-rejected", stdout);
    } else {
        printf("h3:0x%" PRIx64, (uint64_t)err);
    }
}

static void on_stream_reset(struct wt_stream *stream, uint64_t code, int is_h3)
{
    if (stream->recv_done)
        return;
    stream->recv_done = 1;
    print_stream_label(stream);
    fputs(" reset ", stdout);
    print_error_code(code, is_h3);
    putchar('\n');
    if (!stream->is_local)
        ++session.server_streams_done;
    check_done();
}

static void on_stream_stop_sending(struct wt_stream *stream, uint64_t code, int is_h3)
{
    print_stream_label(stream);
    fputs(" stop-sending ", stdout);
    print_error_code(code, is_h3);
    putchar('\n');
}

static void on_datagram(const void *data, size_t len)
{
    fputs("datagram ", stdout);
    print_data(data, len);
    putchar('\n');
    ++session.datagrams_received;
    check_done();
}

/**
 * Handles the capsules found in `buf`, consuming those that are complete. The capsules carrying WebTransport streams appear only
 * when the session is carried by HTTP/2.
 */
static int handle_capsules(h2o_buffer_t **buf, void (*handle_stream_capsule)(uint64_t type, h2o_iovec_t payload))
{
    while ((*buf)->size != 0) {
        const uint8_t *src = (const uint8_t *)(*buf)->bytes, *end = src + (*buf)->size;
        uint64_t type, length;
        int ret = h2o_webtransport_decode_capsule_header(&src, end, &type, &length);
        if (ret == H2O_WEBTRANSPORT_DECODE_INCOMPLETE)
            return 0;
        if (ret != 0) {
            fprintf(stderr, "invalid capsule\n");
            return -1;
        }
        if ((uint64_t)(end - src) < length)
            return 0;
        h2o_iovec_t payload = h2o_iovec_init(src, length);
        switch (type) {
        case H2O_WEBTRANSPORT_CAPSULE_CLOSE_SESSION: {
            uint32_t code;
            h2o_iovec_t reason;
            if (h2o_webtransport_decode_close_session(payload, &code, &reason) != 0) {
                fprintf(stderr, "invalid WT_CLOSE_SESSION\n");
                return -1;
            }
            printf("close %" PRIu32 " ", code);
            print_data(reason.base, reason.len);
            putchar('\n');
            h2o_buffer_consume(buf, src + length - (const uint8_t *)(*buf)->bytes);
            on_session_closed();
            continue;
        }
        case H2O_WEBTRANSPORT_CAPSULE_DRAIN_SESSION:
            printf("drain\n");
            break;
        default:
            if (handle_stream_capsule != NULL)
                handle_stream_capsule(type, payload);
            break;
        }
        h2o_buffer_consume(buf, src + length - (const uint8_t *)(*buf)->bytes);
    }
    return 0;
}

static void close_session(uint32_t code, const char *reason)
{
    if (session.close_sent)
        return;
    session.close_sent = 1;
    h2o_buffer_t *buf;
    h2o_buffer_init(&buf, &h2o_socket_buffer_prototype);
    h2o_webtransport_encode_close_session(&buf, code, h2o_iovec_init(reason, strlen(reason)));
    transport->send_capsule(&buf, 1);
    h2o_buffer_dispose(&buf);
}

static uint32_t parse_code(const char *s)
{
    char *end;
    unsigned long v = strtoul(s, &end, 10);
    if (*end != '\0' && *end != ':') {
        fprintf(stderr, "invalid error code: %s\n", s);
        exit(1);
    }
    return (uint32_t)v;
}

static void send_text_or_pattern(struct wt_stream *stream, const char *arg, int fin)
{
    if (arg[0] == '@') {
        /* `@<size>` sends a pattern of the given size */
        size_t size = strtoul(arg + 1, NULL, 10), off = 0;
        while (off < size) {
            char chunk[16384];
            size_t n = size - off < sizeof(chunk) ? size - off : sizeof(chunk);
            for (size_t i = 0; i != n; ++i)
                chunk[i] = pattern_byte(off + i);
            off += n;
            transport->send(stream, chunk, n, fin && off == size);
        }
    } else {
        transport->send(stream, arg, strlen(arg), fin);
    }
}

static void run_actions(void)
{
    for (size_t i = 0; i != num_actions; ++i) {
        char *action = actions[i], *arg = strchr(action, ':');
        size_t name_len = arg != NULL ? (size_t)(arg++ - action) : strlen(action);
#define IS(n) (name_len == sizeof(n) - 1 && memcmp(action, n, name_len) == 0)
        if (IS("bidi") && arg != NULL) {
            send_text_or_pattern(transport->open_stream(0), arg, 1);
        } else if (IS("uni") && arg != NULL) {
            send_text_or_pattern(transport->open_stream(1), arg, 1);
            ++expected_server_streams; /* echoed back using a unidirectional stream opened by the server */
        } else if (IS("bidi-reset") && arg != NULL) {
            struct wt_stream *stream = transport->open_stream(0);
            transport->send(stream, "x", 1, 0);
            stream->deferred_action = transport->reset;
            stream->deferred_code = parse_code(arg);
        } else if (IS("bidi-stop") && arg != NULL) {
            struct wt_stream *stream = transport->open_stream(0);
            transport->send(stream, "x", 1, 0);
            stream->deferred_action = transport->stop;
            stream->deferred_code = parse_code(arg);
        } else if (IS("dgram") && arg != NULL) {
            transport->send_datagram(arg, strlen(arg));
            ++session.datagrams_sent;
        } else if (IS("drain") && arg == NULL) {
            h2o_buffer_t *buf;
            h2o_buffer_init(&buf, &h2o_socket_buffer_prototype);
            h2o_webtransport_encode_drain_session(&buf);
            transport->send_capsule(&buf, 0);
            h2o_buffer_dispose(&buf);
        } else if (IS("close") && arg != NULL) {
            const char *reason = strchr(arg, ':');
            close_session(parse_code(arg), reason != NULL ? reason + 1 : "");
        } else {
            fprintf(stderr, "unknown action: %s\n", action);
            exit(1);
        }
#undef IS
    }
}

static void on_established(int status)
{
    printf("response %d\n", status);
    if (status != 200) {
        session.done = 1;
        session.exit_status = 0;
        return;
    }
    session.established = 1;
    run_actions();
    check_done();
}

static void check_done(void)
{
    if (session.done || !session.established)
        return;

    if (!session.closed) {
        for (size_t i = 0; i != streams.count; ++i)
            if (streams.list[i]->is_local && !streams.list[i]->recv_done)
                return;
        if (session.server_streams_done < expected_server_streams || session.datagrams_received < session.datagrams_sent ||
            wait_close)
            return;
        close_session(close_code, "");
    }

    printf("done\n");
    session.done = 1;
    session.exit_status = 0;
    /* give the transport some time to deliver WT_CLOSE_SESSION or to close the connection gracefully */
    session.deadline = now_ms() + 1000;
}

/* HTTP/3 */

enum {
    H3_STREAM_CONTROL,          /* our control stream */
    H3_STREAM_PEER_UNI_PENDING, /* the type of a unidirectional stream opened by the server is not known yet */
    H3_STREAM_PEER_CONTROL,
    H3_STREAM_IGNORED,
    H3_STREAM_CONNECT,
    H3_STREAM_WT_PENDING, /* a bidirectional stream opened by the server, the signal value is yet to be received */
    H3_STREAM_WT,
};

struct h3_stream {
    quicly_streambuf_t sb;
    int kind;
    struct wt_stream *wt;
};

static struct {
    quicly_context_t ctx;
    ptls_context_t tls;
    quicly_conn_t *conn;
    int fd;
    struct sockaddr_in peer;
    quicly_stream_t *connect;
    h2o_qpack_decoder_t *qpack_dec;
    int settings_received;
    int response_received;
    h2o_buffer_t *capsules;
} h3;

static void h3_on_destroy(quicly_stream_t *qs, quicly_error_t err)
{
    struct h3_stream *s = qs->data;
    if (s->wt != NULL)
        s->wt->quic = NULL;
    if (qs == h3.connect)
        h3.connect = NULL;
    quicly_streambuf_destroy(qs, err);
}

static int h3_read_frame(ptls_iovec_t *input, uint64_t *type, ptls_iovec_t *payload)
{
    const uint8_t *src = input->base, *end = src + input->len;
    uint64_t length;
    if ((*type = quicly_decodev(&src, end)) == UINT64_MAX || (length = quicly_decodev(&src, end)) == UINT64_MAX ||
        (uint64_t)(end - src) < length)
        return 0;
    *payload = ptls_iovec_init(src, length);
    input->len -= src + length - input->base;
    input->base = (uint8_t *)src + length;
    return 1;
}

static void h3_start_session(void);

static int h3_handle_settings(ptls_iovec_t payload)
{
    const uint8_t *src = payload.base, *end = src + payload.len;
    uint64_t wt_enabled = 0;
    while (src != end) {
        uint64_t id, value;
        if ((id = quicly_decodev(&src, end)) == UINT64_MAX || (value = quicly_decodev(&src, end)) == UINT64_MAX)
            return -1;
        if (id == H2O_WEBTRANSPORT_H3_SETTINGS_WT_ENABLED)
            wt_enabled = value;
    }
    printf("settings wt-enabled=%" PRIu64 "\n", wt_enabled);
    h3.settings_received = 1;
    h3_start_session();
    return 0;
}

static void h3_handle_connect_frame(uint64_t type, ptls_iovec_t payload)
{
    switch (type) {
    case H2O_HTTP3_FRAME_TYPE_HEADERS: {
        if (h3.response_received)
            return; /* trailers */
        int status;
        h2o_headers_t headers = {NULL};
        h2o_iovec_t datagram_flow_id = {NULL};
        uint8_t header_ack[H2O_HPACK_ENCODE_INT_MAX_LENGTH];
        size_t header_ack_len;
        const char *err_desc = NULL;
        h2o_qpack_section_stats_t stats = {0};
        if (h2o_qpack_parse_response(&pool, h3.qpack_dec, h3.connect->stream_id, &status, &headers, &datagram_flow_id, 0, NULL,
                                     &stats, header_ack, &header_ack_len, payload.base, payload.len, &err_desc) != 0) {
            fprintf(stderr, "failed to parse response: %s\n", err_desc != NULL ? err_desc : "");
            exit(1);
        }
        if (100 <= status && status <= 199)
            return;
        h3.response_received = 1;
        on_established(status);
    } break;
    case H2O_HTTP3_FRAME_TYPE_DATA:
        h2o_buffer_append(&h3.capsules, payload.base, payload.len);
        if (handle_capsules(&h3.capsules, NULL) != 0)
            exit(1);
        break;
    default:
        break;
    }
}

static void h3_on_receive(quicly_stream_t *qs, size_t off, const void *src, size_t len)
{
    struct h3_stream *s = qs->data;

    if (quicly_streambuf_ingress_receive(qs, off, src, len) != 0)
        return;
    ptls_iovec_t input = quicly_streambuf_ingress_get(qs);
    size_t input_len = input.len;
    int fin = quicly_recvstate_transfer_complete(&qs->recvstate);

Redo:
    switch (s->kind) {
    case H3_STREAM_PEER_UNI_PENDING:
    case H3_STREAM_WT_PENDING: {
        const uint8_t *p = input.base, *end = p + input.len;
        uint64_t type, session_id;
        if ((type = quicly_decodev(&p, end)) == UINT64_MAX)
            break;
        if (s->kind == H3_STREAM_PEER_UNI_PENDING && type != H2O_WEBTRANSPORT_H3_STREAM_TYPE_UNI) {
            s->kind = type == H2O_HTTP3_STREAM_TYPE_CONTROL ? H3_STREAM_PEER_CONTROL : H3_STREAM_IGNORED;
        } else {
            if (s->kind == H3_STREAM_WT_PENDING && type != H2O_WEBTRANSPORT_H3_SIGNAL_BIDI) {
                fprintf(stderr, "unexpected bidirectional stream from server\n");
                exit(1);
            }
            if ((session_id = quicly_decodev(&p, end)) == UINT64_MAX)
                break;
            if (h3.connect == NULL || session_id != (uint64_t)h3.connect->stream_id) {
                fprintf(stderr, "stream for unknown session %" PRIu64 "\n", session_id);
                exit(1);
            }
            s->kind = H3_STREAM_WT;
            s->wt = new_stream(qs->stream_id);
            s->wt->quic = qs;
        }
        input.len -= p - input.base;
        input.base = (uint8_t *)p;
        goto Redo;
    }
    case H3_STREAM_PEER_CONTROL: {
        uint64_t type;
        ptls_iovec_t payload;
        while (h3_read_frame(&input, &type, &payload)) {
            if (!h3.settings_received) {
                if (type != H2O_HTTP3_FRAME_TYPE_SETTINGS || h3_handle_settings(payload) != 0) {
                    fprintf(stderr, "invalid SETTINGS\n");
                    exit(1);
                }
            } else if (type == H2O_HTTP3_FRAME_TYPE_GOAWAY) {
                printf("goaway\n");
            }
        }
    } break;
    case H3_STREAM_CONNECT: {
        uint64_t type;
        ptls_iovec_t payload;
        while (h3.connect != NULL && h3_read_frame(&input, &type, &payload))
            h3_handle_connect_frame(type, payload);
        if (fin && !session.closed) {
            printf("session-fin\n");
            on_session_closed();
        }
    } break;
    case H3_STREAM_WT:
        on_stream_data(s->wt, input.base, input.len, fin);
        input.len = 0;
        break;
    default:
        input.len = 0;
        break;
    }

    quicly_streambuf_ingress_shift(qs, input_len - input.len);
}

static void h3_on_receive_reset(quicly_stream_t *qs, quicly_error_t err)
{
    struct h3_stream *s = qs->data;
    switch (s->kind) {
    case H3_STREAM_WT:
        on_stream_reset(s->wt, QUICLY_ERROR_GET_ERROR_CODE(err), 1);
        break;
    case H3_STREAM_CONNECT:
        if (!session.closed) {
            printf("session-reset h3:0x%" PRIx64 "\n", QUICLY_ERROR_GET_ERROR_CODE(err));
            on_session_closed();
        }
        break;
    default:
        break;
    }
}

static void h3_on_send_stop(quicly_stream_t *qs, quicly_error_t err)
{
    struct h3_stream *s = qs->data;
    if (s->kind == H3_STREAM_WT)
        on_stream_stop_sending(s->wt, QUICLY_ERROR_GET_ERROR_CODE(err), 1);
}

static const quicly_stream_callbacks_t h3_stream_callbacks = {
    h3_on_destroy,      quicly_streambuf_egress_shift, quicly_streambuf_egress_emit, h3_on_send_stop, h3_on_receive,
    h3_on_receive_reset};

static quicly_error_t h3_on_stream_open(quicly_stream_open_t *self, quicly_stream_t *qs)
{
    int ret;
    if ((ret = quicly_streambuf_create(qs, sizeof(struct h3_stream))) != 0)
        return ret;
    qs->callbacks = &h3_stream_callbacks;
    struct h3_stream *s = qs->data;
    s->wt = NULL;
    if (quicly_stream_is_client_initiated(qs->stream_id)) {
        s->kind = H3_STREAM_IGNORED; /* set by the caller */
    } else if (quicly_stream_is_unidirectional(qs->stream_id)) {
        s->kind = H3_STREAM_PEER_UNI_PENDING;
    } else {
        s->kind = H3_STREAM_WT_PENDING;
    }
    return 0;
}

static void h3_on_receive_datagram(quicly_receive_datagram_frame_t *self, quicly_conn_t *conn, ptls_iovec_t payload)
{
    uint64_t quarter_stream_id;
    h2o_iovec_t data;
    if (h2o_webtransport_decode_datagram(h2o_iovec_init(payload.base, payload.len), &quarter_stream_id, &data) != 0 ||
        h3.connect == NULL || quarter_stream_id != (uint64_t)h3.connect->stream_id / 4)
        return;
    on_datagram(data.base, data.len);
}

static quicly_stream_t *h3_open(int uni, int kind)
{
    quicly_stream_t *qs;
    if (quicly_open_stream(h3.conn, &qs, uni) != 0) {
        fprintf(stderr, "failed to open stream\n");
        exit(1);
    }
    ((struct h3_stream *)qs->data)->kind = kind;
    return qs;
}

static void h3_send_control_stream(void)
{
    quicly_stream_t *qs = h3_open(1, H3_STREAM_CONTROL);
    uint8_t buf[64], *p = buf, settings[32], *q = settings;
    q = quicly_encodev(q, H2O_HTTP3_SETTINGS_H3_DATAGRAM);
    q = quicly_encodev(q, 1);
    q = quicly_encodev(q, H2O_WEBTRANSPORT_H3_SETTINGS_WT_ENABLED);
    q = quicly_encodev(q, 1);
    p = quicly_encodev(p, H2O_HTTP3_STREAM_TYPE_CONTROL);
    p = quicly_encodev(p, H2O_HTTP3_FRAME_TYPE_SETTINGS);
    p = quicly_encodev(p, q - settings);
    memcpy(p, settings, q - settings);
    p += q - settings;
    quicly_streambuf_egress_write(qs, buf, p - buf);
}

static void h3_start_session(void)
{
    h3.connect = h3_open(0, H3_STREAM_CONNECT);
    h2o_qpack_section_stats_t stats = {0};
    h2o_iovec_t frame = h2o_qpack_flatten_request(
        NULL, &pool, h3.connect->stream_id, NULL, h2o_iovec_init(H2O_STRLIT("CONNECT")), &H2O_URL_SCHEME_HTTPS, url.authority,
        url.path, h2o_iovec_init(H2O_STRLIT("webtransport-h3")), req_headers, num_req_headers, h2o_iovec_init(NULL, 0), &stats);
    quicly_streambuf_egress_write(h3.connect, frame.base, frame.len);
}

static struct wt_stream *h3_open_stream(int uni)
{
    quicly_stream_t *qs = h3_open(uni, H3_STREAM_WT);
    struct wt_stream *stream = new_stream(qs->stream_id);
    stream->quic = qs;
    ((struct h3_stream *)qs->data)->wt = stream;
    uint8_t prefix[H2O_WEBTRANSPORT_H3_MAX_STREAM_PREFIX_SIZE];
    uint8_t *end = h2o_webtransport_encode_stream_prefix(
        prefix, uni ? H2O_WEBTRANSPORT_H3_STREAM_TYPE_UNI : H2O_WEBTRANSPORT_H3_SIGNAL_BIDI, h3.connect->stream_id);
    quicly_streambuf_egress_write(qs, prefix, end - prefix);
    return stream;
}

static void h3_send(struct wt_stream *stream, const void *data, size_t len, int fin)
{
    if (stream->quic == NULL)
        return;
    if (len != 0)
        quicly_streambuf_egress_write(stream->quic, data, len);
    if (fin)
        quicly_streambuf_egress_shutdown(stream->quic);
}

static void h3_reset(struct wt_stream *stream, uint32_t code)
{
    if (stream->quic != NULL)
        quicly_reset_stream(stream->quic,
                            QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(h2o_webtransport_h3_error_from_application(code)));
}

static void h3_stop(struct wt_stream *stream, uint32_t code)
{
    if (stream->quic != NULL)
        quicly_request_stop(stream->quic,
                            QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(h2o_webtransport_h3_error_from_application(code)));
}

static void h3_send_datagram(const void *data, size_t len)
{
    uint8_t buf[1500];
    uint8_t *p = h2o_webtransport_encode_datagram_prefix(buf, h3.connect->stream_id / 4);
    if (len > sizeof(buf) - (p - buf))
        len = sizeof(buf) - (p - buf);
    memcpy(p, data, len);
    ptls_iovec_t datagram = ptls_iovec_init(buf, p - buf + len);
    quicly_send_datagram_frames(h3.conn, &datagram, 1);
}

static void h3_send_capsule(h2o_buffer_t **capsules, int fin)
{
    if (h3.connect == NULL || !quicly_sendstate_is_open(&h3.connect->sendstate))
        return;
    uint8_t hdr[16], *p = hdr;
    p = quicly_encodev(p, H2O_HTTP3_FRAME_TYPE_DATA);
    p = quicly_encodev(p, (*capsules)->size);
    quicly_streambuf_egress_write(h3.connect, hdr, p - hdr);
    quicly_streambuf_egress_write(h3.connect, (*capsules)->bytes, (*capsules)->size);
    if (fin)
        quicly_streambuf_egress_shutdown(h3.connect);
}

static const struct transport h3_transport = {h3_open_stream, h3_send, h3_reset, h3_stop, h3_send_datagram, h3_send_capsule};

static int h3_send_pending(void)
{
    quicly_address_t dest, src;
    struct iovec packets[16];
    uint8_t buf[16 * 1500];
    size_t num_packets = PTLS_ELEMENTSOF(packets);
    quicly_error_t ret;

    if ((ret = quicly_send(h3.conn, &dest, &src, packets, &num_packets, buf, sizeof(buf))) != 0)
        return ret == QUICLY_ERROR_FREE_CONNECTION ? 1 : -1;
    for (size_t i = 0; i != num_packets; ++i)
        sendto(h3.fd, packets[i].iov_base, packets[i].iov_len, 0, &dest.sa, sizeof(dest.sin));
    return 0;
}

static int run_h3(void)
{
    static quicly_stream_open_t stream_open = {h3_on_stream_open};
    static quicly_receive_datagram_frame_t receive_datagram = {h3_on_receive_datagram};
    static quicly_cid_plaintext_t next_cid;

    h3.tls = (ptls_context_t){.random_bytes = ptls_openssl_random_bytes,
                              .get_time = &ptls_get_time,
                              .key_exchanges = ptls_openssl_key_exchanges,
                              .cipher_suites = ptls_openssl_cipher_suites};
    quicly_amend_ptls_context(&h3.tls);
    h3.ctx = quicly_spec_context;
    h3.ctx.tls = &h3.tls;
    h3.ctx.stream_open = &stream_open;
    h3.ctx.receive_datagram_frame = &receive_datagram;
    h3.ctx.transport_params.max_streams_uni = 100;
    h3.ctx.transport_params.max_streams_bidi = 100;
    h3.ctx.transport_params.max_data = RECV_WINDOW;
    h3.ctx.transport_params.max_stream_data.uni = RECV_WINDOW;
    h3.ctx.transport_params.max_stream_data.bidi_local = RECV_WINDOW;
    h3.ctx.transport_params.max_stream_data.bidi_remote = RECV_WINDOW;
    h3.ctx.transport_params.max_datagram_frame_size = 1500;
    h3.qpack_dec = h2o_qpack_create_decoder(0, 0);
    h2o_buffer_init(&h3.capsules, &h2o_socket_buffer_prototype);

    /* resolve the server address (IPv4 only, as the tests listen on 127.0.0.1) */
    struct addrinfo hints = {.ai_family = AF_INET, .ai_socktype = SOCK_DGRAM}, *res;
    char host[256], port[8];
    snprintf(host, sizeof(host), "%.*s", (int)url.host.len, url.host.base);
    snprintf(port, sizeof(port), "%" PRIu16, h2o_url_get_port(&url));
    if (getaddrinfo(host, port, &hints, &res) != 0) {
        fprintf(stderr, "failed to resolve %s\n", host);
        return 1;
    }
    memcpy(&h3.peer, res->ai_addr, sizeof(h3.peer));
    freeaddrinfo(res);
    if ((h3.fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        perror("socket");
        return 1;
    }
    struct sockaddr_in local = {.sin_family = AF_INET};
    if (bind(h3.fd, (void *)&local, sizeof(local)) != 0) {
        perror("bind");
        return 1;
    }

    ptls_iovec_t alpn = ptls_iovec_init("h3", 2);
    ptls_handshake_properties_t hsprops = {{{{NULL}}}};
    hsprops.client.negotiated_protocols.list = &alpn;
    hsprops.client.negotiated_protocols.count = 1;
    if (quicly_connect(&h3.conn, &h3.ctx, host, (void *)&h3.peer, NULL, &next_cid, ptls_iovec_init(NULL, 0), &hsprops, NULL,
                       NULL) != 0) {
        fprintf(stderr, "quicly_connect failed\n");
        return 1;
    }
    h3_send_control_stream();

    int64_t deadline = now_ms() + timeout_ms, closing = 0;
    while (1) {
        int64_t now = now_ms();
        if (session.done && !closing && (session.closed || now >= session.deadline)) {
            quicly_close(h3.conn, H2O_HTTP3_ERROR_NONE, "");
            closing = 1;
        }
        if (now >= deadline) {
            printf("timeout\n");
            return 1;
        }
        int ret;
        if ((ret = h3_send_pending()) != 0) {
            if (ret < 0)
                fprintf(stderr, "quicly_send failed\n");
            break;
        }
        if (quicly_get_state(h3.conn) >= QUICLY_STATE_CLOSING && !closing) {
            int is_remote;
            quicly_error_t err = quicly_get_close_reason(h3.conn, NULL, NULL, &is_remote);
            if (!session.done) {
                printf("connection-close %s 0x%" PRIx64 "\n", is_remote ? "remote" : "local", QUICLY_ERROR_GET_ERROR_CODE(err));
                session.done = 1;
            }
            closing = 1;
        }
        int64_t delay = quicly_get_first_timeout(h3.conn) - h3.ctx.now->cb(h3.ctx.now);
        if (delay < 0)
            delay = 0;
        if (delay > 50)
            delay = 50;
        struct pollfd pfd = {.fd = h3.fd, .events = POLLIN};
        if (poll(&pfd, 1, (int)delay) <= 0 || (pfd.revents & POLLIN) == 0)
            continue;
        uint8_t input[65536];
        struct sockaddr_in from;
        socklen_t fromlen = sizeof(from);
        ssize_t len;
        while ((len = recvfrom(h3.fd, input, sizeof(input), MSG_DONTWAIT, (void *)&from, &fromlen)) > 0) {
            size_t off = 0;
            while (off < (size_t)len) {
                quicly_decoded_packet_t packet;
                if (quicly_decode_packet(&h3.ctx, &packet, input, len, &off) == SIZE_MAX)
                    break;
                quicly_receive(h3.conn, NULL, (void *)&from, &packet);
            }
            fromlen = sizeof(from);
        }
    }

    return session.exit_status;
}

/* HTTP/2 */

static struct {
    h2o_httpclient_t *client;
    h2o_buffer_t *outbuf;
    int write_inflight;
    int fin_pending;
    int fin_sent;
    int ended;
} h2;

static void h2_flush(void)
{
    if (h2.client == NULL || h2.write_inflight || h2.fin_sent || (h2.outbuf->size == 0 && !h2.fin_pending))
        return;
    h2.write_inflight = 1;
    h2.fin_sent = h2.fin_pending;
    h2o_iovec_t chunk = h2o_iovec_init(h2.outbuf->bytes, h2.outbuf->size);
    h2.client->write_req(h2.client, chunk, h2.fin_sent);
    h2o_buffer_consume(&h2.outbuf, chunk.len);
}

static void h2_append_varint_capsule(uint64_t type, const uint64_t *fields, size_t num_fields)
{
    h2o_webtransport_encode_varint_capsule(&h2.outbuf, type, fields, num_fields);
}

static struct wt_stream *h2_open_stream(int uni)
{
    int64_t *next = uni ? &streams.next_uni : &streams.next_bidi;
    struct wt_stream *stream = new_stream(*next);
    *next += 4;
    return stream;
}

static void h2_send(struct wt_stream *stream, const void *data, size_t len, int fin)
{
    if (stream->send_closed && !fin)
        return;
    uint8_t hdr[H2O_WEBTRANSPORT_MAX_CAPSULE_HEADER_SIZE + 8], *p = hdr;
    p = h2o_webtransport_encode_capsule_header(p, fin ? H2O_WEBTRANSPORT_CAPSULE_STREAM_FIN : H2O_WEBTRANSPORT_CAPSULE_STREAM,
                                               quicly_encodev_capacity(stream->id) + len);
    p = quicly_encodev(p, stream->id);
    h2o_buffer_append(&h2.outbuf, hdr, p - hdr);
    if (len != 0)
        h2o_buffer_append(&h2.outbuf, data, len);
    stream->bytes_sent += len;
    if (fin)
        stream->send_closed = 1;
    h2_flush();
}

static void h2_reset(struct wt_stream *stream, uint32_t code)
{
    if (stream->send_closed)
        return;
    stream->send_closed = 1;
    uint64_t fields[] = {stream->id, code, stream->bytes_sent}; /* reliable size equals the bytes sent (draft-15 section 6.2) */
    h2_append_varint_capsule(H2O_WEBTRANSPORT_CAPSULE_RESET_STREAM, fields, 3);
    h2_flush();
}

static void h2_stop(struct wt_stream *stream, uint32_t code)
{
    uint64_t fields[] = {stream->id, code};
    h2_append_varint_capsule(H2O_WEBTRANSPORT_CAPSULE_STOP_SENDING, fields, 2);
    h2_flush();
}

static void h2_send_datagram(const void *data, size_t len)
{
    uint8_t hdr[H2O_WEBTRANSPORT_MAX_CAPSULE_HEADER_SIZE];
    uint8_t *p = h2o_webtransport_encode_capsule_header(hdr, H2O_WEBTRANSPORT_CAPSULE_DATAGRAM, len);
    h2o_buffer_append(&h2.outbuf, hdr, p - hdr);
    h2o_buffer_append(&h2.outbuf, data, len);
    h2_flush();
}

static void h2_send_capsule(h2o_buffer_t **capsules, int fin)
{
    if (h2.fin_pending)
        return;
    h2o_buffer_append(&h2.outbuf, (*capsules)->bytes, (*capsules)->size);
    if (fin)
        h2.fin_pending = 1;
    h2_flush();
}

static const struct transport h2_transport = {h2_open_stream, h2_send, h2_reset, h2_stop, h2_send_datagram, h2_send_capsule};

static void h2_handle_stream_capsule(uint64_t type, h2o_iovec_t payload)
{
    const uint8_t *src = (const uint8_t *)payload.base, *end = src + payload.len;

    switch (type) {
    case H2O_WEBTRANSPORT_CAPSULE_STREAM:
    case H2O_WEBTRANSPORT_CAPSULE_STREAM_FIN: {
        uint64_t id;
        if ((id = quicly_decodev(&src, end)) == UINT64_MAX)
            goto Invalid;
        struct wt_stream *stream = find_stream(id);
        if (stream == NULL) {
            if (!h2o_webtransport_stream_is_server_initiated(id))
                return; /* already closed */
            stream = new_stream(id);
        }
        on_stream_data(stream, src, end - src, type == H2O_WEBTRANSPORT_CAPSULE_STREAM_FIN);
    } break;
    case H2O_WEBTRANSPORT_CAPSULE_RESET_STREAM: {
        uint64_t fields[3];
        if (h2o_webtransport_decode_varint_capsule(payload, fields, 3) != 0)
            goto Invalid;
        struct wt_stream *stream = find_stream(fields[0]);
        if (stream == NULL && h2o_webtransport_stream_is_server_initiated(fields[0]))
            stream = new_stream(fields[0]);
        if (stream != NULL)
            on_stream_reset(stream, fields[1], 0);
    } break;
    case H2O_WEBTRANSPORT_CAPSULE_STOP_SENDING: {
        uint64_t fields[2];
        if (h2o_webtransport_decode_varint_capsule(payload, fields, 2) != 0)
            goto Invalid;
        struct wt_stream *stream = find_stream(fields[0]);
        if (stream == NULL)
            return;
        on_stream_stop_sending(stream, fields[1], 0);
        /* respond by resetting the stream, as QUIC stacks do */
        h2_reset(stream, (uint32_t)fields[1]);
    } break;
    case H2O_WEBTRANSPORT_CAPSULE_DATAGRAM:
        on_datagram(payload.base, payload.len);
        break;
    default:
        break;
    }
    return;
Invalid:
    fprintf(stderr, "invalid capsule of type 0x%" PRIx64 "\n", type);
    exit(1);
}

static int h2_on_body(h2o_httpclient_t *client, const char *errstr, h2o_header_t *trailers, size_t num_trailers)
{
    if (handle_capsules(client->buf, h2_handle_stream_capsule) != 0)
        exit(1);
    if (errstr != NULL) {
        h2.client = NULL;
        h2.ended = 1;
        if (errstr != h2o_httpclient_error_is_eos)
            fprintf(stderr, "%s\n", errstr);
        if (!session.closed) {
            printf("session-fin\n");
            on_session_closed();
        }
        return -1;
    }
    return 0;
}

static h2o_httpclient_body_cb h2_on_head(h2o_httpclient_t *client, const char *errstr, h2o_httpclient_on_head_t *args)
{
    if (errstr != NULL && errstr != h2o_httpclient_error_is_eos) {
        printf("error %s\n", errstr);
        h2.client = NULL;
        h2.ended = 1;
        return NULL;
    }
    if (args->version != 0x200) {
        printf("unexpected HTTP version %x\n", args->version);
        h2.client = NULL;
        h2.ended = 1;
        return NULL;
    }
    on_established(args->status);
    if (args->status != 200 || errstr != NULL) {
        h2.client = NULL;
        h2.ended = 1;
        return NULL;
    }

    /* grant credit for the streams opened by the server, as the default limits of WebTransport over HTTP/2 are zero */
    uint64_t max_data = RECV_WINDOW, max_streams = 100;
    h2_append_varint_capsule(H2O_WEBTRANSPORT_CAPSULE_MAX_DATA, &max_data, 1);
    h2_append_varint_capsule(H2O_WEBTRANSPORT_CAPSULE_MAX_STREAMS_BIDI, &max_streams, 1);
    h2_append_varint_capsule(H2O_WEBTRANSPORT_CAPSULE_MAX_STREAMS_UNI, &max_streams, 1);
    h2_flush();

    return h2_on_body;
}

static void h2_proceed_req(h2o_httpclient_t *client, const char *errstr)
{
    if (errstr != NULL) {
        fprintf(stderr, "write failed: %s\n", errstr);
        h2.client = NULL;
        h2.ended = 1;
        return;
    }
    h2.write_inflight = 0;
    h2_flush();
}

static h2o_httpclient_head_cb h2_on_connect(h2o_httpclient_t *client, const char *errstr, h2o_iovec_t *method, h2o_url_t *_url,
                                            const h2o_header_t **headers, size_t *num_headers, h2o_iovec_t *body,
                                            h2o_httpclient_proceed_req_cb *proceed_req_cb, h2o_httpclient_properties_t *props,
                                            h2o_url_t *origin)
{
    if (errstr != NULL) {
        printf("error %s\n", errstr);
        h2.ended = 1;
        return NULL;
    }
    h2.client = client;
    h2.write_inflight = 1; /* until `proceed_req` is called after the HEADERS frame is sent */
    *method = h2o_iovec_init(H2O_STRLIT("CONNECT"));
    *_url = url;
    *headers = req_headers;
    *num_headers = num_req_headers;
    *body = h2o_iovec_init(NULL, 0);
    *proceed_req_cb = h2_proceed_req;
    return h2_on_head;
}

static int run_h2(void)
{
    h2o_multithread_receiver_t getaddr_receiver;
    h2o_httpclient_ctx_t ctx = {
        .loop = h2o_evloop_create(),
        .getaddr_receiver = &getaddr_receiver,
        .io_timeout = timeout_ms,
        .connect_timeout = timeout_ms,
        .first_byte_timeout = timeout_ms,
        .keepalive_timeout = timeout_ms,
        .max_buffer_size = RECV_WINDOW,
        .http2 = {.max_concurrent_streams = 100},
        .protocol_selector = {.ratio = {.http2 = 100}},
    };
    h2o_multithread_queue_t *queue = h2o_multithread_create_queue(ctx.loop);
    h2o_multithread_register_receiver(queue, ctx.getaddr_receiver, h2o_hostinfo_getaddr_receiver);

    h2o_buffer_init(&h2.outbuf, &h2o_socket_buffer_prototype);
    streams.next_bidi = 0;
    streams.next_uni = 2;

    /* advertise the per-stream limits using WebTransport-Init, as h2o_httpclient does not send WebTransport SETTINGS */
    char init[128];
    snprintf(init, sizeof(init), "u=%d, bl=%d, br=%d", RECV_WINDOW, RECV_WINDOW, RECV_WINDOW);
    static h2o_iovec_t init_name = {H2O_STRLIT("webtransport-init")};
    req_headers[num_req_headers++] = (h2o_header_t){&init_name, NULL, h2o_strdup(&pool, init, SIZE_MAX)};

    h2o_httpclient_connection_pool_t *connpool = h2o_mem_alloc(sizeof(*connpool));
    h2o_socketpool_t *sockpool = h2o_mem_alloc(sizeof(*sockpool));
    h2o_socketpool_target_t *target = h2o_socketpool_create_target(&url, NULL);
    h2o_socketpool_init_specific(sockpool, 10, &target, 1, NULL);
    h2o_socketpool_set_timeout(sockpool, timeout_ms);
    h2o_socketpool_register_loop(sockpool, ctx.loop);
    h2o_httpclient_connection_pool_init(connpool, sockpool);
    SSL_CTX *ssl_ctx = SSL_CTX_new(SSLv23_client_method());
    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_NONE, NULL);
    h2o_socketpool_set_ssl_ctx(sockpool, ssl_ctx);
    SSL_CTX_free(ssl_ctx);

    h2o_httpclient_connect(NULL, &pool, NULL, &ctx, connpool, &url, "webtransport", h2_on_connect);

    int64_t deadline = now_ms() + timeout_ms;
    while (!h2.ended || h2.outbuf->size != 0) {
        int64_t now = now_ms();
        if (now >= deadline) {
            printf("timeout\n");
            return 1;
        }
        if (session.done && (h2.ended || now >= session.deadline))
            break;
        h2o_evloop_run(ctx.loop, 50);
    }

    return session.exit_status;
}

static void usage(const char *cmd)
{
    fprintf(stderr,
            "Usage: %s [options] <url> [action...]\n"
            "Options:\n"
            "  -3              use HTTP/3 (default: HTTP/2)\n"
            "  -H name:value   adds a request header\n"
            "  -e <count>      number of streams the server is expected to open (in addition to the echo of `uni`)\n"
            "  -w              wait for the server to close the session\n"
            "  -c <code>       error code used for closing the session (default: 0)\n"
            "  -t <msec>       timeout (default: 10000)\n"
            "Actions:\n"
            "  bidi:<text>     opens a bidirectional stream and sends <text> followed by FIN\n"
            "  uni:<text>      opens a unidirectional stream and sends <text> followed by FIN\n"
            "                  (`@<size>` can be used in place of <text> to send a pattern of given size)\n"
            "  bidi-reset:<code> opens a bidirectional stream, sends a byte, then resets it once echoed\n"
            "  bidi-stop:<code> opens a bidirectional stream, sends a byte, then sends STOP_SENDING once echoed\n"
            "  dgram:<text>    sends a datagram\n"
            "  drain           sends WT_DRAIN_SESSION\n"
            "  close:<code>[:<reason>] closes the session\n",
            cmd);
    exit(1);
}

int main(int argc, char **argv)
{
    int use_h3 = 0, ch;

    setvbuf(stdout, NULL, _IOLBF, 0);
    h2o_mem_init_pool(&pool);
    SSL_load_error_strings();
    SSL_library_init();
    OpenSSL_add_all_algorithms();

    while ((ch = getopt(argc, argv, "3H:e:wc:t:h")) != -1) {
        switch (ch) {
        case '3':
            use_h3 = 1;
            break;
        case 'H': {
            const char *colon = strchr(optarg, ':'), *value;
            if (colon == NULL || num_req_headers == MAX_HEADERS)
                usage(argv[0]);
            for (value = colon + 1; *value == ' '; ++value)
                ;
            h2o_iovec_t *name = h2o_mem_alloc_pool(&pool, *name, 1);
            *name = h2o_strdup(&pool, optarg, colon - optarg);
            h2o_strtolower(name->base, name->len);
            req_headers[num_req_headers++] = (h2o_header_t){name, NULL, h2o_strdup(&pool, value, SIZE_MAX)};
        } break;
        case 'e':
            expected_server_streams = (unsigned)strtoul(optarg, NULL, 10);
            break;
        case 'w':
            wait_close = 1;
            break;
        case 'c':
            close_code = parse_code(optarg);
            break;
        case 't':
            timeout_ms = strtoll(optarg, NULL, 10);
            break;
        default:
            usage(argv[0]);
        }
    }
    if (optind == argc)
        usage(argv[0]);
    url_str = argv[optind++];
    if (h2o_url_parse(&pool, url_str, SIZE_MAX, &url) != 0 || url.scheme != &H2O_URL_SCHEME_HTTPS) {
        fprintf(stderr, "invalid URL: %s\n", url_str);
        exit(1);
    }
    actions = argv + optind;
    num_actions = argc - optind;

    if (use_h3) {
        transport = &h3_transport;
        return run_h3();
    } else {
        transport = &h2_transport;
        return run_h2();
    }
}

int __lsan_is_turned_off(void)
{
    return 1;
}
