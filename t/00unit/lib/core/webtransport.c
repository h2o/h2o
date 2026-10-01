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
/*
 * Tests of the capsule backend. The session is established on a fake extended CONNECT request; the capsules sent by the peer are
 * fed through `write_req.cb`, and those sent by the session are captured by the ostream, which acknowledges each batch on the next
 * iteration of the event loop. The callbacks of the application, as well as the capsules being sent, are recorded as strings.
 */
#include <inttypes.h>
#include <stdarg.h>
#include "../../test.h"
#include "../../../../lib/core/webtransport.c"

static h2o_globalconf_t globalconf;
static h2o_context_t ctx;

static struct {
    h2o_conn_t *conn;
    h2o_req_t req;
    h2o_ostream_t ostr;
    /**
     * settings returned by `get_webtransport_settings`; the callback fails if `settings_unavailable` is set
     */
    h2o_webtransport_settings_t local, remote;
    unsigned settings_unavailable : 1;
    /**
     * behavior of the application
     */
    unsigned echo : 1;
    unsigned hold_input : 1;
    quicly_error_t open_error;
    /**
     * state of the fake protocol layer
     */
    h2o_buffer_t *out;
    h2o_send_state_t send_state;
    unsigned proceed_pending : 1;
    unsigned final_sent : 1;
    h2o_webtransport_session_t *session;
    /**
     * events recorded
     */
    char events[4096];
    size_t events_len;
    char output[4096];
} t;

static void record(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

static void record(const char *fmt, ...)
{
    va_list args;

    if (t.events_len != 0 && t.events_len < sizeof(t.events) - 1)
        t.events[t.events_len++] = ' ';
    va_start(args, fmt);
    int ret = vsnprintf(t.events + t.events_len, sizeof(t.events) - t.events_len, fmt, args);
    va_end(args);
    if (ret > 0)
        t.events_len += (size_t)ret;
    if (t.events_len >= sizeof(t.events))
        t.events_len = sizeof(t.events) - 1;
}

static const char *error_str(quicly_error_t err)
{
    static char buf[32];

    if (err == 0)
        return "0";
    if (QUICLY_ERROR_IS_QUIC_APPLICATION(err)) {
        sprintf(buf, "app:%" PRIu64, (uint64_t)QUICLY_ERROR_GET_ERROR_CODE(err));
    } else {
        sprintf(buf, "0x%" PRIx64, (uint64_t)err);
    }
    return buf;
}

static const char *take_events(void)
{
    static char buf[sizeof(t.events)];

    memcpy(buf, t.events, t.events_len);
    buf[t.events_len] = '\0';
    t.events_len = 0;
    return buf;
}

/* application */

static void app_on_destroy(h2o_webtransport_stream_t *stream, quicly_error_t err)
{
    record("destroy(%" PRId64 ",%s)", stream->stream_id, error_str(err));
    h2o_webtransport_streambuf_destroy(stream, err);
}

static void app_on_receive(h2o_webtransport_stream_t *stream, size_t off, const void *src, size_t len)
{
    if (h2o_webtransport_streambuf_ingress_receive(stream, off, src, len) != 0)
        return;

    ptls_iovec_t input = h2o_webtransport_streambuf_ingress_get(stream);
    int is_fin = quicly_recvstate_transfer_complete(&stream->recvstate);
    record("recv(%" PRId64 ",\"%.*s\"%s)", stream->stream_id, (int)input.len, (const char *)input.base, is_fin ? ",fin" : "");

    if (t.echo && h2o_webtransport_stream_has_send_side(stream) && quicly_sendstate_is_open(&stream->sendstate)) {
        if (input.len != 0)
            h2o_webtransport_streambuf_egress_write(stream, input.base, input.len);
        if (is_fin)
            h2o_webtransport_streambuf_egress_shutdown(stream);
    }
    if (!t.hold_input)
        h2o_webtransport_streambuf_ingress_shift(stream, input.len);
}

static void app_on_send_stop(h2o_webtransport_stream_t *stream, quicly_error_t err)
{
    record("stop(%" PRId64 ",%s)", stream->stream_id, error_str(err));
}

static void app_on_receive_reset(h2o_webtransport_stream_t *stream, quicly_error_t err)
{
    record("reset(%" PRId64 ",%s)", stream->stream_id, error_str(err));
}

static const h2o_webtransport_stream_callbacks_t app_stream_callbacks = {
    app_on_destroy,
    h2o_webtransport_streambuf_egress_shift,
    h2o_webtransport_streambuf_egress_emit,
    app_on_send_stop,
    app_on_receive,
    app_on_receive_reset,
};

static quicly_error_t app_on_stream_open(h2o_webtransport_stream_t *stream)
{
    record("open(%" PRId64 ")", stream->stream_id);
    if (h2o_webtransport_streambuf_create(stream, sizeof(h2o_webtransport_streambuf_t)) != 0)
        return PTLS_ERROR_NO_MEMORY;
    stream->callbacks = &app_stream_callbacks;
    return t.open_error;
}

static void app_on_receive_datagram(h2o_webtransport_session_t *session, h2o_iovec_t payload)
{
    record("datagram(\"%.*s\")", (int)payload.len, payload.base);
    if (t.echo)
        h2o_webtransport_send_datagrams(session, &payload, 1);
}

static void app_on_drain(h2o_webtransport_session_t *session)
{
    record("drain");
}

static void app_on_close(h2o_webtransport_session_t *session, quicly_error_t err, h2o_iovec_t reason)
{
    record("close(%s,\"%.*s\")", error_str(err), (int)reason.len, reason.base);
    t.session = NULL;
}

static const h2o_webtransport_session_callbacks_t app_session_callbacks = {app_on_stream_open, app_on_receive_datagram,
                                                                           app_on_drain, app_on_close};

/* fake protocol layer */

static int get_webtransport_settings(h2o_conn_t *conn, h2o_webtransport_settings_t *local, h2o_webtransport_settings_t *remote)
{
    if (t.settings_unavailable)
        return -1;
    *local = t.local;
    *remote = t.remote;
    return 0;
}

static void on_do_send(h2o_ostream_t *self, h2o_req_t *req, h2o_sendvec_t *bufs, size_t bufcnt, h2o_send_state_t state)
{
    assert(!t.proceed_pending && !t.final_sent);

    for (size_t i = 0; i != bufcnt; ++i) {
        size_t len = bufs[i].len;
        h2o_buffer_reserve(&t.out, len);
        if (!bufs[i].callbacks->read_(bufs + i, t.out->bytes + t.out->size, len))
            h2o_fatal("read_ failed");
        t.out->size += len;
    }
    t.send_state = state;
    if (h2o_send_state_is_in_progress(state)) {
        t.proceed_pending = 1;
    } else {
        t.final_sent = 1;
    }
}

static void on_proceed_req(h2o_req_t *req, const char *errstr)
{
    assert(errstr == NULL);
    req->entity = h2o_iovec_init(NULL, 0);
}

static void run_loop(void)
{
    for (int i = 0; i < 10 || t.proceed_pending; ++i) {
        assert(i < 1000);
#if H2O_USE_LIBUV
        uv_run(ctx.loop, UV_RUN_NOWAIT);
#else
        h2o_evloop_run(ctx.loop, 0);
#endif
        if (t.proceed_pending) {
            t.proceed_pending = 0;
            h2o_proceed_response(&t.req);
        }
    }
}

static void setup_request(void)
{
    static const h2o_conn_callbacks_t conn_callbacks = {.get_webtransport_settings = get_webtransport_settings};

    t.conn = h2o_create_connection(sizeof(*t.conn), &ctx, globalconf.hosts, (struct timeval){0}, &conn_callbacks);
    h2o_init_request(&t.req, t.conn, NULL);
    h2o_req_bind_conf(&t.req, globalconf.hosts[0], &globalconf.hosts[0]->fallback_path);
    t.req.method = h2o_iovec_init(H2O_STRLIT("CONNECT"));
    t.req.upgrade = h2o_iovec_init(H2O_STRLIT("webtransport"));
    t.req.is_tunnel_req = 1;
    t.req.entity = h2o_iovec_init("", 0);
    t.req.proceed_req = on_proceed_req;
    t.req._ostr_top = &t.ostr;
    t.ostr = (h2o_ostream_t){.do_send = on_do_send};
    h2o_buffer_init(&t.out, &h2o_socket_buffer_prototype);
}

/**
 * Accepts the session with the given flow control limits (NULL for the defaults).
 */
static void setup(const h2o_webtransport_settings_t *local, const h2o_webtransport_settings_t *remote)
{
    static const h2o_webtransport_settings_t defaults = {
        .max_data = 1000,
        .max_stream_data_uni = 100,
        .max_stream_data_bidi_local = 100,
        .max_stream_data_bidi_remote = 100,
        .max_streams_uni = 2,
        .max_streams_bidi = 2,
    };

    memset(&t, 0, sizeof(t));
    t.local = local != NULL ? *local : defaults;
    t.remote = remote != NULL ? *remote : defaults;
    setup_request();

    t.session = h2o_webtransport_accept(&t.req, &app_session_callbacks, NULL, h2o_iovec_init(NULL, 0));
    ok(t.session != NULL);
    ok(t.req.res.status == 200);
    run_loop();
}

static void teardown(void)
{
    h2o_dispose_request(&t.req);
    h2o_destroy_connection(t.conn);
    h2o_buffer_dispose(&t.out);
}

/**
 * Feeds the bytes as the request body. When `is_end` is set, the request body ends after the bytes.
 */
static void feed(const void *bytes, size_t len, int is_end)
{
    assert(t.req.entity.base == NULL);
    t.req.entity = h2o_iovec_init(bytes, len);
    if (is_end)
        t.req.proceed_req = NULL;
    t.req.write_req.cb(t.req.write_req.ctx, is_end);
    run_loop();
}

static void feed_buffer(h2o_buffer_t **buf, int is_end)
{
    feed((*buf)->bytes, (*buf)->size, is_end);
    h2o_buffer_consume(buf, (*buf)->size);
}

static void build_stream(h2o_buffer_t **buf, uint64_t stream_id, const void *data, size_t len, int is_fin)
{
    uint8_t *dst = (uint8_t *)h2o_buffer_reserve(buf, STREAM_CAPSULE_HEADER_RESERVE + len).base, *p = dst;
    p = h2o_webtransport_encode_capsule_header(p, is_fin ? H2O_WEBTRANSPORT_CAPSULE_STREAM_FIN : H2O_WEBTRANSPORT_CAPSULE_STREAM,
                                               quicly_encodev_capacity(stream_id) + len);
    p = ptls_encode_quicint(p, stream_id);
    memcpy(p, data, len);
    p += len;
    (*buf)->size += p - dst;
}

static void build_varint(h2o_buffer_t **buf, uint64_t type, const uint64_t *fields, size_t num_fields)
{
    h2o_webtransport_encode_varint_capsule(buf, type, fields, num_fields);
}

static void build_datagram(h2o_buffer_t **buf, const char *payload)
{
    size_t len = strlen(payload);
    uint8_t *dst = (uint8_t *)h2o_buffer_reserve(buf, H2O_WEBTRANSPORT_MAX_CAPSULE_HEADER_SIZE + len).base, *p = dst;
    p = h2o_webtransport_encode_capsule_header(p, H2O_WEBTRANSPORT_CAPSULE_DATAGRAM, len);
    memcpy(p, payload, len);
    p += len;
    (*buf)->size += p - dst;
}

static void feed_stream(uint64_t stream_id, const char *data, int is_fin)
{
    h2o_buffer_t *buf;
    h2o_buffer_init(&buf, &h2o_socket_buffer_prototype);
    build_stream(&buf, stream_id, data, strlen(data), is_fin);
    feed_buffer(&buf, 0);
    h2o_buffer_dispose(&buf);
}

static void feed_varint(uint64_t type, const uint64_t *fields, size_t num_fields)
{
    h2o_buffer_t *buf;
    h2o_buffer_init(&buf, &h2o_socket_buffer_prototype);
    build_varint(&buf, type, fields, num_fields);
    feed_buffer(&buf, 0);
    h2o_buffer_dispose(&buf);
}

#define FEED_VARINT(type, ...)                                                                                                     \
    do {                                                                                                                           \
        uint64_t fields_[] = {__VA_ARGS__};                                                                                        \
        feed_varint((type), fields_, PTLS_ELEMENTSOF(fields_));                                                                    \
    } while (0)

/**
 * Returns the capsules sent since the last invocation as a string, consuming them.
 */
static const char *take_output(void)
{
    static const struct {
        uint64_t type;
        const char *name;
        size_t num_fields;
    } varint_capsules[] = {
        {H2O_WEBTRANSPORT_CAPSULE_RESET_STREAM, "reset-stream", 3},
        {H2O_WEBTRANSPORT_CAPSULE_STOP_SENDING, "stop-sending", 2},
        {H2O_WEBTRANSPORT_CAPSULE_MAX_DATA, "max-data", 1},
        {H2O_WEBTRANSPORT_CAPSULE_MAX_STREAM_DATA, "max-stream-data", 2},
        {H2O_WEBTRANSPORT_CAPSULE_MAX_STREAMS_BIDI, "max-streams-bidi", 1},
        {H2O_WEBTRANSPORT_CAPSULE_MAX_STREAMS_UNI, "max-streams-uni", 1},
        {H2O_WEBTRANSPORT_CAPSULE_DATA_BLOCKED, "data-blocked", 1},
        {H2O_WEBTRANSPORT_CAPSULE_STREAM_DATA_BLOCKED, "stream-data-blocked", 2},
        {H2O_WEBTRANSPORT_CAPSULE_STREAMS_BLOCKED_BIDI, "streams-blocked-bidi", 1},
        {H2O_WEBTRANSPORT_CAPSULE_STREAMS_BLOCKED_UNI, "streams-blocked-uni", 1},
    };
    const uint8_t *src = (const uint8_t *)t.out->bytes, *end = src != NULL ? src + t.out->size : src;
    char *dst = t.output, *dst_end = t.output + sizeof(t.output);

#define APPEND(...) dst += snprintf(dst, dst_end - dst, __VA_ARGS__)
    *dst = '\0';
    while (src != end && dst < dst_end - 1) {
        uint64_t type, length;
        if (dst != t.output)
            APPEND(" ");
        if (h2o_webtransport_decode_capsule_header(&src, end, &type, &length) != 0 || (uint64_t)(end - src) < length) {
            APPEND("<broken>");
            break;
        }
        h2o_iovec_t payload = h2o_iovec_init(src, length);
        src += length;
        switch (type) {
        case H2O_WEBTRANSPORT_CAPSULE_STREAM:
        case H2O_WEBTRANSPORT_CAPSULE_STREAM_FIN: {
            const uint8_t *p = (const uint8_t *)payload.base, *payload_end = p + payload.len;
            uint64_t id = ptls_decode_quicint(&p, payload_end);
            APPEND("%s(%" PRIu64 ",\"%.*s\")", type == H2O_WEBTRANSPORT_CAPSULE_STREAM_FIN ? "stream-fin" : "stream", id,
                   (int)(payload_end - p), (const char *)p);
        } break;
        case H2O_WEBTRANSPORT_CAPSULE_DATAGRAM:
            APPEND("datagram(\"%.*s\")", (int)payload.len, payload.base);
            break;
        case H2O_WEBTRANSPORT_CAPSULE_CLOSE_SESSION: {
            uint32_t app_error;
            h2o_iovec_t reason;
            if (h2o_webtransport_decode_close_session(payload, &app_error, &reason) != 0) {
                APPEND("<broken-close>");
            } else {
                APPEND("close(%" PRIu32 ",\"%.*s\")", app_error, (int)reason.len, reason.base);
            }
        } break;
        case H2O_WEBTRANSPORT_CAPSULE_DRAIN_SESSION:
            APPEND("drain");
            break;
        default: {
            size_t i;
            for (i = 0; i != PTLS_ELEMENTSOF(varint_capsules); ++i)
                if (varint_capsules[i].type == type)
                    break;
            uint64_t fields[3];
            if (i == PTLS_ELEMENTSOF(varint_capsules) ||
                h2o_webtransport_decode_varint_capsule(payload, fields, varint_capsules[i].num_fields) != 0) {
                APPEND("<unknown:%" PRIx64 ">", type);
                break;
            }
            APPEND("%s(", varint_capsules[i].name);
            for (size_t j = 0; j != varint_capsules[i].num_fields; ++j)
                APPEND("%s%" PRIu64, j == 0 ? "" : ",", fields[j]);
            APPEND(")");
        } break;
        }
    }
#undef APPEND

    h2o_buffer_consume(&t.out, t.out->size);
    return t.output;
}

static void check_str(const char *file, int line, const char *got, const char *expected)
{
    if (strcmp(got, expected) == 0) {
        _ok(1, "%s %d", file, line);
    } else {
        _ok(0, "%s %d", file, line);
        note("expected: %s", expected);
        note("     got: %s", got);
    }
}

#define check_events(expected) check_str(__FILE__, __LINE__, take_events(), (expected))
#define check_output(expected) check_str(__FILE__, __LINE__, take_output(), (expected))

/* tests */

static void test_echo(void)
{
    setup(NULL, NULL);
    t.echo = 1;
    check_events("");
    check_output("");
    ok(!t.final_sent);

    feed_stream(0, "hello", 1);
    check_events("open(0) recv(0,\"hello\",fin) destroy(0,0)");
    /* half of the window has been used, so the limit is raised */
    check_output("stream-fin(0,\"hello\") max-streams-bidi(3)");

    feed_stream(2, "world", 1);
    check_events("open(2) recv(2,\"world\",fin) destroy(2,0)");
    check_output("max-streams-uni(3)");

    teardown();
    check_events("close(0x2e706,\"\")");
}

static void test_split_input(void)
{
    h2o_buffer_t *buf;
    size_t i;

    setup(NULL, NULL);
    t.echo = 1;

    /* a stream capsule followed by a datagram capsule, fed one byte at a time */
    h2o_buffer_init(&buf, &h2o_socket_buffer_prototype);
    build_stream(&buf, 0, "abc", 3, 1);
    build_datagram(&buf, "dg");
    for (i = 0; i != buf->size; ++i)
        feed(buf->bytes + i, 1, 0);
    h2o_buffer_dispose(&buf);

    check_events("open(0) recv(0,\"a\") recv(0,\"b\") recv(0,\"c\",fin) destroy(0,0) datagram(\"dg\")");
    check_output("stream(0,\"a\") stream(0,\"b\") stream-fin(0,\"c\") max-streams-bidi(3) datagram(\"dg\")");

    teardown();
}

static void test_initial_body(void)
{
    h2o_buffer_t *buf;

    /* capsules that arrive with the request are processed after `h2o_webtransport_accept` returns */
    memset(&t, 0, sizeof(t));
    t.local = t.remote = (h2o_webtransport_settings_t){1000, 100, 100, 100, 2, 2};
    t.echo = 1;
    setup_request();
    h2o_buffer_init(&buf, &h2o_socket_buffer_prototype);
    build_stream(&buf, 0, "early", 5, 1);
    t.req.entity = h2o_iovec_init(buf->bytes, buf->size);

    t.session = h2o_webtransport_accept(&t.req, &app_session_callbacks, NULL, h2o_iovec_init(H2O_STRLIT("proto")));
    ok(t.session != NULL);
    check_events("");
    run_loop();
    check_events("open(0) recv(0,\"early\",fin) destroy(0,0)");
    check_output("stream-fin(0,\"early\") max-streams-bidi(3)");
    ssize_t header_index = h2o_find_header_by_str(&t.req.res.headers, H2O_STRLIT("wt-protocol"), -1);
    ok(header_index != -1);
    if (header_index != -1)
        ok(h2o_memis(t.req.res.headers.entries[header_index].value.base, t.req.res.headers.entries[header_index].value.len,
                     H2O_STRLIT("\"proto\"")));

    h2o_buffer_dispose(&buf);
    teardown();
}

static void test_unavailable(void)
{
    memset(&t, 0, sizeof(t));
    t.settings_unavailable = 1;
    setup_request();

    ok(h2o_webtransport_accept(&t.req, &app_session_callbacks, NULL, h2o_iovec_init(NULL, 0)) == NULL);
    ok(t.req.res.status == 400);
    run_loop();
    ok(t.final_sent);

    teardown();
    check_events("");
}

static void test_implicit_open(void)
{
    setup(NULL, NULL);

    /* opening stream 4 opens stream 0 as well */
    feed_stream(4, "x", 0);
    check_events("open(0) open(4) recv(4,\"x\")");
    /* stream 0 can be used afterwards */
    feed_stream(0, "y", 0);
    check_events("recv(0,\"y\")");
    check_output("");

    teardown();
    check_events("destroy(0,0x2e701) destroy(4,0x2e701) close(0x2e706,\"\")");
}

static void test_open_rejected(void)
{
    setup(NULL, NULL);
    t.open_error = QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(3);

    /* the stream is reset and STOP_SENDING is sent */
    feed_stream(0, "x", 0);
    check_output("reset-stream(0,3,0) stop-sending(0,3)");

    teardown();
}

static void expect_session_error(quicly_error_t err)
{
    char expected[64];
    sprintf(expected, "close(%s,\"\")", error_str(err));
    check_str(__FILE__, __LINE__, take_events(), expected);
    ok(t.final_sent);
    ok(t.send_state == H2O_SEND_STATE_ERROR);
    ok(t.session == NULL);
}

static void test_flow_control_violations(void)
{
    char data[200];
    memset(data, 'a', sizeof(data));

    note("too many bidi streams");
    setup(NULL, NULL);
    feed_stream(8, "x", 0);
    expect_session_error(H2O_WEBTRANSPORT_ERROR_FLOW_CONTROL);
    teardown();

    note("too many uni streams");
    setup(NULL, NULL);
    feed_stream(10, "x", 0);
    expect_session_error(H2O_WEBTRANSPORT_ERROR_FLOW_CONTROL);
    teardown();

    note("stream-level credit exceeded");
    setup(NULL, NULL);
    data[101] = '\0';
    feed_stream(0, data, 0);
    check_events("open(0) destroy(0,0x2e701) close(0x2e704,\"\")");
    ok(t.send_state == H2O_SEND_STATE_ERROR);
    teardown();

    note("session-level credit exceeded");
    setup(&(h2o_webtransport_settings_t){150, 100, 100, 100, 2, 2}, NULL);
    t.hold_input = 1;
    data[100] = '\0';
    feed_stream(0, data, 0);
    data[60] = '\0';
    feed_stream(4, data, 0);
    ok(strstr(take_events(), "close(0x2e704,\"\")") != NULL);
    ok(t.send_state == H2O_SEND_STATE_ERROR);
    teardown();

    note("MAX_DATA decreased");
    setup(NULL, NULL);
    FEED_VARINT(H2O_WEBTRANSPORT_CAPSULE_MAX_DATA, 999);
    expect_session_error(H2O_WEBTRANSPORT_ERROR_FLOW_CONTROL);
    teardown();

    note("MAX_STREAMS decreased");
    setup(NULL, NULL);
    FEED_VARINT(H2O_WEBTRANSPORT_CAPSULE_MAX_STREAMS_UNI, 1);
    expect_session_error(H2O_WEBTRANSPORT_ERROR_FLOW_CONTROL);
    teardown();

    note("MAX_STREAM_DATA decreased");
    setup(NULL, NULL);
    feed_stream(0, "x", 0);
    FEED_VARINT(H2O_WEBTRANSPORT_CAPSULE_MAX_STREAM_DATA, 0, 99);
    check_events("open(0) recv(0,\"x\") destroy(0,0x2e701) close(0x2e704,\"\")");
    teardown();
}

static void test_stream_state_violations(void)
{
    note("data on a server-initiated stream not yet opened");
    setup(NULL, NULL);
    feed_stream(1, "x", 0);
    expect_session_error(H2O_WEBTRANSPORT_ERROR_STREAM_STATE);
    teardown();

    note("STOP_SENDING on a client-initiated unidirectional stream");
    setup(NULL, NULL);
    FEED_VARINT(H2O_WEBTRANSPORT_CAPSULE_STOP_SENDING, 2, 0);
    expect_session_error(H2O_WEBTRANSPORT_ERROR_STREAM_STATE);
    teardown();

    note("data after FIN");
    setup(NULL, NULL);
    feed_stream(2, "x", 1);
    feed_stream(2, "y", 0);
    check_events("open(2) recv(2,\"x\",fin) destroy(2,0) close(0x2e705,\"\")");
    teardown();
}

static void test_reset(void)
{
    setup(NULL, NULL);

    feed_stream(0, "abc", 0);
    FEED_VARINT(H2O_WEBTRANSPORT_CAPSULE_RESET_STREAM, 0, 7, 3);
    check_events("open(0) recv(0,\"abc\") reset(0,app:7)");

    /* the reliable size must be equal to the bytes received */
    feed_stream(4, "abc", 0);
    FEED_VARINT(H2O_WEBTRANSPORT_CAPSULE_RESET_STREAM, 4, 7, 2);
    check_events("open(4) recv(4,\"abc\") destroy(0,0x2e701) destroy(4,0x2e701) close(0x2e705,\"\")");
    ok(t.send_state == H2O_SEND_STATE_ERROR);

    teardown();
}

static void test_stop_sending(void)
{
    setup(NULL, NULL);
    t.echo = 1;

    feed_stream(0, "abc", 0);
    check_events("open(0) recv(0,\"abc\")");
    check_output("stream(0,\"abc\")");

    /* the send side is reset with the bytes sent as the reliable size, then the application is notified */
    FEED_VARINT(H2O_WEBTRANSPORT_CAPSULE_STOP_SENDING, 0, 9);
    check_events("stop(0,app:9)");
    check_output("reset-stream(0,9,3)");

    /* duplicate STOP_SENDING is an error */
    FEED_VARINT(H2O_WEBTRANSPORT_CAPSULE_STOP_SENDING, 0, 9);
    check_events("destroy(0,0x2e701) close(0x2e705,\"\")");
    ok(t.send_state == H2O_SEND_STATE_ERROR);

    teardown();
}

static void test_local_reset_and_stop(void)
{
    h2o_webtransport_stream_t *stream;

    setup(NULL, NULL);

    ok(h2o_webtransport_open_stream(t.session, &stream, 0) == 0);
    check_events("open(1)");
    h2o_webtransport_streambuf_egress_write(stream, "abc", 3);
    run_loop();
    check_output("stream(1,\"abc\")");

    h2o_webtransport_reset_stream(stream, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(5));
    h2o_webtransport_request_stop(stream, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(6));
    run_loop();
    check_output("reset-stream(1,5,3) stop-sending(1,6)");

    /* the peer resets the receive side in response, then the stream is destroyed */
    FEED_VARINT(H2O_WEBTRANSPORT_CAPSULE_RESET_STREAM, 1, 6, 0);
    check_events("reset(1,app:6) destroy(1,0)");

    teardown();
}

static void test_server_streams(void)
{
    h2o_webtransport_stream_t *bidi1, *bidi2, *uni;

    setup(NULL, &(h2o_webtransport_settings_t){1000, 100, 100, 100, 1, 1});

    ok(h2o_webtransport_open_stream(t.session, &bidi1, 0) == 0);
    ok(h2o_webtransport_open_stream(t.session, &uni, 1) == 0);
    ok(h2o_webtransport_open_stream(t.session, &bidi2, 0) == 0);
    check_events("open(1) open(3) open(5)");
    ok(bidi1->stream_id == 1 && uni->stream_id == 3 && bidi2->stream_id == 5);

    h2o_webtransport_streambuf_egress_write(bidi1, "b1", 2);
    h2o_webtransport_streambuf_egress_shutdown(bidi1);
    h2o_webtransport_streambuf_egress_write(uni, "u", 1);
    h2o_webtransport_streambuf_egress_shutdown(uni);
    h2o_webtransport_streambuf_egress_write(bidi2, "b2", 2);
    run_loop();
    /* stream 5 is beyond the limit */
    check_output("streams-blocked-bidi(1) stream-fin(1,\"b1\") stream-fin(3,\"u\")");
    check_events("destroy(3,0)");

    /* raising the limit unblocks stream 5 */
    FEED_VARINT(H2O_WEBTRANSPORT_CAPSULE_MAX_STREAMS_BIDI, 2);
    check_output("stream(5,\"b2\")");

    /* the peer closes stream 1 */
    feed_stream(1, "r", 1);
    check_events("recv(1,\"r\",fin) destroy(1,0)");

    teardown();
}

static void test_send_flow_control(void)
{
    h2o_webtransport_stream_t *stream;

    note("stream-level");
    setup(NULL, &(h2o_webtransport_settings_t){1000, 100, 100, 4, 2, 2});
    ok(h2o_webtransport_open_stream(t.session, &stream, 0) == 0);
    h2o_webtransport_streambuf_egress_write(stream, "abcdefgh", 8);
    run_loop();
    check_output("stream(1,\"abcd\") stream-data-blocked(1,4)");
    FEED_VARINT(H2O_WEBTRANSPORT_CAPSULE_MAX_STREAM_DATA, 1, 8);
    check_output("stream(1,\"efgh\")");
    teardown();

    note("session-level");
    setup(NULL, &(h2o_webtransport_settings_t){3, 100, 100, 100, 2, 2});
    ok(h2o_webtransport_open_stream(t.session, &stream, 0) == 0);
    h2o_webtransport_streambuf_egress_write(stream, "abcdefgh", 8);
    run_loop();
    check_output("stream(1,\"abc\") data-blocked(3)");
    FEED_VARINT(H2O_WEBTRANSPORT_CAPSULE_MAX_DATA, 8);
    check_output("stream(1,\"defgh\")");
    teardown();
}

static void test_credit_update(void)
{
    char data[61];
    memset(data, 'a', 60);
    data[60] = '\0';

    setup(&(h2o_webtransport_settings_t){100, 100, 100, 100, 2, 2}, NULL);

    /* credit is returned once more than half of the window is consumed */
    feed_stream(0, data, 0);
    take_events();
    check_output("max-stream-data(0,160) max-data(160)");

    /* closing streams replenishes the stream count */
    feed_stream(2, "", 1);
    check_events("open(2) recv(2,\"\",fin) destroy(2,0)");
    check_output("max-streams-uni(3)");
    feed_stream(6, "", 1);
    check_events("open(6) recv(6,\"\",fin) destroy(6,0)");
    check_output("max-streams-uni(4)");

    teardown();
}

static void test_datagram(void)
{
    h2o_buffer_t *buf;

    setup(NULL, NULL);
    t.echo = 1;

    h2o_buffer_init(&buf, &h2o_socket_buffer_prototype);
    build_datagram(&buf, "one");
    build_datagram(&buf, "two");
    feed_buffer(&buf, 0);
    h2o_buffer_dispose(&buf);
    check_events("datagram(\"one\") datagram(\"two\")");
    check_output("datagram(\"one\") datagram(\"two\")");

    teardown();
}

static void test_close_by_peer(void)
{
    h2o_buffer_t *buf;

    setup(NULL, NULL);
    feed_stream(0, "x", 0);
    take_events();

    h2o_buffer_init(&buf, &h2o_socket_buffer_prototype);
    h2o_webtransport_encode_close_session(&buf, 42, h2o_iovec_init(H2O_STRLIT("bye")));
    build_datagram(&buf, "ignored");
    feed_buffer(&buf, 0);
    h2o_buffer_dispose(&buf);

    check_events("destroy(0,0x2e701) close(app:42,\"bye\")");
    check_output("");
    ok(t.final_sent);
    ok(t.send_state == H2O_SEND_STATE_FINAL);

    teardown();
    check_events("");
}

static void test_close_by_app(void)
{
    setup(NULL, NULL);
    feed_stream(0, "x", 0);
    take_events();

    h2o_webtransport_close(t.session, 5, h2o_iovec_init(H2O_STRLIT("done")));
    check_events("destroy(0,0x2e701)");
    run_loop();
    check_output("close(5,\"done\")");
    ok(t.final_sent);
    ok(t.send_state == H2O_SEND_STATE_FINAL);

    teardown();
    check_events("");
}

static void test_end_of_stream(void)
{
    note("FIN without WT_CLOSE_SESSION");
    setup(NULL, NULL);
    feed("", 0, 1);
    check_events("close(app:0,\"\")");
    ok(t.final_sent);
    ok(t.send_state == H2O_SEND_STATE_FINAL);
    teardown();

    note("FIN in the middle of a capsule");
    setup(NULL, NULL);
    feed("\x80", 1, 1);
    expect_session_error(H2O_WEBTRANSPORT_ERROR_PROTOCOL);
    teardown();
}

static void test_drain(void)
{
    note("by peer");
    setup(NULL, NULL);
    feed("\x80\x00\x78\xae\x00", 5, 0);
    check_events("drain");
    check_output("");
    teardown();

    note("by app");
    setup(NULL, NULL);
    h2o_webtransport_drain(t.session);
    h2o_webtransport_drain(t.session);
    run_loop();
    check_output("drain");
    check_events("");
    teardown();

    note("server shutdown");
    setup(NULL, NULL);
    h2o_webtransport_notify_shutdown(&t.req);
    h2o_webtransport_notify_shutdown(&t.req);
    run_loop();
    check_output("drain");
    check_events("drain");
    teardown();
}

static void test_unknown_capsules(void)
{
    setup(NULL, NULL);

    /* PADDING and unknown capsules are skipped */
    feed("\x80\x00\x00\x21\x03xyz"
         "\xc0\x00\x00\x00\x19\x0b\x4d\x38\x02pp",
         19, 0);
    check_events("");
    ok(!t.final_sent);

    teardown();
}

void test_lib__core__webtransport_c(void)
{
    h2o_config_init(&globalconf);
    h2o_config_register_host(&globalconf, h2o_iovec_init(H2O_STRLIT("default")), 65535);
    h2o_context_init(&ctx, test_loop, &globalconf);

    subtest("echo", test_echo);
    subtest("split-input", test_split_input);
    subtest("initial-body", test_initial_body);
    subtest("unavailable", test_unavailable);
    subtest("implicit-open", test_implicit_open);
    subtest("open-rejected", test_open_rejected);
    subtest("flow-control-violations", test_flow_control_violations);
    subtest("stream-state-violations", test_stream_state_violations);
    subtest("reset", test_reset);
    subtest("stop-sending", test_stop_sending);
    subtest("local-reset-and-stop", test_local_reset_and_stop);
    subtest("server-streams", test_server_streams);
    subtest("send-flow-control", test_send_flow_control);
    subtest("credit-update", test_credit_update);
    subtest("datagram", test_datagram);
    subtest("close-by-peer", test_close_by_peer);
    subtest("close-by-app", test_close_by_app);
    subtest("end-of-stream", test_end_of_stream);
    subtest("drain", test_drain);
    subtest("unknown-capsules", test_unknown_capsules);

    h2o_context_dispose(&ctx);
    h2o_config_dispose(&globalconf);
}
