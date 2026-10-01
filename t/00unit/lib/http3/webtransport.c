/* Included after reliable-reset.c by the server unit translation unit. The same real TLS/QUIC fixture drives the native
 * WebTransport backend of the HTTP/3 server (draft-ietf-webtrans-http3-16) through an ordinary handler that calls
 * `h2o_webtransport_accept`: the SETTINGS and transport parameter gating, the streams that arrive before their session, the limit
 * of buffered streams, SESSION_GONE, resets received before the stream header, and RESET_STREAM_AT retaining the stream header in
 * both directions. */
#if !H2O_USE_LIBUV

#define WT_ERR(code) QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(code)
#define WT_APP_ERR(code) WT_ERR(h2o_webtransport_h3_error_from_application(code))

static struct {
    unsigned enabled, server_reset_stream_at, client_reset_stream_at;
} wt_config;

/* a stream as seen by the test application; the record outlives the stream */
struct wt_app_stream {
    h2o_webtransport_stream_t *stream; /* NULL once destroyed */
    quicly_stream_id_t id;
    int fin, destroyed;
    quicly_error_t reset_err, stop_err, destroy_err;
    uint8_t data[256];
    size_t len;
};

/* The test application. Records every callback; if `echo` is set, data received on a bidirectional stream opened by the client is
 * echoed back once FIN is received. If `refuse` is set, the session is refused with 403. */
static struct {
    int refuse, echo;
    h2o_webtransport_session_t *session; /* NULL once closed */
    unsigned accepts, closes, drains;
    quicly_error_t close_err;
    struct wt_app_stream streams[16];
    size_t num_streams;
} wt_app;

struct wt_app_streambuf {
    h2o_webtransport_streambuf_t super;
    struct wt_app_stream *rec;
};

static struct wt_app_stream *wt_app_rec(h2o_webtransport_stream_t *stream)
{
    return ((struct wt_app_streambuf *)stream->data)->rec;
}

static void wt_app_on_destroy(h2o_webtransport_stream_t *stream, quicly_error_t err)
{
    struct wt_app_stream *rec = wt_app_rec(stream);
    rec->stream = NULL;
    rec->destroyed = 1;
    rec->destroy_err = err;
    h2o_webtransport_streambuf_destroy(stream, err);
}

static void wt_app_on_send_stop(h2o_webtransport_stream_t *stream, quicly_error_t err)
{
    wt_app_rec(stream)->stop_err = err;
}

static void wt_app_on_receive(h2o_webtransport_stream_t *stream, size_t off, const void *src, size_t len)
{
    struct wt_app_stream *rec = wt_app_rec(stream);
    if (h2o_webtransport_streambuf_ingress_receive(stream, off, src, len) != 0)
        return;
    ptls_iovec_t input = h2o_webtransport_streambuf_ingress_get(stream);
    assert(input.len <= sizeof(rec->data) - rec->len);
    memcpy(rec->data + rec->len, input.base, input.len);
    rec->len += input.len;
    h2o_webtransport_streambuf_ingress_shift(stream, input.len);
    /* a transfer completed by a reset is not FIN; on_receive_reset is called afterwards */
    rec->fin = quicly_recvstate_transfer_complete(&stream->recvstate) && stream->recvstate.app_error_code == UINT64_MAX;
    if (wt_app.echo && rec->fin && h2o_webtransport_stream_has_send_side(stream) && quicly_sendstate_is_open(&stream->sendstate)) {
        assert(h2o_webtransport_streambuf_egress_write(stream, rec->data, rec->len) == 0);
        assert(h2o_webtransport_streambuf_egress_shutdown(stream) == 0);
    }
}

static void wt_app_on_receive_reset(h2o_webtransport_stream_t *stream, quicly_error_t err)
{
    wt_app_rec(stream)->reset_err = err;
}

static const h2o_webtransport_stream_callbacks_t wt_app_stream_callbacks = {wt_app_on_destroy,
                                                                            h2o_webtransport_streambuf_egress_shift,
                                                                            h2o_webtransport_streambuf_egress_emit,
                                                                            wt_app_on_send_stop,
                                                                            wt_app_on_receive,
                                                                            wt_app_on_receive_reset};

static quicly_error_t wt_app_on_stream_open(h2o_webtransport_stream_t *stream)
{
    assert(wt_app.num_streams < PTLS_ELEMENTSOF(wt_app.streams));
    if (h2o_webtransport_streambuf_create(stream, sizeof(struct wt_app_streambuf)) != 0)
        return QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0);
    struct wt_app_stream *rec = wt_app.streams + wt_app.num_streams++;
    *rec = (struct wt_app_stream){.stream = stream, .id = stream->stream_id};
    ((struct wt_app_streambuf *)stream->data)->rec = rec;
    stream->callbacks = &wt_app_stream_callbacks;
    return 0;
}

static void wt_app_on_drain(h2o_webtransport_session_t *session)
{
    ++wt_app.drains;
}

static void wt_app_on_close(h2o_webtransport_session_t *session, quicly_error_t err, h2o_iovec_t reason)
{
    ++wt_app.closes;
    wt_app.close_err = err;
    wt_app.session = NULL;
}

static const h2o_webtransport_session_callbacks_t wt_app_session_callbacks = {wt_app_on_stream_open, NULL, wt_app_on_drain,
                                                                              wt_app_on_close};

static int wt_handler(h2o_handler_t *self, h2o_req_t *req)
{
    if (!h2o_webtransport_is_request(req))
        return rr_handler(self, req);
    if (wt_app.refuse) {
        h2o_send_error_403(req, "Forbidden", "refused", 0);
        return 0;
    }
    if ((wt_app.session = h2o_webtransport_accept(req, &wt_app_session_callbacks, NULL, h2o_iovec_init(NULL, 0))) != NULL)
        ++wt_app.accepts;
    return 0;
}

static void wt_client_datagram(quicly_receive_datagram_frame_t *self, quicly_conn_t *conn, ptls_iovec_t payload)
{
}
static quicly_receive_datagram_frame_t wt_client_datagram_cb = {wt_client_datagram};

static void wt_amend(struct rr_fixture *f)
{
    /* H3 DATAGRAM, required by WebTransport, can be advertised only by an endpoint accepting DATAGRAM frames */
    f->qc.transport_params.max_datagram_frame_size = 1500;
    f->qc.receive_datagram_frame = &wt_client_datagram_cb;
    f->conf.webtransport.enabled = wt_config.enabled;
    f->qs.transport_params.reset_stream_at = wt_config.server_reset_stream_at;
    f->qc.transport_params.reset_stream_at = wt_config.client_reset_stream_at;
    f->conf.hosts[0]->paths.entries[0]->handlers.entries[0]->on_req = wt_handler;
}

static struct rr_fixture *wt_setup(unsigned enabled, unsigned server_reset_stream_at, unsigned client_reset_stream_at)
{
    memset(&wt_app, 0, sizeof(wt_app));
    wt_config.enabled = enabled;
    wt_config.server_reset_stream_at = server_reset_stream_at;
    wt_config.client_reset_stream_at = client_reset_stream_at;
    return rr_setup_with(wt_amend);
}

/* Steps the connection and runs the event loop, which invokes the callbacks that the core defers; stops once the server closes, so
 * that the close is observed on the wire. */
static void wt_steps(struct rr_fixture *f)
{
    for (unsigned i = 0; i != 8 && quicly_get_state(f->server->h3.super.quic) == QUICLY_STATE_CONNECTED; ++i) {
        rr_step(f);
        h2o_evloop_run(f->loop, 0);
    }
}

/* Finds the value of `id` in the server's SETTINGS frame as received by the client. Returns UINT64_MAX when absent. */
static uint64_t wt_server_setting(struct rr_fixture *f, uint64_t id)
{
    for (struct rr_client_stream *s = f->streams; s != NULL; s = s->next) {
        const uint8_t *src = s->super.ingress.base, *end = src + s->super.ingress.off;
        uint64_t v;
        if (src == end || (v = quicly_decodev(&src, end)) != H2O_HTTP3_STREAM_TYPE_CONTROL)
            continue;
        if ((v = quicly_decodev(&src, end)) != H2O_HTTP3_FRAME_TYPE_SETTINGS || (v = quicly_decodev(&src, end)) == UINT64_MAX ||
            v > (uint64_t)(end - src)) {
            ok(!"malformed server control stream");
            return UINT64_MAX;
        }
        end = src + v;
        while (src != end) {
            uint64_t sid = quicly_decodev(&src, end), value = quicly_decodev(&src, end);
            if (sid == UINT64_MAX || value == UINT64_MAX) {
                ok(!"malformed server SETTINGS");
                return UINT64_MAX;
            }
            if (sid == id)
                return value;
        }
        return UINT64_MAX;
    }
    ok(!"no server control stream");
    return UINT64_MAX;
}

#define WT_SETTING_BYTES 0xac, 0x7c, 0xf0, 0x00 /* SETTINGS_WT_ENABLED (0x2c7cf000) as a four-byte varint */

/* Sends a client control stream carrying one SETTINGS frame with the given payload. */
static void wt_send_settings(struct rr_fixture *f, const uint8_t *payload, size_t len)
{
    uint8_t bytes[64] = {H2O_HTTP3_STREAM_TYPE_CONTROL, H2O_HTTP3_FRAME_TYPE_SETTINGS, (uint8_t)len};
    assert(len + 3 <= sizeof(bytes));
    memcpy(bytes + 3, payload, len);
    rr_write(f, 1, bytes, len + 3);
    wt_steps(f);
    ok(h2o_http3_has_received_settings(&f->server->h3));
}

static void wt_send_complete_settings(struct rr_fixture *f)
{
    static const uint8_t complete[] = {H2O_HTTP3_SETTINGS_H3_DATAGRAM, 1, WT_SETTING_BYTES, 1};
    wt_send_settings(f, complete, sizeof(complete));
}

static void wt_append(uint8_t **p, const uint8_t *end, const void *src, size_t len)
{
    assert(len <= (size_t)(end - *p));
    memcpy(*p, src, len);
    *p += len;
}

/* QPACK string with a 7-bit length prefix (H=0), or a literal name with its 3-bit prefix */
static void wt_append_string(uint8_t **p, const uint8_t *end, uint8_t first, unsigned prefix_bits, const char *str)
{
    size_t len = strlen(str), max = ((size_t)1 << prefix_bits) - 1;
    assert(len < max + 128 && end - *p >= 2);
    if (len < max) {
        *(*p)++ = first | (uint8_t)len;
    } else {
        *(*p)++ = first | (uint8_t)max;
        *(*p)++ = (uint8_t)(len - max);
    }
    wt_append(p, end, str, len);
}

/* Sends an extended CONNECT request for webtransport-h3 without FIN, as a WebTransport client would, and steps the connection.
 * quicly may retire the stream while stepping (e.g., after an error response); the fixture record outlives it. */
static struct rr_client_stream *wt_connect(struct rr_fixture *f)
{
    uint8_t fields[256], *p = fields, *end = fields + sizeof(fields);
    *p++ = 0;         /* required insert count */
    *p++ = 0;         /* base */
    *p++ = 0xc0 | 15; /* :method CONNECT */
    *p++ = 0xc0 | 23; /* :scheme https */
    *p++ = 0x51;      /* :path, literal value with static name reference */
    wt_append_string(&p, end, 0, 7, "/wt");
    *p++ = 0x50; /* :authority */
    wt_append_string(&p, end, 0, 7, "localhost");
    wt_append_string(&p, end, 0x20, 3, ":protocol");
    wt_append_string(&p, end, 0, 7, "webtransport-h3");
    uint8_t frame[sizeof(fields) + 8], *q = frame;
    *q++ = H2O_HTTP3_FRAME_TYPE_HEADERS;
    q = quicly_encodev(q, (uint64_t)(p - fields));
    memcpy(q, fields, p - fields);
    q += p - fields;
    struct rr_client_stream *s = rr_write(f, 0, frame, q - frame)->data;
    wt_steps(f);
    return s;
}

/* returns the :status of the response received on `s`, or -1 */
static int wt_response_status(struct rr_client_stream *s)
{
    const uint8_t *src = s->super.ingress.base, *end = src + s->super.ingress.off;
    h2o_http3_read_frame_t frame;
    const char *err_desc = NULL;
    if (h2o_http3_read_frame(&frame, 1, H2O_HTTP3_STREAM_TYPE_REQUEST, 16384, &src, end, &err_desc) != 0 ||
        frame.type != H2O_HTTP3_FRAME_TYPE_HEADERS)
        return -1;
    h2o_mem_pool_t pool;
    h2o_mem_init_pool(&pool);
    h2o_qpack_decoder_t *dec = h2o_qpack_create_decoder(0, 0);
    h2o_headers_t headers = {NULL};
    h2o_iovec_t datagram_flow_id = {NULL};
    h2o_qpack_section_stats_t stats = {0};
    uint64_t blocked_ref = 0;
    uint8_t ack[H2O_HPACK_ENCODE_INT_MAX_LENGTH];
    size_t ack_len;
    int status = -1;
    if (h2o_qpack_parse_response(&pool, dec, 0, &status, &headers, &datagram_flow_id, 0, &blocked_ref, &stats, ack, &ack_len,
                                 frame.payload, frame.length, &err_desc) != 0)
        status = -1;
    h2o_qpack_destroy_decoder(dec);
    h2o_mem_clear_pool(&pool);
    return status;
}

/* opens a session, checking the 2xx */
static struct rr_client_stream *wt_open_session(struct rr_fixture *f)
{
    struct rr_client_stream *s = wt_connect(f);
    ok(wt_response_status(s) == 200);
    ok(!s->fin);
    ok(s->reset_err == 0);
    ok(wt_app.accepts == 1);
    ok(wt_app.session != NULL);
    ok(f->server->wt.session == wt_app.session);
    return s;
}

static size_t wt_header_len(int uni, uint64_t session_id)
{
    uint8_t buf[16];
    return h2o_webtransport_encode_stream_prefix(buf, uni ? H2O_WEBTRANSPORT_H3_STREAM_TYPE_UNI : H2O_WEBTRANSPORT_H3_SIGNAL_BIDI,
                                                 session_id) -
           buf;
}

/* Opens a client WT stream carrying the stream header for `session_id` and `payload`, then FIN if requested. The stream is not
 * stepped; the returned stream is valid only while it is open. */
static quicly_stream_t *wt_write_stream(struct rr_fixture *f, int uni, uint64_t session_id, const char *payload, int fin)
{
    uint8_t buf[128], *p = h2o_webtransport_encode_stream_prefix(
                          buf, uni ? H2O_WEBTRANSPORT_H3_STREAM_TYPE_UNI : H2O_WEBTRANSPORT_H3_SIGNAL_BIDI, session_id);
    assert(strlen(payload) <= sizeof(buf) - (p - buf));
    memcpy(p, payload, strlen(payload));
    p += strlen(payload);
    quicly_stream_t *qs = rr_write(f, uni, buf, p - buf);
    if (fin)
        assert(quicly_streambuf_egress_shutdown(qs) == 0);
    return qs;
}

static struct rr_client_stream *wt_open_stream(struct rr_fixture *f, int uni, uint64_t session_id, const char *payload, int fin)
{
    struct rr_client_stream *s = wt_write_stream(f, uni, session_id, payload, fin)->data;
    wt_steps(f);
    return s;
}

static struct wt_app_stream *wt_app_find(quicly_stream_id_t id)
{
    for (size_t i = 0; i != wt_app.num_streams; ++i)
        if (wt_app.streams[i].id == id)
            return wt_app.streams + i;
    return NULL;
}

static int wt_app_received(struct wt_app_stream *rec, const char *data, int fin)
{
    if (rec == NULL)
        return 0;
    printf("# app stream %" PRId64 ": %zu bytes, fin %d, reset 0x%" PRIx64 ", destroyed %d\n", rec->id, rec->len, rec->fin,
           (uint64_t)rec->reset_err, rec->destroyed);
    return rec->len == strlen(data) && memcmp(rec->data, data, rec->len) == 0 && rec->fin == fin;
}

static int wt_client_received(struct rr_client_stream *s, const void *data, size_t len, int fin)
{
    printf("# client stream %" PRId64 ": %zu bytes, fin %d, reset 0x%" PRIx64 "\n", s->id, s->super.ingress.off, s->fin,
           s->reset_err == 0 ? 0 : (uint64_t)QUICLY_ERROR_GET_ERROR_CODE(s->reset_err));
    return s->super.ingress.off == len && memcmp(s->super.ingress.base, data, len) == 0 && s->fin == fin;
}

static struct rr_client_stream *wt_client_stream(struct rr_fixture *f, quicly_stream_id_t id)
{
    for (struct rr_client_stream *s = f->streams; s != NULL; s = s->next)
        if (s->id == id)
            return s;
    return NULL;
}

static void wt_check_alive(struct rr_fixture *f)
{
    ok(quicly_get_state(f->server->h3.super.quic) == QUICLY_STATE_CONNECTED);
    ok(quicly_get_state(f->client) == QUICLY_STATE_CONNECTED);
}

/* SETTINGS_WT_ENABLED is advertised only when WebTransport is enabled and the server offers reset_stream_at; a CONNECT request is
 * admitted only if the client advertised SETTINGS_WT_ENABLED, H3 DATAGRAM and reset_stream_at. */
static void test_h3_webtransport_gating(void)
{
    static const uint8_t no_wt[] = {H2O_HTTP3_SETTINGS_H3_DATAGRAM, 1}, no_datagram[] = {WT_SETTING_BYTES, 1};
    struct rr_fixture *f;

    /* enabled */
    f = wt_setup(1, 1, 1);
    ok(f->server->h3.local_settings.wt_enabled);
    ok(wt_server_setting(f, H2O_WEBTRANSPORT_H3_SETTINGS_WT_ENABLED) == 1);
    ok(wt_server_setting(f, H2O_HTTP3_SETTINGS_H3_DATAGRAM) == 1);
    rr_dispose(f);

    /* disabled, or enabled without reset_stream_at on the server */
    for (unsigned i = 0; i != 2; ++i) {
        f = wt_setup(i, !i, 1);
        ok(!f->server->h3.local_settings.wt_enabled);
        ok(wt_server_setting(f, H2O_WEBTRANSPORT_H3_SETTINGS_WT_ENABLED) == UINT64_MAX);
        rr_dispose(f);
    }

    /* the client lacks reset_stream_at, SETTINGS_WT_ENABLED or H3 DATAGRAM */
    for (unsigned i = 0; i != 3; ++i) {
        f = wt_setup(1, 1, i != 0);
        switch (i) {
        case 0:
            wt_send_complete_settings(f);
            break;
        case 1:
            wt_send_settings(f, no_wt, sizeof(no_wt));
            break;
        case 2:
            wt_send_settings(f, no_datagram, sizeof(no_datagram));
            break;
        }
        struct rr_client_stream *s = wt_connect(f);
        printf("# client lacking requirement %u: status %d\n", i, wt_response_status(s));
        ok(wt_response_status(s) == 400);
        ok(s->fin);
        ok(wt_app.accepts == 0);
        wt_check_alive(f);
        rr_check_get(f);
        rr_dispose(f);
    }
}

/* streams sent before the CONNECT request are buffered up to WT_MAX_PENDING_STREAMS, then delivered once the session is accepted */
static void test_h3_webtransport_early_streams(void)
{
    struct rr_fixture *f = wt_setup(1, 1, 1);
    wt_send_complete_settings(f);

    /* the server allows 10 unidirectional streams, one being the control stream; the CONNECT stream will be stream 0 */
    struct rr_client_stream *early[9];
    for (size_t i = 0; i != PTLS_ELEMENTSOF(early); ++i) {
        char payload[16];
        sprintf(payload, "early%zu", i);
        early[i] = wt_open_stream(f, 1, 0, payload, 0); /* without FIN, as STOP_SENDING is not sent once all data is received */
    }
    ok(f->server->wt.num_pending == WT_MAX_PENDING_STREAMS);
    ok(wt_app.num_streams == 0);
    /* the stream exceeding the limit is rejected */
    for (size_t i = 0; i != PTLS_ELEMENTSOF(early); ++i)
        ok((early[i]->stop_err == WT_ERR(H2O_WEBTRANSPORT_H3_ERROR_BUFFERED_STREAM_REJECTED)) == (i == WT_MAX_PENDING_STREAMS));
    wt_check_alive(f);

    ok(wt_open_session(f)->id == 0);
    ok(f->server->wt.num_pending == 0);
    ok(wt_app.num_streams == WT_MAX_PENDING_STREAMS);
    for (size_t i = 0; i != WT_MAX_PENDING_STREAMS; ++i) {
        char payload[16];
        sprintf(payload, "early%zu", i);
        ok(wt_app_received(wt_app_find(early[i]->id), payload, 0));
    }

    /* streams sent after the session is accepted are delivered immediately */
    wt_app.echo = 1;
    struct rr_client_stream *bidi = wt_open_stream(f, 0, 0, "hello", 1);
    ok(wt_app_received(wt_app_find(bidi->id), "hello", 1));
    ok(wt_client_received(bidi, "hello", 5, 1));
    wt_check_alive(f);

    rr_dispose(f);
}

/* the buffered streams are rejected with SESSION_GONE when the CONNECT request is refused, as are the streams that arrive later */
static void test_h3_webtransport_refused(void)
{
    struct rr_fixture *f = wt_setup(1, 1, 1);
    wt_send_complete_settings(f);
    wt_app.refuse = 1;

    struct rr_client_stream *early = wt_open_stream(f, 1, 0, "early", 0);
    ok(f->server->wt.num_pending == 1);
    struct rr_client_stream *s = wt_connect(f);
    ok(wt_response_status(s) == 403);
    ok(s->fin);
    ok(wt_app.accepts == 0);
    ok(f->server->wt.num_pending == 0);
    ok(early->stop_err == WT_ERR(H2O_WEBTRANSPORT_H3_ERROR_SESSION_GONE));

    struct rr_client_stream *late = wt_open_stream(f, 0, 0, "late", 0);
    ok(late->stop_err == WT_ERR(H2O_WEBTRANSPORT_H3_ERROR_SESSION_GONE));
    ok(late->reset_err == WT_ERR(H2O_WEBTRANSPORT_H3_ERROR_SESSION_GONE));
    ok(f->server->wt.num_pending == 0);
    ok(wt_app.num_streams == 0);
    wt_check_alive(f);
    rr_check_get(f);

    rr_dispose(f);
}

/* when the application closes the session, the streams are destroyed and reset with SESSION_GONE, as are the streams that arrive
 * later */
static void test_h3_webtransport_session_gone(void)
{
    struct rr_fixture *f = wt_setup(1, 1, 1);
    wt_send_complete_settings(f);
    struct rr_client_stream *connect = wt_open_session(f);

    struct rr_client_stream *bidi = wt_open_stream(f, 0, 0, "open", 0);
    struct wt_app_stream *rec = wt_app_find(bidi->id);
    ok(wt_app_received(rec, "open", 0));

    h2o_webtransport_close(wt_app.session, 7, h2o_iovec_init(H2O_STRLIT("bye")));
    wt_app.session = NULL;
    ok(rec->destroyed);
    ok(rec->destroy_err == H2O_WEBTRANSPORT_ERROR_SESSION_GONE);
    ok(wt_app.closes == 0); /* not invoked when the application closes the session */
    wt_steps(f);
    ok(bidi->stop_err == WT_ERR(H2O_WEBTRANSPORT_H3_ERROR_SESSION_GONE));
    ok(bidi->reset_err == WT_ERR(H2O_WEBTRANSPORT_H3_ERROR_SESSION_GONE));
    ok(connect->fin);
    ok(f->server->wt.session == NULL);

    struct rr_client_stream *late = wt_open_stream(f, 1, 0, "late", 0);
    ok(late->stop_err == WT_ERR(H2O_WEBTRANSPORT_H3_ERROR_SESSION_GONE));
    ok(f->server->wt.num_pending == 0);
    ok(wt_app.num_streams == 1);
    wt_check_alive(f);

    rr_dispose(f);
}

/* streams reset before their header is complete are discarded without involving the application */
static void test_h3_webtransport_reset_before_header(void)
{
    struct rr_fixture *f = wt_setup(1, 1, 1);
    wt_send_complete_settings(f);
    wt_open_session(f);

    for (int uni = 0; uni != 2; ++uni) {
        /* nothing sent */
        quicly_stream_t *qs;
        assert(quicly_open_stream(f->client, &qs, uni) == 0);
        quicly_reset_stream(qs, WT_APP_ERR(1));
        wt_steps(f);
        wt_check_alive(f);
        /* only the stream type (or the WT_STREAM signal), delivered reliably */
        uint8_t type = uni ? H2O_WEBTRANSPORT_H3_STREAM_TYPE_UNI : H2O_WEBTRANSPORT_H3_SIGNAL_BIDI;
        qs = rr_write(f, uni, &type, 1);
        rr_reset_at(qs, WT_APP_ERR(2), 1);
        wt_steps(f);
        wt_check_alive(f);
    }
    ok(wt_app.num_streams == 0);
    ok(f->server->wt.num_pending == 0);

    /* the session remains usable */
    wt_app.echo = 1;
    struct rr_client_stream *bidi = wt_open_stream(f, 0, 0, "after", 1);
    ok(wt_app_received(wt_app_find(bidi->id), "after", 1));
    ok(wt_client_received(bidi, "after", 5, 1));

    rr_dispose(f);
}

/* RESET_STREAM_AT retains the stream header (and the bytes before Reliable Size) in both directions */
static void test_h3_webtransport_reliable_reset(void)
{
    struct rr_fixture *f = wt_setup(1, 1, 1);
    wt_send_complete_settings(f);
    wt_open_session(f);

    /* client resets with Reliable Size covering the header and "abc": the application receives "abc", then the reset */
    for (int uni = 0; uni != 2; ++uni) {
        quicly_stream_t *qs = wt_write_stream(f, uni, 0, "abcdef", 0);
        quicly_stream_id_t id = qs->stream_id;
        rr_reset_at(qs, WT_APP_ERR(5), wt_header_len(uni, 0) + 3);
        wt_steps(f);
        struct wt_app_stream *rec = wt_app_find(id);
        ok(wt_app_received(rec, "abc", 0));
        ok(rec != NULL && rec->reset_err == WT_ERR(5));
        wt_check_alive(f);
    }

    /* the application resets a stream before anything is sent: the header is delivered before the reset */
    h2o_webtransport_stream_t *stream;
    ok(h2o_webtransport_open_stream(wt_app.session, &stream, 1) == 0);
    quicly_stream_id_t id = stream->stream_id;
    ok(h2o_webtransport_streambuf_egress_write(stream, "lost", 4) == 0);
    h2o_webtransport_reset_stream(stream, WT_ERR(9));
    wt_steps(f);
    struct rr_client_stream *s = wt_client_stream(f, id);
    ok(s != NULL);
    if (s != NULL) {
        uint8_t hdr[16];
        size_t hdr_len = h2o_webtransport_encode_stream_prefix(hdr, H2O_WEBTRANSPORT_H3_STREAM_TYPE_UNI, 0) - hdr;
        ok(wt_client_received(s, hdr, hdr_len, 0));
        ok(s->reset_err == WT_APP_ERR(9));
    }

    /* a server-initiated stream that is sent completely */
    ok(h2o_webtransport_open_stream(wt_app.session, &stream, 1) == 0);
    id = stream->stream_id;
    ok(h2o_webtransport_streambuf_egress_write(stream, "srv", 3) == 0);
    ok(h2o_webtransport_streambuf_egress_shutdown(stream) == 0);
    wt_steps(f);
    if ((s = wt_client_stream(f, id)) != NULL) {
        uint8_t expected[16], *p = h2o_webtransport_encode_stream_prefix(expected, H2O_WEBTRANSPORT_H3_STREAM_TYPE_UNI, 0);
        memcpy(p, "srv", 3);
        ok(wt_client_received(s, expected, p + 3 - expected, 1));
    } else {
        ok(!"server-initiated stream not received");
    }
    wt_check_alive(f);

    rr_dispose(f);
}

static void test_h3_webtransport(void)
{
    subtest("gating", test_h3_webtransport_gating);
    subtest("early streams", test_h3_webtransport_early_streams);
    subtest("refused", test_h3_webtransport_refused);
    subtest("session gone", test_h3_webtransport_session_gone);
    subtest("reset before header", test_h3_webtransport_reset_before_header);
    subtest("reliable reset", test_h3_webtransport_reliable_reset);
}

#else
static void test_h3_webtransport(void)
{
    printf("# WebTransport fixture requires the native event loop\n");
}
#endif
