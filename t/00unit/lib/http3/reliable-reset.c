/* Included by the server unit translation unit to inspect ownership as well as wire results.
 * Real TLS/QUIC connections and h2o_http3_server_accept, production H3 parsing/scheduling/teardown.
 * Only this fixture advertises reset_stream_at. Packets are held/reordered deterministically;
 * the accept-time server flight uses loopback UDP. This is not browser or standalone-server coverage. */
#include <openssl/x509v3.h>
#include "picotls/openssl.h"
#include "quicly/defaults.h"
#include "quicly/streambuf.h"

#if !H2O_USE_LIBUV
struct rr_client_stream {
    quicly_streambuf_t super;
    struct rr_client_stream *next;
    quicly_stream_id_t id;
    int fin, destroyed;
    quicly_error_t reset_err; /* 0 until the peer resets the receive side */
    quicly_error_t stop_err;  /* 0 until the peer asks to stop sending; quicly then resets the send side */
};

struct rr_fixture {
    h2o_globalconf_t conf;
    h2o_context_t ctx;
    h2o_loop_t *loop;
    h2o_accept_ctx_t accept;
    h2o_http3_server_ctx_t server_ctx;
    struct st_h2o_http3_server_conn_t *server;
    quicly_conn_t *client;
    quicly_context_t qc, qs;
    ptls_context_t tc, ts;
    ptls_openssl_sign_certificate_t signer;
    ptls_openssl_verify_certificate_t verifier;
    ptls_iovec_t cert;
    ptls_handshake_properties_t properties;
    quicly_cid_plaintext_t cid;
    quicly_address_t ca, sa;
    int fd;
    struct rr_client_stream *streams;
};

struct rr_packets {
    struct iovec packets[16];
    uint8_t bytes[16 * 1500];
    size_t count;
};

static int64_t rr_clock;
static void rr_now(quicly_now_t *self, double *now)
{
    *now = rr_clock;
}
static quicly_now_t rr_now_cb = {rr_now};

static int rr_hello(ptls_on_client_hello_t *self, ptls_t *tls, ptls_on_client_hello_parameters_t *params)
{
    for (size_t i = 0; i != params->negotiated_protocols.count; ++i)
        if (h2o_memis(params->negotiated_protocols.list[i].base, params->negotiated_protocols.list[i].len, H2O_STRLIT("h3")))
            return ptls_set_negotiated_protocol(tls, H2O_STRLIT("h3"));
    return PTLS_ALERT_NO_APPLICATION_PROTOCOL;
}
static ptls_on_client_hello_t rr_hello_cb = {rr_hello};

static void rr_receive(quicly_stream_t *qs, size_t off, const void *src, size_t len)
{
    assert(quicly_streambuf_ingress_receive(qs, off, src, len) == 0);
    /* a transfer completed by a reset is not FIN; rr_receive_reset is called afterwards */
    ((struct rr_client_stream *)qs->data)->fin =
        quicly_recvstate_transfer_complete(&qs->recvstate) && qs->recvstate.app_error_code == UINT64_MAX;
}

static void rr_destroy(quicly_stream_t *qs, quicly_error_t err)
{
    ((struct rr_client_stream *)qs->data)->destroyed = 1; /* fixture retains the received result through transport retirement */
}

static void rr_receive_reset(quicly_stream_t *qs, quicly_error_t err)
{
    ((struct rr_client_stream *)qs->data)->reset_err = err;
}

static void rr_send_stop(quicly_stream_t *qs, quicly_error_t err)
{
    ((struct rr_client_stream *)qs->data)->stop_err = err;
}

static quicly_error_t rr_open(quicly_stream_open_t *self, quicly_stream_t *qs)
{
    static const quicly_stream_callbacks_t callbacks = {
        rr_destroy, quicly_streambuf_egress_shift, quicly_streambuf_egress_emit, rr_send_stop, rr_receive, rr_receive_reset};
    assert(quicly_streambuf_create(qs, sizeof(struct rr_client_stream)) == 0);
    struct rr_fixture *f = *quicly_get_data(qs->conn);
    struct rr_client_stream *s = qs->data;
    s->next = f->streams;
    s->id = qs->stream_id;
    s->fin = s->destroyed = 0;
    s->reset_err = s->stop_err = 0;
    f->streams = s;
    qs->callbacks = &callbacks;
    return 0;
}
static quicly_stream_open_t rr_open_cb = {rr_open};

/* Production always installs a generator (src/main.c); h2o's scheduler requests a token once 200 KB have been sent. The client has
 * no save_resumption_token callback, so an opaque token is enough. */
static quicly_error_t rr_generate_token(quicly_generate_resumption_token_t *self, quicly_conn_t *conn, ptls_buffer_t *buf,
                                        quicly_address_token_plaintext_t *token)
{
    int ret;
    ptls_buffer_pushv(buf, "rr-token", 8);
Exit:
    return ret;
}
static quicly_generate_resumption_token_t rr_generate_token_cb = {rr_generate_token};

static unsigned rr_handler_calls;

static int rr_handler(h2o_handler_t *self, h2o_req_t *req)
{
    ++rr_handler_calls;
    req->res.status = 200;
    req->res.reason = "OK";
    h2o_send_inline(req, H2O_STRLIT("alive-after-reset"));
    return 0;
}

static void rr_certificate(struct rr_fixture *f)
{
    EVP_PKEY_CTX *keygen = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    EVP_PKEY *key = NULL;
    assert(keygen != NULL && EVP_PKEY_keygen_init(keygen) == 1);
    assert(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(keygen, NID_X9_62_prime256v1) == 1);
    assert(EVP_PKEY_keygen(keygen, &key) == 1);
    EVP_PKEY_CTX_free(keygen);
    /* OpenSSL 1.0.2 otherwise encodes explicit curve parameters, which TLS 1.3 peers cannot map to secp256r1 */
    EC_KEY *eckey = EVP_PKEY_get1_EC_KEY(key);
    assert(eckey != NULL);
    EC_KEY_set_asn1_flag(eckey, OPENSSL_EC_NAMED_CURVE);
    EC_KEY_free(eckey);
    X509 *cert = X509_new();
    assert(cert != NULL && X509_set_version(cert, 2) == 1);
    assert(ASN1_INTEGER_set(X509_get_serialNumber(cert), 1) == 1);
    assert(X509_gmtime_adj(X509_get_notBefore(cert), -60) != NULL);
    assert(X509_gmtime_adj(X509_get_notAfter(cert), 3600) != NULL);
    assert(X509_set_pubkey(cert, key) == 1);
    X509_NAME *name = X509_get_subject_name(cert);
    assert(X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char *)"localhost", -1, -1, 0) == 1);
    assert(X509_set_issuer_name(cert, name) == 1);
    X509_EXTENSION *san = X509V3_EXT_conf_nid(NULL, NULL, NID_subject_alt_name, "DNS:localhost");
    assert(san != NULL && X509_add_ext(cert, san, -1) == 1);
    X509_EXTENSION_free(san);
    assert(X509_sign(cert, key, EVP_sha256()) > 0);
    unsigned char *der = NULL;
    int len = i2d_X509(cert, &der);
    assert(len > 0);
    f->cert = ptls_iovec_init(der, len);
    assert(ptls_openssl_init_sign_certificate(&f->signer, key) == 0);
    EVP_PKEY_free(key);
    X509_STORE *store = X509_STORE_new();
    assert(store != NULL && X509_STORE_add_cert(store, cert) == 1);
    assert(ptls_openssl_init_verify_certificate(&f->verifier, store) == 0);
    X509_STORE_free(store);
    X509_free(cert);
}

static void rr_deliver(struct rr_fixture *f, int to_server, struct rr_packets *batch)
{
    for (size_t i = 0; i != batch->count; ++i) {
        size_t off = 0;
        while (off < batch->packets[i].iov_len) {
            quicly_decoded_packet_t packet;
            quicly_context_t *ctx = to_server ? &f->qs : &f->qc;
            assert(quicly_decode_packet(ctx, &packet, batch->packets[i].iov_base, batch->packets[i].iov_len, &off) != SIZE_MAX);
            if (to_server && f->server == NULL) {
                h2o_http3_conn_t *h3 =
                    h2o_http3_server_accept(&f->server_ctx, &f->sa, &f->ca, &packet, NULL, &H2O_HTTP3_CONN_CALLBACKS);
                assert(h3 != NULL && h3 != &h2o_http3_accept_conn_closed && h3 != (void *)&h2o_quic_accept_conn_decryption_failed);
                f->server = H2O_STRUCT_FROM_MEMBER(struct st_h2o_http3_server_conn_t, h3, h3);
            } else {
                quicly_error_t ret = quicly_receive(to_server ? f->server->h3.super.quic : f->client, to_server ? &f->sa.sa : NULL,
                                                    to_server ? &f->ca.sa : &f->sa.sa, &packet);
                assert(ret == 0 || ret == QUICLY_ERROR_PACKET_IGNORED || ret == QUICLY_ERROR_IS_CLOSING);
            }
        }
    }
    /* as h2o_quic_receive does after each batch */
    if (to_server && f->server != NULL)
        h2o_quic_schedule_timer(&f->server->h3.super);
}

static void rr_collect(quicly_conn_t *conn, struct rr_packets *batch)
{
    quicly_address_t dest, src;
    batch->count = PTLS_ELEMENTSOF(batch->packets);
    quicly_error_t ret = quicly_send(conn, &dest, &src, batch->packets, &batch->count, batch->bytes, sizeof(batch->bytes));
    /* The owner, not quicly_send, frees the connection. Sending CONNECTION_CLOSE does destroy its streams, however. */
    assert(ret == 0 || (ret == QUICLY_ERROR_FREE_CONNECTION && batch->count == 0 && quicly_num_streams(conn) == 0));
}

static void rr_step(struct rr_fixture *f)
{
    struct rr_packets batch;
    rr_collect(f->client, &batch);
    rr_deliver(f, 1, &batch);
    /* quicly measures RTT in fractions of a millisecond; with a zero sample, the handshake would time out immediately */
    rr_clock += 5;
    if (f->server != NULL) {
        /* server_accept writes its first flight through the actual loopback socket */
        ssize_t len;
        while ((len = recv(f->fd, batch.bytes, sizeof(batch.bytes), MSG_DONTWAIT)) > 0) {
            batch.packets[0] = (struct iovec){batch.bytes, (size_t)len};
            batch.count = 1;
            rr_deliver(f, 0, &batch);
        }
        assert(errno == EAGAIN || errno == EWOULDBLOCK);
        if (h2o_timer_is_linked(&f->server->timeout)) {
            h2o_timer_unlink(&f->server->timeout);
            run_delayed(&f->server->timeout);
        }
        rr_collect(f->server->h3.super.quic, &batch);
        rr_deliver(f, 0, &batch);
    }
    rr_clock += 5;
}

/* amend, if any, adjusts transport parameters and the server context before the handshake starts */
static struct rr_fixture *rr_setup_with(void (*amend)(struct rr_fixture *f))
{
    struct rr_fixture *f = calloc(1, sizeof(*f));
    assert(f != NULL);
    rr_clock = 1000;
    rr_certificate(f);
    f->tc = (ptls_context_t){.random_bytes = ptls_openssl_random_bytes,
                             .get_time = &ptls_get_time,
                             .key_exchanges = ptls_openssl_key_exchanges,
                             .cipher_suites = ptls_openssl_cipher_suites,
                             .verify_certificate = &f->verifier.super};
    f->ts = f->tc;
    f->ts.verify_certificate = NULL;
    f->ts.certificates.list = &f->cert;
    f->ts.certificates.count = 1;
    f->ts.sign_certificate = &f->signer.super;
    f->ts.on_client_hello = &rr_hello_cb;
    quicly_amend_ptls_context(&f->tc);
    quicly_amend_ptls_context(&f->ts);
    f->qc = quicly_spec_context;
    f->qc.tls = &f->tc;
    f->qc.now = &rr_now_cb;
    f->qc.stream_open = &rr_open_cb;
    f->qc.transport_params.max_streams_uni = 16;
    f->qs = f->qc;
    f->qs.tls = &f->ts;
    f->qs.generate_resumption_token = &rr_generate_token_cb;
    f->loop = h2o_evloop_create();
    h2o_config_init(&f->conf);
    h2o_hostconf_t *host = h2o_config_register_host(&f->conf, h2o_iovec_init(H2O_STRLIT("localhost")), 65535);
    h2o_pathconf_t *pathconf = h2o_config_register_path(host, "/", 0);
    h2o_create_handler(pathconf, sizeof(h2o_handler_t))->on_req = rr_handler;
    h2o_context_init(&f->ctx, f->loop, &f->conf);
    f->accept = (h2o_accept_ctx_t){.ctx = &f->ctx, .hosts = f->conf.hosts};
    f->server_ctx.accept_ctx = &f->accept;
    f->server_ctx.qpack.decoder_table_capacity = 4096;
    h2o_http3_server_amend_quicly_context(&f->conf, &f->qs);
    /* Production defaults and the ordinary H3 amendment must stay OFF. Only these two fixture-owned copies opt in. */
    ok(!f->qc.transport_params.reset_stream_at && !f->qs.transport_params.reset_stream_at);
    f->qc.transport_params.reset_stream_at = f->qs.transport_params.reset_stream_at = 1;
    /* Small connection credit exposes leaks through a finite number of aborted streams; normal H3 stream windows stay intact. */
    f->qs.transport_params.max_data = 8192;
    if (amend != NULL)
        amend(f);
    h2o_socket_t *sock = h2o_quic_create_client_socket(f->loop, AF_INET);
    assert(sock != NULL);
    h2o_http3_server_init_context(&f->ctx, &f->server_ctx.super, f->loop, sock, NULL, &f->qs, &f->cid, NULL, NULL, 0);
    socklen_t salen = sizeof(f->sa);
    assert(getsockname(h2o_socket_get_fd(sock), &f->sa.sa, &salen) == 0);
    f->sa.sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    f->fd = socket(AF_INET, SOCK_DGRAM, 0);
    f->ca.sin.sin_family = AF_INET;
    f->ca.sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    assert(f->fd >= 0 && bind(f->fd, &f->ca.sa, sizeof(f->ca.sin)) == 0);
    salen = sizeof(f->ca);
    assert(getsockname(f->fd, &f->ca.sa, &salen) == 0);
    f->properties.client.negotiated_protocols.list = h2o_http3_alpn;
    f->properties.client.negotiated_protocols.count = 1;
    quicly_cid_plaintext_t cid = {.master_id = 123};
    assert(quicly_connect(&f->client, &f->qc, "localhost", &f->sa.sa, NULL, &cid, ptls_iovec_init(NULL, 0), &f->properties, NULL,
                          f) == 0);
    for (unsigned i = 0; i != 32; ++i)
        rr_step(f);
    ok(ptls_handshake_is_complete(quicly_get_tls(f->client)));
    ok(ptls_handshake_is_complete(quicly_get_tls(f->server->h3.super.quic)));
    ok(strcmp(ptls_get_negotiated_protocol(quicly_get_tls(f->client)), "h3") == 0);
    ok(quicly_get_remote_transport_parameters(f->client)->reset_stream_at == f->qs.transport_params.reset_stream_at);
    ok(quicly_get_remote_transport_parameters(f->server->h3.super.quic)->reset_stream_at == f->qc.transport_params.reset_stream_at);
    return f;
}

static struct rr_fixture *rr_setup(void)
{
    return rr_setup_with(NULL);
}

static void rr_dispose(struct rr_fixture *f)
{
    struct rr_packets batch;
    if (quicly_get_state(f->client) < QUICLY_STATE_CLOSING)
        assert(quicly_close(f->client, 0, NULL) == 0);
    rr_collect(f->client, &batch);
    ok(quicly_num_streams(f->client) == 0);
    quicly_free(f->client);
    while (f->streams != NULL) {
        struct rr_client_stream *s = f->streams;
        f->streams = s->next;
        assert(s->destroyed);
        quicly_sendbuf_dispose(&s->super.egress);
        ptls_buffer_dispose(&s->super.ingress);
        free(s);
    }
    if (quicly_get_state(f->server->h3.super.quic) < QUICLY_STATE_CLOSING)
        assert(quicly_close(f->server->h3.super.quic, 0, NULL) == 0);
    rr_collect(f->server->h3.super.quic, &batch);
    ok(quicly_num_streams(f->server->h3.super.quic) == 0);
    f->server->h3.super.callbacks->destroy_connection(&f->server->h3.super);
    ok(h2o_quic_num_connections(&f->server_ctx.super) == 0);
    h2o_quic_dispose_context(&f->server_ctx.super);
    close(f->fd);
    h2o_context_dispose(&f->ctx);
    h2o_config_dispose(&f->conf);
    h2o_evloop_destroy(f->loop);
    ptls_openssl_dispose_sign_certificate(&f->signer);
    ptls_openssl_dispose_verify_certificate(&f->verifier);
    OPENSSL_free(f->cert.base);
    free(f);
}

static quicly_stream_t *rr_write(struct rr_fixture *f, int uni, const void *bytes, size_t len)
{
    quicly_stream_t *qs;
    /* quicly_open_stream does not reject DRAINING: creating streams there violates the close-path invariant. */
    assert(quicly_get_state(f->client) == QUICLY_STATE_CONNECTED);
    assert(quicly_open_stream(f->client, &qs, uni) == 0);
    assert(quicly_streambuf_egress_write(qs, bytes, len) == 0);
    return qs;
}

/* Static QPACK GET / with authority localhost. No dynamic table or Huffman shortcuts in the receiving stack. */
static const uint8_t rr_get[] = {1, 16, 0, 0, 0xd1, 0xd7, 0xc1, 0x50, 9, 'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't'};

static void rr_check_get(struct rr_fixture *f)
{
    int connected = quicly_get_state(f->client) == QUICLY_STATE_CONNECTED &&
                    quicly_get_state(f->server->h3.super.quic) == QUICLY_STATE_CONNECTED;
    ok(connected);
    if (!connected) {
        printf("# GET prerequisite failed: unexpected connection close; do not open a stream on a draining peer\n");
        return;
    }
    quicly_stream_t *qs = rr_write(f, 0, rr_get, sizeof(rr_get));
    struct rr_client_stream *s = qs->data;
    assert(quicly_streambuf_egress_shutdown(qs) == 0);
    struct rr_packets batch;
    rr_collect(f->client, &batch);
    rr_deliver(f, 1, &batch);
    h2o_timer_unlink(&f->server->timeout);
    run_delayed(&f->server->timeout);
    rr_collect(f->server->h3.super.quic, &batch);
    rr_deliver(f, 0, &batch);
    ptls_iovec_t response = ptls_iovec_init(s->super.ingress.base, s->super.ingress.off);
    ok(s->fin);
    ok(response.len >= sizeof("alive-after-reset") - 1);
    ok(response.len >= 17 && memcmp(response.base + response.len - 17, "alive-after-reset", 17) == 0);
    ok(quicly_get_state(f->server->h3.super.quic) == QUICLY_STATE_CONNECTED);
    for (unsigned i = 0; i != 8; ++i)
        rr_step(f);
}

/* resets the send side of a client stream by RESET_STREAM_AT, which the fixture always negotiates */
static void rr_reset_at(quicly_stream_t *qs, quicly_error_t err, uint64_t reliable_size)
{
    int reliable = h2o_http3_reset_stream_reliably(qs, err, reliable_size);
    assert(reliable);
}

/* fills `bytes` with an unknown (reserved) frame, which the receiver skips */
static void rr_unknown_frame(uint8_t *bytes, size_t len)
{
    assert(3 <= len && len - 3 < 16384);
    bytes[0] = 0x21;
    bytes[1] = 0x40 | (uint8_t)((len - 3) >> 8);
    bytes[2] = (uint8_t)(len - 3);
    memset(bytes + 3, 0xff, len - 3);
}

static void rr_check_credit(struct rr_fixture *f)
{
    uint64_t consumed, shifted;
    quicly_get_max_data(f->server->h3.super.quic, NULL, NULL, &consumed, &shifted);
    ok(consumed == shifted);
}

/* the connection-level credit charged and not returned */
static uint64_t rr_credit_held(struct rr_fixture *f)
{
    uint64_t consumed, shifted;
    quicly_get_max_data(f->server->h3.super.quic, NULL, NULL, &consumed, &shifted);
    return consumed - shifted;
}

static struct {
    const quicly_stream_callbacks_t *orig;
    quicly_stream_callbacks_t wrapped;
    int state_after_complete; /* the state of the server stream once `on_receive` completing the transfer has returned */
} rr_body_probe;

static void rr_body_probe_on_receive(quicly_stream_t *qs, size_t off, const void *input, size_t len)
{
    rr_body_probe.orig->on_receive(qs, off, input, len);
    if (quicly_recvstate_transfer_complete(&qs->recvstate))
        rr_body_probe.state_after_complete = ((struct st_h2o_http3_server_stream_t *)qs->data)->state;
}

/* H1 (quicly #550): a transfer completed by RESET_STREAM_AT, by the reset or by a STREAM frame arriving after it, is not the end of
 * a request, whose body has no content-length; the request is not processed, the body being incomplete. quicly calls
 * `on_receive_reset` right after the `on_receive` completing the transfer, so the state is observed in between. */
static void rr_test_body_completed_by_reset(struct rr_fixture *f, int reset_first)
{
    static const uint8_t body[] = {0, 4, 'b', 'o', 'd', 'y'};
    unsigned calls = rr_handler_calls;
    quicly_stream_t *qs = rr_write(f, 0, rr_get, sizeof(rr_get));
    quicly_stream_id_t id = qs->stream_id;
    struct rr_client_stream *cs = qs->data;
    struct rr_packets held, reset;
    rr_collect(f->client, &held);
    rr_deliver(f, 1, &held);
    quicly_stream_t *server_qs = quicly_get_stream(f->server->h3.super.quic, id);
    assert(server_qs != NULL);
    struct st_h2o_http3_server_stream_t *s = server_qs->data;
    ok(s->state == H2O_HTTP3_SERVER_STREAM_STATE_RECV_BODY_BEFORE_BLOCK);
    rr_body_probe.orig = server_qs->callbacks;
    rr_body_probe.wrapped = *server_qs->callbacks;
    rr_body_probe.wrapped.on_receive = rr_body_probe_on_receive;
    rr_body_probe.state_after_complete = -1;
    server_qs->callbacks = &rr_body_probe.wrapped;
    assert(quicly_streambuf_egress_write(qs, body, sizeof(body)) == 0);
    rr_collect(f->client, &held);
    ok(held.count != 0);
    if (!reset_first)
        rr_deliver(f, 1, &held);
    rr_reset_at(qs, H2O_HTTP3_ERROR_REQUEST_CANCELLED, sizeof(rr_get) + sizeof(body));
    rr_collect(f->client, &reset);
    ok(reset.count != 0);
    rr_deliver(f, 1, &reset);
    if (reset_first) {
        ok(!quicly_recvstate_transfer_complete(&server_qs->recvstate));
        rr_deliver(f, 1, &held);
    }
    ok(quicly_recvstate_transfer_complete(&server_qs->recvstate) &&
       server_qs->recvstate.app_error_code == QUICLY_ERROR_GET_ERROR_CODE(H2O_HTTP3_ERROR_REQUEST_CANCELLED));
    /* a STREAM frame completes the transfer only if it arrives after the reset */
    ok(rr_body_probe.state_after_complete == (reset_first ? H2O_HTTP3_SERVER_STREAM_STATE_RECV_BODY_BEFORE_BLOCK : -1));
    ok(s->state == H2O_HTTP3_SERVER_STREAM_STATE_CLOSE_WAIT);
    ok(rr_handler_calls == calls);
    rr_check_credit(f);
    for (unsigned i = 0; i != 8; ++i)
        rr_step(f);
    ok(quicly_get_stream(f->server->h3.super.quic, id) == NULL);
    ok(rr_handler_calls == calls);
    ok(cs->super.ingress.off == 0); /* no response */
    rr_check_credit(f);
}

static void rr_test_response_and_qpack(struct rr_fixture *f, int mode)
{
    /* An already-final early error response is preserved by reset_only_if_open; a QPACK-blocked request must instead be
     * cancelled and removed from its delayed list. Both cases have buffered/previously-consumed data before the reset. */
    static const uint8_t qpack_blocked[] = {1, 3, 2, 0, 0x80};
    int blocked = mode != 0;
    uint8_t early_error[sizeof(rr_get) + 3];
    memcpy(early_error, rr_get, sizeof(rr_get));
    early_error[1] += 3;
    memcpy(early_error + sizeof(rr_get),
           "\x54\x01"
           "1",
           3); /* content-length: 1 */
    f->conf.max_request_entity_size = 0;
    quicly_stream_t *qs =
        rr_write(f, 0, blocked ? qpack_blocked : early_error, blocked ? sizeof(qpack_blocked) : sizeof(early_error));
    quicly_stream_id_t id = qs->stream_id;
    struct rr_packets held, reset;
    rr_collect(f->client, &held);
    rr_deliver(f, 1, &held);
    quicly_stream_t *server_qs = quicly_get_stream(f->server->h3.super.quic, id);
    assert(server_qs != NULL);
    struct st_h2o_http3_server_stream_t *s = server_qs->data;
    if (blocked) {
        ok(s->qpack_blocked_ref != 0 && f->server->num_qpack_blocked == 1);
    } else {
        ok(s->req.res.status == 413);
        ok(!quicly_sendstate_is_open(&server_qs->sendstate));
    }
    if (mode == 2) {
        /* Use an open, QPACK-blocked response: for the final early error response, whose FIN is in flight, quicly would also call
         * on_send_stop (#715). A real STOP_SENDING must move this request to CLOSE_WAIT before its first receive-reset callback. */
        quicly_request_stop(qs, H2O_HTTP3_ERROR_REQUEST_CANCELLED);
        rr_collect(f->client, &reset);
        rr_deliver(f, 1, &reset);
        ok(s->state == H2O_HTTP3_SERVER_STREAM_STATE_CLOSE_WAIT && s->req_disposed);
    }
    /* bytes are sent beyond the Reliable Size; quicly drops them once the reset has been received (#550 8a22a76d) */
    uint8_t tail[64];
    rr_unknown_frame(tail, sizeof(tail));
    assert(quicly_streambuf_egress_write(qs, tail, sizeof(tail)) == 0);
    rr_collect(f->client, &held);
    size_t request_len = blocked ? sizeof(qpack_blocked) : sizeof(early_error);
    rr_reset_at(qs, H2O_HTTP3_ERROR_REQUEST_CANCELLED, request_len + 8);
    rr_collect(f->client, &reset);
    assert(reset.count != 0);
    rr_deliver(f, 1, &reset);
    /* the reset is not reported before the bytes below the Reliable Size have been received */
    ok(server_qs->recvstate.app_error_code == QUICLY_ERROR_GET_ERROR_CODE(H2O_HTTP3_ERROR_REQUEST_CANCELLED));
    ok(server_qs->recvstate.eos == request_len + 8);
    ok(s->state == (mode == 2 ? H2O_HTTP3_SERVER_STREAM_STATE_CLOSE_WAIT
                    : blocked ? H2O_HTTP3_SERVER_STREAM_STATE_RECV_HEADERS
                              : H2O_HTTP3_SERVER_STREAM_STATE_SEND_BODY));
    /* the reset charges the final size and returns at once the credit of the bytes above the Reliable Size */
    ok(rr_credit_held(f) == request_len + 8 - server_qs->recvstate.data_off);
    rr_deliver(f, 1, &held);
    ok(quicly_get_stream(f->server->h3.super.quic, id) == server_qs);
    ok(quicly_recvstate_transfer_complete(&server_qs->recvstate) && server_qs->recvstate.eos == request_len + 8);
    ok(quicly_recvstate_bytes_available(&server_qs->recvstate) == 0);
    ok(s->qpack_blocked_ref == 0 && f->server->num_qpack_blocked == 0);
    ok(!h2o_linklist_is_linked(&s->link));
    ok(s->state == (mode != 0 ? H2O_HTTP3_SERVER_STREAM_STATE_CLOSE_WAIT : H2O_HTTP3_SERVER_STREAM_STATE_SEND_BODY));
    rr_check_credit(f);
    handle_buffered_input(s, 0); /* deferred processing is also inert */
    ok(quicly_recvstate_bytes_available(&server_qs->recvstate) == 0);
    rr_check_credit(f);
    for (unsigned i = 0; i != 8; ++i)
        rr_step(f);
    ok(quicly_get_stream(f->server->h3.super.quic, id) == NULL);
    rr_check_get(f);
}

/* quicly #715: STOP_SENDING resets the send side of a request stream even once the response is final, unless its FIN has been
 * acknowledged, and then calls on_send_stop, which must not reset it again. Mode 0 sends STOP_SENDING along with the request, mode
 * 1 after the response, whose flight is lost, and mode 2 before the response, the STOP_SENDING arriving after the acknowledgement
 * of the FIN. The reset, sent through h2o's scheduler, carries the peer's error code and goes out once. */
static void rr_test_stop_after_response(struct rr_fixture *f, int mode)
{
    quicly_stats_t before, after;
    assert(quicly_get_stats(f->server->h3.super.quic, &before) == 0);
    quicly_stream_t *qs = rr_write(f, 0, rr_get, sizeof(rr_get));
    struct rr_client_stream *cs = qs->data;
    quicly_stream_id_t id = qs->stream_id;
    assert(quicly_streambuf_egress_shutdown(qs) == 0);
    if (mode == 0)
        quicly_request_stop(qs, H2O_HTTP3_ERROR_REQUEST_CANCELLED);
    struct rr_packets batch, stop;
    rr_collect(f->client, &batch);
    rr_deliver(f, 1, &batch);
    h2o_timer_unlink(&f->server->timeout);
    run_delayed(&f->server->timeout);
    if (mode != 0) {
        quicly_stream_t *server_qs = quicly_get_stream(f->server->h3.super.quic, id);
        assert(server_qs != NULL);
        uint64_t final_size = server_qs->sendstate.final_size;
        ok(quicly_sendstate_eos_type(&server_qs->sendstate) == QUICLY_SENDSTATE_EOS_TYPE_FIN);
        rr_collect(f->server->h3.super.quic, &batch);
        ok(server_qs->sendstate.size_inflight == final_size);
        quicly_request_stop(qs, H2O_HTTP3_ERROR_REQUEST_CANCELLED);
        rr_collect(f->client, &stop);
        if (mode == 1) {
            rr_deliver(f, 1, &stop);
            server_qs = quicly_get_stream(f->server->h3.super.quic, id);
            ok(server_qs != NULL && quicly_sendstate_eos_type(&server_qs->sendstate) == QUICLY_SENDSTATE_EOS_TYPE_RESET &&
               server_qs->sendstate.app_error_code == QUICLY_ERROR_GET_ERROR_CODE(H2O_HTTP3_ERROR_REQUEST_CANCELLED) &&
               server_qs->sendstate.final_size == final_size);
        } else {
            struct rr_packets ack;
            rr_deliver(f, 0, &batch);
            ok(cs->fin);
            rr_clock += 30; /* past the delay of the acknowledgement */
            rr_collect(f->client, &ack);
            rr_deliver(f, 1, &ack);
            server_qs = quicly_get_stream(f->server->h3.super.quic, id);
            ok(server_qs == NULL || quicly_sendstate_transfer_complete(&server_qs->sendstate));
            rr_deliver(f, 1, &stop);
        }
    }
    for (unsigned i = 0; i != 8; ++i)
        rr_step(f);
    ok(quicly_get_state(f->server->h3.super.quic) == QUICLY_STATE_CONNECTED);
    ok(quicly_get_stream(f->server->h3.super.quic, id) == NULL);
    ok(cs->destroyed);
    assert(quicly_get_stats(f->server->h3.super.quic, &after) == 0);
    uint64_t resets = after.num_frames_sent.reset_stream - before.num_frames_sent.reset_stream;
    printf("# stop after response (mode %d): %" PRIu64 " RESET_STREAM sent\n", mode, resets);
    ok(resets == (mode == 2 ? 0 : 1));
    ok(cs->reset_err == (mode == 2 ? 0 : H2O_HTTP3_ERROR_REQUEST_CANCELLED));
    ok(mode != 2 || cs->fin);
    rr_check_credit(f);
}

static void test_h3_reliable_reset(void)
{
    struct rr_fixture *f = rr_setup();
    const uint8_t settings[] = {0, 4, 0};
    rr_write(f, 1, settings, sizeof(settings));
    for (unsigned i = 0; i != 8; ++i)
        rr_step(f);
    ok(h2o_http3_has_received_settings(&f->server->h3));

    /* Many reliably reset requests exceed the initial connection window. Deliver reset before all data, then the held
     * bytes, without delivering STOP to the sender first. A credit leak would block later requests. The reset charges the final
     * size and returns at once the credit of the bytes above the Reliable Size, which are dropped when they arrive; it is
     * reported, and the rest of the credit returned, once the bytes below it have arrived. On odd iterations the Reliable Size
     * equals the final size. */
    for (unsigned i = 0; i != 8; ++i) {
        uint8_t bytes[2048];
        rr_unknown_frame(bytes, sizeof(bytes)); /* incomplete unless all bytes are delivered */
        quicly_stream_t *qs = rr_write(f, 0, bytes, sizeof(bytes));
        quicly_stream_id_t id = qs->stream_id;
        struct rr_packets held, reset;
        rr_collect(f->client, &held);
        ok(held.count != 0);
        uint64_t reliable_size = i % 2 != 0 ? sizeof(bytes) : 16;
        rr_reset_at(qs, H2O_HTTP3_ERROR_REQUEST_CANCELLED, reliable_size);
        rr_collect(f->client, &reset);
        ok(reset.count != 0);
        rr_deliver(f, 1, &reset);
        quicly_stream_t *server_qs = quicly_get_stream(f->server->h3.super.quic, id);
        ok(server_qs != NULL);
        assert(server_qs != NULL);
        struct st_h2o_http3_server_stream_t *s = server_qs->data;
        ok(server_qs->recvstate.app_error_code == QUICLY_ERROR_GET_ERROR_CODE(H2O_HTTP3_ERROR_REQUEST_CANCELLED));
        ok(server_qs->recvstate.eos == reliable_size);
        ok(s->state == H2O_HTTP3_SERVER_STREAM_STATE_RECV_HEADERS && !s->req_disposed);
        ok(rr_credit_held(f) == reliable_size);
        rr_deliver(f, 1, &held);
        ok(quicly_get_stream(f->server->h3.super.quic, id) == server_qs);
        ok(s->state == H2O_HTTP3_SERVER_STREAM_STATE_CLOSE_WAIT && s->req_disposed);
        ok(quicly_recvstate_transfer_complete(&server_qs->recvstate) && server_qs->recvstate.eos == reliable_size);
        ok(quicly_recvstate_bytes_available(&server_qs->recvstate) == 0);
        rr_check_credit(f);
        /* Direct duplicate callback also checks application idempotence independently of QUIC packet deduplication. */
        server_qs->callbacks->on_receive_reset(server_qs, H2O_HTTP3_ERROR_REQUEST_CANCELLED);
        rr_check_credit(f);
        for (unsigned j = 0; j != 8; ++j)
            rr_step(f);
        ok(quicly_get_stream(f->server->h3.super.quic, id) == NULL);
    }
    rr_test_body_completed_by_reset(f, 0);
    rr_test_body_completed_by_reset(f, 1);
    rr_test_response_and_qpack(f, 0);
    rr_test_response_and_qpack(f, 1);
    rr_test_response_and_qpack(f, 2);
    rr_test_stop_after_response(f, 0);
    rr_test_stop_after_response(f, 1);
    rr_test_stop_after_response(f, 2);
    rr_check_get(f);
    rr_dispose(f);

    /* Minimal and all nonminimal type widths, with reset before type, after partial type, after a sparse suffix, and after
     * known type. Critical-stream reset must not be forgotten; unknown extensions must leave this H3 connection usable. */
    const uint64_t types[] = {0, 2, 3, 0x21};
    for (size_t t = 0; t != PTLS_ELEMENTSOF(types); ++t) {
        for (unsigned variant = 0; variant != 16; ++variant) {
            size_t width = (size_t)1 << (variant / 4);
            unsigned partial = variant % 4;
            if (width == 1 && partial == 1)
                continue; /* a one-byte type has no partial encoding */
            printf("# uni type=%" PRIu64 " width=%zu ordering=%u (0=reset-first,1=fragmented,2=sparse,3=known)\n", types[t], width,
                   partial);
            f = rr_setup();
            uint8_t bytes[2048] = {0};
            bytes[0] = width == 8 ? 0xc0 : width == 4 ? 0x80 : width == 2 ? 0x40 : 0;
            bytes[width - 1] |= (uint8_t)types[t];
            /* The bytes following the type are delivered and processed before the reset is reported; use valid input: SETTINGS
             * then an unknown frame, Set Dynamic Table Capacity (0) and Stream Cancellation (0) instructions, or opaque bytes. */
            switch (types[t]) {
            case 0:
                bytes[width] = 4;
                bytes[width + 1] = 0;
                rr_unknown_frame(bytes + width + 2, sizeof(bytes) - width - 2);
                break;
            case 2:
                memset(bytes + width, 0x20, sizeof(bytes) - width);
                break;
            case 3:
                memset(bytes + width, 0x40, sizeof(bytes) - width);
                break;
            default:
                memset(bytes + width, 0xff, sizeof(bytes) - width);
                break;
            }
            size_t initial = partial == 1 ? (width == 8 ? 3 : width - 1) : partial == 3 ? width : sizeof(bytes);
            quicly_stream_t *qs = rr_write(f, 1, bytes, initial);
            quicly_stream_id_t id = qs->stream_id;
            struct rr_packets held, reset;
            if (partial == 1 || partial == 3) {
                rr_collect(f->client, &held);
                rr_deliver(f, 1, &held);
                quicly_stream_t *incoming = quicly_get_stream(f->server->h3.super.quic, id);
                assert(incoming != NULL);
                /* on_receive's offset is relative to data_off, not an absolute wire offset. An incomplete type must
                 * consume NOTHING, otherwise the next callback will interpret its continuation as a new type. */
                printf("# after initial %zu type bytes: data_off=%" PRIu64 " available=%zu\n", initial,
                       incoming->recvstate.data_off, quicly_recvstate_bytes_available(&incoming->recvstate));
                ok(incoming->recvstate.data_off == (partial == 1 ? 0 : width));
                assert(quicly_streambuf_egress_write(qs, bytes + initial, sizeof(bytes) - initial) == 0);
            }
            rr_collect(f->client, &held);
            ok(held.count != 0);
            if (partial == 2) {
                /* Deliver only the high-offset packet first, forcing a sparse pre-reset buffer. */
                assert(held.count >= 2);
                struct rr_packets suffix = {.count = 1};
                suffix.packets[0] = held.packets[held.count - 1];
                rr_deliver(f, 1, &suffix);
                --held.count;
            }
            uint64_t reliable_size = partial == 3 ? width + 8 : width;
            rr_reset_at(qs, H2O_HTTP3_ERROR_REQUEST_CANCELLED, reliable_size);
            rr_collect(f->client, &reset);
            ok(reset.count != 0);
            rr_deliver(f, 1, &reset);
            /* the bytes below the Reliable Size are still to be received, so the reset is not reported yet (even for a known
             * critical stream); the sparse suffix, above the Reliable Size, is dropped */
            ok(quicly_get_state(f->server->h3.super.quic) == QUICLY_STATE_CONNECTED);
            quicly_stream_t *incoming = quicly_get_stream(f->server->h3.super.quic, id);
            assert(incoming != NULL);
            ok(incoming->recvstate.app_error_code == QUICLY_ERROR_GET_ERROR_CODE(H2O_HTTP3_ERROR_REQUEST_CANCELLED));
            ok(incoming->recvstate.eos == reliable_size);
            /* the credit of the sparse suffix stays tied to the memory holding it until the stream is destroyed */
            ok(rr_credit_held(f) == (partial == 2 ? sizeof(bytes) : reliable_size) - incoming->recvstate.data_off);
            rr_deliver(f, 1, &held);
            if (types[t] == 0x21) {
                ok(quicly_get_state(f->server->h3.super.quic) == QUICLY_STATE_CONNECTED);
                rr_check_credit(f);
                ok(quicly_get_stream(f->server->h3.super.quic, id) == NULL);
                if (quicly_get_state(f->server->h3.super.quic) == QUICLY_STATE_CONNECTED) {
                    rr_write(f, 1, settings, sizeof(settings));
                    for (unsigned j = 0; j != 8; ++j)
                        rr_step(f);
                }
                rr_check_get(f);
            } else {
                ok(quicly_get_state(f->server->h3.super.quic) == QUICLY_STATE_CLOSING);
                ok(quicly_get_close_reason(f->server->h3.super.quic, NULL, NULL, NULL) == H2O_HTTP3_ERROR_CLOSED_CRITICAL_STREAM);
                /* Exercise the actual close emission / stream destruction and the peer's wire-observed error. */
                rr_collect(f->server->h3.super.quic, &reset);
                ok(quicly_num_streams(f->server->h3.super.quic) == 0);
                rr_deliver(f, 0, &reset);
                ok(quicly_get_state(f->client) == QUICLY_STATE_DRAINING);
                ok(quicly_get_close_reason(f->client, NULL, NULL, NULL) == H2O_HTTP3_ERROR_CLOSED_CRITICAL_STREAM);
                ok(quicly_num_streams(f->client) == 0);
            }
            rr_dispose(f);
        }
    }

    /* An unknown type reset before any byte arrives with a Reliable Size equal to the final size: the final size is charged at
     * the reset, and the credit returned as the bytes are discarded and once the transfer completes. */
    f = rr_setup();
    {
        uint8_t bytes[2048];
        memset(bytes, 0xff, sizeof(bytes));
        bytes[0] = 0x21;
        quicly_stream_t *qs = rr_write(f, 1, bytes, sizeof(bytes));
        quicly_stream_id_t id = qs->stream_id;
        struct rr_packets held, reset;
        rr_collect(f->client, &held);
        ok(held.count != 0);
        rr_reset_at(qs, H2O_HTTP3_ERROR_REQUEST_CANCELLED, sizeof(bytes));
        rr_collect(f->client, &reset);
        ok(reset.count != 0);
        rr_deliver(f, 1, &reset);
        ok(quicly_get_state(f->server->h3.super.quic) == QUICLY_STATE_CONNECTED);
        ok(rr_credit_held(f) == sizeof(bytes));
        rr_deliver(f, 1, &held);
        rr_check_credit(f);
        for (unsigned j = 0; j != 8; ++j)
            rr_step(f);
        ok(quicly_get_stream(f->server->h3.super.quic, id) == NULL);
        rr_write(f, 1, settings, sizeof(settings));
        for (unsigned j = 0; j != 8; ++j)
            rr_step(f);
        rr_check_get(f);
    }
    rr_dispose(f);
}
#else
static void test_h3_reliable_reset(void)
{
    printf("# reliable reset transport fixture requires the native event loop\n");
}
#endif