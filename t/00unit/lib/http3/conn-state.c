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
/* Included by the server unit translation unit to inspect server-side stream state.
 * Real TLS/QUIC connections and h2o_http3_server_accept; packets are exchanged deterministically in memory, except the accept-time
 * server flight, which uses loopback UDP. */
#include <openssl/x509v3.h>
#include "picotls/openssl.h"
#include "quicly/defaults.h"
#include "quicly/streambuf.h"

#if !H2O_USE_LIBUV
struct cs_client_stream {
    quicly_streambuf_t super;
    struct cs_client_stream *next;
    quicly_stream_id_t id;
    int fin, destroyed;
};

struct cs_fixture {
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
    struct cs_client_stream *streams;
};

struct cs_packets {
    struct iovec packets[16];
    uint8_t bytes[16 * 1500];
    size_t count;
};

static int64_t cs_clock;
static int64_t cs_now(quicly_now_t *self)
{
    return cs_clock;
}
static quicly_now_t cs_now_cb = {cs_now};

static int cs_hello(ptls_on_client_hello_t *self, ptls_t *tls, ptls_on_client_hello_parameters_t *params)
{
    for (size_t i = 0; i != params->negotiated_protocols.count; ++i) {
        ptls_iovec_t p = params->negotiated_protocols.list[i];
        if (h2o_memis(p.base, p.len, H2O_STRLIT("h3")))
            return ptls_set_negotiated_protocol(tls, (const char *)p.base, p.len);
    }
    return PTLS_ALERT_NO_APPLICATION_PROTOCOL;
}
static ptls_on_client_hello_t cs_hello_cb = {cs_hello};

static void cs_receive(quicly_stream_t *qs, size_t off, const void *src, size_t len)
{
    assert(quicly_streambuf_ingress_receive(qs, off, src, len) == 0);
    ((struct cs_client_stream *)qs->data)->fin = quicly_recvstate_transfer_complete(&qs->recvstate);
}

static void cs_destroy(quicly_stream_t *qs, quicly_error_t err)
{
    ((struct cs_client_stream *)qs->data)->destroyed = 1; /* the fixture retains the received result */
}

static void cs_ignore_error(quicly_stream_t *qs, quicly_error_t err)
{
}

static quicly_error_t cs_open(quicly_stream_open_t *self, quicly_stream_t *qs)
{
    static const quicly_stream_callbacks_t callbacks = {
        cs_destroy, quicly_streambuf_egress_shift, quicly_streambuf_egress_emit, cs_ignore_error, cs_receive, cs_ignore_error};
    assert(quicly_streambuf_create(qs, sizeof(struct cs_client_stream)) == 0);
    struct cs_fixture *f = *quicly_get_data(qs->conn);
    struct cs_client_stream *s = qs->data;
    s->next = f->streams;
    s->id = qs->stream_id;
    s->fin = s->destroyed = 0;
    f->streams = s;
    qs->callbacks = &callbacks;
    return 0;
}
static quicly_stream_open_t cs_open_cb = {cs_open};

static int cs_handler(h2o_handler_t *self, h2o_req_t *req)
{
    req->res.status = 200;
    req->res.reason = "OK";
    h2o_send_inline(req, H2O_STRLIT("hello"));
    return 0;
}

static void cs_certificate(struct cs_fixture *f)
{
    EVP_PKEY_CTX *keygen = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    EVP_PKEY *key = NULL;
    assert(keygen != NULL && EVP_PKEY_keygen_init(keygen) == 1);
    assert(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(keygen, NID_X9_62_prime256v1) == 1);
    assert(EVP_PKEY_keygen(keygen, &key) == 1);
    EVP_PKEY_CTX_free(keygen);
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

static void cs_deliver(struct cs_fixture *f, int to_server, struct cs_packets *batch)
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
}

static void cs_collect(quicly_conn_t *conn, struct cs_packets *batch)
{
    quicly_address_t dest, src;
    batch->count = PTLS_ELEMENTSOF(batch->packets);
    quicly_error_t ret = quicly_send(conn, &dest, &src, batch->packets, &batch->count, batch->bytes, sizeof(batch->bytes));
    assert(ret == 0 || (ret == QUICLY_ERROR_FREE_CONNECTION && batch->count == 0 && quicly_num_streams(conn) == 0));
}

static void cs_step(struct cs_fixture *f)
{
    struct cs_packets batch;
    cs_collect(f->client, &batch);
    cs_deliver(f, 1, &batch);
    if (f->server != NULL) {
        /* server_accept writes its first flight through the actual loopback socket */
        ssize_t len;
        while ((len = recv(f->fd, batch.bytes, sizeof(batch.bytes), MSG_DONTWAIT)) > 0) {
            batch.packets[0] = (struct iovec){batch.bytes, (size_t)len};
            batch.count = 1;
            cs_deliver(f, 0, &batch);
        }
        assert(errno == EAGAIN || errno == EWOULDBLOCK);
        if (h2o_timer_is_linked(&f->server->timeout)) {
            h2o_timer_unlink(&f->server->timeout);
            run_delayed(&f->server->timeout);
        }
        cs_collect(f->server->h3.super.quic, &batch);
        cs_deliver(f, 0, &batch);
    }
    cs_clock += 10;
}

static struct cs_fixture *cs_setup(void)
{
    struct cs_fixture *f = calloc(1, sizeof(*f));
    assert(f != NULL);
    cs_clock = 1000;
    cs_certificate(f);
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
    f->ts.on_client_hello = &cs_hello_cb;
    quicly_amend_ptls_context(&f->tc);
    quicly_amend_ptls_context(&f->ts);
    f->qc = quicly_spec_context;
    f->qc.tls = &f->tc;
    f->qc.now = &cs_now_cb;
    f->qc.stream_open = &cs_open_cb;
    f->qc.transport_params.max_streams_uni = 16;
    f->qs = f->qc;
    f->qs.tls = &f->ts;
    f->loop = h2o_evloop_create();
    h2o_config_init(&f->conf);
    h2o_hostconf_t *host = h2o_config_register_host(&f->conf, h2o_iovec_init(H2O_STRLIT("localhost")), 65535);
    h2o_pathconf_t *pathconf = h2o_config_register_path(host, "/", 0);
    h2o_create_handler(pathconf, sizeof(h2o_handler_t))->on_req = cs_handler;
    h2o_context_init(&f->ctx, f->loop, &f->conf);
    f->accept = (h2o_accept_ctx_t){.ctx = &f->ctx, .hosts = f->conf.hosts};
    f->server_ctx.accept_ctx = &f->accept;
    f->server_ctx.qpack.decoder_table_capacity = 4096;
    h2o_http3_server_amend_quicly_context(&f->conf, &f->qs);
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
        cs_step(f);
    ok(f->server != NULL);
    ok(ptls_handshake_is_complete(quicly_get_tls(f->client)));
    ok(quicly_get_state(f->server->h3.super.quic) == QUICLY_STATE_CONNECTED);
    return f;
}

static void cs_dispose(struct cs_fixture *f)
{
    struct cs_packets batch;
    if (quicly_get_state(f->client) < QUICLY_STATE_CLOSING)
        assert(quicly_close(f->client, 0, NULL) == 0);
    cs_collect(f->client, &batch);
    quicly_free(f->client);
    while (f->streams != NULL) {
        struct cs_client_stream *s = f->streams;
        f->streams = s->next;
        assert(s->destroyed);
        quicly_sendbuf_dispose(&s->super.egress);
        ptls_buffer_dispose(&s->super.ingress);
        free(s);
    }
    if (quicly_get_state(f->server->h3.super.quic) < QUICLY_STATE_CLOSING)
        assert(quicly_close(f->server->h3.super.quic, 0, NULL) == 0);
    cs_collect(f->server->h3.super.quic, &batch);
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

/* opens a client bidi stream carrying `bytes`, and a FIN if `fin`, then runs the exchange until it settles; quicly may free the
 * stream on the way, so the result is the record the fixture retains */
static struct cs_client_stream *cs_send(struct cs_fixture *f, const void *bytes, size_t len, int fin)
{
    quicly_stream_t *qs;
    assert(quicly_open_stream(f->client, &qs, 0) == 0);
    struct cs_client_stream *s = qs->data;
    assert(quicly_streambuf_egress_write(qs, bytes, len) == 0);
    if (fin)
        assert(quicly_streambuf_egress_shutdown(qs) == 0);
    for (unsigned i = 0; i != 16; ++i)
        cs_step(f);
    return s;
}

static void test_conn_state_disposed_before_headers(void)
{
    struct cs_fixture *f = cs_setup();

    /* A HEADERS frame type with no length yet: the server opens the stream but never reaches SEND_HEADERS. */
    quicly_stream_id_t id = cs_send(f, "\x01", 1, 0)->id;
    quicly_stream_t *qs = quicly_get_stream(f->server->h3.super.quic, id);
    ok(qs != NULL);
    if (qs != NULL) {
        struct st_h2o_http3_server_stream_t *stream = qs->data;
        ok(stream->state == H2O_HTTP3_SERVER_STREAM_STATE_RECV_HEADERS);
        /* pre_dispose_request reads this when the stream is disposed, so it must be set from the start */
        ok(stream->datagram_flow_id == UINT64_MAX);
    }

    /* The client gives up; the server disposes of the stream before any request exists, and the connection carries on. */
    quicly_stream_t *cqs = quicly_get_stream(f->client, id);
    assert(cqs != NULL);
    quicly_reset_stream(cqs, H2O_HTTP3_ERROR_REQUEST_CANCELLED);
    quicly_request_stop(cqs, H2O_HTTP3_ERROR_REQUEST_CANCELLED);
    for (unsigned i = 0; i != 16; ++i)
        cs_step(f);
    ok(quicly_get_stream(f->server->h3.super.quic, id) == NULL);
    ok(quicly_get_state(f->server->h3.super.quic) == QUICLY_STATE_CONNECTED);

    cs_dispose(f);
}

static void test_conn_state(void)
{
    subtest("disposed before headers", test_conn_state_disposed_before_headers);
}
#else
static void test_conn_state(void)
{
    printf("# connection state transport fixture requires the native event loop\n");
}
#endif
