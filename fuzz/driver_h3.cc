/*
 * Copyright (c) 2021 Fastly, Inc.
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
 * This file implements a test harness for using h2o with LibFuzzer.
 * See http://llvm.org/docs/LibFuzzer.html for more info.
 */

#define H2O_USE_EPOLL 1
#include <signal.h>

#include "driver_common.h"

#include "picotls.h"
#include "quicly.h"
#include "quicly_mock.h"
#include "picotls/openssl.h"
#include "h2o.h"
#include "h2o/http3_server.h"
#include "h2o/http3_internal.h"
#include "h2o/qpack.h"

static h2o_globalconf_t config;
static h2o_context_t ctx;
static h2o_accept_ctx_t accept_ctx;
static h2o_http3_server_ctx_t server_ctx;
static quicly_context_t qctx = quicly_spec_context;
static ptls_context_t ptls_ctx = {
    .random_bytes = ptls_openssl_random_bytes,
    .cipher_suites = ptls_openssl_cipher_suites,
    .get_time = &ptls_get_time,
};
static h2o_http3_conn_callbacks_t conn_callbacks = H2O_HTTP3_CONN_CALLBACKS;
static char unix_listener[PATH_MAX];
static int client_timeout_ms;

static quicly_address_t src_addr;
static quicly_address_t dst_addr;

static void quic_init_context(h2o_quic_ctx_t *ctx, h2o_evloop_t *loop)
{
    ctx->loop = loop;
    ctx->quic = &qctx;
    ctx->quic->tls = &ptls_ctx;
    ctx->conns_by_id = kh_init_h2o_quic_idmap();
    ctx->conns_accepting = kh_init_h2o_quic_acceptmap();
}

static bool init_done;
static size_t num_connections = 0;

static void on_destroy_connection(h2o_quic_conn_t *conn)
{
    --num_connections;
    H2O_HTTP3_CONN_CALLBACKS.super.destroy_connection(conn);
}

/* record egress activities on stream 0 */
/**
 * sent a full response?
 */
static bool sent_response = false;
static uint64_t last_sent_off;
static size_t last_sent_len;

static void on_stream_send_cb(mquicly_on_stream_send_t *self, quicly_conn_t *conn, quicly_stream_t *stream, const void *buff,
                              uint64_t off, size_t len, int is_fin)
{
    /* at the moment we aren't interested in streams other than 0 */
    if (stream->stream_id != 0)
        return;

    last_sent_off = off;
    last_sent_len = len;

    if (is_fin)
        sent_response = true;
}

static mquicly_on_stream_send_t on_stream_send = {.cb = on_stream_send_cb};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    if (!init_done) {
        h2o_hostconf_t *hostconf;
        h2o_access_log_filehandle_t *logfh = NULL;
        h2o_pathconf_t *pathconf;
        static char tmpname[] = "/tmp/h2o-fuzz-XXXXXX";
        char *dirname;
        pthread_t tupstream;
        const char *client_timeout_ms_str, *log_access_str;

        h2o_barrier_init(&init_barrier, 2);
        signal(SIGPIPE, SIG_IGN);

        dirname = mkdtemp(tmpname);
        snprintf(unix_listener, sizeof(unix_listener), "http://[unix://%s/_.sock]/proxy", dirname);
        if ((client_timeout_ms_str = getenv("H2O_FUZZER_CLIENT_TIMEOUT")) != NULL)
            client_timeout_ms = atoi(client_timeout_ms_str);
        if (!client_timeout_ms)
            client_timeout_ms = 10;

        if ((log_access_str = getenv("H2O_FUZZER_LOG_ACCESS")) != NULL) {
            bool log_access = atoi(log_access_str) != 0;
            if (log_access)
                logfh = h2o_access_log_open_handle("/dev/stdout", NULL, H2O_LOGCONF_ESCAPE_APACHE);
        }

        h2o_config_init(&config);
        hostconf = h2o_config_register_host(&config, h2o_iovec_init(H2O_STRLIT("default")), 65535);

        register_proxy(hostconf, unix_listener, logfh);

        pathconf = h2o_config_register_path(hostconf, "/", 0);
        h2o_file_register(pathconf, "examples/doc_root", NULL, NULL, 0);
        if (logfh != NULL)
            h2o_access_log_register(pathconf, logfh);

        mquicly_context.on_stream_send = &on_stream_send;

        h2o_context_init(&ctx, h2o_evloop_create(), &config);
        accept_ctx.ctx = &ctx;
        accept_ctx.hosts = config.hosts;

        server_ctx.accept_ctx = &accept_ctx;
        server_ctx.send_retry = 0;
        server_ctx.qpack.encoder_table_capacity = 4096;

        conn_callbacks.super.destroy_connection = on_destroy_connection;

        quic_init_context(&server_ctx.super, ctx.loop);
        h2o_http3_server_amend_quicly_context(&config, server_ctx.super.quic);
        if (pthread_create(&tupstream, NULL, upstream_thread, dirname) != 0) {
            abort();
        }
        h2o_barrier_wait(&init_barrier);
        init_done = true;
    }

    src_addr.sin.sin_family = dst_addr.sin.sin_family = AF_INET;
    src_addr.sin.sin_addr.s_addr = dst_addr.sin.sin_addr.s_addr = htonl(0x7f000001);
    src_addr.sin.sin_port = htons(12345);
    dst_addr.sin.sin_port = htons(8443);

    ++num_connections;
    sent_response = false;
    h2o_http3_conn_t *conn = h2o_http3_server_accept(&server_ctx, &dst_addr, &src_addr, NULL /* initial_packet */,
                                                     NULL /* address_token */, 0 /* skip_tracing */, &conn_callbacks);
    assert(conn != NULL);
    assert(&conn->super != H2O_QUIC_ACCEPT_CONN_DECRYPTION_FAILED);
    quicly_stream_t *stream;
    int ret = mquicly_open_stream(conn->super.quic, &stream, 1 /* remote initiated */, 0 /* bidi */);
    assert(ret == 0);
    assert(stream != NULL);

    quicly_recvstate_update(&stream->recvstate, 0, &Size, 1, 63);
    stream->callbacks->on_receive(stream, 0, Data, Size);

    uint64_t loop_start = h2o_now(ctx.loop);
    do {
        if (loop_start + client_timeout_ms < h2o_now(ctx.loop)) {
            break; /* time up */
        }
        uint64_t time_left = loop_start + client_timeout_ms - h2o_now(ctx.loop);
        h2o_evloop_run(ctx.loop, time_left);
        if (num_connections == 0) {
            /* connection was closed abruptly due to an error in the input */
            return 0;
        }

        if (last_sent_len > 0) {
            /* simulate ack-receiving event */
            quicly_sendstate_sent_t sent = {.start = last_sent_off, .end = last_sent_off + last_sent_len};
            size_t bytes_to_shift;

            last_sent_len = 0;
            int ret = quicly_sendstate_acked(&stream->sendstate, &sent, &bytes_to_shift);
            assert(ret == 0);
            if (bytes_to_shift != 0)
                stream->callbacks->on_send_shift(stream, bytes_to_shift);
        }
    } while (!sent_response);

    mquicly_closed_by_remote(conn->super.quic, 0, 0 /* TODO: frame_type */, ptls_iovec_init(NULL, 0));
    /* simulate timer update at the end of process_packets() */
    h2o_quic_schedule_timer(&conn->super);

    do {
        h2o_evloop_run(ctx.loop, 1);
    } while (num_connections != 0);

    return 0;
}
