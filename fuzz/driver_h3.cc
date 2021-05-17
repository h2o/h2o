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

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    if (!init_done) {
        h2o_hostconf_t *hostconf;
        h2o_access_log_filehandle_t *logfh = h2o_access_log_open_handle("/dev/stdout", NULL, H2O_LOGCONF_ESCAPE_APACHE);
        h2o_pathconf_t *pathconf;

        h2o_config_init(&config);
        hostconf = h2o_config_register_host(&config, h2o_iovec_init(H2O_STRLIT("default")), 65535);

        pathconf = h2o_config_register_path(hostconf, "/", 0);
        h2o_file_register(pathconf, "examples/doc_root", NULL, NULL, 0);
        if (logfh != NULL)
            h2o_access_log_register(pathconf, logfh);

        h2o_context_init(&ctx, h2o_evloop_create(), &config);
        accept_ctx.ctx = &ctx;
        accept_ctx.hosts = config.hosts;

        server_ctx.accept_ctx = &accept_ctx;
        server_ctx.send_retry = 0;
        server_ctx.qpack.encoder_table_capacity = 4096;

        conn_callbacks.super.destroy_connection = on_destroy_connection;

        quic_init_context(&server_ctx.super, ctx.loop);
        h2o_http3_server_amend_quicly_context(&config, server_ctx.super.quic);

        init_done = true;
    }

    src_addr.sin.sin_family = dst_addr.sin.sin_family = AF_INET;
    src_addr.sin.sin_addr.s_addr = dst_addr.sin.sin_addr.s_addr = htonl(0x7f000001);
    src_addr.sin.sin_port = htons(12345);
    dst_addr.sin.sin_port = htons(8443);

    ++num_connections;
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

    h2o_evloop_run(ctx.loop, 1);

    mquicly_closed_by_remote(conn->super.quic, 0, 0 /* TODO: frame_type */, ptls_iovec_init(NULL, 0));
    /* simulate timer update at the end of process_packets() */
    h2o_quic_schedule_timer(&conn->super);

    do {
        h2o_evloop_run(ctx.loop, 1);
    } while (num_connections != 0);

    return 0;
}
