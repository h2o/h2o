/*
 * Copyright (c) 2014 DeNA Co., Ltd.
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
#include <fcntl.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/time.h>
#include "cloexec.h"
#include "picotls.h"
#include "picotls/openssl.h"
#include "h2o.h"
#include "h2o/http3_server.h"
#include "h2o/memcached.h"
#if H2O_USE_FUSION
#include "picotls/fusion.h"
#endif

h2o_http3client_ctx_t *h2o_create_proxy_http3_context(h2o_context_t *ctx, SSL_CTX *ssl_ctx, int64_t max_concurrent_streams,
                                                      int use_ecn, int use_gso)
{
#if H2O_USE_LIBUV
    h2o_fatal("no HTTP/3 support for libuv");
#else

    h2o_http3client_ctx_t *h3ctx = h2o_mem_alloc(sizeof(*h3ctx));

    /* tls (TODO inherit session cache setting of ssl_ctx) */
    h3ctx->tls = (ptls_context_t){
        .random_bytes = ptls_openssl_random_bytes,
        .get_time = &ptls_get_time,
        .key_exchanges = ptls_openssl_key_exchanges,
        .cipher_suites = ptls_openssl_cipher_suites,
    };
    h3ctx->verify_cert = (ptls_openssl_verify_certificate_t){};
    if ((SSL_CTX_get_verify_mode(ssl_ctx) & SSL_VERIFY_PEER) != 0) {
        X509_STORE *store;
        if ((store = SSL_CTX_get_cert_store(ssl_ctx)) == NULL)
            h2o_fatal("failed to obtain the store to be used for server certificate verification");
        ptls_openssl_init_verify_certificate(&h3ctx->verify_cert, store);
        h3ctx->tls.verify_certificate = &h3ctx->verify_cert.super;
    }
    quicly_amend_ptls_context(&h3ctx->tls);

    /* quic */
    h3ctx->quic = quicly_spec_context;
    h3ctx->quic.tls = &h3ctx->tls;
    h3ctx->quic.transport_params.max_streams_uni = 10;
    h3ctx->quic.transport_params.max_streams_bidi = max_concurrent_streams;
    if (!use_ecn)
        h3ctx->quic.enable_ratio.ecn = 0;
    uint8_t cid_key[PTLS_SHA256_DIGEST_SIZE];
    ptls_openssl_random_bytes(cid_key, sizeof(cid_key));
    h3ctx->quic.cid_encryptor = quicly_new_default_cid_encryptor(
#if H2O_USE_FUSION
        ptls_fusion_is_supported_by_cpu() ? &ptls_fusion_quiclb :
#endif
                                          &ptls_openssl_quiclb,
        &ptls_openssl_aes128ecb, &ptls_openssl_sha256, ptls_iovec_init(cid_key, sizeof(cid_key)));
    ptls_clear_memory(cid_key, sizeof(cid_key));
    h3ctx->quic.stream_open = &h2o_httpclient_http3_on_stream_open;

    /* http3 client-specific fields */
    h3ctx->max_frame_payload_size = h2o_http3_calc_min_flow_control_size(H2O_MAX_REQLEN); /* same maximum for HEADERS frame in both
                                                                                           directions */

    /* h2o server http3 integration */
    h2o_socket_t *socks[2], **sp = socks;
    if ((*sp = h2o_quic_create_client_socket(ctx->loop, AF_INET, use_ecn)) != NULL)
        ++sp;
    if ((*sp = h2o_quic_create_client_socket(ctx->loop, AF_INET6, use_ecn)) != NULL)
        ++sp;
    if (sp == socks) {
        char buf[256];
        h2o_fatal("failed to create UDP socket for both IPv4 and v6: %s", h2o_strerror_r(errno, buf, sizeof(buf)));
    }
    h2o_http3_server_init_context(ctx, &h3ctx->h3, ctx->loop, socks[0], socks[1], &h3ctx->quic, &ctx->http3.next_cid, NULL,
                                  h2o_httpclient_http3_notify_connection_update, use_gso);

    h3ctx->load_session = NULL; /* TODO reuse session? */

    return h3ctx;
#endif
}

void h2o_destroy_proxy_http3_context(h2o_http3client_ctx_t *h3ctx)
{
    h2o_quic_dispose_context(&h3ctx->h3);
    quicly_free_default_cid_encryptor(h3ctx->quic.cid_encryptor);
    if (h3ctx->verify_cert.super.cb != NULL)
        ptls_openssl_dispose_verify_certificate(&h3ctx->verify_cert);
    free(h3ctx);
}

void h2o_context_init_pathconf_context(h2o_context_t *ctx, h2o_pathconf_t *pathconf)
{
    /* add pathconf to the inited list (or return if already inited) */
    size_t i;
    for (i = 0; i != ctx->_pathconfs_inited.size; ++i)
        if (ctx->_pathconfs_inited.entries[i] == pathconf)
            return;
    h2o_vector_reserve(NULL, &ctx->_pathconfs_inited, ctx->_pathconfs_inited.size + 1);
    ctx->_pathconfs_inited.entries[ctx->_pathconfs_inited.size++] = pathconf;

#define DOIT(type, list)                                                                                                           \
    do {                                                                                                                           \
        size_t i;                                                                                                                  \
        for (i = 0; i != pathconf->list.size; ++i) {                                                                               \
            type *o = pathconf->list.entries[i];                                                                                   \
            if (o->on_context_init != NULL)                                                                                        \
                o->on_context_init(o, ctx);                                                                                        \
        }                                                                                                                          \
    } while (0)

    DOIT(h2o_handler_t, handlers);
    DOIT(h2o_filter_t, _filters);
    DOIT(h2o_logger_t, _loggers);

#undef DOIT
}

void h2o_context_dispose_pathconf_context(h2o_context_t *ctx, h2o_pathconf_t *pathconf)
{
    /* nullify pathconf in the inited list (or return if already disposed) */
    size_t i;
    for (i = 0; i != ctx->_pathconfs_inited.size; ++i)
        if (ctx->_pathconfs_inited.entries[i] == pathconf)
            break;
    if (i == ctx->_pathconfs_inited.size)
        return;
    ctx->_pathconfs_inited.entries[i] = NULL;

#define DOIT(type, list)                                                                                                           \
    do {                                                                                                                           \
        size_t i;                                                                                                                  \
        for (i = 0; i != pathconf->list.size; ++i) {                                                                               \
            type *o = pathconf->list.entries[i];                                                                                   \
            if (o->on_context_dispose != NULL)                                                                                     \
                o->on_context_dispose(o, ctx);                                                                                     \
        }                                                                                                                          \
    } while (0)

    DOIT(h2o_handler_t, handlers);
    DOIT(h2o_filter_t, _filters);
    DOIT(h2o_logger_t, _loggers);

#undef DOIT
}

void h2o_context_init(h2o_context_t *ctx, h2o_loop_t *loop, h2o_globalconf_t *config)
{
    size_t i, j;

    assert(config->hosts[0] != NULL);

    memset(ctx, 0, sizeof(*ctx));
    ctx->loop = loop;
    ctx->globalconf = config;
    ctx->queue = h2o_multithread_create_queue(loop);
    h2o_multithread_register_receiver(ctx->queue, &ctx->receivers.hostinfo_getaddr, h2o_hostinfo_getaddr_receiver);
    ctx->filecache = h2o_filecache_create(config->filecache.capacity);
    ctx->spare_pipes.pipes = h2o_mem_alloc(sizeof(ctx->spare_pipes.pipes[0]) * config->max_spare_pipes);

    h2o_linklist_init_anchor(&ctx->_conns.active);
    h2o_linklist_init_anchor(&ctx->_conns.idle);
    h2o_linklist_init_anchor(&ctx->_conns.shutdown);
    ctx->proxy.client_ctx.loop = loop;
    ctx->proxy.client_ctx.io_timeout = ctx->globalconf->proxy.io_timeout;
    ctx->proxy.client_ctx.connect_timeout = ctx->globalconf->proxy.connect_timeout;
    ctx->proxy.client_ctx.first_byte_timeout = ctx->globalconf->proxy.first_byte_timeout;
    ctx->proxy.client_ctx.keepalive_timeout = ctx->globalconf->proxy.keepalive_timeout;
    ctx->proxy.client_ctx.getaddr_receiver = &ctx->receivers.hostinfo_getaddr;
    ctx->proxy.client_ctx.http2.latency_optimization = ctx->globalconf->http2.latency_optimization;
    ctx->proxy.client_ctx.max_buffer_size = ctx->globalconf->proxy.max_buffer_size;
    ctx->proxy.client_ctx.http2.max_concurrent_streams = ctx->globalconf->proxy.http2.max_concurrent_streams;
    ctx->proxy.client_ctx.protocol_selector.ratio.http2 = ctx->globalconf->proxy.protocol_ratio.http2;
    ctx->proxy.client_ctx.protocol_selector.ratio.http3 = ctx->globalconf->proxy.protocol_ratio.http3;
    if (ctx->globalconf->proxy.protocol_ratio.http3 != 0)
        ctx->proxy.client_ctx.http3 = h2o_create_proxy_http3_context(
            ctx, ctx->globalconf->proxy.global_socketpool._ssl_ctx, ctx->globalconf->proxy.http3.max_concurrent_streams,
            ctx->globalconf->proxy.http3.ecn, ctx->globalconf->http3.use_gso);
    ctx->proxy.connpool.socketpool = &ctx->globalconf->proxy.global_socketpool;
    h2o_linklist_init_anchor(&ctx->proxy.connpool.http2.conns);

    ctx->_module_configs = h2o_mem_alloc(sizeof(*ctx->_module_configs) * config->_num_config_slots);
    memset(ctx->_module_configs, 0, sizeof(*ctx->_module_configs) * config->_num_config_slots);

    static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
    pthread_mutex_lock(&mutex);

    h2o_socketpool_register_loop(&ctx->globalconf->proxy.global_socketpool, loop);

    for (i = 0; config->hosts[i] != NULL; ++i) {
        h2o_hostconf_t *hostconf = config->hosts[i];
        for (j = 0; j != hostconf->paths.size; ++j) {
            h2o_pathconf_t *pathconf = hostconf->paths.entries[j];
            h2o_context_init_pathconf_context(ctx, pathconf);
        }
        h2o_context_init_pathconf_context(ctx, &hostconf->fallback_path);
    }

    pthread_mutex_unlock(&mutex);
}

void h2o_context_dispose(h2o_context_t *ctx)
{
    h2o_globalconf_t *config = ctx->globalconf;

    h2o_socketpool_unregister_loop(&ctx->globalconf->proxy.global_socketpool, ctx->loop);

    for (size_t i = 0; config->hosts[i] != NULL; ++i) {
        h2o_hostconf_t *hostconf = config->hosts[i];
        for (size_t j = 0; j != hostconf->paths.size; ++j) {
            h2o_pathconf_t *pathconf = hostconf->paths.entries[j];
            h2o_context_dispose_pathconf_context(ctx, pathconf);
        }
        h2o_context_dispose_pathconf_context(ctx, &hostconf->fallback_path);
    }
    free(ctx->_pathconfs_inited.entries);
    if (ctx->proxy.client_ctx.http3 != NULL)
        h2o_destroy_proxy_http3_context(ctx->proxy.client_ctx.http3);
    free(ctx->_module_configs);
    /* what should we do here? assert(!h2o_linklist_is_empty(&ctx->http2._conns); */

    for (size_t i = 0; i < ctx->spare_pipes.count; ++i) {
        close(ctx->spare_pipes.pipes[i][0]);
        close(ctx->spare_pipes.pipes[i][1]);
    }
    free(ctx->spare_pipes.pipes);

    h2o_filecache_destroy(ctx->filecache);
    ctx->filecache = NULL;

    /* clear storage */
    for (size_t i = 0; i != ctx->storage.size; ++i) {
        h2o_context_storage_item_t *item = ctx->storage.entries + i;
        if (item->dispose != NULL) {
            item->dispose(item->data);
        }
    }
    free(ctx->storage.entries);

    /* TODO assert that the all the getaddrinfo threads are idle */
    h2o_multithread_unregister_receiver(ctx->queue, &ctx->receivers.hostinfo_getaddr);
    h2o_multithread_destroy_queue(ctx->queue);

    if (ctx->_timestamp_cache.value != NULL)
        h2o_mem_release_shared(ctx->_timestamp_cache.value);
}

void h2o_context_request_shutdown(h2o_context_t *ctx)
{
    ctx->shutdown_requested = 1;

    H2O_CONN_LIST_FOREACH(h2o_conn_t * conn, ({&ctx->_conns.active, &ctx->_conns.idle}), {
        if (conn->callbacks->request_shutdown != NULL) {
            conn->callbacks->request_shutdown(conn);
        }
    });
}

void h2o_context_update_timestamp_string_cache(h2o_context_t *ctx)
{
    struct tm gmt;
    if (ctx->_timestamp_cache.value != NULL)
        h2o_mem_release_shared(ctx->_timestamp_cache.value);
    ctx->_timestamp_cache.value = h2o_mem_alloc_shared(NULL, sizeof(h2o_timestamp_string_t), NULL);
    gmtime_r(&ctx->_timestamp_cache.tv_at.tv_sec, &gmt);
    h2o_time2str_rfc1123(ctx->_timestamp_cache.value->rfc1123, &gmt);
    h2o_time2str_log(ctx->_timestamp_cache.value->log, ctx->_timestamp_cache.tv_at.tv_sec);
}

void h2o_context_close_idle_connections(h2o_context_t *ctx, size_t max_connections_to_close, uint64_t min_age)
{
    if (max_connections_to_close <= 0)
        return;

    size_t closed = ctx->_conns.num_conns.shutdown;

    if (closed >= max_connections_to_close)
        return;

    H2O_CONN_LIST_FOREACH(h2o_conn_t * conn, ({&ctx->_conns.idle}), {
        struct timeval now = h2o_gettimeofday(ctx->loop);
        if (h2o_timeval_subtract(&conn->connected_at, &now) < (min_age * 1000))
            continue;
        ctx->connection_stats.idle_closed++;
        conn->callbacks->close_idle_connection(conn);
        closed++;
        if (closed == max_connections_to_close)
            return;
    });
}

static size_t *get_connection_state_counter(h2o_context_t *ctx, h2o_conn_state_t state)
{
    return ctx->_conns.num_conns.counters + (size_t)state;
}

static void unlink_conn(h2o_conn_t *conn)
{
    --*get_connection_state_counter(conn->ctx, conn->state);
    h2o_linklist_unlink(&conn->_conns);
}

static void link_conn(h2o_conn_t *conn)
{
    switch (conn->state) {
    case H2O_CONN_STATE_IDLE:
        h2o_linklist_insert(&conn->ctx->_conns.idle, &conn->_conns);
        break;
    case H2O_CONN_STATE_ACTIVE:
        h2o_linklist_insert(&conn->ctx->_conns.active, &conn->_conns);
        break;
    case H2O_CONN_STATE_SHUTDOWN:
        h2o_linklist_insert(&conn->ctx->_conns.shutdown, &conn->_conns);
        break;
    }
    ++*get_connection_state_counter(conn->ctx, conn->state);
}

h2o_conn_t *h2o_create_connection(size_t sz, h2o_context_t *ctx, h2o_hostconf_t **hosts, struct timeval connected_at,
                                  const h2o_conn_callbacks_t *callbacks)
{
    h2o_conn_t *conn = (h2o_conn_t *)h2o_mem_alloc(sz);

    conn->ctx = ctx;
    conn->hosts = hosts;
    conn->connected_at = connected_at;
#ifdef H2O_NO_64BIT_ATOMICS
    pthread_mutex_lock(&h2o_conn_id_mutex);
    conn->id = ++h2o_connection_id;
    pthread_mutex_unlock(&h2o_conn_id_mutex);
#else
    conn->id = __sync_add_and_fetch(&h2o_connection_id, 1);
#endif
    conn->callbacks = callbacks;
    conn->_uuid.is_initialized = 0;

    conn->state = H2O_CONN_STATE_ACTIVE;
    conn->_conns = (h2o_linklist_t){};
    link_conn(conn);

    return conn;
}

void h2o_destroy_connection(h2o_conn_t *conn)
{
    unlink_conn(conn);
    free(conn);
}

void h2o_conn_set_state(h2o_conn_t *conn, h2o_conn_state_t state)
{
    if (conn->state != state) {
        unlink_conn(conn);
        conn->state = state;
        link_conn(conn);
    }
}
