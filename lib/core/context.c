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
#include "h2o.h"
#include "h2o/memcached.h"

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
    ctx->proxy.connpool.socketpool = &ctx->globalconf->proxy.global_socketpool;
    ctx->proxy.spare_pipes.pipes = h2o_mem_alloc(sizeof(ctx->proxy.spare_pipes.pipes[0]) * config->proxy.max_spare_pipes);
    h2o_linklist_init_anchor(&ctx->proxy.connpool.http2.conns);

#ifdef __linux__
    /* pre-fill the pipe cache at context init */
    for (i = 0; i < config->proxy.max_spare_pipes; ++i) {
        if (pipe2(ctx->proxy.spare_pipes.pipes[i], O_NONBLOCK | O_CLOEXEC) != 0) {
            char errbuf[256];
            h2o_fatal("pipe2(2) failed:%s", h2o_strerror_r(errno, errbuf, sizeof(errbuf)));
        }
        ctx->proxy.spare_pipes.count++;
    }
#endif

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
    size_t i, j;

    for (size_t i = 0; i < ctx->proxy.spare_pipes.count; ++i) {
        close(ctx->proxy.spare_pipes.pipes[i][0]);
        close(ctx->proxy.spare_pipes.pipes[i][1]);
    }
    free(ctx->proxy.spare_pipes.pipes);

    h2o_socketpool_unregister_loop(&ctx->globalconf->proxy.global_socketpool, ctx->loop);

    for (i = 0; config->hosts[i] != NULL; ++i) {
        h2o_hostconf_t *hostconf = config->hosts[i];
        for (j = 0; j != hostconf->paths.size; ++j) {
            h2o_pathconf_t *pathconf = hostconf->paths.entries[j];
            h2o_context_dispose_pathconf_context(ctx, pathconf);
        }
        h2o_context_dispose_pathconf_context(ctx, &hostconf->fallback_path);
    }
    free(ctx->_pathconfs_inited.entries);
    free(ctx->_module_configs);
    /* what should we do here? assert(!h2o_linklist_is_empty(&ctx->http2._conns); */

    h2o_filecache_destroy(ctx->filecache);
    ctx->filecache = NULL;

    /* clear storage */
    for (i = 0; i != ctx->storage.size; ++i) {
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
