/*
 * Copyright (c) 2016 Fastly
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

#include "h2o.h"
#include <inttypes.h>

struct st_events_status_ctx_t {
    h2o_context_t agg;
    pthread_mutex_t mutex;
};
/* clang-format off */
static const char *status_error_labels[] = {
    "400",
    "403",
    "404",
    "405",
    "413",
    "416",
    "417",
    "500",
    "502",
    "503",
};
/* clang-format on */
_Static_assert(PTLS_ELEMENTSOF(status_error_labels) == PTLS_ELEMENTSOF(((struct st_h2o_context_t *)0)->stats.emitted_error_status),
               "There must be as much error labels as error status");

/* clang-format off */
static const char *http2_error_labels[] = {
    "none",
    "protocol",
    "internal",
    "flow_control",
    "settings_timeout",
    "stream_closed",
    "frame_size",
    "refused_stream",
    "cancel",
    "compression",
    "connect",
    "enhance_your_calm",
    "inadequate_security",
};
/* clang-format off */
_Static_assert(PTLS_ELEMENTSOF(http2_error_labels) == PTLS_ELEMENTSOF(((struct st_h2o_context_t *)0)->stats.http2.server.protocol_level_errors), "There must be as much error labels as error status");

static const struct st_h2o_stat_ops_t stat_ops[] = {
#define ADD_HIST(name, desc, member)                                                                                               \
    {                                                                                                                              \
        {H2O_STRLIT(name)}, {H2O_STRLIT(desc)}, offsetof(struct st_h2o_context_t, member), 1, NULL, hist_aggregate, hist_stringify,      \
            hist_prometheus,                                                                                                       \
    }
#define ADD_METRIC(name, desc, member)                                                                                             \
    {                                                                                                                              \
        {H2O_STRLIT(name)}, {H2O_STRLIT(desc)}, offsetof(struct st_h2o_context_t, member), 1, NULL, metric_aggregate, metric_stringify,  \
            metric_prometheus,                                                                                                     \
    }
#define ADD_GAUGE(name, desc, member)                                                                                              \
    {                                                                                                                              \
        {H2O_STRLIT(name)}, {H2O_STRLIT(desc)}, offsetof(struct st_h2o_context_t, member), 1,  NULL,metric_aggregate, gauge_stringify,   \
            gauge_prometheus,                                                                                                      \
    }
#define ADD_COUNTER(name, desc, member)                                                                                            \
    {                                                                                                                              \
        {H2O_STRLIT(name)}, {H2O_STRLIT(desc)}, offsetof(struct st_h2o_context_t, member), 1, NULL, metric_aggregate, counter_stringify, \
            counter_prometheus,                                                                                                    \
    }
#define ADD_COUNTER_ARRAY(name, desc, member, labels)                                                                                      \
    {                                                                                                                              \
        {H2O_STRLIT(name)}, {H2O_STRLIT(desc)}, offsetof(struct st_h2o_context_t, member),                                         \
            PTLS_ELEMENTSOF(((struct st_h2o_context_t *)0)->member), labels, metric_aggregate, counter_stringify, counter_prometheus       \
    }
    ADD_COUNTER_ARRAY("stats_emitted_error_status", "", stats.emitted_error_status, status_error_labels),
    ADD_COUNTER("stats_ssl_server_handshake_errors", "", stats.ssl.server.handshake_errors),
    ADD_COUNTER("stats_ssl_server_alpn_h1", "", stats.ssl.server.alpn_h1),
    ADD_COUNTER("stats_ssl_server_alpn_h2", "", stats.ssl.server.alpn_h2),
    ADD_COUNTER("stats_ssl_server_handshake_full", "", stats.ssl.server.handshake_full),
    ADD_COUNTER("stats_ssl_server_handshake_resume", "", stats.ssl.server.handshake_resume),
    ADD_COUNTER("stats_ssl_server_handshake_accum_time_full", "", stats.ssl.server.handshake_accum_time_full),
    ADD_COUNTER("stats_ssl_server_handshake_accum_time_resume", "", stats.ssl.server.handshake_accum_time_resume),

    ADD_COUNTER("stats_http1_server_request_timeouts", "", stats.http1.server.request_timeouts),
    ADD_COUNTER("stats_http1_server_request_io_timeouts", "", stats.http1.server.request_io_timeouts),

    ADD_COUNTER_ARRAY("stats_http2_server_protocol_level_errors", "", stats.http2.server.protocol_level_errors, http2_error_labels),
    ADD_COUNTER("stats_http2_server_read_closed", "", stats.http2.server.read_closed),
    ADD_COUNTER("stats_http2_server_write_closed", "", stats.http2.server.write_closed),
    ADD_COUNTER("stats_http2_server_idle_timeouts", "", stats.http2.server.idle_timeouts),

    ADD_COUNTER("stats_http3_server_packet_forwarded", "", stats.http3.server.packet_forwarded),
    ADD_COUNTER("stats_http3_server_forwarded_packet_received", "", stats.http3.server.forwarded_packet_received),
    ADD_COUNTER("stats_http3_server_quic_packets_received", "", stats.http3.server.quic.num_packets.received),
    ADD_COUNTER("stats_http3_server_quic_packets_decryption_failed", "", stats.http3.server.quic.num_packets.decryption_failed),
    ADD_COUNTER("stats_http3_server_quic_packets_sent", "", stats.http3.server.quic.num_packets.sent),
    ADD_COUNTER("stats_http3_server_quic_packets_lost", "", stats.http3.server.quic.num_packets.lost),
    ADD_COUNTER("stats_http3_server_quic_packets_lost_time_threshold", "", stats.http3.server.quic.num_packets.lost_time_threshold),
    ADD_COUNTER("stats_http3_server_quic_packets_ack_received", "", stats.http3.server.quic.num_packets.ack_received),
    ADD_COUNTER("stats_http3_server_quic_packets_late_acked", "", stats.http3.server.quic.num_packets.late_acked),
    ADD_COUNTER("stats_http3_server_quic_received_bytes", "", stats.http3.server.quic.num_bytes.received),
    ADD_COUNTER("stats_http3_server_quic_sent_bytes", "", stats.http3.server.quic.num_bytes.sent),
#undef ADD_HIST
#undef ADD_COUNTER
#undef ADD_GAUGE
#undef ADD_METRIC
};
static void events_status_per_thread(void *priv, h2o_context_t *ctx)
{
    struct st_events_status_ctx_t *esc = priv;

    pthread_mutex_lock(&esc->mutex);

    for (size_t i = 0; i < PTLS_ELEMENTSOF(stat_ops); i++) {
        const struct st_h2o_stat_ops_t *op = stat_ops + i;
        op->aggregate(op, &esc->agg, ctx);
    }

    pthread_mutex_unlock(&esc->mutex);
}

static void *events_status_init(void)
{
    struct st_events_status_ctx_t *ret;

    ret = h2o_mem_alloc(sizeof(*ret));
    memset(ret, 0, sizeof(*ret));
    pthread_mutex_init(&ret->mutex, NULL);

    return ret;
}

static void ctx_dispose(struct st_events_status_ctx_t *esc)
{
    pthread_mutex_destroy(&esc->mutex);
    free(esc);
}

static h2o_iovec_t events_status_json(void *priv, h2o_globalconf_t *gconf, h2o_req_t *req)
{
    struct st_events_status_ctx_t *esc = priv;
    h2o_iovec_t ret;
    h2o_buffer_t *buf;
    h2o_buffer_init(&buf, &h2o_socket_buffer_prototype);

    for (size_t i = 0; i < PTLS_ELEMENTSOF(stat_ops); i++) {
        const h2o_iovec_t prefix = h2o_iovec_init(H2O_STRLIT(",\n"));
        const struct st_h2o_stat_ops_t *op = stat_ops + i;
        h2o_buffer_reserve(&buf, buf->size + prefix.len);
        memcpy(buf->bytes + buf->size, prefix.base, prefix.len);
        buf->size += prefix.len;
        op->stringify(op, &esc->agg, &buf);
    }

    ret.base = h2o_mem_alloc_pool(&req->pool, char, buf->size);
    ret.len = buf->size;
    memcpy(ret.base, buf->bytes, buf->size);
    h2o_buffer_dispose(&buf);

    ctx_dispose(esc);

    return ret;
}

static h2o_iovec_t events_status_prometheus(void *priv, h2o_globalconf_t *gconf, h2o_req_t *req)
{
    struct st_events_status_ctx_t *esc = priv;
    h2o_iovec_t ret;
    h2o_buffer_t *buf;
    h2o_buffer_init(&buf, &h2o_socket_buffer_prototype);

    for (size_t i = 0; i < PTLS_ELEMENTSOF(stat_ops); i++) {
        const struct st_h2o_stat_ops_t *op = stat_ops + i;
        op->prometheus(op, &esc->agg, &buf);
    }

    ret.base = h2o_mem_alloc_pool(&req->pool, char, buf->size);
    ret.len = buf->size;
    memcpy(ret.base, buf->bytes, buf->size);

    h2o_buffer_dispose(&buf);
    ctx_dispose(esc);

    return ret;
}

h2o_status_handler_t h2o_events_status_handler = {
    {H2O_STRLIT("events")}, events_status_json, events_status_prometheus, events_status_init, events_status_per_thread};
