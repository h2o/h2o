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
    uint64_t emitted_status_errors[H2O_STATUS_ERROR_MAX];
    uint64_t h2_protocol_level_errors[H2O_HTTP2_ERROR_MAX];
    uint64_t h2_read_closed;
    uint64_t h2_write_closed;
    uint64_t h2_idle_timeout;
    uint64_t h1_request_timeout;
    uint64_t h1_request_io_timeout;
    uint64_t ssl_errors;
    struct {
        uint64_t packet_forwarded;
        uint64_t forwarded_packet_received;
        QUICLY_STATS_PREBUILT_FIELDS;
    } http3;
    pthread_mutex_t mutex;
};

static void events_status_per_thread(void *priv, h2o_context_t *ctx)
{
    size_t i;
    struct st_events_status_ctx_t *esc = priv;

    pthread_mutex_lock(&esc->mutex);

    for (i = 0; i < H2O_STATUS_ERROR_MAX; i++) {
        esc->emitted_status_errors[i] += ctx->emitted_error_status[i];
    }
    esc->ssl_errors += ctx->ssl.errors;
    for (i = 0; i < H2O_HTTP2_ERROR_MAX; i++) {
        esc->h2_protocol_level_errors[i] += ctx->http2.events.protocol_level_errors[i];
    }
    esc->h2_read_closed += ctx->http2.events.read_closed;
    esc->h2_write_closed += ctx->http2.events.write_closed;
    esc->h2_idle_timeout += ctx->http2.events.idle_timeouts;
    esc->h1_request_timeout += ctx->http1.events.request_timeouts;
    esc->h1_request_io_timeout += ctx->http1.events.request_io_timeouts;
    esc->http3.packet_forwarded += ctx->http3.events.packet_forwarded;
    esc->http3.forwarded_packet_received += ctx->http3.events.forwarded_packet_received;
    esc->http3.num_packets.received += ctx->http3.num_packets.received;
    esc->http3.num_packets.decryption_failed += ctx->http3.num_packets.decryption_failed;
    esc->http3.num_packets.sent += ctx->http3.num_packets.sent;
    esc->http3.num_packets.lost += ctx->http3.num_packets.lost;
    esc->http3.num_packets.lost_time_threshold += ctx->http3.num_packets.lost_time_threshold;
    esc->http3.num_packets.ack_received += ctx->http3.num_packets.ack_received;
    esc->http3.num_packets.late_acked += ctx->http3.num_packets.late_acked;
    esc->http3.num_bytes.received += ctx->http3.num_bytes.received;
    esc->http3.num_bytes.sent += ctx->http3.num_bytes.sent;
    esc->http3.num_frames_sent.padding += ctx->http3.num_frames_sent.padding;
    esc->http3.num_frames_sent.ping += ctx->http3.num_frames_sent.ping;
    esc->http3.num_frames_sent.ack += ctx->http3.num_frames_sent.ack;
    esc->http3.num_frames_sent.reset_stream += ctx->http3.num_frames_sent.reset_stream;
    esc->http3.num_frames_sent.stop_sending += ctx->http3.num_frames_sent.stop_sending;
    esc->http3.num_frames_sent.crypto += ctx->http3.num_frames_sent.crypto;
    esc->http3.num_frames_sent.new_token += ctx->http3.num_frames_sent.new_token;
    esc->http3.num_frames_sent.stream += ctx->http3.num_frames_sent.stream;
    esc->http3.num_frames_sent.max_data += ctx->http3.num_frames_sent.max_data;
    esc->http3.num_frames_sent.max_stream_data += ctx->http3.num_frames_sent.max_stream_data;
    esc->http3.num_frames_sent.max_streams_bidi += ctx->http3.num_frames_sent.max_streams_bidi;
    esc->http3.num_frames_sent.max_streams_uni += ctx->http3.num_frames_sent.max_streams_uni;
    esc->http3.num_frames_sent.data_blocked += ctx->http3.num_frames_sent.data_blocked;
    esc->http3.num_frames_sent.stream_data_blocked += ctx->http3.num_frames_sent.stream_data_blocked;
    esc->http3.num_frames_sent.streams_blocked += ctx->http3.num_frames_sent.streams_blocked;
    esc->http3.num_frames_sent.new_connection_id += ctx->http3.num_frames_sent.new_connection_id;
    esc->http3.num_frames_sent.retire_connection_id += ctx->http3.num_frames_sent.retire_connection_id;
    esc->http3.num_frames_sent.path_challenge += ctx->http3.num_frames_sent.path_challenge;
    esc->http3.num_frames_sent.path_response += ctx->http3.num_frames_sent.path_response;
    esc->http3.num_frames_sent.transport_close += ctx->http3.num_frames_sent.transport_close;
    esc->http3.num_frames_sent.application_close += ctx->http3.num_frames_sent.application_close;
    esc->http3.num_frames_sent.handshake_done += ctx->http3.num_frames_sent.handshake_done;
    esc->http3.num_frames_sent.datagram += ctx->http3.num_frames_sent.datagram;
    esc->http3.num_frames_sent.ack_frequency += ctx->http3.num_frames_sent.ack_frequency;
    esc->http3.num_frames_received.padding += ctx->http3.num_frames_received.padding;
    esc->http3.num_frames_received.ping += ctx->http3.num_frames_received.ping;
    esc->http3.num_frames_received.ack += ctx->http3.num_frames_received.ack;
    esc->http3.num_frames_received.reset_stream += ctx->http3.num_frames_received.reset_stream;
    esc->http3.num_frames_received.stop_sending += ctx->http3.num_frames_received.stop_sending;
    esc->http3.num_frames_received.crypto += ctx->http3.num_frames_received.crypto;
    esc->http3.num_frames_received.new_token += ctx->http3.num_frames_received.new_token;
    esc->http3.num_frames_received.stream += ctx->http3.num_frames_received.stream;
    esc->http3.num_frames_received.max_data += ctx->http3.num_frames_received.max_data;
    esc->http3.num_frames_received.max_stream_data += ctx->http3.num_frames_received.max_stream_data;
    esc->http3.num_frames_received.max_streams_bidi += ctx->http3.num_frames_received.max_streams_bidi;
    esc->http3.num_frames_received.max_streams_uni += ctx->http3.num_frames_received.max_streams_uni;
    esc->http3.num_frames_received.data_blocked += ctx->http3.num_frames_received.data_blocked;
    esc->http3.num_frames_received.stream_data_blocked += ctx->http3.num_frames_received.stream_data_blocked;
    esc->http3.num_frames_received.streams_blocked += ctx->http3.num_frames_received.streams_blocked;
    esc->http3.num_frames_received.new_connection_id += ctx->http3.num_frames_received.new_connection_id;
    esc->http3.num_frames_received.retire_connection_id += ctx->http3.num_frames_received.retire_connection_id;
    esc->http3.num_frames_received.path_challenge += ctx->http3.num_frames_received.path_challenge;
    esc->http3.num_frames_received.path_response += ctx->http3.num_frames_received.path_response;
    esc->http3.num_frames_received.transport_close += ctx->http3.num_frames_received.transport_close;
    esc->http3.num_frames_received.application_close += ctx->http3.num_frames_received.application_close;
    esc->http3.num_frames_received.handshake_done += ctx->http3.num_frames_received.handshake_done;
    esc->http3.num_frames_received.datagram += ctx->http3.num_frames_received.datagram;
    esc->http3.num_frames_received.ack_frequency += ctx->http3.num_frames_received.ack_frequency;
    esc->http3.num_ptos += ctx->http3.num_ptos;
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

static h2o_iovec_t events_status_final(void *priv, h2o_globalconf_t *gconf, h2o_req_t *req)
{
    struct st_events_status_ctx_t *esc = priv;
    h2o_iovec_t ret;

#define H1_AGG_ERR(status_) esc->emitted_status_errors[H2O_STATUS_ERROR_##status_]
#define H2_AGG_ERR(err_) esc->h2_protocol_level_errors[-H2O_HTTP2_ERROR_##err_]
#define BUFSIZE (8 * 1024)
    ret.base = h2o_mem_alloc_pool(&req->pool, char, BUFSIZE);
    ret.len = snprintf(
        ret.base, BUFSIZE, ",\n"
                           " \"status-errors.400\": %" PRIu64 ",\n"
                           " \"status-errors.403\": %" PRIu64 ",\n"
                           " \"status-errors.404\": %" PRIu64 ",\n"
                           " \"status-errors.405\": %" PRIu64 ",\n"
                           " \"status-errors.416\": %" PRIu64 ",\n"
                           " \"status-errors.417\": %" PRIu64 ",\n"
                           " \"status-errors.500\": %" PRIu64 ",\n"
                           " \"status-errors.502\": %" PRIu64 ",\n"
                           " \"status-errors.503\": %" PRIu64 ",\n"
                           " \"http1-errors.request-timeout\": %" PRIu64 ",\n"
                           " \"http1-errors.request-io-timeout\": %" PRIu64 ",\n"
                           " \"http2-errors.protocol\": %" PRIu64 ", \n"
                           " \"http2-errors.internal\": %" PRIu64 ", \n"
                           " \"http2-errors.flow-control\": %" PRIu64 ", \n"
                           " \"http2-errors.settings-timeout\": %" PRIu64 ", \n"
                           " \"http2-errors.stream-closed\": %" PRIu64 ", \n"
                           " \"http2-errors.frame-size\": %" PRIu64 ", \n"
                           " \"http2-errors.refused-stream\": %" PRIu64 ", \n"
                           " \"http2-errors.cancel\": %" PRIu64 ", \n"
                           " \"http2-errors.compression\": %" PRIu64 ", \n"
                           " \"http2-errors.connect\": %" PRIu64 ", \n"
                           " \"http2-errors.enhance-your-calm\": %" PRIu64 ", \n"
                           " \"http2-errors.inadequate-security\": %" PRIu64 ", \n"
                           " \"http2.read-closed\": %" PRIu64 ", \n"
                           " \"http2.write-closed\": %" PRIu64 ", \n"
                           " \"http2.idle-timeout\": %" PRIu64 ", \n"
                           " \"http3.packet-forwarded\": %" PRIu64 ", \n"
                           " \"http3.forwarded-packet-received\": %" PRIu64 ", \n"
                           " \"http3.num_packets.received\": %" PRIu64 ", \n"
                           " \"http3.num_packets.decryption_failed\": %" PRIu64 ", \n"
                           " \"http3.num_packets.sent\": %" PRIu64 ", \n"
                           " \"http3.num_packets.lost\": %" PRIu64 ", \n"
                           " \"http3.num_packets.lost_time_threshold\": %" PRIu64 ", \n"
                           " \"http3.num_packets.ack_received\": %" PRIu64 ", \n"
                           " \"http3.num_packets.late_acked\": %" PRIu64 ", \n"
                           " \"http3.num_bytes.received\": %" PRIu64 ", \n"
                           " \"http3.num_bytes.sent\": %" PRIu64 ", \n"
                           " \"http3.num_frames_sent.padding\": %" PRIu64 ", \n"
                           " \"http3.num_frames_sent.ping\": %" PRIu64 ", \n"
                           " \"http3.num_frames_sent.ack\": %" PRIu64 ", \n"
                           " \"http3.num_frames_sent.reset_stream\": %" PRIu64 ", \n"
                           " \"http3.num_frames_sent.stop_sending\": %" PRIu64 ", \n"
                           " \"http3.num_frames_sent.crypto\": %" PRIu64 ", \n"
                           " \"http3.num_frames_sent.new_token\": %" PRIu64 ", \n"
                           " \"http3.num_frames_sent.stream\": %" PRIu64 ", \n"
                           " \"http3.num_frames_sent.max_data\": %" PRIu64 ", \n"
                           " \"http3.num_frames_sent.max_stream_data\": %" PRIu64 ", \n"
                           " \"http3.num_frames_sent.max_streams_bidi\": %" PRIu64 ", \n"
                           " \"http3.num_frames_sent.max_streams_uni\": %" PRIu64 ", \n"
                           " \"http3.num_frames_sent.data_blocked\": %" PRIu64 ", \n"
                           " \"http3.num_frames_sent.stream_data_blocked\": %" PRIu64 ", \n"
                           " \"http3.num_frames_sent.streams_blocked\": %" PRIu64 ", \n"
                           " \"http3.num_frames_sent.new_connection_id\": %" PRIu64 ", \n"
                           " \"http3.num_frames_sent.retire_connection_id\": %" PRIu64 ", \n"
                           " \"http3.num_frames_sent.path_challenge\": %" PRIu64 ", \n"
                           " \"http3.num_frames_sent.path_response\": %" PRIu64 ", \n"
                           " \"http3.num_frames_sent.transport_close\": %" PRIu64 ", \n"
                           " \"http3.num_frames_sent.application_close\": %" PRIu64 ", \n"
                           " \"http3.num_frames_sent.handshake_done\": %" PRIu64 ", \n"
                           " \"http3.num_frames_sent.datagram\": %" PRIu64 ", \n"
                           " \"http3.num_frames_sent.ack_frequency\": %" PRIu64 ", \n"
                           " \"http3.num_frames_received.padding\": %" PRIu64 ", \n"
                           " \"http3.num_frames_received.ping\": %" PRIu64 ", \n"
                           " \"http3.num_frames_received.ack\": %" PRIu64 ", \n"
                           " \"http3.num_frames_received.reset_stream\": %" PRIu64 ", \n"
                           " \"http3.num_frames_received.stop_sending\": %" PRIu64 ", \n"
                           " \"http3.num_frames_received.crypto\": %" PRIu64 ", \n"
                           " \"http3.num_frames_received.new_token\": %" PRIu64 ", \n"
                           " \"http3.num_frames_received.stream\": %" PRIu64 ", \n"
                           " \"http3.num_frames_received.max_data\": %" PRIu64 ", \n"
                           " \"http3.num_frames_received.max_stream_data\": %" PRIu64 ", \n"
                           " \"http3.num_frames_received.max_streams_bidi\": %" PRIu64 ", \n"
                           " \"http3.num_frames_received.max_streams_uni\": %" PRIu64 ", \n"
                           " \"http3.num_frames_received.data_blocked\": %" PRIu64 ", \n"
                           " \"http3.num_frames_received.stream_data_blocked\": %" PRIu64 ", \n"
                           " \"http3.num_frames_received.streams_blocked\": %" PRIu64 ", \n"
                           " \"http3.num_frames_received.new_connection_id\": %" PRIu64 ", \n"
                           " \"http3.num_frames_received.retire_connection_id\": %" PRIu64 ", \n"
                           " \"http3.num_frames_received.path_challenge\": %" PRIu64 ", \n"
                           " \"http3.num_frames_received.path_response\": %" PRIu64 ", \n"
                           " \"http3.num_frames_received.transport_close\": %" PRIu64 ", \n"
                           " \"http3.num_frames_received.application_close\": %" PRIu64 ", \n"
                           " \"http3.num_frames_received.handshake_done\": %" PRIu64 ", \n"
                           " \"http3.num_frames_received.datagram\": %" PRIu64 ", \n"
                           " \"http3.num_frames_received.ack_frequency\": %" PRIu64 ", \n"
                           " \"http3.num_ptos\": %" PRIu64 ", \n"
                           " \"ssl.errors\": %" PRIu64 ", \n"
                           " \"memory.mmap_errors\": %zu\n",
        H1_AGG_ERR(400), H1_AGG_ERR(403), H1_AGG_ERR(404), H1_AGG_ERR(405), H1_AGG_ERR(416), H1_AGG_ERR(417), H1_AGG_ERR(500),
        H1_AGG_ERR(502), H1_AGG_ERR(503), esc->h1_request_timeout, esc->h1_request_io_timeout, H2_AGG_ERR(PROTOCOL),
        H2_AGG_ERR(INTERNAL), H2_AGG_ERR(FLOW_CONTROL), H2_AGG_ERR(SETTINGS_TIMEOUT), H2_AGG_ERR(STREAM_CLOSED),
        H2_AGG_ERR(FRAME_SIZE), H2_AGG_ERR(REFUSED_STREAM), H2_AGG_ERR(CANCEL), H2_AGG_ERR(COMPRESSION), H2_AGG_ERR(CONNECT),
        H2_AGG_ERR(ENHANCE_YOUR_CALM), H2_AGG_ERR(INADEQUATE_SECURITY), esc->h2_read_closed, esc->h2_write_closed,
        esc->h2_idle_timeout, esc->http3.packet_forwarded, esc->http3.forwarded_packet_received, esc->http3.num_packets.received,
        esc->http3.num_packets.decryption_failed, esc->http3.num_packets.sent, esc->http3.num_packets.lost,
        esc->http3.num_packets.lost_time_threshold, esc->http3.num_packets.ack_received, esc->http3.num_packets.late_acked,
        esc->http3.num_bytes.received, esc->http3.num_bytes.sent, esc->http3.num_frames_sent.padding,
        esc->http3.num_frames_sent.ping, esc->http3.num_frames_sent.ack, esc->http3.num_frames_sent.reset_stream,
        esc->http3.num_frames_sent.stop_sending, esc->http3.num_frames_sent.crypto, esc->http3.num_frames_sent.new_token,
        esc->http3.num_frames_sent.stream, esc->http3.num_frames_sent.max_data, esc->http3.num_frames_sent.max_stream_data,
        esc->http3.num_frames_sent.max_streams_bidi, esc->http3.num_frames_sent.max_streams_uni,
        esc->http3.num_frames_sent.data_blocked, esc->http3.num_frames_sent.stream_data_blocked,
        esc->http3.num_frames_sent.streams_blocked, esc->http3.num_frames_sent.new_connection_id,
        esc->http3.num_frames_sent.retire_connection_id, esc->http3.num_frames_sent.path_challenge,
        esc->http3.num_frames_sent.path_response, esc->http3.num_frames_sent.transport_close,
        esc->http3.num_frames_sent.application_close, esc->http3.num_frames_sent.handshake_done,
        esc->http3.num_frames_sent.datagram, esc->http3.num_frames_sent.ack_frequency, esc->http3.num_frames_received.padding,
        esc->http3.num_frames_received.ping, esc->http3.num_frames_received.ack, esc->http3.num_frames_received.reset_stream,
        esc->http3.num_frames_received.stop_sending, esc->http3.num_frames_received.crypto,
        esc->http3.num_frames_received.new_token, esc->http3.num_frames_received.stream, esc->http3.num_frames_received.max_data,
        esc->http3.num_frames_received.max_stream_data, esc->http3.num_frames_received.max_streams_bidi,
        esc->http3.num_frames_received.max_streams_uni, esc->http3.num_frames_received.data_blocked,
        esc->http3.num_frames_received.stream_data_blocked, esc->http3.num_frames_received.streams_blocked,
        esc->http3.num_frames_received.new_connection_id, esc->http3.num_frames_received.retire_connection_id,
        esc->http3.num_frames_received.path_challenge, esc->http3.num_frames_received.path_response,
        esc->http3.num_frames_received.transport_close, esc->http3.num_frames_received.application_close,
        esc->http3.num_frames_received.handshake_done, esc->http3.num_frames_received.datagram,
        esc->http3.num_frames_received.ack_frequency, esc->http3.num_ptos, esc->ssl_errors, h2o_mmap_errors);
    pthread_mutex_destroy(&esc->mutex);
    free(esc);
    return ret;
#undef BUFSIZE
#undef H1_AGG_ERR
#undef H2_AGG_ERR
}

h2o_status_handler_t h2o_events_status_handler = {
    {H2O_STRLIT("events")}, events_status_final, events_status_init, events_status_per_thread};
