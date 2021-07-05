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

#include <assert.h>
#include <malloc.h>
#include "khash.h"
#include "quicly.h"
#include "quicly/sendstate.h"
#include "quicly/recvstate.h"
#include "quicly_mock.h"

KHASH_MAP_INIT_INT64(quicly_stream_t, quicly_stream_t *)

mquicly_context_t mquicly_context;

struct st_quicly_conn_t {
    struct _st_quicly_conn_public_t super;
    khash_t(quicly_stream_t) * streams;
};

struct st_quicly_send_context_t {
};

static quicly_conn_t *create_connection(quicly_context_t *ctx, int is_client, struct sockaddr *remote_addr,
                                        struct sockaddr *local_addr)
{
    quicly_conn_t *conn = calloc(1, sizeof(*conn));
    assert(conn != NULL);
    conn->super.ctx = ctx;
    if (is_client) {
        conn->super.local.bidi.next_stream_id = 0;
        conn->super.local.uni.next_stream_id = 2;
        conn->super.remote.bidi.next_stream_id = 1;
        conn->super.remote.uni.next_stream_id = 3;
    } else {
        conn->super.local.bidi.next_stream_id = 1;
        conn->super.local.uni.next_stream_id = 3;
        conn->super.remote.bidi.next_stream_id = 0;
        conn->super.remote.uni.next_stream_id = 2;
    }
    conn->streams = kh_init(quicly_stream_t);

    conn->super.local.address.sa = *local_addr;
    conn->super.remote.address.sa = *remote_addr;

    return conn;
}

int quicly_accept(quicly_conn_t **conn, quicly_context_t *ctx, struct sockaddr *dest_addr, struct sockaddr *src_addr,
                  quicly_decoded_packet_t *packet, quicly_address_token_plaintext_t *address_token,
                  const quicly_cid_plaintext_t *new_cid, ptls_handshake_properties_t *handshake_properties)
{
    *conn = create_connection(ctx, 0, src_addr, dest_addr);
    (*conn)->super.state = QUICLY_STATE_CONNECTED;
    return 0;
}

int quicly_stream_sync_sendbuf(quicly_stream_t *stream, int activate)
{
    int ret;

    if (activate) {
        if ((ret = quicly_sendstate_activate(&stream->sendstate)) != 0)
            return ret;
    }

    quicly_stream_scheduler_t *scheduler = stream->conn->super.ctx->stream_scheduler;
    scheduler->update_state(scheduler, stream);
    return 0;
}

void quicly_stream_sync_recvbuf(quicly_stream_t *stream, size_t shift_amount)
{
    stream->recvstate.data_off += shift_amount;
}

int quicly_stream_can_send(quicly_stream_t *stream, int at_stream_level)
{
    /* return if there is nothing to be sent */
    if (stream->sendstate.pending.num_ranges == 0)
        return 0;
    return 1;
}

ptls_t *quicly_get_tls(quicly_conn_t *conn)
{
    /* TODO: is this okay */
    return NULL;
}

int quicly_is_blocked(quicly_conn_t *conn)
{
    return 0;
}

void quicly_request_stop(quicly_stream_t *stream, int err)
{
    stream->_send_aux.stop_sending.sender_state = QUICLY_SENDER_STATE_SEND;
}

void quicly_reset_stream(quicly_stream_t *stream, int err)
{
    /* dispose sendbuf state */
    quicly_sendstate_reset(&stream->sendstate);

    stream->_send_aux.reset_stream.sender_state = QUICLY_SENDER_STATE_SEND;

    /* inline expansion of resched_stream_data() */
    /* TODO: consider streams_blocked? */
    quicly_stream_scheduler_t *scheduler = stream->conn->super.ctx->stream_scheduler;
    scheduler->update_state(scheduler, stream);
}

socklen_t quicly_get_socklen(struct sockaddr *sa)
{
    switch (sa->sa_family) {
    case AF_INET:
        return sizeof(struct sockaddr_in);
    case AF_INET6:
        return sizeof(struct sockaddr_in6);
    default:
        assert(!"unexpected socket type");
        return 0;
    }
}

size_t quicly_decode_packet(quicly_context_t *ctx, quicly_decoded_packet_t *packet, const uint8_t *datagram, size_t datagram_size,
                            size_t *off)
{
    assert(0 && "unimplemented");
    return 0;
}

int quicly_send_stream(quicly_stream_t *stream, quicly_send_context_t *s)
{
    /* quicly_send -> scheduler->do_send -> quicly_send_stream -> on_send_emit */
    uint8_t buff[1024];
    uint64_t off = stream->sendstate.pending.ranges[0].start, end_off;
    size_t capacity = sizeof(buff);
    int wrote_all = 0, is_fin;
    int ret;

    if (!quicly_sendstate_is_open(&stream->sendstate) && off == stream->sendstate.final_size) {
        /* special case for emitting FIN only */
        end_off = off;
        wrote_all = 1;
        is_fin = 1;
        goto UpdateState;
    }
    { /* cap the capacity to the current range */
        uint64_t range_capacity = stream->sendstate.pending.ranges[0].end - off;
        if (!quicly_sendstate_is_open(&stream->sendstate) && off + range_capacity > stream->sendstate.final_size) {
            assert(range_capacity > 1); /* see the special case above */
            range_capacity -= 1;
        }
        if (capacity > range_capacity)
            capacity = range_capacity;
    }
    size_t len = capacity;
    size_t emit_off = (size_t)(off - stream->sendstate.acked.ranges[0].end);
    stream->callbacks->on_send_emit(stream, emit_off, buff, &len, &wrote_all);

    end_off = off + len;

    /* determine if the frame incorporates FIN */
    if (!quicly_sendstate_is_open(&stream->sendstate) && end_off == stream->sendstate.final_size) {
        is_fin = 1;
    } else {
        is_fin = 0;
    }

UpdateState:
    /* notify the fuzzing driver of stream send event */
    if (mquicly_context.on_stream_send != NULL) {
        mquicly_context.on_stream_send->cb(mquicly_context.on_stream_send, stream->conn, stream, buff, off, len, is_fin);
    }
    if (stream->sendstate.size_inflight < end_off) {
        stream->sendstate.size_inflight = end_off;
    }
    if ((ret = quicly_ranges_subtract(&stream->sendstate.pending, off, end_off + is_fin)) != 0)
        return ret;
    if (wrote_all) {
        if ((ret = quicly_ranges_subtract(&stream->sendstate.pending, stream->sendstate.size_inflight, UINT64_MAX)) != 0)
            return ret;
    }

    return 0;
}

static quicly_stream_t *open_stream(quicly_conn_t *conn, quicly_stream_id_t stream_id)
{
    quicly_stream_t *stream;

    if ((stream = calloc(1, sizeof(*stream))) == NULL)
        return NULL;
    stream->conn = conn;
    stream->stream_id = stream_id;
    stream->callbacks = NULL;
    stream->data = NULL;

    int r;
    khiter_t iter = kh_put(quicly_stream_t, conn->streams, stream_id, &r);
    assert(iter != kh_end(conn->streams));
    kh_val(conn->streams, iter) = stream;

    int is_client = quicly_is_client(stream->conn);

    if (quicly_stream_has_send_side(is_client, stream->stream_id)) {
        quicly_sendstate_init(&stream->sendstate);
    } else {
        quicly_sendstate_init_closed(&stream->sendstate);
    }
    if (quicly_stream_has_receive_side(is_client, stream->stream_id)) {
        quicly_recvstate_init(&stream->recvstate);
    } else {
        quicly_recvstate_init_closed(&stream->recvstate);
    }

    return stream;
}

static struct st_quicly_conn_streamgroup_state_t *get_streamgroup_state(quicly_conn_t *conn, int is_remote_initiated,
                                                                        int unidirectional)
{
    struct st_quicly_conn_streamgroup_state_t *group;
    if (unidirectional) {
        if (is_remote_initiated)
            group = &conn->super.remote.uni;
        else
            group = &conn->super.local.uni;
    } else {
        if (is_remote_initiated)
            group = &conn->super.remote.bidi;
        else
            group = &conn->super.local.bidi;
    }
    return group;
}

int mquicly_open_stream(quicly_conn_t *conn, quicly_stream_t **stream, int is_remote_initiated, int unidirectional)
{
    struct st_quicly_conn_streamgroup_state_t *group = get_streamgroup_state(conn, is_remote_initiated, unidirectional);

    *stream = open_stream(conn, group->next_stream_id);
    group->next_stream_id += 4;
    group->num_streams++;

    conn->super.ctx->stream_open->cb(conn->super.ctx->stream_open, *stream);

    return 0;
}

static void destroy_stream(quicly_stream_t *stream, int err)
{
    quicly_conn_t *conn = stream->conn;

    if (stream->callbacks != NULL)
        stream->callbacks->on_destroy(stream, err);

    khiter_t iter = kh_get(quicly_stream_t, conn->streams, stream->stream_id);
    assert(iter != kh_end(conn->streams));
    kh_del(quicly_stream_t, conn->streams, iter);

    struct st_quicly_conn_streamgroup_state_t *group = get_streamgroup_state(
        conn, !quicly_stream_is_client_initiated(stream->stream_id), quicly_stream_is_unidirectional(stream->stream_id));
    --group->num_streams;

    quicly_sendstate_dispose(&stream->sendstate);
    quicly_recvstate_dispose(&stream->recvstate);

    free(stream);
}

static void destroy_all_streams(quicly_conn_t *conn, int err)
{
    quicly_stream_t *stream;
    kh_foreach_value(conn->streams, stream, { destroy_stream(stream, err); });
    assert(quicly_num_streams(conn) == 0);
}

int mquicly_closed_by_remote(quicly_conn_t *conn, int err, uint64_t frame_type, ptls_iovec_t reason_phrase)
{
    /* TODO: invoke conn->super.ctx->closed_by_remote->cb() but h2o does not use it so far */
    assert(conn->super.ctx->closed_by_remote == NULL);
    conn->super.state = QUICLY_STATE_DRAINING;
    destroy_all_streams(conn, err);
    return 0;
}

int quicly_open_stream(quicly_conn_t *conn, quicly_stream_t **stream, int unidirectional)
{
    return mquicly_open_stream(conn, stream, 0, unidirectional);
}

int quicly_get_or_open_stream(quicly_conn_t *conn, uint64_t stream_id, quicly_stream_t **stream)
{
    /* conn->super.ctx->stream_open->cb */
    assert(0 && "unimplemented");
    return 0;
}

int quicly_is_destination(quicly_conn_t *conn, struct sockaddr *dest_addr, struct sockaddr *src_addr,
                          quicly_decoded_packet_t *decoded)
{
    assert(0 && "unimplemented");
    return 0;
}

uint32_t quicly_num_streams_by_group(quicly_conn_t *conn, int uni, int locally_initiated)
{
    assert(0 && "unimplemented");
    return 0;
}

int quicly_get_stats(quicly_conn_t *conn, quicly_stats_t *stats)
{
    /* Do nothing */
    memset(stats, 0, sizeof(*stats));
    return 0;
}

void quicly_stream_noop_on_destroy(quicly_stream_t *stream, int err)
{
}

void quicly_stream_noop_on_send_shift(quicly_stream_t *stream, size_t delta)
{
}

void quicly_stream_noop_on_send_emit(quicly_stream_t *stream, size_t off, void *dst, size_t *len, int *wrote_all)
{
}

void quicly_stream_noop_on_send_stop(quicly_stream_t *stream, int err)
{
}

void quicly_stream_noop_on_receive(quicly_stream_t *stream, size_t off, const void *src, size_t len)
{
}

void quicly_stream_noop_on_receive_reset(quicly_stream_t *stream, int err)
{
}

const quicly_stream_callbacks_t quicly_stream_noop_callbacks = {
    quicly_stream_noop_on_destroy,   quicly_stream_noop_on_send_shift, quicly_stream_noop_on_send_emit,
    quicly_stream_noop_on_send_stop, quicly_stream_noop_on_receive,    quicly_stream_noop_on_receive_reset};

size_t quicly_send_version_negotiation(quicly_context_t *ctx, ptls_iovec_t dest_cid, ptls_iovec_t src_cid, const uint32_t *versions,
                                       void *payload)
{
    assert(0 && "unimplemented");
    return 0;
}

size_t quicly_send_stateless_reset(quicly_context_t *ctx, const void *src_cid, void *payload)
{
    assert(0 && "unimplemented");
    return 0;
}

int quicly_can_send_data(quicly_conn_t *conn, quicly_send_context_t *s)
{
    return 1;
}

int quicly_connect(quicly_conn_t **conn, quicly_context_t *ctx, const char *server_name, struct sockaddr *dest_addr,
                   struct sockaddr *src_addr, const quicly_cid_plaintext_t *new_cid, ptls_iovec_t address_token,
                   ptls_handshake_properties_t *handshake_properties, const quicly_transport_parameters_t *resumed_transport_params)
{
    assert(0 && "unimplemented");
    return 0;
}

int quicly_connection_is_ready(quicly_conn_t *conn)
{
    assert(0 && "unimplemented");
    return 0;
}

void quicly_amend_ptls_context(ptls_context_t *ptls)
{
    assert(0 && "unimplemented");
}

int quicly_receive(quicly_conn_t *conn, struct sockaddr *dest_addr, struct sockaddr *src_addr, quicly_decoded_packet_t *packet)
{
    assert(0 && "unimplemented");
    return 0;
}

int quicly_close(quicly_conn_t *conn, int err, const char *reason_phrase)
{
    if (conn->super.state >= QUICLY_STATE_CLOSING)
        return 0;

    conn->super.state = QUICLY_STATE_CLOSING;
    return 0;
}

int64_t quicly_get_first_timeout(quicly_conn_t *conn)
{
    /* TODO: simulate delay */
    return conn->super.ctx->now->cb(conn->super.ctx->now) + 1;
}

void quicly_free(quicly_conn_t *conn)
{
    destroy_all_streams(conn, 0);
    kh_destroy(quicly_stream_t, conn->streams);
    free(conn);
}

int quicly_send(quicly_conn_t *conn, quicly_address_t *dest, quicly_address_t *src, struct iovec *datagrams, size_t *num_datagrams,
                void *buf, size_t bufsize)
{
    quicly_send_context_t s = {};
    int ret;
    if (conn->super.state >= QUICLY_STATE_CLOSING) {
        ret = QUICLY_ERROR_FREE_CONNECTION;
        goto Exit;
    }
    ret = conn->super.ctx->stream_scheduler->do_send(conn->super.ctx->stream_scheduler, conn, &s);

Exit:
    *num_datagrams = 0;
    return ret;
}

int quicly_foreach_stream(quicly_conn_t *conn, void *thunk, int (*cb)(void *thunk, quicly_stream_t *stream))
{
    assert(0 && "unimplemented");
    return 0;
}

const uint32_t quicly_supported_versions[] = {QUICLY_PROTOCOL_VERSION_1, QUICLY_PROTOCOL_VERSION_DRAFT29,
                                              QUICLY_PROTOCOL_VERSION_DRAFT27, 0};
