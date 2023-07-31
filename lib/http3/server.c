/*
 * Copyright (c) 2018 Fastly, Kazuho Oku
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
#include <sys/socket.h>
#include "khash.h"
#include "h2o/absprio.h"
#include "h2o/http3_common.h"
#include "h2o/http3_server.h"
#include "h2o/http3_internal.h"
#include "./../probes_.h"

/**
 * the scheduler
 */
struct st_h2o_http3_req_scheduler_t {
    struct {
        struct {
            h2o_linklist_t high;
            h2o_linklist_t low;
        } urgencies[H2O_ABSPRIO_NUM_URGENCY_LEVELS];
        size_t smallest_urgency;
    } active;
    h2o_linklist_t conn_blocked;
};

/**
 *
 */
struct st_h2o_http3_req_scheduler_node_t {
    h2o_linklist_t link;
    h2o_absprio_t priority;
    uint64_t call_cnt;
};

/**
 * callback used to compare precedence of the entries within the same urgency level (e.g., by comparing stream IDs)
 */
typedef int (*h2o_http3_req_scheduler_compare_cb)(struct st_h2o_http3_req_scheduler_t *sched,
                                                  const struct st_h2o_http3_req_scheduler_node_t *x,
                                                  const struct st_h2o_http3_req_scheduler_node_t *y);

/**
 * Once the size of the request body being received exceeds thit limit, streaming mode will be used (if possible), and the
 * concurrency of such requests would be limited to one per connection.
 */
#define H2O_HTTP3_REQUEST_BODY_MIN_BYTES_TO_BLOCK 10240

enum h2o_http3_server_stream_state {
    /**
     * receiving headers
     */
    H2O_HTTP3_SERVER_STREAM_STATE_RECV_HEADERS,
    /**
     * receiving request body (runs concurrently)
     */
    H2O_HTTP3_SERVER_STREAM_STATE_RECV_BODY_BEFORE_BLOCK,
    /**
     * blocked, waiting to be unblocked one by one (either in streaming mode or in non-streaming mode)
     */
    H2O_HTTP3_SERVER_STREAM_STATE_RECV_BODY_BLOCKED,
    /**
     * in non-streaming mode, receiving body
     */
    H2O_HTTP3_SERVER_STREAM_STATE_RECV_BODY_UNBLOCKED,
    /**
     * in non-streaming mode, waiting for the request to be processed
     */
    H2O_HTTP3_SERVER_STREAM_STATE_REQ_PENDING,
    /**
     * request has been processed, waiting for the response headers
     */
    H2O_HTTP3_SERVER_STREAM_STATE_SEND_HEADERS,
    /**
     * sending body (the generator MAY have closed, but the transmission to the client is still ongoing)
     */
    H2O_HTTP3_SERVER_STREAM_STATE_SEND_BODY,
    /**
     * all data has been sent and ACKed, waiting for the transport stream to close (req might be disposed when entering this state)
     */
    H2O_HTTP3_SERVER_STREAM_STATE_CLOSE_WAIT
};

struct st_h2o_http3_server_stream_t;
KHASH_MAP_INIT_INT64(stream, struct st_h2o_http3_server_stream_t *)

struct st_h2o_http3_server_conn_t {
    h2o_conn_t super;
    h2o_http3_conn_t h3;
    ptls_handshake_properties_t handshake_properties;
    /**
     * link-list of pending requests using st_h2o_http3_server_stream_t::link
     */
    struct {
        /**
         * holds streams in RECV_BODY_BLOCKED state. They are promoted one by one to the POST_BLOCK State.
         */
        h2o_linklist_t recv_body_blocked;
        /**
         * holds streams that are in request streaming mode.
         */
        h2o_linklist_t req_streaming;
        /**
         * holds streams in REQ_PENDING state or RECV_BODY_POST_BLOCK state (that is using streaming; i.e., write_req.cb != NULL).
         */
        h2o_linklist_t pending;
    } delayed_streams;
    /**
     * responses blocked by SETTINGS frame yet to arrive (e.g., CONNECT-UDP requests waiting for SETTINGS to see if
     * datagram-flow-id can be sent). There is no separate state for streams linked here, because these streams are techincally
     * indifferent from those that are currently queued by the filters after `h2o_send` is called.
     */
    h2o_linklist_t streams_resp_settings_blocked;
    /**
     * next application-level timeout
     */
    h2o_timer_t timeout;
    /**
     * counter (the order MUST match that of h2o_http3_server_stream_state; it is accessed by index via the use of counters[])
     */
    union {
        struct {
            uint32_t recv_headers;
            uint32_t recv_body_before_block;
            uint32_t recv_body_blocked;
            uint32_t recv_body_unblocked;
            uint32_t req_pending;
            uint32_t send_headers;
            uint32_t send_body;
            uint32_t close_wait;
        };
        uint32_t counters[1];
    } num_streams;
    /**
     * Number of streams that is request streaming. The state can be in either one of SEND_HEADERS, SEND_BODY, CLOSE_WAIT.
     */
    uint32_t num_streams_req_streaming;
    /**
     * number of streams in tunneling mode
     */
    uint32_t num_streams_tunnelling;
    /**
     * scheduler
     */
    struct {
        /**
         * States for request streams.
         */
        struct st_h2o_http3_req_scheduler_t reqs;
        /**
         * States for unidirectional streams. Each element is a bit vector where slot for each stream is defined as: 1 << stream_id.
         */
        struct {
            uint16_t active;
            uint16_t conn_blocked;
        } uni;
    } scheduler;
    /**
     * stream map used for datagram flows
     */
    khash_t(stream) * datagram_flows;
    /**
     * timeout entry used for graceful shutdown
     */
    h2o_timer_t _graceful_shutdown_timeout;
};

/**
 * sendvec, with additional field that contains the starting offset of the content
 */
struct st_h2o_http3_server_sendvec_t {
    h2o_sendvec_t vec;
    /**
     * Starting offset of the content carried by the vector, or UINT64_MAX if it is not carrying body
     */
    uint64_t entity_offset;
};

struct st_h2o_http3_server_stream_t {
    quicly_stream_t *quic;
    struct {
        h2o_buffer_t *buf;
        int (*handle_input)(struct st_h2o_http3_server_stream_t *stream, const uint8_t **src, const uint8_t *src_end,
                            int in_generator, const char **err_desc);
        uint64_t bytes_left_in_data_frame;
    } recvbuf;
    struct {
        H2O_VECTOR(struct st_h2o_http3_server_sendvec_t) vecs;
        size_t off_within_first_vec;
        size_t min_index_to_addref;
        uint64_t final_size, final_body_size;
        uint8_t data_frame_header_buf[9];
    } sendbuf;
    enum h2o_http3_server_stream_state state;
    h2o_linklist_t link;
    h2o_linklist_t link_resp_settings_blocked;
    h2o_ostream_t ostr_final;
    struct st_h2o_http3_req_scheduler_node_t scheduler;
    /**
     * if read is blocked
     */
    uint8_t read_blocked : 1;
    /**
     * if h2o_proceed_response has been invoked, or if the invocation has been requested
     */
    uint8_t proceed_requested : 1;
    /**
     * this flag is set by on_send_emit, triggers the invocation h2o_proceed_response in scheduler_do_send, used by do_send to
     * take different actions based on if it has been called while scheduler_do_send is running.
     */
    uint8_t proceed_while_sending : 1;
    /**
     * if a PRIORITY_UPDATE frame has been received
     */
    uint8_t received_priority_update : 1;
    /**
     * used in CLOSE_WAIT state to determine if h2o_dispose_request has been called
     */
    uint8_t req_disposed : 1;
    /**
     * indicates if the request is in streaming mode
     */
    uint8_t req_streaming : 1;
    /**
     * buffer to hold the request body (or a chunk of, if in streaming mode), or CONNECT payload
     */
    h2o_buffer_t *req_body;
    /**
     * flow ID used by masque over H3_DATAGRAMS
     */
    uint64_t datagram_flow_id;
    /**
     * the request. Placed at the end, as it holds the pool.
     */
    h2o_req_t req;
};

static int foreach_request(h2o_conn_t *_conn, int (*cb)(h2o_req_t *req, void *cbdata), void *cbdata);
static void initiate_graceful_shutdown(h2o_conn_t *_conn);
static void close_idle_connection(h2o_conn_t *_conn);
static void on_stream_destroy(quicly_stream_t *qs, int err);
static int handle_input_post_trailers(struct st_h2o_http3_server_stream_t *stream, const uint8_t **src, const uint8_t *src_end,
                                      int in_generator, const char **err_desc);
static int handle_input_expect_data(struct st_h2o_http3_server_stream_t *stream, const uint8_t **src, const uint8_t *src_end,
                                    int in_generator, const char **err_desc);

static const h2o_sendvec_callbacks_t self_allocated_vec_callbacks = {h2o_sendvec_read_raw, NULL},
                                     immutable_vec_callbacks = {h2o_sendvec_read_raw, NULL};

static int sendvec_size_is_for_recycle(size_t size)
{
    if (h2o_socket_ssl_buffer_allocator.conf->memsize / 2 <= size && size <= h2o_socket_ssl_buffer_allocator.conf->memsize)
        return 1;
    return 0;
}

static void dispose_sendvec(struct st_h2o_http3_server_sendvec_t *vec)
{
    if (vec->vec.callbacks == &self_allocated_vec_callbacks) {
        if (sendvec_size_is_for_recycle(vec->vec.len)) {
            h2o_mem_free_recycle(&h2o_socket_ssl_buffer_allocator, vec->vec.raw);
        } else {
            free(vec->vec.raw);
        }
    }
}

static void req_scheduler_init(struct st_h2o_http3_req_scheduler_t *sched)
{
    size_t i;

    for (i = 0; i < H2O_ABSPRIO_NUM_URGENCY_LEVELS; ++i) {
        h2o_linklist_init_anchor(&sched->active.urgencies[i].high);
        h2o_linklist_init_anchor(&sched->active.urgencies[i].low);
    }
    sched->active.smallest_urgency = i;
    h2o_linklist_init_anchor(&sched->conn_blocked);
}

static void req_scheduler_activate(struct st_h2o_http3_req_scheduler_t *sched, struct st_h2o_http3_req_scheduler_node_t *node,
                                   h2o_http3_req_scheduler_compare_cb comp)
{
    /* unlink if necessary */
    if (h2o_linklist_is_linked(&node->link))
        h2o_linklist_unlink(&node->link);

    if (!node->priority.incremental || node->call_cnt == 0) {
        /* non-incremental streams and the first emission of incremental streams go in strict order */
        h2o_linklist_t *anchor = &sched->active.urgencies[node->priority.urgency].high, *pos;
        for (pos = anchor->prev; pos != anchor; pos = pos->prev) {
            struct st_h2o_http3_req_scheduler_node_t *node_at_pos =
                H2O_STRUCT_FROM_MEMBER(struct st_h2o_http3_req_scheduler_node_t, link, pos);
            if (comp(sched, node_at_pos, node) < 0)
                break;
        }
        h2o_linklist_insert(pos->next, &node->link);
    } else {
        /* once sent, incremental streams go into a lower list */
        h2o_linklist_insert(&sched->active.urgencies[node->priority.urgency].low, &node->link);
    }

    /* book keeping */
    if (node->priority.urgency < sched->active.smallest_urgency)
        sched->active.smallest_urgency = node->priority.urgency;
}

static void req_scheduler_update_smallest_urgency_post_removal(struct st_h2o_http3_req_scheduler_t *sched, size_t changed)
{
    if (sched->active.smallest_urgency < changed)
        return;

    /* search from the location that *might* have changed */
    sched->active.smallest_urgency = changed;
    while (h2o_linklist_is_empty(&sched->active.urgencies[sched->active.smallest_urgency].high) &&
           h2o_linklist_is_empty(&sched->active.urgencies[sched->active.smallest_urgency].low)) {
        ++sched->active.smallest_urgency;
        if (sched->active.smallest_urgency >= H2O_ABSPRIO_NUM_URGENCY_LEVELS)
            break;
    }
}

static void req_scheduler_deactivate(struct st_h2o_http3_req_scheduler_t *sched, struct st_h2o_http3_req_scheduler_node_t *node)
{
    if (h2o_linklist_is_linked(&node->link))
        h2o_linklist_unlink(&node->link);

    req_scheduler_update_smallest_urgency_post_removal(sched, node->priority.urgency);
}

static void req_scheduler_setup_for_next(struct st_h2o_http3_req_scheduler_t *sched, struct st_h2o_http3_req_scheduler_node_t *node,
                                         h2o_http3_req_scheduler_compare_cb comp)
{
    assert(h2o_linklist_is_linked(&node->link));

    /* reschedule to achieve round-robin behavior */
    if (node->priority.incremental)
        req_scheduler_activate(sched, node, comp);
}

static void req_scheduler_conn_blocked(struct st_h2o_http3_req_scheduler_t *sched, struct st_h2o_http3_req_scheduler_node_t *node)
{
    if (h2o_linklist_is_linked(&node->link))
        h2o_linklist_unlink(&node->link);

    h2o_linklist_insert(&sched->conn_blocked, &node->link);

    req_scheduler_update_smallest_urgency_post_removal(sched, node->priority.urgency);
}

static void req_scheduler_unblock_conn_blocked(struct st_h2o_http3_req_scheduler_t *sched, h2o_http3_req_scheduler_compare_cb comp)
{
    while (!h2o_linklist_is_empty(&sched->conn_blocked)) {
        struct st_h2o_http3_req_scheduler_node_t *node =
            H2O_STRUCT_FROM_MEMBER(struct st_h2o_http3_req_scheduler_node_t, link, sched->conn_blocked.next);
        req_scheduler_activate(sched, node, comp);
    }
}

static int req_scheduler_compare_stream_id(struct st_h2o_http3_req_scheduler_t *sched,
                                           const struct st_h2o_http3_req_scheduler_node_t *x,
                                           const struct st_h2o_http3_req_scheduler_node_t *y)
{
    struct st_h2o_http3_server_stream_t *sx = H2O_STRUCT_FROM_MEMBER(struct st_h2o_http3_server_stream_t, scheduler, x),
                                        *sy = H2O_STRUCT_FROM_MEMBER(struct st_h2o_http3_server_stream_t, scheduler, y);
    if (sx->quic->stream_id < sy->quic->stream_id) {
        return -1;
    } else if (sx->quic->stream_id > sy->quic->stream_id) {
        return 1;
    } else {
        return 0;
    }
}

static struct st_h2o_http3_server_conn_t *get_conn(struct st_h2o_http3_server_stream_t *stream)
{
    return (void *)stream->req.conn;
}

static uint32_t *get_state_counter(struct st_h2o_http3_server_conn_t *conn, enum h2o_http3_server_stream_state state)
{
    return conn->num_streams.counters + (size_t)state;
}

static void tunnel_on_udp_read(h2o_req_t *_req, h2o_iovec_t *datagrams, size_t num_datagrams)
{
    struct st_h2o_http3_server_stream_t *stream = H2O_STRUCT_FROM_MEMBER(struct st_h2o_http3_server_stream_t, req, _req);
    h2o_http3_send_h3_datagrams(&get_conn(stream)->h3, stream->datagram_flow_id, datagrams, num_datagrams);
}

static void request_run_delayed(struct st_h2o_http3_server_conn_t *conn)
{
    if (!h2o_timer_is_linked(&conn->timeout))
        h2o_timer_link(conn->super.ctx->loop, 0, &conn->timeout);
}

static void check_run_blocked(struct st_h2o_http3_server_conn_t *conn)
{
    if (conn->num_streams.recv_body_unblocked + conn->num_streams_req_streaming == 0 &&
        !h2o_linklist_is_empty(&conn->delayed_streams.recv_body_blocked))
        request_run_delayed(conn);
}

static void pre_dispose_request(struct st_h2o_http3_server_stream_t *stream)
{
    struct st_h2o_http3_server_conn_t *conn = get_conn(stream);
    size_t i;

    /* release vectors */
    for (i = 0; i != stream->sendbuf.vecs.size; ++i)
        dispose_sendvec(stream->sendbuf.vecs.entries + i);

    /* dispose request body buffer */
    if (stream->req_body != NULL)
        h2o_buffer_dispose(&stream->req_body);

    /* clean up request streaming */
    if (stream->req_streaming && !stream->req.is_tunnel_req) {
        assert(conn->num_streams_req_streaming != 0);
        stream->req_streaming = 0;
        --conn->num_streams_req_streaming;
        check_run_blocked(conn);
    }

    /* remove stream from datagram flow list */
    if (stream->datagram_flow_id != UINT64_MAX) {
        khiter_t iter = kh_get(stream, conn->datagram_flows, stream->datagram_flow_id);
        /* it's possible the tunnel wasn't established yet */
        if (iter != kh_end(conn->datagram_flows))
            kh_del(stream, conn->datagram_flows, iter);
    }

    if (stream->req.is_tunnel_req)
        --get_conn(stream)->num_streams_tunnelling;
}

static void set_state(struct st_h2o_http3_server_stream_t *stream, enum h2o_http3_server_stream_state state, int in_generator)
{
    struct st_h2o_http3_server_conn_t *conn = get_conn(stream);
    enum h2o_http3_server_stream_state old_state = stream->state;

    H2O_PROBE_CONN(H3S_STREAM_SET_STATE, &conn->super, stream->quic->stream_id, (unsigned)state);

    --*get_state_counter(conn, old_state);
    stream->state = state;
    ++*get_state_counter(conn, stream->state);

    switch (state) {
    case H2O_HTTP3_SERVER_STREAM_STATE_RECV_BODY_BLOCKED:
        assert(conn->delayed_streams.recv_body_blocked.prev == &stream->link || !"stream is not registered to the recv_body list?");
        break;
    case H2O_HTTP3_SERVER_STREAM_STATE_CLOSE_WAIT: {
        if (h2o_linklist_is_linked(&stream->link))
            h2o_linklist_unlink(&stream->link);
        pre_dispose_request(stream);
        if (!in_generator) {
            h2o_dispose_request(&stream->req);
            stream->req_disposed = 1;
        }
        static const quicly_stream_callbacks_t close_wait_callbacks = {on_stream_destroy,
                                                                       quicly_stream_noop_on_send_shift,
                                                                       quicly_stream_noop_on_send_emit,
                                                                       quicly_stream_noop_on_send_stop,
                                                                       quicly_stream_noop_on_receive,
                                                                       quicly_stream_noop_on_receive_reset};
        stream->quic->callbacks = &close_wait_callbacks;
    } break;
    default:
        break;
    }
}

/**
 * Shutdowns a stream. Note that a request stream should not be shut down until receiving some QUIC frame that refers to that
 * stream, but we might might have created stream state due to receiving a PRIORITY_UPDATE frame prior to that (see
 * handle_priority_update_frame).
 */
static void shutdown_stream(struct st_h2o_http3_server_stream_t *stream, int stop_sending_code, int reset_code, int in_generator)
{
    assert(stream->state < H2O_HTTP3_SERVER_STREAM_STATE_CLOSE_WAIT);
    if (quicly_stream_has_receive_side(0, stream->quic->stream_id)) {
        quicly_request_stop(stream->quic, stop_sending_code);
        h2o_buffer_consume(&stream->recvbuf.buf, stream->recvbuf.buf->size);
    }
    if (quicly_stream_has_send_side(0, stream->quic->stream_id) && !quicly_sendstate_transfer_complete(&stream->quic->sendstate))
        quicly_reset_stream(stream->quic, reset_code);
    set_state(stream, H2O_HTTP3_SERVER_STREAM_STATE_CLOSE_WAIT, in_generator);
}

static socklen_t get_sockname(h2o_conn_t *_conn, struct sockaddr *sa)
{
    struct st_h2o_http3_server_conn_t *conn = (void *)_conn;
    struct sockaddr *src = quicly_get_sockname(conn->h3.super.quic);
    socklen_t len = src->sa_family == AF_UNSPEC ? sizeof(struct sockaddr) : quicly_get_socklen(src);
    memcpy(sa, src, len);
    return len;
}

static socklen_t get_peername(h2o_conn_t *_conn, struct sockaddr *sa)
{
    struct st_h2o_http3_server_conn_t *conn = (void *)_conn;
    struct sockaddr *src = quicly_get_peername(conn->h3.super.quic);
    socklen_t len = quicly_get_socklen(src);
    memcpy(sa, src, len);
    return len;
}

static ptls_t *get_ptls(h2o_conn_t *_conn)
{
    struct st_h2o_http3_server_conn_t *conn = (void *)_conn;
    return quicly_get_tls(conn->h3.super.quic);
}

static int get_skip_tracing(h2o_conn_t *conn)
{
    ptls_t *ptls = get_ptls(conn);
    return ptls_skip_tracing(ptls);
}

static uint64_t get_req_id(h2o_req_t *req)
{
    struct st_h2o_http3_server_stream_t *stream = H2O_STRUCT_FROM_MEMBER(struct st_h2o_http3_server_stream_t, req, req);
    return stream->quic->stream_id;
}

static uint32_t num_reqs_inflight(h2o_conn_t *_conn)
{
    struct st_h2o_http3_server_conn_t *conn = (void *)_conn;
    return quicly_num_streams_by_group(conn->h3.super.quic, 0, 0);
}

static quicly_tracer_t *get_tracer(h2o_conn_t *_conn)
{
    struct st_h2o_http3_server_conn_t *conn = (void *)_conn;
    return quicly_get_tracer(conn->h3.super.quic);
}

static h2o_iovec_t log_extensible_priorities(h2o_req_t *_req)
{
    struct st_h2o_http3_server_stream_t *stream = H2O_STRUCT_FROM_MEMBER(struct st_h2o_http3_server_stream_t, req, _req);
    char *buf = h2o_mem_alloc_pool(&stream->req.pool, char, sizeof("u=" H2O_UINT8_LONGEST_STR ",i=?1"));
    int len =
        sprintf(buf, "u=%" PRIu8 "%s", stream->scheduler.priority.urgency, stream->scheduler.priority.incremental ? ",i=?1" : "");
    return h2o_iovec_init(buf, len);
}

static h2o_iovec_t log_cc_name(h2o_req_t *req)
{
    struct st_h2o_http3_server_conn_t *conn = (struct st_h2o_http3_server_conn_t *)req->conn;
    quicly_stats_t stats;

    if (quicly_get_stats(conn->h3.super.quic, &stats) == 0)
        return h2o_iovec_init(stats.cc.type->name, strlen(stats.cc.type->name));
    return h2o_iovec_init(NULL, 0);
}

static h2o_iovec_t log_delivery_rate(h2o_req_t *req)
{
    struct st_h2o_http3_server_conn_t *conn = (struct st_h2o_http3_server_conn_t *)req->conn;
    quicly_rate_t rate;

    if (quicly_get_delivery_rate(conn->h3.super.quic, &rate) == 0 && rate.latest != 0) {
        char *buf = h2o_mem_alloc_pool(&req->pool, char, sizeof(H2O_UINT64_LONGEST_STR));
        size_t len = sprintf(buf, "%" PRIu64, rate.latest);
        return h2o_iovec_init(buf, len);
    }

    return h2o_iovec_init(NULL, 0);
}

static h2o_iovec_t log_tls_protocol_version(h2o_req_t *_req)
{
    return h2o_iovec_init(H2O_STRLIT("TLSv1.3"));
}

static h2o_iovec_t log_session_reused(h2o_req_t *req)
{
    struct st_h2o_http3_server_conn_t *conn = (struct st_h2o_http3_server_conn_t *)req->conn;
    ptls_t *tls = quicly_get_tls(conn->h3.super.quic);
    return ptls_is_psk_handshake(tls) ? h2o_iovec_init(H2O_STRLIT("1")) : h2o_iovec_init(H2O_STRLIT("0"));
}

static h2o_iovec_t log_cipher(h2o_req_t *req)
{
    struct st_h2o_http3_server_conn_t *conn = (struct st_h2o_http3_server_conn_t *)req->conn;
    ptls_t *tls = quicly_get_tls(conn->h3.super.quic);
    ptls_cipher_suite_t *cipher = ptls_get_cipher(tls);
    return cipher != NULL ? h2o_iovec_init(cipher->name, strlen(cipher->name)) : h2o_iovec_init(NULL, 0);
}

static h2o_iovec_t log_cipher_bits(h2o_req_t *req)
{
    struct st_h2o_http3_server_conn_t *conn = (struct st_h2o_http3_server_conn_t *)req->conn;
    ptls_t *tls = quicly_get_tls(conn->h3.super.quic);
    ptls_cipher_suite_t *cipher = ptls_get_cipher(tls);
    if (cipher == NULL)
        return h2o_iovec_init(NULL, 0);

    char *buf = h2o_mem_alloc_pool(&req->pool, char, sizeof(H2O_UINT16_LONGEST_STR));
    return h2o_iovec_init(buf, sprintf(buf, "%" PRIu16, (uint16_t)(cipher->aead->key_size * 8)));
}

static h2o_iovec_t log_session_id(h2o_req_t *_req)
{
    /* FIXME */
    return h2o_iovec_init(NULL, 0);
}

static h2o_iovec_t log_server_name(h2o_req_t *req)
{
    struct st_h2o_http3_server_conn_t *conn = (struct st_h2o_http3_server_conn_t *)req->conn;
    ptls_t *tls = quicly_get_tls(conn->h3.super.quic);
    const char *server_name = ptls_get_server_name(tls);
    return server_name != NULL ? h2o_iovec_init(server_name, strlen(server_name)) : h2o_iovec_init(NULL, 0);
}

static h2o_iovec_t log_negotiated_protocol(h2o_req_t *req)
{
    struct st_h2o_http3_server_conn_t *conn = (struct st_h2o_http3_server_conn_t *)req->conn;
    ptls_t *tls = quicly_get_tls(conn->h3.super.quic);
    const char *proto = ptls_get_negotiated_protocol(tls);
    return proto != NULL ? h2o_iovec_init(proto, strlen(proto)) : h2o_iovec_init(NULL, 0);
}

static h2o_iovec_t log_ech_config_id(h2o_req_t *req)
{
    struct st_h2o_http3_server_conn_t *conn = (struct st_h2o_http3_server_conn_t *)req->conn;
    ptls_t *tls = quicly_get_tls(conn->h3.super.quic);
    uint8_t config_id;

    if (ptls_is_ech_handshake(tls, &config_id, NULL, NULL)) {
        char *s = h2o_mem_alloc_pool(&req->pool, char, sizeof(H2O_UINT8_LONGEST_STR));
        size_t len = sprintf(s, "%" PRIu8, config_id);
        return h2o_iovec_init(s, len);
    } else {
        return h2o_iovec_init(NULL, 0);
    }
}

static h2o_iovec_t log_ech_kem(h2o_req_t *req)
{
    struct st_h2o_http3_server_conn_t *conn = (struct st_h2o_http3_server_conn_t *)req->conn;
    ptls_t *tls = quicly_get_tls(conn->h3.super.quic);
    ptls_hpke_kem_t *kem;

    if (ptls_is_ech_handshake(tls, NULL, &kem, NULL)) {
        return h2o_iovec_init(kem->keyex->name, strlen(kem->keyex->name));
    } else {
        return h2o_iovec_init(NULL, 0);
    }
}

static h2o_iovec_t log_ech_cipher(h2o_req_t *req)
{
    struct st_h2o_http3_server_conn_t *conn = (struct st_h2o_http3_server_conn_t *)req->conn;
    ptls_t *tls = quicly_get_tls(conn->h3.super.quic);
    ptls_hpke_cipher_suite_t *cipher;

    if (ptls_is_ech_handshake(tls, NULL, NULL, &cipher)) {
        return h2o_iovec_init(cipher->name, strlen(cipher->name));
    } else {
        return h2o_iovec_init(NULL, 0);
    }
}

static h2o_iovec_t log_ech_cipher_bits(h2o_req_t *req)
{
    struct st_h2o_http3_server_conn_t *conn = (struct st_h2o_http3_server_conn_t *)req->conn;
    ptls_t *tls = quicly_get_tls(conn->h3.super.quic);
    ptls_hpke_cipher_suite_t *cipher;

    if (ptls_is_ech_handshake(tls, NULL, NULL, &cipher)) {
        uint16_t bits = (uint16_t)(cipher->aead->key_size * 8);
        char *s = h2o_mem_alloc_pool(&req->pool, char, sizeof(H2O_UINT16_LONGEST_STR));
        size_t len = sprintf(s, "%" PRIu16, bits);
        return h2o_iovec_init(s, len);
    } else {
        return h2o_iovec_init(NULL, 0);
    }
}

static h2o_iovec_t log_stream_id(h2o_req_t *_req)
{
    struct st_h2o_http3_server_stream_t *stream = H2O_STRUCT_FROM_MEMBER(struct st_h2o_http3_server_stream_t, req, _req);
    char *buf = h2o_mem_alloc_pool(&stream->req.pool, char, sizeof(H2O_UINT64_LONGEST_STR));
    return h2o_iovec_init(buf, sprintf(buf, "%" PRIu64, stream->quic->stream_id));
}

static h2o_iovec_t log_quic_stats(h2o_req_t *req)
{
#define APPLY_NUM_FRAMES(f, dir)                                                                                                   \
    f(padding, dir) f(ping, dir) f(ack, dir) f(reset_stream, dir) f(stop_sending, dir) f(crypto, dir) f(new_token, dir)            \
        f(stream, dir) f(max_data, dir) f(max_stream_data, dir) f(max_streams_bidi, dir) f(max_streams_uni, dir)                   \
            f(data_blocked, dir) f(stream_data_blocked, dir) f(streams_blocked, dir) f(new_connection_id, dir)                     \
                f(retire_connection_id, dir) f(path_challenge, dir) f(path_response, dir) f(transport_close, dir)                  \
                    f(application_close, dir) f(handshake_done, dir) f(ack_frequency, dir)
#define FORMAT_OF_NUM_FRAMES(n, dir) "," H2O_TO_STR(n) "-" H2O_TO_STR(dir) "=%" PRIu64
#define VALUE_OF_NUM_FRAMES(n, dir) , stats.num_frames_##dir.n

    struct st_h2o_http3_server_conn_t *conn = (struct st_h2o_http3_server_conn_t *)req->conn;
    quicly_stats_t stats;

    if (quicly_get_stats(conn->h3.super.quic, &stats) != 0)
        return h2o_iovec_init(H2O_STRLIT("-"));

    char *buf;
    size_t len, bufsize = 1400;
Redo:
    buf = h2o_mem_alloc_pool(&req->pool, char, bufsize);
    len = snprintf(
        buf, bufsize,
        "packets-received=%" PRIu64 ",packets-decryption-failed=%" PRIu64 ",packets-sent=%" PRIu64 ",packets-lost=%" PRIu64
        ",packets-lost-time-threshold=%" PRIu64 ",packets-ack-received=%" PRIu64 ",late-acked=%" PRIu64 ",bytes-received=%" PRIu64
        ",bytes-sent=%" PRIu64 ",bytes-lost=%" PRIu64 ",bytes-ack-received=%" PRIu64 ",bytes-stream-data-sent=%" PRIu64
        ",bytes-stream-data-resent=%" PRIu64 ",rtt-minimum=%" PRIu32 ",rtt-smoothed=%" PRIu32 ",rtt-variance=%" PRIu32
        ",rtt-latest=%" PRIu32 ",cwnd=%" PRIu32 ",ssthresh=%" PRIu32 ",cwnd-initial=%" PRIu32 ",cwnd-exiting-slow-start=%" PRIu32
        ",cwnd-minimum=%" PRIu32 ",cwnd-maximum=%" PRIu32 ",num-loss-episodes=%" PRIu32 ",num-ptos=%" PRIu64
        ",delivery-rate-latest=%" PRIu64 ",delivery-rate-smoothed=%" PRIu64
        ",delivery-rate-stdev=%" PRIu64 APPLY_NUM_FRAMES(FORMAT_OF_NUM_FRAMES, received)
            APPLY_NUM_FRAMES(FORMAT_OF_NUM_FRAMES, sent) ",num-sentmap-packets-largest=%zu",
        stats.num_packets.received, stats.num_packets.decryption_failed, stats.num_packets.sent, stats.num_packets.lost,
        stats.num_packets.lost_time_threshold, stats.num_packets.ack_received, stats.num_packets.late_acked,
        stats.num_bytes.received, stats.num_bytes.sent, stats.num_bytes.lost, stats.num_bytes.ack_received,
        stats.num_bytes.stream_data_sent, stats.num_bytes.stream_data_resent, stats.rtt.minimum, stats.rtt.smoothed,
        stats.rtt.variance, stats.rtt.latest, stats.cc.cwnd, stats.cc.ssthresh, stats.cc.cwnd_initial,
        stats.cc.cwnd_exiting_slow_start, stats.cc.cwnd_minimum, stats.cc.cwnd_maximum, stats.cc.num_loss_episodes, stats.num_ptos,
        stats.delivery_rate.latest, stats.delivery_rate.smoothed,
        stats.delivery_rate.stdev APPLY_NUM_FRAMES(VALUE_OF_NUM_FRAMES, received) APPLY_NUM_FRAMES(VALUE_OF_NUM_FRAMES, sent),
        stats.num_sentmap_packets_largest);
    if (len + 1 > bufsize) {
        bufsize = len + 1;
        goto Redo;
    }

    return h2o_iovec_init(buf, len);

#undef APPLY_NUM_FRAMES
#undef FORMAT_OF_NUM_FRAMES
#undef VALUE_OF_NUM_FRAMES
}

static h2o_iovec_t log_quic_version(h2o_req_t *_req)
{
    struct st_h2o_http3_server_stream_t *stream = H2O_STRUCT_FROM_MEMBER(struct st_h2o_http3_server_stream_t, req, _req);
    char *buf = h2o_mem_alloc_pool(&stream->req.pool, char, sizeof(H2O_UINT32_LONGEST_STR));
    return h2o_iovec_init(buf, sprintf(buf, "%" PRIu32, quicly_get_protocol_version(stream->quic->conn)));
}

void on_stream_destroy(quicly_stream_t *qs, int err)
{
    struct st_h2o_http3_server_stream_t *stream = qs->data;
    struct st_h2o_http3_server_conn_t *conn = get_conn(stream);

    /* There is no need to call `update_conn_state` upon stream destruction, as all the streams transition to CLOSE_WAIT before
     * being destroyed (and it is hard to call `update_conn_state` here, because the number returned by
     * `quicly_num_streams_by_group` is decremented only after returing from this function. */
    --*get_state_counter(conn, stream->state);

    req_scheduler_deactivate(&conn->scheduler.reqs, &stream->scheduler);

    if (h2o_linklist_is_linked(&stream->link))
        h2o_linklist_unlink(&stream->link);
    if (h2o_linklist_is_linked(&stream->link_resp_settings_blocked))
        h2o_linklist_unlink(&stream->link_resp_settings_blocked);
    if (stream->state != H2O_HTTP3_SERVER_STREAM_STATE_CLOSE_WAIT)
        pre_dispose_request(stream);
    if (!stream->req_disposed)
        h2o_dispose_request(&stream->req);
    /* in case the stream is destroyed before the buffer is fully consumed */
    h2o_buffer_dispose(&stream->recvbuf.buf);

    free(stream);

    uint32_t num_req_streams_incl_self = quicly_num_streams_by_group(conn->h3.super.quic, 0, 0);
    assert(num_req_streams_incl_self > 0 &&
           "during the invocation of the destroy callback, stream count should include the number of the stream being destroyed");
    if (num_req_streams_incl_self == 1)
        h2o_conn_set_state(&conn->super, H2O_CONN_STATE_IDLE);
}

/**
 * Converts vectors owned by the generator to ones owned by the HTTP/3 implementation, as the former becomes inaccessible once we
 * call `do_proceed`.
 */
static int retain_sendvecs(struct st_h2o_http3_server_stream_t *stream)
{
    for (; stream->sendbuf.min_index_to_addref != stream->sendbuf.vecs.size; ++stream->sendbuf.min_index_to_addref) {
        struct st_h2o_http3_server_sendvec_t *vec = stream->sendbuf.vecs.entries + stream->sendbuf.min_index_to_addref;
        assert(vec->vec.callbacks->read_ == h2o_sendvec_read_raw);
        if (!(vec->vec.callbacks == &self_allocated_vec_callbacks || vec->vec.callbacks == &immutable_vec_callbacks)) {
            size_t off_within_vec = stream->sendbuf.min_index_to_addref == 0 ? stream->sendbuf.off_within_first_vec : 0,
                   newlen = vec->vec.len - off_within_vec;
            void *newbuf = sendvec_size_is_for_recycle(newlen) ? h2o_mem_alloc_recycle(&h2o_socket_ssl_buffer_allocator)
                                                               : h2o_mem_alloc(newlen);
            memcpy(newbuf, vec->vec.raw + off_within_vec, newlen);
            vec->vec = (h2o_sendvec_t){&self_allocated_vec_callbacks, newlen, {newbuf}};
            if (stream->sendbuf.min_index_to_addref == 0)
                stream->sendbuf.off_within_first_vec = 0;
        }
    }

    return 1;
}

static void on_send_shift(quicly_stream_t *qs, size_t delta)
{
    struct st_h2o_http3_server_stream_t *stream = qs->data;
    size_t i;

    assert(stream->state == H2O_HTTP3_SERVER_STREAM_STATE_SEND_HEADERS || stream->state == H2O_HTTP3_SERVER_STREAM_STATE_SEND_BODY);
    assert(delta != 0);
    assert(stream->sendbuf.vecs.size != 0);

    size_t bytes_avail_in_first_vec = stream->sendbuf.vecs.entries[0].vec.len - stream->sendbuf.off_within_first_vec;
    if (delta < bytes_avail_in_first_vec) {
        stream->sendbuf.off_within_first_vec += delta;
        return;
    }
    delta -= bytes_avail_in_first_vec;
    stream->sendbuf.off_within_first_vec = 0;
    dispose_sendvec(&stream->sendbuf.vecs.entries[0]);

    for (i = 1; delta != 0; ++i) {
        assert(i < stream->sendbuf.vecs.size);
        if (delta < stream->sendbuf.vecs.entries[i].vec.len) {
            stream->sendbuf.off_within_first_vec = delta;
            break;
        }
        delta -= stream->sendbuf.vecs.entries[i].vec.len;
        dispose_sendvec(&stream->sendbuf.vecs.entries[i]);
    }
    memmove(stream->sendbuf.vecs.entries, stream->sendbuf.vecs.entries + i,
            (stream->sendbuf.vecs.size - i) * sizeof(stream->sendbuf.vecs.entries[0]));
    stream->sendbuf.vecs.size -= i;
    if (stream->sendbuf.min_index_to_addref <= i) {
        stream->sendbuf.min_index_to_addref = 0;
    } else {
        stream->sendbuf.min_index_to_addref -= i;
    }

    if (stream->sendbuf.vecs.size == 0) {
        if (quicly_sendstate_is_open(&stream->quic->sendstate)) {
            assert(stream->state == H2O_HTTP3_SERVER_STREAM_STATE_SEND_HEADERS || stream->proceed_requested);
        } else {
            if (quicly_stream_has_receive_side(0, stream->quic->stream_id))
                quicly_request_stop(stream->quic, H2O_HTTP3_ERROR_EARLY_RESPONSE);
            set_state(stream, H2O_HTTP3_SERVER_STREAM_STATE_CLOSE_WAIT, 0);
        }
    }
}

static void on_send_emit(quicly_stream_t *qs, size_t off, void *_dst, size_t *len, int *wrote_all)
{
    struct st_h2o_http3_server_stream_t *stream = qs->data;

    assert(stream->state == H2O_HTTP3_SERVER_STREAM_STATE_SEND_HEADERS || stream->state == H2O_HTTP3_SERVER_STREAM_STATE_SEND_BODY);

    uint8_t *dst = _dst, *dst_end = dst + *len;
    size_t vec_index = 0;

    /* find the start position identified by vec_index and off */
    off += stream->sendbuf.off_within_first_vec;
    while (off != 0) {
        assert(vec_index < stream->sendbuf.vecs.size);
        if (off < stream->sendbuf.vecs.entries[vec_index].vec.len)
            break;
        off -= stream->sendbuf.vecs.entries[vec_index].vec.len;
        ++vec_index;
    }
    assert(vec_index < stream->sendbuf.vecs.size);

    /* write */
    *wrote_all = 0;
    do {
        struct st_h2o_http3_server_sendvec_t *this_vec = stream->sendbuf.vecs.entries + vec_index;
        size_t sz = this_vec->vec.len - off;
        if (dst_end - dst < sz)
            sz = dst_end - dst;
        /* convert vector into raw form, the first time it's being sent (TODO use ssl_buffer_recyle) */
        if (this_vec->vec.callbacks->read_ != h2o_sendvec_read_raw) {
            size_t newlen = this_vec->vec.len;
            void *newbuf = sendvec_size_is_for_recycle(newlen) ? h2o_mem_alloc_recycle(&h2o_socket_ssl_buffer_allocator)
                                                               : h2o_mem_alloc(newlen);
            if (!this_vec->vec.callbacks->read_(&this_vec->vec, newbuf, newlen)) {
                free(newbuf);
                goto Error;
            }
            this_vec->vec = (h2o_sendvec_t){&self_allocated_vec_callbacks, newlen, {newbuf}};
        }
        /* copy payload */
        memcpy(dst, this_vec->vec.raw + off, sz);
        /* adjust offsets */
        if (this_vec->entity_offset != UINT64_MAX && stream->req.bytes_sent < this_vec->entity_offset + off + sz)
            stream->req.bytes_sent = this_vec->entity_offset + off + sz;
        dst += sz;
        off += sz;
        /* when reaching the end of the current vector, update vec_index, wrote_all */
        if (off == this_vec->vec.len) {
            off = 0;
            ++vec_index;
            if (vec_index == stream->sendbuf.vecs.size) {
                *wrote_all = 1;
                break;
            }
        }
    } while (dst != dst_end);

    *len = dst - (uint8_t *)_dst;

    /* retain the payload of response body before calling `h2o_proceed_request`, as the generator might discard the buffer */
    if (stream->state == H2O_HTTP3_SERVER_STREAM_STATE_SEND_BODY && *wrote_all &&
        quicly_sendstate_is_open(&stream->quic->sendstate) && !stream->proceed_requested) {
        if (!retain_sendvecs(stream))
            goto Error;
        stream->proceed_requested = 1;
        stream->proceed_while_sending = 1;
    }

    return;
Error:
    *len = 0;
    *wrote_all = 1;
    shutdown_stream(stream, H2O_HTTP3_ERROR_EARLY_RESPONSE, H2O_HTTP3_ERROR_INTERNAL, 0);
}

static void on_send_stop(quicly_stream_t *qs, int err)
{
    struct st_h2o_http3_server_stream_t *stream = qs->data;

    shutdown_stream(stream, H2O_HTTP3_ERROR_REQUEST_CANCELLED, err, 0);
}

static void handle_buffered_input(struct st_h2o_http3_server_stream_t *stream, int in_generator)
{
    struct st_h2o_http3_server_conn_t *conn = get_conn(stream);

    if (stream->state >= H2O_HTTP3_SERVER_STREAM_STATE_CLOSE_WAIT)
        return;

    { /* Process contiguous bytes in the receive buffer until one of the following conditions are reached:
       * a) connection- or stream-level error (i.e., state advanced to CLOSE_WAIT) is detected - in which case we exit,
       * b) incomplete frame is detected - wait for more (if the stream is open) or raise a connection error, or
       * c) all bytes are processed - exit the loop. */
        size_t bytes_available = quicly_recvstate_bytes_available(&stream->quic->recvstate);
        assert(bytes_available <= stream->recvbuf.buf->size);
        if (bytes_available != 0) {
            const uint8_t *src = (const uint8_t *)stream->recvbuf.buf->bytes, *src_end = src + bytes_available;
            do {
                int err;
                const char *err_desc = NULL;
                if ((err = stream->recvbuf.handle_input(stream, &src, src_end, in_generator, &err_desc)) != 0) {
                    if (err == H2O_HTTP3_ERROR_INCOMPLETE) {
                        if (!quicly_recvstate_transfer_complete(&stream->quic->recvstate))
                            break;
                        err = H2O_HTTP3_ERROR_GENERAL_PROTOCOL;
                        err_desc = "incomplete frame";
                    }
                    h2o_quic_close_connection(&conn->h3.super, err, err_desc);
                    return;
                } else if (stream->state >= H2O_HTTP3_SERVER_STREAM_STATE_CLOSE_WAIT) {
                    return;
                }
            } while (src != src_end);
            /* Processed zero or more bytes without noticing an error; shift the bytes that have been processed as frames. */
            size_t bytes_consumed = src - (const uint8_t *)stream->recvbuf.buf->bytes;
            h2o_buffer_consume(&stream->recvbuf.buf, bytes_consumed);
            quicly_stream_sync_recvbuf(stream->quic, bytes_consumed);
        }
    }

    if (quicly_recvstate_transfer_complete(&stream->quic->recvstate)) {
        if (stream->recvbuf.buf->size == 0 && (stream->recvbuf.handle_input == handle_input_expect_data ||
                                               stream->recvbuf.handle_input == handle_input_post_trailers)) {
            /* have complete request, advance the state and process the request */
            if (stream->req.content_length != SIZE_MAX && stream->req.content_length != stream->req.req_body_bytes_received) {
                /* the request terminated abruptly; reset the stream as we do for HTTP/2 */
                shutdown_stream(stream, H2O_HTTP3_ERROR_NONE /* ignored */,
                                stream->req.req_body_bytes_received < stream->req.content_length
                                    ? H2O_HTTP3_ERROR_REQUEST_INCOMPLETE
                                    : H2O_HTTP3_ERROR_GENERAL_PROTOCOL,
                                in_generator);
            } else {
                if (stream->req.write_req.cb != NULL) {
                    if (!h2o_linklist_is_linked(&stream->link))
                        h2o_linklist_insert(&conn->delayed_streams.req_streaming, &stream->link);
                    request_run_delayed(conn);
                } else if (!stream->req.process_called && stream->state < H2O_HTTP3_SERVER_STREAM_STATE_SEND_HEADERS) {
                    /* process the request, if we haven't called h2o_process_request nor send an error response */
                    switch (stream->state) {
                    case H2O_HTTP3_SERVER_STREAM_STATE_RECV_HEADERS:
                    case H2O_HTTP3_SERVER_STREAM_STATE_RECV_BODY_BEFORE_BLOCK:
                    case H2O_HTTP3_SERVER_STREAM_STATE_RECV_BODY_UNBLOCKED:
                        break;
                    default:
                        assert(!"unexpected state");
                        break;
                    }
                    set_state(stream, H2O_HTTP3_SERVER_STREAM_STATE_REQ_PENDING, in_generator);
                    h2o_linklist_insert(&conn->delayed_streams.pending, &stream->link);
                    request_run_delayed(conn);
                }
            }
        } else {
            shutdown_stream(stream, H2O_HTTP3_ERROR_NONE /* ignored */, H2O_HTTP3_ERROR_REQUEST_INCOMPLETE, in_generator);
        }
    } else {
        if (stream->state == H2O_HTTP3_SERVER_STREAM_STATE_RECV_BODY_BEFORE_BLOCK && stream->req_body != NULL &&
            stream->req_body->size >= H2O_HTTP3_REQUEST_BODY_MIN_BYTES_TO_BLOCK) {
            /* switch to blocked state if the request body is becoming large (this limits the concurrency to the backend) */
            stream->read_blocked = 1;
            h2o_linklist_insert(&conn->delayed_streams.recv_body_blocked, &stream->link);
            set_state(stream, H2O_HTTP3_SERVER_STREAM_STATE_RECV_BODY_BLOCKED, in_generator);
            check_run_blocked(conn);
        } else if (stream->req.write_req.cb != NULL && stream->req_body->size != 0) {
            /* in streaming mode, let the run_delayed invoke write_req */
            if (!h2o_linklist_is_linked(&stream->link))
                h2o_linklist_insert(&conn->delayed_streams.req_streaming, &stream->link);
            request_run_delayed(conn);
        }
    }
}

static void on_receive(quicly_stream_t *qs, size_t off, const void *input, size_t len)
{
    struct st_h2o_http3_server_stream_t *stream = qs->data;

    /* save received data (FIXME avoid copying if possible; see hqclient.c) */
    h2o_http3_update_recvbuf(&stream->recvbuf.buf, off, input, len);

    if (stream->read_blocked)
        return;

    /* handle input (FIXME propage err_desc) */
    handle_buffered_input(stream, 0);
}

static void on_receive_reset(quicly_stream_t *qs, int err)
{
    struct st_h2o_http3_server_stream_t *stream = qs->data;

    shutdown_stream(stream, H2O_HTTP3_ERROR_NONE /* ignored */,
                    stream->state == H2O_HTTP3_SERVER_STREAM_STATE_RECV_HEADERS ? H2O_HTTP3_ERROR_REQUEST_REJECTED
                                                                                : H2O_HTTP3_ERROR_REQUEST_CANCELLED,
                    0);
}

static void proceed_request_streaming(h2o_req_t *_req, const char *errstr)
{
    struct st_h2o_http3_server_stream_t *stream = H2O_STRUCT_FROM_MEMBER(struct st_h2o_http3_server_stream_t, req, _req);
    struct st_h2o_http3_server_conn_t *conn = get_conn(stream);

    assert(stream->req_body != NULL);
    assert(errstr != NULL || !h2o_linklist_is_linked(&stream->link));
    assert(conn->num_streams_req_streaming != 0 || stream->req.is_tunnel_req);

    if (errstr != NULL || (quicly_recvstate_bytes_available(&stream->quic->recvstate) == 0 &&
                           quicly_recvstate_transfer_complete(&stream->quic->recvstate))) {
        /* tidy up the request streaming */
        stream->req.write_req.cb = NULL;
        stream->req.write_req.ctx = NULL;
        stream->req.proceed_req = NULL;
        stream->req_streaming = 0;
        if (!stream->req.is_tunnel_req)
            --conn->num_streams_req_streaming;
        check_run_blocked(conn);
        /* close the stream if an error occurred */
        if (errstr != NULL) {
            shutdown_stream(stream, H2O_HTTP3_ERROR_INTERNAL, H2O_HTTP3_ERROR_INTERNAL, 1);
            return;
        }
    }

    /* remove the bytes from the request body buffer */
    assert(stream->req.entity.len == stream->req_body->size);
    h2o_buffer_consume(&stream->req_body, stream->req_body->size);
    stream->req.entity = h2o_iovec_init(NULL, 0);

    /* unblock read until the next invocation of write_req, or after the final invocation */
    stream->read_blocked = 0;

    /* handle input in the receive buffer */
    handle_buffered_input(stream, 1);
}

static void run_delayed(h2o_timer_t *timer)
{
    struct st_h2o_http3_server_conn_t *conn = H2O_STRUCT_FROM_MEMBER(struct st_h2o_http3_server_conn_t, timeout, timer);
    int made_progress;

    do {
        made_progress = 0;

        /* promote blocked stream to unblocked state, if possible */
        if (conn->num_streams.recv_body_unblocked + conn->num_streams_req_streaming == 0 &&
            !h2o_linklist_is_empty(&conn->delayed_streams.recv_body_blocked)) {
            struct st_h2o_http3_server_stream_t *stream =
                H2O_STRUCT_FROM_MEMBER(struct st_h2o_http3_server_stream_t, link, conn->delayed_streams.recv_body_blocked.next);
            assert(stream->state == H2O_HTTP3_SERVER_STREAM_STATE_RECV_BODY_BLOCKED);
            assert(stream->read_blocked);
            h2o_linklist_unlink(&stream->link);
            made_progress = 1;
            quicly_stream_set_receive_window(stream->quic, conn->super.ctx->globalconf->http3.active_stream_window_size);
            if (h2o_req_can_stream_request(&stream->req)) {
                /* use streaming mode */
                stream->req_streaming = 1;
                ++conn->num_streams_req_streaming;
                stream->req.proceed_req = proceed_request_streaming;
                set_state(stream, H2O_HTTP3_SERVER_STREAM_STATE_SEND_HEADERS, 0);
                h2o_process_request(&stream->req);
            } else {
                /* unblock, read the bytes in receive buffer */
                stream->read_blocked = 0;
                set_state(stream, H2O_HTTP3_SERVER_STREAM_STATE_RECV_BODY_UNBLOCKED, 0);
                handle_buffered_input(stream, 0);
                if (quicly_get_state(conn->h3.super.quic) >= QUICLY_STATE_CLOSING)
                    return;
            }
        }

        /* process streams using request streaming, that have new data to submit */
        while (!h2o_linklist_is_empty(&conn->delayed_streams.req_streaming)) {
            struct st_h2o_http3_server_stream_t *stream =
                H2O_STRUCT_FROM_MEMBER(struct st_h2o_http3_server_stream_t, link, conn->delayed_streams.req_streaming.next);
            int is_end_stream = quicly_recvstate_transfer_complete(&stream->quic->recvstate);
            assert(stream->req.process_called);
            assert(stream->req.write_req.cb != NULL);
            assert(stream->req_body != NULL);
            assert(stream->req_body->size != 0 || is_end_stream);
            assert(!stream->read_blocked);
            h2o_linklist_unlink(&stream->link);
            stream->read_blocked = 1;
            made_progress = 1;
            assert(stream->req.entity.len == stream->req_body->size &&
                   (stream->req.entity.len == 0 || stream->req.entity.base == stream->req_body->bytes));
            if (stream->req.write_req.cb(stream->req.write_req.ctx, is_end_stream) != 0)
                shutdown_stream(stream, H2O_HTTP3_ERROR_INTERNAL, H2O_HTTP3_ERROR_INTERNAL, 0);
        }

        /* process the requests (not in streaming mode); TODO cap concurrency? */
        while (!h2o_linklist_is_empty(&conn->delayed_streams.pending)) {
            struct st_h2o_http3_server_stream_t *stream =
                H2O_STRUCT_FROM_MEMBER(struct st_h2o_http3_server_stream_t, link, conn->delayed_streams.pending.next);
            assert(stream->state == H2O_HTTP3_SERVER_STREAM_STATE_REQ_PENDING);
            assert(!stream->req.process_called);
            assert(!stream->read_blocked);
            h2o_linklist_unlink(&stream->link);
            made_progress = 1;
            set_state(stream, H2O_HTTP3_SERVER_STREAM_STATE_SEND_HEADERS, 0);
            h2o_process_request(&stream->req);
        }

    } while (made_progress);
}

int handle_input_post_trailers(struct st_h2o_http3_server_stream_t *stream, const uint8_t **src, const uint8_t *src_end,
                               int in_generator, const char **err_desc)
{
    h2o_http3_read_frame_t frame;
    int ret;

    /* read and ignore unknown frames */
    if ((ret = h2o_http3_read_frame(&frame, 0, H2O_HTTP3_STREAM_TYPE_REQUEST, src, src_end, err_desc)) != 0)
        return ret;
    switch (frame.type) {
    case H2O_HTTP3_FRAME_TYPE_HEADERS:
    case H2O_HTTP3_FRAME_TYPE_DATA:
        return H2O_HTTP3_ERROR_FRAME_UNEXPECTED;
    default:
        break;
    }

    return 0;
}

static int handle_input_expect_data_payload(struct st_h2o_http3_server_stream_t *stream, const uint8_t **src,
                                            const uint8_t *src_end, int in_generator, const char **err_desc)
{
    size_t bytes_avail = src_end - *src;

    /* append data to body buffer */
    if (bytes_avail > stream->recvbuf.bytes_left_in_data_frame)
        bytes_avail = stream->recvbuf.bytes_left_in_data_frame;
    if (stream->req_body == NULL)
        h2o_buffer_init(&stream->req_body, &h2o_socket_buffer_prototype);
    if (!h2o_buffer_try_append(&stream->req_body, *src, bytes_avail))
        return H2O_HTTP3_ERROR_INTERNAL;
    stream->req.entity = h2o_iovec_init(stream->req_body->bytes, stream->req_body->size);
    stream->req.req_body_bytes_received += bytes_avail;
    stream->recvbuf.bytes_left_in_data_frame -= bytes_avail;
    *src += bytes_avail;

    if (stream->recvbuf.bytes_left_in_data_frame == 0)
        stream->recvbuf.handle_input = handle_input_expect_data;

    return 0;
}

int handle_input_expect_data(struct st_h2o_http3_server_stream_t *stream, const uint8_t **src, const uint8_t *src_end,
                             int in_generator, const char **err_desc)
{
    h2o_http3_read_frame_t frame;
    int ret;

    /* read frame */
    if ((ret = h2o_http3_read_frame(&frame, 0, H2O_HTTP3_STREAM_TYPE_REQUEST, src, src_end, err_desc)) != 0)
        return ret;
    switch (frame.type) {
    case H2O_HTTP3_FRAME_TYPE_HEADERS:
        /* when in tunnel mode, trailers forbidden */
        if (stream->req.is_tunnel_req) {
            *err_desc = "unexpected frame type";
            return H2O_HTTP3_ERROR_FRAME_UNEXPECTED;
        }
        /* trailers, ignore but disallow succeeding DATA or HEADERS frame */
        stream->recvbuf.handle_input = handle_input_post_trailers;
        return 0;
    case H2O_HTTP3_FRAME_TYPE_DATA:
        if (stream->req.content_length != SIZE_MAX &&
            stream->req.content_length - stream->req.req_body_bytes_received < frame.length) {
            /* The only viable option here is to reset the stream, as we might have already started streaming the request body
             * upstream. This behavior is consistent with what we do in HTTP/2. */
            shutdown_stream(stream, H2O_HTTP3_ERROR_EARLY_RESPONSE, H2O_HTTP3_ERROR_GENERAL_PROTOCOL, in_generator);
            return 0;
        }
        break;
    default:
        return 0;
    }

    /* got a DATA frame */
    if (frame.length != 0) {
        if (h2o_timeval_is_null(&stream->req.timestamps.request_body_begin_at))
            stream->req.timestamps.request_body_begin_at = h2o_gettimeofday(get_conn(stream)->super.ctx->loop);
        stream->recvbuf.handle_input = handle_input_expect_data_payload;
        stream->recvbuf.bytes_left_in_data_frame = frame.length;
    }

    return 0;
}

static int handle_input_expect_headers_send_http_error(struct st_h2o_http3_server_stream_t *stream,
                                                       void (*sendfn)(h2o_req_t *, const char *, const char *, int),
                                                       const char *reason, const char *body, const char **err_desc)
{
    if (!quicly_recvstate_transfer_complete(&stream->quic->recvstate))
        quicly_request_stop(stream->quic, H2O_HTTP3_ERROR_EARLY_RESPONSE);

    set_state(stream, H2O_HTTP3_SERVER_STREAM_STATE_SEND_HEADERS, 0);
    sendfn(&stream->req, reason, body, 0);
    *err_desc = NULL;

    return 0;
}

static int handle_input_expect_headers_process_connect(struct st_h2o_http3_server_stream_t *stream,
                                                       h2o_iovec_t *datagram_flow_id_field, const char **err_desc)
{
    if (stream->req.content_length != SIZE_MAX)
        return handle_input_expect_headers_send_http_error(stream, h2o_send_error_400, "Invalid Request",
                                                           "CONNECT request cannot have request body", err_desc);

    uint64_t datagram_flow_id = UINT64_MAX;
    if (datagram_flow_id_field != NULL) {
        /* CONNECT-UDP */
        if (datagram_flow_id_field->base != NULL) {
            /* check if the peer is permitted to send datagram frames, by consulting our SETTINGS.H3_DATAGRAM parameter */
            quicly_context_t *qctx = quicly_get_context(get_conn(stream)->h3.super.quic);
            if (qctx->transport_params.max_datagram_frame_size == 0) {
                *err_desc = "unexpected h3 datagram";
                return H2O_HTTP3_ERROR_GENERAL_PROTOCOL;
            }
            /* TODO implement proper parsing */
            datagram_flow_id = 0;
            for (const char *p = datagram_flow_id_field->base; p != datagram_flow_id_field->base + datagram_flow_id_field->len;
                 ++p) {
                if (!('0' <= *p && *p <= '9'))
                    break;
                datagram_flow_id = datagram_flow_id * 10 + *p - '0';
            }
        }
    }

    stream->req.is_tunnel_req = 1;
    h2o_buffer_init(&stream->req_body, &h2o_socket_buffer_prototype);
    stream->req.entity = h2o_iovec_init("", 0);
    stream->req.proceed_req = proceed_request_streaming;
    stream->datagram_flow_id = datagram_flow_id;
    ++get_conn(stream)->num_streams_tunnelling;
    set_state(stream, H2O_HTTP3_SERVER_STREAM_STATE_SEND_HEADERS, 0);
    quicly_stream_set_receive_window(stream->quic, get_conn(stream)->super.ctx->globalconf->http3.active_stream_window_size);
    h2o_process_request(&stream->req);

    return 0;
}

static int handle_input_expect_headers(struct st_h2o_http3_server_stream_t *stream, const uint8_t **src, const uint8_t *src_end,
                                       int in_generator, const char **err_desc)
{
    assert(!in_generator); /* this function is processing headers (before generators get assigned), not trailers */

    struct st_h2o_http3_server_conn_t *conn = get_conn(stream);
    h2o_http3_read_frame_t frame;
    int header_exists_map = 0, ret;
    h2o_iovec_t datagram_flow_id = {};
    uint8_t header_ack[H2O_HPACK_ENCODE_INT_MAX_LENGTH];
    size_t header_ack_len;

    /* read the HEADERS frame (or a frame that precedes that) */
    if ((ret = h2o_http3_read_frame(&frame, 0, H2O_HTTP3_STREAM_TYPE_REQUEST, src, src_end, err_desc)) != 0)
        return ret;
    if (frame.type != H2O_HTTP3_FRAME_TYPE_HEADERS) {
        switch (frame.type) {
        case H2O_HTTP3_FRAME_TYPE_DATA:
            return H2O_HTTP3_ERROR_FRAME_UNEXPECTED;
        default:
            break;
        }
        return 0;
    }
    stream->req.timestamps.request_begin_at = h2o_gettimeofday(conn->super.ctx->loop);
    stream->recvbuf.handle_input = handle_input_expect_data;

    /* parse the headers, and ack */
    if ((ret = h2o_qpack_parse_request(&stream->req.pool, get_conn(stream)->h3.qpack.dec, stream->quic->stream_id,
                                       &stream->req.input.method, &stream->req.input.scheme, &stream->req.input.authority,
                                       &stream->req.input.path, &stream->req.headers, &header_exists_map,
                                       &stream->req.content_length, NULL /* TODO cache-digests */, &datagram_flow_id, header_ack,
                                       &header_ack_len, frame.payload, frame.length, err_desc)) != 0 &&
        ret != H2O_HTTP2_ERROR_INVALID_HEADER_CHAR)
        return ret;
    if (header_ack_len != 0)
        h2o_http3_send_qpack_header_ack(&conn->h3, header_ack, header_ack_len);

    if (stream->req.input.scheme == NULL)
        stream->req.input.scheme = &H2O_URL_SCHEME_HTTPS;

    // For RFC compliant CONNECT-UDP requests we wont get the datagram_flow_id as part of the request, so use the stream_id as per RFC
    if (!datagram_flow_id.base) {
        datagram_flow_id.base = h2o_mem_alloc_pool(&stream->req.pool, char, sizeof(H2O_UINT64_LONGEST_STR));
        datagram_flow_id.len = sprintf(datagram_flow_id.base, "%" PRIu64, stream->quic->stream_id);
    }

    h2o_probe_log_request(&stream->req, stream->quic->stream_id);

    int is_connect = h2o_memis(stream->req.input.method.base, stream->req.input.method.len, H2O_STRLIT("CONNECT"));
    int is_connect_udp = h2o_memis(stream->req.input.method.base, stream->req.input.method.len, H2O_STRLIT("CONNECT-UDP"));

    /* check if existence and non-existence of pseudo headers are correct */
    int expected_map = H2O_HPACK_PARSE_HEADERS_METHOD_EXISTS | H2O_HPACK_PARSE_HEADERS_AUTHORITY_EXISTS;
    if (!is_connect && !is_connect_udp)
        expected_map |= H2O_HPACK_PARSE_HEADERS_SCHEME_EXISTS | H2O_HPACK_PARSE_HEADERS_PATH_EXISTS;
    if (is_connect_udp) {
        /* only require method and authority for connect-udp for now, ignore if the others are set */
        if ((header_exists_map & expected_map) != expected_map) {
            shutdown_stream(stream, H2O_HTTP3_ERROR_GENERAL_PROTOCOL, H2O_HTTP3_ERROR_GENERAL_PROTOCOL, 0);
            return 0;
        }
    } else {
        if (header_exists_map != expected_map) {
            shutdown_stream(stream, H2O_HTTP3_ERROR_GENERAL_PROTOCOL, H2O_HTTP3_ERROR_GENERAL_PROTOCOL, 0);
            return 0;
        }
    }

    /* send a 400 error when observing an invalid header character */
    if (ret == H2O_HTTP2_ERROR_INVALID_HEADER_CHAR)
        return handle_input_expect_headers_send_http_error(stream, h2o_send_error_400, "Invalid Request", *err_desc, err_desc);

    /* validate semantic requirement */
    if (!h2o_req_validate_pseudo_headers(&stream->req)) {
        *err_desc = "invalid pseudo headers";
        return H2O_HTTP3_ERROR_GENERAL_PROTOCOL;
    }

    /* check if content-length is within the permitted bounds */
    if (stream->req.content_length != SIZE_MAX && stream->req.content_length > conn->super.ctx->globalconf->max_request_entity_size)
        return handle_input_expect_headers_send_http_error(stream, h2o_send_error_413, "Request Entity Too Large",
                                                           "request entity is too large", err_desc);

    /* set priority */
    assert(!h2o_linklist_is_linked(&stream->scheduler.link));
    if (!stream->received_priority_update) {
        ssize_t index;
        if ((index = h2o_find_header(&stream->req.headers, H2O_TOKEN_PRIORITY, -1)) != -1) {
            h2o_iovec_t *value = &stream->req.headers.entries[index].value;
            h2o_absprio_parse_priority(value->base, value->len, &stream->scheduler.priority);
        } else if (is_connect) {
            stream->scheduler.priority.incremental = 1;
        }
    }

    /* special handling of CONNECT method */
    if (is_connect) {
        return handle_input_expect_headers_process_connect(stream, NULL, err_desc);
    } else if (h2o_memis(stream->req.input.method.base, stream->req.input.method.len, H2O_STRLIT("CONNECT-UDP"))) {
        return handle_input_expect_headers_process_connect(stream, &datagram_flow_id, err_desc);
    }

    /* change state */
    set_state(stream, H2O_HTTP3_SERVER_STREAM_STATE_RECV_BODY_BEFORE_BLOCK, 0);

    return 0;
}

static void write_response(struct st_h2o_http3_server_stream_t *stream, h2o_iovec_t datagram_flow_id)
{
    h2o_iovec_t frame = h2o_qpack_flatten_response(
        get_conn(stream)->h3.qpack.enc, &stream->req.pool, stream->quic->stream_id, NULL, stream->req.res.status,
        stream->req.res.headers.entries, stream->req.res.headers.size, &get_conn(stream)->super.ctx->globalconf->server_name,
        //We send an empty iovec buffer to avoid h2o from sending the flow id in the response since that is not
        // part of RFC-9298 (was part of a draft)
        stream->req.res.content_length, h2o_iovec_init(NULL, 0));

    h2o_vector_reserve(&stream->req.pool, &stream->sendbuf.vecs, stream->sendbuf.vecs.size + 1);
    struct st_h2o_http3_server_sendvec_t *vec = stream->sendbuf.vecs.entries + stream->sendbuf.vecs.size++;
    vec->vec = (h2o_sendvec_t){&immutable_vec_callbacks, frame.len, {frame.base}};
    vec->entity_offset = UINT64_MAX;
    stream->sendbuf.final_size += frame.len;
}

static size_t flatten_data_frame_header(struct st_h2o_http3_server_stream_t *stream, struct st_h2o_http3_server_sendvec_t *dst,
                                        size_t payload_size)
{
    size_t header_size = 0;

    /* build header */
    stream->sendbuf.data_frame_header_buf[header_size++] = H2O_HTTP3_FRAME_TYPE_DATA;
    header_size =
        quicly_encodev(stream->sendbuf.data_frame_header_buf + header_size, payload_size) - stream->sendbuf.data_frame_header_buf;

    /* initilaize the vector */
    h2o_sendvec_init_raw(&dst->vec, stream->sendbuf.data_frame_header_buf, header_size);
    dst->entity_offset = UINT64_MAX;

    return header_size;
}

static void shutdown_by_generator(struct st_h2o_http3_server_stream_t *stream)
{
    quicly_sendstate_shutdown(&stream->quic->sendstate, stream->sendbuf.final_size);
    if (stream->sendbuf.vecs.size == 0) {
        if (quicly_stream_has_receive_side(0, stream->quic->stream_id))
            quicly_request_stop(stream->quic, H2O_HTTP3_ERROR_EARLY_RESPONSE);
        set_state(stream, H2O_HTTP3_SERVER_STREAM_STATE_CLOSE_WAIT, 1);
    }
}

/**
 * returns boolean indicating if the response is ready to be sent, building the value of datagram-flow-id header field
 */
static int finalize_do_send_setup_udp_tunnel(struct st_h2o_http3_server_stream_t *stream, h2o_send_state_t send_state,
                                             h2o_iovec_t *datagram_flow_id)
{
    *datagram_flow_id = h2o_iovec_init(NULL, 0);

    /* Bail out if we cannot receive or send datagrams. */
    if (!((200 <= stream->req.res.status && stream->req.res.status <= 299) && stream->req.forward_datagram.write_ != NULL) ||
        send_state != H2O_SEND_STATE_IN_PROGRESS) {
        stream->datagram_flow_id = UINT64_MAX;
        return 1;
    }

    /* Register the flow id to the connection so that datagram frames being received from the client would be dispatched to
     * `req->forward_datagram.write_`. */
    if (stream->datagram_flow_id != UINT64_MAX) {
        struct st_h2o_http3_server_conn_t *conn = get_conn(stream);
        int r;
        khiter_t iter = kh_put(stream, conn->datagram_flows, stream->datagram_flow_id, &r);
        assert(iter != kh_end(conn->datagram_flows));
        kh_val(conn->datagram_flows, iter) = stream;
    }

    /* If the client sent a `datagram-flow-id` request header field and:
     *  a) if the peer is willing to accept datagrams as well, use the same flow ID for sending datagrams from us,
     *  b) if the peer did not send H3_DATAGRAM Settings, use the stream, or
     *  c) if H3 SETTINGS hasn't been received yet, wait for it, then call `do_send` again. We might drop some packets from origin
     *     that arrive before H3 SETTINGS from the client, in the rare occasion of packet carrying H3 SETTINGS getting lost while
     *     those carrying CONNECT-UDP request and the UDP datagram to be forwarded to the origin arrive. */
    if (stream->datagram_flow_id != UINT64_MAX) {
        struct st_h2o_http3_server_conn_t *conn = get_conn(stream);
        if (!h2o_http3_has_received_settings(&conn->h3)) {
            h2o_linklist_insert(&conn->streams_resp_settings_blocked, &stream->link_resp_settings_blocked);
            return 0;
        }
        if (conn->h3.peer_settings.h3_datagram) {
            /* register the route that would be used by the CONNECT handler for forwarding datagrams */
            stream->req.forward_datagram.read_ = tunnel_on_udp_read;
            /* build and return the value of datagram-flow-id header field */
            datagram_flow_id->base = h2o_mem_alloc_pool(&stream->req.pool, char, sizeof(H2O_UINT64_LONGEST_STR));
            datagram_flow_id->len = sprintf(datagram_flow_id->base, "%" PRIu64, stream->datagram_flow_id);
        }
    }

    return 1;
}

static void finalize_do_send(struct st_h2o_http3_server_stream_t *stream)
{
    quicly_stream_sync_sendbuf(stream->quic, 1);
    if (!stream->proceed_while_sending)
        h2o_quic_schedule_timer(&get_conn(stream)->h3.super);
}

static void do_send(h2o_ostream_t *_ostr, h2o_req_t *_req, h2o_sendvec_t *bufs, size_t bufcnt, h2o_send_state_t send_state)
{
    struct st_h2o_http3_server_stream_t *stream = H2O_STRUCT_FROM_MEMBER(struct st_h2o_http3_server_stream_t, ostr_final, _ostr);

    assert(&stream->req == _req);

    stream->proceed_requested = 0;

    switch (stream->state) {
    case H2O_HTTP3_SERVER_STREAM_STATE_SEND_HEADERS: {
        h2o_iovec_t datagram_flow_id;
        if (!finalize_do_send_setup_udp_tunnel(stream, send_state, &datagram_flow_id))
            return;
        stream->req.timestamps.response_start_at = h2o_gettimeofday(get_conn(stream)->super.ctx->loop);
        write_response(stream, datagram_flow_id);
        h2o_probe_log_response(&stream->req, stream->quic->stream_id);
        set_state(stream, H2O_HTTP3_SERVER_STREAM_STATE_SEND_BODY, 1);
        break;
    }
    case H2O_HTTP3_SERVER_STREAM_STATE_SEND_BODY:
        assert(quicly_sendstate_is_open(&stream->quic->sendstate));
        break;
    case H2O_HTTP3_SERVER_STREAM_STATE_CLOSE_WAIT:
        /* This protocol handler transitions to CLOSE_WAIT when the request side is being reset by the origin. But our client-side
         * implementations are capable of handling uni-directional close, therefore `do_send` might be invoked. The handler swallows
         * the input, and relies on eventual destruction of `h2o_req_t` to discard the generator. */
        return;
    default:
        h2o_fatal("logic flaw");
        break;
    }

    /* If vectors carrying response body are being provided, copy them, incrementing the reference count if possible (for future
     * retransmissions), as well as prepending a DATA frame header */
    if (bufcnt != 0) {
        h2o_vector_reserve(&stream->req.pool, &stream->sendbuf.vecs, stream->sendbuf.vecs.size + 1 + bufcnt);
        uint64_t prev_body_size = stream->sendbuf.final_body_size;
        for (size_t i = 0; i != bufcnt; ++i) {
            /* copy one body vector */
            struct st_h2o_http3_server_sendvec_t *dst = stream->sendbuf.vecs.entries + stream->sendbuf.vecs.size + i + 1;
            dst->vec = bufs[i];
            dst->entity_offset = stream->sendbuf.final_body_size;
            stream->sendbuf.final_body_size += bufs[i].len;
        }
        uint64_t payload_size = stream->sendbuf.final_body_size - prev_body_size;
        /* build DATA frame header */
        size_t header_size =
            flatten_data_frame_header(stream, stream->sendbuf.vecs.entries + stream->sendbuf.vecs.size, payload_size);
        /* update properties */
        stream->sendbuf.vecs.size += 1 + bufcnt;
        stream->sendbuf.final_size += header_size + payload_size;
    }

    switch (send_state) {
    case H2O_SEND_STATE_IN_PROGRESS:
        break;
    case H2O_SEND_STATE_FINAL:
    case H2O_SEND_STATE_ERROR:
        /* TODO consider how to forward error, pending resolution of https://github.com/quicwg/base-drafts/issues/3300 */
        shutdown_by_generator(stream);
        break;
    }

    finalize_do_send(stream);
}

static void do_send_informational(h2o_ostream_t *_ostr, h2o_req_t *_req)
{
    struct st_h2o_http3_server_stream_t *stream = H2O_STRUCT_FROM_MEMBER(struct st_h2o_http3_server_stream_t, ostr_final, _ostr);
    assert(&stream->req == _req);

    write_response(stream, h2o_iovec_init(NULL, 0));

    finalize_do_send(stream);
}

static int handle_priority_update_frame(struct st_h2o_http3_server_conn_t *conn, const h2o_http3_priority_update_frame_t *frame)
{
    if (frame->element_is_push)
        return H2O_HTTP3_ERROR_GENERAL_PROTOCOL;

    /* obtain the stream being referred to (creating one if necessary), or return if the stream has been closed already */
    quicly_stream_t *qs;
    if (quicly_get_or_open_stream(conn->h3.super.quic, frame->element, &qs) != 0)
        return H2O_HTTP3_ERROR_ID;
    if (qs == NULL)
        return 0;

    /* apply the changes */
    struct st_h2o_http3_server_stream_t *stream = qs->data;
    assert(stream != NULL);
    stream->received_priority_update = 1;
    if (h2o_linklist_is_linked(&stream->scheduler.link)) {
        req_scheduler_deactivate(&conn->scheduler.reqs, &stream->scheduler);
        stream->scheduler.priority = frame->priority; /* TODO apply only the delta? */
        req_scheduler_activate(&conn->scheduler.reqs, &stream->scheduler, req_scheduler_compare_stream_id);
    } else {
        stream->scheduler.priority = frame->priority; /* TODO apply only the delta? */
    }

    return 0;
}

static void handle_control_stream_frame(h2o_http3_conn_t *_conn, uint64_t type, const uint8_t *payload, size_t len)
{
    struct st_h2o_http3_server_conn_t *conn = H2O_STRUCT_FROM_MEMBER(struct st_h2o_http3_server_conn_t, h3, _conn);
    int err;
    const char *err_desc = NULL;

    if (!h2o_http3_has_received_settings(&conn->h3)) {
        if (type != H2O_HTTP3_FRAME_TYPE_SETTINGS) {
            err = H2O_HTTP3_ERROR_MISSING_SETTINGS;
            goto Fail;
        }
        if ((err = h2o_http3_handle_settings_frame(&conn->h3, payload, len, &err_desc)) != 0)
            goto Fail;
        assert(h2o_http3_has_received_settings(&conn->h3));
        while (!h2o_linklist_is_empty(&conn->streams_resp_settings_blocked)) {
            struct st_h2o_http3_server_stream_t *stream = H2O_STRUCT_FROM_MEMBER(
                struct st_h2o_http3_server_stream_t, link_resp_settings_blocked, conn->streams_resp_settings_blocked.next);
            h2o_linklist_unlink(&stream->link_resp_settings_blocked);
            do_send(&stream->ostr_final, &stream->req, NULL, 0, H2O_SEND_STATE_IN_PROGRESS);
        }
    } else {
        switch (type) {
        case H2O_HTTP3_FRAME_TYPE_SETTINGS:
            err = H2O_HTTP3_ERROR_FRAME_UNEXPECTED;
            err_desc = "unexpected SETTINGS frame";
            goto Fail;
        case H2O_HTTP3_FRAME_TYPE_PRIORITY_UPDATE_REQUEST:
        case H2O_HTTP3_FRAME_TYPE_PRIORITY_UPDATE_PUSH: {
            h2o_http3_priority_update_frame_t frame;
            if ((err = h2o_http3_decode_priority_update_frame(&frame, type == H2O_HTTP3_FRAME_TYPE_PRIORITY_UPDATE_PUSH, payload,
                                                              len, &err_desc)) != 0)
                goto Fail;
            if ((err = handle_priority_update_frame(conn, &frame)) != 0) {
                err_desc = "invalid PRIORITY_UPDATE frame";
                goto Fail;
            }
        } break;
        default:
            break;
        }
    }

    return;
Fail:
    h2o_quic_close_connection(&conn->h3.super, err, err_desc);
}

static int stream_open_cb(quicly_stream_open_t *self, quicly_stream_t *qs)
{
    static const quicly_stream_callbacks_t callbacks = {on_stream_destroy, on_send_shift, on_send_emit,
                                                        on_send_stop,      on_receive,    on_receive_reset};

    /* handling of unidirectional streams is not server-specific */
    if (quicly_stream_is_unidirectional(qs->stream_id)) {
        h2o_http3_on_create_unidirectional_stream(qs);
        return 0;
    }

    assert(quicly_stream_is_client_initiated(qs->stream_id));

    struct st_h2o_http3_server_conn_t *conn =
        H2O_STRUCT_FROM_MEMBER(struct st_h2o_http3_server_conn_t, h3, *quicly_get_data(qs->conn));

    /* create new stream and start handling the request */
    struct st_h2o_http3_server_stream_t *stream = h2o_mem_alloc(sizeof(*stream));
    stream->quic = qs;
    h2o_buffer_init(&stream->recvbuf.buf, &h2o_socket_buffer_prototype);
    stream->recvbuf.handle_input = handle_input_expect_headers;
    memset(&stream->sendbuf, 0, sizeof(stream->sendbuf));
    stream->state = H2O_HTTP3_SERVER_STREAM_STATE_RECV_HEADERS;
    stream->link = (h2o_linklist_t){NULL};
    stream->link_resp_settings_blocked = (h2o_linklist_t){NULL};
    stream->ostr_final = (h2o_ostream_t){NULL, do_send, NULL, do_send_informational};
    stream->scheduler.link = (h2o_linklist_t){NULL};
    stream->scheduler.priority = h2o_absprio_default;
    stream->scheduler.call_cnt = 0;

    stream->read_blocked = 0;
    stream->proceed_requested = 0;
    stream->proceed_while_sending = 0;
    stream->received_priority_update = 0;
    stream->req_disposed = 0;
    stream->req_streaming = 0;
    stream->req_body = NULL;

    h2o_init_request(&stream->req, &conn->super, NULL);
    stream->req.version = 0x0300;
    stream->req._ostr_top = &stream->ostr_final;

    stream->quic->data = stream;
    stream->quic->callbacks = &callbacks;

    ++*get_state_counter(get_conn(stream), stream->state);
    h2o_conn_set_state(&get_conn(stream)->super, H2O_CONN_STATE_ACTIVE);

    return 0;
}

static quicly_stream_open_t on_stream_open = {stream_open_cb};

static void unblock_conn_blocked_streams(struct st_h2o_http3_server_conn_t *conn)
{
    conn->scheduler.uni.active |= conn->scheduler.uni.conn_blocked;
    conn->scheduler.uni.conn_blocked = 0;
    req_scheduler_unblock_conn_blocked(&conn->scheduler.reqs, req_scheduler_compare_stream_id);
}

static int scheduler_can_send(quicly_stream_scheduler_t *sched, quicly_conn_t *qc, int conn_is_saturated)
{
    struct st_h2o_http3_server_conn_t *conn = H2O_STRUCT_FROM_MEMBER(struct st_h2o_http3_server_conn_t, h3, *quicly_get_data(qc));

    if (!conn_is_saturated) {
        /* not saturated, activate streams marked as being conn-blocked */
        unblock_conn_blocked_streams(conn);
    } else {
        /* TODO lazily move the active request and unidirectional streams to conn_blocked.  Not doing so results in at most one
         * spurious call to quicly_send. */
    }

    if (conn->scheduler.uni.active != 0)
        return 1;
    if (conn->scheduler.reqs.active.smallest_urgency < H2O_ABSPRIO_NUM_URGENCY_LEVELS)
        return 1;

    return 0;
}

static int scheduler_do_send(quicly_stream_scheduler_t *sched, quicly_conn_t *qc, quicly_send_context_t *s)
{
    struct st_h2o_http3_server_conn_t *conn = H2O_STRUCT_FROM_MEMBER(struct st_h2o_http3_server_conn_t, h3, *quicly_get_data(qc));
    int ret = 0;

    while (quicly_can_send_data(conn->h3.super.quic, s)) {
        /* The strategy is:
         *
         * 1. dequeue the first active stream
         * 2. link the stream to the conn_blocked list, if nothing can be sent for the stream due to the connection being capped
         * 3. otherwise, send
         * 4. enqueue to the appropriate place
         */
        if (conn->scheduler.uni.active != 0) {
            static const ptrdiff_t stream_offsets[] = {
                offsetof(struct st_h2o_http3_server_conn_t, h3._control_streams.egress.control),
                offsetof(struct st_h2o_http3_server_conn_t, h3._control_streams.egress.qpack_encoder),
                offsetof(struct st_h2o_http3_server_conn_t, h3._control_streams.egress.qpack_decoder)};
            /* 1. obtain pointer to the offending stream */
            struct st_h2o_http3_egress_unistream_t *stream = NULL;
            size_t i;
            for (i = 0; i != sizeof(stream_offsets) / sizeof(stream_offsets[0]); ++i) {
                stream = *(void **)((char *)conn + stream_offsets[i]);
                if ((conn->scheduler.uni.active & (1 << stream->quic->stream_id)) != 0)
                    break;
            }
            assert(i != sizeof(stream_offsets) / sizeof(stream_offsets[0]) && "we should have found one stream");
            /* 2. move to the conn_blocked list if necessary */
            if (quicly_is_blocked(conn->h3.super.quic) && !quicly_stream_can_send(stream->quic, 0)) {
                conn->scheduler.uni.active &= ~(1 << stream->quic->stream_id);
                conn->scheduler.uni.conn_blocked |= 1 << stream->quic->stream_id;
                continue;
            }
            /* 3. send */
            if ((ret = quicly_send_stream(stream->quic, s)) != 0)
                goto Exit;
            /* 4. update scheduler state */
            conn->scheduler.uni.active &= ~(1 << stream->quic->stream_id);
            if (quicly_stream_can_send(stream->quic, 1)) {
                uint16_t *slot = &conn->scheduler.uni.active;
                if (quicly_is_blocked(conn->h3.super.quic) && !quicly_stream_can_send(stream->quic, 0))
                    slot = &conn->scheduler.uni.conn_blocked;
                *slot |= 1 << stream->quic->stream_id;
            }
        } else if (conn->scheduler.reqs.active.smallest_urgency < H2O_ABSPRIO_NUM_URGENCY_LEVELS) {
            /* 1. obtain pointer to the offending stream */
            h2o_linklist_t *anchor = &conn->scheduler.reqs.active.urgencies[conn->scheduler.reqs.active.smallest_urgency].high;
            if (h2o_linklist_is_empty(anchor)) {
                anchor = &conn->scheduler.reqs.active.urgencies[conn->scheduler.reqs.active.smallest_urgency].low;
                assert(!h2o_linklist_is_empty(anchor));
            }
            struct st_h2o_http3_server_stream_t *stream =
                H2O_STRUCT_FROM_MEMBER(struct st_h2o_http3_server_stream_t, scheduler.link, anchor->next);
            /* 1. link to the conn_blocked list if necessary */
            if (quicly_is_blocked(conn->h3.super.quic) && !quicly_stream_can_send(stream->quic, 0)) {
                req_scheduler_conn_blocked(&conn->scheduler.reqs, &stream->scheduler);
                continue;
            }
            /* 3. send */
            if ((ret = quicly_send_stream(stream->quic, s)) != 0)
                goto Exit;
            ++stream->scheduler.call_cnt;
            if (stream->quic->sendstate.size_inflight == stream->quic->sendstate.final_size &&
                h2o_timeval_is_null(&stream->req.timestamps.response_end_at))
                stream->req.timestamps.response_end_at = h2o_gettimeofday(stream->req.conn->ctx->loop);
            /* 4. invoke h2o_proceed_request synchronously, so that we could obtain additional data for the current (i.e. highest)
             *    stream. */
            if (stream->proceed_while_sending) {
                assert(stream->proceed_requested);
                h2o_proceed_response(&stream->req);
                stream->proceed_while_sending = 0;
            }
            /* 5. prepare for next */
            if (quicly_stream_can_send(stream->quic, 1)) {
                if (quicly_is_blocked(conn->h3.super.quic) && !quicly_stream_can_send(stream->quic, 0)) {
                    /* capped by connection-level flow control, move the stream to conn-blocked */
                    req_scheduler_conn_blocked(&conn->scheduler.reqs, &stream->scheduler);
                } else {
                    /* schedule for next emission */
                    req_scheduler_setup_for_next(&conn->scheduler.reqs, &stream->scheduler, req_scheduler_compare_stream_id);
                }
            } else {
                /* nothing to send at this moment */
                req_scheduler_deactivate(&conn->scheduler.reqs, &stream->scheduler);
            }
        } else {
            break;
        }
    }

Exit:
    return ret;
}

static int scheduler_update_state(struct st_quicly_stream_scheduler_t *sched, quicly_stream_t *qs)
{
    struct st_h2o_http3_server_conn_t *conn =
        H2O_STRUCT_FROM_MEMBER(struct st_h2o_http3_server_conn_t, h3, *quicly_get_data(qs->conn));
    enum { DEACTIVATE, ACTIVATE, CONN_BLOCKED } new_state;

    if (quicly_stream_can_send(qs, 1)) {
        if (quicly_is_blocked(conn->h3.super.quic) && !quicly_stream_can_send(qs, 0)) {
            new_state = CONN_BLOCKED;
        } else {
            new_state = ACTIVATE;
        }
    } else {
        new_state = DEACTIVATE;
    }

    if (quicly_stream_is_unidirectional(qs->stream_id)) {
        assert(qs->stream_id < sizeof(uint16_t) * 8);
        uint16_t mask = (uint16_t)1 << qs->stream_id;
        switch (new_state) {
        case DEACTIVATE:
            conn->scheduler.uni.active &= ~mask;
            conn->scheduler.uni.conn_blocked &= ~mask;
            break;
        case ACTIVATE:
            conn->scheduler.uni.active |= mask;
            conn->scheduler.uni.conn_blocked &= ~mask;
            break;
        case CONN_BLOCKED:
            conn->scheduler.uni.active &= ~mask;
            conn->scheduler.uni.conn_blocked |= mask;
            break;
        }
    } else {
        struct st_h2o_http3_server_stream_t *stream = qs->data;
        if (stream->proceed_while_sending)
            return 0;
        switch (new_state) {
        case DEACTIVATE:
            req_scheduler_deactivate(&conn->scheduler.reqs, &stream->scheduler);
            break;
        case ACTIVATE:
            req_scheduler_activate(&conn->scheduler.reqs, &stream->scheduler, req_scheduler_compare_stream_id);
            break;
        case CONN_BLOCKED:
            req_scheduler_conn_blocked(&conn->scheduler.reqs, &stream->scheduler);
            break;
        }
    }

    return 0;
}

static quicly_stream_scheduler_t scheduler = {scheduler_can_send, scheduler_do_send, scheduler_update_state};

static void datagram_frame_receive_cb(quicly_receive_datagram_frame_t *self, quicly_conn_t *quic, ptls_iovec_t datagram)
{
    struct st_h2o_http3_server_conn_t *conn = H2O_STRUCT_FROM_MEMBER(struct st_h2o_http3_server_conn_t, h3, *quicly_get_data(quic));
    uint64_t flow_id;
    h2o_iovec_t payload;

    /* decode */
    if ((flow_id = h2o_http3_decode_h3_datagram(&payload, datagram.base, datagram.len)) == UINT64_MAX) {
        h2o_quic_close_connection(&conn->h3.super, H2O_HTTP3_ERROR_GENERAL_PROTOCOL, "invalid DATAGRAM frame");
        return;
    }

    /* find stream */
    khiter_t iter = kh_get(stream, conn->datagram_flows, flow_id);
    if (iter == kh_end(conn->datagram_flows))
        return;
    struct st_h2o_http3_server_stream_t *stream = kh_val(conn->datagram_flows, iter);
    assert(stream->req.forward_datagram.write_ != NULL);

    /* forward */
    stream->req.forward_datagram.write_(&stream->req, &payload, 1);
}

static quicly_receive_datagram_frame_t on_receive_datagram_frame = {datagram_frame_receive_cb};

static void on_h3_destroy(h2o_quic_conn_t *h3_)
{
    h2o_http3_conn_t *h3 = (h2o_http3_conn_t *)h3_;
    struct st_h2o_http3_server_conn_t *conn = H2O_STRUCT_FROM_MEMBER(struct st_h2o_http3_server_conn_t, h3, h3);
    quicly_stats_t stats;

    H2O_PROBE_CONN0(H3S_DESTROY, &conn->super);

    if (quicly_get_stats(h3_->quic, &stats) == 0) {
#define ACC(fld, _unused) conn->super.ctx->quic_stats.quicly.fld += stats.fld;
        H2O_QUIC_AGGREGATED_STATS_APPLY(ACC);
#undef ACC
        if (conn->super.ctx->quic_stats.num_sentmap_packets_largest < stats.num_sentmap_packets_largest)
            conn->super.ctx->quic_stats.num_sentmap_packets_largest = stats.num_sentmap_packets_largest;
    }

    /* unlink and dispose */
    if (h2o_timer_is_linked(&conn->timeout))
        h2o_timer_unlink(&conn->timeout);
    if (h2o_timer_is_linked(&conn->_graceful_shutdown_timeout))
        h2o_timer_unlink(&conn->_graceful_shutdown_timeout);
    h2o_http3_dispose_conn(&conn->h3);
    kh_destroy(stream, conn->datagram_flows);

    /* check consistency post-disposal */
    assert(conn->num_streams.recv_headers == 0);
    assert(conn->num_streams.req_pending == 0);
    assert(conn->num_streams.send_headers == 0);
    assert(conn->num_streams.send_body == 0);
    assert(conn->num_streams.close_wait == 0);
    assert(conn->num_streams_req_streaming == 0);
    assert(conn->num_streams_tunnelling == 0);
    assert(h2o_linklist_is_empty(&conn->delayed_streams.recv_body_blocked));
    assert(h2o_linklist_is_empty(&conn->delayed_streams.req_streaming));
    assert(h2o_linklist_is_empty(&conn->delayed_streams.pending));
    assert(h2o_linklist_is_empty(&conn->streams_resp_settings_blocked));
    assert(conn->scheduler.reqs.active.smallest_urgency >= H2O_ABSPRIO_NUM_URGENCY_LEVELS);
    assert(h2o_linklist_is_empty(&conn->scheduler.reqs.conn_blocked));

    /* free memory */
    h2o_destroy_connection(&conn->super);
}

void h2o_http3_server_init_context(h2o_context_t *h2o, h2o_quic_ctx_t *ctx, h2o_loop_t *loop, h2o_socket_t *sock,
                                   quicly_context_t *quic, h2o_quic_accept_cb acceptor,
                                   h2o_quic_notify_connection_update_cb notify_conn_update, uint8_t use_gso)
{
    return h2o_quic_init_context(ctx, loop, sock, quic, acceptor, notify_conn_update, use_gso, &h2o->quic_stats);
}

h2o_http3_conn_t *h2o_http3_server_accept(h2o_http3_server_ctx_t *ctx, quicly_address_t *destaddr, quicly_address_t *srcaddr,
                                          quicly_decoded_packet_t *packet, quicly_address_token_plaintext_t *address_token,
                                          int skip_tracing, const h2o_http3_conn_callbacks_t *h3_callbacks)
{
    static const h2o_conn_callbacks_t conn_callbacks = {
        .get_sockname = get_sockname,
        .get_peername = get_peername,
        .get_ptls = get_ptls,
        .skip_tracing = get_skip_tracing,
        .get_req_id = get_req_id,
        .close_idle_connection = close_idle_connection,
        .foreach_request = foreach_request,
        .request_shutdown = initiate_graceful_shutdown,
        .num_reqs_inflight = num_reqs_inflight,
        .get_tracer = get_tracer,
        .log_ = {{
            .extensible_priorities = log_extensible_priorities,
            .transport =
                {
                    .cc_name = log_cc_name,
                    .delivery_rate = log_delivery_rate,
                },
            .ssl =
                {
                    .protocol_version = log_tls_protocol_version,
                    .session_reused = log_session_reused,
                    .cipher = log_cipher,
                    .cipher_bits = log_cipher_bits,
                    .session_id = log_session_id,
                    .server_name = log_server_name,
                    .negotiated_protocol = log_negotiated_protocol,
                    .ech_config_id = log_ech_config_id,
                    .ech_kem = log_ech_kem,
                    .ech_cipher = log_ech_cipher,
                    .ech_cipher_bits = log_ech_cipher_bits,
                },
            .http3 =
                {
                    .stream_id = log_stream_id,
                    .quic_stats = log_quic_stats,
                    .quic_version = log_quic_version,
                },
        }},
    };

    /* setup the structure */
    struct st_h2o_http3_server_conn_t *conn = (void *)h2o_create_connection(
        sizeof(*conn), ctx->accept_ctx->ctx, ctx->accept_ctx->hosts, h2o_gettimeofday(ctx->accept_ctx->ctx->loop), &conn_callbacks);
    memset((char *)conn + sizeof(conn->super), 0, sizeof(*conn) - sizeof(conn->super));

    h2o_http3_init_conn(&conn->h3, &ctx->super, h3_callbacks, &ctx->qpack);
    conn->handshake_properties = (ptls_handshake_properties_t){{{{NULL}}}};
    h2o_linklist_init_anchor(&conn->delayed_streams.recv_body_blocked);
    h2o_linklist_init_anchor(&conn->delayed_streams.req_streaming);
    h2o_linklist_init_anchor(&conn->delayed_streams.pending);
    h2o_linklist_init_anchor(&conn->streams_resp_settings_blocked);
    h2o_timer_init(&conn->timeout, run_delayed);
    memset(&conn->num_streams, 0, sizeof(conn->num_streams));
    conn->num_streams_req_streaming = 0;
    conn->num_streams_tunnelling = 0;
    req_scheduler_init(&conn->scheduler.reqs);
    conn->scheduler.uni.active = 0;
    conn->scheduler.uni.conn_blocked = 0;
    conn->datagram_flows = kh_init(stream);

    /* accept connection */
#if PICOTLS_USE_DTRACE
    unsigned orig_skip_tracing = ptls_default_skip_tracing;
    ptls_default_skip_tracing = skip_tracing;
#endif
    quicly_conn_t *qconn;
    int accept_ret = quicly_accept(
        &qconn, ctx->super.quic, &destaddr->sa, &srcaddr->sa, packet, address_token, &ctx->super.next_cid,
        &conn->handshake_properties,
        &conn->h3 /* back pointer is set up here so that callbacks being called while parsing ClientHello can refer to `conn` */);
#if PICOTLS_USE_DTRACE
    ptls_default_skip_tracing = orig_skip_tracing;
#endif
    if (accept_ret != 0) {
        h2o_http3_conn_t *ret = NULL;
        if (accept_ret == QUICLY_ERROR_DECRYPTION_FAILED)
            ret = (h2o_http3_conn_t *)&h2o_quic_accept_conn_decryption_failed;
        h2o_http3_dispose_conn(&conn->h3);
        kh_destroy(stream, conn->datagram_flows);
        h2o_destroy_connection(&conn->super);
        return ret;
    }
    if (ctx->super.quic_stats != NULL) {
        ++ctx->super.quic_stats->packet_processed;
    }
    ++ctx->super.next_cid.master_id; /* FIXME check overlap */
    h2o_http3_setup(&conn->h3, qconn);

    H2O_PROBE_CONN(H3S_ACCEPT, &conn->super, &conn->super, conn->h3.super.quic, h2o_conn_get_uuid(&conn->super));

    if (!h2o_quic_send(&conn->h3.super)) {
        /* When `h2o_quic_send` fails, it destroys the connection object. */
        return &h2o_http3_accept_conn_closed;
    }

    return &conn->h3;
}

void h2o_http3_server_amend_quicly_context(h2o_globalconf_t *conf, quicly_context_t *quic)
{
    quic->transport_params.max_data =
        conf->http3.active_stream_window_size; /* set to a size that does not block the unblocked request stream */
    quic->transport_params.max_streams_uni = 10;
    quic->transport_params.max_stream_data.bidi_remote = H2O_HTTP3_INITIAL_REQUEST_STREAM_WINDOW_SIZE;
    quic->transport_params.max_idle_timeout = conf->http3.idle_timeout;
    quic->transport_params.min_ack_delay_usec = conf->http3.allow_delayed_ack ? 0 : UINT64_MAX;
    quic->ack_frequency = conf->http3.ack_frequency;
    quic->transport_params.max_datagram_frame_size = 1500; /* accept DATAGRAM frames; let the sender determine MTU, instead of being
                                                            * potentially too restrictive */
    quic->stream_open = &on_stream_open;
    quic->stream_scheduler = &scheduler;
    quic->receive_datagram_frame = &on_receive_datagram_frame;
}

h2o_conn_t *h2o_http3_get_connection(quicly_conn_t *quic)
{
    struct st_h2o_http3_server_conn_t *conn = H2O_STRUCT_FROM_MEMBER(struct st_h2o_http3_server_conn_t, h3, *quicly_get_data(quic));

    /* this assertion is most likely to fire if the provided QUIC connection does not represent a server-side HTTP connection */
    assert(conn->h3.super.quic == NULL || conn->h3.super.quic == quic);

    return &conn->super;
}

static void graceful_shutdown_close_straggler(h2o_timer_t *entry)
{
    struct st_h2o_http3_server_conn_t *conn =
        H2O_STRUCT_FROM_MEMBER(struct st_h2o_http3_server_conn_t, _graceful_shutdown_timeout, entry);

    /* We've sent two GOAWAY frames, close the remaining connections */
    h2o_quic_close_connection(&conn->h3.super, 0, "shutting down");

    conn->_graceful_shutdown_timeout.cb = NULL;
}

static void graceful_shutdown_resend_goaway(h2o_timer_t *entry)
{
    struct st_h2o_http3_server_conn_t *conn =
        H2O_STRUCT_FROM_MEMBER(struct st_h2o_http3_server_conn_t, _graceful_shutdown_timeout, entry);

    /* HTTP/3 draft section 5.2.8 --
     * "After allowing time for any in-flight requests or pushes to arrive, the endpoint can send another GOAWAY frame
     * indicating which requests or pushes it might accept before the end of the connection.
     * This ensures that a connection can be cleanly shut down without losing requests. */

    if (conn->h3.state < H2O_HTTP3_CONN_STATE_HALF_CLOSED && quicly_get_state(conn->h3.super.quic) == QUICLY_STATE_CONNECTED) {
        quicly_stream_id_t next_stream_id = quicly_get_remote_next_stream_id(conn->h3.super.quic, 0 /* == bidi */);
        /* Section 5.2-1: "This identifier MAY be zero if no requests or pushes were processed."" */
        quicly_stream_id_t max_stream_id = next_stream_id < 4 ? 0 /* we haven't received any stream yet */ : next_stream_id - 4;
        h2o_http3_send_goaway_frame(&conn->h3, max_stream_id);
        conn->h3.state = H2O_HTTP3_CONN_STATE_HALF_CLOSED;
        /* After waiting a second, we still have an active connection. If configured, wait one
         * final timeout before closing the connection */
        if (conn->super.ctx->globalconf->http3.graceful_shutdown_timeout > 0) {
            conn->_graceful_shutdown_timeout.cb = graceful_shutdown_close_straggler;
            h2o_timer_link(conn->super.ctx->loop, conn->super.ctx->globalconf->http3.graceful_shutdown_timeout,
                           &conn->_graceful_shutdown_timeout);
        } else {
            conn->_graceful_shutdown_timeout.cb = NULL;
        }
    }
}

static void close_idle_connection(h2o_conn_t *_conn)
{
    initiate_graceful_shutdown(_conn);
}

static void initiate_graceful_shutdown(h2o_conn_t *_conn)
{
    h2o_conn_set_state(_conn, H2O_CONN_STATE_SHUTDOWN);

    struct st_h2o_http3_server_conn_t *conn = (void *)_conn;
    assert(conn->_graceful_shutdown_timeout.cb == NULL);
    conn->_graceful_shutdown_timeout.cb = graceful_shutdown_resend_goaway;

    h2o_http3_send_shutdown_goaway_frame(&conn->h3);

    h2o_timer_link(conn->super.ctx->loop, 1000, &conn->_graceful_shutdown_timeout);
}

struct foreach_request_ctx {
    int (*cb)(h2o_req_t *req, void *cbdata);
    void *cbdata;
};

static int foreach_request_per_conn(void *_ctx, quicly_stream_t *qs)
{
    struct foreach_request_ctx *ctx = _ctx;

    /* skip if the stream is not a request stream (TODO handle push?) */
    if (!(quicly_stream_is_client_initiated(qs->stream_id) && !quicly_stream_is_unidirectional(qs->stream_id)))
        return 0;

    struct st_h2o_http3_server_stream_t *stream = qs->data;
    assert(stream->quic == qs);

    if (stream->state == H2O_HTTP3_SERVER_STREAM_STATE_CLOSE_WAIT)
        return 0;
    return ctx->cb(&stream->req, ctx->cbdata);
}

static int foreach_request(h2o_conn_t *_conn, int (*cb)(h2o_req_t *req, void *cbdata), void *cbdata)
{
    struct foreach_request_ctx foreach_ctx = {.cb = cb, .cbdata = cbdata};

    struct st_h2o_http3_server_conn_t *conn = (void *)_conn;
    quicly_foreach_stream(conn->h3.super.quic, &foreach_ctx, foreach_request_per_conn);
    return 0;
}

const h2o_http3_conn_callbacks_t H2O_HTTP3_CONN_CALLBACKS = {{on_h3_destroy}, handle_control_stream_frame};
