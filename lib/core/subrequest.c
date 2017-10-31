/*
 * Copyright (c) 2017 Fastly, Inc.
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

struct st_h2o_subreq_t {
    h2o_req_t super;
    h2o_req_t *src;
    h2o_conn_t conn;
};

static socklen_t get_sockname(h2o_conn_t *_conn, struct sockaddr *sa)
{
    struct st_h2o_subreq_t *subreq = H2O_STRUCT_FROM_MEMBER(struct st_h2o_subreq_t, conn, _conn);
    h2o_conn_t *conn = subreq->src->conn;
    return conn->callbacks->get_sockname(conn, sa);
}

static socklen_t get_peername(h2o_conn_t *_conn, struct sockaddr *sa)
{
    struct st_h2o_subreq_t *subreq = H2O_STRUCT_FROM_MEMBER(struct st_h2o_subreq_t, conn, _conn);
    h2o_conn_t *conn = subreq->src->conn;
    return conn->callbacks->get_peername(conn, sa);
}

static h2o_socket_t *get_socket(h2o_conn_t *_conn)
{
    struct st_h2o_subreq_t *subreq = H2O_STRUCT_FROM_MEMBER(struct st_h2o_subreq_t, conn, _conn);
    h2o_conn_t *conn = subreq->src->conn;
    return conn->callbacks->get_socket(conn);
}

static h2o_http2_debug_state_t *get_debug_state(h2o_req_t *req, int hpack_enabled)
{
    struct st_h2o_subreq_t *subreq = (void *)req;
    return subreq->src->conn->callbacks->get_debug_state(subreq->src, hpack_enabled);
}

#define DEFINE_LOGGER(category, name)                                                                                              \
    static h2o_iovec_t log_##name(h2o_req_t *req)                                                                                  \
    {                                                                                                                              \
        struct st_h2o_subreq_t *subreq = (void *)req;                                                                              \
        return subreq->src->conn->callbacks->log_.category.name(subreq->src);                                                      \
    }

DEFINE_LOGGER(ssl, protocol_version)
DEFINE_LOGGER(ssl, session_reused)
DEFINE_LOGGER(ssl, cipher)
DEFINE_LOGGER(ssl, cipher_bits)
DEFINE_LOGGER(ssl, session_id)
DEFINE_LOGGER(http1, request_index)
DEFINE_LOGGER(http2, stream_id)
DEFINE_LOGGER(http2, priority_received)
DEFINE_LOGGER(http2, priority_received_exclusive)
DEFINE_LOGGER(http2, priority_received_parent)
DEFINE_LOGGER(http2, priority_received_weight)
DEFINE_LOGGER(http2, priority_actual)
DEFINE_LOGGER(http2, priority_actual_parent)
DEFINE_LOGGER(http2, priority_actual_weight)

#undef DEFINE_LOGGER

static const h2o_conn_callbacks_t http1_callbacks = {
    get_sockname, /* stringify address */
    get_peername, /* ditto */
    NULL,         /* push */
    get_socket,   /* get underlying socket */
    NULL,         /* get debug state */
    {{
        {log_protocol_version, log_session_reused, log_cipher, log_cipher_bits, log_session_id}, /* ssl */
        {log_request_index},                                                                     /* http1 */
        {NULL}                                                                                   /* http2 */
    }}};

static const h2o_conn_callbacks_t http2_callbacks = {
    get_sockname,    /* stringify address */
    get_peername,    /* ditto */
    NULL,            /* push */
    get_socket,      /* get underlying socket */
    get_debug_state, /* get debug state */
    {{
        {log_protocol_version, log_session_reused, log_cipher, log_cipher_bits, log_session_id}, /* ssl */
        {NULL},                                                                                  /* http1 */
        {log_stream_id, log_priority_received, log_priority_received_exclusive, log_priority_received_parent,
         log_priority_received_weight, log_priority_actual, log_priority_actual_parent, log_priority_actual_weight} /* http2 */
    }}};

static const h2o_conn_callbacks_t *get_subreq_callbacks(h2o_req_t *req)
{
    return req->version < 0x200 ? &http1_callbacks : &http2_callbacks;
}

h2o_req_t *h2o_create_subrequest(h2o_req_t *src)
{
    struct st_h2o_subreq_t *subreq = h2o_mem_alloc(sizeof(*subreq));
    subreq->conn.ctx = src->conn->ctx;
    subreq->conn.hosts = src->conn->hosts;
    subreq->conn.connected_at = src->conn->connected_at;
    subreq->conn.id = src->conn->id;
    subreq->conn.callbacks = get_subreq_callbacks(src);
    h2o_init_request(&subreq->super, &subreq->conn, NULL);

    subreq->src = src;
    subreq->super.input = src->input;
    subreq->super.hostconf = src->hostconf;
    subreq->super.pathconf = src->pathconf;
    subreq->super.version = src->version;
    subreq->super.error_logs = src->error_logs;
    subreq->super.num_delegated = src->num_delegated;
    subreq->super.num_reprocessed = src->num_reprocessed;
    subreq->super.processed_at = src->processed_at;

    return &subreq->super;
}

void h2o_dispose_subrequest(h2o_req_t *subreq)
{
    assert(h2o_is_subrequst(subreq));
    h2o_dispose_request(subreq);
    free(subreq);
}

int h2o_is_subrequst(h2o_req_t *req)
{
    const h2o_conn_callbacks_t *subreq_callbacks = get_subreq_callbacks(req);
    return req->conn->callbacks == subreq_callbacks;
}
