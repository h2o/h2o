#include "h2o.h"
#include "h2o/tracing.h"
struct tracing_msg {
    uint64_t magic;
};

enum h2o_tracing_action {
    H2O_TRACING_ACTION_OK,
    H2O_TRACING_ACTION_CLOSE,
};

uint64_t h2o_tracing_now;
uint64_t should_stop_probe;

#define IS_REMOVE_BIT_SET(x) ((x & H2O_TRACE_REMOVE_PROBE) == H2O_TRACE_REMOVE_PROBE)

static void on_tracing_message_done(struct st_h2o_tracing_conn_t *conn, enum h2o_tracing_action action);

static void close_connection(struct st_h2o_tracing_conn_t *conn, int close_socket)
{
    if (should_stop_probe != 0) {
        __sync_fetch_and_and(&h2o_tracing_now, should_stop_probe);
        __sync_fetch_and_and(&should_stop_probe, 0x0);
    } else {
        __sync_fetch_and_and(&h2o_tracing_now, 0x0);
    }

    if (conn->sock != NULL && close_socket)
        h2o_socket_close(conn->sock);
    h2o_linklist_unlink(&conn->_conns);
    free(conn);
}

static socklen_t get_sockname(h2o_conn_t *_conn, struct sockaddr *sa)
{
    struct st_h2o_tracing_conn_t *conn = (void *)_conn;
    return h2o_socket_getsockname(conn->sock, sa);
}

static socklen_t get_peername(h2o_conn_t *_conn, struct sockaddr *sa)
{
    struct st_h2o_tracing_conn_t *conn = (void *)_conn;
    return h2o_socket_getpeername(conn->sock, sa);
}

static h2o_socket_t *get_socket(h2o_conn_t *_conn)
{
    struct st_h2o_tracing_conn_t *conn = (void *)_conn;
    return conn->sock;
}

static int foreach_request(h2o_context_t *ctx, int (*cb)(h2o_req_t *req, void *cbdata), void *cbdata)
{
    h2o_linklist_t *node;

    for (node = ctx->tracing._conns.next; node != &ctx->tracing._conns; node = node->next) {
        struct st_h2o_tracing_conn_t *conn = H2O_STRUCT_FROM_MEMBER(struct st_h2o_tracing_conn_t, _conns, node);
        int ret = cb(&conn->req, cbdata);
        if (ret != 0)
            return ret;
    }
    return 0;
}

static void init_request(struct st_h2o_tracing_conn_t *conn, int reinit)
{
    if (reinit)
        h2o_dispose_request(&conn->req);
    h2o_init_request(&conn->req, &conn->super, NULL);
}

static void on_tracing_message(struct st_h2o_tracing_conn_t *conn, struct tracing_msg *bmsg);
static void handle_incoming_request(struct st_h2o_tracing_conn_t *conn)
{
    size_t inreqlen = conn->sock->input->size < H2O_MAX_REQLEN ? conn->sock->input->size : H2O_MAX_REQLEN;
    struct tracing_msg *bmsg;

    if (inreqlen < sizeof(*bmsg)) {
        return;
    }
    bmsg = (void *)conn->sock->input->bytes;

    on_tracing_message(conn, bmsg);
}

static void reqread_on_read(h2o_socket_t *sock, const char *err)
{
    struct st_h2o_tracing_conn_t *conn = sock->data;

    if (err != NULL) {
        close_connection(conn, 1);
        return;
    }

    handle_incoming_request(conn);
}

static inline void reqread_start(struct st_h2o_tracing_conn_t *conn)
{
    h2o_socket_read_start(conn->sock, reqread_on_read);
    if (conn->sock->input->size != 0)
        handle_incoming_request(conn);
}


void on_tracing_msg_written(h2o_socket_t *sock, const char *err)
{
    struct st_h2o_tracing_conn_t *conn = sock->data;

    if (err) {
        on_tracing_message_done(conn, H2O_TRACING_ACTION_CLOSE);
        return;
    }
    on_tracing_message_done(conn, H2O_TRACING_ACTION_OK);
}

static void on_tracing_message(struct st_h2o_tracing_conn_t *conn, struct tracing_msg *bmsg)
{
    if (IS_REMOVE_BIT_SET(bmsg->magic)) {
        // add probe in disable list
        uint64_t stopping = (~bmsg->magic) & h2o_tracing_now;
        __sync_fetch_and_or(&should_stop_probe, stopping);
    } else {
        // add new tracer query to filter
        __sync_fetch_and_or(&h2o_tracing_now, bmsg->magic);
    }

    h2o_buffer_consume(&conn->sock->input, sizeof(struct tracing_msg));
}

const h2o_protocol_callbacks_t H2O_BLINK_CALLBACKS = {
    NULL, /* graceful_shutdown (note: nothing special needs to be done for handling graceful shutdown) */
    foreach_request};

void h2o_tracing_accept(h2o_accept_ctx_t *ctx, h2o_socket_t *sock, struct timeval connected_at)
{
    static const h2o_conn_callbacks_t callbacks = {
        get_sockname, /* stringify address */
        get_peername, /* ditto */
        NULL,         /* push */
        get_socket,   /* get underlying socket */
        NULL,         /* get debug state */
        {{
            {NULL}, /* ssl */
            {NULL}, /* http1 */
            {NULL}  /* http2 */
        }}};
    struct st_h2o_tracing_conn_t *conn = (void *)h2o_create_connection(sizeof(*conn), ctx->ctx, ctx->hosts, connected_at, &callbacks);

    /* FIXME: zero-fill all properties expect req */
    memset(conn, 0, sizeof(*conn));

    /* init properties that need to be non-zero */
    conn->super.ctx = ctx->ctx;
    conn->super.hosts = ctx->hosts;
    conn->super.connected_at = connected_at;
    conn->super.callbacks = &callbacks;
    conn->sock = sock;
    sock->data = conn;
    h2o_linklist_insert(&ctx->ctx->tracing._conns, &conn->_conns);

    init_request(conn, 0);
    reqread_start(conn);
}

void on_tracing_message_done(struct st_h2o_tracing_conn_t *conn, enum h2o_tracing_action action)
{
    int do_close = 0;

    h2o_buffer_consume(&conn->sock->input, sizeof(struct tracing_msg));

    switch (action) {
    case H2O_TRACING_ACTION_OK:
        reqread_start(conn);
        break;
    case H2O_TRACING_ACTION_CLOSE:
        do_close = 1;
        break;
    default:
        assert(0 && "Unknown action for lib/blink.c handler");
    }

    if (do_close) {
        close_connection(conn, 1);
    }
    return;
}
