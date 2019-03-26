#ifndef h2o__tracing_h
#define h2o__tracing_h

#ifdef __cplusplus
extern "C" {
#endif

// MSB indicates tracepoint should be disabled
#define H2O_TRACE_REMOVE_PROBE ((uint64_t)1<<63)

// list of available tracepoints
#define H2O_TRACE_SSLNEW     ((uint64_t)1<<0)
#define H2O_TRACE_H1NEW      ((uint64_t)1<<1)
#define H2O_TRACE_H2NEW      ((uint64_t)1<<2)
#define H2O_TRACE_REQ        ((uint64_t)1<<3)
#define H2O_TRACE_RES        ((uint64_t)1<<4)
#define H2O_TRACE_TXHD       ((uint64_t)1<<5)
#define H2O_TRACE_RXHD       ((uint64_t)1<<6)
#define H2O_TRACE_PROXY_REQ  ((uint64_t)1<<7)
#define H2O_TRACE_PROXY_RES  ((uint64_t)1<<8)
#define H2O_TRACE_PROXY_TXHD ((uint64_t)1<<9)
#define H2O_TRACE_PROXY_RXHD ((uint64_t)1<<10)

struct st_h2o_tracing_conn_t {
    h2o_conn_t super;
    h2o_socket_t *sock;

    /* internal structure */
    h2o_linklist_t _conns;
    h2o_req_t req;
};

void h2o_tracing_accept(h2o_accept_ctx_t *ctx, h2o_socket_t *sock, struct timeval connected_at);

extern uint64_t h2o_tracing_now;

#ifdef __cplusplus
}
#endif

#endif

