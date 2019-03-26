#include "h2o.h"
#include <h2o/sdt.h>
#include <h2o/tracing.h>
#include <fcntl.h>

// ebpf tracer payload size
#define EBPF_P0_SZ 150
#define EBPF_P1_SZ 50
#define EBPF_P2_SZ 50

#define DOING_TRACE(trace) ((h2o_tracing_now & trace) == trace)

#define CONN_GET_FD(conn) h2o_socket_get_fd((conn)->callbacks->get_socket(conn))

#define STRINGIFY_VECT_TO_P0(vect, append)                                                                                         \
    do {                                                                                                                           \
        int _len = EBPF_P0_SZ - i - 2 > (vect).len ? (vect).len : EBPF_P0_SZ - i - 2;                                              \
        memcpy(&payload0[i], (vect).base, _len);                                                                                   \
        i += _len;                                                                                                                 \
        payload0[i++] = append;                                                                                                    \
    } while (0)

#define STRINGIFY_HEADER_TO_P0(hd)                                                                                                 \
    do {                                                                                                                           \
        STRINGIFY_VECT_TO_P0(*(hd->name), ' ');                                                                                    \
        STRINGIFY_VECT_TO_P0(hd->value, '\0');                                                                                     \
    } while (0)

void stringify_ip_tuple(char *payload, h2o_socket_t *sock)
{
    char sockname[50];
    char peername[50];
    int32_t sockport, peerport;
    struct sockaddr_storage sa;
    socklen_t salen;

    salen = h2o_socket_getsockname(sock, (void *)&sa);
    h2o_socket_getnumerichost((void *)&sa, salen, &sockname[0]);
    sockport = h2o_socket_getport((void *)&sa);

    salen = h2o_socket_getpeername(sock, (void *)&sa);
    h2o_socket_getnumerichost((void *)&sa, salen, &peername[0]);
    peerport = h2o_socket_getport((void *)&sa);
    snprintf(payload, EBPF_P0_SZ, "%s:%d %s:%d", sockname, sockport, peername, peerport);
}

void h2o_trace_newssl(struct timeval ts, h2o_socket_t *sock)
{
    if (!DOING_TRACE(H2O_TRACE_SSLNEW)) {
        return;
    }
    char payload0[EBPF_P2_SZ];
    h2o_iovec_t sessId = h2o_socket_get_ssl_session_id(sock);
    snprintf(&payload0[0], EBPF_P2_SZ, "%p", &sessId.base);
    DTRACE_PROBE6(h2otrace, SSLNew, ts.tv_sec, ts.tv_usec, h2o_socket_get_fd(sock), h2o_socket_get_ssl_protocol_version(sock),
                  h2o_socket_get_ssl_cipher(sock), &payload0[0]);
}

void h2o_trace_newh1(struct timeval ts, h2o_socket_t *sock)
{
    if (!DOING_TRACE(H2O_TRACE_H1NEW)) {
        return;
    }
    char payload0[EBPF_P0_SZ];
    stringify_ip_tuple(&payload0[0], sock);
    DTRACE_PROBE4(h2otrace, NewConnH1, ts.tv_sec, ts.tv_usec, h2o_socket_get_fd(sock), &payload0[0]);
}

void h2o_trace_newh2(struct timeval ts, h2o_socket_t *sock)
{
    if (!DOING_TRACE(H2O_TRACE_H2NEW)) {
        return;
    }
    char payload0[EBPF_P0_SZ];
    stringify_ip_tuple(&payload0[0], sock);
    DTRACE_PROBE4(h2otrace, NewConnH2, ts.tv_sec, ts.tv_usec, h2o_socket_get_fd(sock), &payload0[0]);
}

void h2o_trace_req(h2o_req_t *req)
{
    if (!DOING_TRACE(H2O_TRACE_REQ) && !DOING_TRACE(H2O_TRACE_RXHD)) {
        return;
    }
    int i = 0;
    h2o_headers_t *hds = &req->headers;
    struct timeval ts = req->conn->connected_at;
    char payload0[EBPF_P0_SZ];

    for (int j = 0; DOING_TRACE(H2O_TRACE_RXHD) && j < hds->size; j++, i = 0) {
        h2o_header_t *hd = &hds->entries[j];
        STRINGIFY_HEADER_TO_P0(hd);
        DTRACE_PROBE4(h2otrace, RxHeader, ts.tv_sec, ts.tv_usec, CONN_GET_FD(req->conn), &payload0[0]);
    }

    if (DOING_TRACE(H2O_TRACE_REQ)) {
        i = h2o_stringify_protocol_version(&payload0[0], req->version);
        payload0[i++] = ' ';
        STRINGIFY_VECT_TO_P0(req->method, ' ');
        STRINGIFY_VECT_TO_P0(req->path, '\0');
        DTRACE_PROBE4(h2otrace, NewReq, ts.tv_sec, ts.tv_usec, CONN_GET_FD(req->conn), &payload0[0]);
    }
}

void h2o_trace_res(h2o_req_t *req)
{
    if (!DOING_TRACE(H2O_TRACE_RES) && !DOING_TRACE(H2O_TRACE_TXHD)) {
        return;
    }
    int i = 0;
    h2o_res_t *res = &req->res;
    h2o_headers_t *hds = &res->headers;
    struct timeval ts = req->conn->connected_at;
    char payload0[EBPF_P0_SZ];

    for (int j = 0; DOING_TRACE(H2O_TRACE_TXHD) && j < hds->size; j++, i = 0) {
        h2o_header_t *hd = &hds->entries[j];
        STRINGIFY_HEADER_TO_P0(hd);
        DTRACE_PROBE4(h2otrace, TxHeader, ts.tv_sec, ts.tv_usec, CONN_GET_FD(req->conn), &payload0[0]);
    }

    if (DOING_TRACE(H2O_TRACE_RES)) {
        i = h2o_stringify_protocol_version(&payload0[0], req->version);
        snprintf(&payload0[i], EBPF_P0_SZ - i, " %d len: %ld", res->status, res->content_length);
        DTRACE_PROBE4(h2otrace, NewRes, ts.tv_sec, ts.tv_usec, CONN_GET_FD(req->conn), &payload0[0]);
    }
}

void h2o_trace_proxyreq(h2o_req_t *req)
{
    if (!DOING_TRACE(H2O_TRACE_PROXY_REQ) && !DOING_TRACE(H2O_TRACE_PROXY_TXHD)) {
        return;
    }
    int i = 0;
    h2o_headers_t *hds = &req->headers;
    struct timeval ts = req->conn->connected_at;
    char payload0[EBPF_P0_SZ];

    STRINGIFY_VECT_TO_P0(req->authority, '\0');
    DTRACE_PROBE4(h2otrace, Proxy, ts.tv_sec, ts.tv_usec, CONN_GET_FD(req->conn), &payload0[0]);

    for (int j = 0, i = 0; DOING_TRACE(H2O_TRACE_PROXY_TXHD) && j < hds->size; j++, i = 0) {
        h2o_header_t *hd = &hds->entries[j];
        STRINGIFY_HEADER_TO_P0(hd);
        DTRACE_PROBE4(h2otrace, ProxyTxHdr, ts.tv_sec, ts.tv_usec, CONN_GET_FD(req->conn), &payload0[0]);
    }

    if (DOING_TRACE(H2O_TRACE_PROXY_REQ)) {
        i = h2o_stringify_protocol_version(&payload0[0], 0x101);
        payload0[i++] = ' ';
        STRINGIFY_VECT_TO_P0(req->method, ' ');
        STRINGIFY_VECT_TO_P0(req->path, '\0');
        DTRACE_PROBE4(h2otrace, ProxyNewReq, ts.tv_sec, ts.tv_usec, CONN_GET_FD(req->conn), &payload0[0]);
    }
}

void h2o_trace_proxyres(h2o_req_t *req)
{
    if (!DOING_TRACE(H2O_TRACE_PROXY_RES) && !DOING_TRACE(H2O_TRACE_PROXY_RXHD)) {
        return;
    }
    int i = 0;
    h2o_res_t *res = &req->res;
    h2o_headers_t *hds = &res->headers;
    struct timeval ts = req->conn->connected_at;
    char payload0[EBPF_P0_SZ];

    for (int j = 0; DOING_TRACE(H2O_TRACE_PROXY_RXHD) && j < hds->size; j++, i = 0) {
        h2o_header_t *hd = &hds->entries[j];
        STRINGIFY_HEADER_TO_P0(hd);
        DTRACE_PROBE4(h2otrace, ProxyRxHdr, ts.tv_sec, ts.tv_usec, CONN_GET_FD(req->conn), &payload0[0]);
    }

    if (DOING_TRACE(H2O_TRACE_PROXY_RES)) {
        i = h2o_stringify_protocol_version(&payload0[0], 0x101);
        snprintf(&payload0[i], EBPF_P0_SZ - i, " %d len: %ld", res->status, res->content_length);
        DTRACE_PROBE4(h2otrace, ProxyNewRes, ts.tv_sec, ts.tv_usec, CONN_GET_FD(req->conn), &payload0[0]);
    }
}
