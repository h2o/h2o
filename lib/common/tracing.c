#include "h2o.h"
#include <h2o/sdt.h>
#include <h2o/tracing.h>
#include <fcntl.h>

// tracer payload size
#define PAYLOAD_SZ 150

#define DOING_TRACE(trace) ((h2o_tracing_now & trace) == trace)

#define CONN_GET_FD(conn) h2o_socket_get_fd((conn)->callbacks->get_socket(conn))

#define VECT_TO_PAYLOAD(vect, append)                                                                                              \
    do {                                                                                                                           \
        int _len = PAYLOAD_SZ - i - 2 > (vect).len ? (vect).len : PAYLOAD_SZ - i - 2;                                              \
        memcpy(&payload[i], (vect).base, _len);                                                                                    \
        i += _len;                                                                                                                 \
        payload[i++] = append;                                                                                                     \
    } while (0)

#define HEADER_TO_PAYLOAD(hd)                                                                                                      \
    do {                                                                                                                           \
        VECT_TO_PAYLOAD(*(hd->name), ' ');                                                                                         \
        VECT_TO_PAYLOAD(hd->value, '\0');                                                                                          \
    } while (0)

void ip_tuple(char *payload, h2o_socket_t *sock)
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
    snprintf(payload, PAYLOAD_SZ, "%s:%d %s:%d", sockname, sockport, peername, peerport);
}

void h2o_trace_newssl(struct timeval ts, h2o_socket_t *sock)
{
    if (!DOING_TRACE(H2O_TRACE_SSLNEW)) {
        return;
    }
    char payload[PAYLOAD_SZ];
    h2o_iovec_t sessId = h2o_socket_get_ssl_session_id(sock);
    snprintf(&payload[0], PAYLOAD_SZ, "%s %s %p", h2o_socket_get_ssl_protocol_version(sock), h2o_socket_get_ssl_cipher(sock), &sessId.base);
    DTRACE_PROBE4(h2otrace, SSLNew, ts.tv_sec, ts.tv_usec, h2o_socket_get_fd(sock), &payload[0]);
}

void h2o_trace_newh1(struct timeval ts, h2o_socket_t *sock)
{
    if (!DOING_TRACE(H2O_TRACE_H1NEW)) {
        return;
    }
    char payload[PAYLOAD_SZ];
    ip_tuple(&payload[0], sock);
    DTRACE_PROBE4(h2otrace, NewConnH1, ts.tv_sec, ts.tv_usec, h2o_socket_get_fd(sock), &payload[0]);
}

void h2o_trace_newh2(struct timeval ts, h2o_socket_t *sock)
{
    if (!DOING_TRACE(H2O_TRACE_H2NEW)) {
        return;
    }
    char payload[PAYLOAD_SZ];
    ip_tuple(&payload[0], sock);
    DTRACE_PROBE4(h2otrace, NewConnH2, ts.tv_sec, ts.tv_usec, h2o_socket_get_fd(sock), &payload[0]);
}

void h2o_trace_req(h2o_req_t *req)
{
    if (!DOING_TRACE(H2O_TRACE_REQ) && !DOING_TRACE(H2O_TRACE_RXHD)) {
        return;
    }
    int i = 0;
    h2o_headers_t *hds = &req->headers;
    struct timeval ts = req->conn->connected_at;
    char payload[PAYLOAD_SZ];

    for (int j = 0; DOING_TRACE(H2O_TRACE_RXHD) && j < hds->size; j++, i = 0) {
        h2o_header_t *hd = &hds->entries[j];
        HEADER_TO_PAYLOAD(hd);
        DTRACE_PROBE4(h2otrace, RxHeader, ts.tv_sec, ts.tv_usec, CONN_GET_FD(req->conn), &payload[0]);
    }

    if (DOING_TRACE(H2O_TRACE_REQ)) {
        i = h2o_stringify_protocol_version(&payload[0], req->version);
        payload[i++] = ' ';
        VECT_TO_PAYLOAD(req->method, ' ');
        VECT_TO_PAYLOAD(req->path, '\0');
        DTRACE_PROBE4(h2otrace, NewReq, ts.tv_sec, ts.tv_usec, CONN_GET_FD(req->conn), &payload[0]);
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
    char payload[PAYLOAD_SZ];

    for (int j = 0; DOING_TRACE(H2O_TRACE_TXHD) && j < hds->size; j++, i = 0) {
        h2o_header_t *hd = &hds->entries[j];
        HEADER_TO_PAYLOAD(hd);
        DTRACE_PROBE4(h2otrace, TxHeader, ts.tv_sec, ts.tv_usec, CONN_GET_FD(req->conn), &payload[0]);
    }

    if (DOING_TRACE(H2O_TRACE_RES)) {
        i = h2o_stringify_protocol_version(&payload[0], req->version);
        snprintf(&payload[i], PAYLOAD_SZ - i, " %d len: %ld", res->status, res->content_length);
        DTRACE_PROBE4(h2otrace, NewRes, ts.tv_sec, ts.tv_usec, CONN_GET_FD(req->conn), &payload[0]);
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
    char payload[PAYLOAD_SZ];

    if (DOING_TRACE(H2O_TRACE_PROXY)) {
        VECT_TO_PAYLOAD(req->authority, '\0');
        DTRACE_PROBE4(h2otrace, Proxy, ts.tv_sec, ts.tv_usec, CONN_GET_FD(req->conn), &payload[0]);
    }

    for (int j = 0, i = 0; DOING_TRACE(H2O_TRACE_PROXY_TXHD) && j < hds->size; j++, i = 0) {
        h2o_header_t *hd = &hds->entries[j];
        HEADER_TO_PAYLOAD(hd);
        DTRACE_PROBE4(h2otrace, ProxyTxHdr, ts.tv_sec, ts.tv_usec, CONN_GET_FD(req->conn), &payload[0]);
    }

    if (DOING_TRACE(H2O_TRACE_PROXY_REQ)) {
        i = h2o_stringify_protocol_version(&payload[0], 0x101);
        payload[i++] = ' ';
        VECT_TO_PAYLOAD(req->method, ' ');
        VECT_TO_PAYLOAD(req->path, '\0');
        DTRACE_PROBE4(h2otrace, ProxyNewReq, ts.tv_sec, ts.tv_usec, CONN_GET_FD(req->conn), &payload[0]);
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
    char payload[PAYLOAD_SZ];

    for (int j = 0; DOING_TRACE(H2O_TRACE_PROXY_RXHD) && j < hds->size; j++, i = 0) {
        h2o_header_t *hd = &hds->entries[j];
        HEADER_TO_PAYLOAD(hd);
        DTRACE_PROBE4(h2otrace, ProxyRxHdr, ts.tv_sec, ts.tv_usec, CONN_GET_FD(req->conn), &payload[0]);
    }

    if (DOING_TRACE(H2O_TRACE_PROXY_RES)) {
        i = h2o_stringify_protocol_version(&payload[0], 0x101);
        snprintf(&payload[i], PAYLOAD_SZ - i, " %d len: %ld", res->status, res->content_length);
        DTRACE_PROBE4(h2otrace, ProxyNewRes, ts.tv_sec, ts.tv_usec, CONN_GET_FD(req->conn), &payload[0]);
    }
}
