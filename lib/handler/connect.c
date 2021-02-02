/*
 * Copyright (c) 2021 Fastly Inc.
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
#include <sys/un.h>
#include "h2o.h"
#include "h2o/socketpool.h"
#include "h2o/balancer.h"
#include "khash.h"

struct st_connect_handler_t {
    h2o_handler_t super;
    h2o_proxy_config_vars_t config;
};

#define NUM_DNS_RESULTS 3
struct dns_res {
    struct sockaddr_storage addr;
    socklen_t len;
};

struct st_connect_request_t {
    h2o_loop_t *loop;
    h2o_req_t *src_req;
    h2o_socket_t *sock;
    h2o_hostinfo_getaddr_req_t *getaddr_req;
    h2o_iovec_t host;
    char servrame[sizeof(H2O_UINT16_LONGEST_STR)];
    struct dns_res dns[NUM_DNS_RESULTS];
    size_t dns_results;
    struct st_connect_handler_t *handler_ctx;
    h2o_timer_t timeout;
};

static void on_error(struct st_connect_request_t *creq, const char *errstr)
{
    h2o_timer_unlink(&creq->timeout);
    h2o_send_error_502(creq->src_req, "Gateway Error", errstr, 0);
}

static void on_timeout(h2o_timer_t *entry)
{
    struct st_connect_request_t *creq = H2O_STRUCT_FROM_MEMBER(struct st_connect_request_t, timeout, entry);
    on_error(creq, h2o_httpclient_error_io_timeout);
}

static void start_connect(struct st_connect_request_t *creq, struct sockaddr *addr, socklen_t addrlen);
static void on_connect(h2o_socket_t *sock, const char *err)
{
    struct st_connect_request_t *creq = sock->data;

    if (err) {
        if (creq->dns_results-- > 0) {
            start_connect(creq, (void *)&creq->dns[creq->dns_results - 1].addr, creq->dns[creq->dns_results - 1].len);
            return;
        }
        on_error(creq, err);
        return;
    }

    h2o_timer_unlink(&creq->timeout);
    h2o_req_t *req = creq->src_req;
    uint64_t timeout = creq->handler_ctx->config.tunnel.timeout;
    sock->data = NULL;
    creq->sock = NULL;
    req->res.status = 200;

    h2o_httpclient_tunnel_t *tunnel = h2o_open_tunnel_from_socket(sock);
    req->establish_tunnel(req, tunnel, timeout);
}

static void on_generator_dispose(void *_self)
{
    struct st_connect_request_t *creq = _self;

    if (creq->getaddr_req != NULL) {
        h2o_hostinfo_getaddr_cancel(creq->getaddr_req);
        creq->getaddr_req = NULL;
    }

    if (creq->sock != NULL)
        h2o_socket_close(creq->sock);
}

void h2o_hostinfo_take_n(struct addrinfo *res, struct dns_res *out, size_t *num)
{
    if (res->ai_next == NULL) {
        *num = 1;
        memcpy(&out[0].addr, res->ai_addr, res->ai_addrlen);
        out[0].len = res->ai_addrlen;
        return;
    }

    /* count the number of candidates */
    size_t i = 0;
    struct addrinfo *start = res, *ai = res;
    do {
        ++i;
    } while ((ai = ai->ai_next) != NULL);

    if (*num > i)
        *num = i;

    i = rand() % i;
    for (ai = res; i != 0; ai = ai->ai_next, --i)
        ;
    for (i = 0; i < *num; i++) {
        memcpy(&out[i].addr, ai->ai_addr, ai->ai_addrlen);
        out[i].len = ai->ai_addrlen;
        ai = ai->ai_next;
        if (ai == NULL)
            ai = start;
    }
}

static void on_getaddr(h2o_hostinfo_getaddr_req_t *getaddr_req, const char *errstr, struct addrinfo *res, void *_creq)
{
    struct st_connect_request_t *creq = _creq;

    assert(getaddr_req == creq->getaddr_req);
    creq->getaddr_req = NULL;

    if (errstr != NULL) {
        on_error(creq, errstr);
        return;
    }

    h2o_hostinfo_take_n(res, creq->dns, &creq->dns_results);
    start_connect(creq, (void *)&creq->dns[creq->dns_results - 1].addr, creq->dns[creq->dns_results - 1].len);
}

static void start_connect(struct st_connect_request_t *creq, struct sockaddr *addr, socklen_t addrlen)
{
    creq->sock = h2o_socket_connect(creq->loop, addr, addrlen, on_connect);
    if (creq->sock == NULL) {
        if (creq->dns_results-- > 0) {
            start_connect(creq, (void *)&creq->dns[creq->dns_results - 1].addr, creq->dns[creq->dns_results - 1].len);
            return;
        }
        on_error(creq, h2o_socket_error_conn_fail);
        return;
    }
    creq->sock->data = creq;
}

static int on_req(h2o_handler_t *_handler, h2o_req_t *req)
{
    struct st_connect_handler_t *handler = (void *)_handler;
    h2o_iovec_t host;
    uint16_t port;

    if (!h2o_memis(req->input.method.base, req->input.method.len, H2O_STRLIT("CONNECT"))) {
        h2o_send_error_405(req, "Method Not Allowed", "Method Not Allowed", 0);
        return 0;
    }
    if (h2o_url_parse_hostport(req->input.path.base, req->input.path.len, &host, &port) == NULL || port == 0 || port == 65535) {
        h2o_send_error_400(req, "Bad Request", "Bad Request", 0);
        return 0;
    }

    struct st_connect_request_t *creq = h2o_mem_alloc_shared(&req->pool, sizeof(*creq), on_generator_dispose);
    *creq = (struct st_connect_request_t){
        .loop = req->conn->ctx->loop,
        .src_req = req,
        .host = host,
        .dns_results = NUM_DNS_RESULTS,
        .handler_ctx = handler,
        .timeout = (h2o_timer_t){.cb = on_timeout},
    };
    int servname_len = sprintf(creq->servrame, "%" PRIu16, port);
    h2o_timer_link(creq->loop, handler->config.tunnel.timeout, &creq->timeout);

    creq->getaddr_req = h2o_hostinfo_getaddr(&creq->src_req->conn->ctx->receivers.hostinfo_getaddr, creq->host,
                                             h2o_iovec_init(creq->servrame, servname_len), AF_UNSPEC, SOCK_STREAM, IPPROTO_TCP,
                                             AI_ADDRCONFIG | AI_NUMERICSERV, on_getaddr, creq);

    return 0;
}

void h2o_connect_register(h2o_pathconf_t *pathconf, h2o_proxy_config_vars_t *config)
{
    struct st_connect_handler_t *self = (void *)h2o_create_handler(pathconf, sizeof(*self));

    self->super.on_req = on_req;
    self->config = *config;
}
