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

struct st_handler_ctx_t {
    h2o_handler_t super;
    h2o_proxy_config_vars_t config;
};

struct connect_request {
    h2o_loop_t *loop;
    h2o_req_t *src_req;
    int remaining_try_count;
    h2o_socket_t *sock;
    h2o_hostinfo_getaddr_req_t *getaddr_req;
    h2o_multithread_receiver_t *getaddr_receiver;
    h2o_iovec_t host;
    char named_serv[sizeof(H2O_UINT16_LONGEST_STR)];
    uint64_t timeout;
};

static void on_connect(h2o_socket_t *sock, const char *err)
{
    struct connect_request *creq = sock->data;
    h2o_req_t *req = creq->src_req;
    uint64_t timeout = creq->timeout;

    free(creq);
    sock->data = NULL;
    req->res.status = 200;

    h2o_httpclient_tunnel_t *tunnel = h2o_open_tunnel_from_socket(sock);
    req->establish_tunnel(req, tunnel, timeout);
}

static void on_generator_dispose(void *_self)
{
}

static void on_error(struct connect_request *req, const char *errstr)
{
    h2o_send_error_502(req->src_req, "Gateway Error", errstr, 0);
    free(req);
}
static void try_connect(struct connect_request *req);
static void start_connect(struct connect_request *req, struct sockaddr *addr, socklen_t addrlen);
static void on_getaddr(h2o_hostinfo_getaddr_req_t *getaddr_req, const char *errstr, struct addrinfo *res, void *_req)
{
    struct connect_request *req = _req;

    assert(getaddr_req == req->getaddr_req);
    req->getaddr_req = NULL;

    if (errstr != NULL) {
        if (req->remaining_try_count > 0) {
            try_connect(req);
            return;
        }
        on_error(req, errstr);
        return;
    }

    struct addrinfo *selected = h2o_hostinfo_select_one(res);
    start_connect(req, selected->ai_addr, selected->ai_addrlen);
}

static void try_connect(struct connect_request *req)
{
    req->remaining_try_count--;

    req->getaddr_req =
        h2o_hostinfo_getaddr(req->getaddr_receiver, req->host, h2o_iovec_init(req->named_serv, strlen(req->named_serv)), AF_UNSPEC,
                             SOCK_STREAM, IPPROTO_TCP, AI_ADDRCONFIG | AI_NUMERICSERV, on_getaddr, req);
}

static void start_connect(struct connect_request *req, struct sockaddr *addr, socklen_t addrlen)
{
    req->sock = h2o_socket_connect(req->loop, addr, addrlen, on_connect);
    if (req->sock == NULL) {
        if (req->remaining_try_count > 0) {
            try_connect(req);
            return;
        }
        on_error(req, h2o_socket_error_conn_fail);
        return;
    }
    req->sock->data = req;
}

static int on_req(h2o_handler_t *_handler, h2o_req_t *req)
{
    struct st_handler_ctx_t *handler = (void *)_handler;
    h2o_iovec_t host;
    uint16_t port = 0;
    const char *ret;
    if (!h2o_memis(req->input.method.base, req->input.method.len, H2O_STRLIT("CONNECT"))) {
        h2o_send_error_405(req, "Method Not Allowed", "Method Not Allowed", 0);
        return 0;
    }
    ret = h2o_url_parse_hostport(req->input.path.base, req->input.path.len, &host, &port);
    if (ret == NULL || port == 0)
        return -1;

    struct connect_request *creq = h2o_mem_alloc(sizeof(*creq));

    *creq = (struct connect_request){req->conn->ctx->loop, req, 1};
    creq->getaddr_receiver = &req->conn->ctx->receivers.hostinfo_getaddr;
    creq->host = host;
    creq->timeout = handler->config.tunnel.timeout;
    sprintf(creq->named_serv, "%" PRIu16, port);

    try_connect(creq);

    return 0;
}

static void on_context_init(h2o_handler_t *_self, h2o_context_t *ctx)
{
}

static void on_context_dispose(h2o_handler_t *_self, h2o_context_t *ctx)
{
}

static void on_handler_dispose(h2o_handler_t *_self)
{
}

void h2o_connect_register(h2o_pathconf_t *pathconf, h2o_proxy_config_vars_t *config)
{
    struct st_handler_ctx_t *self = (void *)h2o_create_handler(pathconf, sizeof(*self));

    self->super.on_context_init = on_context_init;
    self->super.on_context_dispose = on_context_dispose;
    self->super.dispose = on_handler_dispose;
    self->super.on_req = on_req;
    self->super.supports_request_streaming = 1;
    self->config = *config;
}
