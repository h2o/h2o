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
#include "h2o/hostinfo.h"
#include "h2o/memory.h"
#include "h2o/socket.h"
#include "h2o.h"

struct st_connect_handler_t {
    h2o_handler_t super;
    h2o_proxy_config_vars_t config;
};

#define MAX_CONNECT_RETRIES 3

struct st_server_address_t {
    struct sockaddr *sa;
    socklen_t salen;
};

struct st_connect_request_t {
    struct st_connect_handler_t *handler;
    h2o_loop_t *loop;
    h2o_req_t *src_req;
    h2o_socket_t *sock;
    h2o_hostinfo_getaddr_req_t *getaddr_req;
    struct {
        h2o_iovec_t host;
        char port[sizeof(H2O_UINT16_LONGEST_STR)];
    } server_name;
    struct {
        struct st_server_address_t list[MAX_CONNECT_RETRIES];
        size_t size;
        size_t next;
    } server_addresses;
    h2o_timer_t timeout;
};

static void start_connect(struct st_connect_request_t *creq);

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

static void on_connect(h2o_socket_t *sock, const char *err)
{
    struct st_connect_request_t *creq = sock->data;

    if (err) {
        if (creq->server_addresses.next == creq->server_addresses.size) {
            on_error(creq, err);
            return;
        }
        start_connect(creq);
        return;
    }

    h2o_timer_unlink(&creq->timeout);
    h2o_req_t *req = creq->src_req;
    uint64_t timeout = creq->handler->config.io_timeout;
    sock->data = NULL;
    creq->sock = NULL;
    req->res.status = 200;

    h2o_socket_tunnel_t *tunnel = h2o_socket_tunnel_create(sock);
    req->establish_tunnel(req, &tunnel->super, timeout);
    h2o_socket_tunnel_start(tunnel, 0);
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

static void store_server_addresses(struct st_connect_request_t *creq, struct addrinfo *res)
{
    /* copy first entries in the response; ordering of addresses being returned by `getaddrinfo` is respected, as ordinary clients
     * (incl. forward proxy) are not expected to distribute the load among the addresses being returned. */
    do {
        struct st_server_address_t *dst = creq->server_addresses.list + creq->server_addresses.size++;
        dst->sa = h2o_mem_alloc_pool_aligned(&creq->src_req->pool, H2O_ALIGNOF(struct sockaddr), res->ai_addrlen);
        memcpy(dst->sa, res->ai_addr, res->ai_addrlen);
        dst->salen = res->ai_addrlen;
    } while (creq->server_addresses.size < PTLS_ELEMENTSOF(creq->server_addresses.list) && (res = res->ai_next) != NULL);
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

    store_server_addresses(creq, res);
    start_connect(creq);
}

static void start_connect(struct st_connect_request_t *creq)
{
    /* repeat connect(pop_front(address_list)) until we run out of the list */
    do {
        struct st_server_address_t *server_address = creq->server_addresses.list + creq->server_addresses.next++;
        if ((creq->sock = h2o_socket_connect(creq->loop, server_address->sa, server_address->salen, on_connect)) != NULL) {
            creq->sock->data = creq;
            return;
        }
    } while (creq->server_addresses.next < creq->server_addresses.size);

    on_error(creq, h2o_socket_error_conn_fail);
}

static int on_req(h2o_handler_t *_handler, h2o_req_t *req)
{
    struct st_connect_handler_t *handler = (void *)_handler;
    h2o_iovec_t host;
    uint16_t port;

    /* this handler captures CONNECT, delegating requests with other methods to the next handler */
    if (!h2o_memis(req->input.method.base, req->input.method.len, H2O_STRLIT("CONNECT")))
        return -1;

    if (h2o_url_parse_hostport(req->authority.base, req->authority.len, &host, &port) == NULL || port == 0 || port == 65535) {
        h2o_send_error_400(req, "Bad Request", "Bad Request", 0);
        return 0;
    }

    struct st_connect_request_t *creq = h2o_mem_alloc_shared(&req->pool, sizeof(*creq), on_generator_dispose);
    *creq = (struct st_connect_request_t){
        .handler = handler,
        .loop = req->conn->ctx->loop,
        .src_req = req,
        .server_name = {host},
        .timeout = {.cb = on_timeout},
    };
    int port_strlen = sprintf(creq->server_name.port, "%" PRIu16, port);
    h2o_timer_link(creq->loop, handler->config.connect_timeout, &creq->timeout);

    creq->getaddr_req = h2o_hostinfo_getaddr(&creq->src_req->conn->ctx->receivers.hostinfo_getaddr, creq->server_name.host,
                                             h2o_iovec_init(creq->server_name.port, port_strlen), AF_UNSPEC, SOCK_STREAM,
                                             IPPROTO_TCP, AI_ADDRCONFIG | AI_NUMERICSERV, on_getaddr, creq);

    return 0;
}

void h2o_connect_register(h2o_pathconf_t *pathconf, h2o_proxy_config_vars_t *config)
{
    struct st_connect_handler_t *self = (void *)h2o_create_handler(pathconf, sizeof(*self));

    self->super.on_req = on_req;
    self->config = *config;
}
