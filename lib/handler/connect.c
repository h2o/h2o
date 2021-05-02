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

#define MODULE_NAME "lib/handler/connect.c"

struct st_connect_handler_t {
    h2o_handler_t super;
    h2o_proxy_config_vars_t config;
    struct {
        size_t count;
        h2o_connect_acl_entry_t entries[0];
    } acl;
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
        struct st_server_address_t list[MAX_CONNECT_RETRIES];
        size_t size;
        size_t next;
    } server_addresses;
    h2o_timer_t timeout;
};

#define TO_BITMASK(type, len) ((type)~(((type)1 << (sizeof(type) * 8 - (len))) - 1))

static void make_proxy_status_error(struct st_connect_request_t *creq,
    const char *error_type, const char *details, const char *rcode)
{
    h2o_mem_pool_t *pool = &creq->src_req->pool;

    if (!creq->handler->config.connect_proxy_status_enabled)
        return;

    h2o_iovec_t identity = creq->src_req->conn->ctx->globalconf->proxy_status_identity;
    if (identity.base == NULL)
        identity = h2o_iovec_init(H2O_STRLIT("h2o"));

    h2o_iovec_t parts[9] = {
        identity,
        h2o_iovec_init(H2O_STRLIT("; error=")),
        h2o_iovec_init(error_type, strlen(error_type)),
    };
    size_t nparts = 3;
    if (rcode != NULL) {
        parts[nparts++] = h2o_iovec_init(H2O_STRLIT("; rcode="));
        parts[nparts++] = h2o_iovec_init(rcode, strlen(rcode));
    }
    if (details != NULL) {
        parts[nparts++] = h2o_iovec_init(H2O_STRLIT("; details="));
        parts[nparts++] = h2o_encode_sf_string(pool, details, SIZE_MAX);
    }
    assert(nparts <= sizeof(parts) / sizeof(parts[0]));
    h2o_iovec_t hval = h2o_concat_list(pool, parts, nparts);

    h2o_add_header_by_str(pool, &creq->src_req->res.headers, H2O_STRLIT("proxy-status"), 0, NULL, hval.base, hval.len);
}

static void make_proxy_status_error_for_socket_error(struct st_connect_request_t *creq,
    const char *err)
{
    const char *error_type;
    const char *details = NULL;
    if (err == h2o_socket_error_conn_refused)
        error_type = "connection_refused";
    else if (err == h2o_socket_error_conn_timed_out)
        error_type = "connection_timeout";
    else if (err == h2o_socket_error_network_unreachable || err == h2o_socket_error_host_unreachable)
        error_type = "destination_ip_unroutable";
    else {
        error_type = "proxy_internal_error";
        details = err;
    }
    make_proxy_status_error(creq, error_type, details, NULL);
}

static void start_connect(struct st_connect_request_t *creq);

static void on_error(struct st_connect_request_t *creq, const char *errstr)
{
    h2o_timer_unlink(&creq->timeout);
    if (creq->getaddr_req != NULL) {
        h2o_hostinfo_getaddr_cancel(creq->getaddr_req);
        creq->getaddr_req = NULL;
    }
    if (creq->sock != NULL) {
        h2o_socket_close(creq->sock);
        creq->sock = NULL;
    }
    h2o_send_error_502(creq->src_req, "Gateway Error", errstr, H2O_SEND_ERROR_KEEP_HEADERS);
}

static void on_timeout(h2o_timer_t *entry)
{
    struct st_connect_request_t *creq = H2O_STRUCT_FROM_MEMBER(struct st_connect_request_t, timeout, entry);
    if (creq->server_addresses.size > 0) {
        make_proxy_status_error(creq, "connection_timeout", NULL, NULL);
    } else {
        make_proxy_status_error(creq, "dns_timeout", NULL, NULL);
    }
    on_error(creq, h2o_httpclient_error_io_timeout);
}

static void on_connect(h2o_socket_t *sock, const char *err)
{
    struct st_connect_request_t *creq = sock->data;

    assert(creq->sock == sock);

    if (err) {
        if (creq->server_addresses.next == creq->server_addresses.size) {
            make_proxy_status_error_for_socket_error(creq, err);
            on_error(creq, err);
            return;
        }
        h2o_socket_close(sock);
        creq->sock = NULL;
        start_connect(creq);
        return;
    }

    /* create and pass the responsibility to the tunnel */
    h2o_timer_unlink(&creq->timeout);
    sock->data = NULL;
    creq->sock = NULL;
    h2o_socket_tunnel_t *tunnel = h2o_socket_tunnel_create(sock);

    /* send response to client */
    creq->src_req->res.status = 200;
    creq->src_req->establish_tunnel(creq->src_req, &tunnel->super, creq->handler->config.io_timeout);

    /* start the tunnel */
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
    h2o_timer_unlink(&creq->timeout);
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
        const char *rcode;
        if (errstr == h2o_hostinfo_error_nxdomain)
            rcode = "NXDOMAIN";
        else if (errstr == h2o_hostinfo_error_nodata)
            rcode = "NODATA";
        else if (errstr == h2o_hostinfo_error_refused)
            rcode = "REFUSED";
        else if (errstr == h2o_hostinfo_error_servfail)
            rcode = "SERVFAIL";
        else
            rcode = NULL;
        make_proxy_status_error(creq, "dns_error", errstr, rcode);
        on_error(creq, errstr);
        return;
    }

    if (res->ai_socktype == SOCK_STREAM) {
        store_server_addresses(creq, res);
        start_connect(creq);
    } else {
        assert(res->ai_socktype == SOCK_DGRAM);
        const char *err = NULL;
        h2o_tunnel_t *tunnel = h2o_open_udp_tunnel_from_sa(creq->loop, res->ai_addr, res->ai_addrlen, &err);
        h2o_req_t *req = creq->src_req;
        h2o_timer_unlink(&creq->timeout);
        if (tunnel != NULL) {
	    req->res.status = 200;
	    uint64_t timeout = creq->handler->config.io_timeout;
	    req->establish_tunnel(req, tunnel, timeout);
        } else {
            h2o_req_log_error(req, MODULE_NAME, "Failed to create downstream socket");
            make_proxy_status_error_for_socket_error(creq, err);
            h2o_send_error_502(req, "Bad Gateway", "Bad Gateway", H2O_SEND_ERROR_KEEP_HEADERS);
        }
    }
}

static void start_connect(struct st_connect_request_t *creq)
{
    /* repeat connect(pop_front(address_list)) until we run out of the list */
    const char *err = NULL;
    do {
        struct st_server_address_t *server_address = creq->server_addresses.list + creq->server_addresses.next++;
        /* check address */
        if (!h2o_connect_lookup_acl(creq->handler->acl.entries, creq->handler->acl.count, server_address->sa)) {
            h2o_timer_unlink(&creq->timeout);
            h2o_req_log_error(creq->src_req, MODULE_NAME, "access rejected by acl");
            make_proxy_status_error(creq, "destination_ip_prohibited", NULL, NULL);
            h2o_send_error_403(creq->src_req, "Access Forbidden", "Access Forbidden", H2O_SEND_ERROR_KEEP_HEADERS);
            return;
        }
        /* connect */
        if ((creq->sock = h2o_socket_connect(creq->loop, server_address->sa, server_address->salen, on_connect, &err)) != NULL) {
            creq->sock->data = creq;
            return;
        }
    } while (creq->server_addresses.next < creq->server_addresses.size);

    make_proxy_status_error_for_socket_error(creq, err);
    on_error(creq, h2o_socket_error_conn_fail);
}

static int on_req(h2o_handler_t *_handler, h2o_req_t *req)
{
    struct st_connect_handler_t *handler = (void *)_handler;
    h2o_iovec_t host;
    uint16_t port;
    int socket_proto;
    int socket_type;

    if (h2o_memis(req->input.method.base, req->input.method.len, H2O_STRLIT("CONNECT"))) {
        socket_proto = IPPROTO_TCP;
        socket_type = SOCK_STREAM;
    } else if (h2o_memis(req->input.method.base, req->input.method.len, H2O_STRLIT("CONNECT-UDP"))) {
        socket_proto = IPPROTO_UDP;
        socket_type = SOCK_DGRAM;
    } else {
        return -1;
    }

    if (h2o_url_parse_hostport(req->authority.base, req->authority.len, &host, &port) == NULL || port == 0 || port == 65535) {
        h2o_send_error_400(req, "Bad Request", "Bad Request", H2O_SEND_ERROR_KEEP_HEADERS);
        return 0;
    }

    struct st_connect_request_t *creq = h2o_mem_alloc_shared(&req->pool, sizeof(*creq), on_generator_dispose);
    *creq = (struct st_connect_request_t){
        .handler = handler,
        .loop = req->conn->ctx->loop,
        .src_req = req,
        .timeout = {.cb = on_timeout},
    };
    h2o_timer_link(creq->loop, handler->config.connect_timeout, &creq->timeout);

    char port_str[sizeof(H2O_UINT16_LONGEST_STR)];
    int port_strlen = sprintf(port_str, "%" PRIu16, port);
    creq->getaddr_req =
        h2o_hostinfo_getaddr(&creq->src_req->conn->ctx->receivers.hostinfo_getaddr, host, h2o_iovec_init(port_str, port_strlen),
                             AF_UNSPEC, socket_type, socket_proto, AI_ADDRCONFIG | AI_NUMERICSERV, on_getaddr, creq);

    return 0;
}

void h2o_connect_register(h2o_pathconf_t *pathconf, h2o_proxy_config_vars_t *config, h2o_connect_acl_entry_t *acl_entries,
                          size_t num_acl_entries)
{
    struct st_connect_handler_t *self = (void *)h2o_create_handler(pathconf, offsetof(struct st_connect_handler_t, acl.entries) +
                                                                                 sizeof(*self->acl.entries) * num_acl_entries);

    self->super.on_req = on_req;
    self->config = *config;
    self->acl.count = num_acl_entries;
    memcpy(self->acl.entries, acl_entries, sizeof(self->acl.entries[0]) * num_acl_entries);
}

const char *h2o_connect_parse_acl(h2o_connect_acl_entry_t *output, const char *input)
{
    /* type */
    switch (input[0]) {
    case '+':
        output->allow_ = 1;
        break;
    case '-':
        output->allow_ = 0;
        break;
    default:
        return "ACL entry must begin with + or -";
    }

    /* extract address, port */
    h2o_iovec_t host_vec;
    uint16_t port;
    const char *slash_at;
    if ((slash_at = h2o_url_parse_hostport(input + 1, strlen(input + 1), &host_vec, &port)) == NULL)
        goto GenericParseError;
    char *host = alloca(host_vec.len + 1);
    memcpy(host, host_vec.base, host_vec.len);
    host[host_vec.len] = '\0';

    /* parse netmask (or addr_mask is set to zero to indicate that mask was not specified) */
    if (*slash_at != '\0') {
        if (*slash_at != '/')
            goto GenericParseError;
        if (sscanf(slash_at + 1, "%zu", &output->addr_mask) != 1 || output->addr_mask == 0)
            return "invalid address mask";
    } else {
        output->addr_mask = 0;
    }

    /* parse address */
    struct in_addr v4addr;
    struct in6_addr v6addr;
    if (strcmp(host, "*") == 0) {
        output->addr_family = H2O_CONNECT_ACL_ADDRESS_ANY;
        if (output->addr_mask != 0)
            return "wildcard address (*) cannot have a netmask";
    } else if (inet_pton(AF_INET, host, &v4addr) == 1) {
        output->addr_family = H2O_CONNECT_ACL_ADDRESS_V4;
        if (output->addr_mask == 0) {
            output->addr_mask = 32;
        } else if (output->addr_mask > 32) {
            return "invalid address mask";
        }
        output->addr.v4 = ntohl(v4addr.s_addr) & TO_BITMASK(uint32_t, output->addr_mask);
    } else if (inet_pton(AF_INET6, host, &v6addr) == 1) {
        output->addr_family = H2O_CONNECT_ACL_ADDRESS_V6;
        if (output->addr_mask == 0) {
            output->addr_mask = 128;
        } else if (output->addr_mask > 128) {
            return "invalid address mask";
        }
        size_t i;
        for (i = 0; i < output->addr_mask / 8; ++i)
            output->addr.v6[i] = v6addr.s6_addr[i];
        if (output->addr_mask % 8 != 0)
            output->addr.v6[i] = v6addr.s6_addr[i] & TO_BITMASK(uint8_t, v6addr.s6_addr[i]);
        for (++i; i < PTLS_ELEMENTSOF(output->addr.v6); ++i)
            output->addr.v6[i] = 0;
    } else {
        return "failed to parse address";
    }

    /* set port (for whatever reason, `h2o_url_parse_hostport` sets port to 65535 when not specified, convert that to zero) */
    output->port = port == 65535 ? 0 : port;

    return NULL;

GenericParseError:
    return "failed to parse input, expected format is: [+-]address(?::port|)(?:/netmask|)";
}

int h2o_connect_lookup_acl(h2o_connect_acl_entry_t *acl_entries, size_t num_acl_entries, struct sockaddr *target)
{
    uint32_t target_v4addr = 0;
    uint16_t target_port;

    /* reject anything other than v4/v6, as well as converting the values to native format */
    switch (target->sa_family) {
    case AF_INET: {
        struct sockaddr_in *sin = (void *)target;
        target_v4addr = ntohl(sin->sin_addr.s_addr);
        target_port = ntohs(sin->sin_port);
    } break;
    case AF_INET6:
        target_port = htons(((struct sockaddr_in6 *)target)->sin6_port);
        break;
    default:
        return 0;
    }

    /* check each ACL entry */
    for (size_t i = 0; i != num_acl_entries; ++i) {
        h2o_connect_acl_entry_t *entry = acl_entries + i;
        /* check port */
        if (entry->port != 0 && entry->port != target_port)
            goto Next;
        /* check address */
        switch (entry->addr_family) {
        case H2O_CONNECT_ACL_ADDRESS_ANY:
            break;
        case H2O_CONNECT_ACL_ADDRESS_V4: {
            if (target->sa_family != AF_INET)
                goto Next;
            if (entry->addr.v4 != (target_v4addr & TO_BITMASK(uint32_t, entry->addr_mask)))
                goto Next;
        } break;
        case H2O_CONNECT_ACL_ADDRESS_V6: {
            if (target->sa_family != AF_INET6)
                continue;
            uint8_t *target_v6addr = ((struct sockaddr_in6 *)target)->sin6_addr.s6_addr;
            size_t i;
            for (i = 0; i < entry->addr_mask / 8; ++i)
                if (entry->addr.v6[i] != target_v6addr[i])
                    goto Next;
            if (entry->addr_mask % 8 != 0 && entry->addr.v6[i] != (target_v6addr[i] & TO_BITMASK(uint8_t, entry->addr_mask % 8)))
                goto Next;
        } break;
        }
        /* match */
        return entry->allow_;
    Next:;
    }

    /* default rule is deny */
    return 0;
}
