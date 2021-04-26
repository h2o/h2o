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

struct st_connect_generator_t {
    h2o_generator_t super;
    struct st_connect_handler_t *handler;
    h2o_loop_t *loop;
    h2o_req_t *src_req;
    h2o_hostinfo_getaddr_req_t *getaddr_req;
    h2o_socket_t *sock;
    struct {
        struct st_server_address_t list[MAX_CONNECT_RETRIES];
        size_t size;
        size_t next;
    } server_addresses;
    h2o_buffer_t *sendbuf;
    h2o_buffer_t *recvbuf_detached;
    h2o_timer_t timeout;
    /**
     * set when the send-side is closed
     */
    unsigned sendbuf_closed : 1;
    /**
     * set when h2o_send has been called to notify that the socket has been closed
     */
    unsigned read_closed : 1;
    /**
     * if socket has been closed
     */
    unsigned socket_closed : 1;
};

#define TO_BITMASK(type, len) ((type) ~(((type)1 << (sizeof(type) * 8 - (len))) - 1))

static void start_connect(struct st_connect_generator_t *self);

static void dispose_generator(struct st_connect_generator_t *self)
{
    if (self->getaddr_req != NULL) {
        h2o_hostinfo_getaddr_cancel(self->getaddr_req);
        self->getaddr_req = NULL;
    }
    if (self->sock != NULL) {
        h2o_socket_close(self->sock);
        self->sock = NULL;
        self->socket_closed = 1;
    }
    if (self->sendbuf != NULL)
        h2o_buffer_dispose(&self->sendbuf);
    if (self->recvbuf_detached != NULL)
        h2o_buffer_dispose(&self->recvbuf_detached);
    h2o_timer_unlink(&self->timeout);
}

static void close_socket(struct st_connect_generator_t *self)
{
    self->recvbuf_detached = self->sock->input;
    h2o_buffer_init(&self->sock->input, &h2o_socket_buffer_prototype);
    h2o_socket_close(self->sock);
    self->sock = NULL;
    self->socket_closed = 1;
}

static void close_readwrite(struct st_connect_generator_t *self)
{
    if (self->sock != NULL)
        close_socket(self);
    if (h2o_timer_is_linked(&self->timeout))
        h2o_timer_unlink(&self->timeout);

    /* immediately notify read-close if necessary, setting up delayed task to for destroying other items; the timer is reset if
     * `h2o_send` indirectly invokes `dispose_generator`. */
    if (!self->read_closed && self->recvbuf_detached->size == 0) {
        h2o_timer_link(self->loop, 0, &self->timeout);
        self->read_closed = 1;
        h2o_send(self->src_req, NULL, 0, H2O_SEND_STATE_FINAL);
        return;
    }

    /* notify write-close if necessary; see the comment above regarding the use of the timer */
    if (!self->sendbuf_closed && self->sendbuf->size != 0) {
        self->sendbuf_closed = 1;
        h2o_timer_link(self->loop, 0, &self->timeout);
        self->src_req->proceed_req(self->src_req, 0, H2O_SEND_STATE_ERROR);
        return;
    }
}

static void on_io_timeout(h2o_timer_t *timer)
{
    struct st_connect_generator_t *self = H2O_STRUCT_FROM_MEMBER(struct st_connect_generator_t, timeout, timer);
    close_readwrite(self);
}

static void reset_io_timeout(struct st_connect_generator_t *self)
{
    if (self->sock != NULL) {
        h2o_timer_unlink(&self->timeout);
        h2o_timer_link(self->loop, self->handler->config.io_timeout, &self->timeout);
    }
}

static void tunnel_on_write_complete(h2o_socket_t *_sock, const char *err)
{
    struct st_connect_generator_t *self = _sock->data;

    /* until h2o_socket_t implements shutdown(SHUT_WR), do a bidirectional close when we close the write-side */
    if (err != NULL || self->sendbuf_closed) {
        close_readwrite(self);
        return;
    }

    reset_io_timeout(self);

    size_t bytes_written = self->sendbuf->size;
    h2o_buffer_consume(&self->sendbuf, bytes_written);
    self->src_req->proceed_req(self->src_req, bytes_written, H2O_SEND_STATE_IN_PROGRESS);
}

static void tunnel_do_write(struct st_connect_generator_t *self)
{
    reset_io_timeout(self);

    h2o_iovec_t vec = h2o_iovec_init(self->sendbuf->bytes, self->sendbuf->size);
    h2o_socket_write(self->sock, &vec, 1, tunnel_on_write_complete);
}

static int tunnel_write(void *_self, h2o_iovec_t chunk, int is_end_stream)
{
    struct st_connect_generator_t *self = _self;

    assert(!self->sendbuf_closed);
    assert(self->sendbuf->size == 0);

    /* the socket might have been closed due to a read error */
    if (self->socket_closed)
        return 1;

    /* buffer input */
    h2o_buffer_append(&self->sendbuf, chunk.base, chunk.len);
    if (is_end_stream)
        self->sendbuf_closed = 1;

    /* write if the socket has been opened */
    if (self->sock != NULL)
        tunnel_do_write(self);

    return 0;
}

static void tunnel_on_read(h2o_socket_t *_sock, const char *err)
{
    struct st_connect_generator_t *self = _sock->data;

    h2o_socket_read_stop(self->sock);
    reset_io_timeout(self); /* for simplicity, we call out I/O timeout even when downstream fails to deliver data to the client
                             * within given interval */

    if (err == NULL) {
        h2o_iovec_t vec = h2o_iovec_init(self->sock->input->bytes, self->sock->input->size);
        h2o_send(self->src_req, &vec, 1, H2O_SEND_STATE_IN_PROGRESS);
    } else {
        /* unidirectional close is signalled using H2O_SEND_STATE_FINAL, but the write side remains open */
        self->read_closed = 1;
        h2o_send(self->src_req, NULL, 0, H2O_SEND_STATE_FINAL);
    }
}

static void on_proceed(h2o_generator_t *_self, h2o_req_t *req)
{
    struct st_connect_generator_t *self = H2O_STRUCT_FROM_MEMBER(struct st_connect_generator_t, super, _self);

    assert(!self->read_closed);

    if (self->sock != NULL) {
        h2o_buffer_consume(&self->sock->input, self->sock->input->size);
        reset_io_timeout(self);
        h2o_socket_read_start(self->sock, tunnel_on_read);
    } else {
        self->read_closed = 1;
        h2o_send(self->src_req, NULL, 0, H2O_SEND_STATE_FINAL);
    }
}

static void on_connect_error(struct st_connect_generator_t *self, const char *errstr)
{
    h2o_timer_unlink(&self->timeout);
    if (self->sock != NULL) {
        h2o_socket_close(self->sock);
        self->sock = NULL;
    }
    h2o_send_error_502(self->src_req, "Gateway Error", errstr, 0);
}

static void on_connect_timeout(h2o_timer_t *entry)
{
    struct st_connect_generator_t *self = H2O_STRUCT_FROM_MEMBER(struct st_connect_generator_t, timeout, entry);
    on_connect_error(self, h2o_httpclient_error_io_timeout);
}

static void on_connect(h2o_socket_t *_sock, const char *err)
{
    struct st_connect_generator_t *self = _sock->data;

    assert(self->sock == _sock);

    if (err != NULL) {
        if (self->server_addresses.next == self->server_addresses.size) {
            on_connect_error(self, err);
            return;
        }
        h2o_socket_close(self->sock);
        self->sock = NULL;
        start_connect(self);
        return;
    }

    self->timeout.cb = on_io_timeout;
    reset_io_timeout(self);

    /* start the write if there's data to be sent */
    if (self->sendbuf->size != 0 || self->sendbuf_closed)
        tunnel_do_write(self);

    /* strat the read side */
    h2o_socket_read_start(self->sock, tunnel_on_read);

    /* build and submit 200 response */
    self->src_req->res.status = 200;
    h2o_start_response(self->src_req, &self->super);
    h2o_send(self->src_req, NULL, 0, H2O_SEND_STATE_IN_PROGRESS);
}

static void store_server_addresses(struct st_connect_generator_t *self, struct addrinfo *res)
{
    /* copy first entries in the response; ordering of addresses being returned by `getaddrinfo` is respected, as ordinary clients
     * (incl. forward proxy) are not expected to distribute the load among the addresses being returned. */
    do {
        struct st_server_address_t *dst = self->server_addresses.list + self->server_addresses.size++;
        dst->sa = h2o_mem_alloc_pool_aligned(&self->src_req->pool, H2O_ALIGNOF(struct sockaddr), res->ai_addrlen);
        memcpy(dst->sa, res->ai_addr, res->ai_addrlen);
        dst->salen = res->ai_addrlen;
    } while (self->server_addresses.size < PTLS_ELEMENTSOF(self->server_addresses.list) && (res = res->ai_next) != NULL);
}

static void on_getaddr(h2o_hostinfo_getaddr_req_t *getaddr_req, const char *errstr, struct addrinfo *res, void *_self)
{
    struct st_connect_generator_t *self = _self;

    assert(getaddr_req == self->getaddr_req);
    self->getaddr_req = NULL;

    if (errstr != NULL) {
        on_connect_error(self, errstr);
        return;
    }

    store_server_addresses(self, res);
    start_connect(self);
}

static void start_connect(struct st_connect_generator_t *self)
{
    /* repeat connect(pop_front(address_list)) until we run out of the list */
    do {
        struct st_server_address_t *server_address = self->server_addresses.list + self->server_addresses.next++;
        /* check address */
        if (!h2o_connect_lookup_acl(self->handler->acl.entries, self->handler->acl.count, server_address->sa)) {
            h2o_timer_unlink(&self->timeout);
            h2o_req_log_error(self->src_req, "lib/handler/connect.c", "access rejected by acl");
            h2o_send_error_403(self->src_req, "Access Forbidden", "Access Forbidden", 0);
            return;
        }
        /* connect */
        if ((self->sock = h2o_socket_connect(self->loop, server_address->sa, server_address->salen, on_connect)) != NULL) {
            self->sock->data = self;
            return;
        }
    } while (self->server_addresses.next < self->server_addresses.size);

    on_connect_error(self, h2o_socket_error_conn_fail);
}

static void on_stop(h2o_generator_t *_self, h2o_req_t *req)
{
    struct st_connect_generator_t *self = H2O_STRUCT_FROM_MEMBER(struct st_connect_generator_t, super, _self);
    dispose_generator(self);
}

static void on_generator_dispose(void *_self)
{
    struct st_connect_generator_t *self = _self;
    dispose_generator(self);
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

    struct st_connect_generator_t *self = h2o_mem_alloc_shared(&req->pool, sizeof(*self), on_generator_dispose);
    *self = (struct st_connect_generator_t){
        .super = {.proceed = on_proceed, .stop = on_stop},
        .handler = handler,
        .loop = req->conn->ctx->loop,
        .src_req = req,
        .timeout = {.cb = on_connect_timeout},
    };
    h2o_buffer_init(&self->sendbuf, &h2o_socket_buffer_prototype);
    h2o_timer_link(self->loop, handler->config.connect_timeout, &self->timeout);

    /* setup write_req now, so that the protocol handler would not provide additional data until we call `proceed_req` */
    assert(req->entity.len == 0 && "the handler is incapable of accepting input via `write_req.cb` while writing req->entity");
    self->src_req->write_req.cb = tunnel_write;
    self->src_req->write_req.ctx = self;

    char port_str[sizeof(H2O_UINT16_LONGEST_STR)];
    int port_strlen = sprintf(port_str, "%" PRIu16, port);
    self->getaddr_req =
        h2o_hostinfo_getaddr(&self->src_req->conn->ctx->receivers.hostinfo_getaddr, host, h2o_iovec_init(port_str, port_strlen),
                             AF_UNSPEC, SOCK_STREAM, IPPROTO_TCP, AI_ADDRCONFIG | AI_NUMERICSERV, on_getaddr, self);

    return 0;
}

void h2o_connect_register(h2o_pathconf_t *pathconf, h2o_proxy_config_vars_t *config, h2o_connect_acl_entry_t *acl_entries,
                          size_t num_acl_entries)
{
    struct st_connect_handler_t *self = (void *)h2o_create_handler(pathconf, offsetof(struct st_connect_handler_t, acl.entries) +
                                                                                 sizeof(*self->acl.entries) * num_acl_entries);

    self->super.on_req = on_req;
    self->super.supports_request_streaming = 1;
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
