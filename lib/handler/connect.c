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
#define UDP_CHUNK_OVERHEAD 3

struct st_server_address_t {
    struct sockaddr *sa;
    socklen_t salen;
};

struct st_connect_generator_t {
    h2o_generator_t super;
    struct st_connect_handler_t *handler;
    h2o_req_t *src_req;
    h2o_hostinfo_getaddr_req_t *getaddr_req;
    h2o_socket_t *sock;
    struct {
        struct st_server_address_t list[MAX_CONNECT_RETRIES];
        size_t size;
        size_t next;
    } server_addresses;
    h2o_timer_t timeout;
    unsigned write_closed : 1;
    unsigned is_tcp : 1;
    union {
        struct {
            h2o_buffer_t *sendbuf;
        } tcp;
        struct {
            struct {
                h2o_buffer_t *buf; /* for datagram fragments */
                h2o_timer_t delayed;
                size_t bytes_inflight;
            } egress;
            struct {
                uint8_t buf[UDP_CHUNK_OVERHEAD + 1500];
            } ingress;
        } udp;
    };
};

#define TO_BITMASK(type, len) ((type) ~(((type)1 << (sizeof(type) * 8 - (len))) - 1))

static void tcp_start_connect(struct st_connect_generator_t *self);
static void udp_connect(struct st_connect_generator_t *self);

static h2o_loop_t *get_loop(struct st_connect_generator_t *self)
{
    return self->src_req->conn->ctx->loop;
}

static h2o_req_t *dispose_generator(struct st_connect_generator_t *self)
{
    /* detect duplicate call to `dispose_generator`, which could happen due to this function being called via `stop` callback and
     * the pool destructor callback */
    if (self->handler == NULL)
        return NULL;
    self->handler = NULL;

    if (self->getaddr_req != NULL)
        h2o_hostinfo_getaddr_cancel(self->getaddr_req);
    if (self->sock != NULL)
        h2o_socket_close(self->sock);
    if (self->is_tcp) {
        h2o_buffer_dispose(&self->tcp.sendbuf);
    } else {
        h2o_buffer_dispose(&self->udp.egress.buf);
        h2o_timer_unlink(&self->udp.egress.delayed);
    }
    h2o_timer_unlink(&self->timeout);

    return self->src_req;
}

static void close_and_send_final(struct st_connect_generator_t *self)
{
    assert(self->sock != NULL);
    int was_reading = h2o_socket_is_reading(self->sock);

    h2o_socket_close(self->sock);
    self->sock = NULL;
    h2o_timer_unlink(&self->timeout);

    /* if there's nothing inflight, close downstream immediately, otherwise let `do_proceed` handle the signal */
    if (was_reading)
        h2o_send(dispose_generator(self), NULL, 0, H2O_SEND_STATE_FINAL);
}

static void on_io_timeout(h2o_timer_t *timer)
{
    struct st_connect_generator_t *self = H2O_STRUCT_FROM_MEMBER(struct st_connect_generator_t, timeout, timer);
    close_and_send_final(self);
}

static void reset_io_timeout(struct st_connect_generator_t *self)
{
    h2o_timer_unlink(&self->timeout);
    h2o_timer_link(get_loop(self), self->handler->config.io_timeout, &self->timeout);
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

    if (self->is_tcp) {
        assert(res->ai_socktype == SOCK_STREAM);
        tcp_start_connect(self);
    } else {
        assert(res->ai_socktype == SOCK_DGRAM);
        udp_connect(self);
    }
}

static struct st_server_address_t *grab_connect_address(struct st_connect_generator_t *self)
{
    struct st_server_address_t *server_address = self->server_addresses.list + self->server_addresses.next++;

    if (h2o_connect_lookup_acl(self->handler->acl.entries, self->handler->acl.count, server_address->sa))
        return server_address;

    /* cannot connect, send error */
    h2o_timer_unlink(&self->timeout);
    h2o_req_log_error(self->src_req, "lib/handler/connect.c", "access rejected by acl");
    h2o_send_error_403(self->src_req, "Access Forbidden", "Access Forbidden", 0);
    return NULL;
}

static void tcp_on_write_complete(h2o_socket_t *_sock, const char *err)
{
    struct st_connect_generator_t *self = _sock->data;

    if (err != NULL || self->write_closed) {
        close_and_send_final(self);
        return;
    }

    size_t bytes_written = self->tcp.sendbuf->size;
    h2o_buffer_consume(&self->tcp.sendbuf, bytes_written);

    reset_io_timeout(self);
    self->src_req->proceed_req(self->src_req, bytes_written, H2O_SEND_STATE_IN_PROGRESS);
}

static int tcp_write(void *_self, h2o_iovec_t chunk, int is_end_stream)
{
    struct st_connect_generator_t *self = _self;

    assert(self->tcp.sendbuf->size == 0);

    h2o_buffer_append(&self->tcp.sendbuf, chunk.base, chunk.len);
    if (is_end_stream)
        self->write_closed = 1;

    reset_io_timeout(self);

    h2o_iovec_t vec = h2o_iovec_init(self->tcp.sendbuf->bytes, self->tcp.sendbuf->size);
    h2o_socket_write(self->sock, &vec, 1, tcp_on_write_complete);

    return 0;
}

static void tcp_on_read(h2o_socket_t *_sock, const char *err)
{
    struct st_connect_generator_t *self = _sock->data;

    if (err != NULL) {
        h2o_send(dispose_generator(self), NULL, 0, H2O_SEND_STATE_FINAL);
        return;
    }

    h2o_socket_read_stop(self->sock);
    reset_io_timeout(self); /* for simplicity, we call out I/O timeout even when downstream fails to deliver data to the client
                             * within given interval */

    h2o_iovec_t vec = h2o_iovec_init(self->sock->input->bytes, self->sock->input->size);
    h2o_send(self->src_req, &vec, 1, H2O_SEND_STATE_IN_PROGRESS);
}

static void tcp_on_proceed(h2o_generator_t *_self, h2o_req_t *req)
{
    struct st_connect_generator_t *self = H2O_STRUCT_FROM_MEMBER(struct st_connect_generator_t, super, _self);

    if (self->sock != NULL) {
        h2o_buffer_consume(&self->sock->input, self->sock->input->size);
        reset_io_timeout(self);
        h2o_socket_read_start(self->sock, tcp_on_read);
    } else {
        h2o_send(dispose_generator(self), NULL, 0, H2O_SEND_STATE_FINAL);
    }
}

static void tcp_on_connect(h2o_socket_t *_sock, const char *err)
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
        tcp_start_connect(self);
        return;
    }

    self->timeout.cb = on_io_timeout;
    reset_io_timeout(self);

    /* setup write, and initiate if pending data exists */
    self->src_req->write_req.cb = tcp_write;
    self->src_req->write_req.ctx = self;
    if (self->src_req->entity.len != 0)
        tcp_write(self, self->src_req->entity, self->src_req->proceed_req == NULL);

    /* strat the read side */
    h2o_socket_read_start(self->sock, tcp_on_read);

    /* build and submit 200 response */
    self->src_req->res.status = 200;
    h2o_start_response(self->src_req, &self->super);
    h2o_send(self->src_req, NULL, 0, H2O_SEND_STATE_IN_PROGRESS);
}

static void tcp_start_connect(struct st_connect_generator_t *self)
{
    /* repeat connect(pop_front(address_list)) until we run out of the list */
    do {
        struct st_server_address_t *server_address;
        if ((server_address = grab_connect_address(self)) == NULL)
            return;
        if ((self->sock = h2o_socket_connect(get_loop(self), server_address->sa, server_address->salen, tcp_on_connect)) != NULL) {
            self->sock->data = self;
            return;
        }
    } while (self->server_addresses.next < self->server_addresses.size);

    on_connect_error(self, h2o_socket_error_conn_fail);
}

static h2o_iovec_t udp_get_next_chunk(const char *start, size_t len, size_t *to_consume, int *skip)
{
    const uint8_t *bytes = (const uint8_t *)start;
    const uint8_t *end = bytes + len;
    uint64_t chunk_type, chunk_length;

    chunk_type = ptls_decode_quicint(&bytes, end);
    if (chunk_type == UINT64_MAX)
        return h2o_iovec_init(NULL, 0);
    chunk_length = ptls_decode_quicint(&bytes, end);
    if (chunk_length == UINT64_MAX)
        return h2o_iovec_init(NULL, 0);

    /* chunk is incomplete */
    if (end - bytes < chunk_length)
        return h2o_iovec_init(NULL, 0);

    /*
     * https://tools.ietf.org/html/draft-ietf-masque-connect-udp-03#section-6
     * CONNECT-UDP Stream Chunks can be used to convey UDP payloads, by
     * using a CONNECT-UDP Stream Chunk Type of UDP_PACKET (value 0x00).
     */
    *skip = chunk_type != 0;
    *to_consume = (bytes + chunk_length) - (const uint8_t *)start;

    return h2o_iovec_init(bytes, chunk_length);
}

static void udp_write_core(struct st_connect_generator_t *self, h2o_iovec_t datagram)
{
    while (send(h2o_socket_get_fd(self->sock), datagram.base, datagram.len, 0) == -1 && errno == EINTR)
        ;
}

static void udp_write_stream_complete_delayed(h2o_timer_t *_timer)
{
    struct st_connect_generator_t *self = H2O_STRUCT_FROM_MEMBER(struct st_connect_generator_t, udp.egress.delayed, _timer);

    if (self->write_closed) {
        close_and_send_final(self);
        return;
    }

    self->src_req->proceed_req(self->src_req, self->udp.egress.bytes_inflight, H2O_SEND_STATE_IN_PROGRESS);
}

static int udp_write_stream(void *_self, h2o_iovec_t chunk, int is_end_stream)
{
    struct st_connect_generator_t *self = _self;
    int from_buf = 0;
    size_t off = 0;

    self->udp.egress.bytes_inflight = chunk.len;

    reset_io_timeout(self);

    if (self->udp.egress.buf->size != 0) {
        from_buf = 1;
        h2o_buffer_append(&self->udp.egress.buf, chunk.base, chunk.len);
        chunk.base = self->udp.egress.buf->bytes;
        chunk.len = self->udp.egress.buf->size;
    }
    do {
        int skip = 0;
        size_t to_consume;
        h2o_iovec_t datagram = udp_get_next_chunk(chunk.base + off, chunk.len - off, &to_consume, &skip);
        if (datagram.len == 0)
            break;
        if (!skip)
            udp_write_core(self, datagram);
        off += to_consume;
    } while (1);

    if (from_buf) {
        h2o_buffer_consume(&self->udp.egress.buf, off);
    } else if (chunk.len != off) {
        h2o_buffer_append(&self->udp.egress.buf, chunk.base + off, chunk.len - off);
    }

    if (is_end_stream)
        self->write_closed = 1;

    h2o_timer_link(get_loop(self), 0, &self->udp.egress.delayed);

    return 0;
}

static void udp_write_datagrams(h2o_req_t *_req, h2o_iovec_t *datagrams, size_t num_datagrams)
{
    struct st_connect_generator_t *self = _req->write_req.ctx;

    reset_io_timeout(self);

    for (size_t i = 0; i != num_datagrams; ++i)
        udp_write_core(self, datagrams[i]);
}

static void udp_on_read(h2o_socket_t *_sock, const char *err)
{
    struct st_connect_generator_t *self = _sock->data;

    if (err != NULL) {
        h2o_send(dispose_generator(self), NULL, 0, H2O_SEND_STATE_FINAL);
        return;
    }

    /* read UDP packet, or return */
    ssize_t rret;
    while ((rret = recv(h2o_socket_get_fd(self->sock), self->udp.ingress.buf + UDP_CHUNK_OVERHEAD,
                        sizeof(self->udp.ingress.buf) - UDP_CHUNK_OVERHEAD, 0)) == -1 &&
           errno == EINTR)
        ;
    if (rret == -1)
        return;

    /* forward UDP datagram as is; note that it might be zero-sized */
    if (self->src_req->forward_datagram.read_ != NULL) {
        h2o_iovec_t vec = h2o_iovec_init(self->udp.ingress.buf + UDP_CHUNK_OVERHEAD, rret);
        self->src_req->forward_datagram.read_(self->src_req, &vec, 1);
    } else {
        h2o_socket_read_stop(self->sock);
        reset_io_timeout(self); /* for simplicity, we call out I/O timeout even when downstream fails to deliver data to the client
                                 * within given interval */
        size_t off = 0;
        self->udp.ingress.buf[off++] = 0; /* chunk type = UDP_PACKET */
        off = quicly_encodev(self->udp.ingress.buf + off, (uint64_t)rret) - self->udp.ingress.buf;
        assert(off <= UDP_CHUNK_OVERHEAD);
        if (off < UDP_CHUNK_OVERHEAD)
            memmove(self->udp.ingress.buf + off, self->udp.ingress.buf + UDP_CHUNK_OVERHEAD, rret);
        off += rret;
        h2o_iovec_t vec = h2o_iovec_init(self->udp.ingress.buf, off);
        h2o_send(self->src_req, &vec, 1, H2O_SEND_STATE_IN_PROGRESS);
    }
}

static void udp_on_proceed(h2o_generator_t *_self, h2o_req_t *req)
{
    struct st_connect_generator_t *self = H2O_STRUCT_FROM_MEMBER(struct st_connect_generator_t, super, _self);

    if (self->sock != NULL) {
        h2o_buffer_consume(&self->sock->input, self->sock->input->size);
        reset_io_timeout(self);
        h2o_socket_read_start(self->sock, udp_on_read);
    } else {
        h2o_send(dispose_generator(self), NULL, 0, H2O_SEND_STATE_FINAL);
    }
}

static void udp_connect(struct st_connect_generator_t *self)
{
    struct st_server_address_t *server_address;
    int fd;

    /* determine server address an connect */
    if ((server_address = grab_connect_address(self)) == NULL)
        return;
    if ((fd = socket(server_address->sa->sa_family, SOCK_DGRAM, 0)) == -1 ||
        connect(fd, server_address->sa, server_address->salen) != 0) {
        if (fd != -1)
            close(fd);
        on_connect_error(self, "connection failure");
        return;
    }

    self->timeout.cb = on_io_timeout;
    reset_io_timeout(self);

    /* setup, initiating transfer of early data */
#if H2O_USE_LIBUV
    self->sock = h2o_uv__poll_create(get_loop(self), fd, (uv_close_cb)free);
#else
    self->sock = h2o_evloop_socket_create(get_loop(self), fd, H2O_SOCKET_FLAG_DONT_READ);
#endif
    assert(self->sock != NULL);
    self->sock->data = self;
    self->src_req->write_req.cb = udp_write_stream;
    self->src_req->forward_datagram.write_ = udp_write_datagrams;
    self->src_req->write_req.ctx = self;
    if (self->src_req->entity.len != 0)
        udp_write_stream(self, self->src_req->entity, self->src_req->proceed_req == NULL);
    h2o_socket_read_start(self->sock, udp_on_read);

    /* build and submit 200 response */
    self->src_req->res.status = 200;
    h2o_start_response(self->src_req, &self->super);
    h2o_send(self->src_req, NULL, 0, H2O_SEND_STATE_IN_PROGRESS);
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
    int is_tcp;

    if (h2o_memis(req->input.method.base, req->input.method.len, H2O_STRLIT("CONNECT"))) {
        is_tcp = 1;
    } else if (h2o_memis(req->input.method.base, req->input.method.len, H2O_STRLIT("CONNECT-UDP"))) {
        is_tcp = 0;
    } else {
        return -1;
    }

    if (h2o_url_parse_hostport(req->authority.base, req->authority.len, &host, &port) == NULL || port == 0 || port == 65535) {
        h2o_send_error_400(req, "Bad Request", "Bad Request", 0);
        return 0;
    }

    struct st_connect_generator_t *self;
    size_t sizeof_self = offsetof(struct st_connect_generator_t, tcp) + (is_tcp ? sizeof(self->tcp) : sizeof(self->udp));
    self = h2o_mem_alloc_shared(&req->pool, sizeof_self, on_generator_dispose);
    memset(self, 0, sizeof_self);
    self->super.stop = on_stop;
    self->handler = handler;
    self->src_req = req;
    self->timeout.cb = on_connect_timeout;
    if (is_tcp) {
        self->is_tcp = 1;
        self->super.proceed = tcp_on_proceed;
        h2o_buffer_init(&self->tcp.sendbuf, &h2o_socket_buffer_prototype);
    } else {
        self->super.proceed = udp_on_proceed;
        h2o_buffer_init(&self->udp.egress.buf, &h2o_socket_buffer_prototype);
        self->udp.egress.delayed = (h2o_timer_t){.cb = udp_write_stream_complete_delayed};
    }
    h2o_timer_link(get_loop(self), handler->config.connect_timeout, &self->timeout);

    char port_str[sizeof(H2O_UINT16_LONGEST_STR)];
    int port_strlen = sprintf(port_str, "%" PRIu16, port);
    self->getaddr_req = h2o_hostinfo_getaddr(&self->src_req->conn->ctx->receivers.hostinfo_getaddr, host,
                                             h2o_iovec_init(port_str, port_strlen), AF_UNSPEC, is_tcp ? SOCK_STREAM : SOCK_DGRAM,
                                             is_tcp ? IPPROTO_TCP : IPPROTO_UDP, AI_ADDRCONFIG | AI_NUMERICSERV, on_getaddr, self);

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
