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
#include "../probes_.h"

#define MODULE_NAME "lib/handler/connect.c"

struct st_connect_handler_t {
    h2o_handler_t super;
    h2o_proxy_config_vars_t config;
    struct {
        size_t count;
        h2o_connect_acl_entry_t entries[0];
    } acl;
};

#define MAX_ADDRESSES_PER_FAMILY 4
#define UDP_CHUNK_OVERHEAD 3

struct st_server_address_t {
    struct sockaddr *sa;
    socklen_t salen;
};

struct st_connect_generator_t {
    h2o_generator_t super;
    struct st_connect_handler_t *handler;
    h2o_req_t *src_req;

    struct {
        h2o_hostinfo_getaddr_req_t *v4, *v6;
    } getaddr_req;
    struct {
        struct st_server_address_t list[MAX_ADDRESSES_PER_FAMILY * 2];
        size_t size;
        size_t used;
    } server_addresses;

    h2o_socket_t *sock;
    /**
     * Most significant and latest error that occurred, if any. Significance is represented as `class`, in descending order.
     */
    struct {
        enum error_class {
            ERROR_CLASS_NAME_RESOLUTION,
            ERROR_CLASS_ACCESS_PROHIBITED,
            ERROR_CLASS_CONNECT
        } class;
        const char *str;
    } last_error;

    /**
     * timer used to handle user-visible timeouts (i.e., connect- and io-timeout)
     */
    h2o_timer_t timeout;
    /**
     * timer used to for RFC 8305-style happy eyeballs (resolution delay and connection attempt delay)
     */
    h2o_timer_t eyeball_delay;

    /**
     * Pick v4 (or v6) address in the next connection attempt. RFC 8305 recommends trying the other family one by one.
     */
    unsigned pick_v4 : 1;
    /**
     * set when the send-side is closed by the user
     */
    unsigned write_closed : 1;
    /**
     * set when h2o_send has been called to notify that the socket has been closed
     */
    unsigned read_closed : 1;
    /**
     * if socket has been closed
     */
    unsigned socket_closed : 1;
    /**
     * if connecting using TCP (or UDP)
     */
    unsigned is_tcp : 1;
    /**
     * TCP- and UDP-specific data
     */
    union {
        struct {
            h2o_buffer_t *sendbuf;
            h2o_buffer_t *recvbuf_detached;
        } tcp;
        struct {
            struct {
                h2o_buffer_t *buf; /* for datagram fragments */
                h2o_timer_t delayed;
            } egress;
            struct {
                uint8_t buf[UDP_CHUNK_OVERHEAD + 1500];
            } ingress;
        } udp;
    };
};

#define TO_BITMASK(type, len) ((type) ~(((type)1 << (sizeof(type) * 8 - (len))) - 1))

static void record_error(struct st_connect_generator_t *self, const char *error_type, const char *details, const char *rcode)
{
    H2O_PROBE_REQUEST(CONNECT_ERROR, self->src_req, error_type, details, rcode);

    h2o_req_log_error(self->src_req, MODULE_NAME, "%s; rcode=%s; details=%s", error_type, rcode != NULL ? rcode : "(null)",
                      details != NULL ? details : "(null)");

    if (self->handler->config.connect_proxy_status_enabled) {
        h2o_mem_pool_t *pool = &self->src_req->pool;
        h2o_iovec_t identity = self->src_req->conn->ctx->globalconf->proxy_status_identity;
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

        h2o_add_header_by_str(pool, &self->src_req->res.headers, H2O_STRLIT("proxy-status"), 0, NULL, hval.base, hval.len);
    }
}

static void record_socket_error(struct st_connect_generator_t *self, const char *err)
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
    record_error(self, error_type, details, NULL);
}

static void try_connect(struct st_connect_generator_t *self);
static int tcp_start_connect(struct st_connect_generator_t *self, struct st_server_address_t *server_address);
static int udp_connect(struct st_connect_generator_t *self, struct st_server_address_t *server_address);

static h2o_loop_t *get_loop(struct st_connect_generator_t *self)
{
    return self->src_req->conn->ctx->loop;
}

static void stop_eyeballs(struct st_connect_generator_t *self)
{
    if (self->getaddr_req.v4 != NULL) {
        h2o_hostinfo_getaddr_cancel(self->getaddr_req.v4);
        self->getaddr_req.v4 = NULL;
    }
    if (self->getaddr_req.v6 != NULL) {
        h2o_hostinfo_getaddr_cancel(self->getaddr_req.v6);
        self->getaddr_req.v6 = NULL;
    }
    if (self->eyeball_delay.cb != NULL) {
        h2o_timer_unlink(&self->eyeball_delay);
        self->eyeball_delay.cb = NULL;
    }
}

static void dispose_generator(struct st_connect_generator_t *self)
{
    stop_eyeballs(self);
    if (self->sock != NULL) {
        h2o_socket_close(self->sock);
        self->sock = NULL;
        self->socket_closed = 1;
    }
    if (self->is_tcp) {
        if (self->tcp.sendbuf != NULL)
            h2o_buffer_dispose(&self->tcp.sendbuf);
        if (self->tcp.recvbuf_detached != NULL)
            h2o_buffer_dispose(&self->tcp.recvbuf_detached);
    } else {
        if (self->udp.egress.buf != NULL)
            h2o_buffer_dispose(&self->udp.egress.buf);
        h2o_timer_unlink(&self->udp.egress.delayed);
    }
    h2o_timer_unlink(&self->timeout);
}

static void close_socket(struct st_connect_generator_t *self)
{
    if (self->is_tcp)
        self->tcp.recvbuf_detached = self->sock->input;
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
    if (!self->read_closed && (self->is_tcp ? self->tcp.recvbuf_detached->size == 0 : 1)) {
        h2o_timer_link(get_loop(self), 0, &self->timeout);
        self->read_closed = 1;
        h2o_send(self->src_req, NULL, 0, H2O_SEND_STATE_FINAL);
        return;
    }

    /* notify write-close if necessary; see the comment above regarding the use of the timer */
    if (!self->write_closed && self->is_tcp && self->tcp.sendbuf->size != 0) {
        self->write_closed = 1;
        h2o_timer_link(get_loop(self), 0, &self->timeout);
        self->src_req->proceed_req(self->src_req, h2o_httpclient_error_io /* TODO notify as cancel? */);
        return;
    }
}

static void on_io_timeout(h2o_timer_t *timer)
{
    struct st_connect_generator_t *self = H2O_STRUCT_FROM_MEMBER(struct st_connect_generator_t, timeout, timer);
    H2O_PROBE_REQUEST0(CONNECT_IO_TIMEOUT, self->src_req);
    close_readwrite(self);
}

static void reset_io_timeout(struct st_connect_generator_t *self)
{
    if (self->sock != NULL) {
        h2o_timer_unlink(&self->timeout);
        h2o_timer_link(get_loop(self), self->handler->config.io_timeout, &self->timeout);
    }
}

static void send_connect_error(struct st_connect_generator_t *self, int code, const char *msg, const char *errstr)
{
    stop_eyeballs(self);
    h2o_timer_unlink(&self->timeout);

    if (self->sock != NULL) {
        h2o_socket_close(self->sock);
        self->sock = NULL;
    }

    h2o_send_error_generic(self->src_req, code, msg, errstr, H2O_SEND_ERROR_KEEP_HEADERS);
}

static void on_connect_error(struct st_connect_generator_t *self, const char *errstr)
{
    send_connect_error(self, 502, "Gateway Error", errstr);
}

static void on_connect_timeout(h2o_timer_t *entry)
{
    struct st_connect_generator_t *self = H2O_STRUCT_FROM_MEMBER(struct st_connect_generator_t, timeout, entry);
    if (self->server_addresses.size > 0) {
        record_error(self, "connection_timeout", NULL, NULL);
    } else {
        record_error(self, "dns_timeout", NULL, NULL);
    }
    on_connect_error(self, h2o_httpclient_error_io_timeout);
}

static void set_last_error(struct st_connect_generator_t *self, enum error_class class, const char *str)
{
    if (self->last_error.class <= class) {
        self->last_error.class = class;
        self->last_error.str = str;
    }
}

static void on_resolution_delay_timeout(h2o_timer_t *entry)
{
    struct st_connect_generator_t *self = H2O_STRUCT_FROM_MEMBER(struct st_connect_generator_t, eyeball_delay, entry);

    assert(self->server_addresses.used == 0);

    try_connect(self);
}

static void on_connection_attempt_delay_timeout(h2o_timer_t *entry)
{
    struct st_connect_generator_t *self = H2O_STRUCT_FROM_MEMBER(struct st_connect_generator_t, eyeball_delay, entry);

    /* If no more addresses are available, continue trying the current attempt until the connect_timeout expires. */
    if (self->server_addresses.used == self->server_addresses.size)
        return;

    /* close current connection attempt and try next. */
    h2o_socket_close(self->sock);
    self->sock = NULL;
    try_connect(self);
}

static int store_server_addresses(struct st_connect_generator_t *self, struct addrinfo *res)
{
    size_t num_added = 0;

    /* copy first entries in the response; ordering of addresses being returned by `getaddrinfo` is respected, as ordinary clients
     * (incl. forward proxy) are not expected to distribute the load among the addresses being returned. */
    do {
        assert(self->server_addresses.size < PTLS_ELEMENTSOF(self->server_addresses.list));
        if (h2o_connect_lookup_acl(self->handler->acl.entries, self->handler->acl.count, res->ai_addr)) {
            struct st_server_address_t *dst = self->server_addresses.list + self->server_addresses.size++;
            dst->sa = h2o_mem_alloc_pool_aligned(&self->src_req->pool, H2O_ALIGNOF(struct sockaddr), res->ai_addrlen);
            memcpy(dst->sa, res->ai_addr, res->ai_addrlen);
            dst->salen = res->ai_addrlen;
            ++num_added;
        }
    } while ((res = res->ai_next) != NULL && num_added < MAX_ADDRESSES_PER_FAMILY);

    return num_added != 0;
}

static void on_getaddr(h2o_hostinfo_getaddr_req_t *getaddr_req, const char *errstr, struct addrinfo *res, void *_self)
{
    struct st_connect_generator_t *self = _self;
    if (getaddr_req == self->getaddr_req.v4) {
        self->getaddr_req.v4 = NULL;
    } else if (getaddr_req == self->getaddr_req.v6) {
        self->getaddr_req.v6 = NULL;
    } else {
        h2o_fatal("unexpected getaddr_req");
    }

    /* Store addresses, or convert error to ACL denial. */
    if (errstr == NULL) {
        if (self->is_tcp) {
            assert(res->ai_socktype == SOCK_STREAM);
        } else {
            assert(res->ai_socktype == SOCK_DGRAM);
        }
        assert(res != NULL && "upon successful return, getaddrinfo shall return at least one address (RFC 3493 Section 6.1)");
        if (!store_server_addresses(self, res))
            set_last_error(self, ERROR_CLASS_ACCESS_PROHIBITED, "destination_ip_prohibited");
    } else {
        set_last_error(self, ERROR_CLASS_NAME_RESOLUTION, errstr);
    }

    if (self->getaddr_req.v4 == NULL) {
        /* If v6 lookup is still running, that means that v4 lookup has *just* completed. Set the resolution delay timer if v4
         * addresses are available. */
        if (self->getaddr_req.v6 != NULL) {
            assert(self->server_addresses.used == 0);
            if (self->server_addresses.size != 0) {
                self->eyeball_delay.cb = on_resolution_delay_timeout;
                h2o_timer_link(get_loop(self), self->handler->config.happy_eyeballs.name_resolution_delay, &self->eyeball_delay);
            }
            return;
        }

        /* Both v4 and v6 lookups are complete. If the resolution delay timer is running. Reset it. */
        if (h2o_timer_is_linked(&self->eyeball_delay) && self->eyeball_delay.cb == on_resolution_delay_timeout) {
            assert(self->server_addresses.used == 0);
            h2o_timer_unlink(&self->eyeball_delay);
        }
        /* In case no addresses are available, send HTTP error. */
        if (self->server_addresses.size == 0) {
            if (self->last_error.class == ERROR_CLASS_ACCESS_PROHIBITED) {
                record_error(self, self->last_error.str, NULL, NULL);
                send_connect_error(self, 403, "Destination IP Prohibited", "Destination IP Prohibited");
            } else {
                const char *rcode;
                if (self->last_error.str == h2o_hostinfo_error_nxdomain) {
                    rcode = "NXDOMAIN";
                } else if (self->last_error.str == h2o_hostinfo_error_nodata) {
                    rcode = "NODATA";
                } else if (self->last_error.str == h2o_hostinfo_error_refused) {
                    rcode = "REFUSED";
                } else if (self->last_error.str == h2o_hostinfo_error_servfail) {
                    rcode = "SERVFAIL";
                } else {
                    rcode = NULL;
                }
                record_error(self, "dns_error", self->last_error.str, rcode);
                on_connect_error(self, self->last_error.str);
            }
            return;
        }
    }

    /* Try connecting if possible. */
    if (self->server_addresses.used == self->server_addresses.size)
        return;
    /* If connection attempt has been under way for more than CONNECTION_ATTEMPT_DELAY_MS, stop that and try next address. Return
     * otherwise. */
    if (self->sock != NULL) {
        if (h2o_timer_is_linked(&self->eyeball_delay))
            return;
        h2o_socket_close(self->sock);
        self->sock = NULL;
    }
    try_connect(self);
}

static struct st_server_address_t *pick_and_swap(struct st_connect_generator_t *self, size_t idx)
{
    struct st_server_address_t *server_address = NULL;

    if (idx != self->server_addresses.used) {
        struct st_server_address_t swap = self->server_addresses.list[idx];
        self->server_addresses.list[idx] = self->server_addresses.list[self->server_addresses.used];
        self->server_addresses.list[self->server_addresses.used] = swap;
    }
    server_address = &self->server_addresses.list[self->server_addresses.used];
    self->server_addresses.used++;
    self->pick_v4 = !self->pick_v4;
    return server_address;
}

static void try_connect(struct st_connect_generator_t *self)
{
    struct st_server_address_t *server_address;

    do {
        server_address = NULL;

        /* Fetch the next address from the list of resolved addresses. */
        for (size_t i = self->server_addresses.used; i < self->server_addresses.size; i++) {
            if (self->pick_v4 && self->server_addresses.list[i].sa->sa_family == AF_INET)
                server_address = pick_and_swap(self, i);
            else if (!self->pick_v4 && self->server_addresses.list[i].sa->sa_family == AF_INET6)
                server_address = pick_and_swap(self, i);
        }

        /* If address of the preferred address family is not available, select one of the other family, if available. Otherwise,
         * send an HTTP error response or wait for address resolution. */
        if (server_address == NULL) {
            if (self->server_addresses.used == self->server_addresses.size) {
                if (self->getaddr_req.v4 == NULL && self->getaddr_req.v6 == NULL) {
                    assert(self->last_error.class == ERROR_CLASS_CONNECT);
                    record_socket_error(self, self->last_error.str);
                    on_connect_error(self, self->last_error.str);
                }
                return;
            }
            server_address = &self->server_addresses.list[self->server_addresses.used];
            self->server_addresses.used++;
        }

        /* Connect. Retry if the connect function returns error immediately. */
    } while (!(self->is_tcp ? tcp_start_connect : udp_connect)(self, server_address));
}

static void tcp_on_write_complete(h2o_socket_t *_sock, const char *err)
{
    struct st_connect_generator_t *self = _sock->data;

    if (err != NULL) {
        H2O_PROBE_REQUEST(CONNECT_TCP_WRITE_ERROR, self->src_req, err);
    }

    /* until h2o_socket_t implements shutdown(SHUT_WR), do a bidirectional close when we close the write-side */
    if (err != NULL || self->write_closed) {
        close_readwrite(self);
        return;
    }

    reset_io_timeout(self);

    h2o_buffer_consume(&self->tcp.sendbuf, self->tcp.sendbuf->size);
    self->src_req->proceed_req(self->src_req, NULL);
}

static void tcp_do_write(struct st_connect_generator_t *self)
{
    reset_io_timeout(self);

    h2o_iovec_t vec = h2o_iovec_init(self->tcp.sendbuf->bytes, self->tcp.sendbuf->size);
    H2O_PROBE_REQUEST(CONNECT_TCP_WRITE, self->src_req, vec.len);
    h2o_socket_write(self->sock, &vec, 1, tcp_on_write_complete);
}

static int tcp_write(void *_self, int is_end_stream)
{
    struct st_connect_generator_t *self = _self;
    h2o_iovec_t chunk = self->src_req->entity;

    assert(!self->write_closed);
    assert(self->tcp.sendbuf->size == 0);

    /* the socket might have been closed due to a read error */
    if (self->socket_closed)
        return 1;

    /* buffer input */
    h2o_buffer_append(&self->tcp.sendbuf, chunk.base, chunk.len);
    if (is_end_stream)
        self->write_closed = 1;

    /* write if the socket has been opened */
    if (self->sock != NULL && !h2o_socket_is_writing(self->sock))
        tcp_do_write(self);

    return 0;
}

static void tcp_on_read(h2o_socket_t *_sock, const char *err)
{
    struct st_connect_generator_t *self = _sock->data;

    h2o_socket_read_stop(self->sock);
    reset_io_timeout(self); /* for simplicity, we call out I/O timeout even when downstream fails to deliver data to the client
                             * within given interval */

    if (err == NULL) {
        h2o_iovec_t vec = h2o_iovec_init(self->sock->input->bytes, self->sock->input->size);
        H2O_PROBE_REQUEST(CONNECT_TCP_READ, self->src_req, vec.len);
        h2o_send(self->src_req, &vec, 1, H2O_SEND_STATE_IN_PROGRESS);
    } else {
        H2O_PROBE_REQUEST(CONNECT_TCP_READ_ERROR, self->src_req, err);
        /* unidirectional close is signalled using H2O_SEND_STATE_FINAL, but the write side remains open */
        self->read_closed = 1;
        h2o_send(self->src_req, NULL, 0, H2O_SEND_STATE_FINAL);
    }
}

static void tcp_on_proceed(h2o_generator_t *_self, h2o_req_t *req)
{
    struct st_connect_generator_t *self = H2O_STRUCT_FROM_MEMBER(struct st_connect_generator_t, super, _self);

    assert(!self->read_closed);

    if (self->sock != NULL) {
        h2o_buffer_consume(&self->sock->input, self->sock->input->size);
        reset_io_timeout(self);
        h2o_socket_read_start(self->sock, tcp_on_read);
    } else {
        self->read_closed = 1;
        h2o_send(self->src_req, NULL, 0, H2O_SEND_STATE_FINAL);
    }
}

static void tcp_on_connect(h2o_socket_t *_sock, const char *err)
{
    struct st_connect_generator_t *self = _sock->data;

    assert(self->sock == _sock);

    if (err != NULL) {
        set_last_error(self, ERROR_CLASS_CONNECT, err);
        h2o_socket_close(self->sock);
        self->sock = NULL;
        try_connect(self);
        return;
    }

    stop_eyeballs(self);
    self->timeout.cb = on_io_timeout;
    reset_io_timeout(self);

    /* start the write if there's data to be sent */
    if (self->tcp.sendbuf->size != 0 || self->write_closed)
        tcp_do_write(self);

    /* build and submit 200 response */
    self->src_req->res.status = 200;
    h2o_start_response(self->src_req, &self->super);
    h2o_send(self->src_req, NULL, 0, H2O_SEND_STATE_IN_PROGRESS);
}

static int tcp_start_connect(struct st_connect_generator_t *self, struct st_server_address_t *server_address)
{
    H2O_PROBE_REQUEST(CONNECT_TCP_START, self->src_req, server_address->sa);

    const char *errstr;
    if ((self->sock = h2o_socket_connect(get_loop(self), server_address->sa, server_address->salen, tcp_on_connect, &errstr)) ==
        NULL) {
        set_last_error(self, ERROR_CLASS_CONNECT, errstr);
        return 0;
    }

    self->sock->data = self;
#if !H2O_USE_LIBUV
    /* This is the maximum amount of data that will be buffered within userspace. It is hard-coded to 64KB to balance throughput
     * and latency, and because we do not expect the need to change the value. */
    h2o_evloop_socket_set_max_read_size(self->sock, 64 * 1024);
#endif
    self->eyeball_delay.cb = on_connection_attempt_delay_timeout;
    h2o_timer_link(get_loop(self), self->handler->config.happy_eyeballs.connection_attempt_delay, &self->eyeball_delay);

    return 1;
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
    H2O_PROBE_REQUEST(CONNECT_UDP_WRITE, self->src_req, datagram.len);
    while (send(h2o_socket_get_fd(self->sock), datagram.base, datagram.len, 0) == -1 && errno == EINTR)
        ;
}

static void udp_write_stream_complete_delayed(h2o_timer_t *_timer)
{
    struct st_connect_generator_t *self = H2O_STRUCT_FROM_MEMBER(struct st_connect_generator_t, udp.egress.delayed, _timer);

    if (self->write_closed) {
        close_readwrite(self);
        return;
    }

    self->src_req->proceed_req(self->src_req, NULL);
}

static void udp_do_write_stream(struct st_connect_generator_t *self, h2o_iovec_t chunk)
{
    int from_buf = 0;
    size_t off = 0;

    reset_io_timeout(self);

    if (self->udp.egress.buf->size != 0) {
        from_buf = 1;
        if (chunk.len != 0)
            h2o_buffer_append(&self->udp.egress.buf, chunk.base, chunk.len);
        chunk.base = self->udp.egress.buf->bytes;
        chunk.len = self->udp.egress.buf->size;
    }
    do {
        int skip = 0;
        size_t to_consume;
        h2o_iovec_t datagram = udp_get_next_chunk(chunk.base + off, chunk.len - off, &to_consume, &skip);
        if (datagram.base == NULL)
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

    h2o_timer_link(get_loop(self), 0, &self->udp.egress.delayed);
}

static int udp_write_stream(void *_self, int is_end_stream)
{
    struct st_connect_generator_t *self = _self;
    h2o_iovec_t chunk = self->src_req->entity;

    assert(!self->write_closed);

    /* the socket might have been closed tue to a read error */
    if (self->socket_closed)
        return 1;

    if (is_end_stream)
        self->write_closed = 1;

    /* if the socket is not yet open, buffer input and return */
    if (self->sock == NULL) {
        h2o_buffer_append(&self->udp.egress.buf, chunk.base, chunk.len);
        return 0;
    }

    udp_do_write_stream(self, chunk);
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
        close_readwrite(self);
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
    H2O_PROBE_REQUEST(CONNECT_UDP_READ, self->src_req, (size_t)rret);

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
        self->read_closed = 1;
        h2o_send(self->src_req, NULL, 0, H2O_SEND_STATE_FINAL);
    }
}

static int udp_connect(struct st_connect_generator_t *self, struct st_server_address_t *server_address)
{
    int fd;

    H2O_PROBE_REQUEST(CONNECT_UDP_START, self->src_req, server_address->sa);
    /* connect */
    if ((fd = socket(server_address->sa->sa_family, SOCK_DGRAM, 0)) == -1 ||
        connect(fd, server_address->sa, server_address->salen) != 0) {
        const char *err = h2o_socket_error_conn_fail;
        if (fd != -1) {
            err = h2o_socket_get_error_string(errno, err);
            close(fd);
        }
        return 0;
    }

    stop_eyeballs(self);
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
    if (self->udp.egress.buf->size != 0 || self->write_closed)
        udp_do_write_stream(self, h2o_iovec_init(NULL, 0));
    h2o_socket_read_start(self->sock, udp_on_read);

    /* build and submit 200 response */
    self->src_req->res.status = 200;
    h2o_start_response(self->src_req, &self->super);
    h2o_send(self->src_req, NULL, 0, H2O_SEND_STATE_IN_PROGRESS);

    return 1;
}

static void on_stop(h2o_generator_t *_self, h2o_req_t *req)
{
    struct st_connect_generator_t *self = H2O_STRUCT_FROM_MEMBER(struct st_connect_generator_t, super, _self);
    dispose_generator(self);
}

static void on_generator_dispose(void *_self)
{
    struct st_connect_generator_t *self = _self;
    H2O_PROBE_REQUEST0(CONNECT_DISPOSE, self->src_req);
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
        h2o_send_error_400(req, "Bad Request", "Bad Request", H2O_SEND_ERROR_KEEP_HEADERS);
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

    /* setup write_req now, so that the protocol handler would not provide additional data until we call `proceed_req` */
    assert(req->entity.len == 0 && "the handler is incapable of accepting input via `write_req.cb` while writing req->entity");
    self->src_req->write_req.cb = is_tcp ? tcp_write : udp_write_stream;
    self->src_req->write_req.ctx = self;

    char port_str[sizeof(H2O_UINT16_LONGEST_STR)];
    int port_strlen = sprintf(port_str, "%" PRIu16, port);

    self->getaddr_req.v6 =
        h2o_hostinfo_getaddr(&self->src_req->conn->ctx->receivers.hostinfo_getaddr, host, h2o_iovec_init(port_str, port_strlen),
                             AF_INET6, is_tcp ? SOCK_STREAM : SOCK_DGRAM, is_tcp ? IPPROTO_TCP : IPPROTO_UDP,
                             AI_ADDRCONFIG | AI_NUMERICSERV, on_getaddr, self);
    self->getaddr_req.v4 =
        h2o_hostinfo_getaddr(&self->src_req->conn->ctx->receivers.hostinfo_getaddr, host, h2o_iovec_init(port_str, port_strlen),
                             AF_INET, is_tcp ? SOCK_STREAM : SOCK_DGRAM, is_tcp ? IPPROTO_TCP : IPPROTO_UDP,
                             AI_ADDRCONFIG | AI_NUMERICSERV, on_getaddr, self);

    return 0;
}

void h2o_connect_register(h2o_pathconf_t *pathconf, h2o_proxy_config_vars_t *config, h2o_connect_acl_entry_t *acl_entries,
                          size_t num_acl_entries)
{
    assert(config->max_buffer_size != 0);

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
            output->addr.v6[i] = v6addr.s6_addr[i] & TO_BITMASK(uint8_t, output->addr_mask % 8);
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
