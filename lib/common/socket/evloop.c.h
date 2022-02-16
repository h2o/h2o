/*
 * Copyright (c) 2014-2016 DeNA Co., Ltd., Kazuho Oku, Fastly, Inc.
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
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <unistd.h>
#include "cloexec.h"
#include "h2o/linklist.h"

#if !defined(H2O_USE_ACCEPT4)
#ifdef __linux__
#if defined(__ANDROID__) && __ANDROID_API__ < 21
#define H2O_USE_ACCEPT4 0
#else
#define H2O_USE_ACCEPT4 1
#endif
#elif __FreeBSD__ >= 10
#define H2O_USE_ACCEPT4 1
#else
#define H2O_USE_ACCEPT4 0
#endif
#endif

struct st_h2o_evloop_socket_t {
    h2o_socket_t super;
    int fd;
    int _flags;
    h2o_evloop_t *loop;
    size_t max_read_size;
    struct st_h2o_evloop_socket_t *_next_pending;
    struct st_h2o_evloop_socket_t *_next_statechanged;
};

static void link_to_pending(struct st_h2o_evloop_socket_t *sock);
static void write_pending(struct st_h2o_evloop_socket_t *sock);
static h2o_evloop_t *create_evloop(size_t sz);
static void update_now(h2o_evloop_t *loop);
static int32_t adjust_max_wait(h2o_evloop_t *loop, int32_t max_wait);

/* functions to be defined in the backends */
static int evloop_do_proceed(h2o_evloop_t *loop, int32_t max_wait);
static void evloop_do_dispose(h2o_evloop_t *loop);
static void evloop_do_on_socket_create(struct st_h2o_evloop_socket_t *sock);
static void evloop_do_on_socket_close(struct st_h2o_evloop_socket_t *sock);
static void evloop_do_on_socket_export(struct st_h2o_evloop_socket_t *sock);

#if H2O_USE_POLL || H2O_USE_EPOLL || H2O_USE_KQUEUE
/* explicitly specified */
#else
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
#define H2O_USE_KQUEUE 1
#elif defined(__linux)
#define H2O_USE_EPOLL 1
#else
#define H2O_USE_POLL 1
#endif
#endif

#if H2O_USE_POLL
#include "evloop/poll.c.h"
#elif H2O_USE_EPOLL
#include "evloop/epoll.c.h"
#elif H2O_USE_KQUEUE
#include "evloop/kqueue.c.h"
#else
#error "poller not specified"
#endif

void link_to_pending(struct st_h2o_evloop_socket_t *sock)
{
    if (sock->_next_pending == sock) {
        struct st_h2o_evloop_socket_t **slot = (sock->_flags & H2O_SOCKET_FLAG_IS_ACCEPTED_CONNECTION) != 0
                                                   ? &sock->loop->_pending_as_server
                                                   : &sock->loop->_pending_as_client;
        sock->_next_pending = *slot;
        *slot = sock;
    }
}

static void link_to_statechanged(struct st_h2o_evloop_socket_t *sock)
{
    if (sock->_next_statechanged == sock) {
        sock->_next_statechanged = NULL;
        *sock->loop->_statechanged.tail_ref = sock;
        sock->loop->_statechanged.tail_ref = &sock->_next_statechanged;
    }
}

static const char *on_read_core(int fd, h2o_buffer_t **input, size_t max_bytes)
{
    ssize_t read_so_far = 0;

    while (1) {
        ssize_t rret;
        h2o_iovec_t buf = h2o_buffer_try_reserve(input, max_bytes < 4096 ? max_bytes : 4096);
        if (buf.base == NULL) {
            /* memory allocation failed */
            return h2o_socket_error_out_of_memory;
        }
        size_t read_size = buf.len <= INT_MAX / 2 ? buf.len : INT_MAX / 2 + 1;
        if (read_size > max_bytes)
            read_size = max_bytes;
        while ((rret = read(fd, buf.base, read_size)) == -1 && errno == EINTR)
            ;
        if (rret == -1) {
            if (errno == EAGAIN)
                break;
            else
                return h2o_socket_error_io;
        } else if (rret == 0) {
            if (read_so_far == 0)
                return h2o_socket_error_closed; /* TODO notify close */
            break;
        }
        (*input)->size += rret;
        if (buf.len != rret)
            break;
        read_so_far += rret;
        if (read_so_far >= max_bytes)
            break;
    }
    return NULL;
}

static size_t write_vecs(struct st_h2o_evloop_socket_t *sock, h2o_iovec_t **bufs, size_t *bufcnt)
{
    ssize_t wret;

    while (*bufcnt != 0) {
        /* write */
        int iovcnt = *bufcnt < IOV_MAX ? (int)*bufcnt : IOV_MAX;
        while ((wret = writev(sock->fd, (struct iovec *)*bufs, iovcnt)) == -1 && errno == EINTR)
            ;
        SOCKET_PROBE(WRITEV, &sock->super, wret);

        if (wret == -1)
            return errno == EAGAIN ? 0 : SIZE_MAX;

        /* adjust the buffer, doing the write once again only if all IOV_MAX buffers being supplied were fully written */
        while ((*bufs)->len <= wret) {
            wret -= (*bufs)->len;
            ++*bufs;
            --*bufcnt;
            if (*bufcnt == 0) {
                assert(wret == 0);
                return 0;
            }
        }
        if (wret != 0) {
            return wret;
        } else if (iovcnt < IOV_MAX) {
            return 0;
        }
    }

    return 0;
}

static size_t write_core(struct st_h2o_evloop_socket_t *sock, h2o_iovec_t **bufs, size_t *bufcnt)
{
    if (sock->super.ssl == NULL)
        return write_vecs(sock, bufs, bufcnt);

    /* SSL */
    size_t first_buf_written = 0;
    do {
        /* write bytes already encrypted, if any */
        if (has_pending_ssl_bytes(sock->super.ssl)) {
            h2o_iovec_t encbuf = h2o_iovec_init(sock->super.ssl->output.buf.base + sock->super.ssl->output.pending_off,
                                                sock->super.ssl->output.buf.off - sock->super.ssl->output.pending_off);
            h2o_iovec_t *encbufs = &encbuf;
            size_t encbufcnt = 1, enc_written;
            if ((enc_written = write_vecs(sock, &encbufs, &encbufcnt)) == SIZE_MAX) {
                dispose_ssl_output_buffer(sock->super.ssl);
                return SIZE_MAX;
            }
            /* if write is incomplete, record the advance and bail out */
            if (encbufcnt != 0) {
                sock->super.ssl->output.pending_off += enc_written;
                break;
            }
            /* succeeded in writing all the encrypted data; free the buffer */
            dispose_ssl_output_buffer(sock->super.ssl);
        }
        /* bail out if complete */
        if (*bufcnt == 0)
            break;
        /* convert more cleartext to TLS records if possible, or bail out on fatal error */
    } while ((first_buf_written = generate_tls_records(&sock->super, bufs, bufcnt, first_buf_written)) != SIZE_MAX);

    return first_buf_written;
}

void write_pending(struct st_h2o_evloop_socket_t *sock)
{

    assert(sock->super._cb.write != NULL);

    /* DONT_WRITE poll */
    if (sock->super._write_buf.cnt == 0 && !has_pending_ssl_bytes(sock->super.ssl))
        goto Complete;

    { /* write */
        size_t first_buf_written;
        if ((first_buf_written = write_core(sock, &sock->super._write_buf.bufs, &sock->super._write_buf.cnt)) != SIZE_MAX) {
            /* return if there's still pending data, adjusting buf[0] if necessary */
            if (sock->super._write_buf.cnt != 0) {
                sock->super._write_buf.bufs[0].base += first_buf_written;
                sock->super._write_buf.bufs[0].len -= first_buf_written;
                return;
            } else if (has_pending_ssl_bytes(sock->super.ssl)) {
                return;
            }
        }
    }

    /* either completed or failed */
    dispose_write_buf(&sock->super);

Complete:
    SOCKET_PROBE(WRITE_COMPLETE, &sock->super, sock->super._write_buf.cnt == 0 && !has_pending_ssl_bytes(sock->super.ssl));
    sock->_flags |= H2O_SOCKET_FLAG_IS_WRITE_NOTIFY;
    link_to_pending(sock);
    link_to_statechanged(sock); /* might need to disable the write polling */
}

static void read_on_ready(struct st_h2o_evloop_socket_t *sock)
{
    const char *err = 0;
    size_t prev_size = sock->super.input->size;

    if ((sock->_flags & H2O_SOCKET_FLAG_DONT_READ) != 0)
        goto Notify;

    if ((err = on_read_core(sock->fd, sock->super.ssl == NULL ? &sock->super.input : &sock->super.ssl->input.encrypted,
                            sock->max_read_size)) != NULL)
        goto Notify;

    if (sock->super.ssl != NULL && sock->super.ssl->handshake.cb == NULL)
        err = decode_ssl_input(&sock->super);

Notify:
    /* the application may get notified even if no new data is avaiable.  The
     * behavior is intentional; it is designed as such so that the applications
     * can update their timeout counters when a partial SSL record arrives.
     */
    sock->super.bytes_read += sock->super.input->size - prev_size;
    sock->super._cb.read(&sock->super, err);
}

void do_dispose_socket(h2o_socket_t *_sock)
{
    struct st_h2o_evloop_socket_t *sock = (struct st_h2o_evloop_socket_t *)_sock;

    evloop_do_on_socket_close(sock);
    dispose_write_buf(&sock->super);
    if (sock->fd != -1) {
        close(sock->fd);
        sock->fd = -1;
    }
    sock->_flags = H2O_SOCKET_FLAG_IS_DISPOSED;
    link_to_statechanged(sock);
}

void do_write(h2o_socket_t *_sock, h2o_iovec_t *bufs, size_t bufcnt, h2o_socket_cb cb)
{
    struct st_h2o_evloop_socket_t *sock = (struct st_h2o_evloop_socket_t *)_sock;
    size_t first_buf_written;

    sock->super._cb.write = cb;

    /* try to write now */
    if ((first_buf_written = write_core(sock, &bufs, &bufcnt)) == SIZE_MAX) {
        /* fill in _wreq.bufs with fake data to indicate error */
        sock->super._write_buf.bufs = sock->super._write_buf.smallbufs;
        sock->super._write_buf.cnt = 1;
        *sock->super._write_buf.bufs = h2o_iovec_init(H2O_STRLIT("deadbeef"));
        sock->_flags |= H2O_SOCKET_FLAG_IS_WRITE_NOTIFY;
        link_to_pending(sock);
        return;
    }
    if (bufcnt == 0 && !has_pending_ssl_bytes(sock->super.ssl)) {
        /* write complete, schedule the callback */
        sock->_flags |= H2O_SOCKET_FLAG_IS_WRITE_NOTIFY;
        link_to_pending(sock);
        return;
    }

    /* setup the buffer to send pending data */
    init_write_buf(&sock->super, bufs, bufcnt, first_buf_written);

    /* schedule the write */
    link_to_statechanged(sock);
}

int h2o_socket_get_fd(h2o_socket_t *_sock)
{
    struct st_h2o_evloop_socket_t *sock = (struct st_h2o_evloop_socket_t *)_sock;
    return sock->fd;
}

void do_read_start(h2o_socket_t *_sock)
{
    struct st_h2o_evloop_socket_t *sock = (struct st_h2o_evloop_socket_t *)_sock;

    link_to_statechanged(sock);
}

void do_read_stop(h2o_socket_t *_sock)
{
    struct st_h2o_evloop_socket_t *sock = (struct st_h2o_evloop_socket_t *)_sock;

    sock->_flags &= ~H2O_SOCKET_FLAG_IS_READ_READY;
    link_to_statechanged(sock);
}

void h2o_socket_dont_read(h2o_socket_t *_sock, int dont_read)
{
    struct st_h2o_evloop_socket_t *sock = (struct st_h2o_evloop_socket_t *)_sock;

    if (dont_read) {
        sock->_flags |= H2O_SOCKET_FLAG_DONT_READ;
    } else {
        sock->_flags &= ~H2O_SOCKET_FLAG_DONT_READ;
    }
}

int do_export(h2o_socket_t *_sock, h2o_socket_export_t *info)
{
    struct st_h2o_evloop_socket_t *sock = (void *)_sock;

    assert((sock->_flags & H2O_SOCKET_FLAG_IS_DISPOSED) == 0);
    evloop_do_on_socket_export(sock);
    sock->_flags = H2O_SOCKET_FLAG_IS_DISPOSED;

    info->fd = sock->fd;
    sock->fd = -1;

    return 0;
}

h2o_socket_t *do_import(h2o_loop_t *loop, h2o_socket_export_t *info)
{
    return h2o_evloop_socket_create(loop, info->fd, 0);
}

h2o_loop_t *h2o_socket_get_loop(h2o_socket_t *_sock)
{
    struct st_h2o_evloop_socket_t *sock = (void *)_sock;
    return sock->loop;
}

socklen_t get_sockname_uncached(h2o_socket_t *_sock, struct sockaddr *sa)
{
    struct st_h2o_evloop_socket_t *sock = (void *)_sock;
    socklen_t len = sizeof(struct sockaddr_storage);
    if (getsockname(sock->fd, sa, &len) != 0)
        return 0;
    return len;
}

socklen_t get_peername_uncached(h2o_socket_t *_sock, struct sockaddr *sa)
{
    struct st_h2o_evloop_socket_t *sock = (void *)_sock;
    socklen_t len = sizeof(struct sockaddr_storage);
    if (getpeername(sock->fd, sa, &len) != 0)
        return 0;
    return len;
}

static struct st_h2o_evloop_socket_t *create_socket(h2o_evloop_t *loop, int fd, int flags)
{
    struct st_h2o_evloop_socket_t *sock;

    sock = h2o_mem_alloc(sizeof(*sock));
    memset(sock, 0, sizeof(*sock));
    h2o_buffer_init(&sock->super.input, &h2o_socket_buffer_prototype);
    sock->loop = loop;
    sock->fd = fd;
    sock->_flags = flags;
    sock->max_read_size = 1024 * 1024; /* by default, we read up to 1MB at once */
    sock->_next_pending = sock;
    sock->_next_statechanged = sock;

    evloop_do_on_socket_create(sock);

    return sock;
}

/**
 * Sets TCP_NODELAY if the given file descriptor is likely to be a TCP socket. The intent of this function isto reduce number of
 * unnecessary system calls. Therefore, we skip setting TCP_NODELAY when it is certain that the socket is not a TCP socket,
 * otherwise call setsockopt.
 */
static void set_nodelay_if_likely_tcp(int fd, struct sockaddr *sa)
{
    if (sa != NULL && !(sa->sa_family == AF_INET || sa->sa_family == AF_INET6))
        return;

    int on = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));
}

h2o_socket_t *h2o_evloop_socket_create(h2o_evloop_t *loop, int fd, int flags)
{
    /* It is the reponsibility of the event loop to modify the properties of a socket for its use (e.g., set O_NONBLOCK). */
    fcntl(fd, F_SETFL, O_NONBLOCK);
    set_nodelay_if_likely_tcp(fd, NULL);

    return &create_socket(loop, fd, flags)->super;
}

h2o_socket_t *h2o_evloop_socket_accept(h2o_socket_t *_listener)
{
    struct st_h2o_evloop_socket_t *listener = (struct st_h2o_evloop_socket_t *)_listener;
    int fd;
    h2o_socket_t *sock;

    /* cache the remote address, if we know that we are going to use the value (in h2o_socket_ebpf_lookup_flags) */
#if H2O_USE_EBPF_MAP
    struct {
        struct sockaddr_storage storage;
        socklen_t len;
    } _peeraddr;
    _peeraddr.len = sizeof(_peeraddr.storage);
    struct sockaddr_storage *peeraddr = &_peeraddr.storage;
    socklen_t *peeraddrlen = &_peeraddr.len;
#else
    struct sockaddr_storage *peeraddr = NULL;
    socklen_t *peeraddrlen = NULL;
#endif

#if H2O_USE_ACCEPT4
    /* the anticipation here is that a socket returned by `accept4` will inherit the TCP_NODELAY flag from the listening socket */
    if ((fd = accept4(listener->fd, (struct sockaddr *)peeraddr, peeraddrlen, SOCK_NONBLOCK | SOCK_CLOEXEC)) == -1)
        return NULL;
    sock = &create_socket(listener->loop, fd, H2O_SOCKET_FLAG_IS_ACCEPTED_CONNECTION)->super;
#else
    if ((fd = cloexec_accept(listener->fd, (struct sockaddr *)peeraddr, peeraddrlen)) == -1)
        return NULL;
    fcntl(fd, F_SETFL, O_NONBLOCK);
    sock = &create_socket(listener->loop, fd, H2O_SOCKET_FLAG_IS_ACCEPTED_CONNECTION)->super;
#endif
    set_nodelay_if_likely_tcp(fd, (struct sockaddr *)peeraddr);

    if (peeraddr != NULL && *peeraddrlen <= sizeof(*peeraddr))
        h2o_socket_setpeername(sock, (struct sockaddr *)peeraddr, *peeraddrlen);
    uint64_t flags = h2o_socket_ebpf_lookup_flags(listener->loop, h2o_socket_ebpf_init_key, sock);
    if ((flags & H2O_EBPF_FLAGS_SKIP_TRACING_BIT) != 0)
        sock->_skip_tracing = 1;
    return sock;
}

h2o_socket_t *h2o_socket_connect(h2o_loop_t *loop, struct sockaddr *addr, socklen_t addrlen, h2o_socket_cb cb, const char **err)
{
    int fd;
    struct st_h2o_evloop_socket_t *sock;

    if ((fd = cloexec_socket(addr->sa_family, SOCK_STREAM, 0)) == -1) {
        if (err != NULL) {
            *err = h2o_socket_error_socket_fail;
        }
        return NULL;
    }
    fcntl(fd, F_SETFL, O_NONBLOCK);
    if (!(connect(fd, addr, addrlen) == 0 || errno == EINPROGRESS)) {
        if (err != NULL)
            *err = h2o_socket_get_error_string(errno, h2o_socket_error_conn_fail);
        close(fd);
        return NULL;
    }

    sock = create_socket(loop, fd, H2O_SOCKET_FLAG_IS_CONNECTING);
    set_nodelay_if_likely_tcp(fd, addr);

    h2o_socket_notify_write(&sock->super, cb);
    return &sock->super;
}

void h2o_evloop_socket_set_max_read_size(h2o_socket_t *_sock, size_t max_size)
{
    struct st_h2o_evloop_socket_t *sock = (void *)_sock;
    sock->max_read_size = max_size;
}

h2o_evloop_t *create_evloop(size_t sz)
{
    h2o_evloop_t *loop = h2o_mem_alloc(sz);

    memset(loop, 0, sz);
    loop->_statechanged.tail_ref = &loop->_statechanged.head;
    update_now(loop);
    /* 3 levels * 32-slots => 1 second goes into 2nd, becomes O(N) above approx. 31 seconds */
    loop->_timeouts = h2o_timerwheel_create(3, loop->_now_millisec);

    return loop;
}

void update_now(h2o_evloop_t *loop)
{
    gettimeofday(&loop->_tv_at, NULL);
    loop->_now_nanosec = ((uint64_t)loop->_tv_at.tv_sec * 1000000 + loop->_tv_at.tv_usec) * 1000;
    loop->_now_millisec = loop->_now_nanosec / 1000000;
}

int32_t adjust_max_wait(h2o_evloop_t *loop, int32_t max_wait)
{
    uint64_t wake_at = h2o_timerwheel_get_wake_at(loop->_timeouts);

    update_now(loop);

    if (wake_at <= loop->_now_millisec) {
        max_wait = 0;
    } else {
        uint64_t delta = wake_at - loop->_now_millisec;
        if (delta < max_wait)
            max_wait = (int32_t)delta;
    }

    return max_wait;
}

void h2o_socket_notify_write(h2o_socket_t *_sock, h2o_socket_cb cb)
{
    struct st_h2o_evloop_socket_t *sock = (struct st_h2o_evloop_socket_t *)_sock;
    assert(sock->super._cb.write == NULL);
    assert(sock->super._write_buf.cnt == 0);
    assert(!has_pending_ssl_bytes(sock->super.ssl));

    sock->super._cb.write = cb;
    link_to_statechanged(sock);
}

static void run_socket(struct st_h2o_evloop_socket_t *sock)
{
    if ((sock->_flags & H2O_SOCKET_FLAG_IS_DISPOSED) != 0) {
        /* is freed in updatestates phase */
        return;
    }

    if ((sock->_flags & H2O_SOCKET_FLAG_IS_READ_READY) != 0) {
        sock->_flags &= ~H2O_SOCKET_FLAG_IS_READ_READY;
        read_on_ready(sock);
    }

    if ((sock->_flags & H2O_SOCKET_FLAG_IS_WRITE_NOTIFY) != 0) {
        const char *err = NULL;
        assert(sock->super._cb.write != NULL);
        sock->_flags &= ~H2O_SOCKET_FLAG_IS_WRITE_NOTIFY;
        if (sock->super._write_buf.cnt != 0 || has_pending_ssl_bytes(sock->super.ssl)) {
            /* error */
            err = h2o_socket_error_io;
            sock->super._write_buf.cnt = 0;
            if (has_pending_ssl_bytes(sock->super.ssl))
                dispose_ssl_output_buffer(sock->super.ssl);
        } else if ((sock->_flags & H2O_SOCKET_FLAG_IS_CONNECTING) != 0) {
            sock->_flags &= ~H2O_SOCKET_FLAG_IS_CONNECTING;
            int so_err = 0;
            socklen_t l = sizeof(so_err);
            so_err = 0;
            if (getsockopt(sock->fd, SOL_SOCKET, SO_ERROR, &so_err, &l) != 0 || so_err != 0)
                err = h2o_socket_get_error_string(so_err, h2o_socket_error_conn_fail);
        }
        on_write_complete(&sock->super, err);
    }
}

static void run_pending(h2o_evloop_t *loop)
{
    struct st_h2o_evloop_socket_t *sock;

    while (loop->_pending_as_server != NULL || loop->_pending_as_client != NULL) {
        while ((sock = loop->_pending_as_client) != NULL) {
            loop->_pending_as_client = sock->_next_pending;
            sock->_next_pending = sock;
            run_socket(sock);
        }
        if ((sock = loop->_pending_as_server) != NULL) {
            loop->_pending_as_server = sock->_next_pending;
            sock->_next_pending = sock;
            run_socket(sock);
        }
    }
}

void h2o_evloop_destroy(h2o_evloop_t *loop)
{
    struct st_h2o_evloop_socket_t *sock;

    /* timeouts are governed by the application and MUST be destroyed prior to destroying the loop */
    assert(h2o_timerwheel_get_wake_at(loop->_timeouts) == UINT64_MAX);

    /* dispose all socket */
    while ((sock = loop->_pending_as_client) != NULL) {
        loop->_pending_as_client = sock->_next_pending;
        sock->_next_pending = sock;
        h2o_socket_close((h2o_socket_t *)sock);
    }
    while ((sock = loop->_pending_as_server) != NULL) {
        loop->_pending_as_server = sock->_next_pending;
        sock->_next_pending = sock;
        h2o_socket_close((h2o_socket_t *)sock);
    }

    /* now all socket are disposedand and placed in linked list statechanged
     * we can freeing memory in cycle by next_statechanged,
     */
    while ((sock = loop->_statechanged.head) != NULL) {
        loop->_statechanged.head = sock->_next_statechanged;
        free(sock);
    }

    /* dispose backend-specific data */
    evloop_do_dispose(loop);

    /* lastly we need to free loop memory */
    h2o_timerwheel_destroy(loop->_timeouts);
    free(loop);
}

int h2o_evloop_run(h2o_evloop_t *loop, int32_t max_wait)
{
    /* update socket states, poll, set readable flags, perform pending writes */
    if (evloop_do_proceed(loop, max_wait) != 0)
        return -1;

    /* run the pending callbacks */
    run_pending(loop);

    /* run the expired timers at the same time invoking pending callbacks for every timer callback. This is an locality
     * optimization; handles things like timeout -> write -> on_write_complete for each object. */
    while (1) {
        h2o_linklist_t expired;
        h2o_linklist_init_anchor(&expired);
        h2o_timerwheel_get_expired(loop->_timeouts, loop->_now_millisec, &expired);
        if (h2o_linklist_is_empty(&expired))
            break;
        do {
            h2o_timerwheel_entry_t *timer = H2O_STRUCT_FROM_MEMBER(h2o_timerwheel_entry_t, _link, expired.next);
            h2o_linklist_unlink(&timer->_link);
            timer->cb(timer);
            run_pending(loop);
        } while (!h2o_linklist_is_empty(&expired));
    }

    assert(loop->_pending_as_client == NULL);
    assert(loop->_pending_as_server == NULL);

    if (h2o_sliding_counter_is_running(&loop->exec_time_nanosec_counter)) {
        update_now(loop);
        h2o_sliding_counter_stop(&loop->exec_time_nanosec_counter, loop->_now_nanosec);
    }

    return 0;
}
