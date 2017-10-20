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
#define H2O_USE_ACCEPT4 1
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
    struct {
        size_t cnt;
        h2o_iovec_t *bufs;
        union {
            h2o_iovec_t *alloced_ptr;
            h2o_iovec_t smallbufs[4];
        };
    } _wreq;
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

static const char *on_read_core(int fd, h2o_buffer_t **input)
{
    int read_any = 0;

    while (1) {
        ssize_t rret;
        h2o_iovec_t buf = h2o_buffer_reserve(input, 4096);
        if (buf.base == NULL) {
            /* memory allocation failed */
            return h2o_socket_error_out_of_memory;
        }
        while ((rret = read(fd, buf.base, buf.len <= INT_MAX / 2 ? buf.len : INT_MAX / 2 + 1)) == -1 && errno == EINTR)
            ;
        if (rret == -1) {
            if (errno == EAGAIN)
                break;
            else
                return h2o_socket_error_io;
        } else if (rret == 0) {
            if (!read_any)
                return h2o_socket_error_closed; /* TODO notify close */
            break;
        }
        (*input)->size += rret;
        if (buf.len != rret)
            break;
        read_any = 1;
    }
    return NULL;
}

static void wreq_free_buffer_if_allocated(struct st_h2o_evloop_socket_t *sock)
{
    if (sock->_wreq.smallbufs <= sock->_wreq.bufs &&
        sock->_wreq.bufs <= sock->_wreq.smallbufs + sizeof(sock->_wreq.smallbufs) / sizeof(sock->_wreq.smallbufs[0])) {
        /* no need to free */
    } else {
        free(sock->_wreq.alloced_ptr);
        sock->_wreq.bufs = sock->_wreq.smallbufs;
    }
}

static int write_core(int fd, h2o_iovec_t **bufs, size_t *bufcnt)
{
    int iovcnt;
    ssize_t wret;

    if (*bufcnt != 0) {
        do {
            /* write */
            iovcnt = IOV_MAX;
            if (*bufcnt < iovcnt)
                iovcnt = (int)*bufcnt;
            while ((wret = writev(fd, (struct iovec *)*bufs, iovcnt)) == -1 && errno == EINTR)
                ;
            if (wret == -1) {
                if (errno != EAGAIN)
                    return -1;
                break;
            }
            /* adjust the buffer */
            while ((*bufs)->len < wret) {
                wret -= (*bufs)->len;
                ++*bufs;
                --*bufcnt;
                assert(*bufcnt != 0);
            }
            if (((*bufs)->len -= wret) == 0) {
                ++*bufs;
                --*bufcnt;
            } else {
                (*bufs)->base += wret;
            }
        } while (*bufcnt != 0 && iovcnt == IOV_MAX);
    }

    return 0;
}

void write_pending(struct st_h2o_evloop_socket_t *sock)
{
    assert(sock->super._cb.write != NULL);

    /* DONT_WRITE poll */
    if (sock->_wreq.cnt == 0)
        goto Complete;

    /* write */
    if (write_core(sock->fd, &sock->_wreq.bufs, &sock->_wreq.cnt) == 0 && sock->_wreq.cnt != 0) {
        /* partial write */
        return;
    }

    /* either completed or failed */
    wreq_free_buffer_if_allocated(sock);

Complete:
    sock->_flags |= H2O_SOCKET_FLAG_IS_WRITE_NOTIFY;
    link_to_pending(sock);
    link_to_statechanged(sock); /* might need to disable the write polling */
}

static void read_on_ready(struct st_h2o_evloop_socket_t *sock)
{
    const char *err = 0;
    size_t prev_bytes_read = sock->super.input->size;

    if ((sock->_flags & H2O_SOCKET_FLAG_DONT_READ) != 0)
        goto Notify;

    if ((err = on_read_core(sock->fd, sock->super.ssl == NULL ? &sock->super.input : &sock->super.ssl->input.encrypted)) != NULL)
        goto Notify;

    if (sock->super.ssl != NULL && sock->super.ssl->handshake.cb == NULL)
        err = decode_ssl_input(&sock->super);

Notify:
    /* the application may get notified even if no new data is avaiable.  The
     * behavior is intentional; it is designed as such so that the applications
     * can update their timeout counters when a partial SSL record arrives.
     */
    sock->super.bytes_read = sock->super.input->size - prev_bytes_read;
    sock->super._cb.read(&sock->super, err);
}

void do_dispose_socket(h2o_socket_t *_sock)
{
    struct st_h2o_evloop_socket_t *sock = (struct st_h2o_evloop_socket_t *)_sock;

    evloop_do_on_socket_close(sock);
    wreq_free_buffer_if_allocated(sock);
    if (sock->fd != -1) {
        close(sock->fd);
        sock->fd = -1;
    }
    sock->_flags = H2O_SOCKET_FLAG_IS_DISPOSED;
    link_to_statechanged(sock);
}

void do_write(h2o_socket_t *_sock, h2o_iovec_t *_bufs, size_t bufcnt, h2o_socket_cb cb)
{
    struct st_h2o_evloop_socket_t *sock = (struct st_h2o_evloop_socket_t *)_sock;
    h2o_iovec_t *bufs;
    h2o_iovec_t *tofree = NULL;

    assert(sock->super._cb.write == NULL);
    assert(sock->_wreq.cnt == 0);
    sock->super._cb.write = cb;

    /* cap the number of buffers, since we're using alloca */
    if (bufcnt > 10000)
        bufs = tofree = h2o_mem_alloc(sizeof(*bufs) * bufcnt);
    else
        bufs = alloca(sizeof(*bufs) * bufcnt);

    memcpy(bufs, _bufs, sizeof(*bufs) * bufcnt);

    /* try to write now */
    if (write_core(sock->fd, &bufs, &bufcnt) != 0) {
        /* fill in _wreq.bufs with fake data to indicate error */
        sock->_wreq.bufs = sock->_wreq.smallbufs;
        sock->_wreq.cnt = 1;
        *sock->_wreq.bufs = h2o_iovec_init(H2O_STRLIT("deadbeef"));
        sock->_flags |= H2O_SOCKET_FLAG_IS_WRITE_NOTIFY;
        link_to_pending(sock);
        goto Out;
    }
    if (bufcnt == 0) {
        /* write complete, schedule the callback */
        sock->_flags |= H2O_SOCKET_FLAG_IS_WRITE_NOTIFY;
        link_to_pending(sock);
        goto Out;
    }


    /* setup the buffer to send pending data */
    if (bufcnt <= sizeof(sock->_wreq.smallbufs) / sizeof(sock->_wreq.smallbufs[0])) {
        sock->_wreq.bufs = sock->_wreq.smallbufs;
    } else {
        sock->_wreq.bufs = h2o_mem_alloc(sizeof(h2o_iovec_t) * bufcnt);
        sock->_wreq.alloced_ptr = sock->_wreq.bufs;
    }
    memcpy(sock->_wreq.bufs, bufs, sizeof(h2o_iovec_t) * bufcnt);
    sock->_wreq.cnt = bufcnt;

    /* schedule the write */
    link_to_statechanged(sock);
Out:
    free(tofree);
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

socklen_t h2o_socket_getsockname(h2o_socket_t *_sock, struct sockaddr *sa)
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

    fcntl(fd, F_SETFL, O_NONBLOCK);

    sock = h2o_mem_alloc(sizeof(*sock));
    memset(sock, 0, sizeof(*sock));
    h2o_buffer_init(&sock->super.input, &h2o_socket_buffer_prototype);
    sock->loop = loop;
    sock->fd = fd;
    sock->_flags = flags;
    sock->_wreq.bufs = sock->_wreq.smallbufs;
    sock->_next_pending = sock;
    sock->_next_statechanged = sock;

    evloop_do_on_socket_create(sock);

    return sock;
}

static struct st_h2o_evloop_socket_t *create_socket_set_nodelay(h2o_evloop_t *loop, int fd, int flags)
{
    int on = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));
    return create_socket(loop, fd, flags);
}

h2o_socket_t *h2o_evloop_socket_create(h2o_evloop_t *loop, int fd, int flags)
{
    fcntl(fd, F_SETFL, O_NONBLOCK);
    return &create_socket(loop, fd, flags)->super;
}

h2o_socket_t *h2o_evloop_socket_accept(h2o_socket_t *_listener)
{
    struct st_h2o_evloop_socket_t *listener = (struct st_h2o_evloop_socket_t *)_listener;
    int fd;

#if H2O_USE_ACCEPT4
    if ((fd = accept4(listener->fd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC)) == -1)
        return NULL;
#else
    if ((fd = cloexec_accept(listener->fd, NULL, NULL)) == -1)
        return NULL;
    fcntl(fd, F_SETFL, O_NONBLOCK);
#endif

    return &create_socket_set_nodelay(listener->loop, fd, H2O_SOCKET_FLAG_IS_ACCEPTED_CONNECTION)->super;
}

h2o_socket_t *h2o_socket_connect(h2o_loop_t *loop, struct sockaddr *addr, socklen_t addrlen, h2o_socket_cb cb)
{
    int fd;
    struct st_h2o_evloop_socket_t *sock;

    if ((fd = cloexec_socket(addr->sa_family, SOCK_STREAM, 0)) == -1)
        return NULL;
    fcntl(fd, F_SETFL, O_NONBLOCK);
    if (!(connect(fd, addr, addrlen) == 0 || errno == EINPROGRESS)) {
        close(fd);
        return NULL;
    }

    sock = create_socket_set_nodelay(loop, fd, H2O_SOCKET_FLAG_IS_CONNECTING);
    h2o_socket_notify_write(&sock->super, cb);
    return &sock->super;
}

h2o_evloop_t *create_evloop(size_t sz)
{
    h2o_evloop_t *loop = h2o_mem_alloc(sz);

    memset(loop, 0, sz);
    loop->_statechanged.tail_ref = &loop->_statechanged.head;
    h2o_linklist_init_anchor(&loop->_timeouts);

    update_now(loop);

    return loop;
}

void update_now(h2o_evloop_t *loop)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    loop->_now = (uint64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

int32_t adjust_max_wait(h2o_evloop_t *loop, int32_t max_wait)
{
    uint64_t wake_at = h2o_timeout_get_wake_at(&loop->_timeouts);

    update_now(loop);

    if (wake_at <= loop->_now) {
        max_wait = 0;
    } else {
        uint64_t delta = wake_at - loop->_now;
        if (delta < max_wait)
            max_wait = (int32_t)delta;
    }

    return max_wait;
}

void h2o_socket_notify_write(h2o_socket_t *_sock, h2o_socket_cb cb)
{
    struct st_h2o_evloop_socket_t *sock = (struct st_h2o_evloop_socket_t *)_sock;
    assert(sock->super._cb.write == NULL);
    assert(sock->_wreq.cnt == 0);

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
        if (sock->_wreq.cnt != 0) {
            /* error */
            err = h2o_socket_error_io;
            sock->_wreq.cnt = 0;
        } else if ((sock->_flags & H2O_SOCKET_FLAG_IS_CONNECTING) != 0) {
            sock->_flags &= ~H2O_SOCKET_FLAG_IS_CONNECTING;
            int so_err = 0;
            socklen_t l = sizeof(so_err);
            so_err = 0;
            if (getsockopt(sock->fd, SOL_SOCKET, SO_ERROR, &so_err, &l) != 0 || so_err != 0) {
                /* FIXME lookup the error table */
                err = h2o_socket_error_conn_fail;
            }
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
    assert(h2o_linklist_is_empty(&loop->_timeouts));

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

    /* lastly we need to free loop memory */
    free(loop);
}

int h2o_evloop_run(h2o_evloop_t *loop, int32_t max_wait)
{
    h2o_linklist_t *node;

    /* update socket states, poll, set readable flags, perform pending writes */
    if (evloop_do_proceed(loop, max_wait) != 0)
        return -1;

    /* run the pending callbacks */
    run_pending(loop);

    /* run the timeouts */
    for (node = loop->_timeouts.next; node != &loop->_timeouts; node = node->next) {
        h2o_timeout_t *timeout = H2O_STRUCT_FROM_MEMBER(h2o_timeout_t, _link, node);
        h2o_timeout_run(loop, timeout, loop->_now);
    }
    /* assert h2o_timeout_run has called run_pending */
    assert(loop->_pending_as_client == NULL);
    assert(loop->_pending_as_server == NULL);

    if (h2o_sliding_counter_is_running(&loop->exec_time_counter)) {
        update_now(loop);
        h2o_sliding_counter_stop(&loop->exec_time_counter, loop->_now);
    }

    return 0;
}

void h2o_timeout__do_init(h2o_evloop_t *loop, h2o_timeout_t *timeout)
{
    h2o_linklist_insert(&loop->_timeouts, &timeout->_link);
}

void h2o_timeout__do_dispose(h2o_evloop_t *loop, h2o_timeout_t *timeout)
{
    h2o_linklist_unlink(&timeout->_link);
}

void h2o_timeout__do_link(h2o_evloop_t *loop, h2o_timeout_t *timeout, h2o_timeout_entry_t *entry)
{
    /* nothing to do */
}

void h2o_timeout__do_post_callback(h2o_evloop_t *loop)
{
    run_pending(loop);
}
