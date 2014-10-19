/*
 * Copyright (c) 2014 DeNA Co., Ltd.
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
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>
#include "h2o/linklist.h"

struct st_h2o_evloop_socket_t {
    h2o_socket_t super;
    int fd;
    int _flags;
    h2o_evloop_t *loop;
    struct {
        size_t cnt;
        h2o_buf_t *bufs;
        union {
            h2o_buf_t *alloced_ptr;
            h2o_buf_t smallbufs[4];
        };
    } _wreq;
    struct st_h2o_evloop_socket_t *_next_pending;
    struct st_h2o_evloop_socket_t *_next_statechanged;
};

struct st_h2o_evloop_t {
    struct st_h2o_evloop_socket_t *_pending;
    struct {
        struct st_h2o_evloop_socket_t *head;
        struct st_h2o_evloop_socket_t **tail_ref;
    } _statechanged;
    uint64_t _now;
    h2o_linklist_t _timeouts; /* list of h2o_timeout_t */
};

static void link_to_pending(struct st_h2o_evloop_socket_t *sock);
static void write_pending(struct st_h2o_evloop_socket_t *sock);
static h2o_evloop_t *create_evloop(size_t sz);
static void update_now(h2o_evloop_t *loop);
static int32_t get_max_wait(h2o_evloop_t *loop);

/* functions to be defined in the backends */
static int evloop_do_proceed(h2o_evloop_t *loop);
static void evloop_do_on_socket_create(struct st_h2o_evloop_socket_t *sock);
static void evloop_do_on_socket_close(struct st_h2o_evloop_socket_t *sock);

#if H2O_USE_SELECT || H2O_USE_EPOLL || H2O_USE_KQUEUE
/* explicitly specified */
#else
# if defined(__APPLE__)
#  define H2O_USE_KQUEUE 1
# elif defined(__linux)
#  define H2O_USE_EPOLL 1
# else
#  define H2O_USE_SELECT 1
# endif
#endif

#if H2O_USE_SELECT
# include "evloop/select.c.h"
#elif H2O_USE_EPOLL
# include "evloop/epoll.c.h"
#elif H2O_USE_KQUEUE
# include "evloop/kqueue.c.h"
#else
# error "poller not specified"
#endif

void link_to_pending(struct st_h2o_evloop_socket_t *sock)
{
    if (sock->_next_pending == sock) {
        sock->_next_pending = sock->loop->_pending;
        sock->loop->_pending = sock;
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

static int on_read_core(int fd, h2o_input_buffer_t** input)
{
    int read_any = 0;

    while (1) {
        h2o_buf_t buf = h2o_reserve_input_buffer(input, 8192);
        ssize_t rret;
        while ((rret = read(fd, buf.base, buf.len)) == -1 && errno == EINTR)
            ;
        if (rret == -1) {
            if (errno == EAGAIN)
                break;
            else
                return -1;
        } else if (rret == 0) {
            if (! read_any)
                return -1; /* TODO notify close */
            break;
        }
        (*input)->size += rret;
        read_any = 1;
    }
    return 0;
}

static void wreq_free_buffer_if_allocated(struct st_h2o_evloop_socket_t *sock)
{
    if (sock->_wreq.smallbufs <= sock->_wreq.bufs && sock->_wreq.bufs <= sock->_wreq.smallbufs + sizeof(sock->_wreq.smallbufs) / sizeof(sock->_wreq.smallbufs[0])) {
        /* no need to free */
    } else {
        free(sock->_wreq.alloced_ptr);
        sock->_wreq.bufs = sock->_wreq.smallbufs;
    }
}

static int write_core(int fd, h2o_buf_t **bufs, size_t *bufcnt)
{
    int iovcnt;
    ssize_t wret;

    if (*bufcnt != 0) {
        do {
            /* write */
            iovcnt = IOV_MAX;
            if (*bufcnt < iovcnt)
                iovcnt = (int)*bufcnt;
            while ((wret = writev(fd, (struct iovec*)*bufs, iovcnt)) == -1 && errno == EINTR)
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

    if ((sock->_flags & H2O_SOCKET_FLAG_IS_CONNECTING) != 0) {
        /* connection complete */
        assert(sock->_wreq.cnt == 0);
        goto Complete;
    }

    assert(sock->_wreq.cnt != 0);

    /* write */
    if (write_core(sock->fd, &sock->_wreq.bufs, &sock->_wreq.cnt) == 0 && sock->_wreq.cnt != 0) {
        /* partial write */
        return;
    }

    /* either completed or failed */
    wreq_free_buffer_if_allocated(sock);
    if (sock->_wreq.cnt != 0) {
        /* pending data exists -> was an error */
        sock->_wreq.cnt = 0; /* clear it ! */
        sock->_flags |= H2O_SOCKET_FLAG_IS_WRITE_ERROR;
    }

Complete:
    link_to_pending(sock);
    link_to_statechanged(sock); /* might need to disable the write polling */
}

static void read_on_ready(struct st_h2o_evloop_socket_t *sock)
{
    int status = 0;

    if ((sock->_flags & H2O_SOCKET_FLAG_IS_ACCEPT) != 0)
        goto Notify;

    if ((status = on_read_core(sock->fd, sock->super.ssl == NULL ? &sock->super.input : &sock->super.ssl->input.encrypted)) != 0)
        goto Notify;

    if (sock->super.ssl != NULL && sock->super.ssl->handshake.cb == NULL)
        status = decode_ssl_input(&sock->super);

Notify:
    /* the application may get notified even if no new data is avaiable.  The
     * behavior is intentional; it is designed as such so that the applications
     * can update their timeout counters when a partial SSL record arrives.
     */
    sock->super._cb.read(&sock->super, status);
}

void do_dispose_socket(h2o_socket_t *_sock)
{
    struct st_h2o_evloop_socket_t *sock = (struct st_h2o_evloop_socket_t*)_sock;

    evloop_do_on_socket_close(sock);
    wreq_free_buffer_if_allocated(sock);
    close(sock->fd);
    sock->_flags = H2O_SOCKET_FLAG_IS_DISPOSED;
    link_to_statechanged(sock);
}

void do_write(h2o_socket_t *_sock, h2o_buf_t *bufs, size_t bufcnt, h2o_socket_cb cb)
{
    struct st_h2o_evloop_socket_t *sock = (struct st_h2o_evloop_socket_t*)_sock;

    assert(sock->super._cb.write == NULL);
    assert(sock->_wreq.cnt == 0);
    sock->super._cb.write = cb;

    /* try to write now */
    if (write_core(sock->fd, &bufs, &bufcnt) != 0) {
        sock->_flags |= H2O_SOCKET_FLAG_IS_WRITE_ERROR;
        link_to_pending(sock);
        return;
    }
    if (bufcnt == 0) {
        /* write complete, schedule the callback */
        link_to_pending(sock);
        return;
    }

    /* setup the buffer to send pending data */
    if (bufcnt <= sizeof(sock->_wreq.smallbufs) / sizeof(sock->_wreq.smallbufs[0])) {
        sock->_wreq.bufs = sock->_wreq.smallbufs;
    } else {
        sock->_wreq.bufs = h2o_malloc(sizeof(h2o_buf_t) * bufcnt);
        sock->_wreq.alloced_ptr = sock->_wreq.bufs = sock->_wreq.bufs;
    }
    memcpy(sock->_wreq.bufs, bufs, sizeof(h2o_buf_t) * bufcnt);
    sock->_wreq.cnt = bufcnt;

    /* schedule the write */
    link_to_statechanged(sock);
}

void do_read_start(h2o_socket_t *_sock)
{
    struct st_h2o_evloop_socket_t *sock = (struct st_h2o_evloop_socket_t*)_sock;

    link_to_statechanged(sock);
}

void do_read_stop(h2o_socket_t *_sock)
{
    struct st_h2o_evloop_socket_t *sock = (struct st_h2o_evloop_socket_t*)_sock;

    sock->_flags &= ~H2O_SOCKET_FLAG_IS_READ_READY;
    link_to_statechanged(sock);
}

h2o_socket_t *h2o_evloop_socket_create(h2o_evloop_t *loop, int fd, struct sockaddr *addr, socklen_t addrlen, int flags)
{
    struct st_h2o_evloop_socket_t *sock;

    fcntl(fd, F_SETFL, O_NONBLOCK);

    sock = h2o_malloc(sizeof(*sock));
    memset(sock, 0, sizeof(*sock));
    h2o_init_input_buffer(&sock->super.input);
    assert(addrlen < sizeof(sock->super.peername.addr));
    memcpy(&sock->super.peername.addr, addr, addrlen);
    sock->super.peername.len = addrlen;
    sock->loop = loop;
    sock->fd = fd;
    sock->_flags = flags;
    sock->_wreq.bufs = sock->_wreq.smallbufs;
    sock->_next_pending = sock;
    sock->_next_statechanged = sock;

    evloop_do_on_socket_create(sock);

    return &sock->super;
}

h2o_socket_t *h2o_evloop_socket_accept(h2o_socket_t *_listener)
{
    struct st_h2o_evloop_socket_t *listener = (struct st_h2o_evloop_socket_t*)_listener;
    h2o_socket_t *sock;
    struct sockaddr_storage addr;
    socklen_t addrlen = sizeof(addr);
    int fd, on;

#ifdef __linux__
    if ((fd = accept4(listener->fd, (void*)&addr, &addrlen, O_NONBLOCK)) == -1)
        return NULL;
#else
    if ((fd = accept(listener->fd, (void*)&addr, &addrlen)) == -1)
        return NULL;
    fcntl(fd, F_SETFL, O_NONBLOCK);
#endif
    on = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));

    sock = h2o_evloop_socket_create(listener->loop, fd, (void*)&addr, addrlen, 0);
    return sock;
}

h2o_socket_t *h2o_socket_connect(h2o_loop_t *loop, struct sockaddr *addr, socklen_t addrlen, h2o_socket_cb cb)
{
    int fd;
    struct st_h2o_evloop_socket_t *sock;

    if ((fd = socket(addr->sa_family, SOCK_STREAM, IPPROTO_TCP)) == -1)
        return NULL;
    if (! (connect(fd, addr, addrlen) == 0 || errno == EINPROGRESS)) {
        close(fd);
        return NULL;
    }

    sock = (void*)h2o_evloop_socket_create(loop, fd, addr, addrlen, H2O_SOCKET_FLAG_IS_CONNECTING);
    sock->super._cb.write = cb;
    link_to_statechanged(sock);
    return &sock->super;
}

h2o_evloop_t *create_evloop(size_t sz)
{
    h2o_evloop_t *loop = h2o_malloc(sz);

    memset(loop, 0, sz);
    loop->_statechanged.tail_ref = &loop->_statechanged.head;
    h2o_linklist_init_anchor(&loop->_timeouts);

    return loop;
}

void update_now(h2o_evloop_t *loop)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    loop->_now = (uint64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

int32_t get_max_wait(h2o_evloop_t *loop)
{
    uint64_t wake_at = h2o_timeout_get_wake_at(&loop->_timeouts), max_wait;

    update_now(loop);

    if (wake_at <= loop->_now) {
        max_wait = 0;
    } else {
        max_wait = wake_at - loop->_now;
        if (max_wait > INT32_MAX)
            max_wait = INT32_MAX;
    }

    return (int32_t)max_wait;
}

static void run_socket(struct st_h2o_evloop_socket_t* sock)
{
    if ((sock->_flags & H2O_SOCKET_FLAG_IS_DISPOSED) != 0) {
        /* is freed in updatestates phase */
        return;
    }

    if (sock->super._cb.write != NULL && sock->_wreq.cnt == 0) {
        int status;
        if ((sock->_flags & H2O_SOCKET_FLAG_IS_CONNECTING) != 0) {
            socklen_t l = sizeof(status);
            getsockopt(sock->fd, SOL_SOCKET, SO_ERROR, &status, &l);
            sock->_flags &= ~H2O_SOCKET_FLAG_IS_CONNECTING;
        } else {
            status = (sock->_flags & H2O_SOCKET_FLAG_IS_WRITE_ERROR) != 0 ? -1 : 0;
        }
        on_write_complete(&sock->super, status);
    }

    if ((sock->_flags & H2O_SOCKET_FLAG_IS_READ_READY) != 0) {
        sock->_flags &= ~H2O_SOCKET_FLAG_IS_READ_READY;
        read_on_ready(sock);
    }
}

static size_t run_pending(h2o_evloop_t *loop)
{
    size_t n = 0;

    for (; loop->_pending != NULL; ++n) {
        /* detach the first sock and run */
        struct st_h2o_evloop_socket_t *sock = loop->_pending;
        loop->_pending = sock->_next_pending;
        sock->_next_pending = sock;
        run_socket(sock);
    }

    return n;
}

int h2o_evloop_run(h2o_evloop_t *loop)
{
    /* update socket states, poll, set readable flags, perform pending writes */
    if (evloop_do_proceed(loop) != 0)
        return -1;

    /* run the timeouts and pending callbacks */
    while (run_pending(loop) + h2o_timeout_run_all(&loop->_timeouts, loop->_now) != 0)
        ;

    return 0;
}

uint64_t h2o_now(h2o_evloop_t *loop)
{
    return loop->_now;
}

void h2o_timeout__do_init(h2o_evloop_t *loop, h2o_timeout_t *timeout)
{
    h2o_linklist_insert(&loop->_timeouts, &timeout->_link);
}

void h2o_timeout__do_link(h2o_evloop_t *loop, h2o_timeout_t *timeout, h2o_timeout_entry_t *entry)
{
    /* nothing to do */
}
