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
#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <sys/epoll.h>

#if 0
#define DEBUG_LOG(...) fprintf(stderr, __VA_ARGS__)
#else
#define DEBUG_LOG(...)
#endif

struct st_h2o_evloop_epoll_t {
    h2o_evloop_t super;
    int ep;
};

static int update_status(struct st_h2o_evloop_epoll_t *loop)
{
    while (loop->super._statechanged.head != NULL) {
        /* detach the top */
        struct st_h2o_evloop_socket_t *sock = loop->super._statechanged.head;
        loop->super._statechanged.head = sock->_next_statechanged;
        sock->_next_statechanged = sock;
        /* update the state */
        if ((sock->_flags & H2O_SOCKET_FLAG_IS_DISPOSED) != 0) {
            free(sock);
        } else {
            int changed = 0, op, ret;
            struct epoll_event ev;
            ev.events = 0;
            if (h2o_socket_is_reading(&sock->super)) {
                ev.events |= EPOLLIN;
                if ((sock->_flags & H2O_SOCKET_FLAG_IS_POLLED_FOR_READ) == 0) {
                    sock->_flags |= H2O_SOCKET_FLAG_IS_POLLED_FOR_READ;
                    changed = 1;
                }
            } else {
                if ((sock->_flags & H2O_SOCKET_FLAG_IS_POLLED_FOR_READ) != 0) {
                    sock->_flags &= ~H2O_SOCKET_FLAG_IS_POLLED_FOR_READ;
                    changed = 1;
                }
            }
            if (h2o_socket_is_writing(&sock->super)) {
                ev.events |= EPOLLOUT;
                if ((sock->_flags & H2O_SOCKET_FLAG_IS_POLLED_FOR_WRITE) == 0) {
                    sock->_flags |= H2O_SOCKET_FLAG_IS_POLLED_FOR_WRITE;
                    changed = 1;
                }
            } else {
                if ((sock->_flags & H2O_SOCKET_FLAG_IS_POLLED_FOR_WRITE) != 0) {
                    sock->_flags &= ~H2O_SOCKET_FLAG_IS_POLLED_FOR_WRITE;
                    changed = 1;
                }
            }
            if (changed) {
                if ((sock->_flags & H2O_SOCKET_FLAG__EPOLL_IS_REGISTERED) != 0) {
                    if (ev.events != 0)
                        op = EPOLL_CTL_MOD;
                    else
                        op = EPOLL_CTL_DEL;
                } else {
                    assert(ev.events != 0);
                    op = EPOLL_CTL_ADD;
                }
                ev.data.ptr = sock;
                while ((ret = epoll_ctl(loop->ep, op, sock->fd, &ev)) != 0 && errno == EINTR)
                    ;
                if (ret != 0)
                    return -1;
                if (op == EPOLL_CTL_DEL)
                    sock->_flags &= ~H2O_SOCKET_FLAG__EPOLL_IS_REGISTERED;
                else
                    sock->_flags |= H2O_SOCKET_FLAG__EPOLL_IS_REGISTERED;
            }
        }
    }
    loop->super._statechanged.tail_ref = &loop->super._statechanged.head;

    return 0;
}

int evloop_do_proceed(h2o_evloop_t *_loop, int32_t max_wait)
{
    struct st_h2o_evloop_epoll_t *loop = (struct st_h2o_evloop_epoll_t *)_loop;
    struct epoll_event events[256];
    int nevents, i;

    /* collect (and update) status */
    if (update_status(loop) != 0)
        return -1;

    /* poll */
    max_wait = adjust_max_wait(&loop->super, max_wait);
    nevents = epoll_wait(loop->ep, events, sizeof(events) / sizeof(events[0]), max_wait);
    update_now(&loop->super);
    if (nevents == -1)
        return -1;

    if (nevents != 0)
        h2o_sliding_counter_start(&loop->super.exec_time_counter, loop->super._now);

    /* update readable flags, perform writes */
    for (i = 0; i != nevents; ++i) {
        struct st_h2o_evloop_socket_t *sock = events[i].data.ptr;
        int notified = 0;
        if ((events[i].events & (EPOLLIN | EPOLLHUP | EPOLLERR)) != 0) {
            if ((sock->_flags & H2O_SOCKET_FLAG_IS_POLLED_FOR_READ) != 0) {
                sock->_flags |= H2O_SOCKET_FLAG_IS_READ_READY;
                link_to_pending(sock);
                notified = 1;
            }
        }
        if ((events[i].events & (EPOLLOUT | EPOLLHUP | EPOLLERR)) != 0) {
            if ((sock->_flags & H2O_SOCKET_FLAG_IS_POLLED_FOR_WRITE) != 0) {
                write_pending(sock);
                notified = 1;
            }
        }
        if (!notified) {
            static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
            static time_t last_reported = 0;
            time_t now = time(NULL);
            pthread_mutex_lock(&lock);
            if (last_reported + 60 < now) {
                last_reported = now;
                fprintf(stderr, "ignoring epoll event (fd:%d,event:%x)\n", sock->fd, (int)events[i].events);
            }
            pthread_mutex_unlock(&lock);
        }
    }

    return 0;
}

static void evloop_do_on_socket_create(struct st_h2o_evloop_socket_t *sock)
{
}

static void evloop_do_on_socket_close(struct st_h2o_evloop_socket_t *sock)
{
    struct st_h2o_evloop_epoll_t *loop = (void *)sock->loop;
    int ret;

    if (sock->fd == -1)
        return;
    if ((sock->_flags & H2O_SOCKET_FLAG__EPOLL_IS_REGISTERED) == 0)
        return;
    while ((ret = epoll_ctl(loop->ep, EPOLL_CTL_DEL, sock->fd, NULL)) != 0 && errno == EINTR)
        ;
    if (ret != 0)
        fprintf(stderr, "socket_close: epoll(DEL) returned error %d (fd=%d)\n", errno, sock->fd);
}

static void evloop_do_on_socket_export(struct st_h2o_evloop_socket_t *sock)
{
    struct st_h2o_evloop_epoll_t *loop = (void *)sock->loop;
    int ret;

    if ((sock->_flags & H2O_SOCKET_FLAG__EPOLL_IS_REGISTERED) == 0)
        return;
    while ((ret = epoll_ctl(loop->ep, EPOLL_CTL_DEL, sock->fd, NULL)) != 0 && errno == EINTR)
        ;
    if (ret != 0)
        fprintf(stderr, "socket_export: epoll(DEL) returned error %d (fd=%d)\n", errno, sock->fd);
}

h2o_evloop_t *h2o_evloop_create(void)
{
    struct st_h2o_evloop_epoll_t *loop = (struct st_h2o_evloop_epoll_t *)create_evloop(sizeof(*loop));

    pthread_mutex_lock(&cloexec_mutex);
    loop->ep = epoll_create(10);
    while (fcntl(loop->ep, F_SETFD, FD_CLOEXEC) == -1) {
        if (errno != EAGAIN) {
            fprintf(stderr, "h2o_evloop_create: failed to set FD_CLOEXEC to the epoll fd (errno=%d)\n", errno);
            abort();
        }
    }
    pthread_mutex_unlock(&cloexec_mutex);

    return &loop->super;
}
