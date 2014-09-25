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
# define DEBUG_LOG(...) fprintf(stderr, __VA_ARGS__)
#else
# define DEBUG_LOG(...)
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
            int changed = 0;
            struct epoll_event ev;
            ev.events = 0;
            if (h2o_socket_is_reading(&sock->super)) {
                if ((sock->_flags & H2O_SOCKET_FLAG_IS_POLLED_FOR_READ) == 0) {
                    sock->_flags |= H2O_SOCKET_FLAG_IS_POLLED_FOR_READ;
                    ev.events |= EPOLLIN;
                    changed = 1;
                }
            } else {
                if ((sock->_flags & H2O_SOCKET_FLAG_IS_POLLED_FOR_READ) != 0) {
                    sock->_flags &= ~H2O_SOCKET_FLAG_IS_POLLED_FOR_READ;
                    changed = 1;
                }
            }
            if (h2o_socket_is_writing(&sock->super) && sock->_wreq.cnt != 0) {
                if ((sock->_flags & H2O_SOCKET_FLAG_IS_POLLED_FOR_WRITE) == 0) {
                    sock->_flags |= H2O_SOCKET_FLAG_IS_POLLED_FOR_WRITE;
                    ev.events |= EPOLLOUT;
                    changed = 1;
                }
            } else {
                if ((sock->_flags & H2O_SOCKET_FLAG_IS_POLLED_FOR_WRITE) != 0) {
                    sock->_flags &= ~H2O_SOCKET_FLAG_IS_POLLED_FOR_WRITE;
                    changed = 1;
                }
            }
            if (changed) {
                int op = (sock->_flags & H2O_SOCKET_FLAG__EPOLL_IS_REGISTERED) != 0 ? EPOLL_CTL_MOD : EPOLL_CTL_ADD, ret;
                ev.data.ptr = sock;
                while ((ret = epoll_ctl(loop->ep, op, sock->fd, &ev)) != 0 && errno == EINTR)
                    ;
                if (ret != 0)
                    return -1;
                sock->_flags |= H2O_SOCKET_FLAG__EPOLL_IS_REGISTERED;
            }
        }
    }
    loop->super._statechanged.tail_ref = &loop->super._statechanged.head;

    return 0;
}

int evloop_do_proceed(h2o_evloop_t *_loop)
{
    struct st_h2o_evloop_epoll_t *loop = (struct st_h2o_evloop_epoll_t*)_loop;
    struct epoll_event events[256];
    int nevents, i;

    /* collect (and update) status */
    if (update_status(loop) != 0)
        return -1;

    /* poll */
    nevents = epoll_wait(loop->ep, events, sizeof(events) / sizeof(events[0]), get_max_wait(&loop->super));
    update_now(&loop->super);
    if (nevents == -1)
        return -1;

    /* update readable flags, perform writes */
    for (i = 0; i != nevents; ++i) {
        struct st_h2o_evloop_socket_t *sock = events[i].data.ptr;
        if ((events[i].events & EPOLLIN) != 0) {
            if (sock->_flags != H2O_SOCKET_FLAG_IS_DISPOSED) {
                sock->_flags |= H2O_SOCKET_FLAG_IS_READ_READY;
                link_to_pending(sock);
            }
        }
        if ((events[i].events & EPOLLOUT) != 0) {
            if (sock->_flags != H2O_SOCKET_FLAG_IS_DISPOSED) {
                write_pending(sock);
            }
        }
    }

    return 0;
}

static void evloop_do_on_socket_create(struct st_h2o_evloop_socket_t *sock)
{
}

static void evloop_do_on_socket_close(struct st_h2o_evloop_socket_t *sock)
{
}

h2o_evloop_t *h2o_evloop_create(void)
{
    struct st_h2o_evloop_epoll_t *loop = (struct st_h2o_evloop_epoll_t*)create_evloop(sizeof(*loop));

    loop->ep = epoll_create(10);

    return &loop->super;
}
