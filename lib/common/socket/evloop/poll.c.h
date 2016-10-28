/*
 * Copyright (c) 2014,2015 DeNA Co., Ltd., Kazuho Oku
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
#include <stdio.h>
#include <poll.h>

#if 0
#define DEBUG_LOG(...) fprintf(stderr, __VA_ARGS__)
#else
#define DEBUG_LOG(...)
#endif

struct st_h2o_evloop_poll_t {
    h2o_evloop_t super;
    H2O_VECTOR(struct st_h2o_evloop_socket_t *) socks;
};

static void update_socks(struct st_h2o_evloop_poll_t *loop)
{
    /* update loop->socks */
    while (loop->super._statechanged.head != NULL) {
        /* detach the top */
        struct st_h2o_evloop_socket_t *sock = loop->super._statechanged.head;
        loop->super._statechanged.head = sock->_next_statechanged;
        sock->_next_statechanged = sock;
        /* update the state */
        if ((sock->_flags & H2O_SOCKET_FLAG_IS_DISPOSED) != 0) {
            assert(sock->fd == -1);
            free(sock);
        } else {
            assert(sock->fd < loop->socks.size);
            if (loop->socks.entries[sock->fd] == NULL) {
                loop->socks.entries[sock->fd] = sock;
            } else {
                assert(loop->socks.entries[sock->fd] == sock);
            }
            if (h2o_socket_is_reading(&sock->super)) {
                DEBUG_LOG("setting READ for fd: %d\n", sock->fd);
                sock->_flags |= H2O_SOCKET_FLAG_IS_POLLED_FOR_READ;
            } else {
                DEBUG_LOG("clearing READ for fd: %d\n", sock->fd);
                sock->_flags &= ~H2O_SOCKET_FLAG_IS_POLLED_FOR_READ;
            }
            if (h2o_socket_is_writing(&sock->super)) {
                DEBUG_LOG("setting WRITE for fd: %d\n", sock->fd);
                sock->_flags |= H2O_SOCKET_FLAG_IS_POLLED_FOR_WRITE;
            } else {
                DEBUG_LOG("clearing WRITE for fd: %d\n", sock->fd);
                sock->_flags &= ~H2O_SOCKET_FLAG_IS_POLLED_FOR_WRITE;
            }
        }
    }
    loop->super._statechanged.tail_ref = &loop->super._statechanged.head;
}

int evloop_do_proceed(h2o_evloop_t *_loop, int32_t max_wait)
{
    struct st_h2o_evloop_poll_t *loop = (struct st_h2o_evloop_poll_t *)_loop;
    H2O_VECTOR(struct pollfd) pollfds = {NULL};
    int fd, ret;

    /* update status */
    update_socks(loop);

    /* build list of fds to be polled */
    for (fd = 0; fd != loop->socks.size; ++fd) {
        struct st_h2o_evloop_socket_t *sock = loop->socks.entries[fd];
        if (sock == NULL)
            continue;
        assert(fd == sock->fd);
        if ((sock->_flags & (H2O_SOCKET_FLAG_IS_POLLED_FOR_READ | H2O_SOCKET_FLAG_IS_POLLED_FOR_WRITE)) != 0) {
            h2o_vector_reserve(NULL, &pollfds, pollfds.size + 1);
            struct pollfd *slot = pollfds.entries + pollfds.size++;
            slot->fd = fd;
            slot->events = 0;
            slot->revents = 0;
            if ((sock->_flags & H2O_SOCKET_FLAG_IS_POLLED_FOR_READ) != 0)
                slot->events |= POLLIN;
            if ((sock->_flags & H2O_SOCKET_FLAG_IS_POLLED_FOR_WRITE) != 0)
                slot->events |= POLLOUT;
        }
    }

    /* call */
    max_wait = adjust_max_wait(&loop->super, max_wait);
    ret = poll(pollfds.entries, (nfds_t)pollfds.size, max_wait);
    update_now(&loop->super);
    if (ret == -1)
        goto Exit;
    DEBUG_LOG("poll returned: %d\n", ret);

    /* update readable flags, perform writes */
    if (ret > 0) {
        size_t i;
        h2o_sliding_counter_start(&loop->super.exec_time_counter, loop->super._now);
        for (i = 0; i != pollfds.size; ++i) {
            /* set read_ready flag before calling the write cb, since app. code invoked by the latter may close the socket, clearing
             * the former flag */
            if ((pollfds.entries[i].revents & POLLIN) != 0) {
                struct st_h2o_evloop_socket_t *sock = loop->socks.entries[pollfds.entries[i].fd];
                assert(sock != NULL);
                assert(sock->fd == pollfds.entries[i].fd);
                if (sock->_flags != H2O_SOCKET_FLAG_IS_DISPOSED) {
                    sock->_flags |= H2O_SOCKET_FLAG_IS_READ_READY;
                    link_to_pending(sock);
                    DEBUG_LOG("added fd %d as read_ready\n", sock->fd);
                }
            }
            if ((pollfds.entries[i].revents & POLLOUT) != 0) {
                struct st_h2o_evloop_socket_t *sock = loop->socks.entries[pollfds.entries[i].fd];
                assert(sock != NULL);
                assert(sock->fd == pollfds.entries[i].fd);
                if (sock->_flags != H2O_SOCKET_FLAG_IS_DISPOSED) {
                    DEBUG_LOG("handling pending writes on fd %d\n", fd);
                    write_pending(sock);
                }
            }
        }
        ret = 0;
    }

Exit:
    free(pollfds.entries);
    return ret;
}

static void evloop_do_on_socket_create(struct st_h2o_evloop_socket_t *sock)
{
    struct st_h2o_evloop_poll_t *loop = (struct st_h2o_evloop_poll_t *)sock->loop;

    if (sock->fd >= loop->socks.size) {
        h2o_vector_reserve(NULL, &loop->socks, sock->fd + 1);
        memset(loop->socks.entries + loop->socks.size, 0, (sock->fd + 1 - loop->socks.size) * sizeof(loop->socks.entries[0]));
        loop->socks.size = sock->fd + 1;
    }

    if (loop->socks.entries[sock->fd] != NULL)
        assert(loop->socks.entries[sock->fd]->_flags == H2O_SOCKET_FLAG_IS_DISPOSED);
}

static void evloop_do_on_socket_close(struct st_h2o_evloop_socket_t *sock)
{
    struct st_h2o_evloop_poll_t *loop = (struct st_h2o_evloop_poll_t *)sock->loop;

    if (sock->fd != -1)
        loop->socks.entries[sock->fd] = NULL;
}

static void evloop_do_on_socket_export(struct st_h2o_evloop_socket_t *sock)
{
    struct st_h2o_evloop_poll_t *loop = (struct st_h2o_evloop_poll_t *)sock->loop;
    evloop_do_on_socket_close(sock);
    loop->socks.entries[sock->fd] = NULL;
}

h2o_evloop_t *h2o_evloop_create(void)
{
    struct st_h2o_evloop_poll_t *loop = (struct st_h2o_evloop_poll_t *)create_evloop(sizeof(*loop));
    return &loop->super;
}
