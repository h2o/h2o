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
#include <stdio.h>
#include <sys/select.h>

#if 0
#define DEBUG_LOG(...) fprintf(stderr, __VA_ARGS__)
#else
#define DEBUG_LOG(...)
#endif

struct st_h2o_evloop_select_t {
    h2o_evloop_t super;
    fd_set readfds, writefds;
    int max_fd;
    struct st_h2o_evloop_socket_t *socks[FD_SETSIZE];
};

static void update_fdset(struct st_h2o_evloop_select_t *loop)
{
    while (loop->super._statechanged.head != NULL) {
        /* detach the top */
        struct st_h2o_evloop_socket_t *sock = loop->super._statechanged.head;
        loop->super._statechanged.head = sock->_next_statechanged;
        sock->_next_statechanged = sock;
        /* update the state */
        if ((sock->_flags & H2O_SOCKET_FLAG_IS_DISPOSED) != 0) {
            if (sock->fd != -1) {
                assert(loop->socks[sock->fd] == sock);
                loop->socks[sock->fd] = NULL;
            }
            free(sock);
        } else {
            if (loop->socks[sock->fd] == NULL) {
                loop->socks[sock->fd] = sock;
            } else {
                assert(loop->socks[sock->fd] == sock);
            }
            if (h2o_socket_is_reading(&sock->super)) {
                DEBUG_LOG("setting READ for fd: %d\n", sock->fd);
                FD_SET(sock->fd, &loop->readfds);
                sock->_flags |= H2O_SOCKET_FLAG_IS_POLLED_FOR_READ;
            } else {
                DEBUG_LOG("clearing READ for fd: %d\n", sock->fd);
                FD_CLR(sock->fd, &loop->readfds);
                sock->_flags &= ~H2O_SOCKET_FLAG_IS_POLLED_FOR_READ;
            }
            if (h2o_socket_is_writing(&sock->super) &&
                (sock->_wreq.cnt != 0 || (sock->_flags & H2O_SOCKET_FLAG_IS_CONNECTING) != 0)) {
                DEBUG_LOG("setting WRITE for fd: %d\n", sock->fd);
                FD_SET(sock->fd, &loop->writefds);
                sock->_flags |= H2O_SOCKET_FLAG_IS_POLLED_FOR_WRITE;
            } else {
                DEBUG_LOG("clearing WRITE for fd: %d\n", sock->fd);
                FD_CLR(sock->fd, &loop->writefds);
                sock->_flags &= ~H2O_SOCKET_FLAG_IS_POLLED_FOR_WRITE;
            }
        }
    }
    loop->super._statechanged.tail_ref = &loop->super._statechanged.head;
}

int evloop_do_proceed(h2o_evloop_t *_loop)
{
    struct st_h2o_evloop_select_t *loop = (struct st_h2o_evloop_select_t *)_loop;
    fd_set rfds, wfds;
    int32_t max_wait;
    struct timeval timeout;
    int fd, ret;

    /* update status */
    update_fdset(loop);

    /* calc timeout */
    max_wait = get_max_wait(&loop->super);
    timeout.tv_sec = max_wait / 1000;
    timeout.tv_usec = max_wait % 1000 * 1000;
    /* set fds */
    memcpy(&rfds, &loop->readfds, sizeof(rfds));
    memcpy(&wfds, &loop->writefds, sizeof(wfds));
    /* call */
    ret = select(loop->max_fd + 1, &rfds, &wfds, NULL, &timeout);
    update_now(&loop->super);
    if (ret == -1)
        return -1;
    DEBUG_LOG("select returned: %d\n", ret);

    /* update readable flags, perform writes */
    if (ret > 0) {
        for (fd = 0; fd <= loop->max_fd; ++fd) {
            /* set read_ready flag before calling the write cb, since app. code invoked by the latter may close the socket, clearing
             * the former flag */
            if (FD_ISSET(fd, &rfds)) {
                struct st_h2o_evloop_socket_t *sock = loop->socks[fd];
                assert(sock != NULL);
                if (sock->_flags != H2O_SOCKET_FLAG_IS_DISPOSED) {
                    sock->_flags |= H2O_SOCKET_FLAG_IS_READ_READY;
                    link_to_pending(sock);
                    DEBUG_LOG("added fd %d as read_ready\n", fd);
                }
            }
            if (FD_ISSET(fd, &wfds)) {
                struct st_h2o_evloop_socket_t *sock = loop->socks[fd];
                assert(sock != NULL);
                if (sock->_flags != H2O_SOCKET_FLAG_IS_DISPOSED) {
                    DEBUG_LOG("handling pending writes on fd %d\n", fd);
                    write_pending(loop->socks[fd]);
                }
            }
        }
    }

    return 0;
}

static void evloop_do_on_socket_create(struct st_h2o_evloop_socket_t *sock)
{
    struct st_h2o_evloop_select_t *loop = (struct st_h2o_evloop_select_t *)sock->loop;

    if (loop->max_fd < sock->fd)
        loop->max_fd = sock->fd;

    if (loop->socks[sock->fd] != NULL) {
        assert(loop->socks[sock->fd]->_flags == H2O_SOCKET_FLAG_IS_DISPOSED);
    }
    assert(!FD_ISSET(sock->fd, &loop->readfds));
    assert(!FD_ISSET(sock->fd, &loop->writefds));
}

static void evloop_do_on_socket_close(struct st_h2o_evloop_socket_t *sock)
{
    struct st_h2o_evloop_select_t *loop = (struct st_h2o_evloop_select_t *)sock->loop;
    if (sock->fd == -1)
        return;
    if (loop->socks[sock->fd] == NULL)
        return;
    DEBUG_LOG("clearing READ/WRITE for fd: %d\n", sock->fd);
    FD_CLR(sock->fd, &loop->readfds);
    FD_CLR(sock->fd, &loop->writefds);
}

static void evloop_do_on_socket_export(struct st_h2o_evloop_socket_t *sock)
{
    struct st_h2o_evloop_select_t *loop = (struct st_h2o_evloop_select_t *)sock->loop;
    evloop_do_on_socket_close(sock);
    loop->socks[sock->fd] = NULL;
}

h2o_evloop_t *h2o_evloop_create(void)
{
    struct st_h2o_evloop_select_t *loop = (struct st_h2o_evloop_select_t *)create_evloop(sizeof(*loop));
    return &loop->super;
}
