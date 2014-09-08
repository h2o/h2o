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
#include <ws2tcpip.h>
#include <khash.h>
#include <stdio.h>
#undef FD_SETSIZE
#define FD_SETSIZE 256

#if 0
# define DEBUG_LOG(...) fprintf(stderr, __VA_ARGS__)
#else
# define DEBUG_LOG(...)
#endif

KHASH_MAP_INIT_INT(h2o_sock, h2o_socket_t*);

struct st_h2o_socket_loop_select_t {
    h2o_socket_loop_t super;
    khash_t(h2o_sock)* socks;
    fd_set readfds, writefds;
};

static void update_fdset(struct st_h2o_socket_loop_select_t *loop)
{
    khash_t(h2o_sock)* h;
    khint_t k;

    h = loop->socks;

    while (loop->super._statechanged.head != NULL) {
        /* detach the top */
        h2o_socket_t *sock = loop->super._statechanged.head;
        loop->super._statechanged.head = sock->_next_statechanged;
        sock->_next_statechanged = sock;
        /* update the state */
        k = kh_get(h2o_sock, h, sock->fd);
        if ((sock->_flags & H2O_SOCKET_FLAG_IS_DISPOSED) != 0) {
            if (k != kh_end(h))
                kh_del(h2o_sock, h, k);
            free(sock);
        } else {
            if (k == kh_end(h)) {
                int ret;
                k = kh_put(h2o_sock, h, sock->fd, &ret);
                kh_value(h, k) = sock;
            }
            if (h2o_socket_is_reading(sock)) {
                DEBUG_LOG("setting READ for fd: %d\n", sock->fd);
                FD_SET(sock->fd, &loop->readfds);
                sock->_flags |= H2O_SOCKET_FLAG_IS_POLLED_FOR_READ;
            } else {
                DEBUG_LOG("clearing READ for fd: %d\n", sock->fd);
                //FD_CLR(sock->fd, &loop->readfds);
                sock->_flags &= ~H2O_SOCKET_FLAG_IS_POLLED_FOR_READ;
            }
            if (h2o_socket_is_writing(sock) && sock->_wreq.cnt != 0) {
                DEBUG_LOG("setting WRITE for fd: %d\n", sock->fd);
                FD_SET(sock->fd, &loop->writefds);
                sock->_flags |= H2O_SOCKET_FLAG_IS_POLLED_FOR_WRITE;
            } else {
                DEBUG_LOG("clearing WRITE for fd: %d\n", sock->fd);
                //FD_CLR(sock->fd, &loop->writefds);
                sock->_flags &= ~H2O_SOCKET_FLAG_IS_POLLED_FOR_WRITE;
            }
        }
    }
    loop->super._statechanged.tail_ref = &loop->super._statechanged.head;
}

static int proceed(h2o_socket_loop_t *_loop, uint64_t wake_at)
{
    struct st_h2o_socket_loop_select_t *loop = (struct st_h2o_socket_loop_select_t*)_loop;
    fd_set rfds, wfds;
    struct timeval timeout;
    int fd, ret;
    uint64_t max_wait_millis;
    khash_t(h2o_sock)* h;
    khint_t k;

    /* update status */
    update_fdset(loop);

    h = loop->socks;

    /* call select */
    do {
        /* calc timeout */
        update_now(&loop->super);
        max_wait_millis = wake_at - loop->super.now;
        if (max_wait_millis > INT32_MAX)
            max_wait_millis = INT32_MAX;
        timeout.tv_sec = max_wait_millis / 1000;
        timeout.tv_usec = max_wait_millis % 1000 * 1000;
        /* set fds */
        memcpy(&rfds, &loop->readfds, sizeof(rfds));
        memcpy(&wfds, &loop->writefds, sizeof(wfds));
        /* call */
        ret = select(0, &rfds, &wfds, NULL, &timeout);
    } while (ret == -1 && WSAGetLastError() == WSAEINTR);
    if (ret == -1)
        return -1;
    DEBUG_LOG("select returned: %d, %d\n", ret, WSAGetLastError());

    update_now(&loop->super);

    /* update readable flags, perform writes */
    if (ret > 0) {
        for (k = kh_begin(h); k != kh_end(h); ++k) {
            if (!kh_exist(h, k))
                continue;
            h2o_socket_t* sock = kh_value(h, k);
            fd = sock->fd;

            /* set read_ready flag before calling the write cb, since app. code invoked by hte latter may close the socket, clearing the former flag */
            if (FD_ISSET(fd, &rfds)) {
                assert(sock != NULL);
                if (sock->_flags != H2O_SOCKET_FLAG_IS_DISPOSED) {
                    sock->_flags |= H2O_SOCKET_FLAG_IS_READ_READY;
                    h2o_socket__link_to_pending(sock);
                    DEBUG_LOG("added fd %d as read_ready\n", fd);
                }
            }
            if (FD_ISSET(fd, &wfds)) {
                assert(sock != NULL);
                if (sock->_flags != H2O_SOCKET_FLAG_IS_DISPOSED) {
                    DEBUG_LOG("handling pending writes on fd %d\n", fd);
                    printf("status = %x\n", sock->_flags);
                    h2o_socket__write_pending(sock);
                }
            }
        }
    }

    return 0;
}

static void on_create(h2o_socket_t *sock)
{
}

static void on_close(h2o_socket_t *sock)
{
    struct st_h2o_socket_loop_select_t *loop = (struct st_h2o_socket_loop_select_t*)sock->loop;
    DEBUG_LOG("clearing READ/WRITE for fd: %d\n", sock->fd);
    FD_CLR(sock->fd, &loop->readfds);
    FD_CLR(sock->fd, &loop->writefds);
}

h2o_socket_loop_t *h2o_socket_loop_create(void)
{
    struct st_h2o_socket_loop_select_t *loop = (struct st_h2o_socket_loop_select_t*)create_socket_loop(
            sizeof(*loop),
            proceed,
            on_create,
            on_close);

    loop->socks = kh_init(h2o_sock);
    FD_ZERO(&loop->readfds);
    FD_ZERO(&loop->writefds);
    return &loop->super;
}
