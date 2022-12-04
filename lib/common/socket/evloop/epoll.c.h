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
#define DEBUG_LOG(...) h2o_error_printf(__VA_ARGS__)
#else
#define DEBUG_LOG(...)
#endif

struct st_h2o_evloop_epoll_t {
    h2o_evloop_t super;
    int ep;
};

static int change_epoll_mode(struct st_h2o_evloop_socket_t *sock, uint32_t events)
{
    struct st_h2o_evloop_epoll_t *loop = (void *)sock->loop;
    struct epoll_event ev = {.events = events, .data = {.ptr = sock}};
    int op, ret;

    if ((sock->_flags & H2O_SOCKET_FLAG__EPOLL_IS_REGISTERED) == 0) {
        op = EPOLL_CTL_ADD;
        sock->_flags |= H2O_SOCKET_FLAG__EPOLL_IS_REGISTERED;
    } else {
        op = EPOLL_CTL_MOD;
    }
    while ((ret = epoll_ctl(loop->ep, op, sock->fd, &ev)) != 0 && errno == EINTR)
        ;
    return ret == 0;
}

static int delete_from_epoll_on_close(struct st_h2o_evloop_socket_t *sock)
{
    struct st_h2o_evloop_epoll_t *loop = (void *)sock->loop;
    int ret;

    if ((sock->_flags & H2O_SOCKET_FLAG__EPOLL_IS_REGISTERED) == 0)
        return 1;
    while ((ret = epoll_ctl(loop->ep, EPOLL_CTL_DEL, sock->fd, NULL)) != 0 && errno == EINTR)
        ;
    return ret == 0;
}

static int handle_zerocopy_notification(struct st_h2o_evloop_socket_t *sock)
{
#if H2O_USE_MSG_ZEROCOPY
    int made_progress = 0;

    /* Read the completion events and release buffers. `recvmmsg` with two entries is used as a cheap way of making sure that all
     * notifications are read from the queue (this requirement comes from the us eof edge trigger once the socket is closed). */
    while (1) {
        struct mmsghdr msg[2];
        char cbuf[2][CMSG_SPACE(sizeof(struct sock_extended_err))];
        for (size_t i = 0; i < PTLS_ELEMENTSOF(msg); ++i)
            msg[i] = (struct mmsghdr){.msg_hdr = {.msg_control = cbuf[i], .msg_controllen = sizeof(cbuf[i])}};
        struct timespec timeout = {0};

        ssize_t ret;
        while ((ret = recvmmsg(sock->fd, msg, PTLS_ELEMENTSOF(msg), MSG_ERRQUEUE, &timeout)) == -1 && errno == EINTR)
            ;
        if (ret == -1)
            break;

        for (size_t i = 0; i < ret; ++i) {
            struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg[i].msg_hdr);
            if (cmsg != NULL) {
                struct sock_extended_err *ee = (void *)CMSG_DATA(cmsg);
                if (ee->ee_errno == 0 && ee->ee_origin == SO_EE_ORIGIN_ZEROCOPY) {
                    /* for each range being obtained, convert the wrapped value to 64-bit, then release the memory */
                    for (uint32_t c32 = ee->ee_info; c32 <= ee->ee_data; ++c32) {
                        uint64_t c64 = (sock->super._zerocopy->first_counter & 0xffffffff00000000) | c32;
                        if (c64 < sock->super._zerocopy->first_counter)
                            c64 += 0x100000000;
                        void *p = zerocopy_buffers_release(sock->super._zerocopy, c64);
                        if (p != NULL) {
                            if (sock->super.ssl != NULL && p == sock->super.ssl->output.buf.base) {
                                /* buffer being released from zerocopy still has some pending data to be written */
                                assert(sock->super.ssl->output.zerocopy_owned);
                                sock->super.ssl->output.zerocopy_owned = 0;
                            } else {
                                h2o_mem_free_recycle(&h2o_socket_zerocopy_buffer_allocator, p);
                            }
                            --h2o_socket_num_zerocopy_buffers_inflight;
                        }
                    }
                }
            }
            made_progress = 1;
        }

        /* partial read means that the notification queue has become empty */
        if (ret < PTLS_ELEMENTSOF(msg))
            break;
    }

    /* if the socket has been shut down and zerocopy buffer has become empty, link the socket so that it would be destroyed */
    if (made_progress && (sock->_flags & H2O_SOCKET_FLAG_IS_DISPOSED) != 0 && zerocopy_buffers_is_empty(sock->super._zerocopy))
        link_to_statechanged(sock);

    return made_progress;
#else
    return 0;
#endif
}

static int update_status(struct st_h2o_evloop_epoll_t *loop)
{
    while (loop->super._statechanged.head != NULL) {
        /* detach the top */
        struct st_h2o_evloop_socket_t *sock = loop->super._statechanged.head;
        loop->super._statechanged.head = sock->_next_statechanged;
        sock->_next_statechanged = sock;
        /* update the state */
        if ((sock->_flags & H2O_SOCKET_FLAG_IS_DISPOSED) != 0) {
            if (sock->super._zerocopy == NULL || zerocopy_buffers_is_empty(sock->super._zerocopy)) {
                /* Call close (2) and destroy, now that all zero copy buffers have been reclaimed. */
                if (sock->super._zerocopy != NULL) {
                    zerocopy_buffers_dispose(sock->super._zerocopy);
                    free(sock->super._zerocopy);
                }
                if (sock->fd != -1) {
                    if (!delete_from_epoll_on_close(sock))
                        h2o_error_printf("update_status: epoll(DEL) returned error %d (fd=%d)\n", errno, sock->fd);
                    close(sock->fd);
                }
                free(sock);
            }
        } else {
            uint32_t events = 0;
            int changed = 0;
            if (h2o_socket_is_reading(&sock->super)) {
                events |= EPOLLIN;
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
                events |= EPOLLOUT;
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
                if (!change_epoll_mode(sock, events))
                    return -1;
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

    if (nevents != 0) {
        h2o_sliding_counter_start(&loop->super.exec_time_nanosec_counter, loop->super._now_nanosec);
    }

    /* update readable flags, perform writes */
    for (i = 0; i != nevents; ++i) {
        struct st_h2o_evloop_socket_t *sock = events[i].data.ptr;
        int notified = 0;
        /* When receiving HUP (indicating reset) while the socket is polled neither for read nor write, unregister the socket from
         * epoll, otherwise epoll_wait() would continue raising the HUP event. This problem cannot be avoided by using edge trigger.
         * The application will eventually try to read or write to the socket and at that point close the socket, detecting that it
         * has become unusable. */
        if ((events[i].events & EPOLLHUP) != 0 &&
            (sock->_flags & (H2O_SOCKET_FLAG_IS_POLLED_FOR_READ | H2O_SOCKET_FLAG_IS_POLLED_FOR_WRITE)) == 0 &&
            !(sock->super._zerocopy != NULL && (sock->_flags & H2O_SOCKET_FLAG_IS_DISPOSED) != 0)) {
            assert((sock->_flags & H2O_SOCKET_FLAG__EPOLL_IS_REGISTERED) != 0);
            int ret;
            while ((ret = epoll_ctl(loop->ep, EPOLL_CTL_DEL, sock->fd, NULL)) != 0 && errno == EINTR)
                ;
            if (ret != 0)
                h2o_error_printf("failed to unregister socket (fd:%d) that raised HUP; errno=%d\n", sock->fd, errno);
            sock->_flags &= ~H2O_SOCKET_FLAG__EPOLL_IS_REGISTERED;
            notified = 1;
        }
        /* If the error event was a zerocopy notification, hide the error notification to application. Doing so is fine because
         * level-triggered interface is used while the socket is open. If there is another type of pending error event, it would be
         * notified once we run out of zerocopy notifications. */
        if ((events[i].events & EPOLLERR) != 0 && sock->super._zerocopy != NULL && handle_zerocopy_notification(sock)) {
            events[i].events &= ~EPOLLERR;
            notified = 1;
        }
        /* Handle read and write events. */
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
        /* Report events that could be notified, as that would help us debug issues. This mechanism is disabled once the socket is
         * closed, as there will be misfires due to the nature of edge triggers (race between us draining between events queued up).
         */
        if (!notified && (sock->_flags & H2O_SOCKET_FLAG_IS_DISPOSED) == 0) {
            static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
            static time_t last_reported = 0;
            time_t now = time(NULL);
            pthread_mutex_lock(&lock);
            if (last_reported + 60 < now) {
                last_reported = now;
                h2o_error_printf("ignoring epoll event (fd:%d,event:0x%x,flags:0x%x)\n", sock->fd, (int)events[i].events,
                                 sock->_flags);
            }
            pthread_mutex_unlock(&lock);
        }
    }

    return 0;
}

static void evloop_do_on_socket_create(struct st_h2o_evloop_socket_t *sock)
{
}

static int evloop_do_on_socket_close(struct st_h2o_evloop_socket_t *sock)
{
    int ret;

    /* Nothing to do if fd has been detached already. */
    if (sock->fd == -1)
        return 0;

    /* If zero copy is in action, disconnect using shutdown(). Then, poll the socket until all zero copy buffers are reclaimed, at
     * which point we dispose of the socket. Edge trigger is used, as in level trigger EPOLLHUP will be notified continuously. */
    if (sock->super._zerocopy != NULL && !zerocopy_buffers_is_empty(sock->super._zerocopy)) {
        while ((ret = shutdown(sock->fd, SHUT_RDWR)) == -1 && errno == EINTR)
            ;
        if (ret != 0 && errno != ENOTCONN)
            h2o_error_printf("socket_close: shutdown(SHUT_RDWR) failed; errno=%d, fd=%d\n", errno, sock->fd);
        if (!change_epoll_mode(sock, EPOLLET))
            h2o_fatal("socket_close: epoll_ctl(MOD) failed; errno=%d, fd=%d\n", errno, sock->fd);
        /* drain error notifications after registering the edge trigger, otherwise there's chance of stall */
        handle_zerocopy_notification(sock);
        return 1;
    }

    /* Unregister from epoll. */
    if (!delete_from_epoll_on_close(sock))
        h2o_error_printf("socket_close: epoll(DEL) returned error %d (fd=%d)\n", errno, sock->fd);

    return 0;
}

static void evloop_do_on_socket_export(struct st_h2o_evloop_socket_t *sock)
{
    if (!delete_from_epoll_on_close(sock))
        h2o_error_printf("socket_export: epoll(DEL) returned error %d (fd=%d)\n", errno, sock->fd);
}

static void evloop_do_dispose(h2o_evloop_t *_loop)
{
    struct st_h2o_evloop_epoll_t *loop = (struct st_h2o_evloop_epoll_t *)_loop;
    close(loop->ep);
}
h2o_evloop_t *h2o_evloop_create(void)
{
    struct st_h2o_evloop_epoll_t *loop = (struct st_h2o_evloop_epoll_t *)create_evloop(sizeof(*loop));

    if ((loop->ep = epoll_create1(EPOLL_CLOEXEC)) == -1) {
        char buf[128];
        h2o_fatal("h2o_evloop_create: epoll_create1 failed:%d:%s\n", errno, h2o_strerror_r(errno, buf, sizeof(buf)));
    }

    return &loop->super;
}
