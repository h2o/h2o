/*
 * Copyright (c) 2015 DeNA Co., Ltd.
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
#include <fcntl.h>
#ifdef __linux__
#include <sys/eventfd.h>
#endif
#include "cloexec.h"

pthread_mutex_t cloexec_mutex = PTHREAD_MUTEX_INITIALIZER;

static int set_cloexec(int fd)
{
    return fcntl(fd, F_SETFD, FD_CLOEXEC) != -1 ? 0 : -1;
}

/*
 * note: the socket must be in non-blocking mode, or the call might block while the mutex is being locked
 */
int cloexec_accept(int socket, struct sockaddr *addr, socklen_t *addrlen)
{
    int fd = -1;
    pthread_mutex_lock(&cloexec_mutex);

    if ((fd = accept(socket, addr, addrlen)) == -1)
        goto Exit;
    if (set_cloexec(fd) != 0) {
        close(fd);
        fd = -1;
        goto Exit;
    }

Exit:
    pthread_mutex_unlock(&cloexec_mutex);
    return fd;
}

int cloexec_pipe(int fds[2])
{
#if defined(__linux__) && LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 27)
    /* pipe2() was added to Linux in version 2.6.27 */
    return pipe2(fds, O_CLOEXEC);
#else
    int ret = -1;
    pthread_mutex_lock(&cloexec_mutex);

    if (pipe(fds) != 0)
        goto Exit;
    if (set_cloexec(fds[0]) != 0 || set_cloexec(fds[1]) != 0)
        goto Exit;
    ret = 0;

Exit:
    pthread_mutex_unlock(&cloexec_mutex);
    return ret;
#endif
}

int cloexec_nblock_eventfd(void)
{
#if defined(__linux__) && LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 27)
    /**
     * eventfd() is available on Linux since kernel 2.6.22.
     * In Linux up to version 2.6.26, the flags argument is unused, and must be specified as zero
     */
    return eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
#else
    return -1;
#endif
}

int cloexec_socket(int domain, int type, int protocol)
{
#if defined(__linux__) && LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 27)
    return socket(domain, type | SOCK_CLOEXEC, protocol);
#else
    int fd = -1;
    pthread_mutex_lock(&cloexec_mutex);

    if ((fd = socket(domain, type, protocol)) == -1)
        goto Exit;
    if (set_cloexec(fd) != 0) {
        close(fd);
        fd = -1;
        goto Exit;
    }

Exit:
    pthread_mutex_unlock(&cloexec_mutex);
    return fd;
#endif
}
