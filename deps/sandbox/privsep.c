/* Some stuff lifed from OpenSSH here. */
/*
 * Copyright (c) 2003 Can Erkin Acar
 * Copyright (c) 2003 Anil Madhavapeddy <anil@recoil.org>
 * Copyright (c) 2019 Christian S.J. Peron
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#include <sys/types.h>
#include <sys/time.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/uio.h>

#include <linux/un.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <fcntl.h>
#include <signal.h>
#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <stdarg.h>

#include "privsep.h"

volatile pid_t child_pid = -1;
int priv_fd = -1;
int priv_sep_on = 0;

volatile sig_atomic_t gotsig_chld = 0;

/* Proto-types */
static void sig_pass_to_chld(int);
static void sig_chld(int);

static void sig_chld(int sig)
{

    gotsig_chld = 1;
}

/* If priv parent gets a TERM or HUP, pass it through to child instead */
static void sig_pass_to_chld(int sig)
{
    int oerrno;

    oerrno = errno;
    if (child_pid != -1)
        (void) kill(child_pid, sig);
    errno = oerrno;
}

static void priv_deliver_neverbleed_sock(int sock)
{
    struct sockaddr_un sun;
    int error, nb_sock;

    priv_must_read(sock, &sun, sizeof(struct sockaddr_un));
#ifdef SOCK_CLOEXEC
    nb_sock = socket(PF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
#else
    nb_sock = socket(PF_UNIX, SOCK_STREAM, 0);
#endif
    if (sock == -1) {
        error = errno;
        priv_must_write(nb_sock, &error, sizeof(int));
        return;
    }
    while (connect(nb_sock, (void *)&sun, sizeof(sun)) != 0) {
        if (errno != EINTR) {
            error = errno;
            priv_must_write(sock, &error, sizeof(int));
            return;
        }
    }
    error = 0;
    priv_must_write(sock, &error, sizeof(int));
    priv_send_fd(sock, nb_sock);
}

int priv_init(void)
{
    int i, socks[2], cmd;

    fprintf(stderr, "[sandbox] creating privileged process\n");
    for (i = 1; i < NSIG; i++)
        signal(i, SIG_DFL);
    if (socketpair(AF_LOCAL, SOCK_STREAM, PF_UNSPEC, socks) == -1) {
        err(1, "socketpair failed");
    }
    child_pid = fork();
    if (child_pid == -1) {
        err(1, "fork failed");
    }
    if (child_pid == 0) {
        (void) close(socks[0]);
        priv_fd = socks[1];
        priv_sep_on = 1;
        return (0);
    }
    close(socks[1]);
    while (!gotsig_chld) {
        if (priv_may_read(socks[0], &cmd, sizeof(int)))
            break;
        switch (cmd) {
        case PRIV_NEVERBLEED_SOCK:
            priv_deliver_neverbleed_sock(socks[0]);
            break;
        default:
            (void) fprintf(stderr, "got request for unknown priv\n");
        }
    }
    _exit(1);
}

/*
 * priv_may_read():
 *
 * Read all data or return 1 for error.
 */
int priv_may_read(int fd, void *buf, size_t n)
{
    ssize_t res, pos = 0;
    char *s = buf;

    while (n > pos) {
        res = read(fd, s + pos, n - pos);
        switch (res) {
        case -1:
            if (errno == EINTR || errno == EAGAIN)
                continue;
        case 0:
            return (1);
        default:
            pos += res;
        }
    }
    return (0);
}

/*
 * priv_must_read():
 *
 * Read data with the assertion that it all must come through, or
 * else abort the process.  Based on atomicio() from openssh.
 */
void priv_must_read(int fd, void *buf, size_t n)
{
    char *s = buf;
    ssize_t res, pos = 0;

    while (n > pos) {
        res = read(fd, s + pos, n - pos);
        switch (res) {
        case -1:
            if (errno == EINTR || errno == EAGAIN)
                continue;
        case 0:
            _exit(0);
        default:
            pos += res;
        }
    }
}

/*
 * priv_must_write():
 *
 * Write data with the assertion that it all has to be written, or
 * else abort the process.  Based on atomicio() from openssh.
 */
void priv_must_write(int fd, void *buf, size_t n)
{
    char *s = buf;
    ssize_t res, pos = 0;

    while (n > pos) {
        res = write(fd, s + pos, n - pos);
        switch (res) {
        case -1:
            if (errno == EINTR || errno == EAGAIN)
                continue;
        case 0:
            _exit(0);
        default:
            pos += res;
        }
    }
}

/*
 * Send a file descriptor to non-privileged process
 */
void priv_send_fd(int sock, int fd)
{
    struct msghdr msg;
    union {
        struct cmsghdr hdr;
        char buf[CMSG_SPACE(sizeof(int))];
    } cmsgbuf;
    struct cmsghdr *cmsg;
    struct iovec vec;
    int result = 0;
    ssize_t n;

    memset(&msg, 0, sizeof(msg));
    if (fd >= 0) {
        msg.msg_control = (caddr_t)&cmsgbuf.buf;
        msg.msg_controllen = sizeof(cmsgbuf.buf);
        cmsg = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_len = CMSG_LEN(sizeof(int));
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        *CMSG_DATA(cmsg) = fd;
    } else {
        result = errno;
    }
    vec.iov_base = &result;
    vec.iov_len = sizeof(int);
    msg.msg_iov = &vec;
    msg.msg_iovlen = 1;
    if ((n = sendmsg(sock, &msg, 0)) == -1) 
        fprintf(stderr, "sendmsg: %s\n", strerror(errno));
    if (n != sizeof(int))
        fprintf(stderr, "sendmsg: %s\n", strerror(errno));
}

/*
 * Recieve a file descriptor from the privileged process.
 */
int priv_receive_fd(int sock)
{
    struct msghdr msg;
    union {
        struct cmsghdr hdr;
        char buf[CMSG_SPACE(sizeof(int))];
    } cmsgbuf;
    struct cmsghdr *cmsg;
    struct iovec vec;
    ssize_t n;
    int result;
    int fd;

    memset(&msg, 0, sizeof(msg));
    vec.iov_base = &result;
    vec.iov_len = sizeof(int);
    msg.msg_iov = &vec;
    msg.msg_iovlen = 1;
    msg.msg_control = &cmsgbuf.buf;
    msg.msg_controllen = sizeof(cmsgbuf.buf);
    if ((n = recvmsg(sock, &msg, 0)) == -1)
        fprintf(stderr, "recvmsg: %s\n", strerror(errno));
    if (n != sizeof(int))
        fprintf(stderr, "recvmsg: %s\n", strerror(errno));
    if (result == 0) {
        cmsg = CMSG_FIRSTHDR(&msg);
        if (cmsg == NULL) {
            fprintf(stderr, "%s: no message header", __func__);
            return -1;
        }
        if (cmsg->cmsg_type != SCM_RIGHTS)
            (void) fprintf(stderr, "%s: expected type %d got %d", __func__,
                SCM_RIGHTS, cmsg->cmsg_type);
        fd = (*CMSG_DATA(cmsg));
        return (fd);
    } else {
        errno = result;
        return (-1);
    }
}

/**
 * Operations for the sandboxed process.
 **/

/*
 * privsep_get_neverbleed_sock()
 *
 * Receive a connected socket (connected to the neverbleed process) so
 * we do not have to allow socket(2) and connect(2).
 */
int privsep_get_neverbleed_sock(struct sockaddr_un *sun)
{
    int priv, sock, error;

    priv = PRIV_NEVERBLEED_SOCK;
    priv_must_write(priv_fd, &priv, sizeof(int));
    priv_must_write(priv_fd, sun, sizeof(struct sockaddr_un));
    priv_must_read(priv_fd, &error, sizeof(int));
    if (error != 0) {
        errno = error;
        return (-1);
    }
    sock = priv_receive_fd(priv_fd);
    return (sock);
}
