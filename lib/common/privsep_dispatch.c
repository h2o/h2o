/*
 * Copyright (c) 2020 Christian S.J. Peron
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
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/wait.h>
#include <sys/un.h>

#include <err.h>
#include <stdio.h>
#include <grp.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <fcntl.h>
#include <pwd.h>
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>

#include "h2o.h"
#include "h2o/privsep.h"
#include "h2o/serverutil.h"
#include "h2o/memory.h" /* NB: for h2o_fatal */

int privsep_flags;
int privsep_global_sock;

static const char *neverbleed_sock_path;
const char *privsep_sock_path;

static void privsep_handle_dotime_r(privsep_worker_t *pswd)
{
    char tzbuf[H2O_TZ_BUF];
    time_t clock;
    struct tm gmt;
    int type, valid;

    bzero(tzbuf, sizeof(tzbuf));
    h2o_privsep_must_read(pswd->sock, &type, sizeof(type));
    h2o_privsep_must_read(pswd->sock, &clock, sizeof(clock));
    valid = 0;
    switch (type) {
    case PRIV_GMTIME:
        gmtime_r(&clock, &gmt);
        valid = 1;
        break;
    case PRIV_LOCALTIME:
        localtime_r(&clock, &gmt);
        valid = 1;
        break;
    default:
        warnx("%s: invalid type time specified", __func__);
        bzero(&gmt, sizeof(gmt));
        bzero(tzbuf, sizeof(tzbuf));
        valid = 0;
    }
    if (valid) {
        snprintf(tzbuf, sizeof(tzbuf), "%s", gmt.tm_zone);
    }
    h2o_privsep_must_write(pswd->sock, tzbuf, sizeof(tzbuf));
    gmt.tm_zone = NULL;
    h2o_privsep_must_write(pswd->sock, &gmt, sizeof(gmt));
}

static void privsep_handle_waitpid(privsep_worker_t *pswd)
{
    h2o_privsep_watpid_t args;
    int status, ecode;
    pid_t pid;

    h2o_privsep_must_read(pswd->sock, &args, sizeof(args));
    while (1) {
        status = 0;
        pid = waitpid(args.pid, &status, args.options);
        if (pid == -1 && errno == EINTR) {
            continue;
        }
        h2o_privsep_must_write(pswd->sock, &pid, sizeof(pid));
        ecode = errno;
        h2o_privsep_must_write(pswd->sock, &ecode, sizeof(ecode));
        h2o_privsep_must_write(pswd->sock, &status, sizeof(status));
        return;
    }
}

static void privsep_handle_fd_mapped_exec(privsep_worker_t *pswd)
{
    char *f, cmdbuf[H2O_CMD_BUF], **copy, **argv, *marshalled, **envp;
    int error_pipe[2], ecode, ret, k, maps_used;
    h2o_exec_context_t ec;
    extern char **environ;
    size_t msize;
    ssize_t cc;
    pid_t pid;

    /*
     * NB: add access control checks here. We will likely have a registration
     * function for the various files, hosts and executables we want to access
     * from within the sandbox.
     */
    h2o_privsep_must_read(pswd->sock, cmdbuf, H2O_CMD_BUF);
    /*
     * We are dealing with a potentially compromised process. Double chck the
     * data points coming from this process which controls how much memory we
     * are allocating et al.
     */
    h2o_privsep_must_read(pswd->sock, &msize, sizeof(msize));
    if (msize > 8192) {
        ecode = EOVERFLOW;
        h2o_privsep_must_write(pswd->sock, &ecode, sizeof(ecode));
        return;
    }
    marshalled = malloc(msize);
    if (marshalled == NULL) {
        ecode = ENOMEM;
        h2o_privsep_must_write(pswd->sock, &ecode, sizeof(ecode));
    }
    ecode = 0;
    h2o_privsep_must_write(pswd->sock, &ecode, sizeof(ecode));
    /*
     * Read the marshalled version of argv array so we can convert it to an in
     * memory array of pointers good for the exec(2) syscall.
     *
     * NB: we should be validating the commands/arguments that are passed long
     * here.
     */
    h2o_privsep_must_read(pswd->sock, marshalled, msize);
    argv = h2o_privsep_unmarshal_vec(marshalled, msize);
    if (argv == NULL) {
        pid = -1;
        ecode = ENOMEM;
        free(marshalled);
        h2o_privsep_must_write(pswd->sock, &pid, sizeof(pid));
        h2o_privsep_must_write(pswd->sock, &ecode, sizeof(ecode));
        return;
    }
    free(marshalled);
    /*
     * Read the file descriptors from the non-privileged process that the
     * caller would like overlayed on stdin, stdout and stderr. Once we
     * get them into this process, use dup2() to map them.
     */
    h2o_priv_init_exec_context(&ec);
    h2o_privsep_must_read(pswd->sock, &maps_used, sizeof(maps_used));
    ec.fdmaps = calloc(maps_used, sizeof(h2o_fd_mapping_t));
    h2o_privsep_must_read(pswd->sock, ec.fdmaps,
        maps_used * sizeof(h2o_fd_mapping_t));
    for (k = 0; k < maps_used; k++) {
        if (pipe(ec.fdmaps[k].pipefds) == -1) {
            h2o_fatal("pipe failed");
        }
        switch (ec.fdmaps[k].type) {
        case H2O_FDMAP_BASIC:
            break;
        case H2O_FDMAP_SEND_TO_PROC:
            ec.fdmaps[k].from = h2o_privsep_receive_fd(pswd->sock);
            close(ec.fdmaps[k].pipefds[0]);
            close(ec.fdmaps[k].pipefds[1]);
            break;
        case H2O_FDMAP_READ_FROM_PROC:
            h2o_privsep_send_fd(pswd->sock, ec.fdmaps[k].pipefds[0]);
            break;
        }
    }
    if (pipe2(error_pipe, O_CLOEXEC) == -1) {
        pid = -1;
        ecode = errno;
        h2o_privsep_must_write(pswd->sock, &pid, sizeof(pid));
        h2o_privsep_must_write(pswd->sock, &ecode, sizeof(ecode));
        return;
    }
    pid = fork();
    if (pid == -1) {
        ecode = errno;
        h2o_privsep_must_write(pswd->sock, &pid, sizeof(pid));
        h2o_privsep_must_write(pswd->sock, &ecode, sizeof(ecode));
        return;
    }
    if (pid == 0) {
        /*
         * Overlay the file descriptors per the mapping specification in the
         * the caller. h2o_read_command() has a different mapping specification
         * than the backtrace producer. I think we have captured all the use
         * cases for this feature.
         */
        for (k = 0; k < maps_used; k++) {
            switch (ec.fdmaps[k].type) {
            case H2O_FDMAP_BASIC:
                dup2(ec.fdmaps[k].from, ec.fdmaps[k].to);
                break;
            case H2O_FDMAP_SEND_TO_PROC:
                close(ec.fdmaps[k].to);
                dup2(ec.fdmaps[k].from, ec.fdmaps[k].to);
                break;
            case H2O_FDMAP_READ_FROM_PROC:
                close(ec.fdmaps[k].pipefds[0]);
                dup2(ec.fdmaps[k].pipefds[1], ec.fdmaps[k].to);
                break;
            }
        }
        envp = h2o_priv_gen_env();
        if (envp != NULL) {
            environ = envp;
        }
        (void) execvp(cmdbuf, argv);
        ecode = errno;
        (void) write(error_pipe[1], &ecode, sizeof(ecode));
        _exit(EX_SOFTWARE);
    }
    for (k = 0; k < maps_used; k++) {
        switch (ec.fdmaps[k].type) {
        case H2O_FDMAP_BASIC:
            break;
        case H2O_FDMAP_SEND_TO_PROC:
            close(ec.fdmaps[k].from);
            break;
        case H2O_FDMAP_READ_FROM_PROC:
            close(ec.fdmaps[k].pipefds[1]);
            /*
             * NB: do we need to close(pipefds[0] here too since we sent it
             * to the non-privilged process ?
             */
            break;
        }
    }
    /*
     * However the execution goes, we are done with the un-marshalled version
     * of the argv array. Iterate through each element freeing them and cleanup
     * the underlying array after that.
     */
    copy = argv;
    while ((f = *copy++)) {
        free(f);
    }
    free(argv);
    close(error_pipe[1]);
    while (1) {
        cc = read(error_pipe[0], &ecode, sizeof(ecode));
        if (cc == -1 && errno == EINTR) {
            continue;
        }
        /*
         * EOF on this file descriptor is what we want to see. It means that
         * the exec(2) was successful, and the file descriptor was closed as
         * as a result. If this is the case, break from the loop and deliver
         * the PID to the caller.
         */
        if (cc == 0) {
            break;
        }
        /*
         * If we received data, it was the child process informing us that the
         * exec(2) operation was not successful. Copy the error code and and
         * send it to the caller. Call waitpid(2) to collect the exit status
         * since it's invariant that the process is dead.
         */
        while (1) {
            ret = waitpid(pid, NULL, 0);
            if (ret == -1 && errno == EINTR) {
                continue;
            } else if (ret == -1) {
                ecode = errno;
            }
            break;
        }
        pid = -1;
        h2o_privsep_must_write(pswd->sock, &pid, sizeof(pid));
        h2o_privsep_must_write(pswd->sock, &ecode, sizeof(ecode));
        return;
    }
    ecode = 0;
    h2o_privsep_must_write(pswd->sock, &pid, sizeof(pid));
    h2o_privsep_must_write(pswd->sock, &ecode, sizeof(ecode));
}

static void privsep_msghdr_cleanup(struct msghdr *msg)
{
    struct iovec *iovp;
    int index;

    assert(msg != NULL);
    for (index = 0; index < msg->msg_iovlen; index++) {
        iovp = &msg->msg_iov[index];
        free(iovp->iov_base);
    }
    free(msg->msg_iov);
    free(msg->msg_name);
    free(msg->msg_control);
}

static void privsep_handle_sendmsg(privsep_worker_t *pswd)
{
    h2o_privsep_sendmsg_t args;
    int sock, ecode, index;
    struct iovec *iovp;
    struct msghdr msg;
    ssize_t cc;

    bzero(&msg, sizeof(msg));
    sock = h2o_privsep_receive_fd(pswd->sock);
    h2o_privsep_must_read(pswd->sock, &args, sizeof(args));
    msg.msg_namelen = args.msg_namelen;
    msg.msg_controllen = args.msg_controllen;
    msg.msg_iovlen = args.msg_iovlen;
    msg.msg_iov = calloc(msg.msg_iovlen, sizeof(*iovp));
    /* NB: XXX send ecode */
    for (index = 0; index < msg.msg_iovlen; index++) {
        iovp = &msg.msg_iov[index];
        h2o_privsep_must_read(pswd->sock, &iovp->iov_len, sizeof(iovp->iov_len));
        iovp->iov_base = calloc(1, iovp->iov_len);
        h2o_privsep_must_read(pswd->sock, iovp->iov_base, iovp->iov_len);
    }
    /*
     * msg.msg_flags is not used by sendmsg(2). We can just leave it as zero.
     */
    msg.msg_name = calloc(1, args.msg_namelen);
    if (msg.msg_name == NULL) {
        ecode = errno;
        h2o_privsep_must_write(pswd->sock, &ecode, sizeof(ecode));
        close(sock);
        return;
    }
    h2o_privsep_must_read(pswd->sock, msg.msg_name, args.msg_namelen);
    ecode = 0;
    h2o_privsep_must_write(pswd->sock, &ecode, sizeof(ecode));
    msg.msg_control = calloc(1, args.msg_controllen);
    if (msg.msg_name == NULL) {
        ecode = errno;
        h2o_privsep_must_write(pswd->sock, &ecode, sizeof(ecode));
        close(sock);
        return;
    }
    h2o_privsep_must_read(pswd->sock, msg.msg_control, args.msg_controllen);
    ecode = 0;
    h2o_privsep_must_write(pswd->sock, &ecode, sizeof(ecode));
    cc = sendmsg(sock, &msg, args.flags);
    h2o_privsep_must_write(pswd->sock, &cc, sizeof(cc));
    if (cc == -1) {
        ecode = errno;
        h2o_privsep_must_write(pswd->sock, &ecode, sizeof(ecode));
        close(sock);
    }
    ecode = 0;
    h2o_privsep_must_write(pswd->sock, &ecode, sizeof(ecode));
    privsep_msghdr_cleanup(&msg);
    close(sock);
}

static void privsep_handle_open_listener(privsep_worker_t *pswd)
{
    h2o_privsep_open_listener_t args;
    int sock, ecode;

    h2o_privsep_must_read(pswd->sock, &args, sizeof(args));
    sock = h2o_allpriv_open_listener(args.domain, args.type, args.protocol,
      &args.sas, args.addrlen, args.reuseport);
    if (sock == -1) {
        ecode = errno;
        h2o_privsep_must_write(pswd->sock, &ecode, sizeof(ecode));
        return;
    }
    ecode = 0;
    h2o_privsep_must_write(pswd->sock, &ecode, sizeof(ecode));
    h2o_privsep_send_fd(pswd->sock, sock);
    close(sock);
}

static void privsep_deliver_connected_sock(privsep_worker_t *pswd)
{
    int s_ret, s_errno, c_ret, c_errno, sock;
    struct sockaddr_storage saddr;
    struct iovec iov[8];
    socklen_t s;

    sock = pswd->sock;
    /*
     * NB: ACL check from whatever was specified in the configuration.
     * This could probably a generic interface used by neverbleed too.
     */
    h2o_privsep_must_read(sock, &saddr, sizeof(struct sockaddr_storage));
    switch (saddr.ss_family) {
    case PF_UNIX:
        s = sizeof(struct sockaddr_un);
        break;
    case PF_INET:
        s = sizeof(struct sockaddr_in);
        break;
    case PF_INET6:
        s = sizeof(struct sockaddr_in6);
        break;
    default:
        abort();
    }
    /*
     * We need to write multiple error codes back .One for socket and
     * the other for connect so we can replicate the same error
     * conditions exactly.
     */
    s_ret = socket(saddr.ss_family, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (s_ret != -1) {
        (void) fcntl(s_ret, F_SETFL, O_NONBLOCK);
    }
    s_errno = errno;
    iov[0].iov_base = &s_ret;
    iov[0].iov_len = sizeof(s_ret);
    iov[1].iov_base = &s_errno;
    iov[1].iov_len = sizeof(s_errno);
    if (s_ret == -1) {
        iov[2].iov_base = NULL;
        iov[2].iov_len = 0;
        iov[3].iov_base = NULL;
        iov[3].iov_len = 0;
        h2o_privsep_must_writev(sock, iov, 4);
        return;
    }
    c_ret = connect(s_ret, (struct sockaddr *)&saddr, s);
    c_errno = errno;
    iov[2].iov_base = &c_ret;
    iov[2].iov_len = sizeof(c_ret);
    iov[3].iov_base = &c_errno;
    iov[3].iov_len = sizeof(c_errno);
    h2o_privsep_must_writev(sock, iov, 4);
    h2o_privsep_send_fd(sock, s_ret);
    close(s_ret);
}

static void privsep_handle_getaddrinfo(privsep_worker_t *pswd)
{
    h2o_privsep_getaddrinfo_result_t *ent, *vec;
    size_t vec_used, vec_alloc, curlen;
    h2o_privsep_getaddrinfo_t ga_args;
    struct addrinfo *res, *res0;
    int error, sock, ret;

    sock = pswd->sock;
    h2o_privsep_must_read(sock, &ga_args, sizeof(ga_args));
    ret = getaddrinfo(ga_args.hostname, ga_args.servname, &ga_args.hints,
      &res0);
    if (ret != 0) {
        warnx("[PRIVSEP]: getaddr failed: %s\n", gai_strerror(ret));
    }
    vec_used = 0;
    vec_alloc = 0;
    vec = NULL;
    for (res = res0; res; res = res->ai_next) {
        if (vec == NULL) {
            vec_alloc = sizeof(*ent);
            vec = calloc(1, vec_alloc);
            if (vec == NULL) {
                error = -1;
                h2o_privsep_must_write(sock, &error, sizeof(error));
                return;
            }
        } else {
            vec_alloc = vec_alloc + sizeof(*ent);
            vec = realloc(vec,vec_alloc);
            if (vec == NULL) {
                error = -1;
                h2o_privsep_must_write(sock, &error, sizeof(error));
                return;
            }
        }
        ent = &vec[vec_used++];
        ent->ai_flags = res->ai_flags;
        ent->ai_family = res->ai_family;
        ent->ai_socktype = res->ai_socktype;
        ent->ai_protocol = res->ai_protocol;
        ent->ai_addrlen = res->ai_addrlen;
        memcpy(&ent->sas, res->ai_addr, res->ai_addrlen);
        if (res->ai_canonname != NULL) {
            snprintf(ent->ai_canonname, sizeof(ent->ai_canonname),
              "%s", res->ai_canonname);
        } else {
            ent->ai_canonname[0] = '\0';
        }
    }
    /* report success/failure */
    h2o_privsep_must_write(sock, &ret, sizeof(ret));
    if (ret != 0) {
        return;
    }
    curlen = vec_used * sizeof(*ent);
    if (curlen == 0) {
        curlen = -1;
        h2o_privsep_must_write(sock, &curlen, sizeof(curlen));
        return;
    }
    h2o_privsep_must_write(sock, &curlen, sizeof(curlen));
    h2o_privsep_must_write(sock, vec, curlen);
    free(vec);
}

static void privsep_handle_set_neverbleed_path(privsep_worker_t *pswd)
{
	h2o_privsep_neverbleed_path_t args;
	int ecode;

	h2o_privsep_must_read(pswd->sock, &args, sizeof(args));
	neverbleed_sock_path = strdup(args.path);
	ecode = 0;
	h2o_privsep_must_write(pswd->sock, &ecode, sizeof(ecode));
}

static void privsep_handle_neverbleed_sock(privsep_worker_t *pswd)
{
    struct sockaddr_un sun;
    int sock, ecode, ret;

    sock = socket(PF_UNIX, SOCK_STREAM, 0);
    if (sock == -1) {
        ecode = errno;
        h2o_privsep_must_write(pswd->sock, &ecode, sizeof(ecode));
        return;
    }
    bzero(&sun, sizeof(sun));
    sun.sun_family = PF_UNIX;
    snprintf(sun.sun_path, sizeof(sun.sun_path), "%s", neverbleed_sock_path);
    while (1) {
        ret = connect(sock, (struct sockaddr *)&sun, sizeof(sun));
        if (ret == -1 && errno == EINTR) {
            continue;
        } else if (ret == -1) {
            abort();
        }
        break;
    }
    ecode = 0;
    h2o_privsep_must_write(pswd->sock, &ecode, sizeof(ecode));
    h2o_privsep_send_fd(pswd->sock, sock);
    close(sock);
}

static void privsep_handle_privsep_sock(privsep_worker_t *pswd)
{
    struct sockaddr_un sun;
    int sock, ecode, ret;

    sock = socket(PF_UNIX, SOCK_STREAM, 0);
    if (sock == -1) {
        ecode = errno;
        h2o_privsep_must_write(pswd->sock, &ecode, sizeof(ecode));
        return;
    }
    bzero(&sun, sizeof(sun));
    sun.sun_family = PF_UNIX;
    snprintf(sun.sun_path, sizeof(sun.sun_path), "%s", privsep_sock_path);
    while (1) {
        ret = connect(sock, (struct sockaddr *)&sun, sizeof(sun));
        if (ret == -1 && errno == EINTR) {
            continue;
        } else if (ret == -1) {
            close(sock);
            ecode = errno;
            h2o_privsep_must_write(pswd->sock, &ecode, sizeof(ecode));
            return;
        }
        break;
    }
    ecode = 0;
    h2o_privsep_must_write(pswd->sock, &ecode, sizeof(ecode));
    h2o_privsep_send_fd(pswd->sock, sock);
    close(sock);
}

static void privsep_handle_open(privsep_worker_t *pswd)
{
    h2o_privsep_open_t args;
    int ecode, fd;

    /*
     * NB: implement path based access control check
     */
    h2o_privsep_must_read(pswd->sock, &args, sizeof(args));
    fd = open(args.path, args.flags, args.mode);
    if (fd == -1) {
        ecode = errno;
        h2o_privsep_must_write(pswd->sock, &ecode, sizeof(ecode));
        return;
    }
    ecode = 0;
    h2o_privsep_must_write(pswd->sock, &ecode, sizeof(ecode));
    h2o_privsep_send_fd(pswd->sock, fd);
    close(fd);
}

static void privsep_handle_drop_privs(privsep_worker_t *pswd)
{
    struct passwd pwbuf, *pw;
    char pwstrbuf[65536]; /* should be large enough */
    int ecode;

    ecode = 0;
    if (getpwnam_r(pswd->gcp->user, &pwbuf, pwstrbuf, sizeof(pwstrbuf), &pw) != 0) {
        ecode = errno;
        h2o_privsep_must_write(pswd->sock, &ecode, sizeof(ecode));
        return;
    }
    if (pw == NULL) {
        ecode = errno;
        h2o_privsep_must_write(pswd->sock, &ecode, sizeof(ecode));
        return;
    }
    if (setgid(pw->pw_gid) != 0) {
        ecode = errno;
        h2o_privsep_must_write(pswd->sock, &ecode, sizeof(ecode));
        return;
    }
    if (initgroups(pw->pw_name, pw->pw_gid) != 0) {
        ecode = errno;
        h2o_privsep_must_write(pswd->sock, &ecode, sizeof(ecode));
        return;
    }
    if (setuid(pw->pw_uid) != 0) {
        ecode = errno;
        h2o_privsep_must_write(pswd->sock, &ecode, sizeof(ecode));
        return;
    }
    h2o_privsep_must_write(pswd->sock, &ecode, sizeof(ecode));
}

static void *privsep_handle_global_sock(void *arg)
{
    h2o_privsep_socket_worker_t *wdata;
    privsep_worker_t psw;
    uint32_t cmd;

    /*
     * NB: we mighjt be able top consolidate this handler now.
     */
    wdata = (h2o_privsep_socket_worker_t *) arg;
    psw.sock = wdata->sock;
    while (1) {
        if (h2o_privsep_may_read(psw.sock, &cmd, sizeof(cmd))) {
            break;
        } 
        switch (cmd) {
        case PRIV_SET_NEVERBLEED_PATH:
            privsep_handle_set_neverbleed_path(&psw);
            break;
        case PRIV_PRIVSEP_SOCK:
            privsep_handle_privsep_sock(&psw);
            break;
        default:
            h2o_fatal("invalid command over privsep socket: %d", cmd);
            break;
        }
    }
    return NULL;
}

static void *privsep_handle_requests(void *arg)
{
    privsep_worker_t *pswd;
    uint32_t cmd;

    pswd = (privsep_worker_t *) arg;
    while (1) {
        if (h2o_privsep_may_read(pswd->sock, &cmd, sizeof(cmd))) {
            break;
        }
        switch (cmd) {
        case PRIV_PRIVSEP_SOCK:
            privsep_handle_privsep_sock(pswd);
            break;
        case PRIV_LOCALTIME:
        case PRIV_GMTIME:
            privsep_handle_dotime_r(pswd);
            break;
        case PRIV_WAITPID:
            privsep_handle_waitpid(pswd);
            break;
        case PRIV_FD_MAPPED_EXEC:
            privsep_handle_fd_mapped_exec(pswd);
            break;
        case PRIV_SENDMSG:
            privsep_handle_sendmsg(pswd);
            break;
        case PRIV_OPEN_LISTENER:
            privsep_handle_open_listener(pswd);
            break;
        case PRIV_DROP_PRIVS:
            privsep_handle_drop_privs(pswd);
            break;
        case PRIV_CONNECT:
            privsep_deliver_connected_sock(pswd);
            break;
        case PRIV_GETADDRINFO:
            privsep_handle_getaddrinfo(pswd);
            break;
        case PRIV_NEVERBLEED_SOCK:
            privsep_handle_neverbleed_sock(pswd);
            break;
        case PRIV_OPEN:
            privsep_handle_open(pswd);
            break;
        default:
            h2o_fatal("invalid command over privsep socket: %d", cmd);
            break;
        }
    }
    close(pswd->sock);
    free(pswd);
    return (NULL);
}

static void *privsep_handle_accept(void *arg)
{
    h2o_privsep_socket_worker_t *wdata;
    privsep_worker_t *pswp;
    int nsock;

    wdata = (h2o_privsep_socket_worker_t *) arg;
    while (1) {
        nsock = accept(wdata->sock, NULL, NULL);
        if (nsock == -1 && (errno == EINTR || errno == EAGAIN)) {
            continue;
        } else if (nsock == -1) {
            h2o_fatal("[privsep] accept failed: %s", strerror(errno));
        }
        pswp = calloc(1, sizeof(*pswp));
        if (pswp == NULL) {
            h2o_fatal("[privsep] failed to allocate memory");
        }
        pswp->sock = nsock;
        pswp->gcp = wdata->gcp;
        if (pthread_create(&pswp->thr, NULL,
          privsep_handle_requests, pswp) != 0) {
            h2o_fatal("[privsep] pthread create worker: %s", strerror(errno));
        }
    }
    return (NULL);
}

void h2o_privsep_event_loop(h2o_globalconf_t *gcp, int sock, int global_sock)
{
    h2o_privsep_socket_worker_t wdata[2];
    pthread_t thr[2];
    void *ptr;
    int k;

    wdata[0].sock = sock;
    wdata[0].gcp = gcp;
    if (pthread_create(&thr[0], NULL, privsep_handle_accept, &wdata[0]) != 0) {
        h2o_fatal("[privsep] failed to launch accept thread");
    }
    wdata[1].sock = global_sock;
    wdata[1].gcp = gcp;
    if (pthread_create(&thr[1], NULL, privsep_handle_global_sock, &wdata[1]) != 0) {
        h2o_fatal("[privsep] failed to launch accept thread");
    }
    for (k = 0; k < 2; k++) {
        if (pthread_join(thr[k], &ptr) != 0) {
            h2o_fatal("pthread join failed: %s", strerror(errno));
        }
    }
}

int h2o_privsep_set_global_sock(int sock)
{

    privsep_global_sock = sock;
    return (0);
}

static int privsep_setup_socket(h2o_globalconf_t *gcp)
{
    char sock_path[MAXPATHLEN], sock_dir[MAXPATHLEN], *buf;
    struct passwd *pwd, pwbuf;
    struct sockaddr_un sun;
    int sock, alloc;
    struct stat sb;

    if (stat("/etc/passwd", &sb) == -1) {
        h2o_fatal("passwd database not accessible");
    }
    if (sb.st_size == 0) {
        h2o_fatal("invalid passwd database");
    }
    alloc = 3 * sb.st_size;
    buf = malloc(alloc);
    if (buf == NULL) {
        h2o_fatal("failed to allocate buffer");
    }
    if (getpwnam_r(gcp->user, &pwbuf, buf, alloc, &pwd) != 0) {
        h2o_fatal("[privsep] user %s does not exist %s", gcp->user, strerror(errno));
    }
    if (snprintf(sock_dir, MAXPATHLEN, "/tmp/h2o_privsep.XXXXXX") < 0) {
        h2o_fatal("snprintf failed");
    }
    if (mkdtemp(sock_dir) == NULL) {
        h2o_fatal("mkdtemp failed");
    }
    if (chown(sock_dir, pwd->pw_uid, pwd->pw_gid) == -1) {
        h2o_fatal("[privsep] chown failed: %s", strerror(errno));
    }
    free(buf);
    sock = socket(PF_UNIX, SOCK_STREAM, 0);
    if (sock == -1) {
        h2o_fatal("[privsep] socket failed: %s", strerror(errno));
    }
    snprintf(sock_path, sizeof(sock_path), "%s/_", sock_dir);
    bzero(&sun, sizeof(sun));
    sun.sun_family = PF_UNIX;
    bcopy(sock_path, sun.sun_path, strlen(sock_path));
    (void) unlink(sock_path);
    if (bind(sock, (struct sockaddr *)&sun, sizeof(sun)) == -1) {
        h2o_fatal("[privsep] bind failed: %s", strerror(errno));
    }
    if (listen(sock, SOMAXCONN) == -1) {
        h2o_fatal("[privsep] listen failed");
    }
    if (chown(sock_path, pwd->pw_uid, pwd->pw_gid) == -1) {
        h2o_fatal("[privsep] chown failed: %s", strerror(errno));
    }
    privsep_sock_path = strdup(sock_path);
    if (privsep_sock_path == NULL) {
        h2o_fatal("failed to set privsep socket path");
    }
    return (sock);
}

int h2o_privsep_init(h2o_globalconf_t *gcp)
{
    int sock, sock_pair[2];
    pid_t pid;

    if (gcp->privsep_dir == NULL) {
        return (0);
    }
    if (chdir(gcp->privsep_dir) == -1) {
        return -1;
    }
    printf("[PRIVSEP] initializing outer sandbox (chroot)...");
    fflush(stdout);
    if (chroot(".") == -1) {
        return -1;
    }
    if (socketpair(AF_LOCAL, SOCK_STREAM, PF_UNSPEC, sock_pair) == -1) {
        h2o_fatal("socketpair failed: %s", strerror(errno));
    }
    sock = privsep_setup_socket(gcp);
    privsep_flags |= PRIVSEP_NON_PRIVILEGED;
    pid = fork();
    if (pid == -1) {
        h2o_fatal("fork of privileged process failed: %s", strerror(errno));
    }
    if (pid == 0) {
        privsep_flags &= ~PRIVSEP_NON_PRIVILEGED;
        privsep_flags |= PRIVSEP_PRIVILEGED;
        close(sock_pair[0]);
        h2o_privsep_event_loop(gcp, sock, sock_pair[1]);
        _exit(0);
    }
    printf("SUCCESS\n[PRIVSEP] ambient process pid %d\n", pid);
    h2o_privsep_set_global_sock(sock_pair[0]);
    close(sock_pair[1]);
    h2o_privsep_activate();
    return (0);
}
