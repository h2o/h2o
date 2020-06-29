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
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <libgen.h>
#include <err.h>

#include "h2o.h"
#include "h2o/configurator.h"
#include "h2o/privsep.h"

/*
 * New threads will be created in the sandbox. To get their thread specific
 * socket for the privsep operations, serialize them on the socket-pair.
 * This serialization only happens to get the initial socket to bind in
 * thread specific data. All subsequent operations will be parallelized.
 */
static pthread_mutex_t privsep_mutex;
static pthread_key_t privsep_key;
extern int privsep_global_sock;
static int privsep_active;
extern int privsep_flags;

/*
 * This function was largely lifted from FreeBSD which distributes
 * this file/function under the BSD-3-Clause license.
 */
static int h2o_priv_mode_to_flags(const char *mode, int *flagsptr)
{
    int m, o, known;

    switch (*mode++) {
    case 'r':   /* open for reading */
        m = O_RDONLY;
        o = 0;
        break;
    case 'w':   /* open for writing */
        m = O_WRONLY;
        o = O_CREAT | O_TRUNC;
        break;
    case 'a':   /* open for appending */
        m = O_WRONLY;
        o = O_CREAT | O_APPEND;
        break;
    default:    /* illegal mode */
        errno = EINVAL;
        return (-1);
    }
    do {
        known = 1;
        switch (*mode++) {
        case 'b':
            /* 'b' (binary) is ignored */
            break;
        case '+':
            m = O_RDWR;
            break;
        case 'x':
            /* 'x' means exclusive (fail if the file exists) */
            o |= O_EXCL;
            break;
#ifdef O_CLOEXEC
        case 'e':
            /* set close-on-exec */
            o |= O_CLOEXEC;
            break;
#endif
        default:
            known = 0;
            break;
        }
    } while (known);
    if ((o & O_EXCL) != 0 && m == O_RDONLY) {
        errno = EINVAL;
        return (-1);
    }
    *flagsptr = m | o;
    return (0);
}

FILE *h2o_privsep_fopen(const char * restrict path, const char * restrict mode)
{
    int flags, fd;
    FILE *fp;

    if (h2o_priv_mode_to_flags(mode, &flags)) {
        return (NULL);
    }
    fd = h2o_privsep_open(path, flags);
    if (fd == -1) {
        return (NULL);
    }
    fp = fdopen(fd, mode);
    return (fp);
}

struct tm *h2o_privsep_dotime_r(const time_t *clock,
  struct tm *result, int type)
{
    char tzbuf[H2O_TZ_BUF];
    h2o_privsep_t *psd;
    int time_type;
    uint32_t cmd;

    time_type = type;
    assert(time_type == PRIV_LOCALTIME || time_type == PRIV_GMTIME);
    psd = h2o_get_tsd();
    assert(psd != NULL);
    cmd = PRIV_GMTIME;
    h2o_privsep_must_write(psd->ps_sock, &cmd, sizeof(cmd));
    h2o_privsep_must_write(psd->ps_sock, &time_type, sizeof(time_type));
    h2o_privsep_must_write(psd->ps_sock, (void *)clock, sizeof(*clock));
    h2o_privsep_must_read(psd->ps_sock, tzbuf, sizeof(tzbuf));
    h2o_privsep_must_read(psd->ps_sock, result, sizeof(*result));
    /*
     * NB: we need to figure out how important the timezone is and
     * determine how we want to manage the storage. Possibly thread
     * stack?.
     */
    return (result);
}

char **h2o_privsep_init_fastcgi(char *sock_dir, char *spawn_user,
    char *spawn_cmd)
{
    char **argv, buf[512], *dir, *fcgi_cmd_path, *copy;
    size_t index, alloc;

    alloc = 32;
    argv = calloc(alloc, sizeof(argv));
    if (argv == NULL) {
        return (NULL);
    }
    copy = strdup(spawn_cmd);
    dir = dirname(copy);
    if (dir == NULL) {
        free(argv);
        return (NULL);
    }
    index = 0;
    fcgi_cmd_path = h2o_configurator_get_cmd_path("share/h2o/fcgi");
    argv[index++] = fcgi_cmd_path;
    argv[index++] = "--libc-wrapper";
    argv[index++] = "libsandboxc.so";
    argv[index++] = "--sandbox";
    argv[index++] = "--unlink-sock-path";
    argv[index++] = sock_dir;
    argv[index++] = "--wait-fd";
    sprintf(buf, "%d", 5);
    argv[index++] = strdup(buf);
    if (spawn_user != NULL) {
        argv[index++] = "--setuidgid";
        argv[index++] = spawn_user;
    }
    argv[index++] = "--";
    argv[index++] = spawn_cmd;
    /*
     * NB: Currently any command line arguments are being passed in as a single
     * vector entry. We need to split each field up into an element and pass
     * it in.
     */
    argv[index++] = NULL;
    assert(index < alloc);
    return (argv);
}

pid_t h2o_privsep_waitpid(pid_t pid, int *status, int options)
{
    h2o_privsep_watpid_t args;
    h2o_privsep_t *psd;
    uint32_t cmd;
    pid_t ret_pid;
    int ecode;

    psd = h2o_get_tsd();
    assert(psd != NULL);
    cmd = PRIV_WAITPID;
    h2o_privsep_must_write(psd->ps_sock, &cmd, sizeof(cmd));
    args.pid = pid;
    args.options = options;
    h2o_privsep_must_write(psd->ps_sock, &args, sizeof(args));
    h2o_privsep_must_read(psd->ps_sock, &ret_pid, sizeof(ret_pid));
    h2o_privsep_must_read(psd->ps_sock, &ecode, sizeof(ecode));
    h2o_privsep_must_read(psd->ps_sock, status, sizeof(int));
    if (ecode != 0) {
        errno = ecode;
    }
    return (ret_pid);
}

char *h2o_privsep_marshal_vec(char *const vec[], size_t *mlen)
{
    size_t totlen, slen, count, k;
    char *const *copy;
    char *bp, *buf;

    copy = vec;
    count = 0;
    totlen = 0;
    /*
     * Iterate through array/vector to count the number of strings, but also
     * to keep track of the size for each string.
     */
    while ((bp = *copy++)) {
        totlen += strlen(bp);
        count++;
    }
    totlen += count;    /* \0 delimeter for each string */
    totlen += 1;        /* \0 terminating \0 */
    buf = malloc(totlen);
    if (buf == NULL) {
        return (NULL);
    }
    *mlen = totlen;
    bp = buf;
    for (k = 0; k < count; k++) {
        slen = strlen(vec[k]);
        bcopy(vec[k], bp, slen);
        bp += slen;
        *bp++ = '\0';
    }
    *bp = '\0';
    return (buf);
}

char **h2o_privsep_unmarshal_vec(char *marshalled, size_t len)
{
    char **ret, *bp, *ent;
    size_t count, slen;
    int k, j, h;

    if (marshalled == NULL) {
        return (NULL);
    }
    count = 0;
    for (k = 0; k < len; k++) {
       if (marshalled[k] == '\0') {
            count++;
        }
    }
    count--;
    ret = calloc(count + 1, sizeof(char *));
    if (ret == NULL) {
        return (NULL);
    }
    bp = marshalled;
    for (j = 0, k = 0; k < count; k++) {
        slen = strlen(bp);
        if (slen == 0) {
            bp += 1;
            continue;
        }
        ent = strdup(bp);
        if (ent == NULL) {
            for (h = 0; h < j; h++) {
                ent = ret[h];
                free(ent);
            }
            free(ret);
            return (NULL);
        }
        ret[j++] = ent;
        bp += slen;
        bp++;
    }
    ret[j] = NULL;
    return (ret);
}

/*
 * Policy is unused currently but we will want to re-visit this in the future.
 */
pid_t h2o_privsep_exec(h2o_exec_context_t *ec, const char *command,
  char *const argv[], char **env, int policy)
{
    char *marshalled_argv, cmdbuf[H2O_CMD_BUF];
    h2o_privsep_t *psd;
    int ecode, k, fd;
    size_t msize;
    uint32_t cmd;
    pid_t pid;

    marshalled_argv = h2o_privsep_marshal_vec(argv, &msize);
    if (marshalled_argv == NULL) {
        errno = ENOMEM;
        return (-1);
    }
    snprintf(cmdbuf, H2O_CMD_BUF, "%s", command);
    psd = h2o_get_tsd();
    assert(psd != NULL);
    cmd = PRIV_FD_MAPPED_EXEC;
    h2o_privsep_must_write(psd->ps_sock, &cmd, sizeof(cmd));
    h2o_privsep_must_write(psd->ps_sock, cmdbuf, H2O_CMD_BUF);
    h2o_privsep_must_write(psd->ps_sock, &msize, sizeof(msize));
    h2o_privsep_must_read(psd->ps_sock, &ecode, sizeof(ecode));
    if (ecode != 0) {
        errno = ecode;
        return (-1);
    }
    h2o_privsep_must_write(psd->ps_sock, marshalled_argv, msize);
    h2o_privsep_must_write(psd->ps_sock, &ec->maps_used, sizeof(ec->maps_used));
    h2o_privsep_must_write(psd->ps_sock, ec->fdmaps,
        ec->maps_used * sizeof(h2o_fd_mapping_t));
    for (k = 0; k < ec->maps_used; k++) {
        switch (ec->fdmaps[k].type) {
        case H2O_FDMAP_BASIC:
            break;
        case H2O_FDMAP_SEND_TO_PROC:
            h2o_privsep_send_fd(psd->ps_sock, ec->fdmaps[k].from);
            break;
        case H2O_FDMAP_READ_FROM_PROC:
            fd = h2o_privsep_receive_fd(psd->ps_sock);
            close(ec->fdmaps[k].from);
            dup2(fd, ec->fdmaps[k].from);
            break;
        }
    }
    h2o_privsep_must_read(psd->ps_sock, &pid, sizeof(pid));
    h2o_privsep_must_read(psd->ps_sock, &ecode, sizeof(ecode));
    if (pid == -1) {
        errno = ecode;
    }
    return (pid);
}

ssize_t h2o_privsep_sendmsg(int sock, struct msghdr *msg, int flags)
{
    h2o_privsep_sendmsg_t args;
    struct iovec *iovp;
    h2o_privsep_t *psd;
    int ecode, index;
    uint32_t cmd;
    ssize_t cc;

    /*
     * FreeBSD doesn't allow network based sendmsg(2) operations in sandbox
     * mode.  This is not tunable. The existing Linux seccomp policy will
     * allow it for the sake performance. We might revisit this as some
     * point, but if the sandbox implementation allows sendmsg(2) just use
     * the non-privsep path to execute it.
     */
    if ((privsep_flags & SANDBOX_ALLOWS_SENDMSG) != 0) {
        return (h2o_allpriv_sendmsg(sock, msg, flags));
    }
    psd = h2o_get_tsd();
    assert(psd != NULL);
    cmd = PRIV_SENDMSG;
    h2o_privsep_must_write(psd->ps_sock, &cmd, sizeof(cmd));
    /*
     * NB: this is very inefficient. We need to implement a file descriptor
     * cache in he privileged process so we aren't transmitted the fd
     * everytime we want to send an H3 packet.
     */
    h2o_privsep_send_fd(psd->ps_sock, sock);
    args.msg_namelen = msg->msg_namelen;
    args.msg_iovlen = msg->msg_iovlen;
    args.msg_controllen = msg->msg_controllen;
    args.flags = flags;
    h2o_privsep_must_write(psd->ps_sock, &args, sizeof(args));
    for (index = 0; index < msg->msg_iovlen; index++) {
        iovp = &msg->msg_iov[index];
        h2o_privsep_must_write(psd->ps_sock, &iovp->iov_len, sizeof(iovp->iov_len));
        h2o_privsep_must_write(psd->ps_sock, iovp->iov_base, iovp->iov_len);
    }
    h2o_privsep_must_write(psd->ps_sock, msg->msg_name, args.msg_namelen);
    h2o_privsep_must_read(psd->ps_sock, &ecode, sizeof(ecode));
    if (ecode != 0) {
        errno = ecode;
        return (-1);
    }
    h2o_privsep_must_write(psd->ps_sock, msg->msg_control, args.msg_controllen);
    h2o_privsep_must_read(psd->ps_sock, &ecode, sizeof(ecode));
    if (ecode != 0) {
        errno = ecode;
        return (-1);
    }
    h2o_privsep_must_read(psd->ps_sock, &cc, sizeof(cc));
    h2o_privsep_must_read(psd->ps_sock, &ecode, sizeof(ecode));
    return (cc);
}

int h2o_privsep_open_listener(int domain, int type, int protocol,
  struct sockaddr_storage *addr, socklen_t addrlen, int reuseport)
{
    h2o_privsep_open_listener_t args;
    h2o_privsep_t *psd;
    int ecode, sock;
    uint32_t cmd;

    psd = h2o_get_tsd();
    assert(psd != NULL);
    cmd = PRIV_OPEN_LISTENER;
    h2o_privsep_must_write(psd->ps_sock, &cmd, sizeof(cmd));
    args.domain = domain;
    args.type = type;
    args.protocol = protocol;
    bcopy(addr, &args.sas, addrlen);
    args.addrlen = addrlen;
    args.reuseport = reuseport;
    h2o_privsep_must_write(psd->ps_sock, &args, sizeof(args));
    h2o_privsep_must_read(psd->ps_sock, &ecode, sizeof(ecode));
    if (ecode != 0) {
        errno = ecode;
        return (-1);
    }
    sock = h2o_privsep_receive_fd(psd->ps_sock);
    return (sock);
}

void h2o_privsep_sandbox_hints(char *root)
{

#ifdef __linux__
    sandbox_emit_linux_hints(root);
#endif
#ifdef __FreeBSD__
    sandbox_emit_freebsd_hints(root);
#endif
}

void h2o_privsep_bind_sandbox(int policy)
{
    /*
     * SANDBOX_POLICY_BASIC is used to set a minimal sandbox policy on a
     * process. This process will not be using privsep, in which case 
     * skip the call to drop privs (which assumes the full privsep model
     * is being used.
     */
    switch (policy) {
    case SANDBOX_POLICY_NONE:
        return;
        break;
    case SANDBOX_POLICY_NEVERBLEED:
        break;
    case SANDBOX_POLICY_H2OMAIN:
        h2o_privsep_drop_privs();
        break;
    }
#ifdef __linux__
    sandbox_bind_linux(policy);
    privsep_flags |= SANDBOX_ALLOWS_SENDMSG;
#endif
#ifdef __FreeBSD__
    sandbox_bind_freebsd(policy);
#endif
}

int h2o_privsep_may_read(int fd, void *buf, size_t n)
{
    ssize_t res, pos;
    char *s;

    s = buf;
    pos = 0;
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

void h2o_privsep_must_read(int fd, void *buf, size_t n)
{
    ssize_t res, pos;
    char *s;

    pos = 0;
    s = buf;
    while (n > pos) {
        res = read(fd, s + pos, n - pos);
        switch (res) {
        case -1:
            if (errno == EINTR || errno == EAGAIN)
                continue;
            /* FALLTHROUGH */
        case 0:
            if ((privsep_flags & PRIVSEP_PRIVILEGED) != 0) {
                _exit(0);
            } else {
                exit(0);
            }
        default:
            pos += res;
        }
    }
}

void h2o_privsep_must_readv(int fd, const struct iovec *iov, int iovcnt)
{
    ssize_t cc;

    while (1) {
        cc = readv(fd, iov, iovcnt);
        if (cc == -1 && errno == EINTR) {
            continue;
        }
        if (cc == -1) {
            warn("readv failed");
            if ((privsep_flags & PRIVSEP_PRIVILEGED) != 0) {
                _exit(1);
            } else {
                exit(1);
            }
        }
        break;
    }
}

void h2o_privsep_must_writev(int fd, const struct iovec *iov, int iovcnt)
{
    ssize_t cc;

    while (1) {
        cc = writev(fd, iov, iovcnt);
        if (cc == -1 && errno == EINTR) {
            continue;
        }
        if (cc == -1) {
            warn("writev failed");
            if ((privsep_flags & PRIVSEP_PRIVILEGED) != 0) {
                _exit(1);
            } else {
                exit(1);
            }
        }
        break;
    }
}

void h2o_privsep_must_write(int fd, void *buf, size_t n)
{
    ssize_t res, pos;
    char *s;

    pos = 0;
    s = buf;
    while (n > pos) {
        res = write(fd, s + pos, n - pos);
        switch (res) {
        case -1:
            if (errno == EINTR || errno == EAGAIN)
                continue;
        case 0:
            if ((privsep_flags & PRIVSEP_PRIVILEGED) != 0) {
                _exit(0);
            } else {
                exit(0);
            }
        default:
            pos += res;
        }
    }
}

void h2o_privsep_send_fd(int sock, int fd)
{
    struct msghdr msg;
    union {
        struct cmsghdr hdr;
        char buf[CMSG_SPACE(sizeof(int))];
    } cmsgbuf;
    struct cmsghdr *cmsg;
    struct iovec vec;
    int *fdp, result;
    ssize_t n;

    result = 0;
    memset(&msg, 0, sizeof(msg));
    if (fd < 0) {
        return;
    }
    msg.msg_control = (caddr_t)&cmsgbuf.buf;
    msg.msg_controllen = sizeof(cmsgbuf.buf);
    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    fdp = (int *)CMSG_DATA(cmsg);
    *fdp = fd;
    vec.iov_base = &result;
    vec.iov_len = sizeof(int);
    msg.msg_iov = &vec;
    msg.msg_iovlen = 1;
    if ((n = sendmsg(sock, &msg, 0)) == -1)  {
        fprintf(stderr, "h2o_privsep_send_fd: %s\n", strerror(errno));
        abort();
    }
    if (n != sizeof(int)) {
        fprintf(stderr, "h2o_privsep_send_fd: %s\n", strerror(errno));
        abort();
    }
}

int h2o_privsep_receive_fd(int sock)
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
    int fd, *fdp;

    memset(&msg, 0, sizeof(msg));
    vec.iov_base = &result;
    vec.iov_len = sizeof(int);
    msg.msg_iov = &vec;
    msg.msg_iovlen = 1;
    msg.msg_control = &cmsgbuf.buf;
    msg.msg_controllen = sizeof(cmsgbuf.buf);
    if ((n = recvmsg(sock, &msg, 0)) == -1) {
        fprintf(stderr, "%s: %s\n", __func__, strerror(errno));
        abort();
    }
    if (n != sizeof(int)) {
        fprintf(stderr, "%s: %s\n", __func__, strerror(errno));
        abort();
    }
    if (result == 0) {
        cmsg = CMSG_FIRSTHDR(&msg);
        if (cmsg == NULL) {
            abort();
        }
        if (cmsg->cmsg_type != SCM_RIGHTS) {
            (void) fprintf(stderr, "%s: expected type %d got %d", __func__,
                SCM_RIGHTS, cmsg->cmsg_type);
            abort();
        }
        fdp = (int *)CMSG_DATA(cmsg);
        fd = *fdp;
        assert(fd != -1);
        return (fd);
    } else {
        errno = result;
        return (-1);
    }
}

static int h2o_privsep_active(void)
{

    return (privsep_active != 0);
}

void h2o_privsep_set_neverbleed_path(const char *path)
{
	h2o_privsep_neverbleed_path_t args;
	uint32_t cmd;
	int ecode;

	cmd = PRIV_SET_NEVERBLEED_PATH;
	pthread_mutex_lock(&privsep_mutex);
	h2o_privsep_must_write(privsep_global_sock, &cmd, sizeof(cmd));
	snprintf(args.path, sizeof(args.path), "%s", path);
	h2o_privsep_must_write(privsep_global_sock, &args, sizeof(args));
	h2o_privsep_must_read(privsep_global_sock, &ecode, sizeof(ecode));
	pthread_mutex_unlock(&privsep_mutex);
}

int h2o_privsep_get_sock(void)
{
    int ecode, sock;
    uint32_t cmd;

    pthread_mutex_lock(&privsep_mutex);
    cmd = PRIV_PRIVSEP_SOCK;
    h2o_privsep_must_write(privsep_global_sock, &cmd, sizeof(cmd));
    h2o_privsep_must_read(privsep_global_sock, &ecode, sizeof(ecode));
    if (ecode != 0) {
        warnx("%s: PRIV_PRIVSEP_SOCK: %s\n", __func__, strerror(ecode));
        errno = ecode;
        pthread_mutex_unlock(&privsep_mutex);
        return -1;
    }
    sock = h2o_privsep_receive_fd(privsep_global_sock);
    pthread_mutex_unlock(&privsep_mutex);
    return (sock);
}

int h2o_privsep_activate(void)
{

    if (pthread_key_create(&privsep_key, free) != 0) {
        h2o_fatal("[privsep] failed tp initialize thread specific data: %s",
          strerror(errno));
    }
    privsep_active = 1;
    return (0);
}

h2o_privsep_t *h2o_get_tsd(void)
{
    h2o_privsep_t *tsd;

    assert(h2o_privsep_active());
    tsd = pthread_getspecific(privsep_key);
    if (tsd) {
        return (tsd);
    }
    tsd = calloc(1, sizeof(*tsd));
    if (tsd == NULL) {
        return (NULL);
    }
    tsd->ps_sock = h2o_privsep_get_sock();
    if (tsd->ps_sock == -1) {
        /*
         * If we fail to get privsep socket, bail. Something has gone very
         * wrong and nothing will be able to facilitate whatever privilege
         * we are requesting.
         */
        abort();
    }
    if (pthread_setspecific(privsep_key, tsd) != 0) {
        free(tsd);
        close(tsd->ps_sock);
    }
    return (tsd);
}

int h2o_privsep_get_neverbleed_sock(void)
{
    h2o_privsep_t *psd;
    int ecode, sock;
    uint32_t cmd;

    psd = h2o_get_tsd();
    assert(psd != NULL);
    cmd = PRIV_NEVERBLEED_SOCK;
    h2o_privsep_must_write(psd->ps_sock, &cmd, sizeof(cmd));
    h2o_privsep_must_read(psd->ps_sock, &ecode, sizeof(ecode));
    if (ecode != 0) {
        errno = ecode;
        return -1;
    }
    sock = h2o_privsep_receive_fd(psd->ps_sock);
    return (sock);
}

int h2o_privsep_open(const char *path, int flags, ...)
{
    h2o_privsep_open_t oa;
    h2o_privsep_t *psd;
    int cmd, fd, ecode;

    psd = h2o_get_tsd();
    assert(psd != NULL);
    snprintf(oa.path, sizeof(oa.path), "%s", path);
    oa.flags = flags;
    cmd = PRIV_OPEN;
    h2o_privsep_must_write(psd->ps_sock, &cmd, sizeof(cmd));
    h2o_privsep_must_write(psd->ps_sock, &oa, sizeof(oa));
    h2o_privsep_must_read(psd->ps_sock, &ecode, sizeof(ecode));
    if (ecode != 0) {
        errno = ecode;
        return (-1);
    }
    fd = h2o_privsep_receive_fd(psd->ps_sock);
    return (fd);
}

static struct addrinfo *addrinfo_copy(h2o_privsep_getaddrinfo_result_t *ent)
{
	struct addrinfo *cres;

	cres = malloc(sizeof(*cres));
	if (cres == NULL)
		return (NULL);
	cres->ai_flags = ent->ai_flags;
	cres->ai_family = ent->ai_family;
	cres->ai_socktype = ent->ai_socktype;
	cres->ai_protocol = ent->ai_protocol;
	cres->ai_addrlen = ent->ai_addrlen;
	cres->ai_addr = malloc(cres->ai_addrlen);
	memcpy(cres->ai_addr, &ent->sas, cres->ai_addrlen);
	cres->ai_canonname = strdup(ent->ai_canonname);
	if (cres->ai_canonname == NULL) {
		free(cres);
		return (NULL);
	}
	return (cres);
}

static int process_getaddr_data(h2o_privsep_getaddrinfo_result_t *vec,
  size_t blen, struct addrinfo **res)
{
    h2o_privsep_getaddrinfo_result_t *ent;
    struct addrinfo *cres, *head;
    int nitems;

    if (blen % sizeof(*ent) != 0) {
        return (-1);
    }
    head = NULL;
    nitems = blen / sizeof(*ent);
    for (ent = &vec[0]; ent < &vec[nitems]; ent++) {
        cres = addrinfo_copy(ent);
        if (cres == NULL) {
            return (-1);
        }
        cres->ai_next = head;
        head = cres;
    }
    *res = head;
    return (0);
}

void h2o_privsep_freeaddrinfo(struct addrinfo *ai)
{

    assert(ai != NULL);
    free(ai->ai_addr);
    free(ai->ai_canonname);
    free(ai);
}

int h2o_privsep_getaddrinfo(const char *hostname, const char *servname,
  const struct addrinfo *hints, struct addrinfo **res)
{
    h2o_privsep_getaddrinfo_result_t *vec;
    h2o_privsep_getaddrinfo_t ga_args;
    h2o_privsep_t *psd;
    int cmd, ret;
    size_t blen;
 
    psd = h2o_get_tsd();
    assert(psd != NULL);
    memset(&ga_args, 0, sizeof(ga_args));
    snprintf(ga_args.hostname, sizeof(ga_args.hostname), "%s", hostname);
    snprintf(ga_args.servname, sizeof(ga_args.servname), "%s", servname);
    memcpy(&ga_args.hints, hints, sizeof(ga_args.hints));
    cmd = PRIV_GETADDRINFO;
    h2o_privsep_must_write(psd->ps_sock, &cmd, sizeof(cmd));
    h2o_privsep_must_write(psd->ps_sock, &ga_args, sizeof(ga_args));
	h2o_privsep_must_read(psd->ps_sock, &ret, sizeof(cmd));
    if (ret != 0) {
        return (ret);
    }
    h2o_privsep_must_read(psd->ps_sock, &blen, sizeof(blen));
    if (blen == -1) {
        return (EAI_MEMORY);
    }
    vec = malloc(blen);
    if (vec == NULL) {
        return (EAI_MEMORY);
    }
    h2o_privsep_must_read(psd->ps_sock, vec, blen);
    ret = process_getaddr_data(vec, blen, res);
    free(vec);
    if (ret == -1) {
        return (EAI_MEMORY);
    }
    return (0);
}

/*
 * This privilege is used in the critical path, so we want to squeeze whatever
 * performance we can out of it. We are using iov's here to reduce the number
 * of context switches required per connect operation.
 */
int h2o_privsep_connect_sock_noblock(struct sockaddr_storage *sas,
  int *sock_ret, int *connect_ret)
{
    int s_ret, s_errno, c_ret, c_errno, *ptr, priv, sock;
    struct iovec iov[8];
    h2o_privsep_t *psd;

    psd = h2o_get_tsd();
    assert(psd != NULL);
    priv = PRIV_CONNECT;
    h2o_privsep_must_write(psd->ps_sock, &priv, sizeof(int));
    h2o_privsep_must_write(psd->ps_sock, sas, sizeof(struct sockaddr_storage));

    iov[0].iov_base = &s_ret;
    iov[0].iov_len = sizeof(s_ret);
    iov[1].iov_base = &s_errno;
    iov[1].iov_len = sizeof(s_errno);
    iov[2].iov_base = &c_ret;
    iov[2].iov_len = sizeof(c_ret);
    iov[3].iov_base = &c_errno;
    iov[3].iov_len = sizeof(c_errno);
    h2o_privsep_must_readv(psd->ps_sock, iov, 4);
    ptr = iov[0].iov_base;
    *sock_ret = *ptr;
    if (*sock_ret == -1)  {
        ptr = iov[1].iov_base;
        errno = *ptr;
        return (-1);
    }
    ptr = iov[2].iov_base;
    *connect_ret = *ptr;
    ptr = iov[3].iov_base;
    errno = *ptr;
    sock = h2o_privsep_receive_fd(psd->ps_sock);
    return (sock);
}

int h2o_privsep_drop_privs(void)
{
    h2o_privsep_t *psd;
    uint32_t cmd;
    int ecode;

    psd = h2o_get_tsd();
    assert(psd != NULL);
    cmd = PRIV_DROP_PRIVS;
    h2o_privsep_must_write(psd->ps_sock, &cmd, sizeof(cmd));
    h2o_privsep_must_read(psd->ps_sock, &ecode, sizeof(ecode));
    return (ecode);
}
