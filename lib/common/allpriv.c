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
#include <sys/wait.h>

#include <sysexits.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

#include "h2o.h"
#include "h2o/configurator.h"
#include "h2o/privsep.h"

/*
 * NB: We need to move this to a central location so it can be sucked in by
 * main.c and allpriv.c
 */
#if defined(__linux) && defined(SO_REUSEPORT)
#define H2O_HTTP3_USE_REUSEPORT 1
#define H2O_SO_REUSEPORT SO_REUSEPORT
#elif defined(SO_REUSEPORT_LB) /* FreeBSD */
#define H2O_HTTP3_USE_REUSEPORT 1
#define H2O_SO_REUSEPORT SO_REUSEPORT_LB
#else
#define H2O_HTTP3_USE_REUSEPORT 0
#endif

char **h2o_allpriv_init_fastcgi(char *sock_dir, char *spawn_user,
    char *spawn_cmd)
{
    char **argv, *kill_on_close_cmd_path, *setuidgid_cmd_path;
    size_t index, alloc;

    alloc = 32;
    argv = calloc(alloc, sizeof(argv));
    if (argv == NULL) {
        return (NULL);
    }
    index = 0;
    kill_on_close_cmd_path = h2o_configurator_get_cmd_path("share/h2o/kill-on-close");
    argv[index++] = kill_on_close_cmd_path;
    argv[index++] = "--rm";
    argv[index++] = sock_dir;
    argv[index++] = "--";
    if (spawn_user != NULL) {
        setuidgid_cmd_path = h2o_configurator_get_cmd_path("share/h2o/setuidgid");
        argv[index++] = setuidgid_cmd_path;
        argv[index++] = spawn_user;
    }
    argv[index++] = "/bin/sh";
    argv[index++] = "-c";
    argv[index++] = spawn_cmd;
    argv[index++] = NULL;
    assert(index < 32);
    return (argv);
}

pid_t h2o_allpriv_exec(h2o_exec_context_t *ec, const char *cmd,
  char *const argv[], char **env, int policy)
{
    int error_pipe[2], ecode, ret, k;
    extern char **environ;
    char **envp;
    ssize_t cc;
    pid_t pid;

    if (pipe2(error_pipe, O_CLOEXEC) == -1) {
        return (-1);
    }
    pid = fork();
    if (pid == -1) {
        return (-1);
    }
    if (pid == 0) {
        /*
         * Overlay the file descriptors per the mapping specification in the
         * the caller. h2o_read_command() has a different mapping specification
         * than the backtrace producer. I think we have captured all the use
         * cases for this feature.
         */
        for (k = 0; k < ec->maps_used; k++) {
            dup2(ec->fdmaps[k].from, ec->fdmaps[k].to);
        }
        envp = h2o_priv_gen_env();
        if (envp != NULL) {
            environ = envp;
        }
        (void) execvp(cmd, argv);
        ecode = errno;
        (void) write(error_pipe[1], &ecode, sizeof(ecode));
        _exit(EX_SOFTWARE);
    }
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
        errno = ecode;
        return (-1);
    }
    return (pid);
}

ssize_t h2o_allpriv_sendmsg(int sock, struct msghdr *msg, int flag)
{

    return (sendmsg(sock, msg, flag));
}

int h2o_allpriv_open_listener(int domain, int type, int protocol,
  struct sockaddr_storage *addr, socklen_t addrlen, int reuseport)
{
    int fd, flag;

    /*
     * NB: we need to propagate the specific error back to the caller.
     */
    if ((fd = socket(domain, type, protocol)) == -1) {
        return (-1);
    }
    if (fcntl(fd, F_SETFD, O_CLOEXEC) == -1) {
        close(fd);
        return (-1);
    }
    /* if the socket is TCP, set SO_REUSEADDR flag to avoid TIME_WAIT after shutdown */
    if (type == SOCK_STREAM) {
        flag = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag)) != 0) {
            close(fd);
            return (-1);
        }
    }
#ifdef IPV6_V6ONLY
    /* set IPv6only */
    if (domain == AF_INET6) {
        flag = 1;
        if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &flag, sizeof(flag)) != 0) {
            close(fd);
            return (-1);
        }
    }
#endif
    if (reuseport) {
#if H2O_HTTP3_USE_REUSEPORT
        flag = 1;
        if (setsockopt(fd, SOL_SOCKET, H2O_SO_REUSEPORT, &flag, sizeof(flag)) != 0) {
            fprintf(stderr, "[warning] setsockopt(SO_REUSEPORT) failed:%s\n", strerror(errno));
        }
#endif
    }
    if (bind(fd, (struct sockaddr *)addr, addrlen) != 0) {
        close(fd);
        return (-1);
    }

    /* TCP-specific actions */
    if (protocol == IPPROTO_TCP) {
        /* listen */
        if (listen(fd, H2O_SOMAXCONN) != 0) {
            close(fd);
            return (-1);
        }
    }
    return (fd);
}

void h2o_allpriv_bind_sandbox(int policy)
{
}

int h2o_allpriv_init(h2o_globalconf_t *gcp)
{

    return (0);
}

int h2o_allpriv_get_neverbleed_sock(struct sockaddr_un *sun)
{
    int sock;

#ifdef SOCK_CLOEXEC
    sock = socket(PF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
#else
    sock = socket(PF_UNIX, SOCK_STREAM, 0);
#endif
    if (sock == -1) {
        return (-1);
    }
#ifndef SOCK_CLOEXEC
    if (fcntl(sock, F_SETFD, O_CLOEXEC) == -1) {
        return (-1);
    }
#endif
    while (connect(sock, (void *)sun, sizeof(*sun)) != 0)    
        if (errno != EINTR) 
            return (-1);
    return (sock);
}

int h2o_allpriv_open(const char *path, int flags, ...)
{
    /*
     * NB: need to use va_args to extract mode if present.
     */
    return (open(path, flags, 0));
}

int h2o_allpriv_getaddrinfo(const char *hostname, const char *servname,
  const struct addrinfo *hints, struct addrinfo **res)
{

    return (getaddrinfo(hostname, servname, hints, res));
}

int h2o_allpriv_connect_sock_noblock(struct sockaddr_storage *sas,
    int *sock_ret, int *connect_ret)
{
    socklen_t sl;
    int sock;

#ifdef SOCK_CLOEXEC
    sock = socket(PF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
#else
    sock = socket(PF_UNIX, SOCK_STREAM, 0);
#endif 
    if (sock == -1) {
        *sock_ret = sock;
        return (-1);
    }
    (void) fcntl(sock, F_SETFL, O_NONBLOCK);
    switch (sas->ss_family) {
    case PF_UNIX:
        sl = sizeof(struct sockaddr_un);
        break;
    case PF_INET:
        sl = sizeof(struct sockaddr_in);
        break;
    case PF_INET6:
        sl = sizeof(struct sockaddr_in6);
        break;
    default:
        abort();
    }
    *connect_ret = connect(sock, (void *)sas, sl);
    return (sock);
}
