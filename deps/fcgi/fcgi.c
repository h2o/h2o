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
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/syscall.h>

#include <stdio.h>
#include <getopt.h>
#include <grp.h>
#include <unistd.h>
#include <errno.h>
#include <err.h>
#include <pwd.h>
#include <stdlib.h>
#include <sysexits.h>
#include <pthread.h>
#include <signal.h>
#include <string.h>
#include <fcntl.h>

#include <libgen.h>

#include "fcgi.h"
#include "sandbox.h"

static struct option long_options[] = {
    { "unlink-sock-path",   required_argument, 0, 'P' },
    { "setuidgid",          required_argument, 0, 'u' },
    { "help",               no_argument, 0, 'h' },
    { "wait-fd",            required_argument, 0, 'f' },
    { "sandbox",            no_argument, 0, 's' },
    { "libc-wrapper",       required_argument, 0, 'w' },
    { NULL, 0, 0, 0 }
};

static void usage(void) {

    (void) fprintf(stderr,
      "Usage: fcgi [OPTIONS] -- COMMAND\n\n"
      "Options\n"
        " -h, --help                    Display program usage\n"
        " -P, --unlink-sock-path=PATH   Directory containing fcgi socket\n"
        " -u, --setuidgid=USER          User/group for setuid operation\n"
        " -f, --wait-fd=FD              FD to wait on for parent termination\n"
        " -s, --sandbox                 Run process in a sandbox\n"
        " -w, --libc-wrapper=LIB        libc wrapper in sandbox\n\n"
        "Example:\n"
        " fcgi -P /tmp/fastcgi -u nobody -f 5 -e 10 -- /usr/bin/php-cgi\n"
        "\n");
    exit(EX_OSERR);
}

static void setuidgid(char *user)
{
    struct passwd *pwd;

    errno = 0;
    if ((pwd = getpwnam(user)) == NULL) {
        if (errno == 0) {
            errx(EX_CONFIG, "unknown user:%s\n", user);
        } else {
            err(EX_OSERR, "getpwnam");
        }
    }
    if (getuid() == pwd->pw_uid && getgid() == pwd->pw_gid) {
        endpwent();
        return;
    }
    if (setgid(pwd->pw_gid) != 0) {
        err(EX_OSERR, "setgid failed");
    }
    if (initgroups(pwd->pw_name, pwd->pw_gid) != 0) {
        err(EX_OSERR, "initgroups failed");
    }
    if (setuid(pwd->pw_uid) != 0) {
        err(EX_OSERR, "setuid failed");
    }
    endpwent();
}

static void *wait_for_parent(void *arg)
{
    struct wait_params *wp;
    char path[1024];
    ssize_t cc;
    char b;

    wp = (struct wait_params *) arg;
    while (1) {
        cc = read(wp->wait_fd, &b, 1);
        if (cc == -1 && errno == EINTR) {
            continue;
        }
        if (cc == -1) {
            err(EX_OSERR, "read wait_fd failed");
        }
        break;
    }
    warnx("h2o disapeared. cleaning up");
    warnx("sending SIGTERM to child");
    if (kill(wp->fcgi_pid, SIGTERM) == -1) {
        err(EX_OSERR, "kill failed");
    }
    if (wp->sock_path == NULL) {
        return (NULL);
    }
    warnx("removing socket %s/_", wp->sock_path);
    sprintf(path, "%s/_", wp->sock_path);
    (void) unlink(path);
    (void) unlink(wp->sock_path);
    return (NULL);
}

int main(int argc, char *argv [], char *env [])
{
    int option_index, c, ret, status;
    struct wait_params wp;
    pthread_t thr;
    char *user;
    pid_t pid;

    bzero(&wp, sizeof(wp));
    wp.wait_fd = -1;
    wp.sock_path = NULL;
    wp.do_sandbox = 0;
    user = "nobody";
    c = 0;
    while (c >= 0) {
        c = getopt_long(argc, argv, "f:hP:su:w:", long_options,
          &option_index);
        switch (c) {
        case 'w':
            wp.libc_wrapper = optarg;
            break;
        case 'f':
            wp.wait_fd = atoi(optarg);
            break;
        case 'h':
            usage();
            break;  /* NOTREACHED */
        case 'P':
            wp.sock_path = optarg;
            break;
        case 's':
            wp.do_sandbox = 1;
            break;
        case 'u':
            user = optarg;
            break;
        }
    }
    argc -= optind;
    argv += optind;
    if (argc == 0) {
        usage();
        /* NOTREACHED */
    }
    setuidgid(user);
    pid = fork();
    if (pid == -1) {
        err(EX_OSERR, "fork failed");
    }
    if (pid == 0) {
        sandbox_exec(&wp, argv, env);
        err(EX_OSERR, "execve failed");
    }
    wp.fcgi_pid = pid;
    if (wp.wait_fd >= 0) {
        if (pthread_create(&thr, NULL, wait_for_parent, &wp) == -1) {
            err(EX_OSERR, "pthread_create failed");
        }
    }
    while (1) {
        ret = waitpid(pid, &status, 0);
        if (ret == -1 && errno == EINTR) {
            continue;
        }
        if (ret == -1) {
            err(EX_OSERR, "waitpid(%d) failed", pid);
        }
        break;
    }
    warnx("collected exit status (%d) from child (%d)", status, pid);
    return (0);
}
