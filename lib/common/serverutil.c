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
#include <errno.h>
#include <grp.h>
#include <pthread.h>
#include <signal.h>
#include <spawn.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#if !defined(_SC_NPROCESSORS_ONLN)
#include <sys/sysctl.h>
#endif
#include "h2o/memory.h"
#include "h2o/serverutil.h"
#include "h2o/socket.h"
#include "h2o/string_.h"

void h2o_set_signal_handler(int signo, void (*cb)(int signo))
{
    struct sigaction action;

    memset(&action, 0, sizeof(action));
    sigemptyset(&action.sa_mask);
    action.sa_handler = cb;
    sigaction(signo, &action, NULL);
}

void h2o_noop_signal_handler(int signo)
{
}

static int thread_notify_signo;
static __thread volatile sig_atomic_t thread_notified = 0;

static void on_thread_notify_sig(int signo)
{
    thread_notified = 1;
}

void h2o_thread_initialize_signal_for_notification(int signo)
{
    sigset_t mask;

    h2o_set_signal_handler(signo, on_thread_notify_sig);
    pthread_sigmask(SIG_BLOCK, NULL, &mask);
    sigdelset(&mask, signo);
    pthread_sigmask(SIG_SETMASK, &mask, NULL);

    thread_notify_signo = signo;
}

void h2o_thread_notify(pthread_t tid)
{
    assert(thread_notify_signo != 0);
    pthread_kill(tid, thread_notify_signo);
}

int h2o_thread_is_notified(void)
{
    int ret = thread_notified != 0;
    thread_notified = 0;
    return ret;
}

int h2o_setuidgid(struct passwd *passwd)
{
    if (setgid(passwd->pw_gid) != 0) {
        fprintf(stderr, "setgid(%d) failed:%s\n", (int)passwd->pw_gid, strerror(errno));
        return -1;
    }
    if (initgroups(passwd->pw_name, passwd->pw_gid) != 0) {
        fprintf(stderr, "initgroups(%s, %d) failed:%s\n", passwd->pw_name, (int)passwd->pw_gid, strerror(errno));
        return -1;
    }
    if (setuid(passwd->pw_uid) != 0) {
        fprintf(stderr, "setuid(%d) failed:%s\n", (int)passwd->pw_uid, strerror(errno));
        return -1;
    }

    return 0;
}

ssize_t h2o_server_starter_get_fds(int **_fds)
{
    const char *ports_env, *start, *end, *eq;
    size_t t;
    H2O_VECTOR(int)fds = {};

    if ((ports_env = getenv("SERVER_STARTER_PORT")) == NULL)
        return 0;
    if (ports_env[0] == '\0') {
        fprintf(stderr, "$SERVER_STARTER_PORT is empty\n");
        return -1;
    }

    /* ports_env example: 127.0.0.1:80=3;/tmp/sock=4 */
    for (start = ports_env; *start != '\0'; start = *end == ';' ? end + 1 : end) {
        if ((end = strchr(start, ';')) == NULL)
            end = start + strlen(start);
        if ((eq = memchr(start, '=', end - start)) == NULL) {
            fprintf(stderr, "invalid $SERVER_STARTER_PORT, an element without `=` in: %s\n", ports_env);
            return -1;
        }
        if ((t = h2o_strtosize(eq + 1, end - eq - 1)) == SIZE_MAX) {
            fprintf(stderr, "invalid file descriptor number in $SERVER_STARTER_PORT: %s\n", ports_env);
            return -1;
        }
        h2o_vector_reserve(NULL, (void *)&fds, sizeof(fds.entries[0]), fds.size + 1);
        fds.entries[fds.size++] = (int)t;
    }

    *_fds = fds.entries;
    return fds.size;
}

int h2o_read_command(const char *cmd, char **argv, h2o_buffer_t **resp, int *child_status)
{
    int respfds[2] = {-1, -1};
    posix_spawn_file_actions_t file_actions;
    pid_t pid = -1;
    int ret = -1;
    extern char **environ;

    h2o_buffer_init(resp, &h2o_socket_buffer_prototype);

    /* create pipe for reading the result */
    if (pipe(respfds) != 0)
        goto Exit;

    /* spawn */
    posix_spawn_file_actions_init(&file_actions);
    posix_spawn_file_actions_adddup2(&file_actions, respfds[1], 1);
    if ((errno = posix_spawnp(&pid, cmd, &file_actions, NULL, argv, environ)) != 0) {
        pid = -1;
        goto Exit;
    }
    close(respfds[1]);
    respfds[1] = -1;

    /* read the response from pipe */
    while (1) {
        h2o_iovec_t buf = h2o_buffer_reserve(resp, 8192);
        ssize_t r;
        while ((r = read(respfds[0], buf.base, buf.len)) == -1 && errno == EINTR)
            ;
        if (r <= 0)
            break;
        (*resp)->size += r;
    }

Exit:
    if (pid != -1) {
        /* wait for the child to complete */
        pid_t r;
        while ((r = waitpid(pid, child_status, 0)) == -1 && errno == EINTR)
            ;
        if (r == pid) {
            /* success */
            ret = 0;
        }
    }
    if (respfds[0] != -1)
        close(respfds[0]);
    if (respfds[1] != -1)
        close(respfds[1]);
    if (ret != 0)
        h2o_buffer_dispose(resp);

    return ret;
}

size_t h2o_numproc()
{
#if defined(_SC_NPROCESSORS_ONLN)
    return (size_t)sysconf(_SC_NPROCESSORS_ONLN);
#elif defined(CTL_HW) && defined(HW_AVAILCPU)
    int name[] = {CTL_HW, HW_AVAILCPU};
    int ncpu;
    size_t ncpu_sz = sizeof(ncpu);
    if (sysctl(name, sizeof(name) / sizeof(name[0]), &ncpu, &ncpu_sz, NULL, 0) != 0 || sizeof(ncpu) != ncpu_sz) {
        fprintf(stderr, "[ERROR] failed to obtain number of CPU cores, assuming as one\n");
        ncpu = 1;
    }
    return ncpu;
#else
    return 1;
#endif
}
