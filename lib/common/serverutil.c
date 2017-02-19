/*
 * Copyright (c) 2014-2016 DeNA Co., Ltd., Kazuho Oku, Nick Desaulniers
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
#include <fcntl.h>
#include <grp.h>
#include <pthread.h>
#include <pwd.h>
#include <signal.h>
#include <spawn.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#if !defined(_SC_NPROCESSORS_ONLN)
#include <sys/sysctl.h>
#endif
#include "cloexec.h"
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

int h2o_setuidgid(const char *user)
{
    struct passwd pwbuf, *pw;
    char buf[65536]; /* should be large enough */

    errno = 0;
    if (getpwnam_r(user, &pwbuf, buf, sizeof(buf), &pw) != 0) {
        perror("getpwnam_r");
        return -1;
    }
    if (pw == NULL) {
        fprintf(stderr, "unknown user:%s\n", user);
        return -1;
    }
    if (setgid(pw->pw_gid) != 0) {
        fprintf(stderr, "setgid(%d) failed:%s\n", (int)pw->pw_gid, strerror(errno));
        return -1;
    }
    if (initgroups(pw->pw_name, pw->pw_gid) != 0) {
        fprintf(stderr, "initgroups(%s, %d) failed:%s\n", pw->pw_name, (int)pw->pw_gid, strerror(errno));
        return -1;
    }
    if (setuid(pw->pw_uid) != 0) {
        fprintf(stderr, "setuid(%d) failed:%s\n", (int)pw->pw_uid, strerror(errno));
        return -1;
    }

    return 0;
}

size_t h2o_server_starter_get_fds(int **_fds)
{
    const char *ports_env, *start, *end, *eq;
    size_t t;
    H2O_VECTOR(int) fds = {NULL};

    if ((ports_env = getenv("SERVER_STARTER_PORT")) == NULL)
        return 0;
    if (ports_env[0] == '\0') {
        fprintf(stderr, "$SERVER_STARTER_PORT is empty\n");
        return SIZE_MAX;
    }

    /* ports_env example: 127.0.0.1:80=3;/tmp/sock=4 */
    for (start = ports_env; *start != '\0'; start = *end == ';' ? end + 1 : end) {
        if ((end = strchr(start, ';')) == NULL)
            end = start + strlen(start);
        if ((eq = memchr(start, '=', end - start)) == NULL) {
            fprintf(stderr, "invalid $SERVER_STARTER_PORT, an element without `=` in: %s\n", ports_env);
            goto Error;
        }
        if ((t = h2o_strtosize(eq + 1, end - eq - 1)) == SIZE_MAX) {
            fprintf(stderr, "invalid file descriptor number in $SERVER_STARTER_PORT: %s\n", ports_env);
            goto Error;
        }
        h2o_vector_reserve(NULL, &fds, fds.size + 1);
        fds.entries[fds.size++] = (int)t;
    }

    *_fds = fds.entries;
    return fds.size;
Error:
    free(fds.entries);
    return SIZE_MAX;
}

static char **build_spawn_env(void)
{
    extern char **environ;
    size_t num;

    /* calculate number of envvars, as well as looking for H2O_ROOT= */
    for (num = 0; environ[num] != NULL; ++num)
        if (strncmp(environ[num], "H2O_ROOT=", sizeof("H2O_ROOT=") - 1) == 0)
            return NULL;

    /* not found */
    char **newenv = h2o_mem_alloc(sizeof(*newenv) * (num + 2) + sizeof("H2O_ROOT=" H2O_TO_STR(H2O_ROOT)));
    memcpy(newenv, environ, sizeof(*newenv) * num);
    newenv[num] = (char *)(newenv + num + 2);
    newenv[num + 1] = NULL;
    strcpy(newenv[num], "H2O_ROOT=" H2O_TO_STR(H2O_ROOT));

    return newenv;
}

pid_t h2o_spawnp(const char *cmd, char *const *argv, const int *mapped_fds, int cloexec_mutex_is_locked)
{
#if defined(__linux__)

    /* posix_spawnp of Linux does not return error if the executable does not exist, see
     * https://gist.github.com/kazuho/0c233e6f86d27d6e4f09
     */
    extern char **environ;
    int pipefds[2] = {-1, -1}, errnum;
    pid_t pid;

    /* create pipe, used for sending error codes */
    if (pipe2(pipefds, O_CLOEXEC) != 0)
        goto Error;

    /* fork */
    if (!cloexec_mutex_is_locked)
        pthread_mutex_lock(&cloexec_mutex);
    if ((pid = fork()) == 0) {
        /* in child process, map the file descriptors and execute; return the errnum through pipe if exec failed */
        if (mapped_fds != NULL) {
            for (; *mapped_fds != -1; mapped_fds += 2) {
                if (mapped_fds[0] != mapped_fds[1]) {
                    if (mapped_fds[1] != -1)
                        dup2(mapped_fds[0], mapped_fds[1]);
                    close(mapped_fds[0]);
                }
            }
        }
        char **env = build_spawn_env();
        if (env != NULL)
            environ = env;
        execvp(cmd, argv);
        errnum = errno;
        write(pipefds[1], &errnum, sizeof(errnum));
        _exit(EX_SOFTWARE);
    }
    if (!cloexec_mutex_is_locked)
        pthread_mutex_unlock(&cloexec_mutex);
    if (pid == -1)
        goto Error;

    /* parent process */
    close(pipefds[1]);
    pipefds[1] = -1;
    ssize_t rret;
    errnum = 0;
    while ((rret = read(pipefds[0], &errnum, sizeof(errnum))) == -1 && errno == EINTR)
        ;
    if (rret != 0) {
        /* spawn failed */
        while (waitpid(pid, NULL, 0) != pid)
            ;
        pid = -1;
        errno = errnum;
        goto Error;
    }

    /* spawn succeeded */
    close(pipefds[0]);
    return pid;

Error:
    errnum = errno;
    if (pipefds[0] != -1)
        close(pipefds[0]);
    if (pipefds[1] != -1)
        close(pipefds[1]);
    errno = errnum;
    return -1;

#else

    posix_spawn_file_actions_t file_actions;
    pid_t pid;
    extern char **environ;
    char **env = build_spawn_env();
    posix_spawn_file_actions_init(&file_actions);
    if (mapped_fds != NULL) {
        for (; *mapped_fds != -1; mapped_fds += 2) {
            if (mapped_fds[1] != -1)
                posix_spawn_file_actions_adddup2(&file_actions, mapped_fds[0], mapped_fds[1]);
            posix_spawn_file_actions_addclose(&file_actions, mapped_fds[0]);
        }
    }
    if (!cloexec_mutex_is_locked)
        pthread_mutex_lock(&cloexec_mutex);
    errno = posix_spawnp(&pid, cmd, &file_actions, NULL, argv, env != NULL ? env : environ);
    if (!cloexec_mutex_is_locked)
        pthread_mutex_unlock(&cloexec_mutex);
    free(env);
    if (errno != 0)
        return -1;

    return pid;

#endif
}

int h2o_read_command(const char *cmd, char **argv, h2o_buffer_t **resp, int *child_status)
{
    int respfds[2] = {-1, -1};
    pid_t pid = -1;
    int mutex_locked = 0, ret = -1;

    h2o_buffer_init(resp, &h2o_socket_buffer_prototype);

    pthread_mutex_lock(&cloexec_mutex);
    mutex_locked = 1;

    /* create pipe for reading the result */
    if (pipe(respfds) != 0)
        goto Exit;
    if (fcntl(respfds[0], F_SETFD, O_CLOEXEC) < 0)
        goto Exit;

    /* spawn */
    int mapped_fds[] = {respfds[1], 1, /* stdout of the child process is read from the pipe */
                        -1};
    if ((pid = h2o_spawnp(cmd, argv, mapped_fds, 1)) == -1)
        goto Exit;
    close(respfds[1]);
    respfds[1] = -1;

    pthread_mutex_unlock(&cloexec_mutex);
    mutex_locked = 0;

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
    if (mutex_locked)
        pthread_mutex_unlock(&cloexec_mutex);
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

size_t h2o_numproc(void)
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
