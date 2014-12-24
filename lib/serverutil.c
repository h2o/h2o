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
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "h2o/memory.h"
#include "h2o/serverutil.h"
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

static pid_t get_oldgen_worker_pid(void)
{
    const char *env;
    int t;

    if ((env = getenv("_H2O_WORKER_PID")) == NULL)
        return -1;
    if (sscanf(env, "%d", &t) != 1) {
        fprintf(stderr, "failed to parse worker pid of previous generation:%s\n", env);
        exit(EX_SOFTWARE);
    }
    unsetenv("_H2O_WORKER_PID");
    return (pid_t)t;
}

void h2o_run_master_process(void (*restart_cb)(void*), void *restart_arg)
{
    sigset_t sigset;
    int signo, should_exit = 0;
    pid_t worker_pid = -1, oldgen_worker_pid = get_oldgen_worker_pid();

    /* setup the signal mask */
    sigemptyset(&sigset);
    h2o_set_signal_handler(SIGHUP, h2o_noop_signal_handler);
    sigaddset(&sigset, SIGHUP);
    h2o_set_signal_handler(SIGTERM, h2o_noop_signal_handler);
    sigaddset(&sigset, SIGTERM);
    h2o_set_signal_handler(SIGCHLD, h2o_noop_signal_handler);
    sigaddset(&sigset, SIGCHLD);
    sigprocmask(SIG_BLOCK, &sigset, NULL);

    /* the main loop */
    while (! (should_exit && worker_pid == -1)) {
        /* spawn worker process, if not running */
        if (worker_pid == -1) {
            worker_pid = fork();
            switch (worker_pid) {
            case -1:
                perror("fork failed");
                exit(EX_OSERR);
            case 0: /* child process, let it run as the worker process */
                h2o_set_signal_handler(SIGHUP, SIG_DFL);
                h2o_set_signal_handler(SIGTERM, SIG_DFL);
                h2o_set_signal_handler(SIGCHLD, SIG_DFL);
                sigprocmask(SIG_UNBLOCK, &sigset, NULL);
                return;
            default:
                fprintf(stderr, "started worker process:%d\n", (int)worker_pid);
                break;
            }
        }
        /* kill worker process of older generation if it is still running */
        if (oldgen_worker_pid != -1) {
            fprintf(stderr, "killing worker process of older generation:%d\n", (int)oldgen_worker_pid);
            kill(oldgen_worker_pid, SIGTERM);
            oldgen_worker_pid = -1;
        }
        /* wait for and handle the next signal */
        while (sigwait(&sigset, &signo) != 0)
            ;
        switch (signo) {
        case SIGHUP:
            if (! should_exit) {
                /* restart */
                char pidbuf[32];
                sprintf(pidbuf, "%d", (int)worker_pid);
                setenv("_H2O_WORKER_PID", pidbuf, 1);
                fprintf(stderr, "respawning master process:%d\n", (int)getpid());
                restart_cb(restart_arg);
                /* restart failed, continue */
            }
            break;
        case SIGTERM:
            should_exit = 1;
            fprintf(stderr, "shutting down worker process:%d\n", (int)worker_pid);
            kill(worker_pid, SIGTERM);
            break;
        case SIGCHLD:
            while (1) {
                pid_t exit_pid;
                int status;
                while ((exit_pid = waitpid(-1, &status, WNOHANG)) == -1 && errno == EINTR)
                    ;
                if (exit_pid <= 0)
                    break;
                fprintf(stderr, "collected worker process:%d (exit status: %d)\n", exit_pid, status);
                if (worker_pid == exit_pid)
                    worker_pid = -1;
            }
            break;
        }
    }

    fprintf(stderr, "shutting down master process: %d\n", (int)getpid());
    exit(0);
}

ssize_t h2o_server_starter_get_fds(int **_fds)
{
    const char *ports_env, *start, *end, *eq;
    size_t t;
    H2O_VECTOR(int) fds = {};

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
        h2o_vector_reserve(NULL, (void*)&fds, sizeof(fds.entries[0]), fds.size + 1);
        fds.entries[fds.size++] = (int)t;
    }

    *_fds = fds.entries;
    return fds.size;
}
