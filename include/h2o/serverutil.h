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
#ifndef h2o__server_starter_h
#define h2o__server_starter_h

#include <stddef.h>
#include <pwd.h>

/* taken from sysexits.h */
#ifndef EX_SOFTWARE
#define EX_SOFTWARE 70
#endif
#ifndef EX_OSERR
#define EX_OSERR 71
#endif
#ifndef EX_TEMPFAIL
#define EX_TEMPFAIL 75
#endif
#ifndef EX_CONFIG
#define EX_CONFIG 78
#endif

/**
 * equivalent of signal(3)
 */
void h2o_set_signal_handler(int signo, void (*cb)(int signo));
/**
 * a signal handler that does nothing
 */
void h2o_noop_signal_handler(int signo);

/**
 * initializes the given signal to be used for waking up other threads
 */
void h2o_thread_initialize_signal_for_notification(int signo);
/**
 * notifies a thread
 */
void h2o_thread_notify(pthread_t tid);
/**
 * returns if the running thread has received a notification (and clears the flag)
 */
int h2o_thread_is_notified(void);

/**
 * equiv. to setuidgid of djb
 */
int h2o_setuidgid(struct passwd *passwd);

/**
 * return a list of fds passed in from Server::Starter, or 0 if Server::Starter was not used.  -1 on error
 */
ssize_t h2o_server_starter_get_fds(int **_fds);

/**
 * executes a command and returns its output
 * @param cmd
 * @param argv
 * @param resp the output, only available if the function returns zero
 * @param child_status result of waitpid(child_pid), only available if the function returns zero
 */
int h2o_read_command(const char *cmd, char **argv, h2o_buffer_t **resp, int *child_status);

/**
 * Gets the number of processor cores
 */
size_t h2o_numproc();

#endif
