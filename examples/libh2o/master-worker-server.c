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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "h2o/serverutil.h"

int restart_self(char **argv)
{
    execv(argv[0], argv);
    perror("failed to respawn myself");
    exit(EX_OSERR);
}

static int should_exit = 0;

static void on_sigterm(int signo)
{
    should_exit = 1;
}

int main(int argc, char **argv)
{
    fprintf(stderr, "%s is up (pid:%d)\n", argv[0], (int)getpid());

    /* run the master process */
    h2o_run_master_process((void*)restart_self, argv);

    /* in worker process */
    h2o_set_signal_handler(SIGTERM, on_sigterm);
    while (! should_exit)
        sleep(100);

    return 0;
}
