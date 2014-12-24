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
