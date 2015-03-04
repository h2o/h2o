/*
 * Copyright (c) 2015 DeNA Co., Ltd., Kazuho Oku
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
#ifdef __linux__
#define _GNU_SOURCE
#endif
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "asyncaddrinfo.h"

static struct asyncaddrinfo_request_t **reqs;
size_t reqs_pending = 0;

#ifdef __linux__

int asyncaddrinfo_linux_signo = SIGUSR1;

static void on_sigusr1(int signo, siginfo_t *si, void *unused)
{
    asyncaddrinfo_linux_handle_signal(si->si_code, si->si_ptr);
}

static void setup_sighandler(void)
{
    struct sigaction act = {};
    act.sa_sigaction = on_sigusr1;
    act.sa_flags = SA_SIGINFO;
    sigaction(asyncaddrinfo_linux_signo, &act, NULL);
}

#endif

static void on_lookup_complete(struct asyncaddrinfo_request_t *req, const char *errstr, struct addrinfo *res)
{
    const char *name = req->data;

    printf("%s:", name);
    if (errstr != NULL) {
        printf(" error: %s\n", errstr);
    } else {
        do {
            char host[NI_MAXHOST];
            getnameinfo(res->ai_addr, res->ai_addrlen, host, sizeof(host), NULL, 0, NI_NUMERICHOST);
            printf(" %s", host);
        } while ((res = res->ai_next) != NULL);
        printf("\n");
        freeaddrinfo(res);
    }

    --reqs_pending;
}

int main(int argc, char **argv)
{
    int i;

    if (argc == 1) {
        fprintf(stderr, "Usage: %s host1 host2 ...\n", argv[0]);
        return 1;
    }

#ifdef __linux__
    setup_sighandler();
#endif

    reqs = malloc(sizeof(*reqs) * (argc - 1));

    for (i = 1; i != argc; ++i) {
        asyncaddrinfo(&reqs[i - 1], argv[i], argv[i], NULL, SOCK_STREAM, IPPROTO_TCP, AI_ADDRCONFIG, on_lookup_complete);
        ++reqs_pending;
    }

    /* sleep until all gets done */
    while (reqs_pending != 0)
        sleep(100);

    free(reqs);

    return 0;
}
