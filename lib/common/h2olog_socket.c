/*
 * Copyright (c) 2022 Goro Fuji, Fastly, Inc.
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
#include <pthread.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>

#include "h2o.h"
#include "h2o/multithread.h"
#include "h2o/h2olog_socket.h"
#include "cloexec.h"

struct st_h2olog_socket_context_t {
    int listen_fd;
};

static void *thread_main(void *_ctx)
{
    struct st_h2olog_socket_context_t *ctx = _ctx;

    while (1) {
        int fd = accept(ctx->listen_fd, NULL, 0);
        if (fd == -1) {
            h2o_perror("failed to accept");
            continue;
        }
        if (fcntl(fd, F_SETFD, FD_CLOEXEC) == -1) {
            h2o_perror("failed to set FD_CLOEXEC");
            continue;
        }
        if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1) {
            h2o_perror("failed to set O_NONBLOCK");
            continue;
        }
        ptlslog_add_fd(fd);
    }
    return NULL;
}

int h2o_setup_h2olog_socket(const char *socket_path)
{
    struct sockaddr_un sa;

    if (strlen(socket_path) >= sizeof(sa.sun_path)) {
        return EINVAL;
    }

    sa.sun_family = AF_UNIX;
    strcpy(sa.sun_path, socket_path);

    int listen_fd;
    if ((listen_fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        h2o_error_printf("[lib/common/probe_log.c] socket(2) failed: %s\n", strerror(errno));
        return EINVAL;
    }
    if (bind(listen_fd, (void *)&sa, sizeof(sa)) != 0) {
        h2o_error_printf("[lib/common/probe_log.c] bind(2) failed: %s\n", strerror(errno));
        return EINVAL;
    }
    if (listen(listen_fd, 8) != 0) {
        h2o_error_printf("[lib/common/probe_log.c] listen(2) failed: %s\n", strerror(errno));
        return EINVAL;
    }

    struct st_h2olog_socket_context_t *ctx = h2o_mem_alloc(sizeof(*ctx));
    *ctx = (struct st_h2olog_socket_context_t){
        .listen_fd = listen_fd,
    };

    {
        pthread_t tid;
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        h2o_multithread_create_thread(&tid, &attr, thread_main, ctx);
        pthread_attr_destroy(&attr);
    }

    return 0;
}
