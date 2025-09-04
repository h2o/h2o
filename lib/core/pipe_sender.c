/*
 * Copyright (c) 2025 Fastly, Kazuho Oku
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
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include "cloexec.h"
#include "h2o/pipe_sender.h"

static int empty_pipe(int fd)
{
    ssize_t ret;
    char buf[1024];

drain_more:
    while ((ret = read(fd, buf, sizeof(buf))) == -1 && errno == EINTR)
        ;
    if (ret == 0) {
        return 0;
    } else if (ret == -1) {
        if (errno == EAGAIN)
            return 1;
        return 0;
    } else if (ret == sizeof(buf)) {
        goto drain_more;
    }

    return 1;
}

void h2o_pipe_sender_dispose(h2o_pipe_sender_t *sender, h2o_context_t *ctx)
{
    if (sender->fds[0] == -1)
        return;

    if (ctx != NULL && ctx->spare_pipes.count < ctx->globalconf->max_spare_pipes && empty_pipe(sender->fds[0])) {
        int *dst = ctx->spare_pipes.pipes[ctx->spare_pipes.count++];
        dst[0] = sender->fds[0];
        dst[1] = sender->fds[1];
    } else {
        close(sender->fds[0]);
        close(sender->fds[1]);
    }

    sender->fds[0] = -1;
}

int h2o_pipe_sender_start(h2o_context_t *ctx, h2o_pipe_sender_t *sender)
{
    if (ctx->spare_pipes.count > 0) {
        int *src = ctx->spare_pipes.pipes[--ctx->spare_pipes.count];
        sender->fds[0] = src[0];
        sender->fds[1] = src[1];
        return 1;
    }

#ifdef __linux__
    return pipe2(sender->fds, O_NONBLOCK | O_CLOEXEC) == 0;
#else
    if (cloexec_pipe(sender->fds) != 0)
        return 0;
    fcntl(sender->fds[0], F_SETFL, O_NONBLOCK);
    fcntl(sender->fds[1], F_SETFL, O_NONBLOCK);
    return 1;
#endif
}

static int from_pipe_read(h2o_sendvec_t *vec, void *dst, size_t len)
{
    h2o_pipe_sender_t *sender = (void *)vec->cb_arg[0];

    while (len != 0) {
        ssize_t ret;
        while ((ret = read(sender->fds[0], dst, len)) == -1 && errno == EINTR)
            ;
        if (ret <= 0) {
            assert(errno != EAGAIN);
            return 0;
        }
        dst += ret;
        len -= ret;
        vec->len -= ret;
    }

    return 1;
}

static size_t from_pipe_send(h2o_sendvec_t *vec, int sockfd, size_t len)
{
#ifdef __linux__
    h2o_pipe_sender_t *sender = (void *)vec->cb_arg[0];

    ssize_t bytes_sent;
    while ((bytes_sent = splice(sender->fds[0], NULL, sockfd, NULL, len, SPLICE_F_NONBLOCK)) == -1 && errno == EINTR)
        ;
    if (bytes_sent == -1 && errno == EAGAIN)
        return 0;
    if (bytes_sent <= 0)
        return SIZE_MAX;

    vec->len -= bytes_sent;

    return bytes_sent;
#else
    h2o_fatal("%s:not implemented", __FUNCTION__);
#endif
}

void h2o_pipe_sender_send(h2o_req_t *req, h2o_pipe_sender_t *sender, h2o_send_state_t send_state)
{
    static const h2o_sendvec_callbacks_t callbacks = {.read_ = from_pipe_read, .send_ = from_pipe_send};
    h2o_sendvec_t vec = {.callbacks = &callbacks};
    if ((vec.len = sender->bytes_read - sender->bytes_sent) > H2O_PULL_SENDVEC_MAX_SIZE)
        vec.len = H2O_PULL_SENDVEC_MAX_SIZE;
    vec.cb_arg[0] = (uint64_t)sender;
    vec.cb_arg[1] = 0; /* unused */

    sender->bytes_sent += vec.len;
    sender->inflight = 1;
    h2o_sendvec(req, &vec, 1, send_state);
}
