#include "h2o/pipe_utils.h"

#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include "h2o.h"

void h2o_pipe_reader_init(h2o_pipe_reader_t *pipe_reader)
{
    *pipe_reader = (h2o_pipe_reader_t){
        .fds =
            {
                -1, -1,
            },
        .inflight = 0,
        .body_bytes_read = 0,
        .body_bytes_sent = 0,
    };
}

int h2o_pipe_reader_new(h2o_context_t *ctx, h2o_pipe_reader_t *pipe_reader)
{
    if (ctx->spare_pipes.count > 0) {
        int *src = ctx->spare_pipes.pipes[--ctx->spare_pipes.count];
        pipe_reader->fds[0] = src[0];
        pipe_reader->fds[1] = src[1];
        return 1;
    }

#ifdef __linux__
    return pipe2(pipe_reader->fds, O_NONBLOCK | O_CLOEXEC) == 0;
#else
    if (cloexec_pipe(fds) != 0)
        return 0;
    fcntl(pipe_reader->fds[0], F_SETFL, O_NONBLOCK);
    fcntl(pipe_reader->fds[1], F_SETFL, O_NONBLOCK);
    return 1;
#endif
}

int h2o_pipe_reader_start(h2o_context_t *ctx, h2o_pipe_reader_t *pipe_reader)
{
    return h2o_pipe_reader_new(ctx, pipe_reader) ? pipe_reader->fds[1] : -1;
}

void h2o_pipe_reader_dispose(h2o_context_t *ctx, h2o_pipe_reader_t *pipe_reader)
{
    assert(pipe_reader->fds[0] != -1);
    assert(pipe_reader->fds[1] != -1);

    if (ctx->spare_pipes.count < ctx->globalconf->max_spare_pipes && h2o_empty_pipe(pipe_reader->fds[0])) {
        int *dst = ctx->spare_pipes.pipes[ctx->spare_pipes.count++];
        dst[0] = pipe_reader->fds[0];
        dst[1] = pipe_reader->fds[1];
    } else {
        close(pipe_reader->fds[0]);
        close(pipe_reader->fds[1]);
    }

    pipe_reader->fds[0] = -1;
}

int h2o_pipe_reader_is_empty(h2o_pipe_reader_t *pipe_reader)
{
    return pipe_reader->body_bytes_read == pipe_reader->body_bytes_sent;
}

void h2o_pipe_reader_update(h2o_pipe_reader_t *pipe_reader, size_t read_body_bytes)
{
    pipe_reader->body_bytes_read = read_body_bytes;
}

int h2o_empty_pipe(int fd)
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

static int from_pipe_read(h2o_sendvec_t *vec, void *dst, size_t len)
{
    h2o_pipe_reader_t *pipe_reader = (void *)vec->cb_arg[0];

    while (len != 0) {
        ssize_t ret;
        while ((ret = read(pipe_reader->fds[0], dst, len)) == -1 && errno == EINTR)
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
    h2o_pipe_reader_t *pipe_reader = (void *)vec->cb_arg[0];

    ssize_t bytes_sent;
    while ((bytes_sent = splice(pipe_reader->fds[0], NULL, sockfd, NULL, len, SPLICE_F_NONBLOCK)) == -1 && errno == EINTR)
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

void h2o_pipe_reader_send(h2o_req_t *req, h2o_pipe_reader_t *pipe_reader, h2o_send_state_t send_state)
{
    static const h2o_sendvec_callbacks_t callbacks = {.read_ = from_pipe_read, .send_ = from_pipe_send};
    h2o_sendvec_t vec = {.callbacks = &callbacks};
    if ((vec.len = pipe_reader->body_bytes_read - pipe_reader->body_bytes_sent) > H2O_PULL_SENDVEC_MAX_SIZE)
        vec.len = H2O_PULL_SENDVEC_MAX_SIZE;
    vec.cb_arg[0] = (uint64_t)pipe_reader;
    vec.cb_arg[1] = 0; /* unused */

    pipe_reader->body_bytes_sent += vec.len;
    pipe_reader->inflight = 1;
    h2o_sendvec(req, &vec, 1, send_state);
}
