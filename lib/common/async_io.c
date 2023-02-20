/*
 * Copyright (c) 2022,2023 Kazuho Oku, Fastly
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
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#if H2O_USE_IO_URING
#include <liburing.h>
#endif
#include "h2o/socket.h"
#include "h2o/async_io.h"
#include "../probes_.h"

struct st_h2o_io_uring_cmd_t {
    h2o_async_io_cmd_t super;
    struct {
        int filefd, pipefd;
        uint64_t offset;
        size_t len;
    } splice_;
    struct st_h2o_io_uring_cmd_t *next;
};

struct st_h2o_io_uring_queue_t {
    struct st_h2o_io_uring_cmd_t *head;
    struct st_h2o_io_uring_cmd_t **tail;
    size_t size;
};

struct st_h2o_async_io_t {
    h2o_loop_t *loop;
    struct io_uring uring;
    h2o_socket_t *sock_notify;
    struct st_h2o_io_uring_queue_t submission, completion;
    h2o_timer_t delayed;
};

size_t h2o_io_uring_batch_size = 1;

static void init_queue(struct st_h2o_io_uring_queue_t *queue);
static void on_notify(h2o_socket_t *_sock, const char *err);
static void on_delayed(h2o_timer_t *timer);

void init_queue(struct st_h2o_io_uring_queue_t *queue)
{
    queue->head = NULL;
    queue->tail = &queue->head;
    queue->size = 0;
}

static void insert_queue(struct st_h2o_io_uring_queue_t *queue, struct st_h2o_io_uring_cmd_t *cmd)
{
    assert(cmd->next == NULL);
    *queue->tail = cmd;
    queue->tail = &cmd->next;
    ++queue->size;
}

static struct st_h2o_io_uring_cmd_t *pop_queue(struct st_h2o_io_uring_queue_t *queue)
{
    struct st_h2o_io_uring_cmd_t *popped;

    if ((popped = queue->head) != NULL) {
        if ((queue->head = popped->next) == NULL)
            queue->tail = &queue->head;
        --queue->size;
        popped->next = NULL;
    }
    return popped;
}

static int submit_commands(h2o_loop_t *loop, int can_delay)
{
    if (can_delay && loop->_async_io->submission.size < h2o_io_uring_batch_size)
        return 0;

    int made_progress = 0;

    while (loop->_async_io->submission.head != NULL) {
        struct io_uring_sqe *sqe;
        if ((sqe = io_uring_get_sqe(&loop->_async_io->uring)) == NULL)
            break;
        struct st_h2o_io_uring_cmd_t *cmd = pop_queue(&loop->_async_io->submission);
        assert(cmd != NULL);
        io_uring_prep_splice(sqe, cmd->splice_.filefd, cmd->splice_.offset, cmd->splice_.pipefd, -1, cmd->splice_.len, 0);
        sqe->user_data = (uint64_t)cmd;
        made_progress = 1;
    }

    if (made_progress) {
        int ret;
        while ((ret = io_uring_submit(&loop->_async_io->uring)) == -EINTR)
            ;
        if (ret < 0)
            h2o_fatal("io_uring_submit:%s", strerror(-ret));
    }

    return made_progress;
}

static int check_completion(h2o_loop_t *loop, struct st_h2o_io_uring_cmd_t *cmd_sync)
{
    int cmd_sync_done = 0, ret;

    while (1) {
        struct st_h2o_io_uring_cmd_t *cmd;
        int res;

        { /* obtain completed command and its result */
            struct io_uring_cqe *cqe;
            while ((ret = io_uring_peek_cqe(&loop->_async_io->uring, &cqe)) == -EINTR)
                ;
            if (ret != 0)
                break;
            cmd = (struct st_h2o_io_uring_cmd_t *)cqe->user_data;
            res = cqe->res;
            io_uring_cqe_seen(&loop->_async_io->uring, cqe);
        }

        /* Check error. Or if partial read, schedule read of the remainder. */
        if (res != cmd->splice_.len) {
            assert(res < cmd->splice_.len);
            if (res > 0) {
                cmd->splice_.offset += res;
                cmd->splice_.len -= res;
                insert_queue(&loop->_async_io->submission, cmd);
                if (!h2o_timer_is_linked(&loop->_async_io->delayed))
                    h2o_timer_link(loop, 0, &loop->_async_io->delayed);
                continue;
            } else {
                cmd->super.err = h2o_socket_error_io; /* TODO notify partial read / eos? */
            }
        }

        /* link to completion list or indicate to the caller that `cmd_sync` has completed */
        if (cmd == cmd_sync) {
            cmd_sync_done = 1;
        } else {
            insert_queue(&loop->_async_io->completion, cmd);
        }
    }

    return cmd_sync_done;
}

static int dispatch_completed(h2o_loop_t *loop)
{
    if (loop->_async_io->completion.head == NULL)
        return 0;

    do {
        struct st_h2o_io_uring_cmd_t *cmd = pop_queue(&loop->_async_io->completion);
        H2O_PROBE(ASYNC_IO_END, cmd);
        cmd->super.cb.func(&cmd->super);
        free(cmd);
    } while (loop->_async_io->completion.head != NULL);
    return 1;
}

static struct st_h2o_io_uring_cmd_t *start_command(h2o_loop_t *loop, struct st_h2o_io_uring_cmd_t *cmd)
{
    insert_queue(&loop->_async_io->submission, cmd);

    /* Submit enqueued commands as much as possible, then read completed ones as much as possible. The hope here is that the read
     * command generated right above gets issued and completes synchronously, which would be likely when the file is buffer cache.
     * If that is the case, call the callback synchronously. */
    if (submit_commands(loop, 1)) {
        if (check_completion(loop, cmd)) {
            cmd->super.cb.func(&cmd->super);
            free(cmd);
            cmd = NULL;
        }
    } else if (!h2o_timer_is_linked(&loop->_async_io->delayed)) {
        h2o_timer_link(loop, 0, &loop->_async_io->delayed);
    }

    return cmd;
}

void h2o_async_io_splice_file(h2o_async_io_cmd_t **_cmd, h2o_loop_t *loop, int _filefd, uint64_t _offset, int _pipefd, size_t _len,
                              h2o_async_io_cb _cb, void *_data)
{
    /* build command */
    struct st_h2o_io_uring_cmd_t *cmd = h2o_mem_alloc(sizeof(*cmd));
    *cmd = (struct st_h2o_io_uring_cmd_t){
        .super = {.cb = {.func = _cb, .data = _data}},
        .splice_ = {
            .filefd = _filefd,
            .pipefd = _pipefd,
            .offset = _offset,
            .len = _len,
        },
    };

    cmd = start_command(loop, cmd);

    *_cmd = &cmd->super;
    if (cmd != NULL)
        H2O_PROBE(ASYNC_IO_START_SPLICE_FILE, cmd);
}

int h2o_async_io_can_splice(void)
{
    return 1;
}

static void run_uring(h2o_loop_t *loop)
{
    /* Repeatedly read cqe, until we bocome certain we haven't issued more read commands. */
    do {
        check_completion(loop, NULL);
    } while (dispatch_completed(loop) || submit_commands(loop, 0));

    assert(loop->_async_io->completion.head == NULL);
}

void on_notify(h2o_socket_t *sock, const char *err)
{
    assert(err == NULL);

    h2o_loop_t *loop = h2o_socket_get_loop(sock);
    run_uring(loop);
}

void on_delayed(h2o_timer_t *_timer)
{
    struct st_h2o_async_io_t *async_io = H2O_STRUCT_FROM_MEMBER(struct st_h2o_async_io_t, delayed, _timer);
    h2o_loop_t *loop = async_io->loop;

    run_uring(loop);
}

void h2o_async_io_setup(h2o_loop_t *loop)
{
    loop->_async_io = h2o_mem_alloc(sizeof(*loop->_async_io));
    loop->_async_io->loop = loop;

    int ret;
    if ((ret = io_uring_queue_init(16, &loop->_async_io->uring, 0)) != 0)
        h2o_fatal("io_uring_queue_init:%s", strerror(-ret));

    loop->_async_io->sock_notify = h2o_evloop_socket_create(loop, loop->_async_io->uring.ring_fd, H2O_SOCKET_FLAG_DONT_READ);
    h2o_socket_read_start(loop->_async_io->sock_notify, on_notify);

    init_queue(&loop->_async_io->submission);
    init_queue(&loop->_async_io->completion);
    h2o_timer_init(&loop->_async_io->delayed, on_delayed);
}
