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
#include <fcntl.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include "h2o/socket.h"
#include "h2o/io_uring.h"
#include "../probes_.h"

size_t h2o_io_uring_batch_size = 1;

static void init_queue(struct st_h2o_io_uring_queue_t *queue)
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

static int submit_commands(struct st_h2o_io_uring_t *io_uring, int can_delay)
{
    if (can_delay && io_uring->submission.size < h2o_io_uring_batch_size)
        return 0;

    int made_progress = 0;

    while (io_uring->submission.head != NULL) {
        struct io_uring_sqe *sqe;
        if ((sqe = io_uring_get_sqe(&io_uring->uring)) == NULL)
            break;
        struct st_h2o_io_uring_cmd_t *cmd = pop_queue(&io_uring->submission);
        assert(cmd != NULL);
        H2O_PROBE(IO_URING_SUBMIT, cmd);
        io_uring_prep_splice(sqe, cmd->splice_.fd_in, cmd->splice_.off_in, cmd->splice_.fd_out, cmd->splice_.off_out,
                             cmd->splice_.nbytes, cmd->splice_.splice_flags);
        sqe->user_data = (uint64_t)cmd;
        made_progress = 1;
    }

    if (made_progress) {
        int ret;
        while ((ret = io_uring_submit(&io_uring->uring)) == -EINTR)
            ;
        if (ret < 0)
            h2o_fatal("io_uring_submit:%s", strerror(-ret));
    }

    return made_progress;
}

static int check_completion(struct st_h2o_io_uring_t *io_uring, struct st_h2o_io_uring_cmd_t *cmd_sync)
{
    int cmd_sync_done = 0, ret;

    while (1) {
        struct st_h2o_io_uring_cmd_t *cmd;

        { /* obtain completed command and its result */
            struct io_uring_cqe *cqe;
            while ((ret = io_uring_peek_cqe(&io_uring->uring, &cqe)) == -EINTR)
                ;
            if (ret != 0)
                break;
            cmd = (struct st_h2o_io_uring_cmd_t *)cqe->user_data;
            cmd->result = cqe->res;
            io_uring_cqe_seen(&io_uring->uring, cqe);
        }

        /* link to completion list or indicate to the caller that `cmd_sync` has completed */
        if (cmd == cmd_sync) {
            cmd_sync_done = 1;
        } else {
            insert_queue(&io_uring->completion, cmd);
        }
    }

    return cmd_sync_done;
}

static int dispatch_completed(struct st_h2o_io_uring_t *io_uring)
{
    if (io_uring->completion.head == NULL)
        return 0;

    do {
        struct st_h2o_io_uring_cmd_t *cmd = pop_queue(&io_uring->completion);
        H2O_PROBE(IO_URING_END, cmd);
        cmd->cb.func(cmd);
        free(cmd);
    } while (io_uring->completion.head != NULL);
    return 1;
}

static void start_command(h2o_loop_t *loop, struct st_h2o_io_uring_t *io_uring, struct st_h2o_io_uring_cmd_t *cmd)
{
    int needs_timer = 0;

    insert_queue(&io_uring->submission, cmd);

    submit_commands(io_uring, 1);

    /* if we have submitted all commands up to the current one, fetch completion events in hope that we might be able to complete
     * the current one synchronously (as doing so improves locality) */
    if (io_uring->submission.head == NULL) {
        if (check_completion(io_uring, cmd)) {
            cmd->cb.func(cmd);
            free(cmd);
            cmd = NULL;
        }
        if (io_uring->completion.head != NULL)
            needs_timer = 1;
    } else {
        needs_timer = 1;
    }

    if (needs_timer && !h2o_timer_is_linked(&io_uring->delayed))
        h2o_timer_link(loop, 0, &io_uring->delayed);
}

void h2o_io_uring_splice(h2o_loop_t *loop, int fd_in, int64_t off_in, int fd_out, int64_t off_out, unsigned nbytes,
                         unsigned splice_flags, h2o_io_uring_cb cb, void *data)
{
    struct st_h2o_io_uring_t *io_uring = h2o_evloop__io_uring(loop);

    /* build command */
    struct st_h2o_io_uring_cmd_t *cmd = h2o_mem_alloc(sizeof(*cmd));
    *cmd = (struct st_h2o_io_uring_cmd_t){
        .cb.func = cb,
        .cb.data = data,
        .splice_.fd_in = fd_in,
        .splice_.off_in = off_in,
        .splice_.fd_out = fd_out,
        .splice_.off_out = off_out,
        .splice_.nbytes = nbytes,
        .splice_.splice_flags = splice_flags,
    };
    H2O_PROBE(IO_URING_SPLICE, cmd);

    start_command(loop, io_uring, cmd);
}

static void run_uring(struct st_h2o_io_uring_t *io_uring)
{
    /* Repeatedly read cqe, until we bocome certain we haven't issued more read commands. */
    do {
        check_completion(io_uring, NULL);
    } while (dispatch_completed(io_uring) || submit_commands(io_uring, 0));

    assert(io_uring->completion.head == NULL);
}

static void on_notify(h2o_socket_t *sock, const char *err)
{
    assert(err == NULL);

    h2o_loop_t *loop = h2o_socket_get_loop(sock);
    struct st_h2o_io_uring_t *io_uring = h2o_evloop__io_uring(loop);
    run_uring(io_uring);
}

static void on_delayed(h2o_timer_t *_timer)
{
    struct st_h2o_io_uring_t *io_uring = H2O_STRUCT_FROM_MEMBER(struct st_h2o_io_uring_t, delayed, _timer);
    run_uring(io_uring);
}

void h2o_io_uring_init(h2o_loop_t *loop)
{
    struct st_h2o_io_uring_t *io_uring = h2o_evloop__io_uring(loop);

    int ret;
    if ((ret = io_uring_queue_init(16, &io_uring->uring, 0)) != 0)
        h2o_fatal("io_uring_queue_init:%s", strerror(-ret));

    io_uring->sock_notify = h2o_evloop_socket_create(loop, io_uring->uring.ring_fd, H2O_SOCKET_FLAG_DONT_READ);
    h2o_socket_read_start(io_uring->sock_notify, on_notify);

    init_queue(&io_uring->submission);
    init_queue(&io_uring->completion);
    h2o_timer_init(&io_uring->delayed, on_delayed);
}
