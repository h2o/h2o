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
#ifndef h2o__io_uring_h
#define h2o__io_uring_h

#if !H2O_USE_IO_URING
#error "this file may be included only when io_uring support is available"
#endif

#include <liburing.h>

typedef struct st_h2o_io_uring_cmd_t h2o_io_uring_cmd_t;
typedef void (*h2o_io_uring_cb)(h2o_io_uring_cmd_t *);

struct st_h2o_io_uring_queue_t {
    struct st_h2o_io_uring_cmd_t *head;
    struct st_h2o_io_uring_cmd_t **tail;
    size_t size;
};

typedef struct st_h2o_io_uring_t {
    struct io_uring uring;
    h2o_socket_t *sock_notify;
    struct st_h2o_io_uring_queue_t submission, completion;
    h2o_timer_t delayed;
} h2o_io_uring_t;

/**
 * Object used for buffering and tracking requests to io_uring. It is defined here as a public type, because h2o-probes.d referes to
 * the type, in addition to io_uring.c.
 */
struct st_h2o_io_uring_cmd_t {
    struct {
        h2o_io_uring_cb func;
        void *data;
    } cb;
    int result;
    struct st_h2o_io_uring_cmd_t *next;
    struct {
        int fd_in;
        int64_t off_in;
        int fd_out;
        int64_t off_out;
        unsigned nbytes;
        unsigned splice_flags;
    } splice_;
};

extern size_t h2o_io_uring_batch_size;

/**
 * initializes structure related to async I/O of `loop`
 */
void h2o_io_uring_init(h2o_loop_t *loop);
/**
 * Calls splice using io_uring. The callback might get called synchronously, depending on the condition (e.g., if data being read is
 * in page cache and h2o_io_uring_batch_size == 1).
 */
void h2o_io_uring_splice(h2o_loop_t *loop, int fd_in, int64_t off_in, int fd_out, int64_t off_out, unsigned nbytes,
                         unsigned splice_flags, h2o_io_uring_cb cb, void *data);

#endif
