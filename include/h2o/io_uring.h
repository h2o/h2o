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

typedef struct st_h2o_io_uring_t h2o_io_uring_t;
typedef struct st_h2o_io_uring_cmd_t h2o_io_uring_cmd_t;
typedef void (*h2o_io_uring_cb)(h2o_io_uring_cmd_t *);

struct st_h2o_io_uring_cmd_t {
    struct {
        h2o_io_uring_cb func;
        void *data;
    } cb;
    int result;
    struct st_h2o_io_uring_cmd_t *next;
    struct {
        int filefd, pipefd;
        uint64_t offset;
        size_t len;
    } splice_;
};

extern size_t h2o_io_uring_batch_size;

/**
 * initializes structure related to async I/O of `loop`
 */
void h2o_io_uring_setup(h2o_loop_t *loop);
/**
 * Runs `splice` on linux. Buffer size of `outfd` must be large enough to contain `len` bytes.
 */
void h2o_io_uring_splice_file(h2o_io_uring_cmd_t **cmd, h2o_loop_t *loop, int filefd, uint64_t offset, int pipefd, size_t len,
                              h2o_io_uring_cb cb, void *data);

#endif
