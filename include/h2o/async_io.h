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
#ifndef h2o__async_io_h
#define h2o__async_io_h

#include "h2o/filecache.h"

typedef struct st_h2o_async_io_t h2o_async_io_t;
typedef struct st_h2o_async_io_cmd_t h2o_async_io_cmd_t;
typedef void (*h2o_async_io_cb)(h2o_async_io_cmd_t *);

struct st_h2o_async_io_cmd_t {
    struct {
        h2o_async_io_cb func;
        void *data;
    } cb;
    /**
     * result
     */
    const char *err;
};

#if H2O_USE_IO_URING
extern size_t h2o_io_uring_batch_size;
#endif

/**
 * initializes structure related to async I/O of `loop`
 */
void h2o_async_io_setup(h2o_loop_t *loop);
/**
 * Reads file without blocking. Read can complete either synchronously or asynchronously.
 * @param cmd  Upon return, `*cmd` points to an object referring to the read operation inflight. If the read completed
 *             synchronously, `*cmd` is set to NULL.
 * @param cb   Callback function to be invoked when read is complete. This callback can get called synchronously.
 */
void h2o_async_io_read_file(h2o_async_io_cmd_t **cmd, h2o_loop_t *loop, h2o_filecache_ref_t *fileref, uint64_t offset,
                            h2o_iovec_t dst, h2o_async_io_cb cb, void *data);

#endif
