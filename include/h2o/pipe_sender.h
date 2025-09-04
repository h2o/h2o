/*
 * Copyright (c) 2022-2025 Fastly, Kazuho Oku
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
#ifndef h2o__pipe_sender_h
#define h2o__pipe_sender_h

#include "h2o.h"

typedef struct st_h2o_pipe_sender_t {
    /**
     * the pipe fds; they are set to -1 until started
     */
    int fds[2];
    /**
     * if the contents of the pipe is "inflight"; i.e., passed to the protocol handler via `h2o_sendvec`
     */
    int inflight;
    /**
     * cumulative bytes being read
     */
    size_t bytes_read;
    /**
     * cumulative bytes being sent; when `h2o_pipe_sender_send` is called, `bytes_read - bytes_sent` is the amount of data assumed
     * to be in the pipe
     */
    size_t bytes_sent;
} h2o_pipe_sender_t;

/**
 * initialized the pipe sender
 */
static void h2o_pipe_sender_init(h2o_pipe_sender_t *sender);
/**
 * disposes of the pipe sender
 */
void h2o_pipe_sender_dispose(h2o_pipe_sender_t *sender, h2o_context_t *ctx);
/**
 * if the pipe has been allocated
 */
static int h2o_pipe_sender_in_use(h2o_pipe_sender_t *sender);
/**
 * if there is any data to be sent
 */
static int h2o_pipe_sender_is_empty(h2o_pipe_sender_t *sender);
/**
 * starts a pipe sender and returns a boolean indicating success
 */
int h2o_pipe_sender_start(h2o_context_t *ctx, h2o_pipe_sender_t *sender);
/**
 * notifies the pipe sender that new data has become available
 */
static void h2o_pipe_sender_update(h2o_pipe_sender_t *sender, size_t read_bytes);
/**
 * wrapper function of `h2o_sendvec` that submits the contents of the pipe
 */
void h2o_pipe_sender_send(h2o_req_t *req, h2o_pipe_sender_t *sender, h2o_send_state_t send_state);

/* inline definitions */

inline void h2o_pipe_sender_init(h2o_pipe_sender_t *sender)
{
    *sender = (h2o_pipe_sender_t){.fds = {-1, -1}};
}

inline int h2o_pipe_sender_in_use(h2o_pipe_sender_t *sender)
{
    return sender->fds[0] != -1;
}

inline int h2o_pipe_sender_is_empty(h2o_pipe_sender_t *sender)
{
    return sender->bytes_read == sender->bytes_sent;
}

inline void h2o_pipe_sender_update(h2o_pipe_sender_t *sender, size_t read_bytes)
{
    sender->bytes_read = read_bytes;
}

#endif