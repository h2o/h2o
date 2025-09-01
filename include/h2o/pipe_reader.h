#ifndef __H2O__PIPE_UTILS__H__
#define __H2O__PIPE_UTILS__H__

#include "h2o.h"

typedef struct st_h2o_pipe_reader_t {
    /**
     * the pipe fds; they are set to -1 until started
     */
    int fds[2];
    /**
     * if the contents of the pipe is "inflight"; i.e., passed to the protocol handler via `h2o_sendvec`
     */
    int inflight;
    /**
     * cumulative bytes being read to the pipe
     */
    size_t bytes_read;
    /**
     * cumulative bytes being passed to `h2o_sendvec`
     */
    size_t bytes_sent;
} h2o_pipe_reader_t;

/**
 * wrapper function of `h2o_sendvec` that submits the contents of the pipe
 */
void h2o_pipe_reader_send(h2o_req_t *req, h2o_pipe_reader_t *reader, h2o_send_state_t send_state);
/**
 * initialized the pipe reader
 */
void h2o_pipe_reader_init(h2o_pipe_reader_t *reader);
/**
 * starts a pipe reader and returns a boolean indicating success
 */
int h2o_pipe_reader_start(h2o_context_t *ctx, h2o_pipe_reader_t *reader);
/**
 * disposes of the pipe reader
 */
void h2o_pipe_reader_dispose(h2o_context_t *ctx, h2o_pipe_reader_t *reader);
/**
 * if there is any data to be sent
 */
int h2o_pipe_reader_is_empty(h2o_pipe_reader_t *reader);
/**
 * notifies the pipe reader that new data has become available
 */
void h2o_pipe_reader_update(h2o_pipe_reader_t *reader, size_t read_bytes);
/**
 * if the pipe has been allocated
 */
static int h2o_pipe_reader_in_use(h2o_pipe_reader_t *reader);

/* inline definitions */

static inline int h2o_pipe_reader_in_use(h2o_pipe_reader_t *reader)
{
    return reader->fds[0] != -1;
}

#endif /* __H2O__PIPE_UTILS__H__ */
