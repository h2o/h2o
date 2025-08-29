#ifndef __H2O__PIPE_UTILS__H__
#define __H2O__PIPE_UTILS__H__

#include "h2o.h"

typedef struct st_h2o_pipe_reader_t {
    int fds[2]; /* fd[0] set to -1 unless used */
    int inflight;

    size_t bytes_read, bytes_sent;
} h2o_pipe_reader_t;

void h2o_pipe_reader_send(h2o_req_t *req, h2o_pipe_reader_t *reader, h2o_send_state_t send_state);

void h2o_pipe_reader_init(h2o_pipe_reader_t *reader);

int h2o_pipe_reader_new(h2o_context_t *ctx, h2o_pipe_reader_t *reader);

int h2o_pipe_reader_start(h2o_context_t *ctx, h2o_pipe_reader_t *reader);

void h2o_pipe_reader_dispose(h2o_context_t *ctx, h2o_pipe_reader_t *reader);

int h2o_pipe_reader_is_empty(h2o_pipe_reader_t *reader);

void h2o_pipe_reader_update(h2o_pipe_reader_t *reader, size_t read_bytes);

static inline int h2o_pipe_reader_in_use(h2o_pipe_reader_t *reader)
{
    return reader->fds[0] != -1;
}

#endif /* __H2O__PIPE_UTILS__H__ */
