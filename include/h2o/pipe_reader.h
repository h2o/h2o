#ifndef __H2O__PIPE_UTILS__H__
#define __H2O__PIPE_UTILS__H__

#include <stddef.h>
#include <stdbool.h>

enum h2o_send_state;
struct st_h2o_req_t;
struct st_h2o_context_t;

typedef struct st_h2o_pipe_reader_t {
    int fds[2]; /* fd[0] set to -1 unless used */
    int inflight;

    size_t body_bytes_read, body_bytes_sent;
} h2o_pipe_reader_t;

void h2o_pipe_reader_send(struct st_h2o_req_t *req, h2o_pipe_reader_t *pipe_reader, enum h2o_send_state send_state);

void h2o_pipe_reader_init(h2o_pipe_reader_t *pipe_reader);

int h2o_pipe_reader_new(struct st_h2o_context_t *ctx, h2o_pipe_reader_t *pipe_reader);

int h2o_pipe_reader_start(struct st_h2o_context_t *ctx, h2o_pipe_reader_t *pipe_reader);

void h2o_pipe_reader_dispose(struct st_h2o_context_t *ctx, h2o_pipe_reader_t *pipe_reader);

int h2o_pipe_reader_is_empty(h2o_pipe_reader_t *pipe_reader);

void h2o_pipe_reader_update(h2o_pipe_reader_t *pipe_reader, size_t read_body_bytes);

static inline int h2o_pipe_reader_in_use(h2o_pipe_reader_t *pipe_reader)
{
    return pipe_reader->fds[0] != -1;
}

#endif /* __H2O__PIPE_UTILS__H__ */
