/*
 * Copyright (c) 2016 Justin Zhu
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
#include <stdlib.h>
#include "h2o.h"

#ifndef HUNDRED_MS
#define HUNDRED_MS 100
#endif

#ifndef ONE_SECOND
#define ONE_SECOND 1000
#endif

typedef H2O_VECTOR(h2o_iovec_t) iovec_vector_t;

typedef struct st_throttle_resp_t {
    h2o_ostream_t super;
    h2o_timeout_entry_t timeout_entry;
    int64_t tokens;
    size_t token_inc;
    h2o_context_t *ctx;
    h2o_req_t *req;
    struct {
        iovec_vector_t bufs;
        h2o_send_state_t stream_state;
    } state;
} throttle_resp_t;

static void real_send(throttle_resp_t *self)
{
    /* a really simple token bucket implementation */
    assert(self->tokens > 0);
    size_t i, token_consume;

    token_consume = 0;

    for (i = 0; i < self->state.bufs.size; i++) {
        token_consume += self->state.bufs.entries[i].len;
    }

    self->tokens -= token_consume;

    h2o_ostream_send_next(&self->super, self->req, self->state.bufs.entries, self->state.bufs.size, self->state.stream_state);
    if (!h2o_send_state_is_in_progress(self->state.stream_state))
        h2o_timeout_unlink(&self->timeout_entry);
}

static void add_token(h2o_timeout_entry_t *entry)
{
    throttle_resp_t *self = H2O_STRUCT_FROM_MEMBER(throttle_resp_t, timeout_entry, entry);

    h2o_timeout_link(self->ctx->loop, &self->ctx->hundred_ms_timeout, &self->timeout_entry);
    self->tokens += self->token_inc;

    if (self->tokens > 0)
        real_send(self);
}

static void on_send(h2o_ostream_t *_self, h2o_req_t *req, h2o_iovec_t *inbufs, size_t inbufcnt, h2o_send_state_t state)
{
    throttle_resp_t *self = (void *)_self;
    size_t i;

    /* I don't know if this is a proper way. */
    h2o_vector_reserve(&req->pool, &self->state.bufs, inbufcnt);
    /* start to save state */
    for (i = 0; i < inbufcnt; ++i) {
        self->state.bufs.entries[i] = inbufs[i];
    }
    self->state.bufs.size = inbufcnt;
    self->state.stream_state = state;

    /* if there's token, we try to send */
    if (self->tokens > 0)
        real_send(self);
}

static void on_stop(h2o_ostream_t *_self, h2o_req_t *req)
{
    throttle_resp_t *self = (void *)_self;
    if (h2o_timeout_is_linked(&self->timeout_entry)) {
        h2o_timeout_unlink(&self->timeout_entry);
    }
}

static void on_setup_ostream(h2o_filter_t *self, h2o_req_t *req, h2o_ostream_t **slot)
{
    throttle_resp_t *throttle;
    h2o_iovec_t traffic_header_value;
    size_t traffic_limit;

    if (req->res.status != 200)
        goto Next;
    if (h2o_memis(req->input.method.base, req->input.method.len, H2O_STRLIT("HEAD")))
        goto Next;

    ssize_t xt_index;
    if ((xt_index = h2o_find_header(&req->res.headers, H2O_TOKEN_X_TRAFFIC, -1)) == -1)
        goto Next;

    traffic_header_value = req->res.headers.entries[xt_index].value;
    char *buf = traffic_header_value.base;

    if (H2O_UNLIKELY((traffic_limit = h2o_strtosizefwd(&buf, traffic_header_value.len)) == SIZE_MAX))
        goto Next;

    throttle = (void *)h2o_add_ostream(req, sizeof(throttle_resp_t), slot);

    /* calculate the token increment per 100ms */
    throttle->token_inc = traffic_limit * HUNDRED_MS / ONE_SECOND;
    if (req->preferred_chunk_size > throttle->token_inc)
        req->preferred_chunk_size = throttle->token_inc;

    h2o_delete_header(&req->res.headers, xt_index);

    throttle->super.do_send = on_send;
    throttle->super.stop = on_stop;
    throttle->ctx = req->conn->ctx;
    throttle->req = req;
    throttle->state.bufs.capacity = 0;
    throttle->state.bufs.size = 0;
    throttle->timeout_entry = (h2o_timeout_entry_t){0};
    throttle->timeout_entry.cb = add_token;
    throttle->tokens = throttle->token_inc;
    slot = &throttle->super.next;

    h2o_timeout_link(throttle->ctx->loop, &throttle->ctx->hundred_ms_timeout, &throttle->timeout_entry);

Next:
    h2o_setup_next_ostream(req, slot);
}

void h2o_throttle_resp_register(h2o_pathconf_t *pathconf)
{
    h2o_filter_t *self = h2o_create_filter(pathconf, sizeof(*self));
    self->on_setup_ostream = on_setup_ostream;
}
