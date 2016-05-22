#include <stdlib.h>
#include "h2o.h"

#ifndef HUNDRED_MS
#define HUNDRED_MS 100
#endif

#ifndef ONE_SECOND
#define ONE_SECOND 1000
#endif

typedef H2O_VECTOR(h2o_iovec_t) iovec_vector_t;

typedef struct st_traffic_shaper_t {
    h2o_ostream_t super;
    h2o_timeout_entry_t timeout_entry;
    size_t tokens;
    size_t token_inc;
    h2o_context_t *ctx;
    h2o_req_t *req;
    struct {
        iovec_vector_t bufs;
        size_t inbufcnt;
        int is_final;
    } state;
} traffic_shaper_t;

static int real_send(traffic_shaper_t *self) {
    /* a really simple token bucket implementation */
    assert(self->tokens);
    size_t i, token_consume;

    token_consume = 0;

    for (i = 0; i < self->state.inbufcnt; i++) {
        if (self->state.bufs.entries[i].len > self->tokens - token_consume) {
            return 0;
        }
        token_consume += self->state.bufs.entries[i].len;
    }

    self->tokens -= token_consume;

    h2o_ostream_send_next(&self->super, self->req, self->state.bufs.entries,
                          self->state.inbufcnt, self->state.is_final);
    return self->state.is_final;
}

static inline void expand_buf(h2o_mem_pool_t *pool, iovec_vector_t *bufs, size_t count) {
    assert(bufs->size < count);
    h2o_vector_reserve(pool, bufs, count);
    bufs->size = count;
}

static void add_token(h2o_timeout_entry_t *entry) {
    traffic_shaper_t *shaper = H2O_STRUCT_FROM_MEMBER(traffic_shaper_t, timeout_entry, entry);
    shaper->tokens += shaper->token_inc;

    if (!real_send(shaper))
        h2o_timeout_link(shaper->ctx->loop, &shaper->ctx->hundred_ms_timeout, &shaper->timeout_entry);
}

static void on_send(h2o_ostream_t *_self, h2o_req_t *req, h2o_iovec_t *inbufs, size_t inbufcnt, int is_final) {
    traffic_shaper_t *self = (void *)_self;
    size_t i;

    /* I don't know if this is a proper way. */
    if (!h2o_timeout_is_linked(&self->timeout_entry)) {
        h2o_timeout_link(self->ctx->loop, &self->ctx->hundred_ms_timeout, &self->timeout_entry);
    }

    if (self->state.bufs.size < inbufcnt) {
        expand_buf(&req->pool, &self->state.bufs, inbufcnt);
    }

    /* start to save state */
    for (i = 0; i < inbufcnt; ++i) {
        self->state.bufs.entries[i] = inbufs[i];
    }
    self->state.inbufcnt = inbufcnt;
    self->state.is_final = is_final;

    /* if there's token, we try to send */
    if (self->tokens) {
        if(real_send(self) && h2o_timeout_is_linked(&self->timeout_entry))
            h2o_timeout_unlink(&self->timeout_entry);
    }
}

static void on_stop(h2o_ostream_t *_self, h2o_req_t *req) {
    traffic_shaper_t *self = (void *)_self;
    if (h2o_timeout_is_linked(&self->timeout_entry)) {
        h2o_timeout_unlink(&self->timeout_entry);
    }
}

static void on_setup_ostream(h2o_filter_t *self, h2o_req_t *req, h2o_ostream_t **slot) {
    traffic_shaper_t *shaper;
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

    shaper = (void *)h2o_add_ostream(req, sizeof(traffic_shaper_t), slot);

    /* calculate the token increment per 100ms */
    shaper->token_inc = traffic_limit * HUNDRED_MS / ONE_SECOND;
    if (req->preferred_chunk_size > shaper->token_inc)
        req->preferred_chunk_size = shaper->token_inc;

    h2o_delete_header(&req->res.headers, xt_index);

    shaper->super.do_send = on_send;
    shaper->super.stop = on_stop;
    shaper->ctx = req->conn->ctx;
    shaper->req = req;
    shaper->state.bufs.capacity = 0;
    shaper->state.bufs.size = 0;
    shaper->timeout_entry = (h2o_timeout_entry_t){};
    shaper->timeout_entry.cb = add_token;
    shaper->tokens = shaper->token_inc;
    slot = &shaper->super.next;

  Next:
    h2o_setup_next_ostream(req, slot);
}

void h2o_traffic_register(h2o_pathconf_t *pathconf) {
    h2o_filter_t *self = h2o_create_filter(pathconf, sizeof(*self));
    self->on_setup_ostream = on_setup_ostream;
}
