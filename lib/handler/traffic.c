#include <stdlib.h>
#include "h2o.h"

#ifndef BUF_SIZE
#define BUF_SIZE 65536
#endif

#ifndef SECOND_MS
#define SECOND_MS 1000
#endif

typedef H2O_VECTOR(h2o_iovec_t) iovec_vector_t;

typedef struct st_traffic_shaper_t {
    h2o_ostream_t super;
    h2o_timeout_t *timeout;
    size_t speed;
    h2o_timeout_entry_t timeout_entry;
    size_t token; /* a simple token bucket w/ size 1 */
    h2o_context_t *ctx;
    struct {
        h2o_req_t *req;
        iovec_vector_t bufs;
        size_t inbufcnt;
        int is_final;
    } state;
} traffic_shaper_t;

static void real_send(traffic_shaper_t *self) {
    /* a really simple token bucket implementation */
    assert(self->token);

    self->token--;
    h2o_ostream_send_next(&self->super, self->state.req, self->state.bufs.entries,
                          self->state.inbufcnt, self->state.is_final);
}

static void expand_buf(h2o_mem_pool_t *pool, iovec_vector_t *bufs, int count) {
    assert(bufs->size < count);
    size_t i;

    h2o_vector_reserve(pool, (void *)bufs, sizeof(bufs->entries[0]), count);

    for (i = bufs->size; i < count; ++i) {
        bufs->entries[i] = h2o_iovec_init(h2o_mem_alloc_pool(pool, BUF_SIZE), 0);
    }
    bufs->size = count;
}

static void add_token(h2o_timeout_entry_t *entry) {
    traffic_shaper_t *shaper = H2O_STRUCT_FROM_MEMBER(traffic_shaper_t, timeout_entry, entry);
    if (shaper->token == 0) {
        shaper->token = 1;
    }
    real_send(shaper);
    h2o_timeout_link(shaper->ctx->loop, shaper->timeout, &shaper->timeout_entry);
}

static void on_send(h2o_ostream_t *_self, h2o_req_t *req, h2o_iovec_t *inbufs, size_t inbufcnt, int is_final) {
    traffic_shaper_t *self = (void *)_self;
    size_t i;

    /* I don't know if this is a proper way. */
    if (self->timeout == NULL) {
        size_t buf_interval;
        self->timeout = h2o_mem_alloc(sizeof(*self->timeout));
        buf_interval = req->preferred_chunk_size * SECOND_MS / self->speed;
        h2o_timeout_init(self->ctx->loop, self->timeout, buf_interval);
        h2o_timeout_link(self->ctx->loop, self->timeout, &self->timeout_entry);
    }

    if (self->state.bufs.size < inbufcnt) {
        expand_buf(&req->pool, &self->state.bufs, inbufcnt);
    }

    /* start to save state */
    self->state.req = req;
    for (i = 0; i < inbufcnt; ++i) {
        self->state.bufs.entries[i] = inbufs[i];
    }
    self->state.inbufcnt = inbufcnt;
    self->state.is_final = is_final;

    /* if there's token, we send */
    if (self->token) {
        real_send(self);
    }
}

static void deferred_dispose(h2o_timeout_entry_t *entry) {
    traffic_shaper_t *self = H2O_STRUCT_FROM_MEMBER(traffic_shaper_t, timeout_entry, entry);
    h2o_timeout_dispose(self->ctx->loop, self->timeout);
    free(self->timeout);
}

static void on_stop(h2o_ostream_t *_self, h2o_req_t *req) {
    traffic_shaper_t *self = (void *)_self;
    if (h2o_timeout_is_linked(&self->timeout_entry)) {
        h2o_timeout_unlink(&self->timeout_entry);
    }
    self->timeout_entry = (h2o_timeout_entry_t){};
    self->timeout_entry.cb = deferred_dispose;
    h2o_timeout_link(self->ctx->loop, &self->ctx->zero_timeout, &self->timeout_entry);
}

static void on_setup_ostream(h2o_filter_t *self, h2o_req_t *req, h2o_ostream_t **slot) {
    traffic_shaper_t *shaper;
    h2o_iovec_t traffic_header_value;
    size_t traffic_limit, buf_interval;

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

    /* first check if we can limit speed at our max preferred chunk size */
    buf_interval = BUF_SIZE * SECOND_MS / traffic_limit;
    if (buf_interval == 0)
        goto Next;

    if (req->preferred_chunk_size > BUF_SIZE)
        req->preferred_chunk_size = BUF_SIZE;

    /* if traffic limit is over preferred_chunk_size * 1000 B/s, then we cannot limit speed in this way */
    if (buf_interval == 0)
        goto Next;

    h2o_delete_header(&req->res.headers, xt_index);

    shaper = (void *)h2o_add_ostream(req, sizeof(traffic_shaper_t), slot);
    shaper->super.do_send = on_send;
    shaper->super.stop = on_stop;
    shaper->ctx = req->conn->ctx;
    shaper->state.bufs.capacity = 0;
    shaper->state.bufs.size = 0;
    shaper->timeout_entry = (h2o_timeout_entry_t){};
    shaper->timeout_entry.cb = add_token;
    shaper->token = 1;
    shaper->speed = traffic_limit;
    shaper->timeout = NULL;
    slot = &shaper->super.next;


  Next:
    h2o_setup_next_ostream(req, slot);
}

void h2o_traffic_register(h2o_pathconf_t *pathconf) {
    h2o_filter_t *self = h2o_create_filter(pathconf, sizeof(*self));
    self->on_setup_ostream = on_setup_ostream;
}
