#include "h2o.h"

#include <stddef.h>

struct my_generator {
    h2o_generator_t super;
    size_t counter;
};

static void on_generator_proceed(h2o_generator_t *opaque, h2o_req_t *req)
{
    struct my_generator *self = (void *)opaque;
    if (self->counter++ != 0) {
        h2o_iovec_t iov = h2o_iovec_init(H2O_STRLIT("world"));
        h2o_send(req, &iov, 1, H2O_SEND_STATE_FINAL);
    } else if (h2o_memis(req->input.path.base, req->input.path.len, H2O_STRLIT("/zero"))) {
        h2o_send(req, NULL, 0, H2O_SEND_STATE_IN_PROGRESS);
    } else if (h2o_memis(req->input.path.base, req->input.path.len, H2O_STRLIT("/empty"))) {
        h2o_iovec_t iov = h2o_iovec_init(NULL, 0);
        h2o_send(req, &iov, 1, H2O_SEND_STATE_IN_PROGRESS);
    } else {
        h2o_iovec_t iov = h2o_iovec_init(H2O_STRLIT("unknown path"));
        h2o_send(req, &iov, 1, H2O_SEND_STATE_FINAL);
    }
}

static int on_req(h2o_handler_t *_self, h2o_req_t *req)
{
    req->res.status = 200;
    req->res.headers = (h2o_headers_t){};
    req->res.content_length = SIZE_MAX;
    struct my_generator *generator = h2o_mem_alloc_pool(&req->pool, struct my_generator, 1);
    *generator = (struct my_generator){.super = {.proceed = on_generator_proceed}};
    h2o_start_response(req, &generator->super);
    h2o_iovec_t iov = h2o_iovec_init(H2O_STRLIT("hello "));
    h2o_send(req, &iov, 1, H2O_SEND_STATE_IN_PROGRESS);
    return 0;
}

h2o_handler_t *h2o_mishandler_register(h2o_pathconf_t *pathconf)
{
    h2o_handler_t *self = h2o_create_handler(pathconf, sizeof(*self));
    self->on_req = on_req;
    return self;
}
