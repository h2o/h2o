/*
 * Copyright (c) 2015 DeNA Co., Ltd., Kazuho Oku
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

struct st_h2o_redirect_handler_t {
    h2o_handler_t super;
    int status;
    h2o_iovec_t prefix;
};

static void on_dispose(h2o_handler_t *_self)
{
    h2o_redirect_handler_t *self = (void *)_self;
    free(self->prefix.base);
}

static int on_req(h2o_handler_t *_self, h2o_req_t *req)
{
    h2o_redirect_handler_t *self = (void *)_self;

    /* build the URL */
    h2o_iovec_t path =
        h2o_iovec_init(req->path_normalized.base + req->pathconf->path.len, req->path_normalized.len - req->pathconf->path.len);
    h2o_iovec_t query = req->input.query_at != SIZE_MAX
                            ? h2o_iovec_init(req->input.path.base + req->input.query_at, req->input.path.len - req->input.query_at)
                            : h2o_iovec_init(H2O_STRLIT(""));
    h2o_iovec_t dest = h2o_concat(&req->pool, self->prefix, path, query);

    /* respond with a redirect */
    h2o_send_redirect(req, self->status, "Redirected", dest.base, dest.len);

    return 0;
}

h2o_redirect_handler_t *h2o_redirect_register(h2o_pathconf_t *pathconf, int status, const char *prefix)
{
    h2o_redirect_handler_t *self = (void *)h2o_create_handler(pathconf, sizeof(*self));
    self->super.dispose = on_dispose;
    self->super.on_req = on_req;
    self->status = status;
    self->prefix = h2o_strdup(NULL, prefix, SIZE_MAX);
    return self;
}
