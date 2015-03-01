/*
 * Copyright (c) 2014,2015 DeNA Co., Ltd., Kazuho Oku, Daisuke Maki
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
#include "h2o.h"

struct st_reproxy_args_t {
    h2o_timeout_entry_t timeout;
    h2o_req_t *req;
    h2o_iovec_t authority;
    h2o_iovec_t path;
};

static void on_timeout(h2o_timeout_entry_t *entry)
{
    struct st_reproxy_args_t *args = H2O_STRUCT_FROM_MEMBER(struct st_reproxy_args_t, timeout, entry);
    h2o_req_t *req = args->req;

    req->method = h2o_iovec_init(H2O_STRLIT("GET"));
    req->authority = args->authority;
    req->path = args->path;
    req->overrides = NULL;
    req->res_is_delegated |= 1;

    h2o_reprocess_request(req);
}

static void on_send(h2o_ostream_t *self, h2o_req_t *req, h2o_iovec_t *inbufs, size_t inbufcnt, int is_final)
{
    /* nothing to do */
}

static void on_setup_ostream(h2o_filter_t *self, h2o_req_t *req, h2o_ostream_t **slot)
{
    h2o_url_t xru_parsed;
    size_t xru_index = h2o_find_header(&req->res.headers, H2O_TOKEN_X_REPROXY_URL, -1);

    /* skip if not x-reproxy-url */
    if (xru_index == -1)
        goto Next;

    /* see if we can parse x-reproxy-url */
    if (h2o_url_parse(req->res.headers.entries[xru_index].value.base, req->res.headers.entries[xru_index].value.len, &xru_parsed) !=
        0)
        goto Next;

    /* We got ourselves a X-Reproxy-URL header. make sure we have
     * "http" scheme, cause that's all we handle
     */
    if (xru_parsed.scheme != &H2O_URL_SCHEME_HTTP)
        goto Next;

    /* schedule the reprocessing */
    struct st_reproxy_args_t *args = h2o_mem_alloc_pool(&req->pool, sizeof(*args));
    *args = (struct st_reproxy_args_t){
        {0, on_timeout},      /* timeout */
        req,                  /* req */
        xru_parsed.authority, /* authority */
        xru_parsed.path       /* path */
    };
    h2o_timeout_link(req->conn->ctx->loop, &req->conn->ctx->zero_timeout, &args->timeout);

    /* setup filter (that swallows the response until the timeout gets fired) */
    h2o_ostream_t *ostream = h2o_add_ostream(req, sizeof(*ostream), slot);
    ostream->do_send = on_send;
    return;

Next: /* just bypass to the next filter */
    h2o_setup_next_ostream(self, req, slot);
}

void h2o_reproxy_register(h2o_pathconf_t *pathconf)
{
    h2o_filter_t *self = h2o_create_filter(pathconf, sizeof(*self));
    self->on_setup_ostream = on_setup_ostream;
}
