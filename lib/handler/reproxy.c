/*
 * Copyright (c) 2014,2015 DeNA Co., Ltd., Masahiro Nagano
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
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include "h2o.h"
#include "h2o/http1client.h"
#include "h2o/socketpool.h"

typedef struct st_reproxy_filter_t {
    h2o_filter_t super;
} reproxy_filter_t;

typedef struct st_reproxy_ostream_t {
    h2o_ostream_t super;
    h2o_url_t upstream;
    h2o_req_t src_req;
    h2o_http1client_t *client;
    reproxy_filter_t *filter;
} reproxy_ostream_t;

static h2o_http1client_body_cb reproxy_on_head(h2o_http1client_t *client, const char *errstr, int minor_version, int status,
                                       h2o_iovec_t msg, struct phr_header *headers, size_t num_headers)
{
    fprintf(stderr, "reproxy_on_head!\n");
    return NULL;
}

static h2o_http1client_head_cb reproxy_on_connect(h2o_http1client_t *client, const char *errstr, h2o_iovec_t **reqbufs, size_t *reqbufcnt,
                                          int *method_is_head)
{
    reproxy_ostream_t *self = client->data;
fprintf(stderr, "reproxy_on_connect\n");

    if (errstr != NULL) {
        self->client = NULL;
        h2o_send_error(&self->src_req, 502, "Gateway Error", errstr, 0);
        return NULL;
    }

    return reproxy_on_head;
}

static h2o_http1client_head_cb reproxy_on_body(h2o_http1client_t *client, const char *errstr)
{
    reproxy_ostream_t *self = client->data;

    if (errstr != NULL) {
        self->client = NULL;
        h2o_send_error(&self->src_req, 502, "Gateway Error", errstr, 0);
        return NULL;
    }

    return NULL;
}

static void reproxy_send(h2o_ostream_t *_self, h2o_req_t *req) {
    reproxy_ostream_t *self = (void *)_self;
    h2o_url_t upstream = self->upstream;
    h2o_http1client_ctx_t *client_ctx;

    fprintf(stderr, "reproxy_send: ostream: %p, filter: %p\n", self, self->filter);
    client_ctx = h2o_context_get_filter_context(req->conn->ctx, (h2o_filter_t *) self->filter);

    self->client = h2o_http1client_connect(
        client_ctx, &req->pool, h2o_strdup(&req->pool, upstream.host.base, upstream.host.len).base, h2o_url_get_port(&upstream), reproxy_on_connect);
    self->client->data = self;
}

static void *on_context_init(struct st_h2o_filter_t *self, h2o_context_t *ctx) {
    fprintf(stderr, "on_context_init: filter: %p, context: %p\n", self, ctx);
    h2o_http1client_ctx_t *client_ctx = h2o_mem_alloc(sizeof(*ctx) + sizeof(*client_ctx->io_timeout));

    client_ctx->loop = ctx->loop;
    client_ctx->zero_timeout = &ctx->zero_timeout;
    client_ctx->io_timeout = (void *)(client_ctx + 1);
    h2o_timeout_init(client_ctx->loop, client_ctx->io_timeout, 1);

    return client_ctx;
}

static void reproxy_do_send(h2o_ostream_t *_self, h2o_req_t *req, h2o_iovec_t *inbufs, size_t inbufcnt, int is_final)
{
    reproxy_ostream_t *self = (void *)_self;
fprintf(stderr, "reproxy_do_send\n");
    h2o_ostream_send_next(&self->super, req, inbufs, inbufcnt, is_final);
}

static void on_setup_ostream(h2o_filter_t *self, h2o_req_t *req, h2o_ostream_t **slot)
{
    h2o_url_t xru_parsed;
    reproxy_ostream_t *reproxy_ostream;
    size_t header_index = h2o_find_header(&req->res.headers, H2O_TOKEN_X_REPROXY_URL, -1);

    fprintf(stderr, "on_setup_ostream\n");
    /* skip if not x-reproxy-url */
    if (header_index == -1) {
        return;
    }

    /* see if we can parse x-reproxy-url */
    if (h2o_url_parse(req->res.headers.entries[header_index].value.base, req->res.headers.entries[header_index].value.len, &xru_parsed) != 0) {
        return;
    }

    /* We got ourselves a X-Reproxy-URL header. make sure we have
     * "http" scheme, cause that's all we handle
     */
    if (memcmp(xru_parsed.scheme->name.base, "http", xru_parsed.scheme->name.len) != 0) {
        return;
    }

    fprintf(stderr, "found X-Reproxy-URL: %s\n", 
        h2o_url_stringify(&req->pool, &xru_parsed).base);

    /* setup filter */
    reproxy_ostream = (void *)h2o_add_ostream(req, sizeof(reproxy_ostream), slot);
    reproxy_ostream->filter = (void *) self;
    reproxy_ostream->upstream = xru_parsed;

    h2o_init_request(&reproxy_ostream->src_req, req->conn, req);
    reproxy_ostream->super.do_send = reproxy_do_send;
    slot = &reproxy_ostream->super.next;

    reproxy_send((void *) reproxy_ostream, req);

    h2o_setup_next_ostream(self, req, slot);
}

void h2o_reproxy_register(h2o_pathconf_t *pathconf)
{
    // Note to self: *self is stored within pathconf->filters.entries[$tail]
    reproxy_filter_t *self = (void *)h2o_create_filter(pathconf, sizeof(*self));

    // Note to self: on_context_init is called for each thread.
    self->super.on_context_init = on_context_init;
    self->super.on_setup_ostream = on_setup_ostream;
    fprintf(stderr, "h2o_reproxy_register: %p\n", self);
}
