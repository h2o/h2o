/*
 * Copyright (c) 2016 DeNA Co., Ltd., Kazuho Oku
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

struct st_h2o_status_handler_t {
    h2o_handler_t super;
    h2o_logconf_t *logconf;
};

struct st_status_context_t {
    struct st_h2o_status_handler_t *handler;
    h2o_buffer_t *buffer;
};

static int collect_req_status(h2o_req_t *req, void *cbdata)
{
    struct st_status_context_t *ctx = cbdata;

    /* collect log */
    char buf[4096];
    size_t len = sizeof(buf);
    char *logline = h2o_log_request(ctx->handler->logconf, req, &len, buf);

    /* append to buffer */
    h2o_buffer_reserve(&ctx->buffer, len);
    memcpy(ctx->buffer->bytes + ctx->buffer->size, logline, len);
    ctx->buffer->size += len;

    if (logline != buf)
        free(logline);

    return 0;
}

static int on_req(h2o_handler_t *_self, h2o_req_t *req)
{
    struct st_h2o_status_handler_t *self = (void *)_self;
    struct st_status_context_t ctx = {self};
    static h2o_generator_t generator = {NULL, NULL};

    h2o_buffer_init(&ctx.buffer, &h2o_socket_buffer_prototype);
    req->conn->ctx->globalconf->http2.callbacks.foreach_request(req->conn->ctx, collect_req_status, &ctx);

    h2o_buffer_link_to_pool(ctx.buffer, &req->pool);

    req->res.status = 200;
    req->res.content_length = ctx.buffer->size;
    h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_CONTENT_TYPE, H2O_STRLIT("text/plain; charset=utf-8"));

    h2o_start_response(req, &generator);
    if (h2o_memis(req->input.method.base, req->input.method.len, H2O_STRLIT("HEAD"))) {
        h2o_send(req, NULL, 0, 1);
    } else {
        h2o_iovec_t resp = h2o_iovec_init(ctx.buffer->bytes, ctx.buffer->size);
        h2o_send(req, &resp, 1, 1);
    }

    return 0;
}

void on_dispose(h2o_handler_t *_self)
{
    struct st_h2o_status_handler_t *self = (void *)_self;
    h2o_logconf_dispose(self->logconf);
}

void h2o_status_register(h2o_pathconf_t *pathconf)
{
    struct st_h2o_status_handler_t *self = (void *)h2o_create_handler(pathconf, sizeof(*self));
    char errbuf[256];

    self->super.on_req = on_req;
    self->super.dispose = on_dispose;
    if ((self->logconf = h2o_logconf_compile("%h %l %u %t \"%r\" %s %b \"%{Referer}i\" \"%{User-agent}i\"", H2O_LOGCONF_ESCAPE_JSON,
                                             errbuf)) == NULL) {
        fprintf(stderr, "%s\n", errbuf);
        h2o_fatal("[status] failed to compile log format:%s\n");
    }
}
