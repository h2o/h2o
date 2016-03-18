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
};

struct st_status_context_t {
    h2o_buffer_t *buffer;
    h2o_logconf_t *logconf;
};

static int collect_req_status(h2o_req_t *req, void *cbdata)
{
    struct st_status_context_t *ctx = cbdata;

    /* collect log */
    char buf[4096];
    size_t len = sizeof(buf);
    char *logline = h2o_log_request(ctx->logconf, req, &len, buf);

    /* append to buffer */
    assert(len != 0);
    --len; /* omit trailing LF */
    h2o_buffer_reserve(&ctx->buffer, len + 3);
    ctx->buffer->bytes[ctx->buffer->size++] = ',';
    ctx->buffer->bytes[ctx->buffer->size++] = '\n';
    ctx->buffer->bytes[ctx->buffer->size++] = ' ';
    memcpy(ctx->buffer->bytes + ctx->buffer->size, logline, len);
    ctx->buffer->size += len;

    if (logline != buf)
        free(logline);

    return 0;
}

static int on_req_json(struct st_h2o_status_handler_t *self, h2o_req_t *req)
{
    static h2o_generator_t generator = {NULL, NULL};
    struct st_status_context_t ctx = {};
    char errbuf[256];

#define ELEMENT(key, expr) "\"" key "\": \"" expr "\""
#define X_ELEMENT(id) ELEMENT(id, "%{" id "}x")
#define SEPARATOR ", "
    const char *fmt = "{"
        /* combined_log */
        ELEMENT("host", "%h") SEPARATOR ELEMENT("user", "%u") SEPARATOR ELEMENT("at", "%{%Y%m%dT%H%M%S}t.%{usec_frac}t%{%z}t")
            SEPARATOR ELEMENT("method", "%m") SEPARATOR ELEMENT("path", "%U") SEPARATOR ELEMENT("query", "%q")
                SEPARATOR ELEMENT("protocol", "%H") SEPARATOR ELEMENT("referer", "%{Referer}i")
                    SEPARATOR ELEMENT("user-agent", "%{User-agent}i") SEPARATOR
        /* time */
        X_ELEMENT("connect-time") SEPARATOR X_ELEMENT("request-header-time") SEPARATOR X_ELEMENT("request-body-time")
            SEPARATOR X_ELEMENT("request-total-time") SEPARATOR X_ELEMENT("process-time") SEPARATOR X_ELEMENT("response-time")
                SEPARATOR
        /* connection */
        X_ELEMENT("connection-id") SEPARATOR X_ELEMENT("ssl.protocol-version") SEPARATOR X_ELEMENT("ssl.session-reused")
            SEPARATOR X_ELEMENT("ssl.cipher") SEPARATOR X_ELEMENT("ssl.cipher-bits") SEPARATOR
        /* http2 */
        X_ELEMENT("http2.stream-id") SEPARATOR X_ELEMENT("http2.priority.received.exclusive")
            SEPARATOR X_ELEMENT("http2.priority.received.parent") SEPARATOR X_ELEMENT("http2.priority.received.weight")
        /* end */
        "}";
#undef ELEMENT
#undef X_ELEMENT
#undef SEPARATOR

    if ((ctx.logconf = h2o_logconf_compile(fmt, H2O_LOGCONF_ESCAPE_JSON, errbuf)) == NULL) {
        h2o_iovec_t resp = h2o_concat(&req->pool, h2o_iovec_init(H2O_STRLIT("failed to compile log format:")),
                                      h2o_iovec_init(errbuf, strlen(errbuf)));
        h2o_send_error(req, 400, "Invalid Request", resp.base, 0);
        return 0;
    }

    h2o_buffer_init(&ctx.buffer, &h2o_socket_buffer_prototype);

    /* collect the in-flight log as a JSON array */
    req->conn->ctx->globalconf->http2.callbacks.foreach_request(req->conn->ctx, collect_req_status, &ctx);
    ctx.buffer->bytes[0] = '[';
    h2o_buffer_reserve(&ctx.buffer, ctx.buffer->size + 3);
    ctx.buffer->bytes[ctx.buffer->size++] = '\n';
    ctx.buffer->bytes[ctx.buffer->size++] = ']';
    ctx.buffer->bytes[ctx.buffer->size++] = '\n';

    h2o_buffer_link_to_pool(ctx.buffer, &req->pool);
    h2o_logconf_dispose(ctx.logconf);

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

static int on_req(h2o_handler_t *_self, h2o_req_t *req)
{
    struct st_h2o_status_handler_t *self = (void *)_self;
    size_t prefix_len = req->pathconf->path.len - (req->pathconf->path.base[req->pathconf->path.len - 1] == '/');
    h2o_iovec_t local_path = h2o_iovec_init(req->path_normalized.base + prefix_len, req->path_normalized.len - prefix_len);

    if (local_path.len == 0 || h2o_memis(local_path.base, local_path.len, H2O_STRLIT("/"))) {
        /* root of the handler returns HTML that renders the status */
        h2o_iovec_t fn;
        const char *root = getenv("H2O_ROOT");
        if (root == NULL)
            root = H2O_TO_STR(H2O_ROOT);
        fn = h2o_concat(&req->pool, h2o_iovec_init(root, strlen(root)), h2o_iovec_init(H2O_STRLIT("/share/h2o/status/index.html")));
        return h2o_file_send(req, 200, "OK", fn.base, h2o_iovec_init(H2O_STRLIT("text/html; charset=utf-8")), 0);
    } else if (h2o_memis(local_path.base, local_path.len, H2O_STRLIT("/json"))) {
        /* "/json" maps to the JSON API */
        return on_req_json(self, req);
    }

    return -1;
}

void h2o_status_register(h2o_pathconf_t *pathconf)
{
    struct st_h2o_status_handler_t *self = (void *)h2o_create_handler(pathconf, sizeof(*self));
    self->super.on_req = on_req;
}
