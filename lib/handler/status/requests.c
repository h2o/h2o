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

struct requests_status_ctx {
    h2o_logconf_t *logconf;
    h2o_mem_pool_t *pool;
    h2o_iovec_t req_data;
    int first; /* used to know if a thread is the first one, we skip the leading
                * coma in that case. */
};

struct st_collect_req_status_cbdata_t {
    h2o_logconf_t *logconf;
    h2o_buffer_t *buffer;
    int first; /* see requests_status_ctx */
};

static int collect_req_status(h2o_req_t *req, void *_cbdata)
{
    struct st_collect_req_status_cbdata_t *cbdata = _cbdata;

    /* collect log */
    char buf[4096];
    size_t len = sizeof(buf);
    char *logline = h2o_log_request(cbdata->logconf, req, &len, buf);

    /* append to buffer */
    assert(len != 0);
    --len; /* omit trailing LF */
    if (cbdata->first) {
        h2o_buffer_reserve(&cbdata->buffer, len + 3);
        memcpy(cbdata->buffer->bytes + cbdata->buffer->size, "\n  ", 3);
        cbdata->buffer->size += 3;
    } else {
        h2o_buffer_reserve(&cbdata->buffer, len + 4);
        memcpy(cbdata->buffer->bytes + cbdata->buffer->size, ",\n  ", 4);
        cbdata->buffer->size += 4;
    }
    memcpy(cbdata->buffer->bytes + cbdata->buffer->size, logline, len);
    cbdata->buffer->size += len;

    if (logline != buf)
        free(logline);

    return 0;
}

static void requests_status_per_thread(void *priv, h2o_context_t *ctx)
{
    struct requests_status_ctx *rsc = priv;
    struct st_collect_req_status_cbdata_t cbdata = {rsc->logconf};

    cbdata.first = rsc->first;
    if (rsc->first) {
        rsc->first = 0;
    }
    h2o_buffer_init(&cbdata.buffer, &h2o_socket_buffer_prototype);
    ctx->globalconf->http1.callbacks.foreach_request(ctx, collect_req_status, &cbdata);
    ctx->globalconf->http2.callbacks.foreach_request(ctx, collect_req_status, &cbdata);

    if (cbdata.buffer->size != 0) {
        rsc->req_data.base = h2o_mem_realloc(rsc->req_data.base, rsc->req_data.len + cbdata.buffer->size);
        memcpy(rsc->req_data.base + rsc->req_data.len, cbdata.buffer->bytes, cbdata.buffer->size);
        rsc->req_data.len += cbdata.buffer->size;
    }

    h2o_buffer_dispose(&cbdata.buffer);
}

static void *requests_status_alloc_context(h2o_req_t *req)
{
    struct requests_status_ctx *rsc;
    rsc = h2o_mem_alloc_pool(&req->pool, sizeof(*rsc));
    rsc->pool = &req->pool;
    rsc->first = 1;

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
        /* http1 */
        X_ELEMENT("http1.request-index") SEPARATOR
        /* http2 */
        X_ELEMENT("http2.stream-id") SEPARATOR X_ELEMENT("http2.priority.received.exclusive")
        SEPARATOR X_ELEMENT("http2.priority.received.parent") SEPARATOR X_ELEMENT("http2.priority.received.weight")
        SEPARATOR X_ELEMENT("http2.priority.actual.parent") SEPARATOR X_ELEMENT("http2.priority.actual.weight") SEPARATOR
        /* misc */
        ELEMENT("authority", "%V")
        /* end */
        "}";
#undef ELEMENT
#undef X_ELEMENT
#undef SEPARATOR

    { /* compile logconf */
        char errbuf[256];
        if ((rsc->logconf = h2o_logconf_compile(fmt, H2O_LOGCONF_ESCAPE_JSON, errbuf)) == NULL) {
            h2o_iovec_t resp = h2o_concat(&req->pool, h2o_iovec_init(H2O_STRLIT("failed to compile log format:")),
                    h2o_iovec_init(errbuf, strlen(errbuf)));
            h2o_send_error(req, 400, "Invalid Request", resp.base, 0);
            return NULL;
        }
    }

    rsc->req_data = h2o_strdup(NULL, ",\n \"requests\": [", SIZE_MAX);
    return rsc;
}

static h2o_iovec_t requests_status_assemble(void *priv)
{
    struct requests_status_ctx *rsc = priv;

#define JSON_FOOTER "\n ]"
#define JSON_FOOTER_LEN 3
    rsc->req_data.base = h2o_mem_realloc(rsc->req_data.base, rsc->req_data.len + JSON_FOOTER_LEN);
    memcpy(rsc->req_data.base + rsc->req_data.len, JSON_FOOTER, JSON_FOOTER_LEN);
    rsc->req_data.len += JSON_FOOTER_LEN;
#undef JSON_FOOTER
#undef JSON_FOOTER_LEN

    return rsc->req_data;
}

static void requests_status_done(void *priv)
{
    struct requests_status_ctx *rsc = priv;

    h2o_logconf_dispose(rsc->logconf);
    free(rsc->req_data.base);

    if (!rsc->pool) {
        free(rsc);
    }
}
h2o_status_handler_t requests_status_handler = {
    .type = H2O_STATUS_HANDLER_PER_THREAD,
    .name = { H2O_STRLIT("requests") },
    .per_thread = {
        .alloc_context_cb = requests_status_alloc_context,
        .per_thread_cb = requests_status_per_thread,
        .assemble_cb = requests_status_assemble,
        .done_cb = requests_status_done,
    }
};
