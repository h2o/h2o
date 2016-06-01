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

struct st_requests_status_ctx_t {
    h2o_logconf_t *logconf;
    h2o_iovec_t req_data;
    h2o_iovec_t init_error;
    int first; /* used to know if a thread is the first one, we skip the leading
                * coma in that case. */
};

struct st_collect_req_status_cbdata_t {
    h2o_logconf_t *logconf;
    h2o_buffer_t *buffer;
    int first; /* see st_requests_status_ctx_t */
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
    struct st_requests_status_ctx_t *rsc = priv;
    struct st_collect_req_status_cbdata_t cbdata = {rsc->logconf};

    /* we encountered an error at init() time, return early */
    if (rsc->init_error.base) {
        return;
    }

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

static void *requests_status_init(void)
{
    struct st_requests_status_ctx_t *rsc;
    rsc = h2o_mem_alloc(sizeof(*rsc));
    memset(rsc, 0, sizeof(*rsc));
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
            h2o_iovec_t resp = h2o_concat(NULL, h2o_iovec_init(H2O_STRLIT("failed to compile log format:")),
                                          h2o_iovec_init(errbuf, strlen(errbuf)));
            rsc->init_error = resp;
            return rsc;
        }
    }

    rsc->req_data = h2o_strdup(NULL, ",\n \"requests\": [", SIZE_MAX);
    return rsc;
}

static h2o_iovec_t requests_status_final(void *priv, h2o_globalconf_t *gconf, h2o_req_t *req)
{
    h2o_iovec_t ret;
    struct st_requests_status_ctx_t *rsc = priv;

    if (rsc->init_error.base) {
        ret = h2o_strdup(&req->pool, rsc->init_error.base, rsc->init_error.len);
        free(rsc->init_error.base);
        goto out;
    }
#define JSON_FOOTER "\n ]"
#define JSON_FOOTER_LEN 3
    ret.base = h2o_mem_alloc_pool(&req->pool, rsc->req_data.len + JSON_FOOTER_LEN);
    memcpy(ret.base, rsc->req_data.base, rsc->req_data.len);
    memcpy(ret.base + rsc->req_data.len, JSON_FOOTER, JSON_FOOTER_LEN);
    ret.len = rsc->req_data.len + JSON_FOOTER_LEN;
#undef JSON_FOOTER
#undef JSON_FOOTER_LEN

    h2o_logconf_dispose(rsc->logconf);
    free(rsc->req_data.base);
out:
    free(rsc);
    return ret;
}

h2o_status_handler_t requests_status_handler = {
    {H2O_STRLIT("requests")}, requests_status_init, requests_status_per_thread, requests_status_final,
};
