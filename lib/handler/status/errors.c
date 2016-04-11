/*
 * Copyright (c) 2016 Fastly
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

struct errors_status_ctx {
    h2o_mem_pool_t *pool;
    unsigned long long agg_errors[EMITTED_ERRORS_MAX];
};

static void errors_status_per_thread(void *priv, h2o_context_t *ctx)
{
    size_t i;
    struct errors_status_ctx *esc = priv;
    for (i = 0; i < EMITTED_ERRORS_MAX; i++) {
        esc->agg_errors[i] += ctx->emitted_errors.emitted_errors_cnt[i];
    }
}

static void *errors_status_alloc_context(h2o_req_t *req)
{
    struct errors_status_ctx *ret;

    ret = h2o_mem_alloc_pool(&req->pool, sizeof(*ret));
    memset(ret, 0, sizeof(*ret));
    ret->pool = &req->pool;

    return ret;
}

static h2o_iovec_t errors_status_assemble(void *priv)
{
    struct errors_status_ctx *esc = priv;
    h2o_iovec_t ret;

#define BUFSIZE (2*1024)
    ret.base = h2o_mem_alloc_pool(esc->pool, BUFSIZE);
    ret.len = snprintf(ret.base, BUFSIZE, ",\n"
                                          " \"http1-errors-400\": %llu,\n"
                                          " \"http1-errors-403\": %llu,\n"
                                          " \"http1-errors-404\": %llu,\n"
                                          " \"http1-errors-405\": %llu,\n"
                                          " \"http1-errors-416\": %llu,\n"
                                          " \"http1-errors-417\": %llu,\n"
                                          " \"http1-errors-500\": %llu,\n"
                                          " \"http1-errors-502\": %llu,\n"
                                          " \"http1-errors-503\": %llu,\n"
                                          " \"http1-errors-4xx-others\": %llu,\n"
                                          " \"http1-errors-5xx-others\": %llu,\n"
                                          " \"http1-errors-others\": %llu,\n"
                                          " \"http2-errors-protocol\": %llu, \n"
                                          " \"http2-errors-internal\": %llu, \n"
                                          " \"http2-errors-flow_control\": %llu, \n"
                                          " \"http2-errors-settings_timeout\": %llu, \n"
                                          " \"http2-errors-stream_closed\": %llu, \n"
                                          " \"http2-errors-frame_size\": %llu, \n"
                                          " \"http2-errors-refused_stream\": %llu, \n"
                                          " \"http2-errors-cancel\": %llu, \n"
                                          " \"http2-errors-compression\": %llu, \n"
                                          " \"http2-errors-connect\": %llu, \n"
                                          " \"http2-errors-enhance_your_calm\": %llu, \n"
                                          " \"http2-errors-inadequate_security\": %llu, \n"
                                          " \"http2-errors-other\": %llu",
                                          esc->agg_errors[E_HTTP_400], esc->agg_errors[E_HTTP_403], esc->agg_errors[E_HTTP_404],
                                          esc->agg_errors[E_HTTP_405], esc->agg_errors[E_HTTP_416], esc->agg_errors[E_HTTP_417],
                                          esc->agg_errors[E_HTTP_500], esc->agg_errors[E_HTTP_502], esc->agg_errors[E_HTTP_503],
                                          esc->agg_errors[E_HTTP_4XX], esc->agg_errors[E_HTTP_5XX], esc->agg_errors[E_HTTP_XXX],
                                          esc->agg_errors[E_HTTP2_PROTOCOL], esc->agg_errors[E_HTTP2_INTERNAL], esc->agg_errors[E_HTTP2_FLOW_CONTROL],
                                          esc->agg_errors[E_HTTP2_SETTINGS_TIMEOUT], esc->agg_errors[E_HTTP2_STREAM_CLOSED], esc->agg_errors[E_HTTP2_FRAME_SIZE],
                                          esc->agg_errors[E_HTTP2_REFUSED_STREAM], esc->agg_errors[E_HTTP2_CANCEL], esc->agg_errors[E_HTTP2_COMPRESSION],
                                          esc->agg_errors[E_HTTP2_CONNECT], esc->agg_errors[E_HTTP2_ENHANCE_YOUR_CALM], esc->agg_errors[E_HTTP2_INADEQUATE_SECURITY],
                                          esc->agg_errors[E_HTTP2_OTHER]);
    return ret;
#undef BUFSIZE
}

static void errors_status_done(void *priv)
{
    struct errors_status_ctx *esc = priv;
    if (!esc->pool) {
        free(esc);
    }
}

h2o_status_handler_t errors_status_handler = {
    .type = H2O_STATUS_HANDLER_PER_THREAD,
    .name = { H2O_STRLIT("errors") },
    .per_thread = {
        .alloc_context_cb = errors_status_alloc_context,
        .per_thread_cb = errors_status_per_thread,
        .assemble_cb = errors_status_assemble,
        .done_cb = errors_status_done,
    }
};
