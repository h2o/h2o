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
#include "picohttpparser.h"
#include <mruby.h>
#include <mruby/array.h>
#include <mruby/error.h>
#include <mruby/string.h>
#include "h2o/mruby_.h"

struct st_h2o_mruby_http_request_context_t {
    h2o_req_t *req;
    h2o_mruby_context_t *handler_ctx;
    h2o_buffer_t *req_buf;
    struct {
        int status;
        H2O_VECTOR(struct phr_header) headers;
    } resp;
};

static void post_response(h2o_req_t *req, h2o_mruby_context_t *handler_ctx, int status, const struct phr_header *headers,
                          size_t num_headers, h2o_iovec_t body)
{
    mrb_state *mrb = handler_ctx->mrb;
    mrb_int gc_arena = mrb_gc_arena_save(mrb);
    size_t i;

    mrb_value resp = mrb_ary_new_capa(mrb, 3);
    mrb_ary_set(mrb, resp, 0, mrb_fixnum_value(status));
    mrb_value headers_ary = mrb_ary_new_capa(mrb, (mrb_int)num_headers);
    for (i = 0; i < num_headers; ++i) {
        mrb_value nv = mrb_ary_new_capa(mrb, 2);
        mrb_ary_set(mrb, nv, 0, mrb_str_new(mrb, headers[i].name, headers[i].name_len));
        mrb_ary_set(mrb, nv, 1, mrb_str_new(mrb, headers[i].value, headers[i].value_len));
        mrb_ary_set(mrb, headers_ary, (mrb_int)i, nv);
    }
    mrb_ary_set(mrb, resp, 1, headers_ary);
    mrb_ary_set(mrb, resp, 2, mrb_str_new(mrb, body.base, body.len));

    h2o_mruby_run_fiber(req, handler_ctx, resp, gc_arena, NULL);
}

static void post_error(h2o_req_t *req, h2o_mruby_context_t *handler_ctx, const char *errstr)
{
    static const struct phr_header headers[1] = {{H2O_STRLIT("content-type"), H2O_STRLIT("text/plain; charset=utf-8")}};

    post_response(req, handler_ctx, 500, headers, sizeof(headers) / sizeof(headers[0]), h2o_iovec_init(errstr, strlen(errstr)));
}

static int on_body(h2o_http1client_t *client, const char *errstr)
{
    struct st_h2o_mruby_http_request_context_t *ctx = client->data;

    if (errstr != NULL)
        post_response(ctx->req, ctx->handler_ctx, ctx->resp.status, ctx->resp.headers.entries, ctx->resp.headers.size,
                      h2o_iovec_init(client->sock->input->bytes, client->sock->input->size));
    return 0;
}

static h2o_http1client_body_cb on_head(h2o_http1client_t *client, const char *errstr, int minor_version, int status,
                                       h2o_iovec_t msg, struct phr_header *headers, size_t num_headers)
{
    struct st_h2o_mruby_http_request_context_t *ctx = client->data;

    if (errstr != NULL && errstr != h2o_http1client_error_is_eos) {
        post_error(ctx->req, ctx->handler_ctx, errstr);
        return NULL;
    }

    h2o_mem_pool_t *pool = &ctx->req->pool;
    ctx->resp.status = status;
    memset(&ctx->resp.headers, 0, sizeof(ctx->resp.headers));
    h2o_vector_reserve(&ctx->req->pool, (void *)&ctx->resp.headers, sizeof(ctx->resp.headers.entries[0]), num_headers);
    size_t i;
    for (i = 0; i != num_headers; ++i) {
        struct phr_header *dst = ctx->resp.headers.entries + i;
        dst->name = h2o_strdup(pool, headers[i].name, headers[i].name_len).base;
        dst->name_len = headers[i].name_len;
        dst->value = h2o_strdup(pool, headers[i].value, headers[i].value_len).base;
        dst->value_len = headers[i].value_len;
    }

    if (errstr == h2o_http1client_error_is_eos) {
        post_response(ctx->req, ctx->handler_ctx, ctx->resp.status, ctx->resp.headers.entries, ctx->resp.headers.size,
                      h2o_iovec_init(NULL, 0));
        return NULL;
    }
    return on_body;
}

static h2o_http1client_head_cb on_connect(h2o_http1client_t *client, const char *errstr, h2o_iovec_t **reqbufs, size_t *reqbufcnt,
                                          int *method_is_head)
{
    struct st_h2o_mruby_http_request_context_t *ctx = client->data;

    if (errstr != NULL) {
        post_error(ctx->req, ctx->handler_ctx, errstr);
        return NULL;
    }

    *reqbufs = h2o_mem_alloc_pool(&ctx->req->pool, sizeof(**reqbufs));
    **reqbufs = h2o_iovec_init(ctx->req_buf->bytes, ctx->req_buf->size);
    *reqbufcnt = 1;
    *method_is_head = ctx->req_buf->size >= 5 && memcmp(ctx->req_buf->bytes, "HEAD ", 5) == 0;
    return on_head;
}

static inline void append_to_buffer(h2o_buffer_t **buf, const void *src, size_t len)
{
    memcpy((*buf)->bytes + (*buf)->size, src, len);
    (*buf)->size += len;
}

static int flatten_request_header(h2o_mruby_context_t *handler_ctx, h2o_iovec_t name, h2o_iovec_t value, void *_req_buf)
{
    h2o_buffer_t **req_buf = _req_buf;

    h2o_buffer_reserve(req_buf, name.len + value.len + sizeof(": \r\n") - 1);
    append_to_buffer(req_buf, name.base, name.len);
    append_to_buffer(req_buf, H2O_STRLIT(": "));
    append_to_buffer(req_buf, value.base, value.len);
    append_to_buffer(req_buf, H2O_STRLIT("\r\n"));

    return 0;
}

mrb_value h2o_mruby_http_request_callback(h2o_req_t *req, h2o_mruby_context_t *handler_ctx, mrb_value input)
{
    struct st_h2o_mruby_http_request_context_t *ctx = h2o_mem_alloc_pool(&req->pool, sizeof(*ctx));
    mrb_state *mrb = handler_ctx->mrb;
    h2o_url_t url;

    ctx->req = req;
    ctx->handler_ctx = handler_ctx;
    h2o_buffer_init(&ctx->req_buf, &h2o_socket_buffer_prototype);

    if (!mrb_array_p(input)) {
        mrb->exc = mrb_obj_ptr(mrb_exc_new_str_lit(mrb, E_ARGUMENT_ERROR, "http_request: unexpected input"));
        goto RaiseException;
    }

    { /* method */
        mrb_value method = mrb_str_to_str(mrb, mrb_ary_entry(input, 0));
        if (mrb->exc != NULL)
            goto RaiseException;
        h2o_buffer_reserve(&ctx->req_buf, RSTRING_LEN(method) + 1);
        append_to_buffer(&ctx->req_buf, RSTRING_PTR(method), RSTRING_LEN(method));
        append_to_buffer(&ctx->req_buf, H2O_STRLIT(" "));
    }
    { /* uri */
        mrb_value t = mrb_str_to_str(mrb, mrb_ary_entry(input, 1));
        if (mrb->exc != NULL)
            goto RaiseException;
        h2o_iovec_t urlstr = h2o_strdup(&req->pool, RSTRING_PTR(t), RSTRING_LEN(t));
        if (h2o_url_parse(urlstr.base, urlstr.len, &url) != 0) {
            mrb->exc = mrb_obj_ptr(mrb_exc_new_str_lit(mrb, E_ARGUMENT_ERROR, "invaild URL"));
            goto RaiseException;
        }
        if (url.scheme != &H2O_URL_SCHEME_HTTP) {
            mrb->exc = mrb_obj_ptr(mrb_exc_new_str_lit(mrb, E_ARGUMENT_ERROR, "scheme is not HTTP"));
            goto RaiseException;
        }
        h2o_buffer_reserve(&ctx->req_buf,
                           url.path.len + url.authority.len + sizeof(" HTTP/1.1\r\nConnection: close\r\nHost: \r\n") - 1);
        append_to_buffer(&ctx->req_buf, url.path.base, url.path.len);
        append_to_buffer(&ctx->req_buf, H2O_STRLIT(" HTTP/1.1\r\nConnection: close\r\nHost: "));
        append_to_buffer(&ctx->req_buf, url.authority.base, url.authority.len);
        append_to_buffer(&ctx->req_buf, H2O_STRLIT("\r\n"));
    }
    { /* headers */
        mrb_value headers = mrb_ary_entry(input, 2);
        if (!mrb_nil_p(headers)) {
            if (h2o_mruby_iterate_headers(handler_ctx, headers, flatten_request_header, &ctx->req_buf) != 0)
                goto RaiseException;
        }
    }
    h2o_buffer_reserve(&ctx->req_buf, 2);
    append_to_buffer(&ctx->req_buf, H2O_STRLIT("\r\n"));
    /* TODO handle body */

    /* build request and connect */
    h2o_buffer_link_to_pool(ctx->req_buf, &req->pool);
    h2o_http1client_connect(NULL, ctx, &req->conn->ctx->proxy.client_ctx, url.host, h2o_url_get_port(&url), on_connect);
    return mrb_nil_value();

RaiseException:
    h2o_buffer_dispose(&ctx->req_buf);
    {
        mrb_value t = mrb_obj_value(mrb->exc);
        mrb->exc = NULL;
        return t;
    }
}
