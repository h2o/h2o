/*
 * Copyright (c) 2014,2015 DeNA Co., Ltd., Kazuho Oku, Ryosuke Matsumoto
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
#include <mruby.h>
#include <mruby/string.h>
#include <mruby/data.h>
#include <mruby/class.h>
#include <mruby/variable.h>
#include "h2o.h"
#include "h2o/mruby.h"

static mrb_value h2o_mrb_req_init(mrb_state *mrb, mrb_value self)
{
    return self;
}

static mrb_value h2o_mrb_req_log_error(mrb_state *mrb, mrb_value self)
{
    h2o_mruby_internal_context_t *mruby_ctx = (h2o_mruby_internal_context_t *)mrb->ud;
    mrb_value log;

    mrb_get_args(mrb, "o", &log);
    h2o_req_log_error(mruby_ctx->req, H2O_MRUBY_MODULE_NAME, "%.*s", RSTRING_LEN(log), RSTRING_PTR(log));

    return log;
}

static mrb_value h2o_mrb_req_uri(mrb_state *mrb, mrb_value self)
{
    h2o_mruby_internal_context_t *mruby_ctx = (h2o_mruby_internal_context_t *)mrb->ud;

    return h2o_mrb_str_new(mrb, &mruby_ctx->req->input.path);
}

static mrb_value h2o_mrb_req_hostname(mrb_state *mrb, mrb_value self)
{
    h2o_mruby_internal_context_t *mruby_ctx = (h2o_mruby_internal_context_t *)mrb->ud;
    h2o_iovec_t hostname;
    uint16_t port;

    if (h2o_url_parse_hostport(mruby_ctx->req->input.authority.base, mruby_ctx->req->input.authority.len, &hostname, &port) == NULL)
        return mrb_nil_value();

    return h2o_mrb_str_new(mrb, &hostname);
}

static mrb_value h2o_mrb_req_authority(mrb_state *mrb, mrb_value self)
{
    h2o_mruby_internal_context_t *mruby_ctx = (h2o_mruby_internal_context_t *)mrb->ud;

    return h2o_mrb_str_new(mrb, &mruby_ctx->req->input.authority);
}

static mrb_value h2o_mrb_req_method(mrb_state *mrb, mrb_value self)
{
    h2o_mruby_internal_context_t *mruby_ctx = (h2o_mruby_internal_context_t *)mrb->ud;

    return h2o_mrb_str_new(mrb, &mruby_ctx->req->input.method);
}

static mrb_value h2o_mrb_req_query(mrb_state *mrb, mrb_value self)
{
    h2o_mruby_internal_context_t *mruby_ctx = (h2o_mruby_internal_context_t *)mrb->ud;
    h2o_iovec_t *path = &mruby_ctx->req->input.path;
    size_t offset = mruby_ctx->req->input.query_at;
    if (offset == SIZE_MAX)
        return mrb_nil_value();

    return mrb_str_new(mrb, path->base + offset, path->len - offset);
}

static mrb_value h2o_mrb_get_class_obj(mrb_state *mrb, mrb_value self, char *obj_id, char *class_name)
{
    mrb_value obj;
    struct RClass *obj_class, *h2o_class;

    obj = mrb_iv_get(mrb, self, mrb_intern_cstr(mrb, obj_id));
    if (mrb_nil_p(obj)) {
        h2o_class = mrb_class_get(mrb, "H2O");
        obj_class = (struct RClass *)mrb_class_ptr(mrb_const_get(mrb, mrb_obj_value(h2o_class), mrb_intern_cstr(mrb, class_name)));
        obj = mrb_obj_new(mrb, obj_class, 0, NULL);
        mrb_iv_set(mrb, self, mrb_intern_cstr(mrb, obj_id), obj);
    }
    return obj;
}

static mrb_value h2o_mrb_headers_in_obj(mrb_state *mrb, mrb_value self)
{
    return h2o_mrb_get_class_obj(mrb, self, "headers_in_obj", "Headers_in");
}

static mrb_value h2o_mrb_headers_out_obj(mrb_state *mrb, mrb_value self)
{
    return h2o_mrb_get_class_obj(mrb, self, "headers_out_obj", "Headers_out");
}

static mrb_value h2o_mrb_get_request_headers_in(mrb_state *mrb, mrb_value self)
{
    h2o_mruby_internal_context_t *mruby_ctx = (h2o_mruby_internal_context_t *)mrb->ud;
    mrb_value key;
    ssize_t index;
    h2o_header_t *h;

    mrb_get_args(mrb, "o", &key);
    key = mrb_funcall(mrb, key, "downcase", 0);

    index = h2o_find_header_by_str(&mruby_ctx->req->headers, RSTRING_PTR(key), RSTRING_LEN(key), -1);
    if (index == -1)
        return mrb_nil_value();

    h = mruby_ctx->req->headers.entries + index;

    return mrb_str_new(mrb, h->value.base, h->value.len);
}

static mrb_value h2o_mrb_set_request_headers_in(mrb_state *mrb, mrb_value self)
{
    h2o_mruby_internal_context_t *mruby_ctx = (h2o_mruby_internal_context_t *)mrb->ud;
    mrb_value key, val;
    char *key_cstr, *val_cstr;

    mrb_get_args(mrb, "oo", &key, &val);
    key = mrb_funcall(mrb, key, "downcase", 0);

    key_cstr = h2o_mem_alloc_pool(&mruby_ctx->req->pool, RSTRING_LEN(key));
    val_cstr = h2o_mem_alloc_pool(&mruby_ctx->req->pool, RSTRING_LEN(val));
    memcpy(key_cstr, RSTRING_PTR(key), RSTRING_LEN(key));
    memcpy(val_cstr, RSTRING_PTR(val), RSTRING_LEN(val));

    h2o_set_header_by_str(&mruby_ctx->req->pool, &mruby_ctx->req->headers, key_cstr, RSTRING_LEN(key), 0, val_cstr,
                          RSTRING_LEN(val), 1);

    return key;
}

static mrb_value h2o_mrb_get_request_headers_out(mrb_state *mrb, mrb_value self)
{
    h2o_mruby_internal_context_t *mruby_ctx = (h2o_mruby_internal_context_t *)mrb->ud;
    mrb_value key;
    ssize_t index;
    h2o_header_t *h;

    mrb_get_args(mrb, "o", &key);
    key = mrb_funcall(mrb, key, "downcase", 0);

    index = h2o_find_header_by_str(&mruby_ctx->req->res.headers, RSTRING_PTR(key), RSTRING_LEN(key), -1);
    if (index == -1)
        return mrb_nil_value();

    h = mruby_ctx->req->res.headers.entries + index;

    return mrb_str_new(mrb, h->value.base, h->value.len);
}

static mrb_value h2o_mrb_set_request_headers_out(mrb_state *mrb, mrb_value self)
{
    h2o_mruby_internal_context_t *mruby_ctx = (h2o_mruby_internal_context_t *)mrb->ud;
    mrb_value key, val;
    char *key_cstr, *val_cstr;

    mrb_get_args(mrb, "oo", &key, &val);
    key = mrb_funcall(mrb, key, "downcase", 0);

    key_cstr = h2o_mem_alloc_pool(&mruby_ctx->req->pool, RSTRING_LEN(key));
    val_cstr = h2o_mem_alloc_pool(&mruby_ctx->req->pool, RSTRING_LEN(val));
    memcpy(key_cstr, RSTRING_PTR(key), RSTRING_LEN(key));
    memcpy(val_cstr, RSTRING_PTR(val), RSTRING_LEN(val));

    h2o_set_header_by_str(&mruby_ctx->req->pool, &mruby_ctx->req->res.headers, key_cstr, RSTRING_LEN(key), 0, val_cstr,
                          RSTRING_LEN(val), 1);

    return key;
}

static mrb_value h2o_mrb_req_reprocess_request(mrb_state *mrb, mrb_value self)
{
    h2o_mruby_internal_context_t *mruby_ctx = (h2o_mruby_internal_context_t *)mrb->ud;
    char *upstream;
    h2o_url_t parsed;
    h2o_req_overrides_t *overrides = h2o_mem_alloc_pool(&mruby_ctx->req->pool, sizeof(*overrides));

    mrb_get_args(mrb, "z", &upstream);

    if (h2o_url_parse(upstream, SIZE_MAX, &parsed) != 0) {
        mrb_raise(mrb, E_ARGUMENT_ERROR, "failed to parse URL");
    }
    if (parsed.scheme != &H2O_URL_SCHEME_HTTP) {
        mrb_raise(mrb, E_ARGUMENT_ERROR, "only HTTP URLs are supported");
    }

    /* setup overrides */
    *overrides = (h2o_req_overrides_t){};
    overrides->location_rewrite.match = &parsed;
    overrides->location_rewrite.path_prefix = mruby_ctx->req->pathconf->path;

    /* request reprocess */
    h2o_reprocess_request_deferred(mruby_ctx->req, mruby_ctx->req->method, parsed.scheme, parsed.authority,
                                   h2o_concat(&mruby_ctx->req->pool, parsed.path,
                                              h2o_iovec_init(mruby_ctx->req->path.base + mruby_ctx->req->pathconf->path.len,
                                                             mruby_ctx->req->path.len - mruby_ctx->req->pathconf->path.len)),
                                   NULL, 0);
    mruby_ctx->is_last = 1;

    return mrb_nil_value();
}

void h2o_mrb_request_class_init(mrb_state *mrb, struct RClass *class)
{
    struct RClass *class_request;
    struct RClass *class_headers_in;
    struct RClass *class_headers_out;

    class_request = mrb_define_class_under(mrb, class, "Request", mrb->object_class);

    mrb_define_method(mrb, class_request, "initialize", h2o_mrb_req_init, MRB_ARGS_NONE());
    mrb_define_method(mrb, class_request, "log_error", h2o_mrb_req_log_error, MRB_ARGS_REQ(1));
    mrb_define_method(mrb, class_request, "uri", h2o_mrb_req_uri, MRB_ARGS_NONE());
    mrb_define_method(mrb, class_request, "path", h2o_mrb_req_uri, MRB_ARGS_NONE());
    mrb_define_method(mrb, class_request, "hostname", h2o_mrb_req_hostname, MRB_ARGS_NONE());
    mrb_define_method(mrb, class_request, "authority", h2o_mrb_req_authority, MRB_ARGS_NONE());
    mrb_define_method(mrb, class_request, "method", h2o_mrb_req_method, MRB_ARGS_NONE());
    mrb_define_method(mrb, class_request, "query", h2o_mrb_req_query, MRB_ARGS_NONE());
    mrb_define_method(mrb, class_request, "reprocess_request", h2o_mrb_req_reprocess_request, MRB_ARGS_REQ(1));

    mrb_define_method(mrb, class_request, "headers_in", h2o_mrb_headers_in_obj, MRB_ARGS_NONE());
    mrb_define_method(mrb, class_request, "headers_out", h2o_mrb_headers_out_obj, MRB_ARGS_NONE());

    /* request haeder class */
    class_headers_in = mrb_define_class_under(mrb, class, "Headers_in", mrb->object_class);
    mrb_define_method(mrb, class_headers_in, "[]", h2o_mrb_get_request_headers_in, MRB_ARGS_REQ(1));
    mrb_define_method(mrb, class_headers_in, "[]=", h2o_mrb_set_request_headers_in, MRB_ARGS_REQ(2));

    /* response haeder class */
    class_headers_out = mrb_define_class_under(mrb, class, "Headers_out", mrb->object_class);
    mrb_define_method(mrb, class_headers_out, "[]", h2o_mrb_get_request_headers_out, MRB_ARGS_REQ(1));
    mrb_define_method(mrb, class_headers_out, "[]=", h2o_mrb_set_request_headers_out, MRB_ARGS_REQ(2));
}
