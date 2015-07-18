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

#ifdef H2O_USE_MRUBY

#include "h2o.h"
#include "h2o/mruby.h"

#include "mruby.h"
#include "mruby/string.h"
#include "mruby/data.h"
#include "mruby/class.h"
#include <mruby/variable.h>

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

    mrb_get_args(mrb, "oo", &key, &val);
    key = mrb_funcall(mrb, key, "downcase", 0);

    h2o_set_header_by_str(&mruby_ctx->req->pool, &mruby_ctx->req->headers, RSTRING_PTR(key), RSTRING_LEN(key), 0, RSTRING_PTR(val),
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

    mrb_get_args(mrb, "oo", &key, &val);
    key = mrb_funcall(mrb, key, "downcase", 0);

    h2o_set_header_by_str(&mruby_ctx->req->pool, &mruby_ctx->req->res.headers, RSTRING_PTR(key), RSTRING_LEN(key), 0,
                          RSTRING_PTR(val), RSTRING_LEN(val), 1);

    return key;
}

void h2o_mrb_request_class_init(mrb_state *mrb, struct RClass *class)
{
    struct RClass *class_request;
    struct RClass *class_headers_in;
    struct RClass *class_headers_out;

    class_request = mrb_define_class_under(mrb, class, "Request", mrb->object_class);

    mrb_define_method(mrb, class_request, "initialize", h2o_mrb_req_init, MRB_ARGS_NONE());
    mrb_define_method(mrb, class_request, "log_error", h2o_mrb_req_log_error, MRB_ARGS_REQ(1));
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

#endif /* H2O_USE_MRUBY */
