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

void h2o_mrb_request_class_init(mrb_state *mrb, struct RClass *class)
{
    struct RClass *class_request;
    class_request = mrb_define_class_under(mrb, class, "Request", mrb->object_class);

    mrb_define_method(mrb, class_request, "initialize", h2o_mrb_req_init, MRB_ARGS_NONE());
    mrb_define_method(mrb, class_request, "log_error", h2o_mrb_req_log_error, MRB_ARGS_REQ(1));
}

#endif /* H2O_USE_MRUBY */
