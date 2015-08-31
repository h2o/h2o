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
#include "h2o.h"
#include "h2o/mruby_.h"

static mrb_value h2o_mrb_max_headers(mrb_state *mrb, mrb_value self)
{
    return mrb_fixnum_value(H2O_MAX_HEADERS);
}

static mrb_value h2o_mrb_return(mrb_state *mrb, mrb_value self)
{
    h2o_mruby_internal_context_t *mruby_ctx = (h2o_mruby_internal_context_t *)mrb->ud;
    mrb_int status;
    const char *reason, *body;
    mrb_int reason_len, body_len;

    if (mruby_ctx->state != H2O_MRUBY_STATE_UNDETERMINED)
        mrb_raise(mrb, E_RUNTIME_ERROR, "response already sent");

    reason = body = NULL;
    mrb_get_args(mrb, "i|ss", &status, &reason, &reason_len, &body, &body_len);
    if (status == -1) {
        /* pass to next handler */
        mruby_ctx->state = H2O_MRUBY_STATE_FALLTHRU;
    } else {
        if (reason == NULL || body == NULL)
            mrb_raise(mrb, E_ARGUMENT_ERROR, "need both reason and body with status code");
        /* send response */
        h2o_req_t *req = mruby_ctx->req;
        req->res.status = status;
        req->res.reason = h2o_strdup(&mruby_ctx->req->pool, reason, reason_len).base;
        if (h2o_find_header(&req->res.headers, H2O_TOKEN_CONTENT_TYPE, -1) == -1)
            h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_CONTENT_TYPE, H2O_STRLIT(H2O_MRUBY_DEFAULT_CONTENT_TYPE));
        h2o_send_inline(req, body, body_len);
        mruby_ctx->state = H2O_MRUBY_STATE_RESPONSE_SENT;
    }

    return mrb_fixnum_value(status);
}

void h2o_mrb_core_class_init(mrb_state *mrb, struct RClass *class)
{
    mrb_define_const(mrb, class, "DECLINED", mrb_fixnum_value(-1));

    mrb_define_class_method(mrb, class, "max_headers", h2o_mrb_max_headers, MRB_ARGS_NONE());
    mrb_define_class_method(mrb, class, "return", h2o_mrb_return, MRB_ARGS_REQ(3));
}
