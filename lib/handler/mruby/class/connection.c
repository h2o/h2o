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

static mrb_value h2o_mrb_conn_init(mrb_state *mrb, mrb_value self)
{
    return self;
}

static mrb_value h2o_mrb_conn_remote_ip(mrb_state *mrb, mrb_value self)
{
    h2o_mruby_internal_context_t *mruby_ctx = (h2o_mruby_internal_context_t *)mrb->ud;
    size_t remote_addr_len = SIZE_MAX;
    char remote_addr[NI_MAXHOST];
    struct sockaddr_storage ss;
    socklen_t sslen;

    if ((sslen = mruby_ctx->req->conn->get_peername(mruby_ctx->req->conn, (void *)&ss)) != 0) {
        remote_addr_len = h2o_socket_getnumerichost((void *)&ss, sslen, remote_addr);
    } else {
        return mrb_nil_value();
    }

    return mrb_str_new(mrb, remote_addr, remote_addr_len);
}

void h2o_mrb_conn_class_init(mrb_state *mrb, struct RClass *class)
{
    struct RClass *class_conn;

    class_conn = mrb_define_class_under(mrb, class, "Connection", mrb->object_class);

    mrb_define_method(mrb, class_conn, "initialize", h2o_mrb_conn_init, MRB_ARGS_NONE());
    mrb_define_method(mrb, class_conn, "remote_ip", h2o_mrb_conn_remote_ip, MRB_ARGS_NONE());
}
