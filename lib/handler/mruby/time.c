/*
 * Copyright (c) 2017 Ichito Nagata
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
#include <mruby/array.h>
#include "h2o/mruby_.h"

static mrb_value rfc1123_instance_method(mrb_state *mrb, mrb_value self)
{
    mrb_value ts = mrb_funcall(mrb, self, "to_i", 0);
    time_t timestamp = (time_t)mrb_fixnum(ts);
    struct tm gmt;
    gmtime_r(&timestamp, &gmt);
    
    mrb_value buf = mrb_str_buf_new(mrb, H2O_TIMESTR_RFC1123_LEN);
    h2o_time2str_rfc1123(RSTRING_PTR(buf), &gmt);
    RSTR_SET_LEN(RSTRING(buf), strlen(RSTRING_PTR(buf)));
    return buf;
}

static mrb_value rfc1123_class_method(mrb_state *mrb, mrb_value self)
{
    const char *arg;
    mrb_int arg_len;
    struct tm gmt = {0};
    
    mrb_get_args(mrb, "s", &arg, &arg_len);
    if (h2o_time_parse_rfc1123(arg, arg_len, &gmt) != 0) {
        mrb_raise(mrb, E_ARGUMENT_ERROR, "Not a valid time.");
    }
    
    h2o_mruby_shared_context_t *shared_ctx = mrb->ud;
    mrb_value klass = mrb_ary_entry(shared_ctx->constants, H2O_MRUBY_TIME_CLASS);
#define TF(v) mrb_fixnum_value( gmt.tm_ ## v )
    return mrb_funcall(mrb, klass, "gm", 6, TF(year + 1900), TF(mon + 1), TF(mday), TF(hour), TF(min), TF(sec));
    //return mrb_funcall(mrb, klass, "gm", 6, mrb_fixnum_value(gmt.tm_year + 1900), mrb_fixnum_value(gmt.tm_mon + 1), mrb_fixnum_value(gmt.tm_mday), mrb_fixnum_value(gmt.tm_hour), mrb_fixnum_value(gmt.tm_min), mrb_fixnum_value(gmt.tm_sec));
#undef TF
}

void h2o_mruby_time_init_context(h2o_mruby_shared_context_t *ctx)
{
    mrb_state *mrb = ctx->mrb;
    
    struct RClass *klass = mrb_class_get(mrb, "Time");
    mrb_ary_set(mrb, ctx->constants, H2O_MRUBY_TIME_CLASS, mrb_obj_value(klass));
    
    mrb_define_method(mrb, klass, "rfc1123", rfc1123_instance_method, MRB_ARGS_NONE());
    mrb_define_class_method(mrb, klass, "rfc1123", rfc1123_class_method, MRB_ARGS_REQ(1));
}
