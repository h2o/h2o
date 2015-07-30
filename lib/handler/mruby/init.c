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
#include <mruby/compile.h>

#define GC_ARENA_RESTORE mrb_gc_arena_restore(mrb, 0);

void h2o_mrb_core_class_init(mrb_state *mrb, struct RClass *class);
void h2o_mrb_request_class_init(mrb_state *mrb, struct RClass *class);
void h2o_mrb_conn_class_init(mrb_state *mrb, struct RClass *class);

void h2o_mrb_class_init(mrb_state *mrb)
{
    struct RClass *class;

    class = mrb_define_class(mrb, "H2O", mrb->object_class);

    h2o_mrb_core_class_init(mrb, class);
    GC_ARENA_RESTORE;
    h2o_mrb_request_class_init(mrb, class);
    GC_ARENA_RESTORE;
    h2o_mrb_conn_class_init(mrb, class);
    GC_ARENA_RESTORE;
}
