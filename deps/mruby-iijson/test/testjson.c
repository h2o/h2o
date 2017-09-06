#include "mruby.h"
#include "mruby/value.h"
#include "mruby/variable.h"

void
mrb_mruby_iijson_gem_test(mrb_state* mrb)
{
  struct RClass *c = mrb_define_module(mrb, "TestJSON");
  mrb_const_set(mrb, mrb_obj_value(c), mrb_intern_lit(mrb, "MRB_INT_MIN"), mrb_fixnum_value(MRB_INT_MIN));
  mrb_const_set(mrb, mrb_obj_value(c), mrb_intern_lit(mrb, "MRB_INT_MAX"), mrb_fixnum_value(MRB_INT_MAX));
}
