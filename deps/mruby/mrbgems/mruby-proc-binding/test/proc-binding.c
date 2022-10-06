#include <mruby.h>
#include <mruby/compile.h>

static mrb_value
proc_in_c(mrb_state *mrb, mrb_value self)
{
  return mrb_load_string(mrb, "proc { |a, b| a + b }");
}

void
mrb_mruby_proc_binding_gem_test(mrb_state *mrb)
{
  mrb_define_method(mrb, mrb->object_class, "proc_in_c", proc_in_c, MRB_ARGS_NONE());
}
