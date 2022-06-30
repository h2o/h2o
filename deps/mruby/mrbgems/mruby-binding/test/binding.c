#include <mruby.h>
#include <mruby/presym.h>

static mrb_value
binding_in_c(mrb_state *mrb, mrb_value self)
{
  return mrb_funcall_argv(mrb, mrb_obj_value(mrb->object_class), MRB_SYM(binding), 0, NULL);
}

void
mrb_mruby_binding_gem_test(mrb_state *mrb)
{
  mrb_define_method(mrb, mrb->object_class, "binding_in_c", binding_in_c, MRB_ARGS_NONE());
}
