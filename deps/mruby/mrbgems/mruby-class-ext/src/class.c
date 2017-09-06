#include "mruby.h"
#include "mruby/class.h"
#include "mruby/string.h"

static mrb_value
mrb_mod_name(mrb_state *mrb, mrb_value self)
{
  mrb_value name = mrb_class_path(mrb, mrb_class_ptr(self));
  return mrb_nil_p(name)? name : mrb_str_dup(mrb, name);
}

static mrb_value
mrb_mod_singleton_class_p(mrb_state *mrb, mrb_value self)
{
  return mrb_bool_value(mrb_type(self) == MRB_TT_SCLASS);
}

void
mrb_mruby_class_ext_gem_init(mrb_state *mrb)
{
  struct RClass *mod = mrb->module_class;

  mrb_define_method(mrb, mod, "name", mrb_mod_name, MRB_ARGS_NONE());
  mrb_define_method(mrb, mod, "singleton_class?", mrb_mod_singleton_class_p, MRB_ARGS_NONE());
}

void
mrb_mruby_class_ext_gem_final(mrb_state *mrb)
{
}
