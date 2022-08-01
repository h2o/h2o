#include <mruby.h>
#include <mruby/string.h>
#include <stdio.h>

static mrb_value
mrb_c_method(mrb_state *mrb, mrb_value self)
{
  mrb_ensure_string_type(mrb, self);
  printf("%s: A C Extension\n", mrb_str_to_cstr(mrb, self));

  return self;
}

void
mrb_c_and_ruby_extension_example_gem_init(mrb_state* mrb) {
  struct RClass *class_cextension = mrb_define_module(mrb, "CRubyExtension");
  mrb_define_class_method(mrb, class_cextension, "c_method", mrb_c_method, MRB_ARGS_NONE());
}

void
mrb_c_and_ruby_extension_example_gem_final(mrb_state* mrb) {
  /* finalizer */
}
