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

/*
 *  call-seq:
 *     module_exec(arg...) {|var...| block } -> obj
 *     class_exec(arg...) {|var...| block } -> obj
 *
 * Evaluates the given block in the context of the
 * class/module. The method defined in the block will belong
 * to the receiver. Any arguments passed to the method will be
 * passed to the block. This can be used if the block needs to
 * access instance variables.
 *
 *     class Thing
 *     end
 *     Thing.class_exec{
 *       def hello() "Hello there!" end
 *     }
 *     puts Thing.new.hello()
 */

static mrb_value
mrb_mod_module_exec(mrb_state *mrb, mrb_value self)
{
  const mrb_value *argv;
  mrb_int argc;
  mrb_value blk;

  mrb_get_args(mrb, "*&", &argv, &argc, &blk);

  if (mrb_nil_p(blk)) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "no block given");
  }

  mrb->c->ci->target_class = mrb_class_ptr(self);
  return mrb_yield_cont(mrb, blk, self, argc, argv);
}

void
mrb_mruby_class_ext_gem_init(mrb_state *mrb)
{
  struct RClass *mod = mrb->module_class;

  mrb_define_method(mrb, mod, "name", mrb_mod_name, MRB_ARGS_NONE());
  mrb_define_method(mrb, mod, "singleton_class?", mrb_mod_singleton_class_p, MRB_ARGS_NONE());
  mrb_define_method(mrb, mod, "module_exec", mrb_mod_module_exec, MRB_ARGS_ANY()|MRB_ARGS_BLOCK());
  mrb_define_method(mrb, mod, "class_exec", mrb_mod_module_exec, MRB_ARGS_ANY()|MRB_ARGS_BLOCK());
}

void
mrb_mruby_class_ext_gem_final(mrb_state *mrb)
{
}
