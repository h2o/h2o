#include <mruby.h>
#include <mruby/array.h>
#include <mruby/class.h>
#include <mruby/proc.h>

/*
 *  call-seq:
 *     nil.to_a    -> []
 *
 *  Always returns an empty array.
 */

static mrb_value
nil_to_a(mrb_state *mrb, mrb_value obj)
{
  return mrb_ary_new(mrb);
}

#ifndef MRB_WITHOUT_FLOAT
/*
 *  call-seq:
 *     nil.to_f    -> 0.0
 *
 *  Always returns zero.
 */

static mrb_value
nil_to_f(mrb_state *mrb, mrb_value obj)
{
  return mrb_float_value(mrb, 0.0);
}
#endif

/*
 *  call-seq:
 *     nil.to_i    -> 0
 *
 *  Always returns zero.
 */

static mrb_value
nil_to_i(mrb_state *mrb, mrb_value obj)
{
  return mrb_fixnum_value(0);
}

/*
 *  call-seq:
 *     obj.instance_exec(arg...) {|var...| block }                       -> obj
 *
 *  Executes the given block within the context of the receiver
 *  (_obj_). In order to set the context, the variable +self+ is set
 *  to _obj_ while the code is executing, giving the code access to
 *  _obj_'s instance variables.  Arguments are passed as block parameters.
 *
 *     class KlassWithSecret
 *       def initialize
 *         @secret = 99
 *       end
 *     end
 *     k = KlassWithSecret.new
 *     k.instance_exec(5) {|x| @secret+x }   #=> 104
 */

static mrb_value
mrb_obj_instance_exec(mrb_state *mrb, mrb_value self)
{
  const mrb_value *argv;
  mrb_int argc;
  mrb_value blk;
  struct RClass *c;

  mrb_get_args(mrb, "*&", &argv, &argc, &blk);

  if (mrb_nil_p(blk)) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "no block given");
  }

  switch (mrb_type(self)) {
  case MRB_TT_SYMBOL:
  case MRB_TT_FIXNUM:
#ifndef MRB_WITHOUT_FLOAT
  case MRB_TT_FLOAT:
#endif
    c = NULL;
    break;
  default:
    c = mrb_class_ptr(mrb_singleton_class(mrb, self));
    break;
  }
  mrb->c->ci->target_class = c;
  return mrb_yield_cont(mrb, blk, self, argc, argv);
}

void
mrb_mruby_object_ext_gem_init(mrb_state* mrb)
{
  struct RClass * n = mrb->nil_class;

  mrb_define_method(mrb, n, "to_a", nil_to_a,       MRB_ARGS_NONE());
#ifndef MRB_WITHOUT_FLOAT
  mrb_define_method(mrb, n, "to_f", nil_to_f,       MRB_ARGS_NONE());
#endif
  mrb_define_method(mrb, n, "to_i", nil_to_i,       MRB_ARGS_NONE());

  mrb_define_method(mrb, mrb->kernel_module, "instance_exec", mrb_obj_instance_exec, MRB_ARGS_ANY() | MRB_ARGS_BLOCK());
}

void
mrb_mruby_object_ext_gem_final(mrb_state* mrb)
{
}
