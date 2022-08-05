#include <mruby.h>
#include <mruby/array.h>
#include <mruby/class.h>
#include <mruby/hash.h>
#include <mruby/proc.h>
#include <mruby/presym.h>

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

#ifndef MRB_NO_FLOAT
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
 *     nil.to_h    -> {}
 *
 *  Always returns an empty hash.
 */

static mrb_value
nil_to_h(mrb_state *mrb, mrb_value obj)
{
  return mrb_hash_new(mrb);
}

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
 *     obj.itself -> an_object
 *
 *  Returns <i>obj</i>.
 *
 *      string = 'my string' #=> "my string"
 *      string.itself.object_id == string.object_id #=> true
 *
 */
static mrb_value
mrb_f_itself(mrb_state *mrb, mrb_value self)
{
  return self;
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

  mrb_get_args(mrb, "*&!", &argv, &argc, &blk);
  c = mrb_singleton_class_ptr(mrb, self);
  if (mrb->c->ci->cci > 0) {
    return mrb_yield_with_class(mrb, blk, argc, argv, self, c);
  }
  mrb_vm_ci_target_class_set(mrb->c->ci, c);
  return mrb_yield_cont(mrb, blk, self, argc, argv);
}

void
mrb_mruby_object_ext_gem_init(mrb_state* mrb)
{
  struct RClass * n = mrb->nil_class;

  mrb_define_method(mrb, n, "to_a", nil_to_a,       MRB_ARGS_NONE());
#ifndef MRB_NO_FLOAT
  mrb_define_method(mrb, n, "to_f", nil_to_f,       MRB_ARGS_NONE());
#endif
  mrb_define_method(mrb, n, "to_h", nil_to_h,       MRB_ARGS_NONE());
  mrb_define_method(mrb, n, "to_i", nil_to_i,       MRB_ARGS_NONE());

  mrb_define_method(mrb, mrb->kernel_module, "itself", mrb_f_itself, MRB_ARGS_NONE());

  mrb_define_method(mrb, mrb_class_get_id(mrb, MRB_SYM(BasicObject)), "instance_exec", mrb_obj_instance_exec, MRB_ARGS_ANY() | MRB_ARGS_BLOCK());
}

void
mrb_mruby_object_ext_gem_final(mrb_state* mrb)
{
}
