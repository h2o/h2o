#include "mruby.h"
#include "mruby/array.h"
#include "mruby/class.h"
#include "mruby/variable.h"
#include "mruby/proc.h"
#include "mruby/string.h"

static struct RObject *
method_object_alloc(mrb_state *mrb, struct RClass *mclass)
{
  return (struct RObject*)mrb_obj_alloc(mrb, MRB_TT_OBJECT, mclass);
}

static void
bind_check(mrb_state *mrb, mrb_value recv, mrb_value owner)
{
  if (!mrb_module_p(owner) &&
      mrb_class_ptr(owner) != mrb_obj_class(mrb, recv) &&
      !mrb_obj_is_kind_of(mrb, recv, mrb_class_ptr(owner))) {
    if (mrb_sclass_p(owner)) {
      mrb_raise(mrb, E_TYPE_ERROR, "singleton method called for a different object");
    } else {
      mrb_raisef(mrb, E_TYPE_ERROR, "bind argument must be an instance of %v", owner);
    }
  }
}

static mrb_value
unbound_method_bind(mrb_state *mrb, mrb_value self)
{
  struct RObject *me;
  mrb_value owner = mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "_owner"));
  mrb_value name = mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "_name"));
  mrb_value proc = mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "_proc"));
  mrb_value klass = mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "_klass"));
  mrb_value recv = mrb_get_arg1(mrb);

  bind_check(mrb, recv, owner);
  me = method_object_alloc(mrb, mrb_class_get(mrb, "Method"));
  mrb_obj_iv_set(mrb, me, mrb_intern_lit(mrb, "_owner"), owner);
  mrb_obj_iv_set(mrb, me, mrb_intern_lit(mrb, "_recv"), recv);
  mrb_obj_iv_set(mrb, me, mrb_intern_lit(mrb, "_name"), name);
  mrb_obj_iv_set(mrb, me, mrb_intern_lit(mrb, "_proc"), proc);
  mrb_obj_iv_set(mrb, me, mrb_intern_lit(mrb, "_klass"), klass);

  return mrb_obj_value(me);
}

#define IV_GET(value, name) mrb_iv_get(mrb, value, mrb_intern_lit(mrb, name))
static mrb_value
method_eql(mrb_state *mrb, mrb_value self)
{
  mrb_value other = mrb_get_arg1(mrb);
  mrb_value receiver, orig_proc, other_proc;
  struct RClass *owner, *klass;
  struct RProc *orig_rproc, *other_rproc;

  if (!mrb_obj_is_instance_of(mrb, other, mrb_class(mrb, self)))
    return mrb_false_value();

  if (mrb_class(mrb, self) != mrb_class(mrb, other))
    return mrb_false_value();

  klass = mrb_class_ptr(IV_GET(self, "_klass"));
  if (klass != mrb_class_ptr(IV_GET(other, "_klass")))
    return mrb_false_value();

  owner = mrb_class_ptr(IV_GET(self, "_owner"));
  if (owner != mrb_class_ptr(IV_GET(other, "_owner")))
    return mrb_false_value();

  receiver = IV_GET(self, "_recv");
  if (!mrb_obj_equal(mrb, receiver, IV_GET(other, "_recv")))
    return mrb_false_value();

  orig_proc = IV_GET(self, "_proc");
  other_proc = IV_GET(other, "_proc");
  if (mrb_nil_p(orig_proc) && mrb_nil_p(other_proc)) {
    if (mrb_symbol(IV_GET(self, "_name")) == mrb_symbol(IV_GET(other, "_name")))
      return mrb_true_value();
    else
      return mrb_false_value();
  }

  if (mrb_nil_p(orig_proc))
    return mrb_false_value();
  if (mrb_nil_p(other_proc))
    return mrb_false_value();

  orig_rproc = mrb_proc_ptr(orig_proc);
  other_rproc = mrb_proc_ptr(other_proc);
  if (MRB_PROC_CFUNC_P(orig_rproc)) {
    if (!MRB_PROC_CFUNC_P(other_rproc))
      return mrb_false_value();
    if (orig_rproc->body.func != other_rproc->body.func)
      return mrb_false_value();
  }
  else {
    if (MRB_PROC_CFUNC_P(other_rproc))
      return mrb_false_value();
    if (orig_rproc->body.irep != other_rproc->body.irep)
      return mrb_false_value();
  }

  return mrb_true_value();
}

#undef IV_GET

static mrb_value
mcall(mrb_state *mrb, mrb_value recv, mrb_value proc, mrb_value name, struct RClass *owner,
      mrb_int argc, mrb_value *argv, mrb_value block)
{
  mrb_value ret;
  mrb_sym orig_mid = mrb->c->ci->mid;

  mrb->c->ci->mid = mrb_symbol(name);
  if (mrb_nil_p(proc)) {
    mrb_value missing_argv = mrb_ary_new_from_values(mrb, argc, argv);
    mrb_ary_unshift(mrb, missing_argv, name);
    ret = mrb_funcall_argv(mrb, recv, mrb_intern_lit(mrb, "method_missing"), argc + 1, RARRAY_PTR(missing_argv));
  }
  else if (!mrb_nil_p(block)) {
    /*
      workaround since `mrb_yield_with_class` does not support passing block as parameter
      need new API that initializes `mrb->c->stack[argc+1]` with block passed by argument
    */
    ret = mrb_funcall_with_block(mrb, recv, mrb_symbol(name), argc, argv, block);
  }
  else {
    ret = mrb_yield_with_class(mrb, proc, argc, argv, recv, owner);
  }
  mrb->c->ci->mid = orig_mid;
  return ret;
}

static mrb_value
method_call(mrb_state *mrb, mrb_value self)
{
  mrb_value proc = mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "_proc"));
  mrb_value name = mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "_name"));
  mrb_value recv = mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "_recv"));
  struct RClass *owner = mrb_class_ptr(mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "_owner")));
  mrb_int argc;
  mrb_value *argv, block;

  mrb_get_args(mrb, "*&", &argv, &argc, &block);
  return mcall(mrb, recv, proc, name, owner, argc, argv, block);
}

static mrb_value
method_bcall(mrb_state *mrb, mrb_value self)
{
  mrb_value proc = mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "_proc"));
  mrb_value name = mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "_name"));
  mrb_value recv = mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "_recv"));
  mrb_value owner = mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "_owner"));
  mrb_int argc;
  mrb_value *argv, block;

  mrb_get_args(mrb, "o*&", &recv, &argv, &argc, &block);
  bind_check(mrb, recv, owner);
  return mcall(mrb, recv, proc, name, mrb_class_ptr(owner), argc, argv, block);
}

static mrb_value
method_unbind(mrb_state *mrb, mrb_value self)
{
  struct RObject *ume;
  mrb_value owner = mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "_owner"));
  mrb_value name = mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "_name"));
  mrb_value proc = mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "_proc"));
  mrb_value klass = mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "_klass"));

  ume = method_object_alloc(mrb, mrb_class_get(mrb, "UnboundMethod"));
  mrb_obj_iv_set(mrb, ume, mrb_intern_lit(mrb, "_owner"), owner);
  mrb_obj_iv_set(mrb, ume, mrb_intern_lit(mrb, "_recv"), mrb_nil_value());
  mrb_obj_iv_set(mrb, ume, mrb_intern_lit(mrb, "_name"), name);
  mrb_obj_iv_set(mrb, ume, mrb_intern_lit(mrb, "_proc"), proc);
  mrb_obj_iv_set(mrb, ume, mrb_intern_lit(mrb, "_klass"), klass);

  return mrb_obj_value(ume);
}

static struct RProc *
method_search_vm(mrb_state *mrb, struct RClass **cp, mrb_sym mid)
{
  mrb_method_t m = mrb_method_search_vm(mrb, cp, mid);
  if (MRB_METHOD_UNDEF_P(m))
    return NULL;
  if (MRB_METHOD_PROC_P(m))
    return MRB_METHOD_PROC(m);
  return mrb_proc_new_cfunc(mrb, MRB_METHOD_FUNC(m));
}

static mrb_value
method_super_method(mrb_state *mrb, mrb_value self)
{
  mrb_value recv = mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "_recv"));
  mrb_value klass = mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "_klass"));
  mrb_value owner = mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "_owner"));
  mrb_value name = mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "_name"));
  struct RClass *super, *rklass;
  struct RProc *proc;
  struct RObject *me;

  switch (mrb_type(klass)) {
    case MRB_TT_SCLASS:
      super = mrb_class_ptr(klass)->super->super;
      break;
    case MRB_TT_ICLASS:
      super = mrb_class_ptr(klass)->super;
      break;
    default:
      super = mrb_class_ptr(owner)->super;
      break;
  }

  proc = method_search_vm(mrb, &super, mrb_symbol(name));
  if (!proc)
    return mrb_nil_value();

  rklass = super;
  while (super->tt == MRB_TT_ICLASS)
    super = super->c;

  me = method_object_alloc(mrb, mrb_obj_class(mrb, self));
  mrb_obj_iv_set(mrb, me, mrb_intern_lit(mrb, "_owner"), mrb_obj_value(super));
  mrb_obj_iv_set(mrb, me, mrb_intern_lit(mrb, "_recv"), recv);
  mrb_obj_iv_set(mrb, me, mrb_intern_lit(mrb, "_name"), name);
  mrb_obj_iv_set(mrb, me, mrb_intern_lit(mrb, "_proc"), mrb_obj_value(proc));
  mrb_obj_iv_set(mrb, me, mrb_intern_lit(mrb, "_klass"), mrb_obj_value(rklass));

  return mrb_obj_value(me);
}

static mrb_value
method_arity(mrb_state *mrb, mrb_value self)
{
  mrb_value proc = mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "_proc"));
  mrb_int arity = mrb_nil_p(proc) ? -1 : mrb_proc_arity(mrb_proc_ptr(proc));
  return mrb_fixnum_value(arity);
}

static mrb_value
method_source_location(mrb_state *mrb, mrb_value self)
{
  mrb_value proc = mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "_proc"));
  struct RProc *rproc;
  struct RClass *orig;
  mrb_value ret;

  if (mrb_nil_p(proc))
    return mrb_nil_value();

  rproc = mrb_proc_ptr(proc);
  orig = rproc->c;
  rproc->c = mrb->proc_class;
  ret = mrb_funcall(mrb, proc, "source_location", 0);
  rproc->c = orig;
  return ret;
}

static mrb_value
method_parameters(mrb_state *mrb, mrb_value self)
{
  mrb_value proc = mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "_proc"));
  struct RProc *rproc;
  struct RClass *orig;
  mrb_value ret;

  if (mrb_nil_p(proc)) {
    mrb_value rest = mrb_symbol_value(mrb_intern_lit(mrb, "rest"));
    mrb_value arest = mrb_ary_new_from_values(mrb, 1, &rest);
    return mrb_ary_new_from_values(mrb, 1, &arest);
  }

  rproc = mrb_proc_ptr(proc);
  orig = rproc->c;
  rproc->c = mrb->proc_class;
  ret = mrb_funcall(mrb, proc, "parameters", 0);
  rproc->c = orig;
  return ret;
}

static mrb_value
method_to_s(mrb_state *mrb, mrb_value self)
{
  mrb_value owner = mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "_owner"));
  mrb_value klass = mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "_klass"));
  mrb_value name = mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "_name"));
  mrb_value str = mrb_str_new_lit(mrb, "#<");
  struct RClass *rklass;

  mrb_str_cat_cstr(mrb, str, mrb_obj_classname(mrb, self));
  mrb_str_cat_lit(mrb, str, ": ");
  rklass = mrb_class_ptr(klass);
  if (mrb_class_ptr(owner) == rklass) {
    mrb_str_concat(mrb, str, owner);
    mrb_str_cat_lit(mrb, str, "#");
    mrb_str_concat(mrb, str, name);
  }
  else {
    mrb_str_cat_cstr(mrb, str, mrb_class_name(mrb, rklass));
    mrb_str_cat_lit(mrb, str, "(");
    mrb_str_concat(mrb, str, owner);
    mrb_str_cat_lit(mrb, str, ")#");
    mrb_str_concat(mrb, str, name);
  }
  mrb_str_cat_lit(mrb, str, ">");
  return str;
}

static void
mrb_search_method_owner(mrb_state *mrb, struct RClass *c, mrb_value obj, mrb_sym name, struct RClass **owner, struct RProc **proc, mrb_bool unbound)
{
  mrb_value ret;

  *owner = c;
  *proc = method_search_vm(mrb, owner, name);
  if (!*proc) {
    if (unbound) {
      goto name_error;
    }
    if (!mrb_respond_to(mrb, obj, mrb_intern_lit(mrb, "respond_to_missing?"))) {
      goto name_error;
    }
    ret = mrb_funcall(mrb, obj, "respond_to_missing?", 2, mrb_symbol_value(name), mrb_true_value());
    if (!mrb_test(ret)) {
      goto name_error;
    }
    *owner = c;
  }

  while ((*owner)->tt == MRB_TT_ICLASS)
    *owner = (*owner)->c;

  return;

name_error:
  mrb_raisef(mrb, E_NAME_ERROR, "undefined method '%n' for class '%C'", name, c);
}

static mrb_value
mrb_kernel_method(mrb_state *mrb, mrb_value self)
{
  struct RClass *owner;
  struct RProc *proc;
  struct RObject *me;
  mrb_sym name;

  mrb_get_args(mrb, "n", &name);

  mrb_search_method_owner(mrb, mrb_class(mrb, self), self, name, &owner, &proc, FALSE);

  me = method_object_alloc(mrb, mrb_class_get(mrb, "Method"));
  mrb_obj_iv_set(mrb, me, mrb_intern_lit(mrb, "_owner"), mrb_obj_value(owner));
  mrb_obj_iv_set(mrb, me, mrb_intern_lit(mrb, "_recv"), self);
  mrb_obj_iv_set(mrb, me, mrb_intern_lit(mrb, "_name"), mrb_symbol_value(name));
  mrb_obj_iv_set(mrb, me, mrb_intern_lit(mrb, "_proc"), proc ? mrb_obj_value(proc) : mrb_nil_value());
  mrb_obj_iv_set(mrb, me, mrb_intern_lit(mrb, "_klass"), mrb_obj_value(mrb_class(mrb, self)));

  return mrb_obj_value(me);
}

static mrb_value
mrb_module_instance_method(mrb_state *mrb, mrb_value self)
{
  struct RClass *owner;
  struct RProc *proc;
  struct RObject *ume;
  mrb_sym name;

  mrb_get_args(mrb, "n", &name);

  mrb_search_method_owner(mrb, mrb_class_ptr(self), self, name, &owner, &proc, TRUE);

  ume = method_object_alloc(mrb, mrb_class_get(mrb, "UnboundMethod"));
  mrb_obj_iv_set(mrb, ume, mrb_intern_lit(mrb, "_owner"), mrb_obj_value(owner));
  mrb_obj_iv_set(mrb, ume, mrb_intern_lit(mrb, "_recv"), mrb_nil_value());
  mrb_obj_iv_set(mrb, ume, mrb_intern_lit(mrb, "_name"), mrb_symbol_value(name));
  mrb_obj_iv_set(mrb, ume, mrb_intern_lit(mrb, "_proc"), proc ? mrb_obj_value(proc) : mrb_nil_value());
  mrb_obj_iv_set(mrb, ume, mrb_intern_lit(mrb, "_klass"), self);

  return mrb_obj_value(ume);
}

static mrb_value
method_owner(mrb_state *mrb, mrb_value self)
{
  return mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "_owner"));
}

static mrb_value
method_receiver(mrb_state *mrb, mrb_value self)
{
  return mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "_recv"));
}

static mrb_value
method_name(mrb_state *mrb, mrb_value self)
{
  return mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "_name"));
}

void
mrb_mruby_method_gem_init(mrb_state* mrb)
{
  struct RClass *unbound_method = mrb_define_class(mrb, "UnboundMethod", mrb->object_class);
  struct RClass *method = mrb_define_class(mrb, "Method", mrb->object_class);

  mrb_undef_class_method(mrb, unbound_method, "new");
  mrb_define_method(mrb, unbound_method, "bind", unbound_method_bind, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, unbound_method, "super_method", method_super_method, MRB_ARGS_NONE());
  mrb_define_method(mrb, unbound_method, "==", method_eql, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, unbound_method, "eql?", method_eql, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, unbound_method, "to_s", method_to_s, MRB_ARGS_NONE());
  mrb_define_method(mrb, unbound_method, "inspect", method_to_s, MRB_ARGS_NONE());
  mrb_define_method(mrb, unbound_method, "arity", method_arity, MRB_ARGS_NONE());
  mrb_define_method(mrb, unbound_method, "source_location", method_source_location, MRB_ARGS_NONE());
  mrb_define_method(mrb, unbound_method, "parameters", method_parameters, MRB_ARGS_NONE());
  mrb_define_method(mrb, unbound_method, "bind_call", method_bcall, MRB_ARGS_REQ(1)|MRB_ARGS_ANY());
  mrb_define_method(mrb, unbound_method, "owner", method_owner, MRB_ARGS_NONE());
  mrb_define_method(mrb, unbound_method, "name", method_name, MRB_ARGS_NONE());

  mrb_undef_class_method(mrb, method, "new");
  mrb_define_method(mrb, method, "==", method_eql, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, method, "eql?", method_eql, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, method, "to_s", method_to_s, MRB_ARGS_NONE());
  mrb_define_method(mrb, method, "inspect", method_to_s, MRB_ARGS_NONE());
  mrb_define_method(mrb, method, "call", method_call, MRB_ARGS_ANY());
  mrb_define_method(mrb, method, "[]", method_call, MRB_ARGS_ANY());
  mrb_define_method(mrb, method, "unbind", method_unbind, MRB_ARGS_NONE());
  mrb_define_method(mrb, method, "super_method", method_super_method, MRB_ARGS_NONE());
  mrb_define_method(mrb, method, "arity", method_arity, MRB_ARGS_NONE());
  mrb_define_method(mrb, method, "source_location", method_source_location, MRB_ARGS_NONE());
  mrb_define_method(mrb, method, "parameters", method_parameters, MRB_ARGS_NONE());
  mrb_define_method(mrb, method, "owner", method_owner, MRB_ARGS_NONE());
  mrb_define_method(mrb, method, "receiver", method_receiver, MRB_ARGS_NONE());
  mrb_define_method(mrb, method, "name", method_name, MRB_ARGS_NONE());

  mrb_define_method(mrb, mrb->kernel_module, "method", mrb_kernel_method, MRB_ARGS_REQ(1));

  mrb_define_method(mrb, mrb->module_class, "instance_method", mrb_module_instance_method, MRB_ARGS_REQ(1));
}

void
mrb_mruby_method_gem_final(mrb_state* mrb)
{
}
