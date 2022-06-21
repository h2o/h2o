#include "mruby.h"
#include "mruby/array.h"
#include "mruby/class.h"
#include "mruby/variable.h"
#include "mruby/proc.h"
#include "mruby/string.h"
#include "mruby/presym.h"

mrb_noreturn void mrb_method_missing(mrb_state *mrb, mrb_sym name, mrb_value self, mrb_value args);
mrb_value mrb_exec_irep(mrb_state *mrb, mrb_value self, struct RProc *p);

// Defined by mruby-proc-ext on which mruby-method depends
mrb_value mrb_proc_parameters(mrb_state *mrb, mrb_value proc);
mrb_value mrb_proc_source_location(mrb_state *mrb, struct RProc *p);

static mrb_value
args_shift(mrb_state *mrb)
{
  mrb_callinfo *ci = mrb->c->ci;
  mrb_value *argv = ci->stack + 1;

  if (ci->n < 15) {
    if (ci->n == 0) { goto argerr; }
    mrb_assert(ci->nk == 0 || ci->nk == 15);
    mrb_value obj = argv[0];
    int count = ci->n + (ci->nk == 0 ? 0 : 1) + 1 /* block */ - 1 /* first value */;
    memmove(argv, argv + 1, count * sizeof(mrb_value));
    ci->n--;
    return obj;
  }
  else if (RARRAY_LEN(*argv) > 0) {
    return mrb_ary_shift(mrb, *argv);
  }
  else {
  argerr:
    mrb_argnum_error(mrb, 0, 1, -1);
    return mrb_undef_value(); /* not reached */
  }
}

static void
args_unshift(mrb_state *mrb, mrb_value obj)
{
  mrb_callinfo *ci = mrb->c->ci;
  mrb_value *argv = ci->stack + 1;

  if (ci->n < 15) {
    mrb_assert(ci->nk == 0 || ci->nk == 15);
    mrb_value args = mrb_ary_new_from_values(mrb, ci->n, argv);
    if (ci->nk == 0) {
      mrb_value block = argv[ci->n];
      argv[0] = args;
      argv[1] = block;
    }
    else {
      mrb_value keyword = argv[ci->n];
      mrb_value block = argv[ci->n + 1];
      argv[0] = args;
      argv[1] = keyword;
      argv[2] = block;
    }
    ci->n = 15;
  }

  mrb_ary_unshift(mrb, *argv, obj);
}

static struct RProc*
method_missing_prepare(mrb_state *mrb, mrb_sym *mid, mrb_value recv, struct RClass **tc)
{
  const mrb_sym id_method_missing = MRB_SYM(method_missing);
  mrb_callinfo *ci = mrb->c->ci;

  if (*mid == id_method_missing) {
  method_missing: ;
    int n = ci->n;
    mrb_value *argv = ci->stack + 1;
    mrb_value args = (n == 15) ? argv[0] : mrb_ary_new_from_values(mrb, n, argv);
    mrb_method_missing(mrb, id_method_missing, recv, args);
  }

  *tc = mrb_class(mrb, recv);
  mrb_method_t m = mrb_method_search_vm(mrb, tc, id_method_missing);
  if (MRB_METHOD_UNDEF_P(m)) {
    goto method_missing;
  }

  struct RProc *proc;
  if (MRB_METHOD_FUNC_P(m)) {
    proc = mrb_proc_new_cfunc(mrb, MRB_METHOD_FUNC(m));
    MRB_PROC_SET_TARGET_CLASS(proc, *tc);
  }
  else {
    proc = MRB_METHOD_PROC(m);
  }

  args_unshift(mrb, mrb_symbol_value(*mid));
  *mid = id_method_missing;

  return proc;
}

static struct RObject *
method_object_alloc(mrb_state *mrb, struct RClass *mclass)
{
  return MRB_OBJ_ALLOC(mrb, MRB_TT_OBJECT, mclass);
}

static struct RProc*
method_extract_proc(mrb_state *mrb, mrb_value self)
{
  mrb_value obj = mrb_iv_get(mrb, self, MRB_SYM(_proc));
  if (mrb_nil_p(obj)) {
    return NULL;
  }
  else {
    mrb_check_type(mrb, obj, MRB_TT_PROC);
    return mrb_proc_ptr(obj);
  }
}

static mrb_value
method_extract_receiver(mrb_state *mrb, mrb_value self)
{
  return mrb_iv_get(mrb, self, MRB_SYM(_recv));
}

static mrb_sym
method_extract_mid(mrb_state *mrb, mrb_value self)
{
  mrb_value obj = mrb_iv_get(mrb, self, MRB_SYM(_name));
  mrb_check_type(mrb, obj, MRB_TT_SYMBOL);
  return mrb_symbol(obj);
}

static struct RClass*
method_extract_owner(mrb_state *mrb, mrb_value self)
{
  mrb_value obj = mrb_iv_get(mrb, self, MRB_SYM(_owner));
  switch (mrb_type(obj)) {
    case MRB_TT_CLASS:
    case MRB_TT_MODULE:
    case MRB_TT_SCLASS:
      break;
    default:
      mrb_raise(mrb, E_TYPE_ERROR, "not class/module as owner of method object");
  }
  return mrb_class_ptr(obj);
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
  mrb_value owner = mrb_iv_get(mrb, self, MRB_SYM(_owner));
  mrb_value name = mrb_iv_get(mrb, self, MRB_SYM(_name));
  mrb_value proc = mrb_iv_get(mrb, self, MRB_SYM(_proc));
  mrb_value klass = mrb_iv_get(mrb, self, MRB_SYM(_klass));
  mrb_value recv = mrb_get_arg1(mrb);

  bind_check(mrb, recv, owner);
  me = method_object_alloc(mrb, mrb_class_get_id(mrb, MRB_SYM(Method)));
  mrb_obj_iv_set(mrb, me, MRB_SYM(_owner), owner);
  mrb_obj_iv_set(mrb, me, MRB_SYM(_recv), recv);
  mrb_obj_iv_set(mrb, me, MRB_SYM(_name), name);
  mrb_obj_iv_set(mrb, me, MRB_SYM(_proc), proc);
  mrb_obj_iv_set(mrb, me, MRB_SYM(_klass), klass);

  return mrb_obj_value(me);
}

#define IV_GET(value, name) mrb_iv_get(mrb, value, name)
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

  klass = mrb_class_ptr(IV_GET(self, MRB_SYM(_klass)));
  if (klass != mrb_class_ptr(IV_GET(other, MRB_SYM(_klass))))
    return mrb_false_value();

  owner = mrb_class_ptr(IV_GET(self, MRB_SYM(_owner)));
  if (owner != mrb_class_ptr(IV_GET(other, MRB_SYM(_owner))))
    return mrb_false_value();

  receiver = IV_GET(self, MRB_SYM(_recv));
  if (!mrb_obj_equal(mrb, receiver, IV_GET(other, MRB_SYM(_recv))))
    return mrb_false_value();

  orig_proc = IV_GET(self, MRB_SYM(_proc));
  other_proc = IV_GET(other, MRB_SYM(_proc));
  if (mrb_nil_p(orig_proc) && mrb_nil_p(other_proc)) {
    if (mrb_symbol(IV_GET(self, MRB_SYM(_name))) == mrb_symbol(IV_GET(other, MRB_SYM(_name))))
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
mcall(mrb_state *mrb, mrb_value self, mrb_value recv)
{
  struct RProc *proc = method_extract_proc(mrb, self);
  mrb_sym mid = method_extract_mid(mrb, self);
  struct RClass *tc = method_extract_owner(mrb, self);

  if (mrb_undef_p(recv)) {
    recv = method_extract_receiver(mrb, self);
  }
  else {
    bind_check(mrb, recv, mrb_obj_value(tc));
  }

  if (!proc) {
    proc = method_missing_prepare(mrb, &mid, recv, &tc);
  }
  mrb->c->ci->mid = mid;
  mrb->c->ci->u.target_class = tc;

  return mrb_exec_irep(mrb, recv, proc);
}

static mrb_value
method_call(mrb_state *mrb, mrb_value self)
{
  return mcall(mrb, self, mrb_undef_value());
}

static mrb_value
method_bcall(mrb_state *mrb, mrb_value self)
{
  mrb_value recv = args_shift(mrb);
  mrb_gc_protect(mrb, recv);
  return mcall(mrb, self, recv);
}

static mrb_value
method_unbind(mrb_state *mrb, mrb_value self)
{
  struct RObject *ume;
  mrb_value owner = mrb_iv_get(mrb, self, MRB_SYM(_owner));
  mrb_value name = mrb_iv_get(mrb, self, MRB_SYM(_name));
  mrb_value proc = mrb_iv_get(mrb, self, MRB_SYM(_proc));
  mrb_value klass = mrb_iv_get(mrb, self, MRB_SYM(_klass));

  ume = method_object_alloc(mrb, mrb_class_get_id(mrb, MRB_SYM(UnboundMethod)));
  mrb_obj_iv_set(mrb, ume, MRB_SYM(_owner), owner);
  mrb_obj_iv_set(mrb, ume, MRB_SYM(_recv), mrb_nil_value());
  mrb_obj_iv_set(mrb, ume, MRB_SYM(_name), name);
  mrb_obj_iv_set(mrb, ume, MRB_SYM(_proc), proc);
  mrb_obj_iv_set(mrb, ume, MRB_SYM(_klass), klass);

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

  struct RProc *proc = mrb_proc_new_cfunc(mrb, MRB_METHOD_FUNC(m));
  if (MRB_METHOD_NOARG_P(m)) {
    proc->flags |= MRB_PROC_NOARG;
  }
  return proc;
}

static mrb_value
method_super_method(mrb_state *mrb, mrb_value self)
{
  mrb_value recv = mrb_iv_get(mrb, self, MRB_SYM(_recv));
  mrb_value klass = mrb_iv_get(mrb, self, MRB_SYM(_klass));
  mrb_value owner = mrb_iv_get(mrb, self, MRB_SYM(_owner));
  mrb_value name = mrb_iv_get(mrb, self, MRB_SYM(_name));
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
  mrb_obj_iv_set(mrb, me, MRB_SYM(_owner), mrb_obj_value(super));
  mrb_obj_iv_set(mrb, me, MRB_SYM(_recv), recv);
  mrb_obj_iv_set(mrb, me, MRB_SYM(_name), name);
  mrb_obj_iv_set(mrb, me, MRB_SYM(_proc), mrb_obj_value(proc));
  mrb_obj_iv_set(mrb, me, MRB_SYM(_klass), mrb_obj_value(rklass));

  return mrb_obj_value(me);
}

static mrb_value
method_arity(mrb_state *mrb, mrb_value self)
{
  mrb_value proc = mrb_iv_get(mrb, self, MRB_SYM(_proc));
  mrb_int arity = mrb_nil_p(proc) ? -1 : mrb_proc_arity(mrb_proc_ptr(proc));
  return mrb_fixnum_value(arity);
}

static mrb_value
method_source_location(mrb_state *mrb, mrb_value self)
{
  mrb_value proc = mrb_iv_get(mrb, self, MRB_SYM(_proc));

  if (mrb_nil_p(proc))
    return mrb_nil_value();

  return mrb_proc_source_location(mrb, mrb_proc_ptr(proc));
}

static mrb_value
method_parameters(mrb_state *mrb, mrb_value self)
{
  mrb_value proc = mrb_iv_get(mrb, self, MRB_SYM(_proc));

  if (mrb_nil_p(proc)) {
    mrb_value rest = mrb_symbol_value(MRB_SYM(rest));
    mrb_value arest = mrb_ary_new_from_values(mrb, 1, &rest);
    return mrb_ary_new_from_values(mrb, 1, &arest);
  }

  return mrb_proc_parameters(mrb, proc);
}

static mrb_value
method_to_s(mrb_state *mrb, mrb_value self)
{
  mrb_value owner = mrb_iv_get(mrb, self, MRB_SYM(_owner));
  mrb_value klass = mrb_iv_get(mrb, self, MRB_SYM(_klass));
  mrb_value name = mrb_iv_get(mrb, self, MRB_SYM(_name));
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
    if (!mrb_respond_to(mrb, obj, MRB_SYM_Q(respond_to_missing))) {
      goto name_error;
    }
    ret = mrb_funcall_id(mrb, obj, MRB_SYM_Q(respond_to_missing), 2, mrb_symbol_value(name), mrb_true_value());
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

  me = method_object_alloc(mrb, mrb_class_get_id(mrb, MRB_SYM(Method)));
  mrb_obj_iv_set(mrb, me, MRB_SYM(_owner), mrb_obj_value(owner));
  mrb_obj_iv_set(mrb, me, MRB_SYM(_recv), self);
  mrb_obj_iv_set(mrb, me, MRB_SYM(_name), mrb_symbol_value(name));
  mrb_obj_iv_set(mrb, me, MRB_SYM(_proc), proc ? mrb_obj_value(proc) : mrb_nil_value());
  mrb_obj_iv_set(mrb, me, MRB_SYM(_klass), mrb_obj_value(mrb_class(mrb, self)));

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

  ume = method_object_alloc(mrb, mrb_class_get_id(mrb, MRB_SYM(UnboundMethod)));
  mrb_obj_iv_set(mrb, ume, MRB_SYM(_owner), mrb_obj_value(owner));
  mrb_obj_iv_set(mrb, ume, MRB_SYM(_recv), mrb_nil_value());
  mrb_obj_iv_set(mrb, ume, MRB_SYM(_name), mrb_symbol_value(name));
  mrb_obj_iv_set(mrb, ume, MRB_SYM(_proc), proc ? mrb_obj_value(proc) : mrb_nil_value());
  mrb_obj_iv_set(mrb, ume, MRB_SYM(_klass), self);

  return mrb_obj_value(ume);
}

static mrb_value
method_owner(mrb_state *mrb, mrb_value self)
{
  return mrb_iv_get(mrb, self, MRB_SYM(_owner));
}

static mrb_value
method_receiver(mrb_state *mrb, mrb_value self)
{
  return mrb_iv_get(mrb, self, MRB_SYM(_recv));
}

static mrb_value
method_name(mrb_state *mrb, mrb_value self)
{
  return mrb_iv_get(mrb, self, MRB_SYM(_name));
}

void
mrb_mruby_method_gem_init(mrb_state* mrb)
{
  struct RClass *unbound_method = mrb_define_class_id(mrb, MRB_SYM(UnboundMethod), mrb->object_class);
  struct RClass *method = mrb_define_class_id(mrb, MRB_SYM(Method), mrb->object_class);

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
