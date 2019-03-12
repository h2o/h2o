#include "mruby.h"
#include "mruby/array.h"
#include "mruby/hash.h"
#include "mruby/variable.h"
#include "mruby/proc.h"
#include "mruby/class.h"
#include "mruby/string.h"

typedef enum {
  NOEX_PUBLIC    = 0x00,
  NOEX_NOSUPER   = 0x01,
  NOEX_PRIVATE   = 0x02,
  NOEX_PROTECTED = 0x04,
  NOEX_MASK      = 0x06,
  NOEX_BASIC     = 0x08,
  NOEX_UNDEF     = NOEX_NOSUPER,
  NOEX_MODFUNC   = 0x12,
  NOEX_SUPER     = 0x20,
  NOEX_VCALL     = 0x40,
  NOEX_RESPONDS  = 0x80
} mrb_method_flag_t;

static mrb_value
mrb_f_nil(mrb_state *mrb, mrb_value cv)
{
  return mrb_nil_value();
}

/* 15.3.1.3.20 */
/*
 *  call-seq:
 *     obj.instance_variable_defined?(symbol)    -> true or false
 *
 *  Returns <code>true</code> if the given instance variable is
 *  defined in <i>obj</i>.
 *
 *     class Fred
 *       def initialize(p1, p2)
 *         @a, @b = p1, p2
 *       end
 *     end
 *     fred = Fred.new('cat', 99)
 *     fred.instance_variable_defined?(:@a)    #=> true
 *     fred.instance_variable_defined?("@b")   #=> true
 *     fred.instance_variable_defined?("@c")   #=> false
 */
static mrb_value
mrb_obj_ivar_defined(mrb_state *mrb, mrb_value self)
{
  mrb_sym sym;

  mrb_get_args(mrb, "n", &sym);
  mrb_iv_name_sym_check(mrb, sym);
  return mrb_bool_value(mrb_iv_defined(mrb, self, sym));
}

/* 15.3.1.3.21 */
/*
 *  call-seq:
 *     obj.instance_variable_get(symbol)    -> obj
 *
 *  Returns the value of the given instance variable, or nil if the
 *  instance variable is not set. The <code>@</code> part of the
 *  variable name should be included for regular instance
 *  variables. Throws a <code>NameError</code> exception if the
 *  supplied symbol is not valid as an instance variable name.
 *
 *     class Fred
 *       def initialize(p1, p2)
 *         @a, @b = p1, p2
 *       end
 *     end
 *     fred = Fred.new('cat', 99)
 *     fred.instance_variable_get(:@a)    #=> "cat"
 *     fred.instance_variable_get("@b")   #=> 99
 */
static mrb_value
mrb_obj_ivar_get(mrb_state *mrb, mrb_value self)
{
  mrb_sym iv_name;

  mrb_get_args(mrb, "n", &iv_name);
  mrb_iv_name_sym_check(mrb, iv_name);
  return mrb_iv_get(mrb, self, iv_name);
}

/* 15.3.1.3.22 */
/*
 *  call-seq:
 *     obj.instance_variable_set(symbol, obj)    -> obj
 *
 *  Sets the instance variable names by <i>symbol</i> to
 *  <i>object</i>, thereby frustrating the efforts of the class's
 *  author to attempt to provide proper encapsulation. The variable
 *  did not have to exist prior to this call.
 *
 *     class Fred
 *       def initialize(p1, p2)
 *         @a, @b = p1, p2
 *       end
 *     end
 *     fred = Fred.new('cat', 99)
 *     fred.instance_variable_set(:@a, 'dog')   #=> "dog"
 *     fred.instance_variable_set(:@c, 'cat')   #=> "cat"
 *     fred.inspect                             #=> "#<Fred:0x401b3da8 @a=\"dog\", @b=99, @c=\"cat\">"
 */
static mrb_value
mrb_obj_ivar_set(mrb_state *mrb, mrb_value self)
{
  mrb_sym iv_name;
  mrb_value val;

  mrb_get_args(mrb, "no", &iv_name, &val);
  mrb_iv_name_sym_check(mrb, iv_name);
  mrb_iv_set(mrb, self, iv_name, val);
  return val;
}

/* 15.3.1.2.7 */
/*
 *  call-seq:
 *     local_variables   -> array
 *
 *  Returns the names of local variables in the current scope.
 *
 *  [mruby limitation]
 *  If variable symbol information was stripped out from
 *  compiled binary files using `mruby-strip -l`, this
 *  method always returns an empty array.
 */
static mrb_value
mrb_local_variables(mrb_state *mrb, mrb_value self)
{
  struct RProc *proc;
  mrb_irep *irep;
  mrb_value vars;
  size_t i;

  proc = mrb->c->ci[-1].proc;

  if (MRB_PROC_CFUNC_P(proc)) {
    return mrb_ary_new(mrb);
  }
  vars = mrb_hash_new(mrb);
  while (proc) {
    if (MRB_PROC_CFUNC_P(proc)) break;
    irep = proc->body.irep;
    if (!irep->lv) break;
    for (i = 0; i + 1 < irep->nlocals; ++i) {
      if (irep->lv[i].name) {
        mrb_sym sym = irep->lv[i].name;
        const char *name = mrb_sym2name(mrb, sym);
        switch (name[0]) {
        case '*': case '&':
          break;
        default:
          mrb_hash_set(mrb, vars, mrb_symbol_value(sym), mrb_true_value());
          break;
        }
      }
    }
    if (!MRB_PROC_ENV_P(proc)) break;
    proc = proc->upper;
    //if (MRB_PROC_SCOPE_P(proc)) break;
    if (!proc->c) break;
  }

  return mrb_hash_keys(mrb, vars);
}

KHASH_DECLARE(st, mrb_sym, char, FALSE)

static void
method_entry_loop(mrb_state *mrb, struct RClass* klass, khash_t(st)* set)
{
  khint_t i;

  khash_t(mt) *h = klass->mt;
  if (!h || kh_size(h) == 0) return;
  for (i=0;i<kh_end(h);i++) {
    if (kh_exist(h, i)) {
      mrb_method_t m = kh_value(h, i);
      if (MRB_METHOD_UNDEF_P(m)) continue;
      kh_put(st, mrb, set, kh_key(h, i));
    }
  }
}

mrb_value
mrb_class_instance_method_list(mrb_state *mrb, mrb_bool recur, struct RClass* klass, int obj)
{
  khint_t i;
  mrb_value ary;
  mrb_bool prepended = FALSE;
  struct RClass* oldklass;
  khash_t(st)* set = kh_init(st, mrb);

  if (!recur && (klass->flags & MRB_FL_CLASS_IS_PREPENDED)) {
    MRB_CLASS_ORIGIN(klass);
    prepended = TRUE;
  }

  oldklass = 0;
  while (klass && (klass != oldklass)) {
    method_entry_loop(mrb, klass, set);
    if ((klass->tt == MRB_TT_ICLASS && !prepended) ||
        (klass->tt == MRB_TT_SCLASS)) {
    }
    else {
      if (!recur) break;
    }
    oldklass = klass;
    klass = klass->super;
  }

  ary = mrb_ary_new_capa(mrb, kh_size(set));
  for (i=0;i<kh_end(set);i++) {
    if (kh_exist(set, i)) {
      mrb_ary_push(mrb, ary, mrb_symbol_value(kh_key(set, i)));
    }
  }
  kh_destroy(st, mrb, set);

  return ary;
}

static mrb_value
mrb_obj_methods(mrb_state *mrb, mrb_bool recur, mrb_value obj, mrb_method_flag_t flag)
{
  return mrb_class_instance_method_list(mrb, recur, mrb_class(mrb, obj), 0);
}
/* 15.3.1.3.31 */
/*
 *  call-seq:
 *     obj.methods    -> array
 *
 *  Returns a list of the names of methods publicly accessible in
 *  <i>obj</i>. This will include all the methods accessible in
 *  <i>obj</i>'s ancestors.
 *
 *     class Klass
 *       def kMethod()
 *       end
 *     end
 *     k = Klass.new
 *     k.methods[0..9]    #=> [:kMethod, :respond_to?, :nil?, :is_a?,
 *                        #    :class, :instance_variable_set,
 *                        #    :methods, :extend, :__send__, :instance_eval]
 *     k.methods.length   #=> 42
 */
static mrb_value
mrb_obj_methods_m(mrb_state *mrb, mrb_value self)
{
  mrb_bool recur = TRUE;
  mrb_get_args(mrb, "|b", &recur);
  return mrb_obj_methods(mrb, recur, self, (mrb_method_flag_t)0); /* everything but private */
}

/* 15.3.1.3.36 */
/*
 *  call-seq:
 *     obj.private_methods(all=true)   -> array
 *
 *  Returns the list of private methods accessible to <i>obj</i>. If
 *  the <i>all</i> parameter is set to <code>false</code>, only those methods
 *  in the receiver will be listed.
 */
static mrb_value
mrb_obj_private_methods(mrb_state *mrb, mrb_value self)
{
  mrb_bool recur = TRUE;
  mrb_get_args(mrb, "|b", &recur);
  return mrb_obj_methods(mrb, recur, self, NOEX_PRIVATE); /* private attribute not define */
}

/* 15.3.1.3.37 */
/*
 *  call-seq:
 *     obj.protected_methods(all=true)   -> array
 *
 *  Returns the list of protected methods accessible to <i>obj</i>. If
 *  the <i>all</i> parameter is set to <code>false</code>, only those methods
 *  in the receiver will be listed.
 */
static mrb_value
mrb_obj_protected_methods(mrb_state *mrb, mrb_value self)
{
  mrb_bool recur = TRUE;
  mrb_get_args(mrb, "|b", &recur);
  return mrb_obj_methods(mrb, recur, self, NOEX_PROTECTED); /* protected attribute not define */
}

/* 15.3.1.3.38 */
/*
 *  call-seq:
 *     obj.public_methods(all=true)   -> array
 *
 *  Returns the list of public methods accessible to <i>obj</i>. If
 *  the <i>all</i> parameter is set to <code>false</code>, only those methods
 *  in the receiver will be listed.
 */
static mrb_value
mrb_obj_public_methods(mrb_state *mrb, mrb_value self)
{
  mrb_bool recur = TRUE;
  mrb_get_args(mrb, "|b", &recur);
  return mrb_obj_methods(mrb, recur, self, NOEX_PUBLIC); /* public attribute not define */
}

static mrb_value
mrb_obj_singleton_methods(mrb_state *mrb, mrb_bool recur, mrb_value obj)
{
  khint_t i;
  mrb_value ary;
  struct RClass* klass;
  khash_t(st)* set = kh_init(st, mrb);

  klass = mrb_class(mrb, obj);

  if (klass && (klass->tt == MRB_TT_SCLASS)) {
      method_entry_loop(mrb, klass, set);
      klass = klass->super;
  }
  if (recur) {
      while (klass && ((klass->tt == MRB_TT_SCLASS) || (klass->tt == MRB_TT_ICLASS))) {
        method_entry_loop(mrb, klass, set);
        klass = klass->super;
      }
  }

  ary = mrb_ary_new(mrb);
  for (i=0;i<kh_end(set);i++) {
    if (kh_exist(set, i)) {
      mrb_ary_push(mrb, ary, mrb_symbol_value(kh_key(set, i)));
    }
  }
  kh_destroy(st, mrb, set);

  return ary;
}

/* 15.3.1.3.45 */
/*
 *  call-seq:
 *     obj.singleton_methods(all=true)    -> array
 *
 *  Returns an array of the names of singleton methods for <i>obj</i>.
 *  If the optional <i>all</i> parameter is true, the list will include
 *  methods in modules included in <i>obj</i>.
 *  Only public and protected singleton methods are returned.
 *
 *     module Other
 *       def three() end
 *     end
 *
 *     class Single
 *       def Single.four() end
 *     end
 *
 *     a = Single.new
 *
 *     def a.one()
 *     end
 *
 *     class << a
 *       include Other
 *       def two()
 *       end
 *     end
 *
 *     Single.singleton_methods    #=> [:four]
 *     a.singleton_methods(false)  #=> [:two, :one]
 *     a.singleton_methods         #=> [:two, :one, :three]
 */
static mrb_value
mrb_obj_singleton_methods_m(mrb_state *mrb, mrb_value self)
{
  mrb_bool recur = TRUE;
  mrb_get_args(mrb, "|b", &recur);
  return mrb_obj_singleton_methods(mrb, recur, self);
}

static mrb_value
mod_define_singleton_method(mrb_state *mrb, mrb_value self)
{
  struct RProc *p;
  mrb_method_t m;
  mrb_sym mid;
  mrb_value blk = mrb_nil_value();

  mrb_get_args(mrb, "n&", &mid, &blk);
  if (mrb_nil_p(blk)) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "no block given");
  }
  p = (struct RProc*)mrb_obj_alloc(mrb, MRB_TT_PROC, mrb->proc_class);
  mrb_proc_copy(p, mrb_proc_ptr(blk));
  p->flags |= MRB_PROC_STRICT;
  MRB_METHOD_FROM_PROC(m, p);
  mrb_define_method_raw(mrb, mrb_class_ptr(mrb_singleton_class(mrb, self)), mid, m);
  return mrb_symbol_value(mid);
}

static void
check_cv_name_str(mrb_state *mrb, mrb_value str)
{
  const char *s = RSTRING_PTR(str);
  mrb_int len = RSTRING_LEN(str);

  if (len < 3 || !(s[0] == '@' && s[1] == '@')) {
    mrb_name_error(mrb, mrb_intern_str(mrb, str), "'%S' is not allowed as a class variable name", str);
  }
}

static void
check_cv_name_sym(mrb_state *mrb, mrb_sym id)
{
  check_cv_name_str(mrb, mrb_sym2str(mrb, id));
}

/* 15.2.2.4.39 */
/*
 *  call-seq:
 *     remove_class_variable(sym)    -> obj
 *
 *  Removes the definition of the <i>sym</i>, returning that
 *  constant's value.
 *
 *     class Dummy
 *       @@var = 99
 *       puts @@var
 *       p class_variables
 *       remove_class_variable(:@@var)
 *       p class_variables
 *     end
 *
 *  <em>produces:</em>
 *
 *     99
 *     [:@@var]
 *     []
 */

static mrb_value
mrb_mod_remove_cvar(mrb_state *mrb, mrb_value mod)
{
  mrb_value val;
  mrb_sym id;

  mrb_get_args(mrb, "n", &id);
  check_cv_name_sym(mrb, id);

  val = mrb_iv_remove(mrb, mod, id);
  if (!mrb_undef_p(val)) return val;

  if (mrb_cv_defined(mrb, mod, id)) {
    mrb_name_error(mrb, id, "cannot remove %S for %S",
                   mrb_sym2str(mrb, id), mod);
  }

  mrb_name_error(mrb, id, "class variable %S not defined for %S",
                 mrb_sym2str(mrb, id), mod);

 /* not reached */
 return mrb_nil_value();
}

/* 15.2.2.4.16 */
/*
 *  call-seq:
 *     obj.class_variable_defined?(symbol)    -> true or false
 *
 *  Returns <code>true</code> if the given class variable is defined
 *  in <i>obj</i>.
 *
 *     class Fred
 *       @@foo = 99
 *     end
 *     Fred.class_variable_defined?(:@@foo)    #=> true
 *     Fred.class_variable_defined?(:@@bar)    #=> false
 */

static mrb_value
mrb_mod_cvar_defined(mrb_state *mrb, mrb_value mod)
{
  mrb_sym id;

  mrb_get_args(mrb, "n", &id);
  check_cv_name_sym(mrb, id);
  return mrb_bool_value(mrb_cv_defined(mrb, mod, id));
}

/* 15.2.2.4.17 */
/*
 *  call-seq:
 *     mod.class_variable_get(symbol)    -> obj
 *
 *  Returns the value of the given class variable (or throws a
 *  <code>NameError</code> exception). The <code>@@</code> part of the
 *  variable name should be included for regular class variables
 *
 *     class Fred
 *       @@foo = 99
 *     end
 *     Fred.class_variable_get(:@@foo)     #=> 99
 */

static mrb_value
mrb_mod_cvar_get(mrb_state *mrb, mrb_value mod)
{
  mrb_sym id;

  mrb_get_args(mrb, "n", &id);
  check_cv_name_sym(mrb, id);
  return mrb_cv_get(mrb, mod, id);
}

/* 15.2.2.4.18 */
/*
 *  call-seq:
 *     obj.class_variable_set(symbol, obj)    -> obj
 *
 *  Sets the class variable names by <i>symbol</i> to
 *  <i>object</i>.
 *
 *     class Fred
 *       @@foo = 99
 *       def foo
 *         @@foo
 *       end
 *     end
 *     Fred.class_variable_set(:@@foo, 101)     #=> 101
 *     Fred.new.foo                             #=> 101
 */

static mrb_value
mrb_mod_cvar_set(mrb_state *mrb, mrb_value mod)
{
  mrb_value value;
  mrb_sym id;

  mrb_get_args(mrb, "no", &id, &value);
  check_cv_name_sym(mrb, id);
  mrb_cv_set(mrb, mod, id, value);
  return value;
}

static mrb_value
mrb_mod_included_modules(mrb_state *mrb, mrb_value self)
{
  mrb_value result;
  struct RClass *c = mrb_class_ptr(self);
  struct RClass *origin = c;

  MRB_CLASS_ORIGIN(origin);
  result = mrb_ary_new(mrb);
  while (c) {
    if (c != origin && c->tt == MRB_TT_ICLASS) {
      if (c->c->tt == MRB_TT_MODULE) {
        mrb_ary_push(mrb, result, mrb_obj_value(c->c));
      }
    }
    c = c->super;
  }

  return result;
}

mrb_value mrb_class_instance_method_list(mrb_state*, mrb_bool, struct RClass*, int);

/* 15.2.2.4.33 */
/*
 *  call-seq:
 *     mod.instance_methods(include_super=true)   -> array
 *
 *  Returns an array containing the names of the public and protected instance
 *  methods in the receiver. For a module, these are the public and protected methods;
 *  for a class, they are the instance (not singleton) methods. With no
 *  argument, or with an argument that is <code>false</code>, the
 *  instance methods in <i>mod</i> are returned, otherwise the methods
 *  in <i>mod</i> and <i>mod</i>'s superclasses are returned.
 *
 *     module A
 *       def method1()  end
 *     end
 *     class B
 *       def method2()  end
 *     end
 *     class C < B
 *       def method3()  end
 *     end
 *
 *     A.instance_methods                #=> [:method1]
 *     B.instance_methods(false)         #=> [:method2]
 *     C.instance_methods(false)         #=> [:method3]
 *     C.instance_methods(true).length   #=> 43
 */

static mrb_value
mrb_mod_instance_methods(mrb_state *mrb, mrb_value mod)
{
  struct RClass *c = mrb_class_ptr(mod);
  mrb_bool recur = TRUE;
  mrb_get_args(mrb, "|b", &recur);
  return mrb_class_instance_method_list(mrb, recur, c, 0);
}

static void
remove_method(mrb_state *mrb, mrb_value mod, mrb_sym mid)
{
  struct RClass *c = mrb_class_ptr(mod);
  khash_t(mt) *h;
  khiter_t k;

  MRB_CLASS_ORIGIN(c);
  h = c->mt;

  if (h) {
    k = kh_get(mt, mrb, h, mid);
    if (k != kh_end(h)) {
      kh_del(mt, mrb, h, k);
      mrb_funcall(mrb, mod, "method_removed", 1, mrb_symbol_value(mid));
      return;
    }
  }

  mrb_name_error(mrb, mid, "method '%S' not defined in %S",
                 mrb_sym2str(mrb, mid), mod);
}

/* 15.2.2.4.41 */
/*
 *  call-seq:
 *     remove_method(symbol)   -> self
 *
 *  Removes the method identified by _symbol_ from the current
 *  class. For an example, see <code>Module.undef_method</code>.
 */

static mrb_value
mrb_mod_remove_method(mrb_state *mrb, mrb_value mod)
{
  mrb_int argc;
  mrb_value *argv;

  mrb_get_args(mrb, "*", &argv, &argc);
  while (argc--) {
    remove_method(mrb, mod, mrb_obj_to_sym(mrb, *argv));
    argv++;
  }
  return mod;
}

static mrb_value
mrb_mod_s_constants(mrb_state *mrb, mrb_value mod)
{
  mrb_raise(mrb, E_NOTIMP_ERROR, "Module.constants not implemented");
  return mrb_nil_value();       /* not reached */
}

/* implementation of Module.nesting */
mrb_value mrb_mod_s_nesting(mrb_state*, mrb_value);

void
mrb_mruby_metaprog_gem_init(mrb_state* mrb)
{
  struct RClass *krn = mrb->kernel_module;
  struct RClass *mod = mrb->module_class;

  mrb_define_method(mrb, krn, "global_variables", mrb_f_global_variables, MRB_ARGS_NONE()); /* 15.3.1.2.4 */
  mrb_define_method(mrb, krn, "local_variables", mrb_local_variables, MRB_ARGS_NONE()); /* 15.3.1.3.28 */

  mrb_define_method(mrb, krn, "singleton_class", mrb_singleton_class, MRB_ARGS_NONE());
  mrb_define_method(mrb, krn, "instance_variable_defined?", mrb_obj_ivar_defined, MRB_ARGS_REQ(1)); /* 15.3.1.3.20 */
  mrb_define_method(mrb, krn, "instance_variable_get", mrb_obj_ivar_get, MRB_ARGS_REQ(1)); /* 15.3.1.3.21 */
  mrb_define_method(mrb, krn, "instance_variable_set", mrb_obj_ivar_set, MRB_ARGS_REQ(2)); /* 15.3.1.3.22 */
  mrb_define_method(mrb, krn, "instance_variables", mrb_obj_instance_variables, MRB_ARGS_NONE()); /* 15.3.1.3.23 */
  mrb_define_method(mrb, krn, "methods", mrb_obj_methods_m, MRB_ARGS_OPT(1)); /* 15.3.1.3.31 */
  mrb_define_method(mrb, krn, "private_methods", mrb_obj_private_methods, MRB_ARGS_OPT(1)); /* 15.3.1.3.36 */
  mrb_define_method(mrb, krn, "protected_methods", mrb_obj_protected_methods, MRB_ARGS_OPT(1)); /* 15.3.1.3.37 */
  mrb_define_method(mrb, krn, "public_methods", mrb_obj_public_methods, MRB_ARGS_OPT(1)); /* 15.3.1.3.38 */
  mrb_define_method(mrb, krn, "singleton_methods", mrb_obj_singleton_methods_m, MRB_ARGS_OPT(1)); /* 15.3.1.3.45 */
  mrb_define_method(mrb, krn, "define_singleton_method", mod_define_singleton_method, MRB_ARGS_ANY());
  mrb_define_method(mrb, krn, "send", mrb_f_send, MRB_ARGS_ANY()); /* 15.3.1.3.44 */

  mrb_define_method(mrb, mod, "class_variables", mrb_mod_class_variables, MRB_ARGS_NONE()); /* 15.2.2.4.19 */
  mrb_define_method(mrb, mod, "remove_class_variable", mrb_mod_remove_cvar, MRB_ARGS_REQ(1)); /* 15.2.2.4.39 */
  mrb_define_method(mrb, mod, "class_variable_defined?", mrb_mod_cvar_defined, MRB_ARGS_REQ(1)); /* 15.2.2.4.16 */
  mrb_define_method(mrb, mod, "class_variable_get", mrb_mod_cvar_get, MRB_ARGS_REQ(1)); /* 15.2.2.4.17 */
  mrb_define_method(mrb, mod, "class_variable_set", mrb_mod_cvar_set, MRB_ARGS_REQ(2)); /* 15.2.2.4.18 */
  mrb_define_method(mrb, mod, "included_modules", mrb_mod_included_modules, MRB_ARGS_NONE()); /* 15.2.2.4.30 */
  mrb_define_method(mrb, mod, "instance_methods", mrb_mod_instance_methods, MRB_ARGS_ANY()); /* 15.2.2.4.33 */
  mrb_define_method(mrb, mod, "remove_method", mrb_mod_remove_method, MRB_ARGS_ANY()); /* 15.2.2.4.41 */
  mrb_define_method(mrb, mod, "method_removed", mrb_f_nil, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, mod, "constants", mrb_mod_constants, MRB_ARGS_OPT(1)); /* 15.2.2.4.24 */
  mrb_define_class_method(mrb, mod, "constants", mrb_mod_s_constants, MRB_ARGS_ANY()); /* 15.2.2.3.1 */
  mrb_define_class_method(mrb, mod, "nesting", mrb_mod_s_nesting, MRB_ARGS_REQ(0)); /* 15.2.2.3.2 */
}

void
mrb_mruby_metaprog_gem_final(mrb_state* mrb)
{
}
