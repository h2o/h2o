/*
** kernel.c - Kernel module
**
** See Copyright Notice in mruby.h
*/

#include <mruby.h>
#include <mruby/array.h>
#include <mruby/hash.h>
#include <mruby/class.h>
#include <mruby/proc.h>
#include <mruby/string.h>
#include <mruby/variable.h>
#include <mruby/error.h>
#include <mruby/istruct.h>

MRB_API mrb_bool
mrb_func_basic_p(mrb_state *mrb, mrb_value obj, mrb_sym mid, mrb_func_t func)
{
  struct RClass *c = mrb_class(mrb, obj);
  mrb_method_t m = mrb_method_search_vm(mrb, &c, mid);
  struct RProc *p;

  if (MRB_METHOD_UNDEF_P(m)) return FALSE;
  if (MRB_METHOD_FUNC_P(m))
    return MRB_METHOD_FUNC(m) == func;
  p = MRB_METHOD_PROC(m);
  if (MRB_PROC_CFUNC_P(p) && (MRB_PROC_CFUNC(p) == func))
    return TRUE;
  return FALSE;
}

static mrb_bool
mrb_obj_basic_to_s_p(mrb_state *mrb, mrb_value obj)
{
  return mrb_func_basic_p(mrb, obj, mrb_intern_lit(mrb, "to_s"), mrb_any_to_s);
}

/* 15.3.1.3.17 */
/*
 *  call-seq:
 *     obj.inspect   -> string
 *
 *  Returns a string containing a human-readable representation of
 *  <i>obj</i>. If not overridden and no instance variables, uses the
 *  <code>to_s</code> method to generate the string.
 *  <i>obj</i>.  If not overridden, uses the <code>to_s</code> method to
 *  generate the string.
 *
 *     [ 1, 2, 3..4, 'five' ].inspect   #=> "[1, 2, 3..4, \"five\"]"
 *     Time.new.inspect                 #=> "2008-03-08 19:43:39 +0900"
 */
MRB_API mrb_value
mrb_obj_inspect(mrb_state *mrb, mrb_value obj)
{
  if (mrb_object_p(obj) && mrb_obj_basic_to_s_p(mrb, obj)) {
    return mrb_obj_iv_inspect(mrb, mrb_obj_ptr(obj));
  }
  return mrb_any_to_s(mrb, obj);
}

/* 15.3.1.3.2  */
/*
 *  call-seq:
 *     obj === other   -> true or false
 *
 *  Case Equality---For class <code>Object</code>, effectively the same
 *  as calling  <code>#==</code>, but typically overridden by descendants
 *  to provide meaningful semantics in <code>case</code> statements.
 */
static mrb_value
mrb_equal_m(mrb_state *mrb, mrb_value self)
{
  mrb_value arg = mrb_get_arg1(mrb);

  return mrb_bool_value(mrb_equal(mrb, self, arg));
}

/* 15.3.1.3.3  */
/* 15.3.1.3.33 */
/*
 *  Document-method: __id__
 *  Document-method: object_id
 *
 *  call-seq:
 *     obj.__id__       -> fixnum
 *     obj.object_id    -> fixnum
 *
 *  Returns an integer identifier for <i>obj</i>. The same number will
 *  be returned on all calls to <code>id</code> for a given object, and
 *  no two active objects will share an id.
 *  <code>Object#object_id</code> is a different concept from the
 *  <code>:name</code> notation, which returns the symbol id of
 *  <code>name</code>. Replaces the deprecated <code>Object#id</code>.
 */
mrb_value
mrb_obj_id_m(mrb_state *mrb, mrb_value self)
{
  return mrb_fixnum_value(mrb_obj_id(self));
}

/* 15.3.1.2.2  */
/* 15.3.1.2.5  */
/* 15.3.1.3.6  */
/* 15.3.1.3.25 */
/*
 *  call-seq:
 *     block_given?   -> true or false
 *     iterator?      -> true or false
 *
 *  Returns <code>true</code> if <code>yield</code> would execute a
 *  block in the current context. The <code>iterator?</code> form
 *  is mildly deprecated.
 *
 *     def try
 *       if block_given?
 *         yield
 *       else
 *         "no block"
 *       end
 *     end
 *     try                  #=> "no block"
 *     try { "hello" }      #=> "hello"
 *     try do "hello" end   #=> "hello"
 */
static mrb_value
mrb_f_block_given_p_m(mrb_state *mrb, mrb_value self)
{
  mrb_callinfo *ci = &mrb->c->ci[-1];
  mrb_callinfo *cibase = mrb->c->cibase;
  mrb_value *bp;
  struct RProc *p;

  if (ci <= cibase) {
    /* toplevel does not have block */
    return mrb_false_value();
  }
  p = ci->proc;
  /* search method/class/module proc */
  while (p) {
    if (MRB_PROC_SCOPE_P(p)) break;
    p = p->upper;
  }
  if (p == NULL) return mrb_false_value();
  /* search ci corresponding to proc */
  while (cibase < ci) {
    if (ci->proc == p) break;
    ci--;
  }
  if (ci == cibase) {
    return mrb_false_value();
  }
  else if (ci->env) {
    struct REnv *e = ci->env;
    int bidx;

    /* top-level does not have block slot (always false) */
    if (e->stack == mrb->c->stbase)
      return mrb_false_value();
    /* use saved block arg position */
    bidx = MRB_ENV_BIDX(e);
    /* bidx may be useless (e.g. define_method) */
    if (bidx >= MRB_ENV_LEN(e))
      return mrb_false_value();
    bp = &e->stack[bidx];
  }
  else {
    bp = ci[1].stackent+1;
    if (ci->argc >= 0) {
      bp += ci->argc;
    }
    else {
      bp++;
    }
  }
  if (mrb_nil_p(*bp))
    return mrb_false_value();
  return mrb_true_value();
}

/* 15.3.1.3.7  */
/*
 *  call-seq:
 *     obj.class    -> class
 *
 *  Returns the class of <i>obj</i>. This method must always be
 *  called with an explicit receiver, as <code>class</code> is also a
 *  reserved word in Ruby.
 *
 *     1.class      #=> Fixnum
 *     self.class   #=> Object
 */
static mrb_value
mrb_obj_class_m(mrb_state *mrb, mrb_value self)
{
  return mrb_obj_value(mrb_obj_class(mrb, self));
}

static struct RClass*
mrb_singleton_class_clone(mrb_state *mrb, mrb_value obj)
{
  struct RClass *klass = mrb_basic_ptr(obj)->c;

  if (klass->tt != MRB_TT_SCLASS)
    return klass;
  else {
    /* copy singleton(unnamed) class */
    struct RClass *clone = (struct RClass*)mrb_obj_alloc(mrb, klass->tt, mrb->class_class);

    switch (mrb_type(obj)) {
    case MRB_TT_CLASS:
    case MRB_TT_SCLASS:
      break;
    default:
      clone->c = mrb_singleton_class_clone(mrb, mrb_obj_value(klass));
      break;
    }
    clone->super = klass->super;
    if (klass->iv) {
      mrb_iv_copy(mrb, mrb_obj_value(clone), mrb_obj_value(klass));
      mrb_obj_iv_set(mrb, (struct RObject*)clone, mrb_intern_lit(mrb, "__attached__"), obj);
    }
    if (klass->mt) {
      clone->mt = kh_copy(mt, mrb, klass->mt);
    }
    else {
      clone->mt = kh_init(mt, mrb);
    }
    clone->tt = MRB_TT_SCLASS;
    return clone;
  }
}

static void
copy_class(mrb_state *mrb, mrb_value dst, mrb_value src)
{
  struct RClass *dc = mrb_class_ptr(dst);
  struct RClass *sc = mrb_class_ptr(src);
  /* if the origin is not the same as the class, then the origin and
     the current class need to be copied */
  if (sc->flags & MRB_FL_CLASS_IS_PREPENDED) {
    struct RClass *c0 = sc->super;
    struct RClass *c1 = dc;

    /* copy prepended iclasses */
    while (!(c0->flags & MRB_FL_CLASS_IS_ORIGIN)) {
      c1->super = mrb_class_ptr(mrb_obj_dup(mrb, mrb_obj_value(c0)));
      c1 = c1->super;
      c0 = c0->super;
    }
    c1->super = mrb_class_ptr(mrb_obj_dup(mrb, mrb_obj_value(c0)));
    c1->super->flags |= MRB_FL_CLASS_IS_ORIGIN;
  }
  if (sc->mt) {
    dc->mt = kh_copy(mt, mrb, sc->mt);
  }
  else {
    dc->mt = kh_init(mt, mrb);
  }
  dc->super = sc->super;
  MRB_SET_INSTANCE_TT(dc, MRB_INSTANCE_TT(sc));
}

static void
init_copy(mrb_state *mrb, mrb_value dest, mrb_value obj)
{
  switch (mrb_type(obj)) {
    case MRB_TT_ICLASS:
      copy_class(mrb, dest, obj);
      return;
    case MRB_TT_CLASS:
    case MRB_TT_MODULE:
      copy_class(mrb, dest, obj);
      mrb_iv_copy(mrb, dest, obj);
      mrb_iv_remove(mrb, dest, mrb_intern_lit(mrb, "__classname__"));
      break;
    case MRB_TT_OBJECT:
    case MRB_TT_SCLASS:
    case MRB_TT_HASH:
    case MRB_TT_DATA:
    case MRB_TT_EXCEPTION:
      mrb_iv_copy(mrb, dest, obj);
      break;
    case MRB_TT_ISTRUCT:
      mrb_istruct_copy(dest, obj);
      break;

    default:
      break;
  }
  mrb_funcall(mrb, dest, "initialize_copy", 1, obj);
}

/* 15.3.1.3.8  */
/*
 *  call-seq:
 *     obj.clone -> an_object
 *
 *  Produces a shallow copy of <i>obj</i>---the instance variables of
 *  <i>obj</i> are copied, but not the objects they reference. Copies
 *  the frozen state of <i>obj</i>. See also the discussion
 *  under <code>Object#dup</code>.
 *
 *     class Klass
 *        attr_accessor :str
 *     end
 *     s1 = Klass.new      #=> #<Klass:0x401b3a38>
 *     s1.str = "Hello"    #=> "Hello"
 *     s2 = s1.clone       #=> #<Klass:0x401b3998 @str="Hello">
 *     s2.str[1,4] = "i"   #=> "i"
 *     s1.inspect          #=> "#<Klass:0x401b3a38 @str=\"Hi\">"
 *     s2.inspect          #=> "#<Klass:0x401b3998 @str=\"Hi\">"
 *
 *  This method may have class-specific behavior.  If so, that
 *  behavior will be documented under the #+initialize_copy+ method of
 *  the class.
 *
 *  Some Class(True False Nil Symbol Fixnum Float) Object  cannot clone.
 */
MRB_API mrb_value
mrb_obj_clone(mrb_state *mrb, mrb_value self)
{
  struct RObject *p;
  mrb_value clone;

  if (mrb_immediate_p(self)) {
    return self;
  }
  if (mrb_sclass_p(self)) {
    mrb_raise(mrb, E_TYPE_ERROR, "can't clone singleton class");
  }
  p = (struct RObject*)mrb_obj_alloc(mrb, mrb_type(self), mrb_obj_class(mrb, self));
  p->c = mrb_singleton_class_clone(mrb, self);
  mrb_field_write_barrier(mrb, (struct RBasic*)p, (struct RBasic*)p->c);
  clone = mrb_obj_value(p);
  init_copy(mrb, clone, self);
  p->flags |= mrb_obj_ptr(self)->flags & MRB_FL_OBJ_IS_FROZEN;

  return clone;
}

/* 15.3.1.3.9  */
/*
 *  call-seq:
 *     obj.dup -> an_object
 *
 *  Produces a shallow copy of <i>obj</i>---the instance variables of
 *  <i>obj</i> are copied, but not the objects they reference.
 *  <code>dup</code> copies the frozen state of <i>obj</i>. See also
 *  the discussion under <code>Object#clone</code>. In general,
 *  <code>clone</code> and <code>dup</code> may have different semantics
 *  in descendant classes. While <code>clone</code> is used to duplicate
 *  an object, including its internal state, <code>dup</code> typically
 *  uses the class of the descendant object to create the new instance.
 *
 *  This method may have class-specific behavior.  If so, that
 *  behavior will be documented under the #+initialize_copy+ method of
 *  the class.
 */

MRB_API mrb_value
mrb_obj_dup(mrb_state *mrb, mrb_value obj)
{
  struct RBasic *p;
  mrb_value dup;

  if (mrb_immediate_p(obj)) {
    return obj;
  }
  if (mrb_sclass_p(obj)) {
    mrb_raise(mrb, E_TYPE_ERROR, "can't dup singleton class");
  }
  p = mrb_obj_alloc(mrb, mrb_type(obj), mrb_obj_class(mrb, obj));
  dup = mrb_obj_value(p);
  init_copy(mrb, dup, obj);

  return dup;
}

static mrb_value
mrb_obj_extend(mrb_state *mrb, mrb_int argc, mrb_value *argv, mrb_value obj)
{
  mrb_int i;

  if (argc == 0) {
    mrb_argnum_error(mrb, argc, 1, -1);
  }
  for (i = 0; i < argc; i++) {
    mrb_check_type(mrb, argv[i], MRB_TT_MODULE);
  }
  while (argc--) {
    mrb_funcall(mrb, argv[argc], "extend_object", 1, obj);
    mrb_funcall(mrb, argv[argc], "extended", 1, obj);
  }
  return obj;
}

/* 15.3.1.3.13 */
/*
 *  call-seq:
 *     obj.extend(module, ...)    -> obj
 *
 *  Adds to _obj_ the instance methods from each module given as a
 *  parameter.
 *
 *     module Mod
 *       def hello
 *         "Hello from Mod.\n"
 *       end
 *     end
 *
 *     class Klass
 *       def hello
 *         "Hello from Klass.\n"
 *       end
 *     end
 *
 *     k = Klass.new
 *     k.hello         #=> "Hello from Klass.\n"
 *     k.extend(Mod)   #=> #<Klass:0x401b3bc8>
 *     k.hello         #=> "Hello from Mod.\n"
 */
static mrb_value
mrb_obj_extend_m(mrb_state *mrb, mrb_value self)
{
  mrb_value *argv;
  mrb_int argc;

  mrb_get_args(mrb, "*", &argv, &argc);
  return mrb_obj_extend(mrb, argc, argv, self);
}

MRB_API mrb_value
mrb_obj_freeze(mrb_state *mrb, mrb_value self)
{
  if (!mrb_immediate_p(self)) {
    struct RBasic *b = mrb_basic_ptr(self);
    if (!mrb_frozen_p(b)) {
      MRB_SET_FROZEN_FLAG(b);
      if (b->c->tt == MRB_TT_SCLASS) MRB_SET_FROZEN_FLAG(b->c);
    }
  }
  return self;
}

static mrb_value
mrb_obj_frozen(mrb_state *mrb, mrb_value self)
{
  return mrb_bool_value(mrb_immediate_p(self) || mrb_frozen_p(mrb_basic_ptr(self)));
}

/* 15.3.1.3.15 */
/*
 *  call-seq:
 *     obj.hash    -> fixnum
 *
 *  Generates a <code>Fixnum</code> hash value for this object. This
 *  function must have the property that <code>a.eql?(b)</code> implies
 *  <code>a.hash == b.hash</code>. The hash value is used by class
 *  <code>Hash</code>. Any hash value that exceeds the capacity of a
 *  <code>Fixnum</code> will be truncated before being used.
 */
static mrb_value
mrb_obj_hash(mrb_state *mrb, mrb_value self)
{
  return mrb_fixnum_value(mrb_obj_id(self));
}

/* 15.3.1.3.16 */
static mrb_value
mrb_obj_init_copy(mrb_state *mrb, mrb_value self)
{
  mrb_value orig = mrb_get_arg1(mrb);

  if (mrb_obj_equal(mrb, self, orig)) return self;
  if ((mrb_type(self) != mrb_type(orig)) || (mrb_obj_class(mrb, self) != mrb_obj_class(mrb, orig))) {
      mrb_raise(mrb, E_TYPE_ERROR, "initialize_copy should take same class object");
  }
  return self;
}


MRB_API mrb_bool
mrb_obj_is_instance_of(mrb_state *mrb, mrb_value obj, struct RClass* c)
{
  if (mrb_obj_class(mrb, obj) == c) return TRUE;
  return FALSE;
}

/* 15.3.1.3.19 */
/*
 *  call-seq:
 *     obj.instance_of?(class)    -> true or false
 *
 *  Returns <code>true</code> if <i>obj</i> is an instance of the given
 *  class. See also <code>Object#kind_of?</code>.
 */
static mrb_value
obj_is_instance_of(mrb_state *mrb, mrb_value self)
{
  mrb_value arg;

  mrb_get_args(mrb, "C", &arg);

  return mrb_bool_value(mrb_obj_is_instance_of(mrb, self, mrb_class_ptr(arg)));
}

/* 15.3.1.3.24 */
/* 15.3.1.3.26 */
/*
 *  call-seq:
 *     obj.is_a?(class)       -> true or false
 *     obj.kind_of?(class)    -> true or false
 *
 *  Returns <code>true</code> if <i>class</i> is the class of
 *  <i>obj</i>, or if <i>class</i> is one of the superclasses of
 *  <i>obj</i> or modules included in <i>obj</i>.
 *
 *     module M;    end
 *     class A
 *       include M
 *     end
 *     class B < A; end
 *     class C < B; end
 *     b = B.new
 *     b.instance_of? A   #=> false
 *     b.instance_of? B   #=> true
 *     b.instance_of? C   #=> false
 *     b.instance_of? M   #=> false
 *     b.kind_of? A       #=> true
 *     b.kind_of? B       #=> true
 *     b.kind_of? C       #=> false
 *     b.kind_of? M       #=> true
 */
static mrb_value
mrb_obj_is_kind_of_m(mrb_state *mrb, mrb_value self)
{
  mrb_value arg;

  mrb_get_args(mrb, "C", &arg);

  return mrb_bool_value(mrb_obj_is_kind_of(mrb, self, mrb_class_ptr(arg)));
}

KHASH_DECLARE(st, mrb_sym, char, FALSE)
KHASH_DEFINE(st, mrb_sym, char, FALSE, kh_int_hash_func, kh_int_hash_equal)

/* 15.3.1.3.32 */
/*
 * call_seq:
 *   nil.nil?               -> true
 *   <anything_else>.nil?   -> false
 *
 * Only the object <i>nil</i> responds <code>true</code> to <code>nil?</code>.
 */
static mrb_value
mrb_false(mrb_state *mrb, mrb_value self)
{
  return mrb_false_value();
}

/* 15.3.1.2.12  */
/* 15.3.1.3.40 */
/*
 *  call-seq:
 *     raise
 *     raise(string)
 *     raise(exception [, string])
 *
 *  With no arguments, raises a <code>RuntimeError</code>
 *  With a single +String+ argument, raises a
 *  +RuntimeError+ with the string as a message. Otherwise,
 *  the first parameter should be the name of an +Exception+
 *  class (or an object that returns an +Exception+ object when sent
 *  an +exception+ message). The optional second parameter sets the
 *  message associated with the exception, and the third parameter is an
 *  array of callback information. Exceptions are caught by the
 *  +rescue+ clause of <code>begin...end</code> blocks.
 *
 *     raise "Failed to create socket"
 *     raise ArgumentError, "No parameters", caller
 */
MRB_API mrb_value
mrb_f_raise(mrb_state *mrb, mrb_value self)
{
  mrb_value a[2], exc;
  mrb_int argc;


  argc = mrb_get_args(mrb, "|oo", &a[0], &a[1]);
  switch (argc) {
  case 0:
    mrb_raise(mrb, E_RUNTIME_ERROR, "");
    break;
  case 1:
    if (mrb_string_p(a[0])) {
      a[1] = a[0];
      argc = 2;
      a[0] = mrb_obj_value(E_RUNTIME_ERROR);
    }
    /* fall through */
  default:
    exc = mrb_make_exception(mrb, argc, a);
    mrb_exc_raise(mrb, exc);
    break;
  }
  return mrb_nil_value();            /* not reached */
}

/* 15.3.1.3.41 */
/*
 *  call-seq:
 *     obj.remove_instance_variable(symbol)    -> obj
 *
 *  Removes the named instance variable from <i>obj</i>, returning that
 *  variable's value.
 *
 *     class Dummy
 *       attr_reader :var
 *       def initialize
 *         @var = 99
 *       end
 *       def remove
 *         remove_instance_variable(:@var)
 *       end
 *     end
 *     d = Dummy.new
 *     d.var      #=> 99
 *     d.remove   #=> 99
 *     d.var      #=> nil
 */
static mrb_value
mrb_obj_remove_instance_variable(mrb_state *mrb, mrb_value self)
{
  mrb_sym sym;
  mrb_value val;

  mrb_get_args(mrb, "n", &sym);
  mrb_iv_name_sym_check(mrb, sym);
  val = mrb_iv_remove(mrb, self, sym);
  if (mrb_undef_p(val)) {
    mrb_name_error(mrb, sym, "instance variable %n not defined", sym);
  }
  return val;
}

void
mrb_method_missing(mrb_state *mrb, mrb_sym name, mrb_value self, mrb_value args)
{
  mrb_no_method_error(mrb, name, args, "undefined method '%n'", name);
}

/* 15.3.1.3.30 */
/*
 *  call-seq:
 *     obj.method_missing(symbol [, *args] )   -> result
 *
 *  Invoked by Ruby when <i>obj</i> is sent a message it cannot handle.
 *  <i>symbol</i> is the symbol for the method called, and <i>args</i>
 *  are any arguments that were passed to it. By default, the interpreter
 *  raises an error when this method is called. However, it is possible
 *  to override the method to provide more dynamic behavior.
 *  If it is decided that a particular method should not be handled, then
 *  <i>super</i> should be called, so that ancestors can pick up the
 *  missing method.
 *  The example below creates
 *  a class <code>Roman</code>, which responds to methods with names
 *  consisting of roman numerals, returning the corresponding integer
 *  values.
 *
 *     class Roman
 *       def romanToInt(str)
 *         # ...
 *       end
 *       def method_missing(methId)
 *         str = methId.id2name
 *         romanToInt(str)
 *       end
 *     end
 *
 *     r = Roman.new
 *     r.iv      #=> 4
 *     r.xxiii   #=> 23
 *     r.mm      #=> 2000
 */
static mrb_value
mrb_obj_missing(mrb_state *mrb, mrb_value mod)
{
  mrb_sym name;
  mrb_value *a;
  mrb_int alen;

  mrb_get_args(mrb, "n*!", &name, &a, &alen);
  mrb_method_missing(mrb, name, mod, mrb_ary_new_from_values(mrb, alen, a));
  /* not reached */
  return mrb_nil_value();
}

static inline mrb_bool
basic_obj_respond_to(mrb_state *mrb, mrb_value obj, mrb_sym id, int pub)
{
  return mrb_respond_to(mrb, obj, id);
}

/* 15.3.1.3.43 */
/*
 *  call-seq:
 *     obj.respond_to?(symbol, include_private=false) -> true or false
 *
 *  Returns +true+ if _obj_ responds to the given
 *  method. Private methods are included in the search only if the
 *  optional second parameter evaluates to +true+.
 *
 *  If the method is not implemented,
 *  as Process.fork on Windows, File.lchmod on GNU/Linux, etc.,
 *  false is returned.
 *
 *  If the method is not defined, <code>respond_to_missing?</code>
 *  method is called and the result is returned.
 */
static mrb_value
obj_respond_to(mrb_state *mrb, mrb_value self)
{
  mrb_sym id, rtm_id;
  mrb_bool priv = FALSE, respond_to_p;

  mrb_get_args(mrb, "n|b", &id, &priv);
  respond_to_p = basic_obj_respond_to(mrb, self, id, !priv);
  if (!respond_to_p) {
    rtm_id = mrb_intern_lit(mrb, "respond_to_missing?");
    if (basic_obj_respond_to(mrb, self, rtm_id, !priv)) {
      mrb_value args[2], v;
      args[0] = mrb_symbol_value(id);
      args[1] = mrb_bool_value(priv);
      v = mrb_funcall_argv(mrb, self, rtm_id, 2, args);
      return mrb_bool_value(mrb_bool(v));
    }
  }
  return mrb_bool_value(respond_to_p);
}

static mrb_value
mrb_obj_ceqq(mrb_state *mrb, mrb_value self)
{
  mrb_value v = mrb_get_arg1(mrb);
  mrb_int i, len;
  mrb_sym eqq = mrb_intern_lit(mrb, "===");
  mrb_value ary = mrb_ary_splat(mrb, self);

  len = RARRAY_LEN(ary);
  for (i=0; i<len; i++) {
    mrb_value c = mrb_funcall_argv(mrb, mrb_ary_entry(ary, i), eqq, 1, &v);
    if (mrb_test(c)) return mrb_true_value();
  }
  return mrb_false_value();
}

mrb_value mrb_obj_equal_m(mrb_state *mrb, mrb_value);

void
mrb_init_kernel(mrb_state *mrb)
{
  struct RClass *krn;

  mrb->kernel_module = krn = mrb_define_module(mrb, "Kernel");                                                    /* 15.3.1 */
  mrb_define_class_method(mrb, krn, "block_given?",         mrb_f_block_given_p_m,           MRB_ARGS_NONE());    /* 15.3.1.2.2  */
  mrb_define_class_method(mrb, krn, "iterator?",            mrb_f_block_given_p_m,           MRB_ARGS_NONE());    /* 15.3.1.2.5  */
;     /* 15.3.1.2.11 */
  mrb_define_class_method(mrb, krn, "raise",                mrb_f_raise,                     MRB_ARGS_OPT(2));    /* 15.3.1.2.12 */


  mrb_define_method(mrb, krn, "===",                        mrb_equal_m,                     MRB_ARGS_REQ(1));    /* 15.3.1.3.2  */
  mrb_define_method(mrb, krn, "block_given?",               mrb_f_block_given_p_m,           MRB_ARGS_NONE());    /* 15.3.1.3.6  */
  mrb_define_method(mrb, krn, "class",                      mrb_obj_class_m,                 MRB_ARGS_NONE());    /* 15.3.1.3.7  */
  mrb_define_method(mrb, krn, "clone",                      mrb_obj_clone,                   MRB_ARGS_NONE());    /* 15.3.1.3.8  */
  mrb_define_method(mrb, krn, "dup",                        mrb_obj_dup,                     MRB_ARGS_NONE());    /* 15.3.1.3.9  */
  mrb_define_method(mrb, krn, "eql?",                       mrb_obj_equal_m,                 MRB_ARGS_REQ(1));    /* 15.3.1.3.10 */
  mrb_define_method(mrb, krn, "extend",                     mrb_obj_extend_m,                MRB_ARGS_ANY());     /* 15.3.1.3.13 */
  mrb_define_method(mrb, krn, "freeze",                     mrb_obj_freeze,                  MRB_ARGS_NONE());
  mrb_define_method(mrb, krn, "frozen?",                    mrb_obj_frozen,                  MRB_ARGS_NONE());
  mrb_define_method(mrb, krn, "hash",                       mrb_obj_hash,                    MRB_ARGS_NONE());    /* 15.3.1.3.15 */
  mrb_define_method(mrb, krn, "initialize_copy",            mrb_obj_init_copy,               MRB_ARGS_REQ(1));    /* 15.3.1.3.16 */
  mrb_define_method(mrb, krn, "inspect",                    mrb_obj_inspect,                 MRB_ARGS_NONE());    /* 15.3.1.3.17 */
  mrb_define_method(mrb, krn, "instance_of?",               obj_is_instance_of,              MRB_ARGS_REQ(1));    /* 15.3.1.3.19 */

  mrb_define_method(mrb, krn, "is_a?",                      mrb_obj_is_kind_of_m,            MRB_ARGS_REQ(1));    /* 15.3.1.3.24 */
  mrb_define_method(mrb, krn, "iterator?",                  mrb_f_block_given_p_m,           MRB_ARGS_NONE());    /* 15.3.1.3.25 */
  mrb_define_method(mrb, krn, "kind_of?",                   mrb_obj_is_kind_of_m,            MRB_ARGS_REQ(1));    /* 15.3.1.3.26 */
  mrb_define_method(mrb, krn, "method_missing",             mrb_obj_missing,                 MRB_ARGS_ANY());     /* 15.3.1.3.30 */
  mrb_define_method(mrb, krn, "nil?",                       mrb_false,                       MRB_ARGS_NONE());    /* 15.3.1.3.32 */
  mrb_define_method(mrb, krn, "object_id",                  mrb_obj_id_m,                    MRB_ARGS_NONE());    /* 15.3.1.3.33 */
  mrb_define_method(mrb, krn, "raise",                      mrb_f_raise,                     MRB_ARGS_ANY());     /* 15.3.1.3.40 */
  mrb_define_method(mrb, krn, "remove_instance_variable",   mrb_obj_remove_instance_variable,MRB_ARGS_REQ(1));    /* 15.3.1.3.41 */
  mrb_define_method(mrb, krn, "respond_to?",                obj_respond_to,                  MRB_ARGS_ARG(1,1));     /* 15.3.1.3.43 */
  mrb_define_method(mrb, krn, "to_s",                       mrb_any_to_s,                    MRB_ARGS_NONE());    /* 15.3.1.3.46 */
  mrb_define_method(mrb, krn, "__case_eqq",                 mrb_obj_ceqq,                    MRB_ARGS_REQ(1));    /* internal */
  mrb_define_method(mrb, krn, "__to_int",                   mrb_to_int,                      MRB_ARGS_NONE()); /* internal */
  mrb_define_method(mrb, krn, "__to_str",                   mrb_to_str,                      MRB_ARGS_NONE()); /* internal */

  mrb_include_module(mrb, mrb->object_class, mrb->kernel_module);
}
