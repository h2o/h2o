/*
** object.c - Object, NilClass, TrueClass, FalseClass class
**
** See Copyright Notice in mruby.h
*/

#include <mruby.h>
#include <mruby/class.h>
#include <mruby/numeric.h>
#include <mruby/string.h>
#include <mruby/class.h>
#include <mruby/presym.h>

MRB_API mrb_bool
mrb_obj_eq(mrb_state *mrb, mrb_value v1, mrb_value v2)
{
#if defined(MRB_NAN_BOXING)
  return v1.u == v2.u;
#elif defined(MRB_WORD_BOXING)
  return v1.w == v2.w;
#else  /* MRB_NO_BOXING */
  if (mrb_type(v1) != mrb_type(v2)) return FALSE;
  switch (mrb_type(v1)) {
  case MRB_TT_TRUE:
    return TRUE;

  case MRB_TT_FALSE:
    return (mrb_fixnum(v1) == mrb_fixnum(v2));
  case MRB_TT_INTEGER:
    return (mrb_integer(v1) == mrb_integer(v2));
  case MRB_TT_SYMBOL:
    return (mrb_symbol(v1) == mrb_symbol(v2));

#ifndef MRB_NO_FLOAT
  case MRB_TT_FLOAT:
    return (mrb_float(v1) == mrb_float(v2));
#endif

  default:
    return (mrb_ptr(v1) == mrb_ptr(v2));
  }
#endif
}

MRB_API mrb_bool
mrb_obj_equal(mrb_state *mrb, mrb_value v1, mrb_value v2)
{
  /* temporary definition */
  return mrb_obj_eq(mrb, v1, v2);
}

MRB_API mrb_bool
mrb_equal(mrb_state *mrb, mrb_value obj1, mrb_value obj2)
{
  mrb_value result;

  if (mrb_obj_eq(mrb, obj1, obj2)) return TRUE;
#ifndef MRB_NO_FLOAT
  /* value mixing with integer and float */
  if (mrb_integer_p(obj1)) {
    if (mrb_float_p(obj2) && (mrb_float)mrb_integer(obj1) == mrb_float(obj2))
      return TRUE;
  }
  else if (mrb_float_p(obj1)) {
    if (mrb_integer_p(obj2) && mrb_float(obj1) == (mrb_float)mrb_integer(obj2))
      return TRUE;
  }
#endif
  result = mrb_funcall_id(mrb, obj1, MRB_OPSYM(eq), 1, obj2);
  if (mrb_test(result)) return TRUE;
  return FALSE;
}

/*
 * Document-class: NilClass
 *
 *  The class of the singleton object <code>nil</code>.
 */

/* 15.2.4.3.4  */
/*
 * call_seq:
 *   nil.nil?               -> true
 *
 * Only the object <i>nil</i> responds <code>true</code> to <code>nil?</code>.
 */

static mrb_value
mrb_true(mrb_state *mrb, mrb_value obj)
{
  return mrb_true_value();
}

/* 15.2.4.3.5  */
/*
 *  call-seq:
 *     nil.to_s    -> ""
 *
 *  Always returns the empty string.
 */

static mrb_value
nil_to_s(mrb_state *mrb, mrb_value obj)
{
  mrb_value str = mrb_str_new_frozen(mrb, NULL, 0);
  RSTR_SET_ASCII_FLAG(mrb_str_ptr(str));
  return str;
}

static mrb_value
nil_inspect(mrb_state *mrb, mrb_value obj)
{
  mrb_value str = mrb_str_new_lit_frozen(mrb, "nil");
  RSTR_SET_ASCII_FLAG(mrb_str_ptr(str));
  return str;
}

/***********************************************************************
 *  Document-class: TrueClass
 *
 *  The global value <code>true</code> is the only instance of class
 *  <code>TrueClass</code> and represents a logically true value in
 *  boolean expressions. The class provides operators allowing
 *  <code>true</code> to be used in logical expressions.
 */

/* 15.2.5.3.1  */
/*
 *  call-seq:
 *     true & obj    -> true or false
 *
 *  And---Returns <code>false</code> if <i>obj</i> is
 *  <code>nil</code> or <code>false</code>, <code>true</code> otherwise.
 */

static mrb_value
true_and(mrb_state *mrb, mrb_value obj)
{
  mrb_bool obj2;

  mrb_get_args(mrb, "b", &obj2);

  return mrb_bool_value(obj2);
}

/* 15.2.5.3.2  */
/*
 *  call-seq:
 *     true ^ obj   -> !obj
 *
 *  Exclusive Or---Returns <code>true</code> if <i>obj</i> is
 *  <code>nil</code> or <code>false</code>, <code>false</code>
 *  otherwise.
 */

static mrb_value
true_xor(mrb_state *mrb, mrb_value obj)
{
  mrb_bool obj2;

  mrb_get_args(mrb, "b", &obj2);
  return mrb_bool_value(!obj2);
}

/* 15.2.5.3.3  */
/*
 * call-seq:
 *   true.to_s   ->  "true"
 *
 * The string representation of <code>true</code> is "true".
 */

static mrb_value
true_to_s(mrb_state *mrb, mrb_value obj)
{
  mrb_value str = mrb_str_new_lit_frozen(mrb, "true");
  RSTR_SET_ASCII_FLAG(mrb_str_ptr(str));
  return str;
}

/* 15.2.5.3.4  */
/*
 *  call-seq:
 *     true | obj   -> true
 *
 *  Or---Returns <code>true</code>. As <i>anObject</i> is an argument to
 *  a method call, it is always evaluated; there is no short-circuit
 *  evaluation in this case.
 *
 *     true |  puts("or")
 *     true || puts("logical or")
 *
 *  <em>produces:</em>
 *
 *     or
 */

static mrb_value
true_or(mrb_state *mrb, mrb_value obj)
{
  return mrb_true_value();
}

/*
 *  Document-class: FalseClass
 *
 *  The global value <code>false</code> is the only instance of class
 *  <code>FalseClass</code> and represents a logically false value in
 *  boolean expressions. The class provides operators allowing
 *  <code>false</code> to participate correctly in logical expressions.
 *
 */

/* 15.2.4.3.1  */
/* 15.2.6.3.1  */
/*
 *  call-seq:
 *     false & obj   -> false
 *     nil & obj     -> false
 *
 *  And---Returns <code>false</code>. <i>obj</i> is always
 *  evaluated as it is the argument to a method call---there is no
 *  short-circuit evaluation in this case.
 */

static mrb_value
false_and(mrb_state *mrb, mrb_value obj)
{
  return mrb_false_value();
}

/* 15.2.4.3.2  */
/* 15.2.6.3.2  */
/*
 *  call-seq:
 *     false ^ obj    -> true or false
 *     nil   ^ obj    -> true or false
 *
 *  Exclusive Or---If <i>obj</i> is <code>nil</code> or
 *  <code>false</code>, returns <code>false</code>; otherwise, returns
 *  <code>true</code>.
 *
 */

static mrb_value
false_xor(mrb_state *mrb, mrb_value obj)
{
  mrb_bool obj2;

  mrb_get_args(mrb, "b", &obj2);
  return mrb_bool_value(obj2);
}

/* 15.2.4.3.3  */
/* 15.2.6.3.4  */
/*
 *  call-seq:
 *     false | obj   ->   true or false
 *     nil   | obj   ->   true or false
 *
 *  Or---Returns <code>false</code> if <i>obj</i> is
 *  <code>nil</code> or <code>false</code>; <code>true</code> otherwise.
 */

static mrb_value
false_or(mrb_state *mrb, mrb_value obj)
{
  mrb_bool obj2;

  mrb_get_args(mrb, "b", &obj2);
  return mrb_bool_value(obj2);
}

/* 15.2.6.3.3  */
/*
 * call-seq:
 *   false.to_s   ->  "false"
 *
 * 'nuf said...
 */

static mrb_value
false_to_s(mrb_state *mrb, mrb_value obj)
{
  mrb_value str = mrb_str_new_lit_frozen(mrb, "false");
  RSTR_SET_ASCII_FLAG(mrb_str_ptr(str));
  return str;
}

void
mrb_init_object(mrb_state *mrb)
{
  struct RClass *n;
  struct RClass *t;
  struct RClass *f;

  mrb->nil_class   = n = mrb_define_class(mrb, "NilClass",   mrb->object_class);
  MRB_SET_INSTANCE_TT(n, MRB_TT_FALSE);
  mrb_undef_class_method(mrb, n, "new");
  mrb_define_method(mrb, n, "&",    false_and,      MRB_ARGS_REQ(1));  /* 15.2.4.3.1  */
  mrb_define_method(mrb, n, "^",    false_xor,      MRB_ARGS_REQ(1));  /* 15.2.4.3.2  */
  mrb_define_method(mrb, n, "|",    false_or,       MRB_ARGS_REQ(1));  /* 15.2.4.3.3  */
  mrb_define_method(mrb, n, "nil?", mrb_true,       MRB_ARGS_NONE());  /* 15.2.4.3.4  */
  mrb_define_method(mrb, n, "to_s", nil_to_s,       MRB_ARGS_NONE());  /* 15.2.4.3.5  */
  mrb_define_method(mrb, n, "inspect", nil_inspect, MRB_ARGS_NONE());

  mrb->true_class  = t = mrb_define_class(mrb, "TrueClass",  mrb->object_class);
  MRB_SET_INSTANCE_TT(t, MRB_TT_TRUE);
  mrb_undef_class_method(mrb, t, "new");
  mrb_define_method(mrb, t, "&",    true_and,       MRB_ARGS_REQ(1));  /* 15.2.5.3.1  */
  mrb_define_method(mrb, t, "^",    true_xor,       MRB_ARGS_REQ(1));  /* 15.2.5.3.2  */
  mrb_define_method(mrb, t, "to_s", true_to_s,      MRB_ARGS_NONE());  /* 15.2.5.3.3  */
  mrb_define_method(mrb, t, "|",    true_or,        MRB_ARGS_REQ(1));  /* 15.2.5.3.4  */
  mrb_define_method(mrb, t, "inspect", true_to_s,   MRB_ARGS_NONE());

  mrb->false_class = f = mrb_define_class(mrb, "FalseClass", mrb->object_class);
  MRB_SET_INSTANCE_TT(f, MRB_TT_FALSE);
  mrb_undef_class_method(mrb, f, "new");
  mrb_define_method(mrb, f, "&",    false_and,      MRB_ARGS_REQ(1));  /* 15.2.6.3.1  */
  mrb_define_method(mrb, f, "^",    false_xor,      MRB_ARGS_REQ(1));  /* 15.2.6.3.2  */
  mrb_define_method(mrb, f, "to_s", false_to_s,     MRB_ARGS_NONE());  /* 15.2.6.3.3  */
  mrb_define_method(mrb, f, "|",    false_or,       MRB_ARGS_REQ(1));  /* 15.2.6.3.4  */
  mrb_define_method(mrb, f, "inspect", false_to_s,  MRB_ARGS_NONE());
}

static const char*
type_name(enum mrb_vtype t)
{
  switch (t) {
#define MRB_VTYPE_NAME(tt, type, name) case tt: return name;
    MRB_VTYPE_FOREACH(MRB_VTYPE_NAME)
#undef MRB_VTYPE_NAME
    default: return NULL;
  }
}

static mrb_value
convert_type(mrb_state *mrb, mrb_value val, const char *tname, mrb_sym method, mrb_bool raise)
{
  if (!mrb_respond_to(mrb, val, method)) {
    if (raise) {
      if (tname) mrb_raisef(mrb, E_TYPE_ERROR, "can't convert %Y into %s", val, tname);
      mrb_raisef(mrb, E_TYPE_ERROR, "can't convert %Y", val);
    }
    return mrb_nil_value();
  }
  return mrb_funcall_argv(mrb, val, method, 0, 0);
}

MRB_API mrb_value
mrb_type_convert(mrb_state *mrb, mrb_value val, enum mrb_vtype type, mrb_sym method)
{
  mrb_value v;
  const char *tname;

  if (mrb_type(val) == type) return val;
  tname = type_name(type);
  v = convert_type(mrb, val, tname, method, TRUE);
  if (mrb_type(v) != type) {
    if (type == MRB_TT_STRING) return mrb_any_to_s(mrb, val);
    mrb_raisef(mrb, E_TYPE_ERROR, "%v cannot be converted to %s by #%n", val, tname, method);
  }
  return v;
}

MRB_API mrb_value
mrb_type_convert_check(mrb_state *mrb, mrb_value val, enum mrb_vtype type, mrb_sym method)
{
  mrb_value v;

  if (mrb_type(val) == type && type != MRB_TT_DATA && type != MRB_TT_ISTRUCT) return val;
  v = convert_type(mrb, val, type_name(type), method, FALSE);
  if (mrb_nil_p(v) || mrb_type(v) != type) return mrb_nil_value();
  return v;
}

MRB_API void
mrb_check_type(mrb_state *mrb, mrb_value x, enum mrb_vtype t)
{
  enum mrb_vtype xt = mrb_type(x);
  const char *tname, *ename;

  if (t == xt) return;

  tname = type_name(t);
  if (mrb_nil_p(x)) {
    ename = "nil";
  }
  else if (mrb_integer_p(x)) {
    ename = "Integer";
  }
  else if (mrb_symbol_p(x)) {
    ename = "Symbol";
  }
  else if (mrb_immediate_p(x)) {
    ename = RSTRING_PTR(mrb_obj_as_string(mrb, x));
  }
  else {
    ename = mrb_obj_classname(mrb, x);
  }
  if (tname) {
    mrb_raisef(mrb, E_TYPE_ERROR, "wrong argument type %s (expected %s)",
               ename, tname);
  }
  mrb_raisef(mrb, E_TYPE_ERROR, "unknown type %d (%s given)", t, ename);
}

/* 15.3.1.3.46 */
/*
 *  call-seq:
 *     obj.to_s    => string
 *
 *  Returns a string representing <i>obj</i>. The default
 *  <code>to_s</code> prints the object's class and an encoding of the
 *  object id. As a special case, the top-level object that is the
 *  initial execution context of Ruby programs returns "main."
 */

MRB_API mrb_value
mrb_any_to_s(mrb_state *mrb, mrb_value obj)
{
  mrb_value str = mrb_str_new_capa(mrb, 20);
  const char *cname = mrb_obj_classname(mrb, obj);

  mrb_str_cat_lit(mrb, str, "#<");
  mrb_str_cat_cstr(mrb, str, cname);
  if (!mrb_immediate_p(obj)) {
    mrb_str_cat_lit(mrb, str, ":");
    mrb_str_cat_str(mrb, str, mrb_ptr_to_str(mrb, mrb_ptr(obj)));
  }
  mrb_str_cat_lit(mrb, str, ">");

  return str;
}

/*
 *  call-seq:
 *     obj.is_a?(class)       => true or false
 *     obj.kind_of?(class)    => true or false
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

MRB_API mrb_bool
mrb_obj_is_kind_of(mrb_state *mrb, mrb_value obj, struct RClass *c)
{
  struct RClass *cl = mrb_class(mrb, obj);

  switch (c->tt) {
    case MRB_TT_MODULE:
    case MRB_TT_CLASS:
    case MRB_TT_ICLASS:
    case MRB_TT_SCLASS:
      break;

    default:
      mrb_raise(mrb, E_TYPE_ERROR, "class or module required");
  }

  MRB_CLASS_ORIGIN(c);
  while (cl) {
    if (cl == c || cl->mt == c->mt)
      return TRUE;
    cl = cl->super;
  }
  return FALSE;
}

#ifdef MRB_USE_RATIONAL
// provided by mruby-rational with MRB_USE_RATIONAL
mrb_value mrb_rational_to_i(mrb_state *mrb, mrb_value rat);
mrb_value mrb_rational_to_f(mrb_state *mrb, mrb_value rat);
#endif
#ifdef MRB_USE_COMPLEX
// provided by mruby-complex with MRB_USE_COMPLEX
mrb_value mrb_complex_to_f(mrb_state *mrb, mrb_value comp);
mrb_value mrb_complex_to_i(mrb_state *mrb, mrb_value comp);
#endif

MRB_API mrb_value
mrb_ensure_int_type(mrb_state *mrb, mrb_value val)
{
  if (!mrb_integer_p(val)) {
#ifndef MRB_NO_FLOAT
    if (mrb_float_p(val)) {
      return mrb_float_to_integer(mrb, val);
    }
    else {
      switch (mrb_type(val)) {
#ifdef MRB_USE_RATIONAL
      case MRB_TT_RATIONAL:
        return mrb_rational_to_i(mrb, val);
#endif
#ifdef MRB_USE_COMPLEX
      case MRB_TT_COMPLEX:
        return mrb_complex_to_i(mrb, val);
#endif
      default:
        break;
      }
    }
#endif
    mrb_raisef(mrb, E_TYPE_ERROR, "%Y cannot be converted to Integer", val);
  }
  return val;
}

#ifndef MRB_NO_FLOAT
MRB_API mrb_value
mrb_ensure_float_type(mrb_state *mrb, mrb_value val)
{
  if (mrb_nil_p(val)) {
    mrb_raise(mrb, E_TYPE_ERROR, "can't convert nil into Float");
  }
  switch (mrb_type(val)) {
    case MRB_TT_INTEGER:
      return mrb_float_value(mrb, (mrb_float)mrb_integer(val));

    case MRB_TT_FLOAT:
      return val;

#ifdef MRB_USE_RATIONAL
    case MRB_TT_RATIONAL:
      return mrb_rational_to_f(mrb, val);
#endif

#ifdef MRB_USE_COMPLEX
    case MRB_TT_COMPLEX:
      return mrb_complex_to_f(mrb, val);
#endif

    default:
      mrb_raisef(mrb, E_TYPE_ERROR, "%Y cannot be converted to Float", val);
      /* not reached */
      return val;
  }
}
#endif

MRB_API mrb_value
mrb_ensure_string_type(mrb_state *mrb, mrb_value str)
{
  if (!mrb_string_p(str)) {
    mrb_raisef(mrb, E_TYPE_ERROR, "%Y cannot be converted to String", str);
  }
  return str;
}

MRB_API mrb_value
mrb_check_string_type(mrb_state *mrb, mrb_value str)
{
  if (!mrb_string_p(str)) return mrb_nil_value();
  return str;
}

MRB_API mrb_value
mrb_ensure_array_type(mrb_state *mrb, mrb_value ary)
{
  if (!mrb_array_p(ary)) {
    mrb_raisef(mrb, E_TYPE_ERROR, "%Y cannot be converted to Array", ary);
  }
  return ary;
}

MRB_API mrb_value
mrb_check_array_type(mrb_state *mrb, mrb_value ary)
{
  if (!mrb_array_p(ary)) return mrb_nil_value();
  return ary;
}

MRB_API mrb_value
mrb_ensure_hash_type(mrb_state *mrb, mrb_value hash)
{
  if (!mrb_hash_p(hash)) {
    mrb_raisef(mrb, E_TYPE_ERROR, "%Y cannot be converted to Hash", hash);
  }
  return hash;
}

MRB_API mrb_value
mrb_check_hash_type(mrb_state *mrb, mrb_value hash)
{
  if (!mrb_hash_p(hash)) return mrb_nil_value();
  return hash;
}

MRB_API mrb_value
mrb_inspect(mrb_state *mrb, mrb_value obj)
{
  return mrb_obj_as_string(mrb, mrb_funcall_id(mrb, obj, MRB_SYM(inspect), 0));
}

MRB_API mrb_bool
mrb_eql(mrb_state *mrb, mrb_value obj1, mrb_value obj2)
{
  if (mrb_obj_eq(mrb, obj1, obj2)) return TRUE;
  return mrb_test(mrb_funcall_id(mrb, obj1, MRB_SYM_Q(eql), 1, obj2));
}
