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

MRB_API mrb_bool
mrb_obj_eq(mrb_state *mrb, mrb_value v1, mrb_value v2)
{
  if (mrb_type(v1) != mrb_type(v2)) return FALSE;
  switch (mrb_type(v1)) {
  case MRB_TT_TRUE:
    return TRUE;

  case MRB_TT_FALSE:
  case MRB_TT_FIXNUM:
    return (mrb_fixnum(v1) == mrb_fixnum(v2));
  case MRB_TT_SYMBOL:
    return (mrb_symbol(v1) == mrb_symbol(v2));

#ifndef MRB_WITHOUT_FLOAT
  case MRB_TT_FLOAT:
    return (mrb_float(v1) == mrb_float(v2));
#endif

  default:
    return (mrb_ptr(v1) == mrb_ptr(v2));
  }
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
  result = mrb_funcall(mrb, obj1, "==", 1, obj2);
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
  return mrb_str_new(mrb, 0, 0);
}

static mrb_value
nil_inspect(mrb_state *mrb, mrb_value obj)
{
  return mrb_str_new_lit(mrb, "nil");
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
  return mrb_str_new_lit(mrb, "true");
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
  return mrb_str_new_lit(mrb, "false");
}

void
mrb_init_object(mrb_state *mrb)
{
  struct RClass *n;
  struct RClass *t;
  struct RClass *f;

  mrb->nil_class   = n = mrb_define_class(mrb, "NilClass",   mrb->object_class);
  MRB_SET_INSTANCE_TT(n, MRB_TT_TRUE);
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
  MRB_SET_INSTANCE_TT(f, MRB_TT_TRUE);
  mrb_undef_class_method(mrb, f, "new");
  mrb_define_method(mrb, f, "&",    false_and,      MRB_ARGS_REQ(1));  /* 15.2.6.3.1  */
  mrb_define_method(mrb, f, "^",    false_xor,      MRB_ARGS_REQ(1));  /* 15.2.6.3.2  */
  mrb_define_method(mrb, f, "to_s", false_to_s,     MRB_ARGS_NONE());  /* 15.2.6.3.3  */
  mrb_define_method(mrb, f, "|",    false_or,       MRB_ARGS_REQ(1));  /* 15.2.6.3.4  */
  mrb_define_method(mrb, f, "inspect", false_to_s,  MRB_ARGS_NONE());
}

static mrb_value
inspect_type(mrb_state *mrb, mrb_value val)
{
  if (mrb_type(val) == MRB_TT_FALSE || mrb_type(val) == MRB_TT_TRUE) {
    return mrb_inspect(mrb, val);
  }
  else {
    return mrb_str_new_cstr(mrb, mrb_obj_classname(mrb, val));
  }
}

static mrb_value
convert_type(mrb_state *mrb, mrb_value val, const char *tname, const char *method, mrb_bool raise)
{
  mrb_sym m = 0;

  m = mrb_intern_cstr(mrb, method);
  if (!mrb_respond_to(mrb, val, m)) {
    if (raise) {
      mrb_raisef(mrb, E_TYPE_ERROR, "can't convert %S into %S", inspect_type(mrb, val), mrb_str_new_cstr(mrb, tname));
    }
    return mrb_nil_value();
  }
  return mrb_funcall_argv(mrb, val, m, 0, 0);
}

MRB_API mrb_value
mrb_convert_type(mrb_state *mrb, mrb_value val, enum mrb_vtype type, const char *tname, const char *method)
{
  mrb_value v;

  if (mrb_type(val) == type) return val;
  v = convert_type(mrb, val, tname, method, TRUE);
  if (mrb_type(v) != type) {
    mrb_raisef(mrb, E_TYPE_ERROR, "%S cannot be converted to %S by #%S", val,
               mrb_str_new_cstr(mrb, tname), mrb_str_new_cstr(mrb, method));
  }
  return v;
}

MRB_API mrb_value
mrb_check_convert_type(mrb_state *mrb, mrb_value val, enum mrb_vtype type, const char *tname, const char *method)
{
  mrb_value v;

  if (mrb_type(val) == type && type != MRB_TT_DATA && type != MRB_TT_ISTRUCT) return val;
  v = convert_type(mrb, val, tname, method, FALSE);
  if (mrb_nil_p(v) || mrb_type(v) != type) return mrb_nil_value();
  return v;
}

static const struct types {
  unsigned char type;
  const char *name;
} builtin_types[] = {
/*    {MRB_TT_NIL,  "nil"}, */
  {MRB_TT_FALSE,  "false"},
  {MRB_TT_TRUE,   "true"},
  {MRB_TT_FIXNUM, "Fixnum"},
  {MRB_TT_SYMBOL, "Symbol"},  /* :symbol */
  {MRB_TT_MODULE, "Module"},
  {MRB_TT_OBJECT, "Object"},
  {MRB_TT_CLASS,  "Class"},
  {MRB_TT_ICLASS, "iClass"},  /* internal use: mixed-in module holder */
  {MRB_TT_SCLASS, "SClass"},
  {MRB_TT_PROC,   "Proc"},
#ifndef MRB_WITHOUT_FLOAT
  {MRB_TT_FLOAT,  "Float"},
#endif
  {MRB_TT_ARRAY,  "Array"},
  {MRB_TT_HASH,   "Hash"},
  {MRB_TT_STRING, "String"},
  {MRB_TT_RANGE,  "Range"},
/*    {MRB_TT_BIGNUM,  "Bignum"}, */
  {MRB_TT_FILE,   "File"},
  {MRB_TT_DATA,   "Data"},  /* internal use: wrapped C pointers */
/*    {MRB_TT_VARMAP,  "Varmap"}, */ /* internal use: dynamic variables */
/*    {MRB_TT_NODE,  "Node"}, */ /* internal use: syntax tree node */
/*    {MRB_TT_UNDEF,  "undef"}, */ /* internal use: #undef; should not happen */
  {MRB_TT_MAXDEFINE,  0}
};

MRB_API void
mrb_check_type(mrb_state *mrb, mrb_value x, enum mrb_vtype t)
{
  const struct types *type = builtin_types;
  enum mrb_vtype xt;

  xt = mrb_type(x);
  if ((xt != t) || (xt == MRB_TT_DATA) || (xt == MRB_TT_ISTRUCT)) {
    while (type->type < MRB_TT_MAXDEFINE) {
      if (type->type == t) {
        const char *etype;

        if (mrb_nil_p(x)) {
          etype = "nil";
        }
        else if (mrb_fixnum_p(x)) {
          etype = "Fixnum";
        }
        else if (mrb_type(x) == MRB_TT_SYMBOL) {
          etype = "Symbol";
        }
        else if (mrb_immediate_p(x)) {
          etype = RSTRING_PTR(mrb_obj_as_string(mrb, x));
        }
        else {
          etype = mrb_obj_classname(mrb, x);
        }
        mrb_raisef(mrb, E_TYPE_ERROR, "wrong argument type %S (expected %S)",
                   mrb_str_new_cstr(mrb, etype), mrb_str_new_cstr(mrb, type->name));
      }
      type++;
    }
    mrb_raisef(mrb, E_TYPE_ERROR, "unknown type %S (%S given)",
               mrb_fixnum_value(t), mrb_fixnum_value(mrb_type(x)));
  }
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
  mrb_str_cat_lit(mrb, str, ":");
  mrb_str_concat(mrb, str, mrb_ptr_to_str(mrb, mrb_ptr(obj)));
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

MRB_API mrb_value
mrb_to_int(mrb_state *mrb, mrb_value val)
{

  if (!mrb_fixnum_p(val)) {
    mrb_value type;

#ifndef MRB_WITHOUT_FLOAT
    if (mrb_float_p(val)) {
      return mrb_flo_to_fixnum(mrb, val);
    }
#endif
    type = inspect_type(mrb, val);
    mrb_raisef(mrb, E_TYPE_ERROR, "can't convert %S to Integer", type);
  }
  return val;
}

MRB_API mrb_value
mrb_convert_to_integer(mrb_state *mrb, mrb_value val, mrb_int base)
{
  mrb_value tmp;

  if (mrb_nil_p(val)) {
    if (base != 0) goto arg_error;
    mrb_raise(mrb, E_TYPE_ERROR, "can't convert nil into Integer");
  }
  switch (mrb_type(val)) {
#ifndef MRB_WITHOUT_FLOAT
    case MRB_TT_FLOAT:
      if (base != 0) goto arg_error;
      return mrb_flo_to_fixnum(mrb, val);
#endif

    case MRB_TT_FIXNUM:
      if (base != 0) goto arg_error;
      return val;

    case MRB_TT_STRING:
    string_conv:
      return mrb_str_to_inum(mrb, val, base, TRUE);

    default:
      break;
  }
  if (base != 0) {
    tmp = mrb_check_string_type(mrb, val);
    if (!mrb_nil_p(tmp)) {
      val = tmp;
      goto string_conv;
    }
arg_error:
    mrb_raise(mrb, E_ARGUMENT_ERROR, "base specified for non string value");
  }
  /* to raise TypeError */
  return mrb_to_int(mrb, val);
}

MRB_API mrb_value
mrb_Integer(mrb_state *mrb, mrb_value val)
{
  return mrb_convert_to_integer(mrb, val, 0);
}

#ifndef MRB_WITHOUT_FLOAT
MRB_API mrb_value
mrb_Float(mrb_state *mrb, mrb_value val)
{
  if (mrb_nil_p(val)) {
    mrb_raise(mrb, E_TYPE_ERROR, "can't convert nil into Float");
  }
  switch (mrb_type(val)) {
    case MRB_TT_FIXNUM:
      return mrb_float_value(mrb, (mrb_float)mrb_fixnum(val));

    case MRB_TT_FLOAT:
      return val;

    case MRB_TT_STRING:
      return mrb_float_value(mrb, mrb_str_to_dbl(mrb, val, TRUE));

    default:
      return mrb_convert_type(mrb, val, MRB_TT_FLOAT, "Float", "to_f");
  }
}
#endif

MRB_API mrb_value
mrb_to_str(mrb_state *mrb, mrb_value val)
{
  if (!mrb_string_p(val)) {
    mrb_value type = inspect_type(mrb, val);
    mrb_raisef(mrb, E_TYPE_ERROR, "can't convert %S to String", type);
  }
  return val;
}

/* obsolete: use mrb_ensure_string_type() instead */
MRB_API mrb_value
mrb_string_type(mrb_state *mrb, mrb_value str)
{
  return mrb_ensure_string_type(mrb, str);
}

MRB_API mrb_value
mrb_ensure_string_type(mrb_state *mrb, mrb_value str)
{
  if (!mrb_string_p(str)) {
    mrb_raisef(mrb, E_TYPE_ERROR, "%S cannot be converted to String",
               inspect_type(mrb, str));
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
    mrb_raisef(mrb, E_TYPE_ERROR, "%S cannot be converted to Array",
               inspect_type(mrb, ary));
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
    mrb_raisef(mrb, E_TYPE_ERROR, "%S cannot be converted to Hash",
               inspect_type(mrb, hash));
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
  return mrb_obj_as_string(mrb, mrb_funcall(mrb, obj, "inspect", 0));
}

MRB_API mrb_bool
mrb_eql(mrb_state *mrb, mrb_value obj1, mrb_value obj2)
{
  if (mrb_obj_eq(mrb, obj1, obj2)) return TRUE;
  return mrb_test(mrb_funcall(mrb, obj1, "eql?", 1, obj2));
}
