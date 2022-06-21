#include <mruby.h>
#include <mruby/error.h>
#include <mruby/array.h>
#include <mruby/hash.h>
#include <mruby/range.h>
#include <mruby/string.h>
#include <mruby/numeric.h>
#include <mruby/proc.h>
#include <mruby/presym.h>

static mrb_value
mrb_f_caller(mrb_state *mrb, mrb_value self)
{
  mrb_value bt, v;
  mrb_int bt_len, argc, lev, n;

  argc = mrb_get_args(mrb, "|oi", &v, &n);

  bt = mrb_get_backtrace(mrb);
  bt_len = RARRAY_LEN(bt);

  switch (argc) {
  case 0:
    lev = 1;
    n = bt_len - 1;
    break;
  case 1:
    if (mrb_range_p(v)) {
      mrb_int beg, len;
      if (mrb_range_beg_len(mrb, v, &beg, &len, bt_len, TRUE) == MRB_RANGE_OK) {
        lev = beg;
        n = len;
      }
      else {
        return mrb_nil_value();
      }
    }
    else {
      lev = mrb_as_int(mrb, v);
      if (lev < 0) {
        mrb_raisef(mrb, E_ARGUMENT_ERROR, "negative level (%v)", v);
      }
      n = bt_len - lev;
    }
    break;
  case 2:
    lev = mrb_as_int(mrb, v);
    break;
  default:
    /* not reached */
    lev = n = 0;
    break;
  }
  if (lev >= bt_len) return mrb_nil_value();
  if (lev < 0) {
    mrb_raisef(mrb, E_ARGUMENT_ERROR, "negative level (%v)", v);
  }
  if (n < 0) {
    mrb_raisef(mrb, E_ARGUMENT_ERROR, "negative size (%d)", n);
  }
  if (n == 0 || bt_len <= lev) {
    return mrb_ary_new(mrb);
  }
  if (bt_len <= n + lev) n = bt_len - lev - 1;
  return mrb_ary_new_from_values(mrb, n, RARRAY_PTR(bt)+lev+1);
}

/*
 *  call-seq:
 *     __method__         -> symbol
 *
 *  Returns the called name of the current method as a Symbol.
 *  If called outside of a method, it returns <code>nil</code>.
 *
 */
static mrb_value
mrb_f_method(mrb_state *mrb, mrb_value self)
{
  mrb_callinfo *ci = mrb->c->ci;
  ci--;
  if (ci->proc->e.env->tt == MRB_TT_ENV && ci->proc->e.env->mid)
    return mrb_symbol_value(ci->proc->e.env->mid);
  else if (ci->mid)
    return mrb_symbol_value(ci->mid);
  else
    return mrb_nil_value();
}

/*
 *  call-seq:
 *     __callee__         -> symbol
 *
 *  Returns the called name of the current method as a Symbol.
 *  If called outside of a method, it returns <code>nil</code>.
 *
 */
static mrb_value
mrb_f_callee(mrb_state *mrb, mrb_value self)
{
  mrb_callinfo *ci = mrb->c->ci;
  ci--;
  if (ci->mid)
    return mrb_symbol_value(ci->mid);
  else
    return mrb_nil_value();
}

/*
 *  call-seq:
 *     Integer(arg,base=0)    -> integer
 *
 *  Converts <i>arg</i> to a <code>Integer</code>.
 *  Numeric types are converted directly (with floating-point numbers
 *  being truncated).    <i>base</i> (0, or between 2 and 36) is a base for
 *  integer string representation.  If <i>arg</i> is a <code>String</code>,
 *  when <i>base</i> is omitted or equals to zero, radix indicators
 *  (<code>0</code>, <code>0b</code>, and <code>0x</code>) are honored.
 *  In any case, strings should be strictly conformed to numeric
 *  representation. This behavior is different from that of
 *  <code>String#to_i</code>.  Non string values will be treated as integers.
 *  Passing <code>nil</code> raises a TypeError.
 *
 *     Integer(123.999)    #=> 123
 *     Integer("0x1a")     #=> 26
 *     Integer(Time.new)   #=> 1204973019
 *     Integer("0930", 10) #=> 930
 *     Integer("111", 2)   #=> 7
 *     Integer(nil)        #=> TypeError
 */
static mrb_value
mrb_f_integer(mrb_state *mrb, mrb_value self)
{
  mrb_value val, tmp;
  mrb_int base = 0;

  mrb_get_args(mrb, "o|i", &val, &base);
  if (mrb_nil_p(val)) {
    if (base != 0) goto arg_error;
    mrb_raise(mrb, E_TYPE_ERROR, "can't convert nil into Integer");
  }
  switch (mrb_type(val)) {
#ifndef MRB_NO_FLOAT
    case MRB_TT_FLOAT:
      if (base != 0) goto arg_error;
      return mrb_float_to_integer(mrb, val);
#endif

    case MRB_TT_INTEGER:
      if (base != 0) goto arg_error;
      return val;

    case MRB_TT_STRING:
    string_conv:
      return mrb_str_to_integer(mrb, val, base, TRUE);

    default:
      break;
  }
  if (base != 0) {
    tmp = mrb_obj_as_string(mrb, val);
    if (mrb_string_p(tmp)) {
      val = tmp;
      goto string_conv;
    }
arg_error:
    mrb_raise(mrb, E_ARGUMENT_ERROR, "base specified for non string value");
  }
  /* to raise TypeError */
  return mrb_to_integer(mrb, val);
}

#ifndef MRB_NO_FLOAT
/*
 *  call-seq:
 *     Float(arg)    -> float
 *
 *  Returns <i>arg</i> converted to a float. Numeric types are converted
 *  directly, the rest are converted using <i>arg</i>.to_f.
 *
 *     Float(1)           #=> 1.0
 *     Float(123.456)     #=> 123.456
 *     Float("123.456")   #=> 123.456
 *     Float(nil)         #=> TypeError
 */
static mrb_value
mrb_f_float(mrb_state *mrb, mrb_value self)
{
  mrb_value arg = mrb_get_arg1(mrb);

  if (mrb_string_p(arg)) {
    return mrb_float_value(mrb, mrb_str_to_dbl(mrb, arg, TRUE));
  }
  return mrb_to_float(mrb, arg);
}
#endif

/*
 *  call-seq:
 *     String(arg)   -> string
 *
 *  Returns <i>arg</i> as an <code>String</code>.
 *  converted using <code>to_s</code> method.
 *
 *     String(self)        #=> "main"
 *     String(self.class)  #=> "Object"
 *     String(123456)      #=> "123456"
 */
static mrb_value
mrb_f_string(mrb_state *mrb, mrb_value self)
{
  mrb_value arg = mrb_get_arg1(mrb);
  mrb_value tmp;

  tmp = mrb_type_convert(mrb, arg, MRB_TT_STRING, MRB_SYM(to_s));
  return tmp;
}

/*
 *  call-seq:
 *     Array(arg)    -> array
 *
 *  Returns +arg+ as an Array using to_a method.
 *
 *     Array(1..5)   #=> [1, 2, 3, 4, 5]
 *
 */
static mrb_value
mrb_f_array(mrb_state *mrb, mrb_value self)
{
  mrb_value arg = mrb_get_arg1(mrb);
  mrb_value tmp;

  tmp = mrb_type_convert_check(mrb, arg, MRB_TT_ARRAY, MRB_SYM(to_a));
  if (mrb_nil_p(tmp)) {
    return mrb_ary_new_from_values(mrb, 1, &arg);
  }

  return tmp;
}

/*
 *  call-seq:
 *     Hash(arg)    -> hash
 *
 *  Returns a <code>Hash</code> if <i>arg</i> is a <code>Hash</code>.
 *  Returns an empty <code>Hash</code> when <i>arg</i> is <tt>nil</tt>
 *  or <tt>[]</tt>.
 *
 *      Hash([])          #=> {}
 *      Hash(nil)         #=> {}
 *      Hash(key: :value) #=> {:key => :value}
 *      Hash([1, 2, 3])   #=> TypeError
 *
 */
static mrb_value
mrb_f_hash(mrb_state *mrb, mrb_value self)
{
  mrb_value arg = mrb_get_arg1(mrb);

  if (mrb_nil_p(arg) || (mrb_array_p(arg) && RARRAY_LEN(arg) == 0)) {
    return mrb_hash_new(mrb);
  }
  mrb_ensure_hash_type(mrb, arg);
  return arg;
}

void
mrb_mruby_kernel_ext_gem_init(mrb_state *mrb)
{
  struct RClass *krn = mrb->kernel_module;

  mrb_define_module_function(mrb, krn, "fail", mrb_f_raise, MRB_ARGS_OPT(2));
  mrb_define_module_function(mrb, krn, "caller", mrb_f_caller, MRB_ARGS_OPT(2));
  mrb_define_method(mrb, krn, "__method__", mrb_f_method, MRB_ARGS_NONE());
  mrb_define_method(mrb, krn, "__callee__", mrb_f_callee, MRB_ARGS_NONE());
  mrb_define_module_function(mrb, krn, "Integer", mrb_f_integer, MRB_ARGS_ARG(1,1));
#ifndef MRB_NO_FLOAT
  mrb_define_module_function(mrb, krn, "Float", mrb_f_float, MRB_ARGS_REQ(1));
#endif
  mrb_define_module_function(mrb, krn, "String", mrb_f_string, MRB_ARGS_REQ(1));
  mrb_define_module_function(mrb, krn, "Array", mrb_f_array, MRB_ARGS_REQ(1));
  mrb_define_module_function(mrb, krn, "Hash", mrb_f_hash, MRB_ARGS_REQ(1));
}

void
mrb_mruby_kernel_ext_gem_final(mrb_state *mrb)
{
}
