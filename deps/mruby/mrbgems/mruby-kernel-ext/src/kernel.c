#include "mruby.h"
#include "mruby/error.h"
#include "mruby/array.h"
#include "mruby/hash.h"

/*
 *  call-seq:
 *     __method__         -> symbol
 *
 *  Returns the name at the definition of the current method as a
 *  Symbol.
 *  If called outside of a method, it returns <code>nil</code>.
 *
 */
static mrb_value
mrb_f_method(mrb_state *mrb, mrb_value self)
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
 *  Converts <i>arg</i> to a <code>Fixnum</code>.
 *  Numeric types are converted directly (with floating point numbers
 *  being truncated).    <i>base</i> (0, or between 2 and 36) is a base for
 *  integer string representation.  If <i>arg</i> is a <code>String</code>,
 *  when <i>base</i> is omitted or equals to zero, radix indicators
 *  (<code>0</code>, <code>0b</code>, and <code>0x</code>) are honored.
 *  In any case, strings should be strictly conformed to numeric
 *  representation. This behavior is different from that of
 *  <code>String#to_i</code>.  Non string values will be converted using
 *  <code>to_int</code>, and <code>to_i</code>. Passing <code>nil</code>
 *  raises a TypeError.
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
  mrb_value arg;
  mrb_int base = 0;

  mrb_get_args(mrb, "o|i", &arg, &base);
  return mrb_convert_to_integer(mrb, arg, base);
}

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
  mrb_value arg;

  mrb_get_args(mrb, "o", &arg);
  return mrb_Float(mrb, arg);
}

/*
 *  call-seq:
 *     String(arg)   -> string
 *
 *  Returns <i>arg</i> as an <code>String</code>.
 *
 *  First tries to call its <code>to_str</code> method, then its to_s method.
 *
 *     String(self)        #=> "main"
 *     String(self.class)  #=> "Object"
 *     String(123456)      #=> "123456"
 */
static mrb_value
mrb_f_string(mrb_state *mrb, mrb_value self)
{
  mrb_value arg, tmp;

  mrb_get_args(mrb, "o", &arg);
  tmp = mrb_check_convert_type(mrb, arg, MRB_TT_STRING, "String", "to_str");
  if (mrb_nil_p(tmp)) {
    tmp = mrb_check_convert_type(mrb, arg, MRB_TT_STRING, "String", "to_s");
  }
  return tmp;
}

/*
 *  call-seq:
 *     Array(arg)    -> array
 *
 *  Returns +arg+ as an Array.
 *
 *  First tries to call Array#to_ary on +arg+, then Array#to_a.
 *
 *     Array(1..5)   #=> [1, 2, 3, 4, 5]
 *
 */
static mrb_value
mrb_f_array(mrb_state *mrb, mrb_value self)
{
  mrb_value arg, tmp;

  mrb_get_args(mrb, "o", &arg);
  tmp = mrb_check_convert_type(mrb, arg, MRB_TT_ARRAY, "Array", "to_ary");
  if (mrb_nil_p(tmp)) {
    tmp = mrb_check_convert_type(mrb, arg, MRB_TT_ARRAY, "Array", "to_a");
  }
  if (mrb_nil_p(tmp)) {
    return mrb_ary_new_from_values(mrb, 1, &arg);
  }

  return tmp;
}

/*
 *  call-seq:
 *     Hash(arg)    -> hash
 *
 *  Converts <i>arg</i> to a <code>Hash</code> by calling
 *  <i>arg</i><code>.to_hash</code>. Returns an empty <code>Hash</code> when
 *  <i>arg</i> is <tt>nil</tt> or <tt>[]</tt>.
 *
 *     Hash([])          #=> {}
 *     Hash(nil)         #=> {}
 *     Hash(key: :value) #=> {:key => :value}
 *     Hash([1, 2, 3])   #=> TypeError
 */
static mrb_value
mrb_f_hash(mrb_state *mrb, mrb_value self)
{
  mrb_value arg, tmp;

  mrb_get_args(mrb, "o", &arg);
  if (mrb_nil_p(arg)) {
    return mrb_hash_new(mrb);
  }
  tmp = mrb_check_convert_type(mrb, arg, MRB_TT_HASH, "Hash", "to_hash");
  if (mrb_nil_p(tmp)) {
    if (mrb_array_p(arg) && RARRAY_LEN(arg) == 0) {
      return mrb_hash_new(mrb);
    }
    mrb_raisef(mrb, E_TYPE_ERROR, "can't convert %S into Hash",
      mrb_str_new_cstr(mrb, mrb_obj_classname(mrb, arg)));
  }
  return tmp;
}

void
mrb_mruby_kernel_ext_gem_init(mrb_state *mrb)
{
  struct RClass *krn = mrb->kernel_module;

  mrb_define_module_function(mrb, krn, "fail", mrb_f_raise, MRB_ARGS_OPT(2));
  mrb_define_method(mrb, krn, "__method__", mrb_f_method, MRB_ARGS_NONE());
  mrb_define_module_function(mrb, krn, "Integer", mrb_f_integer, MRB_ARGS_ANY());
  mrb_define_module_function(mrb, krn, "Float", mrb_f_float, MRB_ARGS_REQ(1));
  mrb_define_module_function(mrb, krn, "String", mrb_f_string, MRB_ARGS_REQ(1));
  mrb_define_module_function(mrb, krn, "Array", mrb_f_array, MRB_ARGS_REQ(1));
  mrb_define_module_function(mrb, krn, "Hash", mrb_f_hash, MRB_ARGS_REQ(1));
}

void
mrb_mruby_kernel_ext_gem_final(mrb_state *mrb)
{
}
