#include <limits.h>
#include <mruby.h>
#include <mruby/numeric.h>
#include <mruby/presym.h>

/*
 *  call-seq:
 *     int.allbits?(mask)  ->  true or false
 *
 *  Returns +true+ if all bits of <code>+int+ & +mask+</code> are 1.
 */
static mrb_value
mrb_int_allbits(mrb_state *mrb, mrb_value self)
{
  mrb_int n, m;

  mrb_get_args(mrb, "i", &m);
  n = mrb_int(mrb, self);
  return mrb_bool_value((n & m) == m);
}

/*
 *  call-seq:
 *     int.anybits?(mask)  ->  true or false
 *
 *  Returns +true+ if any bits of <code>+int+ & +mask+</code> are 1.
 */
static mrb_value
mrb_int_anybits(mrb_state *mrb, mrb_value self)
{
  mrb_int n, m;

  mrb_get_args(mrb, "i", &m);
  n = mrb_int(mrb, self);
  return mrb_bool_value((n & m) != 0);
}

/*
 *  call-seq:
 *     int.nobits?(mask)  ->  true or false
 *
 *  Returns +true+ if no bits of <code>+int+ & +mask+</code> are 1.
 */
static mrb_value
mrb_int_nobits(mrb_state *mrb, mrb_value self)
{
  mrb_int n, m;

  mrb_get_args(mrb, "i", &m);
  n = mrb_int(mrb, self);
  return mrb_bool_value((n & m) == 0);
}

void
mrb_mruby_numeric_ext_gem_init(mrb_state* mrb)
{
  struct RClass *i = mrb_class_get(mrb, "Integer");

  mrb_define_method(mrb, i, "allbits?", mrb_int_allbits, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, i, "anybits?", mrb_int_anybits, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, i, "nobits?", mrb_int_nobits, MRB_ARGS_REQ(1));

#ifndef MRB_NO_FLOAT
  mrb_define_const_id(mrb, mrb->float_class, MRB_SYM(RADIX),        mrb_fixnum_value(MRB_FLT_RADIX));
  mrb_define_const_id(mrb, mrb->float_class, MRB_SYM(MANT_DIG),     mrb_fixnum_value(MRB_FLT_MANT_DIG));
  mrb_define_const_id(mrb, mrb->float_class, MRB_SYM(EPSILON),      mrb_float_value(mrb, MRB_FLT_EPSILON));
  mrb_define_const_id(mrb, mrb->float_class, MRB_SYM(DIG),          mrb_fixnum_value(MRB_FLT_DIG));
  mrb_define_const_id(mrb, mrb->float_class, MRB_SYM(MIN_EXP),      mrb_fixnum_value(MRB_FLT_MIN_EXP));
  mrb_define_const_id(mrb, mrb->float_class, MRB_SYM(MIN),          mrb_float_value(mrb, MRB_FLT_MIN));
  mrb_define_const_id(mrb, mrb->float_class, MRB_SYM(MIN_10_EXP),   mrb_fixnum_value(MRB_FLT_MIN_10_EXP));
  mrb_define_const_id(mrb, mrb->float_class, MRB_SYM(MAX_EXP),      mrb_fixnum_value(MRB_FLT_MAX_EXP));
  mrb_define_const_id(mrb, mrb->float_class, MRB_SYM(MAX),          mrb_float_value(mrb, MRB_FLT_MAX));
  mrb_define_const_id(mrb, mrb->float_class, MRB_SYM(MAX_10_EXP),   mrb_fixnum_value(MRB_FLT_MAX_10_EXP));
#endif /* MRB_NO_FLOAT */
}

void
mrb_mruby_numeric_ext_gem_final(mrb_state* mrb)
{
}
