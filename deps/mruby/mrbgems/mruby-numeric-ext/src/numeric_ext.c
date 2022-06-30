#include <mruby.h>
#include <mruby/numeric.h>
#include <mruby/internal.h>
#include <mruby/presym.h>

#ifdef MRB_USE_BIGINT
static mrb_value
bint_allbits(mrb_state *mrb, mrb_value x, mrb_value y)
{
  y = mrb_as_bint(mrb, y);
  x = mrb_bint_and(mrb, x, y);
  if (mrb_bint_cmp(mrb, x, y) == 0) return mrb_true_value();
  return mrb_false_value();
}

static mrb_value
bint_anybits(mrb_state *mrb, mrb_value x, mrb_value y)
{
  y = mrb_as_bint(mrb, y);
  x = mrb_bint_and(mrb, x, y);
  if (mrb_bint_cmp(mrb, x, mrb_fixnum_value(0)) != 0)
    return mrb_true_value();
  return mrb_false_value();
}

static mrb_value
bint_nobits(mrb_state *mrb, mrb_value x, mrb_value y)
{
  y = mrb_as_bint(mrb, y);
  x = mrb_bint_and(mrb, x, y);
  if (mrb_bint_cmp(mrb, x, mrb_fixnum_value(0)) == 0)
    return mrb_true_value();
  return mrb_false_value();
}
#endif

/*
 *  call-seq:
 *     int.allbits?(mask)  ->  true or false
 *
 *  Returns +true+ if all bits of <code>+int+ & +mask+</code> are 1.
 */
static mrb_value
int_allbits(mrb_state *mrb, mrb_value self)
{
#ifdef MRB_USE_BIGINT
  return bint_allbits(mrb, self, mrb_get_arg1(mrb));
#endif
  mrb_int n, m;

  mrb_get_args(mrb, "i", &m);
  n = mrb_integer(self);
  return mrb_bool_value((n & m) == m);
}

/*
 *  call-seq:
 *     int.anybits?(mask)  ->  true or false
 *
 *  Returns +true+ if any bits of <code>+int+ & +mask+</code> are 1.
 */
static mrb_value
int_anybits(mrb_state *mrb, mrb_value self)
{
#ifdef MRB_USE_BIGINT
  return bint_anybits(mrb, self, mrb_get_arg1(mrb));
#endif
  mrb_int n, m;

  mrb_get_args(mrb, "i", &m);
  n = mrb_integer(self);
  return mrb_bool_value((n & m) != 0);
}

/*
 *  call-seq:
 *     int.nobits?(mask)  ->  true or false
 *
 *  Returns +true+ if no bits of <code>+int+ & +mask+</code> are 1.
 */
static mrb_value
int_nobits(mrb_state *mrb, mrb_value self)
{
#ifdef MRB_USE_BIGINT
  return bint_nobits(mrb, self, mrb_get_arg1(mrb));
#endif
  mrb_int n, m;

  mrb_get_args(mrb, "i", &m);
  n = mrb_integer(self);
  return mrb_bool_value((n & m) == 0);
}

#ifndef MRB_NO_FLOAT
static mrb_value flo_remainder(mrb_state *mrb, mrb_value self);
#endif

/*
 *  call-seq:
 *     num.remainder(numeric)  ->  real
 *
 *  <code>x.remainder(y)</code> means <code>x-y*(x/y).truncate</code>.
 *
 *  See Numeric#divmod.
 */
static mrb_value
int_remainder(mrb_state *mrb, mrb_value x)
{
  mrb_value y = mrb_get_arg1(mrb);
  mrb_int a, b;

#ifdef MRB_USE_BIGINT
  if (mrb_bigint_p(x)) {
    if (mrb_integer_p(y) || mrb_bigint_p(y)) {
      return mrb_bint_rem(mrb, x, y);
    }
    return flo_remainder(mrb, mrb_float_value(mrb, mrb_as_float(mrb, x)));
  }
#endif
  a = mrb_integer(x);
  if (mrb_integer_p(y)) {
    b = mrb_integer(y);
    if (b == 0) mrb_int_zerodiv(mrb);
    if (a == MRB_INT_MIN && b == -1) return mrb_fixnum_value(0);
    return mrb_int_value(mrb, a % b);
  }
#ifdef MRB_NO_FLOAT
  mrb_raise(mrb, E_TYPE_ERROR, "non integer remainder");
#else
  return flo_remainder(mrb, mrb_float_value(mrb, mrb_as_float(mrb, x)));
#endif
}

mrb_value mrb_int_pow(mrb_state *mrb, mrb_value x);

/*
 * call-seq:
 *    integer.pow(numeric)           ->  numeric
 *    integer.pow(integer, integer)  ->  integer
 *
 * Returns (modular) exponentiation as:
 *
 *   a.pow(b)     #=> same as a**b
 *   a.pow(b, m)  #=> same as (a**b) % m, but avoids huge temporary values
 */
static mrb_value
int_powm(mrb_state *mrb, mrb_value x)
{
  mrb_value m;
  mrb_int base, exp, mod, result = 1;

  if (mrb_get_argc(mrb) == 1) {
    return mrb_int_pow(mrb, x);
  }
  mrb_get_args(mrb, "io", &exp, &m);
  if (exp < 0) mrb_raise(mrb, E_ARGUMENT_ERROR, "int.pow(n,m): n must be positive");
#ifdef MRB_USE_BIGINT
  if (mrb_bigint_p(x)) {
    return mrb_bint_powm(mrb, x, exp, m);
  }
  if (mrb_bigint_p(m)) {
    return mrb_bint_powm(mrb, mrb_bint_new_int(mrb, mrb_integer(x)), exp, m);
  }
#endif
  if (!mrb_integer_p(m)) mrb_raise(mrb, E_TYPE_ERROR, "int.pow(n,m): m must be integer");
  mod = mrb_integer(m);
  if (mod < 0) mrb_raise(mrb, E_ARGUMENT_ERROR, "int.pow(n,m): m must be positive");
  if (mod == 0) mrb_int_zerodiv(mrb);
  if (mod == 1) return mrb_fixnum_value(0);
  base = mrb_integer(x);
  for (;;) {
    if (exp & 1) {
      if (mrb_int_mul_overflow(result, base, &result)) {
        mrb_int_overflow(mrb, "pow");
      }
      result %= mod;
    }
    exp >>= 1;
    if (exp == 0) break;
    if (mrb_int_mul_overflow(base, base, &base)) {
      mrb_int_overflow(mrb, "pow");
    }
    base %= mod;
  }
  return mrb_int_value(mrb, result);
}

#ifndef MRB_NO_FLOAT
static mrb_value
flo_remainder(mrb_state *mrb, mrb_value self)
{
  mrb_float a, b;

  a = mrb_float(self);
  mrb_get_args(mrb, "f", &b);
  if (b == 0) mrb_int_zerodiv(mrb);
  if (isinf(b)) return mrb_float_value(mrb, a);
  return mrb_float_value(mrb, a-b*trunc(a/b));
}
#endif

void
mrb_mruby_numeric_ext_gem_init(mrb_state* mrb)
{
  struct RClass *i = mrb_class_get(mrb, "Integer");

  mrb_define_method(mrb, i, "allbits?", int_allbits, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, i, "anybits?", int_anybits, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, i, "nobits?", int_nobits, MRB_ARGS_REQ(1));

  mrb_define_alias(mrb, i, "modulo", "%");
  mrb_define_method(mrb, i, "remainder", int_remainder, MRB_ARGS_REQ(1));

  mrb_define_method_id(mrb, i, MRB_SYM(pow), int_powm, MRB_ARGS_ARG(1,1));

#ifndef MRB_NO_FLOAT
  struct RClass *f = mrb_class_get(mrb, "Float");

  mrb_define_alias(mrb, f, "modulo", "%");
  mrb_define_method(mrb, f, "remainder", flo_remainder, MRB_ARGS_REQ(1));

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
