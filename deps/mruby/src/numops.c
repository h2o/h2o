/*
** numeric.c - Numeric, Integer, Float class
**
** See Copyright Notice in mruby.h
*/

#include <mruby.h>
#include <mruby/numeric.h>
#include <mruby/internal.h>
#include <mruby/presym.h>

MRB_API mrb_value
mrb_num_add(mrb_state *mrb, mrb_value x, mrb_value y)
{
#ifdef MRB_USE_BIGINT
  if (mrb_bigint_p(x)) {
    return mrb_bint_add(mrb, x, y);
  }
#endif
  if (mrb_integer_p(x)) {
    return mrb_int_add(mrb, x, y);
  }
#ifndef MRB_NO_FLOAT
  if (mrb_float_p(x)) {
    return mrb_float_value(mrb, mrb_float(x) + mrb_as_float(mrb, y));
  }
#endif
#if defined(MRB_USE_RATIONAL) || defined(MRB_USE_COMPLEX)
  switch (mrb_type(x)) {
#if defined(MRB_USE_RATIONAL)
  case MRB_TT_RATIONAL:
    return mrb_rational_add(mrb, x, y);
#endif
#if defined(MRB_USE_COMPLEX)
  case MRB_TT_COMPLEX:
    return mrb_complex_add(mrb, x, y);
#endif
  default:
    break;
  }
#endif
  mrb_raise(mrb, E_TYPE_ERROR, "no number addition");
  return mrb_nil_value();       /* not reached */
}

MRB_API mrb_value
mrb_num_sub(mrb_state *mrb, mrb_value x, mrb_value y)
{
#ifdef MRB_USE_BIGINT
  if (mrb_bigint_p(x)) {
    return mrb_bint_sub(mrb, x, y);
  }
#endif
  if (mrb_integer_p(x)) {
    return mrb_int_sub(mrb, x, y);
  }
#ifndef MRB_NO_FLOAT
  if (mrb_float_p(x)) {
    return mrb_float_value(mrb, mrb_float(x) - mrb_as_float(mrb, y));
  }
#endif
#if defined(MRB_USE_RATIONAL) || defined(MRB_USE_COMPLEX)
  switch (mrb_type(x)) {
#if defined(MRB_USE_RATIONAL)
  case MRB_TT_RATIONAL:
    return mrb_rational_sub(mrb, x, y);
#endif
#if defined(MRB_USE_COMPLEX)
  case MRB_TT_COMPLEX:
    return mrb_complex_sub(mrb, x, y);
#endif
  default:
    break;
  }
#endif
  mrb_raise(mrb, E_TYPE_ERROR, "no number subtraction");
  return mrb_nil_value();       /* not reached */
}

MRB_API mrb_value
mrb_num_mul(mrb_state *mrb, mrb_value x, mrb_value y)
{
#ifdef MRB_USE_BIGINT
  if (mrb_bigint_p(x)) {
    return mrb_bint_mul(mrb, x, y);
  }
#endif
  if (mrb_integer_p(x)) {
    return mrb_int_mul(mrb, x, y);
  }
#ifndef MRB_NO_FLOAT
  if (mrb_float_p(x)) {
    return mrb_float_value(mrb, mrb_float(x) * mrb_as_float(mrb, y));
  }
#endif
#if defined(MRB_USE_RATIONAL) || defined(MRB_USE_COMPLEX)
  switch (mrb_type(x)) {
#if defined(MRB_USE_RATIONAL)
  case MRB_TT_RATIONAL:
    return mrb_rational_mul(mrb, x, y);
#endif
#if defined(MRB_USE_COMPLEX)
  case MRB_TT_COMPLEX:
    return mrb_complex_mul(mrb, x, y);
#endif
  default:
    break;
  }
#endif
  mrb_raise(mrb, E_TYPE_ERROR, "no number multiply");
  return mrb_nil_value();       /* not reached */
}
