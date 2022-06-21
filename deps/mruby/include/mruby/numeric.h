/**
** @file mruby/numeric.h - Numeric, Integer, Float class
**
** See Copyright Notice in mruby.h
*/

#ifndef MRUBY_NUMERIC_H
#define MRUBY_NUMERIC_H

#include "common.h"

/**
 * Numeric class and it's sub-classes.
 *
 * Integer and Float
 */
MRB_BEGIN_DECL

#define TYPED_POSFIXABLE(f,t) ((f) <= (t)MRB_FIXNUM_MAX)
#define TYPED_NEGFIXABLE(f,t) ((f) >= (t)MRB_FIXNUM_MIN)
#define TYPED_FIXABLE(f,t) (TYPED_POSFIXABLE(f,t) && TYPED_NEGFIXABLE(f,t))
#define POSFIXABLE(f) TYPED_POSFIXABLE(f,mrb_int)
#define NEGFIXABLE(f) TYPED_NEGFIXABLE(f,mrb_int)
#define FIXABLE(f) TYPED_FIXABLE(f,mrb_int)
#ifndef MRB_NO_FLOAT
#ifdef MRB_INT64
#define FIXABLE_FLOAT(f) ((f)>=-9223372036854775808.0 && (f)<9223372036854775808.0)
#else
#define FIXABLE_FLOAT(f) TYPED_FIXABLE(f,mrb_float)
#endif
#endif

MRB_API mrb_value mrb_num_plus(mrb_state *mrb, mrb_value x, mrb_value y);
MRB_API mrb_value mrb_num_minus(mrb_state *mrb, mrb_value x, mrb_value y);
MRB_API mrb_value mrb_num_mul(mrb_state *mrb, mrb_value x, mrb_value y);

MRB_API mrb_value mrb_integer_to_str(mrb_state *mrb, mrb_value x, mrb_int base);
MRB_API char *mrb_int_to_cstr(char *buf, size_t len, mrb_int n, mrb_int base);

/* internal function(s) */
mrb_int mrb_div_int(mrb_state *mrb, mrb_int x, mrb_int y);

/* obsolete function(s); will be removed */
#define mrb_fixnum_to_str(mrb, x, base) mrb_integer_to_str(mrb, x, base)

#ifndef __has_builtin
  #define __has_builtin(x) 0
#endif

#if (defined(__GNUC__) && __GNUC__ >= 5) ||   \
    (__has_builtin(__builtin_add_overflow) && \
     __has_builtin(__builtin_sub_overflow) && \
     __has_builtin(__builtin_mul_overflow))
# define MRB_HAVE_TYPE_GENERIC_CHECKED_ARITHMETIC_BUILTINS
#endif

/*
// Clang 3.8 and 3.9 have problem compiling mruby in 32-bit mode, when MRB_INT64 is set
// because of missing __mulodi4 and similar functions in its runtime. We need to use custom
// implementation for them.
*/
#ifdef MRB_HAVE_TYPE_GENERIC_CHECKED_ARITHMETIC_BUILTINS
#if defined(__clang__) && (__clang_major__ == 3) && (__clang_minor__ >= 8) && \
    defined(MRB_32BIT) && defined(MRB_INT64)
#undef MRB_HAVE_TYPE_GENERIC_CHECKED_ARITHMETIC_BUILTINS
#endif
#endif

#ifdef MRB_HAVE_TYPE_GENERIC_CHECKED_ARITHMETIC_BUILTINS

static inline mrb_bool
mrb_int_add_overflow(mrb_int augend, mrb_int addend, mrb_int *sum)
{
  return __builtin_add_overflow(augend, addend, sum);
}

static inline mrb_bool
mrb_int_sub_overflow(mrb_int minuend, mrb_int subtrahend, mrb_int *difference)
{
  return __builtin_sub_overflow(minuend, subtrahend, difference);
}

static inline mrb_bool
mrb_int_mul_overflow(mrb_int multiplier, mrb_int multiplicand, mrb_int *product)
{
  return __builtin_mul_overflow(multiplier, multiplicand, product);
}

#else

#define MRB_INT_OVERFLOW_MASK ((mrb_uint)1 << (MRB_INT_BIT - 1))

static inline mrb_bool
mrb_int_add_overflow(mrb_int a, mrb_int b, mrb_int *c)
{
  mrb_uint x = (mrb_uint)a;
  mrb_uint y = (mrb_uint)b;
  mrb_uint z = (mrb_uint)(x + y);
  *c = (mrb_int)z;
  return !!(((x ^ z) & (y ^ z)) & MRB_INT_OVERFLOW_MASK);
}

static inline mrb_bool
mrb_int_sub_overflow(mrb_int a, mrb_int b, mrb_int *c)
{
  mrb_uint x = (mrb_uint)a;
  mrb_uint y = (mrb_uint)b;
  mrb_uint z = (mrb_uint)(x - y);
  *c = (mrb_int)z;
  return !!(((x ^ z) & (~y ^ z)) & MRB_INT_OVERFLOW_MASK);
}

static inline mrb_bool
mrb_int_mul_overflow(mrb_int a, mrb_int b, mrb_int *c)
{
#ifdef MRB_INT32
  int64_t n = (int64_t)a * b;
  *c = (mrb_int)n;
  return n > MRB_INT_MAX || n < MRB_INT_MIN;
#else /* MRB_INT64 */
  if (a > 0 && b > 0 && a > MRB_INT_MAX / b) return TRUE;
  if (a < 0 && b > 0 && a < MRB_INT_MIN / b) return TRUE;
  if (a > 0 && b < 0 && b < MRB_INT_MIN / a) return TRUE;
  if (a < 0 && b < 0 && (a <= MRB_INT_MIN || b <= MRB_INT_MIN || -a > MRB_INT_MAX / -b))
    return TRUE;
  *c = a * b;
  return FALSE;
#endif
}

#undef MRB_INT_OVERFLOW_MASK

#endif

#ifndef MRB_NO_FLOAT

# define MRB_FLT_RADIX          FLT_RADIX

# ifdef MRB_USE_FLOAT32
#  define MRB_FLT_MANT_DIG      FLT_MANT_DIG
#  define MRB_FLT_EPSILON       FLT_EPSILON
#  define MRB_FLT_DIG           FLT_DIG
#  define MRB_FLT_MIN_EXP       FLT_MIN_EXP
#  define MRB_FLT_MIN           FLT_MIN
#  define MRB_FLT_MIN_10_EXP    FLT_MIN_10_EXP
#  define MRB_FLT_MAX_EXP       FLT_MAX_EXP
#  define MRB_FLT_MAX           FLT_MAX
#  define MRB_FLT_MAX_10_EXP    FLT_MAX_10_EXP

# else /* not MRB_USE_FLOAT32 */
#  define MRB_FLT_MANT_DIG      DBL_MANT_DIG
#  define MRB_FLT_EPSILON       DBL_EPSILON
#  define MRB_FLT_DIG           DBL_DIG
#  define MRB_FLT_MIN_EXP       DBL_MIN_EXP
#  define MRB_FLT_MIN           DBL_MIN
#  define MRB_FLT_MIN_10_EXP    DBL_MIN_10_EXP
#  define MRB_FLT_MAX_EXP       DBL_MAX_EXP
#  define MRB_FLT_MAX           DBL_MAX
#  define MRB_FLT_MAX_10_EXP    DBL_MAX_10_EXP
# endif /* MRB_USE_FLOAT32 */

MRB_API mrb_value mrb_float_to_integer(mrb_state *mrb, mrb_value val);

/* internal functions */
mrb_float mrb_div_float(mrb_float x, mrb_float y);
mrb_value mrb_float_to_str(mrb_state *mrb, mrb_value x, const char *fmt);
int mrb_format_float(mrb_float f, char *buf, size_t buf_size, char fmt, int prec, char sign);

/* obsolete functions; will be removed */
#define mrb_flo_to_fixnum(mrb, val) mrb_float_to_integer(mrb, val)
#define mrb_to_flo(mrb, x) mrb_as_float(mrb, x)

#endif /* MRB_NO_FLOAT */

MRB_END_DECL

#endif  /* MRUBY_NUMERIC_H */
