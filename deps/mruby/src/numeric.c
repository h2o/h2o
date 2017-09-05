/*
** numeric.c - Numeric, Integer, Float, Fixnum class
**
** See Copyright Notice in mruby.h
*/

#include <float.h>
#include <limits.h>
#include <math.h>
#include <stdlib.h>

#include <mruby.h>
#include <mruby/array.h>
#include <mruby/numeric.h>
#include <mruby/string.h>
#include <mruby/class.h>

#ifdef MRB_USE_FLOAT
#define trunc(f) truncf(f)
#define floor(f) floorf(f)
#define ceil(f) ceilf(f)
#define fmod(x,y) fmodf(x,y)
#define MRB_FLO_TO_STR_FMT "%.7g"
#else
#define MRB_FLO_TO_STR_FMT "%.14g"
#endif

MRB_API mrb_float
mrb_to_flo(mrb_state *mrb, mrb_value val)
{
  switch (mrb_type(val)) {
  case MRB_TT_FIXNUM:
    return (mrb_float)mrb_fixnum(val);
  case MRB_TT_FLOAT:
    break;
  default:
    mrb_raise(mrb, E_TYPE_ERROR, "non float value");
  }
  return mrb_float(val);
}

/*
 * call-seq:
 *
 *  num ** other  ->  num
 *
 * Raises <code>num</code> the <code>other</code> power.
 *
 *    2.0**3      #=> 8.0
 */
static mrb_value
num_pow(mrb_state *mrb, mrb_value x)
{
  mrb_value y;
  mrb_float d;

  mrb_get_args(mrb, "o", &y);
  if (mrb_fixnum_p(x) && mrb_fixnum_p(y)) {
    /* try ipow() */
    mrb_int base = mrb_fixnum(x);
    mrb_int exp = mrb_fixnum(y);
    mrb_int result = 1;

    if (exp < 0) goto float_pow;
    for (;;) {
      if (exp & 1) {
        if (mrb_int_mul_overflow(result, base, &result)) {
          goto float_pow;
        }
      }
      exp >>= 1;
      if (exp == 0) break;
      if (mrb_int_mul_overflow(base, base, &base)) {
        goto float_pow;
      }
    }
    return mrb_fixnum_value(result);
  }
 float_pow:
  d = pow(mrb_to_flo(mrb, x), mrb_to_flo(mrb, y));
  return mrb_float_value(mrb, d);
}

/* 15.2.8.3.4  */
/* 15.2.9.3.4  */
/*
 * call-seq:
 *   num / other  ->  num
 *
 * Performs division: the class of the resulting object depends on
 * the class of <code>num</code> and on the magnitude of the
 * result.
 */

mrb_value
mrb_num_div(mrb_state *mrb, mrb_value x, mrb_value y)
{
  return mrb_float_value(mrb, mrb_to_flo(mrb, x) / mrb_to_flo(mrb, y));
}

/* 15.2.9.3.19(x) */
/*
 *  call-seq:
 *     num.quo(numeric)  ->  real
 *
 *  Returns most exact division.
 */

static mrb_value
num_div(mrb_state *mrb, mrb_value x)
{
  mrb_float y;

  mrb_get_args(mrb, "f", &y);
  return mrb_float_value(mrb, mrb_to_flo(mrb, x) / y);
}

/********************************************************************
 *
 * Document-class: Float
 *
 *  <code>Float</code> objects represent inexact real numbers using
 *  the native architecture's double-precision floating point
 *  representation.
 */

/* 15.2.9.3.16(x) */
/*
 *  call-seq:
 *     flt.to_s  ->  string
 *
 *  Returns a string containing a representation of self. As well as a
 *  fixed or exponential form of the number, the call may return
 *  "<code>NaN</code>", "<code>Infinity</code>", and
 *  "<code>-Infinity</code>".
 */

static mrb_value
flo_to_s(mrb_state *mrb, mrb_value flt)
{
  if (isnan(mrb_float(flt))) {
    return mrb_str_new_lit(mrb, "NaN");
  }
  return mrb_float_to_str(mrb, flt, MRB_FLO_TO_STR_FMT);
}

/* 15.2.9.3.2  */
/*
 * call-seq:
 *   float - other  ->  float
 *
 * Returns a new float which is the difference of <code>float</code>
 * and <code>other</code>.
 */

static mrb_value
flo_minus(mrb_state *mrb, mrb_value x)
{
  mrb_value y;

  mrb_get_args(mrb, "o", &y);
  return mrb_float_value(mrb, mrb_float(x) - mrb_to_flo(mrb, y));
}

/* 15.2.9.3.3  */
/*
 * call-seq:
 *   float * other  ->  float
 *
 * Returns a new float which is the product of <code>float</code>
 * and <code>other</code>.
 */

static mrb_value
flo_mul(mrb_state *mrb, mrb_value x)
{
  mrb_value y;

  mrb_get_args(mrb, "o", &y);
  return mrb_float_value(mrb, mrb_float(x) * mrb_to_flo(mrb, y));
}

static void
flodivmod(mrb_state *mrb, mrb_float x, mrb_float y, mrb_float *divp, mrb_float *modp)
{
  mrb_float div;
  mrb_float mod;

  if (y == 0.0) {
    if (x > 0.0) div = INFINITY;
    else if (x < 0.0) div = -INFINITY;
    else div = NAN;             /* x == 0.0 */
    mod = NAN;
  }
  else {
    mod = fmod(x, y);
    if (isinf(x) && isfinite(y))
      div = x;
    else
      div = (x - mod) / y;
    if (y*mod < 0) {
      mod += y;
      div -= 1.0;
    }
  }

  if (modp) *modp = mod;
  if (divp) *divp = div;
}

/* 15.2.9.3.5  */
/*
 *  call-seq:
 *     flt % other        ->  float
 *     flt.modulo(other)  ->  float
 *
 *  Return the modulo after division of <code>flt</code> by <code>other</code>.
 *
 *     6543.21.modulo(137)      #=> 104.21
 *     6543.21.modulo(137.24)   #=> 92.9299999999996
 */

static mrb_value
flo_mod(mrb_state *mrb, mrb_value x)
{
  mrb_value y;
  mrb_float mod;

  mrb_get_args(mrb, "o", &y);

  flodivmod(mrb, mrb_float(x), mrb_to_flo(mrb, y), 0, &mod);
  return mrb_float_value(mrb, mod);
}

/* 15.2.8.3.16 */
/*
 *  call-seq:
 *     num.eql?(numeric)  ->  true or false
 *
 *  Returns <code>true</code> if <i>num</i> and <i>numeric</i> are the
 *  same type and have equal values.
 *
 *     1 == 1.0          #=> true
 *     1.eql?(1.0)       #=> false
 *     (1.0).eql?(1.0)   #=> true
 */
static mrb_value
fix_eql(mrb_state *mrb, mrb_value x)
{
  mrb_value y;

  mrb_get_args(mrb, "o", &y);
  if (!mrb_fixnum_p(y)) return mrb_false_value();
  return mrb_bool_value(mrb_fixnum(x) == mrb_fixnum(y));
}

static mrb_value
flo_eql(mrb_state *mrb, mrb_value x)
{
  mrb_value y;

  mrb_get_args(mrb, "o", &y);
  if (!mrb_float_p(y)) return mrb_false_value();
  return mrb_bool_value(mrb_float(x) == (mrb_float)mrb_fixnum(y));
}

/* 15.2.9.3.7  */
/*
 *  call-seq:
 *     flt == obj  ->  true or false
 *
 *  Returns <code>true</code> only if <i>obj</i> has the same value
 *  as <i>flt</i>. Contrast this with <code>Float#eql?</code>, which
 *  requires <i>obj</i> to be a <code>Float</code>.
 *
 *     1.0 == 1   #=> true
 *
 */

static mrb_value
flo_eq(mrb_state *mrb, mrb_value x)
{
  mrb_value y;
  mrb_get_args(mrb, "o", &y);

  switch (mrb_type(y)) {
  case MRB_TT_FIXNUM:
    return mrb_bool_value(mrb_float(x) == (mrb_float)mrb_fixnum(y));
  case MRB_TT_FLOAT:
    return mrb_bool_value(mrb_float(x) == mrb_float(y));
  default:
    return mrb_false_value();
  }
}

static int64_t
value_int64(mrb_state *mrb, mrb_value x)
{
  switch (mrb_type(x)) {
  case MRB_TT_FIXNUM:
    return (int64_t)mrb_fixnum(x);
    break;
  case MRB_TT_FLOAT:
    return (int64_t)mrb_float(x);
  default:
    mrb_raise(mrb, E_TYPE_ERROR, "cannot convert to Integer");
    break;
  }
  /* not reached */
  return 0;
}

static mrb_value
int64_value(mrb_state *mrb, int64_t v)
{
  if (FIXABLE(v)) {
    return mrb_fixnum_value((mrb_int)v);
  }
  return mrb_float_value(mrb, (mrb_float)v);
}

static mrb_value
flo_rev(mrb_state *mrb, mrb_value x)
{
  int64_t v1;
  mrb_get_args(mrb, "");
  v1 = (int64_t)mrb_float(x);
  return int64_value(mrb, ~v1);
}

static mrb_value
flo_and(mrb_state *mrb, mrb_value x)
{
  mrb_value y;
  int64_t v1, v2;
  mrb_get_args(mrb, "o", &y);

  v1 = (int64_t)mrb_float(x);
  v2 = value_int64(mrb, y);
  return int64_value(mrb, v1 & v2);
}

static mrb_value
flo_or(mrb_state *mrb, mrb_value x)
{
  mrb_value y;
  int64_t v1, v2;
  mrb_get_args(mrb, "o", &y);

  v1 = (int64_t)mrb_float(x);
  v2 = value_int64(mrb, y);
  return int64_value(mrb, v1 | v2);
}

static mrb_value
flo_xor(mrb_state *mrb, mrb_value x)
{
  mrb_value y;
  int64_t v1, v2;
  mrb_get_args(mrb, "o", &y);

  v1 = (int64_t)mrb_float(x);
  v2 = value_int64(mrb, y);
  return int64_value(mrb, v1 ^ v2);
}

static mrb_value
flo_shift(mrb_state *mrb, mrb_value x, mrb_int width)
{
  mrb_float val;

  if (width == 0) {
    return x;
  }
  val = mrb_float(x);
  if (width < 0) {
    while (width++) {
      val /= 2;
    }
#if defined(_ISOC99_SOURCE)
    val = trunc(val);
#else
    if (val > 0){
        val = floor(val);    
    } else {
        val = ceil(val);
    }
#endif
    if (val == 0 && mrb_float(x) < 0) {
      return mrb_fixnum_value(-1);
    }
  }
  else {
    while (width--) {
      val *= 2;
    }
  }
  if (FIXABLE_FLOAT(val)) {
    return mrb_fixnum_value((mrb_int)val);
  }
  return mrb_float_value(mrb, val);
}

static mrb_value
flo_lshift(mrb_state *mrb, mrb_value x)
{
  mrb_int width;

  mrb_get_args(mrb, "i", &width);
  return flo_shift(mrb, x, -width);
}

static mrb_value
flo_rshift(mrb_state *mrb, mrb_value x)
{
  mrb_int width;

  mrb_get_args(mrb, "i", &width);
  return flo_shift(mrb, x, width);
}

/* 15.2.9.3.13 */
/*
 * call-seq:
 *   flt.to_f  ->  self
 *
 * As <code>flt</code> is already a float, returns +self+.
 */

static mrb_value
flo_to_f(mrb_state *mrb, mrb_value num)
{
  return num;
}

/* 15.2.9.3.11 */
/*
 *  call-seq:
 *     flt.infinite?  ->  nil, -1, +1
 *
 *  Returns <code>nil</code>, -1, or +1 depending on whether <i>flt</i>
 *  is finite, -infinity, or +infinity.
 *
 *     (0.0).infinite?        #=> nil
 *     (-1.0/0.0).infinite?   #=> -1
 *     (+1.0/0.0).infinite?   #=> 1
 */

static mrb_value
flo_infinite_p(mrb_state *mrb, mrb_value num)
{
  mrb_float value = mrb_float(num);

  if (isinf(value)) {
    return mrb_fixnum_value(value < 0 ? -1 : 1);
  }
  return mrb_nil_value();
}

/* 15.2.9.3.9  */
/*
 *  call-seq:
 *     flt.finite?  ->  true or false
 *
 *  Returns <code>true</code> if <i>flt</i> is a valid IEEE floating
 *  point number (it is not infinite, and <code>nan?</code> is
 *  <code>false</code>).
 *
 */

static mrb_value
flo_finite_p(mrb_state *mrb, mrb_value num)
{
  return mrb_bool_value(isfinite(mrb_float(num)));
}

void
mrb_check_num_exact(mrb_state *mrb, mrb_float num)
{
  if (isinf(num)) {
    mrb_raise(mrb, E_FLOATDOMAIN_ERROR, num < 0 ? "-Infinity" : "Infinity");
  }
  if (isnan(num)) {
    mrb_raise(mrb, E_FLOATDOMAIN_ERROR, "NaN");
  }
}

/* 15.2.9.3.10 */
/*
 *  call-seq:
 *     flt.floor  ->  integer
 *
 *  Returns the largest integer less than or equal to <i>flt</i>.
 *
 *     1.2.floor      #=> 1
 *     2.0.floor      #=> 2
 *     (-1.2).floor   #=> -2
 *     (-2.0).floor   #=> -2
 */

static mrb_value
flo_floor(mrb_state *mrb, mrb_value num)
{
  mrb_float f = floor(mrb_float(num));

  mrb_check_num_exact(mrb, f);
  if (!FIXABLE_FLOAT(f)) {
    return mrb_float_value(mrb, f);
  }
  return mrb_fixnum_value((mrb_int)f);
}

/* 15.2.9.3.8  */
/*
 *  call-seq:
 *     flt.ceil  ->  integer
 *
 *  Returns the smallest <code>Integer</code> greater than or equal to
 *  <i>flt</i>.
 *
 *     1.2.ceil      #=> 2
 *     2.0.ceil      #=> 2
 *     (-1.2).ceil   #=> -1
 *     (-2.0).ceil   #=> -2
 */

static mrb_value
flo_ceil(mrb_state *mrb, mrb_value num)
{
  mrb_float f = ceil(mrb_float(num));

  mrb_check_num_exact(mrb, f);
  if (!FIXABLE_FLOAT(f)) {
    return mrb_float_value(mrb, f);
  }
  return mrb_fixnum_value((mrb_int)f);
}

/* 15.2.9.3.12 */
/*
 *  call-seq:
 *     flt.round([ndigits])  ->  integer or float
 *
 *  Rounds <i>flt</i> to a given precision in decimal digits (default 0 digits).
 *  Precision may be negative.  Returns a floating point number when ndigits
 *  is more than zero.
 *
 *     1.4.round      #=> 1
 *     1.5.round      #=> 2
 *     1.6.round      #=> 2
 *     (-1.5).round   #=> -2
 *
 *     1.234567.round(2)  #=> 1.23
 *     1.234567.round(3)  #=> 1.235
 *     1.234567.round(4)  #=> 1.2346
 *     1.234567.round(5)  #=> 1.23457
 *
 *     34567.89.round(-5) #=> 0
 *     34567.89.round(-4) #=> 30000
 *     34567.89.round(-3) #=> 35000
 *     34567.89.round(-2) #=> 34600
 *     34567.89.round(-1) #=> 34570
 *     34567.89.round(0)  #=> 34568
 *     34567.89.round(1)  #=> 34567.9
 *     34567.89.round(2)  #=> 34567.89
 *     34567.89.round(3)  #=> 34567.89
 *
 */

static mrb_value
flo_round(mrb_state *mrb, mrb_value num)
{
  double number, f;
  mrb_int ndigits = 0;
  mrb_int i;

  mrb_get_args(mrb, "|i", &ndigits);
  number = mrb_float(num);

  if (0 < ndigits && (isinf(number) || isnan(number))) {
    return num;
  }
  mrb_check_num_exact(mrb, number);

  f = 1.0;
  i = ndigits >= 0 ? ndigits : -ndigits;
  while  (--i >= 0)
    f = f*10.0;

  if (isinf(f)) {
    if (ndigits < 0) number = 0;
  }
  else {
    double d;

    if (ndigits < 0) number /= f;
    else number *= f;

    /* home-made inline implementation of round(3) */
    if (number > 0.0) {
      d = floor(number);
      number = d + (number - d >= 0.5);
    }
    else if (number < 0.0) {
      d = ceil(number);
      number = d - (d - number >= 0.5);
    }

    if (ndigits < 0) number *= f;
    else number /= f;
  }

  if (ndigits > 0) {
    if (!isfinite(number)) return num;
    return mrb_float_value(mrb, number);
  }
  return mrb_fixnum_value((mrb_int)number);
}

/* 15.2.9.3.14 */
/* 15.2.9.3.15 */
/*
 *  call-seq:
 *     flt.to_i      ->  integer
 *     flt.to_int    ->  integer
 *     flt.truncate  ->  integer
 *
 *  Returns <i>flt</i> truncated to an <code>Integer</code>.
 */

static mrb_value
flo_truncate(mrb_state *mrb, mrb_value num)
{
  mrb_float f = mrb_float(num);

  if (f > 0.0) f = floor(f);
  if (f < 0.0) f = ceil(f);

  mrb_check_num_exact(mrb, f);
  if (!FIXABLE_FLOAT(f)) {
    return mrb_float_value(mrb, f);
  }
  return mrb_fixnum_value((mrb_int)f);
}

static mrb_value
flo_nan_p(mrb_state *mrb, mrb_value num)
{
  return mrb_bool_value(isnan(mrb_float(num)));
}

/*
 * Document-class: Integer
 *
 *  <code>Integer</code> is the basis for the two concrete classes that
 *  hold whole numbers, <code>Bignum</code> and <code>Fixnum</code>.
 *
 */


/*
 *  call-seq:
 *     int.to_i      ->  integer
 *     int.to_int    ->  integer
 *
 *  As <i>int</i> is already an <code>Integer</code>, all these
 *  methods simply return the receiver.
 */

static mrb_value
int_to_i(mrb_state *mrb, mrb_value num)
{
  return num;
}

mrb_value
mrb_fixnum_mul(mrb_state *mrb, mrb_value x, mrb_value y)
{
  mrb_int a;

  a = mrb_fixnum(x);
  if (mrb_fixnum_p(y)) {
    mrb_int b, c;

    if (a == 0) return x;
    b = mrb_fixnum(y);
    if (mrb_int_mul_overflow(a, b, &c)) {
      return mrb_float_value(mrb, (mrb_float)a * (mrb_float)b);
    }
    return mrb_fixnum_value(c);
  }
  return mrb_float_value(mrb, (mrb_float)a * mrb_to_flo(mrb, y));
}

/* 15.2.8.3.3  */
/*
 * call-seq:
 *   fix * numeric  ->  numeric_result
 *
 * Performs multiplication: the class of the resulting object depends on
 * the class of <code>numeric</code> and on the magnitude of the
 * result.
 */

static mrb_value
fix_mul(mrb_state *mrb, mrb_value x)
{
  mrb_value y;

  mrb_get_args(mrb, "o", &y);
  return mrb_fixnum_mul(mrb, x, y);
}

static void
fixdivmod(mrb_state *mrb, mrb_int x, mrb_int y, mrb_int *divp, mrb_int *modp)
{
  mrb_int div, mod;

  /* TODO: add mrb_assert(y != 0) to make sure */

  if (y < 0) {
    if (x < 0)
      div = -x / -y;
    else
      div = - (x / -y);
  }
  else {
    if (x < 0)
      div = - (-x / y);
    else
      div = x / y;
  }
  mod = x - div*y;
  if ((mod < 0 && y > 0) || (mod > 0 && y < 0)) {
    mod += y;
    div -= 1;
  }
  if (divp) *divp = div;
  if (modp) *modp = mod;
}

/* 15.2.8.3.5  */
/*
 *  call-seq:
 *    fix % other        ->  real
 *    fix.modulo(other)  ->  real
 *
 *  Returns <code>fix</code> modulo <code>other</code>.
 *  See <code>numeric.divmod</code> for more information.
 */

static mrb_value
fix_mod(mrb_state *mrb, mrb_value x)
{
  mrb_value y;
  mrb_int a;

  mrb_get_args(mrb, "o", &y);
  a = mrb_fixnum(x);
  if (mrb_fixnum_p(y)) {
    mrb_int b, mod;

    if ((b=mrb_fixnum(y)) == 0) {
      return mrb_float_value(mrb, NAN);
    }
    fixdivmod(mrb, a, b, 0, &mod);
    return mrb_fixnum_value(mod);
  }
  else {
    mrb_float mod;

    flodivmod(mrb, (mrb_float)a, mrb_to_flo(mrb, y), 0, &mod);
    return mrb_float_value(mrb, mod);
  }
}

/*
 *  call-seq:
 *     fix.divmod(numeric)  ->  array
 *
 *  See <code>Numeric#divmod</code>.
 */
static mrb_value
fix_divmod(mrb_state *mrb, mrb_value x)
{
  mrb_value y;

  mrb_get_args(mrb, "o", &y);

  if (mrb_fixnum_p(y)) {
    mrb_int div, mod;

    if (mrb_fixnum(y) == 0) {
      return mrb_assoc_new(mrb, ((mrb_fixnum(x) == 0) ?
                                 mrb_float_value(mrb, NAN):
                                 mrb_float_value(mrb, INFINITY)),
                           mrb_float_value(mrb, NAN));
    }
    fixdivmod(mrb, mrb_fixnum(x), mrb_fixnum(y), &div, &mod);
    return mrb_assoc_new(mrb, mrb_fixnum_value(div), mrb_fixnum_value(mod));
  }
  else {
    mrb_float div, mod;
    mrb_value a, b;

    flodivmod(mrb, (mrb_float)mrb_fixnum(x), mrb_to_flo(mrb, y), &div, &mod);
    a = mrb_float_value(mrb, div);
    b = mrb_float_value(mrb, mod);
    return mrb_assoc_new(mrb, a, b);
  }
}

static mrb_value
flo_divmod(mrb_state *mrb, mrb_value x)
{
  mrb_value y;
  mrb_float div, mod;
  mrb_value a, b;

  mrb_get_args(mrb, "o", &y);

  flodivmod(mrb, mrb_float(x), mrb_to_flo(mrb, y), &div, &mod);
  a = mrb_float_value(mrb, div);
  b = mrb_float_value(mrb, mod);
  return mrb_assoc_new(mrb, a, b);
}

/* 15.2.8.3.7  */
/*
 * call-seq:
 *   fix == other  ->  true or false
 *
 * Return <code>true</code> if <code>fix</code> equals <code>other</code>
 * numerically.
 *
 *   1 == 2      #=> false
 *   1 == 1.0    #=> true
 */

static mrb_value
fix_equal(mrb_state *mrb, mrb_value x)
{
  mrb_value y;

  mrb_get_args(mrb, "o", &y);
  switch (mrb_type(y)) {
  case MRB_TT_FIXNUM:
    return mrb_bool_value(mrb_fixnum(x) == mrb_fixnum(y));
  case MRB_TT_FLOAT:
    return mrb_bool_value((mrb_float)mrb_fixnum(x) == mrb_float(y));
  default:
    return mrb_false_value();
  }
}

/* 15.2.8.3.8  */
/*
 * call-seq:
 *   ~fix  ->  integer
 *
 * One's complement: returns a number where each bit is flipped.
 *   ex.0---00001 (1)-> 1---11110 (-2)
 *   ex.0---00010 (2)-> 1---11101 (-3)
 *   ex.0---00100 (4)-> 1---11011 (-5)
 */

static mrb_value
fix_rev(mrb_state *mrb, mrb_value num)
{
  mrb_int val = mrb_fixnum(num);

  return mrb_fixnum_value(~val);
}

static mrb_value flo_and(mrb_state *mrb, mrb_value x);
static mrb_value flo_or(mrb_state *mrb, mrb_value x);
static mrb_value flo_xor(mrb_state *mrb, mrb_value x);
#define bit_op(x,y,op1,op2) do {\
  if (mrb_fixnum_p(y)) return mrb_fixnum_value(mrb_fixnum(x) op2 mrb_fixnum(y));\
  return flo_ ## op1(mrb, mrb_float_value(mrb, mrb_fixnum(x)));\
} while(0)

/* 15.2.8.3.9  */
/*
 * call-seq:
 *   fix & integer  ->  integer_result
 *
 * Bitwise AND.
 */

static mrb_value
fix_and(mrb_state *mrb, mrb_value x)
{
  mrb_value y;

  mrb_get_args(mrb, "o", &y);
  bit_op(x, y, and, &);
}

/* 15.2.8.3.10 */
/*
 * call-seq:
 *   fix | integer  ->  integer_result
 *
 * Bitwise OR.
 */

static mrb_value
fix_or(mrb_state *mrb, mrb_value x)
{
  mrb_value y;

  mrb_get_args(mrb, "o", &y);
  bit_op(x, y, or, |);
}

/* 15.2.8.3.11 */
/*
 * call-seq:
 *   fix ^ integer  ->  integer_result
 *
 * Bitwise EXCLUSIVE OR.
 */

static mrb_value
fix_xor(mrb_state *mrb, mrb_value x)
{
  mrb_value y;

  mrb_get_args(mrb, "o", &y);
  bit_op(x, y, or, ^);
}

#define NUMERIC_SHIFT_WIDTH_MAX (MRB_INT_BIT-1)

static mrb_value
lshift(mrb_state *mrb, mrb_int val, mrb_int width)
{
  if (width < 0) {              /* mrb_int overflow */
    return mrb_float_value(mrb, INFINITY);
  }
  if (val > 0) {
    if ((width > NUMERIC_SHIFT_WIDTH_MAX) ||
        (val   > (MRB_INT_MAX >> width))) {
      goto bit_overflow;
    }
    return mrb_fixnum_value(val << width);
  }
  else {
    if ((width > NUMERIC_SHIFT_WIDTH_MAX) ||
        (val   < (MRB_INT_MIN >> width))) {
      goto bit_overflow;
    }
    return mrb_fixnum_value(val * (1u << width));
  }

bit_overflow:
  {
    mrb_float f = (mrb_float)val;
    while (width--) {
      f *= 2;
    }
    return mrb_float_value(mrb, f);
  }
}

static mrb_value
rshift(mrb_int val, mrb_int width)
{
  if (width < 0) {              /* mrb_int overflow */
    return mrb_fixnum_value(0);
  }
  if (width >= NUMERIC_SHIFT_WIDTH_MAX) {
    if (val < 0) {
      return mrb_fixnum_value(-1);
    }
    return mrb_fixnum_value(0);
  }
  return mrb_fixnum_value(val >> width);
}

/* 15.2.8.3.12 */
/*
 * call-seq:
 *   fix << count  ->  integer or float
 *
 * Shifts _fix_ left _count_ positions (right if _count_ is negative).
 */

static mrb_value
fix_lshift(mrb_state *mrb, mrb_value x)
{
  mrb_int width, val;

  mrb_get_args(mrb, "i", &width);
  if (width == 0) {
    return x;
  }
  val = mrb_fixnum(x);
  if (val == 0) return x;
  if (width < 0) {
    return rshift(val, -width);
  }
  return lshift(mrb, val, width);
}

/* 15.2.8.3.13 */
/*
 * call-seq:
 *   fix >> count  ->  integer or float
 *
 * Shifts _fix_ right _count_ positions (left if _count_ is negative).
 */

static mrb_value
fix_rshift(mrb_state *mrb, mrb_value x)
{
  mrb_int width, val;

  mrb_get_args(mrb, "i", &width);
  if (width == 0) {
    return x;
  }
  val = mrb_fixnum(x);
  if (val == 0) return x;
  if (width < 0) {
    return lshift(mrb, val, -width);
  }
  return rshift(val, width);
}

/* 15.2.8.3.23 */
/*
 *  call-seq:
 *     fix.to_f  ->  float
 *
 *  Converts <i>fix</i> to a <code>Float</code>.
 *
 */

static mrb_value
fix_to_f(mrb_state *mrb, mrb_value num)
{
  return mrb_float_value(mrb, (mrb_float)mrb_fixnum(num));
}

/*
 *  Document-class: FloatDomainError
 *
 *  Raised when attempting to convert special float values
 *  (in particular infinite or NaN)
 *  to numerical classes which don't support them.
 *
 *     Float::INFINITY.to_r
 *
 *  <em>raises the exception:</em>
 *
 *     FloatDomainError: Infinity
 */
/* ------------------------------------------------------------------------*/
MRB_API mrb_value
mrb_flo_to_fixnum(mrb_state *mrb, mrb_value x)
{
  mrb_int z = 0;

  if (!mrb_float_p(x)) {
    mrb_raise(mrb, E_TYPE_ERROR, "non float value");
    z = 0; /* not reached. just suppress warnings. */
  }
  else {
    mrb_float d = mrb_float(x);

    if (isinf(d)) {
      mrb_raise(mrb, E_FLOATDOMAIN_ERROR, d < 0 ? "-Infinity" : "Infinity");
    }
    if (isnan(d)) {
      mrb_raise(mrb, E_FLOATDOMAIN_ERROR, "NaN");
    }
    if (FIXABLE_FLOAT(d)) {
      z = (mrb_int)d;
    }
    else {
      mrb_raisef(mrb, E_ARGUMENT_ERROR, "number (%S) too big for integer", x);
    }
  }
  return mrb_fixnum_value(z);
}

mrb_value
mrb_fixnum_plus(mrb_state *mrb, mrb_value x, mrb_value y)
{
  mrb_int a;

  a = mrb_fixnum(x);
  if (mrb_fixnum_p(y)) {
    mrb_int b, c;

    if (a == 0) return y;
    b = mrb_fixnum(y);
    if (mrb_int_add_overflow(a, b, &c)) {
      return mrb_float_value(mrb, (mrb_float)a + (mrb_float)b);
    }
    return mrb_fixnum_value(c);
  }
  return mrb_float_value(mrb, (mrb_float)a + mrb_to_flo(mrb, y));
}

/* 15.2.8.3.1  */
/*
 * call-seq:
 *   fix + numeric  ->  numeric_result
 *
 * Performs addition: the class of the resulting object depends on
 * the class of <code>numeric</code> and on the magnitude of the
 * result.
 */
static mrb_value
fix_plus(mrb_state *mrb, mrb_value self)
{
  mrb_value other;

  mrb_get_args(mrb, "o", &other);
  return mrb_fixnum_plus(mrb, self, other);
}

mrb_value
mrb_fixnum_minus(mrb_state *mrb, mrb_value x, mrb_value y)
{
  mrb_int a;

  a = mrb_fixnum(x);
  if (mrb_fixnum_p(y)) {
    mrb_int b, c;

    b = mrb_fixnum(y);
    if (mrb_int_sub_overflow(a, b, &c)) {
      return mrb_float_value(mrb, (mrb_float)a - (mrb_float)b);
    }
    return mrb_fixnum_value(c);
  }
  return mrb_float_value(mrb, (mrb_float)a - mrb_to_flo(mrb, y));
}

/* 15.2.8.3.2  */
/* 15.2.8.3.16 */
/*
 * call-seq:
 *   fix - numeric  ->  numeric_result
 *
 * Performs subtraction: the class of the resulting object depends on
 * the class of <code>numeric</code> and on the magnitude of the
 * result.
 */
static mrb_value
fix_minus(mrb_state *mrb, mrb_value self)
{
  mrb_value other;

  mrb_get_args(mrb, "o", &other);
  return mrb_fixnum_minus(mrb, self, other);
}


MRB_API mrb_value
mrb_fixnum_to_str(mrb_state *mrb, mrb_value x, int base)
{
  char buf[MRB_INT_BIT+1];
  char *b = buf + sizeof buf;
  mrb_int val = mrb_fixnum(x);

  if (base < 2 || 36 < base) {
    mrb_raisef(mrb, E_ARGUMENT_ERROR, "invalid radix %S", mrb_fixnum_value(base));
  }

  if (val == 0) {
    *--b = '0';
  }
  else if (val < 0) {
    do {
      *--b = mrb_digitmap[-(val % base)];
    } while (val /= base);
    *--b = '-';
  }
  else {
    do {
      *--b = mrb_digitmap[(int)(val % base)];
    } while (val /= base);
  }

  return mrb_str_new(mrb, b, buf + sizeof(buf) - b);
}

/* 15.2.8.3.25 */
/*
 *  call-seq:
 *     fix.to_s(base=10)  ->  string
 *
 *  Returns a string containing the representation of <i>fix</i> radix
 *  <i>base</i> (between 2 and 36).
 *
 *     12345.to_s       #=> "12345"
 *     12345.to_s(2)    #=> "11000000111001"
 *     12345.to_s(8)    #=> "30071"
 *     12345.to_s(10)   #=> "12345"
 *     12345.to_s(16)   #=> "3039"
 *     12345.to_s(36)   #=> "9ix"
 *
 */
static mrb_value
fix_to_s(mrb_state *mrb, mrb_value self)
{
  mrb_int base = 10;

  mrb_get_args(mrb, "|i", &base);
  return mrb_fixnum_to_str(mrb, self, base);
}

/* 15.2.9.3.6  */
/*
 * call-seq:
 *     self.f <=> other.f    => -1, 0, +1
 *             <  => -1
 *             =  =>  0
 *             >  => +1
 *  Comparison---Returns -1, 0, or +1 depending on whether <i>fix</i> is
 *  less than, equal to, or greater than <i>numeric</i>. This is the
 *  basis for the tests in <code>Comparable</code>.
 */
static mrb_value
num_cmp(mrb_state *mrb, mrb_value self)
{
  mrb_value other;
  mrb_float x, y;

  mrb_get_args(mrb, "o", &other);

  x = mrb_to_flo(mrb, self);
  switch (mrb_type(other)) {
  case MRB_TT_FIXNUM:
    y = (mrb_float)mrb_fixnum(other);
    break;
  case MRB_TT_FLOAT:
    y = mrb_float(other);
    break;
  default:
    return mrb_nil_value();
  }
  if (x > y)
    return mrb_fixnum_value(1);
  else {
    if (x < y)
      return mrb_fixnum_value(-1);
    return mrb_fixnum_value(0);
  }
}

/* 15.2.9.3.1  */
/*
 * call-seq:
 *   float + other  ->  float
 *
 * Returns a new float which is the sum of <code>float</code>
 * and <code>other</code>.
 */
static mrb_value
flo_plus(mrb_state *mrb, mrb_value x)
{
  mrb_value y;

  mrb_get_args(mrb, "o", &y);
  return mrb_float_value(mrb, mrb_float(x) + mrb_to_flo(mrb, y));
}

/* ------------------------------------------------------------------------*/
void
mrb_init_numeric(mrb_state *mrb)
{
  struct RClass *numeric, *integer, *fixnum, *fl;

  /* Numeric Class */
  numeric = mrb_define_class(mrb, "Numeric",  mrb->object_class);                /* 15.2.7 */

  mrb_define_method(mrb, numeric, "**",       num_pow,         MRB_ARGS_REQ(1));
  mrb_define_method(mrb, numeric, "/",        num_div,         MRB_ARGS_REQ(1)); /* 15.2.8.3.4  */
  mrb_define_method(mrb, numeric, "quo",      num_div,         MRB_ARGS_REQ(1)); /* 15.2.7.4.5 (x) */
  mrb_define_method(mrb, numeric, "<=>",      num_cmp,         MRB_ARGS_REQ(1)); /* 15.2.9.3.6  */

  /* Integer Class */
  integer = mrb_define_class(mrb, "Integer",  numeric);                          /* 15.2.8 */
  MRB_SET_INSTANCE_TT(integer, MRB_TT_FIXNUM);
  mrb_undef_class_method(mrb, integer, "new");
  mrb_define_method(mrb, integer, "to_i",     int_to_i,        MRB_ARGS_NONE()); /* 15.2.8.3.24 */
  mrb_define_method(mrb, integer, "to_int",   int_to_i,        MRB_ARGS_NONE());
  mrb_define_method(mrb, integer, "ceil",     int_to_i,        MRB_ARGS_REQ(1)); /* 15.2.8.3.8 (x) */
  mrb_define_method(mrb, integer, "floor",    int_to_i,        MRB_ARGS_REQ(1)); /* 15.2.8.3.10 (x) */
  mrb_define_method(mrb, integer, "round",    int_to_i,        MRB_ARGS_REQ(1)); /* 15.2.8.3.12 (x) */
  mrb_define_method(mrb, integer, "truncate", int_to_i,        MRB_ARGS_REQ(1)); /* 15.2.8.3.15 (x) */

  /* Fixnum Class */
  mrb->fixnum_class = fixnum = mrb_define_class(mrb, "Fixnum", integer);
  mrb_define_method(mrb, fixnum,  "+",        fix_plus,        MRB_ARGS_REQ(1)); /* 15.2.8.3.1  */
  mrb_define_method(mrb, fixnum,  "-",        fix_minus,       MRB_ARGS_REQ(1)); /* 15.2.8.3.2  */
  mrb_define_method(mrb, fixnum,  "*",        fix_mul,         MRB_ARGS_REQ(1)); /* 15.2.8.3.3  */
  mrb_define_method(mrb, fixnum,  "%",        fix_mod,         MRB_ARGS_REQ(1)); /* 15.2.8.3.5  */
  mrb_define_method(mrb, fixnum,  "==",       fix_equal,       MRB_ARGS_REQ(1)); /* 15.2.8.3.7  */
  mrb_define_method(mrb, fixnum,  "~",        fix_rev,         MRB_ARGS_NONE()); /* 15.2.8.3.8  */
  mrb_define_method(mrb, fixnum,  "&",        fix_and,         MRB_ARGS_REQ(1)); /* 15.2.8.3.9  */
  mrb_define_method(mrb, fixnum,  "|",        fix_or,          MRB_ARGS_REQ(1)); /* 15.2.8.3.10 */
  mrb_define_method(mrb, fixnum,  "^",        fix_xor,         MRB_ARGS_REQ(1)); /* 15.2.8.3.11 */
  mrb_define_method(mrb, fixnum,  "<<",       fix_lshift,      MRB_ARGS_REQ(1)); /* 15.2.8.3.12 */
  mrb_define_method(mrb, fixnum,  ">>",       fix_rshift,      MRB_ARGS_REQ(1)); /* 15.2.8.3.13 */
  mrb_define_method(mrb, fixnum,  "eql?",     fix_eql,         MRB_ARGS_REQ(1)); /* 15.2.8.3.16 */
  mrb_define_method(mrb, fixnum,  "to_f",     fix_to_f,        MRB_ARGS_NONE()); /* 15.2.8.3.23 */
  mrb_define_method(mrb, fixnum,  "to_s",     fix_to_s,        MRB_ARGS_NONE()); /* 15.2.8.3.25 */
  mrb_define_method(mrb, fixnum,  "inspect",  fix_to_s,        MRB_ARGS_NONE());
  mrb_define_method(mrb, fixnum,  "divmod",   fix_divmod,      MRB_ARGS_REQ(1)); /* 15.2.8.3.30 (x) */

  /* Float Class */
  mrb->float_class = fl = mrb_define_class(mrb, "Float", numeric);                 /* 15.2.9 */
  MRB_SET_INSTANCE_TT(fl, MRB_TT_FLOAT);
  mrb_undef_class_method(mrb,  fl, "new");
  mrb_define_method(mrb, fl,      "+",         flo_plus,       MRB_ARGS_REQ(1)); /* 15.2.9.3.1  */
  mrb_define_method(mrb, fl,      "-",         flo_minus,      MRB_ARGS_REQ(1)); /* 15.2.9.3.2  */
  mrb_define_method(mrb, fl,      "*",         flo_mul,        MRB_ARGS_REQ(1)); /* 15.2.9.3.3  */
  mrb_define_method(mrb, fl,      "%",         flo_mod,        MRB_ARGS_REQ(1)); /* 15.2.9.3.5  */
  mrb_define_method(mrb, fl,      "==",        flo_eq,         MRB_ARGS_REQ(1)); /* 15.2.9.3.7  */
  mrb_define_method(mrb, fl,      "~",         flo_rev,        MRB_ARGS_NONE());
  mrb_define_method(mrb, fl,      "&",         flo_and,        MRB_ARGS_REQ(1));
  mrb_define_method(mrb, fl,      "|",         flo_or,         MRB_ARGS_REQ(1));
  mrb_define_method(mrb, fl,      "^",         flo_xor,        MRB_ARGS_REQ(1));
  mrb_define_method(mrb, fl,      ">>",        flo_lshift,     MRB_ARGS_REQ(1));
  mrb_define_method(mrb, fl,      "<<",        flo_rshift,     MRB_ARGS_REQ(1));
  mrb_define_method(mrb, fl,      "ceil",      flo_ceil,       MRB_ARGS_NONE()); /* 15.2.9.3.8  */
  mrb_define_method(mrb, fl,      "finite?",   flo_finite_p,   MRB_ARGS_NONE()); /* 15.2.9.3.9  */
  mrb_define_method(mrb, fl,      "floor",     flo_floor,      MRB_ARGS_NONE()); /* 15.2.9.3.10 */
  mrb_define_method(mrb, fl,      "infinite?", flo_infinite_p, MRB_ARGS_NONE()); /* 15.2.9.3.11 */
  mrb_define_method(mrb, fl,      "round",     flo_round,      MRB_ARGS_OPT(1)); /* 15.2.9.3.12 */
  mrb_define_method(mrb, fl,      "to_f",      flo_to_f,       MRB_ARGS_NONE()); /* 15.2.9.3.13 */
  mrb_define_method(mrb, fl,      "to_i",      flo_truncate,   MRB_ARGS_NONE()); /* 15.2.9.3.14 */
  mrb_define_method(mrb, fl,      "to_int",    flo_truncate,   MRB_ARGS_NONE());
  mrb_define_method(mrb, fl,      "truncate",  flo_truncate,   MRB_ARGS_NONE()); /* 15.2.9.3.15 */
  mrb_define_method(mrb, fl,      "divmod",    flo_divmod,     MRB_ARGS_REQ(1));
  mrb_define_method(mrb, fl,      "eql?",      flo_eql,        MRB_ARGS_REQ(1)); /* 15.2.8.3.16 */

  mrb_define_method(mrb, fl,      "to_s",      flo_to_s,       MRB_ARGS_NONE()); /* 15.2.9.3.16(x) */
  mrb_define_method(mrb, fl,      "inspect",   flo_to_s,       MRB_ARGS_NONE());
  mrb_define_method(mrb, fl,      "nan?",      flo_nan_p,      MRB_ARGS_NONE());

#ifdef INFINITY
  mrb_define_const(mrb, fl, "INFINITY", mrb_float_value(mrb, INFINITY));
#endif
#ifdef NAN
  mrb_define_const(mrb, fl, "NAN", mrb_float_value(mrb, NAN));
#endif
}
