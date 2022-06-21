#include <mruby.h>
#include <mruby/class.h>
#include <mruby/numeric.h>
#include <mruby/presym.h>

struct mrb_rational {
  mrb_int numerator;
  mrb_int denominator;
};

#if defined(MRB_INT64) && defined(MRB_32BIT)
struct RRational {
  MRB_OBJECT_HEADER;
  struct mrb_rational *p;
};

static struct mrb_rational*
rational_ptr(mrb_state *mrb, mrb_value v)
{
  struct RRational *r = (struct RRational*)mrb_obj_ptr(v);

  if (!r->p) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "uninitialized rational");
  }
  return r->p;
}
#else
#define RATIONAL_INLINE
struct RRational {
  MRB_OBJECT_HEADER;
  struct mrb_rational r;
};
#define rational_ptr(mrb, v) (&((struct RRational*)mrb_obj_ptr(v))->r)
#endif

static struct RBasic*
rational_alloc(mrb_state *mrb, struct RClass *c, struct mrb_rational **p)
{
  struct RRational *s;
  s = MRB_OBJ_ALLOC(mrb, MRB_TT_RATIONAL, c);
#ifdef RATIONAL_INLINE
  *p = &s->r;
#else
  *p = s->p = (struct mrb_rational*)mrb_malloc(mrb, sizeof(struct mrb_rational));
#endif
  return (struct RBasic*)s;
}

static mrb_value
rational_numerator(mrb_state *mrb, mrb_value self)
{
  struct mrb_rational *p = rational_ptr(mrb, self);
  return mrb_int_value(mrb, p->numerator);
}

static mrb_value
rational_denominator(mrb_state *mrb, mrb_value self)
{
  struct mrb_rational *p = rational_ptr(mrb, self);
  return mrb_int_value(mrb, p->denominator);
}

static void
rat_overflow(mrb_state *mrb)
{
  mrb_raise(mrb, E_RANGE_ERROR, "integer overflow in rational");
}

static void
rat_zerodiv(mrb_state *mrb)
{
  mrb_raise(mrb, E_ZERODIV_ERROR, "divided by 0 in rational");
}

mrb_value
mrb_rational_new(mrb_state *mrb, mrb_int numerator, mrb_int denominator)
{
  struct RClass *c = mrb_class_get_id(mrb, MRB_SYM(Rational));
  struct mrb_rational *p;
  struct RBasic *rat;

  if (denominator == 0) {
    rat_zerodiv(mrb);
  }
  if (denominator < 0) {
    if (numerator == MRB_INT_MIN || denominator == MRB_INT_MIN) {
      rat_overflow(mrb);
    }
    numerator *= -1;
    denominator *= -1;
  }
  rat = rational_alloc(mrb, c, &p);
  p->numerator = numerator;
  p->denominator = denominator;
  MRB_SET_FROZEN_FLAG(rat);
  return mrb_obj_value(rat);
}

#define rational_new(mrb,n,d) mrb_rational_new(mrb, n, d)

inline static mrb_int
i_gcd(mrb_int x, mrb_int y)
{
  mrb_uint u, v, t;
  int shift;

  if (x < 0)
    x = -x;
  if (y < 0)
    y = -y;

  if (x == 0)
    return y;
  if (y == 0)
    return x;

  u = (mrb_uint)x;
  v = (mrb_uint)y;
  for (shift = 0; ((u | v) & 1) == 0; ++shift) {
    u >>= 1;
    v >>= 1;
  }

  while ((u & 1) == 0)
    u >>= 1;

  do {
    while ((v & 1) == 0)
      v >>= 1;

    if (u > v) {
      t = v;
      v = u;
      u = t;
    }
    v = v - u;
  } while (v != 0);

  return (mrb_int)(u << shift);
}

static mrb_value
rational_new_i(mrb_state *mrb, mrb_int n, mrb_int d)
{
  mrb_int a;

  if (d == 0) {
    rat_zerodiv(mrb);
  }
  if (n == MRB_INT_MIN || d == MRB_INT_MIN) {
    rat_overflow(mrb);
  }
  a = i_gcd(n, d);
  return rational_new(mrb, n/a, d/a);
}

#ifndef MRB_NO_FLOAT

#if defined(MRB_INT32) || defined(MRB_USE_FLOAT32)
#define frexp_rat(x,exp) frexpf((float)x, exp)
#define ldexp_rat(x,exp) ldexpf((float)x, exp)
#define RAT_MANT_DIG FLT_MANT_DIG
#define RAT_INT_LIMIT 30
#define RAT_HUGE_VAL HUGE_VALF
#else
#define frexp_rat frexp
#define ldexp_rat ldexp
#define RAT_MANT_DIG DBL_MANT_DIG
#define RAT_INT_LIMIT 62
#define RAT_HUGE_VAL HUGE_VAL
#endif

static void
float_decode_internal(mrb_state *mrb, mrb_float f, mrb_float *rf, int *n)
{
  f = (mrb_float)frexp_rat(f, n);
  if (isinf(f)) rat_overflow(mrb);
  f = (mrb_float)ldexp_rat(f, RAT_MANT_DIG);
  *n -= RAT_MANT_DIG;
  *rf = f;
}

void mrb_check_num_exact(mrb_state *mrb, mrb_float num);

static mrb_value
rational_new_f(mrb_state *mrb, mrb_float f0)
{
  mrb_float f;
  int n;

  mrb_check_num_exact(mrb, f0);
  float_decode_internal(mrb, f0, &f, &n);
#if FLT_RADIX == 2
  if (n == 0)
    return rational_new(mrb, (mrb_int)f, 1);
  if (n > 0) {
    f = ldexp_rat(f, n);
    if (f == RAT_HUGE_VAL || f > (mrb_float)MRB_INT_MAX) {
      rat_overflow(mrb);
    }
    return rational_new(mrb, (mrb_uint)f, 1);
  }
  if (n < -RAT_INT_LIMIT) {
    f = ldexp_rat(f, n+RAT_INT_LIMIT);
    n = RAT_INT_LIMIT;
  }
  else {
    n = -n;
  }
  return rational_new_i(mrb, (mrb_int)f, ((mrb_int)1)<<n);
#else
  mrb_int pow = 1;
  if (n < 0) {
    n = -n;
    while (n > RAT_INT_LIMIT) {
      f /= 2;
      n--;
    }
    while (n--) {
      pow *= FLT_RADIX;
    }
    return rational_new_i(mrb, f, pow);
  }
  else {
    while (n--) {
      if (MRB_INT_MAX/FLT_RADIX < pow) {
        rat_overflow(mrb);
      }
      pow *= FLT_RADIX;
    }
    return rational_new(mrb, (mrb_int)f*pow, 1);
  }
#endif
}
#endif

static mrb_value
rational_s_new(mrb_state *mrb, mrb_value self)
{
  mrb_int numerator, denominator;

#ifdef MRB_NO_FLOAT
  mrb_get_args(mrb, "ii", &numerator, &denominator);
#else

 mrb_value numv, denomv;

  mrb_get_args(mrb, "oo", &numv, &denomv);
  if (mrb_integer_p(numv)) {
    numerator = mrb_integer(numv);

    if (mrb_integer_p(denomv)) {
      denominator = mrb_integer(denomv);
    }
    else {
      mrb_float numf = (mrb_float)numerator;
      mrb_float denomf = mrb_as_float(mrb, denomv);

      return rational_new_f(mrb, numf/denomf);
    }
  }
  else {
    mrb_float numf = mrb_as_float(mrb, numv);
    mrb_float denomf;

    if (mrb_integer_p(denomv)) {
      denomf = (mrb_float)mrb_integer(denomv);
    }
    else {
      denomf = mrb_as_float(mrb, denomv);
    }
    return rational_new_f(mrb, numf/denomf);
  }
#endif
  return rational_new(mrb, numerator, denominator);
}

#ifndef MRB_NO_FLOAT
static mrb_float
rat_float(struct mrb_rational *p)
{
  mrb_float f;

  if (p->denominator == 0.0) {
    f = INFINITY;
  }
  else {
    f = (mrb_float)p->numerator / (mrb_float)p->denominator;
  }

  return f;
}

mrb_value
mrb_rational_to_f(mrb_state *mrb, mrb_value self)
{
  struct mrb_rational *p = rational_ptr(mrb, self);
  return mrb_float_value(mrb, rat_float(p));
}
#endif

mrb_value
mrb_rational_to_i(mrb_state *mrb, mrb_value self)
{
  struct mrb_rational *p = rational_ptr(mrb, self);
  if (p->denominator == 0) {
    rat_zerodiv(mrb);
  }
  return mrb_int_value(mrb, p->numerator / p->denominator);
}

static mrb_value
rational_to_r(mrb_state *mrb, mrb_value self)
{
  return self;
}

static mrb_value
rational_negative_p(mrb_state *mrb, mrb_value self)
{
  struct mrb_rational *p = rational_ptr(mrb, self);
  if (p->numerator < 0) {
    return mrb_true_value();
  }
  return mrb_false_value();
}

static mrb_value
fix_to_r(mrb_state *mrb, mrb_value self)
{
  return rational_new(mrb, mrb_integer(self), 1);
}

static mrb_value
rational_m(mrb_state *mrb, mrb_value self)
{
#ifdef MRB_NO_FLOAT
  mrb_int n, d = 1;
  mrb_get_args(mrb, "i|i", &n, &d);
  return rational_new_i(mrb, n, d);
#else
  mrb_value a, b = mrb_fixnum_value(1);
  mrb_get_args(mrb, "o|o", &a, &b);
  if (mrb_integer_p(a) && mrb_integer_p(b)) {
    return rational_new_i(mrb, mrb_integer(a), mrb_integer(b));
  }
  else {
    mrb_float x = mrb_as_float(mrb, a);
    mrb_float y = mrb_as_float(mrb, b);
    return rational_new_f(mrb, x/y);
  }
#endif
}

static mrb_value
rational_eq(mrb_state *mrb, mrb_value x)
{
  mrb_value y = mrb_get_arg1(mrb);
  struct mrb_rational *p1 = rational_ptr(mrb, x);
  mrb_bool result;

  switch (mrb_type(y)) {
  case MRB_TT_INTEGER:
    if (p1->denominator != 1) return mrb_false_value();
    result = p1->numerator == mrb_integer(y);
    break;
#ifndef MRB_NO_FLOAT
  case MRB_TT_FLOAT:
    result = ((double)p1->numerator/p1->denominator) == mrb_float(y);
    break;
#endif
  case MRB_TT_RATIONAL:
    {
      struct mrb_rational *p2 = rational_ptr(mrb, y);
      mrb_int a, b;

      if (p1->numerator == p2->numerator && p1->denominator == p2->denominator) {
        return mrb_true_value();
      }
      if (mrb_int_mul_overflow(p1->numerator, p2->denominator, &a) ||
          mrb_int_mul_overflow(p2->numerator, p1->denominator, &b)) {
#ifdef MRB_NO_FLOAT
        rat_overflow(mrb);
#else
        result = (double)p1->numerator*p2->denominator == (double)p2->numerator*p2->denominator;
        break;
#endif
      }
      result = a == b;
      break;
    }

#ifdef MRB_USE_COMPLEX
  case MRB_TT_COMPLEX:
   {
      mrb_bool mrb_complex_eq(mrb_state *mrb, mrb_value, mrb_value);
      result = mrb_complex_eq(mrb, y, mrb_rational_to_f(mrb, x));
      break;
    }
#endif
  default:
    result = mrb_equal(mrb, y, x);
    break;
  }
  return mrb_bool_value(result);
}

#ifndef MRB_NO_FLOAT
mrb_value mrb_complex_new(mrb_state *, mrb_float, mrb_float);
#endif

static mrb_value
rational_cmp(mrb_state *mrb, mrb_value x)
{
  struct mrb_rational *p1 = rational_ptr(mrb, x);
  mrb_value y = mrb_get_arg1(mrb);

  switch(mrb_type(y)) {
  case MRB_TT_RATIONAL:
    {
      struct mrb_rational *p2 = rational_ptr(mrb, y);
      mrb_int a, b;

      if (mrb_int_mul_overflow(p1->numerator, p2->denominator, &a) ||
          mrb_int_mul_overflow(p1->denominator, p2->numerator, &b)) {
        return mrb_nil_value();
      }
      if (a > b)
        return mrb_fixnum_value(1);
      else if (a < b)
        return mrb_fixnum_value(-1);
      return mrb_fixnum_value(0);
    }
  case MRB_TT_INTEGER:
#ifndef MRB_NO_FLOAT
  case MRB_TT_FLOAT:
    {
      mrb_float a = rat_float(p1), b = mrb_as_float(mrb, y);
      if (a > b)
        return mrb_fixnum_value(1);
      else if (a < b)
        return mrb_fixnum_value(-1);
      return mrb_fixnum_value(0);
    }
#else
    {
      mrb_int a = p1->numerator, b;
      if (mrb_int_mul_overflow(p1->denominator, mrb_integer(y), &b)) {
        return mrb_nil_value();
      }
      if (a > b)
        return mrb_fixnum_value(1);
      else if (a < b)
        return mrb_fixnum_value(-1);
      return mrb_fixnum_value(0);
    }
#endif
#ifdef MRB_USE_COMPLEX
  case MRB_TT_COMPLEX:
    x = mrb_complex_new(mrb, rat_float(p1), 0);
    return mrb_funcall_id(mrb, x, MRB_OPSYM(cmp), 1, y);
#endif
  default:
    x = mrb_funcall_id(mrb, y, MRB_OPSYM(cmp), 1, x);
    if (mrb_integer_p(x)) {
      mrb_int z = mrb_integer(x);
      return mrb_fixnum_value(-z);
    }
    return mrb_nil_value();
 }
}

static mrb_value
rational_minus(mrb_state *mrb, mrb_value x)
{
  struct mrb_rational *p = rational_ptr(mrb, x);
  mrb_int n = p->numerator;
  if (n == MRB_INT_MIN) rat_overflow(mrb);
  return rational_new(mrb, -n, p->denominator);
}

static mrb_value
rational_add(mrb_state *mrb, mrb_value x)
{
  struct mrb_rational *p1 = rational_ptr(mrb, x);
  mrb_value y = mrb_get_arg1(mrb);

  switch (mrb_type(y)) {
  case MRB_TT_INTEGER:
    {
      mrb_int z = mrb_integer(y);
      if (mrb_int_mul_overflow(z, p1->denominator, &z)) rat_overflow(mrb);
      if (mrb_int_add_overflow(p1->numerator, z, &z)) rat_overflow(mrb);
      return rational_new_i(mrb, z, p1->denominator);
    }
  case MRB_TT_RATIONAL:
    {
      struct mrb_rational *p2 = rational_ptr(mrb, y);
      mrb_int a, b;

      if (mrb_int_mul_overflow(p1->numerator, p2->denominator, &a)) rat_overflow(mrb);
      if (mrb_int_mul_overflow(p2->numerator, p1->denominator, &b)) rat_overflow(mrb);
      if (mrb_int_add_overflow(a, b, &a)) rat_overflow(mrb);
      if (mrb_int_mul_overflow(p1->denominator, p2->denominator, &b)) rat_overflow(mrb);
      return rational_new_i(mrb, a, b);
    }

#ifndef MRB_NO_FLOAT
  case MRB_TT_FLOAT:
    {
      mrb_float z = p1->numerator + mrb_float(y) * p1->denominator;
      return mrb_float_value(mrb, mrb_div_float(z, (mrb_float)p1->denominator));
    }
#endif

  default:
    return mrb_funcall_id(mrb, y, MRB_OPSYM(add), 1, x);
  }
}

static mrb_value
rational_sub(mrb_state *mrb, mrb_value x)
{
  struct mrb_rational *p1 = rational_ptr(mrb, x);
  mrb_value y = mrb_get_arg1(mrb);

  switch (mrb_type(y)) {
  case MRB_TT_INTEGER:
    {
      mrb_int z = mrb_integer(y);
      if (mrb_int_mul_overflow(z, p1->denominator, &z)) rat_overflow(mrb);
      if (mrb_int_sub_overflow(p1->numerator, z, &z)) rat_overflow(mrb);
      return rational_new_i(mrb, z, p1->denominator);
    }
  case MRB_TT_RATIONAL:
    {
      struct mrb_rational *p2 = rational_ptr(mrb, y);
      mrb_int a, b;

      if (mrb_int_mul_overflow(p1->numerator, p2->denominator, &a)) rat_overflow(mrb);
      if (mrb_int_mul_overflow(p2->numerator, p1->denominator, &b)) rat_overflow(mrb);
      if (mrb_int_sub_overflow(a, b, &a)) rat_overflow(mrb);
      if (mrb_int_mul_overflow(p1->denominator, p2->denominator, &b)) rat_overflow(mrb);
      return rational_new_i(mrb, a, b);
    }

#if defined(MRB_USE_COMPLEX)
  case MRB_TT_COMPLEX:
    x = mrb_complex_new(mrb, rat_float(p1), 0);
    return mrb_funcall_id(mrb, x, MRB_OPSYM(sub), 1, y);
#endif

#ifndef MRB_NO_FLOAT
  case MRB_TT_FLOAT:
  default:
    {
      mrb_float z = p1->numerator - mrb_as_float(mrb, y) * p1->denominator;
      return mrb_float_value(mrb, mrb_div_float(z, (mrb_float)p1->denominator));
    }
#else
  default:
    mrb_raise(mrb, E_TYPE_ERROR, "non integer subtraction");
#endif
  }
}

static mrb_value
rational_mul(mrb_state *mrb, mrb_value x)
{
  struct mrb_rational *p1 = rational_ptr(mrb, x);
  mrb_value y = mrb_get_arg1(mrb);

  switch (mrb_type(y)) {
  case MRB_TT_INTEGER:
    {
      mrb_int z = mrb_integer(y);
      if (mrb_int_mul_overflow(p1->numerator, z, &z)) rat_overflow(mrb);
      return rational_new_i(mrb, z, p1->denominator);
    }
  case MRB_TT_RATIONAL:
    {
      struct mrb_rational *p2 = rational_ptr(mrb, y);
      mrb_int a, b;

      if (mrb_int_mul_overflow(p1->numerator, p2->numerator, &a)) rat_overflow(mrb);
      if (mrb_int_mul_overflow(p1->denominator, p2->denominator, &b)) rat_overflow(mrb);
      return rational_new_i(mrb, a, b);
    }

#ifndef MRB_NO_FLOAT
  case MRB_TT_FLOAT:
    {
      mrb_float z = p1->numerator * mrb_float(y);
      return mrb_float_value(mrb, mrb_div_float(z, (mrb_float)p1->denominator));
  }
#endif

  default:
    return mrb_funcall_id(mrb, y, MRB_OPSYM(mul), 1, x);
  }
}

mrb_value
mrb_rational_div(mrb_state *mrb, mrb_value x)
{
  struct mrb_rational *p1 = rational_ptr(mrb, x);
  mrb_value y = mrb_get_arg1(mrb);

  switch (mrb_type(y)) {
  case MRB_TT_INTEGER:
    {
      mrb_int z = mrb_integer(y);
      if (mrb_int_mul_overflow(p1->denominator, z, &z)) rat_overflow(mrb);
      return rational_new_i(mrb, p1->numerator, z);
    }
  case MRB_TT_RATIONAL:
    {
      struct mrb_rational *p2 = rational_ptr(mrb, y);
      mrb_int a, b;

      if (mrb_int_mul_overflow(p1->numerator, p2->denominator, &a)) rat_overflow(mrb);
      if (mrb_int_mul_overflow(p2->numerator, p1->denominator, &b)) rat_overflow(mrb);
      return rational_new_i(mrb, a, b);
    }

#if defined(MRB_USE_COMPLEX)
  case MRB_TT_COMPLEX:
    x = mrb_complex_new(mrb, rat_float(p1), 0);
    return mrb_funcall_id(mrb, x, MRB_OPSYM(div), 1, y);
#endif

  default:
#ifndef MRB_NO_FLOAT
  case MRB_TT_FLOAT:
    {
      mrb_float z = mrb_div_float((mrb_float)p1->numerator, mrb_as_float(mrb, y));
      return mrb_float_value(mrb, mrb_div_float(z, (mrb_float)p1->denominator));
    }
#else
    mrb_raise(mrb, E_TYPE_ERROR, "non integer division");
#endif
  }
}

#define rational_div mrb_rational_div
mrb_int mrb_div_int(mrb_state *, mrb_int, mrb_int);

#ifndef MRB_USE_COMPLEX
/* 15.2.8.3.4  */
/*
 * redefine Integer#/
 */
static mrb_value
rational_int_div(mrb_state *mrb, mrb_value x)
{
  mrb_value y = mrb_get_arg1(mrb);
  mrb_int a = mrb_integer(x);

  if (mrb_integer_p(y)) {
    mrb_int div = mrb_div_int(mrb, a, mrb_integer(y));
    return mrb_int_value(mrb, div);
  }
  switch (mrb_type(y)) {
  case MRB_TT_RATIONAL:
    return rational_div(mrb, rational_new(mrb, a, 1));
  default:
#ifdef MRB_NO_FLOAT
  case MRB_TT_FLOAT:
    mrb_raise(mrb, E_TYPE_ERROR, "non integer multiplication");
#else
    return mrb_float_value(mrb, mrb_div_float((mrb_float)a, mrb_as_float(mrb, y)));
#endif
  }
}

/* 15.2.9.3.19(x) */
/*
 * redefine Integer#quo
 */

static mrb_value
rational_int_quo(mrb_state *mrb, mrb_value x)
{
  mrb_value y = mrb_get_arg1(mrb);
  mrb_int a = mrb_integer(x);

  if (mrb_integer_p(y)) {
    return rational_new(mrb, a, mrb_integer(y));
  }
  switch (mrb_type(y)) {
  case MRB_TT_RATIONAL:
    x = rational_new(mrb, a, 1);
    return mrb_funcall_id(mrb, x, MRB_OPSYM(div), 1, y);
  default:
#ifdef MRB_NO_FLOAT
    mrb_raise(mrb, E_TYPE_ERROR, "non integer multiplication");
#else
    return mrb_float_value(mrb, mrb_div_float((mrb_float)a, mrb_as_float(mrb, y)));
#endif
  }
}
#endif  /* !MRB_USE_COMPLEX */

void mrb_mruby_rational_gem_init(mrb_state *mrb)
{
  struct RClass *rat;

  rat = mrb_define_class_id(mrb, MRB_SYM(Rational), mrb_class_get_id(mrb, MRB_SYM(Numeric)));
  MRB_SET_INSTANCE_TT(rat, MRB_TT_RATIONAL);
  mrb_undef_class_method(mrb, rat, "new");
  mrb_define_class_method(mrb, rat, "_new", rational_s_new, MRB_ARGS_REQ(2));
  mrb_define_method(mrb, rat, "numerator", rational_numerator, MRB_ARGS_NONE());
  mrb_define_method(mrb, rat, "denominator", rational_denominator, MRB_ARGS_NONE());
#ifndef MRB_NO_FLOAT
  mrb_define_method(mrb, rat, "to_f", mrb_rational_to_f, MRB_ARGS_NONE());
#endif
  mrb_define_method(mrb, rat, "to_i", mrb_rational_to_i, MRB_ARGS_NONE());
  mrb_define_method(mrb, rat, "to_r", rational_to_r, MRB_ARGS_NONE());
  mrb_define_method(mrb, rat, "negative?", rational_negative_p, MRB_ARGS_NONE());
  mrb_define_method(mrb, rat, "==", rational_eq, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, rat, "<=>", rational_cmp, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, rat, "-@", rational_minus, MRB_ARGS_NONE());
  mrb_define_method(mrb, rat, "+", rational_add, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, rat, "-", rational_sub, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, rat, "*", rational_mul, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, rat, "/", rational_div, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, rat, "quo", rational_div, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, mrb->integer_class, "to_r", fix_to_r, MRB_ARGS_NONE());
#ifndef MRB_USE_COMPLEX
  mrb_define_method(mrb, mrb->integer_class, "/", rational_int_div, MRB_ARGS_REQ(1)); /* override */
  mrb_define_method(mrb, mrb->integer_class, "quo", rational_int_quo, MRB_ARGS_REQ(1)); /* override */
#endif
  mrb_define_method(mrb, mrb->kernel_module, "Rational", rational_m, MRB_ARGS_ARG(1,1));
}

void
mrb_mruby_rational_gem_final(mrb_state* mrb)
{
}
