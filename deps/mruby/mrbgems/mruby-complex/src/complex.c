#include <mruby.h>
#include <mruby/class.h>
#include <mruby/numeric.h>
#include <mruby/presym.h>

#ifdef MRB_NO_FLOAT
# error Complex conflicts with 'MRB_NO_FLOAT' configuration
#endif

#ifdef MRB_USE_FLOAT32
#define F(x) x##f
#else
#define F(x) x
#endif

struct mrb_complex {
  mrb_float real;
  mrb_float imaginary;
};

#if defined(MRB_32BIT) && !defined(MRB_USE_FLOAT32)

struct RComplex {
  MRB_OBJECT_HEADER;
  struct mrb_complex *p;
};

static struct mrb_complex*
complex_ptr(mrb_state *mrb, mrb_value v)
{
  struct RComplex *r = (struct RComplex*)mrb_obj_ptr(v);

  if (!r->p) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "uninitialized complex");
  }
  return r->p;
}

#else
#define COMPLEX_INLINE
struct RComplex {
  MRB_OBJECT_HEADER;
  struct mrb_complex r;
};
#define complex_ptr(mrb, v) (&((struct RComplex*)mrb_obj_ptr(v))->r)
#endif

static struct RBasic*
complex_alloc(mrb_state *mrb, struct RClass *c, struct mrb_complex **p)
{
  struct RComplex *s;
  s = MRB_OBJ_ALLOC(mrb, MRB_TT_COMPLEX, c);
#ifdef COMPLEX_INLINE
  *p = &s->r;
#else
  *p = s->p = (struct mrb_complex*)mrb_malloc(mrb, sizeof(struct mrb_complex));
#endif
  return (struct RBasic*)s;
}

void
mrb_complex_get(mrb_state *mrb, mrb_value cpx, mrb_float *r, mrb_float *i)
{
  struct mrb_complex *c = complex_ptr(mrb, cpx);

  *r = c->real;
  *i = c->imaginary;
}

mrb_value
mrb_complex_new(mrb_state *mrb, mrb_float real, mrb_float imaginary)
{
  struct RClass *c = mrb_class_get_id(mrb, MRB_SYM(Complex));
  struct mrb_complex *p;
  struct RBasic *comp = complex_alloc(mrb, c, &p);
  p->real = real;
  p->imaginary = imaginary;
  MRB_SET_FROZEN_FLAG(comp);

  return mrb_obj_value(comp);
}

#define complex_new(mrb, real, imag) mrb_complex_new(mrb, real, imag)

static mrb_value
complex_real(mrb_state *mrb, mrb_value self)
{
  struct mrb_complex *p = complex_ptr(mrb, self);
  return mrb_float_value(mrb, p->real);
}

static mrb_value
complex_imaginary(mrb_state *mrb, mrb_value self)
{
  struct mrb_complex *p = complex_ptr(mrb, self);
  return mrb_float_value(mrb, p->imaginary);
}

static mrb_value
complex_s_rect(mrb_state *mrb, mrb_value self)
{
  mrb_float real, imaginary = 0.0;

  mrb_get_args(mrb, "f|f", &real, &imaginary);
  return complex_new(mrb, real, imaginary);
}

mrb_value
mrb_complex_to_f(mrb_state *mrb, mrb_value self)
{
  struct mrb_complex *p = complex_ptr(mrb, self);

  if (p->imaginary != 0) {
    mrb_raisef(mrb, E_RANGE_ERROR, "can't convert %v into Float", self);
  }

  return mrb_float_value(mrb, p->real);
}

mrb_value
mrb_complex_to_i(mrb_state *mrb, mrb_value self)
{
  struct mrb_complex *p = complex_ptr(mrb, self);

  if (p->imaginary != 0) {
    mrb_raisef(mrb, E_RANGE_ERROR, "can't convert %v into Integer", self);
  }
  return mrb_int_value(mrb, (mrb_int)p->real);
}

static mrb_value
complex_to_c(mrb_state *mrb, mrb_value self)
{
  return self;
}

mrb_bool
mrb_complex_eq(mrb_state *mrb, mrb_value x, mrb_value y)
{
  struct mrb_complex *p1 = complex_ptr(mrb, x);

  switch (mrb_type(y)) {
  case MRB_TT_COMPLEX:
    {
      struct mrb_complex *p2 = complex_ptr(mrb, y);

      if (p1->real == p2->real && p1->imaginary == p2->imaginary) {
        return TRUE;
      }
      return FALSE;
    }
  case MRB_TT_INTEGER:
    if (p1->imaginary != 0) return FALSE;
    return p1->real == mrb_integer(y);
  case MRB_TT_FLOAT:
    if (p1->imaginary != 0) return FALSE;
    return p1->real == mrb_float(y);

  default:
    return mrb_equal(mrb, y, x);
  }
}

static mrb_value
complex_eq(mrb_state *mrb, mrb_value x)
{
  mrb_value y = mrb_get_arg1(mrb);
  return mrb_bool_value(mrb_complex_eq(mrb, x, y));
}

static mrb_value
complex_add(mrb_state *mrb, mrb_value x)
{
  mrb_value y = mrb_get_arg1(mrb);
  struct mrb_complex *p1 = complex_ptr(mrb, x);

  switch (mrb_type(y)) {
  case MRB_TT_COMPLEX:
    {
      struct mrb_complex *p2 = complex_ptr(mrb, y);
      return mrb_complex_new(mrb, p1->real+p2->real, p1->imaginary+p2->imaginary);
    }

  default:
    {
      mrb_float z = mrb_as_float(mrb, y);
      return mrb_complex_new(mrb, p1->real+z, p1->imaginary);
    }
  }
}

static mrb_value
complex_sub(mrb_state *mrb, mrb_value x)
{
  mrb_value y = mrb_get_arg1(mrb);
  struct mrb_complex *p1 = complex_ptr(mrb, x);

  switch (mrb_type(y)) {
  case MRB_TT_COMPLEX:
    {
      struct mrb_complex *p2 = complex_ptr(mrb, y);
      return mrb_complex_new(mrb, p1->real-p2->real, p1->imaginary-p2->imaginary);
    }

  default:
    {
      mrb_float z = mrb_as_float(mrb, y);
      return mrb_complex_new(mrb, p1->real-z, p1->imaginary);
    }
  }
}

static mrb_value
complex_mul(mrb_state *mrb, mrb_value x)
{
  mrb_value y = mrb_get_arg1(mrb);
  struct mrb_complex *p1 = complex_ptr(mrb, x);

  switch (mrb_type(y)) {
  case MRB_TT_COMPLEX:
    {
      struct mrb_complex *p2 = complex_ptr(mrb, y);
      return mrb_complex_new(mrb, p1->real*p2->real - p1->imaginary*p2->imaginary,
                                  p1->real*p2->imaginary + p2->real*p1->imaginary);
    }

  default:
    {
      mrb_float z = mrb_as_float(mrb, y);
      return mrb_complex_new(mrb, p1->real*z, p1->imaginary*z);
    }
  }
}

/* Arithmetic on (significand, exponent) pairs avoids premature overflow in
   complex division */
struct float_pair {
  mrb_float s;
  int x;
};

static void
add_pair(struct float_pair *s, struct float_pair const *a,
         struct float_pair const *b)
{
  if (b->s == 0.0F) {
    *s = *a;
  } else if (a->s == 0.0F) {
    *s = *b;
  } else if (a->x >= b->x) {
    s->s = a->s + F(ldexp)(b->s, b->x - a->x);
    s->x = a->x;
  } else {
    s->s = F(ldexp)(a->s, a->x - b->x) + b->s;
    s->x = b->x;
  }
}

static void
mul_pair(struct float_pair *p, struct float_pair const *a,
         struct float_pair const *b)
{
  p->s = a->s * b->s;
  p->x = a->x + b->x;
}

static void
div_pair(struct float_pair *q, struct float_pair const *a,
         struct float_pair const *b)
{
  q->s = mrb_div_float(a->s, b->s);
  q->x = a->x - b->x;
}

static mrb_value
complex_div(mrb_state *mrb, mrb_value self)
{
  struct mrb_complex *a, *b;
  mrb_value rhs = mrb_get_arg1(mrb);

  a = complex_ptr(mrb, self);
  if (mrb_type(rhs) != MRB_TT_COMPLEX) {
    mrb_float f = mrb_as_float(mrb, rhs);
    return complex_new(mrb, mrb_div_float(a->real, f), mrb_div_float(a->imaginary, f));
  }

  struct float_pair ar, ai, br, bi;
  struct float_pair br2, bi2;
  struct float_pair div;
  struct float_pair ar_br, ai_bi;
  struct float_pair ai_br, ar_bi;
  struct float_pair zr, zi;

  b = complex_ptr(mrb, rhs);

  /* Split floating-point components into significand and exponent */
  ar.s = F(frexp)(a->real, &ar.x);
  ai.s = F(frexp)(a->imaginary, &ai.x);
  br.s = F(frexp)(b->real, &br.x);
  bi.s = F(frexp)(b->imaginary, &bi.x);

  /* Perform arithmetic on (significand, exponent) pairs to produce
     the result: */

  /* the divisor */
  mul_pair(&br2, &br, &br);
  mul_pair(&bi2, &bi, &bi);
  add_pair(&div, &br2, &bi2);

  /* real component */
  mul_pair(&ar_br, &ar, &br);
  mul_pair(&ai_bi, &ai, &bi);
  add_pair(&zr, &ar_br, &ai_bi);
  div_pair(&zr, &zr, &div);

  /* imaginary component */
  mul_pair(&ai_br, &ai, &br);
  mul_pair(&ar_bi, &ar, &bi);
  ar_bi.s = -ar_bi.s;
  add_pair(&zi, &ai_br, &ar_bi);
  div_pair(&zi, &zi, &div);

  /* assemble the result */
  return complex_new(mrb, F(ldexp)(zr.s, zr.x), F(ldexp)(zi.s, zi.x));
}

mrb_int mrb_div_int(mrb_state *mrb, mrb_int x, mrb_int y);
mrb_value mrb_rational_new(mrb_state *mrb, mrb_int n, mrb_int d);
mrb_value mrb_rational_div(mrb_state *mrb, mrb_value x);

/* 15.2.8.3.4  */
/*
 * redefine Integer#/
 */
static mrb_value
cpx_int_div(mrb_state *mrb, mrb_value x)
{
  mrb_value y = mrb_get_arg1(mrb);
  mrb_int a = mrb_integer(x);

  if (mrb_integer_p(y)) {
    mrb_int div = mrb_div_int(mrb, a, mrb_integer(y));
    return mrb_int_value(mrb, div);
  }
  switch (mrb_type(y)) {
#ifdef MRB_USE_RATIONAL
  case MRB_TT_RATIONAL:
    return mrb_rational_div(mrb, mrb_rational_new(mrb, a, 1));
#endif
  case MRB_TT_COMPLEX:
    x = complex_new(mrb, (mrb_float)a, 0);
    return complex_div(mrb, x);
  default:
    return mrb_float_value(mrb, mrb_div_float((mrb_float)a, mrb_as_float(mrb, y)));
  }
}

/* 15.2.9.3.19(x) */
/*
 * redefine Integer#quo
 */

static mrb_value
cpx_int_quo(mrb_state *mrb, mrb_value x)
{
  mrb_value y = mrb_get_arg1(mrb);
  mrb_int a = mrb_integer(x);

  switch (mrb_type(y)) {
#ifdef MRB_USE_RATIONAL
  case MRB_TT_RATIONAL:
    x = mrb_rational_new(mrb, a, 1);
    return mrb_funcall_id(mrb, x, MRB_OPSYM(div), 1, y);
#endif
  case MRB_TT_COMPLEX:
    x = complex_new(mrb, (mrb_float)a, 0);
    return complex_div(mrb, x);
  default:
    return mrb_float_value(mrb, mrb_div_float((mrb_float)a, mrb_as_float(mrb, y)));
  }
}

static mrb_value
cpx_flo_div(mrb_state *mrb, mrb_value x)
{
  mrb_float a = mrb_float(x);
  mrb_value y = mrb_get_arg1(mrb);

  switch(mrb_type(y)) {
  case MRB_TT_COMPLEX:
    return complex_div(mrb, complex_new(mrb, a, 0));
  case MRB_TT_FLOAT:
    a = mrb_div_float(a, mrb_float(y));
    return mrb_float_value(mrb, a);
  default:
    a = mrb_div_float(a, mrb_as_float(mrb, y));
    return mrb_float_value(mrb, a);
  }
}

void mrb_mruby_complex_gem_init(mrb_state *mrb)
{
  struct RClass *comp;

#ifdef COMPLEX_INLINE
  mrb_assert(sizeof(struct mrb_complex) < sizeof(void*)*3);
#endif

  comp = mrb_define_class_id(mrb, MRB_SYM(Complex), mrb_class_get_id(mrb, MRB_SYM(Numeric)));
  MRB_SET_INSTANCE_TT(comp, MRB_TT_COMPLEX);

  mrb_undef_class_method(mrb, comp, "new");
  mrb_define_class_method(mrb, comp, "rectangular", complex_s_rect, MRB_ARGS_REQ(1)|MRB_ARGS_OPT(1));
  mrb_define_class_method(mrb, comp, "rect", complex_s_rect, MRB_ARGS_REQ(1)|MRB_ARGS_OPT(1));
  mrb_define_method(mrb, mrb->kernel_module, "Complex", complex_s_rect, MRB_ARGS_REQ(1)|MRB_ARGS_OPT(1));
  mrb_define_method(mrb, comp, "real", complex_real, MRB_ARGS_NONE());
  mrb_define_method(mrb, comp, "imaginary", complex_imaginary, MRB_ARGS_NONE());
  mrb_define_method(mrb, comp, "to_f", mrb_complex_to_f, MRB_ARGS_NONE());
  mrb_define_method(mrb, comp, "to_i", mrb_complex_to_i, MRB_ARGS_NONE());
  mrb_define_method(mrb, comp, "to_c", complex_to_c, MRB_ARGS_NONE());
  mrb_define_method(mrb, comp, "+", complex_add, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, comp, "-", complex_sub, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, comp, "*", complex_mul, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, comp, "/", complex_div, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, comp, "quo", complex_div, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, comp, "==", complex_eq, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, mrb->integer_class, "/", cpx_int_div, MRB_ARGS_REQ(1)); /* override */
  mrb_define_method(mrb, mrb->integer_class, "quo", cpx_int_quo, MRB_ARGS_REQ(1)); /* override */
  mrb_define_method(mrb, mrb->float_class, "/", cpx_flo_div, MRB_ARGS_REQ(1)); /* override */
  mrb_define_method(mrb, mrb->float_class, "quo", cpx_flo_div, MRB_ARGS_REQ(1)); /* override */
}

void
mrb_mruby_complex_gem_final(mrb_state* mrb)
{
}
