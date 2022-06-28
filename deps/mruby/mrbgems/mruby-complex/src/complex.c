#include <mruby.h>
#include <mruby/class.h>
#include <mruby/numeric.h>
#include <math.h>

#ifdef MRB_WITHOUT_FLOAT
# error Complex conflicts 'MRB_WITHOUT_FLOAT' configuration in your 'build_config.rb'
#endif

struct mrb_complex {
  mrb_float real;
  mrb_float imaginary;
};

#ifdef MRB_USE_FLOAT
#define F(x) x##f
#else
#define F(x) x
#endif

#if defined(MRB_64BIT) || defined(MRB_USE_FLOAT)

#define COMPLEX_USE_ISTRUCT
/* use TT_ISTRUCT */
#include <mruby/istruct.h>

#define complex_ptr(mrb, v) (struct mrb_complex*)mrb_istruct_ptr(v)

static struct RBasic*
complex_alloc(mrb_state *mrb, struct RClass *c, struct mrb_complex **p)
{
  struct RIStruct *s;

  s = (struct RIStruct*)mrb_obj_alloc(mrb, MRB_TT_ISTRUCT, c);
  *p = (struct mrb_complex*)s->inline_data;

  return (struct RBasic*)s;
}

#else
/* use TT_DATA */
#include <mruby/data.h>

static const struct mrb_data_type mrb_complex_type = {"Complex", mrb_free};

static struct RBasic*
complex_alloc(mrb_state *mrb, struct RClass *c, struct mrb_complex **p)
{
  struct RData *d;

  Data_Make_Struct(mrb, c, struct mrb_complex, &mrb_complex_type, *p, d);

  return (struct RBasic*)d;
}

static struct mrb_complex*
complex_ptr(mrb_state *mrb, mrb_value v)
{
  struct mrb_complex *p;

  p = DATA_GET_PTR(mrb, v, &mrb_complex_type, struct mrb_complex);
  if (!p) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "uninitialized complex");
  }
  return p;
}
#endif

static mrb_value
complex_new(mrb_state *mrb, mrb_float real, mrb_float imaginary)
{
  struct RClass *c = mrb_class_get(mrb, "Complex");
  struct mrb_complex *p;
  struct RBasic *comp = complex_alloc(mrb, c, &p);
  p->real = real;
  p->imaginary = imaginary;
  MRB_SET_FROZEN_FLAG(comp);

  return mrb_obj_value(comp);
}

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

static mrb_value
complex_to_f(mrb_state *mrb, mrb_value self)
{
  struct mrb_complex *p = complex_ptr(mrb, self);

  if (p->imaginary != 0) {
    mrb_raisef(mrb, E_RANGE_ERROR, "can't convert %v into Float", self);
  }

  return mrb_float_value(mrb, p->real);
}

static mrb_value
complex_to_i(mrb_state *mrb, mrb_value self)
{
  struct mrb_complex *p = complex_ptr(mrb, self);

  if (p->imaginary != 0) {
    mrb_raisef(mrb, E_RANGE_ERROR, "can't convert %v into Float", self);
  }
  return mrb_int_value(mrb, p->real);
}

static mrb_value
complex_to_c(mrb_state *mrb, mrb_value self)
{
  return self;
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
  q->s = a->s / b->s;
  q->x = a->x - b->x;
}

static mrb_value
complex_div(mrb_state *mrb, mrb_value self)
{
  mrb_value rhs = mrb_get_arg1(mrb);
  struct mrb_complex *a, *b;
  struct float_pair ar, ai, br, bi;
  struct float_pair br2, bi2;
  struct float_pair div;
  struct float_pair ar_br, ai_bi;
  struct float_pair ai_br, ar_bi;
  struct float_pair zr, zi;

  a = complex_ptr(mrb, self);
  b = complex_ptr(mrb, rhs);

  /* Split floating point components into significand and exponent */
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

void mrb_mruby_complex_gem_init(mrb_state *mrb)
{
  struct RClass *comp;

#ifdef COMPLEX_USE_ISTRUCT
  mrb_assert(sizeof(struct mrb_complex) < ISTRUCT_DATA_SIZE);
#endif
  comp = mrb_define_class(mrb, "Complex", mrb_class_get(mrb, "Numeric"));
#ifdef COMPLEX_USE_ISTRUCT
  MRB_SET_INSTANCE_TT(comp, MRB_TT_ISTRUCT);
#else
  MRB_SET_INSTANCE_TT(comp, MRB_TT_DATA);
#endif
  mrb_undef_class_method(mrb, comp, "new");
  mrb_define_class_method(mrb, comp, "rectangular", complex_s_rect, MRB_ARGS_REQ(1)|MRB_ARGS_OPT(1));
  mrb_define_class_method(mrb, comp, "rect", complex_s_rect, MRB_ARGS_REQ(1)|MRB_ARGS_OPT(1));
  mrb_define_method(mrb, mrb->kernel_module, "Complex", complex_s_rect, MRB_ARGS_REQ(1)|MRB_ARGS_OPT(1));
  mrb_define_method(mrb, comp, "real", complex_real, MRB_ARGS_NONE());
  mrb_define_method(mrb, comp, "imaginary", complex_imaginary, MRB_ARGS_NONE());
  mrb_define_method(mrb, comp, "to_f", complex_to_f, MRB_ARGS_NONE());
  mrb_define_method(mrb, comp, "to_i", complex_to_i, MRB_ARGS_NONE());
  mrb_define_method(mrb, comp, "to_c", complex_to_c, MRB_ARGS_NONE());
  mrb_define_method(mrb, comp, "__div__", complex_div, MRB_ARGS_REQ(1));
}

void
mrb_mruby_complex_gem_final(mrb_state* mrb)
{
}
