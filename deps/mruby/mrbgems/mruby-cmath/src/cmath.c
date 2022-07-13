/*
** cmath.c - Math module with complex numbers
**
** See Copyright Notice in mruby.h
*/

/*
** This `mruby-cmath` gem uses C99 _Complex features
** You need C compiler that support C99+
*/

#include <mruby.h>

#ifdef MRB_NO_FLOAT
# error CMath conflicts with 'MRB_NO_FLOAT' configuration
#endif

#include <complex.h>

mrb_value mrb_complex_new(mrb_state *mrb, mrb_float real, mrb_float imag);
void mrb_complex_get(mrb_state *mrb, mrb_value cpx, mrb_float*, mrb_float*);

static mrb_bool
cmath_get_complex(mrb_state *mrb, mrb_value c, mrb_float *r, mrb_float *i)
{
  if (mrb_integer_p(c)) {
    *r = (mrb_float)mrb_integer(c);
    *i = 0;
    return FALSE;
  }
  else if (mrb_float_p(c)) {
    *r = mrb_float(c);
    *i = 0;
    return FALSE;
  }
  else if (mrb_obj_is_kind_of(mrb, c, mrb_class_get(mrb, "Complex"))) {
    mrb_complex_get(mrb, c, r, i);
    return TRUE;
  }
  else {
    mrb_raise(mrb, E_TYPE_ERROR, "Numeric required");
    return FALSE;
  }
}

#ifdef MRB_USE_FLOAT32
#define F(x) x##f
#else
#define F(x) x
#endif

#if defined(_WIN32) && !defined(__MINGW32__)

#ifdef MRB_USE_FLOAT32
typedef _Fcomplex mrb_complex;
#define CX(r,i) _FCbuild(r,i)
#else
typedef _Dcomplex mrb_complex;
#define CX(r,i) _Cbuild(r,i)
#endif

static mrb_complex
CXDIVf(mrb_complex x, mrb_float y)
{
  return CX(creal(x)/y, cimag(x)/y);
}

static mrb_complex
CXDIVc(mrb_complex a, mrb_complex b)
{
  mrb_float ratio, den;
  mrb_float abr, abi, cr, ci;

  if ((abr = creal(b)) < 0)
    abr = - abr;
  if ((abi = cimag(b)) < 0)
    abi = - abi;
  if (abr <= abi) {
    ratio = creal(b) / cimag(b) ;
    den = cimag(a) * (1 + ratio*ratio);
    cr = (creal(a)*ratio + cimag(a)) / den;
    ci = (cimag(a)*ratio - creal(a)) / den;
  }
  else {
    ratio = cimag(b) / creal(b) ;
    den = creal(a) * (1 + ratio*ratio);
    cr = (creal(a) + cimag(a)*ratio) / den;
    ci = (cimag(a) - creal(a)*ratio) / den;
  }
  return CX(cr, ci);
}

#else

#if defined(__cplusplus) && (defined(__APPLE__) || (defined(__clang__) && (defined(__FreeBSD__) || defined(__OpenBSD__))))

#ifdef MRB_USE_FLOAT32
typedef std::complex<float> mrb_complex;
#else
typedef std::complex<double> mrb_complex;
#endif  /* MRB_USE_FLOAT32 */

#define CX(r,i) mrb_complex(r,i)
#define creal(c) c.real()
#define cimag(c) c.imag()
#define FC(n) F(n)

#else  /* cpp */

#ifdef MRB_USE_FLOAT32
typedef float _Complex mrb_complex;
#else
typedef double _Complex mrb_complex;
#endif  /*  MRB_USE_FLOAT32 */

#define CX(r,i) ((r)+(i)*_Complex_I)
#endif

#define CXDIVf(x,y) (x)/(y)
#define CXDIVc(x,y) (x)/(y)

#endif

#ifndef FC
#define FC(n) F(c ## n)
#endif

#define DEF_CMATH_METHOD(name) \
static mrb_value \
cmath_ ## name(mrb_state *mrb, mrb_value self)\
{\
  mrb_value z = mrb_get_arg1(mrb);\
  mrb_float real, imag;\
  if (cmath_get_complex(mrb, z, &real, &imag)) {\
    mrb_complex c = CX(real,imag);\
    c = FC(name)(c);\
    return mrb_complex_new(mrb, creal(c), cimag(c));\
  }\
  return mrb_float_value(mrb, F(name)(real));\
}

/* exp(z): return the exponential of z */
DEF_CMATH_METHOD(exp)

/* log(z): return the natural logarithm of z, with branch cut along the negative real axis */
static mrb_value
cmath_log(mrb_state *mrb, mrb_value self) {
  mrb_value z;
  mrb_float base;
  mrb_float real, imag;

  mrb_int n = mrb_get_args(mrb, "o|f", &z, &base);

#ifndef M_E
#define M_E F(exp)(1.0)
#endif

  if (n == 1) base = M_E;
  if (cmath_get_complex(mrb, z, &real, &imag) || real < 0.0) {
    mrb_complex c = CX(real,imag);
    c = FC(log)(c);
    if (n == 2) c = CXDIVc(c, FC(log)(CX(base,0)));
    return mrb_complex_new(mrb, creal(c), cimag(c));
  }
  if (n == 1) return mrb_float_value(mrb, F(log)(real));
  return mrb_float_value(mrb, F(log)(real)/F(log)(base));
}

/* log10(z): return the base-10 logarithm of z, with branch cut along the negative real axis */
static mrb_value
cmath_log10(mrb_state *mrb, mrb_value self) {
  mrb_value z = mrb_get_arg1(mrb);
  mrb_float real, imag;
  if (cmath_get_complex(mrb, z, &real, &imag) || real < 0.0) {
    mrb_complex c = CX(real,imag);
    c = CXDIVf(FC(log)(c),log(10));
    return mrb_complex_new(mrb, creal(c), cimag(c));
  }
  return mrb_float_value(mrb, F(log10)(real));
}

/* log2(z): return the base-2 logarithm of z, with branch cut along the negative real axis */
static mrb_value
cmath_log2(mrb_state *mrb, mrb_value self) {
  mrb_value z = mrb_get_arg1(mrb);
  mrb_float real, imag;
  if (cmath_get_complex(mrb, z, &real, &imag) || real < 0.0) {
    mrb_complex c = CX(real,imag);
    c = CXDIVf(FC(log)(c),log(2.0));
    return mrb_complex_new(mrb, creal(c), cimag(c));
  }
  return mrb_float_value(mrb, F(log2)(real));
}

/* sqrt(z): return square root of z */
static mrb_value
cmath_sqrt(mrb_state *mrb, mrb_value self) {
  mrb_value z = mrb_get_arg1(mrb);
  mrb_float real, imag;
  if (cmath_get_complex(mrb, z, &real, &imag) || real < 0.0) {
    mrb_complex c = CX(real,imag);
    c = FC(sqrt)(c);
    return mrb_complex_new(mrb, creal(c), cimag(c));
  }
  return mrb_float_value(mrb, F(sqrt)(real));
}

/* sin(z): sine function */
DEF_CMATH_METHOD(sin)
/* cos(z): cosine function */
DEF_CMATH_METHOD(cos)
/* tan(z): tangent function */
DEF_CMATH_METHOD(tan)
/* asin(z): arc sine function */
DEF_CMATH_METHOD(asin)
/* acos(z): arc cosine function */
DEF_CMATH_METHOD(acos)
/* atan(z): arg tangent function */
DEF_CMATH_METHOD(atan)
/* sinh(z): hyperbolic sine function */
DEF_CMATH_METHOD(sinh)
/* cosh(z): hyperbolic cosine function */
DEF_CMATH_METHOD(cosh)
/* tanh(z): hyperbolic tangent function */
DEF_CMATH_METHOD(tanh)
/* asinh(z): inverse hyperbolic sine function */
DEF_CMATH_METHOD(asinh)
/* acosh(z): inverse hyperbolic cosine function */
DEF_CMATH_METHOD(acosh)
/* atanh(z): inverse hyperbolic tangent function */
DEF_CMATH_METHOD(atanh)

/* ------------------------------------------------------------------------*/

void
mrb_mruby_cmath_gem_init(mrb_state* mrb)
{
  struct RClass *cmath;
  cmath = mrb_define_module(mrb, "CMath");

  mrb_include_module(mrb, cmath, mrb_module_get(mrb, "Math"));

  mrb_define_module_function(mrb, cmath, "sin", cmath_sin, MRB_ARGS_REQ(1));
  mrb_define_module_function(mrb, cmath, "cos", cmath_cos, MRB_ARGS_REQ(1));
  mrb_define_module_function(mrb, cmath, "tan", cmath_tan, MRB_ARGS_REQ(1));

  mrb_define_module_function(mrb, cmath, "asin", cmath_asin, MRB_ARGS_REQ(1));
  mrb_define_module_function(mrb, cmath, "acos", cmath_acos, MRB_ARGS_REQ(1));
  mrb_define_module_function(mrb, cmath, "atan", cmath_atan, MRB_ARGS_REQ(1));

  mrb_define_module_function(mrb, cmath, "sinh", cmath_sinh, MRB_ARGS_REQ(1));
  mrb_define_module_function(mrb, cmath, "cosh", cmath_cosh, MRB_ARGS_REQ(1));
  mrb_define_module_function(mrb, cmath, "tanh", cmath_tanh, MRB_ARGS_REQ(1));

  mrb_define_module_function(mrb, cmath, "asinh", cmath_asinh, MRB_ARGS_REQ(1));
  mrb_define_module_function(mrb, cmath, "acosh", cmath_acosh, MRB_ARGS_REQ(1));
  mrb_define_module_function(mrb, cmath, "atanh", cmath_atanh, MRB_ARGS_REQ(1));

  mrb_define_module_function(mrb, cmath, "exp", cmath_exp, MRB_ARGS_REQ(1));
  mrb_define_module_function(mrb, cmath, "log", cmath_log, MRB_ARGS_REQ(1)|MRB_ARGS_OPT(1));
  mrb_define_module_function(mrb, cmath, "log2", cmath_log2, MRB_ARGS_REQ(1));
  mrb_define_module_function(mrb, cmath, "log10", cmath_log10, MRB_ARGS_REQ(1));
  mrb_define_module_function(mrb, cmath, "sqrt", cmath_sqrt, MRB_ARGS_REQ(1));
}

void
mrb_mruby_cmath_gem_final(mrb_state* mrb)
{
}
