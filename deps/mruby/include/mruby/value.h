/*
** mruby/value.h - mruby value definitions
**
** See Copyright Notice in mruby.h
*/

#ifndef MRUBY_VALUE_H
#define MRUBY_VALUE_H

#include "common.h"

/**
 * MRuby Value definition functions and macros.
 */
MRB_BEGIN_DECL

typedef uint32_t mrb_sym;
typedef uint8_t mrb_bool;
struct mrb_state;

#if defined(MRB_INT16) && defined(MRB_INT64)
# error "You can't define MRB_INT16 and MRB_INT64 at the same time."
#endif

#if defined _MSC_VER && _MSC_VER < 1800
# define PRIo64 "llo"
# define PRId64 "lld"
# define PRIx64 "llx"
# define PRIo16 "ho"
# define PRId16 "hd"
# define PRIx16 "hx"
# define PRIo32 "o"
# define PRId32 "d"
# define PRIx32 "x"
#else
# include <inttypes.h>
#endif

#if defined(MRB_INT64)
  typedef int64_t mrb_int;
# define MRB_INT_BIT 64
# define MRB_INT_MIN (INT64_MIN>>MRB_FIXNUM_SHIFT)
# define MRB_INT_MAX (INT64_MAX>>MRB_FIXNUM_SHIFT)
# define MRB_PRIo PRIo64
# define MRB_PRId PRId64
# define MRB_PRIx PRIx64
#elif defined(MRB_INT16)
  typedef int16_t mrb_int;
# define MRB_INT_BIT 16
# define MRB_INT_MIN (INT16_MIN>>MRB_FIXNUM_SHIFT)
# define MRB_INT_MAX (INT16_MAX>>MRB_FIXNUM_SHIFT)
# define MRB_PRIo PRIo16
# define MRB_PRId PRId16
# define MRB_PRIx PRIx16
#else
  typedef int32_t mrb_int;
# define MRB_INT_BIT 32
# define MRB_INT_MIN (INT32_MIN>>MRB_FIXNUM_SHIFT)
# define MRB_INT_MAX (INT32_MAX>>MRB_FIXNUM_SHIFT)
# define MRB_PRIo PRIo32
# define MRB_PRId PRId32
# define MRB_PRIx PRIx32
#endif


MRB_API double mrb_float_read(const char*, char**);
#ifdef MRB_USE_FLOAT
  typedef float mrb_float;
#else
  typedef double mrb_float;
#endif

#if defined _MSC_VER && _MSC_VER < 1900
# ifndef __cplusplus
#  define inline __inline
# endif
# include <stdarg.h>
MRB_API int mrb_msvc_vsnprintf(char *s, size_t n, const char *format, va_list arg);
MRB_API int mrb_msvc_snprintf(char *s, size_t n, const char *format, ...);
# define vsnprintf(s, n, format, arg) mrb_msvc_vsnprintf(s, n, format, arg)
# define snprintf(s, n, format, ...) mrb_msvc_snprintf(s, n, format, __VA_ARGS__)
# if _MSC_VER < 1800
#  include <float.h>
#  define isfinite(n) _finite(n)
#  define isnan _isnan
#  define isinf(n) (!_finite(n) && !_isnan(n))
#  define signbit(n) (_copysign(1.0, (n)) < 0.0)
static const unsigned int IEEE754_INFINITY_BITS_SINGLE = 0x7F800000;
#  define INFINITY (*(float *)&IEEE754_INFINITY_BITS_SINGLE)
#  define NAN ((float)(INFINITY - INFINITY))
# endif
#endif

enum mrb_vtype {
  MRB_TT_FALSE = 0,   /*   0 */
  MRB_TT_FREE,        /*   1 */
  MRB_TT_TRUE,        /*   2 */
  MRB_TT_FIXNUM,      /*   3 */
  MRB_TT_SYMBOL,      /*   4 */
  MRB_TT_UNDEF,       /*   5 */
  MRB_TT_FLOAT,       /*   6 */
  MRB_TT_CPTR,        /*   7 */
  MRB_TT_OBJECT,      /*   8 */
  MRB_TT_CLASS,       /*   9 */
  MRB_TT_MODULE,      /*  10 */
  MRB_TT_ICLASS,      /*  11 */
  MRB_TT_SCLASS,      /*  12 */
  MRB_TT_PROC,        /*  13 */
  MRB_TT_ARRAY,       /*  14 */
  MRB_TT_HASH,        /*  15 */
  MRB_TT_STRING,      /*  16 */
  MRB_TT_RANGE,       /*  17 */
  MRB_TT_EXCEPTION,   /*  18 */
  MRB_TT_FILE,        /*  19 */
  MRB_TT_ENV,         /*  20 */
  MRB_TT_DATA,        /*  21 */
  MRB_TT_FIBER,       /*  22 */
  MRB_TT_ISTRUCT,     /*  23 */
  MRB_TT_MAXDEFINE    /*  24 */
};

#include <mruby/object.h>

#ifdef MRB_DOCUMENTATION_BLOCK

/**
 * @abstract
 * MRuby value boxing.
 *
 * Actual implementation depends on configured boxing type.
 *
 * @see mruby/boxing_no.h Default boxing representation
 * @see mruby/boxing_word.h Word representation
 * @see mruby/boxing_nan.h Boxed double representation
 */
typedef void mrb_value;

#endif

#if defined(MRB_NAN_BOXING)
#include "boxing_nan.h"
#elif defined(MRB_WORD_BOXING)
#include "boxing_word.h"
#else
#include "boxing_no.h"
#endif

#ifndef mrb_fixnum_p
#define mrb_fixnum_p(o) (mrb_type(o) == MRB_TT_FIXNUM)
#endif
#ifndef mrb_undef_p
#define mrb_undef_p(o) (mrb_type(o) == MRB_TT_UNDEF)
#endif
#ifndef mrb_nil_p
#define mrb_nil_p(o)  (mrb_type(o) == MRB_TT_FALSE && !mrb_fixnum(o))
#endif
#ifndef mrb_bool
#define mrb_bool(o)   (mrb_type(o) != MRB_TT_FALSE)
#endif
#define mrb_float_p(o) (mrb_type(o) == MRB_TT_FLOAT)
#define mrb_symbol_p(o) (mrb_type(o) == MRB_TT_SYMBOL)
#define mrb_array_p(o) (mrb_type(o) == MRB_TT_ARRAY)
#define mrb_string_p(o) (mrb_type(o) == MRB_TT_STRING)
#define mrb_hash_p(o) (mrb_type(o) == MRB_TT_HASH)
#define mrb_cptr_p(o) (mrb_type(o) == MRB_TT_CPTR)
#define mrb_exception_p(o) (mrb_type(o) == MRB_TT_EXCEPTION)
#define mrb_test(o)   mrb_bool(o)
MRB_API mrb_bool mrb_regexp_p(struct mrb_state*, mrb_value);

/*
 * Returns a float in Ruby.
 */
MRB_INLINE mrb_value mrb_float_value(struct mrb_state *mrb, mrb_float f)
{
  mrb_value v;
  (void) mrb;
  SET_FLOAT_VALUE(mrb, v, f);
  return v;
}

static inline mrb_value
mrb_cptr_value(struct mrb_state *mrb, void *p)
{
  mrb_value v;
  (void) mrb;
  SET_CPTR_VALUE(mrb,v,p);
  return v;
}

/*
 * Returns a fixnum in Ruby.
 */
MRB_INLINE mrb_value mrb_fixnum_value(mrb_int i)
{
  mrb_value v;
  SET_INT_VALUE(v, i);
  return v;
}

static inline mrb_value
mrb_symbol_value(mrb_sym i)
{
  mrb_value v;
  SET_SYM_VALUE(v, i);
  return v;
}

static inline mrb_value
mrb_obj_value(void *p)
{
  mrb_value v;
  SET_OBJ_VALUE(v, (struct RBasic*)p);
  mrb_assert(p == mrb_ptr(v));
  mrb_assert(((struct RBasic*)p)->tt == mrb_type(v));
  return v;
}


/*
 * Get a nil mrb_value object.
 *
 * @return
 *      nil mrb_value object reference.
 */
MRB_INLINE mrb_value mrb_nil_value(void)
{
  mrb_value v;
  SET_NIL_VALUE(v);
  return v;
}

/*
 * Returns false in Ruby.
 */
MRB_INLINE mrb_value mrb_false_value(void)
{
  mrb_value v;
  SET_FALSE_VALUE(v);
  return v;
}

/*
 * Returns true in Ruby.
 */
MRB_INLINE mrb_value mrb_true_value(void)
{
  mrb_value v;
  SET_TRUE_VALUE(v);
  return v;
}

static inline mrb_value
mrb_bool_value(mrb_bool boolean)
{
  mrb_value v;
  SET_BOOL_VALUE(v, boolean);
  return v;
}

static inline mrb_value
mrb_undef_value(void)
{
  mrb_value v;
  SET_UNDEF_VALUE(v);
  return v;
}

#ifdef MRB_USE_ETEXT_EDATA
extern char _etext[];
#ifdef MRB_NO_INIT_ARRAY_START
extern char _edata[];

static inline mrb_bool
mrb_ro_data_p(const char *p)
{
  return _etext < p && p < _edata;
}
#else
extern char __init_array_start[];

static inline mrb_bool
mrb_ro_data_p(const char *p)
{
  return _etext < p && p < (char*)&__init_array_start;
}
#endif
#else
# define mrb_ro_data_p(p) FALSE
#endif

MRB_END_DECL

#endif  /* MRUBY_VALUE_H */
