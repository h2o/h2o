/**
** @file mruby/value.h - mruby value definitions
**
** See Copyright Notice in mruby.h
*/

#ifndef MRUBY_VALUE_H
#define MRUBY_VALUE_H

#include "common.h"

/*
 * MRuby Value definition functions and macros.
 */
MRB_BEGIN_DECL

/**
 * mruby Symbol.
 * @class mrb_sym
 *
 * You can create an mrb_sym by simply using mrb_str_intern() or mrb_intern_cstr()
 */
typedef uint32_t mrb_sym;

/**
 * mruby Boolean.
 * @class mrb_bool
 *
 *
 * Used internally to represent boolean. Can be TRUE or FALSE.
 * Not to be confused with Ruby's boolean classes, which can be
 * obtained using mrb_false_value() and mrb_true_value()
 */
typedef uint8_t mrb_bool;
struct mrb_state;

#if defined _MSC_VER && _MSC_VER < 1800
# define PRIo64 "llo"
# define PRId64 "lld"
# define PRIu64 "llu"
# define PRIx64 "llx"
# define PRIo16 "ho"
# define PRId16 "hd"
# define PRIu16 "hu"
# define PRIx16 "hx"
# define PRIo32 "o"
# define PRId32 "d"
# define PRIu32 "u"
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
#else
  typedef int32_t mrb_int;
# define MRB_INT_BIT 32
# define MRB_INT_MIN (INT32_MIN>>MRB_FIXNUM_SHIFT)
# define MRB_INT_MAX (INT32_MAX>>MRB_FIXNUM_SHIFT)
# define MRB_PRIo PRIo32
# define MRB_PRId PRId32
# define MRB_PRIx PRIx32
#endif

#ifdef MRB_ENDIAN_BIG
# define MRB_ENDIAN_LOHI(a,b) a b
#else
# define MRB_ENDIAN_LOHI(a,b) b a
#endif

#ifndef MRB_WITHOUT_FLOAT
MRB_API double mrb_float_read(const char*, char**);
#ifdef MRB_USE_FLOAT
  typedef float mrb_float;
#else
  typedef double mrb_float;
#endif
#endif

#if defined _MSC_VER && _MSC_VER < 1900
# include <stdarg.h>
MRB_API int mrb_msvc_vsnprintf(char *s, size_t n, const char *format, va_list arg);
MRB_API int mrb_msvc_snprintf(char *s, size_t n, const char *format, ...);
# define vsnprintf(s, n, format, arg) mrb_msvc_vsnprintf(s, n, format, arg)
# define snprintf(s, n, format, ...) mrb_msvc_snprintf(s, n, format, __VA_ARGS__)
# if _MSC_VER < 1800 && !defined MRB_WITHOUT_FLOAT
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
  MRB_TT_FALSE = 0,
  MRB_TT_TRUE,
  MRB_TT_FLOAT,
  MRB_TT_FIXNUM,
  MRB_TT_SYMBOL,
  MRB_TT_UNDEF,
  MRB_TT_CPTR,
  MRB_TT_FREE,
  MRB_TT_OBJECT,
  MRB_TT_CLASS,
  MRB_TT_MODULE,
  MRB_TT_ICLASS,
  MRB_TT_SCLASS,
  MRB_TT_PROC,
  MRB_TT_ARRAY,
  MRB_TT_HASH,
  MRB_TT_STRING,
  MRB_TT_RANGE,
  MRB_TT_EXCEPTION,
  MRB_TT_ENV,
  MRB_TT_DATA,
  MRB_TT_FIBER,
  MRB_TT_ISTRUCT,
  MRB_TT_BREAK,
  MRB_TT_MAXDEFINE
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

#if defined(MRB_WORD_BOXING) || (defined(MRB_NAN_BOXING) && defined(MRB_64BIT))
struct RCptr {
  MRB_OBJECT_HEADER;
  void *p;
};
#endif

#if defined(MRB_NAN_BOXING)
#include "boxing_nan.h"
#elif defined(MRB_WORD_BOXING)
#include "boxing_word.h"
#else
#include "boxing_no.h"
#endif

#define MRB_SYMBOL_BIT (sizeof(mrb_sym) * CHAR_BIT - MRB_SYMBOL_SHIFT)
#define MRB_SYMBOL_MAX (UINT32_MAX >> MRB_SYMBOL_SHIFT)

#if INTPTR_MAX < MRB_INT_MAX
  typedef intptr_t mrb_ssize;
# define MRB_SSIZE_MAX (INTPTR_MAX>>MRB_FIXNUM_SHIFT)
#else
  typedef mrb_int mrb_ssize;
# define MRB_SSIZE_MAX MRB_INT_MAX
#endif

#ifndef mrb_immediate_p
#define mrb_immediate_p(o) (mrb_type(o) < MRB_TT_FREE)
#endif
#ifndef mrb_fixnum_p
#define mrb_fixnum_p(o) (mrb_type(o) == MRB_TT_FIXNUM)
#endif
#ifndef mrb_symbol_p
#define mrb_symbol_p(o) (mrb_type(o) == MRB_TT_SYMBOL)
#endif
#ifndef mrb_undef_p
#define mrb_undef_p(o) (mrb_type(o) == MRB_TT_UNDEF)
#endif
#ifndef mrb_nil_p
#define mrb_nil_p(o)  (mrb_type(o) == MRB_TT_FALSE && !mrb_fixnum(o))
#endif
#ifndef mrb_false_p
#define mrb_false_p(o) (mrb_type(o) == MRB_TT_FALSE && !!mrb_fixnum(o))
#endif
#ifndef mrb_true_p
#define mrb_true_p(o)  (mrb_type(o) == MRB_TT_TRUE)
#endif
#ifndef MRB_WITHOUT_FLOAT
#ifndef mrb_float_p
#define mrb_float_p(o) (mrb_type(o) == MRB_TT_FLOAT)
#endif
#endif
#ifndef mrb_array_p
#define mrb_array_p(o) (mrb_type(o) == MRB_TT_ARRAY)
#endif
#ifndef mrb_string_p
#define mrb_string_p(o) (mrb_type(o) == MRB_TT_STRING)
#endif
#ifndef mrb_hash_p
#define mrb_hash_p(o) (mrb_type(o) == MRB_TT_HASH)
#endif
#ifndef mrb_cptr_p
#define mrb_cptr_p(o) (mrb_type(o) == MRB_TT_CPTR)
#endif
#ifndef mrb_exception_p
#define mrb_exception_p(o) (mrb_type(o) == MRB_TT_EXCEPTION)
#endif
#ifndef mrb_free_p
#define mrb_free_p(o) (mrb_type(o) == MRB_TT_FREE)
#endif
#ifndef mrb_object_p
#define mrb_object_p(o) (mrb_type(o) == MRB_TT_OBJECT)
#endif
#ifndef mrb_class_p
#define mrb_class_p(o) (mrb_type(o) == MRB_TT_CLASS)
#endif
#ifndef mrb_module_p
#define mrb_module_p(o) (mrb_type(o) == MRB_TT_MODULE)
#endif
#ifndef mrb_iclass_p
#define mrb_iclass_p(o) (mrb_type(o) == MRB_TT_ICLASS)
#endif
#ifndef mrb_sclass_p
#define mrb_sclass_p(o) (mrb_type(o) == MRB_TT_SCLASS)
#endif
#ifndef mrb_proc_p
#define mrb_proc_p(o) (mrb_type(o) == MRB_TT_PROC)
#endif
#ifndef mrb_range_p
#define mrb_range_p(o) (mrb_type(o) == MRB_TT_RANGE)
#endif
#ifndef mrb_env_p
#define mrb_env_p(o) (mrb_type(o) == MRB_TT_ENV)
#endif
#ifndef mrb_data_p
#define mrb_data_p(o) (mrb_type(o) == MRB_TT_DATA)
#endif
#ifndef mrb_fiber_p
#define mrb_fiber_p(o) (mrb_type(o) == MRB_TT_FIBER)
#endif
#ifndef mrb_istruct_p
#define mrb_istruct_p(o) (mrb_type(o) == MRB_TT_ISTRUCT)
#endif
#ifndef mrb_break_p
#define mrb_break_p(o) (mrb_type(o) == MRB_TT_BREAK)
#endif
#ifndef mrb_bool
#define mrb_bool(o)   (mrb_type(o) != MRB_TT_FALSE)
#endif
#define mrb_test(o)   mrb_bool(o)

/**
 * Returns a float in Ruby.
 *
 * Takes a float and boxes it into an mrb_value
 */
#ifndef MRB_WITHOUT_FLOAT
MRB_INLINE mrb_value mrb_float_value(struct mrb_state *mrb, mrb_float f)
{
  mrb_value v;
  (void) mrb;
  SET_FLOAT_VALUE(mrb, v, f);
  return v;
}
#endif

MRB_INLINE mrb_value
mrb_cptr_value(struct mrb_state *mrb, void *p)
{
  mrb_value v;
  (void) mrb;
  SET_CPTR_VALUE(mrb,v,p);
  return v;
}

/**
 * Returns a fixnum in Ruby.
 *
 * Takes an integer and boxes it into an mrb_value
 */
MRB_INLINE mrb_value mrb_fixnum_value(mrb_int i)
{
  mrb_value v;
  SET_INT_VALUE(v, i);
  return v;
}

MRB_INLINE mrb_value
mrb_symbol_value(mrb_sym i)
{
  mrb_value v;
  SET_SYM_VALUE(v, i);
  return v;
}

MRB_INLINE mrb_value
mrb_obj_value(void *p)
{
  mrb_value v;
  SET_OBJ_VALUE(v, (struct RBasic*)p);
  mrb_assert(p == mrb_ptr(v));
  mrb_assert(((struct RBasic*)p)->tt == mrb_type(v));
  return v;
}

/**
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

/**
 * Returns false in Ruby.
 */
MRB_INLINE mrb_value mrb_false_value(void)
{
  mrb_value v;
  SET_FALSE_VALUE(v);
  return v;
}

/**
 * Returns true in Ruby.
 */
MRB_INLINE mrb_value mrb_true_value(void)
{
  mrb_value v;
  SET_TRUE_VALUE(v);
  return v;
}

MRB_INLINE mrb_value
mrb_bool_value(mrb_bool boolean)
{
  mrb_value v;
  SET_BOOL_VALUE(v, boolean);
  return v;
}

MRB_INLINE mrb_value
mrb_undef_value(void)
{
  mrb_value v;
  SET_UNDEF_VALUE(v);
  return v;
}

#if defined(MRB_USE_ETEXT_EDATA) && !defined(MRB_USE_LINK_TIME_RO_DATA_P)
# ifdef __GNUC__
#  warning MRB_USE_ETEXT_EDATA is deprecated. Define MRB_USE_LINK_TIME_RO_DATA_P instead.
# endif
# define MRB_USE_LINK_TIME_RO_DATA_P
#endif

#if defined(MRB_USE_CUSTOM_RO_DATA_P)
/* If you define `MRB_USE_CUSTOM_RO_DATA_P`, you must implement `mrb_ro_data_p()`. */
mrb_bool mrb_ro_data_p(const char *p);
#elif defined(MRB_USE_LINK_TIME_RO_DATA_P)
extern char __ehdr_start[];
extern char __init_array_start[];

static inline mrb_bool
mrb_ro_data_p(const char *p)
{
  return __ehdr_start < p && p < __init_array_start;
}
#else
# define mrb_ro_data_p(p) FALSE
#endif

MRB_END_DECL

#endif  /* MRUBY_VALUE_H */
