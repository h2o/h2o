/*
**"common.h - mruby common platform definition"
**
** See Copyright Notice in mruby.h
*/

#ifndef MRUBY_COMMON_H
#define MRUBY_COMMON_H


#ifdef __cplusplus
#ifdef MRB_ENABLE_CXX_ABI
#define MRB_BEGIN_DECL
#define MRB_END_DECL
#else
# define MRB_BEGIN_DECL extern "C" {
# define MRB_END_DECL }
#endif
#else
/** Start declarations in C mode */
# define MRB_BEGIN_DECL
/** End declarations in C mode */
# define MRB_END_DECL
#endif

/**
 * Shared compiler macros
 */
MRB_BEGIN_DECL

/** Declare a function that never returns. */
#if __STDC_VERSION__ >= 201112L
# define mrb_noreturn _Noreturn
#elif defined __GNUC__ && !defined __STRICT_ANSI__
# define mrb_noreturn __attribute__((noreturn))
#elif defined _MSC_VER
# define mrb_noreturn __declspec(noreturn)
#else
# define mrb_noreturn
#endif

/** Mark a function as deprecated. */
#if defined __GNUC__ && !defined __STRICT_ANSI__
# define mrb_deprecated __attribute__((deprecated))
#elif defined _MSC_VER
# define mrb_deprecated __declspec(deprecated)
#else
# define mrb_deprecated
#endif

/** Declare a function as always inlined. */
#if defined(_MSC_VER)
# define MRB_INLINE static __inline
#else
# define MRB_INLINE static inline
#endif


/** Declare a public MRuby API function. */
#if defined(MRB_BUILD_AS_DLL)
#if defined(MRB_CORE) || defined(MRB_LIB)
# define MRB_API __declspec(dllexport)
#else
# define MRB_API __declspec(dllimport)
#endif
#else
# define MRB_API extern
#endif

MRB_END_DECL

#endif  /* MRUBY_COMMON_H */
