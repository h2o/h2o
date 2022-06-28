/*
** mrbconf.h - mruby core configuration
**
** See Copyright Notice in mruby.h
*/

#ifndef MRUBYCONF_H
#define MRUBYCONF_H

#include <limits.h>
#include <stdint.h>

/* architecture selection: */
/* specify -DMRB_32BIT or -DMRB_64BIT to override */
#if !defined(MRB_32BIT) && !defined(MRB_64BIT)
#if UINT64_MAX == SIZE_MAX
#define MRB_64BIT
#else
#define MRB_32BIT
#endif
#endif

#if defined(MRB_32BIT) && defined(MRB_64BIT)
#error Cannot build for 32 and 64 bit architecture at the same time
#endif

/* configuration options: */
/* add -DMRB_USE_FLOAT to use float instead of double for floating point numbers */
//#define MRB_USE_FLOAT

/* exclude floating point numbers */
//#define MRB_WITHOUT_FLOAT

/* add -DMRB_METHOD_CACHE to use method cache to improve performance */
//#define MRB_METHOD_CACHE
/* size of the method cache (need to be the power of 2) */
//#define MRB_METHOD_CACHE_SIZE (1<<7)

/* add -DMRB_METHOD_T_STRUCT on machines that use higher bits of pointers */
/* no MRB_METHOD_T_STRUCT requires highest 2 bits of function pointers to be zero */
#ifndef MRB_METHOD_T_STRUCT
  // can't use highest 2 bits of function pointers at least on 32bit
  // Windows and 32bit Linux.
# ifdef MRB_32BIT
#   define MRB_METHOD_T_STRUCT
# endif
#endif

/* add -DMRB_INT32 to use 32bit integer for mrb_int; conflict with MRB_INT64;
   Default for 32-bit CPU mode. */
//#define MRB_INT32

/* add -DMRB_INT64 to use 64bit integer for mrb_int; conflict with MRB_INT32;
   Default for 64-bit CPU mode. */
//#define MRB_INT64

/* if no specific integer type is chosen */
#if !defined(MRB_INT32) && !defined(MRB_INT64)
# if defined(MRB_64BIT) && !defined(MRB_NAN_BOXING)
/* Use 64bit integers on 64bit architecture (without MRB_NAN_BOXING) */
#  define MRB_INT64
# else
/* Otherwise use 32bit integers */
#  define MRB_INT32
# endif
#endif

/* define on big endian machines; used by MRB_NAN_BOXING, etc. */
#ifndef MRB_ENDIAN_BIG
# if (defined(BYTE_ORDER) && defined(BIG_ENDIAN) && BYTE_ORDER == BIG_ENDIAN) || \
     (defined(__BYTE_ORDER__) && defined(__ORDER_BIG_ENDIAN__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
#  define MRB_ENDIAN_BIG
# endif
#endif

/* represent mrb_value in boxed double; conflict with MRB_USE_FLOAT and MRB_WITHOUT_FLOAT */
//#define MRB_NAN_BOXING

/* represent mrb_value as a word (natural unit of data for the processor) */
//#define MRB_WORD_BOXING

/* string class to handle UTF-8 encoding */
//#define MRB_UTF8_STRING

/* argv max size in mrb_funcall */
//#define MRB_FUNCALL_ARGC_MAX 16

/* number of object per heap page */
//#define MRB_HEAP_PAGE_SIZE 1024

/* if __ehdr_start is available, mruby can reduce memory used by symbols */
//#define MRB_USE_LINK_TIME_RO_DATA_P

/* if MRB_USE_LINK_TIME_RO_DATA_P does not work,
   you can try mrb_ro_data_p() that you have implemented yourself in any file;
   prototype is `mrb_bool mrb_ro_data_p(const char *ptr)` */
//#define MRB_USE_CUSTOM_RO_DATA_P

/* turn off generational GC by default */
//#define MRB_GC_TURN_OFF_GENERATIONAL

/* default size of khash table bucket */
//#define KHASH_DEFAULT_SIZE 32

/* allocated memory address alignment */
//#define POOL_ALIGNMENT 4

/* page size of memory pool */
//#define POOL_PAGE_SIZE 16000

/* initial minimum size for string buffer */
//#define MRB_STR_BUF_MIN_SIZE 128

/* arena size */
//#define MRB_GC_ARENA_SIZE 100

/* fixed size GC arena */
//#define MRB_GC_FIXED_ARENA

/* state atexit stack size */
//#define MRB_FIXED_STATE_ATEXIT_STACK_SIZE 5

/* fixed size state atexit stack */
//#define MRB_FIXED_STATE_ATEXIT_STACK

/* -DMRB_DISABLE_XXXX to drop following features */
//#define MRB_DISABLE_STDIO /* use of stdio */

/* -DMRB_ENABLE_XXXX to enable following features */
//#define MRB_ENABLE_DEBUG_HOOK /* hooks for debugger */
//#define MRB_ENABLE_ALL_SYMBOLS /* Symbols.all_symbols */

/* end of configuration */

/* define MRB_DISABLE_XXXX from DISABLE_XXX (for compatibility) */
#ifdef DISABLE_STDIO
#define MRB_DISABLE_STDIO
#endif

/* define MRB_ENABLE_XXXX from ENABLE_XXX (for compatibility) */
#ifdef ENABLE_DEBUG
#define MRB_ENABLE_DEBUG_HOOK
#endif

#ifndef MRB_DISABLE_STDIO
# include <stdio.h>
#endif

#ifndef FALSE
# define FALSE 0
#endif

#ifndef TRUE
# define TRUE 1
#endif

/*
** mruby tuning profiles
**/

/* A profile for micro controllers */
#if defined(MRB_CONSTRAINED_BASELINE_PROFILE)
# ifndef KHASH_DEFAULT_SIZE
#  define KHASH_DEFAULT_SIZE 16
# endif

# ifndef MRB_STR_BUF_MIN_SIZE
#  define MRB_STR_BUF_MIN_SIZE 32
# endif

# ifndef MRB_HEAP_PAGE_SIZE
#  define MRB_HEAP_PAGE_SIZE 256
# endif

/* A profile for default mruby */
#elif defined(MRB_BASELINE_PROFILE)

/* A profile for desktop computers or workstations; rich memory! */
#elif defined(MRB_MAIN_PROFILE)
# ifndef MRB_METHOD_CACHE
#  define MRB_METHOD_CACHE
# endif

# ifndef MRB_METHOD_CACHE_SIZE
#  define MRB_METHOD_CACHE_SIZE (1<<10)
# endif

# ifndef MRB_IV_SEGMENT_SIZE
#  define MRB_IV_SEGMENT_SIZE 32
# endif

# ifndef MRB_HEAP_PAGE_SIZE
#  define MRB_HEAP_PAGE_SIZE 4096
# endif

/* A profile for server; mruby vm is long life */
#elif defined(MRB_HIGH_PROFILE)
# ifndef MRB_METHOD_CACHE
#  define MRB_METHOD_CACHE
# endif

# ifndef MRB_METHOD_CACHE_SIZE
#  define MRB_METHOD_CACHE_SIZE (1<<12)
# endif

# ifndef MRB_IV_SEGMENT_SIZE
#  define MRB_IV_SEGMENT_SIZE 64
# endif

# ifndef MRB_HEAP_PAGE_SIZE
#  define MRB_HEAP_PAGE_SIZE 4096
# endif
#endif

#endif  /* MRUBYCONF_H */
