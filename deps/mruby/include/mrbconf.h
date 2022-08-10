/*
** mrbconf.h - mruby core configuration
**
** See Copyright Notice in mruby.h
*/

#ifndef MRUBYCONF_H
#define MRUBYCONF_H

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
/* add -DMRB_USE_FLOAT32 to use float instead of double for floating-point numbers */
//#define MRB_USE_FLOAT32

/* exclude floating-point numbers */
//#define MRB_NO_FLOAT

/* obsolete configuration */
#if defined(MRB_USE_FLOAT)
# define MRB_USE_FLOAT32
#endif

/* obsolete configuration */
#if defined(MRB_WITHOUT_FLOAT)
# define MRB_NO_FLOAT
#endif

#if defined(MRB_USE_FLOAT32) && defined(MRB_NO_FLOAT)
#error Cannot define MRB_USE_FLOAT32 and MRB_NO_FLOAT at the same time
#endif

/* add -DMRB_NO_METHOD_CACHE to disable method cache to save memory */
//#define MRB_NO_METHOD_CACHE
/* size of the method cache (need to be the power of 2) */
//#define MRB_METHOD_CACHE_SIZE (1<<8)

/* add -DMRB_USE_METHOD_T_STRUCT on machines that use higher bits of function pointers */
/* no MRB_USE_METHOD_T_STRUCT requires highest 2 bits of function pointers to be zero */
#ifndef MRB_USE_METHOD_T_STRUCT
  // can't use highest 2 bits of function pointers at least on 32bit
  // Windows and 32bit Linux.
# ifdef MRB_32BIT
#   define MRB_USE_METHOD_T_STRUCT
# endif
#endif

/* define on big endian machines; used by MRB_NAN_BOXING, etc. */
#ifndef MRB_ENDIAN_BIG
# if (defined(BYTE_ORDER) && defined(BIG_ENDIAN) && BYTE_ORDER == BIG_ENDIAN) || \
     (defined(__BYTE_ORDER__) && defined(__ORDER_BIG_ENDIAN__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
#  define MRB_ENDIAN_BIG
# endif
#endif

/* represent mrb_value in boxed double; conflict with MRB_USE_FLOAT32 and MRB_NO_FLOAT */
//#define MRB_NAN_BOXING

/* represent mrb_value as a word (natural unit of data for the processor) */
//#define MRB_WORD_BOXING

/* represent mrb_value as a struct; occupies 2 words */
//#define MRB_NO_BOXING

/* if no specific boxing type is chosen */
#if !defined(MRB_NAN_BOXING) && !defined(MRB_WORD_BOXING) && !defined(MRB_NO_BOXING)
# define MRB_WORD_BOXING
#endif

/* if defined mruby allocates Float objects in the heap to keep full precision if needed */
//#define MRB_WORDBOX_NO_FLOAT_TRUNCATE

/* add -DMRB_INT32 to use 32bit integer for mrb_int; conflict with MRB_INT64;
   Default for 32-bit CPU mode. */
//#define MRB_INT32

/* add -DMRB_INT64 to use 64bit integer for mrb_int; conflict with MRB_INT32;
   Default for 64-bit CPU mode (unless using MRB_NAN_BOXING). */
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

/* call malloc_trim(0) from mrb_full_gc() */
//#define MRB_USE_MALLOC_TRIM

/* string class to handle UTF-8 encoding */
//#define MRB_UTF8_STRING

/* argv max size in mrb_funcall */
//#define MRB_FUNCALL_ARGC_MAX 16

/* number of object per heap page */
//#define MRB_HEAP_PAGE_SIZE 1024

/* define if your platform does not support etext, edata */
//#define MRB_NO_DEFAULT_RO_DATA_P

/* define if your platform supports etext, edata */
//#define MRB_USE_RO_DATA_P_ETEXT
/* use MRB_USE_ETEXT_RO_DATA_P by default on Linux */
#if (defined(__linux__) && !defined(__KERNEL__))
#define MRB_USE_ETEXT_RO_DATA_P
#endif

/* you can provide and use mrb_ro_data_p() for your platform.
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

/* arena size */
//#define MRB_GC_ARENA_SIZE 100

/* fixed size GC arena */
//#define MRB_GC_FIXED_ARENA

/* state atexit stack size */
//#define MRB_FIXED_STATE_ATEXIT_STACK_SIZE 5

/* fixed size state atexit stack */
//#define MRB_FIXED_STATE_ATEXIT_STACK

/* -DMRB_NO_XXXX to drop following features */
//#define MRB_NO_STDIO /* use of stdio */

/* -DMRB_USE_XXXX to enable following features */
//#define MRB_USE_DEBUG_HOOK /* hooks for debugger */
//#define MRB_USE_ALL_SYMBOLS /* Symbol.all_symbols */

/* obsolete configurations */
#ifdef MRB_METHOD_T_STRUCT
# define MRB_USE_METHOD_T_STRUCT
#endif
#if defined(DISABLE_STDIO) || defined(MRB_DISABLE_STDIO)
# define MRB_NO_STDIO
#endif
#ifdef MRB_DISABLE_DIRECT_THREADING
# define MRB_NO_DIRECT_THREADING
#endif
#if defined(ENABLE_DEBUG) || defined(MRB_ENABLE_DEBUG_HOOK)
# define MRB_USE_DEBUG_HOOK
#endif
#ifdef MRB_ENABLE_ALL_SYMBOLS
# define MRB_USE_ALL_SYMBOLS
#endif
#ifdef MRB_ENABLE_CXX_ABI
# define MRB_USE_CXX_ABI
#endif
#ifdef MRB_ENABLE_CXX_EXCEPTION
# define MRB_USE_CXX_EXCEPTION
#endif

/* end of configuration */

#ifndef MRB_NO_STDIO
# include <stdio.h>
#endif

/*
** mruby tuning profiles
**/

/* A profile for micro controllers */
#if defined(MRB_CONSTRAINED_BASELINE_PROFILE)
# ifndef MRB_NO_METHOD_CACHE
#  define MRB_NO_METHOD_CACHE
# endif

# ifndef KHASH_DEFAULT_SIZE
#  define KHASH_DEFAULT_SIZE 16
# endif

# ifndef MRB_HEAP_PAGE_SIZE
#  define MRB_HEAP_PAGE_SIZE 256
# endif

/* A profile for default mruby */
#elif defined(MRB_BASELINE_PROFILE)

/* A profile for desktop computers or workstations; rich memory! */
#elif defined(MRB_MAIN_PROFILE)
# ifndef MRB_METHOD_CACHE_SIZE
#  define MRB_METHOD_CACHE_SIZE (1<<10)
# endif

# ifndef MRB_HEAP_PAGE_SIZE
#  define MRB_HEAP_PAGE_SIZE 4096
# endif

/* A profile for server; mruby vm is long life */
#elif defined(MRB_HIGH_PROFILE)
# ifndef MRB_METHOD_CACHE_SIZE
#  define MRB_METHOD_CACHE_SIZE (1<<12)
# endif

# ifndef MRB_HEAP_PAGE_SIZE
#  define MRB_HEAP_PAGE_SIZE 4096
# endif
#endif

#endif  /* MRUBYCONF_H */
