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

/* add -DMRB_INT16 to use 16bit integer for mrb_int; conflict with MRB_INT64 */
//#define MRB_INT16

/* add -DMRB_INT64 to use 64bit integer for mrb_int; conflict with MRB_INT16 */
//#define MRB_INT64

/* if no specific integer type is chosen */
#if !defined(MRB_INT16) && !defined(MRB_INT32) && !defined(MRB_INT64)
# if defined(MRB_64BIT) && !defined(MRB_NAN_BOXING)
/* Use 64bit integers on 64bit architecture (without MRB_NAN_BOXING) */
#  define MRB_INT64
# else
/* Otherwise use 32bit integers */
#  define MRB_INT32
# endif
#endif

/* represent mrb_value in boxed double; conflict with MRB_USE_FLOAT */
//#define MRB_NAN_BOXING

/* define on big endian machines; used by MRB_NAN_BOXING */
//#define MRB_ENDIAN_BIG

/* represent mrb_value as a word (natural unit of data for the processor) */
//#define MRB_WORD_BOXING

/* string class to handle UTF-8 encoding */
//#define MRB_UTF8_STRING

/* argv max size in mrb_funcall */
//#define MRB_FUNCALL_ARGC_MAX 16

/* number of object per heap page */
//#define MRB_HEAP_PAGE_SIZE 1024

/* if _etext and _edata available, mruby can reduce memory used by symbols */
//#define MRB_USE_ETEXT_EDATA

/* do not use __init_array_start to determine readonly data section;
   effective only when MRB_USE_ETEXT_EDATA is defined */
//#define MRB_NO_INIT_ARRAY_START

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

#endif  /* MRUBYCONF_H */
