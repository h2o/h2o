#define STDC_HEADERS 1
#define HAVE_SYS_TYPES_H 1
#define HAVE_SYS_STAT_H 1
#define HAVE_STDLIB_H 1
#define HAVE_STRING_H 1
#define HAVE_MEMORY_H 1
#define HAVE_FLOAT_H 1
#define HAVE_OFF_T 1
#define SIZEOF_INT 4
#define SIZEOF_SHORT 2
#define SIZEOF_LONG 4
#define SIZEOF_LONG_LONG 8
#define SIZEOF___INT64 8
#define SIZEOF_OFF_T 4
#ifdef _WIN64
# define SIZEOF_VOIDP 8
#else
# define SIZEOF_VOIDP 4
#endif
#define SIZEOF_FLOAT 4
#define SIZEOF_DOUBLE 8
#define TOKEN_PASTE(x,y) x##y
#ifndef NORETURN
# if defined(_MSC_VER) && (_MSC_VER > 1100)
#  define NORETURN(x) __declspec(noreturn) x
# else
#  define NORETURN(x) x
# endif
#endif
#define HAVE_DECL_SYS_NERR 1
#define HAVE_LIMITS_H 1
#define HAVE_FCNTL_H 1
#define HAVE_SYS_UTIME_H 1
#if defined(__MINGW32__) || (defined(_MSC_VER) && _MSC_VER >= 1600)
# define HAVE_STDINT_H 1
#endif
#if defined(__MINGW32__) || (defined(_MSC_VER) && _MSC_VER >= 1800)
# define HAVE_INTTYPES_H 1
#endif
#define uid_t int
#define gid_t int
#define HAVE_STRUCT_STAT_ST_RDEV 1
#define HAVE_ST_RDEV 1
#define GETGROUPS_T int
#define RETSIGTYPE void
#define HAVE_ALLOCA 1
#define HAVE_DUP2 1
#define HAVE_MEMCMP 1
#define HAVE_MEMMOVE 1
#define HAVE_MKDIR 1
#define HAVE_STRERROR 1
#define HAVE_STRFTIME 1
#define HAVE_STRCHR 1
#define HAVE_STRSTR 1
#define HAVE_STRTOD 1
#define HAVE_STRTOL 1
#define HAVE_STRTOUL 1
#define HAVE_FLOCK 1
#define HAVE_VSNPRINTF 1
#define HAVE_FINITE 1
#define HAVE_FMOD 1
#define HAVE_FREXP 1
#define HAVE_HYPOT 1
#define HAVE_MODF 1
#define HAVE_WAITPID 1
#define HAVE_CHSIZE 1
#define HAVE_TIMES 1
#define HAVE__SETJMP 1
#define HAVE_TELLDIR 1
#define HAVE_SEEKDIR 1
#define HAVE_MKTIME 1
#define HAVE_COSH 1
#define HAVE_SINH 1
#define HAVE_TANH 1
#define HAVE_EXECVE 1
#define HAVE_TZNAME 1
#define HAVE_DAYLIGHT 1
#define SETPGRP_VOID 1
#define inline __inline
#define NEED_IO_SEEK_BETWEEN_RW 1
#define RSHIFT(x,y) ((x)>>(int)y)
#define FILE_COUNT _cnt
#define FILE_READPTR _ptr
#define DEFAULT_KCODE KCODE_NONE
#define DLEXT ".so"
#define DLEXT2 ".dll"
