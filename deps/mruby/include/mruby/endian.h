/**
** @file mruby/endian.h - detect endian-ness
**
** See Copyright Notice in mruby.h
*/

#ifndef MRUBY_ENDIAN_H
#define MRUBY_ENDIAN_H

#include <limits.h>

MRB_BEGIN_DECL

#if !defined(BYTE_ORDER) && defined(__BYTE_ORDER__)
# define BYTE_ORDER __BYTE_ORDER__
#endif
#if !defined(BIG_ENDIAN) && defined(__ORDER_BIG_ENDIAN__)
# define BIG_ENDIAN __ORDER_BIG_ENDIAN__
#endif
#if !defined(LITTLE_ENDIAN) && defined(__ORDER_LITTLE_ENDIAN__)
# define LITTLE_ENDIAN __ORDER_LITTLE_ENDIAN__
#endif

#ifdef BYTE_ORDER
# if BYTE_ORDER == BIG_ENDIAN
#  define littleendian 0
# elif BYTE_ORDER == LITTLE_ENDIAN
#  define littleendian 1
# endif
#endif
#ifndef littleendian
/* can't distinguish endian in compile time */
static inline int
check_little_endian(void)
{
  unsigned int n = 1;
  return (*(unsigned char *)&n == 1);
}
#  define littleendian check_little_endian()
#endif

MRB_END_DECL

#endif  /* MRUBY_ENDIAN_H */
