/**
** @file mruby/bigint.h - Multi-precision, Integer
**
** See Copyright Notice in mruby.h
*/

#ifndef MRUBY_BIGINT_H
#define MRUBY_BIGINT_H
/*
 * FREE GMP - a public domain implementation of a subset of the
 *           gmp library
 *
 * I hearby place the file in the public domain.
 *
 * Do whatever you want with this code. Change it. Sell it. Claim you
 *  wrote it.
 * Bugs, complaints, flames, rants: please send email to
 *    Mark Henderson <markh@wimsey.bc.ca>
 * I'm already aware that fgmp is considerably slower than gmp
 *
 * CREDITS:
 *  Paul Rouse <par@r-cube.demon.co.uk> - generic bug fixes, mpz_sqrt and
 *    mpz_sqrtrem, and modifications to get fgmp to compile on a system
 *    with int and long of different sizes (specifically MS-DOS,286 compiler)
 *  Also see the file "notes" included with the fgmp distribution, for
 *    more credits.
 *
 * VERSION 1.0 - beta 5
 */

#include <sys/types.h>

#if defined(MRB_32BIT) && defined(MRB_INT32)
/*
 * The values below are for 32 bit machines (i.e. machines with a
 *  32 bit long type)
 * You'll need to change them, if you're using something else
 * If DIGITBITS is odd, see the comment at the top of mpz_sqrtrem
 */
typedef int32_t mp_limb;
typedef uint32_t mp_ulimb;
#define LMAX 0x3fffffffL
#define LC   0xc0000000L
#define CMASK (LMAX+1)
#define HLMAX 0x7fffL
#define HCMASK (HLMAX + 1)
#define HIGH(x) (((x) & 0x3fff8000L) >> 15)
#define LOW(x)  ((x) & 0x7fffL)

#else
/* 64 bit long type */
typedef int64_t mp_limb;
typedef uint64_t mp_ulimb;
#define LMAX 0x3fffffffffffffffLL
#define LC 0xc000000000000000LL
#define CMASK (LMAX+1)
#define HLMAX 0x7fffffffLL
#define HCMASK (HLMAX + 1)
#define HIGH(x) (((x) & 0x3fffffff80000000LL) >> 31)
#define LOW(x) ((x) & 0x7fffffffLL)
#endif

typedef struct _mpz_t {
  mp_limb *p;
  short sn;
  size_t sz;
} mpz_t;

struct RBigint {
  MRB_OBJECT_HEADER;
  mpz_t mp;
};
#define RBIGINT(v) ((struct RBigint*)mrb_ptr(v))

#define iabs(x) ((x>0) ? (x) : (-x))
#define imax(x,y) ((x>y)?x:y)
#define LONGBITS (sizeof(mp_limb)*8)
#define DIGITBITS (LONGBITS-2)
#define HALFDIGITBITS ((LONGBITS-2)/2)

#define hd(x,i)  (((size_t)(i)>=2*((x)->sz))? 0:(((i)%2) ? HIGH((x)->p[(i)/2]) \
    : LOW((x)->p[(i)/2])))
#define dg(x,i) (((size_t)(i) < (x)->sz) ? ((x)->p)[i] : 0)

#define RBIGINT(v) ((struct RBigint*)mrb_ptr(v))

mrb_static_assert_object_size(struct RBigint);

#endif  /* MRUBY_BIGINT_H */
