/*

Most code in this file originates from musl (src/stdio/vfprintf.c)
which, just like mruby itself, is licensed under the MIT license.

Copyright (c) 2005-2014 Rich Felker, et al.

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

*/

#include <limits.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
#include <float.h>
#include <ctype.h>

#include <mruby.h>
#include <mruby/string.h>

struct fmt_args {
  mrb_state *mrb;
  mrb_value str;
};

#define MAX(a,b) ((a)>(b) ? (a) : (b))
#define MIN(a,b) ((a)<(b) ? (a) : (b))

/* Convenient bit representation for modifier flags, which all fall
 * within 31 codepoints of the space character. */

#define ALT_FORM   (1U<<('#'-' '))
#define ZERO_PAD   (1U<<('0'-' '))
#define LEFT_ADJ   (1U<<('-'-' '))
#define PAD_POS    (1U<<(' '-' '))
#define MARK_POS   (1U<<('+'-' '))

static void
out(struct fmt_args *f, const char *s, size_t l)
{
  mrb_str_cat(f->mrb, f->str, s, l);
}

#define PAD_SIZE 256
static void
pad(struct fmt_args *f, char c, int w, int l, int fl)
{
  char pad[PAD_SIZE];
  if (fl & (LEFT_ADJ | ZERO_PAD) || l >= w) return;
  l = w - l;
  memset(pad, c, l>PAD_SIZE ? PAD_SIZE : l);
  for (; l >= PAD_SIZE; l -= PAD_SIZE)
    out(f, pad, PAD_SIZE);
  out(f, pad, l);
}

static const char xdigits[16] = {
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
};

static char*
fmt_u(uint32_t x, char *s)
{
  for (; x; x /= 10) *--s = '0' + x % 10;
  return s;
}

/* Do not override this check. The floating point printing code below
 * depends on the float.h constants being right. If they are wrong, it
 * may overflow the stack. */
#if LDBL_MANT_DIG == 53
typedef char compiler_defines_long_double_incorrectly[9-(int)sizeof(long double)];
#endif

static int
fmt_fp(struct fmt_args *f, long double y, int w, int p, int fl, int t)
{
  uint32_t big[(LDBL_MANT_DIG+28)/29 + 1          // mantissa expansion
    + (LDBL_MAX_EXP+LDBL_MANT_DIG+28+8)/9]; // exponent expansion
  uint32_t *a, *d, *r, *z;
  uint32_t i;
  int e2=0, e, j, l;
  char buf[9+LDBL_MANT_DIG/4], *s;
  const char *prefix="-0X+0X 0X-0x+0x 0x";
  int pl;
  char ebuf0[3*sizeof(int)], *ebuf=&ebuf0[3*sizeof(int)], *estr;

  pl=1;
  if (signbit(y)) {
    y=-y;
  } else if (fl & MARK_POS) {
    prefix+=3;
  } else if (fl & PAD_POS) {
    prefix+=6;
  } else prefix++, pl=0;

  if (!isfinite(y)) {
    const char *ss = (t&32)?"inf":"INF";
    if (y!=y) ss=(t&32)?"nan":"NAN";
    pad(f, ' ', w, 3+pl, fl&~ZERO_PAD);
    out(f, prefix, pl);
    out(f, ss, 3);
    pad(f, ' ', w, 3+pl, fl^LEFT_ADJ);
    return MAX(w, 3+pl);
  }

  y = frexp((double)y, &e2) * 2;
  if (y) e2--;

  if ((t|32)=='a') {
    long double round = 8.0;
    int re;

    if (t&32) prefix += 9;
    pl += 2;

    if (p<0 || p>=LDBL_MANT_DIG/4-1) re=0;
    else re=LDBL_MANT_DIG/4-1-p;

    if (re) {
      while (re--) round*=16;
      if (*prefix=='-') {
        y=-y;
        y-=round;
        y+=round;
        y=-y;
      }
      else {
        y+=round;
        y-=round;
      }
    }

    estr=fmt_u(e2<0 ? -e2 : e2, ebuf);
    if (estr==ebuf) *--estr='0';
    *--estr = (e2<0 ? '-' : '+');
    *--estr = t+('p'-'a');

    s=buf;
    do {
      int x=(int)y;
      *s++=xdigits[x]|(t&32);
      y=16*(y-x);
      if (s-buf==1 && (y||p>0||(fl&ALT_FORM))) *s++='.';
    } while (y);

    if (p && s-buf-2 < p)
      l = (p+2) + (ebuf-estr);
    else
      l = (s-buf) + (ebuf-estr);

    pad(f, ' ', w, pl+l, fl);
    out(f, prefix, pl);
    pad(f, '0', w, pl+l, fl^ZERO_PAD);
    out(f, buf, s-buf);
    pad(f, '0', l-(ebuf-estr)-(s-buf), 0, 0);
    out(f, estr, ebuf-estr);
    pad(f, ' ', w, pl+l, fl^LEFT_ADJ);
    return MAX(w, pl+l);
  }
  if (p<0) p=6;

  if (y) y *= 268435456.0, e2-=28;

  if (e2<0) a=r=z=big;
  else a=r=z=big+sizeof(big)/sizeof(*big) - LDBL_MANT_DIG - 1;

  do {
    *z = (uint32_t)y;
    y = 1000000000*(y-*z++);
  } while (y);

  while (e2>0) {
    uint32_t carry=0;
    int sh=MIN(29,e2);
    for (d=z-1; d>=a; d--) {
      uint64_t x = ((uint64_t)*d<<sh)+carry;
      *d = x % 1000000000;
      carry = (uint32_t)(x / 1000000000);
    }
    if (carry) *--a = carry;
    while (z>a && !z[-1]) z--;
    e2-=sh;
  }
  while (e2<0) {
    uint32_t carry=0, *b;
    int sh=MIN(9,-e2), need=1+(p+LDBL_MANT_DIG/3+8)/9;
    for (d=a; d<z; d++) {
      uint32_t rm = *d & ((1<<sh)-1);
      *d = (*d>>sh) + carry;
      carry = (1000000000>>sh) * rm;
    }
    if (!*a) a++;
    if (carry) *z++ = carry;
    /* Avoid (slow!) computation past requested precision */
    b = (t|32)=='f' ? r : a;
    if (z-b > need) z = b+need;
    e2+=sh;
  }

  if (a<z) for (i=10, e=9*(r-a); *a>=i; i*=10, e++);
  else e=0;

  /* Perform rounding: j is precision after the radix (possibly neg) */
  j = p - ((t|32)!='f')*e - ((t|32)=='g' && p);
  if (j < 9*(z-r-1)) {
    uint32_t x;
    /* We avoid C's broken division of negative numbers */
    d = r + 1 + ((j+9*LDBL_MAX_EXP)/9 - LDBL_MAX_EXP);
    j += 9*LDBL_MAX_EXP;
    j %= 9;
    for (i=10, j++; j<9; i*=10, j++);
    x = *d % i;
    /* Are there any significant digits past j? */
    if (x || d+1!=z) {
      long double round = 2/LDBL_EPSILON;
      long double small;
      if (*d/i & 1) round += 2;
      if (x<i/2) small=0.5;
      else if (x==i/2 && d+1==z) small=1.0;
      else small=1.5;
      if (pl && *prefix=='-') round*=-1, small*=-1;
      *d -= x;
      /* Decide whether to round by probing round+small */
      if (round+small != round) {
        *d = *d + i;
        while (*d > 999999999) {
          *d--=0;
          if (d<a) *--a=0;
          (*d)++;
        }
        for (i=10, e=9*(r-a); *a>=i; i*=10, e++);
      }
    }
    if (z>d+1) z=d+1;
  }
  for (; z>a && !z[-1]; z--);

  if ((t|32)=='g') {
    if (!p) p++;
    if (p>e && e>=-4) {
      t--;
      p-=e+1;
    }
    else {
      t-=2;
      p--;
    }
    if (!(fl&ALT_FORM)) {
      /* Count trailing zeros in last place */
      if (z>a && z[-1]) for (i=10, j=0; z[-1]%i==0; i*=10, j++);
      else j=9;
      if ((t|32)=='f')
        p = MIN(p,MAX(0,9*(z-r-1)-j));
      else
        p = MIN(p,MAX(0,9*(z-r-1)+e-j));
    }
  }
  l = 1 + p + (p || (fl&ALT_FORM));
  if ((t|32)=='f') {
    if (e>0) l+=e;
  }
  else {
    estr=fmt_u(e<0 ? -e : e, ebuf);
    while(ebuf-estr<2) *--estr='0';
    *--estr = (e<0 ? '-' : '+');
    *--estr = t;
    l += ebuf-estr;
  }

  pad(f, ' ', w, pl+l, fl);
  out(f, prefix, pl);
  pad(f, '0', w, pl+l, fl^ZERO_PAD);

  if ((t|32)=='f') {
    if (a>r) a=r;
    for (d=a; d<=r; d++) {
      char *ss = fmt_u(*d, buf+9);
      if (d!=a) while (ss>buf) *--ss='0';
      else if (ss==buf+9) *--ss='0';
      out(f, ss, buf+9-ss);
    }
    if (p || (fl&ALT_FORM)) out(f, ".", 1);
    for (; d<z && p>0; d++, p-=9) {
      char *ss = fmt_u(*d, buf+9);
      while (ss>buf) *--ss='0';
      out(f, ss, MIN(9,p));
    }
    pad(f, '0', p+9, 9, 0);
  }
  else {
    if (z<=a) z=a+1;
    for (d=a; d<z && p>=0; d++) {
      char *ss = fmt_u(*d, buf+9);
      if (ss==buf+9) *--ss='0';
      if (d!=a) while (ss>buf) *--ss='0';
      else {
        out(f, ss++, 1);
        if (p>0||(fl&ALT_FORM)) out(f, ".", 1);
      }
      out(f, ss, MIN(buf+9-ss, p));
      p -= buf+9-ss;
    }
    pad(f, '0', p+18, 18, 0);
    out(f, estr, ebuf-estr);
  }

  pad(f, ' ', w, pl+l, fl^LEFT_ADJ);

  return MAX(w, pl+l);
}

static int
fmt_core(struct fmt_args *f, const char *fmt, mrb_float flo)
{
  int p;

  if (*fmt != '%') {
    return -1;
  }
  ++fmt;

  if (*fmt == '.') {
    ++fmt;
    for (p = 0; ISDIGIT(*fmt); ++fmt) {
      p = 10 * p + (*fmt - '0');
    }
  }
  else {
    p = -1;
  }

  switch (*fmt) {
  case 'e': case 'f': case 'g': case 'a':
  case 'E': case 'F': case 'G': case 'A':
    return fmt_fp(f, flo, 0, p, 0, *fmt);
  default:
    return -1;
  }
}

mrb_value
mrb_float_to_str(mrb_state *mrb, mrb_value flo, const char *fmt)
{
  struct fmt_args f;

  f.mrb = mrb;
  f.str = mrb_str_buf_new(mrb, 24);
  if (fmt_core(&f, fmt, mrb_float(flo)) < 0) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid format string");
  }
  return f.str;
}
