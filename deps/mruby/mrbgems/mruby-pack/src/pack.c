/*
 ** pack.c - Array#pack, String#unpack
 */

#include <mruby.h>
#include "mruby/error.h"
#include "mruby/array.h"
#include "mruby/class.h"
#include "mruby/numeric.h"
#include "mruby/string.h"
#include "mruby/variable.h"
#include "mruby/endian.h"

#include <ctype.h>
#include <errno.h>
#include <string.h>

#define INT_OVERFLOW_P(n)  ((n) < MRB_INT_MIN || (n) > MRB_INT_MAX)
#define UINT_OVERFLOW_P(n) ((n) > MRB_INT_MAX)

#ifndef EOF
# define EOF (-1) /* for MRB_NO_STDIO */
#endif

struct tmpl {
  mrb_value str;
  int idx;
};

enum pack_dir {
  PACK_DIR_CHAR,      /* C */
  PACK_DIR_SHORT,     /* S */
  PACK_DIR_LONG,      /* L */
  PACK_DIR_QUAD,      /* Q */
  //PACK_DIR_INT,     /* i */
  //PACK_DIR_VAX,
  PACK_DIR_BER,       /* w */
  PACK_DIR_UTF8,      /* U */
  //PACK_DIR_BER,
  PACK_DIR_DOUBLE,    /* E */
  PACK_DIR_FLOAT,     /* f */
  PACK_DIR_STR,       /* A */
  PACK_DIR_HEX,       /* h */
  PACK_DIR_BASE64,    /* m */
  PACK_DIR_QENC,      /* M */
  PACK_DIR_NUL,       /* x */
  PACK_DIR_BACK,      /* X */
  PACK_DIR_ABS,       /* @ */
  PACK_DIR_INVALID
};

enum pack_type {
  PACK_TYPE_INTEGER,
  PACK_TYPE_FLOAT,
  PACK_TYPE_STRING,
  PACK_TYPE_NONE
};

#define PACK_FLAG_s             0x00000001      /* native size ("_" "!") */
#define PACK_FLAG_a             0x00000002      /* null padding ("a") */
#define PACK_FLAG_Z             0x00000004      /* append nul char ("z") */
#define PACK_FLAG_SIGNED        0x00000008      /* native size ("_" "!") */
#define PACK_FLAG_GT            0x00000010      /* big endian (">") */
#define PACK_FLAG_LT            0x00000020      /* little endian ("<") */
#define PACK_FLAG_WIDTH         0x00000040      /* "count" is "width" */
#define PACK_FLAG_LSB           0x00000080      /* LSB / low nibble first */
#define PACK_FLAG_COUNT2        0x00000100      /* "count" is special... */
#define PACK_FLAG_LITTLEENDIAN  0x00000200      /* little endian actually */

#define PACK_BASE64_IGNORE      0xff
#define PACK_BASE64_PADDING     0xfe

const static unsigned char base64chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static unsigned char base64_dec_tab[128];

static unsigned int
hex2int(unsigned char ch)
{
  if (ch >= '0' && ch <= '9')
    return ch - '0';
  else if (ch >= 'A' && ch <= 'F')
    return 10 + (ch - 'A');
  else if (ch >= 'a' && ch <= 'f')
    return 10 + (ch - 'a');
  else
    return -1;
}

static void
make_base64_dec_tab(void)
{
  int i;
  memset(base64_dec_tab, PACK_BASE64_IGNORE, sizeof(base64_dec_tab));
  for (i = 0; i < 26; i++)
    base64_dec_tab['A' + i] = i;
  for (i = 0; i < 26; i++)
    base64_dec_tab['a' + i] = i + 26;
  for (i = 0; i < 10; i++)
    base64_dec_tab['0' + i] = i + 52;
  base64_dec_tab['+'+0] = 62;
  base64_dec_tab['/'+0] = 63;
  base64_dec_tab['='+0] = PACK_BASE64_PADDING;
}

static mrb_value
str_len_ensure(mrb_state *mrb, mrb_value str, mrb_int len)
{
  mrb_int n = RSTRING_LEN(str);
  if (len < 0) {
    mrb_raise(mrb, E_RANGE_ERROR, "negative (or overflowed) integer");
  }
  if (len > n) {
    do {
      n *= 2;
    } while (len > n);
    str = mrb_str_resize(mrb, str, n);
  }
  return str;
}


static int
pack_char(mrb_state *mrb, mrb_value o, mrb_value str, mrb_int sidx, unsigned int flags)
{
  str = str_len_ensure(mrb, str, sidx + 1);
  RSTRING_PTR(str)[sidx] = (char)mrb_integer(o);
  return 1;
}

static int
unpack_char(mrb_state *mrb, const void *src, int srclen, mrb_value ary, unsigned int flags)
{
  if (flags & PACK_FLAG_SIGNED)
    mrb_ary_push(mrb, ary, mrb_fixnum_value(*(signed char *)src));
  else
    mrb_ary_push(mrb, ary, mrb_fixnum_value(*(unsigned char *)src));
  return 1;
}

static int
pack_short(mrb_state *mrb, mrb_value o, mrb_value str, mrb_int sidx, unsigned int flags)
{
  uint16_t n;

  str = str_len_ensure(mrb, str, sidx + 2);
  n = (uint16_t)mrb_integer(o);
  if (flags & PACK_FLAG_LITTLEENDIAN) {
    RSTRING_PTR(str)[sidx+0] = n % 256;
    RSTRING_PTR(str)[sidx+1] = n / 256;
  } else {
    RSTRING_PTR(str)[sidx+0] = n / 256;
    RSTRING_PTR(str)[sidx+1] = n % 256;
  }
  return 2;
}

static int
unpack_short(mrb_state *mrb, const unsigned char *src, int srclen, mrb_value ary, unsigned int flags)
{
  int n;

  if (flags & PACK_FLAG_LITTLEENDIAN) {
    n = src[1] * 256 + src[0];
  } else {
    n = src[0] * 256 + src[1];
  }
  if ((flags & PACK_FLAG_SIGNED) && (n >= 0x8000)) {
    n -= 0x10000;
  }
  mrb_ary_push(mrb, ary, mrb_fixnum_value(n));
  return 2;
}

static int
pack_long(mrb_state *mrb, mrb_value o, mrb_value str, mrb_int sidx, unsigned int flags)
{
  uint32_t n;

  str = str_len_ensure(mrb, str, sidx + 4);
  n = (uint32_t)mrb_integer(o);
  if (flags & PACK_FLAG_LITTLEENDIAN) {
    RSTRING_PTR(str)[sidx+0] = (char)(n & 0xff);
    RSTRING_PTR(str)[sidx+1] = (char)(n >> 8);
    RSTRING_PTR(str)[sidx+2] = (char)(n >> 16);
    RSTRING_PTR(str)[sidx+3] = (char)(n >> 24);
  } else {
    RSTRING_PTR(str)[sidx+0] = (char)(n >> 24);
    RSTRING_PTR(str)[sidx+1] = (char)(n >> 16);
    RSTRING_PTR(str)[sidx+2] = (char)(n >> 8);
    RSTRING_PTR(str)[sidx+3] = (char)(n & 0xff);
  }
  return 4;
}

#ifndef MRB_INT64
static void
u32tostr(char *buf, size_t len, uint32_t n)
{
#ifdef MRB_NO_STDIO
  char *bufend = buf + len;
  char *p = bufend - 1;

  if (len < 1) {
    return;
  }

  *p -- = '\0';
  len --;

  if (n > 0) {
    for (; len > 0 && n > 0; len --, n /= 10) {
      *p -- = '0' + (n % 10);
    }
    p ++;
  }
  else if (len > 0) {
    *p = '0';
    len --;
  }

  memmove(buf, p, bufend - p);
#else
  snprintf(buf, len, "%" PRIu32, n);
#endif /* MRB_NO_STDIO */
}
#endif /* MRB_INT64 */

static int
unpack_long(mrb_state *mrb, const unsigned char *src, int srclen, mrb_value ary, unsigned int flags)
{
#ifndef MRB_INT64
  char msg[60];
#endif
  uint32_t ul;
  mrb_int n;

  if (flags & PACK_FLAG_LITTLEENDIAN) {
    ul = (uint32_t)src[3] * 256*256*256;
    ul += (uint32_t)src[2] *256*256;
    ul += (uint32_t)src[1] *256;
    ul += (uint32_t)src[0];
  } else {
    ul = (uint32_t)src[0] * 256*256*256;
    ul += (uint32_t)src[1] *256*256;
    ul += (uint32_t)src[2] *256;
    ul += (uint32_t)src[3];
  }
  if (flags & PACK_FLAG_SIGNED) {
    n = (int32_t)ul;
  } else {
#ifndef MRB_INT64
    if (UINT_OVERFLOW_P(ul)) {
      u32tostr(msg, sizeof(msg), ul);
      mrb_raisef(mrb, E_RANGE_ERROR, "cannot unpack to Integer: %s", msg);
    }
#endif
    n = ul;
  }
  mrb_ary_push(mrb, ary, mrb_int_value(mrb, n));
  return 4;
}

static int
pack_quad(mrb_state *mrb, mrb_value o, mrb_value str, mrb_int sidx, unsigned int flags)
{
  uint64_t n;

  str = str_len_ensure(mrb, str, sidx + 8);
  n = (uint64_t)mrb_integer(o);
  if (flags & PACK_FLAG_LITTLEENDIAN) {
    RSTRING_PTR(str)[sidx+0] = (char)(n & 0xff);
    RSTRING_PTR(str)[sidx+1] = (char)(n >> 8);
    RSTRING_PTR(str)[sidx+2] = (char)(n >> 16);
    RSTRING_PTR(str)[sidx+3] = (char)(n >> 24);
    RSTRING_PTR(str)[sidx+4] = (char)(n >> 32);
    RSTRING_PTR(str)[sidx+5] = (char)(n >> 40);
    RSTRING_PTR(str)[sidx+6] = (char)(n >> 48);
    RSTRING_PTR(str)[sidx+7] = (char)(n >> 56);
  } else {
    RSTRING_PTR(str)[sidx+0] = (char)(n >> 56);
    RSTRING_PTR(str)[sidx+1] = (char)(n >> 48);
    RSTRING_PTR(str)[sidx+2] = (char)(n >> 40);
    RSTRING_PTR(str)[sidx+3] = (char)(n >> 32);
    RSTRING_PTR(str)[sidx+4] = (char)(n >> 24);
    RSTRING_PTR(str)[sidx+5] = (char)(n >> 16);
    RSTRING_PTR(str)[sidx+6] = (char)(n >> 8);
    RSTRING_PTR(str)[sidx+7] = (char)(n & 0xff);
  }
  return 8;
}

static void
u64tostr(char *buf, size_t len, uint64_t n)
{
#ifdef MRB_NO_STDIO
  char *bufend = buf + len;
  char *p = bufend - 1;

  if (len < 1) {
    return;
  }

  *p -- = '\0';
  len --;

  if (n > 0) {
    for (; len > 0 && n > 0; len --, n /= 10) {
      *p -- = '0' + (n % 10);
    }
    p ++;
  }
  else if (len > 0) {
    *p = '0';
    len --;
  }

  memmove(buf, p, bufend - p);
#else
  snprintf(buf, len, "%" PRIu64, n);
#endif /* MRB_NO_STDIO */
}

#ifndef MRB_INT64
static void
i64tostr(char *buf, size_t len, int64_t n)
{
#ifdef MRB_NO_STDIO
  if (len < 1) {
    return;
  }

  if (n < 0) {
    *buf ++ = '-';
    len --;
    n = -n;
  }

  u64tostr(buf, len, (uint64_t)n);
#else
  snprintf(buf, len, "%" PRId64, n);
#endif /* MRB_NO_STDIO */
}
#endif /* MRB_INT64 */

static int
unpack_quad(mrb_state *mrb, const unsigned char *src, int srclen, mrb_value ary, unsigned int flags)
{
  char msg[60];
  uint64_t ull;
  int i, pos, step;
  mrb_int n;

  if (flags & PACK_FLAG_LITTLEENDIAN) {
    pos  = 7;
    step = -1;
  } else {
    pos  = 0;
    step = 1;
  }
  ull = 0;
  for (i = 0; i < 8; i++) {
    ull = ull * 256 + (uint64_t)src[pos];
    pos += step;
  }
  if (flags & PACK_FLAG_SIGNED) {
    int64_t sll = ull;
#ifndef MRB_INT64
    if (INT_OVERFLOW_P(sll)) {
      i64tostr(msg, sizeof(msg), sll);
      mrb_raisef(mrb, E_RANGE_ERROR, "cannot unpack to Integer: %s", msg);
    }
#endif
    n = (mrb_int)sll;
  } else {
    if (UINT_OVERFLOW_P(ull)) {
      u64tostr(msg, sizeof(msg), ull);
      mrb_raisef(mrb, E_RANGE_ERROR, "cannot unpack to Integer: %s", msg);
    }
    n = (mrb_int)ull;
  }
  mrb_ary_push(mrb, ary, mrb_int_value(mrb, n));
  return 8;
}

static int
pack_BER(mrb_state *mrb, mrb_value o, mrb_value str, mrb_int sidx, unsigned int flags)
{
  mrb_int n = mrb_integer(o);
  size_t i;
  char *p;

  if (n < 0) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "can't compress negative numbers");
  }
  for (i=1; i<sizeof(mrb_int)+1; i++) {
    mrb_int mask = ~((1L<<(7*i))-1);
    if ((n & mask) == 0) break;
  }
  str = str_len_ensure(mrb, str, sidx + i);
  p = RSTRING_PTR(str)+sidx;
  for (size_t j=i; j>0; p++,j--) {
    mrb_int x = (n>>(7*(j-1)))&0x7f;
    *p = (char)x;
    if (j > 1) *p |= 0x80;
  }
  return i;
}

static int
unpack_BER(mrb_state *mrb, const unsigned char *src, int srclen, mrb_value ary, unsigned int flags)
{
  mrb_int i, n = 0;
  const unsigned char *p = src;
  const unsigned char *e = p + srclen;

  for (i=1; p<e; p++,i++) {
    if (n > (MRB_INT_MAX>>7)) {
      mrb_raise(mrb, E_RANGE_ERROR, "BER unpacking 'w' overflow");
    }
    n <<= 7;
    n |= *p & 0x7f;
    if ((*p & 0x80) == 0) break;
  }
  mrb_ary_push(mrb, ary, mrb_int_value(mrb, n));
  return i;
}

#ifndef MRB_NO_FLOAT
static int
pack_double(mrb_state *mrb, mrb_value o, mrb_value str, mrb_int sidx, unsigned int flags)
{
  int i;
  double d;
  uint8_t *buffer = (uint8_t *)&d;
  str = str_len_ensure(mrb, str, sidx + 8);
  d = mrb_float(o);

  if (flags & PACK_FLAG_LITTLEENDIAN) {
    if (littleendian) {
      memcpy(RSTRING_PTR(str) + sidx, buffer, 8);
    }
    else {
      for (i = 0; i < 8; ++i) {
        RSTRING_PTR(str)[sidx + i] = buffer[8 - i - 1];
      }
    }
  } else {
    if (littleendian) {
      for (i = 0; i < 8; ++i) {
        RSTRING_PTR(str)[sidx + i] = buffer[8 - i - 1];
      }
    }
    else {
      memcpy(RSTRING_PTR(str) + sidx, buffer, 8);
    }
  }

  return 8;
}

static int
unpack_double(mrb_state *mrb, const unsigned char * src, int srclen, mrb_value ary, unsigned int flags)
{
  int i;
  double d;
  uint8_t *buffer = (uint8_t *)&d;

  if (flags & PACK_FLAG_LITTLEENDIAN) {
    if (littleendian) {
      memcpy(buffer, src, 8);
    }
    else {
      for (i = 0; i < 8; ++i) {
        buffer[8 - i - 1] = src[i];
      }
    }
  } else {
    if (littleendian) {
      for (i = 0; i < 8; ++i) {
        buffer[8 - i - 1] = src[i];
      }
    }
    else {
      memcpy(buffer, src, 8);
    }
  }
  mrb_ary_push(mrb, ary, mrb_float_value(mrb, d));

  return 8;
}

static int
pack_float(mrb_state *mrb, mrb_value o, mrb_value str, mrb_int sidx, unsigned int flags)
{
  int i;
  float f;
  uint8_t *buffer = (uint8_t *)&f;
  str = str_len_ensure(mrb, str, sidx + 4);
  f = (float)mrb_float(o);

  if (flags & PACK_FLAG_LITTLEENDIAN) {
    if (littleendian) {
      memcpy(RSTRING_PTR(str) + sidx, buffer, 4);
    }
    else {
      for (i = 0; i < 4; ++i) {
        RSTRING_PTR(str)[sidx + i] = buffer[4 - i - 1];
      }
    }
  } else {
    if (littleendian) {
      for (i = 0; i < 4; ++i) {
        RSTRING_PTR(str)[sidx + i] = buffer[4 - i - 1];
      }
    }
    else {
      memcpy(RSTRING_PTR(str) + sidx, buffer, 4);
    }
  }

  return 4;
}

static int
unpack_float(mrb_state *mrb, const unsigned char * src, int srclen, mrb_value ary, unsigned int flags)
{
  int i;
  float f;
  uint8_t *buffer = (uint8_t *)&f;

  if (flags & PACK_FLAG_LITTLEENDIAN) {
    if (littleendian) {
      memcpy(buffer, src, 4);
    }
    else {
      for (i = 0; i < 4; ++i) {
        buffer[4 - i - 1] = src[i];
      }
    }
  } else {
    if (littleendian) {
      for (i = 0; i < 4; ++i) {
        buffer[4 - i - 1] = src[i];
      }
    }
    else {
      memcpy(buffer, src, 4);
    }
  }
  mrb_ary_push(mrb, ary, mrb_float_value(mrb, f));

  return 4;
}
#endif

static int
pack_utf8(mrb_state *mrb, mrb_value o, mrb_value str, mrb_int sidx, int count, unsigned int flags)
{
  char utf8[4];
  int len = 0;
  uint32_t c = 0;

  c = (uint32_t)mrb_integer(o);

  /* Unicode character */
  /* from mruby-compiler gem */
  if (c < 0x80) {
    utf8[0] = (char)c;
    len = 1;
  }
  else if (c < 0x800) {
    utf8[0] = (char)(0xC0 | (c >> 6));
    utf8[1] = (char)(0x80 | (c & 0x3F));
    len = 2;
  }
  else if (c < 0x10000) {
    utf8[0] = (char)(0xE0 |  (c >> 12)        );
    utf8[1] = (char)(0x80 | ((c >>  6) & 0x3F));
    utf8[2] = (char)(0x80 | ( c        & 0x3F));
    len = 3;
  }
  else if (c < 0x200000) {
    utf8[0] = (char)(0xF0 |  (c >> 18)        );
    utf8[1] = (char)(0x80 | ((c >> 12) & 0x3F));
    utf8[2] = (char)(0x80 | ((c >>  6) & 0x3F));
    utf8[3] = (char)(0x80 | ( c        & 0x3F));
    len = 4;
  }
  else {
    mrb_raise(mrb, E_RANGE_ERROR, "pack(U): value out of range");
  }

  str = str_len_ensure(mrb, str, sidx + len);
  memcpy(RSTRING_PTR(str) + sidx, utf8, len);

  return len;
}

static const unsigned long utf8_limits[] = {
  0x0,        /* 1 */
  0x80,       /* 2 */
  0x800,      /* 3 */
  0x10000,    /* 4 */
  0x200000,   /* 5 */
  0x4000000,  /* 6 */
  0x80000000, /* 7 */
};

static unsigned long
utf8_to_uv(mrb_state *mrb, const char *p, long *lenp)
{
  int c = *p++ & 0xff;
  unsigned long uv = c;
  long n = 1;

  if (!(uv & 0x80)) {
    *lenp = 1;
    return uv;
  }
  if (!(uv & 0x40)) {
    *lenp = 1;
    mrb_raise(mrb, E_ARGUMENT_ERROR, "malformed UTF-8 character");
  }

  if      (!(uv & 0x20)) { n = 2; uv &= 0x1f; }
  else if (!(uv & 0x10)) { n = 3; uv &= 0x0f; }
  else if (!(uv & 0x08)) { n = 4; uv &= 0x07; }
  else if (!(uv & 0x04)) { n = 5; uv &= 0x03; }
  else if (!(uv & 0x02)) { n = 6; uv &= 0x01; }
  else {
    *lenp = 1;
    mrb_raise(mrb, E_ARGUMENT_ERROR, "malformed UTF-8 character");
  }
  if (n > *lenp) {
    mrb_raisef(mrb, E_ARGUMENT_ERROR, "malformed UTF-8 character (expected %d bytes, given %d bytes)",
               n, *lenp);
  }
  *lenp = n--;
  if (n != 0) {
    while (n--) {
      c = *p++ & 0xff;
      if ((c & 0xc0) != 0x80) {
        *lenp -= n + 1;
        mrb_raise(mrb, E_ARGUMENT_ERROR, "malformed UTF-8 character");
      }
      else {
        c &= 0x3f;
        uv = uv << 6 | c;
      }
    }
  }
  n = *lenp - 1;
  if (uv < utf8_limits[n]) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "redundant UTF-8 sequence");
  }
  return uv;
}

static int
unpack_utf8(mrb_state *mrb, const unsigned char * src, int srclen, mrb_value ary, unsigned int flags)
{
  unsigned long uv;
  long lenp = srclen;

  if (srclen == 0) {
    return 1;
  }
  uv = utf8_to_uv(mrb, (const char *)src, &lenp);
  mrb_ary_push(mrb, ary, mrb_fixnum_value((mrb_int)uv));
  return (int)lenp;
}

static int
pack_str(mrb_state *mrb, mrb_value src, mrb_value dst, mrb_int didx, int count, unsigned int flags)
{
  mrb_int copylen, slen, padlen;
  char *dptr, *dptr0, pad, *sptr;

  sptr = RSTRING_PTR(src);
  slen = RSTRING_LEN(src);

  if ((flags & PACK_FLAG_a) || (flags & PACK_FLAG_Z))
    pad = '\0';
  else
    pad = ' ';

  if (count == 0) {
    return 0;
  } else if (count == -1) {
    copylen = slen;
    padlen = (flags & PACK_FLAG_Z) ? 1 : 0;
  } else if (count < slen) {
    copylen = count;
    padlen = 0;
  } else {
    copylen = slen;
    padlen = count - slen;
  }

  dst = str_len_ensure(mrb, dst, didx + copylen + padlen);
  dptr0 = dptr = RSTRING_PTR(dst) + didx;
  memcpy(dptr, sptr, copylen);
  dptr += copylen;
  while (padlen-- > 0) {
    *dptr++ = pad;
  }

  return (int)(dptr - dptr0);
}

static int
unpack_str(mrb_state *mrb, const void *src, int slen, mrb_value ary, int count, unsigned int flags)
{
  mrb_value dst;
  const char *cp, *sptr;
  int copylen;

  sptr = (const char *)src;
  if (count != -1 && count < slen)  {
    slen = count;
  }
  copylen = slen;

  if (slen >= 0 && flags & PACK_FLAG_Z) {  /* "Z" */
    if ((cp = (const char *)memchr(sptr, '\0', slen)) != NULL) {
      copylen = (int)(cp - sptr);
      if (count == -1) {
        slen = copylen + 1;
      }
    }
  }
  else if (!(flags & PACK_FLAG_a)) {  /* "A" */
    while (copylen > 0 && (sptr[copylen - 1] == '\0' || ISSPACE(sptr[copylen - 1]))) {
      copylen--;
    }
  }

  if (copylen < 0) copylen = 0;
  dst = mrb_str_new(mrb, sptr, (mrb_int)copylen);
  mrb_ary_push(mrb, ary, dst);
  return slen;
}


static int
pack_hex(mrb_state *mrb, mrb_value src, mrb_value dst, mrb_int didx, int count, unsigned int flags)
{
  unsigned int a, ashift, b, bshift;
  long slen;
  char *dptr, *dptr0, *sptr;

  sptr = RSTRING_PTR(src);
  slen = (long)RSTRING_LEN(src);

  if (flags & PACK_FLAG_LSB) {
    ashift = 0;
    bshift = 4;
  } else {
    ashift = 4;
    bshift = 0;
  }

  if (count == -1) {
    count = slen;
  } else if (slen > count) {
    slen = count;
  }

  dst = str_len_ensure(mrb, dst, didx + count);
  dptr = RSTRING_PTR(dst) + didx;

  dptr0 = dptr;
  for (; count > 0; count -= 2) {
    a = b = 0;
    if (slen > 0) {
      a = hex2int(*sptr++);
      if (a < 0) break;
      slen--;
    }
    if (slen > 0) {
      b = hex2int(*sptr++);
      if (b < 0) break;
      slen--;
    }
    *dptr++ = (a << ashift) + (b << bshift);
  }

  return (int)(dptr - dptr0);
}

static int
unpack_hex(mrb_state *mrb, const void *src, int slen, mrb_value ary, int count, unsigned int flags)
{
  mrb_value dst;
  int a, ashift, b, bshift;
  const char *sptr, *sptr0;
  char *dptr, *dptr0;
  const char hexadecimal[] = "0123456789abcdef";

  if (flags & PACK_FLAG_LSB) {
    ashift = 0;
    bshift = 4;
  } else {
    ashift = 4;
    bshift = 0;
  }

  sptr = (const char *)src;

  if (count == -1)
    count = slen * 2;

  dst = mrb_str_new(mrb, NULL, count);
  dptr = RSTRING_PTR(dst);

  sptr0 = sptr;
  dptr0 = dptr;
  while (slen > 0 && count > 0) {
    a = (*sptr >> ashift) & 0x0f;
    b = (*sptr >> bshift) & 0x0f;
    sptr++;
    slen--;

    *dptr++ = hexadecimal[a];
    count--;

    if (count > 0) {
      *dptr++ = hexadecimal[b];
      count--;
    }
  }

  dst = mrb_str_resize(mrb, dst, (mrb_int)(dptr - dptr0));
  mrb_ary_push(mrb, ary, dst);
  return (int)(sptr - sptr0);
}

static int
pack_base64(mrb_state *mrb, mrb_value src, mrb_value dst, mrb_int didx, int count)
{
  mrb_int dstlen;
  unsigned long l;
  mrb_int column, srclen;
  char *srcptr, *dstptr, *dstptr0;

  srcptr = RSTRING_PTR(src);
  srclen = RSTRING_LEN(src);

  if (srclen == 0)  /* easy case */
    return 0;

  if (count != 0 && count < 3) {  /* -1, 1 or 2 */
    count = 45;
  } else if (count >= 3) {
    count -= count % 3;
  }

  dstlen = (srclen+2) / 3 * 4;
  if (count > 0) {
    dstlen += (srclen / count) + ((srclen % count) == 0 ? 0 : 1);
  }
  dst = str_len_ensure(mrb, dst, didx + dstlen);
  dstptr = RSTRING_PTR(dst) + didx;

  dstptr0 = dstptr;
  for (column = 3; srclen >= 3; srclen -= 3, column += 3) {
    l = (unsigned char)*srcptr++ << 16;
    l += (unsigned char)*srcptr++ << 8;
    l += (unsigned char)*srcptr++;

    *dstptr++ = base64chars[(l >> 18) & 0x3f];
    *dstptr++ = base64chars[(l >> 12) & 0x3f];
    *dstptr++ = base64chars[(l >>  6) & 0x3f];
    *dstptr++ = base64chars[ l        & 0x3f];

    if (column == count) {
      *dstptr++ = '\n';
      column = 0;
    }
  }
  if (srclen == 1) {
    l = (unsigned char)*srcptr++ << 16;
    *dstptr++ = base64chars[(l >> 18) & 0x3f];
    *dstptr++ = base64chars[(l >> 12) & 0x3f];
    *dstptr++ = '=';
    *dstptr++ = '=';
    column += 3;
  } else if (srclen == 2) {
    l = (unsigned char)*srcptr++ << 16;
    l += (unsigned char)*srcptr++ << 8;
    *dstptr++ = base64chars[(l >> 18) & 0x3f];
    *dstptr++ = base64chars[(l >> 12) & 0x3f];
    *dstptr++ = base64chars[(l >>  6) & 0x3f];
    *dstptr++ = '=';
    column += 3;
  }
  if (column > 0 && count > 0) {
    *dstptr++ = '\n';
  }

  return (int)(dstptr - dstptr0);
}

static int
unpack_base64(mrb_state *mrb, const void *src, int slen, mrb_value ary)
{
  mrb_value dst;
  int dlen;
  unsigned long l;
  int i, padding;
  unsigned char c, ch[4];
  const char *sptr, *sptr0;
  char *dptr, *dptr0;

  sptr0 = sptr = (const char *)src;

  dlen = slen / 4 * 3;  /* an estimated value - may be shorter */
  dst = mrb_str_new(mrb, NULL, dlen);
  dptr0 = dptr = RSTRING_PTR(dst);

  padding = 0;
  while (slen >= 4) {
    for (i = 0; i < 4; i++) {
      do {
        if (slen-- == 0)
          goto done;
        c = *sptr++;
        if (c >= sizeof(base64_dec_tab))
          continue;
        ch[i] = base64_dec_tab[c];
        if (ch[i] == PACK_BASE64_PADDING) {
          ch[i] = 0;
          padding++;
        }
      } while (c >= sizeof(base64_dec_tab) || ch[i] == PACK_BASE64_IGNORE);
    }

    l = (ch[0] << 18) + (ch[1] << 12) + (ch[2] << 6) + ch[3];

    if (padding == 0) {
      *dptr++ = (l >> 16) & 0xff;
      *dptr++ = (l >> 8) & 0xff;
      *dptr++ = l & 0xff;
    } else if (padding == 1) {
      *dptr++ = (l >> 16) & 0xff;
      *dptr++ = (l >> 8) & 0xff;
      break;
    } else {
      *dptr++ = (l >> 16) & 0xff;
      break;
    }
  }

done:
  dst = mrb_str_resize(mrb, dst, (mrb_int)(dptr - dptr0));
  mrb_ary_push(mrb, ary, dst);
  return (int)(sptr - sptr0);
}

static int
pack_qenc(mrb_state *mrb, mrb_value src, mrb_value dst, mrb_int didx, int count)
{
  static const char hex_table[] = "0123456789ABCDEF";
  char buff[1024];
  char *s = RSTRING_PTR(src);
  char *send = s + RSTRING_LEN(src);
  int i = 0, n = 0, prev = EOF;
  int dlen = 0;

  if (count <= 1) count = 72;
  while (s < send) {
    if ((*s > 126) ||
        (*s < 32 && *s != '\n' && *s != '\t') ||
        (*s == '=')) {
      buff[i++] = '=';
      buff[i++] = hex_table[(*s & 0xf0) >> 4];
      buff[i++] = hex_table[*s & 0x0f];
      n += 3;
      prev = EOF;
    }
    else if (*s == '\n') {
      if (prev == ' ' || prev == '\t') {
        buff[i++] = '=';
        buff[i++] = *s;
      }
      buff[i++] = *s;
      n = 0;
      prev = *s;
    }
    else {
      buff[i++] = *s;
      n++;
      prev = *s;
    }
    if (n > count) {
      buff[i++] = '=';
      buff[i++] = '\n';
      n = 0;
      prev = '\n';
    }
    if (i > 1024 - 5) {
      str_len_ensure(mrb, dst, didx+dlen+i);
      memcpy(RSTRING_PTR(dst)+didx+dlen, buff, i);
      dlen += i;
      i = 0;
    }
    s++;
  }
  if (n > 0) {
    buff[i++] = '=';
    buff[i++] = '\n';
  }
  if (i > 0) {
    str_len_ensure(mrb, dst, didx+dlen+i);
    memcpy(RSTRING_PTR(dst)+didx+dlen, buff, i);
    dlen += i;
  }
  return dlen;
}

static int
unpack_qenc(mrb_state *mrb, const void *src, int slen, mrb_value ary)
{
  mrb_value buf = mrb_str_new(mrb, 0, slen);
  const char *s = (const char*)src, *ss = s;
  const char *send = s + slen;
  char *ptr = RSTRING_PTR(buf);
  int c1, c2;

  while (s < send) {
    if (*s == '=') {
      if (++s == send) break;
      if (s+1 < send && *s == '\r' && *(s+1) == '\n')
        s++;
      if (*s != '\n') {
        if ((c1 = hex2int(*s)) == -1) break;
        if (++s == send) break;
        if ((c2 = hex2int(*s)) == -1) break;
        *ptr++ = (char)(c1 << 4 | c2);
      }
    }
    else {
      *ptr++ = *s;
    }
    s++;
    ss = s;
  }
  buf = mrb_str_resize(mrb, buf, (mrb_int)(ptr - RSTRING_PTR(buf)));
  mrb_str_cat(mrb, buf, ss, send-ss);
  mrb_ary_push(mrb, ary, buf);
  return slen;
}

static int
pack_nul(mrb_state *mrb, mrb_value dst, mrb_int didx, int count)
{
  long i;

  dst = str_len_ensure(mrb, dst, didx + count);
  for (i = 0; i < count; i++) {
    RSTRING_PTR(dst)[didx + i] = '\0';
  }
  return count;
}

static void
check_x(mrb_state *mrb, int a, int count, char c)
{
  if (a < count) {
    mrb_raisef(mrb, E_ARGUMENT_ERROR, "%c outside of string", c);
  }
}

static void
prepare_tmpl(mrb_state *mrb, struct tmpl *tmpl)
{
  mrb_get_args(mrb, "S", &tmpl->str);
  tmpl->idx = 0;
}

static int
has_tmpl(const struct tmpl *tmpl)
{
  return (tmpl->idx < RSTRING_LEN(tmpl->str));
}

static void
read_tmpl(mrb_state *mrb, struct tmpl *tmpl, enum pack_dir *dirp, enum pack_type *typep, int *sizep, int *countp, unsigned int *flagsp)
{
  mrb_int t, tlen;
  int ch, size = 0;
  enum pack_dir dir;
  enum pack_type type;
  int count = 1;
  unsigned int flags = 0;
  const char *tptr;

  tptr = RSTRING_PTR(tmpl->str);
  tlen = RSTRING_LEN(tmpl->str);

  t = tptr[tmpl->idx++];
alias:
  switch (t) {
  case 'A':
    dir = PACK_DIR_STR;
    type = PACK_TYPE_STRING;
    flags |= PACK_FLAG_WIDTH | PACK_FLAG_COUNT2;
    break;
  case 'a':
    dir = PACK_DIR_STR;
    type = PACK_TYPE_STRING;
    flags |= PACK_FLAG_WIDTH | PACK_FLAG_COUNT2 | PACK_FLAG_a;
    break;
  case 'C':
    dir = PACK_DIR_CHAR;
    type = PACK_TYPE_INTEGER;
    size = 1;
    break;
  case 'c':
    dir = PACK_DIR_CHAR;
    type = PACK_TYPE_INTEGER;
    size = 1;
    flags |= PACK_FLAG_SIGNED;
    break;
  case 'D': case 'd':
    dir = PACK_DIR_DOUBLE;
    type = PACK_TYPE_FLOAT;
    size = 8;
    flags |= PACK_FLAG_SIGNED;
    break;
  case 'F': case 'f':
    dir = PACK_DIR_FLOAT;
    type = PACK_TYPE_FLOAT;
    size = 4;
    flags |= PACK_FLAG_SIGNED;
    break;
  case 'E':
    dir = PACK_DIR_DOUBLE;
    type = PACK_TYPE_FLOAT;
    size = 8;
    flags |= PACK_FLAG_SIGNED | PACK_FLAG_LT;
    break;
  case 'e':
    dir = PACK_DIR_FLOAT;
    type = PACK_TYPE_FLOAT;
    size = 4;
    flags |= PACK_FLAG_SIGNED | PACK_FLAG_LT;
    break;
  case 'G':
    dir = PACK_DIR_DOUBLE;
    type = PACK_TYPE_FLOAT;
    size = 8;
    flags |= PACK_FLAG_SIGNED | PACK_FLAG_GT;
    break;
  case 'g':
    dir = PACK_DIR_FLOAT;
    type = PACK_TYPE_FLOAT;
    size = 4;
    flags |= PACK_FLAG_SIGNED | PACK_FLAG_GT;
    break;
  case 'H':
    dir = PACK_DIR_HEX;
    type = PACK_TYPE_STRING;
    flags |= PACK_FLAG_COUNT2;
    break;
  case 'h':
    dir = PACK_DIR_HEX;
    type = PACK_TYPE_STRING;
    flags |= PACK_FLAG_COUNT2 | PACK_FLAG_LSB;
    break;
  case 'I':
    switch (sizeof(int)) {
      case 2: t = 'S'; goto alias;
      case 4: t = 'L'; goto alias;
      case 8: t = 'Q'; goto alias;
      default:
        mrb_raisef(mrb, E_RUNTIME_ERROR, "mruby-pack does not support sizeof(int) == %d", (int)sizeof(int));
    }
    break;
  case 'i':
    switch (sizeof(int)) {
      case 2: t = 's'; goto alias;
      case 4: t = 'l'; goto alias;
      case 8: t = 'q'; goto alias;
      default:
        mrb_raisef(mrb, E_RUNTIME_ERROR, "mruby-pack does not support sizeof(int) == %d", (int)sizeof(int));
    }
    break;
  case 'L':
    dir = PACK_DIR_LONG;
    type = PACK_TYPE_INTEGER;
    size = 4;
    break;
  case 'l':
    dir = PACK_DIR_LONG;
    type = PACK_TYPE_INTEGER;
    size = 4;
    flags |= PACK_FLAG_SIGNED;
    break;
  case 'w':
    dir = PACK_DIR_BER;
    type = PACK_TYPE_INTEGER;
    flags |= PACK_FLAG_SIGNED;
    break;
  case 'm':
    dir = PACK_DIR_BASE64;
    type = PACK_TYPE_STRING;
    flags |= PACK_FLAG_WIDTH | PACK_FLAG_COUNT2;
    break;
  case 'M':
    dir = PACK_DIR_QENC;
    type = PACK_TYPE_STRING;
    flags |= PACK_FLAG_WIDTH | PACK_FLAG_COUNT2;
    break;
  case 'N':  /* = "L>" */
    dir = PACK_DIR_LONG;
    type = PACK_TYPE_INTEGER;
    size = 4;
    flags |= PACK_FLAG_GT;
    break;
  case 'n':  /* = "S>" */
    dir = PACK_DIR_SHORT;
    type = PACK_TYPE_INTEGER;
    size = 2;
    flags |= PACK_FLAG_GT;
    break;
  case 'Q':
    dir = PACK_DIR_QUAD;
    type = PACK_TYPE_INTEGER;
    size = 8;
    break;
  case 'q':
    dir = PACK_DIR_QUAD;
    type = PACK_TYPE_INTEGER;
    size = 8;
    flags |= PACK_FLAG_SIGNED;
    break;
  case 'S':
    dir = PACK_DIR_SHORT;
    type = PACK_TYPE_INTEGER;
    size = 2;
    break;
  case 's':
    dir = PACK_DIR_SHORT;
    type = PACK_TYPE_INTEGER;
    size = 2;
    flags |= PACK_FLAG_SIGNED;
    break;
  case 'U':
    dir = PACK_DIR_UTF8;
    type = PACK_TYPE_INTEGER;
    break;
  case 'V':  /* = "L<" */
    dir = PACK_DIR_LONG;
    type = PACK_TYPE_INTEGER;
    size = 4;
    flags |= PACK_FLAG_LT;
    break;
  case 'v':  /* = "S<" */
    dir = PACK_DIR_SHORT;
    type = PACK_TYPE_INTEGER;
    size = 2;
    flags |= PACK_FLAG_LT;
    break;
  case 'x':
    dir = PACK_DIR_NUL;
    type = PACK_TYPE_NONE;
    break;
  case 'X':
    dir = PACK_DIR_BACK;
    type = PACK_TYPE_NONE;
    break;
  case '@':
    dir = PACK_DIR_ABS;
    type = PACK_TYPE_NONE;
    break;
  case 'Z':
    dir = PACK_DIR_STR;
    type = PACK_TYPE_STRING;
    flags |= PACK_FLAG_WIDTH | PACK_FLAG_COUNT2 | PACK_FLAG_Z;
    break;
  case 'p': case 'P':
  case '%':
    mrb_raisef(mrb, E_ARGUMENT_ERROR, "%c is not supported", (char)t);
    break;
  default:
    dir = PACK_DIR_INVALID;
    type = PACK_TYPE_NONE;
    break;
  }

  /* read suffix [0-9*_!<>] */
  while (tmpl->idx < tlen) {
    ch = tptr[tmpl->idx];
    if (ISDIGIT(ch)) {
      char *e;
      mrb_int n = mrb_int_read(tptr+tmpl->idx, tptr+tlen, &e);
      if (e == NULL || n > INT_MAX) {
        mrb_raise(mrb, E_RUNTIME_ERROR, "too big template length");
      }
      count = (int)n;
      tmpl->idx = e - tptr;
      continue;
    } else if (ch == '*')  {
      if (type == PACK_TYPE_NONE)
        count = 0;
      else
        count = -1;
    } else if (ch == '_' || ch == '!' || ch == '<' || ch == '>') {
      if (strchr("sSiIlLqQ", (int)t) == NULL) {
        mrb_raisef(mrb, E_ARGUMENT_ERROR, "'%c' allowed only after types sSiIlLqQ", ch);
      }
      if (ch == '_' || ch == '!') {
        flags |= PACK_FLAG_s;
      } else if (ch == '<') {
        flags |= PACK_FLAG_LT;
      } else if (ch == '>') {
        flags |= PACK_FLAG_GT;
      }
    }
    else {
      break;
    }
    tmpl->idx++;
  }

  if ((flags & PACK_FLAG_LT) || (!(flags & PACK_FLAG_GT) && littleendian)) {
    flags |= PACK_FLAG_LITTLEENDIAN;
  }

  *dirp = dir;
  *typep = type;
  *sizep = size;
  *countp = count;
  *flagsp = flags;
}

static mrb_value
mrb_pack_pack(mrb_state *mrb, mrb_value ary)
{
  mrb_value o, result;
  mrb_int aidx;
  struct tmpl tmpl;
  int count;
  unsigned int flags;
  enum pack_dir dir;
  enum pack_type type;
  int ridx, size;

  prepare_tmpl(mrb, &tmpl);

  result = mrb_str_new(mrb, NULL, 128);  /* allocate initial buffer */
  aidx = 0;
  ridx = 0;
  while (has_tmpl(&tmpl)) {
    read_tmpl(mrb, &tmpl, &dir, &type, &size, &count, &flags);

    if (dir == PACK_DIR_INVALID)
      continue;
    else if (dir == PACK_DIR_NUL) {
    grow:
      if (ridx > INT_MAX - count) goto overflow;
      ridx += pack_nul(mrb, result, ridx, count);
      continue;
    }
    else if (dir == PACK_DIR_BACK) {
      check_x(mrb, ridx, count, 'X');
      ridx -= count;
      continue;
    }
    else if (dir == PACK_DIR_ABS) {
      count -= ridx;
      if (count > 0) goto grow;
      count = -count;
      check_x(mrb, ridx, count, '@');
      ridx -= count;
      continue;
    }

    if ((flags & PACK_FLAG_WIDTH) && aidx >= RARRAY_LEN(ary)) {
      mrb_raise(mrb, E_ARGUMENT_ERROR, "too few arguments");
    }
    for (; aidx < RARRAY_LEN(ary); aidx++) {
      if (count == 0 && !(flags & PACK_FLAG_WIDTH))
        break;

      o = mrb_ary_ref(mrb, ary, aidx);
      if (type == PACK_TYPE_INTEGER) {
        o = mrb_to_integer(mrb, o);
      }
#ifndef MRB_NO_FLOAT
      else if (type == PACK_TYPE_FLOAT) {
        if (!mrb_float_p(o)) {
          mrb_float f = mrb_as_float(mrb, o);
          o = mrb_float_value(mrb, f);
        }
      }
#endif
      else if (type == PACK_TYPE_STRING) {
        if (!mrb_string_p(o)) {
          mrb_raisef(mrb, E_TYPE_ERROR, "can't convert %T into String", o);
        }
      }

      switch (dir) {
      case PACK_DIR_CHAR:
        ridx += pack_char(mrb, o, result, ridx, flags);
        break;
      case PACK_DIR_SHORT:
        ridx += pack_short(mrb, o, result, ridx, flags);
        break;
      case PACK_DIR_LONG:
        ridx += pack_long(mrb, o, result, ridx, flags);
        break;
      case PACK_DIR_QUAD:
        ridx += pack_quad(mrb, o, result, ridx, flags);
        break;
      case PACK_DIR_BER:
        ridx += pack_BER(mrb, o, result, ridx, flags);
        break;
      case PACK_DIR_BASE64:
        ridx += pack_base64(mrb, o, result, ridx, count);
        break;
      case PACK_DIR_QENC:
        ridx += pack_qenc(mrb, o, result, ridx, count);
        break;
      case PACK_DIR_HEX:
        ridx += pack_hex(mrb, o, result, ridx, count, flags);
        break;
      case PACK_DIR_STR:
        ridx += pack_str(mrb, o, result, ridx, count, flags);
        break;
#ifndef MRB_NO_FLOAT
      case PACK_DIR_DOUBLE:
        ridx += pack_double(mrb, o, result, ridx, flags);
        break;
      case PACK_DIR_FLOAT:
        ridx += pack_float(mrb, o, result, ridx, flags);
        break;
#endif
      case PACK_DIR_UTF8:
        ridx += pack_utf8(mrb, o, result, ridx, count, flags);
        break;
      default:
        break;
      }
      if (flags & PACK_FLAG_COUNT2) {
        /* always consumes 1 entry */
        aidx++;
        break;
      }
      if (count > 0) {
        count--;
      }
    }
    if (ridx < 0) {
    overflow:
      mrb_raise(mrb, E_RANGE_ERROR, "negative (or overflowed) template size");
    }
  }

  mrb_str_resize(mrb, result, ridx);
  return result;
}

static mrb_value
pack_unpack(mrb_state *mrb, mrb_value str, int single)
{
  mrb_value result;
  struct tmpl tmpl;
  int count;
  unsigned int flags;
  enum pack_dir dir;
  enum pack_type type;
  int size;
  int srcidx, srclen;
  const unsigned char *sptr;

  prepare_tmpl(mrb, &tmpl);

  srcidx = 0;
  srclen = (int)RSTRING_LEN(str);

  result = mrb_ary_new(mrb);
  while (has_tmpl(&tmpl)) {
    read_tmpl(mrb, &tmpl, &dir, &type, &size, &count, &flags);

    if (dir == PACK_DIR_INVALID)
      continue;
    else if (dir == PACK_DIR_NUL) {
      check_x(mrb, srclen-srcidx, count, 'x');
      srcidx += count;
      continue;
    }
    else if (dir == PACK_DIR_BACK) {
      check_x(mrb, srcidx, count, 'X');
      srcidx -= count;
      continue;
    }
    else if (dir == PACK_DIR_ABS) {
      check_x(mrb, srclen, count, '@');
      srcidx = count;
      continue;
    }

    /* PACK_FLAG_COUNT2 directions */
    sptr = (const unsigned char *)RSTRING_PTR(str) + srcidx;
    switch (dir) {
    case PACK_DIR_HEX:
      srcidx += unpack_hex(mrb, sptr, srclen - srcidx, result, count, flags);
      continue;
    case PACK_DIR_STR:
      srcidx += unpack_str(mrb, sptr, srclen - srcidx, result, count, flags);
      continue;
    case PACK_DIR_BASE64:
      srcidx += unpack_base64(mrb, sptr, srclen - srcidx, result);
      continue;
      break;
    case PACK_DIR_QENC:
      srcidx += unpack_qenc(mrb, sptr, srclen - srcidx, result);
      continue;
    default:
      break;
    }

    while (count != 0) {
      if (srclen - srcidx < size) {
        while (count-- > 0) {
          mrb_ary_push(mrb, result, mrb_nil_value());
        }
        break;
      }

      sptr = (const unsigned char*)RSTRING_PTR(str) + srcidx;
      switch (dir) {
      case PACK_DIR_CHAR:
        srcidx += unpack_char(mrb, sptr, srclen - srcidx, result, flags);
        break;
      case PACK_DIR_SHORT:
        srcidx += unpack_short(mrb, sptr, srclen - srcidx, result, flags);
        break;
      case PACK_DIR_LONG:
        srcidx += unpack_long(mrb, sptr, srclen - srcidx, result, flags);
        break;
      case PACK_DIR_QUAD:
        srcidx += unpack_quad(mrb, sptr, srclen - srcidx, result, flags);
        break;
      case PACK_DIR_BER:
        srcidx += unpack_BER(mrb, sptr, srclen - srcidx, result, flags);
        break;
#ifndef MRB_NO_FLOAT
      case PACK_DIR_FLOAT:
        srcidx += unpack_float(mrb, sptr, srclen - srcidx, result, flags);
        break;
      case PACK_DIR_DOUBLE:
        srcidx += unpack_double(mrb, sptr, srclen - srcidx, result, flags);
        break;
#endif
      case PACK_DIR_UTF8:
        srcidx += unpack_utf8(mrb, sptr, srclen - srcidx, result, flags);
        break;
      default:
        mrb_raise(mrb, E_RUNTIME_ERROR, "mruby-pack's bug");
      }
      if (count > 0) {
        count--;
      }
    }
    if (single) break;
  }

  if (single) {
    if (RARRAY_LEN(result) > 0) {
      return RARRAY_PTR(result)[0];
    }
    return mrb_nil_value();
  }
  return result;
}

static mrb_value
mrb_pack_unpack(mrb_state *mrb, mrb_value str)
{
  return pack_unpack(mrb, str, 0);
}

static mrb_value
mrb_pack_unpack1(mrb_state *mrb, mrb_value str)
{
  return pack_unpack(mrb, str, 1);
}

void
mrb_mruby_pack_gem_init(mrb_state *mrb)
{
  make_base64_dec_tab();

  mrb_define_method(mrb, mrb->array_class, "pack", mrb_pack_pack, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, mrb->string_class, "unpack", mrb_pack_unpack, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, mrb->string_class, "unpack1", mrb_pack_unpack1, MRB_ARGS_REQ(1));
}

void
mrb_mruby_pack_gem_final(mrb_state *mrb)
{
}
