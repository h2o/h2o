/* This is based on tweetnacl.  Some typedefs have been
 * replaced with their stdint equivalents.
 *
 * Original code was public domain. */

#include <stdint.h>
#include <stddef.h>

#include "handy.h"

typedef int64_t gf[16];

static const uint8_t _0[16],
                     _9[32] = {9};
static const gf gf0,
                gf1 = {1},
                _121665 = {0xDB41, 1},
                D = {0x78a3, 0x1359, 0x4dca, 0x75eb,
                     0xd8ab, 0x4141, 0x0a4d, 0x0070,
                     0xe898, 0x7779, 0x4079, 0x8cc7,
                     0xfe73, 0x2b6f, 0x6cee, 0x5203},
                D2 = {0xf159, 0x26b2, 0x9b94, 0xebd6,
                      0xb156, 0x8283, 0x149a, 0x00e0,
                      0xd130, 0xeef3, 0x80f2, 0x198e,
                      0xfce7, 0x56df, 0xd9dc, 0x2406},
                X = {0xd51a, 0x8f25, 0x2d60, 0xc956,
                     0xa7b2, 0x9525, 0xc760, 0x692c,
                     0xdc5c, 0xfdd6, 0xe231, 0xc0a4,
                     0x53fe, 0xcd6e, 0x36d3, 0x2169},
                Y = {0x6658, 0x6666, 0x6666, 0x6666,
                     0x6666, 0x6666, 0x6666, 0x6666,
                     0x6666, 0x6666, 0x6666, 0x6666,
                     0x6666, 0x6666, 0x6666, 0x6666},
                I = {0xa0b0, 0x4a0e, 0x1b27, 0xc4ee,
                     0xe478, 0xad2f, 0x1806, 0x2f43,
                     0xd7a7, 0x3dfb, 0x0099, 0x2b4d,
                     0xdf0b, 0x4fc1, 0x2480, 0x2b83};

static void set25519(gf r, const gf a)
{
  size_t i;
  for (i = 0; i < 16; i++)
    r[i] = a[i];
}

static void car25519(gf o)
{
  int64_t c;
  size_t i;

  for (i = 0; i < 16; i++)
  {
    o[i] += (1LL << 16);
    c = o[i] >> 16;
    o[(i + 1) * (i < 15)] += c - 1 + 37 * (c - 1) * (i == 15);
    o[i] -= (int64_t)((uint64_t)c << 16);
  }
}

static void sel25519(gf p, gf q, int64_t b)
{
  int64_t tmp, mask = ~(b-1);
  size_t i;
  for (i = 0; i < 16; i++)
  {
    tmp = mask & (p[i] ^ q[i]);
    p[i] ^= tmp;
    q[i] ^= tmp;
  }
}

static void pack25519(uint8_t out[32], const gf n)
{
  size_t i, j;
  int b;
  gf m, t;
  set25519(t, n);
  car25519(t);
  car25519(t);
  car25519(t);

  for(j = 0; j < 2; j++)
  {
    m[0] = t[0] - 0xffed;
    for (i = 1; i < 15; i++)
    {
      m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
      m[i - 1] &= 0xffff;
    }
    m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
    b = (m[15] >> 16) & 1;
    m[14] &= 0xffff;
    sel25519(t, m, 1 - b);
  }

  for (i = 0; i < 16; i++)
  {
    out[2 * i] = t[i] & 0xff;
    out[2 * i + 1] = (uint8_t) (t[i] >> 8);
  }
}



static void unpack25519(gf o, const uint8_t *n)
{
  size_t i;
  for (i = 0; i < 16; i++)
    o[i] = n[2 * i] + ((int64_t) n[2 * i + 1] << 8);
  o[15] &= 0x7fff;
}

static void add(gf o, const gf a, const gf b)
{
  size_t i;
  for (i = 0; i < 16; i++)
    o[i] = a[i] + b[i];
}

static void sub(gf o, const gf a, const gf b)
{
  size_t i;
  for (i = 0; i < 16; i++)
    o[i] = a[i] - b[i];
}

static void mul(gf o, const gf a, const gf b)
{
  int64_t t[31];
  size_t i, j;

  for (i = 0; i < 31; i++)
    t[i] = 0;

  for (i = 0; i < 16; i++)
    for (j = 0; j < 16; j++)
      t[i + j] += a[i] * b[j];

  for (i = 0; i < 15; i++)
    t[i] += 38 * t[i + 16];

  for (i = 0; i < 16; i++)
    o[i] = t[i];

  car25519(o);
  car25519(o);
}

static void sqr(gf o, const gf a)
{
  mul(o, a, a);
}

static void inv25519(gf o, const gf i)
{
  gf c;
  int a;
  for (a = 0; a < 16; a++)
    c[a] = i[a];

  for (a = 253; a >= 0; a--)
  {
    sqr(c, c);
    if(a != 2 && a != 4)
      mul(c, c, i);
  }

  for (a = 0; a < 16; a++)
    o[a] = c[a];
}


void cf_curve25519_mul(uint8_t *q, const uint8_t *n, const uint8_t *p)
{
  uint8_t z[32];
  gf x;
  gf a, b, c, d, e, f;

  {
  size_t i;
  for (i = 0; i < 31; i++)
    z[i] = n[i];
  z[31] = (n[31] & 127) | 64;
  z[0] &= 248;

  unpack25519(x, p);

  for(i = 0; i < 16; i++)
  {
    b[i] = x[i];
    d[i] = a[i] = c[i] = 0;
  }
  }

  a[0] = d[0] = 1;

  {int i;
  for (i = 254; i >= 0; i--)
  {
    int64_t r = (z[i >> 3] >> (i & 7)) & 1;
    sel25519(a, b, r);
    sel25519(c, d, r);
    add(e, a, c);
    sub(a, a, c);
    add(c, b, d);
    sub(b, b, d);
    sqr(d, e);
    sqr(f, a);
    mul(a, c, a);
    mul(c, b, e);
    add(e, a, c);
    sub(a, a, c);
    sqr(b, a);
    sub(c, d, f);
    mul(a, c, _121665);
    add(a, a, d);
    mul(c, c, a);
    mul(a, d, f);
    mul(d, b, x);
    sqr(b, e);
    sel25519(a, b, r);
    sel25519(c, d, r);
  }
  }

  inv25519(c, c);
  mul(a, a, c);
  pack25519(q, a);
}

void cf_curve25519_mul_base(uint8_t *q, const uint8_t *n)
{
  cf_curve25519_mul(q, n, _9);
}

