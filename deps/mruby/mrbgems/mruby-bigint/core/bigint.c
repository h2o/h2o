/**
** @file mruby/bigint.h - Multi-precision, Integer
**
** See Copyright Notice in mruby.h
*/

#include <mruby.h>
#include <mruby/object.h>
#include <mruby/numeric.h>
#include <mruby/array.h>
#include <mruby/string.h>
#include <mruby/internal.h>
#include <string.h>
#include "bigint.h"

static void
mpz_init(mrb_state *mrb, mpz_t *s)
{
  s->p = (mp_limb*)mrb_malloc(mrb, sizeof(mp_limb)*2);
  (s->p)[0] = 0;
  (s->p)[1] = 0;
  s->sn=0;
  s->sz=2;
}

#if 0
static void
mpz_init_set(mrb_state *mrb, mpz_t *s, mpz_t *t)
{
  s->p = (mp_limb*)mrb_malloc(mrb, sizeof(mp_limb) * t->sz);
  for (size_t i=0;i < t->sz ; i++)
    (s->p)[i] = (t->p)[i];

  s->sn = t->sn;
  s->sz = t->sz;
}
#endif

static void
mpz_set_int(mrb_state *mrb, mpz_t *y, mrb_int v)
{
  for (size_t i=1; i<y->sz; i++)
    y->p[i] = 0;
  if (v < 0) {
    y->sn = -1;
    y->p[0] = (-v) & LMAX;
    y->p[1] = ((-v) & LC) >> DIGITBITS;
  }
  else if (v > 0) {
    y->sn = 1;
    y->p[0] = v & LMAX;
    y->p[1] = (v & LC) >> DIGITBITS;
  }
  else {
    y->sn=0;
    y->p[0] = 0;
    y->p[1] = 0;
  }
}

static void
mpz_init_set_int(mrb_state *mrb, mpz_t *y, mrb_int v)
{
  mp_limb u;

  y->p = (mp_limb*)mrb_malloc(mrb, sizeof(mp_limb)*2);
  if (v < 0) {
    y->sn = -1;
    u = -v;
  }
  else if (v > 0) {
    y->sn = 1;
    u = v;
  }
  else {
    y->sn=0;
    u = 0;
  }
  y->p[0] = u & LMAX;
  y->p[1] = (u & LC) >> DIGITBITS;
  y -> sz = 2;
}

static void
mpz_clear(mrb_state *mrb, mpz_t *s)
{
  if (s->p)
    mrb_free(mrb, s->p);
  s->p=NULL;
  s->sn=0;
  s->sz=0;
}

static void
mpz_realloc(mrb_state *mrb, mpz_t *x, size_t size)
{
  if (size > 1 && x->sz < size) {
    x->p=(mp_limb*)mrb_realloc(mrb,x->p,size * sizeof(mp_limb));
    for (size_t i=x->sz; i<size; i++)
      (x->p)[i] = 0;
    x->sz = size;
  }
}

static size_t
digits(mpz_t *x)
{
  size_t i;
  for (i = (x->sz) - 1; (x->p)[i] == 0 ; i--)
    if (i == 0) break;
  return i+1;
}

/* y = x */
static void
mpz_set(mrb_state *mrb, mpz_t *y, mpz_t *x)
{
  size_t i,k = x->sz;
  if (y->sz < k) {
    k=digits(x);
    mpz_realloc(mrb, y, (size_t)k);
  }
  if (y->sz > x->sz) {
    mpz_clear(mrb, y);
    mpz_init(mrb, y);
    mpz_realloc(mrb, y, (size_t)(x->sz));
  }

  for (i=0;i < k; i++)
    (y->p)[i] = (x->p)[i];

  for (;i<y->sz;i++)
    (y->p)[i] = 0;

  y->sn = x->sn;
}

/* z = x + y, without regard for sign */
static void
uadd(mrb_state *mrb, mpz_t *z, mpz_t *x, mpz_t *y)
{
  mp_limb c;
  size_t i;
  mpz_t *t;

  if (y->sz < x->sz) {
    t=x; x=y; y=t;
  }

  /* now y->sz >= x->sz */

  mpz_realloc(mrb, z, (size_t)((y->sz)+1));

  c=0;
  for (i=0; i<x->sz; i++) {
    if ((z->p[i] = y->p[i] + x->p[i] + c) & CMASK) {
      c=1;
      (z->p[i]) &=LMAX;
    }
    else
      c=0;
  }
  for (;i<y->sz; i++) {
    if ((z->p[i] = (y->p[i] + c)) & CMASK)
      z->p[i]=0;
    else
      c=0;
  }
  (z->p)[y->sz]=c;
}

/* z = y - x, ignoring sign */
/* precondition: abs(y) >= abs(x) */
static void
usub(mrb_state *mrb, mpz_t *z, mpz_t *y, mpz_t *x)
{
  mp_limb b,m;
  mpz_realloc(mrb, z, (size_t)(y->sz));
  b=0;
  for (size_t i=0;i<y->sz;i++) {
    m=((y->p)[i]-b)-dg(x,i);
    if (m < 0) {
      b = 1;
      m = LMAX + 1 + m;
    }
    else
      b = 0;
    z->p[i] = m;
  }
}

/* compare abs(x) and abs(y) */
static int
ucmp(mpz_t *y, mpz_t *x)
{
  size_t i;
  for (i=imax(x->sz,y->sz)-1;;i--) {
    if (dg(y,i) < dg(x,i))
      return (-1);
    else if (dg(y,i) > dg(x,i))
      return 1;
    if (i == 0) break;
  }
  return 0;
}

static int
uzero(mpz_t *x)
{
  for (size_t i=0; i < x->sz; i++)
    if ((x->p)[i] != 0)
      return 0;
  return 1;
}

static void
zero(mpz_t *x)
{
  x->sn=0;
  for (size_t i=0;i<x->sz;i++)
    (x->p)[i] = 0;
}

/* z = x + y */
static void
mpz_add(mrb_state *mrb, mpz_t *zz, mpz_t *x, mpz_t *y)
{
  int mg;
  mpz_t z;
  if (x->sn == 0) {
    mpz_set(mrb, zz, y);
    return;
  }
  if (y->sn == 0) {
    mpz_set(mrb, zz, x);
    return;
  }
  mpz_init(mrb, &z);

  if (x->sn > 0 && y->sn > 0) {
    uadd(mrb, &z, x, y);
    z.sn = 1;
  }
  else if (x->sn < 0 && y->sn < 0) {
    uadd(mrb, &z, x, y);
    z.sn = -1;
  }
  else {
    /* signs differ */
    if ((mg = ucmp(x,y)) == 0) {
      zero(&z);
    }
    else if (mg > 0) {  /* abs(y) < abs(x) */
      usub(mrb, &z, x, y);
      z.sn = (x->sn > 0 && y->sn < 0) ? 1 : (-1);
    }
    else { /* abs(y) > abs(x) */
      usub(mrb, &z, y, x);
      z.sn = (x->sn < 0 && y->sn > 0) ? 1 : (-1);
    }
  }
  mpz_set(mrb,zz,&z);
  mpz_clear(mrb,&z);
}

/* z = x - y  -- just use mpz_add - I'm lazy */
static void
mpz_sub(mrb_state *mrb, mpz_t *z, mpz_t *x, mpz_t *y)
{
  mpz_t u;
  mpz_init(mrb, &u);
  mpz_set(mrb, &u, y);
  u.sn = -(u.sn);
  mpz_add(mrb, z, x, &u);
  mpz_clear(mrb, &u);
}

/* x = y - n */
static void
mpz_sub_int(mrb_state *mrb, mpz_t *x, mpz_t *y, mrb_int n)
{
  mpz_t z;
  mpz_init_set_int(mrb, &z, n);
  mpz_sub(mrb, x, y, &z);
  mpz_clear(mrb, &z);
}

/* w = u * v */
static void
mpz_mul(mrb_state *mrb, mpz_t *ww, mpz_t *u, mpz_t *v)
{
  size_t i,j;
  mp_limb t0,t1,t2,t3;
  mp_limb cc;
  mpz_t w;

  mpz_init(mrb, &w);
  mpz_realloc(mrb, &w, (size_t)(u->sz + v->sz));
  for (j=0; j < 2*u->sz; j++) {
    cc = (mp_limb)0;
    t3 = hd(u,j);
    for (i=0; i < 2*v->sz; i++) {
      t0 = t3 * hd(v,i);
      t1 = HIGH(t0); t0 = LOW(t0);
      if ((i+j)%2)
        t2 = HIGH(w.p[(i+j)/2]);
      else
        t2 = LOW(w.p[(i+j)/2]);
      t2 += cc;
      if (t2 & HCMASK) {
        cc = 1; t2&=HLMAX;
      }
      else
        cc = 0;
      t2 += t0;
      if (t2 & HCMASK) {
        cc++ ; t2&=HLMAX;
      }
      cc+=t1;
      if ((i+j)%2)
        w.p[(i+j)/2] = LOW(w.p[(i+j)/2]) |
          (t2 << HALFDIGITBITS);
      else
        w.p[(i+j)/2] = (HIGH(w.p[(i+j)/2]) << HALFDIGITBITS) | t2;
    }
    if (cc) {
      if ((j+i)%2)
        w.p[(i+j)/2] += cc << HALFDIGITBITS;
      else
        w.p[(i+j)/2] += cc;
    }
  }
  w.sn = (u->sn) * (v->sn);
  mpz_set(mrb, ww, &w);
  mpz_clear(mrb, &w);
}

static void
mpz_mul_int(mrb_state *mrb, mpz_t *x, mpz_t *y, mrb_int n)
{
  mpz_t z;
  mpz_init_set_int(mrb,&z,n);
  mpz_mul(mrb,x,y,&z);
  mpz_clear(mrb,&z);
}

/* number of leading zero bits in digit */
static int
lzb(mp_limb a)
{
  mp_limb i; int j=0;

  for (i = ((mp_limb)1 << (DIGITBITS-1)); i && !(a&i) ; j++,i>>=1)
    ;
  return j;
}

/* c1 = a>>n */
/* n must be < DIGITBITS */
static void
urshift(mrb_state *mrb, mpz_t *c1, mpz_t *a, size_t n)
{
  mp_limb cc = 0;
  mrb_assert(n < DIGITBITS);
  if (n == 0)
    mpz_set(mrb, c1, a);
  else {
    mpz_t c; size_t i;
    mp_limb rm = (((mp_limb)1<<n) - 1);
    mpz_init(mrb,&c); mpz_realloc(mrb,&c,(size_t)(a->sz));
    for (i=a->sz-1;; i--) {
      c.p[i] = ((a->p[i] >> n) | cc) & LMAX;
      cc = (a->p[i] & rm) << (DIGITBITS - n);
      if (i == 0) break;
    }
    mpz_set(mrb,c1,&c);
    mpz_clear(mrb,&c);
  }
}

/* c1 = a<<n */
/* n must be < DIGITBITS */
static void
ulshift(mrb_state *mrb, mpz_t *c1, mpz_t *a, size_t n)
{
  mp_limb cc = 0;
  mrb_assert(n < DIGITBITS);
  if (n == 0)
    mpz_set(mrb,c1,a);
  else {
    mpz_t c; size_t i;
    mp_limb rm = (((mp_ulimb)1<<n) - 1) << (DIGITBITS-n);
    mpz_init(mrb,&c); mpz_realloc(mrb,&c,(size_t)(a->sz + 1));
    for (i=0; i<a->sz; i++) {
      c.p[i] = (((mp_ulimb)a->p[i] << n) | cc) & LMAX;
      cc = (a->p[i] & rm) >> (DIGITBITS -n);
    }
    c.p[i] = cc;
    mpz_set(mrb,c1,&c);
    mpz_clear(mrb,&c);
  }
}

/* internal routine to compute x/y and x%y ignoring signs */
static void
udiv(mrb_state *mrb, mpz_t *qq, mpz_t *rr, mpz_t *xx, mpz_t *yy)
{
  mpz_t q, x, y, r;
  int ns,f,ccc=0;
  size_t xd,yd,i,j;
  mp_limb zz,z,qhat,b,u,m;

  if (uzero(yy))
    return;
  mpz_init(mrb,&q); mpz_init(mrb,&x);mpz_init(mrb,&y);mpz_init(mrb,&r);
  mpz_realloc(mrb,&x,(size_t)((xx->sz)+1));
  yd = digits(yy);
  ns = lzb(yy->p[yd-1]);
  ulshift(mrb,&x,xx,ns);
  ulshift(mrb,&y,yy,ns);
  xd = digits(&x);
  mpz_realloc(mrb,&q,(size_t)xd);
  xd*=2; yd*=2;
  z = hd(&y,yd-1);
  for (j=(xd-yd);;j--) {
    if (z == LMAX)
      qhat = hd(&x,j+yd);
    else {
      qhat = ((hd(&x,j+yd)<< HALFDIGITBITS) + hd(&x,j+yd-1)) / (z+1);
    }
    b = 0; zz=0;
    if (qhat) {
      for (i=0; i<yd; i++) {
        zz = qhat * hd(&y,i);
        u = hd(&x,i+j);
        u-=b;
        if (u<0) {
          b=1; u+=HLMAX+1;
        }
        else
          b=0;
        u-=LOW(zz);
        if (u < 0) {
          b++;
          u+=HLMAX+1;
        }
        b+=HIGH(zz);
        if ((i+j)%2)
          x.p[(i+j)/2] = LOW(x.p[(i+j)/2]) | (u << HALFDIGITBITS);
        else
          x.p[(i+j)/2] = (HIGH(x.p[(i+j)/2]) << HALFDIGITBITS) | u;
      }
      if (b) {
        if ((j+i)%2)
          x.p[(i+j)/2] -= b << HALFDIGITBITS;
        else
          x.p[(i+j)/2] -= b;
      }
    }
    for (;;zz++) {
      f=1;
      if (!hd(&x,j+yd)) {
        for (i=yd-1; ; i--) {
          if (hd(&x,j+i) > hd(&y,i)) {
            f=1;
            break;
          }
          if (hd(&x,j+i) < hd(&y,i)) {
            f=0;
            break;
          }
          if (i == 0) break;
        }
      }
      if (!f)
        break;
      qhat++;
      ccc++;
      b=0;
      for (i=0;i<yd;i++) {
        m = hd(&x,i+j)-hd(&y,i)-b;
        if (m < 0) {
          b = 1;
          m = HLMAX + 1 + m;
        }
        else
          b = 0;
        if ((i+j)%2)
          x.p[(i+j)/2] = LOW(x.p[(i+j)/2]) | (m << HALFDIGITBITS);
        else
          x.p[(i+j)/2] = (HIGH(x.p[(i+j)/2]) << HALFDIGITBITS) | m;
      }
      if (b) {
        if ((j+i)%2)
          x.p[(i+j)/2] -= b << HALFDIGITBITS;
        else
          x.p[(i+j)/2] -= b;
      }
    }
    if (j%2)
      q.p[j/2] |= qhat << HALFDIGITBITS;
    else
      q.p[j/2] |= qhat;
    if (j == 0) break;
  }
  mpz_realloc(mrb,&r,(size_t)(yy->sz));
  zero(&r);
  urshift(mrb,&r,&x,ns);
  mpz_set(mrb,rr,&r);
  mpz_set(mrb,qq,&q);
  mpz_clear(mrb,&x); mpz_clear(mrb,&y);
  mpz_clear(mrb,&q); mpz_clear(mrb,&r);
}

static void
mpz_mdiv(mrb_state *mrb, mpz_t *q, mpz_t *x, mpz_t *y)
{
  mpz_t r;
  short sn1 = x->sn, sn2 = y->sn, qsign;
  mpz_init(mrb,&r);
  udiv(mrb,q,&r,x,y);
  qsign = q->sn = sn1*sn2;
  if (uzero(q))
    q->sn = 0;
  /* now if r != 0 and q < 0 we need to round q towards -inf */
  if (!uzero(&r) && qsign < 0)
    mpz_sub_int(mrb,q,q,1);
  mpz_clear(mrb,&r);
}

static void
mpz_mmod(mrb_state *mrb, mpz_t *r, mpz_t *x, mpz_t *y)
{
  mpz_t q;
  short sn1 = x->sn, sn2 = y->sn;
  mpz_init(mrb, &q);
  if (sn1 == 0) {
    zero(r);
    return;
  }
  udiv(mrb,&q,r,x,y);
  if (uzero(r)) {
    r->sn = 0;
    return;
  }
  q.sn = sn1*sn2;
  if (q.sn > 0)
    r->sn = sn1;
  else if (sn1 < 0 && sn2 > 0) {
    r->sn = 1;
    mpz_sub(mrb,r,y,r);
  }
  else {
    r->sn = 1;
    mpz_add(mrb,r,y,r);
  }
}

static void
mpz_mdivmod(mrb_state *mrb, mpz_t *q, mpz_t *r, mpz_t *x, mpz_t *y)
{
  short sn1 = x->sn, sn2 = y->sn, qsign;
  if (sn1 == 0) {
    zero(q);
    zero(r);
    return;
  }
  udiv(mrb,q,r,x,y);
  qsign = q->sn = sn1*sn2;
  if (uzero(r)) {
    /* q != 0, since q=r=0 would mean x=0, which was tested above */
    r->sn = 0;
    return;
  }
  if (q->sn > 0)
    r->sn = sn1;
  else if (sn1 < 0 && sn2 > 0) {
    r->sn = 1;
    mpz_sub(mrb,r,y,r);
  }
  else {
    r->sn = 1;
    mpz_add(mrb,r,y,r);
  }
  if (uzero(q))
    q->sn = 0;
  /* now if r != 0 and q < 0 we need to round q towards -inf */
  if (!uzero(r) && qsign < 0)
    mpz_sub_int(mrb,q,q,1);
}

static void
mpz_mod(mrb_state *mrb, mpz_t *r, mpz_t *x, mpz_t *y)
{
  mpz_t q;
  short sn = x->sn;
  mpz_init(mrb, &q);
  if (x->sn == 0) {
    zero(r);
    return;
  }
  udiv(mrb,&q,r,x,y);
  r->sn = sn;
  if (uzero(r))
    r->sn = 0;
  mpz_clear(mrb,&q);
}

static mrb_int
mpz_cmp(mrb_state *mrb, mpz_t *x, mpz_t *y)
{
  int abscmp;
  if (x->sn < 0 && y->sn > 0)
    return (-1);
  if (x->sn > 0 && y->sn < 0)
    return 1;
  abscmp=ucmp(x,y);
  if (x->sn >=0 && y->sn >=0)
    return abscmp;
  return (-abscmp);          // if (x->sn <=0 && y->sn <=0)
}

/* 2<=base <=36 - this overestimates the optimal value, which is OK */
static int
mpz_sizeinbase(mpz_t *x, int base)
{
  int i,j;
  size_t bits = digits(x) * DIGITBITS;
  mrb_assert(2 <= base && base <= 36);
  for (j=0,i=1; i<=base; i*=2,j++)
    ;
  return (int)((bits)/(j-1)+1);
}

static int
mpz_init_set_str(mrb_state *mrb, mpz_t *x, const char *s, mrb_int len, mrb_int base)
{
  size_t i;
  int retval = 0;
  mpz_t t,m,bb;
  short sn;
  unsigned int k;
  mpz_init(mrb,x);
  mpz_init_set_int(mrb,&m,1);
  mpz_init(mrb,&t);
  zero(x);
  if (*s == '-') {
    sn = -1; s++;
  }
  else if (base < 0) {          /* trick: negative if base < 0 */
    sn = -1; base = -base;
  }
  else
    sn = 1;
  mpz_init_set_int(mrb,&bb, base);
  for (i = len-1;; i--) {
    if (s[i]=='_') continue;
    if (s[i] >= '0' && s[i] <= '9')
      k = (unsigned int)s[i] - (unsigned int)'0';
    else if (s[i] >= 'A' && s[i] <= 'Z')
      k = (unsigned int)s[i] - (unsigned int)'A'+10;
    else if (s[i] >= 'a' && s[i] <= 'z')
      k = (unsigned int)s[i] - (unsigned int)'a'+10;
    else {
      retval = (-1);
      break;
    }
    if (k >= base) {
      retval = (-1);
      break;
    }
    mpz_mul_int(mrb,&t,&m,(mrb_int)k);
    mpz_add(mrb,x,x,&t);
    mpz_mul(mrb,&m,&m,&bb);
    if (i == 0) break;
  }
  if (x->sn)
    x->sn = sn;
  mpz_clear(mrb,&m);
  mpz_clear(mrb,&bb);
  mpz_clear(mrb,&t);
  return retval;
}

static char*
mpz_get_str(mrb_state *mrb, char *s, mrb_int sz, mrb_int base, mpz_t *x)
{
  mpz_t xx,q,r,bb;
  char *p,*t,*ps;
  mp_limb d;
  mrb_assert(2 <= base && base <= 36);
  if (uzero(x)) {
    *s='0';
    *(s+1)='\0';
    return s;
  }
  t = (char*)mrb_malloc(mrb, sz+2);
  mpz_init(mrb,&xx); mpz_init(mrb,&q); mpz_init(mrb,&r);
  mpz_init_set_int(mrb,&bb,base);
  mpz_set(mrb,&xx,x);
  ps = s;
  if (x->sn < 0) {
    *ps++= '-';
    xx.sn = 1;
  }
  p = t;
  while (!uzero(&xx)) {
    udiv(mrb,&xx,&r,&xx,&bb);
    d = r.p[0];
    if (d < 10)
      *p++ = (char)(r.p[0] + '0');
    else
      *p++ = (char)(r.p[0] + -10 + 'a');
  }

  p--;
  for (;p>=t;p--,ps++)
    *ps = *p;
  *ps='\0';

  mrb_free(mrb,t);
  mpz_clear(mrb,&xx); mpz_clear(mrb,&q); mpz_clear(mrb,&r); mpz_clear(mrb,&bb);
  return s;
}

static int
mpz_get_int(mpz_t *y, mrb_int *v)
{
  mp_limb i;

  if (y->sn == 0) {
    i = 0;
  }
  else if (digits(y) > 2 || y->p[1] > 1) {
    return FALSE;
  }
  else {
    i = (y->sn * (y->p[0] | (y->p[1] & 1) << DIGITBITS));
    if (MRB_INT_MAX < i || i < MRB_INT_MIN) return FALSE;
  }
  *v = i;
  return TRUE;
}

static void
mpz_mul_2exp(mrb_state *mrb, mpz_t *z, mpz_t *x, mrb_int e)
{
  short sn = x->sn;
  if (e==0)
    mpz_set(mrb,z,x);
  else {
    size_t i;
    mp_limb digs = (e / DIGITBITS);
    size_t bs = (e % (DIGITBITS));
    mpz_t y;

    mpz_init(mrb, &y);
    mpz_realloc(mrb, &y,(size_t)((x->sz)+digs));
    for (i=digs;i<((x->sz) + digs);i++)
      (y.p)[i] = (x->p)[i - digs];
    if (bs) {
      ulshift(mrb,z,&y,bs);
    }
    else {
      mpz_set(mrb,z,&y);
    }
    z->sn = sn;
    mpz_clear(mrb,&y);
  }
}

static void
mpz_div_2exp(mrb_state *mrb, mpz_t *z, mpz_t *x, mrb_int e)
{
  short sn = x->sn;
  if (e==0)
    mpz_set(mrb,z,x);
  else {
    size_t i;
    mp_limb digs = (e / DIGITBITS);
    size_t bs = (e % (DIGITBITS));
    mpz_t y;

    mpz_init(mrb,&y);
    mpz_realloc(mrb,&y,(size_t)((x->sz) - digs));
    for (i=0; i < (x->sz - digs); i++)
      (y.p)[i] = (x->p)[i+digs];
    if (bs) {
      urshift(mrb,z,&y,bs);
    }
    else {
      mpz_set(mrb,z,&y);
    }
    if (uzero(z))
      z->sn = 0;
    else
      z->sn = sn;
    mpz_clear(mrb,&y);
  }
}

static void
mpz_neg(mrb_state *mrb, mpz_t *x, mpz_t *y)
{
  if (x!=y)
    mpz_set(mrb,x,y);
  x->sn = -(y->sn);
}

static void
mpz_and(mrb_state *mrb, mpz_t *z, mpz_t *x, mpz_t *y) /* not the most efficient way to do this */
{
  size_t i,sz;
  sz = imax(x->sz, y->sz);
  mpz_realloc(mrb,z,(size_t)sz);
  for (i=0; i < sz; i++)
    (z->p)[i] = dg(x,i) & dg(y,i);
  if (x->sn < 0 && y->sn < 0)
    z->sn = (-1);
  else
    z->sn = 1;
  if (uzero(z))
    z->sn = 0;
}

static void
mpz_or(mrb_state *mrb, mpz_t *z, mpz_t *x, mpz_t *y)  /* not the most efficient way to do this */
{
  size_t i,sz;
  sz = imax(x->sz, y->sz);
  mpz_realloc(mrb,z,(size_t)sz);
  for (i=0; i < sz; i++)
    (z->p)[i] = dg(x,i) | dg(y,i);
  if (x->sn < 0 || y->sn < 0)
    z->sn = (-1);
  else
    z->sn = 1;
  if (uzero(z))
    z->sn = 0;
}

static void
mpz_xor(mrb_state *mrb, mpz_t *z, mpz_t *x, mpz_t *y)  /* not the most efficient way to do this */
{
  size_t i,sz;
  sz = imax(x->sz, y->sz);
  mpz_realloc(mrb,z,(size_t)sz);
  for (i=0; i < sz; i++)
    (z->p)[i] = dg(x,i) ^ dg(y,i);
  if ((x->sn <= 0 && y->sn > 0) || (x->sn > 0 && y->sn <=0))
    z->sn = (-1);
  else
    z->sn = 1;
  if (uzero(z))
    z->sn = 0;
}

static void
mpz_pow(mrb_state *mrb, mpz_t *zz, mpz_t *x, mrb_int e)
{
  mpz_t t;
  mp_ulimb mask = (((mp_ulimb)1)<< (LONGBITS-1));

  if (e==0) {
    mpz_set_int(mrb, zz, 1L);
    return;
  }

  mpz_init(mrb,&t);
  mpz_set(mrb,&t,x);
  for (;!(mask &e); mask>>=1)
    ;
  mask>>=1;
  for (;mask!=0; mask>>=1) {
    mpz_mul(mrb,&t,&t,&t);
    if (e & mask)
      mpz_mul(mrb,&t,&t,x);
  }
  mpz_set(mrb,zz,&t);
  mpz_clear(mrb,&t);
}

#define lowdigit(x) (((x)->p)[0])

struct is {
  mp_limb v;
  struct is *next;
};

static void
push(mrb_state *mrb, mp_limb i, struct is **sp)
{
  struct is *tmp;
  tmp = *sp;
  *sp = (struct is*)mrb_malloc(mrb, sizeof(struct is));
  (*sp)->v = i;
  (*sp)->next=tmp;
}

static mp_limb
pop(mrb_state *mrb, struct is **sp)
{
  struct is *tmp;
  mp_limb i;
  if (!(*sp))
    return (-1);
  tmp = *sp;
  *sp = (*sp)->next;
  i = tmp->v;
  tmp->v = 0;
  mrb_free(mrb,tmp);
  return i;
}

static void
mpz_powm(mrb_state *mrb, mpz_t *zz, mpz_t *x, mrb_int ex, mpz_t *n)
{
  mpz_t t, e;
  struct is *stack = NULL;
  size_t k,i;

  if (ex == 0) {
    mpz_set_int(mrb,zz,1);
    return;
  }

  if (ex < 0) {
    return;
  }
  mpz_init_set_int(mrb,&e, ex);
  mpz_init(mrb,&t);

  for (k=0;!uzero(&e);k++,mpz_div_2exp(mrb,&e,&e,1))
    push(mrb,lowdigit(&e) & 1,&stack);
  k--;
  i=pop(mrb,&stack);

  mpz_mod(mrb,&t,x,n);  /* t=x%n */

  for (i=k-1;;i--) {
    mpz_mul(mrb,&t,&t,&t);
    mpz_mod(mrb,&t,&t,n);
    if (pop(mrb,&stack)) {
      mpz_mul(mrb,&t,&t,x);
      mpz_mod(mrb,&t,&t,n);
    }
    if (i == 0) break;
  }
  mpz_set(mrb,zz,&t);
  mpz_clear(mrb,&t);
  mpz_clear(mrb,&e);
}

/* --- mruby functions --- */
static struct RBigint*
bint_new(mrb_state *mrb)
{
  struct RBigint *b = MRB_OBJ_ALLOC(mrb, MRB_TT_BIGINT, mrb->integer_class);
  mpz_init(mrb, &b->mp);
  return b;
}

static struct RBigint*
bint_new_int(mrb_state *mrb, mrb_int x)
{
  struct RBigint *b = MRB_OBJ_ALLOC(mrb, MRB_TT_BIGINT, mrb->integer_class);
  mpz_init_set_int(mrb, &b->mp, x);
  return b;
}

mrb_value
mrb_bint_new(mrb_state *mrb)
{
  struct RBigint *b = bint_new(mrb);
  return mrb_obj_value(b);
}

mrb_value
mrb_bint_new_int(mrb_state *mrb, mrb_int x)
{
  struct RBigint *b = bint_new_int(mrb, x);
  return mrb_obj_value(b);
}

mrb_value
mrb_bint_new_str(mrb_state *mrb, const char *x, mrb_int len, mrb_int base)
{
  struct RBigint *b = MRB_OBJ_ALLOC(mrb, MRB_TT_BIGINT, mrb->integer_class);
  mrb_assert(2 <= iabs(base) && iabs(base) <= 36);
  mpz_init_set_str(mrb, &b->mp, x, len, base);
  return mrb_obj_value(b);
}

static mrb_value
bint_norm(mrb_state *mrb, struct RBigint *b)
{
  mrb_int i;

  if (mpz_get_int(&b->mp, &i)) {
    return mrb_int_value(mrb, i);
  }
  return mrb_obj_value(b);
}

void
mrb_gc_free_bint(mrb_state *mrb, struct RBasic *x)
{
  struct RBigint *b = (struct RBigint*)x;
  mpz_clear(mrb, &b->mp);
}

#ifndef MRB_NO_FLOAT
mrb_value
mrb_bint_new_float(mrb_state *mrb, mrb_float x)
{
  /* x should not be NaN nor Infinity */
  mrb_assert(x == x && x != x * 0.5);

  if (x < 1.0) {
    return mrb_fixnum_value(0);
  }

  struct RBigint *bint = bint_new(mrb);
  mpz_t *r = &bint->mp;

  if (x < 0.0) {
    x = -x;
    r->sn = -1;
  }
  else {
    r->sn = 1;
  }

  mrb_float b = (double)CMASK;
  mrb_float bi = 1.0 / b;
  size_t rn, i;
  mp_limb *rp;
  mp_limb f;

  for (rn = 1; x >= b; rn++)
    x *= bi;

  mpz_realloc(mrb, r, rn);
  rp = r->p;
  for (i=rn-1;;i--) {
    f = (mp_limb)x;
    x -= f;
    mrb_assert(x < 1.0);
    rp[i] = f;
    if (i == 0) break;
  }
  return bint_norm(mrb, bint);
}

mrb_float
mrb_bint_as_float(mrb_state *mrb, mrb_value self)
{
  struct RBigint *b = RBIGINT(self);
  mpz_t *i = &b->mp;
  mp_limb *d = i->p + i->sz;
  mrb_float val = 0;

  while (d-- > i->p) {
    val = val * (LMAX+1) + *d;
  }

  if (i->sn < 0) {
    val = -val;
  }
  return val;
}
#endif

mrb_value
mrb_as_bint(mrb_state *mrb, mrb_value x)
{
  if (mrb_bigint_p(x)) return x;
  return mrb_bint_new_int(mrb, mrb_as_int(mrb, x));
}

mrb_int
mrb_bint_as_int(mrb_state *mrb, mrb_value x)
{
  struct RBigint *b = RBIGINT(x);
  mrb_int i;

  if (!mpz_get_int(&b->mp, &i)) {
    mrb_raise(mrb, E_RANGE_ERROR, "integer too big");
  }
  return i;
}

mrb_value
mrb_bint_add(mrb_state *mrb, mrb_value x, mrb_value y)
{
#ifndef MRB_NO_FLOAT
  if (mrb_float_p(y)) {
    mrb_float v1 = mrb_bint_as_float(mrb, x);
    mrb_float v2 = mrb_float(y);
    return mrb_float_value(mrb,v1+v2);
  }
#endif
  y = mrb_as_bint(mrb, y);
  struct RBigint *b = RBIGINT(x);
  struct RBigint *b2 = RBIGINT(y);
  struct RBigint *b3 = bint_new(mrb);
  mpz_add(mrb, &b3->mp, &b->mp, &b2->mp);
  return bint_norm(mrb, b3);
}

mrb_value
mrb_bint_sub(mrb_state *mrb, mrb_value x, mrb_value y)
{
#ifndef MRB_NO_FLOAT
  if (mrb_float_p(y)) {
    mrb_float v1 = mrb_bint_as_float(mrb, x);
    mrb_float v2 = mrb_float(y);
    return mrb_float_value(mrb,v1-v2);
  }
#endif
  y = mrb_as_bint(mrb, y);
  struct RBigint *b = RBIGINT(x);
  struct RBigint *b2 = RBIGINT(y);
  struct RBigint *b3 = bint_new(mrb);
  mpz_sub(mrb, &b3->mp, &b->mp, &b2->mp);
  return bint_norm(mrb, b3);
}

mrb_value
mrb_bint_mul(mrb_state *mrb, mrb_value x, mrb_value y)
{
#ifndef MRB_NO_FLOAT
  if (mrb_float_p(y)) {
    mrb_float v1 = mrb_bint_as_float(mrb, x);
    mrb_float v2 = mrb_float(y);
    return mrb_float_value(mrb,v1*v2);
  }
#endif
  y = mrb_as_bint(mrb, y);
  struct RBigint *b = RBIGINT(x);
  struct RBigint *b2 = RBIGINT(y);
  struct RBigint *b3 = bint_new(mrb);
  mpz_mul(mrb, &b3->mp, &b->mp, &b2->mp);
  return bint_norm(mrb, b3);
}

mrb_value
mrb_bint_div(mrb_state *mrb, mrb_value x, mrb_value y)
{
#ifndef MRB_NO_FLOAT
  if (mrb_float_p(y)) {
    mrb_float v1 = mrb_bint_as_float(mrb, x);
    mrb_float v2 = mrb_float(y);
    return mrb_float_value(mrb,v1*v2);
  }
#endif
  y = mrb_as_bint(mrb, y);
  struct RBigint *b = RBIGINT(x);
  struct RBigint *b2 = RBIGINT(y);
  struct RBigint *b3 = bint_new(mrb);
  mpz_mdiv(mrb, &b3->mp, &b->mp, &b2->mp);
  return bint_norm(mrb, b3);
}

mrb_value
mrb_bint_add_ii(mrb_state *mrb, mrb_int x, mrb_int y)
{
  struct RBigint *b = bint_new(mrb);
  mpz_t z1, z2;

  mpz_init_set_int(mrb,&z1,x);
  mpz_init_set_int(mrb,&z2,y);
  mpz_add(mrb,&b->mp,&z1,&z2);
  mpz_clear(mrb,&z1);
  mpz_clear(mrb,&z2);
  return bint_norm(mrb, b);
}

mrb_value
mrb_bint_sub_ii(mrb_state *mrb, mrb_int x, mrb_int y)
{
  struct RBigint *b = bint_new(mrb);
  mpz_t z1, z2;

  mpz_init_set_int(mrb,&z1,x);
  mpz_init_set_int(mrb,&z2,y);
  mpz_sub(mrb,&b->mp,&z1,&z2);
  mpz_clear(mrb,&z1);
  mpz_clear(mrb,&z2);
  return bint_norm(mrb, b);
}

mrb_value
mrb_bint_mul_ii(mrb_state *mrb, mrb_int x, mrb_int y)
{
  struct RBigint *b = bint_new(mrb);
  mpz_t z1, z2;

  mpz_init_set_int(mrb,&z1,x);
  mpz_init_set_int(mrb,&z2,y);
  mpz_mul(mrb,&b->mp,&z1,&z2);
  mpz_clear(mrb,&z1);
  mpz_clear(mrb,&z2);
  return bint_norm(mrb, b);
}

mrb_value
mrb_bint_div_ii(mrb_state *mrb, mrb_int x, mrb_int y)
{
  struct RBigint *b = bint_new(mrb);
  mpz_t z1, z2;

  mpz_init_set_int(mrb,&z1,x);
  mpz_init_set_int(mrb,&z2,y);
  mpz_mdiv(mrb,&b->mp,&z1,&z2);
  mpz_clear(mrb,&z1);
  mpz_clear(mrb,&z2);
  return bint_norm(mrb, b);
}

mrb_value
mrb_bint_idiv(mrb_state *mrb, mrb_value x, mrb_value y)
{
  return mrb_nil_value();
}

mrb_value
mrb_bint_mod(mrb_state *mrb, mrb_value x, mrb_value y)
{
#ifndef MRB_NO_FLOAT
  if (mrb_float_p(y)) {
    mrb_float v1 = mrb_bint_as_float(mrb, x);
    mrb_float v2 = mrb_float(y);
    return mrb_float_value(mrb,fmod(v1,v2));
  }
#endif
  y = mrb_as_bint(mrb, y);
  struct RBigint *b = RBIGINT(x);
  struct RBigint *b2 = RBIGINT(y);
  struct RBigint *b3 = bint_new(mrb);
  mpz_mmod(mrb, &b3->mp, &b->mp, &b2->mp);
  return bint_norm(mrb, b3);
}

mrb_value
mrb_bint_rem(mrb_state *mrb, mrb_value x, mrb_value y)
{
  /* called from mrbgems/mruby-numeric-ext/src/numeric_ext.c */
  /* y should not be float */
  struct RBigint *b = RBIGINT(x);
  struct RBigint *b2 = RBIGINT(y);
  struct RBigint *b3 = bint_new(mrb);
  y = mrb_as_bint(mrb, y);
  mpz_mod(mrb, &b3->mp, &b->mp, &b2->mp);
  return bint_norm(mrb, b3);
}

mrb_value
mrb_bint_divmod(mrb_state *mrb, mrb_value x, mrb_value y)
{
  /* called from src/numeric.c */
  /* y should not be float */
  y = mrb_as_bint(mrb, y);
  struct RBigint *b = RBIGINT(x);
  struct RBigint *b2 = RBIGINT(y);
  struct RBigint *b3 = bint_new(mrb);
  struct RBigint *b4 = bint_new(mrb);
  mpz_mdivmod(mrb, &b3->mp, &b4->mp, &b->mp, &b2->mp);
  x = bint_norm(mrb, b3);
  y = bint_norm(mrb, b4);
  return mrb_assoc_new(mrb, x, y);
}

mrb_int
mrb_bint_cmp(mrb_state *mrb, mrb_value x, mrb_value y)
{
#ifndef MRB_NO_FLOAT
  if (mrb_float_p(y)) {
    mrb_float v1 = mrb_bint_as_float(mrb, x);
    mrb_float v2 = mrb_float(y);
    if (v1 == v2) return 0;
    if (v1 > v2)  return 1;
    return -1;
  }
#endif
  struct RBigint *b = RBIGINT(x);
  if (!mrb_bigint_p(y)) {
    if (!mrb_integer_p(y)) return -2; /* type mismatch */

    mrb_int i1, i2 = mrb_integer(y);
    if (mpz_get_int(&b->mp, &i1)) {
      if (i1 == i2) return 0;
      if (i1 > i2) return 1;
      return -1;
    }
    if (b->mp.sn > 0) return 1;
    return -1;
  }
  struct RBigint *b2 = RBIGINT(y);
  return mpz_cmp(mrb, &b->mp, &b2->mp);
}

mrb_value
mrb_bint_pow(mrb_state *mrb, mrb_value x, mrb_value y)
{
  struct RBigint *b = RBIGINT(x);
  switch (mrb_type(y)) {
  case MRB_TT_INTEGER:
    {
      struct RBigint *b3 = bint_new(mrb);
      mpz_pow(mrb, &b3->mp, &b->mp, mrb_integer(y));
      return mrb_obj_value(b3);
    }
  case MRB_TT_BIGINT:
    mrb_raise(mrb, E_TYPE_ERROR, "too big power");
  default:
    mrb_raisef(mrb, E_TYPE_ERROR, "%v cannot be convert to integer", y);
  }
  return mrb_nil_value();
}

mrb_value
mrb_bint_powm(mrb_state *mrb, mrb_value x, mrb_int exp, mrb_value mod)
{
  struct RBigint *b = RBIGINT(x);
  switch (mrb_type(mod)) {
  case MRB_TT_INTEGER:
    {
      struct RBigint *b2 = bint_new(mrb);
      struct RBigint *b3 = bint_new_int(mrb, mrb_integer(mod));
      mpz_powm(mrb, &b2->mp, &b->mp, exp, &b3->mp);
      return mrb_obj_value(b3);
    }
  case MRB_TT_BIGINT:
    {
      struct RBigint *b2 = bint_new(mrb);
      struct RBigint *b3 = RBIGINT(mod);
      mpz_powm(mrb, &b2->mp, &b->mp, exp, &b3->mp);
      return bint_norm(mrb, b3);
    }
    mrb_raise(mrb, E_TYPE_ERROR, "too big power");
  default:
    mrb_raisef(mrb, E_TYPE_ERROR, "%v cannot be convert to integer", mod);
  }
  return mrb_nil_value();
}

mrb_value
mrb_bint_to_s(mrb_state *mrb, mrb_value x, mrb_int base)
{
  struct RBigint *b = RBIGINT(x);
  mrb_int len = mpz_sizeinbase(&b->mp, (int)base);
  mrb_value str = mrb_str_new(mrb, NULL, len+2);
  mpz_get_str(mrb, RSTRING_PTR(str), len, base, &b->mp);
  RSTR_SET_LEN(RSTRING(str), strlen(RSTRING_PTR(str)));
  return str;
}

mrb_value
mrb_bint_and(mrb_state *mrb, mrb_value x, mrb_value y)
{
  struct RBigint *b1 = RBIGINT(x);
  struct RBigint *b3 = bint_new(mrb);

#ifndef MRB_NO_FLOAT
  if (mrb_float_p(y)) {
    mpz_t z;
    mpz_init_set_int(mrb, &z, (mrb_int)mrb_float(y));
    mpz_and(mrb, &b3->mp, &b1->mp, &z);
    mpz_clear(mrb, &z);
    return bint_norm(mrb, b3);
  }
#endif
  y = mrb_as_bint(mrb, y);
  struct RBigint *b2 = RBIGINT(y);
  mpz_and(mrb, &b3->mp, &b1->mp, &b2->mp);
  return bint_norm(mrb, b3);
}

mrb_value
mrb_bint_or(mrb_state *mrb, mrb_value x, mrb_value y)
{
  struct RBigint *b1 = RBIGINT(x);
  struct RBigint *b3 = bint_new(mrb);

#ifndef MRB_NO_FLOAT
  if (mrb_float_p(y)) {
    mpz_t z;
    mpz_init_set_int(mrb, &z, (mrb_int)mrb_float(y));
    mpz_or(mrb, &b3->mp, &b1->mp, &z);
    mpz_clear(mrb, &z);
    return bint_norm(mrb, b3);
  }
#endif
  y = mrb_as_bint(mrb, y);
  struct RBigint *b2 = RBIGINT(y);
  mpz_or(mrb, &b3->mp, &b1->mp, &b2->mp);
  return bint_norm(mrb, b3);
}

mrb_value
mrb_bint_xor(mrb_state *mrb, mrb_value x, mrb_value y)
{
  struct RBigint *b3 = bint_new(mrb);
  struct RBigint *b1 = RBIGINT(x);

#ifndef MRB_NO_FLOAT
  if (mrb_float_p(y)) {
    mpz_t z;
    mpz_init_set_int(mrb, &z, (mrb_int)mrb_float(y));
    mpz_xor(mrb, &b3->mp, &b1->mp, &z);
    mpz_clear(mrb, &z);
    return bint_norm(mrb, b3);
  }
#endif
  y = mrb_as_bint(mrb, y);
  struct RBigint *b2 = RBIGINT(y);
  mpz_xor(mrb, &b3->mp, &b1->mp, &b2->mp);
  return bint_norm(mrb, b3);
}

mrb_value
mrb_bint_rev(mrb_state *mrb, mrb_value x)
{
  struct RBigint *b1 = RBIGINT(x);
  struct RBigint *b2 = bint_new(mrb);

  mpz_neg(mrb, &b2->mp, &b1->mp);
  mpz_sub_int(mrb, &b2->mp, &b2->mp, 1);
  return bint_norm(mrb, b2);
}

mrb_value
mrb_bint_lshift(mrb_state *mrb, mrb_value x, mrb_int width)
{
  struct RBigint *b = RBIGINT(x);
  struct RBigint *b2 = bint_new(mrb);
  if (width < 0) {
    mpz_div_2exp(mrb, &b2->mp, &b->mp, -width);
  }
  else {
    mpz_mul_2exp(mrb, &b2->mp, &b->mp, width);
  }
  return bint_norm(mrb, b2);
}

mrb_value
mrb_bint_rshift(mrb_state *mrb, mrb_value x, mrb_int width)
{
  struct RBigint *b = RBIGINT(x);
  struct RBigint *b2 = bint_new(mrb);
  if (width < 0) {
    mpz_mul_2exp(mrb, &b2->mp, &b->mp, -width);
  }
  else {
    mpz_div_2exp(mrb, &b2->mp, &b->mp, width);
  }
  return bint_norm(mrb, b2);
}
