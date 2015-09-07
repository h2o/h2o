#include "mruby.h"
#include "mruby/array.h"
#include "mruby/class.h"
#include "mruby/string.h"
#include "mruby/range.h"
#include "mruby/numeric.h"
#include "mruby/re.h"
#include <string.h>

static const char utf8len_codepage[256] =
{
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
  2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,
  3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,4,4,4,4,4,1,1,1,1,1,1,1,1,1,1,1,
};

static const char utf8len_codepage_zero[256] =
{
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,
  3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,4,4,4,4,4,0,0,0,0,0,0,0,0,0,0,0,
};

static mrb_int
utf8code(unsigned char* p)
{
  mrb_int len;

  if (p[0] < 0x80)
    return p[0];

  len = utf8len_codepage_zero[p[0]];
  if (len > 1 && (p[1] & 0xc0) == 0x80) {
    if (len == 2)
      return ((p[0] & 0x1f) << 6) + (p[1] & 0x3f);
    if ((p[2] & 0xc0) == 0x80) {
      if (len == 3)
        return ((p[0] & 0x0f) << 12) + ((p[1] & 0x3f) << 6)
          + (p[2] & 0x3f);
      if ((p[3] & 0xc0) == 0x80) {
        if (len == 4)
          return ((p[0] & 0x07) << 18) + ((p[1] & 0x3f) << 12)
            + ((p[2] & 0x3f) << 6) + (p[3] & 0x3f);
        if ((p[4] & 0xc0) == 0x80) {
          if (len == 5)
            return ((p[0] & 0x03) << 24) + ((p[1] & 0x3f) << 18)
              + ((p[2] & 0x3f) << 12) + ((p[3] & 0x3f) << 6)
              + (p[4] & 0x3f);
          if ((p[5] & 0xc0) == 0x80 && len == 6)
            return ((p[0] & 0x01) << 30) + ((p[1] & 0x3f) << 24)
              + ((p[2] & 0x3f) << 18) + ((p[3] & 0x3f) << 12)
              + ((p[4] & 0x3f) << 6) + (p[5] & 0x3f);
        }
      }
    }
  }
  return p[0];
}

static mrb_value mrb_fixnum_chr(mrb_state*, mrb_value);

static mrb_int
utf8len(unsigned char* p)
{
  mrb_int len;
  mrb_int i;

  if (*p == 0)
    return 1;
  len = utf8len_codepage[*p];
  for (i = 1; i < len; ++i)
    if ((p[i] & 0xc0) != 0x80)
      return 1;
  return len;
}

static mrb_int
mrb_utf8_strlen(mrb_value str, mrb_int len)
{
  mrb_int total = 0;
  unsigned char* p = (unsigned char*) RSTRING_PTR(str);
  unsigned char* e = p;
  e += len < 0 ? RSTRING_LEN(str) : len;
  while (p<e) {
    p += utf8len(p);
    total++;
  }
  return total;
}

static mrb_value
mrb_str_size(mrb_state *mrb, mrb_value str)
{
  return mrb_fixnum_value(mrb_utf8_strlen(str, -1));
}

#define RSTRING_LEN_UTF8(s) mrb_utf8_strlen(s, -1)

static inline mrb_int
mrb_memsearch_qs(const unsigned char *xs, mrb_int m, const unsigned char *ys, mrb_int n)
{
  const unsigned char *x = xs, *xe = xs + m;
  const unsigned char *y = ys;
  int i, qstable[256];

  /* Preprocessing */
  for (i = 0; i < 256; ++i)
    qstable[i] = m + 1;
  for (; x < xe; ++x)
    qstable[*x] = xe - x;
  /* Searching */
  for (; y + m <= ys + n; y += *(qstable + y[m])) {
    if (*xs == *y && memcmp(xs, y, m) == 0)
      return y - ys;
  }
  return -1;
}
static mrb_int
mrb_memsearch(const void *x0, mrb_int m, const void *y0, mrb_int n)
{
  const unsigned char *x = (const unsigned char *)x0, *y = (const unsigned char *)y0;

  if (m > n) return -1;
  else if (m == n) {
    return memcmp(x0, y0, m) == 0 ? 0 : -1;
  }
  else if (m < 1) {
    return 0;
  }
  else if (m == 1) {
    const unsigned char *ys = y, *ye = ys + n;
    for (; y < ye; ++y) {
      if (*x == *y)
        return y - ys;
    }
    return -1;
  }
  return mrb_memsearch_qs((const unsigned char *)x0, m, (const unsigned char *)y0, n);
}

static mrb_value
str_subseq(mrb_state *mrb, mrb_value str, mrb_int beg, mrb_int len)
{
  mrb_int i;
  unsigned char *p = (unsigned char*) RSTRING_PTR(str), *t;
  unsigned char *e = p + RSTRING_LEN(str);

  for (i = 0; i < beg && p<e; i++) {
    p += utf8len(p);
  }
  t = p;
  for (i = 0; i < len && t<e; i++) {
    t += utf8len(t);
  }
  return mrb_str_new(mrb, (const char*)p, (size_t)(t - p));
}

static mrb_value
str_substr(mrb_state *mrb, mrb_value str, mrb_int beg, mrb_int len)
{
  mrb_value str2;
  mrb_int len8 = RSTRING_LEN_UTF8(str);

  if (len < 0) return mrb_nil_value();
  if (len8 == 0) {
    len = 0;
  }
  else if (beg < 0) {
    beg = len8 + beg;
  }
  if (beg > len8) return mrb_nil_value();
  if (beg < 0) {
    beg += len8;
    if (beg < 0) return mrb_nil_value();
  }
  if (beg + len > len8)
    len = len8 - beg;
  if (len <= 0) {
    len = 0;
  }
  str2 = str_subseq(mrb, str, beg, len);

  return str2;
}

static mrb_int
str_index(mrb_state *mrb, mrb_value str, mrb_value sub, mrb_int offset)
{
  mrb_int pos;
  char *s, *sptr;
  mrb_int len, slen;

  len = RSTRING_LEN(str);
  slen = RSTRING_LEN(sub);
  if (offset < 0) {
    offset += len;
    if (offset < 0) return -1;
  }
  if (len - offset < slen) return -1;
  s = RSTRING_PTR(str);
  if (offset) {
    s += offset;
  }
  if (slen == 0) return offset;
  /* need proceed one character at a time */
  sptr = RSTRING_PTR(sub);
  slen = RSTRING_LEN(sub);
  len = RSTRING_LEN(str) - offset;
  pos = mrb_memsearch(sptr, slen, s, len);
  if (pos < 0) return pos;
  return pos + offset;
}

static mrb_int
str_rindex(mrb_state *mrb, mrb_value str, mrb_value sub, mrb_int pos)
{
  char *s, *sbeg, *t;
  struct RString *ps = mrb_str_ptr(str);
  mrb_int len = RSTRING_LEN(sub);

  /* substring longer than string */
  if (RSTR_LEN(ps) < len) return -1;
  if (RSTR_LEN(ps) - pos < len) {
    pos = RSTR_LEN(ps) - len;
  }
  sbeg = RSTR_PTR(ps);
  s = RSTR_PTR(ps) + pos;
  t = RSTRING_PTR(sub);
  if (len) {
    while (sbeg <= s) {
      if (memcmp(s, t, len) == 0) {
        return s - RSTR_PTR(ps);
      }
      s--;
    }
    return -1;
  }
  else {
    return pos;
  }
}

static mrb_value
mrb_str_aref(mrb_state *mrb, mrb_value str, mrb_value indx)
{
  mrb_int idx;

  mrb_regexp_check(mrb, indx);
  switch (mrb_type(indx)) {
    case MRB_TT_FLOAT:
      indx = mrb_flo_to_fixnum(mrb, indx);
      /* fall through */
    case MRB_TT_FIXNUM:
      idx = mrb_fixnum(indx);

num_index:
      str = str_substr(mrb, str, idx, 1);
      if (!mrb_nil_p(str) && RSTRING_LEN(str) == 0) return mrb_nil_value();
      return str;

    case MRB_TT_STRING:
      if (str_index(mrb, str, indx, 0) != -1)
        return mrb_str_dup(mrb, indx);
      return mrb_nil_value();

    case MRB_TT_RANGE:
      /* check if indx is Range */
      {
        mrb_int beg, len;
        mrb_value tmp;

        len = RSTRING_LEN_UTF8(str);
        if (mrb_range_beg_len(mrb, indx, &beg, &len, len)) {
          tmp = str_subseq(mrb, str, beg, len);
          return tmp;
        }
        else {
          return mrb_nil_value();
        }
      }
    default:
      idx = mrb_fixnum(indx);
      goto num_index;
    }
    return mrb_nil_value();    /* not reached */
}

static mrb_value
mrb_str_aref_m(mrb_state *mrb, mrb_value str)
{
  mrb_value a1, a2;
  int argc;

  argc = mrb_get_args(mrb, "o|o", &a1, &a2);
  if (argc == 2) {
    mrb_regexp_check(mrb, a1);
    return str_substr(mrb, str, mrb_fixnum(a1), mrb_fixnum(a2));
  }
  if (argc != 1) {
    mrb_raisef(mrb, E_ARGUMENT_ERROR, "wrong number of arguments (%S for 1)", mrb_fixnum_value(argc));
  }
  return mrb_str_aref(mrb, str, a1);
}

static mrb_value
mrb_str_index_m(mrb_state *mrb, mrb_value str)
{
  mrb_value *argv;
  mrb_int argc;

  mrb_value sub;
  mrb_int pos;

  mrb_get_args(mrb, "*", &argv, &argc);
  if (argc == 2) {
    pos = mrb_fixnum(argv[1]);
    sub = argv[0];
  }
  else {
    pos = 0;
    if (argc > 0)
      sub = argv[0];
    else
      sub = mrb_nil_value();

  }
  mrb_regexp_check(mrb, sub);
  if (pos < 0) {
    pos += RSTRING_LEN(str);
    if (pos < 0) {
      return mrb_nil_value();
    }
  }

  if (mrb_type(sub) == MRB_TT_FIXNUM) {
    sub = mrb_fixnum_chr(mrb, sub);
  }

  switch (mrb_type(sub)) {
    default: {
      mrb_value tmp;

      tmp = mrb_check_string_type(mrb, sub);
      if (mrb_nil_p(tmp)) {
        mrb_raisef(mrb, E_TYPE_ERROR, "type mismatch: %S given", sub);
      }
      sub = tmp;
    }
    /* fall through */
    case MRB_TT_STRING:
      pos = str_index(mrb, str, sub, pos);
      break;
  }

  if (pos == -1) return mrb_nil_value();
  return mrb_fixnum_value(mrb_utf8_strlen(str, pos));
}

static mrb_value
mrb_str_reverse_bang(mrb_state *mrb, mrb_value str)
{
  mrb_int utf8_len = mrb_utf8_strlen(str, -1);
  if (utf8_len > 1) {
    mrb_int len;
    char *buf;
    unsigned char *p, *e, *r;

    mrb_str_modify(mrb, mrb_str_ptr(str));
    len = RSTRING_LEN(str);
    buf = (char *)mrb_malloc(mrb, (size_t)len);
    p = (unsigned char*)buf;
    e = (unsigned char*)buf + len;

    memcpy(buf, RSTRING_PTR(str), len);
    r = (unsigned char*)RSTRING_PTR(str) + len;

    while (p<e) {
      mrb_int clen = utf8len(p);
      r -= clen;
      memcpy(r, p, clen);
      p += clen;
    }
    mrb_free(mrb, buf);
  }

  return str;
}

static mrb_value
mrb_str_rindex_m(mrb_state *mrb, mrb_value str)
{
  mrb_value *argv;
  mrb_int argc;
  mrb_value sub;
  mrb_value vpos;
  mrb_int pos, len = RSTRING_LEN(str);

  mrb_get_args(mrb, "*", &argv, &argc);
  if (argc == 2) {
    sub = argv[0];
    vpos = argv[1];
    pos = mrb_fixnum(vpos);
    if (pos < 0) {
      pos += len;
      if (pos < 0) {
        mrb_regexp_check(mrb, sub);
        return mrb_nil_value();
      }
    }
    if (pos > len) pos = len;
  }
  else {
    pos = len;
    if (argc > 0)
      sub = argv[0];
    else
      sub = mrb_nil_value();
  }
  mrb_regexp_check(mrb, sub);

  if (mrb_type(sub) == MRB_TT_FIXNUM) {
    sub = mrb_fixnum_chr(mrb, sub);
  }

  switch (mrb_type(sub)) {
    default: {
      mrb_value tmp;

      tmp = mrb_check_string_type(mrb, sub);
      if (mrb_nil_p(tmp)) {
        mrb_raisef(mrb, E_TYPE_ERROR, "type mismatch: %S given", sub);
      }
      sub = tmp;
    }
     /* fall through */
    case MRB_TT_STRING:
      pos = str_rindex(mrb, str, sub, pos);
      break;
  }

  if (pos == -1) return mrb_nil_value();
  return mrb_fixnum_value(mrb_utf8_strlen(str, pos));
}

static mrb_value
mrb_str_reverse(mrb_state *mrb, mrb_value str)
{
  return mrb_str_reverse_bang(mrb, mrb_str_dup(mrb, str));
}

static mrb_value
mrb_fixnum_chr(mrb_state *mrb, mrb_value num)
{
  mrb_int cp = mrb_fixnum(num);
  char utf8[4];
  mrb_int len;

  if (cp < 0 || 0x10FFFF < cp) {
    mrb_raisef(mrb, E_RANGE_ERROR, "%S out of char range", num);
  }
  if (cp < 0x80) {
    utf8[0] = (char)cp;
    len = 1;
  }
  else if (cp < 0x800) {
    utf8[0] = (char)(0xC0 | (cp >> 6));
    utf8[1] = (char)(0x80 | (cp & 0x3F));
    len = 2;
  }
  else if (cp < 0x10000) {
    utf8[0] = (char)(0xE0 |  (cp >> 12));
    utf8[1] = (char)(0x80 | ((cp >>  6) & 0x3F));
    utf8[2] = (char)(0x80 | ( cp        & 0x3F));
    len = 3;
  }
  else {
    utf8[0] = (char)(0xF0 |  (cp >> 18));
    utf8[1] = (char)(0x80 | ((cp >> 12) & 0x3F));
    utf8[2] = (char)(0x80 | ((cp >>  6) & 0x3F));
    utf8[3] = (char)(0x80 | ( cp        & 0x3F));
    len = 4;
  }
  return mrb_str_new(mrb, utf8, len);
}

static mrb_value
mrb_str_ord(mrb_state* mrb, mrb_value str)
{
  mrb_int len = RSTRING_LEN(str);

  if (len == 0) mrb_raise(mrb, E_ARGUMENT_ERROR, "empty string");
  return mrb_fixnum_value(utf8code((unsigned char*) RSTRING_PTR(str)));
}

static mrb_value
mrb_str_split_m(mrb_state *mrb, mrb_value str)
{
  int argc;
  mrb_value spat = mrb_nil_value();
  enum {awk, string, regexp} split_type = string;
  long i = 0, lim_p;
  mrb_int beg;
  mrb_int end;
  mrb_int lim = 0;
  mrb_value result, tmp;

  argc = mrb_get_args(mrb, "|oi", &spat, &lim);
  lim_p = (lim > 0 && argc == 2);
  if (argc == 2) {
    if (lim == 1) {
      if (RSTRING_LEN(str) == 0)
        return mrb_ary_new_capa(mrb, 0);
      return mrb_ary_new_from_values(mrb, 1, &str);
    }
    i = 1;
  }

  if (argc == 0 || mrb_nil_p(spat)) {
    split_type = awk;
  }
  else {
    if (mrb_string_p(spat)) {
      split_type = string;
      if (RSTRING_LEN(spat) == 1 && RSTRING_PTR(spat)[0] == ' '){
        split_type = awk;
      }
    }
    else {
      mrb_noregexp(mrb, str);
    }
  }

  result = mrb_ary_new(mrb);
  beg = 0;
  if (split_type == awk) {
    char *ptr = RSTRING_PTR(str);
    char *eptr = RSTRING_END(str);
    char *bptr = ptr;
    int skip = 1;
    unsigned int c;

    end = beg;
    while (ptr < eptr) {
      int ai = mrb_gc_arena_save(mrb);
      c = (unsigned char)*ptr++;
      if (skip) {
        if (ISSPACE(c)) {
          beg = ptr - bptr;
        }
        else {
          end = ptr - bptr;
          skip = 0;
          if (lim_p && lim <= i) break;
        }
      }
      else if (ISSPACE(c)) {
        mrb_ary_push(mrb, result, str_subseq(mrb, str, beg, end-beg));
        mrb_gc_arena_restore(mrb, ai);
        skip = 1;
        beg = ptr - bptr;
        if (lim_p) ++i;
      }
      else {
        end = ptr - bptr;
      }
    }
  }
  else if (split_type == string) {
    char *ptr = RSTRING_PTR(str); // s->as.ary
    char *temp = ptr;
    char *eptr = RSTRING_END(str);
    mrb_int slen = RSTRING_LEN(spat);

    if (slen == 0) {
      int ai = mrb_gc_arena_save(mrb);
      while (ptr < eptr) {
        mrb_ary_push(mrb, result, str_subseq(mrb, str, ptr-temp, 1));
        mrb_gc_arena_restore(mrb, ai);
        ptr++;
        if (lim_p && lim <= ++i) break;
      }
    }
    else {
      char *sptr = RSTRING_PTR(spat);
      int ai = mrb_gc_arena_save(mrb);

      while (ptr < eptr &&
        (end = mrb_memsearch(sptr, slen, ptr, eptr - ptr)) >= 0) {
        /*        mrb_ary_push(mrb, result, str_subseq(mrb, str, ptr - temp, end)); */
        mrb_ary_push(mrb, result, mrb_str_new(mrb, ptr, end));
        mrb_gc_arena_restore(mrb, ai);
        ptr += end + slen;
        if (lim_p && lim <= ++i) break;
      }
    }
    beg = ptr - temp;
  }
  else {
    mrb_noregexp(mrb, str);
  }
  if (RSTRING_LEN(str) > 0 && (lim_p || RSTRING_LEN(str) > beg || lim < 0)) {
    if (RSTRING_LEN(str) == beg) {
      tmp = mrb_str_new_lit(mrb, "");
    }
    else {
      tmp = mrb_str_new(mrb, RSTRING_PTR(str)+beg, RSTRING_LEN(str)-beg);
    }
    mrb_ary_push(mrb, result, tmp);
  }
  if (!lim_p && lim == 0) {
    mrb_int len;
    while ((len = RARRAY_LEN(result)) > 0 &&
           (tmp = RARRAY_PTR(result)[len-1], RSTRING_LEN(tmp) == 0))
      mrb_ary_pop(mrb, result);
  }

  return result;
}

static mrb_value
mrb_str_chr(mrb_state *mrb, mrb_value self)
{
  return str_substr(mrb, self, 0, 1);
}

static mrb_value
mrb_str_chars(mrb_state *mrb, mrb_value self)
{
  mrb_value result;
  mrb_value blk;
  int ai;
  mrb_int len;
  mrb_value arg;
  char *p = RSTRING_PTR(self);
  char *e = p + RSTRING_LEN(self);

  mrb_get_args(mrb, "&", &blk);

  result = mrb_ary_new(mrb);

  if (!mrb_nil_p(blk)) {
    while (p < e) {
      len = utf8len((unsigned char*) p);
      arg = mrb_str_new(mrb, p, len);
      mrb_yield_argv(mrb, blk, 1, &arg);
      p += len;
    }
    return self;
  }
  while (p < e) {
    ai = mrb_gc_arena_save(mrb);
    len = utf8len((unsigned char*) p);
    mrb_ary_push(mrb, result, mrb_str_new(mrb, p, len));
    mrb_gc_arena_restore(mrb, ai);
    p += len;
  }
  return result;
}

static mrb_value
mrb_str_codepoints(mrb_state *mrb, mrb_value self)
{
  mrb_value result;
  mrb_value blk;
  int ai;
  mrb_int len;
  mrb_value arg;
  char *p = RSTRING_PTR(self);
  char *e = p + RSTRING_LEN(self);

  mrb_get_args(mrb, "&", &blk);

  result = mrb_ary_new(mrb);

  if (!mrb_nil_p(blk)) {
    while (p < e) {
      len = utf8len((unsigned char*) p);
      arg = mrb_fixnum_value(utf8code((unsigned char*) p));
      mrb_yield_argv(mrb, blk, 1, &arg);
      p += len;
    }
    return self;
  }
  while (p < e) {
    ai = mrb_gc_arena_save(mrb);
    len = utf8len((unsigned char*) p);
    mrb_ary_push(mrb, result, mrb_fixnum_value(utf8code((unsigned char*) p)));
    mrb_gc_arena_restore(mrb, ai);
    p += len;
  }
  return result;
}

void
mrb_mruby_string_utf8_gem_init(mrb_state* mrb)
{
  struct RClass * s = mrb->string_class;

  mrb_define_method(mrb, s, "size", mrb_str_size, MRB_ARGS_NONE());
  mrb_define_method(mrb, s, "length", mrb_str_size, MRB_ARGS_NONE());
  mrb_define_method(mrb, s, "index", mrb_str_index_m, MRB_ARGS_ANY());
  mrb_define_method(mrb, s, "[]", mrb_str_aref_m, MRB_ARGS_ANY());
  mrb_define_method(mrb, s, "ord", mrb_str_ord, MRB_ARGS_NONE());
  mrb_define_method(mrb, s, "slice", mrb_str_aref_m, MRB_ARGS_ANY());
  mrb_define_method(mrb, s, "split", mrb_str_split_m, MRB_ARGS_ANY());
  mrb_define_method(mrb, s, "reverse",  mrb_str_reverse, MRB_ARGS_NONE());
  mrb_define_method(mrb, s, "reverse!", mrb_str_reverse_bang, MRB_ARGS_NONE());
  mrb_define_method(mrb, s, "rindex", mrb_str_rindex_m, MRB_ARGS_ANY());
  mrb_define_method(mrb, s, "chr", mrb_str_chr, MRB_ARGS_NONE());
  mrb_define_method(mrb, s, "chars", mrb_str_chars, MRB_ARGS_NONE());
  mrb_alias_method(mrb, s, mrb_intern_lit(mrb, "each_char"), mrb_intern_lit(mrb, "chars"));
  mrb_define_method(mrb, s, "codepoints", mrb_str_codepoints, MRB_ARGS_NONE());
  mrb_alias_method(mrb, s, mrb_intern_lit(mrb, "each_codepoint"), mrb_intern_lit(mrb, "codepoints"));

  mrb_define_method(mrb, mrb->fixnum_class, "chr", mrb_fixnum_chr, MRB_ARGS_NONE());
}

void
mrb_mruby_string_utf8_gem_final(mrb_state* mrb)
{
}
