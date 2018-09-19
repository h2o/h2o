#include <string.h>
#include <mruby.h>
#include <mruby/array.h>
#include <mruby/class.h>
#include <mruby/string.h>
#include <mruby/range.h>

static mrb_value
mrb_str_getbyte(mrb_state *mrb, mrb_value str)
{
  mrb_int pos;
  mrb_get_args(mrb, "i", &pos);

  if (pos < 0)
    pos += RSTRING_LEN(str);
  if (pos < 0 ||  RSTRING_LEN(str) <= pos)
    return mrb_nil_value();

  return mrb_fixnum_value((unsigned char)RSTRING_PTR(str)[pos]);
}

static mrb_value
mrb_str_setbyte(mrb_state *mrb, mrb_value str)
{
  mrb_int pos, byte;
  mrb_int len;

  mrb_get_args(mrb, "ii", &pos, &byte);

  len = RSTRING_LEN(str);
  if (pos < -len || len <= pos)
    mrb_raisef(mrb, E_INDEX_ERROR, "index %S is out of array", mrb_fixnum_value(pos));
  if (pos < 0)
    pos += len;

  mrb_str_modify(mrb, mrb_str_ptr(str));
  byte &= 0xff;
  RSTRING_PTR(str)[pos] = (unsigned char)byte;
  return mrb_fixnum_value((unsigned char)byte);
}

static mrb_value
mrb_str_byteslice(mrb_state *mrb, mrb_value str)
{
  mrb_value a1;
  mrb_int len;

  if (mrb_get_argc(mrb) == 2) {
    mrb_int pos;
    mrb_get_args(mrb, "ii", &pos, &len);
    return mrb_str_substr(mrb, str, pos, len);
  }
  mrb_get_args(mrb, "o|i", &a1, &len);
  switch (mrb_type(a1)) {
  case MRB_TT_RANGE:
    {
      mrb_int beg;

      len = RSTRING_LEN(str);
      switch (mrb_range_beg_len(mrb, a1, &beg, &len, len, TRUE)) {
      case 0:                   /* not range */
        break;
      case 1:                   /* range */
        return mrb_str_substr(mrb, str, beg, len);
      case 2:                   /* out of range */
        mrb_raisef(mrb, E_RANGE_ERROR, "%S out of range", a1);
        break;
      }
      return mrb_nil_value();
    }
#ifndef MRB_WITHOUT_FLOAT
  case MRB_TT_FLOAT:
    a1 = mrb_fixnum_value((mrb_int)mrb_float(a1));
    /* fall through */
#endif
  case MRB_TT_FIXNUM:
    return mrb_str_substr(mrb, str, mrb_fixnum(a1), 1);
  default:
    mrb_raise(mrb, E_TYPE_ERROR, "wrong type of argument");
  }
  /* not reached */
  return mrb_nil_value();
}

/*
 *  call-seq:
 *     str.swapcase!   -> str or nil
 *
 *  Equivalent to <code>String#swapcase</code>, but modifies the receiver in
 *  place, returning <i>str</i>, or <code>nil</code> if no changes were made.
 *  Note: case conversion is effective only in ASCII region.
 */
static mrb_value
mrb_str_swapcase_bang(mrb_state *mrb, mrb_value str)
{
  char *p, *pend;
  int modify = 0;
  struct RString *s = mrb_str_ptr(str);

  mrb_str_modify(mrb, s);
  p = RSTRING_PTR(str);
  pend = p + RSTRING_LEN(str);
  while (p < pend) {
    if (ISUPPER(*p)) {
      *p = TOLOWER(*p);
      modify = 1;
    }
    else if (ISLOWER(*p)) {
      *p = TOUPPER(*p);
      modify = 1;
    }
    p++;
  }

  if (modify) return str;
  return mrb_nil_value();
}

/*
 *  call-seq:
 *     str.swapcase   -> new_str
 *
 *  Returns a copy of <i>str</i> with uppercase alphabetic characters converted
 *  to lowercase and lowercase characters converted to uppercase.
 *  Note: case conversion is effective only in ASCII region.
 *
 *     "Hello".swapcase          #=> "hELLO"
 *     "cYbEr_PuNk11".swapcase   #=> "CyBeR_pUnK11"
 */
static mrb_value
mrb_str_swapcase(mrb_state *mrb, mrb_value self)
{
  mrb_value str;

  str = mrb_str_dup(mrb, self);
  mrb_str_swapcase_bang(mrb, str);
  return str;
}

static mrb_value mrb_fixnum_chr(mrb_state *mrb, mrb_value num);

/*
 *  call-seq:
 *     str << integer       -> str
 *     str.concat(integer)  -> str
 *     str << obj           -> str
 *     str.concat(obj)      -> str
 *
 *  Append---Concatenates the given object to <i>str</i>. If the object is a
 *  <code>Integer</code>, it is considered as a codepoint, and is converted
 *  to a character before concatenation.
 *
 *     a = "hello "
 *     a << "world"   #=> "hello world"
 *     a.concat(33)   #=> "hello world!"
 */
static mrb_value
mrb_str_concat_m(mrb_state *mrb, mrb_value self)
{
  mrb_value str;

  mrb_get_args(mrb, "o", &str);
  if (mrb_fixnum_p(str))
    str = mrb_fixnum_chr(mrb, str);
  else
    str = mrb_string_type(mrb, str);
  mrb_str_concat(mrb, self, str);
  return self;
}

/*
 *  call-seq:
 *     str.start_with?([prefixes]+)   -> true or false
 *
 *  Returns true if +str+ starts with one of the +prefixes+ given.
 *
 *    "hello".start_with?("hell")               #=> true
 *
 *    # returns true if one of the prefixes matches.
 *    "hello".start_with?("heaven", "hell")     #=> true
 *    "hello".start_with?("heaven", "paradise") #=> false
 *    "h".start_with?("heaven", "hell")         #=> false
 */
static mrb_value
mrb_str_start_with(mrb_state *mrb, mrb_value self)
{
  mrb_value *argv, sub;
  mrb_int argc, i;
  mrb_get_args(mrb, "*", &argv, &argc);

  for (i = 0; i < argc; i++) {
    size_t len_l, len_r;
    int ai = mrb_gc_arena_save(mrb);
    sub = mrb_string_type(mrb, argv[i]);
    mrb_gc_arena_restore(mrb, ai);
    len_l = RSTRING_LEN(self);
    len_r = RSTRING_LEN(sub);
    if (len_l >= len_r) {
      if (memcmp(RSTRING_PTR(self), RSTRING_PTR(sub), len_r) == 0) {
        return mrb_true_value();
      }
    }
  }
  return mrb_false_value();
}

/*
 *  call-seq:
 *     str.end_with?([suffixes]+)   -> true or false
 *
 *  Returns true if +str+ ends with one of the +suffixes+ given.
 */
static mrb_value
mrb_str_end_with(mrb_state *mrb, mrb_value self)
{
  mrb_value *argv, sub;
  mrb_int argc, i;
  mrb_get_args(mrb, "*", &argv, &argc);

  for (i = 0; i < argc; i++) {
    size_t len_l, len_r;
    int ai = mrb_gc_arena_save(mrb);
    sub = mrb_string_type(mrb, argv[i]);
    mrb_gc_arena_restore(mrb, ai);
    len_l = RSTRING_LEN(self);
    len_r = RSTRING_LEN(sub);
    if (len_l >= len_r) {
      if (memcmp(RSTRING_PTR(self) + (len_l - len_r),
                 RSTRING_PTR(sub),
                 len_r) == 0) {
        return mrb_true_value();
      }
    }
  }
  return mrb_false_value();
}

static mrb_value
mrb_str_hex(mrb_state *mrb, mrb_value self)
{
  return mrb_str_to_inum(mrb, self, 16, FALSE);
}

static mrb_value
mrb_str_oct(mrb_state *mrb, mrb_value self)
{
  return mrb_str_to_inum(mrb, self, 8, FALSE);
}

/*
 *  call-seq:
 *     string.chr    ->  string
 *
 *  Returns a one-character string at the beginning of the string.
 *
 *     a = "abcde"
 *     a.chr    #=> "a"
 */
static mrb_value
mrb_str_chr(mrb_state *mrb, mrb_value self)
{
  return mrb_str_substr(mrb, self, 0, 1);
}

static mrb_value
mrb_fixnum_chr(mrb_state *mrb, mrb_value num)
{
  mrb_int cp = mrb_fixnum(num);
#ifdef MRB_UTF8_STRING
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
#else
  char c;

  if (cp < 0 || 0xff < cp) {
    mrb_raisef(mrb, E_RANGE_ERROR, "%S out of char range", num);
  }
  c = (char)cp;
  return mrb_str_new(mrb, &c, 1);
#endif
}

/*
 *  call-seq:
 *     string.succ    ->  string
 *
 *  Returns next sequence of the string;
 *
 *     a = "abc"
 *     a.succ    #=> "abd"
 */
static mrb_value
mrb_str_succ_bang(mrb_state *mrb, mrb_value self)
{
  mrb_value result;
  unsigned char *p, *e, *b, *t;
  const char *prepend;
  struct RString *s = mrb_str_ptr(self);
  mrb_int l;

  if (RSTRING_LEN(self) == 0)
    return self;

  mrb_str_modify(mrb, s);
  l = RSTRING_LEN(self);
  b = p = (unsigned char*) RSTRING_PTR(self);
  t = e = p + l;
  *(e--) = 0;

  // find trailing ascii/number
  while (e >= b) {
    if (ISALNUM(*e))
      break;
    e--;
  }
  if (e < b) {
    e = p + l - 1;
    result = mrb_str_new_lit(mrb, "");
  }
  else {
    // find leading letter of the ascii/number
    b = e;
    while (b > p) {
      if (!ISALNUM(*b) || (ISALNUM(*b) && *b != '9' && *b != 'z' && *b != 'Z'))
        break;
      b--;
    }
    if (!ISALNUM(*b))
      b++;
    result = mrb_str_new(mrb, (char*) p, b - p);
  }

  while (e >= b) {
    if (!ISALNUM(*e)) {
      if (*e == 0xff) {
        mrb_str_cat_lit(mrb, result, "\x01");
        (*e) = 0;
      }
      else
        (*e)++;
      break;
    }
    prepend = NULL;
    if (*e == '9') {
      if (e == b) prepend = "1";
      *e = '0';
    }
    else if (*e == 'z') {
      if (e == b) prepend = "a";
      *e = 'a';
    }
    else if (*e == 'Z') {
      if (e == b) prepend = "A";
      *e = 'A';
    }
    else {
      (*e)++;
      break;
    }
    if (prepend) mrb_str_cat_cstr(mrb, result, prepend);
    e--;
  }
  result = mrb_str_cat(mrb, result, (char*) b, t - b);
  l = RSTRING_LEN(result);
  mrb_str_resize(mrb, self, l);
  memcpy(RSTRING_PTR(self), RSTRING_PTR(result), l);
  return self;
}

static mrb_value
mrb_str_succ(mrb_state *mrb, mrb_value self)
{
  mrb_value str;

  str = mrb_str_dup(mrb, self);
  mrb_str_succ_bang(mrb, str);
  return str;
}

#ifdef MRB_UTF8_STRING
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

static mrb_value
mrb_str_ord(mrb_state* mrb, mrb_value str)
{
  if (RSTRING_LEN(str) == 0)
    mrb_raise(mrb, E_ARGUMENT_ERROR, "empty string");
  return mrb_fixnum_value(utf8code((unsigned char*) RSTRING_PTR(str)));
}
#else
static mrb_value
mrb_str_ord(mrb_state* mrb, mrb_value str)
{
  if (RSTRING_LEN(str) == 0)
    mrb_raise(mrb, E_ARGUMENT_ERROR, "empty string");
  return mrb_fixnum_value((unsigned char)RSTRING_PTR(str)[0]);
}
#endif

/*
 *  call-seq:
 *     str.delete_prefix!(prefix) -> self or nil
 *
 *  Deletes leading <code>prefix</code> from <i>str</i>, returning
 *  <code>nil</code> if no change was made.
 *
 *     "hello".delete_prefix!("hel") #=> "lo"
 *     "hello".delete_prefix!("llo") #=> nil
 */
static mrb_value
mrb_str_del_prefix_bang(mrb_state *mrb, mrb_value self)
{
  mrb_int plen, slen;
  char *ptr, *s;
  struct RString *str = RSTRING(self);

  mrb_get_args(mrb, "s", &ptr, &plen);
  slen = RSTR_LEN(str);
  if (plen > slen) return mrb_nil_value();
  s = RSTR_PTR(str);
  if (memcmp(s, ptr, plen) != 0) return mrb_nil_value();
  if (!MRB_FROZEN_P(str) && (RSTR_SHARED_P(str) || RSTR_FSHARED_P(str))) {
    str->as.heap.ptr += plen;
  }
  else {
    mrb_str_modify(mrb, str);
    s = RSTR_PTR(str);
    memmove(s, s+plen, slen-plen);
  }
  RSTR_SET_LEN(str, slen-plen);
  return self;
}

/*
 *  call-seq:
 *     str.delete_prefix(prefix) -> new_str
 *
 *  Returns a copy of <i>str</i> with leading <code>prefix</code> deleted.
 *
 *     "hello".delete_prefix("hel") #=> "lo"
 *     "hello".delete_prefix("llo") #=> "hello"
 */
static mrb_value
mrb_str_del_prefix(mrb_state *mrb, mrb_value self)
{
  mrb_int plen, slen;
  char *ptr;

  mrb_get_args(mrb, "s", &ptr, &plen);
  slen = RSTRING_LEN(self);
  if (plen > slen) return mrb_str_dup(mrb, self);
  if (memcmp(RSTRING_PTR(self), ptr, plen) != 0)
    return mrb_str_dup(mrb, self);
  return mrb_str_substr(mrb, self, plen, slen-plen);
}

/*
 *  call-seq:
 *     str.delete_suffix!(suffix) -> self or nil
 *
 *  Deletes trailing <code>suffix</code> from <i>str</i>, returning
 *  <code>nil</code> if no change was made.
 *
 *     "hello".delete_suffix!("llo") #=> "he"
 *     "hello".delete_suffix!("hel") #=> nil
 */
static mrb_value
mrb_str_del_suffix_bang(mrb_state *mrb, mrb_value self)
{
  mrb_int plen, slen;
  char *ptr, *s;
  struct RString *str = RSTRING(self);

  mrb_get_args(mrb, "s", &ptr, &plen);
  slen = RSTR_LEN(str);
  if (plen > slen) return mrb_nil_value();
  s = RSTR_PTR(str);
  if (memcmp(s+slen-plen, ptr, plen) != 0) return mrb_nil_value();
  if (!MRB_FROZEN_P(str) && (RSTR_SHARED_P(str) || RSTR_FSHARED_P(str))) {
    /* no need to modify string */
  }
  else {
    mrb_str_modify(mrb, str);
  }
  RSTR_SET_LEN(str, slen-plen);
  return self;
}

/*
 *  call-seq:
 *     str.delete_suffix(suffix) -> new_str
 *
 *  Returns a copy of <i>str</i> with leading <code>suffix</code> deleted.
 *
 *     "hello".delete_suffix("hel") #=> "lo"
 *     "hello".delete_suffix("llo") #=> "hello"
 */
static mrb_value
mrb_str_del_suffix(mrb_state *mrb, mrb_value self)
{
  mrb_int plen, slen;
  char *ptr;

  mrb_get_args(mrb, "s", &ptr, &plen);
  slen = RSTRING_LEN(self);
  if (plen > slen) return mrb_str_dup(mrb, self);
  if (memcmp(RSTRING_PTR(self)+slen-plen, ptr, plen) != 0)
    return mrb_str_dup(mrb, self);
  return mrb_str_substr(mrb, self, 0, slen-plen);
}

static mrb_value
mrb_str_lines(mrb_state *mrb, mrb_value self)
{
  mrb_value result;
  int ai;
  mrb_int len;
  char *b = RSTRING_PTR(self);
  char *p = b, *t;
  char *e = b + RSTRING_LEN(self);

  mrb_get_args(mrb, "");

  result = mrb_ary_new(mrb);
  ai = mrb_gc_arena_save(mrb);
  while (p < e) {
    t = p;
    while (p < e && *p != '\n') p++;
    if (*p == '\n') p++;
    len = (mrb_int) (p - t);
    mrb_ary_push(mrb, result, mrb_str_new(mrb, t, len));
    mrb_gc_arena_restore(mrb, ai);
  }
  return result;
}

void
mrb_mruby_string_ext_gem_init(mrb_state* mrb)
{
  struct RClass * s = mrb->string_class;

  mrb_define_method(mrb, s, "dump",            mrb_str_dump,            MRB_ARGS_NONE());
  mrb_define_method(mrb, s, "getbyte",         mrb_str_getbyte,         MRB_ARGS_REQ(1));
  mrb_define_method(mrb, s, "setbyte",         mrb_str_setbyte,         MRB_ARGS_REQ(2));
  mrb_define_method(mrb, s, "byteslice",       mrb_str_byteslice,       MRB_ARGS_REQ(1)|MRB_ARGS_OPT(1));
  mrb_define_method(mrb, s, "swapcase!",       mrb_str_swapcase_bang,   MRB_ARGS_NONE());
  mrb_define_method(mrb, s, "swapcase",        mrb_str_swapcase,        MRB_ARGS_NONE());
  mrb_define_method(mrb, s, "concat",          mrb_str_concat_m,        MRB_ARGS_REQ(1));
  mrb_define_method(mrb, s, "<<",              mrb_str_concat_m,        MRB_ARGS_REQ(1));
  mrb_define_method(mrb, s, "start_with?",     mrb_str_start_with,      MRB_ARGS_REST());
  mrb_define_method(mrb, s, "end_with?",       mrb_str_end_with,        MRB_ARGS_REST());
  mrb_define_method(mrb, s, "hex",             mrb_str_hex,             MRB_ARGS_NONE());
  mrb_define_method(mrb, s, "oct",             mrb_str_oct,             MRB_ARGS_NONE());
  mrb_define_method(mrb, s, "chr",             mrb_str_chr,             MRB_ARGS_NONE());
  mrb_define_method(mrb, s, "succ",            mrb_str_succ,            MRB_ARGS_NONE());
  mrb_define_method(mrb, s, "succ!",           mrb_str_succ_bang,       MRB_ARGS_NONE());
  mrb_alias_method(mrb, s, mrb_intern_lit(mrb, "next"), mrb_intern_lit(mrb, "succ"));
  mrb_alias_method(mrb, s, mrb_intern_lit(mrb, "next!"), mrb_intern_lit(mrb, "succ!"));
  mrb_define_method(mrb, s, "ord",             mrb_str_ord,             MRB_ARGS_NONE());
  mrb_define_method(mrb, s, "delete_prefix!",  mrb_str_del_prefix_bang, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, s, "delete_prefix",   mrb_str_del_prefix,      MRB_ARGS_REQ(1));
  mrb_define_method(mrb, s, "delete_suffix!",  mrb_str_del_suffix_bang, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, s, "delete_suffix",   mrb_str_del_suffix,      MRB_ARGS_REQ(1));

  mrb_define_method(mrb, s, "__lines",         mrb_str_lines,           MRB_ARGS_NONE());
  mrb_define_method(mrb, mrb->fixnum_class, "chr", mrb_fixnum_chr, MRB_ARGS_NONE());
}

void
mrb_mruby_string_ext_gem_final(mrb_state* mrb)
{
}
