#include <string.h>
#include "mruby.h"
#include "mruby/array.h"
#include "mruby/class.h"
#include "mruby/string.h"
#include "mruby/range.h"

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
  long len = RSTRING_LEN(str);

  mrb_get_args(mrb, "ii", &pos, &byte);

  if (pos < -len || len <= pos)
    mrb_raisef(mrb, E_INDEX_ERROR, "index %S is out of array", mrb_fixnum_value(pos));
  if (pos < 0)
    pos += len;

  mrb_str_modify(mrb, mrb_str_ptr(str));
  byte &= 0xff;
  RSTRING_PTR(str)[pos] = byte;
  return mrb_fixnum_value((unsigned char)byte);
}

static mrb_value
mrb_str_byteslice(mrb_state *mrb, mrb_value str)
{
  mrb_value a1;
  mrb_int len;
  int argc;

  argc = mrb_get_args(mrb, "o|i", &a1, &len);
  if (argc == 2) {
    return mrb_str_substr(mrb, str, mrb_fixnum(a1), len);
  }
  switch (mrb_type(a1)) {
  case MRB_TT_RANGE:
    {
      mrb_int beg;

      len = RSTRING_LEN(str);
      if (mrb_range_beg_len(mrb, a1, &beg, &len, len)) {
        return mrb_str_substr(mrb, str, beg, len);
      }
      return mrb_nil_value();
    }
  case MRB_TT_FLOAT:
    a1 = mrb_fixnum_value((mrb_int)mrb_float(a1));
    /* fall through */
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
mrb_str_concat2(mrb_state *mrb, mrb_value self)
{
  mrb_value str;
  mrb_get_args(mrb, "S", &str);
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

/*
 *  call-seq:
 *     string.lines    ->  array of string
 *
 *  Returns strings per line;
 *
 *     a = "abc\ndef"
 *     a.lines    #=> ["abc\n", "def"]
 */
static mrb_value
mrb_str_lines(mrb_state *mrb, mrb_value self)
{
  mrb_value result;
  mrb_value blk;
  int ai;
  mrb_int len;
  mrb_value arg;
  char *p = RSTRING_PTR(self), *t;
  char *e = p + RSTRING_LEN(self);

  mrb_get_args(mrb, "&", &blk);

  result = mrb_ary_new(mrb);

  if (!mrb_nil_p(blk)) {
    while (p < e) {
      t = p;
      while (p < e && *p != '\n') p++;
      if (*p == '\n') p++;
      len = (mrb_int) (p - t);
      arg = mrb_str_new(mrb, t, len);
      mrb_yield_argv(mrb, blk, 1, &arg);
    }
    return self;
  }
  while (p < e) {
    ai = mrb_gc_arena_save(mrb);
    t = p;
    while (p < e && *p != '\n') p++;
    if (*p == '\n') p++;
    len = (mrb_int) (p - t);
    mrb_ary_push(mrb, result, mrb_str_new(mrb, t, len));
    mrb_gc_arena_restore(mrb, ai);
  }
  return result;
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
  size_t l;

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
  } else {
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
      } else
        (*e)++;
      break;
    }
    prepend = NULL;
    if (*e == '9') {
      if (e == b) prepend = "1";
      *e = '0';
    } else if (*e == 'z') {
      if (e == b) prepend = "a";
      *e = 'a';
    } else if (*e == 'Z') {
      if (e == b) prepend = "A";
      *e = 'A';
    } else {
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

/*
 *  call-seq:
 *     str.prepend(other_str)  -> str
 *
 *  Prepend---Prepend the given string to <i>str</i>.
 *
 *     a = "world"
 *     a.prepend("hello ") #=> "hello world"
 *     a                   #=> "hello world"
 */
static mrb_value
mrb_str_prepend(mrb_state *mrb, mrb_value self)
{
  struct RString *s1 = mrb_str_ptr(self), *s2, *temp_s;
  mrb_int len;
  mrb_value other, temp_str;

  mrb_get_args(mrb, "S", &other);

  mrb_str_modify(mrb, s1);
  if (!mrb_string_p(other)) {
    other = mrb_str_to_str(mrb, other);
  }
  s2 = mrb_str_ptr(other);
  len = RSTR_LEN(s1) + RSTR_LEN(s2);
  temp_str = mrb_str_new(mrb, NULL, RSTR_LEN(s1));
  temp_s = mrb_str_ptr(temp_str);
  memcpy(RSTR_PTR(temp_s), RSTR_PTR(s1), RSTR_LEN(s1));
  if (RSTRING_CAPA(self) < len) {
    mrb_str_resize(mrb, self, len);
  }
  memcpy(RSTR_PTR(s1), RSTR_PTR(s2), RSTR_LEN(s2));
  memcpy(RSTR_PTR(s1) + RSTR_LEN(s2), RSTR_PTR(temp_s), RSTR_LEN(temp_s));
  RSTR_SET_LEN(s1, len);
  RSTR_PTR(s1)[len] = '\0';
  return self;
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
  mrb_define_method(mrb, s, "concat",          mrb_str_concat2,         MRB_ARGS_REQ(1));
  mrb_define_method(mrb, s, "<<",              mrb_str_concat2,         MRB_ARGS_REQ(1));
  mrb_define_method(mrb, s, "start_with?",     mrb_str_start_with,      MRB_ARGS_REST());
  mrb_define_method(mrb, s, "end_with?",       mrb_str_end_with,        MRB_ARGS_REST());
  mrb_define_method(mrb, s, "hex",             mrb_str_hex,             MRB_ARGS_NONE());
  mrb_define_method(mrb, s, "oct",             mrb_str_oct,             MRB_ARGS_NONE());
  mrb_define_method(mrb, s, "chr",             mrb_str_chr,             MRB_ARGS_NONE());
  mrb_define_method(mrb, s, "lines",           mrb_str_lines,           MRB_ARGS_NONE());
  mrb_define_method(mrb, s, "succ",            mrb_str_succ,            MRB_ARGS_NONE());
  mrb_define_method(mrb, s, "succ!",           mrb_str_succ_bang,       MRB_ARGS_NONE());
  mrb_define_method(mrb, s, "prepend",         mrb_str_prepend,         MRB_ARGS_REQ(1));
  mrb_alias_method(mrb, s, mrb_intern_lit(mrb, "next"), mrb_intern_lit(mrb, "succ"));
  mrb_alias_method(mrb, s, mrb_intern_lit(mrb, "next!"), mrb_intern_lit(mrb, "succ!"));
}

void
mrb_mruby_string_ext_gem_final(mrb_state* mrb)
{
}
