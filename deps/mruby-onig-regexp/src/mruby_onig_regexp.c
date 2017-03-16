/*
The MIT License (MIT)

Copyright (c) 2015 mattn.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <memory.h>
#include <mruby.h>
#include <mruby/class.h>
#include <mruby/variable.h>
#include <mruby/array.h>
#include <mruby/string.h>
#include <mruby/data.h>
#include <mruby/variable.h>
#ifdef _MSC_VER
#define ONIG_EXTERN extern
#endif
#ifdef HAVE_ONIGMO_H
#include <onigmo.h>
#elif defined(HAVE_ONIGURUMA_H)
#include <oniguruma.h>
#else
#include "oniguruma.h"
#endif

#ifdef MRUBY_VERSION
#define mrb_args_int mrb_int
#else
#define mrb_args_int int
#endif

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

static mrb_int
utf8len(const char* p, const char* e)
{
  mrb_int len;
  mrb_int i;

  len = utf8len_codepage[(unsigned char)*p];
  if (p + len > e) return 1;
  for (i = 1; i < len; ++i)
    if ((p[i] & 0xc0) != 0x80)
      return 1;
  return len;
}

static void
onig_regexp_free(mrb_state *mrb, void *p) {
  onig_free((OnigRegex) p);
}

static struct mrb_data_type mrb_onig_regexp_type = {
  "PosixRegexp", onig_regexp_free
};

static void
match_data_free(mrb_state* mrb, void* p) {
  (void)mrb;
  onig_region_free((OnigRegion*)p, 1);
}

static struct mrb_data_type mrb_onig_region_type = {
  "OnigRegion", match_data_free
};

static mrb_value
onig_regexp_initialize(mrb_state *mrb, mrb_value self) {
  mrb_value str, flag = mrb_nil_value(), code = mrb_nil_value();
  mrb_get_args(mrb, "S|oo", &str, &flag, &code);

  int cflag = 0;
  OnigEncoding enc = ONIG_ENCODING_UTF8;
  if(mrb_string_p(code)) {
    char const* str_code = mrb_string_value_ptr(mrb, code);
    if(strchr(str_code, 'n') || strchr(str_code, 'N')) {
      enc = ONIG_ENCODING_ASCII;
    }
  }
  if(mrb_nil_p(flag)) {
  } else if(mrb_type(flag) == MRB_TT_TRUE) {
    cflag |= ONIG_OPTION_IGNORECASE;
  } else if(mrb_fixnum_p(flag)) {
    int int_flags = mrb_fixnum(flag);
    if(int_flags & 0x1) { cflag |= ONIG_OPTION_IGNORECASE; }
    if(int_flags & 0x2) { cflag |= ONIG_OPTION_EXTEND; }
    if(int_flags & 0x4) { cflag |= ONIG_OPTION_MULTILINE; }
  } else if(mrb_string_p(flag)) {
    char const* str_flags = mrb_string_value_ptr(mrb, flag);
    if(strchr(str_flags, 'i')) { cflag |= ONIG_OPTION_IGNORECASE; }
    if(strchr(str_flags, 'x')) { cflag |= ONIG_OPTION_EXTEND; }
    if(strchr(str_flags, 'm')) { cflag |= ONIG_OPTION_MULTILINE; }
  } else {
    mrb_raisef(mrb, E_ARGUMENT_ERROR, "unknown regexp flag: %S", flag);
  }

  OnigErrorInfo einfo;
  OnigRegex reg;
  int result = onig_new(&reg, (OnigUChar*)RSTRING_PTR(str), (OnigUChar*) RSTRING_PTR(str) + RSTRING_LEN(str),
                        cflag, enc, ONIG_SYNTAX_RUBY, &einfo);
  if (result != ONIG_NORMAL) {
    char err[ONIG_MAX_ERROR_MESSAGE_LEN] = "";
    onig_error_code_to_str((OnigUChar*)err, result);
    mrb_raisef(mrb, E_ARGUMENT_ERROR, "'%S' is an invalid regular expression because %S.",
               str, mrb_str_new_cstr(mrb, err));
  }
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@source"), str);

  DATA_PTR(self) = reg;
  DATA_TYPE(self) = &mrb_onig_regexp_type;

  return self;
}

static mrb_value
create_onig_region(mrb_state* mrb, mrb_value const str, mrb_value rex) {
  mrb_assert(mrb_string_p(str));
  mrb_assert(mrb_type(rex) == MRB_TT_DATA && DATA_TYPE(rex) == &mrb_onig_regexp_type);
  mrb_value const c = mrb_obj_value(mrb_data_object_alloc(
      mrb, mrb_class_get(mrb, "OnigMatchData"), onig_region_new(), &mrb_onig_region_type));
  mrb_iv_set(mrb, c, mrb_intern_lit(mrb, "string"), mrb_str_dup(mrb, str));
  mrb_iv_set(mrb, c, mrb_intern_lit(mrb, "regexp"), rex);
  return c;
}

static int
onig_match_common(mrb_state* mrb, OnigRegex reg, mrb_value match_value, mrb_value str, int pos) {
  mrb_assert(mrb_string_p(str));
  mrb_assert(DATA_TYPE(match_value) == &mrb_onig_region_type);
  OnigRegion* const match = (OnigRegion*)DATA_PTR(match_value);
  OnigUChar const* str_ptr = (OnigUChar const*)RSTRING_PTR(str);
  int const result = onig_search(reg, str_ptr, str_ptr + RSTRING_LEN(str),
                                 str_ptr + pos, str_ptr + RSTRING_LEN(str), match, 0);
  if (result != ONIG_MISMATCH && result < 0) {
    char err[ONIG_MAX_ERROR_MESSAGE_LEN] = "";
    onig_error_code_to_str((OnigUChar*)err, result);
    mrb_raise(mrb, E_REGEXP_ERROR, err);
  }

  struct RObject* const cls = (struct RObject*)mrb_class_get(mrb, "OnigRegexp");
  mrb_obj_iv_set(mrb, cls, mrb_intern_lit(mrb, "@last_match"), match_value);

  if (result != ONIG_MISMATCH &&
      mrb_class_get(mrb, "Regexp") == (struct RClass*)cls &&
      mrb_bool(mrb_obj_iv_get(mrb, (struct RObject*)cls, mrb_intern_lit(mrb, "@set_global_variables"))))
  {
    mrb_gv_set(mrb, mrb_intern_lit(mrb, "$~"), match_value);
    mrb_gv_set(mrb, mrb_intern_lit(mrb, "$&"),
               mrb_funcall(mrb, match_value, "[]", 1, mrb_fixnum_value(0)));
    mrb_gv_set(mrb, mrb_intern_lit(mrb, "$`"), mrb_funcall(mrb, match_value, "pre_match", 0));
    mrb_gv_set(mrb, mrb_intern_lit(mrb, "$'"), mrb_funcall(mrb, match_value, "post_match", 0));
    mrb_gv_set(mrb, mrb_intern_lit(mrb, "$+"),
               mrb_funcall(mrb, match_value, "[]", 1, mrb_fixnum_value(match->num_regs - 1)));

    // $1 to $9
    int idx = 1;
    int const idx_max = match->num_regs > 10? 10 : match->num_regs;
    for(; idx < idx_max; ++idx) {
      char const n[] = { '$', '0' + idx };
      mrb_gv_set(mrb, mrb_intern(mrb, n, 2),
                 mrb_funcall(mrb, match_value, "[]", 1, mrb_fixnum_value(idx)));
    }

    for(; idx < 10; ++idx) {
      char const n[] = { '$', '0' + idx };
      mrb_gv_remove(mrb, mrb_intern(mrb, n, 2));
    }
  }

  return result;
}

static mrb_value
onig_regexp_match(mrb_state *mrb, mrb_value self) {
  mrb_value str = mrb_nil_value();
  OnigRegex reg;
  mrb_int pos = 0;

  mrb_get_args(mrb, "o|i", &str, &pos);
  if (pos < 0 || (pos > 0 && pos >= RSTRING_LEN(str))) {
    return mrb_nil_value();
  }

  if (mrb_nil_p(str)) {
    return mrb_nil_value();
  }
  str = mrb_string_type(mrb, str);

  Data_Get_Struct(mrb, self, &mrb_onig_regexp_type, reg);

  mrb_value const ret = create_onig_region(mrb, str, self);
  return (onig_match_common(mrb, reg, ret, str, pos) == ONIG_MISMATCH)
      ? mrb_nil_value() : ret;
}

static mrb_value
onig_regexp_equal(mrb_state *mrb, mrb_value self) {
  mrb_value other;
  OnigRegex self_reg, other_reg;

  mrb_get_args(mrb, "o", &other);
  if (mrb_obj_equal(mrb, self, other)){
    return mrb_true_value();
  }
  if (mrb_nil_p(other)) {
    return mrb_false_value();
  }
  if (!mrb_obj_is_kind_of(mrb, other, mrb_class_get(mrb, "OnigRegexp"))) {
    return mrb_false_value();
  }
  Data_Get_Struct(mrb, self, &mrb_onig_regexp_type, self_reg);
  Data_Get_Struct(mrb, other, &mrb_onig_regexp_type, other_reg);

  if (!self_reg || !other_reg){
      mrb_raise(mrb, E_RUNTIME_ERROR, "Invalid OnigRegexp");
  }
  if (onig_get_options(self_reg) != onig_get_options(other_reg)){
      return mrb_false_value();
  }
  return mrb_str_equal(mrb, mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "@source")), mrb_iv_get(mrb, other, mrb_intern_lit(mrb, "@source"))) ?
      mrb_true_value() : mrb_false_value();
}

static mrb_value
onig_regexp_casefold_p(mrb_state *mrb, mrb_value self) {
  OnigRegex reg;

  Data_Get_Struct(mrb, self, &mrb_onig_regexp_type, reg);
  return (onig_get_options(reg) & ONIG_OPTION_IGNORECASE) ? mrb_true_value() : mrb_false_value();
}

static mrb_value
onig_regexp_options(mrb_state *mrb, mrb_value self) {
  OnigRegex reg;
  Data_Get_Struct(mrb, self, &mrb_onig_regexp_type, reg);
  return mrb_fixnum_value(onig_get_options(reg));
}

static char *
option_to_str(char str[4], int options) {
  char *p = str;
  if (options & ONIG_OPTION_MULTILINE) *p++ = 'm';
  if (options & ONIG_OPTION_IGNORECASE) *p++ = 'i';
  if (options & ONIG_OPTION_EXTEND) *p++ = 'x';
  *p = 0;
  return str;
}

static mrb_value
regexp_expr_str(mrb_state *mrb, mrb_value str, const char *p, int len) {
  const char *pend;
  char buf[5];

  pend = (const char *) p + len;
  for (;p < pend; p++) {
    unsigned char c, cc;

    c = *p;
    if (c == '/'|| c == '\\') {
      buf[0] = '\\'; buf[1] = c;
      mrb_str_cat(mrb, str, buf, 2);
      continue;
    }
    if (ISPRINT(c)) {
      buf[0] = c;
      mrb_str_cat(mrb, str, buf, 1);
      continue;
    }
    switch (c) {
      case '\n': cc = 'n'; break;
      case '\r': cc = 'r'; break;
      case '\t': cc = 't'; break;
      default: cc = 0; break;
    }
    if (cc) {
      buf[0] = '\\';
      buf[1] = (char)cc;
      mrb_str_cat(mrb, str, buf, 2);
      continue;
    }
    else {
      buf[0] = '\\';
      buf[3] = '0' + c % 8; c /= 8;
      buf[2] = '0' + c % 8; c /= 8;
      buf[1] = '0' + c % 8;
      mrb_str_cat(mrb, str, buf, 4);
      continue;
    }
  }
  return str;
}

static mrb_value
onig_regexp_inspect(mrb_state *mrb, mrb_value self) {
  OnigRegex reg;
  Data_Get_Struct(mrb, self, &mrb_onig_regexp_type, reg);
  mrb_value str = mrb_str_new_lit(mrb, "/");
  mrb_value src = mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "@source"));
  regexp_expr_str(mrb, str, (const char *)RSTRING_PTR(src), RSTRING_LEN(src));
  mrb_str_cat_lit(mrb, str, "/");
  char opts[4];
  if (*option_to_str(opts, onig_get_options(reg))) {
    mrb_str_cat_cstr(mrb, str, opts);
  }
  if (onig_get_encoding(reg) == ONIG_ENCODING_ASCII) {
    mrb_str_cat_lit(mrb, str, "n");
  }
  return str;
}

static mrb_value
onig_regexp_to_s(mrb_state *mrb, mrb_value self) {
  int options;
  const int embeddable = ONIG_OPTION_MULTILINE|ONIG_OPTION_IGNORECASE|ONIG_OPTION_EXTEND;
  long len;
  const char* ptr;
  mrb_value str = mrb_str_new_lit(mrb, "(?");
  char optbuf[5];

  OnigRegex reg;
  Data_Get_Struct(mrb, self, &mrb_onig_regexp_type, reg);
  options = onig_get_options(reg);
  mrb_value src = mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "@source"));
  ptr = RSTRING_PTR(src);
  len = RSTRING_LEN(src);

 again:
  if (len >= 4 && ptr[0] == '(' && ptr[1] == '?') {
    int err = 1;
    ptr += 2;
    if ((len -= 2) > 0) {
      do {
        if(strchr(ptr, 'i')) { options |= ONIG_OPTION_IGNORECASE; }
        if(strchr(ptr, 'x')) { options |= ONIG_OPTION_EXTEND; }
        if(strchr(ptr, 'm')) { options |= ONIG_OPTION_MULTILINE; }
        ++ptr;
      } while (--len > 0);
    }
    if (len > 1 && *ptr == '-') {
      ++ptr;
      --len;
      do {
        if(strchr(ptr, 'i')) { options &= ~ONIG_OPTION_IGNORECASE; }
        if(strchr(ptr, 'x')) { options &= ~ONIG_OPTION_EXTEND; }
        if(strchr(ptr, 'm')) { options &= ~ONIG_OPTION_MULTILINE; }
        ++ptr;
      } while (--len > 0);
    }
    if (*ptr == ')') {
      --len;
      ++ptr;
      goto again;
    }
    if (*ptr == ':' && ptr[len-1] == ')') {
      OnigRegex rp;
      ++ptr;
      len -= 2;
      err = onig_new(&rp, (OnigUChar*)ptr, (OnigUChar*)ptr + len, ONIG_OPTION_DEFAULT,
                     ONIG_ENCODING_UTF8, OnigDefaultSyntax, NULL);
      onig_free(rp);
    }
    if (err) {
      options = onig_get_options(reg);
      ptr = RSTRING_PTR(src);
      len = RSTRING_LEN(src);
    }
  }

  if (*option_to_str(optbuf, options)) mrb_str_cat_cstr(mrb, str, optbuf);

  if ((options & embeddable) != embeddable) {
    optbuf[0] = '-';
    option_to_str(optbuf + 1, ~options);
    mrb_str_cat_cstr(mrb, str, optbuf);
  }

  mrb_str_cat_cstr(mrb, str, ":");
  regexp_expr_str(mrb, str, ptr, len);
  mrb_str_cat_cstr(mrb, str, ")");
  return str;
}


static mrb_value
onig_regexp_version(mrb_state* mrb, mrb_value self) {
  (void)self;
  return mrb_str_new_cstr(mrb, onig_version());
}

static mrb_value
match_data_to_a(mrb_state* mrb, mrb_value self);

static mrb_int
match_data_actual_index(mrb_state* mrb, mrb_value self, mrb_value idx_value) {
  if(mrb_fixnum_p(idx_value)) { return mrb_fixnum(idx_value); }

  char const* name = NULL;
  char const* name_end = NULL;
  if(mrb_symbol_p(idx_value)) {
    mrb_int sym_len;
    name = mrb_sym2name_len(mrb, mrb_symbol(idx_value), &sym_len);
    name_end = name + sym_len;
  } else if(mrb_string_p(idx_value)) {
    name = mrb_string_value_ptr(mrb, idx_value);
    name_end = name + strlen(name);
  } else { mrb_assert(FALSE); }
  mrb_assert(name && name_end);

  mrb_value const regexp = mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "regexp"));
  mrb_assert(!mrb_nil_p(regexp));
  mrb_assert(DATA_TYPE(regexp) == &mrb_onig_regexp_type);
  mrb_assert(DATA_TYPE(self) == &mrb_onig_region_type);
  int const idx = onig_name_to_backref_number(
      (OnigRegex)DATA_PTR(regexp), (OnigUChar const*)name, (OnigUChar const*)name_end,
      (OnigRegion*)DATA_PTR(self));
  if (idx < 0) {
    mrb_raisef(mrb, E_INDEX_ERROR, "undefined group name reference: %S", idx_value);
  }
  return idx;
}

// ISO 15.2.16.3.1
static mrb_value
match_data_index(mrb_state* mrb, mrb_value self) {
  mrb_value src;
  mrb_int argc; mrb_value *argv;

  mrb_get_args(mrb, "*", &argv, &argc);

  src = match_data_to_a(mrb, self);

  if (argc == 1) {
    switch (mrb_type(argv[0])) {
    case MRB_TT_FIXNUM:
    case MRB_TT_SYMBOL:
    case MRB_TT_STRING:
      return mrb_ary_entry(src, match_data_actual_index(mrb, self, argv[0]));
    default: break;
    }
  }

  return mrb_funcall_argv(mrb, src, mrb_intern_lit(mrb, "[]"), argc, argv);
}

#define match_data_check_index(idx) \
  if(idx < 0 || reg->num_regs <= idx) \
    mrb_raisef(mrb, E_INDEX_ERROR, "index %S out of matches", mrb_fixnum_value(idx)) \

// ISO 15.2.16.3.2
static mrb_value
match_data_begin(mrb_state* mrb, mrb_value self) {
  mrb_value idx_value;
  mrb_get_args(mrb, "o", &idx_value);
  OnigRegion* reg;
  Data_Get_Struct(mrb, self, &mrb_onig_region_type, reg);
  mrb_int const idx = match_data_actual_index(mrb, self, idx_value);
  match_data_check_index(idx);
  return mrb_fixnum_value(reg->beg[idx]);
}

// ISO 15.2.16.3.3
static mrb_value
match_data_captures(mrb_state* mrb, mrb_value self) {
  mrb_value ary = match_data_to_a(mrb, self);
  return mrb_ary_new_from_values(mrb, RARRAY_LEN(ary) - 1, RARRAY_PTR(ary) + 1);
}

// ISO 15.2.16.3.4
static mrb_value
match_data_end(mrb_state* mrb, mrb_value self) {
  mrb_value idx_value;
  mrb_get_args(mrb, "o", &idx_value);
  OnigRegion* reg;
  Data_Get_Struct(mrb, self, &mrb_onig_region_type, reg);
  mrb_int const idx = match_data_actual_index(mrb, self, idx_value);
  match_data_check_index(idx);
  return mrb_fixnum_value(reg->end[idx]);
}

// ISO 15.2.16.3.5
static mrb_value
match_data_copy(mrb_state* mrb, mrb_value self) {
  mrb_value src_val;
  mrb_get_args(mrb, "o", &src_val);

  OnigRegion* src;
  Data_Get_Struct(mrb, src_val, &mrb_onig_region_type, src);

  OnigRegion* dst = onig_region_new();
  onig_region_copy(dst, src);

  DATA_PTR(self) = dst;
  DATA_TYPE(self) = &mrb_onig_region_type;
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "string"), mrb_iv_get(mrb, src_val, mrb_intern_lit(mrb, "string")));
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "regexp"), mrb_iv_get(mrb, src_val, mrb_intern_lit(mrb, "regexp")));
  return self;
}

// ISO 15.2.16.3.6
// ISO 15.2.16.3.10
static mrb_value
match_data_length(mrb_state* mrb, mrb_value self) {
  OnigRegion* reg;
  Data_Get_Struct(mrb, self, &mrb_onig_region_type, reg);
  return mrb_fixnum_value(reg->num_regs);
}

// ISO 15.2.16.3.7
static mrb_value
match_data_offset(mrb_state* mrb, mrb_value self) {
  mrb_value idx_value;
  mrb_get_args(mrb, "o", &idx_value);
  OnigRegion* reg;
  Data_Get_Struct(mrb, self, &mrb_onig_region_type, reg);
  mrb_int const idx = match_data_actual_index(mrb, self, idx_value);
  match_data_check_index(idx);
  mrb_value ret = mrb_ary_new_capa(mrb, 2);
  mrb_ary_push(mrb, ret, mrb_fixnum_value(reg->beg[idx]));
  mrb_ary_push(mrb, ret, mrb_fixnum_value(reg->end[idx]));
  return ret;
}

// ISO 15.2.16.3.8
static mrb_value
match_data_post_match(mrb_state* mrb, mrb_value self) {
  OnigRegion* reg;
  Data_Get_Struct(mrb, self, &mrb_onig_region_type, reg);
  mrb_value str = mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "string"));
  return mrb_str_substr(mrb, str, reg->end[0], RSTRING_LEN(str) - reg->end[0]);
}

// ISO 15.2.16.3.9
static mrb_value
match_data_pre_match(mrb_state* mrb, mrb_value self) {
  OnigRegion* reg;
  Data_Get_Struct(mrb, self, &mrb_onig_region_type, reg);
  mrb_value str = mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "string"));
  return mrb_str_substr(mrb, str, 0, reg->beg[0]);
}

// ISO 15.2.16.3.11
static mrb_value
match_data_string(mrb_state* mrb, mrb_value self) {
  return mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "string"));
}

static mrb_value
match_data_regexp(mrb_state* mrb, mrb_value self) {
  return mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "regexp"));
}

// ISO 15.2.16.3.12
static mrb_value
match_data_to_a(mrb_state* mrb, mrb_value self) {
  mrb_value cache = mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "cache"));
  if(!mrb_nil_p(cache)) {
    return cache;
  }

  mrb_value str = mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "string"));
  OnigRegion* reg;
  Data_Get_Struct(mrb, self, &mrb_onig_region_type, reg);

  mrb_value ret = mrb_ary_new_capa(mrb, reg->num_regs);
  int i, ai = mrb_gc_arena_save(mrb);
  for(i = 0; i < reg->num_regs; ++i) {
    if(reg->beg[i] == ONIG_REGION_NOTPOS) {
      mrb_ary_push(mrb, ret, mrb_nil_value());
    } else {
      mrb_ary_push(mrb, ret, mrb_str_substr(mrb, str, reg->beg[i], reg->end[i] - reg->beg[i]));
    }
    mrb_gc_arena_restore(mrb, ai);
  }
  return ret;
}

// ISO 15.2.16.3.13
static mrb_value
match_data_to_s(mrb_state* mrb, mrb_value self) {
  mrb_value str = mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "string"));
  OnigRegion* reg;
  Data_Get_Struct(mrb, self, &mrb_onig_region_type, reg);
  return mrb_str_substr(mrb, str, reg->beg[0], reg->end[0] - reg->beg[0]);
}

static void
append_replace_str(mrb_state* mrb, mrb_value result, mrb_value replace,
                   mrb_value src, OnigRegex reg, OnigRegion* match)
{
  mrb_assert(mrb_string_p(replace));
  char const* ch;
  char const* const end = RSTRING_PTR(replace) + RSTRING_LEN(replace);
  for(ch = RSTRING_PTR(replace); ch < end; ++ch) {
    if (*ch != '\\' || (ch + 1) >= end) {
      mrb_str_cat(mrb, result, ch, 1);
      continue;
    }

    switch(*(++ch)) { // skip back slash and get next char
      case 'k': { // group name
        if ((ch + 2) >= end || ch[1] != '<') { goto replace_expr_error; }
        char const* name_beg = ch += 2;
        while (*ch != '>') { if(++ch == end) { goto replace_expr_error; } }
        mrb_assert(ch < end);
        mrb_assert(*ch == '>');
        int const idx = onig_name_to_backref_number(
            reg, (OnigUChar const*)name_beg, (OnigUChar const*)ch, match);
        if (idx < 0) {
          mrb_raisef(mrb, E_INDEX_ERROR, "undefined group name reference: %S",
                     mrb_str_substr(mrb, replace, name_beg - RSTRING_PTR(replace), ch - name_beg));
        }
        mrb_str_cat(mrb, result, RSTRING_PTR(src) + match->beg[idx], match->end[idx] - match->beg[idx]);
      } break;

      case '\\': // escaped back slash
        mrb_str_cat(mrb, result, ch, 1);
        break;

      default:
        if (isdigit(*ch)) { // group number 0-9
          int const idx = *ch - '0';
          if (idx < match->num_regs) {
            mrb_str_cat(mrb, result, RSTRING_PTR(src) + match->beg[idx], match->end[idx] - match->beg[idx]);
          }
        } else {
          char const str[] = { '\\', *ch };
          mrb_str_cat(mrb, result, str, 2);
        }
        break;
    }
  }

  if(ch == end) { return; }

replace_expr_error:
  mrb_raisef(mrb, E_REGEXP_ERROR, "invalid replace expression: %S", replace);
}

// ISO 15.2.10.5.18
static mrb_value
string_gsub(mrb_state* mrb, mrb_value self) {
  mrb_value blk, match_expr, replace_expr = mrb_nil_value();
  int const argc = mrb_get_args(mrb, "&o|S", &blk, &match_expr, &replace_expr);

  if(mrb_string_p(match_expr)) {
    mrb_value argv[] = { match_expr, replace_expr };
    return mrb_funcall_with_block(mrb, self, mrb_intern_lit(mrb, "string_gsub"), argc, argv, blk);
  }

  if(!mrb_nil_p(blk) && !mrb_nil_p(replace_expr)) {
    blk = mrb_nil_value();
  }

  OnigRegex reg;
  Data_Get_Struct(mrb, match_expr, &mrb_onig_regexp_type, reg);
  mrb_value const result = mrb_str_new(mrb, NULL, 0);
  mrb_value const match_value = create_onig_region(mrb, self, match_expr);
  OnigRegion* const match = (OnigRegion*)DATA_PTR(match_value);
  int last_end_pos = 0;

  while(1) {
    if(onig_match_common(mrb, reg, match_value, self, last_end_pos) == ONIG_MISMATCH) { break; }

    mrb_str_cat(mrb, result, RSTRING_PTR(self) + last_end_pos, match->beg[0] - last_end_pos);

    if(mrb_nil_p(blk)) {
      append_replace_str(mrb, result, replace_expr, self, reg, match);
    } else {
      mrb_value const tmp_str = mrb_str_to_str(mrb, mrb_yield(mrb, blk, mrb_str_substr(
          mrb, self, match->beg[0], match->end[0] - match->beg[0])));
      mrb_assert(mrb_string_p(tmp_str));
      mrb_str_concat(mrb, result, tmp_str);
    }

    last_end_pos = match->end[0];
    if (match->beg[0] == match->end[0]) {
      /*
       * Always consume at least one character of the input string
       * in order to prevent infinite loops.
       */
      char* p = RSTRING_PTR(self) + last_end_pos;
      char* e = p + RSTRING_LEN(self);
      int len = utf8len(p, e);
      if (RSTRING_LEN(self) < last_end_pos + len) break;
      mrb_str_cat(mrb, result, p, len);
      last_end_pos += len;
    }
  }

  mrb_str_cat(mrb, result, RSTRING_PTR(self) + last_end_pos, RSTRING_LEN(self) - last_end_pos);
  return result;
}

// ISO 15.2.10.5.32
static mrb_value
string_scan(mrb_state* mrb, mrb_value self) {
  mrb_value blk, match_expr;
  mrb_get_args(mrb, "&o", &blk, &match_expr);

  if(mrb_string_p(match_expr)) {
    return mrb_funcall_with_block(mrb, self, mrb_intern_lit(mrb, "string_scan"),
                                  1, &match_expr, blk);
  }

  OnigRegex reg;
  Data_Get_Struct(mrb, match_expr, &mrb_onig_regexp_type, reg);
  mrb_value const result = mrb_nil_p(blk)? mrb_ary_new(mrb) : self;
  mrb_value m_value = create_onig_region(mrb, self, match_expr);
  OnigRegion* const m = (OnigRegion*)DATA_PTR(m_value);
  int last_end_pos = 0;
  int i;

  while (1) {
    if(onig_match_common(mrb, reg, m_value, self, last_end_pos) == ONIG_MISMATCH) { break; }

    if(mrb_nil_p(blk)) {
      mrb_assert(mrb_array_p(result));
      if(m->num_regs == 1) {
        mrb_ary_push(mrb, result, mrb_str_substr(mrb, self, m->beg[0], m->end[0] - m->beg[0]));
      } else {
        mrb_value const elem = mrb_ary_new_capa(mrb, m->num_regs - 1);
        for(i = 1; i < m->num_regs; ++i) {
          mrb_ary_push(mrb, elem, mrb_str_substr(mrb, self, m->beg[i], m->end[i] - m->beg[i]));
        }
        mrb_ary_push(mrb, result, elem);
      }
    } else { // call block
      mrb_assert(mrb_string_p(result));
      if(m->num_regs == 1) {
        mrb_yield(mrb, blk, mrb_str_substr(mrb, self, m->beg[0], m->end[0] - m->beg[0]));
      } else {
        mrb_value argv = mrb_ary_new_capa(mrb, m->num_regs - 1);
        for(i = 1; i < m->num_regs; ++i) {
          mrb_ary_push(mrb, argv, mrb_str_substr(mrb, self, m->beg[i], m->end[i] - m->beg[i]));
        }
        mrb_yield(mrb, blk, argv);
      }
    }

    last_end_pos = m->end[0];
  }

  return result;
}

// ISO 15.2.10.5.35
static mrb_value
string_split(mrb_state* mrb, mrb_value self) {
  mrb_value pattern = mrb_nil_value(); mrb_int limit = 0;
  int argc = mrb_get_args(mrb, "|oi", &pattern, &limit);

  if(argc == 0) { // check $; global variable
    pattern = mrb_gv_get(mrb, mrb_intern_lit(mrb, "$;"));
    if(!mrb_nil_p(pattern)) { argc = 1; }
  }

  if(mrb_nil_p(pattern) || mrb_string_p(pattern)) {
    return mrb_funcall(mrb, self, "string_split", argc, pattern, mrb_fixnum_value(limit));
  }

  mrb_value const result = mrb_ary_new(mrb);
  if(RSTRING_LEN(self) == 0) { return result; }

  OnigRegex reg;
  Data_Get_Struct(mrb, pattern, &mrb_onig_regexp_type, reg);
  mrb_value const match_value = create_onig_region(mrb, self, pattern);
  OnigRegion* const match = (OnigRegion*)DATA_PTR(match_value);
  int last_end_pos = 0, next_match_pos = 0;
  mrb_int num_matches = 0;

  while (limit <= 0 || (limit - 1) > num_matches) {
    int i;
    if(next_match_pos >= RSTRING_LEN(self) ||
       onig_match_common(mrb, reg, match_value, self, next_match_pos) == ONIG_MISMATCH) { break; }

    if (last_end_pos == match->end[0]) {
      ++next_match_pos;
      // Remove this loop if not using UTF-8
      for (; next_match_pos < RSTRING_LEN(self) && (RSTRING_PTR(self)[next_match_pos] & 0xC0) == 0x80;
          ++next_match_pos) {}
    } else {
      mrb_ary_push(mrb, result, mrb_str_substr(
          mrb, self, last_end_pos, match->beg[0] - last_end_pos));
      // If there are captures, add them to the array
      for (i = 1; i < match->num_regs; ++i) {
        mrb_ary_push(mrb, result, mrb_str_substr(
            mrb, self, match->beg[i], match->end[i] - match->beg[i]));
      }
      last_end_pos = match->end[0];
      next_match_pos = last_end_pos;
      ++num_matches;
    }
  }
  if (last_end_pos <= RSTRING_LEN(self)) {
    mrb_ary_push(mrb, result, mrb_str_substr(
        mrb, self, last_end_pos, RSTRING_LEN(self) - last_end_pos));
  }

  if (limit == 0) { // remove empty trailing elements
    int count = 0, i;
    for (i = RARRAY_LEN(result); i > 0; --i) {
      mrb_assert(mrb_string_p(RARRAY_PTR(result)[i - 1]));
      if (RSTRING_LEN(RARRAY_PTR(result)[i - 1]) != 0) { break; }
      else { ++count; }
    }
    if(count > 0) {
      return mrb_ary_new_from_values(mrb, RARRAY_LEN(result) - count, RARRAY_PTR(result));
    }
  }

  return result;
}

// ISO 15.2.10.5.36
static mrb_value
string_sub(mrb_state* mrb, mrb_value self) {
  mrb_value blk, match_expr, replace_expr = mrb_nil_value();
  int const argc = mrb_get_args(mrb, "&o|S", &blk, &match_expr, &replace_expr);

  if(mrb_string_p(match_expr)) {
    mrb_value argv[] = { match_expr, replace_expr };
    return mrb_funcall_with_block(mrb, self, mrb_intern_lit(mrb, "string_sub"), argc, argv, blk);
  }

  if(!mrb_nil_p(blk) && !mrb_nil_p(replace_expr)) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "both block and replace expression must not be passed");
  }

  OnigRegex reg;
  Data_Get_Struct(mrb, match_expr, &mrb_onig_regexp_type, reg);
  mrb_value const result = mrb_str_new(mrb, NULL, 0);
  mrb_value const match_value = create_onig_region(mrb, self, match_expr);
  OnigRegion* const match = (OnigRegion*)DATA_PTR(match_value);

  int const onig_result = onig_match_common(mrb, reg, match_value, self, 0);
  if(onig_result == ONIG_MISMATCH) { return self; }

  mrb_str_cat(mrb, result, RSTRING_PTR(self), match->beg[0]);

  if(mrb_nil_p(blk)) {
    append_replace_str(mrb, result, replace_expr, self, reg, match);
  } else {
    mrb_value const tmp_str = mrb_str_to_str(mrb, mrb_yield(mrb, blk, mrb_str_substr(
        mrb, self, match->beg[0], match->end[0] - match->beg[0])));
    mrb_assert(mrb_string_p(tmp_str));
    mrb_str_concat(mrb, result, tmp_str);
  }

  int const last_end_pos = match->end[0];
  mrb_str_cat(mrb, result, RSTRING_PTR(self) + last_end_pos, RSTRING_LEN(self) - last_end_pos);

  return result;
}

static mrb_value
onig_regexp_clear_global_variables(mrb_state* mrb, mrb_value self) {
  mrb_gv_remove(mrb, mrb_intern_lit(mrb, "$~"));
  mrb_gv_remove(mrb, mrb_intern_lit(mrb, "$&"));
  mrb_gv_remove(mrb, mrb_intern_lit(mrb, "$`"));
  mrb_gv_remove(mrb, mrb_intern_lit(mrb, "$'"));
  mrb_gv_remove(mrb, mrb_intern_lit(mrb, "$+"));

  int idx;
  for(idx = 1; idx < 10; ++idx) {
    char const n[] = { '$', '0' + idx };
    mrb_gv_remove(mrb, mrb_intern(mrb, n, 2));
  }

  return self;
}

static mrb_value
onig_regexp_does_set_global_variables(mrb_state* mrb, mrb_value self) {
  (void)self;
  return mrb_obj_iv_get(mrb, (struct RObject*)mrb_class_get(mrb, "OnigRegexp"),
                        mrb_intern_lit(mrb, "@set_global_variables"));
}
static mrb_value
onig_regexp_set_set_global_variables(mrb_state* mrb, mrb_value self) {
  mrb_value arg;
  mrb_get_args(mrb, "o", &arg);
  mrb_value const ret = mrb_bool_value(mrb_bool(arg));
  mrb_obj_iv_set(mrb, (struct RObject*)mrb_class_get(mrb, "OnigRegexp"),
                 mrb_intern_lit(mrb, "@set_global_variables"), ret);
  onig_regexp_clear_global_variables(mrb, self);
  return ret;
}

// ISO 15.2.15.6.2
static mrb_value
onig_regexp_escape(mrb_state* mrb, mrb_value self) {
  char* str_begin; mrb_args_int str_len;
  mrb_get_args(mrb, "s", &str_begin, &str_len);

  mrb_value const ret = mrb_str_new(mrb, NULL, 0);
  char escaped_char = 0;
  int substr_count = 0;
  char const* str = str_begin;

  for(; str < (str_begin + str_len); ++str) {
    switch(*str) {
      case '\n': escaped_char = 'n'; break;
      case '\t': escaped_char = 't'; break;
      case '\r': escaped_char = 'r'; break;
      case '\f': escaped_char = 'f'; break;

      case ' ':
      case '#':
      case '$':
      case '(':
      case ')':
      case '*':
      case '+':
      case '-':
      case '.':
      case '?':
      case '[':
      case '\\':
      case ']':
      case '^':
      case '{':
      case '|':
      case '}':
        escaped_char = *str; break;

      default: ++substr_count; continue;
    }

    mrb_str_cat(mrb, ret, str - substr_count, substr_count);
    substr_count = 0;

    char const c[] = { '\\', escaped_char };
    mrb_str_cat(mrb, ret, c, 2);
  }
  mrb_str_cat(mrb, ret, str - substr_count, substr_count);
  return ret;
}

void
mrb_mruby_onig_regexp_gem_init(mrb_state* mrb) {
  struct RClass *clazz;

  clazz = mrb_define_class(mrb, "OnigRegexp", mrb->object_class);
  MRB_SET_INSTANCE_TT(clazz, MRB_TT_DATA);

  // enable global variables setting in onig_match_common by default
  mrb_obj_iv_set(mrb, (struct RObject*)clazz, mrb_intern_lit(mrb, "@set_global_variables"), mrb_true_value());

  mrb_define_const(mrb, clazz, "IGNORECASE", mrb_fixnum_value(ONIG_OPTION_IGNORECASE));
  mrb_define_const(mrb, clazz, "EXTENDED", mrb_fixnum_value(ONIG_OPTION_EXTEND));
  mrb_define_const(mrb, clazz, "MULTILINE", mrb_fixnum_value(ONIG_OPTION_MULTILINE));
  mrb_define_const(mrb, clazz, "SINGLELINE", mrb_fixnum_value(ONIG_OPTION_SINGLELINE));
  mrb_define_const(mrb, clazz, "FIND_LONGEST", mrb_fixnum_value(ONIG_OPTION_FIND_LONGEST));
  mrb_define_const(mrb, clazz, "FIND_NOT_EMPTY", mrb_fixnum_value(ONIG_OPTION_FIND_NOT_EMPTY));
  mrb_define_const(mrb, clazz, "NEGATE_SINGLELINE", mrb_fixnum_value(ONIG_OPTION_NEGATE_SINGLELINE));
  mrb_define_const(mrb, clazz, "DONT_CAPTURE_GROUP", mrb_fixnum_value(ONIG_OPTION_DONT_CAPTURE_GROUP));
  mrb_define_const(mrb, clazz, "CAPTURE_GROUP", mrb_fixnum_value(ONIG_OPTION_CAPTURE_GROUP));
  mrb_define_const(mrb, clazz, "NOTBOL", mrb_fixnum_value(ONIG_OPTION_NOTBOL));
  mrb_define_const(mrb, clazz, "NOTEOL", mrb_fixnum_value(ONIG_OPTION_NOTEOL));
#ifdef ONIG_OPTION_POSIX_REGION
  mrb_define_const(mrb, clazz, "POSIX_REGION", mrb_fixnum_value(ONIG_OPTION_POSIX_REGION));
#endif
#ifdef ONIG_OPTION_ASCII_RANGE
  mrb_define_const(mrb, clazz, "ASCII_RANGE", mrb_fixnum_value(ONIG_OPTION_ASCII_RANGE));
#endif
#ifdef ONIG_OPTION_POSIX_BRACKET_ALL_RANGE
  mrb_define_const(mrb, clazz, "POSIX_BRACKET_ALL_RANGE", mrb_fixnum_value(ONIG_OPTION_POSIX_BRACKET_ALL_RANGE));
#endif
#ifdef ONIG_OPTION_WORD_BOUND_ALL_RANGE
  mrb_define_const(mrb, clazz, "WORD_BOUND_ALL_RANGE", mrb_fixnum_value(ONIG_OPTION_WORD_BOUND_ALL_RANGE));
#endif
#ifdef ONIG_OPTION_NEWLINE_CRLF
  mrb_define_const(mrb, clazz, "NEWLINE_CRLF", mrb_fixnum_value(ONIG_OPTION_NEWLINE_CRLF));
#endif
#ifdef ONIG_OPTION_NOTBOS
  mrb_define_const(mrb, clazz, "NOTBOS", mrb_fixnum_value(ONIG_OPTION_NOTBOS));
#endif
#ifdef ONIG_OPTION_NOTEOS
  mrb_define_const(mrb, clazz, "NOTEOS", mrb_fixnum_value(ONIG_OPTION_NOTEOS));
#endif

  mrb_define_method(mrb, clazz, "initialize", onig_regexp_initialize, MRB_ARGS_REQ(1) | MRB_ARGS_OPT(2));
  mrb_define_method(mrb, clazz, "==", onig_regexp_equal, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, clazz, "match", onig_regexp_match, MRB_ARGS_REQ(1) | MRB_ARGS_OPT(1));
  mrb_define_method(mrb, clazz, "casefold?", onig_regexp_casefold_p, MRB_ARGS_NONE());

  mrb_define_method(mrb, clazz, "options", onig_regexp_options, MRB_ARGS_NONE());
  mrb_define_method(mrb, clazz, "inspect", onig_regexp_inspect, MRB_ARGS_NONE());
  mrb_define_method(mrb, clazz, "to_s", onig_regexp_to_s, MRB_ARGS_NONE());

  mrb_define_module_function(mrb, clazz, "escape", onig_regexp_escape, MRB_ARGS_REQ(1));
  mrb_define_module_function(mrb, clazz, "quote", onig_regexp_escape, MRB_ARGS_REQ(1));
  mrb_define_module_function(mrb, clazz, "version", onig_regexp_version, MRB_ARGS_NONE());
  mrb_define_module_function(mrb, clazz, "set_global_variables?", onig_regexp_does_set_global_variables, MRB_ARGS_NONE());
  mrb_define_module_function(mrb, clazz, "set_global_variables=", onig_regexp_set_set_global_variables, MRB_ARGS_REQ(1));
  mrb_define_module_function(mrb, clazz, "clear_global_variables", onig_regexp_clear_global_variables, MRB_ARGS_NONE());

  struct RClass* match_data = mrb_define_class(mrb, "OnigMatchData", mrb->object_class);
  MRB_SET_INSTANCE_TT(clazz, MRB_TT_DATA);
  mrb_undef_class_method(mrb, match_data, "new");

  // mrb_define_method(mrb, match_data, "==", &match_data_eq);
  mrb_define_method(mrb, match_data, "[]", &match_data_index, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, match_data, "begin", &match_data_begin, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, match_data, "captures", &match_data_captures, MRB_ARGS_NONE());
  mrb_define_method(mrb, match_data, "end", &match_data_end, MRB_ARGS_REQ(1));
  // mrb_define_method(mrb, match_data, "eql?", &match_data_eq);
  // mrb_define_method(mrb, match_data, "hash", &match_data_hash);
  mrb_define_method(mrb, match_data, "initialize_copy", &match_data_copy, MRB_ARGS_REQ(1));
  // mrb_define_method(mrb, match_data, "inspect", &match_data_inspect);
  mrb_define_method(mrb, match_data, "length", &match_data_length, MRB_ARGS_NONE());
  // mrb_define_method(mrb, match_data, "names", &match_data_names);
  mrb_define_method(mrb, match_data, "offset", &match_data_offset, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, match_data, "post_match", &match_data_post_match, MRB_ARGS_NONE());
  mrb_define_method(mrb, match_data, "pre_match", &match_data_pre_match, MRB_ARGS_NONE());
  mrb_define_method(mrb, match_data, "regexp", &match_data_regexp, MRB_ARGS_NONE());
  mrb_define_method(mrb, match_data, "size", &match_data_length, MRB_ARGS_NONE());
  mrb_define_method(mrb, match_data, "string", &match_data_string, MRB_ARGS_NONE());
  mrb_define_method(mrb, match_data, "to_a", &match_data_to_a, MRB_ARGS_NONE());
  mrb_define_method(mrb, match_data, "to_s", &match_data_to_s, MRB_ARGS_NONE());
  // mrb_define_method(mrb, match_data, "values_at", &match_data_values_at);

  mrb_define_method(mrb, mrb->string_class, "onig_regexp_gsub", &string_gsub, MRB_ARGS_REQ(1) | MRB_ARGS_OPT(1) | MRB_ARGS_BLOCK());
  mrb_define_method(mrb, mrb->string_class, "onig_regexp_sub", &string_sub, MRB_ARGS_REQ(1) | MRB_ARGS_OPT(1) | MRB_ARGS_BLOCK());
  mrb_define_method(mrb, mrb->string_class, "onig_regexp_split", &string_split, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, mrb->string_class, "onig_regexp_scan", &string_scan, MRB_ARGS_REQ(1) | MRB_ARGS_BLOCK());
}

void
mrb_mruby_onig_regexp_gem_final(mrb_state* mrb) {
  (void)mrb;
}

// vim:set et:
