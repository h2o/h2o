/*
** mrbtest - Test for Embeddable Ruby
**
** This program runs Ruby test programs in test/t directory
** against the current mruby implementation.
*/


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <mruby.h>
#include <mruby/proc.h>
#include <mruby/data.h>
#include <mruby/compile.h>
#include <mruby/string.h>
#include <mruby/variable.h>
#include <mruby/array.h>

extern const uint8_t mrbtest_assert_irep[];

void mrbgemtest_init(mrb_state* mrb);
void mrb_init_test_vformat(mrb_state* mrb);

/* Print a short remark for the user */
static void
print_hint(void)
{
  printf("mrbtest - Embeddable Ruby Test\n\n");
}

static int
eval_test(mrb_state *mrb)
{
  /* evaluate the test */
  mrb_value result = mrb_funcall(mrb, mrb_top_self(mrb), "report", 0);
  /* did an exception occur? */
  if (mrb->exc) {
    mrb_print_error(mrb);
    mrb->exc = 0;
    return EXIT_FAILURE;
  }
  else {
    return mrb_bool(result) ? EXIT_SUCCESS : EXIT_FAILURE;
  }
}

/* Implementation of print due to the reason that there might be no print */
static mrb_value
t_print(mrb_state *mrb, mrb_value self)
{
  mrb_value *argv;
  mrb_int argc;
  mrb_int i;

  mrb_get_args(mrb, "*!", &argv, &argc);
  for (i = 0; i < argc; ++i) {
    mrb_value s = mrb_obj_as_string(mrb, argv[i]);
    fwrite(RSTRING_PTR(s), RSTRING_LEN(s), 1, stdout);
  }
  fflush(stdout);

  return mrb_nil_value();
}

#define UNESCAPE(p, endp) ((p) != (endp) && *(p) == '\\' ? (p)+1 : (p))
#define CHAR_CMP(c1, c2) ((unsigned char)(c1) - (unsigned char)(c2))

static const char *
str_match_bracket(const char *p, const char *pat_end,
                  const char *s, const char *str_end)
{
  mrb_bool ok = FALSE, negated = FALSE;

  if (p == pat_end) return NULL;
  if (*p == '!' || *p == '^') {
    negated = TRUE;
    ++p;
  }

  while (*p != ']') {
    const char *t1 = p;
    if ((t1 = UNESCAPE(t1, pat_end)) == pat_end) return NULL;
    if ((p = t1 + 1) == pat_end) return NULL;
    if (p[0] == '-' && p[1] != ']') {
      const char *t2 = p + 1;
      if ((t2 = UNESCAPE(t2, pat_end)) == pat_end) return NULL;
      p = t2 + 1;
      if (!ok && CHAR_CMP(*t1, *s) <= 0 && CHAR_CMP(*s, *t2) <= 0) ok = TRUE;
    }
    else {
      if (!ok && CHAR_CMP(*t1, *s) == 0) ok = TRUE;
    }
  }

  return ok == negated ? NULL : p + 1;
}

static mrb_bool
str_match_no_brace_p(const char *pat, mrb_int pat_len,
                     const char *str, mrb_int str_len)
{
  const char *p = pat, *s = str;
  const char *pat_end = pat + pat_len, *str_end = str + str_len;
  const char *p_tmp = NULL, *s_tmp = NULL;

  for (;;) {
    if (p == pat_end) return s == str_end;
    switch (*p) {
      case '*':
        do { ++p; } while (p != pat_end && *p == '*');
        if (UNESCAPE(p, pat_end) == pat_end) return TRUE;
        if (s == str_end) return FALSE;
        p_tmp = p;
        s_tmp = s;
        continue;
      case '?':
        if (s == str_end) return FALSE;
        ++p;
        ++s;
        continue;
      case '[': {
        const char *t;
        if (s == str_end) return FALSE;
        if ((t = str_match_bracket(p+1, pat_end, s, str_end))) {
          p = t;
          ++s;
          continue;
        }
        goto L_failed;
      }
    }

    /* ordinary */
    p = UNESCAPE(p, pat_end);
    if (s == str_end) return p == pat_end;
    if (p == pat_end) goto L_failed;
    if (*p++ != *s++) goto L_failed;
    continue;

    L_failed:
    if (p_tmp && s_tmp) {
      /* try next '*' position */
      p = p_tmp;
      s = ++s_tmp;
      continue;
    }

    return FALSE;
  }
}

#define COPY_AND_INC(dst, src, len) \
  do { memcpy(dst, src, len); dst += len; } while (0)

static mrb_bool
str_match_p(mrb_state *mrb,
            const char *pat, mrb_int pat_len,
            const char *str, mrb_int str_len)
{
  const char *p = pat, *pat_end = pat + pat_len;
  const char *lbrace = NULL, *rbrace = NULL;
  int nest = 0;
  mrb_bool ret = FALSE;

  for (; p != pat_end; ++p) {
    if (*p == '{' && nest++ == 0) lbrace = p;
    else if (*p == '}' && lbrace && --nest == 0) { rbrace = p; break; }
    else if (*p == '\\' && ++p == pat_end) break;
  }

  if (lbrace && rbrace) {
    /* expand brace */
    char *ex_pat = (char *)mrb_malloc(mrb, pat_len-2);  /* expanded pattern */
    char *ex_p = ex_pat;

    COPY_AND_INC(ex_p, pat, lbrace-pat);
    p = lbrace;
    while (p < rbrace) {
      char *orig_ex_p = ex_p;
      const char *t = ++p;
      for (nest = 0; p < rbrace && !(*p == ',' && nest == 0); ++p) {
        if (*p == '{') ++nest;
        else if (*p == '}') --nest;
        else if (*p == '\\' && ++p == rbrace) break;
      }
      COPY_AND_INC(ex_p, t, p-t);
      COPY_AND_INC(ex_p, rbrace+1, pat_end-rbrace-1);
      if ((ret = str_match_p(mrb, ex_pat, ex_p-ex_pat, str, str_len))) break;
      ex_p = orig_ex_p;
    }
    mrb_free(mrb, ex_pat);
  }
  else if (!lbrace && !rbrace) {
    ret = str_match_no_brace_p(pat, pat_len, str, str_len);
  }

  return ret;
}

static mrb_value
m_str_match_p(mrb_state *mrb, mrb_value self)
{
  const char *pat, *str;
  mrb_int pat_len, str_len;

  mrb_get_args(mrb, "ss", &pat, &pat_len, &str, &str_len);
  return mrb_bool_value(str_match_p(mrb, pat, pat_len, str, str_len));
}

void
mrb_init_test_driver(mrb_state *mrb, mrb_bool verbose)
{
  struct RClass *krn, *mrbtest;

  krn = mrb->kernel_module;
  mrb_define_method(mrb, krn, "t_print", t_print, MRB_ARGS_ANY());
  mrb_define_method(mrb, krn, "_str_match?", m_str_match_p, MRB_ARGS_REQ(2));

  mrbtest = mrb_define_module(mrb, "Mrbtest");

  mrb_define_const(mrb, mrbtest, "FIXNUM_MAX", mrb_fixnum_value(MRB_INT_MAX));
  mrb_define_const(mrb, mrbtest, "FIXNUM_MIN", mrb_fixnum_value(MRB_INT_MIN));
  mrb_define_const(mrb, mrbtest, "FIXNUM_BIT", mrb_fixnum_value(MRB_INT_BIT));

#ifndef MRB_WITHOUT_FLOAT
#ifdef MRB_USE_FLOAT
  mrb_define_const(mrb, mrbtest, "FLOAT_TOLERANCE", mrb_float_value(mrb, 1e-6));
#else
  mrb_define_const(mrb, mrbtest, "FLOAT_TOLERANCE", mrb_float_value(mrb, 1e-12));
#endif
#endif

  mrb_init_test_vformat(mrb);

  if (verbose) {
    mrb_gv_set(mrb, mrb_intern_lit(mrb, "$mrbtest_verbose"), mrb_true_value());
  }
}

void
mrb_t_pass_result(mrb_state *mrb_dst, mrb_state *mrb_src)
{
  mrb_value res_src;

  if (mrb_src->exc) {
    mrb_print_error(mrb_src);
    exit(EXIT_FAILURE);
  }

#define TEST_COUNT_PASS(name)                                           \
  do {                                                                  \
    res_src = mrb_gv_get(mrb_src, mrb_intern_lit(mrb_src, "$" #name));  \
    if (mrb_fixnum_p(res_src)) {                                        \
      mrb_value res_dst = mrb_gv_get(mrb_dst, mrb_intern_lit(mrb_dst, "$" #name)); \
      mrb_gv_set(mrb_dst, mrb_intern_lit(mrb_dst, "$" #name), mrb_fixnum_value(mrb_fixnum(res_dst) + mrb_fixnum(res_src))); \
    }                                                                   \
  } while (FALSE)                                                       \

  TEST_COUNT_PASS(ok_test);
  TEST_COUNT_PASS(ko_test);
  TEST_COUNT_PASS(kill_test);
  TEST_COUNT_PASS(warning_test);
  TEST_COUNT_PASS(skip_test);

#undef TEST_COUNT_PASS

  res_src = mrb_gv_get(mrb_src, mrb_intern_lit(mrb_src, "$asserts"));

  if (mrb_array_p(res_src)) {
    mrb_int i;
    mrb_value res_dst = mrb_gv_get(mrb_dst, mrb_intern_lit(mrb_dst, "$asserts"));
    for (i = 0; i < RARRAY_LEN(res_src); ++i) {
      mrb_value val_src = RARRAY_PTR(res_src)[i];
      mrb_ary_push(mrb_dst, res_dst, mrb_str_new(mrb_dst, RSTRING_PTR(val_src), RSTRING_LEN(val_src)));
    }
  }
}

int
main(int argc, char **argv)
{
  mrb_state *mrb;
  int ret;
  mrb_bool verbose = FALSE;

  print_hint();

  /* new interpreter instance */
  mrb = mrb_open();
  if (mrb == NULL) {
    fprintf(stderr, "Invalid mrb_state, exiting test driver");
    return EXIT_FAILURE;
  }

  if (argc == 2 && argv[1][0] == '-' && argv[1][1] == 'v') {
    printf("verbose mode: enable\n\n");
    verbose = TRUE;
  }

  mrb_init_test_driver(mrb, verbose);
  mrb_load_irep(mrb, mrbtest_assert_irep);
  mrbgemtest_init(mrb);
  ret = eval_test(mrb);
  mrb_close(mrb);

  return ret;
}
