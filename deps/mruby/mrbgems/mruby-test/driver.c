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

void
mrb_init_mrbtest(mrb_state *);

/* Print a short remark for the user */
static void
print_hint(void)
{
  printf("mrbtest - Embeddable Ruby Test\n\n");
}

static int
check_error(mrb_state *mrb)
{
  /* Error check */
  /* $ko_test and $kill_test should be 0 */
  mrb_value ko_test = mrb_gv_get(mrb, mrb_intern_lit(mrb, "$ko_test"));
  mrb_value kill_test = mrb_gv_get(mrb, mrb_intern_lit(mrb, "$kill_test"));

  return mrb_fixnum_p(ko_test) && mrb_fixnum(ko_test) == 0 && mrb_fixnum_p(kill_test) && mrb_fixnum(kill_test) == 0;
}

static int
eval_test(mrb_state *mrb)
{
  /* evaluate the test */
  mrb_funcall(mrb, mrb_top_self(mrb), "report", 0);
  /* did an exception occur? */
  if (mrb->exc) {
    mrb_print_error(mrb);
    mrb->exc = 0;
    return EXIT_FAILURE;
  }
  else if (!check_error(mrb)) {
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}

static void
t_printstr(mrb_state *mrb, mrb_value obj)
{
  char *s;
  mrb_int len;

  if (mrb_string_p(obj)) {
    s = RSTRING_PTR(obj);
    len = RSTRING_LEN(obj);
    fwrite(s, len, 1, stdout);
    fflush(stdout);
  }
}

mrb_value
mrb_t_printstr(mrb_state *mrb, mrb_value self)
{
  mrb_value argv;

  mrb_get_args(mrb, "o", &argv);
  t_printstr(mrb, argv);

  return argv;
}

void
mrb_init_test_driver(mrb_state *mrb, mrb_bool verbose)
{
  struct RClass *krn, *mrbtest;

  krn = mrb->kernel_module;
  mrb_define_method(mrb, krn, "__t_printstr__", mrb_t_printstr, MRB_ARGS_REQ(1));

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
  mrb_init_mrbtest(mrb);
  ret = eval_test(mrb);
  mrb_close(mrb);

  return ret;
}
