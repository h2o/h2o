#include <stdlib.h>
#include <mruby.h>
#include <mruby/irep.h>
#include <mruby/variable.h>

extern const uint8_t mrbtest_assert_irep[];

void mrbgemtest_init(mrb_state* mrb);
void mrb_init_test_driver(mrb_state* mrb, mrb_bool verbose);
void mrb_t_pass_result(mrb_state *mrb_dst, mrb_state *mrb_src);

void
mrb_init_mrbtest(mrb_state *mrb)
{
  mrb_state *core_test;

  mrb_load_irep(mrb, mrbtest_assert_irep);

  core_test = mrb_open_core(mrb_default_allocf, NULL);
  if (core_test == NULL) {
    fprintf(stderr, "Invalid mrb_state, exiting %s", __FUNCTION__);
    exit(EXIT_FAILURE);
  }
  mrb_init_test_driver(core_test, mrb_test(mrb_gv_get(mrb, mrb_intern_lit(mrb, "$mrbtest_verbose"))));
  mrb_load_irep(core_test, mrbtest_assert_irep);
  mrb_t_pass_result(mrb, core_test);

#ifndef DISABLE_GEMS
  mrbgemtest_init(mrb);
#endif

  if (mrb->exc) {
    mrb_print_error(mrb);
    exit(EXIT_FAILURE);
  }
  mrb_close(core_test);
}

