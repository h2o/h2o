#include <stdlib.h>
#include <mruby.h>

static mrb_value
f_exit(mrb_state *mrb, mrb_value self)
{
  mrb_value status = mrb_true_value();
  int istatus;

  mrb_get_args(mrb, "|o", &status);
  istatus = mrb_true_p(status) ? EXIT_SUCCESS :
            mrb_false_p(status) ? EXIT_FAILURE :
            (int)mrb_int(mrb, status);
  exit(istatus);

  /* not reached */
  return status;
}

void
mrb_mruby_exit_gem_init(mrb_state* mrb)
{
  mrb_define_method(mrb, mrb->kernel_module, "exit", f_exit, MRB_ARGS_OPT(1));
}

void
mrb_mruby_exit_gem_final(mrb_state* mrb)
{
}
