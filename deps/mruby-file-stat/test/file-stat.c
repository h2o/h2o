#include <mruby.h>
#include <stdlib.h>

static mrb_value
test_system(mrb_state *mrb, mrb_value klass)
{
  char *cmd = NULL;
  mrb_get_args(mrb, "z", &cmd);
  system(cmd);
  return mrb_nil_value();
}

static mrb_value
test_win_p(mrb_state *mrb, mrb_value klass)
{
#if defined(_WIN32)
  return mrb_true_value();
#else
  return mrb_false_value();
#endif
}

void mrb_mruby_file_stat_gem_test(mrb_state *mrb)
{
  struct RClass *t;

  t = mrb_define_class(mrb, "FileStatTest", mrb->object_class);
  mrb_define_module_function(mrb, t, "system", test_system, MRB_ARGS_REQ(1));
  mrb_define_module_function(mrb, t, "win?", test_win_p, MRB_ARGS_NONE());
}
