#include <mruby.h>
#include <mruby/error.h>
#include <mruby/array.h>

static mrb_value
protect_cb(mrb_state *mrb, mrb_value b)
{
  return mrb_yield_argv(mrb, b, 0, NULL);
}

static mrb_value
run_protect(mrb_state *mrb, mrb_value self)
{
  mrb_value b;
  mrb_value ret[2];
  mrb_bool state;
  mrb_get_args(mrb, "&", &b);
  ret[0] = mrb_protect(mrb, protect_cb, b, &state);
  ret[1] = mrb_bool_value(state);
  return mrb_ary_new_from_values(mrb, 2, ret);
}

static mrb_value
run_ensure(mrb_state *mrb, mrb_value self)
{
  mrb_value b, e;
  mrb_get_args(mrb, "oo", &b, &e);
  return mrb_ensure(mrb, protect_cb, b, protect_cb, e);
}

static mrb_value
run_rescue(mrb_state *mrb, mrb_value self)
{
  mrb_value b, r;
  mrb_get_args(mrb, "oo", &b, &r);
  return mrb_rescue(mrb, protect_cb, b, protect_cb, r);
}

static mrb_value
run_rescue_exceptions(mrb_state *mrb, mrb_value self)
{
  mrb_value b, r;
  struct RClass *cls[1];
  mrb_get_args(mrb, "oo", &b, &r);
  cls[0] = E_TYPE_ERROR;
  return mrb_rescue_exceptions(mrb, protect_cb, b, protect_cb, r, 1, cls);
}

void
mrb_mruby_error_gem_test(mrb_state *mrb)
{
  struct RClass *cls;

  cls = mrb_define_class(mrb, "ExceptionTest", mrb->object_class);
  mrb_define_module_function(mrb, cls, "mrb_protect", run_protect, MRB_ARGS_NONE() | MRB_ARGS_BLOCK());
  mrb_define_module_function(mrb, cls, "mrb_ensure", run_ensure, MRB_ARGS_REQ(2));
  mrb_define_module_function(mrb, cls, "mrb_rescue", run_rescue, MRB_ARGS_REQ(2));
  mrb_define_module_function(mrb, cls, "mrb_rescue_exceptions", run_rescue_exceptions, MRB_ARGS_REQ(2));
}
