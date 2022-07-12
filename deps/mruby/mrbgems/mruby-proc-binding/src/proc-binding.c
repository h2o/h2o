#include <mruby.h>
#include <mruby/presym.h>
#include <mruby/proc.h>
#include <mruby/variable.h>

/* provided by mruby-proc-ext */
mrb_value mrb_proc_source_location(mrb_state *mrb, struct RProc *p);

/* provided by mruby-binding-core */
mrb_value mrb_binding_alloc(mrb_state *mrb);
struct RProc *mrb_binding_wrap_lvspace(mrb_state *mrb, const struct RProc *proc, struct REnv **envp);

static mrb_value
mrb_proc_binding(mrb_state *mrb, mrb_value procval)
{
  mrb_value binding = mrb_binding_alloc(mrb);
  const struct RProc *proc = mrb_proc_ptr(procval);
  struct REnv *env;

  mrb_value receiver;
  if (!proc || MRB_PROC_CFUNC_P(proc) || !proc->upper || MRB_PROC_CFUNC_P(proc->upper)) {
    env = NULL;
    proc = NULL;
    receiver = mrb_nil_value();
  }
  else {
    env = MRB_PROC_ENV(proc);
    mrb_assert(env);
    proc = proc->upper;
    receiver = MRB_ENV_LEN(env) > 0 ? env->stack[0] : mrb_nil_value();
  }

  proc = mrb_binding_wrap_lvspace(mrb, proc, &env);
  mrb_iv_set(mrb, binding, MRB_SYM(proc), mrb_obj_value((void *)proc));
  mrb_iv_set(mrb, binding, MRB_SYM(recv), receiver);
  mrb_iv_set(mrb, binding, MRB_SYM(env), mrb_obj_value(env));
  mrb_iv_set(mrb, binding, MRB_SYM(source_location), mrb_proc_source_location(mrb, mrb_proc_ptr(procval)));
  return binding;
}

void
mrb_mruby_proc_binding_gem_init(mrb_state *mrb)
{
  mrb_define_method(mrb, mrb->proc_class, "binding", mrb_proc_binding, MRB_ARGS_NONE());
}

void
mrb_mruby_proc_binding_gem_final(mrb_state *mrb)
{
}
