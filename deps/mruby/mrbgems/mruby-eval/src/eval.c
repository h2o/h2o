#include <mruby.h>
#include <mruby/class.h>
#include <mruby/compile.h>
#include <mruby/irep.h>
#include <mruby/proc.h>
#include <mruby/opcode.h>
#include <mruby/error.h>
#include <mruby/presym.h>

struct REnv *mrb_env_new(mrb_state *mrb, struct mrb_context *c, mrb_callinfo *ci, int nstacks, mrb_value *stack, struct RClass *tc);
mrb_value mrb_exec_irep(mrb_state *mrb, mrb_value self, struct RProc *p);
mrb_value mrb_obj_instance_eval(mrb_state *mrb, mrb_value self);

void mrb_codedump_all(mrb_state*, struct RProc*);

static struct RProc*
create_proc_from_string(mrb_state *mrb, const char *s, mrb_int len, mrb_value binding, const char *file, mrb_int line)
{
  mrbc_context *cxt;
  struct mrb_parser_state *p;
  struct RProc *proc;
  struct REnv *e;
  mrb_callinfo *ci; /* callinfo of eval caller */
  struct RClass *target_class = NULL;

  if (!mrb_nil_p(binding)) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "Binding of eval must be nil.");
  }

  cxt = mrbc_context_new(mrb);
  cxt->lineno = (uint16_t)line;

  mrbc_filename(mrb, cxt, file ? file : "(eval)");
  cxt->capture_errors = TRUE;
  cxt->no_optimize = TRUE;
  ci = (mrb->c->ci > mrb->c->cibase) ? mrb->c->ci - 1 : mrb->c->cibase;
  cxt->upper = ci->proc && MRB_PROC_CFUNC_P(ci->proc) ? NULL : ci->proc;

  p = mrb_parse_nstring(mrb, s, len, cxt);

  /* only occur when memory ran out */
  if (!p) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "Failed to create parser state (out of memory)");
  }

  if (0 < p->nerr) {
    /* parse error */
    mrb_value str;

    if (file) {
      str = mrb_format(mrb, "file %s line %d: %s",
                       file,
                       p->error_buffer[0].lineno,
                       p->error_buffer[0].message);
    }
    else {
      str = mrb_format(mrb, "line %d: %s",
                       p->error_buffer[0].lineno,
                       p->error_buffer[0].message);
    }
    mrb_parser_free(p);
    mrbc_context_free(mrb, cxt);
    mrb_exc_raise(mrb, mrb_exc_new_str(mrb, E_SYNTAX_ERROR, str));
  }

  proc = mrb_generate_code(mrb, p);
  if (proc == NULL) {
    /* codegen error */
    mrb_parser_free(p);
    mrbc_context_free(mrb, cxt);
    mrb_raise(mrb, E_SCRIPT_ERROR, "codegen error");
  }
  if (mrb->c->ci > mrb->c->cibase) {
    ci = &mrb->c->ci[-1];
  }
  else {
    ci = mrb->c->cibase;
  }
  if (ci->proc) {
    target_class = MRB_PROC_TARGET_CLASS(ci->proc);
  }
  if (ci->proc && !MRB_PROC_CFUNC_P(ci->proc)) {
    if ((e = mrb_vm_ci_env(ci)) != NULL) {
      /* do nothing, because e is assigned already */
    }
    else {
      e = mrb_env_new(mrb, mrb->c, ci, ci->proc->body.irep->nlocals, ci->stack, target_class);
      ci->u.env = e;
    }
    proc->e.env = e;
    proc->flags |= MRB_PROC_ENVSET;
    mrb_field_write_barrier(mrb, (struct RBasic*)proc, (struct RBasic*)e);
  }
  proc->upper = ci->proc;
  mrb_vm_ci_target_class_set(mrb->c->ci, target_class);
  /* mrb_codedump_all(mrb, proc); */

  mrb_parser_free(p);
  mrbc_context_free(mrb, cxt);

  return proc;
}

static mrb_value
exec_irep(mrb_state *mrb, mrb_value self, struct RProc *proc)
{
  /* no argument passed from eval() */
  mrb->c->ci->argc = 0;
  if (mrb->c->ci->acc < 0) {
    ptrdiff_t cioff = mrb->c->ci - mrb->c->cibase;
    mrb_value ret = mrb_top_run(mrb, proc, self, 0);
    if (mrb->exc) {
      mrb_exc_raise(mrb, mrb_obj_value(mrb->exc));
    }
    mrb->c->ci = mrb->c->cibase + cioff;
    return ret;
  }
  /* clear block */
  mrb->c->ci->stack[1] = mrb_nil_value();
  return mrb_exec_irep(mrb, self, proc);
}

static mrb_value
f_eval(mrb_state *mrb, mrb_value self)
{
  const char *s;
  mrb_int len;
  mrb_value binding = mrb_nil_value();
  const char *file = NULL;
  mrb_int line = 1;
  struct RProc *proc;

  mrb_get_args(mrb, "s|ozi", &s, &len, &binding, &file, &line);

  proc = create_proc_from_string(mrb, s, len, binding, file, line);
  mrb_assert(!MRB_PROC_CFUNC_P(proc));
  return exec_irep(mrb, self, proc);
}

static mrb_value
f_instance_eval(mrb_state *mrb, mrb_value self)
{
  mrb_value b;
  mrb_int argc; const mrb_value *argv;

  mrb_get_args(mrb, "*!&", &argv, &argc, &b);

  if (mrb_nil_p(b)) {
    const char *s;
    mrb_int len;
    const char *file = NULL;
    mrb_int line = 1;
    mrb_value cv;
    struct RProc *proc;

    mrb_get_args(mrb, "s|zi", &s, &len, &file, &line);
    cv = mrb_singleton_class(mrb, self);
    proc = create_proc_from_string(mrb, s, len, mrb_nil_value(), file, line);
    MRB_PROC_SET_TARGET_CLASS(proc, mrb_class_ptr(cv));
    mrb_assert(!MRB_PROC_CFUNC_P(proc));
    mrb_vm_ci_target_class_set(mrb->c->ci, mrb_class_ptr(cv));
    return exec_irep(mrb, self, proc);
  }
  else {
    mrb_get_args(mrb, "&", &b);
    return mrb_obj_instance_eval(mrb, self);
  }
}

void
mrb_mruby_eval_gem_init(mrb_state* mrb)
{
  mrb_define_module_function(mrb, mrb->kernel_module, "eval", f_eval, MRB_ARGS_ARG(1, 3));
  mrb_define_method(mrb, mrb_class_get_id(mrb, MRB_SYM(BasicObject)), "instance_eval", f_instance_eval, MRB_ARGS_OPT(3)|MRB_ARGS_BLOCK());
}

void
mrb_mruby_eval_gem_final(mrb_state* mrb)
{
}
