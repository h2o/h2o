#include <mruby.h>
#include <mruby/class.h>
#include <mruby/compile.h>
#include <mruby/irep.h>
#include <mruby/proc.h>
#include <mruby/opcode.h>
#include <mruby/error.h>
#include <mruby/presym.h>
#include <mruby/variable.h>

struct REnv *mrb_env_new(mrb_state *mrb, struct mrb_context *c, mrb_callinfo *ci, int nstacks, mrb_value *stack, struct RClass *tc);
mrb_value mrb_exec_irep(mrb_state *mrb, mrb_value self, struct RProc *p);
mrb_value mrb_obj_instance_eval(mrb_state *mrb, mrb_value self);
mrb_value mrb_mod_module_eval(mrb_state*, mrb_value);
void mrb_codedump_all(mrb_state*, struct RProc*);

static struct RProc*
create_proc_from_string(mrb_state *mrb, const char *s, mrb_int len, mrb_value binding, const char *file, mrb_int line)
{
  mrbc_context *cxt;
  struct mrb_parser_state *p;
  struct RProc *proc;
  const struct RProc *scope;
  struct REnv *e;
  mrb_callinfo *ci; /* callinfo of eval caller */
  struct RClass *target_class = NULL;
  struct mrb_context *c = mrb->c;

  if (!mrb_nil_p(binding)) {
    mrb_value scope_obj;
    if (!mrb_class_defined_id(mrb, MRB_SYM(Binding))
        || !mrb_obj_is_kind_of(mrb, binding, mrb_class_get_id(mrb, MRB_SYM(Binding)))) {
      mrb_raisef(mrb, E_TYPE_ERROR, "wrong argument type %C (expected binding)",
          mrb_obj_class(mrb, binding));
    }
    scope_obj = mrb_iv_get(mrb, binding, MRB_SYM(proc));
    mrb_assert(mrb_proc_p(scope_obj));
    scope = mrb_proc_ptr(scope_obj);
    if (MRB_PROC_CFUNC_P(scope)) {
      e = NULL;
    }
    else {
      mrb_value env = mrb_iv_get(mrb, binding, MRB_SYM(env));
      mrb_assert(mrb_env_p(env));
      e = (struct REnv *)mrb_obj_ptr(env);
      mrb_assert(e != NULL);
    }
  }
  else {
    ci = (c->ci > c->cibase) ? c->ci - 1 : c->cibase;
    scope = ci->proc;
    e = NULL;
  }

  if (file) {
    if (strlen(file) >= UINT16_MAX) {
      mrb_raise(mrb, E_ARGUMENT_ERROR, "filename too long");
    }
  }
  else {
    file = "(eval)";
  }

  cxt = mrbc_context_new(mrb);
  cxt->lineno = (uint16_t)line;

  mrbc_filename(mrb, cxt, file);
  cxt->capture_errors = TRUE;
  cxt->no_optimize = TRUE;
  cxt->upper = scope && MRB_PROC_CFUNC_P(scope) ? NULL : scope;

  p = mrb_parse_nstring(mrb, s, len, cxt);

  /* only occur when memory ran out */
  if (!p) {
    mrbc_context_free(mrb, cxt);
    mrb_raise(mrb, E_RUNTIME_ERROR, "Failed to create parser state (out of memory)");
  }

  if (0 < p->nerr) {
    /* parse error */
    mrb_value str;

    mrbc_context_free(mrb, cxt);
    if (!p->error_buffer[0].message) {
      mrb_parser_free(p);
      mrb_raise(mrb, E_SYNTAX_ERROR, "compile error");
    }
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
    mrb_exc_raise(mrb, mrb_exc_new_str(mrb, E_SYNTAX_ERROR, str));
  }

  proc = mrb_generate_code(mrb, p);
  if (proc == NULL) {
    /* codegen error */
    mrb_parser_free(p);
    mrbc_context_free(mrb, cxt);
    mrb_raise(mrb, E_SCRIPT_ERROR, "codegen error");
  }
  if (c->ci > c->cibase) {
    ci = &c->ci[-1];
  }
  else {
    ci = c->cibase;
  }
  if (scope) {
    target_class = MRB_PROC_TARGET_CLASS(scope);
    if (!MRB_PROC_CFUNC_P(scope)) {
      if (e == NULL) {
        /* when `binding` is nil */
        e = mrb_vm_ci_env(ci);
        if (e == NULL) {
          e = mrb_env_new(mrb, c, ci, ci->proc->body.irep->nlocals, ci->stack, target_class);
          ci->u.env = e;
        }
      }
      proc->e.env = e;
      proc->flags |= MRB_PROC_ENVSET;
      mrb_field_write_barrier(mrb, (struct RBasic*)proc, (struct RBasic*)e);
    }
  }
  proc->upper = scope;
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
  mrb->c->ci->n = 0;
  mrb->c->ci->nk = 0;
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
  if (!mrb_nil_p(binding)) {
    self = mrb_iv_get(mrb, binding, MRB_SYM(recv));
  }
  mrb_assert(!MRB_PROC_CFUNC_P(proc));
  return exec_irep(mrb, self, proc);
}

static mrb_value
f_instance_eval(mrb_state *mrb, mrb_value self)
{
  if (!mrb_block_given_p(mrb)) {
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
    mrb_get_args(mrb, "");
    return mrb_obj_instance_eval(mrb, self);
  }
}

static mrb_value
f_class_eval(mrb_state *mrb, mrb_value self)
{
  if (!mrb_block_given_p(mrb)) {
    const char *s;
    mrb_int len;
    const char *file = NULL;
    mrb_int line = 1;
    struct RProc *proc;

    mrb_get_args(mrb, "s|zi", &s, &len, &file, &line);
    proc = create_proc_from_string(mrb, s, len, mrb_nil_value(), file, line);
    MRB_PROC_SET_TARGET_CLASS(proc, mrb_class_ptr(self));
    mrb_assert(!MRB_PROC_CFUNC_P(proc));
    mrb_vm_ci_target_class_set(mrb->c->ci, mrb_class_ptr(self));
    return exec_irep(mrb, self, proc);
  }
  else {
    mrb_get_args(mrb, "");
    return mrb_mod_module_eval(mrb, self);
  }
}

void
mrb_mruby_eval_gem_init(mrb_state* mrb)
{
  mrb_define_module_function(mrb, mrb->kernel_module, "eval", f_eval, MRB_ARGS_ARG(1, 3));
  mrb_define_method_id(mrb, mrb_class_get_id(mrb, MRB_SYM(BasicObject)), MRB_SYM(instance_eval), f_instance_eval, MRB_ARGS_OPT(3)|MRB_ARGS_BLOCK());
  mrb_define_method_id(mrb, mrb_class_get_id(mrb, MRB_SYM(Module)), MRB_SYM(module_eval), f_class_eval, MRB_ARGS_OPT(3)|MRB_ARGS_BLOCK());
  mrb_define_method_id(mrb, mrb_class_get_id(mrb, MRB_SYM(Module)), MRB_SYM(class_eval), f_class_eval, MRB_ARGS_OPT(3)|MRB_ARGS_BLOCK());
}

void
mrb_mruby_eval_gem_final(mrb_state* mrb)
{
}
