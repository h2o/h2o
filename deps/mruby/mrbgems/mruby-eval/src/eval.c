#include <mruby.h>
#include <mruby/class.h>
#include <mruby/compile.h>
#include <mruby/irep.h>
#include <mruby/proc.h>
#include <mruby/opcode.h>
#include <mruby/error.h>

mrb_value mrb_exec_irep(mrb_state *mrb, mrb_value self, struct RProc *p);
mrb_value mrb_obj_instance_eval(mrb_state *mrb, mrb_value self);

static struct mrb_irep *
get_closure_irep(mrb_state *mrb, int level)
{
  struct RProc *proc = mrb->c->ci[-1].proc;

  while (level--) {
    if (!proc) return NULL;
    proc = proc->upper;
  }
  if (!proc) return NULL;
  if (MRB_PROC_CFUNC_P(proc)) {
    return NULL;
  }
  return proc->body.irep;
}

/* search for irep lev above the bottom */
static mrb_irep*
search_irep(mrb_irep *top, int bnest, int lev, mrb_irep *bottom)
{
  int i;

  for (i=0; i<top->rlen; i++) {
    mrb_irep* tmp = top->reps[i];

    if (tmp == bottom) return top;
    tmp = search_irep(tmp, bnest-1, lev, bottom);
    if (tmp) {
      if (bnest == lev) return top;
      return tmp;
    }
  }
  return NULL;
}

static inline mrb_code
search_variable(mrb_state *mrb, mrb_sym vsym, int bnest)
{
  mrb_irep *virep;
  int level;
  int pos;

  for (level = 0; (virep = get_closure_irep(mrb, level)); level++) {
    if (virep->lv == NULL) {
      continue;
    }
    for (pos = 0; pos < virep->nlocals - 1; pos++) {
      if (vsym == virep->lv[pos].name) {
        return (MKARG_B(pos + 1) | MKARG_C(level + bnest));
      }
    }
  }

  return 0;
}

static int
irep_argc(mrb_irep *irep)
{
  mrb_code c;

  c = irep->iseq[0];
  if (GET_OPCODE(c) == OP_ENTER) {
    mrb_aspec ax = GETARG_Ax(c);
    /* extra 1 means a slot for block */
    return MRB_ASPEC_REQ(ax)+MRB_ASPEC_OPT(ax)+MRB_ASPEC_REST(ax)+MRB_ASPEC_POST(ax)+1;
  }
  return 0;
}

static mrb_bool
potential_upvar_p(struct mrb_locals *lv, uint16_t v, int argc, uint16_t nlocals)
{
  if (v >= nlocals) return FALSE;
  /* skip arguments  */
  if (v < argc+1) return FALSE;
  return TRUE;
}

static void
patch_irep(mrb_state *mrb, mrb_irep *irep, int bnest, mrb_irep *top)
{
  int i;
  mrb_code c;
  int argc = irep_argc(irep);

  for (i = 0; i < irep->ilen; i++) {
    c = irep->iseq[i];
    switch(GET_OPCODE(c)){
    case OP_EPUSH:
      patch_irep(mrb, irep->reps[GETARG_Bx(c)], bnest + 1, top);
      break;

    case OP_LAMBDA:
      {
        int arg_c = GETARG_c(c);
        if (arg_c & OP_L_CAPTURE) {
          patch_irep(mrb, irep->reps[GETARG_b(c)], bnest + 1, top);
        }
      }
      break;

    case OP_SEND:
      if (GETARG_C(c) != 0) {
        break;
      }
      else {
        mrb_code arg = search_variable(mrb, irep->syms[GETARG_B(c)], bnest);
        if (arg != 0) {
          /* must replace */
          irep->iseq[i] = MKOPCODE(OP_GETUPVAR) | MKARG_A(GETARG_A(c)) | arg;
        }
      }
      break;

    case OP_MOVE:
      /* src part */
      if (potential_upvar_p(irep->lv, GETARG_B(c), argc, irep->nlocals)) {
        mrb_code arg = search_variable(mrb, irep->lv[GETARG_B(c) - 1].name, bnest);
        if (arg != 0) {
          /* must replace */
          irep->iseq[i] = MKOPCODE(OP_GETUPVAR) | MKARG_A(GETARG_A(c)) | arg;
        }
      }
      /* dst part */
      if (potential_upvar_p(irep->lv, GETARG_A(c), argc, irep->nlocals)) {
        mrb_code arg = search_variable(mrb, irep->lv[GETARG_A(c) - 1].name, bnest);
        if (arg != 0) {
          /* must replace */
          irep->iseq[i] = MKOPCODE(OP_SETUPVAR) | MKARG_A(GETARG_B(c)) | arg;
        }
      }
      break;

    case OP_GETUPVAR:
      {
        int lev = GETARG_C(c)+1;
        mrb_irep *tmp = search_irep(top, bnest, lev, irep);
        if (potential_upvar_p(tmp->lv, GETARG_B(c), irep_argc(tmp), tmp->nlocals)) {
          mrb_code arg = search_variable(mrb, tmp->lv[GETARG_B(c)-1].name, bnest);
          if (arg != 0) {
            /* must replace */
            irep->iseq[i] = MKOPCODE(OP_GETUPVAR) | MKARG_A(GETARG_A(c)) | arg;
          }
        }
      }
      break;

    case OP_SETUPVAR:
      {
        int lev = GETARG_C(c)+1;
        mrb_irep *tmp = search_irep(top, bnest, lev, irep);
        if (potential_upvar_p(tmp->lv, GETARG_B(c), irep_argc(tmp), tmp->nlocals)) {
          mrb_code arg = search_variable(mrb, tmp->lv[GETARG_B(c)-1].name, bnest);
          if (arg != 0) {
            /* must replace */
            irep->iseq[i] = MKOPCODE(OP_SETUPVAR) | MKARG_A(GETARG_A(c)) | arg;
          }
        }
      }
      break;

    case OP_STOP:
      if (mrb->c->ci->acc >= 0) {
        irep->iseq[i] = MKOP_AB(OP_RETURN, irep->nlocals, OP_R_NORMAL);
      }
      break;
    }
  }
}

void mrb_codedump_all(mrb_state*, struct RProc*);

static struct RProc*
create_proc_from_string(mrb_state *mrb, char *s, mrb_int len, mrb_value binding, const char *file, mrb_int line)
{
  mrbc_context *cxt;
  struct mrb_parser_state *p;
  struct RProc *proc;
  struct REnv *e;
  mrb_callinfo *ci = &mrb->c->ci[-1]; /* callinfo of eval caller */
  struct RClass *target_class = NULL;
  int bidx;

  if (!mrb_nil_p(binding)) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "Binding of eval must be nil.");
  }

  cxt = mrbc_context_new(mrb);
  cxt->lineno = (short)line;

  mrbc_filename(mrb, cxt, file ? file : "(eval)");
  cxt->capture_errors = TRUE;
  cxt->no_optimize = TRUE;

  p = mrb_parse_nstring(mrb, s, len, cxt);

  /* only occur when memory ran out */
  if (!p) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "Failed to create parser state.");
  }

  if (0 < p->nerr) {
    /* parse error */
    mrb_value str;

    if (file) {
      str = mrb_format(mrb, " file %S line %S: %S",
                       mrb_str_new_cstr(mrb, file),
                       mrb_fixnum_value(p->error_buffer[0].lineno),
                       mrb_str_new_cstr(mrb, p->error_buffer[0].message));
    }
    else {
      str = mrb_format(mrb, " line %S: %S",
                       mrb_fixnum_value(p->error_buffer[0].lineno),
                       mrb_str_new_cstr(mrb, p->error_buffer[0].message));
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
  target_class = MRB_PROC_TARGET_CLASS(ci->proc);
  if (!MRB_PROC_CFUNC_P(ci->proc)) {
    if (ci->env) {
      e = ci->env;
    }
    else {
      e = (struct REnv*)mrb_obj_alloc(mrb, MRB_TT_ENV,
                                      (struct RClass*)target_class);
      e->mid = ci->mid;
      e->stack = ci[1].stackent;
      e->cxt = mrb->c;
      MRB_ENV_SET_STACK_LEN(e, ci->proc->body.irep->nlocals);
      bidx = ci->argc;
      if (ci->argc < 0) bidx = 2;
      else bidx += 1;
      MRB_ENV_SET_BIDX(e, bidx);
      ci->env = e;
    }
    proc->e.env = e;
    proc->flags |= MRB_PROC_ENVSET;
    mrb_field_write_barrier(mrb, (struct RBasic*)proc, (struct RBasic*)e);
  }
  proc->upper = ci->proc;
  mrb->c->ci->target_class = target_class;
  patch_irep(mrb, proc->body.irep, 0, proc->body.irep);
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
    mrb_value ret = mrb_top_run(mrb, proc, self, 0);
    if (mrb->exc) {
      mrb_exc_raise(mrb, mrb_obj_value(mrb->exc));
    }
    return ret;
  }
  /* clear block */
  mrb->c->stack[1] = mrb_nil_value();
  return mrb_exec_irep(mrb, self, proc);
}

static mrb_value
f_eval(mrb_state *mrb, mrb_value self)
{
  char *s;
  mrb_int len;
  mrb_value binding = mrb_nil_value();
  char *file = NULL;
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
  mrb_int argc; mrb_value *argv;

  mrb_get_args(mrb, "*!&", &argv, &argc, &b);

  if (mrb_nil_p(b)) {
    char *s;
    mrb_int len;
    char *file = NULL;
    mrb_int line = 1;
    mrb_value cv;
    struct RProc *proc;

    mrb_get_args(mrb, "s|zi", &s, &len, &file, &line);
    cv = mrb_singleton_class(mrb, self);
    proc = create_proc_from_string(mrb, s, len, mrb_nil_value(), file, line);
    MRB_PROC_SET_TARGET_CLASS(proc, mrb_class_ptr(cv));
    mrb_assert(!MRB_PROC_CFUNC_P(proc));
    mrb->c->ci->target_class = mrb_class_ptr(cv);
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
  mrb_define_method(mrb, mrb->kernel_module, "instance_eval", f_instance_eval, MRB_ARGS_ARG(1, 2));
}

void
mrb_mruby_eval_gem_final(mrb_state* mrb)
{
}
