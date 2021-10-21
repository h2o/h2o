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

static uint16_t
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
        return (pos+1)<<8 | (level+bnest);
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
  if (c == OP_ENTER) {
    mrb_aspec ax = PEEK_W(irep->iseq+1);
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

extern uint8_t mrb_insn_size[];
extern uint8_t mrb_insn_size1[];
extern uint8_t mrb_insn_size2[];
extern uint8_t mrb_insn_size3[];

static void
patch_irep(mrb_state *mrb, mrb_irep *irep, int bnest, mrb_irep *top)
{
  int i;
  uint32_t a;
  uint16_t b;
  uint8_t c;
  mrb_code insn;
  int argc = irep_argc(irep);

  for (i = 0; i < irep->ilen; ) {
    insn = irep->iseq[i];
    switch(insn){
    case OP_EPUSH:
      b = PEEK_S(irep->iseq+i+1);
      patch_irep(mrb, irep->reps[b], bnest + 1, top);
      break;

    case OP_LAMBDA:
    case OP_BLOCK:
      a = PEEK_B(irep->iseq+i+1);
      b = PEEK_B(irep->iseq+i+2);
      patch_irep(mrb, irep->reps[b], bnest + 1, top);
      break;

    case OP_SEND:
      b = PEEK_B(irep->iseq+i+2);
      c = PEEK_B(irep->iseq+i+3);
      if (c != 0) {
        break;
      }
      else {
        uint16_t arg = search_variable(mrb, irep->syms[b], bnest);
        if (arg != 0) {
          /* must replace */
          irep->iseq[i] = OP_GETUPVAR;
          irep->iseq[i+2] = arg >> 8;
          irep->iseq[i+3] = arg & 0xff;
        }
      }
      break;

    case OP_MOVE:
      a = PEEK_B(irep->iseq+i+1);
      b = PEEK_B(irep->iseq+i+2);
      /* src part */
      if (potential_upvar_p(irep->lv, b, argc, irep->nlocals)) {
        uint16_t arg = search_variable(mrb, irep->lv[b - 1].name, bnest);
        if (arg != 0) {
          /* must replace */
          irep->iseq[i] = insn = OP_GETUPVAR;
          irep->iseq[i+2] = arg >> 8;
          irep->iseq[i+3] = arg & 0xff;
        }
      }
      /* dst part */
      if (potential_upvar_p(irep->lv, a, argc, irep->nlocals)) {
        uint16_t arg = search_variable(mrb, irep->lv[a - 1].name, bnest);
        if (arg != 0) {
          /* must replace */
          irep->iseq[i] = insn = OP_SETUPVAR;
          irep->iseq[i+1] = (mrb_code)b;
          irep->iseq[i+2] = arg >> 8;
          irep->iseq[i+3] = arg & 0xff;
        }
      }
      break;

    case OP_GETUPVAR:
      a = PEEK_B(irep->iseq+i+1);
      b = PEEK_B(irep->iseq+i+2);
      c = PEEK_B(irep->iseq+i+3);
      {
        int lev = c+1;
        mrb_irep *tmp = search_irep(top, bnest, lev, irep);
        if (potential_upvar_p(tmp->lv, b, irep_argc(tmp), tmp->nlocals)) {
          uint16_t arg = search_variable(mrb, tmp->lv[b-1].name, bnest);
          if (arg != 0) {
            /* must replace */
            irep->iseq[i] = OP_GETUPVAR;
            irep->iseq[i+2] = arg >> 8;
            irep->iseq[i+3] = arg & 0xff;
          }
        }
      }
      break;

    case OP_SETUPVAR:
      a = PEEK_B(irep->iseq+i+1);
      b = PEEK_B(irep->iseq+i+2);
      c = PEEK_B(irep->iseq+i+3);
      {
        int lev = c+1;
        mrb_irep *tmp = search_irep(top, bnest, lev, irep);
        if (potential_upvar_p(tmp->lv, b, irep_argc(tmp), tmp->nlocals)) {
          uint16_t arg = search_variable(mrb, tmp->lv[b-1].name, bnest);
          if (arg != 0) {
            /* must replace */
            irep->iseq[i] = OP_SETUPVAR;
            irep->iseq[i+1] = a;
            irep->iseq[i+2] = arg >> 8;
            irep->iseq[i+3] = arg & 0xff;
          }
        }
      }
      break;

    case OP_EXT1:
      insn = PEEK_B(irep->iseq+i+1);
      i += mrb_insn_size1[insn]+1;
      continue;
    case OP_EXT2:
      insn = PEEK_B(irep->iseq+i+1);
      i += mrb_insn_size2[insn]+1;
      continue;
    case OP_EXT3:
      insn = PEEK_B(irep->iseq+i+1);
      i += mrb_insn_size3[insn]+1;
      continue;
    }
    i+=mrb_insn_size[insn];
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
  mrb_callinfo *ci; /* callinfo of eval caller */
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
  cxt->on_eval = TRUE;

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
    ptrdiff_t cioff = mrb->c->ci - mrb->c->cibase;
    mrb_value ret = mrb_top_run(mrb, proc, self, 0);
    if (mrb->exc) {
      mrb_exc_raise(mrb, mrb_obj_value(mrb->exc));
    }
    mrb->c->ci = mrb->c->cibase + cioff;
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
