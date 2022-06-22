/*
** proc.c - Proc class
**
** See Copyright Notice in mruby.h
*/

#include <mruby.h>
#include <mruby/class.h>
#include <mruby/proc.h>
#include <mruby/opcode.h>
#include <mruby/data.h>
#include <mruby/presym.h>

static const mrb_code call_iseq[] = {
  OP_CALL,
};

static const mrb_irep call_irep = {
  0,                                   /* nlocals */
  2,                                   /* nregs */
  0,                                   /* clen */
  MRB_ISEQ_NO_FREE | MRB_IREP_NO_FREE, /* flags */
  call_iseq,                           /* iseq */
  NULL,                                /* pool */
  NULL,                                /* syms */
  NULL,                                /* reps */
  NULL,                                /* lv */
  NULL,                                /* debug_info */
  1,                                   /* ilen */
  0,                                   /* plen */
  0,                                   /* slen */
  1,                                   /* rlen */
  0,                                   /* refcnt */
};

struct RProc*
mrb_proc_new(mrb_state *mrb, const mrb_irep *irep)
{
  struct RProc *p;
  mrb_callinfo *ci = mrb->c->ci;

  p = (struct RProc*)mrb_obj_alloc(mrb, MRB_TT_PROC, mrb->proc_class);
  if (ci) {
    struct RClass *tc = NULL;

    if (ci->proc) {
      tc = MRB_PROC_TARGET_CLASS(ci->proc);
    }
    if (tc == NULL) {
      tc = mrb_vm_ci_target_class(ci);
    }
    p->upper = ci->proc;
    p->e.target_class = tc;
  }
  p->body.irep = irep;
  if (irep) {
    mrb_irep_incref(mrb, (mrb_irep*)irep);
  }

  return p;
}

struct REnv*
mrb_env_new(mrb_state *mrb, struct mrb_context *c, mrb_callinfo *ci, int nstacks, mrb_value *stack, struct RClass *tc)
{
  struct REnv *e;
  mrb_int bidx;

  e = (struct REnv*)mrb_obj_alloc(mrb, MRB_TT_ENV, tc);
  MRB_ENV_SET_LEN(e, nstacks);
  bidx = ci->argc;
  if (bidx < 0) bidx = 2;
  else bidx += 1;
  MRB_ENV_SET_BIDX(e, bidx);
  e->mid = ci->mid;
  e->stack = stack;
  e->cxt = c;

  return e;
}

static void
closure_setup(mrb_state *mrb, struct RProc *p)
{
  mrb_callinfo *ci = mrb->c->ci;
  const struct RProc *up = p->upper;
  struct REnv *e = NULL;

  if (ci && (e = mrb_vm_ci_env(ci)) != NULL) {
    /* do nothing, because e is assigned already */
  }
  else if (up) {
    struct RClass *tc = MRB_PROC_TARGET_CLASS(p);

    e = mrb_env_new(mrb, mrb->c, ci, up->body.irep->nlocals, ci->stack, tc);
    ci->u.env = e;
    if (MRB_PROC_ENV_P(up) && MRB_PROC_ENV(up)->cxt == NULL) {
      e->mid = MRB_PROC_ENV(up)->mid;
    }
  }
  if (e) {
    p->e.env = e;
    p->flags |= MRB_PROC_ENVSET;
    mrb_field_write_barrier(mrb, (struct RBasic*)p, (struct RBasic*)e);
  }
}

struct RProc*
mrb_closure_new(mrb_state *mrb, const mrb_irep *irep)
{
  struct RProc *p = mrb_proc_new(mrb, irep);

  closure_setup(mrb, p);
  return p;
}

MRB_API struct RProc*
mrb_proc_new_cfunc(mrb_state *mrb, mrb_func_t func)
{
  struct RProc *p;

  p = (struct RProc*)mrb_obj_alloc(mrb, MRB_TT_PROC, mrb->proc_class);
  p->body.func = func;
  p->flags |= MRB_PROC_CFUNC_FL;
  p->upper = 0;
  p->e.target_class = 0;

  return p;
}

MRB_API struct RProc*
mrb_proc_new_cfunc_with_env(mrb_state *mrb, mrb_func_t func, mrb_int argc, const mrb_value *argv)
{
  struct RProc *p = mrb_proc_new_cfunc(mrb, func);
  struct REnv *e;
  int i;

  p->e.env = e = mrb_env_new(mrb, mrb->c, mrb->c->ci, 0, NULL, NULL);
  p->flags |= MRB_PROC_ENVSET;
  mrb_field_write_barrier(mrb, (struct RBasic*)p, (struct RBasic*)e);
  MRB_ENV_CLOSE(e);

  e->stack = (mrb_value*)mrb_malloc(mrb, sizeof(mrb_value) * argc);
  MRB_ENV_SET_LEN(e, argc);

  if (argv) {
    for (i = 0; i < argc; ++i) {
      e->stack[i] = argv[i];
    }
  }
  else {
    for (i = 0; i < argc; ++i) {
      SET_NIL_VALUE(e->stack[i]);
    }
  }
  return p;
}

MRB_API struct RProc*
mrb_closure_new_cfunc(mrb_state *mrb, mrb_func_t func, int nlocals)
{
  return mrb_proc_new_cfunc_with_env(mrb, func, nlocals, NULL);
}

MRB_API mrb_value
mrb_proc_cfunc_env_get(mrb_state *mrb, mrb_int idx)
{
  const struct RProc *p = mrb->c->ci->proc;
  struct REnv *e;

  if (!p || !MRB_PROC_CFUNC_P(p)) {
    mrb_raise(mrb, E_TYPE_ERROR, "Can't get cfunc env from non-cfunc proc.");
  }
  e = MRB_PROC_ENV(p);
  if (!e) {
    mrb_raise(mrb, E_TYPE_ERROR, "Can't get cfunc env from cfunc Proc without REnv.");
  }
  if (idx < 0 || MRB_ENV_LEN(e) <= idx) {
    mrb_raisef(mrb, E_INDEX_ERROR, "Env index out of range: %i (expected: 0 <= index < %i)",
               idx, MRB_ENV_LEN(e));
  }

  return e->stack[idx];
}

void
mrb_proc_copy(struct RProc *a, struct RProc *b)
{
  if (a->body.irep) {
    /* already initialized proc */
    return;
  }
  a->flags = b->flags;
  a->body = b->body;
  if (!MRB_PROC_CFUNC_P(a) && a->body.irep) {
    mrb_irep_incref(NULL, (mrb_irep*)a->body.irep);
  }
  a->upper = b->upper;
  a->e.env = b->e.env;
  /* a->e.target_class = a->e.target_class; */
}

static mrb_value
mrb_proc_s_new(mrb_state *mrb, mrb_value proc_class)
{
  mrb_value blk;
  mrb_value proc;
  struct RProc *p;

  /* Calling Proc.new without a block is not implemented yet */
  mrb_get_args(mrb, "&!", &blk);
  p = (struct RProc *)mrb_obj_alloc(mrb, MRB_TT_PROC, mrb_class_ptr(proc_class));
  mrb_proc_copy(p, mrb_proc_ptr(blk));
  proc = mrb_obj_value(p);
  mrb_funcall_with_block(mrb, proc, MRB_SYM(initialize), 0, NULL, proc);
  if (!MRB_PROC_STRICT_P(p) &&
      mrb->c->ci > mrb->c->cibase && MRB_PROC_ENV(p) == mrb->c->ci[-1].u.env) {
    p->flags |= MRB_PROC_ORPHAN;
  }
  return proc;
}

static mrb_value
mrb_proc_init_copy(mrb_state *mrb, mrb_value self)
{
  mrb_value proc = mrb_get_arg1(mrb);

  if (!mrb_proc_p(proc)) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "not a proc");
  }
  mrb_proc_copy(mrb_proc_ptr(self), mrb_proc_ptr(proc));
  return self;
}

/* 15.2.17.4.2 */
static mrb_value
proc_arity(mrb_state *mrb, mrb_value self)
{
  return mrb_int_value(mrb, mrb_proc_arity(mrb_proc_ptr(self)));
}

/* 15.3.1.2.6  */
/* 15.3.1.3.27 */
/*
 * call-seq:
 *   lambda { |...| block }  -> a_proc
 *
 * Equivalent to <code>Proc.new</code>, except the resulting Proc objects
 * check the number of parameters passed when called.
 */
static mrb_value
proc_lambda(mrb_state *mrb, mrb_value self)
{
  mrb_value blk;
  struct RProc *p;

  mrb_get_args(mrb, "&", &blk);
  if (mrb_nil_p(blk)) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "tried to create Proc object without a block");
  }
  if (!mrb_proc_p(blk)) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "not a proc");
  }
  p = mrb_proc_ptr(blk);
  if (!MRB_PROC_STRICT_P(p)) {
    struct RProc *p2 = (struct RProc*)mrb_obj_alloc(mrb, MRB_TT_PROC, p->c);
    mrb_proc_copy(p2, p);
    p2->flags |= MRB_PROC_STRICT;
    return mrb_obj_value(p2);
  }
  return blk;
}

mrb_int
mrb_proc_arity(const struct RProc *p)
{
  const mrb_irep *irep;
  const mrb_code *pc;
  mrb_aspec aspec;
  int ma, op, ra, pa, arity;

  if (MRB_PROC_CFUNC_P(p)) {
    /* TODO cfunc aspec not implemented yet */
    return -1;
  }

  irep = p->body.irep;
  if (!irep) {
    return 0;
  }

  pc = irep->iseq;
  /* arity is depend on OP_ENTER */
  if (*pc != OP_ENTER) {
    return 0;
  }

  aspec = PEEK_W(pc+1);
  ma = MRB_ASPEC_REQ(aspec);
  op = MRB_ASPEC_OPT(aspec);
  ra = MRB_ASPEC_REST(aspec);
  pa = MRB_ASPEC_POST(aspec);
  arity = ra || (MRB_PROC_STRICT_P(p) && op) ? -(ma + pa + 1) : ma + pa;

  return arity;
}

void
mrb_init_proc(mrb_state *mrb)
{
  struct RProc *p;
  mrb_method_t m;

  mrb_define_class_method(mrb, mrb->proc_class, "new", mrb_proc_s_new, MRB_ARGS_NONE()|MRB_ARGS_BLOCK());
  mrb_define_method(mrb, mrb->proc_class, "initialize_copy", mrb_proc_init_copy, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, mrb->proc_class, "arity", proc_arity, MRB_ARGS_NONE());

  p = mrb_proc_new(mrb, &call_irep);
  MRB_METHOD_FROM_PROC(m, p);
  mrb_define_method_raw(mrb, mrb->proc_class, MRB_SYM(call), m);
  mrb_define_method_raw(mrb, mrb->proc_class, MRB_OPSYM(aref), m);

  mrb_define_class_method(mrb, mrb->kernel_module, "lambda", proc_lambda, MRB_ARGS_NONE()|MRB_ARGS_BLOCK()); /* 15.3.1.2.6  */
  mrb_define_method(mrb, mrb->kernel_module,       "lambda", proc_lambda, MRB_ARGS_NONE()|MRB_ARGS_BLOCK()); /* 15.3.1.3.27 */
}
