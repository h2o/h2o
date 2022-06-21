#include <mruby.h>
#include <mruby/array.h>
#include <mruby/class.h>
#include <mruby/proc.h>

#define fiber_ptr(o) ((struct RFiber*)mrb_ptr(o))

#define FIBER_STACK_INIT_SIZE 64
#define FIBER_CI_INIT_SIZE 8
/* copied from vm.c */
#define CINFO_RESUMED 3

/*
 *  call-seq:
 *     Fiber.new{...} -> obj
 *
 *  Creates a fiber, whose execution is suspend until it is explicitly
 *  resumed using <code>Fiber#resume</code> method.
 *  The code running inside the fiber can give up control by calling
 *  <code>Fiber.yield</code> in which case it yields control back to caller
 *  (the caller of the <code>Fiber#resume</code>).
 *
 *  Upon yielding or termination the Fiber returns the value of the last
 *  executed expression
 *
 *  For instance:
 *
 *    fiber = Fiber.new do
 *      Fiber.yield 1
 *      2
 *    end
 *
 *    puts fiber.resume
 *    puts fiber.resume
 *    puts fiber.resume
 *
 *  <em>produces</em>
 *
 *    1
 *    2
 *    resuming dead fiber (FiberError)
 *
 *  The <code>Fiber#resume</code> method accepts an arbitrary number of
 *  parameters, if it is the first call to <code>resume</code> then they
 *  will be passed as block arguments. Otherwise they will be the return
 *  value of the call to <code>Fiber.yield</code>
 *
 *  Example:
 *
 *    fiber = Fiber.new do |first|
 *      second = Fiber.yield first + 2
 *    end
 *
 *    puts fiber.resume 10
 *    puts fiber.resume 14
 *    puts fiber.resume 18
 *
 *  <em>produces</em>
 *
 *    12
 *    14
 *    resuming dead fiber (FiberError)
 *
 */
static mrb_value
fiber_init(mrb_state *mrb, mrb_value self)
{
  static const struct mrb_context mrb_context_zero = { 0 };
  struct RFiber *f = fiber_ptr(self);
  struct mrb_context *c;
  struct RProc *p;
  mrb_callinfo *ci;
  mrb_value blk;
  size_t slen;

  mrb_get_args(mrb, "&!", &blk);

  if (f->cxt) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "cannot initialize twice");
  }
  p = mrb_proc_ptr(blk);
  if (MRB_PROC_CFUNC_P(p)) {
    mrb_raise(mrb, E_FIBER_ERROR, "tried to create Fiber from C defined method");
  }

  c = (struct mrb_context*)mrb_malloc(mrb, sizeof(struct mrb_context));
  *c = mrb_context_zero;
  f->cxt = c;

  /* initialize VM stack */
  slen = FIBER_STACK_INIT_SIZE;
  if (p->body.irep->nregs > slen) {
    slen += p->body.irep->nregs;
  }
  c->stbase = (mrb_value *)mrb_malloc(mrb, slen*sizeof(mrb_value));
  c->stend = c->stbase + slen;

  {
    mrb_value *p = c->stbase;
    mrb_value *pend = c->stend;

    while (p < pend) {
      SET_NIL_VALUE(*p);
      p++;
    }
  }

  /* copy receiver from a block */
  c->stbase[0] = mrb->c->ci->stack[0];

  /* initialize callinfo stack */
  c->cibase = (mrb_callinfo *)mrb_calloc(mrb, FIBER_CI_INIT_SIZE, sizeof(mrb_callinfo));
  c->ciend = c->cibase + FIBER_CI_INIT_SIZE;
  c->ci = c->cibase;

  /* adjust return callinfo */
  ci = c->ci;
  mrb_vm_ci_target_class_set(ci, MRB_PROC_TARGET_CLASS(p));
  mrb_vm_ci_proc_set(ci, p);
  mrb_field_write_barrier(mrb, (struct RBasic*)mrb_obj_ptr(self), (struct RBasic*)p);
  ci->stack = c->stbase;
  ci[1] = ci[0];
  c->ci++;                      /* push dummy callinfo */

  c->fib = f;
  c->status = MRB_FIBER_CREATED;

  return self;
}

static struct mrb_context*
fiber_check(mrb_state *mrb, mrb_value fib)
{
  struct RFiber *f = fiber_ptr(fib);

  mrb_assert(f->tt == MRB_TT_FIBER);
  if (!f->cxt) {
    mrb_raise(mrb, E_FIBER_ERROR, "uninitialized Fiber");
  }
  return f->cxt;
}

static mrb_value
fiber_result(mrb_state *mrb, const mrb_value *a, mrb_int len)
{
  if (len == 0) return mrb_nil_value();
  if (len == 1) return a[0];
  return mrb_ary_new_from_values(mrb, len, a);
}

/* mark return from context modifying method */
#define MARK_CONTEXT_MODIFY(c) (c)->ci->u.target_class = NULL

static void
fiber_check_cfunc(mrb_state *mrb, struct mrb_context *c)
{
  mrb_callinfo *ci;

  for (ci = c->ci; ci >= c->cibase; ci--) {
    if (ci->cci > 0) {
      mrb_raise(mrb, E_FIBER_ERROR, "can't cross C function boundary");
    }
  }
}

static void
fiber_switch_context(mrb_state *mrb, struct mrb_context *c)
{
  if (mrb->c->fib) {
    mrb_write_barrier(mrb, (struct RBasic*)mrb->c->fib);
  }
  c->status = MRB_FIBER_RUNNING;
  mrb->c = c;
}

static mrb_value
fiber_switch(mrb_state *mrb, mrb_value self, mrb_int len, const mrb_value *a, mrb_bool resume, mrb_bool vmexec)
{
  struct mrb_context *c = fiber_check(mrb, self);
  struct mrb_context *old_c = mrb->c;
  enum mrb_fiber_state status;
  mrb_value value;

  fiber_check_cfunc(mrb, c);
  status = c->status;
  switch (status) {
  case MRB_FIBER_TRANSFERRED:
    if (resume) {
      mrb_raise(mrb, E_FIBER_ERROR, "resuming transferred fiber");
    }
    break;
  case MRB_FIBER_RUNNING:
  case MRB_FIBER_RESUMED:
    mrb_raise(mrb, E_FIBER_ERROR, "double resume");
    break;
  case MRB_FIBER_TERMINATED:
    mrb_raise(mrb, E_FIBER_ERROR, "resuming dead fiber");
    break;
  default:
    break;
  }
  old_c->status = resume ? MRB_FIBER_RESUMED : MRB_FIBER_TRANSFERRED;
  c->prev = resume ? mrb->c : (c->prev ? c->prev : mrb->root_c);
  fiber_switch_context(mrb, c);
  if (status == MRB_FIBER_CREATED) {
    mrb_value *b, *e;

    if (!c->ci->proc) {
      mrb_raise(mrb, E_FIBER_ERROR, "double resume (current)");
    }
    if (vmexec) {
      c->ci--;                    /* pop dummy callinfo */
    }
    if (len >= 15) {
      mrb_stack_extend(mrb, 3);   /* for receiver, args and (optional) block */
      c->stbase[1] = mrb_ary_new_from_values(mrb, len, a);
      len = 15;
    }
    else {
      mrb_stack_extend(mrb, len+2); /* for receiver and (optional) block */
      b = c->stbase+1;
      e = b + len;
      while (b<e) {
        *b++ = *a++;
      }
    }
    c->cibase->n = len;
    value = c->stbase[0] = MRB_PROC_ENV(c->cibase->proc)->stack[0];
  }
  else {
    value = fiber_result(mrb, a, len);
    if (vmexec) {
      c->ci[1].stack[0] = value;
    }
  }

  if (vmexec) {
    c->vmexec = TRUE;
    value = mrb_vm_exec(mrb, c->ci->proc, c->ci->pc);
    mrb->c = old_c;
  }
  else {
    MARK_CONTEXT_MODIFY(c);
  }
  return value;
}

/*
 *  call-seq:
 *     fiber.resume(args, ...) -> obj
 *
 *  Resumes the fiber from the point at which the last <code>Fiber.yield</code>
 *  was called, or starts running it if it is the first call to
 *  <code>resume</code>. Arguments passed to resume will be the value of
 *  the <code>Fiber.yield</code> expression or will be passed as block
 *  parameters to the fiber's block if this is the first <code>resume</code>.
 *
 *  Alternatively, when resume is called it evaluates to the arguments passed
 *  to the next <code>Fiber.yield</code> statement inside the fiber's block
 *  or to the block value if it runs to completion without any
 *  <code>Fiber.yield</code>
 */
static mrb_value
fiber_resume(mrb_state *mrb, mrb_value self)
{
  const mrb_value *a;
  mrb_int len;
  mrb_bool vmexec = FALSE;

  mrb_get_args(mrb, "*!", &a, &len);
  if (mrb->c->ci->cci > 0) {
    vmexec = TRUE;
  }
  return fiber_switch(mrb, self, len, a, TRUE, vmexec);
}

/* resume thread with given arguments */
MRB_API mrb_value
mrb_fiber_resume(mrb_state *mrb, mrb_value fib, mrb_int len, const mrb_value *a)
{
  return fiber_switch(mrb, fib, len, a, TRUE, TRUE);
}

/*
 *  call-seq:
 *     fiber.alive? -> true or false
 *
 *  Returns true if the fiber can still be resumed. After finishing
 *  execution of the fiber block this method will always return false.
 */
MRB_API mrb_value
mrb_fiber_alive_p(mrb_state *mrb, mrb_value self)
{
  struct mrb_context *c = fiber_check(mrb, self);
  return mrb_bool_value(c->status != MRB_FIBER_TERMINATED);
}
#define fiber_alive_p mrb_fiber_alive_p

static mrb_value
fiber_eq(mrb_state *mrb, mrb_value self)
{
  mrb_value other = mrb_get_arg1(mrb);

  if (!mrb_fiber_p(other)) {
    return mrb_false_value();
  }
  return mrb_bool_value(fiber_ptr(self) == fiber_ptr(other));
}

/*
 *  call-seq:
 *     fiber.transfer(args, ...) -> obj
 *
 *  Transfers control to receiver fiber of the method call.
 *  Unlike <code>resume</code> the receiver wouldn't be pushed to call
 * stack of fibers. Instead it will switch to the call stack of
 * transferring fiber.
 *  When resuming a fiber that was transferred to another fiber it would
 * cause double resume error. Though when the fiber is re-transferred
 * and <code>Fiber.yield</code> is called, the fiber would be resumable.
 */
static mrb_value
fiber_transfer(mrb_state *mrb, mrb_value self)
{
  struct mrb_context *c = fiber_check(mrb, self);
  const mrb_value* a;
  mrb_int len;

  fiber_check_cfunc(mrb, mrb->c);
  mrb_get_args(mrb, "*!", &a, &len);

  if (c == mrb->root_c) {
    mrb->c->status = MRB_FIBER_TRANSFERRED;
    fiber_switch_context(mrb, c);
    MARK_CONTEXT_MODIFY(c);
    return fiber_result(mrb, a, len);
  }

  if (c == mrb->c) {
    return fiber_result(mrb, a, len);
  }

  return fiber_switch(mrb, self, len, a, FALSE, FALSE);
}

/* yield values to the caller fiber */
/* mrb_fiber_yield() must be called as `return mrb_fiber_yield(...)` */
MRB_API mrb_value
mrb_fiber_yield(mrb_state *mrb, mrb_int len, const mrb_value *a)
{
  struct mrb_context *c = mrb->c;

  if (!c->prev) {
    mrb_raise(mrb, E_FIBER_ERROR, "can't yield from root fiber");
  }

  fiber_check_cfunc(mrb, c);
  c->prev->status = MRB_FIBER_RUNNING;
  c->status = MRB_FIBER_SUSPENDED;
  fiber_switch_context(mrb, c->prev);
  c->prev = NULL;
  if (c->vmexec) {
    c->vmexec = FALSE;
    mrb->c->ci->cci = CINFO_RESUMED;
    c->ci--;                    /* pop callinfo for yield */
  }
  MARK_CONTEXT_MODIFY(mrb->c);
  return fiber_result(mrb, a, len);
}

/*
 *  call-seq:
 *     Fiber.yield(args, ...) -> obj
 *
 *  Yields control back to the context that resumed the fiber, passing
 *  along any arguments that were passed to it. The fiber will resume
 *  processing at this point when <code>resume</code> is called next.
 *  Any arguments passed to the next <code>resume</code> will be the
 *
 *  mruby limitation: Fiber resume/yield cannot cross C function boundary.
 *  thus you cannot yield from #initialize which is called by mrb_funcall().
 */
static mrb_value
fiber_yield(mrb_state *mrb, mrb_value self)
{
  const mrb_value *a;
  mrb_int len;

  mrb_get_args(mrb, "*!", &a, &len);
  return mrb_fiber_yield(mrb, len, a);
}

/*
 *  call-seq:
 *     Fiber.current() -> fiber
 *
 *  Returns the current fiber. If you are not running in the context of
 *  a fiber this method will return the root fiber.
 */
static mrb_value
fiber_current(mrb_state *mrb, mrb_value self)
{
  if (!mrb->c->fib) {
    struct RFiber *f = MRB_OBJ_ALLOC(mrb, MRB_TT_FIBER, mrb_class_ptr(self));

    f->cxt = mrb->c;
    mrb->c->fib = f;
  }
  return mrb_obj_value(mrb->c->fib);
}

void
mrb_mruby_fiber_gem_init(mrb_state* mrb)
{
  struct RClass *c;

  c = mrb_define_class(mrb, "Fiber", mrb->object_class);
  MRB_SET_INSTANCE_TT(c, MRB_TT_FIBER);

  mrb_define_method(mrb, c, "initialize", fiber_init,    MRB_ARGS_NONE()|MRB_ARGS_BLOCK());
  mrb_define_method(mrb, c, "resume",     fiber_resume,  MRB_ARGS_ANY());
  mrb_define_method(mrb, c, "transfer",   fiber_transfer, MRB_ARGS_ANY());
  mrb_define_method(mrb, c, "alive?",     fiber_alive_p, MRB_ARGS_NONE());
  mrb_define_method(mrb, c, "==",         fiber_eq,      MRB_ARGS_REQ(1));

  mrb_define_class_method(mrb, c, "yield", fiber_yield, MRB_ARGS_ANY());
  mrb_define_class_method(mrb, c, "current", fiber_current, MRB_ARGS_NONE());

  mrb_define_class(mrb, "FiberError", mrb->eStandardError_class);
}

void
mrb_mruby_fiber_gem_final(mrb_state* mrb)
{
}
