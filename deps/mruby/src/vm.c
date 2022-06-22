/*
** vm.c - virtual machine for mruby
**
** See Copyright Notice in mruby.h
*/

#include <stddef.h>
#include <stdarg.h>
#ifndef MRB_NO_FLOAT
#include <math.h>
#endif
#include <mruby.h>
#include <mruby/array.h>
#include <mruby/class.h>
#include <mruby/hash.h>
#include <mruby/irep.h>
#include <mruby/numeric.h>
#include <mruby/proc.h>
#include <mruby/range.h>
#include <mruby/string.h>
#include <mruby/variable.h>
#include <mruby/error.h>
#include <mruby/opcode.h>
#include "value_array.h"
#include <mruby/throw.h>
#include <mruby/dump.h>
#include <mruby/presym.h>

#ifdef MRB_NO_STDIO
#if defined(__cplusplus)
extern "C" {
#endif
void abort(void);
#if defined(__cplusplus)
}  /* extern "C" { */
#endif
#endif

#define STACK_INIT_SIZE 128
#define CALLINFO_INIT_SIZE 32

/* Define amount of linear stack growth. */
#ifndef MRB_STACK_GROWTH
#define MRB_STACK_GROWTH 128
#endif

/* Maximum mrb_funcall() depth. Should be set lower on memory constrained systems. */
#ifndef MRB_FUNCALL_DEPTH_MAX
#define MRB_FUNCALL_DEPTH_MAX 512
#endif

/* Maximum stack depth. Should be set lower on memory constrained systems.
The value below allows about 60000 recursive calls in the simplest case. */
#ifndef MRB_STACK_MAX
#define MRB_STACK_MAX (0x40000 - MRB_STACK_GROWTH)
#endif

#ifdef VM_DEBUG
# define DEBUG(x) (x)
#else
# define DEBUG(x)
#endif


#ifndef MRB_GC_FIXED_ARENA
static void
mrb_gc_arena_shrink(mrb_state *mrb, int idx)
{
  mrb_gc *gc = &mrb->gc;
  int capa = gc->arena_capa;

  if (idx < capa / 4) {
    capa >>= 2;
    if (capa < MRB_GC_ARENA_SIZE) {
      capa = MRB_GC_ARENA_SIZE;
    }
    if (capa != gc->arena_capa) {
      gc->arena = (struct RBasic**)mrb_realloc(mrb, gc->arena, sizeof(struct RBasic*)*capa);
      gc->arena_capa = capa;
    }
  }
}
#else
#define mrb_gc_arena_shrink(mrb,idx)
#endif

#define CALL_MAXARGS 127

void mrb_method_missing(mrb_state *mrb, mrb_sym name, mrb_value self, mrb_value args);

static inline void
stack_clear(mrb_value *from, size_t count)
{
#ifdef MRB_NAN_BOXING
  while (count-- > 0) {
    SET_NIL_VALUE(*from);
    from++;
  }
#else
  memset(from, 0, sizeof(mrb_value)*count);
#endif
}

static inline void
stack_copy(mrb_value *dst, const mrb_value *src, size_t size)
{
  memcpy(dst, src, sizeof(mrb_value)*size);
}

static void
stack_init(mrb_state *mrb)
{
  struct mrb_context *c = mrb->c;

  /* mrb_assert(mrb->stack == NULL); */
  c->stbase = (mrb_value *)mrb_calloc(mrb, STACK_INIT_SIZE, sizeof(mrb_value));
  c->stend = c->stbase + STACK_INIT_SIZE;

  /* mrb_assert(ci == NULL); */
  c->cibase = (mrb_callinfo *)mrb_calloc(mrb, CALLINFO_INIT_SIZE, sizeof(mrb_callinfo));
  c->ciend = c->cibase + CALLINFO_INIT_SIZE;
  c->ci = c->cibase;
  c->ci->u.target_class = mrb->object_class;
  c->ci->stack = c->stbase;
}

static inline void
envadjust(mrb_state *mrb, mrb_value *oldbase, mrb_value *newbase, size_t oldsize)
{
  mrb_callinfo *ci = mrb->c->cibase;

  if (newbase == oldbase) return;
  while (ci <= mrb->c->ci) {
    struct REnv *e = mrb_vm_ci_env(ci);
    mrb_value *st;

    if (e && MRB_ENV_ONSTACK_P(e) &&
        (st = e->stack) && oldbase <= st && st < oldbase+oldsize) {
      ptrdiff_t off = e->stack - oldbase;

      e->stack = newbase + off;
    }

    if (ci->proc && MRB_PROC_ENV_P(ci->proc) && e != MRB_PROC_ENV(ci->proc)) {
      e = MRB_PROC_ENV(ci->proc);

      if (e && MRB_ENV_ONSTACK_P(e) &&
          (st = e->stack) && oldbase <= st && st < oldbase+oldsize) {
        ptrdiff_t off = e->stack - oldbase;

        e->stack = newbase + off;
      }
    }

    ci->stack = newbase + (ci->stack - oldbase);
    ci++;
  }
}

/** def rec ; $deep =+ 1 ; if $deep > 1000 ; return 0 ; end ; rec ; end  */

static void
stack_extend_alloc(mrb_state *mrb, mrb_int room)
{
  mrb_value *oldbase = mrb->c->stbase;
  mrb_value *newstack;
  size_t oldsize = mrb->c->stend - mrb->c->stbase;
  size_t size = oldsize;
  size_t off = mrb->c->ci->stack ? mrb->c->stend - mrb->c->ci->stack : 0;

  if (off > size) size = off;
#ifdef MRB_STACK_EXTEND_DOUBLING
  if ((size_t)room <= size)
    size *= 2;
  else
    size += room;
#else
  /* Use linear stack growth.
     It is slightly slower than doubling the stack space,
     but it saves memory on small devices. */
  if (room <= MRB_STACK_GROWTH)
    size += MRB_STACK_GROWTH;
  else
    size += room;
#endif

  newstack = (mrb_value *)mrb_realloc_simple(mrb, mrb->c->stbase, sizeof(mrb_value) * size);
  if (newstack == NULL) {
    mrb_exc_raise(mrb, mrb_obj_value(mrb->stack_err));
  }
  stack_clear(&(newstack[oldsize]), size - oldsize);
  envadjust(mrb, oldbase, newstack, oldsize);
  mrb->c->stbase = newstack;
  mrb->c->stend = mrb->c->stbase + size;

  /* Raise an exception if the new stack size will be too large,
     to prevent infinite recursion. However, do this only after resizing the stack, so mrb_raise has stack space to work with. */
  if (size > MRB_STACK_MAX) {
    mrb_exc_raise(mrb, mrb_obj_value(mrb->stack_err));
  }
}

MRB_API void
mrb_stack_extend(mrb_state *mrb, mrb_int room)
{
  if (!mrb->c->ci->stack || mrb->c->ci->stack + room >= mrb->c->stend) {
    stack_extend_alloc(mrb, room);
  }
}

static inline struct REnv*
uvenv(mrb_state *mrb, mrb_int up)
{
  const struct RProc *proc = mrb->c->ci->proc;
  struct REnv *e;

  while (up--) {
    proc = proc->upper;
    if (!proc) return NULL;
  }
  e = MRB_PROC_ENV(proc);
  if (e) return e;              /* proc has enclosed env */
  else {
    mrb_callinfo *ci = mrb->c->ci;
    mrb_callinfo *cb = mrb->c->cibase;

    while (cb <= ci) {
      if (ci->proc == proc) {
        return mrb_vm_ci_env(ci);
      }
      ci--;
    }
  }
  return NULL;
}

static inline const struct RProc*
top_proc(mrb_state *mrb, const struct RProc *proc)
{
  while (proc->upper) {
    if (MRB_PROC_SCOPE_P(proc) || MRB_PROC_STRICT_P(proc))
      return proc;
    proc = proc->upper;
  }
  return proc;
}

#define CI_ACC_SKIP    -1
#define CI_ACC_DIRECT  -2
#define CI_ACC_RESUMED -3

static inline mrb_callinfo*
cipush(mrb_state *mrb, mrb_int push_stacks, mrb_int acc,
       struct RClass *target_class, const struct RProc *proc, mrb_sym mid, mrb_int argc)
{
  struct mrb_context *c = mrb->c;
  mrb_callinfo *ci = c->ci;

  if (ci + 1 == c->ciend) {
    ptrdiff_t size = ci - c->cibase;

    c->cibase = (mrb_callinfo *)mrb_realloc(mrb, c->cibase, sizeof(mrb_callinfo)*size*2);
    c->ci = c->cibase + size;
    c->ciend = c->cibase + size * 2;
  }
  ci = ++c->ci;
  ci->mid = mid;
  mrb_vm_ci_proc_set(ci, proc);
  ci->stack = ci[-1].stack + push_stacks;
  ci->argc = (int16_t)argc;
  ci->acc = (int16_t)acc;
  ci->u.target_class = target_class;

  return ci;
}

void
mrb_env_unshare(mrb_state *mrb, struct REnv *e)
{
  if (e == NULL) return;
  else {
    size_t len = (size_t)MRB_ENV_LEN(e);
    mrb_value *p;

    if (!MRB_ENV_ONSTACK_P(e)) return;
    if (e->cxt != mrb->c) return;
    if (e == mrb_vm_ci_env(mrb->c->cibase)) return; /* for mirb */
    p = (mrb_value *)mrb_malloc(mrb, sizeof(mrb_value)*len);
    if (len > 0) {
      stack_copy(p, e->stack, len);
    }
    e->stack = p;
    MRB_ENV_CLOSE(e);
    mrb_write_barrier(mrb, (struct RBasic *)e);
  }
}

static inline mrb_callinfo*
cipop(mrb_state *mrb)
{
  struct mrb_context *c = mrb->c;
  struct REnv *env = mrb_vm_ci_env(c->ci);

  c->ci--;
  if (env) mrb_env_unshare(mrb, env);
  return c->ci;
}

void mrb_exc_set(mrb_state *mrb, mrb_value exc);
static mrb_value mrb_run(mrb_state *mrb, const struct RProc* proc, mrb_value self);

#ifndef MRB_FUNCALL_ARGC_MAX
#define MRB_FUNCALL_ARGC_MAX 16
#endif

MRB_API mrb_value
mrb_funcall(mrb_state *mrb, mrb_value self, const char *name, mrb_int argc, ...)
{
  mrb_value argv[MRB_FUNCALL_ARGC_MAX];
  va_list ap;
  mrb_int i;
  mrb_sym mid = mrb_intern_cstr(mrb, name);

  if (argc > MRB_FUNCALL_ARGC_MAX) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "Too long arguments. (limit=" MRB_STRINGIZE(MRB_FUNCALL_ARGC_MAX) ")");
  }

  va_start(ap, argc);
  for (i = 0; i < argc; i++) {
    argv[i] = va_arg(ap, mrb_value);
  }
  va_end(ap);
  return mrb_funcall_argv(mrb, self, mid, argc, argv);
}

MRB_API mrb_value
mrb_funcall_id(mrb_state *mrb, mrb_value self, mrb_sym mid, mrb_int argc, ...)
{
  mrb_value argv[MRB_FUNCALL_ARGC_MAX];
  va_list ap;
  mrb_int i;

  if (argc > MRB_FUNCALL_ARGC_MAX) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "Too long arguments. (limit=" MRB_STRINGIZE(MRB_FUNCALL_ARGC_MAX) ")");
  }

  va_start(ap, argc);
  for (i = 0; i < argc; i++) {
    argv[i] = va_arg(ap, mrb_value);
  }
  va_end(ap);
  return mrb_funcall_argv(mrb, self, mid, argc, argv);
}

static mrb_int
ci_nregs(mrb_callinfo *ci)
{
  const struct RProc *p;
  mrb_int n = 0;

  if (!ci) return 3;
  p = ci->proc;
  if (!p) {
    if (ci->argc < 0) return 3;
    return ci->argc+2;
  }
  if (!MRB_PROC_CFUNC_P(p) && p->body.irep) {
    n = p->body.irep->nregs;
  }
  if (ci->argc < 0) {
    if (n < 3) n = 3; /* self + args + blk */
  }
  if (ci->argc > n) {
    n = ci->argc + 2; /* self + blk */
  }
  return n;
}

MRB_API mrb_value
mrb_funcall_with_block(mrb_state *mrb, mrb_value self, mrb_sym mid, mrb_int argc, const mrb_value *argv, mrb_value blk)
{
  mrb_value val;
  int ai = mrb_gc_arena_save(mrb);

  if (!mrb->jmp) {
    struct mrb_jmpbuf c_jmp;
    ptrdiff_t nth_ci = mrb->c->ci - mrb->c->cibase;

    MRB_TRY(&c_jmp) {
      mrb->jmp = &c_jmp;
      /* recursive call */
      val = mrb_funcall_with_block(mrb, self, mid, argc, argv, blk);
      mrb->jmp = 0;
    }
    MRB_CATCH(&c_jmp) { /* error */
      while (nth_ci < (mrb->c->ci - mrb->c->cibase)) {
        cipop(mrb);
      }
      mrb->jmp = 0;
      val = mrb_obj_value(mrb->exc);
    }
    MRB_END_EXC(&c_jmp);
    mrb->jmp = 0;
  }
  else {
    mrb_method_t m;
    struct RClass *c;
    mrb_callinfo *ci;
    mrb_int n = ci_nregs(mrb->c->ci);
    ptrdiff_t voff = -1;

    if (!mrb->c->stbase) {
      stack_init(mrb);
    }
    if (argc < 0) {
      mrb_raisef(mrb, E_ARGUMENT_ERROR, "negative argc for funcall (%i)", argc);
    }
    c = mrb_class(mrb, self);
    m = mrb_method_search_vm(mrb, &c, mid);
    if (MRB_METHOD_UNDEF_P(m)) {
      mrb_sym missing = MRB_SYM(method_missing);
      mrb_value args = mrb_ary_new_from_values(mrb, argc, argv);
      m = mrb_method_search_vm(mrb, &c, missing);
      if (MRB_METHOD_UNDEF_P(m)) {
        mrb_method_missing(mrb, mid, self, args);
      }
      mrb_ary_unshift(mrb, args, mrb_symbol_value(mid));
      mrb_stack_extend(mrb, n+2);
      mrb->c->ci->stack[n+1] = args;
      argc = -1;
    }
    if (mrb->c->ci - mrb->c->cibase > MRB_FUNCALL_DEPTH_MAX) {
      mrb_exc_raise(mrb, mrb_obj_value(mrb->stack_err));
    }
    ci = cipush(mrb, n, 0, c, NULL, mid, argc);
    if (argc < 0) argc = 1;
    if (mrb->c->stbase <= argv && argv < mrb->c->stend) {
      voff = argv - mrb->c->stbase;
    }
    if (argc >= CALL_MAXARGS) {
      mrb_value args = mrb_ary_new_from_values(mrb, argc, argv);

      mrb->c->ci->stack[1] = args;
      ci->argc = -1;
      argc = 1;
    }
    mrb_stack_extend(mrb, argc + 2);
    if (MRB_METHOD_PROC_P(m)) {
      struct RProc *p = MRB_METHOD_PROC(m);

      mrb_vm_ci_proc_set(ci, p);
      if (!MRB_PROC_CFUNC_P(p)) {
        mrb_stack_extend(mrb, p->body.irep->nregs + argc);
      }
    }
    if (voff >= 0) {
      argv = mrb->c->stbase + voff;
    }
    mrb->c->ci->stack[0] = self;
    if (ci->argc > 0) {
      stack_copy(mrb->c->ci->stack+1, argv, argc);
    }
    mrb->c->ci->stack[argc+1] = blk;

    if (MRB_METHOD_CFUNC_P(m)) {
      ci->acc = CI_ACC_DIRECT;
      val = MRB_METHOD_CFUNC(m)(mrb, self);
      cipop(mrb);
    }
    else {
      ci->acc = CI_ACC_SKIP;
      val = mrb_run(mrb, MRB_METHOD_PROC(m), self);
    }
  }
  mrb_gc_arena_restore(mrb, ai);
  mrb_gc_protect(mrb, val);
  return val;
}

MRB_API mrb_value
mrb_funcall_argv(mrb_state *mrb, mrb_value self, mrb_sym mid, mrb_int argc, const mrb_value *argv)
{
  return mrb_funcall_with_block(mrb, self, mid, argc, argv, mrb_nil_value());
}

mrb_value
mrb_exec_irep(mrb_state *mrb, mrb_value self, struct RProc *p)
{
  mrb_callinfo *ci = mrb->c->ci;
  mrb_int keep, nregs;

  mrb->c->ci->stack[0] = self;
  mrb_vm_ci_proc_set(ci, p);
  if (MRB_PROC_CFUNC_P(p)) {
    return MRB_PROC_CFUNC(p)(mrb, self);
  }
  nregs = p->body.irep->nregs;
  if (ci->argc < 0) keep = 3;
  else keep = ci->argc + 2;
  if (nregs < keep) {
    mrb_stack_extend(mrb, keep);
  }
  else {
    mrb_stack_extend(mrb, nregs);
    stack_clear(mrb->c->ci->stack+keep, nregs-keep);
  }

  cipush(mrb, 0, 0, NULL, NULL, 0, 0);

  return self;
}

/* 15.3.1.3.4  */
/* 15.3.1.3.44 */
/*
 *  call-seq:
 *     obj.send(symbol [, args...])        -> obj
 *     obj.__send__(symbol [, args...])      -> obj
 *
 *  Invokes the method identified by _symbol_, passing it any
 *  arguments specified. You can use <code>__send__</code> if the name
 *  +send+ clashes with an existing method in _obj_.
 *
 *     class Klass
 *       def hello(*args)
 *         "Hello " + args.join(' ')
 *       end
 *     end
 *     k = Klass.new
 *     k.send :hello, "gentle", "readers"   #=> "Hello gentle readers"
 */
mrb_value
mrb_f_send(mrb_state *mrb, mrb_value self)
{
  mrb_sym name;
  mrb_value block, *regs;
  const mrb_value *argv;
  mrb_int argc, i, len;
  mrb_method_t m;
  struct RClass *c;
  mrb_callinfo *ci;

  mrb_get_args(mrb, "n*&", &name, &argv, &argc, &block);
  ci = mrb->c->ci;
  if (ci->acc < 0) {
  funcall:
    return mrb_funcall_with_block(mrb, self, name, argc, argv, block);
  }

  c = mrb_class(mrb, self);
  m = mrb_method_search_vm(mrb, &c, name);
  if (MRB_METHOD_UNDEF_P(m)) {            /* call method_mising */
    goto funcall;
  }

  ci->mid = name;
  ci->u.target_class = c;
  regs = mrb->c->ci->stack+1;
  /* remove first symbol from arguments */
  if (ci->argc >= 0) {
    for (i=0,len=ci->argc; i<len; i++) {
      regs[i] = regs[i+1];
    }
    ci->argc--;
  }
  else {                     /* variable length arguments */
    regs[0] = mrb_ary_subseq(mrb, regs[0], 1, RARRAY_LEN(regs[0]) - 1);
  }

  if (MRB_METHOD_CFUNC_P(m)) {
    if (MRB_METHOD_PROC_P(m)) {
      mrb_vm_ci_proc_set(ci, MRB_METHOD_PROC(m));
    }
    return MRB_METHOD_CFUNC(m)(mrb, self);
  }
  return mrb_exec_irep(mrb, self, MRB_METHOD_PROC(m));
}

static mrb_value
eval_under(mrb_state *mrb, mrb_value self, mrb_value blk, struct RClass *c)
{
  struct RProc *p;
  mrb_callinfo *ci;
  int nregs;

  if (mrb_nil_p(blk)) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "no block given");
  }
  ci = mrb->c->ci;
  if (ci->acc == CI_ACC_DIRECT) {
    return mrb_yield_with_class(mrb, blk, 1, &self, self, c);
  }
  ci->u.target_class = c;
  p = mrb_proc_ptr(blk);
  mrb_vm_ci_proc_set(ci, p);
  ci->argc = 1;
  ci->mid = ci[-1].mid;
  if (MRB_PROC_CFUNC_P(p)) {
    mrb_stack_extend(mrb, 3);
    mrb->c->ci->stack[0] = self;
    mrb->c->ci->stack[1] = self;
    mrb->c->ci->stack[2] = mrb_nil_value();
    return MRB_PROC_CFUNC(p)(mrb, self);
  }
  nregs = p->body.irep->nregs;
  if (nregs < 3) nregs = 3;
  mrb_stack_extend(mrb, nregs);
  mrb->c->ci->stack[0] = self;
  mrb->c->ci->stack[1] = self;
  stack_clear(mrb->c->ci->stack+2, nregs-2);
  ci = cipush(mrb, 0, 0, NULL, NULL, 0, 0);

  return self;
}

/* 15.2.2.4.35 */
/*
 *  call-seq:
 *     mod.class_eval {| | block }  -> obj
 *     mod.module_eval {| | block } -> obj
 *
 *  Evaluates block in the context of _mod_. This can
 *  be used to add methods to a class. <code>module_eval</code> returns
 *  the result of evaluating its argument.
 */
mrb_value
mrb_mod_module_eval(mrb_state *mrb, mrb_value mod)
{
  mrb_value a, b;

  if (mrb_get_args(mrb, "|S&", &a, &b) == 1) {
    mrb_raise(mrb, E_NOTIMP_ERROR, "module_eval/class_eval with string not implemented");
  }
  return eval_under(mrb, mod, b, mrb_class_ptr(mod));
}

/* 15.3.1.3.18 */
/*
 *  call-seq:
 *     obj.instance_eval {| | block }                       -> obj
 *
 *  Evaluates the given block,within  the context of the receiver (_obj_).
 *  In order to set the context, the variable +self+ is set to _obj_ while
 *  the code is executing, giving the code access to _obj_'s
 *  instance variables. In the version of <code>instance_eval</code>
 *  that takes a +String+, the optional second and third
 *  parameters supply a filename and starting line number that are used
 *  when reporting compilation errors.
 *
 *     class KlassWithSecret
 *       def initialize
 *         @secret = 99
 *       end
 *     end
 *     k = KlassWithSecret.new
 *     k.instance_eval { @secret }   #=> 99
 */
mrb_value
mrb_obj_instance_eval(mrb_state *mrb, mrb_value self)
{
  mrb_value a, b;

  if (mrb_get_args(mrb, "|S&", &a, &b) == 1) {
    mrb_raise(mrb, E_NOTIMP_ERROR, "instance_eval with string not implemented");
  }
  return eval_under(mrb, self, b, mrb_singleton_class_ptr(mrb, self));
}

MRB_API mrb_value
mrb_yield_with_class(mrb_state *mrb, mrb_value b, mrb_int argc, const mrb_value *argv, mrb_value self, struct RClass *c)
{
  struct RProc *p;
  mrb_sym mid = mrb->c->ci->mid;
  mrb_callinfo *ci;
  mrb_value val;
  mrb_int n;

  if (mrb_nil_p(b)) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "no block given");
  }
  ci = mrb->c->ci;
  n = ci_nregs(ci);
  if (ci - mrb->c->cibase > MRB_FUNCALL_DEPTH_MAX) {
    mrb_exc_raise(mrb, mrb_obj_value(mrb->stack_err));
  }
  p = mrb_proc_ptr(b);
  ci = cipush(mrb, n, CI_ACC_SKIP, c, p, mid, 0 /* dummy */);
  if (argc >= CALL_MAXARGS) {
    ci->argc = -1;
    n = 3;
  }
  else {
    ci->argc = (int)argc;
    n = argc + 2;
  }
  mrb_stack_extend(mrb, n);
  mrb->c->ci->stack[0] = self;
  if (ci->argc < 0) {
    mrb->c->ci->stack[1] = mrb_ary_new_from_values(mrb, argc, argv);
    argc = 1;
  }
  else if (argc > 0) {
    stack_copy(mrb->c->ci->stack+1, argv, argc);
  }
  mrb->c->ci->stack[argc+1] = mrb_nil_value();

  if (MRB_PROC_CFUNC_P(p)) {
    val = MRB_PROC_CFUNC(p)(mrb, self);
    cipop(mrb);
  }
  else {
    val = mrb_run(mrb, p, self);
  }
  return val;
}

MRB_API mrb_value
mrb_yield_argv(mrb_state *mrb, mrb_value b, mrb_int argc, const mrb_value *argv)
{
  struct RProc *p = mrb_proc_ptr(b);

  return mrb_yield_with_class(mrb, b, argc, argv, MRB_PROC_ENV(p)->stack[0], MRB_PROC_TARGET_CLASS(p));
}

MRB_API mrb_value
mrb_yield(mrb_state *mrb, mrb_value b, mrb_value arg)
{
  struct RProc *p = mrb_proc_ptr(b);

  return mrb_yield_with_class(mrb, b, 1, &arg, MRB_PROC_ENV(p)->stack[0], MRB_PROC_TARGET_CLASS(p));
}

mrb_value
mrb_yield_cont(mrb_state *mrb, mrb_value b, mrb_value self, mrb_int argc, const mrb_value *argv)
{
  struct RProc *p;
  mrb_callinfo *ci;

  if (mrb_nil_p(b)) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "no block given");
  }
  if (!mrb_proc_p(b)) {
    mrb_raise(mrb, E_TYPE_ERROR, "not a block");
  }

  p = mrb_proc_ptr(b);
  ci = mrb->c->ci;

  mrb_stack_extend(mrb, 3);
  mrb->c->ci->stack[1] = mrb_ary_new_from_values(mrb, argc, argv);
  mrb->c->ci->stack[2] = mrb_nil_value();
  ci->argc = -1;
  return mrb_exec_irep(mrb, self, p);
}

static struct RBreak*
break_new(mrb_state *mrb, uint32_t tag, const struct RProc *p, mrb_value val)
{
  struct RBreak *brk;

  brk = (struct RBreak*)mrb_obj_alloc(mrb, MRB_TT_BREAK, NULL);
  mrb_break_proc_set(brk, p);
  mrb_break_value_set(brk, val);
  mrb_break_tag_set(brk, tag);

  return brk;
}

#define MRB_CATCH_FILTER_RESCUE (UINT32_C(1) << MRB_CATCH_RESCUE)
#define MRB_CATCH_FILTER_ENSURE (UINT32_C(1) << MRB_CATCH_ENSURE)
#define MRB_CATCH_FILTER_ALL    (MRB_CATCH_FILTER_RESCUE | MRB_CATCH_FILTER_ENSURE)

static const struct mrb_irep_catch_handler *
catch_handler_find(mrb_state *mrb, mrb_callinfo *ci, const mrb_code *pc, uint32_t filter)
{
  const mrb_irep *irep;
  ptrdiff_t xpc;
  size_t cnt;
  const struct mrb_irep_catch_handler *e;

/* The comparison operators use `>` and `<=` because pc already points to the next instruction */
#define catch_cover_p(pc, beg, end) ((pc) > (ptrdiff_t)(beg) && (pc) <= (ptrdiff_t)(end))

  if (ci->proc == NULL || MRB_PROC_CFUNC_P(ci->proc)) return NULL;
  irep = ci->proc->body.irep;
  if (irep->clen < 1) return NULL;
  xpc = pc - irep->iseq;
  /* If it retry at the top level, pc will be 0, so check with -1 as the start position */
  mrb_assert(catch_cover_p(xpc, -1, irep->ilen));
  if (!catch_cover_p(xpc, -1, irep->ilen)) return NULL;

  /* Currently uses a simple linear search to avoid processing complexity. */
  cnt = irep->clen;
  e = mrb_irep_catch_handler_table(irep) + cnt - 1;
  for (; cnt > 0; cnt --, e --) {
    if (((UINT32_C(1) << e->type) & filter) &&
        catch_cover_p(xpc, mrb_irep_catch_handler_unpack(e->begin), mrb_irep_catch_handler_unpack(e->end))) {
      return e;
    }
  }

#undef catch_cover_p

  return NULL;
}

typedef enum {
  LOCALJUMP_ERROR_RETURN = 0,
  LOCALJUMP_ERROR_BREAK = 1,
  LOCALJUMP_ERROR_YIELD = 2
} localjump_error_kind;

static void
localjump_error(mrb_state *mrb, localjump_error_kind kind)
{
  char kind_str[3][7] = { "return", "break", "yield" };
  char kind_str_len[] = { 6, 5, 5 };
  static const char lead[] = "unexpected ";
  mrb_value msg;
  mrb_value exc;

  msg = mrb_str_new_capa(mrb, sizeof(lead) + 7);
  mrb_str_cat(mrb, msg, lead, sizeof(lead) - 1);
  mrb_str_cat(mrb, msg, kind_str[kind], kind_str_len[kind]);
  exc = mrb_exc_new_str(mrb, E_LOCALJUMP_ERROR, msg);
  mrb_exc_set(mrb, exc);
}

static void
argnum_error(mrb_state *mrb, mrb_int num)
{
  mrb_value exc;
  mrb_value str;
  mrb_int argc = mrb->c->ci->argc;

  if (argc < 0) {
    mrb_value args = mrb->c->ci->stack[1];
    if (mrb_array_p(args)) {
      argc = RARRAY_LEN(args);
    }
  }
  if (mrb->c->ci->mid) {
    str = mrb_format(mrb, "'%n': wrong number of arguments (%i for %i)",
                     mrb->c->ci->mid, argc, num);
  }
  else {
    str = mrb_format(mrb, "wrong number of arguments (%i for %i)", argc, num);
  }
  exc = mrb_exc_new_str(mrb, E_ARGUMENT_ERROR, str);
  mrb_exc_set(mrb, exc);
}

static mrb_bool
break_tag_p(struct RBreak *brk, uint32_t tag)
{
  return (brk != NULL && brk->tt == MRB_TT_BREAK) ? TRUE : FALSE;
}

static void
prepare_tagged_break(mrb_state *mrb, uint32_t tag, const struct RProc *proc, mrb_value val)
{
  if (break_tag_p((struct RBreak*)mrb->exc, tag)) {
    mrb_break_tag_set((struct RBreak*)mrb->exc, tag);
  }
  else {
    mrb->exc = (struct RObject*)break_new(mrb, tag, proc, val);
  }
}

#define THROW_TAGGED_BREAK(mrb, tag, proc, val) \
  do { \
    prepare_tagged_break(mrb, tag, proc, val); \
    goto L_CATCH_TAGGED_BREAK; \
  } while (0)

#define UNWIND_ENSURE(mrb, ci, pc, tag, proc, val) \
  do { \
    ch = catch_handler_find(mrb, ci, pc, MRB_CATCH_FILTER_ENSURE); \
    if (ch) { \
      THROW_TAGGED_BREAK(mrb, tag, proc, val); \
    } \
  } while (0)

/*
 *  CHECKPOINT_RESTORE(tag) {
 *    This part is executed when jumping by the same "tag" of RBreak (it is not executed the first time).
 *    Write the code required (initialization of variables, etc.) for the subsequent processing.
 *  }
 *  CHECKPOINT_MAIN(tag) {
 *    This part is always executed.
 *  }
 *  CHECKPOINT_END(tag);
 *
 *  ...
 *
 *  // Jump to CHECKPOINT_RESTORE with the same "tag".
 *  goto CHECKPOINT_LABEL_MAKE(tag);
 */

#define CHECKPOINT_LABEL_MAKE(tag) L_CHECKPOINT_ ## tag

#define CHECKPOINT_RESTORE(tag) \
  do { \
    if (FALSE) { \
      CHECKPOINT_LABEL_MAKE(tag): \
      do {

#define CHECKPOINT_MAIN(tag) \
      } while (0); \
    } \
    do {

#define CHECKPOINT_END(tag) \
    } while (0); \
  } while (0)

#ifdef MRB_USE_DEBUG_HOOK
#define CODE_FETCH_HOOK(mrb, irep, pc, regs) if ((mrb)->code_fetch_hook) (mrb)->code_fetch_hook((mrb), (irep), (pc), (regs));
#else
#define CODE_FETCH_HOOK(mrb, irep, pc, regs)
#endif

#ifdef MRB_BYTECODE_DECODE_OPTION
#define BYTECODE_DECODER(x) ((mrb)->bytecode_decoder)?(mrb)->bytecode_decoder((mrb), (x)):(x)
#else
#define BYTECODE_DECODER(x) (x)
#endif

#ifndef MRB_NO_DIRECT_THREADING
#if defined __GNUC__ || defined __clang__ || defined __INTEL_COMPILER
#define DIRECT_THREADED
#endif
#endif /* ifndef MRB_NO_DIRECT_THREADING */

#ifndef DIRECT_THREADED

#define INIT_DISPATCH for (;;) { insn = BYTECODE_DECODER(*pc); CODE_FETCH_HOOK(mrb, irep, pc, regs); switch (insn) {
#define CASE(insn,ops) case insn: pc++; FETCH_ ## ops (); mrb->c->ci->pc = pc;
#define NEXT goto L_END_DISPATCH
#define JUMP NEXT
#define END_DISPATCH L_END_DISPATCH:;}}

#else

#define INIT_DISPATCH JUMP; return mrb_nil_value();
#define CASE(insn,ops) L_ ## insn: pc++; FETCH_ ## ops (); mrb->c->ci->pc = pc;
#define NEXT insn=BYTECODE_DECODER(*pc); CODE_FETCH_HOOK(mrb, irep, pc, regs); goto *optable[insn]
#define JUMP NEXT

#define END_DISPATCH

#endif

MRB_API mrb_value
mrb_vm_run(mrb_state *mrb, const struct RProc *proc, mrb_value self, mrb_int stack_keep)
{
  const mrb_irep *irep = proc->body.irep;
  mrb_value result;
  struct mrb_context *c = mrb->c;
  ptrdiff_t cioff = c->ci - c->cibase;
  mrb_int nregs = irep->nregs;

  if (!c->stbase) {
    stack_init(mrb);
  }
  if (stack_keep > nregs)
    nregs = stack_keep;
  mrb_stack_extend(mrb, nregs);
  stack_clear(c->ci->stack + stack_keep, nregs - stack_keep);
  c->ci->stack[0] = self;
  result = mrb_vm_exec(mrb, proc, irep->iseq);
  if (mrb->c != c) {
    if (mrb->c->fib) {
      mrb_write_barrier(mrb, (struct RBasic*)mrb->c->fib);
    }
    mrb->c = c;
  }
  else if (c->ci - c->cibase > cioff) {
    c->ci = c->cibase + cioff;
  }
  return result;
}

static mrb_bool
check_target_class(mrb_state *mrb)
{
  if (!mrb_vm_ci_target_class(mrb->c->ci)) {
    mrb_value exc = mrb_exc_new_lit(mrb, E_TYPE_ERROR, "no target class or module");
    mrb_exc_set(mrb, exc);
    return FALSE;
  }
  return TRUE;
}

void mrb_hash_check_kdict(mrb_state *mrb, mrb_value self);

MRB_API mrb_value
mrb_vm_exec(mrb_state *mrb, const struct RProc *proc, const mrb_code *pc)
{
  /* mrb_assert(MRB_PROC_CFUNC_P(proc)) */
  const mrb_irep *irep = proc->body.irep;
  const mrb_pool_value *pool = irep->pool;
  const mrb_sym *syms = irep->syms;
  mrb_code insn;
  int ai = mrb_gc_arena_save(mrb);
  struct mrb_jmpbuf *prev_jmp = mrb->jmp;
  struct mrb_jmpbuf c_jmp;
  uint32_t a;
  uint16_t b;
  uint16_t c;
  mrb_sym mid;
  const struct mrb_irep_catch_handler *ch;

#ifdef DIRECT_THREADED
  static void *optable[] = {
#define OPCODE(x,_) &&L_OP_ ## x,
#include "mruby/ops.h"
#undef OPCODE
  };
#endif

  mrb_bool exc_catched = FALSE;
RETRY_TRY_BLOCK:

  MRB_TRY(&c_jmp) {

  if (exc_catched) {
    exc_catched = FALSE;
    mrb_gc_arena_restore(mrb, ai);
    if (mrb->exc && mrb->exc->tt == MRB_TT_BREAK)
      goto L_BREAK;
    goto L_RAISE;
  }
  mrb->jmp = &c_jmp;
  mrb_vm_ci_proc_set(mrb->c->ci, proc);

#define regs (mrb->c->ci->stack)
  INIT_DISPATCH {
    CASE(OP_NOP, Z) {
      /* do nothing */
      NEXT;
    }

    CASE(OP_MOVE, BB) {
      regs[a] = regs[b];
      NEXT;
    }

    CASE(OP_LOADL16, BS) {
      goto op_loadl;
    }
    CASE(OP_LOADL, BB) {
    op_loadl:
      switch (pool[b].tt) {   /* number */
      case IREP_TT_INT32:
        regs[a] = mrb_int_value(mrb, (mrb_int)pool[b].u.i32);
        break;
      case IREP_TT_INT64:
#if defined(MRB_INT64)
        regs[a] = mrb_int_value(mrb, (mrb_int)pool[b].u.i64);
        break;
#else
#if defined(MRB_64BIT)
        if (INT32_MIN <= pool[b].u.i64 && pool[b].u.i64 <= INT32_MAX) {
          regs[a] = mrb_int_value(mrb, (mrb_int)pool[b].u.i64);
          break;
        }
#endif
        goto L_INT_OVERFLOW;
#endif
#ifndef MRB_NO_FLOAT
      case IREP_TT_FLOAT:
        regs[a] = mrb_float_value(mrb, pool[b].u.f);
        break;
#endif
      default:
        /* should not happen (tt:string) */
        regs[a] = mrb_nil_value();
        break;
      }
      NEXT;
    }

    CASE(OP_LOADI, BB) {
      SET_FIXNUM_VALUE(regs[a], b);
      NEXT;
    }

    CASE(OP_LOADINEG, BB) {
      SET_FIXNUM_VALUE(regs[a], -b);
      NEXT;
    }

    CASE(OP_LOADI__1,B) goto L_LOADI;
    CASE(OP_LOADI_0,B) goto L_LOADI;
    CASE(OP_LOADI_1,B) goto L_LOADI;
    CASE(OP_LOADI_2,B) goto L_LOADI;
    CASE(OP_LOADI_3,B) goto L_LOADI;
    CASE(OP_LOADI_4,B) goto L_LOADI;
    CASE(OP_LOADI_5,B) goto L_LOADI;
    CASE(OP_LOADI_6,B) goto L_LOADI;
    CASE(OP_LOADI_7, B) {
    L_LOADI:
      SET_FIXNUM_VALUE(regs[a], (mrb_int)insn - (mrb_int)OP_LOADI_0);
      NEXT;
    }

    CASE(OP_LOADI16, BS) {
      SET_FIXNUM_VALUE(regs[a], (mrb_int)(int16_t)b);
      NEXT;
    }

    CASE(OP_LOADI32, BSS) {
      SET_INT_VALUE(mrb, regs[a], (int32_t)(((uint32_t)b<<16)+c));
      NEXT;
    }

    CASE(OP_LOADSYM, BB) {
      SET_SYM_VALUE(regs[a], syms[b]);
      NEXT;
    }

    CASE(OP_LOADSYM16, BS) {
      SET_SYM_VALUE(regs[a], syms[b]);
      NEXT;
    }

    CASE(OP_LOADNIL, B) {
      SET_NIL_VALUE(regs[a]);
      NEXT;
    }

    CASE(OP_LOADSELF, B) {
      regs[a] = regs[0];
      NEXT;
    }

    CASE(OP_LOADT, B) {
      SET_TRUE_VALUE(regs[a]);
      NEXT;
    }

    CASE(OP_LOADF, B) {
      SET_FALSE_VALUE(regs[a]);
      NEXT;
    }

    CASE(OP_GETGV, BB) {
      mrb_value val = mrb_gv_get(mrb, syms[b]);
      regs[a] = val;
      NEXT;
    }

    CASE(OP_SETGV, BB) {
      mrb_gv_set(mrb, syms[b], regs[a]);
      NEXT;
    }

    CASE(OP_GETSV, BB) {
      mrb_value val = mrb_vm_special_get(mrb, syms[b]);
      regs[a] = val;
      NEXT;
    }

    CASE(OP_SETSV, BB) {
      mrb_vm_special_set(mrb, syms[b], regs[a]);
      NEXT;
    }

    CASE(OP_GETIV, BB) {
      regs[a] = mrb_iv_get(mrb, regs[0], syms[b]);
      NEXT;
    }

    CASE(OP_SETIV, BB) {
      mrb_iv_set(mrb, regs[0], syms[b], regs[a]);
      NEXT;
    }

    CASE(OP_GETCV, BB) {
      mrb_value val;
      val = mrb_vm_cv_get(mrb, syms[b]);
      regs[a] = val;
      NEXT;
    }

    CASE(OP_SETCV, BB) {
      mrb_vm_cv_set(mrb, syms[b], regs[a]);
      NEXT;
    }

    CASE(OP_GETCONST, BB) {
      mrb_value val;
      mrb_sym sym = syms[b];

      val = mrb_vm_const_get(mrb, sym);
      regs[a] = val;
      NEXT;
    }

    CASE(OP_SETCONST, BB) {
      mrb_vm_const_set(mrb, syms[b], regs[a]);
      NEXT;
    }

    CASE(OP_GETMCNST, BB) {
      mrb_value val;

      val = mrb_const_get(mrb, regs[a], syms[b]);
      regs[a] = val;
      NEXT;
    }

    CASE(OP_SETMCNST, BB) {
      mrb_const_set(mrb, regs[a+1], syms[b], regs[a]);
      NEXT;
    }

    CASE(OP_GETUPVAR, BBB) {
      mrb_value *regs_a = regs + a;
      struct REnv *e = uvenv(mrb, c);

      if (e && b < MRB_ENV_LEN(e)) {
        *regs_a = e->stack[b];
      }
      else {
        *regs_a = mrb_nil_value();
      }
      NEXT;
    }

    CASE(OP_SETUPVAR, BBB) {
      struct REnv *e = uvenv(mrb, c);

      if (e) {
        mrb_value *regs_a = regs + a;

        if (b < MRB_ENV_LEN(e)) {
          e->stack[b] = *regs_a;
          mrb_write_barrier(mrb, (struct RBasic*)e);
        }
      }
      NEXT;
    }

    CASE(OP_JMP, S) {
      pc += (int16_t)a;
      JUMP;
    }
    CASE(OP_JMPIF, BS) {
      if (mrb_test(regs[a])) {
        pc += (int16_t)b;
        JUMP;
      }
      NEXT;
    }
    CASE(OP_JMPNOT, BS) {
      if (!mrb_test(regs[a])) {
        pc += (int16_t)b;
        JUMP;
      }
      NEXT;
    }
    CASE(OP_JMPNIL, BS) {
      if (mrb_nil_p(regs[a])) {
        pc += (int16_t)b;
        JUMP;
      }
      NEXT;
    }

    CASE(OP_JMPUW, S) {
      a = (uint32_t)((pc - irep->iseq) + (int16_t)a);
      CHECKPOINT_RESTORE(RBREAK_TAG_JUMP) {
        struct RBreak *brk = (struct RBreak*)mrb->exc;
        mrb_value target = mrb_break_value_get(brk);
        mrb_assert(mrb_integer_p(target));
        a = (uint32_t)mrb_integer(target);
        mrb_assert(a >= 0 && a < irep->ilen);
      }
      CHECKPOINT_MAIN(RBREAK_TAG_JUMP) {
        ch = catch_handler_find(mrb, mrb->c->ci, pc, MRB_CATCH_FILTER_ENSURE);
        if (ch) {
          /* avoiding a jump from a catch handler into the same handler */
          if (a < mrb_irep_catch_handler_unpack(ch->begin) || a >= mrb_irep_catch_handler_unpack(ch->end)) {
            THROW_TAGGED_BREAK(mrb, RBREAK_TAG_JUMP, proc, mrb_fixnum_value(a));
          }
        }
      }
      CHECKPOINT_END(RBREAK_TAG_JUMP);

      mrb->exc = NULL; /* clear break object */
      pc = irep->iseq + a;
      JUMP;
    }

    CASE(OP_EXCEPT, B) {
      mrb_value exc;

      if (mrb->exc == NULL) {
        exc = mrb_nil_value();
      }
      else {
        switch (mrb->exc->tt) {
        case MRB_TT_BREAK:
        case MRB_TT_EXCEPTION:
          exc = mrb_obj_value(mrb->exc);
          break;
        default:
          mrb_assert(!"bad mrb_type");
          exc = mrb_nil_value();
          break;
        }
        mrb->exc = NULL;
      }
      regs[a] = exc;
      NEXT;
    }
    CASE(OP_RESCUE, BB) {
      mrb_value exc = regs[a];  /* exc on stack */
      mrb_value e = regs[b];
      struct RClass *ec;

      switch (mrb_type(e)) {
      case MRB_TT_CLASS:
      case MRB_TT_MODULE:
        break;
      default:
        {
          mrb_value exc;

          exc = mrb_exc_new_lit(mrb, E_TYPE_ERROR,
                                    "class or module required for rescue clause");
          mrb_exc_set(mrb, exc);
          goto L_RAISE;
        }
      }
      ec = mrb_class_ptr(e);
      regs[b] = mrb_bool_value(mrb_obj_is_kind_of(mrb, exc, ec));
      NEXT;
    }

    CASE(OP_RAISEIF, B) {
      mrb_value exc = regs[a];
      if (mrb_break_p(exc)) {
        mrb->exc = mrb_obj_ptr(exc);
        goto L_BREAK;
      }
      mrb_exc_set(mrb, exc);
      if (mrb->exc) {
        goto L_RAISE;
      }
      NEXT;
    }

    CASE(OP_SENDV, BB) {
      c = CALL_MAXARGS;
      goto L_SEND;
    };

    CASE(OP_SENDVB, BB) {
      c = CALL_MAXARGS;
      goto L_SENDB;
    };

    CASE(OP_SEND, BBB)
    L_SEND:
    {
      /* push nil after arguments */
      int bidx = (c == CALL_MAXARGS) ? a+2 : a+c+1;
      SET_NIL_VALUE(regs[bidx]);
      goto L_SENDB;
    };
    L_SEND_SYM:
    {
      /* push nil after arguments */
      int bidx = (c == CALL_MAXARGS) ? a+2 : a+c+1;
      SET_NIL_VALUE(regs[bidx]);
      goto L_SENDB_SYM;
    };

    CASE(OP_SENDB, BBB)
    L_SENDB:
    mid = syms[b];
    L_SENDB_SYM:
    {
      mrb_int argc = (c == CALL_MAXARGS) ? -1 : c;
      mrb_int bidx = (argc < 0) ? a+2 : a+c+1;
      mrb_method_t m;
      struct RClass *cls;
      mrb_callinfo *ci = mrb->c->ci;
      mrb_value recv, blk;

      mrb_assert(bidx < irep->nregs);

      recv = regs[a];
      blk = regs[bidx];
      if (!mrb_nil_p(blk) && !mrb_proc_p(blk)) {
        blk = mrb_type_convert(mrb, blk, MRB_TT_PROC, MRB_SYM(to_proc));
        /* The stack might have been reallocated during mrb_type_convert(),
           see #3622 */
        regs[bidx] = blk;
      }
      cls = mrb_class(mrb, recv);
      m = mrb_method_search_vm(mrb, &cls, mid);
      if (MRB_METHOD_UNDEF_P(m)) {
        mrb_sym missing = MRB_SYM(method_missing);
        m = mrb_method_search_vm(mrb, &cls, missing);
        if (MRB_METHOD_UNDEF_P(m) || (missing == mrb->c->ci->mid && mrb_obj_eq(mrb, regs[0], recv))) {
          mrb_value args = (argc < 0) ? regs[a+1] : mrb_ary_new_from_values(mrb, c, regs+a+1);
          mrb_method_missing(mrb, mid, recv, args);
        }
        if (argc >= 0) {
          if (a+2 >= irep->nregs) {
            mrb_stack_extend(mrb, a+3);
          }
          regs[a+1] = mrb_ary_new_from_values(mrb, c, regs+a+1);
          regs[a+2] = blk;
          argc = -1;
        }
        mrb_ary_unshift(mrb, regs[a+1], mrb_symbol_value(mid));
        mid = missing;
      }

      /* push callinfo */
      ci = cipush(mrb, a, a, cls, NULL, mid, argc);

      if (MRB_METHOD_CFUNC_P(m)) {
        if (MRB_METHOD_PROC_P(m)) {
          struct RProc *p = MRB_METHOD_PROC(m);

          mrb_vm_ci_proc_set(ci, p);
          recv = p->body.func(mrb, recv);
        }
        else if (MRB_METHOD_NOARG_P(m) &&
                 (argc > 0 || (argc == -1 && RARRAY_LEN(regs[1]) != 0))) {
          argnum_error(mrb, 0);
          goto L_RAISE;
        }
        else {
          recv = MRB_METHOD_FUNC(m)(mrb, recv);
        }
        mrb_gc_arena_restore(mrb, ai);
        mrb_gc_arena_shrink(mrb, ai);
        if (mrb->exc) goto L_RAISE;
        ci = mrb->c->ci;
        if (mrb_proc_p(blk)) {
          struct RProc *p = mrb_proc_ptr(blk);
          if (p && !MRB_PROC_STRICT_P(p) && MRB_PROC_ENV(p) == mrb_vm_ci_env(&ci[-1])) {
            p->flags |= MRB_PROC_ORPHAN;
          }
        }
        if (!ci->u.target_class) { /* return from context modifying method (resume/yield) */
          if (ci->acc == CI_ACC_RESUMED) {
            mrb->jmp = prev_jmp;
            return recv;
          }
          else {
            mrb_assert(!MRB_PROC_CFUNC_P(ci[-1].proc));
            proc = ci[-1].proc;
            irep = proc->body.irep;
            pool = irep->pool;
            syms = irep->syms;
          }
        }
        mrb->c->ci->stack[0] = recv;
        /* pop stackpos */
        ci = cipop(mrb);
        pc = ci->pc;
        JUMP;
      }
      else {
        /* setup environment for calling method */
        mrb_vm_ci_proc_set(ci, (proc = MRB_METHOD_PROC(m)));
        irep = proc->body.irep;
        pool = irep->pool;
        syms = irep->syms;
        mrb_stack_extend(mrb, (argc < 0 && irep->nregs < 3) ? 3 : irep->nregs);
        pc = irep->iseq;
        JUMP;
      }
    }

    CASE(OP_CALL, Z) {
      mrb_callinfo *ci;
      mrb_value recv = mrb->c->ci->stack[0];
      struct RProc *m = mrb_proc_ptr(recv);

      /* replace callinfo */
      ci = mrb->c->ci;
      ci->u.target_class = MRB_PROC_TARGET_CLASS(m);
      mrb_vm_ci_proc_set(ci, m);
      if (MRB_PROC_ENV_P(m)) {
        ci->mid = MRB_PROC_ENV(m)->mid;
      }

      /* prepare stack */
      if (MRB_PROC_CFUNC_P(m)) {
        recv = MRB_PROC_CFUNC(m)(mrb, recv);
        mrb_gc_arena_restore(mrb, ai);
        mrb_gc_arena_shrink(mrb, ai);
        if (mrb->exc) goto L_RAISE;
        /* pop stackpos */
        ci = cipop(mrb);
        pc = ci->pc;
        regs[ci[1].acc] = recv;
        irep = mrb->c->ci->proc->body.irep;
        pool = irep->pool;
        syms = irep->syms;
        JUMP;
      }
      else {
        /* setup environment for calling method */
        proc = m;
        irep = m->body.irep;
        if (!irep) {
          mrb->c->ci->stack[0] = mrb_nil_value();
          a = 0;
          c = OP_R_NORMAL;
          goto L_RETURN;
        }
        pool = irep->pool;
        syms = irep->syms;
        mrb_stack_extend(mrb, irep->nregs);
        if (ci->argc < 0) {
          if (irep->nregs > 3) {
            stack_clear(regs+3, irep->nregs-3);
          }
        }
        else if (ci->argc+2 < irep->nregs) {
          stack_clear(regs+ci->argc+2, irep->nregs-ci->argc-2);
        }
        if (MRB_PROC_ENV_P(m)) {
          regs[0] = MRB_PROC_ENV(m)->stack[0];
        }
        pc = irep->iseq;
        JUMP;
      }
    }

    CASE(OP_SUPER, BB) {
      mrb_int argc = (b == CALL_MAXARGS) ? -1 : b;
      int bidx = (argc < 0) ? a+2 : a+b+1;
      mrb_method_t m;
      struct RClass *cls;
      mrb_callinfo *ci = mrb->c->ci;
      mrb_value recv, blk;
      const struct RProc *p = ci->proc;
      mrb_sym mid = ci->mid;
      struct RClass* target_class = MRB_PROC_TARGET_CLASS(p);

      if (MRB_PROC_ENV_P(p) && p->e.env->mid && p->e.env->mid != mid) { /* alias support */
        mid = p->e.env->mid;    /* restore old mid */
      }
      mrb_assert(bidx < irep->nregs);

      if (mid == 0 || !target_class) {
        mrb_value exc = mrb_exc_new_lit(mrb, E_NOMETHOD_ERROR, "super called outside of method");
        mrb_exc_set(mrb, exc);
        goto L_RAISE;
      }
      if (target_class->flags & MRB_FL_CLASS_IS_PREPENDED) {
        target_class = mrb_vm_ci_target_class(ci);
      }
      else if (target_class->tt == MRB_TT_MODULE) {
        target_class = mrb_vm_ci_target_class(ci);
        if (target_class->tt != MRB_TT_ICLASS) {
          mrb_value exc = mrb_exc_new_lit(mrb, E_RUNTIME_ERROR, "superclass info lost [mruby limitations]");
          mrb_exc_set(mrb, exc);
          goto L_RAISE;
        }
      }
      recv = regs[0];
      if (!mrb_obj_is_kind_of(mrb, recv, target_class)) {
        mrb_value exc = mrb_exc_new_lit(mrb, E_TYPE_ERROR,
                                            "self has wrong type to call super in this context");
        mrb_exc_set(mrb, exc);
        goto L_RAISE;
      }
      blk = regs[bidx];
      if (!mrb_nil_p(blk) && !mrb_proc_p(blk)) {
        blk = mrb_type_convert(mrb, blk, MRB_TT_PROC, MRB_SYM(to_proc));
        /* The stack or ci stack might have been reallocated during
           mrb_type_convert(), see #3622 and #3784 */
        regs[bidx] = blk;
        ci = mrb->c->ci;
      }
      cls = target_class->super;
      m = mrb_method_search_vm(mrb, &cls, mid);
      if (MRB_METHOD_UNDEF_P(m)) {
        mrb_sym missing = MRB_SYM(method_missing);

        if (mid != missing) {
          cls = mrb_class(mrb, recv);
        }
        m = mrb_method_search_vm(mrb, &cls, missing);
        if (MRB_METHOD_UNDEF_P(m)) {
          mrb_value args = (argc < 0) ? regs[a+1] : mrb_ary_new_from_values(mrb, b, regs+a+1);
          mrb_method_missing(mrb, mid, recv, args);
        }
        mid = missing;
        if (argc >= 0) {
          if (a+2 >= irep->nregs) {
            mrb_stack_extend(mrb, a+3);
          }
          regs[a+1] = mrb_ary_new_from_values(mrb, b, regs+a+1);
          regs[a+2] = blk;
          argc = -1;
        }
        mrb_ary_unshift(mrb, regs[a+1], mrb_symbol_value(ci->mid));
      }

      /* push callinfo */
      ci = cipush(mrb, a, 0, cls, NULL, mid, argc);

      /* prepare stack */
      mrb->c->ci->stack[0] = recv;

      if (MRB_METHOD_CFUNC_P(m)) {
        mrb_value v;

        if (MRB_METHOD_PROC_P(m)) {
          mrb_vm_ci_proc_set(ci, MRB_METHOD_PROC(m));
        }
        v = MRB_METHOD_CFUNC(m)(mrb, recv);
        mrb_gc_arena_restore(mrb, ai);
        if (mrb->exc) goto L_RAISE;
        ci = mrb->c->ci;
        mrb_assert(!mrb_break_p(v));
        if (!mrb_vm_ci_target_class(ci)) { /* return from context modifying method (resume/yield) */
          if (ci->acc == CI_ACC_RESUMED) {
            mrb->jmp = prev_jmp;
            return v;
          }
          else {
            mrb_assert(!MRB_PROC_CFUNC_P(ci[-1].proc));
            proc = ci[-1].proc;
            irep = proc->body.irep;
            pool = irep->pool;
            syms = irep->syms;
          }
        }
        mrb->c->ci->stack[0] = v;
        ci = cipop(mrb);
        pc = ci->pc;
        JUMP;
      }
      else {
        /* fill callinfo */
        ci->acc = a;

        /* setup environment for calling method */
        mrb_vm_ci_proc_set(ci, (proc = MRB_METHOD_PROC(m)));
        irep = proc->body.irep;
        pool = irep->pool;
        syms = irep->syms;
        mrb_stack_extend(mrb, (argc < 0 && irep->nregs < 3) ? 3 : irep->nregs);
        pc = irep->iseq;
        JUMP;
      }
    }

    CASE(OP_ARGARY, BS) {
      mrb_int m1 = (b>>11)&0x3f;
      mrb_int r  = (b>>10)&0x1;
      mrb_int m2 = (b>>5)&0x1f;
      mrb_int kd = (b>>4)&0x1;
      mrb_int lv = (b>>0)&0xf;
      mrb_value *stack;

      if (mrb->c->ci->mid == 0 || mrb_vm_ci_target_class(mrb->c->ci) == NULL) {
        mrb_value exc;

      L_NOSUPER:
        exc = mrb_exc_new_lit(mrb, E_NOMETHOD_ERROR, "super called outside of method");
        mrb_exc_set(mrb, exc);
        goto L_RAISE;
      }
      if (lv == 0) stack = regs + 1;
      else {
        struct REnv *e = uvenv(mrb, lv-1);
        if (!e) goto L_NOSUPER;
        if (MRB_ENV_LEN(e) <= m1+r+m2+kd+1)
          goto L_NOSUPER;
        stack = e->stack + 1;
      }
      if (r == 0) {
        regs[a] = mrb_ary_new_from_values(mrb, m1+m2+kd, stack);
      }
      else {
        mrb_value *pp = NULL;
        struct RArray *rest;
        mrb_int len = 0;

        if (mrb_array_p(stack[m1])) {
          struct RArray *ary = mrb_ary_ptr(stack[m1]);

          pp = ARY_PTR(ary);
          len = ARY_LEN(ary);
        }
        regs[a] = mrb_ary_new_capa(mrb, m1+len+m2+kd);
        rest = mrb_ary_ptr(regs[a]);
        if (m1 > 0) {
          stack_copy(ARY_PTR(rest), stack, m1);
        }
        if (len > 0) {
          stack_copy(ARY_PTR(rest)+m1, pp, len);
        }
        if (m2 > 0) {
          stack_copy(ARY_PTR(rest)+m1+len, stack+m1+1, m2);
        }
        if (kd) {
          stack_copy(ARY_PTR(rest)+m1+len+m2, stack+m1+m2+1, kd);
        }
        ARY_SET_LEN(rest, m1+len+m2+kd);
      }
      regs[a+1] = stack[m1+r+m2];
      mrb_gc_arena_restore(mrb, ai);
      NEXT;
    }

    CASE(OP_ENTER, W) {
      mrb_int m1 = MRB_ASPEC_REQ(a);
      mrb_int o  = MRB_ASPEC_OPT(a);
      mrb_int r  = MRB_ASPEC_REST(a);
      mrb_int m2 = MRB_ASPEC_POST(a);
      mrb_int kd = (MRB_ASPEC_KEY(a) > 0 || MRB_ASPEC_KDICT(a))? 1 : 0;
      /* unused
      int b  = MRB_ASPEC_BLOCK(a);
      */
      mrb_int argc = mrb->c->ci->argc;
      mrb_value *argv = regs+1;
      mrb_value * const argv0 = argv;
      mrb_int const len = m1 + o + r + m2;
      mrb_int const blk_pos = len + kd + 1;
      mrb_value *blk = &argv[argc < 0 ? 1 : argc];
      mrb_value kdict = mrb_nil_value();
      mrb_int kargs = kd;

      /* arguments is passed with Array */
      if (argc < 0) {
        struct RArray *ary = mrb_ary_ptr(regs[1]);
        argv = ARY_PTR(ary);
        argc = (int)ARY_LEN(ary);
        mrb_gc_protect(mrb, regs[1]);
      }

      /* strict argument check */
      if (mrb->c->ci->proc && MRB_PROC_STRICT_P(mrb->c->ci->proc)) {
        if (argc < m1 + m2 || (r == 0 && argc > len + kd)) {
          argnum_error(mrb, m1+m2);
          goto L_RAISE;
        }
      }
      /* extract first argument array to arguments */
      else if (len > 1 && argc == 1 && mrb_array_p(argv[0])) {
        mrb_gc_protect(mrb, argv[0]);
        argc = (int)RARRAY_LEN(argv[0]);
        argv = RARRAY_PTR(argv[0]);
      }

      if (kd) {
        /* check last arguments is hash if method takes keyword arguments */
        if (argc == m1+m2) {
          kdict = mrb_hash_new(mrb);
          kargs = 0;
        }
        else {
          if (argv && argc > 0 && mrb_hash_p(argv[argc-1])) {
            kdict = argv[argc-1];
            mrb_hash_check_kdict(mrb, kdict);
          }
          else if (r || argc <= m1+m2+o
                   || !(mrb->c->ci->proc && MRB_PROC_STRICT_P(mrb->c->ci->proc))) {
            kdict = mrb_hash_new(mrb);
            kargs = 0;
          }
          else {
            argnum_error(mrb, m1+m2);
            goto L_RAISE;
          }
          if (MRB_ASPEC_KEY(a) > 0) {
            kdict = mrb_hash_dup(mrb, kdict);
          }
        }
      }

      /* no rest arguments */
      if (argc-kargs < len) {
        mrb_int mlen = m2;
        if (argc < m1+m2) {
          mlen = m1 < argc ? argc - m1 : 0;
        }
        regs[blk_pos] = *blk; /* move block */
        if (kd) regs[len + 1] = kdict;

        /* copy mandatory and optional arguments */
        if (argv0 != argv && argv) {
          value_move(&regs[1], argv, argc-mlen); /* m1 + o */
        }
        if (argc < m1) {
          stack_clear(&regs[argc+1], m1-argc);
        }
        /* copy post mandatory arguments */
        if (mlen) {
          value_move(&regs[len-m2+1], &argv[argc-mlen], mlen);
        }
        if (mlen < m2) {
          stack_clear(&regs[len-m2+mlen+1], m2-mlen);
        }
        /* initialize rest arguments with empty Array */
        if (r) {
          regs[m1+o+1] = mrb_ary_new_capa(mrb, 0);
        }
        /* skip initializer of passed arguments */
        if (o > 0 && argc-kargs > m1+m2)
          pc += (argc - kargs - m1 - m2)*3;
      }
      else {
        mrb_int rnum = 0;
        if (argv0 != argv) {
          regs[blk_pos] = *blk; /* move block */
          if (kd) regs[len + 1] = kdict;
          value_move(&regs[1], argv, m1+o);
        }
        if (r) {
          mrb_value ary;

          rnum = argc-m1-o-m2-kargs;
          ary = mrb_ary_new_from_values(mrb, rnum, argv+m1+o);
          regs[m1+o+1] = ary;
        }
        if (m2) {
          if (argc-m2 > m1) {
            value_move(&regs[m1+o+r+1], &argv[m1+o+rnum], m2);
          }
        }
        if (argv0 == argv) {
          regs[blk_pos] = *blk; /* move block */
          if (kd) regs[len + 1] = kdict;
        }
        pc += o*3;
      }

      /* format arguments for generated code */
      mrb->c->ci->argc = (int16_t)(len + kd);

      /* clear local (but non-argument) variables */
      if (irep->nlocals-blk_pos-1 > 0) {
        stack_clear(&regs[blk_pos+1], irep->nlocals-blk_pos-1);
      }
      JUMP;
    }

    CASE(OP_KARG, BB) {
      mrb_value k = mrb_symbol_value(syms[b]);
      mrb_value kdict = regs[mrb->c->ci->argc];

      if (!mrb_hash_p(kdict) || !mrb_hash_key_p(mrb, kdict, k)) {
        mrb_value str = mrb_format(mrb, "missing keyword: %v", k);
        mrb_exc_set(mrb, mrb_exc_new_str(mrb, E_ARGUMENT_ERROR, str));
        goto L_RAISE;
      }
      regs[a] = mrb_hash_get(mrb, kdict, k);
      mrb_hash_delete_key(mrb, kdict, k);
      NEXT;
    }

    CASE(OP_KEY_P, BB) {
      mrb_value k = mrb_symbol_value(syms[b]);
      mrb_value kdict = regs[mrb->c->ci->argc];
      mrb_bool key_p = FALSE;

      if (mrb_hash_p(kdict)) {
        key_p = mrb_hash_key_p(mrb, kdict, k);
      }
      regs[a] = mrb_bool_value(key_p);
      NEXT;
    }

    CASE(OP_KEYEND, Z) {
      mrb_value kdict = regs[mrb->c->ci->argc];

      if (mrb_hash_p(kdict) && !mrb_hash_empty_p(mrb, kdict)) {
        mrb_value keys = mrb_hash_keys(mrb, kdict);
        mrb_value key1 = RARRAY_PTR(keys)[0];
        mrb_value str = mrb_format(mrb, "unknown keyword: %v", key1);
        mrb_exc_set(mrb, mrb_exc_new_str(mrb, E_ARGUMENT_ERROR, str));
        goto L_RAISE;
      }
      NEXT;
    }

    CASE(OP_BREAK, B) {
      c = OP_R_BREAK;
      goto L_RETURN;
    }
    CASE(OP_RETURN_BLK, B) {
      c = OP_R_RETURN;
      goto L_RETURN;
    }
    CASE(OP_RETURN, B)
    c = OP_R_NORMAL;
    L_RETURN:
    {
      mrb_callinfo *ci;

      ci = mrb->c->ci;
      if (ci->mid) {
        mrb_value blk;

        if (ci->argc < 0) {
          blk = regs[2];
        }
        else {
          blk = regs[ci->argc+1];
        }
        if (mrb_proc_p(blk)) {
          struct RProc *p = mrb_proc_ptr(blk);

          if (!MRB_PROC_STRICT_P(p) &&
              ci > mrb->c->cibase && MRB_PROC_ENV(p) == mrb_vm_ci_env(&ci[-1])) {
            p->flags |= MRB_PROC_ORPHAN;
          }
        }
      }

      if (mrb->exc) {
      L_RAISE:
        ci = mrb->c->ci;
        if (ci == mrb->c->cibase) {
          ch = catch_handler_find(mrb, ci, pc, MRB_CATCH_FILTER_ALL);
          if (ch == NULL) goto L_FTOP;
          goto L_CATCH;
        }
        while ((ch = catch_handler_find(mrb, ci, pc, MRB_CATCH_FILTER_ALL)) == NULL) {
          ci = cipop(mrb);
          if (ci[1].acc == CI_ACC_SKIP && prev_jmp) {
            mrb->jmp = prev_jmp;
            MRB_THROW(prev_jmp);
          }
          pc = ci[0].pc;
          if (ci == mrb->c->cibase) {
            ch = catch_handler_find(mrb, ci, pc, MRB_CATCH_FILTER_ALL);
            if (ch == NULL) {
            L_FTOP:             /* fiber top */
              if (mrb->c == mrb->root_c) {
                mrb->c->ci->stack = mrb->c->stbase;
                goto L_STOP;
              }
              else {
                struct mrb_context *c = mrb->c;

                c->status = MRB_FIBER_TERMINATED;
                mrb->c = c->prev;
                c->prev = NULL;
                goto L_RAISE;
              }
            }
            break;
          }
        }
      L_CATCH:
        if (ch == NULL) goto L_STOP;
        if (FALSE) {
        L_CATCH_TAGGED_BREAK: /* from THROW_TAGGED_BREAK() or UNWIND_ENSURE() */
          ci = mrb->c->ci;
        }
        proc = ci->proc;
        irep = proc->body.irep;
        pool = irep->pool;
        syms = irep->syms;
        mrb_stack_extend(mrb, irep->nregs);
        pc = irep->iseq + mrb_irep_catch_handler_unpack(ch->target);
      }
      else {
        mrb_int acc;
        mrb_value v;

        ci = mrb->c->ci;
        v = regs[a];
        mrb_gc_protect(mrb, v);
        switch (c) {
        case OP_R_RETURN:
          /* Fall through to OP_R_NORMAL otherwise */
          if (ci->acc >=0 && MRB_PROC_ENV_P(proc) && !MRB_PROC_STRICT_P(proc)) {
            const struct RProc *dst;
            mrb_callinfo *cibase;
            cibase = mrb->c->cibase;
            dst = top_proc(mrb, proc);

            if (MRB_PROC_ENV_P(dst)) {
              struct REnv *e = MRB_PROC_ENV(dst);

              if (!MRB_ENV_ONSTACK_P(e) || (e->cxt && e->cxt != mrb->c)) {
                localjump_error(mrb, LOCALJUMP_ERROR_RETURN);
                goto L_RAISE;
              }
            }
            /* check jump destination */
            while (cibase <= ci && ci->proc != dst) {
              if (ci->acc < 0) { /* jump cross C boudary */
                localjump_error(mrb, LOCALJUMP_ERROR_RETURN);
                goto L_RAISE;
              }
              ci--;
            }
            if (ci <= cibase) { /* no jump destination */
              localjump_error(mrb, LOCALJUMP_ERROR_RETURN);
              goto L_RAISE;
            }
            ci = mrb->c->ci;
            while (cibase <= ci && ci->proc != dst) {
              CHECKPOINT_RESTORE(RBREAK_TAG_RETURN_BLOCK) {
                cibase = mrb->c->cibase;
                dst = top_proc(mrb, proc);
              }
              CHECKPOINT_MAIN(RBREAK_TAG_RETURN_BLOCK) {
                UNWIND_ENSURE(mrb, ci, pc, RBREAK_TAG_RETURN_BLOCK, proc, v);
              }
              CHECKPOINT_END(RBREAK_TAG_RETURN_BLOCK);
              ci = cipop(mrb);
              pc = ci->pc;
            }
            proc = ci->proc;
            mrb->exc = NULL; /* clear break object */
            break;
          }
          /* fallthrough */
        case OP_R_NORMAL:
        NORMAL_RETURN:
          if (ci == mrb->c->cibase) {
            struct mrb_context *c;
            c = mrb->c;

            if (!c->prev) { /* toplevel return */
              regs[irep->nlocals] = v;
              goto CHECKPOINT_LABEL_MAKE(RBREAK_TAG_STOP);
            }
            if (!c->vmexec && c->prev->ci == c->prev->cibase) {
              mrb_value exc = mrb_exc_new_lit(mrb, E_FIBER_ERROR, "double resume");
              mrb_exc_set(mrb, exc);
              goto L_RAISE;
            }
            CHECKPOINT_RESTORE(RBREAK_TAG_RETURN_TOPLEVEL) {
              c = mrb->c;
            }
            CHECKPOINT_MAIN(RBREAK_TAG_RETURN_TOPLEVEL) {
              UNWIND_ENSURE(mrb, ci, pc, RBREAK_TAG_RETURN_TOPLEVEL, proc, v);
            }
            CHECKPOINT_END(RBREAK_TAG_RETURN_TOPLEVEL);
            /* automatic yield at the end */
            c->status = MRB_FIBER_TERMINATED;
            mrb->c = c->prev;
            mrb->c->status = MRB_FIBER_RUNNING;
            c->prev = NULL;
            if (c->vmexec) {
              mrb_gc_arena_restore(mrb, ai);
              c->vmexec = FALSE;
              mrb->jmp = prev_jmp;
              return v;
            }
            ci = mrb->c->ci;
          }
          CHECKPOINT_RESTORE(RBREAK_TAG_RETURN) {
            /* do nothing */
          }
          CHECKPOINT_MAIN(RBREAK_TAG_RETURN) {
            UNWIND_ENSURE(mrb, ci, pc, RBREAK_TAG_RETURN, proc, v);
          }
          CHECKPOINT_END(RBREAK_TAG_RETURN);
          mrb->exc = NULL; /* clear break object */
          break;
        case OP_R_BREAK:
          if (MRB_PROC_STRICT_P(proc)) goto NORMAL_RETURN;
          if (MRB_PROC_ORPHAN_P(proc)) {
            mrb_value exc;

          L_BREAK_ERROR:
            exc = mrb_exc_new_lit(mrb, E_LOCALJUMP_ERROR,
                                      "break from proc-closure");
            mrb_exc_set(mrb, exc);
            goto L_RAISE;
          }
          if (!MRB_PROC_ENV_P(proc) || !MRB_ENV_ONSTACK_P(MRB_PROC_ENV(proc))) {
            goto L_BREAK_ERROR;
          }
          else {
            struct REnv *e = MRB_PROC_ENV(proc);

            if (e->cxt != mrb->c) {
              goto L_BREAK_ERROR;
            }
          }
          CHECKPOINT_RESTORE(RBREAK_TAG_BREAK) {
            /* do nothing */
          }
          CHECKPOINT_MAIN(RBREAK_TAG_BREAK) {
            UNWIND_ENSURE(mrb, ci, pc, RBREAK_TAG_BREAK, proc, v);
          }
          CHECKPOINT_END(RBREAK_TAG_BREAK);
          /* break from fiber block */
          if (ci == mrb->c->cibase && ci->pc) {
            struct mrb_context *c = mrb->c;

            mrb->c = c->prev;
            c->prev = NULL;
            ci = mrb->c->ci;
          }
          if (ci->acc < 0) {
            ci = cipop(mrb);
            mrb_gc_arena_restore(mrb, ai);
            mrb->c->vmexec = FALSE;
            mrb->exc = (struct RObject*)break_new(mrb, RBREAK_TAG_BREAK, proc, v);
            mrb->jmp = prev_jmp;
            MRB_THROW(prev_jmp);
          }
          if (FALSE) {
            struct RBreak *brk;

          L_BREAK:
            brk = (struct RBreak*)mrb->exc;
            proc = mrb_break_proc_get(brk);
            v = mrb_break_value_get(brk);
            ci = mrb->c->ci;

            switch (mrb_break_tag_get(brk)) {
#define DISPATCH_CHECKPOINTS(n, i) case n: goto CHECKPOINT_LABEL_MAKE(n);
              RBREAK_TAG_FOREACH(DISPATCH_CHECKPOINTS)
#undef DISPATCH_CHECKPOINTS
              default:
                mrb_assert(!"wrong break tag");
            }
          }
          while (mrb->c->cibase < ci && ci[-1].proc != proc->upper) {
            if (ci[-1].acc == CI_ACC_SKIP) {
              goto L_BREAK_ERROR;
            }
            CHECKPOINT_RESTORE(RBREAK_TAG_BREAK_UPPER) {
              /* do nothing */
            }
            CHECKPOINT_MAIN(RBREAK_TAG_BREAK_UPPER) {
              UNWIND_ENSURE(mrb, ci, pc, RBREAK_TAG_BREAK_UPPER, proc, v);
            }
            CHECKPOINT_END(RBREAK_TAG_BREAK_UPPER);
            ci = cipop(mrb);
            pc = ci->pc;
          }
          CHECKPOINT_RESTORE(RBREAK_TAG_BREAK_INTARGET) {
            /* do nothing */
          }
          CHECKPOINT_MAIN(RBREAK_TAG_BREAK_INTARGET) {
            UNWIND_ENSURE(mrb, ci, pc, RBREAK_TAG_BREAK_INTARGET, proc, v);
          }
          CHECKPOINT_END(RBREAK_TAG_BREAK_INTARGET);
          if (ci == mrb->c->cibase) {
            goto L_BREAK_ERROR;
          }
          mrb->exc = NULL; /* clear break object */
          break;
        default:
          /* cannot happen */
          break;
        }
        mrb_assert(ci == mrb->c->ci);
        mrb_assert(mrb->exc == NULL);

        if (mrb->c->vmexec && !mrb_vm_ci_target_class(ci)) {
          mrb_gc_arena_restore(mrb, ai);
          mrb->c->vmexec = FALSE;
          mrb->jmp = prev_jmp;
          return v;
        }
        acc = ci->acc;
        ci = cipop(mrb);
        if (acc == CI_ACC_SKIP || acc == CI_ACC_DIRECT) {
          mrb_gc_arena_restore(mrb, ai);
          mrb->jmp = prev_jmp;
          return v;
        }
        pc = ci[0].pc;
        DEBUG(fprintf(stderr, "from :%s\n", mrb_sym_name(mrb, ci->mid)));
        proc = mrb->c->ci->proc;
        irep = proc->body.irep;
        pool = irep->pool;
        syms = irep->syms;

        regs[acc] = v;
        mrb_gc_arena_restore(mrb, ai);
      }
      JUMP;
    }

    CASE(OP_BLKPUSH, BS) {
      int m1 = (b>>11)&0x3f;
      int r  = (b>>10)&0x1;
      int m2 = (b>>5)&0x1f;
      int kd = (b>>4)&0x1;
      int lv = (b>>0)&0xf;
      mrb_value *stack;

      if (lv == 0) stack = regs + 1;
      else {
        struct REnv *e = uvenv(mrb, lv-1);
        if (!e || (!MRB_ENV_ONSTACK_P(e) && e->mid == 0) ||
            MRB_ENV_LEN(e) <= m1+r+m2+1) {
          localjump_error(mrb, LOCALJUMP_ERROR_YIELD);
          goto L_RAISE;
        }
        stack = e->stack + 1;
      }
      if (mrb_nil_p(stack[m1+r+m2])) {
        localjump_error(mrb, LOCALJUMP_ERROR_YIELD);
        goto L_RAISE;
      }
      regs[a] = stack[m1+r+m2+kd];
      NEXT;
    }

  L_INT_OVERFLOW:
    {
      mrb_value exc = mrb_exc_new_lit(mrb, E_RANGE_ERROR, "integer overflow");
      mrb_exc_set(mrb, exc);
    }
    goto L_RAISE;

#define TYPES2(a,b) ((((uint16_t)(a))<<8)|(((uint16_t)(b))&0xff))
#define OP_MATH(op_name)                                                    \
  /* need to check if op is overridden */                                   \
  switch (TYPES2(mrb_type(regs[a]),mrb_type(regs[a+1]))) {                  \
    OP_MATH_CASE_INTEGER(op_name);                                          \
    OP_MATH_CASE_FLOAT(op_name, integer, float);                            \
    OP_MATH_CASE_FLOAT(op_name, float,  integer);                           \
    OP_MATH_CASE_FLOAT(op_name, float,  float);                             \
    OP_MATH_CASE_STRING_##op_name();                                        \
    default:                                                                \
      c = 1;                                                                \
      mid = MRB_OPSYM(op_name);                                             \
      goto L_SEND_SYM;                                                      \
  }                                                                         \
  NEXT;
#define OP_MATH_CASE_INTEGER(op_name)                                       \
  case TYPES2(MRB_TT_INTEGER, MRB_TT_INTEGER):                              \
    {                                                                       \
      mrb_int x = mrb_integer(regs[a]), y = mrb_integer(regs[a+1]), z;      \
      if (mrb_int_##op_name##_overflow(x, y, &z))                           \
        OP_MATH_OVERFLOW_INT();                                             \
      else                                                                  \
        SET_INT_VALUE(mrb,regs[a], z);                                      \
    }                                                                       \
    break
#ifdef MRB_NO_FLOAT
#define OP_MATH_CASE_FLOAT(op_name, t1, t2) (void)0
#else
#define OP_MATH_CASE_FLOAT(op_name, t1, t2)                                     \
  case TYPES2(OP_MATH_TT_##t1, OP_MATH_TT_##t2):                                \
    {                                                                           \
      mrb_float z = mrb_##t1(regs[a]) OP_MATH_OP_##op_name mrb_##t2(regs[a+1]); \
      SET_FLOAT_VALUE(mrb, regs[a], z);                                         \
    }                                                                           \
    break
#endif
#define OP_MATH_OVERFLOW_INT() goto L_INT_OVERFLOW
#define OP_MATH_CASE_STRING_add()                                           \
  case TYPES2(MRB_TT_STRING, MRB_TT_STRING):                                \
    regs[a] = mrb_str_plus(mrb, regs[a], regs[a+1]);                        \
    mrb_gc_arena_restore(mrb, ai);                                          \
    break
#define OP_MATH_CASE_STRING_sub() (void)0
#define OP_MATH_CASE_STRING_mul() (void)0
#define OP_MATH_OP_add +
#define OP_MATH_OP_sub -
#define OP_MATH_OP_mul *
#define OP_MATH_TT_integer MRB_TT_INTEGER
#define OP_MATH_TT_float   MRB_TT_FLOAT

    CASE(OP_ADD, B) {
      OP_MATH(add);
    }

    CASE(OP_SUB, B) {
      OP_MATH(sub);
    }

    CASE(OP_MUL, B) {
      OP_MATH(mul);
    }

    CASE(OP_DIV, B) {
      mrb_int mrb_num_div_int(mrb_state *mrb, mrb_int x, mrb_int y);
#ifndef MRB_NO_FLOAT
      mrb_float mrb_num_div_flo(mrb_state *mrb, mrb_float x, mrb_float y);
      mrb_float x, y, f;
#endif

      /* need to check if op is overridden */
      switch (TYPES2(mrb_type(regs[a]),mrb_type(regs[a+1]))) {
      case TYPES2(MRB_TT_INTEGER,MRB_TT_INTEGER):
        {
          mrb_int x = mrb_integer(regs[a]);
          mrb_int y = mrb_integer(regs[a+1]);
          mrb_int div = mrb_num_div_int(mrb, x, y);
          SET_INT_VALUE(mrb, regs[a], div);
        }
        NEXT;
#ifndef MRB_NO_FLOAT
      case TYPES2(MRB_TT_INTEGER,MRB_TT_FLOAT):
        x = (mrb_float)mrb_integer(regs[a]);
        y = mrb_float(regs[a+1]);
        break;
      case TYPES2(MRB_TT_FLOAT,MRB_TT_INTEGER):
        x = mrb_float(regs[a]);
        y = (mrb_float)mrb_integer(regs[a+1]);
        break;
      case TYPES2(MRB_TT_FLOAT,MRB_TT_FLOAT):
        x = mrb_float(regs[a]);
        y = mrb_float(regs[a+1]);
        break;
#endif
      default:
        c = 1;
        mid = MRB_OPSYM(div);
        goto L_SEND_SYM;
      }

#ifndef MRB_NO_FLOAT
      f = mrb_num_div_flo(mrb, x, y);
      SET_FLOAT_VALUE(mrb, regs[a], f);
#endif
      NEXT;
    }

#define OP_MATHI(op_name)                                                   \
  /* need to check if op is overridden */                                   \
  switch (mrb_type(regs[a])) {                                              \
    OP_MATHI_CASE_INTEGER(op_name);                                         \
    OP_MATHI_CASE_FLOAT(op_name);                                           \
    default:                                                                \
      SET_INT_VALUE(mrb,regs[a+1], b);                                      \
      c = 1;                                                                \
      mid = MRB_OPSYM(op_name);                                             \
      goto L_SEND_SYM;                                                      \
  }                                                                         \
  NEXT;
#define OP_MATHI_CASE_INTEGER(op_name)                                      \
  case MRB_TT_INTEGER:                                                      \
    {                                                                       \
      mrb_int x = mrb_integer(regs[a]), y = (mrb_int)b, z;                  \
      if (mrb_int_##op_name##_overflow(x, y, &z))                           \
        OP_MATH_OVERFLOW_INT();                                             \
      else                                                                  \
        SET_INT_VALUE(mrb,regs[a], z);                                      \
    }                                                                       \
    break
#ifdef MRB_NO_FLOAT
#define OP_MATHI_CASE_FLOAT(op_name) (void)0
#else
#define OP_MATHI_CASE_FLOAT(op_name)                                        \
  case MRB_TT_FLOAT:                                                        \
    {                                                                       \
      mrb_float z = mrb_float(regs[a]) OP_MATH_OP_##op_name b;              \
      SET_FLOAT_VALUE(mrb, regs[a], z);                                     \
    }                                                                       \
    break
#endif

    CASE(OP_ADDI, BB) {
      OP_MATHI(add);
    }

    CASE(OP_SUBI, BB) {
      OP_MATHI(sub);
    }

#define OP_CMP_BODY(op,v1,v2) (v1(regs[a]) op v2(regs[a+1]))

#ifdef MRB_NO_FLOAT
#define OP_CMP(op,sym) do {\
  int result;\
  /* need to check if - is overridden */\
  switch (TYPES2(mrb_type(regs[a]),mrb_type(regs[a+1]))) {\
  case TYPES2(MRB_TT_INTEGER,MRB_TT_INTEGER):\
    result = OP_CMP_BODY(op,mrb_fixnum,mrb_fixnum);\
    break;\
  default:\
    c = 1;\
    mid = MRB_OPSYM(sym);\
    goto L_SEND_SYM;\
  }\
  if (result) {\
    SET_TRUE_VALUE(regs[a]);\
  }\
  else {\
    SET_FALSE_VALUE(regs[a]);\
  }\
} while(0)
#else
#define OP_CMP(op, sym) do {\
  int result;\
  /* need to check if - is overridden */\
  switch (TYPES2(mrb_type(regs[a]),mrb_type(regs[a+1]))) {\
  case TYPES2(MRB_TT_INTEGER,MRB_TT_INTEGER):\
    result = OP_CMP_BODY(op,mrb_fixnum,mrb_fixnum);\
    break;\
  case TYPES2(MRB_TT_INTEGER,MRB_TT_FLOAT):\
    result = OP_CMP_BODY(op,mrb_fixnum,mrb_float);\
    break;\
  case TYPES2(MRB_TT_FLOAT,MRB_TT_INTEGER):\
    result = OP_CMP_BODY(op,mrb_float,mrb_fixnum);\
    break;\
  case TYPES2(MRB_TT_FLOAT,MRB_TT_FLOAT):\
    result = OP_CMP_BODY(op,mrb_float,mrb_float);\
    break;\
  default:\
    c = 1;\
    mid = MRB_OPSYM(sym);\
    goto L_SEND_SYM;\
  }\
  if (result) {\
    SET_TRUE_VALUE(regs[a]);\
  }\
  else {\
    SET_FALSE_VALUE(regs[a]);\
  }\
} while(0)
#endif

    CASE(OP_EQ, B) {
      if (mrb_obj_eq(mrb, regs[a], regs[a+1])) {
        SET_TRUE_VALUE(regs[a]);
      }
      else {
        OP_CMP(==,eq);
      }
      NEXT;
    }

    CASE(OP_LT, B) {
      OP_CMP(<,lt);
      NEXT;
    }

    CASE(OP_LE, B) {
      OP_CMP(<=,le);
      NEXT;
    }

    CASE(OP_GT, B) {
      OP_CMP(>,gt);
      NEXT;
    }

    CASE(OP_GE, B) {
      OP_CMP(>=,ge);
      NEXT;
    }

    CASE(OP_ARRAY, BB) {
      mrb_value v = mrb_ary_new_from_values(mrb, b, &regs[a]);
      regs[a] = v;
      mrb_gc_arena_restore(mrb, ai);
      NEXT;
    }
    CASE(OP_ARRAY2, BBB) {
      mrb_value v = mrb_ary_new_from_values(mrb, c, &regs[b]);
      regs[a] = v;
      mrb_gc_arena_restore(mrb, ai);
      NEXT;
    }

    CASE(OP_ARYCAT, B) {
      mrb_value splat = mrb_ary_splat(mrb, regs[a+1]);
      if (mrb_nil_p(regs[a])) {
        regs[a] = splat;
      }
      else {
        mrb_ary_concat(mrb, regs[a], splat);
      }
      mrb_gc_arena_restore(mrb, ai);
      NEXT;
    }

    CASE(OP_ARYPUSH, B) {
      mrb_ary_push(mrb, regs[a], regs[a+1]);
      NEXT;
    }

    CASE(OP_ARYDUP, B) {
      mrb_value ary = regs[a];
      if (mrb_array_p(ary)) {
        ary = mrb_ary_new_from_values(mrb, RARRAY_LEN(ary), RARRAY_PTR(ary));
      }
      else {
        ary = mrb_ary_new_from_values(mrb, 1, &ary);
      }
      regs[a] = ary;
      NEXT;
    }

    CASE(OP_AREF, BBB) {
      mrb_value v = regs[b];

      if (!mrb_array_p(v)) {
        if (c == 0) {
          regs[a] = v;
        }
        else {
          SET_NIL_VALUE(regs[a]);
        }
      }
      else {
        v = mrb_ary_ref(mrb, v, c);
        regs[a] = v;
      }
      NEXT;
    }

    CASE(OP_ASET, BBB) {
      mrb_ary_set(mrb, regs[b], c, regs[a]);
      NEXT;
    }

    CASE(OP_APOST, BBB) {
      mrb_value v = regs[a];
      int pre  = b;
      int post = c;
      struct RArray *ary;
      int len, idx;

      if (!mrb_array_p(v)) {
        v = mrb_ary_new_from_values(mrb, 1, &regs[a]);
      }
      ary = mrb_ary_ptr(v);
      len = (int)ARY_LEN(ary);
      if (len > pre + post) {
        v = mrb_ary_new_from_values(mrb, len - pre - post, ARY_PTR(ary)+pre);
        regs[a++] = v;
        while (post--) {
          regs[a++] = ARY_PTR(ary)[len-post-1];
        }
      }
      else {
        v = mrb_ary_new_capa(mrb, 0);
        regs[a++] = v;
        for (idx=0; idx+pre<len; idx++) {
          regs[a+idx] = ARY_PTR(ary)[pre+idx];
        }
        while (idx < post) {
          SET_NIL_VALUE(regs[a+idx]);
          idx++;
        }
      }
      mrb_gc_arena_restore(mrb, ai);
      NEXT;
    }

    CASE(OP_INTERN, B) {
      mrb_sym sym = mrb_intern_str(mrb, regs[a]);

      regs[a] = mrb_symbol_value(sym);
      mrb_gc_arena_restore(mrb, ai);
      NEXT;
    }

    CASE(OP_STRING16, BS) {
      goto op_string;
    }
    CASE(OP_STRING, BB) {
      size_t len;
    op_string:
      len = pool[b].tt >> 2;
      if (pool[b].tt & IREP_TT_SFLAG) {
        regs[a] = mrb_str_new_static(mrb, pool[b].u.str, len);
      }
      else {
        regs[a] = mrb_str_new(mrb, pool[b].u.str, len);
      }
      mrb_gc_arena_restore(mrb, ai);
      NEXT;
    }

    CASE(OP_STRCAT, B) {
      mrb_str_concat(mrb, regs[a], regs[a+1]);
      NEXT;
    }

    CASE(OP_HASH, BB) {
      mrb_value hash = mrb_hash_new_capa(mrb, b);
      int i;
      int lim = a+b*2;

      for (i=a; i<lim; i+=2) {
        mrb_hash_set(mrb, hash, regs[i], regs[i+1]);
      }
      regs[a] = hash;
      mrb_gc_arena_restore(mrb, ai);
      NEXT;
    }

    CASE(OP_HASHADD, BB) {
      mrb_value hash;
      int i;
      int lim = a+b*2+1;

      hash = mrb_ensure_hash_type(mrb, regs[a]);
      for (i=a+1; i<lim; i+=2) {
        mrb_hash_set(mrb, hash, regs[i], regs[i+1]);
      }
      mrb_gc_arena_restore(mrb, ai);
      NEXT;
    }
    CASE(OP_HASHCAT, B) {
      mrb_value hash = mrb_ensure_hash_type(mrb, regs[a]);

      mrb_hash_merge(mrb, hash, regs[a+1]);
      mrb_gc_arena_restore(mrb, ai);
      NEXT;
    }

    CASE(OP_LAMBDA, BB)
    c = OP_L_LAMBDA;
    L_MAKE_LAMBDA:
    {
      struct RProc *p;
      const mrb_irep *nirep = irep->reps[b];

      if (c & OP_L_CAPTURE) {
        p = mrb_closure_new(mrb, nirep);
      }
      else {
        p = mrb_proc_new(mrb, nirep);
        p->flags |= MRB_PROC_SCOPE;
      }
      if (c & OP_L_STRICT) p->flags |= MRB_PROC_STRICT;
      regs[a] = mrb_obj_value(p);
      mrb_gc_arena_restore(mrb, ai);
      NEXT;
    }
    CASE(OP_BLOCK, BB) {
      c = OP_L_BLOCK;
      goto L_MAKE_LAMBDA;
    }
    CASE(OP_METHOD, BB) {
      c = OP_L_METHOD;
      goto L_MAKE_LAMBDA;
    }
    CASE(OP_LAMBDA16, BS) {
      c = OP_L_LAMBDA;
      goto L_MAKE_LAMBDA;
    }
    CASE(OP_BLOCK16, BS) {
      c = OP_L_BLOCK;
      goto L_MAKE_LAMBDA;
    }
    CASE(OP_METHOD16, BS) {
      c = OP_L_METHOD;
      goto L_MAKE_LAMBDA;
    }

    CASE(OP_RANGE_INC, B) {
      mrb_value val = mrb_range_new(mrb, regs[a], regs[a+1], FALSE);
      regs[a] = val;
      mrb_gc_arena_restore(mrb, ai);
      NEXT;
    }

    CASE(OP_RANGE_EXC, B) {
      mrb_value val = mrb_range_new(mrb, regs[a], regs[a+1], TRUE);
      regs[a] = val;
      mrb_gc_arena_restore(mrb, ai);
      NEXT;
    }

    CASE(OP_OCLASS, B) {
      regs[a] = mrb_obj_value(mrb->object_class);
      NEXT;
    }

    CASE(OP_CLASS, BB) {
      struct RClass *c = 0, *baseclass;
      mrb_value base, super;
      mrb_sym id = syms[b];

      base = regs[a];
      super = regs[a+1];
      if (mrb_nil_p(base)) {
        baseclass = MRB_PROC_TARGET_CLASS(mrb->c->ci->proc);
        if (!baseclass) baseclass = mrb->object_class;
        base = mrb_obj_value(baseclass);
      }
      c = mrb_vm_define_class(mrb, base, super, id);
      regs[a] = mrb_obj_value(c);
      mrb_gc_arena_restore(mrb, ai);
      NEXT;
    }

    CASE(OP_MODULE, BB) {
      struct RClass *cls = 0, *baseclass;
      mrb_value base;
      mrb_sym id = syms[b];

      base = regs[a];
      if (mrb_nil_p(base)) {
        baseclass = MRB_PROC_TARGET_CLASS(mrb->c->ci->proc);
        if (!baseclass) baseclass = mrb->object_class;
        base = mrb_obj_value(baseclass);
      }
      cls = mrb_vm_define_module(mrb, base, id);
      regs[a] = mrb_obj_value(cls);
      mrb_gc_arena_restore(mrb, ai);
      NEXT;
    }

    CASE(OP_EXEC16, BS)
      goto L_EXEC;
    CASE(OP_EXEC, BB)
    L_EXEC:
    {
      mrb_value recv = regs[a];
      struct RProc *p;
      const mrb_irep *nirep = irep->reps[b];

      /* prepare closure */
      p = mrb_proc_new(mrb, nirep);
      p->c = NULL;
      mrb_field_write_barrier(mrb, (struct RBasic*)p, (struct RBasic*)proc);
      MRB_PROC_SET_TARGET_CLASS(p, mrb_class_ptr(recv));
      p->flags |= MRB_PROC_SCOPE;

      /* prepare call stack */
      cipush(mrb, a, a, mrb_class_ptr(recv), p, 0, 0);

      irep = p->body.irep;
      pool = irep->pool;
      syms = irep->syms;
      mrb_stack_extend(mrb, irep->nregs);
      stack_clear(regs+1, irep->nregs-1);
      pc = irep->iseq;
      JUMP;
    }

    CASE(OP_DEF, BB) {
      struct RClass *target = mrb_class_ptr(regs[a]);
      struct RProc *p = mrb_proc_ptr(regs[a+1]);
      mrb_method_t m;

      MRB_METHOD_FROM_PROC(m, p);
      mrb_define_method_raw(mrb, target, syms[b], m);
      mrb_gc_arena_restore(mrb, ai);
      NEXT;
    }

    CASE(OP_SCLASS, B) {
      regs[a] = mrb_singleton_class(mrb, regs[a]);
      mrb_gc_arena_restore(mrb, ai);
      NEXT;
    }

    CASE(OP_TCLASS, B) {
      if (!check_target_class(mrb)) goto L_RAISE;
      regs[a] = mrb_obj_value(mrb_vm_ci_target_class(mrb->c->ci));
      NEXT;
    }

    CASE(OP_ALIAS, BB) {
      struct RClass *target;

      if (!check_target_class(mrb)) goto L_RAISE;
      target = mrb_vm_ci_target_class(mrb->c->ci);
      mrb_alias_method(mrb, target, syms[a], syms[b]);
      NEXT;
    }
    CASE(OP_UNDEF, B) {
      struct RClass *target;

      if (!check_target_class(mrb)) goto L_RAISE;
      target = mrb_vm_ci_target_class(mrb->c->ci);
      mrb_undef_method_id(mrb, target, syms[a]);
      NEXT;
    }

    CASE(OP_DEBUG, Z) {
      FETCH_BBB();
#ifdef MRB_USE_DEBUG_HOOK
      mrb->debug_op_hook(mrb, irep, pc, regs);
#else
#ifndef MRB_NO_STDIO
      printf("OP_DEBUG %d %d %d\n", a, b, c);
#else
      abort();
#endif
#endif
      NEXT;
    }

    CASE(OP_ERR, B) {
      size_t len = pool[a].tt >> 2;
      mrb_value exc;

      mrb_assert((pool[a].tt&IREP_TT_NFLAG)==0);
      exc = mrb_exc_new(mrb, E_LOCALJUMP_ERROR, pool[a].u.str, len);
      mrb_exc_set(mrb, exc);
      goto L_RAISE;
    }

    CASE(OP_SENDVK, BB) {       /* not yet implemented */
      NEXT;
    }

    CASE(OP_STOP, Z) {
      /*        stop VM */
      CHECKPOINT_RESTORE(RBREAK_TAG_STOP) {
        /* do nothing */
      }
      CHECKPOINT_MAIN(RBREAK_TAG_STOP) {
        UNWIND_ENSURE(mrb, mrb->c->ci, pc, RBREAK_TAG_STOP, proc, mrb_nil_value());
      }
      CHECKPOINT_END(RBREAK_TAG_STOP);
    L_STOP:
      mrb->jmp = prev_jmp;
      if (mrb->exc) {
        mrb_assert(mrb->exc->tt == MRB_TT_EXCEPTION);
        return mrb_obj_value(mrb->exc);
      }
      return regs[irep->nlocals];
    }
  }
  END_DISPATCH;
#undef regs
  }
  MRB_CATCH(&c_jmp) {
    mrb_callinfo *ci = mrb->c->ci;
    while (ci > mrb->c->cibase && ci->acc == CI_ACC_DIRECT) {
      ci = cipop(mrb);
    }
    exc_catched = TRUE;
    pc = ci->pc;
    goto RETRY_TRY_BLOCK;
  }
  MRB_END_EXC(&c_jmp);
}

static mrb_value
mrb_run(mrb_state *mrb, const struct RProc *proc, mrb_value self)
{
  if (mrb->c->ci->argc < 0) {
    return mrb_vm_run(mrb, proc, self, 3); /* receiver, args and block) */
  }
  else {
    return mrb_vm_run(mrb, proc, self, mrb->c->ci->argc + 2); /* argc + 2 (receiver and block) */
  }
}

MRB_API mrb_value
mrb_top_run(mrb_state *mrb, const struct RProc *proc, mrb_value self, mrb_int stack_keep)
{
  mrb_value v;

  if (!mrb->c->cibase) {
    return mrb_vm_run(mrb, proc, self, stack_keep);
  }
  if (mrb->c->ci == mrb->c->cibase) {
    mrb_vm_ci_env_set(mrb->c->ci, NULL);
    return mrb_vm_run(mrb, proc, self, stack_keep);
  }
  cipush(mrb, 0, CI_ACC_SKIP, mrb->object_class, NULL, 0, 0);
  v = mrb_vm_run(mrb, proc, self, stack_keep);

  return v;
}

#if defined(MRB_USE_CXX_EXCEPTION) && defined(__cplusplus)
# if !defined(MRB_USE_CXX_ABI)
} /* end of extern "C" */
# endif
mrb_int mrb_jmpbuf::jmpbuf_id = 0;
# if !defined(MRB_USE_CXX_ABI)
extern "C" {
# endif
#endif
