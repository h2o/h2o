/*
** vm.c - virtual machine for mruby
**
** See Copyright Notice in mruby.h
*/

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

/* Maximum recursive depth. Should be set lower on memory constrained systems. */
#ifndef MRB_CALL_LEVEL_MAX
#define MRB_CALL_LEVEL_MAX 512
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

  mrb->gc.arena_idx = idx;
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
#define mrb_gc_arena_shrink(mrb,idx) mrb_gc_arena_restore(mrb,idx)
#endif

#define CALL_MAXARGS 15
#define CALL_VARARGS (CALL_MAXARGS<<4 | CALL_MAXARGS)

void mrb_method_missing(mrb_state *mrb, mrb_sym name, mrb_value self, mrb_value args);

static inline void
stack_clear(mrb_value *from, size_t count)
{
  while (count-- > 0) {
    SET_NIL_VALUE(*from);
    from++;
  }
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

#define CINFO_NONE    0
#define CINFO_SKIP    1
#define CINFO_DIRECT  2
#define CINFO_RESUMED 3

static inline mrb_callinfo*
cipush(mrb_state *mrb, mrb_int push_stacks, uint8_t cci,
       struct RClass *target_class, const struct RProc *proc, mrb_sym mid, uint8_t argc)
{
  struct mrb_context *c = mrb->c;
  mrb_callinfo *ci = c->ci;

  if (ci + 1 == c->ciend) {
    ptrdiff_t size = ci - c->cibase;

    if (size > MRB_CALL_LEVEL_MAX) {
      mrb_exc_raise(mrb, mrb_obj_value(mrb->stack_err));
    }
    c->cibase = (mrb_callinfo *)mrb_realloc(mrb, c->cibase, sizeof(mrb_callinfo)*size*2);
    c->ci = c->cibase + size;
    c->ciend = c->cibase + size * 2;
  }
  ci = ++c->ci;
  ci->mid = mid;
  mrb_vm_ci_proc_set(ci, proc);
  ci->stack = ci[-1].stack + push_stacks;
  ci->n = argc & 0xf;
  ci->nk = (argc>>4) & 0xf;
  ci->cci = cci;
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

MRB_API mrb_value
mrb_protect_error(mrb_state *mrb, mrb_protect_error_func *body, void *userdata, mrb_bool *error)
{
  struct mrb_jmpbuf *prev_jmp = mrb->jmp;
  struct mrb_jmpbuf c_jmp;
  mrb_value result = mrb_nil_value();
  int ai = mrb_gc_arena_save(mrb);
  const struct mrb_context *c = mrb->c;
  ptrdiff_t ci_index = c->ci - c->cibase;

  if (error) { *error = FALSE; }

  MRB_TRY(&c_jmp) {
    mrb->jmp = &c_jmp;
    result = body(mrb, userdata);
    mrb->jmp = prev_jmp;
  }
  MRB_CATCH(&c_jmp) {
    mrb->jmp = prev_jmp;
    result = mrb_obj_value(mrb->exc);
    mrb->exc = NULL;
    if (error) { *error = TRUE; }
    if (mrb->c == c) {
      while (c->ci - c->cibase > ci_index) {
        cipop(mrb);
      }
    }
    else {
      // It was probably switched by mrb_fiber_resume().
      // Simply destroy all successive CINFO_DIRECTs once the fiber has been switched.
      c = mrb->c;
      while (c->ci > c->cibase && c->ci->cci == CINFO_DIRECT) {
        cipop(mrb);
      }
    }
  }
  MRB_END_EXC(&c_jmp);

  mrb_gc_arena_restore(mrb, ai);
  mrb_gc_protect(mrb, result);
  return result;
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
mrb_ci_kidx(const mrb_callinfo *ci)
{
  return (ci->n == CALL_MAXARGS) ? 2 : ci->n + 1;
}

static mrb_int
mrb_bidx(uint16_t c)
{
  uint8_t n = c & 0xf;
  uint8_t k = (c>>4) & 0xf;
  if (n == 15) n = 1;
  if (k == 15) n += 1;
  else n += k*2;
  return n + 1;                 /* self + args + kargs */
}

mrb_int
mrb_ci_bidx(mrb_callinfo *ci)
{
  return mrb_bidx(ci->n|(ci->nk<<4));
}

mrb_int
mrb_ci_nregs(mrb_callinfo *ci)
{
  const struct RProc *p;

  if (!ci) return 4;
  uint8_t nregs = mrb_ci_bidx(ci) + 1; /* self + args + kargs + blk */
  p = ci->proc;
  if (p && !MRB_PROC_CFUNC_P(p) && p->body.irep && p->body.irep->nregs > nregs) {
    return p->body.irep->nregs;
  }
  return nregs;
}

mrb_value mrb_obj_missing(mrb_state *mrb, mrb_value mod);

static mrb_method_t
prepare_missing(mrb_state *mrb, mrb_value recv, mrb_sym mid, struct RClass **clsp, uint32_t a, uint16_t *c, mrb_value blk, int super)
{
  mrb_sym missing = MRB_SYM(method_missing);
  mrb_callinfo *ci = mrb->c->ci;
  uint16_t b = *c;
  mrb_int n = b & 0xf;
  mrb_int nk = (b>>4) & 0xf;
  mrb_value *argv = &ci->stack[a+1];
  mrb_value args;
  mrb_method_t m;

  /* pack positional arguments */
  if (n == 15) args = argv[0];
  else args = mrb_ary_new_from_values(mrb, n, argv);

  if (mrb_func_basic_p(mrb, recv, missing, mrb_obj_missing)) {
  method_missing:
    if (super) mrb_no_method_error(mrb, mid, args, "no superclass method '%n'", mid);
    else mrb_method_missing(mrb, mid, recv, args);
    /* not reached */
  }
  if (mid != missing) {
    *clsp = mrb_class(mrb, recv);
  }
  m = mrb_method_search_vm(mrb, clsp, missing);
  if (MRB_METHOD_UNDEF_P(m)) goto method_missing; /* just in case */
  mrb_stack_extend(mrb, a+4);

  argv = &ci->stack[a+1];       /* maybe reallocated */
  argv[0] = args;
  if (nk == 0) {
    argv[1] = blk;
  }
  else {
    mrb_assert(nk == 15);
    argv[1] = argv[n];
    argv[2] = blk;
  }
  *c = 15 | (nk<<4);
  mrb_ary_unshift(mrb, args, mrb_symbol_value(mid));
  return m;
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
    mrb_callinfo *ci = mrb->c->ci;
    mrb_int n = mrb_ci_nregs(ci);
    ptrdiff_t voff = -1;

    if (!mrb->c->stbase) {
      stack_init(mrb);
    }
    if (ci - mrb->c->cibase > MRB_CALL_LEVEL_MAX) {
      mrb_exc_raise(mrb, mrb_obj_value(mrb->stack_err));
    }
    if (mrb->c->stbase <= argv && argv < mrb->c->stend) {
      voff = argv - mrb->c->stbase;
    }
    if (argc < 0) {
      mrb_raisef(mrb, E_ARGUMENT_ERROR, "negative argc for funcall (%i)", argc);
    }
    c = mrb_class(mrb, self);
    m = mrb_method_search_vm(mrb, &c, mid);
    mrb_stack_extend(mrb, n + argc + 3);
    if (argc >= 15) {
      ci->stack[n+1] = mrb_ary_new_from_values(mrb, argc, argv);
      argc = 15;
    }
    if (MRB_METHOD_UNDEF_P(m)) {
      uint16_t ac = (uint16_t)argc;
      m = prepare_missing(mrb, self, mid, &c, n, &ac, mrb_nil_value(), 0);
      argc = (mrb_int)ac;
      mid = MRB_SYM(method_missing);
    }
    ci = cipush(mrb, n, 0, c, NULL, mid, argc);
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
    ci->stack[0] = self;
    if (argc < 15) {
      if (argc > 0)
        stack_copy(ci->stack+1, argv, argc);
      ci->stack[argc+1] = blk;
    }
    else {
      ci->stack[2] = blk;
    }

    if (MRB_METHOD_CFUNC_P(m)) {
      ci->cci = CINFO_DIRECT;
      val = MRB_METHOD_CFUNC(m)(mrb, self);
      cipop(mrb);
    }
    else {
      ci->cci = CINFO_SKIP;
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

static void
check_method_noarg(mrb_state *mrb, const mrb_callinfo *ci)
{
  int argc = ci->n == CALL_MAXARGS ? RARRAY_LEN(ci->stack[1]) : ci->n;
  if (ci->nk > 0) {
    mrb_value kdict = ci->stack[mrb_ci_kidx(ci)];
    if (!(mrb_hash_p(kdict) && mrb_hash_empty_p(mrb, kdict))) {
      argc++;
    }
  }
  if (argc > 0) {
    mrb_argnum_error(mrb, argc, 0, 0);
  }
}

static mrb_value
exec_irep(mrb_state *mrb, mrb_value self, struct RProc *p)
{
  mrb_callinfo *ci = mrb->c->ci;
  int keep, nregs;

  ci->stack[0] = self;
  mrb_vm_ci_proc_set(ci, p);
  if (MRB_PROC_CFUNC_P(p)) {
    if (MRB_PROC_NOARG_P(p)) {
      check_method_noarg(mrb, ci);
    }
    return MRB_PROC_CFUNC(p)(mrb, self);
  }
  nregs = p->body.irep->nregs;
  keep = mrb_ci_bidx(ci)+1;
  if (nregs < keep) {
    mrb_stack_extend(mrb, keep);
  }
  else {
    mrb_stack_extend(mrb, nregs);
    stack_clear(ci->stack+keep, nregs-keep);
  }

  cipush(mrb, 0, 0, NULL, NULL, 0, 0);

  return self;
}

mrb_value
mrb_exec_irep(mrb_state *mrb, mrb_value self, struct RProc *p)
{
  mrb_callinfo *ci = mrb->c->ci;
  if (ci->cci == CINFO_NONE) {
    return exec_irep(mrb, self, p);
  }
  else {
    mrb_value ret;
    if (MRB_PROC_CFUNC_P(p)) {
      if (MRB_PROC_NOARG_P(p)) {
        check_method_noarg(mrb, ci);
      }
      cipush(mrb, 0, CINFO_DIRECT, mrb_vm_ci_target_class(ci), p, ci->mid, ci->n|(ci->nk<<4));
      ret = MRB_PROC_CFUNC(p)(mrb, self);
      cipop(mrb);
    }
    else {
      int keep = mrb_ci_bidx(ci) + 1; /* receiver + block */
      ret = mrb_top_run(mrb, p, self, keep);
    }
    if (mrb->exc && mrb->jmp) {
      mrb_exc_raise(mrb, mrb_obj_value(mrb->exc));
    }
    return ret;
  }
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
  mrb_method_t m;
  struct RClass *c;
  mrb_callinfo *ci = mrb->c->ci;
  int n = ci->n;

  if (ci->cci > CINFO_NONE) {
  funcall:;
    const mrb_value *argv;
    mrb_int argc;
    mrb_get_args(mrb, "n*&", &name, &argv, &argc, &block);
    return mrb_funcall_with_block(mrb, self, name, argc, argv, block);
  }

  regs = mrb->c->ci->stack+1;

  if (n == 0) {
  argnum_error:
    mrb_argnum_error(mrb, 0, 1, -1);
  }
  else if (n == 15) {
    if (RARRAY_LEN(regs[0]) == 0) goto argnum_error;
    name = mrb_obj_to_sym(mrb, RARRAY_PTR(regs[0])[0]);
  }
  else {
    name = mrb_obj_to_sym(mrb, regs[0]);
  }

  c = mrb_class(mrb, self);
  m = mrb_method_search_vm(mrb, &c, name);
  if (MRB_METHOD_UNDEF_P(m)) {            /* call method_mising */
    goto funcall;
  }

  ci->mid = name;
  ci->u.target_class = c;
  /* remove first symbol from arguments */
  if (n == 15) {     /* variable length arguments */
    regs[0] = mrb_ary_subseq(mrb, regs[0], 1, RARRAY_LEN(regs[0]) - 1);
  }
  else { /* n > 0 */
    for (int i=0; i<n; i++) {
      regs[i] = regs[i+1];
    }
    regs[n] = regs[n+1];        /* copy kdict or block */
    if (ci->nk > 0) {
      regs[n+1] = regs[n+2];    /* copy block */
    }
    ci->n--;
  }

  if (MRB_METHOD_CFUNC_P(m)) {
    if (MRB_METHOD_NOARG_P(m)) {
      check_method_noarg(mrb, ci);
    }

    if (MRB_METHOD_PROC_P(m)) {
      mrb_vm_ci_proc_set(ci, MRB_METHOD_PROC(m));
    }
    return MRB_METHOD_CFUNC(m)(mrb, self);
  }
  return exec_irep(mrb, self, MRB_METHOD_PROC(m));
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
  if (ci->cci == CINFO_DIRECT) {
    return mrb_yield_with_class(mrb, blk, 1, &self, self, c);
  }
  ci->u.target_class = c;
  p = mrb_proc_ptr(blk);
  mrb_vm_ci_proc_set(ci, p);
  ci->n = 1;
  ci->nk = 0;
  ci->mid = ci[-1].mid;
  if (MRB_PROC_CFUNC_P(p)) {
    mrb_stack_extend(mrb, 4);
    mrb->c->ci->stack[0] = self;
    mrb->c->ci->stack[1] = self;
    mrb->c->ci->stack[2] = mrb_nil_value();
    return MRB_PROC_CFUNC(p)(mrb, self);
  }
  nregs = p->body.irep->nregs;
  if (nregs < 4) nregs = 4;
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
  n = mrb_ci_nregs(ci);
  p = mrb_proc_ptr(b);
  ci = cipush(mrb, n, CINFO_SKIP, c, p, mid, 0 /* dummy */);
  ci->nk = 0;
  if (argc >= CALL_MAXARGS) {
    ci->n = 15;
    n = 3;
  }
  else {
    ci->n = argc;
    n = argc + 2;
  }
  mrb_stack_extend(mrb, n);
  mrb->c->ci->stack[0] = self;
  if (ci->n == 15) {
    mrb->c->ci->stack[1] = mrb_ary_new_from_values(mrb, argc, argv);
    argc = 1;
  }
  else if (argc > 0) {
    stack_copy(mrb->c->ci->stack+1, argv, argc);
  }
  mrb->c->ci->stack[argc+1] = mrb_nil_value(); /* clear blk */

  if (MRB_PROC_CFUNC_P(p)) {
    ci->cci = CINFO_DIRECT;
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

  mrb_stack_extend(mrb, 4);
  mrb->c->ci->stack[1] = mrb_ary_new_from_values(mrb, argc, argv);
  mrb->c->ci->stack[2] = mrb_nil_value();
  mrb->c->ci->stack[3] = mrb_nil_value();
  ci->n = 15;
  ci->nk = 0;
  return exec_irep(mrb, self, p);
}

static struct RBreak*
break_new(mrb_state *mrb, uint32_t tag, const struct RProc *p, mrb_value val)
{
  struct RBreak *brk;

  brk = MRB_OBJ_ALLOC(mrb, MRB_TT_BREAK, NULL);
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
  mrb_int argc = mrb->c->ci->n;

  if (argc == 15) {
    mrb_value args = mrb->c->ci->stack[1];
    if (mrb_array_p(args)) {
      argc = RARRAY_LEN(args);
    }
  }
  if (argc == 0 && mrb->c->ci->nk != 0 && !mrb_hash_empty_p(mrb, mrb->c->ci->stack[1])) {
    argc++;
  }
  str = mrb_format(mrb, "wrong number of arguments (given %i, expected %i)", argc, num);
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
#define CASE(insn,ops) case insn: pc++; FETCH_ ## ops (); mrb->c->ci->pc = pc; L_ ## insn ## _BODY:
#define NEXT goto L_END_DISPATCH
#define JUMP NEXT
#define END_DISPATCH L_END_DISPATCH:;}}

#else

#define INIT_DISPATCH JUMP; return mrb_nil_value();
#define CASE(insn,ops) L_ ## insn: pc++; FETCH_ ## ops (); mrb->c->ci->pc = pc; L_ ## insn ## _BODY:
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

static struct RClass*
check_target_class(mrb_state *mrb)
{
  struct RClass *target = mrb_vm_ci_target_class(mrb->c->ci);
  if (!target) {
    mrb_value exc = mrb_exc_new_lit(mrb, E_TYPE_ERROR, "no target class or module");
    mrb_exc_set(mrb, exc);
  }
  return target;
}

static mrb_value
hash_new_from_values(mrb_state *mrb, mrb_int argc, mrb_value *regs)
{
  mrb_value hash = mrb_hash_new_capa(mrb, argc);
  while (argc--) {
    mrb_hash_set(mrb, hash, regs[0], regs[1]);
    regs += 2;
  }
  return hash;
}

void mrb_method_added(mrb_state *mrb, struct RClass *c, mrb_sym mid);
mrb_value mrb_str_aref(mrb_state *mrb, mrb_value str, mrb_value idx, mrb_value len);

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
  static const void * const optable[] = {
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

    CASE(OP_LOADL, BB) {
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
      case IREP_TT_BIGINT:
        goto L_INT_OVERFLOW;
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

    CASE(OP_GETIDX, B) {
      mrb_value va = regs[a], vb = regs[a+1];
      switch (mrb_type(va)) {
      case MRB_TT_ARRAY:
        if (!mrb_integer_p(vb)) goto getidx_fallback;
        regs[a] = mrb_ary_entry(va, mrb_integer(vb));
        break;
      case MRB_TT_HASH:
        va = mrb_hash_get(mrb, va, vb);
        regs[a] = va;
        break;
      case MRB_TT_STRING:
        switch (mrb_type(vb)) {
        case MRB_TT_INTEGER:
        case MRB_TT_STRING:
        case MRB_TT_RANGE:
          va = mrb_str_aref(mrb, va, vb, mrb_undef_value());
          regs[a] = va;
          break;
        default:
          goto getidx_fallback;
        }
        break;
      default:
      getidx_fallback:
        mid = MRB_OPSYM(aref);
        goto L_SEND_SYM;
      }
      NEXT;
    }

    CASE(OP_SETIDX, B) {
      c = 2;
      mid = MRB_OPSYM(aset);
      SET_NIL_VALUE(regs[a+3]);
      goto L_SENDB_SYM;
    }

    CASE(OP_GETCONST, BB) {
      mrb_value v = mrb_vm_const_get(mrb, syms[b]);
      regs[a] = v;
      NEXT;
    }

    CASE(OP_SETCONST, BB) {
      mrb_vm_const_set(mrb, syms[b], regs[a]);
      NEXT;
    }

    CASE(OP_GETMCNST, BB) {
      mrb_value v = mrb_const_get(mrb, regs[a], syms[b]);
      regs[a] = v;
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

    CASE(OP_SSEND, BBB) {
      regs[a] = regs[0];
      insn = OP_SEND;
    }
    goto L_SENDB;

    CASE(OP_SSENDB, BBB) {
      regs[a] = regs[0];
    }
    goto L_SENDB;

    CASE(OP_SEND, BBB)
    goto L_SENDB;

    L_SEND_SYM:
    c = 1;
    /* push nil after arguments */
    SET_NIL_VALUE(regs[a+2]);
    goto L_SENDB_SYM;

    CASE(OP_SENDB, BBB)
    L_SENDB:
    mid = syms[b];
    L_SENDB_SYM:
    {
      int n = c&0xf;
      int nk = (c>>4)&0xf;
      mrb_callinfo *ci = mrb->c->ci;
      mrb_int bidx = a + mrb_bidx(c);
      mrb_method_t m;
      struct RClass *cls;
      mrb_value recv;

      if (0 < nk && nk < 15) {  /* pack keyword arguments */
        mrb_int kidx = a+(n==15?1:n)+1;
        mrb_value kdict = hash_new_from_values(mrb, nk, regs+kidx);
        regs[kidx] = kdict;
        nk = 15;
        c = n | (nk<<4);
      }

      mrb_assert(bidx < irep->nregs+a);
      mrb_value blk;
      mrb_int new_bidx = a+mrb_bidx(c);
      if (insn == OP_SEND) {
        /* clear block argument */
        SET_NIL_VALUE(regs[new_bidx]);
        SET_NIL_VALUE(blk);
      }
      else {
        blk = regs[bidx];
        if (!mrb_nil_p(blk) && !mrb_proc_p(blk)) {
          blk = mrb_type_convert(mrb, blk, MRB_TT_PROC, MRB_SYM(to_proc));
          /* The stack might have been reallocated during mrb_type_convert(),
             see #3622 */
        }
        regs[new_bidx] = blk;
      }

      recv = regs[a];
      cls = mrb_class(mrb, recv);
      m = mrb_method_search_vm(mrb, &cls, mid);
      if (MRB_METHOD_UNDEF_P(m)) {
        m = prepare_missing(mrb, recv, mid, &cls, a, &c, blk, 0);
        mid = MRB_SYM(method_missing);
      }

      /* push callinfo */
      ci = cipush(mrb, a, 0, cls, NULL, mid, c);

      if (MRB_METHOD_CFUNC_P(m)) {
        if (MRB_METHOD_PROC_P(m)) {
          struct RProc *p = MRB_METHOD_PROC(m);

          mrb_vm_ci_proc_set(ci, p);
          recv = p->body.func(mrb, recv);
        }
        else {
          if (MRB_METHOD_NOARG_P(m)) {
            check_method_noarg(mrb, ci);
          }
          recv = MRB_METHOD_FUNC(m)(mrb, recv);
        }
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
          if (ci->cci == CINFO_RESUMED) {
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
        ci->stack[0] = recv;
        /* pop stackpos */
        ci = cipop(mrb);
        pc = ci->pc;
      }
      else {
        /* setup environment for calling method */
        mrb_vm_ci_proc_set(ci, (proc = MRB_METHOD_PROC(m)));
        irep = proc->body.irep;
        pool = irep->pool;
        syms = irep->syms;
        mrb_stack_extend(mrb, (irep->nregs < 4) ? 4 : irep->nregs);
        pc = irep->iseq;
      }
    }
    JUMP;

    CASE(OP_CALL, Z) {
      mrb_callinfo *ci = mrb->c->ci;
      mrb_value recv = ci->stack[0];
      struct RProc *m = mrb_proc_ptr(recv);

      /* replace callinfo */
      ci->u.target_class = MRB_PROC_TARGET_CLASS(m);
      mrb_vm_ci_proc_set(ci, m);
      if (MRB_PROC_ENV_P(m)) {
        ci->mid = MRB_PROC_ENV(m)->mid;
      }

      /* prepare stack */
      if (MRB_PROC_CFUNC_P(m)) {
        recv = MRB_PROC_CFUNC(m)(mrb, recv);
        mrb_gc_arena_shrink(mrb, ai);
        if (mrb->exc) goto L_RAISE;
        /* pop stackpos */
        ci = cipop(mrb);
        pc = ci->pc;
        ci[1].stack[0] = recv;
        irep = mrb->c->ci->proc->body.irep;
      }
      else {
        /* setup environment for calling method */
        proc = m;
        irep = m->body.irep;
        if (!irep) {
          mrb->c->ci->stack[0] = mrb_nil_value();
          a = 0;
          c = OP_R_NORMAL;
          goto L_OP_RETURN_BODY;
        }
        mrb_int nargs = mrb_ci_bidx(ci)+1;
        if (nargs < irep->nregs) {
          mrb_stack_extend(mrb, irep->nregs);
          stack_clear(regs+nargs, irep->nregs-nargs);
        }
        if (MRB_PROC_ENV_P(m)) {
          regs[0] = MRB_PROC_ENV(m)->stack[0];
        }
        pc = irep->iseq;
      }
      pool = irep->pool;
      syms = irep->syms;
      JUMP;
    }

    CASE(OP_SUPER, BB) {
      mrb_method_t m;
      struct RClass *cls;
      mrb_callinfo *ci = mrb->c->ci;
      mrb_int bidx = mrb_bidx(b)+a;
      mrb_value recv, blk;
      const struct RProc *p = ci->proc;
      mrb_sym mid = ci->mid;
      struct RClass* target_class = MRB_PROC_TARGET_CLASS(p);

      if (MRB_PROC_ENV_P(p) && p->e.env->mid && p->e.env->mid != mid) { /* alias support */
        mid = p->e.env->mid;    /* restore old mid */
      }
      mrb_assert(bidx < irep->nregs);

      blk = regs[bidx];
      uint8_t nk = (b >> 4) & 0x0f;
      if (nk > 0 && nk < CALL_MAXARGS) {  /* pack keyword arguments */
        uint8_t n = b & 0x0f;
        mrb_int kidx = a+(n==15?1:n)+1;
        mrb_value kdict = hash_new_from_values(mrb, nk, regs+kidx);
        regs[kidx] = kdict;
        nk = 15;
        b = n | (nk<<4);
        bidx = kidx + 1;
        regs[bidx] = blk;
      }

      if (mid == 0 || !target_class) {
        mrb_value exc = mrb_exc_new_lit(mrb, E_NOMETHOD_ERROR, "super called outside of method");
        mrb_exc_set(mrb, exc);
        goto L_RAISE;
      }
      if ((target_class->flags & MRB_FL_CLASS_IS_PREPENDED) || target_class->tt == MRB_TT_MODULE) {
        target_class = mrb_vm_ci_target_class(ci);
        if (!target_class || target_class->tt != MRB_TT_ICLASS) {
          goto super_typeerror;
        }
      }
      recv = regs[0];
      if (!mrb_obj_is_kind_of(mrb, recv, target_class)) {
      super_typeerror: ;
        mrb_value exc = mrb_exc_new_lit(mrb, E_TYPE_ERROR,
                                            "self has wrong type to call super in this context");
        mrb_exc_set(mrb, exc);
        goto L_RAISE;
      }
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
        m = prepare_missing(mrb, recv, mid, &cls, a, &b, blk, 1);
        mid = MRB_SYM(method_missing);
      }

      /* push callinfo */
      ci = cipush(mrb, a, 0, cls, NULL, mid, b);

      /* prepare stack */
      ci->stack[0] = recv;

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
          if (ci->cci == CINFO_RESUMED) {
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
      }
      else {
        /* setup environment for calling method */
        mrb_vm_ci_proc_set(ci, (proc = MRB_METHOD_PROC(m)));
        irep = proc->body.irep;
        pool = irep->pool;
        syms = irep->syms;
        mrb_stack_extend(mrb, (irep->nregs < 4) ? 4 : irep->nregs);
        pc = irep->iseq;
      }
      JUMP;
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
        if (MRB_ENV_LEN(e) <= m1+r+m2+1)
          goto L_NOSUPER;
        stack = e->stack + 1;
      }
      if (r == 0) {
        regs[a] = mrb_ary_new_from_values(mrb, m1+m2, stack);
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
        regs[a] = mrb_ary_new_capa(mrb, m1+len+m2);
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
        ARY_SET_LEN(rest, m1+len+m2);
      }
      if (kd) {
        regs[a+1] = stack[m1+r+m2];
        regs[a+2] = stack[m1+r+m2+1];
      }
      else {
        regs[a+1] = stack[m1+r+m2];
      }
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
      mrb_int const len = m1 + o + r + m2;

      mrb_callinfo *ci = mrb->c->ci;
      mrb_int argc = ci->n;
      mrb_value *argv = regs+1;
      mrb_value * const argv0 = argv;
      mrb_int const kw_pos = len + kd;    /* where kwhash should be */
      mrb_int const blk_pos = kw_pos + 1; /* where block should be */
      mrb_value blk = regs[mrb_ci_bidx(ci)];
      mrb_value kdict = mrb_nil_value();

      /* keyword arguments */
      if (ci->nk > 0) {
        mrb_int kidx = mrb_ci_kidx(ci);
        kdict = regs[kidx];
        if (!mrb_hash_p(kdict) || mrb_hash_size(mrb, kdict) == 0) {
          kdict = mrb_nil_value();
          ci->nk = 0;
        }
      }
      if (!kd && !mrb_nil_p(kdict)) {
        if (argc < 14) {
          ci->n++;
          argc++;    /* include kdict in normal arguments */
        }
        else if (argc == 14) {
          /* pack arguments and kdict */
          regs[1] = mrb_ary_new_from_values(mrb, argc+1, &regs[1]);
          argc = ci->n = 15;
        }
        else {/* argc == 15 */
          /* push kdict to packed arguments */
          mrb_ary_push(mrb, regs[1], regs[2]);
        }
        ci->nk = 0;
      }
      if (kd && MRB_ASPEC_KEY(a) > 0 && mrb_hash_p(kdict)) {
        kdict = mrb_hash_dup(mrb, kdict);
      }

      /* arguments is passed with Array */
      if (argc == 15) {
        struct RArray *ary = mrb_ary_ptr(regs[1]);
        argv = ARY_PTR(ary);
        argc = (int)ARY_LEN(ary);
        mrb_gc_protect(mrb, regs[1]);
      }

      /* strict argument check */
      if (ci->proc && MRB_PROC_STRICT_P(ci->proc)) {
        if (argc < m1 + m2 || (r == 0 && argc > len)) {
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

      /* rest arguments */
      mrb_value rest = mrb_nil_value();
      if (argc < len) {
        mrb_int mlen = m2;
        if (argc < m1+m2) {
          mlen = m1 < argc ? argc - m1 : 0;
        }

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
          rest = mrb_ary_new_capa(mrb, 0);
          regs[m1+o+1] = rest;
        }
        /* skip initializer of passed arguments */
        if (o > 0 && argc > m1+m2)
          pc += (argc - m1 - m2)*3;
      }
      else {
        mrb_int rnum = 0;
        if (argv0 != argv) {
          value_move(&regs[1], argv, m1+o);
        }
        if (r) {
          rnum = argc-m1-o-m2;
          rest = mrb_ary_new_from_values(mrb, rnum, argv+m1+o);
          regs[m1+o+1] = rest;
        }
        if (m2 > 0 && argc-m2 > m1) {
          value_move(&regs[m1+o+r+1], &argv[m1+o+rnum], m2);
        }
        pc += o*3;
      }

      /* need to be update blk first to protect blk from GC */
      regs[blk_pos] = blk;              /* move block */
      if (kd) {
        if (mrb_nil_p(kdict))
          kdict = mrb_hash_new_capa(mrb, 0);
        regs[kw_pos] = kdict;           /* set kwhash */
      }

      /* format arguments for generated code */
      mrb->c->ci->n = len;

      /* clear local (but non-argument) variables */
      if (irep->nlocals-blk_pos-1 > 0) {
        stack_clear(&regs[blk_pos+1], irep->nlocals-blk_pos-1);
      }
      JUMP;
    }

    CASE(OP_KARG, BB) {
      mrb_value k = mrb_symbol_value(syms[b]);
      mrb_int kidx = mrb_ci_kidx(mrb->c->ci);
      mrb_value kdict, v;

      if (kidx < 0 || !mrb_hash_p(kdict=regs[kidx]) || !mrb_hash_key_p(mrb, kdict, k)) {
        mrb_value str = mrb_format(mrb, "missing keyword: %v", k);
        mrb_exc_set(mrb, mrb_exc_new_str(mrb, E_ARGUMENT_ERROR, str));
        goto L_RAISE;
      }
      v = mrb_hash_get(mrb, kdict, k);
      regs[a] = v;
      mrb_hash_delete_key(mrb, kdict, k);
      NEXT;
    }

    CASE(OP_KEY_P, BB) {
      mrb_value k = mrb_symbol_value(syms[b]);
      mrb_int kidx = mrb_ci_kidx(mrb->c->ci);
      mrb_value kdict;
      mrb_bool key_p = FALSE;

      if (kidx >= 0 && mrb_hash_p(kdict=regs[kidx])) {
        key_p = mrb_hash_key_p(mrb, kdict, k);
      }
      regs[a] = mrb_bool_value(key_p);
      NEXT;
    }

    CASE(OP_KEYEND, Z) {
      mrb_int kidx = mrb_ci_kidx(mrb->c->ci);
      mrb_value kdict;

      if (kidx >= 0 && mrb_hash_p(kdict=regs[kidx]) && !mrb_hash_empty_p(mrb, kdict)) {
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
        mrb_value blk = regs[mrb_ci_bidx(ci)];

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
          if (ci[1].cci == CINFO_SKIP && prev_jmp) {
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
          if (ci->cci == CINFO_NONE && MRB_PROC_ENV_P(proc) && !MRB_PROC_STRICT_P(proc)) {
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
              if (ci->cci > CINFO_NONE) { /* jump cross C boundary */
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
          if (ci->cci > CINFO_NONE) {
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
            if (ci[-1].cci == CINFO_SKIP) {
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
        acc = ci->cci;
        ci = cipop(mrb);
        if (acc == CINFO_SKIP || acc == CINFO_DIRECT) {
          mrb_gc_arena_restore(mrb, ai);
          mrb->jmp = prev_jmp;
          return v;
        }
        pc = ci->pc;
        DEBUG(fprintf(stderr, "from :%s\n", mrb_sym_name(mrb, ci->mid)));
        proc = ci->proc;
        irep = proc->body.irep;
        pool = irep->pool;
        syms = irep->syms;

        ci[1].stack[0] = v;
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
      if (mrb_nil_p(stack[m1+r+m2+kd])) {
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
#ifndef MRB_NO_FLOAT
      mrb_float x, y, f;
#endif

      /* need to check if op is overridden */
      switch (TYPES2(mrb_type(regs[a]),mrb_type(regs[a+1]))) {
      case TYPES2(MRB_TT_INTEGER,MRB_TT_INTEGER):
        {
          mrb_int x = mrb_integer(regs[a]);
          mrb_int y = mrb_integer(regs[a+1]);
          mrb_int div = mrb_div_int(mrb, x, y);
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
        mid = MRB_OPSYM(div);
        goto L_SEND_SYM;
      }

#ifndef MRB_NO_FLOAT
      f = mrb_div_float(x, y);
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
      regs[a] = mrb_ary_new_from_values(mrb, b, &regs[a]);
      mrb_gc_arena_restore(mrb, ai);
      NEXT;
    }
    CASE(OP_ARRAY2, BBB) {
      regs[a] = mrb_ary_new_from_values(mrb, c, &regs[b]);
      mrb_gc_arena_restore(mrb, ai);
      NEXT;
    }

    CASE(OP_ARYCAT, B) {
      mrb_value splat = mrb_ary_splat(mrb, regs[a+1]);
      if (mrb_nil_p(regs[a])) {
        regs[a] = splat;
      }
      else {
        mrb_assert(mrb_type(regs[a]) == MRB_TT_ARRAY);
        mrb_ary_concat(mrb, regs[a], splat);
      }
      mrb_gc_arena_restore(mrb, ai);
      NEXT;
    }

    CASE(OP_ARYPUSH, BB) {
      mrb_assert(mrb_type(regs[a]) == MRB_TT_ARRAY);
      for (mrb_int i=0; i<b; i++) {
        mrb_ary_push(mrb, regs[a], regs[a+i+1]);
      }
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
      mrb_assert(mrb_type(regs[b]) == MRB_TT_ARRAY);
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
      NEXT;
    }

    CASE(OP_SYMBOL, BB) {
      size_t len;
      mrb_sym sym;

      mrb_assert((pool[b].tt&IREP_TT_NFLAG)==0);
      len = pool[b].tt >> 2;
      if (pool[b].tt & IREP_TT_SFLAG) {
        sym = mrb_intern_static(mrb, pool[b].u.str, len);
      }
      else {
        sym  = mrb_intern(mrb, pool[b].u.str, len);
      }
      regs[a] = mrb_symbol_value(sym);
      NEXT;
    }

    CASE(OP_STRING, BB) {
      size_t len;

      mrb_assert((pool[b].tt&IREP_TT_NFLAG)==0);
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

      hash = regs[a];
      mrb_ensure_hash_type(mrb, hash);
      for (i=a+1; i<lim; i+=2) {
        mrb_hash_set(mrb, hash, regs[i], regs[i+1]);
      }
      mrb_gc_arena_restore(mrb, ai);
      NEXT;
    }
    CASE(OP_HASHCAT, B) {
      mrb_value hash = regs[a];

      mrb_ensure_hash_type(mrb, hash);
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

    CASE(OP_RANGE_INC, B) {
      mrb_value v = mrb_range_new(mrb, regs[a], regs[a+1], FALSE);
      regs[a] = v;
      mrb_gc_arena_restore(mrb, ai);
      NEXT;
    }

    CASE(OP_RANGE_EXC, B) {
      mrb_value v = mrb_range_new(mrb, regs[a], regs[a+1], TRUE);
      regs[a] = v;
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

    CASE(OP_EXEC, BB)
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
      cipush(mrb, a, 0, mrb_class_ptr(recv), p, 0, 0);

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
      mrb_sym mid = syms[b];

      MRB_METHOD_FROM_PROC(m, p);
      mrb_define_method_raw(mrb, target, mid, m);
      mrb_method_added(mrb, target, mid);
      mrb_gc_arena_restore(mrb, ai);
      regs[a] = mrb_symbol_value(mid);
      NEXT;
    }

    CASE(OP_SCLASS, B) {
      regs[a] = mrb_singleton_class(mrb, regs[a]);
      mrb_gc_arena_restore(mrb, ai);
      NEXT;
    }

    CASE(OP_TCLASS, B) {
      struct RClass *target = check_target_class(mrb);
      if (!target) goto L_RAISE;
      regs[a] = mrb_obj_value(target);
      NEXT;
    }

    CASE(OP_ALIAS, BB) {
      struct RClass *target = check_target_class(mrb);

      if (!target) goto L_RAISE;
      mrb_alias_method(mrb, target, syms[a], syms[b]);
      mrb_method_added(mrb, target, syms[a]);
      NEXT;
    }
    CASE(OP_UNDEF, B) {
      struct RClass *target = check_target_class(mrb);

      if (!target) goto L_RAISE;
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

    CASE(OP_EXT1, Z) {
      insn = READ_B();
      switch (insn) {
#define OPCODE(insn,ops) case OP_ ## insn: FETCH_ ## ops ## _1(); mrb->c->ci->pc = pc; goto L_OP_ ## insn ## _BODY;
#include "mruby/ops.h"
#undef OPCODE
      }
      pc--;
      NEXT;
    }
    CASE(OP_EXT2, Z) {
      insn = READ_B();
      switch (insn) {
#define OPCODE(insn,ops) case OP_ ## insn: FETCH_ ## ops ## _2(); mrb->c->ci->pc = pc; goto L_OP_ ## insn ## _BODY;
#include "mruby/ops.h"
#undef OPCODE
      }
      pc--;
      NEXT;
    }
    CASE(OP_EXT3, Z) {
      uint8_t insn = READ_B();
      switch (insn) {
#define OPCODE(insn,ops) case OP_ ## insn: FETCH_ ## ops ## _3(); mrb->c->ci->pc = pc; goto L_OP_ ## insn ## _BODY;
#include "mruby/ops.h"
#undef OPCODE
      }
      pc--;
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
    while (ci > mrb->c->cibase && ci->cci == CINFO_DIRECT) {
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
  return mrb_vm_run(mrb, proc, self, mrb_ci_bidx(mrb->c->ci) + 1);
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
  cipush(mrb, 0, CINFO_SKIP, mrb->object_class, NULL, 0, 0);
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
