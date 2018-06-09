/*
** mruby/proc.h - Proc class
**
** See Copyright Notice in mruby.h
*/

#ifndef MRUBY_PROC_H
#define MRUBY_PROC_H

#include "common.h"
#include <mruby/irep.h>

/**
 * Proc class
 */
MRB_BEGIN_DECL

struct REnv {
  MRB_OBJECT_HEADER;
  mrb_value *stack;
  struct mrb_context *cxt;
  mrb_sym mid;
};

/* flags (21bits): 1(shared flag):10(cioff/bidx):10(stack_len) */
#define MRB_ENV_SET_STACK_LEN(e,len) (e)->flags = (((e)->flags & ~0x3ff)|((unsigned int)(len) & 0x3ff))
#define MRB_ENV_STACK_LEN(e) ((mrb_int)((e)->flags & 0x3ff))
#define MRB_ENV_STACK_UNSHARED (1<<20)
#define MRB_ENV_UNSHARE_STACK(e) (e)->flags |= MRB_ENV_STACK_UNSHARED
#define MRB_ENV_STACK_SHARED_P(e) (((e)->flags & MRB_ENV_STACK_UNSHARED) == 0)
#define MRB_ENV_BIDX(e) (((e)->flags >> 10) & 0x3ff)
#define MRB_ENV_SET_BIDX(e,idx) (e)->flags = (((e)->flags & ~(0x3ff<<10))|((unsigned int)(idx) & 0x3ff)<<10)

void mrb_env_unshare(mrb_state*, struct REnv*);

struct RProc {
  MRB_OBJECT_HEADER;
  union {
    mrb_irep *irep;
    mrb_func_t func;
  } body;
  struct RProc *upper;
  union {
    struct RClass *target_class;
    struct REnv *env;
  } e;
};

/* aspec access */
#define MRB_ASPEC_REQ(a)          (((a) >> 18) & 0x1f)
#define MRB_ASPEC_OPT(a)          (((a) >> 13) & 0x1f)
#define MRB_ASPEC_REST(a)         (((a) >> 12) & 0x1)
#define MRB_ASPEC_POST(a)         (((a) >> 7) & 0x1f)
#define MRB_ASPEC_KEY(a)          (((a) >> 2) & 0x1f)
#define MRB_ASPEC_KDICT(a)        ((a) & (1<<1))
#define MRB_ASPEC_BLOCK(a)        ((a) & 1)

#define MRB_PROC_CFUNC_FL 128
#define MRB_PROC_CFUNC_P(p) (((p)->flags & MRB_PROC_CFUNC_FL) != 0)
#define MRB_PROC_CFUNC(p) (p)->body.func
#define MRB_PROC_STRICT 256
#define MRB_PROC_STRICT_P(p) (((p)->flags & MRB_PROC_STRICT) != 0)
#define MRB_PROC_ORPHAN 512
#define MRB_PROC_ORPHAN_P(p) (((p)->flags & MRB_PROC_ORPHAN) != 0)
#define MRB_PROC_ENVSET 1024
#define MRB_PROC_ENV_P(p) (((p)->flags & MRB_PROC_ENVSET) != 0)
#define MRB_PROC_ENV(p) (MRB_PROC_ENV_P(p) ? (p)->e.env : NULL)
#define MRB_PROC_TARGET_CLASS(p) (MRB_PROC_ENV_P(p) ? (p)->e.env->c : (p)->e.target_class)
#define MRB_PROC_SET_TARGET_CLASS(p,tc) do {\
  if (MRB_PROC_ENV_P(p)) {\
    (p)->e.env->c = (tc);\
    mrb_field_write_barrier(mrb, (struct RBasic*)(p)->e.env, (struct RBasic*)tc);\
  }\
  else {\
    (p)->e.target_class = (tc);\
    mrb_field_write_barrier(mrb, (struct RBasic*)p, (struct RBasic*)tc);\
  }\
} while (0)
#define MRB_PROC_SCOPE 2048
#define MRB_PROC_SCOPE_P(p) (((p)->flags & MRB_PROC_SCOPE) != 0)

#define mrb_proc_ptr(v)    ((struct RProc*)(mrb_ptr(v)))

struct RProc *mrb_proc_new(mrb_state*, mrb_irep*);
struct RProc *mrb_closure_new(mrb_state*, mrb_irep*);
MRB_API struct RProc *mrb_proc_new_cfunc(mrb_state*, mrb_func_t);
MRB_API struct RProc *mrb_closure_new_cfunc(mrb_state *mrb, mrb_func_t func, int nlocals);
void mrb_proc_copy(struct RProc *a, struct RProc *b);

/* implementation of #send method */
MRB_API mrb_value mrb_f_send(mrb_state *mrb, mrb_value self);

/* following functions are defined in mruby-proc-ext so please include it when using */
MRB_API struct RProc *mrb_proc_new_cfunc_with_env(mrb_state*, mrb_func_t, mrb_int, const mrb_value*);
MRB_API mrb_value mrb_proc_cfunc_env_get(mrb_state*, mrb_int);
/* old name */
#define mrb_cfunc_env_get(mrb, idx) mrb_proc_cfunc_env_get(mrb, idx)

#ifdef MRB_METHOD_TABLE_INLINE

#define MRB_METHOD_FUNC_FL ((uintptr_t)1)
#define MRB_METHOD_FUNC_P(m) (((uintptr_t)(m))&MRB_METHOD_FUNC_FL)
#define MRB_METHOD_FUNC(m) ((mrb_func_t)((uintptr_t)(m)&(~MRB_METHOD_FUNC_FL)))
#define MRB_METHOD_FROM_FUNC(m,fn) m=(mrb_method_t)((struct RProc*)((uintptr_t)(fn)|MRB_METHOD_FUNC_FL))
#define MRB_METHOD_FROM_PROC(m,pr) m=(mrb_method_t)(struct RProc*)(pr)
#define MRB_METHOD_PROC_P(m) (!MRB_METHOD_FUNC_P(m))
#define MRB_METHOD_PROC(m) ((struct RProc*)(m))
#define MRB_METHOD_UNDEF_P(m) ((m)==0)

#else

#define MRB_METHOD_FUNC_P(m) ((m).func_p)
#define MRB_METHOD_FUNC(m) ((m).func)
#define MRB_METHOD_FROM_FUNC(m,fn) do{(m).func_p=TRUE;(m).func=(fn);}while(0)
#define MRB_METHOD_FROM_PROC(m,pr) do{(m).func_p=FALSE;(m).proc=(pr);}while(0)
#define MRB_METHOD_PROC_P(m) (!MRB_METHOD_FUNC_P(m))
#define MRB_METHOD_PROC(m) ((m).proc)
#define MRB_METHOD_UNDEF_P(m) ((m).proc==NULL)

#endif /* MRB_METHOD_TABLE_INLINE */

#define MRB_METHOD_CFUNC_P(m) (MRB_METHOD_FUNC_P(m)?TRUE:(MRB_METHOD_PROC(m)?(MRB_PROC_CFUNC_P(MRB_METHOD_PROC(m))):FALSE))
#define MRB_METHOD_CFUNC(m) (MRB_METHOD_FUNC_P(m)?MRB_METHOD_FUNC(m):((MRB_METHOD_PROC(m)&&MRB_PROC_CFUNC_P(MRB_METHOD_PROC(m)))?MRB_PROC_CFUNC(MRB_METHOD_PROC(m)):NULL))


#include <mruby/khash.h>
KHASH_DECLARE(mt, mrb_sym, mrb_method_t, TRUE)

MRB_END_DECL

#endif  /* MRUBY_PROC_H */
