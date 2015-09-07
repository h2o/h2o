/*
** mruby/proc.h - Proc class
**
** See Copyright Notice in mruby.h
*/

#ifndef MRUBY_PROC_H
#define MRUBY_PROC_H

#include "mruby/irep.h"

#if defined(__cplusplus)
extern "C" {
#endif

struct REnv {
  MRB_OBJECT_HEADER;
  mrb_value *stack;
  mrb_sym mid;
  ptrdiff_t cioff;
};

#define MRB_SET_ENV_STACK_LEN(e,len) (e)->flags = (unsigned int)(len)
#define MRB_ENV_STACK_LEN(e) ((mrb_int)(e)->flags)
#define MRB_ENV_UNSHARE_STACK(e) ((e)->cioff = -1)
#define MRB_ENV_STACK_SHARED_P(e) ((e)->cioff >= 0)

struct RProc {
  MRB_OBJECT_HEADER;
  union {
    mrb_irep *irep;
    mrb_func_t func;
  } body;
  struct RClass *target_class;
  struct REnv *env;
};

/* aspec access */
#define MRB_ASPEC_REQ(a)          (((a) >> 18) & 0x1f)
#define MRB_ASPEC_OPT(a)          (((a) >> 13) & 0x1f)
#define MRB_ASPEC_REST(a)         (((a) >> 12) & 0x1)
#define MRB_ASPEC_POST(a)         (((a) >> 7) & 0x1f)
#define MRB_ASPEC_KEY(a)          (((a) >> 2) & 0x1f)
#define MRB_ASPEC_KDICT(a)        ((a) & (1<<1))
#define MRB_ASPEC_BLOCK(a)        ((a) & 1)

#define MRB_PROC_CFUNC 128
#define MRB_PROC_CFUNC_P(p) (((p)->flags & MRB_PROC_CFUNC) != 0)
#define MRB_PROC_STRICT 256
#define MRB_PROC_STRICT_P(p) (((p)->flags & MRB_PROC_STRICT) != 0)

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

#include "mruby/khash.h"
KHASH_DECLARE(mt, mrb_sym, struct RProc*, TRUE)

#if defined(__cplusplus)
}  /* extern "C" { */
#endif

#endif  /* MRUBY_PROC_H */
