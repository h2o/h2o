/**
** @file mruby/presym/enable.h - Enable Preallocated Symbols
**
** See Copyright Notice in mruby.h
*/

#ifndef MRUBY_PRESYM_ENABLE_H
#define MRUBY_PRESYM_ENABLE_H

#include <mruby/presym/id.h>

#define MRB_OPSYM(name) MRB_OPSYM__##name
#define MRB_CVSYM(name) MRB_CVSYM__##name
#define MRB_IVSYM(name) MRB_IVSYM__##name
#define MRB_SYM_B(name) MRB_SYM_B__##name
#define MRB_SYM_Q(name) MRB_SYM_Q__##name
#define MRB_SYM_E(name) MRB_SYM_E__##name
#define MRB_SYM(name) MRB_SYM__##name

#define MRB_OPSYM_2(mrb, name) MRB_OPSYM__##name
#define MRB_CVSYM_2(mrb, name) MRB_CVSYM__##name
#define MRB_IVSYM_2(mrb, name) MRB_IVSYM__##name
#define MRB_SYM_B_2(mrb, name) MRB_SYM_B__##name
#define MRB_SYM_Q_2(mrb, name) MRB_SYM_Q__##name
#define MRB_SYM_E_2(mrb, name) MRB_SYM_E__##name
#define MRB_SYM_2(mrb, name) MRB_SYM__##name

#define MRB_PRESYM_DEFINE_VAR_AND_INITER(name, size, ...)                     \
  static const mrb_sym name[] = {__VA_ARGS__};

#define MRB_PRESYM_INIT_SYMBOLS(mrb, name) (void)(mrb)

/* use MRB_SYM() for E_RUNTIME_ERROR etc. */
#undef MRB_ERROR_SYM
#define MRB_ERROR_SYM(sym) MRB_SYM(sym)

#endif  /* MRUBY_PRESYM_ENABLE_H */
