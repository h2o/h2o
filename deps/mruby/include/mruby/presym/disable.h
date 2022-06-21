/**
** @file mruby/presym/disable.h - Disable Preallocated Symbols
**
** See Copyright Notice in mruby.h
*/

#ifndef MRUBY_PRESYM_DISABLE_H
#define MRUBY_PRESYM_DISABLE_H

#include <string.h>

#define MRB_PRESYM_MAX 0

#define MRB_OPSYM(name) MRB_OPSYM__##name(mrb)
#define MRB_CVSYM(name) mrb_intern_lit(mrb, "@@" #name)
#define MRB_IVSYM(name) mrb_intern_lit(mrb, "@" #name)
#define MRB_SYM_B(name) mrb_intern_lit(mrb, #name "!")
#define MRB_SYM_Q(name) mrb_intern_lit(mrb, #name "?")
#define MRB_SYM_E(name) mrb_intern_lit(mrb, #name "=")
#define MRB_SYM(name) mrb_intern_lit(mrb, #name)

#define MRB_OPSYM_2(mrb, name) MRB_OPSYM__##name(mrb)
#define MRB_CVSYM_2(mrb, name) mrb_intern_lit(mrb, "@@" #name)
#define MRB_IVSYM_2(mrb, name) mrb_intern_lit(mrb, "@" #name)
#define MRB_SYM_B_2(mrb, name) mrb_intern_lit(mrb, #name "!")
#define MRB_SYM_Q_2(mrb, name) mrb_intern_lit(mrb, #name "?")
#define MRB_SYM_E_2(mrb, name) mrb_intern_lit(mrb, #name "=")
#define MRB_SYM_2(mrb, name) mrb_intern_lit(mrb, #name)

#define MRB_OPSYM__not(mrb) mrb_intern_lit(mrb, "!")
#define MRB_OPSYM__mod(mrb) mrb_intern_lit(mrb, "%")
#define MRB_OPSYM__and(mrb) mrb_intern_lit(mrb, "&")
#define MRB_OPSYM__mul(mrb) mrb_intern_lit(mrb, "*")
#define MRB_OPSYM__add(mrb) mrb_intern_lit(mrb, "+")
#define MRB_OPSYM__sub(mrb) mrb_intern_lit(mrb, "-")
#define MRB_OPSYM__div(mrb) mrb_intern_lit(mrb, "/")
#define MRB_OPSYM__lt(mrb) mrb_intern_lit(mrb, "<")
#define MRB_OPSYM__gt(mrb) mrb_intern_lit(mrb, ">")
#define MRB_OPSYM__xor(mrb) mrb_intern_lit(mrb, "^")
#define MRB_OPSYM__tick(mrb) mrb_intern_lit(mrb, "`")
#define MRB_OPSYM__or(mrb) mrb_intern_lit(mrb, "|")
#define MRB_OPSYM__neg(mrb) mrb_intern_lit(mrb, "~")
#define MRB_OPSYM__neq(mrb) mrb_intern_lit(mrb, "!=")
#define MRB_OPSYM__nmatch(mrb) mrb_intern_lit(mrb, "!~")
#define MRB_OPSYM__andand(mrb) mrb_intern_lit(mrb, "&&")
#define MRB_OPSYM__pow(mrb) mrb_intern_lit(mrb, "**")
#define MRB_OPSYM__plus(mrb) mrb_intern_lit(mrb, "+@")
#define MRB_OPSYM__minus(mrb) mrb_intern_lit(mrb, "-@")
#define MRB_OPSYM__lshift(mrb) mrb_intern_lit(mrb, "<<")
#define MRB_OPSYM__le(mrb) mrb_intern_lit(mrb, "<=")
#define MRB_OPSYM__eq(mrb) mrb_intern_lit(mrb, "==")
#define MRB_OPSYM__match(mrb) mrb_intern_lit(mrb, "=~")
#define MRB_OPSYM__ge(mrb) mrb_intern_lit(mrb, ">=")
#define MRB_OPSYM__rshift(mrb) mrb_intern_lit(mrb, ">>")
#define MRB_OPSYM__aref(mrb) mrb_intern_lit(mrb, "[]")
#define MRB_OPSYM__oror(mrb) mrb_intern_lit(mrb, "||")
#define MRB_OPSYM__cmp(mrb) mrb_intern_lit(mrb, "<=>")
#define MRB_OPSYM__eqq(mrb) mrb_intern_lit(mrb, "===")
#define MRB_OPSYM__aset(mrb) mrb_intern_lit(mrb, "[]=")

#define MRB_PRESYM_DEFINE_VAR_AND_INITER(name, size, ...)                     \
  static mrb_sym name[size];                                                  \
  static void presym_init_##name(mrb_state *mrb) {                            \
    mrb_sym name__[] = {__VA_ARGS__};                                         \
    memcpy(name, name__, sizeof(name));                                       \
  }

#define MRB_PRESYM_INIT_SYMBOLS(mrb, name) presym_init_##name(mrb)

#endif  /* MRUBY_PRESYM_DISABLE_H */
