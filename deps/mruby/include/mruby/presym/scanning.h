/**
** @file mruby/presym/scanning.h - Scanning Preallocated Symbols
**
** See Copyright Notice in mruby.h
*/

#ifndef MRUBY_PRESYM_SCANNING_H
#define MRUBY_PRESYM_SCANNING_H

#define MRB_PRESYM_SCANNING_TAGGED(arg) <@! arg !@>

#undef mrb_intern_lit
#define mrb_intern_lit(mrb, name) MRB_PRESYM_SCANNING_TAGGED(name)
#define mrb_intern_cstr(mrb, name) MRB_PRESYM_SCANNING_TAGGED(name)
#define mrb_define_method(mrb, c, name, ...) MRB_PRESYM_SCANNING_TAGGED(name) (c) (__VA_ARGS__)
#define mrb_define_class_method(mrb, c, name, ...) MRB_PRESYM_SCANNING_TAGGED(name) (c) (__VA_ARGS__)
#define mrb_define_singleton_method(mrb, c, name, ...) MRB_PRESYM_SCANNING_TAGGED(name) (c) (__VA_ARGS__)
#define mrb_define_class(mrb, name, s) MRB_PRESYM_SCANNING_TAGGED(name) (s)
#define mrb_define_class_under(mrb, o, name, s) MRB_PRESYM_SCANNING_TAGGED(name) (o) (s)
#define mrb_define_module(mrb, name) MRB_PRESYM_SCANNING_TAGGED(name)
#define mrb_define_module_under(mrb, o, name) MRB_PRESYM_SCANNING_TAGGED(name) (o)
#define mrb_define_module_function(mrb, c, name, ...) MRB_PRESYM_SCANNING_TAGGED(name) (c) (__VA_ARGS__)
#define mrb_define_const(mrb, c, name, v) MRB_PRESYM_SCANNING_TAGGED(name) (c) (v)
#define mrb_define_global_const(mrb, name, v) MRB_PRESYM_SCANNING_TAGGED(name) (v)
#define mrb_define_alias(mrb, c, a, b) MRB_PRESYM_SCANNING_TAGGED(a) MRB_PRESYM_SCANNING_TAGGED(b) (c)
#define mrb_class_get(mrb, name) MRB_PRESYM_SCANNING_TAGGED(name)
#define mrb_class_get_under(mrb, outer, name) MRB_PRESYM_SCANNING_TAGGED(name) (outer)
#define mrb_module_get(mrb, name) MRB_PRESYM_SCANNING_TAGGED(name)
#define mrb_module_get_under(mrb, outer, name) MRB_PRESYM_SCANNING_TAGGED(name) (outer)
#define mrb_funcall(mrb, v, name, ...) MRB_PRESYM_SCANNING_TAGGED(name) (v) (__VA_ARGS__)

#define MRB_OPSYM(name) MRB_OPSYM__##name(mrb)
#define MRB_CVSYM(name) MRB_PRESYM_SCANNING_TAGGED("@@" #name)
#define MRB_IVSYM(name) MRB_PRESYM_SCANNING_TAGGED("@" #name)
#define MRB_SYM_B(name) MRB_PRESYM_SCANNING_TAGGED(#name "!")
#define MRB_SYM_Q(name) MRB_PRESYM_SCANNING_TAGGED(#name "?")
#define MRB_SYM_E(name) MRB_PRESYM_SCANNING_TAGGED(#name "=")
#define MRB_SYM(name) MRB_PRESYM_SCANNING_TAGGED(#name)

#define MRB_OPSYM_2(mrb, name) MRB_OPSYM__##name(mrb)
#define MRB_CVSYM_2(mrb, name) MRB_PRESYM_SCANNING_TAGGED("@@" #name)
#define MRB_IVSYM_2(mrb, name) MRB_PRESYM_SCANNING_TAGGED("@" #name)
#define MRB_SYM_B_2(mrb, name) MRB_PRESYM_SCANNING_TAGGED(#name "!")
#define MRB_SYM_Q_2(mrb, name) MRB_PRESYM_SCANNING_TAGGED(#name "?")
#define MRB_SYM_E_2(mrb, name) MRB_PRESYM_SCANNING_TAGGED(#name "=")
#define MRB_SYM_2(mrb, name) MRB_PRESYM_SCANNING_TAGGED(#name)

#define MRB_OPSYM__not(mrb) MRB_PRESYM_SCANNING_TAGGED("!")
#define MRB_OPSYM__mod(mrb) MRB_PRESYM_SCANNING_TAGGED("%")
#define MRB_OPSYM__and(mrb) MRB_PRESYM_SCANNING_TAGGED("&")
#define MRB_OPSYM__mul(mrb) MRB_PRESYM_SCANNING_TAGGED("*")
#define MRB_OPSYM__add(mrb) MRB_PRESYM_SCANNING_TAGGED("+")
#define MRB_OPSYM__sub(mrb) MRB_PRESYM_SCANNING_TAGGED("-")
#define MRB_OPSYM__div(mrb) MRB_PRESYM_SCANNING_TAGGED("/")
#define MRB_OPSYM__lt(mrb) MRB_PRESYM_SCANNING_TAGGED("<")
#define MRB_OPSYM__gt(mrb) MRB_PRESYM_SCANNING_TAGGED(">")
#define MRB_OPSYM__xor(mrb) MRB_PRESYM_SCANNING_TAGGED("^")
#define MRB_OPSYM__tick(mrb) MRB_PRESYM_SCANNING_TAGGED("`")
#define MRB_OPSYM__or(mrb) MRB_PRESYM_SCANNING_TAGGED("|")
#define MRB_OPSYM__neg(mrb) MRB_PRESYM_SCANNING_TAGGED("~")
#define MRB_OPSYM__neq(mrb) MRB_PRESYM_SCANNING_TAGGED("!=")
#define MRB_OPSYM__nmatch(mrb) MRB_PRESYM_SCANNING_TAGGED("!~")
#define MRB_OPSYM__andand(mrb) MRB_PRESYM_SCANNING_TAGGED("&&")
#define MRB_OPSYM__pow(mrb) MRB_PRESYM_SCANNING_TAGGED("**")
#define MRB_OPSYM__plus(mrb) MRB_PRESYM_SCANNING_TAGGED("+@")
#define MRB_OPSYM__minus(mrb) MRB_PRESYM_SCANNING_TAGGED("-@")
#define MRB_OPSYM__lshift(mrb) MRB_PRESYM_SCANNING_TAGGED("<<")
#define MRB_OPSYM__le(mrb) MRB_PRESYM_SCANNING_TAGGED("<=")
#define MRB_OPSYM__eq(mrb) MRB_PRESYM_SCANNING_TAGGED("==")
#define MRB_OPSYM__match(mrb) MRB_PRESYM_SCANNING_TAGGED("=~")
#define MRB_OPSYM__ge(mrb) MRB_PRESYM_SCANNING_TAGGED(">=")
#define MRB_OPSYM__rshift(mrb) MRB_PRESYM_SCANNING_TAGGED(">>")
#define MRB_OPSYM__aref(mrb) MRB_PRESYM_SCANNING_TAGGED("[]")
#define MRB_OPSYM__oror(mrb) MRB_PRESYM_SCANNING_TAGGED("||")
#define MRB_OPSYM__cmp(mrb) MRB_PRESYM_SCANNING_TAGGED("<=>")
#define MRB_OPSYM__eqq(mrb) MRB_PRESYM_SCANNING_TAGGED("===")
#define MRB_OPSYM__aset(mrb) MRB_PRESYM_SCANNING_TAGGED("[]=")

#endif  /* MRUBY_PRESYM_SCANNING_H */
