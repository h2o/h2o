/**
** @file mruby/boxing_no.h - unboxed mrb_value definition
**
** See Copyright Notice in mruby.h
*/

#ifndef MRUBY_BOXING_NO_H
#define MRUBY_BOXING_NO_H

#define MRB_FIXNUM_SHIFT 0
#define MRB_SYMBOL_SHIFT 0
#define MRB_FIXNUM_MIN MRB_INT_MIN
#define MRB_FIXNUM_MAX MRB_INT_MAX

union mrb_value_union {
#ifndef MRB_NO_FLOAT
  mrb_float f;
#endif
  void *p;
  mrb_int i;
  mrb_sym sym;
};

typedef struct mrb_value {
  union mrb_value_union value;
  enum mrb_vtype tt;
} mrb_value;

#define mrb_ptr(o)      (o).value.p
#define mrb_cptr(o)     mrb_ptr(o)
#ifndef MRB_NO_FLOAT
#define mrb_float(o)    (o).value.f
#endif
#define mrb_fixnum(o)   (o).value.i
#define mrb_integer(o)  mrb_fixnum(o)
#define mrb_symbol(o)   (o).value.sym
#define mrb_type(o)     (o).tt

#define BOXNIX_SET_VALUE(o, ttt, attr, v) do {\
  (o).tt = ttt;\
  (o).attr = v;\
} while (0)

#define SET_NIL_VALUE(r) BOXNIX_SET_VALUE(r, MRB_TT_FALSE, value.i, 0)
#define SET_FALSE_VALUE(r) BOXNIX_SET_VALUE(r, MRB_TT_FALSE, value.i, 1)
#define SET_TRUE_VALUE(r) BOXNIX_SET_VALUE(r, MRB_TT_TRUE, value.i, 1)
#define SET_BOOL_VALUE(r,b) BOXNIX_SET_VALUE(r, b ? MRB_TT_TRUE : MRB_TT_FALSE, value.i, 1)
#define SET_INT_VALUE(mrb,r,n) BOXNIX_SET_VALUE(r, MRB_TT_INTEGER, value.i, (n))
#define SET_FIXNUM_VALUE(r,n) BOXNIX_SET_VALUE(r, MRB_TT_INTEGER, value.i, (n))
#ifndef MRB_NO_FLOAT
#define SET_FLOAT_VALUE(mrb,r,v) BOXNIX_SET_VALUE(r, MRB_TT_FLOAT, value.f, (v))
#endif
#define SET_SYM_VALUE(r,v) BOXNIX_SET_VALUE(r, MRB_TT_SYMBOL, value.sym, (v))
#define SET_OBJ_VALUE(r,v) BOXNIX_SET_VALUE(r, (((struct RObject*)(v))->tt), value.p, (v))
#define SET_CPTR_VALUE(mrb,r,v) BOXNIX_SET_VALUE(r, MRB_TT_CPTR, value.p, v)
#define SET_UNDEF_VALUE(r) BOXNIX_SET_VALUE(r, MRB_TT_UNDEF, value.i, 0)

#endif  /* MRUBY_BOXING_NO_H */
