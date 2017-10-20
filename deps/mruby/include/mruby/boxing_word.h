/*
** mruby/boxing_word.h - word boxing mrb_value definition
**
** See Copyright Notice in mruby.h
*/

#ifndef MRUBY_BOXING_WORD_H
#define MRUBY_BOXING_WORD_H

#if defined(MRB_INT16)
# error MRB_INT16 is too small for MRB_WORD_BOXING.
#endif

#if defined(MRB_INT64) && !defined(MRB_64BIT)
#error MRB_INT64 cannot be used with MRB_WORD_BOXING in 32-bit mode.
#endif

struct RFloat {
  MRB_OBJECT_HEADER;
  mrb_float f;
};

struct RCptr {
  MRB_OBJECT_HEADER;
  void *p;
};

#define MRB_FIXNUM_SHIFT 1
#define MRB_TT_HAS_BASIC MRB_TT_FLOAT

enum mrb_special_consts {
  MRB_Qnil    = 0,
  MRB_Qfalse  = 2,
  MRB_Qtrue   = 4,
  MRB_Qundef  = 6,
};

#define MRB_FIXNUM_FLAG   0x01
#define MRB_SYMBOL_FLAG   0x0e
#define MRB_SPECIAL_SHIFT 8

typedef union mrb_value {
  union {
    void *p;
    struct {
      unsigned int i_flag : MRB_FIXNUM_SHIFT;
      mrb_int i : (MRB_INT_BIT - MRB_FIXNUM_SHIFT);
    };
    struct {
      unsigned int sym_flag : MRB_SPECIAL_SHIFT;
      mrb_sym sym : (sizeof(mrb_sym) * CHAR_BIT);
    };
    struct RBasic *bp;
    struct RFloat *fp;
    struct RCptr *vp;
  } value;
  unsigned long w;
} mrb_value;

MRB_API mrb_value mrb_word_boxing_cptr_value(struct mrb_state*, void*);
MRB_API mrb_value mrb_word_boxing_float_value(struct mrb_state*, mrb_float);
MRB_API mrb_value mrb_word_boxing_float_pool(struct mrb_state*, mrb_float);

#define mrb_float_pool(mrb,f) mrb_word_boxing_float_pool(mrb,f)

#define mrb_ptr(o)     (o).value.p
#define mrb_cptr(o)    (o).value.vp->p
#define mrb_float(o)   (o).value.fp->f
#define mrb_fixnum(o)  ((mrb_int)(o).value.i)
#define mrb_symbol(o)  (o).value.sym

static inline enum mrb_vtype
mrb_type(mrb_value o)
{
  switch (o.w) {
  case MRB_Qfalse:
  case MRB_Qnil:
    return MRB_TT_FALSE;
  case MRB_Qtrue:
    return MRB_TT_TRUE;
  case MRB_Qundef:
    return MRB_TT_UNDEF;
  }
  if (o.value.i_flag == MRB_FIXNUM_FLAG) {
    return MRB_TT_FIXNUM;
  }
  if (o.value.sym_flag == MRB_SYMBOL_FLAG) {
    return MRB_TT_SYMBOL;
  }
  return o.value.bp->tt;
}

#define mrb_bool(o)    ((o).w != MRB_Qnil && (o).w != MRB_Qfalse)
#define mrb_fixnum_p(o) ((o).value.i_flag == MRB_FIXNUM_FLAG)
#define mrb_undef_p(o) ((o).w == MRB_Qundef)
#define mrb_nil_p(o)  ((o).w == MRB_Qnil)

#define BOXWORD_SET_VALUE(o, ttt, attr, v) do { \
  switch (ttt) {\
  case MRB_TT_FALSE:  (o).w = (v) ? MRB_Qfalse : MRB_Qnil; break;\
  case MRB_TT_TRUE:   (o).w = MRB_Qtrue; break;\
  case MRB_TT_UNDEF:  (o).w = MRB_Qundef; break;\
  case MRB_TT_FIXNUM: (o).w = 0;(o).value.i_flag = MRB_FIXNUM_FLAG; (o).attr = (v); break;\
  case MRB_TT_SYMBOL: (o).w = 0;(o).value.sym_flag = MRB_SYMBOL_FLAG; (o).attr = (v); break;\
  default:            (o).w = 0; (o).attr = (v); if ((o).value.bp) (o).value.bp->tt = ttt; break;\
  }\
} while (0)

#define SET_FLOAT_VALUE(mrb,r,v) r = mrb_word_boxing_float_value(mrb, v)
#define SET_CPTR_VALUE(mrb,r,v) r = mrb_word_boxing_cptr_value(mrb, v)
#define SET_NIL_VALUE(r) BOXWORD_SET_VALUE(r, MRB_TT_FALSE, value.i, 0)
#define SET_FALSE_VALUE(r) BOXWORD_SET_VALUE(r, MRB_TT_FALSE, value.i, 1)
#define SET_TRUE_VALUE(r) BOXWORD_SET_VALUE(r, MRB_TT_TRUE, value.i, 1)
#define SET_BOOL_VALUE(r,b) BOXWORD_SET_VALUE(r, b ? MRB_TT_TRUE : MRB_TT_FALSE, value.i, 1)
#define SET_INT_VALUE(r,n) BOXWORD_SET_VALUE(r, MRB_TT_FIXNUM, value.i, (n))
#define SET_SYM_VALUE(r,v) BOXWORD_SET_VALUE(r, MRB_TT_SYMBOL, value.sym, (v))
#define SET_OBJ_VALUE(r,v) BOXWORD_SET_VALUE(r, (((struct RObject*)(v))->tt), value.p, (v))
#define SET_UNDEF_VALUE(r) BOXWORD_SET_VALUE(r, MRB_TT_UNDEF, value.i, 0)

#endif  /* MRUBY_BOXING_WORD_H */
