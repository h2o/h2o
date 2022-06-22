/**
** @file mruby/boxing_word.h - word boxing mrb_value definition
**
** See Copyright Notice in mruby.h
*/

#ifndef MRUBY_BOXING_WORD_H
#define MRUBY_BOXING_WORD_H

#ifndef MRB_NO_FLOAT
struct RFloat {
  MRB_OBJECT_HEADER;
  mrb_float f;
};
#endif

struct RInteger {
  MRB_OBJECT_HEADER;
  mrb_int i;
};

enum mrb_special_consts {
  MRB_Qnil    =  0,
  MRB_Qfalse  =  4,
  MRB_Qtrue   = 12,
  MRB_Qundef  = 20,
};

#if defined(MRB_64BIT) && defined(MRB_INT32)
#define MRB_FIXNUM_SHIFT        0
#else
#define MRB_FIXNUM_SHIFT        BOXWORD_FIXNUM_SHIFT
#endif
#define MRB_SYMBOL_SHIFT        BOXWORD_SYMBOL_SHIFT

#if defined(MRB_64BIT) && defined(MRB_INT64)
# define MRB_FIXNUM_MIN (INT64_MIN>>MRB_FIXNUM_SHIFT)
# define MRB_FIXNUM_MAX (INT64_MAX>>MRB_FIXNUM_SHIFT)
#else
# define MRB_FIXNUM_MIN (INT32_MIN>>MRB_FIXNUM_SHIFT)
# define MRB_FIXNUM_MAX (INT32_MAX>>MRB_FIXNUM_SHIFT)
#endif

#define BOXWORD_FIXNUM_BIT_POS  1
#define BOXWORD_SYMBOL_BIT_POS  2
#define BOXWORD_FIXNUM_SHIFT    BOXWORD_FIXNUM_BIT_POS
#ifdef MRB_64BIT
#define BOXWORD_SYMBOL_SHIFT    0
#else
#define BOXWORD_SYMBOL_SHIFT    BOXWORD_SYMBOL_BIT_POS
#endif
#define BOXWORD_FIXNUM_FLAG     (1 << (BOXWORD_FIXNUM_BIT_POS - 1))
#define BOXWORD_SYMBOL_FLAG     (1 << (BOXWORD_SYMBOL_BIT_POS - 1))
#define BOXWORD_FIXNUM_MASK     ((1 << BOXWORD_FIXNUM_BIT_POS) - 1)
#define BOXWORD_SYMBOL_MASK     ((1 << BOXWORD_SYMBOL_BIT_POS) - 1)
#define BOXWORD_IMMEDIATE_MASK  0x07

#define BOXWORD_SET_SHIFT_VALUE(o,n,v) \
  ((o).w = (((uintptr_t)(v)) << BOXWORD_##n##_SHIFT) | BOXWORD_##n##_FLAG)
#define BOXWORD_SHIFT_VALUE_P(o,n) \
  (((o).w & BOXWORD_##n##_MASK) == BOXWORD_##n##_FLAG)
#define BOXWORD_OBJ_TYPE_P(o,n) \
  (!mrb_immediate_p(o) && mrb_val_union(o).bp->tt == MRB_TT_##n)

/*
 * mrb_value representation:
 *
 *   nil   : ...0000 0000 (all bits are 0)
 *   false : ...0000 0100 (mrb_fixnum(v) != 0)
 *   true  : ...0000 1100
 *   undef : ...0001 0100
 *   fixnum: ...IIII III1
 *   symbol: ...SSSS SS10 (use only upper 32-bit as symbol value on 64-bit CPU)
 *   object: ...PPPP P000 (any bits are 1)
 */
typedef struct mrb_value {
  uintptr_t w;
} mrb_value;

union mrb_value_ {
  void *p;
#ifdef MRB_64BIT
  /* use struct to avoid bit shift. */
  struct {
    MRB_ENDIAN_LOHI(
      mrb_sym sym;
      ,uint32_t sym_flag;
    )
  };
#endif
  struct RBasic *bp;
#ifndef MRB_NO_FLOAT
  struct RFloat *fp;
#endif
  struct RInteger *ip;
  struct RCptr *vp;
  uintptr_t w;
  mrb_value value;
};

mrb_static_assert1(sizeof(mrb_value) == sizeof(union mrb_value_));

static inline union mrb_value_
mrb_val_union(mrb_value v)
{
  union mrb_value_ x;
  x.value = v;
  return x;
}

MRB_API mrb_value mrb_word_boxing_cptr_value(struct mrb_state*, void*);
#ifndef MRB_NO_FLOAT
MRB_API mrb_value mrb_word_boxing_float_value(struct mrb_state*, mrb_float);
#endif
MRB_API mrb_value mrb_word_boxing_int_value(struct mrb_state*, mrb_int);

#define mrb_immediate_p(o) ((o).w & BOXWORD_IMMEDIATE_MASK || (o).w == MRB_Qnil)

#define mrb_ptr(o)     mrb_val_union(o).p
#define mrb_cptr(o)    mrb_val_union(o).vp->p
#ifndef MRB_NO_FLOAT
#define mrb_float(o)   mrb_val_union(o).fp->f
#endif
#define mrb_fixnum(o)  (mrb_int)(((intptr_t)(o).w) >> BOXWORD_FIXNUM_SHIFT)
MRB_INLINE mrb_int
mrb_integer_func(mrb_value o) {
  if (mrb_immediate_p(o)) return mrb_fixnum(o);
  return mrb_val_union(o).ip->i;
}
#define mrb_integer(o) mrb_integer_func(o)
#ifdef MRB_64BIT
#define mrb_symbol(o)  mrb_val_union(o).sym
#else
#define mrb_symbol(o)  (mrb_sym)(((o).w) >> BOXWORD_SYMBOL_SHIFT)
#endif
#define mrb_bool(o)    (((o).w & ~(uintptr_t)MRB_Qfalse) != 0)

#define mrb_fixnum_p(o) BOXWORD_SHIFT_VALUE_P(o, FIXNUM)
#define mrb_integer_p(o) (BOXWORD_SHIFT_VALUE_P(o, FIXNUM)||BOXWORD_OBJ_TYPE_P(o, INTEGER))
#ifdef MRB_64BIT
#define mrb_symbol_p(o) (mrb_val_union(o).sym_flag == BOXWORD_SYMBOL_FLAG)
#else
#define mrb_symbol_p(o) BOXWORD_SHIFT_VALUE_P(o, SYMBOL)
#endif
#define mrb_undef_p(o) ((o).w == MRB_Qundef)
#define mrb_nil_p(o)  ((o).w == MRB_Qnil)
#define mrb_false_p(o) ((o).w == MRB_Qfalse)
#define mrb_true_p(o)  ((o).w == MRB_Qtrue)
#ifndef MRB_NO_FLOAT
#define mrb_float_p(o) BOXWORD_OBJ_TYPE_P(o, FLOAT)
#endif
#define mrb_array_p(o) BOXWORD_OBJ_TYPE_P(o, ARRAY)
#define mrb_string_p(o) BOXWORD_OBJ_TYPE_P(o, STRING)
#define mrb_hash_p(o) BOXWORD_OBJ_TYPE_P(o, HASH)
#define mrb_cptr_p(o) BOXWORD_OBJ_TYPE_P(o, CPTR)
#define mrb_exception_p(o) BOXWORD_OBJ_TYPE_P(o, EXCEPTION)
#define mrb_free_p(o) BOXWORD_OBJ_TYPE_P(o, FREE)
#define mrb_object_p(o) BOXWORD_OBJ_TYPE_P(o, OBJECT)
#define mrb_class_p(o) BOXWORD_OBJ_TYPE_P(o, CLASS)
#define mrb_module_p(o) BOXWORD_OBJ_TYPE_P(o, MODULE)
#define mrb_iclass_p(o) BOXWORD_OBJ_TYPE_P(o, ICLASS)
#define mrb_sclass_p(o) BOXWORD_OBJ_TYPE_P(o, SCLASS)
#define mrb_proc_p(o) BOXWORD_OBJ_TYPE_P(o, PROC)
#define mrb_range_p(o) BOXWORD_OBJ_TYPE_P(o, RANGE)
#define mrb_env_p(o) BOXWORD_OBJ_TYPE_P(o, ENV)
#define mrb_data_p(o) BOXWORD_OBJ_TYPE_P(o, DATA)
#define mrb_fiber_p(o) BOXWORD_OBJ_TYPE_P(o, FIBER)
#define mrb_istruct_p(o) BOXWORD_OBJ_TYPE_P(o, ISTRUCT)
#define mrb_break_p(o) BOXWORD_OBJ_TYPE_P(o, BREAK)

#ifndef MRB_NO_FLOAT
#define SET_FLOAT_VALUE(mrb,r,v) ((r) = mrb_word_boxing_float_value(mrb, v))
#endif
#define SET_CPTR_VALUE(mrb,r,v) ((r) = mrb_word_boxing_cptr_value(mrb, v))
#define SET_UNDEF_VALUE(r) ((r).w = MRB_Qundef)
#define SET_NIL_VALUE(r) ((r).w = MRB_Qnil)
#define SET_FALSE_VALUE(r) ((r).w = MRB_Qfalse)
#define SET_TRUE_VALUE(r) ((r).w = MRB_Qtrue)
#define SET_BOOL_VALUE(r,b) ((b) ? SET_TRUE_VALUE(r) : SET_FALSE_VALUE(r))
#define SET_INT_VALUE(mrb,r,n) ((r) = mrb_word_boxing_int_value(mrb, n))
#define SET_FIXNUM_VALUE(r,n) BOXWORD_SET_SHIFT_VALUE(r, FIXNUM, n)
#ifdef MRB_64BIT
#define SET_SYM_VALUE(r,v) do {\
  union mrb_value_ mrb_value_union_variable;\
  mrb_value_union_variable.sym = v;\
  mrb_value_union_variable.sym_flag = BOXWORD_SYMBOL_FLAG;\
  (r) = mrb_value_union_variable.value;\
} while (0)
#else
#define SET_SYM_VALUE(r,n) BOXWORD_SET_SHIFT_VALUE(r, SYMBOL, n)
#endif
#define SET_OBJ_VALUE(r,v) ((r).w = (uintptr_t)(v))

MRB_INLINE enum mrb_vtype
mrb_type(mrb_value o)
{
  return !mrb_bool(o)    ? MRB_TT_FALSE :
         mrb_true_p(o)   ? MRB_TT_TRUE :
         mrb_fixnum_p(o) ? MRB_TT_INTEGER :
         mrb_symbol_p(o) ? MRB_TT_SYMBOL :
         mrb_undef_p(o)  ? MRB_TT_UNDEF :
         mrb_val_union(o).bp->tt;
}

#endif  /* MRUBY_BOXING_WORD_H */
