/**
** @file mruby/boxing_word.h - word boxing mrb_value definition
**
** See Copyright Notice in mruby.h
*/

#ifndef MRUBY_BOXING_WORD_H
#define MRUBY_BOXING_WORD_H

#if defined(MRB_32BIT) && !defined(MRB_USE_FLOAT32) && !defined(MRB_WORDBOX_NO_FLOAT_TRUNCATE)
# define MRB_WORDBOX_NO_FLOAT_TRUNCATE
#endif

#if !defined(MRB_NO_FLOAT) && defined(MRB_WORDBOX_NO_FLOAT_TRUNCATE)
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
#define MRB_FIXNUM_SHIFT        WORDBOX_FIXNUM_SHIFT
#endif
#define MRB_SYMBOL_SHIFT        WORDBOX_SYMBOL_SHIFT

#if defined(MRB_64BIT) && defined(MRB_INT64)
# define MRB_FIXNUM_MIN (INT64_MIN>>MRB_FIXNUM_SHIFT)
# define MRB_FIXNUM_MAX (INT64_MAX>>MRB_FIXNUM_SHIFT)
#else
# define MRB_FIXNUM_MIN (INT32_MIN>>MRB_FIXNUM_SHIFT)
# define MRB_FIXNUM_MAX (INT32_MAX>>MRB_FIXNUM_SHIFT)
#endif

#define WORDBOX_FIXNUM_BIT_POS  1
#define WORDBOX_FIXNUM_SHIFT    WORDBOX_FIXNUM_BIT_POS
#define WORDBOX_FIXNUM_FLAG     (1 << (WORDBOX_FIXNUM_BIT_POS - 1))
#define WORDBOX_FIXNUM_MASK     ((1 << WORDBOX_FIXNUM_BIT_POS) - 1)

#if defined(MRB_WORDBOX_NO_FLOAT_TRUNCATE)
/* floats are allocated in heaps */
#define WORDBOX_SYMBOL_BIT_POS  2
#define WORDBOX_SYMBOL_SHIFT    WORDBOX_SYMBOL_BIT_POS
#define WORDBOX_SYMBOL_FLAG     (1 << (WORDBOX_SYMBOL_BIT_POS - 1))
#define WORDBOX_SYMBOL_MASK     ((1 << WORDBOX_SYMBOL_BIT_POS) - 1)
#else
#define WORDBOX_FLOAT_FLAG      2
#define WORDBOX_FLOAT_MASK      3
#if defined(MRB_64BIT)
#define WORDBOX_SYMBOL_SHIFT    32
#else  /* MRB_32BIT */
#define WORDBOX_SYMBOL_SHIFT    5
#endif
#define WORDBOX_SYMBOL_FLAG     0x1c
#define WORDBOX_SYMBOL_MASK     0x1f
#endif

#define WORDBOX_IMMEDIATE_MASK  0x07

#define WORDBOX_SET_SHIFT_VALUE(o,n,v) \
  ((o).w = (((uintptr_t)(v)) << WORDBOX_##n##_SHIFT) | WORDBOX_##n##_FLAG)
#define WORDBOX_SHIFT_VALUE_P(o,n) \
  (((o).w & WORDBOX_##n##_MASK) == WORDBOX_##n##_FLAG)
#define WORDBOX_OBJ_TYPE_P(o,n) \
  (!mrb_immediate_p(o) && mrb_val_union(o).bp->tt == MRB_TT_##n)

/*
 * mrb_value representation:
 *
 * 64bit word with inline float:
 *   nil   : ...0000 0000 (all bits are 0)
 *   false : ...0000 0100 (mrb_fixnum(v) != 0)
 *   true  : ...0000 1100
 *   undef : ...0001 0100
 *   symbol: ...0001 1100 (use only upper 32-bit as symbol value with MRB_64BIT)
 *   fixnum: ...IIII III1
 *   float : ...FFFF FF10 (51 bit significands; require MRB_64BIT)
 *   object: ...PPPP P000
 *
 * 32bit word with inline float:
 *   nil   : ...0000 0000 (all bits are 0)
 *   false : ...0000 0100 (mrb_fixnum(v) != 0)
 *   true  : ...0000 1100
 *   undef : ...0001 0100
 *   symbol: ...SSS1 0100 (symbol occupies 20bits)
 *   fixnum: ...IIII III1
 *   float : ...FFFF FF10 (22 bit significands; require MRB_64BIT)
 *   object: ...PPPP P000
 *
 * and word boxing without inline float (MRB_WORDBOX_NO_FLOAT_TRUNCATE):
 *   nil   : ...0000 0000 (all bits are 0)
 *   false : ...0000 0100 (mrb_fixnum(v) != 0)
 *   true  : ...0000 1100
 *   undef : ...0001 0100
 *   fixnum: ...IIII III1
 *   symbol: ...SSSS SS10
 *   object: ...PPPP P000 (any bits are 1)
 */
typedef struct mrb_value {
  uintptr_t w;
} mrb_value;

union mrb_value_ {
  void *p;
  struct RBasic *bp;
#ifndef MRB_NO_FLOAT
#ifndef MRB_WORDBOX_NO_FLOAT_TRUNCATE
  mrb_float f;
#else
  struct RFloat *fp;
#endif
#endif
  struct RInteger *ip;
  struct RCptr *vp;
  uintptr_t w;
  mrb_value value;
};

mrb_static_assert(sizeof(mrb_value) == sizeof(union mrb_value_));

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
MRB_API mrb_value mrb_boxing_int_value(struct mrb_state*, mrb_int);

#define mrb_immediate_p(o) ((o).w & WORDBOX_IMMEDIATE_MASK || (o).w == MRB_Qnil)

#define mrb_ptr(o)     mrb_val_union(o).p
#define mrb_cptr(o)    mrb_val_union(o).vp->p
#ifndef MRB_NO_FLOAT
#ifndef MRB_WORDBOX_NO_FLOAT_TRUNCATE
MRB_API mrb_float mrb_word_boxing_value_float(mrb_value v);
#define mrb_float(o) mrb_word_boxing_value_float(o)
#else
#define mrb_float(o) mrb_val_union(o).fp->f
#endif
#endif
#define mrb_fixnum(o)  (mrb_int)(((intptr_t)(o).w) >> WORDBOX_FIXNUM_SHIFT)
MRB_INLINE mrb_int
mrb_integer_func(mrb_value o) {
  if (mrb_immediate_p(o)) return mrb_fixnum(o);
  return mrb_val_union(o).ip->i;
}
#define mrb_integer(o) mrb_integer_func(o)
#define mrb_symbol(o)  (mrb_sym)(((o).w) >> WORDBOX_SYMBOL_SHIFT)
#define mrb_bool(o)    (((o).w & ~(uintptr_t)MRB_Qfalse) != 0)

#define mrb_fixnum_p(o) WORDBOX_SHIFT_VALUE_P(o, FIXNUM)
#define mrb_integer_p(o) (WORDBOX_SHIFT_VALUE_P(o, FIXNUM)||WORDBOX_OBJ_TYPE_P(o, INTEGER))
#define mrb_symbol_p(o) WORDBOX_SHIFT_VALUE_P(o, SYMBOL)
#define mrb_undef_p(o) ((o).w == MRB_Qundef)
#define mrb_nil_p(o)  ((o).w == MRB_Qnil)
#define mrb_false_p(o) ((o).w == MRB_Qfalse)
#define mrb_true_p(o)  ((o).w == MRB_Qtrue)
#ifndef MRB_NO_FLOAT
#ifndef MRB_WORDBOX_NO_FLOAT_TRUNCATE
#define mrb_float_p(o) WORDBOX_SHIFT_VALUE_P(o, FLOAT)
#else
#define mrb_float_p(o) WORDBOX_OBJ_TYPE_P(o, FLOAT)
#endif
#endif
#define mrb_array_p(o) WORDBOX_OBJ_TYPE_P(o, ARRAY)
#define mrb_string_p(o) WORDBOX_OBJ_TYPE_P(o, STRING)
#define mrb_hash_p(o) WORDBOX_OBJ_TYPE_P(o, HASH)
#define mrb_cptr_p(o) WORDBOX_OBJ_TYPE_P(o, CPTR)
#define mrb_exception_p(o) WORDBOX_OBJ_TYPE_P(o, EXCEPTION)
#define mrb_free_p(o) WORDBOX_OBJ_TYPE_P(o, FREE)
#define mrb_object_p(o) WORDBOX_OBJ_TYPE_P(o, OBJECT)
#define mrb_class_p(o) WORDBOX_OBJ_TYPE_P(o, CLASS)
#define mrb_module_p(o) WORDBOX_OBJ_TYPE_P(o, MODULE)
#define mrb_iclass_p(o) WORDBOX_OBJ_TYPE_P(o, ICLASS)
#define mrb_sclass_p(o) WORDBOX_OBJ_TYPE_P(o, SCLASS)
#define mrb_proc_p(o) WORDBOX_OBJ_TYPE_P(o, PROC)
#define mrb_range_p(o) WORDBOX_OBJ_TYPE_P(o, RANGE)
#define mrb_env_p(o) WORDBOX_OBJ_TYPE_P(o, ENV)
#define mrb_data_p(o) WORDBOX_OBJ_TYPE_P(o, DATA)
#define mrb_fiber_p(o) WORDBOX_OBJ_TYPE_P(o, FIBER)
#define mrb_istruct_p(o) WORDBOX_OBJ_TYPE_P(o, ISTRUCT)
#define mrb_break_p(o) WORDBOX_OBJ_TYPE_P(o, BREAK)

#ifndef MRB_NO_FLOAT
#define SET_FLOAT_VALUE(mrb,r,v) ((r) = mrb_word_boxing_float_value(mrb, v))
#endif
#define SET_CPTR_VALUE(mrb,r,v) ((r) = mrb_word_boxing_cptr_value(mrb, v))
#define SET_UNDEF_VALUE(r) ((r).w = MRB_Qundef)
#define SET_NIL_VALUE(r) ((r).w = MRB_Qnil)
#define SET_FALSE_VALUE(r) ((r).w = MRB_Qfalse)
#define SET_TRUE_VALUE(r) ((r).w = MRB_Qtrue)
#define SET_BOOL_VALUE(r,b) ((b) ? SET_TRUE_VALUE(r) : SET_FALSE_VALUE(r))
#define SET_INT_VALUE(mrb,r,n) ((r) = mrb_boxing_int_value(mrb, n))
#define SET_FIXNUM_VALUE(r,n) WORDBOX_SET_SHIFT_VALUE(r, FIXNUM, n)
#define SET_SYM_VALUE(r,n) WORDBOX_SET_SHIFT_VALUE(r, SYMBOL, n)
#define SET_OBJ_VALUE(r,v) ((r).w = (uintptr_t)(v))

MRB_INLINE enum mrb_vtype
mrb_type(mrb_value o)
{
  return !mrb_bool(o)    ? MRB_TT_FALSE :
         mrb_true_p(o)   ? MRB_TT_TRUE :
         mrb_fixnum_p(o) ? MRB_TT_INTEGER :
         mrb_symbol_p(o) ? MRB_TT_SYMBOL :
         mrb_undef_p(o)  ? MRB_TT_UNDEF :
#ifndef MRB_NO_FLOAT
         mrb_float_p(o)  ? MRB_TT_FLOAT :
#endif
         mrb_val_union(o).bp->tt;
}

#endif  /* MRUBY_BOXING_WORD_H */
