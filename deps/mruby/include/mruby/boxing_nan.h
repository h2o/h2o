/*
** mruby/boxing_nan.h - nan boxing mrb_value definition
**
** See Copyright Notice in mruby.h
*/

#ifndef MRUBY_BOXING_NAN_H
#define MRUBY_BOXING_NAN_H

#ifdef MRB_USE_FLOAT
# error ---->> MRB_NAN_BOXING and MRB_USE_FLOAT conflict <<----
#endif

#ifdef MRB_INT64
# error ---->> MRB_NAN_BOXING and MRB_INT64 conflict <<----
#endif

#define MRB_FIXNUM_SHIFT 0
#define MRB_TT_HAS_BASIC MRB_TT_OBJECT

#ifdef MRB_ENDIAN_BIG
#define MRB_ENDIAN_LOHI(a,b) a b
#else
#define MRB_ENDIAN_LOHI(a,b) b a
#endif

/* value representation by nan-boxing:
 *   float : FFFFFFFFFFFFFFFF FFFFFFFFFFFFFFFF FFFFFFFFFFFFFFFF FFFFFFFFFFFFFFFF
 *   object: 111111111111TTTT TTPPPPPPPPPPPPPP PPPPPPPPPPPPPPPP PPPPPPPPPPPPPPPP
 *   int   : 1111111111110001 0000000000000000 IIIIIIIIIIIIIIII IIIIIIIIIIIIIIII
 *   sym   : 1111111111110001 0100000000000000 SSSSSSSSSSSSSSSS SSSSSSSSSSSSSSSS
 * In order to get enough bit size to save TT, all pointers are shifted 2 bits
 * in the right direction. Also, TTTTTT is the mrb_vtype + 1;
 */
typedef struct mrb_value {
  union {
    mrb_float f;
    union {
      void *p;
      struct {
        MRB_ENDIAN_LOHI(
          uint32_t ttt;
          ,union {
            mrb_int i;
            mrb_sym sym;
          };
        )
      };
    } value;
  };
} mrb_value;

#define mrb_float_pool(mrb,f) mrb_float_value(mrb,f)

#define mrb_tt(o)       ((enum mrb_vtype)(((o).value.ttt & 0xfc000)>>14)-1)
#define mrb_type(o)     (enum mrb_vtype)((uint32_t)0xfff00000 < (o).value.ttt ? mrb_tt(o) : MRB_TT_FLOAT)
#define mrb_ptr(o)      ((void*)((((uintptr_t)0x3fffffffffff)&((uintptr_t)((o).value.p)))<<2))
#define mrb_float(o)    (o).f
#define mrb_cptr(o)     mrb_ptr(o)
#define mrb_fixnum(o)   (o).value.i
#define mrb_symbol(o)   (o).value.sym

#ifdef MRB_64BIT
#define BOXNAN_SHIFT_LONG_POINTER(v) (((uintptr_t)(v)>>34)&0x3fff)
#else
#define BOXNAN_SHIFT_LONG_POINTER(v) 0
#endif

#define BOXNAN_SET_VALUE(o, tt, attr, v) do {\
  (o).attr = (v);\
  (o).value.ttt = 0xfff00000 | (((tt)+1)<<14);\
} while (0)

#define BOXNAN_SET_OBJ_VALUE(o, tt, v) do {\
  (o).value.p = (void*)((uintptr_t)(v)>>2);\
  (o).value.ttt = (0xfff00000|(((tt)+1)<<14)|BOXNAN_SHIFT_LONG_POINTER(v));\
} while (0)

#define SET_FLOAT_VALUE(mrb,r,v) do { \
  if (v != v) { \
    (r).value.ttt = 0x7ff80000; \
    (r).value.i = 0; \
  } \
  else { \
    (r).f = v; \
  }} while(0)

#define SET_NIL_VALUE(r) BOXNAN_SET_VALUE(r, MRB_TT_FALSE, value.i, 0)
#define SET_FALSE_VALUE(r) BOXNAN_SET_VALUE(r, MRB_TT_FALSE, value.i, 1)
#define SET_TRUE_VALUE(r) BOXNAN_SET_VALUE(r, MRB_TT_TRUE, value.i, 1)
#define SET_BOOL_VALUE(r,b) BOXNAN_SET_VALUE(r, b ? MRB_TT_TRUE : MRB_TT_FALSE, value.i, 1)
#define SET_INT_VALUE(r,n) BOXNAN_SET_VALUE(r, MRB_TT_FIXNUM, value.i, (n))
#define SET_SYM_VALUE(r,v) BOXNAN_SET_VALUE(r, MRB_TT_SYMBOL, value.sym, (v))
#define SET_OBJ_VALUE(r,v) BOXNAN_SET_OBJ_VALUE(r, (((struct RObject*)(v))->tt), (v))
#define SET_CPTR_VALUE(mrb,r,v) BOXNAN_SET_OBJ_VALUE(r, MRB_TT_CPTR, v)
#define SET_UNDEF_VALUE(r) BOXNAN_SET_VALUE(r, MRB_TT_UNDEF, value.i, 0)

#endif  /* MRUBY_BOXING_NAN_H */
