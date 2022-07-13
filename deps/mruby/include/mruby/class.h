/**
** @file mruby/class.h - Class class
**
** See Copyright Notice in mruby.h
*/

#ifndef MRUBY_CLASS_H
#define MRUBY_CLASS_H

#include "common.h"

/**
 * Class class
 */
MRB_BEGIN_DECL

struct RClass {
  MRB_OBJECT_HEADER;
  struct iv_tbl *iv;
  struct mt_tbl *mt;
  struct RClass *super;
};

#define mrb_class_ptr(v)    ((struct RClass*)(mrb_ptr(v)))

MRB_INLINE struct RClass*
mrb_class(mrb_state *mrb, mrb_value v)
{
  switch (mrb_type(v)) {
  case MRB_TT_FALSE:
    if (mrb_fixnum(v))
      return mrb->false_class;
    return mrb->nil_class;
  case MRB_TT_TRUE:
    return mrb->true_class;
  case MRB_TT_SYMBOL:
    return mrb->symbol_class;
  case MRB_TT_INTEGER:
    return mrb->integer_class;
#ifndef MRB_NO_FLOAT
  case MRB_TT_FLOAT:
    return mrb->float_class;
#endif
  case MRB_TT_CPTR:
    return mrb->object_class;
  case MRB_TT_ENV:
    return NULL;
  default:
    return mrb_obj_ptr(v)->c;
  }
}

/* flags:
   20: frozen
   19: is_prepended
   18: is_origin
   17: is_inherited (used by method cache)
   16: unused
   0-15: instance type
*/
#define MRB_FL_CLASS_IS_PREPENDED (1 << 19)
#define MRB_FL_CLASS_IS_ORIGIN (1 << 18)
#define MRB_CLASS_ORIGIN(c) do {\
  if ((c)->flags & MRB_FL_CLASS_IS_PREPENDED) {\
    (c) = (c)->super;\
    while (!((c)->flags & MRB_FL_CLASS_IS_ORIGIN)) {\
      (c) = (c)->super;\
    }\
  }\
} while (0)
#define MRB_FL_CLASS_IS_INHERITED (1 << 17)
#define MRB_INSTANCE_TT_MASK (0xFF)
#define MRB_SET_INSTANCE_TT(c, tt) ((c)->flags = (((c)->flags & ~MRB_INSTANCE_TT_MASK) | (char)(tt)))
#define MRB_INSTANCE_TT(c) (enum mrb_vtype)((c)->flags & MRB_INSTANCE_TT_MASK)

MRB_API void mrb_define_method_raw(mrb_state*, struct RClass*, mrb_sym, mrb_method_t);
MRB_API void mrb_alias_method(mrb_state*, struct RClass *c, mrb_sym a, mrb_sym b);
MRB_API void mrb_remove_method(mrb_state *mrb, struct RClass *c, mrb_sym sym);

MRB_API mrb_method_t mrb_method_search_vm(mrb_state*, struct RClass**, mrb_sym);
MRB_API mrb_method_t mrb_method_search(mrb_state*, struct RClass*, mrb_sym);

MRB_API struct RClass* mrb_class_real(struct RClass* cl);

#ifndef MRB_NO_METHOD_CACHE
void mrb_mc_clear_by_class(mrb_state *mrb, struct RClass* c);
#else
#define mrb_mc_clear_by_class(mrb,c)
#endif

/* return non zero to break the loop */
typedef int (mrb_mt_foreach_func)(mrb_state*,mrb_sym,mrb_method_t,void*);
MRB_API void mrb_mt_foreach(mrb_state*, struct RClass*, mrb_mt_foreach_func*, void*);

MRB_END_DECL

#endif  /* MRUBY_CLASS_H */
