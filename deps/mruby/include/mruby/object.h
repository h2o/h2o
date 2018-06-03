/*
** mruby/object.h - mruby object definition
**
** See Copyright Notice in mruby.h
*/

#ifndef MRUBY_OBJECT_H
#define MRUBY_OBJECT_H

#define MRB_OBJECT_HEADER \
  enum mrb_vtype tt:8;\
  uint32_t color:3;\
  uint32_t flags:21;\
  struct RClass *c;\
  struct RBasic *gcnext

#define MRB_FLAG_TEST(obj, flag) ((obj)->flags & flag)


struct RBasic {
  MRB_OBJECT_HEADER;
};
#define mrb_basic_ptr(v) ((struct RBasic*)(mrb_ptr(v)))

/* flags bits >= 18 is reserved */
#define MRB_FLAG_IS_FROZEN (1 << 18)
#define MRB_FROZEN_P(o) ((o)->flags & MRB_FLAG_IS_FROZEN)
#define MRB_SET_FROZEN_FLAG(o) ((o)->flags |= MRB_FLAG_IS_FROZEN)
#define MRB_UNSET_FROZEN_FLAG(o) ((o)->flags &= ~MRB_FLAG_IS_FROZEN)

struct RObject {
  MRB_OBJECT_HEADER;
  struct iv_tbl *iv;
};
#define mrb_obj_ptr(v)   ((struct RObject*)(mrb_ptr(v)))

#define mrb_immediate_p(x) (mrb_type(x) < MRB_TT_HAS_BASIC)
#define mrb_special_const_p(x) mrb_immediate_p(x)

struct RFiber {
  MRB_OBJECT_HEADER;
  struct mrb_context *cxt;
};

#endif  /* MRUBY_OBJECT_H */
