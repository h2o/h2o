#include <stdlib.h>
#include <mruby.h>
#include <mruby/class.h>

/* copy of mrb_instance_alloc (see include/mruby.h for copyright) */
static mrb_value class_allocate(mrb_state *mrb, mrb_value cv)
{
  struct RClass *c = mrb_class_ptr(cv);
  struct RObject *o;
  enum mrb_vtype ttype = MRB_INSTANCE_TT(c);

  if (c->tt == MRB_TT_SCLASS)
    mrb_raise(mrb, E_TYPE_ERROR, "can't create instance of singleton class");

  if (ttype == 0) ttype = MRB_TT_OBJECT;
  if (ttype <= MRB_TT_CPTR) {
    mrb_raisef(mrb, E_TYPE_ERROR, "can't create instance of %S", cv);
  }
  o = (struct RObject*)mrb_obj_alloc(mrb, ttype, c);
  return mrb_obj_value(o);
}

void mrb_mruby_class_new_fiber_safe_gem_init(mrb_state* mrb)
{
    struct RClass *cls = mrb->class_class;
    mrb_define_method(mrb, cls, "allocate", class_allocate, MRB_ARGS_NONE());
}

void mrb_mruby_class_new_fiber_safe_gem_final(mrb_state* mrb)
{
}
