/*
** enum.c - Enumerable module
**
** See Copyright Notice in mruby.h
*/

#include <mruby.h>
#include <mruby/proc.h>

/* internal method `__update_hash(oldhash, index, itemhash)` */
static mrb_value
enum_update_hash(mrb_state *mrb, mrb_value self)
{
  mrb_int hash;
  mrb_int index;
  mrb_int hv;
  mrb_value item_hash;

  mrb_get_args(mrb, "iio", &hash, &index, &item_hash);
  if (mrb_fixnum_p(item_hash)) {
    hv = mrb_fixnum(item_hash);
  }
#ifndef MRB_WITHOUT_FLOAT
  else if (mrb_float_p(item_hash)) {
    hv = (mrb_int)mrb_float(item_hash);
  }
#endif
  else {
    mrb_raise(mrb, E_TYPE_ERROR, "can't calculate hash");
    /* not reached */
    hv = 0;
  }
  hash ^= (hv << (index % 16));

  return mrb_fixnum_value(hash);
}

void
mrb_init_enumerable(mrb_state *mrb)
{
  struct RClass *enumerable;
  enumerable = mrb_define_module(mrb, "Enumerable");  /* 15.3.2 */
  mrb_define_module_function(mrb, enumerable, "__update_hash", enum_update_hash, MRB_ARGS_REQ(1));
}
