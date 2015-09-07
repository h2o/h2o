/*
** mruby/range.h - Range class
**
** See Copyright Notice in mruby.h
*/

#ifndef MRUBY_RANGE_H
#define MRUBY_RANGE_H

#if defined(__cplusplus)
extern "C" {
#endif

typedef struct mrb_range_edges {
  mrb_value beg;
  mrb_value end;
} mrb_range_edges;

struct RRange {
  MRB_OBJECT_HEADER;
  mrb_range_edges *edges;
  mrb_bool excl : 1;
};

#define mrb_range_ptr(v)    ((struct RRange*)(mrb_ptr(v)))
#define mrb_range_value(p)  mrb_obj_value((void*)(p))

MRB_API mrb_value mrb_range_new(mrb_state*, mrb_value, mrb_value, mrb_bool);
MRB_API mrb_bool mrb_range_beg_len(mrb_state *mrb, mrb_value range, mrb_int *begp, mrb_int *lenp, mrb_int len);
mrb_value mrb_get_values_at(mrb_state *mrb, mrb_value obj, mrb_int olen, mrb_int argc, const mrb_value *argv, mrb_value (*func)(mrb_state*, mrb_value, mrb_int));

#if defined(__cplusplus)
}  /* extern "C" { */
#endif

#endif  /* MRUBY_RANGE_H */
