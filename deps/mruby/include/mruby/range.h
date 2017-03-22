/*
** mruby/range.h - Range class
**
** See Copyright Notice in mruby.h
*/

#ifndef MRUBY_RANGE_H
#define MRUBY_RANGE_H

#include "common.h"

/**
 * Range class
 */
MRB_BEGIN_DECL

typedef struct mrb_range_edges {
  mrb_value beg;
  mrb_value end;
} mrb_range_edges;

struct RRange {
  MRB_OBJECT_HEADER;
  mrb_range_edges *edges;
  mrb_bool excl : 1;
};

MRB_API struct RRange* mrb_range_ptr(mrb_state *mrb, mrb_value v);
#define mrb_range_raw_ptr(v) ((struct RRange*)mrb_ptr(v))
#define mrb_range_value(p)  mrb_obj_value((void*)(p))

/*
 * Initializes a Range.
 *
 * If the third parameter is FALSE then it includes the last value in the range.
 * If the third parameter is TRUE then it excludes the last value in the range.
 *
 * @param start the beginning value.
 * @param end the ending value.
 * @param exclude represents the inclusion or exclusion of the last value.
 */
MRB_API mrb_value mrb_range_new(mrb_state *mrb, mrb_value start, mrb_value end, mrb_bool exclude);

MRB_API mrb_int mrb_range_beg_len(mrb_state *mrb, mrb_value range, mrb_int *begp, mrb_int *lenp, mrb_int len, mrb_bool trunc);
mrb_value mrb_get_values_at(mrb_state *mrb, mrb_value obj, mrb_int olen, mrb_int argc, const mrb_value *argv, mrb_value (*func)(mrb_state*, mrb_value, mrb_int));

MRB_END_DECL

#endif  /* MRUBY_RANGE_H */
