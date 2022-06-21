/**
** @file mruby/range.h - Range class
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

#if defined(MRB_NAN_BOXING) && defined(MRB_64BIT) || defined(MRB_WORD_BOXING)
# define MRB_RANGE_EMBED
#endif

#ifdef MRB_RANGE_EMBED
struct RRange {
  MRB_OBJECT_HEADER;
  mrb_value beg;
  mrb_value end;
  mrb_bool excl;
};
# define mrb_gc_free_range(mrb, p) ((void)0)
# define RANGE_BEG(p) ((p)->beg)
# define RANGE_END(p) ((p)->end)
#else
typedef struct mrb_range_edges {
  mrb_value beg;
  mrb_value end;
} mrb_range_edges;
struct RRange {
  MRB_OBJECT_HEADER;
  mrb_range_edges *edges;
  mrb_bool excl;
};
# define mrb_gc_free_range(mrb, p) mrb_free(mrb, (p)->edges)
# define RANGE_BEG(p) ((p)->edges->beg)
# define RANGE_END(p) ((p)->edges->end)
#endif

#define mrb_range_beg(mrb, r) RANGE_BEG(mrb_range_ptr(mrb, r))
#define mrb_range_end(mrb, r) RANGE_END(mrb_range_ptr(mrb, r))
#define mrb_range_excl_p(mrb, r) RANGE_EXCL(mrb_range_ptr(mrb, r))
#define mrb_range_raw_ptr(r) ((struct RRange*)mrb_ptr(r))
#define mrb_range_value(p) mrb_obj_value((void*)(p))
#define RANGE_EXCL(p) ((p)->excl)

MRB_API struct RRange* mrb_range_ptr(mrb_state *mrb, mrb_value range);

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

enum mrb_range_beg_len {
  MRB_RANGE_TYPE_MISMATCH = 0,  /* (failure) not range */
  MRB_RANGE_OK = 1,             /* (success) range */
  MRB_RANGE_OUT = 2             /* (failure) out of range */
};

MRB_API enum mrb_range_beg_len mrb_range_beg_len(mrb_state *mrb, mrb_value range, mrb_int *begp, mrb_int *lenp, mrb_int len, mrb_bool trunc);
mrb_value mrb_get_values_at(mrb_state *mrb, mrb_value obj, mrb_int olen, mrb_int argc, const mrb_value *argv, mrb_value (*func)(mrb_state*, mrb_value, mrb_int));
void mrb_gc_mark_range(mrb_state *mrb, struct RRange *r);

MRB_END_DECL

#endif  /* MRUBY_RANGE_H */
