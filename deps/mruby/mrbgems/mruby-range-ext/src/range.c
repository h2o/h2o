#include <mruby.h>
#include <mruby/range.h>
#include <math.h>

static mrb_bool
r_le(mrb_state *mrb, mrb_value a, mrb_value b)
{
  mrb_value r = mrb_funcall(mrb, a, "<=>", 1, b); /* compare result */
  /* output :a < b => -1, a = b =>  0, a > b => +1 */

  if (mrb_fixnum_p(r)) {
    mrb_int c = mrb_fixnum(r);
    if (c == 0 || c == -1) return TRUE;
  }

  return FALSE;
}

static mrb_bool
r_lt(mrb_state *mrb, mrb_value a, mrb_value b)
{
  mrb_value r = mrb_funcall(mrb, a, "<=>", 1, b);
  /* output :a < b => -1, a = b =>  0, a > b => +1 */

  return mrb_fixnum_p(r) && mrb_fixnum(r) == -1;
}

/*
 *  call-seq:
 *     rng.cover?(obj)  ->  true or false
 *
 *  Returns <code>true</code> if +obj+ is between the begin and end of
 *  the range.
 *
 *  This tests <code>begin <= obj <= end</code> when #exclude_end? is +false+
 *  and <code>begin <= obj < end</code> when #exclude_end? is +true+.
 *
 *     ("a".."z").cover?("c")    #=> true
 *     ("a".."z").cover?("5")    #=> false
 *     ("a".."z").cover?("cc")   #=> true
 */
static mrb_value
mrb_range_cover(mrb_state *mrb, mrb_value range)
{
  mrb_value val;
  struct RRange *r = mrb_range_ptr(mrb, range);
  mrb_value beg, end;

  mrb_get_args(mrb, "o", &val);

  beg = r->edges->beg;
  end = r->edges->end;

  if (r_le(mrb, beg, val)) {
    if (r->excl) {
      if (r_lt(mrb, val, end))
        return mrb_true_value();
    }
    else {
      if (r_le(mrb, val, end))
        return mrb_true_value();
    }
  }

  return mrb_false_value();
}

/*
 *  call-seq:
 *     rng.last    -> obj
 *     rng.last(n) -> an_array
 *
 *  Returns the last object in the range,
 *  or an array of the last +n+ elements.
 *
 *  Note that with no arguments +last+ will return the object that defines
 *  the end of the range even if #exclude_end? is +true+.
 *
 *    (10..20).last      #=> 20
 *    (10...20).last     #=> 20
 *    (10..20).last(3)   #=> [18, 19, 20]
 *    (10...20).last(3)  #=> [17, 18, 19]
 */
static mrb_value
mrb_range_last(mrb_state *mrb, mrb_value range)
{
  mrb_value num;
  mrb_value array;
  struct RRange *r = mrb_range_ptr(mrb, range);

  if (mrb_get_args(mrb, "|o", &num) == 0) {
    return r->edges->end;
  }

  array = mrb_funcall(mrb, range, "to_a", 0);
  return mrb_funcall(mrb, array, "last", 1, mrb_to_int(mrb, num));
}

/*
 *  call-seq:
 *     rng.size                   -> num
 *
 *  Returns the number of elements in the range. Both the begin and the end of
 *  the Range must be Numeric, otherwise nil is returned.
 *
 *    (10..20).size    #=> 11
 *    ('a'..'z').size  #=> nil
 */

static mrb_value
mrb_range_size(mrb_state *mrb, mrb_value range)
{
  struct RRange *r = mrb_range_ptr(mrb, range);
  mrb_value beg, end;
  mrb_float beg_f, end_f;
  mrb_bool num_p = TRUE;
  mrb_bool excl;

  beg = r->edges->beg;
  end = r->edges->end;
  excl = r->excl;
  if (mrb_fixnum_p(beg)) {
    beg_f = (mrb_float)mrb_fixnum(beg);
  }
  else if (mrb_float_p(beg)) {
    beg_f = mrb_float(beg);
  }
  else {
    num_p = FALSE;
  }
  if (mrb_fixnum_p(end)) {
    end_f = (mrb_float)mrb_fixnum(end);
  }
  else if (mrb_float_p(end)) {
    end_f = mrb_float(end);
  }
  else {
    num_p = FALSE;
  }
  if (num_p) {
    mrb_float n = end_f - beg_f;
    mrb_float err = (fabs(beg_f) + fabs(end_f) + fabs(end_f-beg_f)) * MRB_FLOAT_EPSILON;

    if (err>0.5) err=0.5;
    if (excl) {
      if (n<=0) return mrb_fixnum_value(0);
      if (n<1)
        n = 0;
      else
        n = floor(n - err);
    }
    else {
      if (n<0) return mrb_fixnum_value(0);
      n = floor(n + err);
    }
    if (isinf(n+1))
      return mrb_float_value(mrb, INFINITY);
    return mrb_fixnum_value((mrb_int)n+1);
  }
  return mrb_nil_value();
}

void
mrb_mruby_range_ext_gem_init(mrb_state* mrb)
{
  struct RClass * s = mrb_class_get(mrb, "Range");

  mrb_define_method(mrb, s, "cover?", mrb_range_cover, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, s, "last",   mrb_range_last,  MRB_ARGS_OPT(1));
  mrb_define_method(mrb, s, "size",   mrb_range_size,  MRB_ARGS_NONE());
}

void
mrb_mruby_range_ext_gem_final(mrb_state* mrb)
{
}
