#include <mruby.h>
#include <mruby/range.h>

static mrb_bool
r_le(mrb_state *mrb, mrb_value a, mrb_value b)
{
  mrb_int n = mrb_cmp(mrb, a, b);

  if (n == 0 || n == -1) return TRUE;
  return FALSE;
}

static mrb_bool
r_lt(mrb_state *mrb, mrb_value a, mrb_value b)
{
  return mrb_cmp(mrb, a, b) == -1;
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
range_cover(mrb_state *mrb, mrb_value range)
{
  struct RRange *r = mrb_range_ptr(mrb, range);
  mrb_value val = mrb_get_arg1(mrb);
  mrb_value beg, end;

  beg = RANGE_BEG(r);
  end = RANGE_END(r);

  if (r_le(mrb, beg, val)) {
    if (mrb_nil_p(end)) {
      return mrb_true_value();
    }
    if (RANGE_EXCL(r)) {
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
 *     rng.size                   -> num
 *
 *  Returns the number of elements in the range. Both the begin and the end of
 *  the Range must be Numeric, otherwise nil is returned.
 *
 *    (10..20).size    #=> 11
 *    ('a'..'z').size  #=> nil
 */

#ifndef MRB_NO_FLOAT
static mrb_value
range_size(mrb_state *mrb, mrb_value range)
{
  struct RRange *r = mrb_range_ptr(mrb, range);
  mrb_value beg, end;
  mrb_float beg_f, end_f;
  mrb_bool num_p = TRUE;
  mrb_bool excl;

  beg = RANGE_BEG(r);
  end = RANGE_END(r);
  if ((mrb_integer_p(beg) || mrb_float_p(beg)) && mrb_nil_p(end)) {
    return mrb_float_value(mrb, INFINITY);
  }

  excl = RANGE_EXCL(r);
  if (mrb_integer_p(beg)) {
    beg_f = (mrb_float)mrb_integer(beg);
  }
  else if (mrb_float_p(beg)) {
    beg_f = mrb_float(beg);
  }
  else {
    num_p = FALSE;
  }
  if (mrb_integer_p(end)) {
    end_f = (mrb_float)mrb_integer(end);
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
#else
static mrb_value
range_size(mrb_state *mrb, mrb_value range)
{
  struct RRange *r = mrb_range_ptr(mrb, range);
  mrb_value beg, end;
  mrb_int excl;

  beg = RANGE_BEG(r);
  end = RANGE_END(r);
  if (mrb_integer_p(beg) && mrb_nil_p(end)) {
    return mrb_nil_value();
  }

  excl = RANGE_EXCL(r) ? 0 : 1;

  if (mrb_integer_p(beg) && mrb_integer_p(end)) {
    mrb_int a = mrb_integer(beg);
    mrb_int b = mrb_integer(end);
    mrb_int c = b - a + excl;

    return mrb_int_value(mrb, c);
  }
  return mrb_nil_value();
}
#endif /* MRB_NO_FLOAT */

void
mrb_mruby_range_ext_gem_init(mrb_state* mrb)
{
  struct RClass * s = mrb_class_get(mrb, "Range");

  mrb_define_method(mrb, s, "cover?", range_cover, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, s, "size",   range_size,  MRB_ARGS_NONE());
}

void
mrb_mruby_range_ext_gem_final(mrb_state* mrb)
{
}
