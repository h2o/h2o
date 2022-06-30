#include <mruby.h>
#include <mruby/range.h>

static mrb_bool
r_less(mrb_state *mrb, mrb_value a, mrb_value b, mrb_bool excl)
{
  switch (mrb_cmp(mrb, a, b)) {
  case -2:                      /* failure */
  case 1:
    return FALSE;
  case 0:
    return !excl;
  case -1:
  default:                      /* just in case */
    return TRUE;
  }
}

/*
 *  call-seq:
 *     rng.cover?(obj)  ->  true or false
 *     rng.cover?(range) -> true or false
 *
 *  Returns +true+ if the given argument is within +self+, +false+ otherwise.
 *
 *  With non-range argument +object+, evaluates with <tt><=</tt> and <tt><</tt>.
 *
 *  For range +self+ with included end value (<tt>#exclude_end? == false</tt>),
 *  evaluates thus:
 *
 *    self.begin <= object <= self.end
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

  if (mrb_nil_p(beg) && mrb_nil_p(end)) return mrb_true_value();

  if (mrb_range_p(val)) {
    struct RRange *r2 = mrb_range_ptr(mrb, val);
    mrb_value beg2 = RANGE_BEG(r2);
    mrb_value end2 = RANGE_END(r2);

    /* range.cover?(nil..nil) => true */
    if (mrb_nil_p(beg2) && mrb_nil_p(end2)) return mrb_true_value();

    /* (a..b).cover?(c..d) */
    if (mrb_nil_p(end)) {       /* a.. */
      /* (a..).cover?(c..) => true */
      if (mrb_nil_p(end2)) return mrb_bool_value(mrb_cmp(mrb, beg, beg2) != -2);
      /* (a..).cover?(c..d) where d<a => false */
      if (r_less(mrb, end2, beg, RANGE_EXCL(r2))) return mrb_false_value();
      return mrb_true_value();
    }
    else if (mrb_nil_p(beg)) {  /* ..b */
      /* (..b).cover?(..d) => true */
      if (mrb_nil_p(beg2)) return mrb_bool_value(mrb_cmp(mrb, end, end2) != -2);
      /* (..b).cover?(c..d) where b<c => false */
      if (r_less(mrb, end, beg2, RANGE_EXCL(r))) return mrb_false_value();
      return mrb_true_value();
    }
    else {                      /* a..b */
      /* (a..b).cover?(c..) => (c<b) */
      if (mrb_nil_p(end2))
        return mrb_bool_value(r_less(mrb, beg2, end, RANGE_EXCL(r)));
      /* (a..b).cover?(..d) => (a<d) */
      if (mrb_nil_p(beg2))
        return mrb_bool_value(r_less(mrb, beg, end2, RANGE_EXCL(r2)));
      /* (a..b).cover?(c..d) where (b<c) => false */
      if (r_less(mrb, end, beg2, RANGE_EXCL(r))) return mrb_false_value();
      /* (a..b).cover?(c..d) where (d<a) => false */
      if (r_less(mrb, end2, beg, RANGE_EXCL(r2))) return mrb_false_value();
      return mrb_true_value();
    }
  }

  if (mrb_nil_p(beg) || r_less(mrb, beg, val, FALSE)) {
    if (mrb_nil_p(end)) {
      return mrb_true_value();
    }
    if (r_less(mrb, val, end, RANGE_EXCL(r)))
      return mrb_true_value();
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
