/*
** range.c - Range class
**
** See Copyright Notice in mruby.h
*/

#include <mruby.h>
#include <mruby/class.h>
#include <mruby/range.h>
#include <mruby/string.h>
#include <mruby/array.h>
#include <mruby/numeric.h>
#include <mruby/presym.h>

#define RANGE_INITIALIZED_FLAG 1
#define RANGE_INITIALIZED(p) ((p)->flags |= RANGE_INITIALIZED_FLAG)
#define RANGE_INITIALIZED_P(p) ((p)->flags & RANGE_INITIALIZED_FLAG)

static void
r_check(mrb_state *mrb, mrb_value a, mrb_value b)
{
  enum mrb_vtype ta;
  enum mrb_vtype tb;
  mrb_int n;

  ta = mrb_type(a);
  tb = mrb_type(b);
#ifdef MRB_NO_FLOAT
  if (ta == MRB_TT_INTEGER && tb == MRB_TT_INTEGER ) return;
#else
  if ((ta == MRB_TT_INTEGER || ta == MRB_TT_FLOAT) &&
      (tb == MRB_TT_INTEGER || tb == MRB_TT_FLOAT)) {
    return;
  }
#endif

  if (mrb_nil_p(a) || mrb_nil_p(b)) return;

  n = mrb_cmp(mrb, a, b);
  if (n == -2) {                /* can not be compared */
    mrb_raise(mrb, E_ARGUMENT_ERROR, "bad value for range");
  }
}

static mrb_bool
r_le(mrb_state *mrb, mrb_value a, mrb_value b)
{
  mrb_int n = mrb_cmp(mrb, a, b);

  if (n == 0 || n == -1) return TRUE;
  return FALSE;
}

static mrb_bool
r_gt(mrb_state *mrb, mrb_value a, mrb_value b)
{
  return mrb_cmp(mrb, a, b) == 1;
}

static mrb_bool
r_ge(mrb_state *mrb, mrb_value a, mrb_value b)
{
  mrb_int n = mrb_cmp(mrb, a, b);

  if (n == 0 || n == 1) return TRUE;
  return FALSE;
}

static void
range_ptr_alloc_edges(mrb_state *mrb, struct RRange *r)
{
#ifndef MRB_RANGE_EMBED
  r->edges = (mrb_range_edges *)mrb_malloc(mrb, sizeof(mrb_range_edges));
#endif
}

static struct RRange *
range_ptr_init(mrb_state *mrb, struct RRange *r, mrb_value beg, mrb_value end, mrb_bool excl)
{
  r_check(mrb, beg, end);

  if (r) {
    if (RANGE_INITIALIZED_P(r)) {
      /* Ranges are immutable, so that they should be initialized only once. */
      mrb_name_error(mrb, MRB_SYM(initialize), "'initialize' called twice");
    }
    else {
      range_ptr_alloc_edges(mrb, r);
    }
  }
  else {
    r = MRB_OBJ_ALLOC(mrb, MRB_TT_RANGE, mrb->range_class);
    range_ptr_alloc_edges(mrb, r);
  }

  RANGE_BEG(r) = beg;
  RANGE_END(r) = end;
  RANGE_EXCL(r) = excl;
  RANGE_INITIALIZED(r);

  return r;
}

static void
range_ptr_replace(mrb_state *mrb, struct RRange *r, mrb_value beg, mrb_value end, mrb_bool excl)
{
  range_ptr_init(mrb, r, beg, end, excl);
  mrb_write_barrier(mrb, (struct RBasic*)r);
}

/*
 *  call-seq:
 *     rng.first    => obj
 *     rng.begin    => obj
 *
 *  Returns the first object in <i>rng</i>.
 */
static mrb_value
range_beg(mrb_state *mrb, mrb_value range)
{
  return mrb_range_beg(mrb, range);
}

/*
 *  call-seq:
 *     rng.end    => obj
 *     rng.last   => obj
 *
 *  Returns the object that defines the end of <i>rng</i>.
 *
 *     (1..10).end    #=> 10
 *     (1...10).end   #=> 10
 */
static mrb_value
range_end(mrb_state *mrb, mrb_value range)
{
  return mrb_range_end(mrb, range);
}

/*
 *  call-seq:
 *     range.exclude_end?    => true or false
 *
 *  Returns <code>true</code> if <i>range</i> excludes its end value.
 */
static mrb_value
range_excl(mrb_state *mrb, mrb_value range)
{
  return mrb_bool_value(mrb_range_excl_p(mrb, range));
}

/*
 *  call-seq:
 *     Range.new(start, end, exclusive=false)    => range
 *
 *  Constructs a range using the given <i>start</i> and <i>end</i>. If the third
 *  parameter is omitted or is <code>false</code>, the <i>range</i> will include
 *  the end object; otherwise, it will be excluded.
 */
static mrb_value
range_initialize(mrb_state *mrb, mrb_value range)
{
  mrb_value beg, end;
  mrb_bool exclusive = FALSE;

  mrb_get_args(mrb, "oo|b", &beg, &end, &exclusive);
  range_ptr_replace(mrb, mrb_range_raw_ptr(range), beg, end, exclusive);
  mrb_obj_freeze(mrb, range);
  return range;
}

/*
 *  call-seq:
 *     range == obj    => true or false
 *
 *  Returns <code>true</code> only if
 *  1) <i>obj</i> is a Range,
 *  2) <i>obj</i> has equivalent beginning and end items (by comparing them with <code>==</code>),
 *  3) <i>obj</i> has the same #exclude_end? setting as <i>rng</t>.
 *
 *    (0..2) == (0..2)            #=> true
 *    (0..2) == Range.new(0,2)    #=> true
 *    (0..2) == (0...2)           #=> false
 */
static mrb_value
range_eq(mrb_state *mrb, mrb_value range)
{
  struct RRange *rr;
  struct RRange *ro;
  mrb_value obj = mrb_get_arg1(mrb);
  mrb_bool v1, v2;

  if (mrb_obj_equal(mrb, range, obj)) return mrb_true_value();
  if (!mrb_obj_is_instance_of(mrb, obj, mrb_obj_class(mrb, range))) { /* same class? */
    return mrb_false_value();
  }

  rr = mrb_range_ptr(mrb, range);
  ro = mrb_range_ptr(mrb, obj);
  v1 = mrb_equal(mrb, RANGE_BEG(rr), RANGE_BEG(ro));
  v2 = mrb_equal(mrb, RANGE_END(rr), RANGE_END(ro));
  if (!v1 || !v2 || RANGE_EXCL(rr) != RANGE_EXCL(ro)) {
    return mrb_false_value();
  }
  return mrb_true_value();
}

/*
 *  call-seq:
 *     range === obj       =>  true or false
 *     range.member?(val)  =>  true or false
 *     range.include?(val) =>  true or false
 */
static mrb_value
range_include(mrb_state *mrb, mrb_value range)
{
  mrb_value val = mrb_get_arg1(mrb);
  struct RRange *r = mrb_range_ptr(mrb, range);
  mrb_value beg, end;

  beg = RANGE_BEG(r);
  end = RANGE_END(r);
  if (mrb_nil_p(beg)) {
    if (RANGE_EXCL(r) ? r_gt(mrb, end, val)    /* end >  val */
                      : r_ge(mrb, end, val)) { /* end >= val */
      return mrb_true_value();
    }
  }
  else if (r_le(mrb, beg, val)) {              /* beg <= val */
    if (mrb_nil_p(end)) {
      return mrb_true_value();
    }
    if (RANGE_EXCL(r) ? r_gt(mrb, end, val)    /* end >  val */
                      : r_ge(mrb, end, val)) { /* end >= val */
      return mrb_true_value();
    }
  }
  return mrb_false_value();
}

/* 15.2.14.4.12(x) */
/*
 * call-seq:
 *   rng.to_s   -> string
 *
 * Convert this range object to a printable form.
 */
static mrb_value
range_to_s(mrb_state *mrb, mrb_value range)
{
  mrb_value str, str2;
  struct RRange *r = mrb_range_ptr(mrb, range);

  str  = mrb_obj_as_string(mrb, RANGE_BEG(r));
  str2 = mrb_obj_as_string(mrb, RANGE_END(r));
  str  = mrb_str_dup(mrb, str);
  mrb_str_cat(mrb, str, "...", RANGE_EXCL(r) ? 3 : 2);
  mrb_str_cat_str(mrb, str, str2);

  return str;
}

/* 15.2.14.4.13(x) */
/*
 * call-seq:
 *   rng.inspect  -> string
 *
 * Convert this range object to a printable form (using
 * <code>inspect</code> to convert the start and end
 * objects).
 */
static mrb_value
range_inspect(mrb_state *mrb, mrb_value range)
{
  mrb_value str;
  struct RRange *r = mrb_range_ptr(mrb, range);

  if (!mrb_nil_p(RANGE_BEG(r))) {
    str  = mrb_inspect(mrb, RANGE_BEG(r));
    str  = mrb_str_dup(mrb, str);
    mrb_str_cat(mrb, str, "...", RANGE_EXCL(r) ? 3 : 2);
  }
  else {
    str = mrb_str_new(mrb, "...", RANGE_EXCL(r) ? 3 : 2);
  }
  if (!mrb_nil_p(RANGE_END(r))) {
    mrb_value str2 = mrb_inspect(mrb, RANGE_END(r));
    mrb_str_cat_str(mrb, str, str2);
  }

  return str;
}

/* 15.2.14.4.14(x) */
/*
 *  call-seq:
 *     rng.eql?(obj)    -> true or false
 *
 *  Returns <code>true</code> only if <i>obj</i> is a Range, has equivalent
 *  beginning and end items (by comparing them with #eql?), and has the same
 *  #exclude_end? setting as <i>rng</i>.
 *
 *    (0..2).eql?(0..2)            #=> true
 *    (0..2).eql?(Range.new(0,2))  #=> true
 *    (0..2).eql?(0...2)           #=> false
 */
static mrb_value
range_eql(mrb_state *mrb, mrb_value range)
{
  mrb_value obj = mrb_get_arg1(mrb);
  struct RRange *r, *o;

  if (mrb_obj_equal(mrb, range, obj)) return mrb_true_value();
  if (!mrb_obj_is_kind_of(mrb, obj, mrb->range_class)) return mrb_false_value();
  if (!mrb_range_p(obj)) return mrb_false_value();

  r = mrb_range_ptr(mrb, range);
  o = mrb_range_ptr(mrb, obj);
  if (!mrb_eql(mrb, RANGE_BEG(r), RANGE_BEG(o)) ||
      !mrb_eql(mrb, RANGE_END(r), RANGE_END(o)) ||
      (RANGE_EXCL(r) != RANGE_EXCL(o))) {
    return mrb_false_value();
  }
  return mrb_true_value();
}

/* 15.2.14.4.15(x) */
static mrb_value
range_initialize_copy(mrb_state *mrb, mrb_value copy)
{
  mrb_value src = mrb_get_arg1(mrb);
  struct RRange *r;

  if (mrb_obj_equal(mrb, copy, src)) return copy;
  if (!mrb_obj_is_instance_of(mrb, src, mrb_obj_class(mrb, copy))) {
    mrb_raise(mrb, E_TYPE_ERROR, "wrong argument class");
  }

  r = mrb_range_ptr(mrb, src);
  range_ptr_replace(mrb, mrb_range_raw_ptr(copy), RANGE_BEG(r), RANGE_END(r), RANGE_EXCL(r));
  mrb_obj_freeze(mrb, copy);

  return copy;
}

static mrb_value
range_num_to_a(mrb_state *mrb, mrb_value range)
{
  struct RRange *r = mrb_range_ptr(mrb, range);
  mrb_value beg = RANGE_BEG(r);
  mrb_value end = RANGE_END(r);
  mrb_value ary;

  mrb->c->ci->mid = 0;
  if (mrb_nil_p(end)) {
    mrb_raise(mrb, E_RANGE_ERROR, "cannot convert endless range to an array");
  }
  if (mrb_integer_p(beg)) {
    if (mrb_integer_p(end)) {
      mrb_int a = mrb_integer(beg);
      mrb_int b = mrb_integer(end);
      mrb_int len;

      if (mrb_int_sub_overflow(b, a, &len)) {
        mrb_raise(mrb, E_RANGE_ERROR, "integer range too long");
      }
      if (!RANGE_EXCL(r)) len++;
      ary = mrb_ary_new_capa(mrb, len);
      for (mrb_int i=0; i<len; i++) {
        mrb_ary_push(mrb, ary, mrb_int_value(mrb, a+i));
      }
      return ary;
    }
#ifndef MRB_NO_FLOAT
    if (mrb_float_p(end)) {
      mrb_float a = (mrb_float)mrb_integer(beg);
      mrb_float b = mrb_float(end);

      ary = mrb_ary_new_capa(mrb, (mrb_int)(b - a) + 1);
      if (RANGE_EXCL(r)) {
        while (a < b) {
          mrb_ary_push(mrb, ary, mrb_int_value(mrb, (mrb_int)a));
          a += 1.0;
        }
      }
      else {
        while (a <= b) {
          mrb_ary_push(mrb, ary, mrb_int_value(mrb, (mrb_int)a));
          a += 1.0;
        }
      }
      return ary;
    }
#endif
  }
  return mrb_nil_value();
}

mrb_value
mrb_get_values_at(mrb_state *mrb, mrb_value obj, mrb_int olen, mrb_int argc, const mrb_value *argv, mrb_value (*func)(mrb_state*, mrb_value, mrb_int))
{
  mrb_int i, j, beg, len;
  mrb_value result;
  result = mrb_ary_new(mrb);

  for (i = 0; i < argc; ++i) {
    if (mrb_integer_p(argv[i])) {
      mrb_ary_push(mrb, result, func(mrb, obj, mrb_integer(argv[i])));
    }
    else if (mrb_range_beg_len(mrb, argv[i], &beg, &len, olen, FALSE) == MRB_RANGE_OK) {
      mrb_int const end = olen < beg + len ? olen : beg + len;
      for (j = beg; j < end; ++j) {
        mrb_ary_push(mrb, result, func(mrb, obj, j));
      }

      for (; j < beg + len; ++j) {
        mrb_ary_push(mrb, result, mrb_nil_value());
      }
    }
    else {
      mrb_raisef(mrb, E_TYPE_ERROR, "invalid values selector: %v", argv[i]);
    }
  }

  return result;
}

void
mrb_gc_mark_range(mrb_state *mrb, struct RRange *r)
{
  if (RANGE_INITIALIZED_P(r)) {
    mrb_gc_mark_value(mrb, RANGE_BEG(r));
    mrb_gc_mark_value(mrb, RANGE_END(r));
  }
}

MRB_API struct RRange*
mrb_range_ptr(mrb_state *mrb, mrb_value range)
{
  struct RRange *r = mrb_range_raw_ptr(range);

  /* check for if #initialize_copy was removed [#3320] */
  if (!RANGE_INITIALIZED_P(r)) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "uninitialized range");
  }
  return r;
}

MRB_API mrb_value
mrb_range_new(mrb_state *mrb, mrb_value beg, mrb_value end, mrb_bool excl)
{
  struct RRange *r = range_ptr_init(mrb, NULL, beg, end, excl);
  return mrb_range_value(r);
}

MRB_API enum mrb_range_beg_len
mrb_range_beg_len(mrb_state *mrb, mrb_value range, mrb_int *begp, mrb_int *lenp, mrb_int len, mrb_bool trunc)
{
  mrb_int beg, end;
  mrb_bool excl;
  struct RRange *r;

  if (!mrb_range_p(range)) return MRB_RANGE_TYPE_MISMATCH;
  r = mrb_range_ptr(mrb, range);

  beg = mrb_nil_p(RANGE_BEG(r)) ? 0 : mrb_as_int(mrb, RANGE_BEG(r));
  end = mrb_nil_p(RANGE_END(r)) ? -1 : mrb_as_int(mrb, RANGE_END(r));
  excl = mrb_nil_p(RANGE_END(r)) ? 0 : RANGE_EXCL(r);

  if (beg < 0) {
    beg += len;
    if (beg < 0) return MRB_RANGE_OUT;
  }

  if (trunc) {
    if (beg > len) return MRB_RANGE_OUT;
    if (end > len) end = len;
  }

  if (end < 0) end += len;
  if (!excl && (!trunc || end < len)) end++;  /* include end point */
  len = end - beg;
  if (len < 0) len = 0;

  *begp = beg;
  *lenp = len;
  return MRB_RANGE_OK;
}

void
mrb_init_range(mrb_state *mrb)
{
  struct RClass *r;

  r = mrb_define_class(mrb, "Range", mrb->object_class);                                /* 15.2.14 */
  mrb->range_class = r;
  MRB_SET_INSTANCE_TT(r, MRB_TT_RANGE);

  mrb_define_method(mrb, r, "begin",           range_beg,             MRB_ARGS_NONE()); /* 15.2.14.4.3  */
  mrb_define_method(mrb, r, "end",             range_end,             MRB_ARGS_NONE()); /* 15.2.14.4.5  */
  mrb_define_method(mrb, r, "==",              range_eq,              MRB_ARGS_REQ(1)); /* 15.2.14.4.1  */
  mrb_define_method(mrb, r, "===",             range_include,         MRB_ARGS_REQ(1)); /* 15.2.14.4.2  */
  mrb_define_method(mrb, r, "exclude_end?",    range_excl,            MRB_ARGS_NONE()); /* 15.2.14.4.6  */
  mrb_define_method(mrb, r, "first",           range_beg,             MRB_ARGS_NONE()); /* 15.2.14.4.7  */
  mrb_define_method(mrb, r, "include?",        range_include,         MRB_ARGS_REQ(1)); /* 15.2.14.4.8  */
  mrb_define_method(mrb, r, "initialize",      range_initialize,      MRB_ARGS_ANY());  /* 15.2.14.4.9  */
  mrb_define_method(mrb, r, "last",            range_end,             MRB_ARGS_NONE()); /* 15.2.14.4.10 */
  mrb_define_method(mrb, r, "member?",         range_include,         MRB_ARGS_REQ(1)); /* 15.2.14.4.11 */
  mrb_define_method(mrb, r, "to_s",            range_to_s,            MRB_ARGS_NONE()); /* 15.2.14.4.12(x) */
  mrb_define_method(mrb, r, "inspect",         range_inspect,         MRB_ARGS_NONE()); /* 15.2.14.4.13(x) */
  mrb_define_method(mrb, r, "eql?",            range_eql,             MRB_ARGS_REQ(1)); /* 15.2.14.4.14(x) */
  mrb_define_method(mrb, r, "initialize_copy", range_initialize_copy, MRB_ARGS_REQ(1)); /* 15.2.14.4.15(x) */
  mrb_define_method(mrb, r, "__num_to_a",      range_num_to_a,        MRB_ARGS_NONE());
}
