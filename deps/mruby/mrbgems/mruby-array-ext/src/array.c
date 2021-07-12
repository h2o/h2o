#include <mruby.h>
#include <mruby/value.h>
#include <mruby/array.h>
#include <mruby/range.h>
#include <mruby/hash.h>

/*
 *  call-seq:
 *     ary.assoc(obj)   -> new_ary  or  nil
 *
 *  Searches through an array whose elements are also arrays
 *  comparing _obj_ with the first element of each contained array
 *  using obj.==.
 *  Returns the first contained array that matches (that
 *  is, the first associated array),
 *  or +nil+ if no match is found.
 *  See also <code>Array#rassoc</code>.
 *
 *     s1 = [ "colors", "red", "blue", "green" ]
 *     s2 = [ "letters", "a", "b", "c" ]
 *     s3 = "foo"
 *     a  = [ s1, s2, s3 ]
 *     a.assoc("letters")  #=> [ "letters", "a", "b", "c" ]
 *     a.assoc("foo")      #=> nil
 */

static mrb_value
mrb_ary_assoc(mrb_state *mrb, mrb_value ary)
{
  mrb_int i;
  mrb_value v;
  mrb_value k = mrb_get_arg1(mrb);

  for (i = 0; i < RARRAY_LEN(ary); ++i) {
    v = mrb_check_array_type(mrb, RARRAY_PTR(ary)[i]);
    if (!mrb_nil_p(v) && RARRAY_LEN(v) > 0 &&
        mrb_equal(mrb, RARRAY_PTR(v)[0], k))
      return v;
  }
  return mrb_nil_value();
}

/*
 *  call-seq:
 *     ary.rassoc(obj) -> new_ary or nil
 *
 *  Searches through the array whose elements are also arrays. Compares
 *  _obj_ with the second element of each contained array using
 *  <code>==</code>. Returns the first contained array that matches. See
 *  also <code>Array#assoc</code>.
 *
 *     a = [ [ 1, "one"], [2, "two"], [3, "three"], ["ii", "two"] ]
 *     a.rassoc("two")    #=> [2, "two"]
 *     a.rassoc("four")   #=> nil
 */

static mrb_value
mrb_ary_rassoc(mrb_state *mrb, mrb_value ary)
{
  mrb_int i;
  mrb_value v;
  mrb_value value = mrb_get_arg1(mrb);

  for (i = 0; i < RARRAY_LEN(ary); ++i) {
    v = RARRAY_PTR(ary)[i];
    if (mrb_array_p(v) &&
        RARRAY_LEN(v) > 1 &&
        mrb_equal(mrb, RARRAY_PTR(v)[1], value))
      return v;
  }
  return mrb_nil_value();
}

/*
 *  call-seq:
 *     ary.at(index)   ->   obj  or nil
 *
 *  Returns the element at _index_. A
 *  negative index counts from the end of +self+.  Returns +nil+
 *  if the index is out of range. See also <code>Array#[]</code>.
 *
 *     a = [ "a", "b", "c", "d", "e" ]
 *     a.at(0)     #=> "a"
 *     a.at(-1)    #=> "e"
 */

static mrb_value
mrb_ary_at(mrb_state *mrb, mrb_value ary)
{
  mrb_int pos;
  mrb_get_args(mrb, "i", &pos);

  return mrb_ary_entry(ary, pos);
}

static mrb_value
mrb_ary_values_at(mrb_state *mrb, mrb_value self)
{
  mrb_int argc;
  mrb_value *argv;

  mrb_get_args(mrb, "*", &argv, &argc);

  return mrb_get_values_at(mrb, self, RARRAY_LEN(self), argc, argv, mrb_ary_ref);
}


/*
 *  call-seq:
 *     ary.slice!(index)         -> obj or nil
 *     ary.slice!(start, length) -> new_ary or nil
 *     ary.slice!(range)         -> new_ary or nil
 *
 *  Deletes the element(s) given by an +index+ (optionally up to +length+
 *  elements) or by a +range+.
 *
 *  Returns the deleted object (or objects), or +nil+ if the +index+ is out of
 *  range.
 *
 *     a = [ "a", "b", "c" ]
 *     a.slice!(1)     #=> "b"
 *     a               #=> ["a", "c"]
 *     a.slice!(-1)    #=> "c"
 *     a               #=> ["a"]
 *     a.slice!(100)   #=> nil
 *     a               #=> ["a"]
 */

static mrb_value
mrb_ary_slice_bang(mrb_state *mrb, mrb_value self)
{
  struct RArray *a = mrb_ary_ptr(self);
  mrb_int i, j, k, len, alen;
  mrb_value val;
  mrb_value *ptr;
  mrb_value ary;

  mrb_ary_modify(mrb, a);

  if (mrb_get_argc(mrb) == 1) {
    mrb_value index = mrb_get_arg1(mrb);

    switch (mrb_type(index)) {
    case MRB_TT_RANGE:
      if (mrb_range_beg_len(mrb, index, &i, &len, ARY_LEN(a), TRUE) == MRB_RANGE_OK) {
        goto delete_pos_len;
      }
      else {
        return mrb_nil_value();
      }
    case MRB_TT_FIXNUM:
      val = mrb_funcall(mrb, self, "delete_at", 1, index);
      return val;
    default:
      val = mrb_funcall(mrb, self, "delete_at", 1, index);
      return val;
    }
  }

  mrb_get_args(mrb, "ii", &i, &len);
 delete_pos_len:
  alen = ARY_LEN(a);
  if (i < 0) i += alen;
  if (i < 0 || alen < i) return mrb_nil_value();
  if (len < 0) return mrb_nil_value();
  if (alen == i) return mrb_ary_new(mrb);
  if (len > alen - i) len = alen - i;

  ary = mrb_ary_new_capa(mrb, len);
  ptr = ARY_PTR(a);
  for (j = i, k = 0; k < len; ++j, ++k) {
    mrb_ary_push(mrb, ary, ptr[j]);
  }

  ptr += i;
  for (j = i; j < alen - len; ++j) {
    *ptr = *(ptr+len);
    ++ptr;
  }

  mrb_ary_resize(mrb, self, alen - len);
  return ary;
}

void
mrb_mruby_array_ext_gem_init(mrb_state* mrb)
{
  struct RClass * a = mrb->array_class;

  mrb_define_method(mrb, a, "assoc",  mrb_ary_assoc,  MRB_ARGS_REQ(1));
  mrb_define_method(mrb, a, "at",     mrb_ary_at,     MRB_ARGS_REQ(1));
  mrb_define_method(mrb, a, "rassoc", mrb_ary_rassoc, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, a, "values_at", mrb_ary_values_at, MRB_ARGS_ANY());
  mrb_define_method(mrb, a, "slice!", mrb_ary_slice_bang,   MRB_ARGS_ARG(1,1));
}

void
mrb_mruby_array_ext_gem_final(mrb_state* mrb)
{
}
