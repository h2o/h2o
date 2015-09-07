#include "mruby.h"
#include "mruby/value.h"
#include "mruby/array.h"
#include "mruby/range.h"
#include "mruby/hash.h"

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
  mrb_value v, k;

  mrb_get_args(mrb, "o", &k);

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
  mrb_value v, value;

  mrb_get_args(mrb, "o", &value);

  for (i = 0; i < RARRAY_LEN(ary); ++i) {
    v = RARRAY_PTR(ary)[i];
    if (mrb_type(v) == MRB_TT_ARRAY &&
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
 *     ary.to_h   ->   Hash
 *
 *  Returns the result of interpreting <i>aray</i> as an array of
 *  <tt>[key, value]</tt> paris.
 *
 *     [[:foo, :bar], [1, 2]].to_h
 *       # => {:foo => :bar, 1 => 2}
 */

static mrb_value
mrb_ary_to_h(mrb_state *mrb, mrb_value ary)
{
  mrb_int i;
  mrb_value v, hash;

  hash = mrb_hash_new_capa(mrb, 0);

  for (i = 0; i < RARRAY_LEN(ary); ++i) {
    v = mrb_check_array_type(mrb, RARRAY_PTR(ary)[i]);

    if (mrb_nil_p(v)) {
      mrb_raisef(mrb, E_TYPE_ERROR, "wrong element type %S at %S (expected array)",
        mrb_str_new_cstr(mrb,  mrb_obj_classname(mrb, RARRAY_PTR(ary)[i])),
        mrb_fixnum_value(i)
      );
    }

    if (RARRAY_LEN(v) != 2) {
      mrb_raisef(mrb, E_ARGUMENT_ERROR, "wrong array length at %S (expected 2, was %S)",
        mrb_fixnum_value(i),
        mrb_fixnum_value(RARRAY_LEN(v))
      );
    }

    mrb_hash_set(mrb, hash, RARRAY_PTR(v)[0], RARRAY_PTR(v)[1]);
  }

  return hash;
}

void
mrb_mruby_array_ext_gem_init(mrb_state* mrb)
{
  struct RClass * a = mrb->array_class;

  mrb_define_method(mrb, a, "assoc",  mrb_ary_assoc,  MRB_ARGS_REQ(1));
  mrb_define_method(mrb, a, "at",     mrb_ary_at,     MRB_ARGS_REQ(1));
  mrb_define_method(mrb, a, "rassoc", mrb_ary_rassoc, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, a, "values_at", mrb_ary_values_at, MRB_ARGS_ANY());
  mrb_define_method(mrb, a, "to_h",   mrb_ary_to_h, MRB_ARGS_REQ(0));
}

void
mrb_mruby_array_ext_gem_final(mrb_state* mrb)
{
}
