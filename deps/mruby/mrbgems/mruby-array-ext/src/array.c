#include <mruby.h>
#include <mruby/value.h>
#include <mruby/array.h>
#include <mruby/range.h>
#include <mruby/hash.h>
#include <mruby/presym.h>

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
ary_ref(mrb_state *mrb, mrb_value ary, mrb_int n)
{
  return mrb_ary_entry(ary, n);
}

static mrb_value
mrb_ary_values_at(mrb_state *mrb, mrb_value self)
{
  mrb_int argc;
  const mrb_value *argv;

  mrb_get_args(mrb, "*", &argv, &argc);

  return mrb_get_values_at(mrb, self, RARRAY_LEN(self), argc, argv, ary_ref);
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
    case MRB_TT_INTEGER:
      val = mrb_funcall_id(mrb, self, MRB_SYM(delete_at), 1, index);
      return val;
    default:
      val = mrb_funcall_id(mrb, self, MRB_SYM(delete_at), 1, index);
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

/*
 * call-seq:
 *    ary.compact     -> new_ary
 *
 * Returns a copy of +self+ with all +nil+ elements removed.
 *
 *   [ "a", nil, "b", nil, "c", nil ].compact
 *                      #=> [ "a", "b", "c" ]
 */

static mrb_value
mrb_ary_compact(mrb_state *mrb, mrb_value self)
{
  mrb_value ary = mrb_ary_new(mrb);
  mrb_int len = RARRAY_LEN(self);
  mrb_value *p = RARRAY_PTR(self);

  for (mrb_int i = 0; i < len; ++i) {
    if (!mrb_nil_p(p[i])) {
      mrb_ary_push(mrb, ary, p[i]);
    }
  }
  return ary;
}

/*
 * call-seq:
 *    ary.compact!    -> ary  or  nil
 *
 * Removes +nil+ elements from the array.
 * Returns +nil+ if no changes were made, otherwise returns
 * <i>ary</i>.
 *
 *    [ "a", nil, "b", nil, "c" ].compact! #=> [ "a", "b", "c" ]
 *    [ "a", "b", "c" ].compact!           #=> nil
 */
static mrb_value
mrb_ary_compact_bang(mrb_state *mrb, mrb_value self)
{
  struct RArray *a = mrb_ary_ptr(self);
  mrb_int i, j = 0;
  mrb_int len = ARY_LEN(a);
  mrb_value *p = ARY_PTR(a);

  mrb_ary_modify(mrb, a);
  for (i = 0; i < len; ++i) {
    if (!mrb_nil_p(p[i])) {
      if (i != j) p[j] = p[i];
      j++;
    }
  }
  if (i == j) return mrb_nil_value();
  if (j < len) ARY_SET_LEN(RARRAY(self), j);
  return self;
}


/*
 *  call-seq:
 *     ary.rotate(count=1)    -> new_ary
 *
 *  Returns a new array by rotating +self+ so that the element at +count+ is
 *  the first element of the new array.
 *
 *  If +count+ is negative then it rotates in the opposite direction, starting
 *  from the end of +self+ where +-1+ is the last element.
 *
 *     a = [ "a", "b", "c", "d" ]
 *     a.rotate         #=> ["b", "c", "d", "a"]
 *     a                #=> ["a", "b", "c", "d"]
 *     a.rotate(2)      #=> ["c", "d", "a", "b"]
 *     a.rotate(-3)     #=> ["b", "c", "d", "a"]
 */
static mrb_value
mrb_ary_rotate(mrb_state *mrb, mrb_value self)
{
  mrb_int count=1;
  mrb_get_args(mrb, "|i", &count);

  mrb_value ary = mrb_ary_new(mrb);
  mrb_int len = RARRAY_LEN(self);
  mrb_value *p = RARRAY_PTR(self);
  mrb_int idx;

  if (len <= 0) return ary;
  if (count < 0) {
    idx = len - (~count % len) - 1;
  }
  else {
    idx = count % len;
  }
  for (mrb_int i = 0; i<len; i++) {
    mrb_ary_push(mrb, ary, p[idx++]);
    if (idx == len) idx = 0;
  }
  return ary;
}

static void
rev(mrb_value *p, mrb_int beg, mrb_int end)
{
  for (mrb_int i=beg,j=end-1; i<j; i++,j--) {
    mrb_value v = p[i];
    p[i] = p[j];
    p[j] = v;
  }
}

/*
 *  call-seq:
 *     ary.rotate!(count=1)   -> ary
 *
 *  Rotates +self+ in place so that the element at +count+ comes first, and
 *  returns +self+.
 *
 *  If +count+ is negative then it rotates in the opposite direction, starting
 *  from the end of the array where +-1+ is the last element.
 *
 *     a = [ "a", "b", "c", "d" ]
 *     a.rotate!        #=> ["b", "c", "d", "a"]
 *     a                #=> ["b", "c", "d", "a"]
 *     a.rotate!(2)     #=> ["d", "a", "b", "c"]
 *     a.rotate!(-3)    #=> ["a", "b", "c", "d"]
 */
static mrb_value
mrb_ary_rotate_bang(mrb_state *mrb, mrb_value self)
{
  mrb_int count=1;
  mrb_get_args(mrb, "|i", &count);

  struct RArray *a = mrb_ary_ptr(self);
  mrb_int len = ARY_LEN(a);
  mrb_value *p = ARY_PTR(a);
  mrb_int idx;

  mrb_ary_modify(mrb, a);
  if (len == 0 || count == 0) return self;
  if (count == 1) {
    mrb_value v = p[0];
    for (mrb_int i=1; i<len; i++) {
      p[i-1] = p[i];
    }
    p[len-1] = v;
    return self;
  }
  if (count < 0) {
    idx = len - (~count % len) - 1;
  }
  else {
    idx = count % len;
  }
  /* e.g. [1,2,3,4,5].rotate!(2) -> [3,4,5,1,2] */
  /* first, reverse the whole array */
  /* [1,2,3,4,5] -> [5,4,3,2,1] */
  rev(p, 0, len);
  /* then, re-reverse part before idx */
  /* [5,4,3,2,1] -> [3,4,5,2,1] */
  /*        ^idx     ~~~~~      */
  rev(p, 0, len-idx);
  /* finally, re-reverse part after idx */
  /* [3,4,5,2,1] -> [3,4,5,1,2] */
  /*        ^idx           ~~~  */
  rev(p, len-idx, len);
  return self;
}

void
mrb_mruby_array_ext_gem_init(mrb_state* mrb)
{
  struct RClass * a = mrb->array_class;

  mrb_define_method(mrb, a, "assoc",  mrb_ary_assoc,  MRB_ARGS_REQ(1));
  mrb_define_method(mrb, a, "at",     mrb_ary_at,     MRB_ARGS_REQ(1));
  mrb_define_method(mrb, a, "rassoc", mrb_ary_rassoc, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, a, "values_at", mrb_ary_values_at, MRB_ARGS_ANY());
  mrb_define_method(mrb, a, "slice!", mrb_ary_slice_bang, MRB_ARGS_ARG(1,1));
  mrb_define_method(mrb, a, "compact", mrb_ary_compact, MRB_ARGS_NONE());
  mrb_define_method(mrb, a, "compact!", mrb_ary_compact_bang, MRB_ARGS_NONE());
  mrb_define_method(mrb, a, "rotate", mrb_ary_rotate, MRB_ARGS_OPT(1));
  mrb_define_method(mrb, a, "rotate!", mrb_ary_rotate_bang, MRB_ARGS_OPT(1));
}

void
mrb_mruby_array_ext_gem_final(mrb_state* mrb)
{
}
