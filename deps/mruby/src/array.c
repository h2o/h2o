/*
** array.c - Array class
**
** See Copyright Notice in mruby.h
*/

#include <mruby.h>
#include <mruby/array.h>
#include <mruby/class.h>
#include <mruby/string.h>
#include <mruby/range.h>
#include "value_array.h"

#define ARY_DEFAULT_LEN   4
#define ARY_SHRINK_RATIO  5 /* must be larger than 2 */
#define ARY_C_MAX_SIZE (SIZE_MAX / sizeof(mrb_value))
#define ARY_MAX_SIZE ((mrb_int)((ARY_C_MAX_SIZE < (size_t)MRB_INT_MAX) ? ARY_C_MAX_SIZE : MRB_INT_MAX-1))

static struct RArray*
ary_new_capa(mrb_state *mrb, mrb_int capa)
{
  struct RArray *a;
  size_t blen;

  if (capa > ARY_MAX_SIZE) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "array size too big");
  }
  blen = capa * sizeof(mrb_value);

  a = (struct RArray*)mrb_obj_alloc(mrb, MRB_TT_ARRAY, mrb->array_class);
  if (capa <= MRB_ARY_EMBED_LEN_MAX) {
    ARY_SET_EMBED_LEN(a, 0);
  }
  else {
    a->as.heap.ptr = (mrb_value *)mrb_malloc(mrb, blen);
    a->as.heap.aux.capa = capa;
    a->as.heap.len = 0;
  }

  return a;
}

MRB_API mrb_value
mrb_ary_new_capa(mrb_state *mrb, mrb_int capa)
{
  struct RArray *a = ary_new_capa(mrb, capa);
  return mrb_obj_value(a);
}

MRB_API mrb_value
mrb_ary_new(mrb_state *mrb)
{
  return mrb_ary_new_capa(mrb, 0);
}

/*
 * to copy array, use this instead of memcpy because of portability
 * * gcc on ARM may fail optimization of memcpy
 *   http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.faqs/ka3934.html
 * * gcc on MIPS also fail
 *   http://gcc.gnu.org/bugzilla/show_bug.cgi?id=39755
 * * memcpy doesn't exist on freestanding environment
 *
 * If you optimize for binary size, use memcpy instead of this at your own risk
 * of above portability issue.
 *
 * see also http://togetter.com/li/462898
 *
 */
static inline void
array_copy(mrb_value *dst, const mrb_value *src, mrb_int size)
{
  mrb_int i;

  for (i = 0; i < size; i++) {
    dst[i] = src[i];
  }
}

static struct RArray*
ary_new_from_values(mrb_state *mrb, mrb_int size, const mrb_value *vals)
{
  struct RArray *a = ary_new_capa(mrb, size);

  array_copy(ARY_PTR(a), vals, size);
  ARY_SET_LEN(a, size);

  return a;
}

MRB_API mrb_value
mrb_ary_new_from_values(mrb_state *mrb, mrb_int size, const mrb_value *vals)
{
  struct RArray *a = ary_new_from_values(mrb, size, vals);
  return mrb_obj_value(a);
}

MRB_API mrb_value
mrb_assoc_new(mrb_state *mrb, mrb_value car, mrb_value cdr)
{
  struct RArray *a;

  a = ary_new_capa(mrb, 2);
  ARY_PTR(a)[0] = car;
  ARY_PTR(a)[1] = cdr;
  ARY_SET_LEN(a, 2);
  return mrb_obj_value(a);
}

static void
ary_fill_with_nil(mrb_value *ptr, mrb_int size)
{
  mrb_value nil = mrb_nil_value();

  while (size--) {
    *ptr++ = nil;
  }
}

static void
ary_modify_check(mrb_state *mrb, struct RArray *a)
{
  if (MRB_FROZEN_P(a)) {
    mrb_raise(mrb, E_FROZEN_ERROR, "can't modify frozen array");
  }
}

static void
ary_modify(mrb_state *mrb, struct RArray *a)
{
  ary_modify_check(mrb, a);

  if (ARY_SHARED_P(a)) {
    mrb_shared_array *shared = a->as.heap.aux.shared;

    if (shared->refcnt == 1 && a->as.heap.ptr == shared->ptr) {
      a->as.heap.ptr = shared->ptr;
      a->as.heap.aux.capa = a->as.heap.len;
      mrb_free(mrb, shared);
    }
    else {
      mrb_value *ptr, *p;
      mrb_int len;

      p = a->as.heap.ptr;
      len = a->as.heap.len * sizeof(mrb_value);
      ptr = (mrb_value *)mrb_malloc(mrb, len);
      if (p) {
        array_copy(ptr, p, a->as.heap.len);
      }
      a->as.heap.ptr = ptr;
      a->as.heap.aux.capa = a->as.heap.len;
      mrb_ary_decref(mrb, shared);
    }
    ARY_UNSET_SHARED_FLAG(a);
  }
}

MRB_API void
mrb_ary_modify(mrb_state *mrb, struct RArray* a)
{
  mrb_write_barrier(mrb, (struct RBasic*)a);
  ary_modify(mrb, a);
}

static void
ary_make_shared(mrb_state *mrb, struct RArray *a)
{
  if (!ARY_SHARED_P(a) && !ARY_EMBED_P(a)) {
    mrb_shared_array *shared = (mrb_shared_array *)mrb_malloc(mrb, sizeof(mrb_shared_array));
    mrb_value *ptr = a->as.heap.ptr;
    mrb_int len = a->as.heap.len;

    shared->refcnt = 1;
    if (a->as.heap.aux.capa > len) {
      a->as.heap.ptr = shared->ptr = (mrb_value *)mrb_realloc(mrb, ptr, sizeof(mrb_value)*len+1);
    }
    else {
      shared->ptr = ptr;
    }
    shared->len = len;
    a->as.heap.aux.shared = shared;
    ARY_SET_SHARED_FLAG(a);
  }
}

static void
ary_expand_capa(mrb_state *mrb, struct RArray *a, mrb_int len)
{
  mrb_int capa = ARY_CAPA(a);

  if (len > ARY_MAX_SIZE || len < 0) {
  size_error:
    mrb_raise(mrb, E_ARGUMENT_ERROR, "array size too big");
  }

  if (capa < ARY_DEFAULT_LEN) {
    capa = ARY_DEFAULT_LEN;
  }
  while (capa < len) {
    if (capa <= ARY_MAX_SIZE / 2) {
      capa *= 2;
    }
    else {
      capa = len;
    }
  }
  if (capa < len || capa > ARY_MAX_SIZE) {
    goto size_error;
  }

  if (ARY_EMBED_P(a)) {
    mrb_value *ptr = ARY_EMBED_PTR(a);
    mrb_int len = ARY_EMBED_LEN(a);
    mrb_value *expanded_ptr = (mrb_value *)mrb_malloc(mrb, sizeof(mrb_value)*capa);

    ARY_UNSET_EMBED_FLAG(a);
    array_copy(expanded_ptr, ptr, len);
    a->as.heap.len = len;
    a->as.heap.aux.capa = capa;
    a->as.heap.ptr = expanded_ptr;
  }
  else if (capa > a->as.heap.aux.capa) {
    mrb_value *expanded_ptr = (mrb_value *)mrb_realloc(mrb, a->as.heap.ptr, sizeof(mrb_value)*capa);

    a->as.heap.aux.capa = capa;
    a->as.heap.ptr = expanded_ptr;
  }
}

static void
ary_shrink_capa(mrb_state *mrb, struct RArray *a)
{
  
  mrb_int capa;

  if (ARY_EMBED_P(a)) return;

  capa = a->as.heap.aux.capa;
  if (capa < ARY_DEFAULT_LEN * 2) return;
  if (capa <= a->as.heap.len * ARY_SHRINK_RATIO) return;

  do {
    capa /= 2;
    if (capa < ARY_DEFAULT_LEN) {
      capa = ARY_DEFAULT_LEN;
      break;
    }
  } while (capa > a->as.heap.len * ARY_SHRINK_RATIO);

  if (capa > a->as.heap.len && capa < a->as.heap.aux.capa) {
    a->as.heap.aux.capa = capa;
    a->as.heap.ptr = (mrb_value *)mrb_realloc(mrb, a->as.heap.ptr, sizeof(mrb_value)*capa);
  }
}

MRB_API mrb_value
mrb_ary_resize(mrb_state *mrb, mrb_value ary, mrb_int new_len)
{
  mrb_int old_len;
  struct RArray *a = mrb_ary_ptr(ary);

  ary_modify(mrb, a);
  old_len = RARRAY_LEN(ary);
  if (old_len != new_len) {
    if (new_len < old_len) {
      ary_shrink_capa(mrb, a);
    }
    else {
      ary_expand_capa(mrb, a, new_len);
      ary_fill_with_nil(ARY_PTR(a) + old_len, new_len - old_len);
    }
    ARY_SET_LEN(a, new_len);
  }

  return ary;
}

static mrb_value
mrb_ary_s_create(mrb_state *mrb, mrb_value klass)
{
  mrb_value ary;
  mrb_value *vals;
  mrb_int len;
  struct RArray *a;

  mrb_get_args(mrb, "*!", &vals, &len);
  ary = mrb_ary_new_from_values(mrb, len, vals);
  a = mrb_ary_ptr(ary);
  a->c = mrb_class_ptr(klass);

  return ary;
}

static void ary_replace(mrb_state*, struct RArray*, struct RArray*);

static void
ary_concat(mrb_state *mrb, struct RArray *a, struct RArray *a2)
{
  mrb_int len;

  if (ARY_LEN(a) == 0) {
    ary_replace(mrb, a, a2);
    return;
  }
  if (ARY_LEN(a2) > ARY_MAX_SIZE - ARY_LEN(a)) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "array size too big");
  }
  len = ARY_LEN(a) + ARY_LEN(a2);

  ary_modify(mrb, a);
  if (ARY_CAPA(a) < len) {
    ary_expand_capa(mrb, a, len);
  }
  array_copy(ARY_PTR(a)+ARY_LEN(a), ARY_PTR(a2), ARY_LEN(a2));
  mrb_write_barrier(mrb, (struct RBasic*)a);
  ARY_SET_LEN(a, len);
}

MRB_API void
mrb_ary_concat(mrb_state *mrb, mrb_value self, mrb_value other)
{
  struct RArray *a2 = mrb_ary_ptr(other);

  ary_concat(mrb, mrb_ary_ptr(self), a2);
}

static mrb_value
mrb_ary_concat_m(mrb_state *mrb, mrb_value self)
{
  mrb_value ary;

  mrb_get_args(mrb, "A", &ary);
  mrb_ary_concat(mrb, self, ary);
  return self;
}

static mrb_value
mrb_ary_plus(mrb_state *mrb, mrb_value self)
{
  struct RArray *a1 = mrb_ary_ptr(self);
  struct RArray *a2;
  mrb_value *ptr;
  mrb_int blen, len1;

  mrb_get_args(mrb, "a", &ptr, &blen);
  if (ARY_MAX_SIZE - blen < ARY_LEN(a1)) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "array size too big");
  }
  len1 = ARY_LEN(a1);
  a2 = ary_new_capa(mrb, len1 + blen);
  array_copy(ARY_PTR(a2), ARY_PTR(a1), len1);
  array_copy(ARY_PTR(a2) + len1, ptr, blen);
  ARY_SET_LEN(a2, len1+blen);

  return mrb_obj_value(a2);
}

#define ARY_REPLACE_SHARED_MIN 20

static void
ary_replace(mrb_state *mrb, struct RArray *a, struct RArray *b)
{
  mrb_int len = ARY_LEN(b);

  ary_modify_check(mrb, a);
  if (a == b) return;
  if (ARY_SHARED_P(a)) {
    mrb_ary_decref(mrb, a->as.heap.aux.shared);
    a->as.heap.aux.capa = 0;
    a->as.heap.len = 0;
    a->as.heap.ptr = NULL;
    ARY_UNSET_SHARED_FLAG(a);
  }
  if (ARY_SHARED_P(b)) {
  shared_b:
    if (ARY_EMBED_P(a)) {
      ARY_UNSET_EMBED_FLAG(a);
    }
    else {
      mrb_free(mrb, a->as.heap.ptr);
    }
    a->as.heap.ptr = b->as.heap.ptr;
    a->as.heap.len = len;
    a->as.heap.aux.shared = b->as.heap.aux.shared;
    a->as.heap.aux.shared->refcnt++;
    ARY_SET_SHARED_FLAG(a);
    mrb_write_barrier(mrb, (struct RBasic*)a);
    return;
  }
  if (!MRB_FROZEN_P(b) && len > ARY_REPLACE_SHARED_MIN) {
    ary_make_shared(mrb, b);
    goto shared_b;
  }
  if (ARY_CAPA(a) < len)
    ary_expand_capa(mrb, a, len);
  array_copy(ARY_PTR(a), ARY_PTR(b), len);
  mrb_write_barrier(mrb, (struct RBasic*)a);
  ARY_SET_LEN(a, len);
}

MRB_API void
mrb_ary_replace(mrb_state *mrb, mrb_value self, mrb_value other)
{
  struct RArray *a1 = mrb_ary_ptr(self);
  struct RArray *a2 = mrb_ary_ptr(other);

  if (a1 != a2) {
    ary_replace(mrb, a1, a2);
  }
}

static mrb_value
mrb_ary_replace_m(mrb_state *mrb, mrb_value self)
{
  mrb_value other;

  mrb_get_args(mrb, "A", &other);
  mrb_ary_replace(mrb, self, other);

  return self;
}

static mrb_value
mrb_ary_times(mrb_state *mrb, mrb_value self)
{
  struct RArray *a1 = mrb_ary_ptr(self);
  struct RArray *a2;
  mrb_value *ptr;
  mrb_int times, len1;

  mrb_get_args(mrb, "i", &times);
  if (times < 0) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "negative argument");
  }
  if (times == 0) return mrb_ary_new(mrb);
  if (ARY_MAX_SIZE / times < ARY_LEN(a1)) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "array size too big");
  }
  len1 = ARY_LEN(a1);
  a2 = ary_new_capa(mrb, len1 * times);
  ARY_SET_LEN(a2, len1 * times);
  ptr = ARY_PTR(a2);
  while (times--) {
    array_copy(ptr, ARY_PTR(a1), len1);
    ptr += len1;
  }

  return mrb_obj_value(a2);
}

static mrb_value
mrb_ary_reverse_bang(mrb_state *mrb, mrb_value self)
{
  struct RArray *a = mrb_ary_ptr(self);
  mrb_int len = ARY_LEN(a);

  if (len > 1) {
    mrb_value *p1, *p2;

    ary_modify(mrb, a);
    p1 = ARY_PTR(a);
    p2 = p1 + len - 1;

    while (p1 < p2) {
      mrb_value tmp = *p1;
      *p1++ = *p2;
      *p2-- = tmp;
    }
  }
  return self;
}

static mrb_value
mrb_ary_reverse(mrb_state *mrb, mrb_value self)
{
  struct RArray *a = mrb_ary_ptr(self), *b = ary_new_capa(mrb, ARY_LEN(a));
  mrb_int len = ARY_LEN(a);

  if (len > 0) {
    mrb_value *p1, *p2, *e;

    p1 = ARY_PTR(a);
    e  = p1 + len;
    p2 = ARY_PTR(b) + len - 1;
    while (p1 < e) {
      *p2-- = *p1++;
    }
    ARY_SET_LEN(b, len);
  }
  return mrb_obj_value(b);
}

MRB_API void
mrb_ary_push(mrb_state *mrb, mrb_value ary, mrb_value elem)
{
  struct RArray *a = mrb_ary_ptr(ary);
  mrb_int len = ARY_LEN(a);

  ary_modify(mrb, a);
  if (len == ARY_CAPA(a))
    ary_expand_capa(mrb, a, len + 1);
  ARY_PTR(a)[len] = elem;
  ARY_SET_LEN(a, len+1);
  mrb_field_write_barrier_value(mrb, (struct RBasic*)a, elem);
}

static mrb_value
mrb_ary_push_m(mrb_state *mrb, mrb_value self)
{
  mrb_value *argv;
  mrb_int len, len2, alen;
  struct RArray *a;

  mrb_get_args(mrb, "*!", &argv, &alen);
  a = mrb_ary_ptr(self);
  ary_modify(mrb, a);
  len = ARY_LEN(a);
  len2 = len + alen;
  if (ARY_CAPA(a) < len2) {
    ary_expand_capa(mrb, a, len2);
  }
  array_copy(ARY_PTR(a)+len, argv, alen);
  ARY_SET_LEN(a, len2);
  mrb_write_barrier(mrb, (struct RBasic*)a);

  return self;
}

MRB_API mrb_value
mrb_ary_pop(mrb_state *mrb, mrb_value ary)
{
  struct RArray *a = mrb_ary_ptr(ary);
  mrb_int len = ARY_LEN(a);

  ary_modify_check(mrb, a);
  if (len == 0) return mrb_nil_value();
  ARY_SET_LEN(a, len-1);
  return ARY_PTR(a)[len-1];
}

#define ARY_SHIFT_SHARED_MIN 10

MRB_API mrb_value
mrb_ary_shift(mrb_state *mrb, mrb_value self)
{
  struct RArray *a = mrb_ary_ptr(self);
  mrb_int len = ARY_LEN(a);
  mrb_value val;

  ary_modify_check(mrb, a);
  if (len == 0) return mrb_nil_value();
  if (ARY_SHARED_P(a)) {
  L_SHIFT:
    val = a->as.heap.ptr[0];
    a->as.heap.ptr++;
    a->as.heap.len--;
    return val;
  }
  if (len > ARY_SHIFT_SHARED_MIN) {
    ary_make_shared(mrb, a);
    goto L_SHIFT;
  }
  else {
    mrb_value *ptr = ARY_PTR(a);
    mrb_int size = len;

    val = *ptr;
    while (--size) {
      *ptr = *(ptr+1);
      ++ptr;
    }
    ARY_SET_LEN(a, len-1);
  }
  return val;
}

/* self = [1,2,3]
   item = 0
   self.unshift item
   p self #=> [0, 1, 2, 3] */
MRB_API mrb_value
mrb_ary_unshift(mrb_state *mrb, mrb_value self, mrb_value item)
{
  struct RArray *a = mrb_ary_ptr(self);
  mrb_int len = ARY_LEN(a);

  if (ARY_SHARED_P(a)
      && a->as.heap.aux.shared->refcnt == 1 /* shared only referenced from this array */
      && a->as.heap.ptr - a->as.heap.aux.shared->ptr >= 1) /* there's room for unshifted item */ {
    a->as.heap.ptr--;
    a->as.heap.ptr[0] = item;
  }
  else {
    mrb_value *ptr;

    ary_modify(mrb, a);
    if (ARY_CAPA(a) < len + 1)
      ary_expand_capa(mrb, a, len + 1);
    ptr = ARY_PTR(a);
    value_move(ptr + 1, ptr, len);
    ptr[0] = item;
  }
  ARY_SET_LEN(a, len+1);
  mrb_field_write_barrier_value(mrb, (struct RBasic*)a, item);

  return self;
}

static mrb_value
mrb_ary_unshift_m(mrb_state *mrb, mrb_value self)
{
  struct RArray *a = mrb_ary_ptr(self);
  mrb_value *vals, *ptr;
  mrb_int alen, len;

  mrb_get_args(mrb, "*!", &vals, &alen);
  if (alen == 0) {
    ary_modify_check(mrb, a);
    return self;
  }
  len = ARY_LEN(a);
  if (alen > ARY_MAX_SIZE - len) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "array size too big");
  }
  if (ARY_SHARED_P(a)
      && a->as.heap.aux.shared->refcnt == 1 /* shared only referenced from this array */
      && a->as.heap.ptr - a->as.heap.aux.shared->ptr >= alen) /* there's room for unshifted item */ {
    ary_modify_check(mrb, a);
    a->as.heap.ptr -= alen;
    ptr = a->as.heap.ptr;
  }
  else {
    ary_modify(mrb, a);
    if (ARY_CAPA(a) < len + alen)
      ary_expand_capa(mrb, a, len + alen);
    ptr = ARY_PTR(a);
    value_move(ptr + alen, ptr, len);
  }
  array_copy(ptr, vals, alen);
  ARY_SET_LEN(a, len+alen);
  while (alen--) {
    mrb_field_write_barrier_value(mrb, (struct RBasic*)a, vals[alen]);
  }

  return self;
}

MRB_API mrb_value
mrb_ary_ref(mrb_state *mrb, mrb_value ary, mrb_int n)
{
  struct RArray *a = mrb_ary_ptr(ary);
  mrb_int len = ARY_LEN(a);

  /* range check */
  if (n < 0) n += len;
  if (n < 0 || len <= n) return mrb_nil_value();

  return ARY_PTR(a)[n];
}

MRB_API void
mrb_ary_set(mrb_state *mrb, mrb_value ary, mrb_int n, mrb_value val)
{
  struct RArray *a = mrb_ary_ptr(ary);
  mrb_int len = ARY_LEN(a);

  ary_modify(mrb, a);
  /* range check */
  if (n < 0) {
    n += len;
    if (n < 0) {
      mrb_raisef(mrb, E_INDEX_ERROR, "index %S out of array", mrb_fixnum_value(n - len));
    }
  }
  if (len <= n) {
    if (ARY_CAPA(a) <= n)
      ary_expand_capa(mrb, a, n + 1);
    ary_fill_with_nil(ARY_PTR(a) + len, n + 1 - len);
    ARY_SET_LEN(a, n+1);
  }

  ARY_PTR(a)[n] = val;
  mrb_field_write_barrier_value(mrb, (struct RBasic*)a, val);
}

static struct RArray*
ary_dup(mrb_state *mrb, struct RArray *a)
{
  return ary_new_from_values(mrb, ARY_LEN(a), ARY_PTR(a));
}

MRB_API mrb_value
mrb_ary_splice(mrb_state *mrb, mrb_value ary, mrb_int head, mrb_int len, mrb_value rpl)
{
  struct RArray *a = mrb_ary_ptr(ary);
  mrb_int alen = ARY_LEN(a);
  const mrb_value *argv;
  mrb_int argc;
  mrb_int tail;

  ary_modify(mrb, a);

  /* len check */
  if (len < 0) mrb_raisef(mrb, E_INDEX_ERROR, "negative length (%S)", mrb_fixnum_value(len));

  /* range check */
  if (head < 0) {
    head += alen;
    if (head < 0) {
      mrb_raise(mrb, E_INDEX_ERROR, "index is out of array");
    }
  }
  tail = head + len;
  if (alen < len || alen < tail) {
    len = alen - head;
  }

  /* size check */
  if (mrb_array_p(rpl)) {
    argc = RARRAY_LEN(rpl);
    argv = RARRAY_PTR(rpl);
    if (argv == ARY_PTR(a)) {
      struct RArray *r;

      if (argc > 32767) {
        mrb_raise(mrb, E_ARGUMENT_ERROR, "too big recursive splice");
      }
      r = ary_dup(mrb, a);
      argv = ARY_PTR(r);
    }
  }
  else {
    argc = 1;
    argv = &rpl;
  }
  if (head >= alen) {
    if (head > ARY_MAX_SIZE - argc) {
      mrb_raisef(mrb, E_INDEX_ERROR, "index %S too big", mrb_fixnum_value(head));
    }
    len = head + argc;
    if (len > ARY_CAPA(a)) {
      ary_expand_capa(mrb, a, head + argc);
    }
    ary_fill_with_nil(ARY_PTR(a) + alen, head - alen);
    if (argc > 0) {
      array_copy(ARY_PTR(a) + head, argv, argc);
    }
    ARY_SET_LEN(a, len);
  }
  else {
    mrb_int newlen;

    if (alen - len > ARY_MAX_SIZE - argc) {
      mrb_raisef(mrb, E_INDEX_ERROR, "index %S too big", mrb_fixnum_value(alen + argc - len));
    }
    newlen = alen + argc - len;
    if (newlen > ARY_CAPA(a)) {
      ary_expand_capa(mrb, a, newlen);
    }

    if (len != argc) {
      mrb_value *ptr = ARY_PTR(a);
      tail = head + len;
      value_move(ptr + head + argc, ptr + tail, alen - tail);
      ARY_SET_LEN(a, newlen);
    }
    if (argc > 0) {
      value_move(ARY_PTR(a) + head, argv, argc);
    }
  }
  mrb_write_barrier(mrb, (struct RBasic*)a);
  return ary;
}

void
mrb_ary_decref(mrb_state *mrb, mrb_shared_array *shared)
{
  shared->refcnt--;
  if (shared->refcnt == 0) {
    mrb_free(mrb, shared->ptr);
    mrb_free(mrb, shared);
  }
}

static mrb_value
ary_subseq(mrb_state *mrb, struct RArray *a, mrb_int beg, mrb_int len)
{
  struct RArray *b;

  if (!ARY_SHARED_P(a) && len <= ARY_SHIFT_SHARED_MIN) {
    return mrb_ary_new_from_values(mrb, len, ARY_PTR(a)+beg);
  }
  ary_make_shared(mrb, a);
  b  = (struct RArray*)mrb_obj_alloc(mrb, MRB_TT_ARRAY, mrb->array_class);
  b->as.heap.ptr = a->as.heap.ptr + beg;
  b->as.heap.len = len;
  b->as.heap.aux.shared = a->as.heap.aux.shared;
  b->as.heap.aux.shared->refcnt++;
  ARY_SET_SHARED_FLAG(b);

  return mrb_obj_value(b);
}

static mrb_int
aget_index(mrb_state *mrb, mrb_value index)
{
  if (mrb_fixnum_p(index)) {
    return mrb_fixnum(index);
  }
#ifndef MRB_WITHOUT_FLOAT
  else if (mrb_float_p(index)) {
    return (mrb_int)mrb_float(index);
  }
#endif
  else {
    mrb_int i, argc;
    mrb_value *argv;

    mrb_get_args(mrb, "i*!", &i, &argv, &argc);
    return i;
  }
}

/*
 *  call-seq:
 *     ary[index]                -> obj     or nil
 *     ary[start, length]        -> new_ary or nil
 *     ary[range]                -> new_ary or nil
 *     ary.slice(index)          -> obj     or nil
 *     ary.slice(start, length)  -> new_ary or nil
 *     ary.slice(range)          -> new_ary or nil
 *
 *  Element Reference --- Returns the element at +index+, or returns a
 *  subarray starting at the +start+ index and continuing for +length+
 *  elements, or returns a subarray specified by +range+ of indices.
 *
 *  Negative indices count backward from the end of the array (-1 is the last
 *  element).  For +start+ and +range+ cases the starting index is just before
 *  an element.  Additionally, an empty array is returned when the starting
 *  index for an element range is at the end of the array.
 *
 *  Returns +nil+ if the index (or starting index) are out of range.
 *
 *  a = [ "a", "b", "c", "d", "e" ]
 *  a[1]     => "b"
 *  a[1,2]   => ["b", "c"]
 *  a[1..-2] => ["b", "c", "d"]
 *
 */

static mrb_value
mrb_ary_aget(mrb_state *mrb, mrb_value self)
{
  struct RArray *a = mrb_ary_ptr(self);
  mrb_int i, len, alen = ARY_LEN(a);
  mrb_value index;

  if (mrb_get_args(mrb, "o|i", &index, &len) == 1) {
    switch (mrb_type(index)) {
      /* a[n..m] */
    case MRB_TT_RANGE:
      if (mrb_range_beg_len(mrb, index, &i, &len, alen, TRUE) == 1) {
        return ary_subseq(mrb, a, i, len);
      }
      else {
        return mrb_nil_value();
      }
    case MRB_TT_FIXNUM:
      return mrb_ary_ref(mrb, self, mrb_fixnum(index));
    default:
      return mrb_ary_ref(mrb, self, aget_index(mrb, index));
    }
  }

  i = aget_index(mrb, index);
  if (i < 0) i += alen;
  if (i < 0 || alen < i) return mrb_nil_value();
  if (len < 0) return mrb_nil_value();
  if (alen == i) return mrb_ary_new(mrb);
  if (len > alen - i) len = alen - i;

  return ary_subseq(mrb, a, i, len);
}

/*
 *  call-seq:
 *     ary[index]         = obj                      ->  obj
 *     ary[start, length] = obj or other_ary or nil  ->  obj or other_ary or nil
 *     ary[range]         = obj or other_ary or nil  ->  obj or other_ary or nil
 *
 *  Element Assignment --- Sets the element at +index+, or replaces a subarray
 *  from the +start+ index for +length+ elements, or replaces a subarray
 *  specified by the +range+ of indices.
 *
 *  If indices are greater than the current capacity of the array, the array
 *  grows automatically.  Elements are inserted into the array at +start+ if
 *  +length+ is zero.
 *
 *  Negative indices will count backward from the end of the array.  For
 *  +start+ and +range+ cases the starting index is just before an element.
 *
 *  An IndexError is raised if a negative index points past the beginning of
 *  the array.
 *
 *  See also Array#push, and Array#unshift.
 *
 *     a = Array.new
 *     a[4] = "4";                 #=> [nil, nil, nil, nil, "4"]
 *     a[0, 3] = [ 'a', 'b', 'c' ] #=> ["a", "b", "c", nil, "4"]
 *     a[1..2] = [ 1, 2 ]          #=> ["a", 1, 2, nil, "4"]
 *     a[0, 2] = "?"               #=> ["?", 2, nil, "4"]
 *     a[0..2] = "A"               #=> ["A", "4"]
 *     a[-1]   = "Z"               #=> ["A", "Z"]
 *     a[1..-1] = nil              #=> ["A", nil]
 *     a[1..-1] = []               #=> ["A"]
 *     a[0, 0] = [ 1, 2 ]          #=> [1, 2, "A"]
 *     a[3, 0] = "B"               #=> [1, 2, "A", "B"]
 */

static mrb_value
mrb_ary_aset(mrb_state *mrb, mrb_value self)
{
  mrb_value v1, v2, v3;
  mrb_int i, len;

  mrb_ary_modify(mrb, mrb_ary_ptr(self));
  if (mrb_get_args(mrb, "oo|o", &v1, &v2, &v3) == 2) {
    /* a[n..m] = v */
    switch (mrb_range_beg_len(mrb, v1, &i, &len, RARRAY_LEN(self), FALSE)) {
    case 0:                   /* not range */
      mrb_ary_set(mrb, self, aget_index(mrb, v1), v2);
      break;
    case 1:                   /* range */
      mrb_ary_splice(mrb, self, i, len, v2);
      break;
    case 2:                   /* out of range */
      mrb_raisef(mrb, E_RANGE_ERROR, "%S out of range", v1);
      break;
    }
    return v2;
  }

  /* a[n,m] = v */
  mrb_ary_splice(mrb, self, aget_index(mrb, v1), aget_index(mrb, v2), v3);
  return v3;
}

static mrb_value
mrb_ary_delete_at(mrb_state *mrb, mrb_value self)
{
  struct RArray *a = mrb_ary_ptr(self);
  mrb_int   index;
  mrb_value val;
  mrb_value *ptr;
  mrb_int len, alen = ARY_LEN(a);

  mrb_get_args(mrb, "i", &index);
  if (index < 0) index += alen;
  if (index < 0 || alen <= index) return mrb_nil_value();

  ary_modify(mrb, a);
  ptr = ARY_PTR(a);
  val = ptr[index];

  ptr += index;
  len = alen - index;
  while (--len) {
    *ptr = *(ptr+1);
    ++ptr;
  }
  ARY_SET_LEN(a, alen-1);

  ary_shrink_capa(mrb, a);

  return val;
}

static mrb_value
mrb_ary_first(mrb_state *mrb, mrb_value self)
{
  struct RArray *a = mrb_ary_ptr(self);
  mrb_int size, alen = ARY_LEN(a);

  if (mrb_get_argc(mrb) == 0) {
    return (alen > 0)? ARY_PTR(a)[0]: mrb_nil_value();
  }
  mrb_get_args(mrb, "|i", &size);
  if (size < 0) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "negative array size");
  }

  if (size > alen) size = alen;
  if (ARY_SHARED_P(a)) {
    return ary_subseq(mrb, a, 0, size);
  }
  return mrb_ary_new_from_values(mrb, size, ARY_PTR(a));
}

static mrb_value
mrb_ary_last(mrb_state *mrb, mrb_value self)
{
  struct RArray *a = mrb_ary_ptr(self);
  mrb_int size, alen = ARY_LEN(a);

  if (mrb_get_args(mrb, "|i", &size) == 0)
    return (alen > 0)? ARY_PTR(a)[alen - 1]: mrb_nil_value();

  if (size < 0) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "negative array size");
  }
  if (size > alen) size = alen;
  if (ARY_SHARED_P(a) || size > ARY_DEFAULT_LEN) {
    return ary_subseq(mrb, a, alen - size, size);
  }
  return mrb_ary_new_from_values(mrb, size, ARY_PTR(a) + alen - size);
}

static mrb_value
mrb_ary_index_m(mrb_state *mrb, mrb_value self)
{
  mrb_value obj;
  mrb_int i;

  mrb_get_args(mrb, "o", &obj);
  for (i = 0; i < RARRAY_LEN(self); i++) {
    if (mrb_equal(mrb, RARRAY_PTR(self)[i], obj)) {
      return mrb_fixnum_value(i);
    }
  }
  return mrb_nil_value();
}

static mrb_value
mrb_ary_rindex_m(mrb_state *mrb, mrb_value self)
{
  mrb_value obj;
  mrb_int i, len;

  mrb_get_args(mrb, "o", &obj);
  for (i = RARRAY_LEN(self) - 1; i >= 0; i--) {
    if (mrb_equal(mrb, RARRAY_PTR(self)[i], obj)) {
      return mrb_fixnum_value(i);
    }
    if (i > (len = RARRAY_LEN(self))) {
      i = len;
    }
  }
  return mrb_nil_value();
}

MRB_API mrb_value
mrb_ary_splat(mrb_state *mrb, mrb_value v)
{
  mrb_value a, recv_class;

  if (mrb_array_p(v)) {
    return v;
  }

  if (!mrb_respond_to(mrb, v, mrb_intern_lit(mrb, "to_a"))) {
    return mrb_ary_new_from_values(mrb, 1, &v);
  }

  a = mrb_funcall(mrb, v, "to_a", 0);
  if (mrb_array_p(a)) {
    return a;
  }
  else if (mrb_nil_p(a)) {
    return mrb_ary_new_from_values(mrb, 1, &v);
  }
  else {
    recv_class = mrb_obj_value(mrb_obj_class(mrb, v));
    mrb_raisef(mrb, E_TYPE_ERROR, "can't convert %S to Array (%S#to_a gives %S)",
      recv_class,
      recv_class,
      mrb_obj_value(mrb_obj_class(mrb, a))
    );
    /* not reached */
    return mrb_undef_value();
  }
}

static mrb_value
mrb_ary_size(mrb_state *mrb, mrb_value self)
{
  struct RArray *a = mrb_ary_ptr(self);

  return mrb_fixnum_value(ARY_LEN(a));
}

MRB_API mrb_value
mrb_ary_clear(mrb_state *mrb, mrb_value self)
{
  struct RArray *a = mrb_ary_ptr(self);

  ary_modify(mrb, a);
  if (ARY_SHARED_P(a)) {
    mrb_ary_decref(mrb, a->as.heap.aux.shared);
    ARY_UNSET_SHARED_FLAG(a);
  }
  else if (!ARY_EMBED_P(a)){
    mrb_free(mrb, a->as.heap.ptr);
  }
  ARY_SET_EMBED_LEN(a, 0);

  return self;
}

static mrb_value
mrb_ary_empty_p(mrb_state *mrb, mrb_value self)
{
  struct RArray *a = mrb_ary_ptr(self);

  return mrb_bool_value(ARY_LEN(a) == 0);
}

MRB_API mrb_value
mrb_check_array_type(mrb_state *mrb, mrb_value ary)
{
  return mrb_check_convert_type(mrb, ary, MRB_TT_ARRAY, "Array", "to_ary");
}

MRB_API mrb_value
mrb_ary_entry(mrb_value ary, mrb_int offset)
{
  if (offset < 0) {
    offset += RARRAY_LEN(ary);
  }
  if (offset < 0 || RARRAY_LEN(ary) <= offset) {
    return mrb_nil_value();
  }
  return RARRAY_PTR(ary)[offset];
}

static mrb_value
join_ary(mrb_state *mrb, mrb_value ary, mrb_value sep, mrb_value list)
{
  mrb_int i;
  mrb_value result, val, tmp;

  /* check recursive */
  for (i=0; i<RARRAY_LEN(list); i++) {
    if (mrb_obj_equal(mrb, ary, RARRAY_PTR(list)[i])) {
      mrb_raise(mrb, E_ARGUMENT_ERROR, "recursive array join");
    }
  }

  mrb_ary_push(mrb, list, ary);

  result = mrb_str_new_capa(mrb, 64);

  for (i=0; i<RARRAY_LEN(ary); i++) {
    if (i > 0 && !mrb_nil_p(sep)) {
      mrb_str_cat_str(mrb, result, sep);
    }

    val = RARRAY_PTR(ary)[i];
    switch (mrb_type(val)) {
    case MRB_TT_ARRAY:
    ary_join:
      val = join_ary(mrb, val, sep, list);
      /* fall through */

    case MRB_TT_STRING:
    str_join:
      mrb_str_cat_str(mrb, result, val);
      break;

    default:
      if (!mrb_immediate_p(val)) {
        tmp = mrb_check_string_type(mrb, val);
        if (!mrb_nil_p(tmp)) {
          val = tmp;
          goto str_join;
        }
        tmp = mrb_check_convert_type(mrb, val, MRB_TT_ARRAY, "Array", "to_ary");
        if (!mrb_nil_p(tmp)) {
          val = tmp;
          goto ary_join;
        }
      }
      val = mrb_obj_as_string(mrb, val);
      goto str_join;
    }
  }

  mrb_ary_pop(mrb, list);

  return result;
}

MRB_API mrb_value
mrb_ary_join(mrb_state *mrb, mrb_value ary, mrb_value sep)
{
  if (!mrb_nil_p(sep)) {
    sep = mrb_obj_as_string(mrb, sep);
  }
  return join_ary(mrb, ary, sep, mrb_ary_new(mrb));
}

/*
 *  call-seq:
 *     ary.join(sep="")    -> str
 *
 *  Returns a string created by converting each element of the array to
 *  a string, separated by <i>sep</i>.
 *
 *     [ "a", "b", "c" ].join        #=> "abc"
 *     [ "a", "b", "c" ].join("-")   #=> "a-b-c"
 */

static mrb_value
mrb_ary_join_m(mrb_state *mrb, mrb_value ary)
{
  mrb_value sep = mrb_nil_value();

  mrb_get_args(mrb, "|S!", &sep);
  return mrb_ary_join(mrb, ary, sep);
}

static mrb_value
mrb_ary_eq(mrb_state *mrb, mrb_value ary1)
{
  mrb_value ary2;

  mrb_get_args(mrb, "o", &ary2);
  if (mrb_obj_equal(mrb, ary1, ary2)) return mrb_true_value();
  if (!mrb_array_p(ary2)) {
    return mrb_false_value();
  }
  if (RARRAY_LEN(ary1) != RARRAY_LEN(ary2)) return mrb_false_value();

  return ary2;
}

static mrb_value
mrb_ary_cmp(mrb_state *mrb, mrb_value ary1)
{
  mrb_value ary2;

  mrb_get_args(mrb, "o", &ary2);
  if (mrb_obj_equal(mrb, ary1, ary2)) return mrb_fixnum_value(0);
  if (!mrb_array_p(ary2)) {
    return mrb_nil_value();
  }

  return ary2;
}

/* internal method to convert multi-value to single value */
static mrb_value
mrb_ary_svalue(mrb_state *mrb, mrb_value ary)
{
  mrb_get_args(mrb, "");
  switch (RARRAY_LEN(ary)) {
  case 0:
    return mrb_nil_value();
  case 1:
    return RARRAY_PTR(ary)[0];
  default:
    return ary;
  }
}

void
mrb_init_array(mrb_state *mrb)
{
  struct RClass *a;

  mrb->array_class = a = mrb_define_class(mrb, "Array", mrb->object_class);            /* 15.2.12 */
  MRB_SET_INSTANCE_TT(a, MRB_TT_ARRAY);

  mrb_define_class_method(mrb, a, "[]",        mrb_ary_s_create,     MRB_ARGS_ANY());  /* 15.2.12.4.1 */

  mrb_define_method(mrb, a, "+",               mrb_ary_plus,         MRB_ARGS_REQ(1)); /* 15.2.12.5.1  */
  mrb_define_method(mrb, a, "*",               mrb_ary_times,        MRB_ARGS_REQ(1)); /* 15.2.12.5.2  */
  mrb_define_method(mrb, a, "<<",              mrb_ary_push_m,       MRB_ARGS_REQ(1)); /* 15.2.12.5.3  */
  mrb_define_method(mrb, a, "[]",              mrb_ary_aget,         MRB_ARGS_ANY());  /* 15.2.12.5.4  */
  mrb_define_method(mrb, a, "[]=",             mrb_ary_aset,         MRB_ARGS_ANY());  /* 15.2.12.5.5  */
  mrb_define_method(mrb, a, "clear",           mrb_ary_clear,        MRB_ARGS_NONE()); /* 15.2.12.5.6  */
  mrb_define_method(mrb, a, "concat",          mrb_ary_concat_m,     MRB_ARGS_REQ(1)); /* 15.2.12.5.8  */
  mrb_define_method(mrb, a, "delete_at",       mrb_ary_delete_at,    MRB_ARGS_REQ(1)); /* 15.2.12.5.9  */
  mrb_define_method(mrb, a, "empty?",          mrb_ary_empty_p,      MRB_ARGS_NONE()); /* 15.2.12.5.12 */
  mrb_define_method(mrb, a, "first",           mrb_ary_first,        MRB_ARGS_OPT(1)); /* 15.2.12.5.13 */
  mrb_define_method(mrb, a, "index",           mrb_ary_index_m,      MRB_ARGS_REQ(1)); /* 15.2.12.5.14 */
  mrb_define_method(mrb, a, "initialize_copy", mrb_ary_replace_m,    MRB_ARGS_REQ(1)); /* 15.2.12.5.16 */
  mrb_define_method(mrb, a, "join",            mrb_ary_join_m,       MRB_ARGS_ANY());  /* 15.2.12.5.17 */
  mrb_define_method(mrb, a, "last",            mrb_ary_last,         MRB_ARGS_ANY());  /* 15.2.12.5.18 */
  mrb_define_method(mrb, a, "length",          mrb_ary_size,         MRB_ARGS_NONE()); /* 15.2.12.5.19 */
  mrb_define_method(mrb, a, "pop",             mrb_ary_pop,          MRB_ARGS_NONE()); /* 15.2.12.5.21 */
  mrb_define_method(mrb, a, "push",            mrb_ary_push_m,       MRB_ARGS_ANY());  /* 15.2.12.5.22 */
  mrb_define_method(mrb, a, "append",          mrb_ary_push_m,       MRB_ARGS_ANY());
  mrb_define_method(mrb, a, "replace",         mrb_ary_replace_m,    MRB_ARGS_REQ(1)); /* 15.2.12.5.23 */
  mrb_define_method(mrb, a, "reverse",         mrb_ary_reverse,      MRB_ARGS_NONE()); /* 15.2.12.5.24 */
  mrb_define_method(mrb, a, "reverse!",        mrb_ary_reverse_bang, MRB_ARGS_NONE()); /* 15.2.12.5.25 */
  mrb_define_method(mrb, a, "rindex",          mrb_ary_rindex_m,     MRB_ARGS_REQ(1)); /* 15.2.12.5.26 */
  mrb_define_method(mrb, a, "shift",           mrb_ary_shift,        MRB_ARGS_NONE()); /* 15.2.12.5.27 */
  mrb_define_method(mrb, a, "size",            mrb_ary_size,         MRB_ARGS_NONE()); /* 15.2.12.5.28 */
  mrb_define_method(mrb, a, "slice",           mrb_ary_aget,         MRB_ARGS_ANY());  /* 15.2.12.5.29 */
  mrb_define_method(mrb, a, "unshift",         mrb_ary_unshift_m,    MRB_ARGS_ANY());  /* 15.2.12.5.30 */
  mrb_define_method(mrb, a, "prepend",         mrb_ary_unshift_m,    MRB_ARGS_ANY());

  mrb_define_method(mrb, a, "__ary_eq",        mrb_ary_eq,           MRB_ARGS_REQ(1));
  mrb_define_method(mrb, a, "__ary_cmp",       mrb_ary_cmp,          MRB_ARGS_REQ(1));
  mrb_define_method(mrb, a, "__ary_index",     mrb_ary_index_m,      MRB_ARGS_REQ(1)); /* kept for mruby-array-ext */
  mrb_define_method(mrb, a, "__svalue",        mrb_ary_svalue,       MRB_ARGS_NONE());
}
