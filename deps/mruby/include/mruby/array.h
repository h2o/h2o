/*
** mruby/array.h - Array class
**
** See Copyright Notice in mruby.h
*/

#ifndef MRUBY_ARRAY_H
#define MRUBY_ARRAY_H

#if defined(__cplusplus)
extern "C" {
#endif

typedef struct mrb_shared_array {
  int refcnt;
  mrb_int len;
  mrb_value *ptr;
} mrb_shared_array;

struct RArray {
  MRB_OBJECT_HEADER;
  mrb_int len;
  union {
    mrb_int capa;
    mrb_shared_array *shared;
  } aux;
  mrb_value *ptr;
};

#define mrb_ary_ptr(v)    ((struct RArray*)(mrb_ptr(v)))
#define mrb_ary_value(p)  mrb_obj_value((void*)(p))
#define RARRAY(v)  ((struct RArray*)(mrb_ptr(v)))

#define RARRAY_LEN(a) (RARRAY(a)->len)
#define RARRAY_PTR(a) ((const mrb_value*)RARRAY(a)->ptr)
#define MRB_ARY_SHARED      256
#define ARY_SHARED_P(a) ((a)->flags & MRB_ARY_SHARED)
#define ARY_SET_SHARED_FLAG(a) ((a)->flags |= MRB_ARY_SHARED)
#define ARY_UNSET_SHARED_FLAG(a) ((a)->flags &= ~MRB_ARY_SHARED)

void mrb_ary_decref(mrb_state*, mrb_shared_array*);
MRB_API void mrb_ary_modify(mrb_state*, struct RArray*);
MRB_API mrb_value mrb_ary_new_capa(mrb_state*, mrb_int);
MRB_API mrb_value mrb_ary_new(mrb_state *mrb);
MRB_API mrb_value mrb_ary_new_from_values(mrb_state *mrb, mrb_int size, const mrb_value *vals);
MRB_API mrb_value mrb_assoc_new(mrb_state *mrb, mrb_value car, mrb_value cdr);
MRB_API void mrb_ary_concat(mrb_state*, mrb_value, mrb_value);
MRB_API mrb_value mrb_ary_splat(mrb_state*, mrb_value);
MRB_API void mrb_ary_push(mrb_state*, mrb_value, mrb_value);
MRB_API mrb_value mrb_ary_pop(mrb_state *mrb, mrb_value ary);
MRB_API mrb_value mrb_ary_ref(mrb_state *mrb, mrb_value ary, mrb_int n);
MRB_API void mrb_ary_set(mrb_state *mrb, mrb_value ary, mrb_int n, mrb_value val);
MRB_API void mrb_ary_replace(mrb_state *mrb, mrb_value a, mrb_value b);
MRB_API mrb_value mrb_check_array_type(mrb_state *mrb, mrb_value self);
MRB_API mrb_value mrb_ary_unshift(mrb_state *mrb, mrb_value self, mrb_value item);
MRB_API mrb_value mrb_ary_entry(mrb_value ary, mrb_int offset);
MRB_API mrb_value mrb_ary_shift(mrb_state *mrb, mrb_value self);
MRB_API mrb_value mrb_ary_clear(mrb_state *mrb, mrb_value self);
MRB_API mrb_value mrb_ary_join(mrb_state *mrb, mrb_value ary, mrb_value sep);
MRB_API mrb_value mrb_ary_resize(mrb_state *mrb, mrb_value ary, mrb_int len);

static inline mrb_int
mrb_ary_len(mrb_state *mrb, mrb_value ary)
{
  (void)mrb;
  mrb_assert(mrb_array_p(ary));
  return RARRAY_LEN(ary);
}

#if defined(__cplusplus)
}  /* extern "C" { */
#endif

#endif  /* MRUBY_ARRAY_H */
