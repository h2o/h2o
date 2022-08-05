/**
** @file mruby/array.h - Array class
**
** See Copyright Notice in mruby.h
*/

#ifndef MRUBY_ARRAY_H
#define MRUBY_ARRAY_H

#include "common.h"

/*
 * Array class
 */
MRB_BEGIN_DECL

typedef struct mrb_shared_array {
  int refcnt;
  mrb_ssize len;
  mrb_value *ptr;
} mrb_shared_array;

#if defined(MRB_32BIT) && defined(MRB_NO_BOXING) && !defined(MRB_USE_FLOAT32) && !defined(MRB_ARY_NO_EMBED)
# define MRB_ARY_NO_EMBED
#endif

#ifdef MRB_ARY_NO_EMBED
# define MRB_ARY_EMBED_LEN_MAX 0
#else
# define MRB_ARY_EMBED_LEN_MAX ((mrb_int)(sizeof(void*)*3/sizeof(mrb_value)))
mrb_static_assert(MRB_ARY_EMBED_LEN_MAX > 0, "MRB_ARY_EMBED_LEN_MAX > 0");
#endif

struct RArray {
  MRB_OBJECT_HEADER;
  union {
    struct {
      mrb_ssize len;
      union {
        mrb_ssize capa;
        mrb_shared_array *shared;
      } aux;
      mrb_value *ptr;
    } heap;
#ifndef MRB_ARY_NO_EMBED
    mrb_value ary[MRB_ARY_EMBED_LEN_MAX];
#endif
  } as;
};

#define mrb_ary_ptr(v)    ((struct RArray*)(mrb_ptr(v)))
#define mrb_ary_value(p)  mrb_obj_value((void*)(p))
#define RARRAY(v)  ((struct RArray*)(mrb_ptr(v)))

#ifdef MRB_ARY_NO_EMBED
#define ARY_EMBED_P(a) 0
#define ARY_UNSET_EMBED_FLAG(a) (void)0
#define ARY_EMBED_LEN(a) 0
#define ARY_SET_EMBED_LEN(a,len) (void)0
#define ARY_EMBED_PTR(a) 0
#else
#define MRB_ARY_EMBED_MASK  7
#define ARY_EMBED_P(a) ((a)->flags & MRB_ARY_EMBED_MASK)
#define ARY_UNSET_EMBED_FLAG(a) ((a)->flags &= ~(MRB_ARY_EMBED_MASK))
#define ARY_EMBED_LEN(a) ((mrb_int)(((a)->flags & MRB_ARY_EMBED_MASK) - 1))
#define ARY_SET_EMBED_LEN(a,len) ((a)->flags = ((a)->flags&~MRB_ARY_EMBED_MASK) | ((uint32_t)(len) + 1))
#define ARY_EMBED_PTR(a) ((a)->as.ary)
#endif

#define ARY_LEN(a) (ARY_EMBED_P(a)?ARY_EMBED_LEN(a):(mrb_int)(a)->as.heap.len)
#define ARY_PTR(a) (ARY_EMBED_P(a)?ARY_EMBED_PTR(a):(a)->as.heap.ptr)
#define RARRAY_LEN(a) ARY_LEN(RARRAY(a))
#define RARRAY_PTR(a) ARY_PTR(RARRAY(a))
#define ARY_SET_LEN(a,n) do {\
  if (ARY_EMBED_P(a)) {\
    mrb_assert((n) <= MRB_ARY_EMBED_LEN_MAX); \
    ARY_SET_EMBED_LEN(a,n);\
  }\
  else\
    (a)->as.heap.len = (n);\
} while (0)
#define ARY_CAPA(a) (ARY_EMBED_P(a)?MRB_ARY_EMBED_LEN_MAX:(a)->as.heap.aux.capa)
#define MRB_ARY_SHARED      256
#define ARY_SHARED_P(a) ((a)->flags & MRB_ARY_SHARED)
#define ARY_SET_SHARED_FLAG(a) ((a)->flags |= MRB_ARY_SHARED)
#define ARY_UNSET_SHARED_FLAG(a) ((a)->flags &= ~MRB_ARY_SHARED)

MRB_API void mrb_ary_modify(mrb_state*, struct RArray*);
MRB_API mrb_value mrb_ary_new_capa(mrb_state*, mrb_int);

/*
 * Initializes a new array.
 *
 * Equivalent to:
 *
 *      Array.new
 *
 * @param mrb The mruby state reference.
 * @return The initialized array.
 */
MRB_API mrb_value mrb_ary_new(mrb_state *mrb);

/*
 * Initializes a new array with initial values
 *
 * Equivalent to:
 *
 *      Array[value1, value2, ...]
 *
 * @param mrb The mruby state reference.
 * @param size The number of values.
 * @param vals The actual values.
 * @return The initialized array.
 */
MRB_API mrb_value mrb_ary_new_from_values(mrb_state *mrb, mrb_int size, const mrb_value *vals);

/*
 * Initializes a new array with two initial values
 *
 * Equivalent to:
 *
 *      Array[car, cdr]
 *
 * @param mrb The mruby state reference.
 * @param car The first value.
 * @param cdr The second value.
 * @return The initialized array.
 */
MRB_API mrb_value mrb_assoc_new(mrb_state *mrb, mrb_value car, mrb_value cdr);

/*
 * Concatenate two arrays. The target array will be modified
 *
 * Equivalent to:
 *      ary.concat(other)
 *
 * @param mrb The mruby state reference.
 * @param self The target array.
 * @param other The array that will be concatenated to self.
 */
MRB_API void mrb_ary_concat(mrb_state *mrb, mrb_value self, mrb_value other);

/*
 * Create an array from the input. It tries calling to_a on the
 * value. If value does not respond to that, it creates a new
 * array with just this value.
 *
 * @param mrb The mruby state reference.
 * @param value The value to change into an array.
 * @return An array representation of value.
 */
MRB_API mrb_value mrb_ary_splat(mrb_state *mrb, mrb_value value);

/*
 * Pushes value into array.
 *
 * Equivalent to:
 *
 *      ary << value
 *
 * @param mrb The mruby state reference.
 * @param ary The array in which the value will be pushed
 * @param value The value to be pushed into array
 */
MRB_API void mrb_ary_push(mrb_state *mrb, mrb_value array, mrb_value value);

/*
 * Pops the last element from the array.
 *
 * Equivalent to:
 *
 *      ary.pop
 *
 * @param mrb The mruby state reference.
 * @param ary The array from which the value will be popped.
 * @return The popped value.
 */
MRB_API mrb_value mrb_ary_pop(mrb_state *mrb, mrb_value ary);

/*
 * Sets a value on an array at the given index
 *
 * Equivalent to:
 *
 *      ary[n] = val
 *
 * @param mrb The mruby state reference.
 * @param ary The target array.
 * @param n The array index being referenced.
 * @param val The value being set.
 */
MRB_API void mrb_ary_set(mrb_state *mrb, mrb_value ary, mrb_int n, mrb_value val);

/*
 * Replace the array with another array
 *
 * Equivalent to:
 *
 *      ary.replace(other)
 *
 * @param mrb The mruby state reference
 * @param self The target array.
 * @param other The array to replace it with.
 */
MRB_API void mrb_ary_replace(mrb_state *mrb, mrb_value self, mrb_value other);

/*
 * Unshift an element into the array
 *
 * Equivalent to:
 *
 *     ary.unshift(item)
 *
 * @param mrb The mruby state reference.
 * @param self The target array.
 * @param item The item to unshift.
 */
MRB_API mrb_value mrb_ary_unshift(mrb_state *mrb, mrb_value self, mrb_value item);

/*
 * Get nth element in the array
 *
 * Equivalent to:
 *
 *     ary[offset]
 *
 * @param ary The target array.
 * @param offset The element position (negative counts from the tail).
 */
MRB_API mrb_value mrb_ary_entry(mrb_value ary, mrb_int offset);
#define mrb_ary_ref(mrb, ary, n) mrb_ary_entry(ary, n)

/*
 * Replace subsequence of an array.
 *
 * Equivalent to:
 *
 *      ary[head, len] = rpl
 *
 * @param mrb The mruby state reference.
 * @param self The array from which the value will be partiality replaced.
 * @param head Beginning position of a replacement subsequence.
 * @param len Length of a replacement subsequence.
 * @param rpl The array of replacement elements.
 *            It is possible to pass `mrb_undef_value()` instead of an empty array.
 * @return The receiver array.
 */
MRB_API mrb_value mrb_ary_splice(mrb_state *mrb, mrb_value self, mrb_int head, mrb_int len, mrb_value rpl);

/*
 * Shifts the first element from the array.
 *
 * Equivalent to:
 *
 *      ary.shift
 *
 * @param mrb The mruby state reference.
 * @param self The array from which the value will be shifted.
 * @return The shifted value.
 */
MRB_API mrb_value mrb_ary_shift(mrb_state *mrb, mrb_value self);

/*
 * Removes all elements from the array
 *
 * Equivalent to:
 *
 *      ary.clear
 *
 * @param mrb The mruby state reference.
 * @param self The target array.
 * @return self
 */
MRB_API mrb_value mrb_ary_clear(mrb_state *mrb, mrb_value self);

/*
 * Join the array elements together in a string
 *
 * Equivalent to:
 *
 *      ary.join(sep="")
 *
 * @param mrb The mruby state reference.
 * @param ary The target array
 * @param sep The separator, can be NULL
 */
MRB_API mrb_value mrb_ary_join(mrb_state *mrb, mrb_value ary, mrb_value sep);

/*
 * Update the capacity of the array
 *
 * @param mrb The mruby state reference.
 * @param ary The target array.
 * @param new_len The new capacity of the array
 */
MRB_API mrb_value mrb_ary_resize(mrb_state *mrb, mrb_value ary, mrb_int new_len);


MRB_END_DECL

#endif  /* MRUBY_ARRAY_H */
