/**
** @file mruby/khash.h - Hash for mruby
**
** See Copyright Notice in mruby.h
*/

#ifndef MRUBY_KHASH_H
#define MRUBY_KHASH_H

#include <string.h>

#include <mruby.h>
#include "common.h"

/**
 * khash definitions used in mruby's hash table.
 */
MRB_BEGIN_DECL

typedef uint32_t khint_t;
typedef khint_t khiter_t;

#ifndef KHASH_DEFAULT_SIZE
# define KHASH_DEFAULT_SIZE 32
#endif
#define KHASH_MIN_SIZE 8

#define UPPER_BOUND(x) ((x)>>2|(x)>>1)

/* extern uint8_t __m[]; */

/* mask for flags */
static const uint8_t __m_empty[]  = {0x02, 0x08, 0x20, 0x80};
static const uint8_t __m_del[]    = {0x01, 0x04, 0x10, 0x40};
static const uint8_t __m_either[] = {0x03, 0x0c, 0x30, 0xc0};


#define __ac_isempty(ed_flag, i) (ed_flag[(i)/4]&__m_empty[(i)%4])
#define __ac_isdel(ed_flag, i) (ed_flag[(i)/4]&__m_del[(i)%4])
#define __ac_iseither(ed_flag, i) (ed_flag[(i)/4]&__m_either[(i)%4])
#define khash_power2(v) do { \
  v--;\
  v |= v >> 1;\
  v |= v >> 2;\
  v |= v >> 4;\
  v |= v >> 8;\
  v |= v >> 16;\
  v++;\
} while (0)
#define khash_mask(h) ((h)->n_buckets-1)
#define khash_upper_bound(h) (UPPER_BOUND((h)->n_buckets))

/* declare struct kh_xxx and kh_xxx_funcs

   name: hash name
   khkey_t: key data type
   khval_t: value data type
   kh_is_map: (0: hash set / 1: hash map)
*/
#define KHASH_DECLARE(name, khkey_t, khval_t, kh_is_map)                \
  typedef struct kh_##name {                                            \
    khint_t n_buckets;                                                  \
    khint_t size;                                                       \
    khint_t n_occupied;                                                 \
    uint8_t *ed_flags;                                                  \
    khkey_t *keys;                                                      \
    khval_t *vals;                                                      \
  } kh_##name##_t;                                                      \
  void kh_alloc_##name(mrb_state *mrb, kh_##name##_t *h);               \
  kh_##name##_t *kh_init_##name##_size(mrb_state *mrb, khint_t size);   \
  kh_##name##_t *kh_init_##name(mrb_state *mrb);                        \
  void kh_destroy_##name(mrb_state *mrb, kh_##name##_t *h);             \
  void kh_clear_##name(mrb_state *mrb, kh_##name##_t *h);               \
  khint_t kh_get_##name(mrb_state *mrb, kh_##name##_t *h, khkey_t key);           \
  khint_t kh_put_##name(mrb_state *mrb, kh_##name##_t *h, khkey_t key, int *ret); \
  void kh_put_prepare_##name(mrb_state *mrb, kh_##name##_t *h);                   \
  void kh_resize_##name(mrb_state *mrb, kh_##name##_t *h, khint_t new_n_buckets); \
  void kh_del_##name(mrb_state *mrb, kh_##name##_t *h, khint_t x);                \
  kh_##name##_t *kh_copy_##name(mrb_state *mrb, kh_##name##_t *h);

static inline void
kh_fill_flags(uint8_t *p, uint8_t c, size_t len)
{
  while (len-- > 0) {
    *p++ = c;
  }
}

/* define kh_xxx_funcs

   name: hash name
   khkey_t: key data type
   khval_t: value data type
   kh_is_map: (0: hash set / 1: hash map)
   __hash_func: hash function
   __hash_equal: hash comparation function
*/
#define KHASH_DEFINE(name, khkey_t, khval_t, kh_is_map, __hash_func, __hash_equal) \
  mrb_noreturn void mrb_raise_nomemory(mrb_state *mrb);                 \
  int kh_alloc_simple_##name(mrb_state *mrb, kh_##name##_t *h)          \
  {                                                                     \
    khint_t sz = h->n_buckets;                                          \
    size_t len = sizeof(khkey_t) + (kh_is_map ? sizeof(khval_t) : 0);   \
    uint8_t *p = (uint8_t*)mrb_malloc_simple(mrb, sizeof(uint8_t)*sz/4+len*sz); \
    if (!p) { return 1; }                                               \
    h->size = h->n_occupied = 0;                                        \
    h->keys = (khkey_t *)p;                                             \
    h->vals = kh_is_map ? (khval_t *)(p+sizeof(khkey_t)*sz) : NULL;     \
    h->ed_flags = p+len*sz;                                             \
    kh_fill_flags(h->ed_flags, 0xaa, sz/4);                             \
    return 0;                                                           \
  }                                                                     \
  void kh_alloc_##name(mrb_state *mrb, kh_##name##_t *h)                \
  {                                                                     \
    if (kh_alloc_simple_##name(mrb, h)) {                               \
      mrb_raise_nomemory(mrb);                                          \
    }                                                                   \
  }                                                                     \
  kh_##name##_t *kh_init_##name##_size(mrb_state *mrb, khint_t size) {  \
    kh_##name##_t *h = (kh_##name##_t*)mrb_calloc(mrb, 1, sizeof(kh_##name##_t)); \
    if (size < KHASH_MIN_SIZE)                                          \
      size = KHASH_MIN_SIZE;                                            \
    khash_power2(size);                                                 \
    h->n_buckets = size;                                                \
    if (kh_alloc_simple_##name(mrb, h)) {                               \
      mrb_free(mrb, h);                                                 \
      mrb_raise_nomemory(mrb);                                          \
    }                                                                   \
    return h;                                                           \
  }                                                                     \
  kh_##name##_t *kh_init_##name(mrb_state *mrb) {                       \
    return kh_init_##name##_size(mrb, KHASH_DEFAULT_SIZE);              \
  }                                                                     \
  void kh_destroy_##name(mrb_state *mrb, kh_##name##_t *h)              \
  {                                                                     \
    if (h) {                                                            \
      mrb_free(mrb, h->keys);                                           \
      mrb_free(mrb, h);                                                 \
    }                                                                   \
  }                                                                     \
  void kh_clear_##name(mrb_state *mrb, kh_##name##_t *h)                \
  {                                                                     \
    (void)mrb;                                                          \
    if (h && h->ed_flags) {                                             \
      kh_fill_flags(h->ed_flags, 0xaa, h->n_buckets/4);                 \
      h->size = h->n_occupied = 0;                                      \
    }                                                                   \
  }                                                                     \
  khint_t kh_get_##name(mrb_state *mrb, kh_##name##_t *h, khkey_t key)  \
  {                                                                     \
    khint_t k = __hash_func(mrb,key) & khash_mask(h), step = 0;         \
    (void)mrb;                                                          \
    while (!__ac_isempty(h->ed_flags, k)) {                             \
      if (!__ac_isdel(h->ed_flags, k)) {                                \
        if (__hash_equal(mrb,h->keys[k], key)) return k;                \
      }                                                                 \
      k = (k+(++step)) & khash_mask(h);                                 \
    }                                                                   \
    return kh_end(h);                                                   \
  }                                                                     \
  void kh_resize_##name(mrb_state *mrb, kh_##name##_t *h, khint_t new_n_buckets) \
  {                                                                     \
    if (new_n_buckets < KHASH_MIN_SIZE)                                 \
      new_n_buckets = KHASH_MIN_SIZE;                                   \
    khash_power2(new_n_buckets);                                        \
    {                                                                   \
      kh_##name##_t hh;                                                 \
      uint8_t *old_ed_flags = h->ed_flags;                              \
      khkey_t *old_keys = h->keys;                                      \
      khval_t *old_vals = h->vals;                                      \
      khint_t old_n_buckets = h->n_buckets;                             \
      khint_t i;                                                        \
      hh.n_buckets = new_n_buckets;                                     \
      kh_alloc_##name(mrb, &hh);                                        \
      /* relocate */                                                    \
      for (i=0 ; i<old_n_buckets ; i++) {                               \
        if (!__ac_iseither(old_ed_flags, i)) {                          \
          khint_t k = kh_put_##name(mrb, &hh, old_keys[i], NULL);       \
          if (kh_is_map) kh_value(&hh,k) = old_vals[i];                 \
        }                                                               \
      }                                                                 \
      /* copy hh to h */                                                \
      *h = hh;                                                          \
      mrb_free(mrb, old_keys);                                          \
    }                                                                   \
  }                                                                     \
  void kh_put_prepare_##name(mrb_state *mrb, kh_##name##_t *h)          \
  {                                                                     \
    if (h->n_occupied >= khash_upper_bound(h)) {                        \
      kh_resize_##name(mrb, h, h->n_buckets*2);                         \
    }                                                                   \
  }                                                                     \
  khint_t kh_put_##name(mrb_state *mrb, kh_##name##_t *h, khkey_t key, int *ret) \
  {                                                                     \
    khint_t k, del_k, step = 0;                                         \
    kh_put_prepare_##name(mrb, h);                                      \
    k = __hash_func(mrb,key) & khash_mask(h);                           \
    del_k = kh_end(h);                                                  \
    while (!__ac_isempty(h->ed_flags, k)) {                             \
      if (!__ac_isdel(h->ed_flags, k)) {                                \
        if (__hash_equal(mrb,h->keys[k], key)) {                        \
          if (ret) *ret = 0;                                            \
          return k;                                                     \
        }                                                               \
      }                                                                 \
      else if (del_k == kh_end(h)) {                                    \
        del_k = k;                                                      \
      }                                                                 \
      k = (k+(++step)) & khash_mask(h);                                 \
    }                                                                   \
    if (del_k != kh_end(h)) {                                           \
      /* put at del */                                                  \
      h->keys[del_k] = key;                                             \
      h->ed_flags[del_k/4] &= ~__m_del[del_k%4];                        \
      h->size++;                                                        \
      if (ret) *ret = 2;                                                \
      return del_k;                                                     \
    }                                                                   \
    else {                                                              \
      /* put at empty */                                                \
      h->keys[k] = key;                                                 \
      h->ed_flags[k/4] &= ~__m_empty[k%4];                              \
      h->size++;                                                        \
      h->n_occupied++;                                                  \
      if (ret) *ret = 1;                                                \
      return k;                                                         \
    }                                                                   \
  }                                                                     \
  void kh_del_##name(mrb_state *mrb, kh_##name##_t *h, khint_t x)       \
  {                                                                     \
    (void)mrb;                                                          \
    mrb_assert(x != h->n_buckets && !__ac_iseither(h->ed_flags, x));    \
    h->ed_flags[x/4] |= __m_del[x%4];                                   \
    h->size--;                                                          \
  }                                                                     \
  kh_##name##_t *kh_copy_##name(mrb_state *mrb, kh_##name##_t *h)       \
  {                                                                     \
    kh_##name##_t *h2;                                                  \
    khiter_t k, k2;                                                     \
                                                                        \
    h2 = kh_init_##name(mrb);                                           \
    for (k = kh_begin(h); k != kh_end(h); k++) {                        \
      if (kh_exist(h, k)) {                                             \
        k2 = kh_put_##name(mrb, h2, kh_key(h, k), NULL);                \
        if (kh_is_map) kh_value(h2, k2) = kh_value(h, k);               \
      }                                                                 \
    }                                                                   \
    return h2;                                                          \
  }


#define khash_t(name) kh_##name##_t

#define kh_init_size(name,mrb,size) kh_init_##name##_size(mrb,size)
#define kh_init(name,mrb) kh_init_##name(mrb)
#define kh_destroy(name, mrb, h) kh_destroy_##name(mrb, h)
#define kh_clear(name, mrb, h) kh_clear_##name(mrb, h)
#define kh_resize(name, mrb, h, s) kh_resize_##name(mrb, h, s)
#define kh_put_prepare(name, mrb, h) kh_put_prepare_##name(mrb, h)
#define kh_put(name, mrb, h, k) kh_put_##name(mrb, h, k, NULL)
#define kh_put2(name, mrb, h, k, r) kh_put_##name(mrb, h, k, r)
#define kh_get(name, mrb, h, k) kh_get_##name(mrb, h, k)
#define kh_del(name, mrb, h, k) kh_del_##name(mrb, h, k)
#define kh_copy(name, mrb, h) kh_copy_##name(mrb, h)

#define kh_exist(h, x) (!__ac_iseither((h)->ed_flags, (x)))
#define kh_key(h, x) ((h)->keys[x])
#define kh_val(h, x) ((h)->vals[x])
#define kh_value(h, x) ((h)->vals[x])
#define kh_begin(h) (khint_t)(0)
#define kh_end(h) ((h)->n_buckets)
#define kh_size(h) ((h)->size)
#define kh_n_buckets(h) ((h)->n_buckets)

#define kh_int_hash_func(mrb,key) (khint_t)((key)^((key)<<2)^((key)>>2))
#define kh_int_hash_equal(mrb,a, b) (a == b)
#define kh_int64_hash_func(mrb,key) (khint_t)((key)>>33^(key)^(key)<<11)
#define kh_int64_hash_equal(mrb,a, b) (a == b)
static inline khint_t __ac_X31_hash_string(const char *s)
{
    khint_t h = *s;
    if (h) for (++s ; *s; ++s) h = (h << 5) - h + *s;
    return h;
}
#define kh_str_hash_func(mrb,key) __ac_X31_hash_string(key)
#define kh_str_hash_equal(mrb,a, b) (strcmp(a, b) == 0)

typedef const char *kh_cstr_t;

MRB_END_DECL

#endif  /* MRUBY_KHASH_H */
