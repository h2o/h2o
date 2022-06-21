/*
** hash.c - Hash class
**
** See Copyright Notice in mruby.h
*/

#include <string.h>
#include <mruby.h>
#include <mruby/array.h>
#include <mruby/class.h>
#include <mruby/hash.h>
#include <mruby/string.h>
#include <mruby/variable.h>
#include <mruby/presym.h>

/*
 * === Glossary
 *
 * [EA]
 *   Entry Array. Store `Hash' entries in insertion order.
 *
 * [AR]
 *   Array Table Implementation. The structure of `Hash` that doesn't have a
 *   hash table and linearly searches EA. It is used when `Hash` size <= 16.
 *
 * [IB]
 *   Index Buckets. The buckets of hash table, where the bucket value is EA
 *   index. The index is represented by variable length bits according to
 *   the capacity.
 *
 * [HT]
 *   Hash Table Implementation. The structure of `Hash` that has IB and is
 *   searched by hash table algorithm. It is used when `Hash` size > 16.
 *   Collision resolution strategy is open addressing method.
 *
 * [size]
 *   The number of `Hash` entries (value of `Hash#size`).
 *
 * [slot]
 *   The generic term for EA or IB elements.
 *
 * [active]
 *   The state in which a slot is recognized as a `Hash` entry.
 *
 * [deleted]
 *   The state in which a slot is marked as deleted.
 *
 * [used]
 *   The state in which a slot is active or deleted.
 *
 * [empty]
 *   The state in which a slot is not used. Capacity is equal to the sum of
 *   the number of used slots and the number of empty slots.
 */

#define EA_N_RESERVED_INDICES 2  /* empty and deleted */
#define EA_INCREASE_RATIO 6 / 5 + 6
#define EA_MAX_INCREASE UINT16_MAX
#define EA_MAX_CAPA U32(lesser(IB_MAX_CAPA - EA_N_RESERVED_INDICES, MRB_INT_MAX))
#define IB_MAX_CAPA (U32(1) << IB_MAX_BIT)
#define IB_TYPE_BIT 32
#define IB_INIT_BIT (                                                         \
  ib_upper_bound_for(32) <= AR_MAX_SIZE ? 6 :                                 \
  ib_upper_bound_for(16) <= AR_MAX_SIZE ? 5 :                                 \
  4                                                                           \
)
#define IB_MAX_BIT (IB_TYPE_BIT - 1)
#define AR_DEFAULT_CAPA 4
#define AR_MAX_SIZE 16
#define H_MAX_SIZE EA_MAX_CAPA

mrb_static_assert(offsetof(struct RHash, iv) == offsetof(struct RObject, iv));
mrb_static_assert(AR_MAX_SIZE < (1 << MRB_HASH_AR_EA_CAPA_BIT));

typedef struct hash_entry {
  mrb_value key;
  mrb_value val;
} hash_entry;

typedef struct hash_table {
  hash_entry *ea;
#ifdef MRB_32BIT
  uint32_t ea_capa;
  uint32_t ea_n_used;
#endif
  uint32_t ib[];
} hash_table;

typedef struct index_buckets_iter {
  struct RHash *h;
  uint32_t bit;
  uint32_t mask;
  uint32_t pos;
  uint32_t ary_index;
  uint32_t ea_index;
  uint32_t shift1;
  uint32_t shift2;
  uint32_t step;
} index_buckets_iter;

/*
 * `c_` :: receiver class (category)
 * `n_` :: attribute name
 * `t_` :: attribute type
 * `p_` :: struct member path
 * `k_` :: macro key
 */
#define DEFINE_GETTER(c_, n_, t_, p_)                                         \
  MRB_INLINE t_ c_##_##n_(const struct RHash *h) {return h->p_;}
#define DEFINE_SETTER(c_, n_, t_, p_)                                         \
  MRB_INLINE void c_##_set_##n_(struct RHash *h, t_ v) {h->p_ = v;}
#define DEFINE_ACCESSOR(c_, n_, t_, p_)                                       \
  DEFINE_GETTER(c_, n_, t_, p_)                                               \
  DEFINE_SETTER(c_, n_, t_, p_)
#define DEFINE_FLAG_GETTER(c_, n_, t_, k_)                                    \
  MRB_INLINE t_ c_##_##n_(const struct RHash *h) {                            \
    return (t_)((h->flags & MRB_HASH_##k_##_MASK) >> MRB_HASH_##k_##_SHIFT);  \
  }
#define DEFINE_FLAG_SETTER(c_, n_, t_, k_)                                    \
  MRB_INLINE void c_##_set_##n_(struct RHash *h, t_ v) {                      \
    h->flags &= ~MRB_HASH_##k_##_MASK;                                        \
    h->flags |= v << MRB_HASH_##k_##_SHIFT;                                   \
  }
#define DEFINE_FLAG_ACCESSOR(c_, n_, t_, k_)                                  \
  DEFINE_FLAG_GETTER(c_, n_, t_, k_)                                          \
  DEFINE_FLAG_SETTER(c_, n_, t_, k_)
#define DEFINE_INCREMENTER(c_, n_)                                            \
  MRB_INLINE void c_##_inc_##n_(struct RHash *h) {                            \
    c_##_set_##n_(h, c_##_##n_(h) + 1);                                       \
  }
#define DEFINE_DECREMENTER(c_, n_)                                            \
  MRB_INLINE void c_##_dec_##n_(struct RHash *h) {                            \
    c_##_set_##n_(h, c_##_##n_(h) - 1);                                       \
  }
#define DEFINE_SWITCHER(n_, k_)                                               \
  MRB_INLINE void h_##n_##_on(struct RHash *h) {                              \
    h->flags |= MRB_HASH_##k_;                                                \
  }                                                                           \
  MRB_INLINE void h_##n_##_off(struct RHash *h) {                             \
    h->flags &= ~MRB_HASH_##k_;                                               \
  }                                                                           \
  MRB_INLINE mrb_bool h_##n_##_p(const struct RHash *h) {                     \
    return (h->flags & MRB_HASH_##k_) == MRB_HASH_##k_;                       \
  }

#ifdef MRB_64BIT
DEFINE_ACCESSOR(ar, ea_capa, uint32_t, ea_capa)
DEFINE_ACCESSOR(ar, ea_n_used, uint32_t, ea_n_used)
DEFINE_ACCESSOR(ht, ea_capa, uint32_t, ea_capa)
DEFINE_ACCESSOR(ht, ea_n_used, uint32_t, ea_n_used)
#else
DEFINE_FLAG_ACCESSOR(ar, ea_capa, uint32_t, AR_EA_CAPA)
DEFINE_FLAG_ACCESSOR(ar, ea_n_used, uint32_t, AR_EA_N_USED)
DEFINE_ACCESSOR(ht, ea_capa, uint32_t, hsh.ht->ea_capa)
DEFINE_ACCESSOR(ht, ea_n_used, uint32_t, hsh.ht->ea_n_used)
#endif
DEFINE_FLAG_ACCESSOR(ib, bit, uint32_t, IB_BIT)
DEFINE_ACCESSOR(ar, size, uint32_t, size)
DEFINE_ACCESSOR(ar, ea, hash_entry*, hsh.ea)
DEFINE_DECREMENTER(ar, size)
DEFINE_ACCESSOR(ht, size, uint32_t, size)
DEFINE_ACCESSOR(ht, ea, hash_entry*, hsh.ht->ea)
DEFINE_GETTER(ht, ib, uint32_t*, hsh.ht->ib)
DEFINE_INCREMENTER(ht, size)
DEFINE_DECREMENTER(ht, size)
DEFINE_GETTER(h, size, uint32_t, size)
DEFINE_ACCESSOR(h, ht, hash_table*, hsh.ht)
DEFINE_SWITCHER(ht, HT)

#define ea_each_used(ea, n_used, entry_var, code) do {                        \
  hash_entry *entry_var = ea, *ea_end__ = entry_var + (n_used);               \
  for (; entry_var < ea_end__; ++entry_var) {                                 \
    code;                                                                     \
  }                                                                           \
} while (0)

#define ea_each(ea, size, entry_var, code) do {                               \
  hash_entry *entry_var = ea;                                                 \
  uint32_t size__ = size;                                                     \
  for (; 0 < size__; ++entry_var) {                                           \
    if (entry_deleted_p(entry_var)) continue;                                 \
    --size__;                                                                 \
    code;                                                                     \
  }                                                                           \
} while (0)

#define ib_cycle_by_key(mrb, h, key, it_var, code) do {                       \
  index_buckets_iter it_var[1];                                               \
  ib_it_init(mrb, it_var, h, key);                                            \
  for (;;) {                                                                  \
    ib_it_next(it_var);                                                       \
    code;                                                                     \
  }                                                                           \
} while (0)

#define ib_find_by_key(mrb, h_, key_, it_var, code) do {                      \
  mrb_value ib_fbk_key__ = key_;                                              \
  ib_cycle_by_key(mrb, h_, ib_fbk_key__, it_var, {                            \
    if (ib_it_empty_p(it_var)) break;                                         \
    if (ib_it_deleted_p(it_var)) continue;                                    \
    if (obj_eql(mrb, ib_fbk_key__, ib_it_entry(it_var)->key, it_var->h)) {    \
      code;                                                                   \
      break;                                                                  \
    }                                                                         \
  });                                                                         \
} while (0)

#define h_each(h, entry_var, code) do {                                       \
  struct RHash *h__ = h;                                                      \
  hash_entry *h_e_ea__;                                                       \
  uint32_t h_e_size__;                                                        \
  h_ar_p(h) ? (h_e_ea__ = ar_ea(h__), h_e_size__ = ar_size(h__)) :            \
              (h_e_ea__ = ht_ea(h__), h_e_size__ = ht_size(h__));             \
  ea_each(h_e_ea__, h_e_size__, entry_var, code);                             \
} while (0)

/*
 * In `h_check_modified()`, in the case of `MRB_NO_BOXING`, `ht_ea()` or
 * `ht_ea_capa()` for AR may read uninitialized area (#5332). Therefore, do
 * not use those macros for AR in `MRB_NO_BOXING` (but in the case of
 * `MRB_64BIT`, `ht_ea_capa()` is the same as `ar_ea_capa()`, so use it).
 */
#ifdef MRB_NO_BOXING
# define H_CHECK_MODIFIED_USE_HT_EA_FOR_AR FALSE
# ifdef MRB_64BIT
#  define H_CHECK_MODIFIED_USE_HT_EA_CAPA_FOR_AR TRUE
# else
#  define H_CHECK_MODIFIED_USE_HT_EA_CAPA_FOR_AR FALSE
# endif  /* MRB_64BIT */
#else
# define H_CHECK_MODIFIED_USE_HT_EA_FOR_AR TRUE
# define H_CHECK_MODIFIED_USE_HT_EA_CAPA_FOR_AR TRUE
 /*
  * `h_check_modified` raises an exception when a dangerous modification is
  * made to `h` by executing `code`.
  *
  * `h_check_modified` macro is not called if `h->hsh.ht` (`h->hsh.ea`) is `NULL`
  * (`Hash` size is zero). And because the `hash_entry` is rather large,
  * `h->hsh.ht->ea` and `h->hsh.ht->ea_capa` are able to be safely accessed even for
  * AR. This nature is used to eliminate branch of AR or HT.
  *
  * `HT_ASSERT_SAFE_READ` checks if members can be accessed according to its
  * assumptions.
  */
# define HT_ASSERT_SAFE_READ(attr_name)                                       \
  mrb_static_assert(                                                          \
    offsetof(hash_table, attr_name) + sizeof(((hash_table*)0)->attr_name) <=  \
    sizeof(hash_entry))
HT_ASSERT_SAFE_READ(ea);
# ifdef MRB_32BIT
HT_ASSERT_SAFE_READ(ea_capa);
# endif
# undef HT_ASSERT_SAFE_READ
#endif  /* MRB_NO_BOXING */

/*
 * `h_check_modified` raises an exception when a dangerous modification is
 * made to `h` by executing `code`.
 */
#define h_check_modified(mrb, h, code) do {                                     \
  struct RHash *h__ = h;                                                        \
  uint32_t mask__ = MRB_HASH_HT|MRB_HASH_IB_BIT_MASK|MRB_HASH_AR_EA_CAPA_MASK;  \
  uint32_t flags__ = h__->flags & mask__;                                       \
  void* tbl__ = (mrb_assert(h__->hsh.ht), h__->hsh.ht);                         \
  uint32_t ht_ea_capa__ = 0;                                                    \
  hash_entry *ht_ea__ = NULL;                                                   \
  if (H_CHECK_MODIFIED_USE_HT_EA_CAPA_FOR_AR || h_ht_p(h__)) {                  \
    ht_ea_capa__ = ht_ea_capa(h__);                                             \
  }                                                                             \
  if (H_CHECK_MODIFIED_USE_HT_EA_FOR_AR || h_ht_p(h__)) {                       \
    ht_ea__ = ht_ea(h__);                                                       \
  }                                                                             \
  code;                                                                         \
  if (flags__ != (h__->flags & mask__) ||                                       \
      tbl__ != h__->hsh.ht ||                                                       \
      ((H_CHECK_MODIFIED_USE_HT_EA_CAPA_FOR_AR || h_ht_p(h__)) &&               \
       ht_ea_capa__ != ht_ea_capa(h__)) ||                                      \
      ((H_CHECK_MODIFIED_USE_HT_EA_FOR_AR || h_ht_p(h__)) &&                    \
       ht_ea__ != ht_ea(h__))) {                                                \
    mrb_raise(mrb, E_RUNTIME_ERROR, "hash modified");                           \
  }                                                                             \
} while (0)

#define U32(v) ((uint32_t)(v))
#define h_ar_p(h) (!h_ht_p(h))
#define h_ar_on(h) h_ht_off(h)
#define lesser(a, b) ((a) < (b) ? (a) : (b))
#define RHASH_IFNONE(hash) mrb_iv_get(mrb, (hash), MRB_SYM(ifnone))
#define RHASH_PROCDEFAULT(hash) RHASH_IFNONE(hash)

static uint32_t ib_upper_bound_for(uint32_t capa);
static uint32_t ib_bit_to_capa(uint32_t bit);
static void ht_init(
  mrb_state *mrb, struct RHash *h, uint32_t size,
  hash_entry *ea, uint32_t ea_capa, hash_table *ht, uint32_t ib_bit);
static void ht_set_without_ib_adjustment(
  mrb_state *mrb, struct RHash *h, mrb_value key, mrb_value val);

static uint32_t
next_power2(uint32_t v)
{
  mrb_assert(v != 0);
#ifdef __GNUC__
  return U32(1) << ((sizeof(unsigned) * CHAR_BIT) - __builtin_clz(v));
#else
  v |= v >> 1;
  v |= v >> 2;
  v |= v >> 4;
  v |= v >> 8;
  v |= v >> 16;
  ++v;
  return v;
#endif
}

static uint32_t
obj_hash_code(mrb_state *mrb, mrb_value key, struct RHash *h)
{
  enum mrb_vtype tt = mrb_type(key);
  uint32_t hash_code;
  mrb_value hash_code_obj;
  switch (tt) {
  case MRB_TT_STRING:
    hash_code = mrb_str_hash(mrb, key);
    break;
  case MRB_TT_TRUE:
  case MRB_TT_FALSE:
  case MRB_TT_SYMBOL:
    hash_code = U32(mrb_fixnum(key));
    break;
  case MRB_TT_INTEGER:
    if (mrb_fixnum_p(key)) {
      hash_code = U32(mrb_fixnum(key));
      break;
    }
#ifndef MRB_NO_FLOAT
    /* fall through */
  case MRB_TT_FLOAT:
#endif
    hash_code = U32(mrb_obj_id(key));
    break;
  default:
    h_check_modified(mrb, h, {
      hash_code_obj = mrb_funcall_argv(mrb, key, MRB_SYM(hash), 0, NULL);
    });

    hash_code = U32(tt) ^ U32(mrb_integer(hash_code_obj));
    break;
  }
  return hash_code ^ (hash_code << 2) ^ (hash_code >> 2);
}

static mrb_bool
obj_eql(mrb_state *mrb, mrb_value a, mrb_value b, struct RHash *h)
{
  enum mrb_vtype tt = mrb_type(a);
  mrb_bool eql;

  switch (tt) {
  case MRB_TT_STRING:
    return mrb_str_equal(mrb, a, b);

  case MRB_TT_SYMBOL:
    if (!mrb_symbol_p(b)) return FALSE;
    return mrb_symbol(a) == mrb_symbol(b);

  case MRB_TT_INTEGER:
    if (!mrb_integer_p(b)) return FALSE;
    return mrb_integer(a) == mrb_integer(b);

#ifndef MRB_NO_FLOAT
  case MRB_TT_FLOAT:
    if (!mrb_float_p(b)) return FALSE;
    return mrb_float(a) == mrb_float(b);
#endif

  default:
    h_check_modified(mrb, h, {eql = mrb_eql(mrb, a, b);});
    return eql;
  }
}

static mrb_bool
entry_deleted_p(const hash_entry* entry)
{
  return mrb_undef_p(entry->key);
}

static void
entry_delete(hash_entry* entry)
{
  entry->key = mrb_undef_value();
}

static uint32_t
ea_next_capa_for(uint32_t size, uint32_t max_capa)
{
  if (size < AR_DEFAULT_CAPA) {
    return AR_DEFAULT_CAPA;
  }
  else {
    /*
     * For 32-bit CPU, the theoretical value of maximum EA capacity is
     * `UINT32_MAX / sizeof (hash_entry)`. At this time, if
     * `EA_INCREASE_RATIO` is the current value, 32-bit range will not be
     * exceeded during the calculation of `capa`, so `size_t` is used.
     */
    size_t capa = (size_t)size * EA_INCREASE_RATIO, inc = capa - size;
    if (EA_MAX_INCREASE < inc) capa = size + EA_MAX_INCREASE;
    return capa <= max_capa ? U32(capa) : max_capa;
  }
}

static hash_entry*
ea_resize(mrb_state *mrb, hash_entry *ea, uint32_t capa)
{
  return (hash_entry*)mrb_realloc(mrb, ea, sizeof(hash_entry) * capa);
}

static void
ea_compress(hash_entry *ea, uint32_t n_used)
{
  hash_entry *w_entry = ea;
  ea_each_used(ea, n_used, r_entry, {
    if (entry_deleted_p(r_entry)) continue;
    if (r_entry != w_entry) *w_entry = *r_entry;
    ++w_entry;
  });
}

/*
 * Increase or decrease capacity of `ea` to a standard size that can
 * accommodate `*capap + 1` entries (but, not exceed `max_capa`). Set the
 * changed capacity to `*capap` and return a pointer to `mrb_realloc`ed EA.
 */
static hash_entry*
ea_adjust(mrb_state *mrb, hash_entry *ea, uint32_t *capap, uint32_t max_capa)
{
  *capap = ea_next_capa_for(*capap, max_capa);
  return ea_resize(mrb, ea, *capap);
}

static hash_entry*
ea_dup(mrb_state *mrb, const hash_entry *ea, uint32_t capa)
{
  size_t byte_size = sizeof(hash_entry) * capa;
  hash_entry *new_ea = (hash_entry*)mrb_malloc(mrb, byte_size);
  return (hash_entry*)memcpy(new_ea, ea, byte_size);
}

static hash_entry*
ea_get_by_key(mrb_state *mrb, hash_entry *ea, uint32_t size, mrb_value key,
              struct RHash *h)
{
  ea_each(ea, size, entry, {
    if (obj_eql(mrb, key, entry->key, h)) return entry;
  });
  return NULL;
}

static hash_entry*
ea_get(hash_entry *ea, uint32_t index)
{
  return &ea[index];
}

static void
ea_set(hash_entry *ea, uint32_t index, mrb_value key, mrb_value val)
{
  ea[index].key = key;
  ea[index].val = val;
}

static void
ar_init(struct RHash *h, uint32_t size,
        hash_entry *ea, uint32_t ea_capa, uint32_t ea_n_used)
{
  h_ar_on(h);
  ar_set_size(h, size);
  ar_set_ea(h, ea);
  ar_set_ea_capa(h, ea_capa);
  ar_set_ea_n_used(h, ea_n_used);
}

static void
ar_free(mrb_state *mrb, struct RHash *h)
{
  mrb_free(mrb, ar_ea(h));
}

static void
ar_adjust_ea(mrb_state *mrb, struct RHash *h, uint32_t size, uint32_t max_ea_capa)
{
  uint32_t ea_capa = size;
  hash_entry *ea = ea_adjust(mrb, ar_ea(h), &ea_capa, max_ea_capa);
  ar_set_ea(h, ea);
  ar_set_ea_capa(h, ea_capa);
}

static void
ar_compress(mrb_state *mrb, struct RHash *h)
{
  uint32_t size = ar_size(h);
  ea_compress(ar_ea(h), ar_ea_n_used(h));
  ar_set_ea_n_used(h, size);
  ar_adjust_ea(mrb, h, size, lesser(ar_ea_capa(h), AR_MAX_SIZE));
}

static mrb_bool
ar_get(mrb_state *mrb, struct RHash *h, mrb_value key, mrb_value *valp)
{
  ea_each(ar_ea(h), ar_size(h), entry, {
    if (!obj_eql(mrb, key, entry->key, h)) continue;
    *valp = entry->val;
    return TRUE;
  });
  return FALSE;
}

static void
ar_set(mrb_state *mrb, struct RHash *h, mrb_value key, mrb_value val)
{
  uint32_t size = ar_size(h);
  hash_entry *entry;
  if ((entry = ea_get_by_key(mrb, ar_ea(h), size, key, h))) {
    entry->val = val;
  }
  else {
    uint32_t ea_capa = ar_ea_capa(h), ea_n_used = ar_ea_n_used(h);
    if (ea_capa == ea_n_used) {
      if (size == ea_n_used) {
        if (size == AR_MAX_SIZE) {
          hash_entry *ea = ea_adjust(mrb, ar_ea(h), &ea_capa, EA_MAX_CAPA);
          ea_set(ea, ea_n_used, key, val);
          ht_init(mrb, h, ++size, ea, ea_capa, NULL, IB_INIT_BIT);
          return;
        }
        else {
          ar_adjust_ea(mrb, h, size, AR_MAX_SIZE);
        }
      }
      else {
        ar_compress(mrb, h);
        ea_n_used = size;
      }
    }
    ea_set(ar_ea(h), ea_n_used, key, val);
    ar_set_size(h, ++size);
    ar_set_ea_n_used(h, ++ea_n_used);
  }
}

static mrb_bool
ar_delete(mrb_state *mrb, struct RHash *h, mrb_value key, mrb_value *valp)
{
  hash_entry *entry = ea_get_by_key(mrb, ar_ea(h), ar_size(h), key, h);
  if (!entry) return FALSE;
  *valp = entry->val;
  entry_delete(entry);
  ar_dec_size(h);
  return TRUE;
}

static void
ar_shift(mrb_state *mrb, struct RHash *h, mrb_value *keyp, mrb_value *valp)
{
  uint32_t size = ar_size(h);
  ea_each(ar_ea(h), size, entry, {
    *keyp = entry->key;
    *valp = entry->val;
    entry_delete(entry);
    ar_set_size(h, --size);
    return;
  });
}

static void
ar_rehash(mrb_state *mrb, struct RHash *h)
{
  /* see comments in `h_rehash` */
  uint32_t size = ar_size(h), w_size = 0, ea_capa = ar_ea_capa(h);
  hash_entry *ea = ar_ea(h), *w_entry;
  ea_each(ea, size, r_entry, {
    if ((w_entry = ea_get_by_key(mrb, ea, w_size, r_entry->key, h))) {
      w_entry->val = r_entry->val;
      ar_set_size(h, --size);
      entry_delete(r_entry);
    }
    else {
      if (w_size != U32(r_entry - ea)) {
        ea_set(ea, w_size, r_entry->key, r_entry->val);
        entry_delete(r_entry);
      }
      ++w_size;
    }
  });
  mrb_assert(size == w_size);
  ar_set_ea_n_used(h, size);
  ar_adjust_ea(mrb, h, size, ea_capa);
}

static uint32_t
ib_it_pos_for(index_buckets_iter *it, uint32_t v)
{
  return v & it->mask;
}

static uint32_t
ib_it_empty_value(const index_buckets_iter *it)
{
  return it->mask;
}

static uint32_t
ib_it_deleted_value(const index_buckets_iter *it)
{
  return it->mask - 1;
}

static mrb_bool
ib_it_empty_p(const index_buckets_iter *it)
{
  return it->ea_index == ib_it_empty_value(it);
}

static mrb_bool
ib_it_deleted_p(const index_buckets_iter *it)
{
  return it->ea_index == ib_it_deleted_value(it);
}

static mrb_bool
ib_it_active_p(const index_buckets_iter *it)
{
  return it->ea_index < ib_it_deleted_value(it);
}

static void
ib_it_init(mrb_state *mrb, index_buckets_iter *it, struct RHash *h, mrb_value key)
{
  it->h = h;
  it->bit = ib_bit(h);
  it->mask = ib_bit_to_capa(it->bit) - 1;
  it->pos = ib_it_pos_for(it, obj_hash_code(mrb, key, h));
  it->step = 0;
}

static void
ib_it_next(index_buckets_iter *it)
{
  /*
   * [IB image]
   *
   *                  ary_index(1) --.
   *                                  \          .-- shift1(3)  .-- shift2(29)
   *                     pos(6) --.    \        /              /
   *  View    |                    \    \    <-o-> <----------o---------->
   * -------- +---------------------\----\--+-----------------------------+-----
   *  array   |               0      `--. `-|--- o          1             | ...
   *          +---------+---------+-----+\--+-----+---------+---------+---+-----
   *  buckets |    0    |    1    | ... | o  6    |    7    |    8    |     ...
   *          +---------+---------+-----+=========+---------+---------+---------
   *  bit set |1 1 1 0 0|0 0 0 1 1| ... |0 1 0 1 1|0 1 1 1 0|0 1 0 1 0|     ...
   *          +---------+---------+-----+========*+---------+---------+---------
   *           <---o--->                          \
   *                \                              `-- bit_pos(34)
   *                 `-- bit(5)
   */

  /* Slide to handle as `capa == 32` to avoid 64-bit operations */
  uint32_t slid_pos = it->pos & (IB_TYPE_BIT - 1);
  uint32_t slid_bit_pos = it->bit * (slid_pos + 1) - 1;
  uint32_t slid_ary_index = slid_bit_pos / IB_TYPE_BIT;
  it->ary_index = slid_ary_index + it->pos / IB_TYPE_BIT * it->bit;
  it->shift2 = (slid_ary_index + 1) * IB_TYPE_BIT - slid_bit_pos - 1;
  it->ea_index = (ht_ib(it->h)[it->ary_index] >> it->shift2) & it->mask;
  if (IB_TYPE_BIT - it->bit < it->shift2) {
    it->shift1 = IB_TYPE_BIT - it->shift2;
    it->ea_index |= (ht_ib(it->h)[it->ary_index - 1] << it->shift1) & it->mask;
  }
  else {
    it->shift1 = 0;
  }
  it->pos = ib_it_pos_for(it, it->pos + (++it->step));
}

static uint32_t
ib_it_get(const index_buckets_iter *it)
{
  return it->ea_index;
}

static void
ib_it_set(index_buckets_iter *it, uint32_t ea_index)
{
  uint32_t mask, i;
  it->ea_index = ea_index;
  if (it->shift1) {
    i = it->ary_index - 1;
    mask = it->mask >> it->shift1;
    ht_ib(it->h)[i] = (ht_ib(it->h)[i] & ~mask) | (ea_index >> it->shift1);
  }
  i = it->ary_index;
  mask = it->mask << it->shift2;
  ht_ib(it->h)[i] = (ht_ib(it->h)[i] & ~mask) | (ea_index << it->shift2);
}

static void
ib_it_delete(index_buckets_iter *it)
{
  ib_it_set(it, ib_it_deleted_value(it));
}

static hash_entry*
ib_it_entry(index_buckets_iter *it)
{
  return ea_get(ht_ea(it->h), it->ea_index);
}

static uint32_t
ib_capa_to_bit(uint32_t capa)
{
#ifdef __GNUC__
  return U32(__builtin_ctz(capa));
#else
  /* http://graphics.stanford.edu/~seander/bithacks.html#IntegerLogDeBruijn */
  static const uint32_t MultiplyDeBruijnBitPosition2[] = {
    0, 1, 28, 2, 29, 14, 24, 3, 30, 22, 20, 15, 25, 17, 4, 8,
    31, 27, 13, 23, 21, 19, 16, 7, 26, 12, 18, 6, 11, 5, 10, 9
  };
  return MultiplyDeBruijnBitPosition2[U32(capa * 0x077CB531U) >> 27];
#endif
}

static uint32_t
ib_bit_to_capa(uint32_t bit)
{
  return U32(1) << bit;
}

static uint32_t
ib_upper_bound_for(uint32_t capa)
{
  return (capa >> 2) | (capa >> 1);  /* 3/4 */
}

static uint32_t
ib_bit_for(uint32_t size)
{
  uint32_t capa = next_power2(size);
  if (capa != IB_MAX_CAPA && ib_upper_bound_for(capa) < size) capa *= 2;
  return ib_capa_to_bit(capa);
}

static uint32_t
ib_byte_size_for(uint32_t ib_bit)
{
  mrb_assert(IB_INIT_BIT <= ib_bit);
  uint32_t ary_size = IB_INIT_BIT == 4 ?
    ib_bit_to_capa(ib_bit) * 2 / IB_TYPE_BIT * ib_bit / 2 :
    ib_bit_to_capa(ib_bit) / IB_TYPE_BIT * ib_bit;
  return U32(sizeof(uint32_t) * ary_size);
}

static void
ib_init(mrb_state *mrb, struct RHash *h, uint32_t ib_bit, size_t ib_byte_size)
{
  hash_entry *ea = ht_ea(h);
  memset(ht_ib(h), 0xff, ib_byte_size);
  ib_set_bit(h, ib_bit);
  ea_each_used(ea, ht_ea_n_used(h), entry, {
    ib_cycle_by_key(mrb, h, entry->key, it, {
      if (!ib_it_empty_p(it)) continue;
      ib_it_set(it, U32(entry - ea));
      break;
    });
  });
}

static void
ht_init(mrb_state *mrb, struct RHash *h, uint32_t size,
        hash_entry *ea, uint32_t ea_capa, hash_table *ht, uint32_t ib_bit)
{
  size_t ib_byte_size = ib_byte_size_for(ib_bit);
  size_t ht_byte_size = sizeof(hash_table) + ib_byte_size;
  h_ht_on(h);
  h_set_ht(h, (hash_table*)mrb_realloc(mrb, ht, ht_byte_size));
  ht_set_size(h, size);
  ht_set_ea(h, ea);
  ht_set_ea_capa(h, ea_capa);
  ht_set_ea_n_used(h, size);
  ib_init(mrb, h, ib_bit, ib_byte_size);
}

static void
ht_free(mrb_state *mrb, struct RHash *h)
{
  mrb_free(mrb, ht_ea(h));
  mrb_free(mrb, h_ht(h));
}

static hash_table*
ht_dup(mrb_state *mrb, const struct RHash *h)
{
  size_t ib_byte_size = ib_byte_size_for(ib_bit(h));
  size_t ht_byte_size = sizeof(hash_table) + ib_byte_size;
  hash_table *new_ht = (hash_table*)mrb_malloc(mrb, ht_byte_size);
  return (hash_table*)memcpy(new_ht, h_ht(h), ht_byte_size);
}

static void
ht_adjust_ea(mrb_state *mrb, struct RHash *h, uint32_t size, uint32_t max_ea_capa)
{
  uint32_t ea_capa = size;
  hash_entry *ea = ea_adjust(mrb, ht_ea(h), &ea_capa, max_ea_capa);
  ht_set_ea(h, ea);
  ht_set_ea_capa(h, ea_capa);
}

static void
ht_to_ar(mrb_state *mrb, struct RHash *h)
{
  uint32_t size = ht_size(h), ea_capa = size;
  hash_entry *ea = ht_ea(h);
  ea_compress(ea, ht_ea_n_used(h));
  ea = ea_adjust(mrb, ea, &ea_capa, AR_MAX_SIZE);
  mrb_free(mrb, h_ht(h));
  ar_init(h, size, ea, ea_capa, size);
}

static mrb_bool
ht_get(mrb_state *mrb, struct RHash *h, mrb_value key, mrb_value *valp)
{
  ib_find_by_key(mrb, h, key, it, {
    *valp = ib_it_entry(it)->val;
    return TRUE;
  });
  return FALSE;
}

static void
ht_set_as_ar(mrb_state *mrb, struct RHash *h, mrb_value key, mrb_value val)
{
  ht_to_ar(mrb, h);
  ar_set(mrb, h, key, val);
}

static void
ht_set_without_ib_adjustment(mrb_state *mrb, struct RHash *h,
                             mrb_value key, mrb_value val)
{
  mrb_assert(ht_size(h) < ib_bit_to_capa(ib_bit(h)));
  ib_cycle_by_key(mrb, h, key, it, {
    if (ib_it_active_p(it)) {
      if (!obj_eql(mrb, key, ib_it_entry(it)->key, h)) continue;
      ib_it_entry(it)->val = val;
    }
    else {
      uint32_t ea_n_used = ht_ea_n_used(h);
      if (ea_n_used == H_MAX_SIZE) {
        mrb_assert(ht_size(h) == ea_n_used);
        mrb_raise(mrb, E_ARGUMENT_ERROR, "hash too big");
      }
      if (ea_n_used == ht_ea_capa(h)) ht_adjust_ea(mrb, h, ea_n_used, EA_MAX_CAPA);
      ib_it_set(it, ea_n_used);
      ea_set(ht_ea(h), ea_n_used, key, val);
      ht_inc_size(h);
      ht_set_ea_n_used(h, ++ea_n_used);
    }
    return;
  });
}

static void
ht_set(mrb_state *mrb, struct RHash *h, mrb_value key, mrb_value val)
{
  uint32_t size = ht_size(h);
  uint32_t ib_bit_width = ib_bit(h), ib_capa = ib_bit_to_capa(ib_bit_width);
  if (ib_upper_bound_for(ib_capa) <= size) {
    if (size != ht_ea_n_used(h)) ea_compress(ht_ea(h), ht_ea_n_used(h));
    ht_init(mrb, h, size, ht_ea(h), ht_ea_capa(h), h_ht(h), ++ib_bit_width);
  }
  else if (size != ht_ea_n_used(h)) {
    if (ib_capa - EA_N_RESERVED_INDICES <= ht_ea_n_used(h)) goto compress;
    if (ht_ea_capa(h) == ht_ea_n_used(h)) {
      if (size <= AR_MAX_SIZE) {ht_set_as_ar(mrb, h, key, val); return;}
      if (ea_next_capa_for(size, EA_MAX_CAPA) <= ht_ea_capa(h)) {
       compress:
        ea_compress(ht_ea(h), ht_ea_n_used(h));
        ht_adjust_ea(mrb, h, size, ht_ea_capa(h));
        ht_init(mrb, h, size, ht_ea(h), ht_ea_capa(h), h_ht(h), ib_bit_width);
      }
    }
  }
  ht_set_without_ib_adjustment(mrb, h, key, val);
}

static mrb_bool
ht_delete(mrb_state *mrb, struct RHash *h, mrb_value key, mrb_value *valp)
{
  ib_find_by_key(mrb, h, key, it, {
    hash_entry *entry = ib_it_entry(it);
    *valp = entry->val;
    ib_it_delete(it);
    entry_delete(entry);
    ht_dec_size(h);
    return TRUE;
  });
  return FALSE;
}

static void
ht_shift(mrb_state *mrb, struct RHash *h, mrb_value *keyp, mrb_value *valp)
{
  hash_entry *ea = ht_ea(h);
  ea_each(ea, ht_size(h), entry, {
    ib_cycle_by_key(mrb, h, entry->key, it, {
      if (ib_it_get(it) != U32(entry - ea)) continue;
      *keyp = entry->key;
      *valp = entry->val;
      ib_it_delete(it);
      entry_delete(entry);
      ht_dec_size(h);
      return;
    });
  });
}

static void
ht_rehash(mrb_state *mrb, struct RHash *h)
{
  /* see comments in `h_rehash` */
  uint32_t size = ht_size(h);
  if (size <= AR_MAX_SIZE) {
    ht_to_ar(mrb, h);
    ar_rehash(mrb, h);
    return;
  }
  uint32_t w_size = 0, ea_capa = ht_ea_capa(h);
  hash_entry *ea = ht_ea(h);
  ht_init(mrb, h, 0, ea, ea_capa, h_ht(h), ib_bit_for(size));
  ht_set_size(h, size);
  ht_set_ea_n_used(h, ht_ea_n_used(h));
  ea_each(ea, size, r_entry, {
    ib_cycle_by_key(mrb, h, r_entry->key, it, {
      if (ib_it_active_p(it)) {
        if (!obj_eql(mrb, r_entry->key, ib_it_entry(it)->key, h)) continue;
        ib_it_entry(it)->val = r_entry->val;
        ht_set_size(h, --size);
        entry_delete(r_entry);
      }
      else {
        if (w_size != U32(r_entry - ea)) {
          ea_set(ea, w_size, r_entry->key, r_entry->val);
          entry_delete(r_entry);
        }
        ib_it_set(it, w_size++);
      }
      break;
    });
  });
  mrb_assert(size == w_size);
  ht_set_ea_n_used(h, size);
  size <= AR_MAX_SIZE ? ht_to_ar(mrb, h) : ht_adjust_ea(mrb, h, size, ea_capa);
}

static mrb_value
h_key_for(mrb_state *mrb, mrb_value key)
{
  if (mrb_string_p(key) && !MRB_FROZEN_P(mrb_str_ptr(key))) {
    key = mrb_str_dup(mrb, key);
    MRB_SET_FROZEN_FLAG(mrb_str_ptr(key));
  }
  return key;
}

static struct RHash*
h_alloc(mrb_state *mrb)
{
  return MRB_OBJ_ALLOC(mrb, MRB_TT_HASH, mrb->hash_class);
}

static void
h_init(struct RHash *h)
{
  ar_init(h, 0, NULL, 0, 0);
}

static void
h_free_table(mrb_state *mrb, struct RHash *h)
{
  (h_ar_p(h) ? ar_free : ht_free)(mrb, h);
}

static void
h_clear(mrb_state *mrb, struct RHash *h)
{
  h_free_table(mrb, h);
  h_init(h);
}

static mrb_bool
h_get(mrb_state *mrb, struct RHash *h, mrb_value key, mrb_value *valp)
{
  return (h_ar_p(h) ? ar_get : ht_get)(mrb, h, key, valp);
}

static void
h_set(mrb_state *mrb, struct RHash *h, mrb_value key, mrb_value val)
{
  (h_ar_p(h) ? ar_set : ht_set)(mrb, h, key, val);
}

static mrb_bool
h_delete(mrb_state *mrb, struct RHash *h, mrb_value key, mrb_value *valp)
{
  return (h_ar_p(h) ? ar_delete : ht_delete)(mrb, h, key, valp);
}

/* find first element in the table, and remove it. */
static void
h_shift(mrb_state *mrb, struct RHash *h, mrb_value *keyp, mrb_value *valp)
{
  (h_ar_p(h) ? ar_shift : ht_shift)(mrb, h, keyp, valp);
}

static void
h_rehash(mrb_state *mrb, struct RHash *h)
{
  /*
   * ==== Comments common to `ar_rehash` and `ht_rehash`
   *
   * - Because reindex (such as elimination of duplicate keys) must be
   *   guaranteed, it is necessary to set one by one.
   *
   * - To prevent EA from breaking if an exception occurs in the middle,
   *   delete the slot before moving when moving the entry, and update size
   *   at any time when overwriting.
   */
  (h_size(h) == 0 ? h_clear : h_ar_p(h) ? ar_rehash : ht_rehash)(mrb, h);
}

static void
h_replace(mrb_state *mrb, struct RHash *h, struct RHash *orig_h)
{
  uint32_t size = h_size(orig_h);
  if (size == 0) {
    h_clear(mrb, h);
  }
  else if (h_ar_p(orig_h)) {
    uint32_t ea_capa = ar_ea_capa(orig_h);
    hash_entry *ea = ea_dup(mrb, ar_ea(orig_h), ea_capa);
    h_free_table(mrb, h);
    ar_init(h, size, ea, ea_capa, ar_ea_n_used(orig_h));
  }
  else { /* HT */
    uint32_t ea_capa = ht_ea_capa(orig_h);
    hash_entry *ea = ea_dup(mrb, ht_ea(orig_h), ea_capa);
    hash_table *ht = ht_dup(mrb, orig_h);
    h_free_table(mrb, h);
    h_ht_on(h);
    h_set_ht(h, ht);
    ht_set_size(h, size);
    ht_set_ea(h, ea);
#ifdef MRB_64BIT
    ht_set_ea_capa(h, ea_capa);
    ht_set_ea_n_used(h, ht_ea_n_used(orig_h));
#endif
    ib_set_bit(h, ib_bit(orig_h));
  }
}

void
mrb_gc_mark_hash(mrb_state *mrb, struct RHash *h)
{
  h_each(h, entry, {
    mrb_gc_mark_value(mrb, entry->key);
    mrb_gc_mark_value(mrb, entry->val);
  });
}

size_t
mrb_gc_mark_hash_size(mrb_state *mrb, struct RHash *h)
{
  return h_size(h) * 2;
}

void
mrb_gc_free_hash(mrb_state *mrb, struct RHash *h)
{
  h_free_table(mrb, h);
}

size_t
mrb_hash_memsize(mrb_value self)
{
  struct RHash *h = mrb_hash_ptr(self);
  return mrb_obj_iv_tbl_memsize(self) +
         (h_ar_p(h) ? (ar_ea_capa(h) * sizeof(hash_entry)) :
                      (ht_ea_capa(h) * sizeof(hash_entry) +
                       sizeof(hash_table) +
                       ib_byte_size_for(ib_bit(h))));
}

/* Iterates over the key/value pairs. */
MRB_API void
mrb_hash_foreach(mrb_state *mrb, struct RHash *h, mrb_hash_foreach_func *func, void *data)
{
  h_each(h, entry, {
    if (func(mrb, entry->key, entry->val, data) != 0) return;
  });
}

MRB_API mrb_value
mrb_hash_new(mrb_state *mrb)
{
  struct RHash *h = h_alloc(mrb);
  return mrb_obj_value(h);
}

/*
 * Set the capacity of EA and IB to minimum capacity (and appropriate load
 * factor) that does not cause expansion when inserting `capa` elements.
 */
MRB_API mrb_value
mrb_hash_new_capa(mrb_state *mrb, mrb_int capa)
{
  if (capa < 0 || EA_MAX_CAPA < capa) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "hash too big");
    return mrb_nil_value();  /* not reached */
  }
  else if (capa == 0) {
    return mrb_hash_new(mrb);
  }
  else {
    uint32_t size = U32(capa);
    struct RHash *h = h_alloc(mrb);
    hash_entry *ea = ea_resize(mrb, NULL, size);
    if (size <= AR_MAX_SIZE) {
      ar_init(h, 0, ea, size, 0);
    }
    else {
      ht_init(mrb, h, 0, ea, size, NULL, ib_bit_for(size));
    }
    return mrb_obj_value(h);
  }
}

static mrb_value mrb_hash_default(mrb_state *mrb, mrb_value hash);

static void
hash_modify(mrb_state *mrb, mrb_value hash)
{
  mrb_check_frozen(mrb, mrb_hash_ptr(hash));
}

static mrb_value
hash_default(mrb_state *mrb, mrb_value hash, mrb_value key)
{
  if (MRB_RHASH_DEFAULT_P(hash)) {
    if (MRB_RHASH_PROCDEFAULT_P(hash)) {
      return mrb_funcall_id(mrb, RHASH_PROCDEFAULT(hash), MRB_SYM(call), 2, hash, key);
    }
    else {
      return RHASH_IFNONE(hash);
    }
  }
  return mrb_nil_value();
}

static void
hash_replace(mrb_state *mrb, mrb_value self, mrb_value orig)
{
  struct RHash *h = mrb_hash_ptr(self), *orig_h = mrb_hash_ptr(orig);
  uint32_t mask = MRB_HASH_DEFAULT | MRB_HASH_PROC_DEFAULT;
  mrb_sym name;
  h_replace(mrb, h, orig_h);
  name = MRB_SYM(ifnone);
  if (orig_h->flags & MRB_HASH_DEFAULT) {
    mrb_iv_set(mrb, self, name, mrb_iv_get(mrb, orig, name));
  }
  else {
    mrb_iv_remove(mrb, self, name);
  }
  h->flags &= ~mask;
  h->flags |= orig_h->flags & mask;
}

static mrb_value
mrb_hash_init_copy(mrb_state *mrb, mrb_value self)
{
  mrb_value orig;
  mrb_get_args(mrb, "H", &orig);
  hash_modify(mrb, self);
  if (mrb_hash_ptr(self) != mrb_hash_ptr(orig)) hash_replace(mrb, self, orig);
  return self;
}

MRB_API mrb_value
mrb_hash_dup(mrb_state *mrb, mrb_value self)
{
  struct RHash* copy_h = h_alloc(mrb);
  mrb_value copy = mrb_obj_value(copy_h);
  copy_h->c = mrb_hash_ptr(self)->c;
  hash_replace(mrb, copy, self);
  return copy;
}

MRB_API mrb_value
mrb_hash_get(mrb_state *mrb, mrb_value hash, mrb_value key)
{
  mrb_value val;
  mrb_sym mid;

  if (h_get(mrb, mrb_hash_ptr(hash), key, &val)) {
    return val;
  }

  mid = MRB_SYM(default);
  if (mrb_func_basic_p(mrb, hash, mid, mrb_hash_default)) {
    return hash_default(mrb, hash, key);
  }
  /* xxx mrb_funcall_tailcall(mrb, hash, "default", 1, key); */
  return mrb_funcall_argv(mrb, hash, mid, 1, &key);
}

MRB_API mrb_value
mrb_hash_fetch(mrb_state *mrb, mrb_value hash, mrb_value key, mrb_value def)
{
  mrb_value val;

  if (h_get(mrb, mrb_hash_ptr(hash), key, &val)) {
    return val;
  }
  /* not found */
  return def;
}

MRB_API void
mrb_hash_set(mrb_state *mrb, mrb_value hash, mrb_value key, mrb_value val)
{
  hash_modify(mrb, hash);
  key = h_key_for(mrb, key);
  h_set(mrb, mrb_hash_ptr(hash), key, val);
  mrb_field_write_barrier_value(mrb, mrb_basic_ptr(hash), key);
  mrb_field_write_barrier_value(mrb, mrb_basic_ptr(hash), val);
}

/* 15.2.13.4.16 */
/*
 *  call-seq:
 *     Hash.new                          -> new_hash
 *     Hash.new(obj)                     -> new_hash
 *     Hash.new {|hash, key| block }     -> new_hash
 *
 *  Returns a new, empty hash. If this hash is subsequently accessed by
 *  a key that doesn't correspond to a hash entry, the value returned
 *  depends on the style of <code>new</code> used to create the hash. In
 *  the first form, the access returns <code>nil</code>. If
 *  <i>obj</i> is specified, this single object will be used for
 *  all <em>default values</em>. If a block is specified, it will be
 *  called with the hash object and the key, and should return the
 *  default value. It is the block's responsibility to store the value
 *  in the hash if required.
 *
 *      h = Hash.new("Go Fish")
 *      h["a"] = 100
 *      h["b"] = 200
 *      h["a"]           #=> 100
 *      h["c"]           #=> "Go Fish"
 *      # The following alters the single default object
 *      h["c"].upcase!   #=> "GO FISH"
 *      h["d"]           #=> "GO FISH"
 *      h.keys           #=> ["a", "b"]
 *
 *      # While this creates a new default object each time
 *      h = Hash.new { |hash, key| hash[key] = "Go Fish: #{key}" }
 *      h["c"]           #=> "Go Fish: c"
 *      h["c"].upcase!   #=> "GO FISH: C"
 *      h["d"]           #=> "Go Fish: d"
 *      h.keys           #=> ["c", "d"]
 *
 */

static mrb_value
mrb_hash_init(mrb_state *mrb, mrb_value hash)
{
  mrb_value block, ifnone;
  mrb_bool ifnone_p;

  ifnone = mrb_nil_value();
  mrb_get_args(mrb, "&|o?", &block, &ifnone, &ifnone_p);
  hash_modify(mrb, hash);
  if (!mrb_nil_p(block)) {
    if (ifnone_p) {
      mrb_argnum_error(mrb, 1, 0, 0);
    }
    RHASH(hash)->flags |= MRB_HASH_PROC_DEFAULT;
    ifnone = block;
  }
  if (!mrb_nil_p(ifnone)) {
    RHASH(hash)->flags |= MRB_HASH_DEFAULT;
    mrb_iv_set(mrb, hash, MRB_SYM(ifnone), ifnone);
  }
  return hash;
}

/* 15.2.13.4.2  */
/*
 *  call-seq:
 *     hsh[key]    ->  value
 *
 *  Element Reference---Retrieves the <i>value</i> object corresponding
 *  to the <i>key</i> object. If not found, returns the default value (see
 *  <code>Hash::new</code> for details).
 *
 *     h = { "a" => 100, "b" => 200 }
 *     h["a"]   #=> 100
 *     h["c"]   #=> nil
 *
 */
static mrb_value
mrb_hash_aget(mrb_state *mrb, mrb_value self)
{
  mrb_value key = mrb_get_arg1(mrb);

  return mrb_hash_get(mrb, self, key);
}

/* 15.2.13.4.5  */
/*
 *  call-seq:
 *     hsh.default(key=nil)   -> obj
 *
 *  Returns the default value, the value that would be returned by
 *  <i>hsh</i>[<i>key</i>] if <i>key</i> did not exist in <i>hsh</i>.
 *  See also <code>Hash::new</code> and <code>Hash#default=</code>.
 *
 *     h = Hash.new                            #=> {}
 *     h.default                               #=> nil
 *     h.default(2)                            #=> nil
 *
 *     h = Hash.new("cat")                     #=> {}
 *     h.default                               #=> "cat"
 *     h.default(2)                            #=> "cat"
 *
 *     h = Hash.new {|h,k| h[k] = k.to_i*10}   #=> {}
 *     h.default                               #=> nil
 *     h.default(2)                            #=> 20
 */

static mrb_value
mrb_hash_default(mrb_state *mrb, mrb_value hash)
{
  mrb_value key;
  mrb_bool given;

  mrb_get_args(mrb, "|o?", &key, &given);
  if (MRB_RHASH_DEFAULT_P(hash)) {
    if (MRB_RHASH_PROCDEFAULT_P(hash)) {
      if (!given) return mrb_nil_value();
      return mrb_funcall_id(mrb, RHASH_PROCDEFAULT(hash), MRB_SYM(call), 2, hash, key);
    }
    else {
      return RHASH_IFNONE(hash);
    }
  }
  return mrb_nil_value();
}

/* 15.2.13.4.6  */
/*
 *  call-seq:
 *     hsh.default = obj     -> obj
 *
 *  Sets the default value, the value returned for a key that does not
 *  exist in the hash. It is not possible to set the default to a
 *  <code>Proc</code> that will be executed on each key lookup.
 *
 *     h = { "a" => 100, "b" => 200 }
 *     h.default = "Go fish"
 *     h["a"]     #=> 100
 *     h["z"]     #=> "Go fish"
 *     # This doesn't do what you might hope...
 *     h.default = proc do |hash, key|
 *       hash[key] = key + key
 *     end
 *     h[2]       #=> #<Proc:0x401b3948@-:6>
 *     h["cat"]   #=> #<Proc:0x401b3948@-:6>
 */

static mrb_value
mrb_hash_set_default(mrb_state *mrb, mrb_value hash)
{
  mrb_value ifnone = mrb_get_arg1(mrb);

  hash_modify(mrb, hash);
  mrb_iv_set(mrb, hash, MRB_SYM(ifnone), ifnone);
  RHASH(hash)->flags &= ~MRB_HASH_PROC_DEFAULT;
  if (!mrb_nil_p(ifnone)) {
    RHASH(hash)->flags |= MRB_HASH_DEFAULT;
  }
  else {
    RHASH(hash)->flags &= ~MRB_HASH_DEFAULT;
  }
  return ifnone;
}

/* 15.2.13.4.7  */
/*
 *  call-seq:
 *     hsh.default_proc -> anObject
 *
 *  If <code>Hash::new</code> was invoked with a block, return that
 *  block, otherwise return <code>nil</code>.
 *
 *     h = Hash.new {|h,k| h[k] = k*k }   #=> {}
 *     p = h.default_proc                 #=> #<Proc:0x401b3d08@-:1>
 *     a = []                             #=> []
 *     p.call(a, 2)
 *     a                                  #=> [nil, nil, 4]
 */

static mrb_value
mrb_hash_default_proc(mrb_state *mrb, mrb_value hash)
{
  if (MRB_RHASH_PROCDEFAULT_P(hash)) {
    return RHASH_PROCDEFAULT(hash);
  }
  return mrb_nil_value();
}

/*
 *  call-seq:
 *     hsh.default_proc = proc_obj     -> proc_obj
 *
 *  Sets the default proc to be executed on each key lookup.
 *
 *     h.default_proc = proc do |hash, key|
 *       hash[key] = key + key
 *     end
 *     h[2]       #=> 4
 *     h["cat"]   #=> "catcat"
 */

static mrb_value
mrb_hash_set_default_proc(mrb_state *mrb, mrb_value hash)
{
  mrb_value ifnone = mrb_get_arg1(mrb);

  hash_modify(mrb, hash);
  mrb_iv_set(mrb, hash, MRB_SYM(ifnone), ifnone);
  if (!mrb_nil_p(ifnone)) {
    RHASH(hash)->flags |= MRB_HASH_PROC_DEFAULT;
    RHASH(hash)->flags |= MRB_HASH_DEFAULT;
  }
  else {
    RHASH(hash)->flags &= ~MRB_HASH_DEFAULT;
    RHASH(hash)->flags &= ~MRB_HASH_PROC_DEFAULT;
  }

  return ifnone;
}

MRB_API mrb_value
mrb_hash_delete_key(mrb_state *mrb, mrb_value hash, mrb_value key)
{
  mrb_value del_val;

  hash_modify(mrb, hash);
  if (h_delete(mrb, mrb_hash_ptr(hash), key, &del_val)) {
    return del_val;
  }

  /* not found */
  return mrb_nil_value();
}

static mrb_value
mrb_hash_delete(mrb_state *mrb, mrb_value self)
{
  mrb_value key = mrb_get_arg1(mrb);
  mrb->c->ci->mid = 0;
  return mrb_hash_delete_key(mrb, self, key);
}

/* 15.2.13.4.24 */
/*
 *  call-seq:
 *     hsh.shift -> anArray or obj
 *
 *  Removes a key-value pair from <i>hsh</i> and returns it as the
 *  two-item array <code>[</code> <i>key, value</i> <code>]</code>, or
 *  the hash's default value if the hash is empty.
 *
 *      h = { 1 => "a", 2 => "b", 3 => "c" }
 *      h.shift   #=> [1, "a"]
 *      h         #=> {2=>"b", 3=>"c"}
 */

static mrb_value
mrb_hash_shift(mrb_state *mrb, mrb_value hash)
{
  struct RHash *h = mrb_hash_ptr(hash);

  hash_modify(mrb, hash);
  if (h_size(h) == 0) {
    return mrb_nil_value();
  }
  else {
    mrb_value del_key, del_val;
    h_shift(mrb, h, &del_key, &del_val);
    mrb_gc_protect(mrb, del_key);
    mrb_gc_protect(mrb, del_val);
    return mrb_assoc_new(mrb, del_key, del_val);
  }
}

/* 15.2.13.4.4  */
/*
 *  call-seq:
 *     hsh.clear -> hsh
 *
 *  Removes all key-value pairs from `hsh`.
 *
 *      h = { "a" => 100, "b" => 200 }   #=> {"a"=>100, "b"=>200}
 *      h.clear                          #=> {}
 *
 */

MRB_API mrb_value
mrb_hash_clear(mrb_state *mrb, mrb_value hash)
{
  hash_modify(mrb, hash);
  h_clear(mrb, mrb_hash_ptr(hash));
  return hash;
}

/* 15.2.13.4.3  */
/* 15.2.13.4.26 */
/*
 *  call-seq:
 *     hsh[key] = value        -> value
 *     hsh.store(key, value)   -> value
 *
 *  Element Assignment---Associates the value given by
 *  <i>value</i> with the key given by <i>key</i>.
 *  <i>key</i> should not have its value changed while it is in
 *  use as a key (a <code>String</code> passed as a key will be
 *  duplicated and frozen).
 *
 *      h = { "a" => 100, "b" => 200 }
 *      h["a"] = 9
 *      h["c"] = 4
 *      h   #=> {"a"=>9, "b"=>200, "c"=>4}
 *
 */
static mrb_value
mrb_hash_aset(mrb_state *mrb, mrb_value self)
{
  mrb_value key, val;

  mrb_get_args(mrb, "oo", &key, &val);
  mrb_hash_set(mrb, self, key, val);
  return val;
}

MRB_API mrb_int
mrb_hash_size(mrb_state *mrb, mrb_value hash)
{
  return (mrb_int)h_size(mrb_hash_ptr(hash));
}

/* 15.2.13.4.20 */
/* 15.2.13.4.25 */
/*
 *  call-seq:
 *     hsh.length    ->  integer
 *     hsh.size      ->  integer
 *
 *  Returns the number of key-value pairs in the hash.
 *
 *     h = { "d" => 100, "a" => 200, "v" => 300, "e" => 400 }
 *     h.length        #=> 4
 *     h.delete("a")   #=> 200
 *     h.length        #=> 3
 */
static mrb_value
mrb_hash_size_m(mrb_state *mrb, mrb_value self)
{
  mrb_int size = mrb_hash_size(mrb, self);
  return mrb_int_value(mrb, size);
}

MRB_API mrb_bool
mrb_hash_empty_p(mrb_state *mrb, mrb_value self)
{
  return h_size(mrb_hash_ptr(self)) == 0;
}

/* 15.2.13.4.12 */
/*
 *  call-seq:
 *     hsh.empty?    -> true or false
 *
 *  Returns <code>true</code> if <i>hsh</i> contains no key-value pairs.
 *
 *     {}.empty?   #=> true
 *
 */
static mrb_value
mrb_hash_empty_m(mrb_state *mrb, mrb_value self)
{
  return mrb_bool_value(mrb_hash_empty_p(mrb, self));
}

/* 15.2.13.4.19 */
/*
 *  call-seq:
 *     hsh.keys    -> array
 *
 *  Returns a new array populated with the keys from this hash. See also
 *  <code>Hash#values</code>.
 *
 *     h = { "a" => 100, "b" => 200, "c" => 300, "d" => 400 }
 *     h.keys   #=> ["a", "b", "c", "d"]
 *
 */

MRB_API mrb_value
mrb_hash_keys(mrb_state *mrb, mrb_value hash)
{
  struct RHash *h = mrb_hash_ptr(hash);
  mrb_value ary = mrb_ary_new_capa(mrb, (mrb_int)h_size(h));
  h_each(h, entry, {
    mrb_ary_push(mrb, ary, entry->key);
  });
  return ary;
}

/* 15.2.13.4.28 */
/*
 *  call-seq:
 *     hsh.values    -> array
 *
 *  Returns a new array populated with the values from <i>hsh</i>. See
 *  also <code>Hash#keys</code>.
 *
 *     h = { "a" => 100, "b" => 200, "c" => 300 }
 *     h.values   #=> [100, 200, 300]
 *
 */

MRB_API mrb_value
mrb_hash_values(mrb_state *mrb, mrb_value hash)
{
  struct RHash *h = mrb_hash_ptr(hash);
  mrb_value ary = mrb_ary_new_capa(mrb, (mrb_int)h_size(h));
  h_each(h, entry, {
    mrb_ary_push(mrb, ary, entry->val);
  });
  return ary;
}

/* 15.2.13.4.13 */
/* 15.2.13.4.15 */
/* 15.2.13.4.18 */
/* 15.2.13.4.21 */
/*
 *  call-seq:
 *     hsh.has_key?(key)    -> true or false
 *     hsh.include?(key)    -> true or false
 *     hsh.key?(key)        -> true or false
 *     hsh.member?(key)     -> true or false
 *
 *  Returns <code>true</code> if the given key is present in <i>hsh</i>.
 *
 *     h = { "a" => 100, "b" => 200 }
 *     h.has_key?("a")   #=> true
 *     h.has_key?("z")   #=> false
 *
 */

MRB_API mrb_bool
mrb_hash_key_p(mrb_state *mrb, mrb_value hash, mrb_value key)
{
  mrb_value val;
  return h_get(mrb, mrb_hash_ptr(hash), key, &val);
}

static mrb_value
mrb_hash_has_key(mrb_state *mrb, mrb_value hash)
{
  mrb_value key = mrb_get_arg1(mrb);
  mrb_bool key_p;

  key_p = mrb_hash_key_p(mrb, hash, key);
  return mrb_bool_value(key_p);
}

/* 15.2.13.4.14 */
/* 15.2.13.4.27 */
/*
 *  call-seq:
 *     hsh.has_value?(value)    -> true or false
 *     hsh.value?(value)        -> true or false
 *
 *  Returns <code>true</code> if the given value is present for some key
 *  in <i>hsh</i>.
 *
 *     h = { "a" => 100, "b" => 200 }
 *     h.has_value?(100)   #=> true
 *     h.has_value?(999)   #=> false
 */

static mrb_value
mrb_hash_has_value(mrb_state *mrb, mrb_value hash)
{
  mrb_value val = mrb_get_arg1(mrb);
  struct RHash *h = mrb_hash_ptr(hash);
  h_each(h, entry, {
    h_check_modified(mrb, h, {
      if (mrb_equal(mrb, val, entry->val)) return mrb_true_value();
    });
  });
  return mrb_false_value();
}

MRB_API void
mrb_hash_merge(mrb_state *mrb, mrb_value hash1, mrb_value hash2)
{
  struct RHash *h1, *h2;

  hash_modify(mrb, hash1);
  mrb_ensure_hash_type(mrb, hash2);
  h1 = mrb_hash_ptr(hash1);
  h2 = mrb_hash_ptr(hash2);

  if (h1 == h2) return;
  if (h_size(h2) == 0) return;
  h_each(h2, entry, {
    h_check_modified(mrb, h2, {h_set(mrb, h1, entry->key, entry->val);});
    mrb_field_write_barrier_value(mrb, (struct RBasic *)h1, entry->key);
    mrb_field_write_barrier_value(mrb, (struct RBasic *)h1, entry->val);
  });
}

/*
 *  call-seq:
 *    hsh.rehash -> hsh
 *
 *  Rebuilds the hash based on the current hash values for each key. If
 *  values of key objects have changed since they were inserted, this
 *  method will reindex <i>hsh</i>.
 *
 *     keys = (1..17).map{|n| [n]}
 *     k = keys[0]
 *     h = {}
 *     keys.each{|key| h[key] = key[0]}
 *     h     #=> { [1]=>1, [2]=>2, ... [16]=>16, [17]=>17}
 *     h[k]  #=> 1
 *     k[0] = keys.size + 1
 *     h     #=> {[18]=>1, [2]=>2, ... [16]=>16, [17]=>17}
 *     h[k]  #=> nil
 *     h.rehash
 *     h[k]  #=> 1
 */
static mrb_value
mrb_hash_rehash(mrb_state *mrb, mrb_value self)
{
  h_rehash(mrb, mrb_hash_ptr(self));
  return self;
}

void
mrb_init_hash(mrb_state *mrb)
{
  struct RClass *h;

  mrb->hash_class = h = mrb_define_class(mrb, "Hash", mrb->object_class);              /* 15.2.13 */
  MRB_SET_INSTANCE_TT(h, MRB_TT_HASH);

  mrb_define_method(mrb, h, "[]",              mrb_hash_aget,        MRB_ARGS_REQ(1)); /* 15.2.13.4.2  */
  mrb_define_method(mrb, h, "[]=",             mrb_hash_aset,        MRB_ARGS_REQ(2)); /* 15.2.13.4.3  */
  mrb_define_method(mrb, h, "clear",           mrb_hash_clear,       MRB_ARGS_NONE()); /* 15.2.13.4.4  */
  mrb_define_method(mrb, h, "default",         mrb_hash_default,     MRB_ARGS_OPT(1)); /* 15.2.13.4.5  */
  mrb_define_method(mrb, h, "default=",        mrb_hash_set_default, MRB_ARGS_REQ(1)); /* 15.2.13.4.6  */
  mrb_define_method(mrb, h, "default_proc",    mrb_hash_default_proc,MRB_ARGS_NONE()); /* 15.2.13.4.7  */
  mrb_define_method(mrb, h, "default_proc=",   mrb_hash_set_default_proc,MRB_ARGS_REQ(1)); /* 15.2.13.4.7  */
  mrb_define_method(mrb, h, "__delete",        mrb_hash_delete,      MRB_ARGS_REQ(1)); /* core of 15.2.13.4.8  */
  mrb_define_method(mrb, h, "empty?",          mrb_hash_empty_m,     MRB_ARGS_NONE()); /* 15.2.13.4.12 */
  mrb_define_method(mrb, h, "has_key?",        mrb_hash_has_key,     MRB_ARGS_REQ(1)); /* 15.2.13.4.13 */
  mrb_define_method(mrb, h, "has_value?",      mrb_hash_has_value,   MRB_ARGS_REQ(1)); /* 15.2.13.4.14 */
  mrb_define_method(mrb, h, "include?",        mrb_hash_has_key,     MRB_ARGS_REQ(1)); /* 15.2.13.4.15 */
  mrb_define_method(mrb, h, "initialize",      mrb_hash_init,        MRB_ARGS_OPT(1)|MRB_ARGS_BLOCK()); /* 15.2.13.4.16 */
  mrb_define_method(mrb, h, "initialize_copy", mrb_hash_init_copy,   MRB_ARGS_REQ(1)); /* 15.2.13.4.17 */
  mrb_define_method(mrb, h, "key?",            mrb_hash_has_key,     MRB_ARGS_REQ(1)); /* 15.2.13.4.18 */
  mrb_define_method(mrb, h, "keys",            mrb_hash_keys,        MRB_ARGS_NONE()); /* 15.2.13.4.19 */
  mrb_define_method(mrb, h, "length",          mrb_hash_size_m,      MRB_ARGS_NONE()); /* 15.2.13.4.20 */
  mrb_define_method(mrb, h, "member?",         mrb_hash_has_key,     MRB_ARGS_REQ(1)); /* 15.2.13.4.21 */
  mrb_define_method(mrb, h, "replace",         mrb_hash_init_copy,   MRB_ARGS_REQ(1)); /* 15.2.13.4.23 */
  mrb_define_method(mrb, h, "shift",           mrb_hash_shift,       MRB_ARGS_NONE()); /* 15.2.13.4.24 */
  mrb_define_method(mrb, h, "size",            mrb_hash_size_m,      MRB_ARGS_NONE()); /* 15.2.13.4.25 */
  mrb_define_method(mrb, h, "store",           mrb_hash_aset,        MRB_ARGS_REQ(2)); /* 15.2.13.4.26 */
  mrb_define_method(mrb, h, "value?",          mrb_hash_has_value,   MRB_ARGS_REQ(1)); /* 15.2.13.4.27 */
  mrb_define_method(mrb, h, "values",          mrb_hash_values,      MRB_ARGS_NONE()); /* 15.2.13.4.28 */
  mrb_define_method(mrb, h, "rehash",          mrb_hash_rehash,      MRB_ARGS_NONE());
}
