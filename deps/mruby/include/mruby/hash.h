/*
** mruby/hash.h - Hash class
**
** See Copyright Notice in mruby.h
*/

#ifndef MRUBY_HASH_H
#define MRUBY_HASH_H

#include "common.h"
#include <mruby/khash.h>

/**
 * Hash class
 */
MRB_BEGIN_DECL

struct RHash {
  MRB_OBJECT_HEADER;
  struct iv_tbl *iv;
  struct kh_ht *ht;
};

#define mrb_hash_ptr(v)    ((struct RHash*)(mrb_ptr(v)))
#define mrb_hash_value(p)  mrb_obj_value((void*)(p))

MRB_API mrb_value mrb_hash_new_capa(mrb_state*, mrb_int);

/*
 * Initializes a new hash.
 *
 * Equivalent to:
 *
 *      Hash.new
 *
 * @param mrb The mruby state reference.
 * @return The initialized hash.
 */
MRB_API mrb_value mrb_hash_new(mrb_state *mrb);

/*
 * Sets a keys and values to hashes.
 *
 * Equivalent to:
 *
 *      hash[key] = val
 *
 * @param mrb The mruby state reference.
 * @param hash The target hash.
 * @param key The key to set.
 * @param val The value to set.
 * @return The value.
 */
MRB_API void mrb_hash_set(mrb_state *mrb, mrb_value hash, mrb_value key, mrb_value val);

/*
 * Gets a value from a key. If the key is not found, the default of the
 * hash is used.
 *
 * Equivalent to:
 *
 *     hash[key]
 *
 * @param mrb The mruby state reference.
 * @param hash The target hash.
 * @param key The key to get.
 * @return The found value.
 */
MRB_API mrb_value mrb_hash_get(mrb_state *mrb, mrb_value hash, mrb_value key);

/*
 * Gets a value from a key. If the key is not found, the default parameter is
 * used.
 *
 * Equivalent to:
 *
 *     hash.hash_key?(key) ? hash[key] : def
 *
 * @param mrb The mruby state reference.
 * @param hash The target hash.
 * @param key The key to get.
 * @param def The default value.
 * @return The found value.
 */
MRB_API mrb_value mrb_hash_fetch(mrb_state *mrb, mrb_value hash, mrb_value key, mrb_value def);

/*
 * Deletes hash key and value pair.
 *
 * Equivalent to:
 *
 *     hash.delete(key)
 *
 * @param mrb The mruby state reference.
 * @param hash The target hash.
 * @param key The key to delete.
 * @return The deleted value.
 */
MRB_API mrb_value mrb_hash_delete_key(mrb_state *mrb, mrb_value hash, mrb_value key);

/*
 * Gets an array of keys.
 *
 * Equivalent to:
 *
 *     hash.keys
 *
 * @param mrb The mruby state reference.
 * @param hash The target hash.
 * @return An array with the keys of the hash.
 */
MRB_API mrb_value mrb_hash_keys(mrb_state *mrb, mrb_value hash);
MRB_API mrb_value mrb_check_hash_type(mrb_state *mrb, mrb_value hash);

/*
 * Check if the hash is empty
 *
 * Equivalent to:
 *
 *     hash.empty?
 *
 * @param mrb The mruby state reference.
 * @param self The target hash.
 * @return True if the hash is empty, false otherwise.
 */
MRB_API mrb_value mrb_hash_empty_p(mrb_state *mrb, mrb_value self);

/*
 * Gets an array of values.
 *
 * Equivalent to:
 *
 *     hash.values
 *
 * @param mrb The mruby state reference.
 * @param hash The target hash.
 * @return An array with the values of the hash.
 */
MRB_API mrb_value mrb_hash_values(mrb_state *mrb, mrb_value hash);

/*
 * Clears the hash.
 *
 * Equivalent to:
 *
 *     hash.clear
 *
 * @param mrb The mruby state reference.
 * @param hash The target hash.
 * @return The hash
 */
MRB_API mrb_value mrb_hash_clear(mrb_state *mrb, mrb_value hash);

/* declaration of struct kh_ht */
/* be careful when you touch the internal */
typedef struct {
  mrb_value v;
  mrb_int n;
} mrb_hash_value;

KHASH_DECLARE(ht, mrb_value, mrb_hash_value, TRUE)

/* RHASH_TBL allocates st_table if not available. */
#define RHASH(obj)   ((struct RHash*)(mrb_ptr(obj)))
#define RHASH_TBL(h)          (RHASH(h)->ht)
#define RHASH_IFNONE(h)       mrb_iv_get(mrb, (h), mrb_intern_lit(mrb, "ifnone"))
#define RHASH_PROCDEFAULT(h)  RHASH_IFNONE(h)
MRB_API struct kh_ht * mrb_hash_tbl(mrb_state *mrb, mrb_value hash);

#define MRB_HASH_DEFAULT      1
#define MRB_HASH_PROC_DEFAULT 2
#define MRB_RHASH_DEFAULT_P(h) (RHASH(h)->flags & MRB_HASH_DEFAULT)
#define MRB_RHASH_PROCDEFAULT_P(h) (RHASH(h)->flags & MRB_HASH_PROC_DEFAULT)

/* GC functions */
void mrb_gc_mark_hash(mrb_state*, struct RHash*);
size_t mrb_gc_mark_hash_size(mrb_state*, struct RHash*);
void mrb_gc_free_hash(mrb_state*, struct RHash*);

MRB_END_DECL

#endif  /* MRUBY_HASH_H */
